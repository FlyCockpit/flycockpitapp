//! SQLite persistence layer.
//!
//! File-backed databases use one dedicated writer thread plus a small
//! read-only WAL connection pool. Async call sites use [`Db::read`] and
//! [`Db::write`]. The permanent synchronous escape hatch is
//! [`Db::blocking_for_sync_cli`], which runs a read/write-capable closure on
//! the writer connection and panics if called from any Tokio runtime; async
//! code must use [`Db::read`], [`Db::write`], or [`Db::transaction`] instead.
//! Four temporary sync UI/event/maintenance wrappers remain until
//! `db-sync-wrapper-migration`. Three typed agent-publication journal methods
//! also bridge the writer while a caller owns a `!Send` cross-process
//! filesystem lock; unlike the CLI escape hatch, they accept only journal
//! fields and cannot run caller-provided SQL. The cockpit-db-local
//! AST/call-graph gate in `tests/db_blocking_boundary_gate.rs` freezes that
//! exact allowlist and its ownership rationale.
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

pub mod agent_editor_leases;
pub mod agent_installations;
pub mod agent_mutation_journals;
pub mod agent_tree_decisions;
pub mod app_flags;
pub mod archive_import;
pub mod assistant_inbox;
pub mod assistants;
pub mod code_root_projection;
pub mod computer_audit;
pub mod computer_outcomes;
#[cfg(feature = "remote")]
pub mod connector;
pub mod conversation_rules;
pub mod execution_containments;
pub mod external_journal;
mod files;
pub mod filesystem_identity;
pub mod guidance;
pub mod guidance_proposals;
pub mod history_scope;
#[cfg(feature = "extended")]
pub mod image_generation;
pub mod image_generation_plan;
pub mod image_sidecar;
#[cfg(feature = "extended")]
pub mod image_spend;
pub mod inference_calls;
pub mod installation_identity;
pub mod installation_operations;
pub mod knowledge_dreams;
pub mod lang;
pub mod ledger_retention;
pub mod local_operation_receipts;
pub mod locks;
pub mod media_attachments;
pub mod message_attachments;
pub mod monty_network;
pub mod needs_attention;
#[cfg(feature = "remote")]
pub mod org_sync;
pub mod packages;
pub mod paused_work;
pub mod pins;
pub mod principals;
pub mod project_notes;
pub mod protected_leak_records;
pub mod protected_redaction_history;
pub mod prune_ledger;
#[cfg(feature = "remote")]
pub mod remote_attachment_operations;
#[cfg(feature = "remote")]
pub mod remote_audit_upload;
pub mod retention;
pub mod run_invocations;
#[cfg(feature = "extended")]
pub mod scheduler;
pub mod sealed_actions;
pub mod sealed_scope;
pub mod sealed_values;
pub mod secret_vault;
pub mod secure_key;
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
pub mod text_artifacts;
pub mod tokenizer_calibration;
pub mod tool_calls;
pub mod tool_media_subject_bindings;
pub mod turn_scheduler_continuations;
pub mod usage_events;
pub mod verification_ledger;
pub mod wire;
pub mod workspace_lease_artifacts;
pub mod workspace_trust;
pub mod write_scope_leases;

use std::any::Any;
use std::io::Seek as _;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, mpsc};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use sha2::{Digest, Sha256};

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const MIGRATION_BACKUP_LIMIT: usize = 3;
const UNTRUSTED_MIGRATION_BACKUP_LIMIT: usize = 2;
const UNTRUSTED_MIGRATION_BACKUP_TOTAL_BYTES: u64 = 2 * 1024 * 1024 * 1024;

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

#[derive(Debug, thiserror::Error)]
#[error("database transaction rollback failed after {primary:#}: {rollback}")]
struct TransactionRollbackFailed {
    primary: anyhow::Error,
    rollback: rusqlite::Error,
}

/// Returned when an append-only delete fence cannot be restored before the
/// writer connection is released. The writer loop poisons on this error so an
/// unfenced database is never reused.
#[derive(Debug, thiserror::Error)]
#[error("append-only delete fence could not be restored: {restore:#}")]
pub(crate) struct AppendOnlyDeleteFenceViolation {
    restore: anyhow::Error,
    #[source]
    truncation: Option<anyhow::Error>,
}

fn writer_error_poisoned(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause.is::<TransactionRollbackFailed>() || cause.is::<AppendOnlyDeleteFenceViolation>()
    })
}

#[cfg(test)]
static FORCED_ROLLBACK_FAILURE_DB: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

#[cfg(test)]
fn force_rollback_failure_for_test(database: Option<String>) {
    *FORCED_ROLLBACK_FAILURE_DB
        .lock()
        .expect("rollback failure hook poisoned") = database;
}

fn rollback_transaction(conn: &Connection) -> rusqlite::Result<()> {
    #[cfg(test)]
    {
        let database: String = conn.query_row(
            "SELECT file FROM pragma_database_list WHERE name='main'",
            [],
            |row| row.get(0),
        )?;
        let mut forced = FORCED_ROLLBACK_FAILURE_DB
            .lock()
            .expect("rollback failure hook poisoned");
        if forced.as_deref() == Some(database.as_str()) {
            *forced = None;
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    conn.execute_batch("ROLLBACK;")
}

#[derive(Clone)]
struct Writer {
    inner: Arc<WriterInner>,
}

/// Shared writer lifetime. `Db` declares its `writer` field before its owner
/// lock, so the final clone joins this thread (including its final checkpoint)
/// before releasing exclusive database ownership.
struct WriterInner {
    tx: Mutex<Option<mpsc::SyncSender<WriteRequest>>>,
    join: Mutex<Option<std::thread::JoinHandle<Result<()>>>>,
}

impl Drop for WriterInner {
    fn drop(&mut self) {
        // Closing the channel is the writer's orderly shutdown signal.
        if let Ok(slot) = self.tx.get_mut() {
            slot.take();
        }
        let join = self.join.get_mut().ok().and_then(Option::take);
        if let Some(join) = join {
            match join.join() {
                Ok(Ok(())) => {}
                Ok(Err(error)) => tracing::error!(%error, "database writer shutdown failed"),
                Err(_) => tracing::error!("database writer thread panicked during shutdown"),
            }
        }
    }
}

impl Writer {
    fn start(path: PathBuf) -> Result<Self> {
        let (tx, rx) = mpsc::sync_channel::<WriteRequest>(1024);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let join = std::thread::Builder::new()
            .name("cockpit-db-writer".into())
            .spawn(move || -> Result<()> {
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
                        return Err(e);
                    }
                };

                while let Ok(request) = rx.recv() {
                    let result = catch_unwind(AssertUnwindSafe(|| (request.job)(&conn)))
                        .map_err(|_| anyhow::anyhow!("db writer job panicked"))
                        .and_then(|result| result)
                        .map_err(annotate_database_storage_failure);
                    let poison = result.as_ref().err().is_some_and(writer_error_poisoned);
                    let _ = request.reply.send(result);
                    if poison {
                        // The connection may still own an unknown transaction
                        // or an unrestored append-only delete fence. Drop it
                        // and close the queue rather than serving a later write
                        // from an unprovable state.
                        return Err(anyhow::anyhow!(
                            "database writer poisoned after unrecoverable writer fault"
                        ));
                    }
                }
                // The last database owner performs an explicit truncating
                // checkpoint before SQLite closes the writer. This bounds
                // WAL growth and makes the durable shutdown boundary
                // independent of SQLite's build-time autocheckpoint defaults.
                conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
                    .context("checkpointing SQLite WAL during writer shutdown")?;
                Ok(())
            })
            .context("spawning db writer thread")?;
        match ready_rx.recv().context("waiting for db writer startup")? {
            Ok(()) => Ok(Self {
                inner: Arc::new(WriterInner {
                    tx: Mutex::new(Some(tx)),
                    join: Mutex::new(Some(join)),
                }),
            }),
            Err(e) => {
                let _ = join.join();
                anyhow::bail!(e)
            }
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
        self.inner
            .tx
            .lock()
            .map_err(|_| anyhow::anyhow!("db writer mutex poisoned"))?
            .as_ref()
            .context("db writer is shut down")?
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
            let mut guard = self
                .idle
                .lock()
                .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?;

            if let Some(conn) = guard.pop() {
                return Ok(conn);
            }

            let total = self.total.load(Ordering::SeqCst);
            if total < self.max {
                drop(guard);
                if self
                    .total
                    .compare_exchange(total, total + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    match self.open_conn() {
                        Ok(conn) => return Ok(conn),
                        Err(e) => {
                            let _ = self.release_capacity_and_notify();
                            return Err(e);
                        }
                    }
                }
                continue;
            }

            while guard.is_empty() && self.total.load(Ordering::SeqCst) >= self.max {
                guard = self
                    .available
                    .wait(guard)
                    .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?;
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

    /// Decrement live-connection count and wake a waiter. Must hold `idle` across
    /// the mutation and notify so a waiter cannot miss the signal between
    /// predicate check and condvar wait.
    fn release_capacity_and_notify(&self) -> Result<()> {
        let _guard = self
            .idle
            .lock()
            .map_err(|_| anyhow::anyhow!("db read pool mutex poisoned"))?;
        self.total.fetch_sub(1, Ordering::SeqCst);
        self.available.notify_one();
        Ok(())
    }

    fn run<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        let conn = self.checkout().map_err(annotate_database_storage_failure)?;
        match catch_unwind(AssertUnwindSafe(|| {
            f(&conn).map_err(annotate_database_storage_failure)
        })) {
            Ok(result) => {
                let checkin = self.checkin(conn);
                match (result, checkin) {
                    (Ok(value), Ok(())) => Ok(value),
                    (Err(e), _) => Err(e),
                    (Ok(_), Err(e)) => Err(e),
                }
            }
            Err(_) => {
                drop(conn);
                let _ = self.release_capacity_and_notify();
                Err(annotate_database_storage_failure(anyhow::anyhow!(
                    "db read job panicked"
                )))
            }
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
    /// Kernel-backed exclusive ownership retained by every clone until the
    /// final file-backed daemon handle is dropped.
    _owner_lock: Option<Arc<files::DatabaseOwnerLock>>,
    _diagnostic_lock: Option<Arc<files::DatabaseDiagnosticLock>>,
    read_only: bool,
    /// Process-local revocation fence for history disclosure. A reader keeps
    /// the shared permit until its tool call returns; a consent mutation takes
    /// the exclusive side before its SQLite write can commit.
    history_scope_gate: Arc<tokio::sync::RwLock<()>>,
    /// Process-local revocation fence for governed Monty egress. A request
    /// retains the shared permit from its final policy read through transport
    /// dispatch; durable policy mutations take the exclusive side before
    /// their SQLite transaction commits.
    monty_network_egress_gate: Arc<tokio::sync::RwLock<()>>,
}

/// Shared side of the history-scope revocation fence.
///
/// This is deliberately opaque: callers may hold it only while producing one
/// already-authorized history response. Dropping it is the disclosure
/// linearization point, after which a pending consent revocation may commit.
pub struct HistoryScopeDisclosurePermit {
    _guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

/// Shared side of the durable Monty-network revocation fence.
///
/// The permit is intentionally opaque. Callers retain it from their final
/// durable-policy check through the actual transport egress boundary.
pub struct MontyNetworkEgressPermit {
    _guard: tokio::sync::OwnedRwLockReadGuard<()>,
}

/// Read-only physical storage accounting for diagnostics and retention UX.
///
/// `allocated_bytes` is SQLite's main-file page allocation, while
/// `reclaimable_bytes` is the freelist portion of that allocation. The WAL and
/// shared-memory sidecars are reported separately because they are bounded by
/// the daemon's checkpoint policy rather than retention deletes alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatabaseStorageReport {
    pub page_size_bytes: u64,
    pub page_count: u64,
    pub freelist_page_count: u64,
    pub allocated_bytes: u64,
    pub reclaimable_bytes: u64,
    pub live_bytes: u64,
    pub main_file_bytes: u64,
    pub wal_file_bytes: u64,
    pub shared_memory_file_bytes: u64,
}

/// Stable recovery category for storage failures that require user action.
///
/// Callers must not retry these as ordinary contention. In particular,
/// `Capacity` and `Io` leave the outcome of an interrupted commit unknown;
/// recovery must reopen through the daemon and reconcile durable state before
/// reporting success.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DatabaseStorageFailure {
    Capacity,
    Memory,
    ReadOnly,
    Io,
    Corrupt,
}

impl DatabaseStorageFailure {
    pub const fn diagnostic_code(self) -> &'static str {
        match self {
            Self::Capacity => "FCDB_STORAGE_FULL",
            Self::Memory => "FCDB_STORAGE_MEMORY",
            Self::ReadOnly => "FCDB_STORAGE_READ_ONLY",
            Self::Io => "FCDB_STORAGE_IO",
            Self::Corrupt => "FCDB_STORAGE_CORRUPT",
        }
    }
}

/// Classify an SQLite storage failure through any `anyhow` context chain.
pub fn classify_database_storage_failure(
    error: &(dyn std::error::Error + 'static),
) -> Option<DatabaseStorageFailure> {
    let mut current = Some(error);
    while let Some(cause) = current {
        if let Some(rusqlite::Error::SqliteFailure(info, _)) =
            cause.downcast_ref::<rusqlite::Error>()
        {
            return match info.code {
                rusqlite::ErrorCode::DiskFull => Some(DatabaseStorageFailure::Capacity),
                rusqlite::ErrorCode::OutOfMemory => Some(DatabaseStorageFailure::Memory),
                rusqlite::ErrorCode::ReadOnly
                | rusqlite::ErrorCode::PermissionDenied
                | rusqlite::ErrorCode::AuthorizationForStatementDenied => {
                    Some(DatabaseStorageFailure::ReadOnly)
                }
                rusqlite::ErrorCode::SystemIoFailure
                | rusqlite::ErrorCode::CannotOpen
                | rusqlite::ErrorCode::FileLockingProtocolFailed => {
                    Some(DatabaseStorageFailure::Io)
                }
                rusqlite::ErrorCode::DatabaseCorrupt | rusqlite::ErrorCode::NotADatabase => {
                    Some(DatabaseStorageFailure::Corrupt)
                }
                _ => None,
            };
        }
        current = cause.source();
    }
    None
}

fn annotate_database_storage_failure(error: anyhow::Error) -> anyhow::Error {
    let Some(failure) = classify_database_storage_failure(error.as_ref()) else {
        return error;
    };
    let guidance = match failure {
        DatabaseStorageFailure::Capacity => {
            "free disk space, then restart the daemon and reconcile the operation before retrying"
        }
        DatabaseStorageFailure::Memory => {
            "free memory or reduce the operation size, then restart the daemon before retrying"
        }
        DatabaseStorageFailure::ReadOnly => {
            "readonly storage: restore write permission to the Cockpit data directory, then restart the daemon"
        }
        DatabaseStorageFailure::Io => {
            "check the storage device and filesystem, then restart the daemon and reconcile the operation before retrying"
        }
        DatabaseStorageFailure::Corrupt => {
            "stop the daemon and restore a validated database backup; do not retry the mutation"
        }
    };
    error.context(format!(
        "{}: database durability failure; {guidance}",
        failure.diagnostic_code()
    ))
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
        Self::open_daemon_owned(&path)
    }

    /// Open a database at an arbitrary path without claiming daemon ownership.
    ///
    /// This is the general/test multi-handle API. Production daemon startup
    /// must use [`Self::open_default`] (or [`Self::open_daemon_owned`]) so its
    /// migration and writer lifetime remain protected by the singleton lock.
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_impl(path, false)
    }

    /// Open an arbitrary database as its exclusive daemon owner.
    pub fn open_daemon_owned(path: &Path) -> Result<Self> {
        Self::open_impl(path, true)
    }

    fn open_impl(path: &Path, daemon_owned: bool) -> Result<Self> {
        let mut timer = files::PhaseTimer::start("Db::open");
        files::ensure_parent_dir_private(path)
            .with_context(|| format!("securing parent of {}", path.display()))?;
        // Acquire exclusive process ownership before opening SQLite. The guard
        // is stored in `Db`, so migration, writer startup, and the full daemon
        // lifetime are one ownership interval.
        let owner_lock = daemon_owned
            .then(|| files::DatabaseOwnerLock::acquire(path))
            .transpose()?
            .map(Arc::new);
        let existed_before_open = path.exists();
        if existed_before_open {
            let incoming = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
                .with_context(|| {
                    format!("opening existing SQLite read-only at {}", path.display())
                })?;
            if table_exists(&incoming, "schema_version")? {
                verify_existing_database(&incoming, MIGRATIONS)?;
            }
        }
        files::create_private_file_if_missing(path)?;
        let conn = Connection::open(path)
            .with_context(|| format!("opening sqlite at {}", path.display()))?;
        apply_connection_pragmas(&conn, true)
            .with_context(|| format!("setting pragmas on {}", path.display()))?;
        repair_db_file_permissions(path);
        timer.phase("connect_and_pragmas");
        migrate(&conn)?;
        reconcile_interrupted_sealed_value_acquisitions(&conn)?;
        timer.phase("migrate");

        drop(conn);
        let writer = Writer::start(path.to_path_buf())?;
        let db = Self {
            memory: None,
            writer: Some(writer),
            read_pool: Some(Arc::new(ReadPool::new(path.to_path_buf()))),
            path: Some(path.to_path_buf()),
            _owner_lock: owner_lock,
            _diagnostic_lock: None,
            read_only: false,
            history_scope_gate: Arc::new(tokio::sync::RwLock::new(())),
            monty_network_egress_gate: Arc::new(tokio::sync::RwLock::new(())),
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
        reconcile_interrupted_sealed_value_acquisitions(&conn)?;

        let db = Self {
            memory: Some(Arc::new(Mutex::new(conn))),
            writer: None,
            read_pool: None,
            path: None,
            _owner_lock: None,
            _diagnostic_lock: None,
            read_only: false,
            history_scope_gate: Arc::new(tokio::sync::RwLock::new(())),
            monty_network_egress_gate: Arc::new(tokio::sync::RwLock::new(())),
        };
        Ok(db)
    }

    /// Open the canonical database for the hidden offline diagnostic worker.
    /// This never creates files, applies pragmas, backs up, migrates, repairs,
    /// or starts a writer. The shared non-blocking ownership lock also ensures
    /// a live daemon must be queried over RPC rather than inspected beside it.
    pub fn open_default_read_only_diagnostic() -> Result<Self> {
        let path = Self::default_path()?;
        match path.metadata() {
            Ok(meta) if meta.is_file() => {}
            Ok(_) => anyhow::bail!(
                "database path is not openable because {} is not a file",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(Self::explain_missing_database(&path));
            }
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                anyhow::bail!(
                    "database path is not readable at {}: permission denied",
                    path.display()
                );
            }
            Err(error) => {
                anyhow::bail!(
                    "database path cannot be inspected at {}: {error}",
                    path.display()
                );
            }
        }
        let diagnostic_lock = Arc::new(files::DatabaseDiagnosticLock::try_acquire(&path)?);
        Self::open_read_only_diagnostic_impl(path, Some(diagnostic_lock))
    }

    fn explain_missing_database(path: &Path) -> anyhow::Error {
        for ancestor in path.ancestors().skip(1) {
            match ancestor.metadata() {
                Ok(meta) if !meta.is_dir() => {
                    return anyhow::anyhow!(
                        "database path is not openable because {} is not a directory",
                        ancestor.display()
                    );
                }
                Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                    return anyhow::anyhow!(
                        "database path is not readable because {} cannot be inspected: permission denied",
                        ancestor.display()
                    );
                }
                Ok(_) | Err(_) => {}
            }
        }
        anyhow::anyhow!("database does not exist at {}", path.display())
    }

    /// Inspect an explicitly supplied offline copy/snapshot. Unlike the
    /// canonical database path, a copied database has no ownership sidecar;
    /// the caller must opt into this API and the file is opened read-only.
    pub fn open_read_only_diagnostic_snapshot(path: &Path) -> Result<Self> {
        anyhow::ensure!(
            path.is_file(),
            "database snapshot does not exist at {}",
            path.display()
        );
        Self::open_read_only_diagnostic_impl(path.to_path_buf(), None)
    }

    fn open_read_only_diagnostic_impl(
        path: PathBuf,
        diagnostic_lock: Option<Arc<files::DatabaseDiagnosticLock>>,
    ) -> Result<Self> {
        let conn = Connection::open_with_flags(
            &path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .with_context(|| format!("opening SQLite read-only at {}", path.display()))?;
        verify_existing_database(&conn, MIGRATIONS)?;
        foreign_key_check(&conn).context("validating diagnostic foreign keys")?;
        let quick_check: String = conn
            .query_row("PRAGMA quick_check", [], |row| row.get(0))
            .context("running diagnostic SQLite quick_check")?;
        if quick_check != "ok" {
            anyhow::bail!("SQLite quick_check failed: {quick_check}");
        }
        Ok(Self {
            memory: Some(Arc::new(Mutex::new(conn))),
            writer: None,
            read_pool: None,
            path: Some(path),
            _owner_lock: None,
            _diagnostic_lock: diagnostic_lock,
            read_only: true,
            history_scope_gate: Arc::new(tokio::sync::RwLock::new(())),
            monty_network_egress_gate: Arc::new(tokio::sync::RwLock::new(())),
        })
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

    /// Acquire the shared history-disclosure fence. The permit must be held
    /// from the final authorization check through construction and return of
    /// the response. `set_workspace_history_scope` takes the exclusive fence
    /// before committing a consent mutation.
    pub async fn history_scope_disclosure_permit(&self) -> HistoryScopeDisclosurePermit {
        HistoryScopeDisclosurePermit {
            _guard: self.history_scope_gate.clone().read_owned().await,
        }
    }

    /// Acquire the shared durable Monty-network egress fence. The permit must
    /// be held from the final policy check through `RequestBuilder::send`.
    /// `mutate_monty_network_installation_policy` takes the exclusive side before
    /// committing any durable policy change.
    pub async fn monty_network_egress_permit(&self) -> MontyNetworkEgressPermit {
        MontyNetworkEgressPermit {
            _guard: self.monty_network_egress_gate.clone().read_owned().await,
        }
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
    pub async fn schema_version(&self) -> Result<i64> {
        self.read(sqlite_schema_version).await
    }

    /// Return the latest migration recorded by the legacy squashed-schema
    /// runner. This remains useful to read-only diagnostics until the
    /// checksum-backed migration ledger replaces `schema_version`.
    pub async fn applied_migration_version(&self) -> Result<i64> {
        self.read(current_schema_version).await
    }

    /// Return physical database accounting without mutating or checkpointing.
    ///
    /// This is safe for both the live daemon handle and the hidden read-only
    /// diagnostic opener. Missing WAL/SHM sidecars count as zero; all other
    /// metadata failures are surfaced so `doctor` cannot claim a complete
    /// report from partial evidence.
    pub async fn storage_report(&self) -> Result<DatabaseStorageReport> {
        let path = self.path.clone();
        self.read(move |conn| database_storage_report(conn, path.as_deref()))
            .await
    }

    /// Run SQLite's physical and relational integrity checks through the
    /// daemon-owned/read-only database handle used by diagnostics.
    pub async fn diagnostic_integrity_check(&self) -> Result<()> {
        self.read(|conn| {
            foreign_key_check(conn).context("running diagnostic foreign_key_check")?;
            let quick_check: String = conn
                .query_row("PRAGMA quick_check", [], |row| row.get(0))
                .context("running diagnostic SQLite quick_check")?;
            anyhow::ensure!(
                quick_check == "ok",
                "SQLite quick_check failed: {quick_check}"
            );
            Ok(())
        })
        .await
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
        if self.read_only {
            anyhow::bail!("read-only diagnostic database does not permit writes");
        }
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
        if self.read_only {
            anyhow::bail!("read-only diagnostic database does not permit transactions");
        }
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
    /// It is the permanent allowlisted blocking DB entrypoint for synchronous
    /// CLI one-shots; async code must use [`Self::read`], [`Self::write`], or
    /// [`Self::transaction`]. Temporary sync UI/event/maintenance wrappers
    /// below are owned for removal by `db-sync-wrapper-migration`.
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

    /// Blocking read access for synchronous TUI render/input edges.
    ///
    /// Temporary allowlisted boundary; owned for removal by
    /// `db-sync-wrapper-migration`. This uses the read pool for file-backed
    /// databases and never touches the writer connection. Async application
    /// code should still use [`Self::read`]; this exists for synchronous UI
    /// paths that cannot await while rendering or handling input.
    pub fn blocking_read_for_sync_ui<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T>,
    {
        self.read_blocking_unguarded(f)
    }

    /// Blocking write access for synchronous TUI input edges.
    ///
    /// Temporary allowlisted boundary; owned for removal by
    /// `db-sync-wrapper-migration`. TUI input handlers are synchronous but may
    /// need to persist settings after local file writes. Async application
    /// code should still use [`Self::write`].
    pub fn blocking_write_for_sync_ui<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.write_blocking_unguarded(f)
    }

    /// Blocking write access for synchronous event fanout callbacks.
    ///
    /// Temporary allowlisted boundary; owned for removal by
    /// `db-sync-wrapper-migration`. This is intentionally narrower than
    /// [`Self::blocking_for_sync_cli`]: it exists for call stacks that must
    /// synchronously broadcast an event and persist its audit row from a
    /// non-async callback.
    pub fn blocking_write_for_sync_event<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.write_blocking_unguarded(f)
    }

    /// Blocking write access for synchronous startup maintenance.
    ///
    /// Temporary allowlisted boundary; owned for removal by
    /// `db-sync-wrapper-migration`. Startup housekeeping is called before the
    /// daemon context is fully assembled, while some tests exercise it from an
    /// async harness. Keep this out of regular async code; prefer
    /// [`Self::write`] there.
    pub fn blocking_write_for_sync_maintenance<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        self.write_blocking_unguarded(f)
    }

    fn read_blocking_unguarded<F, T>(&self, f: F) -> Result<T>
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

    fn write_blocking_unguarded<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        if self.read_only {
            anyhow::bail!("read-only diagnostic database does not permit writes");
        }
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

/// An acquisition child has no resumable secret output. On process recovery,
/// every audit row left pending by a dropped runtime is therefore terminally
/// failed before the database is exposed to readers or a new acquisition.
fn reconcile_interrupted_sealed_value_acquisitions(conn: &Connection) -> Result<()> {
    conn.execute(
        "UPDATE sealed_value_acquisition_audit
            SET outcome = 'failed', completed_at_ms = ?1
          WHERE outcome = 'pending' AND completed_at_ms IS NULL",
        rusqlite::params![chrono::Utc::now().timestamp_millis()],
    )
    .context("reconciling interrupted sealed value acquisitions")?;
    Ok(())
}

// Canonical `BEGIN IMMEDIATE` transaction wrapper: rolls back on body error,
// COMMIT failure, and panic, chaining a rollback failure via
// `TransactionRollbackFailed` so the writer loop can poison a wedged
// connection. `task_delegations::immediate_transaction` deliberately mirrors
// this control flow (it only differs by carrying per-operation context
// strings) — keep the two in sync; a drift there is what reintroduced the
// COMMIT-failure leak once already.
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
                let primary = anyhow::Error::new(error).context("committing db transaction");
                match rollback_transaction(conn) {
                    Ok(()) => Err(primary),
                    Err(rollback) => Err(TransactionRollbackFailed { primary, rollback }.into()),
                }
            } else {
                Ok(value)
            }
        }
        Ok(Err(error)) => match rollback_transaction(conn) {
            Ok(()) => Err(error),
            Err(rollback) => Err(TransactionRollbackFailed {
                primary: error,
                rollback,
            }
            .into()),
        },
        Err(_) => {
            let primary = anyhow::anyhow!("db transaction job panicked");
            match rollback_transaction(conn) {
                Ok(()) => Err(primary),
                Err(rollback) => Err(TransactionRollbackFailed { primary, rollback }.into()),
            }
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
        // Durable daemon acknowledgements mean the WAL commit has crossed the
        // operating-system durability boundary. Do not inherit SQLite build or
        // environment defaults for this contract.
        conn.execute_batch(
            "PRAGMA synchronous = FULL;
             PRAGMA wal_autocheckpoint = 1000;
             PRAGMA journal_size_limit = 67108864;",
        )
        .context("setting SQLite durability policy")?;
        // `pragma_update` doesn't accept the kind of literal that
        // `journal_mode = WAL` needs; the query-row form does. The
        // return value is the resolved mode. A non-WAL result fails closed:
        // the read-pool and durability contracts rely on WAL semantics.
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .context("enabling WAL")?;
        anyhow::ensure!(
            journal_mode.eq_ignore_ascii_case("wal"),
            "file-backed SQLite database requires WAL journal mode; SQLite selected {journal_mode:?}"
        );
    }
    Ok(())
}

// ---- migration runner ------------------------------------------------------

/// An immutable, explicitly named schema migration. Names are part of the
/// checksum ledger contract and must describe the real file.
#[derive(Debug, Clone, Copy)]
struct Migration {
    name: &'static str,
    sql: &'static str,
    deferred_sql: &'static str,
    extension_sql: &'static str,
}

#[cfg(all(feature = "remote", feature = "extended"))]
const SCHEMA_PROFILE: &str = "remote-extended-v0.1";
#[cfg(all(feature = "remote", not(feature = "extended")))]
const SCHEMA_PROFILE: &str = "remote-v0.1";
#[cfg(all(not(feature = "remote"), feature = "extended"))]
const SCHEMA_PROFILE: &str = "extended-local-v0.1";
#[cfg(all(not(feature = "remote"), not(feature = "extended")))]
const SCHEMA_PROFILE: &str = "local-v0.1";

/// Stable diagnostic identifier for attempting to open one prerelease build
/// profile's database with the other profile. Profile transitions are not an
/// in-place migration in v0.1: opt-in remote builds must use a separate data
/// directory (or an explicit supported export/import flow).
pub const SCHEMA_PROFILE_MISMATCH_CODE: &str = "FCDB_SCHEMA_PROFILE_MISMATCH";
/// All schema migrations in version order. Pre-release: fold schema changes
/// into `0001_initial.sql`. Do not append `0002_*`.
const MIGRATIONS: &[Migration] = &[Migration {
    name: "0001_initial.sql",
    sql: include_str!("migrations/0001_initial.sql"),
    #[cfg(not(feature = "extended"))]
    deferred_sql: "",
    #[cfg(feature = "extended")]
    deferred_sql: include_str!("migrations/0001_extended_profile.sql"),
    #[cfg(not(feature = "remote"))]
    extension_sql: "",
    #[cfg(feature = "remote")]
    extension_sql: include_str!("migrations/0001_remote_profile.sql"),
}];

/// Latest schema version understood by this build.
///
/// Kept as a public compatibility constant for daemon protocol and diagnostics
/// consumers; the migration runner remains the source of truth.
pub const EXPECTED_SCHEMA_VERSION: i64 = MIGRATIONS.len() as i64;

fn schema_profile_mismatch(database_profile: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{SCHEMA_PROFILE_MISMATCH_CODE}: database schema profile is {database_profile}, binary requires {SCHEMA_PROFILE}; in-place local/remote profile transitions are unsupported in v0.1; use a separate data directory or a supported export/import flow"
    )
}

fn migrate(conn: &Connection) -> Result<()> {
    migrate_with(conn, MIGRATIONS)
}

fn migration_hash(sql: &str) -> String {
    Sha256::digest(sql.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn migration_definition_hash(migration: &Migration) -> String {
    // The checksum identifies the exact SQL applied by this build profile.
    // Omitting the extension made two materially different schemas share a
    // migration checksum and allowed an edited profile extension to pass the
    // ledger check.
    let mut definition = String::with_capacity(
        migration.sql.len() + migration.deferred_sql.len() + migration.extension_sql.len(),
    );
    definition.push_str(migration.sql);
    definition.push_str(migration.deferred_sql);
    definition.push_str(migration.extension_sql);
    migration_hash(&definition)
}

fn compiled_expected_fingerprint(migrations: &[Migration]) -> Result<String> {
    let expected = Connection::open_in_memory().context("opening expected-schema database")?;
    for migration in migrations {
        expected.execute_batch(migration.sql)?;
        expected.execute_batch(migration.deferred_sql)?;
        expected.execute_batch(migration.extension_sql)?;
    }
    expected.execute_batch(
        "CREATE TABLE schema_version (\
            version INTEGER PRIMARY KEY CHECK (version > 0), \
            name TEXT NOT NULL CHECK (length(name) > 0), \
            sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 = lower(sha256) AND sha256 NOT GLOB '*[^0-9a-f]*'), \
            schema_fingerprint TEXT NOT NULL CHECK (length(schema_fingerprint) = 64 AND schema_fingerprint = lower(schema_fingerprint) AND schema_fingerprint NOT GLOB '*[^0-9a-f]*'), \
            schema_profile TEXT NOT NULL CHECK (schema_profile IN ('local-v0.1', 'extended-local-v0.1', 'remote-v0.1', 'remote-extended-v0.1')), \
            applied_at TEXT NOT NULL\
        );",
    )?;
    exact_ddl_fingerprint(&expected)
}

/// Hash the exact persisted DDL text for every application-owned table,
/// index, trigger, and view. This is deliberately an exact-DDL fingerprint,
/// not a semantic schema hash: formatting or equivalent rewritten SQL is an
/// amended prerelease schema and requires controlled recovery.
fn exact_ddl_fingerprint(conn: &Connection) -> Result<String> {
    let mut stmt = conn.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') \
         FROM sqlite_schema \
         WHERE name NOT LIKE 'sqlite_%' \
         ORDER BY type, name, tbl_name",
    )?;
    let mut canonical = String::new();
    for row in stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
        ))
    })? {
        let (kind, name, table, sql) = row?;
        use std::fmt::Write as _;
        writeln!(&mut canonical, "{kind}\0{name}\0{table}\0{sql}")?;
    }
    Ok(migration_hash(&canonical))
}

fn is_lower_hex_64(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn verify_ledger(conn: &Connection, migrations: &[Migration]) -> Result<()> {
    let mut stmt = conn.prepare(
        "SELECT version, name, sha256, schema_fingerprint, schema_profile \
             FROM schema_version ORDER BY version",
    )?;
    for (idx, row) in stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })?
        .enumerate()
    {
        let expected_version = idx as i64 + 1;
        let (version, name, hash, fingerprint, profile) = row?;
        if version != expected_version {
            anyhow::bail!(
                "database migration ledger is corrupt: expected version {expected_version}, found {version}"
            );
        }
        if version > migrations.len() as i64 {
            anyhow::bail!(
                "incompatible prerelease database schema v{version}; this binary supports v{}. Restore a compatible migration backup or move the database aside and restart",
                migrations.len()
            );
        }
        if !is_lower_hex_64(&hash) || !is_lower_hex_64(&fingerprint) {
            anyhow::bail!(
                "database migration ledger is corrupt at version {version}: hashes must be 64 lowercase hexadecimal characters"
            );
        }
        let expected = &migrations[(version - 1) as usize];
        let expected_name = expected.name;
        let expected_hash = migration_definition_hash(expected);
        if name != expected_name || hash != expected_hash {
            anyhow::bail!(
                "migration checksum mismatch for {expected_name}: applied migration was amended"
            );
        }
        if profile != SCHEMA_PROFILE {
            return Err(schema_profile_mismatch(&profile));
        }
        if version == current_schema_version(conn)? && fingerprint != exact_ddl_fingerprint(conn)? {
            anyhow::bail!(
                "database schema fingerprint mismatch at migration {version}: schema objects were altered or are missing"
            );
        }
    }
    Ok(())
}

fn verify_user_version(conn: &Connection, ledger_version: i64) -> Result<()> {
    let user_version = sqlite_schema_version(conn)?;
    if user_version != ledger_version {
        anyhow::bail!(
            "database schema version is inconsistent: migration ledger is {ledger_version}, SQLite user_version is {user_version}"
        );
    }
    Ok(())
}

fn verify_existing_database(conn: &Connection, migrations: &[Migration]) -> Result<()> {
    verify_supported_ledger_shape(conn)?;
    verify_ledger(conn, migrations)?;
    let current = current_schema_version(conn)?;
    if current == 0 {
        anyhow::bail!("database migration ledger is empty");
    }
    verify_user_version(conn, current)?;
    if exact_ddl_fingerprint(conn)? != compiled_expected_fingerprint(migrations)? {
        anyhow::bail!(
            "database schema does not match the exact DDL compiled for schema profile {SCHEMA_PROFILE}"
        );
    }
    Ok(())
}

fn database_has_application_objects(conn: &Connection) -> Result<bool> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%')",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(|exists| exists != 0)
    .context("checking whether database is proven empty")
}

/// Apply pending migrations under one `BEGIN IMMEDIATE` writer lock.
///
/// Pending migration work runs with SQLite foreign-key enforcement
/// disabled, then validates with `PRAGMA foreign_key_check` before
/// commit. This is the runner-owned seam for SQLite table-rebuild
/// migrations; migration SQL must not emit `PRAGMA foreign_keys` itself
/// because that pragma is a no-op inside a transaction.
fn migrate_with(conn: &Connection, migrations: &[Migration]) -> Result<()> {
    verify_supported_ledger_shape(conn)?;
    if !table_exists(conn, "schema_version")? && database_has_application_objects(conn)? {
        anyhow::bail!(
            "unledgered prerelease database contains application schema objects; refusing to bootstrap over unproven data"
        );
    }
    let current_before_lock = current_schema_version(conn)?;
    if current_before_lock > migrations.len() as i64 {
        anyhow::bail!(
            "incompatible prerelease database schema v{current_before_lock}; this binary supports v{}. Restore a compatible migration backup or move the database aside and restart",
            migrations.len()
        );
    }

    let fk_was_on = foreign_keys_enabled(conn).context("reading foreign_keys pragma")?;
    set_foreign_keys(conn, false).context("disabling foreign_keys for migrations")?;

    let apply = (|| -> Result<()> {
        conn.execute_batch("BEGIN IMMEDIATE;")
            .context("database is busy applying migrations")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_version (\
                version INTEGER PRIMARY KEY CHECK (version > 0), \
                name TEXT NOT NULL CHECK (length(name) > 0), \
                sha256 TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 = lower(sha256) AND sha256 NOT GLOB '*[^0-9a-f]*'), \
                schema_fingerprint TEXT NOT NULL CHECK (length(schema_fingerprint) = 64 AND schema_fingerprint = lower(schema_fingerprint) AND schema_fingerprint NOT GLOB '*[^0-9a-f]*'), \
                schema_profile TEXT NOT NULL CHECK (schema_profile IN ('local-v0.1', 'extended-local-v0.1', 'remote-v0.1', 'remote-extended-v0.1')), \
                applied_at TEXT NOT NULL\
            );",
        )
        .context("creating schema_version table")?;

        verify_ledger(conn, migrations)?;
        let current = current_schema_version(conn)?;
        if current > 0 {
            verify_user_version(conn, current)?;
        }

        for (i, migration) in migrations.iter().enumerate() {
            let version = (i as i64) + 1;
            if version <= current {
                continue;
            }
            conn.execute_batch(migration.sql)
                .with_context(|| format!("applying migration {version}"))?;
            if !migration.deferred_sql.is_empty() {
                conn.execute_batch(migration.deferred_sql)
                    .with_context(|| format!("applying migration {version} deferred profile"))?;
            }
            if !migration.extension_sql.is_empty() {
                conn.execute_batch(migration.extension_sql)
                    .with_context(|| format!("applying migration {version} build profile"))?;
            }
            let fingerprint = exact_ddl_fingerprint(conn)?;
            conn.execute(
                "INSERT INTO schema_version (version, name, sha256, schema_fingerprint, schema_profile, applied_at) VALUES (?1, ?2, ?3, ?4, ?5, CURRENT_TIMESTAMP)",
                rusqlite::params![
                    version,
                    migration.name,
                    migration_definition_hash(migration),
                    fingerprint,
                    SCHEMA_PROFILE
                ],
            )
            .with_context(|| format!("recording migration {version}"))?;
        }

        conn.pragma_update(None, "user_version", migrations.len() as i64)?;
        verify_ledger(conn, migrations)?;
        verify_user_version(conn, migrations.len() as i64)?;
        let actual = exact_ddl_fingerprint(conn)?;
        let expected = compiled_expected_fingerprint(migrations)?;
        if actual != expected {
            anyhow::bail!(
                "database schema does not match the exact DDL compiled for schema profile {SCHEMA_PROFILE}"
            );
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

fn table_columns(conn: &Connection, table: &str) -> Result<Vec<String>> {
    let quoted = table.replace('"', "\"\"");
    let mut stmt = conn
        .prepare(&format!("PRAGMA table_info(\"{quoted}\");"))
        .with_context(|| format!("inspecting `{table}` columns"))?;
    stmt.query_map([], |row| row.get(1))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .with_context(|| format!("decoding `{table}` columns"))
}

fn legacy_schema_version(conn: &Connection) -> Result<i64> {
    conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )
    .context("reading legacy prerelease schema version")
}

fn verify_supported_ledger_shape(conn: &Connection) -> Result<()> {
    if !table_exists(conn, "schema_version")? {
        return Ok(());
    }
    let columns = table_columns(conn, "schema_version")?;
    const REQUIRED: &[&str] = &[
        "version",
        "name",
        "sha256",
        "schema_fingerprint",
        "schema_profile",
        "applied_at",
    ];
    let missing = REQUIRED
        .iter()
        .copied()
        .filter(|required| !columns.iter().any(|column| column == required))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        let version = legacy_schema_version(conn)?;
        anyhow::bail!(
            "incompatible legacy prerelease database schema v{version}: schema_version ledger is missing {}; move the database aside and restart to create the local v0.1 schema",
            missing.join(", ")
        );
    }
    Ok(())
}

fn current_schema_version(conn: &Connection) -> Result<i64> {
    if !table_exists(conn, "schema_version")? {
        return Ok(0);
    }
    let (count, minimum, maximum): (i64, Option<i64>, Option<i64>) = conn
        .query_row(
            "SELECT COUNT(*), MIN(version), MAX(version) FROM schema_version",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .context("reading current schema version")?;
    if count == 0 {
        return Ok(0);
    }
    let minimum = minimum.context("migration ledger has no minimum version")?;
    let maximum = maximum.context("migration ledger has no maximum version")?;
    if minimum != 1 || maximum != count {
        anyhow::bail!(
            "database migration ledger is corrupt: expected contiguous versions 1 through {count}, found {minimum} through {maximum}"
        );
    }
    Ok(maximum)
}

fn sqlite_schema_version(conn: &Connection) -> Result<i64> {
    conn.pragma_query_value(None, "user_version", |row| row.get(0))
        .context("reading SQLite schema version")
}

fn database_storage_report(
    conn: &Connection,
    path: Option<&Path>,
) -> Result<DatabaseStorageReport> {
    let nonnegative = |name: &str, value: i64| -> Result<u64> {
        u64::try_from(value).with_context(|| format!("SQLite {name} was negative: {value}"))
    };
    let page_size_bytes = nonnegative(
        "page_size",
        conn.pragma_query_value(None, "page_size", |row| row.get(0))
            .context("reading SQLite page_size")?,
    )?;
    let page_count = nonnegative(
        "page_count",
        conn.pragma_query_value(None, "page_count", |row| row.get(0))
            .context("reading SQLite page_count")?,
    )?;
    let freelist_page_count = nonnegative(
        "freelist_count",
        conn.pragma_query_value(None, "freelist_count", |row| row.get(0))
            .context("reading SQLite freelist_count")?,
    )?;
    anyhow::ensure!(
        freelist_page_count <= page_count,
        "SQLite freelist_count {freelist_page_count} exceeds page_count {page_count}"
    );
    let allocated_bytes = page_size_bytes
        .checked_mul(page_count)
        .context("SQLite allocated byte count overflow")?;
    let reclaimable_bytes = page_size_bytes
        .checked_mul(freelist_page_count)
        .context("SQLite reclaimable byte count overflow")?;

    let required_file_size = |candidate: &Path| -> Result<u64> {
        std::fs::metadata(candidate)
            .map(|metadata| metadata.len())
            .with_context(|| format!("reading database file size {}", candidate.display()))
    };
    let optional_sidecar_size = |candidate: &Path| -> Result<u64> {
        match std::fs::metadata(candidate) {
            Ok(metadata) => Ok(metadata.len()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => Err(error)
                .with_context(|| format!("reading database sidecar size {}", candidate.display())),
        }
    };
    let sidecar = |base: &Path, suffix: &str| {
        let mut name = base.as_os_str().to_os_string();
        name.push(suffix);
        PathBuf::from(name)
    };
    let (main_file_bytes, wal_file_bytes, shared_memory_file_bytes) = match path {
        Some(path) => (
            required_file_size(path)?,
            optional_sidecar_size(&sidecar(path, "-wal"))?,
            optional_sidecar_size(&sidecar(path, "-shm"))?,
        ),
        None => (0, 0, 0),
    };

    Ok(DatabaseStorageReport {
        page_size_bytes,
        page_count,
        freelist_page_count,
        allocated_bytes,
        reclaimable_bytes,
        live_bytes: allocated_bytes - reclaimable_bytes,
        main_file_bytes,
        wal_file_bytes,
        shared_memory_file_bytes,
    })
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
    use uuid::Uuid;

    fn migrate_test_with(conn: &Connection, sqls: &[&'static str]) -> Result<()> {
        const NAMES: &[&str] = &[
            "0001_test.sql",
            "0002_test.sql",
            "0003_test.sql",
            "0004_test.sql",
        ];
        assert!(sqls.len() <= NAMES.len());
        let migrations = sqls
            .iter()
            .enumerate()
            .map(|(index, sql)| Migration {
                name: NAMES[index],
                sql,
                deferred_sql: "",
                extension_sql: "",
            })
            .collect::<Vec<_>>();
        migrate_with(conn, &migrations)
    }

    #[test]
    fn opening_database_terminalizes_only_interrupted_acquisition_audits() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("interrupted-acquisition.db");
        let db = Db::open(&path).unwrap();
        db.blocking_for_sync_cli(|conn| {
            conn.execute_batch(
                "INSERT INTO sealed_value_acquisition_audit
                     (acquisition_id, record_id, session_id, project_key, name, description,
                      child_agent, consent_mode, outcome, created_at_ms, completed_at_ms)
                 VALUES
                     ('interrupted', 'record-interrupted', 'session-interrupted', 'project',
                      'interrupted_value', 'interrupted acquisition', 'sealed-acquisition',
                      'audit_only', 'pending', 1, NULL),
                     ('already-terminal', 'record-terminal', 'session-terminal', 'project',
                      'terminal_value', 'terminal acquisition', 'sealed-acquisition',
                      'audit_only', 'failed', 2, 77);",
            )?;
            Ok(())
        })
        .unwrap();
        drop(db);

        // This models a cancellation or runtime shutdown after publishing the
        // audit row. Reopen recovery runs before the DB can be observed again.
        let recovered = Db::open(&path).unwrap();
        let rows: Vec<(String, Option<i64>)> = recovered
            .blocking_for_sync_cli(|conn| {
                let mut statement = conn.prepare(
                    "SELECT outcome, completed_at_ms
                       FROM sealed_value_acquisition_audit
                      ORDER BY acquisition_id",
                )?;
                statement
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .collect::<rusqlite::Result<Vec<_>>>()
                    .map_err(anyhow::Error::from)
            })
            .unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0], ("failed".to_owned(), Some(77)));
        assert_eq!(rows[1].0, "failed");
        assert!(
            rows[1].1.is_some(),
            "recovery must terminalize the interrupted pending audit"
        );
    }

    #[test]
    fn storage_failure_contract_is_stable_through_context() {
        let cases = [
            (
                rusqlite::ErrorCode::DiskFull,
                DatabaseStorageFailure::Capacity,
                "FCDB_STORAGE_FULL",
            ),
            (
                rusqlite::ErrorCode::ReadOnly,
                DatabaseStorageFailure::ReadOnly,
                "FCDB_STORAGE_READ_ONLY",
            ),
            (
                rusqlite::ErrorCode::OutOfMemory,
                DatabaseStorageFailure::Memory,
                "FCDB_STORAGE_MEMORY",
            ),
            (
                rusqlite::ErrorCode::SystemIoFailure,
                DatabaseStorageFailure::Io,
                "FCDB_STORAGE_IO",
            ),
            (
                rusqlite::ErrorCode::DatabaseCorrupt,
                DatabaseStorageFailure::Corrupt,
                "FCDB_STORAGE_CORRUPT",
            ),
        ];
        for (code, expected, diagnostic_code) in cases {
            let sqlite = rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code,
                    extended_code: 0,
                },
                None,
            );
            let error = anyhow::Error::new(sqlite).context("writer commit failed");
            let classified = classify_database_storage_failure(error.as_ref());
            assert_eq!(classified, Some(expected));
            assert_eq!(classified.unwrap().diagnostic_code(), diagnostic_code);
        }
    }

    #[test]
    fn storage_report_requires_main_file_but_allows_absent_sidecars() {
        let temp = tempfile::tempdir().unwrap();
        let main = temp.path().join("snapshot.db");
        std::fs::write(&main, b"main").unwrap();
        let conn = Connection::open_in_memory().unwrap();

        let report = database_storage_report(&conn, Some(&main)).unwrap();
        assert_eq!(report.main_file_bytes, 4);
        assert_eq!(report.wal_file_bytes, 0);
        assert_eq!(report.shared_memory_file_bytes, 0);

        std::fs::remove_file(&main).unwrap();
        let error = database_storage_report(&conn, Some(&main)).unwrap_err();
        assert!(
            format!("{error:#}").contains("reading database file size"),
            "unexpected error: {error:#}"
        );
    }

    #[tokio::test]
    async fn rollback_failure_poison_closes_the_writer_queue() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("rollback-poison.db");
        let db = Db::open(&path).unwrap();
        let canonical = std::fs::canonicalize(&path).unwrap();
        force_rollback_failure_for_test(Some(canonical.to_string_lossy().into_owned()));

        let first: Result<()> = db
            .transaction(|_| anyhow::bail!("injected transaction failure"))
            .await;
        let error = first.unwrap_err();
        assert!(
            error.to_string().contains("rollback failed"),
            "the initiating request receives the poisoned rollback: {error:#}"
        );

        let queued = db
            .write(|conn| {
                conn.execute_batch("CREATE TABLE must_not_run(value INTEGER)")?;
                Ok(())
            })
            .await
            .unwrap_err();
        assert!(
            queued.to_string().contains("writer")
                || queued.to_string().contains("channel")
                || queued.to_string().contains("reply dropped"),
            "later queued work must fail closed after writer poison: {queued:#}"
        );
    }

    #[tokio::test]
    async fn migrate_idempotent() {
        let db = Db::open_in_memory().unwrap();
        // Second migrate call is a no-op.
        db.read(migrate).await.unwrap();
        let v: i64 = db
            .read(|conn| {
                Ok(
                    conn.query_row("SELECT MAX(version) FROM schema_version", [], |row| {
                        row.get(0)
                    })?,
                )
            })
            .await
            .unwrap();
        assert_eq!(v, MIGRATIONS.len() as i64);
        let ledger: (String, String) = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT name, sha256 FROM schema_version WHERE version = 1",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(ledger.0, "0001_initial.sql");
        assert!(!ledger.1.is_empty());
    }

    #[test]
    fn fixtures_migrate_forward_cleanly() {
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/schema");
        let fixture_paths: Vec<_> = std::fs::read_dir(&fixtures)
            .unwrap()
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| {
                path.extension()
                    .is_some_and(|extension| extension == "sqlite")
            })
            .collect();
        if fixture_paths.is_empty() {
            eprintln!(
                "skipping fixture upgrade test: no released schema fixtures exist before v0.1.0"
            );
            return;
        }
        for fixture in fixture_paths {
            let tmp = tempfile::tempdir().unwrap();
            let copy = tmp.path().join("fixture.sqlite");
            std::fs::copy(&fixture, &copy).unwrap();
            let conn = Connection::open(&copy).unwrap();
            migrate_with(&conn, MIGRATIONS).unwrap();
            assert_eq!(
                current_schema_version(&conn).unwrap(),
                MIGRATIONS.len() as i64
            );
            assert_eq!(
                sqlite_schema_version(&conn).unwrap(),
                MIGRATIONS.len() as i64
            );
            foreign_key_check(&conn).unwrap();
        }
    }

    #[test]
    fn runner_writes_user_version_mirror() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_with(&conn, MIGRATIONS).unwrap();
        assert_eq!(
            sqlite_schema_version(&conn).unwrap(),
            MIGRATIONS.len() as i64
        );
    }

    #[test]
    fn user_version_drift_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_with(&conn, MIGRATIONS).unwrap();
        conn.pragma_update(None, "user_version", 0).unwrap();
        let error = migrate_with(&conn, MIGRATIONS).unwrap_err().to_string();
        assert!(error.contains("user_version"), "unexpected error: {error}");
    }

    #[test]
    fn altered_schema_fingerprint_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_with(&conn, MIGRATIONS).unwrap();
        conn.execute_batch("DROP INDEX idx_sessions_parent;")
            .unwrap();
        let error = migrate_with(&conn, MIGRATIONS).unwrap_err().to_string();
        assert!(
            error.contains("schema fingerprint mismatch"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn amended_migration_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger.db");
        {
            let conn = Connection::open(&path).unwrap();
            migrate_with(&conn, MIGRATIONS).unwrap();
        }
        let conn = Connection::open(&path).unwrap();
        conn.execute(
            "UPDATE schema_version SET sha256 = ?1 WHERE version = 1",
            ["a".repeat(64)],
        )
        .unwrap();
        let error = migrate_with(&conn, MIGRATIONS).unwrap_err();
        assert!(error.to_string().contains("0001_initial.sql"));
    }

    /// The folded schema is the only schema definition. Applying only 0001
    /// must create the media reservation ledger; there is no runtime ALTER
    /// path for an older ledger.
    #[test]
    fn media_ledger_is_an_append_only_upgrade_for_existing_v2_databases() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_with(&conn, &MIGRATIONS[..1]).unwrap();
        assert_eq!(
            current_schema_version(&conn).unwrap(),
            1,
            "folded media ledger lives in 0001; there is no v2→v3 upgrade"
        );
        assert_eq!(MIGRATIONS.len(), 1, "squash leaves only 0001_initial.sql");
        conn.query_row("SELECT COUNT(*) FROM media_reservations", [], |_| Ok(()))
            .unwrap();
        conn.query_row("SELECT COUNT(*) FROM media_execution_ready", [], |_| Ok(()))
            .unwrap();
        let trigger: String = conn
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'trigger' AND name = 'media_reservation_state_graph'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(trigger, "media_reservation_state_graph");
    }

    #[test]
    fn legacy_schema_ledger_without_checksum_columns_fails_closed() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY);
             INSERT INTO schema_version (version) VALUES (1);",
        )
        .unwrap();

        let error = migrate_with(&conn, MIGRATIONS).unwrap_err().to_string();
        assert!(
            error.contains("no such column") || error.contains("schema_version"),
            "legacy schema must be rejected without ALTER/checksum repair: {error}"
        );
        let columns = conn
            .prepare("PRAGMA table_info(schema_version)")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(columns, vec!["version"]);
    }

    #[test]
    fn newer_database_is_refused() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_with(&conn, MIGRATIONS).unwrap();
        let fingerprint = exact_ddl_fingerprint(&conn).unwrap();
        let future_hash = migration_hash("future");
        conn.execute(
            "INSERT INTO schema_version (version, name, sha256, schema_fingerprint, schema_profile, applied_at) VALUES (2, 'future', ?1, ?2, ?3, 'now')",
            rusqlite::params![future_hash, fingerprint, SCHEMA_PROFILE],
        )
        .unwrap();
        assert!(
            migrate_with(&conn, MIGRATIONS)
                .unwrap_err()
                .to_string()
                .contains("incompatible prerelease database schema v2")
        );
    }

    #[test]
    fn future_v2_ledger_is_refused_not_recreated() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cockpit.db");
        {
            let conn = Connection::open(&path).unwrap();
            migrate_with(&conn, MIGRATIONS).unwrap();
            let fingerprint = exact_ddl_fingerprint(&conn).unwrap();
            let future_hash = migration_hash("future");
            conn.execute(
                "INSERT INTO schema_version (version, name, sha256, schema_fingerprint, schema_profile, applied_at)
                 VALUES (2, 'future', ?1, ?2, ?3, 'now')",
                rusqlite::params![future_hash, fingerprint, SCHEMA_PROFILE],
            )
            .unwrap();
        }
        let err = Db::open(&path).unwrap_err().to_string();
        assert!(
            err.contains("incompatible prerelease database schema v2"),
            "future v2 must fail closed, not recreate: {err}"
        );
        assert!(
            !temp
                .path()
                .read_dir()
                .unwrap()
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().contains("pre-0.1.0")),
            "future v2 must not be treated as a folded 0002–0005 ledger"
        );
    }

    #[test]
    fn second_migration_applies_to_existing_database() {
        let conn = Connection::open_in_memory().unwrap();
        let first = "CREATE TABLE first_migration (id INTEGER PRIMARY KEY);";
        let second = "CREATE TABLE second_migration (id INTEGER PRIMARY KEY);";
        migrate_test_with(&conn, &[first]).unwrap();
        migrate_test_with(&conn, &[first, second]).unwrap();
        assert_eq!(current_schema_version(&conn).unwrap(), 2);
        assert_eq!(sqlite_schema_version(&conn).unwrap(), 2);
        let names = conn
            .prepare("SELECT name FROM schema_version ORDER BY version")
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(names, vec!["0001_test.sql", "0002_test.sql"]);
    }

    /// Pre-release DBs are recreated; the old v1 `status` column and 0002
    /// upgrade INSERT are rejected. A fresh 0001 schema already has
    /// disposition/phase plus control-job tables, and a new goal leases a
    /// planner before any root turn.
    #[tokio::test]
    async fn goal_upgrade_preserves_v1_rows_and_validates_migration_ledger() {
        let db = Db::open_in_memory().unwrap();
        let columns: Vec<String> = db
            .read(|conn| {
                let mut stmt = conn.prepare("PRAGMA table_info(session_goals)")?;
                let names = stmt
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(names)
            })
            .await
            .unwrap();
        assert!(
            columns.iter().any(|name| name == "disposition"),
            "folded session_goals must have disposition: {columns:?}"
        );
        assert!(
            columns.iter().any(|name| name == "phase"),
            "folded session_goals must have phase: {columns:?}"
        );
        assert!(
            !columns.iter().any(|name| name == "status"),
            "v1 status column must not exist after the 0002 fold: {columns:?}"
        );
        let tables: Vec<String> = db
            .read(|conn| {
                let mut stmt = conn.prepare(
                    "SELECT name FROM sqlite_master WHERE type = 'table'
                     AND name IN ('goal_control_jobs', 'goal_root_turns')
                     ORDER BY name",
                )?;
                let names = stmt
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok(names)
            })
            .await
            .unwrap();
        assert_eq!(
            tables,
            vec![
                "goal_control_jobs".to_string(),
                "goal_root_turns".to_string()
            ]
        );

        let session = db
            .create_session("project-v1", "/tmp/v1", "Build")
            .await
            .unwrap();
        let created = db
            .create_session_goal(
                session.session_id,
                &session.project_id,
                "preserve me",
                Some("legacy context"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(
            created.disposition,
            crate::db::session_goals::GoalDisposition::Running
        );
        assert_eq!(
            created.phase,
            Some(crate::db::session_goals::GoalPhase::Planning)
        );
        assert_eq!(created.objective, "preserve me");
        assert_eq!(created.context.as_deref(), Some("legacy context"));
        assert_eq!(created.token_budget, 200_000);

        let (schema, mirror) = db
            .read(|conn| Ok((current_schema_version(conn)?, sqlite_schema_version(conn)?)))
            .await
            .unwrap();
        assert_eq!(schema, MIGRATIONS.len() as i64);
        assert_eq!(mirror, MIGRATIONS.len() as i64);
        db.read(foreign_key_check).await.unwrap();
        db.write(|conn| migrate_with(conn, MIGRATIONS))
            .await
            .unwrap();
        let ledger_rows: i64 = db
            .read(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM schema_version", [], |row| row.get(0))?)
            })
            .await
            .unwrap();
        assert_eq!(ledger_rows, MIGRATIONS.len() as i64);

        let planner = db
            .lease_goal_control_job(created.id, created.attempt_generation, 30, 60)
            .await
            .unwrap()
            .expect("a fresh goal must register a planner");
        assert_eq!(
            planner.role,
            crate::db::session_goals::GoalControlRole::Planner
        );
        assert!(
            db.begin_goal_root_turn(created.id, created.attempt_generation)
                .await
                .is_err(),
            "a goal cannot dispatch root work before planner acceptance"
        );
    }

    /// Goal provenance lives on the 0001 `CREATE TABLE inference_requests`,
    /// not a later ALTER. Applying only 0001 must expose the columns + index,
    /// and a production insert that sets them must round-trip.
    #[tokio::test]
    async fn inference_requests_goal_provenance_is_in_0001_create() {
        let conn = Connection::open_in_memory().unwrap();
        migrate_with(&conn, &MIGRATIONS[..1]).unwrap();
        let columns: Vec<String> = {
            let mut stmt = conn
                .prepare("PRAGMA table_info(inference_requests)")
                .unwrap();
            stmt.query_map([], |row| row.get::<_, String>(1))
                .unwrap()
                .collect::<rusqlite::Result<Vec<_>>>()
                .unwrap()
        };
        assert!(
            columns.iter().any(|name| name == "goal_id"),
            "0001 CREATE must include goal_id: {columns:?}"
        );
        assert!(
            columns.iter().any(|name| name == "goal_attempt_generation"),
            "0001 CREATE must include goal_attempt_generation: {columns:?}"
        );
        let index_sql: String = conn
            .query_row(
                "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'idx_ireq_goal_provenance'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            index_sql.contains("goal_id") && index_sql.contains("goal_attempt_generation"),
            "idx_ireq_goal_provenance missing provenance columns: {index_sql}"
        );

        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/tmp/ireq", "Build").await.unwrap();
        let goal = db
            .create_session_goal(session.session_id, &session.project_id, "ship", None, None)
            .await
            .unwrap();
        let call_id = Uuid::new_v4().to_string();
        db.insert_inference_request(
            &call_id,
            0,
            session.session_id,
            &serde_json::json!({}),
            crate::db::session_log::InferenceAttemptMeta::default(),
            Some((goal.id, goal.attempt_generation)),
        )
        .await
        .unwrap();
        let stored: (String, i64) = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT goal_id, goal_attempt_generation FROM inference_requests WHERE call_id = ?1",
                    rusqlite::params![call_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(stored.0, goal.id.to_string());
        assert_eq!(stored.1, goal.attempt_generation);
    }

    #[tokio::test]
    async fn connection_pragmas_set_busy_timeout_to_five_seconds() {
        let db = Db::open_in_memory().unwrap();
        let timeout_ms: i64 = db
            .read(|conn| Ok(conn.query_row("PRAGMA busy_timeout;", [], |row| row.get(0))?))
            .await
            .unwrap();
        assert_eq!(timeout_ms, 5000);
    }

    #[tokio::test]
    async fn db_async_ops_schema_version_available_through_async_api() {
        let db = Db::open_in_memory().unwrap();
        assert_eq!(db.schema_version().await.unwrap(), MIGRATIONS.len() as i64);
    }

    #[test]
    fn db_async_ops_accessor_layer_has_no_blocking_calls() {
        // Mechanical substring guard for accessor modules. The semantic
        // AST/call-graph gate lives in `tests/db_blocking_boundary_gate.rs`
        // (db-blocking-api-removal) and is authoritative for public reachability.
        let db_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src").join("db");
        let mut stack = vec![db_dir];
        while let Some(path) = stack.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let entry = entry.unwrap();
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                    continue;
                }
                if path.file_name().and_then(|name| name.to_str()) == Some("mod.rs") {
                    continue;
                }
                let source = std::fs::read_to_string(&path).unwrap();
                assert!(
                    !source.contains("read_blocking(") && !source.contains("write_blocking("),
                    "blocking DB accessor token remains in {}",
                    path.display()
                );
            }
        }
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
        drop(Db::open(&path).unwrap());
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
        drop(Db::open(&path).unwrap());
        let seed = Connection::open(&path).unwrap();
        let _: String = seed
            .query_row("PRAGMA journal_mode = WAL;", [], |row| row.get(0))
            .unwrap();
        seed.execute("UPDATE schema_version SET applied_at = applied_at", [])
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn panicking_read_returns_error_and_pool_keeps_serving() {
        use std::sync::Arc;

        let tmp = TempDir::new().unwrap();
        let db = Arc::new(Db::open(&tmp.path().join("read-panic.db")).unwrap());
        db.write(|conn| {
            conn.execute_batch("CREATE TABLE after_read_panic (value INTEGER NOT NULL);")?;
            conn.execute("INSERT INTO after_read_panic (value) VALUES (7)", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let err = db
            .read(|_conn| -> Result<i64> { panic!("intentional db read panic") })
            .await
            .unwrap_err();
        assert!(err.to_string().contains("panicked"));

        let num_readers = 8;
        let mut handles = Vec::with_capacity(num_readers);
        for _ in 0..num_readers {
            let db = db.clone();
            handles.push(tokio::spawn(async move {
                let value: i64 = db
                    .read(|conn| {
                        Ok(
                            conn.query_row("SELECT value FROM after_read_panic", [], |row| {
                                row.get(0)
                            })?,
                        )
                    })
                    .await
                    .unwrap();
                value
            }));
        }
        for handle in handles {
            assert_eq!(handle.await.unwrap(), 7);
        }
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn read_pool_saturated_concurrent_readers_do_not_hang() {
        use std::sync::Arc;
        use std::time::Duration;

        let tmp = TempDir::new().unwrap();
        let db = Arc::new(Db::open(&tmp.path().join("pool-stress.db")).unwrap());
        db.write(|conn| {
            conn.execute_batch("CREATE TABLE pool_stress (value INTEGER NOT NULL);")?;
            conn.execute("INSERT INTO pool_stress (value) VALUES (42)", [])?;
            Ok(())
        })
        .await
        .unwrap();

        let stress = async {
            let num_readers = 8;
            let iterations = 100;
            let mut handles = Vec::with_capacity(num_readers);
            for _ in 0..num_readers {
                let db = db.clone();
                handles.push(tokio::spawn(async move {
                    for _ in 0..iterations {
                        let value: i64 = db
                            .read(|conn| {
                                Ok(conn.query_row("SELECT value FROM pool_stress", [], |row| {
                                    row.get(0)
                                })?)
                            })
                            .await
                            .unwrap();
                        assert_eq!(value, 42);
                    }
                }));
            }
            for handle in handles {
                handle.await.unwrap();
            }
        };

        tokio::time::timeout(Duration::from_secs(30), stress)
            .await
            .expect("read pool stress test hung");
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
        let (read_done_tx, read_done_rx) = mpsc::sync_channel(1);
        let slow_db = db.clone();
        let writer = tokio::spawn(async move {
            slow_db
                .write(move |conn| {
                    conn.execute_batch("BEGIN IMMEDIATE;")?;
                    let _ = entered_tx.send(());
                    read_done_rx
                        .recv_timeout(Duration::from_secs(2))
                        .expect("reader should observe the open write transaction");
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
        let _ = read_done_tx.send(());
        writer.await.unwrap().unwrap();
    }

    #[test]
    fn busy_timeout_waits_for_short_write_contention() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("busy.db");
        let db_a = Db::open(&path).unwrap();
        let db_b = Db::open(&path).unwrap();

        db_a.blocking_for_sync_cli(move |conn| {
            conn.execute_batch(
                "CREATE TABLE busy_probe (id INTEGER PRIMARY KEY, value TEXT NOT NULL);",
            )?;
            Ok(())
        })
        .unwrap();

        db_a.blocking_for_sync_cli(move |conn| {
            conn.execute_batch("BEGIN IMMEDIATE;")?;
            conn.execute("INSERT INTO busy_probe (value) VALUES ('held')", [])?;
            Ok(())
        })
        .unwrap();

        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let writer = std::thread::spawn(move || {
            let result = db_b.blocking_for_sync_cli(move |conn| {
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

        db_a.blocking_for_sync_cli(move |conn| {
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
            .blocking_for_sync_cli(|conn| {
                Ok(conn.query_row("SELECT COUNT(*) FROM busy_probe", [], |row| row.get(0))?)
            })
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn migration_waits_for_lock_then_skips_already_applied_versions() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("migrate-wait.db");
        // The ledger is checksum-backed: `schema_version` records the name and
        // sha256 of each applied migration, and `verify_ledger` reads those
        // columns. Seed version 1 in that current shape (matching the name the
        // test runner assigns and the hash of its SQL) so the second migrator
        // recognizes it as already applied and skips it rather than re-running
        // `CREATE TABLE migration_probe`.
        const PROBE_SQL: &str = "CREATE TABLE migration_probe (id INTEGER PRIMARY KEY);";
        let conn_a = Connection::open(&path).unwrap();
        apply_connection_pragmas(&conn_a, true).unwrap();
        migrate_test_with(&conn_a, &[PROBE_SQL]).unwrap();
        conn_a.execute_batch("BEGIN IMMEDIATE;").unwrap();

        let path_for_thread = path.clone();
        let (tx, rx) = mpsc::channel();
        let started = Instant::now();
        let waiter = std::thread::spawn(move || {
            let conn_b = Connection::open(path_for_thread).unwrap();
            apply_connection_pragmas(&conn_b, true).unwrap();
            let result = migrate_test_with(&conn_b, &[PROBE_SQL]);
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
        let err = migrate_test_with(
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

        migrate_test_with(
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

        let err = migrate_test_with(
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

        migrate_test_with(&conn, &[first]).unwrap();
        let err = migrate_test_with(&conn, &[first, violating_second]).unwrap_err();
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

        let err = migrate_test_with(
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

        migrate_test_with(&conn, migrations).unwrap();
        set_foreign_keys(&conn, false).unwrap();

        migrate_test_with(&conn, migrations).unwrap();

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

        migrate_test_with(
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

    #[tokio::test]
    async fn essential_tables_exist() {
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
                .read(move |conn| {
                    Ok(conn.query_row(
                        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |row| row.get(0),
                    )?)
                })
                .await
                .unwrap();
            assert_eq!(count, 1, "table `{table}` missing");
        }
        // And the view.
        let view_count: i64 = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='view' AND name='tool_call_stats'",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(view_count, 1);
    }

    #[tokio::test]
    async fn approval_grants_has_risk_tier_column() {
        let db = Db::open_in_memory().unwrap();
        let columns: Vec<(String, String)> = db
            .read(|conn| {
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
            .await
            .unwrap();

        assert!(
            columns
                .iter()
                .any(|(name, ty)| name == "risk_tier" && ty == "TEXT"),
            "approval_grants.risk_tier TEXT column missing; columns were {columns:?}"
        );
    }

    #[tokio::test]
    async fn approval_grants_allows_mcp_tool_kind_with_null_access() {
        let db = Db::open_in_memory().unwrap();
        let session_id = uuid::Uuid::new_v4().to_string();

        db.write(move |conn| {
            conn.execute(
                "INSERT INTO sessions \
                 (session_id, project_id, project_root, started_at_unix_ms, last_active_at_unix_ms) \
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
        .await
        .unwrap();
    }

    fn has_cascade_path_to_sessions(
        conn: &Connection,
        table: &str,
        visiting: &mut std::collections::HashSet<String>,
    ) -> Result<bool> {
        if table == "sessions" {
            return Ok(true);
        }
        if !visiting.insert(table.to_string()) {
            return Ok(false);
        }
        let mut foreign_keys = conn.prepare(&format!("PRAGMA foreign_key_list({table})"))?;
        let parents = foreign_keys
            .query_map([], |row| {
                Ok((row.get::<_, String>(2)?, row.get::<_, String>(6)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        for (parent, on_delete) in parents {
            if on_delete.eq_ignore_ascii_case("cascade")
                && has_cascade_path_to_sessions(conn, &parent, visiting)?
            {
                visiting.remove(table);
                return Ok(true);
            }
        }
        visiting.remove(table);
        Ok(false)
    }

    fn session_tables_missing_cascade(conn: &Connection) -> Result<Vec<String>> {
        let mut tables = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let names = tables.query_map([], |row| row.get::<_, String>(0))?;
        let mut missing = Vec::new();
        for name in names {
            let name = name?;
            let mut columns = conn.prepare(&format!("PRAGMA table_info({name})"))?;
            let has_session_id = columns
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?
                .iter()
                .any(|column| column == "session_id");
            if !has_session_id || name == "sessions" {
                continue;
            }
            // Run invocations retain durable receipts after session deletion
            // (cancelled_session_deleted terminalization; no FK cascade).
            // Tombstones are global UUID receipts with no session column FK.
            // Monetary reservations and debt are immutable billing receipts;
            // deleting a session must not erase spend or unblock its scopes.
            // Sidecar intents outlive the session row so boot can delete
            // files that the cascading payload delete can no longer see.
            // Text-artifact blob cleanup intents follow the same contract:
            // every blob identity is preserved before the cascade so replayed
            // filesystem cleanup work survives the session delete.
            // Sealed action/value audit rows deliberately carry no FKs:
            // retiring an action or deleting a session must not erase evidence.
            // Guidance proposal receipts are content-free audit rows that
            // may outlive the session during retention (session_id is not a FK).
            // Image-sidecar grants are project-owned; session_id is an optional
            // external binding, not a cascading session relationship.
            // Tool-media authorization epochs treat session_id as identity,
            // not a cascade: invalidation is an explicit epoch bump.
            if name == "run_invocations"
                || name == "run_invocation_tombstones"
                || name == "image_spend_reservations"
                || name == "task_delegation_sidecar_cleanup_intents"
                || name == "task_delegation_sidecar_prepare_intents"
                || name == "text_artifact_blob_cleanup_intents"
                || name == "sealed_action_invocation_audit"
                || name == "sealed_value_acquisition_audit"
                || name == "guidance_proposal_receipts"
                || name == "image_sidecar_grants"
                || name == "tool_media_authorization_epochs"
            {
                continue;
            }
            if !has_cascade_path_to_sessions(conn, &name, &mut std::collections::HashSet::new())? {
                missing.push(name);
            }
        }
        Ok(missing)
    }

    #[tokio::test]
    async fn every_session_scoped_table_cascades() {
        let db = Db::open_in_memory().unwrap();
        let missing = db.read(session_tables_missing_cascade).await.unwrap();
        assert!(
            missing.is_empty(),
            "session-scoped tables without cascading FK: {missing:?}"
        );
        db.write(|conn| {
            conn.execute_batch(
                "CREATE TABLE unprotected_session_fixture (session_id TEXT NOT NULL)",
            )?;
            assert_eq!(
                session_tables_missing_cascade(conn)?,
                vec!["unprotected_session_fixture"]
            );
            conn.execute_batch("DROP TABLE unprotected_session_fixture")?;
            Ok(())
        })
        .await
        .unwrap();
    }

    fn schema_check_values(conn: &Connection, table: &str, column: &str) -> Result<Vec<String>> {
        let sql: String = conn.query_row(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?1",
            [table],
            |row| row.get(0),
        )?;
        let marker = format!("CHECK ({column} IN (");
        let values = sql
            .split_once(&marker)
            .and_then(|(_, tail)| tail.split_once("))"))
            .map(|(body, _)| {
                body.split('\'')
                    .skip(1)
                    .step_by(2)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .ok_or_else(|| anyhow::anyhow!("missing closed CHECK for {table}.{column}"))?;
        Ok(values)
    }

    #[tokio::test]
    async fn rust_enums_and_schema_checks_have_identical_vocabularies() {
        let db = Db::open_in_memory().unwrap();
        db.read(|conn| {
            let cases: Vec<(&str, &str, Vec<&str>)> = vec![
                (
                    "needs_attention",
                    "state",
                    crate::db::needs_attention::InterruptState::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "inference_requests",
                    "status",
                    crate::db::session_log::InferenceRequestStatus::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "tandem_inference",
                    "status",
                    crate::db::session_log::InferenceRequestStatus::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "session_events",
                    "type",
                    crate::db::session_log::SessionEventKind::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "session_goals",
                    "disposition",
                    crate::db::session_goals::GoalDisposition::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "task_todos",
                    "status",
                    crate::db::task_todos::TodoStatus::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "task_todo_notes",
                    "kind",
                    crate::db::task_todos::TodoNoteKind::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "task_delegation_jobs",
                    "status",
                    crate::db::task_delegations::DelegationStatus::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "task_delegation_children",
                    "status",
                    crate::db::task_delegations::DelegationStatus::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "paused_session_work",
                    "status",
                    crate::db::paused_work::PausedWorkStatus::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
                (
                    "packages",
                    "source_type",
                    crate::db::packages::SourceType::ALL
                        .iter()
                        .map(|value| value.as_str())
                        .collect(),
                ),
            ];
            for (table, column, expected) in cases {
                assert_eq!(
                    schema_check_values(conn, table, column)?,
                    expected,
                    "schema vocabulary drift for {table}.{column}"
                );
            }
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn foreign_keys_enforced_on_open() {
        let db = Db::open_in_memory().unwrap();
        let enabled: i64 = db
            .read(|conn| {
                conn.query_row("PRAGMA foreign_keys", [], |row| row.get(0))
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(enabled, 1);
    }

    #[tokio::test]
    async fn session_delete_cascades_to_retained_local_children() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/p", "Build").await.unwrap();
        db.insert_session_event(
            session.session_id,
            crate::db::session_log::SessionEventKind::UserNote,
            Some("Build"),
            None,
            &serde_json::json!({ "text": "local child" }),
        )
        .await
        .unwrap();

        db.delete_session(session.session_id).await.unwrap();
        let remaining: i64 = db
            .read(|conn| {
                conn.query_row("SELECT COUNT(*) FROM session_events", [], |row| row.get(0))
                    .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(remaining, 0, "retained local child rows must cascade");
    }

    #[tokio::test]
    #[cfg(feature = "remote")]
    async fn session_delete_cascades_to_remote_audit_extension() {
        let db = Db::open_in_memory().unwrap();
        let session_id = Uuid::new_v4();
        let id = session_id.to_string();
        db.write(move |conn| {
            conn.execute("INSERT INTO sessions (session_id, project_id, project_root, started_at_unix_ms, last_active_at_unix_ms) VALUES (?1, 'p', '/p', 1, 1)", [&id])?;
            conn.execute("INSERT INTO remote_principal_audit (ts_ms, principal, request_kind, session_id, verdict) VALUES (1, 'p', 'request', ?1, 'allowed')", [&id])?;
            Ok(())
        }).await.unwrap();
        db.delete_session(session_id).await.unwrap();
        let remaining: i64 = db
            .read(|conn| {
                conn.query_row("SELECT COUNT(*) FROM remote_principal_audit", [], |row| {
                    row.get(0)
                })
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(remaining, 0);
    }

    fn session_foreign_keys_missing_index(conn: &Connection) -> Result<Vec<String>> {
        let mut tables = conn.prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
        )?;
        let names = tables.query_map([], |row| row.get::<_, String>(0))?;
        let mut missing = Vec::new();
        for name in names {
            let name = name?;
            let mut foreign_keys = conn.prepare(&format!("PRAGMA foreign_key_list({name})"))?;
            let has_session_cascade = foreign_keys
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(6)?,
                    ))
                })?
                .collect::<std::result::Result<Vec<_>, _>>()?
                .iter()
                .any(|(table, from, on_delete)| {
                    table == "sessions"
                        && from == "session_id"
                        && on_delete.eq_ignore_ascii_case("cascade")
                });
            if !has_session_cascade {
                continue;
            }
            let mut indexes = conn.prepare(&format!("PRAGMA index_list({name})"))?;
            let index_names = indexes
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            let indexed = index_names.into_iter().any(|index| {
                conn.prepare(&format!("PRAGMA index_info({index})"))
                    .and_then(|mut info| {
                        info.query_map([], |row| row.get::<_, String>(2))?
                            .collect::<std::result::Result<Vec<_>, _>>()
                    })
                    .map(|columns| columns.first().is_some_and(|column| column == "session_id"))
                    .unwrap_or(false)
            });
            if !indexed {
                missing.push(name);
            }
        }
        Ok(missing)
    }

    #[tokio::test]
    async fn session_foreign_keys_are_indexed() {
        let db = Db::open_in_memory().unwrap();
        let missing = db.read(session_foreign_keys_missing_index).await.unwrap();
        assert!(
            missing.is_empty(),
            "session cascading foreign keys without indexes: {missing:?}"
        );
    }

    #[tokio::test]
    async fn session_delete_removes_delegation_sidecars() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session_id = Uuid::new_v4();
        let id = session_id.to_string();
        let relative = format!("delegation_payloads/{id}/payload.txt");
        let sidecar = tmp.path().join(&relative);
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(&sidecar, "payload").unwrap();
        let relative_for_db = relative.clone();
        db.write(move |conn| {
            conn.execute("INSERT INTO sessions (session_id, project_id, project_root, started_at_unix_ms, last_active_at_unix_ms) VALUES (?1, 'p', '/p', 1, 1)", [&id])?;
            conn.execute("INSERT INTO task_delegation_jobs (task_call_id, parent_session_id, parent_agent, status, created_at, updated_at) VALUES ('task', ?1, 'agent', 'completed', 1, 1)", [&id])?;
            conn.execute("INSERT INTO task_delegation_payloads (task_call_id, label, payload_hash, parent_session_id, parent_agent, child_agent, prompt_byte_len, sidecar_path, created_at) VALUES ('task', 'default', 'hash', ?1, 'agent', 'child', 7, ?2, 1)", rusqlite::params![id, relative_for_db])?;
            Ok(())
        }).await.unwrap();
        db.delete_session(session_id).await.unwrap();
        assert!(!sidecar.exists());
    }

    #[tokio::test]
    async fn delegation_sidecar_cleanup_intent_survives_delete_commit() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session_id = Uuid::new_v4();
        let id = session_id.to_string();
        let relative = format!("delegation_payloads/{id}/recovery.txt");
        let sidecar = tmp.path().join(&relative);
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(&sidecar, "payload").unwrap();
        db.write({
            let id = id.clone();
            let relative = relative.clone();
            move |conn| {
                conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at_unix_ms,last_active_at_unix_ms) VALUES(?1,'p','/p',1,1)",[&id])?;
                conn.execute("INSERT INTO task_delegation_jobs(task_call_id,parent_session_id,parent_agent,status,created_at,updated_at) VALUES('task',?1,'agent','completed',1,1)",[&id])?;
                conn.execute("INSERT INTO task_delegation_payloads(task_call_id,label,payload_hash,parent_session_id,parent_agent,child_agent,prompt_byte_len,sidecar_path,created_at) VALUES('task','default','hash',?1,'agent','child',7,?2,1)",rusqlite::params![id,relative])?;
                Db::enqueue_delegation_sidecar_cleanup_conn(conn, session_id, 2)?;
                Db::delete_existing_session_row_conn(conn, session_id)?;
                Ok(())
            }
        }).await.unwrap();
        assert!(sidecar.exists(), "commit precedes external cleanup");
        let pending = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM task_delegation_sidecar_cleanup_intents",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(pending, 1);
        assert_eq!(
            db.reconcile_delegation_sidecar_cleanup_intents()
                .await
                .unwrap(),
            1
        );
        assert!(!sidecar.exists());
    }

    #[tokio::test]
    async fn delegation_sidecar_cleanup_refuses_a_current_payload_reference() {
        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let session_id = Uuid::new_v4();
        let id = session_id.to_string();
        let relative = format!("delegation_payloads/{id}/generation.txt");
        let sidecar = tmp.path().join(&relative);
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(&sidecar, "current").unwrap();
        db.write({
            let id = id.clone();
            let relative = relative.clone();
            move |conn| {
                conn.execute("INSERT INTO sessions(session_id,project_id,project_root,started_at_unix_ms,last_active_at_unix_ms) VALUES(?1,'p','/p',1,1)",[&id])?;
                conn.execute("INSERT INTO task_delegation_jobs(task_call_id,parent_session_id,parent_agent,status,created_at,updated_at) VALUES('task',?1,'agent','completed',1,1)",[&id])?;
                conn.execute("INSERT INTO task_delegation_payloads(task_call_id,label,payload_hash,parent_session_id,parent_agent,child_agent,prompt_byte_len,sidecar_path,created_at) VALUES('task','default','hash',?1,'agent','child',7,?2,1)",rusqlite::params![id,relative])?;
                conn.execute("INSERT INTO task_delegation_sidecar_cleanup_intents(sidecar_path,session_id,created_at_unix_ms) VALUES(?1,?2,2)",rusqlite::params![relative,id])?;
                Ok(())
            }
        }).await.unwrap();

        assert_eq!(
            db.reconcile_delegation_sidecar_cleanup_intents()
                .await
                .unwrap(),
            0
        );
        assert!(
            sidecar.exists(),
            "a current payload reference protects its sidecar"
        );
        db.write(move |conn| {
            conn.execute(
                "DELETE FROM task_delegation_payloads WHERE sidecar_path=?1",
                [relative],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            db.reconcile_delegation_sidecar_cleanup_intents()
                .await
                .unwrap(),
            1
        );
        assert!(!sidecar.exists());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn delegation_sidecar_cleanup_retains_intent_when_parent_fsync_fails() {
        struct ResetSyncFailure;
        impl Drop for ResetSyncFailure {
            fn drop(&mut self) {
                crate::db::files::force_sidecar_parent_sync_failure_for_test(None);
            }
        }

        let tmp = TempDir::new().unwrap();
        let db = Db::open(&tmp.path().join("cockpit.db")).unwrap();
        let relative = "delegation_payloads/orphan/generation.txt".to_string();
        let sidecar = tmp.path().join(&relative);
        std::fs::create_dir_all(sidecar.parent().unwrap()).unwrap();
        std::fs::write(&sidecar, "orphan").unwrap();
        db.write({
            let relative = relative.clone();
            move |conn| {
                conn.execute("INSERT INTO task_delegation_sidecar_cleanup_intents(sidecar_path,session_id,created_at_unix_ms) VALUES(?1,?2,2)",rusqlite::params![relative,Uuid::new_v4().to_string()])?;
                Ok(())
            }
        }).await.unwrap();

        let _reset = ResetSyncFailure;
        crate::db::files::force_sidecar_parent_sync_failure_for_test(Some(
            sidecar.parent().unwrap().to_path_buf(),
        ));
        assert_eq!(
            db.reconcile_delegation_sidecar_cleanup_intents()
                .await
                .unwrap(),
            0
        );
        let pending = db
            .read(|conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM task_delegation_sidecar_cleanup_intents",
                    [],
                    |row| row.get::<_, i64>(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(pending, 1, "uncertain unlink durability retains the intent");

        crate::db::files::force_sidecar_parent_sync_failure_for_test(None);
        assert_eq!(
            db.reconcile_delegation_sidecar_cleanup_intents()
                .await
                .unwrap(),
            1
        );
    }

    #[test]
    fn migration_files_on_disk_match_expected_set() {
        // Pre-release: the directory contains the local base plus independent
        // opt-in extended and remote profile extensions. The literal catches
        // stray or deleted schema inputs without deriving expectations from
        // MIGRATIONS.
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

        assert_eq!(
            migrations,
            vec![
                "0001_extended_profile.sql".to_string(),
                "0001_initial.sql".to_string(),
                "0001_remote_profile.sql".to_string(),
            ]
        );
    }
}
