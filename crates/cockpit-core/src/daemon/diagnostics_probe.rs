//! The single DB opener for the offline `cockpit doctor` diagnostic. When no
//! daemon is running (or one failed to boot), doctor opens the existing session
//! DB read-only to report SQLite and migration-ledger health. A running daemon's
//! doctor RPC does not use this — it passes its already-open `ctx.db` handle.
use crate::db::Db;

/// Open the default-path session DB for the offline doctor diagnostic. Returns
/// the open `Result` so the caller can render `openability: FAILED (<reason>)`
/// (or a schema-rejection line) when the open fails, which is exactly what
/// `reports_unopenable_database` / `reports_amended_migration` assert.
pub(crate) fn open_diagnostic_db() -> anyhow::Result<Db> {
    Db::open_default_read_only_diagnostic()
}
