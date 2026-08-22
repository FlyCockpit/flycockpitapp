//! The single DB opener for the offline `cockpit doctor` diagnostic. When no
//! daemon is running (or one failed to boot), doctor opens the session DB
//! in-process to report openability + migration-ledger health. This bootstraps
//! the DB exactly as daemon boot would (create + migrate); that is intended and
//! is covered by the `doctor::reports_amended_migration` /
//! `reports_unopenable_database` e2e tests. A running daemon's doctor RPC does
//! NOT use this — it passes its already-open `ctx.db` handle.
use crate::db::Db;

/// Open the default-path session DB for the offline doctor diagnostic. Returns
/// the open `Result` so the caller can render `openability: FAILED (<reason>)`
/// (or a schema-rejection line) when the open fails, which is exactly what
/// `reports_unopenable_database` / `reports_amended_migration` assert.
pub(crate) fn open_diagnostic_db() -> anyhow::Result<Db> {
    Db::open_default()
}
