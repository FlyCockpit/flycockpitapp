//! Compile-fail consumer fixture: `Db::write_blocking` must not exist.
//!
//! This file is not part of the crate build. The boundary gate asserts the
//! method is absent from cockpit-db's public API; a consumer that still called
//! it would fail to compile after `db-blocking-api-removal`.

use cockpit_db::Db;

fn consumer(db: &Db) {
    let _ = db.write_blocking(|_conn| Ok::<(), anyhow::Error>(()));
}
