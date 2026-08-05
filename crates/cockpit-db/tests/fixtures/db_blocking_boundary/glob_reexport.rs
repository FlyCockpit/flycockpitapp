//! Fixture: public glob re-export exposes a free function that reaches an unguarded helper.
//! Expected: gate expands the local glob and rejects the public path.
//! cockpit-db-local analysis only; not a workspace-wide wrapper detector.

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }
}

mod internal {
    use super::Db;

    pub fn sneaky_read(db: &Db) {
        db.read_blocking_unguarded(|| ())
    }
}

// Public glob expansion must surface sneaky_read as a public path.
pub use internal::*;
