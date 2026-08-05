//! Fixture: imported alias call reaches an unguarded helper.
//! Expected: gate rejects (semantic alias).
//!
//! Resolution is crate-local only; this mini-crate is the whole analysis unit.

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }
}

use Db::read_blocking_unguarded as sneaky_read;

impl Db {
    /// Public name contains neither "read" nor "write" nor "blocking".
    pub fn load_snapshot<F, T>(&self, f: F) -> T {
        sneaky_read(self, f)
    }
}
