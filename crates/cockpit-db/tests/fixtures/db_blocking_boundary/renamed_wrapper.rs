//! Fixture: renamed public wrapper reaches an unguarded helper.
//! Expected: gate rejects even when the name has no blocking/read/write tokens.

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    pub fn persist_local_preference<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }
}
