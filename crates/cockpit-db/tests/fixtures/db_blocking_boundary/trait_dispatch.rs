//! Fixture: trait implementation exposes an unguarded helper path.
//! Expected: gate fails closed (trait dispatch is unsupported on the boundary).

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }
}

trait SyncDbAccess {
    fn run_sync<F, T>(&self, f: F) -> T;
}

impl SyncDbAccess for Db {
    fn run_sync<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }
}

pub fn via_trait<F, T>(db: &Db, f: F) -> T {
    SyncDbAccess::run_sync(db, f)
}
