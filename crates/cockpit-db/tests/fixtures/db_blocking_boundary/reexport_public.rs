//! Fixture: public re-export exposes a free function that reaches an unguarded helper.
//! Expected: gate rejects (re-export reachability).

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }
}

fn internal_bridge<F, T>(db: &Db, f: F) -> T {
    db.read_blocking_unguarded(f)
}

mod surface {
    pub use super::internal_bridge as public_bridge;
}

pub use surface::public_bridge;
