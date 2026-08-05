//! Fixture: associated-function item reference reaches an unguarded helper.
//! Expected: gate rejects (semantic alias / function-item reference).

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    /// Indirect associated-function reference, not a direct method call.
    pub fn via_associated_item<F, T>(&self, f: F) -> T {
        let runner = Self::read_blocking_unguarded;
        runner(self, f)
    }
}
