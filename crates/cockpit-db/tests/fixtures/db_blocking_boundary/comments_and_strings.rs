//! Fixture: unguarded helper tokens appear only in comments and string literals.
//! Expected: gate accepts (non-code text is irrelevant).

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    /// Docs may mention read_blocking_unguarded and write_blocking_unguarded.
    pub fn schema_probe(&self) -> &'static str {
        // self.read_blocking_unguarded(|_| ())
        // self.write_blocking_unguarded(|_| ())
        "call read_blocking_unguarded / write_blocking_unguarded only via allowlisted entrypoints"
    }
}
