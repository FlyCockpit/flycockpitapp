//! Fixture: only the exact reviewed allowlist reaches unguarded helpers.
//! Expected: gate accepts with that exact allowlist set.

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    /// Permanent guarded boundary for synchronous CLI one-shots.
    pub fn blocking_for_sync_cli<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_read_for_sync_ui<F, T>(&self, f: F) -> T {
        self.read_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_write_for_sync_ui<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_write_for_sync_event<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }

    /// Temporary; owned for removal by db-sync-wrapper-migration.
    pub fn blocking_write_for_sync_maintenance<F, T>(&self, f: F) -> T {
        self.write_blocking_unguarded(f)
    }
}
