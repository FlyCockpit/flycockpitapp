//! Fixture: unresolved indirect callable on a public path.
//! Expected: gate fails closed (function pointer / variable call).

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    pub fn via_function_pointer<F, T>(&self, f: F) -> T {
        let runner: fn(&Db, F) -> T = choose_runner();
        runner(self, f)
    }
}

fn choose_runner<F, T>() -> fn(&Db, F) -> T {
    |db, f| db.write_blocking_unguarded(f)
}
