//! Fixture: macro-generated public Db method (unsupported construct).
//! Expected: gate fails closed with a source location.

struct Db;

impl Db {
    fn read_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }

    fn write_blocking_unguarded<F, T>(&self, f: F) -> T {
        f()
    }
}

macro_rules! generate_public_db_method {
    ($name:ident) => {
        impl Db {
            pub fn $name<F, T>(&self, f: F) -> T {
                self.write_blocking_unguarded(f)
            }
        }
    };
}

generate_public_db_method!(macro_exposed_write);
