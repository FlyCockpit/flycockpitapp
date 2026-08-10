use cockpit_core::db as storage;

fn main() {
    let _ = storage::Db::open_default();
}
