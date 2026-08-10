use cockpit_db as storage;

fn main() {
    let _ = storage::Db::open_default();
}
