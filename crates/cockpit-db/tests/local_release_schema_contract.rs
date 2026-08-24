//! Executed-schema contract for the physical local-v0.1 profile.

use std::collections::{BTreeMap, BTreeSet};
use rusqlite::Connection;

fn schema_inventory(conn: &Connection) -> BTreeMap<String, BTreeSet<String>> {
    let mut inventory = BTreeMap::<String, BTreeSet<String>>::new();
    let mut stmt = conn.prepare(
        "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    ).unwrap();
    for row in stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap() {
        let (kind, name) = row.unwrap();
        inventory.entry(kind).or_default().insert(name);
    }
    inventory
}

fn ownership() -> BTreeMap<String, String> {
    let parsed: toml::Value = toml::from_str(include_str!("../schema-ownership.toml"))
        .expect("schema-ownership.toml must be valid TOML");
    let table = parsed.get("table").and_then(toml::Value::as_table)
        .expect("schema-ownership.toml must contain a nonempty [table] map");
    assert!(!table.is_empty(), "ownership classification cannot be vacuous");
    table.iter().map(|(name, value)| {
        let owner = value.as_str().unwrap_or_else(|| panic!("table {name} has unsupported ownership format"));
        assert!(matches!(owner, "local-launch" | "remote"), "table {name} has unsupported owner {owner}");
        (name.clone(), owner.to_owned())
    }).collect()
}

#[test]
fn local_profile_executes_and_removes_every_remote_schema_object() {
    let full = Connection::open_in_memory().unwrap();
    full.execute_batch(include_str!("../src/db/migrations/0001_initial.sql"))
        .expect("0001_initial.sql must execute as SQLite");
    let full_inventory = schema_inventory(&full);
    let full_tables = full_inventory.get("table").cloned().unwrap_or_default();
    let ownership = ownership();
    assert_eq!(ownership.keys().cloned().collect::<BTreeSet<_>>(), full_tables,
        "ownership manifest must classify every executed table exactly once");

    let local = Connection::open_in_memory().unwrap();
    local.execute_batch(include_str!("../src/db/migrations/0001_initial.sql")).unwrap();
    local.execute_batch(include_str!("../src/db/migrations/0001_local_profile.sql"))
        .expect("local profile SQL must execute against the full schema");
    let local_inventory = schema_inventory(&local);
    let local_tables = local_inventory.get("table").cloned().unwrap_or_default();
    let remote_tables = ownership.iter()
        .filter_map(|(name, owner)| (owner == "remote").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(full_tables.difference(&local_tables).cloned().collect::<BTreeSet<_>>(), remote_tables);

    let mut stmt = local.prepare(
        "SELECT type, name, COALESCE(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    ).unwrap();
    for row in stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))).unwrap() {
        let (kind, name, sql) = row.unwrap();
        for remote in &remote_tables {
            assert!(!sql.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .any(|token| token == remote),
                "retained {kind} {name} references removed table {remote}");
        }
    }
    assert!(local_inventory.contains_key("index"));
    assert!(local_inventory.contains_key("trigger"));
    assert!(full_inventory.keys().all(|kind| matches!(kind.as_str(), "table" | "index" | "trigger" | "view")));
}
