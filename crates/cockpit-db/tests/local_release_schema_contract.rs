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

#[derive(Debug)]
struct Ownership {
    status: String,
}

fn required_text<'a>(name: &str, entry: &'a toml::value::Table, field: &str) -> &'a str {
    let value = entry
        .get(field)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("table {name} must declare nonempty {field}"));
    assert!(!value.trim().is_empty(), "table {name} has empty {field}");
    value
}

fn ownership() -> BTreeMap<String, Ownership> {
    let parsed: toml::Value = toml::from_str(include_str!("../schema-ownership.toml"))
        .expect("schema-ownership.toml must be valid TOML");
    let table = parsed.get("table").and_then(toml::Value::as_table)
        .expect("schema-ownership.toml must contain a nonempty [table] map");
    assert!(!table.is_empty(), "ownership classification cannot be vacuous");
    table.iter().map(|(name, value)| {
        let entry = value.as_table().unwrap_or_else(|| panic!("table {name} must use the rich ownership format"));
        for field in ["domain", "rust_owner", "recovery_entrypoint", "retention_policy", "state_machine", "invariant_owner"] {
            required_text(name, entry, field);
        }
        let status = required_text(name, entry, "status");
        assert!(matches!(status, "launch-required" | "launch-disabled-but-schema-required" | "remove-from-v0.1"),
            "table {name} has unsupported status {status}");
        (name.clone(), Ownership { status: status.to_owned() })
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
        .filter_map(|(name, owner)| (owner.status == "remove-from-v0.1").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(full_tables.difference(&local_tables).cloned().collect::<BTreeSet<_>>(), remote_tables);

    let mut stmt = local.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    ).unwrap();
    for row in stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?))).unwrap() {
        let (kind, name, owning_table, sql) = row.unwrap();
        if matches!(kind.as_str(), "index" | "trigger") {
            let owner = ownership.get(&owning_table)
                .unwrap_or_else(|| panic!("{kind} {name} has unclassified owning table {owning_table}"));
            assert_ne!(owner.status, "remove-from-v0.1", "retained {kind} {name} belongs to removed table {owning_table}");
        }
        for remote in &remote_tables {
            assert!(!sql.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .any(|token| token == remote),
                "retained {kind} {name} references removed table {remote}");
        }
    }
    assert!(local_inventory.contains_key("index"));
    assert!(local_inventory.contains_key("trigger"));
    assert!(full_inventory.keys().all(|kind| matches!(kind.as_str(), "table" | "index" | "trigger" | "view")));

    // Disabled-but-retained tables must be justified by a real schema
    // reference from another retained object; otherwise they should not cross
    // the v0.1 boundary merely as speculative storage.
    for (table, owner) in &ownership {
        if owner.status == "launch-disabled-but-schema-required" {
            let referenced = local_inventory.iter().any(|(_, objects)| {
                objects.iter().any(|object| object != table && {
                    let sql: Option<String> = local.query_row(
                        "SELECT sql FROM sqlite_schema WHERE name = ?1",
                        [object],
                        |row| row.get(0),
                    ).ok();
                    sql.is_some_and(|sql| sql.split(|character: char| !(character.is_ascii_alphanumeric() || character == '_')).any(|token| token == table))
                })
            });
            assert!(referenced, "disabled retained table {table} has no retained schema dependency");
        }
    }
}
