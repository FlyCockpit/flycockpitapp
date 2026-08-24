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
fn local_base_and_remote_extension_have_exact_physical_ownership() {
    let local_sql = include_str!("../src/db/migrations/0001_initial.sql");
    for remote_vocabulary in ["remote_device", "public_remote"] {
        assert!(
            !local_sql.contains(remote_vocabulary),
            "local launch schema contains remote-only vocabulary {remote_vocabulary}"
        );
    }
    let local = Connection::open_in_memory().unwrap();
    local.execute_batch(local_sql)
        .expect("0001_initial.sql must execute as SQLite");
    let local_inventory = schema_inventory(&local);
    let local_tables = local_inventory.get("table").cloned().unwrap_or_default();
    let full = Connection::open_in_memory().unwrap();
    full.execute_batch(include_str!("../src/db/migrations/0001_initial.sql"))
        .expect("local base must execute before the remote extension");
    full.execute_batch(include_str!("../src/db/migrations/0001_remote_profile.sql"))
        .expect("remote profile extension must execute after the local base");
    let full_inventory = schema_inventory(&full);
    let full_tables = full_inventory.get("table").cloned().unwrap_or_default();
    let ownership = ownership();
    assert_eq!(ownership.keys().cloned().collect::<BTreeSet<_>>(), full_tables,
        "ownership manifest must classify every executed table exactly once");

    let remote_tables = ownership.iter()
        .filter_map(|(name, owner)| (owner.status == "remove-from-v0.1").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(full_tables.difference(&local_tables).cloned().collect::<BTreeSet<_>>(), remote_tables);

    assert!(remote_tables.is_disjoint(&local_tables),
        "local base migration must not contain a remote-owned table");

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
