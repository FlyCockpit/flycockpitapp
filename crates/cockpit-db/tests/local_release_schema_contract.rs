//! Static release contract for the physical local/remote schema split.
//!
//! This intentionally inspects source artifacts rather than an opened database:
//! it catches an unclassified table or a remote table omitted from the local
//! prune profile before release packaging reaches runtime.

use std::collections::{BTreeMap, BTreeSet};

fn migration_tables(sql: &str) -> BTreeSet<&str> {
    sql.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("CREATE TABLE ")
                .and_then(|tail| tail.split_whitespace().next())
                .map(|name| name.trim_end_matches('('))
        })
        .collect()
}

fn ownership_manifest(source: &str) -> BTreeMap<&str, &str> {
    source
        .lines()
        .filter_map(|line| {
            let (name, owner) = line.split_once(" = ")?;
            Some((name.trim_matches('"'), owner.trim_matches('"')))
        })
        .collect()
}

fn pruned_tables(sql: &str) -> BTreeSet<&str> {
    sql.lines()
        .filter_map(|line| {
            line.trim()
                .strip_prefix("DROP TABLE ")
                .map(|name| name.trim_end_matches(';'))
        })
        .collect()
}

#[test]
fn every_table_is_classified_and_local_profile_excludes_exactly_remote_tables() {
    let initial = include_str!("../src/db/migrations/0001_initial.sql");
    let local_profile = include_str!("../src/db/migrations/0001_local_profile.sql");
    let ownership = ownership_manifest(include_str!("../schema-ownership.toml"));
    let tables = migration_tables(initial);

    assert_eq!(
        ownership.keys().copied().collect::<BTreeSet<_>>(),
        tables,
        "schema-ownership.toml must classify every table and no nonexistent table"
    );
    assert!(ownership.values().all(|owner| matches!(*owner, "local-launch" | "remote")));

    let remote = ownership
        .iter()
        .filter_map(|(table, owner)| (*owner == "remote").then_some(*table))
        .collect::<BTreeSet<_>>();
    assert_eq!(pruned_tables(local_profile), remote);
}
