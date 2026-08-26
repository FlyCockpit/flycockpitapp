use std::path::{Path, PathBuf};

#[path = "support/schema_parser.rs"]
mod schema_parser;

const SCHEMA: &str = include_str!("../src/db/migrations/0001_initial.sql");
const EXTENDED_SCHEMA: &str = include_str!("../src/db/migrations/0001_extended_profile.sql");

fn source(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).expect("read production query owner")
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn rust_sources_below(root: &Path, relative: &Path, output: &mut Vec<PathBuf>) {
    let directory = root.join(relative);
    for entry in std::fs::read_dir(&directory).expect("read production source directory") {
        let entry = entry.expect("read production source entry");
        let path = entry.path();
        let child = relative.join(entry.file_name());
        if path.is_dir() {
            rust_sources_below(root, &child, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(child);
        }
    }
}

fn effective_profiles() -> [(&'static str, schema_parser::Schema); 2] {
    [
        ("local", schema_parser::parse(&[SCHEMA])),
        ("extended", schema_parser::parse(&[SCHEMA, EXTENDED_SCHEMA])),
    ]
}

#[test]
fn effective_schema_profiles_are_ordered_closed_and_indexed() {
    let [(local_name, local), (extended_name, extended)] = effective_profiles();
    assert_eq!(local_name, "local");
    assert_eq!(extended_name, "extended");
    assert!(
        local
            .tables
            .keys()
            .all(|table| extended.tables.contains_key(table)),
        "extended must apply after, and retain every table from, local 0001"
    );
    assert!(
        extended.tables.len() > local.tables.len(),
        "extended profile must add its deferred-domain inventory"
    );

    for (profile, schema) in [(local_name, &local), (extended_name, &extended)] {
        for (table_name, table) in &schema.tables {
            for foreign_key in &table.foreign_keys {
                assert!(
                    matches!(
                        foreign_key.on_delete.as_deref(),
                        Some("cascade" | "restrict" | "set null" | "no action")
                    ),
                    "{profile}.{table_name} lacks an explicit ON DELETE action: {foreign_key:?}"
                );
                assert_eq!(
                    foreign_key.on_update.as_deref(),
                    Some("restrict"),
                    "{profile}.{table_name} permits referenced identity mutation: {foreign_key:?}"
                );
                assert!(
                    schema.tables.contains_key(&foreign_key.target_table),
                    "{profile}.{table_name} references absent target {}",
                    foreign_key.target_table
                );
                assert!(
                    schema_parser::exact_target_keys(schema, &foreign_key.target_table)
                        .contains(&foreign_key.target_columns),
                    "{profile}.{table_name} references non-key {}({:?})",
                    foreign_key.target_table,
                    foreign_key.target_columns
                );
                assert!(
                    schema_parser::child_leading_keys(schema, table_name)
                        .iter()
                        .any(|key| key.starts_with(&foreign_key.child_columns)),
                    "{profile}.{table_name} foreign key {:?} lacks a usable leading child index",
                    foreign_key.child_columns
                );
            }
        }
    }
}

#[test]
fn scoped_session_relationships_are_database_enforced_and_indexed() {
    for contract in [
        "FOREIGN KEY (parent_session_id, fork_point_turn_id)\n        REFERENCES session_events(session_id, seq)\n        ON DELETE RESTRICT ON UPDATE RESTRICT DEFERRABLE INITIALLY DEFERRED",
        "CREATE INDEX idx_sessions_parent_fork_point ON sessions(parent_session_id, fork_point_turn_id)",
        "FOREIGN KEY (session_id, parent_call_id)\n        REFERENCES tool_call_events(session_id, call_id)\n        ON DELETE CASCADE ON UPDATE RESTRICT",
        "CREATE UNIQUE INDEX uq_tce_session_call ON tool_call_events(session_id, call_id)",
        "CREATE INDEX idx_tce_parent     ON tool_call_events (session_id, parent_call_id)",
    ] {
        assert!(
            SCHEMA.contains(contract),
            "missing scoped FK contract: {contract}"
        );
    }
}

#[test]
fn intentional_session_soft_relationships_are_classified_in_schema() {
    for classification in [
        "[relationship:foreign] parent_session_id",
        "[relationship:foreign] Optional historical event sequence",
        "[relationship:foreign] Same-session parent tool call",
        "[relationship:denormalized] Immutable-attribution display snapshots",
        "[relationship:denormalized] Historical assistant label",
        "[relationship:external] Provider-owned opaque wire identifiers",
    ] {
        assert!(
            SCHEMA.contains(classification),
            "missing relationship classification: {classification}"
        );
    }
}

#[test]
fn hot_query_inventory_is_exact_and_keeps_reviewed_leading_indexes() {
    let root = workspace();
    let shapes = [
        (
            "local.sessions.open",
            "crates/cockpit-db/src/db/sessions.rs",
            "WHERE ended_at_unix_ms IS NULL AND ephemeral = 0",
            false,
            "sessions",
            &["ended_at_unix_ms"][..],
        ),
        (
            "local.agent-preparation.terminalize",
            "crates/cockpit-db/src/db/agent_installations.rs",
            "WHERE session_id=?1 AND claim_state IN ('claimed', 'running')",
            false,
            "agent_session_preparation_claims",
            &["claim_state", "session_id"],
        ),
        (
            "extended.scheduler.by-owner",
            "crates/cockpit-db/src/db/scheduler.rs",
            "WHERE owner = ?1",
            true,
            "scheduled_jobs",
            &["owner"],
        ),
        (
            "extended.image-generation.dispatch-scan",
            "crates/cockpit-db/src/db/image_generation.rs",
            "WHERE j.state='queued' AND s.state='queued' AND a.state='planned'",
            true,
            "image_generation_jobs",
            &["state", "created_at_unix_ms", "job_id"],
        ),
    ];
    let expected_markers = shapes
        .iter()
        .map(|(marker, owner, ..)| (marker.to_string(), owner.to_string()))
        .collect::<std::collections::BTreeSet<_>>();
    let mut production_sources = Vec::new();
    rust_sources_below(
        &root,
        Path::new("crates/cockpit-db/src/db"),
        &mut production_sources,
    );
    let actual_markers = production_sources
        .into_iter()
        .flat_map(|owner| {
            let contents = source(root.join(&owner));
            contents
                .lines()
                .filter_map(|line| {
                    line.split_once("schema-hot-query:")
                        .map(|(_, marker)| (marker.trim().to_owned(), owner.display().to_string()))
                })
                .collect::<Vec<_>>()
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual_markers, expected_markers,
        "hot-query annotations drifted"
    );

    let [(_, local), (_, extended)] = effective_profiles();
    for (marker, owner, query, uses_extended, table, leading) in shapes {
        assert!(
            source(root.join(owner)).contains(query),
            "query shape drifted for {marker}: {owner}: {query}"
        );
        let schema = if uses_extended { &extended } else { &local };
        assert!(
            schema
                .indexes
                .iter()
                .any(|index| { index.table == table && index.columns.starts_with(leading) }),
            "reviewed leading index missing for {marker}: {table}{leading:?}"
        );
    }
}
