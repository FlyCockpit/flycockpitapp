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
fn hot_query_shapes_keep_reviewed_leading_indexes() {
    let root = workspace();
    let shapes = [
        (
            "crates/cockpit-db/src/db/sessions.rs",
            "WHERE parent_session_id = ?1 ORDER BY started_at_unix_ms",
            "CREATE INDEX idx_sessions_parent_started ON sessions (parent_session_id, started_at_unix_ms DESC)",
        ),
        (
            "crates/cockpit-db/src/db/sessions.rs",
            "WHERE ended_at_unix_ms IS NULL AND ephemeral = 0",
            "CREATE INDEX idx_sessions_open            ON sessions (ended_at_unix_ms) WHERE ended_at_unix_ms IS NULL",
        ),
        (
            "crates/cockpit-db/src/db/agent_installations.rs",
            "WHERE session_id=?1 AND claim_state IN ('claimed', 'running')",
            "CREATE INDEX idx_agent_session_preparation_claims_recovery\n    ON agent_session_preparation_claims(claim_state, session_id)",
        ),
    ];
    for (owner, query, index) in shapes {
        assert!(
            source(root.join(owner)).contains(query),
            "query shape drifted: {owner}: {query}"
        );
        assert!(
            SCHEMA.contains(index),
            "reviewed index missing for {owner}: {index}"
        );
    }
}
