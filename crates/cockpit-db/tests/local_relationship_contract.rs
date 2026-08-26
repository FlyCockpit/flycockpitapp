use std::path::{Path, PathBuf};

const SCHEMA: &str = include_str!("../src/db/migrations/0001_initial.sql");

fn reference_policies(sql: &str) -> Vec<String> {
    let uncommented = sql
        .lines()
        .map(|line| line.split_once("--").map_or(line, |(code, _)| code))
        .collect::<Vec<_>>()
        .join("\n");
    let normalized = uncommented.to_ascii_uppercase();
    let mut clauses = Vec::new();
    let mut offset = 0;
    while let Some(relative) = normalized[offset..].find("REFERENCES") {
        let start = offset + relative;
        let Some(open_relative) = normalized[start..].find('(') else {
            break;
        };
        let open = start + open_relative;
        let mut depth = 0_i32;
        let mut close = None;
        for (relative, character) in normalized[open..].char_indices() {
            match character {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(open + relative);
                        break;
                    }
                }
                _ => {}
            }
        }
        let close = close.expect("REFERENCES target columns must close");
        let tail = &normalized[close + 1..];
        let end = [tail.find(','), tail.find("\n);")]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or(tail.len());
        clauses.push(normalized[start..close + 1 + end].to_string());
        offset = close + 1;
    }
    clauses
}

fn source(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).expect("read production query owner")
}

fn workspace() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

#[test]
fn every_local_foreign_key_has_explicit_delete_and_immutable_id_update_policy() {
    let gaps = reference_policies(SCHEMA)
        .into_iter()
        .filter(|clause| !clause.contains("ON DELETE ") || !clause.contains("ON UPDATE RESTRICT"))
        .collect::<Vec<_>>();
    assert!(
        gaps.is_empty(),
        "foreign keys without explicit delete/update policy: {gaps:#?}"
    );
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
