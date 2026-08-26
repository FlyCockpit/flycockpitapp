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

fn matching_paren(source: &str, open: usize) -> usize {
    let mut depth = 0_i32;
    let mut quote = None;
    let bytes = source.as_bytes();
    let mut index = open;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                if index + 1 < bytes.len() && bytes[index + 1] == delimiter {
                    index += 2;
                    continue;
                }
                quote = None;
            }
        } else {
            match byte {
                b'\'' | b'"' | b'`' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return index;
                    }
                }
                _ => {}
            }
        }
        index += 1;
    }
    panic!("unclosed SQL parenthesis")
}

fn split_top_level(body: &str) -> Vec<&str> {
    let mut clauses = Vec::new();
    let mut start = 0;
    let mut depth = 0_i32;
    let mut quote = None;
    let bytes = body.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(delimiter) = quote {
            if byte == delimiter {
                if index + 1 < bytes.len() && bytes[index + 1] == delimiter {
                    index += 2;
                    continue;
                }
                quote = None;
            }
        } else {
            match byte {
                b'\'' | b'"' | b'`' => quote = Some(byte),
                b'(' => depth += 1,
                b')' => depth -= 1,
                b',' if depth == 0 => {
                    clauses.push(body[start..index].trim());
                    start = index + 1;
                }
                _ => {}
            }
        }
        index += 1;
    }
    clauses.push(body[start..].trim());
    clauses
}

fn identifier(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character| matches!(character, '"' | '`' | '[' | ']'))
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|character| matches!(character, '"' | '`' | '[' | ']'))
        .to_ascii_lowercase()
}

fn column_list(value: &str) -> Vec<String> {
    value.split(',').map(identifier).collect()
}

#[derive(Debug)]
struct ForeignKey {
    table: String,
    columns: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RelationshipClass {
    Foreign,
    External,
    Polymorphic,
    Denormalized,
}

fn id_like_columns(sql: &str) -> Vec<(String, String)> {
    let mut columns = Vec::new();
    for (table, body) in table_bodies(sql) {
        for clause in split_top_level(body) {
            let upper = clause.to_ascii_uppercase();
            if [
                "FOREIGN KEY",
                "PRIMARY KEY",
                "UNIQUE",
                "CHECK",
                "CONSTRAINT",
            ]
            .iter()
            .any(|prefix| upper.starts_with(prefix))
            {
                continue;
            }
            let column = identifier(clause);
            if column == "id"
                || column.ends_with("_id")
                || column.ends_with("_ids")
                || column.ends_with("_ids_json")
                || column.ends_with("_key")
            {
                columns.push((table.clone(), column));
            }
        }
    }
    columns
}

fn relationship_class(
    table: &str,
    column: &str,
    foreign_keys: &std::collections::BTreeSet<(String, String)>,
) -> RelationshipClass {
    if foreign_keys.contains(&(table.to_owned(), column.to_owned())) {
        return RelationshipClass::Foreign;
    }
    if column == "scope_id"
        || column == "consumer_id"
        || column == "owner_id"
        || column.ends_with("_scope_id")
        || column.ends_with("_consumer_id")
    {
        return RelationshipClass::Polymorphic;
    }
    if matches!(
        (table, column),
        ("tool_call_events", "project_id")
            | ("inference_calls", "project_id")
            | ("usage_events", "project_id")
            | ("session_events", "provider_id" | "model_id")
    ) {
        return RelationshipClass::Denormalized;
    }
    // The remaining values are deliberately opaque domain/upstream IDs, or
    // the stable identity of the row itself. They have no local target and
    // must not acquire a guessed FK merely because their spelling ends `_id`.
    RelationshipClass::External
}

fn table_bodies(sql: &str) -> Vec<(String, &str)> {
    let upper = sql.to_ascii_uppercase();
    let mut tables = Vec::new();
    let mut offset = 0;
    while let Some(relative) = upper[offset..].find("CREATE TABLE ") {
        let start = offset + relative + "CREATE TABLE ".len();
        let remainder = &sql[start..];
        let name_end = remainder
            .find(|character: char| character.is_whitespace() || character == '(')
            .expect("table declaration has a body");
        let name = identifier(&remainder[..name_end]);
        let open = start + remainder.find('(').expect("table body opens");
        let close = matching_paren(sql, open);
        tables.push((name, &sql[open + 1..close]));
        offset = close + 1;
    }
    tables
}

fn foreign_keys_and_local_keys(
    sql: &str,
) -> (
    Vec<ForeignKey>,
    std::collections::BTreeMap<String, Vec<Vec<String>>>,
) {
    let mut foreign_keys = Vec::new();
    let mut keys = std::collections::BTreeMap::<String, Vec<Vec<String>>>::new();
    for (table, body) in table_bodies(sql) {
        for clause in split_top_level(body) {
            let upper = clause.to_ascii_uppercase();
            if upper.starts_with("FOREIGN KEY") {
                let open = clause.find('(').expect("foreign key columns open");
                let close = matching_paren(clause, open);
                foreign_keys.push(ForeignKey {
                    table: table.clone(),
                    columns: column_list(&clause[open + 1..close]),
                });
            } else if upper.contains(" REFERENCES ") {
                foreign_keys.push(ForeignKey {
                    table: table.clone(),
                    columns: vec![identifier(clause)],
                });
            }
            for keyword in ["PRIMARY KEY", "UNIQUE"] {
                if let Some(position) = upper.find(keyword) {
                    let tail = &clause[position + keyword.len()..];
                    if let Some(open_relative) = tail.find('(') {
                        let open = position + keyword.len() + open_relative;
                        let close = matching_paren(clause, open);
                        keys.entry(table.clone())
                            .or_default()
                            .push(column_list(&clause[open + 1..close]));
                    } else if !upper.starts_with("CHECK") {
                        keys.entry(table.clone())
                            .or_default()
                            .push(vec![identifier(clause)]);
                    }
                }
            }
        }
    }
    (foreign_keys, keys)
}

fn declared_indexes(sql: &str) -> std::collections::BTreeMap<String, Vec<Vec<String>>> {
    let upper = sql.to_ascii_uppercase();
    let mut indexes = std::collections::BTreeMap::<String, Vec<Vec<String>>>::new();
    let mut offset = 0;
    loop {
        let ordinary = upper[offset..].find("CREATE INDEX ");
        let unique = upper[offset..].find("CREATE UNIQUE INDEX ");
        let Some(relative) = [ordinary, unique].into_iter().flatten().min() else {
            break;
        };
        let start = offset + relative;
        let end = start + sql[start..].find(';').expect("index declaration ends");
        let declaration = &sql[start..end];
        let declaration_upper = declaration.to_ascii_uppercase();
        if declaration_upper.contains(" WHERE ") {
            offset = end + 1;
            continue;
        }
        let on = declaration_upper.find(" ON ").expect("index has ON") + " ON ".len();
        let tail = &declaration[on..];
        let open_relative = tail.find('(').expect("index columns open");
        let table = identifier(&tail[..open_relative]);
        let open = on + open_relative;
        let close = matching_paren(declaration, open);
        indexes
            .entry(table)
            .or_default()
            .push(column_list(&declaration[open + 1..close]));
        offset = end + 1;
    }
    indexes
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
fn every_foreign_key_group_has_a_usable_child_leading_index() {
    let (foreign_keys, mut indexes) = foreign_keys_and_local_keys(SCHEMA);
    for (table, declared) in declared_indexes(SCHEMA) {
        indexes.entry(table).or_default().extend(declared);
    }
    let missing = foreign_keys
        .into_iter()
        .filter(|foreign_key| {
            !indexes.get(&foreign_key.table).is_some_and(|candidates| {
                candidates.iter().any(|candidate| {
                    candidate.len() >= foreign_key.columns.len()
                        && candidate[..foreign_key.columns.len()] == foreign_key.columns
                })
            })
        })
        .map(|foreign_key| format!("{}({})", foreign_key.table, foreign_key.columns.join(",")))
        .collect::<Vec<_>>();
    assert!(
        missing.is_empty(),
        "foreign-key child groups without a usable leading index: {missing:?}"
    );
}

#[test]
fn every_id_like_column_has_exactly_one_relationship_classification() {
    let (foreign_keys, _) = foreign_keys_and_local_keys(SCHEMA);
    let foreign_columns = foreign_keys
        .iter()
        .flat_map(|foreign_key| {
            foreign_key
                .columns
                .iter()
                .map(|column| (foreign_key.table.clone(), column.clone()))
        })
        .collect::<std::collections::BTreeSet<_>>();
    let inventory = id_like_columns(SCHEMA)
        .into_iter()
        .map(|(table, column)| {
            let class = relationship_class(&table, &column, &foreign_columns);
            ((table, column), class)
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    assert!(
        inventory.len() >= 200,
        "id-like inventory unexpectedly shrank"
    );
    for required in [
        (
            ("sessions", "parent_session_id"),
            RelationshipClass::Foreign,
        ),
        (
            ("tool_call_events", "parent_call_id"),
            RelationshipClass::Foreign,
        ),
        (
            ("tool_call_events", "project_id"),
            RelationshipClass::Denormalized,
        ),
        (
            ("media_reservation_deltas", "scope_id"),
            RelationshipClass::Polymorphic,
        ),
        (("sessions", "session_id"), RelationshipClass::External),
    ] {
        assert_eq!(
            inventory.get(&(required.0.0.to_owned(), required.0.1.to_owned())),
            Some(&required.1),
            "relationship classification drifted for {}.{}",
            required.0.0,
            required.0.1
        );
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
