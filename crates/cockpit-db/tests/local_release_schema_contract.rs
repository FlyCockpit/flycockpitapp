//! Executed-schema contract for the physical local-v0.1 profile.

use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};

fn schema_inventory(conn: &Connection) -> BTreeMap<String, BTreeSet<String>> {
    let mut inventory = BTreeMap::<String, BTreeSet<String>>::new();
    let mut stmt = conn.prepare(
        "SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    ).unwrap();
    for row in stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
    {
        let (kind, name) = row.unwrap();
        if kind == "table" && is_runtime_managed_table(&name) {
            continue;
        }
        inventory.entry(kind).or_default().insert(name);
    }
    inventory
}

fn is_runtime_managed_table(name: &str) -> bool {
    matches!(
        name,
        "schema_version"
            | "session_fts"
            | "session_fts_data"
            | "session_fts_idx"
            | "session_fts_content"
            | "session_fts_docsize"
            | "session_fts_config"
    )
}

#[derive(Debug, PartialEq, Eq)]
enum SqlToken {
    Word(String),
    Identifier(String),
    Symbol(char),
}

impl SqlToken {
    fn is_keyword(&self, expected: &str) -> bool {
        matches!(self, Self::Word(value) if value.eq_ignore_ascii_case(expected))
    }

    fn identifier(&self) -> Option<&str> {
        match self {
            Self::Word(value) | Self::Identifier(value) => Some(value),
            Self::Symbol(_) => None,
        }
    }
}

fn sql_tokens(sql: &str) -> Vec<SqlToken> {
    let bytes = sql.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index..].starts_with(b"--") {
            index += 2;
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
        } else if bytes[index..].starts_with(b"/*") {
            index += 2;
            while index + 1 < bytes.len() && !bytes[index..].starts_with(b"*/") {
                index += 1;
            }
            index = (index + 2).min(bytes.len());
        } else if matches!(bytes[index], b'\'' | b'"' | b'`' | b'[') {
            let opening = bytes[index];
            let closing = if opening == b'[' { b']' } else { opening };
            let quoted_identifier = opening != b'\'';
            index += 1;
            let mut value = Vec::new();
            while index < bytes.len() {
                if bytes[index] == closing {
                    if closing != b']' && index + 1 < bytes.len() && bytes[index + 1] == closing {
                        value.push(closing);
                        index += 2;
                        continue;
                    }
                    index += 1;
                    break;
                }
                value.push(bytes[index]);
                index += 1;
            }
            if quoted_identifier {
                tokens.push(SqlToken::Identifier(
                    String::from_utf8_lossy(&value).into_owned(),
                ));
            }
        } else if matches!(bytes[index], b'.' | b'(' | b')' | b';') {
            tokens.push(SqlToken::Symbol(char::from(bytes[index])));
            index += 1;
        } else {
            let start = index;
            while index < bytes.len()
                && !bytes[index].is_ascii_whitespace()
                && !matches!(
                    bytes[index],
                    b'.' | b'(' | b')' | b';' | b'\'' | b'"' | b'`' | b'['
                )
                && !bytes[index..].starts_with(b"--")
                && !bytes[index..].starts_with(b"/*")
            {
                index += 1;
            }
            tokens.push(SqlToken::Word(
                String::from_utf8_lossy(&bytes[start..index]).into_owned(),
            ));
        }
    }
    tokens
}

fn sql_table_objects(sql: &str) -> Vec<String> {
    let tokens = sql_tokens(sql);
    let mut tables = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        if !tokens[index].is_keyword("CREATE") {
            index += 1;
            continue;
        }
        let mut cursor = index + 1;
        if tokens
            .get(cursor)
            .is_some_and(|token| token.is_keyword("VIRTUAL"))
        {
            cursor += 1;
        }
        if !tokens
            .get(cursor)
            .is_some_and(|token| token.is_keyword("TABLE"))
        {
            index += 1;
            continue;
        }
        cursor += 1;
        if tokens
            .get(cursor)
            .is_some_and(|token| token.is_keyword("IF"))
            && tokens
                .get(cursor + 1)
                .is_some_and(|token| token.is_keyword("NOT"))
            && tokens
                .get(cursor + 2)
                .is_some_and(|token| token.is_keyword("EXISTS"))
        {
            cursor += 3;
        }
        let Some(mut name) = tokens.get(cursor).and_then(SqlToken::identifier) else {
            index += 1;
            continue;
        };
        if tokens.get(cursor + 1) == Some(&SqlToken::Symbol('.')) {
            let Some(qualified_name) = tokens.get(cursor + 2).and_then(SqlToken::identifier) else {
                index += 1;
                continue;
            };
            name = qualified_name;
        }
        if !is_runtime_managed_table(name) {
            tables.push(name.to_owned());
        }
        index = cursor + 1;
    }
    tables
}

fn assert_static_table_ownership(
    ownership: &BTreeMap<String, Ownership>,
    local_sql: &str,
    remote_sql: &str,
) {
    let local = sql_table_objects(local_sql);
    let remote = sql_table_objects(remote_sql);
    let mut counts = BTreeMap::<String, usize>::new();
    for table in local.iter().chain(&remote) {
        *counts.entry(table.clone()).or_default() += 1;
    }
    let duplicates = counts
        .iter()
        .filter_map(|(name, count)| (*count > 1).then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert!(
        duplicates.is_empty(),
        "SQL profiles declare duplicate table ownership: {duplicates:?}"
    );

    let declared = counts.into_keys().collect::<BTreeSet<_>>();
    let classified = ownership.keys().cloned().collect::<BTreeSet<_>>();
    assert_eq!(
        classified, declared,
        "ownership manifest and static SQL table declarations must match exactly"
    );

    let local = local.into_iter().collect::<BTreeSet<_>>();
    let remote = remote.into_iter().collect::<BTreeSet<_>>();
    assert!(
        local.is_disjoint(&remote),
        "local and remote SQL profiles must not declare the same table"
    );
    let classified_remote = ownership
        .iter()
        .filter_map(|(name, owner)| (owner.status == "remove-from-v0.1").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classified_remote, remote,
        "remote-profile SQL tables must be exactly the remove-from-v0.1 classifications"
    );
    assert!(local.iter().all(|table| {
        ownership
            .get(table)
            .is_some_and(|owner| owner.status != "remove-from-v0.1")
    }));
}

#[test]
fn static_sql_table_lexer_preserves_real_duplicates_and_ignores_decoys() {
    let sql = r#"
        -- CREATE TABLE line_comment_decoy(value TEXT);
        /* CREATE TABLE block_comment_decoy(value TEXT); */
        SELECT 'CREATE TABLE string_decoy(value TEXT)';
        CREATE
          TABLE IF NOT EXISTS "main"."quoted table" (value TEXT);
        CREATE VIRTUAL TABLE [session_fts] USING fts5(body);
        CREATE TABLE duplicate(value TEXT);
        CREATE TABLE duplicate(other TEXT);
    "#;
    assert_eq!(
        sql_table_objects(sql),
        vec!["quoted table", "duplicate", "duplicate"]
    );
}

#[test]
fn local_operation_receipts_have_fenced_terminal_settlement() {
    let sql = include_str!("../src/db/migrations/0001_initial.sql");
    for required in [
        "fencing_generation  INTEGER NOT NULL",
        "execution_expires_at_unix_ms INTEGER",
        "'terminal_success', 'terminal_error', 'terminal_cancelled'",
        "terminal_outcome_json TEXT",
    ] {
        assert!(
            sql.contains(required),
            "missing receipt invariant: {required}"
        );
    }
    assert!(!sql.contains("state IN ('prepared', 'terminal')"));
}

#[test]
fn provider_config_journal_actions_have_strict_payload_shapes() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../src/db/migrations/0001_initial.sql"))
        .unwrap();

    let insert = |provider_id: &str, action: &str, entry: Option<&str>| {
        conn.execute(
            "INSERT INTO provider_config_journals
             (journal_id, project_root, provider_id, action, config_path,
              consumed_revision, intended_revision, consumed_config_generation,
             intended_config_generation, entry_json,
              cleanup_named_json, cleanup_credential_json, created_at)
             VALUES (lower(hex(randomblob(16))), '/project', ?1, ?2,
                     '/project/.cockpit/config.json',
                     lower(hex(zeroblob(32))), lower(hex(zeroblob(32))), 7, 8,
                     ?3, '[]', '[]', 1)",
            rusqlite::params![provider_id, action, entry],
        )
    };

    assert!(insert("provider", "save", Some("{}")).is_ok());
    assert!(insert("provider", "delete", None).is_ok());
    assert!(insert("__provider_batch__", "batch", Some("{}")).is_ok());
    assert!(insert("provider", "batch", Some("{}")).is_err());
    assert!(insert("__provider_batch__", "save", Some("{}")).is_err());
    assert!(insert("provider", "delete", Some("{}")).is_err());
    assert!(insert("provider", "save", Some("not-json")).is_err());
}

#[test]
fn authority_journals_bind_exact_fenced_terminal_receipts() {
    let sql = include_str!("../src/db/migrations/0001_initial.sql");
    for table in [
        "provider_config_journals",
        "mcp_config_journals",
        "extended_config_patch_journals",
        "image_config_mutation_journals",
        "agent_mutation_journals",
    ] {
        let declaration = sql
            .split(&format!("CREATE TABLE {table}"))
            .nth(1)
            .and_then(|tail| tail.split(");").next())
            .unwrap_or_else(|| panic!("missing {table}"));
        for field in [
            "owner_digest",
            "client_operation_id",
            "request_hash",
            "fencing_generation",
            "terminal_response_json",
        ] {
            assert!(
                declaration.contains(field),
                "{table} must bind {field} for exact crash recovery"
            );
        }
    }
}

#[test]
fn interrupted_settlement_excludes_provider_journal_owned_receipts() {
    let source = include_str!("../src/db/local_operation_receipts.rs");
    let settlement = source
        .split("pub async fn settle_interrupted_local_operations")
        .nth(1)
        .and_then(|tail| tail.split("pub async fn finish_local_operation").next())
        .expect("interrupted local-operation settlement source");
    assert!(settlement.contains("NOT EXISTS ("));
    assert!(settlement.contains("FROM provider_config_journals journal"));
    assert!(settlement.contains("journal.owner_digest=local_operation_receipts.owner_digest"));
    assert!(
        settlement
            .contains("journal.client_operation_id=local_operation_receipts.client_operation_id")
    );
    assert!(settlement.contains("journal.request_hash=local_operation_receipts.request_hash"));
    assert!(
        settlement
            .contains("journal.fencing_generation=local_operation_receipts.fencing_generation")
    );
}

#[test]
fn assistant_mutation_recovery_is_keyed_identity_only_and_receipt_fenced() {
    let sql = include_str!("../src/db/migrations/0001_initial.sql");
    let declaration = sql
        .split("CREATE TABLE assistant_mutation_journals")
        .nth(1)
        .and_then(|tail| tail.split(");").next())
        .expect("assistant mutation journal must exist");
    for field in [
        "owner_digest",
        "client_operation_id",
        "request_hash",
        "fencing_generation",
        "mutation_intent_hash",
        "requested_project_root",
        "project_root",
        "assistant_name",
        "consumed_revision",
        "intended_content_identity",
    ] {
        assert!(declaration.contains(field), "missing {field}");
    }
    assert!(
        !declaration.contains("terminal_response_json"),
        "assistant terminal outcomes belong only in the atomic local receipt"
    );
    for forbidden in ["markdown", "file_bytes", "secret"] {
        assert!(
            !declaration.contains(forbidden),
            "assistant recovery must not persist {forbidden}"
        );
    }
    let receipts = include_str!("../src/db/local_operation_receipts.rs");
    assert!(receipts.contains("SELECT 1 FROM assistant_mutation_journals"));
}

#[test]
fn agent_mutation_recovery_is_hash_only_and_blocks_blind_restart_rejection() {
    let sql = include_str!("../src/db/migrations/0001_initial.sql");
    let declaration = sql
        .split("CREATE TABLE agent_mutation_journals")
        .nth(1)
        .and_then(|tail| tail.split(");").next())
        .expect("agent mutation journal must exist");
    for field in [
        "owner_digest",
        "client_operation_id",
        "request_hash",
        "keyed_request_identity",
        "fencing_generation",
        "consumed_revision",
        "mutation_intent_hash",
        "consumed_projection_identity",
        "intended_projection_identity",
        "terminal_response_json",
    ] {
        assert!(declaration.contains(field), "missing {field}");
    }
    for forbidden in ["markdown", "file_bytes", "payload_json"] {
        assert!(
            !declaration.contains(forbidden),
            "agent recovery must not persist {forbidden}"
        );
    }
    let receipts = include_str!("../src/db/local_operation_receipts.rs");
    assert!(receipts.contains("SELECT 1 FROM agent_mutation_journals"));
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
    let table = parsed
        .get("table")
        .and_then(toml::Value::as_table)
        .expect("schema-ownership.toml must contain a nonempty [table] map");
    assert!(
        !table.is_empty(),
        "ownership classification cannot be vacuous"
    );
    table
        .iter()
        .map(|(name, value)| {
            let entry = value
                .as_table()
                .unwrap_or_else(|| panic!("table {name} must use the rich ownership format"));
            for field in [
                "domain",
                "rust_owner",
                "recovery_entrypoint",
                "retention_policy",
                "state_machine",
                "invariant_owner",
            ] {
                required_text(name, entry, field);
            }
            let status = required_text(name, entry, "status");
            assert!(
                matches!(
                    status,
                    "launch-required" | "launch-disabled-but-schema-required" | "remove-from-v0.1"
                ),
                "table {name} has unsupported status {status}"
            );
            (
                name.clone(),
                Ownership {
                    status: status.to_owned(),
                },
            )
        })
        .collect()
}

#[test]
fn local_base_and_remote_extension_have_exact_physical_ownership() {
    let local_sql = include_str!("../src/db/migrations/0001_initial.sql");
    let remote_sql = include_str!("../src/db/migrations/0001_remote_profile.sql");
    let ownership = ownership();
    // Keep this source-level gate before either migration is handed to SQLite:
    // malformed or unavailable extensions must not hide ownership drift.
    assert_static_table_ownership(&ownership, local_sql, remote_sql);
    for remote_vocabulary in ["remote_device", "public_remote"] {
        assert!(
            !local_sql.contains(remote_vocabulary),
            "local launch schema contains remote-only vocabulary {remote_vocabulary}"
        );
    }
    let local = Connection::open_in_memory().unwrap();
    local
        .execute_batch(local_sql)
        .expect("0001_initial.sql must execute as SQLite");
    let local_inventory = schema_inventory(&local);
    let local_tables = local_inventory.get("table").cloned().unwrap_or_default();
    let full = Connection::open_in_memory().unwrap();
    full.execute_batch(include_str!("../src/db/migrations/0001_initial.sql"))
        .expect("local base must execute before the remote extension");
    full.execute_batch(remote_sql)
        .expect("remote profile extension must execute after the local base");
    let full_inventory = schema_inventory(&full);
    let full_tables = full_inventory.get("table").cloned().unwrap_or_default();
    assert_eq!(
        ownership.keys().cloned().collect::<BTreeSet<_>>(),
        full_tables,
        "ownership manifest must classify every executed table exactly once"
    );

    let remote_tables = ownership
        .iter()
        .filter_map(|(name, owner)| (owner.status == "remove-from-v0.1").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        full_tables
            .difference(&local_tables)
            .cloned()
            .collect::<BTreeSet<_>>(),
        remote_tables
    );

    assert!(
        remote_tables.is_disjoint(&local_tables),
        "local base migration must not contain a remote-owned table"
    );

    let mut stmt = local.prepare(
        "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
    ).unwrap();
    for row in stmt
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .unwrap()
    {
        let (kind, name, owning_table, sql) = row.unwrap();
        if matches!(kind.as_str(), "index" | "trigger") {
            let owner = ownership.get(&owning_table).unwrap_or_else(|| {
                panic!("{kind} {name} has unclassified owning table {owning_table}")
            });
            assert_ne!(
                owner.status, "remove-from-v0.1",
                "retained {kind} {name} belongs to removed table {owning_table}"
            );
        }
        for remote in &remote_tables {
            assert!(
                !sql.split(
                    |character: char| !(character.is_ascii_alphanumeric() || character == '_')
                )
                .any(|token| token == remote),
                "retained {kind} {name} references removed table {remote}"
            );
        }
    }
    assert!(local_inventory.contains_key("index"));
    assert!(local_inventory.contains_key("trigger"));
    assert!(
        full_inventory
            .keys()
            .all(|kind| matches!(kind.as_str(), "table" | "index" | "trigger" | "view"))
    );

    // Disabled-but-retained tables must be justified by a real schema
    // reference from another retained object; otherwise they should not cross
    // the v0.1 boundary merely as speculative storage.
    for (table, owner) in &ownership {
        if owner.status == "launch-disabled-but-schema-required" {
            let referenced = local_inventory.iter().any(|(_, objects)| {
                objects.iter().any(|object| {
                    object != table && {
                        let sql: Option<String> = local
                            .query_row(
                                "SELECT sql FROM sqlite_schema WHERE name = ?1",
                                [object],
                                |row| row.get(0),
                            )
                            .ok();
                        sql.is_some_and(|sql| {
                            sql.split(|character: char| {
                                !(character.is_ascii_alphanumeric() || character == '_')
                            })
                            .any(|token| token == table)
                        })
                    }
                })
            });
            assert!(
                referenced,
                "disabled retained table {table} has no retained schema dependency"
            );
        }
    }
}
