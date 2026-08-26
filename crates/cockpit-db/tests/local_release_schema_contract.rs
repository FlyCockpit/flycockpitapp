//! Executed-schema contract for the physical local-v0.1 profile.

use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

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
            | "session_fts_docsize"
            | "session_fts_config"
    )
}

fn assert_session_fts_runtime_contract(conn: &Connection, local_sql: &str) {
    let declaration = local_sql
        .split("CREATE VIRTUAL TABLE session_fts")
        .nth(1)
        .and_then(|tail| tail.split_once(");").map(|(body, _)| body))
        .expect("session_fts virtual-table declaration must exist");
    assert_eq!(
        declaration, " USING fts5(\n    body,\n    content=''\n",
        "session_fts columns, tokenizer, or content options changed; review its runtime shadows"
    );

    let mut statement = conn
        .prepare(
            "SELECT name FROM sqlite_schema
             WHERE type='table' AND name LIKE 'session_fts_%' AND name!='session_fts_docs'
             ORDER BY name",
        )
        .unwrap();
    let shadows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<BTreeSet<_>>>()
        .unwrap();
    assert_eq!(
        shadows,
        BTreeSet::from([
            "session_fts_config".to_owned(),
            "session_fts_data".to_owned(),
            "session_fts_docsize".to_owned(),
            "session_fts_idx".to_owned(),
        ]),
        "contentless session_fts must generate exactly the reviewed FTS5 shadows"
    );
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
    extended_sql: &str,
    remote_sql: &str,
) {
    let local = sql_table_objects(local_sql);
    let extended = sql_table_objects(extended_sql);
    let remote = sql_table_objects(remote_sql);
    let mut counts = BTreeMap::<String, usize>::new();
    for table in local.iter().chain(&extended).chain(&remote) {
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
    let extended = extended.into_iter().collect::<BTreeSet<_>>();
    let remote = remote.into_iter().collect::<BTreeSet<_>>();
    assert!(
        local.is_disjoint(&extended) && local.is_disjoint(&remote) && extended.is_disjoint(&remote),
        "local, extended-local, and remote SQL profiles must have disjoint table ownership"
    );
    let classified_extended = ownership
        .iter()
        .filter_map(|(name, owner)| (owner.launch_profile == "extended").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        classified_extended, extended,
        "extended-local SQL tables must be exactly the extended-local classifications"
    );
    let classified_remote = ownership
        .iter()
        .filter_map(|(name, owner)| (owner.launch_profile == "remote").then_some(name.clone()))
        .collect::<BTreeSet<_>>();
    assert_eq!(classified_remote, remote);
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
    launch_profile: String,
}

fn required_text<'a>(name: &str, entry: &'a toml::value::Table, field: &str) -> &'a str {
    let value = entry
        .get(field)
        .and_then(toml::Value::as_str)
        .unwrap_or_else(|| panic!("table {name} must declare nonempty {field}"));
    assert!(!value.trim().is_empty(), "table {name} has empty {field}");
    value
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cockpit-db must live under crates/")
        .to_owned()
}

fn declared_owner_sources(owner: &str) -> Vec<PathBuf> {
    owner
        .split(" + ")
        .flat_map(|part| {
            let module = part.trim_end_matches(" table accessors");
            let relative = module
                .strip_prefix("cockpit_db::db::")
                .map(|module| ("crates/cockpit-db/src/db", module))
                .or_else(|| {
                    module
                        .strip_prefix("cockpit_core::")
                        .map(|module| ("crates/cockpit-core/src", module))
                });
            let Some((base, module)) = relative else {
                return Vec::new();
            };
            let module = module.replace("::", "/");
            vec![
                repository_root().join(format!("{base}/{module}.rs")),
                repository_root().join(format!("{base}/{module}/mod.rs")),
            ]
        })
        .collect()
}

fn csv_set(value: &str) -> BTreeSet<String> {
    value
        .split(',')
        .map(|item| item.trim().to_owned())
        .collect()
}

fn quoted_literals(value: &str) -> Vec<String> {
    value
        .split('\'')
        .enumerate()
        .filter_map(|(index, value)| (index % 2 == 1).then(|| value.to_owned()))
        .collect()
}

fn rust_constant(source: &str, symbol: &str) -> &str {
    source
        .split(&format!(" {symbol}:"))
        .nth(1)
        .and_then(|tail| tail.split("]; ").next().or_else(|| tail.split("];").next()))
        .unwrap_or_else(|| panic!("Rust contract constant {symbol} is absent"))
}

fn sql_trigger<'a>(sql: &'a str, name: &str, table: &str) -> &'a str {
    let trigger = sql
        .split(&format!("CREATE TRIGGER {name}"))
        .nth(1)
        .and_then(|tail| tail.split("END;").next())
        .unwrap_or_else(|| panic!("SQL trigger {name} is absent"));
    assert!(
        trigger.contains(&format!(" ON {table}")),
        "SQL trigger {name} is not bound to {table}"
    );
    trigger
}

fn semantic_transition_guard_tables(sql: &str) -> BTreeSet<String> {
    sql.split("CREATE TRIGGER ")
        .skip(1)
        .filter_map(|trigger| {
            let body = trigger.split("END;").next()?;
            let header = body.split("BEGIN").next()?;
            if !header.contains(" UPDATE ") && !header.contains("UPDATE ON ") {
                return None;
            }
            let field = ["state", "phase"].into_iter().find(|field| {
                let old = format!("OLD.{field}");
                let new = format!("NEW.{field}");
                if !body.contains(&old) || !body.contains(&new) {
                    return false;
                }
                body.contains(&format!("CASE {old}"))
                    || body.contains(&format!("CASE {new}"))
                    || body.contains(&format!("{old} || '>' || {new}"))
                    || body.contains(&format!("{old}<>{new}"))
                    || body.contains(&format!("{old} <> {new}"))
                    || body.lines().any(|line| {
                        line.contains(&old)
                            && line.contains(&new)
                            && ["=", "<>", "!=", " IN ", " NOT IN "]
                                .iter()
                                .any(|operator| line.contains(operator))
                    })
                    || (body.contains(&format!("{old} = '"))
                        && (body.contains(&format!("{new} <> '"))
                            || body.contains(&format!("{new} != '"))
                            || body.contains(&format!("{new} NOT IN ("))))
            });
            field?;
            let tokens = header.split_whitespace().collect::<Vec<_>>();
            tokens
                .windows(2)
                .rev()
                .find_map(|pair| (pair[0] == "ON").then(|| pair[1].trim().to_owned()))
        })
        .collect()
}

fn sql_registry_edges(sql: &str, registry: &str) -> BTreeSet<String> {
    let values = sql
        .split(&format!("INSERT INTO {registry} VALUES"))
        .nth(1)
        .and_then(|tail| tail.split(';').next())
        .unwrap_or_else(|| panic!("SQL transition registry {registry} has no seed rows"));
    let literals = quoted_literals(values);
    assert_eq!(
        literals.len() % 2,
        0,
        "SQL registry {registry} is malformed"
    );
    literals
        .chunks_exact(2)
        .map(|edge| format!("{}>{}", edge[0], edge[1]))
        .collect()
}

fn quoted_set_after(value: &str, marker: &str) -> BTreeSet<String> {
    value
        .split(marker)
        .nth(1)
        .and_then(|tail| tail.split(')').next())
        .map(quoted_literals)
        .unwrap_or_else(|| panic!("SQL state allowlist marker {marker} is absent"))
        .into_iter()
        .collect()
}

fn cartesian_edges(from: &str, destinations: BTreeSet<String>) -> BTreeSet<String> {
    destinations
        .into_iter()
        .filter(|to| to != from)
        .map(|to| format!("{from}>{to}"))
        .collect()
}

fn sql_state_check(declaration: &str) -> &str {
    [
        "CHECK (state IN (",
        "CHECK(state IN (",
        "CHECK (state IN(",
        "CHECK(state IN(",
    ]
    .into_iter()
    .find_map(|marker| declaration.split(marker).nth(1))
    .and_then(|tail| tail.split("))").next())
    .or_else(|| {
        [
            "CHECK (phase IN (",
            "CHECK(phase IN (",
            "CHECK (phase IN(",
            "CHECK(phase IN(",
        ]
        .into_iter()
        .find_map(|marker| declaration.split(marker).nth(1))
        .and_then(|tail| tail.split("))").next())
    })
    .unwrap_or_else(|| panic!("table has no closed SQL state/phase CHECK"))
}

fn sql_only_edges(name: &str, trigger: &str) -> BTreeSet<String> {
    match name {
        "media_repair" => {
            let normalized = trigger.split_whitespace().collect::<Vec<_>>().join(" ");
            assert!(normalized.contains("(OLD.state='planned' AND NEW.state='rebuilding') OR (OLD.state='rebuilding' AND NEW.state='verifying') OR (OLD.state='verifying' AND NEW.state IN ('committed','failed')) OR OLD.state=NEW.state"), "media repair SQL edge graph drifted");
            BTreeSet::from([
                "planned>rebuilding".to_owned(),
                "rebuilding>verifying".to_owned(),
                "verifying>committed".to_owned(),
                "verifying>failed".to_owned(),
            ])
        }
        "remote_attachment_operation" => {
            let mut edges = cartesian_edges(
                "reserved",
                quoted_set_after(trigger, "OLD.state = 'reserved' AND NEW.state NOT IN ("),
            );
            edges.extend(cartesian_edges(
                "dispatched",
                quoted_set_after(trigger, "OLD.state = 'dispatched' AND NEW.state NOT IN ("),
            ));
            edges
        }
        "image_response_publication" => {
            assert!(trigger.contains("OLD.state!='pending'"));
            cartesian_edges("pending", quoted_set_after(trigger, "NEW.state NOT IN ("))
        }
        "image_security_recovery_attempt" => {
            assert!(trigger.contains("OLD.state!='received'"));
            cartesian_edges("received", quoted_set_after(trigger, "NEW.state NOT IN ("))
        }
        "image_security_recovery_audit" => {
            assert!(trigger.contains("OLD.state!='recorded'"));
            cartesian_edges("recorded", quoted_set_after(trigger, "NEW.state NOT IN ("))
        }
        "write_scope_transfer" => {
            let states = [
                "prepared",
                "parent_excluded",
                "child_activated",
                "child_terminal",
                "parent_restored",
                "committed",
            ];
            for (index, state) in states.iter().enumerate() {
                assert!(
                    trigger.contains(&format!("WHEN '{state}' THEN {index}")),
                    "write-scope transfer SQL phase ordering drifted"
                );
            }
            let mut edges = states
                .iter()
                .map(|state| format!("{state}>{state}"))
                .collect::<BTreeSet<_>>();
            edges.extend(
                states
                    .windows(2)
                    .map(|pair| format!(">{}", pair[1]))
                    .zip(states)
                    .map(|(to, from)| format!("{from}{to}")),
            );
            assert!(trigger.contains("NEW.phase = 'committed' AND OLD.child_lease_id IS NULL"));
            edges.insert("prepared>committed".to_owned());
            edges
        }
        "write_scope_permit" => {
            assert!(trigger.contains("OLD.state = 'released' AND NEW.state <> 'released'"));
            BTreeSet::from([
                "held>held".to_owned(),
                "held>released".to_owned(),
                "released>released".to_owned(),
            ])
        }
        "remote_rename" => {
            let cases = [
                (
                    "prepared",
                    &["prepared", "artifact_synced", "effect_unknown"][..],
                ),
                (
                    "artifact_synced",
                    &[
                        "artifact_synced",
                        "renamed",
                        "applied_mismatch",
                        "effect_unknown",
                    ][..],
                ),
                (
                    "renamed",
                    &["renamed", "source_parent_synced", "effect_unknown"][..],
                ),
                (
                    "source_parent_synced",
                    &[
                        "source_parent_synced",
                        "target_parent_synced",
                        "effect_unknown",
                    ][..],
                ),
                (
                    "target_parent_synced",
                    &["target_parent_synced", "applied", "effect_unknown"][..],
                ),
                ("applied", &["applied", "ledger_committed"][..]),
            ];
            let mut edges = BTreeSet::new();
            for (from, destinations) in cases {
                let marker = format!("WHEN '{from}' THEN NEW.state NOT IN (");
                let parsed = quoted_set_after(trigger, &marker);
                assert_eq!(
                    parsed,
                    destinations
                        .iter()
                        .map(|value| (*value).to_owned())
                        .collect(),
                    "remote rename SQL CASE drifted for {from}"
                );
                edges.extend(destinations.iter().map(|to| format!("{from}>{to}")));
            }
            for terminal in ["applied_mismatch", "effect_unknown", "ledger_committed"] {
                edges.insert(format!("{terminal}>{terminal}"));
            }
            edges
        }
        _ => panic!("SQL-only family {name} needs a registry or exact extractor"),
    }
}

fn ownership() -> BTreeMap<String, Ownership> {
    let parsed: toml::Value = toml::from_str(include_str!("../schema-ownership.toml"))
        .expect("schema-ownership.toml must be valid TOML");
    let families = parsed
        .get("state_machine_family")
        .and_then(toml::Value::as_table)
        .expect("schema-ownership.toml must contain state-machine families");
    assert!(
        !families.is_empty(),
        "state-machine families cannot be vacuous"
    );
    for (name, value) in families {
        let family = value
            .as_table()
            .unwrap_or_else(|| panic!("state-machine family {name} must be a rich record"));
        for field in [
            "table",
            "rust_source",
            "states_symbol",
            "edges_symbol",
            "terminals_symbol",
            "sql_triggers",
            "allowed_states",
            "edges",
            "recovery_entrypoint",
            "terminal_states",
            "retention_rule",
            "authoritative_invariant",
        ] {
            required_text(name, family, field);
        }
        let allowed = csv_set(required_text(name, family, "allowed_states"));
        let edges = csv_set(required_text(name, family, "edges"));
        let terminal = csv_set(required_text(name, family, "terminal_states"));
        assert!(
            !terminal.is_empty(),
            "state-machine family {name} needs terminal states"
        );
        assert!(
            terminal.is_subset(&allowed),
            "family {name} terminal states must be allowed"
        );
        let sql = [
            include_str!("../src/db/migrations/0001_initial.sql"),
            include_str!("../src/db/migrations/0001_extended_profile.sql"),
            include_str!("../src/db/migrations/0001_remote_profile.sql"),
        ]
        .join("\n");
        let table = required_text(name, family, "table");
        let declaration = sql
            .split(&format!("CREATE TABLE {table}"))
            .nth(1)
            .and_then(|tail| tail.split(";").next())
            .unwrap_or_else(|| panic!("family {name} table declaration is absent"));
        if family.get("state_columns").is_none() {
            let sql_states = quoted_literals(sql_state_check(declaration))
                .into_iter()
                .collect::<BTreeSet<_>>();
            assert_eq!(allowed, sql_states, "family {name} SQL state set drifted");
        }
        let mut sql_edges = family
            .get("sql_edge_registry")
            .and_then(toml::Value::as_str)
            .map(|registry| sql_registry_edges(&sql, registry))
            .unwrap_or_default();
        let mut trigger_bodies = String::new();
        for trigger_name in required_text(name, family, "sql_triggers")
            .split(',')
            .map(str::trim)
        {
            let trigger = sql_trigger(&sql, trigger_name, table);
            trigger_bodies.push_str(trigger);
            for literal in quoted_literals(trigger) {
                if literal.contains('>') {
                    sql_edges.insert(literal);
                }
            }
        }
        assert_eq!(edges, sql_edges, "family {name} SQL edge set drifted");
        let conditional_edges = family
            .get("conditional_edges")
            .and_then(toml::Value::as_str)
            .map(csv_set)
            .unwrap_or_default();
        if !conditional_edges.is_empty() {
            assert_eq!(
                conditional_edges,
                BTreeSet::from([
                    "dispatching>queued".to_owned(),
                    "submission_unknown>queued".to_owned(),
                ]),
                "family {name} has an unknown conditional-edge shape"
            );
            assert!(
                trigger_bodies.contains("OLD.state IN ('dispatching','submission_unknown')")
                    && trigger_bodies.contains("NEW.state='queued'"),
                "family {name} SQL conditional retry edges drifted"
            );
        }
        let sql_sources = sql_edges
            .iter()
            .chain(conditional_edges.iter())
            .filter_map(|edge| edge.split_once('>').map(|(from, _)| from.to_owned()))
            .collect::<BTreeSet<_>>();
        assert_eq!(
            terminal,
            allowed.difference(&sql_sources).cloned().collect(),
            "family {name} SQL terminal set drifted"
        );
        if family.get("state_columns").is_some() {
            let edge_states = edges
                .iter()
                .flat_map(|edge| edge.split('>').map(str::to_owned))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                allowed, edge_states,
                "family {name} SQL event state vocabulary drifted"
            );
            let sql_terminals = quoted_literals(&trigger_bodies)
                .into_iter()
                .filter(|literal| allowed.contains(literal))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                terminal, sql_terminals,
                "family {name} SQL event terminal flag drifted"
            );
        }
        let rust_source = repository_root().join(required_text(name, family, "rust_source"));
        let rust = std::fs::read_to_string(&rust_source).unwrap_or_else(|error| {
            panic!(
                "family {name} Rust source {} is unreadable: {error}",
                rust_source.display()
            )
        });
        let rust_states = quoted_literals(rust_constant(
            &rust,
            required_text(name, family, "states_symbol"),
        ))
        .into_iter()
        .collect::<BTreeSet<_>>();
        let rust_edge_values = quoted_literals(rust_constant(
            &rust,
            required_text(name, family, "edges_symbol"),
        ));
        assert_eq!(
            rust_edge_values.len() % 2,
            0,
            "family {name} Rust edge constant is malformed"
        );
        let rust_edges = rust_edge_values
            .chunks_exact(2)
            .map(|edge| format!("{}>{}", edge[0], edge[1]))
            .collect::<BTreeSet<_>>();
        let rust_conditional_edges = family
            .get("conditional_edges_symbol")
            .and_then(toml::Value::as_str)
            .map(|symbol| {
                let values = quoted_literals(rust_constant(&rust, symbol));
                assert_eq!(
                    values.len() % 2,
                    0,
                    "family {name} Rust conditional edges malformed"
                );
                values
                    .chunks_exact(2)
                    .map(|edge| format!("{}>{}", edge[0], edge[1]))
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let rust_terminals = quoted_literals(rust_constant(
            &rust,
            required_text(name, family, "terminals_symbol"),
        ))
        .into_iter()
        .collect::<BTreeSet<_>>();
        assert_eq!(allowed, rust_states, "family {name} Rust state set drifted");
        assert_eq!(edges, rust_edges, "family {name} Rust edge set drifted");
        assert_eq!(
            conditional_edges, rust_conditional_edges,
            "family {name} Rust conditional edge set drifted"
        );
        assert_eq!(
            terminal, rust_terminals,
            "family {name} Rust terminal set drifted"
        );
    }
    let sql_families = parsed
        .get("sql_state_machine")
        .and_then(toml::Value::as_table)
        .expect("schema-ownership.toml must contain SQL-only state-machine families");
    let all_sql = [
        include_str!("../src/db/migrations/0001_initial.sql"),
        include_str!("../src/db/migrations/0001_extended_profile.sql"),
        include_str!("../src/db/migrations/0001_remote_profile.sql"),
    ]
    .join("\n");
    for (name, value) in sql_families {
        let family = value
            .as_table()
            .unwrap_or_else(|| panic!("SQL-only family {name} must be a rich record"));
        for field in [
            "table",
            "sql_triggers",
            "allowed_states",
            "edges",
            "terminal_states",
            "edge_evidence",
        ] {
            required_text(name, family, field);
        }
        let table_name = required_text(name, family, "table");
        let declaration = all_sql
            .split(&format!("CREATE TABLE {table_name}"))
            .nth(1)
            .and_then(|tail| tail.split(';').next())
            .unwrap_or_else(|| panic!("SQL-only family {name} table is absent"));
        let allowed = csv_set(required_text(name, family, "allowed_states"));
        if family.get("state_columns").is_none() {
            assert_eq!(
                allowed,
                quoted_literals(sql_state_check(declaration))
                    .into_iter()
                    .collect(),
                "SQL-only family {name} state set drifted"
            );
        }
        let trigger = required_text(name, family, "sql_triggers")
            .split(',')
            .map(str::trim)
            .map(|trigger| sql_trigger(&all_sql, trigger, table_name))
            .collect::<Vec<_>>()
            .join("\n");
        let evidence = required_text(name, family, "edge_evidence");
        let sql_edges = if let Some(registry) = family
            .get("sql_edge_registry")
            .and_then(toml::Value::as_str)
        {
            sql_registry_edges(&all_sql, registry)
        } else if evidence == "quoted-edges" {
            quoted_literals(&trigger)
                .into_iter()
                .filter(|literal| literal.contains('>'))
                .collect()
        } else if evidence == "terminal-only" {
            let terminals = csv_set(required_text(name, family, "terminal_states"));
            allowed
                .iter()
                .filter(|from| !terminals.contains(*from))
                .flat_map(|from| {
                    allowed
                        .iter()
                        .filter(move |to| *to != from)
                        .map(move |to| format!("{from}>{to}"))
                })
                .collect()
        } else {
            sql_only_edges(name, &trigger)
        };
        let edges = csv_set(required_text(name, family, "edges"));
        assert_eq!(edges, sql_edges, "SQL-only family {name} edge set drifted");
        let declared_terminals = csv_set(required_text(name, family, "terminal_states"));
        if evidence == "terminal-only" {
            let sql_terminals = if trigger.contains("OLD.state LIKE 'terminal_%'") {
                allowed
                    .iter()
                    .filter(|state| state.starts_with("terminal_"))
                    .cloned()
                    .collect()
            } else {
                quoted_literals(&trigger)
                    .into_iter()
                    .filter(|literal| allowed.contains(literal))
                    .collect()
            };
            assert_eq!(
                declared_terminals, sql_terminals,
                "SQL-only family {name} terminal guard drifted"
            );
        }
        if family.get("state_columns").is_some() {
            let edge_states = edges
                .iter()
                .flat_map(|edge| edge.split('>').map(str::to_owned))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                allowed, edge_states,
                "SQL-only event family {name} state vocabulary drifted"
            );
            let sql_terminals = quoted_literals(&trigger)
                .into_iter()
                .filter(|literal| allowed.contains(literal))
                .collect::<BTreeSet<_>>();
            assert_eq!(
                declared_terminals, sql_terminals,
                "SQL-only event family {name} terminal flag drifted"
            );
        }
        let sources = edges
            .iter()
            .filter_map(|edge| {
                edge.split_once('>')
                    .filter(|(from, to)| from != to)
                    .map(|(from, _)| from.to_owned())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            declared_terminals,
            allowed.difference(&sources).cloned().collect(),
            "SQL-only family {name} terminal set drifted"
        );
    }
    let table = parsed
        .get("table")
        .and_then(toml::Value::as_table)
        .expect("schema-ownership.toml must contain a nonempty [table] map");
    let sql = [
        include_str!("../src/db/migrations/0001_initial.sql"),
        include_str!("../src/db/migrations/0001_extended_profile.sql"),
        include_str!("../src/db/migrations/0001_remote_profile.sql"),
    ]
    .join("\n");
    let guarded_tables = semantic_transition_guard_tables(&sql);
    let explicit_guarded_tables = [
        "agent_editor_leases",
        "external_journal_operations",
        "image_generation_artifact_cleanup_intents",
        "image_generation_artifact_components",
        "image_generation_artifact_security_recovery_attempts",
        "image_generation_artifact_security_recovery_audits",
        "image_generation_artifacts",
        "image_generation_attempts",
        "image_generation_jobs",
        "image_generation_late_publication_leases",
        "image_generation_response_publication_intents",
        "image_generation_slots",
        "local_operation_receipts",
        "media_repair_attempts",
        "media_reservations",
        "remote_attachment_operations",
        "remote_rename_journal",
        "task_artifacts",
        "workspace_leases",
        "write_scope_leases",
        "write_scope_permits",
        "write_scope_transfers",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    assert_eq!(
        guarded_tables, explicit_guarded_tables,
        "semantic SQL transition-guard registry drifted"
    );
    for guarded_table in &guarded_tables {
        let classification = table
            .get(guarded_table)
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("transition-guarded table {guarded_table} is unclassified"));
        assert_ne!(
            required_text(guarded_table, classification, "state_machine"),
            "none",
            "transition-guarded table {guarded_table} cannot be classified none"
        );
    }
    let exact_guarded_tables = families
        .values()
        .filter(|family| {
            family
                .as_table()
                .is_some_and(|family| family.get("state_columns").is_none())
        })
        .chain(sql_families.values())
        .filter_map(|family| family.as_table()?.get("table")?.as_str().map(str::to_owned))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        guarded_tables, exact_guarded_tables,
        "transition-guard inventory and exact family inventory must match"
    );
    assert!(
        !table.is_empty(),
        "ownership classification cannot be vacuous"
    );
    let referenced_families = table
        .iter()
        .filter_map(|(name, value)| {
            let entry = value.as_table()?;
            (entry.get("state_machine")?.as_str()? == "rust-and-sql")
                .then(|| required_text(name, entry, "state_machine_family").to_owned())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        referenced_families,
        families.keys().cloned().collect::<BTreeSet<_>>(),
        "every state-machine family must be referenced and every reference must resolve"
    );
    let referenced_sql_families = table
        .iter()
        .filter_map(|(name, value)| {
            let entry = value.as_table()?;
            (entry.get("state_machine")?.as_str()? == "sql")
                .then(|| required_text(name, entry, "sql_state_machine_family").to_owned())
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        referenced_sql_families,
        sql_families.keys().cloned().collect::<BTreeSet<_>>(),
        "every SQL-only family must be referenced and every reference must resolve"
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
                "semantic_class",
                "identity_policy",
                "snapshot_policy",
                "launch_profile",
                "invariant_owner",
            ] {
                required_text(name, entry, field);
            }
            let status = required_text(name, entry, "status");
            let rust_owner = required_text(name, entry, "rust_owner");
            let recovery = required_text(name, entry, "recovery_entrypoint");
            assert_ne!(
                rust_owner, "cockpit-db::db",
                "table {name} has a generic Rust owner"
            );
            assert_ne!(
                rust_owner, "cockpit_db::db",
                "table {name} has a generic Rust owner"
            );
            let owner_sources = declared_owner_sources(rust_owner);
            assert!(
                !owner_sources.is_empty(),
                "table {name} must declare a resolvable Rust owner module"
            );
            assert!(
                owner_sources.iter().any(|source| {
                    std::fs::read_to_string(source).is_ok_and(|contents| contents.contains(name))
                }),
                "table {name} is absent from every declared Rust owner source: {owner_sources:?}"
            );
            for placeholder in [
                "cockpit-db remote domain module",
                "cockpit-db::db:: methods",
                "daemon-owned domain retention policy",
            ] {
                assert!(
                    !entry
                        .values()
                        .filter_map(toml::Value::as_str)
                        .any(|value| value.contains(placeholder)),
                    "table {name} contains generic placeholder {placeholder}"
                );
            }
            assert!(
                !recovery.contains("daemon boot recovery and cockpit doctor inspection"),
                "table {name} has a generic recovery placeholder"
            );
            let state_machine = required_text(name, entry, "state_machine");
            assert!(
                matches!(state_machine, "rust" | "sql" | "rust-and-sql" | "none"),
                "table {name} has unsupported state-machine ownership {state_machine}"
            );
            if state_machine == "rust-and-sql" {
                let family = required_text(name, entry, "state_machine_family");
                assert!(
                    families.contains_key(family),
                    "table {name} references unknown state-machine family {family}"
                );
                assert_eq!(
                    recovery,
                    format!("state-machine-family:{family}"),
                    "table {name} must delegate recovery to its declared family"
                );
            }
            let semantic_class = required_text(name, entry, "semantic_class");
            assert!(
                matches!(
                    semantic_class,
                    "entity"
                        | "junction"
                        | "immutable-fact"
                        | "projection"
                        | "singleton"
                        | "queue-lease"
                ),
                "table {name} has unsupported semantic class {semantic_class}"
            );
            let launch_profile = required_text(name, entry, "launch_profile");
            assert!(
                matches!(launch_profile, "local" | "extended" | "remote"),
                "table {name} has unsupported launch profile {launch_profile}"
            );
            assert_eq!(
                status == "launch-required",
                launch_profile == "local",
                "table {name} launch status/profile disagree"
            );
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
                    launch_profile: launch_profile.to_owned(),
                },
            )
        })
        .collect()
}

fn applied_profile_inventory(
    extended: bool,
    remote: bool,
    ownership: &BTreeMap<String, Ownership>,
) -> BTreeMap<String, BTreeSet<String>> {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(include_str!("../src/db/migrations/0001_initial.sql"))
        .expect("local base schema must apply first");
    if extended {
        conn.execute_batch(include_str!(
            "../src/db/migrations/0001_extended_profile.sql"
        ))
        .expect("extended-local schema must apply after local base");
    }
    if remote {
        conn.execute_batch(include_str!("../src/db/migrations/0001_remote_profile.sql"))
            .expect("remote schema must apply after local base");
    }
    let inventory = schema_inventory(&conn);
    let tables = inventory.get("table").cloned().unwrap_or_default();
    let mut statement = conn
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_schema \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .unwrap();
    for row in statement
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
            assert!(
                tables.contains(&owning_table) || is_runtime_managed_table(&owning_table),
                "profile object {kind} {name} has absent owning table {owning_table}"
            );
        }
        for classified_table in ownership.keys() {
            let referenced = sql
                .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .any(|token| token == classified_table);
            assert!(
                !referenced || tables.contains(classified_table),
                "profile object {kind} {name} references absent table {classified_table}"
            );
        }
    }
    inventory
}

#[test]
fn all_four_schema_profiles_have_exact_physical_ownership() {
    let local_sql = include_str!("../src/db/migrations/0001_initial.sql");
    let extended_sql = include_str!("../src/db/migrations/0001_extended_profile.sql");
    let remote_sql = include_str!("../src/db/migrations/0001_remote_profile.sql");
    let profile_sql = [
        local_sql.to_owned(),
        [local_sql, extended_sql].concat(),
        [local_sql, remote_sql].concat(),
        [local_sql, extended_sql, remote_sql].concat(),
    ];
    assert!(
        profile_sql[3].starts_with(&profile_sql[1])
            && &profile_sql[3][profile_sql[1].len()..] == remote_sql,
        "full profile composition must be local then extended then remote"
    );
    let ownership = ownership();
    // Keep this source-level gate before either migration is handed to SQLite:
    // malformed or unavailable extensions must not hide ownership drift.
    assert_static_table_ownership(&ownership, local_sql, extended_sql, remote_sql);
    for remote_vocabulary in ["remote_device", "public_remote"] {
        assert!(
            !local_sql.contains(remote_vocabulary),
            "local launch schema contains remote-only vocabulary {remote_vocabulary}"
        );
    }
    for deferred_table in [
        "scheduled_jobs",
        "image_spend_policy_versions",
        "image_generation_jobs",
    ] {
        assert!(
            !sql_table_objects(local_sql)
                .iter()
                .any(|table| table == deferred_table),
            "local launch schema contains deferred table {deferred_table}"
        );
        assert!(
            sql_table_objects(extended_sql)
                .iter()
                .any(|table| table == deferred_table),
            "extended-local schema is missing deferred table {deferred_table}"
        );
    }
    let local = Connection::open_in_memory().unwrap();
    local
        .execute_batch(local_sql)
        .expect("0001_initial.sql must execute as SQLite");
    assert_session_fts_runtime_contract(&local, local_sql);
    let local_inventory = applied_profile_inventory(false, false, &ownership);
    let local_tables = local_inventory.get("table").cloned().unwrap_or_default();
    let extended_inventory = applied_profile_inventory(true, false, &ownership);
    let remote_inventory = applied_profile_inventory(false, true, &ownership);
    let full_inventory = applied_profile_inventory(true, true, &ownership);
    let full_tables = full_inventory.get("table").cloned().unwrap_or_default();
    assert_eq!(
        ownership.keys().cloned().collect::<BTreeSet<_>>(),
        full_tables,
        "ownership manifest must classify every executed table exactly once"
    );

    for (label, inventory, included_profiles) in [
        ("local", &local_inventory, &["local"][..]),
        (
            "local+extended",
            &extended_inventory,
            &["local", "extended"][..],
        ),
        ("local+remote", &remote_inventory, &["local", "remote"][..]),
        (
            "local+extended+remote",
            &full_inventory,
            &["local", "extended", "remote"][..],
        ),
    ] {
        let expected = ownership
            .iter()
            .filter_map(|(name, owner)| {
                included_profiles
                    .contains(&owner.launch_profile.as_str())
                    .then_some(name.clone())
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(
            inventory.get("table").cloned().unwrap_or_default(),
            expected,
            "{label} profile table inventory disagrees with ownership manifest"
        );
    }

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

#[test]
fn extended_local_and_remote_feature_gates_remain_independent() {
    let cli_config = include_str!("../../../apps/cli/src/commands/config.rs");
    assert!(
        !cli_config.contains("feature = \"remote\""),
        "image-spend CLI code must be gated only by extended"
    );
    assert_eq!(
        cli_config.matches("feature = \"extended\"").count(),
        4,
        "ImageSpendArgs import, bail import, dispatch arm, and handler must share one gate"
    );

    let cli_manifest = include_str!("../../../apps/cli/Cargo.toml");
    let core_manifest = include_str!("../../cockpit-core/Cargo.toml");
    let db_manifest = include_str!("../Cargo.toml");
    for manifest in [cli_manifest, core_manifest, db_manifest] {
        assert!(
            manifest.contains("extended = ["),
            "extended feature is missing"
        );
        let remote = manifest
            .split("remote = [")
            .nth(1)
            .and_then(|tail| tail.split_once(']').map(|(body, _)| body))
            .expect("remote feature declaration must remain explicit");
        assert!(
            !remote.contains("extended"),
            "remote must not implicitly enable future local product domains"
        );
    }

    let migration_runner = include_str!("../src/db/mod.rs");
    assert!(migration_runner.contains("#[cfg(feature = \"extended\")]\n    deferred_sql:"));
    assert!(migration_runner.contains("#[cfg(feature = \"remote\")]\n    extension_sql:"));
    assert!(migration_runner.contains("remote-extended-v0.1"));
}
