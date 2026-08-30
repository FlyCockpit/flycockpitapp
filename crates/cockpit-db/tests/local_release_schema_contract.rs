//! Executed-schema contract for the physical local-v0.1 profile.

use rusqlite::Connection;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::parse::Parser;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

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
        .filter_map(|(index, value)| (index % 2 == 1).then_some(value.to_owned()))
        .collect()
}

fn rust_string_literals(value: &str) -> Vec<String> {
    value
        .split('"')
        .enumerate()
        .filter_map(|(index, value)| (index % 2 == 1).then_some(value.to_owned()))
        .collect()
}

fn table_declaration<'a>(sql: &'a str, table: &str) -> &'a str {
    let tail = sql
        .split(&format!("CREATE TABLE {table}"))
        .nth(1)
        .unwrap_or_else(|| panic!("CREATE TABLE {table} is absent"));
    let bytes = tail.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'-' && bytes.get(index + 1) == Some(&b'-') {
            while index < bytes.len() && bytes[index] != b'\n' {
                index += 1;
            }
            continue;
        }
        if bytes[index] == b';' {
            return &tail[..index];
        }
        index += 1;
    }
    panic!("CREATE TABLE {table} is unterminated")
}

fn rust_constant<'a>(source: &'a str, symbol: &str) -> &'a str {
    source
        .split(&format!(" {symbol}:"))
        .nth(1)
        .and_then(|tail| tail.split_once("];").map(|(body, _)| body))
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
                if !body.contains(&old) {
                    return false;
                }
                // Terminal-final UPDATE guards mention only OLD.state.
                if !body.contains(&new) {
                    return body.contains(&format!("{old} = 'terminal"))
                        || body.contains(&format!("{old} LIKE 'terminal_"));
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
            let event = tokens.iter().position(|token| {
                matches!(
                    *token,
                    "UPDATE" | "INSERT" | "DELETE" | "update" | "insert" | "delete"
                )
            })?;
            tokens[event + 1..].windows(2).find_map(|pair| {
                (pair[0] == "ON" || pair[0] == "on").then(|| {
                    pair[1]
                        .trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_')
                        .to_owned()
                })
            })
        })
        .collect()
}

#[derive(Clone)]
struct TransitionEvidence {
    line: usize,
    family: &'static str,
    edge: Option<(String, String)>,
}
#[derive(Clone)]
struct StateMutation {
    line: usize,
    family: &'static str,
    edge: Option<(String, String)>,
    exact_cas: bool,
}
#[derive(Default)]
struct TransitionAstAudit {
    validators: Vec<TransitionEvidence>,
    mutations: Vec<StateMutation>,
    row_count_checks: usize,
}

fn image_family(value: &str) -> Option<&'static str> {
    match value {
        "job_transition_allowed" | "IMAGE_JOB_CONDITIONAL_EDGES" | "image_generation_jobs" => {
            Some("job")
        }
        "slot_transition_allowed" | "IMAGE_SLOT_CONDITIONAL_EDGES" | "image_generation_slots" => {
            Some("slot")
        }
        "attempt_transition_allowed" | "image_generation_attempts" => Some("attempt"),
        "artifact_transition_allowed" | "image_generation_artifacts" => Some("artifact"),
        "artifact_component_transition_allowed" | "image_generation_artifact_components" => {
            Some("component")
        }
        _ => None,
    }
}

fn path_tail(expr: &syn::Expr) -> Option<String> {
    let syn::Expr::Path(path) = expr else {
        return None;
    };
    path.path
        .segments
        .last()
        .map(|segment| segment.ident.to_string())
}

fn sql_literal_edge(sql: &str) -> Option<(String, String)> {
    fn state_literal(value: &str) -> Option<String> {
        let tail = value.split("state").nth(1)?;
        let quote = tail.find('\'')?;
        let remainder = &tail[quote + 1..];
        Some(remainder.split('\'').next()?.to_owned())
    }
    let (assignments, predicate) = sql.split_once(" WHERE ")?;
    Some((state_literal(predicate)?, state_literal(assignments)?))
}

impl<'ast> Visit<'ast> for TransitionAstAudit {
    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        self.row_count_checks += mac.tokens.to_string().matches("== 1").count();
        if let Ok(arguments) =
            syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                .parse2(mac.tokens.clone())
        {
            for argument in arguments {
                let mut nested = TransitionAstAudit::default();
                nested.visit_expr(&argument);
                self.validators.extend(nested.validators);
                self.mutations.extend(nested.mutations);
                self.row_count_checks += nested.row_count_checks;
            }
        }
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let Some(name) = path_tail(&call.func)
            && let Some(family) = image_family(&name)
        {
            let edge = call
                .args
                .first()
                .and_then(path_tail)
                .zip(call.args.iter().nth(1).and_then(path_tail));
            self.validators.push(TransitionEvidence {
                line: call.span().start().line,
                family,
                edge,
            });
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "contains"
            && let Some(name) = path_tail(&call.receiver)
            && let Some(family) = image_family(&name)
        {
            self.validators.push(TransitionEvidence {
                line: call.span().start().line,
                family,
                edge: None,
            });
        }
        if call.method == "execute"
            && let Some(syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(sql),
                ..
            })) = call.args.first()
        {
            let normalized = sql.value().split_whitespace().collect::<Vec<_>>().join(" ");
            for table in [
                "image_generation_jobs",
                "image_generation_slots",
                "image_generation_attempts",
                "image_generation_artifacts",
                "image_generation_artifact_components",
            ] {
                let marker = format!("UPDATE {table} SET ");
                if let Some(tail) = normalized.split(&marker).nth(1)
                    && tail
                        .split(" WHERE ")
                        .next()
                        .is_some_and(|set| set.contains("state=") || set.contains("state ="))
                {
                    let predicate = normalized.split(" WHERE ").nth(1).unwrap_or_default();
                    self.mutations.push(StateMutation {
                        line: call.span().start().line,
                        family: image_family(table).unwrap(),
                        edge: sql_literal_edge(&normalized),
                        exact_cas: (predicate.contains("state=") || predicate.contains("state ="))
                            && (predicate.contains("version=")
                                || predicate.contains("version =")
                                || predicate.contains("generation=")
                                || predicate.contains("generation =")),
                    });
                }
            }
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn audit_transition_block(block: &syn::Block) -> Result<(), String> {
    let mut audit = TransitionAstAudit::default();
    audit.visit_block(block);
    audit.validators.sort_by_key(|item| item.line);
    audit.mutations.sort_by_key(|item| item.line);
    let mut used = BTreeSet::new();
    for mutation in audit.mutations {
        let candidate = audit
            .validators
            .iter()
            .enumerate()
            .find(|(index, validator)| {
                !used.contains(index)
                    && validator.family == mutation.family
                    && validator.line <= mutation.line
                    && match (&mutation.edge, &validator.edge) {
                        (Some((from, to)), Some((validated_from, validated_to))) => {
                            let expected = |state: &str| {
                                state
                                    .split('_')
                                    .map(|part| {
                                        let mut chars = part.chars();
                                        chars
                                            .next()
                                            .into_iter()
                                            .flat_map(char::to_uppercase)
                                            .chain(chars)
                                            .collect::<String>()
                                    })
                                    .collect::<String>()
                            };
                            *validated_from == expected(from) && *validated_to == expected(to)
                        }
                        _ => true,
                    }
            });
        let Some((index, _)) = candidate else {
            return Err(format!(
                "{} state mutation at line {} has no preceding exact validator",
                mutation.family, mutation.line
            ));
        };
        used.insert(index);
    }
    Ok(())
}

const IMAGE_STATE_EXECUTORS: &[&str] = &[
    "execute_image_job_transition_conn",
    "transition_image_generation_artifact_conn",
    "transition_image_generation_artifact_component_conn",
    "execute_late_publication_artifact_transition_conn",
    "execute_artifact_cleanup_transition_conn",
    "execute_component_tombstone_transition_conn",
    "execute_artifact_tombstone_transition_conn",
    "execute_basic_image_slot_transition_conn",
    "execute_basic_image_attempt_transition_conn",
    "execute_queue_image_slots_conn",
    "execute_image_publication_attempt_transition_conn",
    "execute_image_publication_slot_transition_conn",
    "execute_image_dispatch_preparation_transitions_conn",
    "execute_image_attempt_handoff_transition_conn",
    "execute_image_handoff_outcome_transitions_conn",
    "execute_reconciliation_claim_attempt_transition_conn",
    "execute_reconciliation_state_transitions_conn",
    "execute_accepted_response_failure_transitions_conn",
    "execute_response_adoption_transitions_conn",
    "execute_deadline_attempt_journal_binding_conn",
    "execute_cancellation_attempt_transition_conn",
    "execute_cancellation_slot_transition_conn",
    "execute_validating_slot_cancellation_marker_conn",
    "execute_late_publication_slot_transition_conn",
    "execute_security_blocked_artifact_cleanup_transition_conn",
    "execute_ready_component_cleanup_transition_conn",
    "execute_security_blocked_component_cleanup_transition_conn",
    "execute_late_quarantined_artifact_retention_transition_conn",
    "execute_security_blocked_artifact_retention_transition_conn",
];

fn raw_transition_boundary_error(
    name: &str,
    block: &syn::Block,
    trust_executor: bool,
) -> Option<String> {
    let mut audit = TransitionAstAudit::default();
    audit.visit_block(block);
    let mutation_count = audit.mutations.len();
    audit
        .mutations
        .into_iter()
        .find_map(|mutation| {
            (!(trust_executor && IMAGE_STATE_EXECUTORS.contains(&name)))
                .then_some(())
                .map(|_| {
                    format!(
                        "{name} contains raw {} state SQL outside a typed executor",
                        mutation.family
                    )
                })
                .or_else(|| {
                    (!mutation.exact_cas).then(|| {
                        format!("{name} contains a state mutation without exact state/version CAS")
                    })
                })
        })
        .or_else(|| {
            (mutation_count > 0 && audit.row_count_checks == 0)
                .then(|| format!("{name} does not enforce changed == 1 for its state mutation"))
        })
}

#[derive(Default)]
struct RawImageSqlLiteralAudit {
    literals: Vec<(usize, String)>,
}

impl<'ast> Visit<'ast> for RawImageSqlLiteralAudit {
    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        let normalized = literal
            .value()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase();
        self.literals
            .push((literal.span().start().line, normalized));
        visit::visit_lit_str(self, literal);
    }

    fn visit_macro(&mut self, item_macro: &'ast syn::Macro) {
        self.literals.push((
            item_macro.span().start().line,
            item_macro.tokens.to_string().to_ascii_uppercase(),
        ));
    }
}

impl RawImageSqlLiteralAudit {
    fn state_mutation_line(&self) -> Option<usize> {
        let combined = self
            .literals
            .iter()
            .map(|(_, literal)| literal.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let targets = [
            "IMAGE_GENERATION_JOBS",
            "IMAGE_GENERATION_SLOTS",
            "IMAGE_GENERATION_ATTEMPTS",
            "IMAGE_GENERATION_ARTIFACTS",
            "IMAGE_GENERATION_ARTIFACT_COMPONENTS",
        ];
        let is_state_update = targets.iter().any(|table| {
            let marker = format!("UPDATE {table}");
            combined.split(&marker).skip(1).any(|tail| {
                tail.split_once(" SET ").is_some_and(|(_, after_set)| {
                    let assignments = after_set.split(" WHERE ").next().unwrap_or(after_set);
                    assignments.contains("STATE=") || assignments.contains("STATE =")
                })
            })
        });
        is_state_update.then(|| {
            self.literals
                .iter()
                .find(|(_, literal)| literal.contains("UPDATE IMAGE_GENERATION_"))
                .map_or(0, |(line, _)| *line)
        })
    }
}

fn raw_sql_literal_boundary_error(
    name: &str,
    block: &syn::Block,
    trust_executor: bool,
) -> Option<String> {
    let mut audit = RawImageSqlLiteralAudit::default();
    audit.visit_block(block);
    let line = audit.state_mutation_line()?;
    if !(trust_executor && IMAGE_STATE_EXECUTORS.contains(&name)) {
        return Some(format!(
            "{name} contains image state-table UPDATE SQL at line {line} outside an executor"
        ));
    }
    let mut direct = TransitionAstAudit::default();
    direct.visit_block(block);
    direct.mutations.is_empty().then(|| {
        format!(
            "{name} hides image state-table UPDATE SQL at line {line} behind an indirect executor"
        )
    })
}

fn transition_source_errors_with_trust(source: &str, trust_executor: bool) -> Vec<String> {
    fn meta_requires_test(meta: &syn::Meta) -> bool {
        match meta {
            syn::Meta::Path(path) => path.is_ident("test"),
            syn::Meta::List(list) if list.path.is_ident("all") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .map(|preds| preds.iter().any(meta_requires_test))
                .unwrap_or(false),
            syn::Meta::List(list) if list.path.is_ident("any") => list
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                )
                .map(|preds| !preds.is_empty() && preds.iter().all(meta_requires_test))
                .unwrap_or(false),
            _ => false,
        }
    }
    fn is_test_only(attrs: &[syn::Attribute]) -> bool {
        attrs.iter().any(|attr| {
            attr.path().is_ident("cfg")
                && matches!(&attr.meta, syn::Meta::List(list) if meta_requires_test(
                    &syn::parse2::<syn::Meta>(list.tokens.clone()).unwrap_or(syn::parse_quote!(never_test_only))
                ))
        })
    }
    let mut errors = Vec::new();
    fn audit_block(name: &str, block: &syn::Block, trust_executor: bool, errors: &mut Vec<String>) {
        if let Some(error) = raw_transition_boundary_error(name, block, trust_executor) {
            errors.push(error);
        }
        if let Some(error) = raw_sql_literal_boundary_error(name, block, trust_executor) {
            errors.push(error);
        }
        if let Err(error) = audit_transition_block(block) {
            errors.push(format!("{name}: {error}"));
        }
    }
    fn audit_items(items: Vec<syn::Item>, trust_executor: bool, errors: &mut Vec<String>) {
        for item in items {
            match item {
                syn::Item::Fn(function) if !is_test_only(&function.attrs) => {
                    audit_block(
                        &function.sig.ident.to_string(),
                        &function.block,
                        trust_executor,
                        errors,
                    );
                }
                syn::Item::Impl(item_impl) if !is_test_only(&item_impl.attrs) => {
                    for item in item_impl.items {
                        if let syn::ImplItem::Fn(function) = item
                            && !is_test_only(&function.attrs)
                        {
                            audit_block(
                                &function.sig.ident.to_string(),
                                &function.block,
                                trust_executor,
                                errors,
                            );
                        }
                    }
                }
                syn::Item::Trait(item_trait) if !is_test_only(&item_trait.attrs) => {
                    for item in item_trait.items {
                        if let syn::TraitItem::Fn(function) = item
                            && !is_test_only(&function.attrs)
                            && let Some(block) = function.default
                        {
                            audit_block(
                                &function.sig.ident.to_string(),
                                &block,
                                trust_executor,
                                errors,
                            );
                        }
                    }
                }
                syn::Item::Mod(module) if !is_test_only(&module.attrs) => {
                    if let Some((_, items)) = module.content {
                        audit_items(items, trust_executor, errors);
                    }
                }
                syn::Item::Const(item_const) if !is_test_only(&item_const.attrs) => {
                    let mut audit = RawImageSqlLiteralAudit::default();
                    audit.visit_expr(&item_const.expr);
                    if let Some(line) = audit.state_mutation_line() {
                        errors.push(format!(
                            "const {} contains image state-table UPDATE SQL at line {line}",
                            item_const.ident
                        ));
                    }
                }
                syn::Item::Static(item_static) if !is_test_only(&item_static.attrs) => {
                    let mut audit = RawImageSqlLiteralAudit::default();
                    audit.visit_expr(&item_static.expr);
                    if let Some(line) = audit.state_mutation_line() {
                        errors.push(format!(
                            "static {} contains image state-table UPDATE SQL at line {line}",
                            item_static.ident
                        ));
                    }
                }
                syn::Item::Macro(item_macro) if !is_test_only(&item_macro.attrs) => {
                    let tokens = item_macro.mac.tokens.to_string().to_ascii_uppercase();
                    if (tokens.contains("UPDATE IMAGE_GENERATION_")
                        || (tokens.contains("UPDATE") && tokens.contains("IMAGE_GENERATION_")))
                        && (tokens.contains("SET STATE") || tokens.contains("STATE ="))
                    {
                        errors.push(
                            "production macro contains image state-table UPDATE SQL".to_owned(),
                        );
                    }
                }
                _ => {}
            }
        }
    }
    let file = syn::parse_file(source).expect("image-generation source parses");
    audit_items(file.items, trust_executor, &mut errors);
    errors
}

fn transition_source_errors(source: &str) -> Vec<String> {
    transition_source_errors_with_trust(source, true)
}

fn assert_production_image_mutations_use_ast(source: &str) {
    let errors = transition_source_errors(source);
    assert!(
        errors.is_empty(),
        "image transition AST audit failed: {errors:#?}"
    );
}

fn collect_production_rust_sources(directory: &Path, sources: &mut Vec<PathBuf>) {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot read {}: {error}", directory.display()));
    for entry in entries {
        let path = entry.expect("production source entry is readable").path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| {
                matches!(
                    name.to_str(),
                    Some("target" | "tests" | "benches" | "examples")
                )
            }) {
                continue;
            }
            collect_production_rust_sources(&path, sources);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            sources.push(path);
        }
    }
}

fn assert_repo_wide_image_state_write_boundary(image_source_path: &Path) {
    let repository = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cockpit-db is nested under the repository crates directory")
        .to_path_buf();
    let mut sources = Vec::new();
    collect_production_rust_sources(&repository.join("apps"), &mut sources);
    collect_production_rust_sources(&repository.join("crates"), &mut sources);
    let canonical_owner = image_source_path
        .canonicalize()
        .expect("image-generation owner path canonicalizes");
    let mut failures = Vec::new();
    for path in sources {
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
        let trusted = path
            .canonicalize()
            .is_ok_and(|candidate| candidate == canonical_owner);
        for error in transition_source_errors_with_trust(&source, trusted) {
            failures.push(format!("{}: {error}", path.display()));
        }
    }
    assert!(
        failures.is_empty(),
        "repo-wide image state-write boundary failed: {failures:#?}"
    );
}

fn assert_image_executor_visibility_and_fixed_api(source: &str) {
    for generic in [
        "transition_image_generation_artifact_conn",
        "transition_image_generation_artifact_component_conn",
    ] {
        assert!(
            source.contains(&format!("    fn {generic}("))
                && !source.contains(&format!("pub fn {generic}(")),
            "generic image transition executor {generic} must remain private"
        );
    }
    for semantic in [
        "begin_image_generation_artifact_write_conn",
        "begin_image_generation_artifact_component_write_conn",
        "commit_image_generation_artifact_component_ready_conn",
        "commit_image_generation_artifact_retained_conn",
        "commit_image_generation_artifact_late_quarantined_conn",
        "commit_image_generation_security_cleanup_conn",
        "commit_image_generation_security_publication_conn",
    ] {
        let body = source
            .split(&format!("pub fn {semantic}"))
            .nth(1)
            .and_then(|tail| tail.split("\n    }").next())
            .unwrap_or_else(|| panic!("semantic image operation {semantic} is absent"));
        assert!(
            !body.contains("input.from") && !body.contains("input.to"),
            "semantic image operation {semantic} exposes an arbitrary edge"
        );
    }
}

#[test]
fn image_transition_ast_audit_rejects_decoys_and_unvalidated_occurrences() {
    let decoy = r#"
        fn bad(conn: &Connection) {
            ensure!(job_transition_allowed(ImageGenerationJobState::Created, ImageGenerationJobState::Validating));
            conn.execute("UPDATE image_generation_jobs SET state='dispatching' WHERE state='queued'", []);
        }
    "#;
    assert!(!transition_source_errors(decoy).is_empty());

    let missing_second = r#"
        fn bad(conn: &Connection) {
            ensure!(slot_transition_allowed(ImageGenerationSlotState::Planned, ImageGenerationSlotState::Queued));
            conn.execute("UPDATE image_generation_slots SET state='queued' WHERE state='planned'", []);
            conn.execute("UPDATE image_generation_slots SET state='dispatching' WHERE state='queued'", []);
        }
    "#;
    assert!(!transition_source_errors(missing_second).is_empty());

    let async_restricted_visibility = r#"
        async fn execute_basic_image_attempt_transition_conn(conn: &Connection) {
            ensure!(attempt_transition_allowed(ImageGenerationAttemptState::Planned, ImageGenerationAttemptState::Preparing));
            ensure!(conn.execute("UPDATE image_generation_attempts SET state='preparing',version=2 WHERE state='planned' AND version=1", []) == 1);
        }
    "#;
    assert!(transition_source_errors(async_restricted_visibility).is_empty());

    let nested = r#"
        mod hidden { fn mutate(conn: &Connection) {
            let sql = "UPDATE image_generation_slots SET state='queued' WHERE state='planned'";
            conn.prepare(sql).unwrap();
        }}
    "#;
    assert!(!transition_source_errors(nested).is_empty());

    let trait_default = r#"
        trait Hidden { fn mutate(conn: &Connection) {
            conn.execute("UPDATE image_generation_attempts SET state='accepted' WHERE state='dispatching'", []);
        }}
    "#;
    assert!(!transition_source_errors(trait_default).is_empty());

    let constant_wrapper = r#"
        const SQL: &str = "UPDATE image_generation_jobs SET state='failed' WHERE state='running'";
        fn wrapper(conn: &Connection) { conn.prepare(SQL).unwrap(); }
    "#;
    assert!(!transition_source_errors(constant_wrapper).is_empty());

    let macro_sql = r#"
        macro_rules! hidden { () => { "UPDATE image_generation_artifacts SET state='ready'" } }
    "#;
    assert!(!transition_source_errors(macro_sql).is_empty());

    let dynamic = r#"
        fn wrapper(conn: &Connection) {
            let prefix = "UPDATE image_generation_slots";
            let sql = format!("{prefix} SET state='queued'");
            conn.execute(&sql, []);
        }
    "#;
    assert!(!transition_source_errors(dynamic).is_empty());

    let disguised_executor = r#"
        fn execute_basic_image_slot_transition_conn(conn: &Connection) {
            let prefix = "UPDATE image_generation_slots";
            conn.prepare(&format!("{prefix} SET state='queued'")).unwrap();
        }
    "#;
    assert!(!transition_source_errors(disguised_executor).is_empty());

    let invocation_macro = r#"
        fn wrapper(conn: &Connection) {
            conn.execute(sql!("UPDATE image_generation_attempts SET state='accepted'"), []);
        }
    "#;
    assert!(!transition_source_errors(invocation_macro).is_empty());

    let missing_version_fence = r#"
        fn execute_basic_image_slot_transition_conn(conn: &Connection) {
            ensure!(slot_transition_allowed(ImageGenerationSlotState::Planned, ImageGenerationSlotState::Queued));
            ensure!(conn.execute("UPDATE image_generation_slots SET state='queued' WHERE state='planned'", []) == 1);
        }
    "#;
    assert!(!transition_source_errors(missing_version_fence).is_empty());

    let missing_row_count = r#"
        fn execute_basic_image_slot_transition_conn(conn: &Connection) {
            ensure!(slot_transition_allowed(ImageGenerationSlotState::Planned, ImageGenerationSlotState::Queued));
            conn.execute("UPDATE image_generation_slots SET state='queued',version=2 WHERE state='planned' AND version=1", []);
        }
    "#;
    assert!(!transition_source_errors(missing_row_count).is_empty());

    let copied_executor_outside_owner = r#"
        fn execute_basic_image_slot_transition_conn(conn: &Connection) {
            ensure!(slot_transition_allowed(ImageGenerationSlotState::Planned, ImageGenerationSlotState::Queued));
            ensure!(conn.execute("UPDATE image_generation_slots SET state='queued',version=2 WHERE state='planned' AND version=1", []) == 1);
        }
    "#;
    assert!(!transition_source_errors_with_trust(copied_executor_outside_owner, false).is_empty());
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

fn sql_state_check(declaration: &str) -> String {
    let collapsed = declaration.split_whitespace().collect::<Vec<_>>().join(" ");
    [
        "CHECK (state IN (",
        "CHECK(state IN (",
        "CHECK (state IN(",
        "CHECK(state IN(",
    ]
    .into_iter()
    .find_map(|marker| collapsed.split(marker).nth(1))
    .and_then(|tail| tail.split("))").next())
    .or_else(|| {
        [
            "CHECK (phase IN (",
            "CHECK(phase IN (",
            "CHECK (phase IN(",
            "CHECK(phase IN(",
        ]
        .into_iter()
        .find_map(|marker| collapsed.split(marker).nth(1))
        .and_then(|tail| tail.split("))").next())
    })
    .map(str::to_owned)
    .unwrap_or_else(|| panic!("table has no closed SQL state/phase CHECK: {declaration}"))
}

fn sql_only_edges(name: &str, trigger: &str) -> BTreeSet<String> {
    match name {
        "agent_host_approval_effect_handoff" => BTreeSet::from([
            "ready>dispatching".to_owned(),
            "ready>rejected".to_owned(),
            "dispatching>succeeded".to_owned(),
            "dispatching>rejected".to_owned(),
            "dispatching>submission_unknown".to_owned(),
        ]),
        "agent_host_approval_operation" => BTreeSet::from([
            "pending>approved".to_owned(),
            "pending>cancelled".to_owned(),
            "approved>dispatching".to_owned(),
            "approved>rejected".to_owned(),
            "approved>cancelled".to_owned(),
            "dispatching>completed".to_owned(),
            "dispatching>rejected".to_owned(),
            "dispatching>submission_unknown".to_owned(),
        ]),
        "host_capability_refresh_initialization" => BTreeSet::from([
            "initializing>bound".to_owned(),
            "initializing>cancelled".to_owned(),
        ]),
        "host_capability_refresh_operation" => BTreeSet::from([
            "pending>allowed".to_owned(),
            "pending>cancelled".to_owned(),
            "pending>failed".to_owned(),
            "allowed>executing".to_owned(),
            "allowed>cancelled".to_owned(),
            "allowed>failed".to_owned(),
            "executing>completed".to_owned(),
            "executing>failed".to_owned(),
            "executing>cancelled".to_owned(),
        ]),
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
    let image_source_path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/db/image_generation.rs");
    let image_source = include_str!("../src/db/image_generation.rs");
    assert_production_image_mutations_use_ast(image_source);
    assert_repo_wide_image_state_write_boundary(&image_source_path);
    assert_image_executor_visibility_and_fixed_api(image_source);
    let reconciliation = image_source
        .split("fn reconcile_image_generation_attempt_inner")
        .nth(1)
        .and_then(|tail| {
            tail.split("\n    fn create_image_generation_job_conn")
                .next()
        })
        .expect("reconciliation reducer source is present");
    for evidence in [
        "SELECT a.state,s.state,s.version,j.state,j.version,a.applied_cancellation_version",
        "attempt_transition_allowed(attempt_state, attempt_next)",
        "slot_transition_allowed(slot_state, slot_next)",
        "job_transition_allowed(job_state, ImageGenerationJobState::Running)",
        ".contains(&(job_state.as_str(), ImageGenerationJobState::Queued.as_str()))",
        ".contains(&(slot_state.as_str(), slot_next.as_str()))",
        "execute_reconciliation_state_transitions_conn",
        "execute_image_job_transition_conn",
        "slot_state == ImageGenerationSlotState::CancellationRequested",
        "slot_version == i64::try_from(input.slot_version)?",
        "job_state == input.job_state",
        "job_version == i64::try_from(input.job_version)?",
    ] {
        assert!(
            reconciliation.contains(evidence),
            "reconciliation exact transition evidence is absent: {evidence}"
        );
    }
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
        let declaration = table_declaration(&sql, table);
        if family.get("state_columns").is_none() {
            let sql_states = quoted_literals(&sql_state_check(declaration))
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
                if let Some((from, to)) = literal.split_once('>')
                    && !from.is_empty()
                    && !to.is_empty()
                {
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
        let rust_states = rust_string_literals(rust_constant(
            &rust,
            required_text(name, family, "states_symbol"),
        ))
        .into_iter()
        .collect::<BTreeSet<_>>();
        let rust_edge_values = rust_string_literals(rust_constant(
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
                let values = rust_string_literals(rust_constant(&rust, symbol));
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
        let rust_terminals = rust_string_literals(rust_constant(
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
        let declaration = table_declaration(&all_sql, table_name);
        let allowed = csv_set(required_text(name, family, "allowed_states"));
        if family.get("state_columns").is_none() {
            assert_eq!(
                allowed,
                quoted_literals(&sql_state_check(declaration))
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
        "agent_host_approval_effect_handoffs",
        "agent_host_approval_operations",
        "external_journal_operations",
        "host_capability_refresh_initializations",
        "host_capability_refresh_operations",
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
