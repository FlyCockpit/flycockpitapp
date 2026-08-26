use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[path = "support/schema_parser.rs"]
mod schema_parser;

const SCHEMA: &str = include_str!("../src/db/migrations/0001_initial.sql");
const EXTENDED_SCHEMA: &str = include_str!("../src/db/migrations/0001_extended_profile.sql");
const RELATIONSHIP_INVENTORY: &str = include_str!("support/relationship_inventory.tsv");
const LOCAL_SCHEMA_REVIEW_DIGEST: &str =
    "5c15f7acb82576b40c178036da773a5963de471b79f3c899599048f902df4f64";
const EXTENDED_SCHEMA_REVIEW_DIGEST: &str =
    "e32fef009c919d44dd8de06788cc473394959a8835de3d4f40dc4bd4a62ed1e2";
const RELATIONSHIP_INVENTORY_REVIEW_DIGEST: &str =
    "7bfa5210915fa6c642baba54f6281786164efa8159c243d207be3d187826c88f";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RelationshipClass {
    Primary,
    LocalIdentity,
    Foreign,
    External,
    Polymorphic,
    Denormalized,
}

fn relationship_inventory()
-> std::collections::BTreeMap<(String, String, String), RelationshipClass> {
    let mut inventory = std::collections::BTreeMap::new();
    for line in RELATIONSHIP_INVENTORY
        .lines()
        .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
    {
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            4,
            "invalid relationship inventory row: {line}"
        );
        let class = match fields[3] {
            "primary" => RelationshipClass::Primary,
            "local_identity" => RelationshipClass::LocalIdentity,
            "foreign" => RelationshipClass::Foreign,
            "external" => RelationshipClass::External,
            "polymorphic" => RelationshipClass::Polymorphic,
            "denormalized" => RelationshipClass::Denormalized,
            value => panic!("unknown relationship class {value}: {line}"),
        };
        let prior = inventory.insert(
            (
                fields[0].to_owned(),
                fields[1].to_owned(),
                fields[2].to_owned(),
            ),
            class,
        );
        assert!(
            prior.is_none(),
            "duplicate relationship inventory row: {line}"
        );
    }
    inventory
}

fn structurally_owned_identifier_columns(
    schema: &schema_parser::Schema,
    tables: impl Iterator<Item = String>,
) -> std::collections::BTreeSet<(String, String)> {
    tables
        .flat_map(|table_name| {
            let table = &schema.tables[&table_name];
            let mut columns = table
                .primary_keys
                .iter()
                .chain(&table.unique_keys)
                .flat_map(|key| key.columns.iter().cloned())
                .collect::<std::collections::BTreeSet<_>>();
            columns.extend(
                schema
                    .indexes
                    .iter()
                    .filter(|index| index.table == table_name && index.unique && !index.partial)
                    .flat_map(|index| index.columns.iter().cloned()),
            );
            columns.extend(
                table
                    .foreign_keys
                    .iter()
                    .flat_map(|foreign_key| foreign_key.child_columns.iter().cloned()),
            );
            columns
                .into_iter()
                .map(move |column| (table_name.clone(), column))
        })
        .collect()
}

fn source(path: impl AsRef<Path>) -> String {
    std::fs::read_to_string(path).expect("read production query owner")
}

#[derive(Clone, Copy)]
struct SourceSpan {
    start_line: usize,
    start_column: usize,
    end_line: usize,
    end_column: usize,
}

fn literal_spans(source: &str) -> Vec<SourceSpan> {
    fn record_macro_literals(tokens: proc_macro2::TokenStream, output: &mut Vec<SourceSpan>) {
        for token in tokens {
            match token {
                proc_macro2::TokenTree::Group(group) => {
                    record_macro_literals(group.stream(), output);
                }
                proc_macro2::TokenTree::Literal(literal) => {
                    let start = literal.span().start();
                    let end = literal.span().end();
                    output.push(SourceSpan {
                        start_line: start.line,
                        start_column: start.column,
                        end_line: end.line,
                        end_column: end.column,
                    });
                }
                _ => {}
            }
        }
    }

    struct Literals(Vec<SourceSpan>);
    impl<'ast> syn::visit::Visit<'ast> for Literals {
        fn visit_lit(&mut self, literal: &'ast syn::Lit) {
            let start = syn::spanned::Spanned::span(literal).start();
            let end = syn::spanned::Spanned::span(literal).end();
            self.0.push(SourceSpan {
                start_line: start.line,
                start_column: start.column,
                end_line: end.line,
                end_column: end.column,
            });
        }

        fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
            record_macro_literals(invocation.tokens.clone(), &mut self.0);
        }
    }
    let mut literals = Literals(Vec::new());
    syn::visit::Visit::visit_file(&mut literals, &syn::parse_file(source).unwrap());
    literals.0
}

fn span_contains(span: SourceSpan, line: usize, column: usize) -> bool {
    (line > span.start_line || line == span.start_line && column >= span.start_column)
        && (line < span.end_line || line == span.end_line && column < span.end_column)
}

fn hot_query_comments(source: &str) -> Vec<(usize, String)> {
    let literal_spans = literal_spans(source);
    let mut markers = Vec::new();
    let mut block_comment_depth = 0_u32;
    for (line_offset, line) in source.lines().enumerate() {
        let line_number = line_offset + 1;
        let bytes = line.as_bytes();
        let mut column = 0;
        while column + 1 < bytes.len() {
            if literal_spans
                .iter()
                .any(|span| span_contains(*span, line_number, column))
            {
                column += 1;
                continue;
            }
            match (bytes[column], bytes[column + 1], block_comment_depth) {
                (b'/', b'*', _) => {
                    block_comment_depth = block_comment_depth
                        .checked_add(1)
                        .expect("Rust block-comment nesting overflow");
                    column += 2;
                }
                (b'*', b'/', depth) if depth > 0 => {
                    block_comment_depth -= 1;
                    column += 2;
                }
                (b'/', b'/', 0) => {
                    if let Some(marker) =
                        line[column + 2..].trim().strip_prefix("schema-hot-query:")
                    {
                        assert!(
                            line[..column].trim().is_empty(),
                            "hot-query marker must be a standalone line comment"
                        );
                        let marker = marker.trim();
                        assert!(!marker.is_empty(), "hot-query marker cannot be empty");
                        markers.push((line_number, marker.to_owned()));
                    }
                    break;
                }
                _ => column += 1,
            }
        }
    }
    assert_eq!(
        block_comment_depth, 0,
        "unterminated Rust block comment in query owner"
    );
    markers
}

fn annotated_sql_literal(source: &str, marker: &str) -> String {
    struct Literals(Vec<(usize, String)>);
    impl<'ast> syn::visit::Visit<'ast> for Literals {
        fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
            self.0.push((literal.span().start().line, literal.value()));
        }
    }
    let marker_lines = hot_query_comments(source)
        .into_iter()
        .filter(|(_, candidate)| candidate == marker)
        .map(|(line, _)| line)
        .collect::<Vec<_>>();
    assert_eq!(
        marker_lines.len(),
        1,
        "marker must occur exactly once: {marker}"
    );
    let mut literals = Literals(Vec::new());
    syn::visit::Visit::visit_file(&mut literals, &syn::parse_file(source).unwrap());
    let bound = literals
        .0
        .into_iter()
        .filter(|(line, _)| *line == marker_lines[0] + 1)
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    assert_eq!(
        bound.len(),
        1,
        "hot-query marker must immediately precede exactly one Rust SQL literal: {marker}"
    );
    bound.into_iter().next().unwrap()
}

fn normalized_sql(sql: &str) -> String {
    sql.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[test]
fn hot_query_binding_rejects_duplicate_and_ignores_unrelated_literals() {
    let stale = r#"
        fn owner() {
            let unrelated = "SELECT stale FROM elsewhere";
            // schema-hot-query: reviewed.shape
            let query = "SELECT exact FROM owned WHERE id=?1";
        }
    "#;
    assert_eq!(
        annotated_sql_literal(stale, "reviewed.shape"),
        "SELECT exact FROM owned WHERE id=?1"
    );
    let duplicate = r#"
        fn owner() {
            // schema-hot-query: reviewed.shape
            let one = "SELECT 1";
            // schema-hot-query: reviewed.shape
            let two = "SELECT 2";
        }
    "#;
    assert!(
        std::panic::catch_unwind(|| annotated_sql_literal(duplicate, "reviewed.shape")).is_err()
    );
    let spoofed = r###"
        fn owner() {
            let raw = r#"
                // schema-hot-query: reviewed.shape
            "#;
            /*
                // schema-hot-query: reviewed.shape
            */
            println!(r#"
                // schema-hot-query: reviewed.shape
            "#);
            // schema-hot-query: reviewed.shape
            "SELECT exact FROM owned WHERE id=?1";
        }
    "###;
    assert_eq!(
        hot_query_comments(spoofed),
        vec![(12, "reviewed.shape".to_owned())]
    );
    assert_eq!(
        annotated_sql_literal(spoofed, "reviewed.shape"),
        "SELECT exact FROM owned WHERE id=?1"
    );
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

fn production_rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut output = Vec::new();
    for family in ["apps", "crates"] {
        let family_root = root.join(family);
        for entry in std::fs::read_dir(&family_root).expect("read Rust workspace family") {
            let entry = entry.expect("read Rust workspace member");
            if !entry.path().is_dir() {
                continue;
            }
            let relative_src = Path::new(family).join(entry.file_name()).join("src");
            if root.join(&relative_src).is_dir() {
                rust_sources_below(root, &relative_src, &mut output);
            }
        }
    }
    output.sort();
    output
}

fn portable_relative_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn effective_profiles() -> [(&'static str, schema_parser::Schema); 2] {
    [
        ("local", schema_parser::parse(&[SCHEMA])),
        ("extended", schema_parser::parse(&[SCHEMA, EXTENDED_SCHEMA])),
    ]
}

fn schema_digest(schema: &str) -> String {
    format!("{:x}", Sha256::digest(schema.as_bytes()))
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
                        Some("cascade" | "restrict" | "set null" | "set default" | "no action")
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

    assert!(
        std::panic::catch_unwind(|| schema_parser::parse(&[EXTENDED_SCHEMA])).is_err(),
        "the extended layer unexpectedly became a standalone or first-applied schema"
    );
}

fn validate_relationship_inventory(
    profile: &str,
    schema: &schema_parser::Schema,
    owned_tables: std::collections::BTreeSet<String>,
    effective_rows: &std::collections::BTreeMap<(String, String), RelationshipClass>,
) -> Result<(), String> {
    let mut expected =
        structurally_owned_identifier_columns(schema, owned_tables.clone().into_iter());
    expected.extend(effective_rows.keys().cloned());
    let actual = effective_rows
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    if actual != expected {
        return Err(format!(
            "{profile} relationship inventory differs: missing={:?}, stale={:?}",
            expected.difference(&actual).collect::<Vec<_>>(),
            actual.difference(&expected).collect::<Vec<_>>()
        ));
    }
    for (table, column) in &actual {
        if !owned_tables.contains(table) || !schema.tables[table].columns.contains(column) {
            return Err(format!(
                "{profile} inventory names absent column {table}.{column}"
            ));
        }
    }

    let foreign = owned_tables
        .iter()
        .flat_map(|table_name| {
            schema.tables[table_name]
                .foreign_keys
                .iter()
                .flat_map(|foreign_key| {
                    foreign_key
                        .child_columns
                        .iter()
                        .map(|column| (table_name.clone(), column.clone()))
                })
        })
        .collect::<std::collections::BTreeSet<_>>();
    let classified_foreign = effective_rows
        .iter()
        .filter(|(_, class)| **class == RelationshipClass::Foreign)
        .map(|(identity, _)| identity.clone())
        .collect::<std::collections::BTreeSet<_>>();
    if classified_foreign != foreign {
        return Err(format!(
            "{profile} Foreign classification is not bidirectional: classified={classified_foreign:?}, parsed={foreign:?}"
        ));
    }

    for ((table_name, column), class) in effective_rows {
        let table = &schema.tables[table_name];
        let primary = table
            .primary_keys
            .iter()
            .any(|key| key.columns.contains(column));
        let unique = table
            .unique_keys
            .iter()
            .any(|key| key.columns.contains(column))
            || schema.indexes.iter().any(|index| {
                index.table == *table_name
                    && index.unique
                    && !index.partial
                    && index.columns.contains(column)
            });
        match class {
            RelationshipClass::Primary if !primary => {
                return Err(format!("{profile}.{table_name}.{column} is not PK-owned"));
            }
            RelationshipClass::LocalIdentity if primary || !unique => {
                return Err(format!(
                    "{profile}.{table_name}.{column} is not solely nonpartial-UNIQUE-owned"
                ));
            }
            RelationshipClass::Foreign
                if !foreign.contains(&(table_name.clone(), column.clone())) =>
            {
                return Err(format!(
                    "{profile}.{table_name}.{column} is not an FK child"
                ));
            }
            _ => {}
        }
        if primary
            && !foreign.contains(&(table_name.clone(), column.clone()))
            && *class != RelationshipClass::Primary
        {
            return Err(format!(
                "{profile}.{table_name}.{column} hides primary identity as {class:?}"
            ));
        }
        if unique
            && !primary
            && !foreign.contains(&(table_name.clone(), column.clone()))
            && *class != RelationshipClass::LocalIdentity
        {
            return Err(format!(
                "{profile}.{table_name}.{column} hides local unique identity as {class:?}"
            ));
        }
    }
    Ok(())
}

#[test]
fn identifier_relationship_map_is_exhaustive_and_schema_owned() {
    assert_eq!(schema_digest(SCHEMA), LOCAL_SCHEMA_REVIEW_DIGEST);
    assert_eq!(
        schema_digest(EXTENDED_SCHEMA),
        EXTENDED_SCHEMA_REVIEW_DIGEST
    );
    assert_eq!(
        schema_digest(RELATIONSHIP_INVENTORY),
        RELATIONSHIP_INVENTORY_REVIEW_DIGEST
    );
    let [(_, local), (_, extended)] = effective_profiles();
    let inventory = relationship_inventory();
    let local_tables = local
        .tables
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let extended_tables = extended
        .tables
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let deferred_tables = extended_tables
        .difference(&local_tables)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();

    let manifest_local = inventory
        .iter()
        .filter(|((owner, _, _), _)| owner == "local")
        .map(|((_, table, column), class)| ((table.clone(), column.clone()), *class))
        .collect::<std::collections::BTreeMap<_, _>>();
    let manifest_deferred = inventory
        .iter()
        .filter(|((owner, _, _), _)| owner == "extended")
        .map(|((_, table, column), class)| ((table.clone(), column.clone()), *class))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut manifest_effective_extended = manifest_local.clone();
    assert!(
        manifest_deferred
            .keys()
            .all(|key| manifest_effective_extended
                .insert(key.clone(), manifest_deferred[key])
                .is_none()),
        "extended identifier ownership must be an additive table layer"
    );

    validate_relationship_inventory("local", &local, local_tables.clone(), &manifest_local)
        .expect("local identifier inventory must be exact");
    validate_relationship_inventory(
        "extended-owned",
        &extended,
        deferred_tables,
        &manifest_deferred,
    )
    .expect("extended identifier inventory must be exact");
    validate_relationship_inventory(
        "extended-effective",
        &extended,
        extended_tables,
        &manifest_effective_extended,
    )
    .expect("effective extended identifier inventory must be exact");
}

#[test]
fn identifier_inventory_rejects_unannotated_and_misclassified_schema_changes() {
    let [(_, mut local), _] = effective_profiles();
    let tables = local
        .tables
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let inventory = relationship_inventory()
        .into_iter()
        .filter(|((owner, _, _), _)| owner == "local")
        .map(|((_, table, column), class)| ((table, column), class))
        .collect::<std::collections::BTreeMap<_, _>>();

    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .columns
        .insert("unreviewed_authority_ref".to_owned());
    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .unique_keys
        .push(schema_parser::Key {
            columns: vec!["unreviewed_authority_ref".to_owned()],
            collations: vec![None],
        });
    assert!(
        validate_relationship_inventory("adversarial", &local, tables.clone(), &inventory)
            .unwrap_err()
            .contains("missing")
    );
    local
        .tables
        .get_mut("sessions")
        .unwrap()
        .columns
        .remove("unreviewed_authority_ref");
    local.tables.get_mut("sessions").unwrap().unique_keys.pop();

    let foreign_identity = inventory
        .iter()
        .find(|(_, class)| **class == RelationshipClass::Foreign)
        .map(|(identity, _)| identity.clone())
        .unwrap();
    let mut missing = inventory.clone();
    missing.remove(&foreign_identity);
    assert!(
        validate_relationship_inventory("adversarial", &local, tables.clone(), &missing)
            .unwrap_err()
            .contains("missing")
    );

    for (from, to, expected_error) in [
        (
            RelationshipClass::Foreign,
            RelationshipClass::External,
            "bidirectional",
        ),
        (
            RelationshipClass::Primary,
            RelationshipClass::External,
            "hides primary",
        ),
        (
            RelationshipClass::LocalIdentity,
            RelationshipClass::External,
            "hides local unique",
        ),
        (
            RelationshipClass::External,
            RelationshipClass::Primary,
            "is not PK-owned",
        ),
    ] {
        let identity = inventory
            .iter()
            .find(|(_, class)| **class == from)
            .map(|(identity, _)| identity.clone())
            .unwrap();
        let mut misclassified = inventory.clone();
        misclassified.insert(identity, to);
        assert!(
            validate_relationship_inventory("adversarial", &local, tables.clone(), &misclassified)
                .unwrap_err()
                .contains(expected_error),
            "{from:?} -> {to:?} did not fail with {expected_error}"
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

    let inventory = relationship_inventory();
    for (table, column, expected) in [
        ("sessions", "provider", RelationshipClass::Denormalized),
        ("sessions", "model", RelationshipClass::Denormalized),
        (
            "sessions",
            "assistant_name",
            RelationshipClass::Denormalized,
        ),
        (
            "tool_call_events",
            "provider_call_id",
            RelationshipClass::External,
        ),
        (
            "write_scope_leases",
            "owner_id",
            RelationshipClass::Polymorphic,
        ),
    ] {
        assert_eq!(
            inventory.get(&("local".to_owned(), table.to_owned(), column.to_owned())),
            Some(&expected),
            "soft relationship policy drifted for {table}.{column}"
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
            "e676358dd6092ff77aa5915f430806d623c0987afd982014542b4e9cb4ea55c9",
            false,
            "sessions",
            "idx_sessions_open",
            &["ephemeral", "last_active_at_unix_ms"][..],
            true,
        ),
        (
            "local.agent-preparation.terminalize",
            "crates/cockpit-db/src/db/agent_installations.rs",
            "WHERE session_id=?1 AND claim_state IN ('claimed', 'running')",
            "529c9bf816b241c309b49f2e54c8ae0f398e87c117103eb4063d98eceb0d129a",
            false,
            "agent_session_preparation_claims",
            "idx_agent_session_preparation_claims_recovery",
            &["claim_state", "session_id"],
            false,
        ),
        (
            "extended.scheduler.by-owner",
            "crates/cockpit-db/src/db/scheduler.rs",
            "WHERE owner = ?1",
            "4c04bc561abef009306ec51c13858d2a4c801c130781eeda44a1cff97abfacd1",
            true,
            "scheduled_jobs",
            "idx_scheduled_jobs_owner",
            &["owner"],
            false,
        ),
        (
            "extended.image-generation.dispatch-scan",
            "crates/cockpit-db/src/db/image_generation.rs",
            "WHERE j.state='queued' AND s.state='queued' AND a.state='planned'",
            "5235dd10724aef22eb5daf2e4e543db47aac88d0f0b5d7a4eb603522684df7bf",
            true,
            "image_generation_jobs",
            "idx_image_generation_jobs_dispatch_scan",
            &["state", "created_at_unix_ms", "job_id"],
            false,
        ),
    ];
    let expected_markers = shapes
        .iter()
        .map(|(marker, owner, ..)| (marker.to_string(), owner.to_string()))
        .collect::<std::collections::BTreeSet<_>>();
    let actual_marker_rows = production_rust_sources(&root)
        .into_iter()
        .flat_map(|owner| {
            let contents = source(root.join(&owner));
            hot_query_comments(&contents)
                .into_iter()
                .map(|(_, marker)| (marker, portable_relative_path(&owner)))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let actual_markers = actual_marker_rows
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        actual_marker_rows.len(),
        actual_markers.len(),
        "duplicate hot-query annotation"
    );
    assert_eq!(
        actual_markers, expected_markers,
        "hot-query annotations drifted"
    );

    let [(_, local), (_, extended)] = effective_profiles();
    for (marker, owner, query, query_digest, uses_extended, table, index_name, columns, partial) in
        shapes
    {
        let owner_source = source(root.join(owner));
        let bound_query = normalized_sql(&annotated_sql_literal(&owner_source, marker));
        assert!(
            bound_query.contains(&normalized_sql(query)),
            "bound query shape drifted for {marker}: {bound_query}"
        );
        assert_eq!(
            schema_digest(&bound_query),
            query_digest,
            "full bound query drifted for {marker}"
        );
        let schema = if uses_extended { &extended } else { &local };
        assert!(
            schema.indexes.iter().any(|index| index.name == index_name
                && index.table == table
                && index.columns.len() >= columns.len()
                && index
                    .columns
                    .iter()
                    .zip(columns)
                    .all(|(actual, expected)| actual == *expected)
                && index.partial == partial),
            "reviewed leading index missing for {marker}: {index_name} on {table}{columns:?} partial={partial}"
        );
    }
}
