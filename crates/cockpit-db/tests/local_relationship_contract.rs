use std::path::{Path, PathBuf};

#[path = "support/schema_parser.rs"]
mod schema_parser;

const SCHEMA: &str = include_str!("../src/db/migrations/0001_initial.sql");
const EXTENDED_SCHEMA: &str = include_str!("../src/db/migrations/0001_extended_profile.sql");
const RELATIONSHIP_INVENTORY: &str = include_str!("support/relationship_inventory.tsv");

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum RelationshipClass {
    Primary,
    LocalIdentity,
    Foreign,
    External,
    Polymorphic,
    Denormalized,
}

fn relationship_inventory(
) -> std::collections::BTreeMap<(String, String, String), RelationshipClass> {
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

fn reviewed_identifier(column: &str) -> bool {
    column == "id"
        || [
            "_id",
            "_ids",
            "_ids_json",
            "_key",
            "_uuid",
            "_token",
            "_handle",
            "_digest",
            "_identity",
            "_ref",
        ]
        .iter()
        .any(|suffix| column.ends_with(suffix))
        || matches!(column, "owner" | "namespace")
}

fn owned_identifier_columns(
    schema: &schema_parser::Schema,
    tables: impl Iterator<Item = String>,
) -> std::collections::BTreeSet<(String, String)> {
    tables
        .flat_map(|table_name| {
            let table = &schema.tables[&table_name];
            let mut columns = table
                .columns
                .iter()
                .filter(|column| reviewed_identifier(column))
                .cloned()
                .collect::<std::collections::BTreeSet<_>>();
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

fn validate_relationship_inventory(
    profile: &str,
    schema: &schema_parser::Schema,
    owned_tables: std::collections::BTreeSet<String>,
    effective_rows: &std::collections::BTreeMap<(String, String), RelationshipClass>,
) -> Result<(), String> {
    let expected = owned_identifier_columns(schema, owned_tables.clone().into_iter());
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
        let primary = table.primary_keys.iter().any(|key| key.contains(column));
        let unique = table.unique_keys.iter().any(|key| key.contains(column))
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

    let foreign_identity = inventory
        .iter()
        .find(|(_, class)| **class == RelationshipClass::Foreign)
        .map(|(identity, _)| identity.clone())
        .unwrap();
    let mut misclassified = inventory;
    misclassified.insert(foreign_identity, RelationshipClass::External);
    assert!(
        validate_relationship_inventory("adversarial", &local, tables, &misclassified)
            .unwrap_err()
            .contains("bidirectional")
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
