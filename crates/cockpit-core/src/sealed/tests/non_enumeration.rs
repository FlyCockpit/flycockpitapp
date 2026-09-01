//! AC1 `persistent_sealed_values_are_not_enumerable_outside_agent_scope`
//! AC7 `sealed_storage_compartment_is_non_enumerable`

use super::*;
use crate::sealed::identity::SealedRecordId;

/// Method names that would constitute an enumeration, count, prefix,
/// existence, status, debug, doctor, or export oracle.
const ORACLE_NAME_FRAGMENTS: &[&str] = &[
    "list", "keys", "names", "iter", "count", "len", "contains", "exists", "any", "all", "prefix",
    "search", "scan", "find", "status", "doctor", "export", "dump", "debug_",
];

/// Extract the identifier of every `pub fn` / `pub async fn` in a source file.
/// `pub(crate)`, `pub(super)`, and `pub(in ...)` are deliberately excluded:
/// those are not reachable from outside the crate, which is the boundary that
/// matters for an agent-reachable oracle.
fn public_fn_names(source: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("pub fn ").or_else(|| {
            trimmed
                .strip_prefix("pub async fn ")
                .or_else(|| trimmed.strip_prefix("pub const fn "))
        }) else {
            continue;
        };
        let name: String = rest
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() {
            names.push(name);
        }
    }
    names
}

#[tokio::test]
async fn persistent_sealed_values_are_not_enumerable_outside_agent_scope() {
    let fixture = SealedFixture::new().await;
    let directory = fixture.directory();
    let owner = SealedFixture::owner();

    let project = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;
    let global = fixture
        .seed_value(SealedScopeRef::Global, "org_token")
        .await;

    // ---- storage is opaque exact-key --------------------------------------
    // The record row holds a locator, and the locator is what the vault item
    // is keyed by. Neither the name nor anything derived from the literal
    // appears as a listable surface. After unification there is no
    // sealed-compartment.json leftover, and listing sealed_compartment item
    // ids is refused.
    let row = fixture
        .db
        .sealed_value_record(project.record_id.to_string())
        .await
        .expect("record read")
        .expect("record exists");
    let locator = row
        .compartment_key
        .clone()
        .expect("project record has a locator");
    assert_eq!(locator.len(), 64, "locator is a 32-byte opaque exact key");
    assert!(locator.chars().all(|c| c.is_ascii_hexdigit()));

    if fixture.compartment.path().exists() {
        let on_disk =
            std::fs::read_to_string(fixture.compartment.path()).expect("legacy compartment file");
        assert!(
            !on_disk.contains("deploy_token") && !on_disk.contains("org_token"),
            "the compartment is keyed by opaque locators, never by canonical names"
        );
        assert!(
            !on_disk.contains(TEST_LITERAL),
            "a leftover import file must not keep the plaintext literal after activate"
        );
    }

    // ---- Owner-only safe inventory ----------------------------------------
    let inventory = directory
        .inventory(owner, &SealedScopeRef::Project(fixture.project_key.clone()))
        .await
        .expect("owner inventory");
    assert_eq!(inventory.len(), 1);
    assert_eq!(inventory[0].name.as_str(), "deploy_token");
    assert_eq!(inventory[0].description.as_str(), "deployment credential");
    assert_eq!(inventory[0].version, 1);

    // Safe metadata carries no literal and no locator, even under `Debug`.
    let rendered = format!("{inventory:?}");
    assert!(!rendered.contains(TEST_LITERAL));
    assert!(!rendered.contains(&locator));

    // Global values are not in the project scope's inventory: reach is an
    // explicit Owner grant, never implicit scope membership.
    assert!(
        !inventory
            .iter()
            .any(|entry| entry.record_id == global.record_id),
        "a global value is not implicitly a member of any project scope"
    );

    // ---- no agent-reachable lifecycle or machine-wide inventory ------------
    // Structural: every public entry point on the Owner store demands an
    // `OwnerAuthority`, which an agent cannot construct.
    let store_source = include_str!("../store.rs");
    // Accessors and the staged-literal writer are exempt: the first return
    // handles the caller already owns, and the second requires a ticket that
    // only an owner-gated `prepare_*` can mint.
    // `with_redaction_resolver` is a construction-time builder (installs the
    // protected-history key resolver at wiring time); it is not an agent-facing
    // operation, so like `new` it carries no Owner authority.
    const OWNERLESS_BY_DESIGN: &[&str] = &[
        "new",
        "db",
        "compartment",
        "stage_literal",
        "is_empty",
        "with_redaction_resolver",
    ];
    let store_lines: Vec<&str> = store_source.lines().collect();
    let mut checked_entry_points = 0usize;
    for (index, line) in store_lines.iter().enumerate() {
        let trimmed = line.trim_start();
        if !(trimmed.starts_with("pub fn ") || trimmed.starts_with("pub async fn ")) {
            continue;
        }
        let name: String = trimmed
            .trim_start_matches("pub ")
            .trim_start_matches("async ")
            .trim_start_matches("fn ")
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if OWNERLESS_BY_DESIGN.contains(&name.as_str()) {
            continue;
        }
        // The signature is this line plus the next few, which is where the
        // parameter list lives after rustfmt wraps it.
        let signature = store_lines[index..(index + 12).min(store_lines.len())].join("\n");
        assert!(
            signature.contains("OwnerAuthority"),
            "sealed store entry point `{name}` must require Owner authority"
        );
        checked_entry_points += 1;
    }
    assert!(
        checked_entry_points >= 10,
        "expected the Owner lifecycle surface to be scanned, saw {checked_entry_points}"
    );

    // Structural: the *use* runtime an agent reaches has no listing surface.
    // Scoped safe metadata belongs to the separate listing tool, which is
    // covered by its own end-to-end test and does not expose this runtime.
    let runtime_public = public_fn_names(include_str!("../runtime.rs"));
    for name in &runtime_public {
        // `literal_reads` is a test-observability counter over reads that
        // already happened; it names no value and cannot be used to probe one.
        if name == "literal_reads" || name == "len" {
            continue;
        }
        for fragment in ORACLE_NAME_FRAGMENTS {
            assert!(
                !name.contains(fragment),
                "sealed runtime must expose no `{fragment}` oracle, found `{name}`"
            );
        }
    }

    // Behavioral: an unknown record id is indistinguishable from a known one
    // that the caller was not granted — both are simply absent to a non-owner
    // path, because there is no non-owner path that answers at all.
    let unknown = SealedRecordId::generate();
    assert!(
        fixture
            .db
            .sealed_value_record(unknown.to_string())
            .await
            .expect("record read")
            .is_none()
    );
}

#[tokio::test]
async fn sealed_storage_compartment_is_non_enumerable() {
    let fixture = SealedFixture::new().await;
    let directory = fixture.directory();
    let owner = SealedFixture::owner();
    let seeded = fixture
        .seed_value(
            SealedScopeRef::Project(fixture.project_key.clone()),
            "deploy_token",
        )
        .await;

    // ---- the compartment's own public surface ------------------------------
    let compartment_source = include_str!("../compartment.rs");
    for name in public_fn_names(compartment_source) {
        // `default_compartment_path` and `path` expose a location, not
        // contents; `parse`/`generate`/`new`/`handle`/`at`/`open_default` are
        // constructors and accessors over a single value.
        const LOCATION_AND_CONSTRUCTORS: &[&str] = &[
            "default_compartment_path",
            "path",
            "parse",
            "generate",
            "new",
            "handle",
            "at",
            "open_default",
            "as_str",
            "expose",
        ];
        if LOCATION_AND_CONSTRUCTORS.contains(&name.as_str()) {
            continue;
        }
        for fragment in ORACLE_NAME_FRAGMENTS {
            assert!(
                !name.contains(fragment),
                "the sealed compartment must expose no `{fragment}` surface, found `{name}`"
            );
        }
    }

    // The three literal-touching methods are crate-private, so no public,
    // re-exported, status, debug, doctor, or export path can grow onto them.
    for method in ["fn put(", "fn get_exact(", "fn remove("] {
        let at = compartment_source
            .find(method)
            .unwrap_or_else(|| panic!("compartment defines `{method}`"));
        let prefix = &compartment_source[at.saturating_sub(24)..at];
        assert!(
            prefix.contains("pub(crate)"),
            "compartment method `{method}` must stay crate-private, saw `{prefix}`"
        );
    }

    // ---- the generic credential store cannot reach the compartment ---------
    let credentials_source = include_str!("../../credentials.rs");
    assert!(
        !credentials_source.contains("    pub fn list_named_secrets"),
        "generic named-secret enumeration must not be public"
    );
    assert!(
        credentials_source.contains("pub(crate) fn list_named_secrets"),
        "named-secret enumeration must be privatized, not silently deleted"
    );
    // Nothing in the credential store knows the compartment exists.
    assert!(
        !credentials_source.contains("SealedCompartment")
            && !credentials_source.contains("sealed-compartment"),
        "the sealed compartment is a separate store, not a credential-store section"
    );
    // Distinct files, so a credential-file reader never sees sealed literals.
    let credential_path = crate::credentials::default_path();
    let compartment_path = crate::sealed::compartment::default_compartment_path();
    if let (Some(credential_path), Some(compartment_path)) = (credential_path, compartment_path) {
        assert_ne!(credential_path, compartment_path);
    }

    // The public credential surface exposes no enumeration of secrets.
    for name in public_fn_names(credentials_source) {
        if name == "default_path" || name == "path" {
            continue;
        }
        assert!(
            !name.contains("list_named") && !name.contains("count") && !name.contains("export"),
            "credential store must expose no secret enumeration, found `{name}`"
        );
    }

    // ---- exact authorized lifecycle lookup still works ---------------------
    let summary = directory
        .summary(owner, seeded.record_id)
        .await
        .expect("owner summary")
        .expect("record exists");
    assert_eq!(summary.name.as_str(), "deploy_token");
    assert_eq!(summary.version, 1);

    // And the exact-key compartment read still resolves for the Owner path.
    let row = fixture
        .db
        .sealed_value_record(seeded.record_id.to_string())
        .await
        .expect("record read")
        .expect("record exists");
    let key = crate::sealed::SealedCompartmentKey::parse(
        row.compartment_key.as_deref().expect("locator"),
    )
    .expect("locator parses");
    let literal = fixture
        .compartment
        .get_exact(&key)
        .expect("exact read")
        .expect("literal present");
    assert_eq!(literal.handle().expose(), TEST_LITERAL);
}
