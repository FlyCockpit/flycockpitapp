use std::path::{Path, PathBuf};

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).expect("read source directory") {
            let path = entry.expect("read source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

#[test]
fn assistant_registry_updates_are_owned_by_validated_db_cas_executors() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let owner = workspace.join("crates/cockpit-db/src/db/assistants.rs");
    let violations = [workspace.join("crates"), workspace.join("apps")]
        .into_iter()
        .flat_map(|root| rust_sources(&root))
        .filter(|path| path != &owner && !path.components().any(|part| part.as_os_str() == "tests"))
        .filter_map(|path| {
            let source = std::fs::read_to_string(&path).expect("read production Rust source");
            source
                .to_ascii_lowercase()
                .contains("update assistants")
                .then_some(path)
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "raw assistant registry updates outside cockpit-db: {violations:?}"
    );

    let source = std::fs::read_to_string(owner).expect("read assistant DB owner");
    for contract in [
        "pub fn update_assistant_identity_hashes_cas_conn",
        "pub fn update_assistant_content_hash_cas_conn",
        "validate_config_json(config_json)?",
        "validate_content_hash(expected_hash)?",
        "validate_content_hash(next_hash)?",
        "if changed != 1",
    ] {
        assert!(
            source.contains(contract),
            "missing CAS contract: {contract}"
        );
    }
}
