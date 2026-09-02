//! One conservative ratchet for the local Rust daemon-wire authority.
//!
//! Starting at `cockpit-proto`, Cargo metadata discovers the recursive local
//! normal-dependency closure. The digest frames and hashes the crate-qualified
//! path and raw bytes of every `.rs` file below each crate's manifest directory,
//! including `build.rs`, non-`src` Rust inputs, comments, and test-only code.
//! Consequently every checked-in local Rust-source edit in that closure requires
//! a protocol bump and a new version digest. The deliberately broad coverage can
//! produce false positives for changes unrelated to the wire contract.
//!
//! This is a source-change ratchet, not proof that all behavior is captured.
//! External dependency behavior and non-Rust or generated inputs (including the
//! SQL files included by `cockpit-db`) are outside the digest, and a deliberate
//! coordinated digest rebaseline remains possible and review-visible.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

#[derive(Debug, Eq, PartialEq)]
struct LocalCrate {
    name: String,
    manifest_dir: PathBuf,
}

#[test]
fn rust_wire_authority_matches_versioned_digest_and_archives() {
    let proto_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let authority_crates = production_local_dependency_closure(proto_manifest);
    let sources = authority_source_files(&authority_crates);
    let actual = source_digest(&sources);
    let digest_path = proto_manifest.join(format!(
        "tests/fixtures/daemon_proto/v{}/wire-schema.sha256",
        cockpit_proto::PROTOCOL_VERSION
    ));
    let expected = std::fs::read_to_string(&digest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", digest_path.display()));
    assert_eq!(
        actual,
        expected.trim(),
        "local Rust source in the recursive production dependency closure changed; bump PROTOCOL_VERSION and add a complete vN fixture directory"
    );

    assert_archived_fixture_bytes(proto_manifest);
}

fn authority_source_files(authority_crates: &[LocalCrate]) -> Vec<(String, Vec<u8>)> {
    let mut sources = Vec::new();
    for local_crate in authority_crates {
        let mut relative_paths = Vec::new();
        rust_sources(
            &local_crate.manifest_dir,
            Path::new(""),
            &mut relative_paths,
        );
        relative_paths.sort();
        for relative in relative_paths {
            let path = local_crate.manifest_dir.join(&relative);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let relative = relative.to_string_lossy().replace('\\', "/");
            sources.push((format!("{}/{relative}", local_crate.name), bytes));
        }
    }
    sources.sort_by(|left, right| left.0.cmp(&right.0));
    sources
}

fn source_digest(sources: &[(String, Vec<u8>)]) -> String {
    let mut digest = Sha256::new();
    for (qualified_path, bytes) in sources {
        // Length-prefix both fields so neither file names nor contents can
        // create concatenation ambiguities.
        digest.update((qualified_path.len() as u64).to_be_bytes());
        digest.update(qualified_path.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn production_local_dependency_closure(proto_manifest: &Path) -> Vec<LocalCrate> {
    let workspace_root = proto_manifest
        .parent()
        .and_then(Path::parent)
        .expect("cockpit-proto must be in the workspace crates directory");
    let output = std::process::Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--format-version", "1"])
        .current_dir(workspace_root)
        .output()
        .expect("run cargo metadata for the production dependency graph");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("cargo metadata packages must be an array");
    let mut graph = BTreeMap::new();
    for package in packages {
        let unresolved_manifest_path = PathBuf::from(
            package["manifest_path"]
                .as_str()
                .expect("metadata package must have a manifest path"),
        );
        let manifest_path = unresolved_manifest_path
            .canonicalize()
            .unwrap_or_else(|error| {
                panic!("resolve {}: {error}", unresolved_manifest_path.display())
            });
        let name = package["name"]
            .as_str()
            .expect("metadata package must have a name")
            .to_owned();
        let manifest_dir = manifest_path
            .parent()
            .expect("manifest has a parent directory")
            .to_owned();
        let dependencies = package["dependencies"]
            .as_array()
            .expect("metadata package dependencies must be an array")
            .iter()
            .filter(|dependency| dependency["kind"].is_null())
            .filter_map(|dependency| dependency["path"].as_str())
            .map(PathBuf::from)
            .collect::<Vec<_>>();
        graph.insert(manifest_dir, (name, dependencies));
    }

    let root = proto_manifest
        .canonicalize()
        .unwrap_or_else(|error| panic!("resolve {}: {error}", proto_manifest.display()));
    let mut pending = vec![root];
    let mut seen = BTreeSet::new();
    let mut authority = BTreeMap::new();
    while let Some(manifest_dir) = pending.pop() {
        if !seen.insert(manifest_dir.clone()) {
            continue;
        }
        let (name, dependencies) = graph.get(&manifest_dir).unwrap_or_else(|| {
            panic!(
                "local production dependency {} is absent from cargo metadata",
                manifest_dir.display()
            )
        });
        authority.insert(
            name.clone(),
            LocalCrate {
                name: name.clone(),
                manifest_dir,
            },
        );
        pending.extend(dependencies.iter().map(|path| {
            path.canonicalize()
                .unwrap_or_else(|error| panic!("resolve {}: {error}", path.display()))
        }));
    }
    authority.into_values().collect()
}

fn assert_archived_fixture_bytes(proto_manifest: &Path) {
    let root = proto_manifest.join("tests/fixtures/daemon_proto");
    let manifest_path = root.join("archive.sha256");
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let mut listed = BTreeSet::new();
    for (line_number, line) in manifest.lines().enumerate() {
        let (expected, relative) = line.split_once("  ").unwrap_or_else(|| {
            panic!(
                "{}:{} must be sha256<two spaces>path",
                manifest_path.display(),
                line_number + 1
            )
        });
        assert!(
            listed.insert(relative.to_string()),
            "duplicate archive path {relative}"
        );
        let actual = hex_digest(&std::fs::read(root.join(relative)).expect("read archive fixture"));
        assert_eq!(
            actual, expected,
            "historical fixture {relative} changed; restore its exact archived bytes"
        );
    }
    let expected = (12..=21)
        .flat_map(|version| {
            ["event.json", "request.json", "response.json"]
                .map(move |file| format!("v{version}/{file}"))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        listed, expected,
        "archive manifest must cover every historical fixture exactly once"
    );
    // These checks close accidental edits/additions/removals. A deliberate,
    // coordinated digest/checksum rewrite remains visible only in review;
    // local tests cannot prevent an authorized rebaseline.
}

#[test]
fn raw_digest_captures_manual_serializer_constants() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/event.rs");
    let before_bytes = std::fs::read(&path).expect("read event wire authority");
    let before_source = String::from_utf8(before_bytes.clone()).expect("event.rs is UTF-8");
    assert!(
        before_source.contains("map.serialize_entry(\"kind\", CLASS_MISSING_TOOL_ENTITLEMENT)?")
    );
    let after_source = before_source.replacen(
        "const CLASS_MISSING_TOOL_ENTITLEMENT: &str = \"missing_tool_entitlement\";",
        "const CLASS_MISSING_TOOL_ENTITLEMENT: &str = \"missing_entitlement\";",
        1,
    );
    assert_ne!(
        after_source, before_source,
        "the authority constant must exist"
    );
    let before = vec![("cockpit-proto/src/event.rs".to_owned(), before_bytes)];
    let after = vec![(
        "cockpit-proto/src/event.rs".to_owned(),
        after_source.into_bytes(),
    )];

    assert_ne!(source_digest(&before), source_digest(&after));
}

#[test]
fn authority_follows_transitive_local_production_dependencies() {
    let proto_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let authority = production_local_dependency_closure(proto_manifest);
    let names = authority
        .iter()
        .map(|local_crate| local_crate.name.as_str())
        .collect::<BTreeSet<_>>();
    assert!(names.contains("cockpit-config"));
    assert!(names.contains("cockpit-db"));
    assert!(names.contains("cockpit-tokenizer"));

    let sources = authority_source_files(&authority);
    assert!(
        sources
            .iter()
            .any(|(path, _)| path == "cockpit-tokenizer/src/lib.rs"),
        "the transitive tokenizer crate's Rust source must contribute to the digest"
    );
}

fn rust_sources(root: &Path, relative: &Path, out: &mut Vec<PathBuf>) {
    let directory = root.join(relative);
    for entry in std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()))
    {
        let entry = entry.expect("read Rust source directory entry");
        let path = entry.path();
        let child_relative = relative.join(entry.file_name());
        if path.is_dir() {
            rust_sources(root, &child_relative, out);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            out.push(child_relative);
        }
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
