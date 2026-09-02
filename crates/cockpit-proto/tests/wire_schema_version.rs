//! Freeze ratchet for the local Rust daemon-wire authority.
//!
//! This test owns two mechanisms, one per era of a protocol version:
//!
//! * While a version is **current**, `v{PROTOCOL_VERSION}/wire-schema.sha256`
//!   is the single canonical digest file for it. It records the SHA-256 of
//!   the production Rust dependency closure (`source`), the SHA-256 of this
//!   version's `event.json`/`request.json`/`response.json` fixture bytes
//!   (`fixtures`), and the archive-ledger chain head at this version's mint
//!   (`archive-chain`). The `source` and `fixtures` lines are the only
//!   sanctioned in-place rebaseline path: pre-mint development churn is
//!   legitimate, and the failure messages below document the exact update
//!   procedure. The `archive-chain` line is mint-time history and is never
//!   legitimately edited afterwards.
//!
//! * Once a version is retired it is **frozen** in the append-only archive
//!   ledger `tests/fixtures/daemon_proto/archive.sha256`. The ledger records
//!   the digest of every file in each frozen version's directory plus a
//!   chained `chain v<N> <sha256>` line: `chain(N)` is `SHA-256` over the
//!   previous version's chain line and `N`'s recorded entries, seeded by the
//!   `ARCHIVE_CHAIN_DOMAIN` constant. Recorded digests are append-only: they
//!   are never legitimately rewritten or removed, and the chain makes any
//!   rewrite of a recorded digest disagree with every chain line minted
//!   after it, including the `archive-chain` anchors frozen inside each
//!   retired version's own `wire-schema.sha256`.
//!
//! Freezing is automatic, not remembered: the frozen range is derived as
//! `FIRST_ARCHIVED_PROTOCOL_VERSION..PROTOCOL_VERSION`, so minting a new
//! `PROTOCOL_VERSION` fails this test until the retiring version is appended
//! to the ledger — the failure message prints the exact lines to append.
//! There is no hand-maintained version list anywhere in this mechanism.
//!
//! Honest limit, stated once: a repository-local test cannot make a fully
//! coordinated rewrite of the whole fixture tree cryptographically
//! impossible; such a rewrite necessarily touches every recorded digest,
//! every chain line, and every version's canonical digest file at once and
//! is only visible in review. Every smaller edit — a lone fixture rewrite, a
//! lone ledger line rewrite, a missing freeze, an unanchored chain, a
//! mismatched canonical line — fails here.
//!
//! The source digest covers the recursive local normal-dependency closure of
//! `cockpit-proto` discovered via Cargo metadata: every `.rs` file below each
//! crate's manifest directory, including `build.rs`, non-`src` Rust inputs,
//! comments, and test-only code. Consequently every checked-in local
//! Rust-source edit in that closure requires either a sanctioned pre-mint
//! rebaseline of the current version's `source` line or a protocol-version
//! mint. The deliberately broad coverage can produce false positives for
//! changes unrelated to the wire contract. External dependency behavior and
//! non-Rust or generated inputs (including the SQL files included by
//! `cockpit-db`) are outside the digest.
//!
//! This is a source-change ratchet, not proof that all behavior is captured.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

const ARCHIVE_LEDGER_FILE: &str = "archive.sha256";
const WIRE_SCHEMA_DIGEST_FILE: &str = "wire-schema.sha256";
/// Domain-separates the archive ledger chain from every other digest use.
const ARCHIVE_CHAIN_DOMAIN: &str = "cockpit-proto/daemon_proto/archive/v1";
/// Fixture files every frozen version must record. Keep sorted: the ledger
/// requires path-sorted entries and the fixtures digest below reads them in
/// this order.
const FIXTURE_FILES: [&str; 3] = ["event.json", "request.json", "response.json"];

/// Documents the single sanctioned rebaseline path for the current version's
/// canonical digest file; embedded verbatim in that check's failure messages.
const CANONICAL_DIGEST_PROCEDURE: &str = "\
v{PROTOCOL_VERSION}/wire-schema.sha256 is the single canonical digest file for \
the current protocol version:
- `source`       SHA-256 over the production Rust dependency closure (every \
.rs file, length-prefixed paths and bytes)
- `fixtures`     SHA-256 over this directory's event.json, request.json, \
response.json
- `archive-chain` archive ledger chain head at this version's mint; NEVER \
edited after mint
Sanctioned pre-mint rebaseline (development churn before this version is \
retired): replace the mismatching `source`/`fixtures` line with the computed \
value printed above. There is no other sanctioned edit path, and the frozen \
archive has no rebaseline procedure at all. A wire-incompatible change is not \
rebaselined away: bump PROTOCOL_VERSION, mint the next fixture directory, and \
let the archive ledger check print the exact freeze lines for this version.";

#[derive(Debug, Eq, PartialEq)]
struct LocalCrate {
    name: String,
    manifest_dir: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct LedgerEntry {
    digest: String,
    path: String,
}

#[derive(Debug, Eq, PartialEq)]
struct LedgerVersion {
    version: u32,
    files: Vec<LedgerEntry>,
    chain: String,
}

#[derive(Debug, Eq, PartialEq)]
struct Ledger {
    versions: Vec<LedgerVersion>,
}

impl Ledger {
    fn head(&self) -> &str {
        &self
            .versions
            .last()
            .expect("archive ledger holds at least one frozen version")
            .chain
    }

    fn chain_through(&self, version: u32) -> Option<&str> {
        self.versions
            .iter()
            .find(|frozen| frozen.version == version)
            .map(|frozen| frozen.chain.as_str())
    }
}

#[derive(Debug, Eq, PartialEq)]
struct CanonicalDigest {
    source: String,
    fixtures: String,
    archive_chain: String,
}

#[test]
fn rust_wire_authority_matches_versioned_digest_and_archives() {
    let proto_manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let fixture_root = daemon_proto_fixture_root(proto_manifest);
    let derived: Vec<u32> =
        (cockpit_proto::FIRST_ARCHIVED_PROTOCOL_VERSION..cockpit_proto::PROTOCOL_VERSION).collect();
    assert!(
        !derived.is_empty(),
        "every released protocol version has frozen history: \
         FIRST_ARCHIVED_PROTOCOL_VERSION must stay below PROTOCOL_VERSION"
    );

    // Frozen history: append-only, derived coverage, chain-verified.
    let ledger = read_archive_ledger(&fixture_root);
    assert_ledger_covers_derived_range(&ledger, &derived, &fixture_root);
    assert_ledger_entries_match_frozen_bytes(&ledger, &fixture_root);
    assert_ledger_chains_are_consistent(&ledger);
    assert_frozen_mint_anchors_match_ledger_prefixes(&ledger, &fixture_root);

    // Current version: one canonical digest file, loud single rebaseline path.
    let authority_crates = production_local_dependency_closure(proto_manifest);
    let actual_source = labeled_digest(&authority_source_files(&authority_crates));
    let current_dir = fixture_root.join(format!("v{}", cockpit_proto::PROTOCOL_VERSION));
    let actual_fixtures = fixtures_digest(&current_dir);
    let canonical_path = current_dir.join(WIRE_SCHEMA_DIGEST_FILE);
    if !canonical_path.is_file() {
        panic!(
            "the canonical digest file for the current protocol version is \
             missing: {path}. Create it with exactly three lines (source = \
             production Rust closure digest, fixtures = this version's \
             event/request/response fixture digest, archive-chain = the \
             archive ledger head at this mint):\nsource {actual_source}\n\
             fixtures {actual_fixtures}\narchive-chain {archive_chain}",
            path = canonical_path.display(),
            archive_chain = ledger.head(),
        );
    }
    let canonical = read_canonical_digest_file(&canonical_path);

    assert_eq!(
        canonical.source,
        actual_source,
        "{procedure}\n{path} `source` mismatch:\n  recorded: {recorded}\n  \
         computed: {computed}\npre-mint rebaseline: replace the `source` line \
         with:\nsource {computed}",
        procedure = CANONICAL_DIGEST_PROCEDURE,
        path = canonical_path.display(),
        recorded = canonical.source,
        computed = actual_source,
    );
    assert_eq!(
        canonical.fixtures,
        actual_fixtures,
        "{procedure}\n{path} `fixtures` mismatch — the current fixture bytes \
         were rewritten with no digest change:\n  recorded: {recorded}\n  \
         computed: {computed}\npre-mint rebaseline: replace the `fixtures` \
         line with:\nfixtures {computed}",
        procedure = CANONICAL_DIGEST_PROCEDURE,
        path = canonical_path.display(),
        recorded = canonical.fixtures,
        computed = actual_fixtures,
    );
    assert_eq!(
        canonical.archive_chain,
        ledger.head(),
        "{procedure}\n{path} `archive-chain` mismatch: the archive ledger no \
         longer matches the chain head minted into the current version's \
         canonical digest file. The frozen archive has no rebaseline \
         procedure: restore the archived fixture bytes to their recorded \
         digests. To change the wire, mint a new protocol version (bump \
         PROTOCOL_VERSION; the ledger check prints the exact freeze lines).",
        procedure = CANONICAL_DIGEST_PROCEDURE,
        path = canonical_path.display(),
    );

    let mut expected_current_files: BTreeSet<String> = FIXTURE_FILES
        .iter()
        .map(|file| (*file).to_string())
        .collect();
    expected_current_files.insert(WIRE_SCHEMA_DIGEST_FILE.to_string());
    assert_eq!(
        directory_file_names(&current_dir),
        expected_current_files,
        "the current protocol's fixture directory must contain exactly \
         event.json, request.json, response.json, and wire-schema.sha256"
    );
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

/// Length-prefixes both fields so neither labels nor contents can create
/// concatenation ambiguities. Shared by the source and fixture digests so
/// every recorded digest in this ratchet has one definition.
fn labeled_digest(items: &[(String, Vec<u8>)]) -> String {
    let mut digest = Sha256::new();
    for (label, bytes) in items {
        digest.update((label.len() as u64).to_be_bytes());
        digest.update(label.as_bytes());
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixtures_digest(fixture_dir: &Path) -> String {
    let mut items = Vec::new();
    for file in FIXTURE_FILES {
        let path = fixture_dir.join(file);
        let bytes =
            std::fs::read(&path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        items.push((file.to_string(), bytes));
    }
    labeled_digest(&items)
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

fn read_archive_ledger(root: &Path) -> Ledger {
    let manifest_path = root.join(ARCHIVE_LEDGER_FILE);
    let manifest = std::fs::read_to_string(&manifest_path)
        .unwrap_or_else(|error| panic!("read {}: {error}", manifest_path.display()));
    let mut versions: Vec<LedgerVersion> = Vec::new();
    let mut group: Option<LedgerVersion> = None;
    for (line_number, line) in manifest.lines().enumerate() {
        assert!(
            !line.trim().is_empty(),
            "{}:{} must not be blank",
            manifest_path.display(),
            line_number + 1
        );
        if let Some(rest) = line.strip_prefix("chain v") {
            let (version, digest) = rest.split_once(' ').unwrap_or_else(|| {
                panic!(
                    "{}:{} must be `chain v<N> <sha256>`",
                    manifest_path.display(),
                    line_number + 1
                )
            });
            let version: u32 = version.parse().unwrap_or_else(|error| {
                panic!(
                    "{}:{} chain version must be numeric: {error}",
                    manifest_path.display(),
                    line_number + 1
                )
            });
            assert_is_digest(digest);
            let mut finished = group.take().unwrap_or_else(|| {
                panic!(
                    "{}:{} chain line must follow that version's file entries",
                    manifest_path.display(),
                    line_number + 1
                )
            });
            assert_eq!(
                finished.version,
                version,
                "{}:{} chain version must match the group it terminates",
                manifest_path.display(),
                line_number + 1
            );
            finished.chain = digest.to_string();
            versions.push(finished);
            continue;
        }
        let (digest, path) = line.split_once("  ").unwrap_or_else(|| {
            panic!(
                "{}:{} must be `<sha256>  v<N>/<file>` or `chain v<N> <sha256>`",
                manifest_path.display(),
                line_number + 1
            )
        });
        assert_is_digest(digest);
        let (directory, file_name) = path.split_once('/').unwrap_or_else(|| {
            panic!(
                "{}:{} archive path must be v<N>/<file>",
                manifest_path.display(),
                line_number + 1
            )
        });
        let version: u32 = directory
            .strip_prefix('v')
            .unwrap_or_else(|| {
                panic!(
                    "{}:{} archive directory must start with `v`",
                    manifest_path.display(),
                    line_number + 1
                )
            })
            .parse()
            .unwrap_or_else(|error| {
                panic!(
                    "{}:{} archive directory must be v<N>: {error}",
                    manifest_path.display(),
                    line_number + 1
                )
            });
        assert!(
            FIXTURE_FILES.contains(&file_name) || file_name == WIRE_SCHEMA_DIGEST_FILE,
            "{}:{} unexpected archived fixture path {path}",
            manifest_path.display(),
            line_number + 1
        );
        let entry = LedgerEntry {
            digest: digest.to_string(),
            path: path.to_string(),
        };
        match group.as_mut() {
            None => {
                group = Some(LedgerVersion {
                    version,
                    files: vec![entry],
                    chain: String::new(),
                });
            }
            Some(current_group) => {
                assert_eq!(
                    current_group.version,
                    version,
                    "{}:{} archive entries must be grouped by version",
                    manifest_path.display(),
                    line_number + 1
                );
                let last = current_group.files.last().expect("group has entries");
                assert!(
                    last.path < entry.path,
                    "{}:{} archive entries within v{version} must be sorted by path",
                    manifest_path.display(),
                    line_number + 1
                );
                current_group.files.push(entry);
            }
        }
    }
    assert!(
        group.is_none(),
        "{} ends without a final `chain v<N> <sha256>` line",
        manifest_path.display()
    );
    for pair in versions.windows(2) {
        assert!(
            pair[0].version < pair[1].version,
            "archive ledger versions must be strictly increasing"
        );
    }
    Ledger { versions }
}

fn assert_ledger_covers_derived_range(ledger: &Ledger, derived: &[u32], root: &Path) {
    let present: Vec<u32> = ledger
        .versions
        .iter()
        .map(|frozen| frozen.version)
        .collect();
    if present.as_slice() == derived {
        return;
    }
    let ledger_path = root.join(ARCHIVE_LEDGER_FILE);
    let is_proper_prefix = !present.is_empty()
        && present.len() < derived.len()
        && present
            .iter()
            .zip(derived.iter())
            .all(|(recorded, expected)| recorded == expected);
    if is_proper_prefix {
        let unfrozen = &derived[present.len()..];
        panic!(
            "PROTOCOL_VERSION minted a new current version but the archive \
             ledger was not extended: every version below PROTOCOL_VERSION \
             must be frozen at mint time, and this check is the onboarding \
             step — nothing is left to human memory. Append these exact lines \
             to {ledger}:\n{lines}",
            ledger = ledger_path.display(),
            lines = freeze_lines(unfrozen, root, ledger.head()),
        );
    }
    panic!(
        "the archive ledger must cover exactly the frozen versions {derived:?} \
         (every historical protocol version, derived as \
         FIRST_ARCHIVED_PROTOCOL_VERSION..PROTOCOL_VERSION); recorded digests \
         are append-only. Found {present:?}"
    );
}

fn assert_ledger_entries_match_frozen_bytes(ledger: &Ledger, root: &Path) {
    for frozen in &ledger.versions {
        let mut recorded = BTreeSet::new();
        for entry in &frozen.files {
            assert!(
                recorded.insert(entry.path.as_str()),
                "duplicate archive ledger path {}",
                entry.path
            );
            let bytes = std::fs::read(root.join(&entry.path)).unwrap_or_else(|error| {
                panic!(
                    "read archived fixture {} (recorded digests are \
                     append-only; a missing archived file is a history \
                     rewrite): {error}",
                    entry.path
                )
            });
            assert_eq!(
                hex_digest(&bytes),
                entry.digest,
                "historical fixture {path} changed; restore its exact archived \
                 bytes. The frozen archive has no rebaseline procedure: to \
                 change the wire, mint a new protocol version",
                path = entry.path,
            );
        }
        let expected_paths: Vec<String> = FIXTURE_FILES
            .iter()
            .map(|file| format!("v{}/{}", frozen.version, file))
            .collect();
        for path in expected_paths {
            assert!(
                recorded.contains(path.as_str()),
                "frozen v{} must record {path}",
                frozen.version
            );
        }
        let directory = root.join(format!("v{}", frozen.version));
        let ledger_file_names: BTreeSet<String> = recorded
            .iter()
            .map(|path| file_name(path).to_string())
            .collect();
        assert_eq!(
            directory_file_names(&directory),
            ledger_file_names,
            "frozen v{} directory and archive ledger must record exactly the \
             same files",
            frozen.version
        );
    }
}

fn assert_ledger_chains_are_consistent(ledger: &Ledger) {
    let mut previous = hex_digest(ARCHIVE_CHAIN_DOMAIN.as_bytes());
    for frozen in &ledger.versions {
        let mut payload = previous.clone().into_bytes();
        payload.push(b'\n');
        for entry in &frozen.files {
            payload.extend_from_slice(format!("{}  {}\n", entry.digest, entry.path).as_bytes());
        }
        assert_eq!(
            hex_digest(&payload),
            frozen.chain,
            "archive ledger chain for v{} does not match its recorded \
             entries; recorded digests are append-only — restore them",
            frozen.version
        );
        previous.clone_from(&frozen.chain);
    }
}

fn assert_frozen_mint_anchors_match_ledger_prefixes(ledger: &Ledger, root: &Path) {
    for frozen in &ledger.versions {
        let digest_path = root
            .join(format!("v{}", frozen.version))
            .join(WIRE_SCHEMA_DIGEST_FILE);
        if !digest_path.is_file() {
            // Versions retired before the canonical digest file existed.
            continue;
        }
        let canonical = read_canonical_digest_file(&digest_path);
        let directory = root.join(format!("v{}", frozen.version));
        assert_eq!(
            canonical.fixtures,
            fixtures_digest(&directory),
            "frozen v{version}/wire-schema.sha256 records a `fixtures` digest \
             that disagrees with the fixture bytes archived beside it; the \
             frozen state is internally inconsistent — restore the frozen \
             bytes or re-freeze the version from a consistent state",
            version = frozen.version,
        );
        let previous_chain = match ledger.chain_through(frozen.version.saturating_sub(1)) {
            Some(chain) => chain,
            None => hex_digest(ARCHIVE_CHAIN_DOMAIN.as_bytes()),
        };
        assert_eq!(
            canonical.archive_chain,
            previous_chain,
            "frozen v{version}/wire-schema.sha256 mint anchor no longer matches \
             the archive ledger prefix ending at v{previous}; the frozen \
             archive has no rebaseline procedure — restore the archived bytes",
            version = frozen.version,
            previous = frozen.version.saturating_sub(1),
        );
    }
}

fn freeze_lines(versions: &[u32], root: &Path, start_chain: &str) -> String {
    let mut output = String::new();
    let mut previous = start_chain.to_string();
    for version in versions {
        let directory = root.join(format!("v{version}"));
        let names = directory_file_names(&directory);
        for name in &names {
            assert!(
                FIXTURE_FILES.contains(&name.as_str()) || name == WIRE_SCHEMA_DIGEST_FILE,
                "unexpected file {path} in v{version}: the ledger records only \
                 event.json, request.json, response.json, and \
                 wire-schema.sha256; remove it before freezing",
                path = directory.join(name).display(),
            );
        }
        let mut payload = previous.clone().into_bytes();
        payload.push(b'\n');
        for name in &names {
            let path = directory.join(name);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let digest = hex_digest(&bytes);
            let line = format!("{digest}  v{version}/{name}\n");
            output.push_str(&line);
            payload.extend_from_slice(line.as_bytes());
        }
        let chain = hex_digest(&payload);
        output.push_str(&format!("chain v{version} {chain}\n"));
        previous = chain;
    }
    output
}

fn read_canonical_digest_file(path: &Path) -> CanonicalDigest {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    let lines: Vec<&str> = raw.lines().collect();
    assert_eq!(
        lines.len(),
        3,
        "{} must contain exactly three lines: `source <sha256>`, `fixtures \
         <sha256>`, `archive-chain <sha256>`",
        path.display()
    );
    let mut values: Vec<String> = Vec::new();
    for (index, key) in ["source", "fixtures", "archive-chain"].iter().enumerate() {
        let line = lines[index];
        let (actual_key, digest) = line
            .split_once(' ')
            .unwrap_or_else(|| panic!("{}:{} must be `{key} <sha256>`", path.display(), index + 1));
        assert_eq!(
            actual_key,
            *key,
            "{}:{} must use key `{key}`",
            path.display(),
            index + 1
        );
        assert_is_digest(digest);
        values.push(digest.to_string());
    }
    CanonicalDigest {
        source: values[0].clone(),
        fixtures: values[1].clone(),
        archive_chain: values[2].clone(),
    }
}

fn directory_file_names(directory: &Path) -> BTreeSet<String> {
    let entries = std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("read {}: {error}", directory.display()));
    let mut names = BTreeSet::new();
    for entry in entries {
        let entry =
            entry.unwrap_or_else(|error| panic!("read {} entry: {error}", directory.display()));
        let path = entry.path();
        assert!(
            path.is_file(),
            "unexpected non-file under {}: {}",
            directory.display(),
            path.display()
        );
        assert!(
            names.insert(entry.file_name().to_string_lossy().to_string()),
            "duplicate file name under {}",
            directory.display()
        );
    }
    names
}

fn file_name(path: &str) -> &str {
    path.rsplit_once('/').map(|(_, name)| name).unwrap_or(path)
}

fn daemon_proto_fixture_root(proto_manifest: &Path) -> PathBuf {
    proto_manifest
        .join("tests")
        .join("fixtures")
        .join("daemon_proto")
}

fn assert_is_digest(value: &str) {
    assert!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "malformed sha256 digest \"{value}\""
    );
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
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

    assert_ne!(labeled_digest(&before), labeled_digest(&after));
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
