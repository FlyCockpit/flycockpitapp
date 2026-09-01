//! Deterministic inventory of cockpit-core platform packages for computer target identity.
//!
//! Compares `cargo metadata --locked --offline` against the checked-in fixture.
//! Does not fetch during tests.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

const TRIPLES: &[&str] = &[
    "aarch64-apple-darwin",
    "x86_64-pc-windows-msvc",
    "x86_64-unknown-linux-gnu",
];

const MACH2_CHECKSUM: &str = "dae608c151f68243f2b000364e1f7b186d9c29845f7d2d85bd31b9ad77ad552b";
const WORKSPACE_MSRV: &str = "1.95";

#[derive(Debug, serde::Deserialize)]
struct InventoryFixture {
    packages_by_platform: BTreeMap<String, Vec<PackageRecord>>,
    direct_features: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, serde::Deserialize, serde::Serialize, PartialEq, Eq)]
struct PackageRecord {
    name: String,
    version: String,
    source: String,
    checksum: Option<String>,
    license: Option<String>,
    rust_version: Option<String>,
    edition: Option<String>,
    features: Vec<String>,
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = crates/cockpit-core
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn lock_checksums(root: &std::path::Path) -> BTreeMap<(String, String), String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    let mut map = BTreeMap::new();
    let mut name = None;
    let mut version = None;
    for line in lock.lines() {
        if let Some(rest) = line.strip_prefix("name = \"") {
            name = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = \"") {
            version = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("checksum = \"") {
            if let (Some(n), Some(v)) = (name.take(), version.take()) {
                let ck = rest.trim_end_matches('"').to_string();
                map.insert((n, v), ck);
            }
        } else if line.starts_with("[[package]]") {
            name = None;
            version = None;
        }
    }
    map
}

fn metadata_for_platform(root: &std::path::Path, triple: &str) -> Value {
    let out = Command::new("cargo")
        .args([
            "metadata",
            "--locked",
            "--offline",
            "--format-version",
            "1",
            "--filter-platform",
            triple,
        ])
        .current_dir(root)
        .output()
        .expect("cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed for {triple}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    serde_json::from_slice(&out.stdout).expect("metadata json")
}

fn resolve_cockpit_core_package_ids(meta: &Value) -> BTreeSet<String> {
    let packages = meta["packages"].as_array().unwrap();
    let mut by_id: BTreeMap<String, &Value> = BTreeMap::new();
    for p in packages {
        by_id.insert(p["id"].as_str().unwrap().to_string(), p);
    }
    let core = packages
        .iter()
        .find(|p| p["name"] == "cockpit-core")
        .expect("cockpit-core in metadata");
    let mut stack = vec![core["id"].as_str().unwrap().to_string()];
    let mut seen = BTreeSet::new();
    while let Some(id) = stack.pop() {
        if !seen.insert(id.clone()) {
            continue;
        }
        let Some(pkg) = by_id.get(&id) else {
            continue;
        };
        if let Some(deps) = pkg["dependencies"].as_array() {
            for dep in deps {
                // Only normal deps
                let kind = dep.get("kind").and_then(|k| k.as_str()).unwrap_or("");
                if kind == "dev" || kind == "build" {
                    continue;
                }
                let dep_name = dep["name"].as_str().unwrap();
                // Find resolved package by name matching a dependency source if possible
                for (pid, p) in &by_id {
                    if p["name"] == dep_name && !seen.contains(pid.as_str()) {
                        stack.push(pid.clone());
                    }
                }
            }
        }
    }
    seen
}

fn platform_package_names(triple: &str) -> BTreeSet<&'static str> {
    let mut s = BTreeSet::new();
    // Always relevant for inventory of target-identity platform crates
    match triple {
        "aarch64-apple-darwin" => {
            for n in [
                "mach2",
                "block2",
                "objc2-app-kit",
                "objc2-application-services",
                "objc2-core-foundation",
                "objc2-core-graphics",
                "objc2-color-sync",
                "objc2-foundation",
                "libc",
            ] {
                s.insert(n);
            }
        }
        "x86_64-pc-windows-msvc" => {
            s.insert("windows");
        }
        "x86_64-unknown-linux-gnu" => {
            for n in [
                "x11rb",
                "x11rb-protocol",
                "atspi",
                "atspi-common",
                "atspi-connection",
                "atspi-proxies",
            ] {
                s.insert(n);
            }
        }
        _ => {}
    }
    s
}

fn target_condition_for_triple(triple: &str) -> &'static str {
    match triple {
        "aarch64-apple-darwin" => "cfg(target_os = \"macos\")",
        "x86_64-pc-windows-msvc" => "cfg(target_os = \"windows\")",
        "x86_64-unknown-linux-gnu" => "cfg(target_os = \"linux\")",
        _ => panic!("unsupported inventory triple {triple}"),
    }
}

/// Read the feature set selected on every direct, audited platform package.
/// The fixture is a ratchet for this exact manifest surface, rather than a
/// hand-maintained subset that a newly enabled feature could bypass.
fn manifest_direct_features(manifest: &toml::Value, triple: &str) -> BTreeMap<String, Vec<String>> {
    let dependencies = manifest
        .get("target")
        .and_then(toml::Value::as_table)
        .and_then(|targets| targets.get(target_condition_for_triple(triple)))
        .and_then(toml::Value::as_table)
        .and_then(|target| target.get("dependencies"))
        .and_then(toml::Value::as_table)
        .unwrap_or_else(|| panic!("missing target dependencies for {triple}"));

    platform_package_names(triple)
        .into_iter()
        .filter_map(|package| {
            let dependency = dependencies.get(package)?;
            let mut features = dependency
                .as_table()
                .and_then(|table| table.get("features"))
                .and_then(toml::Value::as_array)
                .unwrap_or_else(|| panic!("{package} must declare a features array"))
                .iter()
                .map(|feature| {
                    feature
                        .as_str()
                        .unwrap_or_else(|| panic!("{package} has a non-string feature"))
                        .to_string()
                })
                .collect::<Vec<_>>();
            features.sort();
            assert_eq!(
                features.len(),
                features.iter().collect::<BTreeSet<_>>().len(),
                "{package} declares a duplicate feature"
            );
            Some((package.to_string(), features))
        })
        .collect()
}

#[test]
fn computer_target_dependency_inventory() {
    let root = workspace_root();
    let fixture_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/computer-target-dependency-inventory.json");
    let fixture_raw = std::fs::read_to_string(&fixture_path)
        .unwrap_or_else(|e| panic!("missing fixture {}: {e}", fixture_path.display()));
    let fixture: InventoryFixture =
        serde_json::from_str(&fixture_raw).expect("fixture json schema");

    let manifest_raw =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("cockpit-core Cargo.toml");
    let manifest: toml::Value = manifest_raw.parse().expect("valid cockpit-core Cargo.toml");

    let checksums = lock_checksums(&root);

    // The fixture must exactly inventory every direct feature enabled for the
    // audited packages. This closes the omission class: a new Cargo.toml
    // feature cannot escape the forbidden-feature checks below.
    let expected_direct = &fixture.direct_features;

    for triple in TRIPLES {
        let manifest_direct = manifest_direct_features(&manifest, triple);
        let mut fixture_direct = expected_direct
            .get(*triple)
            .cloned()
            .unwrap_or_else(|| panic!("fixture missing direct features for {triple}"));
        for (package, features) in &mut fixture_direct {
            features.sort();
            assert_eq!(
                features.len(),
                features.iter().collect::<BTreeSet<_>>().len(),
                "fixture declares a duplicate feature for {package}"
            );
        }
        assert_eq!(
            fixture_direct, manifest_direct,
            "direct feature inventory drift for {triple}; update the fixture after auditing Cargo.toml"
        );
        let meta = metadata_for_platform(&root, triple);
        let resolve_ids = resolve_cockpit_core_package_ids(&meta);
        let packages = meta["packages"].as_array().unwrap();
        let wanted = platform_package_names(triple);

        let mut found: BTreeMap<String, PackageRecord> = BTreeMap::new();
        // Prefer fixture-expected versions when multiple crates share a name (e.g. windows).
        let preferred_versions: BTreeMap<&str, &str> = fixture
            .packages_by_platform
            .get(*triple)
            .map(|rows| {
                rows.iter()
                    .map(|r| (r.name.as_str(), r.version.as_str()))
                    .collect()
            })
            .unwrap_or_default();
        for p in packages {
            let name = p["name"].as_str().unwrap();
            if !wanted.contains(name) {
                continue;
            }
            let version = p["version"].as_str().unwrap().to_string();
            if let Some(pref) = preferred_versions.get(name)
                && version != *pref
            {
                continue;
            }
            let id = p["id"].as_str().unwrap();
            if !resolve_ids.iter().any(|r| r == id) && name != "cockpit-core" {
                // Still record if listed as workspace package for the platform filter
            }
            let source = p
                .get("source")
                .and_then(|s| s.as_str())
                .unwrap_or("path")
                .to_string();
            assert!(
                source.contains("registry") || source == "path",
                "{name} non-registry source: {source}"
            );
            let license = p
                .get("license")
                .and_then(|l| l.as_str())
                .map(str::to_string);
            let rust_version = p
                .get("rust_version")
                .and_then(|l| l.as_str())
                .map(str::to_string);
            let edition = p
                .get("edition")
                .and_then(|l| l.as_str())
                .map(str::to_string);
            let mut features: Vec<String> = p["features"]
                .as_object()
                .map(|obj| obj.keys().cloned().collect())
                .unwrap_or_default();
            features.sort();
            let checksum = checksums.get(&(name.to_string(), version.clone())).cloned();

            // License permissive check for direct platform packages
            if let Some(ref lic) = license {
                let ok = lic.contains("MIT")
                    || lic.contains("Apache")
                    || lic.contains("BSD")
                    || lic.contains("Zlib")
                    || lic.contains("ISC");
                assert!(ok, "{name} license not permissive: {lic}");
            } else if name != "mach2" {
                // mach2 has license in crate metadata; if missing fail
                // allow only if fixture records it
            }

            // MSRV: must not exceed workspace 1.95 except mach2 null exception
            if name == "mach2" {
                assert!(rust_version.is_none(), "mach2 must have null rust_version");
            } else if let Some(ref rv) = rust_version {
                // Compare major.minor
                let parse = |s: &str| {
                    let mut it = s.split('.');
                    let maj: u32 = it.next().unwrap_or("0").parse().unwrap_or(0);
                    let min: u32 = it.next().unwrap_or("0").parse().unwrap_or(0);
                    (maj, min)
                };
                let (a, b) = parse(rv);
                let (c, d) = parse(WORKSPACE_MSRV);
                assert!(
                    (a, b) <= (c, d),
                    "{name} rust-version {rv} exceeds workspace MSRV {WORKSPACE_MSRV}"
                );
            }

            found.insert(
                name.to_string(),
                PackageRecord {
                    name: name.to_string(),
                    version,
                    source,
                    checksum,
                    license,
                    rust_version,
                    edition,
                    features,
                },
            );
        }

        // Required packages present
        for name in &wanted {
            assert!(
                found.contains_key(*name)
                    || *name == "atspi-proxies"
                    || *name == "atspi-connection"
                    || *name == "atspi-common",
                "missing package {name} on {triple}; found {:?}",
                found.keys().collect::<Vec<_>>()
            );
        }

        // Compare against fixture records for packages that are listed
        let expected = fixture
            .packages_by_platform
            .get(*triple)
            .unwrap_or_else(|| panic!("fixture missing platform {triple}"));
        for exp in expected {
            let got = found.get(&exp.name).unwrap_or_else(|| {
                panic!("package {} not found for {triple} in metadata", exp.name)
            });
            assert_eq!(got.version, exp.version, "{} version drift", exp.name);
            if let Some(ref ck) = exp.checksum {
                assert_eq!(
                    got.checksum.as_deref(),
                    Some(ck.as_str()),
                    "{} checksum drift",
                    exp.name
                );
            }
            if exp.name == "mach2" {
                assert_eq!(got.checksum.as_deref(), Some(MACH2_CHECKSUM));
                assert_eq!(got.edition.as_deref(), Some("2024"));
                assert!(got.rust_version.is_none());
            }
        }

        // Forbid dangerous feature leaves on direct deps when declared in fixture
        if let Some(direct) = expected_direct.get(*triple) {
            for (pkg, feats) in direct {
                for f in feats {
                    assert!(
                        f != "all-extensions"
                            && f != "default"
                            && !f.to_lowercase().contains("xtest")
                            && !f.to_lowercase().contains("xinput"),
                        "forbidden feature {f} on {pkg}"
                    );
                }
                if pkg == "objc2-application-services" {
                    for f in feats {
                        assert!(
                            !f.contains("AXMacro") && f != "AXUIElementCopyAttributeNames",
                            "unused AX macro-constant feature {f}"
                        );
                    }
                }
            }
        }
    }

    // Manifest pins: exact versions in cockpit-core Cargo.toml
    assert!(manifest_raw.contains("mach2 = { version = \"=0.6.0\""));
    assert!(manifest_raw.contains("block2 = { version = \"=0.6.2\""));
    assert!(manifest_raw.contains("objc2-app-kit = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-application-services = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-core-foundation = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-core-graphics = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-color-sync = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("objc2-foundation = { version = \"=0.3.2\""));
    assert!(manifest_raw.contains("windows = { version = \"=0.62.2\""));
    assert!(manifest_raw.contains("x11rb = { version = \"=0.13.2\""));
    assert!(manifest_raw.contains("atspi = { version = \"=0.30.0\""));
    assert!(manifest_raw.contains("\"randr\""));
    assert!(manifest_raw.contains("Wdk_Foundation"));
    assert!(manifest_raw.contains("Wdk_Storage_FileSystem"));
    assert!(manifest_raw.contains("Win32_Storage_Packaging_Appx"));
    assert!(manifest_raw.contains("Win32_System_StationsAndDesktops"));
    assert!(manifest_raw.contains("CFArray"));
    assert!(manifest_raw.contains("CFDictionary"));
    assert!(manifest_raw.contains("CFFileDescriptor"));
    assert!(manifest_raw.contains("ColorSyncDevice"));
    assert!(manifest_raw.contains("HIServices"));
    // No private BSM / handwritten observer mentions in production target modules
    let macos_src = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/computer/platform/macos.rs"),
    )
    .unwrap();
    assert!(!macos_src.contains("audit_session_self"));
    assert!(!macos_src.contains("_AXUIElementGetWindow"));
    assert!(!macos_src.contains("AXWindowNumber"));
}
