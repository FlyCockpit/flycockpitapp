//! Dependency audit for the TURN socket provider's pinned client crates.
//!
//! Non-tautological: expected versions/checksums/licenses are independent
//! literals recorded here; the test reads the real `Cargo.lock` and
//! `cargo metadata --locked --offline` and fails on any drift. It proves exact
//! pins + checksums for `turn-client-proto` / `turn-client-rustls` /
//! `rustls-native-certs`, MIT-OR-Apache licensing, registry provenance, the
//! `default-features = false` + `["std"]`-only manifest (so the optional
//! `openssl` feature stays off), and that no alternate TURN/WebRTC/TLS stack is
//! pulled as a direct dependency.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// (name, expected version, expected crates.io checksum) — independent
/// literals, NOT derived from the lock at runtime.
const EXPECTED: &[(&str, &str, &str)] = &[
    (
        "turn-client-proto",
        "0.7.1",
        "3cecb85f46bc0d695711183cdd36be9fd7fd30232f46235c0525276fe14093f2",
    ),
    (
        "turn-client-rustls",
        "0.1.0",
        "9759ad9615c5738e7e1a314204b5722ff9a545d23e09f0f2ff0c5c6f38c47da8",
    ),
    (
        "rustls-native-certs",
        "0.8.4",
        "dab5152771c58876a2146916e53e35057e1a4dfa2b9df0f0305b07f611fdea4d",
    ),
    // Transitive support crates pinned through the client crates.
    (
        "turn-types",
        "0.7.2",
        "b219ecb1e95783c98ff2819d51e95ef54dad78ae438be7ffa490d6480a3df0de",
    ),
    (
        "stun-proto",
        "2.0.2",
        "d93b223082474c3952d14cbea5b2d5356e913f6253e6b0e0659199149c483058",
    ),
];

const WORKSPACE_MSRV: (u32, u32) = (1, 95);

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

/// (name, version) -> checksum from Cargo.lock.
fn lock_checksums(root: &Path) -> BTreeMap<(String, String), String> {
    let lock = std::fs::read_to_string(root.join("Cargo.lock")).expect("Cargo.lock");
    let mut map = BTreeMap::new();
    let (mut name, mut version) = (None, None);
    for line in lock.lines() {
        if line.starts_with("[[package]]") {
            name = None;
            version = None;
        } else if let Some(rest) = line.strip_prefix("name = \"") {
            name = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = \"") {
            version = Some(rest.trim_end_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("checksum = \"")
            && let (Some(n), Some(v)) = (name.clone(), version.clone())
        {
            map.insert((n, v), rest.trim_end_matches('"').to_string());
        }
    }
    map
}

#[test]
fn remote_turn_socket_provider_dependency_audit() {
    let root = workspace_root();

    // 1. Exact versions + checksums against the real lock.
    let checksums = lock_checksums(&root);
    for (name, version, checksum) in EXPECTED {
        let got = checksums
            .get(&(name.to_string(), version.to_string()))
            .unwrap_or_else(|| panic!("{name} {version} not resolved in Cargo.lock"));
        assert_eq!(
            got, checksum,
            "{name} checksum drift (lock resolved a different artifact)"
        );
    }

    // 2. Manifest pins + features (defaults off, `std` only, no openssl).
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .unwrap();
    assert!(
        manifest.contains(
            "turn-client-proto = { version = \"=0.7.1\", default-features = false, features = [\"std\"] }"
        ),
        "turn-client-proto must be pinned =0.7.1 with default-features off + std only"
    );
    assert!(
        manifest.contains(
            "turn-client-rustls = { version = \"=0.1.0\", default-features = false, features = [\"std\"] }"
        ),
        "turn-client-rustls must be pinned =0.1.0 with default-features off + std only"
    );
    assert!(
        manifest
            .contains("rustls-native-certs = { version = \"=0.8.4\", default-features = false }"),
        "rustls-native-certs must be an exact =0.8.4 pin (no caret)"
    );
    // No openssl / native-tls / alternate TURN or WebRTC stack as a direct dep.
    for forbidden in [
        "turn-client-openssl",
        "turn-client-dimpl",
        "webrtc =",
        "webrtc-rs",
        "native-tls",
        "openssl =",
        "\nturn = ",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "forbidden alternate TURN/WebRTC/TLS stack in cockpit-core deps: {forbidden}"
        );
    }

    // 3. License + provenance + MSRV via cargo metadata (offline; CI pre-fetches).
    let out = Command::new(env!("CARGO"))
        .args(["metadata", "--locked", "--offline", "--format-version", "1"])
        .current_dir(&root)
        .output()
        .expect("cargo metadata");
    assert!(
        out.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: Value = serde_json::from_slice(&out.stdout).expect("metadata json");
    let packages = meta["packages"].as_array().expect("packages array");

    for (name, version, _) in EXPECTED {
        let pkg = packages
            .iter()
            .find(|p| p["name"] == *name && p["version"] == *version)
            .unwrap_or_else(|| panic!("{name} {version} missing from metadata"));

        let license = pkg["license"].as_str().unwrap_or("");
        assert!(
            license.contains("MIT") && license.contains("Apache"),
            "{name} license not MIT OR Apache-2.0: {license}"
        );
        let source = pkg["source"].as_str().unwrap_or("");
        assert!(
            source.contains("registry+https://github.com/rust-lang/crates.io-index"),
            "{name} not from crates.io registry: {source}"
        );
        if let Some(rv) = pkg["rust_version"].as_str() {
            let mut it = rv.split('.');
            let maj: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            let min: u32 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
            assert!(
                (maj, min) <= WORKSPACE_MSRV,
                "{name} rust-version {rv} exceeds workspace MSRV 1.95"
            );
        }
    }

    // 4. Resolved feature sets must be EXACTLY {std} (ignoring the `default`
    //    meta-feature, which only expands to std). This is stricter than
    //    "includes std / excludes openssl": a future feature-unification that
    //    silently enabled ANY extra leaf (openssl, a server feature, …) fails
    //    here. Independent expected literal `["std"]` vs cargo metadata.
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .expect("resolve.nodes array");
    let resolved_leaf_features = |crate_name: &str, version: &str| -> Vec<String> {
        // Resolve the exact package id, then find its node by id equality
        // (robust to the PackageId string format).
        let pkg_id = packages
            .iter()
            .find(|p| p["name"] == crate_name && p["version"] == version)
            .and_then(|p| p["id"].as_str())
            .unwrap_or_else(|| panic!("{crate_name} {version} missing from packages"));
        let node = nodes
            .iter()
            .find(|n| n["id"].as_str() == Some(pkg_id))
            .unwrap_or_else(|| panic!("{crate_name} missing from resolve.nodes"));
        let mut feats: Vec<String> = node["features"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|f| f.as_str())
                    // `default` only re-exports std here; ignore the meta-feature.
                    .filter(|f| *f != "default")
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        feats.sort();
        feats.dedup();
        feats
    };
    assert_eq!(
        resolved_leaf_features("turn-client-proto", "0.7.1"),
        vec!["std".to_string()],
        "turn-client-proto resolved features must be exactly {{std}} (no openssl/extra)"
    );
    assert_eq!(
        resolved_leaf_features("turn-client-rustls", "0.1.0"),
        vec!["std".to_string()],
        "turn-client-rustls resolved features must be exactly {{std}} (no extra default/feature)"
    );
}
