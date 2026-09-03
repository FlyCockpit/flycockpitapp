use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("cockpit-client must remain under crates/")
        .to_path_buf()
}

#[test]
fn client_manifest_stays_below_application_and_storage_layers() {
    let manifest = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
        .expect("read cockpit-client manifest");
    let mut section = "";
    let mut local_dependencies = BTreeSet::new();
    for line in manifest.lines() {
        let line = line.trim();
        if line.starts_with('[') && line.ends_with(']') {
            section = line;
            continue;
        }
        if section != "[dependencies]" || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, specification)) = line.split_once('=') else {
            continue;
        };
        if specification.contains("path =") {
            local_dependencies.insert(name.trim());
        }
    }
    assert_eq!(
        local_dependencies,
        BTreeSet::from(["cockpit-host", "cockpit-proto"]),
        "cockpit-client production workspace dependencies must be exactly cockpit-host and cockpit-proto"
    );

    let feature_mappings = manifest
        .split_once("[features]")
        .and_then(|(_, rest)| rest.split_once("[dependencies]"))
        .map(|(features, _)| {
            features
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .collect::<BTreeSet<_>>()
        })
        .expect("features must precede normal dependencies");
    assert_eq!(
        feature_mappings,
        BTreeSet::from([
            "default = []",
            "extended = [\"cockpit-proto/extended\"]",
            "remote = [\"cockpit-proto/remote\"]",
            "test-support = []",
        ]),
        "client feature mappings must be exact"
    );
}

#[test]
fn connection_counter_instrumentation_is_feature_gated() {
    let root = workspace_root();
    let manifest = fs::read_to_string(root.join("crates/cockpit-client/Cargo.toml"))
        .expect("read cockpit-client manifest");
    assert!(
        manifest.contains("default = []"),
        "production client defaults must remain feature-free"
    );
    assert!(
        manifest.contains("test-support = []"),
        "test instrumentation must have an explicit feature"
    );

    let source = fs::read_to_string(root.join("crates/cockpit-client/src/lib.rs"))
        .expect("read cockpit-client source");
    for symbol in [
        "static CONNECT_CALLS",
        "pub fn reset_connect_call_count",
        "pub fn connect_call_count",
    ] {
        let offset = source.find(symbol).expect("connection counter symbol");
        let prefix = &source[..offset];
        let cfg = prefix
            .rfind("#[cfg(feature = \"test-support\")]")
            .expect("test-support cfg before instrumentation symbol");
        let intervening = &prefix[cfg..];
        assert!(
            intervening.lines().count() <= 3,
            "{symbol} must be directly guarded by test-support"
        );
    }

    let connect = source
        .find("CONNECT_CALLS.with(|calls| calls.set(calls.get() + 1))")
        .expect("connect counter increment");
    let prefix = &source[..connect];
    let cfg = prefix
        .rfind("#[cfg(feature = \"test-support\")]")
        .expect("test-support cfg before increment");
    assert!(
        prefix[cfg..].lines().count() <= 3,
        "the production connect hot path must not include test instrumentation"
    );

    let tui_manifest = fs::read_to_string(root.join("crates/cockpit-tui/Cargo.toml"))
        .expect("read cockpit-tui manifest");
    let production = tui_manifest
        .split_once("[dev-dependencies]")
        .expect("TUI dev-dependencies section")
        .0;
    assert!(
        !production.contains("cockpit-client/test-support")
            && !production.lines().any(|line| {
                line.starts_with("cockpit-client") && line.contains("test-support")
            }),
        "TUI production dependency must not enable client test instrumentation"
    );
}

#[test]
fn core_does_not_reimplement_or_reexport_daemon_transport() {
    let root = workspace_root();
    let lifecycle = fs::read_to_string(root.join("crates/cockpit-core/src/daemon/client.rs"))
        .expect("read core daemon lifecycle module");
    for forbidden in [
        "pub struct DaemonClient",
        "impl DaemonClient",
        "ProtoStream",
        "fn negotiate_hello",
        "fn run_io",
        "pub use cockpit_client",
    ] {
        assert!(
            !lifecycle.contains(forbidden),
            "core daemon lifecycle must not own or re-export client transport: {forbidden}"
        );
    }

    let core_lib = fs::read_to_string(root.join("crates/cockpit-core/src/lib.rs"))
        .expect("read cockpit-core lib");
    assert!(
        !core_lib.contains("pub use cockpit_client"),
        "cockpit-core must not re-export cockpit-client"
    );
}

#[test]
fn tui_uses_client_transport_directly() {
    let tui_src = workspace_root().join("crates/cockpit-tui/src");
    let mut pending = vec![tui_src];
    while let Some(path) = pending.pop() {
        for entry in fs::read_dir(path).expect("read TUI source directory") {
            let entry = entry.expect("read TUI source entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = fs::read_to_string(&path).expect("read TUI Rust source");
                assert!(
                    !source.contains("cockpit_core::daemon::client::DaemonClient"),
                    "{} reaches client transport through cockpit-core",
                    path.display()
                );
                assert!(
                    !source.contains("daemon::client::{DaemonClient"),
                    "{} imports client transport through a lifecycle module",
                    path.display()
                );
            }
        }
    }
}
