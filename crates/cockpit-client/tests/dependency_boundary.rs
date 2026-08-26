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
    for forbidden in [
        "cockpit-core",
        "cockpit-db",
        "cockpit-host",
        "cockpit-tui",
        "ratatui",
        "crossterm",
    ] {
        assert!(
            !manifest.lines().any(|line| {
                line.trim_start()
                    .strip_prefix(forbidden)
                    .is_some_and(|suffix| suffix.trim_start().starts_with('='))
            }),
            "cockpit-client must not depend on {forbidden}"
        );
    }
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
