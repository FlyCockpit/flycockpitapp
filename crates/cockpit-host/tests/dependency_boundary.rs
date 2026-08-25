use std::path::PathBuf;

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("cockpit-host must remain under crates/")
        .to_path_buf()
}

#[test]
fn host_is_a_workspace_dependency_leaf() {
    let manifest =
        std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read cockpit-host manifest");
    for forbidden in [
        "cockpit-core",
        "cockpit-config",
        "cockpit-db",
        "cockpit-proto",
        "cockpit-tui",
        "relay-protocol",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "cockpit-host must not depend on {forbidden}"
        );
    }
}

#[test]
fn core_does_not_reexport_moved_host_authority() {
    let core = workspace_root().join("crates/cockpit-core/src");
    for module in [
        "goal_scratch.rs",
        "path_containment.rs",
        "private_fs.rs",
        "process.rs",
    ] {
        assert!(
            !core.join(module).exists(),
            "moved host authority must not remain in cockpit-core: {module}"
        );
    }
    let lib = std::fs::read_to_string(core.join("lib.rs")).expect("read cockpit-core lib.rs");
    for forbidden in [
        "pub mod goal_scratch",
        "pub mod path_containment",
        "pub mod private_fs",
        "pub mod process",
        "pub use cockpit_host",
    ] {
        assert!(
            !lib.contains(forbidden),
            "cockpit-core must not shim moved host authority: {forbidden}"
        );
    }
}

#[test]
fn daemon_pid_and_metadata_guard_live_only_in_host() {
    let daemon =
        std::fs::read_to_string(workspace_root().join("crates/cockpit-core/src/daemon/mod.rs"))
            .expect("read daemon module");
    for forbidden in [
        "struct ForegroundMetadataGuard",
        "enum PidIdentity",
        "fn verify_daemon_pid_identity",
        "fn read_process_cmdline",
        "fn process_exists",
    ] {
        assert!(
            !daemon.contains(forbidden),
            "daemon lifecycle host primitive leaked back into core: {forbidden}"
        );
    }
}
