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
    ] {
        assert!(
            !lib.contains(forbidden),
            "cockpit-core must not shim moved host authority: {forbidden}"
        );
    }
    let mut pending = vec![core];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("read core source directory") {
            let path = entry.expect("core source entry").path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                let source = std::fs::read_to_string(&path).expect("read core production source");
                assert!(
                    !source.contains("pub use cockpit_host"),
                    "cockpit-core production source must not re-export host authority: {}",
                    path.display()
                );
            }
        }
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
        "libc::kill(pid as libc::pid_t, libc::SIGTERM)",
        "remove_metadata_if_pid_matches",
    ] {
        assert!(
            !daemon.contains(forbidden),
            "daemon lifecycle host primitive leaked back into core: {forbidden}"
        );
    }
    let host = std::fs::read_to_string(
        workspace_root().join("crates/cockpit-host/src/daemon_lifecycle.rs"),
    )
    .expect("read host daemon lifecycle");
    for required in [
        "struct DaemonPidReceipt",
        "fn read_daemon_pid_record",
        "cockpit-daemon-pid-v2",
        "unix-bytes:",
        "windows-utf16le:",
        "struct ProcessStartIdentity",
        "publication_nonce: [u8; 32]",
        "struct SerializedDaemonPidReceipt",
        "write_private_file_exclusive",
        "fn read_process_start_identity",
        "offset_of!(ProcBsdInfo, start_sec) == 120",
        "let error = (ok == 0).then(std::io::Error::last_os_error)",
        "with_lifecycle_lock",
        "retire_metadata_if_receipt_matches",
        "SYS_pidfd_open",
        "SYS_pidfd_send_signal",
        "pub fn is_alive(&self) -> std::io::Result<bool>",
    ] {
        assert!(
            host.contains(required),
            "stable receipt-bound lifecycle primitive is missing: {required}"
        );
    }
    for required in [
        "fn read_bound_endpoint_record_from",
        "record.socket != canonical.socket",
        "DaemonPidRecord::Receipt(receipt)",
        "preserving metadata and refusing numeric signaling",
    ] {
        assert!(
            daemon.contains(required),
            "daemon endpoint/stop fail-closed contract is missing: {required}"
        );
    }
}
