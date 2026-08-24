//! Source-level contract for the default local-v0.1 release profile.
//!
//! This intentionally complements behavioral tests: it fails before packaging
//! if a remote dependency, command, daemon worker, protocol module, or release
//! workflow becomes reachable without the single `remote` feature.

use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("apps/cli must live two levels below the repository root")
        .to_path_buf()
}

fn source(relative: &str) -> String {
    std::fs::read_to_string(repo_root().join(relative))
        .unwrap_or_else(|error| panic!("reading {relative}: {error}"))
}

#[test]
fn local_release_has_one_opt_in_remote_capability() {
    for manifest in [
        "apps/cli/Cargo.toml",
        "crates/cockpit-core/Cargo.toml",
        "crates/cockpit-proto/Cargo.toml",
        "crates/cockpit-db/Cargo.toml",
    ] {
        let parsed: toml::Value = toml::from_str(&source(manifest))
            .unwrap_or_else(|error| panic!("parsing {manifest}: {error}"));
        let features = parsed["features"]
            .as_table()
            .unwrap_or_else(|| panic!("{manifest} must declare [features]"));
        assert_eq!(features["default"].as_array().map(Vec::len), Some(0));
        assert!(
            features.contains_key("remote"),
            "{manifest} lacks remote feature"
        );
    }

    let cli: toml::Value = toml::from_str(&source("apps/cli/Cargo.toml")).unwrap();
    for dependency in ["tokio-tungstenite", "flycockpit-relay-protocol"] {
        assert_eq!(
            cli["dependencies"][dependency]["optional"].as_bool(),
            Some(true),
            "{dependency} must not enter the default binary graph"
        );
    }
}

#[test]
fn local_release_cfg_gates_commands_modules_workers_and_protocol() {
    let cli = source("apps/cli/src/cli.rs");
    for command in ["Account", "Sync", "Connect"] {
        let offset = cli
            .find(&format!("    {command}"))
            .unwrap_or_else(|| panic!("missing {command} command"));
        let prefix = &cli[offset.saturating_sub(160)..offset];
        assert!(
            prefix.contains("#[cfg(feature = \"remote\")]"),
            "{command} is not feature gated"
        );
    }

    let daemon = source("crates/cockpit-core/src/daemon/mod.rs");
    for module in ["connector", "remote_attempt", "remote_audit_upload"] {
        let marker = format!("#[cfg(feature = \"remote\")]\npub mod {module};");
        assert!(
            daemon.contains(&marker),
            "daemon module {module} is reachable locally"
        );
    }
    for worker in [
        "org_sync::spawn_background",
        "remote_audit_upload::spawn_background",
        "connector::spawn_background",
        "remote_outbox_worker::spawn_background",
    ] {
        let offset = daemon
            .find(worker)
            .unwrap_or_else(|| panic!("missing worker {worker}"));
        let prefix = &daemon[offset.saturating_sub(80)..offset];
        assert!(prefix.contains("#[cfg(feature = \"remote\")]"));
    }

    let protocol = source("crates/cockpit-proto/src/lib.rs");
    for module in [
        "remote_connection_metadata",
        "remote_device_identity_enrollment",
        "remote_enterprise_connection_policy",
        "remote_ip_consent",
        "remote_protocol_id",
        "remote_session_continuity",
        "remote_signaling_attempt_store",
        "remote_tenant_authority_protocol",
        "remote_transport",
        "remote_transport_selection",
        "remote_turn_ice_policy",
        "remote_wire_magic_registry",
    ] {
        let marker = format!("#[cfg(feature = \"remote\")]\npub mod {module};");
        assert!(
            protocol.contains(&marker),
            "protocol module {module} is reachable locally"
        );
    }
    let dispatch = source("crates/cockpit-core/src/daemon/server/dispatch.rs");
    assert!(!dispatch.contains("requires_remote_feature"));
}

#[test]
fn remote_conformance_is_opt_in_and_release_declares_local_profile() {
    let ci = source(".github/workflows/cli-ci.yml");
    assert!(ci.contains("remote_conformance:"));
    assert_eq!(
        ci.matches("if: github.event_name == 'workflow_dispatch' && inputs.remote_conformance")
            .count(),
        3
    );
    let release = source(".github/workflows/release.yml");
    assert!(release.contains("FLYCOCKPIT_RELEASE_PROFILE: local-v0.1"));
}
