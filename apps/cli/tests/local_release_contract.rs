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

fn enables_grok_subscription(value: &str) -> bool {
    let value = value.strip_prefix("dep:").unwrap_or(value);
    let value = value.strip_suffix('?').unwrap_or(value);
    value == "grok-subscription" || value.ends_with("/grok-subscription")
}

fn dependency_enables_grok_subscription(value: &toml::Value) -> bool {
    let Some(table) = value.as_table() else {
        return false;
    };

    for (key, child) in table {
        if matches!(
            key.as_str(),
            "dependencies" | "build-dependencies" | "dev-dependencies"
        ) && child.as_table().is_some_and(|dependencies| {
            dependencies.values().any(|specification| {
                specification
                    .as_table()
                    .and_then(|specification| specification.get("features"))
                    .and_then(toml::Value::as_array)
                    .is_some_and(|features| {
                        features
                            .iter()
                            .filter_map(toml::Value::as_str)
                            .any(enables_grok_subscription)
                    })
            })
        }) {
            return true;
        }
        if dependency_enables_grok_subscription(child) {
            return true;
        }
    }
    false
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
    assert!(!ci.contains("remote-workspace-static:"));
    assert_eq!(
        ci.matches("if: github.event_name == 'workflow_dispatch' && inputs.remote_conformance")
            .count(),
        2,
        "the two external-service remote conformance jobs must remain manual opt-ins"
    );
    let remote = source(".github/workflows/remote-profile-checks.yml");
    assert!(remote.contains("schedule:"));
    assert!(remote.contains("workflow_dispatch:"));
    assert!(remote.contains("continue-on-error: true"));
    assert!(remote.contains("cargo check --locked -p cockpit-cli --all-targets --features remote"));
    let release = source(".github/workflows/release.yml");
    assert!(release.contains("FLYCOCKPIT_RELEASE_PROFILE: local-v0.1"));
}

#[test]
fn official_release_never_enables_optional_cargo_features() {
    let release = source(".github/workflows/release.yml");
    let policy = source("scripts/check-official-release-feature-policy.sh");
    assert!(release.contains("bash scripts/check-official-release-feature-policy.sh"));
    assert!(release.contains("[ \"$default_features\" != \"[]\" ]"));
    assert!(release.contains("official release default features must be empty"));
    assert!(release.contains("(--all-features|--features|-F)"));
    assert!(release.contains("cockpit-cli/(remote|grok-subscription)"));
    assert_eq!(release.matches("CARGO_ENCODED_RUSTFLAGS: \"\"").count(), 4);
    assert_eq!(release.matches("CARGO_BUILD_RUSTFLAGS: \"\"").count(), 4);
    assert_eq!(release.matches("\n          RUSTFLAGS: \"\"").count(), 4);
    assert_eq!(release.matches("CARGO_TARGET_*_RUSTFLAGS").count(), 4);
    assert!(policy.contains("dependency feature declaration"));
    assert!(policy.contains("default feature declaration"));
    assert!(policy.contains("Cargo config"));
    assert!(policy.contains("grok-subscription"));
}

#[test]
fn official_release_manifest_graph_cannot_unify_grok_subscription() {
    let workspace: toml::Value = toml::from_str(&source("Cargo.toml")).unwrap();
    for member in workspace["workspace"]["members"]
        .as_array()
        .expect("workspace members")
    {
        let manifest = format!(
            "{}/Cargo.toml",
            member.as_str().expect("workspace member path")
        );
        let parsed: toml::Value = toml::from_str(&source(&manifest))
            .unwrap_or_else(|error| panic!("parsing {manifest}: {error}"));
        let mut default_features = parsed
            .get("features")
            .and_then(toml::Value::as_table)
            .and_then(|features| features.get("default"))
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str);
        assert!(
            !default_features.any(enables_grok_subscription),
            "{manifest} default features activate grok-subscription"
        );
        assert!(
            !dependency_enables_grok_subscription(&parsed),
            "{manifest} activates grok-subscription through a dependency feature"
        );
    }
}

#[test]
fn public_v0_1_allowlist_is_exact_and_single_source() {
    let fixture: serde_json::Value = serde_json::from_str(&source(
        "apps/cli/tests/fixtures/public-v0.1-command-snapshot.json",
    ))
    .unwrap();
    let expected = fixture["commands"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    let command = cockpit_cli::public_v0_1_command();
    let actual = command
        .get_subcommands()
        .flat_map(|subcommand| {
            std::iter::once(subcommand.get_name().to_owned()).chain(
                subcommand
                    .get_all_aliases()
                    .map(str::to_owned)
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn local_release_outbound_network_inventory_is_fail_closed() {
    let acceptance = source("apps/cli/tests/e2e/local_offline_acceptance.rs");
    for required in [
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "assert_no_network_attempt",
    ] {
        assert!(
            acceptance.contains(required),
            "missing network ratchet {required}"
        );
    }
    let daemon = source("crates/cockpit-core/src/daemon/mod.rs");
    assert!(daemon.contains("#[cfg(feature = \"remote\")]\npub mod connector;"));
    let connector = source("crates/cockpit-core/src/daemon/connector.rs");
    assert!(connector.contains("connect_async(request)"));
}

#[test]
fn generated_local_profile_inventory_is_bound_to_sources() {
    let inventory: serde_json::Value =
        serde_json::from_str(&source("apps/cli/release/local-profile-inventory-v1.json")).unwrap();
    assert_eq!(inventory["profile"], "local-v0.1");
    let daemon = source("crates/cockpit-core/src/daemon/mod.rs");
    for worker in inventory["remoteDaemonWorkers"].as_array().unwrap() {
        let worker = worker.as_str().unwrap();
        let marker = format!("{worker}::spawn_background");
        let offset = daemon
            .find(&marker)
            .unwrap_or_else(|| panic!("missing {marker}"));
        assert!(daemon[offset.saturating_sub(100)..offset].contains("feature = \"remote\""));
    }
    let protocol = source("crates/cockpit-proto/src/request.rs");
    let expected_remote_tags = protocol
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            if line.trim() != "#[cfg(feature = \"remote\")]" {
                return None;
            }
            protocol.lines().nth(index + 1).and_then(|variant| {
                let variant = variant.trim();
                let end = variant.find([' ', '{', ','])?;
                let name = &variant[..end];
                if name.contains("::") {
                    return None;
                }
                name.chars().next()?.is_ascii_uppercase().then(|| {
                    name.chars()
                        .enumerate()
                        .flat_map(|(offset, ch)| {
                            (ch.is_ascii_uppercase() && offset > 0)
                                .then_some('_')
                                .into_iter()
                                .chain(std::iter::once(ch.to_ascii_lowercase()))
                        })
                        .collect::<String>()
                })
            })
        })
        .collect::<std::collections::BTreeSet<_>>();
    let inventoried_tags = inventory["localProtocolTagDenylist"]
        .as_array()
        .unwrap()
        .iter()
        .map(|tag| tag.as_str().unwrap().to_owned())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(inventoried_tags, expected_remote_tags);
    for tag in inventory["localProtocolTagDenylist"].as_array().unwrap() {
        let tag = format!("\"{}\"", tag.as_str().unwrap());
        let offset = protocol
            .find(&tag)
            .unwrap_or_else(|| panic!("missing {tag}"));
        assert!(protocol[offset.saturating_sub(180)..offset].contains("feature = \"remote\""));
    }
    let db = source("crates/cockpit-db/src/db/mod.rs");
    assert!(db.contains("extension_sql: \"\""));
    assert!(db.contains(inventory["remoteSchemaExtension"].as_str().unwrap()));
}
