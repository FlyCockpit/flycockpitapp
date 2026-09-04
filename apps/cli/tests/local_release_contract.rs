//! Source-level contract for the default local-v0.1 release profile.
//!
//! This intentionally complements behavioral tests: it fails before packaging
//! if a remote dependency, command, daemon worker, protocol module, or release
//! workflow becomes reachable without the single `remote` feature.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

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

/// Job body in `.github/workflows/cli-ci.yml` bounded by the next job name.
/// A file-wide substring is not a job binding: relocating a step, wrapping it
/// in `echo`, or parking it on a `workflow_dispatch` job stays green unless
/// the assertion is against this slice.
fn cli_ci_job<'a>(ci: &'a str, name: &str, next: &str) -> &'a str {
    ci.split(&format!("\n  {name}:\n"))
        .nth(1)
        .and_then(|rest| rest.split(&format!("\n  {next}:\n")).next())
        .unwrap_or_else(|| {
            panic!("cli-ci.yml must contain job `{name}` immediately before `{next}`")
        })
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
fn feature_gated_tests_are_mapped_to_executing_gates() {
    let ci = source(".github/workflows/cli-ci.yml");
    let gates = cli_ci_job(&ci, "gates", "supply-chain");
    assert!(
        gates
            .lines()
            .any(|line| line.trim() == "run: bash scripts/check-feature-gated-test-coverage.sh"),
        "gates must run the coverage ratchet as an unconditional `run:` step"
    );
    assert!(
        !gates.contains("continue-on-error:"),
        "gates must fail the PR/push gate"
    );
    assert!(
        !gates.contains("workflow_dispatch"),
        "gates must not be a manual opt-in"
    );
    assert!(
        gates.contains("--no-default-features"),
        "the default local gate must stay local-only"
    );
    let lockstep = cli_ci_job(&ci, "remote-lockstep", "daemon-custody-pkcs11-softhsm");
    assert!(
        !lockstep.contains("continue-on-error:"),
        "remote lockstep must fail the PR/push gate"
    );
    assert!(
        !lockstep.contains("workflow_dispatch"),
        "remote lockstep must not be a manual opt-in"
    );
    assert!(lockstep.contains("cargo nextest run --locked"));
    assert!(
        lockstep.lines().any(|line| {
            line.trim() == "run: bash scripts/check-tenant-authority-acceptance-manifest.sh"
        }),
        "remote-lockstep must run the tenant-authority acceptance-manifest ratchet as an unconditional `run:` step"
    );
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
    assert!(policy.contains("Cargo features form a graph"));
    assert!(policy.contains("reaches_grok_subscription"));
    assert!(policy.contains("grok-subscription"));
}

fn feature_policy_fixture(
    core_default_features: &str,
    cli_dependency_features: &str,
) -> tempfile::TempDir {
    let fixture = tempfile::tempdir().expect("creating feature-policy fixture");
    let root = fixture.path();
    fs::create_dir_all(root.join("scripts")).expect("creating fixture script directory");
    fs::create_dir_all(root.join("apps/cli/src")).expect("creating fixture CLI source directory");
    fs::create_dir_all(root.join("crates/cockpit-core/src"))
        .expect("creating fixture core source directory");

    fs::write(
        root.join("Cargo.toml"),
        r#"[workspace]
members = ["apps/cli", "crates/cockpit-core"]
resolver = "3"
"#,
    )
    .expect("writing fixture workspace manifest");
    fs::write(root.join("apps/cli/src/lib.rs"), "").expect("writing fixture CLI source");
    fs::write(root.join("crates/cockpit-core/src/lib.rs"), "")
        .expect("writing fixture core source");
    fs::write(
        root.join("apps/cli/Cargo.toml"),
        format!(
            r#"[package]
name = "cockpit-cli"
version = "0.1.0"
edition = "2024"

[dependencies]
cockpit-core = {{ path = "../../crates/cockpit-core", default-features = false, features = [{cli_dependency_features}] }}
"#,
        ),
    )
    .expect("writing fixture CLI manifest");
    fs::write(
        root.join("crates/cockpit-core/Cargo.toml"),
        format!(
            r#"[package]
name = "cockpit-core"
version = "0.1.0"
edition = "2024"

[features]
default = [{core_default_features}]
release-grok = ["intermediate-grok"]
intermediate-grok = ["grok-subscription"]
grok-subscription = []
"#,
        ),
    )
    .expect("writing fixture core manifest");
    fs::copy(
        repo_root().join("scripts/check-official-release-feature-policy.sh"),
        root.join("scripts/check-official-release-feature-policy.sh"),
    )
    .expect("copying release feature policy into fixture");

    let lockfile = Command::new("cargo")
        .arg("generate-lockfile")
        .current_dir(root)
        .status()
        .expect("generating fixture lockfile");
    assert!(lockfile.success(), "generating fixture lockfile failed");
    fixture
}

#[test]
fn official_release_feature_policy_rejects_transitive_grok_subscription_aliases() {
    for (description, core_default_features, cli_dependency_features, expected_failure) in [
        (
            "default feature alias chain",
            "\"release-grok\"",
            "",
            Some("cockpit-core: default feature declaration enables grok-subscription"),
        ),
        (
            "dependency feature alias chain",
            "",
            "\"release-grok\"",
            Some(
                "cockpit-cli: dependency feature declaration for cockpit-core enables grok-subscription",
            ),
        ),
        ("manifest with no grok feature root", "", "", None),
    ] {
        let fixture = feature_policy_fixture(core_default_features, cli_dependency_features);
        let output = Command::new("bash")
            .arg(
                fixture
                    .path()
                    .join("scripts/check-official-release-feature-policy.sh"),
            )
            .current_dir(fixture.path())
            .output()
            .expect("running copied release feature policy");
        let stderr = String::from_utf8_lossy(&output.stderr);
        match expected_failure {
            Some(expected) => {
                assert!(
                    !output.status.success(),
                    "the policy accepted a {description}: stderr={stderr}"
                );
                assert!(
                    stderr.contains(expected),
                    "the policy did not identify the {description}: stderr={stderr}"
                );
            }
            None => assert!(
                output.status.success(),
                "the policy rejected a {description}: stderr={stderr}"
            ),
        }
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
