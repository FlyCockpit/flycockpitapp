//! Gate tests for the workspace Clippy command authorities.
//!
//! The canonical final gate remains
//! `CARGO_TARGET_DIR=target cargo clippy --locked --tests -- -D warnings`.
//! Examples are a companion CI gate only:
//! `CARGO_TARGET_DIR=target cargo clippy --locked --workspace --examples -- -D warnings`.

use super::workspace_root;
use serde_json::Value;
use std::collections::BTreeSet;
use std::process::Command;

const CANONICAL_TESTS_CORE: &[&str] = &["--locked", "--tests", "--", "-D", "warnings"];
const EXAMPLES_COMPANION_ARGV: &str = "cargo clippy --locked --workspace --examples -- -D warnings";
const CLI_CI: &str = ".github/workflows/cli-ci.yml";
const RELEASE_PREFLIGHT: &str = ".github/workflows/release-preflight.yml";

fn read_workspace_file(rel: &str) -> String {
    let path = workspace_root().join(rel);
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!("read {}: {err}", path.display());
    })
}

/// Extract `cargo clippy ...` argv tokens from free-form docs/workflow text.
///
/// Each match is the token stream after `cargo clippy` through end-of-line
/// (YAML `run:` single-liners) or through a fenced code line.
fn clippy_invocations(source: &str) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for line in source.lines() {
        let trimmed = line.trim();
        // Skip pure comments.
        if trimmed.starts_with('#') {
            continue;
        }
        let Some(idx) = find_cargo_clippy(trimmed) else {
            continue;
        };
        let after = &trimmed[idx + "cargo clippy".len()..];
        let tokens = shellish_tokens(after);
        if !tokens.is_empty() {
            out.push(tokens);
        }
    }
    out
}

fn find_cargo_clippy(line: &str) -> Option<usize> {
    line.find("cargo clippy")
}

fn shellish_tokens(s: &str) -> Vec<String> {
    // Trim common prose/code-span wrappers that trail documented commands in
    // AGENTS.md / CONTRIBUTING.md (`... warnings` (test targets...)).
    let raw: Vec<String> = s
        .split_whitespace()
        .map(|t| {
            t.trim_matches(|c: char| matches!(c, '`' | ',' | '.' | ';' | ')' | '(' | '"' | '\''))
                .to_string()
        })
        .filter(|t| !t.is_empty())
        .collect();

    let mut out = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let t = &raw[i];
        if t == "--" {
            out.push(t.clone());
            i += 1;
            continue;
        }
        if t.starts_with('-') {
            out.push(t.clone());
            // Values for short/long options that take an argument.
            if (t == "-D" || t == "--target") && i + 1 < raw.len() {
                i += 1;
                out.push(raw[i].clone());
            }
            i += 1;
            continue;
        }
        // Once flags have started, a non-flag token is trailing prose.
        if !out.is_empty() {
            break;
        }
        i += 1;
    }
    out
}

fn is_tests_gate(tokens: &[String]) -> bool {
    tokens.iter().any(|t| t == "--tests")
        && !tokens.iter().any(|t| t == "--examples")
        && !tokens.iter().any(|t| t == "--all-targets")
}

fn is_examples_gate(tokens: &[String]) -> bool {
    tokens.iter().any(|t| t == "--examples")
        && !tokens.iter().any(|t| t == "--tests")
        && !tokens.iter().any(|t| t == "--all-targets")
}

/// Normalize a tests-gate argv to the authoritative core flag set.
///
/// Drops `--workspace` (implicit for a virtual workspace root) and any
/// `--target <triple>` pair so docs, Linux CI, and Windows CI compare equal.
/// Flag order is not significant (`--locked --tests` vs `--tests --locked`).
fn normalize_tests_core(tokens: &[String]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut i = 0;
    while i < tokens.len() {
        let t = &tokens[i];
        if t == "--workspace" {
            i += 1;
            continue;
        }
        if t == "--target" {
            i += 2; // skip triple
            continue;
        }
        if t.starts_with("--target=") {
            i += 1;
            continue;
        }
        out.insert(t.clone());
        i += 1;
    }
    out
}

fn authority_tests_cores(label: &str, source: &str) -> Vec<BTreeSet<String>> {
    let cores: Vec<BTreeSet<String>> = clippy_invocations(source)
        .into_iter()
        .filter(|toks| is_tests_gate(toks))
        .map(|toks| normalize_tests_core(&toks))
        .collect();
    assert!(
        !cores.is_empty(),
        "{label} must document/run a cargo clippy --tests gate"
    );
    cores
}

fn assert_core_is_canonical(label: &str, core: &BTreeSet<String>) {
    let expected: BTreeSet<String> = CANONICAL_TESTS_CORE
        .iter()
        .map(|s| (*s).to_string())
        .collect();
    assert_eq!(
        core,
        &expected,
        "{label}: canonical --tests clippy argv core must be exactly \
         `{}` (after dropping --workspace/--target); got `{}`",
        CANONICAL_TESTS_CORE.join(" "),
        core.iter().cloned().collect::<Vec<_>>().join(" ")
    );
}

fn workflow_has_env_cargo_target_dir(source: &str) -> bool {
    source.lines().any(|line| {
        let t = line.trim();
        t == "CARGO_TARGET_DIR: target"
            || t == "CARGO_TARGET_DIR: \"target\""
            || t == "CARGO_TARGET_DIR: 'target'"
    })
}

fn workflow_has_posix_inline_cargo_target_dir(source: &str) -> bool {
    // GitHub Actions env mapping uses `KEY: value`. POSIX inline assignment
    // uses `KEY=value` before a command — forbidden so Windows PowerShell
    // steps share the same argv + Actions env.
    source.lines().any(|line| {
        let t = line.trim();
        if t.starts_with('#') {
            return false;
        }
        t.contains("CARGO_TARGET_DIR=")
    })
}

fn workflow_rust_cache_maps_repo_root_target(source: &str) -> bool {
    // Swatinem/rust-cache workspaces mapping: `. -> target`
    source.lines().any(|line| {
        let t = line.trim().trim_matches('"').trim_matches('\'');
        t == "workspaces: . -> target"
            || t == ". -> target"
            || t.ends_with("workspaces: . -> target")
    })
}

fn workflow_has_non_root_working_directory(source: &str) -> bool {
    // Historical defect: defaults.run.working-directory: apps/cli (or any
    // step pinning Cargo under apps/cli). Both workflows must run at repo root.
    source.lines().any(|line| {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            return false;
        }
        if let Some(rest) = trimmed.strip_prefix("working-directory:") {
            let value = rest.trim().trim_matches('"').trim_matches('\'');
            return !value.is_empty() && value != ".";
        }
        false
    })
}

fn cargo_toml_members(cargo_toml: &str) -> Vec<String> {
    let mut members = Vec::new();
    let mut in_members = false;
    for line in cargo_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("members") && trimmed.contains('[') {
            in_members = true;
            // Possibly same-line: members = ["a", "b"]
            if let Some(start) = trimmed.find('[') {
                let rest = &trimmed[start + 1..];
                if let Some(end) = rest.find(']') {
                    parse_member_fragments(&rest[..end], &mut members);
                    in_members = false;
                }
            }
            continue;
        }
        if in_members {
            if trimmed.starts_with(']') {
                in_members = false;
                continue;
            }
            parse_member_fragments(trimmed, &mut members);
        }
    }
    members
}

fn parse_member_fragments(s: &str, out: &mut Vec<String>) {
    for part in s.split(',') {
        let p = part.trim().trim_matches(',').trim();
        if p.is_empty() {
            continue;
        }
        let p = p.trim_matches('"').trim_matches('\'');
        if !p.is_empty() && !p.starts_with('#') {
            out.push(p.to_string());
        }
    }
}

fn cli_ci_path_filters(cli_ci: &str) -> BTreeSet<String> {
    let mut filters = BTreeSet::new();
    let mut in_paths = false;
    for line in cli_ci.lines() {
        let trimmed = line.trim();
        if trimmed == "paths:" {
            in_paths = true;
            continue;
        }
        if in_paths {
            if let Some(rest) = trimmed.strip_prefix("- ") {
                let value = rest.trim().trim_matches('"').trim_matches('\'');
                if !value.is_empty() {
                    filters.insert(value.to_string());
                }
                continue;
            }
            // left the paths list
            if !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('-') {
                in_paths = false;
            }
        }
    }
    filters
}

fn path_filter_covers(filters: &BTreeSet<String>, member: &str) -> bool {
    filters.iter().any(|f| {
        if let Some(prefix) = f.strip_suffix("/**") {
            member == prefix || member.starts_with(&format!("{prefix}/"))
        } else {
            member == f.as_str() || member.starts_with(&format!("{f}/"))
        }
    })
}

fn has_exact_examples_companion_argv(source: &str) -> bool {
    source.lines().any(|line| {
        let t = line.trim().trim_start_matches("run:").trim();
        // Exact companion argv, optionally with a Windows --target triple
        // inserted before the trailing `-- -D warnings`.
        if t.contains(EXAMPLES_COMPANION_ARGV) {
            return !t.contains("--package")
                && !t.contains("-p ")
                && !t.contains("--bin")
                && !t.contains("--lib");
        }
        // Windows form: cargo clippy --locked --workspace --examples --target <triple> -- -D warnings
        let tokens = if let Some(idx) = find_cargo_clippy(t) {
            shellish_tokens(&t[idx + "cargo clippy".len()..])
        } else {
            return false;
        };
        exact_examples_companion_tokens(&tokens)
    })
}

/// Allowed token set for the companion gate: locked + workspace + examples +
/// optional --target <triple> + -- -D warnings. No package/feature selectors.
fn exact_examples_companion_tokens(tokens: &[String]) -> bool {
    if !is_examples_gate(tokens) {
        return false;
    }
    if !tokens.iter().any(|x| x == "--locked") || !tokens.iter().any(|x| x == "--workspace") {
        return false;
    }
    if !tokens
        .windows(2)
        .any(|w| w[0] == "-D" && w[1] == "warnings")
    {
        return false;
    }
    let forbidden = [
        "--package",
        "-p",
        "--bin",
        "--lib",
        "--test",
        "--bench",
        "--all-targets",
        "--tests",
        "--features",
        "--all-features",
        "--no-default-features",
    ];
    if tokens.iter().any(|t| forbidden.contains(&t.as_str())) {
        return false;
    }
    let mut i = 0;
    while i < tokens.len() {
        let t = tokens[i].as_str();
        match t {
            "--locked" | "--workspace" | "--examples" | "--" | "-D" | "warnings" => i += 1,
            "--target" => {
                if i + 1 >= tokens.len() {
                    return false;
                }
                i += 2;
            }
            other if other.starts_with("--target=") => i += 1,
            _ => return false,
        }
    }
    true
}

#[test]
fn clippy_command_authorities_are_consistent() {
    let agents = read_workspace_file("AGENTS.md");
    let contributing = read_workspace_file("CONTRIBUTING.md");
    let cli_ci = read_workspace_file(CLI_CI);
    let preflight = read_workspace_file(RELEASE_PREFLIGHT);

    let authorities = [
        ("AGENTS.md", agents.as_str()),
        ("CONTRIBUTING.md", contributing.as_str()),
        (CLI_CI, cli_ci.as_str()),
        (RELEASE_PREFLIGHT, preflight.as_str()),
    ];

    for (label, source) in authorities {
        for core in authority_tests_cores(label, source) {
            assert_core_is_canonical(label, &core);
        }
    }
}

#[test]
fn clippy_workflows_use_repo_root_target() {
    let cli_ci = read_workspace_file(CLI_CI);
    let preflight = read_workspace_file(RELEASE_PREFLIGHT);

    assert!(
        !workflow_has_non_root_working_directory(&preflight),
        "{RELEASE_PREFLIGHT} must not set a non-root working-directory; every Cargo step runs at monorepo root"
    );
    assert!(
        !workflow_has_non_root_working_directory(&cli_ci),
        "{CLI_CI} must not set a non-root working-directory"
    );

    assert!(
        workflow_rust_cache_maps_repo_root_target(&cli_ci),
        "{CLI_CI} rust-cache must map `. -> target`"
    );
    assert!(
        workflow_rust_cache_maps_repo_root_target(&preflight),
        "{RELEASE_PREFLIGHT} rust-cache must map `. -> target` (not apps/cli -> target)"
    );

    // No step may pin Cargo back under apps/cli.
    for (label, source) in [(CLI_CI, &cli_ci), (RELEASE_PREFLIGHT, &preflight)] {
        assert!(
            !workflow_has_non_root_working_directory(source),
            "{label} must execute Cargo from the repository root (no non-root working-directory)"
        );
    }
}

#[test]
fn clippy_windows_uses_actions_env() {
    let cli_ci = read_workspace_file(CLI_CI);
    let preflight = read_workspace_file(RELEASE_PREFLIGHT);

    for (label, source) in [(CLI_CI, &cli_ci), (RELEASE_PREFLIGHT, &preflight)] {
        assert!(
            workflow_has_env_cargo_target_dir(source),
            "{label} must set CARGO_TARGET_DIR: target via GitHub Actions env"
        );
        assert!(
            !workflow_has_posix_inline_cargo_target_dir(source),
            "{label} must not use POSIX inline CARGO_TARGET_DIR= assignment in run strings"
        );
    }
}

#[test]
fn clippy_examples_companion_is_present() {
    let cli_ci = read_workspace_file(CLI_CI);
    let preflight = read_workspace_file(RELEASE_PREFLIGHT);

    for (label, source) in [(CLI_CI, &cli_ci), (RELEASE_PREFLIGHT, &preflight)] {
        assert!(
            has_exact_examples_companion_argv(source),
            "{label} must run the companion examples gate argv \
             `{EXAMPLES_COMPANION_ARGV}` (Windows may insert --target <triple>)"
        );
        assert!(
            workflow_has_env_cargo_target_dir(source),
            "{label} companion examples gate requires CARGO_TARGET_DIR: target in Actions env"
        );
        // Companion must not replace the canonical --tests gate.
        let tests_gates = clippy_invocations(source)
            .into_iter()
            .filter(|t| is_tests_gate(t))
            .count();
        assert!(
            tests_gates >= 1,
            "{label} must keep the canonical --tests Clippy gate alongside --examples"
        );
    }
}

#[test]
fn clippy_examples_companion_has_nonempty_targets() {
    let root = workspace_root();
    let output = Command::new("cargo")
        .args(["metadata", "--locked", "--format-version", "1", "--no-deps"])
        .current_dir(&root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .output()
        .expect("spawn cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let meta: Value = serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON");
    let workspace_member_ids: BTreeSet<&str> = meta
        .get("workspace_members")
        .and_then(Value::as_array)
        .expect("metadata.workspace_members")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let packages = meta
        .get("packages")
        .and_then(Value::as_array)
        .expect("metadata.packages");

    let mut examples = Vec::new();
    for package in packages {
        let id = package.get("id").and_then(Value::as_str).unwrap_or("");
        if !workspace_member_ids.contains(id) {
            continue;
        }
        let pkg_name = package
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("<unknown>");
        let targets = match package.get("targets").and_then(Value::as_array) {
            Some(t) => t,
            None => continue,
        };
        for target in targets {
            let kinds = target
                .get("kind")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            let is_example = kinds.iter().any(|k| k.as_str() == Some("example"));
            if !is_example {
                continue;
            }
            let name = target
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("<unnamed>");
            examples.push(format!("{pkg_name}::{name}"));
        }
    }

    assert!(
        !examples.is_empty(),
        "workspace Cargo metadata must expose at least one example target for the \
         companion Clippy --examples gate; empty example set is a failing fixture"
    );
}

#[test]
fn clippy_ci_path_filters_match_workspace_members() {
    let cargo_toml = read_workspace_file("Cargo.toml");
    let cli_ci = read_workspace_file(CLI_CI);
    let members = cargo_toml_members(&cargo_toml);
    assert!(
        !members.is_empty(),
        "root Cargo.toml must list workspace members"
    );

    let filters = cli_ci_path_filters(&cli_ci);
    assert!(!filters.is_empty(), "{CLI_CI} must declare path filters");

    let mut missing = Vec::new();
    for member in &members {
        if !path_filter_covers(&filters, member) {
            missing.push(member.clone());
        }
    }
    assert!(
        missing.is_empty(),
        "{CLI_CI} path filters must cover every Cargo.toml workspace member; missing: {missing:?}\n\
         filters: {filters:?}"
    );

    // The Rust WebSocket relay server experiment is retired. No workspace
    // member or CLI CI path filter may reintroduce it.
    let retired_member = format!("apps/{}", "relay-rs");
    let retired_filter = format!("{retired_member}/**");
    let retired_package = format!("{}-{}", "flycockpit", "relay");
    assert!(
        !members.iter().any(|m| m == &retired_member),
        "Cargo workspace must not list retired Rust relay member {retired_member}"
    );
    assert!(
        !filters.iter().any(|f| f == &retired_member
            || f == &retired_filter
            || f.starts_with(&format!("{retired_member}/"))),
        "CLI CI path filters must not watch retired Rust relay paths ({retired_member})"
    );

    let metadata = Command::new("cargo")
        .args(["metadata", "--locked", "--no-deps", "--format-version", "1"])
        .current_dir(workspace_root())
        .output()
        .expect("run cargo metadata for retired relay package check");
    assert!(
        metadata.status.success(),
        "cargo metadata --locked --no-deps failed: {}",
        String::from_utf8_lossy(&metadata.stderr)
    );
    let meta: Value = serde_json::from_slice(&metadata.stdout).expect("parse cargo metadata JSON");
    let packages = meta
        .get("packages")
        .and_then(Value::as_array)
        .expect("metadata.packages");
    let retired_pkg_present = packages
        .iter()
        .any(|pkg| pkg.get("name").and_then(Value::as_str) == Some(retired_package.as_str()));
    assert!(
        !retired_pkg_present,
        "cargo metadata must not expose retired package {retired_package}"
    );
    // Surviving daemon/protocol crates must remain.
    for required in [
        "cockpit-cli",
        "cockpit-core",
        "cockpit-proto",
        "flycockpit-relay-protocol",
    ] {
        assert!(
            packages
                .iter()
                .any(|pkg| pkg.get("name").and_then(Value::as_str) == Some(required)),
            "cargo metadata must retain required package {required}"
        );
    }
}

#[test]
fn retire_rust_relay_correct_tests_first_rejects_rust_server_presence() {
    let cargo_toml = read_workspace_file("Cargo.toml");
    let cli_ci = read_workspace_file(CLI_CI);
    let retired_member = format!("apps/{}", "relay-rs");
    let retired_package = format!("{}-{}", "flycockpit", "relay");
    let retired_env = format!("{}_{}", "RELAY_UNDER", "TEST_BIN");

    assert!(
        !cargo_toml.contains(&format!("\"{retired_member}\"")),
        "root Cargo.toml must not list {retired_member}"
    );
    assert!(
        !cli_ci.contains(&format!("{retired_member}/**")),
        "{CLI_CI} must not path-filter {retired_member}"
    );
    let retired_path = workspace_root().join(&retired_member);
    if retired_path.exists() {
        // Prefer full deletion; an empty tombstone is only tolerated while the
        // directory is removed by the landing cleanup step.
        let cargo = retired_path.join("Cargo.toml");
        let main = retired_path.join("src").join("main.rs");
        let cargo_text = if cargo.exists() {
            std::fs::read_to_string(&cargo).unwrap_or_default()
        } else {
            String::new()
        };
        let main_text = if main.exists() {
            std::fs::read_to_string(&main).unwrap_or_default()
        } else {
            String::new()
        };
        assert!(
            cargo_text.trim().is_empty() && main_text.trim().is_empty(),
            "{retired_member} must be deleted (or emptied of all package/source content)"
        );
        assert!(
            !cargo_text.contains(&retired_package),
            "{retired_member}/Cargo.toml must not declare package {retired_package}"
        );
    }

    // TypeScript temporary bridge harness must not reintroduce external-binary selection.
    let fixture = read_workspace_file("apps/relay/src/conformance-fixture.ts");
    let server_test = read_workspace_file("apps/relay/src/server.test.ts");
    assert!(
        !fixture.contains(&retired_env),
        "conformance harness must not reference {retired_env}"
    );
    assert!(
        !fixture.contains("startSubprocessRelay"),
        "conformance harness must not spawn an external relay binary"
    );
    assert!(
        fixture.contains("createRelayServer"),
        "conformance harness must use in-process createRelayServer"
    );
    assert!(
        !server_test.contains(&retired_env),
        "server.test.ts must not branch on {retired_env}"
    );
    assert!(
        !fixture.contains(&retired_package),
        "conformance harness must not name retired package {retired_package}"
    );
}
