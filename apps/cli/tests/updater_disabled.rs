//! Disabled updater boundary tests for issue #402.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::cargo::cargo_bin;
use cockpit_core::updater::{
    UpdateCheckResult, Updater, effective_update_channel, installed_composition, installed_updater,
    run_startup_check, update_notice, update_status,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

const WORKSPACE_SCAN_ROOTS: &[&str] = &["apps", "crates"];

const EXPECTED_UPDATER_CONSUMERS: &[&str] = &[
    "apps/cli/src/commands/update.rs",
    "apps/cli/tests/updater_disabled.rs",
    "crates/cockpit-core/src/daemon/mod.rs",
    "crates/cockpit-core/src/daemon/server/mod.rs",
    "crates/cockpit-tui/src/tui/app/update_notice.rs",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn production_updater_implementation_sources() -> Vec<PathBuf> {
    let root = workspace_root().join("crates/cockpit-core/src/updater");
    fs::read_dir(&root)
        .unwrap_or_else(|error| {
            panic!(
                "failed to read updater sources at {}: {error}",
                root.display()
            )
        })
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "rs")
                && path.file_name().is_some_and(|name| name != "fake.rs")
        })
        .collect()
}

fn is_updater_implementation_source(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "updater")
        && path
            .components()
            .any(|component| component.as_os_str() == "cockpit-core")
}

fn strip_rust_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let bytes = source.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'/' && i + 1 < bytes.len() {
            if bytes[i + 1] == b'/' {
                i += 2;
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            if bytes[i + 1] == b'*' {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i = (i + 2).min(bytes.len());
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn parse_use_as_alias(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim().trim_end_matches(';').trim();
    let rest = trimmed.strip_prefix("use ")?.trim();
    let (path, alias) = rest.split_once(" as ")?;
    Some((path.trim().to_string(), alias.trim().to_string()))
}

fn updater_module_prefixes(source: &str) -> Vec<String> {
    let mut prefixes = vec!["cockpit_core".to_string(), "crate".to_string()];
    for line in source.lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with("use ") {
            continue;
        }
        if let Some((path, alias)) = parse_use_as_alias(trimmed) {
            if path == "cockpit_core"
                || path == "crate"
                || path.starts_with("cockpit_core::")
                || path.starts_with("crate::")
            {
                prefixes.push(alias);
            }
        }
    }
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

fn references_installed_updater_module(source: &str) -> bool {
    let production = strip_rust_comments(&strip_test_modules(source));
    for prefix in updater_module_prefixes(&production) {
        if production.contains(&format!("{prefix}::updater")) {
            return true;
        }
    }
    production.contains("::updater::")
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    if !dir.is_dir() {
        return;
    }
    let entries = fs::read_dir(dir).unwrap_or_else(|error| {
        panic!(
            "failed to read updater consumer scan root {}: {error}",
            dir.display()
        )
    });
    for entry in entries.filter_map(|entry| entry.ok()) {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

fn discover_updater_consumer_sources() -> Vec<PathBuf> {
    let root = workspace_root();
    let mut sources = Vec::new();
    for relative in WORKSPACE_SCAN_ROOTS {
        collect_rs_files(&root.join(relative), &mut sources);
    }

    let mut consumers = sources
        .into_iter()
        .filter(|path| !is_updater_implementation_source(path))
        .filter(|path| {
            let source = fs::read_to_string(path).unwrap_or_else(|error| {
                panic!(
                    "failed to read updater consumer candidate {}: {error}",
                    path.display()
                )
            });
            let production_source = strip_test_modules(&source);
            references_installed_updater_module(&production_source)
        })
        .collect::<Vec<_>>();
    consumers.sort();
    consumers.dedup();
    consumers
}

fn expected_updater_consumer_sources() -> Vec<PathBuf> {
    EXPECTED_UPDATER_CONSUMERS
        .iter()
        .map(|relative| workspace_root().join(relative))
        .collect()
}

fn production_updater_consumer_sources() -> Vec<PathBuf> {
    let discovered = discover_updater_consumer_sources();
    let expected = expected_updater_consumer_sources();
    assert_eq!(
        discovered, expected,
        "updater consumer surface changed; update EXPECTED_UPDATER_CONSUMERS and review boundary scans"
    );
    expected
}

fn production_updater_boundary_sources() -> Vec<PathBuf> {
    let mut sources = production_updater_implementation_sources();
    sources.extend(production_updater_consumer_sources());
    sources
}

fn implementation_updater_sources() -> Vec<PathBuf> {
    production_updater_implementation_sources()
        .into_iter()
        .filter(|path| {
            path.file_name().is_some_and(|name| {
                name == "disabled.rs" || name == "composition.rs" || name == "background.rs"
            })
        })
        .collect()
}

fn boundary_side_effect_sources() -> Vec<PathBuf> {
    let mut sources = implementation_updater_sources();
    sources.extend(production_updater_consumer_sources());
    sources
}

fn side_effect_scan_segments(_path: &Path, source: &str) -> Vec<String> {
    vec![strip_test_modules(source)]
}

fn scan_segments_for_forbidden(segments: &[String], needles: &[&str], path: &Path, label: &str) {
    for segment in segments {
        for needle in needles {
            assert!(
                !segment.contains(needle),
                "{} must not {label} `{needle}` in production updater code",
                path.display()
            );
        }
    }
}

fn is_run_startup_check_call_site(line: &str) -> bool {
    if !line.contains("run_startup_check(") {
        return false;
    }
    let trimmed = line.trim_start();
    !(trimmed.starts_with("use ")
        || line.contains("pub async fn run_startup_check")
        || line.contains("pub fn run_startup_check"))
}

fn byte_offset_for_line(source: &str, line_idx: usize) -> usize {
    source
        .lines()
        .take(line_idx)
        .map(|line| line.len() + 1)
        .sum()
}

fn find_enclosing_block_opener(source: &str, call_offset: usize) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut depth = 0usize;
    let mut index = call_offset;
    while index > 0 {
        index -= 1;
        match bytes[index] {
            b'}' => depth += 1,
            b'{' => {
                if depth == 0 {
                    return Some(index);
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    None
}

fn controlling_statement_for_block(source: &str, block_opener: usize) -> String {
    let prefix = source[..block_opener].trim_end();
    if let Some(arm_start) = prefix.rfind("=>") {
        let before_arm = prefix[..arm_start].trim_end();
        let line_start = before_arm.rfind('\n').map(|idx| idx + 1).unwrap_or(0);
        return prefix[line_start..arm_start].trim().to_string();
    }
    if let Some(if_start) = prefix.rfind("\nif ") {
        return prefix[if_start + 1..].trim().to_string();
    }
    if let Some(if_start) = prefix.rfind(" if ") {
        return prefix[if_start + 1..].trim().to_string();
    }
    if prefix.trim_start().starts_with("if ") {
        return prefix.trim().to_string();
    }
    String::new()
}

fn call_is_update_check_gated(source: &str, line_idx: usize) -> bool {
    let call_offset = byte_offset_for_line(source, line_idx);
    let call_line = source.lines().nth(line_idx).unwrap_or("");
    if call_line.contains("update_checks_enabled") {
        return true;
    }
    let block_opener = find_enclosing_block_opener(source, call_offset)?;
    let controller = controlling_statement_for_block(source, block_opener);
    controller.contains("update_checks_enabled")
}

fn assert_run_startup_check_gated(source: &str, path_label: &str) {
    let production = strip_rust_comments(&strip_test_modules(source));
    for (line_idx, line) in production.lines().enumerate() {
        if !is_run_startup_check_call_site(line) {
            continue;
        }
        assert!(
            call_is_update_check_gated(&production, line_idx),
            "{}: run_startup_check must be enclosed by an update_checks_enabled guard",
            path_label
        );
    }
}

fn assert_update_checks_suppressed_when_off() {
    let server_path = workspace_root().join("crates/cockpit-core/src/daemon/server/mod.rs");
    let server = fs::read_to_string(&server_path).expect("read daemon server source");
    assert!(
        server.contains("update_checks_enabled(update_channel)"),
        "daemon boot must gate startup update checks behind update_checks_enabled"
    );
    assert_run_startup_check_gated(&server, server_path.display().to_string());

    let daemon = fs::read_to_string(workspace_root().join("crates/cockpit-core/src/daemon/mod.rs"))
        .expect("read daemon source");
    assert!(
        daemon.contains("maybe_spawn_background"),
        "daemon must spawn background update checks only through maybe_spawn_background"
    );
    assert!(
        !strip_rust_comments(&strip_test_modules(&daemon))
            .contains("crate::updater::spawn_background"),
        "daemon must not invoke updater::spawn_background directly"
    );

    let background_path = workspace_root().join("crates/cockpit-core/src/updater/background.rs");
    let background = fs::read_to_string(&background_path).expect("read updater background source");
    assert!(
        background.contains("update_checks_enabled(channel)"),
        "background update loop must skip checks when the effective channel is off"
    );
    assert_run_startup_check_gated(&background, background_path.display().to_string());
}

#[test]
fn installed_composition_has_no_trust_or_transport() {
    assert_update_checks_suppressed_when_off();

    let transport_forbidden = [
        "reqwest",
        "tough",
        "self_replace",
        "ureq",
        "minisign",
        "https://",
        "http://",
        "FakeFixture",
    ];
    let capability_forbidden = [
        "download_verified_target",
        "stage_and_swap",
        "request_maintenance",
        "refresh_trusted_metadata",
        "acquire_exclusive",
        "std::process::Command",
        "Command::new",
        "tokio::process",
    ];
    for path in production_updater_boundary_sources() {
        assert!(
            path.is_file(),
            "updater boundary source must exist: {}",
            path.display()
        );
        let source = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read production updater source {}: {error}",
                path.display()
            )
        });
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        let scan_transport = file_name != "traits.rs" && file_name != "types.rs";
        let segments = side_effect_scan_segments(&path, &source);
        if scan_transport {
            scan_segments_for_forbidden(&segments, &transport_forbidden, &path, "reference");
        }
        if boundary_side_effect_sources()
            .iter()
            .any(|candidate| candidate == &path)
        {
            scan_segments_for_forbidden(&segments, &capability_forbidden, &path, "invoke");
        }
    }

    let composition_source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/cockpit-core/src/updater/composition.rs"),
    )
    .expect("read composition source");
    assert!(
        composition_source.contains("DisabledUpdater"),
        "installed composition must wire only DisabledUpdater"
    );
    assert!(
        !composition_source.contains("FakeFixture"),
        "installed composition must not reference fake adapters"
    );
    let _composition = installed_composition();
}

#[tokio::test]
async fn all_check_entrypoints_return_disabled_without_side_effect() {
    let _guard = cockpit_test_support::TestEnvGuard::lock().await;
    let state_dir = isolated_state_dir();
    fs::create_dir_all(&state_dir).expect("create isolated state dir");
    _guard.set_var(
        "COCKPIT_STATE_DIR",
        state_dir.to_str().expect("utf8 state dir"),
    );
    let channel = effective_update_channel().expect("effective update channel");
    let before = snapshot_state_tree(&state_dir);

    let startup = run_startup_check(channel).await;
    let manual = installed_updater().check(channel).await;
    let status = update_status(channel);
    let notice = update_notice(channel);

    match channel {
        cockpit_config::config::update_channel::UpdateChannel::Off => {
            assert_eq!(startup, UpdateCheckResult::Off);
            assert_eq!(manual, UpdateCheckResult::Off);
            assert!(matches!(
                status,
                cockpit_core::updater::UpdateStatusSnapshot::Off
            ));
            assert!(notice.is_none());
        }
        _ => {
            assert!(matches!(startup, UpdateCheckResult::Disabled(_)));
            assert!(matches!(manual, UpdateCheckResult::Disabled(_)));
            assert!(matches!(
                status,
                cockpit_core::updater::UpdateStatusSnapshot::Disabled { .. }
            ));
            assert!(notice.is_some());
        }
    }

    let after = snapshot_state_tree(&state_dir);
    assert_eq!(before, after, "update checks must not touch the state tree");

    let bin = cargo_bin("cockpit");
    let output = Command::new(&bin)
        .args(["update", "--check"])
        .output()
        .expect("run cockpit update --check");
    if channel == cockpit_config::config::update_channel::UpdateChannel::Off {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    } else {
        assert!(!output.status.success(), "disabled apply must fail closed");
        let combined = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            combined.contains("disabled") || combined.contains("production TUF updater"),
            "expected disabled updater output, got: {combined}"
        );
    }

    for path in boundary_side_effect_sources() {
        let source = fs::read_to_string(&path).expect("read updater boundary source");
        for segment in side_effect_scan_segments(&path, &source) {
            assert!(
                !segment.contains("reqwest::")
                    && !segment.contains("tough::")
                    && !segment.contains("self_replace::")
                    && !segment.contains("MetadataRepository")
                    && !segment.contains("TargetFetcher")
                    && !segment.contains("BinaryReplacer")
                    && !segment.contains("SupervisorMaintenanceClient")
                    && !segment.contains("UpdateLockStore"),
                "{} must not delegate to transport/trust/maintenance seams",
                path.display()
            );
        }
    }
}

#[test]
fn tuf_release_uses_canonical_fake_fixture_schema() {
    let main_rs = fs::read_to_string(workspace_root().join("tools/tuf-release/src/main.rs"))
        .expect("read tuf-release main source");
    assert!(
        main_rs.contains("cockpit_updater_evidence::FakeFixtureEvidence")
            || main_rs.contains("cockpit_updater_evidence::{FakeFixtureEvidence"),
        "tuf-release must deserialize canonical FakeFixtureEvidence from cockpit-updater-evidence"
    );
    let tuf_manifest = fs::read_to_string(workspace_root().join("tools/tuf-release/Cargo.toml"))
        .expect("read tuf-release manifest");
    assert!(
        !tuf_manifest.contains("cockpit-core"),
        "tuf-release must not depend on the request-capable cockpit-core crate"
    );
    assert!(
        tuf_manifest.contains("cockpit-updater-evidence"),
        "tuf-release must depend only on the evidence schema crate"
    );
    assert!(
        main_rs.contains("validate_fake_fixture_evidence"),
        "tuf-release must validate evidence through the shared cockpit-core validator"
    );
    assert!(
        !main_rs.contains("struct FakeFixtureTarget"),
        "tuf-release must not declare a parallel fake-fixture schema"
    );
}

#[test]
fn fixture_adapter_cannot_link_to_installed_binary() {
    let mod_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../crates/cockpit-core/src/updater/mod.rs");
    let source = fs::read_to_string(mod_path).expect("read updater mod source");
    assert!(
        source.contains("#[cfg(any(test, feature = \"test-support\"))]"),
        "fake fixture adapters must be cfg-gated in updater/mod.rs"
    );

    let cli_manifest =
        fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml"))
            .expect("read cli manifest");
    let production_dep = cli_manifest
        .split("[dependencies]")
        .nth(1)
        .and_then(|section| section.split("[dev-dependencies]").next())
        .unwrap_or("");
    assert!(
        !production_dep.contains("test-support"),
        "installed CLI production dependency must not enable cockpit-core test-support"
    );

    let core_manifest = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/cockpit-core/Cargo.toml"),
    )
    .expect("read cockpit-core manifest");
    assert!(
        core_manifest.contains("[features]"),
        "cockpit-core manifest must declare explicit features"
    );
    assert!(
        !core_manifest.contains("default = [\"test-support\"]"),
        "cockpit-core default features must not expose fake updater adapters"
    );

    let composition_source = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/cockpit-core/src/updater/composition.rs"),
    )
    .expect("read composition source");
    assert!(
        !composition_source.contains("fake::"),
        "installed composition must not reference fake adapters"
    );
}

#[test]
fn cargo_dist_and_docs_remain_disabled() {
    let dist = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../dist-workspace.toml"),
    )
    .expect("read dist-workspace.toml");
    assert!(dist.contains("install-updater = false"));

    let readme = fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md"))
        .expect("read cli README");
    assert!(
        readme.contains("cargo-dist"),
        "README must document cargo-dist installer ownership"
    );
    assert!(
        readme.contains("self-update"),
        "README must document that generic self-update remains disabled"
    );
}

fn isolated_state_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "cockpit-updater-disabled-{}",
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

fn snapshot_state_tree(root: &Path) -> Vec<String> {
    walk_tree(root)
}

fn walk_tree(root: &Path) -> Vec<String> {
    if !root.exists() {
        return Vec::new();
    }
    let mut out = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        let meta = entry.metadata().unwrap();
        if meta.is_dir() {
            out.extend(walk_tree(&path));
        } else {
            out.push(format!("{}:{}", path.display(), meta.len()));
        }
    }
    out.sort();
    out
}

fn strip_test_modules(src: &str) -> String {
    let mut out = String::new();
    let mut i = 0;
    let bytes = src.as_bytes();
    while i < src.len() {
        if let Some(rel) = src[i..].find("#[cfg(test)]") {
            out.push_str(&src[i..i + rel]);
            let after = i + rel + "#[cfg(test)]".len();
            if let Some(mod_rel) = src[after..].find('{') {
                let mut depth = 0;
                let mut j = after + mod_rel;
                while j < src.len() {
                    match bytes[j] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                j += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    j += 1;
                }
                i = j;
            } else {
                i = after;
            }
            continue;
        }
        out.push_str(&src[i..]);
        break;
    }
    out
}
