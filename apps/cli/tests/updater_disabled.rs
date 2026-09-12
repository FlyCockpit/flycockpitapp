//! Disabled updater boundary tests for issue #402.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use assert_cmd::cargo::cargo_bin;
use cockpit_core::updater::{
    UpdateCheckResult, Updater, effective_update_channel, installed_composition, installed_updater,
    run_startup_check, update_notice, update_status,
};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn production_updater_sources() -> Vec<PathBuf> {
    use std::path::PathBuf;
    let root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../crates/cockpit-core/src/updater");
    let mut files = Vec::new();
    for name in ["disabled.rs", "composition.rs"] {
        files.push(root.join(name));
    }
    files
}

use std::path::PathBuf;

#[test]
fn installed_composition_has_no_trust_or_transport() {
    let forbidden = [
        "reqwest::",
        "tough::",
        "self_replace::",
        "https://",
        "http://",
        "FakeFixture",
    ];
    for path in production_updater_sources() {
        let source = fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "failed to read production updater source {}: {error}",
                path.display()
            )
        });
        let production = strip_test_modules(&source);
        for needle in forbidden {
            assert!(
                !production.contains(needle),
                "{} must not reference `{needle}` in production code",
                path.display()
            );
        }
    }
    let _composition = installed_composition();
}

#[tokio::test]
async fn all_check_entrypoints_return_disabled_without_side_effect() {
    let _guard = cockpit_test_support::TestEnvGuard::lock().await;
    let channel = effective_update_channel();
    let before = snapshot_state_tree();

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

    let after = snapshot_state_tree();
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

    let cli_lib = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs");
    let cli_source = fs::read_to_string(cli_lib).expect("read cli lib");
    assert!(
        !cli_source.contains("updater::fake"),
        "installed CLI must not import fake updater adapters"
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

fn snapshot_state_tree() -> Vec<String> {
    let root = std::env::var("COCKPIT_STATE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("/tmp"))
                .join(format!(
                    "cockpit-updater-disabled-{}",
                    COUNTER.fetch_add(1, Ordering::Relaxed)
                ))
        });
    walk_tree(&root)
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
