use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).unwrap()
}

fn tui_sources() -> String {
    fn collect(path: &Path, out: &mut String) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().and_then(|value| value.to_str()) == Some("rs") {
                out.push_str(&fs::read_to_string(path).unwrap());
            }
        }
    }
    let mut sources = String::new();
    collect(&repo_root().join("crates/cockpit-tui/src"), &mut sources);
    sources
}

#[test]
fn cockpit_core_db_reexport_removed() {
    let source = read("crates/cockpit-core/src/lib.rs");
    assert!(!source.contains(concat!("pub use cockpit_", "db as db")));
}

#[test]
fn tui_manifest_has_no_cockpit_db() {
    let manifest = read("crates/cockpit-tui/Cargo.toml");
    assert!(
        !manifest
            .lines()
            .any(|line| line.starts_with(concat!("cockpit", "-db")))
    );
}

#[test]
fn tui_db_inventory_converted() {
    let sources = tui_sources();
    for forbidden in [
        concat!("cockpit_", "db"),
        concat!("cockpit_core::", "db"),
        concat!("D", "b::open"),
        concat!("new_with_", "db"),
    ] {
        assert!(
            !sources.contains(forbidden),
            "forbidden TUI DB surface: {forbidden}"
        );
    }
    for rpc in [
        "SetWorkspaceTrust",
        "GetStartupDisclosures",
        "GetAppFlag",
        "MarkAppFlagSeen",
        "ResolveAssistantSession",
        "ReadSubagentHistoryPage",
        "StatsRollup",
        "ListProjectNotes",
        "ListPinnedMessages",
        "ListSessions",
    ] {
        assert!(sources.contains(rpc), "missing daemon RPC migration: {rpc}");
    }
}

#[test]
fn tui_db_surface_behavior_matrix() {
    let sources = tui_sources();
    assert!(sources.contains("startup_disclosures_ready"));
    assert!(sources.contains("Startup disclosures Unavailable"));
    assert!(sources.contains("Assistants Unavailable"));
    assert!(sources.contains("reconnect to the daemon, then Retry"));
    assert!(sources.contains("source_session_id"));
    assert!(sources.contains("result.project_root != self.project_root"));
}

#[test]
fn tui_db_boundary_gate_first_has_real_negative_alias_fixtures() {
    for fixture in ["direct_alias.rs", "core_alias.rs"] {
        let source = read(&format!("scripts/fixtures/tui-db-boundary/{fixture}"));
        assert!(source.contains("use "));
        assert!(source.contains(" as storage;"));
        assert!(source.contains(concat!("storage::D", "b::open_default()")));
    }
    let gate = read("scripts/check-tui-db-boundary.sh");
    assert!(gate.contains("cargo check"));
    assert!(gate.contains("negative fixture unexpectedly compiled"));
}
