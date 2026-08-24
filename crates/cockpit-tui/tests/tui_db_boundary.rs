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
fn tui_agent_authority_is_daemon_owned() {
    fn production_part(source: String) -> String {
        source
            .split("#[cfg(test)]\nmod tests")
            .next()
            .unwrap_or(&source)
            .to_string()
    }
    let agents = production_part(read("crates/cockpit-tui/src/tui/settings/agents_page.rs"));
    let goals = production_part(read("crates/cockpit-tui/src/tui/goal_settings_pane.rs"));
    let tools = production_part(read("crates/cockpit-tui/src/tui/tools_pane.rs"));
    let production = format!("{agents}\n{goals}\n{tools}");
    for forbidden in [
        "cockpit_core::agents::resolve(",
        "cockpit_core::agents::list_all(",
        "cockpit_core::agents::eject_builtin(",
        "cockpit_core::agents::find_override(",
        "cockpit_core::agents::reset_all_builtins(",
        "cockpit_core::assistants::load_from_home(",
        "cockpit_core::agents::load_daemon_local_named_from_file(",
        "Request::FsWrite",
        "Request::UpsertAssistant",
        "std::fs::remove_file(",
    ] {
        assert!(
            !production.contains(forbidden),
            "TUI retained mutation-capable agent authority: {forbidden}"
        );
    }
    for rpc in [
        "GetAgentInventory",
        "GetAgentEditSnapshot",
        "MutateAgent",
        "BeginAgentEditorLease",
        "CompleteAgentEditorLease",
        "SaveAssistantDefinition",
    ] {
        assert!(production.contains(rpc), "missing agent owner RPC: {rpc}");
    }
    assert_eq!(
        production.matches("std::fs::write(").count(),
        1,
        "agent UI may write only its isolated external-editor staging file"
    );
    assert!(production.contains("std::fs::write(&staging.path, text)"));
}

#[test]
fn full_production_tree_rejects_agent_and_config_authority() {
    fn visit(path: &Path, findings: &mut Vec<String>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, findings);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("rs")
                || path.components().any(|part| part.as_os_str() == "tests")
                || path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|name| name.ends_with("_tests.rs"))
            {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let production = source
                .split("#[cfg(test)]\nmod tests")
                .next()
                .unwrap_or(&source);
            for forbidden in [
                "cockpit_core::agents::resolve(",
                "cockpit_core::agents::list_all(",
                "cockpit_core::agents::eject_builtin(",
                "cockpit_core::agents::reset_all_builtins(",
                "Request::SaveExtendedConfig",
                "patch_json:",
            ] {
                if production.contains(forbidden) {
                    findings.push(format!("{}: {forbidden}", path.display()));
                }
            }
        }
    }
    let mut findings = Vec::new();
    visit(&repo_root().join("crates/cockpit-tui/src"), &mut findings);
    assert!(
        findings.is_empty(),
        "authority leaks:\n{}",
        findings.join("\n")
    );
}

#[test]
fn production_filesystem_mutations_have_device_ui_owners() {
    const MUTATIONS: &[&str] = &[
        "std::fs::write(",
        "std::fs::remove_file(",
        "std::fs::remove_dir(",
        "std::fs::rename(",
        "std::fs::create_dir(",
        "std::fs::create_dir_all(",
        "std::fs::OpenOptions",
        "tokio::fs::write(",
        "tokio::fs::remove_file(",
    ];
    const ALLOWED: &[(&str, &str)] = &[
        (
            "crates/cockpit-tui/src/tui/settings/agents_page.rs",
            "std::fs::write(&staging.path, text)",
        ),
        (
            "crates/cockpit-tui/src/tui/app/panes.rs",
            "std::fs::write(&path, effect.text_before_launch)",
        ),
        ("crates/cockpit-tui/src/tui/async_action.rs", ""),
        ("crates/cockpit-tui/src/tui/app/export_actions.rs", ""),
        ("crates/cockpit-tui/src/clipboard/recovery/unix.rs", ""),
        ("crates/cockpit-tui/src/clipboard/recovery/windows.rs", ""),
    ];
    fn visit(path: &Path, findings: &mut Vec<String>) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, findings);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("rs")
                || path.components().any(|part| part.as_os_str() == "tests")
                || path.file_name().and_then(|value| value.to_str())
                    .is_some_and(|name| name.ends_with("_tests.rs"))
            {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let production = source.split("#[cfg(test)]\nmod tests").next().unwrap_or(&source);
            let relative = path.strip_prefix(repo_root()).unwrap().to_string_lossy();
            for mutation in MUTATIONS {
                if !production.contains(mutation) {
                    continue;
                }
                let allowed = ALLOWED.iter().any(|(file, required)| {
                    relative == *file && (required.is_empty() || production.contains(required))
                });
                if !allowed {
                    findings.push(format!("{relative}: {mutation}"));
                }
            }
            if production.contains("use std::fs as ")
                || production.contains("use tokio::fs as ")
            {
                findings.push(format!("{relative}: filesystem alias obscures authority audit"));
            }
        }
    }
    let mut findings = Vec::new();
    visit(&repo_root().join("crates/cockpit-tui/src"), &mut findings);
    assert!(findings.is_empty(), "unowned TUI filesystem mutations:\n{}", findings.join("\n"));
}

#[test]
fn tui_settings_use_revisioned_typed_mutation() {
    let settings = read("crates/cockpit-tui/src/tui/settings/mod.rs");
    assert!(settings.contains("GetExtendedConfigSnapshot"));
    assert!(settings.contains("ApplyExtendedConfigPatch"));
    assert!(!settings.contains("Request::SaveExtendedConfig"));
    assert!(!settings.contains("base_hash = None"));
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
