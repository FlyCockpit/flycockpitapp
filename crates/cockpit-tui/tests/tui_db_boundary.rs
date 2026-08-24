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
        "DeleteAssistant",
    ] {
        assert!(production.contains(rpc), "missing agent owner RPC: {rpc}");
    }
    assert!(!production.contains("std::fs::write("));
    assert_eq!(
        production
            .matches("cockpit_config::config::write_config_bytes_atomic(&staging.path")
            .count(),
        1,
        "agent UI may seed only its isolated private editor staging file"
    );
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
        "std::fs::write",
        "std::fs::remove_file",
        "std::fs::remove_dir",
        "std::fs::rename",
        "std::fs::copy",
        "std::fs::hard_link",
        "std::os::unix::fs::symlink",
        "std::os::windows::fs::symlink_file",
        "std::os::windows::fs::symlink_dir",
        "std::fs::create_dir",
        "std::fs::create_dir_all",
        "std::fs::set_permissions",
        "std::fs::File::create",
        "File::create",
        "std::fs::OpenOptions",
        "std::fs::File::options",
        ".set_len(",
        ".write(",
        "tokio::fs::write",
        "tokio::fs::remove_file",
        "tokio::fs::create_dir_all",
        "tokio::fs::set_permissions",
        ".write_all(",
    ];
    // Every exception is a single reviewed source line, not a whole-file
    // exemption. Adding a second mutation in an allowed host-integration file
    // must therefore update this inventory explicitly.
    const ALLOWED_LINES: &[(&str, &str)] = &[
        (
            "crates/cockpit-tui/src/tui/app/panes.rs",
            "if let Err(error) = std::fs::write(&path, effect.text_before_launch) {",
        ),
        (
            "crates/cockpit-tui/src/tui/async_action.rs",
            "std::fs::create_dir_all(&dir)?",
        ),
        (
            "crates/cockpit-tui/src/tui/async_action.rs",
            "std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?",
        ),
        (
            "crates/cockpit-tui/src/tui/async_action.rs",
            "let mut file = std::fs::OpenOptions::new()",
        ),
        (
            "crates/cockpit-tui/src/tui/async_action.rs",
            "file.write_all(format!(\"v1\\n{name}\\n\").as_bytes())?",
        ),
        (
            "crates/cockpit-tui/src/tui/async_action.rs",
            "match tokio::fs::remove_file(&path).await",
        ),
        (
            "crates/cockpit-tui/src/tui/app/export_actions.rs",
            "let _ = tokio::fs::remove_file(entry.path()).await",
        ),
        (
            "crates/cockpit-tui/src/tui/app/export_actions.rs",
            "tokio::fs::create_dir_all(exports_dir)",
        ),
        (
            "crates/cockpit-tui/src/clipboard/recovery/unix.rs",
            "std::fs::create_dir_all(parent).map_err(|e| io_err(\"creating state directory\", e))?;",
        ),
        (
            "crates/cockpit-tui/src/clipboard/recovery/windows.rs",
            "std::fs::create_dir_all(parent)?",
        ),
        (
            "crates/cockpit-tui/src/tui/settings/category.rs",
            "temp.write_all(text.as_bytes())",
        ),
        (
            "crates/cockpit-tui/src/tui/app/panes.rs",
            "if let Err(e) = temp.write_all(editor_text.as_bytes()) {",
        ),
        (
            "crates/cockpit-tui/src/clipboard/service.rs",
            "let _ = stdin.write_all(text.as_bytes());",
        ),
        (
            "crates/cockpit-tui/src/clipboard/executable.rs",
            "let _ = stdin.write_all(bytes);",
        ),
        (
            "crates/cockpit-tui/src/tui/app/mod.rs",
            "let _ = out.write_all(sequence.as_bytes());",
        ),
        (
            "crates/cockpit-tui/src/tui/app/mod.rs",
            "let _ = out.write_all(b\"\\x07\");",
        ),
        (
            "crates/cockpit-tui/src/tui/app/mod.rs",
            "let _ = out.write_all(escapes.as_bytes());",
        ),
        (
            "crates/cockpit-tui/src/tui/pty.rs",
            "let _ = self.writer.write_all(bytes);",
        ),
        (
            "crates/cockpit-tui/src/tui/links.rs",
            "lock.write_all(&bytes)?;",
        ),
    ];
    fn visit(
        path: &Path,
        findings: &mut Vec<String>,
        allowed_hits: &mut std::collections::HashMap<(&'static str, &'static str), usize>,
    ) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, findings, allowed_hits);
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
            let relative = path.strip_prefix(repo_root()).unwrap().to_string_lossy();
            for (line_number, line) in production.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                for mutation in MUTATIONS {
                    if !line.contains(mutation) {
                        continue;
                    }
                    let allowed = ALLOWED_LINES
                        .iter()
                        .find(|(file, exact)| relative == *file && line.trim() == *exact);
                    if let Some(allowed) = allowed {
                        *allowed_hits.entry(*allowed).or_default() += 1;
                    }
                    if allowed.is_none() {
                        findings.push(format!("{relative}:{}: {mutation}", line_number + 1));
                    }
                }
            }
            if production.contains("use std::fs as ") || production.contains("use tokio::fs as ") {
                findings.push(format!(
                    "{relative}: filesystem alias obscures authority audit"
                ));
            }
            for line in production.lines().map(str::trim) {
                let imports_mutation = (line.starts_with("use std::fs::")
                    || line.starts_with("use tokio::fs::"))
                    && [
                        "write",
                        "remove_file",
                        "remove_dir",
                        "rename",
                        "create_dir",
                        "create_dir_all",
                        "set_permissions",
                    ]
                    .iter()
                    .any(|name| line.contains(name));
                if imports_mutation
                    || (line.starts_with("use ") && line.contains(" as ") && line.contains("fs::"))
                {
                    findings.push(format!(
                        "{relative}: filesystem mutation import/alias obscures authority audit: {line}"
                    ));
                }
            }
        }
    }
    let mut findings = Vec::new();
    let mut allowed_hits = std::collections::HashMap::new();
    visit(
        &repo_root().join("crates/cockpit-tui/src"),
        &mut findings,
        &mut allowed_hits,
    );
    for allowed in ALLOWED_LINES {
        let count = allowed_hits.get(allowed).copied().unwrap_or_default();
        if count != 1 {
            findings.push(format!(
                "allowlisted mutation must occur exactly once: {}: {:?} (found {count})",
                allowed.0, allowed.1
            ));
        }
    }
    assert!(
        findings.is_empty(),
        "unowned TUI filesystem mutations:\n{}",
        findings.join("\n")
    );
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
