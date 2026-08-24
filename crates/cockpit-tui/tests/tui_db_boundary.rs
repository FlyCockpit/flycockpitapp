use quote::ToTokens;
use std::fs;
use std::path::{Path, PathBuf};
use syn::spanned::Spanned;
use syn::visit::Visit;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(relative: &str) -> String {
    fs::read_to_string(repo_root().join(relative)).unwrap()
}

fn cfg_test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        if !attribute.path().is_ident("cfg") {
            return false;
        }
        let compact: String = attribute
            .meta
            .to_token_stream()
            .to_string()
            .chars()
            .filter(|ch| !ch.is_whitespace())
            .collect();
        compact == "cfg(test)"
    })
}

fn item_attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(value) => &value.attrs,
        syn::Item::Enum(value) => &value.attrs,
        syn::Item::ExternCrate(value) => &value.attrs,
        syn::Item::Fn(value) => &value.attrs,
        syn::Item::ForeignMod(value) => &value.attrs,
        syn::Item::Impl(value) => &value.attrs,
        syn::Item::Macro(value) => &value.attrs,
        syn::Item::Mod(value) => &value.attrs,
        syn::Item::Static(value) => &value.attrs,
        syn::Item::Struct(value) => &value.attrs,
        syn::Item::Trait(value) => &value.attrs,
        syn::Item::TraitAlias(value) => &value.attrs,
        syn::Item::Type(value) => &value.attrs,
        syn::Item::Union(value) => &value.attrs,
        syn::Item::Use(value) => &value.attrs,
        _ => &[],
    }
}

/// Return the complete source with only structurally parsed `#[cfg(test)]`
/// items blanked. Newlines are retained so exact source-line allowlists and
/// diagnostics remain stable, and production declared after a test module is
/// still audited.
fn production_source(source: &str) -> String {
    struct TestItems(Vec<(proc_macro2::LineColumn, proc_macro2::LineColumn)>);
    impl<'ast> Visit<'ast> for TestItems {
        fn visit_item(&mut self, item: &'ast syn::Item) {
            if cfg_test_only(item_attributes(item)) {
                let attrs = item_attributes(item);
                let start = attrs
                    .first()
                    .map_or_else(|| item.span().start(), |a| a.span().start());
                self.0.push((start, item.span().end()));
                return;
            }
            syn::visit::visit_item(self, item);
        }
    }

    let Ok(file) = syn::parse_file(source) else {
        panic!("TUI authority ratchet could not parse Rust source");
    };
    let mut visitor = TestItems(Vec::new());
    visitor.visit_file(&file);
    let mut offsets = Vec::with_capacity(source.lines().count() + 1);
    offsets.push(0usize);
    for (index, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            offsets.push(index + 1);
        }
    }
    let byte_offset =
        |point: proc_macro2::LineColumn| offsets[point.line.saturating_sub(1)] + point.column;
    let mut bytes = source.as_bytes().to_vec();
    for (start, end) in visitor.0 {
        for byte in &mut bytes[byte_offset(start)..byte_offset(end)] {
            if *byte != b'\n' {
                *byte = b' ';
            }
        }
    }
    String::from_utf8(bytes).expect("Rust source remains UTF-8 after masking")
}

fn use_tree_has_rename(tree: &syn::UseTree) -> bool {
    match tree {
        syn::UseTree::Rename(_) => true,
        syn::UseTree::Path(path) => use_tree_has_rename(&path.tree),
        syn::UseTree::Group(group) => group.items.iter().any(use_tree_has_rename),
        syn::UseTree::Name(_) | syn::UseTree::Glob(_) => false,
    }
}

fn obscured_authority_findings(source: &str) -> Vec<String> {
    struct AuthorityVisitor(Vec<String>);
    impl<'ast> Visit<'ast> for AuthorityVisitor {
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            let tokens: String = item
                .to_token_stream()
                .to_string()
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect();
            let authority = [
                "std::fs",
                "std::process",
                "std::net",
                "tokio::fs",
                "tokio::process",
                "tokio::net",
                "cockpit_core::agents",
                "cockpit_core::assistants",
                "cockpit_core::db",
                "cockpit_config::extended::ExtendedConfigDoc",
                "cockpit_config::providers::ConfigDoc",
                "cockpit_config::dirs::scaffold_config_dir",
            ]
            .iter()
            .any(|path| tokens.contains(path));
            let root_alias = tokens.starts_with("usestdas")
                || tokens.starts_with("usetokioas")
                || tokens.starts_with("usecockpit_coreas")
                || tokens.starts_with("usecockpit_configas");
            if (authority || root_alias)
                && (use_tree_has_rename(&item.tree)
                    || !matches!(&item.vis, syn::Visibility::Inherited))
            {
                self.0.push(format!(
                    "line {}: aliased or re-exported authority import: {tokens}",
                    item.span().start().line
                ));
            }
            syn::visit::visit_item_use(self, item);
        }

        fn visit_macro(&mut self, value: &'ast syn::Macro) {
            let tokens: String = value
                .tokens
                .to_string()
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            if [
                "std::fs",
                "std::process",
                "std::net",
                "tokio::fs",
                "tokio::process",
                "tokio::net",
                "cockpit_core::agents",
                "cockpit_core::assistants",
                "cockpit_core::db",
                "cockpit_config::extended",
                "cockpit_config::providers",
                "cockpit_config::config",
            ]
            .iter()
            .any(|path| tokens.contains(path))
            {
                self.0.push(format!(
                    "line {}: macro obscures authority path",
                    value.span().start().line
                ));
            }
            syn::visit::visit_macro(self, value);
        }
    }
    let file = syn::parse_file(source).expect("production source remains parseable");
    let mut visitor = AuthorityVisitor(Vec::new());
    visitor.visit_file(&file);
    visitor.0
}

/// A `*_tests.rs` spelling is not evidence that a module is test-only. Accept
/// the exclusion only when syn finds an owning `mod` item with `#[cfg(test)]`.
fn is_explicit_cfg_test_module(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|value| value.to_str()) else {
        return false;
    };
    let Some(parent) = path.parent() else {
        return false;
    };
    let declarations = [parent.join("mod.rs"), parent.with_extension("rs")];
    declarations.into_iter().any(|owner| {
        let Ok(source) = fs::read_to_string(owner) else {
            return false;
        };
        let Ok(file) = syn::parse_file(&source) else {
            panic!("TUI authority ratchet could not parse module owner");
        };
        file.items.into_iter().any(|item| {
            matches!(item, syn::Item::Mod(module) if module.ident == stem && cfg_test_only(&module.attrs))
        })
    })
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
    let agents = production_source(&read("crates/cockpit-tui/src/tui/settings/agents_page.rs"));
    let goals = production_source(&read("crates/cockpit-tui/src/tui/goal_settings_pane.rs"));
    let tools = production_source(&read("crates/cockpit-tui/src/tui/tools_pane.rs"));
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
                || is_explicit_cfg_test_module(&path)
            {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let production = production_source(&source);
            findings.extend(
                obscured_authority_findings(&production)
                    .into_iter()
                    .map(|finding| format!("{}: {finding}", path.display())),
            );
            for forbidden in [
                "cockpit_core::agents::resolve(",
                "cockpit_core::agents::list_all(",
                "cockpit_core::agents::eject_builtin(",
                "cockpit_core::agents::find_override(",
                "cockpit_core::agents::reset_all_builtins(",
                "cockpit_core::agents::load_workspace_named_from_file(",
                "cockpit_core::agents::load_daemon_local_named_from_file(",
                "cockpit_core::assistants::load_from_home(",
                "cockpit_core::assistants::load_verified(",
                "ExtendedConfigDoc",
                "ConfigDoc::load(",
                "ConfigDoc::providers_from_paths(",
                "McpConfig::discover(",
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
fn production_process_and_network_authority_is_exactly_allowlisted() {
    const AUTHORITY: &[&str] = &[
        "std::process::Command::new(",
        "tokio::process::Command::new(",
        "std::net::TcpStream::connect(",
        "tokio::net::TcpStream::connect(",
        "tokio::net::TcpListener::bind(",
        "tokio::net::UdpSocket::bind(",
        "reqwest::Client::",
        "tokio_tungstenite::",
    ];
    const ALLOWED: &[(&str, &str)] = &[
        (
            "crates/cockpit-tui/src/clipboard/service.rs",
            "let mut child = std::process::Command::new(\"tmux\")",
        ),
        (
            "crates/cockpit-tui/src/tui/app/terminal_suspend.rs",
            "let mut child = tokio::process::Command::new(&editor)",
        ),
        (
            "crates/cockpit-tui/src/tui/app/terminal_suspend.rs",
            "std::process::Command::new(\"true\")",
        ),
        (
            "crates/cockpit-tui/src/tui/app/events.rs",
            "command = std::process::Command::new(\"cmd\");",
        ),
        (
            "crates/cockpit-tui/src/tui/app/events.rs",
            "command = std::process::Command::new(shell);",
        ),
        (
            "crates/cockpit-tui/src/tui/app/events.rs",
            "let mut command = std::process::Command::new(\"git\");",
        ),
        (
            "crates/cockpit-tui/src/clipboard/executable.rs",
            "let mut cmd = Command::new(path);",
        ),
    ];

    fn visit(
        path: &Path,
        findings: &mut Vec<String>,
        hits: &mut std::collections::HashMap<(&'static str, &'static str), usize>,
    ) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                visit(&path, findings, hits);
                continue;
            }
            if path.extension().and_then(|value| value.to_str()) != Some("rs")
                || path.components().any(|part| part.as_os_str() == "tests")
                || is_explicit_cfg_test_module(&path)
            {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let production = production_source(&source);
            let relative = path.strip_prefix(repo_root()).unwrap().to_string_lossy();
            for (line_number, line) in production.lines().enumerate() {
                for authority in AUTHORITY {
                    if !line.contains(authority) {
                        continue;
                    }
                    if let Some(allowed) = ALLOWED
                        .iter()
                        .find(|(file, exact)| relative == *file && line.trim() == *exact)
                    {
                        *hits.entry(*allowed).or_default() += 1;
                    } else {
                        findings.push(format!(
                            "{relative}:{}: unowned authority {authority}",
                            line_number + 1
                        ));
                    }
                }
                let imported_command_call = line.contains("Command::new(")
                    && !line.contains("std::process::Command::new(")
                    && !line.contains("tokio::process::Command::new(");
                if imported_command_call {
                    if let Some(allowed) = ALLOWED
                        .iter()
                        .find(|(file, exact)| relative == *file && line.trim() == *exact)
                    {
                        *hits.entry(*allowed).or_default() += 1;
                    } else {
                        findings.push(format!(
                            "{relative}:{}: imported process Command authority",
                            line_number + 1
                        ));
                    }
                }
                let trimmed = line.trim();
                if (trimmed.starts_with("use std::process")
                    || trimmed.starts_with("use tokio::process")
                    || trimmed.starts_with("use std as ")
                    || trimmed.starts_with("use tokio as "))
                    && trimmed != "use std::process::{Command, Stdio};"
                    && trimmed != "use std::process::ExitStatus;"
                {
                    findings.push(format!(
                        "{relative}:{}: process import/alias obscures authority audit",
                        line_number + 1
                    ));
                }
            }
            let compact: String = production
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect();
            for statement in compact
                .split(';')
                .filter(|statement| statement.starts_with("use"))
            {
                let authority = statement.contains("std::process")
                    || statement.contains("tokio::process")
                    || statement.contains("std::net")
                    || statement.contains("tokio::net")
                    || statement.contains("std::{process")
                    || statement.contains("tokio::{process")
                    || statement.contains("std::{net")
                    || statement.contains("tokio::{net");
                if authority && statement.contains("as") {
                    findings.push(format!(
                        "{relative}: grouped/renamed process or network import obscures audit: {statement}"
                    ));
                }
            }
        }
    }

    let mut findings = Vec::new();
    let mut hits = std::collections::HashMap::new();
    visit(
        &repo_root().join("crates/cockpit-tui/src"),
        &mut findings,
        &mut hits,
    );
    for allowed in ALLOWED {
        let count = hits.get(allowed).copied().unwrap_or_default();
        if count != 1 {
            findings.push(format!(
                "allowlisted host integration must occur exactly once: {}: {:?} (found {count})",
                allowed.0, allowed.1
            ));
        }
    }
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
        "OpenOptions::new(",
        "std::fs::File::options",
        ".write(true)",
        ".append(true)",
        ".truncate(true)",
        ".create(true)",
        ".create_new(true)",
        ".set_len(",
        "file.write(",
        "temp.write(",
        "stdin.write(",
        "out.write(",
        "lock.write(",
        "tokio::fs::write",
        "tokio::fs::remove_file",
        "tokio::fs::create_dir_all",
        "tokio::fs::set_permissions",
        "cockpit_config::config::write_config_bytes_atomic",
        ".write_all(",
    ];
    // Every exception is a single reviewed source line, not a whole-file
    // exemption. Adding a second mutation in an allowed host-integration file
    // must therefore update this inventory explicitly.
    const ALLOWED_LINES: &[(&str, &str)] = &[
        (
            "crates/cockpit-tui/src/tui/settings/agents_page.rs",
            "cockpit_config::config::write_config_bytes_atomic(&staging.path, text.as_bytes())",
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
        ("crates/cockpit-tui/src/tui/async_action.rs", ".write(true)"),
        (
            "crates/cockpit-tui/src/tui/image_path_probe.rs",
            "std::fs::OpenOptions::new() // Unix no-follow read-only handle.",
        ),
        (
            "crates/cockpit-tui/src/tui/image_path_probe.rs",
            "std::fs::OpenOptions::new() // Windows reparse-point read-only handle.",
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
                || is_explicit_cfg_test_module(&path)
            {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            let production = production_source(&source);
            let relative = path.strip_prefix(repo_root()).unwrap().to_string_lossy();
            for (line_number, line) in production.lines().enumerate() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("//") {
                    continue;
                }
                let matched: Vec<_> = MUTATIONS
                    .iter()
                    .filter(|mutation| line.contains(**mutation))
                    .collect();
                if !matched.is_empty() {
                    let allowed = ALLOWED_LINES
                        .iter()
                        .find(|(file, exact)| relative == *file && line.trim() == *exact);
                    if let Some(allowed) = allowed {
                        *allowed_hits.entry(*allowed).or_default() += 1;
                    } else {
                        findings.push(format!(
                            "{relative}:{}: {}",
                            line_number + 1,
                            matched.into_iter().copied().collect::<Vec<_>>().join(", ")
                        ));
                    }
                }
            }
            if production.contains("use std::fs as ")
                || production.contains("use tokio::fs as ")
                || production.contains("use std::fs::{self")
                || production.contains("use tokio::fs::{self")
                || production.lines().any(|line| line.trim() == "use std::fs;")
                || production
                    .lines()
                    .any(|line| line.trim() == "use tokio::fs;")
            {
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
            let compact: String = production
                .chars()
                .filter(|ch| !ch.is_whitespace())
                .collect();
            for statement in compact
                .split(';')
                .filter(|statement| statement.starts_with("use"))
            {
                let authority_import = statement.contains("std::fs")
                    || statement.contains("tokio::fs")
                    || statement.contains("std::{fs")
                    || statement.contains("tokio::{fs");
                let mutation_import = [
                    "write",
                    "remove_file",
                    "remove_dir",
                    "rename",
                    "create_dir",
                    "create_dir_all",
                    "set_permissions",
                    "OpenOptions",
                ]
                .iter()
                .any(|name| statement.contains(name));
                if authority_import && (statement.contains("as") || mutation_import) {
                    findings.push(format!(
                        "{relative}: grouped/renamed filesystem authority import obscures audit: {statement}"
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

#[test]
fn syntax_aware_authority_filter_has_negative_fixtures() {
    let source = r#"
        #[cfg(test)]
        mod tests { fn hidden() { std::fs::write("x", b"x").unwrap(); } }
        fn production_after_tests() { std::fs::write("x", b"x").unwrap(); }
    "#;
    let production = production_source(source);
    assert!(!production.contains("hidden"));
    assert!(production.contains("production_after_tests"));
    assert!(production.contains("std::fs::write"));

    for fixture in [
        "use std::fs as storage;",
        "pub use tokio::process::Command;",
        "use cockpit_core as owner;",
        "macro_rules! hidden { () => { std::net::TcpStream::connect(\"x\") } }",
    ] {
        assert!(
            !obscured_authority_findings(fixture).is_empty(),
            "negative authority fixture escaped: {fixture}"
        );
    }
    assert!(obscured_authority_findings("use std::process::{Command, Stdio};").is_empty());
}
