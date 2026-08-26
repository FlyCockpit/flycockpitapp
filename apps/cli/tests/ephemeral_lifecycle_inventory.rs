use std::path::{Path, PathBuf};

const RAW_AUTHORITY: &[&str] = &[
    "probe_or_spawn",
    "ConnectedDaemon",
    "take_owned_daemon_guard",
    "spawn_signal_shutdown",
    "EphemeralDaemonGuard::new",
];
fn flatten_use(tree: &syn::UseTree, prefix: &mut Vec<String>, paths: &mut Vec<String>) {
    match tree {
        syn::UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, paths);
            prefix.pop();
        }
        syn::UseTree::Name(name) => {
            let mut path = prefix.clone();
            path.push(name.ident.to_string());
            paths.push(path.join("::"));
        }
        syn::UseTree::Rename(rename) => {
            let mut path = prefix.clone();
            path.push(rename.ident.to_string());
            paths.push(path.join("::"));
        }
        syn::UseTree::Glob(_) => paths.push(format!("{}::*", prefix.join("::"))),
        syn::UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use(tree, prefix, paths);
            }
        }
    }
}

fn inspect_items(items: &[syn::Item], violations: &mut Vec<String>) {
    for item in items {
        match item {
            syn::Item::Use(item) => {
                let mut paths = Vec::new();
                flatten_use(&item.tree, &mut Vec::new(), &mut paths);
                for path in paths {
                    let public = !matches!(item.vis, syn::Visibility::Inherited);
                    if (public && path == "cockpit_core::daemon")
                        || path.ends_with("daemon::client::*")
                    {
                        violations.push(path);
                    }
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_, items)) = &module.content {
                    inspect_items(items, violations);
                }
            }
            _ => {}
        }
    }
}

fn source_violations(source: &str) -> Vec<String> {
    let mut violations = RAW_AUTHORITY
        .iter()
        .filter(|symbol| source.contains(**symbol))
        .map(|symbol| (*symbol).to_string())
        .collect::<Vec<_>>();
    if let Ok(file) = syn::parse_file(source) {
        inspect_items(&file.items, &mut violations);
    } else {
        violations.push("unparseable Rust source".into());
    }
    violations
}

fn rust_sources(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut sources = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                sources.push(path);
            }
        }
    }
    sources.sort();
    sources
}

#[test]
fn cli_production_has_no_raw_daemon_lifecycle_authority() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let violations = rust_sources(&root)
        .into_iter()
        .flat_map(|path| {
            let source = std::fs::read_to_string(&path).unwrap();
            source_violations(&source)
                .into_iter()
                .map(move |symbol| format!("{}: {symbol}", path.display()))
        })
        .collect::<Vec<_>>();
    assert!(violations.is_empty(), "{}", violations.join("\n"));
}

#[test]
fn owned_session_is_the_single_cli_lifecycle_facade() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let facade =
        std::fs::read_to_string(workspace.join("crates/cockpit-core/src/daemon/client.rs"))
            .unwrap();
    for contract in [
        "pub struct OwnedDaemonSession",
        "pub async fn connect(mode: LifecycleMode)",
        "let mut connected = probe_or_spawn(mode).await?",
        "let guard = connected.take_owned_daemon_guard()",
        "spawn_signal_shutdown(",
        "pub fn client(&self) -> &DaemonClient",
        "pub async fn finish<T>",
        "aggregate_shutdown_result(result, shutdown)",
        "impl Drop for OwnedDaemonSession",
        "self.signal_task.take()",
    ] {
        assert!(
            facade.contains(contract),
            "missing facade contract: {contract}"
        );
    }
    for private_raw_contract in [
        "pub(crate) struct ConnectedDaemon",
        "pub(crate) async fn probe_or_spawn",
    ] {
        assert!(facade.contains(private_raw_contract));
    }
    let owned_fields = facade
        .split_once("pub struct OwnedDaemonSession {")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    for forbidden_public_field in [
        "pub client: DaemonClient",
        "pub guard: Option<",
        "pub signal_task: Option<",
    ] {
        assert!(!owned_fields.contains(forbidden_public_field));
    }
}

#[test]
fn adversarial_raw_alias_reexport_glob_and_helper_are_rejected() {
    for source in [
        "use crate::daemon::client::probe_or_spawn as connect;",
        "pub use cockpit_core::daemon;",
        "pub use cockpit_core::{daemon as runtime};",
        "use cockpit_core::daemon::client::*;",
        "async fn helper() { crate::daemon::client::probe_or_spawn(mode).await; }",
        "macro_rules! hidden { () => { ConnectedDaemon } }",
    ] {
        assert!(!source_violations(source).is_empty(), "accepted: {source}");
    }
}

#[test]
fn omitted_finish_still_aborts_signal_watcher_before_guard_drop() {
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let facade =
        std::fs::read_to_string(workspace.join("crates/cockpit-core/src/daemon/client.rs"))
            .unwrap();
    let drop_impl = facade
        .split_once("impl Drop for OwnedDaemonSession")
        .unwrap()
        .1;
    let take = drop_impl.find("self.signal_task.take()").unwrap();
    let abort = drop_impl.find("task.abort()").unwrap();
    assert!(take < abort);
    assert!(drop_impl.contains("guard` deliberately remains armed"));
}

#[test]
fn every_ephemeral_command_uses_and_finishes_the_owned_session() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/commands");
    for command in [
        "doctor.rs",
        "init.rs",
        "invocation.rs",
        "learn.rs",
        "run.rs",
        "schedule.rs",
        "session.rs",
    ] {
        let source = std::fs::read_to_string(root.join(command)).unwrap();
        assert!(
            source.contains("OwnedDaemonSession"),
            "{command} does not acquire the owned-session facade"
        );
        assert!(
            source.contains(".finish("),
            "{command} does not explicitly finish its owned session"
        );
    }
}
