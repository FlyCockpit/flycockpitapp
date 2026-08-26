use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

const RAW_AUTHORITY: &[&str] = &[
    "probe_or_spawn",
    "ConnectedDaemon",
    "take_owned_daemon_guard",
    "spawn_signal_shutdown",
    "EphemeralDaemonGuard",
];

#[derive(Default)]
struct RawAuthority(Vec<String>);

impl<'ast> Visit<'ast> for RawAuthority {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        let ident = ident.to_string();
        if RAW_AUTHORITY.contains(&ident.as_str()) {
            self.0.push(ident);
        }
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        for token in invocation
            .tokens
            .to_string()
            .split(|character: char| !character.is_alphanumeric() && character != '_')
        {
            if RAW_AUTHORITY.contains(&token) {
                self.0.push(token.into());
            }
        }
        visit::visit_macro(self, invocation);
    }
}
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
    if let Ok(file) = syn::parse_file(source) {
        let mut raw = RawAuthority::default();
        raw.visit_file(&file);
        let mut violations = raw.0;
        inspect_items(&file.items, &mut violations);
        violations
    } else {
        vec!["unparseable Rust source".into()]
    }
}

fn public_core_raw_signatures(source: &str) -> Vec<String> {
    let file = syn::parse_file(source).unwrap();
    let mut violations = Vec::new();
    for item in file.items {
        match item {
            syn::Item::Fn(function) if matches!(function.vis, syn::Visibility::Public(_)) => {
                let mut raw = RawAuthority::default();
                raw.visit_signature(&function.sig);
                violations.extend(raw.0);
            }
            syn::Item::Struct(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                for field in item.fields {
                    if matches!(field.vis, syn::Visibility::Public(_)) {
                        let mut raw = RawAuthority::default();
                        raw.visit_type(&field.ty);
                        violations.extend(raw.0);
                    }
                }
            }
            syn::Item::Type(item) if matches!(item.vis, syn::Visibility::Public(_)) => {
                let mut raw = RawAuthority::default();
                raw.visit_type(&item.ty);
                violations.extend(raw.0);
            }
            syn::Item::Impl(item) => {
                for member in item.items {
                    if let syn::ImplItem::Fn(method) = member
                        && matches!(method.vis, syn::Visibility::Public(_))
                    {
                        let mut raw = RawAuthority::default();
                        raw.visit_signature(&method.sig);
                        violations.extend(raw.0);
                    }
                }
            }
            _ => {}
        }
    }
    violations
}

#[derive(Default)]
struct OwnedFlow {
    acquisitions: Vec<String>,
    finishes: Vec<String>,
}

struct ConnectFinder(bool);

impl<'ast> Visit<'ast> for ConnectFinder {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref() {
            let segments = path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            if segments.ends_with(&["OwnedDaemonSession".into(), "connect".into()]) {
                self.0 = true;
            }
        }
        visit::visit_expr_call(self, call);
    }
}

impl<'ast> Visit<'ast> for OwnedFlow {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let syn::Pat::Ident(binding) = &local.pat
            && let Some(init) = &local.init
        {
            let mut finder = ConnectFinder(false);
            finder.visit_expr(&init.expr);
            if finder.0 {
                self.acquisitions.push(binding.ident.to_string());
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        if call.method == "finish"
            && let syn::Expr::Path(receiver) = call.receiver.as_ref()
            && let Some(ident) = receiver.path.get_ident()
        {
            self.finishes.push(ident.to_string());
        }
        visit::visit_expr_method_call(self, call);
    }
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
    assert!(
        public_core_raw_signatures(&facade).is_empty(),
        "public core API leaks raw lifecycle authority"
    );
    for contract in [
        "pub struct OwnedDaemonSession",
        "pub async fn connect(mode: OwnedSessionMode)",
        "let mut connected = probe_or_spawn(mode.lifecycle()).await?",
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
    let owned_modes = facade
        .split_once("pub enum OwnedSessionMode")
        .unwrap()
        .1
        .split_once('}')
        .unwrap()
        .0;
    assert!(!owned_modes.contains("AttachOwnEphemeral"));
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
        "use crate::daemon::ephemeral_guard::EphemeralDaemonGuard as Guard; fn leak(value: Guard) { Guard::shutdown(&value); }",
        "pub fn leak() -> crate::daemon::client::ConnectedDaemon { unreachable!() }",
    ] {
        assert!(!source_violations(source).is_empty(), "accepted: {source}");
    }
}

#[test]
fn adversarial_unrelated_finish_does_not_satisfy_owned_acquisition() {
    let parsed = syn::parse_file(
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; other.finish(result).await; }",
    )
    .unwrap();
    let mut flow = OwnedFlow::default();
    flow.visit_file(&parsed);
    assert_eq!(flow.acquisitions, ["daemon"]);
    assert_eq!(flow.finishes, ["other"]);
    assert!(!flow.finishes.contains(&flow.acquisitions[0]));
}

#[test]
fn adversarial_public_core_facades_cannot_leak_raw_authority() {
    for source in [
        "pub fn leak() -> ConnectedDaemon { unreachable!() }",
        "pub struct Leak { pub guard: EphemeralDaemonGuard }",
        "struct Api; impl Api { pub fn leak(&self, value: ConnectedDaemon) {} }",
    ] {
        assert!(!public_core_raw_signatures(source).is_empty());
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
        let parsed = syn::parse_file(&source).unwrap();
        let mut flow = OwnedFlow::default();
        flow.visit_file(&parsed);
        assert!(!flow.acquisitions.is_empty(), "{command}: no acquisition");
        for acquisition in &flow.acquisitions {
            assert!(
                flow.finishes.contains(acquisition),
                "{command}: `{acquisition}` is not the receiver consumed by finish"
            );
        }
    }
}
