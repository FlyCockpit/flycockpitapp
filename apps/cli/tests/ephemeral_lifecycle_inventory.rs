use std::collections::HashMap;
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
            if RAW_AUTHORITY.contains(&token) || token == "OwnedDaemonSession" {
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
                    if path == "cockpit_core::daemon"
                        || path.ends_with("daemon::client::*")
                        || (public && path.ends_with("daemon::client::OwnedDaemonSession"))
                        || (public && path.contains("daemon::client"))
                    {
                        violations.push(path);
                    }
                }
                fn reject_renames(
                    tree: &syn::UseTree,
                    prefix: &mut Vec<String>,
                    violations: &mut Vec<String>,
                ) {
                    match tree {
                        syn::UseTree::Rename(rename)
                            if rename.ident == "OwnedDaemonSession"
                                || (rename.ident == "client"
                                    && prefix
                                        .iter()
                                        .map(String::as_str)
                                        .eq(["crate", "daemon"])) =>
                        {
                            violations.push(format!("renamed lifecycle facade: {}", rename.ident));
                        }
                        syn::UseTree::Path(path) => {
                            prefix.push(path.ident.to_string());
                            reject_renames(&path.tree, prefix, violations);
                            prefix.pop();
                        }
                        syn::UseTree::Group(group) => {
                            for tree in &group.items {
                                reject_renames(tree, prefix, violations);
                            }
                        }
                        _ => {}
                    }
                }
                reject_renames(&item.tree, &mut Vec::new(), violations);
            }
            syn::Item::Type(alias) => {
                let mut facade = OwnedFacade::default();
                facade.visit_type(&alias.ty);
                violations.extend(facade.0);
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

#[derive(Default)]
struct OwnedFacade(Vec<String>);

impl<'ast> Visit<'ast> for OwnedFacade {
    fn visit_ident(&mut self, ident: &'ast syn::Ident) {
        if ident == "OwnedDaemonSession" {
            self.0.push(ident.to_string());
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
    scopes: Vec<HashMap<String, Option<u64>>>,
    acquisitions: Vec<(String, String, u64, usize)>,
    finishes: Vec<(u64, usize)>,
    unresolved_finishes: Vec<(String, usize)>,
    violations: Vec<String>,
    next_binding: u64,
    position: usize,
    function: String,
    closure_depth: usize,
    branch_depth: usize,
    dead_depth: usize,
    connect_calls: usize,
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
    fn visit_item_fn(&mut self, function: &'ast syn::ItemFn) {
        let old = std::mem::replace(&mut self.function, function.sig.ident.to_string());
        visit::visit_item_fn(self, function);
        self.function = old;
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        self.scopes.push(HashMap::new());
        let mut terminated = false;
        for statement in &block.stmts {
            if terminated {
                self.dead_depth += 1;
            }
            self.visit_stmt(statement);
            if terminated {
                self.dead_depth -= 1;
            }
            terminated |= statement_terminates(statement);
        }
        self.scopes.pop();
    }

    fn visit_expr_closure(&mut self, closure: &'ast syn::ExprClosure) {
        self.closure_depth += 1;
        visit::visit_expr_closure(self, closure);
        self.closure_depth -= 1;
    }

    fn visit_expr_async(&mut self, expression: &'ast syn::ExprAsync) {
        self.closure_depth += 1;
        visit::visit_expr_async(self, expression);
        self.closure_depth -= 1;
    }

    fn visit_expr_if(&mut self, expression: &'ast syn::ExprIf) {
        self.branch_depth += 1;
        visit::visit_expr_if(self, expression);
        self.branch_depth -= 1;
    }

    fn visit_expr_match(&mut self, expression: &'ast syn::ExprMatch) {
        self.branch_depth += 1;
        visit::visit_expr_match(self, expression);
        self.branch_depth -= 1;
    }

    fn visit_expr_loop(&mut self, expression: &'ast syn::ExprLoop) {
        self.branch_depth += 1;
        visit::visit_expr_loop(self, expression);
        self.branch_depth -= 1;
    }

    fn visit_expr_while(&mut self, expression: &'ast syn::ExprWhile) {
        self.branch_depth += 1;
        visit::visit_expr_while(self, expression);
        self.branch_depth -= 1;
    }

    fn visit_expr_for_loop(&mut self, expression: &'ast syn::ExprForLoop) {
        self.branch_depth += 1;
        visit::visit_expr_for_loop(self, expression);
        self.branch_depth -= 1;
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let mut finder = ConnectFinder(false);
        finder.visit_expr_call(call);
        if finder.0 {
            self.connect_calls += 1;
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.position += 1;
        if let Some(init) = &local.init {
            let mut finder = ConnectFinder(false);
            finder.visit_expr(&init.expr);
            if finder.0 {
                let syn::Pat::Ident(binding) = &local.pat else {
                    self.violations
                        .push("owned session acquired through non-identifier pattern".into());
                    visit::visit_local(self, local);
                    return;
                };
                if self.closure_depth > 0 {
                    self.violations
                        .push("owned session acquired in a deferred closure".into());
                }
                if self.branch_depth > 0 {
                    self.violations
                        .push("owned session acquired in a conditional branch".into());
                }
                self.next_binding += 1;
                let id = self.next_binding;
                self.scopes
                    .last_mut()
                    .expect("local scope")
                    .insert(binding.ident.to_string(), Some(id));
                self.acquisitions.push((
                    self.function.clone(),
                    binding.ident.to_string(),
                    id,
                    self.position,
                ));
            } else if let syn::Expr::Path(path) = init.expr.as_ref()
                && let Some(name) = path.path.get_ident()
                && self.resolve(&name.to_string()).is_some()
            {
                self.violations
                    .push("owned session moved into an alias".into());
            } else if let syn::Pat::Ident(binding) = &local.pat {
                self.scopes
                    .last_mut()
                    .expect("local scope")
                    .insert(binding.ident.to_string(), None);
            }
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.position += 1;
        if call.method == "finish"
            && let syn::Expr::Path(receiver) = call.receiver.as_ref()
            && let Some(ident) = receiver.path.get_ident()
        {
            let name = ident.to_string();
            if let Some(id) = self.resolve(&name) {
                if self.closure_depth > 0 || self.branch_depth > 0 || self.dead_depth > 0 {
                    self.violations.push(
                        "owned session finished in deferred, conditional, or dead control flow"
                            .into(),
                    );
                } else {
                    self.finishes.push((id, self.position));
                }
            } else {
                self.unresolved_finishes.push((name, self.position));
            }
        }
        visit::visit_expr_method_call(self, call);
    }
}

fn statement_terminates(statement: &syn::Stmt) -> bool {
    let syn::Stmt::Expr(expression, _) = statement else {
        return false;
    };
    match expression {
        syn::Expr::Return(_) | syn::Expr::Break(_) | syn::Expr::Continue(_) => true,
        syn::Expr::Loop(loop_expression) => !loop_expression
            .body
            .stmts
            .iter()
            .any(|statement| matches!(statement, syn::Stmt::Expr(syn::Expr::Break(_), _))),
        syn::Expr::Macro(invocation) => {
            invocation.mac.path.segments.last().is_some_and(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "panic" | "unreachable" | "todo"
                )
            })
        }
        syn::Expr::Call(call) => match call.func.as_ref() {
            syn::Expr::Path(path) => path.path.segments.last().is_some_and(|segment| {
                matches!(segment.ident.to_string().as_str(), "exit" | "abort")
            }),
            _ => false,
        },
        _ => false,
    }
}

impl OwnedFlow {
    fn resolve(&self, name: &str) -> Option<u64> {
        for scope in self.scopes.iter().rev() {
            if let Some(binding) = scope.get(name) {
                return *binding;
            }
        }
        None
    }

    fn validate(&self) -> Vec<String> {
        let mut errors = self.violations.clone();
        if self.connect_calls != self.acquisitions.len() {
            errors.push("owned connect call is not a direct local acquisition".into());
        }
        for (function, name, id, acquired) in &self.acquisitions {
            let finishes = self
                .finishes
                .iter()
                .filter(|(finished, _)| finished == id)
                .collect::<Vec<_>>();
            if finishes.len() != 1 {
                errors.push(format!(
                    "{function}: owned binding {id} finished {} times",
                    finishes.len()
                ));
            } else if finishes[0].1 <= *acquired {
                errors.push(format!("{function}: finish precedes acquisition"));
            }
            if self
                .unresolved_finishes
                .iter()
                .any(|(finished, position)| finished == name && position < acquired)
            {
                errors.push(format!("{function}: finish precedes acquisition"));
            }
        }
        errors
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
        "use crate::daemon::client::OwnedDaemonSession as Session;",
        "use crate::daemon::client as lifecycle;",
        "pub use crate::daemon::client::OwnedDaemonSession;",
        "pub use crate::daemon::client;",
        "pub use cockpit_core::daemon::client as lifecycle;",
        "pub use crate::daemon::{self, client as lifecycle};",
        "type Session = crate::daemon::client::OwnedDaemonSession;",
        "macro_rules! extra_owned { () => { OwnedDaemonSession::connect(mode).await } }",
    ] {
        assert!(!source_violations(source).is_empty(), "accepted: {source}");
    }
}

#[test]
fn adversarial_finish_after_unconditional_termination_is_rejected() {
    for source in [
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; return; daemon.finish(result).await; }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; loop { break; daemon.finish(result).await; } }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; loop { continue; daemon.finish(result).await; } }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; panic!(); daemon.finish(result).await; }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; std::process::exit(1); daemon.finish(result).await; }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; loop {}; daemon.finish(result).await; }",
    ] {
        let mut flow = OwnedFlow::default();
        flow.visit_file(&syn::parse_file(source).unwrap());
        assert!(!flow.validate().is_empty(), "accepted: {source}");
    }
}

#[test]
fn ordinary_try_before_finish_remains_reachable() {
    let source = "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; operation()?; daemon.finish(result).await; }";
    let mut flow = OwnedFlow::default();
    flow.visit_file(&syn::parse_file(source).unwrap());
    assert!(flow.validate().is_empty(), "{:?}", flow.validate());
}

#[test]
fn run_finish_helper_is_test_only_and_uniquely_inventoried() {
    let source = include_str!("../src/commands/run.rs");
    assert_eq!(source.matches("fn finish_owned_run<").count(), 1);
    assert!(source.contains("#[cfg(test)]\nfn finish_owned_run<"));
}

#[test]
fn adversarial_unrelated_finish_does_not_satisfy_owned_acquisition() {
    let parsed = syn::parse_file(
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; other.finish(result).await; }",
    )
    .unwrap();
    let mut flow = OwnedFlow::default();
    flow.visit_file(&parsed);
    assert_eq!(flow.acquisitions.len(), 1);
    assert_eq!(flow.finishes.len(), 0);
    assert!(!flow.validate().is_empty());
}

#[test]
fn adversarial_shadow_move_deferred_and_finish_order_are_rejected() {
    for source in [
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; { let daemon = Other; daemon.finish(result).await; } }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; let moved = daemon; moved.finish(result).await; }",
        "fn run() { let deferred = || async { let daemon = OwnedDaemonSession::connect(mode).await?; daemon.finish(result).await; }; }",
        "async fn run() { if condition { let daemon = OwnedDaemonSession::connect(mode).await?; daemon.finish(result).await; } }",
        "async fn run() { daemon.finish(result).await; let daemon = OwnedDaemonSession::connect(mode).await?; }",
        "async fn run() { let (daemon,) = (OwnedDaemonSession::connect(mode).await?,); daemon.finish(result).await; }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; if false { daemon.finish(result).await; } }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; let deferred = || async { daemon.finish(result).await; }; }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; async { daemon.finish(result).await; }; }",
        "async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; while false { daemon.finish(result).await; } }",
    ] {
        let mut flow = OwnedFlow::default();
        flow.visit_file(&syn::parse_file(source).unwrap());
        assert!(!flow.validate().is_empty(), "accepted: {source}");
    }
}

#[test]
fn adversarial_hidden_additional_acquisitions_are_rejected() {
    for source in [
        "use crate::daemon::client::OwnedDaemonSession as Session; async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; daemon.finish(result).await; let extra = Session::connect(mode).await?; }",
        "type Session = OwnedDaemonSession; async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; daemon.finish(result).await; let extra = Session::connect(mode).await?; }",
        "macro_rules! extra_owned { () => { OwnedDaemonSession::connect(mode).await } } async fn run() { let daemon = OwnedDaemonSession::connect(mode).await?; daemon.finish(result).await; let extra = extra_owned!()?; }",
    ] {
        assert!(!source_violations(source).is_empty(), "accepted: {source}");
    }
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
    for (command, expected) in [
        ("doctor.rs", &["run"][..]),
        ("init.rs", &["run"][..]),
        ("invocation.rs", &["cancel", "status"][..]),
        ("learn.rs", &["run"][..]),
        ("run.rs", &["run"][..]),
        (
            "schedule.rs",
            &["create", "list", "run_now", "set_enabled"][..],
        ),
        ("session.rs", &["answer_inner"][..]),
    ] {
        let source = std::fs::read_to_string(root.join(command)).unwrap();
        let parsed = syn::parse_file(&source).unwrap();
        let mut flow = OwnedFlow::default();
        flow.visit_file(&parsed);
        let mut actual = flow
            .acquisitions
            .iter()
            .map(|(function, _, _, _)| function.as_str())
            .collect::<Vec<_>>();
        actual.sort_unstable();
        assert_eq!(actual, expected, "{command}: inventory drift");
        assert!(
            flow.validate().is_empty(),
            "{command}: {:?}",
            flow.validate()
        );
    }
}
