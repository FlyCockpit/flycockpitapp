use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};

const RAW_AUTHORITY: &[&str] = &[
    "OwnedDaemonSession",
    "probe_or_spawn",
    "ConnectedDaemon",
    "take_owned_daemon_guard",
    "spawn_signal_shutdown",
    "EphemeralDaemonGuard",
];
const EXPECTED_RUNNERS: &[(&str, &str)] = &[
    ("commands/doctor.rs", "run"),
    ("commands/init.rs", "run"),
    ("commands/invocation.rs", "cancel"),
    ("commands/invocation.rs", "status"),
    ("commands/learn.rs", "run"),
    ("commands/run.rs", "run"),
    ("commands/schedule.rs", "create"),
    ("commands/schedule.rs", "list"),
    ("commands/schedule.rs", "run_now"),
    ("commands/schedule.rs", "set_enabled"),
    ("commands/session.rs", "answer_inner"),
];

fn rust_files(root: &Path) -> Vec<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn is_test_only(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr
                    .parse_args::<syn::Path>()
                    .is_ok_and(|path| path.is_ident("test")))
    })
}

#[derive(Default)]
struct UseInspection {
    names: Vec<String>,
    renamed: bool,
    glob: bool,
}

fn inspect_use(tree: &syn::UseTree, inspection: &mut UseInspection) {
    match tree {
        syn::UseTree::Path(path) => {
            inspection.names.push(path.ident.to_string());
            inspect_use(&path.tree, inspection);
        }
        syn::UseTree::Name(name) => inspection.names.push(name.ident.to_string()),
        syn::UseTree::Rename(rename) => {
            inspection.names.push(rename.ident.to_string());
            inspection.names.push(rename.rename.to_string());
            inspection.renamed = true;
        }
        syn::UseTree::Glob(_) => inspection.glob = true,
        syn::UseTree::Group(group) => {
            for item in &group.items {
                inspect_use(item, inspection);
            }
        }
    }
}

struct Inventory<'a> {
    relative: &'a str,
    function: Option<String>,
    test_depth: usize,
    runner_callee_depth: usize,
    runners: Vec<(String, String)>,
    violations: Vec<String>,
}

impl Inventory<'_> {
    fn violation(&mut self, message: impl Into<String>) {
        self.violations
            .push(format!("{}: {}", self.relative, message.into()));
    }
}

impl<'ast> Visit<'ast> for Inventory<'_> {
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = self.function.replace(item.sig.ident.to_string());
        let test_only = usize::from(is_test_only(&item.attrs));
        self.test_depth += test_only;
        visit::visit_item_fn(self, item);
        self.test_depth -= test_only;
        self.function = previous;
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        let test_only = usize::from(is_test_only(&item.attrs));
        self.test_depth += test_only;
        visit::visit_item_mod(self, item);
        self.test_depth -= test_only;
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut use_tree = UseInspection::default();
        inspect_use(&item.tree, &mut use_tree);
        if self.test_depth == 0
            && (RAW_AUTHORITY
                .iter()
                .any(|name| use_tree.names.iter().any(|part| part == name))
                || (use_tree.glob && use_tree.names.iter().any(|part| part == "client")))
        {
            self.violation("raw lifecycle authority import or client glob");
        }
        if self.test_depth == 0
            && use_tree.names.iter().any(|part| part == "run_owned_daemon")
            && (use_tree.renamed || use_tree.glob)
        {
            self.violation("runner imports may not be renamed or globbed");
        }
        let narrow_cli_facade = self.relative == "lib.rs"
            && [
                "cockpit_core",
                "daemon",
                "client",
                "run_owned_daemon",
                "OwnedSessionMode",
                "OwnedDaemonRunError",
                "ensure_persistent_daemon",
            ]
            .iter()
            .all(|name| use_tree.names.iter().any(|part| part == name));
        if self.test_depth == 0
            && !matches!(item.vis, syn::Visibility::Inherited)
            && !narrow_cli_facade
            && (use_tree.names.iter().any(|part| part == "run_owned_daemon")
                || RAW_AUTHORITY
                    .iter()
                    .any(|name| use_tree.names.iter().any(|part| part == name)))
        {
            self.violation("lifecycle authority may not be re-exported");
        }
        visit::visit_item_use(self, item);
    }

    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        let is_runner = matches!(&*call.func, syn::Expr::Path(path)
            if path.path.segments.last().is_some_and(|segment| segment.ident == "run_owned_daemon"));
        if is_runner && self.test_depth == 0 {
            if let Some(function) = self.function.clone() {
                self.runners.push((self.relative.to_owned(), function));
            } else {
                self.violation("runner call outside a named function");
            }
        }
        self.runner_callee_depth += usize::from(is_runner);
        self.visit_expr(&call.func);
        self.runner_callee_depth -= usize::from(is_runner);
        for argument in &call.args {
            self.visit_expr(argument);
        }
    }

    fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
        if self.test_depth == 0 {
            for segment in &path.path.segments {
                let name = segment.ident.to_string();
                if RAW_AUTHORITY.contains(&name.as_str()) {
                    self.violation(format!("raw lifecycle authority `{name}`"));
                }
                if name == "run_owned_daemon" && self.runner_callee_depth == 0 {
                    self.violation("runner may only be used as a direct call");
                }
            }
        }
        visit::visit_expr_path(self, path);
    }

    fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
        if self.test_depth == 0 {
            for segment in &path.path.segments {
                let name = segment.ident.to_string();
                if RAW_AUTHORITY.contains(&name.as_str()) {
                    self.violation(format!("raw lifecycle authority type `{name}`"));
                }
            }
        }
        visit::visit_type_path(self, path);
    }

    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        if self.test_depth == 0 {
            let tokens = invocation.tokens.to_string();
            for name in RAW_AUTHORITY.iter().copied().chain(["run_owned_daemon"]) {
                if tokens
                    .split(|character: char| !character.is_alphanumeric() && character != '_')
                    .any(|token| token == name)
                {
                    self.violation(format!("lifecycle symbol `{name}` hidden in macro"));
                }
            }
        }
        visit::visit_macro(self, invocation);
    }
}

fn inspect<'a>(source: &str, relative: &'a str) -> Inventory<'a> {
    let file = syn::parse_file(source).unwrap();
    let mut inventory = Inventory {
        relative,
        function: None,
        test_depth: 0,
        runner_callee_depth: 0,
        runners: Vec::new(),
        violations: Vec::new(),
    };
    inventory.visit_file(&file);
    inventory
}

#[test]
fn production_cli_has_one_structural_lifecycle_runner_inventory() {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut runners = Vec::new();
    let mut violations = Vec::new();
    for path in rust_files(&source_root) {
        let relative = path.strip_prefix(&source_root).unwrap().to_string_lossy();
        let source = std::fs::read_to_string(&path).unwrap();
        let inventory = inspect(&source, &relative);
        runners.extend(inventory.runners);
        violations.extend(inventory.violations);
    }
    runners.sort();
    let mut expected = EXPECTED_RUNNERS
        .iter()
        .map(|(file, function)| ((*file).to_owned(), (*function).to_owned()))
        .collect::<Vec<_>>();
    expected.sort();
    assert!(violations.is_empty(), "{}", violations.join("\n"));
    assert_eq!(runners, expected, "production runner inventory changed");
}

#[test]
fn core_runner_is_the_only_raw_owner() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/cockpit-core/src/daemon/client.rs"),
    )
    .unwrap();
    let file = syn::parse_file(&source).unwrap();
    let session = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Struct(item) if item.ident == "OwnedDaemonSession" => Some(item),
            _ => None,
        })
        .unwrap();
    assert!(matches!(session.vis, syn::Visibility::Inherited));
    let implementation = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("OwnedDaemonSession")) =>
            {
                Some(item)
            }
            _ => None,
        })
        .unwrap();
    for name in ["connect", "client", "finish"] {
        let method = implementation
            .items
            .iter()
            .find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
            .unwrap();
        assert!(
            matches!(method.vis, syn::Visibility::Inherited),
            "{name} leaked"
        );
    }
    let runner = file
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(item) if item.sig.ident == "run_owned_daemon" => Some(item),
            _ => None,
        })
        .unwrap();
    assert!(matches!(runner.vis, syn::Visibility::Public(_)));
    assert!(source.contains("let session = OwnedDaemonSession::connect(mode)"));
    assert!(source.contains("let result = operation(session.client()).await;"));
    assert!(source.contains(".finish(result)"));
    assert!(source.contains("impl Drop for OwnedDaemonSession"));
}

#[test]
fn inventory_rejects_unlisted_alias_function_item_and_macro() {
    for source in [
        "use crate::daemon::client::run_owned_daemon as run; async fn extra() { run(mode, op).await; }",
        "async fn extra() { let run = run_owned_daemon; run(mode, op).await; }",
        "macro_rules! hidden { () => { run_owned_daemon(mode, op).await } }",
        "async fn extra() { OwnedDaemonSession::connect(mode).await; }",
    ] {
        let inventory = inspect(source, "fixture.rs");
        assert!(
            !inventory.violations.is_empty(),
            "accepted fixture: {source}"
        );
    }

    let inventory = inspect(
        "async fn surprise() { run_owned_daemon(mode, op).await; }",
        "commands/surprise.rs",
    );
    assert_eq!(inventory.runners.len(), 1);
    assert!(!EXPECTED_RUNNERS.contains(&(
        inventory.runners[0].0.as_str(),
        inventory.runners[0].1.as_str()
    )));
}
