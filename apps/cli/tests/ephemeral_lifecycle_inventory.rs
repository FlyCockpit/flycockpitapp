use std::path::{Path, PathBuf};

use quote::ToTokens;
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
    fn possible_when_test_is_false(meta: &syn::Meta) -> (bool, bool) {
        match meta {
            syn::Meta::Path(path) if path.is_ident("test") => (true, false),
            syn::Meta::Path(_) | syn::Meta::NameValue(_) => (true, true),
            syn::Meta::List(list) => {
                let nested = list
                    .parse_args_with(
                        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
                    )
                    .map(|items| {
                        items
                            .iter()
                            .map(possible_when_test_is_false)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_else(|_| vec![(true, true)]);
                if list.path.is_ident("all") {
                    let can_be_true = nested.iter().all(|(_, can_true)| *can_true);
                    let can_be_false = nested.iter().any(|(can_false, _)| *can_false);
                    (can_be_false, can_be_true)
                } else if list.path.is_ident("any") {
                    let can_be_true = nested.iter().any(|(_, can_true)| *can_true);
                    let can_be_false = nested.iter().all(|(can_false, _)| *can_false);
                    (can_be_false, can_be_true)
                } else if list.path.is_ident("not") && nested.len() == 1 {
                    let (can_be_false, can_be_true) = nested[0];
                    (can_be_true, can_be_false)
                } else {
                    (true, true)
                }
            }
        }
    }

    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || (attr.path().is_ident("cfg")
                && attr.parse_args::<syn::Meta>().is_ok_and(|meta| {
                    let (_, can_be_true_without_test) = possible_when_test_is_false(&meta);
                    !can_be_true_without_test
                }))
    })
}

fn owned_session_occurrences_in_source(source: &str, relative: &str) -> Vec<String> {
    fn contains_owner(tokens: impl ToTokens) -> bool {
        tokens
            .to_token_stream()
            .to_string()
            .split(|character: char| !character.is_alphanumeric() && character != '_')
            .any(|token| token == "OwnedDaemonSession")
    }

    fn inspect_items(items: &[syn::Item], relative: &str, violations: &mut Vec<String>) {
        for item in items {
            let attrs = match item {
                syn::Item::Const(item) => item.attrs.as_slice(),
                syn::Item::Enum(item) => item.attrs.as_slice(),
                syn::Item::ExternCrate(item) => item.attrs.as_slice(),
                syn::Item::Fn(item) => item.attrs.as_slice(),
                syn::Item::ForeignMod(item) => item.attrs.as_slice(),
                syn::Item::Impl(item) => item.attrs.as_slice(),
                syn::Item::Macro(item) => item.attrs.as_slice(),
                syn::Item::Mod(item) => item.attrs.as_slice(),
                syn::Item::Static(item) => item.attrs.as_slice(),
                syn::Item::Struct(item) => item.attrs.as_slice(),
                syn::Item::Trait(item) => item.attrs.as_slice(),
                syn::Item::TraitAlias(item) => item.attrs.as_slice(),
                syn::Item::Type(item) => item.attrs.as_slice(),
                syn::Item::Union(item) => item.attrs.as_slice(),
                syn::Item::Use(item) => item.attrs.as_slice(),
                _ => &[],
            };
            if is_test_only(attrs) {
                continue;
            }
            if let syn::Item::Mod(module) = item
                && let Some((_, nested)) = &module.content
            {
                if module.ident == "OwnedDaemonSession" {
                    violations.push(format!(
                        "{relative}: production module named OwnedDaemonSession"
                    ));
                }
                inspect_items(nested, relative, violations);
                continue;
            }
            if contains_owner(item) {
                violations.push(format!(
                    "{relative}: production OwnedDaemonSession identifier outside canonical owner"
                ));
            }
        }
    }

    let file = syn::parse_file(source).expect("core source parses");
    let mut violations = Vec::new();
    inspect_items(&file.items, relative, &mut violations);
    violations
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
        if self.test_depth == 0 && item.sig.ident == "run_owned_daemon" {
            self.violation("runner name may not be defined locally");
        }
        let previous = self.function.replace(item.sig.ident.to_string());
        let test_only = usize::from(is_test_only(&item.attrs));
        self.test_depth += test_only;
        visit::visit_item_fn(self, item);
        self.test_depth -= test_only;
        self.function = previous;
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if self.test_depth == 0 && item.sig.ident == "run_owned_daemon" {
            self.violation("runner name may not be defined by an impl method");
        }
        let previous = self.function.replace(item.sig.ident.to_string());
        let test_only = usize::from(is_test_only(&item.attrs));
        self.test_depth += test_only;
        visit::visit_impl_item_fn(self, item);
        self.test_depth -= test_only;
        self.function = previous;
    }

    fn visit_trait_item_fn(&mut self, item: &'ast syn::TraitItemFn) {
        if self.test_depth == 0 && item.sig.ident == "run_owned_daemon" {
            self.violation("runner name may not be defined by a trait method");
        }
        visit::visit_trait_item_fn(self, item);
    }

    fn visit_impl_item_type(&mut self, item: &'ast syn::ImplItemType) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be used by an associated type");
        }
        visit::visit_impl_item_type(self, item);
    }

    fn visit_trait_item_type(&mut self, item: &'ast syn::TraitItemType) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be used by a trait associated type");
        }
        visit::visit_trait_item_type(self, item);
    }

    fn visit_impl_item_const(&mut self, item: &'ast syn::ImplItemConst) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be shadowed by an associated const");
        }
        visit::visit_impl_item_const(self, item);
    }

    fn visit_trait_item_const(&mut self, item: &'ast syn::TraitItemConst) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be shadowed by a trait associated const");
        }
        visit::visit_trait_item_const(self, item);
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        if self.test_depth == 0 && variant.ident == "run_owned_daemon" {
            self.violation("runner name may not be shadowed by an enum variant");
        }
        visit::visit_variant(self, variant);
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        if self.test_depth == 0
            && field
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "run_owned_daemon")
        {
            self.violation("runner name may not be shadowed by a field");
        }
        visit::visit_field(self, field);
    }

    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be used by a local module");
        }
        let test_only = usize::from(is_test_only(&item.attrs));
        self.test_depth += test_only;
        visit::visit_item_mod(self, item);
        self.test_depth -= test_only;
    }

    fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be used by a type alias");
        }
        visit::visit_item_type(self, item);
    }

    fn visit_item_const(&mut self, item: &'ast syn::ItemConst) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be shadowed by a const binding");
        }
        visit::visit_item_const(self, item);
    }

    fn visit_item_static(&mut self, item: &'ast syn::ItemStatic) {
        if self.test_depth == 0 && item.ident == "run_owned_daemon" {
            self.violation("runner name may not be shadowed by a static binding");
        }
        visit::visit_item_static(self, item);
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if self.test_depth == 0
            && item
                .ident
                .as_ref()
                .is_some_and(|ident| ident == "run_owned_daemon")
        {
            self.violation("runner name may not be used by a local macro");
        }
        visit::visit_item_macro(self, item);
    }

    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        if self.test_depth == 0 && pattern.ident == "run_owned_daemon" {
            self.violation("runner name may not be shadowed by a binding or parameter");
        }
        visit::visit_pat_ident(self, pattern);
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
            if path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>()
                == ["crate", "daemon", "client", "run_owned_daemon"]);
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
                    self.violation("runner may only be used as a fully qualified direct call");
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

fn path_ends(path: &syn::Path, name: &str) -> bool {
    path.segments
        .last()
        .is_some_and(|segment| segment.ident == name)
}

fn path_is(path: &syn::Path, expected: &[&str]) -> bool {
    path.leading_colon.is_none()
        && path.segments.len() == expected.len()
        && path
            .segments
            .iter()
            .zip(expected)
            .all(|(segment, expected)| segment.ident == *expected)
}

fn scoped_client_type(ty: &syn::Type, lifetime: &str) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    let Some(segment) = path.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return false;
    };
    path.path.segments.len() == 1
        && segment.ident == "ScopedDaemonClient"
        && arguments.args.len() == 1
        && matches!(arguments.args.first(), Some(syn::GenericArgument::Lifetime(value)) if value.ident == lifetime)
}

fn runner_hrtb_is_exact(runner: &syn::ItemFn) -> bool {
    if runner.sig.asyncness.is_none()
        || runner.sig.constness.is_some()
        || runner.sig.unsafety.is_some()
        || runner.sig.abi.is_some()
        || runner.sig.inputs.len() != 2
    {
        return false;
    }
    let mut inputs = runner.sig.inputs.iter();
    let exact_input = |input: Option<&syn::FnArg>, name: &str, ty: &str| {
        matches!(input, Some(syn::FnArg::Typed(input))
            if matches!(&*input.pat, syn::Pat::Ident(pattern)
                if pattern.by_ref.is_none() && pattern.mutability.is_none()
                    && pattern.subpat.is_none() && pattern.ident == name)
                && matches!(&*input.ty, syn::Type::Path(path) if path.path.is_ident(ty)))
    };
    if !exact_input(inputs.next(), "mode", "OwnedSessionMode")
        || !exact_input(inputs.next(), "operation", "F")
    {
        return false;
    }
    let syn::ReturnType::Type(_, return_type) = &runner.sig.output else {
        return false;
    };
    let syn::Type::Path(return_path) = &**return_type else {
        return false;
    };
    if !path_is(&return_path.path, &["std", "result", "Result"]) {
        return false;
    }
    let return_segment = return_path.path.segments.last().unwrap();
    let syn::PathArguments::AngleBracketed(return_arguments) = &return_segment.arguments else {
        return false;
    };
    if return_segment.ident != "Result"
        || return_arguments.args.len() != 2
        || !matches!(return_arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Path(value))) if value.path.is_ident("T"))
        || !matches!(return_arguments.args.iter().nth(1), Some(syn::GenericArgument::Type(syn::Type::Path(value))) if value.path.is_ident("OwnedDaemonRunError"))
    {
        return false;
    }
    let type_parameters = runner
        .sig
        .generics
        .params
        .iter()
        .filter_map(|parameter| match parameter {
            syn::GenericParam::Type(parameter) => Some(parameter),
            _ => None,
        })
        .collect::<Vec<_>>();
    if type_parameters.len() != 2
        || type_parameters[0].ident != "T"
        || type_parameters[1].ident != "F"
        || !type_parameters
            .iter()
            .all(|parameter| parameter.bounds.is_empty())
    {
        return false;
    }
    let Some(where_clause) = &runner.sig.generics.where_clause else {
        return false;
    };
    if where_clause.predicates.len() != 1 {
        return false;
    }
    let Some(syn::WherePredicate::Type(predicate)) = where_clause.predicates.first() else {
        return false;
    };
    if !matches!(&predicate.bounded_ty, syn::Type::Path(path) if path.path.is_ident("F"))
        || predicate.bounds.len() != 1
    {
        return false;
    }
    let Some(syn::TypeParamBound::Trait(bound)) = predicate.bounds.first() else {
        return false;
    };
    if !matches!(bound.modifier, syn::TraitBoundModifier::None) {
        return false;
    }
    let Some(lifetimes) = &bound.lifetimes else {
        return false;
    };
    if lifetimes.lifetimes.len() != 1
        || !matches!(lifetimes.lifetimes.first(), Some(syn::GenericParam::Lifetime(value)) if value.lifetime.ident == "client")
    {
        return false;
    }
    if !path_is(&bound.path, &["std", "ops", "FnOnce"]) {
        return false;
    }
    let fn_once = bound.path.segments.last().unwrap();
    let syn::PathArguments::Parenthesized(arguments) = &fn_once.arguments else {
        return false;
    };
    if fn_once.ident != "FnOnce"
        || arguments.inputs.len() != 1
        || !arguments
            .inputs
            .first()
            .is_some_and(|input| scoped_client_type(input, "client"))
    {
        return false;
    }
    let syn::ReturnType::Type(_, output) = &arguments.output else {
        return false;
    };
    let syn::Type::Path(pin) = &**output else {
        return false;
    };
    if !path_is(&pin.path, &["std", "pin", "Pin"]) {
        return false;
    }
    let pin_segment = pin.path.segments.last().unwrap();
    let syn::PathArguments::AngleBracketed(pin_arguments) = &pin_segment.arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(syn::Type::Path(boxed))) = pin_arguments.args.first()
    else {
        return false;
    };
    if pin_segment.ident != "Pin" || pin_arguments.args.len() != 1 {
        return false;
    }
    if !path_is(&boxed.path, &["std", "boxed", "Box"]) {
        return false;
    }
    let box_segment = boxed.path.segments.last().unwrap();
    let syn::PathArguments::AngleBracketed(box_arguments) = &box_segment.arguments else {
        return false;
    };
    let Some(syn::GenericArgument::Type(syn::Type::TraitObject(future))) =
        box_arguments.args.first()
    else {
        return false;
    };
    if box_segment.ident != "Box" || box_arguments.args.len() != 1 {
        return false;
    }
    if future.bounds.len() != 2 {
        return false;
    }
    let has_client_lifetime = matches!(future.bounds.iter().nth(1),
        Some(syn::TypeParamBound::Lifetime(value)) if value.ident == "client");
    let future_bound = match future.bounds.first() {
        Some(syn::TypeParamBound::Trait(bound))
            if matches!(bound.modifier, syn::TraitBoundModifier::None)
                && bound.lifetimes.is_none()
                && path_is(&bound.path, &["std", "future", "Future"]) =>
        {
            Some(bound)
        }
        _ => None,
    };
    let output_is_result_t = future_bound.is_some_and(|bound| {
        let Some(segment) = bound.path.segments.last() else {
            return false;
        };
        let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return false;
        };
        arguments.args.len() == 1 && arguments.args.iter().any(|argument| match argument {
            syn::GenericArgument::AssocType(output) if output.ident == "Output" => {
                matches!(&output.ty, syn::Type::Path(result)
                    if path_is(&result.path, &["anyhow", "Result"])
                        && result.path.segments.last().is_some_and(|segment|
                            matches!(&segment.arguments, syn::PathArguments::AngleBracketed(arguments)
                                if arguments.args.len() == 1
                                    && matches!(arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Path(value))) if value.path.is_ident("T")))))
            }
            _ => false,
        })
    });
    has_client_lifetime && output_is_result_t
}

fn canonical_runner_body() -> syn::Block {
    syn::parse_str::<syn::ItemFn>(
        r#"async fn canonical<T, F>(mode: OwnedSessionMode, operation: F) {
            let session = OwnedDaemonSession::connect(mode)
                .await
                .map_err(OwnedDaemonRunError::Connect)?;
            let result = operation(ScopedDaemonClient {
                client: session.client(),
            })
            .await;
            session
                .finish(result)
                .await
                .map_err(OwnedDaemonRunError::OperationOrCleanup)
        }"#,
    )
    .unwrap()
    .block
    .as_ref()
    .clone()
}

fn canonical_owned_method(name: &str) -> syn::ImplItemFn {
    let source = match name {
        "lifecycle" => {
            r#"
            fn lifecycle(self) -> LifecycleMode {
                match self {
                    Self::AttachOrAutoPromote => LifecycleMode::AttachOrAutoPromote,
                    Self::AttachOrEphemeral => LifecycleMode::AttachOrEphemeral,
                    Self::AlwaysEphemeral => LifecycleMode::AlwaysEphemeral,
                }
            }
        "#
        }
        "connect" => {
            r#"
            async fn connect(mode: OwnedSessionMode) -> Result<Self> {
                let mut connected = probe_or_spawn(mode.lifecycle()).await?;
                let guard = connected.take_owned_daemon_guard();
                let signal_task =
                    match crate::daemon::ephemeral_guard::spawn_signal_shutdown(guard.as_ref(), true) {
                        Ok(task) => task,
                        Err(error) => {
                            let shutdown = guard.as_ref().map_or(Ok(()), |guard| guard.shutdown());
                            drop(guard);
                            return crate::daemon::ephemeral_guard::aggregate_shutdown_result(
                                Err::<Self, _>(error.context("arming owned-daemon signal cleanup")),
                                shutdown,
                            );
                        }
                    };
                Ok(Self {
                    client: connected.client,
                    guard,
                    signal_task,
                })
            }
        "#
        }
        "finish" => {
            r#"
            async fn finish<T>(mut self, result: Result<T>) -> Result<T> {
                let signal_task = self.signal_task.take();
                if let Some(task) = &signal_task {
                    task.abort();
                }
                let shutdown = self.guard.as_ref().map_or(Ok(()), |guard| guard.shutdown());
                self.guard.take();
                if let Some(task) = signal_task {
                    let _ = task.await;
                }
                crate::daemon::ephemeral_guard::aggregate_shutdown_result(result, shutdown)
            }
        "#
        }
        "client" => {
            r#"
            fn client(&self) -> &DaemonClient {
                &self.client
            }
        "#
        }
        "drop" => {
            r#"
            fn drop(&mut self) {
                if let Some(task) = self.signal_task.take() {
                    task.abort();
                }
            }
        "#
        }
        _ => panic!("unknown canonical owner method {name}"),
    };
    syn::parse_str(source).unwrap()
}

fn core_contract_violations(source: &str) -> Vec<String> {
    #[derive(Default)]
    struct RawDaemonSurface(bool);
    impl<'ast> Visit<'ast> for RawDaemonSurface {
        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            if path_ends(&path.path, "DaemonClient") {
                self.0 = true;
            }
            visit::visit_type_path(self, path);
        }
    }
    let file = syn::parse_file(source).unwrap();
    let mut violations = Vec::new();
    for item in &file.items {
        let shadow = match item {
            syn::Item::Mod(item) => Some(item.ident.to_string()),
            syn::Item::Type(item) => Some(item.ident.to_string()),
            syn::Item::ExternCrate(item) => item.rename.as_ref().map_or_else(
                || Some(item.ident.to_string()),
                |(_, name)| Some(name.to_string()),
            ),
            syn::Item::Use(item) => {
                let mut inspection = UseInspection::default();
                inspect_use(&item.tree, &mut inspection);
                inspection
                    .renamed
                    .then(|| inspection.names.last().cloned())
                    .flatten()
            }
            _ => None,
        };
        if shadow
            .as_deref()
            .is_some_and(|name| matches!(name, "std" | "anyhow"))
        {
            violations.push(format!(
                "canonical lifecycle type root `{}` is shadowed",
                shadow.unwrap()
            ));
        }
    }
    let scoped = file.items.iter().find_map(|item| match item {
        syn::Item::Struct(item) if item.ident == "ScopedDaemonClient" => Some(item),
        _ => None,
    });
    let Some(scoped) = scoped else {
        return vec!["ScopedDaemonClient missing".into()];
    };
    if !matches!(scoped.vis, syn::Visibility::Public(_)) {
        violations.push("ScopedDaemonClient visibility changed".into());
    }
    let derives_clone_or_copy = scoped.attrs.iter().any(|attribute| {
        attribute.path().is_ident("derive")
            && attribute
                .parse_args_with(
                    syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
                )
                .is_ok_and(|derives| {
                    derives
                        .iter()
                        .any(|derive| path_ends(derive, "Clone") || path_ends(derive, "Copy"))
                })
    });
    if derives_clone_or_copy {
        violations.push("ScopedDaemonClient may not derive Clone/Copy".into());
    }
    let syn::Fields::Named(fields) = &scoped.fields else {
        violations.push("ScopedDaemonClient must have named fields".into());
        return violations;
    };
    if fields.named.len() != 1 {
        violations.push("ScopedDaemonClient must have exactly one field".into());
    } else {
        let field = fields.named.first().unwrap();
        let exact = field.ident.as_ref().is_some_and(|name| name == "client")
            && matches!(field.vis, syn::Visibility::Inherited)
            && matches!(&field.ty, syn::Type::Reference(reference)
                if reference.mutability.is_none()
                    && reference.lifetime.as_ref().is_some_and(|lifetime| lifetime.ident == "session")
                    && matches!(&*reference.elem, syn::Type::Path(path) if path.path.is_ident("DaemonClient")));
        if !exact {
            violations
                .push("ScopedDaemonClient field must be private &'session DaemonClient".into());
        }
    }

    let implementations = file
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Impl(item)
                if matches!(&*item.self_ty, syn::Type::Path(path) if path_ends(&path.path, "ScopedDaemonClient")) => Some(item),
            _ => None,
        })
        .collect::<Vec<_>>();
    if implementations.is_empty() {
        violations.push("ScopedDaemonClient inherent impl missing".into());
        return violations;
    }
    let method_items = implementations
        .iter()
        .filter(|implementation| implementation.trait_.is_none())
        .flat_map(|implementation| &implementation.items)
        .filter_map(|item| match item {
            syn::ImplItem::Fn(method) => Some(method),
            _ => None,
        })
        .collect::<Vec<_>>();
    let methods = method_items
        .iter()
        .map(|method| method.sig.ident.to_string())
        .collect::<Vec<_>>();
    if methods != ["request", "request_ok", "next_event", "negotiated"] {
        violations.push(format!("ScopedDaemonClient API changed: {methods:?}"));
    }
    for method in method_items {
        if !matches!(method.vis, syn::Visibility::Public(_)) {
            violations.push(format!("{} is not public", method.sig.ident));
        }
        let mut raw = RawDaemonSurface::default();
        raw.visit_signature(&method.sig);
        if raw.0 {
            violations.push(format!(
                "{} exposes raw daemon client authority in its signature",
                method.sig.ident
            ));
        }
        let expected = match method.sig.ident.to_string().as_str() {
            "request" => {
                r#"pub async fn request(&self, request: proto::Request) -> anyhow::Result<std::result::Result<proto::Response, proto::ErrorPayload>> { self.client.request(request).await }"#
            }
            "request_ok" => {
                r#"pub async fn request_ok(&self, request: proto::Request) -> anyhow::Result<proto::Response> { self.client.request_ok(request).await }"#
            }
            "next_event" => {
                r#"pub async fn next_event(&self) -> Option<proto::Event> { self.client.next_event().await }"#
            }
            "negotiated" => {
                r#"pub fn negotiated(&self) -> &proto::NegotiatedProtocol { self.client.negotiated() }"#
            }
            _ => continue,
        };
        let expected = syn::parse_str::<syn::ImplItemFn>(expected).unwrap();
        if compact_tokens(method) != compact_tokens(expected) {
            violations.push(format!(
                "{} signature or private-client delegation changed",
                method.sig.ident
            ));
        }
    }
    for implementation in implementations {
        if let Some((_, path, _)) = &implementation.trait_ {
            violations.push(format!(
                "ScopedDaemonClient may not implement trait {}",
                path.segments.last().unwrap().ident
            ));
        }
    }
    let runner = file.items.iter().find_map(|item| match item {
        syn::Item::Fn(item) if item.sig.ident == "run_owned_daemon" => Some(item),
        _ => None,
    });
    if !runner.is_some_and(runner_hrtb_is_exact) {
        violations.push("run_owned_daemon HRTB/result lifetime contract changed".into());
    }
    if runner.is_some_and(|runner| {
        compact_tokens(&runner.block) != compact_tokens(canonical_runner_body())
    }) {
        violations.push("run_owned_daemon ordered canonical body changed".into());
    }

    let mode_impl = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item)
            if item.trait_.is_none()
                && matches!(&*item.self_ty, syn::Type::Path(path)
                    if path.path.is_ident("OwnedSessionMode")) =>
        {
            Some(item)
        }
        _ => None,
    });
    let lifecycle = mode_impl.and_then(|implementation| {
        implementation.items.iter().find_map(|item| match item {
            syn::ImplItem::Fn(method) if method.sig.ident == "lifecycle" => Some(method),
            _ => None,
        })
    });
    if lifecycle.is_none_or(|method| {
        compact_tokens(method) != compact_tokens(canonical_owned_method("lifecycle"))
    }) {
        violations.push("OwnedSessionMode::lifecycle canonical mapping changed".into());
    }

    let owned_impl = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item)
            if item.trait_.is_none()
                && matches!(&*item.self_ty, syn::Type::Path(path)
                    if path.path.is_ident("OwnedDaemonSession")) =>
        {
            Some(item)
        }
        _ => None,
    });
    for name in ["connect", "client", "finish"] {
        let method = owned_impl.and_then(|implementation| {
            implementation.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == name => Some(method),
                _ => None,
            })
        });
        if method.is_none_or(|method| {
            compact_tokens(method) != compact_tokens(canonical_owned_method(name))
        }) {
            violations.push(format!(
                "OwnedDaemonSession::{name} canonical cleanup body changed"
            ));
        }
    }
    let drop_method = file.items.iter().find_map(|item| match item {
        syn::Item::Impl(item)
            if matches!(&item.trait_, Some((_, path, _)) if path.is_ident("Drop"))
                && matches!(&*item.self_ty, syn::Type::Path(path)
                    if path.path.is_ident("OwnedDaemonSession")) =>
        {
            item.items.iter().find_map(|item| match item {
                syn::ImplItem::Fn(method) if method.sig.ident == "drop" => Some(method),
                _ => None,
            })
        }
        _ => None,
    });
    if drop_method.is_none_or(|method| {
        compact_tokens(method) != compact_tokens(canonical_owned_method("drop"))
    }) {
        violations.push("OwnedDaemonSession::drop canonical fallback cleanup body changed".into());
    }
    violations
}

fn raw_owner_acquisitions(source: &str) -> Vec<String> {
    struct RawOwnerVisitor {
        function: Option<String>,
        test_depth: usize,
        acquisitions: Vec<String>,
    }
    impl<'ast> Visit<'ast> for RawOwnerVisitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_mod(self, item);
            self.test_depth -= test;
        }

        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_fn(self, item);
            self.test_depth -= test;
            self.function = previous;
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_impl_item_fn(self, item);
            self.test_depth -= test;
            self.function = previous;
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            if self.test_depth == 0
                && matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.iter().map(|segment| segment.ident.to_string()).eq(["OwnedDaemonSession", "connect"]))
            {
                self.acquisitions
                    .push(self.function.clone().unwrap_or_else(|| "<none>".into()));
            }
            visit::visit_expr_call(self, call);
        }
    }

    let file = syn::parse_file(source).unwrap();
    let mut visitor = RawOwnerVisitor {
        function: None,
        test_depth: 0,
        acquisitions: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.acquisitions
}

fn raw_owner_aliases(source: &str) -> Vec<String> {
    struct AliasVisitor {
        test_depth: usize,
        aliases: Vec<String>,
    }
    impl<'ast> Visit<'ast> for AliasVisitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_mod(self, item);
            self.test_depth -= test;
        }
        fn visit_item_type(&mut self, item: &'ast syn::ItemType) {
            if self.test_depth == 0 && compact_tokens(&item.ty).contains("OwnedDaemonSession") {
                self.aliases.push(item.ident.to_string());
            }
            visit::visit_item_type(self, item);
        }
        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            if self.test_depth == 0 {
                let mut inspection = UseInspection::default();
                inspect_use(&item.tree, &mut inspection);
                if inspection.renamed
                    && inspection
                        .names
                        .iter()
                        .any(|name| matches!(name.as_str(), "OwnedDaemonSession" | "connect"))
                {
                    self.aliases.push("use".into());
                }
            }
            visit::visit_item_use(self, item);
        }
    }
    let file = syn::parse_file(source).unwrap();
    let mut visitor = AliasVisitor {
        test_depth: 0,
        aliases: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.aliases
}

fn raw_owner_connect_path_count(source: &str) -> usize {
    struct ConnectPaths(usize);
    impl<'ast> Visit<'ast> for ConnectPaths {
        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            if path
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .eq(["OwnedDaemonSession", "connect"])
            {
                self.0 += 1;
            }
            visit::visit_expr_path(self, path);
        }
    }
    let file = syn::parse_file(source).unwrap();
    let mut visitor = ConnectPaths(0);
    visitor.visit_file(&file);
    visitor.0
}

fn compact_tokens(tokens: impl quote::ToTokens) -> String {
    tokens.to_token_stream().to_string().replace(' ', "")
}

fn raw_owner_occurrence_violations(source: &str) -> Vec<String> {
    struct OwnerOccurrences {
        function: Option<String>,
        test_depth: usize,
        allowed_connect_callee_depth: usize,
        owned_impl_depth: usize,
        canonical_self_types: Vec<String>,
        violations: Vec<String>,
    }

    impl OwnerOccurrences {
        fn reject(&mut self, context: &str) {
            if self.test_depth == 0 {
                self.violations.push(format!(
                    "OwnedDaemonSession appears outside canonical authority context: {context}"
                ));
            }
        }
    }

    impl<'ast> Visit<'ast> for OwnerOccurrences {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_mod(self, item);
            self.test_depth -= test;
        }

        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_fn(self, item);
            self.test_depth -= test;
            self.function = previous;
        }

        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_impl_item_fn(self, item);
            self.test_depth -= test;
            self.function = previous;
        }

        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let canonical_self = matches!(&*item.self_ty, syn::Type::Path(path)
                if path.path.is_ident("OwnedDaemonSession"));
            if canonical_self && self.test_depth == 0 {
                let methods = item
                    .items
                    .iter()
                    .filter_map(|implementation_item| match implementation_item {
                        syn::ImplItem::Fn(method) => Some(method.sig.ident.to_string()),
                        _ => None,
                    })
                    .collect::<Vec<_>>();
                let canonical = match &item.trait_ {
                    None => methods == ["connect", "client", "finish"],
                    Some((_, path, _)) if path.is_ident("Drop") => methods == ["drop"],
                    Some(_) => false,
                };
                if !canonical || methods.len() != item.items.len() {
                    self.reject("noncanonical impl or associated item");
                }
            }
            if !canonical_self {
                self.visit_type(&item.self_ty);
            }
            self.visit_generics(&item.generics);
            if let Some((_, path, _)) = &item.trait_ {
                self.visit_path(path);
            }
            self.owned_impl_depth += usize::from(canonical_self);
            for implementation_item in &item.items {
                self.visit_impl_item(implementation_item);
            }
            self.owned_impl_depth -= usize::from(canonical_self);
        }

        fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
            let canonical_connect = self.test_depth == 0
                && self.function.as_deref() == Some("run_owned_daemon")
                && matches!(&*call.func, syn::Expr::Path(path)
                    if path.path.segments.iter().map(|segment| segment.ident.to_string())
                        .eq(["OwnedDaemonSession", "connect"]));
            self.allowed_connect_callee_depth += usize::from(canonical_connect);
            self.visit_expr(&call.func);
            self.allowed_connect_callee_depth -= usize::from(canonical_connect);
            for argument in &call.args {
                self.visit_expr(argument);
            }
        }

        fn visit_expr_path(&mut self, path: &'ast syn::ExprPath) {
            let contains_owner = path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "OwnedDaemonSession");
            if contains_owner && self.allowed_connect_callee_depth == 0 {
                self.reject("value path");
            }
            if self.owned_impl_depth > 0 && path.path.is_ident("Self") {
                self.reject("nonliteral Self value path in owner impl");
            }
            visit::visit_expr_path(self, path);
        }

        fn visit_type_path(&mut self, path: &'ast syn::TypePath) {
            if self.test_depth == 0 && self.owned_impl_depth > 0 && path.path.is_ident("Self") {
                self.canonical_self_types
                    .push(self.function.clone().unwrap_or_else(|| "<none>".into()));
            }
            if path
                .path
                .segments
                .iter()
                .any(|segment| segment.ident == "OwnedDaemonSession")
            {
                self.reject("type path");
            }
            visit::visit_type_path(self, path);
        }

        fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
            let mut inspection = UseInspection::default();
            inspect_use(&item.tree, &mut inspection);
            if inspection
                .names
                .iter()
                .any(|name| name == "OwnedDaemonSession")
            {
                self.reject("use or re-export");
            }
            visit::visit_item_use(self, item);
        }

        fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
            if invocation
                .tokens
                .to_string()
                .split(|character: char| !character.is_alphanumeric() && character != '_')
                .any(|token| token == "OwnedDaemonSession")
            {
                self.reject("macro tokens");
            }
            visit::visit_macro(self, invocation);
        }
    }

    let file = syn::parse_file(source).unwrap();
    let mut visitor = OwnerOccurrences {
        function: None,
        test_depth: 0,
        allowed_connect_callee_depth: 0,
        owned_impl_depth: 0,
        canonical_self_types: Vec::new(),
        violations: Vec::new(),
    };
    visitor.visit_file(&file);
    if visitor.canonical_self_types != ["connect", "connect"] {
        visitor.violations.push(format!(
            "OwnedDaemonSession Self type inventory changed: {:?}",
            visitor.canonical_self_types
        ));
    }
    visitor.violations
}

fn raw_owner_struct_literals(source: &str) -> Vec<String> {
    struct StructLiteralVisitor {
        function: Option<String>,
        test_depth: usize,
        owned_impl_depth: usize,
        owners: Vec<String>,
    }
    impl<'ast> Visit<'ast> for StructLiteralVisitor {
        fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_mod(self, item);
            self.test_depth -= test;
        }
        fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_item_fn(self, item);
            self.test_depth -= test;
            self.function = previous;
        }
        fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
            let previous = self.function.replace(item.sig.ident.to_string());
            let test = usize::from(is_test_only(&item.attrs));
            self.test_depth += test;
            visit::visit_impl_item_fn(self, item);
            self.test_depth -= test;
            self.function = previous;
        }
        fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
            let owned = usize::from(
                matches!(&*item.self_ty, syn::Type::Path(path) if path_ends(&path.path, "OwnedDaemonSession")),
            );
            self.owned_impl_depth += owned;
            visit::visit_item_impl(self, item);
            self.owned_impl_depth -= owned;
        }
        fn visit_expr_struct(&mut self, value: &'ast syn::ExprStruct) {
            if self.test_depth == 0
                && (value.path.is_ident("OwnedDaemonSession")
                    || (self.owned_impl_depth > 0 && value.path.is_ident("Self")))
            {
                self.owners
                    .push(self.function.clone().unwrap_or_else(|| "<none>".into()));
            }
            visit::visit_expr_struct(self, value);
        }
    }
    let file = syn::parse_file(source).unwrap();
    let mut visitor = StructLiteralVisitor {
        function: None,
        test_depth: 0,
        owned_impl_depth: 0,
        owners: Vec::new(),
    };
    visitor.visit_file(&file);
    visitor.owners
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
    let core_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/cockpit-core/src");
    let owner_path = Path::new("daemon/client.rs");
    let source = std::fs::read_to_string(core_root.join(owner_path)).unwrap();
    let mut outside_owner_violations = Vec::new();
    for path in rust_files(&core_root) {
        let relative = path.strip_prefix(&core_root).unwrap();
        if relative == owner_path {
            continue;
        }
        let file_name = relative
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if file_name == "tests.rs" || file_name.ends_with("_tests.rs") {
            continue;
        }
        outside_owner_violations.extend(owned_session_occurrences_in_source(
            &std::fs::read_to_string(&path).unwrap(),
            &relative.display().to_string(),
        ));
    }
    assert!(
        outside_owner_violations.is_empty(),
        "{}",
        outside_owner_violations.join("\n")
    );
    let file = syn::parse_file(&source).unwrap();
    assert!(
        core_contract_violations(&source).is_empty(),
        "{}",
        core_contract_violations(&source).join("\n")
    );
    assert_eq!(raw_owner_acquisitions(&source), ["run_owned_daemon"]);
    assert_eq!(raw_owner_connect_path_count(&source), 1);
    assert_eq!(raw_owner_struct_literals(&source), ["connect"]);
    assert!(raw_owner_aliases(&source).is_empty());
    assert!(
        raw_owner_occurrence_violations(&source).is_empty(),
        "{}",
        raw_owner_occurrence_violations(&source).join("\n")
    );
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
}

#[test]
fn scoped_capability_contract_rejects_clone_raw_escape_and_weakened_lifetimes() {
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/cockpit-core/src/daemon/client.rs"),
    )
    .unwrap();
    for (before, after) in [
        (
            "pub struct ScopedDaemonClient<'session>",
            "#[derive(Clone)] pub struct ScopedDaemonClient<'session>",
        ),
        (
            "pub fn negotiated(&self) -> &proto::NegotiatedProtocol",
            "pub fn negotiated(&self) -> &DaemonClient",
        ),
        ("for<'client> std::ops::FnOnce(", "std::ops::FnOnce("),
        ("+ 'client>", "+ 'static>"),
        ("std::pin::Pin<", "crate::EvilPin<"),
        (
            "Box<dyn std::future::Future",
            "EvilBox<dyn std::future::Future",
        ),
        (
            "std::result::Result<T, OwnedDaemonRunError>",
            "std::result::Result<T, OwnedDaemonRunError, anyhow::Error>",
        ),
        (
            "pub fn negotiated(&self) -> &proto::NegotiatedProtocol {\n        self.client.negotiated()\n    }",
            "pub fn negotiated(&self) -> impl std::any::Any + Clone {\n        self.client.clone()\n    }",
        ),
        ("std::pin::Pin<", "evil::Pin<"),
        ("std::boxed::Box<", "evil::Box<"),
        ("std::future::Future", "evil::Future"),
        ("std::ops::FnOnce", "evil::FnOnce"),
        ("anyhow::Result<T>", "evil::Result<T>"),
        (
            "std::result::Result<T, OwnedDaemonRunError>",
            "evil::Result<T, OwnedDaemonRunError>",
        ),
    ] {
        let adversarial = source.replacen(before, after, 1);
        assert_ne!(adversarial, source, "fixture seam exists: {before}");
        assert!(
            !core_contract_violations(&adversarial).is_empty(),
            "accepted weakened scoped capability contract: {after}"
        );
    }

    for addition in [
        "mod std {}",
        "mod anyhow {}",
        "use evil as std;",
        "use evil as anyhow;",
        "type std = evil::Std;",
        "type anyhow = evil::Anyhow;",
    ] {
        let adversarial = format!("{source}\n{addition}");
        assert!(
            !core_contract_violations(&adversarial).is_empty(),
            "accepted canonical lifecycle path shadow: {addition}"
        );
    }

    for addition in [
        r#"
            impl ScopedDaemonClient<'_> {
                pub fn with_raw<R>(&self, callback: impl FnOnce(&DaemonClient) -> R) -> R {
                    callback(self.client)
                }
            }
        "#,
        r#"
            trait CustomEscape { fn expose(&self, callback: &mut dyn FnMut(&DaemonClient)); }
            impl CustomEscape for ScopedDaemonClient<'_> {
                fn expose(&self, callback: &mut dyn FnMut(&DaemonClient)) { callback(self.client); }
            }
        "#,
    ] {
        let adversarial = format!("{source}\n{addition}");
        assert!(
            !core_contract_violations(&adversarial).is_empty(),
            "accepted extra capability surface: {addition}"
        );
    }

    for (before, after) in [
        (
            "Self::AlwaysEphemeral => LifecycleMode::AlwaysEphemeral",
            "Self::AlwaysEphemeral => LifecycleMode::AttachOrAutoPromote",
        ),
        (
            "fn client(&self) -> &DaemonClient {\n        &self.client\n    }",
            "fn client(&self) -> &DaemonClient {\n        global_daemon_client()\n    }",
        ),
        (
            "fn client(&self) -> &DaemonClient {\n        &self.client\n    }",
            "fn client(&self) -> &DaemonClient {\n        detached_daemon_client(&self.client)\n    }",
        ),
        (
            "let result = operation(ScopedDaemonClient",
            "if false { return Err(OwnedDaemonRunError::OperationOrCleanup(anyhow::anyhow!(\"early\"))); }\n    let result = operation(ScopedDaemonClient",
        ),
        ("client: session.client()", "client: other.client()"),
        (
            "let result = operation(ScopedDaemonClient",
            "loop { break; }\n    let result = operation(ScopedDaemonClient",
        ),
        (
            "let signal_task = self.signal_task.take();\n        if let Some(task) = &signal_task",
            "if false { return result; }\n        let signal_task = self.signal_task.take();\n        if let Some(task) = &signal_task",
        ),
        (
            "task.abort();\n        }\n        let shutdown",
            "let _dead = || task.abort();\n        }\n        let shutdown",
        ),
        (
            "let guard = connected.take_owned_daemon_guard();",
            "let guard = connected.take_owned_daemon_guard();\n        if false { return Err(anyhow::anyhow!(\"before signal arming\")); }",
        ),
        (
            "drop(guard);\n                    return crate::daemon::ephemeral_guard::aggregate_shutdown_result",
            "return crate::daemon::ephemeral_guard::aggregate_shutdown_result",
        ),
        (
            "if let Some(task) = self.signal_task.take() {\n            task.abort();\n        }\n        // `guard` deliberately remains armed.",
            "if let Some(_task) = self.signal_task.take() {}\n        // `guard` deliberately remains armed.",
        ),
    ] {
        let adversarial = source.replacen(before, after, 1);
        assert_ne!(
            adversarial, source,
            "canonical body fixture seam exists: {before}"
        );
        assert!(
            !core_contract_violations(&adversarial).is_empty(),
            "accepted lifecycle cleanup body mutation: {after}"
        );
    }

    let bypass = source.replacen(
        "let session = OwnedDaemonSession::connect(mode)",
        "let extra = OwnedDaemonSession::connect(mode).await?; drop(extra);\n    let session = OwnedDaemonSession::connect(mode)",
        1,
    );
    assert_eq!(raw_owner_acquisitions(&bypass).len(), 2);
    let literal = source.replacen(
        "let session = OwnedDaemonSession::connect(mode)",
        "let leaked = OwnedDaemonSession { client: todo!(), guard: None, signal_task: None }; drop(leaked);\n    let session = OwnedDaemonSession::connect(mode)",
        1,
    );
    assert_eq!(
        raw_owner_struct_literals(&literal),
        ["connect", "run_owned_daemon"]
    );
    let alias = source.replacen(
        "impl OwnedDaemonSession {",
        "type Session = OwnedDaemonSession;\nimpl OwnedDaemonSession {",
        1,
    );
    assert_eq!(raw_owner_aliases(&alias), ["Session"]);
    let function_item = source.replacen(
        "let session = OwnedDaemonSession::connect(mode)",
        "let constructor = OwnedDaemonSession::connect;\n    let session = constructor(mode)",
        1,
    );
    assert_eq!(raw_owner_acquisitions(&function_item), Vec::<String>::new());
    assert_eq!(raw_owner_connect_path_count(&function_item), 1);

    let test_then_production_literal = r#"
        #[cfg(test)] mod tests { fn ignored() { let _ = OwnedDaemonSession { field: () }; } }
        fn production() { let _ = OwnedDaemonSession { field: () }; }
    "#;
    assert_eq!(
        raw_owner_struct_literals(test_then_production_literal),
        ["production"]
    );

    for addition in [
        "fn extra() { let _: OwnedDaemonSession = unsafe { std::mem::zeroed() }; }",
        "struct Wrapper { owner: OwnedDaemonSession }",
        "enum Wrapper { Owner(OwnedDaemonSession) }",
        "union Wrapper { owner: std::mem::ManuallyDrop<OwnedDaemonSession> }",
        "fn expose(value: OwnedDaemonSession) -> OwnedDaemonSession { value }",
        "fn generic<T: Into<OwnedDaemonSession>>() {}",
        "trait Escape { type Owner; const OWNER: Option<OwnedDaemonSession>; }",
        "struct EscapeImpl; impl Escape for EscapeImpl { type Owner = OwnedDaemonSession; const OWNER: Option<OwnedDaemonSession> = None; }",
        "static OWNER: Option<OwnedDaemonSession> = None;",
        "const OWNER: Option<OwnedDaemonSession> = None;",
        "fn extra() { let constructor = OwnedDaemonSession::connect; let _ = constructor; }",
        "fn extra() { let _ = OwnedDaemonSession::connect(mode); }",
        "macro_rules! owner { () => { OwnedDaemonSession::connect(mode) } }",
        "impl OwnedDaemonSession { fn escape(self) -> Self { self } }",
    ] {
        let adversarial = format!("{source}\n{addition}");
        assert!(
            !raw_owner_occurrence_violations(&adversarial).is_empty(),
            "accepted raw owner occurrence: {addition}"
        );
    }
}

#[test]
fn core_wide_owner_inventory_rejects_a_second_file_and_respects_cfg_polarity() {
    let adversarial = r#"
        #[cfg(test)]
        struct TestOnly(OwnedDaemonSession);
        #[cfg(all(unix, test))]
        const ALSO_TEST_ONLY: Option<OwnedDaemonSession> = None;
        #[cfg(any(test, unix))]
        struct ProductionOnUnix { owner: OwnedDaemonSession }
    "#;
    let violations = owned_session_occurrences_in_source(adversarial, "other.rs");
    assert_eq!(violations.len(), 1);
    assert!(violations[0].starts_with("other.rs:"));

    let second_file = "pub(crate) type HiddenOwner = OwnedDaemonSession;";
    assert_eq!(
        owned_session_occurrences_in_source(second_file, "nested/second.rs"),
        ["nested/second.rs: production OwnedDaemonSession identifier outside canonical owner"]
    );
}

#[test]
fn inventory_rejects_unlisted_alias_function_item_and_macro() {
    for source in [
        "use crate::daemon::client::run_owned_daemon as run; async fn extra() { run(mode, op).await; }",
        "async fn extra() { let run = run_owned_daemon; run(mode, op).await; }",
        "macro_rules! hidden { () => { run_owned_daemon(mode, op).await } }",
        "async fn extra() { OwnedDaemonSession::connect(mode).await; }",
        "async fn run_owned_daemon() {}",
        "async fn extra(run_owned_daemon: usize) { let _ = run_owned_daemon; }",
        "async fn extra() { let run_owned_daemon = fake; run_owned_daemon(); }",
        "mod run_owned_daemon {}",
        "type run_owned_daemon = usize;",
        "const run_owned_daemon: usize = 0;",
        "static run_owned_daemon: usize = 0;",
        "macro_rules! run_owned_daemon { () => {} }",
        "struct Shadow { run_owned_daemon: usize }",
        "enum Shadow { run_owned_daemon }",
        "struct Shadow; impl Shadow { fn run_owned_daemon() {} }",
        "trait Shadow { fn run_owned_daemon(); }",
        "trait Shadow { type run_owned_daemon; }",
        "trait Shadow { const run_owned_daemon: usize; }",
        "struct Shadow; impl Trait for Shadow { type run_owned_daemon = usize; const run_owned_daemon: usize = 0; }",
    ] {
        let inventory = inspect(source, "fixture.rs");
        assert!(
            !inventory.violations.is_empty(),
            "accepted fixture: {source}"
        );
    }

    let inventory = inspect(
        "async fn surprise() { crate::daemon::client::run_owned_daemon(mode, op).await; }",
        "commands/surprise.rs",
    );
    assert_eq!(inventory.runners.len(), 1);
    assert!(!EXPECTED_RUNNERS.contains(&(
        inventory.runners[0].0.as_str(),
        inventory.runners[0].1.as_str()
    )));
}
