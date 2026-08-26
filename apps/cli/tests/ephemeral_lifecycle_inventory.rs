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
    segment.ident == "ScopedDaemonClient"
        && arguments.args.len() == 1
        && matches!(arguments.args.first(), Some(syn::GenericArgument::Lifetime(value)) if value.ident == lifetime)
}

fn runner_hrtb_is_exact(runner: &syn::ItemFn) -> bool {
    let syn::ReturnType::Type(_, return_type) = &runner.sig.output else {
        return false;
    };
    let syn::Type::Path(return_path) = &**return_type else {
        return false;
    };
    let Some(return_segment) = return_path.path.segments.last() else {
        return false;
    };
    let syn::PathArguments::AngleBracketed(return_arguments) = &return_segment.arguments else {
        return false;
    };
    if return_segment.ident != "Result"
        || return_arguments.args.len() != 2
        || !matches!(return_arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Path(value))) if value.path.is_ident("T"))
        || !matches!(return_arguments.args.iter().nth(1), Some(syn::GenericArgument::Type(syn::Type::Path(value))) if path_ends(&value.path, "OwnedDaemonRunError"))
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
    let Some(lifetimes) = &bound.lifetimes else {
        return false;
    };
    if lifetimes.lifetimes.len() != 1
        || !matches!(lifetimes.lifetimes.first(), Some(syn::GenericParam::Lifetime(value)) if value.lifetime.ident == "client")
    {
        return false;
    }
    let Some(fn_once) = bound.path.segments.last() else {
        return false;
    };
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
    let Some(pin_segment) = pin.path.segments.last() else {
        return false;
    };
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
    let Some(box_segment) = boxed.path.segments.last() else {
        return false;
    };
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
    let has_client_lifetime = future.bounds.iter().any(
        |bound| matches!(bound, syn::TypeParamBound::Lifetime(value) if value.ident == "client"),
    );
    let future_bound = future.bounds.iter().find_map(|bound| match bound {
        syn::TypeParamBound::Trait(bound) if path_ends(&bound.path, "Future") => Some(bound),
        _ => None,
    });
    let output_is_result_t = future_bound.is_some_and(|bound| {
        let Some(segment) = bound.path.segments.last() else {
            return false;
        };
        let syn::PathArguments::AngleBracketed(arguments) = &segment.arguments else {
            return false;
        };
        arguments.args.iter().any(|argument| match argument {
            syn::GenericArgument::AssocType(output) if output.ident == "Output" => {
                matches!(&output.ty, syn::Type::Path(result)
                    if result.path.segments.last().is_some_and(|segment| {
                        segment.ident == "Result"
                            && matches!(&segment.arguments, syn::PathArguments::AngleBracketed(arguments)
                                if arguments.args.len() == 1
                                    && matches!(arguments.args.first(), Some(syn::GenericArgument::Type(syn::Type::Path(value))) if value.path.is_ident("T")))
                    }))
            }
            _ => false,
        })
    });
    has_client_lifetime && output_is_result_t
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
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/cockpit-core/src/daemon/client.rs"),
    )
    .unwrap();
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
    assert!(source.contains("let result = operation(ScopedDaemonClient"));
    assert!(source.contains(".finish(result)"));
    assert!(source.contains("impl Drop for OwnedDaemonSession"));
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
        ("for<'client> FnOnce(", "FnOnce("),
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
    ] {
        let adversarial = source.replacen(before, after, 1);
        assert_ne!(adversarial, source, "fixture seam exists: {before}");
        assert!(
            !core_contract_violations(&adversarial).is_empty(),
            "accepted weakened scoped capability contract: {after}"
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
    assert_eq!(raw_owner_acquisitions(&function_item), []);
    assert_eq!(raw_owner_connect_path_count(&function_item), 1);
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
