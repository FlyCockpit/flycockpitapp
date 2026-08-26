use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Expr, ImplItemFn, ItemFn, ItemImpl, ItemMacro, ItemMod, ItemType, ItemUse, Local, Macro, Meta,
    Pat, Type, UseTree,
    punctuated::Punctuated,
    token::Comma,
    visit::{self, Visit},
};

fn cfg_test(attrs: &[syn::Attribute]) -> bool {
    fn requires_test(meta: &Meta) -> bool {
        match meta {
            Meta::Path(path) => path.is_ident("test"),
            Meta::List(list) if list.path.is_ident("not") => false,
            Meta::List(list) => {
                let nested = list
                    .parse_args_with(Punctuated::<Meta, Comma>::parse_terminated)
                    .unwrap_or_default();
                if list.path.is_ident("all") {
                    nested.iter().any(requires_test)
                } else if list.path.is_ident("any") {
                    !nested.is_empty() && nested.iter().all(requires_test)
                } else {
                    false
                }
            }
            Meta::NameValue(_) => false,
        }
    }

    attrs.iter().any(|attr| {
        attr.path().is_ident("cfg")
            && attr
                .parse_args::<Meta>()
                .is_ok_and(|meta| requires_test(&meta))
    })
}
fn is_self_composer(expr: &Expr) -> bool {
    match expr {
        Expr::Field(f) => {
            matches!(&f.member, syn::Member::Named(n) if n == "composer")
                && matches!(&*f.base, Expr::Path(p) if p.path.is_ident("self"))
        }
        Expr::Reference(e) => is_self_composer(&e.expr),
        Expr::Paren(e) => is_self_composer(&e.expr),
        _ => false,
    }
}

fn is_self(expr: &Expr) -> bool {
    match expr {
        Expr::Path(path) => path.path.is_ident("self"),
        Expr::Reference(reference) => is_self(&reference.expr),
        Expr::Paren(paren) => is_self(&paren.expr),
        _ => false,
    }
}

#[derive(Default)]
struct BindingCollector {
    bindings: HashSet<String>,
}

impl<'ast> Visit<'ast> for BindingCollector {
    fn visit_pat_ident(&mut self, node: &'ast syn::PatIdent) {
        self.bindings.insert(node.ident.to_string());
        visit::visit_pat_ident(self, node);
    }
}

fn collect_bindings(pat: &Pat, out: &mut HashSet<String>) {
    let mut collector = BindingCollector::default();
    collector.visit_pat(pat);
    out.extend(collector.bindings);
}

fn collect_composer_field_bindings(pat: &Pat, out: &mut HashSet<String>) {
    match pat {
        Pat::Ident(ident) => {
            if let Some((_, subpat)) = &ident.subpat {
                collect_composer_field_bindings(subpat, out);
            }
        }
        Pat::Or(or) => {
            for case in &or.cases {
                collect_composer_field_bindings(case, out);
            }
        }
        Pat::Paren(paren) => collect_composer_field_bindings(&paren.pat, out),
        Pat::Reference(reference) => collect_composer_field_bindings(&reference.pat, out),
        Pat::Slice(slice) => {
            for element in &slice.elems {
                collect_composer_field_bindings(element, out);
            }
        }
        Pat::Struct(structure) => {
            for field in &structure.fields {
                if matches!(&field.member, syn::Member::Named(name) if name == "composer") {
                    collect_bindings(&field.pat, out);
                } else {
                    collect_composer_field_bindings(&field.pat, out);
                }
            }
        }
        Pat::Tuple(tuple) => {
            for element in &tuple.elems {
                collect_composer_field_bindings(element, out);
            }
        }
        Pat::TupleStruct(tuple) => {
            for element in &tuple.elems {
                collect_composer_field_bindings(element, out);
            }
        }
        Pat::Type(typed) => collect_composer_field_bindings(&typed.pat, out),
        _ => {}
    }
}

struct TargetFinder<'a> {
    aliases: &'a HashSet<String>,
    allow_self: bool,
    found: bool,
}

impl<'ast> Visit<'ast> for TargetFinder<'_> {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if self.found {
            return;
        }
        if (self.allow_self && is_self_composer(node))
            || matches!(node, Expr::Path(path) if path.path.get_ident().is_some_and(|ident| self.aliases.contains(&ident.to_string())))
        {
            self.found = true;
            return;
        }
        visit::visit_expr(self, node);
    }
}

fn token_idents(tokens: TokenStream, out: &mut Vec<String>) {
    for token in tokens {
        match token {
            TokenTree::Group(group) => token_idents(group.stream(), out),
            TokenTree::Ident(ident) => out.push(ident.to_string()),
            TokenTree::Punct(_) | TokenTree::Literal(_) => {}
        }
    }
}

#[derive(Default)]
struct RawFunctionSummary {
    direct: HashSet<usize>,
    calls: Vec<(String, Vec<Option<usize>>)>,
}

struct FunctionProbe<'a> {
    params: &'a HashMap<String, usize>,
    aliases: HashMap<String, usize>,
    summary: RawFunctionSummary,
}

impl FunctionProbe<'_> {
    fn param_index(&self, expr: &Expr) -> Option<usize> {
        match expr {
            Expr::Path(path) => path.path.get_ident().and_then(|ident| {
                self.aliases
                    .get(&ident.to_string())
                    .or_else(|| self.params.get(&ident.to_string()))
                    .copied()
            }),
            Expr::Reference(reference) => self.param_index(&reference.expr),
            Expr::Paren(paren) => self.param_index(&paren.expr),
            _ => None,
        }
    }
}

impl<'ast> Visit<'ast> for FunctionProbe<'_> {
    fn visit_local(&mut self, node: &'ast Local) {
        if let Pat::Ident(binding) = &node.pat {
            let parameter = node
                .init
                .as_ref()
                .and_then(|init| self.param_index(&init.expr));
            if let Some(parameter) = parameter {
                self.aliases.insert(binding.ident.to_string(), parameter);
            } else {
                self.aliases.remove(&binding.ident.to_string());
            }
        }
        visit::visit_local(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(node.method.to_string().as_str(), "set" | "clear")
            && let Some(index) = self.param_index(&node.receiver)
        {
            self.summary.direct.insert(index);
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(path) = &*node.func
            && let Some(callee) = path.path.segments.last()
        {
            if matches!(callee.ident.to_string().as_str(), "set" | "clear")
                && let Some(index) = node.args.first().and_then(|arg| self.param_index(arg))
            {
                self.summary.direct.insert(index);
            }
            self.summary.calls.push((
                callee.ident.to_string(),
                node.args.iter().map(|arg| self.param_index(arg)).collect(),
            ));
        }
        visit::visit_expr_call(self, node);
    }
}

#[derive(Default)]
struct ProgramFacts {
    functions: HashMap<String, HashSet<usize>>,
    dangerous_macros: HashSet<String>,
}

fn program_facts(file: &syn::File) -> ProgramFacts {
    #[derive(Default)]
    struct Collector {
        raw: HashMap<String, RawFunctionSummary>,
        dangerous_macros: HashSet<String>,
        macro_identifiers: HashMap<String, Vec<String>>,
    }

    impl Collector {
        fn function(&mut self, sig: &syn::Signature, block: &syn::Block) {
            let params = sig
                .inputs
                .iter()
                .filter_map(|arg| match arg {
                    syn::FnArg::Typed(typed) => match &*typed.pat {
                        Pat::Ident(ident) => Some(ident.ident.to_string()),
                        _ => None,
                    },
                    syn::FnArg::Receiver(_) => None,
                })
                .enumerate()
                .map(|(index, name)| (name, index))
                .collect::<HashMap<_, _>>();
            let mut probe = FunctionProbe {
                params: &params,
                aliases: HashMap::new(),
                summary: RawFunctionSummary::default(),
            };
            probe.visit_block(block);
            self.raw.insert(sig.ident.to_string(), probe.summary);
        }
    }

    impl<'ast> Visit<'ast> for Collector {
        fn visit_item_mod(&mut self, node: &'ast ItemMod) {
            if !cfg_test(&node.attrs) {
                visit::visit_item_mod(self, node);
            }
        }

        fn visit_item_fn(&mut self, node: &'ast ItemFn) {
            if !cfg_test(&node.attrs) {
                self.function(&node.sig, &node.block);
            }
        }

        fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
            if !cfg_test(&node.attrs) {
                self.function(&node.sig, &node.block);
            }
        }

        fn visit_item_macro(&mut self, node: &'ast ItemMacro) {
            if cfg_test(&node.attrs) {
                return;
            }
            let Some(name) = &node.ident else {
                return;
            };
            let mut identifiers = Vec::new();
            token_idents(node.mac.tokens.clone(), &mut identifiers);
            if identifiers
                .iter()
                .any(|ident| matches!(ident.as_str(), "set" | "clear"))
            {
                self.dangerous_macros.insert(name.to_string());
            }
            self.macro_identifiers.insert(name.to_string(), identifiers);
        }
    }

    let mut collector = Collector::default();
    collector.visit_file(file);
    loop {
        let snapshot = collector.dangerous_macros.clone();
        let mut changed = false;
        for (name, identifiers) in &collector.macro_identifiers {
            if identifiers.iter().any(|ident| snapshot.contains(ident))
                && collector.dangerous_macros.insert(name.clone())
            {
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut functions = collector
        .raw
        .iter()
        .map(|(name, summary)| (name.clone(), summary.direct.clone()))
        .collect::<HashMap<_, _>>();
    loop {
        let snapshot = functions.clone();
        let mut changed = false;
        for (name, summary) in &collector.raw {
            let dangerous = functions.entry(name.clone()).or_default();
            for (callee, arguments) in &summary.calls {
                let Some(callee_dangerous) = snapshot.get(callee) else {
                    continue;
                };
                for callee_index in callee_dangerous {
                    if let Some(Some(caller_index)) = arguments.get(*callee_index)
                        && dangerous.insert(*caller_index)
                    {
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            break;
        }
    }
    ProgramFacts {
        functions,
        dangerous_macros: collector.dangerous_macros,
    }
}

struct Audit {
    scopes: Vec<HashMap<String, bool>>,
    composer_types: HashSet<String>,
    composer_method_aliases: HashSet<String>,
    macro_operation_aliases: HashSet<String>,
    dangerous_functions: HashMap<String, HashSet<usize>>,
    dangerous_macros: HashSet<String>,
    violations: Vec<String>,
    helper: bool,
    in_app: bool,
    trusted_helpers: HashSet<String>,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            composer_types: HashSet::new(),
            composer_method_aliases: HashSet::new(),
            macro_operation_aliases: HashSet::new(),
            dangerous_functions: HashMap::new(),
            dangerous_macros: HashSet::new(),
            violations: Vec::new(),
            helper: false,
            in_app: false,
            trusted_helpers: HashSet::new(),
        }
    }
}

impl Audit {
    fn active_aliases(&self) -> HashSet<String> {
        let mut bindings = HashMap::new();
        for scope in &self.scopes {
            bindings.extend(scope.iter().map(|(name, tainted)| (name.clone(), *tainted)));
        }
        bindings
            .into_iter()
            .filter_map(|(name, tainted)| tainted.then_some(name))
            .collect()
    }
    fn targets(&self, expr: &Expr) -> bool {
        let aliases = self.active_aliases();
        (self.in_app && is_self_composer(expr))
            || matches!(expr, Expr::Path(p) if p.path.get_ident().is_some_and(|i| aliases.contains(&i.to_string())))
    }
    fn contains_target(&self, expr: &Expr) -> bool {
        let aliases = self.active_aliases();
        let mut finder = TargetFinder {
            aliases: &aliases,
            allow_self: self.in_app,
            found: false,
        };
        finder.visit_expr(expr);
        finder.found
    }
    fn is_composer_type(&self, ty: &Type) -> bool {
        matches!(ty, Type::Path(path) if {
            let segments = path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>();
            segments.join("::") == "crate::tui::composer::Composer"
                || (segments.len() == 1 && self.composer_types.contains(&segments[0]))
        })
    }
    fn register_use(&mut self, tree: &UseTree, prefix: &mut Vec<String>) {
        match tree {
            UseTree::Path(path) => {
                prefix.push(path.ident.to_string());
                self.register_use(&path.tree, prefix);
                prefix.pop();
            }
            UseTree::Name(name) => {
                let mut path = prefix.clone();
                path.push(name.ident.to_string());
                let composer = path.join("::") == "crate::tui::composer::Composer";
                if composer {
                    self.composer_types.insert(name.ident.to_string());
                } else if name.ident == "Composer" {
                    self.composer_types.remove("Composer");
                }
                if prefix
                    .last()
                    .is_some_and(|parent| self.composer_types.contains(parent))
                    && matches!(name.ident.to_string().as_str(), "set" | "clear")
                {
                    self.composer_method_aliases.insert(name.ident.to_string());
                }
            }
            UseTree::Glob(_) => {}
            UseTree::Rename(rename) => {
                let original = rename.ident.to_string();
                let renamed = rename.rename.to_string();
                let mut path = prefix.clone();
                path.push(original.clone());
                let composer = path.join("::") == "crate::tui::composer::Composer";
                if composer {
                    self.composer_types.insert(renamed.clone());
                } else {
                    self.composer_types.remove(&renamed);
                }
                if prefix
                    .last()
                    .is_some_and(|parent| self.composer_types.contains(parent))
                    && matches!(original.as_str(), "set" | "clear")
                {
                    self.composer_method_aliases.insert(renamed.clone());
                }
                if matches!(original.as_str(), "set" | "clear" | "replace") {
                    self.macro_operation_aliases.insert(renamed);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.register_use(item, prefix);
                }
            }
        }
    }
    fn macro_targets_composer(&self, node: &Macro) -> bool {
        let mut identifiers = Vec::new();
        token_idents(node.tokens.clone(), &mut identifiers);
        let aliases = self.active_aliases();
        let targets_composer = identifiers.iter().any(|ident| aliases.contains(ident))
            || (self.in_app
                && identifiers
                    .windows(2)
                    .any(|pair| pair[0] == "self" && pair[1] == "composer"));
        let operation = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .is_some_and(|name| {
                matches!(name.as_str(), "set" | "clear" | "replace")
                    || self.macro_operation_aliases.contains(&name)
                    || self.dangerous_macros.contains(&name)
            })
            || identifiers
                .iter()
                .any(|ident| matches!(ident.as_str(), "set" | "clear" | "replace"));
        targets_composer && operation
    }
    fn reject(&mut self, node: impl ToTokens, reason: &str) {
        if !self.helper {
            self.violations
                .push(format!("{reason}: {}", node.to_token_stream()));
        }
    }
    fn body(&mut self, helper: bool, block: &syn::Block) {
        let old = std::mem::replace(&mut self.helper, helper);
        self.visit_block(block);
        self.helper = old;
    }

    fn exact_trusted_helper(&self, node: &ImplItemFn) -> bool {
        if !self.in_app {
            return false;
        }
        let signature = node.sig.to_token_stream().to_string().replace(' ', "");
        let body = node.block.to_token_stream().to_string().replace(' ', "");
        matches!(
            (signature.as_str(), body.as_str()),
            (
                "fnreplace_composer_buffer(&mutself,text:implInto<String>)",
                "{self.paste_registry.clear();self.composer.set(text.into());}"
            ) | (
                "fnclear_composer_buffer(&mutself)",
                "{self.paste_registry.clear();self.composer.clear();}"
            ) | (
                "fnrebuild_composer_buffer(&mutself,rebuilt:crate::tui::paste::EditorPasteRebuild)",
                "{self.paste_registry=rebuilt.registry;self.composer.set(rebuilt.buffer);}"
            )
        )
    }
}
impl<'ast> Visit<'ast> for Audit {
    fn visit_item_mod(&mut self, node: &'ast ItemMod) {
        if cfg_test(&node.attrs) {
            return;
        }
        let composer_types = self.composer_types.clone();
        let composer_method_aliases = self.composer_method_aliases.clone();
        let macro_operation_aliases = self.macro_operation_aliases.clone();
        visit::visit_item_mod(self, node);
        self.composer_types = composer_types;
        self.composer_method_aliases = composer_method_aliases;
        self.macro_operation_aliases = macro_operation_aliases;
    }

    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        let mut prefix = Vec::new();
        self.register_use(&node.tree, &mut prefix);
        visit::visit_item_use(self, node);
    }
    fn visit_item_type(&mut self, node: &'ast ItemType) {
        if self.is_composer_type(&node.ty) {
            self.composer_types.insert(node.ident.to_string());
        } else {
            self.composer_types.remove(&node.ident.to_string());
        }
        visit::visit_item_type(self, node);
    }
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if cfg_test(&node.attrs) {
            return;
        }
        let old = std::mem::replace(
            &mut self.in_app,
            matches!(&*node.self_ty, Type::Path(path) if path.path.is_ident("App")),
        );
        visit::visit_item_impl(self, node);
        self.in_app = old;
    }
    fn visit_item_fn(&mut self, node: &'ast ItemFn) {
        if !cfg_test(&node.attrs) {
            self.body(false, &node.block);
        }
    }
    fn visit_impl_item_fn(&mut self, node: &'ast ImplItemFn) {
        if cfg_test(&node.attrs) {
            return;
        }
        let helper = self.exact_trusted_helper(node);
        if helper && !self.trusted_helpers.insert(node.sig.ident.to_string()) {
            self.reject(node, "duplicate trusted Composer helper");
        }
        self.body(helper, &node.block);
    }
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let composer_types = self.composer_types.clone();
        let composer_method_aliases = self.composer_method_aliases.clone();
        let macro_operation_aliases = self.macro_operation_aliases.clone();
        self.scopes.push(HashMap::new());
        visit::visit_block(self, node);
        self.scopes.pop();
        self.composer_types = composer_types;
        self.composer_method_aliases = composer_method_aliases;
        self.macro_operation_aliases = macro_operation_aliases;
    }
    fn visit_local(&mut self, node: &'ast Local) {
        let mut bindings = HashSet::new();
        collect_bindings(&node.pat, &mut bindings);
        let mut tainted = HashSet::new();
        if let Some(init) = &node.init {
            if self.contains_target(&init.expr) {
                tainted.extend(bindings.iter().cloned());
            } else if self.in_app && is_self(&init.expr) {
                collect_composer_field_bindings(&node.pat, &mut tainted);
            }
        }
        let scope = self.scopes.last_mut().expect("function scope");
        for binding in bindings {
            scope.insert(binding.clone(), tainted.contains(&binding));
        }
        visit::visit_local(self, node);
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(node.method.to_string().as_str(), "set" | "clear")
            && self.targets(&node.receiver)
        {
            self.reject(node, "Composer method bypass");
        }
        if let Some(indices) = self
            .dangerous_functions
            .get(&node.method.to_string())
            .cloned()
            && indices.into_iter().any(|index| {
                node.args
                    .iter()
                    .nth(index)
                    .is_some_and(|argument| self.contains_target(argument))
            })
        {
            self.reject(node, "Composer helper-method bypass");
        }
        visit::visit_expr_method_call(self, node);
    }
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(p) = &*node.func {
            let segs = &p.path.segments;
            let method = segs.last().map(|s| s.ident.to_string());
            let path = segs
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>();
            let composer = (path.len() == 2 && self.composer_types.contains(&path[0]))
                || path.strip_suffix(&["clear".to_string()]).is_some_and(|ty| {
                    ty.iter().map(String::as_str).collect::<Vec<_>>().join("::")
                        == "crate::tui::composer::Composer"
                })
                || path.strip_suffix(&["set".to_string()]).is_some_and(|ty| {
                    ty.iter().map(String::as_str).collect::<Vec<_>>().join("::")
                        == "crate::tui::composer::Composer"
                })
                || p.qself
                    .as_ref()
                    .is_some_and(|qself| self.is_composer_type(&qself.ty));
            let composer_method_alias = method
                .as_ref()
                .is_some_and(|name| self.composer_method_aliases.contains(name));
            if ((composer && matches!(method.as_deref(), Some("set" | "clear")))
                || composer_method_alias)
                && node.args.first().is_some_and(|a| self.contains_target(a))
            {
                self.reject(node, "Composer UFCS bypass");
            }
            if matches!(method.as_deref(), Some("replace" | "take" | "swap"))
                && node.args.iter().any(|a| self.contains_target(a))
            {
                self.reject(node, "Composer indirect replacement");
            }
            if let Some(name) = method
                && let Some(indices) = self.dangerous_functions.get(&name).cloned()
                && indices.into_iter().any(|index| {
                    node.args
                        .iter()
                        .nth(index)
                        .is_some_and(|argument| self.contains_target(argument))
                })
            {
                self.reject(node, "Composer helper-call bypass");
            }
        }
        visit::visit_expr_call(self, node);
    }
    fn visit_expr_assign(&mut self, node: &'ast syn::ExprAssign) {
        if self.targets(&node.left) {
            self.reject(node, "Composer assignment bypass");
        }
        visit::visit_expr_assign(self, node);
    }
    fn visit_macro(&mut self, node: &'ast Macro) {
        if self.macro_targets_composer(node) {
            self.reject(node, "unresolved Composer macro");
        }
        visit::visit_macro(self, node);
    }
}
fn audit_report(source: &str) -> Audit {
    let file = syn::parse_file(source).expect("valid Rust source");
    let facts = program_facts(&file);
    let mut audit = Audit {
        dangerous_functions: facts.functions,
        dangerous_macros: facts.dangerous_macros,
        ..Audit::default()
    };
    audit.visit_file(&file);
    audit
}
fn audit(source: &str) -> Vec<String> {
    audit_report(source).violations
}
fn rust_sources(root: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(root).expect("read TUI source") {
        let path = entry.expect("source entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().and_then(|v| v.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

#[test]
fn production_tui_uses_registry_aware_whole_buffer_helpers() {
    let mut paths = Vec::new();
    rust_sources(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui"),
        &mut paths,
    );
    let mut violations = Vec::new();
    let mut trusted_helpers = Vec::new();
    for path in paths {
        let source = fs::read_to_string(&path).expect("read source");
        let report = audit_report(&source);
        violations.extend(
            report
                .violations
                .into_iter()
                .map(|violation| format!("{}: {violation}", path.display())),
        );
        trusted_helpers.extend(
            report
                .trusted_helpers
                .into_iter()
                .map(|helper| format!("{}::{helper}", path.display())),
        );
    }
    assert!(
        violations.is_empty(),
        "whole-buffer Composer bypasses:\n{}",
        violations.join("\n")
    );
    trusted_helpers.sort();
    assert_eq!(
        trusted_helpers,
        [
            "clear_composer_buffer",
            "rebuild_composer_buffer",
            "replace_composer_buffer",
        ]
        .map(|helper| format!(
            "{}::{helper}",
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("src/tui/app/mod.rs")
                .display()
        )),
        "trusted Composer helpers must be the unique exact App definitions"
    );
}

#[test]
fn ast_gate_rejects_adversarial_alias_ufcs_macro_and_nested_bypasses() {
    let fixtures = [
        (
            "plain alias",
            "impl App { fn bypass(&mut self) { let c = &mut self.composer; c.clear(); } }",
        ),
        (
            "typed alias",
            "impl App { fn bypass(&mut self) { let c: &mut Composer = &mut self.composer; c.clear(); } }",
        ),
        (
            "destructured alias",
            "impl App { fn bypass(&mut self) { let (c, _) = (&mut self.composer, 0); c.set(String::new()); } }",
        ),
        (
            "self destructuring",
            "impl App { fn bypass(&mut self) { let Self { composer: c, .. } = self; c.clear(); } }",
        ),
        (
            "use-renamed Composer UFCS",
            "use crate::tui::composer::Composer as Editor; impl App { fn bypass(&mut self) { Editor::clear(&mut self.composer); } }",
        ),
        (
            "type-aliased Composer UFCS",
            "use crate::tui::composer::Composer; type Editor = Composer; impl App { fn bypass(&mut self) { Editor::set(&mut self.composer, String::new()); } }",
        ),
        (
            "use-renamed Composer method",
            "use crate::tui::composer::Composer; use Composer::clear as wipe; impl App { fn bypass(&mut self) { wipe(&mut self.composer); } }",
        ),
        (
            "UseTree name operation import",
            "use crate::tui::composer::Composer; use Composer::clear; impl App { fn bypass(&mut self) { clear(&mut self.composer); } }",
        ),
        (
            "macro alias argument",
            "impl App { fn bypass(&mut self) { let c = &mut self.composer; mutate!(c, clear); } }",
        ),
        (
            "use-renamed macro",
            "use crate::clear as wipe; impl App { fn bypass(&mut self) { wipe!(&mut self.composer); } }",
        ),
        (
            "assignment",
            "impl App { fn bypass(&mut self, c: Composer) { self.composer = c; } }",
        ),
        (
            "nested multiline",
            "mod nested { impl App { fn bypass(&mut self) { self.composer\n.set(String::new()); } } }",
        ),
        (
            "cfg not test remains production",
            "#[cfg(not(test))] impl App { fn bypass(&mut self) { self.composer.clear(); } }",
        ),
        (
            "tainted helper parameter propagates through calls",
            "fn clear_inner(c: &mut Composer) { let alias = c; alias.clear(); } fn clear_outer(c: &mut Composer) { clear_inner(c); } impl App { fn bypass(&mut self) { clear_outer(&mut self.composer); } }",
        ),
        (
            "macro definition propagates to invocation",
            "macro_rules! wipe { ($c:expr) => { $c.clear() } } impl App { fn bypass(&mut self) { wipe!(&mut self.composer); } }",
        ),
        (
            "macro taint propagates through nested expansion",
            "macro_rules! inner { ($c:expr) => { $c.clear() } } macro_rules! outer { ($c:expr) => { inner!($c) } } impl App { fn bypass(&mut self) { outer!(&mut self.composer); } }",
        ),
    ];

    for (name, source) in fixtures {
        let violations = audit(source);
        assert_eq!(violations.len(), 1, "{name}: {violations:#?}");
    }
}

#[test]
fn ast_gate_honors_lexical_shadowing_and_exact_type_identity() {
    let source = r#"
        use other::Composer;
        #[cfg(test)] impl App { fn test_only(&mut self) { self.composer.clear(); } }
        impl BtwPane { fn clear(&mut self) { self.composer.clear(); } }
        impl App {
            fn scoped(&mut self) {
                let c = &mut self.composer;
                { let c = Unrelated; c.clear(); }
                c.clear();
            }
            fn unrelated_ufcs(&mut self) { Composer::clear(&mut self.composer); }
        }
    "#;
    let violations = audit(source);
    assert_eq!(violations.len(), 1, "{violations:#?}");
}

#[test]
fn ast_gate_allows_only_exact_trusted_helpers() {
    let source = r#"
        impl App {
            fn replace_composer_buffer(&mut self, text: impl Into<String>) {
                self.paste_registry.clear(); self.composer.set(text.into());
            }
            fn clear_composer_buffer(&mut self) {
                self.paste_registry.clear(); self.composer.clear();
            }
            fn rebuild_composer_buffer(&mut self, rebuilt: crate::tui::paste::EditorPasteRebuild) {
                self.paste_registry = rebuilt.registry; self.composer.set(rebuilt.buffer);
            }
        }
    "#;
    assert!(audit(source).is_empty());

    let spoof = "impl App { fn clear_composer_buffer(&mut self) { self.composer.clear(); } }";
    assert_eq!(audit(spoof).len(), 1);

    let duplicate = format!("{source}{source}");
    assert_eq!(
        audit(&duplicate).len(),
        3,
        "duplicate exact helpers are rejected"
    );
}

#[test]
fn known_replacements_are_pinned_to_the_helper_seam() {
    assert!(
        include_str!("../src/tui/app/input.rs")
            .contains("replace_composer_buffer(completions[chosen].clone())")
    );
    assert!(
        include_str!("../src/tui/app/async_actions.rs").contains("replace_composer_buffer(seed)")
    );
    assert!(include_str!("../src/tui/app/panes.rs").contains("rebuild_composer_buffer(rebuilt)"));
}
