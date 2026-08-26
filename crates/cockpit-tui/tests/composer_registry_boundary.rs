use proc_macro2::{TokenStream, TokenTree};
use quote::ToTokens;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Expr, ImplItemFn, ItemFn, ItemImpl, ItemType, ItemUse, Local, Macro, Pat, Type, UseTree,
    visit::{self, Visit},
};

fn cfg_test(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .any(|a| a.path().is_ident("cfg") && a.meta.to_token_stream().to_string().contains("test"))
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
    found: bool,
}

impl<'ast> Visit<'ast> for TargetFinder<'_> {
    fn visit_expr(&mut self, node: &'ast Expr) {
        if self.found {
            return;
        }
        if is_self_composer(node)
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

struct Audit {
    aliases: HashSet<String>,
    composer_types: HashSet<String>,
    composer_method_aliases: HashSet<String>,
    macro_operation_aliases: HashSet<String>,
    violations: Vec<String>,
    helper: bool,
}

impl Default for Audit {
    fn default() -> Self {
        Self {
            aliases: HashSet::new(),
            composer_types: HashSet::from(["Composer".to_string()]),
            composer_method_aliases: HashSet::new(),
            macro_operation_aliases: HashSet::new(),
            violations: Vec::new(),
            helper: false,
        }
    }
}

impl Audit {
    fn targets(&self, expr: &Expr) -> bool {
        is_self_composer(expr)
            || matches!(expr, Expr::Path(p) if p.path.get_ident().is_some_and(|i| self.aliases.contains(&i.to_string())))
    }
    fn contains_target(&self, expr: &Expr) -> bool {
        let mut finder = TargetFinder {
            aliases: &self.aliases,
            found: false,
        };
        finder.visit_expr(expr);
        finder.found
    }
    fn is_composer_type(&self, ty: &Type) -> bool {
        matches!(ty, Type::Path(path) if path.path.segments.last().is_some_and(|segment| self.composer_types.contains(&segment.ident.to_string())))
    }
    fn register_use(&mut self, tree: &UseTree, composer_prefix: bool) {
        match tree {
            UseTree::Path(path) => {
                let composer_prefix =
                    composer_prefix || self.composer_types.contains(&path.ident.to_string());
                self.register_use(&path.tree, composer_prefix);
            }
            UseTree::Name(_) | UseTree::Glob(_) => {}
            UseTree::Rename(rename) => {
                let original = rename.ident.to_string();
                let renamed = rename.rename.to_string();
                if self.composer_types.contains(&original)
                    || (composer_prefix && original == "self")
                {
                    self.composer_types.insert(renamed.clone());
                }
                if composer_prefix && matches!(original.as_str(), "set" | "clear") {
                    self.composer_method_aliases.insert(renamed.clone());
                }
                if matches!(original.as_str(), "set" | "clear" | "replace") {
                    self.macro_operation_aliases.insert(renamed);
                }
            }
            UseTree::Group(group) => {
                for item in &group.items {
                    self.register_use(item, composer_prefix);
                }
            }
        }
    }
    fn macro_targets_composer(&self, node: &Macro) -> bool {
        let mut identifiers = Vec::new();
        token_idents(node.tokens.clone(), &mut identifiers);
        let targets_composer = identifiers.iter().any(|ident| self.aliases.contains(ident))
            || identifiers
                .windows(2)
                .any(|pair| pair[0] == "self" && pair[1] == "composer");
        let operation = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .is_some_and(|name| {
                matches!(name.as_str(), "set" | "clear" | "replace")
                    || self.macro_operation_aliases.contains(&name)
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
        let aliases = std::mem::take(&mut self.aliases);
        let old = std::mem::replace(&mut self.helper, helper);
        visit::visit_block(self, block);
        self.aliases = aliases;
        self.helper = old;
    }
}
impl<'ast> Visit<'ast> for Audit {
    fn visit_item_use(&mut self, node: &'ast ItemUse) {
        self.register_use(&node.tree, false);
        visit::visit_item_use(self, node);
    }
    fn visit_item_type(&mut self, node: &'ast ItemType) {
        if self.is_composer_type(&node.ty) {
            self.composer_types.insert(node.ident.to_string());
        }
        visit::visit_item_type(self, node);
    }
    fn visit_item_impl(&mut self, node: &'ast ItemImpl) {
        if cfg_test(&node.attrs)
            || node
                .self_ty
                .to_token_stream()
                .to_string()
                .replace(' ', "")
                .ends_with("BtwPane")
        {
            return;
        }
        visit::visit_item_impl(self, node);
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
        let helper = matches!(
            node.sig.ident.to_string().as_str(),
            "replace_composer_buffer" | "clear_composer_buffer" | "rebuild_composer_buffer"
        );
        self.body(helper, &node.block);
    }
    fn visit_local(&mut self, node: &'ast Local) {
        if let Some(init) = &node.init {
            if self.contains_target(&init.expr) {
                collect_bindings(&node.pat, &mut self.aliases);
            } else if is_self(&init.expr) {
                collect_composer_field_bindings(&node.pat, &mut self.aliases);
            }
        }
        visit::visit_local(self, node);
    }
    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if matches!(node.method.to_string().as_str(), "set" | "clear")
            && self.targets(&node.receiver)
        {
            self.reject(node, "Composer method bypass");
        }
        visit::visit_expr_method_call(self, node);
    }
    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let Expr::Path(p) = &*node.func {
            let segs = &p.path.segments;
            let method = segs.last().map(|s| s.ident.to_string());
            let composer = segs
                .iter()
                .rev()
                .nth(1)
                .is_some_and(|s| self.composer_types.contains(&s.ident.to_string()))
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
fn audit(source: &str) -> Vec<String> {
    let file = syn::parse_file(source).expect("valid Rust source");
    let mut audit = Audit::default();
    audit.visit_file(&file);
    audit.violations
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
    let violations = paths
        .into_iter()
        .flat_map(|p| {
            let source = fs::read_to_string(&p).expect("read source");
            audit(&source)
                .into_iter()
                .map(move |v| format!("{}: {v}", p.display()))
        })
        .collect::<Vec<_>>();
    assert!(
        violations.is_empty(),
        "whole-buffer Composer bypasses:\n{}",
        violations.join("\n")
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
            "type Editor = Composer; impl App { fn bypass(&mut self) { Editor::set(&mut self.composer, String::new()); } }",
        ),
        (
            "use-renamed Composer method",
            "use Composer::clear as wipe; impl App { fn bypass(&mut self) { wipe(&mut self.composer); } }",
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
    ];

    for (name, source) in fixtures {
        let violations = audit(source);
        assert_eq!(violations.len(), 1, "{name}: {violations:#?}");
    }
}

#[test]
fn ast_gate_allows_exact_helpers_and_typed_btw_pane() {
    let source = r#"
        impl App {
            fn replace_composer_buffer(&mut self, s: String) { self.composer.set(s); }
            fn clear_composer_buffer(&mut self) { self.composer.clear(); }
            fn rebuild_composer_buffer(&mut self, s: String) { self.composer.set(s); }
        }
        impl BtwPane { fn clear(&mut self) { self.composer.clear(); } }
    "#;
    assert!(audit(source).is_empty());
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
