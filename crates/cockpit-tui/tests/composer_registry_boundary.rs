use quote::ToTokens;
use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};
use syn::{
    Expr, ImplItemFn, ItemFn, ItemImpl, Local, Macro,
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

#[derive(Default)]
struct Audit {
    aliases: HashSet<String>,
    violations: Vec<String>,
    helper: bool,
}
impl Audit {
    fn targets(&self, expr: &Expr) -> bool {
        is_self_composer(expr)
            || matches!(expr, Expr::Path(p) if p.path.get_ident().is_some_and(|i| self.aliases.contains(&i.to_string())))
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
        if let Some(init) = &node.init
            && self.targets(&init.expr)
            && let syn::Pat::Ident(p) = &node.pat
        {
            self.aliases.insert(p.ident.to_string());
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
                .is_some_and(|s| s.ident == "Composer");
            if composer
                && matches!(method.as_deref(), Some("set" | "clear"))
                && node.args.first().is_some_and(|a| self.targets(a))
            {
                self.reject(node, "Composer UFCS bypass");
            }
            if matches!(method.as_deref(), Some("replace" | "take" | "swap"))
                && node.args.iter().any(|a| self.targets(a))
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
        let t = node.tokens.to_string();
        if t.contains("composer")
            && (t.contains("set") || t.contains("clear") || t.contains("replace"))
        {
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
fn ast_gate_rejects_alias_ufcs_macro_assignment_and_nested_bypasses() {
    let source = r#"
        impl App {
            fn alias(&mut self) { let c = &mut self.composer; c.clear(); }
            fn ufcs(&mut self) { Composer::set(&mut self.composer, String::new()); }
            fn assignment(&mut self, c: Composer) { self.composer = c; }
            fn macro_call(&mut self) { mutate!(self.composer, clear); }
        }
        mod nested { impl App { fn multiline(&mut self) { self.composer
            .set(String::new()); } } }
    "#;
    let violations = audit(source);
    assert_eq!(violations.len(), 5, "{violations:#?}");
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
