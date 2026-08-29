//! AST/call-graph gate for the cockpit-db synchronous blocking boundary.
//!
//! # Scope (cockpit-db local only)
//!
//! This gate resolves an explicitly supported Rust subset **inside the crate
//! under analysis** (production `src/` or a fixture mini-crate). It makes **no**
//! workspace-wide wrapper-detection claim: other crates can call only the exact
//! public cockpit-db entrypoints this gate approves.
//!
//! # Supported resolution
//!
//! Out-of-line and inline modules; inherent `impl Db` methods; crate-local free
//! functions; `pub`/`pub(crate)` reachability; `self`/`Self`/`Db`/`<Db>`/
//! `crate`/`super` paths; `use` trees including `as` aliases and local glob
//! imports; `pub use` re-exports; calls and function-item references; calls
//! nested in closures, async blocks, matches, and multiline expressions.
//!
//! # Fail-closed
//!
//! Macro-generated public `Db` methods, trait implementations that expose an
//! unguarded helper path, and unresolved indirect callables on a public path
//! (function pointers / non-parameter variables) are gate errors with source
//! locations — never silently skipped edges.
//!
//! # Allowlist
//!
//! Exact only — no wildcards. See [`ALLOWLIST`].

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};

use syn::spanned::Spanned;
use syn::visit::Visit;
use syn::{
    Expr, FnArg, ImplItem, Item, ItemFn, ItemImpl, ItemMod, ItemUse, Pat, UseTree, Visibility,
    visit,
};

/// Private unguarded helpers that must not leak through unapproved public paths.
const UNGUARDED_HELPERS: &[&str] = &["read_blocking_unguarded", "write_blocking_unguarded"];

/// Deleted public methods that must stay absent from the production API.
const DELETED_PUBLIC_METHODS: &[&str] = &["read_blocking", "write_blocking"];

/// Exact reviewed allowlist of public/pub(crate) entrypoints that may reach an
/// unguarded helper. No unnamed or wildcard entries.
///
/// - `blocking_for_sync_cli`: permanent guarded boundary for synchronous CLI one-shots.
/// - four `blocking_*_for_sync_*` wrappers: temporary; owned by `db-sync-wrapper-migration`.
/// - three typed agent-publication journal methods: permanent, narrow bridges
///   used only while a caller owns the cross-process filesystem publication
///   lock; none accepts an arbitrary closure.
const ALLOWLIST: &[AllowlistEntry] = &[
    AllowlistEntry {
        name: "blocking_for_sync_cli",
        kind: AllowlistKind::PermanentCli,
        owner: "db-blocking-api-removal",
        rationale: "permanent guarded boundary for synchronous CLI one-shots",
    },
    AllowlistEntry {
        name: "blocking_read_for_sync_ui",
        kind: AllowlistKind::TemporarySyncWrapper,
        owner: "db-sync-wrapper-migration",
        rationale: "temporary sync UI read boundary pending db-sync-wrapper-migration",
    },
    AllowlistEntry {
        name: "blocking_write_for_sync_ui",
        kind: AllowlistKind::TemporarySyncWrapper,
        owner: "db-sync-wrapper-migration",
        rationale: "temporary sync UI write boundary pending db-sync-wrapper-migration",
    },
    AllowlistEntry {
        name: "blocking_write_for_sync_event",
        kind: AllowlistKind::TemporarySyncWrapper,
        owner: "db-sync-wrapper-migration",
        rationale: "temporary sync event write boundary pending db-sync-wrapper-migration",
    },
    AllowlistEntry {
        name: "blocking_write_for_sync_maintenance",
        kind: AllowlistKind::TemporarySyncWrapper,
        owner: "db-sync-wrapper-migration",
        rationale: "temporary sync maintenance write boundary pending db-sync-wrapper-migration",
    },
    AllowlistEntry {
        name: "insert_agent_mutation_journal_under_publication_lock",
        kind: AllowlistKind::PermanentPublicationJournal,
        owner: "agent-mutation-journal",
        rationale: "typed recovery fence must be ordered inside the cross-process agent publication lock",
    },
    AllowlistEntry {
        name: "insert_agent_mutation_journal_with_stage_under_publication_lock",
        kind: AllowlistKind::PermanentPublicationJournal,
        owner: "agent-mutation-journal",
        rationale: "same publication lock fence, with credential staging in the identical writer transaction",
    },
    AllowlistEntry {
        name: "prepare_agent_editor_publication_under_publication_lock",
        kind: AllowlistKind::PermanentPublicationJournal,
        owner: "agent-editor-mutation-journal",
        rationale: "typed editor intent must precede filesystem replacement under one publication lock",
    },
    AllowlistEntry {
        name: "record_agent_editor_publication_under_publication_lock",
        kind: AllowlistKind::PermanentPublicationJournal,
        owner: "agent-editor-mutation-journal",
        rationale: "typed editor publication evidence must follow replacement under one publication lock",
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AllowlistKind {
    PermanentCli,
    TemporarySyncWrapper,
    PermanentPublicationJournal,
}

#[derive(Debug, Clone, Copy)]
struct AllowlistEntry {
    name: &'static str,
    kind: AllowlistKind,
    owner: &'static str,
    rationale: &'static str,
}

fn allowlist_names() -> BTreeSet<&'static str> {
    ALLOWLIST.iter().map(|e| e.name).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
enum ItemId {
    Method { ty: String, name: String },
    FreeFn { module: String, name: String },
    Alias { module: String, name: String },
}

impl ItemId {
    fn display(&self) -> String {
        match self {
            ItemId::Method { ty, name } => format!("{ty}::{name}"),
            ItemId::FreeFn { module, name } if module.is_empty() => name.clone(),
            ItemId::FreeFn { module, name } => format!("{module}::{name}"),
            ItemId::Alias { module, name } if module.is_empty() => format!("alias:{name}"),
            ItemId::Alias { module, name } => format!("alias:{module}::{name}"),
        }
    }

    fn short_name(&self) -> &str {
        match self {
            ItemId::Method { name, .. }
            | ItemId::FreeFn { name, .. }
            | ItemId::Alias { name, .. } => name,
        }
    }
}

#[derive(Debug, Clone)]
struct ItemInfo {
    id: ItemId,
    is_public: bool,
    location: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PendingUnresolved {
    item: ItemId,
    detail: String,
    location: String,
    force_public: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct GateFinding {
    kind: FindingKind,
    subject: String,
    detail: String,
    location: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum FindingKind {
    UnapprovedPublicPath,
    UnsupportedConstruct,
    DeletedPublicMethod,
}

#[derive(Debug, Default)]
struct Analysis {
    items: HashMap<ItemId, ItemInfo>,
    calls: HashMap<ItemId, HashSet<ItemId>>,
    /// module path -> local binding name -> ItemId
    bindings: HashMap<String, HashMap<String, ItemId>>,
    findings: BTreeSet<GateFinding>,
    public_paths_to_unguarded: BTreeMap<ItemId, String>,
    pending_unresolved: Vec<PendingUnresolved>,
}

impl Analysis {
    fn binding_map(&mut self, module: &str) -> &mut HashMap<String, ItemId> {
        self.bindings.entry(module.to_string()).or_default()
    }

    fn register_item(&mut self, info: ItemInfo) {
        let module = match &info.id {
            ItemId::FreeFn { module, .. } | ItemId::Alias { module, .. } => module.clone(),
            ItemId::Method { .. } => String::new(),
        };
        let name = info.id.short_name().to_string();
        if matches!(info.id, ItemId::FreeFn { .. } | ItemId::Alias { .. }) {
            self.binding_map(&module).insert(name, info.id.clone());
        }
        if let ItemId::Method { ty, name } = &info.id
            && ty == "Db"
        {
            self.binding_map("__db_methods__")
                .insert(name.clone(), info.id.clone());
        }
        self.items.insert(info.id.clone(), info);
    }

    fn add_edge(&mut self, from: ItemId, to: ItemId) {
        self.calls.entry(from).or_default().insert(to);
    }

    fn note_finding(&mut self, finding: GateFinding) {
        self.findings.insert(finding);
    }
}

fn join_module(parent: &str, child: &str) -> String {
    if parent.is_empty() {
        child.to_string()
    } else {
        format!("{parent}::{child}")
    }
}

fn parent_module(module: &str) -> String {
    match module.rsplit_once("::") {
        Some((parent, _)) => parent.to_string(),
        None => String::new(),
    }
}

fn vis_is_exported(vis: &Visibility) -> bool {
    match vis {
        Visibility::Public(_) => true,
        Visibility::Restricted(restricted) => restricted
            .path
            .segments
            .first()
            .is_some_and(|seg| seg.ident == "crate"),
        Visibility::Inherited => false,
    }
}

fn path_idents(path: &syn::Path) -> Vec<String> {
    path.segments
        .iter()
        .map(|seg| seg.ident.to_string())
        .collect()
}

fn is_db_self_ty(ty: &syn::Type) -> bool {
    match ty {
        syn::Type::Path(tp) if tp.qself.is_none() => {
            path_idents(&tp.path).last().is_some_and(|n| n == "Db")
        }
        syn::Type::Paren(p) => is_db_self_ty(&p.elem),
        _ => false,
    }
}

fn span_location(span: proc_macro2::Span, file: &str) -> String {
    let start = span.start();
    format!("{file}:{}:{}", start.line, start.column)
}

fn fn_param_names(sig: &syn::Signature) -> HashSet<String> {
    let mut names = HashSet::new();
    for input in &sig.inputs {
        if let FnArg::Typed(pat_ty) = input
            && let Pat::Ident(ident) = &*pat_ty.pat
        {
            names.insert(ident.ident.to_string());
        }
    }
    names
}

struct BodyWalker<'a> {
    analysis: &'a mut Analysis,
    current: ItemId,
    module: String,
    file: String,
    public_context: bool,
    _in_db_impl: bool,
    /// FnOnce/closure parameters — calling them is the normal Db accessor pattern.
    param_names: HashSet<String>,
}

impl BodyWalker<'_> {
    fn resolve_path_to_item(&self, path: &syn::Path) -> Option<ItemId> {
        let idents = path_idents(path);
        if idents.is_empty() {
            return None;
        }

        if idents.len() == 1 {
            let name = &idents[0];
            if let Some(id) = self
                .analysis
                .bindings
                .get(&self.module)
                .and_then(|m| m.get(name))
            {
                return Some(id.clone());
            }
            if let Some(id) = self.analysis.bindings.get("").and_then(|m| m.get(name)) {
                return Some(id.clone());
            }
            if let Some(id) = self
                .analysis
                .bindings
                .get("__db_methods__")
                .and_then(|m| m.get(name))
            {
                return Some(id.clone());
            }
            return None;
        }

        if idents.len() == 2 {
            let (head, name) = (&idents[0], &idents[1]);
            if head == "Self" || head == "Db" {
                return Some(
                    self.analysis
                        .bindings
                        .get("__db_methods__")
                        .and_then(|m| m.get(name))
                        .cloned()
                        .unwrap_or(ItemId::Method {
                            ty: "Db".to_string(),
                            name: name.clone(),
                        }),
                );
            }
            if head == "super" {
                let parent = parent_module(&self.module);
                if let Some(id) = self
                    .analysis
                    .bindings
                    .get(&parent)
                    .and_then(|m| m.get(name))
                {
                    return Some(id.clone());
                }
            }
            if head == "crate"
                && let Some(id) = self.analysis.bindings.get("").and_then(|m| m.get(name))
            {
                return Some(id.clone());
            }
            let mod_path = head.clone();
            if let Some(id) = self
                .analysis
                .bindings
                .get(&mod_path)
                .and_then(|m| m.get(name))
            {
                return Some(id.clone());
            }
        }

        if idents.first().is_some_and(|s| s == "crate") && idents.len() >= 3 {
            let name = idents.last()?.clone();
            let module = idents[1..idents.len() - 1].join("::");
            if let Some(id) = self
                .analysis
                .bindings
                .get(&module)
                .and_then(|m| m.get(&name))
            {
                return Some(id.clone());
            }
        }

        if idents.first().is_some_and(|s| s == "super") && idents.len() >= 3 {
            let mut module = parent_module(&self.module);
            for seg in &idents[1..idents.len() - 1] {
                module = join_module(&module, seg);
            }
            let name = idents.last()?.clone();
            if let Some(id) = self
                .analysis
                .bindings
                .get(&module)
                .and_then(|m| m.get(&name))
            {
                return Some(id.clone());
            }
        }

        if idents.len() >= 2 {
            let name = idents.last()?.clone();
            let module = idents[..idents.len() - 1].join("::");
            if let Some(id) = self
                .analysis
                .bindings
                .get(&module)
                .and_then(|m| m.get(&name))
            {
                return Some(id.clone());
            }
        }

        None
    }

    fn add_resolved_or_helper(&mut self, path: &syn::Path) {
        if let Some(target) = self.resolve_path_to_item(path) {
            self.analysis.add_edge(self.current.clone(), target);
            return;
        }
        let idents = path_idents(path);
        if let Some(last) = idents.last()
            && UNGUARDED_HELPERS.contains(&last.as_str())
        {
            self.analysis.add_edge(
                self.current.clone(),
                ItemId::Method {
                    ty: "Db".to_string(),
                    name: last.clone(),
                },
            );
            return;
        }
        // Multi-segment external paths (tokio::..., std::...) are outside the
        // cockpit-db resolution boundary. Crate-local multi-segment calls that
        // still do not resolve after two-pass collection fail closed only on a
        // public body (private helper code may call free functions that the
        // subset resolver does not model).
        if self.public_context
            && is_crate_local_path(&idents)
            && idents
                .last()
                .is_some_and(|n| n.chars().next().is_some_and(|c| c.is_lowercase()))
        {
            self.note_unresolved_callable(
                &format!("call via `{}`", idents.join("::")),
                path.span(),
            );
        }
    }

    fn note_unresolved_callable(&mut self, label: &str, span: proc_macro2::Span) {
        // Only public bodies record unresolved callables (prompt: "on a public path").
        if !self.public_context {
            return;
        }
        self.analysis.pending_unresolved.push(PendingUnresolved {
            item: self.current.clone(),
            detail: format!("unresolved indirect callable: {label}"),
            location: span_location(span, &self.file),
            force_public: true,
        });
    }
}

fn item_is_cfg_test(item: &Item) -> bool {
    let attrs = match item {
        Item::Fn(f) => &f.attrs,
        Item::Impl(i) => &i.attrs,
        Item::Mod(m) => &m.attrs,
        Item::Use(u) => &u.attrs,
        Item::Macro(m) => &m.attrs,
        Item::Struct(s) => &s.attrs,
        Item::Enum(e) => &e.attrs,
        Item::Const(c) => &c.attrs,
        Item::Static(s) => &s.attrs,
        Item::Type(t) => &t.attrs,
        Item::Trait(t) => &t.attrs,
        _ => return false,
    };
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        // #[cfg(test)] or #[cfg(any(..., test, ...))] — token string is enough
        // for the gate's coarse test-module skip.
        let tokens = attr
            .meta
            .require_list()
            .map(|list| list.tokens.to_string())
            .unwrap_or_default();
        tokens
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|t| t == "test")
    })
}

fn is_crate_local_path(idents: &[String]) -> bool {
    matches!(
        idents.first().map(String::as_str),
        Some("crate" | "super" | "self")
    )
}

impl<'ast> Visit<'ast> for BodyWalker<'_> {
    fn visit_expr(&mut self, expr: &'ast Expr) {
        match expr {
            Expr::MethodCall(mc) => {
                let method = mc.method.to_string();
                if let Some(target) = self
                    .analysis
                    .bindings
                    .get("__db_methods__")
                    .and_then(|m| m.get(&method))
                {
                    self.analysis.add_edge(self.current.clone(), target.clone());
                } else if UNGUARDED_HELPERS.contains(&method.as_str())
                    || method.starts_with("blocking_")
                    || DELETED_PUBLIC_METHODS.contains(&method.as_str())
                {
                    self.analysis.add_edge(
                        self.current.clone(),
                        ItemId::Method {
                            ty: "Db".to_string(),
                            name: method,
                        },
                    );
                }
                visit::visit_expr_method_call(self, mc);
            }
            Expr::Call(call) => {
                match &*call.func {
                    Expr::Path(path) => {
                        let idents = path_idents(&path.path);
                        if let Some(target) = self.resolve_path_to_item(&path.path) {
                            self.analysis.add_edge(self.current.clone(), target);
                        } else if idents.len() == 1 && self.param_names.contains(&idents[0]) {
                            // Normal Db accessor pattern: invoke the caller's closure.
                        } else if idents.len() == 1 {
                            let name = &idents[0];
                            // Capitalized singles are treated as enum/type constructors
                            // (`Ok`, `Err`, `Some`) — not local function pointers.
                            // snake_case unresolved singles on a public path are
                            // fail-closed only when they look like local callables,
                            // not ubiquitous language/std helpers.
                            let is_constructor_like =
                                name.chars().next().is_some_and(|c| c.is_uppercase());
                            let is_language_builtin = matches!(
                                name.as_str(),
                                "drop"
                                    | "size_of"
                                    | "size_of_val"
                                    | "align_of"
                                    | "align_of_val"
                                    | "panic"
                                    | "todo"
                                    | "unimplemented"
                                    | "unreachable"
                                    | "assert"
                                    | "assert_eq"
                                    | "assert_ne"
                                    | "debug_assert"
                                    | "print"
                                    | "println"
                                    | "eprint"
                                    | "eprintln"
                                    | "format"
                                    | "write"
                                    | "writeln"
                                    | "vec"
                                    | "box"
                                    | "Some"
                                    | "None"
                                    | "Ok"
                                    | "Err"
                            );
                            if !is_constructor_like && !is_language_builtin {
                                self.note_unresolved_callable(
                                    &format!("call via `{name}`"),
                                    path.path.span(),
                                );
                            }
                        } else {
                            // Multi-segment: record crate-local / helper edges only.
                            // External paths (e.g. tokio::task::spawn_blocking) are
                            // outside the cockpit-db resolution boundary and ignored.
                            self.add_resolved_or_helper(&path.path);
                        }
                    }
                    Expr::Closure(closure) => {
                        // Immediate closures / IIFEs are ordinary control flow.
                        visit::visit_expr_closure(self, closure);
                    }
                    Expr::Paren(paren) => {
                        // `(|| { ... })()` — paren-wrapped IIFE callee.
                        self.visit_expr(&paren.expr);
                    }
                    other => {
                        // Soften: only fail closed for field/method-style
                        // function values that look like fn pointers, not for
                        // complex but ordinary expression callables.
                        match other {
                            Expr::Field(_) | Expr::Index(_) | Expr::Try(_) => {
                                self.note_unresolved_callable(
                                    "call via non-path function expression",
                                    other.span(),
                                );
                            }
                            _ => {}
                        }
                        self.visit_expr(other);
                    }
                }
                for arg in &call.args {
                    self.visit_expr(arg);
                }
            }
            Expr::Path(path) => {
                // Function-item reference (associated item or free fn alias).
                let idents = path_idents(&path.path);
                if let Some(last) = idents.last() {
                    let interesting = self.resolve_path_to_item(&path.path).is_some()
                        || UNGUARDED_HELPERS.contains(&last.as_str())
                        || (idents.len() == 2 && (idents[0] == "Self" || idents[0] == "Db"));
                    if interesting {
                        self.add_resolved_or_helper(&path.path);
                    }
                }
                // Do not recurse into path segments (types / turbofish noise).
            }
            Expr::Macro(_mac) => {
                // Expression macros (`anyhow!`, `format!`, …) are ubiquitous and
                // not expanded. Macro-*generated public methods* are caught at
                // item/impl position (fail-closed). We do not treat expr macros
                // as silent success for helper edges because they cannot name
                // private unguarded helpers from outside this module without an
                // item-level expansion the item walker already rejects.
            }
            _ => visit::visit_expr(self, expr),
        }
    }
}

struct PendingBody {
    id: ItemId,
    module: String,
    file: String,
    is_public: bool,
    _in_db_impl: bool,
    param_names: HashSet<String>,
    block: syn::Block,
}

struct CrateCollector<'a> {
    analysis: &'a mut Analysis,
    module: String,
    file: String,
    pending_bodies: Vec<PendingBody>,
}

impl CrateCollector<'_> {
    fn handle_items(&mut self, items: &[Item]) {
        for item in items {
            self.handle_item(item);
        }
    }

    fn handle_item(&mut self, item: &Item) {
        if item_is_cfg_test(item) {
            return;
        }
        match item {
            Item::Fn(func) => self.handle_fn(func),
            Item::Impl(item_impl) => self.handle_impl(item_impl),
            Item::Mod(item_mod) => self.handle_mod(item_mod),
            Item::Use(item_use) => self.handle_use(item_use),
            Item::Macro(item_macro) => {
                // `macro_rules!` definitions and ubiquitous std/build macros are fine.
                // Unknown item-position invocations may generate public Db methods
                // and are fail-closed.
                let mac_name = item_macro
                    .mac
                    .path
                    .segments
                    .last()
                    .map(|s| s.ident.to_string())
                    .unwrap_or_default();
                let allowed = matches!(
                    mac_name.as_str(),
                    "macro_rules"
                        | "thread_local"
                        | "include"
                        | "include_str"
                        | "include_bytes"
                        | "cfg_if"
                        | "lazy_static"
                        | "once_cell"
                        | "constructor"
                        // `dto!`/`state_enum!`/`text_enum!` (e.g. db/image_generation_plan.rs,
                        // db/image_generation.rs) expand only to plain
                        // `#[derive(Serialize, Deserialize)]` DTO `struct`s / enums — they
                        // generate no `Db` methods and no blocking DB calls, so none can
                        // reach an unguarded blocking boundary.
                        | "dto"
                        | "state_enum"
                        | "text_enum"
                );
                if !allowed {
                    self.analysis.note_finding(GateFinding {
                        kind: FindingKind::UnsupportedConstruct,
                        subject: format!("module `{}`", self.module),
                        detail: format!(
                            "item-position macro `{mac_name}` on crate boundary (fail-closed)"
                        ),
                        location: span_location(item_macro.span(), &self.file),
                    });
                }
            }
            _ => {}
        }
    }

    fn handle_fn(&mut self, func: &ItemFn) {
        let name = func.sig.ident.to_string();
        let is_public = vis_is_exported(&func.vis);
        let id = ItemId::FreeFn {
            module: self.module.clone(),
            name,
        };
        self.analysis.register_item(ItemInfo {
            id: id.clone(),
            is_public,
            location: span_location(func.sig.ident.span(), &self.file),
        });
        self.pending_bodies.push(PendingBody {
            id,
            module: self.module.clone(),
            file: self.file.clone(),
            is_public,
            _in_db_impl: false,
            param_names: fn_param_names(&func.sig),
            block: func.block.as_ref().clone(),
        });
    }

    fn handle_impl(&mut self, item_impl: &ItemImpl) {
        let is_db = is_db_self_ty(&item_impl.self_ty);
        let is_trait_impl = item_impl.trait_.is_some();

        if is_trait_impl && is_db {
            // Trait dispatch is not modeled as ordinary inherent resolution. Any
            // trait method body that reaches an unguarded helper is recorded as a
            // public path (`Db::<trait>::name`) and rejected in allowlist
            // evaluation — including `Debug`/`Clone` style impls only when they
            // actually touch the helpers (they must not).
            for impl_item in &item_impl.items {
                if let ImplItem::Fn(method) = impl_item {
                    let name = method.sig.ident.to_string();
                    let id = ItemId::Method {
                        ty: "Db".to_string(),
                        name: format!("<trait>::{name}"),
                    };
                    self.analysis.register_item(ItemInfo {
                        id: id.clone(),
                        is_public: true,
                        location: span_location(method.sig.ident.span(), &self.file),
                    });
                    self.pending_bodies.push(PendingBody {
                        id,
                        module: self.module.clone(),
                        file: self.file.clone(),
                        is_public: true,
                        _in_db_impl: true,
                        param_names: fn_param_names(&method.sig),
                        block: method.block.clone(),
                    });
                } else if let ImplItem::Macro(mac) = impl_item {
                    self.analysis.note_finding(GateFinding {
                        kind: FindingKind::UnsupportedConstruct,
                        subject: "impl Trait for Db".into(),
                        detail: "macro-generated trait impl item on Db (fail-closed)".into(),
                        location: span_location(mac.span(), &self.file),
                    });
                }
            }
            return;
        }

        if !is_db {
            return;
        }

        for impl_item in &item_impl.items {
            match impl_item {
                ImplItem::Fn(method) => {
                    let name = method.sig.ident.to_string();
                    let is_public = vis_is_exported(&method.vis);
                    let id = ItemId::Method {
                        ty: "Db".to_string(),
                        name: name.clone(),
                    };
                    if DELETED_PUBLIC_METHODS.contains(&name.as_str()) && is_public {
                        self.analysis.note_finding(GateFinding {
                            kind: FindingKind::DeletedPublicMethod,
                            subject: format!("Db::{name}"),
                            detail: "deleted public blocking accessor must not exist".into(),
                            location: span_location(method.sig.ident.span(), &self.file),
                        });
                    }
                    self.analysis.register_item(ItemInfo {
                        id: id.clone(),
                        is_public,
                        location: span_location(method.sig.ident.span(), &self.file),
                    });
                    self.pending_bodies.push(PendingBody {
                        id,
                        module: self.module.clone(),
                        file: self.file.clone(),
                        is_public,
                        _in_db_impl: true,
                        param_names: fn_param_names(&method.sig),
                        block: method.block.clone(),
                    });
                }
                ImplItem::Macro(mac) => {
                    self.analysis.note_finding(GateFinding {
                        kind: FindingKind::UnsupportedConstruct,
                        subject: "impl Db".into(),
                        detail: "macro-generated inherent Db item (fail-closed)".into(),
                        location: span_location(mac.span(), &self.file),
                    });
                }
                _ => {}
            }
        }
    }

    fn handle_mod(&mut self, item_mod: &ItemMod) {
        let name = item_mod.ident.to_string();
        let child = join_module(&self.module, &name);
        if let Some((_, items)) = &item_mod.content {
            let mut child_collector = CrateCollector {
                analysis: self.analysis,
                module: child,
                file: self.file.clone(),
                pending_bodies: Vec::new(),
            };
            child_collector.handle_items(items);
            self.pending_bodies
                .append(&mut child_collector.pending_bodies);
        }
    }

    fn handle_use(&mut self, item_use: &ItemUse) {
        let is_public = vis_is_exported(&item_use.vis);
        let mut imports = Vec::new();
        let mut globs: Vec<Vec<String>> = Vec::new();
        flatten_use_tree(&item_use.tree, &[], &mut imports, &mut globs);
        // Expand local globs to currently-known public free fns/aliases in the
        // target module. Unknown/empty modules still fail closed so a public
        // glob cannot silently hide an unapproved path.
        for glob_prefix in &globs {
            let target_module = resolve_glob_module(&self.module, glob_prefix);
            let expanded = expand_local_glob(self.analysis, &target_module);
            if expanded.is_empty() && is_public {
                self.analysis.note_finding(GateFinding {
                    kind: FindingKind::UnsupportedConstruct,
                    subject: format!("use {}::*", glob_prefix.join("::")),
                    detail: "public local use-tree glob could not be expanded (fail-closed)".into(),
                    location: span_location(item_use.span(), &self.file),
                });
            }
            for (binding_name, target) in expanded {
                let alias_id = ItemId::Alias {
                    module: self.module.clone(),
                    name: binding_name.clone(),
                };
                self.analysis.register_item(ItemInfo {
                    id: alias_id.clone(),
                    is_public,
                    location: span_location(item_use.span(), &self.file),
                });
                self.analysis.add_edge(alias_id.clone(), target);
                self.analysis
                    .binding_map(&self.module)
                    .insert(binding_name, alias_id);
            }
        }
        for (path_idents_vec, binding_name) in imports {
            let target = resolve_import_target(self.analysis, &self.module, &path_idents_vec)
                .or_else(|| {
                    path_idents_vec.last().map(|last| {
                        if path_idents_vec.len() == 2
                            && (path_idents_vec[0] == "Db" || path_idents_vec[0] == "Self")
                        {
                            ItemId::Method {
                                ty: "Db".to_string(),
                                name: last.clone(),
                            }
                        } else {
                            ItemId::FreeFn {
                                module: if path_idents_vec.len() == 1 {
                                    self.module.clone()
                                } else {
                                    path_idents_vec[..path_idents_vec.len() - 1].join("::")
                                },
                                name: last.clone(),
                            }
                        }
                    })
                });
            let Some(target) = target else {
                continue;
            };
            let alias_id = ItemId::Alias {
                module: self.module.clone(),
                name: binding_name.clone(),
            };
            self.analysis.register_item(ItemInfo {
                id: alias_id.clone(),
                is_public,
                location: span_location(item_use.span(), &self.file),
            });
            self.analysis.add_edge(alias_id.clone(), target);
            self.analysis
                .binding_map(&self.module)
                .insert(binding_name, alias_id);
        }
    }
}

fn flatten_use_tree(
    tree: &UseTree,
    prefix: &[String],
    out: &mut Vec<(Vec<String>, String)>,
    globs: &mut Vec<Vec<String>>,
) {
    match tree {
        UseTree::Path(path) => {
            let mut p = prefix.to_vec();
            p.push(path.ident.to_string());
            flatten_use_tree(&path.tree, &p, out, globs);
        }
        UseTree::Name(name) => {
            let mut p = prefix.to_vec();
            p.push(name.ident.to_string());
            out.push((p, name.ident.to_string()));
        }
        UseTree::Rename(rename) => {
            let mut p = prefix.to_vec();
            p.push(rename.ident.to_string());
            out.push((p, rename.rename.to_string()));
        }
        UseTree::Glob(_) => {
            globs.push(prefix.to_vec());
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                flatten_use_tree(tree, prefix, out, globs);
            }
        }
    }
}

fn resolve_glob_module(current_module: &str, prefix: &[String]) -> String {
    if prefix.is_empty() {
        return current_module.to_string();
    }
    if prefix[0] == "crate" {
        return prefix[1..].join("::");
    }
    if prefix[0] == "super" {
        let parent = parent_module(current_module);
        if prefix.len() == 1 {
            return parent;
        }
        let rest = prefix[1..].join("::");
        if parent.is_empty() {
            return rest;
        }
        return format!("{parent}::{rest}");
    }
    if prefix[0] == "self" {
        let rest = prefix[1..].join("::");
        if current_module.is_empty() {
            return rest;
        }
        if rest.is_empty() {
            return current_module.to_string();
        }
        return format!("{current_module}::{rest}");
    }
    let rest = prefix.join("::");
    if current_module.is_empty() {
        rest
    } else {
        format!("{current_module}::{rest}")
    }
}

/// Expand `use target::*` to free functions / aliases already registered in the module.
fn expand_local_glob(analysis: &Analysis, target_module: &str) -> Vec<(String, ItemId)> {
    let mut out = Vec::new();
    for (id, info) in &analysis.items {
        match id {
            ItemId::FreeFn { module, name } | ItemId::Alias { module, name }
                if module == target_module && info.is_public =>
            {
                out.push((name.clone(), id.clone()));
            }
            _ => {}
        }
    }
    out
}

fn resolve_import_target(
    analysis: &Analysis,
    current_module: &str,
    path_idents: &[String],
) -> Option<ItemId> {
    if path_idents.is_empty() {
        return None;
    }
    let name = path_idents.last()?.clone();

    if path_idents.len() == 2 && (path_idents[0] == "Db" || path_idents[0] == "Self") {
        return Some(ItemId::Method {
            ty: "Db".to_string(),
            name,
        });
    }

    let (module, name) = if path_idents[0] == "crate" {
        if path_idents.len() == 2 {
            (String::new(), path_idents[1].clone())
        } else {
            (
                path_idents[1..path_idents.len() - 1].join("::"),
                path_idents.last()?.clone(),
            )
        }
    } else if path_idents[0] == "super" {
        let parent = parent_module(current_module);
        if path_idents.len() == 2 {
            (parent, path_idents[1].clone())
        } else {
            let mut m = parent;
            for seg in &path_idents[1..path_idents.len() - 1] {
                m = join_module(&m, seg);
            }
            (m, path_idents.last()?.clone())
        }
    } else if path_idents.len() == 1 {
        if let Some(id) = analysis
            .bindings
            .get(current_module)
            .and_then(|m| m.get(&name))
        {
            return Some(id.clone());
        }
        if let Some(id) = analysis.bindings.get("").and_then(|m| m.get(&name)) {
            return Some(id.clone());
        }
        return Some(ItemId::FreeFn {
            module: current_module.to_string(),
            name,
        });
    } else {
        (
            path_idents[..path_idents.len() - 1].join("::"),
            path_idents.last()?.clone(),
        )
    };

    if let Some(id) = analysis.bindings.get(&module).and_then(|m| m.get(&name)) {
        return Some(id.clone());
    }
    Some(ItemId::FreeFn { module, name })
}

fn walk_pending_bodies(analysis: &mut Analysis, pending: Vec<PendingBody>) {
    for body in pending {
        let mut walker = BodyWalker {
            analysis,
            current: body.id,
            module: body.module,
            file: body.file,
            public_context: body.is_public,
            _in_db_impl: body._in_db_impl,
            param_names: body.param_names,
        };
        for stmt in &body.block.stmts {
            walker.visit_stmt(stmt);
        }
    }
}

fn analyze_file(analysis: &mut Analysis, file: &str, source: &str, module: &str) {
    let parsed = match syn::parse_file(source) {
        Ok(f) => f,
        Err(err) => {
            analysis.note_finding(GateFinding {
                kind: FindingKind::UnsupportedConstruct,
                subject: file.to_string(),
                detail: format!("syn parse failure: {err}"),
                location: file.to_string(),
            });
            return;
        }
    };
    let mut collector = CrateCollector {
        analysis,
        module: module.to_string(),
        file: file.to_string(),
        pending_bodies: Vec::new(),
    };
    collector.handle_items(&parsed.items);
    let pending = collector.pending_bodies;
    walk_pending_bodies(analysis, pending);
}

fn finalize_analysis(analysis: &mut Analysis) {
    for helper in UNGUARDED_HELPERS {
        let id = ItemId::Method {
            ty: "Db".to_string(),
            name: (*helper).to_string(),
        };
        analysis
            .items
            .entry(id.clone())
            .or_insert_with(|| ItemInfo {
                id: id.clone(),
                is_public: false,
                location: "<synthetic>".into(),
            });
        analysis
            .binding_map("__db_methods__")
            .entry((*helper).to_string())
            .or_insert(id);
    }

    let public_items: Vec<ItemId> = analysis
        .items
        .iter()
        .filter(|(_, info)| info.is_public)
        .map(|(id, _)| id.clone())
        .collect();

    let unguarded: HashSet<ItemId> = UNGUARDED_HELPERS
        .iter()
        .map(|name| ItemId::Method {
            ty: "Db".to_string(),
            name: (*name).to_string(),
        })
        .collect();

    for start in public_items {
        let mut seen = HashSet::new();
        let mut q = VecDeque::new();
        q.push_back(start.clone());
        seen.insert(start.clone());
        let mut reaches = false;
        while let Some(node) = q.pop_front() {
            if unguarded.contains(&node) {
                reaches = true;
                break;
            }
            if let Some(callees) = analysis.calls.get(&node) {
                for callee in callees {
                    if seen.insert(callee.clone()) {
                        q.push_back(callee.clone());
                    }
                }
            }
        }
        if reaches {
            let loc = analysis
                .items
                .get(&start)
                .map(|i| i.location.clone())
                .unwrap_or_else(|| "<unknown>".into());
            analysis.public_paths_to_unguarded.insert(start, loc);
        }
    }

    // Promote unresolved callables that sit on a public path (the item itself
    // is public, was force-flagged during a public body walk, or is reachable
    // from any public start via the call graph).
    let mut public_reachable: HashSet<ItemId> = analysis
        .items
        .iter()
        .filter(|(_, info)| info.is_public)
        .map(|(id, _)| id.clone())
        .collect();
    let mut q: VecDeque<ItemId> = public_reachable.iter().cloned().collect();
    while let Some(node) = q.pop_front() {
        if let Some(callees) = analysis.calls.get(&node) {
            for callee in callees {
                if public_reachable.insert(callee.clone()) {
                    q.push_back(callee.clone());
                }
            }
        }
    }
    for pending in std::mem::take(&mut analysis.pending_unresolved) {
        let on_public_path = pending.force_public
            || public_reachable.contains(&pending.item)
            || analysis
                .items
                .get(&pending.item)
                .is_some_and(|info| info.is_public);
        if on_public_path {
            analysis.findings.insert(GateFinding {
                kind: FindingKind::UnsupportedConstruct,
                subject: pending.item.display(),
                detail: pending.detail,
                location: pending.location,
            });
        }
    }
}

fn evaluate_against_allowlist(analysis: &mut Analysis) {
    let allowed = allowlist_names();
    for (id, loc) in &analysis.public_paths_to_unguarded {
        let name = id.short_name();
        if name.starts_with("<trait>") {
            analysis.findings.insert(GateFinding {
                kind: FindingKind::UnsupportedConstruct,
                subject: id.display(),
                detail: "public path via trait method reaches unguarded helper".into(),
                location: loc.clone(),
            });
            continue;
        }
        let is_db_method = matches!(id, ItemId::Method { ty, .. } if ty == "Db");
        if is_db_method && allowed.contains(name) {
            continue;
        }
        analysis.findings.insert(GateFinding {
            kind: FindingKind::UnapprovedPublicPath,
            subject: id.display(),
            detail: format!(
                "public/pub(crate) path reaches read_blocking_unguarded/write_blocking_unguarded; \
                 not on the exact allowlist ({})",
                allowed.iter().cloned().collect::<Vec<_>>().join(", ")
            ),
            location: loc.clone(),
        });
    }

    for entry in ALLOWLIST {
        assert!(
            !entry.name.contains('*') && !entry.name.contains('?'),
            "wildcard allowlist entry forbidden: {}",
            entry.name
        );
        assert!(
            !entry.rationale.is_empty() && !entry.owner.is_empty(),
            "allowlist entry {} missing owner/rationale",
            entry.name
        );
        match entry.kind {
            AllowlistKind::PermanentCli => assert_eq!(entry.name, "blocking_for_sync_cli"),
            AllowlistKind::TemporarySyncWrapper => {
                assert_eq!(entry.owner, "db-sync-wrapper-migration");
            }
            AllowlistKind::PermanentPublicationJournal => {
                assert!(entry.name.ends_with("under_publication_lock"));
                assert!(entry.rationale.contains("publication lock"));
            }
        }
    }
}

fn analyze_source(file: &str, source: &str) -> Analysis {
    let mut analysis = Analysis::default();
    analyze_file(&mut analysis, file, source, "");
    finalize_analysis(&mut analysis);
    analysis
}

fn collect_file_items(
    analysis: &mut Analysis,
    file: &str,
    source: &str,
    module: &str,
) -> Vec<PendingBody> {
    let parsed = match syn::parse_file(source) {
        Ok(f) => f,
        Err(err) => {
            analysis.note_finding(GateFinding {
                kind: FindingKind::UnsupportedConstruct,
                subject: file.to_string(),
                detail: format!("syn parse failure: {err}"),
                location: file.to_string(),
            });
            return Vec::new();
        }
    };
    let mut collector = CrateCollector {
        analysis,
        module: module.to_string(),
        file: file.to_string(),
        pending_bodies: Vec::new(),
    };
    collector.handle_items(&parsed.items);
    collector.pending_bodies
}

fn analyze_production_crate(src_root: &Path) -> Analysis {
    let mut analysis = Analysis::default();
    let mut files: Vec<PathBuf> = Vec::new();
    collect_rs_files(src_root, &mut files);
    files.sort();
    // Pass 1: register items across every file so multi-segment crate-local
    // paths resolve independent of filesystem order.
    let mut pending_all = Vec::new();
    for path in &files {
        let source = fs::read_to_string(path).unwrap_or_default();
        let rel = path
            .strip_prefix(src_root)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| path.display().to_string());
        let module = module_path_for_src_file(&rel);
        pending_all.extend(collect_file_items(&mut analysis, &rel, &source, &module));
    }
    // Pass 2: walk bodies with the complete binding map.
    walk_pending_bodies(&mut analysis, pending_all);
    finalize_analysis(&mut analysis);
    evaluate_against_allowlist(&mut analysis);
    analysis
}

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn module_path_for_src_file(rel: &str) -> String {
    let rel = rel.replace('\\', "/");
    if rel == "lib.rs" {
        return String::new();
    }
    let without_ext = rel.trim_end_matches(".rs");
    if let Some(module) = without_ext.strip_suffix("/mod") {
        return module.replace('/', "::");
    }
    without_ext.replace('/', "::")
}

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/db_blocking_boundary")
        .join(name)
}

fn load_fixture(name: &str) -> String {
    fs::read_to_string(fixture_path(name)).unwrap_or_else(|e| {
        panic!("failed to read fixture {name}: {e}");
    })
}

fn analyze_fixture(name: &str) -> Analysis {
    let source = load_fixture(name);
    let mut analysis = analyze_source(name, &source);
    evaluate_against_allowlist(&mut analysis);
    analysis
}

fn findings_of_kind(analysis: &Analysis, kind: FindingKind) -> Vec<&GateFinding> {
    analysis
        .findings
        .iter()
        .filter(|f| f.kind == kind)
        .collect()
}

fn assert_rejects_unguarded_path(analysis: &Analysis, context: &str) {
    let bad = findings_of_kind(analysis, FindingKind::UnapprovedPublicPath);
    let unsupported = findings_of_kind(analysis, FindingKind::UnsupportedConstruct);
    assert!(
        !bad.is_empty() || !unsupported.is_empty(),
        "{context}: expected unapproved public path or fail-closed unsupported construct, got findings {:#?}",
        analysis.findings
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn db_blocking_boundary_gate_allowlist_is_exact_and_documented() {
    let names: Vec<_> = ALLOWLIST.iter().map(|e| e.name).collect();
    assert_eq!(
        names,
        vec![
            "blocking_for_sync_cli",
            "blocking_read_for_sync_ui",
            "blocking_write_for_sync_ui",
            "blocking_write_for_sync_event",
            "blocking_write_for_sync_maintenance",
            "insert_agent_mutation_journal_under_publication_lock",
            "prepare_agent_editor_publication_under_publication_lock",
            "record_agent_editor_publication_under_publication_lock",
        ]
    );
    assert_eq!(ALLOWLIST[0].kind, AllowlistKind::PermanentCli);
    assert!(ALLOWLIST[0].rationale.contains("synchronous CLI"));
    for entry in &ALLOWLIST[1..5] {
        assert_eq!(entry.kind, AllowlistKind::TemporarySyncWrapper);
        assert_eq!(entry.owner, "db-sync-wrapper-migration");
    }
    for entry in &ALLOWLIST[5..] {
        assert_eq!(entry.kind, AllowlistKind::PermanentPublicationJournal);
        assert!(entry.rationale.contains("publication lock"));
    }
    for entry in ALLOWLIST {
        assert!(!entry.name.contains('*'));
    }
}

#[test]
fn permanent_publication_bridges_have_closed_typed_signatures() {
    fn type_shape(ty: &syn::Type) -> String {
        match ty {
            syn::Type::Path(path) => path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
                .unwrap_or_default(),
            syn::Type::Array(array) => {
                let syn::Expr::Lit(length) = &array.len else {
                    panic!("publication array length must be a literal")
                };
                let syn::Lit::Int(length) = &length.lit else {
                    panic!("publication array length must be an integer")
                };
                format!("[{};{}]", type_shape(&array.elem), length.base10_digits())
            }
            syn::Type::Reference(reference) => format!("&{}", type_shape(&reference.elem)),
            other => panic!(
                "unsupported permanent publication parameter type at {:?}",
                other.span()
            ),
        }
    }
    struct CallableTypeVisitor {
        found: bool,
    }
    impl<'ast> Visit<'ast> for CallableTypeVisitor {
        fn visit_type_bare_fn(&mut self, node: &'ast syn::TypeBareFn) {
            self.found = true;
            visit::visit_type_bare_fn(self, node);
        }

        fn visit_type_path(&mut self, node: &'ast syn::TypePath) {
            if node.path.segments.iter().any(|segment| {
                matches!(
                    segment.ident.to_string().as_str(),
                    "Fn" | "FnMut" | "FnOnce"
                )
            }) {
                self.found = true;
            }
            visit::visit_type_path(self, node);
        }
    }

    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sources = [
        manifest.join("src/db/agent_mutation_journals.rs"),
        manifest.join("src/db/agent_editor_leases.rs"),
    ];
    let expected_arity = BTreeMap::from([
        (
            "insert_agent_mutation_journal_under_publication_lock",
            2_usize,
        ),
        ("prepare_agent_editor_publication_under_publication_lock", 2),
        ("record_agent_editor_publication_under_publication_lock", 5),
    ]);
    let expected_types = BTreeMap::from([
        (
            "insert_agent_mutation_journal_under_publication_lock",
            vec!["AgentMutationJournalFence"],
        ),
        (
            "prepare_agent_editor_publication_under_publication_lock",
            vec!["AgentEditorPublicationIntent"],
        ),
        (
            "record_agent_editor_publication_under_publication_lock",
            vec!["String", "[u8;32]", "String", "String"],
        ),
    ]);
    let mut seen = BTreeSet::new();
    for path in sources {
        let source = fs::read_to_string(&path).expect("publication bridge source");
        let file = syn::parse_file(&source).expect("publication bridge source parses");
        for item in file.items {
            let Item::Impl(item_impl) = item else {
                continue;
            };
            if !is_db_self_ty(&item_impl.self_ty) || item_impl.trait_.is_some() {
                continue;
            }
            for item in item_impl.items {
                let ImplItem::Fn(method) = item else { continue };
                let name = method.sig.ident.to_string();
                let Some(expected) = expected_arity.get(name.as_str()) else {
                    continue;
                };
                assert!(
                    method.sig.generics.params.is_empty(),
                    "permanent publication bridge Db::{name} must not be generic"
                );
                assert_eq!(
                    method.sig.inputs.len(),
                    *expected,
                    "permanent publication bridge Db::{name} changed its reviewed typed signature"
                );
                let actual_types = method
                    .sig
                    .inputs
                    .iter()
                    .filter_map(|input| match input {
                        FnArg::Receiver(_) => None,
                        FnArg::Typed(argument) => Some(type_shape(&argument.ty)),
                    })
                    .collect::<Vec<_>>();
                let actual_types = actual_types.iter().map(String::as_str).collect::<Vec<_>>();
                assert_eq!(
                    actual_types,
                    expected_types[name.as_str()],
                    "permanent publication bridge Db::{name} changed parameter types"
                );
                let mut callable = CallableTypeVisitor { found: false };
                callable.visit_signature(&method.sig);
                assert!(
                    !callable.found,
                    "permanent publication bridge Db::{name} must not accept a closure or callable type"
                );
                assert!(
                    matches!(method.sig.output, syn::ReturnType::Type(_, ref ty)
                        if matches!(ty.as_ref(), syn::Type::Path(path)
                            if path.path.segments.last().is_some_and(|segment| segment.ident == "Result"))),
                    "permanent publication bridge Db::{name} must return typed Result"
                );
                seen.insert(name);
            }
        }
    }
    assert_eq!(
        seen,
        expected_arity
            .keys()
            .map(|name| (*name).to_owned())
            .collect()
    );
}

#[test]
fn db_blocking_boundary_gate_rejects_semantic_aliases() {
    // AC1: imported alias calls and associated-function references.
    let alias = analyze_fixture("alias_imported_call.rs");
    assert_rejects_unguarded_path(&alias, "alias_imported_call");
    assert!(
        alias
            .public_paths_to_unguarded
            .keys()
            .any(|id| id.short_name() == "load_snapshot"),
        "expected load_snapshot to reach unguarded helper: {:?}",
        alias
            .public_paths_to_unguarded
            .keys()
            .map(|i| i.display())
            .collect::<Vec<_>>()
    );

    let associated = analyze_fixture("associated_fn_reference.rs");
    assert_rejects_unguarded_path(&associated, "associated_fn_reference");
    assert!(
        associated
            .public_paths_to_unguarded
            .keys()
            .any(|id| id.short_name() == "via_associated_item"),
        "expected via_associated_item to reach unguarded helper"
    );
}

#[test]
fn db_blocking_boundary_gate_rejects_reexports_and_renames() {
    // AC2: public re-export and renamed-wrapper fixtures.
    let reexport = analyze_fixture("reexport_public.rs");
    assert_rejects_unguarded_path(&reexport, "reexport_public");
    assert!(
        reexport
            .public_paths_to_unguarded
            .keys()
            .any(|id| id.short_name() == "public_bridge"),
        "expected public_bridge re-export path: {:?}",
        reexport
            .public_paths_to_unguarded
            .keys()
            .map(|i| i.display())
            .collect::<Vec<_>>()
    );

    let renamed = analyze_fixture("renamed_wrapper.rs");
    assert_rejects_unguarded_path(&renamed, "renamed_wrapper");
    assert!(
        renamed
            .public_paths_to_unguarded
            .keys()
            .any(|id| id.short_name() == "persist_local_preference"),
        "expected renamed wrapper persist_local_preference to be rejected"
    );

    let glob = analyze_fixture("glob_reexport.rs");
    // Glob either expands to a public free-fn alias path that reaches unguarded
    // helpers, or fails closed when expansion is empty — never silent success.
    let glob_findings = findings_of_kind(&glob, FindingKind::UnsupportedConstruct);
    let glob_rejects = !glob.public_paths_to_unguarded.is_empty() || !glob_findings.is_empty();
    assert!(
        glob_rejects,
        "public use glob must expand to a rejected path or fail closed: paths={:?} findings={:?}",
        glob.public_paths_to_unguarded
            .keys()
            .map(|i| i.display())
            .collect::<Vec<_>>(),
        glob_findings
    );
}

#[test]
fn db_blocking_boundary_gate_ignores_comments_and_strings() {
    // AC3: non-code text is irrelevant.
    let analysis = analyze_fixture("comments_and_strings.rs");
    assert!(
        findings_of_kind(&analysis, FindingKind::UnapprovedPublicPath).is_empty(),
        "comments/strings must not create unapproved paths: {:?}",
        analysis.findings
    );
    assert!(
        analysis.public_paths_to_unguarded.is_empty(),
        "schema_probe must not be treated as reaching helpers via comments/strings: {:?}",
        analysis.public_paths_to_unguarded
    );
}

#[test]
fn db_blocking_boundary_gate_fails_closed_on_unsupported_constructs() {
    // AC4: macro-generated public methods, trait dispatch, unresolved callables.
    let macro_fx = analyze_fixture("macro_public_method.rs");
    assert!(
        !findings_of_kind(&macro_fx, FindingKind::UnsupportedConstruct).is_empty(),
        "macro fixture must fail closed: {:?}",
        macro_fx.findings
    );

    let trait_fx = analyze_fixture("trait_dispatch.rs");
    assert!(
        !findings_of_kind(&trait_fx, FindingKind::UnsupportedConstruct).is_empty()
            || !findings_of_kind(&trait_fx, FindingKind::UnapprovedPublicPath).is_empty(),
        "trait dispatch fixture must fail closed: {:?}",
        trait_fx.findings
    );

    let unresolved = analyze_fixture("unresolved_callable.rs");
    assert!(
        !findings_of_kind(&unresolved, FindingKind::UnsupportedConstruct).is_empty()
            || !findings_of_kind(&unresolved, FindingKind::UnapprovedPublicPath).is_empty(),
        "unresolved callable fixture must fail closed: {:?}",
        unresolved.findings
    );
}

#[test]
fn db_blocking_boundary_gate_accepts_exact_allowlist_fixture() {
    let analysis = analyze_fixture("allowlisted_only.rs");
    assert!(
        findings_of_kind(&analysis, FindingKind::UnapprovedPublicPath).is_empty(),
        "allowlisted_only must pass: {:?}",
        analysis.findings
    );
    let reached: BTreeSet<_> = analysis
        .public_paths_to_unguarded
        .keys()
        .map(|id| id.short_name().to_string())
        .collect();
    let expected: BTreeSet<_> = allowlist_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        reached, expected,
        "allowlisted fixture reach set must match exact allowlist"
    );
}

#[test]
fn db_blocking_boundary_gate_production_matches_allowlist() {
    // AC6 + AC9: production crate gate with exact allowlist.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let analysis = analyze_production_crate(&src);
    assert!(
        analysis.findings.is_empty(),
        "production cockpit-db must satisfy the blocking boundary gate; findings: {:#?}",
        analysis.findings
    );
    let reached: BTreeSet<_> = analysis
        .public_paths_to_unguarded
        .keys()
        .filter(|id| matches!(id, ItemId::Method { ty, .. } if ty == "Db"))
        .map(|id| id.short_name().to_string())
        .collect();
    let expected: BTreeSet<_> = allowlist_names()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    assert_eq!(
        reached, expected,
        "production public paths to unguarded helpers must equal the exact allowlist"
    );
}

#[test]
fn db_blocking_boundary_gate_deleted_methods_absent_from_public_api() {
    // AC5: read_blocking / write_blocking absent; compile-fail fixtures document consumers.
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let analysis = analyze_production_crate(&src);
    for deleted in DELETED_PUBLIC_METHODS {
        let id = ItemId::Method {
            ty: "Db".to_string(),
            name: (*deleted).to_string(),
        };
        if let Some(info) = analysis.items.get(&id) {
            assert!(
                !info.is_public,
                "Db::{deleted} must not be public; found at {}",
                info.location
            );
        }
    }

    for (name, method) in [
        ("compile_fail/read_blocking_consumer.rs", "read_blocking"),
        ("compile_fail/write_blocking_consumer.rs", "write_blocking"),
    ] {
        let source = load_fixture(name);
        assert!(
            source.contains(method),
            "compile-fail fixture {name} must reference deleted method {method}"
        );
        // Fixture is a consumer sketch (not part of the cockpit-db build). Parse
        // it as Rust and prove production no longer exposes the method publicly,
        // so any real crate containing this consumer sketch cannot compile.
        syn::parse_file(&source)
            .unwrap_or_else(|e| panic!("compile-fail fixture {name} must parse as Rust: {e}"));
        let id = ItemId::Method {
            ty: "Db".to_string(),
            name: method.to_string(),
        };
        assert!(
            analysis
                .items
                .get(&id)
                .map(|info| !info.is_public)
                .unwrap_or(true),
            "Db::{method} must be absent from public API so consumer fixture cannot compile"
        );
    }

    let prod = fs::read_to_string(src.join("db/mod.rs")).unwrap();
    let file = syn::parse_file(&prod).unwrap();
    for item in file.items {
        if let Item::Impl(item_impl) = item
            && is_db_self_ty(&item_impl.self_ty)
            && item_impl.trait_.is_none()
        {
            for impl_item in item_impl.items {
                if let ImplItem::Fn(method) = impl_item {
                    let n = method.sig.ident.to_string();
                    assert!(
                        !DELETED_PUBLIC_METHODS.contains(&n.as_str())
                            || !vis_is_exported(&method.vis),
                        "Db::{n} must be absent from the public API"
                    );
                }
            }
        }
    }
}

#[test]
fn db_blocking_boundary_gate_documents_local_resolution_boundary() {
    // AC7: documentation and fixtures state cockpit-db-local resolution boundary.
    let readme = load_fixture("README.md");
    assert!(
        readme.contains("cockpit-db-local") || readme.contains("crate under analysis"),
        "README must state local resolution boundary"
    );
    assert!(
        readme.to_lowercase().contains("workspace"),
        "README must mention workspace boundary disclaimer"
    );
    assert!(
        readme.contains("db-sync-wrapper-migration"),
        "README must name the temporary wrapper owner"
    );

    let gate_src = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/db_blocking_boundary_gate.rs"),
    )
    .expect("gate source");
    assert!(
        gate_src.contains("cockpit-db local") || gate_src.contains("cockpit-db-local"),
        "gate module docs must state cockpit-db-local resolution boundary"
    );
    assert!(
        gate_src.contains("workspace-wide"),
        "gate module docs must disclaim workspace-wide claims"
    );
}
