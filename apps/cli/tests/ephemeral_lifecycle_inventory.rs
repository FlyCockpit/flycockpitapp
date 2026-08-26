use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMatch, ExprMethodCall, UseTree};

const PROBE_SUFFIX: &str = "daemon::client::probe_or_spawn";

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProbeSite {
    function: String,
    mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Probe,
    FactoryCall,
    Guard,
    Signal,
    Await,
    Try,
    Aggregate,
    DropGuard,
    ProcessExit,
    Return,
}

#[derive(Debug, Default)]
struct FunctionFacts {
    returns_connected_daemon: bool,
    direct_probe: bool,
    probe_modes: Vec<String>,
    calls: Vec<String>,
    call_positions: Vec<(String, usize)>,
    dynamic_items: Vec<String>,
    unresolved_calls: Vec<(String, usize)>,
    events: Vec<Event>,
}

#[derive(Debug, Default)]
struct Analysis {
    functions: BTreeMap<String, FunctionFacts>,
    probes: Vec<ProbeSite>,
    errors: Vec<String>,
}

struct SourceUnit {
    module: String,
    parsed: syn::File,
    imports: BTreeMap<String, String>,
}

fn module_for(relative: &str) -> String {
    let bare = relative.strip_suffix(".rs").unwrap();
    if matches!(bare, "lib" | "main") {
        return "crate".into();
    }
    let mut parts = bare.split('/').collect::<Vec<_>>();
    if parts.last() == Some(&"mod") {
        parts.pop();
    }
    if parts.is_empty() {
        "crate".into()
    } else {
        format!("crate::{}", parts.join("::"))
    }
}

fn flatten_use(
    tree: &UseTree,
    prefix: &mut Vec<String>,
    public: bool,
    imports: &mut BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    match tree {
        UseTree::Path(path) => {
            prefix.push(path.ident.to_string());
            flatten_use(&path.tree, prefix, public, imports, errors);
            prefix.pop();
        }
        UseTree::Name(name) => register_import(
            prefix,
            &name.ident.to_string(),
            &name.ident.to_string(),
            public,
            imports,
            errors,
        ),
        UseTree::Rename(rename) => register_import(
            prefix,
            &rename.ident.to_string(),
            &rename.rename.to_string(),
            public,
            imports,
            errors,
        ),
        UseTree::Group(group) => {
            for item in &group.items {
                flatten_use(item, prefix, public, imports, errors);
            }
        }
        UseTree::Glob(_) => {
            let canonical = prefix.join("::");
            if canonical.ends_with("daemon::client") {
                errors.push(format!(
                    "glob import can hide lifecycle authority: {canonical}::*"
                ));
            }
        }
    }
}

fn register_import(
    prefix: &[String],
    source: &str,
    local: &str,
    public: bool,
    imports: &mut BTreeMap<String, String>,
    errors: &mut Vec<String>,
) {
    let mut parts = prefix.to_vec();
    parts.push(source.into());
    let canonical = parts.join("::");
    if public && canonical.ends_with(PROBE_SUFFIX) {
        errors.push(format!(
            "public re-export of lifecycle authority: {canonical}"
        ));
    }
    imports.insert(local.into(), canonical);
}

fn resolve_path(path: &syn::Path, module: &str, imports: &BTreeMap<String, String>) -> String {
    let parts = path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>();
    let Some(first) = parts.first() else {
        return "<empty>".into();
    };
    if first == "crate" {
        return parts.join("::");
    }
    if first == "self" {
        return format!("{module}::{}", parts[1..].join("::"));
    }
    if first == "super" {
        let parent = module
            .rsplit_once("::")
            .map_or("crate", |(parent, _)| parent);
        return format!("{parent}::{}", parts[1..].join("::"));
    }
    if let Some(imported) = imports.get(first) {
        return if parts.len() == 1 {
            imported.clone()
        } else {
            format!("{imported}::{}", parts[1..].join("::"))
        };
    }
    if parts.len() == 1 {
        format!("{module}::{first}")
    } else {
        parts.join("::")
    }
}

fn type_contains_connected_daemon(ty: &syn::Type) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    path.path.segments.iter().any(|segment| segment.ident == "ConnectedDaemon" || match &segment.arguments {
        syn::PathArguments::AngleBracketed(args) => args.args.iter().any(|arg| matches!(arg, syn::GenericArgument::Type(ty) if type_contains_connected_daemon(ty))),
        _ => false,
    })
}

fn returns_connected_daemon(output: &syn::ReturnType) -> bool {
    matches!(output, syn::ReturnType::Type(_, ty) if type_contains_connected_daemon(ty))
}

fn resolved_mode_name(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string()),
        Expr::If(branch) => {
            let mut variants = Vec::new();
            if let Some(mode) = branch.then_branch.stmts.last().and_then(stmt_mode) {
                variants.push(mode);
            }
            if let Some((_, otherwise)) = &branch.else_branch
                && let Some(mode) = resolved_mode_name(otherwise)
            {
                variants.push(mode);
            }
            variants.sort();
            variants.dedup();
            (!variants.is_empty()).then(|| variants.join("|"))
        }
        Expr::Block(block) => block.block.stmts.last().and_then(stmt_mode),
        _ => None,
    }
}

fn stmt_mode(statement: &syn::Stmt) -> Option<String> {
    let syn::Stmt::Expr(expression, _) = statement else {
        return None;
    };
    resolved_mode_name(expression)
}

struct FunctionVisitor<'a> {
    module: &'a str,
    imports: &'a BTreeMap<String, String>,
    known: &'a BTreeSet<String>,
    facts: FunctionFacts,
    modes: BTreeMap<String, String>,
    errors: Vec<String>,
}

impl FunctionVisitor<'_> {
    fn event(&mut self, event: Event) {
        self.facts.events.push(event);
    }

    fn known_call(&self, resolved: &str, leaf: &str) -> Option<String> {
        if self.known.contains(resolved) {
            return Some(resolved.into());
        }
        let candidates = self
            .known
            .iter()
            .filter(|name| name.ends_with(&format!("::{leaf}")))
            .cloned()
            .collect::<Vec<_>>();
        (candidates.len() == 1).then(|| candidates[0].clone())
    }

    fn path_call(&mut self, call: &ExprCall, path: &syn::ExprPath) {
        let resolved = resolve_path(&path.path, self.module, self.imports);
        let last = path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if path.qself.is_some() {
            if last.as_deref() == Some("probe_or_spawn")
                || last
                    .as_deref()
                    .and_then(|leaf| self.known_call(&resolved, leaf))
                    .is_some()
            {
                self.errors.push(format!(
                    "QSelf lifecycle call is not auditable: {}",
                    last.as_deref().unwrap_or("<unknown>")
                ));
            }
            return;
        }
        if resolved.ends_with(PROBE_SUFFIX) {
            let mode = call.args.first().map_or_else(
                || "<missing>".into(),
                |expr| match expr {
                    Expr::Path(path) if path.path.segments.len() == 1 => self
                        .modes
                        .get(&path.path.segments[0].ident.to_string())
                        .cloned()
                        .or_else(|| resolved_mode_name(expr))
                        .unwrap_or_else(|| "<unresolved-mode>".into()),
                    _ => resolved_mode_name(expr).unwrap_or_else(|| "<unresolved-mode>".into()),
                },
            );
            self.facts.direct_probe = true;
            self.facts.probe_modes.push(mode);
            self.event(Event::Probe);
        } else if last.as_deref() == Some("probe_or_spawn") {
            self.errors.push(format!(
                "unresolved or shadowed probe_or_spawn path: {resolved}"
            ));
        }
        if let Some(leaf) = last.as_deref() {
            if let Some(target) = self.known_call(&resolved, leaf) {
                self.facts.calls.push(target.clone());
                self.facts
                    .call_positions
                    .push((target, self.facts.events.len()));
            } else if path.path.segments.len() <= 2 {
                self.facts
                    .unresolved_calls
                    .push((leaf.into(), self.facts.events.len()));
            }
        }
        match last.as_deref() {
            Some("spawn_signal_shutdown") => self.event(Event::Signal),
            Some("aggregate_shutdown_result") | Some("finish_owned_run") => {
                self.event(Event::Aggregate)
            }
            Some("drop") if matches!(call.args.first(), Some(Expr::Path(path)) if path.path.is_ident("guard")) => {
                self.event(Event::DropGuard)
            }
            Some("exit") if resolved.ends_with("process::exit") => self.event(Event::ProcessExit),
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for FunctionVisitor<'_> {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let syn::Pat::Ident(binding) = &local.pat
            && let Some(init) = &local.init
        {
            if let Some(mode) = resolved_mode_name(&init.expr) {
                self.modes.insert(binding.ident.to_string(), mode);
            }
            if let Expr::Path(path) = init.expr.as_ref() {
                let resolved = resolve_path(&path.path, self.module, self.imports);
                let leaf = path
                    .path
                    .segments
                    .last()
                    .map(|segment| segment.ident.to_string())
                    .unwrap_or_default();
                if resolved.ends_with(PROBE_SUFFIX) {
                    self.errors.push(format!("dynamic lifecycle function item requires audited exact consumers: {resolved}"));
                } else if let Some(target) = self.known_call(&resolved, &leaf) {
                    self.facts.dynamic_items.push(target);
                }
            }
        }
        visit::visit_local(self, local);
    }
    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        match call.func.as_ref() {
            Expr::Path(path) => self.path_call(call, path),
            Expr::Paren(paren) if matches!(paren.expr.as_ref(), Expr::Path(_)) => self
                .errors
                .push("parenthesized lifecycle function item is not auditable".into()),
            _ => {}
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "take_owned_daemon_guard" {
            self.event(Event::Guard);
        } else if let Some(target) = self.known_call("", &call.method.to_string()) {
            self.facts.calls.push(target.clone());
            self.facts
                .call_positions
                .push((target, self.facts.events.len()));
        } else {
            self.facts
                .unresolved_calls
                .push((call.method.to_string(), self.facts.events.len()));
        }
        visit::visit_expr_method_call(self, call);
    }
    fn visit_expr_match(&mut self, expression: &'ast ExprMatch) {
        if let Expr::Tuple(tuple) = expression.expr.as_ref()
            && tuple.elems.len() == 2
            && matches!(&tuple.elems[0], Expr::Path(path) if path.path.is_ident("response"))
            && matches!(&tuple.elems[1], Expr::Path(path) if path.path.is_ident("shutdown"))
        {
            self.event(Event::Aggregate);
        }
        visit::visit_expr_match(self, expression);
    }
    fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
        visit::visit_expr_await(self, expression);
        self.event(Event::Await);
    }
    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        visit::visit_expr_try(self, expression);
        self.event(Event::Try);
    }
    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        visit::visit_expr_return(self, expression);
        self.event(Event::Return);
    }
    fn visit_macro(&mut self, invocation: &'ast syn::Macro) {
        let tokens = invocation.tokens.to_string();
        if tokens.contains("probe_or_spawn")
            || self.imports.iter().any(|(alias, canonical)| {
                canonical.ends_with(PROBE_SUFFIX)
                    && tokens.split_whitespace().any(|token| token == alias)
            })
        {
            self.errors
                .push("macro-wrapped lifecycle authority requires audited exact consumers".into());
        }
        visit::visit_macro(self, invocation);
    }
}

fn analyze_sources(sources: BTreeMap<String, String>) -> Analysis {
    let mut analysis = Analysis::default();
    let mut units = Vec::new();
    for (relative, source) in sources {
        let parsed = match syn::parse_file(&source) {
            Ok(file) => file,
            Err(error) => {
                analysis.errors.push(format!("parsing {relative}: {error}"));
                continue;
            }
        };
        let mut imports = BTreeMap::new();
        for item in &parsed.items {
            if let syn::Item::Use(item) = item {
                flatten_use(
                    &item.tree,
                    &mut Vec::new(),
                    !matches!(item.vis, syn::Visibility::Inherited),
                    &mut imports,
                    &mut analysis.errors,
                );
            }
        }
        units.push(SourceUnit {
            module: module_for(&relative),
            parsed,
            imports,
        });
    }
    let mut known = BTreeSet::new();
    for unit in &units {
        collect_function_names(&unit.module, &unit.parsed.items, &mut known);
    }
    for unit in units {
        analyze_items(
            &unit.module,
            &unit.imports,
            &known,
            unit.parsed.items,
            &mut analysis,
        );
    }
    close_factory_graph(&mut analysis);
    analysis.probes.sort();
    analysis
}

fn collect_function_names(module: &str, items: &[syn::Item], known: &mut BTreeSet<String>) {
    for item in items {
        match item {
            syn::Item::Fn(function) => {
                known.insert(format!("{module}::{}", function.sig.ident));
            }
            syn::Item::Impl(implementation) => {
                let owner = impl_owner(&implementation.self_ty);
                for item in &implementation.items {
                    if let syn::ImplItem::Fn(method) = item {
                        known.insert(format!("{module}::{owner}::{}", method.sig.ident));
                    }
                }
            }
            syn::Item::Mod(item) => {
                if let Some((_, items)) = &item.content {
                    collect_function_names(&format!("{module}::{}", item.ident), items, known);
                }
            }
            _ => {}
        }
    }
}

fn analyze_items(
    module: &str,
    imports: &BTreeMap<String, String>,
    known: &BTreeSet<String>,
    items: Vec<syn::Item>,
    analysis: &mut Analysis,
) {
    for item in items {
        match item {
            syn::Item::Fn(function) => analyze_function(
                module,
                imports,
                known,
                function.sig.ident.to_string(),
                &function.sig.output,
                &function.block,
                analysis,
            ),
            syn::Item::Impl(implementation) => {
                let owner = impl_owner(&implementation.self_ty);
                for item in implementation.items {
                    if let syn::ImplItem::Fn(method) = item {
                        analyze_function(
                            module,
                            imports,
                            known,
                            format!("{owner}::{}", method.sig.ident),
                            &method.sig.output,
                            &method.block,
                            analysis,
                        );
                    }
                }
            }
            syn::Item::Macro(item) if item.mac.tokens.to_string().contains("probe_or_spawn") => {
                analysis.errors.push(
                    "macro definition wraps probe_or_spawn without audited exact consumers".into(),
                )
            }
            syn::Item::Mod(item) => {
                if let Some((_, items)) = item.content {
                    let mut child_imports = imports.clone();
                    for child in &items {
                        if let syn::Item::Use(item) = child {
                            flatten_use(
                                &item.tree,
                                &mut Vec::new(),
                                !matches!(item.vis, syn::Visibility::Inherited),
                                &mut child_imports,
                                &mut analysis.errors,
                            );
                        }
                    }
                    analyze_items(
                        &format!("{module}::{}", item.ident),
                        &child_imports,
                        known,
                        items,
                        analysis,
                    );
                }
            }
            _ => {}
        }
    }
}

fn impl_owner(ty: &syn::Type) -> String {
    match ty {
        syn::Type::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_else(|| "<impl>".into()),
        _ => "<impl>".into(),
    }
}

fn analyze_function(
    module: &str,
    imports: &BTreeMap<String, String>,
    known: &BTreeSet<String>,
    name: String,
    output: &syn::ReturnType,
    block: &syn::Block,
    analysis: &mut Analysis,
) {
    let canonical = format!("{module}::{name}");
    let mut visitor = FunctionVisitor {
        module,
        imports,
        known,
        facts: FunctionFacts {
            returns_connected_daemon: returns_connected_daemon(output),
            ..FunctionFacts::default()
        },
        modes: BTreeMap::new(),
        errors: Vec::new(),
    };
    visitor.visit_block(block);
    analysis.probes.extend(
        visitor
            .facts
            .probe_modes
            .iter()
            .cloned()
            .map(|mode| ProbeSite {
                function: canonical.clone(),
                mode,
            }),
    );
    analysis.errors.extend(
        visitor
            .errors
            .into_iter()
            .map(|error| format!("{canonical}: {error}")),
    );
    analysis.functions.insert(canonical, visitor.facts);
}

fn close_factory_graph(analysis: &mut Analysis) {
    let mut factories = analysis
        .functions
        .iter()
        .filter_map(|(name, facts)| {
            (facts.returns_connected_daemon && facts.direct_probe).then_some(name.clone())
        })
        .collect::<BTreeSet<_>>();
    loop {
        let before = factories.len();
        let mut resolved_call = false;
        for facts in analysis.functions.values_mut() {
            for (leaf, position) in facts.unresolved_calls.clone() {
                let candidates = factories
                    .iter()
                    .filter(|factory| factory.ends_with(&format!("::{leaf}")))
                    .cloned()
                    .collect::<Vec<_>>();
                if candidates.len() == 1 && !facts.calls.contains(&candidates[0]) {
                    facts.calls.push(candidates[0].clone());
                    facts.call_positions.push((candidates[0].clone(), position));
                    resolved_call = true;
                }
            }
        }
        for (name, facts) in &analysis.functions {
            if facts.returns_connected_daemon
                && facts.calls.iter().any(|called| factories.contains(called))
            {
                factories.insert(name.clone());
            }
        }
        if factories.len() == before && !resolved_call {
            break;
        }
    }
    for (name, facts) in &analysis.functions {
        for (leaf, _) in &facts.unresolved_calls {
            let candidates = factories
                .iter()
                .filter(|factory| factory.ends_with(&format!("::{leaf}")))
                .collect::<Vec<_>>();
            if candidates.len() > 1 {
                analysis.errors.push(format!(
                    "{name}: unresolved dynamic factory/method call `{leaf}` has non-exact consumers"
                ));
            }
        }
    }
    for (name, facts) in &analysis.functions {
        for target in &facts.dynamic_items {
            if factories.contains(target) {
                analysis.errors.push(format!("{name}: dynamic lifecycle function item requires audited exact consumers: {target}"));
            }
        }
    }
    for facts in analysis.functions.values_mut() {
        if let Some(origin) = facts
            .call_positions
            .iter()
            .filter_map(|(called, position)| factories.contains(called).then_some(*position))
            .min()
        {
            facts
                .events
                .insert(origin.min(facts.events.len()), Event::FactoryCall);
        }
    }
    for (name, facts) in &analysis.functions {
        let auto_promote = facts.direct_probe
            && !facts.probe_modes.is_empty()
            && facts
                .probe_modes
                .iter()
                .all(|mode| mode == "AttachOrAutoPromote");
        let consumer = facts.calls.iter().any(|called| factories.contains(called));
        let direct_owner = facts.direct_probe && !facts.returns_connected_daemon && !auto_promote;
        if (consumer || direct_owner)
            && let Err(error) = owner_flow_error(&facts.events)
        {
            analysis.errors.push(format!("{name}: {error}"));
        }
    }
}

fn owner_flow_error(events: &[Event]) -> Result<(), String> {
    let origin = events
        .iter()
        .position(|event| matches!(event, Event::Probe | Event::FactoryCall))
        .ok_or("missing lifecycle origin")?;
    let guard = events
        .iter()
        .position(|event| *event == Event::Guard)
        .ok_or("missing guard take")?;
    let signal = events
        .iter()
        .position(|event| *event == Event::Signal)
        .ok_or("missing signal arm")?;
    if events[origin + 1..guard]
        .iter()
        .any(|event| !matches!(event, Event::Await | Event::Try))
    {
        return Err(
            "work occurs between successful lifecycle resolution and guard transfer".into(),
        );
    }
    let first_risk = events
        .iter()
        .enumerate()
        .skip(guard + 1)
        .find(|(_, event)| {
            matches!(
                event,
                Event::Signal | Event::Await | Event::Try | Event::Return | Event::ProcessExit
            )
        })
        .map(|(index, _)| index)
        .ok_or("no signal/fallible event after guard")?;
    if first_risk != signal {
        return Err("signal arm is not first after guard transfer".into());
    }
    let aggregate = events
        .iter()
        .rposition(|event| *event == Event::Aggregate)
        .ok_or("missing cleanup aggregation")?;
    let drop_guard = events
        .iter()
        .rposition(|event| *event == Event::DropGuard)
        .ok_or("missing guard drop")?;
    for (index, event) in events.iter().enumerate() {
        if matches!(event, Event::ProcessExit | Event::Return)
            && index > guard
            && (index < aggregate || index < drop_guard)
        {
            return Err("exit/return before aggregation and guard drop".into());
        }
    }
    Ok(())
}

fn rust_sources(root: &Path, output: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(root).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_sources(&path, output);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            output.push(path);
        }
    }
}

fn production_sources() -> BTreeMap<String, String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = Vec::new();
    rust_sources(&root, &mut paths);
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let relative = path
                .strip_prefix(&root)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            (relative, std::fs::read_to_string(path).unwrap())
        })
        .collect()
}

#[test]
fn production_lifecycle_authority_graph_is_exact_and_closed() {
    let analysis = analyze_sources(production_sources());
    assert!(analysis.errors.is_empty(), "{}", analysis.errors.join("\n"));
    assert_eq!(
        analysis.probes,
        [
            ProbeSite {
                function: "crate::commands::doctor::run".into(),
                mode: "AttachOrEphemeral".into()
            },
            ProbeSite {
                function: "crate::commands::init::run".into(),
                mode: "AlwaysEphemeral|AttachOrEphemeral".into()
            },
            ProbeSite {
                function: "crate::commands::invocation::connect".into(),
                mode: "AttachOrEphemeral".into()
            },
            ProbeSite {
                function: "crate::commands::learn::run".into(),
                mode: "AlwaysEphemeral|AttachOrEphemeral".into()
            },
            ProbeSite {
                function: "crate::commands::run::run".into(),
                mode: "AlwaysEphemeral|AttachOrEphemeral".into()
            },
            ProbeSite {
                function: "crate::commands::schedule::client".into(),
                mode: "AttachOrAutoPromote".into()
            },
            ProbeSite {
                function: "crate::commands::session::answer_inner".into(),
                mode: "AttachOrEphemeral".into()
            },
        ]
    );
}

fn fixture(source: &str) -> Analysis {
    analyze_sources(BTreeMap::from([("fixture.rs".into(), source.into())]))
}

#[test]
fn adversarial_alias_is_resolved_to_probe() {
    let analysis = fixture(
        "use crate::daemon::client::probe_or_spawn as launch; async fn run() { let _ = launch(LifecycleMode::AttachOrEphemeral).await; }",
    );
    assert_eq!(analysis.probes.len(), 1);
}

#[test]
fn adversarial_reexport_and_function_item_are_rejected() {
    assert!(
        !fixture("pub use crate::daemon::client::probe_or_spawn as launch;")
            .errors
            .is_empty()
    );
    let pointer = fixture(
        "use crate::daemon::client::probe_or_spawn; async fn run() { let launch = probe_or_spawn; let _ = launch(LifecycleMode::AttachOrEphemeral).await; }",
    );
    assert!(
        pointer
            .errors
            .iter()
            .any(|error| error.contains("function item"))
    );
}

#[test]
fn adversarial_wrapper_chain_and_second_factory_find_unowned_consumer() {
    let analysis = fixture(
        "use crate::daemon::client::probe_or_spawn; async fn first() -> Result<ConnectedDaemon> { probe_or_spawn(LifecycleMode::AttachOrEphemeral).await } async fn second() -> Result<Option<ConnectedDaemon>> { Ok(Some(first().await?)) } async fn unowned() { let _daemon = second().await; }",
    );
    assert!(
        analysis
            .errors
            .iter()
            .any(|error| error.contains("unowned"))
    );
}

#[test]
fn adversarial_macro_and_qself_wrappers_are_rejected() {
    let wrapped = fixture(
        "use crate::daemon::client::probe_or_spawn; macro_rules! launch { ($mode:expr) => { probe_or_spawn($mode) } }",
    );
    assert!(wrapped.errors.iter().any(|error| error.contains("macro")));
    let qself = fixture(
        "async fn run() { let _ = <Factory as Spawn>::probe_or_spawn(LifecycleMode::AttachOrEphemeral).await; }",
    );
    assert!(qself.errors.iter().any(|error| error.contains("QSelf")));
}
