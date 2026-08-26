use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprMatch, ExprMethodCall, ItemFn};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ProbeSite {
    file: String,
    function: String,
    mode: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LifecycleEvent {
    Probe,
    Guard,
    Signal,
    Await,
    Try,
    Aggregate,
    DropGuard,
    ProcessExit,
    FactoryConnect,
    Return,
}

#[derive(Default)]
struct InventoryVisitor {
    current_function: Option<String>,
    mode_bindings: BTreeMap<String, String>,
    probes: Vec<(String, String)>,
    events: BTreeMap<String, Vec<LifecycleEvent>>,
}

impl InventoryVisitor {
    fn event(&mut self, event: LifecycleEvent) {
        if let Some(function) = &self.current_function {
            self.events.entry(function.clone()).or_default().push(event);
        }
    }
}

impl<'ast> Visit<'ast> for InventoryVisitor {
    fn visit_item_fn(&mut self, function: &'ast ItemFn) {
        let previous = self
            .current_function
            .replace(function.sig.ident.to_string());
        let previous_bindings = std::mem::take(&mut self.mode_bindings);
        visit::visit_item_fn(self, function);
        self.mode_bindings = previous_bindings;
        self.current_function = previous;
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let syn::Pat::Ident(binding) = &local.pat
            && let Some(initializer) = &local.init
            && let Some(mode) = resolved_mode_name(&initializer.expr)
        {
            self.mode_bindings.insert(binding.ident.to_string(), mode);
        }
        visit::visit_local(self, local);
    }

    fn visit_expr_call(&mut self, call: &'ast ExprCall) {
        if let Expr::Path(path) = call.func.as_ref()
            && let Some(name) = path
                .path
                .segments
                .last()
                .map(|segment| segment.ident.to_string())
        {
            match name.as_str() {
                "probe_or_spawn" => {
                    let mode = call.args.first().map_or_else(
                        || "<missing>".into(),
                        |expression| match expression {
                            Expr::Path(path) if path.path.segments.len() == 1 => self
                                .mode_bindings
                                .get(&path.path.segments[0].ident.to_string())
                                .cloned()
                                .unwrap_or_else(|| mode_name(expression)),
                            _ => mode_name(expression),
                        },
                    );
                    self.probes.push((
                        self.current_function
                            .clone()
                            .unwrap_or_else(|| "<module>".into()),
                        mode,
                    ));
                    self.event(LifecycleEvent::Probe);
                }
                "spawn_signal_shutdown" => self.event(LifecycleEvent::Signal),
                "aggregate_shutdown_result" | "finish_owned_run" => {
                    self.event(LifecycleEvent::Aggregate);
                }
                "drop" if matches!(call.args.first(), Some(Expr::Path(path)) if path.path.is_ident("guard")) =>
                {
                    self.event(LifecycleEvent::DropGuard);
                }
                "exit"
                    if path
                        .path
                        .segments
                        .iter()
                        .any(|segment| segment.ident == "process") =>
                {
                    self.event(LifecycleEvent::ProcessExit);
                }
                "connect" => self.event(LifecycleEvent::FactoryConnect),
                _ => {}
            }
        }
        visit::visit_expr_call(self, call);
    }

    fn visit_expr_method_call(&mut self, call: &'ast ExprMethodCall) {
        if call.method == "take_owned_daemon_guard" {
            self.event(LifecycleEvent::Guard);
        }
        visit::visit_expr_method_call(self, call);
    }

    fn visit_expr_match(&mut self, expression: &'ast ExprMatch) {
        if let Expr::Tuple(tuple) = expression.expr.as_ref()
            && tuple.elems.len() == 2
            && matches!(&tuple.elems[0], Expr::Path(path) if path.path.is_ident("response"))
            && matches!(&tuple.elems[1], Expr::Path(path) if path.path.is_ident("shutdown"))
        {
            self.event(LifecycleEvent::Aggregate);
        }
        visit::visit_expr_match(self, expression);
    }

    fn visit_expr_await(&mut self, expression: &'ast syn::ExprAwait) {
        visit::visit_expr_await(self, expression);
        self.event(LifecycleEvent::Await);
    }

    fn visit_expr_try(&mut self, expression: &'ast syn::ExprTry) {
        visit::visit_expr_try(self, expression);
        self.event(LifecycleEvent::Try);
    }

    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        visit::visit_expr_return(self, expression);
        self.event(LifecycleEvent::Return);
    }
}

fn mode_name(expression: &Expr) -> String {
    match expression {
        Expr::Path(path) => path
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string())
            .unwrap_or_else(|| "<empty>".into()),
        _ => "<expression>".into(),
    }
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
            if let Some(then_mode) = branch.then_branch.stmts.last().and_then(|statement| {
                let syn::Stmt::Expr(expression, _) = statement else {
                    return None;
                };
                resolved_mode_name(expression)
            }) {
                variants.push(then_mode);
            }
            if let Some((_, otherwise)) = &branch.else_branch
                && let Some(other_mode) = resolved_mode_name(otherwise)
            {
                variants.push(other_mode);
            }
            variants.sort();
            variants.dedup();
            (!variants.is_empty()).then(|| variants.join("|"))
        }
        Expr::Block(block) => block.block.stmts.last().and_then(|statement| {
            let syn::Stmt::Expr(expression, _) = statement else {
                return None;
            };
            resolved_mode_name(expression)
        }),
        _ => None,
    }
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

fn inventory() -> (
    Vec<ProbeSite>,
    BTreeMap<(String, String), Vec<LifecycleEvent>>,
) {
    let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut sources = Vec::new();
    rust_sources(&source_root, &mut sources);
    sources.sort();
    let mut probes = Vec::new();
    let mut functions = BTreeMap::new();
    for path in sources {
        let relative = path
            .strip_prefix(&source_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        let parsed = syn::parse_file(&std::fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()));
        let mut visitor = InventoryVisitor::default();
        visitor.visit_file(&parsed);
        probes.extend(
            visitor
                .probes
                .into_iter()
                .map(|(function, mode)| ProbeSite {
                    file: relative.clone(),
                    function,
                    mode,
                }),
        );
        functions.extend(
            visitor
                .events
                .into_iter()
                .map(|(function, events)| ((relative.clone(), function), events)),
        );
    }
    probes.sort();
    (probes, functions)
}

fn type_contains_ident(ty: &syn::Type, expected: &str) -> bool {
    let syn::Type::Path(path) = ty else {
        return false;
    };
    path.path.segments.iter().any(|segment| {
        segment.ident == expected
            || match &segment.arguments {
                syn::PathArguments::AngleBracketed(arguments) => {
                    arguments.args.iter().any(|argument| {
                        matches!(argument, syn::GenericArgument::Type(ty) if type_contains_ident(ty, expected))
                    })
                }
                _ => false,
            }
    })
}

fn function_returns_connected_daemon(relative: &str, function: &str) -> bool {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(relative);
    let parsed = syn::parse_file(&std::fs::read_to_string(path).unwrap()).unwrap();
    parsed.items.iter().any(|item| {
        let syn::Item::Fn(item) = item else {
            return false;
        };
        item.sig.ident == function
            && matches!(&item.sig.output, syn::ReturnType::Type(_, ty) if type_contains_ident(ty, "ConnectedDaemon"))
    })
}

fn assert_owner_flow(events: &[LifecycleEvent], label: &str) {
    let guard = events
        .iter()
        .position(|event| *event == LifecycleEvent::Guard)
        .unwrap_or_else(|| panic!("{label}: missing guard take"));
    let signal = events
        .iter()
        .position(|event| *event == LifecycleEvent::Signal)
        .unwrap_or_else(|| panic!("{label}: missing signal registration"));
    if let Some(probe) = events
        .iter()
        .position(|event| *event == LifecycleEvent::Probe)
    {
        assert!(
            events[probe + 1..guard]
                .iter()
                .all(|event| matches!(event, LifecycleEvent::Await | LifecycleEvent::Try)),
            "{label}: successful probe performs work before transferring ownership"
        );
    }
    if let Some(connect) = events
        .iter()
        .position(|event| *event == LifecycleEvent::FactoryConnect)
    {
        assert!(connect < guard, "{label}: factory result is not guarded");
        assert!(
            events[connect + 1..guard]
                .iter()
                .all(|event| matches!(event, LifecycleEvent::Await | LifecycleEvent::Try)),
            "{label}: successful factory connection performs work before ownership transfer"
        );
    }
    let first_risk_after_guard = events
        .iter()
        .enumerate()
        .skip(guard + 1)
        .find(|(_, event)| {
            matches!(
                event,
                LifecycleEvent::Signal
                    | LifecycleEvent::Await
                    | LifecycleEvent::Try
                    | LifecycleEvent::Return
                    | LifecycleEvent::ProcessExit
            )
        })
        .map(|(index, _)| index)
        .unwrap();
    assert_eq!(
        first_risk_after_guard, signal,
        "{label}: signal handler is not the first fallible/awaited action after guard take"
    );
    let aggregate = events
        .iter()
        .rposition(|event| *event == LifecycleEvent::Aggregate)
        .unwrap_or_else(|| panic!("{label}: missing cleanup result aggregation"));
    let drop_guard = events
        .iter()
        .rposition(|event| *event == LifecycleEvent::DropGuard)
        .unwrap_or_else(|| panic!("{label}: missing explicit guard drop"));
    assert!(
        signal < aggregate,
        "{label}: cleanup aggregated before signal path was armed"
    );
    assert!(drop_guard < events.len(), "{label}: guard drop missing");
    for exit in events
        .iter()
        .enumerate()
        .filter_map(|(index, event)| (*event == LifecycleEvent::ProcessExit).then_some(index))
    {
        assert!(
            drop_guard < exit && aggregate < exit,
            "{label}: process::exit occurs before guard drop/cleanup aggregation"
        );
    }
    for returned in events.iter().enumerate().filter_map(|(index, event)| {
        (*event == LifecycleEvent::Return && index > guard).then_some(index)
    }) {
        assert!(
            drop_guard < returned && aggregate < returned,
            "{label}: explicit return occurs before guard drop/cleanup aggregation"
        );
    }
}

#[test]
fn production_ephemeral_lifecycle_inventory_is_exact_and_guarded() {
    let (probes, functions) = inventory();
    let expected = vec![
        ProbeSite {
            file: "commands/doctor.rs".into(),
            function: "run".into(),
            mode: "AttachOrEphemeral".into(),
        },
        ProbeSite {
            file: "commands/init.rs".into(),
            function: "run".into(),
            mode: "AlwaysEphemeral|AttachOrEphemeral".into(),
        },
        ProbeSite {
            file: "commands/invocation.rs".into(),
            function: "connect".into(),
            mode: "AttachOrEphemeral".into(),
        },
        ProbeSite {
            file: "commands/learn.rs".into(),
            function: "run".into(),
            mode: "AlwaysEphemeral|AttachOrEphemeral".into(),
        },
        ProbeSite {
            file: "commands/run.rs".into(),
            function: "run".into(),
            mode: "AlwaysEphemeral|AttachOrEphemeral".into(),
        },
        ProbeSite {
            file: "commands/schedule.rs".into(),
            function: "client".into(),
            mode: "AttachOrAutoPromote".into(),
        },
        ProbeSite {
            file: "commands/session.rs".into(),
            function: "answer_inner".into(),
            mode: "AttachOrEphemeral".into(),
        },
    ];
    assert_eq!(
        probes, expected,
        "every new probe_or_spawn call must be classified here"
    );

    for (file, function) in [
        ("commands/doctor.rs", "run"),
        ("commands/init.rs", "run"),
        ("commands/learn.rs", "run"),
        ("commands/run.rs", "run"),
        ("commands/session.rs", "answer_inner"),
        ("commands/invocation.rs", "status"),
        ("commands/invocation.rs", "cancel"),
    ] {
        let events = functions.get(&(file.into(), function.into())).unwrap();
        assert_owner_flow(events, &format!("{file}::{function}"));
    }

    // Schedule auto-promotes before returning its client and therefore never
    // exposes ephemeral ownership to its command callers. Invocation's
    // `connect` factory deliberately returns the full ConnectedDaemon; both
    // consumers above are independently inventoried as owner paths.
    assert!(function_returns_connected_daemon(
        "commands/invocation.rs",
        "connect"
    ));
    let invocation_consumers = functions
        .iter()
        .filter_map(|((file, function), events)| {
            (file == "commands/invocation.rs" && events.contains(&LifecycleEvent::FactoryConnect))
                .then_some(function.as_str())
        })
        .collect::<Vec<_>>();
    assert_eq!(invocation_consumers, ["cancel", "status"]);
    assert_eq!(probes.len(), 7);
}
