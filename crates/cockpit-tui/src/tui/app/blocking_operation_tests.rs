use super::blocking_operations::BlockingOperationKind;
use super::*;

struct BarrierRelease(Option<std::sync::Arc<blocking_operations::OwnedTestGate>>);

impl BarrierRelease {
    fn release(mut self) {
        self.0.take().unwrap().release();
    }
}

impl Drop for BarrierRelease {
    fn drop(&mut self) {
        if let Some(barrier) = self.0.take() {
            barrier.release();
        }
    }
}

fn activate_composer(app: &mut App) {
    app.dialog = crate::tui::settings::Dialog::None;
    app.overlay = Overlay::None;
    app.question_dialog = None;
    app.composer.set_vim_enabled(false);
}

#[test]
fn blocking_operation_manifest_is_complete() {
    use super::blocking_operations::BLOCKING_OPERATION_MANIFEST;

    let app = App::new(None, false);
    for registration in BLOCKING_OPERATION_MANIFEST {
        assert_eq!((registration.binding)(&app), registration.kind);
    }

    let mut sites = std::collections::HashSet::new();
    let mut kinds = std::collections::HashSet::new();
    let mut actions = std::collections::HashSet::new();
    let mut wrappers = std::collections::HashSet::new();
    for registration in BLOCKING_OPERATION_MANIFEST {
        assert!(
            sites.insert(registration.site),
            "duplicate blocking-operation site: {:?}",
            registration.site,
        );
        assert!(
            kinds.insert(registration.kind),
            "duplicate blocking-operation kind: {:?}",
            registration.kind,
        );
        assert!(!registration.actions.is_empty());
        assert!(wrappers.insert(registration.wrapper), "duplicate wrapper");
        for action in registration.actions {
            assert!(actions.insert(*action), "duplicate action: {action}");
            let index = registration
                .actions
                .iter()
                .position(|it| it == action)
                .unwrap();
            assert_eq!(registration.kind.action_name_at(index), *action);
        }
        let (source, handler) = derive_wrapper_handler(registration.wrapper)
            .unwrap_or_else(|error| panic!("{:?}: {error}", registration.site));
        validate_handler_source(source, &handler, registration.wrapper)
            .unwrap_or_else(|error| panic!("{:?}: {error}", registration.site));
        validate_site_reachability(registration.site, &handler)
            .unwrap_or_else(|error| panic!("{:?}: {error}", registration.site));
    }
    let declared = derive_production_sites().unwrap();
    assert_eq!(
        sites, declared,
        "manifest must cover every sealed site exactly once"
    );
}

const PRODUCTION_ROUTING_SOURCES: &[&str] = &[
    include_str!("slash.rs"),
    include_str!("input.rs"),
    include_str!("queue_controls.rs"),
    include_str!("export_actions.rs"),
    include_str!("btw_pane.rs"),
];

fn derive_wrapper_handler(wrapper: &str) -> Result<(&'static str, String), String> {
    const MAX_SOURCES: usize = 8;
    const MAX_FUNCTIONS_PER_SOURCE: usize = 2_000;
    if PRODUCTION_ROUTING_SOURCES.len() > MAX_SOURCES {
        return Err("production routing source budget exceeded".to_string());
    }
    let mut found = Vec::new();
    for source in PRODUCTION_ROUTING_SOURCES {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|e| e.to_string())?;
        let tree = parser
            .parse(source, None)
            .ok_or("Rust parser returned no tree")?;
        let mut functions = Vec::new();
        collect_all_functions(tree.root_node(), &mut functions);
        if functions.len() > MAX_FUNCTIONS_PER_SOURCE {
            return Err(format!("function budget exceeded: {}", functions.len()));
        }
        for function in functions {
            let Some(name) = function
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            else {
                continue;
            };
            let Some(body) = function.child_by_field_name("body") else {
                continue;
            };
            let mut calls = 0;
            if inspect_handler_calls_bounded(body, source.as_bytes(), wrapper, &mut calls).is_ok()
                && calls == 1
            {
                found.push((*source, name.to_string()));
            }
        }
    }
    if found.len() != 1 {
        return Err(format!(
            "wrapper `{wrapper}` has {} production handlers",
            found.len()
        ));
    }
    Ok(found.pop().unwrap())
}

fn collect_all_functions<'tree>(
    node: tree_sitter::Node<'tree>,
    found: &mut Vec<tree_sitter::Node<'tree>>,
) {
    if node.kind() == "function_item" {
        found.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_all_functions(child, found);
    }
}

fn validate_site_reachability(site: &str, handler: &str) -> Result<(), String> {
    let slash = include_str!("slash.rs");
    let input = include_str!("input.rs");
    let graph = production_call_graph()?;
    let reachable = match site {
        "slash:curator" => slash_route(slash, "curator", &graph, handler)?,
        "slash:doctor" => slash_route(slash, "doctor", &graph, handler)?,
        "slash:export" => slash_route(slash, "export", &graph, handler)?,
        "slash:btw" => slash_route(slash, "btw", &graph, handler)?,
        "queue:focus-up-edit" => {
            let queue = include_str!("queue_controls.rs");
            match_arm_calls(queue, "KeyCode::Up", "self.queue_action_edit")?
                && function_invokes_parameter(
                    queue,
                    "queue_action_edit",
                    "self.edit_queued_messages",
                )?
                && graph_reaches(&graph, "queue_action_edit", handler)?
        }
        "composer:char-reset-at" => {
            match_arm_calls(input, "KeyCode::Char(ch)", "self.reset_at_window")?
                && graph_reaches(&graph, "reset_at_window", handler)?
        }
        _ => false,
    };
    reachable.then_some(()).ok_or_else(|| {
        format!("handler `{handler}` is unreachable from its production registration")
    })
}

fn derive_production_sites() -> Result<std::collections::HashSet<&'static str>, String> {
    let slash = include_str!("slash.rs");
    let mut sites = std::collections::HashSet::new();
    for (command, site) in [
        ("curator", "slash:curator"),
        ("doctor", "slash:doctor"),
        ("export", "slash:export"),
        ("btw", "slash:btw"),
    ] {
        slash_registry_run(slash, command)?;
        sites.insert(site);
    }
    let queue = include_str!("queue_controls.rs");
    if match_arm_calls(queue, "KeyCode::Up", "self.queue_action_edit")? {
        sites.insert("queue:focus-up-edit");
    }
    let input = include_str!("input.rs");
    if match_arm_calls(input, "KeyCode::Char(ch)", "self.reset_at_window")? {
        sites.insert("composer:char-reset-at");
    }
    Ok(sites)
}

fn production_call_graph()
-> Result<std::collections::HashMap<String, std::collections::HashSet<String>>, String> {
    let mut graph = std::collections::HashMap::new();
    let mut owners = std::collections::HashMap::<String, usize>::new();
    let mut ambiguous = std::collections::HashSet::new();
    for (source_id, source) in PRODUCTION_ROUTING_SOURCES.iter().enumerate() {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .map_err(|e| e.to_string())?;
        let tree = parser
            .parse(source, None)
            .ok_or("Rust parser returned no tree")?;
        let mut functions = Vec::new();
        collect_all_functions(tree.root_node(), &mut functions);
        for function in functions {
            let Some(name) = function
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            else {
                continue;
            };
            let mut calls = std::collections::HashSet::new();
            collect_direct_call_names(
                function.child_by_field_name("body").unwrap_or(function),
                source.as_bytes(),
                &mut calls,
            );
            let name = name.to_string();
            if owners.get(&name).is_some_and(|owner| *owner != source_id) {
                ambiguous.insert(name.clone());
                graph.remove(&name);
                continue;
            }
            owners.insert(name.clone(), source_id);
            if !ambiguous.contains(&name) {
                graph
                    .entry(name)
                    .or_insert_with(std::collections::HashSet::new)
                    .extend(calls);
            }
        }
    }
    Ok(graph)
}

fn collect_direct_call_names(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    calls: &mut std::collections::HashSet<String>,
) {
    if matches!(node.kind(), "closure_expression" | "function_item") {
        return;
    }
    if node.kind() == "call_expression"
        && let Some(function) = node.child_by_field_name("function")
        && let Ok(text) = function.utf8_text(source)
    {
        calls.insert(text.rsplit('.').next().unwrap_or(text).to_string());
        if let Some(arguments) = node.child_by_field_name("arguments") {
            collect_self_function_items(arguments, source, calls);
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_direct_call_names(child, source, calls);
    }
}

fn collect_self_function_items(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    calls: &mut std::collections::HashSet<String>,
) {
    if node.kind() == "scoped_identifier"
        && let Ok(text) = node.utf8_text(source)
        && let Some(callback) = text.strip_prefix("Self::")
    {
        calls.insert(callback.to_string());
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_self_function_items(child, source, calls);
    }
}

fn function_invokes_parameter(
    source: &str,
    function: &str,
    parameter: &str,
) -> Result<bool, String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| e.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("Rust parser returned no tree")?;
    let mut functions = Vec::new();
    collect_named_functions(
        tree.root_node(),
        source.as_bytes(),
        function,
        &mut functions,
    );
    if functions.len() != 1 {
        return Err(format!(
            "expected one `{function}`, found {}",
            functions.len()
        ));
    }
    let body = functions[0]
        .child_by_field_name("body")
        .ok_or("callback receiver has no body")?;
    let mut invoked = false;
    scan_exact_call(body, source.as_bytes(), parameter, &mut invoked);
    Ok(invoked)
}

fn graph_reaches(
    graph: &std::collections::HashMap<String, std::collections::HashSet<String>>,
    root: &str,
    target: &str,
) -> Result<bool, String> {
    let mut pending = vec![root.to_string()];
    let mut visited = std::collections::HashSet::new();
    while let Some(node) = pending.pop() {
        if !visited.insert(node.clone()) {
            continue;
        }
        if visited.len() > 512 {
            return Err("route call-graph budget exceeded".to_string());
        }
        if node == target {
            return Ok(true);
        }
        if let Some(next) = graph.get(&node) {
            pending.extend(next.iter().cloned());
        }
    }
    Ok(false)
}

fn slash_route(
    source: &str,
    command: &str,
    graph: &std::collections::HashMap<String, std::collections::HashSet<String>>,
    target: &str,
) -> Result<bool, String> {
    let run = slash_registry_run(source, command)?;
    graph_reaches(graph, &run, target)
}

fn slash_registry_run(source: &str, command: &str) -> Result<String, String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| e.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("Rust parser returned no tree")?;
    let mut found = Vec::new();
    find_registry_entries(tree.root_node(), source.as_bytes(), command, &mut found);
    if found.len() != 1 {
        return Err(format!(
            "slash `{command}` has {} registry entries",
            found.len()
        ));
    }
    Ok(found.pop().unwrap())
}

fn find_registry_entries(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    command: &str,
    found: &mut Vec<String>,
) {
    if node.kind() == "struct_expression" {
        let mut name = None;
        let mut run = None;
        let mut initializers = Vec::new();
        collect_struct_initializers(node, &mut initializers);
        for child in initializers {
            let mut child_cursor = child.walk();
            let mut fields = child.named_children(&mut child_cursor);
            let key = fields.next().and_then(|n| n.utf8_text(source).ok());
            let value = fields.next().and_then(|n| n.utf8_text(source).ok());
            match key {
                Some("name") => name = value,
                Some("run") => run = value,
                _ => {}
            }
        }
        let expected = format!("\"{command}\"");
        if name == Some(expected.as_str())
            && let Some(run) = run
        {
            found.push(run.to_string());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_registry_entries(child, source, command, found);
    }
}

fn collect_struct_initializers<'tree>(
    node: tree_sitter::Node<'tree>,
    found: &mut Vec<tree_sitter::Node<'tree>>,
) {
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        if child.kind() == "field_initializer" {
            found.push(child);
        } else if child.kind() != "struct_expression" {
            collect_struct_initializers(child, found);
        }
    }
}

fn match_arm_calls(source: &str, pattern: &str, call: &str) -> Result<bool, String> {
    match_arm_query(source, Some(pattern), call)
}
fn match_arm_query(source: &str, pattern: Option<&str>, call: &str) -> Result<bool, String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|e| e.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("Rust parser returned no tree")?;
    let mut matched = false;
    find_match_arm(
        tree.root_node(),
        source.as_bytes(),
        pattern,
        call,
        &mut matched,
    );
    Ok(matched)
}
fn find_match_arm(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    pattern: Option<&str>,
    call: &str,
    matched: &mut bool,
) {
    if node.kind() == "match_arm" {
        let mut has_pattern = pattern.is_none()
            || node
                .child_by_field_name("pattern")
                .and_then(|pattern_node| pattern_node.named_child(0))
                .and_then(|pattern_node| pattern_node.utf8_text(source).ok())
                == pattern;
        let mut has_call = false;
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            if child.utf8_text(source).ok() == pattern {
                has_pattern = true;
            }
            scan_exact_call(child, source, call, &mut has_call);
        }
        *matched |= has_pattern && has_call;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_match_arm(child, source, pattern, call, matched);
    }
}
fn scan_exact_call(node: tree_sitter::Node<'_>, source: &[u8], call: &str, found: &mut bool) {
    if node.kind() == "call_expression"
        && node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(source).ok())
            == Some(call)
    {
        *found = true;
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        scan_exact_call(child, source, call, found);
    }
}

fn validate_handler_source(source: &str, handler: &str, wrapper: &str) -> Result<(), String> {
    let calls = analyze_handler_source(source, handler, wrapper)?;
    if calls != 1 {
        return Err(format!(
            "`{handler}` must call `{wrapper}` exactly once, found {calls}"
        ));
    }
    Ok(())
}

fn analyze_handler_source(source: &str, handler: &str, wrapper: &str) -> Result<usize, String> {
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_rust::LANGUAGE.into())
        .map_err(|error| error.to_string())?;
    let tree = parser
        .parse(source, None)
        .ok_or("Rust parser returned no tree")?;
    let mut handlers = Vec::new();
    collect_named_functions(tree.root_node(), source.as_bytes(), handler, &mut handlers);
    if handlers.len() != 1 {
        return Err(format!(
            "expected one `{handler}` function, found {}",
            handlers.len()
        ));
    }
    let mut wrapper_calls = 0;
    let body = handlers[0]
        .child_by_field_name("body")
        .ok_or("handler has no executable body")?;
    inspect_handler_calls(body, source.as_bytes(), wrapper, &mut wrapper_calls)?;
    Ok(wrapper_calls)
}

fn collect_named_functions<'tree>(
    node: tree_sitter::Node<'tree>,
    source: &[u8],
    handler: &str,
    found: &mut Vec<tree_sitter::Node<'tree>>,
) {
    if node.kind() == "function_item"
        && node
            .child_by_field_name("name")
            .and_then(|name| name.utf8_text(source).ok())
            == Some(handler)
    {
        found.push(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_named_functions(child, source, handler, found);
    }
}

fn inspect_handler_calls(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    wrapper: &str,
    wrapper_calls: &mut usize,
) -> Result<(), String> {
    let mut remaining = 50_000usize;
    inspect_handler_calls_inner(node, source, wrapper, wrapper_calls, &mut remaining)
}

fn inspect_handler_calls_bounded(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    wrapper: &str,
    wrapper_calls: &mut usize,
) -> Result<(), String> {
    inspect_handler_calls(node, source, wrapper, wrapper_calls)
}

fn inspect_handler_calls_inner(
    node: tree_sitter::Node<'_>,
    source: &[u8],
    wrapper: &str,
    wrapper_calls: &mut usize,
    remaining: &mut usize,
) -> Result<(), String> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or_else(|| "handler AST node budget exceeded".to_string())?;
    if matches!(node.kind(), "closure_expression" | "function_item") {
        return Ok(());
    }
    if node.kind() == "call_expression"
        && let Some(function) = node.child_by_field_name("function")
    {
        let callable = function
            .utf8_text(source)
            .map_err(|error| error.to_string())?;
        if callable == format!("self.{wrapper}") {
            *wrapper_calls += 1;
        }
        const FORBIDDEN: &[&str] = &[
            "std::fs::read",
            "std::fs::write",
            "std::fs::remove_file",
            "std::thread::sleep",
            "daemon_request_blocking",
            "Command::new",
        ];
        if FORBIDDEN.iter().any(|blocked| callable.contains(blocked)) {
            return Err(format!("inline blocking call `{callable}`"));
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        inspect_handler_calls_inner(child, source, wrapper, wrapper_calls, remaining)?;
    }
    Ok(())
}

#[test]
fn handler_source_gate_rejects_bypasses() {
    assert!(validate_handler_source("fn h() {}", "h", "dispatch").is_err());
    assert!(
        validate_handler_source(
            "fn h(){ self.dispatch(); self.dispatch(); }",
            "h",
            "dispatch"
        )
        .is_err()
    );
    assert!(validate_handler_source("fn h(){ self.wrong(); }", "h", "dispatch").is_err());
    assert!(validate_handler_source("fn h(){ other.dispatch(); }", "h", "dispatch").is_err());
    assert!(
        validate_handler_source(
            "fn h(){ let fake = || self.dispatch(); drop(fake); }",
            "h",
            "dispatch"
        )
        .is_err()
    );
    assert!(
        validate_handler_source(
            "fn h(){ self.dispatch(); std::fs::read(\"x\"); }",
            "h",
            "dispatch"
        )
        .is_err()
    );
}

#[test]
fn reducers_and_async_loop_do_not_reenter_daemon_runtime_synchronously() {
    const RESPONSIVE_SOURCES: &[(&str, &str)] = &[
        ("app/mod.rs", include_str!("mod.rs")),
        ("app/input.rs", include_str!("input.rs")),
        ("app/resume.rs", include_str!("resume.rs")),
        (
            "app/attach_lifecycle.rs",
            include_str!("attach_lifecycle.rs"),
        ),
        ("app/model_controls.rs", include_str!("model_controls.rs")),
        ("app/local_commands.rs", include_str!("local_commands.rs")),
        ("app/btw_pane.rs", include_str!("btw_pane.rs")),
        ("app/overlay_actions.rs", include_str!("overlay_actions.rs")),
        ("tools_pane.rs", include_str!("../tools_pane.rs")),
        (
            "goal_settings_pane.rs",
            include_str!("../goal_settings_pane.rs"),
        ),
    ];
    const FORBIDDEN: &[&str] = &[
        "daemon_request_blocking",
        "daemon_request_blocking_classified",
        "attached_request_tx_blocking",
        "attached_request_blocking",
        "block_in_place",
        ".block_on(",
    ];
    for (name, source) in RESPONSIVE_SOURCES {
        for forbidden in FORBIDDEN {
            assert!(
                !source.contains(forbidden),
                "{name} must enqueue/await typed effects, not call `{forbidden}`"
            );
        }
    }

    // Worker-only blocking adapters are enforced structurally across every
    // production source file by `tests/tui_db_boundary.rs`; this reducer gate
    // deliberately owns only the synchronous event-loop spellings above.
}

#[test]
fn mcp_local_commands_are_correlated_async_effects() {
    let source = include_str!("local_commands.rs");
    for required in [
        "AsyncActionKind::DaemonRpc(\"mcp.local\")",
        "McpLocalCompletion",
        "pending_mcp_local",
        "snapshot_session_id",
        "client_operation_id",
        "commit status is unknown",
    ] {
        assert!(
            source.contains(required),
            "MCP local command lifecycle must retain `{required}`"
        );
    }
    for forbidden in [
        "daemon_request_blocking",
        "settings_daemon_request(",
        "block_in_place",
        ".block_on(",
    ] {
        assert!(
            !source.contains(forbidden),
            "MCP local command reducers must not use `{forbidden}`"
        );
    }
}

#[test]
fn every_production_block_on_is_test_only_or_worker_owned() {
    let runner = include_str!("../agent_runner.rs");
    assert_eq!(
        runner.matches(".block_on(").count(),
        5,
        "agent-runner blocking adapters require a fresh call-site audit"
    );
    assert!(runner.contains("may be called only from an\n/// `AsyncActionRunner::start_blocking`/`spawn_blocking` worker"));

    let settings = include_str!("../settings/mod.rs");
    assert_eq!(
        settings.matches(".block_on(").count(),
        0,
        "settings reducers must enqueue effects and never block on daemon work"
    );
    assert!(
        settings.contains("#[cfg(not(test))]\nstruct ProductionSettingsDaemonEffect;"),
        "the production settings daemon transport remains explicitly gated"
    );

    let image_spend = include_str!("../settings/image_spend.rs");
    assert_eq!(image_spend.matches("handle.block_on(").count(), 1);
    assert!(
        image_spend.contains("image spend persistence may run only on its dedicated OS worker")
    );
}

#[test]
fn sealed_site_catalog_detects_a_deleted_manifest_row() {
    use super::blocking_operations::BLOCKING_OPERATION_MANIFEST;
    let declared = derive_production_sites().unwrap();
    let missing_one = BLOCKING_OPERATION_MANIFEST[1..]
        .iter()
        .map(|registration| registration.site)
        .collect::<std::collections::HashSet<_>>();
    assert_ne!(declared, missing_one);
}

#[test]
fn production_route_gate_rejects_unreachable_and_unclassified_handlers() {
    assert!(validate_site_reachability("slash:curator", "bypass").is_err());
    assert!(derive_wrapper_handler("unclassified_owned_dispatch").is_err());
    assert!(
        slash_registry_run(
            "const NOTE: &str = \"name: \\\"curator\\\" run: run_curator\";",
            "curator"
        )
        .is_err()
    );
    let rerouted =
        r#"const COMMANDS: &[SlashCommand] = &[SlashCommand { name: "curator", run: run_wrong }];"#;
    let run = slash_registry_run(rerouted, "curator").unwrap();
    assert_eq!(run, "run_wrong");
    assert!(
        !graph_reaches(
            &std::collections::HashMap::new(),
            &run,
            "handle_curator_command"
        )
        .unwrap()
    );
    assert!(
        !function_invokes_parameter("fn receiver(cb: fn()){ wrong(); }", "receiver", "cb").unwrap()
    );
    let wrong_arm = "fn key(){ match code { KeyCode::Down => self.reset_at_window(), _ => {} } }";
    assert!(!match_arm_calls(wrong_arm, "KeyCode::Char(ch)", "self.reset_at_window").unwrap());
    assert!(
        graph_reaches(
            &std::collections::HashMap::new(),
            "reset_at_window",
            "reset_at_window"
        )
        .unwrap()
    );
}

#[test]
fn production_slash_registry_entries_are_structurally_derived() {
    let source = include_str!("slash.rs");
    assert_eq!(
        slash_registry_run(source, "curator").unwrap(),
        "run_curator"
    );
    assert_eq!(slash_registry_run(source, "doctor").unwrap(), "run_doctor");
    assert_eq!(slash_registry_run(source, "export").unwrap(), "run_export");
    assert_eq!(slash_registry_run(source, "btw").unwrap(), "run_btw");
}

#[tokio::test]
async fn no_owned_blocking_command_runs_on_event_loop() {
    let mut app = App::new(None, false);
    activate_composer(&mut app);
    app.startup_background.daemon_socket = Some(std::path::PathBuf::from("/nonexistent-test.sock"));
    app.launch.session_id = Some(uuid::Uuid::nil());
    app.launch.session_short_id = Some("test".to_string());
    let mut arrivals = Vec::new();
    let mut release_guards = Vec::new();
    for registration in blocking_operations::BLOCKING_OPERATION_MANIFEST {
        let (gate, arrived) = blocking_operations::OwnedTestGate::new();
        blocking_operations::install_owned_test_barrier(registration.kind, gate.clone());
        arrivals.push((registration.kind, arrived));
        release_guards.push(BarrierRelease(Some(gate)));
    }
    app.handle_curator_command("status");
    app.handle_doctor_command();
    app.handle_export_command("");
    app.handle_btw_command("end");
    app.composer.set("@src".to_string());
    app.reset_at_window();
    app.composer.clear();
    app.queue
        .push(input::optimistic_queue_item("queued".to_string()));
    app.queue_action_edit(None);

    let unclaimed = blocking_operations::unclaimed_owned_test_operations();
    assert!(
        unclaimed.is_empty(),
        "handlers did not claim registered work gates: {unclaimed:?}"
    );

    for (kind, arrived) in arrivals {
        arrived
            .await
            .unwrap_or_else(|_| panic!("{kind:?} never reached its registered work seam"));
        assert_eq!(app.async_actions.pending_kind_count(&kind.action_kind()), 1);
    }

    app.handle_terminal_event(crossterm::event::Event::Key(
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('x'),
            crossterm::event::KeyModifiers::NONE,
        ),
    ));
    app.handle_terminal_event(crossterm::event::Event::Mouse(
        crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Moved,
            column: 0,
            row: 0,
            modifiers: crossterm::event::KeyModifiers::NONE,
        },
    ));
    app.handle_terminal_event(crossterm::event::Event::Resize(100, 40));
    app.apply_event(cockpit_client::presentation::TurnEvent::Notice {
        text: "daemon reduced".to_string(),
    });

    assert_eq!(app.composer.text(), "x");
    assert!(matches!(
        app.history.last(),
        Some(HistoryEntry::Plain { line }) if line == "⚠ daemon reduced"
    ));
    let retained = [
        BlockingOperationKind::CuratorMaintenance,
        BlockingOperationKind::DoctorSnapshot,
        BlockingOperationKind::ExportWrite,
        BlockingOperationKind::QueueMutation,
        BlockingOperationKind::BtwTeardown,
    ];
    assert_eq!(app.async_actions.pending_count(), retained.len());
    for kind in retained {
        assert_eq!(app.async_actions.pending_kind_count(&kind.action_kind()), 1);
    }
    assert_eq!(
        app.async_actions
            .pending_kind_count(&BlockingOperationKind::FileAutocomplete.action_kind()),
        0
    );
    let cancelled = app.async_actions.drain_cancelled();
    assert_eq!(cancelled.len(), 1);
    assert_eq!(
        cancelled[0].kind,
        BlockingOperationKind::FileAutocomplete.action_kind()
    );
    assert!(matches!(
        &cancelled[0].payload,
        Err(error) if error == "operation cancelled"
    ));
    assert!(app.async_actions.drain_cancelled().is_empty());
    for guard in release_guards {
        guard.release();
    }
}

fn owned_barrier(
    kind: BlockingOperationKind,
) -> (BarrierRelease, tokio::sync::oneshot::Receiver<()>) {
    let (gate, arrived) = blocking_operations::OwnedTestGate::new();
    blocking_operations::install_owned_test_barrier(kind, gate.clone());
    (BarrierRelease(Some(gate)), arrived)
}

#[tokio::test]
async fn curator_command_is_async_with_pending_line() {
    let (barrier, arrived) = owned_barrier(BlockingOperationKind::CuratorMaintenance);
    let mut app = App::new(None, false);
    app.startup_background.daemon_socket = Some(std::path::PathBuf::from("/nonexistent-test.sock"));
    app.handle_curator_command("status");
    arrived.await.unwrap();
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line == "/curator: pending")
    );
    assert_eq!(app.async_actions.pending_count(), 1);
    barrier.release();
}

#[tokio::test]
async fn doctor_command_is_async() {
    let (barrier, arrived) = owned_barrier(BlockingOperationKind::DoctorSnapshot);
    let mut app = App::new(None, false);
    app.handle_doctor_command();
    arrived.await.unwrap();
    assert!(
        matches!(app.history.last(), Some(HistoryEntry::Plain { line }) if line == "/doctor: collecting diagnostics…")
    );
    assert_eq!(app.async_actions.pending_count(), 1);
    barrier.release();
}

#[test]
fn doctor_snapshot_is_point_in_time() {
    let mut app = App::new(None, false);
    app.launch.agent_name = "before".to_string();
    app.launch.active_model = Some(("provider-a".to_string(), "model-a".to_string()));
    let input = app.doctor_snapshot_input();

    app.launch.agent_name = "after".to_string();
    app.launch.active_model = Some(("provider-b".to_string(), "model-b".to_string()));

    assert_eq!(input.active_agent, "before");
    assert_eq!(
        input.active_model,
        Some(("provider-a".to_string(), "model-a".to_string()))
    );
}

#[tokio::test]
async fn cancelled_app_with_live_export_owner_reaps_before_drop_returns() {
    let tmp = tempfile::tempdir().unwrap();
    let partial = tmp.path().join(".cancelled-app.partial");
    let worker_partial = partial.clone();
    let (owned_tx, owned_rx) = tokio::sync::oneshot::channel();
    let mut app = App::new(None, false);
    app.async_actions.start_export(
        AsyncActionKind::Blocking("export.transcript"),
        AsyncActionPolicy::AllowConcurrent,
        move |owner| async move {
            std::fs::write(&worker_partial, b"partial").unwrap();
            owner.own_export_temp(worker_partial);
            owned_tx.send(()).unwrap();
            std::future::pending::<Result<AsyncActionPayload, String>>().await
        },
    );
    owned_rx.await.unwrap();
    drop(app);
    assert!(!partial.exists());
}

#[tokio::test]
async fn queue_edit_does_not_block_key_handler() {
    let (barrier, arrived) = owned_barrier(BlockingOperationKind::QueueMutation);
    let mut app = App::new(None, false);
    activate_composer(&mut app);
    app.queue
        .push(input::optimistic_queue_item("queued".to_string()));
    app.queue_action_edit(None);
    arrived.await.unwrap();
    app.handle_terminal_event(crossterm::event::Event::Key(
        crossterm::event::KeyEvent::new(
            crossterm::event::KeyCode::Char('x'),
            crossterm::event::KeyModifiers::NONE,
        ),
    ));
    assert_eq!(app.composer.text(), "x");
    assert_eq!(app.async_actions.pending_count(), 1);
    barrier.release();
}

#[tokio::test]
async fn btw_teardown_does_not_block_during_session() {
    let (barrier, arrived) = owned_barrier(BlockingOperationKind::BtwTeardown);
    let mut app = App::new(None, false);
    app.handle_btw_command("end");
    arrived.await.unwrap();
    app.handle_terminal_event(crossterm::event::Event::Resize(91, 37));
    assert_eq!(app.async_actions.pending_count(), 1);
    barrier.release();
}

#[test]
fn btw_teardown_on_exit_path_remains_synchronous() {
    let called = std::cell::Cell::new(false);
    assert!(run_post_loop_btw_teardown(true, || called.set(true)));
    assert!(
        called.get(),
        "post-loop teardown completed before returning"
    );

    called.set(false);
    assert!(!run_post_loop_btw_teardown(false, || called.set(true)));
    assert!(!called.get());
}

#[tokio::test]
async fn at_suggestions_do_no_blocking_work() {
    let (barrier, arrived) = owned_barrier(BlockingOperationKind::FileAutocomplete);
    let mut app = App::new(None, false);
    app.composer.set("@src".to_string());
    app.reset_at_window();
    arrived.await.unwrap();
    app.handle_terminal_event(crossterm::event::Event::Resize(80, 24));
    assert!(app.at_suggestions_loading);
    assert_eq!(app.async_actions.pending_count(), 1);
    barrier.release();
}

#[tokio::test]
async fn stale_at_suggestion_result_is_discarded() {
    let mut app = App::new(None, false);
    app.composer.set("@new".to_string());
    app.at_suggestions_loading = true;
    app.async_actions.start(
        AsyncActionKind::Blocking("autocomplete.files"),
        AsyncActionPolicy::AllowConcurrent,
        async {
            Ok(AsyncActionPayload::FileSuggestions {
                query: "old".to_string(),
                suggestions: Vec::new(),
            })
        },
    );
    app.async_actions.notifier().notified().await;
    app.drain_async_actions();

    assert!(app.at_suggestions_loading);
    assert!(app.at_suggestions_loaded_query.is_none());
    assert!(app.at_cache.borrow().is_none());
}

#[tokio::test]
async fn at_suggestion_failure_is_terminal() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.composer.set("@missing".to_string());
    app.at_suggestions_loading = true;
    app.async_actions.start(
        AsyncActionKind::Blocking("autocomplete.files"),
        AsyncActionPolicy::AllowConcurrent,
        async { Err("walk failed".to_string()) },
    );
    app.async_actions.notifier().notified().await;
    app.drain_async_actions();

    assert!(!app.at_suggestions_loading);
    assert_eq!(app.at_suggestions_error.as_deref(), Some("walk failed"));
}

#[tokio::test]
async fn at_suggestions_distinguish_loading_from_empty() {
    let mut app = App::new(None, false);
    app.composer.set("@none".to_string());
    app.at_suggestions_loading = true;
    app.async_actions.start(
        AsyncActionKind::Blocking("autocomplete.files"),
        AsyncActionPolicy::AllowConcurrent,
        async {
            Ok(AsyncActionPayload::FileSuggestions {
                query: "none".to_string(),
                suggestions: Vec::new(),
            })
        },
    );
    assert!(app.at_suggestions_loading);
    app.async_actions.notifier().notified().await;
    app.drain_async_actions();
    assert!(!app.at_suggestions_loading);
    assert!(
        matches!(&*app.at_cache.borrow(), Some((query, suggestions)) if query == "none" && suggestions.is_empty())
    );
}

#[tokio::test]
async fn export_is_atomic_and_does_not_clobber() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("existing.json");
    tokio::fs::write(&target, b"original").await.unwrap();
    let cancellation = std::sync::Arc::new(AsyncActionCancellation::default());
    let error =
        export_actions::write_export_no_clobber(&target, b"replacement", "/export", &cancellation)
            .await
            .unwrap_err();
    assert!(error.contains("already exists"));
    assert_eq!(tokio::fs::read(&target).await.unwrap(), b"original");
    assert_eq!(
        std::fs::read_dir(tmp.path())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains("partial"))
            .count(),
        0
    );
}
