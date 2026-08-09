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
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app.overlay = Overlay::None;
    app.question_dialog = None;
    app.composer.set_vim_enabled(false);
}

#[test]
fn blocking_operation_manifest_is_complete() {
    use super::blocking_operations::{ALL_BLOCKING_OPERATION_SITES, BLOCKING_OPERATION_MANIFEST};

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
        ALL_BLOCKING_OPERATION_SITES
            .iter()
            .find(|authority| authority.site == registration.site)
            .unwrap_or_else(|| panic!("manifest contains undeclared site {:?}", registration.site));
        let (source, handler) = derive_wrapper_handler(registration.wrapper)
            .unwrap_or_else(|error| panic!("{:?}: {error}", registration.site));
        validate_handler_source(source, &handler, registration.wrapper)
            .unwrap_or_else(|error| panic!("{:?}: {error}", registration.site));
        validate_site_reachability(registration.site, &handler)
            .unwrap_or_else(|error| panic!("{:?}: {error}", registration.site));
    }
    let declared = ALL_BLOCKING_OPERATION_SITES
        .iter()
        .map(|authority| authority.site)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(
        sites, declared,
        "manifest must cover every sealed site exactly once"
    );
}

const PRODUCTION_ROUTING_SOURCES: &[&str] = &[
    include_str!("slash.rs"),
    include_str!("input.rs"),
    include_str!("export_actions.rs"),
    include_str!("btw_pane.rs"),
];

fn derive_wrapper_handler(wrapper: &str) -> Result<(&'static str, String), String> {
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
        for function in functions {
            let Some(name) = function
                .child_by_field_name("name")
                .and_then(|n| n.utf8_text(source.as_bytes()).ok())
            else {
                continue;
            };
            if analyze_handler_source(source, name, wrapper).is_ok_and(|calls| calls == 1) {
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

fn validate_site_reachability(
    site: super::blocking_operations::BlockingOperationSite,
    handler: &str,
) -> Result<(), String> {
    use super::blocking_operations::BlockingOperationSite::*;
    let slash = include_str!("slash.rs");
    let input = include_str!("input.rs");
    let reachable = match site {
        SlashCurator => {
            slash.contains("name: \"curator\"")
                && slash.contains("run: run_curator")
                && handler == "handle_curator_command"
        }
        SlashDoctor => {
            slash.contains("name: \"doctor\"")
                && slash.contains("run: run_doctor")
                && handler == "handle_doctor_command"
        }
        SlashExport => {
            slash.contains("name: \"export\"")
                && slash.contains("run: run_export")
                && handler == "start_export_action"
        }
        SlashBtw => {
            slash.contains("name: \"btw\"")
                && slash.contains("run: run_btw")
                && handler == "handle_btw_command"
        }
        QueueEditKey => {
            input.contains("KeyCode::Up")
                && input.contains("self.history_up()")
                && handler == "edit_queued_messages"
        }
        ComposerSuggestions => {
            input.contains("self.reset_at_window()") && handler == "reset_at_window"
        }
    };
    reachable.then_some(()).ok_or_else(|| {
        format!("handler `{handler}` is unreachable from its production registration")
    })
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
        inspect_handler_calls(child, source, wrapper, wrapper_calls)?;
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
fn sealed_site_catalog_detects_a_deleted_manifest_row() {
    use super::blocking_operations::{ALL_BLOCKING_OPERATION_SITES, BLOCKING_OPERATION_MANIFEST};
    let declared = ALL_BLOCKING_OPERATION_SITES
        .iter()
        .map(|authority| authority.site)
        .collect::<std::collections::HashSet<_>>();
    let missing_one = BLOCKING_OPERATION_MANIFEST[1..]
        .iter()
        .map(|registration| registration.site)
        .collect::<std::collections::HashSet<_>>();
    assert_ne!(declared, missing_one);
}

#[test]
fn production_route_gate_rejects_unreachable_and_unclassified_handlers() {
    use super::blocking_operations::BlockingOperationSite;
    assert!(validate_site_reachability(BlockingOperationSite::SlashCurator, "bypass").is_err());
    assert!(derive_wrapper_handler("unclassified_owned_dispatch").is_err());
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
    app.history_up();

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
    app.apply_event(cockpit_core::engine::TurnEvent::Notice {
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
    app.daemon_prompt = None;
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
    app.history_up();
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
