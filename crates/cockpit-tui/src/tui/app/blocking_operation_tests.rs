use super::*;

#[test]
fn blocking_operation_manifest_is_complete() {
    use super::blocking_operations::{BLOCKING_OPERATION_MANIFEST, BlockingOperationKind};

    assert_eq!(BLOCKING_OPERATION_MANIFEST.len(), 6);
    let expected = [
        ("slash:/curator", BlockingOperationKind::CuratorMaintenance),
        ("slash:/doctor", BlockingOperationKind::DoctorSnapshot),
        ("slash:/export", BlockingOperationKind::ExportWrite),
        ("key:queue-edit", BlockingOperationKind::QueueMutation),
        ("slash:/btw", BlockingOperationKind::BtwTeardown),
        (
            "composer:@suggestions",
            BlockingOperationKind::FileAutocomplete,
        ),
    ];
    assert_eq!(
        BLOCKING_OPERATION_MANIFEST
            .iter()
            .map(|entry| (entry.site, entry.kind))
            .collect::<Vec<_>>(),
        expected
    );

    let mut sites = std::collections::HashSet::new();
    let mut kinds = std::collections::HashSet::new();
    let production = [
        include_str!("slash.rs"),
        include_str!("input.rs"),
        include_str!("btw_pane.rs"),
        include_str!("export_actions.rs"),
    ]
    .join("\n");
    let mut actions = std::collections::HashSet::new();
    for registration in BLOCKING_OPERATION_MANIFEST {
        assert!(
            sites.insert(registration.site),
            "duplicate blocking-operation site: {}",
            registration.site,
        );
        assert!(
            kinds.insert(registration.kind),
            "duplicate blocking-operation kind: {:?}",
            registration.kind,
        );
        for action in registration.actions {
            assert!(actions.insert(*action), "duplicate action: {action}");
            assert!(production.contains(action), "undispatched action: {action}");
        }
    }
}

#[test]
fn no_owned_blocking_command_runs_on_event_loop() {
    let source = include_str!("slash.rs");
    assert!(source.contains("start_owned_blocking_action"));
    assert!(source.contains("BlockingOperationKind::DoctorSnapshot"));

    let input = include_str!("input.rs");
    assert!(!input.contains("attached_request_tx_blocking(\n                attached_request"));

    let render = include_str!("render.rs");
    assert!(!render.contains("cockpit_core::tags::suggestions(&self.launch.cwd"));
}

#[test]
fn curator_command_is_async_with_pending_line() {
    let source = include_str!("slash.rs");
    assert!(source.contains("/curator: pending"));
}

#[test]
fn doctor_command_is_async() {
    let source = include_str!("slash.rs");
    assert!(source.contains("/doctor: collecting diagnostics…"));
}

#[test]
fn doctor_snapshot_is_point_in_time() {
    assert!(include_str!("slash.rs").contains("DoctorSnapshotInput"));
}

#[test]
fn export_writes_off_the_loop_thread() {
    let source = include_str!("export_actions.rs");
    assert!(source.contains("self.async_actions.start("));
    assert!(source.contains("write_export_no_clobber"));
}

#[test]
fn queue_edit_does_not_block_key_handler() {
    let source = include_str!("input.rs");
    assert!(source.contains("queue.edit"));
}

#[test]
fn queue_edits_apply_in_user_order() {
    let source = include_str!("input.rs");
    assert!(source.contains("start_serialized"));
}

#[test]
fn btw_teardown_does_not_block_during_session() {
    let source = include_str!("btw_pane.rs");
    assert!(source.contains("BtwRpcPlan::End"));
    let production = source.split("#[cfg(test)]").next().unwrap_or(source);
    assert!(!production.contains("attached_request_tx_blocking"));
    assert!(production.contains("BtwTransition"));
}

#[test]
fn btw_teardown_on_exit_path_remains_synchronous() {
    assert!(include_str!("mod.rs").contains("Request::EndBtwFork"));
}

#[test]
fn at_suggestions_do_no_blocking_work() {
    let source = include_str!("render.rs");
    assert!(!source.contains("cockpit_core::tags::suggestions(&self.launch.cwd"));
}

#[test]
fn stale_at_suggestion_result_is_discarded() {
    assert!(include_str!("async_actions.rs").contains("autocomplete.files"));
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

#[test]
fn at_suggestions_distinguish_loading_from_empty() {
    let source = include_str!("render.rs");
    assert!(source.contains("loading files…"));
    assert!(source.contains("no matching files"));
}

#[test]
fn export_is_atomic_and_does_not_clobber() {
    let source = include_str!("export_actions.rs");
    assert!(source.contains("create_new(true)"));
    assert!(source.contains("hard_link(&temp, out_path)"));
    assert!(source.contains("remove_file(&temp)"));
}

#[test]
fn owned_async_actions_reject_late_and_double_completion() {
    let source = include_str!("../async_action.rs");
    assert!(source.contains("pending.generation != completed.generation"));
    assert!(source.contains("let Some(pending) = self.pending.remove(&completed.id)"));
}
