use super::{App, HistoryEntry, LOCAL_CMD_DISPLAY_LINES};
use crate::tui::async_action::{AsyncActionKind, AsyncActionPayload, AsyncActionPolicy};
use std::fs;
use std::sync::mpsc;
use std::time::Duration;
use tokio::sync::oneshot;

fn configured_app(tmp: &tempfile::TempDir) -> App {
    let _env = cockpit_config::dirs::test_support::IsolatedCockpitHome::new(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    fs::write(cockpit.join("config.json"), "{}").unwrap();
    let provider_dir = cockpit.join("providers");
    fs::create_dir(&provider_dir).unwrap();
    fs::write(
        provider_dir.join("p.json"),
        r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
    )
    .unwrap();
    App::new(Some(tmp.path()), false)
}

async fn drain_until_idle(app: &mut App) {
    for _ in 0..100 {
        tokio::task::yield_now().await;
        app.drain_async_actions();
        if app.async_actions.pending_count() == 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("async action did not complete");
}

#[tokio::test]
async fn local_command_records_pending_without_final_output_until_completion() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let (release_tx, release_rx) = mpsc::channel();

    app.start_local_command_action("! slow".to_string(), None, move || {
        release_rx.recv().unwrap();
        ("done".to_string(), false)
    });

    assert_eq!(app.async_actions.pending_count(), 1);
    assert!(matches!(
        app.history.last(),
        Some(HistoryEntry::Plain { line })
            if line == "! slow: running (local command; cancellation unavailable)"
    ));
    assert!(
        app.history
            .iter()
            .all(|entry| !matches!(entry, HistoryEntry::LocalCommand { .. }))
    );

    app.composer.insert_char('x');
    assert_eq!(app.composer.text(), "x");

    release_tx.send(()).unwrap();
    drain_until_idle(&mut app).await;

    assert!(app.history.iter().any(|entry| matches!(
        entry,
        HistoryEntry::LocalCommand {
            label,
            output,
            failed: false,
        } if label == "! slow" && output == "done"
    )));
}

#[tokio::test(flavor = "current_thread")]
async fn local_command_work_runs_off_event_loop_thread() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let event_loop_thread = std::thread::current().id();

    app.start_local_command_action("! thread-check".to_string(), None, move || {
        (
            (std::thread::current().id() != event_loop_thread).to_string(),
            false,
        )
    });
    drain_until_idle(&mut app).await;

    assert!(app.history.iter().any(|entry| matches!(
        entry,
        HistoryEntry::LocalCommand {
            label,
            output,
            failed: false,
        } if label == "! thread-check" && output == "true"
    )));
}

#[tokio::test]
async fn local_command_completion_preserves_failure_and_display_cleanup() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let mut raw = String::new();
    for idx in 0..(LOCAL_CMD_DISPLAY_LINES + 2) {
        raw.push_str(&format!("\x1b[31mline-{idx}\x1b[0m\n"));
    }

    app.start_local_command_action("! noisy".to_string(), None, move || (raw, true));
    drain_until_idle(&mut app).await;

    let entry = app
        .history
        .iter()
        .find_map(|entry| match entry {
            HistoryEntry::LocalCommand {
                label,
                output,
                failed,
            } if label == "! noisy" => Some((output, failed)),
            _ => None,
        })
        .expect("local command output");
    assert!(*entry.1);
    assert!(!entry.0.contains('\x1b'));
    assert!(entry.0.contains("line-0"));
    assert!(entry.0.contains("… [2 more lines"));
}

#[tokio::test]
async fn git_command_completion_appends_local_entry_and_git_context() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.start_local_command_action(
        "/git status --short".to_string(),
        Some("status --short".to_string()),
        || (" M src/main.rs\n".to_string(), false),
    );
    drain_until_idle(&mut app).await;

    assert!(app.history.iter().any(|entry| matches!(
        entry,
        HistoryEntry::LocalCommand {
            label,
            output,
            failed: false,
        } if label == "/git status --short" && output == " M src/main.rs"
    )));
    assert_eq!(
        app.pending_git_blocks,
        vec!["<git cmd=\"status --short\">\n M src/main.rs\n\n</git>".to_string()]
    );
}

#[tokio::test]
async fn display_daemon_probe_dedupes_and_does_not_block_input() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let (release_tx, release_rx) = mpsc::channel();

    app.start_display_daemon_probe_action(move || {
        release_rx.recv().unwrap();
        cockpit_core::daemon::DaemonStatus::Stale
    });
    app.start_display_daemon_probe_action(|| cockpit_core::daemon::DaemonStatus::Running);

    assert_eq!(app.async_actions.pending_count(), 1);
    app.composer.insert_char('p');
    assert_eq!(app.composer.text(), "p");

    release_tx.send(()).unwrap();
    drain_until_idle(&mut app).await;

    assert!(app.agent_runner.is_none());
}

#[tokio::test]
async fn stale_display_daemon_probe_result_is_ignored_after_context_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.start_display_daemon_probe_action(|| cockpit_core::daemon::DaemonStatus::Running);
    app.launch.cwd = tmp.path().join("different-root");
    drain_until_idle(&mut app).await;

    assert!(app.agent_runner.is_none());
}

#[tokio::test]
async fn display_daemon_probe_non_running_status_degrades_quietly() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.start_display_daemon_probe_action(|| cockpit_core::daemon::DaemonStatus::Stale);
    drain_until_idle(&mut app).await;

    assert!(app.agent_runner.is_none());
    assert!(app.completed_async_actions.is_empty());
}

#[tokio::test]
async fn app_drop_does_not_panic_with_in_flight_async_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    let (_tx, rx) = oneshot::channel::<()>();

    app.async_actions.start(
        AsyncActionKind::Internal("app-drop"),
        AsyncActionPolicy::AllowConcurrent,
        async move {
            let _ = rx.await;
            Ok(AsyncActionPayload::Unit)
        },
    );

    drop(app);
}

#[tokio::test]
async fn rename_and_note_errors_surface_from_async_results() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.async_actions.start(
        AsyncActionKind::DaemonRpc("rename"),
        AsyncActionPolicy::AllowConcurrent,
        async { Err("rename failed".to_string()) },
    );
    app.async_actions.start(
        AsyncActionKind::DaemonRpc("note"),
        AsyncActionPolicy::AllowConcurrent,
        async { Err("note failed".to_string()) },
    );

    tokio::task::yield_now().await;
    app.drain_async_actions();

    assert!(app.history.iter().any(|entry| matches!(
        entry,
        super::HistoryEntry::CommandError { line } if line == "/rename: rename failed"
    )));
    assert!(app.history.iter().any(|entry| matches!(
        entry,
        super::HistoryEntry::CommandError { line } if line == "/note: note failed"
    )));
}

#[tokio::test]
async fn stale_fork_result_is_ignored_after_context_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);

    app.async_actions.start(
        AsyncActionKind::DaemonRpc("fork.create"),
        AsyncActionPolicy::AllowConcurrent,
        async {
            Ok(AsyncActionPayload::ForkCreated {
                parent_session_id: uuid::Uuid::new_v4(),
                socket: std::path::PathBuf::from("/tmp/missing.sock"),
                session_id: uuid::Uuid::new_v4(),
                short_id: "fork01".to_string(),
                seed_composer: None,
            })
        },
    );

    tokio::task::yield_now().await;
    app.drain_async_actions();

    assert!(app.agent_runner.is_none());
    assert!(app.history.iter().all(|entry| !matches!(
        entry,
        super::HistoryEntry::Plain { line } if line.contains("fork01")
    )));
}
