use super::{App, Dialog, SESSION_SWITCH_SPINNER_THRESHOLD};
use crate::tui::agent_runner::{SessionSwitchOutcome, SessionTarget};
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::history::HistoryEntry;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::time::{Duration, Instant};

#[test]
fn new_session_swap_loads_extended_config_once() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    cockpit_config::extended::reset_load_for_cwd_call_count();

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
    assert_eq!(cockpit_config::extended::load_for_cwd_call_count(), 1);
}

#[test]
fn new_session_swap_makes_no_daemon_probe_or_connect() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    cockpit_core::daemon::reset_blocking_probe_call_count();
    cockpit_core::daemon::client::reset_connect_call_count();

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
    assert_eq!(cockpit_core::daemon::blocking_probe_call_count(), 0);
    assert_eq!(cockpit_core::daemon::client::connect_call_count(), 0);
}

#[test]
fn new_session_swap_opens_no_database() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    cockpit_db::reset_open_default_call_count();

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
    assert_eq!(cockpit_db::open_default_call_count(), 0);
}

fn app_with_only_session_switch_pending(started_at: Instant) -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    app.busy = false;
    app.pending = None;
    app.toast = None;
    app.ctrl_c_armed_at = None;
    app.reconnect = None;
    app.pane = None;
    app.dialog = Dialog::None;
    app.question_dialog = None;
    app.daemon_prompt = None;
    let kind = AsyncActionKind::Internal("session.switch");
    app.async_actions.start(
        kind.clone(),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    app.async_actions
        .set_pending_kind_started_at(&kind, started_at);
    app
}

async fn drain_async_actions_until_idle(app: &mut App) {
    for _ in 0..20 {
        app.drain_async_actions();
        if app.async_actions.pending_count() == 0 {
            app.drain_async_actions();
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("async action did not complete");
}

fn switch_outcome(session_id: uuid::Uuid, short_id: &str) -> AsyncActionPayload {
    AsyncActionPayload::SessionSwitched(Box::new(SessionSwitchOutcome {
        target: SessionTarget::New,
        session_id,
        short_id: short_id.to_string(),
        foreground_target: None,
        active_model_state: None,
        project_id: format!("project-{short_id}"),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
    }))
}

#[tokio::test]
async fn swap_below_threshold_shows_no_spinner() {
    let started_at = Instant::now()
        .checked_sub(SESSION_SWITCH_SPINNER_THRESHOLD / 2)
        .unwrap();
    let app = app_with_only_session_switch_pending(started_at);

    assert!(!app.animation_tick_active());
}

#[tokio::test]
async fn swap_above_threshold_shows_spinner() {
    let started_at = Instant::now()
        .checked_sub(SESSION_SWITCH_SPINNER_THRESHOLD + Duration::from_millis(1))
        .unwrap();
    let app = app_with_only_session_switch_pending(started_at);

    assert!(app.animation_tick_active());
}

#[tokio::test]
async fn new_session_swap_failure_keeps_cleared_history() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    app.history.push(HistoryEntry::Plain {
        line: "old transcript".to_string(),
    });
    app.history.clear();

    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { Err("attach failed".to_string()) },
    );
    drain_async_actions_until_idle(&mut app).await;

    assert!(
        !app.history.iter().any(|entry| {
            matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
        }),
        "failed swap must not restore the previous transcript"
    );
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line == "/new: attach failed")
    }));
    assert!(matches!(
        app.agent_runner.as_ref(),
        Some(Err(error)) if error == "attach failed"
    ));
}

#[tokio::test]
async fn new_session_swap_draws_before_swap_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    app.history.clear();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

    terminal.draw(|frame| app.render(frame)).unwrap();

    assert_eq!(app.async_actions.pending_count(), 1);
    assert!(app.history.is_empty());
}

#[tokio::test]
async fn new_session_swap_supersedes_in_flight_swap() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    let first = uuid::Uuid::new_v4();
    let second = uuid::Uuid::new_v4();

    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { Ok(switch_outcome(second, "second")) },
    );
    drain_async_actions_until_idle(&mut app).await;

    assert_eq!(app.launch.session_id, Some(second));
    assert_ne!(app.launch.session_id, Some(first));
    assert_eq!(app.launch.session_short_id.as_deref(), Some("second"));
}

#[tokio::test]
async fn new_session_swap_discards_stale_result() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new_with_db(
        Some(tmp.path()),
        false,
        cockpit_db::Db::open_in_memory().unwrap(),
    );
    let stale_session = uuid::Uuid::new_v4();
    let active_session = uuid::Uuid::new_v4();

    let stale_id = app
        .async_actions
        .start(
            AsyncActionKind::Internal("session.switch"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
            async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
        )
        .id();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { Ok(switch_outcome(active_session, "active")) },
    );
    drain_async_actions_until_idle(&mut app).await;
    app.async_actions.inject_completed_for_test(
        stale_id,
        AsyncActionKind::Internal("session.switch"),
        Ok(switch_outcome(stale_session, "stale")),
    );
    app.drain_async_actions();

    assert_eq!(app.launch.session_id, Some(active_session));
    assert_ne!(app.launch.session_id, Some(stale_session));
    assert_eq!(app.launch.session_short_id.as_deref(), Some("active"));
}
