use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratatui::layout::Rect;
use tokio::sync::mpsc;

use super::{App, DispatchOutcome, SideConversation};
use crate::engine::message::UserSubmission;
use crate::tui::agent_runner::{AgentRunner, ClientTasks, ControlRequest, UsageCounts};
use crate::tui::history::HistoryEntry;

fn runner_with_sender(
    input_tx: mpsc::Sender<UserSubmission>,
    events: Arc<Mutex<Vec<crate::engine::TurnEvent>>>,
) -> AgentRunner {
    let (record_tx, _record_rx) = mpsc::channel(1);
    runner_with_channels(input_tx, record_tx, events)
}

fn runner_with_channels(
    input_tx: mpsc::Sender<UserSubmission>,
    record_tx: mpsc::Sender<crate::daemon::proto::Request>,
    events: Arc<Mutex<Vec<crate::engine::TurnEvent>>>,
) -> AgentRunner {
    let (control_tx, _control_rx) = mpsc::channel(1);
    runner_with_all_channels(input_tx, record_tx, control_tx, events)
}

fn runner_with_all_channels(
    input_tx: mpsc::Sender<UserSubmission>,
    record_tx: mpsc::Sender<crate::daemon::proto::Request>,
    control_tx: mpsc::Sender<ControlRequest>,
    events: Arc<Mutex<Vec<crate::engine::TurnEvent>>>,
) -> AgentRunner {
    let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
    AgentRunner {
        input_tx,
        record_tx,
        control_tx,
        attached_request_tx,
        events,
        event_notify: Arc::new(tokio::sync::Notify::new()),
        active_agent: Arc::new(Mutex::new("Build".to_string())),
        active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
        skill_inventory_names: Arc::new(Mutex::new(None)),
        foreground_target: Some(crate::engine::message::QueueTarget::root("Build")),
        session_id: uuid::Uuid::new_v4(),
        short_id: "abc123".to_string(),
        project_id: "project".to_string(),
        usage: UsageCounts::default(),
        owns_daemon: false,
        socket: PathBuf::from("/tmp/cockpit-test.sock"),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        client_tasks: ClientTasks::default(),
    }
}

fn seed_session_live_state(app: &mut App) {
    app.queue
        .push(crate::tui::app::input::optimistic_queue_item(
            "queued".to_string(),
        ));
    app.pending = Some(super::PendingMsg {
        name: "Build".to_string(),
        text: "partial".to_string(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        started_at: Instant::now(),
        text_started_at: None,
        inside_think: false,
        body_started: false,
        tag_partial: String::new(),
        seq: None,
        strip_think: true,
    });
    app.prunable_tokens = 42;
    app.elided_event_ids.insert("event-1".to_string());
    app.active_schedules.insert(
        "job-1".to_string(),
        super::ActiveSchedule {
            session_id: uuid::Uuid::new_v4(),
            label: "background".to_string(),
            kind: "background".to_string(),
            iteration: 1,
            last_activity: Instant::now(),
        },
    );
    app.pending_stop_confirm = Some(vec!["job-1".to_string()]);
    app.chat_scroll_offset = 7;
    app.begin_working_span();
    app.reconnect = Some(super::ReconnectStatus {
        attempt: 2,
        provider: "provider".to_string(),
        model: "model".to_string(),
        url: "https://example.test".to_string(),
    });
    app.prediction_state.begin_turn();
    app.prediction_state.on_result(
        app.prediction_state.turn(),
        Some("predicted text".to_string()),
        false,
        true,
    );
    app.prompt_history_cursor = 3;
    app.staged_draft = Some("draft".to_string());
    app.pending_git_blocks.push("git diff".to_string());
    app.accepted_tags.push("path with spaces.rs".to_string());
    app.pending_edit_args.insert(
        "cid".to_string(),
        super::PendingEditArgs {
            path: "src/lib.rs".to_string(),
            old: "old".to_string(),
            new: "new".to_string(),
        },
    );
}

fn fake_side_conversation(tmp: &std::path::Path) -> SideConversation {
    SideConversation {
        side_session_id: uuid::Uuid::new_v4(),
        socket: tmp.join("missing-daemon.sock"),
        saved_runner: None,
        saved_history: vec![HistoryEntry::Plain {
            line: "main history".to_string(),
        }],
        saved_queue: vec![crate::tui::app::input::optimistic_queue_item(
            "queued main message".to_string(),
        )],
        saved_pending: None,
        saved_prunable_tokens: 42,
        saved_cache_cold: false,
        saved_elided_event_ids: std::collections::HashSet::from(["event-1".to_string()]),
        saved_active_schedules: std::collections::BTreeMap::new(),
        saved_pending_stop_confirm: Some(vec!["stop-me".to_string()]),
        saved_chat_scroll_offset: 7,
        saved_project_id: Some("project-main".to_string()),
        saved_session_id: Some(uuid::Uuid::new_v4()),
        saved_session_short_id: Some("main123".to_string()),
        saved_current_session_persisted: true,
    }
}

fn seed_new_session_reset_state(app: &mut App) -> mpsc::Receiver<ControlRequest> {
    let (input_tx, _input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));
    app.pending_new_session = true;
    app.busy = true;
    app.history.push(HistoryEntry::Plain {
        line: "old transcript".to_string(),
    });
    seed_session_live_state(app);
    app.clickable_rows = vec![Some(0)];
    app.box_rows = vec![Some(0)];
    app.chat_area = Some(Rect::new(0, 0, 80, 20));
    app.chat_text_grid = vec![vec!["x".to_string()]];
    app.chat_cont_rows = vec![true];
    app.selection = Some(super::Selection {
        anchor: (0, 0),
        focus: (1, 1),
        active: false,
    });
    app.display_attach_backoff.record_failure(Instant::now());
    app.current_session_persisted = true;
    app.usage_models.insert("p/m".to_string(), 2);
    app.usage_slash.insert("/new".to_string(), 1);
    app.usage_tags.insert("src/lib.rs".to_string(), 1);
    app.project_id = Some("project-old".to_string());
    app.pending_usage
        .push(crate::daemon::proto::Request::CancelTurn);
    app.last_usage = Some(crate::tokens::TokenUsage {
        input_tokens: 10,
        output_tokens: 2,
        cached_input_tokens: 3,
        cache_creation_input_tokens: 4,
    });
    app.estimate_at_last_usage = 99;
    control_rx
}

#[test]
fn queued_submit_from_off_tail_returns_to_live_tail_immediately() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, mut input_rx) = mpsc::channel(1);
    app.agent_runner = Some(Ok(runner_with_sender(
        input_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));
    app.busy = true;
    app.chat_scroll_offset = 6;
    app.composer.set("queued while busy".to_string());

    let keep_running = app.submit_input();

    assert!(!keep_running);
    assert_eq!(app.chat_scroll_offset, 0);
    let submission = input_rx.try_recv().expect("queued submission sent");
    assert_eq!(submission.text, "queued while busy");
}

#[test]
fn reset_session_live_state_clears_hidden_per_session_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.history.push(HistoryEntry::Plain {
        line: "visible history is caller-owned".to_string(),
    });
    app.composer.set("visible draft".to_string());
    app.prompt_history.push("cross-session recall".to_string());
    let turn_before = app.prediction_state.turn();
    seed_session_live_state(&mut app);

    app.reset_session_live_state();

    assert!(app.queue.is_empty());
    assert!(app.pending.is_none());
    assert_eq!(app.prunable_tokens, 0);
    assert!(app.elided_event_ids.is_empty());
    assert!(app.active_schedules.is_empty());
    assert!(app.pending_stop_confirm.is_none());
    assert_eq!(app.chat_scroll_offset, 0);
    assert!(!app.busy);
    assert!(app.span_started_at.is_none());
    assert!(app.reconnect.is_none());
    assert!(app.prediction_state.ghost().is_none());
    assert!(
        app.prediction_state.turn() > turn_before,
        "reset invalidates stale async prediction results"
    );
    assert_eq!(app.prompt_history_cursor, 0);
    assert!(app.staged_draft.is_none());
    assert!(app.pending_git_blocks.is_empty());
    assert!(app.accepted_tags.is_empty());
    assert!(app.pending_edit_args.is_empty());
    assert_eq!(app.composer.text(), "visible draft");
    assert_eq!(app.prompt_history, vec!["cross-session recall"]);
    assert_eq!(app.history.len(), 1, "history is reset by each caller");
}

#[test]
fn session_switch_busy_guard_interrupts_only_when_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, _input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    app.busy = false;
    app.cancel_outgoing_turn_if_busy();
    assert!(control_rx.try_recv().is_err());

    app.busy = true;
    app.cancel_outgoing_turn_if_busy();
    assert!(matches!(
        control_rx.try_recv().map(|request| request.request),
        Ok(crate::daemon::proto::Request::CancelTurn)
    ));
    assert!(control_rx.try_recv().is_err(), "only one cancel is sent");
}

#[test]
fn new_session_without_pending_does_not_clear_or_request_redraw() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let mut clear_called = false;

    let changed = app
        .maybe_service_new_session_with_clear(|| {
            clear_called = true;
            Ok(())
        })
        .unwrap();

    assert!(!changed);
    assert!(!clear_called);
}

#[test]
fn new_session_clear_failure_is_nonfatal_and_finishes_reset() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let mut control_rx = seed_new_session_reset_state(&mut app);

    let changed = app
        .maybe_service_new_session_with_clear(|| {
            Err(anyhow::anyhow!(
                "The cursor position could not be read within a normal duration"
            ))
        })
        .unwrap();

    assert!(changed, "serviced /new must request a follow-up redraw");
    assert!(matches!(
        control_rx.try_recv().map(|request| request.request),
        Ok(crate::daemon::proto::Request::CancelTurn)
    ));
    assert!(control_rx.try_recv().is_err(), "only one cancel is sent");
    assert!(!app.pending_new_session);
    assert!(app.history.is_empty());
    assert!(app.queue.is_empty());
    assert!(app.pending.is_none());
    assert!(app.clickable_rows.is_empty());
    assert!(app.box_rows.is_empty());
    assert!(app.chat_area.is_none());
    assert!(app.chat_text_grid.is_empty());
    assert!(app.chat_cont_rows.is_empty());
    assert!(app.selection.is_none());
    assert!(app.agent_runner.is_none());
    assert!(app.display_attach_backoff.can_attempt(Instant::now()));
    assert!(!app.current_session_persisted);
    assert!(app.usage_models.is_empty());
    assert!(app.usage_slash.is_empty());
    assert!(app.usage_tags.is_empty());
    assert!(app.project_id.is_none());
    assert!(app.pending_usage.is_empty());
    assert!(app.last_usage.is_none());
    assert_eq!(app.estimate_at_last_usage, 0);
    assert!(!app.busy);
    assert!(app.toast.is_none(), "clear failure should not show a toast");
}

#[test]
fn new_session_success_invokes_terminal_clear_and_requests_redraw() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.pending_new_session = true;
    let mut clear_count = 0;

    let changed = app
        .maybe_service_new_session_with_clear(|| {
            clear_count += 1;
            Ok(())
        })
        .unwrap();

    assert!(changed);
    assert_eq!(clear_count, 1);
}

#[tokio::test]
async fn new_session_from_side_conversation_discards_side_before_resetting() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.side_conversation = Some(fake_side_conversation(tmp.path()));
    app.pending_new_session = true;
    app.history.push(HistoryEntry::Plain {
        line: "side-only history".to_string(),
    });

    let changed = app.maybe_service_new_session_with_clear(|| Ok(())).unwrap();

    assert!(changed);
    assert!(app.side_conversation.is_none());
    assert!(app.history.is_empty());
    assert!(app.queue.is_empty());
    assert!(app.project_id.is_none());
    assert!(!app.current_session_persisted);
    assert_eq!(app.async_actions.pending_count(), 1);
}

fn newest_user_failed(app: &App) -> bool {
    app.history.iter().rev().any(|entry| {
        matches!(
            entry,
            HistoryEntry::User {
                seq: None,
                persist_failed: true,
                preflight_pending: false,
                ..
            }
        )
    })
}

fn error_lines(app: &App) -> Vec<&str> {
    app.history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::InferenceError { summary, .. } => Some(summary.as_str()),
            HistoryEntry::CommandError { line } => Some(line.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn normal_dispatch_queue_full_marks_user_failed_and_ends_span() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (tx, _rx) = mpsc::channel(1);
    tx.try_send(UserSubmission::text("already queued".to_string()))
        .unwrap();
    app.agent_runner = Some(Ok(runner_with_sender(tx, Arc::new(Mutex::new(Vec::new())))));
    app.begin_working_span();

    let outcome = app.dispatch_optimistic_user_submission(
        "hello".to_string(),
        UserSubmission::text("hello".to_string()),
        "engine",
        true,
        &[],
    );

    assert_eq!(outcome, DispatchOutcome::QueueFull);
    assert!(!app.busy, "failed fresh dispatch ends its own span");
    assert!(!app.current_session_persisted);
    assert!(newest_user_failed(&app));
    assert!(
        app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::CommandError { line } if line.contains("input queue full")
            )
        }),
        "queue-full dispatch failure should use the command-error variant"
    );
    assert!(
        error_lines(&app)
            .iter()
            .any(|line| line.contains("input queue full")),
        "queue-full error is rendered with the error-styled variant"
    );
}

#[test]
fn normal_dispatch_closed_marks_user_failed_and_ends_span() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    app.agent_runner = Some(Ok(runner_with_sender(tx, Arc::new(Mutex::new(Vec::new())))));
    app.begin_working_span();

    let outcome = app.dispatch_optimistic_user_submission(
        "hello".to_string(),
        UserSubmission::text("hello".to_string()),
        "engine",
        true,
        &[],
    );

    assert_eq!(outcome, DispatchOutcome::DriverClosed);
    assert!(!app.busy);
    assert!(!app.current_session_persisted);
    assert!(newest_user_failed(&app));
    assert!(
        error_lines(&app)
            .iter()
            .any(|line| line.contains("driver task has exited"))
    );
}

#[test]
fn slash_dispatch_failures_use_same_failed_user_reconciliation() {
    let tmp = tempfile::tempdir().unwrap();
    for (label, dispatch) in [
        (
            "/init",
            App::dispatch_init_turn as fn(&mut App, &str, String),
        ),
        (
            "/goal",
            App::dispatch_goal_turn as fn(&mut App, &str, String),
        ),
    ] {
        let mut app = App::new(Some(tmp.path()), false);
        app.agent_runner = Some(Err("model missing".to_string()));
        dispatch(&mut app, "thing", "wire".to_string());

        assert!(!app.busy, "{label} failed dispatch ends its span");
        assert!(!app.current_session_persisted);
        assert!(newest_user_failed(&app));
        assert!(
            error_lines(&app).iter().any(|line| line.starts_with(label)),
            "{label} failure uses the shared error path"
        );
    }

    let mut app = App::new(Some(tmp.path()), false);
    app.agent_runner = Some(Err("model missing".to_string()));
    app.dispatch_skill_invocation("/skill demo".to_string(), "demo", "task");
    assert!(!app.busy, "/skill failed dispatch ends its span");
    assert!(!app.current_session_persisted);
    assert!(newest_user_failed(&app));
    assert!(
        error_lines(&app)
            .iter()
            .any(|line| line.starts_with("/skill"))
    );
}

#[test]
fn failed_fresh_dispatch_removes_unsent_tag_rows() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.agent_runner = Some(Err("model missing".to_string()));
    app.begin_working_span();
    let tags = vec![crate::daemon::proto::TagExpansionMeta {
        tool: "read".to_string(),
        path: "src/lib.rs".to_string(),
        detail: "10 lines".to_string(),
        ok: true,
    }];

    app.dispatch_optimistic_user_submission(
        "read @src/lib.rs".to_string(),
        UserSubmission::text("read file".to_string()),
        "engine",
        true,
        &tags,
    );

    assert!(newest_user_failed(&app));
    assert!(
        !app.history.iter().any(|entry| {
            matches!(entry, HistoryEntry::Plain { line } if line.contains("src/lib.rs"))
        }),
        "tag attachment row is removed because the agent never received it"
    );
}

#[test]
fn queued_path_failures_do_not_end_an_existing_span() {
    assert!(DispatchOutcome::QueueFull.span_orphaned());
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.begin_working_span();
    app.reconcile_failed_dispatch(DispatchOutcome::QueueFull, "engine", 0);
    assert!(
        app.busy,
        "shared reconciliation alone does not own the span"
    );
}

#[test]
fn multireview_set_agent_failure_shows_guidance_without_token_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);

    app.start_multireview("kickoff".to_string());

    assert!(
        app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line }
                    if line == "/multireview: send a message first to start a session"
            )
        }),
        "start-session-first guidance remains visible"
    );
    assert!(
        !app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line }
                    if line == super::MULTIREVIEW_TOKEN_BURN_WARNING
            )
        }),
        "warning is not shown when SetAgent was not accepted"
    );
    assert!(!app.busy);
}

#[test]
fn multireview_kickoff_queue_full_reconciles_user_row_and_ends_span() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, _input_rx) = mpsc::channel(1);
    input_tx
        .try_send(UserSubmission::text("already queued".to_string()))
        .unwrap();
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    app.start_multireview("kickoff".to_string());

    assert!(matches!(
        control_rx.try_recv().map(|request| request.request),
        Ok(crate::daemon::proto::Request::SetAgent { name }) if name == "Multireview"
    ));
    app.apply_event(crate::engine::TurnEvent::ControlRequestFinished {
        request_id: crate::engine::ControlRequestId(1),
        outcome: crate::engine::ControlRequestOutcome::Applied,
    });
    assert!(
        app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line }
                    if line == super::MULTIREVIEW_TOKEN_BURN_WARNING
            )
        }),
        "warning remains because the app entered Multireview mode"
    );
    assert!(newest_user_failed(&app));
    assert!(
        error_lines(&app)
            .iter()
            .any(|line| line.starts_with("/multireview") && line.contains("queue full"))
    );
    assert!(!app.busy);
}

#[test]
fn multireview_kickoff_closed_reconciles_user_row_and_ends_span() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, input_rx) = mpsc::channel(1);
    drop(input_rx);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    app.start_multireview("kickoff".to_string());

    assert!(matches!(
        control_rx.try_recv().map(|request| request.request),
        Ok(crate::daemon::proto::Request::SetAgent { name }) if name == "Multireview"
    ));
    app.apply_event(crate::engine::TurnEvent::ControlRequestFinished {
        request_id: crate::engine::ControlRequestId(1),
        outcome: crate::engine::ControlRequestOutcome::Applied,
    });
    assert!(newest_user_failed(&app));
    assert!(error_lines(&app).iter().any(
        |line| line.starts_with("/multireview") && line.contains("driver task has exited")
    ));
    assert!(!app.busy);
}

#[test]
fn multireview_kickoff_success_warns_pushes_user_and_dispatches() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, mut input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    app.start_multireview("kickoff".to_string());

    assert!(matches!(
        control_rx.try_recv().map(|request| request.request),
        Ok(crate::daemon::proto::Request::SetAgent { name }) if name == "Multireview"
    ));
    app.apply_event(crate::engine::TurnEvent::ControlRequestFinished {
        request_id: crate::engine::ControlRequestId(1),
        outcome: crate::engine::ControlRequestOutcome::Applied,
    });
    let submission = input_rx.try_recv().expect("kickoff submitted");
    assert_eq!(submission.text, "kickoff");
    assert!(
        app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line }
                    if line == super::MULTIREVIEW_TOKEN_BURN_WARNING
            )
        }),
        "warning appears on successful kickoff"
    );
    assert!(
        app.history.iter().any(|entry| {
            matches!(entry, HistoryEntry::User { text, persist_failed: false, .. } if text == "kickoff")
        }),
        "kickoff user row appears as sent"
    );
    assert!(app.busy, "successful dispatch stays busy until AgentIdle");
}
