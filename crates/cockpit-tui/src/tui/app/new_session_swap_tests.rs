use super::{App, Dialog, SESSION_SWITCH_SPINNER_THRESHOLD, SideConversation};
use crate::tui::agent_runner::{AgentRunner, RunnerInput, SessionSwitchOutcome, SessionTarget};
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::history::HistoryEntry;
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

use cockpit_core::engine::message::UserSubmission;

#[test]
fn new_session_swap_reads_no_config_from_disk() {
    // A `/new` swap performs no client-side config resolution
    // (`tui-config-single-source`): the swapped-in session's attach delivers a
    // fresh `ConfigSnapshot`, so the swap itself never touches disk.
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    cockpit_config::extended::reset_load_for_cwd_call_count();
    cockpit_config::providers::reset_load_effective_call_count();

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
    assert_eq!(cockpit_config::extended::load_for_cwd_call_count(), 0);
    assert_eq!(cockpit_config::providers::load_effective_call_count(), 0);
}

#[test]
fn new_session_swap_makes_no_daemon_probe_or_connect() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
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
    let mut app = App::new(Some(tmp.path()), false);

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
}

fn app_with_only_session_switch_pending(started_at: Instant) -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
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

async fn drain_session_switch_until_complete(app: &mut App) {
    for _ in 0..20 {
        app.drain_async_actions();
        if !app
            .async_actions
            .has_pending_kind(&AsyncActionKind::Internal("session.switch"))
        {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("session switch action did not complete");
}

fn switch_outcome(session_id: uuid::Uuid, short_id: &str) -> AsyncActionPayload {
    AsyncActionPayload::SessionSwitched(Box::new(SessionSwitchOutcome {
        target: SessionTarget::New,
        session_id,
        short_id: short_id.to_string(),
        active_agent: "Build".to_string(),
        active_agent_path: vec!["Build".to_string()],
        last_applied_seq: None,
        foreground_target: None,
        active_model_state: None,
        project_id: format!("project-{short_id}"),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        transition_guard: None,
    }))
}

fn runner_with_input(
    capacity: usize,
) -> (
    AgentRunner,
    mpsc::Receiver<RunnerInput>,
    mpsc::Receiver<crate::tui::agent_runner::ControlRequest>,
) {
    let (input_tx, input_rx) = mpsc::channel(capacity);
    let (control_tx, control_rx) = mpsc::channel(4);
    let mut runner = AgentRunner::stub_with_channels(control_tx, input_tx);
    runner.last_applied_seq = Some(Arc::new(Mutex::new(Some(0))));
    (runner, input_rx, control_rx)
}

fn complete_submission(index: usize) -> UserSubmission {
    UserSubmission {
        expected_model_state_generation: None,
        expected_model: None,
        kind: cockpit_core::engine::message::UserSubmissionKind::Compact,
        origin: Default::default(),
        text: format!("wire-{index}"),
        display_text: Some(format!("display-{index}")),
        tag_expansions: vec![cockpit_core::daemon::proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: format!("src/{index}.rs"),
            detail: "complete".to_string(),
            ok: true,
        }],
        images: vec![vec![index as u8, 2, 3, 4]],
        forced_skill: Some("review".to_string()),
        origin_principal: Some("flycockpit:test-owner".to_string()),
        job_id: Some(format!("job-{index}")),
        preflight_cleaned: Some(format!("clean-{index}")),
        queue_item_ids: vec![uuid::Uuid::from_u128(index as u128 + 1)],
        client_submissions: Vec::new(),
        pending_terminal_disposition: None,
        run_invocation_id: None,
        queue_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
    }
}

fn side_conversation(tmp: &std::path::Path) -> SideConversation {
    SideConversation {
        side_session_id: uuid::Uuid::new_v4(),
        socket: tmp.join("side.sock"),
        saved_runner: None,
        saved_history: Vec::new().into(),
        saved_history_render_versions: Default::default(),
        saved_history_render_fingerprints: Default::default(),
        saved_history_render_cache: Default::default(),
        saved_history_render_cache_rows: 0,
        saved_queue: Vec::new(),
        saved_pending: None,
        saved_prunable_tokens: 0,
        saved_cache_cold: false,
        saved_elided_event_ids: Default::default(),
        saved_active_schedules: Default::default(),
        saved_pending_stop_confirm: None,
        saved_chat_scroll_offset: 0,
        saved_chat_scroll_anchor: None,
        saved_chat_pinned_to_tail: true,
        saved_project_id: Some("main-project".to_string()),
        saved_session_id: Some(uuid::Uuid::new_v4()),
        saved_session_short_id: Some("main01".to_string()),
        saved_current_session_persisted: true,
    }
}

#[tokio::test]
async fn swap_below_threshold_shows_no_spinner() {
    let started_at = Instant::now();
    let app = app_with_only_session_switch_pending(started_at);

    assert!(!app.async_action_animation_active(started_at + SESSION_SWITCH_SPINNER_THRESHOLD / 2));
}

#[tokio::test]
async fn swap_above_threshold_shows_spinner() {
    let started_at = Instant::now();
    let app = app_with_only_session_switch_pending(started_at);

    assert!(app.async_action_animation_active(
        started_at + SESSION_SWITCH_SPINNER_THRESHOLD + Duration::from_millis(1)
    ));
}

#[tokio::test]
async fn new_session_swap_failure_preserves_old_state_and_exact_staged_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (runner, mut input_rx, mut control_rx) = runner_with_input(1);
    let old_session_id = runner.session_id();
    app.agent_runner = Some(Ok(runner));
    app.history.push(HistoryEntry::Plain {
        line: "old transcript".to_string(),
    });
    app.queue
        .push(crate::tui::app::input::optimistic_queue_item(
            "old queued message".to_string(),
        ));
    app.busy = true;
    app.current_session_persisted = true;
    app.project_id = Some("old-project".to_string());
    app.side_conversation = Some(side_conversation(tmp.path()));
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move { Err("attach failed".to_string()) },
    );
    app.begin_session_switch_submission_target(SessionTarget::New);
    let first = complete_submission(7);
    let second = complete_submission(8);
    let expected = [&first, &second]
        .into_iter()
        .map(|submission| serde_json::to_value(submission).unwrap())
        .collect::<Vec<_>>();
    app.queue_pending_session_switch_submission(first, "engine", 0, false);
    app.queue_pending_session_switch_submission(second, "engine", 0, false);
    drain_session_switch_until_complete(&mut app).await;

    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
    }));
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line == "/new: attach failed")
    }));
    let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(runner.session_id(), old_session_id);
    assert!(
        app.busy,
        "the old turn is not interrupted on attach failure"
    );
    assert!(
        control_rx.try_recv().is_err(),
        "a failed replacement Attach must not cancel the outgoing turn"
    );
    assert!(app.current_session_persisted);
    assert_eq!(app.project_id.as_deref(), Some("old-project"));
    assert!(app.side_conversation.is_some());
    assert_eq!(app.queue.len(), 1);
    assert!(
        input_rx.try_recv().is_err(),
        "failed /new must not release new-session payloads to the old attachment"
    );
    assert!(app.pending_session_switch_submissions.is_empty());
    assert_eq!(app.retained_session_switch_submissions.len(), 1);
    assert_eq!(
        app.retained_session_switch_submissions[0].target,
        Some(SessionTarget::New)
    );
    assert_eq!(
        app.retained_session_switch_submissions[0]
            .submissions
            .iter()
            .map(|pending| serde_json::to_value(&pending.submission).unwrap())
            .collect::<Vec<_>>(),
        expected,
        "attach failure retains both exact payloads in FIFO order"
    );

    let retry_session_id = uuid::Uuid::new_v4();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move { Ok(switch_outcome(retry_session_id, "retry")) },
    );
    app.begin_session_switch_submission_target(SessionTarget::New);
    assert!(app.retained_session_switch_submissions.is_empty());
    drain_session_switch_until_complete(&mut app).await;

    let RunnerInput::SubmissionBatch(delivered) =
        input_rx.try_recv().expect("retained retry batch delivered")
    else {
        panic!("two retained payloads should transfer as one FIFO batch");
    };
    assert!(
        delivered
            .iter()
            .all(|bound| bound.intended_session_id == retry_session_id)
    );
    assert_eq!(
        delivered
            .into_iter()
            .map(|bound| serde_json::to_value(bound.submission).unwrap())
            .collect::<Vec<_>>(),
        expected
    );
}

#[tokio::test]
async fn new_session_swap_draws_before_swap_completes() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.history.push(HistoryEntry::Plain {
        line: "old transcript remains visible".to_string(),
    });
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

    terminal.draw(|frame| app.render(frame)).unwrap();

    assert_eq!(app.async_actions.pending_count(), 1);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript remains visible")
    }));
}

#[tokio::test]
async fn new_session_swap_success_commits_reset_and_keeps_new_optimistic_message() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (runner, mut input_rx, _control_rx) = runner_with_input(1);
    app.agent_runner = Some(Ok(runner));
    app.history.push(HistoryEntry::Plain {
        line: "old transcript".to_string(),
    });
    app.project_id = Some("old-project".to_string());
    app.current_session_persisted = true;
    app.side_conversation = Some(side_conversation(tmp.path()));
    let new_session_id = uuid::Uuid::new_v4();
    let (finish_tx, finish_rx) = oneshot::channel();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move {
            finish_rx.await.expect("finish successful attach");
            Ok(switch_outcome(new_session_id, "new123"))
        },
    );
    let exact = complete_submission(9);
    let expected = serde_json::to_value(&exact).unwrap();
    let tags = exact.tag_expansions.clone();
    app.dispatch_optimistic_user_submission(
        "new visible message".to_string(),
        exact,
        "engine",
        true,
        &tags,
    );

    finish_tx.send(()).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
    }));
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::User { text, .. } if text == "new visible message")
    }));
    assert_eq!(app.launch.session_id, Some(new_session_id));
    assert_eq!(app.project_id.as_deref(), Some("project-new123"));
    assert!(app.side_conversation.is_none());
    assert!(
        app.busy,
        "the released new-session message owns a working span"
    );
    assert!(app.new_session_terminal_clear_pending);
    let RunnerInput::Submission(delivered) = input_rx.try_recv().expect("new message released")
    else {
        panic!("one staged payload should use the single-submission input");
    };
    assert_eq!(delivered.intended_session_id, new_session_id);
    assert_eq!(
        serde_json::to_value(&delivered.submission).unwrap(),
        expected
    );
}

#[tokio::test]
async fn new_session_swap_replays_each_identical_optimistic_row_by_submission_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (runner, mut input_rx, _control_rx) = runner_with_input(2);
    app.agent_runner = Some(Ok(runner));
    app.history.push(HistoryEntry::Plain {
        line: "outgoing transcript".to_string(),
    });
    let new_session_id = uuid::Uuid::new_v4();
    let (finish_tx, finish_rx) = oneshot::channel();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move {
            finish_rx.await.expect("finish successful attach");
            Ok(switch_outcome(new_session_id, "identity"))
        },
    );

    let mut first = complete_submission(31);
    first.display_text = Some("same visible text".to_string());
    first.tag_expansions[0].detail = "first exact expansion".to_string();
    let mut second = complete_submission(32);
    second.display_text = Some("same visible text".to_string());
    second.tag_expansions[0].detail = "second exact expansion".to_string();
    let expected = [first.clone(), second.clone()]
        .into_iter()
        .map(|submission| serde_json::to_value(submission).unwrap())
        .collect::<Vec<_>>();
    let first_tags = first.tag_expansions.clone();
    let second_tags = second.tag_expansions.clone();
    app.dispatch_optimistic_user_submission(
        "same visible text".to_string(),
        first,
        "engine",
        true,
        &first_tags,
    );
    app.dispatch_optimistic_user_submission(
        "same visible text".to_string(),
        second,
        "engine",
        false,
        &second_tags,
    );

    let staged_ids = app
        .pending_session_switch_submissions
        .iter()
        .map(|pending| pending.optimistic_submission_id)
        .collect::<Vec<_>>();
    assert_eq!(staged_ids.len(), 2);
    assert_ne!(staged_ids[0], staged_ids[1]);
    assert!(
        app.pending_session_switch_submissions
            .iter()
            .all(|pending| {
                matches!(
                    pending.optimistic_history.first(),
                    Some(HistoryEntry::User {
                        optimistic_submission_id: Some(id),
                        ..
                    }) if *id == pending.optimistic_submission_id
                )
            })
    );

    finish_tx.send(()).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    let rows = app
        .history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::User {
                text,
                optimistic_submission_id,
                ..
            } => Some((text.as_str(), *optimistic_submission_id)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![
            ("same visible text", Some(staged_ids[0])),
            ("same visible text", Some(staged_ids[1])),
        ],
        "transactional reset replays A then B, never A then A"
    );
    let tag_lines = app
        .history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Plain { line } if line.contains("exact expansion") => Some(line.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(tag_lines.len(), 2);
    assert!(tag_lines[0].contains("first exact expansion"));
    assert!(tag_lines[1].contains("second exact expansion"));

    let RunnerInput::SubmissionBatch(delivered) =
        input_rx.try_recv().expect("identity-preserving batch")
    else {
        panic!("two staged submissions must transfer as one batch");
    };
    assert_eq!(
        delivered
            .iter()
            .map(|bound| bound.optimistic_submission_id)
            .collect::<Vec<_>>(),
        staged_ids
    );
    assert_eq!(
        delivered
            .into_iter()
            .map(|bound| serde_json::to_value(bound.submission).unwrap())
            .collect::<Vec<_>>(),
        expected
    );
}

#[tokio::test]
async fn new_session_normal_fresh_a_then_busy_b_preserves_distinct_optimistic_surfaces() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    super::seed_ready_model_for_tests(&mut app);
    let (runner, mut input_rx, _control_rx) = runner_with_input(2);
    app.agent_runner = Some(Ok(runner));
    app.history.push(HistoryEntry::Plain {
        line: "outgoing transcript".to_string(),
    });
    let new_session_id = uuid::Uuid::new_v4();
    let (finish_tx, finish_rx) = oneshot::channel();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move {
            finish_rx.await.expect("finish successful attach");
            Ok(switch_outcome(new_session_id, "normal-ab"))
        },
    );

    app.composer.set("identical visible text".to_string());
    assert!(!app.submit_input());
    assert!(app.busy, "fresh A owns the working span");
    app.composer.set("identical visible text".to_string());
    assert!(!app.submit_input());

    assert_eq!(app.pending_session_switch_submissions.len(), 2);
    let staged_ids = app
        .pending_session_switch_submissions
        .iter()
        .map(|pending| pending.optimistic_submission_id)
        .collect::<Vec<_>>();
    assert_ne!(staged_ids[0], staged_ids[1]);
    assert_eq!(
        app.pending_session_switch_submissions[0]
            .optimistic_history
            .len(),
        1,
        "fresh A owns one optimistic history row"
    );
    assert!(
        app.pending_session_switch_submissions[0]
            .optimistic_queue_item
            .is_none()
    );
    assert!(
        app.pending_session_switch_submissions[1]
            .optimistic_history
            .is_empty(),
        "busy B must never capture A's last unstamped history row"
    );
    let queued_b = app.pending_session_switch_submissions[1]
        .optimistic_queue_item
        .clone()
        .expect("busy B owns exact optimistic queue row");
    assert_eq!(queued_b.id, staged_ids[1]);
    let expected_payloads = app
        .pending_session_switch_submissions
        .iter()
        .map(|pending| serde_json::to_value(&pending.submission).unwrap())
        .collect::<Vec<_>>();

    finish_tx.send(()).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    assert_eq!(
        app.history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User {
                    text,
                    optimistic_submission_id,
                    ..
                } => Some((text.as_str(), *optimistic_submission_id)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![("identical visible text", Some(staged_ids[0]))],
        "successful reset replays A exactly once and never clones it for B"
    );
    assert_eq!(app.queue.len(), 1);
    assert_eq!(app.queue[0].id, queued_b.id);
    assert_eq!(app.queue[0].text, queued_b.text);

    let RunnerInput::SubmissionBatch(delivered) =
        input_rx.try_recv().expect("normal A/B staged batch")
    else {
        panic!("two normal staged submissions transfer as one FIFO batch");
    };
    assert_eq!(
        delivered
            .iter()
            .map(|bound| bound.optimistic_submission_id)
            .collect::<Vec<_>>(),
        staged_ids
    );
    assert_eq!(
        delivered
            .into_iter()
            .map(|bound| serde_json::to_value(bound.submission).unwrap())
            .collect::<Vec<_>>(),
        expected_payloads,
        "every exact wire field remains FIFO-aligned with its optimistic UUID"
    );
}

#[tokio::test]
async fn new_session_swap_transfers_sixty_four_complete_submissions_in_order() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (runner, mut input_rx, _control_rx) = runner_with_input(1);
    app.agent_runner = Some(Ok(runner));
    let expected = (0..64)
        .map(complete_submission)
        .map(|submission| serde_json::to_value(submission).unwrap())
        .collect::<Vec<_>>();
    for index in 0..64 {
        app.queue_pending_session_switch_submission(complete_submission(index), "engine", 0, false);
    }
    let new_session_id = uuid::Uuid::new_v4();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move { Ok(switch_outcome(new_session_id, "batch64")) },
    );

    drain_async_actions_until_idle(&mut app).await;

    let RunnerInput::SubmissionBatch(delivered) =
        input_rx.try_recv().expect("one dispatcher-owned batch")
    else {
        panic!("64 staged submissions must transfer as one batch");
    };
    assert_eq!(delivered.len(), 64);
    assert!(
        delivered
            .iter()
            .all(|bound| bound.intended_session_id == new_session_id)
    );
    let delivered = delivered
        .into_iter()
        .map(|bound| serde_json::to_value(bound.submission).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(delivered, expected);
    assert!(app.pending_session_switch_submissions.is_empty());
}

#[tokio::test]
async fn new_session_swap_keeps_in_flight_switch_non_replaceable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let first = uuid::Uuid::new_v4();
    let (finish_first_tx, finish_first_rx) = oneshot::channel();

    let first_action = app
        .async_actions
        .start(
            AsyncActionKind::Internal("session.switch"),
            App::session_switch_action_policy(),
            async move {
                finish_first_rx.await.expect("finish first switch");
                Ok(switch_outcome(first, "first"))
            },
        )
        .id();
    let replacement_ran = Arc::new(AtomicBool::new(false));
    let replacement_ran_in_task = Arc::clone(&replacement_ran);
    let second_action = app
        .async_actions
        .start(
            AsyncActionKind::Internal("session.resume"),
            App::session_switch_action_policy(),
            async move {
                replacement_ran_in_task.store(true, Ordering::Release);
                Err("replacement attach failed".to_string())
            },
        )
        .id();

    assert_eq!(first_action, second_action);
    finish_first_tx.send(()).expect("first switch alive");
    drain_async_actions_until_idle(&mut app).await;

    assert!(!replacement_ran.load(Ordering::Acquire));
    assert_eq!(app.launch.session_id, Some(first));
    assert_eq!(app.launch.session_short_id.as_deref(), Some("first"));
}
