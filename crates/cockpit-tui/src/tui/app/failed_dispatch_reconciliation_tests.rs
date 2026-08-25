use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratatui::layout::Rect;
use tokio::sync::{mpsc, oneshot};

use super::{App, DispatchOutcome, EphemeralSessionSwitchIntent, SideConversation};
use crate::tui::agent_runner::{
    AgentRunner, ClientTasks, ControlRequest, RunnerInput, SessionSwitchOutcome, SessionTarget,
    UsageCounts,
};
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::history::HistoryEntry;
use cockpit_core::engine::message::UserSubmission;

fn runner_with_sender(
    input_tx: mpsc::Sender<RunnerInput>,
    events: Arc<Mutex<Vec<crate::tui::agent_runner::QueuedTurnEvent>>>,
) -> AgentRunner {
    let (record_tx, _record_rx) = mpsc::channel(1);
    runner_with_channels(input_tx, record_tx, events)
}

fn runner_with_channels(
    input_tx: mpsc::Sender<RunnerInput>,
    record_tx: mpsc::Sender<cockpit_core::daemon::proto::Request>,
    events: Arc<Mutex<Vec<crate::tui::agent_runner::QueuedTurnEvent>>>,
) -> AgentRunner {
    let (control_tx, _control_rx) = mpsc::channel(1);
    runner_with_all_channels(input_tx, record_tx, control_tx, events)
}

fn runner_with_all_channels(
    input_tx: mpsc::Sender<RunnerInput>,
    record_tx: mpsc::Sender<cockpit_core::daemon::proto::Request>,
    control_tx: mpsc::Sender<ControlRequest>,
    events: Arc<Mutex<Vec<crate::tui::agent_runner::QueuedTurnEvent>>>,
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
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: None,
        session_id_state: Arc::new(Mutex::new(uuid::Uuid::new_v4())),
        attachment_epoch: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        submission_session_tx: tokio::sync::watch::channel(
            crate::tui::agent_runner::SubmissionSessionBinding::unbound(),
        )
        .0,
        awaiting_durable: Default::default(),
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
        current_client: None,
        attach_context: None,
        last_applied_seq: Some(Arc::new(Mutex::new(Some(0)))),
        client_tasks: ClientTasks::default(),
        #[cfg(test)]
        test_session_switch_rx: Arc::new(Mutex::new(None)),
        #[cfg(test)]
        test_force_can_switch: false,
        test_advance_epoch_when_switch_task_created: false,
    }
}

fn switch_outcome(session_id: uuid::Uuid) -> AsyncActionPayload {
    switch_outcome_with_epoch(session_id, 0)
}

fn switch_outcome_with_epoch(session_id: uuid::Uuid, attachment_epoch: u64) -> AsyncActionPayload {
    AsyncActionPayload::SessionSwitched(Box::new(SessionSwitchOutcome {
        target: SessionTarget::New,
        session_id,
        short_id: "fresh1".to_string(),
        active_agent: "Build".to_string(),
        active_agent_path: vec!["Build".to_string()],
        last_applied_seq: None,
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: None,
        project_id: "project".to_string(),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        attachment_epoch,
        transition_guard: None,
    }))
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
        attempt_id: None,
        seq: None,
        strip_think: true,
        response_performance: None,
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
        }]
        .into(),
        saved_history_render_versions: std::collections::HashMap::new(),
        saved_history_render_fingerprints: std::collections::HashMap::new(),
        saved_history_render_cache: std::collections::HashMap::new(),
        saved_history_render_cache_rows: 0,
        saved_queue: vec![crate::tui::app::input::optimistic_queue_item(
            "queued main message".to_string(),
        )],
        saved_pending: None,
        saved_active_display_attempt_id: None,
        saved_prunable_tokens: 42,
        saved_cache_cold: false,
        saved_elided_event_ids: std::collections::HashSet::from(["event-1".to_string()]),
        saved_active_schedules: std::collections::BTreeMap::new(),
        saved_pending_stop_confirm: Some(vec!["stop-me".to_string()]),
        saved_chat_scroll_offset: 7,
        saved_chat_scroll_anchor: None,
        saved_chat_pinned_to_tail: false,
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
        .push(cockpit_core::daemon::proto::Request::CancelTurn);
    app.last_usage = Some(cockpit_core::tokens::TokenUsage {
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
    super::seed_ready_model_for_tests(&mut app);
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

fn assert_busy_submit_failure_removes_only_new_optimistic_queue_item(
    mut app: App,
    existing_id: uuid::Uuid,
) {
    super::seed_ready_model_for_tests(&mut app);
    app.busy = true;
    let mut existing = crate::tui::app::input::optimistic_queue_item("same text".to_string());
    existing.id = existing_id;
    app.queue.push(existing);
    app.composer.set("same text".to_string());

    assert!(!app.submit_input());

    assert_eq!(
        app.queue.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![existing_id],
        "the failed submit removes its UUID and cannot remove an identical older row"
    );
    assert!(app.history.iter().any(|entry| {
        matches!(
            entry,
            HistoryEntry::InferenceError { summary, .. }
                if summary == "engine: queued message could not be sent"
        )
    }));
}

#[test]
fn busy_queue_full_removes_exact_optimistic_queue_item() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, _input_rx) = mpsc::channel(1);
    input_tx
        .try_send(UserSubmission::text("occupies bounded slot".to_string()).into())
        .unwrap();
    app.agent_runner = Some(Ok(runner_with_sender(
        input_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    assert_busy_submit_failure_removes_only_new_optimistic_queue_item(app, uuid::Uuid::new_v4());
}

#[test]
fn busy_closed_runner_removes_exact_optimistic_queue_item() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, input_rx) = mpsc::channel(1);
    drop(input_rx);
    app.agent_runner = Some(Ok(runner_with_sender(
        input_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    assert_busy_submit_failure_removes_only_new_optimistic_queue_item(app, uuid::Uuid::new_v4());
}

#[test]
fn busy_failed_runner_removes_exact_optimistic_queue_item() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.agent_runner = Some(Err("runner unavailable".to_string()));

    assert_busy_submit_failure_removes_only_new_optimistic_queue_item(app, uuid::Uuid::new_v4());
}

#[test]
fn transition_failure_removes_identical_queue_rows_by_uuid_not_text() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let mut unrelated = crate::tui::app::input::optimistic_queue_item("same text".to_string());
    unrelated.id = uuid::Uuid::new_v4();
    app.queue.push(unrelated.clone());

    let mut expected_payloads = Vec::new();
    for marker in ["first", "second"] {
        let mut item = crate::tui::app::input::optimistic_queue_item("same text".to_string());
        item.id = uuid::Uuid::new_v4();
        app.queue.push(item.clone());
        let mut submission = UserSubmission::text(format!("wire-{marker}"));
        submission.display_text = Some("same text".to_string());
        submission.images = vec![cockpit_core::engine::message::SubmissionImage::png(
            marker.as_bytes().to_vec(),
        )];
        submission.forced_skill = Some(marker.to_string());
        expected_payloads.push(serde_json::to_value(&submission).unwrap());
        app.queue_pending_session_switch_submission_with_optimistic_state(
            submission,
            "engine",
            false,
            super::OptimisticSubmissionState {
                id: item.id,
                tag_entries: 0,
                history: Vec::new(),
                queue_item: Some(item),
            },
        );
    }
    assert_eq!(
        app.pending_session_switch_submissions
            .iter()
            .map(|pending| serde_json::to_value(&pending.submission).unwrap())
            .collect::<Vec<_>>(),
        expected_payloads,
        "staging preserves every field before terminal reconciliation"
    );

    app.fail_pending_session_switch_submissions();

    assert_eq!(
        app.queue.iter().map(|item| item.id).collect::<Vec<_>>(),
        vec![unrelated.id],
        "failure keeps an unrelated identical-text row and removes only staged UUIDs"
    );
}

#[test]
fn async_dispatch_failure_reconciles_exact_row_before_next_record_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, mut input_rx) = mpsc::channel(2);
    app.agent_runner = Some(Ok(runner_with_sender(
        input_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));
    let mut first = UserSubmission::text("wire-a".to_string());
    first.display_text = Some("same visible text".to_string());
    first.images = vec![cockpit_core::engine::message::SubmissionImage::png(vec![
        1, 2, 3,
    ])];
    first.forced_skill = Some("review".to_string());
    let mut second = UserSubmission::text("wire-b".to_string());
    second.display_text = Some("same visible text".to_string());
    second.images = vec![cockpit_core::engine::message::SubmissionImage::png(vec![
        4, 5, 6,
    ])];
    second.forced_skill = Some("build".to_string());
    let expected_first = serde_json::to_value(&first).unwrap();
    let expected_second = serde_json::to_value(&second).unwrap();

    app.dispatch_optimistic_user_submission(
        "same visible text".to_string(),
        first,
        "engine",
        true,
        &[],
    );
    app.dispatch_optimistic_user_submission(
        "same visible text".to_string(),
        second,
        "engine",
        false,
        &[],
    );
    let RunnerInput::Submission(first) = input_rx.try_recv().expect("first exact payload") else {
        panic!("expected first submission");
    };
    let RunnerInput::Submission(second) = input_rx.try_recv().expect("second exact payload") else {
        panic!("expected second submission");
    };
    assert_eq!(
        serde_json::to_value(&first.submission).unwrap(),
        expected_first
    );
    assert_eq!(
        serde_json::to_value(&second.submission).unwrap(),
        expected_second
    );
    assert_ne!(
        first.optimistic_submission_id,
        second.optimistic_submission_id
    );

    app.apply_event(cockpit_core::engine::TurnEvent::UserMessageDispatchFailed {
        error: "image upload rejected".to_string(),
        optimistic_submission_id: first.optimistic_submission_id,
    });
    app.apply_event(cockpit_core::engine::TurnEvent::UserMessageRecorded {
        seq: 91,
        client_submission_ids: vec![second.optimistic_submission_id],
        preflight_cleaned: None,
    });

    let rows = app
        .history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::User {
                seq,
                optimistic_submission_id,
                persist_failed,
                ..
            } => Some((*seq, *optimistic_submission_id, *persist_failed)),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        rows,
        vec![
            (None, Some(first.optimistic_submission_id), true),
            (Some(91), None, false),
        ]
    );
}

#[test]
fn fresh_a_failure_then_busy_b_fold_reconciles_history_queue_and_duplicate_record() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    super::seed_ready_model_for_tests(&mut app);
    let (input_tx, mut input_rx) = mpsc::channel(2);
    app.agent_runner = Some(Ok(runner_with_sender(
        input_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    app.composer.set("same visible text".to_string());
    assert!(!app.submit_input());
    assert!(app.busy, "A starts the live working span");
    app.composer.set("same visible text".to_string());
    assert!(!app.submit_input());
    assert_eq!(app.queue.len(), 1, "busy B is optimistic queue chrome");

    let RunnerInput::Submission(first) = input_rx.try_recv().expect("fresh A payload") else {
        panic!("expected A submission");
    };
    let RunnerInput::Submission(second) = input_rx.try_recv().expect("busy B payload") else {
        panic!("expected B submission");
    };
    let queued_b_id = second.optimistic_submission_id;
    assert_eq!(app.queue[0].id, queued_b_id);
    assert_ne!(first.optimistic_submission_id, queued_b_id);
    assert_eq!(first.submission.text, "same visible text");
    assert_eq!(second.submission.text, "same visible text");

    app.apply_event(cockpit_core::engine::TurnEvent::UserMessageDispatchFailed {
        error: "upload failed".to_string(),
        optimistic_submission_id: first.optimistic_submission_id,
    });
    app.apply_event(cockpit_core::engine::TurnEvent::QueuedUserMessagesFolded {
        text: second.submission.text.clone(),
        display_text: second.submission.display_text.clone(),
        tag_expansions: second.submission.tag_expansions.clone(),
        queue_item_ids: vec![queued_b_id],
        target: cockpit_core::engine::message::QueueTarget::root("Build"),
        seq: Some(92),
        preflight_cleaned: None,
    });
    app.apply_event(cockpit_core::engine::TurnEvent::UserMessageRecorded {
        seq: 92,
        client_submission_ids: vec![queued_b_id],
        preflight_cleaned: None,
    });

    assert!(app.queue.is_empty());
    assert_eq!(
        app.history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User {
                    text,
                    seq,
                    persist_failed,
                    ..
                } => Some((text.as_str(), *seq, *persist_failed)),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![
            ("same visible text", None, true),
            ("same visible text", Some(92), false),
        ],
        "A remains failed and unstamped while folded B is created exactly once"
    );
}

#[test]
fn async_busy_b_failure_removes_only_b_and_keeps_fresh_a_working() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    super::seed_ready_model_for_tests(&mut app);
    let (input_tx, mut input_rx) = mpsc::channel(2);
    app.agent_runner = Some(Ok(runner_with_sender(
        input_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    app.composer.set("fresh A".to_string());
    assert!(!app.submit_input());
    app.composer.set("busy B".to_string());
    assert!(!app.submit_input());
    let RunnerInput::Submission(first) = input_rx.try_recv().expect("fresh A payload") else {
        panic!("expected A submission");
    };
    let RunnerInput::Submission(second) = input_rx.try_recv().expect("busy B payload") else {
        panic!("expected B submission");
    };
    assert!(app.busy);
    assert_eq!(app.queue[0].id, second.optimistic_submission_id);

    app.apply_event(cockpit_core::engine::TurnEvent::UserMessageDispatchFailed {
        error: "busy upload failed".to_string(),
        optimistic_submission_id: second.optimistic_submission_id,
    });

    assert!(app.busy, "B did not own A's working span");
    assert!(
        app.queue.is_empty(),
        "only B's optimistic queue row is removed"
    );
    assert!(matches!(
        app.history.iter().find(|entry| matches!(entry, HistoryEntry::User { .. })),
        Some(HistoryEntry::User {
            text,
            optimistic_submission_id: Some(id),
            persist_failed: false,
            ..
        }) if text == "fresh A" && *id == first.optimistic_submission_id
    ));
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
    let folded_id = uuid::Uuid::new_v4();
    app.folded_queue_item_ids.insert(folded_id);
    app.folded_queue_item_order.push_back(folded_id);
    app.retained_user_submission_ids.insert(folded_id);

    app.reset_session_live_state();

    assert!(app.queue.is_empty());
    assert!(app.folded_queue_item_ids.is_empty());
    assert!(app.folded_queue_item_order.is_empty());
    assert!(app.retained_user_submission_ids.is_empty());
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
        Ok(cockpit_core::daemon::proto::Request::CancelTurn)
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
        Ok(cockpit_core::daemon::proto::Request::CancelTurn)
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

#[test]
fn paste_fence_session_switch_ordering_bounds_unconfirmed_and_recovers_after_link_loss() {
    use crate::tui::structured_paste::{
        CapturedModel, FenceLifecycle, HostIdentity, OrderedIntent, SubmissionFenceV1,
    };

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let session_id = uuid::Uuid::new_v4();
    let host = HostIdentity {
        client_instance_id: app.paste_client_instance_id,
        connection_epoch: 1,
        session_id,
        terminal_generation: 1,
    };
    let sent_id = uuid::Uuid::new_v4();
    let sent_sequence = app
        .submission_order
        .enqueue(OrderedIntent::Fence(sent_id))
        .unwrap();
    assert!(app.submission_order.complete(sent_sequence));
    let ready_id = uuid::Uuid::new_v4();
    let ready_sequence = app
        .submission_order
        .enqueue(OrderedIntent::Fence(ready_id))
        .unwrap();
    let fence = |id, sequence, lifecycle, digest| SubmissionFenceV1 {
        client_submission_id: id,
        fence_sequence: sequence,
        host,
        view_generation: 1,
        source_draft_generation: 1,
        created_at: std::time::Duration::ZERO,
        captured_composer: format!("message-{id}"),
        accepted_tags: Vec::new(),
        pending_git_blocks: Vec::new(),
        model: CapturedModel {
            provider_id: "p".into(),
            model_id: "m".into(),
            active_model_state_generation: 1,
            image_capability_generation: 1,
            supports_images: false,
        },
        assembled_wire_digest: digest,
        slots: Vec::new(),
        lifecycle,
    };
    app.submission_fences.insert(
        sent_id,
        fence(
            sent_id,
            sent_sequence,
            FenceLifecycle::PossiblySent,
            Some([7; 32]),
        ),
    );
    app.submission_fences.insert(
        ready_id,
        fence(ready_id, ready_sequence, FenceLifecycle::Ready, None),
    );

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert!(app.submission_fences.contains_key(&ready_id));
    assert_eq!(
        app.submission_fences[&sent_id].lifecycle,
        FenceLifecycle::Reconciling
    );
    assert!(app.delivery_unconfirmed_records.contains_key(&sent_id));

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert!(!app.submission_fences.contains_key(&ready_id));
    assert!(app.delivery_unconfirmed_records[&sent_id].surfaced);
    assert!(app.history.iter().any(|entry| matches!(
        entry,
        HistoryEntry::CommandError { line } if line.contains("Delivery unconfirmed")
    )));
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

#[tokio::test]
async fn pending_resume_rejects_created_side_without_mutating_main_view() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, _input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::channel(1);
    let runner = runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    );
    let parent_session_id = runner.session_id();
    app.agent_runner = Some(Ok(runner));
    app.current_session_persisted = true;
    app.project_id = Some("main-project".to_string());
    app.history.push(HistoryEntry::Plain {
        line: "main remains visible".to_string(),
    });
    app.queue
        .push(crate::tui::app::input::optimistic_queue_item(
            "main queued message".to_string(),
        ));
    app.async_actions.start(
        AsyncActionKind::Internal("session.resume"),
        App::session_switch_action_policy(),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );

    app.apply_side_created(
        parent_session_id,
        tmp.path().join("missing-daemon.sock"),
        uuid::Uuid::new_v4(),
        "side123".to_string(),
    );

    assert!(app.side_conversation.is_none());
    assert!(app.current_session_persisted);
    assert_eq!(app.project_id.as_deref(), Some("main-project"));
    assert_eq!(app.queue.len(), 1);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "main remains visible")
    }));
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line.contains("another session change is still finishing"))
    }));
    let kinds = app.async_actions.pending_kinds();
    assert!(kinds.contains(&AsyncActionKind::Internal("session.resume")));
    assert!(
        kinds.contains(&AsyncActionKind::DaemonRpc("side.discard")),
        "the already-created ephemeral fork must be scheduled for cleanup"
    );
}

#[tokio::test]
async fn pending_resume_discards_created_fork_instead_of_reusing_existing_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, _input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::channel(1);
    let runner = runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    );
    let parent_session_id = runner.session_id();
    app.agent_runner = Some(Ok(runner));
    app.current_session_persisted = true;
    app.async_actions.start(
        AsyncActionKind::Internal("session.resume"),
        App::session_switch_action_policy(),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );

    app.apply_fork_created(
        parent_session_id,
        tmp.path().join("missing-daemon.sock"),
        uuid::Uuid::new_v4(),
        "fork123".to_string(),
        None,
        Some("exact composer seed".to_string()),
    );

    let kinds = app.async_actions.pending_kinds();
    assert!(kinds.contains(&AsyncActionKind::Internal("session.resume")));
    assert!(!kinds.contains(&AsyncActionKind::Internal("session.fork")));
    assert!(kinds.contains(&AsyncActionKind::DaemonRpc("side.discard")));
}

#[tokio::test]
async fn pending_switch_rejects_new_before_any_destructive_pre_effects() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let mut control_rx = seed_new_session_reset_state(&mut app);
    app.async_actions.start(
        AsyncActionKind::Internal("session.resume"),
        App::session_switch_action_policy(),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    let queue_len = app.queue.len();
    let mut clear_called = false;

    let changed = app
        .maybe_service_new_session_with_clear(|| {
            clear_called = true;
            Ok(())
        })
        .unwrap();

    assert!(changed);
    assert!(!clear_called);
    assert!(!app.pending_new_session);
    assert!(app.busy, "the outgoing turn must not be interrupted");
    assert!(app.agent_runner.is_some());
    assert!(app.current_session_persisted);
    assert_eq!(app.queue.len(), queue_len);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
    }));
    assert!(control_rx.try_recv().is_err());
}

#[tokio::test]
async fn pending_switch_rejects_resume_without_discarding_active_side() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let mut control_rx = seed_new_session_reset_state(&mut app);
    app.pending_new_session = false;
    app.side_conversation = Some(fake_side_conversation(tmp.path()));
    app.history.push(HistoryEntry::Plain {
        line: "side remains visible".to_string(),
    });
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        App::session_switch_action_policy(),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    let queue_len = app.queue.len();

    app.resume_session(uuid::Uuid::new_v4());

    assert!(app.side_conversation.is_some());
    assert!(app.busy, "the outgoing turn must not be interrupted");
    assert_eq!(app.queue.len(), queue_len);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "side remains visible")
    }));
    assert!(control_rx.try_recv().is_err());
    assert_eq!(app.async_actions.pending_count(), 1);
}

#[tokio::test]
async fn pending_switch_rejects_side_return_without_restoring_or_discarding() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.side_conversation = Some(fake_side_conversation(tmp.path()));
    app.history.push(HistoryEntry::Plain {
        line: "side remains visible".to_string(),
    });
    app.async_actions.start(
        AsyncActionKind::Internal("session.resume"),
        App::session_switch_action_policy(),
        async move { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );

    app.end_side_conversation(true);

    assert!(app.side_conversation.is_some());
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "side remains visible")
    }));
    assert_eq!(app.async_actions.pending_count(), 1);
    assert!(
        !app.async_actions
            .pending_kinds()
            .contains(&AsyncActionKind::DaemonRpc("side.discard"))
    );
}

#[tokio::test]
async fn successful_side_return_commits_snapshot_restore_and_discard_after_result() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let side = fake_side_conversation(tmp.path());
    let side_session_id = side.side_session_id;
    let main_session_id = side.saved_session_id.expect("saved main session");
    let (input_tx, _input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::channel(1);
    let runner = runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    );
    *runner.session_id_state.lock().unwrap() = side_session_id;
    app.agent_runner = Some(Ok(runner));
    app.side_conversation = Some(side);
    app.history.clear();
    app.history.push(HistoryEntry::Plain {
        line: "side-only history".to_string(),
    });
    let outcome = SessionSwitchOutcome {
        target: SessionTarget::Resume {
            session_id: main_session_id,
            since_seq: None,
        },
        session_id: main_session_id,
        short_id: "main123".to_string(),
        active_agent: "Build".to_string(),
        active_agent_path: vec!["Build".to_string()],
        last_applied_seq: Some(0),
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: None,
        project_id: "project-main".to_string(),
        history: Vec::new(),
        paused_work: Vec::new(),
        repair_required: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        attachment_epoch: 0,
        transition_guard: None,
    };
    app.async_actions.start(
        AsyncActionKind::Internal("session.side.return"),
        App::session_switch_action_policy(),
        async move { Ok(AsyncActionPayload::SideSessionReturned(Box::new(outcome))) },
    );

    assert!(app.side_conversation.is_some());
    for _ in 0..20 {
        tokio::task::yield_now().await;
        app.drain_async_actions();
        if app.side_conversation.is_none() {
            break;
        }
    }

    assert!(app.side_conversation.is_none());
    let runner = app
        .agent_runner
        .as_ref()
        .and_then(|runner| runner.as_ref().ok())
        .expect("main runner remains live");
    assert_eq!(runner.session_id(), main_session_id);
    assert!(
        app.history.iter().any(|entry| {
            matches!(entry, HistoryEntry::Plain { line } if line == "main history")
        })
    );
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "side-only history")
    }));
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line.contains("back in the main session"))
    }));
    assert!(
        app.async_actions
            .pending_kinds()
            .contains(&AsyncActionKind::DaemonRpc("side.discard"))
    );
}

#[tokio::test]
async fn failed_side_return_preserves_side_runner_ui_and_exact_queued_submission() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let side = fake_side_conversation(tmp.path());
    let side_session_id = side.side_session_id;
    let main_session_id = side.saved_session_id.expect("saved main session");
    let (input_tx, mut input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::channel(1);
    let runner = runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    );
    *runner.session_id_state.lock().unwrap() = side_session_id;
    app.agent_runner = Some(Ok(runner));
    app.side_conversation = Some(side);
    app.history.clear();
    app.history.push(HistoryEntry::Plain {
        line: "side-only history".to_string(),
    });
    let exact_submission = UserSubmission {
        expected_model_state_generation: None,
        expected_model: None,
        kind: cockpit_core::engine::message::UserSubmissionKind::Compact,
        origin: Default::default(),
        text: "exact wire text".to_string(),
        display_text: Some("visible side draft".to_string()),
        tag_expansions: vec![cockpit_core::daemon::proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: "src/lib.rs".to_string(),
            detail: "expanded".to_string(),
            ok: true,
        }],
        images: vec![cockpit_core::engine::message::SubmissionImage::png(vec![
            1, 2, 3, 4,
        ])],
        forced_skill: Some("review".to_string()),
        origin_principal: Some("flycockpit:test-owner".to_string()),
        job_id: Some("side-job".to_string()),
        preflight_cleaned: Some("clean wire".to_string()),
        queue_item_ids: vec![uuid::Uuid::new_v4()],
        client_submissions: Vec::new(),
        pending_terminal_disposition: None,
        run_invocation_id: None,
        queue_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
    };
    let expected_submission = serde_json::to_value(&exact_submission).unwrap();
    app.async_actions.start(
        AsyncActionKind::Internal("session.side.return"),
        App::session_switch_action_policy(),
        async move { Err("attach rejected".to_string()) },
    );
    app.begin_session_switch_submission_target(SessionTarget::Resume {
        session_id: main_session_id,
        since_seq: None,
    });
    app.queue_pending_session_switch_submission(exact_submission, "side", 0, false);

    for _ in 0..20 {
        tokio::task::yield_now().await;
        app.drain_async_actions();
        if app.async_actions.pending_count() == 0 {
            break;
        }
    }

    assert!(app.side_conversation.is_some());
    let runner = app
        .agent_runner
        .as_ref()
        .and_then(|runner| runner.as_ref().ok())
        .expect("failed replacement keeps side runner live");
    assert_eq!(runner.session_id(), side_session_id);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "side-only history")
    }));
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line.contains("retry `/side end`"))
    }));
    assert!(
        !app.async_actions
            .pending_kinds()
            .contains(&AsyncActionKind::DaemonRpc("side.discard"))
    );
    assert!(
        input_rx.try_recv().is_err(),
        "failed return must not send main-session input to the side session"
    );
    assert_eq!(app.retained_session_switch_submissions.len(), 1);
    assert_eq!(
        app.retained_session_switch_submissions[0].target,
        Some(SessionTarget::Resume {
            session_id: main_session_id,
            since_seq: None,
        })
    );
    assert_eq!(
        serde_json::to_value(&app.retained_session_switch_submissions[0].submissions[0].submission)
            .unwrap(),
        expected_submission
    );
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

fn complete_dispatch_submission(marker: &str) -> UserSubmission {
    UserSubmission {
        expected_model_state_generation: None,
        expected_model: None,
        kind: cockpit_core::engine::message::UserSubmissionKind::Compact,
        origin: Default::default(),
        text: format!("wire-{marker}"),
        display_text: Some(format!("visible-{marker}")),
        tag_expansions: vec![cockpit_core::daemon::proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: format!("src/{marker}.rs"),
            detail: format!("expanded-{marker}"),
            ok: true,
        }],
        images: vec![
            cockpit_core::engine::message::SubmissionImage::png(marker.as_bytes().to_vec()),
            cockpit_core::engine::message::SubmissionImage::png(vec![0x89, b'P', b'N', b'G']),
        ],
        forced_skill: Some("review".to_string()),
        origin_principal: Some("flycockpit:test-owner".to_string()),
        job_id: Some(format!("job-{marker}")),
        preflight_cleaned: Some(format!("clean-{marker}")),
        queue_item_ids: vec![uuid::Uuid::new_v4(), uuid::Uuid::new_v4()],
        client_submissions: vec![cockpit_core::engine::message::ClientSubmissionReceipt {
            id: uuid::Uuid::new_v4(),
            fingerprint: format!("content-{marker}"),
            wire_fingerprint: format!("wire-fingerprint-{marker}"),
            origin_principal: Some("flycockpit:test-owner".to_string()),
        }],
        queue_target: Some(cockpit_core::engine::message::QueueTarget::child(
            "Build",
            1,
            "task-call",
            "reviewer",
        )),
        pending_terminal_disposition: None,
        run_invocation_id: None,
    }
}

#[tokio::test]
async fn failed_side_attach_rebinds_exact_fifo_to_next_side_and_discards_old_target() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (main_tx, mut main_rx) = mpsc::channel(4);
    let main_runner = runner_with_sender(main_tx, Arc::new(Mutex::new(Vec::new())));
    let main_session_id = uuid::Uuid::new_v4();
    *main_runner.session_id_state.lock().unwrap() = main_session_id;
    app.agent_runner = Some(Ok(main_runner));

    let discarded_side_session_id = uuid::Uuid::new_v4();
    let mut abandoned_side = fake_side_conversation(tmp.path());
    abandoned_side.side_session_id = discarded_side_session_id;
    abandoned_side.saved_session_id = Some(main_session_id);
    app.side_conversation = Some(abandoned_side);
    app.async_actions.start(
        AsyncActionKind::Internal("session.side"),
        App::session_switch_action_policy(),
        async move { Err("side attach rejected".to_string()) },
    );
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: discarded_side_session_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Side {
            parent_session_id: main_session_id,
        },
    );

    let first = complete_dispatch_submission("side-first");
    let second = complete_dispatch_submission("side-second");
    let expected = vec![
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap(),
    ];
    app.queue_pending_session_switch_submission(first, "side", 0, false);
    app.queue_pending_session_switch_submission(second, "side", 0, false);

    for _ in 0..20 {
        tokio::task::yield_now().await;
        app.drain_async_actions();
        if !app
            .async_actions
            .pending_kinds()
            .contains(&AsyncActionKind::Internal("session.side"))
        {
            break;
        }
    }

    assert!(
        main_rx.try_recv().is_err(),
        "side-bound input must never reach the restored main session"
    );
    assert!(app.side_conversation.is_none());
    assert!(
        app.async_actions
            .pending_kinds()
            .contains(&AsyncActionKind::DaemonRpc("side.discard")),
        "the unreachable ephemeral target must be abandoned deterministically"
    );
    assert_eq!(app.retained_session_switch_submissions.len(), 1);
    assert_eq!(
        app.retained_session_switch_submissions[0].target,
        Some(SessionTarget::Resume {
            session_id: discarded_side_session_id,
            since_seq: None,
        })
    );
    assert_eq!(
        app.retained_session_switch_submissions[0].retry_intent,
        Some(EphemeralSessionSwitchIntent::Side {
            parent_session_id: main_session_id,
        })
    );

    let unrelated_parent_session_id = uuid::Uuid::new_v4();
    let unrelated_side_session_id = uuid::Uuid::new_v4();
    let (unrelated_tx, mut unrelated_rx) = mpsc::channel(4);
    let unrelated_runner = runner_with_sender(unrelated_tx, Arc::new(Mutex::new(Vec::new())));
    *unrelated_runner.session_id_state.lock().unwrap() = unrelated_side_session_id;
    app.agent_runner = Some(Ok(unrelated_runner));
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: unrelated_side_session_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Side {
            parent_session_id: unrelated_parent_session_id,
        },
    );
    assert!(
        app.pending_session_switch_submissions.is_empty(),
        "a side retry from another parent must not reclaim the payload"
    );
    app.flush_pending_session_switch_submissions();
    assert!(unrelated_rx.try_recv().is_err());
    assert_eq!(app.retained_session_switch_submissions.len(), 1);

    let (retry_tx, mut retry_rx) = mpsc::channel(4);
    let retry_runner = runner_with_sender(retry_tx, Arc::new(Mutex::new(Vec::new())));
    let replacement_side_session_id = uuid::Uuid::new_v4();
    *retry_runner.session_id_state.lock().unwrap() = replacement_side_session_id;
    app.agent_runner = Some(Ok(retry_runner));
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: replacement_side_session_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Side {
            parent_session_id: main_session_id,
        },
    );
    assert_eq!(app.pending_session_switch_submissions.len(), 2);
    app.flush_pending_session_switch_submissions();

    let RunnerInput::SubmissionBatch(delivered) =
        retry_rx.try_recv().expect("retried side batch delivered")
    else {
        panic!("multiple retained submissions must remain one FIFO batch");
    };
    assert_eq!(delivered.len(), 2);
    assert!(
        delivered
            .iter()
            .all(|submission| { submission.intended_session_id == replacement_side_session_id })
    );
    assert_eq!(
        delivered
            .iter()
            .map(|submission| serde_json::to_value(&submission.submission).unwrap())
            .collect::<Vec<_>>(),
        expected,
        "every exact payload field and FIFO position must survive the failed side attach"
    );
    assert!(app.retained_session_switch_submissions.is_empty());
    assert!(app.pending_session_switch_submissions.is_empty());
    assert!(app.pending_session_switch_target.is_none());
    assert!(app.pending_ephemeral_session_switch_intent.is_none());
}

#[test]
fn failed_fork_retry_requires_same_parent_and_fork_point() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let parent_session_id = uuid::Uuid::new_v4();
    let discarded_fork_session_id = uuid::Uuid::new_v4();
    let fork_point_seq = 17;
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: discarded_fork_session_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Fork {
            parent_session_id,
            fork_point_seq: Some(fork_point_seq),
        },
    );
    let first = complete_dispatch_submission("fork-first");
    let second = complete_dispatch_submission("fork-second");
    let expected = vec![
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap(),
    ];
    app.queue_pending_session_switch_submission(first, "fork", 0, false);
    app.queue_pending_session_switch_submission(second, "fork", 0, false);
    app.fail_pending_session_switch_submissions();

    let (wrong_parent_tx, mut wrong_parent_rx) = mpsc::channel(4);
    let wrong_parent_runner = runner_with_sender(wrong_parent_tx, Arc::new(Mutex::new(Vec::new())));
    let wrong_parent_fork_id = uuid::Uuid::new_v4();
    *wrong_parent_runner.session_id_state.lock().unwrap() = wrong_parent_fork_id;
    app.agent_runner = Some(Ok(wrong_parent_runner));
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: wrong_parent_fork_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Fork {
            parent_session_id: uuid::Uuid::new_v4(),
            fork_point_seq: Some(fork_point_seq),
        },
    );
    assert!(app.pending_session_switch_submissions.is_empty());
    app.flush_pending_session_switch_submissions();
    assert!(wrong_parent_rx.try_recv().is_err());

    let (wrong_point_tx, mut wrong_point_rx) = mpsc::channel(4);
    let wrong_point_runner = runner_with_sender(wrong_point_tx, Arc::new(Mutex::new(Vec::new())));
    let wrong_point_fork_id = uuid::Uuid::new_v4();
    *wrong_point_runner.session_id_state.lock().unwrap() = wrong_point_fork_id;
    app.agent_runner = Some(Ok(wrong_point_runner));
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: wrong_point_fork_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Fork {
            parent_session_id,
            fork_point_seq: Some(fork_point_seq + 1),
        },
    );
    assert!(app.pending_session_switch_submissions.is_empty());
    app.flush_pending_session_switch_submissions();
    assert!(wrong_point_rx.try_recv().is_err());
    assert_eq!(app.retained_session_switch_submissions.len(), 1);

    let (retry_tx, mut retry_rx) = mpsc::channel(4);
    let retry_runner = runner_with_sender(retry_tx, Arc::new(Mutex::new(Vec::new())));
    let replacement_fork_session_id = uuid::Uuid::new_v4();
    *retry_runner.session_id_state.lock().unwrap() = replacement_fork_session_id;
    app.agent_runner = Some(Ok(retry_runner));
    app.begin_ephemeral_session_switch_submission_target(
        SessionTarget::Resume {
            session_id: replacement_fork_session_id,
            since_seq: None,
        },
        EphemeralSessionSwitchIntent::Fork {
            parent_session_id,
            fork_point_seq: Some(fork_point_seq),
        },
    );
    assert_eq!(app.pending_session_switch_submissions.len(), 2);
    app.flush_pending_session_switch_submissions();

    let RunnerInput::SubmissionBatch(delivered) =
        retry_rx.try_recv().expect("retried fork batch delivered")
    else {
        panic!("multiple retained fork submissions must remain one FIFO batch");
    };
    assert_eq!(delivered.len(), 2);
    assert!(
        delivered
            .iter()
            .all(|submission| { submission.intended_session_id == replacement_fork_session_id })
    );
    assert_eq!(
        delivered
            .iter()
            .map(|submission| serde_json::to_value(&submission.submission).unwrap())
            .collect::<Vec<_>>(),
        expected
    );
    assert!(app.retained_session_switch_submissions.is_empty());
}

#[test]
fn normal_dispatch_queue_full_retains_and_retries_complete_payload() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(UserSubmission::text("already queued".to_string()).into())
        .unwrap();
    let runner = runner_with_sender(tx, Arc::new(Mutex::new(Vec::new())));
    let session_id = runner.session_id();
    app.launch.session_id = Some(session_id);
    app.agent_runner = Some(Ok(runner));
    app.begin_working_span();
    let submission = complete_dispatch_submission("queue-full");
    let expected = serde_json::to_value(&submission).unwrap();

    let outcome = app.dispatch_optimistic_user_submission(
        "visible-queue-full".to_string(),
        submission,
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
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    assert_eq!(
        serde_json::to_value(&app.retained_pre_dispatch_submissions[0].pending.submission).unwrap(),
        expected,
        "bounded-channel rejection retains every submission field"
    );

    let _blocker = rx.try_recv().expect("free one input slot");
    assert!(app.retry_retained_pre_dispatch_submissions());
    assert!(app.retained_pre_dispatch_submissions.is_empty());
    let RunnerInput::Submission(delivered) = rx.try_recv().expect("exact retry delivered") else {
        panic!("one retry should use one submission input");
    };
    assert_eq!(delivered.intended_session_id, session_id);
    assert_eq!(
        serde_json::to_value(delivered.submission).unwrap(),
        expected
    );
    assert!(app.busy, "successful fresh retry re-arms its working span");
    assert!(!newest_user_failed(&app));
}

#[test]
fn normal_dispatch_closed_marks_user_failed_and_ends_span() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (tx, rx) = mpsc::channel(1);
    drop(rx);
    app.agent_runner = Some(Ok(runner_with_sender(tx, Arc::new(Mutex::new(Vec::new())))));
    app.begin_working_span();

    let submission = complete_dispatch_submission("closed");
    let expected = serde_json::to_value(&submission).unwrap();
    let outcome = app.dispatch_optimistic_user_submission(
        "visible-closed".to_string(),
        submission,
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
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    assert_eq!(
        serde_json::to_value(&app.retained_pre_dispatch_submissions[0].pending.submission).unwrap(),
        expected
    );
}

#[test]
fn busy_submit_queue_full_retries_consumed_wire_payload_exactly() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    super::seed_ready_model_for_tests(&mut app);
    let (tx, mut rx) = mpsc::channel(1);
    tx.try_send(UserSubmission::text("channel blocker".to_string()).into())
        .unwrap();
    let runner = runner_with_sender(tx, Arc::new(Mutex::new(Vec::new())));
    let session_id = runner.session_id();
    app.launch.session_id = Some(session_id);
    app.launch.active_model_supports_images = true;
    app.agent_runner = Some(Ok(runner));
    app.busy = true;

    let image = image::DynamicImage::ImageRgba8(image::RgbaImage::from_pixel(
        1,
        1,
        image::Rgba([7, 8, 9, 255]),
    ));
    let mut png = Vec::new();
    image
        .write_to(&mut std::io::Cursor::new(&mut png), image::ImageFormat::Png)
        .unwrap();
    let placeholder = app.paste_registry.register_image(0, png.clone());
    let display = format!("{placeholder} inspect the staged changes");
    app.composer.set(display.clone());
    app.pending_git_blocks
        .push("git diff --binary\nexact-busy-marker".to_string());

    assert!(!app.submit_input());
    assert!(
        app.composer.is_empty(),
        "normal submit consumed the composer"
    );
    assert!(app.pending_git_blocks.is_empty());
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    let retained = &app.retained_pre_dispatch_submissions[0].pending.submission;
    assert_eq!(retained.display_text.as_deref(), Some(display.as_str()));
    assert_eq!(
        retained.images,
        vec![cockpit_core::engine::message::SubmissionImage::png(png)]
    );
    assert!(
        retained
            .text
            .contains(cockpit_core::engine::message::IMAGE_PART_SENTINEL)
    );
    assert!(retained.text.contains("exact-busy-marker"));
    let expected = serde_json::to_value(retained).unwrap();

    let _blocker = rx.try_recv().expect("free one input slot");
    assert!(app.retry_retained_pre_dispatch_submissions());
    let RunnerInput::Submission(delivered) = rx.try_recv().expect("busy retry delivered") else {
        panic!("one busy retry should use one submission input");
    };
    assert_eq!(delivered.intended_session_id, session_id);
    assert_eq!(
        serde_json::to_value(delivered.submission).unwrap(),
        expected
    );
    assert!(
        app.busy,
        "retrying a queued message preserves the active turn span"
    );
}

#[test]
fn runner_failure_before_session_creation_binds_retry_to_first_runner() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.agent_runner = Some(Err("provider could not be constructed".to_string()));
    app.begin_working_span();
    let submission = complete_dispatch_submission("first-runner");
    let expected = serde_json::to_value(&submission).unwrap();

    assert_eq!(
        app.dispatch_optimistic_user_submission(
            "visible-first-runner".to_string(),
            submission,
            "engine",
            true,
            &[],
        ),
        DispatchOutcome::RunnerFailed
    );
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    assert_eq!(
        app.retained_pre_dispatch_submissions[0].intended_session_id, None,
        "no durable session existed at the failed construction boundary"
    );

    let (tx, mut rx) = mpsc::channel(1);
    let runner = runner_with_sender(tx, Arc::new(Mutex::new(Vec::new())));
    let session_id = runner.session_id();
    app.agent_runner = Some(Ok(runner));
    assert!(app.retry_retained_pre_dispatch_submissions());
    let RunnerInput::Submission(delivered) = rx.try_recv().expect("first runner receives retry")
    else {
        panic!("one retained payload should use one submission input");
    };
    assert_eq!(delivered.intended_session_id, session_id);
    assert_eq!(
        serde_json::to_value(delivered.submission).unwrap(),
        expected
    );
}

#[test]
fn slash_dispatch_failures_use_same_failed_user_reconciliation() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.agent_runner = Some(Err("model missing".to_string()));
    app.dispatch_init_turn("thing", "wire".to_string());

    assert!(!app.busy, "/init failed dispatch ends its span");
    assert!(!app.current_session_persisted);
    assert!(newest_user_failed(&app));
    assert!(
        error_lines(&app)
            .iter()
            .any(|line| line.starts_with("/init")),
        "/init failure uses the shared error path"
    );

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
    let tags = vec![cockpit_core::daemon::proto::TagExpansionMeta {
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
        .try_send(UserSubmission::text("already queued".to_string()).into())
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
        Ok(cockpit_core::daemon::proto::Request::SetAgent { name }) if name == "Multireview"
    ));
    app.apply_event(cockpit_core::engine::TurnEvent::ControlRequestFinished {
        request_id: cockpit_core::engine::ControlRequestId(1),
        outcome: cockpit_core::engine::ControlRequestOutcome::Applied,
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
        Ok(cockpit_core::daemon::proto::Request::SetAgent { name }) if name == "Multireview"
    ));
    app.apply_event(cockpit_core::engine::TurnEvent::ControlRequestFinished {
        request_id: cockpit_core::engine::ControlRequestId(1),
        outcome: cockpit_core::engine::ControlRequestOutcome::Applied,
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
        Ok(cockpit_core::daemon::proto::Request::SetAgent { name }) if name == "Multireview"
    ));
    app.apply_event(cockpit_core::engine::TurnEvent::ControlRequestFinished {
        request_id: cockpit_core::engine::ControlRequestId(1),
        outcome: cockpit_core::engine::ControlRequestOutcome::Applied,
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

#[tokio::test]
async fn submission_during_swap_is_not_sent_to_previous_session() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, mut input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));
    let (switch_tx, switch_rx) = oneshot::channel();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { switch_rx.await.expect("switch result sent") },
    );

    let outcome = app.dispatch_optimistic_user_submission(
        "hello".to_string(),
        UserSubmission::text("hello".to_string()),
        "engine",
        true,
        &[],
    );

    assert_eq!(outcome, DispatchOutcome::Sent);
    assert!(input_rx.try_recv().is_err());
    assert!(!newest_user_failed(&app));
    assert!(error_lines(&app).is_empty());

    switch_tx
        .send(Ok(switch_outcome(uuid::Uuid::new_v4())))
        .expect("switch receiver alive");
    drain_async_actions_until_idle(&mut app).await;

    let submission = input_rx
        .try_recv()
        .expect("queued input flushed after swap");
    assert_eq!(submission.text, "hello");
    assert!(!newest_user_failed(&app));
}

#[tokio::test]
async fn completed_switch_cannot_be_replaced_before_ui_adopts_it() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, mut input_rx) = mpsc::channel(4);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));

    let switched_session = uuid::Uuid::new_v4();
    let (complete_first_tx, complete_first_rx) = oneshot::channel();
    let first_returned = Arc::new(AtomicBool::new(false));
    let first_returned_in_task = Arc::clone(&first_returned);
    let first_action = app
        .async_actions
        .start(
            AsyncActionKind::Internal("session.switch"),
            App::session_switch_action_policy(),
            async move {
                complete_first_rx.await.expect("release first switch");
                first_returned_in_task.store(true, Ordering::Release);
                // Outcome epoch must match the transport attach epoch the
                // runner will publish before App drains (see store below).
                Ok(switch_outcome_with_epoch(switched_session, 1))
            },
        )
        .id();

    let exact_submission = UserSubmission {
        expected_model_state_generation: None,
        expected_model: None,
        kind: cockpit_core::engine::message::UserSubmissionKind::Compact,
        origin: Default::default(),
        text: format!(
            "wire-before{}wire-after",
            cockpit_core::engine::message::IMAGE_PART_SENTINEL
        ),
        display_text: Some("visible composer text".to_string()),
        tag_expansions: vec![cockpit_core::daemon::proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: "src/lib.rs".to_string(),
            detail: "expanded before switch".to_string(),
            ok: true,
        }],
        images: vec![cockpit_core::engine::message::SubmissionImage::png(vec![
            0x89, b'P', b'N', b'G',
        ])],
        forced_skill: Some("review".to_string()),
        origin_principal: Some("flycockpit:test-owner".to_string()),
        job_id: Some("job-before-switch".to_string()),
        preflight_cleaned: Some("cleaned wire text".to_string()),
        queue_item_ids: vec![uuid::Uuid::new_v4()],
        client_submissions: Vec::new(),
        pending_terminal_disposition: None,
        run_invocation_id: None,
        queue_target: Some(cockpit_core::engine::message::QueueTarget::child(
            "Build",
            1,
            "task-call",
            "reviewer",
        )),
    };
    let expected_submission = serde_json::to_value(&exact_submission).unwrap();
    assert_eq!(
        app.dispatch_optimistic_user_submission(
            "visible composer text".to_string(),
            exact_submission,
            "engine",
            true,
            &[],
        ),
        DispatchOutcome::Sent
    );
    assert!(input_rx.try_recv().is_err());

    complete_first_tx.send(()).expect("first switch alive");
    while !first_returned.load(Ordering::Acquire) {
        tokio::task::yield_now().await;
    }
    // Model the transport-side epoch mutation that happens before App drains
    // the completed action and adopts its attach snapshot.
    app.agent_runner
        .as_ref()
        .and_then(|runner| runner.as_ref().ok())
        .expect("runner")
        .attachment_epoch
        .store(1, Ordering::Release);
    tokio::task::yield_now().await;

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

    assert_eq!(
        first_action, second_action,
        "the completed-but-unapplied switch remains the sole transaction"
    );
    drain_async_actions_until_idle(&mut app).await;

    assert!(!replacement_ran.load(Ordering::Acquire));
    assert_eq!(app.launch.session_id, Some(switched_session));
    let runner = app
        .agent_runner
        .as_ref()
        .and_then(|runner| runner.as_ref().ok())
        .expect("successful first switch keeps runner live");
    assert_eq!(runner.session_id(), switched_session);
    assert_eq!(runner.attachment_epoch(), 1);
    let RunnerInput::Submission(delivered) = input_rx.try_recv().expect("queued submission sent")
    else {
        panic!("expected queued submission, found a flush marker");
    };
    assert_eq!(delivered.intended_session_id, switched_session);
    assert_eq!(delivered.intended_attachment_epoch, 1);
    assert_eq!(
        serde_json::to_value(&delivered.submission).unwrap(),
        expected_submission,
        "every accepted submission field must survive switch serialization"
    );
}

#[tokio::test]
async fn connection_loss_during_new_swap_keeps_runner_and_retains_target_bound_input() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (input_tx, mut input_rx) = mpsc::channel(1);
    let (record_tx, _record_rx) = mpsc::channel(4);
    let (control_tx, _control_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(runner_with_all_channels(
        input_tx,
        record_tx,
        control_tx,
        Arc::new(Mutex::new(Vec::new())),
    )));
    let (switch_tx, switch_rx) = oneshot::channel();
    app.async_actions.start(
        AsyncActionKind::Internal("session.switch"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
        async move { switch_rx.await.expect("switch result sent") },
    );
    app.begin_session_switch_submission_target(SessionTarget::New);

    let outcome = app.dispatch_optimistic_user_submission(
        "hello".to_string(),
        UserSubmission::text("hello".to_string()),
        "engine",
        true,
        &[],
    );
    assert_eq!(outcome, DispatchOutcome::Sent);
    assert!(input_rx.try_recv().is_err());

    switch_tx
        .send(Err("attach: daemon connection closed".to_string()))
        .expect("switch receiver alive");
    drain_async_actions_until_idle(&mut app).await;

    assert!(
        matches!(app.agent_runner, Some(Ok(_))),
        "connection loss during switch must leave the live runner for reconnect"
    );
    assert!(
        input_rx.try_recv().is_err(),
        "new-session input must not be released to the preserved old runner"
    );
    assert!(newest_user_failed(&app));
    assert_eq!(app.retained_session_switch_submissions.len(), 1);
    assert_eq!(
        app.retained_session_switch_submissions[0].target,
        Some(SessionTarget::New)
    );
    assert_eq!(
        app.retained_session_switch_submissions[0].submissions[0]
            .submission
            .text,
        "hello"
    );
    assert!(error_lines(&app).contains(&"/new: daemon connection lost; reconnecting"));
}
