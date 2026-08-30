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

use cockpit_client::submission::ClientUserSubmission as UserSubmission;

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
    cockpit_client::reset_connect_call_count();

    app.pending_new_session = true;
    let serviced = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("/new should be serviced");

    assert!(serviced);
    assert_eq!(cockpit_core::daemon::blocking_probe_call_count(), 0);
    assert_eq!(cockpit_client::connect_call_count(), 0);
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
    for _ in 0..100 {
        app.drain_async_actions();
        if !app
            .async_actions
            .has_pending_kind(&AsyncActionKind::Internal("session.switch"))
        {
            return;
        }
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("session switch action did not complete");
}

fn switch_outcome(session_id: uuid::Uuid, short_id: &str) -> AsyncActionPayload {
    switch_outcome_with_epoch(session_id, short_id, 0)
}

fn switch_outcome_with_epoch(
    session_id: uuid::Uuid,
    short_id: &str,
    attachment_epoch: u64,
) -> AsyncActionPayload {
    AsyncActionPayload::SessionSwitched(Box::new(SessionSwitchOutcome {
        target: SessionTarget::New,
        session_id,
        session_entry_mode: cockpit_core::daemon::proto::SessionEntryMode::Code,
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
        resume_compaction_offer: None,
        btw_fork: None,
        daemon_version: "test".to_string(),
        daemon_compatible: true,
        attachment_epoch,
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

/// Live-swappable runner: `can_switch_session` is true and `/new` awaits
/// `outcome_tx` without a Unix socket, network, or daemon.
fn install_live_swappable_runner(
    app: &mut App,
    capacity: usize,
) -> (
    mpsc::Receiver<RunnerInput>,
    mpsc::Receiver<crate::tui::agent_runner::ControlRequest>,
    oneshot::Sender<Result<SessionSwitchOutcome, String>>,
) {
    let (runner, input_rx, control_rx) = runner_with_input(capacity);
    let (outcome_tx, outcome_rx) = oneshot::channel();
    let mut runner = runner;
    runner.install_live_swappable_switch_seam(outcome_rx);
    app.agent_runner = Some(Ok(runner));
    (input_rx, control_rx, outcome_tx)
}

fn assert_cleared_provisional_view(app: &App) {
    assert!(
        app.provisional_new_session,
        "live-runner /new must enter provisional-new after scheduling session.switch"
    );
    assert!(app.history.is_empty() || app.history.iter().all(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line.starts_with("Delivery unconfirmed"))
    }));
    assert!(app.queue.is_empty());
    assert!(app.pending.is_none());
    assert!(!app.busy);
    assert!(app.launch.session_id.is_none());
    assert!(app.launch.session_short_id.is_none());
    assert!(app.project_id.is_none());
    assert!(app.foreground_input_target.is_none());
    assert!(app.side_conversation.is_none());
    // Terminal clear is scheduled then best-effort serviced in the same tick.
}

fn complete_submission(index: usize) -> UserSubmission {
    UserSubmission {
        expected_model_state_generation: None,
        expected_model: None,
        kind: cockpit_client::submission::UserSubmissionKind::Compact,
        origin: Default::default(),
        text: format!("wire-{index}"),
        display_text: Some(format!("display-{index}")),
        tag_expansions: vec![cockpit_proto::TagExpansionMeta {
            tool: "read".to_string(),
            path: format!("src/{index}.rs"),
            detail: "complete".to_string(),
            ok: true,
        }],
        images: vec![cockpit_client::image_upload::SubmissionImage::png(vec![
            index as u8,
            2,
            3,
            4,
        ])],
        media: Vec::new(),
        forced_skill: Some("review".to_string()),
        origin_principal: Some("flycockpit:test-owner".to_string()),
        job_id: Some(format!("job-{index}")),
        preflight_cleaned: Some(format!("clean-{index}")),
        queue_item_ids: vec![uuid::Uuid::from_u128(index as u128 + 1)],
        client_submissions: Vec::new(),
        pending_terminal_disposition: None,
        run_invocation_id: None,
        queue_target: Some(cockpit_proto::QueueTarget::root("Build")),
        delivery_class: Default::default(),
        delivery_class_override: None,
    }
}

fn side_conversation(tmp: &std::path::Path) -> SideConversation {
    SideConversation {
        endpoint: cockpit_client::ClientEndpoint::Wire(tmp.join("daemon.sock")),
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
        saved_active_display_attempt_id: None,
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
    let (mut input_rx, mut control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    let old_session_id = app
        .agent_runner
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap()
        .session_id();
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
    app.launch.session_id = Some(old_session_id);
    app.launch.session_short_id = Some("old001".to_string());
    app.foreground_input_target = Some(cockpit_proto::QueueTarget::root("Build"));

    app.pending_new_session = true;
    let cleared = Arc::new(AtomicBool::new(false));
    let cleared_flag = Arc::clone(&cleared);
    assert!(
        app.maybe_service_new_session_with_clear(|| {
            cleared_flag.store(true, Ordering::Release);
            Ok(())
        })
        .expect("/new should schedule")
    );
    assert!(
        cleared.load(Ordering::Acquire),
        "provisional /new schedules the terminal clear"
    );
    assert_eq!(
        app.async_actions
            .pending_kinds()
            .into_iter()
            .filter(|kind| kind == &AsyncActionKind::Internal("session.switch"))
            .count(),
        1,
        "exactly one pending session.switch action"
    );
    assert_cleared_provisional_view(&app);
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
    }));

    let first = complete_submission(7);
    let second = complete_submission(8);
    let expected = [&first, &second]
        .into_iter()
        .map(|submission| serde_json::to_value(submission).unwrap())
        .collect::<Vec<_>>();
    app.queue_pending_session_switch_submission(first, "engine", 0, false);
    app.queue_pending_session_switch_submission(second, "engine", 0, false);

    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;

    assert!(
        app.provisional_new_session,
        "failed /new keeps the cleared provisional barrier until a successful adoption"
    );
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
    }));
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line == "/new: attach failed")
    }));
    assert!(
        !app.history
            .iter()
            .any(|entry| matches!(entry, HistoryEntry::InferenceError { .. })),
        "failed attach must not append outgoing-session inference rows"
    );
    let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
    assert_eq!(runner.session_id(), old_session_id);
    assert!(
        !app.busy,
        "provisional failure keeps the cleared view without a working span"
    );
    assert!(
        control_rx.try_recv().is_err(),
        "a failed replacement Attach must not cancel the outgoing turn"
    );
    assert!(!app.current_session_persisted);
    assert!(app.project_id.is_none());
    assert!(app.side_conversation.is_none());
    assert!(app.launch.session_id.is_none());
    assert!(app.queue.is_empty());
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
    let (retry_tx, retry_rx) = oneshot::channel();
    {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        runner.install_live_swappable_switch_seam(retry_rx);
        runner
            .attachment_epoch
            .store(1, std::sync::atomic::Ordering::Release);
    }
    app.pending_new_session = true;
    assert!(
        app.maybe_service_new_session_with_clear(|| Ok(()))
            .expect("retry /new schedules")
    );
    assert!(app.retained_session_switch_submissions.is_empty());
    let AsyncActionPayload::SessionSwitched(outcome) =
        switch_outcome_with_epoch(retry_session_id, "retry", 1)
    else {
        unreachable!()
    };
    retry_tx.send(Ok(*outcome)).unwrap();
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
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.history.push(HistoryEntry::Plain {
        line: "old transcript remains visible".to_string(),
    });
    app.project_id = Some("old-project".to_string());
    app.launch.session_id = Some(uuid::Uuid::new_v4());
    app.launch.session_short_id = Some("old001".to_string());
    app.side_conversation = Some(side_conversation(tmp.path()));
    app.pending_new_session = true;
    let cleared = Arc::new(AtomicBool::new(false));
    let cleared_flag = Arc::clone(&cleared);
    assert!(
        app.maybe_service_new_session_with_clear(|| {
            cleared_flag.store(true, Ordering::Release);
            Ok(())
        })
        .expect("/new should schedule")
    );
    assert!(cleared.load(Ordering::Acquire));
    assert_cleared_provisional_view(&app);
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript remains visible")
    }));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|frame| app.render(frame)).unwrap();
    assert!(
        app.async_actions
            .has_pending_kind(&AsyncActionKind::Internal("session.switch"))
    );
    assert!(app.history.is_empty());
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
    // Adoption validates against the runner's authoritative epoch.
    let (runner, _input_rx, _control_rx) = runner_with_input(1);
    app.agent_runner = Some(Ok(runner));
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

#[tokio::test]
async fn new_session_swap_discards_old_epoch_events_while_provisional() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    let outgoing_epoch = app.visible_attachment_epoch;
    let config_extended = app.config_snapshot.extended.clone();

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        let mut events = runner.events.lock().unwrap();
        for event in [
            TurnEvent::ThinkingStarted {
                agent: "Build".into(),
                turn_id: None,
            },
            TurnEvent::AssistantTextDelta {
                agent: "Build".into(),
                delta: "stale".into(),
            },
            TurnEvent::ToolStart {
                agent: "Build".into(),
                call_id: "c1".into(),
                tool: "read".into(),
                args: serde_json::json!({}),
            },
            TurnEvent::Usage {
                agent: "Build".into(),
                usage: Default::default(),
            },
            TurnEvent::QueueUpdated { queue: vec![] },
            TurnEvent::ConfigSnapshot {
                snapshot: Box::new(cockpit_proto::ConfigSnapshot {
                    session_id: uuid::Uuid::nil(),
                    generation: 1,
                    extended: config_extended.clone(),
                    providers: Default::default(),
                }),
            },
            TurnEvent::AgentIdle {
                turn_id: None,
                reason: cockpit_proto::IdleReason::Completed,
            },
            TurnEvent::InferenceFailed {
                agent: "Build".into(),
                provider: "p".into(),
                model: "m".into(),
                error_class: cockpit_proto::InferenceErrorClass::Network,
                detail: "boom".into(),
                auth_failure: None,
            },
        ] {
            events.push(QueuedTurnEvent {
                attachment_epoch: outgoing_epoch,
                event,
            });
        }
    }

    assert!(app.drain_agent_events());
    assert!(app.history.is_empty());
    assert!(app.pending.is_none());
    assert!(app.queue.is_empty());
    assert!(app.usage_models.is_empty());
    assert!(app.toast.is_none());
    assert!(!app.busy);
    assert!(app.foreground_input_target.is_none());
    // ConfigSnapshot / idle presentation must not mutate while provisional.
    assert!(app.pending.is_none());
    let _ = config_extended;
}

#[tokio::test]
async fn new_session_swap_buffers_new_epoch_events_until_adoption() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    let new_epoch = 3;
    {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        runner
            .attachment_epoch
            .store(new_epoch, std::sync::atomic::Ordering::Release);
        let mut events = runner.events.lock().unwrap();
        events.push(QueuedTurnEvent {
            attachment_epoch: new_epoch,
            event: TurnEvent::Notice {
                text: "first-new".into(),
            },
        });
        events.push(QueuedTurnEvent {
            attachment_epoch: new_epoch,
            event: TurnEvent::Notice {
                text: "second-new".into(),
            },
        });
        // Stale non-replacement epoch must not enter the buffer.
        events.push(QueuedTurnEvent {
            attachment_epoch: 2,
            event: TurnEvent::Notice {
                text: "stale-other".into(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert!(app.history.is_empty());
    assert_eq!(app.provisional_new_epoch_event_buffer.len(), 2);
    assert!(
        app.provisional_new_epoch_event_buffer
            .iter()
            .all(|queued| queued.attachment_epoch == new_epoch)
    );

    let AsyncActionPayload::SessionSwitched(outcome) =
        switch_outcome_with_epoch(uuid::Uuid::new_v4(), "adopt1", new_epoch)
    else {
        unreachable!()
    };
    outcome_tx.send(Ok(*outcome)).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    assert!(!app.provisional_new_session);
    assert!(app.provisional_new_epoch_event_buffer.is_empty());
    let notices: Vec<_> = app
        .history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Plain { line } => Some(line.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(notices, vec!["⚠ first-new", "⚠ second-new"]);
    assert!(!notices.iter().any(|line| line.contains("stale-other")));
}

#[tokio::test]
async fn new_session_swap_mismatched_epoch_rejects_adoption_and_discards_buffer() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        runner
            .attachment_epoch
            .store(9, std::sync::atomic::Ordering::Release);
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: 9,
            event: TurnEvent::Notice {
                text: "should-discard".into(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert_eq!(app.provisional_new_epoch_event_buffer.len(), 1);

    {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        runner
            .attachment_epoch
            .store(1, std::sync::atomic::Ordering::Release);
    }
    let AsyncActionPayload::SessionSwitched(outcome) =
        switch_outcome_with_epoch(uuid::Uuid::new_v4(), "mismatch", 9)
    else {
        unreachable!()
    };
    outcome_tx.send(Ok(*outcome)).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    assert!(app.launch.session_id.is_none());
    assert!(
        app.provisional_new_session,
        "mismatched adoption keeps the cleared barrier"
    );
    assert!(app.provisional_new_epoch_event_buffer.is_empty());
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line.contains("should-discard"))
    }));
}

#[tokio::test]
async fn new_session_swap_failed_outcome_discards_buffered_replacement_events() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        runner
            .attachment_epoch
            .store(4, std::sync::atomic::Ordering::Release);
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: 4,
            event: TurnEvent::Notice {
                text: "buffered-then-fail".into(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert_eq!(app.provisional_new_epoch_event_buffer.len(), 1);

    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;

    assert!(app.provisional_new_session);
    assert!(app.provisional_new_epoch_event_buffer.is_empty());
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line.contains("buffered-then-fail"))
    }));
}

#[tokio::test]
async fn new_session_swap_old_epoch_bookkeeping_settles_fence_without_presentation() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    let outgoing_epoch = app.visible_attachment_epoch;
    let fence_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    app.submission_fences.insert(
        fence_id,
        crate::tui::structured_paste::SubmissionFenceV1 {
            client_submission_id: fence_id,
            fence_sequence: 1,
            host: crate::tui::structured_paste::HostIdentity {
                client_instance_id: app.paste_client_instance_id,
                connection_epoch: 1,
                session_id,
                terminal_generation: 1,
            },
            view_generation: 1,
            source_draft_generation: 1,
            created_at: std::time::Duration::ZERO,
            captured_composer: "wire".into(),
            accepted_tags: Vec::new(),
            pending_git_blocks: Vec::new(),
            model: crate::tui::structured_paste::CapturedModel {
                provider_id: "p".into(),
                model_id: "m".into(),
                active_model_state_generation: 1,
                image_capability_generation: 1,
                supports_images: false,
            },
            assembled_wire_digest: Some([1; 32]),
            slots: Vec::new(),
            retained_drafts: Vec::new(),
            lifecycle: crate::tui::structured_paste::FenceLifecycle::PossiblySent,
        },
    );
    app.delivery_unconfirmed_records.insert(
        fence_id,
        super::DeliveryUnconfirmedRecord {
            client_submission_id: fence_id,
            session_id,
            text: "wire".into(),
            wire_digest: [1; 32],
            fence_sequence: 1,
            surfaced: true,
            probe_in_flight: false,
            next_probe_at: std::time::Duration::ZERO,
            probe_deadline: std::time::Duration::from_secs(2),
            probe_attachment_epoch: outgoing_epoch,
            probe_exhausted: false,
        },
    );

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: outgoing_epoch,
            event: TurnEvent::UserMessageRecorded {
                seq: 7,
                client_submission_ids: vec![fence_id],
                preflight_cleaned: None,
            },
        });
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: outgoing_epoch,
            event: TurnEvent::UserMessageDispatchFailed {
                error: "late fail".into(),
                optimistic_submission_id: uuid::Uuid::new_v4(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert!(
        !app.submission_fences.contains_key(&fence_id),
        "old-epoch recorded event must settle the fence"
    );
    assert!(!app.delivery_unconfirmed_records.contains_key(&fence_id));
    assert!(
        app.history.is_empty()
            || app.history.iter().all(|entry| {
                matches!(
                    entry,
                    HistoryEntry::CommandError { line }
                        if line.starts_with("Delivery unconfirmed")
                )
            }),
        "bookkeeping must not append delivery/history presentation"
    );
    assert!(app.toast.is_none());
    assert!(app.queue.is_empty());
}

#[tokio::test]
async fn provisional_new_bookkeeping_records_dispatch_restored_without_history() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    let outgoing_epoch = app.visible_attachment_epoch;
    let restored_id = uuid::Uuid::new_v4();
    assert!(!app.retained_user_submission_ids.contains(&restored_id));

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: outgoing_epoch,
            event: TurnEvent::UserMessageDispatchRestored {
                optimistic_submission_id: restored_id,
                text: "should not appear".into(),
                display_text: None,
                tag_expansions: Vec::new(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert!(
        app.retained_user_submission_ids.contains(&restored_id),
        "provisional bookkeeping must retain the restored submission id"
    );
    assert!(
        !app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::User {
                    optimistic_submission_id: Some(id),
                    ..
                } if *id == restored_id
            )
        }),
        "must not restore user history into the cleared provisional view"
    );
    assert!(app.toast.is_none());
}

#[tokio::test]
async fn new_session_swap_failed_keeps_barrier_against_late_events_and_outgoing_dispatch() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (mut input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    let outgoing_epoch = app.visible_attachment_epoch;
    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;
    assert!(app.provisional_new_session);

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: outgoing_epoch,
            event: TurnEvent::Notice {
                text: "late-old-notice".into(),
            },
        });
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: outgoing_epoch,
            event: TurnEvent::AssistantTextDelta {
                agent: "Build".into(),
                delta: "should-not-appear".into(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line.contains("late-old-notice"))
    }));
    assert!(app.pending.is_none());

    let exact = complete_submission(99);
    let expected = serde_json::to_value(&exact).unwrap();
    let outcome =
        app.dispatch_optimistic_user_submission("display-99".into(), exact, "engine", true, &[]);
    assert!(matches!(outcome, super::DispatchOutcome::SessionSwitching));
    assert!(
        input_rx.try_recv().is_err(),
        "post-failure submissions must not reach the outgoing client"
    );
    assert!(
        !app.history
            .iter()
            .any(|entry| matches!(entry, HistoryEntry::User { .. })),
        "post-failure retain must not present optimistic rows"
    );
    assert!(app.retained_session_switch_submissions.iter().any(|group| {
        group.target == Some(SessionTarget::New)
            && group
                .submissions
                .iter()
                .any(|pending| serde_json::to_value(&pending.submission).unwrap() == expected)
    }));
}

#[tokio::test]
async fn new_session_swap_missing_runner_rejects_adoption() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);

    app.agent_runner = None;
    let AsyncActionPayload::SessionSwitched(outcome) =
        switch_outcome_with_epoch(uuid::Uuid::new_v4(), "orphan", 2)
    else {
        unreachable!()
    };
    outcome_tx.send(Ok(*outcome)).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    assert!(app.launch.session_id.is_none());
    assert!(app.provisional_new_session);
    assert!(app.history.iter().any(|entry| {
        matches!(
            entry,
            HistoryEntry::CommandError { line }
                if line.contains("could not validate attachment epoch")
        )
    }));
}

#[tokio::test]
async fn new_session_switch_outcome_adopts_identity_after_immediate_reset() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (mut input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);

    let new_session_id = uuid::Uuid::new_v4();
    let exact = complete_submission(42);
    let expected = serde_json::to_value(&exact).unwrap();
    app.queue_pending_session_switch_submission(exact, "engine", 0, false);
    assert!(
        input_rx.try_recv().is_err(),
        "staged submission must not dispatch before successful adoption"
    );

    {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        runner
            .attachment_epoch
            .store(2, std::sync::atomic::Ordering::Release);
    }
    let foreground = cockpit_proto::QueueTarget::root("Build");
    let selection = cockpit_config::providers::ActiveModelRef {
        provider: "openai".into(),
        model: "gpt-test".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    let active_model = cockpit_proto::ActiveModelState {
        selection: selection.clone(),
        default_selection: Some(selection.clone()),
        diverged: false,
        generation: 3,
    };
    let AsyncActionPayload::SessionSwitched(mut outcome) =
        switch_outcome_with_epoch(new_session_id, "ident", 2)
    else {
        unreachable!()
    };
    outcome.foreground_target = Some(foreground.clone());
    outcome.active_model_state = Some(active_model);
    outcome_tx.send(Ok(*outcome)).unwrap();
    drain_session_switch_until_complete(&mut app).await;

    assert_eq!(app.launch.session_id, Some(new_session_id));
    assert_eq!(app.launch.session_short_id.as_deref(), Some("ident"));
    assert_eq!(app.project_id.as_deref(), Some("project-ident"));
    assert_eq!(app.foreground_input_target.as_ref(), Some(&foreground));
    assert_eq!(app.active_model_selection.as_ref(), Some(&selection));
    assert!(!app.provisional_new_session);
    let RunnerInput::Submission(delivered) = input_rx.try_recv().expect("flushed") else {
        panic!("expected single submission");
    };
    assert_eq!(delivered.intended_session_id, new_session_id);
    assert_eq!(
        serde_json::to_value(&delivered.submission).unwrap(),
        expected
    );
    // Adoption installs deferred persistence (false); flush of staged
    // submissions then marks the new session persisted.
    assert!(app.current_session_persisted);
}

#[tokio::test]
async fn new_session_swap_second_new_while_pending_is_busy_dedupe() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    let pending_before = app.async_actions.pending_count();

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_eq!(app.async_actions.pending_count(), pending_before);
    assert!(app.history.iter().any(|entry| {
        matches!(
            entry,
            HistoryEntry::CommandError { line }
                if line.contains("another session change is still finishing")
        )
    }));
    assert!(app.provisional_new_session);
    assert!(app.launch.session_id.is_none());
}

#[tokio::test]
async fn new_session_swap_waits_for_possibly_sent_fence_before_clear() {
    use crate::tui::structured_paste::{
        CapturedModel, FenceLifecycle, HostIdentity, OrderedIntent,
        SESSION_SWITCH_RECONCILIATION_TIMEOUT, SubmissionFenceV1,
    };

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.history.push(HistoryEntry::Plain {
        line: "old transcript".to_string(),
    });
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
    app.submission_fences.insert(
        sent_id,
        SubmissionFenceV1 {
            client_submission_id: sent_id,
            fence_sequence: sent_sequence,
            host,
            view_generation: 1,
            source_draft_generation: 1,
            created_at: std::time::Duration::ZERO,
            captured_composer: "pending paste".into(),
            accepted_tags: Vec::new(),
            pending_git_blocks: Vec::new(),
            model: CapturedModel {
                provider_id: "p".into(),
                model_id: "m".into(),
                active_model_state_generation: 1,
                image_capability_generation: 1,
                supports_images: false,
            },
            assembled_wire_digest: Some([1; 32]),
            slots: Vec::new(),
            retained_drafts: Vec::new(),
            lifecycle: FenceLifecycle::PossiblySent,
        },
    );
    app.event_loop_monotonic_now = SESSION_SWITCH_RECONCILIATION_TIMEOUT / 2;
    app.pending_new_session = true;
    let changed = app
        .maybe_service_new_session_with_clear(|| Ok(()))
        .expect("waiting gate is non-fatal");
    let _ = changed;
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line == "old transcript")
    }));
    assert!(
        !app.async_actions
            .has_pending_kind(&AsyncActionKind::Internal("session.switch"))
    );
    assert!(!app.provisional_new_session);
    assert!(app.pending_new_session);
}

#[tokio::test]
async fn new_session_swap_suppresses_outgoing_delivery_receipt_while_provisional() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);

    let client_submission_id = uuid::Uuid::new_v4();
    let session_id = uuid::Uuid::new_v4();
    app.delivery_unconfirmed_records.insert(
        client_submission_id,
        super::DeliveryUnconfirmedRecord {
            client_submission_id,
            session_id,
            text: "wire".into(),
            wire_digest: [9; 32],
            fence_sequence: 1,
            surfaced: true,
            probe_in_flight: true,
            next_probe_at: std::time::Duration::ZERO,
            probe_deadline: std::time::Duration::from_secs(2),
            probe_attachment_epoch: app.visible_attachment_epoch,
            probe_exhausted: false,
        },
    );
    app.submission_fences.insert(
        client_submission_id,
        crate::tui::structured_paste::SubmissionFenceV1 {
            client_submission_id,
            fence_sequence: 1,
            host: crate::tui::structured_paste::HostIdentity {
                client_instance_id: app.paste_client_instance_id,
                connection_epoch: 1,
                session_id,
                terminal_generation: 1,
            },
            view_generation: 1,
            source_draft_generation: 1,
            created_at: std::time::Duration::ZERO,
            captured_composer: "wire".into(),
            accepted_tags: Vec::new(),
            pending_git_blocks: Vec::new(),
            model: crate::tui::structured_paste::CapturedModel {
                provider_id: "p".into(),
                model_id: "m".into(),
                active_model_state_generation: 1,
                image_capability_generation: 1,
                supports_images: false,
            },
            assembled_wire_digest: Some([9; 32]),
            slots: Vec::new(),
            retained_drafts: Vec::new(),
            lifecycle: crate::tui::structured_paste::FenceLifecycle::Reconciling,
        },
    );

    app.async_actions.start(
        AsyncActionKind::Blocking("paste.delivery_receipt"),
        AsyncActionPolicy::AllowConcurrent,
        async move {
            Ok(AsyncActionPayload::ClientSubmissionReceipt {
                client_submission_id,
                result: Ok(cockpit_proto::ClientSubmissionReceiptStatus::Terminal {
                    disposition: "accepted".into(),
                    wire_fingerprint: "abc".into(),
                }),
            })
        },
    );
    for _ in 0..20 {
        app.drain_async_actions();
        if !app
            .delivery_unconfirmed_records
            .contains_key(&client_submission_id)
        {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(
        !app.delivery_unconfirmed_records
            .contains_key(&client_submission_id)
    );
    assert!(!app.submission_fences.contains_key(&client_submission_id));
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line.starts_with("Delivery "))
    }));
}

#[tokio::test]
async fn new_session_swap_cancelled_discards_replacement_buffer_and_keeps_cleared_view() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);

    let replacement_epoch = {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        // Simulate a replacement-epoch advance while the switch is still pending.
        runner.attachment_epoch.store(42, Ordering::Release);
        42
    };
    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: replacement_epoch,
            event: TurnEvent::Notice {
                text: "buffered-replacement".into(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert_eq!(app.provisional_new_epoch_event_buffer.len(), 1);

    assert!(
        app.async_actions
            .abort_key(&App::session_switch_action_key()),
        "pending session.switch must be abortable for the cancellation path"
    );
    app.drain_async_actions();

    assert!(
        !app.async_actions
            .has_pending_kind(&AsyncActionKind::Internal("session.switch")),
        "cancelled switch must leave no pending action"
    );
    assert!(
        app.provisional_new_session,
        "cancelled switch keeps the cleared provisional barrier"
    );
    assert!(
        app.provisional_new_epoch_event_buffer.is_empty(),
        "cancelled switch must discard the replacement-epoch buffer"
    );
    assert!(
        !app.history
            .iter()
            .any(|entry| matches!(entry, HistoryEntry::Plain { line } if line.contains("buffered-replacement"))),
        "discarded buffer must not present into the cleared view"
    );
    assert!(app.history.iter().any(|entry| {
        matches!(
            entry,
            HistoryEntry::CommandError { line } if line.starts_with("/new:")
        )
    }));
}

#[tokio::test]
async fn new_session_swap_suppresses_active_agent_sync_while_provisional() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.launch.agent_name = "Build".into();
    app.agent_path = vec!["Build".into()];
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert!(app.provisional_new_session);

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        *runner.active_agent.lock().unwrap() = "Plan".into();
        *runner.active_agent_path.lock().unwrap() = vec!["Plan".into()];
    }
    app.sync_active_agent();
    assert_eq!(app.launch.agent_name, "Build");
    assert_eq!(app.agent_path, vec!["Build".to_string()]);
}

#[tokio::test]
async fn new_session_swap_failed_barrier_does_not_mark_fence_possibly_sent() {
    use crate::tui::structured_paste::{FenceLifecycle, SubmissionFenceV1};

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (mut input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;
    assert!(app.provisional_new_session);

    let client_submission_id = uuid::Uuid::new_v4();
    app.submission_fences.insert(
        client_submission_id,
        SubmissionFenceV1 {
            client_submission_id,
            fence_sequence: 7,
            host: crate::tui::structured_paste::HostIdentity {
                client_instance_id: app.paste_client_instance_id,
                connection_epoch: 1,
                session_id: uuid::Uuid::nil(),
                terminal_generation: 1,
            },
            view_generation: 1,
            source_draft_generation: 1,
            created_at: std::time::Duration::ZERO,
            captured_composer: "wire".into(),
            accepted_tags: Vec::new(),
            pending_git_blocks: Vec::new(),
            model: crate::tui::structured_paste::CapturedModel {
                provider_id: "p".into(),
                model_id: "m".into(),
                active_model_state_generation: 1,
                image_capability_generation: 1,
                supports_images: false,
            },
            assembled_wire_digest: None,
            slots: Vec::new(),
            retained_drafts: Vec::new(),
            lifecycle: FenceLifecycle::Ready,
        },
    );

    let outcome = app.dispatch_optimistic_user_submission_with_id(
        client_submission_id,
        "display".into(),
        complete_submission(3),
        "engine",
        true,
        &[],
    );
    assert!(matches!(outcome, super::DispatchOutcome::SessionSwitching));
    assert!(input_rx.try_recv().is_err());
    let fence = app
        .submission_fences
        .get(&client_submission_id)
        .expect("fence retained for retry bookkeeping");
    assert_eq!(
        fence.lifecycle,
        FenceLifecycle::Ready,
        "barrier retain must not claim a phantom PossiblySent dispatch"
    );
    assert!(fence.assembled_wire_digest.is_none());
}

#[tokio::test]
async fn new_session_swap_captures_outgoing_epoch_before_switch_task_advances() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    let outgoing_before = {
        let runner = app.agent_runner.as_mut().unwrap().as_mut().unwrap();
        // Simulate a fast replacement attach advancing the atomic epoch as
        // soon as the switch task is constructed — before provisional reset.
        runner.test_advance_epoch_when_switch_task_created = true;
        runner.attachment_epoch()
    };
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_eq!(
        app.visible_attachment_epoch, outgoing_before,
        "provisional reset must freeze the pre-spawn outgoing epoch"
    );
    let advanced = app
        .agent_runner
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap()
        .attachment_epoch();
    assert_eq!(
        advanced,
        outgoing_before + 1,
        "switch-task construction advanced the runner epoch"
    );

    // Replacement-epoch events must buffer (not bookkeeping-drop) while
    // visible stays on the captured outgoing epoch.
    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: advanced,
            event: TurnEvent::Notice {
                text: "replacement-before-adopt".into(),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert_eq!(app.provisional_new_epoch_event_buffer.len(), 1);
    assert!(!app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::Plain { line } if line.contains("replacement-before-adopt"))
    }));
}

#[tokio::test]
async fn new_session_swap_failed_event_loop_retry_does_not_dispatch_outgoing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (mut input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;
    assert!(app.provisional_new_session);

    let exact = complete_submission(77);
    let expected = serde_json::to_value(&exact).unwrap();
    // A post-failure submission is retained privately…
    let outcome = app.dispatch_optimistic_user_submission(
        "display-77".into(),
        exact.clone(),
        "engine",
        true,
        &[],
    );
    assert!(matches!(outcome, super::DispatchOutcome::SessionSwitching));
    assert!(input_rx.try_recv().is_err());

    // …and even if pending still holds a staged payload (e.g. orphaned
    // QueueFull leftover), event-loop retry must not flush to the outgoing
    // runner while the cleared provisional barrier is active.
    app.queue_pending_session_switch_submission(exact, "engine", 0, false);
    assert!(!app.retry_pending_session_switch_submissions());
    assert!(
        input_rx.try_recv().is_err(),
        "post-failure retry must not send to the outgoing client"
    );
    assert_eq!(app.pending_session_switch_submissions.len(), 1);
    assert_eq!(
        serde_json::to_value(&app.pending_session_switch_submissions[0].submission).unwrap(),
        expected
    );
}

#[tokio::test]
async fn new_session_swap_failed_pre_dispatch_retry_does_not_dispatch_outgoing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (mut input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    let outgoing_session_id = {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.session_id()
    };

    // QueueFull leftover from before `/new` — exactly the payload the
    // event-loop wake would otherwise flush after the switch action ends.
    let exact = complete_submission(88);
    let expected = serde_json::to_value(&exact).unwrap();
    app.retained_pre_dispatch_submissions
        .push(super::RetainedPreDispatchSubmission {
            intended_session_id: Some(outgoing_session_id),
            pending: super::PendingSessionSwitchSubmission {
                submission: exact,
                optimistic_submission_id: uuid::Uuid::new_v4(),
                error_prefix: "engine".into(),
                optimistic_tag_entries: 0,
                owns_working_span: false,
                optimistic_history: Vec::new(),
                optimistic_queue_item: None,
            },
        });

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;
    assert!(app.provisional_new_session);
    assert!(!app.session_switch_in_progress());

    assert!(
        !app.retry_retained_pre_dispatch_submissions(),
        "post-failure provisional barrier must suppress pre-dispatch retry"
    );
    assert!(
        input_rx.try_recv().is_err(),
        "retained pre-dispatch must not reach the outgoing client"
    );
    assert_eq!(app.retained_pre_dispatch_submissions.len(), 1);
    assert_eq!(
        serde_json::to_value(&app.retained_pre_dispatch_submissions[0].pending.submission).unwrap(),
        expected
    );
}

#[tokio::test]
async fn same_session_resync_adopts_visible_epoch_and_renders_new_epoch_events() {
    use crate::tui::agent_runner::{GLOBAL_ATTACHMENT_EPOCH, QueuedTurnEvent};
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.visible_attachment_epoch = 1;
    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.attachment_epoch.store(1, Ordering::Release);
    }
    assert!(!app.provisional_new_session);

    // Lag-resync / reconnect advances the runner epoch, then enqueues
    // HistoryReplay-shaped turn events with the new client epoch before the
    // global DaemonLinkResynced signal.
    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.attachment_epoch.store(2, Ordering::Release);
        let mut events = runner.events.lock().unwrap();
        events.push(QueuedTurnEvent {
            attachment_epoch: 2,
            event: TurnEvent::Notice {
                text: "post-resync-history".into(),
            },
        });
        events.push(QueuedTurnEvent {
            attachment_epoch: GLOBAL_ATTACHMENT_EPOCH,
            event: TurnEvent::DaemonLinkResynced {
                active_model_state: None,
            },
        });
    }

    assert!(app.drain_agent_events());
    assert_eq!(
        app.visible_attachment_epoch, 2,
        "App must adopt the runner's post-resync attachment epoch"
    );
    assert!(
        app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line } if line.contains("post-resync-history")
            )
        }),
        "new-epoch turn events after same-session resync must render"
    );
    assert!(
        app.same_session_resync_event_buffer.is_empty(),
        "resync adoption must flush the held pre-signal events"
    );
}

#[tokio::test]
async fn replacement_epoch_advance_without_resync_does_not_adopt_or_render() {
    use crate::tui::agent_runner::QueuedTurnEvent;
    use cockpit_client::presentation::TurnEvent;

    // Resume (and other replacement attaches) can advance the runner epoch and
    // forward events before App adopts the switch outcome. Matching-epoch
    // traffic must not auto-adopt visibility or mutate the outgoing transcript.
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.visible_attachment_epoch = 1;
    app.history.push(HistoryEntry::Plain {
        line: "outgoing transcript".into(),
    });
    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.attachment_epoch.store(1, Ordering::Release);
    }
    assert!(!app.provisional_new_session);

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.attachment_epoch.store(2, Ordering::Release);
        let mut events = runner.events.lock().unwrap();
        events.push(QueuedTurnEvent {
            attachment_epoch: 2,
            event: TurnEvent::Notice {
                text: "replacement-before-outcome".into(),
            },
        });
    }

    assert!(
        app.drain_agent_events(),
        "queued replacement-epoch event must be drained from the runner"
    );
    assert_eq!(
        app.visible_attachment_epoch, 1,
        "replacement epoch advance must not auto-adopt without DaemonLinkResynced/Reconnected"
    );
    assert!(
        !app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line } if line.contains("replacement-before-outcome")
            )
        }),
        "replacement-epoch events must not render against the outgoing transcript"
    );
    assert_eq!(
        app.same_session_resync_event_buffer.len(),
        1,
        "events are held only for an explicit same-session resync flush"
    );
    assert!(
        app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line } if line == "outgoing transcript"
            )
        }),
        "outgoing transcript must remain intact"
    );
}

#[tokio::test]
async fn provisional_new_ignores_same_session_resync_epoch_adoption() {
    use crate::tui::agent_runner::{GLOBAL_ATTACHMENT_EPOCH, QueuedTurnEvent};
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    let outgoing = app.visible_attachment_epoch;
    assert!(app.provisional_new_session);

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        // Simulate an outgoing-client reconnect advancing the atomic epoch while
        // provisional-new must keep the captured outgoing barrier.
        runner
            .attachment_epoch
            .store(outgoing + 5, Ordering::Release);
        let mut events = runner.events.lock().unwrap();
        events.push(QueuedTurnEvent {
            attachment_epoch: GLOBAL_ATTACHMENT_EPOCH,
            event: TurnEvent::DaemonLinkResynced {
                active_model_state: None,
            },
        });
        events.push(QueuedTurnEvent {
            attachment_epoch: outgoing + 5,
            event: TurnEvent::Notice {
                text: "should-buffer-or-drop".into(),
            },
        });
    }

    assert!(app.drain_agent_events());
    assert_eq!(
        app.visible_attachment_epoch, outgoing,
        "provisional `/new` must not adopt a reconnect-advanced runner epoch"
    );
    assert!(
        !app.history.iter().any(|entry| {
            matches!(
                entry,
                HistoryEntry::Plain { line } if line.contains("should-buffer-or-drop")
            )
        }),
        "replacement-epoch notice must not present into the cleared view"
    );
}

#[tokio::test]
async fn provisional_new_fences_stale_async_action_completions() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);

    let (release, barrier) = oneshot::channel::<()>();
    let export_key = AsyncActionKey::new("export");
    app.async_actions.start(
        AsyncActionKind::Blocking("export.transcript"),
        AsyncActionPolicy::Dedupe(export_key.clone()),
        async move {
            let _ = barrier.await;
            Ok(AsyncActionPayload::Text(
                "stale export must not repopulate".into(),
            ))
        },
    );
    app.async_actions.start(
        AsyncActionKind::Blocking("curator.command"),
        AsyncActionPolicy::AllowConcurrent,
        async move {
            Ok(AsyncActionPayload::Text(
                "stale curator must not repopulate".into(),
            ))
        },
    );
    app.async_actions.start(
        AsyncActionKind::Blocking("doctor.snapshot"),
        AsyncActionPolicy::AllowConcurrent,
        async move {
            Ok(AsyncActionPayload::DoctorSnapshot(
                "stale doctor must not repopulate".into(),
            ))
        },
    );

    app.history.push(HistoryEntry::Plain {
        line: "outgoing transcript".into(),
    });
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);

    let _ = release.send(());
    for _ in 0..20 {
        app.drain_async_actions();
        tokio::task::yield_now().await;
    }
    // session.switch remains pending behind the live-swappable seam.
    assert!(
        app.async_actions
            .has_pending_kind(&AsyncActionKind::Internal("session.switch"))
    );
    assert!(
        !app.async_actions
            .has_pending_kind(&AsyncActionKind::Blocking("curator.command")),
        "view-generation advance must abort non-export Blocking work"
    );
    assert!(
        !app.async_actions
            .has_pending_kind(&AsyncActionKind::Blocking("doctor.snapshot")),
        "view-generation advance must abort non-export Blocking work"
    );
    assert!(
        !app.async_actions
            .has_pending_kind(&AsyncActionKind::Blocking("export.transcript")),
        "stale-view export completion must release pending ownership"
    );
    let retry = app.async_actions.start(
        AsyncActionKind::Blocking("export.transcript"),
        AsyncActionPolicy::Dedupe(export_key),
        async { Ok(AsyncActionPayload::Text("post-/new export".into())) },
    );
    assert!(
        matches!(
            retry,
            crate::tui::async_action::AsyncActionStart::Started(_)
        ),
        "post-/new same-key export must not remain blocked by discarded stale completion"
    );
    assert!(
        app.history.is_empty()
            || app.history.iter().all(|entry| {
                matches!(
                    entry,
                    HistoryEntry::CommandError { line }
                        if line.starts_with("Delivery unconfirmed")
                )
            }),
        "stale async-action completions must not push_plain into provisional history: {:?}",
        app.history
    );
}

#[tokio::test]
async fn provisional_new_suppresses_caffeinate_presentation() {
    use crate::tui::agent_runner::{GLOBAL_ATTACHMENT_EPOCH, QueuedTurnEvent};
    use cockpit_client::presentation::TurnEvent;

    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.caffeinate_active = false;
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner.events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: GLOBAL_ATTACHMENT_EPOCH,
            event: TurnEvent::CaffeinateState {
                active: true,
                lid_close_guaranteed: false,
                message: Some("caffeinate on".into()),
            },
        });
    }
    assert!(app.drain_agent_events());
    assert!(
        !app.caffeinate_active,
        "provisional globals must not mutate caffeinate chrome"
    );
    assert!(
        app.toast.is_none(),
        "provisional globals must not surface caffeinate toasts"
    );
}

fn seed_outgoing_model_and_config_chrome(app: &mut App) {
    let mut providers = cockpit_proto::ProviderConfigView::default();
    providers.providers.insert(
        "outgoing".into(),
        cockpit_proto::ProviderEntryView {
            entry: cockpit_config::providers::ProviderEntry {
                name: Some("Outgoing".into()),
                models: vec![cockpit_config::providers::ModelEntry {
                    id: "old-model".into(),
                    favorite: true,
                    ..Default::default()
                }],
                ..Default::default()
            },
            headers: Vec::new(),
            credential_configured: true,
        },
    );
    providers.active_model = Some(cockpit_config::providers::ActiveModelRef {
        provider: "outgoing".into(),
        model: "old-model".into(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    let mut extended = app.config_snapshot.extended.clone();
    extended.dialog.lockout_ms = 4242;
    app.apply_config_snapshot(cockpit_proto::ConfigSnapshot {
        session_id: uuid::Uuid::nil(),
        generation: 9,
        extended,
        providers,
    });
    app.apply_active_model_state(
        cockpit_config::providers::ActiveModelRef {
            provider: "outgoing".into(),
            model: "old-model".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        None,
        false,
        7,
    );
    assert_eq!(app.active_model_state_generation, 7);
    assert!(app.active_model_state_confirmed);
    assert_eq!(
        app.launch
            .active_model
            .as_ref()
            .map(|(p, m)| (p.as_str(), m.as_str())),
        Some(("outgoing", "old-model"))
    );
    assert!(app.config_snapshot.from_daemon);
    assert_eq!(app.config_snapshot.generation, 9);
    assert!(
        app.config_snapshot
            .providers
            .providers
            .contains_key("outgoing")
    );
}

fn assert_empty_session_model_and_config_chrome(app: &App) {
    assert_eq!(app.active_model_state_generation, 0);
    assert!(!app.active_model_state_confirmed);
    assert!(app.active_model_selection.is_none());
    assert!(app.launch.active_model.is_none());
    assert!(app.launch.provider_line.is_empty());
    assert!(!app.launch.active_model_diverged);
    assert!(app.config_drift.is_none());
    assert!(!app.config_snapshot.from_daemon);
    assert_eq!(app.config_snapshot.generation, 0);
    assert!(app.config_snapshot.providers.providers.is_empty());
}

#[tokio::test]
async fn provisional_new_clears_outgoing_model_and_config_chrome() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    seed_outgoing_model_and_config_chrome(&mut app);

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    assert_empty_session_model_and_config_chrome(&app);

    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;

    assert!(app.provisional_new_session);
    assert_empty_session_model_and_config_chrome(&app);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line == "/new: attach failed")
    }));
}

#[tokio::test]
async fn provisional_new_staged_submission_omits_outgoing_model_fence_metadata() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, _outcome_tx) = install_live_swappable_runner(&mut app, 1);
    seed_outgoing_model_and_config_chrome(&mut app);

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    assert_empty_session_model_and_config_chrome(&app);

    // Display readiness for submit without re-confirming daemon model state —
    // the capture gates must stay unset so outgoing generation cannot leak.
    crate::tui::app::seed_ready_model_for_tests(&mut app);
    assert!(!app.active_model_state_confirmed);
    assert_eq!(app.active_model_state_generation, 0);

    app.composer.insert_str("staged during provisional");
    let _ = app.submit_input();
    assert_eq!(
        app.pending_session_switch_submissions.len(),
        1,
        "submit while session.switch is pending must stage exactly one payload"
    );
    let staged = &app.pending_session_switch_submissions[0].submission;
    assert!(
        staged.expected_model_state_generation.is_none(),
        "provisional staging must not fence on outgoing model generation"
    );
    assert!(
        staged.expected_model.is_none(),
        "provisional staging must not capture outgoing expected_model"
    );
    let fence = app
        .submission_fences
        .values()
        .find(|fence| {
            fence
                .captured_composer
                .contains("staged during provisional")
        })
        .expect("submit creates a fence");
    assert_eq!(
        fence.model.active_model_state_generation, 0,
        "fence must not retain outgoing active-model generation"
    );
    assert_ne!(
        fence.model.provider_id.as_str(),
        "outgoing",
        "fence must not retain outgoing provider id"
    );
}

#[tokio::test]
async fn provisional_new_clears_pending_file_autocomplete_loading() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.composer.set("@src".to_string());
    app.at_suggestions_loading = true;
    app.at_suggestions_error = Some("stale walk".to_string());
    app.at_suggestions_loaded_query = Some("src".to_string());
    *app.at_cache.borrow_mut() = Some(("src".to_string(), Vec::new()));
    app.at_selected = 3;
    app.at_scroll = 2;
    app.suggestion_box_area = Some(ratatui::layout::Rect::new(0, 5, 40, 4));
    app.suggestion_row_hits = vec![super::SuggestionBoxRowHit {
        target: super::SuggestionBoxTarget {
            kind: super::SuggestionBoxKind::At,
            index: 0,
        },
        rect: ratatui::layout::Rect::new(0, 5, 40, 1),
    }];
    app.hovered_suggestion = Some(super::SuggestionBoxTarget {
        kind: super::SuggestionBoxKind::At,
        index: 0,
    });
    app.async_actions.start(
        AsyncActionKind::Blocking("autocomplete.files"),
        AsyncActionPolicy::Replace(AsyncActionKey::new("autocomplete.files")),
        async { std::future::pending::<Result<AsyncActionPayload, String>>().await },
    );
    assert!(app.at_suggestions_loading);
    assert!(
        app.async_actions
            .has_pending_kind(&AsyncActionKind::Blocking("autocomplete.files"))
    );
    assert_eq!(
        app.suggestion_box_lines(),
        3,
        "stale empty cache shows popup"
    );

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    assert!(
        !app.at_suggestions_loading,
        "provisional /new must clear cancelled autocomplete loading UI"
    );
    assert!(
        app.at_suggestions_error.is_none(),
        "provisional /new must clear stale autocomplete error chrome"
    );
    assert!(
        app.at_suggestions_loaded_query.is_none(),
        "provisional /new must clear loaded-query so empty cache cannot show “no matches”"
    );
    assert!(
        app.at_cache.borrow().is_none(),
        "provisional /new must drop stale @ suggestion cache"
    );
    assert_eq!(app.at_selected, 0);
    assert_eq!(app.at_scroll, 0);
    assert!(
        app.suggestion_box_area.is_none(),
        "provisional /new must clear stale suggestion hit-test area"
    );
    assert!(
        app.suggestion_row_hits.is_empty(),
        "provisional /new must clear stale suggestion row hits"
    );
    assert!(
        app.hovered_suggestion.is_none(),
        "provisional /new must clear hovered suggestion"
    );
    assert_eq!(
        app.suggestion_box_lines(),
        0,
        "cleared popup state must not reserve autocomplete chrome for stale empty results"
    );
    assert!(
        !app.async_actions
            .has_pending_kind(&AsyncActionKind::Blocking("autocomplete.files")),
        "view-generation advance must abort pending autocomplete.files"
    );

    // A cancelled completion must not re-stick the loading popup while
    // provisional (discarded by the provisional async-action fence).
    app.at_suggestions_loading = true;
    app.at_suggestions_loaded_query = Some("src".to_string());
    *app.at_cache.borrow_mut() = Some(("src".to_string(), Vec::new()));
    app.async_actions.start(
        AsyncActionKind::Blocking("autocomplete.files"),
        AsyncActionPolicy::AllowConcurrent,
        async {
            Ok(AsyncActionPayload::FileSuggestions {
                query: "src".to_string(),
                suggestions: Vec::new(),
            })
        },
    );
    app.async_actions.notifier().notified().await;
    app.drain_async_actions();
    // Manually reset to the post-entry contract before failure/success checks:
    // the mid-provisional restart above is only to prove discard; entry already
    // cleared loading, and failure must not leave a stuck popup either.
    app.clear_at_suggestion_popup_state();

    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;
    assert!(app.provisional_new_session);
    assert!(
        !app.at_suggestions_loading,
        "failed /new must not retain autocomplete loading state"
    );
    assert!(app.at_suggestions_error.is_none());
    assert!(app.at_suggestions_loaded_query.is_none());
    assert!(app.at_cache.borrow().is_none());

    // Successful adoption also re-runs reset_new_session_view; prove loading
    // stays clear when composer still has an @ query.
    let (_input_rx2, _control_rx2, outcome_tx2) = install_live_swappable_runner(&mut app, 1);
    app.composer.set("@src".to_string());
    app.at_suggestions_loading = true;
    app.at_suggestions_error = Some("stale".to_string());
    app.at_suggestions_loaded_query = Some("src".to_string());
    *app.at_cache.borrow_mut() = Some(("src".to_string(), Vec::new()));
    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert!(!app.at_suggestions_loading);
    assert!(app.at_suggestions_error.is_none());
    assert!(app.at_suggestions_loaded_query.is_none());
    assert!(app.at_cache.borrow().is_none());
    let new_id = uuid::Uuid::new_v4();
    let epoch = app
        .agent_runner
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap()
        .attachment_epoch();
    outcome_tx2
        .send(Ok({
            let AsyncActionPayload::SessionSwitched(outcome) =
                switch_outcome_with_epoch(new_id, "new001", epoch)
            else {
                unreachable!()
            };
            *outcome
        }))
        .expect("release successful attach");
    drain_session_switch_until_complete(&mut app).await;
    assert!(!app.provisional_new_session);
    assert!(
        !app.at_suggestions_loading,
        "successful /new adoption must not retain autocomplete loading state"
    );
    assert!(app.at_suggestions_error.is_none());
    assert!(app.at_suggestions_loaded_query.is_none());
    assert!(app.at_cache.borrow().is_none());
}

#[tokio::test]
async fn provisional_new_suppresses_model_selection_cancel_notice() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    let (_input_rx, _control_rx, outcome_tx) = install_live_swappable_runner(&mut app, 1);
    app.launch.session_id = Some(uuid::Uuid::new_v4());
    app.history.push(HistoryEntry::Plain {
        line: "outgoing transcript".into(),
    });
    app.pending_model_selection = Some(super::PendingModelSelection {
        order_sequence: 0,
        session_id: app.launch.session_id,
        selection_id: uuid::Uuid::new_v4(),
        requested: cockpit_config::providers::ActiveModelRef {
            provider: "p".to_string(),
            model: "m".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        trigger: cockpit_proto::ActiveModelSwitchTrigger::Picker,
        minimum_generation: 1,
        started_at: Instant::now(),
        queued_submission: None,
    });

    app.pending_new_session = true;
    assert!(app.maybe_service_new_session_with_clear(|| Ok(())).unwrap());
    assert_cleared_provisional_view(&app);
    assert!(
        app.pending_model_selection.is_none(),
        "pending /model must be cancelled internally on provisional /new"
    );
    assert!(
        app.history.iter().all(|entry| {
            !matches!(
                entry,
                HistoryEntry::Plain { line } if line.contains("Model selection was cancelled")
            )
        }),
        "provisional /new must not leak model-cancel presentation into the cleared view: {:?}",
        app.history
    );

    outcome_tx
        .send(Err("attach failed".to_string()))
        .expect("release failed attach");
    drain_session_switch_until_complete(&mut app).await;

    assert!(app.provisional_new_session);
    assert!(app.history.iter().any(|entry| {
        matches!(entry, HistoryEntry::CommandError { line } if line == "/new: attach failed")
    }));
    assert!(
        app.history.iter().all(|entry| {
            !matches!(
                entry,
                HistoryEntry::Plain { line } if line.contains("Model selection was cancelled")
            )
        }),
        "failed /new history must not include a model-cancel row: {:?}",
        app.history
    );
}
