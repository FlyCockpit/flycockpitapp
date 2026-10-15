use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use super::{
    App, ControlApplied, ControlEpochAbandonAction, ControlEpochAbandonment, PendingControlRequest,
};
use crate::tui::agent_runner::{
    AgentRunner, ControlRequest, QueuedTurnEvent, TestRunnerOverrides, control_response_outcome,
};
use crate::tui::history::HistoryEntry;
use cockpit_client::presentation::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, TurnEvent,
};
use cockpit_core::config::extended::ApprovalMode;
use cockpit_proto::{Request, Response};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

fn app() -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = crate::tui::settings::Dialog::None;
    app
}

fn runner_with_channels(
    record_tx: mpsc::Sender<Request>,
    control_tx: mpsc::Sender<ControlRequest>,
    events: Arc<Mutex<Vec<QueuedTurnEvent>>>,
) -> AgentRunner {
    AgentRunner::test_fixture(TestRunnerOverrides {
        record_tx: Some(record_tx),
        control_tx: Some(control_tx),
        events: Some(events),
        ..Default::default()
    })
}

fn install_runner(
    app: &mut App,
    record_tx: mpsc::Sender<Request>,
    control_tx: mpsc::Sender<ControlRequest>,
) -> Arc<Mutex<Vec<QueuedTurnEvent>>> {
    let events = Arc::new(Mutex::new(Vec::new()));
    app.agent_runner = Some(Ok(runner_with_channels(
        record_tx,
        control_tx,
        events.clone(),
    )));
    events
}

fn history_lines(app: &App) -> Vec<&str> {
    app.history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Plain { line } | HistoryEntry::CommandError { line } => {
                Some(line.as_str())
            }
            _ => None,
        })
        .collect()
}

async fn drain_control_events(app: &mut App) {
    for _ in 0..20 {
        if app.drain_agent_events() {
            return;
        }
        tokio::task::yield_now().await;
    }
}

fn dummy_control_request() -> ControlRequest {
    let (response_tx, _response_rx) = oneshot::channel();
    ControlRequest {
        request: Request::Prune,
        intended_session_id: uuid::Uuid::nil(),
        intended_attachment_epoch: 0,
        response_tx,
    }
}

#[tokio::test]
async fn control_request_survives_full_telemetry_channel() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    record_tx.try_send(Request::Prune).unwrap();
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request(
        "/preflight",
        Request::SetPreflight {
            enabled: Some(true),
        },
        ControlApplied::None,
    );

    let control = control_rx.recv().await.expect("control request");
    assert!(matches!(
        control.request,
        Request::SetPreflight {
            enabled: Some(true)
        }
    ));
    assert_eq!(app.pending_control_requests.len(), 1);
}

#[test]
fn control_request_full_channel_reports_not_delivered() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, _control_rx) = mpsc::channel(1);
    control_tx.try_send(dummy_control_request()).unwrap();
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request("/prune", Request::Prune, ControlApplied::None);

    assert!(app.pending_control_requests.is_empty());
    let lines = history_lines(&app);
    assert!(lines.iter().any(|line| line.contains("request not sent")));
    assert!(
        !lines
            .iter()
            .any(|line| line.contains("send a message first"))
    );
}

#[test]
fn control_request_without_runner_reports_not_delivered() {
    let mut app = app();

    app.send_daemon_request("/prune", Request::Prune, ControlApplied::None);

    assert_eq!(
        history_lines(&app),
        vec!["/prune: send a message first to start a session"]
    );
}

#[test]
fn resume_compaction_enter_keeps_the_displayed_full_history_default() {
    let mut app = app();
    app.pending_resume_compaction_confirm = true;

    assert!(!app.handle_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)));

    assert!(
        !app.pending_resume_compaction_confirm,
        "Enter must resolve the choice rather than leave the confirmation armed"
    );
    assert_eq!(
        history_lines(&app),
        vec!["Resume: keeping full conversation."],
        "Enter must accept the displayed full-history default without dispatching compaction"
    );
    assert!(app.pending_control_requests.is_empty());
}

#[tokio::test]
async fn control_request_daemon_error_reports_rejected() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request("/prune", Request::Prune, ControlApplied::None);
    let control = control_rx.recv().await.expect("control request");
    control
        .response_tx
        .send(Err(
            crate::tui::agent_runner::ControlRequestError::rejected("no active session"),
        ))
        .unwrap();
    drain_control_events(&mut app).await;

    assert_eq!(
        history_lines(&app),
        vec!["/prune: daemon rejected request: no active session"]
    );
    assert!(app.pending_control_requests.is_empty());
}

#[tokio::test]
async fn control_request_ack_reports_applied() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request(
        "/agent",
        Request::SetAgent {
            name: "Plan".to_string(),
        },
        ControlApplied::PrimaryAgentSwitch {
            name: "Plan".to_string(),
        },
    );
    let control = control_rx.recv().await.expect("control request");
    control.response_tx.send(Ok(Response::Ack)).unwrap();
    drain_control_events(&mut app).await;

    assert_eq!(
        history_lines(&app),
        vec!["Switched primary agent to `Plan`"]
    );
    assert!(app.pending_control_requests.is_empty());
}

#[test]
fn control_response_outcome_table() {
    let successful = [
        Response::Ack,
        Response::RedactionState {
            scan_environment: true,
            scan_dotenv: false,
            scan_ssh_keys: true,
        },
        Response::PreflightState { enabled: true },
        Response::LongcacheState { enabled: true },
        Response::ApprovalModeState {
            mode: ApprovalMode::Auto,
        },
        Response::DelegationRecursionState {
            enabled: true,
            default_depth: 3,
        },
        Response::CaffeinateState {
            active: true,
            lid_close_guaranteed: false,
            message: "active".to_string(),
        },
    ];
    for response in successful {
        assert!(matches!(
            control_response_outcome(Ok(response)),
            ControlRequestOutcome::Applied
        ));
    }
    assert!(matches!(
        control_response_outcome(Ok(Response::Unknown)),
        ControlRequestOutcome::Rejected(message) if message.contains("Unknown")
    ));
    assert!(matches!(
        control_response_outcome(Err(crate::tui::agent_runner::ControlRequestError::rejected("daemon error"))),
        ControlRequestOutcome::Rejected(message) if message == "daemon error"
    ));
    assert!(matches!(
        control_response_outcome(Ok(Response::ExitGuardStatus {
            ephemeral_owner: true,
            has_live_work: true,
        })),
        ControlRequestOutcome::ExitGuardStatus {
            ephemeral_owner: true,
            has_live_work: true,
        }
    ));
}

#[tokio::test]
async fn longcache_toggles_session_override_and_status_indicator() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    let events = install_runner(&mut app, record_tx, control_tx);

    app.handle_longcache_command("");

    let control = control_rx.recv().await.expect("longcache control request");
    assert!(matches!(
        control.request,
        Request::SetLongcache { enabled: None }
    ));
    events.lock().unwrap().push(QueuedTurnEvent {
        attachment_epoch: 0,
        event: TurnEvent::LongcacheState {
            enabled: true,
            supported: true,
        },
    });
    drain_control_events(&mut app).await;

    assert!(app.longcache_enabled);
    assert!(app.longcache_supported);

    app.handle_longcache_command("off");
    let control = control_rx.recv().await.expect("longcache off request");
    assert!(matches!(
        control.request,
        Request::SetLongcache {
            enabled: Some(false)
        }
    ));
    events.lock().unwrap().push(QueuedTurnEvent {
        attachment_epoch: 0,
        event: TurnEvent::LongcacheState {
            enabled: false,
            supported: true,
        },
    });
    drain_control_events(&mut app).await;

    assert!(!app.longcache_enabled);
    assert!(app.longcache_supported);

    app.handle_longcache_command("on");
    let control = control_rx
        .recv()
        .await
        .expect("longcache unsupported control request");
    assert!(matches!(
        control.request,
        Request::SetLongcache {
            enabled: Some(true)
        }
    ));
    events.lock().unwrap().extend([
        QueuedTurnEvent {
            attachment_epoch: 0,
            event: TurnEvent::Notice {
                text: "/longcache: extended prompt-cache retention is not verified for the active model"
                    .to_string(),
            },
        },
        QueuedTurnEvent {
            attachment_epoch: 0,
            event: TurnEvent::LongcacheState {
                enabled: false,
                supported: false,
            },
        },
    ]);
    drain_control_events(&mut app).await;

    assert!(!app.longcache_enabled);
    assert!(!app.longcache_supported);
    assert!(
        history_lines(&app)
            .iter()
            .any(|line| line.contains("not verified for the active model"))
    );
}

#[tokio::test]
async fn plan_default_available_everywhere_tui_plan_swap() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.swap_primary_agent("Plan");

    let control = control_rx
        .recv()
        .await
        .expect("/plan should send a SetAgent request");
    match control.request {
        Request::SetAgent { name } => assert_eq!(name, "Plan"),
        other => panic!("expected SetAgent request, got {other:?}"),
    }
    assert!(history_lines(&app).is_empty());
}

#[tokio::test]
async fn roster_trim_swarm_swap_is_sent_to_daemon_validation() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.swap_primary_agent("Swarm");

    let control = control_rx
        .recv()
        .await
        .expect("Swarm is no longer blocked by a local experimental gate");
    match control.request {
        Request::SetAgent { name } => assert_eq!(name, "Swarm"),
        other => panic!("expected SetAgent request, got {other:?}"),
    }
    assert!(history_lines(&app).is_empty());
}

#[test]
fn control_request_stale_ack_is_ignored() {
    let mut app = app();

    app.apply_event(TurnEvent::ControlRequestFinished {
        request_id: ControlRequestId(999),
        outcome: ControlRequestOutcome::Applied,
    });

    assert!(app.history.is_empty());
}

#[tokio::test]
async fn control_request_acks_preserve_send_order() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(2);
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request(
        "/pin-context",
        Request::Pin {
            text: "first".to_string(),
        },
        ControlApplied::PinContext {
            text: "first".to_string(),
        },
    );
    app.send_daemon_request(
        "/pin-context",
        Request::Pin {
            text: "second".to_string(),
        },
        ControlApplied::PinContext {
            text: "second".to_string(),
        },
    );
    let first = control_rx.recv().await.expect("first control request");
    let second = control_rx.recv().await.expect("second control request");
    first.response_tx.send(Ok(Response::Ack)).unwrap();
    drain_control_events(&mut app).await;
    second.response_tx.send(Ok(Response::Ack)).unwrap();
    drain_control_events(&mut app).await;

    assert_eq!(
        history_lines(&app),
        vec![
            "/pin-context: pinned (survives /compact verbatim): first",
            "/pin-context: pinned (survives /compact verbatim): second",
        ]
    );
}

#[tokio::test]
async fn successful_repair_resume_ack_wakes_retained_submission_retry() {
    let mut app = app();
    let (control_tx, mut control_rx) = mpsc::channel(1);
    let (input_tx, _input_rx) = mpsc::channel(1);
    let (runner, mut retry_rx) =
        AgentRunner::stub_with_channels_and_submission_watch(control_tx, input_tx);
    let session_id = runner.session_id();
    app.agent_runner = Some(Ok(runner));

    app.send_daemon_request(
        "/resume",
        Request::RepairResume { session_id },
        ControlApplied::RepairResume,
    );
    let control = control_rx.recv().await.expect("repair control request");
    control.response_tx.send(Ok(Response::Ack)).unwrap();
    drain_control_events(&mut app).await;

    tokio::time::timeout(std::time::Duration::from_secs(1), retry_rx.changed())
        .await
        .expect("successful repair ACK wakes retained submissions")
        .expect("retry watch remains open");
    assert_eq!(retry_rx.borrow_and_update().session_id, session_id);
}

#[tokio::test]
async fn control_request_runner_teardown_reports_unknown_delivery() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request("/prune", Request::Prune, ControlApplied::None);
    drop(control_rx.recv().await.expect("control request"));
    drain_control_events(&mut app).await;

    assert_eq!(
        history_lines(&app),
        vec![
            "/prune: daemon response unavailable: daemon request: runner stopped before returning a daemon response; delivery and effects are unknown"
        ]
    );
    assert!(app.pending_control_requests.is_empty());
}

#[test]
fn control_request_outcome_has_three_terminal_states() {
    let outcomes = [
        ControlRequestOutcome::NotDelivered(ControlRequestNotDelivered::NoRunner),
        ControlRequestOutcome::Rejected("bad request".to_string()),
        ControlRequestOutcome::Applied,
    ];
    assert_eq!(outcomes.len(), 3);
}

#[test]
fn tool_call_view_toggle_is_local_and_preserves_history() {
    let mut app = app();
    app.history.push(HistoryEntry::Plain {
        line: "assistant message".to_string(),
    });
    let history_len = app.history.len();

    app.handle_tool_calls_command("hide");
    assert!(app.hide_tool_calls);
    assert_eq!(app.history.len(), history_len);

    app.handle_tool_calls_command("show");
    assert!(!app.hide_tool_calls);
    assert_eq!(app.history.len(), history_len);
}

fn sample_control_applied() -> Vec<ControlApplied> {
    vec![
        ControlApplied::None,
        ControlApplied::ModelSelection {
            selection_id: uuid::Uuid::nil(),
        },
        ControlApplied::PrimaryAgentSwitch {
            name: "Build".to_string(),
        },
        ControlApplied::ToolSurfaceOverride { cache_break: false },
        ControlApplied::Multireview {
            kickoff: "kickoff".to_string(),
        },
        ControlApplied::ScheduleCancel {
            command: "/cron-cancel".to_string(),
            job_id: "job".to_string(),
        },
        ControlApplied::ModelFavorite {
            provider: "openai".to_string(),
            model: "gpt-test".to_string(),
            favorite: true,
        },
        ControlApplied::PinContext {
            text: "pin".to_string(),
        },
        ControlApplied::RepairResume,
        ControlApplied::ExitGuardStatus,
        ControlApplied::ExitAfterStoppingWork,
        ControlApplied::ExitAfterBackgroundPromotion,
        ControlApplied::ResponseMetricsTokenizer {
            confirm_id: uuid::Uuid::nil(),
        },
    ]
}

#[test]
fn epoch_abandon_action_is_exhaustive_for_every_control_applied() {
    use ControlEpochAbandonAction as Action;
    use ControlEpochAbandonment as Reason;

    let expected = |applied: &ControlApplied, reason: Reason| -> Action {
        match applied {
            ControlApplied::None => Action::Silent,
            ControlApplied::ModelSelection { .. } => Action::ModelSelection,
            ControlApplied::PrimaryAgentSwitch { .. }
            | ControlApplied::ToolSurfaceOverride { .. } => Action::RefreshSnapshot,
            ControlApplied::ResponseMetricsTokenizer { .. } => Action::FailTokenizer,
            ControlApplied::ScheduleCancel { .. }
            | ControlApplied::ModelFavorite { .. }
            | ControlApplied::PinContext { .. } => Action::DaemonOwnedNotice,
            ControlApplied::Multireview { .. } => Action::DropFollowOn,
            ControlApplied::RepairResume => match reason {
                Reason::SameSession => Action::ParkRepairResume,
                Reason::SessionTransition | Reason::TerminalDisconnect => Action::DropFollowOn,
            },
            ControlApplied::ExitGuardStatus => match reason {
                Reason::TerminalDisconnect => Action::CompleteExitLocally,
                Reason::SameSession | Reason::SessionTransition => Action::ParkExitGuard,
            },
            ControlApplied::ExitAfterStoppingWork => match reason {
                Reason::TerminalDisconnect => Action::CompleteExitLocally,
                Reason::SameSession | Reason::SessionTransition => Action::ParkExitAfterStop,
            },
            ControlApplied::ExitAfterBackgroundPromotion => match reason {
                Reason::TerminalDisconnect => Action::CompleteExitAfterBackground,
                Reason::SameSession | Reason::SessionTransition => Action::ParkExitAfterBackground,
            },
        }
    };

    for applied in sample_control_applied() {
        for reason in [
            Reason::SameSession,
            Reason::SessionTransition,
            Reason::TerminalDisconnect,
        ] {
            assert_eq!(
                applied.epoch_abandon_action(reason),
                expected(&applied, reason),
                "{applied:?} abandoned for {reason:?}"
            );
        }
    }
}

#[test]
fn epoch_abandonment_drops_multireview_kickoff_without_dispatching() {
    let mut app = app();
    let (control_tx, mut control_rx) = mpsc::channel(4);
    let (input_tx, mut input_rx) = mpsc::channel(4);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_channels(control_tx, input_tx)));
    app.pending_control_requests.insert(
        ControlRequestId(1),
        PendingControlRequest::new(
            "/multireview",
            ControlApplied::Multireview {
                kickoff: "kickoff".to_string(),
            },
        ),
    );

    app.abandon_epoch_bound_control_receipts(ControlEpochAbandonment::SameSession);

    assert!(app.pending_control_requests.is_empty());
    assert!(input_rx.try_recv().is_err(), "kickoff must not dispatch");
    assert!(control_rx.try_recv().is_err(), "SetAgent is not re-issued");
    assert!(
        history_lines(&app)
            .iter()
            .any(|line| line.contains("/multireview") && line.contains("not confirmed")),
        "dropped follow-on must be visible: {:?}",
        history_lines(&app)
    );
    assert!(!app.busy);
}

#[test]
fn epoch_abandonment_parks_repair_resume_on_same_session_and_retries() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    install_runner(&mut app, record_tx, control_tx);
    app.pending_control_requests.insert(
        ControlRequestId(1),
        PendingControlRequest::new("/resume", ControlApplied::RepairResume),
    );

    app.abandon_epoch_bound_control_receipts(ControlEpochAbandonment::SameSession);
    assert!(app.pending_control_requests.is_empty());
    assert!(app.parked_control_follow_ons.repair_resume);
    assert!(
        history_lines(&app).is_empty(),
        "parked repair does not dispatch retry submissions itself: {:?}",
        history_lines(&app)
    );

    app.retry_parked_control_follow_ons();
    let retried = control_rx.try_recv().expect("repair is re-issued");
    assert!(matches!(retried.request, Request::RepairResume { .. }));
    assert!(!app.parked_control_follow_ons.repair_resume);
}

#[test]
fn epoch_abandonment_drops_repair_resume_on_session_transition() {
    let mut app = app();
    app.pending_control_requests.insert(
        ControlRequestId(1),
        PendingControlRequest::new("/resume", ControlApplied::RepairResume),
    );
    app.abandon_epoch_bound_control_receipts(ControlEpochAbandonment::SessionTransition);
    assert!(app.pending_control_requests.is_empty());
    assert!(!app.parked_control_follow_ons.repair_resume);
    assert!(
        history_lines(&app)
            .iter()
            .any(|line| line.contains("/resume") && line.contains("not confirmed")),
        "{:?}",
        history_lines(&app)
    );
}

#[test]
fn epoch_abandonment_notices_daemon_owned_confirmations() {
    let mut app = app();
    app.pending_control_requests.insert(
        ControlRequestId(1),
        PendingControlRequest::new(
            "/pin-context",
            ControlApplied::PinContext {
                text: "keep".to_string(),
            },
        ),
    );
    app.abandon_epoch_bound_control_receipts(ControlEpochAbandonment::SessionTransition);
    assert!(
        history_lines(&app)
            .iter()
            .any(|line| { line.contains("/pin-context") && line.contains("session change") }),
        "{:?}",
        history_lines(&app)
    );
}

#[test]
fn epoch_abandonment_completes_exit_on_terminal_disconnect() {
    let mut app = app();
    app.pending_control_requests.insert(
        ControlRequestId(1),
        PendingControlRequest::new("stop all", ControlApplied::ExitAfterStoppingWork),
    );
    app.abandon_epoch_bound_control_receipts(ControlEpochAbandonment::TerminalDisconnect);
    assert!(app.exit_requested);
    assert!(app.pending_control_requests.is_empty());
    assert!(!app.parked_control_follow_ons.exit_after_stop);
}

#[test]
fn epoch_abandonment_parks_exit_guard_until_model_epoch_retries() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(4);
    install_runner(&mut app, record_tx, control_tx);
    app.pending_control_requests.insert(
        ControlRequestId(1),
        PendingControlRequest::new("exit check", ControlApplied::ExitGuardStatus),
    );

    app.start_model_state_epoch(app.launch.session_id, None);
    let retried = control_rx.try_recv().expect("exit check is re-issued");
    assert!(matches!(retried.request, Request::ExitGuardStatus));
}

#[test]
fn epoch_abandon_action_source_has_no_wildcard() {
    let source = include_str!("mod.rs");
    let body = source
        .split_once("fn epoch_abandon_action")
        .expect("epoch_abandon_action")
        .1
        .split_once("\n}\n")
        .map(|(body, _)| body)
        .expect("epoch_abandon_action body");
    assert!(
        !body.contains("_ =>"),
        "epoch abandonment must stay exhaustive over ControlApplied"
    );
}

#[test]
fn fenced_epoch_retirement_settles_every_control_without_follow_ons() {
    for reason in [
        ControlEpochAbandonment::SameSession,
        ControlEpochAbandonment::SessionTransition,
        ControlEpochAbandonment::TerminalDisconnect,
    ] {
        for applied in sample_control_applied() {
            let mut app = app();
            match &applied {
                ControlApplied::ModelSelection { selection_id } => {
                    install_pending_model_selection(&mut app, *selection_id);
                }
                ControlApplied::ResponseMetricsTokenizer { confirm_id } => {
                    app.pending_tokenizer_confirm = Some(super::TokenizerConfirmPending::new(
                        *confirm_id,
                        uuid::Uuid::nil(),
                        0,
                        cockpit_tokenizer::TiktokenEncoding::default(),
                        std::time::Duration::ZERO,
                    ));
                }
                _ => {}
            }
            let id = ControlRequestId(1);
            app.pending_control_requests
                .insert(id, PendingControlRequest::new("fenced", applied.clone()));
            app.fence_pending_control_request(id);

            app.abandon_epoch_bound_control_receipts(reason);

            assert!(
                app.pending_control_requests.is_empty(),
                "{applied:?} {reason:?}"
            );
            assert!(
                app.pending_model_selection.is_none(),
                "{applied:?} {reason:?}"
            );
            assert!(
                app.pending_tokenizer_confirm.is_none(),
                "{applied:?} {reason:?}"
            );
            assert!(
                !app.has_unsettled_local_authority(),
                "{applied:?} {reason:?}"
            );
            assert!(!app.parked_control_follow_ons.is_pending());
            assert!(!app.exit_requested);
            assert!(app.exit_check_escape.is_none());
            assert!(
                history_lines(&app).is_empty(),
                "no fenced confirmation/follow-on"
            );
            if matches!(applied, ControlApplied::ModelSelection { .. }) {
                assert!(app.current_model_selection_retry().is_some());
            }
        }
    }
}

fn install_pending_model_selection(app: &mut App, selection_id: uuid::Uuid) {
    let order_sequence = app
        .submission_order
        .enqueue(crate::tui::structured_paste::OrderedIntent::ModelSwitch(
            selection_id,
        ))
        .unwrap();
    app.pending_model_selection = Some(super::PendingModelSelection {
        order_sequence,
        session_id: app.launch.session_id,
        selection_id,
        requested: cockpit_config::providers::ActiveModelRef {
            provider: "openai".to_string(),
            model: "gpt-test".to_string(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        trigger: cockpit_proto::ActiveModelSwitchTrigger::Picker,
        minimum_generation: 0,
        started_at: std::time::Instant::now(),
        queued_submission: None,
    });
}

#[test]
fn fenced_epoch_retirement_preserves_slots_owned_by_other_correlations() {
    let mut app = app();
    let old = uuid::Uuid::from_u128(1);
    let successor = uuid::Uuid::from_u128(2);
    install_pending_model_selection(&mut app, successor);
    app.pending_tokenizer_confirm = Some(super::TokenizerConfirmPending::new(
        successor,
        uuid::Uuid::nil(),
        1,
        cockpit_tokenizer::TiktokenEncoding::default(),
        std::time::Duration::ZERO,
    ));
    for (id, applied) in [
        (1, ControlApplied::ModelSelection { selection_id: old }),
        (
            2,
            ControlApplied::ResponseMetricsTokenizer { confirm_id: old },
        ),
    ] {
        let id = ControlRequestId(id);
        app.pending_control_requests
            .insert(id, PendingControlRequest::new("old", applied));
        app.fence_pending_control_request(id);
    }

    app.abandon_epoch_bound_control_receipts(ControlEpochAbandonment::SameSession);

    assert!(app.pending_control_requests.is_empty());
    assert_eq!(
        app.pending_model_selection.as_ref().unwrap().selection_id,
        successor
    );
    assert_eq!(
        app.pending_tokenizer_confirm.as_ref().unwrap().request_id,
        successor
    );
    assert!(app.current_model_selection_retry().is_none());
    assert!(history_lines(&app).is_empty());
}

// Keep the independent r6 App-boundary regression: accepted receipts use
// the real send helper, queue and event router on both sides of resync.
#[tokio::test]
async fn reviewer_r6_fenced_control_receipt_is_settled_after_resync() {
    use crate::tui::composer_controls::ComposerControlKind;

    for resync in [false, true] {
        for kind in [ComposerControlKind::Approval, ComposerControlKind::Sandbox] {
            for refused in [false, true] {
                let mut app = app();
                let (record_tx, _record_rx) = mpsc::channel(1);
                let (control_tx, mut control_rx) = mpsc::channel(4);
                install_runner(&mut app, record_tx, control_tx);
                let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
                app.visible_attachment_epoch = runner.attachment_epoch();
                app.launch.session_id = Some(runner.session_id());
                let notify = runner.event_notifier();
                app.composer_controls.pending =
                    Some(super::composer_controls::PendingComposerMutation {
                        generation: app.composer_controls.generation,
                        session_id: app.launch.session_id,
                        attachment_epoch: app.visible_attachment_epoch,
                        kind,
                        request_id: None,
                    });
                app.composer_controls.dispatch_armed = true;
                let request = match kind {
                    ComposerControlKind::Approval => Request::SetApprovalMode {
                        mode: ApprovalMode::default(),
                    },
                    ComposerControlKind::Sandbox => Request::SetSandbox {
                        mode: Some(cockpit_proto::SandboxMode::Sandbox),
                        container_network_enabled: None,
                    },
                    _ => unreachable!(),
                };
                app.send_daemon_request("composer", request, ControlApplied::None);
                let control = control_rx.recv().await.unwrap();
                let id = *app.pending_control_requests.keys().next().unwrap();
                assert_eq!(
                    app.composer_controls.pending.as_ref().unwrap().request_id,
                    Some(id)
                );
                if resync {
                    advance_control_epoch(&mut app);
                    assert!(
                        !app.pending_control_requests.contains_key(&id),
                        "retirement itself settles the fenced correlation"
                    );
                    assert!(!app.has_unsettled_local_authority());
                } else {
                    app.invalidate_composer_control_ownership(true, false);
                    assert!(app.pending_control_requests.get(&id).unwrap().fenced);
                    assert!(app.has_unsettled_local_authority());
                }
                assert!(app.composer_controls.pending.is_none());

                // A live successor must survive both the old success and refusal.
                app.send_daemon_request(
                    "/agent",
                    Request::SetAgent {
                        name: "Plan".to_string(),
                    },
                    ControlApplied::PrimaryAgentSwitch {
                        name: "Plan".to_string(),
                    },
                );
                let successor = control_rx.recv().await.unwrap();
                let successor_id = ControlRequestId(app.next_control_request_seq);
                assert_eq!(
                    successor.intended_attachment_epoch,
                    app.visible_attachment_epoch
                );
                let history_before = history_lines(&app)
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<Vec<_>>();
                let response = if refused {
                    Err(crate::tui::agent_runner::ControlRequestError::rejected(
                        "old refusal",
                    ))
                } else {
                    Ok(Response::Ack)
                };
                control.response_tx.send(response).unwrap();
                await_control_receipt(&mut app, &notify).await;
                assert!(
                    !app.pending_control_requests.contains_key(&id),
                    "fenced completed control leaked after resync={resync}"
                );
                assert!(app.pending_control_requests.contains_key(&successor_id));
                assert_eq!(history_lines(&app), history_before);
                assert!(app.composer_controls.picker.is_none());
                assert!(app.exit_check_escape.is_none());
                assert!(!app.exit_requested);

                successor.response_tx.send(Ok(Response::Ack)).unwrap();
                await_control_receipt(&mut app, &notify).await;
                assert!(app.pending_control_requests.is_empty());
                assert!(!app.has_unsettled_local_authority());
                assert!(history_lines(&app).contains(&"Switched primary agent to `Plan`"));
            }
        }
    }
}

fn advance_control_epoch(app: &mut App) {
    app.agent_runner
        .as_ref()
        .unwrap()
        .as_ref()
        .unwrap()
        .attachment_epoch
        .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    app.apply_event(TurnEvent::DaemonLinkResynced {
        active_model_state: None,
    });
}

async fn await_control_receipt(app: &mut App, notify: &tokio::sync::Notify) {
    tokio::time::timeout(std::time::Duration::from_secs(2), notify.notified())
        .await
        .expect("actual accepted-control receipt must be queued");
    assert!(
        app.drain_agent_events(),
        "actual queued receipt must be routed"
    );
}

#[tokio::test]
async fn retired_fenced_exit_receipts_never_confirm_or_arm_escape() {
    for outcome in [
        ControlRequestOutcome::ExitGuardStatus {
            ephemeral_owner: false,
            has_live_work: false,
        },
        ControlRequestOutcome::Unauthorized("old authorization refusal".to_string()),
        ControlRequestOutcome::TransportFailed("old response loss".to_string()),
    ] {
        let mut app = app();
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let events = install_runner(&mut app, record_tx, control_tx);
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        app.launch.session_id = Some(runner.session_id());
        app.visible_attachment_epoch = runner.attachment_epoch();
        app.send_daemon_request(
            "exit check",
            Request::ExitGuardStatus,
            ControlApplied::ExitGuardStatus,
        );
        let old = control_rx.recv().await.unwrap();
        let id = ControlRequestId(app.next_control_request_seq);
        app.fence_pending_control_request(id);
        advance_control_epoch(&mut app);
        assert!(app.pending_control_requests.is_empty());
        assert!(!app.has_unsettled_local_authority());
        assert!(
            control_rx.try_recv().is_err(),
            "a fenced exit must not be reissued"
        );

        // Route the stamped old result, then also check exact-ID reduction
        // cannot revive a retired correlation through an untagged caller.
        events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: old.intended_attachment_epoch,
            event: TurnEvent::ControlRequestFinished {
                request_id: id,
                outcome: outcome.clone(),
            },
        });
        assert!(app.drain_agent_events());
        app.apply_control_request_outcome(id, outcome);
        assert!(app.exit_check_escape.is_none());
        assert!(!app.exit_requested);
        assert!(
            !app.request_guarded_exit(),
            "a fresh check is still required"
        );
        let successor = control_rx.recv().await.unwrap();
        assert!(matches!(successor.request, Request::ExitGuardStatus));
        let notify = app
            .agent_runner
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .event_notifier();
        successor
            .response_tx
            .send(Ok(Response::ExitGuardStatus {
                ephemeral_owner: false,
                has_live_work: false,
            }))
            .unwrap();
        await_control_receipt(&mut app, &notify).await;
        assert!(app.pending_control_requests.is_empty());
        assert!(
            app.exit_requested,
            "a legitimate new-epoch check still completes exit"
        );
        assert!(app.exit_check_escape.is_none());
    }
}

fn default_model_selection() -> cockpit_config::providers::ActiveModelRef {
    cockpit_config::providers::ActiveModelRef {
        provider: "openai".to_string(),
        model: "gpt-test".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    }
}

#[tokio::test]
async fn default_model_epoch_retirement_settles_before_and_after_ack() {
    for ack_before_resync in [false, true] {
        let mut app = app();
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (control_tx, mut control_rx) = mpsc::channel(4);
        let events = install_runner(&mut app, record_tx, control_tx);
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        app.launch.session_id = Some(runner.session_id());
        app.visible_attachment_epoch = runner.attachment_epoch();
        let notify = runner.event_notifier();
        app.request_default_model_only(default_model_selection());
        let old = control_rx.recv().await.unwrap();
        let old_id = app.pending_default_model_update_id.unwrap();
        let old_epoch = old.intended_attachment_epoch;
        let mut old_response = Some(old.response_tx);
        if ack_before_resync {
            old_response
                .take()
                .unwrap()
                .send(Ok(Response::Ack))
                .unwrap();
            await_control_receipt(&mut app, &notify).await;
            assert!(app.pending_control_requests.is_empty());
            assert_eq!(app.pending_default_model_update_id, Some(old_id));
        }
        advance_control_epoch(&mut app);
        assert!(
            app.pending_default_model_update_id.is_none(),
            "epoch-only default-model owner must retire even after Ack removed its control entry"
        );
        assert!(!app.has_unsettled_local_authority());

        app.request_default_model_only(default_model_selection());
        let successor = control_rx.recv().await.unwrap();
        let successor_id = app.pending_default_model_update_id.unwrap();
        assert_ne!(old_id, successor_id);
        let before = history_lines(&app)
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: old_epoch,
            event: default_model_refusal(old_id, "old refusal"),
        });
        events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: old_epoch,
            event: TurnEvent::DefaultModelUpdateResult {
                default_update_id: old_id,
                outcome: cockpit_proto::DefaultModelStandaloneOutcome::Applied {
                    selection: Some(default_model_selection()),
                    generation: 1,
                    authority_revision:
                        "4d8d4cd5bbf18d6ae07e52adf7f0b6a9e5e8f91a9e72d8cb69c6a129e84e400c"
                            .to_string(),
                    scope_label: "user".to_string(),
                    unchanged: false,
                },
            },
        });
        assert!(app.drain_agent_events());
        if let Some(response) = old_response {
            response
                .send(Err(
                    crate::tui::agent_runner::ControlRequestError::rejected("old failed control"),
                ))
                .unwrap();
            await_control_receipt(&mut app, &notify).await;
        }
        assert_eq!(app.pending_default_model_update_id, Some(successor_id));
        assert_eq!(history_lines(&app), before);
        assert!(app.exit_check_escape.is_none());

        successor.response_tx.send(Ok(Response::Ack)).unwrap();
        await_control_receipt(&mut app, &notify).await;
        assert_eq!(app.pending_default_model_update_id, Some(successor_id));
        events.lock().unwrap().push(QueuedTurnEvent {
            attachment_epoch: app.visible_attachment_epoch,
            event: default_model_refusal(successor_id, "successor refusal"),
        });
        assert!(app.drain_agent_events());
        assert!(!app.has_unsettled_local_authority());
        assert!(history_lines(&app).contains(&"Default model was not changed — successor refusal"));
    }
}

fn default_model_refusal(default_update_id: uuid::Uuid, message: &str) -> TurnEvent {
    TurnEvent::DefaultModelUpdateResult {
        default_update_id,
        outcome: cockpit_proto::DefaultModelStandaloneOutcome::Rejected {
            user_message: message.to_string(),
            diagnostic_code: "effective_default_target_unwritable".to_string(),
        },
    }
}

#[tokio::test]
async fn default_model_failed_control_receipts_release_only_their_slot() {
    for code in [
        cockpit_proto::ErrorCode::Internal,
        cockpit_proto::ErrorCode::Authorization,
    ] {
        let mut app = app();
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (control_tx, mut control_rx) = mpsc::channel(4);
        install_runner(&mut app, record_tx, control_tx);
        let notify = app
            .agent_runner
            .as_ref()
            .unwrap()
            .as_ref()
            .unwrap()
            .event_notifier();
        let refusal = || {
            crate::tui::agent_runner::control_request_result(Ok(Err(cockpit_proto::ErrorPayload {
                code: code.clone(),
                message: "default write refused".to_string(),
            })))
        };
        app.request_default_model_only(default_model_selection());
        let old = control_rx.recv().await.unwrap();
        app.request_default_model_only(default_model_selection());
        let successor = control_rx.recv().await.unwrap();
        let successor_id = app.pending_default_model_update_id.unwrap();
        old.response_tx.send(refusal()).unwrap();
        await_control_receipt(&mut app, &notify).await;
        assert_eq!(app.pending_default_model_update_id, Some(successor_id));
        successor.response_tx.send(refusal()).unwrap();
        await_control_receipt(&mut app, &notify).await;
        assert!(app.pending_default_model_update_id.is_none());
        assert!(!app.has_unsettled_local_authority());
        assert!(app.exit_check_escape.is_none());

        app.request_default_model_only(default_model_selection());
        control_rx
            .recv()
            .await
            .unwrap()
            .response_tx
            .send(Err("delivery unknown".to_string().into()))
            .unwrap();
        await_control_receipt(&mut app, &notify).await;
        assert!(app.pending_default_model_update_id.is_none());
        assert!(!app.has_unsettled_local_authority());
        assert!(app.exit_check_escape.is_none());
    }
}

#[test]
fn default_model_non_delivery_never_leaves_a_confirmation_owner() {
    let mut detached = app();
    detached.request_default_model_only(default_model_selection());
    assert!(detached.pending_default_model_update_id.is_none());
    assert!(!detached.has_unsettled_local_authority());
    for full in [false, true] {
        let mut app = app();
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (control_tx, control_rx) = mpsc::channel(1);
        if full {
            control_tx.try_send(dummy_control_request()).unwrap();
        } else {
            drop(control_rx);
        }
        install_runner(&mut app, record_tx, control_tx);
        app.request_default_model_only(default_model_selection());
        assert!(app.pending_default_model_update_id.is_none());
        assert!(app.pending_control_requests.is_empty());
        assert!(!app.has_unsettled_local_authority());
        assert!(app.exit_check_escape.is_none());
    }
}
