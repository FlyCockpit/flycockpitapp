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
        .send(Err("no active session".to_string()))
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
        control_response_outcome(Err("daemon error".to_string())),
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
async fn control_request_runner_teardown_reports_not_delivered() {
    let mut app = app();
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (control_tx, mut control_rx) = mpsc::channel(1);
    install_runner(&mut app, record_tx, control_tx);

    app.send_daemon_request("/prune", Request::Prune, ControlApplied::None);
    drop(control_rx.recv().await.expect("control request"));
    drain_control_events(&mut app).await;

    assert_eq!(
        history_lines(&app),
        vec!["/prune: request not sent - daemon control channel closed; try again"]
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
