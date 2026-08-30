use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use super::{App, ControlApplied};
use crate::tui::agent_runner::{
    AgentRunner, ControlRequest, QueuedTurnEvent, TestRunnerOverrides, control_response_outcome,
};
use crate::tui::history::HistoryEntry;
use cockpit_client::presentation::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, TurnEvent,
};
use cockpit_core::config::extended::ApprovalMode;
use cockpit_proto::{Request, Response};

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
