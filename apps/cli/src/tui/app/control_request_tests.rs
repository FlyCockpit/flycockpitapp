use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};

use super::{App, ControlApplied};
use crate::daemon::proto::{Request, Response};
use crate::engine::message::UserSubmission;
use crate::engine::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, TurnEvent,
};
use crate::tui::agent_runner::{AgentRunner, ClientTasks, ControlRequest, UsageCounts};
use crate::tui::history::HistoryEntry;

fn app() -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = crate::tui::settings::Dialog::None;
    app
}

fn runner_with_channels(
    record_tx: mpsc::Sender<Request>,
    control_tx: mpsc::Sender<ControlRequest>,
    events: Arc<Mutex<Vec<TurnEvent>>>,
) -> AgentRunner {
    let (input_tx, _input_rx) = mpsc::channel::<UserSubmission>(1);
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

fn install_runner(
    app: &mut App,
    record_tx: mpsc::Sender<Request>,
    control_tx: mpsc::Sender<ControlRequest>,
) -> Arc<Mutex<Vec<TurnEvent>>> {
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

#[tokio::test]
async fn control_request_full_channel_reports_not_delivered() {
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

#[tokio::test]
async fn control_request_without_runner_reports_not_delivered() {
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

#[tokio::test]
async fn control_request_stale_ack_is_ignored() {
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
