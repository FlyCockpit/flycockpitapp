use super::{App, HistoryEntry};
use crate::tui::agent_runner::{AgentRunner, ControlRequest};
use crate::tui::settings::Dialog;
use cockpit_client::presentation::{ControlRequestId, ControlRequestOutcome, TurnEvent};
use cockpit_proto::Request;
use tokio::sync::mpsc;

fn app(tmp: &tempfile::TempDir) -> App {
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = Dialog::None;
    app
}

fn app_with_runner(tmp: &tempfile::TempDir) -> (App, mpsc::Receiver<ControlRequest>) {
    let mut app = app(tmp);
    let (control_tx, control_rx) = mpsc::channel(8);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    (app, control_rx)
}

fn plain_lines(app: &App) -> Vec<&str> {
    app.history
        .iter()
        .filter_map(|entry| match entry {
            HistoryEntry::Plain { line } => Some(line.as_str()),
            _ => None,
        })
        .collect()
}

#[test]
fn agent_switch_success_lines_coalesce_until_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);

    app.swap_primary_agent("Build");
    app.swap_primary_agent("Custom");

    assert!(matches!(
        control_rx.try_recv().unwrap().request,
        Request::SetAgent { name } if name == "Build"
    ));
    assert!(matches!(
        control_rx.try_recv().unwrap().request,
        Request::SetAgent { name } if name == "Custom"
    ));
    app.apply_event(TurnEvent::ControlRequestFinished {
        request_id: ControlRequestId(1),
        outcome: ControlRequestOutcome::Applied,
    });
    app.apply_event(TurnEvent::ControlRequestFinished {
        request_id: ControlRequestId(2),
        outcome: ControlRequestOutcome::Applied,
    });
    assert_eq!(
        plain_lines(&app)
            .into_iter()
            .filter(|line| line.starts_with("Switched primary agent"))
            .collect::<Vec<_>>(),
        vec!["Switched primary agent to `Custom`"]
    );

    app.lock_pending_agent_switch_log();
    app.swap_primary_agent("Build");
    assert!(matches!(
        control_rx.try_recv().unwrap().request,
        Request::SetAgent { name } if name == "Build"
    ));
    app.apply_event(TurnEvent::ControlRequestFinished {
        request_id: ControlRequestId(3),
        outcome: ControlRequestOutcome::Applied,
    });
    assert_eq!(
        plain_lines(&app)
            .into_iter()
            .filter(|line| line.starts_with("Switched primary agent"))
            .collect::<Vec<_>>(),
        vec![
            "Switched primary agent to `Custom`",
            "Switched primary agent to `Build`"
        ]
    );
}

#[test]
fn roster_trim_primary_switch_confirmation_has_no_swarm_warning() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);

    app.record_primary_switch_confirmation("Swarm");
    assert_eq!(plain_lines(&app), vec!["Switched primary agent to `Swarm`"]);

    app.lock_pending_agent_switch_log();
    assert_eq!(plain_lines(&app), vec!["Switched primary agent to `Swarm`"]);
}
