use super::{
    App, FooterAgentPicker, FooterHitArea, FooterModePicker, FooterPickerKind, FooterPickerRowHit,
    HistoryEntry, Overlay,
};
use crate::tui::agent_runner::{AgentRunner, ClientTasks, ControlRequest, UsageCounts};
use crate::tui::settings::Dialog;
use cockpit_config::extended::LlmMode;
use cockpit_core::daemon::proto::Request;
use cockpit_core::engine::message::UserSubmission;
use cockpit_core::engine::{ControlRequestId, ControlRequestOutcome, TurnEvent};
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::Rect;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn click(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

fn app(tmp: &tempfile::TempDir) -> App {
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = Dialog::None;
    app
}

fn runner_with_control_tx(control_tx: mpsc::Sender<ControlRequest>) -> AgentRunner {
    let (input_tx, _input_rx) = mpsc::channel::<UserSubmission>(8);
    let (record_tx, _record_rx) = mpsc::channel(1);
    let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
    AgentRunner {
        input_tx,
        record_tx,
        control_tx,
        attached_request_tx,
        events: Arc::new(Mutex::new(Vec::new())),
        event_notify: Arc::new(tokio::sync::Notify::new()),
        active_agent: Arc::new(Mutex::new("Build".to_string())),
        active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
        skill_inventory_names: Arc::new(Mutex::new(None)),
        foreground_target: Some(cockpit_core::engine::message::QueueTarget::root("Build")),
        active_model_state: None,
        session_id_state: Arc::new(Mutex::new(uuid::Uuid::new_v4())),
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
        last_applied_seq: None,
        client_tasks: ClientTasks::default(),
    }
}

fn app_with_runner(tmp: &tempfile::TempDir) -> (App, mpsc::Receiver<ControlRequest>) {
    let mut app = app(tmp);
    let (control_tx, control_rx) = mpsc::channel(8);
    app.agent_runner = Some(Ok(runner_with_control_tx(control_tx)));
    (app, control_rx)
}

fn write_model_config(root: &std::path::Path) {
    let cockpit = root.join(".cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    fs::write(&config_path, "{}").unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
    fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    fs::write(
        provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a"}]}"#,
    )
    .unwrap();
}

fn write_favorite_model_config(root: &std::path::Path) {
    let cockpit = root.join(".cockpit");
    fs::create_dir_all(&cockpit).unwrap();
    let config_path = cockpit.join("config.json");
    fs::write(
        &config_path,
        r#"{"active_model":{"provider":"p","model":"a"}}"#,
    )
    .unwrap();
    let provider_path =
        cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
    fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
    fs::write(
        provider_path,
        r#"{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b","favorite":true}]}"#,
    )
    .unwrap();
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
fn footer_enter_opens_selector_for_each_axis() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_model_config(tmp.path());
    let mut app = app(&tmp);

    app.footer_selection = Some(crate::tui::chrome::FooterControl::Agent);
    app.handle_key(press(KeyCode::Enter));
    assert!(app.footer_agent_picker.is_some());
    assert!(!matches!(app.overlay, Overlay::ModelPicker(_)));

    app.footer_agent_picker = None;
    app.footer_selection = Some(crate::tui::chrome::FooterControl::Model);
    app.handle_key(press(KeyCode::Enter));
    assert!(matches!(app.overlay, Overlay::ModelPicker(_)));

    app.overlay = Overlay::None;
    app.footer_selection = Some(crate::tui::chrome::FooterControl::Mode);
    app.handle_key(press(KeyCode::Enter));
    assert!(app.footer_mode_picker.is_some());
}

#[test]
fn quick_dialog_space_stages_without_daemon_request_enter_commits() {
    let tmp = tempfile::tempdir().unwrap();
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    write_favorite_model_config(tmp.path());
    let (mut app, mut rx) = app_with_runner(&tmp);
    let config_path = tmp.path().join(".cockpit").join("config.json");
    let before = fs::read_to_string(&config_path).unwrap();

    app.open_quick_dialog();
    assert!(matches!(app.overlay, Overlay::Quick(_)));

    // Mode tab opens on the current defensive row. Move to normal and
    // stage it locally; no request should be sent until Enter.
    app.handle_key(press(KeyCode::Up));
    app.handle_key(press(KeyCode::Char(' ')));
    assert!(
        rx.try_recv().is_err(),
        "Space must not send daemon requests"
    );
    assert!(
        matches!(app.overlay, Overlay::Quick(_)),
        "Space keeps the dialog open"
    );

    app.handle_key(press(KeyCode::Enter));
    assert!(
        !matches!(app.overlay, Overlay::Quick(_)),
        "Enter closes after commit"
    );
    match rx.try_recv().expect("quick commit sends a request").request {
        Request::SetSessionLlmMode { mode } => {
            assert_eq!(mode, cockpit_config::extended::LlmMode::Normal);
        }
        other => panic!("expected session-only LLM mode request, got {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(&config_path).unwrap(),
        before,
        "/quick must not write config defaults"
    );
}

#[test]
fn footer_mouse_capture_gates_footer_hits_and_second_click_opens() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.footer_hit_areas = vec![FooterHitArea {
        control: crate::tui::chrome::FooterControl::Agent,
        rect: Rect::new(2, 9, 6, 1),
    }];

    app.mouse_capture = false;
    app.handle_mouse(click(3, 9));
    assert!(app.footer_selection.is_none());

    app.mouse_capture = true;
    app.handle_mouse(click(3, 9));
    assert_eq!(
        app.footer_selection,
        Some(crate::tui::chrome::FooterControl::Agent)
    );
    assert!(app.footer_agent_picker.is_none());

    app.handle_mouse(click(3, 9));
    assert!(app.footer_agent_picker.is_some());
}

#[test]
fn agent_picker_mouse_row_commits_through_set_agent() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.mouse_capture = true;
    app.footer_agent_picker = Some(FooterAgentPicker::new("Build", vec!["Build".to_string()]));
    app.footer_picker_row_hits = vec![FooterPickerRowHit {
        kind: FooterPickerKind::Agent,
        index: 0,
        rect: Rect::new(0, 4, 20, 1),
    }];

    app.handle_mouse(click(1, 4));

    assert!(app.footer_agent_picker.is_none());
    assert!(matches!(
        control_rx.try_recv().unwrap().request,
        Request::SetAgent { name } if name == "Build"
    ));
}

#[test]
fn mode_picker_mouse_row_commits_through_llm_mode_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.mouse_capture = true;
    app.llm_mode = LlmMode::Normal;
    app.footer_mode_picker = Some(FooterModePicker::new(LlmMode::Normal));
    app.footer_picker_row_hits = vec![FooterPickerRowHit {
        kind: FooterPickerKind::Mode,
        index: 2,
        rect: Rect::new(0, 5, 20, 1),
    }];

    app.handle_mouse(click(1, 5));

    assert!(app.footer_mode_picker.is_none());
    assert!(matches!(
        control_rx.try_recv().unwrap().request,
        Request::SetLlmMode {
            mode: Some(LlmMode::Frontier)
        }
    ));
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
fn swarm_warning_is_inserted_only_when_switch_line_locks() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);

    app.record_primary_switch_confirmation("Swarm");
    assert_eq!(plain_lines(&app), vec!["Switched primary agent to `Swarm`"]);

    app.lock_pending_agent_switch_log();
    assert_eq!(
        plain_lines(&app),
        vec![
            super::SWARM_TOKEN_BURN_WARNING,
            "Switched primary agent to `Swarm`"
        ]
    );
}
