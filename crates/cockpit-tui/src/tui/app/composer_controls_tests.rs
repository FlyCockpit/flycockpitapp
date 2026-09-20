//! Composer control deck, hierarchical pickers, queue ladder, and parity
//! proofs for the #397 replacement.

use super::{App, HistoryEntry, Overlay, StartupWorkspaceTrust};
use crate::tui::agent_runner::{AgentRunner, ControlRequest};
use crate::tui::chat_header::HeaderPillKind;
use crate::tui::composer::VimMode;
use crate::tui::composer_controls::{
    COMPOSER_CONTROL_PROBE_WIDTHS, ComposerControlKind, capability_parity_table,
};
use crate::tui::tools_pane::ToolsOutcome;
use cockpit_client::presentation::{ControlRequestId, ControlRequestOutcome};
use cockpit_config::extended::ApprovalMode;
use cockpit_config::providers::{
    ActiveModelRef, CapabilityValue, ModelEntry, ProviderEntry, ReasoningEffortCapability,
    ThinkingMode,
};
use cockpit_core::agents::{ToolTier, legal_tool_tiers};
use cockpit_proto::{QueueDeliveryClass, QueueItemStatus, QueueTarget, Request, SandboxMode};
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::{Terminal, backend::TestBackend};
use tokio::sync::mpsc;
use uuid::Uuid;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn ctrl(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
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
    let mut app =
        App::new_with_workspace_trust(Some(tmp.path()), false, StartupWorkspaceTrust::Decided);
    app.dialog = crate::tui::settings::Dialog::None;
    app.launch.banner_enabled = false;
    app.mouse_capture = true;
    app.launch.agent_name = "Build".to_string();
    app.launch.active_model = Some(("openai".to_string(), "gpt-test".to_string()));
    app.active_model_selection = Some(ActiveModelRef {
        provider: "openai".to_string(),
        model: "gpt-test".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    app.config_snapshot.providers.providers.insert(
        "openai".to_string(),
        ProviderEntry {
            models: vec![
                ModelEntry {
                    id: "gpt-test".to_string(),
                    ..Default::default()
                },
                ModelEntry {
                    id: "gpt-other".to_string(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
    );
    app
}

fn app_with_runner(tmp: &tempfile::TempDir) -> (App, mpsc::Receiver<ControlRequest>) {
    let mut app = app(tmp);
    let (control_tx, control_rx) = mpsc::channel(8);
    app.agent_runner = Some(Ok(AgentRunner::stub_with_control_tx(control_tx)));
    (app, control_rx)
}

fn render(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test backend");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    terminal.backend().buffer().clone()
}

fn row_text(buf: &ratatui::buffer::Buffer, y: u16) -> String {
    (0..buf.area.width)
        .map(|x| buf[(x, y)].symbol().to_string())
        .collect()
}

fn queue_item(text: &str, class: QueueDeliveryClass) -> cockpit_proto::QueueItem {
    cockpit_proto::QueueItem {
        id: Uuid::new_v4(),
        status: QueueItemStatus::Queued,
        text: text.to_string(),
        display_text: None,
        target: QueueTarget::root("Build"),
        delivery_class: class,
        send_now: false,
    }
}

#[test]
fn key_router_precedence_matrix_covers_every_focus_and_picker_state() {
    use super::input::KeyRouterStage;

    #[derive(Clone, Copy, Debug)]
    enum FocusState {
        Composer,
        Queue,
        Btw,
        Rail,
    }

    #[derive(Clone, Copy, Debug)]
    enum PickerState {
        Closed,
        Model,
        Effort,
    }

    #[derive(Clone, Copy, Debug)]
    enum Chord {
        CtrlP,
        CtrlE,
        CtrlB,
        CtrlN,
        CtrlKb,
        CtrlKn,
        CtrlKr,
        CtrlUp,
        AltUp,
        AltDown,
        Enter,
        Esc,
        Up,
        Down,
        CtrlJ,
    }

    impl Chord {
        fn keys(self) -> Vec<KeyEvent> {
            match self {
                Self::CtrlP => vec![ctrl(KeyCode::Char('p'))],
                Self::CtrlE => vec![ctrl(KeyCode::Char('e'))],
                Self::CtrlB => vec![ctrl(KeyCode::Char('b'))],
                Self::CtrlN => vec![ctrl(KeyCode::Char('n'))],
                Self::CtrlKb => vec![ctrl(KeyCode::Char('k')), press(KeyCode::Char('b'))],
                Self::CtrlKn => vec![ctrl(KeyCode::Char('k')), press(KeyCode::Char('n'))],
                Self::CtrlKr => vec![ctrl(KeyCode::Char('k')), press(KeyCode::Char('r'))],
                Self::CtrlUp => vec![ctrl(KeyCode::Up)],
                Self::AltUp => vec![KeyEvent::new(KeyCode::Up, KeyModifiers::ALT)],
                Self::AltDown => vec![KeyEvent::new(KeyCode::Down, KeyModifiers::ALT)],
                Self::Enter => vec![press(KeyCode::Enter)],
                Self::Esc => vec![press(KeyCode::Esc)],
                Self::Up => vec![press(KeyCode::Up)],
                Self::Down => vec![press(KeyCode::Down)],
                Self::CtrlJ => vec![ctrl(KeyCode::Char('j'))],
            }
        }

        fn expected(self, focus: FocusState, picker: PickerState) -> KeyRouterStage {
            match self {
                Self::CtrlP
                | Self::CtrlE
                | Self::CtrlB
                | Self::CtrlN
                | Self::CtrlKb
                | Self::CtrlKn
                | Self::CtrlKr
                | Self::CtrlJ => KeyRouterStage::CtrlChord,
                Self::AltUp | Self::AltDown => KeyRouterStage::AltChord,
                Self::CtrlUp | Self::Enter | Self::Esc | Self::Up | Self::Down
                    if !matches!(picker, PickerState::Closed) =>
                {
                    KeyRouterStage::ComposerPicker
                }
                Self::Enter | Self::Esc | Self::Up | Self::Down => match focus {
                    FocusState::Queue => KeyRouterStage::Queue,
                    FocusState::Btw if matches!(self, Self::Enter | Self::Esc) => {
                        KeyRouterStage::Btw
                    }
                    FocusState::Rail => KeyRouterStage::Rail,
                    FocusState::Composer | FocusState::Btw => KeyRouterStage::Composer,
                },
                Self::CtrlUp => match focus {
                    FocusState::Rail => KeyRouterStage::Rail,
                    FocusState::Composer | FocusState::Queue | FocusState::Btw => {
                        KeyRouterStage::Composer
                    }
                },
            }
        }
    }

    const FOCUSES: [FocusState; 4] = [
        FocusState::Composer,
        FocusState::Queue,
        FocusState::Btw,
        FocusState::Rail,
    ];
    const PICKERS: [PickerState; 3] =
        [PickerState::Closed, PickerState::Model, PickerState::Effort];
    const CHORDS: [Chord; 15] = [
        Chord::CtrlP,
        Chord::CtrlE,
        Chord::CtrlB,
        Chord::CtrlN,
        Chord::CtrlKb,
        Chord::CtrlKn,
        Chord::CtrlKr,
        Chord::CtrlUp,
        Chord::AltUp,
        Chord::AltDown,
        Chord::Enter,
        Chord::Esc,
        Chord::Up,
        Chord::Down,
        Chord::CtrlJ,
    ];

    for picker in PICKERS {
        for focus in FOCUSES {
            for chord in CHORDS {
                let tmp = tempfile::tempdir().unwrap();
                let mut app = app(&tmp);
                match picker {
                    PickerState::Closed => {}
                    PickerState::Model => {
                        app.composer_controls.selection = Some(ComposerControlKind::Model);
                        app.open_composer_picker(ComposerControlKind::Model);
                    }
                    PickerState::Effort => {
                        app.composer_controls.selection = Some(ComposerControlKind::Effort);
                        app.open_composer_picker(ComposerControlKind::Effort);
                    }
                }
                match focus {
                    FocusState::Composer => {}
                    FocusState::Queue => {
                        let item = queue_item("queued", QueueDeliveryClass::Held);
                        app.queue_focus = Some(item.id);
                        app.queue.push(item);
                    }
                    FocusState::Btw => {
                        app.btw_pane = Some(super::btw_pane::BtwPane::new(
                            cockpit_proto::BtwForkInfo {
                                session_id: Uuid::new_v4(),
                                parent_session_id: Uuid::new_v4(),
                                short_id: Some("btw001".to_string()),
                                tangent: false,
                                created_at: 1,
                                message_count: 0,
                            },
                            false,
                        ));
                        app.btw_pane.as_mut().expect("btw pane").focused = true;
                    }
                    FocusState::Rail => app.session_rail.focus(),
                }

                let keys = chord.keys();
                let mut actual = KeyRouterStage::Composer;
                for (index, key) in keys.iter().copied().enumerate() {
                    actual = app
                        .handle_precedence_key(key)
                        .unwrap_or(KeyRouterStage::Composer);
                    if index + 1 < keys.len() {
                        assert_eq!(
                            actual,
                            KeyRouterStage::CtrlChord,
                            "leader must own prefix: chord={chord:?} focus={focus:?} picker={picker:?}"
                        );
                    }
                }
                assert_eq!(
                    actual,
                    chord.expected(focus, picker),
                    "chord={chord:?} focus={focus:?} picker={picker:?}"
                );
            }
        }
    }
}

fn bottom_border(buf: &ratatui::buffer::Buffer, app: &App) -> String {
    let area = app.input_area.expect("input rendered");
    row_text(buf, area.y + area.height.saturating_sub(1))
}

#[test]
fn composer_bottom_border_has_five_pills_then_send_at_wide_and_narrow() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    for width in COMPOSER_CONTROL_PROBE_WIDTHS {
        let buf = render(&mut app, width, 24);
        let layout = app
            .composer_controls
            .layout
            .clone()
            .expect("composer deck planned");
        let kinds = layout.active_kinds();
        assert_eq!(kinds.first().copied(), Some(ComposerControlKind::Agent));
        for window in kinds.windows(2) {
            assert!(window[0] < window[1], "order at {width}: {kinds:?}");
        }
        assert!(
            layout.send_button.is_some(),
            "Send/Queue present at {width}"
        );
        let border = bottom_border(&buf, &app);
        assert!(
            !border.to_lowercase().contains("compact"),
            "no compact on bottom border at {width}: {border:?}"
        );
        assert!(
            !border.to_lowercase().contains("export"),
            "no export on bottom border at {width}: {border:?}"
        );
        assert!(
            !border.to_lowercase().contains("tools"),
            "no tools on bottom border at {width}: {border:?}"
        );
        assert_eq!(
            kinds,
            ComposerControlKind::ALL.to_vec(),
            "all five pills at {width}"
        );
        assert!(border.contains("[Send]") || border.contains("Send"));
    }
}

#[test]
fn working_swaps_send_for_queue() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.busy = true;
    let buf = render(&mut app, 120, 24);
    let border = bottom_border(&buf, &app);
    assert!(
        border.contains("[Queue]") || border.contains("Queue"),
        "{border:?}"
    );
    assert!(!border.contains("[Send]"), "{border:?}");
}

#[test]
fn composer_pills_open_hierarchical_pickers() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    app.activate_composer_pill(ComposerControlKind::Model);
    let picker = app.composer_controls.picker.as_ref().expect("model picker");
    assert_eq!(picker.kind, ComposerControlKind::Model);
    assert!(
        !picker.categories.is_empty(),
        "model picker has provider categories"
    );
    app.activate_composer_pill(ComposerControlKind::Agent);
    let picker = app.composer_controls.picker.as_ref().expect("agent picker");
    assert_eq!(picker.kind, ComposerControlKind::Agent);
    app.activate_composer_pill(ComposerControlKind::Approval);
    let picker = app
        .composer_controls
        .picker
        .as_ref()
        .expect("approval picker");
    assert_eq!(picker.kind, ComposerControlKind::Approval);
    assert_eq!(picker.level, 1, "single-category approval opens at items");
}

#[test]
fn ctrl_p_opens_composer_model_menu_through_router_and_keyboard_moves() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    app.handle_key(ctrl(KeyCode::Char('p')));
    assert_eq!(
        app.composer_controls.selection,
        Some(ComposerControlKind::Model)
    );
    let picker = app.composer_controls.picker.as_ref().expect("open");
    assert_eq!(picker.kind, ComposerControlKind::Model);
    assert_eq!(picker.level, 0, "Ctrl+P always starts at providers");
    app.handle_key(press(KeyCode::Enter));
    let before = app.composer_controls.picker.as_ref().expect("open").cursor;
    app.handle_key(press(KeyCode::Down));
    let after = app
        .composer_controls
        .picker
        .as_ref()
        .expect("still open")
        .cursor;
    assert_ne!(before, after);
    app.handle_key(press(KeyCode::Esc));
    assert_eq!(
        app.composer_controls
            .picker
            .as_ref()
            .expect("provider list")
            .level,
        0
    );
    app.handle_key(press(KeyCode::Esc));
    assert!(app.composer_controls.picker.is_none());
}

#[test]
fn composer_picker_mouse_opens_from_pill() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    let layout = app.composer_controls.layout.clone().expect("layout");
    let agent = layout.pill_rect(ComposerControlKind::Agent).expect("agent");
    app.handle_mouse(click(agent.x, agent.y));
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: agent.x,
        row: agent.y,
        modifiers: KeyModifiers::empty(),
    });
    assert!(
        app.composer_controls
            .picker
            .as_ref()
            .is_some_and(|p| p.kind == ComposerControlKind::Agent)
    );
}

#[test]
fn ctrl_e_opens_effort_picker_through_router() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let model = &mut app
        .config_snapshot
        .providers
        .providers
        .get_mut("openai")
        .expect("provider")
        .models[0];
    model.capabilities.reasoning_effort = Some(ReasoningEffortCapability {
        values: vec![CapabilityValue {
            value: "medium".to_string(),
            label: Some("Balanced".to_string()),
            description: None,
        }],
        ..Default::default()
    });
    model.thinking_modes = vec![ThinkingMode::Low, ThinkingMode::High];
    let _ = render(&mut app, 120, 24);

    app.handle_key(ctrl(KeyCode::Char('e')));

    assert_eq!(
        app.composer_controls.selection,
        Some(ComposerControlKind::Effort)
    );
    let picker = app
        .composer_controls
        .picker
        .as_ref()
        .expect("effort picker");
    assert_eq!(picker.kind, ComposerControlKind::Effort);
    assert_eq!(
        picker
            .categories
            .iter()
            .map(|category| category.id.as_str())
            .collect::<Vec<_>>(),
        ["effort"],
        "native reasoning effort and legacy thinking modes remain available"
    );
    assert!(
        picker.categories[0]
            .items
            .iter()
            .any(|item| item.id == "thinking:high"),
        "legacy thinking modes are included in the effort choices"
    );
}

#[test]
fn ctrl_b_and_ctrl_n_route_to_session_seams() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    assert!(!app.session_rail.is_focused());
    assert!(!app.pending_new_session);

    app.handle_key(ctrl(KeyCode::Char('b')));
    assert!(app.session_rail.is_focused());
    app.handle_key(ctrl(KeyCode::Char('b')));
    assert!(!app.session_rail.is_focused());

    app.handle_key(ctrl(KeyCode::Char('n')));
    assert!(app.pending_new_session);
}

#[test]
fn ctrl_b_dismisses_an_open_picker_before_focusing_the_session_rail() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    app.handle_key(ctrl(KeyCode::Char('p')));
    assert!(app.composer_controls.picker.is_some());

    app.handle_key(ctrl(KeyCode::Char('b')));

    assert!(app.session_rail.is_focused());
    assert!(
        app.composer_controls.picker.is_none(),
        "rail focus must release picker ownership of arrows and Enter"
    );
    assert!(app.composer_controls.selection.is_none());
}

#[test]
fn ctrl_j_focuses_rail_while_picker_open_instead_of_committing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    app.handle_key(ctrl(KeyCode::Char('p')));
    assert!(app.composer_controls.picker.is_some());

    app.handle_key(ctrl(KeyCode::Char('j')));

    assert!(
        app.session_rail.is_focused(),
        "Ctrl+J must keep focusing the session rail while a picker is open"
    );
    assert!(app.composer_controls.picker.is_none());
    assert_eq!(
        app.launch.active_model,
        Some(("openai".to_string(), "gpt-test".to_string())),
        "Ctrl+J must not commit the highlighted picker row"
    );
}

#[test]
fn ctrl_m_is_the_cr_alias_for_picker_enter() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    app.handle_key(ctrl(KeyCode::Char('p')));
    assert_eq!(
        app.composer_controls.picker.as_ref().expect("open").level,
        0,
        "providers level"
    );

    // Under the kitty keyboard protocol a literal Ctrl+M press is reported
    // as Char('m') + CONTROL, not Enter; it must still commit.
    app.handle_key(ctrl(KeyCode::Char('m')));

    let picker = app.composer_controls.picker.as_ref().expect("still open");
    assert_eq!(
        picker.level, 1,
        "Ctrl+M drills into the provider like Enter"
    );
}

#[test]
fn ctrl_p_opens_the_picker_replacing_an_open_overlay_pane() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    // Open a real overlay pane through the router (which-key → scratchpad).
    app.handle_key(ctrl(KeyCode::Char('k')));
    app.handle_key(press(KeyCode::Char('n')));
    assert!(matches!(app.overlay, Overlay::Notes(_)));

    app.handle_key(ctrl(KeyCode::Char('p')));

    assert!(
        matches!(app.overlay, Overlay::None),
        "the picker chord replaces the open pane (excoc tui.rs:172)"
    );
    assert!(
        app.composer_controls
            .picker
            .as_ref()
            .is_some_and(|picker| picker.kind == ComposerControlKind::Model)
    );
}

#[test]
fn focused_btw_cannot_intercept_composer_model_menu_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    let _ = render(&mut app, 120, 24);
    app.btw_pane = Some(super::btw_pane::BtwPane::new(
        cockpit_proto::BtwForkInfo {
            session_id: Uuid::new_v4(),
            parent_session_id: Uuid::new_v4(),
            short_id: Some("btw001".to_string()),
            tangent: false,
            created_at: 1,
            message_count: 0,
        },
        false,
    ));
    let pane = app.btw_pane.as_mut().expect("btw pane");
    pane.focused = true;
    pane.composer.insert_str("side draft");

    app.handle_key(ctrl(KeyCode::Char('p')));
    app.handle_key(press(KeyCode::Enter));
    app.handle_key(press(KeyCode::Up));
    app.handle_key(press(KeyCode::Enter));

    match control_rx
        .try_recv()
        .expect("picker commit sends SetActiveModel")
        .request
    {
        Request::SetActiveModel {
            model,
            persist_as_default,
            ..
        } => {
            assert_eq!(model, "gpt-other");
            assert!(!persist_as_default, "plain Enter is session-only");
        }
        other => panic!("expected SetActiveModel, got {other:?}"),
    }
    let pane = app.btw_pane.as_ref().expect("btw pane");
    assert!(
        pane.focused,
        "the picker does not silently change pane focus"
    );
    assert_eq!(pane.composer.text(), "side draft");
    assert!(
        pane.history.is_empty(),
        "picker Enter must not send or error in the side composer"
    );
}

#[test]
fn queue_reentry_cannot_intercept_composer_model_menu_navigation_or_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    let queued = queue_item("keep queued", QueueDeliveryClass::Held);
    let queued_id = queued.id;
    app.queue.push(queued);
    let _ = render(&mut app, 120, 24);

    app.handle_key(ctrl(KeyCode::Up));
    assert_eq!(
        app.queue_focus,
        Some(queued_id),
        "Ctrl+Up focuses the queue"
    );

    app.handle_key(ctrl(KeyCode::Char('p')));
    assert!(
        app.queue_focus.is_none(),
        "opening a modal picker relinquishes queue key ownership"
    );
    app.handle_key(ctrl(KeyCode::Up));
    assert!(
        app.queue_focus.is_none(),
        "Ctrl+Up after opening must remain picker-owned instead of re-entering the queue"
    );
    assert!(
        app.composer_controls.picker.is_some(),
        "Ctrl+Up keeps the picker open"
    );
    app.handle_key(press(KeyCode::Enter));
    assert_eq!(
        app.composer_controls.picker.as_ref().expect("open").level,
        1,
        "Enter drills into the provider"
    );
    app.handle_key(press(KeyCode::Up));
    let picker = app.composer_controls.picker.as_ref().expect("open");
    assert_eq!(
        picker.categories[picker.category].items[picker.cursor].id,
        "gpt-other"
    );
    app.handle_key(press(KeyCode::Enter));

    match control_rx
        .try_recv()
        .expect("picker commit sends SetActiveModel")
        .request
    {
        Request::SetActiveModel {
            model,
            persist_as_default,
            ..
        } => {
            assert_eq!(model, "gpt-other");
            assert!(!persist_as_default, "plain Enter is session-only");
        }
        other => panic!("expected SetActiveModel, got {other:?}"),
    }
    assert_eq!(app.queue.len(), 1, "picker keys do not alter the queue");
    assert_eq!(app.queue[0].id, queued_id);
    assert_eq!(app.queue[0].text, "keep queued");
}

#[test]
fn ctrl_k_router_dispatches_b_n_and_r_continuations() {
    let tmp = tempfile::tempdir().unwrap();

    let mut btw = app(&tmp);
    btw.btw_pane = Some(super::btw_pane::BtwPane::new(
        cockpit_proto::BtwForkInfo {
            session_id: Uuid::new_v4(),
            parent_session_id: Uuid::new_v4(),
            short_id: Some("btw001".to_string()),
            tangent: false,
            created_at: 1,
            message_count: 0,
        },
        false,
    ));
    btw.handle_key(ctrl(KeyCode::Char('k')));
    btw.handle_key(press(KeyCode::Char('b')));
    assert!(btw.btw_pane.as_ref().expect("btw pane").focused);

    let pane = btw.btw_pane.as_mut().expect("btw pane");
    pane.composer.insert_str("draft");
    btw.handle_key(ctrl(KeyCode::Char('k')));
    btw.handle_key(press(KeyCode::Char('b')));
    let pane = btw.btw_pane.as_ref().expect("btw pane");
    assert!(
        !pane.focused,
        "Ctrl+K b must also leave a focused /btw pane"
    );
    assert_eq!(
        pane.composer.text(),
        "draft",
        "the leader continuation must not be inserted into /btw"
    );

    btw.btw_pane.as_mut().expect("btw pane").focused = true;
    btw.handle_key(ctrl(KeyCode::Char('b')));
    assert!(
        btw.session_rail.is_focused(),
        "bare Ctrl+B uses the global session-sidebar seam"
    );
    assert!(
        btw.btw_pane.as_ref().expect("btw pane").focused,
        "bare Ctrl+B must not trigger the old /btw focus toggle"
    );

    let mut scratchpad = app(&tmp);
    scratchpad.handle_key(ctrl(KeyCode::Char('k')));
    scratchpad.handle_key(press(KeyCode::Char('n')));
    assert!(matches!(scratchpad.overlay, Overlay::Notes(_)));

    let mut transcript = app(&tmp);
    transcript.history.push(HistoryEntry::User {
        text: "original".to_string(),
        cleaned: Some("cleaned".to_string()),
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: Some(1),
        optimistic_submission_id: None,
        preflight_pending: false,
        persist_failed: false,
    });
    transcript.handle_key(ctrl(KeyCode::Char('k')));
    transcript.handle_key(press(KeyCode::Char('r')));
    assert!(matches!(
        transcript.history.last(),
        Some(HistoryEntry::User { expanded: true, .. })
    ));
}

#[test]
fn slash_model_opens_composer_picker_not_fullscreen_overlay() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let command = *super::slash::SLASH_COMMANDS
        .iter()
        .find(|command| command.name == "model")
        .expect("/model command");

    app.execute_slash(command);

    assert!(matches!(app.overlay, Overlay::None));
    assert!(
        app.composer_controls
            .picker
            .as_ref()
            .is_some_and(|picker| picker.kind == ComposerControlKind::Model)
    );
}

#[test]
fn composer_model_menu_pins_favorites_annotates_failures_usage_drift_and_add_action() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let provider = app
        .config_snapshot
        .providers
        .providers
        .get_mut("openai")
        .expect("provider");
    provider.models[1].favorite = true;
    app.usage_models.insert("openai/gpt-test".to_string(), 99);
    app.usage_models.insert("openai/gpt-other".to_string(), 3);
    app.auth_failure_annotations.insert(
        ("openai".to_string(), "gpt-other".to_string()),
        crate::tui::auth_failure::AuthFailureRecord {
            kind: cockpit_proto::AuthFailureKind::CredentialsRejected { status: 401 },
            failed_at_epoch_secs: chrono::Utc::now().timestamp(),
        },
    );

    app.handle_key(ctrl(KeyCode::Char('p')));
    let category = &app
        .composer_controls
        .picker
        .as_ref()
        .expect("picker")
        .categories[0];
    assert_eq!(category.items[0].id, "gpt-other");
    assert!(category.items[0].favorite);
    assert!(category.items[0].hint.contains("3 uses"));
    assert!(
        category.items[0].hint.contains("failed"),
        "auth failure annotation is retained on the failed model: {}",
        category.items[0].hint
    );
    assert_eq!(
        category.items.last().expect("add action").id,
        "\u{0}add-model"
    );

    app.config_drift = Some(super::ConfigDriftState {
        config_provider: Some("openai".to_string()),
        config_model: Some("gpt-other".to_string()),
    });
    app.refresh_config_drift_surfaces();
    let picker = app.composer_controls.picker.as_ref().expect("picker");
    assert_eq!(picker.categories[0].label, "Config drift");
    assert!(
        picker
            .status_text
            .as_deref()
            .is_some_and(|text| text.contains("config: openai/gpt-other"))
    );
}

#[test]
fn composer_model_menu_refresh_preserves_provider_cursor_across_config_drift_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.config_drift = Some(super::ConfigDriftState {
        config_provider: Some("openai".to_string()),
        config_model: Some("configured-model".to_string()),
    });

    app.handle_key(ctrl(KeyCode::Char('p')));
    let selected_before = {
        let picker = app.composer_controls.picker.as_ref().expect("picker");
        assert_eq!(picker.level, 0);
        assert_eq!(picker.categories[0].label, "Config drift");
        assert_eq!(picker.categories[picker.cursor].label, "openai");
        picker.categories[picker.cursor].id.clone()
    };
    assert_eq!(selected_before, "openai");

    app.refresh_open_composer_model_menu();

    let picker = app.composer_controls.picker.as_ref().expect("picker");
    assert_eq!(picker.categories[picker.cursor].id, selected_before);
    app.handle_key(press(KeyCode::Enter));
    let picker = app.composer_controls.picker.as_ref().expect("model rows");
    assert_eq!(picker.level, 1);
    assert_eq!(picker.categories[picker.category].id, "openai");
    assert_eq!(
        picker.categories[picker.category].items[picker.cursor].id,
        "gpt-test"
    );
}

#[test]
fn open_picker_wheel_hover_and_scrollbar_drag_move_selection() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let provider = app
        .config_snapshot
        .providers
        .providers
        .get_mut("openai")
        .expect("provider");
    for index in 0..20 {
        provider.models.push(ModelEntry {
            id: format!("gpt-{index:02}"),
            ..Default::default()
        });
    }
    let _ = render(&mut app, 80, 24);
    app.handle_key(ctrl(KeyCode::Char('p')));
    app.handle_key(press(KeyCode::Enter));
    let _ = render(&mut app, 80, 24);
    let picker_rect = app.composer_controls.picker_rect.expect("picker rect");
    let before = app
        .composer_controls
        .picker
        .as_ref()
        .expect("picker")
        .cursor;

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::ScrollDown,
        column: picker_rect.x + 1,
        row: picker_rect.y + 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_ne!(
        app.composer_controls
            .picker
            .as_ref()
            .expect("picker")
            .cursor,
        before,
        "wheel steps one picker row"
    );

    let _ = render(&mut app, 80, 24);
    let hover = app
        .button_registry
        .targets()
        .iter()
        .find_map(|target| match &target.dispatch {
            crate::tui::button::ButtonDispatch::ComposerPickerRow { index } if *index >= 2 => {
                Some((*index, target.rect))
            }
            _ => None,
        })
        .expect("visible picker row");
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column: hover.1.x,
        row: hover.1.y,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(
        app.composer_controls
            .picker
            .as_ref()
            .expect("picker")
            .cursor,
        hover.0,
        "hover owns the highlighted row"
    );

    let track = app
        .composer_controls
        .picker_scrollbar_rect
        .expect("overflowing picker scrollbar");
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: track.x,
        row: track.bottom() - 1,
        modifiers: KeyModifiers::empty(),
    });
    assert!(app.composer_controls.picker_scroll_drag);
    assert!(
        app.composer_controls
            .picker
            .as_ref()
            .expect("picker")
            .cursor
            > hover.0,
        "scrollbar track drag moves toward the bottom"
    );
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: track.x,
        row: track.bottom() - 1,
        modifiers: KeyModifiers::empty(),
    });
    assert!(!app.composer_controls.picker_scroll_drag);
}

fn arm_approval_mutation(app: &mut App) -> ControlRequestId {
    app.activate_composer_pill(ComposerControlKind::Approval);
    app.handle_key(press(KeyCode::Enter));
    app.composer_controls
        .pending
        .as_ref()
        .and_then(|pending| pending.request_id)
        .expect("approval mutation bound to a control request")
}

fn install_agent_inventory(app: &mut App) {
    app.inventory.snapshot = Some(super::inventory::InventorySnapshot {
        selected_agent: "Build".to_string(),
        agents: vec![
            cockpit_proto::AgentSummary {
                name: "Build".to_string(),
                description: String::new(),
                mode: String::new(),
                source: String::new(),
                builtin: true,
            },
            cockpit_proto::AgentSummary {
                name: "Plan".to_string(),
                description: String::new(),
                mode: String::new(),
                source: String::new(),
                builtin: true,
            },
        ],
        models: Vec::new(),
        skills: Vec::new(),
        session_generation: 0,
        config_generation: 0,
        inventory_generation: 0,
    });
}

fn arm_model_mutation(app: &mut App) -> ControlRequestId {
    app.activate_composer_pill(ComposerControlKind::Model);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    if let Some(picker) = app.composer_controls.picker.as_mut()
        && let Some(idx) = picker.categories.get(picker.category).and_then(|category| {
            category
                .items
                .iter()
                .position(|item| item.id == "gpt-other")
        })
    {
        picker.cursor = idx;
    }
    app.handle_key(press(KeyCode::Enter));
    app.composer_controls
        .pending
        .as_ref()
        .and_then(|pending| pending.request_id)
        .expect("model mutation bound to a control request")
}

fn commit_plan_agent(app: &mut App) -> ControlRequestId {
    app.activate_composer_pill(ComposerControlKind::Agent);
    if let Some(picker) = app.composer_controls.picker.as_mut()
        && let Some(idx) = picker
            .categories
            .get(picker.category)
            .and_then(|category| category.items.iter().position(|item| item.id == "Plan"))
    {
        picker.cursor = idx;
    }
    app.handle_key(press(KeyCode::Enter));
    app.composer_controls
        .pending
        .as_ref()
        .and_then(|pending| pending.request_id)
        .expect("agent mutation bound")
}

fn history_plain_lines(app: &App) -> Vec<&str> {
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

fn apply_control_outcome(
    app: &mut App,
    request_id: ControlRequestId,
    outcome: ControlRequestOutcome,
) {
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ControlRequestFinished {
            request_id,
            outcome,
        },
    );
}

fn apply_control_applied(app: &mut App, request_id: ControlRequestId) {
    apply_control_outcome(app, request_id, ControlRequestOutcome::Applied);
}

fn snapshot_refresh_pending(app: &App) -> bool {
    app.async_actions
        .has_pending_key(&crate::tui::async_action::AsyncActionKey::new(
            "session_setup.snapshot",
        ))
}

fn tools_snapshot(tools: &[(&str, &str)]) -> cockpit_proto::SessionSetupSnapshotV1 {
    cockpit_proto::SessionSetupSnapshotV1 {
        dto_version: cockpit_proto::SESSION_SETUP_DTO_VERSION,
        session_id: "11111111-1111-4111-8111-111111111111".to_string(),
        config_generation: 1,
        revision: 1,
        selected_installation_id: None,
        candidates: Vec::new(),
        resolved_agent: Some("Build".to_string()),
        last_used_agent: None,
        available_agents: Vec::new(),
        root_agent_instance_id: None,
        override_revision: 0,
        root_foreground: true,
        model: Default::default(),
        tools: tools
            .iter()
            .map(|(name, tier)| cockpit_proto::SessionSetupToolV1 {
                name: (*name).to_string(),
                tier: (*tier).to_string(),
                locked: false,
                legal_tiers: vec!["enabled".into(), "discoverable".into(), "disabled".into()],
                family: "test".into(),
            })
            .collect(),
        mcps: Vec::new(),
    }
}

fn apply_tools_snapshot(app: &mut App, tools: &[(&str, &str)]) {
    let correlation = match &app.overlay {
        Overlay::Tools(pane) => pane.session_override_wait(),
        _ => None,
    };
    let session_id = correlation
        .and_then(|correlation| correlation.session_id)
        .or_else(|| {
            app.agent_runner
                .as_ref()
                .and_then(|runner| runner.as_ref().ok())
                .map(|runner| runner.session_id())
        });
    let mut snapshot = tools_snapshot(tools);
    if let Some(session_id) = session_id {
        snapshot.session_id = session_id.to_string();
    }
    let response = cockpit_proto::Response::SessionSetupSnapshot { snapshot };
    if let Some(correlation) = correlation {
        app.apply_session_setup_snapshot_response_correlated(response, correlation);
    } else {
        app.apply_session_setup_snapshot_response(response);
    }
}

#[test]
fn composer_picker_discards_stale_generation_and_session() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.activate_composer_pill(ComposerControlKind::Approval);
    let prior_generation = app.composer_controls.generation;
    app.bump_composer_control_generation();
    assert!(app.composer_controls.picker.is_none());
    assert_ne!(app.composer_controls.generation, prior_generation);
    app.activate_composer_pill(ComposerControlKind::Approval);
    let request_id = ControlRequestId(7);
    app.composer_controls.pending = Some(super::composer_controls::PendingComposerMutation {
        generation: prior_generation,
        session_id: app.launch.session_id,
        attachment_epoch: app.visible_attachment_epoch,
        kind: ComposerControlKind::Approval,
        request_id: Some(request_id),
    });
    app.apply_composer_control_outcome(request_id, None, false);
    assert!(
        app.composer_controls.picker.as_ref().is_some_and(|p| p
            .status_text
            .as_deref()
            .is_some_and(|text| text.contains("Stale"))),
        "late result from a prior generation is discarded"
    );
}

#[test]
fn closing_composer_picker_fences_in_flight_control_request() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, _control_rx) = app_with_runner(&tmp);
    let request_id = arm_approval_mutation(&mut app);
    assert!(app.pending_control_requests.contains_key(&request_id));
    assert_eq!(
        app.composer_controls
            .picker
            .as_ref()
            .map(|picker| picker.status),
        Some(super::composer_controls::ComposerPickerStatus::Loading)
    );

    app.close_composer_picker();
    assert!(app.composer_controls.pending.is_none());
    assert!(app.composer_controls.picker.is_none());
    assert!(
        app.pending_control_requests
            .get(&request_id)
            .is_some_and(|pending| pending.fenced),
        "close fences picker confirmation but keeps correlation for outcome cleanup"
    );
    assert!(
        app.async_actions
            .has_pending_key(&crate::tui::async_action::AsyncActionKey::new(
                "session_setup.snapshot"
            )),
        "close with an in-flight mutation must refresh from daemon state"
    );

    apply_control_applied(&mut app, request_id);
    assert!(app.composer_controls.pending.is_none());
    assert!(app.composer_controls.picker.is_none());
    assert!(
        !app.pending_control_requests.contains_key(&request_id),
        "the fenced outcome is consumed without re-confirming the picker"
    );

    let (mut app, _control_rx) = app_with_runner(&tmp);
    let request_id = arm_approval_mutation(&mut app);
    app.bump_composer_control_generation();
    assert!(app.composer_controls.pending.is_none());
    assert!(app.composer_controls.picker.is_none());
    assert!(
        app.pending_control_requests
            .get(&request_id)
            .is_some_and(|pending| pending.fenced),
        "generation bump must fence the in-flight request"
    );
    apply_control_applied(&mut app, request_id);
    assert!(app.composer_controls.pending.is_none());

    let (mut app, _control_rx) = app_with_runner(&tmp);
    let request_id = arm_approval_mutation(&mut app);
    app.activate_composer_pill(ComposerControlKind::Model);
    assert!(
        app.pending_control_requests
            .get(&request_id)
            .is_some_and(|pending| pending.fenced),
        "opening another pill must fence the previous in-flight request"
    );
    apply_control_applied(&mut app, request_id);
    assert!(
        app.composer_controls
            .pending
            .as_ref()
            .is_none_or(|pending| pending.request_id != Some(request_id))
    );
}

#[test]
fn detached_model_commit_without_runner_avoids_false_delivery_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    App::prepare_runner_attach_harness(&mut app);
    app.agent_runner = None;
    app.activate_composer_pill(ComposerControlKind::Model);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    if let Some(picker) = app.composer_controls.picker.as_mut()
        && let Some(idx) = picker.categories.get(picker.category).and_then(|category| {
            category
                .items
                .iter()
                .position(|item| item.id == "gpt-other")
        })
    {
        picker.cursor = idx;
    }
    app.handle_key(press(KeyCode::Enter));
    assert!(
        app.pending_runner_attach.is_some(),
        "choosing a model without a runner must queue attach"
    );
    assert!(
        app.composer_controls.picker.as_ref().is_none_or(|picker| {
            !picker
                .status_text
                .as_ref()
                .is_some_and(|text| text.contains("Control request was not delivered"))
        }),
        "attach-in-flight must not surface a false delivery failure"
    );
    let attach = app.pending_runner_attach.as_ref().unwrap();
    app.apply_runner_attach_result(attach.action_id, Err("session not found".to_string()));
    assert!(app.composer_controls.picker.as_ref().is_some_and(|picker| {
        picker.status_text.as_ref().is_some_and(|error| {
            error
                .to_ascii_lowercase()
                .contains("could not start a session")
        })
    }));
}

#[test]
fn fenced_model_selection_failed_delivery_releases_ownership() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, _control_rx) = app_with_runner(&tmp);
    let request_id = arm_model_mutation(&mut app);
    assert!(app.pending_model_selection.is_some());
    app.close_composer_picker();
    assert!(
        app.pending_control_requests
            .get(&request_id)
            .is_some_and(|pending| pending.fenced),
        "close must keep model-selection correlation"
    );
    assert!(
        app.pending_model_selection.is_some(),
        "applied ModelSelectionResult still owns a live selection"
    );

    apply_control_outcome(
        &mut app,
        request_id,
        ControlRequestOutcome::Rejected("model refused".to_string()),
    );
    assert!(
        app.pending_model_selection.is_none(),
        "rejected fenced model selection must release ownership"
    );
    assert!(
        app.composer_controls.picker.is_none(),
        "fenced model rejection must not reopen the model picker"
    );

    let retry_id = arm_model_mutation(&mut app);
    assert!(
        app.pending_model_selection.is_some(),
        "a later model selection must not be blocked by the fenced rejection"
    );

    app.close_composer_picker();
    apply_control_outcome(
        &mut app,
        retry_id,
        ControlRequestOutcome::NotDelivered(
            cockpit_client::presentation::ControlRequestNotDelivered::ChannelClosed,
        ),
    );
    assert!(
        app.pending_model_selection.is_none(),
        "undelivered fenced model selection must release ownership"
    );
    let _ = arm_model_mutation(&mut app);
    assert!(
        app.pending_model_selection.is_some(),
        "a later model selection must not be blocked by the fenced undelivered request"
    );
}

#[test]
fn session_reset_and_terminal_link_terminate_composer_pending() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, _control_rx) = app_with_runner(&tmp);
    let request_id = arm_approval_mutation(&mut app);
    app.reset_session_live_state();
    assert!(
        app.composer_controls.pending.is_none(),
        "session reset must not leave Applying…"
    );
    assert!(app.composer_controls.picker.is_none());
    assert!(!app.pending_control_requests.contains_key(&request_id));
    apply_control_applied(&mut app, request_id);
    assert!(app.composer_controls.pending.is_none());
    assert!(app.composer_controls.picker.is_none());

    let (mut app, _control_rx) = app_with_runner(&tmp);
    let request_id = arm_approval_mutation(&mut app);
    app.apply_event(
        cockpit_client::presentation::TurnEvent::DaemonLinkTerminal {
            error: "protocol link ended".to_string(),
        },
    );
    assert!(
        app.composer_controls.pending.is_none(),
        "terminal disconnect must not leave Applying…"
    );
    assert!(app.composer_controls.picker.is_none());
    assert!(
        app.pending_control_requests
            .get(&request_id)
            .is_some_and(|pending| pending.fenced),
        "terminal disconnect fences composer confirmation and keeps correlation"
    );
    apply_control_applied(&mut app, request_id);
    assert!(app.composer_controls.pending.is_none());
    assert!(app.composer_controls.picker.is_none());
}

#[test]
fn fenced_composer_agent_receipt_does_not_confirm() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, _control_rx) = app_with_runner(&tmp);
    install_agent_inventory(&mut app);
    let request_id = commit_plan_agent(&mut app);
    app.close_composer_picker();
    apply_control_applied(&mut app, request_id);
    assert!(
        history_plain_lines(&app)
            .iter()
            .all(|line| !line.contains("Switched primary agent")),
        "a fenced composer agent receipt must not record confirmation: {:?}",
        history_plain_lines(&app)
    );

    let (mut app, _control_rx) = app_with_runner(&tmp);
    install_agent_inventory(&mut app);
    let request_id = commit_plan_agent(&mut app);
    apply_control_applied(&mut app, request_id);
    assert!(
        history_plain_lines(&app)
            .iter()
            .any(|line| line.contains("Switched primary agent to `Plan`")),
        "a live composer agent receipt must still confirm: {:?}",
        history_plain_lines(&app)
    );
}

#[test]
fn composer_mutation_waits_for_originating_request_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, _control_rx) = app_with_runner(&tmp);
    app.activate_composer_pill(ComposerControlKind::Approval);
    app.handle_key(press(KeyCode::Enter));
    let pending = app
        .composer_controls
        .pending
        .clone()
        .expect("approval mutation is pending");
    let request_id = pending.request_id.expect("pending is bound to a request");
    assert_eq!(
        app.composer_controls
            .picker
            .as_ref()
            .map(|picker| picker.status),
        Some(super::composer_controls::ComposerPickerStatus::Loading)
    );

    app.send_daemon_request(
        "/preflight",
        Request::SetPreflight {
            enabled: Some(true),
        },
        super::ControlApplied::None,
    );
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ControlRequestFinished {
            request_id: ControlRequestId(request_id.0.saturating_add(1)),
            outcome: ControlRequestOutcome::Applied,
        },
    );
    assert!(
        app.composer_controls.pending.is_some(),
        "an unrelated applied request must not confirm the composer mutation"
    );
    assert_eq!(
        app.composer_controls
            .picker
            .as_ref()
            .map(|picker| picker.status),
        Some(super::composer_controls::ComposerPickerStatus::Loading)
    );

    app.apply_event(
        cockpit_client::presentation::TurnEvent::ControlRequestFinished {
            request_id,
            outcome: ControlRequestOutcome::Applied,
        },
    );
    assert!(app.composer_controls.pending.is_none());
    assert!(app.composer_controls.picker.is_none());
}

#[test]
fn composer_dispatch_failure_clears_applying_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.activate_composer_pill(ComposerControlKind::Approval);
    app.handle_key(press(KeyCode::Enter));
    assert!(
        app.composer_controls.pending.is_none(),
        "failed dispatch must not leave a pending mutation"
    );
    let picker = app
        .composer_controls
        .picker
        .as_ref()
        .expect("picker stays open");
    assert_eq!(
        picker.status,
        super::composer_controls::ComposerPickerStatus::Unavailable
    );
    assert!(
        picker
            .status_text
            .as_deref()
            .is_some_and(|text| text.contains("start a session") || text.contains("not delivered")),
        "refused/unavailable copy, got {:?}",
        picker.status_text
    );

    let (mut app, _control_rx) = app_with_runner(&tmp);
    app.activate_composer_pill(ComposerControlKind::Approval);
    app.handle_key(press(KeyCode::Enter));
    let request_id = app
        .composer_controls
        .pending
        .as_ref()
        .and_then(|pending| pending.request_id)
        .expect("bound request");
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ControlRequestFinished {
            request_id,
            outcome: ControlRequestOutcome::NotDelivered(
                cockpit_client::presentation::ControlRequestNotDelivered::ChannelClosed,
            ),
        },
    );
    assert!(app.composer_controls.pending.is_none());
    let picker = app
        .composer_controls
        .picker
        .as_ref()
        .expect("picker stays open");
    assert_eq!(
        picker.status,
        super::composer_controls::ComposerPickerStatus::Unavailable
    );
}

#[test]
fn model_selection_waits_for_set_active_model_receipt() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    let prior = app.launch.active_model.clone();
    app.activate_composer_pill(ComposerControlKind::Model);
    // Drill into the openai category if the picker is still at level 0.
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|p| p.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    let picker = app.composer_controls.picker.as_mut().expect("picker");
    if let Some(idx) = picker
        .categories
        .get(picker.category)
        .and_then(|c| c.items.iter().position(|item| item.id == "gpt-other"))
    {
        picker.cursor = idx;
    }
    app.handle_key(press(KeyCode::Enter));
    assert_eq!(
        app.launch.active_model, prior,
        "display does not change before the applied receipt"
    );
    let req = control_rx.try_recv().expect("SetActiveModel sent").request;
    match req {
        Request::SetActiveModel {
            persist_as_default,
            model,
            ..
        } => {
            assert!(!persist_as_default, "plain Enter is session-only");
            assert_eq!(model, "gpt-other");
        }
        other => panic!("expected SetActiveModel, got {other:?}"),
    }
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ControlRequestFinished {
            request_id: ControlRequestId(1),
            outcome: ControlRequestOutcome::Rejected("default write failed".to_string()),
        },
    );
    assert_eq!(
        app.launch.active_model, prior,
        "rejection leaves the confirmed model unchanged"
    );
}

#[test]
fn persist_as_default_is_atomic_set_active_model() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.activate_composer_pill(ComposerControlKind::Model);
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|p| p.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    let persist = KeyEvent {
        code: KeyCode::Enter,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(persist);
    match control_rx.try_recv().expect("request").request {
        Request::SetActiveModel {
            persist_as_default, ..
        } => assert!(
            persist_as_default,
            "Ctrl+Enter is the atomic session+default write"
        ),
        other => panic!("expected SetActiveModel, got {other:?}"),
    }
}

#[test]
fn approval_and_sandbox_pills_are_capability_gated() {
    let tmp = tempfile::tempdir().unwrap();
    let mut untrusted = app(&tmp);
    untrusted.sandbox_mode = SandboxMode::Refuse;
    untrusted.activate_composer_pill(ComposerControlKind::Sandbox);
    let picker = untrusted
        .composer_controls
        .picker
        .as_ref()
        .expect("sandbox");
    assert!(
        picker
            .status_text
            .as_deref()
            .is_some_and(|text| text.to_lowercase().contains("refused")
                || text.to_lowercase().contains("bypass")),
        "refused sandbox is truthful: {:?}",
        picker.status_text
    );
    assert!(
        picker
            .categories
            .iter()
            .flat_map(|c| &c.items)
            .all(|item| !item.selectable),
        "refused sandbox offers no local bypass"
    );
    untrusted.approval_mode = ApprovalMode::Manual;
    untrusted.activate_composer_pill(ComposerControlKind::Approval);
    let picker = untrusted
        .composer_controls
        .picker
        .as_ref()
        .expect("approval");
    let items: Vec<_> = picker
        .categories
        .iter()
        .flat_map(|c| c.items.iter())
        .collect();
    assert!(
        items
            .iter()
            .any(|item| item.label == "manual" && item.selectable)
    );
    assert!(
        items
            .iter()
            .any(|item| item.label == "auto" && !item.selectable),
        "auto must stay trust-gated without a trusted workspace: {:?}",
        items
            .iter()
            .map(|item| (&item.label, item.selectable, &item.hint))
            .collect::<Vec<_>>()
    );
    assert!(
        items
            .iter()
            .any(|item| item.label == "yolo" && !item.selectable),
        "yolo must stay trust-gated without a trusted workspace"
    );

    let tmp_trusted = tempfile::tempdir().unwrap();
    cockpit_config::trust::with_workspace_trust_policy(
        super::trusted_workspace_policy_for_tests(tmp_trusted.path()),
        || {
            let mut trusted = app(&tmp_trusted);
            trusted.activate_composer_pill(ComposerControlKind::Approval);
            let picker = trusted.composer_controls.picker.as_ref().expect("approval");
            assert!(
                picker
                    .categories
                    .iter()
                    .flat_map(|c| &c.items)
                    .filter(|item| item.label == "auto" || item.label == "yolo")
                    .all(|item| item.selectable),
                "trusted workspace may select auto/yolo"
            );
        },
    );
}

#[test]
fn header_tools_pill_reconciles_tool_surface_override() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.history.push(HistoryEntry::ToolLine {
        call_id: "c1".to_string(),
        tool: "edit".to_string(),
        summary: "src/lib.rs".to_string(),
        icon_path: None,
        state: crate::tui::history::ToolCallState::Processing,
    });
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Tool);
    assert!(matches!(app.overlay, Overlay::Tools(_)));

    let legal = legal_tool_tiers("code");
    assert!(
        legal.contains(&ToolTier::Discoverable),
        "code may be discoverable"
    );
    let inspect = legal_tool_tiers("inspect_audio");
    assert!(
        !inspect.contains(&ToolTier::Discoverable),
        "native-schema tools list discoverable as illegal"
    );
    assert_eq!(inspect, &[ToolTier::Enabled, ToolTier::Disabled]);

    app.handle_tools_outcome(ToolsOutcome::Apply {
        override_json: "{}".to_string(),
        persist_session: true,
        cache_break: false,
        monty_nudge: None,
    });
    match control_rx.try_recv().unwrap().request {
        Request::SetToolSurfaceOverride {
            cache_break_acknowledged,
            persist_session,
            ..
        } => {
            assert!(
                !cache_break_acknowledged,
                "legal non-cache-breaking transition does not claim a cache break"
            );
            assert!(persist_session);
        }
        other => panic!("expected SetToolSurfaceOverride, got {other:?}"),
    }
    assert!(
        matches!(app.overlay, Overlay::Tools(_)),
        "header tools surface stays open until daemon confirmation"
    );
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "session override waits for the daemon receipt"
    );
    let original = pane.original_selection().clone();
    assert_eq!(
        app.pending_control_requests
            .get(&ControlRequestId(1))
            .map(|pending| pending.applied.clone()),
        Some(super::ControlApplied::ToolSurfaceOverride { cache_break: false })
    );
    apply_tools_snapshot(&mut app, &[("premature", "enabled")]);
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "a snapshot that arrives before Applied cannot confirm pending ownership"
    );
    assert_eq!(
        pane.original_selection(),
        &original,
        "a pre-Applied snapshot must not restore or replace the daemon baseline"
    );

    apply_control_applied(&mut app, ControlRequestId(1));
    assert!(
        snapshot_refresh_pending(&app),
        "applied header-tools mutation must refresh daemon tool-surface state"
    );
    assert!(matches!(app.overlay, Overlay::Tools(_)));
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "applied receipt must not confirm from the local draft"
    );
    assert_eq!(
        pane.original_selection(),
        &original,
        "applied receipt must not promote the local draft"
    );

    apply_tools_snapshot(&mut app, &[("bash", "enabled"), ("read", "discoverable")]);
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        !pane.session_override_pending(),
        "daemon snapshot is the header tools confirmation"
    );
    assert_eq!(
        pane.original_selection().tools,
        vec!["bash".to_string(), "read".to_string()]
    );
    assert_eq!(
        pane.original_selection().tool_tiers.get("read").copied(),
        Some(ToolTier::Discoverable)
    );
    assert_eq!(pane.original_selection(), pane.draft_selection());
    let confirmed = pane.original_selection().clone();

    app.handle_tools_outcome(ToolsOutcome::Apply {
        override_json: "{}".to_string(),
        persist_session: true,
        cache_break: true,
        monty_nudge: None,
    });
    match control_rx.try_recv().unwrap().request {
        Request::SetToolSurfaceOverride {
            cache_break_acknowledged,
            ..
        } => assert!(
            cache_break_acknowledged,
            "cache-breaking transition requires acknowledgement on the request"
        ),
        other => panic!("expected SetToolSurfaceOverride, got {other:?}"),
    }
    assert_eq!(
        app.pending_control_requests
            .get(&ControlRequestId(2))
            .map(|pending| pending.applied.clone()),
        Some(super::ControlApplied::ToolSurfaceOverride { cache_break: true })
    );

    apply_control_outcome(
        &mut app,
        ControlRequestId(2),
        ControlRequestOutcome::Rejected("illegal tier".to_string()),
    );
    assert!(
        snapshot_refresh_pending(&app),
        "refused header-tools mutation must refresh from daemon state"
    );
    assert!(matches!(app.overlay, Overlay::Tools(_)));
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        !pane.session_override_pending(),
        "refusal must release session-override pending ownership"
    );
    assert_eq!(
        pane.draft_selection(),
        pane.original_selection(),
        "refusal leaves confirmed tool-surface state intact"
    );
    assert_eq!(pane.original_selection(), &confirmed);
    assert_eq!(
        app.launch.active_model,
        Some(("openai".to_string(), "gpt-test".to_string()))
    );
}

#[test]
fn header_tools_reconnect_discards_stale_receipt_and_reconciles_snapshot() {
    use std::sync::atomic::Ordering;

    use crate::tui::agent_runner::{GLOBAL_ATTACHMENT_EPOCH, QueuedTurnEvent};

    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Tool);
    app.handle_tools_outcome(ToolsOutcome::Apply {
        override_json: "{}".to_string(),
        persist_session: true,
        cache_break: false,
        monty_nudge: None,
    });
    let _ = control_rx.try_recv();
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    let original = pane.original_selection().clone();
    assert!(pane.session_override_pending());
    let old_epoch = app.visible_attachment_epoch;
    let request_id = ControlRequestId(1);

    {
        let runner = app.agent_runner.as_ref().unwrap().as_ref().unwrap();
        runner
            .attachment_epoch
            .store(old_epoch + 1, Ordering::Release);
        let mut events = runner.events.lock().unwrap();
        events.push(QueuedTurnEvent {
            attachment_epoch: GLOBAL_ATTACHMENT_EPOCH,
            event: cockpit_client::presentation::TurnEvent::DaemonLinkReconnected {
                active_model_state: None,
            },
        });
        events.push(QueuedTurnEvent {
            attachment_epoch: old_epoch,
            event: cockpit_client::presentation::TurnEvent::ControlRequestFinished {
                request_id,
                outcome: ControlRequestOutcome::Applied,
            },
        });
    }
    app.drain_agent_events();
    assert_eq!(app.visible_attachment_epoch, old_epoch + 1);
    assert!(
        !app.pending_control_requests.contains_key(&request_id),
        "old-epoch tool receipts must be abandoned when visibility advances"
    );
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "reconnect must keep the pane pending until the daemon snapshot arrives"
    );
    assert_eq!(
        pane.original_selection(),
        &original,
        "reconnect must not promote the local draft"
    );
    assert!(
        snapshot_refresh_pending(&app),
        "reconnect must refresh tool-surface state from the daemon"
    );

    apply_tools_snapshot(&mut app, &[("bash", "enabled")]);
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        !pane.session_override_pending(),
        "snapshot after reconnect is the remaining settlement path"
    );
    assert_eq!(pane.original_selection().tools, vec!["bash".to_string()]);
    assert_eq!(pane.original_selection(), pane.draft_selection());
}

#[test]
fn header_tools_uncorrelated_snapshots_do_not_confirm_pending_override() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    let _ = render(&mut app, 100, 30);
    app.activate_header_pill(HeaderPillKind::Tool);
    app.handle_tools_outcome(ToolsOutcome::Apply {
        override_json: "{}".to_string(),
        persist_session: true,
        cache_break: false,
        monty_nudge: None,
    });
    let _ = control_rx.try_recv();
    apply_control_applied(&mut app, ControlRequestId(1));
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    let wait = pane
        .session_override_wait()
        .expect("applied mutation waits for a correlated snapshot");
    let original = pane.original_selection().clone();
    let session_id = wait.session_id.expect("refresh is session-bound");

    let mut stale = tools_snapshot(&[("stale", "enabled")]);
    stale.session_id = session_id.to_string();
    app.apply_session_setup_snapshot_response_correlated(
        cockpit_proto::Response::SessionSetupSnapshot { snapshot: stale },
        super::SessionSetupSnapshotCorrelation::refresh(
            wait.generation.saturating_sub(1),
            Some(session_id),
            wait.attachment_epoch,
        ),
    );
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "an older snapshot generation must not confirm the post-mutation wait"
    );
    assert_eq!(pane.original_selection(), &original);

    let mut add_mcp = tools_snapshot(&[("mcp", "enabled")]);
    add_mcp.session_id = session_id.to_string();
    app.apply_session_setup_snapshot_response(cockpit_proto::Response::SessionSetupSnapshot {
        snapshot: add_mcp,
    });
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "Add-MCP and other unrelated snapshots must not confirm tool-surface pending"
    );
    assert_eq!(pane.original_selection(), &original);

    let mut wrong_epoch = tools_snapshot(&[("epoch", "enabled")]);
    wrong_epoch.session_id = session_id.to_string();
    app.apply_session_setup_snapshot_response_correlated(
        cockpit_proto::Response::SessionSetupSnapshot {
            snapshot: wrong_epoch,
        },
        super::SessionSetupSnapshotCorrelation::refresh(
            wait.generation,
            Some(session_id),
            wait.attachment_epoch.wrapping_add(1),
        ),
    );
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        pane.session_override_pending(),
        "a snapshot stamped for another attachment epoch must not confirm"
    );
    assert_eq!(pane.original_selection(), &original);

    apply_tools_snapshot(&mut app, &[("bash", "enabled")]);
    let Overlay::Tools(pane) = &app.overlay else {
        panic!("tools overlay");
    };
    assert!(
        !pane.session_override_pending(),
        "the post-mutation correlated snapshot is the remaining settlement path"
    );
    assert_eq!(pane.original_selection().tools, vec!["bash".to_string()]);
}

#[test]
fn queue_item_and_box_controls_have_mouse_and_key_parity() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let held = queue_item("held", QueueDeliveryClass::Held);
    let steer = queue_item("steer", QueueDeliveryClass::Steering);
    let held_id = held.id;
    app.queue.extend([held, steer]);
    app.focus_queue_from_composer();
    app.handle_queue_key(press(KeyCode::Char('s')));
    app.dispatch_button(crate::tui::button::ButtonDispatch::QueueSetClass {
        item_id: Some(held_id),
        class: QueueDeliveryClass::Steering,
    });
    app.dispatch_button(crate::tui::button::ButtonDispatch::QueueSetClass {
        item_id: None,
        class: QueueDeliveryClass::Held,
    });
    app.handle_queue_key(KeyEvent {
        code: KeyCode::Char('S'),
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    });
    let queue_render = include_str!("render.rs");
    assert!(queue_render.contains("Steer · next safe boundary"));
    assert!(queue_render.contains("Held · after completion"));
    assert!(queue_render.contains("Send now"));
    let queue_ui = include_str!("queue_controls.rs");
    assert!(
        !queue_ui.contains("Interrupt"),
        "queue controls must not present Interrupt as a delivery class"
    );
    assert!(!queue_ui.to_lowercase().contains("kill a tool"));
    assert!(!queue_ui.to_lowercase().contains("mid-tool kill"));
}

fn runner_with_attached_rx() -> (
    crate::tui::agent_runner::AgentRunner,
    mpsc::Receiver<crate::tui::agent_runner::AttachedRequest>,
) {
    let (attached_request_tx, attached_request_rx) = mpsc::channel(8);
    let runner = crate::tui::agent_runner::AgentRunner::test_fixture(
        crate::tui::agent_runner::TestRunnerOverrides {
            attached_request_tx: Some(attached_request_tx),
            ..Default::default()
        },
    );
    (runner, attached_request_rx)
}

async fn take_and_ack_queue_request(
    app: &mut App,
    rx: &mut mpsc::Receiver<crate::tui::agent_runner::AttachedRequest>,
) -> Request {
    for _ in 0..40 {
        app.drain_async_actions();
        if let Ok(attached) = rx.try_recv() {
            let request = attached.request;
            let _ = attached.response_tx.send(Ok(cockpit_proto::Response::Ack));
            tokio::task::yield_now().await;
            app.drain_async_actions();
            return request;
        }
        tokio::task::yield_now().await;
    }
    panic!("queue control RPC was not delivered")
}

#[tokio::test]
async fn empty_composer_enter_is_the_safe_ladder() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut attached_rx) = {
        let mut app = app(&tmp);
        let (runner, rx) = runner_with_attached_rx();
        app.agent_runner = Some(Ok(runner));
        (app, rx)
    };

    app.handle_empty_composer_enter();
    tokio::task::yield_now().await;
    app.drain_async_actions();
    assert!(attached_rx.try_recv().is_err(), "empty queue emits no RPC");
    assert!(app.queue.is_empty());

    let held = queue_item("held", QueueDeliveryClass::Held);
    let held_id = held.id;
    let held_target = held.target.clone();
    app.queue.push(held);
    app.handle_empty_composer_enter();
    let request = take_and_ack_queue_request(&mut app, &mut attached_rx).await;
    match request {
        Request::PromoteQueuedUserMessages { delivery_class } => {
            assert_eq!(delivery_class, QueueDeliveryClass::Steering);
        }
        other => panic!("held-only must promote, got {other:?}"),
    }
    assert_eq!(app.queue[0].id, held_id);
    assert_eq!(app.queue[0].target, held_target);
    assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);

    app.queue.clear();
    let steer = queue_item("steer", QueueDeliveryClass::Steering);
    let steer_id = steer.id;
    let steer_target = steer.target.clone();
    app.queue.push(steer);
    app.handle_empty_composer_enter();
    let request = take_and_ack_queue_request(&mut app, &mut attached_rx).await;
    match request {
        Request::SendNowQueuedUserMessage { queue_item_id } => {
            assert_eq!(queue_item_id, None, "box-level send-now has no item id");
        }
        other => panic!("steering-only must send-now, got {other:?}"),
    }
    assert_eq!(app.queue[0].id, steer_id);
    assert_eq!(app.queue[0].target, steer_target);
    assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Steering);
    assert!(!app.queue[0].send_now);

    let mixed_held = queue_item("h", QueueDeliveryClass::Held);
    let mixed_steer = queue_item("s", QueueDeliveryClass::Steering);
    let mixed_held_id = mixed_held.id;
    let mixed_steer_id = mixed_steer.id;
    let mixed_held_target = mixed_held.target.clone();
    let mixed_steer_target = mixed_steer.target.clone();
    app.queue = vec![mixed_held, mixed_steer];
    app.handle_empty_composer_enter();
    let request = take_and_ack_queue_request(&mut app, &mut attached_rx).await;
    match request {
        Request::PromoteQueuedUserMessages { delivery_class } => {
            assert_eq!(delivery_class, QueueDeliveryClass::Steering);
        }
        other => panic!("mixed queue must promote, got {other:?}"),
    }
    assert!(
        attached_rx.try_recv().is_err(),
        "mixed queue must not also request send-now"
    );
    assert_eq!(app.queue[0].id, mixed_held_id);
    assert_eq!(app.queue[1].id, mixed_steer_id);
    assert_eq!(app.queue[0].target, mixed_held_target);
    assert_eq!(app.queue[1].target, mixed_steer_target);
    assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);
    assert_eq!(app.queue[1].delivery_class, QueueDeliveryClass::Steering);

    app.queue[0].delivery_class = QueueDeliveryClass::Steering;
    app.handle_empty_composer_enter();
    let request = take_and_ack_queue_request(&mut app, &mut attached_rx).await;
    assert!(matches!(
        request,
        Request::SendNowQueuedUserMessage {
            queue_item_id: None
        }
    ));
    assert_eq!(app.queue[0].id, mixed_held_id);
    assert_eq!(app.queue[1].id, mixed_steer_id);
    assert!(
        app.queue
            .iter()
            .all(|item| item.delivery_class == QueueDeliveryClass::Steering && !item.send_now)
    );
}

#[test]
fn send_now_never_uses_cancel_turn() {
    let src = include_str!("queue_controls.rs");
    assert!(src.contains("SendNowQueuedUserMessage"));
    let send_now_fn = src
        .split("fn queue_action_send_now")
        .nth(1)
        .expect("send now exists");
    let body = send_now_fn.split("pub(super) fn").next().unwrap();
    assert!(
        !body.contains("CancelTurn"),
        "Send now must not route through CancelTurn"
    );
    assert!(!body.contains("Ctrl-C") && !body.contains("ctrl_c"));
}

#[test]
fn queue_keys_do_not_intercept_composer_typing() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.queue
        .push(queue_item("queued", QueueDeliveryClass::Held));
    assert!(app.queue_focus.is_none());
    app.handle_key(press(KeyCode::Char('s')));
    assert!(
        app.composer.text().contains('s'),
        "s types into the composer while queue is unfocused"
    );
    app.composer.clear();
    app.focus_queue_from_composer();
    app.handle_key(press(KeyCode::Char('s')));
    assert!(
        app.composer.is_empty(),
        "s is a queue action while queue focus owns input"
    );
}

#[test]
fn footer_agent_and_model_routes_are_gone() {
    let tui = include_str!("../chrome.rs");
    assert!(!tui.contains("FooterControl"));
    assert!(!tui.contains("footer_agent_picker"));
    let app_mod = include_str!("mod.rs");
    assert!(!app_mod.contains("footer_agent_picker"));
    assert!(!app_mod.contains("FooterControl::Agent"));
    let render = include_str!("render.rs");
    assert!(!render.contains("footer_agent_picker"));
    assert!(!render.contains("FooterControl::"));
}

#[test]
fn composer_registry_stays_private_two_value_owner() {
    let boundary = include_str!("../../../tests/composer_registry_boundary.rs");
    assert!(boundary.contains("registered_composer_is_the_exact_private_two_value_owner"));
    assert!(boundary.contains("(\"composer\""));
    assert!(boundary.contains("(\"paste_registry\""));
}

#[test]
fn slash_commands_remain_reachable_from_composer() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.composer.insert_str("/help");
    assert!(
        app.composer.text().starts_with('/'),
        "slash discovery is typed in the composer"
    );
}

#[test]
fn composer_modes_remain_reachable() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    assert!(app.composer.vim_enabled());
    app.handle_key(press(KeyCode::Esc));
    assert_eq!(app.composer.vim_mode(), VimMode::Normal);
}

#[test]
fn held_is_the_public_queue_default() {
    use cockpit_config::extended::ExtendedConfig;
    assert!(!ExtendedConfig::default().queued_messages_as_steering);
    let omitted: ExtendedConfig = serde_json::from_str("{}").unwrap();
    assert!(!omitted.queued_messages_as_steering);
    assert_eq!(
        QueueDeliveryClass::from_steering_setting(false),
        QueueDeliveryClass::Held
    );
    assert_eq!(
        QueueDeliveryClass::from_steering_setting(true),
        QueueDeliveryClass::Steering
    );
    let settings = include_str!("../settings/category.rs");
    assert!(settings.contains("off (default — enter during a run holds until completion)"));
    assert!(settings.contains("Held"));
}

#[test]
fn composer_parity_table_names_retained_surfaces_and_proofs() {
    let behavior_suite = include_str!("composer_controls_tests.rs");
    let mut declared_tests = std::collections::HashSet::new();
    let mut lines = behavior_suite.lines();
    while let Some(line) = lines.next() {
        if line.trim() != "#[test]" {
            continue;
        }
        let Some(declaration) = lines.by_ref().find(|l| !l.trim().is_empty()) else {
            break;
        };
        if let Some(name) = declaration.trim().strip_prefix("fn ")
            && let Some(name) = name.split('(').next()
        {
            declared_tests.insert(name.to_string());
        }
    }
    assert!(!declared_tests.is_empty());
    for row in capability_parity_table() {
        assert!(
            declared_tests.contains(row.proof),
            "parity proof {} for {} on {} must be a declared #[test] in the composer behavior suite",
            row.proof,
            row.control,
            row.surface
        );
    }
}

#[test]
fn default_model_settings_mode_clears_on_dismiss_and_ordinary_open() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.open_default_model_from_settings();
    assert!(app.default_model_settings_mode);
    app.close_composer_picker();
    assert!(!app.default_model_settings_mode);

    app.open_default_model_from_settings();
    assert!(app.default_model_settings_mode);
    app.handle_key(press(KeyCode::Esc));
    assert!(!app.default_model_settings_mode);

    app.open_default_model_from_settings();
    assert!(app.default_model_settings_mode);
    app.handle_key(ctrl(KeyCode::Char('p')));
    assert!(
        !app.default_model_settings_mode,
        "ordinary Ctrl+P open must exit default-only mode"
    );
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    app.handle_key(press(KeyCode::Enter));
    assert!(matches!(
        control_rx
            .try_recv()
            .expect("session switch request")
            .request,
        cockpit_proto::Request::SetActiveModel {
            persist_as_default: false,
            ..
        }
    ));
    assert_eq!(app.pending_default_model_update_id, None);
}

#[test]
fn default_model_settings_mode_survives_add_model_settings_reopen() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.open_default_model_from_settings();
    assert!(app.default_model_settings_mode);
    let add_id = "\u{0}add-model";
    if let Some(picker) = app.composer_controls.picker.as_mut()
        && picker.level == 0
    {
        app.handle_key(press(KeyCode::Enter));
    }
    if let Some(picker) = app.composer_controls.picker.as_mut()
        && let Some(category) = picker.categories.get(picker.category)
        && let Some(index) = category.items.iter().position(|item| item.id == add_id)
    {
        picker.cursor = index;
    }
    app.handle_key(press(KeyCode::Enter));
    assert!(app.dialog.is_active());
    app.dialog = crate::tui::settings::Dialog::None;
    assert!(app.reopen_composer_model_after_provider_settings());
    assert!(
        app.default_model_settings_mode,
        "Add model… reopen must not clear default-only mode from Settings → Choose default"
    );
    assert!(app.refresh_reopened_composer_model_after_settings.is_some());

    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_client::presentation::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(
                &app.config_snapshot.providers,
            ),
        }),
    });
    assert!(app.refresh_reopened_composer_model_after_settings.is_none());
    assert!(
        app.default_model_settings_mode,
        "post-save snapshot refresh must not clear default-only mode"
    );
    app.handle_key(press(KeyCode::Enter));
    assert!(matches!(
        control_rx
            .try_recv()
            .expect("default model request")
            .request,
        Request::SetDefaultModel { .. }
    ));
    assert!(app.pending_default_model_update_id.is_some());
    assert!(!app.default_model_settings_mode);
}

#[test]
fn submit_after_model_selection_submits_on_pick_and_clears_on_cancel() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, mut control_rx) = app_with_runner(&tmp);
    app.launch.active_model = None;
    app.active_model_selection = None;
    app.composer.set("hold this draft".to_string());
    assert!(!app.submit_input());
    assert!(app.submit_after_model_selection);
    assert!(app.composer_controls.picker.is_some());
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    app.handle_key(press(KeyCode::Enter));
    control_rx.try_recv().expect("model switch request");
    let selection_id = app
        .pending_model_selection
        .as_ref()
        .expect("pending selection")
        .selection_id;
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ModelSelectionResult {
            selection_id,
            provider: "openai".into(),
            model: "gpt-test".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
            outcome: cockpit_proto::ModelSelectionOutcome::Applied {
                active_state: Box::new(cockpit_proto::ModelSelectionActiveState {
                    selection: ActiveModelRef {
                        provider: "openai".into(),
                        model: "gpt-test".into(),
                        reasoning_effort: None,
                        thinking_mode: None,
                        prompt_cache_retention: None,
                    },
                    default_selection: None,
                    diverged: false,
                    generation: 1,
                }),
                default_update: cockpit_proto::DefaultModelUpdateOutcome::NotRequested,
            },
        },
    );
    assert!(!app.submit_after_model_selection);
    assert!(app.composer.text().is_empty());

    app.launch.active_model = None;
    app.active_model_selection = None;
    app.composer.set("second draft".to_string());
    assert!(!app.submit_input());
    assert!(app.submit_after_model_selection);
    app.close_composer_picker();
    assert!(!app.submit_after_model_selection);
    assert_eq!(app.composer.text(), "second draft");
}

#[test]
fn restore_and_reopen_composer_model_menu_skip_config_drift_row() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.config_drift = Some(super::ConfigDriftState {
        config_provider: Some("openai".to_string()),
        config_model: Some("configured-model".to_string()),
    });
    app.handle_key(ctrl(KeyCode::Char('p')));
    let picker = app.composer_controls.picker.as_ref().expect("menu");
    assert_eq!(picker.categories[0].label, "Config drift");
    let requested = ActiveModelRef {
        provider: "openai".to_string(),
        model: "gpt-other".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    app.restore_composer_model_menu_selection(&requested);
    let picker = app.composer_controls.picker.as_ref().expect("menu");
    assert_eq!(picker.categories[picker.category].label, "openai");
    assert_eq!(
        picker.categories[picker.category].items[picker.cursor].id,
        "gpt-other"
    );

    app.reopen_composer_model_after_settings = Some("openai".to_string());
    app.refresh_reopened_composer_model_after_settings = Some("openai".to_string());
    assert!(app.reopen_composer_model_after_provider_settings());
    let picker = app.composer_controls.picker.as_ref().expect("menu");
    assert_eq!(picker.level, 1);
    assert_ne!(picker.categories[picker.category].label, "Config drift");
    assert_eq!(picker.categories[picker.category].id, "openai");
    assert!(
        picker.cursor < picker.categories[picker.category].items.len(),
        "cursor must stay on a real model row, not Config drift"
    );
}

#[test]
fn add_model_save_refreshes_reopened_composer_menu_from_post_save_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let (mut app, _control_rx) = app_with_runner(&tmp);
    app.handle_key(ctrl(KeyCode::Char('p')));
    if app
        .composer_controls
        .picker
        .as_ref()
        .is_some_and(|picker| picker.level == 0)
    {
        app.handle_key(press(KeyCode::Enter));
    }
    let add_id = "\u{0}add-model";
    if let Some(picker) = app.composer_controls.picker.as_mut()
        && let Some(category) = picker.categories.get(picker.category)
        && let Some(index) = category.items.iter().position(|item| item.id == add_id)
    {
        picker.cursor = index;
    }
    app.handle_key(press(KeyCode::Enter));
    assert!(app.reopen_composer_model_after_settings.is_some());
    app.dialog = crate::tui::settings::Dialog::None;
    assert!(app.reopen_composer_model_after_provider_settings());
    assert!(app.refresh_reopened_composer_model_after_settings.is_some());

    let mut providers = app.config_snapshot.providers.clone();
    providers
        .providers
        .get_mut("openai")
        .expect("provider")
        .models
        .push(ModelEntry {
            id: "gpt-added".to_string(),
            ..Default::default()
        });
    let generation = app.config_snapshot.generation.saturating_add(1);
    app.apply_event(cockpit_client::presentation::TurnEvent::ConfigSnapshot {
        snapshot: Box::new(cockpit_proto::ConfigSnapshot {
            session_id: uuid::Uuid::new_v4(),
            generation,
            extended: app.config_snapshot.extended.clone(),
            providers: cockpit_core::secret_ref::redact_provider_view(&providers),
        }),
    });
    assert!(app.refresh_reopened_composer_model_after_settings.is_none());
    let picker = app.composer_controls.picker.as_ref().expect("menu");
    assert!(
        picker
            .categories
            .iter()
            .any(|category| category.items.iter().any(|item| item.id == "gpt-added")),
        "post-save snapshot must rebuild inventory once"
    );
}
