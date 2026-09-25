//! The app pointer model (`app/pointer.rs`) end to end: layer ownership of
//! keys, pointer and hover; hover resolution; capture boundaries; and the
//! committed actions that survive them.

use super::App;
use super::pointer::Layer;
use crate::tui::context_menu::ContextMenu;
use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
use crate::tui::pins_overlay::PinsReview;
use crate::tui::rules_overlay::RulesReview;
use crate::tui::settings::Dialog;
use cockpit_client::presentation::TurnEvent;
use cockpit_test_support::TestEnvGuard;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::buffer::Buffer;
use ratatui::layout::{Position, Rect};
use ratatui::{Terminal, backend::TestBackend};

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn draw(app: &mut App, width: u16, height: u16) -> Buffer {
    let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
    app.draw_resolving_pointer(&mut terminal).unwrap();
    terminal.backend().buffer().clone()
}

fn find(buffer: &Buffer, needle: &str) -> Option<Position> {
    let area = buffer.area;
    (area.top()..area.bottom()).find_map(|y| {
        let row: String = (area.left()..area.right())
            .map(|x| buffer[(x, y)].symbol())
            .collect();
        row.find(needle)
            .map(|byte| Position::new(area.x + row[..byte].chars().count() as u16, y))
    })
}

fn snapshot(stage: cockpit_proto::OnboardingStage) -> cockpit_proto::OnboardingBootstrapSnapshot {
    cockpit_proto::OnboardingBootstrapSnapshot {
        run_id: uuid::Uuid::from_u128(1),
        attempt_id: uuid::Uuid::from_u128(2),
        revision: 3,
        stage,
        bootstrap_state: cockpit_proto::OnboardingBootstrapState::Ready,
        limited_mode: false,
        lifetime_selection: None,
        host_capabilities: cockpit_proto::HostCapabilitySnapshot::unpublished(),
        last_receipt: None,
    }
}

fn mount_onboarding(app: &mut App, stage: cockpit_proto::OnboardingStage) {
    app.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
        &snapshot(stage),
        false,
    )));
}

fn chat_app(tmp: &std::path::Path) -> App {
    let mut app = App::new(Some(tmp), false);
    app.dialog = Dialog::None;
    app.mouse_capture = true;
    app
}

fn open_floating(app: &mut App, layer: Layer) {
    match layer {
        Layer::KeysOverlay => app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer)),
        Layer::ContextMenu => {
            app.context_menu = Some(ContextMenu {
                preferred_origin: (10, 5),
                clicked_chat_row: 0,
                cursor: 0,
                items: ContextMenu::build_items(false, false),
            });
        }
        Layer::PinsReview => {
            app.pins_review = PinsReview::enter(vec![cockpit_proto::PinnedMessage {
                seq: 1,
                is_assistant: false,
                text: "pinned".to_string(),
            }]);
        }
        Layer::RulesReview => {
            app.rules_review = RulesReview::enter(vec![cockpit_proto::ConversationRule {
                rule_id: uuid::Uuid::new_v4(),
                lineage_id: uuid::Uuid::new_v4(),
                text: "cite the spec".to_string(),
                created_by: cockpit_proto::ConversationRuleCreatedBy::User,
                source_trust: cockpit_proto::ConversationRuleSourceTrust::Trusted,
                created_at_unix_ms: 0,
            }]);
        }
        other => panic!("{other:?} is not a floating layer"),
    }
}

fn floating_open(app: &App, layer: Layer) -> bool {
    match layer {
        Layer::KeysOverlay => app.keys_overlay.is_some(),
        Layer::ContextMenu => app.context_menu.is_some(),
        Layer::PinsReview => app.pins_review.is_some(),
        Layer::RulesReview => app.rules_review.is_some(),
        other => panic!("{other:?} is not a floating layer"),
    }
}

/// A cell the floating layer takes the pointer on.
fn cell_of(app: &App, layer: Layer) -> Position {
    match layer {
        Layer::PinsReview => app
            .pins_review_rect
            .expect("pins box painted")
            .as_position(),
        Layer::RulesReview => app
            .rules_review_rect
            .expect("rules box painted")
            .as_position(),
        _ => Position::new(40, 12),
    }
}

#[test]
fn every_floating_layer_keeps_keys_pointer_and_hover_over_a_later_mounted_onboarding_shell() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for layer in [
        Layer::KeysOverlay,
        Layer::ContextMenu,
        Layer::PinsReview,
        Layer::RulesReview,
    ] {
        let mut app = chat_app(tmp.path());
        open_floating(&mut app, layer);
        draw(&mut app, 100, 30);
        // Onboarding mounts asynchronously underneath the open layer.
        mount_onboarding(&mut app, cockpit_proto::OnboardingStage::Profile);
        draw(&mut app, 100, 30);

        assert_eq!(app.top_layer(), layer, "{layer:?} is painted on top");
        assert_eq!(app.key_owner(), layer, "{layer:?} keeps the keys");
        let cell = cell_of(&app, layer);
        assert_eq!(
            app.pointer_owner_at(cell),
            layer,
            "{layer:?} keeps the pointer"
        );

        // Hover: the shell underneath paints none while the layer owns the
        // pointer there.
        app.handle_mouse(mouse(MouseEventKind::Moved, cell.x, cell.y));
        draw(&mut app, 100, 30);
        assert!(
            !app.onboarding_shell.as_ref().unwrap().test_pointer_owned(),
            "{layer:?}: the shell under it must not own the pointer"
        );

        // It can be closed with its own key, and then onboarding owns input.
        app.handle_key(key(KeyCode::Esc));
        assert!(!floating_open(&app, layer), "{layer:?} must close on Esc");
        assert_eq!(app.key_owner(), Layer::Onboarding);
        draw(&mut app, 100, 30);
        assert_eq!(
            app.pointer_owner_at(Position::new(40, 12)),
            Layer::Onboarding
        );
    }
}

#[test]
fn the_surface_resolver_gates_every_hover_on_pointer_ownership() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    let link = Rect::new(4, 3, 10, 1);
    app.link_registry.register(link, "https://x.test", "link");
    app.pointer = Some(Position::new(5, 3));
    app.resolve_pointer_hover();
    assert!(
        app.link_registry.hovered().is_some(),
        "owned pointer over the link"
    );

    // A floating layer opens: the surface no longer owns the pointer, so
    // the resolver clears every surface hover.
    open_floating(&mut app, Layer::KeysOverlay);
    app.queue_hover = Some(uuid::Uuid::from_u128(9));
    app.hovered_affordance = Some(super::AffordanceTarget::Chip { history_index: 1 });
    assert!(app.resolve_pointer_hover());
    assert!(app.link_registry.hovered().is_none());
    assert_eq!(app.queue_hover, None);
    assert_eq!(app.hovered_affordance, None);
    assert_eq!(app.session_rail.pointer(), None);
}

#[test]
fn rail_hover_follows_the_last_reported_pointer_not_only_motion() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    app.session_rail.set_pointer(Some((2, 2)));
    // A click (not a Move) elsewhere reports the pointer's new position.
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, 60, 20));
    app.resolve_pointer_hover();
    assert_eq!(
        app.session_rail.pointer(),
        None,
        "the rail kept an old position"
    );
}

#[test]
fn turning_mouse_capture_off_by_either_path_forgets_every_hover_and_ends_captures() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for via_slash in [true, false] {
        let mut app = chat_app(tmp.path());
        let link = Rect::new(4, 3, 10, 1);
        app.link_registry.register(link, "https://x.test", "link");
        app.handle_mouse(mouse(MouseEventKind::Moved, 5, 3));
        assert!(app.link_registry.hovered().is_some());
        app.hovered_suggestion = None;
        app.queue_hover = Some(uuid::Uuid::from_u128(9));
        app.session_rail.set_pointer(Some((1, 1)));
        app.dragging_divider = true;
        app.composer_controls.picker_scroll_drag = true;
        if via_slash {
            app.toggle_mouse_capture_inline();
        } else {
            app.set_mouse_capture_live(false);
        }
        assert!(!app.mouse_capture, "via_slash={via_slash}");
        assert!(
            app.link_registry.hovered().is_none(),
            "via_slash={via_slash}"
        );
        assert_eq!(app.queue_hover, None, "via_slash={via_slash}");
        assert_eq!(app.session_rail.pointer(), None, "via_slash={via_slash}");
        assert_eq!(app.pointer, None, "via_slash={via_slash}");
        assert!(!app.dragging_divider, "via_slash={via_slash}");
        assert!(
            !app.composer_controls.picker_scroll_drag,
            "via_slash={via_slash}"
        );
    }
}

#[test]
fn an_ownership_change_ends_captures_before_the_next_pointer_event() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());

    // A divider drag, then the leader opens the which-key overlay: the
    // overlay swallows the release, so the drag must end when it opens.
    let mut app = chat_app(tmp.path());
    app.handle_mouse(mouse(MouseEventKind::Moved, 1, 1));
    app.dragging_divider = true;
    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 1));
    assert!(!app.dragging_divider, "the divider drag outlived its owner");
    app.keys_overlay = None;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 1));
    assert!(!app.dragging_divider);

    // A composer picker drag, then onboarding mounts asynchronously.
    let mut app = chat_app(tmp.path());
    app.handle_mouse(mouse(MouseEventKind::Moved, 1, 1));
    app.composer_controls.picker_scroll_drag = true;
    mount_onboarding(&mut app, cockpit_proto::OnboardingStage::Profile);
    app.handle_mouse(mouse(MouseEventKind::Moved, 3, 3));
    assert!(
        !app.composer_controls.picker_scroll_drag,
        "plain motion must not keep driving a drag the owner lost"
    );

    // An async mount with no pointer event in between ends it at render.
    let mut app = chat_app(tmp.path());
    draw(&mut app, 80, 24);
    app.dragging_divider = true;
    mount_onboarding(&mut app, cockpit_proto::OnboardingStage::Profile);
    draw(&mut app, 80, 24);
    assert!(!app.dragging_divider);
}

fn arm_every_capture(app: &mut App) {
    // Onboarding is mounted so its provider scrollbar can be dragged.
    mount_onboarding(app, cockpit_proto::OnboardingStage::Provider);
    let engine = Dialog::None;
    let mut links = crate::tui::links::LinkRegistry::default();
    let shell = app.onboarding_shell.as_mut().unwrap();
    crate::tui::golden::render_frame(80, 20, |frame| {
        shell.render(frame, frame.area(), &engine, &mut links);
    });
    let scrollbar = shell.test_provider_scrollbar().expect("provider screen");
    let mut pointer_engine = Dialog::None;
    shell.handle_mouse(
        mouse(
            MouseEventKind::Down(MouseButton::Left),
            scrollbar.x,
            scrollbar.y,
        ),
        &mut pointer_engine,
    );
    assert!(shell.test_pointer_captured());
    app.sync_pointer_owner();

    // Link press, app button press, rail confirm press, settings press.
    let now = std::time::Instant::now();
    let _ = app.link_pointer_gesture.handle(
        MouseEventKind::Down(MouseButton::Left),
        2,
        2,
        Some("https://x.test"),
        app.link_registry.generation(),
        now,
    );
    assert!(app.link_pointer_gesture.has_pending_press());
    app.button_registry.begin_frame(true, 1);
    app.button_registry.register(
        Rect::new(0, 0, 6, 1),
        crate::tui::button::ButtonSpec::new(
            crate::tui::button::ButtonId::NoteNew,
            "new",
            crate::tui::button::ButtonDispatch::NoteNew,
        ),
    );
    app.button_registry
        .handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    assert!(app.button_registry.pressed().is_some());
    app.session_rail
        .test_press_confirm_button(Rect::new(0, 5, 8, 1));
    app.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        std::env::temp_dir().join("pointer-tests-config.json"),
    )));
    app.dialog.test_press_settings_button(Rect::new(2, 2, 8, 1));
    app.dragging_divider = true;
    app.composer_controls.picker_scroll_drag = true;
    app.pending_performance_chip_press = None;

    // A completed click: a link activation waiting out its window.
    app.pending_link_activation = Some(crate::tui::links::PendingActivation {
        url: "https://done.test".into(),
        token: 7,
        deadline: now + std::time::Duration::from_millis(400),
    });
}

fn assert_every_capture_ended_and_committed_actions_kept(app: &App, context: &str) {
    assert!(
        !app.onboarding_shell
            .as_ref()
            .unwrap()
            .test_pointer_captured(),
        "{context}: onboarding scrollbar drag"
    );
    assert!(
        !app.link_pointer_gesture.has_pending_press(),
        "{context}: link press"
    );
    assert!(
        app.button_registry.pressed().is_none(),
        "{context}: button press"
    );
    assert!(
        !app.session_rail.test_confirm_pressed(),
        "{context}: rail press"
    );
    assert!(
        !app.dialog.test_settings_button_pressed(),
        "{context}: settings press"
    );
    assert!(!app.dragging_divider, "{context}: divider drag");
    assert!(
        !app.composer_controls.picker_scroll_drag,
        "{context}: picker drag"
    );
    assert!(
        app.pending_link_activation.is_some(),
        "{context}: a completed link click must still activate"
    );
}

#[test]
fn both_daemon_restart_prompt_sites_end_every_capture_and_keep_completed_actions() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());

    let mut app = chat_app(tmp.path());
    arm_every_capture(&mut app);
    app.apply_event(TurnEvent::DaemonRestartPrompt);
    assert!(app.daemon_restart_prompt.is_some());
    assert_every_capture_ended_and_committed_actions_kept(&app, "apply_event");

    let mut app = chat_app(tmp.path());
    arm_every_capture(&mut app);
    app.apply_provisional_global_event(TurnEvent::DaemonRestartPrompt);
    assert!(app.daemon_restart_prompt.is_some());
    assert_every_capture_ended_and_committed_actions_kept(&app, "provisional");
}

#[test]
fn resize_and_focus_loss_end_captures_keep_completed_actions_and_forget_the_pointer() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for event in [
        crossterm::event::Event::Resize(100, 30),
        crossterm::event::Event::FocusLost,
    ] {
        let mut app = chat_app(tmp.path());
        arm_every_capture(&mut app);
        app.handle_mouse(mouse(MouseEventKind::Moved, 3, 3));
        app.handle_terminal_event(event.clone());
        assert_every_capture_ended_and_committed_actions_kept(&app, &format!("{event:?}"));
        assert_eq!(app.pointer, None, "{event:?}");
        assert!(
            app.onboarding_shell
                .as_ref()
                .unwrap()
                .test_pointer()
                .is_none(),
            "{event:?}"
        );
    }
}

fn settings_tools_app(tmp: &std::path::Path) -> App {
    let mut app = chat_app(tmp);
    let mut dialog = crate::tui::settings::SettingsDialog::open(tmp.join("config.json"));
    dialog.test_enter_root_node("Tools");
    app.dialog = Dialog::Settings(Box::new(dialog));
    app
}

fn hovered(buffer: &Buffer, at: Position) -> bool {
    buffer[(at.x, at.y)].bg != ratatui::style::Color::Reset
}

#[test]
fn settings_help_row_hover_belongs_to_the_top_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = settings_tools_app(tmp.path());
    let idle = draw(&mut app, 120, 50);
    let button = find(&idle, "[ reset to defaults ]").expect("tools help-row action");
    let label = Position::new(button.x + 3, button.y);
    assert!(!hovered(&idle, label));

    app.handle_mouse(mouse(MouseEventKind::Moved, label.x, label.y));
    let owned = draw(&mut app, 120, 50);
    assert!(
        hovered(&owned, label),
        "the settings surface owns the pointer"
    );

    // The which-key overlay opens on top (not over the help row): the row
    // underneath no longer owns the pointer and paints no hover.
    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    let covered = draw(&mut app, 120, 50);
    assert!(
        find(&covered, "[ reset to defaults ]").is_some(),
        "the help row stays visible beside the overlay"
    );
    assert!(!hovered(&covered, label), "hover under the keys overlay");
}

#[test]
fn settings_records_a_pointer_event_another_layer_consumed() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = settings_tools_app(tmp.path());
    draw(&mut app, 120, 50);
    // The keys overlay takes this event; settings never handles it itself.
    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    app.handle_mouse(mouse(MouseEventKind::Moved, 20, 7));
    assert_eq!(
        app.dialog.test_help_row_pointer(),
        Some(Position::new(20, 7))
    );
    assert_eq!(app.pointer, Some(Position::new(20, 7)));
}
