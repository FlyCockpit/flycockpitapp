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
    app.session_rail.set_visible(true);
    draw(&mut app, 120, 40);
    let rail = app.session_rail.rail_area().expect("rail painted");
    let over_rail = Position::new(rail.x + 2, rail.y + 2);
    app.handle_mouse(mouse(MouseEventKind::Moved, over_rail.x, over_rail.y));
    draw(&mut app, 120, 40);
    assert_eq!(app.session_rail.pointer(), Some((over_rail.x, over_rail.y)));
    // The next report is a wheel event far from the rail — not a Move. The
    // rail must not keep hovering the old cell.
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, 100, 30));
    draw(&mut app, 120, 40);
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

// ── Keys and paste enter through the layer stack ────────────────────────

fn queued_item() -> cockpit_proto::QueueItem {
    cockpit_proto::QueueItem {
        id: uuid::Uuid::from_u128(77),
        status: cockpit_proto::QueueItemStatus::Queued,
        text: "queued".to_string(),
        display_text: None,
        target: cockpit_proto::QueueTarget::root("Build"),
        delivery_class: cockpit_proto::QueueDeliveryClass::Steering,
        send_now: false,
    }
}

#[test]
fn a_floating_layer_takes_the_key_before_a_focused_queue_row() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for layer in [Layer::ContextMenu, Layer::KeysOverlay] {
        let mut app = chat_app(tmp.path());
        let item = queued_item();
        let id = item.id;
        app.queue.push(item);
        app.queue_focus = Some(id);
        open_floating(&mut app, layer);
        app.handle_key(key(KeyCode::Char('x')));
        assert!(
            app.toast.is_none(),
            "{layer:?}: `x` reached the queue under the layer: {:?}",
            app.toast.as_ref().map(|toast| toast.text.clone())
        );
        assert_eq!(app.queue_focus, Some(id), "{layer:?}");
        if layer == Layer::ContextMenu {
            assert!(app.context_menu.is_none(), "the menu handled `x` (dismiss)");
        }
    }
}

#[test]
fn a_session_switch_chord_goes_to_the_context_menu_on_top() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    open_floating(&mut app, Layer::ContextMenu);
    assert!(!app.composer_chords_available());
    let counts = app.session_rail.request_counts();
    app.handle_key(KeyEvent::new(KeyCode::Down, KeyModifiers::ALT));
    assert_eq!(
        app.context_menu.as_ref().map(|menu| menu.cursor),
        Some(1),
        "the menu took the key (its cursor moved)"
    );
    assert_eq!(
        app.session_rail.request_counts(),
        counts,
        "no session switch ran"
    );
}

#[test]
fn paste_under_a_floating_layer_reaches_nothing_below_it() {
    // Through the production intake (`handle_observed_terminal_event`), for
    // every floating layer: the paste reaches neither the composer nor any
    // other sink underneath.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for layer in Layer::ALL.into_iter().filter(|layer| layer.is_floating()) {
        let mut app = chat_app(tmp.path());
        open_layer(&mut app, layer);
        assert_eq!(app.top_layer(), layer);
        let at = std::time::Duration::from_secs(10);
        app.event_loop_monotonic_now = at;
        let _ = app.handle_observed_terminal_event(
            crossterm::event::Event::Paste("pasted text".to_string()),
            at,
            1,
            None,
            None,
        );
        let flush = at + std::time::Duration::from_millis(50);
        let decision = app.terminal_paste_classifier.flush_due(flush);
        let _ = app.apply_terminal_paste_decision(decision);
        assert_eq!(
            app.composer.text(),
            "",
            "{layer:?}: the paste reached the composer"
        );
        assert!(
            app.pending_paste_probes.is_empty(),
            "{layer:?}: a paste probe started"
        );
    }
}

#[test]
fn floating_layers_on_the_surface_take_their_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    open_floating(&mut app, Layer::ContextMenu);
    app.handle_key(key(KeyCode::Esc));
    assert!(app.context_menu.is_none());

    let mut app = chat_app(tmp.path());
    app.pins_review = PinsReview::enter(vec![
        cockpit_proto::PinnedMessage {
            seq: 1,
            is_assistant: false,
            text: "one".to_string(),
        },
        cockpit_proto::PinnedMessage {
            seq: 2,
            is_assistant: true,
            text: "two".to_string(),
        },
    ]);
    app.handle_key(key(KeyCode::Char('j')));
    assert_eq!(app.pins_review.as_ref().unwrap().cursor, 1);
    app.handle_key(key(KeyCode::Esc));
    assert!(app.pins_review.is_none());
}

#[test]
fn the_base_quit_key_passes_a_floating_layer_on_either_base() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);

    // Surface base: Ctrl-C arms the interrupt/exit window.
    let mut app = chat_app(tmp.path());
    open_floating(&mut app, Layer::KeysOverlay);
    app.handle_key(ctrl_c);
    assert!(
        app.ctrl_c_armed_at.is_some(),
        "Ctrl-C must reach the surface"
    );

    // Onboarding base: its quit chord closes onboarding.
    let mut app = chat_app(tmp.path());
    mount_onboarding(&mut app, cockpit_proto::OnboardingStage::Profile);
    open_floating(&mut app, Layer::KeysOverlay);
    app.handle_key(ctrl_c);
    assert!(
        app.onboarding_shell.is_none(),
        "Ctrl-C must reach the onboarding shell under the overlay"
    );
}

// ── The onboarding confirmation boundary at app level ───────────────────

fn onboarding_trust_app(tmp: &std::path::Path) -> App {
    let mut app = chat_app(tmp);
    mount_onboarding(&mut app, cockpit_proto::OnboardingStage::Agent);
    app.onboarding_shell
        .as_mut()
        .unwrap()
        .test_mount_agent_model_trust();
    app
}

fn trust(app: &App) -> (Rect, bool) {
    app.onboarding_shell
        .as_ref()
        .unwrap()
        .test_agent_trust()
        .expect("agent screen")
}

fn app_click(app: &mut App, at: Position) {
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), at.x, at.y));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), at.x, at.y));
}

#[test]
fn a_click_in_a_review_box_between_the_two_trust_clicks_disarms() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = onboarding_trust_app(tmp.path());
    open_floating(&mut app, Layer::PinsReview);
    draw(&mut app, 120, 40);
    let (row, _) = trust(&app);
    let row = row.as_position();
    let pins = app
        .pins_review_rect
        .expect("pins box painted")
        .as_position();
    assert_eq!(app.pointer_owner_at(row), Layer::Onboarding);
    app_click(&mut app, row);
    app_click(&mut app, pins);
    draw(&mut app, 120, 40);
    app_click(&mut app, row);
    assert!(
        !trust(&app).1,
        "the review-box click did not break the pair"
    );

    // Control: without the interruption the pair confirms.
    let mut app = onboarding_trust_app(tmp.path());
    open_floating(&mut app, Layer::PinsReview);
    draw(&mut app, 120, 40);
    app_click(&mut app, row);
    draw(&mut app, 120, 40);
    app_click(&mut app, row);
    assert!(trust(&app).1);
}

#[test]
fn the_daemon_prompt_between_the_two_trust_clicks_disarms() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = onboarding_trust_app(tmp.path());
    draw(&mut app, 120, 40);
    let (row, _) = trust(&app);
    let row = row.as_position();
    app_click(&mut app, row);
    app.apply_event(TurnEvent::DaemonRestartPrompt);
    draw(&mut app, 120, 40);
    app.handle_key(key(KeyCode::Char('r')));
    app.daemon_restart_prompt = None;
    draw(&mut app, 120, 40);
    app_click(&mut app, row);
    assert!(!trust(&app).1, "the daemon prompt did not break the pair");
}

// ── Captures follow the pointer's actual owner ──────────────────────────

fn grid_app(tmp: &std::path::Path) -> App {
    let mut app = chat_app(tmp);
    app.copy_on_release = true;
    app.chat_area = Some(Rect::new(0, 0, 11, 1));
    app.chat_text_grid = vec!["hello world".chars().map(|ch| ch.to_string()).collect()];
    app.chat_row_meta = vec![super::mouse_gesture_app_tests::selectable_meta()];
    app
}

#[test]
fn a_drag_that_crosses_into_a_review_box_ends() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = grid_app(tmp.path());
    app.pins_review = PinsReview::enter(vec![cockpit_proto::PinnedMessage {
        seq: 1,
        is_assistant: false,
        text: "pinned".to_string(),
    }]);
    app.pins_review_rect = Some(Rect::new(0, 5, 40, 3));
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    assert!(app.mouse_gesture_state.dragging);
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 6));
    assert!(
        !app.mouse_gesture_state.dragging,
        "the drag outlived its owner"
    );

    // A divider drag released inside the box ends too.
    app.dragging_divider = true;
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 6));
    assert!(!app.dragging_divider);
}

#[test]
fn a_release_swallowed_inside_the_surface_still_ends_the_drag() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = grid_app(tmp.path());
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    assert!(app.mouse_gesture_state.dragging);
    // An overlay inside the surface layer opens and swallows the release.
    app.overlay = super::Overlay::Help(super::help_overlay::HelpOverlay::open());
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    assert!(!app.mouse_gesture_state.dragging);
    assert!(app.mouse_gesture_state.pending_press.is_none());
}

#[test]
fn review_boxes_take_their_cells_for_clicks_and_wheel() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = grid_app(tmp.path());
    app.chat_total_lines = 100;
    app.chat_visible_lines = 1;
    app.pins_review = PinsReview::enter(vec![cockpit_proto::PinnedMessage {
        seq: 1,
        is_assistant: false,
        text: "pinned".to_string(),
    }]);
    app.pins_review_rect = Some(Rect::new(0, 0, 3, 1));
    let offset = app.chat_scroll_offset;
    // Inside the box: the chat under it neither scrolls nor selects.
    app.handle_mouse(mouse(MouseEventKind::ScrollUp, 1, 0));
    assert_eq!(app.chat_scroll_offset, offset, "the wheel reached the chat");
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 2, 0));
    assert!(app.selection.is_none(), "the click reached the chat");
    // Beside the box: the chat does.
    app.handle_mouse(mouse(MouseEventKind::ScrollUp, 8, 0));
    assert_ne!(app.chat_scroll_offset, offset);
}

// ── Hover resolution: every store, every path ───────────────────────────

#[test]
fn settings_button_hover_clears_when_the_pointer_leaves_the_dialog() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = settings_tools_app(tmp.path());
    draw(&mut app, 120, 50);
    let (targets, _) = app.dialog.test_settings_buttons();
    let button = targets
        .first()
        .copied()
        .expect("a registered settings button");
    app.handle_mouse(mouse(MouseEventKind::Moved, button.x, button.y));
    assert!(
        app.dialog.test_settings_buttons().1,
        "hovered over the button"
    );
    // Into the margin outside the dialog (and outside the rail).
    app.handle_mouse(mouse(MouseEventKind::Moved, 119, 49));
    draw(&mut app, 120, 50);
    assert!(
        !app.dialog.test_settings_buttons().1,
        "the button registry kept a hover the pointer left"
    );
}

#[test]
fn a_stationary_pointer_hovers_what_a_new_frame_puts_under_it() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    // Learn where the settings button will be.
    let mut probe = settings_tools_app(tmp.path());
    let idle = draw(&mut probe, 120, 50);
    let (targets, _) = probe.dialog.test_settings_buttons();
    let button = targets
        .first()
        .copied()
        .expect("a registered settings button");
    let cell = Position::new(button.x + 1, button.y);

    // The pointer rests there before the dialog opens; the dialog then
    // appears under it with no further pointer event.
    let mut app = chat_app(tmp.path());
    app.handle_mouse(mouse(MouseEventKind::Moved, cell.x, cell.y));
    let mut dialog = crate::tui::settings::SettingsDialog::open(tmp.path().join("config.json"));
    dialog.test_enter_root_node("Tools");
    app.dialog = Dialog::Settings(Box::new(dialog));
    let presented = draw(&mut app, 120, 50);
    assert_ne!(
        presented[(cell.x, cell.y)].bg,
        idle[(cell.x, cell.y)].bg,
        "the presented frame must already hover the button under the pointer"
    );
}

#[test]
fn a_capture_lost_by_an_editor_restore_forgets_the_pointer() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    app.handle_mouse(mouse(MouseEventKind::Moved, 5, 3));
    app.dragging_divider = true;
    app.sync_mouse_capture_after_restore(false);
    assert!(!app.mouse_capture);
    assert_eq!(app.pointer, None);
    assert!(!app.dragging_divider);
}

#[test]
fn settings_confirmations_drop_only_when_settings_loses_the_input() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = settings_tools_app(tmp.path());
    draw(&mut app, 120, 50);
    app.dialog.test_arm_tools_delete("mytool");

    // A pins box opens over settings: settings lost the top.
    app.pins_review = PinsReview::enter(vec![cockpit_proto::PinnedMessage {
        seq: 1,
        is_assistant: false,
        text: "pinned".to_string(),
    }]);
    draw(&mut app, 120, 50);
    // Settings lost the top to the box: the confirmation is dropped.
    assert!(!app.dialog.test_tools_delete_pending());

    app.dialog.test_arm_tools_delete("mytool");
    let pins = app.pins_review_rect.expect("pins box").as_position();
    app.handle_mouse(mouse(MouseEventKind::Moved, pins.x, pins.y));
    app.handle_mouse(mouse(MouseEventKind::Moved, 60, 10));
    app.handle_mouse(mouse(MouseEventKind::Moved, pins.x, pins.y));
    assert!(
        app.dialog.test_tools_delete_pending(),
        "pointer-owner changes must not drop a keyboard-armed confirmation"
    );
    // The box closes: the top returns to settings, nothing is dropped.
    app.pins_review = None;
    draw(&mut app, 120, 50);
    assert!(app.dialog.test_tools_delete_pending());
    // Settings loses the input to the keys overlay: dropped (fail-safe).
    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    draw(&mut app, 120, 50);
    assert!(!app.dialog.test_tools_delete_pending());

    // A resize voids the pointer's coordinates: it drops an armed
    // confirmation even when the keyboard armed it (fail-safe; an arm does
    // not record which device armed it).
    app.keys_overlay = None;
    draw(&mut app, 120, 50);
    app.dialog.test_arm_tools_delete("mytool");
    app.end_pointer_interactions(super::PointerInteractionEnd::Resize);
    assert!(!app.dialog.test_tools_delete_pending());
}

// ── Keys through the production intake ─────────────────────────────────

/// Put `layer` on top of a chat app. Exhaustive, so a new layer must say how
/// it opens before the intake matrix compiles.
fn open_layer(app: &mut App, layer: Layer) {
    match layer {
        Layer::DaemonRestartPrompt => app.open_daemon_restart_prompt(),
        Layer::KeysOverlay | Layer::ContextMenu | Layer::RulesReview | Layer::PinsReview => {
            open_floating(app, layer)
        }
        Layer::WorkspaceTrust => {
            app.dialog = Dialog::open_workspace_trust(cockpit_config::trust::TrustRoot {
                opened_path: std::path::PathBuf::from("/project"),
                root: std::path::PathBuf::from("/project"),
                kind: cockpit_config::trust::TrustRootKind::Directory,
            });
        }
        Layer::Onboarding => mount_onboarding(app, cockpit_proto::OnboardingStage::Welcome),
        Layer::Surface => {}
    }
}

/// Type `keys` as a real terminal delivers a fast burst: each through
/// `handle_observed_terminal_event` 1 ms apart, then the classifier's idle
/// flush as the event loop's paste-wait arm runs it.
fn typed_burst(app: &mut App, keys: &[KeyCode]) -> bool {
    let start = std::time::Duration::from_secs(10);
    let mut exit = false;
    for (index, code) in keys.iter().enumerate() {
        let at = start + std::time::Duration::from_millis(index as u64);
        app.event_loop_monotonic_now = at;
        exit |= app.handle_observed_terminal_event(
            crossterm::event::Event::Key(key(*code)),
            at,
            1,
            None,
            None,
        );
    }
    let flush = start + std::time::Duration::from_millis(keys.len() as u64 + 50);
    app.event_loop_monotonic_now = flush;
    let decision = app.terminal_paste_classifier.flush_due(flush);
    exit |= app.apply_terminal_paste_decision(decision);
    exit
}

#[test]
fn a_typing_burst_reaches_the_layer_on_top_never_a_hidden_composer() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for layer in Layer::ALL {
        let mut app = chat_app(tmp.path());
        open_layer(&mut app, layer);
        assert_eq!(app.top_layer(), layer, "{layer:?} is on top");
        assert_eq!(
            app.structured_paste_composer_eligible(),
            layer == Layer::Surface,
            "{layer:?}: only the surface's composer may intake-buffer keys"
        );
        // Keys the layer itself handles, typed fast enough to be buffered as
        // a rapid-paste candidate when the composer is eligible.
        let keys: &[KeyCode] = match layer {
            Layer::DaemonRestartPrompt => &[KeyCode::Tab, KeyCode::Enter],
            Layer::KeysOverlay => &[KeyCode::Char('j'), KeyCode::Char('q')],
            Layer::ContextMenu => &[KeyCode::Char('j')],
            Layer::RulesReview | Layer::PinsReview => &[KeyCode::Char('j'), KeyCode::Enter],
            Layer::WorkspaceTrust | Layer::Onboarding | Layer::Surface => {
                &[KeyCode::Char('x'), KeyCode::Char('y')]
            }
        };
        typed_burst(&mut app, keys);
        if layer == Layer::Surface {
            assert_eq!(app.composer.text(), "xy", "the surface composer types");
            continue;
        }
        assert_eq!(
            app.composer.text(),
            "",
            "{layer:?}: typed into the hidden composer"
        );
        match layer {
            // Tab moved the focus to Quit; Enter activated it.
            Layer::DaemonRestartPrompt => assert!(app.exit_requested, "Tab+Enter must quit"),
            Layer::KeysOverlay => assert!(app.keys_overlay.is_none(), "`q` must close it"),
            Layer::ContextMenu => {
                assert_eq!(app.context_menu.as_ref().map(|menu| menu.cursor), Some(1));
            }
            Layer::RulesReview => assert!(app.rules_review.is_some()),
            Layer::PinsReview => assert!(app.pins_review.is_some()),
            Layer::WorkspaceTrust => assert_eq!(app.base_layer(), Layer::WorkspaceTrust),
            Layer::Onboarding => assert!(app.onboarding_shell.is_some()),
            Layer::Surface => unreachable!(),
        }
    }
}

#[test]
fn the_daemon_prompt_restart_key_reaches_the_prompt_through_the_intake() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    app.apply_event(TurnEvent::DaemonRestartPrompt);
    assert_eq!(app.top_layer(), Layer::DaemonRestartPrompt);
    typed_burst(&mut app, &[KeyCode::Char('r')]);
    assert_eq!(
        app.composer.text(),
        "",
        "`r` was typed into the hidden composer"
    );
    // No runner in this app: the prompt's restart reports it unavailable.
    assert!(
        app.toast
            .as_ref()
            .is_some_and(|toast| toast.text.contains("restart is unavailable")),
        "`r` must reach the prompt's restart"
    );
}

#[test]
fn a_typing_burst_reaches_the_surface_owner_ahead_of_the_composer() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());

    let mut app = chat_app(tmp.path());
    app.pending_stop_confirm = Some(Vec::new());
    typed_burst(&mut app, &[KeyCode::Char('n')]);
    assert!(app.pending_stop_confirm.is_none(), "`n` must cancel /stop");
    assert_eq!(app.composer.text(), "");

    let mut app = chat_app(tmp.path());
    app.pending_prune_confirm = true;
    typed_burst(&mut app, &[KeyCode::Char('n')]);
    assert!(!app.pending_prune_confirm, "`n` must cancel /prune");
    assert_eq!(app.composer.text(), "");

    let mut app = chat_app(tmp.path());
    app.session_rail.focus();
    typed_burst(&mut app, &[KeyCode::Char('j'), KeyCode::Char('k')]);
    assert_eq!(app.composer.text(), "", "the focused rail takes its keys");

    let mut app = chat_app(tmp.path());
    app.overlay = super::Overlay::Help(super::help_overlay::HelpOverlay::open());
    typed_burst(&mut app, &[KeyCode::Char('x'), KeyCode::Char('y')]);
    assert_eq!(app.composer.text(), "", "the help overlay takes its keys");
}

#[test]
fn a_key_taken_by_a_persisting_review_box_disarms_the_onboarding_confirmation() {
    // Isolates the key path: the box is on top before either trust click
    // and stays on top across the key, so no top-layer change disarms.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = onboarding_trust_app(tmp.path());
    open_floating(&mut app, Layer::RulesReview);
    draw(&mut app, 120, 40);
    let (row, _) = trust(&app);
    let row = row.as_position();
    let rules = app.rules_review_rect.expect("rules box painted");
    assert!(
        !rules.contains(row),
        "the trust row must be outside the box"
    );

    // Control: two clicks with nothing between them confirm.
    let mut control = onboarding_trust_app(tmp.path());
    open_floating(&mut control, Layer::RulesReview);
    draw(&mut control, 120, 40);
    app_click(&mut control, row);
    draw(&mut control, 120, 40);
    app_click(&mut control, row);
    assert!(trust(&control).1, "two uninterrupted clicks confirm");

    app_click(&mut app, row);
    draw(&mut app, 120, 40);
    app.handle_key(key(KeyCode::Char('j')));
    assert_eq!(app.top_layer(), Layer::RulesReview, "the box stayed on top");
    draw(&mut app, 120, 40);
    app_click(&mut app, row);
    assert!(
        !trust(&app).1,
        "the key taken by the box did not break the pair"
    );
}

#[test]
fn a_successful_editor_round_trip_ends_captures_and_forgets_the_pointer() {
    // Capture was off on the terminal while the editor ran, so a release in
    // that interval never arrived — even though the restore turned capture
    // back on.
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = chat_app(tmp.path());
    app.handle_mouse(mouse(MouseEventKind::Moved, 5, 3));
    arm_every_capture(&mut app);
    app.sync_mouse_capture_after_restore(true);
    assert!(app.mouse_capture, "the restore turned capture back on");
    assert_eq!(app.pointer, None, "the pointer was forgotten");
    assert_every_capture_ended_and_committed_actions_kept(&app, "editor round trip");
}

// ── Surface popovers occlude what they cover ───────────────────────────

fn transcript_app(tmp: &std::path::Path) -> App {
    let mut app =
        App::new_with_workspace_trust(Some(tmp), false, super::StartupWorkspaceTrust::Decided);
    app.dialog = Dialog::None;
    app.launch.banner_enabled = false;
    app.mouse_capture = true;
    for seq in 0..30i64 {
        app.history.push(crate::tui::history::HistoryEntry::User {
            text: format!("user message number {seq} with enough text to fill the row"),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: Some(seq * 2),
            optimistic_submission_id: None,
            preflight_pending: false,
            persist_failed: false,
        });
    }
    app
}

fn is_transcript_control(dispatch: &crate::tui::button::ButtonDispatch) -> bool {
    use crate::tui::button::ButtonDispatch;
    matches!(
        dispatch,
        ButtonDispatch::TranscriptPin { .. }
            | ButtonDispatch::TranscriptUnpin { .. }
            | ButtonDispatch::TranscriptFork { .. }
    )
}

/// Cells of transcript Pin/Fork controls painted this frame, from the
/// transcript's own row geometry (not the registry under test).
fn transcript_control_cells(app: &App) -> Vec<Position> {
    let area = app.chat_area.expect("transcript painted");
    let mut cells = Vec::new();
    for (row, meta) in app.chat_row_meta.iter().enumerate() {
        for hit in [meta.pin_hit, meta.fork_hit].into_iter().flatten() {
            if hit.col_end > hit.col_start {
                cells.push(Position::new(area.x + hit.col_start, area.y + row as u16));
            }
        }
    }
    cells
}

#[test]
fn a_body_overlay_takes_the_pointer_from_the_transcript_controls_it_covers() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = transcript_app(tmp.path());
    app.overlay = super::Overlay::Help(super::help_overlay::HelpOverlay::open());
    draw(&mut app, 120, 50);
    let popover = app.last_popover_rect;
    let cells = transcript_control_cells(&app);
    let covered: Vec<Position> = cells
        .iter()
        .copied()
        .filter(|cell| popover.contains(*cell))
        .collect();
    assert!(
        !covered.is_empty(),
        "the fixture must paint transcript controls under the popover"
    );
    assert!(
        app.button_registry
            .targets()
            .iter()
            .all(|target| !is_transcript_control(&target.dispatch)
                || !target.rect.intersects(popover)),
        "a covered transcript control is still registered"
    );
    let history = app.history.len();
    for cell in covered {
        app.handle_mouse(mouse(MouseEventKind::Moved, cell.x, cell.y));
        draw(&mut app, 120, 50);
        assert!(
            app.button_registry.hover().is_none(),
            "{cell:?} hovers under help"
        );
        app.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            cell.x,
            cell.y,
        ));
        assert!(
            app.button_registry.pressed().is_none(),
            "{cell:?} pressed under help"
        );
        app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), cell.x, cell.y));
        assert!(matches!(app.overlay, super::Overlay::Help(_)));
        assert!(app.pin_pick.is_none() && app.fork_pick.is_none());
        assert_eq!(app.history.len(), history, "{cell:?} acted under help");
        assert!(app.toast.is_none(), "{cell:?} acted under help");
    }

    // Inverse: a transcript control the popover does not cover stays live.
    if let Some(open) = cells.iter().copied().find(|cell| !popover.contains(*cell)) {
        assert!(
            app.button_registry
                .hit(open.x, open.y)
                .is_some_and(|target| is_transcript_control(&target.dispatch)),
            "an uncovered control lost the pointer"
        );
    }
}

#[test]
fn transcript_controls_take_the_pointer_when_no_popover_covers_them() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let mut app = transcript_app(tmp.path());
    draw(&mut app, 120, 50);
    let cells = transcript_control_cells(&app);
    assert!(!cells.is_empty());
    for cell in cells {
        assert!(
            app.button_registry
                .hit(cell.x, cell.y)
                .is_some_and(|target| is_transcript_control(&target.dispatch)),
            "{cell:?} is not hit-testable without a popover"
        );
    }
}

#[test]
fn leader_actions_run_only_over_the_chat_surface() {
    let tmp = tempfile::tempdir().unwrap();
    let _home = TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    for base in [Layer::Onboarding, Layer::WorkspaceTrust, Layer::Surface] {
        let mut app = App::new_with_workspace_trust(
            Some(tmp.path()),
            false,
            super::StartupWorkspaceTrust::Decided,
        );
        app.dialog = Dialog::None;
        open_layer(&mut app, base);
        open_floating(&mut app, Layer::KeysOverlay);
        assert_eq!(app.base_layer(), base);
        app.handle_key(key(KeyCode::Char('n')));
        let notes_open = matches!(app.overlay, super::Overlay::Notes(_));
        if base == Layer::Surface {
            assert!(notes_open, "the leader action runs over the surface");
            assert!(app.keys_overlay.is_none());
        } else {
            assert!(!notes_open, "{base:?}: a leader action ran under the base");
            assert!(
                app.keys_overlay.is_some(),
                "{base:?}: an ordinary overlay key"
            );
        }
    }
}
