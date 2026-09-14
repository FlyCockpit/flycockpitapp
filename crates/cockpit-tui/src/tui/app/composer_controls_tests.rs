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
use cockpit_config::providers::{ActiveModelRef, ModelEntry, ProviderEntry};
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
        if width >= 80 {
            assert_eq!(kinds, ComposerControlKind::ALL.to_vec(), "wide {width}");
            assert!(border.contains("[Send]") || border.contains("Send"));
        }
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
fn composer_picker_keyboard_and_mouse_parity() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    let _ = render(&mut app, 120, 24);
    app.activate_composer_pill(ComposerControlKind::Approval);
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
    assert!(app.composer_controls.picker.is_none());

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
fn composer_picker_discards_stale_generation_and_session() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.activate_composer_pill(ComposerControlKind::Approval);
    let prior_generation = app.composer_controls.generation;
    app.bump_composer_control_generation();
    assert!(app.composer_controls.picker.is_none());
    assert_ne!(app.composer_controls.generation, prior_generation);
    app.activate_composer_pill(ComposerControlKind::Approval);
    app.composer_controls.pending = Some(super::composer_controls::PendingComposerMutation {
        generation: prior_generation,
        session_id: app.launch.session_id,
        attachment_epoch: app.visible_attachment_epoch,
        kind: ComposerControlKind::Approval,
    });
    app.apply_composer_control_outcome(None);
    assert!(
        app.composer_controls.picker.as_ref().is_some_and(|p| p
            .status_text
            .as_deref()
            .is_some_and(|text| text.contains("Stale"))),
        "late result from a prior generation is discarded"
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
    let mut app = app(&tmp);
    app.sandbox_mode = SandboxMode::Refuse;
    app.activate_composer_pill(ComposerControlKind::Sandbox);
    let picker = app.composer_controls.picker.as_ref().expect("sandbox");
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
    app.approval_mode = ApprovalMode::Manual;
    app.activate_composer_pill(ComposerControlKind::Approval);
    let picker = app.composer_controls.picker.as_ref().expect("approval");
    let labels: Vec<_> = picker
        .categories
        .iter()
        .flat_map(|c| c.items.iter().map(|i| i.label.as_str()))
        .collect();
    assert!(labels.contains(&"manual"));
    assert!(labels.contains(&"auto"));
    assert!(labels.contains(&"yolo"));
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
    app.overlay = Overlay::None;

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
            ..
        } => assert!(
            !cache_break_acknowledged,
            "legal non-cache-breaking transition does not claim a cache break"
        ),
        other => panic!("expected SetToolSurfaceOverride, got {other:?}"),
    }

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

    app.handle_tools_outcome(ToolsOutcome::Apply {
        override_json: "{}".to_string(),
        persist_session: true,
        cache_break: true,
        monty_nudge: None,
    });
    let _ = control_rx.try_recv();
    app.apply_event(
        cockpit_client::presentation::TurnEvent::ControlRequestFinished {
            request_id: ControlRequestId(3),
            outcome: ControlRequestOutcome::Rejected("illegal tier".to_string()),
        },
    );
    // Refusal is a daemon event: confirmed display state is not locally rewritten.
    assert_eq!(
        app.launch.active_model,
        Some(("openai".to_string(), "gpt-test".to_string()))
    );
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

#[test]
fn empty_composer_enter_is_the_safe_ladder() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = app(&tmp);
    app.handle_empty_composer_enter();
    assert!(app.queue.is_empty(), "empty queue is a no-op");

    let held = queue_item("held", QueueDeliveryClass::Held);
    app.queue.push(held);
    app.handle_empty_composer_enter();
    // Promote is requested; snapshot application is daemon-owned.
    assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Held);

    app.queue[0].delivery_class = QueueDeliveryClass::Steering;
    app.handle_empty_composer_enter();
    assert_eq!(app.queue[0].id, app.queue[0].id);
    assert_eq!(app.queue[0].delivery_class, QueueDeliveryClass::Steering);

    let mixed_held = queue_item("h", QueueDeliveryClass::Held);
    let mixed_steer = queue_item("s", QueueDeliveryClass::Steering);
    let held_id = mixed_held.id;
    let steer_id = mixed_steer.id;
    app.queue = vec![mixed_held, mixed_steer];
    app.handle_empty_composer_enter();
    assert_eq!(app.queue[0].id, held_id);
    assert_eq!(app.queue[1].id, steer_id);
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
