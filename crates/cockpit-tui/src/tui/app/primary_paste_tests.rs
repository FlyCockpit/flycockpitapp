use std::path::Path;
use std::time::Duration;

use crossterm::event::{
    Event, KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::Rect;

use super::{App, FooterHitArea, Overlay};
use crate::clipboard::PlatformKind;
use crate::tui::context_menu::ContextMenu;
use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
use crate::tui::primary_paste::{
    FakeHeldPrimaryAdapter, HeldLocalDisplayConnection, PrimaryDisplayBackend, PrimaryPasteAdapter,
    PrimaryPasteEnv, PrimaryPasteLayer, PrimaryPasteOutcome, PrimaryPasteSkip, eligibility,
};
use crate::tui::settings::Dialog;
use crate::tui::structured_paste::PasteSource;

const HELD_TOKEN: u64 = 0xC0_11_EC_7;

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn middle_down(column: u16, row: u16) -> MouseEvent {
    mouse(MouseEventKind::Down(MouseButton::Middle), column, row)
}

fn local_linux() -> PrimaryPasteEnv {
    PrimaryPasteEnv::local_linux()
}

fn held() -> HeldLocalDisplayConnection {
    HeldLocalDisplayConnection {
        backend: PrimaryDisplayBackend::WaylandHeld,
        token: HELD_TOKEN,
    }
}

fn primary_ready_app(tmp: &tempfile::TempDir) -> App {
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app.dialog = Dialog::None;
    app.mouse_capture = true;
    app.terminal_input_generation = Some(1);
    app.event_loop_monotonic_now = Duration::from_millis(10);
    app.input_area = Some(Rect::new(0, 20, 80, 6));
    app.chat_area = Some(Rect::new(0, 0, 80, 20));
    app.primary_paste =
        crate::tui::primary_paste::PrimaryPasteController::for_test(local_linux(), fake_adapter());
    crate::tui::app::seed_ready_model_for_tests(&mut app);
    app
}

fn fake_adapter() -> FakeHeldPrimaryAdapter {
    FakeHeldPrimaryAdapter::new(HELD_TOKEN)
}

fn composer_text(app: &App) -> String {
    app.composer.text().to_string()
}

fn paste_host(app: &App) -> crate::tui::structured_paste::HostIdentity {
    crate::tui::structured_paste::HostIdentity {
        client_instance_id: app.paste_client_instance_id,
        connection_epoch: 0,
        session_id: app.launch.session_id.unwrap_or(uuid::Uuid::nil()),
        terminal_generation: app.terminal_input_generation.unwrap_or_default(),
    }
}

fn walk_rs(dir: &Path, f: &mut dyn FnMut(&Path, &str)) {
    if let Ok(rd) = std::fs::read_dir(dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.is_dir() {
                walk_rs(&p, f);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs")
                && let Ok(src) = std::fs::read_to_string(&p)
            {
                f(&p, &src);
            }
        }
    }
}

#[test]
fn primary_paste_platform_gate() {
    let held_conn = held();
    let linux = local_linux();
    assert_eq!(
        eligibility(
            linux,
            PrimaryDisplayBackend::WaylandHeld,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            true,
        ),
        Ok(())
    );

    let mut skipped = Vec::new();
    for platform in [
        PlatformKind::MacOs,
        PlatformKind::Windows,
        PlatformKind::Other,
    ] {
        let env = PrimaryPasteEnv { platform, ..linux };
        skipped.push((
            "platform",
            eligibility(
                env,
                PrimaryDisplayBackend::WaylandHeld,
                Some(&held_conn),
                PrimaryPasteLayer::Composer,
                true,
            ),
        ));
    }
    for layer in [
        PrimaryPasteLayer::Chat,
        PrimaryPasteLayer::Footer,
        PrimaryPasteLayer::ContextMenu,
        PrimaryPasteLayer::Settings,
        PrimaryPasteLayer::Dialog,
        PrimaryPasteLayer::Overlay,
        PrimaryPasteLayer::KeysOverlay,
        PrimaryPasteLayer::EmbeddedPane,
        PrimaryPasteLayer::BtwPane,
        PrimaryPasteLayer::SuggestionBox,
        PrimaryPasteLayer::Other,
    ] {
        skipped.push((
            "layer",
            eligibility(
                linux,
                PrimaryDisplayBackend::WaylandHeld,
                Some(&held_conn),
                layer,
                true,
            ),
        ));
    }
    skipped.push((
        "capture",
        eligibility(
            linux,
            PrimaryDisplayBackend::WaylandHeld,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            false,
        ),
    ));
    skipped.push((
        "ssh",
        eligibility(
            PrimaryPasteEnv { ssh: true, ..linux },
            PrimaryDisplayBackend::WaylandHeld,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            true,
        ),
    ));
    skipped.push((
        "container",
        eligibility(
            PrimaryPasteEnv {
                wsl_or_container: true,
                ..linux
            },
            PrimaryDisplayBackend::WaylandHeld,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            true,
        ),
    ));
    skipped.push((
        "bridge",
        eligibility(
            PrimaryPasteEnv {
                host_bridge: true,
                ..linux
            },
            PrimaryDisplayBackend::WaylandHeld,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            true,
        ),
    ));
    for backend in [
        PrimaryDisplayBackend::X11,
        PrimaryDisplayBackend::ArboardReconnect,
        PrimaryDisplayBackend::Unknown,
    ] {
        skipped.push((
            "backend",
            eligibility(
                linux,
                backend,
                Some(&held_conn),
                PrimaryPasteLayer::Composer,
                true,
            ),
        ));
    }
    skipped.push((
        "no-held",
        eligibility(
            linux,
            PrimaryDisplayBackend::WaylandHeld,
            None,
            PrimaryPasteLayer::Composer,
            true,
        ),
    ));
    for (label, result) in &skipped {
        assert!(result.is_err(), "{label} must skip PRIMARY: {result:?}");
    }
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::NotLinux))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::NotComposer))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::MouseCaptureOff))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::SshSession))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::WslOrContainer))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::HostBridge))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::UnsupportedBackend))
    );
    assert!(
        skipped
            .iter()
            .any(|(_, r)| *r == Err(PrimaryPasteSkip::NoHeldAuthenticatedConnection))
    );

    let tmp = tempfile::tempdir().unwrap();
    let mut app = primary_ready_app(&tmp);
    assert_eq!(composer_text(&app), "");

    let mut gate_cases: Vec<(&str, Box<dyn Fn(&mut App)>)> = vec![
        (
            "macos",
            Box::new(|app| {
                app.primary_paste.set_env(PrimaryPasteEnv {
                    platform: PlatformKind::MacOs,
                    ..local_linux()
                });
            }),
        ),
        (
            "windows",
            Box::new(|app| {
                app.primary_paste.set_env(PrimaryPasteEnv {
                    platform: PlatformKind::Windows,
                    ..local_linux()
                });
            }),
        ),
        (
            "capture-off",
            Box::new(|app| {
                app.mouse_capture = false;
            }),
        ),
        (
            "ssh",
            Box::new(|app| {
                app.primary_paste.set_env(PrimaryPasteEnv {
                    ssh: true,
                    ..local_linux()
                });
            }),
        ),
        (
            "wsl",
            Box::new(|app| {
                app.primary_paste.set_env(PrimaryPasteEnv {
                    wsl_or_container: true,
                    ..local_linux()
                });
            }),
        ),
        (
            "host-bridge",
            Box::new(|app| {
                app.primary_paste.set_env(PrimaryPasteEnv {
                    host_bridge: true,
                    ..local_linux()
                });
            }),
        ),
        (
            "x11",
            Box::new(|app| {
                app.primary_paste.set_backend(PrimaryDisplayBackend::X11);
            }),
        ),
        (
            "arboard",
            Box::new(|app| {
                app.primary_paste
                    .set_backend(PrimaryDisplayBackend::ArboardReconnect);
            }),
        ),
        (
            "unknown-backend",
            Box::new(|app| {
                app.primary_paste
                    .set_backend(PrimaryDisplayBackend::Unknown);
            }),
        ),
        ("chat", Box::new(|_| {})),
    ];
    for (label, setup) in &mut gate_cases {
        let mut case = primary_ready_app(&tmp);
        setup(&mut case);
        let before = composer_text(&case);
        let click = if *label == "chat" {
            middle_down(4, 2)
        } else {
            middle_down(4, 22)
        };
        case.handle_mouse(click);
        assert_eq!(
            case.primary_paste.adapter_reads(),
            0,
            "{label} must not invoke the adapter"
        );
        assert_eq!(
            composer_text(&case),
            before,
            "{label} must not change composer"
        );
        assert!(
            case.primary_paste.pending().is_none(),
            "{label} must not start a request"
        );
    }

    for (label, mutate) in [
        (
            "keys",
            Box::new(|app: &mut App| {
                app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
            }) as Box<dyn Fn(&mut App)>,
        ),
        (
            "context-menu",
            Box::new(|app| {
                app.context_menu = Some(ContextMenu {
                    preferred_origin: (4, 22),
                    clicked_chat_row: 0,
                    cursor: 0,
                    items: ContextMenu::build_items(false, false),
                });
            }),
        ),
        (
            "settings",
            Box::new(|app| {
                app.dialog = Dialog::Settings(Box::new(
                    crate::tui::settings::SettingsDialog::open(tmp.path().join("config.json")),
                ));
            }),
        ),
        (
            "overlay",
            Box::new(|app| {
                app.overlay = Overlay::Help(crate::tui::app::help_overlay::HelpOverlay::open());
            }),
        ),
        (
            "pane-focus",
            Box::new(|app| {
                app.pane_focused = true;
                app.pane_rect = Some(Rect::new(40, 0, 40, 20));
            }),
        ),
        (
            "footer",
            Box::new(|app| {
                app.footer_hit_areas.push(FooterHitArea {
                    control: crate::tui::chrome::FooterControl::Agent,
                    rect: Rect::new(0, 26, 20, 1),
                });
            }),
        ),
    ] {
        let mut case = primary_ready_app(&tmp);
        mutate(&mut case);
        let before = composer_text(&case);
        let click = if label == "footer" {
            middle_down(2, 26)
        } else if label == "pane-focus" {
            middle_down(4, 22)
        } else {
            middle_down(4, 22)
        };
        case.handle_mouse(click);
        assert_eq!(
            case.primary_paste.adapter_reads(),
            0,
            "{label} must not invoke the adapter"
        );
        assert_eq!(
            composer_text(&case),
            before,
            "{label} must not change composer"
        );
    }

    app.handle_mouse(middle_down(4, 22));
    assert_eq!(app.primary_paste.adapter_reads(), 1);
    assert!(app.primary_paste.pending().is_some());
    assert_eq!(composer_text(&app), "");
}

#[test]
fn primary_paste_held_connection_contract() {
    let adapter = fake_adapter();
    let held_conn = held();
    assert_eq!(
        eligibility(
            local_linux(),
            PrimaryDisplayBackend::WaylandHeld,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            true,
        ),
        Ok(())
    );
    assert_eq!(
        eligibility(
            local_linux(),
            PrimaryDisplayBackend::WaylandHeld,
            None,
            PrimaryPasteLayer::Composer,
            true,
        ),
        Err(PrimaryPasteSkip::NoHeldAuthenticatedConnection)
    );
    assert_eq!(
        eligibility(
            local_linux(),
            PrimaryDisplayBackend::ArboardReconnect,
            Some(&held_conn),
            PrimaryPasteLayer::Composer,
            true,
        ),
        Err(PrimaryPasteSkip::UnsupportedBackend)
    );

    let begin = adapter.read_primary(&held_conn);
    assert!(matches!(
        begin,
        crate::tui::primary_paste::PrimaryPasteBegin::Pending
    ));
    assert_eq!(adapter.reads.get(), 1);
    assert_eq!(adapter.last_token.get(), Some(HELD_TOKEN));

    let wrong = HeldLocalDisplayConnection {
        backend: PrimaryDisplayBackend::WaylandHeld,
        token: 1,
    };
    assert!(matches!(
        adapter.read_primary(&wrong),
        crate::tui::primary_paste::PrimaryPasteBegin::Rejected
    ));

    let production = crate::tui::primary_paste::PrimaryPasteController::production();
    assert!(
        production
            .eligibility(PrimaryPasteLayer::Composer, true)
            .is_err()
    );
    assert_eq!(production.adapter_reads(), 0);
    assert!(production.pending().is_none());

    let mut controller =
        crate::tui::primary_paste::PrimaryPasteController::for_test(local_linux(), fake_adapter());
    controller.set_held(None);
    let view = crate::tui::primary_paste::PrimaryPasteViewEpoch {
        terminal_generation: 1,
        draft_generation: 0,
        mouse_capture: true,
        pane_focused: false,
        composer_eligible: true,
    };
    assert!(
        controller
            .consider_request(PrimaryPasteLayer::Composer, true, view)
            .is_none()
    );
    assert_eq!(controller.adapter_reads(), 0);

    let mut bad = Vec::new();
    let needles = [
        "get_text",
        "Clipboard::",
        "LinuxClipboardKind",
        "osc52",
        "OSC52",
        "Command::",
        "std::process",
        "WAYLAND_DISPLAY",
        "WAYLAND_SOCKET",
        "wl-copy",
        "xclip",
        "xsel",
        "copy_plain",
        "ClipboardService",
        "read_text",
        "read_image",
        "env::var",
        "env::set_var",
    ];
    walk_rs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src/tui"),
        &mut |path, src| {
            let name = path.to_string_lossy();
            if name.contains("primary_paste_tests.rs") {
                return;
            }
            let on_primary_route =
                name.contains("primary_paste.rs") || name.ends_with("app/mouse.rs");
            if !on_primary_route {
                return;
            }
            for (i, line) in src.lines().enumerate() {
                let t = line.trim();
                if t.starts_with("//") || t.starts_with("//!") || t.starts_with('*') {
                    continue;
                }
                if name.ends_with("app/mouse.rs")
                    && !t.contains("primary_paste")
                    && !t.contains("PrimaryPaste")
                {
                    continue;
                }
                for needle in needles {
                    if t.contains(needle) {
                        bad.push(format!("{}:{} {needle}", path.display(), i + 1));
                    }
                }
            }
        },
    );
    assert!(
        bad.is_empty(),
        "PRIMARY route must not reconnect or fall back: {bad:?}"
    );
}

#[test]
fn primary_paste_generation_matrix() {
    let tmp = tempfile::tempdir().unwrap();

    let mut app = primary_ready_app(&tmp);
    app.handle_mouse(middle_down(4, 22));
    let first = app.primary_paste.pending().expect("first request");
    app.handle_mouse(middle_down(5, 22));
    let second = app.primary_paste.pending().expect("second request");
    assert_ne!(first.generation, second.generation);
    assert_ne!(first.correlation_id, second.correlation_id);
    app.apply_primary_paste_outcome(first.generation, PrimaryPasteOutcome::Text("stale".into()));
    assert_eq!(composer_text(&app), "");
    assert_eq!(app.primary_paste.accepted_count(), 0);
    app.apply_primary_paste_outcome(second.generation, PrimaryPasteOutcome::Text("live".into()));
    assert_eq!(composer_text(&app), "live");
    assert_eq!(app.primary_paste.accepted_count(), 1);
    app.apply_primary_paste_outcome(second.generation, PrimaryPasteOutcome::Text("dup".into()));
    assert_eq!(composer_text(&app), "live");
    assert_eq!(app.primary_paste.accepted_count(), 1);

    let mut cancel = primary_ready_app(&tmp);
    cancel.handle_mouse(middle_down(4, 22));
    let cancelled_generation = cancel.primary_paste.pending().unwrap().generation;
    cancel.invalidate_primary_paste();
    cancel.apply_primary_paste_outcome(
        cancelled_generation,
        PrimaryPasteOutcome::Text("cancelled".into()),
    );
    assert_eq!(composer_text(&cancel), "");
    assert_eq!(cancel.primary_paste.accepted_count(), 0);

    let mut focus = primary_ready_app(&tmp);
    focus.handle_mouse(middle_down(4, 22));
    let stale_generation = focus.primary_paste.pending().unwrap().generation;
    focus.pane_focused = true;
    focus.apply_primary_paste_outcome(stale_generation, PrimaryPasteOutcome::Text("focus".into()));
    assert_eq!(composer_text(&focus), "");

    let mut modal = primary_ready_app(&tmp);
    modal.handle_mouse(middle_down(4, 22));
    let generation = modal.primary_paste.pending().unwrap().generation;
    modal.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    modal.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("modal".into()));
    assert_eq!(composer_text(&modal), "");

    let mut pane = primary_ready_app(&tmp);
    pane.handle_mouse(middle_down(4, 22));
    let generation = pane.primary_paste.pending().unwrap().generation;
    pane.overlay = Overlay::Help(crate::tui::app::help_overlay::HelpOverlay::open());
    pane.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("pane".into()));
    assert_eq!(composer_text(&pane), "");

    let mut terminal = primary_ready_app(&tmp);
    terminal.handle_mouse(middle_down(4, 22));
    let generation = terminal.primary_paste.pending().unwrap().generation;
    terminal.terminal_input_generation = Some(99);
    terminal.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("term".into()));
    assert_eq!(composer_text(&terminal), "");

    let mut view = primary_ready_app(&tmp);
    view.handle_mouse(middle_down(4, 22));
    let generation = view.primary_paste.pending().unwrap().generation;
    view.draft_generation = view.draft_generation.saturating_add(1);
    view.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("draft".into()));
    assert_eq!(composer_text(&view), "");

    let mut capture = primary_ready_app(&tmp);
    capture.handle_mouse(middle_down(4, 22));
    let generation = capture.primary_paste.pending().unwrap().generation;
    capture.mouse_capture = false;
    capture.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("cap".into()));
    assert_eq!(composer_text(&capture), "");

    let mut late_fail = primary_ready_app(&tmp);
    late_fail.handle_mouse(middle_down(4, 22));
    let generation = late_fail.primary_paste.pending().unwrap().generation;
    late_fail.overlay = Overlay::Help(crate::tui::app::help_overlay::HelpOverlay::open());
    late_fail.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Failed);
    assert!(late_fail.toast.is_none());
    assert_eq!(composer_text(&late_fail), "");

    let mut empty = primary_ready_app(&tmp);
    empty.handle_mouse(middle_down(4, 22));
    let generation = empty.primary_paste.pending().unwrap().generation;
    empty.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Empty);
    assert_eq!(
        empty.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("No selection")
    );
    assert_eq!(composer_text(&empty), "");
    assert_eq!(empty.primary_paste.accepted_count(), 0);
}

#[tokio::test]
async fn primary_paste_structured_input_parity() {
    let tmp = tempfile::tempdir().unwrap();
    let multiline = "alpha\nbeta\ngamma";

    let mut via_primary = primary_ready_app(&tmp);
    via_primary.handle_mouse(middle_down(4, 22));
    let pending = via_primary.primary_paste.pending().unwrap();
    let correlation = pending.correlation_id;
    via_primary.apply_primary_paste_outcome(
        pending.generation,
        PrimaryPasteOutcome::Text(multiline.to_string()),
    );
    assert!(
        composer_text(&via_primary).contains("[Pasted text #1"),
        "PRIMARY multiline must enter the structured-paste placeholder path: {}",
        composer_text(&via_primary)
    );
    assert_eq!(via_primary.primary_paste.accepted_count(), 1);
    assert_eq!(via_primary.primary_paste.last_accepted(), Some(correlation));
    assert!(!via_primary.busy);
    assert!(via_primary.history.is_empty());
    let host = paste_host(&via_primary);
    assert_eq!(
        via_primary
            .paste_correlations
            .existing(correlation, host, via_primary.event_loop_monotonic_now)
            .map(|(_, result)| result),
        Some(crate::tui::structured_paste::DedupResult::Committed)
    );

    let mut via_native = primary_ready_app(&tmp);
    via_native.handle_identified_paste(
        multiline.to_string(),
        PasteSource::NativePaste,
        uuid::Uuid::new_v4(),
    );
    assert_eq!(composer_text(&via_native), composer_text(&via_primary));
    assert!(!via_native.busy);

    let mut rapid = primary_ready_app(&tmp);
    for (index, ch) in "abcd".chars().enumerate() {
        rapid.event_loop_monotonic_now = Duration::from_millis(index as u64);
        let _ = rapid.handle_observed_terminal_event(
            Event::Key(KeyEvent {
                code: KeyCode::Char(ch),
                modifiers: KeyModifiers::NONE,
                kind: KeyEventKind::Press,
                state: KeyEventState::NONE,
            }),
            rapid.event_loop_monotonic_now,
            1,
            None,
            None,
        );
    }
    rapid.handle_mouse(middle_down(4, 22));
    let pending = rapid.primary_paste.pending().unwrap();
    rapid.apply_primary_paste_outcome(
        pending.generation,
        PrimaryPasteOutcome::Text("PASTE".into()),
    );
    assert!(
        composer_text(&rapid).contains("PASTE"),
        "PRIMARY must enter the composer through structured paste: {}",
        composer_text(&rapid)
    );
    assert!(!rapid.busy);

    let mut session = primary_ready_app(&tmp);
    session.handle_mouse(middle_down(4, 22));
    let pending = session.primary_paste.pending().unwrap();
    session
        .apply_primary_paste_outcome(pending.generation, PrimaryPasteOutcome::Text("keep".into()));
    session.launch.session_id = Some(uuid::Uuid::new_v4());
    session.active_model_selection = Some(cockpit_config::providers::ActiveModelRef {
        provider: "test-provider".to_string(),
        model: "other-model".to_string(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    });
    session.apply_primary_paste_outcome(
        pending.generation,
        PrimaryPasteOutcome::Text("again".into()),
    );
    assert_eq!(composer_text(&session), "keep");
    assert!(!session.busy);
    assert!(session.history.is_empty());
    assert_eq!(session.primary_paste.accepted_count(), 1);
}

#[test]
fn primary_paste_transition_invalidates_even_after_restore() {
    let tmp = tempfile::tempdir().unwrap();

    let mut modal = primary_ready_app(&tmp);
    modal.handle_mouse(middle_down(4, 22));
    let generation = modal.primary_paste.pending().unwrap().generation;
    modal.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    modal.invalidate_primary_paste();
    modal.dialog = Dialog::None;
    modal.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("roundtrip".into()));
    assert_eq!(composer_text(&modal), "");
    assert_eq!(modal.primary_paste.accepted_count(), 0);

    let mut history = primary_ready_app(&tmp);
    history.prompt_history = vec!["recalled draft".to_string()];
    history.handle_mouse(middle_down(4, 22));
    let generation = history.primary_paste.pending().unwrap().generation;
    history.history_up();
    history.apply_primary_paste_outcome(generation, PrimaryPasteOutcome::Text("into-draft".into()));
    assert_eq!(composer_text(&history), "recalled draft");
    assert_eq!(history.primary_paste.accepted_count(), 0);
}

#[test]
fn primary_paste_context_precedence() {
    let tmp = tempfile::tempdir().unwrap();

    let mut menu = primary_ready_app(&tmp);
    menu.context_menu = Some(ContextMenu {
        preferred_origin: (4, 2),
        clicked_chat_row: 0,
        cursor: 0,
        items: ContextMenu::build_items(false, false),
    });
    menu.handle_mouse(middle_down(4, 2));
    assert!(
        menu.context_menu.is_none(),
        "middle-down dismisses the context menu"
    );
    assert_eq!(menu.primary_paste.adapter_reads(), 0);
    assert_eq!(composer_text(&menu), "");

    let mut settings = primary_ready_app(&tmp);
    settings.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    settings.handle_mouse(middle_down(4, 22));
    assert!(matches!(settings.dialog, Dialog::Settings(_)));
    assert_eq!(settings.primary_paste.adapter_reads(), 0);
    assert_eq!(composer_text(&settings), "");

    let mut overlay = primary_ready_app(&tmp);
    overlay.overlay = Overlay::Help(crate::tui::app::help_overlay::HelpOverlay::open());
    overlay.handle_mouse(middle_down(4, 22));
    assert!(matches!(overlay.overlay, Overlay::Help(_)));
    assert_eq!(overlay.primary_paste.adapter_reads(), 0);
    assert_eq!(composer_text(&overlay), "");

    let mut pane = primary_ready_app(&tmp);
    pane.pane_focused = true;
    pane.pane_rect = Some(Rect::new(40, 0, 40, 20));
    pane.handle_mouse(middle_down(45, 4));
    assert_eq!(pane.primary_paste.adapter_reads(), 0);
    assert_eq!(composer_text(&pane), "");
    pane.handle_mouse(middle_down(4, 22));
    assert_eq!(pane.primary_paste.adapter_reads(), 0);
    assert_eq!(composer_text(&pane), "");

    let mut chat = primary_ready_app(&tmp);
    chat.handle_mouse(middle_down(10, 4));
    assert_eq!(chat.primary_paste.adapter_reads(), 0);
    assert_eq!(composer_text(&chat), "");
    assert!(chat.context_menu.is_none());
    assert!(chat.selection.is_none());
}
