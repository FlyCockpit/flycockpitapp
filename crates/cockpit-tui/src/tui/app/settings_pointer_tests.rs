use super::App;
use crate::tui::context_menu::ContextMenu;
use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
use crate::tui::settings::{Dialog, TestPageRef};
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Terminal, backend::TestBackend, layout::Rect};

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn render_settings(app: &mut App, width: u16, height: u16) {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("terminal");
    let Dialog::Settings(dialog) = &app.dialog else {
        panic!("settings dialog");
    };
    terminal
        .draw(|frame| {
            dialog.render(
                frame,
                Rect::new(0, 0, width, height),
                &mut app.link_registry,
            )
        })
        .expect("draw");
}

pub(crate) fn run_settings_pointer_z_order_matrix() {
    let tmp = tempfile::TempDir::new().expect("tempdir");
    let mut app = App::new(Some(tmp.path()), false);
    app.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    app.mouse_capture = true;
    app.chat_area = Some(Rect::new(0, 0, 80, 24));
    app.chat_scroll_offset = 7;
    render_settings(&mut app, 80, 24);
    let Dialog::Settings(dialog) = &app.dialog else {
        unreachable!()
    };
    let target = dialog
        .pointer_test_target_rects()
        .into_iter()
        .max_by_key(|rect| rect.y)
        .expect("root target");

    app.sandbox_notice_copy_rect = Some(target);
    app.auth_failure_notice = Some(crate::tui::auth_failure::AuthFailureNotice {
        provider: "fixture".into(),
        model: "fixture".into(),
        kind: cockpit_core::daemon::proto::AuthFailureKind::ProviderNotConfigured,
    });
    app.auth_notice_switch_rect = Some(target);
    app.auth_notice_fix_rect = Some(target);
    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        target.x,
        target.y,
    ));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if !matches!(dialog.test_page(), TestPageRef::Root { .. })),
        "settings must preempt ordinary persistent-notice controls"
    );
    assert!(app.auth_failure_notice.is_some());

    app.dialog = Dialog::Settings(Box::new(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    )));
    render_settings(&mut app, 80, 24);

    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, target.x, target.y));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 0 }))
    );
    assert_eq!(app.chat_scroll_offset, 7);
    app.keys_overlay = None;

    app.context_menu = Some(ContextMenu {
        preferred_origin: (target.x, target.y),
        clicked_chat_row: 0,
        cursor: 0,
        items: ContextMenu::build_items(false, false),
    });
    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Middle),
        target.x,
        target.y,
    ));
    assert!(app.context_menu.is_none());
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 0 }))
    );

    render_settings(&mut app, 80, 24);
    app.handle_mouse(mouse(MouseEventKind::ScrollDown, target.x, target.y));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 3 }))
    );
    assert_eq!(app.chat_scroll_offset, 7, "settings preempts chat wheel");

    app.handle_mouse(mouse(MouseEventKind::ScrollDown, 100, 100));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 3 }))
    );
    assert_eq!(
        app.chat_scroll_offset, 7,
        "outside settings is inert while modal is open"
    );

    render_settings(&mut app, 80, 24);
    app.link_registry
        .register(target, "https://example.test", "fixture");
    app.handle_mouse(mouse(MouseEventKind::Moved, target.x, target.y));
    assert!(
        app.link_registry.hovered().is_some(),
        "link wins hover z-order"
    );
    let Dialog::Settings(dialog) = &app.dialog else {
        unreachable!()
    };
    assert!(dialog.pointer_test_hover_is_none());
}

#[test]
fn settings_pointer_z_order_matrix() {
    run_settings_pointer_z_order_matrix();
}
