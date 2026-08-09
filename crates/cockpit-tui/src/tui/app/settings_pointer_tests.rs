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
    app.dialog = Dialog::Settings(crate::tui::settings::SettingsDialog::open(
        tmp.path().join("config.json"),
    ));
    app.mouse_capture = true;
    app.chat_area = Some(Rect::new(0, 0, 80, 24));
    app.chat_scroll_offset = 7;
    render_settings(&mut app, 80, 24);
    let Dialog::Settings(dialog) = &app.dialog else {
        unreachable!()
    };
    let target = dialog
        .pointer_surface
        .targets
        .borrow()
        .iter()
        .max_by_key(|target| target.rect.y)
        .cloned()
        .expect("root target");

    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Chat));
    app.handle_mouse(mouse(
        MouseEventKind::ScrollDown,
        target.rect.x,
        target.rect.y,
    ));
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 0 }))
    );
    assert_eq!(app.chat_scroll_offset, 7);
    app.keys_overlay = None;

    app.context_menu = Some(ContextMenu {
        preferred_origin: (target.rect.x, target.rect.y),
        clicked_chat_row: 0,
        cursor: 0,
        items: ContextMenu::build_items(false, false),
    });
    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Middle),
        target.rect.x,
        target.rect.y,
    ));
    assert!(app.context_menu.is_none());
    assert!(
        matches!(&app.dialog, Dialog::Settings(dialog) if matches!(dialog.test_page(), TestPageRef::Root { cursor: 0 }))
    );

    render_settings(&mut app, 80, 24);
    app.handle_mouse(mouse(
        MouseEventKind::ScrollDown,
        target.rect.x,
        target.rect.y,
    ));
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
        .register(target.rect, "https://example.test".into(), "fixture".into());
    app.handle_mouse(mouse(MouseEventKind::Moved, target.rect.x, target.rect.y));
    assert!(
        app.link_registry.hovered().is_some(),
        "link wins hover z-order"
    );
    let Dialog::Settings(dialog) = &app.dialog else {
        unreachable!()
    };
    assert!(dialog.pointer_surface.hover.borrow().is_none());
}

#[test]
fn settings_pointer_z_order_matrix() {
    run_settings_pointer_z_order_matrix();
}
