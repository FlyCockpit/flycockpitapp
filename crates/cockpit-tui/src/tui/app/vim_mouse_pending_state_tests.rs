use super::App;
use crate::tui::composer::{FindSpec, Operator, Register, VimMode, input_prefix_width};
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::Rect;
use std::fs;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn configured_app(tmp: &tempfile::TempDir) -> App {
    let _env = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
    let cockpit = tmp.path().join(".cockpit");
    fs::create_dir(&cockpit).unwrap();
    fs::write(cockpit.join("config.json"), "{}").unwrap();
    let provider_dir = cockpit.join("providers");
    fs::create_dir(&provider_dir).unwrap();
    fs::write(
        provider_dir.join("p.json"),
        r#"{"url":"https://example.test","models":[{"id":"m"}]}"#,
    )
    .unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.daemon_prompt = None;
    app
}

fn seed_pending_vim_state(app: &mut App) {
    app.composer.set_pending_g(true);
    app.composer.set_pending_find(Some(FindSpec {
        target: 'x',
        till: true,
        forward: false,
    }));
    app.pending_text_object = Some(true);
}

fn vim_app_with_text(tmp: &tempfile::TempDir, text: &str, cursor: usize) -> App {
    let mut app = configured_app(tmp);
    app.composer.set_vim_enabled(true);
    app.composer.insert_str(text);
    app.composer.set_cursor(cursor);
    app.composer.set_vim_mode(VimMode::Normal);
    app.composer.set_register(Register {
        text: "seed".to_string(),
        linewise: false,
    });
    app
}

fn press_x(app: &mut App) {
    app.handle_key(press(KeyCode::Char('x')));
}

fn click_input(app: &mut App) {
    app.input_area = Some(Rect::new(0, 0, 40, 3));
    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 1 + input_prefix_width() as u16,
        row: 1,
        modifiers: KeyModifiers::empty(),
    });
}

#[test]
fn mouse_click_into_composer_clears_pending_vim_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.composer.set_vim_enabled(true);
    app.composer
        .set_vim_mode(VimMode::Operator(Operator::Delete));
    seed_pending_vim_state(&mut app);

    click_input(&mut app);

    assert_eq!(app.composer.vim_mode(), VimMode::Insert);
    assert!(!app.composer.pending_g());
    assert!(app.composer.pending_find().is_none());
    assert!(app.pending_text_object.is_none());
}

#[test]
fn mouse_click_on_wide_composer_glyph_lands_on_that_glyph() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.composer.insert_str("a中b");
    app.input_area = Some(Rect::new(0, 0, 40, 3));
    let wide_first_cell = 1 + input_prefix_width() as u16 + "a".len() as u16;

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: wide_first_cell,
        row: 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(
        app.composer.cursor(),
        "a".len(),
        "clicking the first cell of a wide glyph lands on the glyph byte"
    );

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: wide_first_cell + 1,
        row: 1,
        modifiers: KeyModifiers::empty(),
    });
    assert_eq!(
        app.composer.cursor(),
        "a".len(),
        "clicking the second cell of a wide glyph still lands on the glyph byte"
    );
}

#[test]
fn esc_still_clears_pending_vim_state() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = configured_app(&tmp);
    app.composer.set_vim_enabled(true);
    app.composer
        .set_vim_mode(VimMode::Operator(Operator::Change));
    seed_pending_vim_state(&mut app);

    app.handle_key(press(KeyCode::Esc));

    assert_eq!(app.composer.vim_mode(), VimMode::Normal);
    assert!(!app.composer.pending_g());
    assert!(app.composer.pending_find().is_none());
    assert!(app.pending_text_object.is_none());
}

#[test]
fn vim_x_on_empty_interior_line_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = vim_app_with_text(&tmp, "a\n\nb", 2);

    press_x(&mut app);

    assert_eq!(app.composer.text(), "a\n\nb");
    assert_eq!(app.composer.cursor(), 2);
    assert_eq!(app.composer.register().text, "seed");
}

#[test]
fn vim_x_at_line_end_does_not_join_next_line() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = vim_app_with_text(&tmp, "ab\ncd", 2);

    press_x(&mut app);

    assert_eq!(app.composer.text(), "ab\ncd");
    assert_eq!(app.composer.cursor(), 2);
    assert_eq!(app.composer.register().text, "seed");
}

#[test]
fn vim_x_on_normal_char_cuts_into_register() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = vim_app_with_text(&tmp, "abc", 1);

    press_x(&mut app);

    assert_eq!(app.composer.text(), "ac");
    assert_eq!(app.composer.cursor(), 1);
    assert_eq!(app.composer.register().text, "b");
    assert!(!app.composer.register().linewise);
}

#[test]
fn vim_x_on_multibyte_char_cuts_one_char() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = vim_app_with_text(&tmp, "áb", 0);

    press_x(&mut app);

    assert_eq!(app.composer.text(), "b");
    assert_eq!(app.composer.cursor(), 0);
    assert_eq!(app.composer.register().text, "á");
    assert!(!app.composer.register().linewise);
}

#[test]
fn vim_x_at_end_of_buffer_is_noop() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = vim_app_with_text(&tmp, "ab", 2);

    press_x(&mut app);

    assert_eq!(app.composer.text(), "ab");
    assert_eq!(app.composer.cursor(), 2);
    assert_eq!(app.composer.register().text, "seed");
}
