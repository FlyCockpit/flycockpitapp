use super::render::chat_visible_top;
use super::sticky_header::STICKY_USER_HEADER_HEIGHT;
use super::{App, Selection, TranscriptFind};
use crate::tui::history::HistoryEntry;
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::Terminal;
use ratatui::backend::TestBackend;
use ratatui::layout::Rect;

fn user(text: &str) -> HistoryEntry {
    HistoryEntry::User {
        text: text.to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        optimistic_submission_id: None,
        preflight_pending: false,
        persist_failed: false,
    }
}

fn sequenced_user(text: &str, seq: i64) -> HistoryEntry {
    match user(text) {
        HistoryEntry::User {
            text,
            cleaned,
            expanded,
            timestamp,
            optimistic_submission_id,
            preflight_pending,
            persist_failed,
            ..
        } => HistoryEntry::User {
            text,
            cleaned,
            expanded,
            timestamp,
            seq: Some(seq),
            optimistic_submission_id,
            preflight_pending,
            persist_failed,
        },
        other => other,
    }
}

fn agent(text: &str) -> HistoryEntry {
    HistoryEntry::Agent {
        name: "Build".to_string(),
        text: text.to_string(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        expanded: false,
        reasoning_offset: 0,
        think_duration: None,
        seq: None,
        performance: None,
        performance_expanded: false,
    }
}

fn overflowing_app(root: &std::path::Path) -> App {
    let mut app = App::new(Some(root), false);
    app.launch.banner_enabled = false;
    app.sticky_user_message = true;
    app.daemon_prompt = None;
    app.mouse_capture = true;
    let mut entries = Vec::new();
    for i in 0..12 {
        entries.push(user(&format!("user-msg-{i} unique-token-{i}")));
        entries.push(agent(&format!(
            "agent-reply-{i} padding so the row wraps a bit more than one line"
        )));
    }
    app.history = entries.into();
    app
}

fn render_history_direct(app: &mut App, width: u16, height: u16) {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| app.render_history(f, Rect::new(0, 0, width, height)))
        .unwrap();
}

fn render_sticky(app: &mut App, width: u16, height: u16) {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| app.render_chat_history_pane(f, Rect::new(0, 0, width, height)))
        .unwrap();
}

fn render_sticky_buffer(app: &mut App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|f| app.render_chat_history_pane(f, Rect::new(0, 0, width, height)))
        .unwrap();
    terminal.backend().buffer().clone()
}

fn row_text(buf: &ratatui::buffer::Buffer, y: u16, width: u16) -> String {
    (0..width)
        .map(|x| buf[(x, y)].symbol().to_string())
        .collect::<String>()
}

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

fn prime_overflowing(app: &mut App, width: u16, height: u16) {
    render_history_direct(app, width, height);
    assert!(
        app.chat_total_lines > height as usize,
        "fixture must overflow the pane so a user message can sit above the viewport"
    );
}

#[test]
fn layout_carves_two_lines_when_header_is_on() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);

    let header = app.sticky_header_area.expect("header should show at tail");
    assert_eq!(header.height, STICKY_USER_HEADER_HEIGHT);
    assert_eq!(header.y, 0);
    assert_eq!(
        app.chat_visible_lines,
        10 - STICKY_USER_HEADER_HEIGHT as usize
    );
    let chat = app.chat_area.expect("history area after carve");
    assert_eq!(chat.y, STICKY_USER_HEADER_HEIGHT);
    assert_eq!(chat.height, 10 - STICKY_USER_HEADER_HEIGHT);
    assert_eq!(app.chat_row_meta.len(), app.chat_visible_lines);
    assert_eq!(app.clickable_rows.len(), app.chat_visible_lines);
    assert_eq!(app.box_rows.len(), app.chat_visible_lines);
}

#[test]
fn layout_hides_header_when_setting_is_off() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    app.sticky_user_message = false;
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);

    assert!(app.sticky_header_area.is_none());
    assert_eq!(app.chat_visible_lines, 10);
    let chat = app.chat_area.expect("full pane");
    assert_eq!(chat.y, 0);
    assert_eq!(chat.height, 10);
    assert_eq!(app.chat_row_meta.len(), app.chat_visible_lines);
}

#[test]
fn layout_keeps_two_line_header_at_narrow_width() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 16, 10);
    let buf = render_sticky_buffer(&mut app, 16, 10);
    let header = app.sticky_header_area.expect("header at narrow width");
    assert_eq!(header.height, STICKY_USER_HEADER_HEIGHT);
    assert_eq!(app.chat_visible_lines, 8);
    let top = row_text(&buf, 0, 16);
    let second = row_text(&buf, 1, 16);
    assert!(
        top.contains("you") || top.contains("user-msg"),
        "narrow header row 0 should still show pinned chrome or preview: {top:?}"
    );
    assert_ne!(top.trim(), "", "header row 0 must be painted");
    let _ = second;
}

#[test]
fn header_preview_uses_raw_user_text() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 48, 10);
    let buf = render_sticky_buffer(&mut app, 48, 10);
    let header = app.sticky_header_area.expect("header");
    let idx = app.sticky_header_history_index.expect("target");
    let HistoryEntry::User { text, .. } = &app.history[idx] else {
        panic!("target must be a user message");
    };
    let needle = text.split_whitespace().next().unwrap();
    let row0 = row_text(&buf, header.y, 48);
    let row1 = row_text(&buf, header.y + 1, 48);
    assert!(
        row0.contains(needle) || row1.contains(needle),
        "header should show raw user text {needle:?}: {row0:?} / {row1:?}"
    );
    assert!(row0.contains("you"), "pinned header label: {row0:?}");
}

#[test]
fn target_derivation_matrix() {
    let tmp = tempfile::tempdir().unwrap();

    // Overflowing tail: last user fully above the uncarved top.
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    let tail = app
        .sticky_user_target(10)
        .expect("user message above tail viewport");
    match &app.history[tail.history_index] {
        HistoryEntry::User { seq, .. } => {
            assert!(seq.is_none(), "optimistic entries with seq=None still pin")
        }
        other => panic!("expected user, got {other:?}"),
    }

    // Scrolled to the top of the buffer: every user is visible.
    let max_offset = app.chat_total_lines.saturating_sub(10).max(1);
    app.set_chat_scroll_offset_from_interaction(max_offset);
    assert!(
        app.sticky_user_target(10).is_none(),
        "no sticky target when the viewport top is the buffer top"
    );

    // Short transcript at tail: nothing above.
    let mut short = App::new(Some(tmp.path()), false);
    short.launch.banner_enabled = false;
    short.sticky_user_message = true;
    short.history = vec![user("only one"), agent("short reply")].into();
    render_history_direct(&mut short, 40, 20);
    assert!(
        short.sticky_user_target(20).is_none(),
        "tail with no user message above must not pin"
    );

    // Banner occupying the viewport top.
    let mut banner = App::new(Some(tmp.path()), false);
    banner.launch.banner_enabled = true;
    banner.sticky_user_message = true;
    banner.history = vec![user("hello")].into();
    render_history_direct(&mut banner, 100, 24);
    if banner.chat_banner_lines > 0 {
        let top = chat_visible_top(banner.chat_total_lines, 24, banner.chat_scroll_offset);
        if top < banner.chat_banner_lines {
            assert!(
                banner.sticky_user_target(24).is_none(),
                "banner at the top suppresses the sticky header"
            );
        }
    }

    // Sequenced (persisted) user still pins; seq=None already covered above.
    let mut sequenced = overflowing_app(tmp.path());
    sequenced.history = (0..12)
        .flat_map(|i| {
            [
                sequenced_user(&format!("user-msg-{i} unique-token-{i}"), i as i64),
                agent(&format!("agent-reply-{i} padding so the row wraps a bit")),
            ]
        })
        .collect::<Vec<_>>()
        .into();
    prime_overflowing(&mut sequenced, 40, 10);
    let target = sequenced
        .sticky_user_target(10)
        .expect("sequenced user above viewport");
    match &sequenced.history[target.history_index] {
        HistoryEntry::User { seq, .. } => assert!(seq.is_some()),
        other => panic!("expected user, got {other:?}"),
    }
}

#[test]
fn selection_clears_when_header_visibility_flips() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_some());

    app.selection = Some(Selection {
        anchor: (0, 4),
        focus: (8, 6),
        active: false,
    });
    app.sticky_user_message = false;
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_none());
    assert!(
        app.selection.is_none(),
        "visibility flip must clear live selections"
    );
}

#[test]
fn click_jump_lands_with_two_row_margin() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);
    let header = app.sticky_header_area.expect("header");
    let idx = app.sticky_header_history_index.expect("target");
    let rel = *app.msg_abs_line.get(&idx).expect("target has an abs line");
    let abs = app.chat_banner_lines + rel;

    app.handle_mouse(mouse(
        MouseEventKind::Down(MouseButton::Left),
        header.x,
        header.y,
    ));

    let visible = app.chat_visible_lines.max(1);
    let top = chat_visible_top(app.chat_total_lines, visible, app.chat_scroll_offset);
    assert_eq!(
        top,
        abs.saturating_sub(2),
        "click-jump uses the 2-row margin of scroll_abs_line_into_view"
    );
}

#[test]
fn home_key_jumps_to_sticky_target_when_composer_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);
    let idx = app.sticky_header_history_index.expect("target");
    let rel = *app.msg_abs_line.get(&idx).expect("abs line");
    let abs = app.chat_banner_lines + rel;
    let before = app.chat_scroll_offset;

    app.handle_key(press(KeyCode::Home));
    assert_ne!(
        app.chat_scroll_offset, before,
        "Home jumps when composer is empty"
    );
    let visible = app.chat_visible_lines.max(1);
    let top = chat_visible_top(app.chat_total_lines, visible, app.chat_scroll_offset);
    assert_eq!(top, abs.saturating_sub(2));

    app.composer.set("draft".to_string());
    let offset = app.chat_scroll_offset;
    app.handle_key(press(KeyCode::Home));
    assert_eq!(
        app.chat_scroll_offset, offset,
        "Home is composer-owned when the input is not empty"
    );
}

#[test]
fn find_indices_ignore_the_sticky_header() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    app.transcript_find = Some(TranscriptFind {
        query: "user-msg".to_string(),
        matches: Vec::new(),
        current: None,
        saved_offset: 0,
    });
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_some());
    assert_eq!(
        app.chat_find_lines.len(),
        app.chat_total_lines,
        "find lines stay aligned with the scroll buffer, not the carved header"
    );
    let header_idx = app.sticky_header_history_index.unwrap();
    let HistoryEntry::User { text, .. } = &app.history[header_idx] else {
        panic!("target is a user message");
    };
    let needle = text.to_lowercase();
    assert!(
        app.chat_find_lines.iter().any(|line| line.contains(&needle)
            || needle
                .split_whitespace()
                .next()
                .is_some_and(|word| line.contains(word))),
        "the pinned message remains searchable in the transcript"
    );
}

#[test]
fn selection_grid_matches_carved_history_area() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    app.selection = Some(Selection {
        anchor: (0, 3),
        focus: (10, 7),
        active: false,
    });
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);
    let chat = app.chat_area.expect("carved history");
    assert_eq!(app.chat_text_grid.len(), chat.height as usize);
    assert!(
        app.chat_text_grid
            .iter()
            .all(|row| row.len() == chat.width as usize)
    );
    assert_eq!(app.chat_row_meta.len(), chat.height as usize);
}

#[test]
fn anchor_round_trip_is_stable_across_header_appear_and_disappear() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    app.set_chat_scroll_offset_from_interaction(6);
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_some());
    let offset_with_header = app.chat_scroll_offset;
    let top_with_header = chat_visible_top(
        app.chat_total_lines,
        app.chat_visible_lines.max(1),
        offset_with_header,
    );

    app.history
        .push(agent("new bottom row should not yank the sticky viewport"));
    render_sticky(&mut app, 40, 10);
    let top_after_push = chat_visible_top(
        app.chat_total_lines,
        app.chat_visible_lines.max(1),
        app.chat_scroll_offset,
    );
    assert_eq!(
        top_after_push, top_with_header,
        "scroll-anchor round-trip must keep the same history top while the header stays up"
    );

    app.sticky_user_message = false;
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_none());
    // Offset-from-bottom is preserved across the flip so the round-trip
    // cannot oscillate (header decision uses the uncarved pane height).
    assert_eq!(app.chat_scroll_offset, offset_with_header);

    app.sticky_user_message = true;
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_some());
    assert_eq!(app.chat_scroll_offset, offset_with_header);
}

#[test]
fn toggling_the_setting_repaints_the_header() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = overflowing_app(tmp.path());
    prime_overflowing(&mut app, 40, 10);
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_some());

    app.sticky_user_message = false;
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_none());
    assert_eq!(app.chat_visible_lines, 10);

    app.sticky_user_message = true;
    render_sticky(&mut app, 40, 10);
    assert!(app.sticky_header_area.is_some());
    assert_eq!(app.chat_visible_lines, 8);
}
