use super::*;
use crate::tui::async_action::{AsyncActionKind, AsyncActionPayload, MouseCopyResult};
use crate::tui::context_menu::ContextMenu;
use crate::tui::history::HistoryEntry;
use crate::tui::keys_overlay::{KeyContext, KeysOverlay};
use crate::tui::markdown::CopyFragment;
use crossterm::event::{
    KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::Rect;
use std::rc::Rc;
use std::time::Duration;

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: crossterm::event::KeyEventState::empty(),
    }
}

fn selectable_meta() -> render::ChatRowMeta {
    render::ChatRowMeta {
        history_index: Some(0),
        row_kind: render::ChatRowKind::Message,
        copy_target: Some(render::ChatCopyTarget::Message { history_index: 0 }),
        chip_target: None,
        subagent_target: None,
        tool_box_target: None,
        tool_call_target: None,
        tool_result_scroll: None,
        reasoning_window_scroll: None,
        reasoning_window_target: None,
        diff_path: None,
        pin_hit: None,
        fork_hit: None,
        metric_hit: None,
        continuation: false,
        selectable: true,
        copy_cells: Vec::new(),
        copy_fragments: Rc::new(Vec::new()),
        copy_newlines_before: 0,
        copy_fallback_if_unmapped: false,
        copy_provenance_present: false,
    }
}

fn app_with_hello_grid() -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;
    app.copy_on_release = true;
    app.chat_area = Some(Rect::new(0, 0, 11, 1));
    app.chat_text_grid = vec!["hello world".chars().map(|ch| ch.to_string()).collect()];
    app.chat_row_meta = vec![selectable_meta()];
    app
}

fn table_fragments() -> (Rc<Vec<CopyFragment>>, Vec<Option<u32>>) {
    let fragments = Rc::new(vec![
        CopyFragment {
            id: 0,
            text: "alpha".to_string(),
            source: None,
            logical_line: 0,
            table_cell: Some((0, 0, 0)),
        },
        CopyFragment {
            id: 1,
            text: "beta".to_string(),
            source: None,
            logical_line: 0,
            table_cell: Some((0, 0, 1)),
        },
    ]);
    let mut row0 = vec![Some(0); 5];
    row0.extend(std::iter::repeat_n(None, 1));
    row0.extend(std::iter::repeat_n(Some(1), 4));
    (fragments, row0)
}

#[test]
fn handle_mouse_single_click_does_not_copy_when_copy_on_release() {
    let mut app = app_with_hello_grid();
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));
    assert!(app.selection.is_none(), "single click never selects");
    assert!(app.toast.is_none(), "single click never copies");
    assert!(app.pending_mouse_copies.is_empty());
}

#[tokio::test]
async fn handle_mouse_drag_across_cells_copies_once() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    assert!(matches!(
        app.selection,
        Some(Selection { active: false, .. })
    ));
    assert!(app.toast.is_none());
    assert_eq!(app.pending_mouse_copies.len(), 1);
    app.controllable_mouse_copy
        .take()
        .unwrap()
        .release(MouseCopyResult::Confirmed);
    tokio::task::yield_now().await;
    app.drain_async_actions();
    assert_eq!(app.pending_mouse_copies.len(), 0);
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("Copied 5 chars to clipboard.")
    );
}

#[test]
fn handle_mouse_double_click_selects_markdown_word() {
    let mut app = app_with_hello_grid();
    app.copy_on_release = false;
    app.event_loop_monotonic_now = Duration::from_millis(0);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 6, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 6, 0));
    app.event_loop_monotonic_now = Duration::from_millis(20);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 6, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 6, 0));
    let sel = app.selection.expect("word selection");
    assert!(!sel.active);
    assert_eq!(sel.anchor, (6, 0));
    assert_eq!(sel.focus, (10, 0));
    let spans = app.selection_spans.clone().expect("word spans");
    assert_eq!(
        spans,
        vec![SelectionSpan {
            row: 0,
            start_col: 6,
            end_col: 10
        }]
    );
    assert_eq!(app.snapshot_selection_text(), "world");
}

#[test]
fn handle_mouse_double_click_selects_wrapped_table_cell() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;
    app.copy_on_release = false;
    app.chat_area = Some(Rect::new(0, 0, 10, 2));
    let (fragments, row0) = table_fragments();
    let mut row1 = vec![Some(0); 5];
    row1.extend(std::iter::repeat_n(None, 5));
    app.chat_text_grid = vec![
        "alpha beta".chars().map(|ch| ch.to_string()).collect(),
        "alpha     ".chars().map(|ch| ch.to_string()).collect(),
    ];
    let mut meta0 = selectable_meta();
    meta0.copy_cells = row0;
    meta0.copy_fragments = fragments.clone();
    meta0.copy_provenance_present = true;
    let mut meta1 = selectable_meta();
    meta1.copy_cells = row1;
    meta1.copy_fragments = fragments;
    meta1.copy_provenance_present = true;
    meta1.continuation = true;
    app.chat_row_meta = vec![meta0, meta1];

    app.event_loop_monotonic_now = Duration::from_millis(0);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));
    app.event_loop_monotonic_now = Duration::from_millis(20);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));

    let spans = app.selection_spans.clone().expect("table spans");
    assert!(
        spans.iter().all(|span| span.end_col < 6),
        "adjacent beta cell must not be selected: {spans:?}"
    );
    assert!(
        spans
            .iter()
            .any(|span| span.row == 0 && span.start_col == 0)
    );
    assert!(spans.iter().any(|span| span.row == 1));
    assert_eq!(app.snapshot_selection_text(), "alpha");
}

#[test]
fn handle_mouse_triple_click_selects_logical_line() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;
    app.copy_on_release = false;
    app.chat_area = Some(Rect::new(0, 0, 5, 2));
    app.chat_text_grid = vec![
        "hello".chars().map(|ch| ch.to_string()).collect(),
        "world".chars().map(|ch| ch.to_string()).collect(),
    ];
    let first = selectable_meta();
    let mut second = selectable_meta();
    second.continuation = true;
    app.chat_row_meta = vec![first, second];

    app.event_loop_monotonic_now = Duration::from_millis(0);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));
    app.event_loop_monotonic_now = Duration::from_millis(20);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));
    app.event_loop_monotonic_now = Duration::from_millis(40);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));

    let spans = app.selection_spans.clone().expect("line spans");
    assert_eq!(spans.len(), 2);
    assert_eq!(spans[0].row, 0);
    assert_eq!(spans[1].row, 1);
    assert_eq!(app.snapshot_selection_text(), "hello world");
}

#[test]
fn chat_semantic_target_at_classifies_plain_table_padding_and_chrome() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.chat_area = Some(Rect::new(0, 0, 10, 3));
    let (fragments, row0) = table_fragments();
    let mut table = selectable_meta();
    table.copy_cells = row0;
    table.copy_fragments = fragments;
    table.copy_provenance_present = true;
    let mut padding = selectable_meta();
    padding.selectable = false;
    padding.row_kind = render::ChatRowKind::Padding;
    padding.copy_target = None;
    let mut chrome = selectable_meta();
    chrome.copy_cells = vec![None; 10];
    chrome.copy_provenance_present = true;
    app.chat_row_meta = vec![table, padding, chrome];

    assert!(matches!(
        app.chat_semantic_target_at((1, 0)),
        mouse_gesture::SemanticTarget::TableCell { fragment_id: 0, .. }
    ));
    assert!(matches!(
        app.chat_semantic_target_at((7, 0)),
        mouse_gesture::SemanticTarget::TableCell { fragment_id: 1, .. }
    ));
    assert_eq!(
        app.chat_semantic_target_at((1, 1)),
        mouse_gesture::SemanticTarget::NonSelectable
    );
    assert_eq!(
        app.chat_semantic_target_at((1, 2)),
        mouse_gesture::SemanticTarget::NonSelectable
    );
    assert_eq!(
        app.chat_semantic_target_at((0, 10)),
        mouse_gesture::SemanticTarget::NonSelectable
    );
}

#[test]
fn settings_link_and_chat_selection_z_order_preserved() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;
    app.copy_on_release = true;
    app.chat_area = Some(Rect::new(0, 0, 20, 4));
    app.chat_text_grid = vec![vec!["x".to_string(); 20]; 4];
    app.chat_row_meta = vec![selectable_meta(); 4];

    app.keys_overlay = Some(KeysOverlay::open(KeyContext::Composer));
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 2, 1));
    assert!(app.selection.is_none());
    app.keys_overlay = None;

    app.context_menu = Some(ContextMenu {
        preferred_origin: (2, 1),
        clicked_chat_row: 0,
        cursor: 0,
        items: ContextMenu::build_items(false, false),
    });
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 80, 20));
    assert!(app.context_menu.is_none());
    assert!(app.selection.is_none());

    app.link_registry
        .register(Rect::new(0, 0, 8, 1), "https://settings.test", "docs");
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 2, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 2, 0));
    assert!(
        app.selection.is_none(),
        "registered settings link must not start chat selection"
    );
}

#[test]
fn mouse_gesture_source_inventory_rejects_legacy_path() {
    let gesture = include_str!("mouse_gesture.rs");
    assert!(
        !gesture.contains("#![allow(dead_code)]"),
        "mouse_gesture.rs must not allow dead_code"
    );
    let mouse = include_str!("mouse.rs");
    assert!(
        !mouse.contains("copy_selection_plaintext_auto()"),
        "handle_mouse must not copy synchronously"
    );
    assert!(
        !mouse.contains("active: true"),
        "handle_mouse must not start a naive active Selection"
    );
}

#[test]
fn cancel_mouse_gesture_clears_selection_and_pending_copy_map() {
    let mut app = app_with_hello_grid();
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: false,
    });
    app.cancel_mouse_gesture(Duration::from_millis(10));
    assert!(app.selection.is_none());
    assert!(app.pending_mouse_copies.is_empty());
}

#[tokio::test]
async fn invalidate_mouse_gesture_sources_drop_pending_copy_and_ignore_late_result() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    assert_eq!(app.pending_mouse_copies.len(), 1);
    let runner = app.controllable_mouse_copy.take().unwrap();

    app.handle_key(key(KeyCode::Esc));
    assert!(app.selection.is_none());
    assert_eq!(app.pending_mouse_copies.len(), 0);
    assert!(app.toast.is_none());

    runner.release(MouseCopyResult::Confirmed);
    tokio::task::yield_now().await;
    app.drain_async_actions();
    assert!(app.toast.is_none());
    assert!(app.selection.is_none());
}

#[tokio::test]
async fn mouse_copy_result_matrix_maps_toasts() {
    async fn release_one(result: MouseCopyResult) -> (Option<String>, Option<ToastKind>, usize) {
        let mut app = app_with_hello_grid();
        app.arm_controllable_mouse_copy = true;
        app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
        app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
        app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
        let runner = app.controllable_mouse_copy.take().unwrap();
        runner.release(result);
        tokio::task::yield_now().await;
        app.drain_async_actions();
        (
            app.toast.as_ref().map(|toast| toast.text.clone()),
            app.toast.as_ref().map(|toast| toast.kind),
            app.pending_mouse_copies.len(),
        )
    }

    let (text, kind, pending) = release_one(MouseCopyResult::Confirmed).await;
    assert_eq!(text.as_deref(), Some("Copied 5 chars to clipboard."));
    assert_eq!(kind, Some(ToastKind::Success));
    assert_eq!(pending, 0);

    let (text, kind, _) = release_one(MouseCopyResult::Unverified).await;
    assert_eq!(
        text.as_deref(),
        Some("Copied 5 chars to clipboard. (unverified — could not confirm delivery)")
    );
    assert_eq!(kind, Some(ToastKind::Warning));

    let (text, kind, _) = release_one(MouseCopyResult::TooLarge).await;
    assert_eq!(
        text.as_deref(),
        Some("Selection too large to copy (max sequence size) — copy a smaller range.")
    );
    assert_eq!(kind, Some(ToastKind::Error));

    let (text, kind, _) = release_one(MouseCopyResult::Failed).await;
    assert_eq!(text.as_deref(), Some("Copy failed."));
    assert_eq!(kind, Some(ToastKind::Error));

    let (text, kind, _) = release_one(MouseCopyResult::Empty).await;
    assert_eq!(text, None);
    assert_eq!(kind, None);
}

#[tokio::test]
async fn mouse_copy_dedupe_rejects_newer_token() {
    let mut app = app_with_hello_grid();
    let first = app
        .start_controllable_mouse_copy(1, 0, 3)
        .expect("first copy starts");
    assert!(app.start_controllable_mouse_copy(2, 1, 3).is_none());
    assert_eq!(app.pending_mouse_copies.len(), 1);
    assert!(app.pending_mouse_copies.contains_key(&first));
}

#[tokio::test]
async fn drain_cancelled_tombstones_mouse_copy_without_toast() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    let id = *app.pending_mouse_copies.keys().next().unwrap();
    app.async_actions.abort_id(id);
    app.drain_async_actions();
    assert_eq!(app.pending_mouse_copies.len(), 0);
    assert!(app.toast.is_none());
}

#[tokio::test]
async fn expired_unknown_mouse_copy_id_is_inert() {
    let mut app = app_with_hello_grid();
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: false,
    });
    app.async_actions.inject_completed_for_test(
        crate::tui::async_action::AsyncActionId::from_raw_for_test(99),
        AsyncActionKind::Blocking("mouse.copy"),
        Ok(AsyncActionPayload::MouseCopy(MouseCopyResult::Confirmed)),
    );
    app.drain_async_actions();
    assert!(app.toast.is_none());
    assert!(app.selection.is_some());
}

#[tokio::test]
async fn mouse_copy_shutdown_drops_ui_ownership() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    let runner = app.controllable_mouse_copy.take();
    app.drop_mouse_copy_ui_ownership();
    assert_eq!(app.pending_mouse_copies.len(), 0);
    app.async_actions.shutdown();
    if let Some(runner) = runner {
        runner.release(MouseCopyResult::Confirmed);
    }
    tokio::task::yield_now().await;
    app.drain_async_actions();
    assert!(app.toast.is_none());
}

#[tokio::test]
async fn session_reset_and_view_generation_drop_pending_mouse_copy() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    assert_eq!(app.pending_mouse_copies.len(), 1);
    app.invalidate_mouse_gesture(
        MouseGestureInvalidation::TerminalChange,
        Duration::from_millis(10),
    );
    app.async_actions.advance_view_generation();
    assert_eq!(app.pending_mouse_copies.len(), 0);
    assert!(app.selection.is_none());
    assert!(app.toast.is_none());
}

#[test]
fn composer_input_and_scroll_invalidate_mouse_gesture() {
    let mut app = app_with_hello_grid();
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: false,
    });
    app.handle_key(key(KeyCode::Char('a')));
    assert!(app.selection.is_none());

    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: false,
    });
    app.handle_mouse(mouse(MouseEventKind::ScrollUp, 1, 0));
    assert!(app.selection.is_none());
}

#[test]
fn service_due_mouse_gesture_timers_is_input_first() {
    let mut app = app_with_hello_grid();
    app.copy_on_release = true;
    app.event_loop_monotonic_now = Duration::from_millis(0);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 6, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 6, 0));
    app.event_loop_monotonic_now = Duration::from_millis(20);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 6, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 6, 0));
    assert!(app.mouse_gesture_state.pending_copy_deadline.is_some());
    assert!(app.pending_mouse_copies.is_empty());

    app.event_loop_monotonic_now = Duration::from_millis(500);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 6, 0));
    app.service_due_mouse_gesture_timers(Duration::from_millis(500));
    assert!(
        app.pending_mouse_copies.is_empty(),
        "third press must precede the word copy timer"
    );
}

#[tokio::test]
async fn mouse_copy_stale_newer_token_result_is_inert() {
    let mut app = app_with_hello_grid();
    let id = app.start_controllable_mouse_copy(7, 3, 4).expect("started");
    app.mouse_gesture_state.press_generation = 9;
    app.mouse_gesture_state.copy_token = Some(8);
    app.mouse_gesture_state.copy_press_generation = Some(9);
    app.controllable_mouse_copy
        .take()
        .unwrap()
        .release(MouseCopyResult::Confirmed);
    tokio::task::yield_now().await;
    app.drain_async_actions();
    assert!(app.toast.is_none());
    assert!(!app.pending_mouse_copies.contains_key(&id));
}

#[test]
fn handle_mouse_double_click_does_not_select_other_table_same_cell() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;
    app.copy_on_release = false;
    app.chat_area = Some(Rect::new(0, 0, 5, 2));
    app.chat_text_grid = vec![
        "alpha".chars().map(|ch| ch.to_string()).collect(),
        "gamma".chars().map(|ch| ch.to_string()).collect(),
    ];
    let fragments = Rc::new(vec![
        CopyFragment {
            id: 0,
            text: "alpha".to_string(),
            source: None,
            logical_line: 0,
            table_cell: Some((0, 0, 0)),
        },
        CopyFragment {
            id: 1,
            text: "gamma".to_string(),
            source: None,
            logical_line: 1,
            table_cell: Some((1, 0, 0)),
        },
    ]);
    let mut first = selectable_meta();
    first.copy_cells = vec![Some(0); 5];
    first.copy_fragments = fragments.clone();
    first.copy_provenance_present = true;
    let mut second = selectable_meta();
    second.copy_cells = vec![Some(1); 5];
    second.copy_fragments = fragments;
    second.copy_provenance_present = true;
    app.chat_row_meta = vec![first, second];

    app.event_loop_monotonic_now = Duration::from_millis(0);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));
    app.event_loop_monotonic_now = Duration::from_millis(20);
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 1, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 1, 0));

    let spans = app.selection_spans.clone().expect("first table spans");
    assert!(
        spans.iter().all(|span| span.row == 0),
        "second table cell (0,0) must stay unselected: {spans:?}"
    );
    assert_eq!(app.snapshot_selection_text(), "alpha");
}

#[tokio::test]
async fn mouse_copy_runner_expiry_rejects_without_stale_toast() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    assert_eq!(app.pending_mouse_copies.len(), 1);
    let expired = app.async_actions.expire_blocking(
        std::time::Instant::now() + Duration::from_secs(60),
        Duration::from_secs(30),
    );
    assert_eq!(expired.len(), 1);
    for result in expired {
        app.apply_async_action_result(result);
    }
    assert_eq!(app.pending_mouse_copies.len(), 0);
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("Copy failed.")
    );
}

#[tokio::test]
async fn mouse_copy_duplicate_completed_result_is_inert() {
    let mut app = app_with_hello_grid();
    app.arm_controllable_mouse_copy = true;
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 0, 0));
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 4, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 4, 0));
    let id = *app.pending_mouse_copies.keys().next().unwrap();
    app.controllable_mouse_copy
        .take()
        .unwrap()
        .release(MouseCopyResult::Confirmed);
    tokio::task::yield_now().await;
    app.drain_async_actions();
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("Copied 5 chars to clipboard.")
    );
    app.async_actions.inject_completed_for_test(
        id,
        AsyncActionKind::Blocking("mouse.copy"),
        Ok(AsyncActionPayload::MouseCopy(MouseCopyResult::Failed)),
    );
    app.drain_async_actions();
    assert_eq!(
        app.toast.as_ref().map(|toast| toast.text.as_str()),
        Some("Copied 5 chars to clipboard.")
    );
    assert!(app.pending_mouse_copies.is_empty());
}

fn agent_with_perf_entry(performance_expanded: bool) -> HistoryEntry {
    HistoryEntry::Agent {
        name: "Build".into(),
        text: "hello".into(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        expanded: false,
        reasoning_offset: 0,
        think_duration: None,
        seq: Some(1),
        performance: Some(cockpit_client::presentation::ResponsePerformance {
            ttft_ms: 3000,
            generation_ms: 500,
            displayed_tokens: 27,
            encoding: "cl100k_base".to_string(),
        }),
        performance_expanded,
    }
}

fn app_with_metric_chip() -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.mouse_capture = true;
    app.chat_area = Some(Rect::new(0, 0, 40, 2));
    app.history.push(agent_with_perf_entry(false));
    let mut meta = selectable_meta();
    meta.history_index = Some(0);
    meta.metric_hit = Some(render::MetricHit {
        history_index: 0,
        col_start: 2,
        col_end: 6,
    });
    // Non-selectable over the metric so gesture selection does not claim it.
    meta.selectable = false;
    app.chat_row_meta = vec![meta];
    app
}

#[test]
fn response_performance_chip_click_has_exact_hit_range() {
    let mut app = app_with_metric_chip();
    let press_gen = app.mouse_gesture_state.press_generation;
    let view_gen = app.mouse_gesture_state.view_generation;

    // Click inside hit range: Down arms, Up toggles.
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 3, 0));
    assert!(app.pending_performance_chip_press.is_some());
    assert_eq!(
        app.pending_performance_chip_press.unwrap().press_generation,
        press_gen
    );
    assert_eq!(
        app.pending_performance_chip_press.unwrap().view_generation,
        view_gen
    );
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 3, 0));
    match &app.history[0] {
        HistoryEntry::Agent {
            performance_expanded: true,
            expanded: false,
            ..
        } => {}
        other => panic!("expected performance expanded only, got {other:?}"),
    }

    // Click outside chip: no toggle.
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 20, 0));
    assert!(app.pending_performance_chip_press.is_none());
    match &app.history[0] {
        HistoryEntry::Agent {
            performance_expanded: true,
            ..
        } => {}
        other => panic!("outside click must not change expansion: {other:?}"),
    }
}

#[test]
fn response_performance_chip_gesture_cancels_on_drag_release_outside_and_stale_generation() {
    let mut app = app_with_metric_chip();

    // Drag cancels.
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 3, 0));
    assert!(app.pending_performance_chip_press.is_some());
    app.handle_mouse(mouse(MouseEventKind::Drag(MouseButton::Left), 8, 0));
    assert!(app.pending_performance_chip_press.is_none());
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 8, 0));
    match &app.history[0] {
        HistoryEntry::Agent {
            performance_expanded: false,
            ..
        } => {}
        other => panic!("drag must cancel toggle: {other:?}"),
    }

    // Release outside cancels.
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 3, 0));
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 30, 0));
    match &app.history[0] {
        HistoryEntry::Agent {
            performance_expanded: false,
            ..
        } => {}
        other => panic!("outside release must cancel: {other:?}"),
    }

    // Stale view generation cancels.
    app.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), 3, 0));
    assert!(app.pending_performance_chip_press.is_some());
    app.invalidate_mouse_gesture(
        MouseGestureInvalidation::ViewChange,
        app.event_loop_monotonic_now,
    );
    assert!(app.pending_performance_chip_press.is_none());
    app.handle_mouse(mouse(MouseEventKind::Up(MouseButton::Left), 3, 0));
    match &app.history[0] {
        HistoryEntry::Agent {
            performance_expanded: false,
            ..
        } => {}
        other => panic!("stale generation must cancel: {other:?}"),
    }
}
