use super::*;
use crate::clipboard::{Confidence, CopyError, DeliveryResult, Representation};
use crate::tui::app::render::{ChatCopyTarget, ChatRowKind, ChatRowMeta};
use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;

fn cells(text: &str, width: usize) -> Vec<String> {
    let mut row = text.chars().map(|ch| ch.to_string()).collect::<Vec<_>>();
    row.resize(width, " ".to_string());
    row
}

fn message_meta(history_index: usize) -> ChatRowMeta {
    ChatRowMeta {
        history_index: Some(history_index),
        row_kind: ChatRowKind::Message,
        copy_target: Some(ChatCopyTarget::Message { history_index }),
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
        continuation: false,
        selectable: true,
        copy_cells: Vec::new(),
        copy_fragments: std::rc::Rc::new(Vec::new()),
        copy_newlines_before: 0,
        copy_fallback_if_unmapped: false,
        copy_provenance_present: false,
    }
}

fn copy_outcome() -> DeliveryResult {
    DeliveryResult {
        attempts: vec![],
        requested_representation: Representation::Plain,
        delivered_representation: Representation::Plain,
        downgrade: None,
        confidence: Confidence::Unverified,
    }
}

fn app_with_selection() -> App {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.chat_area = Some(Rect::new(0, 0, 5, 1));
    app.chat_text_grid = vec![
        ["h", "e", "l", "l", "o"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    ];
    app.chat_row_meta = vec![ChatRowMeta {
        history_index: Some(0),
        row_kind: ChatRowKind::Message,
        copy_target: None,
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
        continuation: false,
        selectable: true,
        copy_cells: Vec::new(),
        copy_fragments: std::rc::Rc::new(Vec::new()),
        copy_newlines_before: 0,
        copy_fallback_if_unmapped: false,
        copy_provenance_present: false,
    }];
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: false,
    });
    app
}

#[test]
fn copy_selection_uses_visible_user_semantics_without_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.history = vec![HistoryEntry::User {
        text: "- **item**\n    code".to_string(),
        cleaned: None,
        expanded: false,
        timestamp: chrono::Local::now(),
        seq: None,
        optimistic_submission_id: None,
        preflight_pending: false,
        persist_failed: false,
    }]
    .into();
    app.chat_area = Some(Rect::new(0, 0, 12, 2));
    app.chat_text_grid = vec![cells("- item", 12), cells("    code", 12)];
    app.chat_row_meta = vec![message_meta(0), message_meta(0)];
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (11, 1),
        active: false,
    });
    let mut copied = None;

    app.copy_selection_plaintext_with(|text| {
        copied = Some(text.to_string());
        Ok(copy_outcome())
    });

    assert_eq!(copied.as_deref(), Some("- item\n  code"));
    assert!(app.selection.is_none());
}

#[test]
fn copy_selection_uses_visible_agent_semantics_without_provenance() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.history = vec![HistoryEntry::Agent {
        name: "Build".to_string(),
        text: "> **quoted**".to_string(),
        reasoning: String::new(),
        timestamp: chrono::Local::now(),
        expanded: false,
        reasoning_offset: 0,
        think_duration: None,
        seq: None,
    }]
    .into();
    app.chat_area = Some(Rect::new(0, 0, 12, 1));
    app.chat_text_grid = vec![cells("quoted", 12)];
    app.chat_row_meta = vec![message_meta(0)];
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (11, 0),
        active: false,
    });
    let mut copied = None;

    app.copy_selection_plaintext_with(|text| {
        copied = Some(text.to_string());
        Ok(copy_outcome())
    });

    assert_eq!(copied.as_deref(), Some("quoted"));
}

#[test]
fn copy_selection_cross_message_falls_back_to_plaintext() {
    let tmp = tempfile::tempdir().unwrap();
    let mut app = App::new(Some(tmp.path()), false);
    app.history = vec![
        HistoryEntry::User {
            text: "**bold**".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            optimistic_submission_id: None,
            preflight_pending: false,
            persist_failed: false,
        },
        HistoryEntry::Agent {
            name: "Build".to_string(),
            text: "_plain_".to_string(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq: None,
        },
    ]
    .into();
    app.chat_area = Some(Rect::new(0, 0, 8, 2));
    app.chat_text_grid = vec![cells("bold", 8), cells("plain", 8)];
    app.chat_row_meta = vec![message_meta(0), message_meta(1)];
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (7, 1),
        active: false,
    });
    let mut copied = None;

    app.copy_selection_plaintext_with(|text| {
        copied = Some(text.to_string());
        Ok(copy_outcome())
    });

    assert_eq!(copied.as_deref(), Some("bold\nplain"));
}

#[test]
fn copy_selection_unmapped_row_falls_back_to_plaintext() {
    let mut app = app_with_selection();
    app.chat_area = Some(Rect::new(0, 0, 5, 2));
    app.chat_text_grid.push(cells("tool", 5));
    app.chat_row_meta.push(ChatRowMeta {
        history_index: None,
        row_kind: ChatRowKind::ToolBox,
        copy_target: None,
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
        continuation: false,
        selectable: true,
        copy_cells: Vec::new(),
        copy_fragments: std::rc::Rc::new(Vec::new()),
        copy_newlines_before: 0,
        copy_fallback_if_unmapped: false,
        copy_provenance_present: false,
    });
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 1),
        active: false,
    });
    let mut copied = None;

    app.copy_selection_plaintext_with(|text| {
        copied = Some(text.to_string());
        Ok(copy_outcome())
    });

    assert_eq!(copied.as_deref(), Some("hello\ntool"));
}

#[test]
fn left_mouse_release_finalizes_selection_without_copy_feedback() {
    let mut app = app_with_selection();
    app.mouse_capture = true;
    // Disable copy_on_release so the release only finalizes the
    // selection without scheduling a clipboard copy or toast.
    app.copy_on_release = false;
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: true,
    });

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 4,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });

    assert!(matches!(
        app.selection,
        Some(Selection { active: false, .. })
    ));
    assert!(app.toast.is_none());
}

#[test]
fn copy_selection_keeps_selection_on_hard_failure() {
    let mut app = app_with_selection();

    app.copy_selection_plaintext_with(|_| Err(CopyError::Backend));

    assert!(app.selection.is_some());
    assert!(matches!(
        app.toast.as_ref().map(|toast| toast.kind),
        Some(ToastKind::Error)
    ));
}

#[test]
fn copy_selection_clears_selection_after_accepted_copy() {
    let mut app = app_with_selection();

    app.copy_selection_plaintext_with(|_| Ok(copy_outcome()));

    assert!(app.selection.is_none());
    assert!(app.toast.is_some());
}

#[test]
fn auto_copy_retains_highlight_on_success() {
    let mut app = app_with_selection();

    app.copy_selection_plaintext_auto_with(|_| Ok(copy_outcome()));

    // Auto-copy retains the highlight for every CopyOutcome — the
    // selection is NOT cleared after a successful copy.
    assert!(
        app.selection.is_some(),
        "auto-copy retains highlight on success"
    );
    assert!(app.toast.is_some(), "auto-copy shows a toast on success");
}

#[test]
fn auto_copy_retains_highlight_on_failure() {
    let mut app = app_with_selection();

    app.copy_selection_plaintext_auto_with(|_| Err(CopyError::Backend));

    // Auto-copy retains the highlight even on hard failure.
    assert!(
        app.selection.is_some(),
        "auto-copy retains highlight on failure"
    );
    assert!(
        matches!(
            app.toast.as_ref().map(|toast| toast.kind),
            Some(ToastKind::Error)
        ),
        "auto-copy shows an error toast on failure"
    );
}

#[test]
fn auto_copy_with_empty_text_is_noop() {
    let mut app = app_with_selection();
    // Replace the grid with all-blank cells so the extracted text is
    // empty — a deterministic no-copy outcome.
    app.chat_text_grid = vec![vec![" ".to_string(); 5]];
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: false,
    });

    app.copy_selection_plaintext_auto_with(|_| panic!("should not copy empty text"));

    // No toast, selection retained (empty selections are no-copy).
    assert!(app.toast.is_none());
    assert!(app.selection.is_some());
}

#[test]
fn auto_copy_release_with_copy_on_release_copies_and_retains() {
    let mut app = app_with_selection();
    app.mouse_capture = true;
    app.copy_on_release = true;
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: true,
    });

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 4,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });

    // The selection is finalized (active=false) and retained (not cleared).
    assert!(matches!(
        app.selection,
        Some(Selection { active: false, .. })
    ));
    // A toast was shown because copy_on_release triggered the copy.
    assert!(app.toast.is_some());
}

#[test]
fn auto_copy_release_with_copy_on_release_disabled_no_copy() {
    let mut app = app_with_selection();
    app.mouse_capture = true;
    app.copy_on_release = false;
    app.selection = Some(Selection {
        anchor: (0, 0),
        focus: (4, 0),
        active: true,
    });

    app.handle_mouse(MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column: 4,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });

    // Selection finalized but no copy (copy_on_release disabled).
    assert!(matches!(
        app.selection,
        Some(Selection { active: false, .. })
    ));
    assert!(
        app.toast.is_none(),
        "no toast when copy_on_release is false"
    );
}
