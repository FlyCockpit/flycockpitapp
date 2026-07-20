//! Shared rendering primitives for the `/settings` dialog shell.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::tui::theme::MUTED_COLOR_INDEX;

pub(super) const SELECTED_MARKER: &str = "▸ ";
pub(super) const ROW_MARKER_WIDTH: usize = 2;
const CURSOR_MARKER: &str = "\u{E000}";
pub(super) const TEXT_COLUMN_GUTTER_WIDTH: u16 = 2;
const TEXT_COLUMN_MIN_LEFT_WIDTH: u16 = 34;
const TEXT_COLUMN_MIN_RIGHT_WIDTH: u16 = 20;
const TEXT_COLUMN_STACKED_GAP: u16 = 1;
const TEXT_COLUMN_STACKED_LIST_PERCENT: u16 = 62;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TextColumnLayout {
    Two { left: Rect, right: Rect },
    Stacked { top: Rect, bottom: Rect },
}

pub(super) fn settings_text_columns(area: Rect) -> TextColumnLayout {
    let min_two_column_width =
        TEXT_COLUMN_MIN_LEFT_WIDTH + TEXT_COLUMN_GUTTER_WIDTH + TEXT_COLUMN_MIN_RIGHT_WIDTH;
    if area.width >= min_two_column_width {
        let cols = Layout::horizontal([Constraint::Percentage(62), Constraint::Percentage(38)])
            .spacing(TEXT_COLUMN_GUTTER_WIDTH)
            .split(area);
        return TextColumnLayout::Two {
            left: cols[0],
            right: cols[1],
        };
    }

    let rows = Layout::vertical([
        Constraint::Percentage(TEXT_COLUMN_STACKED_LIST_PERCENT),
        Constraint::Percentage(100 - TEXT_COLUMN_STACKED_LIST_PERCENT),
    ])
    .spacing(TEXT_COLUMN_STACKED_GAP)
    .split(area);
    TextColumnLayout::Stacked {
        top: rows[0],
        bottom: rows[1],
    }
}

pub(super) fn normal_style() -> Style {
    Style::default()
}

pub(super) fn muted_style() -> Style {
    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))
}

pub(super) fn selected_style() -> Style {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
}

pub(super) fn heading_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

pub(super) fn focused_field_style() -> Style {
    Style::default().fg(Color::White)
}

pub(super) fn inactive_field_style() -> Style {
    muted_style()
}

pub(super) fn caret_style() -> Style {
    Style::default().fg(Color::Yellow)
}

pub(super) fn cursor_marker_span() -> Span<'static> {
    Span::styled(CURSOR_MARKER.to_string(), caret_style())
}

pub(super) fn park_cursor_from_markers(frame: &mut Frame, area: Rect) -> Option<Position> {
    let mut cursor = None;
    let buf = frame.buffer_mut();
    for y in area.y..area.y.saturating_add(area.height) {
        for x in area.x..area.x.saturating_add(area.width) {
            if let Some(cell) = buf.cell_mut((x, y))
                && cell.symbol() == CURSOR_MARKER
            {
                cell.set_symbol(" ");
                cursor.get_or_insert(Position::new(x, y));
            }
        }
    }
    cursor
}

pub(super) fn success_style() -> Style {
    Style::default().fg(Color::Green)
}

pub(super) fn warning_style() -> Style {
    Style::default().fg(Color::Yellow)
}

pub(super) fn error_style() -> Style {
    Style::default().fg(Color::Red)
}

pub(super) fn marker(selected: bool) -> &'static str {
    if selected { SELECTED_MARKER } else { "  " }
}

pub(super) fn selected_line_from_marker(lines: &[Line<'static>]) -> Option<usize> {
    lines.iter().position(|line| {
        line.spans
            .first()
            .is_some_and(|span| span.content.contains(SELECTED_MARKER))
    })
}

pub(super) fn selected_or_normal(selected: bool) -> Style {
    if selected {
        selected_style()
    } else {
        normal_style()
    }
}

pub(super) fn selected_or_field(selected: bool) -> Style {
    if selected {
        selected_style()
    } else {
        focused_field_style()
    }
}

pub(super) fn indicator_line(label: String) -> Line<'static> {
    Line::from(Span::styled(label, muted_style()))
}

#[derive(Debug, Default)]
pub(super) struct SettingsScrollStates {
    states: RefCell<BTreeMap<String, ListState>>,
}

impl SettingsScrollStates {
    pub(super) fn render_lines(
        &self,
        frame: &mut Frame,
        area: Rect,
        key: impl Into<String>,
        lines: Vec<Line<'static>>,
        selected_line: Option<usize>,
    ) {
        let item_count = lines.len();
        let items = lines.into_iter().map(ListItem::new).collect::<Vec<_>>();
        let selected = selected_line
            .filter(|_| item_count > 0)
            .map(|line| line.min(item_count.saturating_sub(1)));
        let mut states = self.states.borrow_mut();
        let state = states.entry(key.into()).or_default();
        state.select(selected);
        frame.render_stateful_widget(List::new(items).scroll_padding(1), area, state);
    }

    pub(super) fn offset_for(&self, key: &str) -> usize {
        self.states
            .borrow()
            .get(key)
            .map(ListState::offset)
            .unwrap_or(0)
    }
}

pub(super) struct WrappedValueLayout {
    pub(super) first_prefix: Vec<Span<'static>>,
    pub(super) prefix_width: usize,
    pub(super) continuation_prefix: Vec<Span<'static>>,
    pub(super) suffix: Option<Span<'static>>,
}

pub(super) fn push_wrapped_prefixed_value(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    layout: WrappedValueLayout,
    value: &str,
    value_style: Style,
) {
    let width = usize::from(width);
    if width == 0 {
        lines.push(Line::from(layout.first_prefix));
        return;
    }
    let prefix_width = layout.prefix_width.min(width.saturating_sub(1));
    let value_width = width.saturating_sub(prefix_width).max(1);
    let chunks = wrap_chunks(value, value_width);

    if chunks.is_empty() {
        let mut spans = layout.first_prefix;
        if let Some(suffix) = layout.suffix {
            spans.push(suffix);
        }
        lines.push(Line::from(spans));
        return;
    }

    for (idx, chunk) in chunks.into_iter().enumerate() {
        let mut spans = if idx == 0 {
            layout.first_prefix.clone()
        } else {
            layout.continuation_prefix.clone()
        };
        spans.push(Span::styled(chunk, value_style));
        if idx == 0
            && let Some(suffix) = &layout.suffix
        {
            spans.push(suffix.clone());
        }
        lines.push(Line::from(spans));
    }
}

pub(super) fn push_label_value_row(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    selected: bool,
    label: &str,
    label_width: usize,
    value: &str,
    value_style: Style,
) {
    let indent = ROW_MARKER_WIDTH + label_width + 2;
    push_wrapped_prefixed_value(
        lines,
        width,
        WrappedValueLayout {
            first_prefix: vec![
                Span::raw(marker(selected).to_string()),
                Span::styled(
                    format!("{label:<width$}", width = label_width),
                    selected_or_field(selected),
                ),
                Span::raw("  "),
            ],
            prefix_width: indent,
            continuation_prefix: vec![Span::raw(" ".repeat(indent))],
            suffix: None,
        },
        value,
        value_style,
    );
}

pub(super) fn push_label_text_field_row(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    selected: bool,
    label: &str,
    label_width: usize,
    value: &str,
    cursor: usize,
) {
    let indent = ROW_MARKER_WIDTH + label_width + 2;
    let value_width = usize::from(width).saturating_sub(indent).max(1);
    let visible = cursor_visible_slice(value, cursor, value_width);
    let cursor = crate::text::floor_char_boundary(value, cursor);
    let rel_cursor = cursor.saturating_sub(visible.start).min(visible.text.len());
    let rel_cursor = crate::text::floor_char_boundary(&visible.text, rel_cursor);
    let (before, after) = visible.text.split_at(rel_cursor);
    let mut spans = vec![
        Span::raw(marker(selected).to_string()),
        Span::styled(
            format!("{label:<width$}", width = label_width),
            selected_or_field(selected),
        ),
        Span::raw("  "),
    ];
    if visible.text.is_empty() {
        spans.push(cursor_marker_span());
    } else {
        spans.push(Span::styled(before.to_string(), focused_field_style()));
        spans.push(cursor_marker_span());
        spans.push(Span::styled(after.to_string(), focused_field_style()));
    }
    lines.push(Line::from(spans));
}

pub(super) fn push_text_field_at_cursor(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    label: &str,
    value: &str,
    cursor: usize,
    focused: bool,
    placeholder: Option<&str>,
) {
    let prompt = format!("{label}: ");
    if focused {
        let mut spans = vec![Span::styled(prompt, muted_style())];
        if value.is_empty() {
            spans.push(cursor_marker_span());
            if let Some(placeholder) = placeholder {
                spans.push(Span::styled(
                    placeholder.to_string(),
                    inactive_field_style(),
                ));
            }
            lines.push(Line::from(spans));
            return;
        }
        let cursor = crate::text::floor_char_boundary(value, cursor);
        let (before, after) = value.split_at(cursor);
        spans.push(Span::styled(before.to_string(), focused_field_style()));
        spans.push(cursor_marker_span());
        spans.push(Span::styled(after.to_string(), focused_field_style()));
        lines.push(Line::from(spans));
        return;
    }

    let shown = if value.is_empty() {
        placeholder.unwrap_or("")
    } else {
        value
    };
    let value_style = if value.is_empty() {
        inactive_field_style()
    } else {
        focused_field_style()
    };
    push_wrapped_prefixed_value(
        lines,
        width,
        WrappedValueLayout {
            first_prefix: vec![Span::styled(prompt.clone(), muted_style())],
            prefix_width: prompt.width(),
            continuation_prefix: vec![Span::raw(" ".repeat(prompt.width()))],
            suffix: None,
        },
        shown,
        value_style,
    );
}

pub(super) fn push_wrapped_text(
    lines: &mut Vec<Line<'static>>,
    width: u16,
    text: &str,
    style: Style,
) {
    for chunk in wrap_chunks(text, usize::from(width).max(1)) {
        lines.push(Line::from(Span::styled(chunk, style)));
    }
}

struct VisibleSlice {
    start: usize,
    text: String,
}

fn cursor_visible_slice(value: &str, cursor: usize, max_width: usize) -> VisibleSlice {
    let cursor = crate::text::floor_char_boundary(value, cursor);
    let before = &value[..cursor];
    let mut start = 0;
    while before[start..].width() >= max_width && start < cursor {
        let Some((idx, ch)) = before[start..].char_indices().next() else {
            break;
        };
        start += idx + ch.len_utf8();
    }
    let start = crate::text::floor_char_boundary(value, start);
    let mut end = cursor;
    while end < value.len() && value[start..end].width() < max_width.saturating_sub(1) {
        let Some(ch) = value[end..].chars().next() else {
            break;
        };
        let next = end + ch.len_utf8();
        if value[start..next].width() > max_width {
            break;
        }
        end = next;
    }
    VisibleSlice {
        start,
        text: value[start..end].to_string(),
    }
}

pub(super) fn text_area_lines(
    title: String,
    mode_label: String,
    hint: &'static str,
    text: &str,
    cursor: (usize, usize),
) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(vec![
            Span::styled(title, heading_style()),
            Span::raw(" "),
            Span::styled(format!("[{mode_label}]"), warning_style()),
        ]),
        Line::from(Span::styled(hint.to_string(), muted_style())),
        Line::default(),
    ];

    let (cur_line, cur_col) = cursor;
    for (li, line_text) in text.split('\n').enumerate() {
        if li == cur_line {
            let chars: Vec<char> = line_text.chars().collect();
            let split = cur_col.min(chars.len());
            let before: String = chars[..split].iter().collect();
            let after: String = chars[split..].iter().collect();
            lines.push(Line::from(vec![
                Span::styled(before, focused_field_style()),
                cursor_marker_span(),
                Span::styled(after, focused_field_style()),
            ]));
        } else {
            lines.push(Line::from(Span::styled(
                line_text.to_string(),
                focused_field_style(),
            )));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    #[test]
    fn settings_text_columns_reserves_two_cell_gutter() {
        let area = Rect::new(3, 4, 90, 12);
        let TextColumnLayout::Two { left, right } = settings_text_columns(area) else {
            panic!("expected two-column layout");
        };

        assert_eq!(right.x, left.x + left.width + TEXT_COLUMN_GUTTER_WIDTH);
        assert_eq!(left.y, area.y);
        assert_eq!(right.y, area.y);
        assert_eq!(left.height, area.height);
        assert_eq!(right.height, area.height);
    }

    #[test]
    fn settings_text_columns_stacks_below_minimum_width() {
        let area = Rect::new(1, 2, 48, 20);
        let TextColumnLayout::Stacked { top, bottom } = settings_text_columns(area) else {
            panic!("expected stacked layout");
        };

        assert_eq!(top.x, area.x);
        assert_eq!(bottom.x, area.x);
        assert_eq!(top.width, area.width);
        assert_eq!(bottom.width, area.width);
        assert_eq!(bottom.y, top.y + top.height + TEXT_COLUMN_STACKED_GAP);
    }

    #[test]
    fn list_state_keeps_offset_when_new_selection_remains_visible() {
        let states = SettingsScrollStates::default();
        let backend = TestBackend::new(24, 5);
        let mut terminal = Terminal::new(backend).expect("terminal");
        let lines = || {
            (0..20)
                .map(|i| Line::from(format!("row {i:02}")))
                .collect::<Vec<_>>()
        };

        terminal
            .draw(|frame| {
                states.render_lines(frame, Rect::new(0, 0, 24, 5), "test", lines(), Some(8));
            })
            .expect("draw selected row");
        let offset_after_down = states.offset_for("test");
        assert!(
            offset_after_down > 0,
            "selection should move the list window"
        );

        terminal
            .draw(|frame| {
                states.render_lines(frame, Rect::new(0, 0, 24, 5), "test", lines(), Some(7));
            })
            .expect("draw adjacent selected row");

        assert_eq!(
            states.offset_for("test"),
            offset_after_down,
            "moving up within the visible padded window must not bottom-anchor"
        );
    }
}

fn wrap_chunks(value: &str, width: usize) -> Vec<String> {
    if value.is_empty() {
        return Vec::new();
    }

    let mut chunks = Vec::new();
    let mut current = String::new();
    let mut current_width = 0usize;
    for ch in value.chars() {
        if ch == '\n' {
            chunks.push(std::mem::take(&mut current));
            current_width = 0;
            continue;
        }
        let ch_width = ch.width().unwrap_or(0);
        if current_width > 0 && current_width + ch_width > width {
            chunks.push(std::mem::take(&mut current));
            current_width = 0;
        }
        current.push(ch);
        current_width += ch_width;
    }
    chunks.push(current);
    chunks
}
