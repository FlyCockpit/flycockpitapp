//! Shared rendering primitives for the `/settings` dialog shell.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::tui::button::{
    ButtonDispatch, ButtonId, ButtonKind, ButtonRegistry, ButtonSpec, RowControlId,
    RowControlRegistry, RowDispatch, RowTarget, first_bracketed_label,
};
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

/// Monotonic identity for a pointer-triggered effect.  Results are accepted
/// only while the matching operation is live; this prevents a completion
/// from a page that has since been cancelled/replaced from updating its
/// successor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PointerOperationId(pub u64);

#[derive(Debug, Default)]
pub(super) struct PointerOperationGate {
    next: u64,
    pending: Option<PointerOperationId>,
}

impl PointerOperationGate {
    pub(super) fn is_pending(&self) -> bool {
        self.pending.is_some()
    }

    pub(super) fn begin(&mut self) -> PointerOperationId {
        self.next = self.next.saturating_add(1).max(1);
        let id = PointerOperationId(self.next);
        self.pending = Some(id);
        id
    }

    /// Consume a matching completion exactly once.
    pub(super) fn complete(&mut self, id: PointerOperationId) -> bool {
        if self.pending == Some(id) {
            self.pending = None;
            true
        } else {
            false
        }
    }

    pub(super) fn cancel(&mut self) {
        self.pending = None;
    }

    pub(super) fn pending(&self) -> Option<PointerOperationId> {
        self.pending
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum SettingsHeaderAction {
    Close,
    Back,
    BackToConfigPicker,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum SettingsPointerAction {
    Header(SettingsHeaderAction),
    /// A sealed, domain-identified page action. Render-local row keys never
    /// cross this boundary or enter a behavioral reducer.
    Page(super::pointer_actions::SettingsPointerAction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct SettingsControlId(pub u64);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct SettingsScrollRegionId(pub &'static str);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SettingsPointerTarget {
    pub rect: Rect,
    pub action: SettingsPointerAction,
    pub enabled: bool,
    pub disabled_reason: Option<&'static str>,
}

#[derive(Debug)]
pub(super) struct SettingsPointerSurface {
    pub area: std::cell::Cell<Option<Rect>>,
    page_token: std::cell::Cell<Option<u64>>,
    pub targets: RefCell<Vec<SettingsPointerTarget>>,
    pub scroll_regions: RefCell<Vec<(Rect, SettingsScrollRegionId)>>,
    pub hover: RefCell<Option<super::pointer_actions::SettingsPointerAction>>,
    pub header_hover: std::cell::Cell<Option<SettingsHeaderAction>>,
    pub enabled: std::cell::Cell<bool>,
    pub pressed: RefCell<Option<SettingsPointerAction>>,
    pub buttons: RefCell<ButtonRegistry>,
    pub rows: RefCell<RowControlRegistry>,
    pub surface_generation: std::cell::Cell<u64>,
}

impl Default for SettingsPointerSurface {
    fn default() -> Self {
        Self {
            area: std::cell::Cell::new(None),
            page_token: std::cell::Cell::new(None),
            targets: RefCell::new(Vec::new()),
            scroll_regions: RefCell::new(Vec::new()),
            hover: RefCell::new(None),
            header_hover: std::cell::Cell::new(None),
            enabled: std::cell::Cell::new(true),
            pressed: RefCell::new(None),
            buttons: RefCell::new(ButtonRegistry::default()),
            rows: RefCell::new(RowControlRegistry::default()),
            surface_generation: std::cell::Cell::new(0),
        }
    }
}

impl SettingsPointerSurface {
    pub fn clear_for(&self, area: Rect) {
        if self.area.get() != Some(area) {
            *self.hover.borrow_mut() = None;
            self.header_hover.set(None);
        }
        self.area.set(Some(area));
        self.targets.borrow_mut().clear();
        self.scroll_regions.borrow_mut().clear();
    }

    pub fn clear_for_page(&self, area: Rect, page_token: u64) {
        if self.page_token.replace(Some(page_token)) != Some(page_token) {
            *self.hover.borrow_mut() = None;
            self.header_hover.set(None);
            *self.pressed.borrow_mut() = None;
            self.surface_generation
                .set(self.surface_generation.get().wrapping_add(1));
        }
        self.clear_for(area);
        let capture = self.enabled.get();
        self.buttons
            .borrow_mut()
            .begin_frame(capture, self.surface_generation.get());
        self.rows.borrow_mut().begin_frame(capture);
    }

    pub fn register(&self, target: SettingsPointerTarget) {
        if !self.enabled.get() {
            return;
        }
        self.targets.borrow_mut().push(target);
    }

    pub fn paint_header_button(
        &self,
        frame: &mut Frame,
        x: u16,
        y: u16,
        max_width: u16,
        action: SettingsHeaderAction,
        label: &str,
    ) -> Option<Rect> {
        let spec = ButtonSpec::new(
            ButtonId::SettingsHeader(action),
            label,
            ButtonDispatch::SettingsHeader(action),
        );
        let rect = self
            .buttons
            .borrow_mut()
            .paint(frame, x, y, max_width, spec)?;
        self.register(SettingsPointerTarget {
            rect,
            action: SettingsPointerAction::Header(action),
            enabled: true,
            disabled_reason: None,
        });
        Some(rect)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn paint_page_button(
        &self,
        frame: &mut Frame,
        x: u16,
        y: u16,
        max_width: u16,
        action: super::pointer_actions::SettingsPointerAction,
        label: impl Into<String>,
        enabled: bool,
        focused: bool,
    ) -> Option<Rect> {
        let kind = if is_destructive_settings_action(&action) {
            ButtonKind::Destructive
        } else {
            ButtonKind::Default
        };
        let spec = ButtonSpec::new(
            ButtonId::Settings(action.clone()),
            label,
            ButtonDispatch::Settings(action.clone()),
        )
        .enabled(enabled)
        .focused(focused)
        .kind(kind);
        let rect = self
            .buttons
            .borrow_mut()
            .paint(frame, x, y, max_width, spec)?;
        self.register(SettingsPointerTarget {
            rect,
            action: SettingsPointerAction::Page(action),
            enabled,
            disabled_reason: None,
        });
        Some(rect)
    }

    pub fn button_hit(&self, column: u16, row: u16) -> Option<ButtonId> {
        self.buttons
            .borrow()
            .hit(column, row)
            .map(|target| target.id.clone())
    }

    pub fn hit(&self, column: u16, row: u16) -> Option<SettingsPointerTarget> {
        self.targets
            .borrow()
            .iter()
            .rev()
            .find(|target| {
                column >= target.rect.x
                    && column < target.rect.right()
                    && row >= target.rect.y
                    && row < target.rect.bottom()
            })
            .cloned()
    }

    pub fn register_scroll_region(&self, rect: Rect, id: SettingsScrollRegionId) {
        if !self.enabled.get() {
            return;
        }
        self.scroll_regions.borrow_mut().push((rect, id));
    }

    pub fn scroll_region_at(&self, column: u16, row: u16) -> Option<SettingsScrollRegionId> {
        self.scroll_regions
            .borrow()
            .iter()
            .rev()
            .find(|(rect, _)| {
                column >= rect.x && column < rect.right() && row >= rect.y && row < rect.bottom()
            })
            .map(|(_, id)| *id)
    }
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

    /// Render a list and publish its page-declared semantic controls from the
    /// same final line layout and `ListState` offset. `controls` is parallel
    /// to `lines`; continuation, heading, blank, and status lines use `None`.
    /// This is deliberately source-backed metadata, not terminal-buffer or
    /// marker-text inference.
    pub(super) fn render_control_lines(
        &self,
        frame: &mut Frame,
        area: Rect,
        key: impl Into<String>,
        content: (Vec<Line<'static>>, Option<usize>),
        controls: Vec<
            Option<(
                super::pointer_actions::SettingsPointerAction,
                bool,
                Option<&'static str>,
            )>,
        >,
        pointer: PointerRenderContext<'_>,
    ) {
        let (lines, selected_line) = content;
        let PointerRenderContext { surface, region } = pointer;
        debug_assert_eq!(lines.len(), controls.len());
        let key = key.into();
        let line_texts: Vec<String> = lines
            .iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect()
            })
            .collect();
        self.render_lines(frame, area, key.clone(), lines, selected_line);
        surface.register_scroll_region(area, region);
        let offset = self.offset_for(&key);
        for (screen_row, binding) in controls
            .into_iter()
            .skip(offset)
            .take(usize::from(area.height))
            .enumerate()
        {
            let Some((action, enabled, disabled_reason)) = binding else {
                continue;
            };
            let y = area.y.saturating_add(screen_row as u16);
            let line_idx = offset.saturating_add(screen_row);
            if action.is_row_control() {
                let rect = Rect::new(area.x, y, area.width, 1);
                surface.register(SettingsPointerTarget {
                    rect,
                    action: SettingsPointerAction::Page(action.clone()),
                    enabled,
                    disabled_reason,
                });
                surface.rows.borrow_mut().register(RowTarget {
                    id: RowControlId::Settings(action.clone()),
                    rect,
                    dispatch: RowDispatch::Settings(action),
                });
                continue;
            }
            if let Some((col_offset, label)) = line_texts
                .get(line_idx)
                .and_then(|text| first_bracketed_label(text))
            {
                let x = area.x.saturating_add(col_offset);
                let max_width = area.right().saturating_sub(x);
                let focused = selected_line == Some(line_idx);
                surface.paint_page_button(frame, x, y, max_width, action, label, enabled, focused);
                if disabled_reason.is_some()
                    && let Some(last) = surface.targets.borrow_mut().last_mut()
                {
                    last.disabled_reason = disabled_reason;
                }
                continue;
            }
            let rect = Rect::new(area.x, y, area.width, 1);
            surface.register(SettingsPointerTarget {
                rect,
                action: SettingsPointerAction::Page(action),
                enabled,
                disabled_reason,
            });
        }
    }

    pub(super) fn render_bound_lines<A>(
        &self,
        frame: &mut Frame,
        area: Rect,
        key: impl Into<String>,
        content: (Vec<Line<'static>>, Option<usize>),
        bindings: impl IntoIterator<Item = (usize, A)>,
        pointer: PointerRenderContext<'_>,
    ) where
        A: Into<super::pointer_actions::SettingsPointerAction>,
    {
        let (lines, selected_line) = content;
        let mut controls = vec![None; lines.len()];
        for (line, id) in bindings {
            if let Some(slot) = controls.get_mut(line) {
                *slot = Some((id.into(), true, None));
            }
        }
        self.render_control_lines(frame, area, key, (lines, selected_line), controls, pointer);
    }

    pub(super) fn offset_for(&self, key: &str) -> usize {
        self.states
            .borrow()
            .get(key)
            .map(ListState::offset)
            .unwrap_or(0)
    }
}

pub(super) struct PointerRenderContext<'a> {
    pub(super) surface: &'a SettingsPointerSurface,
    pub(super) region: SettingsScrollRegionId,
}

impl<'a> PointerRenderContext<'a> {
    pub(super) fn new(surface: &'a SettingsPointerSurface, region: SettingsScrollRegionId) -> Self {
        Self { surface, region }
    }
}

impl<'a> From<(&'a SettingsPointerSurface, SettingsScrollRegionId)> for PointerRenderContext<'a> {
    fn from((surface, region): (&'a SettingsPointerSurface, SettingsScrollRegionId)) -> Self {
        Self::new(surface, region)
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
    let cursor = cockpit_host::text::floor_char_boundary(value, cursor);
    let rel_cursor = cursor.saturating_sub(visible.start).min(visible.text.len());
    let rel_cursor = cockpit_host::text::floor_char_boundary(&visible.text, rel_cursor);
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
) -> std::ops::Range<usize> {
    let start = lines.len();
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
            return start..lines.len();
        }
        let cursor = cockpit_host::text::floor_char_boundary(value, cursor);
        let (before, after) = value.split_at(cursor);
        spans.push(Span::styled(before.to_string(), focused_field_style()));
        spans.push(cursor_marker_span());
        spans.push(Span::styled(after.to_string(), focused_field_style()));
        lines.push(Line::from(spans));
        return start..lines.len();
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
    start..lines.len()
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
    let cursor = cockpit_host::text::floor_char_boundary(value, cursor);
    let before = &value[..cursor];
    let mut start = 0;
    while before[start..].width() >= max_width && start < cursor {
        let Some((idx, ch)) = before[start..].char_indices().next() else {
            break;
        };
        start += idx + ch.len_utf8();
    }
    let start = cockpit_host::text::floor_char_boundary(value, start);
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

fn is_destructive_settings_action(action: &super::pointer_actions::SettingsPointerAction) -> bool {
    use super::pointer_actions::*;
    matches!(
        action,
        SettingsPointerAction::Agents(AgentsAction::Delete(_))
            | SettingsPointerAction::Agents(AgentsAction::Reset(_))
            | SettingsPointerAction::Agents(AgentsAction::ResetAll)
            | SettingsPointerAction::Tools(ToolsAction::DeleteUserTool(_))
            | SettingsPointerAction::Tools(ToolsAction::Reset)
            | SettingsPointerAction::Harnesses(HarnessesAction::Delete(_))
            | SettingsPointerAction::Skills(SkillsAction::DeleteScanDirectory(_))
            | SettingsPointerAction::Skills(SkillsAction::Reset)
            | SettingsPointerAction::Mcp(McpAction::Delete(_))
            | SettingsPointerAction::Providers(ProvidersAction::Delete(_, _))
            | SettingsPointerAction::Providers(ProvidersAction::BeginDelete(_))
            | SettingsPointerAction::Providers(ProvidersAction::DeleteModel(_, _))
            | SettingsPointerAction::Lsp(LspAction::Uninstall(_))
            | SettingsPointerAction::Lsp(LspAction::Reset)
            | SettingsPointerAction::List(ListAction::Delete(_))
            | SettingsPointerAction::Category(CategoryAction::Reset)
            | SettingsPointerAction::Generation(GenerationAction::DeleteEndpoint(_))
            | SettingsPointerAction::Generation(GenerationAction::DeleteTarget(_))
            | SettingsPointerAction::Generation(GenerationAction::DeleteWorkflow(_))
            | SettingsPointerAction::Generation(GenerationAction::CancelJob(_))
            | SettingsPointerAction::Sidecar(SidecarAction::RevokeGrant(_))
            | SettingsPointerAction::DefaultModel(DefaultModelAction::Clear)
    )
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

    #[test]
    fn semantic_control_renderer_registers_visible_rows_only() {
        let states = SettingsScrollStates::default();
        let surface = SettingsPointerSurface::default();
        let mut terminal = Terminal::new(TestBackend::new(20, 3)).expect("terminal");
        terminal
            .draw(|frame| {
                surface.clear_for_page(Rect::new(0, 0, 20, 3), 7);
                states.render_control_lines(
                    frame,
                    Rect::new(0, 0, 20, 3),
                    "controls",
                    (
                        (0..8).map(|row| Line::from(format!("row {row}"))).collect(),
                        Some(6),
                    ),
                    (0..8)
                        .map(|row| {
                            let ids = [
                                super::super::pointer_actions::RootNodeId::DefaultModel,
                                super::super::pointer_actions::RootNodeId::Providers,
                                super::super::pointer_actions::RootNodeId::Agents,
                                super::super::pointer_actions::RootNodeId::Interface,
                                super::super::pointer_actions::RootNodeId::Behavior,
                                super::super::pointer_actions::RootNodeId::Privacy,
                                super::super::pointer_actions::RootNodeId::Translation,
                                super::super::pointer_actions::RootNodeId::Tools,
                            ];
                            Some((
                                super::super::pointer_actions::SettingsPointerAction::Root(
                                    super::super::pointer_actions::RootAction::Open(ids[row]),
                                ),
                                true,
                                None,
                            ))
                        })
                        .collect(),
                    (&surface, SettingsScrollRegionId("controls")).into(),
                );
            })
            .expect("draw controls");

        let targets = surface.targets.borrow();
        assert_eq!(targets.len(), 3);
        assert!(targets.iter().all(|target| target.rect.bottom() <= 3));
        assert!(
            targets
                .iter()
                .all(|target| matches!(target.action, SettingsPointerAction::Page(_)))
        );
        assert_eq!(
            surface.scroll_region_at(5, 2),
            Some(SettingsScrollRegionId("controls"))
        );
        assert_eq!(surface.scroll_region_at(5, 3), None);
    }

    #[test]
    fn hover_survives_same_surface_redraw_and_clears_on_transition() {
        let surface = SettingsPointerSurface::default();
        let area = Rect::new(1, 2, 20, 5);
        surface.clear_for_page(area, 10);
        let action = super::super::pointer_actions::SettingsPointerAction::Root(
            super::super::pointer_actions::RootAction::Open(
                super::super::pointer_actions::RootNodeId::Interface,
            ),
        );
        *surface.hover.borrow_mut() = Some(action.clone());
        surface.clear_for_page(area, 10);
        assert_eq!(surface.hover.borrow().as_ref(), Some(&action));
        surface.clear_for_page(area, 11);
        assert!(surface.hover.borrow().is_none());
    }
}
