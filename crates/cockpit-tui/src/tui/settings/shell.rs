//! Shared rendering primitives for the `/settings` dialog shell.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use unicode_width::UnicodeWidthChar;

use crate::tui::button::{
    ButtonDispatch, ButtonId, ButtonKind, ButtonRegistry, ButtonSpec, RowControlId,
    RowControlRegistry, RowDispatch, RowTarget, first_bracketed_label,
};
use crate::tui::theme::{
    BRASS, BRASS_INDEX, FOG, FOG_INDEX, GOOD, GOOD_INDEX, INK, INK_INDEX, RED, RED_INDEX, YELLOW,
    YELLOW_INDEX, resolve_color,
};

pub(super) const SELECTED_MARKER: &str = "› ";
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
    Style::default().fg(resolve_color(INK, INK_INDEX))
}

pub(super) fn muted_style() -> Style {
    Style::default().fg(resolve_color(FOG, FOG_INDEX))
}

pub(super) fn selected_style() -> Style {
    crate::tui::chrome::selection_style()
}

pub(super) fn heading_style() -> Style {
    Style::default().add_modifier(Modifier::BOLD)
}

pub(super) fn focused_field_style() -> Style {
    Style::default().fg(resolve_color(INK, INK_INDEX))
}

pub(super) fn caret_style() -> Style {
    Style::default().fg(resolve_color(BRASS, BRASS_INDEX))
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
    Style::default().fg(resolve_color(GOOD, GOOD_INDEX))
}

pub(super) fn warning_style() -> Style {
    Style::default().fg(resolve_color(YELLOW, YELLOW_INDEX))
}

pub(super) fn error_style() -> Style {
    Style::default().fg(resolve_color(RED, RED_INDEX))
}

pub(super) fn marker(selected: bool) -> &'static str {
    if selected { SELECTED_MARKER } else { "  " }
}

/// One footer action on the settings help row (excoc ActionBar idiom).
pub(super) struct SettingsHelpAction<'a> {
    pub label: &'a str,
    pub enabled: bool,
    pub primary: bool,
    pub action: super::pointer_actions::SettingsPointerAction,
}

pub(super) struct SettingsHelpRow<'a> {
    pub actions: Vec<SettingsHelpAction<'a>>,
    /// Last known pointer position. Hover is derived from it against the
    /// row's layout at render, never stored as a button index.
    pub pointer: Option<ratatui::layout::Position>,
    disabled_reasons: Vec<Option<&'static str>>,
}

pub(super) fn finish_help_row<'a>(
    cx: &super::SettingsCx,
    actions: Vec<SettingsHelpAction<'a>>,
) -> SettingsHelpRow<'a> {
    SettingsHelpRow {
        disabled_reasons: vec![None; actions.len()],
        actions,
        pointer: cx.pointer_surface.help_row_pointer.get(),
    }
}

impl<'a> SettingsHelpRow<'a> {
    /// Attach the domain reason for a disabled action without forcing every
    /// always-enabled ActionBar call site to carry redundant metadata.
    pub(super) fn with_disabled_reason(
        mut self,
        index: usize,
        disabled_reason: Option<&'static str>,
    ) -> Self {
        if let Some(reason) = self.disabled_reasons.get_mut(index) {
            *reason = disabled_reason;
        }
        self
    }

    pub(super) fn disabled_reason(&self, index: usize) -> Option<&'static str> {
        if self
            .actions
            .get(index)
            .is_some_and(|action| !action.enabled)
        {
            self.disabled_reasons
                .get(index)
                .copied()
                .flatten()
                .or(Some("action unavailable"))
        } else {
            None
        }
    }
}

pub(super) fn render_settings_help_row(
    frame: &mut Frame,
    area: Rect,
    help: &str,
    row: &SettingsHelpRow<'_>,
) -> Vec<Rect> {
    let buttons: Vec<crate::tui::chrome::ActionButton<'_>> = row
        .actions
        .iter()
        .map(|action| crate::tui::chrome::ActionButton {
            label: action.label,
            enabled: action.enabled,
            primary: action.primary,
        })
        .collect();
    let bar_width = if buttons.is_empty() {
        0
    } else {
        crate::tui::chrome::action_bar_width(&buttons)
    };
    let help_width = area.width.saturating_sub(bar_width.saturating_add(1));
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            help.to_string(),
            Style::default().fg(resolve_color(FOG, FOG_INDEX)),
        ))),
        Rect {
            x: area.x,
            y: area.y,
            width: help_width,
            height: 1,
        },
    );
    if buttons.is_empty() {
        Vec::new()
    } else {
        let layout = crate::tui::chrome::action_bar_layout(area, &buttons);
        let hover = row
            .pointer
            .and_then(|pos| crate::tui::chrome::action_button_at(&layout, pos))
            .filter(|index| buttons[*index].enabled);
        crate::tui::chrome::render_action_bar(frame, area, &buttons, hover)
    }
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
    /// Last pointer position seen over the settings surface; the help row
    /// derives its hover from it each frame.
    pub help_row_pointer: std::cell::Cell<Option<ratatui::layout::Position>>,
    /// Whether this surface owns the pointer this frame (the app clears it
    /// while an app-level overlay sits on top).
    pub pointer_owned: std::cell::Cell<bool>,
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
            help_row_pointer: std::cell::Cell::new(None),
            pointer_owned: std::cell::Cell::new(true),
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
        let view_h = usize::from(area.height);
        let content = crate::tui::chrome::scrollbar_content(area);
        frame.render_stateful_widget(
            List::new(items)
                .scroll_padding(1)
                .highlight_style(crate::tui::chrome::selection_style()),
            content,
            state,
        );
        crate::tui::chrome::scrollbar(frame, area, item_count, view_h, state.offset());
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

    fn help_row_hover_cells(width: u16, pointer: Option<ratatui::layout::Position>) -> Vec<u16> {
        let row = SettingsHelpRow {
            actions: vec![SettingsHelpAction {
                label: "Save",
                enabled: true,
                primary: true,
                action: super::super::pointer_actions::SettingsPointerAction::Root(
                    super::super::pointer_actions::RootAction::Open(
                        super::super::pointer_actions::RootNodeId::Interface,
                    ),
                ),
            }],
            pointer,
            disabled_reasons: vec![None],
        };
        let mut terminal = Terminal::new(TestBackend::new(width, 1)).unwrap();
        terminal
            .draw(|frame| {
                render_settings_help_row(frame, frame.area(), "help", &row);
            })
            .unwrap();
        let buffer = terminal.backend().buffer();
        (0..width)
            .filter(|x| buffer[(*x, 0)].bg != ratatui::style::Color::Reset)
            .collect()
    }

    #[test]
    fn help_row_hover_is_derived_from_the_pointer_against_this_frames_layout() {
        // "[ Save ]" is right-aligned: x 32..40 in a 40-cell row.
        let over_save = ratatui::layout::Position::new(34, 0);
        assert_eq!(
            help_row_hover_cells(40, Some(over_save)),
            (32..40).collect::<Vec<_>>()
        );
        // Wider row: the button moved away from the unchanged pointer.
        assert!(help_row_hover_cells(60, Some(over_save)).is_empty());
        assert!(help_row_hover_cells(40, None).is_empty());
    }

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
