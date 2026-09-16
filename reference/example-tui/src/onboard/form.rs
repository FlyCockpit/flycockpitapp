//! Fullscreen first-run form: pick a provider from the catalog.
//!
//! Search is a real input — the terminal cursor sits in the filter field.
//! The list is a ratatui [`List`] with a scrollbar when it overflows.
//! [`ListState`] owns only the viewport offset so the wheel can scroll
//! without moving the selected provider. The scrollbar is drawn by hand
//! (see [`thumb_span`]) and its click and drag are hit-tested here and
//! mapped onto that offset.

use std::io::Stdout;

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use ratatui::Frame;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout, Margin, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap,
};

use super::chrome;
use super::providers::{PROVIDERS, Provider};

/// Warm instrument-panel colours. Independent of the fly-in palette on
/// purpose — this crate is allowed to look like a different object.
const INK: Color = Color::Rgb(0xF4, 0xEF, 0xE6);
const FOG: Color = Color::Rgb(0x8A, 0x9B, 0xB0);
const BRASS: Color = Color::Rgb(0xE0, 0xB1, 0x56);
const NIGHT: Color = Color::Rgb(0x4A, 0x5A, 0x6A);
const PLACEHOLDER: Color = Color::Rgb(0x6A, 0x7A, 0x8A);

const SEARCH_PROMPT: &str = "/  ";
const HIGHLIGHT: &str = "▸ ";
const HOVER_BG: Color = Color::Rgb(0x2C, 0x38, 0x46);

const SCROLL_TRACK: &str = "│";
const SCROLL_THUMB: &str = "█";
/// Thumb colour while the pointer is dragging it.
const THUMB_DRAG: Color = INK;

/// How the provider form finished. `Back` returns to the previous wizard step
/// (the secrets screen); `Quit` exits onboarding entirely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Outcome {
    Chosen(&'static Provider),
    Back,
    Quit,
}

pub(super) fn run(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<Outcome> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

fn run_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<Outcome> {
    let mut picker = ProviderPicker::new();
    loop {
        terminal.draw(|frame| picker.render(frame, frame.area()))?;
        match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                match picker.handle_key(key) {
                    FormAction::Continue => {}
                    FormAction::Quit => return Ok(Outcome::Quit),
                    FormAction::Back => return Ok(Outcome::Back),
                    FormAction::Chosen(provider) => return Ok(Outcome::Chosen(provider)),
                }
            }
            Event::Mouse(mouse) => match picker.handle_mouse(mouse) {
                FormAction::Continue => {}
                FormAction::Quit => return Ok(Outcome::Quit),
                FormAction::Back => return Ok(Outcome::Back),
                FormAction::Chosen(provider) => return Ok(Outcome::Chosen(provider)),
            },
            Event::Paste(text) => picker.paste(&text),
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FormAction {
    Continue,
    Quit,
    Back,
    Chosen(&'static Provider),
}

struct SearchField {
    buffer: String,
    /// Byte index into [`Self::buffer`]. Always on a char boundary.
    cursor: usize,
}

impl SearchField {
    fn new() -> Self {
        Self {
            buffer: String::new(),
            cursor: 0,
        }
    }

    fn text(&self) -> &str {
        &self.buffer
    }

    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn cursor_col(&self) -> usize {
        self.buffer[..self.cursor].chars().count()
    }

    fn insert(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    fn paste(&mut self, text: &str) {
        let first_line = text.split('\n').next().unwrap_or("");
        if first_line.is_empty() {
            return;
        }
        self.buffer.insert_str(self.cursor, first_line);
        self.cursor += first_line.len();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.buffer[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.buffer.drain(prev..self.cursor);
        self.cursor = prev;
    }

    fn delete(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        let len = self.buffer[self.cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        self.buffer.drain(self.cursor..self.cursor + len);
    }

    fn left(&mut self) {
        if let Some((i, _)) = self.buffer[..self.cursor].char_indices().next_back() {
            self.cursor = i;
        }
    }

    fn right(&mut self) {
        if let Some(ch) = self.buffer[self.cursor..].chars().next() {
            self.cursor += ch.len_utf8();
        }
    }

    fn home(&mut self) {
        self.cursor = 0;
    }

    fn end(&mut self) {
        self.cursor = self.buffer.len();
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    fn delete_word(&mut self) {
        let before = &self.buffer[..self.cursor];
        let without_trail = before.trim_end_matches(|c: char| !c.is_alphanumeric());
        let cut = without_trail.trim_end_matches(char::is_alphanumeric).len();
        self.buffer.replace_range(cut..self.cursor, "");
        self.cursor = cut;
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(ch)
                if key.modifiers.intersects(
                    KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER,
                ) =>
            {
                match ch {
                    'u' | 'U' if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.clear();
                        true
                    }
                    'w' | 'W' if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        self.delete_word();
                        true
                    }
                    _ => false,
                }
            }
            KeyCode::Char(ch) => {
                self.insert(ch);
                true
            }
            KeyCode::Backspace => {
                self.backspace();
                true
            }
            KeyCode::Delete => {
                self.delete();
                true
            }
            KeyCode::Left => {
                self.left();
                true
            }
            KeyCode::Right => {
                self.right();
                true
            }
            KeyCode::Home => {
                self.home();
                true
            }
            KeyCode::End => {
                self.end();
                true
            }
            _ => false,
        }
    }
}

struct ProviderPicker {
    query: SearchField,
    /// Keyboard/click selection. Independent of the list viewport so a
    /// wheel or scrollbar drag can pan without stealing the choice.
    selected: Option<usize>,
    /// Viewport only — `selected` stays `None` so [`List`] honors offset.
    list: ListState,
    /// Row under the pointer, if the pointer is inside the provider list.
    hover: Option<usize>,
    pointer: Option<Position>,
    /// Inner list body from the last draw, used for hit-testing.
    list_area: Rect,
    scrollbar_area: Option<Rect>,
    dragging_scrollbar: bool,
    /// Inner height of the list the last time we drew, for PageUp/PageDown.
    last_view_h: u16,
    /// Top-left back button rect from the last draw, and whether it is hovered.
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl ProviderPicker {
    fn new() -> Self {
        Self {
            query: SearchField::new(),
            selected: Some(0),
            list: ListState::default(),
            hover: None,
            pointer: None,
            list_area: Rect::default(),
            scrollbar_area: None,
            dragging_scrollbar: false,
            last_view_h: 8,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    fn matches(&self) -> Vec<&'static Provider> {
        PROVIDERS
            .iter()
            .filter(|provider| provider.matches(self.query.text()))
            .collect()
    }

    fn selected(&self) -> Option<&'static Provider> {
        let matches = self.matches();
        self.selected.and_then(|index| matches.get(index).copied())
    }

    fn view_h(&self) -> usize {
        usize::from(self.last_view_h.max(1))
    }

    fn max_offset(&self) -> usize {
        self.matches().len().saturating_sub(self.view_h())
    }

    fn set_offset(&mut self, offset: usize) {
        *self.list.offset_mut() = offset.min(self.max_offset());
        self.refresh_hover();
    }

    fn scroll_by(&mut self, delta: isize) {
        let next = (self.list.offset() as isize + delta).clamp(0, self.max_offset() as isize);
        self.set_offset(next as usize);
    }

    fn over_scrollable(&self, pos: Position) -> bool {
        self.list_area.contains(pos) || self.scrollbar_area.is_some_and(|area| area.contains(pos))
    }

    fn set_offset_from_scrollbar_y(&mut self, y: u16) {
        let Some(area) = self.scrollbar_area else {
            return;
        };
        if area.height <= 1 {
            self.set_offset(0);
            return;
        }
        let rel = y.saturating_sub(area.y).min(area.height.saturating_sub(1));
        let max_offset = self.max_offset();
        let offset = usize::from(rel) * max_offset / usize::from(area.height.saturating_sub(1));
        self.set_offset(offset);
    }

    fn ensure_selected_visible(&mut self) {
        let Some(selected) = self.selected else {
            return;
        };
        let view_h = self.view_h();
        let offset = self.list.offset();
        if selected < offset {
            self.set_offset(selected);
        } else if selected >= offset.saturating_add(view_h) {
            self.set_offset(selected.saturating_add(1).saturating_sub(view_h));
        }
    }

    fn retarget(&mut self, keep: Option<&str>) {
        let matches = self.matches();
        if matches.is_empty() {
            self.selected = None;
            self.set_offset(0);
            return;
        }
        let index = keep
            .and_then(|id| matches.iter().position(|provider| provider.id == id))
            .unwrap_or(0);
        self.selected = Some(index);
        self.ensure_selected_visible();
        self.refresh_hover();
    }

    fn index_at(&self, pos: Position) -> Option<usize> {
        if !self.list_area.contains(pos) {
            return None;
        }
        let row = usize::from(pos.y.saturating_sub(self.list_area.y));
        let index = self.list.offset() + row;
        (index < self.matches().len()).then_some(index)
    }

    fn refresh_hover(&mut self) {
        self.hover = self.pointer.and_then(|pos| self.index_at(pos));
    }

    fn move_by(&mut self, delta: isize) {
        let n = self.matches().len();
        if n == 0 {
            self.selected = None;
            return;
        }
        let current = self.selected.unwrap_or(0).min(n - 1);
        let next = (current as isize + delta).rem_euclid(n as isize) as usize;
        self.selected = Some(next);
        self.ensure_selected_visible();
    }

    fn page(&mut self, down: bool) {
        let n = self.matches().len();
        if n == 0 {
            self.selected = None;
            return;
        }
        let step = self.view_h();
        let current = self.selected.unwrap_or(0).min(n - 1);
        let next = if down {
            (current + step).min(n - 1)
        } else {
            current.saturating_sub(step)
        };
        self.selected = Some(next);
        self.ensure_selected_visible();
    }

    fn paste(&mut self, text: &str) {
        let keep = self.selected().map(|provider| provider.id);
        self.query.paste(text);
        self.retarget(keep);
    }

    fn handle_key(&mut self, key: KeyEvent) -> FormAction {
        let abort = key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'));
        if abort {
            return FormAction::Quit;
        }
        // Esc steps back to the previous wizard screen rather than exiting.
        if key.code == KeyCode::Esc {
            return FormAction::Back;
        }
        match key.code {
            KeyCode::Enter => {
                if let Some(provider) = self.selected() {
                    FormAction::Chosen(provider)
                } else {
                    FormAction::Continue
                }
            }
            KeyCode::Up => {
                self.move_by(-1);
                FormAction::Continue
            }
            KeyCode::Down | KeyCode::Tab => {
                self.move_by(1);
                FormAction::Continue
            }
            KeyCode::BackTab => {
                self.move_by(-1);
                FormAction::Continue
            }
            KeyCode::PageUp => {
                self.page(false);
                FormAction::Continue
            }
            KeyCode::PageDown => {
                self.page(true);
                FormAction::Continue
            }
            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.move_by(1);
                FormAction::Continue
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.move_by(-1);
                FormAction::Continue
            }
            _ => {
                let keep = self.selected().map(|provider| provider.id);
                if self.query.handle_key(key) {
                    self.retarget(keep);
                }
                FormAction::Continue
            }
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> FormAction {
        let pos = Position::new(event.column, event.row);
        self.pointer = Some(pos);
        self.back_hover = chrome::hit(self.back_rect, pos);
        self.actions.track(pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return FormAction::Back;
        }
        // The "Choose" button confirms the highlighted provider.
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && self.actions.clicked(pos).is_some()
            && let Some(provider) = self.selected()
        {
            return FormAction::Chosen(provider);
        }
        match event.kind {
            MouseEventKind::ScrollDown if self.over_scrollable(pos) => {
                self.scroll_by(1);
                FormAction::Continue
            }
            MouseEventKind::ScrollUp if self.over_scrollable(pos) => {
                self.scroll_by(-1);
                FormAction::Continue
            }
            MouseEventKind::Down(MouseButton::Left)
                if self.scrollbar_area.is_some_and(|area| area.contains(pos)) =>
            {
                self.dragging_scrollbar = true;
                self.set_offset_from_scrollbar_y(pos.y);
                FormAction::Continue
            }
            MouseEventKind::Down(MouseButton::Left) => {
                self.dragging_scrollbar = false;
                if let Some(index) = self.index_at(pos) {
                    // A second click on the already-selected row chooses it.
                    if self.selected == Some(index)
                        && let Some(provider) = self.selected()
                    {
                        return FormAction::Chosen(provider);
                    }
                    self.selected = Some(index);
                    self.hover = Some(index);
                }
                FormAction::Continue
            }
            MouseEventKind::Drag(_) if self.dragging_scrollbar => {
                self.set_offset_from_scrollbar_y(pos.y);
                FormAction::Continue
            }
            MouseEventKind::Up(_) => {
                self.dragging_scrollbar = false;
                self.refresh_hover();
                FormAction::Continue
            }
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.refresh_hover();
                FormAction::Continue
            }
            _ => {
                self.refresh_hover();
                FormAction::Continue
            }
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = column(area);
        let layout = Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(4),
            Constraint::Length(1),
        ]);
        let [header, search, _, list, detail, help] = col.layout(&layout);

        render_header(frame, header);
        self.render_search(frame, search);
        self.render_list(frame, list);
        self.render_detail(frame, detail);
        render_help(frame, help);
        let can_choose = self.selected().is_some();
        self.actions.render(
            frame,
            help,
            &[chrome::Button::primary("Choose").enabled(can_choose)],
        );
    }

    fn render_search(&self, frame: &mut Frame, area: Rect) {
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(BRASS))
            .title(Span::styled(" Filter ", Style::new().fg(BRASS)))
            .padding(Padding::horizontal(1));
        let inner = block.inner(area);
        frame.render_widget(&block, area);

        let prompt_w = SEARCH_PROMPT.chars().count();
        let avail = usize::from(inner.width.saturating_sub(prompt_w as u16));
        let cursor_col = self.query.cursor_col();
        let scroll = cursor_col.saturating_sub(avail.saturating_sub(1));
        let visible: String = self.query.text().chars().skip(scroll).take(avail).collect();

        let mut spans = vec![Span::styled(SEARCH_PROMPT, Style::new().fg(BRASS))];
        if self.query.is_empty() {
            spans.push(Span::styled(
                "filter by name",
                Style::new().fg(PLACEHOLDER).add_modifier(Modifier::ITALIC),
            ));
        } else {
            spans.push(Span::styled(visible, Style::new().fg(INK)));
        }
        frame.render_widget(Paragraph::new(Line::from(spans)), inner);

        if inner.width > 0 && inner.height > 0 {
            let col =
                (prompt_w + cursor_col - scroll).min(usize::from(inner.width.saturating_sub(1)));
            frame.set_cursor_position(Position::new(inner.x + col as u16, inner.y));
        }
    }

    fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let matches = self.matches();
        let total = PROVIDERS.len();
        let title = if matches.len() == total {
            format!(" Providers  ·  {total} ")
        } else {
            format!(" Providers  ·  {} of {total} ", matches.len())
        };
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(title, Style::new().fg(INK)));
        let inner = block.inner(area);
        frame.render_widget(&block, area);

        if matches.is_empty() {
            self.list_area = inner;
            self.scrollbar_area = None;
            self.hover = None;
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "Nothing matches that filter.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                ))
                .centered(),
                inner,
            );
            return;
        }

        let overflow = matches.len() > usize::from(inner.height);
        let (list_area, scrollbar_area) = if overflow && inner.width >= 2 {
            let [items, scrollbar] = inner.layout(&Layout::horizontal([
                Constraint::Min(0),
                Constraint::Length(1),
            ]));
            (items, Some(scrollbar))
        } else {
            (inner, None)
        };
        self.last_view_h = list_area.height;
        self.list_area = list_area;
        self.scrollbar_area = scrollbar_area;
        let max_offset = matches.len().saturating_sub(self.view_h());
        *self.list.offset_mut() = self.list.offset().min(max_offset);
        self.refresh_hover();

        let row_width = usize::from(list_area.width);
        let selected = self.selected;
        let hover = self.hover;
        let items: Vec<ListItem> = matches
            .iter()
            .enumerate()
            .map(|(index, provider)| {
                let mut item =
                    ListItem::new(provider_row(provider, row_width, selected == Some(index)));
                if hover == Some(index) {
                    item = item.style(Style::new().bg(HOVER_BG));
                }
                item
            })
            .collect();
        // `ListState.selected` stays None so the widget honors our offset
        // instead of yanking the viewport back to the chosen provider.
        frame.render_stateful_widget(List::new(items), list_area, &mut self.list);

        if let Some(scrollbar_area) = scrollbar_area {
            self.render_scrollbar(frame, scrollbar_area, matches.len());
        }
    }

    /// Ratatui's `Scrollbar` rounds a proportional thumb onto the last
    /// track cell one step before the final row scrolls into view, so the
    /// bar is painted by hand from [`thumb_span`] instead. The thumb
    /// brightens while it is being dragged.
    fn render_scrollbar(&self, frame: &mut Frame, area: Rect, total: usize) {
        let track = usize::from(area.height);
        let (start, len) = thumb_span(track, total, self.view_h(), self.list.offset());
        let thumb_fg = if self.dragging_scrollbar {
            THUMB_DRAG
        } else {
            BRASS
        };
        let thumb_style = Style::new().fg(thumb_fg);
        let track_style = Style::new().fg(NIGHT);
        let buf = frame.buffer_mut();
        for row in 0..track {
            let (symbol, style) = if (start..start + len).contains(&row) {
                (SCROLL_THUMB, thumb_style)
            } else {
                (SCROLL_TRACK, track_style)
            };
            buf.set_string(area.x, area.y + row as u16, symbol, style);
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let Some(provider) = self.selected() else {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "Type a few letters to narrow the list.",
                    Style::new().fg(FOG),
                )),
                area,
            );
            return;
        };
        let lines = vec![
            Line::from(vec![
                Span::styled(provider.kind.label(), Style::new().fg(BRASS)),
                Span::styled("  ·  ", Style::new().fg(NIGHT)),
                Span::styled(provider.id, Style::new().fg(FOG)),
            ]),
            Line::from(Span::styled(provider.hint, Style::new().fg(FOG))),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }
}

fn render_header(frame: &mut Frame, area: Rect) {
    let rule = "─".repeat(28.min(usize::from(area.width)));
    let lines = vec![
        Line::from(Span::styled(
            "Let's add a provider",
            Style::new().fg(INK).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "Pick who you'll fly with.",
            Style::new().fg(FOG),
        )),
        Line::from(Span::styled(rule, Style::new().fg(BRASS))),
    ];
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_help(frame: &mut Frame, area: Rect) {
    frame.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "type to filter   ↑↓ move   click select · dbl-click choose   enter choose   esc back",
            Style::new().fg(FOG),
        ))),
        area,
    );
}

fn provider_row(provider: &Provider, width: usize, selected: bool) -> Line<'static> {
    let prefix = if selected { HIGHLIGHT } else { "  " };
    let label = provider.display;
    let id = provider.id;
    let used = prefix.chars().count() + label.chars().count() + 1 + id.chars().count();
    let pad = width.saturating_sub(used).max(1);
    let label_style = if selected {
        Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
    } else {
        Style::new().fg(INK)
    };
    Line::from(vec![
        Span::styled(
            prefix,
            if selected {
                Style::new().fg(BRASS)
            } else {
                Style::new().fg(FOG)
            },
        ),
        Span::styled(label.to_string(), label_style),
        Span::raw(" ".repeat(pad)),
        Span::styled(id.to_string(), Style::new().fg(FOG)),
    ])
}

/// Centre a readable column on the screen. Wide terminals get a card, not
/// a stretched spreadsheet.
/// Where the thumb sits on a `track`-cell scrollbar for `total` rows with
/// `view_h` visible at `offset`. Returns `(start, length)` in track cells.
///
/// Length is the visible fraction of the list, so a taller viewport means a
/// fatter thumb. Start uses floor division over the thumb's travel, so the
/// thumb touches the bottom cell only at the maximum offset — ratatui's
/// widget rounds and gets there one step early.
fn thumb_span(track: usize, total: usize, view_h: usize, offset: usize) -> (usize, usize) {
    if track == 0 {
        return (0, 0);
    }
    let max_offset = total.saturating_sub(view_h);
    if max_offset == 0 {
        return (0, track);
    }
    // Nearest cell, but always leave at least one cell of travel.
    let len = ((track * view_h + total / 2) / total).clamp(1, track.saturating_sub(1).max(1));
    let travel = track - len;
    let start = offset.min(max_offset) * travel / max_offset;
    (start, len)
}

fn column(area: Rect) -> Rect {
    area.inner(Margin::new(2, 1))
        .centered(Constraint::Max(86), Constraint::Fill(1))
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Position;

    use super::*;

    fn mouse(kind: MouseEventKind, pos: Position) -> MouseEvent {
        MouseEvent {
            kind,
            column: pos.x,
            row: pos.y,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn type_text(picker: &mut ProviderPicker, text: &str) {
        for ch in text.chars() {
            picker.handle_key(key(KeyCode::Char(ch)));
        }
    }

    fn draw(picker: &mut ProviderPicker, width: u16, height: u16) -> (TestBackend, Position, bool) {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| picker.render(frame, frame.area()))
            .unwrap();
        let pos = terminal.get_cursor_position().unwrap();
        let visible = terminal.backend().cursor_visible();
        (terminal.backend().clone(), pos, visible)
    }

    fn screen(backend: &TestBackend) -> String {
        let buf = backend.buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            for x in 0..buf.area.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn empty_filter_lists_every_provider() {
        let picker = ProviderPicker::new();
        assert_eq!(picker.matches().len(), PROVIDERS.len());
        assert_eq!(picker.selected().unwrap().id, "codex-oauth");
    }

    #[test]
    fn typing_filters_and_keeps_a_still_visible_selection() {
        let mut picker = ProviderPicker::new();
        picker.handle_key(key(KeyCode::Down));
        picker.handle_key(key(KeyCode::Down));
        assert_eq!(picker.selected().unwrap().id, "copilot");
        type_text(&mut picker, "git");
        assert_eq!(
            picker.matches().iter().map(|p| p.id).collect::<Vec<_>>(),
            ["copilot"]
        );
        assert_eq!(picker.selected().unwrap().id, "copilot");
    }

    #[test]
    fn filter_drops_to_the_first_match_when_the_selection_disappears() {
        let mut picker = ProviderPicker::new();
        assert_eq!(picker.selected().unwrap().id, "codex-oauth");
        type_text(&mut picker, "anthropic");
        let ids: Vec<_> = picker.matches().iter().map(|p| p.id).collect();
        assert_eq!(ids, ["anthropic"]);
        assert_eq!(picker.selected().unwrap().id, "anthropic");
    }

    #[test]
    fn wrapping_moves_off_the_ends() {
        let mut picker = ProviderPicker::new();
        picker.handle_key(key(KeyCode::Up));
        assert_eq!(picker.selected().unwrap().id, PROVIDERS.last().unwrap().id);
        picker.handle_key(key(KeyCode::Down));
        assert_eq!(picker.selected().unwrap().id, PROVIDERS[0].id);
    }

    #[test]
    fn enter_chooses_the_highlighted_provider() {
        let mut picker = ProviderPicker::new();
        type_text(&mut picker, "deep");
        assert_eq!(
            picker.handle_key(key(KeyCode::Enter)),
            FormAction::Chosen(PROVIDERS.iter().find(|p| p.id == "deepseek").unwrap())
        );
    }

    #[test]
    fn esc_goes_back_and_ctrl_c_quits() {
        let mut picker = ProviderPicker::new();
        assert_eq!(picker.handle_key(key(KeyCode::Esc)), FormAction::Back);
        let mut ctrl_c = key(KeyCode::Char('c'));
        ctrl_c.modifiers = KeyModifiers::CONTROL;
        assert_eq!(picker.handle_key(ctrl_c), FormAction::Quit);
    }

    #[test]
    fn clicking_the_back_button_steps_back() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        assert!(picker.back_rect.width > 0, "back button should be drawn");
        let pos = Position::new(picker.back_rect.x, picker.back_rect.y);
        assert_eq!(
            picker.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            FormAction::Back
        );
    }

    #[test]
    fn back_button_renders_top_left() {
        let mut picker = ProviderPicker::new();
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("‹ Back"), "expected a back button: {text}");
    }

    fn find(backend: &TestBackend, needle: &str) -> Position {
        let buf = backend.buffer();
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            if let Some(col) = row.find(needle) {
                return Position::new(col as u16, y);
            }
        }
        panic!("{needle:?} not found on screen");
    }

    #[test]
    fn clicking_the_choose_button_chooses_the_selection() {
        let mut picker = ProviderPicker::new();
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let pos = find(&backend, "[ Choose ]");
        assert_eq!(
            picker.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            FormAction::Chosen(&PROVIDERS[0])
        );
    }

    #[test]
    fn a_second_click_on_the_selected_row_chooses_it() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let area = picker.list_area;
        // Row 1 is not selected: first click selects, second chooses.
        let pos = Position::new(area.x, area.y + 1);
        assert_eq!(
            picker.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            FormAction::Continue
        );
        assert_eq!(picker.selected, Some(1));
        assert_eq!(
            picker.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            FormAction::Chosen(&PROVIDERS[1])
        );
    }

    #[test]
    fn q_types_into_the_filter_instead_of_quitting() {
        let mut picker = ProviderPicker::new();
        picker.handle_key(key(KeyCode::Char('q')));
        assert_eq!(picker.query.text(), "q");
        assert_ne!(picker.handle_key(key(KeyCode::Char('q'))), FormAction::Quit);
    }

    #[test]
    fn no_matches_clears_the_selection() {
        let mut picker = ProviderPicker::new();
        type_text(&mut picker, "zzzz-nope");
        assert!(picker.matches().is_empty());
        assert!(picker.selected().is_none());
        assert_eq!(picker.handle_key(key(KeyCode::Enter)), FormAction::Continue);
    }

    #[test]
    fn fullscreen_card_uses_native_widgets_and_cursor() {
        let mut picker = ProviderPicker::new();
        let (backend, pos, visible) = draw(&mut picker, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("Let's add a provider"), "{text}");
        assert!(text.contains("Pick who you'll fly with."), "{text}");
        assert!(text.contains("Filter"), "{text}");
        assert!(text.contains("Codex (ChatGPT Plus/Pro)"), "{text}");
        assert!(text.contains("codex-oauth"), "{text}");
        assert!(text.contains("type to filter"), "{text}");
        assert!(
            visible,
            "the terminal cursor must be shown in the search field"
        );
        // Prompt is "/  " inside a rounded, padded filter box. The column is
        // centred; y sits on the filter's inner row.
        assert!(
            pos.x > 0,
            "cursor should sit after the filter prompt, got {pos:?}"
        );
        assert!(
            pos.y > 0,
            "cursor should sit in the filter row, got {pos:?}"
        );
    }

    #[test]
    fn typing_advances_the_native_cursor() {
        let mut picker = ProviderPicker::new();
        let (_, empty, _) = draw(&mut picker, 80, 24);
        type_text(&mut picker, "grok");
        let (backend, typed, visible) = draw(&mut picker, 80, 24);
        let text = screen(&backend);
        assert!(text.contains("Grok (xAI API)"), "{text}");
        assert!(text.contains("Grok (SuperGrok)"), "{text}");
        assert!(!text.contains("DeepSeek"), "{text}");
        assert!(visible);
        assert_eq!(typed.y, empty.y);
        assert_eq!(typed.x, empty.x + 4);
    }

    #[test]
    fn backspace_moves_the_native_cursor_back() {
        let mut picker = ProviderPicker::new();
        type_text(&mut picker, "ab");
        let (_, two, _) = draw(&mut picker, 80, 24);
        picker.handle_key(key(KeyCode::Backspace));
        let (_, one, _) = draw(&mut picker, 80, 24);
        assert_eq!(one.x + 1, two.x);
    }

    #[test]
    fn mouse_hover_tracks_the_row_under_the_pointer() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let area = picker.list_area;
        assert!(
            area.height > 2,
            "list should show several rows, got {area:?}"
        );
        picker.handle_mouse(mouse(
            MouseEventKind::Moved,
            Position::new(area.x, area.y + 2),
        ));
        assert_eq!(picker.hover, Some(2));
        assert_eq!(picker.selected, Some(0), "hover is not selection");
    }

    #[test]
    fn mouse_hover_clears_when_leaving_the_list() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let area = picker.list_area;
        picker.handle_mouse(mouse(MouseEventKind::Moved, Position::new(area.x, area.y)));
        assert_eq!(picker.hover, Some(0));
        picker.handle_mouse(mouse(MouseEventKind::Moved, Position::ORIGIN));
        assert_eq!(picker.hover, None);
    }

    #[test]
    fn mouse_hover_paints_a_background_on_the_row() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let area = picker.list_area;
        picker.handle_mouse(mouse(
            MouseEventKind::Moved,
            Position::new(area.x, area.y + 2),
        ));
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let cell = &backend.buffer()[(area.x, area.y + 2)];
        assert_eq!(cell.bg, HOVER_BG);
        let selected = &backend.buffer()[(area.x, area.y)];
        assert_ne!(
            selected.bg, HOVER_BG,
            "the selected row should not pick up hover from another row"
        );
    }

    #[test]
    fn mouse_scroll_moves_the_viewport_not_the_selection() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let area = picker.list_area;
        assert!(picker.max_offset() > 0, "the 80x24 list should overflow");
        picker.handle_mouse(mouse(
            MouseEventKind::ScrollDown,
            Position::new(area.x, area.y),
        ));
        assert_eq!(picker.list.offset(), 1);
        assert_eq!(picker.selected, Some(0));
        picker.handle_mouse(mouse(
            MouseEventKind::ScrollUp,
            Position::new(area.x, area.y),
        ));
        assert_eq!(picker.list.offset(), 0);
        assert_eq!(picker.selected, Some(0));
    }

    #[test]
    fn mouse_scroll_outside_the_provider_box_is_ignored() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        picker.handle_mouse(mouse(MouseEventKind::ScrollDown, Position::ORIGIN));
        assert_eq!(picker.list.offset(), 0);
        assert_eq!(picker.selected, Some(0));
    }

    #[test]
    fn mouse_click_selects_the_hovered_provider() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let area = picker.list_area;
        let pos = Position::new(area.x, area.y + 3);
        picker.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos));
        assert_eq!(picker.selected, Some(3));
        assert_eq!(picker.hover, Some(3));
    }

    #[test]
    fn clicking_the_scrollbar_jumps_the_viewport_without_changing_selection() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let bar = picker
            .scrollbar_area
            .expect("overflowing list should grow a scrollbar");
        picker.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            Position::new(bar.x, bar.bottom().saturating_sub(1)),
        ));
        assert_eq!(picker.list.offset(), picker.max_offset());
        assert_eq!(picker.selected, Some(0));
    }

    #[test]
    fn dragging_the_scrollbar_pans_the_list() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let bar = picker.scrollbar_area.expect("scrollbar");
        picker.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            Position::new(bar.x, bar.y),
        ));
        assert_eq!(picker.list.offset(), 0);
        picker.handle_mouse(mouse(
            MouseEventKind::Drag(MouseButton::Left),
            Position::new(bar.x, bar.bottom().saturating_sub(1)),
        ));
        assert_eq!(picker.list.offset(), picker.max_offset());
        assert_eq!(picker.selected, Some(0));
    }

    #[test]
    fn scrollbar_thumb_reaches_the_bottom_at_max_offset() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let bar = picker.scrollbar_area.expect("scrollbar");
        picker.set_offset(picker.max_offset());
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let last = &backend.buffer()[(bar.x, bar.bottom().saturating_sub(1))];
        assert_eq!(
            last.symbol(),
            "█",
            "thumb should sit on the last scrollbar row, got {last:?}"
        );
    }

    fn scrollbar_cell(backend: &TestBackend, bar: Rect, y: u16) -> String {
        backend.buffer()[(bar.x, y)].symbol().to_string()
    }

    fn thumb_rows(backend: &TestBackend, bar: Rect) -> Vec<u16> {
        (bar.y..bar.bottom())
            .filter(|&y| scrollbar_cell(backend, bar, y) == SCROLL_THUMB)
            .collect()
    }

    #[test]
    fn thumb_span_is_proportional_and_bottoms_out_only_at_max_offset() {
        // 16 rows, 8 visible, 8-cell track: half the list is on screen.
        assert_eq!(thumb_span(8, 16, 8, 0), (0, 4));
        assert_eq!(thumb_span(8, 16, 8, 4), (2, 4));
        assert_eq!(
            thumb_span(8, 16, 8, 7),
            (3, 4),
            "one short of max stays off the bottom"
        );
        assert_eq!(
            thumb_span(8, 16, 8, 8),
            (4, 4),
            "max offset touches the bottom"
        );
        assert_eq!(thumb_span(8, 16, 8, 99), (4, 4), "offset is clamped");
        // Nothing to scroll: the thumb fills the track.
        assert_eq!(thumb_span(8, 8, 8, 0), (0, 8));
        // A tiny track still leaves the thumb room to move.
        assert_eq!(thumb_span(2, 100, 99, 1), (1, 1));
        assert_eq!(thumb_span(0, 16, 8, 0), (0, 0));
    }

    #[test]
    fn scrollbar_thumb_is_sized_to_the_viewport() {
        let mut picker = ProviderPicker::new();
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let bar = picker.scrollbar_area.expect("scrollbar");
        let rows = thumb_rows(&backend, bar);
        assert!(
            rows.len() > 1 && rows.len() < usize::from(bar.height),
            "thumb should cover part of the track, got rows {rows:?} of {}",
            bar.height
        );
        let expected = thumb_span(usize::from(bar.height), PROVIDERS.len(), picker.view_h(), 0);
        assert_eq!(rows.len(), expected.1);
        assert_eq!(rows[0], bar.y);
        for pair in rows.windows(2) {
            assert_eq!(pair[1], pair[0] + 1, "thumb must be contiguous");
        }
    }

    #[test]
    fn scrollbar_thumb_brightens_while_dragging() {
        let mut picker = ProviderPicker::new();
        let _ = draw(&mut picker, 80, 24);
        let bar = picker.scrollbar_area.expect("scrollbar");
        let thumb_fg = |backend: &TestBackend, y: u16| backend.buffer()[(bar.x, y)].fg;

        let (backend, _, _) = draw(&mut picker, 80, 24);
        assert_eq!(thumb_fg(&backend, bar.y), BRASS);

        picker.handle_mouse(mouse(
            MouseEventKind::Down(MouseButton::Left),
            Position::new(bar.x, bar.y),
        ));
        let (backend, _, _) = draw(&mut picker, 80, 24);
        assert_eq!(thumb_fg(&backend, bar.y), THUMB_DRAG);

        picker.handle_mouse(mouse(
            MouseEventKind::Up(MouseButton::Left),
            Position::new(bar.x, bar.y),
        ));
        let (backend, _, _) = draw(&mut picker, 80, 24);
        assert_eq!(thumb_fg(&backend, bar.y), BRASS);
    }

    #[test]
    fn viewport_shows_first_item_at_top_and_last_item_at_bottom() {
        let mut picker = ProviderPicker::new();
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let bar = picker.scrollbar_area.expect("scrollbar");
        let top = screen(&backend);
        let last = PROVIDERS.last().unwrap();
        assert!(
            top.contains(PROVIDERS[0].display),
            "offset 0 should show the first provider, got {top}"
        );
        assert!(
            !top.contains(last.display),
            "offset 0 should not already show the last provider, got {top}"
        );
        assert_eq!(scrollbar_cell(&backend, bar, bar.y), "█");
        assert_ne!(
            scrollbar_cell(&backend, bar, bar.bottom().saturating_sub(1)),
            "█",
            "a top-of-list thumb must not already sit on the last row"
        );

        picker.set_offset(picker.max_offset().saturating_sub(1));
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let almost = screen(&backend);
        assert!(
            !almost.contains(last.display),
            "one step before the end must not yet show {}",
            last.display
        );
        assert_ne!(
            scrollbar_cell(&backend, bar, bar.bottom().saturating_sub(1)),
            "█",
            "the thumb must not sit on the last row before the last provider is visible"
        );

        picker.set_offset(picker.max_offset());
        let (backend, _, _) = draw(&mut picker, 80, 24);
        let bottom = screen(&backend);
        assert!(
            bottom.contains(last.display),
            "max offset {} view_h {} should show {}, got {bottom}",
            picker.list.offset(),
            picker.view_h(),
            last.display
        );
        assert!(
            !bottom.contains(PROVIDERS[0].display),
            "the first provider should have scrolled off, got {bottom}"
        );
        assert_eq!(
            scrollbar_cell(&backend, bar, bar.bottom().saturating_sub(1)),
            "█"
        );
        assert_ne!(
            scrollbar_cell(&backend, bar, bar.y),
            "█",
            "a bottom-of-list thumb must not still cover the first row"
        );
    }
}
