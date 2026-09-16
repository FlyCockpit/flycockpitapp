//! Reusable tool grant list, shared by the agent Tools phase and the subagent
//! editor.
//!
//! The whole catalog is shown at once, grouped required → suggested → not
//! suggested (headers don't take focus). Required tools are always on. A tool
//! that needs a model (say a vision model to describe images) can't be enabled
//! until one is picked — pressing space on it opens the model chooser, and the
//! chosen model shows inline.

use std::io::Stdout;

use anyhow::Result;
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use crossterm::execute;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};
use ratatui::{Terminal, backend::CrosstermBackend};

use super::super::chrome;
use super::ui::{self, BRASS, DISABLED, FOG, GOOD, HOVER_BG, INK, NIGHT, WARN};
use super::{AvailableModel, Nav, TOOLS, Tier, ToolGrant, ToolState};

/// One rendered row: a tier heading (unfocusable) or a tool (index into TOOLS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DisplayRow {
    Header(Tier),
    Tool(usize),
}

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
    tools: &mut [ToolState],
    title: &str,
    subtitle: &str,
) -> Result<Nav> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, catalog, tools, title, subtitle);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Stay,
    Next,
    Back,
    Quit,
    PickModel(usize),
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
    tools: &mut [ToolState],
    title: &str,
    subtitle: &str,
) -> Result<Nav> {
    let mut screen = Screen::new(title, subtitle);
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area(), catalog, tools))?;
        let act = match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                screen.handle_key(key, tools)
            }
            Event::Mouse(mouse) => screen.handle_mouse(mouse, tools),
            _ => Act::Stay,
        };
        match act {
            Act::Stay => {}
            Act::Next => return Ok(Nav::Next),
            Act::Back => return Ok(Nav::Back),
            Act::Quit => return Ok(Nav::Quit),
            Act::PickModel(index) => {
                let current = tools[index].model;
                match picker::run(terminal, catalog, current)? {
                    picker::Pick::Picked(model) => {
                        tools[index].model = Some(model);
                        tools[index].grant = ToolGrant::Enabled;
                        screen.flash =
                            Some("Switching a tool to enabled busts the prompt cache.".to_string());
                    }
                    picker::Pick::Cancel => {}
                    picker::Pick::Quit => return Ok(Nav::Quit),
                }
                execute!(terminal.backend_mut(), EnableMouseCapture)?;
            }
        }
    }
}

struct Screen {
    title: String,
    subtitle: String,
    display: Vec<DisplayRow>,
    cursor: usize, // index into `display`, always on a Tool row
    offset: usize,
    view_h: usize,
    hover: Option<usize>,
    row_rects: Vec<(Rect, usize)>, // (rect, display index) for visible rows
    list_area: Rect,
    scrollbar_area: Option<Rect>,
    flash: Option<String>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
    fn new(title: &str, subtitle: &str) -> Self {
        let mut display = Vec::new();
        let mut last: Option<Tier> = None;
        for (index, tool) in TOOLS.iter().enumerate() {
            if last != Some(tool.tier) {
                display.push(DisplayRow::Header(tool.tier));
                last = Some(tool.tier);
            }
            display.push(DisplayRow::Tool(index));
        }
        let cursor = display
            .iter()
            .position(|row| matches!(row, DisplayRow::Tool(_)))
            .unwrap_or(0);
        Self {
            title: title.to_string(),
            subtitle: subtitle.to_string(),
            display,
            cursor,
            offset: 0,
            view_h: 1,
            hover: None,
            row_rects: Vec::new(),
            list_area: Rect::default(),
            scrollbar_area: None,
            flash: None,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    fn tool_at(&self, display_index: usize) -> Option<usize> {
        match self.display.get(display_index) {
            Some(DisplayRow::Tool(index)) => Some(*index),
            _ => None,
        }
    }

    fn focused_tool(&self) -> Option<usize> {
        self.tool_at(self.cursor)
    }

    /// Move focus to the next/previous tool row, skipping headers and wrapping.
    fn move_focus(&mut self, down: bool) {
        let n = self.display.len();
        if n == 0 {
            return;
        }
        let mut i = self.cursor;
        for _ in 0..n {
            i = if down { (i + 1) % n } else { (i + n - 1) % n };
            if matches!(self.display[i], DisplayRow::Tool(_)) {
                self.cursor = i;
                break;
            }
        }
        self.ensure_visible();
    }

    fn ensure_visible(&mut self) {
        let n = self.display.len();
        let max_offset = n.saturating_sub(self.view_h);
        // Keep the header above the focused tool visible when possible.
        let anchor = self.cursor.saturating_sub(1);
        if self.cursor < self.offset {
            self.offset = anchor.min(self.cursor);
        } else if self.cursor >= self.offset + self.view_h {
            self.offset = self.cursor + 1 - self.view_h;
        }
        if self.offset > max_offset {
            self.offset = max_offset;
        }
    }

    fn scroll_by(&mut self, delta: isize) {
        let n = self.display.len();
        let max_offset = n.saturating_sub(self.view_h) as isize;
        self.offset = (self.offset as isize + delta).clamp(0, max_offset.max(0)) as usize;
    }

    /// Cycle the focused tool's grant, or request the model chooser.
    fn activate(&mut self, index: usize, tools: &mut [ToolState]) -> Act {
        let tool = &TOOLS[index];
        if matches!(tool.tier, Tier::Required) {
            self.flash = Some("Required tools stay enabled.".to_string());
            return Act::Stay;
        }
        let from = tools[index].grant;
        let to = from.cycle();
        if to.is_enabled() && tool.requires_model.is_some() && tools[index].model.is_none() {
            // Can't enable without a model — go choose one.
            return Act::PickModel(index);
        }
        tools[index].grant = to;
        self.flash = if ToolGrant::breaks_cache(from, to) {
            Some(
                "Switching a tool between enabled and any other grant busts the prompt cache."
                    .to_string(),
            )
        } else {
            None
        };
        Act::Stay
    }

    fn handle_key(&mut self, key: KeyEvent, tools: &mut [ToolState]) -> Act {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Act::Quit;
        }
        match key.code {
            KeyCode::Esc => Act::Back,
            KeyCode::Enter => Act::Next,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.move_focus(false);
                Act::Stay
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.move_focus(true);
                Act::Stay
            }
            KeyCode::PageUp => {
                for _ in 0..self.view_h.max(1) {
                    self.move_focus(false);
                }
                Act::Stay
            }
            KeyCode::PageDown => {
                for _ in 0..self.view_h.max(1) {
                    self.move_focus(true);
                }
                Act::Stay
            }
            KeyCode::Char(' ') => match self.focused_tool() {
                Some(index) => self.activate(index, tools),
                None => Act::Stay,
            },
            KeyCode::Char('m') | KeyCode::Char('M') => match self.focused_tool() {
                Some(index) if TOOLS[index].requires_model.is_some() => Act::PickModel(index),
                _ => Act::Stay,
            },
            _ => Act::Stay,
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent, tools: &mut [ToolState]) -> Act {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return Act::Back;
        }
        let over =
            self.list_area.contains(pos) || self.scrollbar_area.is_some_and(|a| a.contains(pos));
        match event.kind {
            MouseEventKind::ScrollDown if over => {
                self.scroll_by(1);
                Act::Stay
            }
            MouseEventKind::ScrollUp if over => {
                self.scroll_by(-1);
                Act::Stay
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.actions.clicked(pos).is_some() {
                    return Act::Next;
                }
                if let Some(display_index) = self.display_at(pos)
                    && let Some(index) = self.tool_at(display_index)
                {
                    self.cursor = display_index;
                    return self.activate(index, tools);
                }
                Act::Stay
            }
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self
                    .display_at(pos)
                    .filter(|&d| matches!(self.display.get(d), Some(DisplayRow::Tool(_))));
                self.actions.track(pos);
                Act::Stay
            }
            _ => Act::Stay,
        }
    }

    fn display_at(&self, pos: Position) -> Option<usize> {
        self.row_rects
            .iter()
            .find(|(rect, _)| rect.contains(pos))
            .map(|(_, display_index)| *display_index)
    }

    fn render(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        catalog: &[AvailableModel],
        tools: &[ToolState],
    ) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, list, note, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
            Constraint::Length(1),
        ]));
        ui::render_header(frame, header, &self.title, &self.subtitle);
        self.render_list(frame, list, catalog, tools);
        self.render_note(frame, note, tools);
        ui::render_help(
            frame,
            help,
            "\u{2191}\u{2193} move   space cycle grant   m set model   enter continue   esc back",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Continue")]);
    }

    fn render_list(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        catalog: &[AvailableModel],
        tools: &[ToolState],
    ) {
        let enabled = tools
            .iter()
            .filter(|state| state.grant.is_enabled())
            .count();
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(
                format!(" Tools  \u{b7}  {enabled} of {} enabled ", TOOLS.len()),
                Style::new().fg(INK),
            ));
        let inner = block.inner(area);
        frame.render_widget(&block, area);
        self.view_h = usize::from(inner.height).max(1);
        let total = self.display.len();
        self.ensure_visible();

        let overflow = total > usize::from(inner.height);
        let (rows_area, bar_area) = if overflow && inner.width >= 2 {
            let [rows, bar] = inner.layout(&Layout::horizontal([
                Constraint::Min(0),
                Constraint::Length(1),
            ]));
            (rows, Some(bar))
        } else {
            (inner, None)
        };
        self.list_area = rows_area;
        self.scrollbar_area = bar_area;
        self.row_rects.clear();
        let width = usize::from(rows_area.width);
        let visible = usize::from(rows_area.height);
        for row in 0..visible {
            let display_index = self.offset + row;
            if display_index >= total {
                break;
            }
            let rect = Rect {
                x: rows_area.x,
                y: rows_area.y + row as u16,
                width: rows_area.width,
                height: 1,
            };
            self.row_rects.push((rect, display_index));
            let line = match self.display[display_index] {
                DisplayRow::Header(tier) => header_line(tier),
                DisplayRow::Tool(index) => {
                    self.tool_line(index, catalog, tools, width, self.cursor == display_index)
                }
            };
            let mut para = Paragraph::new(line);
            if self.hover == Some(display_index) {
                para = para.style(Style::new().bg(HOVER_BG));
            }
            frame.render_widget(para, rect);
        }
        if let Some(bar_area) = bar_area {
            ui::render_scrollbar(frame, bar_area, total, visible, self.offset);
        }
    }

    fn tool_line(
        &self,
        index: usize,
        catalog: &[AvailableModel],
        tools: &[ToolState],
        width: usize,
        focused: bool,
    ) -> Line<'static> {
        let tool = &TOOLS[index];
        let state = &tools[index];
        let required = matches!(tool.tier, Tier::Required);
        let grant = if required {
            ToolGrant::Enabled
        } else {
            state.grant
        };

        let label_style = if focused {
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
        } else if matches!(grant, ToolGrant::Disabled) {
            Style::new().fg(FOG)
        } else {
            Style::new().fg(INK)
        };

        let mark = if required {
            Span::styled(ui::CHECK_ON, Style::new().fg(DISABLED))
        } else {
            grant_mark(grant, focused)
        };

        let mut spans = vec![mark, Span::styled(tool.display.to_string(), label_style)];

        // Right-hand tag: grant, required lock, or model status.
        let tag = if required {
            Some(("required".to_string(), DISABLED))
        } else if let Some(role) = tool.requires_model {
            match state.model.and_then(|m| catalog.get(m)) {
                Some(model) => Some((format!("{} · {}", grant.label(), model.label()), GOOD)),
                None => Some((format!("needs a {role}"), WARN)),
            }
        } else {
            Some((
                grant.label().to_string(),
                match grant {
                    ToolGrant::Enabled => GOOD,
                    ToolGrant::Discoverable => WARN,
                    ToolGrant::Disabled => FOG,
                },
            ))
        };
        if let Some((text, color)) = tag {
            let used = 2 + tool.display.chars().count() + text.chars().count() + 2;
            let pad = width.saturating_sub(used).max(1);
            spans.push(Span::raw(" ".repeat(pad)));
            spans.push(Span::styled(text, Style::new().fg(color)));
        }
        Line::from(spans)
    }

    fn render_note(&self, frame: &mut Frame, area: Rect, tools: &[ToolState]) {
        let line = if let Some(flash) = &self.flash {
            Line::from(Span::styled(
                flash.clone(),
                Style::new().fg(WARN).add_modifier(Modifier::BOLD),
            ))
        } else if let Some(index) = self.focused_tool() {
            let tool = &TOOLS[index];
            let mut text = tool.hint.to_string();
            if tool.requires_model.is_some() && tools[index].model.is_none() {
                text.push_str("  Press space to pick a model and enable it.");
            } else if !matches!(tool.tier, Tier::Required) {
                text.push_str("  Space cycles enabled / discoverable / disabled.");
            }
            Line::from(Span::styled(
                text,
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            ))
        } else {
            Line::raw("")
        };
        frame.render_widget(Paragraph::new(line), area);
    }
}

fn header_line(tier: Tier) -> Line<'static> {
    Line::from(Span::styled(
        tier.heading().to_string(),
        Style::new().fg(BRASS).add_modifier(Modifier::BOLD),
    ))
}

fn grant_mark(grant: ToolGrant, focused: bool) -> Span<'static> {
    let (mark, color) = match grant {
        ToolGrant::Enabled => (ui::CHECK_ON, if focused { BRASS } else { GOOD }),
        ToolGrant::Discoverable => (ui::RADIO_OFF, if focused { BRASS } else { WARN }),
        ToolGrant::Disabled => (ui::CHECK_OFF, if focused { BRASS } else { FOG }),
    };
    Span::styled(mark, Style::new().fg(color))
}

/// Single-model chooser used when a tool needs a model before it can run.
mod picker {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Pick {
        Picked(usize),
        Cancel,
        Quit,
    }

    pub(super) fn run(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        catalog: &[AvailableModel],
        current: Option<usize>,
    ) -> Result<Pick> {
        execute!(terminal.backend_mut(), EnableMouseCapture)?;
        let result = run_loop(terminal, catalog, current);
        let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
        result
    }

    fn run_loop(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        catalog: &[AvailableModel],
        current: Option<usize>,
    ) -> Result<Pick> {
        if catalog.is_empty() {
            return Ok(Pick::Cancel);
        }
        let mut nav = ui::ListNav::new();
        nav.cursor = current.unwrap_or(0).min(catalog.len() - 1);
        let mut back_rect = Rect::default();
        let mut back_hover = false;
        let mut list_area = Rect::default();
        let mut scrollbar_area: Option<Rect> = None;
        let mut row_rects: Vec<Rect> = Vec::new();
        loop {
            terminal.draw(|frame| {
                let area = frame.area();
                frame.render_widget(Clear, area);
                back_rect = chrome::render_back_button(frame, area, true, back_hover);
                let col = ui::column(area);
                let [header, _, list, help] = col.layout(&Layout::vertical([
                    Constraint::Length(3),
                    Constraint::Length(1),
                    Constraint::Min(3),
                    Constraint::Length(1),
                ]));
                ui::render_header(
                    frame,
                    header,
                    "Choose a model for this tool",
                    "This tool needs a model before it can run.",
                );
                let block = Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(NIGHT))
                    .title(Span::styled(" Models ", Style::new().fg(INK)));
                let inner = block.inner(list);
                frame.render_widget(&block, list);
                nav.set_view_h(usize::from(inner.height));
                nav.clamp(catalog.len());
                let overflow = catalog.len() > usize::from(inner.height);
                let (rows_area, bar_area) = if overflow && inner.width >= 2 {
                    let [rows, bar] = inner.layout(&Layout::horizontal([
                        Constraint::Min(0),
                        Constraint::Length(1),
                    ]));
                    (rows, Some(bar))
                } else {
                    (inner, None)
                };
                list_area = rows_area;
                scrollbar_area = bar_area;
                row_rects.clear();
                let visible = usize::from(rows_area.height);
                let width = usize::from(rows_area.width);
                for row in 0..visible {
                    let index = nav.offset + row;
                    if index >= catalog.len() {
                        break;
                    }
                    let rect = Rect {
                        x: rows_area.x,
                        y: rows_area.y + row as u16,
                        width: rows_area.width,
                        height: 1,
                    };
                    row_rects.push(rect);
                    let model = &catalog[index];
                    let focused = nav.cursor == index;
                    let style = if focused {
                        Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
                    } else {
                        Style::new().fg(INK)
                    };
                    let marker = if focused { "\u{25b8} " } else { "  " };
                    let label = model.label().to_string();
                    let provider = model.provider_display;
                    let used = 2 + label.chars().count() + provider.chars().count() + 2;
                    let pad = width.saturating_sub(used).max(1);
                    frame.render_widget(
                        Paragraph::new(Line::from(vec![
                            Span::styled(marker, Style::new().fg(BRASS)),
                            Span::styled(label, style),
                            Span::raw(" ".repeat(pad)),
                            Span::styled(provider.to_string(), Style::new().fg(DISABLED)),
                        ])),
                        rect,
                    );
                }
                if let Some(bar_area) = bar_area {
                    ui::render_scrollbar(frame, bar_area, catalog.len(), visible, nav.offset);
                }
                ui::render_help(
                    frame,
                    help,
                    "\u{2191}\u{2193} move   enter choose   esc cancel   ^c quit",
                );
            })?;

            match event::read()? {
                Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
                    {
                        return Ok(Pick::Quit);
                    }
                    match key.code {
                        KeyCode::Esc => return Ok(Pick::Cancel),
                        KeyCode::Enter => return Ok(Pick::Picked(nav.cursor)),
                        KeyCode::Up | KeyCode::Char('k') => nav.move_by(-1, catalog.len()),
                        KeyCode::Down | KeyCode::Char('j') => nav.move_by(1, catalog.len()),
                        KeyCode::PageUp => nav.page(false, catalog.len()),
                        KeyCode::PageDown => nav.page(true, catalog.len()),
                        _ => {}
                    }
                }
                Event::Mouse(mouse) => {
                    let pos = Position::new(mouse.column, mouse.row);
                    back_hover = chrome::hit(back_rect, pos);
                    let over =
                        list_area.contains(pos) || scrollbar_area.is_some_and(|a| a.contains(pos));
                    match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) if chrome::hit(back_rect, pos) => {
                            return Ok(Pick::Cancel);
                        }
                        MouseEventKind::ScrollDown if over => nav.scroll_by(1, catalog.len()),
                        MouseEventKind::ScrollUp if over => nav.scroll_by(-1, catalog.len()),
                        MouseEventKind::Down(MouseButton::Left) => {
                            if let Some(row) = row_rects.iter().position(|r| r.contains(pos)) {
                                let index = nav.offset + row;
                                if index < catalog.len() {
                                    return Ok(Pick::Picked(index));
                                }
                            }
                        }
                        _ => {}
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::agent::{default_tools, sample_catalog};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    #[test]
    fn display_rows_are_grouped_required_first() {
        let screen = Screen::new("Tools", "sub");
        // The first display row is the Required header.
        assert_eq!(screen.display[0], DisplayRow::Header(Tier::Required));
        // Headers appear in tier order.
        let headers: Vec<Tier> = screen
            .display
            .iter()
            .filter_map(|row| match row {
                DisplayRow::Header(tier) => Some(*tier),
                _ => None,
            })
            .collect();
        assert_eq!(headers, [Tier::Required, Tier::Suggested, Tier::Other]);
        // The cursor starts on a tool, not a header.
        assert!(matches!(screen.display[screen.cursor], DisplayRow::Tool(_)));
    }

    #[test]
    fn suggested_tools_cycle_all_three_grants() {
        let mut tools = default_tools();
        let mut screen = Screen::new("Tools", "sub");
        let search = TOOLS.iter().position(|t| t.id == "search").unwrap();
        assert_eq!(tools[search].grant, ToolGrant::Enabled);

        assert_eq!(screen.activate(search, &mut tools), Act::Stay);
        assert_eq!(tools[search].grant, ToolGrant::Discoverable);
        assert!(
            screen
                .flash
                .as_deref()
                .is_some_and(|text| text.contains("busts the prompt cache")),
            "enabled → discoverable busts the cache"
        );

        assert_eq!(screen.activate(search, &mut tools), Act::Stay);
        assert_eq!(tools[search].grant, ToolGrant::Disabled);
        assert!(
            screen.flash.is_none(),
            "discoverable → disabled does not bust the cache"
        );

        assert_eq!(screen.activate(search, &mut tools), Act::Stay);
        assert_eq!(tools[search].grant, ToolGrant::Enabled);
        assert!(
            screen
                .flash
                .as_deref()
                .is_some_and(|text| text.contains("busts the prompt cache")),
            "disabled → enabled busts the cache"
        );
    }

    #[test]
    fn required_tools_cannot_be_toggled_off() {
        let mut tools = default_tools();
        let mut screen = Screen::new("Tools", "sub");
        let read = TOOLS.iter().position(|t| t.id == "read").unwrap();
        assert!(matches!(TOOLS[read].tier, Tier::Required));
        let act = screen.activate(read, &mut tools);
        assert_eq!(act, Act::Stay);
        assert!(tools[read].grant.is_enabled(), "required tool stays on");
        assert!(screen.flash.is_some());
    }

    #[test]
    fn model_gated_tool_requests_a_model_before_enabling() {
        let mut tools = default_tools();
        let mut screen = Screen::new("Tools", "sub");
        let describe = TOOLS.iter().position(|t| t.id == "describe_image").unwrap();
        assert!(
            !tools[describe].grant.is_enabled(),
            "starts disabled without a model"
        );
        // Space asks for a model instead of enabling (Disabled → Enabled).
        assert_eq!(
            screen.activate(describe, &mut tools),
            Act::PickModel(describe)
        );
        // With a model set, space cycles Enabled → Discoverable.
        tools[describe].model = Some(0);
        tools[describe].grant = ToolGrant::Enabled;
        assert_eq!(screen.activate(describe, &mut tools), Act::Stay);
        assert_eq!(tools[describe].grant, ToolGrant::Discoverable);
        assert!(
            screen.flash.is_some(),
            "leaving enabled busts the prompt cache"
        );
        // Discoverable → Disabled does not bust the cache.
        assert_eq!(screen.activate(describe, &mut tools), Act::Stay);
        assert_eq!(tools[describe].grant, ToolGrant::Disabled);
        assert!(screen.flash.is_none());
    }

    #[test]
    fn move_focus_skips_headers() {
        let mut screen = Screen::new("Tools", "sub");
        let start = screen.cursor;
        screen.move_focus(true);
        assert!(matches!(screen.display[screen.cursor], DisplayRow::Tool(_)));
        assert_ne!(screen.cursor, start);
        let _ = key(KeyCode::Down);
    }

    #[test]
    fn renders_grouped_headings_without_panicking() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let catalog = sample_catalog();
        let tools = default_tools();
        let mut screen = Screen::new("Grant tools", "sub");
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), &catalog, &tools))
            .unwrap();
        let buf = terminal.backend().buffer();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Required"), "{text}");
        assert!(text.contains("Not suggested"), "{text}");
        assert!(text.contains("Control the computer"), "{text}");
    }
}
