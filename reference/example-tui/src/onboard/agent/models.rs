//! Reusable model multi-select: tick which models a target (the agent, or a
//! subagent) may use, and star exactly one as the default. Shared by the agent
//! Models phase and the subagent editor, so the same list behaves identically
//! wherever models are chosen.
//!
//! Invariant: the default is always an enabled model when any model is enabled.
//! Toggling the current default off moves the star to the next enabled model;
//! enabling the first model claims the star automatically.

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
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Clear, Paragraph};

use super::super::chrome;
use super::ui::{self, BRASS, DISABLED, FOG, HOVER_BG, INK, NIGHT, STAR, WARN};
use super::{AvailableModel, Nav};

/// Run the picker over `allowed`/`default` (both indexed by `catalog`). The
/// selections are edited in place; `Nav` reports where to go next.
pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
    allowed: &mut Vec<bool>,
    default: &mut Option<usize>,
    title: &str,
    subtitle: &str,
) -> Result<Nav> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, catalog, allowed, default, title, subtitle);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
    allowed: &mut Vec<bool>,
    default: &mut Option<usize>,
    title: &str,
    subtitle: &str,
) -> Result<Nav> {
    let mut screen = Screen::new(catalog, allowed, default, title, subtitle);
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area()))?;
        match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                if let Some(nav) = screen.handle_key(key) {
                    screen.commit(allowed, default);
                    return Ok(nav);
                }
            }
            Event::Mouse(mouse) => {
                if let Some(nav) = screen.handle_mouse(mouse) {
                    screen.commit(allowed, default);
                    return Ok(nav);
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

struct Screen<'a> {
    catalog: &'a [AvailableModel],
    title: String,
    subtitle: String,
    allowed: Vec<bool>,
    default: Option<usize>,
    nav: ui::ListNav,
    hover: Option<usize>,
    row_rects: Vec<Rect>,
    list_area: Rect,
    scrollbar_area: Option<Rect>,
    error: bool,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl<'a> Screen<'a> {
    fn new(
        catalog: &'a [AvailableModel],
        allowed: &[bool],
        default: &Option<usize>,
        title: &str,
        subtitle: &str,
    ) -> Self {
        let mut nav = ui::ListNav::new();
        nav.clamp(catalog.len());
        Self {
            catalog,
            title: title.to_string(),
            subtitle: subtitle.to_string(),
            allowed: allowed.to_vec(),
            default: *default,
            nav,
            hover: None,
            row_rects: Vec::new(),
            list_area: Rect::default(),
            scrollbar_area: None,
            error: false,
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    /// Enter / Continue: advance only when at least one model is enabled.
    fn try_next(&mut self) -> Option<Nav> {
        if self.enabled_count() == 0 && !self.catalog.is_empty() {
            self.error = true;
            None
        } else {
            Some(Nav::Next)
        }
    }

    fn commit(&self, allowed: &mut Vec<bool>, default: &mut Option<usize>) {
        *allowed = self.allowed.clone();
        *default = self.default;
    }

    fn enabled_count(&self) -> usize {
        self.allowed.iter().filter(|&&on| on).count()
    }

    fn normalize_default(&mut self) {
        let valid = self
            .default
            .map(|d| self.allowed.get(d).copied().unwrap_or(false))
            .unwrap_or(false);
        if !valid {
            self.default = self.allowed.iter().position(|&on| on);
        }
    }

    fn toggle(&mut self, index: usize) {
        if let Some(slot) = self.allowed.get_mut(index) {
            *slot = !*slot;
            self.normalize_default();
            self.error = false;
        }
    }

    fn set_default(&mut self, index: usize) {
        if index < self.allowed.len() {
            self.allowed[index] = true;
            self.default = Some(index);
            self.error = false;
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Option<Nav> {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Some(Nav::Quit);
        }
        let n = self.catalog.len();
        match key.code {
            KeyCode::Esc => Some(Nav::Back),
            KeyCode::Enter => self.try_next(),
            KeyCode::Up | KeyCode::Char('k') => {
                self.nav.move_by(-1, n);
                None
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.nav.move_by(1, n);
                None
            }
            KeyCode::PageUp => {
                self.nav.page(false, n);
                None
            }
            KeyCode::PageDown => {
                self.nav.page(true, n);
                None
            }
            KeyCode::Home => {
                self.nav.cursor = 0;
                self.nav.ensure_visible(n);
                None
            }
            KeyCode::End => {
                self.nav.cursor = n.saturating_sub(1);
                self.nav.ensure_visible(n);
                None
            }
            KeyCode::Char(' ') => {
                self.toggle(self.nav.cursor);
                None
            }
            KeyCode::Char('d') | KeyCode::Char('*') => {
                self.set_default(self.nav.cursor);
                None
            }
            _ => None,
        }
    }

    fn index_at(&self, pos: Position) -> Option<usize> {
        self.row_rects
            .iter()
            .position(|rect| rect.contains(pos))
            .map(|row| self.nav.offset + row)
            .filter(|&index| index < self.catalog.len())
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Option<Nav> {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return Some(Nav::Back);
        }
        let n = self.catalog.len();
        let over_list =
            self.list_area.contains(pos) || self.scrollbar_area.is_some_and(|a| a.contains(pos));
        match event.kind {
            MouseEventKind::ScrollDown if over_list => {
                self.nav.scroll_by(1, n);
                None
            }
            MouseEventKind::ScrollUp if over_list => {
                self.nav.scroll_by(-1, n);
                None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.actions.clicked(pos).is_some() {
                    return self.try_next();
                }
                if let Some(index) = self.index_at(pos) {
                    self.nav.cursor = index;
                    self.toggle(index);
                }
                None
            }
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self.index_at(pos);
                self.actions.track(pos);
                None
            }
            _ => None,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
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
        self.render_list(frame, list);
        self.render_note(frame, note);
        ui::render_help(
            frame,
            help,
            "\u{2191}\u{2193} move   space toggle   d default   enter continue   esc back",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Continue")]);
    }

    fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let total = self.catalog.len();
        let block = Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(
                format!(" Models  \u{b7}  {} of {total} ", self.enabled_count()),
                Style::new().fg(INK),
            ));
        let inner = block.inner(area);
        frame.render_widget(&block, area);
        self.nav.set_view_h(usize::from(inner.height));
        self.nav.clamp(total);

        if total == 0 {
            self.list_area = inner;
            self.scrollbar_area = None;
            self.row_rects.clear();
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "No models were found while verifying providers.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                ))
                .centered(),
                inner,
            );
            return;
        }

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
            let index = self.nav.offset + row;
            if index >= total {
                break;
            }
            let rect = Rect {
                x: rows_area.x,
                y: rows_area.y + row as u16,
                width: rows_area.width,
                height: 1,
            };
            self.row_rects.push(rect);
            let line = self.row_line(index, width);
            let mut para = Paragraph::new(line);
            if self.hover == Some(index) {
                para = para.style(Style::new().bg(HOVER_BG));
            }
            frame.render_widget(para, rect);
        }

        if let Some(bar_area) = bar_area {
            ui::render_scrollbar(frame, bar_area, total, visible, self.nav.offset);
        }
    }

    fn row_line(&self, index: usize, width: usize) -> Line<'static> {
        let model = &self.catalog[index];
        let focused = self.nav.cursor == index;
        let on = self.allowed[index];
        let is_default = self.default == Some(index);

        let label_style = if focused {
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
        } else if on {
            Style::new().fg(INK)
        } else {
            Style::new().fg(FOG)
        };
        let star = if is_default {
            Span::styled(format!("{STAR} "), Style::new().fg(BRASS))
        } else {
            Span::styled("  ", Style::new().fg(NIGHT))
        };
        let label = model.label().to_string();
        let provider = model.provider_display;
        let used = 2 + 2 + label.chars().count() + provider.chars().count() + 2;
        let pad = width.saturating_sub(used).max(1);
        Line::from(vec![
            ui::check_mark(on, focused),
            star,
            Span::styled(label, label_style),
            Span::raw(" ".repeat(pad)),
            Span::styled(provider.to_string(), Style::new().fg(DISABLED)),
        ])
    }

    fn render_note(&self, frame: &mut Frame, area: Rect) {
        let line = if self.error {
            Line::from(Span::styled(
                "Enable at least one model to continue.",
                Style::new().fg(WARN).add_modifier(Modifier::BOLD),
            ))
        } else {
            Line::from(Span::styled(
                "The starred model is the default; the rest are switchable at runtime.",
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            ))
        };
        frame.render_widget(Paragraph::new(line), area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::agent::sample_catalog;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn screen(catalog: &[AvailableModel]) -> Screen<'_> {
        let (allowed, default) = super::super::default_models(catalog.len());
        Screen::new(catalog, &allowed, &default, "Models", "sub")
    }

    #[test]
    fn toggling_off_the_default_moves_the_star() {
        let catalog = sample_catalog();
        let mut screen = screen(&catalog);
        // Enable model 1 and 2, then turn off model 0 (the default).
        screen.set_default(0);
        screen.toggle(1);
        assert_eq!(screen.default, Some(0));
        screen.toggle(0); // off
        assert_eq!(
            screen.default,
            Some(1),
            "the star should move to the next enabled model"
        );
    }

    #[test]
    fn enter_requires_at_least_one_model() {
        let catalog = sample_catalog();
        let mut screen = screen(&catalog);
        // Disable the only enabled model.
        screen.toggle(0);
        assert_eq!(screen.enabled_count(), 0);
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), None);
        assert!(screen.error);
        // Re-enable and it advances.
        screen.toggle(0);
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), Some(Nav::Next));
    }

    #[test]
    fn set_default_also_enables() {
        let catalog = sample_catalog();
        let mut screen = screen(&catalog);
        screen.toggle(0); // now nothing enabled
        screen.set_default(2);
        assert!(screen.allowed[2]);
        assert_eq!(screen.default, Some(2));
    }

    #[test]
    fn renders_the_catalog_without_panicking() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let catalog = sample_catalog();
        let mut screen = screen(&catalog);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area()))
            .unwrap();
        let buf = terminal.backend().buffer();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        assert!(text.contains("Models"), "{text}");
        assert!(text.contains("GPT-5"), "{text}");
    }
}
