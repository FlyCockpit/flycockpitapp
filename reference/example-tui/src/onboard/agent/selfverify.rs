//! Self-verify configuration, reached from the optimizations screen.
//!
//! Three action surfaces — writes/edits, commands, and Monty — are configured
//! independently. Each is either `off` or verified by any mix of the agent's
//! *own* model and a panel of *other* models.
//!
//! The surface list quick-dials the agent's own model (the common, cheap case:
//! the prompt cache stays warm). Pressing space/enter opens the panel, where the
//! agent's own model is the first verifier alongside every catalog model, each
//! with a copy count and clickable steppers. The runtime sends one copy first
//! and the rest only once it lands, so extra copies re-use the warmed cache —
//! which is why the panel is expressed as per-model copy counts.

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
use ratatui::widgets::{Block, BorderType, Clear, Paragraph, Wrap};
use ratatui::{Terminal, backend::CrosstermBackend};

use super::super::chrome;
use super::ui::{self, BRASS, DISABLED, FOG, GOOD, INK, NIGHT};
use super::{AvailableModel, Nav, SURFACES, SurfaceVerify};

const COPY_MAX: u8 = 9;

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
    surfaces: &mut [SurfaceVerify],
) -> Result<Nav> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, catalog, surfaces);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Stay,
    Close(Nav),
    OpenPanel(usize),
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    catalog: &[AvailableModel],
    surfaces: &mut [SurfaceVerify],
) -> Result<Nav> {
    let mut screen = Screen::new();
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area(), surfaces))?;
        let act = match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                screen.handle_key(key, surfaces)
            }
            Event::Mouse(mouse) => screen.handle_mouse(mouse, surfaces),
            _ => Act::Stay,
        };
        match act {
            Act::Stay => {}
            Act::Close(nav) => return Ok(nav),
            Act::OpenPanel(index) => {
                let nav = panel::run(terminal, catalog, index, &mut surfaces[index])?;
                execute!(terminal.backend_mut(), EnableMouseCapture)?;
                if nav == Nav::Quit {
                    return Ok(Nav::Quit);
                }
            }
        }
    }
}

struct Screen {
    cursor: usize,
    hover: Option<usize>,
    rows: Vec<Rect>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
    fn new() -> Self {
        Self {
            cursor: 0,
            hover: None,
            rows: Vec::new(),
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    /// Quick-dial the agent's own model on the focused surface.
    fn adjust_same(&self, surfaces: &mut [SurfaceVerify], delta: i8) {
        let surface = &mut surfaces[self.cursor];
        surface.same_copies =
            (i16::from(surface.same_copies) + i16::from(delta)).clamp(0, i16::from(COPY_MAX)) as u8;
    }

    fn clear(&self, surfaces: &mut [SurfaceVerify]) {
        let surface = &mut surfaces[self.cursor];
        surface.same_copies = 0;
        surface.copies.iter_mut().for_each(|c| *c = 0);
    }

    fn handle_key(&mut self, key: KeyEvent, surfaces: &mut [SurfaceVerify]) -> Act {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Act::Close(Nav::Quit);
        }
        match key.code {
            KeyCode::Esc => Act::Close(Nav::Back),
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.cursor = (self.cursor + SURFACES.len() - 1) % SURFACES.len();
                Act::Stay
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = (self.cursor + 1) % SURFACES.len();
                Act::Stay
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('-') => {
                self.adjust_same(surfaces, -1);
                Act::Stay
            }
            KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('+') | KeyCode::Char('=') => {
                self.adjust_same(surfaces, 1);
                Act::Stay
            }
            KeyCode::Char('x') | KeyCode::Char('X') | KeyCode::Delete => {
                self.clear(surfaces);
                Act::Stay
            }
            KeyCode::Enter | KeyCode::Char(' ') => Act::OpenPanel(self.cursor),
            _ => Act::Stay,
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent, _surfaces: &mut [SurfaceVerify]) -> Act {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return Act::Close(Nav::Back);
        }
        match event.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self.rows.iter().position(|r| r.contains(pos));
                self.actions.track(pos);
                Act::Stay
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.actions.clicked(pos).is_some() {
                    return Act::Close(Nav::Back);
                }
                if let Some(index) = self.rows.iter().position(|r| r.contains(pos)) {
                    self.cursor = index;
                    return Act::OpenPanel(index);
                }
                Act::Stay
            }
            _ => Act::Stay,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, surfaces: &[SurfaceVerify]) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, list, _, detail, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(SURFACES.len() as u16),
            Constraint::Length(1),
            Constraint::Min(2),
            Constraint::Length(1),
        ]));
        ui::render_header(
            frame,
            header,
            "Self-verify risky actions",
            "Re-check writes, commands, and Monty before they land.",
        );
        self.render_rows(frame, list, surfaces);
        self.render_detail(frame, detail, surfaces);
        ui::render_help(
            frame,
            help,
            "\u{2191}\u{2193} surface   \u{2190}\u{2192} same model   space configure   x off   esc back",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Done")]);
    }

    fn render_rows(&mut self, frame: &mut Frame, area: Rect, surfaces: &[SurfaceVerify]) {
        self.rows.clear();
        let rects = Layout::vertical([Constraint::Length(1); 3]).split(area);
        for (index, (&name, &rect)) in SURFACES.iter().zip(rects.iter()).enumerate() {
            self.rows.push(rect);
            let focused = self.cursor == index;
            let surface = &surfaces[index];
            let label_style = if focused {
                Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(INK)
            };
            let value_style = if surface.is_off() {
                Style::new().fg(FOG)
            } else {
                Style::new().fg(GOOD)
            };
            let marker = if focused { "\u{25b8} " } else { "  " };
            let value = if focused {
                format!("\u{25c2} {} \u{25b8}", surface.describe())
            } else {
                format!("  {}", surface.describe())
            };
            let pad = 18usize.saturating_sub(name.chars().count()).max(1);
            let line = Line::from(vec![
                Span::styled(marker, Style::new().fg(BRASS)),
                Span::styled(name, label_style),
                Span::raw(" ".repeat(pad)),
                Span::styled(value, value_style),
            ]);
            frame.render_widget(Paragraph::new(line), rect);
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect, surfaces: &[SurfaceVerify]) {
        let surface = &surfaces[self.cursor];
        let text = if surface.is_off() {
            "This surface is not verified. Use \u{2190}\u{2192} to add the agent's own model (cheap — the cache stays warm), or press space to open the panel and pick other models too.".to_string()
        } else {
            format!(
                "Verified by {}. \u{2190}\u{2192} dials the agent's own model; press space to open the panel for other models and clickable copy steppers. Press x to turn off.",
                surface.describe()
            )
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(text, Style::new().fg(FOG))))
                .wrap(Wrap { trim: true }),
            area,
        );
    }
}

/// The verifier panel: the agent's own model plus per-model copy counts.
mod panel {
    use super::*;

    /// A clickable row: the whole line, plus its `[-]`/`[+]` stepper hit boxes.
    #[derive(Clone, Copy)]
    struct RowHit {
        rect: Rect,
        minus: Rect,
        plus: Rect,
        index: usize,
    }

    pub(super) fn run(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        catalog: &[AvailableModel],
        surface: usize,
        verify: &mut SurfaceVerify,
    ) -> Result<Nav> {
        execute!(terminal.backend_mut(), EnableMouseCapture)?;
        let result = run_loop(terminal, catalog, surface, verify);
        let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
        result
    }

    fn run_loop(
        terminal: &mut Terminal<CrosstermBackend<Stdout>>,
        catalog: &[AvailableModel],
        surface: usize,
        verify: &mut SurfaceVerify,
    ) -> Result<Nav> {
        // Keep the copies vector sized to the catalog (providers may have been
        // added since it was created).
        if verify.copies.len() != catalog.len() {
            verify.copies.resize(catalog.len(), 0);
        }
        let mut screen = Panel::new(catalog, verify, surface);
        loop {
            terminal.draw(|frame| screen.render(frame, frame.area()))?;
            match event::read()? {
                Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                    if let Some(nav) = screen.handle_key(key) {
                        screen.write_back(verify);
                        return Ok(nav);
                    }
                }
                Event::Mouse(mouse) => {
                    if let Some(nav) = screen.handle_mouse(mouse) {
                        screen.write_back(verify);
                        return Ok(nav);
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }

    struct Panel<'a> {
        catalog: &'a [AvailableModel],
        surface: usize,
        /// Copies for the agent's own model (row 0).
        same_copies: u8,
        /// Copies for each catalog model (rows 1..=n).
        copies: Vec<u8>,
        nav: ui::ListNav,
        hover: Option<usize>,
        row_hits: Vec<RowHit>,
        list_area: Rect,
        scrollbar_area: Option<Rect>,
        back_rect: Rect,
        back_hover: bool,
        actions: chrome::ActionBar,
    }

    impl<'a> Panel<'a> {
        fn new(catalog: &'a [AvailableModel], verify: &SurfaceVerify, surface: usize) -> Self {
            let mut nav = ui::ListNav::new();
            nav.clamp(catalog.len() + 1);
            Self {
                catalog,
                surface,
                same_copies: verify.same_copies,
                copies: verify.copies.clone(),
                nav,
                hover: None,
                row_hits: Vec::new(),
                list_area: Rect::default(),
                scrollbar_area: None,
                back_rect: Rect::default(),
                back_hover: false,
                actions: chrome::ActionBar::default(),
            }
        }

        /// Total rows = the same-model row plus one per catalog model.
        fn row_count(&self) -> usize {
            self.catalog.len() + 1
        }

        fn write_back(&self, verify: &mut SurfaceVerify) {
            verify.same_copies = self.same_copies;
            verify.copies.clone_from(&self.copies);
        }

        /// Adjust the copies for a logical row (0 = same model).
        fn adjust(&mut self, index: usize, delta: i8) {
            let slot = if index == 0 {
                Some(&mut self.same_copies)
            } else {
                self.copies.get_mut(index - 1)
            };
            if let Some(slot) = slot {
                *slot = (i16::from(*slot) + i16::from(delta)).clamp(0, i16::from(COPY_MAX)) as u8;
            }
        }

        fn count_at(&self, index: usize) -> u8 {
            if index == 0 {
                self.same_copies
            } else {
                self.copies.get(index - 1).copied().unwrap_or(0)
            }
        }

        /// Total copies across the same-model row and every catalog model.
        fn total(&self) -> u32 {
            u32::from(self.same_copies) + self.copies.iter().map(|&c| u32::from(c)).sum::<u32>()
        }

        /// Distinct verifiers carrying at least one copy.
        fn verifiers(&self) -> usize {
            usize::from(self.same_copies > 0) + self.copies.iter().filter(|&&c| c > 0).count()
        }

        fn handle_key(&mut self, key: KeyEvent) -> Option<Nav> {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
            {
                return Some(Nav::Quit);
            }
            let n = self.row_count();
            match key.code {
                KeyCode::Esc | KeyCode::Enter => Some(Nav::Back),
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
                KeyCode::Left | KeyCode::Char('-') | KeyCode::Char('h') => {
                    self.adjust(self.nav.cursor, -1);
                    None
                }
                KeyCode::Right | KeyCode::Char('+') | KeyCode::Char('=') | KeyCode::Char('l') => {
                    self.adjust(self.nav.cursor, 1);
                    None
                }
                KeyCode::Char(' ') => {
                    // Space bumps the count, wrapping to 0 past the cap.
                    let cur = self.count_at(self.nav.cursor);
                    let next = if cur >= COPY_MAX { 0 } else { cur + 1 };
                    self.adjust(
                        self.nav.cursor,
                        i8::try_from(i16::from(next) - i16::from(cur)).unwrap_or(0),
                    );
                    None
                }
                _ => None,
            }
        }

        fn handle_mouse(&mut self, event: MouseEvent) -> Option<Nav> {
            let pos = Position::new(event.column, event.row);
            self.back_hover = chrome::hit(self.back_rect, pos);
            if matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
                if chrome::hit(self.back_rect, pos) {
                    return Some(Nav::Back);
                }
                if self.actions.clicked(pos).is_some() {
                    return Some(Nav::Back);
                }
            }
            let n = self.row_count();
            let over = self.list_area.contains(pos)
                || self.scrollbar_area.is_some_and(|a| a.contains(pos));
            match event.kind {
                MouseEventKind::ScrollDown if over => {
                    self.nav.scroll_by(1, n);
                    None
                }
                MouseEventKind::ScrollUp if over => {
                    self.nav.scroll_by(-1, n);
                    None
                }
                MouseEventKind::Down(MouseButton::Left) => {
                    if let Some(hit) = self.row_hits.iter().find(|h| h.rect.contains(pos)).copied()
                    {
                        self.nav.cursor = hit.index;
                        if hit.minus.contains(pos) {
                            self.adjust(hit.index, -1);
                        } else if hit.plus.contains(pos) {
                            self.adjust(hit.index, 1);
                        }
                    }
                    None
                }
                MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                    self.hover = self
                        .row_hits
                        .iter()
                        .find(|h| h.rect.contains(pos))
                        .map(|h| h.index);
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
            ui::render_header(
                frame,
                header,
                &format!("Verifier panel \u{2014} {}", SURFACES[self.surface]),
                &format!(
                    "{} {}, {} total {}.",
                    self.verifiers(),
                    crate::onboard::agent::plural(self.verifiers() as u32, "verifier", "verifiers"),
                    self.total(),
                    crate::onboard::agent::plural(self.total(), "copy", "copies"),
                ),
            );
            self.render_list(frame, list);
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    "Same model re-uses the warm prompt cache. Other models: one copy is sent first, the rest follow once it lands.",
                    Style::new().fg(DISABLED),
                )))
                .wrap(Wrap { trim: true }),
                note,
            );
            ui::render_help(
                frame,
                help,
                "\u{2191}\u{2193} move   -/+ or [\u{2212}][\u{002b}] copies   space bump   enter done   esc back",
            );
            self.actions
                .render(frame, help, &[chrome::Button::primary("Done")]);
        }

        fn render_list(&mut self, frame: &mut Frame, area: Rect) {
            let total = self.row_count();
            let block = Block::bordered()
                .border_type(BorderType::Rounded)
                .border_style(Style::new().fg(NIGHT))
                .title(Span::styled(" Verifiers ", Style::new().fg(INK)));
            let inner = block.inner(area);
            frame.render_widget(&block, area);
            self.nav.set_view_h(usize::from(inner.height));
            self.nav.clamp(total);
            self.row_hits.clear();
            if total == 0 {
                self.list_area = inner;
                self.scrollbar_area = None;
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
            let visible = usize::from(rows_area.height);
            let width = usize::from(rows_area.width);
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
                // Stepper hit boxes: "[-]" at cols 2..5, "[+]" at cols 9..12.
                let minus = Rect {
                    x: rect.x + 2,
                    y: rect.y,
                    width: 3,
                    height: 1,
                };
                let plus = Rect {
                    x: rect.x + 9,
                    y: rect.y,
                    width: 3,
                    height: 1,
                };
                self.row_hits.push(RowHit {
                    rect,
                    minus,
                    plus,
                    index,
                });
                frame.render_widget(Paragraph::new(self.row_line(index, width)), rect);
            }
            if let Some(bar_area) = bar_area {
                ui::render_scrollbar(frame, bar_area, total, visible, self.nav.offset);
            }
        }

        fn row_line(&self, index: usize, width: usize) -> Line<'static> {
            let focused = self.nav.cursor == index;
            let count = self.count_at(index);
            let (label, trailing) = if index == 0 {
                ("Same model".to_string(), "reuses cache".to_string())
            } else {
                let model = &self.catalog[index - 1];
                (
                    model.label().to_string(),
                    model.provider_display.to_string(),
                )
            };
            let trailing_style = if index == 0 {
                Style::new().fg(GOOD)
            } else {
                Style::new().fg(DISABLED)
            };

            let button_style = if focused {
                Style::new().fg(BRASS)
            } else {
                Style::new().fg(FOG)
            };
            let count_span = if count == 0 {
                Span::styled(" \u{b7} ".to_string(), Style::new().fg(DISABLED))
            } else {
                Span::styled(format!("\u{d7}{count} "), Style::new().fg(GOOD))
            };
            let label_style = if focused {
                Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
            } else if count > 0 {
                Style::new().fg(INK)
            } else {
                Style::new().fg(FOG)
            };
            let marker = if focused { "\u{25b8} " } else { "  " };
            // Widths must match the stepper hit boxes in render_list:
            // marker(2) + "[-]"(3) + " "(1) + count(3) + "[+]"(3) + "  "(2).
            let used = 2 + 3 + 1 + 3 + 3 + 2 + label.chars().count() + trailing.chars().count() + 2;
            let pad = width.saturating_sub(used).max(1);
            Line::from(vec![
                Span::styled(marker, Style::new().fg(BRASS)),
                Span::styled("[\u{2212}]", button_style),
                Span::raw(" "),
                count_span,
                Span::styled("[\u{002b}]", button_style),
                Span::raw("  "),
                Span::styled(label, label_style),
                Span::raw(" ".repeat(pad)),
                Span::styled(format!("  {trailing}"), trailing_style),
            ])
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::onboard::agent::sample_catalog;

        fn key(code: KeyCode) -> KeyEvent {
            KeyEvent::from(code)
        }

        fn panel_for(catalog: &[AvailableModel]) -> Panel<'_> {
            let verify = SurfaceVerify {
                same_copies: 0,
                copies: vec![0u8; catalog.len()],
            };
            Panel::new(catalog, &verify, 0)
        }

        #[test]
        fn same_model_is_the_first_row_and_adjusts() {
            let catalog = sample_catalog();
            let mut panel = panel_for(&catalog);
            // Row 0 is the agent's own model.
            panel.adjust(0, 1);
            panel.adjust(0, 1);
            assert_eq!(panel.same_copies, 2);
            assert_eq!(panel.verifiers(), 1);
            assert_eq!(panel.total(), 2);
        }

        #[test]
        fn other_models_and_totals() {
            let catalog = sample_catalog();
            let mut panel = panel_for(&catalog);
            panel.adjust(1, 1); // first catalog model
            panel.adjust(2, 1);
            assert_eq!(panel.copies[0], 1);
            assert_eq!(panel.copies[1], 1);
            assert_eq!(panel.verifiers(), 2);
            assert_eq!(panel.total(), 2);
        }

        #[test]
        fn copies_clamp_at_the_cap() {
            let catalog = sample_catalog();
            let mut panel = panel_for(&catalog);
            for _ in 0..20 {
                panel.adjust(1, 1);
            }
            assert_eq!(panel.copies[0], COPY_MAX);
        }

        #[test]
        fn space_wraps_past_the_cap() {
            let catalog = sample_catalog();
            let mut panel = panel_for(&catalog);
            panel.nav.cursor = 0;
            panel.same_copies = COPY_MAX;
            panel.handle_key(key(KeyCode::Char(' ')));
            assert_eq!(panel.same_copies, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onboard::agent::sample_catalog;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn surfaces(n: usize) -> Vec<SurfaceVerify> {
        vec![
            SurfaceVerify {
                same_copies: 1,
                copies: vec![0; n],
            },
            SurfaceVerify {
                same_copies: 0,
                copies: vec![0; n],
            },
            SurfaceVerify {
                same_copies: 0,
                copies: vec![0; n],
            },
        ]
    }

    #[test]
    fn arrows_dial_same_model_and_clamp() {
        let n = sample_catalog().len();
        let mut surfaces = surfaces(n);
        let mut screen = Screen::new();
        // Writes surface starts at same ×1; dial down to off, back up, clamp high.
        screen.handle_key(key(KeyCode::Left), &mut surfaces);
        assert!(surfaces[0].is_off());
        for _ in 0..20 {
            screen.handle_key(key(KeyCode::Char('+')), &mut surfaces);
        }
        assert_eq!(surfaces[0].same_copies, COPY_MAX);
    }

    #[test]
    fn x_turns_a_surface_off() {
        let n = sample_catalog().len();
        let mut surfaces = surfaces(n);
        surfaces[0].copies[0] = 3;
        let mut screen = Screen::new();
        screen.handle_key(key(KeyCode::Char('x')), &mut surfaces);
        assert!(surfaces[0].is_off());
    }

    #[test]
    fn space_requests_the_panel_for_the_focused_surface() {
        let n = sample_catalog().len();
        let mut surfaces = surfaces(n);
        let mut screen = Screen::new();
        screen.cursor = 2;
        assert_eq!(
            screen.handle_key(key(KeyCode::Char(' ')), &mut surfaces),
            Act::OpenPanel(2)
        );
    }

    #[test]
    fn surfaces_render_without_panicking() {
        use ratatui::Terminal;
        use ratatui::backend::TestBackend;

        let surfaces = surfaces(sample_catalog().len());
        let mut screen = Screen::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| screen.render(frame, frame.area(), &surfaces))
            .unwrap();
        let buf = terminal.backend().buffer();
        let text: String = buf.content().iter().map(|c| c.symbol()).collect();
        for surface in SURFACES {
            assert!(text.contains(surface), "missing {surface}: {text}");
        }
    }
}
