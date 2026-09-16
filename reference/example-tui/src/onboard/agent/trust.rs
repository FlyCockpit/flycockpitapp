//! Agent screen 3: trusted vs. untrusted.
//!
//! Untrusted is the default and the safe choice: the host redacts secrets and
//! sealed values before they reach the model, so a leak or prompt injection
//! can't exfiltrate them. Trusted agents see raw values — necessary for a few
//! host-mediated tasks (like a subagent that *sets up* a sealed value), but a
//! bigger blast radius.

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
use ratatui::widgets::{Clear, Paragraph, Wrap};
use ratatui::{Terminal, backend::CrosstermBackend};

use super::super::chrome;
use super::ui::{self, BRASS, FOG, GOOD, INK, NIGHT, WARN};
use super::{AgentDraft, Nav};

const OPTIONS: [bool; 2] = [false, true]; // untrusted, trusted

pub(super) fn run(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &mut AgentDraft,
) -> Result<Nav> {
    execute!(terminal.backend_mut(), EnableMouseCapture)?;
    let result = run_loop(terminal, draft);
    let _ = execute!(terminal.backend_mut(), DisableMouseCapture);
    result
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    draft: &mut AgentDraft,
) -> Result<Nav> {
    let mut screen = Screen::new(draft.trusted);
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area()))?;
        match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                if let Some(nav) = screen.handle_key(key) {
                    draft.trusted = OPTIONS[screen.selected];
                    return Ok(nav);
                }
            }
            Event::Mouse(mouse) => {
                if let Some(nav) = screen.handle_mouse(mouse) {
                    draft.trusted = OPTIONS[screen.selected];
                    return Ok(nav);
                }
            }
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

struct Screen {
    selected: usize,
    hover: Option<usize>,
    rows: Vec<Rect>,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
    fn new(trusted: bool) -> Self {
        Self {
            selected: if trusted { 1 } else { 0 },
            hover: None,
            rows: Vec::new(),
            back_rect: Rect::default(),
            back_hover: false,
            actions: chrome::ActionBar::default(),
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> Option<Nav> {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
        {
            return Some(Nav::Quit);
        }
        match key.code {
            KeyCode::Esc => Some(Nav::Back),
            KeyCode::Enter => Some(Nav::Next),
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.selected = 1 - self.selected;
                None
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.selected = 1 - self.selected;
                None
            }
            KeyCode::Char(' ') => {
                self.selected = 1 - self.selected;
                None
            }
            _ => None,
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Option<Nav> {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left))
            && chrome::hit(self.back_rect, pos)
        {
            return Some(Nav::Back);
        }
        match event.kind {
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                self.hover = self.rows.iter().position(|r| r.contains(pos));
                self.actions.track(pos);
                None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self.actions.clicked(pos).is_some() {
                    return Some(Nav::Next);
                }
                if let Some(index) = self.rows.iter().position(|r| r.contains(pos)) {
                    if self.selected == index {
                        return Some(Nav::Next);
                    }
                    self.selected = index;
                }
                None
            }
            _ => None,
        }
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, options, _, detail, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(2),
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(1),
        ]));
        ui::render_header(
            frame,
            header,
            "How much does this agent see?",
            "Untrusted keeps secrets and sealed values out of the model's context.",
        );
        self.render_options(frame, options);
        self.render_detail(frame, detail);
        ui::render_help(
            frame,
            help,
            "\u{2191}\u{2193} choose   enter continue   esc back   ^c quit",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Continue")]);
    }

    fn render_options(&mut self, frame: &mut Frame, area: Rect) {
        self.rows.clear();
        let rows = Layout::vertical([Constraint::Length(1); 2]).split(area);
        for (index, &row) in rows.iter().enumerate() {
            self.rows.push(row);
            let selected = self.selected == index;
            let (title, tag) = if index == 0 {
                ("Untrusted", "recommended \u{b7} secrets redacted")
            } else {
                ("Trusted", "sees raw secrets & sealed values")
            };
            let title_style = if selected {
                Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
            } else {
                Style::new().fg(INK)
            };
            let tag_style = if index == 0 {
                Style::new().fg(GOOD)
            } else {
                Style::new().fg(WARN)
            };
            let line = Line::from(vec![
                ui::radio_mark(selected, selected),
                Span::styled(title, title_style),
                Span::styled("  \u{2014}  ", Style::new().fg(NIGHT)),
                Span::styled(tag, tag_style),
            ]);
            frame.render_widget(Paragraph::new(line), row);
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let lines = if self.selected == 0 {
            vec![
                Line::from(Span::styled(
                    "The host strips API keys and sealed values from everything the model reads, and scans tool and subagent results for injection attempts before they reach this agent's history.",
                    Style::new().fg(FOG),
                )),
                Line::raw(""),
                Line::from(Span::styled(
                    "Delegation to cloud models always routes through a redacted, untrusted child \u{2014} the safe default.",
                    Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
                )),
            ]
        } else {
            vec![
                Line::from(Span::styled(
                    "Trusted agents receive raw secret and sealed values. Only grant this to a local, host-mediated agent that genuinely needs them \u{2014} for example a subagent whose whole job is to set up a sealed value.",
                    Style::new().fg(FOG),
                )),
                Line::raw(""),
                Line::from(Span::styled(
                    "Warning: a trusted agent can leak anything it can read. Keep the blast radius small.",
                    Style::new().fg(WARN).add_modifier(Modifier::BOLD),
                )),
            ]
        };
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }
}

#[cfg(test)]
mod tests {
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn mouse(kind: MouseEventKind, pos: Position) -> MouseEvent {
        MouseEvent {
            kind,
            column: pos.x,
            row: pos.y,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn clicking_the_continue_button_advances() {
        let mut screen = Screen::new(false);
        let backend = {
            let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
            terminal
                .draw(|frame| screen.render(frame, frame.area()))
                .unwrap();
            terminal.backend().clone()
        };
        let buf = backend.buffer();
        let mut pos = None;
        for y in 0..buf.area.height {
            let row: String = (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            if let Some(col) = row.find("[ Continue ]") {
                pos = Some(Position::new(col as u16, y));
            }
        }
        let pos = pos.expect("Continue button should render");
        assert_eq!(
            screen.handle_mouse(mouse(MouseEventKind::Down(MouseButton::Left), pos)),
            Some(Nav::Next)
        );
    }

    #[test]
    fn defaults_to_untrusted_and_toggles() {
        let mut screen = Screen::new(false);
        assert_eq!(screen.selected, 0);
        screen.handle_key(key(KeyCode::Down));
        assert_eq!(screen.selected, 1);
        assert!(OPTIONS[screen.selected]);
    }

    #[test]
    fn enter_continues() {
        let mut screen = Screen::new(false);
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), Some(Nav::Next));
        assert_eq!(screen.handle_key(key(KeyCode::Esc)), Some(Nav::Back));
    }
}
