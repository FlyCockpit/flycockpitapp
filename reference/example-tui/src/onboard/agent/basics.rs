//! Agent screen 1: name the agent.
//!
//! One text field. A blank name is allowed — it falls back to "pilot" — so the
//! user can blow straight through with Enter, matching the "good defaults, keep
//! moving" feel of the rest of onboarding.

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
use ratatui::widgets::{Clear, Paragraph, Wrap};

use super::super::chrome;
use super::super::field::TextField;
use super::ui::{self, FOG};
use super::{AgentDraft, Nav};

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
    let mut screen = Screen::new(&draft.name);
    loop {
        terminal.draw(|frame| screen.render(frame, frame.area()))?;
        match event::read()? {
            Event::Key(key) if key.is_press() || key.kind == KeyEventKind::Repeat => {
                match screen.handle_key(key) {
                    None => {}
                    Some(Nav::Next) => {
                        draft.name = screen.name.trimmed().to_string();
                        return Ok(Nav::Next);
                    }
                    Some(Nav::Back) => return Ok(Nav::Back),
                    Some(Nav::Quit) => return Ok(Nav::Quit),
                }
            }
            Event::Mouse(mouse) => match screen.handle_mouse(mouse) {
                None => {}
                Some(Nav::Next) => {
                    draft.name = screen.name.trimmed().to_string();
                    return Ok(Nav::Next);
                }
                Some(Nav::Back) => return Ok(Nav::Back),
                Some(Nav::Quit) => return Ok(Nav::Quit),
            },
            Event::Paste(text) => screen.name.paste(&text),
            Event::Resize(_, _) => {}
            _ => {}
        }
    }
}

struct Screen {
    name: TextField,
    back_rect: Rect,
    back_hover: bool,
    actions: chrome::ActionBar,
}

impl Screen {
    fn new(current: &str) -> Self {
        let mut name = TextField::new();
        if !current.is_empty() {
            name.set(current);
        }
        Self {
            name,
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
            _ => {
                self.name.handle_key(key);
                None
            }
        }
    }

    fn handle_mouse(&mut self, event: MouseEvent) -> Option<Nav> {
        let pos = Position::new(event.column, event.row);
        self.back_hover = chrome::hit(self.back_rect, pos);
        if matches!(event.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)) {
            self.actions.track(pos);
        }
        if matches!(event.kind, MouseEventKind::Down(MouseButton::Left)) {
            if chrome::hit(self.back_rect, pos) {
                return Some(Nav::Back);
            }
            if self.actions.clicked(pos).is_some() {
                return Some(Nav::Next);
            }
        }
        None
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        self.back_rect = chrome::render_back_button(frame, area, true, self.back_hover);
        let col = ui::column(area);
        let [header, _, field, note, _, help] = col.layout(&Layout::vertical([
            Constraint::Length(3),
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Length(2),
            Constraint::Min(0),
            Constraint::Length(1),
        ]));
        ui::render_header(
            frame,
            header,
            "Create your first agent",
            "An agent is a saved configuration you can fly again and again.",
        );
        let caret = ui::render_field(frame, field, "Name", &self.name, true, "e.g. pilot");
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "Leave it blank to call it \u{201c}pilot\u{201d}. You can add more agents later.",
                Style::new().fg(FOG).add_modifier(Modifier::ITALIC),
            )))
            .wrap(Wrap { trim: true }),
            note,
        );
        ui::render_help(
            frame,
            help,
            "type name   enter continue   esc back   ^c quit",
        );
        self.actions
            .render(frame, help, &[chrome::Button::primary("Continue")]);
        if let Some(pos) = caret {
            frame.set_cursor_position(pos);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    #[test]
    fn enter_advances_and_captures_the_name() {
        let mut screen = Screen::new("");
        for ch in "navigator".chars() {
            screen.handle_key(key(KeyCode::Char(ch)));
        }
        assert_eq!(screen.handle_key(key(KeyCode::Enter)), Some(Nav::Next));
        assert_eq!(screen.name.trimmed(), "navigator");
    }

    #[test]
    fn esc_steps_back() {
        let mut screen = Screen::new("");
        assert_eq!(screen.handle_key(key(KeyCode::Esc)), Some(Nav::Back));
    }
}
