//! Background agent lifetime choice for the onboarding shell.

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};

use super::theme::{BRASS, FOG, INK};
use super::ui::{RADIO_OFF, RADIO_ON};

const ROWS: [&str; 2] = [
    "Keep agents running in the background",
    "Stop the daemon when the last client leaves",
];

const DETAIL: &str = "On keeps agents and sessions running so you can reattach later. Off uses an ephemeral lifetime: closing the last client stops agents and owned processes.";

pub(crate) struct LifetimeScreen {
    cursor: usize,
}

impl LifetimeScreen {
    pub(crate) fn new() -> Self {
        Self { cursor: 0 }
    }

    pub(crate) fn background_agents(&self) -> bool {
        self.cursor == 0
    }

    pub(crate) fn submit(&self) -> bool {
        self.background_agents()
    }

    pub(crate) fn move_choice(&mut self, delta: isize) {
        self.cursor = if delta < 0 {
            crate::tui::nav::wrap_prev(self.cursor, ROWS.len())
        } else {
            crate::tui::nav::wrap_next(self.cursor, ROWS.len())
        };
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => self.move_choice(-1),
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => self.move_choice(1),
            KeyCode::Char(' ') => {}
            _ => {}
        }
    }

    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent, row_rects: &[Rect]) {
        if !matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left)) {
            return;
        }
        let Some(index) = row_rects
            .iter()
            .position(|rect| rect.contains((mouse.column, mouse.row).into()))
        else {
            return;
        };
        self.cursor = index;
    }

    pub(crate) fn detail_lines(&self) -> Vec<Line<'static>> {
        vec![Line::from(Span::styled(
            DETAIL.to_string(),
            Style::new().fg(FOG),
        ))]
    }

    pub(crate) fn lines(&self) -> Vec<Line<'static>> {
        let selected = Style::default().fg(BRASS).add_modifier(Modifier::BOLD);
        ROWS.iter()
            .enumerate()
            .map(|(index, label)| {
                let row_style = if self.cursor == index {
                    selected
                } else {
                    Style::default().fg(INK)
                };
                Line::from(vec![
                    Span::styled(
                        if self.cursor == index {
                            RADIO_ON
                        } else {
                            RADIO_OFF
                        },
                        row_style,
                    ),
                    Span::styled(*label, row_style),
                ])
            })
            .collect()
    }
}
