//! `/usage` pane — vendor subscription plan/quota snapshots.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::providers::usage::{ProviderUsageSnapshot, render_usage_lines};
use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;

pub struct UsagePane {
    rows: Result<Vec<ProviderUsageSnapshot>, String>,
    scroll: usize,
    last_body_height: usize,
    last_content_rows: usize,
}

impl UsagePane {
    pub fn loading() -> Self {
        Self {
            rows: Err("Fetching provider usage...".to_string()),
            scroll: 0,
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn open(rows: Vec<ProviderUsageSnapshot>) -> Self {
        Self {
            rows: Ok(rows),
            scroll: 0,
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn error(message: String) -> Self {
        Self {
            rows: Err(message),
            scroll: 0,
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
            KeyCode::PageUp => {
                self.scroll = self.scroll.saturating_sub(self.last_body_height.max(1))
            }
            KeyCode::PageDown => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                self.scroll = (self.scroll + self.last_body_height.max(1)).min(max_scroll);
            }
            KeyCode::Char('g') => self.scroll = 0,
            KeyCode::Char('G') => {
                self.scroll = self.last_content_rows.saturating_sub(self.last_body_height)
            }
            _ => {}
        }
        false
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(" /usage vendor plan limits "));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let lines = self.body_lines();
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.scroll = self.scroll.min(max_scroll);
        frame.render_widget(Paragraph::new(lines).scroll((self.scroll as u16, 0)), body);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                "q quit  ↑/↓ scroll  g/G top/bottom",
                muted,
            ))),
            help_area,
        );
    }

    fn body_lines(&self) -> Vec<Line<'static>> {
        match &self.rows {
            Err(message) => vec![Line::from(Span::styled(
                message.clone(),
                Style::default().fg(Color::Yellow),
            ))],
            Ok(rows) if rows.is_empty() => vec![Line::from("No providers configured.")],
            Ok(rows) => {
                let mut lines = Vec::new();
                for (idx, row) in rows.iter().enumerate() {
                    if idx > 0 {
                        lines.push(Line::default());
                    }
                    lines.extend(render_usage_lines(row).into_iter().map(Line::from));
                }
                lines
            }
        }
    }

    fn scroll_up(&mut self) {
        self.scroll = self.scroll.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        self.scroll = (self.scroll + 1).min(max_scroll);
    }
}

impl Pane for UsagePane {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        UsagePane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        UsagePane::render(self, frame, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loading_body_is_non_empty() {
        let pane = UsagePane::loading();
        assert!(pane.body_lines()[0].to_string().contains("Fetching"));
    }
}
