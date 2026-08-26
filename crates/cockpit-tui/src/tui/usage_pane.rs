//! `/usage` pane — vendor subscription plan/quota snapshots.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_proto::{ProviderUsageAvailabilityView, ProviderUsageSnapshotView};

pub struct UsagePane {
    generation: u64,
    rows: Result<Vec<ProviderUsageSnapshotView>, String>,
    list: ListState,
    last_body_height: usize,
    last_content_rows: usize,
}

impl UsagePane {
    pub fn loading() -> Self {
        static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);
        Self {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            rows: Err("Fetching provider usage...".to_string()),
            list: ListState::default(),
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    pub fn open(rows: Vec<ProviderUsageSnapshotView>) -> Self {
        let mut pane = Self::loading();
        pane.rows = Ok(rows);
        pane
    }

    pub fn error(message: String) -> Self {
        let mut pane = Self::loading();
        pane.rows = Err(message);
        pane
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn apply_result(&mut self, result: Result<Vec<ProviderUsageSnapshotView>, String>) {
        self.rows = result;
        *self.list.offset_mut() = 0;
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => self.scroll_up(),
            KeyCode::Down | KeyCode::Char('j') => self.scroll_down(),
            KeyCode::PageUp => {
                *self.list.offset_mut() = self
                    .list
                    .offset()
                    .saturating_sub(self.last_body_height.max(1))
            }
            KeyCode::PageDown => {
                let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
                *self.list.offset_mut() =
                    (self.list.offset() + self.last_body_height.max(1)).min(max_scroll);
            }
            KeyCode::Char('g') => *self.list.offset_mut() = 0,
            KeyCode::Char('G') => {
                *self.list.offset_mut() =
                    self.last_content_rows.saturating_sub(self.last_body_height)
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
        *self.list.offset_mut() = self.list.offset().min(max_scroll);
        frame.render_stateful_widget(
            List::new(lines.into_iter().map(ListItem::new).collect::<Vec<_>>()),
            body,
            &mut self.list,
        );
        if self.last_content_rows > self.last_body_height && body.width > 1 {
            let mut scrollbar = ScrollbarState::new(self.last_content_rows)
                .position(self.list.offset())
                .viewport_content_length(self.last_body_height);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None),
                body,
                &mut scrollbar,
            );
        }

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

    pub fn scroll_up(&mut self) {
        *self.list.offset_mut() = self.list.offset().saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        *self.list.offset_mut() = (self.list.offset() + 1).min(max_scroll);
    }

    #[cfg(test)]
    pub(crate) fn offset(&self) -> usize {
        self.list.offset()
    }

    #[cfg(test)]
    pub(crate) fn status_text(&self) -> Option<&str> {
        self.rows.as_ref().err().map(String::as_str)
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

fn render_usage_lines(snapshot: &ProviderUsageSnapshotView) -> Vec<String> {
    let mut lines = Vec::new();
    match &snapshot.availability {
        ProviderUsageAvailabilityView::Fetched {
            plan,
            windows,
            details,
            ..
        } => {
            let mut header = format!("{} ({})", snapshot.display_name, snapshot.provider_id);
            if let Some(plan) = plan.as_deref().filter(|value| !value.trim().is_empty()) {
                header.push_str(&format!(" — plan: {plan}"));
            }
            lines.push(header);
            if windows.is_empty() && details.is_empty() {
                lines.push("  No usage windows returned.".to_string());
            }
            for window in windows {
                let mut line = format!("  {}: ", window.label);
                if let Some(used) = window.used_percent {
                    let used = used.clamp(0.0, 100.0);
                    line.push_str(&format!(
                        "{:.0}% remaining ({:.0}% used)",
                        (100.0 - used).max(0.0).round(),
                        used.round()
                    ));
                } else {
                    line.push_str("usage not reported");
                }
                if let Some(reset) = window.reset_at {
                    line.push_str(&format!("; resets {}", reset.to_rfc3339()));
                }
                if let Some(detail) = window.detail.as_deref().filter(|v| !v.trim().is_empty()) {
                    line.push_str(&format!(" — {detail}"));
                }
                lines.push(line);
            }
            lines.extend(details.iter().map(|detail| format!("  {detail}")));
        }
        ProviderUsageAvailabilityView::Unsupported { reason } => lines.push(format!(
            "{} ({}) — unsupported: {reason}",
            snapshot.display_name, snapshot.provider_id
        )),
        ProviderUsageAvailabilityView::Unavailable { reason, hint_url } => {
            let suffix = hint_url
                .as_deref()
                .map_or(String::new(), |url| format!(" {url}"));
            lines.push(format!(
                "{} ({}) — unavailable: {reason}{suffix}",
                snapshot.display_name, snapshot.provider_id
            ));
        }
        ProviderUsageAvailabilityView::Error { message } => lines.push(format!(
            "{} ({}) — error: {message}",
            snapshot.display_name, snapshot.provider_id
        )),
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::ProviderUsageAvailabilityView;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn loading_body_is_non_empty() {
        let pane = UsagePane::loading();
        assert!(pane.body_lines()[0].to_string().contains("Fetching"));
    }

    #[test]
    fn stateful_list_scroll_is_bounded_and_survives_rerender() {
        let rows = (0..20)
            .map(|index| ProviderUsageSnapshotView {
                provider_id: format!("provider-{index}"),
                display_name: format!("Provider {index}"),
                fetched_at: chrono::Utc::now(),
                availability: ProviderUsageAvailabilityView::Error {
                    message: "offline".to_string(),
                },
            })
            .collect();
        let mut pane = UsagePane::open(rows);
        let mut terminal = Terminal::new(TestBackend::new(80, 8)).unwrap();
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 80, 8)))
            .unwrap();
        for _ in 0..100 {
            pane.scroll_down();
        }
        let max = pane.last_content_rows.saturating_sub(pane.last_body_height);
        assert_eq!(pane.offset(), max);
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 80, 8)))
            .unwrap();
        assert_eq!(pane.offset(), max);
        pane.scroll_up();
        assert_eq!(pane.offset(), max.saturating_sub(1));
    }
}
