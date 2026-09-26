use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::Span;
use ratatui::widgets::Paragraph;

use super::ui;
use crate::tui::textfield::TextField;
use crate::tui::theme::BAD;

pub(crate) struct ProfileScreen {
    name: TextField,
    field_rect: Rect,
    status: Option<&'static str>,
}

impl ProfileScreen {
    pub(crate) fn new() -> Self {
        let prefill = ["USER", "USERNAME"]
            .into_iter()
            .find_map(|name| std::env::var(name).ok())
            .map(|name| name.trim().to_string())
            .filter(|name| !name.is_empty())
            .unwrap_or_default();
        Self {
            name: TextField::new(prefill),
            field_rect: Rect::default(),
            status: None,
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<String> {
        if matches!(key.code, KeyCode::Enter) {
            return self.submit();
        }
        self.name.handle_key(key);
        self.status = None;
        None
    }

    pub(crate) fn submit(&mut self) -> Option<String> {
        let name = self.name.text().to_string();
        if name.chars().count() > 80 {
            self.status = Some("name must be 80 characters or fewer");
            return None;
        }
        if name.chars().any(char::is_control) {
            self.status = Some("name cannot contain control characters");
            return None;
        }
        self.status = None;
        Some(name)
    }

    pub(crate) fn paste(&mut self, text: &str) {
        self.name.paste(text);
        self.status = None;
    }

    /// Forget the previous frame's field rectangle.
    pub(crate) fn clear_hit_geometry(&mut self) {
        self.field_rect = Rect::default();
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.field_rect = Rect {
            x: area.x,
            y: area.y,
            width: area.width,
            height: 3.min(area.height),
        };
        if let Some(caret) = ui::render_field(
            frame,
            self.field_rect,
            "Name",
            &self.name,
            true,
            "leave blank to skip",
        ) {
            frame.set_cursor_position(caret);
        }
        if let Some(status) = self.status
            && area.height > 4
        {
            frame.render_widget(
                Paragraph::new(Span::styled(status, Style::new().fg(BAD))),
                Rect {
                    x: area.x,
                    y: area.y.saturating_add(4),
                    width: area.width,
                    height: 1,
                },
            );
        }
    }

    pub(crate) fn field_rect(&self) -> Rect {
        self.field_rect
    }
}
