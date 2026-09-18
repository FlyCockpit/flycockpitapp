use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;

use super::ui;
use crate::tui::textfield::TextField;

pub(crate) struct ProfileScreen {
    name: TextField,
    field_rect: Rect,
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
        }
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<String> {
        if matches!(key.code, KeyCode::Enter) {
            return self.submit();
        }
        self.name.handle_key(key);
        None
    }

    pub(crate) fn submit(&self) -> Option<String> {
        let name = self.name.text().to_string();
        (name.chars().count() <= 80 && !name.chars().any(char::is_control)).then_some(name)
    }

    pub(crate) fn paste(&mut self, text: &str) {
        self.name.paste(text);
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
    }

    pub(crate) fn field_rect(&self) -> Rect {
        self.field_rect
    }
}
