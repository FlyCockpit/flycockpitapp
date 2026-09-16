//! A single-line text input shared by the auth step's fields.
//!
//! This is the same editing model already used by [`super::form`]'s search
//! box and [`super::secrets`]'s password field, factored out so the API-key
//! and base-URL inputs don't reinvent caret math. It owns only the buffer and
//! a byte-offset caret; the owning screen decides masking, scrolling, and
//! where to park the real terminal cursor.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

/// Masked fields render this glyph once per character instead of the text.
const MASK: char = '•';

#[derive(Default)]
pub(super) struct TextField {
    buffer: String,
    /// Byte index into [`Self::buffer`]. Always on a char boundary.
    cursor: usize,
}

impl TextField {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn trimmed(&self) -> &str {
        self.buffer.trim()
    }

    #[cfg(test)]
    fn text(&self) -> &str {
        &self.buffer
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub(super) fn len_chars(&self) -> usize {
        self.buffer.chars().count()
    }

    pub(super) fn cursor_col(&self) -> usize {
        self.buffer[..self.cursor].chars().count()
    }

    /// Replace the contents and park the caret at the end.
    pub(super) fn set(&mut self, text: &str) {
        self.buffer = text.to_string();
        self.cursor = self.buffer.len();
    }

    fn insert(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    pub(super) fn paste(&mut self, text: &str) {
        let first_line = text.split(['\n', '\r']).next().unwrap_or("");
        if first_line.is_empty() {
            return;
        }
        self.buffer.insert_str(self.cursor, first_line);
        self.cursor += first_line.len();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.buffer[..self.cursor]
            .char_indices()
            .next_back()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.buffer.drain(prev..self.cursor);
        self.cursor = prev;
    }

    fn delete(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        let len = self.buffer[self.cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        self.buffer.drain(self.cursor..self.cursor + len);
    }

    fn left(&mut self) {
        if let Some((i, _)) = self.buffer[..self.cursor].char_indices().next_back() {
            self.cursor = i;
        }
    }

    fn right(&mut self) {
        if let Some(ch) = self.buffer[self.cursor..].chars().next() {
            self.cursor += ch.len_utf8();
        }
    }

    fn home(&mut self) {
        self.cursor = 0;
    }

    fn end(&mut self) {
        self.cursor = self.buffer.len();
    }

    fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    fn delete_word(&mut self) {
        let before = &self.buffer[..self.cursor];
        let without_trail = before.trim_end_matches(|c: char| !c.is_alphanumeric());
        let cut = without_trail.trim_end_matches(char::is_alphanumeric).len();
        self.buffer.replace_range(cut..self.cursor, "");
        self.cursor = cut;
    }

    /// Apply an edit key. Returns true when the buffer changed, so callers can
    /// clear a stale validation error. Caret-only motion returns false.
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.clear();
                true
            }
            KeyCode::Char('w') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.delete_word();
                true
            }
            KeyCode::Char(_)
                if key.modifiers.intersects(
                    KeyModifiers::CONTROL | KeyModifiers::ALT | KeyModifiers::SUPER,
                ) =>
            {
                false
            }
            KeyCode::Char(ch) => {
                self.insert(ch);
                true
            }
            KeyCode::Backspace => {
                self.backspace();
                true
            }
            KeyCode::Delete => {
                self.delete();
                true
            }
            KeyCode::Left => {
                self.left();
                false
            }
            KeyCode::Right => {
                self.right();
                false
            }
            KeyCode::Home => {
                self.home();
                false
            }
            KeyCode::End => {
                self.end();
                false
            }
            _ => false,
        }
    }

    /// The spans to draw inside `inner_width` columns, plus the caret column
    /// (relative to the field's inner origin) so the screen can place the real
    /// terminal cursor. `mask` renders the bullet glyph instead of the text;
    /// `placeholder` shows when the buffer is empty.
    pub(super) fn render(
        &self,
        inner_width: u16,
        mask: bool,
        placeholder: &str,
        ink: Color,
        placeholder_fg: Color,
    ) -> (Line<'static>, u16) {
        let avail = usize::from(inner_width).max(1);
        let cursor_col = self.cursor_col();
        // Keep the caret in view by scrolling the visible window right.
        let scroll = cursor_col.saturating_sub(avail.saturating_sub(1));

        if self.buffer.is_empty() {
            let line = Line::from(Span::styled(
                placeholder.to_string(),
                Style::new()
                    .fg(placeholder_fg)
                    .add_modifier(Modifier::ITALIC),
            ));
            return (line, 0);
        }

        let visible: String = if mask {
            std::iter::repeat_n(MASK, self.len_chars())
                .skip(scroll)
                .take(avail)
                .collect()
        } else {
            self.buffer.chars().skip(scroll).take(avail).collect()
        };
        let caret = (cursor_col - scroll).min(avail.saturating_sub(1)) as u16;
        (
            Line::from(Span::styled(visible, Style::new().fg(ink))),
            caret,
        )
    }

    /// Absolute caret position for [`ratatui::Frame::set_cursor_position`],
    /// given the field's inner drawing area.
    pub(super) fn caret_position(&self, inner: Rect) -> Option<Position> {
        if inner.width == 0 || inner.height == 0 {
            return None;
        }
        let avail = usize::from(inner.width).max(1);
        let cursor_col = self.cursor_col();
        let scroll = cursor_col.saturating_sub(avail.saturating_sub(1));
        let col = (cursor_col - scroll).min(avail.saturating_sub(1)) as u16;
        Some(Position::new(inner.x + col, inner.y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::from(code)
    }

    fn ctrl(ch: char) -> KeyEvent {
        let mut key = KeyEvent::from(KeyCode::Char(ch));
        key.modifiers = KeyModifiers::CONTROL;
        key
    }

    fn typed(text: &str) -> TextField {
        let mut field = TextField::new();
        for ch in text.chars() {
            field.handle_key(key(KeyCode::Char(ch)));
        }
        field
    }

    #[test]
    fn typing_appends_and_tracks_the_caret() {
        let field = typed("hello");
        assert_eq!(field.text(), "hello");
        assert_eq!(field.cursor_col(), 5);
    }

    #[test]
    fn backspace_and_delete_edit_around_the_caret() {
        let mut field = typed("abc");
        field.handle_key(key(KeyCode::Left));
        field.handle_key(key(KeyCode::Backspace));
        assert_eq!(field.text(), "ac");
        field.handle_key(key(KeyCode::Delete));
        assert_eq!(field.text(), "a");
    }

    #[test]
    fn ctrl_u_clears_and_ctrl_w_drops_a_word() {
        let mut field = typed("hello world");
        field.handle_key(ctrl('w'));
        assert_eq!(field.text(), "hello ");
        field.handle_key(ctrl('u'));
        assert!(field.is_empty());
    }

    #[test]
    fn paste_takes_only_the_first_line() {
        let mut field = TextField::new();
        field.paste("sk-abc\nleaked-second-line");
        assert_eq!(field.text(), "sk-abc");
    }

    #[test]
    fn trimmed_ignores_surrounding_whitespace() {
        let field = typed("  key  ");
        assert_eq!(field.trimmed(), "key");
    }

    #[test]
    fn masked_render_hides_the_text_but_keeps_the_length() {
        let field = typed("secret");
        let (line, caret) = field.render(40, true, "type", Color::White, Color::Gray);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(rendered, "••••••");
        assert!(!rendered.contains("secret"));
        assert_eq!(caret, 6);
    }

    #[test]
    fn render_scrolls_to_keep_the_caret_visible() {
        let field = typed("0123456789");
        // Only four columns of room. With the caret parked at the end it takes
        // the rightmost cell, so the window shows the last three characters and
        // the caret sits just past them.
        let (line, caret) = field.render(4, false, "", Color::White, Color::Gray);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(rendered, "789");
        assert_eq!(caret, 3);
    }

    #[test]
    fn empty_field_shows_the_placeholder() {
        let field = TextField::new();
        let (line, caret) = field.render(20, false, "type here", Color::White, Color::Gray);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(rendered, "type here");
        assert_eq!(caret, 0);
    }
}
