#![allow(dead_code)]
//! Single-line text input for dialog fields.
//!
//! Not vim-mode aware — dialogs aren't where you live-edit prose. Handles
//! the bread-and-butter cases: char insert, backspace, delete-forward,
//! arrow keys, home/end. Wider character sets (CJK, emoji) are stored
//! by byte position; the cursor moves by char boundary.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

/// Masked fields render this glyph once per character instead of the text.
const MASK: char = '•';

/// Defensive backstop for the kitty keyboard protocol: when a printable
/// char arrives with a *bare* SHIFT modifier (exactly SHIFT — no CONTROL,
/// ALT, or SUPER) and it is a lowercase letter, return its uppercase form;
/// otherwise return the char unchanged. Narrow by design — letters only;
/// layout-correct shifting of digits/symbols is the terminal's job. Never
/// fires on the native path (which delivers `Char('A')` with no SHIFT).
/// Shared by the composer and every [`TextField`] insertion site.
pub fn normalize_shift_char(key: &KeyEvent, ch: char) -> char {
    if key.modifiers == KeyModifiers::SHIFT && ch.is_ascii_lowercase() {
        ch.to_ascii_uppercase()
    } else {
        ch
    }
}

#[derive(Debug, Clone, Default)]
pub struct TextField {
    buffer: String,
    cursor: usize,
}

impl TextField {
    pub fn new(initial: impl Into<String>) -> Self {
        let buffer = initial.into();
        let cursor = buffer.len();
        Self { buffer, cursor }
    }

    pub fn text(&self) -> &str {
        &self.buffer
    }

    pub fn trimmed(&self) -> &str {
        self.buffer.trim()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn len_chars(&self) -> usize {
        self.buffer.chars().count()
    }

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn split_at_cursor(&self) -> (&str, &str) {
        let cursor = cockpit_host::text::floor_char_boundary(&self.buffer, self.cursor);
        self.buffer.split_at(cursor)
    }

    pub fn set(&mut self, value: impl Into<String>) {
        self.buffer = value.into();
        self.cursor = self.buffer.len();
    }

    /// Insert pasted text at the cursor, matching char-insert semantics
    /// (UTF-8 aware; the cursor advances by the inserted byte length).
    /// Single-line fields take only the text up to the first newline and
    /// drop that newline and everything after it; an empty paste (or one
    /// empty after that truncation) is a no-op.
    pub fn paste(&mut self, text: &str) {
        let first_line = text.split(['\n', '\r']).next().unwrap_or("");
        if first_line.is_empty() {
            return;
        }
        self.buffer.insert_str(self.cursor, first_line);
        self.cursor += first_line.len();
    }

    fn insert(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    fn backspace(&mut self) {
        if self.cursor == 0 {
            return;
        }
        let prev = self.buffer[..self.cursor]
            .char_indices()
            .last()
            .map(|(i, _)| i)
            .unwrap_or(0);
        self.buffer.drain(prev..self.cursor);
        self.cursor = prev;
    }

    fn delete(&mut self) {
        if self.cursor >= self.buffer.len() {
            return;
        }
        let next_len = self.buffer[self.cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(0);
        self.buffer.drain(self.cursor..self.cursor + next_len);
    }

    fn left(&mut self) {
        if let Some((i, _)) = self.buffer[..self.cursor].char_indices().last() {
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
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('u' | 'U') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.clear();
                true
            }
            KeyCode::Char('w' | 'W') if key.modifiers.contains(KeyModifiers::CONTROL) => {
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
                self.insert(normalize_shift_char(&key, ch));
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
    pub fn render(
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
    pub fn caret_position(&self, inner: Rect) -> Option<Position> {
        if inner.width == 0 || inner.height == 0 {
            return None;
        }
        let avail = usize::from(inner.width).max(1);
        let cursor_col = self.cursor_col();
        let scroll = cursor_col.saturating_sub(avail.saturating_sub(1));
        let col = (cursor_col - scroll).min(avail.saturating_sub(1)) as u16;
        Some(Position::new(inner.x + col, inner.y))
    }

    /// Char column (not byte). For cursor placement only.
    pub fn cursor_col(&self) -> usize {
        self.buffer[..self.cursor].chars().count()
    }

    /// Display-column of the caret: the rendered width (in terminal cells)
    /// of the text before the cursor. Accounts for wide (CJK) and
    /// multi-byte glyphs so a parked terminal cursor lines up with the
    /// character the user is about to edit.
    pub fn cursor_display_col(&self) -> usize {
        self.buffer[..self.cursor].width()
    }

    /// Place the caret at the nearest display-cell boundary without
    /// splitting combining-mark or common ZWJ grapheme sequences.
    pub fn set_cursor_display_col(&mut self, target: usize) {
        use unicode_width::UnicodeWidthChar;

        let mut byte = 0;
        let mut display = 0;
        let mut chars = self.buffer.char_indices().peekable();
        while let Some((start, ch)) = chars.next() {
            let mut end = start + ch.len_utf8();
            let mut width = ch.width().unwrap_or(0);
            let mut join_next = false;
            while let Some(&(next_start, next)) = chars.peek() {
                let next_width = next.width().unwrap_or(0);
                if next_width == 0 || join_next {
                    let _ = chars.next();
                    end = next_start + next.len_utf8();
                    join_next = next == '\u{200d}';
                    if !join_next {
                        width = width.max(next_width);
                    }
                } else {
                    break;
                }
            }
            if target <= display + width / 2 {
                self.cursor = byte;
                return;
            }
            byte = end;
            display += width;
            if target < display {
                self.cursor = byte;
                return;
            }
        }
        self.cursor = self.buffer.len();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn insert_chars_and_backspace() {
        let mut tf = TextField::default();
        tf.handle_key(key(KeyCode::Char('a')));
        tf.handle_key(key(KeyCode::Char('b')));
        tf.handle_key(key(KeyCode::Char('c')));
        assert_eq!(tf.text(), "abc");
        assert_eq!(tf.cursor_col(), 3);
        tf.handle_key(key(KeyCode::Backspace));
        assert_eq!(tf.text(), "ab");
    }

    #[test]
    fn display_column_caret_does_not_split_wide_or_combining_clusters() {
        let mut field = TextField::new("a界e\u{301}z");
        field.set_cursor_display_col(2);
        assert_eq!(field.split_at_cursor(), ("a", "界e\u{301}z"));
        field.set_cursor_display_col(3);
        assert_eq!(field.split_at_cursor(), ("a界", "e\u{301}z"));
        field.set_cursor_display_col(4);
        assert_eq!(field.split_at_cursor(), ("a界e\u{301}", "z"));
    }

    #[test]
    fn arrows_move_by_char_boundary() {
        let mut tf = TextField::new("héllo");
        assert_eq!(tf.cursor_col(), 5);
        tf.handle_key(key(KeyCode::Home));
        assert_eq!(tf.cursor_col(), 0);
        tf.handle_key(key(KeyCode::Right));
        tf.handle_key(key(KeyCode::Right));
        assert_eq!(tf.cursor_col(), 2);
    }

    #[test]
    fn split_at_cursor_respects_utf8_boundaries() {
        let mut tf = TextField::new("hé中");
        tf.handle_key(key(KeyCode::Home));
        tf.handle_key(key(KeyCode::Right));
        tf.handle_key(key(KeyCode::Right));

        assert_eq!(tf.split_at_cursor(), ("hé", "中"));
    }

    #[test]
    fn paste_inserts_at_cursor() {
        let mut tf = TextField::new("abef");
        // Move cursor between 'b' and 'e'.
        tf.handle_key(key(KeyCode::Left));
        tf.handle_key(key(KeyCode::Left));
        tf.paste("cd");
        assert_eq!(tf.text(), "abcdef");
        // Cursor advanced past the inserted text.
        assert_eq!(tf.cursor_col(), 4);
        // Continue inserting at the new cursor position.
        tf.handle_key(key(KeyCode::Char('X')));
        assert_eq!(tf.text(), "abcdXef");
    }

    #[test]
    fn paste_takes_only_first_line() {
        let mut tf = TextField::default();
        tf.paste("ANTHROPIC_API_KEY\nignored\nrest");
        assert_eq!(tf.text(), "ANTHROPIC_API_KEY");
        assert_eq!(tf.cursor_col(), "ANTHROPIC_API_KEY".chars().count());
        // A trailing newline inserts the value without the newline.
        let mut tf2 = TextField::default();
        tf2.paste("secret\n");
        assert_eq!(tf2.text(), "secret");
    }

    #[test]
    fn paste_empty_or_empty_first_line_is_noop() {
        let mut tf = TextField::new("keep");
        tf.handle_key(key(KeyCode::Home));
        tf.paste("");
        assert_eq!(tf.text(), "keep");
        assert_eq!(tf.cursor_col(), 0);
        // Leading newline → empty first line → no-op.
        tf.paste("\ndiscarded");
        assert_eq!(tf.text(), "keep");
        assert_eq!(tf.cursor_col(), 0);
    }

    #[test]
    fn delete_removes_char_forward() {
        let mut tf = TextField::new("abc");
        tf.handle_key(key(KeyCode::Home));
        tf.handle_key(key(KeyCode::Delete));
        assert_eq!(tf.text(), "bc");
    }

    /// Kitty-protocol backstop: a bare-SHIFT lowercase letter inserts its
    /// uppercase form; no modifiers leaves it lowercase; a CONTROL chord is
    /// untouched by the uppercase path.
    #[test]
    fn shift_letter_normalizes_to_uppercase() {
        let modifiers = |mods: KeyModifiers| KeyEvent {
            code: KeyCode::Char('a'),
            modifiers: mods,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };

        // Bare SHIFT + lowercase letter → uppercase inserted.
        let shift = modifiers(KeyModifiers::SHIFT);
        assert_eq!(normalize_shift_char(&shift, 'a'), 'A');
        let mut tf = TextField::default();
        tf.handle_key(shift);
        assert_eq!(tf.text(), "A");

        // No modifiers → unchanged lowercase.
        let plain = modifiers(KeyModifiers::empty());
        assert_eq!(normalize_shift_char(&plain, 'a'), 'a');
        let mut tf = TextField::default();
        tf.handle_key(plain);
        assert_eq!(tf.text(), "a");

        // CONTROL present → not uppercased by this path.
        let ctrl = modifiers(KeyModifiers::CONTROL);
        assert_eq!(normalize_shift_char(&ctrl, 'a'), 'a');
        let ctrl_shift = modifiers(KeyModifiers::CONTROL | KeyModifiers::SHIFT);
        assert_eq!(normalize_shift_char(&ctrl_shift, 'a'), 'a');
    }

    fn ctrl(ch: char) -> KeyEvent {
        let mut key = key(KeyCode::Char(ch));
        key.modifiers = KeyModifiers::CONTROL;
        key
    }

    fn typed(text: &str) -> TextField {
        let mut field = TextField::new("");
        for ch in text.chars() {
            field.handle_key(key(KeyCode::Char(ch)));
        }
        field
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
    fn caret_motion_does_not_report_a_buffer_change() {
        let mut field = typed("ab");
        assert!(!field.handle_key(key(KeyCode::Left)));
        assert!(!field.handle_key(key(KeyCode::Home)));
        assert!(!field.handle_key(key(KeyCode::End)));
        assert_eq!(field.text(), "ab");
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
        let (line, caret) = field.render(4, false, "", Color::White, Color::Gray);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(rendered, "789");
        assert_eq!(caret, 3);
    }

    #[test]
    fn empty_field_shows_the_placeholder() {
        let field = TextField::new("");
        let (line, caret) = field.render(20, false, "type here", Color::White, Color::Gray);
        let rendered: String = line.spans.iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(rendered, "type here");
        assert_eq!(caret, 0);
    }

    #[test]
    fn caret_position_parks_inside_the_inner_rect() {
        let field = typed("hi");
        let inner = Rect {
            x: 4,
            y: 2,
            width: 10,
            height: 1,
        };
        assert_eq!(field.caret_position(inner), Some(Position::new(6, 2)));
    }
}
