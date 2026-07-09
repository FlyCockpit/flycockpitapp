#![allow(dead_code)]
//! Single-line text input for dialog fields.
//!
//! Not vim-mode aware — dialogs aren't where you live-edit prose. Handles
//! the bread-and-butter cases: char insert, backspace, delete-forward,
//! arrow keys, home/end. Wider character sets (CJK, emoji) are stored
//! by byte position; the cursor moves by char boundary.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use unicode_width::UnicodeWidthStr;

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

    pub fn cursor(&self) -> usize {
        self.cursor
    }

    pub fn split_at_cursor(&self) -> (&str, &str) {
        let mut cursor = self.cursor.min(self.buffer.len());
        while cursor > 0 && !self.buffer.is_char_boundary(cursor) {
            cursor -= 1;
        }
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
        let first_line = match text.find('\n') {
            Some(nl) => &text[..nl],
            None => text,
        };
        if first_line.is_empty() {
            return;
        }
        self.buffer.insert_str(self.cursor, first_line);
        self.cursor += first_line.len();
    }

    /// Apply a key event; returns true if the event was consumed.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char(ch) => {
                let ch = normalize_shift_char(&key, ch);
                self.buffer.insert(self.cursor, ch);
                self.cursor += ch.len_utf8();
                true
            }
            KeyCode::Backspace => {
                if self.cursor == 0 {
                    return true;
                }
                let prev = self.buffer[..self.cursor]
                    .char_indices()
                    .last()
                    .map(|(i, _)| i)
                    .unwrap_or(0);
                self.buffer.drain(prev..self.cursor);
                self.cursor = prev;
                true
            }
            KeyCode::Delete => {
                if self.cursor >= self.buffer.len() {
                    return true;
                }
                let next_len = self.buffer[self.cursor..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(0);
                self.buffer.drain(self.cursor..self.cursor + next_len);
                true
            }
            KeyCode::Left => {
                if let Some((i, _)) = self.buffer[..self.cursor].char_indices().last() {
                    self.cursor = i;
                }
                true
            }
            KeyCode::Right => {
                if let Some(ch) = self.buffer[self.cursor..].chars().next() {
                    self.cursor += ch.len_utf8();
                }
                true
            }
            KeyCode::Home => {
                self.cursor = 0;
                true
            }
            KeyCode::End => {
                self.cursor = self.buffer.len();
                true
            }
            _ => false,
        }
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
}
