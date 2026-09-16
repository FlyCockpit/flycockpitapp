//! Small building blocks shared across the chat views: a single-line text
//! input for the composer, a word-wrapper that reports line counts (so the
//! transcript can compute scroll and sticky offsets itself), and hit-testing
//! helpers for the mouse.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Position, Rect};

/// Whether `pos` falls inside `rect`. Empty rects never match, so an
/// unrendered control is never "clicked".
pub fn hit(rect: Rect, pos: Position) -> bool {
    rect.width > 0 && rect.height > 0 && rect.contains(pos)
}

/// Whether the mouse is over a painted control. Empty rects never match.
pub fn hot(rect: Rect, mouse: Option<Position>) -> bool {
    mouse.is_some_and(|pos| hit(rect, pos))
}

/// Truncate `text` to at most `width` columns, appending an ellipsis when it
/// had to cut. Counts by characters, which is close enough for this demo's
/// mostly-ASCII content.
pub fn truncate(text: &str, width: usize) -> String {
    if width == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= width {
        return text.to_string();
    }
    if width == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(width - 1).collect();
    out.push('…');
    out
}

/// Word-wrap `text` to `width` columns, preserving explicit newlines and
/// breaking words longer than the line. Always returns at least one line.
pub fn wrap(text: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let mut lines = Vec::new();
    for raw in text.split('\n') {
        if raw.is_empty() {
            lines.push(String::new());
            continue;
        }
        let mut current = String::new();
        let mut col = 0usize;
        for word in raw.split(' ') {
            let word_len = word.chars().count();
            // A word that can't fit on any line is hard-split across lines.
            if word_len > width {
                if col > 0 {
                    lines.push(std::mem::take(&mut current));
                    col = 0;
                }
                for ch in word.chars() {
                    if col == width {
                        lines.push(std::mem::take(&mut current));
                        col = 0;
                    }
                    current.push(ch);
                    col += 1;
                }
                continue;
            }
            let need = if col == 0 { word_len } else { word_len + 1 };
            if col + need > width {
                lines.push(std::mem::take(&mut current));
                col = 0;
            }
            if col > 0 {
                current.push(' ');
                col += 1;
            }
            current.push_str(word);
            col += word_len;
        }
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// A single-line editable buffer with a byte-offset caret. The same editing
/// model as the onboarding wizard's field, trimmed to what the composer needs.
#[derive(Default)]
pub struct TextField {
    buffer: String,
    /// Byte index into `buffer`; always on a char boundary.
    cursor: usize,
}

impl TextField {
    pub fn text(&self) -> &str {
        &self.buffer
    }

    pub fn trimmed(&self) -> &str {
        self.buffer.trim()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.trim().is_empty()
    }

    pub fn clear(&mut self) {
        self.buffer.clear();
        self.cursor = 0;
    }

    /// Replace the whole buffer, parking the caret at the end. Used by the
    /// command palette's tab-completion.
    pub fn set_text(&mut self, text: &str) {
        self.buffer.clear();
        self.buffer.push_str(text);
        self.cursor = self.buffer.len();
    }

    fn insert(&mut self, ch: char) {
        self.buffer.insert(self.cursor, ch);
        self.cursor += ch.len_utf8();
    }

    /// Insert a hard line break at the caret. Bound to Shift+Enter (and Alt+Enter
    /// as a fallback on terminals that can't report Shift+Enter) so the composer
    /// can hold multi-line messages while plain Enter still sends.
    pub fn insert_newline(&mut self) {
        self.insert('\n');
    }

    /// Byte index of the start of the logical line the caret sits on.
    fn line_start(&self) -> usize {
        self.buffer[..self.cursor]
            .rfind('\n')
            .map(|i| i + 1)
            .unwrap_or(0)
    }

    /// Byte index of the end of the logical line the caret sits on.
    fn line_end(&self) -> usize {
        self.buffer[self.cursor..]
            .find('\n')
            .map(|i| self.cursor + i)
            .unwrap_or(self.buffer.len())
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

    fn delete_word(&mut self) {
        let before = &self.buffer[..self.cursor];
        let without_trail = before.trim_end_matches(|c: char| !c.is_alphanumeric());
        let cut = without_trail.trim_end_matches(char::is_alphanumeric).len();
        self.buffer.replace_range(cut..self.cursor, "");
        self.cursor = cut;
    }

    /// Apply one edit key. Returns true when text was inserted or removed.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
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
                self.cursor = self.line_start();
                false
            }
            KeyCode::End => {
                self.cursor = self.line_end();
                false
            }
            _ => false,
        }
    }

    /// How many visual rows the buffer occupies when wrapped to `width`.
    pub fn line_count(&self, width: usize) -> usize {
        wrap(&self.buffer, width).len().max(1)
    }

    /// Lay the buffer out for a multi-row composer: the visible wrapped rows
    /// (at most `max_rows`, scrolled to keep the caret in view) and the caret's
    /// `(row, col)` within that window.
    ///
    /// The caret is located by wrapping the text *before* the cursor to the same
    /// width: word-break decisions up to the caret match the full wrap, so the
    /// prefix's last row gives the caret's row and column directly.
    pub fn layout(&self, width: usize, max_rows: usize) -> (Vec<String>, u16, u16) {
        let width = width.max(1);
        let max_rows = max_rows.max(1);
        let rows = wrap(&self.buffer, width);
        let prefix_rows = wrap(&self.buffer[..self.cursor], width);
        let caret_row_abs = prefix_rows.len().saturating_sub(1);
        let caret_col = prefix_rows.last().map(|r| r.chars().count()).unwrap_or(0);

        let scroll = if caret_row_abs >= max_rows {
            caret_row_abs + 1 - max_rows
        } else {
            0
        };
        let end = (scroll + max_rows).min(rows.len());
        let visible = rows[scroll..end].to_vec();
        ((visible), (caret_row_abs - scroll) as u16, caret_col as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_breaks_on_word_boundaries() {
        let lines = wrap("the quick brown fox", 9);
        assert_eq!(lines, vec!["the quick", "brown fox"]);
    }

    #[test]
    fn wrap_preserves_blank_lines() {
        let lines = wrap("a\n\nb", 10);
        assert_eq!(lines, vec!["a", "", "b"]);
    }

    #[test]
    fn wrap_hard_splits_an_overlong_word() {
        let lines = wrap("abcdefgh", 3);
        assert_eq!(lines, vec!["abc", "def", "gh"]);
    }

    #[test]
    fn truncate_appends_an_ellipsis() {
        assert_eq!(truncate("hello world", 8), "hello w…");
        assert_eq!(truncate("hi", 8), "hi");
    }

    #[test]
    fn typing_and_backspace_track_the_caret() {
        let mut field = TextField::default();
        for ch in "abc".chars() {
            field.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        field.handle_key(KeyEvent::from(KeyCode::Left));
        field.handle_key(KeyEvent::from(KeyCode::Backspace));
        assert_eq!(field.text(), "ac");
        let (_, row, col) = field.layout(80, 4);
        assert_eq!((row, col), (0, 1));
    }

    #[test]
    fn insert_newline_splits_into_visual_rows() {
        let mut field = TextField::default();
        for ch in "ab".chars() {
            field.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        field.insert_newline();
        field.handle_key(KeyEvent::from(KeyCode::Char('c')));
        assert_eq!(field.text(), "ab\nc");
        assert_eq!(field.line_count(80), 2);
        // Caret sits on the second row after the single 'c'.
        let (rows, row, col) = field.layout(80, 4);
        assert_eq!(rows, vec!["ab".to_string(), "c".to_string()]);
        assert_eq!((row, col), (1, 1));
    }

    #[test]
    fn layout_wraps_long_input_and_places_the_caret() {
        let mut field = TextField::default();
        field.set_text("the quick brown fox");
        // Width 9 wraps to ["the quick", "brown fox"]; caret is at the end.
        let (rows, row, col) = field.layout(9, 4);
        assert_eq!(rows, vec!["the quick".to_string(), "brown fox".to_string()]);
        assert_eq!((row, col), (1, 9));
        assert_eq!(field.line_count(9), 2);
    }

    #[test]
    fn layout_scrolls_to_keep_the_caret_visible() {
        let mut field = TextField::default();
        field.set_text("a\nb\nc\nd\ne");
        // Only two rows fit; the window follows the caret to the last row.
        let (rows, row, _) = field.layout(80, 2);
        assert_eq!(rows, vec!["d".to_string(), "e".to_string()]);
        assert_eq!(row, 1);
    }

    #[test]
    fn home_and_end_are_line_relative() {
        let mut field = TextField::default();
        field.set_text("first\nsecond");
        field.handle_key(KeyEvent::from(KeyCode::Home));
        // Home moves to the start of the second (current) line, not the buffer.
        let (_, row, col) = field.layout(80, 4);
        assert_eq!((row, col), (1, 0));
        field.handle_key(KeyEvent::from(KeyCode::End));
        let (_, row, col) = field.layout(80, 4);
        assert_eq!((row, col), (1, 6));
    }
}
