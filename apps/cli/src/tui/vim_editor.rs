use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Margin, Position, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use std::cell::Cell;

use crate::tui::composer::{Composer, VimMode};

pub enum VimEditorOutcome {
    Stay,
    Save,
    Cancel,
    ExternalEdit,
}

pub struct VimEditor {
    composer: Composer,
    scroll: Cell<usize>,
}

impl VimEditor {
    pub fn new(text: &str, vim_enabled: bool) -> Self {
        let mut composer = Composer::new(vim_enabled);
        composer.set(text);
        composer.set_cursor(0);
        Self {
            composer,
            scroll: Cell::new(0),
        }
    }

    pub fn text(&self) -> &str {
        self.composer.text()
    }

    pub fn paste(&mut self, text: &str) {
        if !text.is_empty() {
            self.composer.insert_str(text);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> VimEditorOutcome {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('s') => return VimEditorOutcome::Save,
                KeyCode::Char('g') => return VimEditorOutcome::ExternalEdit,
                _ => {}
            }
        }

        if matches!(key.code, KeyCode::Esc)
            && (!self.composer.vim_enabled() || self.composer.vim_mode() == VimMode::Normal)
        {
            return VimEditorOutcome::Cancel;
        }

        self.composer.handle_vim_key(key);
        VimEditorOutcome::Stay
    }

    pub fn mode_label(&self) -> &'static str {
        if !self.composer.vim_enabled() {
            "plain"
        } else {
            match self.composer.vim_mode() {
                VimMode::Insert => "insert",
                VimMode::Normal => "normal",
                VimMode::Operator(_) => "operator",
                VimMode::Visual | VimMode::VisualLine => "visual",
            }
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, title: String, help: &'static str) {
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        if inner.width == 0 || inner.height == 0 {
            return;
        }

        let body = inner.inner(Margin {
            vertical: 0,
            horizontal: 1,
        });
        if body.width == 0 || body.height == 0 {
            return;
        }

        let (cursor_line, cursor_col) = self.composer.cursor_line_col();
        let content_height = body.height.saturating_sub(1) as usize;
        if content_height == 0 {
            return;
        }
        let mut scroll = self.scroll.get();
        if cursor_line < scroll {
            scroll = cursor_line;
        } else if cursor_line >= scroll + content_height {
            scroll = cursor_line + 1 - content_height;
        }
        self.scroll.set(scroll);

        let mut lines: Vec<Line<'static>> = self
            .composer
            .text()
            .split('\n')
            .skip(scroll)
            .take(content_height)
            .map(|line| Line::from(line.to_string()))
            .collect();
        while lines.len() < content_height {
            lines.push(Line::from(""));
        }
        lines.push(Line::from(vec![
            Span::from(format!("{}  ", self.mode_label())),
            Span::from(help),
        ]));
        frame.render_widget(Paragraph::new(lines), body);

        let visible_row = cursor_line.saturating_sub(scroll);
        if visible_row < content_height {
            let clamped_col = cursor_col.min(body.width.saturating_sub(1) as usize);
            frame.set_cursor_position(Position::new(
                body.x + clamped_col as u16,
                body.y + visible_row as u16,
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::Terminal;
    use ratatui::backend::{Backend, TestBackend};
    use unicode_width::UnicodeWidthStr;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl(ch: char) -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char(ch),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    #[test]
    fn handles_mode_transitions_and_operator_motion() {
        let mut editor = VimEditor::new("alpha beta", true);
        assert_eq!(editor.mode_label(), "normal");
        editor.handle_key(key(KeyCode::Char('w')));
        editor.handle_key(key(KeyCode::Char('c')));
        editor.handle_key(key(KeyCode::Char('w')));
        assert_eq!(editor.mode_label(), "insert");
        editor.handle_key(key(KeyCode::Char('X')));
        assert_eq!(editor.text(), "alpha X");
    }

    #[test]
    fn visual_delete_uses_shared_composer_dispatch() {
        let mut editor = VimEditor::new("abcd", true);
        editor.handle_key(key(KeyCode::Char('v')));
        editor.handle_key(key(KeyCode::Char('l')));
        editor.handle_key(key(KeyCode::Char('d')));
        assert_eq!(editor.text(), "cd");
    }

    #[test]
    fn plain_keys_mode_edits_multiline_text() {
        let mut editor = VimEditor::new("", false);
        editor.handle_key(key(KeyCode::Char('a')));
        editor.handle_key(key(KeyCode::Enter));
        editor.handle_key(key(KeyCode::Char('b')));
        assert_eq!(editor.text(), "a\nb");
        assert!(matches!(
            editor.handle_key(key(KeyCode::Esc)),
            VimEditorOutcome::Cancel
        ));
    }

    #[test]
    fn ctrl_chords_request_host_actions() {
        let mut editor = VimEditor::new("x", true);
        assert!(matches!(
            editor.handle_key(ctrl('s')),
            VimEditorOutcome::Save
        ));
        assert!(matches!(
            editor.handle_key(ctrl('g')),
            VimEditorOutcome::ExternalEdit
        ));
    }

    #[test]
    fn render_places_real_cursor_and_scroll_follows() {
        let mut editor = VimEditor::new("one\ntwo\nthree\nfour", true);
        editor.handle_key(key(KeyCode::Char('G')));
        let backend = TestBackend::new(20, 4);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                editor.render(
                    frame,
                    Rect::new(0, 0, 20, 4),
                    "editing test".to_string(),
                    "ctrl+s: save",
                );
            })
            .unwrap();
        assert_eq!(
            terminal.backend_mut().get_cursor_position().unwrap(),
            Position::new(2, 1)
        );
    }

    #[test]
    fn render_cursor_counts_wide_text_columns() {
        let mut editor = VimEditor::new("a中b", true);
        editor.handle_key(key(KeyCode::Char('l')));
        editor.handle_key(key(KeyCode::Char('l')));
        let backend = TestBackend::new(20, 4);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| {
                editor.render(
                    frame,
                    Rect::new(0, 0, 20, 4),
                    "editing test".to_string(),
                    "ctrl+s: save",
                );
            })
            .unwrap();
        assert_eq!(UnicodeWidthStr::width("a中"), 3);
        assert_eq!(
            terminal.backend_mut().get_cursor_position().unwrap(),
            Position::new(5, 1)
        );
    }
}
