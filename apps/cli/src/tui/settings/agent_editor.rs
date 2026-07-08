//! In-TUI multiline editor for an agent's `.cockpit/agents/<name>.md`
//! file (implementation note).
//!
//! This is the in-process fallback for the editor-precedence ladder when
//! `$EDITOR` is unset: a vim-mode editor when the user has vim enabled,
//! else a plain-keybinding editor. There is no dead end — one of the two
//! always handles editing the file.
//!
//! The vim machinery is **not reimplemented** here: the buffer + every
//! motion/edit/mode primitive is [`crate::tui::composer::Composer`] (the
//! same struct that backs the prompt composer). This module only supplies
//! the focused key dispatch — Normal / Operator / Insert for vim, or plain
//! editing keys — without the chat-specific concerns (history recall,
//! paste blocks, slash/`@` menus) that the composer's app-level dispatch
//! folds in. Those don't apply to editing a file on disk.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::widgets::{Paragraph, Wrap};

use crate::tui::composer::{Composer, FindSpec, Operator, VimMode};

use super::shell::text_area_lines;

/// A modal, full-file text editor over a [`Composer`]. Held by the Agents
/// page while the user is editing an agent definition in-process.
pub(super) struct AgentEditor {
    /// The agent name being edited (for the editor header / re-parse).
    pub(super) name: String,
    /// The on-disk file the buffer will be written back to.
    pub(super) path: std::path::PathBuf,
    /// Buffer + vim state. `vim_enabled` decides which dispatch the key
    /// handler routes through.
    composer: Composer,
}

/// What a key did to the editor.
pub(super) enum EditorOutcome {
    /// Stay in the editor; the keystroke was consumed (or ignored).
    Stay,
    /// Save (`:`-less — we use a single chord) and close: write the buffer
    /// back to disk. The page re-reads + re-parses afterwards.
    Save,
    /// Cancel without writing.
    Cancel,
}

impl AgentEditor {
    /// Open the editor on `path`, seeded with `text`. `vim_enabled` mirrors
    /// the user's composer setting — vim starts in Normal mode, plain starts
    /// "always inserting".
    pub(super) fn new(
        name: String,
        path: std::path::PathBuf,
        text: &str,
        vim_enabled: bool,
    ) -> Self {
        let mut composer = Composer::new(vim_enabled);
        composer.set(text);
        // Land the cursor at the top of the file, like a freshly-opened editor.
        composer.set_cursor(0);
        Self {
            name,
            path,
            composer,
        }
    }

    pub(super) fn text(&self) -> &str {
        self.composer.text()
    }

    fn vim_enabled(&self) -> bool {
        self.composer.vim_enabled()
    }

    /// Insert pasted text at the cursor. This is a full-file (multiline)
    /// editor over a [`Composer`], so the raw text — newlines included — is
    /// inserted verbatim, matching the composer's own raw paste. Condensing
    /// and image blocks are chat-only and never apply here. An empty paste
    /// is a no-op.
    pub(super) fn paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        self.composer.insert_str(text);
    }

    /// Apply a key. Save/cancel chords:
    ///   - Ctrl+S saves and closes (works in any mode).
    ///   - In plain (non-vim) mode, Esc cancels.
    ///   - In vim mode, Esc returns Insert→Normal; a second Esc (already in
    ///     Normal) cancels — matching "Esc to leave" muscle memory without
    ///     losing the mode transition.
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> EditorOutcome {
        // Ctrl+S — save from anywhere.
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
            return EditorOutcome::Save;
        }

        if self.vim_enabled() {
            match self.composer.vim_mode() {
                VimMode::Normal => self.handle_normal(key),
                VimMode::Operator(op) => self.handle_operator(key, op),
                // The agent-file editor's mini vim has no visual mode (no
                // `v`/`V` binding), so these are unreachable; treat any
                // stray visual state as Normal.
                VimMode::Insert | VimMode::Visual | VimMode::VisualLine => {
                    if self.composer.vim_mode() == VimMode::Insert {
                        self.handle_insert(key, true)
                    } else {
                        self.composer.set_vim_mode(VimMode::Normal);
                        self.handle_normal(key)
                    }
                }
            }
        } else {
            self.handle_insert(key, false)
        }
    }

    /// Insert-mode (vim) or plain-mode editing. `vim` distinguishes the two:
    /// in vim, Esc drops to Normal; in plain, Esc cancels the whole edit.
    fn handle_insert(&mut self, key: KeyEvent, vim: bool) -> EditorOutcome {
        match key.code {
            KeyCode::Esc => {
                if vim {
                    self.composer.set_vim_mode(VimMode::Normal);
                    self.composer.set_pending_g(false);
                    self.composer.set_pending_find(None);
                    EditorOutcome::Stay
                } else {
                    EditorOutcome::Cancel
                }
            }
            KeyCode::Enter => {
                // Plain Enter inserts a newline — this is a file editor, not
                // a chat input. Save is Ctrl+S.
                self.composer.insert_char('\n');
                EditorOutcome::Stay
            }
            KeyCode::Char(ch) => {
                self.composer.insert_char(ch);
                EditorOutcome::Stay
            }
            KeyCode::Backspace => {
                self.composer.delete_left();
                EditorOutcome::Stay
            }
            KeyCode::Delete => {
                self.composer.delete_right();
                EditorOutcome::Stay
            }
            KeyCode::Left => {
                self.composer.move_left();
                EditorOutcome::Stay
            }
            KeyCode::Right => {
                self.composer.move_right();
                EditorOutcome::Stay
            }
            KeyCode::Up => {
                self.composer.move_up();
                EditorOutcome::Stay
            }
            KeyCode::Down => {
                self.composer.move_down();
                EditorOutcome::Stay
            }
            KeyCode::Home => {
                self.composer.move_line_start();
                EditorOutcome::Stay
            }
            KeyCode::End => {
                self.composer.move_line_end();
                EditorOutcome::Stay
            }
            KeyCode::Tab => {
                self.composer.insert_char('\t');
                EditorOutcome::Stay
            }
            _ => EditorOutcome::Stay,
        }
    }

    /// Normal-mode vim dispatch. Mirrors the composer's Normal-mode key set
    /// (motions, mode entries, line operators) over the same primitives,
    /// minus the chat-only concerns. Esc in Normal cancels the edit.
    fn handle_normal(&mut self, key: KeyEvent) -> EditorOutcome {
        match key.code {
            KeyCode::Esc => return EditorOutcome::Cancel,
            KeyCode::Left => self.composer.move_left(),
            KeyCode::Right => self.composer.move_right(),
            KeyCode::Up => self.composer.move_up(),
            KeyCode::Down => self.composer.move_down(),
            KeyCode::Enter => self.composer.move_down(),
            KeyCode::Backspace => self.composer.move_left(),
            KeyCode::Char(ch) => {
                let was_pending_g = self.composer.pending_g();
                let pending_find = self.composer.pending_find();
                self.composer.set_pending_g(false);
                self.composer.set_pending_find(None);
                if let Some(mut spec) = pending_find {
                    spec.target = ch;
                    self.composer.apply_find(spec, true);
                    return EditorOutcome::Stay;
                }
                match ch {
                    'h' => self.composer.move_left(),
                    'l' => self.composer.move_right(),
                    'k' => self.composer.move_up(),
                    'j' => self.composer.move_down(),
                    'w' => self.composer.move_word_forward(false),
                    'W' => self.composer.move_word_forward(true),
                    'b' => self.composer.move_word_backward(false),
                    'B' => self.composer.move_word_backward(true),
                    '0' => self.composer.move_line_start(),
                    '$' => self.composer.move_line_end(),
                    'G' => self.composer.move_buffer_end(),
                    'g' => {
                        if was_pending_g {
                            self.composer.move_buffer_start();
                        } else {
                            self.composer.set_pending_g(true);
                        }
                    }
                    'f' => self.composer.set_pending_find(Some(FindSpec {
                        target: '\0',
                        till: false,
                        forward: true,
                    })),
                    'F' => self.composer.set_pending_find(Some(FindSpec {
                        target: '\0',
                        till: false,
                        forward: false,
                    })),
                    'i' => self.composer.set_vim_mode(VimMode::Insert),
                    'I' => {
                        self.composer.move_line_start();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'a' => {
                        self.composer.move_right();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'A' => {
                        self.composer.move_line_end();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'x' => self.composer.delete_right(),
                    'D' => self.composer.delete_to_line_end(),
                    'C' => {
                        self.composer.delete_to_line_end();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'o' => {
                        self.composer.open_below();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'O' => {
                        self.composer.open_above();
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                    'd' => self
                        .composer
                        .set_vim_mode(VimMode::Operator(Operator::Delete)),
                    'c' => self
                        .composer
                        .set_vim_mode(VimMode::Operator(Operator::Change)),
                    _ => {}
                }
            }
            _ => {}
        }
        EditorOutcome::Stay
    }

    /// Operator-pending: we just saw `d`/`c`; the next key is the motion.
    /// `dd`/`cc` operate linewise; `dw`/`d$`/`dgg`/… apply the operator to
    /// the motion's range. Unrecognized keys cancel back to Normal.
    fn handle_operator(&mut self, key: KeyEvent, op: Operator) -> EditorOutcome {
        let to_insert = matches!(op, Operator::Change);
        if matches!(key.code, KeyCode::Esc) {
            self.composer.set_vim_mode(VimMode::Normal);
            self.composer.set_pending_g(false);
            return EditorOutcome::Stay;
        }
        if let KeyCode::Char('g') = key.code {
            if self.composer.pending_g() {
                self.composer.delete_to_buffer_start();
                self.composer.set_pending_g(false);
                self.composer.set_vim_mode(if to_insert {
                    VimMode::Insert
                } else {
                    VimMode::Normal
                });
                return EditorOutcome::Stay;
            }
            self.composer.set_pending_g(true);
            return EditorOutcome::Stay;
        }
        self.composer.set_pending_g(false);
        let applied = match key.code {
            KeyCode::Char('w') => {
                self.composer.delete_word_forward(false);
                true
            }
            KeyCode::Char('W') => {
                self.composer.delete_word_forward(true);
                true
            }
            KeyCode::Char('b') => {
                self.composer.delete_word_backward(false);
                true
            }
            KeyCode::Char('B') => {
                self.composer.delete_word_backward(true);
                true
            }
            KeyCode::Char('$') => {
                self.composer.delete_to_line_end();
                true
            }
            KeyCode::Char('0') => {
                self.composer.delete_to_line_start();
                true
            }
            KeyCode::Char('G') => {
                self.composer.delete_to_buffer_end();
                true
            }
            KeyCode::Char('d') if matches!(op, Operator::Delete) => {
                self.composer.delete_current_line();
                true
            }
            KeyCode::Char('c') if matches!(op, Operator::Change) => {
                self.composer.move_line_start();
                self.composer.delete_to_line_end();
                true
            }
            _ => false,
        };
        self.composer.set_vim_mode(if applied && to_insert {
            VimMode::Insert
        } else {
            VimMode::Normal
        });
        EditorOutcome::Stay
    }

    /// Render the editor with the shared settings text-area frame.
    pub(super) fn render(&self, frame: &mut Frame, area: Rect) {
        let mode_label = if !self.vim_enabled() {
            "plain"
        } else {
            match self.composer.vim_mode() {
                VimMode::Insert => "insert",
                VimMode::Normal => "normal",
                VimMode::Operator(_) => "operator",
                VimMode::Visual | VimMode::VisualLine => "visual",
            }
        };
        let lines = text_area_lines(
            format!("editing {}", self.name),
            mode_label.to_string(),
            "ctrl+s: save  enter: newline  esc: cancel",
            self.text(),
            self.composer.cursor_line_col(),
        );
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};

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

    fn editor(text: &str, vim: bool) -> AgentEditor {
        AgentEditor::new(
            "builder".into(),
            std::path::PathBuf::from("builder.md"),
            text,
            vim,
        )
    }

    #[test]
    fn plain_mode_types_and_esc_cancels() {
        let mut e = editor("", false);
        for ch in "hi".chars() {
            assert!(matches!(
                e.handle_key(key(KeyCode::Char(ch))),
                EditorOutcome::Stay
            ));
        }
        assert_eq!(e.text(), "hi");
        assert!(matches!(
            e.handle_key(key(KeyCode::Esc)),
            EditorOutcome::Cancel
        ));
    }

    #[test]
    fn ctrl_s_saves_from_plain_and_vim() {
        let mut plain = editor("x", false);
        assert!(matches!(plain.handle_key(ctrl('s')), EditorOutcome::Save));
        let mut vim = editor("x", true);
        assert!(matches!(vim.handle_key(ctrl('s')), EditorOutcome::Save));
    }

    #[test]
    fn vim_starts_in_normal_and_i_inserts() {
        let mut e = editor("abc", true);
        // Normal-mode `l` moves right without typing.
        e.handle_key(key(KeyCode::Char('l')));
        assert_eq!(e.text(), "abc");
        // `i` enters insert; typing now mutates.
        e.handle_key(key(KeyCode::Char('i')));
        e.handle_key(key(KeyCode::Char('Z')));
        assert_eq!(e.text(), "aZbc");
    }

    #[test]
    fn vim_dd_deletes_line() {
        let mut e = editor("one\ntwo\nthree", true);
        // Move down to the second line, then `dd`.
        e.handle_key(key(KeyCode::Char('j')));
        e.handle_key(key(KeyCode::Char('d')));
        e.handle_key(key(KeyCode::Char('d')));
        assert_eq!(e.text(), "one\nthree");
    }

    #[test]
    fn vim_esc_in_normal_cancels_in_normal_after_insert() {
        let mut e = editor("", true);
        // Insert then Esc → back to Normal (not cancel).
        e.handle_key(key(KeyCode::Char('i')));
        assert!(matches!(
            e.handle_key(key(KeyCode::Esc)),
            EditorOutcome::Stay
        ));
        // Esc again, now in Normal → cancel.
        assert!(matches!(
            e.handle_key(key(KeyCode::Esc)),
            EditorOutcome::Cancel
        ));
    }

    #[test]
    fn vim_dw_deletes_word() {
        let mut e = editor("hello world", true);
        e.handle_key(key(KeyCode::Char('d')));
        e.handle_key(key(KeyCode::Char('w')));
        assert_eq!(e.text(), "world");
    }
}
