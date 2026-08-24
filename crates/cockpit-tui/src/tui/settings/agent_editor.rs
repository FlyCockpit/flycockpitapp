//! In-TUI multiline editor for an agent file.
//!
//! The editing engine is the shared [`crate::tui::vim_editor::VimEditor`]
//! component, which wraps the prompt composer's vim-capable buffer and key
//! dispatch. This page owns only the agent-file metadata and save/cancel
//! interpretation. Authoritative bytes are committed only by daemon RPCs;
//! `$EDITOR` receives a private host staging file under a daemon lease.

use crossterm::event::KeyEvent;
use ratatui::Frame;
use ratatui::layout::Rect;

use crate::tui::vim_editor::{VimEditor, VimEditorOutcome};

/// A modal, full-file text editor over a shared [`VimEditor`]. Held by the
/// Agents page while the user is editing an agent definition in-process.
pub(super) struct AgentEditor {
    /// The agent name being edited (for the editor header / re-parse).
    pub(super) name: String,
    /// Presentation/staging path metadata. This is never an authoritative
    /// agent or assistant destination written by the editor.
    pub(super) path: std::path::PathBuf,
    /// Opaque daemon revision captured with the editable snapshot. Both agent
    /// files and daemon-local assistant definitions require one to save; the
    /// `assistant_definition` bit selects their distinct typed mutation RPCs.
    pub(super) revision: Option<String>,
    assistant_definition: bool,
    vim_enabled: bool,
    editor: VimEditor,
}

/// What a key did to the editor.
pub(super) enum EditorOutcome {
    /// Stay in the editor; the keystroke was consumed (or ignored).
    Stay,
    /// Save and close through the source-specific revisioned daemon RPC.
    Save,
    /// Cancel without writing.
    Cancel,
    /// Defer a workspace-agent draft to `$EDITOR` through a private,
    /// identity-checked staging directory and daemon lease.
    ExternalEdit,
}

impl AgentEditor {
    /// Open the editor on `path`, seeded with `text`. `vim_enabled` mirrors
    /// the user's composer setting: vim starts in Normal mode, plain starts
    /// always inserting.
    pub(super) fn new(
        name: String,
        path: std::path::PathBuf,
        text: &str,
        vim_enabled: bool,
        revision: Option<String>,
    ) -> Self {
        Self {
            name,
            path,
            revision,
            assistant_definition: false,
            vim_enabled,
            editor: VimEditor::new(text, vim_enabled),
        }
    }

    pub(super) fn new_assistant(
        name: String,
        path: std::path::PathBuf,
        text: &str,
        vim_enabled: bool,
        revision: String,
    ) -> Self {
        let mut editor = Self::new(name, path, text, vim_enabled, Some(revision));
        editor.assistant_definition = true;
        editor
    }

    pub(super) fn is_assistant_definition(&self) -> bool {
        self.assistant_definition
    }

    pub(super) fn text(&self) -> &str {
        self.editor.text()
    }

    pub(super) fn replace_with_recovery_text(&mut self, text: &str) {
        self.editor = VimEditor::new(text, self.vim_enabled);
    }

    /// Insert pasted text at the cursor. This is a full-file multiline
    /// editor, so raw text, including newlines, is inserted verbatim.
    pub(super) fn paste(&mut self, text: &str) {
        self.editor.paste(text);
    }

    pub(super) fn set_cursor_from_visible_cell(&mut self, row: usize, col: usize) {
        self.editor.set_cursor_from_visible_cell(row, col);
    }

    /// Apply a key. Save/cancel chords:
    ///   - Ctrl+S saves and closes from any mode.
    ///   - Ctrl+G asks the host to hand a leased workspace-agent staging file
    ///     to `$EDITOR`; assistant definitions deliberately do not support it.
    ///   - In plain mode, Esc cancels.
    ///   - In vim mode, Esc leaves the active editing mode first; Esc from
    ///     normal mode cancels.
    pub(super) fn handle_key(&mut self, key: KeyEvent) -> EditorOutcome {
        match self.editor.handle_key(key) {
            VimEditorOutcome::Stay => EditorOutcome::Stay,
            VimEditorOutcome::Save => EditorOutcome::Save,
            VimEditorOutcome::Cancel => EditorOutcome::Cancel,
            VimEditorOutcome::ExternalEdit if self.assistant_definition => EditorOutcome::Stay,
            VimEditorOutcome::ExternalEdit => EditorOutcome::ExternalEdit,
        }
    }

    /// Render the editor with a real terminal cursor and scroll-follow.
    pub(super) fn render(&self, frame: &mut Frame, area: Rect) {
        let help = if self.assistant_definition {
            "ctrl+s: save  enter: newline  esc: cancel"
        } else {
            "ctrl+s: save  ctrl+g: editor  enter: newline  esc: cancel"
        };
        self.editor
            .render(frame, area, format!("editing {}", self.name), help);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::{Backend, TestBackend};
    use ratatui::layout::{Position, Rect};

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
            None,
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
    fn ctrl_g_requests_external_editor() {
        let mut e = editor("x", true);
        assert!(matches!(
            e.handle_key(ctrl('g')),
            EditorOutcome::ExternalEdit
        ));
    }

    #[test]
    fn vim_starts_in_normal_and_i_inserts() {
        let mut e = editor("abc", true);
        e.handle_key(key(KeyCode::Char('l')));
        assert_eq!(e.text(), "abc");
        e.handle_key(key(KeyCode::Char('i')));
        e.handle_key(key(KeyCode::Char('Z')));
        assert_eq!(e.text(), "aZbc");
    }

    #[test]
    fn vim_dd_deletes_line() {
        let mut e = editor(
            "one
two
three",
            true,
        );
        e.handle_key(key(KeyCode::Char('j')));
        e.handle_key(key(KeyCode::Char('d')));
        e.handle_key(key(KeyCode::Char('d')));
        assert_eq!(
            e.text(),
            "one
three"
        );
    }

    #[test]
    fn vim_visual_delete_is_available() {
        let mut e = editor("abcd", true);
        e.handle_key(key(KeyCode::Char('v')));
        e.handle_key(key(KeyCode::Char('l')));
        e.handle_key(key(KeyCode::Char('d')));
        assert_eq!(e.text(), "cd");
    }

    #[test]
    fn vim_esc_in_normal_cancels_in_normal_after_insert() {
        let mut e = editor("", true);
        e.handle_key(key(KeyCode::Char('i')));
        assert!(matches!(
            e.handle_key(key(KeyCode::Esc)),
            EditorOutcome::Stay
        ));
        assert!(matches!(
            e.handle_key(key(KeyCode::Esc)),
            EditorOutcome::Cancel
        ));
    }

    #[test]
    fn vim_dw_deletes_word() {
        let mut e = editor("abc def", true);
        e.handle_key(key(KeyCode::Char('d')));
        e.handle_key(key(KeyCode::Char('w')));
        assert_eq!(e.text(), "def");
    }

    #[test]
    fn agent_editor_renders_with_real_cursor() {
        let e = editor("a中b", true);
        let backend = TestBackend::new(20, 4);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| e.render(frame, Rect::new(0, 0, 20, 4)))
            .unwrap();
        assert_eq!(
            terminal.backend_mut().get_cursor_position().unwrap(),
            Position::new(2, 1)
        );
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(!rendered.contains('▎'));
    }
}
