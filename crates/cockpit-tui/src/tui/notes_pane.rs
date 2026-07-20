//! `/scratchpad` pane — a project-scoped markdown scratchpad (prompt
//! `notes-scratchpad.md`).
//!
//! A floating dialog over the chat body: a sidebar lists the project's notes
//! by name (plus a "+ new note" affordance); the main pane shows the selected
//! note. Notes are scoped to the **project root** and persist in the global
//! cockpit DB ([`crate::db::project_notes`]), so the same notes appear across
//! every session in that project. Notes are pure TUI/DB state — they never
//! enter any outbound model prompt (token economy, GOALS §10).
//!
//! View vs edit (markdown): a *viewed* note renders its content through the
//! shared markdown renderer ([`crate::tui::markdown::render_with_width`]).
//! Entering edit mode switches the main pane to a **raw editable text**
//! buffer (the markdown source); leaving edit mode re-renders. The two never
//! coexist in the pane.
//!
//! Vim: the editor reuses the composer's vim engine — it holds a
//! [`crate::tui::composer::Composer`] and drives it via
//! [`Composer::handle_vim_key`], the same motions/operators/text-objects the
//! main composer uses. No second vim implementation. When vim is off, editing
//! is plain text entry through the same path.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use uuid::Uuid;

use crate::db::Db;
use crate::db::project_notes::ProjectNote;
use crate::tui::composer::Composer;
use crate::tui::markdown;
use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;

/// Which part of the dialog has focus / what the user is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Browsing the sidebar; the selected note (if any) renders read-only in
    /// the main pane.
    Browsing,
    /// Editing the selected note's raw markdown source in the main pane.
    Editing,
    /// A single-line name prompt is up. `for_note` is `Some(id)` for a rename
    /// and `None` for a create. `buffer` holds the typed name.
    Naming {
        for_note: Option<Uuid>,
        buffer: String,
    },
    /// Delete confirmation for the selected note.
    ConfirmingDelete,
}

/// The notes dialog state. Opened over the chat body; routed input/render by
/// `App` alongside the other panes.
pub struct NotesPane {
    /// Project-root scoping key (git/worktree root, or launch cwd).
    project_root: String,
    /// Owned DB handle for note CRUD. `None` when the global DB couldn't be
    /// opened — the dialog still renders (with an inline error) but every
    /// mutating action is a no-op until it's reachable.
    db: Option<Db>,
    /// Loaded notes for this project, in sidebar order.
    notes: Vec<ProjectNote>,
    /// Selected sidebar index into `notes` (0-based). Clamped to the list.
    selected: usize,
    mode: Mode,
    /// The reused composer editing engine for the raw-markdown editor. Holds
    /// the note source while [`Mode::Editing`]; honors vim when enabled.
    editor: Composer,
    /// Whether vim editing is enabled (mirrors the user's composer setting).
    vim_enabled: bool,
    /// Markdown render scroll offset (rows) for the viewed note.
    view_scroll: usize,
    /// Raw editor vertical scroll offset while editing a note.
    edit_scroll: usize,
    /// Last main-pane content width/height — for render-side scroll clamping.
    last_view_width: usize,
    last_view_height: usize,
    last_view_rows: usize,
    /// A transient error/status line shown under the sidebar (e.g. a failed
    /// DB write). Cleared on the next successful action.
    status: Option<String>,
}

/// Outcome of routing a key to the pane.
pub enum NotesOutcome {
    /// Stay open.
    Stay,
    /// Close the dialog and return focus to the composer/transcript.
    Close,
}

impl NotesPane {
    /// The which-key descriptor for this pane (`crate::tui::keys_overlay`).
    /// Static + data-driven so the overlay never scrapes the help line.
    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Scratchpad",
            bindings: &[
                KeyBinding {
                    key: "↑/↓",
                    action: "move",
                    desc: "highlight a note (or the + new row)",
                },
                KeyBinding {
                    key: "Enter · e",
                    action: "edit",
                    desc: "edit the highlighted note",
                },
                KeyBinding {
                    key: "n",
                    action: "new",
                    desc: "create a new note",
                },
                KeyBinding {
                    key: "r",
                    action: "rename",
                    desc: "rename the highlighted note",
                },
                KeyBinding {
                    key: "d",
                    action: "delete",
                    desc: "delete the highlighted note",
                },
                KeyBinding {
                    key: "Ctrl+S",
                    action: "save",
                    desc: "save + leave edit mode",
                },
                KeyBinding {
                    key: "q · Esc",
                    action: "close",
                    desc: "close the scratchpad",
                },
            ],
        }
    }

    /// Open the dialog for `cwd`, resolving the project root (git/worktree
    /// root, falling back to `cwd`) and loading that project's notes. A DB
    /// failure is surfaced inline rather than refusing to open.
    pub fn open(cwd: &std::path::Path, vim_enabled: bool) -> Self {
        let project_root = crate::git::find_worktree_root(cwd)
            .unwrap_or_else(|| cwd.to_path_buf())
            .to_string_lossy()
            .into_owned();
        let (db, notes, status) = match Db::open_default() {
            Ok(db) => match db.list_project_notes(&project_root) {
                Ok(notes) => (Some(db), notes, None),
                Err(e) => (Some(db), Vec::new(), Some(format!("load failed: {e}"))),
            },
            Err(e) => (None, Vec::new(), Some(format!("db unavailable: {e}"))),
        };
        Self {
            project_root,
            db,
            notes,
            selected: 0,
            mode: Mode::Browsing,
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            last_view_width: 0,
            last_view_height: 0,
            last_view_rows: 0,
            status,
        }
    }

    /// Currently-selected note, if any.
    fn current(&self) -> Option<&ProjectNote> {
        self.notes.get(self.selected)
    }

    /// Reload notes from the DB after a mutation, keeping `id` selected when
    /// it still exists (else clamping).
    fn reload(&mut self, keep: Option<Uuid>) {
        let Some(db) = self.db.clone() else {
            return;
        };
        match db.list_project_notes(&self.project_root) {
            Ok(notes) => {
                self.notes = notes;
                if let Some(id) = keep
                    && let Some(idx) = self.notes.iter().position(|n| n.id == id)
                {
                    self.selected = idx;
                }
                if self.selected >= self.notes.len() {
                    self.selected = self.notes.len().saturating_sub(1);
                }
                self.status = None;
            }
            Err(e) => self.status = Some(format!("reload failed: {e}")),
        }
    }

    /// Begin editing the selected note: load its source into the reused
    /// composer and switch the pane to the raw editor. No-op with no note.
    fn enter_edit(&mut self) {
        let Some(content) = self.current().map(|n| n.content.clone()) else {
            return;
        };
        self.editor = Composer::new(self.vim_enabled);
        self.editor.set(content);
        // Park the cursor at the start so a fresh edit begins at the top.
        self.editor.set_cursor(0);
        self.mode = Mode::Editing;
    }

    /// Persist the editor buffer back to the selected note and return to the
    /// rendered view.
    fn leave_edit(&mut self) {
        if let Some(note) = self.current()
            && let Some(db) = self.db.clone()
        {
            let id = note.id;
            if let Err(e) = db.set_project_note_content(id, self.editor.text()) {
                self.status = Some(format!("save failed: {e}"));
            }
            self.reload(Some(id));
        }
        self.mode = Mode::Browsing;
        self.view_scroll = 0;
    }

    /// Handle a key. Returns the outcome (stay / close).
    pub fn handle_key(&mut self, key: KeyEvent) -> NotesOutcome {
        match &self.mode {
            Mode::Naming { .. } => self.handle_naming_key(key),
            Mode::ConfirmingDelete => self.handle_confirm_delete_key(key),
            Mode::Editing => self.handle_editing_key(key),
            Mode::Browsing => self.handle_browsing_key(key),
        }
    }

    pub fn paste(&mut self, text: &str) {
        match &mut self.mode {
            Mode::Editing => {
                if text.is_empty() {
                    return;
                }
                let normalized = text.replace("\r\n", "\n").replace('\r', "");
                self.editor.insert_str(&normalized);
            }
            Mode::Naming { buffer, .. } => {
                let Some(first_line) = text.split('\n').next() else {
                    return;
                };
                if first_line.is_empty() {
                    return;
                }
                buffer.push_str(&first_line.replace('\r', ""));
            }
            Mode::Browsing | Mode::ConfirmingDelete => {}
        }
    }

    fn handle_browsing_key(&mut self, key: KeyEvent) -> NotesOutcome {
        // `+ new note` row sits at index == notes.len().
        let new_row = self.notes.len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return NotesOutcome::Close,
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                self.view_scroll = 0;
            }
            // Allow landing on the `+ new note` row (one past the last
            // note).
            KeyCode::Down | KeyCode::Char('j') if self.selected < new_row => {
                self.selected += 1;
                self.view_scroll = 0;
            }
            KeyCode::Enter => {
                if self.selected == new_row {
                    self.start_create();
                } else if self.current().is_some() {
                    self.enter_edit();
                }
            }
            KeyCode::Char('n') => self.start_create(),
            KeyCode::Char('e') if self.selected < new_row => {
                self.enter_edit();
            }
            KeyCode::Char('r') => {
                if let Some(note) = self.current() {
                    self.mode = Mode::Naming {
                        for_note: Some(note.id),
                        buffer: note.name.clone(),
                    };
                }
            }
            KeyCode::Char('d') if self.current().is_some() => {
                self.mode = Mode::ConfirmingDelete;
            }
            KeyCode::PageDown => {
                self.scroll_view_down_page();
            }
            KeyCode::PageUp => {
                self.view_scroll = self
                    .view_scroll
                    .saturating_sub(self.last_view_height.max(1));
            }
            _ => {}
        }
        NotesOutcome::Stay
    }

    fn start_create(&mut self) {
        self.mode = Mode::Naming {
            for_note: None,
            buffer: String::new(),
        };
    }

    fn handle_naming_key(&mut self, key: KeyEvent) -> NotesOutcome {
        let Mode::Naming { for_note, buffer } = &mut self.mode else {
            return NotesOutcome::Stay;
        };
        let for_note = *for_note;
        match key.code {
            KeyCode::Esc => {
                self.mode = Mode::Browsing;
            }
            KeyCode::Enter => {
                let name = buffer.trim().to_string();
                if name.is_empty() {
                    self.status = Some("name must not be empty".to_string());
                    return NotesOutcome::Stay;
                }
                let Some(db) = self.db.clone() else {
                    self.status = Some("notes db unavailable".to_string());
                    self.mode = Mode::Browsing;
                    return NotesOutcome::Stay;
                };
                match for_note {
                    // Rename an existing note.
                    Some(id) => match db.rename_project_note(id, &name) {
                        Ok(_) => {
                            self.reload(Some(id));
                            self.mode = Mode::Browsing;
                        }
                        Err(e) => self.status = Some(format!("rename failed: {e}")),
                    },
                    // Create a new note, then drop straight into editing it.
                    None => match db.create_project_note(&self.project_root, &name) {
                        Ok(note) => {
                            let id = note.id;
                            self.reload(Some(id));
                            self.enter_edit();
                        }
                        Err(e) => self.status = Some(format!("create failed: {e}")),
                    },
                }
            }
            KeyCode::Backspace => {
                buffer.pop();
            }
            KeyCode::Char(c) if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                buffer.push(c);
            }
            _ => {}
        }
        NotesOutcome::Stay
    }

    fn handle_confirm_delete_key(&mut self, key: KeyEvent) -> NotesOutcome {
        match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                if let Some(note) = self.current()
                    && let Some(db) = self.db.clone()
                {
                    let id = note.id;
                    if let Err(e) = db.delete_project_note(id) {
                        self.status = Some(format!("delete failed: {e}"));
                    }
                    self.reload(None);
                }
                self.mode = Mode::Browsing;
            }
            _ => {
                self.mode = Mode::Browsing;
            }
        }
        NotesOutcome::Stay
    }

    fn handle_editing_key(&mut self, key: KeyEvent) -> NotesOutcome {
        // Ctrl+S saves + leaves edit mode; Esc leaves edit mode (in vim it
        // first drops Insert→Normal, second Esc leaves — matching the
        // composer's "Esc goes to Normal" feel).
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('s')) {
            self.leave_edit();
            return NotesOutcome::Stay;
        }
        if matches!(key.code, KeyCode::Esc) {
            use crate::tui::composer::VimMode;
            if self.vim_enabled && self.editor.vim_mode() != VimMode::Normal {
                // Let the editor handle Esc (Insert/Visual/Operator → Normal).
                self.editor.handle_vim_key(key);
            } else {
                // Already in Normal (or vim off): leave edit mode, saving.
                self.leave_edit();
            }
            return NotesOutcome::Stay;
        }
        // Everything else is editing — driven through the reused composer vim
        // engine (or plain insert when vim is off).
        self.editor.handle_vim_key(key);
        NotesOutcome::Stay
    }

    fn scroll_view_down_page(&mut self) {
        let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
        self.view_scroll = (self.view_scroll + self.last_view_height.max(1)).min(max_scroll);
    }

    /// Mouse-wheel scroll for the viewed note.
    pub fn scroll_up(&mut self) {
        self.view_scroll = self.view_scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
        self.view_scroll = (self.view_scroll + 1).min(max_scroll);
    }

    #[cfg(test)]
    pub(crate) fn editing_for_test(content: &str, vim_enabled: bool) -> Self {
        let mut pane = Self {
            project_root: "/proj".to_string(),
            db: Some(Db::open_in_memory().unwrap()),
            notes: Vec::new(),
            selected: 0,
            mode: Mode::Editing,
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            last_view_width: 80,
            last_view_height: 24,
            last_view_rows: 0,
            status: None,
        };
        pane.editor.set(content.to_string());
        pane
    }

    #[cfg(test)]
    pub(crate) fn editor_text_for_test(&self) -> &str {
        self.editor.text()
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(" /scratchpad "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        // Sidebar (left, fixed width) | main pane (right).
        let cols = Layout::horizontal([Constraint::Length(28), Constraint::Min(20)]).split(inner);
        self.render_sidebar(frame, cols[0]);
        self.render_main(frame, cols[1]);
    }

    fn render_sidebar(&self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::RIGHT)
            .title(Line::from(" notes "));
        let body = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(2)]).split(body);
        let list_area = layout[0];
        let help_area = layout[1];

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let sel = Style::default()
            .fg(Color::Black)
            .bg(Color::Indexed(crate::tui::theme::ACCENT_BLUE_INDEX));
        let mut lines: Vec<Line<'static>> = Vec::new();
        if self.notes.is_empty() {
            lines.push(Line::from(Span::styled("(no notes yet)", muted)));
        }
        for (i, n) in self.notes.iter().enumerate() {
            let style = if i == self.selected
                && matches!(
                    self.mode,
                    Mode::Browsing | Mode::Editing | Mode::ConfirmingDelete
                ) {
                sel
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(Span::styled(format!(" {} ", n.name), style)));
        }
        // `+ new note` affordance, highlighted when selected.
        let new_selected = self.selected == self.notes.len() && matches!(self.mode, Mode::Browsing);
        let new_style = if new_selected {
            sel
        } else {
            Style::default().fg(Color::Indexed(crate::tui::theme::ACCENT_BLUE_INDEX))
        };
        lines.push(Line::from(Span::styled(" + new note ", new_style)));

        if let Some(status) = &self.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().fg(Color::Red),
            )));
        }
        frame.render_widget(Paragraph::new(lines), list_area);

        let help = match self.mode {
            Mode::Browsing => "↑/↓ select  ↵ edit/new  n new  r rename  d delete  q close",
            Mode::Editing => "Ctrl+S save  Esc done",
            Mode::Naming { .. } => "type a name  ↵ confirm  Esc cancel",
            Mode::ConfirmingDelete => "y delete  any other key cancel",
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(help.to_string(), muted))),
            help_area,
        );
    }

    fn render_main(&mut self, frame: &mut Frame, area: Rect) {
        match &self.mode {
            Mode::Naming { for_note, buffer } => {
                let title = if for_note.is_some() {
                    " rename note "
                } else {
                    " new note name "
                };
                let block = Block::default()
                    .borders(Borders::NONE)
                    .title(Line::from(title));
                let inner = block.inner(area);
                frame.render_widget(block, area);
                let line = Line::from(vec![
                    Span::raw("> "),
                    Span::styled(
                        buffer.clone(),
                        Style::default().add_modifier(Modifier::UNDERLINED),
                    ),
                ]);
                frame.render_widget(Paragraph::new(line), inner);
            }
            Mode::ConfirmingDelete => {
                let name = self.current().map(|n| n.name.clone()).unwrap_or_default();
                let line = Line::from(Span::styled(
                    format!("Delete note `{name}`? [y/N]"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
                frame.render_widget(Paragraph::new(line), area);
            }
            Mode::Editing => {
                // Raw editable markdown source (never rendered while editing).
                let width = area.width.max(1) as usize;
                let height = area.height.max(1) as usize;
                self.last_view_width = width;
                self.last_view_height = height;
                let text = self.editor.text().to_string();
                let lines: Vec<Line<'static>> = if text.is_empty() {
                    vec![Line::default()]
                } else {
                    text.split('\n')
                        .map(|l| Line::from(l.to_string()))
                        .collect()
                };
                let (cursor_line, cursor_col) = self.editor.cursor_line_col();
                let max_scroll = lines.len().saturating_sub(height);
                if cursor_line < self.edit_scroll {
                    self.edit_scroll = cursor_line;
                } else if cursor_line >= self.edit_scroll + height {
                    self.edit_scroll = cursor_line.saturating_sub(height.saturating_sub(1));
                }
                self.edit_scroll = self.edit_scroll.min(max_scroll);
                frame.render_widget(
                    Paragraph::new(lines).scroll((self.edit_scroll as u16, 0)),
                    area,
                );
                let cursor_y = area.y + cursor_line.saturating_sub(self.edit_scroll) as u16;
                let cursor_x = area.x + (cursor_col.min(width.saturating_sub(1)) as u16);
                if cursor_y < area.y + area.height {
                    frame.set_cursor_position((cursor_x, cursor_y));
                }
            }
            Mode::Browsing => {
                let width = area.width.max(1) as usize;
                self.last_view_width = width;
                self.last_view_height = area.height as usize;
                let lines = match self.current() {
                    Some(note) if !note.content.is_empty() => {
                        markdown::render_with_width(&note.content, width)
                    }
                    Some(_) => vec![Line::from(Span::styled(
                        "(empty note — press e or ↵ to edit)",
                        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
                    ))],
                    None => vec![Line::from(Span::styled(
                        "Select a note, or create one with `+ new note`.",
                        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
                    ))],
                };
                self.last_view_rows = lines.len();
                let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
                if self.view_scroll > max_scroll {
                    self.view_scroll = max_scroll;
                }
                frame.render_widget(
                    Paragraph::new(lines).scroll((self.view_scroll as u16, 0)),
                    area,
                );
            }
        }
    }
}

impl Pane for NotesPane {
    type Outcome = NotesOutcome;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        NotesPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        NotesPane::render(self, frame, area);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::composer::VimMode;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::layout::Rect;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// A pane backed by a fresh in-memory DB (no real project on disk needed).
    fn pane(vim_enabled: bool) -> NotesPane {
        let db = Db::open_in_memory().unwrap();
        NotesPane {
            project_root: "/proj".to_string(),
            db: Some(db),
            notes: Vec::new(),
            selected: 0,
            mode: Mode::Browsing,
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            last_view_width: 80,
            last_view_height: 24,
            last_view_rows: 0,
            status: None,
        }
    }

    fn type_chars(p: &mut NotesPane, s: &str) {
        for c in s.chars() {
            p.handle_key(press(KeyCode::Char(c)));
        }
    }

    /// The pane's DB handle (always `Some` in tests — built by `pane`).
    fn db(p: &NotesPane) -> &Db {
        p.db.as_ref().unwrap()
    }

    #[test]
    fn create_note_via_new_row_then_edits() {
        let mut p = pane(false);
        // Empty state: only the `+ new note` row → it's at index 0.
        assert!(matches!(p.mode, Mode::Browsing));
        p.handle_key(press(KeyCode::Enter)); // activate `+ new note`
        assert!(matches!(p.mode, Mode::Naming { for_note: None, .. }));
        type_chars(&mut p, "ideas");
        p.handle_key(press(KeyCode::Enter)); // confirm name
        // Creating drops straight into editing the new note.
        assert!(matches!(p.mode, Mode::Editing));
        assert_eq!(p.notes.len(), 1);
        assert_eq!(p.notes[0].name, "ideas");
    }

    #[test]
    fn empty_name_rejected_in_prompt() {
        let mut p = pane(false);
        p.start_create();
        p.handle_key(press(KeyCode::Enter)); // empty
        assert!(matches!(p.mode, Mode::Naming { .. }), "stays in prompt");
        assert!(p.status.as_deref().unwrap().contains("empty"));
        assert!(p.notes.is_empty());
    }

    #[test]
    fn view_edit_toggle_switches_pane_and_persists() {
        let mut p = pane(false);
        let note = db(&p).create_project_note("/proj", "n").unwrap();
        p.reload(Some(note.id));
        assert!(matches!(p.mode, Mode::Browsing), "viewing renders markdown");
        // Enter edit mode → raw editable text.
        p.handle_key(press(KeyCode::Enter));
        assert!(matches!(p.mode, Mode::Editing));
        type_chars(&mut p, "# Title");
        assert_eq!(p.editor.text(), "# Title");
        // Leave edit mode (Ctrl+S) → re-render + persist.
        p.handle_key(ctrl(KeyCode::Char('s')));
        assert!(matches!(p.mode, Mode::Browsing), "back to rendered view");
        // Content persisted to the DB.
        let reloaded = db(&p).list_project_notes("/proj").unwrap();
        assert_eq!(reloaded[0].content, "# Title");
    }

    #[test]
    fn rename_and_delete_flow() {
        let mut p = pane(false);
        let note = db(&p).create_project_note("/proj", "old").unwrap();
        p.reload(Some(note.id));
        // Rename.
        p.handle_key(press(KeyCode::Char('r')));
        assert!(matches!(
            p.mode,
            Mode::Naming {
                for_note: Some(_),
                ..
            }
        ));
        // Clear the prefilled name and type a new one.
        for _ in 0..10 {
            p.handle_key(press(KeyCode::Backspace));
        }
        type_chars(&mut p, "fresh");
        p.handle_key(press(KeyCode::Enter));
        assert_eq!(p.notes[0].name, "fresh");
        // Delete (confirm).
        p.handle_key(press(KeyCode::Char('d')));
        assert!(matches!(p.mode, Mode::ConfirmingDelete));
        p.handle_key(press(KeyCode::Char('y')));
        assert!(p.notes.is_empty());
        assert!(matches!(p.mode, Mode::Browsing));
    }

    #[test]
    fn delete_cancelled_by_other_key() {
        let mut p = pane(false);
        let note = db(&p).create_project_note("/proj", "keep").unwrap();
        p.reload(Some(note.id));
        p.handle_key(press(KeyCode::Char('d')));
        p.handle_key(press(KeyCode::Char('n'))); // not 'y'
        assert_eq!(p.notes.len(), 1, "cancelled delete keeps the note");
        assert!(matches!(p.mode, Mode::Browsing));
    }

    #[test]
    fn esc_closes_dialog_from_browsing() {
        let mut p = pane(false);
        assert!(matches!(
            p.handle_key(press(KeyCode::Esc)),
            NotesOutcome::Close
        ));
        assert!(matches!(
            p.handle_key(press(KeyCode::Char('q'))),
            NotesOutcome::Close
        ));
    }

    #[test]
    fn editor_reuses_composer_vim_engine() {
        // Wiring-level check: with vim enabled the editor starts in Normal,
        // `i` enters Insert (via the reused Composer::handle_vim_key), text is
        // inserted, and `dd` (Normal) deletes a line — proving the shared vim
        // machinery is driving the note editor, not a fork.
        let mut p = pane(true);
        let note = db(&p).create_project_note("/proj", "v").unwrap();
        db(&p)
            .set_project_note_content(note.id, "alpha\nbeta")
            .unwrap();
        p.reload(Some(note.id));
        p.handle_key(press(KeyCode::Enter)); // edit
        assert!(matches!(p.mode, Mode::Editing));
        assert_eq!(
            p.editor.vim_mode(),
            VimMode::Normal,
            "vim editor starts in Normal"
        );
        // `dd` deletes the first line via the reused operator path.
        p.handle_key(press(KeyCode::Char('d')));
        p.handle_key(press(KeyCode::Char('d')));
        assert_eq!(p.editor.text(), "beta");
        // `i` then typing inserts.
        p.handle_key(press(KeyCode::Char('i')));
        assert_eq!(p.editor.vim_mode(), VimMode::Insert);
        type_chars(&mut p, "X");
        assert_eq!(p.editor.text(), "Xbeta");
        // Esc returns to Normal (first Esc), second Esc leaves edit + saves.
        p.handle_key(press(KeyCode::Esc));
        assert_eq!(p.editor.vim_mode(), VimMode::Normal);
        p.handle_key(press(KeyCode::Esc));
        assert!(matches!(p.mode, Mode::Browsing));
        assert_eq!(
            db(&p).list_project_notes("/proj").unwrap()[0].content,
            "Xbeta"
        );
    }

    #[test]
    fn plain_text_editing_when_vim_off() {
        let mut p = pane(false);
        let note = db(&p).create_project_note("/proj", "p").unwrap();
        p.reload(Some(note.id));
        p.handle_key(press(KeyCode::Enter));
        // 'i' is just a literal char when vim is off (no mode machinery).
        type_chars(&mut p, "ihello");
        assert_eq!(p.editor.text(), "ihello");
        p.handle_key(press(KeyCode::Esc)); // vim off → leaves + saves
        assert!(matches!(p.mode, Mode::Browsing));
    }

    #[test]
    fn render_editing_main_scrolls_to_cursor() {
        let mut p = NotesPane::editing_for_test("one\ntwo\nthree\nfour", false);
        p.editor.set_cursor(p.editor.text().len());
        let backend = TestBackend::new(10, 2);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| p.render_main(frame, Rect::new(0, 0, 10, 2)))
            .unwrap();

        let first_row = (0..10)
            .map(|x| terminal.backend().buffer()[(x, 0)].symbol())
            .collect::<String>();
        let second_row = (0..10)
            .map(|x| terminal.backend().buffer()[(x, 1)].symbol())
            .collect::<String>();

        assert_eq!(p.edit_scroll, 2);
        assert!(first_row.contains("three"), "{first_row:?}");
        assert!(second_row.contains("four"), "{second_row:?}");
    }

    #[test]
    fn paste_in_editing_inserts_at_cursor() {
        let mut p = NotesPane::editing_for_test("ab", false);
        p.editor.set_cursor(1);

        p.paste("XY");

        assert_eq!(p.editor.text(), "aXYb");
    }

    #[test]
    fn paste_in_editing_preserves_newlines() {
        let mut p = NotesPane::editing_for_test("", false);

        p.paste("line1\nline2");

        assert_eq!(p.editor.text(), "line1\nline2");
    }

    #[test]
    fn paste_in_editing_normalizes_crlf() {
        let mut p = NotesPane::editing_for_test("", false);

        p.paste("a\r\nb\rc");

        assert_eq!(p.editor.text(), "a\nbc");
    }

    #[test]
    fn paste_in_browsing_is_noop() {
        let mut p = pane(false);
        let note = db(&p).create_project_note("/proj", "n").unwrap();
        p.reload(Some(note.id));

        p.paste("x");

        assert!(matches!(p.mode, Mode::Browsing));
        assert_eq!(p.notes[0].content, "");
    }

    #[test]
    fn paste_in_naming_takes_first_line() {
        let mut p = pane(false);
        p.start_create();

        p.paste("good\nignored");

        let Mode::Naming { buffer, .. } = &p.mode else {
            panic!("expected naming mode");
        };
        assert_eq!(buffer, "good");
    }

    #[test]
    fn paste_in_naming_empty_first_line_is_noop() {
        let mut p = pane(false);
        p.start_create();

        p.paste("\nx");

        let Mode::Naming { buffer, .. } = &p.mode else {
            panic!("expected naming mode");
        };
        assert_eq!(buffer, "");
    }

    #[test]
    fn paste_empty_is_noop() {
        let mut p = NotesPane::editing_for_test("unchanged", false);

        p.paste("");

        assert_eq!(p.editor.text(), "unchanged");
    }
}
