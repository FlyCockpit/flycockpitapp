//! `/scratchpad` pane — a project-scoped markdown scratchpad (prompt
//! `notes-scratchpad.md`).
//!
//! A floating dialog over the chat body: a sidebar lists the project's notes
//! by name (plus a "+ new note" affordance); the main pane shows the selected
//! note. Notes are scoped to the **project root** and persist in the global
//! daemon-owned project-note storage, so the same notes appear across
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
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};
use uuid::Uuid;

use crate::tui::composer::Composer;
use crate::tui::markdown;
use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_proto::{ProjectNote, Request, Response};

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
    daemon_socket: Option<std::path::PathBuf>,
    /// Loaded notes for this project, in sidebar order.
    notes: Vec<ProjectNote>,
    /// Durable sidebar selection and viewport. The final selectable row is
    /// always the `+ new note` affordance at index `notes.len()`.
    sidebar: ListState,
    selection: SidebarSelection,
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
    /// Mouse-wheel scrolling temporarily owns the editor viewport. Any
    /// subsequent keyboard edit/motion returns ownership to cursor follow.
    edit_scroll_manual: bool,
    /// Last main-pane content width/height — for render-side scroll clamping.
    last_view_width: usize,
    last_view_height: usize,
    last_view_rows: usize,
    last_edit_rows: usize,
    /// A transient error/status line shown under the sidebar (e.g. a failed
    /// DB write). Cleared on the next successful action.
    status: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidebarSelection {
    Note(Uuid),
    New,
}

/// Outcome of routing a key to the pane.
pub enum NotesOutcome {
    /// Stay open.
    Stay,
    /// Run a notes DB action asynchronously, then apply the result to this pane.
    Rpc(NotesRpcAction),
    /// Close the dialog and return focus to the composer/transcript.
    Close,
}

pub struct NotesRpcAction {
    daemon_socket: std::path::PathBuf,
    project_root: String,
    kind: NotesRpcActionKind,
}

enum NotesRpcActionKind {
    Load { keep: Option<Uuid> },
    Save { id: Uuid, content: String },
    Rename { id: Uuid, name: String },
    Create { name: String },
    Delete { id: Uuid, fallback_index: usize },
}

#[derive(Debug, Clone)]
pub struct NotesRpcResult {
    project_root: String,
    notes: Vec<ProjectNote>,
    selection: SelectionAfterRpc,
    enter_edit: bool,
}

#[derive(Debug, Clone, Copy)]
enum SelectionAfterRpc {
    Preserve,
    Keep(Uuid),
    Deleted { fallback_index: usize },
}

impl NotesRpcAction {
    pub fn run_blocking_rpc(
        self,
        endpoint: cockpit_client::ClientEndpoint,
    ) -> anyhow::Result<NotesRpcResult> {
        let project_root = self.project_root;
        let response_project_root = project_root.clone();
        let send = |request| {
            crate::tui::agent_runner::daemon_request_at_blocking(&endpoint, request)
                .map_err(anyhow::Error::msg)
        };
        match self.kind {
            NotesRpcActionKind::Load { keep } => {
                let notes = match send(Request::ListProjectNotes { project_root })? {
                    Response::ProjectNotes { notes } => notes,
                    other => anyhow::bail!("unexpected notes response: {other:?}"),
                };
                Ok(NotesRpcResult {
                    project_root: response_project_root,
                    notes,
                    selection: keep.map_or(SelectionAfterRpc::Preserve, SelectionAfterRpc::Keep),
                    enter_edit: false,
                })
            }
            NotesRpcActionKind::Save { id, content } => {
                send(Request::SetProjectNoteContent {
                    project_root: project_root.clone(),
                    id,
                    content,
                })?;
                let notes = match send(Request::ListProjectNotes { project_root })? {
                    Response::ProjectNotes { notes } => notes,
                    other => anyhow::bail!("unexpected notes response: {other:?}"),
                };
                Ok(NotesRpcResult {
                    project_root: response_project_root,
                    notes,
                    selection: SelectionAfterRpc::Keep(id),
                    enter_edit: false,
                })
            }
            NotesRpcActionKind::Rename { id, name } => {
                send(Request::RenameProjectNote {
                    project_root: project_root.clone(),
                    id,
                    name,
                })?;
                let notes = match send(Request::ListProjectNotes { project_root })? {
                    Response::ProjectNotes { notes } => notes,
                    other => anyhow::bail!("unexpected notes response: {other:?}"),
                };
                Ok(NotesRpcResult {
                    project_root: response_project_root,
                    notes,
                    selection: SelectionAfterRpc::Keep(id),
                    enter_edit: false,
                })
            }
            NotesRpcActionKind::Create { name } => {
                let note = match send(Request::CreateProjectNote {
                    project_root: project_root.clone(),
                    name,
                })? {
                    Response::ProjectNoteCreated { note } => note,
                    other => anyhow::bail!("unexpected create-note response: {other:?}"),
                };
                let notes = match send(Request::ListProjectNotes { project_root })? {
                    Response::ProjectNotes { notes } => notes,
                    other => anyhow::bail!("unexpected notes response: {other:?}"),
                };
                Ok(NotesRpcResult {
                    project_root: response_project_root,
                    notes,
                    selection: SelectionAfterRpc::Keep(note.id),
                    enter_edit: true,
                })
            }
            NotesRpcActionKind::Delete { id, fallback_index } => {
                send(Request::DeleteProjectNote {
                    project_root: project_root.clone(),
                    id,
                })?;
                let notes = match send(Request::ListProjectNotes { project_root })? {
                    Response::ProjectNotes { notes } => notes,
                    other => anyhow::bail!("unexpected notes response: {other:?}"),
                };
                Ok(NotesRpcResult {
                    project_root: response_project_root,
                    notes,
                    selection: SelectionAfterRpc::Deleted { fallback_index },
                    enter_edit: false,
                })
            }
        }
    }
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
    /// root, falling back to `cwd`). Loading happens through
    /// [`Self::initial_load_action`] so the TUI does not block the async
    /// runtime while opening the pane.
    pub fn open(
        cwd: &std::path::Path,
        vim_enabled: bool,
        daemon_socket: Option<std::path::PathBuf>,
    ) -> Self {
        let project_root = cockpit_core::git::find_worktree_root(cwd)
            .unwrap_or_else(|| cwd.to_path_buf())
            .to_string_lossy()
            .into_owned();
        let status = if daemon_socket.is_some() {
            Some("loading notes".to_string())
        } else {
            Some("Unavailable — reconnect to the daemon, then Retry".to_string())
        };
        Self {
            project_root,
            daemon_socket,
            notes: Vec::new(),
            sidebar: initial_sidebar_state(),
            selection: SidebarSelection::New,
            mode: Mode::Browsing,
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            edit_scroll_manual: false,
            last_view_width: 0,
            last_view_height: 0,
            last_view_rows: 0,
            last_edit_rows: 0,
            status,
        }
    }

    pub fn initial_load_action(&self) -> Option<NotesRpcAction> {
        Some(NotesRpcAction {
            daemon_socket: self.daemon_socket.clone()?,
            project_root: self.project_root.clone(),
            kind: NotesRpcActionKind::Load { keep: None },
        })
    }

    /// Currently-selected note, if any.
    fn current(&self) -> Option<&ProjectNote> {
        let SidebarSelection::Note(id) = self.selection else {
            return None;
        };
        self.notes.iter().find(|note| note.id == id)
    }

    fn selected_index(&self) -> usize {
        match self.selection {
            SidebarSelection::Note(id) => self
                .notes
                .iter()
                .position(|note| note.id == id)
                .unwrap_or(self.notes.len()),
            SidebarSelection::New => self.notes.len(),
        }
    }

    fn select_sidebar(&mut self, index: usize) {
        let index = index.min(self.notes.len());
        self.selection = self.notes.get(index).map_or(SidebarSelection::New, |note| {
            SidebarSelection::Note(note.id)
        });
        self.sidebar.select(Some(index));
    }

    pub fn apply_rpc_result(&mut self, result: Result<NotesRpcResult, String>) {
        match result {
            Ok(result) => {
                if result.project_root != self.project_root {
                    return;
                }
                let old_index = self.selected_index();
                let old_selection = self.selection;
                self.notes = result.notes;
                let requested = match result.selection {
                    SelectionAfterRpc::Preserve => old_selection,
                    SelectionAfterRpc::Keep(id) => SidebarSelection::Note(id),
                    SelectionAfterRpc::Deleted { fallback_index } => {
                        self.notes.get(fallback_index).map_or_else(
                            || {
                                self.notes.last().map_or(SidebarSelection::New, |note| {
                                    SidebarSelection::Note(note.id)
                                })
                            },
                            |note| SidebarSelection::Note(note.id),
                        )
                    }
                };
                let resolved = match requested {
                    SidebarSelection::New => SidebarSelection::New,
                    SidebarSelection::Note(id) if self.notes.iter().any(|note| note.id == id) => {
                        SidebarSelection::Note(id)
                    }
                    SidebarSelection::Note(_) => self.notes.get(old_index).map_or_else(
                        || {
                            self.notes.last().map_or(SidebarSelection::New, |note| {
                                SidebarSelection::Note(note.id)
                            })
                        },
                        |note| SidebarSelection::Note(note.id),
                    ),
                };
                self.selection = resolved;
                self.sidebar.select(Some(self.selected_index()));
                self.mode = Mode::Browsing;
                self.status = None;
                if result.enter_edit {
                    self.enter_edit();
                }
            }
            Err(e) => self.status = Some(e),
        }
    }

    fn action(&self, kind: NotesRpcActionKind) -> Option<NotesRpcAction> {
        Some(NotesRpcAction {
            daemon_socket: self.daemon_socket.clone()?,
            project_root: self.project_root.clone(),
            kind,
        })
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
        self.edit_scroll = 0;
        self.edit_scroll_manual = false;
        self.mode = Mode::Editing;
    }

    /// Persist the editor buffer back to the selected note and return to the
    /// rendered view.
    fn leave_edit(&mut self) -> NotesOutcome {
        if let Some(note) = self.current() {
            let id = note.id;
            let content = self.editor.text().to_string();
            self.mode = Mode::Browsing;
            self.view_scroll = 0;
            if let Some(action) = self.action(NotesRpcActionKind::Save { id, content }) {
                return NotesOutcome::Rpc(action);
            }
            self.status = Some("Unavailable — reconnect to the daemon, then Retry".to_string());
        }
        self.mode = Mode::Browsing;
        self.view_scroll = 0;
        NotesOutcome::Stay
    }

    /// Handle a key. Returns the outcome (stay / close).
    pub(crate) fn pointer_new_note(&mut self) {
        self.select_sidebar(self.notes.len());
        self.start_create();
    }

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
                self.select_sidebar(self.selected_index().saturating_sub(1));
                self.view_scroll = 0;
            }
            // Allow landing on the `+ new note` row (one past the last
            // note).
            KeyCode::Down | KeyCode::Char('j') if self.selected_index() < new_row => {
                self.select_sidebar(self.selected_index() + 1);
                self.view_scroll = 0;
            }
            KeyCode::Enter => {
                if self.selected_index() == new_row {
                    self.start_create();
                } else if self.current().is_some() {
                    self.enter_edit();
                }
            }
            KeyCode::Char('n') => self.start_create(),
            KeyCode::Char('e') if self.selected_index() < new_row => {
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
                if self.daemon_socket.is_none() {
                    self.status =
                        Some("Unavailable — reconnect to the daemon, then Retry".to_string());
                    self.mode = Mode::Browsing;
                    return NotesOutcome::Stay;
                };
                let kind = match for_note {
                    Some(id) => NotesRpcActionKind::Rename { id, name },
                    None => NotesRpcActionKind::Create { name },
                };
                if let Some(action) = self.action(kind) {
                    return NotesOutcome::Rpc(action);
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
                if let Some(note) = self.current() {
                    let id = note.id;
                    self.mode = Mode::Browsing;
                    let fallback_index = self.selected_index();
                    if let Some(action) =
                        self.action(NotesRpcActionKind::Delete { id, fallback_index })
                    {
                        return NotesOutcome::Rpc(action);
                    };
                    self.status = Some("notes db unavailable".to_string());
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
            return self.leave_edit();
        }
        if matches!(key.code, KeyCode::Esc) {
            use crate::tui::composer::VimMode;
            if self.vim_enabled && self.editor.vim_mode() != VimMode::Normal {
                // Let the editor handle Esc (Insert/Visual/Operator → Normal).
                self.edit_scroll_manual = false;
                self.editor.handle_vim_key(key);
            } else {
                // Already in Normal (or vim off): leave edit mode, saving.
                return self.leave_edit();
            }
            return NotesOutcome::Stay;
        }
        // Everything else is editing — driven through the reused composer vim
        // engine (or plain insert when vim is off).
        self.edit_scroll_manual = false;
        self.editor.handle_vim_key(key);
        NotesOutcome::Stay
    }

    fn scroll_view_down_page(&mut self) {
        let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
        self.view_scroll = (self.view_scroll + self.last_view_height.max(1)).min(max_scroll);
    }

    /// Mouse-wheel scroll for the viewed note.
    pub fn scroll_up(&mut self) {
        match self.mode {
            Mode::Editing => {
                self.edit_scroll = self.edit_scroll.saturating_sub(1);
                self.edit_scroll_manual = true;
            }
            Mode::Browsing => self.view_scroll = self.view_scroll.saturating_sub(1),
            Mode::Naming { .. } | Mode::ConfirmingDelete => {}
        }
    }

    pub fn scroll_down(&mut self) {
        match self.mode {
            Mode::Editing => {
                let max_scroll = self.last_edit_rows.saturating_sub(self.last_view_height);
                self.edit_scroll = (self.edit_scroll + 1).min(max_scroll);
                self.edit_scroll_manual = true;
            }
            Mode::Browsing => {
                let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
                self.view_scroll = (self.view_scroll + 1).min(max_scroll);
            }
            Mode::Naming { .. } | Mode::ConfirmingDelete => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn editing_for_test(content: &str, vim_enabled: bool) -> Self {
        let mut pane = Self {
            project_root: "/proj".to_string(),
            daemon_socket: Some(std::path::PathBuf::from("/test-daemon.sock")),
            notes: Vec::new(),
            sidebar: initial_sidebar_state(),
            selection: SidebarSelection::New,
            mode: Mode::Editing,
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            edit_scroll_manual: false,
            last_view_width: 80,
            last_view_height: 24,
            last_view_rows: 0,
            last_edit_rows: 0,
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

    fn render_sidebar(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::RIGHT)
            .title(Line::from(" notes "));
        let body = block.inner(area);
        frame.render_widget(block, area);

        let status_height = u16::from(self.status.is_some());
        let layout = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(status_height),
            Constraint::Length(2),
        ])
        .split(body);
        let list_area = layout[0];
        let status_area = layout[1];
        let help_area = layout[2];

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut items = self
            .notes
            .iter()
            .map(|note| {
                ListItem::new(Line::from(Span::styled(
                    format!(" {} ", note.name),
                    Style::default().fg(Color::White),
                )))
            })
            .collect::<Vec<_>>();
        items.push(ListItem::new(Line::from(Span::styled(
            " + new note ",
            Style::default().fg(Color::Indexed(crate::tui::theme::ACCENT_BLUE_INDEX)),
        ))));

        let highlight = if matches!(
            self.mode,
            Mode::Browsing | Mode::Editing | Mode::ConfirmingDelete
        ) {
            crate::tui::theme::row_selection_style()
        } else {
            Style::default()
        };
        let row_count = self.notes.len() + 1;
        self.sidebar.select(Some(self.selected_index()));
        let (list_content, scrollbar_area) =
            scrollbar_areas(list_area, row_count > list_area.height as usize);
        frame.render_stateful_widget(
            List::new(items).highlight_style(highlight),
            list_content,
            &mut self.sidebar,
        );

        if let Some(scrollbar_area) = scrollbar_area {
            let mut scrollbar = ScrollbarState::new(row_count)
                .position(self.sidebar.offset())
                .viewport_content_length(list_content.height as usize);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .begin_symbol(None)
                    .end_symbol(None),
                scrollbar_area,
                &mut scrollbar,
            );
        }

        if let Some(status) = &self.status {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    status.clone(),
                    Style::default().fg(Color::Red),
                ))),
                status_area,
            );
        }

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
                let height = area.height.max(1) as usize;
                let text = self.editor.text().to_string();
                let lines: Vec<Line<'static>> = if text.is_empty() {
                    vec![Line::default()]
                } else {
                    text.split('\n')
                        .map(|l| Line::from(l.to_string()))
                        .collect()
                };
                self.last_edit_rows = lines.len();
                let max_scroll = lines.len().saturating_sub(height);
                let (content_area, scrollbar_area) = scrollbar_areas(area, max_scroll > 0);
                let width = content_area.width.max(1) as usize;
                self.last_view_width = width;
                self.last_view_height = height;
                let (cursor_line, cursor_col) = self.editor.cursor_line_col();
                if !self.edit_scroll_manual {
                    if cursor_line < self.edit_scroll {
                        self.edit_scroll = cursor_line;
                    } else if cursor_line >= self.edit_scroll + height {
                        self.edit_scroll = cursor_line.saturating_sub(height.saturating_sub(1));
                    }
                }
                self.edit_scroll = self.edit_scroll.min(max_scroll);
                frame.render_widget(
                    Paragraph::new(lines).scroll((self.edit_scroll as u16, 0)),
                    content_area,
                );
                if let Some(scrollbar_area) = scrollbar_area {
                    let mut scrollbar = ScrollbarState::new(max_scroll + height)
                        .position(self.edit_scroll)
                        .viewport_content_length(height);
                    frame.render_stateful_widget(
                        Scrollbar::new(ScrollbarOrientation::VerticalRight)
                            .begin_symbol(None)
                            .end_symbol(None),
                        scrollbar_area,
                        &mut scrollbar,
                    );
                }
                let cursor_y = content_area.y + cursor_line.saturating_sub(self.edit_scroll) as u16;
                let cursor_x = content_area.x + (cursor_col.min(width.saturating_sub(1)) as u16);
                if cursor_y < content_area.y + content_area.height
                    && cursor_line >= self.edit_scroll
                {
                    frame.set_cursor_position((cursor_x, cursor_y));
                }
            }
            Mode::Browsing => {
                self.last_view_height = area.height as usize;
                let note_content = self.current().map(|note| note.content.clone());
                let render_lines = |width: usize| match note_content.as_deref() {
                    Some(content) if !content.is_empty() => {
                        markdown::render_with_width(content, width)
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
                let full_width = area.width.max(1) as usize;
                let initial_lines = render_lines(full_width);
                let overflow = initial_lines.len() > self.last_view_height;
                let (content_area, scrollbar_area) = scrollbar_areas(area, overflow);
                let width = content_area.width.max(1) as usize;
                let lines = if width == full_width {
                    initial_lines
                } else {
                    render_lines(width)
                };
                self.last_view_width = width;
                self.last_view_rows = lines.len();
                let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
                if self.view_scroll > max_scroll {
                    self.view_scroll = max_scroll;
                }
                frame.render_widget(
                    Paragraph::new(lines).scroll((self.view_scroll as u16, 0)),
                    content_area,
                );
                if let Some(scrollbar_area) = scrollbar_area {
                    let mut scrollbar = ScrollbarState::new(self.last_view_rows)
                        .position(self.view_scroll)
                        .viewport_content_length(self.last_view_height);
                    frame.render_stateful_widget(
                        Scrollbar::new(ScrollbarOrientation::VerticalRight)
                            .begin_symbol(None)
                            .end_symbol(None),
                        scrollbar_area,
                        &mut scrollbar,
                    );
                }
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

fn initial_sidebar_state() -> ListState {
    let mut state = ListState::default();
    state.select(Some(0));
    state
}

fn scrollbar_areas(area: Rect, overflow: bool) -> (Rect, Option<Rect>) {
    if !overflow || area.width < 2 {
        return (area, None);
    }
    let cols = Layout::horizontal([Constraint::Min(0), Constraint::Length(1)]).split(area);
    (cols[0], Some(cols[1]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState};
    use ratatui::{Terminal, backend::TestBackend};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn pane(connected: bool) -> NotesPane {
        let id = Uuid::new_v4();
        let mut pane = NotesPane {
            project_root: "/proj".to_string(),
            daemon_socket: connected.then(|| std::path::PathBuf::from("/test-daemon.sock")),
            notes: vec![ProjectNote {
                id,
                project_root: "/proj".into(),
                name: "ideas".into(),
                content: "before".into(),
            }],
            sidebar: initial_sidebar_state(),
            selection: SidebarSelection::Note(id),
            mode: Mode::Browsing,
            editor: Composer::new(false),
            vim_enabled: false,
            view_scroll: 0,
            edit_scroll: 0,
            edit_scroll_manual: false,
            last_view_width: 80,
            last_view_height: 24,
            last_view_rows: 0,
            last_edit_rows: 0,
            status: None,
        };
        pane.sidebar.select(Some(0));
        pane
    }

    fn note(id: Uuid, name: impl Into<String>, content: impl Into<String>) -> ProjectNote {
        ProjectNote {
            id,
            project_root: "/proj".into(),
            name: name.into(),
            content: content.into(),
        }
    }

    fn rendered_buffer(pane: &mut NotesPane, width: u16, height: u16) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw notes");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn disconnected_notes_are_unavailable_without_mutation() {
        let mut pane = pane(false);
        pane.start_create();
        if let Mode::Naming { buffer, .. } = &mut pane.mode {
            buffer.push_str("new");
        }
        assert!(matches!(
            pane.handle_key(press(KeyCode::Enter)),
            NotesOutcome::Stay
        ));
        assert_eq!(pane.notes.len(), 1);
        assert!(pane.status.as_deref().unwrap().contains("Unavailable"));
    }

    #[test]
    fn connected_actions_are_typed_rpc_intents() {
        let mut pane = pane(true);
        pane.enter_edit();
        pane.editor.set("after".to_string());
        assert!(matches!(pane.leave_edit(), NotesOutcome::Rpc(_)));
        assert_eq!(pane.notes[0].content, "before");
    }

    #[test]
    fn sidebar_selection_identity_survives_refresh_and_bounds_keyboard_navigation() {
        let keep = Uuid::new_v4();
        let mut pane = pane(true);
        pane.notes = vec![
            note(Uuid::new_v4(), "first", "one"),
            note(keep, "選択中 🚀", "two"),
            note(Uuid::new_v4(), "third", "three"),
        ];
        pane.select_sidebar(1);

        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: vec![
                note(Uuid::new_v4(), "inserted", "zero"),
                note(Uuid::new_v4(), "first", "one"),
                note(keep, "選択中 🚀", "two"),
            ],
            selection: SelectionAfterRpc::Keep(keep),
            enter_edit: false,
        }));
        assert_eq!(pane.selected_index(), 2);
        assert_eq!(pane.current().map(|note| note.id), Some(keep));

        for _ in 0..20 {
            pane.handle_key(press(KeyCode::Down));
        }
        assert_eq!(pane.selected_index(), pane.notes.len());
        for _ in 0..20 {
            pane.handle_key(press(KeyCode::Up));
        }
        assert_eq!(pane.selected_index(), 0);
    }

    #[test]
    fn refresh_preserves_new_and_note_id_and_has_defined_missing_fallbacks() {
        let selected = Uuid::new_v4();
        let mut pane = pane(true);
        pane.notes = vec![
            note(Uuid::new_v4(), "a", "a"),
            note(selected, "selected", "b"),
        ];

        pane.select_sidebar(pane.notes.len());
        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: (0..8)
                .map(|index| note(Uuid::new_v4(), format!("new-{index}"), "x"))
                .collect(),
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::New);
        assert_eq!(pane.selected_index(), pane.notes.len());

        pane.notes = vec![
            note(Uuid::new_v4(), "before", "a"),
            note(selected, "selected", "b"),
            note(Uuid::new_v4(), "after", "c"),
        ];
        pane.select_sidebar(1);
        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: vec![
                note(Uuid::new_v4(), "after", "c"),
                note(selected, "selected", "b"),
                note(Uuid::new_v4(), "before", "a"),
            ],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::Note(selected));
        assert_eq!(pane.selected_index(), 1);

        let fallback = pane.notes[1].id;
        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: pane.notes.clone(),
            selection: SelectionAfterRpc::Keep(Uuid::new_v4()),
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::Note(fallback));

        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Deleted { fallback_index: 1 },
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::New);
        assert_eq!(pane.selected_index(), 0);
    }

    #[test]
    fn delete_fallback_selects_next_then_clamps_to_previous() {
        let mut pane = pane(true);
        let first = Uuid::new_v4();
        let next = Uuid::new_v4();
        pane.notes = vec![
            note(first, "first", "a"),
            note(Uuid::new_v4(), "deleted", "b"),
            note(next, "next", "c"),
        ];
        pane.select_sidebar(1);
        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: vec![note(first, "first", "a"), note(next, "next", "c")],
            selection: SelectionAfterRpc::Deleted { fallback_index: 1 },
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::Note(next));

        pane.apply_rpc_result(Ok(NotesRpcResult {
            project_root: "/proj".into(),
            notes: vec![note(first, "first", "a")],
            selection: SelectionAfterRpc::Deleted { fallback_index: 1 },
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::Note(first));
    }

    #[test]
    fn test_backend_covers_loading_error_empty_long_unicode_resize_and_view_scroll() {
        let mut pane = pane(true);
        pane.notes.clear();
        pane.status = Some("loading notes".into());
        let loading = rendered_buffer(&mut pane, 70, 10);
        assert!(loading.contains("loading notes"));
        assert!(loading.contains("Select a note"));
        assert!(loading.contains("+ new note"));

        pane.status = Some("daemon unavailable — retry".into());
        assert!(rendered_buffer(&mut pane, 70, 10).contains("daemon unavailable"));

        pane.status = None;
        pane.notes = (0..24)
            .map(|index| {
                note(
                    Uuid::new_v4(),
                    format!("筆記-{index} 🚀"),
                    format!(
                        "# Long note {index}\n\n{}",
                        "Unicode café 內容 with a very long wrapped sentence. ".repeat(20)
                    ),
                )
            })
            .collect();
        pane.select_sidebar(0);
        let narrow = rendered_buffer(&mut pane, 58, 10);
        assert!(narrow.contains("筆記-0"));
        assert!(pane.last_view_rows > pane.last_view_height);
        let narrow_rows = pane.last_view_rows;
        let narrow_max_scroll = pane.last_view_rows.saturating_sub(pane.last_view_height);

        pane.select_sidebar(pane.notes.len() - 1);
        let offscreen_selected = rendered_buffer(&mut pane, 58, 10);
        assert!(pane.sidebar.offset() > 0);
        assert!(offscreen_selected.contains("筆記-23"));
        assert!(!offscreen_selected.contains("筆記-0 "));
        pane.select_sidebar(0);

        for _ in 0..200 {
            pane.scroll_down();
        }
        let bottom = pane.view_scroll;
        assert_eq!(
            bottom,
            pane.last_view_rows.saturating_sub(pane.last_view_height)
        );
        pane.scroll_down();
        assert_eq!(pane.view_scroll, bottom);
        pane.scroll_up();
        assert_eq!(pane.view_scroll, bottom.saturating_sub(1));

        let resized = rendered_buffer(&mut pane, 90, 16);
        assert!(resized.contains("/scratchpad"));
        assert!(pane.view_scroll <= pane.last_view_rows.saturating_sub(pane.last_view_height));
        assert!(pane.last_view_rows < narrow_rows);
        assert!(
            pane.last_view_rows.saturating_sub(pane.last_view_height) < narrow_max_scroll,
            "wider/taller resize must reduce the wrapped-note scroll range"
        );
    }

    #[test]
    fn editor_wheel_owns_viewport_until_keyboard_motion_reenables_cursor_follow() {
        let content = (0..30)
            .map(|index| format!("line {index}"))
            .collect::<Vec<_>>()
            .join("\n");
        let mut pane = NotesPane::editing_for_test(&content, false);
        rendered_buffer(&mut pane, 60, 8);
        assert!(pane.last_edit_rows > pane.last_view_height);
        let cursor_follow_bottom = pane.edit_scroll;

        pane.scroll_up();
        pane.scroll_up();
        assert!(pane.edit_scroll_manual);
        assert_eq!(pane.edit_scroll, cursor_follow_bottom.saturating_sub(2));
        let manual_scroll = pane.edit_scroll;
        rendered_buffer(&mut pane, 60, 8);
        assert_eq!(pane.edit_scroll, manual_scroll);

        pane.handle_key(press(KeyCode::Up));
        assert!(!pane.edit_scroll_manual);
        rendered_buffer(&mut pane, 60, 8);
        assert!(pane.edit_scroll >= manual_scroll);
        for _ in 0..100 {
            pane.scroll_down();
        }
        assert_eq!(
            pane.edit_scroll,
            pane.last_edit_rows.saturating_sub(pane.last_view_height)
        );
    }

    #[test]
    fn editor_scrollbar_reserves_the_rightmost_content_cell() {
        let first_line = format!("{}Z", "a".repeat(28));
        let content = std::iter::once(first_line)
            .chain((1..20).map(|index| format!("line {index}")))
            .collect::<Vec<_>>()
            .join("\n");
        let mut pane = NotesPane::editing_for_test(&content, false);
        pane.editor.set_cursor(0);
        let mut terminal = Terminal::new(TestBackend::new(60, 8)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 60, 8)))
            .expect("draw notes editor");
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(57, 1)].symbol(), "Z");
        assert_ne!(buffer[(58, 1)].symbol(), "Z");
        assert!(
            (1..7).any(|row| !buffer[(58, row)].symbol().trim().is_empty()),
            "reserved rightmost editor column contains the scrollbar"
        );
    }

    #[test]
    fn sidebar_and_markdown_scrollbars_reserve_their_rightmost_content_cells() {
        let edge_name = format!("{}Z", "n".repeat(24));
        let edge_content = std::iter::once(format!("{}Z", "m".repeat(28)))
            .chain((1..20).map(|index| format!("markdown row {index}")))
            .collect::<Vec<_>>()
            .join("\n");
        let selected = Uuid::new_v4();
        let mut pane = pane(true);
        pane.notes = std::iter::once(note(selected, edge_name, edge_content))
            .chain((1..20).map(|index| {
                note(
                    Uuid::new_v4(),
                    format!("note-{index}"),
                    format!("row {index}"),
                )
            }))
            .collect();
        pane.selection = SidebarSelection::Note(selected);
        pane.sidebar.select(Some(0));

        let mut terminal = Terminal::new(TestBackend::new(60, 8)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 60, 8)))
            .expect("draw notes");
        let buffer = terminal.backend().buffer();

        assert_eq!(pane.last_view_width, 29);
        assert_eq!(buffer[(26, 1)].symbol(), "Z");
        assert_ne!(buffer[(27, 1)].symbol(), "Z");
        assert!(
            (1..5).any(|row| !buffer[(27, row)].symbol().trim().is_empty()),
            "reserved sidebar column contains its scrollbar"
        );
        assert_eq!(buffer[(57, 1)].symbol(), "Z");
        assert_ne!(buffer[(58, 1)].symbol(), "Z");
        assert!(
            (1..7).any(|row| !buffer[(58, row)].symbol().trim().is_empty()),
            "reserved markdown column contains its scrollbar"
        );
    }
}
