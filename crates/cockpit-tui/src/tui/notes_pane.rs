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

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState,
};
use unicode_width::UnicodeWidthStr;
use uuid::Uuid;

use crate::tui::composer::Composer;
use crate::tui::markdown;
use crate::tui::pane::Pane;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_proto::{ProjectNote, Request, Response};

static NEXT_NOTES_PANE_INSTANCE: AtomicU64 = AtomicU64::new(1);

fn next_notes_pane_instance() -> u64 {
    NEXT_NOTES_PANE_INSTANCE.fetch_add(1, Ordering::Relaxed)
}

/// Which part of the dialog has focus / what the user is doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// Browsing the sidebar; the selected note (if any) renders read-only in
    /// the main pane.
    Browsing,
    /// Editing the selected note's raw markdown source in the main pane.
    Editing { id: Uuid },
    /// A single-line name prompt is up. `for_note` is `Some(id)` for a rename
    /// and `None` for a create. `buffer` holds the typed name.
    Naming {
        for_note: Option<Uuid>,
        buffer: String,
    },
    /// Delete confirmation for the selected note.
    ConfirmingDelete { id: Uuid },
}

/// The notes dialog state. Opened over the chat body; routed input/render by
/// `App` alongside the other panes.
pub struct NotesPane {
    instance_id: u64,
    /// Project-root scoping key (git/worktree root, or launch cwd).
    project_root: String,
    /// Loaded notes for this project, in sidebar order.
    notes: Vec<ProjectNote>,
    /// Durable sidebar selection and viewport. The final selectable row is
    /// always the `+ new note` affordance at index `notes.len()`.
    sidebar: ListState,
    selection: SidebarSelection,
    operation_generation: u64,
    highest_applied_generation: Option<u64>,
    initial_inventory_unresolved: bool,
    pending_save: Option<PendingSave>,
    pending_generations: VecDeque<u64>,
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
    /// Raw editor viewport origin in terminal display columns. It is always
    /// aligned to a semantic grapheme boundary on the cursor line.
    edit_hscroll: usize,
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

#[derive(Debug, Clone)]
struct PendingSave {
    id: Uuid,
    generation: u64,
    draft: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SidebarSelection {
    /// No successful inventory has arrived yet. Visually this occupies the
    /// only available row, but it is not a user commitment to `New`.
    Uninitialized,
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
    instance_id: u64,
    project_root: String,
    kind: NotesRpcActionKind,
    generation: u64,
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
    instance_id: u64,
    generation: u64,
    project_root: String,
    notes: Vec<ProjectNote>,
    selection: SelectionAfterRpc,
    enter_edit: bool,
    error: Option<String>,
}

#[derive(Debug, Clone, Copy)]
enum SelectionAfterRpc {
    Preserve,
    Keep(Uuid),
    Deleted { fallback_index: usize },
}

impl NotesRpcAction {
    pub fn instance_id(&self) -> u64 {
        self.instance_id
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn serialization_key(&self) -> String {
        format!("notes.projection:{}", self.project_root)
    }

    pub fn run_blocking_rpc(
        self,
        endpoint: cockpit_client::ClientEndpoint,
    ) -> anyhow::Result<NotesRpcResult> {
        let generation = self.generation;
        let instance_id = self.instance_id;
        let error_project_root = self.project_root.clone();
        let project_root = self.project_root;
        let response_project_root = project_root.clone();
        let send = |request| {
            crate::tui::agent_runner::daemon_request_at_blocking(&endpoint, request)
                .map_err(anyhow::Error::msg)
        };
        let result: anyhow::Result<NotesRpcResult> = match self.kind {
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
                    generation: 0,
                    error: None,
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
                    generation: 0,
                    error: None,
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
                    generation: 0,
                    error: None,
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
                    generation: 0,
                    error: None,
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
                    generation: 0,
                    error: None,
                })
            }
        };
        Ok(match result {
            Ok(mut result) => {
                result.instance_id = instance_id;
                result.generation = generation;
                result
            }
            Err(error) => NotesRpcResult {
                instance_id,
                generation,
                project_root: error_project_root,
                notes: Vec::new(),
                selection: SelectionAfterRpc::Preserve,
                enter_edit: false,
                error: Some(error.to_string()),
            },
        })
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
    pub fn open(cwd: &std::path::Path, vim_enabled: bool) -> Self {
        let project_root = cockpit_core::git::find_worktree_root(cwd)
            .unwrap_or_else(|| cwd.to_path_buf())
            .to_string_lossy()
            .into_owned();
        Self {
            instance_id: next_notes_pane_instance(),
            project_root,
            notes: Vec::new(),
            sidebar: initial_sidebar_state(),
            selection: SidebarSelection::Uninitialized,
            operation_generation: 0,
            highest_applied_generation: None,
            initial_inventory_unresolved: true,
            pending_save: None,
            pending_generations: VecDeque::new(),
            mode: Mode::Browsing,
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            edit_hscroll: 0,
            edit_scroll_manual: false,
            last_view_width: 0,
            last_view_height: 0,
            last_view_rows: 0,
            last_edit_rows: 0,
            status: Some("loading notes".to_string()),
        }
    }

    pub fn initial_load_action(&mut self) -> NotesRpcAction {
        let action = NotesRpcAction {
            instance_id: self.instance_id,
            project_root: self.project_root.clone(),
            kind: NotesRpcActionKind::Load { keep: None },
            generation: self.operation_generation,
        };
        self.pending_generations.push_back(action.generation);
        action
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
            SidebarSelection::Uninitialized => 0,
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

    pub fn apply_rpc_result(
        &mut self,
        result: Result<NotesRpcResult, String>,
    ) -> Option<NotesRpcAction> {
        match result {
            Ok(result) => {
                if result.instance_id != self.instance_id
                    || result.project_root != self.project_root
                {
                    return None;
                }
                if (result.generation == 0 && !self.initial_inventory_unresolved)
                    || !self.pending_generations.contains(&result.generation)
                    || self
                        .highest_applied_generation
                        .is_some_and(|applied| result.generation <= applied)
                {
                    return None;
                }
                self.pending_generations
                    .retain(|generation| *generation != result.generation);
                let has_newer_intent = result.generation != self.operation_generation;
                if let Some(error) = result.error {
                    if let Some(save) = self
                        .pending_save
                        .as_ref()
                        .filter(|save| save.generation == result.generation)
                    {
                        debug_assert!(matches!(self.mode, Mode::Editing { id } if id == save.id));
                        debug_assert_eq!(self.editor.text(), save.draft);
                        self.status = Some(error);
                    } else if !has_newer_intent {
                        self.status = Some(error);
                    }
                    return None;
                }
                let old_index = self.selected_index();
                let old_selection = self.selection;
                self.notes = result.notes;
                let requested = if has_newer_intent {
                    old_selection
                } else {
                    match result.selection {
                        SelectionAfterRpc::Preserve => match old_selection {
                            SidebarSelection::Uninitialized => {
                                self.notes.first().map_or(SidebarSelection::New, |note| {
                                    SidebarSelection::Note(note.id)
                                })
                            }
                            established => established,
                        },
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
                    }
                };
                let resolved = if has_newer_intent {
                    requested
                } else {
                    match requested {
                        SidebarSelection::Uninitialized => unreachable!(
                            "successful notes refresh must resolve initial selection intent"
                        ),
                        SidebarSelection::New => SidebarSelection::New,
                        SidebarSelection::Note(id)
                            if self.notes.iter().any(|note| note.id == id) =>
                        {
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
                    }
                };
                self.selection = resolved;
                self.sidebar.select(Some(self.selected_index()));
                self.highest_applied_generation = Some(result.generation);
                if result.generation == 0 {
                    self.initial_inventory_unresolved = false;
                }
                if !has_newer_intent {
                    self.mode = Mode::Browsing;
                    if self
                        .pending_save
                        .as_ref()
                        .is_some_and(|save| save.generation == result.generation)
                    {
                        self.pending_save = None;
                    }
                    self.status = None;
                    if result.enter_edit {
                        self.enter_edit();
                    }
                }
                None
            }
            // Transport failures must carry the action envelope; callers route
            // those through `apply_transport_error` instead.
            Err(_) => None,
        }
    }

    pub fn apply_transport_error(
        &mut self,
        instance_id: u64,
        generation: u64,
        error: String,
    ) -> Option<NotesRpcAction> {
        if instance_id != self.instance_id || !self.pending_generations.contains(&generation) {
            return None;
        }
        self.pending_generations
            .retain(|pending| *pending != generation);
        if generation == self.operation_generation {
            self.status = Some(error);
        }
        None
    }

    fn schedule_action(&mut self, kind: NotesRpcActionKind) -> Option<(u64, NotesRpcAction)> {
        self.operation_generation = self.operation_generation.wrapping_add(1);
        let generation = self.operation_generation;
        self.pending_generations.push_back(generation);
        Some((
            generation,
            NotesRpcAction {
                instance_id: self.instance_id,
                project_root: self.project_root.clone(),
                kind,
                generation,
            },
        ))
    }

    fn invalidate_pending_operations(&mut self) {
        self.operation_generation = self.operation_generation.wrapping_add(1);
    }

    fn invalidate_pending_save(&mut self) {
        if self.pending_save.take().is_some() {
            self.invalidate_pending_operations();
        }
    }

    /// Begin editing the selected note: load its source into the reused
    /// composer and switch the pane to the raw editor. No-op with no note.
    fn enter_edit(&mut self) {
        let Some((id, content)) = self.current().map(|n| (n.id, n.content.clone())) else {
            return;
        };
        self.editor = Composer::with_text(content, self.vim_enabled);
        // Park the cursor at the start so a fresh edit begins at the top.
        self.editor.set_cursor(0);
        self.edit_scroll = 0;
        self.edit_hscroll = 0;
        self.edit_scroll_manual = false;
        self.invalidate_pending_operations();
        self.pending_save = None;
        self.mode = Mode::Editing { id };
    }

    /// Persist the editor buffer back to the selected note and return to the
    /// rendered view.
    fn leave_edit(&mut self) -> NotesOutcome {
        if let Mode::Editing { id } = self.mode {
            let content = self.editor.text().to_string();
            if let Some((generation, action)) =
                self.schedule_action(NotesRpcActionKind::Save { id, content })
            {
                self.pending_save = Some(PendingSave {
                    id,
                    generation,
                    draft: self.editor.text().to_string(),
                });
                return NotesOutcome::Rpc(action);
            }
            self.status = Some("Unavailable — reconnect to the daemon, then Retry".to_string());
        }
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
            Mode::ConfirmingDelete { .. } => self.handle_confirm_delete_key(key),
            Mode::Editing { .. } => self.handle_editing_key(key),
            Mode::Browsing => self.handle_browsing_key(key),
        }
    }

    pub fn paste(&mut self, text: &str) {
        match &mut self.mode {
            Mode::Editing { .. } => {
                if text.is_empty() {
                    return;
                }
                let normalized = text.replace("\r\n", "\n").replace('\r', "");
                self.editor.insert_str(&normalized);
                self.edit_scroll_manual = false;
                self.invalidate_pending_save();
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
            Mode::Browsing | Mode::ConfirmingDelete { .. } => {}
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
                if let Some((id, name)) = self.current().map(|note| (note.id, note.name.clone())) {
                    self.invalidate_pending_operations();
                    self.mode = Mode::Naming {
                        for_note: Some(id),
                        buffer: name,
                    };
                }
            }
            KeyCode::Char('d') if self.current().is_some() => {
                let id = self.current().expect("guarded selected note").id;
                self.invalidate_pending_operations();
                self.mode = Mode::ConfirmingDelete { id };
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
        self.selection = SidebarSelection::New;
        self.sidebar.select(Some(self.notes.len()));
        self.invalidate_pending_operations();
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
                let kind = match for_note {
                    Some(id) => NotesRpcActionKind::Rename { id, name },
                    None => NotesRpcActionKind::Create { name },
                };
                if let Some((_, action)) = self.schedule_action(kind) {
                    self.mode = Mode::Browsing;
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
                if let Mode::ConfirmingDelete { id } = self.mode {
                    self.mode = Mode::Browsing;
                    let fallback_index = self
                        .notes
                        .iter()
                        .position(|note| note.id == id)
                        .unwrap_or_else(|| self.selected_index());
                    if let Some((_, action)) =
                        self.schedule_action(NotesRpcActionKind::Delete { id, fallback_index })
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
        let before = self.editor.text().to_string();
        self.editor.handle_vim_key(key);
        if self.editor.text() != before {
            self.invalidate_pending_save();
        }
        NotesOutcome::Stay
    }

    fn scroll_view_down_page(&mut self) {
        let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
        self.view_scroll = (self.view_scroll + self.last_view_height.max(1)).min(max_scroll);
    }

    /// Mouse-wheel scroll for the viewed note.
    pub fn scroll_up(&mut self) {
        match self.mode {
            Mode::Editing { .. } => {
                self.edit_scroll = self.edit_scroll.saturating_sub(1);
                self.edit_scroll_manual = true;
            }
            Mode::Browsing => self.view_scroll = self.view_scroll.saturating_sub(1),
            Mode::Naming { .. } | Mode::ConfirmingDelete { .. } => {}
        }
    }

    pub fn scroll_down(&mut self) {
        match self.mode {
            Mode::Editing { .. } => {
                let max_scroll = self.last_edit_rows.saturating_sub(self.last_view_height);
                self.edit_scroll = (self.edit_scroll + 1).min(max_scroll);
                self.edit_scroll_manual = true;
            }
            Mode::Browsing => {
                let max_scroll = self.last_view_rows.saturating_sub(self.last_view_height);
                self.view_scroll = (self.view_scroll + 1).min(max_scroll);
            }
            Mode::Naming { .. } | Mode::ConfirmingDelete { .. } => {}
        }
    }

    #[cfg(test)]
    pub(crate) fn editing_for_test(content: &str, vim_enabled: bool) -> Self {
        let mut pane = Self {
            instance_id: 0,
            project_root: "/proj".to_string(),
            notes: Vec::new(),
            sidebar: initial_sidebar_state(),
            selection: SidebarSelection::New,
            operation_generation: 1,
            highest_applied_generation: None,
            initial_inventory_unresolved: false,
            pending_save: None,
            pending_generations: VecDeque::new(),
            mode: Mode::Editing { id: Uuid::nil() },
            editor: Composer::new(vim_enabled),
            vim_enabled,
            view_scroll: 0,
            edit_scroll: 0,
            edit_hscroll: 0,
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
            Mode::Browsing | Mode::Editing { .. } | Mode::ConfirmingDelete { .. }
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
            Mode::Editing { .. } => "Ctrl+S save  Esc done",
            Mode::Naming { .. } => "type a name  ↵ confirm  Esc cancel",
            Mode::ConfirmingDelete { .. } => "y delete  any other key cancel",
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
            Mode::ConfirmingDelete { id } => {
                let name = self
                    .notes
                    .iter()
                    .find(|note| note.id == *id)
                    .map(|note| note.name.clone())
                    .unwrap_or_else(|| "missing note".to_string());
                let line = Line::from(Span::styled(
                    format!("Delete note `{name}`? [y/N]"),
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ));
                frame.render_widget(Paragraph::new(line), area);
            }
            Mode::Editing { .. } => {
                // Raw editable markdown source (never rendered while editing).
                let height = area.height.max(1) as usize;
                let text = self.editor.text().to_string();
                let source_lines = if text.is_empty() {
                    vec![""]
                } else {
                    text.split('\n').collect::<Vec<_>>()
                };
                self.last_edit_rows = source_lines.len();
                let max_scroll = source_lines.len().saturating_sub(height);
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
                let cursor_source = source_lines.get(cursor_line).copied().unwrap_or_default();
                self.edit_hscroll =
                    cursor_follow_hscroll(cursor_source, cursor_col, self.edit_hscroll, width);
                let lines = source_lines
                    .into_iter()
                    .map(|line| Line::from(display_column_slice(line, self.edit_hscroll, width)))
                    .collect::<Vec<_>>();
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
                let cursor_view_col = cursor_col.saturating_sub(self.edit_hscroll);
                let cursor_x = content_area.x + cursor_view_col as u16;
                if cursor_y < content_area.y + content_area.height
                    && cursor_line >= self.edit_scroll
                    && cursor_view_col < width
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

fn cursor_follow_hscroll(line: &str, cursor_col: usize, _current: usize, width: usize) -> usize {
    let width = width.max(1);
    let graphemes = markdown::semantic_graphemes(line);
    let mut column = 0usize;
    let mut boundaries = vec![0usize];
    let mut cursor_width = 1usize;
    for grapheme in graphemes {
        let grapheme_width = UnicodeWidthStr::width(grapheme.as_str());
        if column == cursor_col {
            cursor_width = grapheme_width.max(1);
        }
        column += grapheme_width;
        boundaries.push(column);
    }
    let required = cursor_col
        .saturating_add(cursor_width)
        .saturating_sub(width);
    // There is no manual horizontal mode: choose the smallest aligned origin
    // that exposes the full cursor grapheme, revealing more left context as
    // soon as a resize or edit makes it possible.
    let desired = required;
    boundaries
        .into_iter()
        .find(|boundary| *boundary >= desired)
        .unwrap_or(column)
        .min(cursor_col)
}

fn display_column_slice(line: &str, start: usize, width: usize) -> String {
    let end = start.saturating_add(width.max(1));
    let mut column = 0usize;
    let mut output = String::new();
    for grapheme in markdown::semantic_graphemes(line) {
        let grapheme_width = UnicodeWidthStr::width(grapheme.as_str());
        let grapheme_end = column.saturating_add(grapheme_width);
        if grapheme_end <= start {
            column = grapheme_end;
            continue;
        }
        if column < start {
            output.push_str(&" ".repeat(grapheme_end.saturating_sub(start)));
            column = grapheme_end;
            continue;
        }
        if grapheme_end > end {
            break;
        }
        output.push_str(&grapheme);
        column = grapheme_end;
    }
    output
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
    use ratatui::{Terminal, backend::Backend, backend::TestBackend};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn pane(_connected: bool) -> NotesPane {
        let id = Uuid::new_v4();
        let mut pane = NotesPane {
            instance_id: 0,
            project_root: "/proj".to_string(),
            notes: vec![ProjectNote {
                id,
                project_root: "/proj".into(),
                name: "ideas".into(),
                content: "before".into(),
            }],
            sidebar: initial_sidebar_state(),
            selection: SidebarSelection::Note(id),
            operation_generation: 1,
            highest_applied_generation: None,
            initial_inventory_unresolved: false,
            pending_save: None,
            pending_generations: VecDeque::new(),
            mode: Mode::Browsing,
            editor: Composer::new(false),
            vim_enabled: false,
            view_scroll: 0,
            edit_scroll: 0,
            edit_hscroll: 0,
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

    fn mark_initial_inventory_unresolved(pane: &mut NotesPane) {
        pane.operation_generation = 0;
        pane.highest_applied_generation = None;
        pane.initial_inventory_unresolved = true;
        pane.selection = SidebarSelection::Uninitialized;
        pane.pending_generations = VecDeque::from([0]);
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

    fn rendered_editor(pane: &mut NotesPane, width: u16, height: u16) -> (String, (u16, u16)) {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).expect("terminal");
        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw notes editor");
        let cursor = terminal
            .backend_mut()
            .get_cursor_position()
            .expect("cursor position");
        let content = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        (content, (cursor.x, cursor.y))
    }

    #[test]
    fn endpoint_state_does_not_suppress_confirmed_intent() {
        let mut pane = pane(false);
        pane.start_create();
        if let Mode::Naming { buffer, .. } = &mut pane.mode {
            buffer.push_str("new");
        }
        assert!(matches!(
            pane.handle_key(press(KeyCode::Enter)),
            NotesOutcome::Rpc(_)
        ));
        assert_eq!(pane.notes.len(), 1);
        assert!(pane.pending_generations.front().is_some());
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
        pane.pending_generations = VecDeque::from([1]);

        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
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
        let applied_ids = pane.notes.iter().map(|note| note.id).collect::<Vec<_>>();
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(Uuid::new_v4(), "duplicate", "must be ignored")],
            selection: SelectionAfterRpc::Keep(Uuid::new_v4()),
            enter_edit: false,
        }));
        assert_eq!(
            pane.notes.iter().map(|note| note.id).collect::<Vec<_>>(),
            applied_ids,
            "duplicate generation is ignored"
        );
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
        pane.pending_generations = VecDeque::from([1]);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
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
        pane.operation_generation = 2;
        pane.pending_generations = VecDeque::from([2]);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 2,
            error: None,
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
        pane.operation_generation = 3;
        pane.pending_generations = VecDeque::from([3]);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 3,
            error: None,
            project_root: "/proj".into(),
            notes: pane.notes.clone(),
            selection: SelectionAfterRpc::Keep(Uuid::new_v4()),
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::Note(fallback));

        pane.operation_generation = 4;
        pane.pending_generations = VecDeque::from([4]);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 4,
            error: None,
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Deleted { fallback_index: 1 },
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::New);
        assert_eq!(pane.selected_index(), 0);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 2,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(Uuid::new_v4(), "stale", "must be ignored")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert!(
            pane.notes.is_empty(),
            "older positive generation is ignored"
        );
        assert_eq!(pane.selection, SidebarSelection::New);
    }

    #[test]
    fn initial_selection_is_distinct_from_explicit_new_across_loads_and_errors() {
        let first = Uuid::new_v4();
        let mut initial = pane(true);
        initial.notes.clear();
        mark_initial_inventory_unresolved(&mut initial);
        let _ = initial.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 0,
            error: None,
            project_root: "/proj".into(),
            notes: vec![
                note(first, "first", "a"),
                note(Uuid::new_v4(), "second", "b"),
            ],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(initial.selection, SidebarSelection::Note(first));
        assert_eq!(initial.selected_index(), 0);

        let mut initially_empty = pane(true);
        initially_empty.notes.clear();
        mark_initial_inventory_unresolved(&mut initially_empty);
        let _ = initially_empty.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 0,
            error: None,
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(initially_empty.selection, SidebarSelection::New);
        initially_empty.operation_generation = 1;
        initially_empty.pending_generations = VecDeque::from([1]);
        let _ = initially_empty.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(first, "arrived later", "a")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(initially_empty.selection, SidebarSelection::New);
        assert_eq!(initially_empty.selected_index(), 1);

        let mut retry = pane(true);
        retry.notes.clear();
        mark_initial_inventory_unresolved(&mut retry);
        let _ = retry.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 0,
            error: Some("temporary daemon failure".into()),
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(retry.selection, SidebarSelection::Uninitialized);
        assert_eq!(retry.status.as_deref(), Some("temporary daemon failure"));
        retry.pending_generations = VecDeque::from([0]);
        let _ = retry.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 0,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(first, "first after retry", "a")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(retry.selection, SidebarSelection::Note(first));

        retry.select_sidebar(retry.notes.len());
        retry.operation_generation = 1;
        retry.pending_generations = VecDeque::from([1]);
        let _ = retry.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![
                note(Uuid::new_v4(), "inserted", "x"),
                note(first, "first after retry", "a"),
            ],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(retry.selection, SidebarSelection::New);
        assert_eq!(retry.selected_index(), 2);
    }

    #[test]
    fn pending_initial_completion_preserves_keyboard_and_pointer_new_drafts() {
        for activation in [KeyCode::Char('n'), KeyCode::Enter] {
            let mut pane = pane(true);
            pane.notes.clear();
            mark_initial_inventory_unresolved(&mut pane);
            pane.sidebar.select(Some(0));
            pane.handle_key(press(activation));
            assert_eq!(pane.selection, SidebarSelection::New);
            assert!(matches!(pane.mode, Mode::Naming { .. }));

            let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
                instance_id: 0,
                generation: 0,
                error: None,
                project_root: "/proj".into(),
                notes: vec![note(Uuid::new_v4(), "arrived", "content")],
                selection: SelectionAfterRpc::Preserve,
                enter_edit: false,
            }));
            assert_eq!(pane.selection, SidebarSelection::New);
            assert!(matches!(pane.mode, Mode::Naming { .. }));

            let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
                instance_id: 0,
                generation: 0,
                error: Some("stale load error".into()),
                project_root: "/proj".into(),
                notes: Vec::new(),
                selection: SelectionAfterRpc::Preserve,
                enter_edit: false,
            }));
            assert!(pane.status.is_none());
            assert!(matches!(pane.mode, Mode::Naming { .. }));
        }

        let mut pointer = pane(true);
        pointer.pointer_new_note();
        assert_eq!(pointer.selection, SidebarSelection::New);
        assert!(matches!(pointer.mode, Mode::Naming { .. }));
    }

    #[test]
    fn edit_and_delete_remain_bound_to_captured_note_identity() {
        let edited = Uuid::new_v4();
        let other = Uuid::new_v4();
        let mut pane = pane(true);
        pane.notes = vec![
            note(edited, "edited", "draft"),
            note(other, "other", "other"),
        ];
        pane.select_sidebar(0);
        pane.pending_generations = VecDeque::from([1]);
        pane.enter_edit();
        assert!(matches!(pane.mode, Mode::Editing { id } if id == edited));
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(other, "other", "changed")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(
            pane.notes.len(),
            1,
            "serialized older completion may refresh inventory during edit"
        );
        let NotesOutcome::Rpc(save) = pane.leave_edit() else {
            panic!("save action");
        };
        assert!(matches!(save.kind, NotesRpcActionKind::Save { id, .. } if id == edited));

        let mut pane = pane(true);
        pane.notes = vec![
            note(edited, "edited", "draft"),
            note(other, "other", "other"),
        ];
        pane.select_sidebar(0);
        pane.pending_generations = VecDeque::from([1]);
        pane.handle_key(press(KeyCode::Char('d')));
        assert!(matches!(pane.mode, Mode::ConfirmingDelete { id } if id == edited));
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(other, "other", "changed")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert_eq!(
            pane.notes.len(),
            1,
            "serialized older completion may refresh inventory during confirmation"
        );
        let NotesOutcome::Rpc(delete) = pane.handle_key(press(KeyCode::Char('y'))) else {
            panic!("delete action");
        };
        assert!(matches!(delete.kind, NotesRpcActionKind::Delete { id, .. } if id == edited));
    }

    #[test]
    fn failed_save_keeps_exact_draft_and_new_edits_supersede_pending_completion() {
        let id = pane(true).notes[0].id;
        let mut pane = pane(true);
        pane.notes[0].id = id;
        pane.selection = SidebarSelection::Note(id);
        pane.enter_edit();
        pane.editor.set("exact unsaved draft".to_string());
        let NotesOutcome::Rpc(save) = pane.leave_edit() else {
            panic!("save action");
        };
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: save.generation,
            error: Some("disk full".into()),
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Keep(id),
            enter_edit: false,
        }));
        assert!(matches!(pane.mode, Mode::Editing { id: editing } if editing == id));
        assert_eq!(pane.editor.text(), "exact unsaved draft");
        assert_eq!(pane.status.as_deref(), Some("disk full"));

        let NotesOutcome::Rpc(second_save) = pane.leave_edit() else {
            panic!("second save action");
        };
        pane.edit_scroll_manual = true;
        pane.paste("!");
        assert!(pane.editor.text().contains('!'));
        assert!(pane.pending_save.is_none());
        assert!(!pane.edit_scroll_manual);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: second_save.generation,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(id, "ideas", "exact unsaved draft")],
            selection: SelectionAfterRpc::Keep(id),
            enter_edit: false,
        }));
        assert!(matches!(pane.mode, Mode::Editing { id: editing } if editing == id));
        assert!(pane.editor.text().contains('!'));
    }

    #[test]
    fn stalled_initial_load_serializes_before_mutations_and_cannot_replay() {
        let resurrected = Uuid::new_v4();
        let created = Uuid::new_v4();
        let mut pane = pane(true);
        pane.notes.clear();
        mark_initial_inventory_unresolved(&mut pane);

        pane.handle_key(press(KeyCode::Char('n')));
        pane.paste("created");
        let NotesOutcome::Rpc(create) = pane.handle_key(press(KeyCode::Enter)) else {
            panic!("confirmed create is handed to the app lane immediately");
        };
        assert_eq!(
            pane.pending_generations,
            VecDeque::from([0, create.generation])
        );
        let next = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 0,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(resurrected, "old snapshot", "stale")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert!(next.is_none());
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: create.generation,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(created, "created", "")],
            selection: SelectionAfterRpc::Keep(created),
            enter_edit: true,
        }));

        pane.editor.set("saved body".to_string());
        let NotesOutcome::Rpc(save) = pane.leave_edit() else {
            panic!("save action");
        };
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: save.generation,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(created, "created", "saved body")],
            selection: SelectionAfterRpc::Keep(created),
            enter_edit: false,
        }));

        pane.handle_key(press(KeyCode::Char('r')));
        pane.paste(" renamed");
        let NotesOutcome::Rpc(rename) = pane.handle_key(press(KeyCode::Enter)) else {
            panic!("rename action");
        };
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: rename.generation,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(created, "created renamed", "saved body")],
            selection: SelectionAfterRpc::Keep(created),
            enter_edit: false,
        }));

        pane.handle_key(press(KeyCode::Char('d')));
        let NotesOutcome::Rpc(delete) = pane.handle_key(press(KeyCode::Char('y'))) else {
            panic!("delete action");
        };
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: delete.generation,
            error: None,
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Deleted { fallback_index: 0 },
            enter_edit: false,
        }));
        assert!(pane.notes.is_empty());
        let applied = pane.highest_applied_generation;

        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 0,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(resurrected, "old snapshot", "stale")],
            selection: SelectionAfterRpc::Preserve,
            enter_edit: false,
        }));
        assert!(
            pane.notes.is_empty(),
            "stalled load must not resurrect deleted data"
        );
        assert_eq!(pane.selection, SidebarSelection::New);
        assert_eq!(pane.highest_applied_generation, applied);
    }

    #[test]
    fn serialized_saves_execute_a_then_b_and_latest_failure_keeps_b_draft() {
        let mut pane = pane(true);
        pane.pending_generations.clear();
        pane.enter_edit();
        let id = match pane.mode {
            Mode::Editing { id } => id,
            _ => unreachable!(),
        };
        pane.editor.set("draft A".to_string());
        let NotesOutcome::Rpc(save_a) = pane.leave_edit() else {
            panic!("A starts immediately");
        };
        pane.paste(" + draft B");
        let b_draft = pane.editor.text().to_string();
        let NotesOutcome::Rpc(save_b) = pane.leave_edit() else {
            panic!("B is handed to the serialized app lane immediately");
        };
        assert_eq!(
            pane.pending_generations,
            VecDeque::from([save_a.generation, save_b.generation])
        );

        let next = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: save_a.generation,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(id, "ideas", "draft A")],
            selection: SelectionAfterRpc::Keep(id),
            enter_edit: false,
        }));
        assert!(next.is_none());
        assert!(matches!(save_b.kind, NotesRpcActionKind::Save { id: saved, .. } if saved == id));
        assert_eq!(pane.notes[0].content, "draft A");
        assert!(matches!(pane.mode, Mode::Editing { id: editing } if editing == id));

        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: save_b.generation,
            error: Some("disk full on B".into()),
            project_root: "/proj".into(),
            notes: Vec::new(),
            selection: SelectionAfterRpc::Keep(id),
            enter_edit: false,
        }));
        assert_eq!(pane.notes[0].content, "draft A");
        assert_eq!(pane.editor.text(), b_draft);
        assert_eq!(pane.status.as_deref(), Some("disk full on B"));
    }

    #[test]
    fn confirmed_mutations_are_all_handed_to_the_same_app_lane() {
        let mut pane = pane(true);
        pane.pending_generations.clear();
        let id = pane.notes[0].id;
        let (_, first) = pane
            .schedule_action(NotesRpcActionKind::Rename {
                id,
                name: "first".into(),
            })
            .unwrap();
        let (duplicate_generation, duplicate) = pane
            .schedule_action(NotesRpcActionKind::Rename {
                id,
                name: "first".into(),
            })
            .unwrap();
        let (delete_generation, delete) = pane
            .schedule_action(NotesRpcActionKind::Delete {
                id,
                fallback_index: 0,
            })
            .unwrap();
        assert_eq!(duplicate.generation, duplicate_generation);
        assert_eq!(delete.generation, delete_generation);
        assert_eq!(first.serialization_key(), duplicate.serialization_key());
        assert_eq!(duplicate.serialization_key(), delete.serialization_key());
        assert_eq!(
            pane.pending_generations,
            VecDeque::from([first.generation, duplicate_generation, delete_generation])
        );
        assert!(
            matches!(delete.kind, NotesRpcActionKind::Delete { id: deleted, .. } if deleted == id)
        );
    }

    #[test]
    fn pane_instances_are_monotonic_and_reject_closed_pane_completions() {
        let first_instance = next_notes_pane_instance();
        let second_instance = next_notes_pane_instance();
        assert!(second_instance > first_instance);

        let mut reopened = pane(true);
        reopened.instance_id = second_instance;
        reopened.pending_generations = VecDeque::from([1]);
        let original = reopened.notes.clone();
        let foreign_note = Uuid::new_v4();

        let _ = reopened.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: first_instance,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(foreign_note, "closed pane", "stale")],
            selection: SelectionAfterRpc::Keep(foreign_note),
            enter_edit: false,
        }));
        assert_eq!(reopened.notes, original);
        assert_eq!(reopened.pending_generations.front().copied(), Some(1));
        assert!(
            reopened
                .apply_transport_error(first_instance, 1, "closed pane error".into())
                .is_none()
        );
        assert_eq!(reopened.pending_generations.front().copied(), Some(1));

        let current_note = Uuid::new_v4();
        let _ = reopened.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: second_instance,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(current_note, "reopened", "current")],
            selection: SelectionAfterRpc::Keep(current_note),
            enter_edit: false,
        }));
        assert_eq!(reopened.notes[0].id, current_note);
        assert_eq!(reopened.pending_generations.front().copied(), None);

        let _ = reopened.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: first_instance,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(foreign_note, "closed pane", "stale")],
            selection: SelectionAfterRpc::Keep(foreign_note),
            enter_edit: false,
        }));
        assert_eq!(reopened.notes[0].id, current_note);
        assert!(
            reopened
                .apply_transport_error(first_instance, 1, "late closed pane error".into())
                .is_none()
        );
        assert_eq!(reopened.notes[0].id, current_note);
    }

    #[test]
    fn transport_error_settles_one_generation_and_duplicate_is_inert() {
        let mut pane = pane(true);
        pane.instance_id = 41;
        pane.pending_generations.clear();
        pane.enter_edit();
        let id = pane.notes[0].id;
        pane.editor.set("first draft".into());
        let NotesOutcome::Rpc(first) = pane.leave_edit() else {
            panic!("first save starts");
        };
        pane.paste(" plus queued draft");
        let queued_draft = pane.editor.text().to_string();
        let NotesOutcome::Rpc(second) = pane.leave_edit() else {
            panic!("second save is handed to the app lane immediately");
        };
        let queued_generation = second.generation;

        let next = pane.apply_transport_error(41, first.generation, "worker stopped".into());
        assert!(next.is_none(), "the app lane owns release and dispatch");
        assert_eq!(second.instance_id, 41);
        assert_eq!(second.generation, queued_generation);
        assert_eq!(
            pane.pending_generations.front().copied(),
            Some(queued_generation)
        );
        assert_eq!(pane.editor.text(), queued_draft);
        assert!(matches!(pane.mode, Mode::Editing { id: editing } if editing == id));
        assert_eq!(
            pane.status, None,
            "the older failure must not replace newer state"
        );

        assert!(
            pane.apply_transport_error(41, first.generation, "duplicate".into())
                .is_none()
        );
        assert!(
            pane.apply_transport_error(40, queued_generation, "wrong pane".into())
                .is_none()
        );
        assert_eq!(
            pane.pending_generations.front().copied(),
            Some(queued_generation)
        );

        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 41,
            generation: queued_generation,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(id, "ideas", &queued_draft)],
            selection: SelectionAfterRpc::Keep(id),
            enter_edit: false,
        }));
        assert_eq!(pane.notes[0].content, queued_draft);
        assert_eq!(pane.pending_generations.front().copied(), None);
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
        pane.pending_generations = VecDeque::from([1]);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 1,
            error: None,
            project_root: "/proj".into(),
            notes: vec![note(first, "first", "a"), note(next, "next", "c")],
            selection: SelectionAfterRpc::Deleted { fallback_index: 1 },
            enter_edit: false,
        }));
        assert_eq!(pane.selection, SidebarSelection::Note(next));

        pane.operation_generation = 2;
        pane.pending_generations = VecDeque::from([2]);
        let _ = pane.apply_rpc_result(Ok(NotesRpcResult {
            instance_id: 0,
            generation: 2,
            error: None,
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
    fn raw_editor_horizontal_view_follows_ascii_cursor_and_resize() {
        let text = "0123456789abcdefghijklmnopqrstuvwxyz";
        let mut pane = NotesPane::editing_for_test(text, false);
        pane.editor.set_cursor(text.len());
        let (narrow, cursor) = rendered_editor(&mut pane, 40, 8);
        assert!(pane.edit_hscroll > 0);
        assert!(narrow.contains("rstuvwxyz"));
        assert_eq!(cursor.0 as usize, 29 + text.len() - pane.edit_hscroll);

        pane.handle_key(press(KeyCode::Home));
        let (_, home_cursor) = rendered_editor(&mut pane, 40, 8);
        assert_eq!(pane.edit_hscroll, 0);
        assert_eq!(home_cursor.0, 29);

        pane.handle_key(press(KeyCode::End));
        let _ = rendered_editor(&mut pane, 40, 8);
        let previous_scroll = pane.edit_hscroll;
        let (_, wide_cursor) = rendered_editor(&mut pane, 60, 8);
        assert!(pane.edit_hscroll < previous_scroll);
        assert_eq!(wide_cursor.0 as usize, 29 + text.len() - pane.edit_hscroll);

        pane.handle_key(press(KeyCode::Backspace));
        pane.handle_key(press(KeyCode::Char('界')));
        let (_, edited_cursor) = rendered_editor(&mut pane, 40, 8);
        assert!(edited_cursor.0 < 39);
        assert_eq!(
            edited_cursor.0 as usize,
            29 + pane.editor.cursor_line_col().1 - pane.edit_hscroll
        );
        pane.handle_key(press(KeyCode::Left));
        let (_, left_cursor) = rendered_editor(&mut pane, 40, 8);
        assert_eq!(
            left_cursor.0 as usize,
            29 + pane.editor.cursor_line_col().1 - pane.edit_hscroll
        );
        pane.handle_key(press(KeyCode::Right));
        let (_, right_cursor) = rendered_editor(&mut pane, 40, 8);
        assert_eq!(
            right_cursor.0 as usize,
            29 + pane.editor.cursor_line_col().1 - pane.edit_hscroll
        );
    }

    #[test]
    fn raw_editor_slice_never_splits_semantic_graphemes() {
        let family = "👨‍👩‍👧‍👦";
        let combining = "e\u{301}";
        let line = format!("ab中{family}{combining}tail");
        let family_col = UnicodeWidthStr::width("ab中");
        let family_width = UnicodeWidthStr::width(family);
        let combining_col = family_col + family_width;

        assert_eq!(
            display_column_slice(&line, family_col, family_width),
            family
        );
        assert_eq!(display_column_slice(&line, combining_col, 1), combining);
        let inside_wide = display_column_slice(&line, family_col.saturating_sub(1), 3);
        assert!(!inside_wide.contains('\u{200d}') || inside_wide.contains(family));

        let hscroll = cursor_follow_hscroll(&line, family_col, 0, family_width);
        assert_eq!(hscroll, family_col);
        let combining_scroll = cursor_follow_hscroll(&line, combining_col, hscroll, 1);
        assert_eq!(combining_scroll, combining_col);

        let mut pane = NotesPane::editing_for_test(&line, false);
        let family_byte = line.find(family).unwrap();
        pane.editor.set_cursor(family_byte);
        let (rendered, cursor) = rendered_editor(&mut pane, 34, 8);
        assert!(rendered.contains(family));
        assert_eq!(cursor.0 as usize, 29 + family_col - pane.edit_hscroll);
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
