//! `/settings → Agents` page (implementation note).
//!
//! A full management surface over the bundled cast
//! (`Build`/`builder`/`explore`/`Plan`) and any user-authored
//! custom agents. Each row shows the agent name, its builtin/custom
//! (+ overridden) status, and its **effective model** (the frontmatter
//! `model:` in canonical `provider/model` slash form, or the session
//! default). The docs pipeline is deliberately absent: it is a fixed
//! two-stage internal pipeline, never a user-editable [`cockpit_core::agents::AgentDef`].
//!
//! Actions:
//!   - `enter` — open the structured tool surface editor for the highlighted
//!     agent.
//!   - `e` — **raw edit** the highlighted agent's on-disk
//!     `.cockpit/agents/<name>.md`. A non-overridden built-in is
//!     auto-ejected first (existing [`cockpit_core::agents::eject_builtin`] path).
//!     The editor is chosen by precedence: `$EDITOR` (external, the event
//!     loop suspends/restores the TUI) → in-TUI vim editor (when vim mode
//!     is on) → in-TUI plain editor. On return the file is re-read from
//!     disk + re-parsed; a parse error is shown inline and the user stays
//!     on the page.
//!   - `d` — **delete** a custom agent (arm→confirm via [`ResetButton`]).
//!     Built-ins can never be deleted.
//!   - `r` — **reset** the highlighted *overridden* built-in to its
//!     embedded default (arm→confirm), deleting just that one override.
//!   - `R` — **reset all** built-in overrides (the existing confirm flow).
//!
//! The page reads agents fresh from disk on entry and after each
//! edit/eject/delete/reset so the overridden/custom markers + effective
//! model stay accurate.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;
use crate::tui::tool_surface_picker::{
    ToolSurfaceDraft, ToolSurfaceEditOutcome, ToolSurfacePicker, ToolSurfaceRender,
    tool_surface_lines,
};
#[cfg(test)]
use cockpit_core::agents::ToolTier;
use cockpit_core::agents::{AgentDef, AgentKind, AgentListing, is_builtin_agent, list_all};

use super::agent_editor::{AgentEditor, EditorOutcome};
use super::reset::{ResetButton, ResetOutcome};
use super::shell::{
    PointerOperationGate, PointerOperationId, SettingsScrollRegionId, push_wrapped_text,
    selected_line_from_marker,
};
use super::{Nav, SettingsCx, SettingsPage};
#[cfg(test)]
use super::{Page, SettingsDialog, TestPageMut, TestPageRef};

/// `/settings → Agents` state.
pub(super) struct AgentsPage {
    pub(super) cursor: usize,
    /// True while the "reset all built-in agents" confirmation is shown.
    pub(super) confirm_reset: bool,
    /// Arm→confirm guard for deleting the highlighted **custom** agent.
    pub(super) delete: ResetButton,
    /// Arm→confirm guard for resetting the highlighted **overridden
    /// built-in** to its embedded default.
    pub(super) reset_one: ResetButton,
    pub(super) status: Option<String>,
    /// One row per discovered agent (built-ins first, then custom).
    pub(super) rows: Vec<AgentRow>,
    /// In-TUI editor, present while the user is editing an agent file
    /// without `$EDITOR` (vim or plain — see editor-precedence ladder).
    pub(super) editing: Option<AgentEditor>,
    pub(super) detail: Option<AgentDetail>,
    /// Set when the user chose to edit and `$EDITOR` is available: the
    /// event loop drains this (the page can't suspend the TUI itself),
    /// runs `$EDITOR`, then calls back to re-read + re-parse.
    pub(super) pending_external_edit: Option<AgentExternalEdit>,
    /// Pointer/keyboard confirmation shown before the raw editor hands the
    /// current buffer to `$EDITOR`.  Keeping this separate from the live
    /// operation means repeated presses cannot submit an effect early.
    pub(super) external_edit_confirmation: Option<super::pointer_actions::AgentId>,
    external_edit_ops: PointerOperationGate,
    editor_body: Cell<Option<Rect>>,
}

pub(super) struct AgentExternalEdit {
    pub(super) id: PointerOperationId,
    pub(super) agent: super::pointer_actions::AgentId,
    pub(super) path: PathBuf,
    /// Same-directory staging file. The real path is replaced only after a
    /// matching typed `Saved` completion.
    staging: tempfile::TempPath,
    original_contents: Vec<u8>,
    original_metadata: AgentFileMetadata,
    /// Buffer write owned by the injected host effect.
    pub(super) text_before_launch: String,
    /// Raw draft retained until the effect reaches a terminal outcome. A
    /// failed/cancelled operation restores this exact editor for retry.
    draft: Option<AgentEditor>,
    servicing: bool,
}

/// Injected host-effect submission. The settings reducer only constructs this
/// value; the App owns the optional buffer write, terminal suspension/editor
/// launch, and completion callback.
pub(crate) struct AgentExternalEditEffect {
    pub(crate) operation_id: PointerOperationId,
    pub(crate) path: PathBuf,
    pub(crate) text_before_launch: String,
}

struct AgentExternalEditStaging {
    path: tempfile::TempPath,
    original_contents: Vec<u8>,
    original_metadata: AgentFileMetadata,
}

struct AgentFileMetadata {
    permissions: std::fs::Permissions,
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    gid: u32,
}

impl AgentFileMetadata {
    fn capture(metadata: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        Self {
            permissions: metadata.permissions(),
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(unix)]
            uid: metadata.uid(),
            #[cfg(unix)]
            gid: metadata.gid(),
        }
    }

    fn matches(&self, metadata: &std::fs::Metadata) -> bool {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt;
        self.len == metadata.len()
            && self.modified == metadata.modified().ok()
            && self.permissions.readonly() == metadata.permissions().readonly()
            && {
                #[cfg(unix)]
                {
                    self.device == metadata.dev()
                        && self.inode == metadata.ino()
                        && self.mode == metadata.mode()
                        && self.uid == metadata.uid()
                        && self.gid == metadata.gid()
                }
                #[cfg(not(unix))]
                {
                    true
                }
            }
    }
}

fn agent_external_edit_staging(
    target: &std::path::Path,
) -> Result<AgentExternalEditStaging, String> {
    let metadata = std::fs::symlink_metadata(target)
        .map_err(|error| format!("failed to inspect external-edit target: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "refusing to externally edit symbolic link {}",
            target.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "refusing to externally edit non-file {}",
            target.display()
        ));
    }
    let mut original = std::fs::File::open(target)
        .map_err(|error| format!("failed to open external-edit target: {error}"))?;
    let opened_metadata = original
        .metadata()
        .map_err(|error| format!("failed to inspect opened external-edit target: {error}"))?;
    let original_metadata = AgentFileMetadata::capture(&metadata);
    if !original_metadata.matches(&opened_metadata) {
        return Err("external-edit target changed while it was being opened".into());
    }
    let mut original_contents = Vec::new();
    std::io::Read::read_to_end(&mut original, &mut original_contents)
        .map_err(|error| format!("failed to read external-edit target: {error}"))?;
    let parent = target
        .parent()
        .ok_or_else(|| format!("external edit target has no parent: {}", target.display()))?;
    let path = tempfile::Builder::new()
        .prefix(".cockpit-agent-edit-")
        .suffix(".stage")
        .tempfile_in(parent)
        .map(|file| file.into_temp_path())
        .map_err(|error| format!("failed to create external-edit staging file: {error}"))?;
    Ok(AgentExternalEditStaging {
        path,
        original_contents,
        original_metadata,
    })
}

/// A flattened, render-ready view of one [`AgentListing`]. We snapshot the
/// fields the page needs so the page state doesn't borrow the (non-`Clone`,
/// error-carrying) listing.
pub(super) struct AgentRow {
    pub(super) name: String,
    pub(super) kind: AgentKind,
    /// `Ok(description)` when the agent parsed cleanly; `Err(error)`
    /// rendered distinctly when its file is malformed.
    pub(super) detail: Result<String, String>,
    /// Effective model display string: the frontmatter `model:` (canonical
    /// `provider/model` slash form), or `None` when the agent inherits the
    /// session's active model.
    pub(super) model: Option<String>,
    source: AgentRowSource,
}

#[derive(Clone)]
enum AgentRowSource {
    Agent,
    Assistant {
        home_dir: PathBuf,
        config_json: String,
    },
}

pub(super) struct AgentDetail {
    name: String,
    path: PathBuf,
    original_text: String,
    def: AgentDef,
    draft: Box<ToolSurfaceDraft>,
    picker: ToolSurfacePicker,
    status: Option<String>,
    row_errors: BTreeMap<String, String>,
    source: AgentRowSource,
}

impl AgentsPage {
    /// Build the page by discovering agents at `cwd`.
    pub(super) fn new(cwd: &std::path::Path) -> Self {
        let (rows, status) = rows_for(cwd);
        Self {
            cursor: 0,
            confirm_reset: false,
            delete: ResetButton::default(),
            reset_one: ResetButton::default(),
            status,
            rows,
            editing: None,
            detail: None,
            pending_external_edit: None,
            external_edit_confirmation: None,
            external_edit_ops: PointerOperationGate::default(),
            editor_body: Cell::new(None),
        }
    }

    /// Help line for the footer, varying with the page sub-state.
    pub(super) fn help_text(&self) -> &'static str {
        if self.editing.is_some() {
            // The in-TUI editor draws its own hint; this is the footer.
            return "editing agent — ctrl+s: save  esc: cancel";
        }
        if self.detail.is_some() {
            return "↑/↓  space: grant  t: tier  ctrl+s: save  e: raw editor  esc: list";
        }
        if self.confirm_reset {
            return "y: confirm reset-all  n/esc: cancel";
        }
        match self.rows.get(self.cursor).map(|r| &r.kind) {
            Some(AgentKind::Custom) => {
                "↑/↓  enter: tools  e: raw edit  d: delete (×2)  R: reset all  esc/h: back  q: close"
            }
            Some(AgentKind::Builtin { overridden: true }) => {
                "↑/↓  enter: tools  e: raw edit  r: reset (×2)  R: reset all  esc/h: back  q: close"
            }
            _ => "↑/↓  enter: tools  e: raw edit  R: reset all  esc/h: back  q: close",
        }
    }

    /// Disarm both per-agent confirm guards. Called on any navigation /
    /// cancel so a stale "press again" can never fire on a different row.
    fn disarm_guards(&mut self) {
        self.delete.disarm();
        self.reset_one.disarm();
    }

    pub(super) fn take_external_edit_request(&mut self) -> Option<AgentExternalEditEffect> {
        let pending = self.pending_external_edit.as_mut()?;
        if pending.servicing {
            return None;
        }
        pending.servicing = true;
        Some(AgentExternalEditEffect {
            operation_id: pending.id,
            path: pending.staging.to_path_buf(),
            text_before_launch: pending.text_before_launch.clone(),
        })
    }

    /// Re-read the edited file from disk, re-parse it, and refresh the row.
    /// A parse error is surfaced inline (keeping the user on the page); the
    /// `editor_error` from a failed external process is reported as-is.
    pub(super) fn finish_external_edit(
        &mut self,
        cwd: &std::path::Path,
        id: PointerOperationId,
        outcome: super::pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Some(agent) = self
            .pending_external_edit
            .as_ref()
            .filter(|pending| pending.id == id)
            .map(|pending| pending.agent.clone())
        else {
            return;
        };
        self.reduce_external_edit_result(
            cwd,
            id,
            super::pointer_actions::AgentsAction::ExternalEditResult(agent, outcome),
            detail,
        );
    }

    fn reduce_external_edit_result(
        &mut self,
        cwd: &std::path::Path,
        id: PointerOperationId,
        action: super::pointer_actions::AgentsAction,
        detail: Option<String>,
    ) {
        let super::pointer_actions::AgentsAction::ExternalEditResult(agent, outcome) = action
        else {
            return;
        };
        let Some(agent) = self
            .pending_external_edit
            .as_ref()
            .filter(|request| request.id == id && request.agent == agent)
            .map(|request| request.agent.clone())
        else {
            return;
        };
        if !self.external_edit_ops.complete(id) {
            return;
        }
        let Some(mut pending) = self.pending_external_edit.take() else {
            return;
        };
        match outcome {
            super::pointer_actions::ExternalEditOutcome::Saved => {
                let draft = pending.draft.take();
                let commit = (|| -> Result<(), String> {
                    let current_metadata = std::fs::symlink_metadata(&pending.path)
                        .map_err(|error| format!("failed to revalidate agent path: {error}"))?;
                    if current_metadata.file_type().is_symlink() {
                        return Err("agent path became a symbolic link during external edit".into());
                    }
                    if !current_metadata.is_file() {
                        return Err("agent path is no longer a regular file".into());
                    }
                    if !pending.original_metadata.matches(&current_metadata) {
                        return Err(
                            "agent file metadata changed during external edit; refusing overwrite"
                                .into(),
                        );
                    }
                    let mut current_file = std::fs::File::open(&pending.path)
                        .map_err(|error| format!("failed to re-open agent path: {error}"))?;
                    let opened_metadata = current_file
                        .metadata()
                        .map_err(|error| format!("failed to inspect opened agent path: {error}"))?;
                    if !pending.original_metadata.matches(&opened_metadata) {
                        return Err(
                            "agent file changed while commit was being validated; refusing overwrite"
                                .into(),
                        );
                    }
                    let mut current = Vec::new();
                    std::io::Read::read_to_end(&mut current_file, &mut current)
                        .map_err(|error| format!("failed to re-read agent path: {error}"))?;
                    if current != pending.original_contents {
                        return Err(
                            "agent file changed during external edit; refusing overwrite".into(),
                        );
                    }
                    std::fs::set_permissions(
                        pending.staging.as_ref() as &std::path::Path,
                        pending.original_metadata.permissions.clone(),
                    )
                    .map_err(|error| {
                        format!("failed to preserve agent-file permissions: {error}")
                    })?;
                    // Keep the pathname check adjacent to the atomic rename. The
                    // descriptor above binds content validation to the opened
                    // file; this final no-follow check catches a pathname swap
                    // during that read or while staging permissions were set.
                    let final_metadata = std::fs::symlink_metadata(&pending.path)
                        .map_err(|error| format!("failed final agent-path validation: {error}"))?;
                    if final_metadata.file_type().is_symlink()
                        || !final_metadata.is_file()
                        || !pending.original_metadata.matches(&final_metadata)
                    {
                        return Err(
                            "agent path changed before atomic replacement; refusing overwrite"
                                .into(),
                        );
                    }
                    pending
                        .staging
                        .persist(&pending.path)
                        .map(|_| ())
                        .map_err(|error| format!("atomic replacement failed: {error}"))
                })();
                match commit {
                    Ok(_) => {
                        self.refresh_after_edit(cwd, Some(&agent.0));
                        if let Some(detail) = detail {
                            self.status = Some(format!("saved `{}`; {detail}", agent.0));
                        }
                    }
                    Err(error) => {
                        self.editing = draft;
                        self.status = Some(format!(
                            "failed to atomically commit external edit: {error}"
                        ));
                    }
                }
            }
            super::pointer_actions::ExternalEditOutcome::Cancelled => {
                self.editing = pending.draft.take();
                self.status = Some(detail.unwrap_or_else(|| "external edit cancelled".into()));
            }
            super::pointer_actions::ExternalEditOutcome::Failed => {
                self.editing = pending.draft.take();
                self.status = Some(detail.unwrap_or_else(|| "external edit failed".into()));
            }
        }
    }
}

/// Build the per-row view models for `cwd`, including the effective model.
fn rows_for(cwd: &std::path::Path) -> (Vec<AgentRow>, Option<String>) {
    let mut rows: Vec<AgentRow> = list_all(cwd)
        .into_iter()
        .map(|l: AgentListing| {
            let (detail, model) = match l.def {
                Ok(def) => (Ok(def.description), normalize_model(def.model)),
                Err(e) => (Err(format!("{e}")), None),
            };
            AgentRow {
                name: l.name,
                kind: l.kind,
                detail,
                model,
                source: AgentRowSource::Agent,
            }
        })
        .collect();
    match assistant_rows() {
        Ok(assistants) => {
            rows.extend(assistants);
            (rows, None)
        }
        Err(error) => (
            rows,
            Some(format!(
                "Assistants Unavailable — {error}; Retry by reopening Agents"
            )),
        ),
    }
}

fn assistant_rows() -> Result<Vec<AgentRow>, String> {
    let response = crate::tui::agent_runner::daemon_request_blocking(
        cockpit_core::daemon::proto::Request::ListAssistants,
    )?;
    let cockpit_core::daemon::proto::Response::Assistants { assistants } = response else {
        return Err(format!("unexpected assistants response: {response:?}"));
    };
    Ok(assistants
        .into_iter()
        .map(|row| {
            let home_dir = PathBuf::from(&row.home_dir);
            let definition = cockpit_core::assistants::load_from_home(&row.name, &home_dir);
            let (detail, model) = match definition {
                Ok(def) => (Ok(def.description), normalize_model(def.agent.model)),
                Err(error) => (Err(error.to_string()), None),
            };
            AgentRow {
                name: row.name,
                kind: AgentKind::Custom,
                detail,
                model,
                source: AgentRowSource::Assistant {
                    home_dir,
                    config_json: row.config_json,
                },
            }
        })
        .collect())
}

/// Present the effective-model display value in canonical `provider/model`
/// slash form. A frontmatter `model:` is already authored in that form
/// (the live convention); we trim and drop blanks so an empty field reads
/// as "inherits the session model".
fn normalize_model(model: Option<String>) -> Option<String> {
    model
        .map(|m| m.trim().to_string())
        .filter(|m| !m.is_empty())
}

impl AgentDetail {
    fn toggle_selected_tool(&mut self) {
        if let ToolSurfaceEditOutcome::Ungranted(tool) =
            self.draft.toggle_selected_tool(&self.picker, false)
            && self.def.tool_descriptions.remove(&tool).is_some()
        {
            self.status = Some(format!("removed custom description for `{tool}`"));
        }
        if let Some(tool) = self.picker.selected_tool() {
            self.row_errors.remove(tool);
        }
    }

    fn cycle_selected_tier(&mut self) {
        self.draft.cycle_selected_tier(&self.picker);
        if let Some(tool) = self.picker.selected_tool() {
            self.row_errors.remove(tool);
        }
    }
}

fn backticked_tool(message: &str) -> Option<String> {
    let known: BTreeSet<&str> = cockpit_core::agents::known_tool_names()
        .iter()
        .copied()
        .collect();
    let mut rest = message;
    while let Some(start) = rest.find('`') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('`') else {
            break;
        };
        let candidate = &after[..end];
        if known.contains(candidate) {
            return Some(candidate.to_string());
        }
        rest = &after[end + 1..];
    }
    None
}

impl SettingsCx {
    /// The cwd agents are discovered against: the picker's cwd when the
    /// dialog was opened from one, else the directory holding the config
    /// being edited, else the process cwd. Agents resolve through the
    /// layered-config walk rooted here.
    pub(super) fn agents_cwd(&self) -> PathBuf {
        if let Some(cwd) = &self.picker_cwd {
            return cwd.clone();
        }
        // `config_path` is `<dir>/.cockpit/config.json` or similar; walk
        // up past the `.cockpit/` segment to a plausible project cwd.
        self.config_path
            .parent()
            .and_then(|p| p.parent())
            .map(PathBuf::from)
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| PathBuf::from("."))
    }

    /// The config directory eject writes into: the directory holding the
    /// `config.json` this settings dialog is editing (the `.cockpit/`
    /// layer the user selected in the picker).
    fn agents_config_dir(&self) -> PathBuf {
        self.config_path
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn handle_agents_page_key(&mut self, key: KeyEvent, p: &mut AgentsPage) -> Nav {
        // ── In-TUI editor (vim or plain) ────────────────────────────
        if p.external_edit_confirmation.is_some() {
            match key.code {
                KeyCode::Enter => self.submit_agent_external_edit(p),
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    p.external_edit_confirmation = None;
                    p.status = Some("external edit cancelled".into());
                }
                _ => {}
            }
            return Nav::Stay;
        }
        if let Some(editor) = p.editing.as_mut() {
            match editor.handle_key(key) {
                EditorOutcome::Stay => {}
                EditorOutcome::Save => {
                    let path = editor.path.clone();
                    let text = editor.text().to_string();
                    // Ensure a single trailing newline like a real editor.
                    let text = format!("{}\n", text.trim_end_matches('\n'));
                    let name = editor.name.clone();
                    p.editing = None;
                    match std::fs::write(&path, &text) {
                        Ok(()) => {
                            let cwd = self.agents_cwd();
                            p.refresh_after_edit(&cwd, Some(&name));
                        }
                        Err(e) => {
                            p.status = Some(format!("write failed: {e}"));
                        }
                    }
                }
                EditorOutcome::ExternalEdit => {
                    if std::env::var_os("EDITOR").is_none() {
                        p.status = Some("No $EDITOR environment variable".into());
                    } else {
                        p.external_edit_confirmation =
                            Some(super::pointer_actions::AgentId(editor.name.clone()));
                        p.status = Some(format!("Open agent {} in $EDITOR?", editor.name));
                    }
                }
                EditorOutcome::Cancel => {
                    p.editing = None;
                    p.status = Some("edit cancelled".into());
                }
            }
            return Nav::Stay;
        }

        if p.detail.is_some() {
            return self.handle_agent_detail_key(key, p);
        }

        // ── Reset-all confirmation ──────────────────────────────────
        if p.confirm_reset {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    p.confirm_reset = false;
                    let cwd = self.agents_cwd();
                    match cockpit_core::agents::reset_all_builtins(&cwd) {
                        Ok(removed) => {
                            p.status = Some(format!(
                                "reset {} built-in override(s) to default",
                                removed.len()
                            ));
                        }
                        Err(e) => p.status = Some(format!("reset failed: {e}")),
                    }
                    p.rows = rows_for(&cwd).0;
                    p.cursor = p.cursor.min(p.rows.len().saturating_sub(1));
                }
                KeyCode::Esc | KeyCode::Char('n') | KeyCode::Char('N') => {
                    p.confirm_reset = false;
                    p.status = Some("reset cancelled".into());
                }
                _ => {}
            }
            return Nav::Stay;
        }

        let len = p.rows.len();
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                p.disarm_guards();
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, len);
                p.status = None;
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                p.disarm_guards();
                p.cursor = crate::tui::nav::wrap_next(p.cursor, len);
                p.status = None;
            }
            KeyCode::Char('R') => {
                p.disarm_guards();
                p.confirm_reset = true;
                p.status = None;
            }
            KeyCode::Char('d') => self.delete_selected(p),
            KeyCode::Char('r') => self.reset_one_selected(p),
            KeyCode::Char('e') => {
                p.disarm_guards();
                self.edit_selected(p);
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                p.disarm_guards();
                self.open_detail_selected(p);
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Submit the confirmed raw-editor handoff exactly once. The event loop
    /// drains this request as an injected effect and returns the same id.
    fn submit_agent_external_edit(&mut self, p: &mut AgentsPage) {
        let Some(expected) = p.external_edit_confirmation.take() else {
            return;
        };
        let Some(editor) = p.editing.as_ref() else {
            return;
        };
        if editor.name != expected.0 || p.pending_external_edit.is_some() {
            return;
        }
        let path = editor.path.clone();
        let text = format!("{}\n", editor.text().trim_end_matches('\n'));
        let staging = match agent_external_edit_staging(&path) {
            Ok(staging) => staging,
            Err(error) => {
                p.status = Some(error);
                return;
            }
        };
        let draft = p.editing.take();
        let id = p.external_edit_ops.begin();
        p.pending_external_edit = Some(AgentExternalEdit {
            id,
            agent: expected,
            path,
            original_contents: staging.original_contents,
            original_metadata: staging.original_metadata,
            staging: staging.path,
            text_before_launch: text,
            draft,
            servicing: false,
        });
        p.status = Some("opening $EDITOR…".into());
    }

    fn handle_agent_detail_key(&mut self, key: KeyEvent, p: &mut AgentsPage) -> Nav {
        let Some(detail) = p.detail.as_mut() else {
            return Nav::Stay;
        };
        let len = cockpit_core::agents::tool_surface_catalog().len();
        match key.code {
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                p.status = detail.status.clone();
                p.detail = None;
            }
            KeyCode::Up | KeyCode::Char('k') if len > 0 => {
                detail.picker.move_prev();
            }
            KeyCode::Down | KeyCode::Char('j') if len > 0 => {
                detail.picker.move_next();
            }
            KeyCode::Char(' ') => {
                detail.toggle_selected_tool();
            }
            KeyCode::Char('t') => {
                detail.cycle_selected_tier();
            }
            KeyCode::Char('s')
                if key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                self.save_agent_detail(p);
            }
            KeyCode::Char('e') => {
                let path = detail.path.clone();
                let name = detail.name.clone();
                let text = detail.original_text.clone();
                p.detail = None;
                let vim = self.extended.tui.vim_mode.vim_enabled();
                p.editing = Some(AgentEditor::new(name, path, &text, vim));
            }
            _ => {}
        }
        Nav::Stay
    }

    fn open_detail_selected(&mut self, p: &mut AgentsPage) {
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        if let Err(error) = &row.detail {
            p.status = Some(format!(
                "`{}` has a parse error; use the raw editor to repair it: {error}",
                row.name
            ));
            return;
        }
        let name = row.name.clone();
        let source = row.source.clone();
        let cwd = self.agents_cwd();
        let path = match &source {
            AgentRowSource::Agent => match self.agent_edit_path(&cwd, &name) {
                Ok(path) => path,
                Err(e) => {
                    p.status = Some(format!("edit failed: {e}"));
                    return;
                }
            },
            AgentRowSource::Assistant { home_dir, .. } => {
                cockpit_core::assistants::assistant_definition_path(home_dir)
            }
        };
        let original_text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) => {
                p.status = Some(format!("edit failed: reading {}: {e}", path.display()));
                return;
            }
        };
        let def = match cockpit_core::agents::load_named_from_file(&path, &name) {
            Ok(def) => def,
            Err(e) => {
                p.status = Some(format!("structured editor unavailable for `{name}`: {e}"));
                return;
            }
        };
        p.rows = rows_for(&cwd).0;
        if let Some(idx) = p.rows.iter().position(|r| r.name == name) {
            p.cursor = idx;
        }
        let draft = ToolSurfaceDraft::from_def(&def);
        p.detail = Some(AgentDetail {
            name,
            path,
            original_text,
            def,
            draft: Box::new(draft),
            picker: ToolSurfacePicker::default(),
            status: None,
            row_errors: BTreeMap::new(),
            source,
        });
        p.status = None;
    }

    fn save_agent_detail(&mut self, p: &mut AgentsPage) {
        let Some(detail) = p.detail.as_mut() else {
            return;
        };
        detail.row_errors.clear();
        let current = match std::fs::read_to_string(&detail.path) {
            Ok(text) => text,
            Err(e) => {
                detail.status = Some(format!(
                    "save failed: reading {}: {e}",
                    detail.path.display()
                ));
                return;
            }
        };
        if current != detail.original_text {
            detail.status =
                Some("conflict: file changed on disk; raw editor can reconcile it".into());
            return;
        }
        detail.draft.write_to_def(&mut detail.def);
        if let Err(error) = cockpit_core::agents::validate_invariants(&detail.def) {
            let message = error.to_string();
            if let Some(tool) = backticked_tool(&message) {
                detail.row_errors.insert(tool, message.clone());
            }
            detail.status = Some(message);
            return;
        }
        let cleanup_notice = detail
            .status
            .clone()
            .filter(|status| status.starts_with("removed custom description"));
        let markdown = match detail.def.to_markdown() {
            Ok(markdown) => markdown,
            Err(e) => {
                detail.status = Some(format!("serialize failed: {e}"));
                return;
            }
        };
        if let Err(e) = std::fs::write(&detail.path, &markdown) {
            detail.status = Some(format!("write failed: {e}"));
            return;
        }
        if let AgentRowSource::Assistant {
            home_dir,
            config_json,
        } = &detail.source
        {
            let request = cockpit_core::daemon::proto::Request::UpsertAssistant {
                name: detail.name.clone(),
                home_dir: home_dir.to_string_lossy().into_owned(),
                config_json: config_json.clone(),
                content_hash: cockpit_core::assistants::markdown_content_hash(&markdown),
            };
            if let Err(error) = crate::tui::agent_runner::daemon_request_blocking(request) {
                detail.status = Some(format!("save Unavailable — {error}; Retry"));
                return;
            }
        }
        detail.original_text = markdown;
        detail.status = Some(match cleanup_notice {
            Some(notice) => format!("saved `{}`; {notice}", detail.name),
            None => format!("saved `{}`", detail.name),
        });
        let cwd = self.agents_cwd();
        let (rows, status) = rows_for(&cwd);
        p.rows = rows;
        if status.is_some() {
            p.status = status;
        }
    }

    /// Begin editing the highlighted agent. A non-overridden built-in is
    /// auto-ejected first so there's always a concrete on-disk file. The
    /// editor is then chosen by precedence: `$EDITOR` (external — deferred
    /// to the event loop) → in-TUI vim (vim mode on) → in-TUI plain.
    fn edit_selected(&mut self, p: &mut AgentsPage) {
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        let name = row.name.clone();
        let cwd = self.agents_cwd();

        // Resolve (auto-ejecting a pristine built-in) the file to edit.
        let path = match self.agent_edit_path(&cwd, &name) {
            Ok(path) => path,
            Err(e) => {
                p.status = Some(format!("edit failed: {e}"));
                return;
            }
        };

        // 1. `$EDITOR` -> external process, serviced by the event loop.
        if std::env::var_os("EDITOR").is_some() {
            // Refresh the rows now so the auto-ejected built-in is already
            // marked overridden under the cursor; the loop will re-read the
            // file after the external editor returns.
            p.rows = rows_for(&cwd).0;
            let text = match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(error) => {
                    p.status = Some(format!("edit failed: reading {}: {error}", path.display()));
                    return;
                }
            };
            let staging = match agent_external_edit_staging(&path) {
                Ok(staging) => staging,
                Err(error) => {
                    p.status = Some(error);
                    return;
                }
            };
            let id = p.external_edit_ops.begin();
            p.pending_external_edit = Some(AgentExternalEdit {
                id,
                agent: super::pointer_actions::AgentId(name.clone()),
                path,
                original_contents: staging.original_contents,
                original_metadata: staging.original_metadata,
                staging: staging.path,
                text_before_launch: text,
                draft: None,
                servicing: false,
            });
            p.status = Some("opening $EDITOR…".into());
            return;
        }

        // 2/3. In-TUI editor: vim when enabled, else plain. No dead end.
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                p.status = Some(format!("edit failed: reading {}: {e}", path.display()));
                return;
            }
        };
        // Refresh rows so an auto-ejected built-in is marked overridden
        // while the in-TUI editor is open.
        p.rows = rows_for(&cwd).0;
        let vim = self.extended.tui.vim_mode.vim_enabled();
        p.editing = Some(AgentEditor::new(name, path, &text, vim));
        p.status = None;
    }

    /// Pointer raw-edit always enters the in-TUI raw editor first so the
    /// separately named `$EDITOR` control can enforce its confirmation.
    fn edit_selected_in_tui(&mut self, p: &mut AgentsPage) {
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        let name = row.name.clone();
        let cwd = self.agents_cwd();
        let path = match self.agent_edit_path(&cwd, &name) {
            Ok(path) => path,
            Err(error) => {
                p.status = Some(format!("edit failed: {error}"));
                return;
            }
        };
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(error) => {
                p.status = Some(format!("edit failed: reading {}: {error}", path.display()));
                return;
            }
        };
        p.rows = rows_for(&cwd).0;
        p.editing = Some(AgentEditor::new(
            name,
            path,
            &text,
            self.extended.tui.vim_mode.vim_enabled(),
        ));
        p.status = None;
    }

    /// Resolve the on-disk file to edit for `name` in the current cwd's
    /// agents layer, auto-ejecting a non-overridden built-in first. Custom
    /// agents (and already-overridden built-ins) already live on disk; we
    /// return their existing path so we never touch another layer.
    fn agent_edit_path(&self, cwd: &std::path::Path, name: &str) -> anyhow::Result<PathBuf> {
        if is_builtin_agent(name) {
            // eject is a no-clobber no-op when an override already exists,
            // returning the existing path; otherwise it writes the embedded
            // default to this layer's `.cockpit/agents/<name>.md`.
            let config_dir = self.agents_config_dir();
            let (path, _newly) = cockpit_core::agents::eject_builtin(cwd, &config_dir, name)?;
            Ok(path)
        } else {
            // Custom agent — edit its existing file in whatever layer it
            // resolves from.
            cockpit_core::agents::find_override(cwd, name)
                .ok_or_else(|| anyhow::anyhow!("custom agent `{name}` has no on-disk file"))
        }
    }

    /// Delete the highlighted **custom** agent (arm→confirm). Built-ins are
    /// never deletable — for an overridden one the destructive action is
    /// per-agent reset (`r`), and a pristine built-in offers neither.
    fn delete_selected(&mut self, p: &mut AgentsPage) {
        p.reset_one.disarm();
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        if !matches!(row.kind, AgentKind::Custom) {
            p.status = Some("built-in agents cannot be deleted (use r/R to reset)".into());
            return;
        }
        let name = row.name.clone();
        if p.delete.activate() == ResetOutcome::Armed {
            p.status = Some(format!("delete `{name}`? press d again to confirm"));
            return;
        }
        let cwd = self.agents_cwd();
        match cockpit_core::agents::find_override(&cwd, &name) {
            Some(path) => match std::fs::remove_file(&path) {
                Ok(()) => p.status = Some(format!("deleted custom agent `{name}`")),
                Err(e) => p.status = Some(format!("delete failed: {e}")),
            },
            None => p.status = Some(format!("delete failed: `{name}` has no on-disk file")),
        }
        p.rows = rows_for(&cwd).0;
        p.cursor = p.cursor.min(p.rows.len().saturating_sub(1));
    }

    /// Reset the highlighted **overridden built-in** to its embedded
    /// default (arm→confirm), deleting just that one override file. A
    /// custom agent or pristine built-in offers nothing here.
    fn reset_one_selected(&mut self, p: &mut AgentsPage) {
        p.delete.disarm();
        let Some(row) = p.rows.get(p.cursor) else {
            return;
        };
        let AgentKind::Builtin { overridden: true } = row.kind else {
            p.status = Some("only an overridden built-in can be reset".into());
            return;
        };
        let name = row.name.clone();
        if p.reset_one.activate() == ResetOutcome::Armed {
            p.status = Some(format!(
                "reset `{name}` to default? press r again to confirm"
            ));
            return;
        }
        let cwd = self.agents_cwd();
        match cockpit_core::agents::find_override(&cwd, &name) {
            Some(path) => match std::fs::remove_file(&path) {
                Ok(()) => p.status = Some(format!("reset `{name}` to default")),
                Err(e) => p.status = Some(format!("reset failed: {e}")),
            },
            None => p.status = Some(format!("reset: `{name}` has no override")),
        }
        p.rows = rows_for(&cwd).0;
        p.cursor = p.cursor.min(p.rows.len().saturating_sub(1));
    }

    pub(super) fn render_agents_page(&self, frame: &mut Frame, area: Rect, p: &AgentsPage) {
        p.editor_body.set(None);
        // The in-TUI editor takes the whole page area when open.
        if let Some(editor) = &p.editing {
            editor.render(frame, area);
            let action_y = area.bottom().saturating_sub(1);
            let agent = super::pointer_actions::AgentId(editor.name.clone());
            let confirming = p.external_edit_confirmation.as_ref() == Some(&agent);
            if !confirming && area.width > 4 && area.height > 3 {
                let editor_body = Rect::new(
                    area.x.saturating_add(2),
                    area.y.saturating_add(1),
                    area.width.saturating_sub(4),
                    area.height.saturating_sub(3),
                );
                p.editor_body.set(Some(editor_body));
                self.pointer_surface
                    .register(super::shell::SettingsPointerTarget {
                        rect: editor_body,
                        action: super::shell::SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Agents(
                                super::pointer_actions::AgentsAction::EditText(agent.clone()),
                            ),
                        ),
                        enabled: true,
                        disabled_reason: None,
                    });
            }
            let actions = if confirming {
                vec![
                    (
                        super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
                        0,
                        17,
                    ),
                    (
                        super::pointer_actions::AgentsAction::Cancel(agent.clone()),
                        19,
                        8,
                    ),
                ]
            } else {
                vec![
                    (
                        super::pointer_actions::AgentsAction::Save(agent.clone()),
                        0,
                        6u16,
                    ),
                    (
                        super::pointer_actions::AgentsAction::Cancel(agent.clone()),
                        8u16,
                        8u16,
                    ),
                    (
                        super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
                        18u16,
                        17u16,
                    ),
                ]
            };
            for (action, x, width) in actions {
                if x.saturating_add(width) > area.width {
                    continue;
                }
                self.pointer_surface
                    .register(super::shell::SettingsPointerTarget {
                        rect: Rect::new(area.x + x, action_y, width, 1),
                        action: super::shell::SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Agents(action),
                        ),
                        enabled: true,
                        disabled_reason: None,
                    });
            }
            frame.render_widget(
                if confirming {
                    Line::from("[Open in $EDITOR]  [Cancel]")
                } else {
                    Line::from("[Save]  [Cancel]  [Open in $EDITOR]")
                },
                Rect::new(area.x, action_y, area.width, 1),
            );
            return;
        }
        if let Some(detail) = &p.detail {
            self.render_agent_detail(frame, area, detail);
            let action_y = area.bottom().saturating_sub(1);
            let agent = super::pointer_actions::AgentId(detail.name.clone());
            for (action, x, width) in [
                (
                    super::pointer_actions::AgentsAction::OpenRawEditor(agent.clone()),
                    0,
                    15,
                ),
                (
                    super::pointer_actions::AgentsAction::Save(agent.clone()),
                    17,
                    6,
                ),
            ] {
                self.pointer_surface
                    .register(super::shell::SettingsPointerTarget {
                        rect: Rect::new(
                            area.x + x,
                            action_y,
                            width.min(area.width.saturating_sub(x)),
                            1,
                        ),
                        action: super::shell::SettingsPointerAction::Page(
                            super::pointer_actions::SettingsPointerAction::Agents(action),
                        ),
                        enabled: x < area.width,
                        disabled_reason: (x >= area.width).then_some("control is clipped"),
                    });
            }
            frame.render_widget(
                Line::from("[Edit raw file]  [Save]"),
                Rect::new(area.x, action_y, area.width, 1),
            );
            return;
        }

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let red = Style::default().fg(Color::Red);
        let cyan = Style::default().fg(Color::Cyan);

        let mut lines: Vec<Line<'static>> = vec![
            Line::from(Span::styled(
                "Agents".to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::default(),
        ];
        let mut controls = vec![None; lines.len()];
        push_wrapped_text(
            &mut lines,
            area.width,
            "Enter opens a structured tool editor; e opens the raw \
             .cockpit/agents/<name>.md file ($EDITOR, else in-TUI). Editing a built-in ejects its default first. The model is \
             the `model:` frontmatter field (provider/model). Delete removes a \
             custom agent; reset reverts an overridden built-in.",
            muted,
        );
        controls.resize(lines.len(), None);
        lines.push(Line::default());
        controls.push(None);

        for (i, row) in p.rows.iter().enumerate() {
            let on_cursor = i == p.cursor;
            let marker = if on_cursor { "▸ " } else { "  " };
            let name_style = if on_cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let tag = match row.kind {
                AgentKind::Builtin { overridden: true } => " (built-in, overridden)",
                AgentKind::Builtin { overridden: false } => " (built-in)",
                AgentKind::Custom if matches!(row.source, AgentRowSource::Assistant { .. }) => {
                    " (assistant)"
                }
                AgentKind::Custom => " (custom)",
            };
            let model_label = match &row.model {
                Some(m) => m.clone(),
                None => "session default".to_string(),
            };
            let mut spans = vec![
                Span::raw(marker),
                Span::styled(row.name.clone(), name_style),
                Span::styled(tag.to_string(), muted),
                Span::raw("  "),
                Span::styled(format!("model: {model_label}"), cyan),
            ];
            if let Err(e) = &row.detail {
                spans.push(Span::styled(format!("  ⚠ {e}"), red));
            }
            lines.push(Line::from(spans));
            let open = super::pointer_actions::SettingsPointerAction::Agents(
                super::pointer_actions::AgentsAction::Open(super::pointer_actions::AgentId(
                    row.name.clone(),
                )),
            );
            controls.push(Some((open.clone(), true, None)));
            if let Ok(desc) = &row.detail {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(desc.clone(), muted),
                ]));
                controls.push(Some((open, true, None)));
            }
        }

        if p.confirm_reset {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(Span::styled(
                "Reset ALL built-in agents to default? This deletes their \
                 on-disk overrides (custom agents are kept).  y: confirm  n: cancel"
                    .to_string(),
                red.add_modifier(Modifier::BOLD),
            )));
            controls.push(None);
            lines.push(Line::from("[Reset]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::ResetAll,
                ),
                true,
                None,
            )));
            lines.push(Line::from("[Cancel]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::Cancel(super::pointer_actions::AgentId(
                        "reset-all".into(),
                    )),
                ),
                true,
                None,
            )));
        } else if p.delete.is_pending() || p.reset_one.is_pending() {
            let verb = if p.delete.is_pending() {
                "Delete"
            } else {
                "Reset"
            };
            let name = p
                .rows
                .get(p.cursor)
                .map_or("agent", |row| row.name.as_str());
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(format!("{verb} {name}?")));
            controls.push(None);
            lines.push(Line::from(format!("[{verb}]")));
            let id = super::pointer_actions::AgentId(name.to_string());
            let action = if p.delete.is_pending() {
                super::pointer_actions::AgentsAction::Delete(id)
            } else {
                super::pointer_actions::AgentsAction::Reset(id)
            };
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(action),
                true,
                None,
            )));
            lines.push(Line::from("[Cancel]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::Cancel(super::pointer_actions::AgentId(
                        name.to_string(),
                    )),
                ),
                true,
                None,
            )));
        } else {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from("[Open]"));
            let id = super::pointer_actions::AgentId(
                p.rows
                    .get(p.cursor)
                    .map_or("", |r| r.name.as_str())
                    .to_string(),
            );
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::Open(id.clone()),
                ),
                true,
                None,
            )));
            lines.push(Line::from("[Edit raw file]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::Edit(id.clone()),
                ),
                true,
                None,
            )));
            if let Some(kind) = p.rows.get(p.cursor).map(|row| &row.kind) {
                let (label, action) = match kind {
                    AgentKind::Custom => (
                        "[Delete]",
                        Some(super::pointer_actions::AgentsAction::Delete(id.clone())),
                    ),
                    AgentKind::Builtin { overridden: true } => (
                        "[Reset]",
                        Some(super::pointer_actions::AgentsAction::Reset(id.clone())),
                    ),
                    AgentKind::Builtin { overridden: false } => ("", None),
                };
                if let Some(action) = action {
                    lines.push(Line::from(label));
                    controls.push(Some((
                        super::pointer_actions::SettingsPointerAction::Agents(action),
                        true,
                        None,
                    )));
                }
            }
            lines.push(Line::from("[Reset all]"));
            controls.push(Some((
                super::pointer_actions::SettingsPointerAction::Agents(
                    super::pointer_actions::AgentsAction::ResetAll,
                ),
                true,
                None,
            )));
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
            controls.push(None);
        }

        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_control_lines(
            frame,
            area,
            "agents",
            lines,
            selected_line,
            controls,
            &self.pointer_surface,
            SettingsScrollRegionId("agents:list"),
        );
    }

    fn render_agent_detail(&self, frame: &mut Frame, area: Rect, detail: &AgentDetail) {
        let (lines, selected_line, semantic_rows) = tool_surface_lines(
            &detail.picker,
            &detail.draft,
            ToolSurfaceRender {
                title: &detail.name,
                subtitle: "tool surface",
                status: detail.status.as_deref(),
                row_errors: &detail.row_errors,
                block_safety_ungrant: false,
            },
        );
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "agent-detail",
            lines,
            selected_line,
            semantic_rows
                .into_iter()
                .filter(|(_, _, enabled)| *enabled)
                .map(|(line, index, _)| {
                    (
                        line,
                        super::pointer_actions::SettingsPointerAction::Agents(
                            super::pointer_actions::AgentsAction::ToggleTool(
                                super::pointer_actions::AgentId(detail.name.clone()),
                                super::pointer_actions::AgentToolId(
                                    cockpit_core::agents::tool_surface_catalog()[index]
                                        .name
                                        .into(),
                                ),
                            ),
                        ),
                    )
                }),
            &self.pointer_surface,
            SettingsScrollRegionId("agents:detail"),
        );
    }
}

/// Internal helper on the page: re-discover agents and (when a name is
/// given) move the cursor onto that row + re-surface a parse error inline.
impl AgentsPage {
    fn refresh_after_edit(&mut self, cwd: &std::path::Path, name: Option<&str>) {
        self.rows = rows_for(cwd).0;
        if let Some(name) = name {
            if let Some(idx) = self.rows.iter().position(|r| r.name == name) {
                self.cursor = idx;
            }
            // Surface a parse error from the just-edited file rather than
            // silently accepting a broken agent.
            if let Some(row) = self.rows.get(self.cursor) {
                self.status = Some(match &row.detail {
                    Err(e) => format!("parse error in `{name}`: {e}"),
                    Ok(_) => format!("saved `{name}`"),
                });
            }
        }
        self.cursor = self.cursor.min(self.rows.len().saturating_sub(1));
    }
}

impl SettingsPage for AgentsPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Agents
    }

    fn pointer_surface_token(&self) -> u64 {
        if self.editing.is_some() {
            402
        } else if self.detail.is_some() {
            401
        } else {
            400
        }
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        if self.editing.is_some() || self.detail.is_some() {
            super::SettingsLocalBack::LocalBack
        } else {
            super::SettingsLocalBack::NoLocalBack
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_agents_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_agents_page(frame, area, self);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Agents(action) = action else {
            return Nav::Stay;
        };
        if self.editing.is_some() {
            if let Some(confirming) = self.external_edit_confirmation.as_ref()
                && !matches!(
                    &action,
                    super::pointer_actions::AgentsAction::ExternalEditBegin(agent)
                        if agent == confirming
                )
                && !matches!(&action, super::pointer_actions::AgentsAction::Cancel(agent) if agent == confirming)
            {
                self.external_edit_confirmation = None;
                self.status = Some("external edit cancelled".into());
                return Nav::Stay;
            }
            return match action {
                super::pointer_actions::AgentsAction::EditText(_) => Nav::Stay,
                super::pointer_actions::AgentsAction::Save(_) => cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                    self,
                ),
                super::pointer_actions::AgentsAction::Cancel(_) => {
                    cx.handle_agents_page_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), self)
                }
                super::pointer_actions::AgentsAction::ExternalEditBegin(ref agent)
                    if self
                        .editing
                        .as_ref()
                        .is_some_and(|editor| editor.name == agent.0) =>
                {
                    if self.external_edit_confirmation.as_ref() == Some(agent) {
                        cx.handle_agents_page_key(
                            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                            self,
                        )
                    } else if std::env::var_os("EDITOR").is_none() {
                        self.status = Some("No $EDITOR environment variable".into());
                        Nav::Stay
                    } else {
                        self.external_edit_confirmation = Some(agent.clone());
                        self.status = Some(format!("Open agent {} in $EDITOR?", agent.0));
                        Nav::Stay
                    }
                }
                _ => Nav::Stay,
            };
        }
        if self.detail.is_some()
            && matches!(
                &action,
                super::pointer_actions::AgentsAction::OpenRawEditor(_)
            )
        {
            return cx.handle_agents_page_key(
                KeyEvent::new(KeyCode::Char('e'), KeyModifiers::NONE),
                self,
            );
        }
        if self.detail.is_some() && matches!(&action, super::pointer_actions::AgentsAction::Save(_))
        {
            return cx.handle_agents_page_key(
                KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL),
                self,
            );
        }
        if let Some(detail) = self.detail.as_mut() {
            let (super::pointer_actions::AgentsAction::ToggleTool(_, row)
            | super::pointer_actions::AgentsAction::CycleTier(_, row)) = action
            else {
                return Nav::Stay;
            };
            let Some(index) = cockpit_core::agents::tool_surface_catalog()
                .iter()
                .position(|tool| tool.name == row.0)
            else {
                return Nav::Stay;
            };
            if index >= cockpit_core::agents::tool_surface_catalog().len() {
                return Nav::Stay;
            }
            detail.picker.set_cursor(index);
            return cx
                .handle_agents_page_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), self);
        }
        let row_identity = match &action {
            super::pointer_actions::AgentsAction::Open(id)
            | super::pointer_actions::AgentsAction::Edit(id)
            | super::pointer_actions::AgentsAction::Delete(id)
            | super::pointer_actions::AgentsAction::Reset(id) => Some(id),
            _ => None,
        };
        if let Some(id) = row_identity {
            let Some(index) = self.rows.iter().position(|row| row.name == id.0) else {
                return Nav::Stay;
            };
            // A pending destructive action is valid only for the row that
            // still owns it; a different stable target starts fresh.
            if index != self.cursor {
                self.disarm_guards();
            }
            self.cursor = index;
        }
        match &action {
            super::pointer_actions::AgentsAction::ResetAll if self.confirm_reset => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Cancel(_) if self.confirm_reset => {
                self.confirm_reset = false;
                self.status = Some("reset cancelled".into());
                return Nav::Stay;
            }
            super::pointer_actions::AgentsAction::Delete(_) if self.delete.is_pending() => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Reset(_) if self.reset_one.is_pending() => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Open(_) => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Cancel(_) => {
                self.disarm_guards();
                self.status = Some("action cancelled".into());
                return Nav::Stay;
            }
            super::pointer_actions::AgentsAction::Edit(_) => {
                cx.edit_selected_in_tui(self);
                return Nav::Stay;
            }
            super::pointer_actions::AgentsAction::Delete(_) => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::Reset(_) => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
                    self,
                );
            }
            super::pointer_actions::AgentsAction::ResetAll => {
                return cx.handle_agents_page_key(
                    KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE),
                    self,
                );
            }
            _ => {}
        }
        Nav::Stay
    }

    fn handle_pointer_scroll(
        &mut self,
        _cx: &mut SettingsCx,
        region: SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region == SettingsScrollRegionId("agents:list")
            && self.detail.is_none()
            && self.editing.is_none()
        {
            self.disarm_guards();
            self.cursor = self
                .cursor
                .saturating_add_signed(delta)
                .min(self.rows.len().saturating_sub(1));
        } else if region == SettingsScrollRegionId("agents:detail")
            && let Some(detail) = self.detail.as_mut()
        {
            let last = cockpit_core::agents::tool_surface_catalog()
                .len()
                .saturating_sub(1);
            let cursor = detail
                .picker
                .cursor()
                .saturating_add_signed(delta)
                .min(last);
            detail.picker.set_cursor(cursor);
        }
        Nav::Stay
    }

    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
        column: u16,
        row: u16,
    ) -> Nav {
        if matches!(
            &action,
            super::pointer_actions::SettingsPointerAction::Agents(
                super::pointer_actions::AgentsAction::EditText(_)
            )
        ) {
            if self.external_edit_confirmation.take().is_some() {
                self.status = Some("external edit cancelled".into());
                return Nav::Stay;
            }
        }
        if matches!(
            &action,
            super::pointer_actions::SettingsPointerAction::Agents(
                super::pointer_actions::AgentsAction::EditText(_)
            )
        ) && let Some(editor) = self.editing.as_mut()
            && let Some(body) = self.editor_body.get()
        {
            editor.set_cursor_from_visible_cell(
                usize::from(row.saturating_sub(body.y)),
                usize::from(column.saturating_sub(body.x)),
            );
            return Nav::Stay;
        }
        self.handle_pointer_control(cx, action)
    }

    fn cancel_pointer_transients(&mut self) {
        self.confirm_reset = false;
        self.disarm_guards();
        self.external_edit_confirmation = None;
        self.external_edit_ops.cancel();
        self.pending_external_edit = None;
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › Agents",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        self.help_text()
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Agents"
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use std::fs;
    use tempfile::TempDir;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    struct TrustedAgentsDialog {
        dialog: SettingsDialog,
        trust: cockpit_config::trust::ThreadWorkspaceTrustGuard,
    }

    impl std::ops::Deref for TrustedAgentsDialog {
        type Target = SettingsDialog;

        fn deref(&self) -> &Self::Target {
            &self.dialog
        }
    }

    impl std::ops::DerefMut for TrustedAgentsDialog {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.dialog
        }
    }

    impl TrustedAgentsDialog {
        fn into_parts(
            self,
        ) -> (
            SettingsDialog,
            cockpit_config::trust::ThreadWorkspaceTrustGuard,
        ) {
            (self.dialog, self.trust)
        }
    }

    /// A settings dialog whose `config.json` lives in `<tmp>/.cockpit/`
    /// and whose picker cwd is `<tmp>`, on the Agents page. The trust guard
    /// remains live for the whole test so refreshes exercise the same trusted
    /// project policy as the production TUI.
    fn agents_dialog(tmp: &TempDir) -> TrustedAgentsDialog {
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir_all(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        let trust = cockpit_config::trust::enter_workspace_trust_policy(
            crate::tui::app::trusted_workspace_policy_for_tests(tmp.path()),
        );
        let mut d = SettingsDialog::open_from_picker(config_path, tmp.path().to_path_buf());
        d.set_test_page(Page::Agents(AgentsPage::new(tmp.path())));
        TrustedAgentsDialog { dialog: d, trust }
    }

    fn page(d: &SettingsDialog) -> &AgentsPage {
        match d.test_page() {
            TestPageRef::Agents(p) => p,
            _ => panic!("expected Agents page"),
        }
    }

    fn page_mut(d: &mut SettingsDialog) -> &mut AgentsPage {
        match d.test_page_mut() {
            TestPageMut::Agents(p) => p,
            _ => panic!("expected Agents page"),
        }
    }

    /// Move the cursor onto the row whose agent name is `name`.
    fn focus(d: &mut SettingsDialog, name: &str) {
        let idx = page(d).rows.iter().position(|r| r.name == name).unwrap();
        page_mut(d).cursor = idx;
    }

    struct EditorEnv {
        _guard: cockpit_test_support::TestEnvGuard,
    }
    impl EditorEnv {
        /// Take the lock and set `$EDITOR` to `value` (or unset it for `None`).
        fn with(value: Option<&str>) -> Self {
            let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
            match value {
                Some(v) => guard.set_var("EDITOR", v),
                None => guard.remove_var("EDITOR"),
            }
            EditorEnv { _guard: guard }
        }
        fn unset() -> Self {
            Self::with(None)
        }
    }

    struct XdgDataEnv {
        _guard: cockpit_test_support::TestEnvGuard,
    }

    impl XdgDataEnv {
        fn new(path: &std::path::Path) -> Self {
            let guard = cockpit_test_support::TestEnvGuard::blocking_lock();
            guard.set_var("XDG_DATA_HOME", path);
            Self { _guard: guard }
        }

        async fn new_async(path: &std::path::Path) -> Self {
            let guard = cockpit_test_support::TestEnvGuard::lock().await;
            guard.set_var("XDG_DATA_HOME", path);
            Self { _guard: guard }
        }
    }

    fn focus_tool(d: &mut SettingsDialog, name: &str) {
        let idx = cockpit_core::agents::tool_surface_catalog()
            .iter()
            .position(|tool| tool.name == name)
            .unwrap();
        page_mut(d).detail.as_mut().unwrap().picker.set_cursor(idx);
    }

    fn load_agent(path: &std::path::Path, name: &str) -> AgentDef {
        cockpit_core::agents::load_named_from_file(path, name).unwrap()
    }

    #[test]
    fn lists_builtins() {
        let tmp = TempDir::new().unwrap();
        let d = agents_dialog(&tmp);
        let names: Vec<&str> = page(&d).rows.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"Build"));
        assert!(names.contains(&"builder"));
        assert!(names.contains(&"explore"));
        // The docs pipeline is never listed.
        assert!(!names.iter().any(|n| n.starts_with("docs")));
    }

    #[test]
    fn rows_show_effective_model() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("with-model.md"),
            "---\ndescription: m\nmodel: anthropic/claude-opus-4-7\n---\nbody\n",
        )
        .unwrap();
        fs::write(
            agents_dir.join("no-model.md"),
            "---\ndescription: n\n---\nbody\n",
        )
        .unwrap();
        let d = agents_dialog(&tmp);
        let with = page(&d)
            .rows
            .iter()
            .find(|r| r.name == "with-model")
            .unwrap();
        assert_eq!(with.model.as_deref(), Some("anthropic/claude-opus-4-7"));
        let without = page(&d).rows.iter().find(|r| r.name == "no-model").unwrap();
        assert_eq!(
            without.model, None,
            "no frontmatter model → session default"
        );
    }

    #[test]
    fn agents_page_enter_opens_tool_surface_detail_with_tier_state() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            "---\ndescription: mine\ntools: [read, search, mcp]\ntoolTiers:\n  search: discoverable\n---\nbody\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        let detail = page(&d).detail.as_ref().expect("detail opens");
        assert!(detail.draft.granted("read"));
        assert!(detail.draft.granted("search"));
        assert_eq!(detail.draft.tier("search"), ToolTier::Discoverable);
    }

    #[test]
    fn agents_page_grant_and_tier_persist_to_markdown() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        fs::write(&path, "---\ndescription: mine\ntools: [read]\n---\nbody\n").unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        focus_tool(&mut d, "search");
        d.handle_key(press(KeyCode::Char(' ')));
        d.handle_key(press(KeyCode::Char('t')));
        focus_tool(&mut d, "mcp");
        d.handle_key(press(KeyCode::Char(' ')));
        d.handle_key(ctrl_s());
        let def = load_agent(&path, "mine");
        assert!(def.tools.unwrap().iter().any(|tool| tool == "search"));
        assert_eq!(def.tool_tiers.get("search"), Some(&ToolTier::Discoverable));
        let on_disk = fs::read_to_string(&path).unwrap();
        assert!(on_disk.contains("tools:"));
        assert!(on_disk.contains("toolTiers:"));
        assert!(on_disk.find("tools:").unwrap() < on_disk.find("toolTiers:").unwrap());
    }

    #[test]
    fn agents_page_structural_and_write_tools_skip_discoverable() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            "---\ndescription: mine\ntools: [read, question, write]\n---\nbody\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        for tool in ["question", "write"] {
            focus_tool(&mut d, tool);
            let mut observed = Vec::new();
            for _ in 0..4 {
                d.handle_key(press(KeyCode::Char('t')));
                observed.push(page(&d).detail.as_ref().unwrap().draft.tier(tool));
            }
            assert!(!observed.contains(&ToolTier::Discoverable), "{tool}");
            assert!(observed.contains(&ToolTier::Enabled), "{tool}");
            assert!(!observed.contains(&ToolTier::Disabled), "{tool}");
        }
    }

    #[test]
    fn agents_page_validation_error_blocks_persist() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        let original = "---\ndescription: mine\nmode: subagent\ntools: [read]\n---\nbody\n";
        fs::write(&path, original).unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        focus_tool(&mut d, "start_build");
        d.handle_key(press(KeyCode::Char(' ')));
        d.handle_key(ctrl_s());
        let detail = page(&d).detail.as_ref().unwrap();
        assert!(
            detail
                .status
                .as_deref()
                .unwrap_or("")
                .contains("start_build"),
            "{:?}",
            detail.status
        );
        assert!(detail.row_errors.contains_key("start_build"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn agents_page_conflict_blocks_structured_overwrite() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        fs::write(&path, "---\ndescription: mine\ntools: [read]\n---\nbody\n").unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        focus_tool(&mut d, "search");
        d.handle_key(press(KeyCode::Char(' ')));
        let changed = "---\ndescription: changed\ntools: [read]\n---\nbody\n";
        fs::write(&path, changed).unwrap();
        d.handle_key(ctrl_s());
        assert!(
            page(&d)
                .detail
                .as_ref()
                .unwrap()
                .status
                .as_deref()
                .unwrap_or("")
                .contains("conflict")
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), changed);
    }

    #[test]
    fn agents_page_ungrant_drops_tool_description_override_with_notice() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        let path = agents_dir.join("mine.md");
        fs::write(
            &path,
            "---\ndescription: mine\ntools: [read, search, mcp]\ntoolTiers:\n  search: discoverable\ntool_descriptions:\n  search:\n    normal: custom search\n---\nbody\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
        focus_tool(&mut d, "search");
        d.handle_key(press(KeyCode::Char(' ')));
        d.handle_key(ctrl_s());
        let def = load_agent(&path, "mine");
        assert!(!def.tools.unwrap().iter().any(|tool| tool == "search"));
        assert!(!def.tool_tiers.contains_key("search"));
        assert!(!def.tool_descriptions.contains_key("search"));
        assert!(
            page(&d)
                .detail
                .as_ref()
                .unwrap()
                .status
                .as_deref()
                .unwrap_or("")
                .contains("removed custom description for `search`")
        );
    }

    #[test]
    fn agents_page_parse_error_cannot_open_structured_detail() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(agents_dir.join("broken.md"), "no frontmatter\n").unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "broken");
        assert!(page(&d).rows[page(&d).cursor].detail.is_err());
        d.handle_key(press(KeyCode::Enter));
        assert!(page(&d).detail.is_none());
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("raw editor")
        );
    }

    #[test]
    fn agents_page_assistant_wizard_tools_step_is_structured() {
        let descriptor = cockpit_core::assistants::descriptor();
        let step = descriptor
            .steps
            .iter()
            .find(|step| step.id == "tools")
            .unwrap();
        assert!(matches!(
            step.kind,
            cockpit_core::wizard::StepKind::ToolSurface
        ));
        assert!(
            cockpit_core::agents::tool_surface_catalog()
                .iter()
                .any(|tool| tool.name == "read")
        );
    }

    #[test]
    fn agents_page_assistant_wizard_rejects_invalid_grant_before_save() {
        let mut run =
            cockpit_core::wizard::WizardRun::new(cockpit_core::assistants::descriptor()).unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(
            "Assistant".to_string(),
        ))
        .unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Select(
            "primary".to_string(),
        ))
        .unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(String::new()))
            .unwrap();
        let result = run.submit(cockpit_core::wizard::WizardAnswer::ToolSurface(
            cockpit_core::agents::ToolSurfaceSelection {
                tools: vec!["grep".to_string()],
                tool_tiers: BTreeMap::new(),
            },
        ));
        assert!(result.is_err());
        assert!(run.error().unwrap_or("").contains("grep"));
    }

    #[test]
    fn agents_page_assistant_wizard_tiers_persist_in_spec() {
        let mut run =
            cockpit_core::wizard::WizardRun::new(cockpit_core::assistants::descriptor()).unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(
            "Assistant".to_string(),
        ))
        .unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Select(
            "primary".to_string(),
        ))
        .unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(String::new()))
            .unwrap();
        let mut tiers = BTreeMap::new();
        tiers.insert("search".to_string(), ToolTier::Discoverable);
        run.submit(cockpit_core::wizard::WizardAnswer::ToolSurface(
            cockpit_core::agents::ToolSurfaceSelection {
                tools: vec!["read".to_string(), "search".to_string(), "mcp".to_string()],
                tool_tiers: tiers.clone(),
            },
        ))
        .unwrap();
        run.submit(cockpit_core::wizard::WizardAnswer::Text(
            "Help.".to_string(),
        ))
        .unwrap();
        let spec = cockpit_core::assistants::spec_from_wizard(
            "helper-bot",
            std::path::PathBuf::from("/tmp/helper-bot"),
            &run,
        )
        .unwrap();
        assert_eq!(spec.tool_tiers, tiers);
    }

    #[test]
    fn edit_without_editor_opens_in_tui_and_auto_ejects_builtin() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "builder");
        // `e` starts the in-TUI raw editor; the built-in is ejected first.
        d.handle_key(press(KeyCode::Char('e')));
        assert!(page(&d).editing.is_some(), "in-TUI editor should be open");
        let ejected = tmp.path().join(".cockpit/agents/builder.md");
        assert!(ejected.exists(), "editing a pristine built-in ejects it");
        let builder = page(&d).rows.iter().find(|r| r.name == "builder").unwrap();
        assert!(matches!(
            builder.kind,
            AgentKind::Builtin { overridden: true }
        ));
    }

    #[test]
    fn in_tui_edit_save_writes_to_disk_and_reparses() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            "---\ndescription: orig\n---\nbody\n",
        )
        .unwrap();
        // Vim mode off → the in-TUI editor types chars directly.
        let mut d = agents_dialog(&tmp);
        d.extended.tui.vim_mode = cockpit_config::extended::VimModeSetting::Disabled;
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Char('e')));
        assert!(page(&d).editing.is_some());
        // Move to the end of the buffer (past the frontmatter + body) and
        // append a marker to the body, keeping the frontmatter valid, then
        // save.
        for _ in 0..16 {
            d.handle_key(press(KeyCode::Down));
        }
        d.handle_key(press(KeyCode::End));
        d.handle_key(press(KeyCode::Char('Z')));
        d.handle_key(ctrl_s());
        assert!(page(&d).editing.is_none(), "save closes the editor");
        assert!(
            page(&d).status.as_deref().unwrap_or("").contains("saved"),
            "valid save reports saved, got {:?}",
            page(&d).status
        );
        let on_disk = fs::read_to_string(agents_dir.join("mine.md")).unwrap();
        assert!(
            on_disk.contains('Z') && on_disk.contains("description: orig"),
            "the edit was written to disk and frontmatter survived: {on_disk:?}"
        );
    }

    #[test]
    fn in_tui_edit_save_invalid_surfaces_parse_error() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("mine.md"),
            "---\ndescription: orig\n---\nbody\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        d.extended.tui.vim_mode = cockpit_config::extended::VimModeSetting::Disabled;
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Char('e')));
        // Type a body-only document (no frontmatter) so the saved file fails
        // `parse_agent`. We replace by typing after deleting the original via
        // repeated forward-delete, then save: the SAVE path re-reads from disk
        // and surfaces the parse result rather than silently accepting it.
        for _ in 0..64 {
            d.handle_key(press(KeyCode::Delete));
        }
        for ch in "no frontmatter".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(ctrl_s());
        assert!(page(&d).editing.is_none(), "save closes the editor");
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("parse error"),
            "invalid file surfaces a parse error, got {:?}",
            page(&d).status
        );
    }

    #[test]
    fn delete_requires_two_presses_and_only_for_custom() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("scratch.md"),
            "---\ndescription: s\n---\nb\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        // Built-in: delete is refused.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Char('d')));
        assert!(tmp.path().join(".cockpit/agents").exists());
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("cannot be deleted"),
            "built-in delete is refused"
        );
        // Custom: first `d` arms, second deletes.
        focus(&mut d, "scratch");
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            agents_dir.join("scratch.md").exists(),
            "single d must not delete"
        );
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            !agents_dir.join("scratch.md").exists(),
            "double d deletes the custom agent"
        );
    }

    #[test]
    fn delete_disarms_on_navigation() {
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("a-scratch.md"),
            "---\ndescription: s\n---\nb\n",
        )
        .unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "a-scratch");
        d.handle_key(press(KeyCode::Char('d')));
        // Navigate away — must disarm.
        d.handle_key(press(KeyCode::Up));
        d.handle_key(press(KeyCode::Down));
        focus(&mut d, "a-scratch");
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            agents_dir.join("a-scratch.md").exists(),
            "navigation between the two d presses must re-arm, not delete"
        );
    }

    #[test]
    fn per_agent_reset_reverts_overridden_builtin_only() {
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        // Eject Build via the edit path (with $EDITOR unset → in-TUI), then
        // cancel the editor so we just have the override on disk.
        {
            let _g = EditorEnv::unset();
            focus(&mut d, "Build");
            d.handle_key(press(KeyCode::Char('e')));
            d.handle_key(press(KeyCode::Esc)); // cancel editor
        }
        let build_md = tmp.path().join(".cockpit/agents/Build.md");
        assert!(build_md.exists(), "Build was ejected");
        // Now Build is overridden — per-agent reset removes just that file.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Char('r'))); // arm
        assert!(build_md.exists(), "single r must not reset");
        d.handle_key(press(KeyCode::Char('r'))); // confirm
        assert!(
            !build_md.exists(),
            "double r resets the overridden built-in"
        );

        // A pristine built-in offers no reset.
        focus(&mut d, "builder");
        d.handle_key(press(KeyCode::Char('r')));
        assert!(
            page(&d)
                .status
                .as_deref()
                .unwrap_or("")
                .contains("overridden"),
            "pristine built-in r is refused"
        );
    }

    #[test]
    fn external_editor_request_is_drained_when_editor_set() {
        // With $EDITOR set, editing defers to the event loop: a pending
        // external-edit path is recorded and drainable.
        let _g = EditorEnv::with(Some("true"));
        let tmp = TempDir::new().unwrap();
        let (dialog, _trust) = agents_dialog(&tmp).into_parts();
        let mut outer = super::super::Dialog::Settings(Box::new(dialog));
        // Focus + edit `builder` (auto-ejects, then requests $EDITOR).
        if let super::super::Dialog::Settings(s) = &mut outer {
            focus(s, "builder");
        }
        outer.handle_key(press(KeyCode::Char('e')));
        let drained = outer.take_pending_agent_edit();
        assert!(
            drained.is_some(),
            "an external-edit request should be pending"
        );
        assert!(
            tmp.path().join(".cockpit/agents/builder.md").exists(),
            "the built-in was ejected before handing off to $EDITOR"
        );
        // Second drain is empty (taken).
        assert!(outer.take_pending_agent_edit().is_none());
        // A matching completion is accepted once; a duplicate is inert.
        let effect = drained.unwrap();
        let operation_id = effect.operation_id;
        fs::write(&effect.path, &effect.text_before_launch).unwrap();
        outer.finish_agent_edit(
            operation_id,
            super::super::pointer_actions::ExternalEditOutcome::Saved,
            None,
        );
        outer.finish_agent_edit(
            operation_id,
            super::super::pointer_actions::ExternalEditOutcome::Failed,
            Some("late duplicate".into()),
        );
        if let super::super::Dialog::Settings(s) = &mut outer {
            assert_ne!(page(s).status.as_deref(), Some("late duplicate"));
        }
    }

    pub(crate) fn run_pointer_external_edit_exactly_once_regression() {
        external_editor_request_is_drained_when_editor_set();

        let _g = EditorEnv::with(Some("true"));
        let tmp = TempDir::new().unwrap();
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::create_dir_all(&agents_dir).unwrap();
        fs::write(
            agents_dir.join("pointer-agent.md"),
            "---\ndescription: pointer fixture\n---\nbody\n",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                agents_dir.join("pointer-agent.md"),
                fs::Permissions::from_mode(0o640),
            )
            .unwrap();
        }
        let mut dialog = agents_dialog(&tmp);
        focus(&mut dialog, "pointer-agent");
        dialog.handle_key(press(KeyCode::Enter));
        dialog.handle_key(press(KeyCode::Char('e')));
        assert!(page(&dialog).editing.is_some(), "detail opens raw editor");

        let original = fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap();
        let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
        let edit_text = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                matches!(
                    target.action,
                    super::super::shell::SettingsPointerAction::Page(
                        super::super::pointer_actions::SettingsPointerAction::Agents(
                            super::super::pointer_actions::AgentsAction::EditText(_)
                        )
                    )
                )
            })
            .cloned()
            .expect("raw editor publishes text body");
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            edit_text.rect.x,
            edit_text.rect.y + 3,
        ));
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
            edit_text.rect.x,
            edit_text.rect.y + 3,
        ));
        page_mut(&mut dialog)
            .editing
            .as_mut()
            .expect("raw editor remains open after pointer placement")
            .paste("X");
        assert!(
            page(&dialog)
                .editing
                .as_ref()
                .unwrap()
                .text()
                .contains("\nXbody"),
            "click row is relative to retained editor-body origin"
        );

        let agent = super::super::pointer_actions::AgentId("pointer-agent".into());
        let action = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
        );
        let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
        let begin = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
            })
            .cloned()
            .expect("raw editor publishes Open in $EDITOR");
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            begin.rect.x,
            begin.rect.y,
        ));
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
            begin.rect.x,
            begin.rect.y,
        ));
        assert_eq!(
            page(&dialog).external_edit_confirmation.as_ref(),
            Some(&agent),
            "first activation only opens the named confirmation"
        );
        assert!(page(&dialog).pending_external_edit.is_none());
        assert_eq!(
            fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap(),
            original,
            "opening confirmation performs no eager file mutation"
        );
        let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
        assert!(
            !dialog
                .pointer_surface
                .targets
                .borrow()
                .iter()
                .any(|target| {
                    matches!(
                        target.action,
                        super::super::shell::SettingsPointerAction::Page(
                            super::super::pointer_actions::SettingsPointerAction::Agents(
                                super::super::pointer_actions::AgentsAction::EditText(_)
                            )
                        )
                    )
                }),
            "confirmation suppresses the editor text target"
        );
        let confirm = dialog
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .find(|target| {
                target.action == super::super::shell::SettingsPointerAction::Page(action.clone())
            })
            .cloned()
            .expect("confirmation publishes named Open in $EDITOR");
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            confirm.rect.x,
            confirm.rect.y,
        ));
        let operation = page(&dialog)
            .pending_external_edit
            .as_ref()
            .expect("confirmed activation submits effect")
            .id;
        dialog.handle_pointer(super::super::tests::settings_mouse(
            crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
            confirm.rect.x,
            confirm.rect.y,
        ));
        assert_eq!(
            page(&dialog)
                .pending_external_edit
                .as_ref()
                .map(|pending| pending.id),
            Some(operation),
            "release preserves the one correlated operation"
        );
        assert_eq!(
            fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap(),
            original,
            "submitting the injected effect still performs no reducer-side write"
        );
        assert_eq!(page(&dialog).external_edit_ops.pending(), Some(operation));

        let request = page_mut(&mut dialog)
            .take_external_edit_request()
            .expect("effect request drains once");
        assert_eq!(request.operation_id, operation);
        assert_eq!(
            request.text_before_launch,
            "---\ndescription: pointer fixture\n---\nXbody\n"
        );
        assert!(page_mut(&mut dialog).take_external_edit_request().is_none());
        let cwd = dialog.cx.agents_cwd();
        page_mut(&mut dialog).reduce_external_edit_result(
            &cwd,
            operation,
            super::super::pointer_actions::AgentsAction::ExternalEditResult(
                super::super::pointer_actions::AgentId("replacement-agent".into()),
                super::super::pointer_actions::ExternalEditOutcome::Saved,
            ),
            None,
        );
        assert!(
            page(&dialog).pending_external_edit.is_some(),
            "stale stable identity is inert"
        );
        dialog.finish_agent_external_edit(
            PointerOperationId(operation.0 + 1),
            super::super::pointer_actions::ExternalEditOutcome::Saved,
            None,
        );
        assert!(
            page(&dialog).pending_external_edit.is_some(),
            "stale completion is inert"
        );
        fs::write(&request.path, &request.text_before_launch).unwrap();
        let saved_result = super::super::pointer_actions::SettingsPointerAction::Agents(
            super::super::pointer_actions::AgentsAction::ExternalEditResult(
                agent.clone(),
                super::super::pointer_actions::ExternalEditOutcome::Saved,
            ),
        );
        super::super::pointer_acceptance_tests::record_source_action(&saved_result);
        dialog.finish_agent_external_edit(
            operation,
            super::super::pointer_actions::ExternalEditOutcome::Saved,
            None,
        );
        super::super::pointer_acceptance_tests::record_dispatched_action(&saved_result);
        assert!(
            fs::read_to_string(agents_dir.join("pointer-agent.md"))
                .unwrap()
                .contains("\nXbody"),
            "Saved atomically commits the staged edit"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(agents_dir.join("pointer-agent.md"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o640,
                "atomic replacement preserves the original mode"
            );
        }
        let status = page(&dialog).status.clone();
        dialog.finish_agent_external_edit(
            operation,
            super::super::pointer_actions::ExternalEditOutcome::Failed,
            Some("duplicate".into()),
        );
        assert_eq!(
            page(&dialog).status,
            status,
            "duplicate completion is inert"
        );

        for outcome in [
            super::super::pointer_actions::ExternalEditOutcome::Cancelled,
            super::super::pointer_actions::ExternalEditOutcome::Failed,
        ] {
            let mut retry = agents_dialog(&tmp);
            focus(&mut retry, "pointer-agent");
            retry.handle_key(press(KeyCode::Enter));
            retry.handle_key(press(KeyCode::Char('e')));
            page_mut(&mut retry)
                .editing
                .as_mut()
                .unwrap()
                .paste("RETAINED");
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut retry.dialog.page;
                let cx = &mut retry.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut retry)
                .take_external_edit_request()
                .expect("terminal outcome effect");
            let operation = effect.operation_id;
            fs::write(&effect.path, "externally changed staging").unwrap();
            let result_action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditResult(
                    agent.clone(),
                    outcome,
                ),
            );
            super::super::pointer_acceptance_tests::record_source_action(&result_action);
            retry.finish_agent_external_edit(operation, outcome, None);
            super::super::pointer_acceptance_tests::record_dispatched_action(&result_action);
            assert!(page(&retry).pending_external_edit.is_none());
            assert!(
                page(&retry)
                    .editing
                    .as_ref()
                    .is_some_and(|editor| editor.text().contains("RETAINED")),
                "{outcome:?} restores the exact retryable draft"
            );
            assert!(page(&retry).external_edit_ops.pending().is_none());
            assert!(
                !fs::read_to_string(agents_dir.join("pointer-agent.md"))
                    .unwrap()
                    .contains("RETAINED"),
                "{outcome:?} never mutates the real agent path"
            );
        }

        let replacement_cases: &[bool] = if cfg!(unix) { &[false, true] } else { &[false] };
        for &replacement in replacement_cases {
            let target = agents_dir.join("pointer-agent.md");
            fs::write(&target, "---\ndescription: pointer fixture\n---\nXbody\n").unwrap();
            let mut conflict = agents_dialog(&tmp);
            focus(&mut conflict, "pointer-agent");
            conflict.handle_key(press(KeyCode::Enter));
            conflict.handle_key(press(KeyCode::Char('e')));
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut conflict.dialog.page;
                let cx = &mut conflict.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut conflict)
                .take_external_edit_request()
                .expect("regular-file conflict effect");
            fs::write(&effect.path, "staged replacement").unwrap();
            let concurrent = b"---\ndescription: pointer fixture\n---\nYbody\n";
            if replacement {
                let replacement_path = agents_dir.join("replacement.md");
                fs::write(&replacement_path, concurrent).unwrap();
                fs::rename(replacement_path, &target).unwrap();
            } else {
                fs::write(&target, concurrent).unwrap();
            }
            conflict.finish_agent_external_edit(
                effect.operation_id,
                super::super::pointer_actions::ExternalEditOutcome::Saved,
                None,
            );
            assert_eq!(
                fs::read(&target).unwrap(),
                concurrent,
                "{} conflict keeps the concurrent file",
                if replacement { "identity" } else { "content" }
            );
            assert!(page(&conflict).editing.is_some(), "conflict restores draft");
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let target = agents_dir.join("pointer-agent.md");
            let before = fs::read(&target).unwrap();
            let mut chmod_race = agents_dialog(&tmp);
            focus(&mut chmod_race, "pointer-agent");
            chmod_race.handle_key(press(KeyCode::Enter));
            chmod_race.handle_key(press(KeyCode::Char('e')));
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut chmod_race.dialog.page;
                let cx = &mut chmod_race.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut chmod_race)
                .take_external_edit_request()
                .expect("chmod-race effect");
            fs::write(&effect.path, "staged replacement").unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
            chmod_race.finish_agent_external_edit(
                effect.operation_id,
                super::super::pointer_actions::ExternalEditOutcome::Saved,
                None,
            );
            assert_eq!(
                fs::read(&target).unwrap(),
                before,
                "chmod conflict keeps bytes"
            );
            assert_eq!(
                fs::metadata(&target).unwrap().permissions().mode() & 0o777,
                0o600,
                "commit must not restore stale permissions after a concurrent chmod"
            );
            assert!(
                page(&chmod_race).editing.is_some(),
                "draft restored on chmod conflict"
            );
            assert!(
                page(&chmod_race)
                    .status
                    .as_deref()
                    .is_some_and(|status| status.contains("metadata changed"))
            );
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let mut swapped = agents_dialog(&tmp);
            focus(&mut swapped, "pointer-agent");
            swapped.handle_key(press(KeyCode::Enter));
            swapped.handle_key(press(KeyCode::Char('e')));
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                super::super::pointer_actions::AgentsAction::ExternalEditBegin(agent.clone()),
            );
            {
                let page = &mut swapped.dialog.page;
                let cx = &mut swapped.dialog.cx;
                page.handle_pointer_control(cx, action.clone());
                page.handle_pointer_control(cx, action);
            }
            let effect = page_mut(&mut swapped)
                .take_external_edit_request()
                .expect("symlink-swap effect");
            fs::write(&effect.path, "staged replacement").unwrap();
            let target = agents_dir.join("pointer-agent.md");
            let victim = tmp.path().join("symlink-victim.md");
            fs::write(&victim, "victim stays unchanged").unwrap();
            fs::remove_file(&target).unwrap();
            symlink(&victim, &target).unwrap();
            swapped.finish_agent_external_edit(
                effect.operation_id,
                super::super::pointer_actions::ExternalEditOutcome::Saved,
                None,
            );
            assert_eq!(
                fs::read_to_string(&victim).unwrap(),
                "victim stays unchanged"
            );
            assert!(page(&swapped).editing.is_some(), "draft restored on swap");
            assert!(
                page(&swapped)
                    .status
                    .as_deref()
                    .is_some_and(|status| status.contains("symbolic link"))
            );
        }
    }

    pub(crate) fn run_pointer_raw_editor_terminal_actions_regression() {
        let _g = EditorEnv::with(Some("true"));
        for terminal in ["save", "cancel"] {
            let tmp = TempDir::new().unwrap();
            let agents_dir = tmp.path().join(".cockpit/agents");
            fs::create_dir_all(&agents_dir).unwrap();
            fs::write(
                agents_dir.join("pointer-agent.md"),
                "---\ndescription: pointer fixture\n---\nbody\n",
            )
            .unwrap();
            let mut dialog = agents_dialog(&tmp);
            focus(&mut dialog, "pointer-agent");
            dialog.handle_key(press(KeyCode::Enter));
            dialog.handle_key(press(KeyCode::Char('e')));
            page_mut(&mut dialog)
                .editing
                .as_mut()
                .expect("raw editor opens")
                .paste("changed-by-pointer\n");
            let agent = super::super::pointer_actions::AgentId("pointer-agent".into());
            let action = super::super::pointer_actions::SettingsPointerAction::Agents(
                if terminal == "save" {
                    super::super::pointer_actions::AgentsAction::Save(agent)
                } else {
                    super::super::pointer_actions::AgentsAction::Cancel(agent)
                },
            );
            let target = {
                let _ = super::super::tests::render_settings_rows(&dialog, 90, 28);
                dialog
                    .pointer_surface
                    .targets
                    .borrow()
                    .iter()
                    .find(|target| {
                        target.enabled
                            && target.action
                                == super::super::shell::SettingsPointerAction::Page(action.clone())
                    })
                    .cloned()
                    .expect("raw agent editor publishes its named terminal action")
            };
            dialog.handle_pointer(super::super::tests::settings_mouse(
                crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
                target.rect.x,
                target.rect.y,
            ));
            dialog.handle_pointer(super::super::tests::settings_mouse(
                crossterm::event::MouseEventKind::Up(crossterm::event::MouseButton::Left),
                target.rect.x,
                target.rect.y,
            ));
            assert!(
                page(&dialog).editing.is_none(),
                "{terminal} closes the raw editor through its real reducer"
            );
            let persisted = fs::read_to_string(agents_dir.join("pointer-agent.md")).unwrap();
            if terminal == "save" {
                assert!(
                    persisted.contains("changed-by-pointer"),
                    "Save persists the raw editor draft"
                );
            } else {
                assert_eq!(
                    persisted, "---\ndescription: pointer fixture\n---\nbody\n",
                    "Cancel discards the raw editor draft"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn external_editor_rejects_initial_symlink_target() {
        use std::os::unix::fs::symlink;
        let tmp = TempDir::new().unwrap();
        let real = tmp.path().join("real.md");
        let link = tmp.path().join("link.md");
        fs::write(&real, "real").unwrap();
        symlink(&real, &link).unwrap();
        let error = agent_external_edit_staging(&link)
            .err()
            .expect("symlink target must be rejected");
        assert!(error.contains("symbolic link"), "{error}");
        assert_eq!(fs::read_to_string(&real).unwrap(), "real");
    }

    #[cfg(not(unix))]
    #[test]
    fn external_editor_metadata_detects_readonly_permission_change() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("agent.md");
        fs::write(&path, "agent").unwrap();
        let original = AgentFileMetadata::capture(&fs::metadata(&path).unwrap());
        let mut permissions = fs::metadata(&path).unwrap().permissions();
        permissions.set_readonly(!permissions.readonly());
        fs::set_permissions(&path, permissions).unwrap();
        assert!(!original.matches(&fs::metadata(&path).unwrap()));
    }

    #[test]
    fn reset_all_confirm_removes_overrides() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        // Eject one built-in (via edit, then cancel) and add a custom agent.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Char('e'))); // open in-TUI editor (ejects)
        d.handle_key(press(KeyCode::Esc)); // cancel editor
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::write(
            agents_dir.join("my-reviewer.md"),
            "---\ndescription: r\n---\nb\n",
        )
        .unwrap();
        // Refresh the page so it sees the custom agent.
        if let TestPageMut::Agents(p) = d.test_page_mut() {
            *p = AgentsPage::new(tmp.path());
        }
        // `R` then `y` resets.
        d.handle_key(press(KeyCode::Char('R')));
        assert!(page(&d).confirm_reset);
        d.handle_key(press(KeyCode::Char('y')));
        assert!(!page(&d).confirm_reset);
        assert!(
            !agents_dir.join("Build.md").exists(),
            "built-in override removed"
        );
        assert!(
            agents_dir.join("my-reviewer.md").exists(),
            "custom agent kept"
        );
    }

    /// A Ctrl+S key, used by the save test.
    fn ctrl_s() -> KeyEvent {
        KeyEvent {
            code: KeyCode::Char('s'),
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }
}
