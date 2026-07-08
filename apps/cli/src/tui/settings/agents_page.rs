//! `/settings → Agents` page (implementation note).
//!
//! A full management surface over the bundled cast
//! (`Build`/`builder`/`explore`/`Plan`) and any user-authored
//! custom agents. Each row shows the agent name, its builtin/custom
//! (+ overridden) status, and its **effective model** (the frontmatter
//! `model:` in canonical `provider/model` slash form, or the session
//! default). The docs pipeline is deliberately absent: it is a fixed
//! two-stage internal pipeline, never a user-editable [`crate::agents::AgentDef`].
//!
//! Actions:
//!   - `enter` / `e` — **edit** the highlighted agent's on-disk
//!     `.cockpit/agents/<name>.md`. A non-overridden built-in is
//!     auto-ejected first (existing [`crate::agents::eject_builtin`] path).
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

use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::agents::{AgentKind, AgentListing, is_builtin_agent, list_all};
use crate::tui::theme::MUTED_COLOR_INDEX;

use super::agent_editor::{AgentEditor, EditorOutcome};
use super::reset::{ResetButton, ResetOutcome};
use super::{Nav, Page, SettingsDialog};

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
    /// Set when the user chose to edit and `$EDITOR` is available: the
    /// event loop drains this (the page can't suspend the TUI itself),
    /// runs `$EDITOR`, then calls back to re-read + re-parse.
    pub(super) pending_external_edit: Option<PathBuf>,
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
}

impl AgentsPage {
    /// Build the page by discovering agents at `cwd`.
    pub(super) fn new(cwd: &std::path::Path) -> Self {
        Self {
            cursor: 0,
            confirm_reset: false,
            delete: ResetButton::default(),
            reset_one: ResetButton::default(),
            status: None,
            rows: rows_for(cwd),
            editing: None,
            pending_external_edit: None,
        }
    }

    /// Help line for the footer, varying with the page sub-state.
    pub(super) fn help_text(&self) -> &'static str {
        if self.editing.is_some() {
            // The in-TUI editor draws its own hint; this is the footer.
            return "editing agent — ctrl+s: save  esc: cancel";
        }
        if self.confirm_reset {
            return "y: confirm reset-all  n/esc: cancel";
        }
        match self.rows.get(self.cursor).map(|r| &r.kind) {
            Some(AgentKind::Custom) => {
                "↑/↓  enter/e: edit  d: delete (×2)  R: reset all  esc/h: back  q: close"
            }
            Some(AgentKind::Builtin { overridden: true }) => {
                "↑/↓  enter/e: edit  r: reset (×2)  R: reset all  esc/h: back  q: close"
            }
            _ => "↑/↓  enter/e: edit  R: reset all  esc/h: back  q: close",
        }
    }

    /// Disarm both per-agent confirm guards. Called on any navigation /
    /// cancel so a stale "press again" can never fire on a different row.
    fn disarm_guards(&mut self) {
        self.delete.disarm();
        self.reset_one.disarm();
    }

    /// Re-read the edited file from disk, re-parse it, and refresh the row.
    /// A parse error is surfaced inline (keeping the user on the page); the
    /// `editor_error` from a failed external process is reported as-is.
    pub(super) fn finish_external_edit(
        &mut self,
        cwd: &std::path::Path,
        editor_error: Option<String>,
    ) {
        if let Some(err) = editor_error {
            self.status = Some(err);
            return;
        }
        // Find the name we were editing by matching the cursor row (the
        // page didn't navigate while the external editor ran).
        let name = self.rows.get(self.cursor).map(|r| r.name.clone());
        self.refresh_after_edit(cwd, name.as_deref());
    }
}

/// Build the per-row view models for `cwd`, including the effective model.
fn rows_for(cwd: &std::path::Path) -> Vec<AgentRow> {
    list_all(cwd)
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
            }
        })
        .collect()
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

impl SettingsDialog {
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

    pub(super) fn handle_agents_key(&mut self, key: KeyEvent) -> bool {
        let placeholder = Page::Agents(AgentsPage {
            cursor: 0,
            confirm_reset: false,
            delete: ResetButton::default(),
            reset_one: ResetButton::default(),
            status: None,
            rows: Vec::new(),
            editing: None,
            pending_external_edit: None,
        });
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::Agents(p) = &mut page {
            self.handle_agents_page_key(key, p)
        } else {
            Nav::Stay
        };
        match nav {
            Nav::Stay => {
                self.page = page;
                false
            }
            Nav::Replace(new) => {
                self.page = new;
                false
            }
            Nav::Close => true,
        }
    }

    fn handle_agents_page_key(&mut self, key: KeyEvent, p: &mut AgentsPage) -> Nav {
        // ── In-TUI editor (vim or plain) ────────────────────────────
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
                EditorOutcome::Cancel => {
                    p.editing = None;
                    p.status = Some("edit cancelled".into());
                }
            }
            return Nav::Stay;
        }

        // ── Reset-all confirmation ──────────────────────────────────
        if p.confirm_reset {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    p.confirm_reset = false;
                    let cwd = self.agents_cwd();
                    match crate::agents::reset_all_builtins(&cwd) {
                        Ok(removed) => {
                            p.status = Some(format!(
                                "reset {} built-in override(s) to default",
                                removed.len()
                            ));
                        }
                        Err(e) => p.status = Some(format!("reset failed: {e}")),
                    }
                    p.rows = rows_for(&cwd);
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
                return Nav::Replace(Page::Root {
                    cursor: self.last_root_cursor,
                });
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
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('e') => {
                p.disarm_guards();
                self.edit_selected(p);
            }
            _ => {}
        }
        Nav::Stay
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

        // 1. `$EDITOR` → external process, serviced by the event loop.
        if std::env::var_os("EDITOR").is_some() {
            // Refresh the rows now so the auto-ejected built-in is already
            // marked overridden under the cursor; the loop will re-read the
            // file after the external editor returns.
            p.rows = rows_for(&cwd);
            p.pending_external_edit = Some(path);
            p.status = Some("opening $EDITOR…".into());
            return;
        }

        // 2/3. In-TUI editor — vim when enabled, else plain. No dead end.
        let text = match std::fs::read_to_string(&path) {
            Ok(t) => t,
            Err(e) => {
                p.status = Some(format!("edit failed: reading {}: {e}", path.display()));
                return;
            }
        };
        // Refresh rows so an auto-ejected built-in is marked overridden
        // while the in-TUI editor is open.
        p.rows = rows_for(&cwd);
        let vim = self.extended.tui.vim_mode.vim_enabled();
        p.editing = Some(AgentEditor::new(name, path, &text, vim));
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
            let (path, _newly) = crate::agents::eject_builtin(cwd, &config_dir, name)?;
            Ok(path)
        } else {
            // Custom agent — edit its existing file in whatever layer it
            // resolves from.
            crate::agents::find_override(cwd, name)
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
        match crate::agents::find_override(&cwd, &name) {
            Some(path) => match std::fs::remove_file(&path) {
                Ok(()) => p.status = Some(format!("deleted custom agent `{name}`")),
                Err(e) => p.status = Some(format!("delete failed: {e}")),
            },
            None => p.status = Some(format!("delete failed: `{name}` has no on-disk file")),
        }
        p.rows = rows_for(&cwd);
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
        match crate::agents::find_override(&cwd, &name) {
            Some(path) => match std::fs::remove_file(&path) {
                Ok(()) => p.status = Some(format!("reset `{name}` to default")),
                Err(e) => p.status = Some(format!("reset failed: {e}")),
            },
            None => p.status = Some(format!("reset: `{name}` has no override")),
        }
        p.rows = rows_for(&cwd);
        p.cursor = p.cursor.min(p.rows.len().saturating_sub(1));
    }

    pub(super) fn render_agents_page(&self, frame: &mut Frame, area: Rect, p: &AgentsPage) {
        // The in-TUI editor takes the whole page area when open.
        if let Some(editor) = &p.editing {
            editor.render(frame, area);
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
            Line::from(Span::styled(
                "Edit opens the agent's .cockpit/agents/<name>.md ($EDITOR, else \
                 in-TUI). Editing a built-in ejects its default first. The model is \
                 the `model:` frontmatter field (provider/model). Delete removes a \
                 custom agent; reset reverts an overridden built-in."
                    .to_string(),
                muted,
            )),
            Line::default(),
        ];

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
            if let Ok(desc) = &row.detail {
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled(desc.clone(), muted),
                ]));
            }
        }

        if p.confirm_reset {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Reset ALL built-in agents to default? This deletes their \
                 on-disk overrides (custom agents are kept).  y: confirm  n: cancel"
                    .to_string(),
                red.add_modifier(Modifier::BOLD),
            )));
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}

/// Internal helper on the page: re-discover agents and (when a name is
/// given) move the cursor onto that row + re-surface a parse error inline.
impl AgentsPage {
    fn refresh_after_edit(&mut self, cwd: &std::path::Path, name: Option<&str>) {
        self.rows = rows_for(cwd);
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

#[cfg(test)]
mod tests {
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

    /// A settings dialog whose `config.json` lives in `<tmp>/.cockpit/`
    /// and whose picker cwd is `<tmp>`, on the Agents page.
    fn agents_dialog(tmp: &TempDir) -> SettingsDialog {
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir_all(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        let mut d = SettingsDialog::open_from_picker(config_path, tmp.path().to_path_buf());
        d.page = Page::Agents(AgentsPage::new(tmp.path()));
        d
    }

    fn page(d: &SettingsDialog) -> &AgentsPage {
        match &d.page {
            Page::Agents(p) => p,
            _ => panic!("expected Agents page"),
        }
    }

    fn page_mut(d: &mut SettingsDialog) -> &mut AgentsPage {
        match &mut d.page {
            Page::Agents(p) => p,
            _ => panic!("expected Agents page"),
        }
    }

    /// Move the cursor onto the row whose agent name is `name`.
    fn focus(d: &mut SettingsDialog, name: &str) {
        let idx = page(d).rows.iter().position(|r| r.name == name).unwrap();
        page_mut(d).cursor = idx;
    }

    /// `$EDITOR` is process-global, so the editor-precedence tests must not
    /// run concurrently or they'd observe each other's mutations. This lock
    /// serializes them; the [`EditorEnv`] guard holds it for the test's
    /// duration and restores the prior value on drop.
    static EDITOR_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EditorEnv {
        _guard: std::sync::MutexGuard<'static, ()>,
        prev: Option<std::ffi::OsString>,
    }
    impl EditorEnv {
        /// Take the lock and set `$EDITOR` to `value` (or unset it for `None`).
        fn with(value: Option<&str>) -> Self {
            let guard = EDITOR_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let prev = std::env::var_os("EDITOR");
            unsafe {
                match value {
                    Some(v) => std::env::set_var("EDITOR", v),
                    None => std::env::remove_var("EDITOR"),
                }
            }
            EditorEnv {
                _guard: guard,
                prev,
            }
        }
        fn unset() -> Self {
            Self::with(None)
        }
    }
    impl Drop for EditorEnv {
        fn drop(&mut self) {
            unsafe {
                match &self.prev {
                    Some(v) => std::env::set_var("EDITOR", v),
                    None => std::env::remove_var("EDITOR"),
                }
            }
        }
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
    fn edit_without_editor_opens_in_tui_and_auto_ejects_builtin() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        focus(&mut d, "builder");
        // Enter starts the in-TUI editor; the built-in is ejected first.
        d.handle_key(press(KeyCode::Enter));
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
        d.extended.tui.vim_mode = crate::config::extended::VimModeSetting::Disabled;
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
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
        d.extended.tui.vim_mode = crate::config::extended::VimModeSetting::Disabled;
        focus(&mut d, "mine");
        d.handle_key(press(KeyCode::Enter));
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
            d.handle_key(press(KeyCode::Enter));
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
        let mut outer = super::super::Dialog::Settings(Box::new(agents_dialog(&tmp)));
        // Focus + edit `builder` (auto-ejects, then requests $EDITOR).
        if let super::super::Dialog::Settings(s) = &mut outer {
            focus(s, "builder");
        }
        outer.handle_key(press(KeyCode::Enter));
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
        // finish_agent_edit re-parses + refreshes without panicking.
        outer.finish_agent_edit(None);
    }

    #[test]
    fn reset_all_confirm_removes_overrides() {
        let _g = EditorEnv::unset();
        let tmp = TempDir::new().unwrap();
        let mut d = agents_dialog(&tmp);
        // Eject one built-in (via edit, then cancel) and add a custom agent.
        focus(&mut d, "Build");
        d.handle_key(press(KeyCode::Enter)); // open in-TUI editor (ejects)
        d.handle_key(press(KeyCode::Esc)); // cancel editor
        let agents_dir = tmp.path().join(".cockpit/agents");
        fs::write(
            agents_dir.join("my-reviewer.md"),
            "---\ndescription: r\n---\nb\n",
        )
        .unwrap();
        // Refresh the page so it sees the custom agent.
        if let Page::Agents(p) = &mut d.page {
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
