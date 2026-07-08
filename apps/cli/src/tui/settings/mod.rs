#![allow(dead_code)]
//! `/settings` dialog state machine + rendering.
//!
//! Lifecycle:
//!   - `Dialog::None`            no overlay; viewport renders normally
//!   - `Dialog::PickConfig`      choose an existing config to edit
//!   - `Dialog::CreateConfig`    no config yet — pick a location to scaffold
//!   - `Dialog::Settings`        navigate the settings tree
//!
//! The Settings page tree (root has 11 nodes; see `root_nodes()`):
//!
//! ```text
//! Root
//!  ├── Providers
//!  │    ├── List ──── Add Provider wizard ─── (template -> URL -> Auth -> save)
//!  │    │           └── Edit Provider page
//!  │    └── FetchAll dialog (triggered by /fetch-models)
//!  ├── Agents
//!  ├── Interface          ┐
//!  ├── Behavior           │ category pages
//!  ├── Privacy & Safety   │ (descriptor list + optional picker)
//!  ├── Translation        │
//!  ├── Profile            ┘
//!  ├── Tools
//!  ├── Harnesses
//!  ├── Skills
//!  └── MCP
//! ```
//!
//! Async fetches (the `/models` endpoint after Save, or via the Edit
//! page's `r`=refetch action) use [`FetchHandle`] — a shared cell the
//! background task writes into and the event loop reads on each tick.

mod agent_editor;
mod agents_page;
mod auth;
mod category;
mod grab;
mod harnesses_page;
mod mcp_page;
mod providers;
mod reset;
mod secret_display;
mod settings_editor;
mod shell;
mod skills_page;
mod string_list;
mod tools_page;
mod ui_page;

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::config::dirs::{
    ConfigDir, ConfigDirKind, creatable_config_dirs, cwd_scoped_creatable_dirs,
    discover_config_dirs, scaffold_config_dir,
};
use crate::config::extended::{ExtendedConfig, ExtendedConfigDoc};
use crate::config::providers::{ConfigDoc, OnUnlistedModelsFetch, ProvidersConfig};
use crate::daemon::proto::{LspControlAction, Request};
use crate::providers::models_fetch::FetchOutcome;
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use shell::{marker, muted_style, selected_or_field, window_lines};

/// Height (in rows) the dialog wants when active.
pub const DIALOG_HEIGHT: u16 = 20;

pub enum Dialog {
    None,
    PickConfig {
        dirs: Vec<ConfigDir>,
        cursor: usize,
        /// Held so the `a` affordance can scaffold a new scoped config
        /// in the right place.
        cwd: PathBuf,
        /// Transient error/status (e.g. scaffold-failure message).
        status: Option<String>,
    },
    CreateConfig {
        choices: Vec<ConfigDir>,
        cursor: usize,
        /// Held so the resulting settings dialog can offer "back to
        /// picker" — once a config has been scaffolded, reopening the
        /// picker yields a non-empty list.
        cwd: PathBuf,
        /// Transient scaffold error/status.
        status: Option<String>,
    },
    /// "Add a config scoped to the current directory" sub-dialog
    /// reached by pressing `a` on the picker. Offers a `.cockpit/` in
    /// the cwd (shareable with a team) or a hashed-cwd dir under the
    /// cockpit data dir (machine-local).
    CreateScopedConfig {
        choices: Vec<ConfigDir>,
        cursor: usize,
        cwd: PathBuf,
    },
    /// Boxed because [`SettingsDialog`] dwarfs the other variants
    /// (~1.1KB vs <100 bytes), which would otherwise bloat every
    /// [`Dialog`] on the stack.
    Settings(Box<SettingsDialog>),
}

pub struct SettingsDialog {
    pub config_path: PathBuf,
    /// Path to the cockpit-only config keys. Same `config.json` as
    /// [`config_path`](Self::config_path) (GOALS §2a) — the provider/model
    /// keys and the former-`ExtendedConfig` keys share one file. Loaded
    /// lazily when the UI / Tools pages open; saved on each edit there.
    pub(super) extended_path: PathBuf,
    pub(super) page: Page,
    /// Cached config state; reloaded on entry into the Providers list
    /// and after each successful save.
    pub(super) config: ProvidersConfig,
    /// Cached cockpit-only `config.json` state. Read by the UI page and the
    /// Tools page; written back on each edit.
    pub(super) extended: ExtendedConfig,
    /// Malformed known extended-config fields skipped during the most
    /// recent load. Unknown raw keys are preserved separately by
    /// [`ExtendedConfigDoc`].
    pub(super) extended_warnings: Vec<String>,
    /// Root-page cursor restored when navigating back. Updated every
    /// time we leave Root for a subpage.
    pub(super) last_root_cursor: usize,
    /// The cwd this dialog was opened against. Held so Root's `h`/←
    /// can reopen the picker without losing context. `None` when the
    /// settings dialog was opened from a flow that has no picker to
    /// return to.
    pub(super) picker_cwd: Option<PathBuf>,
    /// Active launch/session project root for side effects that must operate on
    /// a project while this dialog may be editing a home/global config file.
    pub(super) active_project_root: Option<PathBuf>,
    /// Set by Root's back action to ask the outer [`Dialog`] to
    /// re-open the picker on the next `true` return from `handle_key`.
    pub(super) back_to_picker: bool,
    /// PATH-presence resolver for harness-preset seeding: returns whether a
    /// harness `command` is installed (found on `PATH`). Defaults to the
    /// real [`crate::harness::preflight::which_on_path`]; tests inject a
    /// stub so seeding doesn't depend on the CI machine's installed tools.
    pub(super) command_installed: fn(&str) -> bool,
    pending_daemon_request: Option<Request>,
    pending_oauth_action: Option<OAuthActionRequest>,
}

#[allow(private_interfaces)]
pub(super) enum Page {
    Root {
        cursor: usize,
    },
    Agents(AgentsPage),
    Tools(ToolsPage),
    Harnesses(HarnessesPage),
    Providers(ProvidersPage),
    /// One of the five reorganized category pages (Interface, Behavior,
    /// Privacy & Safety, Translation, Profile). Boxed because [`CategoryPage`]
    /// (descriptor list + optional picker) is much larger than the other
    /// variants, which would otherwise bloat the enum.
    Category(Box<CategoryPage>),
    Instructions(InstructionsPage),
    RedactPatterns(RedactPatternsPage),
    /// A generic grab/reorder string-list editor (`agent_dirs`,
    /// `redact.extra_dotenv_paths`, `redact.denylist`, `redact.allowlist`).
    StringList(Box<StringListPage>),
    Skills(SkillsPage),
    Mcp(McpPage),
    Lsp(LspPage),
}

#[cfg(test)]
impl Page {
    fn test_name(&self) -> &'static str {
        match self {
            Page::Root { .. } => "Root",
            Page::Agents(_) => "Agents",
            Page::Tools(_) => "Tools",
            Page::Harnesses(_) => "Harnesses",
            Page::Providers(_) => "Providers",
            Page::Category(_) => "Category",
            Page::Instructions(_) => "Instructions",
            Page::RedactPatterns(_) => "RedactPatterns",
            Page::StringList(_) => "StringList",
            Page::Skills(_) => "Skills",
            Page::Mcp(_) => "MCP",
            Page::Lsp(_) => "LSP",
        }
    }
}

use agents_page::AgentsPage;
use category::{Category, CategoryPage};
use harnesses_page::HarnessesPage;
use mcp_page::McpPage;
pub(crate) use mcp_page::row_color as mcp_row_color;
pub(crate) use providers::OAuthActionRequest;
use providers::{AddState, AddStep, ProvidersPage};
use reset::{ResetButton, ResetOutcome};
use skills_page::SkillsPage;
use string_list::StringListPage;
use tools_page::ToolsPage;
pub use tools_page::{builtin_tool_names, default_template_for};

pub(super) struct LspPage {
    cursor: usize,
    editing: Option<LspEdit>,
    buf: TextField,
    status: Option<String>,
    reset: ResetButton,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LspEdit {
    OtherFilesLimit,
    PerFileLimit,
    DebounceMs,
    DocumentTimeoutMs,
    WorkspaceTimeoutMs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LspRow {
    Enabled,
    AutoInstall,
    Diagnostics,
    OtherFilesLimit,
    PerFileLimit,
    DebounceMs,
    DocumentTimeoutMs,
    WorkspaceTimeoutMs,
    Reset,
    Server(usize),
}

const LSP_NAV_ROWS: [LspRow; 9] = [
    LspRow::Enabled,
    LspRow::AutoInstall,
    LspRow::Diagnostics,
    LspRow::OtherFilesLimit,
    LspRow::PerFileLimit,
    LspRow::DebounceMs,
    LspRow::DocumentTimeoutMs,
    LspRow::WorkspaceTimeoutMs,
    LspRow::Reset,
];

const LSP_SERVER_ROW_START: usize = LSP_NAV_ROWS.len();

fn lsp_row_for_cursor(cursor: usize) -> LspRow {
    LSP_NAV_ROWS
        .get(cursor)
        .copied()
        .unwrap_or_else(|| LspRow::Server(cursor - LSP_SERVER_ROW_START))
}
use ui_page::{InstructionsPage, RedactPatternsPage};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct RowDeleteConfirm {
    pending: Option<usize>,
}

impl RowDeleteConfirm {
    pub(super) fn arm_or_confirm(&mut self, row: usize) -> bool {
        if self.pending == Some(row) {
            self.pending = None;
            true
        } else {
            self.pending = Some(row);
            false
        }
    }

    pub(super) fn disarm(&mut self) {
        self.pending = None;
    }

    pub(super) fn is_pending_for(&self, row: usize) -> bool {
        self.pending == Some(row)
    }
}

/// Navigation intent returned by an inner page handler. The outer
/// [`SettingsDialog::handle_providers_key`] applies it *after* swapping
/// the borrowed sub-page back in. Inner handlers cannot write
/// `self.page` directly — the swap-back would discard the write.
#[allow(private_interfaces)]
// `Nav` is a short-lived return value (never stored), so the size gap is
// harmless; boxing `Replace` would churn its ~60 construction sites for no
// real gain. `Page` already boxes its own large variants.
#[allow(clippy::large_enum_variant)]
pub(super) enum Nav {
    /// Stay on the current page; sub-state mutations have already been
    /// applied to the borrowed `&mut SubState`.
    Stay,
    /// Navigate to `Page::...`.
    Replace(Page),
    /// Close the whole dialog.
    Close,
}

// ── Dialog top-level ─────────────────────────────────────────────────────

impl Dialog {
    pub fn is_active(&self) -> bool {
        !matches!(self, Dialog::None)
    }

    #[cfg(test)]
    pub(crate) fn test_page_name(&self) -> Option<&'static str> {
        match self {
            Dialog::Settings(settings) => Some(settings.page.test_name()),
            _ => None,
        }
    }

    pub fn open(cwd: &std::path::Path) -> Self {
        let dirs = discover_config_dirs(cwd);
        if dirs.is_empty() {
            Dialog::CreateConfig {
                choices: creatable_config_dirs(),
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status: None,
            }
        } else {
            Dialog::PickConfig {
                dirs,
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status: None,
            }
        }
    }

    /// Open directly into the MCP page (`/mcp settings`, GOALS §18a).
    pub fn open_mcp(cwd: &std::path::Path) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join("config.json");
            d = Dialog::Settings(Box::new(SettingsDialog::open_from_picker(
                path,
                cwd.to_path_buf(),
            )));
            if let Dialog::Settings(s) = &mut d {
                s.enter_mcp();
            }
        }
        d
    }

    /// Open the settings dialog directly on the **active** model's
    /// model-settings sub-dialog (implementation note,
    /// `/model-settings`). When no model is active — or the active
    /// provider/model can't be found in config — open to the providers list
    /// with an inline status explaining there's nothing selected.
    pub fn open_model_settings(cwd: &std::path::Path) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join("config.json");
            let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
            s.enter_model_settings();
            d = Dialog::Settings(Box::new(s));
        }
        d
    }

    /// Open the settings dialog directly on the gitignore read-allowlist
    /// editor for the **current project** (`/gitignore-allow`,
    /// implementation note). The target config is the
    /// nearest project `.cockpit/config.json` (the deepest ancestor with a
    /// `.cockpit/` layer), scaffolded at `cwd` when none exists, so the editor
    /// writes the project layer. When `glob` is non-empty it is quick-added
    /// (and persisted) before the editor opens.
    pub fn open_gitignore_allow(cwd: &std::path::Path, glob: Option<&str>) -> Self {
        let path = nearest_project_config_path(cwd);
        let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
        match glob {
            Some(g) if !g.trim().is_empty() => s.quick_add_gitignore_allow(g),
            _ => s.enter_gitignore_allow(),
        }
        Dialog::Settings(Box::new(s))
    }

    /// True when the first discovered config layer has zero provider files
    /// configured. Used by the TUI's
    /// first-run flow to auto-route into the Add wizard after the
    /// daemon prompt resolves.
    pub fn has_no_providers(cwd: &std::path::Path) -> bool {
        let dirs = discover_config_dirs(cwd);
        let Some(dir) = dirs.first() else {
            return true;
        };
        let path = dir.path.join("config.json");
        match ConfigDoc::load(&path) {
            Ok(doc) => doc.providers().providers.is_empty(),
            Err(_) => true,
        }
    }

    /// Open the Add-Provider wizard directly, skipping the Providers
    /// list. Used when the user has no providers configured at TUI
    /// launch.
    pub fn open_providers_add(cwd: &std::path::Path) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join("config.json");
            let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
            s.page = Page::Providers(ProvidersPage::Add(AddState::new()));
            d = Dialog::Settings(Box::new(s));
        }
        d
    }

    /// Re-open the picker after scaffolding a new scoped config, so the
    /// fresh row shows up and lands as the cursor target.
    fn reopen_picker(cwd: &std::path::Path, status: Option<String>) -> Self {
        let dirs = discover_config_dirs(cwd);
        if dirs.is_empty() {
            Dialog::CreateConfig {
                choices: creatable_config_dirs(),
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status,
            }
        } else {
            Dialog::PickConfig {
                dirs,
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status,
            }
        }
    }

    /// Drain the UI page's pending `mouse` toggle, if any. Returns
    /// `Some(new_value)` exactly once per user toggle so the App can
    /// push/pop crossterm's `EnableMouseCapture` to match. None when
    /// the dialog isn't on the UI page or the user hasn't touched the
    /// setting since the last drain.
    pub fn take_pending_mouse_capture(&mut self) -> Option<bool> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        let Page::Category(p) = &mut s.page else {
            return None;
        };
        p.pending_mouse_capture.take()
    }

    /// Drain a pending external-editor (`$EDITOR`) request from the Agents
    /// page, if any. Returns the on-disk agent file the event loop should
    /// open `$EDITOR` against; the loop owns the terminal suspend/restore
    /// (the page handler can't), then calls [`Self::finish_agent_edit`] to
    /// re-read + re-parse the file. `None` unless the user just chose to
    /// edit an agent and `$EDITOR` is set.
    pub fn take_pending_agent_edit(&mut self) -> Option<PathBuf> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        let Page::Agents(p) = &mut s.page else {
            return None;
        };
        p.pending_external_edit.take()
    }

    /// Apply the result of an external-editor session the event loop ran on
    /// behalf of the Agents page: re-read the file from disk, re-parse it,
    /// surface any parse error inline, and refresh the row markers/model.
    /// `editor_error` carries an external-process failure (non-zero exit /
    /// missing binary) so the page reports it and leaves the file as-is.
    pub fn finish_agent_edit(&mut self, editor_error: Option<String>) {
        let Dialog::Settings(s) = self else {
            return;
        };
        let cwd = s.agents_cwd();
        if let Page::Agents(p) = &mut s.page {
            p.finish_external_edit(&cwd, editor_error);
        }
    }

    /// Called by the event loop each tick so async fetches can apply
    /// their results.
    pub fn tick(&mut self) {
        if let Dialog::Settings(s) = self {
            s.tick();
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self {
            Dialog::None => false,
            Dialog::PickConfig {
                dirs,
                cursor,
                cwd,
                status,
            } => {
                // `a` opens the "add a scoped config" sub-dialog.
                // Anything else clears the transient status and falls
                // through to the standard list nav.
                if matches!(key.code, KeyCode::Char('a')) {
                    *self = Dialog::CreateScopedConfig {
                        choices: cwd_scoped_creatable_dirs(cwd),
                        cursor: 0,
                        cwd: cwd.clone(),
                    };
                    return false;
                }
                *status = None;
                match list_key_action(key, cursor, dirs.len()) {
                    ListAction::Stay => false,
                    ListAction::Close => true,
                    ListAction::Select(idx) => {
                        let chosen = dirs[idx].path.join("config.json");
                        let cwd = cwd.clone();
                        *self = Dialog::Settings(Box::new(SettingsDialog::open_from_picker(
                            chosen, cwd,
                        )));
                        false
                    }
                }
            }
            Dialog::CreateConfig {
                choices,
                cursor,
                cwd,
                status,
            } => match list_key_action(key, cursor, choices.len()) {
                ListAction::Stay => {
                    *status = None;
                    false
                }
                ListAction::Close => true,
                ListAction::Select(idx) => match scaffold_config_dir(&choices[idx].path) {
                    Ok(config_path) => {
                        let cwd = cwd.clone();
                        *self = Dialog::Settings(Box::new(SettingsDialog::open_from_picker(
                            config_path,
                            cwd,
                        )));
                        false
                    }
                    Err(e) => {
                        *status = Some(scaffold_error(&choices[idx].path, &e));
                        false
                    }
                },
            },
            Dialog::CreateScopedConfig {
                choices,
                cursor,
                cwd,
            } => match list_key_action(key, cursor, choices.len()) {
                // Cancel → back to the picker.
                ListAction::Close => {
                    *self = Dialog::reopen_picker(cwd, None);
                    false
                }
                ListAction::Stay => false,
                ListAction::Select(idx) => {
                    let target = &choices[idx];
                    match scaffold_config_dir(&target.path) {
                        Ok(config_path) => {
                            let cwd = cwd.clone();
                            *self = Dialog::Settings(Box::new(SettingsDialog::open_from_picker(
                                config_path,
                                cwd,
                            )));
                        }
                        Err(e) => {
                            *self =
                                Dialog::reopen_picker(cwd, Some(scaffold_error(&target.path, &e)));
                        }
                    }
                    false
                }
            },
            Dialog::Settings(s) => {
                let close = s.handle_key(key);
                if close
                    && s.back_to_picker
                    && let Some(cwd) = s.picker_cwd.clone()
                {
                    *self = Dialog::reopen_picker(&cwd, None);
                    return false;
                }
                close
            }
        }
    }

    /// Insert pasted text into the focused text field. Only the settings
    /// pages own text fields; the config pickers are pure list nav, so a
    /// paste there is dropped.
    pub fn paste(&mut self, text: &str) {
        if let Dialog::Settings(s) = self {
            s.paste(text);
        }
    }

    pub fn take_daemon_request(&mut self) -> Option<Request> {
        match self {
            Dialog::Settings(s) => s.pending_daemon_request.take(),
            _ => None,
        }
    }

    pub fn take_oauth_action(&mut self) -> Option<OAuthActionRequest> {
        match self {
            Dialog::Settings(s) => s.pending_oauth_action.take(),
            _ => None,
        }
    }

    pub fn oauth_wants_mouse_off(&self) -> bool {
        match self {
            Dialog::Settings(s) => s.oauth_wants_mouse_off(),
            _ => false,
        }
    }

    pub fn apply_oauth_codex_begin(
        &mut self,
        result: Result<crate::auth::codex_oauth::DeviceLogin, String>,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_codex_begin(result);
        }
    }

    pub fn apply_oauth_codex_complete(&mut self, result: Result<bool, String>) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_codex_complete(result);
        }
    }

    pub fn apply_oauth_grok_begin(
        &mut self,
        result: Result<(crate::auth::xai_oauth::ManualLogin, bool, Option<String>), String>,
    ) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_grok_begin(result);
        }
    }

    pub fn apply_oauth_grok_complete(&mut self, result: Result<bool, String>) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_grok_complete(result);
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect) {
        match self {
            Dialog::None => {}
            Dialog::PickConfig {
                dirs,
                cursor,
                status,
                ..
            } => render_picker(
                frame,
                area,
                "pick a config to edit",
                dirs,
                *cursor,
                status.as_deref(),
                "↑/↓  enter: select  a: add scoped  esc: close",
            ),
            Dialog::CreateConfig {
                choices,
                cursor,
                status,
                ..
            } => render_picker(
                frame,
                area,
                "no config found, create one?",
                choices,
                *cursor,
                status.as_deref(),
                "↑/↓  enter: select  esc: cancel",
            ),
            Dialog::CreateScopedConfig {
                choices, cursor, ..
            } => render_picker(
                frame,
                area,
                "where should the new config live?",
                choices,
                *cursor,
                None,
                "↑/↓  enter: select  esc: back to picker",
            ),
            Dialog::Settings(s) => s.render(frame, area),
        }
    }
}

// ── SettingsDialog ───────────────────────────────────────────────────────

impl SettingsDialog {
    pub fn open(config_path: PathBuf) -> Self {
        let config = ConfigDoc::load(&config_path)
            .map(|d| d.providers())
            .unwrap_or_default();
        // The cockpit-only keys live in the same `config.json` as the
        // layer-wide provider metadata (GOALS §2a).
        let extended_path = config_path.clone();
        let (mut extended, extended_warnings) = ExtendedConfigDoc::load(&extended_path)
            .map(|d| d.config_with_warnings())
            .unwrap_or_default();
        // Fresh install (no config at this location yet): seed the
        // skills scan-dir list with the defaults so they show as ordinary
        // editable rows. Materialization-only — an existing config whose
        // `scan_dirs` is absent/empty stays empty (clean break).
        if !extended_path.exists() {
            extended.skills.scan_dirs = crate::config::extended::SEEDED_SCAN_DIRS
                .iter()
                .map(|s| s.to_string())
                .collect();
        }
        Self {
            config_path,
            extended_path,
            page: Page::Root { cursor: 0 },
            config,
            extended,
            extended_warnings,
            last_root_cursor: 0,
            picker_cwd: None,
            active_project_root: None,
            back_to_picker: false,
            command_installed: |cmd| crate::harness::preflight::which_on_path(cmd).is_some(),
            pending_daemon_request: None,
            pending_oauth_action: None,
        }
    }

    /// Same as [`Self::open`] but records the cwd of the picker that
    /// opened this dialog so Root's back keybind can reopen it.
    pub fn open_from_picker(config_path: PathBuf, cwd: PathBuf) -> Self {
        let mut s = Self::open(config_path);
        s.picker_cwd = Some(cwd.clone());
        s.active_project_root = Some(cwd);
        s
    }

    /// Reload extended-config from disk. Used after saving so the
    /// cached view stays in sync.
    fn reload_extended(&mut self) {
        if let Ok(doc) = ExtendedConfigDoc::load(&self.extended_path) {
            let (extended, warnings) = doc.config_with_warnings();
            self.extended = extended;
            self.extended_warnings = warnings;
        }
    }

    /// Persist the cached extended-config to disk.
    pub(super) fn save_extended(&mut self) -> Result<(), String> {
        let mut doc = ExtendedConfigDoc::load(&self.extended_path).map_err(|e| e.to_string())?;
        doc.write(&self.extended).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn enter_providers(&mut self) {
        self.page = Page::Providers(ProvidersPage::List {
            cursor: providers::initial_list_cursor(&self.config),
            status: None,
            delete_pending: false,
        });
    }

    /// Enter a reorganized category page, reloading the cached
    /// extended-config first so the rows reflect on-disk state.
    fn enter_category(&mut self, category: Category) {
        self.reload_extended();
        self.page = Page::Category(Box::new(CategoryPage::new(category)));
    }

    /// Navigate to the active model's model-settings sub-dialog
    /// (implementation note). Falls back to the providers
    /// list with an inline status when no model is active or the active
    /// (provider, model) can't be found.
    fn enter_model_settings(&mut self) {
        self.page = Page::Providers(providers::active_model_settings_page(&self.config));
    }

    fn reload_config(&mut self) {
        if let Ok(doc) = ConfigDoc::load(&self.config_path) {
            self.config = doc.providers();
        }
    }

    fn save_config(&mut self) -> Result<(), String> {
        let mut doc = ConfigDoc::load(&self.config_path).map_err(|e| e.to_string())?;
        doc.write(&self.config).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn tick(&mut self) {
        // Drain finished fetches into config. The Headers sub-page
        // owns its parent's EditState (via Box) — if a /models fetch
        // was started on Edit and the user navigated into Headers
        // while it was in flight, the handle still needs to be
        // drained so the result lands when they come back.
        let pending = match &mut self.page {
            Page::Providers(ProvidersPage::Add(s)) => s.fetch.clone(),
            Page::Providers(ProvidersPage::Edit(s)) => s.fetch.clone(),
            Page::Providers(ProvidersPage::Headers { parent, .. }) => parent.fetch.clone(),
            Page::Providers(ProvidersPage::Models { parent, .. }) => parent.fetch.clone(),
            Page::Providers(ProvidersPage::ModelSettings { parent, .. }) => parent.fetch.clone(),
            Page::Providers(ProvidersPage::ProviderSettings { parent, .. }) => parent.fetch.clone(),
            _ => None,
        };
        if let Some(handle) = pending
            && let Some(result) = handle.take()
        {
            self.apply_fetch_result(&handle.provider_id, result);
        }

        // Drain the all-providers refetch: move any handle that has
        // finished out of `in_flight`, persist its models into config,
        // and record its outcome for the per-provider summary. When the
        // last one lands, compute the aggregated unlisted-models set so
        // the Keep/Remove prompt can render.
        self.drain_fetch_all();
        match &mut self.page {
            Page::Providers(ProvidersPage::GrokOAuthSetup { state, .. })
            | Page::Providers(ProvidersPage::Add(AddState {
                step: AddStep::GrokOAuthAuth(state),
                ..
            })) if state.pending => {
                state.spinner_tick = state.spinner_tick.wrapping_add(1);
            }
            Page::Providers(ProvidersPage::CodexOAuthSetup { state, .. })
            | Page::Providers(ProvidersPage::Add(AddState {
                step: AddStep::CodexOAuthAuth(state),
                ..
            })) if state.polling => {
                state.spinner_tick = state.spinner_tick.wrapping_add(1);
            }
            _ => {}
        }
    }

    fn oauth_wants_mouse_off(&self) -> bool {
        match &self.page {
            Page::Providers(ProvidersPage::GrokOAuthSetup { state, .. })
            | Page::Providers(ProvidersPage::Add(AddState {
                step: AddStep::GrokOAuthAuth(state),
                ..
            })) => state.pending && state.authorize_url.is_some(),
            Page::Providers(ProvidersPage::CodexOAuthSetup { state, .. })
            | Page::Providers(ProvidersPage::Add(AddState {
                step: AddStep::CodexOAuthAuth(state),
                ..
            })) => state.polling && state.pending.is_some(),
            _ => false,
        }
    }

    fn apply_oauth_codex_begin(
        &mut self,
        result: Result<crate::auth::codex_oauth::DeviceLogin, String>,
    ) {
        let Some(state) = self.codex_oauth_state_mut() else {
            return;
        };
        state.polling = false;
        match result {
            Ok(login) => {
                state.status = Some(Ok(format!(
                    "Open {} in any browser and enter code {}. Press Enter to poll for approval; c copies the URL.",
                    login.verification_uri, login.user_code
                )));
                state.pending = Some(login);
            }
            Err(e) => state.status = Some(Err(e)),
        }
    }

    fn apply_oauth_codex_complete(&mut self, result: Result<bool, String>) {
        let Some(state) = self.codex_oauth_state_mut() else {
            return;
        };
        state.polling = false;
        state.logged_in =
            result.as_ref().copied().unwrap_or(false) || crate::auth::codex_oauth::is_logged_in();
        state.status = Some(result.map(|_| "Codex OAuth login complete".to_string()));
        if state.logged_in {
            state.pending = None;
        }
    }

    fn apply_oauth_grok_begin(
        &mut self,
        result: Result<(crate::auth::xai_oauth::ManualLogin, bool, Option<String>), String>,
    ) {
        let Some(state) = self.grok_oauth_state_mut() else {
            return;
        };
        match result {
            Ok((login, auto_attempted, browser_error)) => {
                state.authorize_url = Some(login.authorize_url.clone());
                state.manual_login = Some(login);
                state.manual_mode = true;
                state.pending = auto_attempted && browser_error.is_none();
                state.status = Some(Ok(match browser_error {
                    Some(e) => format!("Could not open browser ({e}); paste callback URL or code."),
                    None if auto_attempted => {
                        "Opened browser; waiting for callback. Paste callback/code here if needed."
                            .to_string()
                    }
                    None => {
                        "SSH detected; open the URL manually and paste callback/code.".to_string()
                    }
                }));
            }
            Err(e) => {
                state.pending = false;
                state.status = Some(Err(e));
            }
        }
    }

    fn apply_oauth_grok_complete(&mut self, result: Result<bool, String>) {
        let Some(state) = self.grok_oauth_state_mut() else {
            return;
        };
        state.pending = false;
        state.logged_in =
            result.as_ref().copied().unwrap_or(false) || crate::auth::xai_oauth::is_logged_in();
        state.status = Some(result.map(|_| "xAI OAuth login complete".to_string()));
        if state.logged_in {
            state.manual_mode = false;
            state.manual_login = None;
            state.manual_input.set("");
        }
    }

    fn grok_oauth_state_mut(&mut self) -> Option<&mut providers::GrokOAuthSetupState> {
        match &mut self.page {
            Page::Providers(ProvidersPage::GrokOAuthSetup { state, .. }) => Some(state),
            Page::Providers(ProvidersPage::Add(AddState {
                step: AddStep::GrokOAuthAuth(state),
                ..
            })) => Some(state),
            _ => None,
        }
    }

    fn codex_oauth_state_mut(&mut self) -> Option<&mut providers::CodexOAuthSetupState> {
        match &mut self.page {
            Page::Providers(ProvidersPage::CodexOAuthSetup { state, .. }) => Some(state),
            Page::Providers(ProvidersPage::Add(AddState {
                step: AddStep::CodexOAuthAuth(state),
                ..
            })) => Some(state),
            _ => None,
        }
    }

    /// True while a header or model add/edit popup or its browsing list
    /// is on screen — those editors own `Tab`/`Shift+Tab` themselves (the
    /// popup switches between fields; the browse list treats Tab as ↓), so
    /// the field-nav rewrite in [`Self::handle_key`] must leave them alone.
    fn in_header_editor(&self) -> bool {
        match &self.page {
            Page::Providers(ProvidersPage::Headers { .. }) => true,
            Page::Providers(ProvidersPage::Models { .. }) => true,
            Page::Providers(ProvidersPage::Add(s)) => matches!(s.step, AddStep::EditHeaders),
            _ => false,
        }
    }

    /// True while a category page is inline-editing the packages-dir field —
    /// there Tab accepts a directory suggestion, so the field-nav Tab→Down
    /// rewrite in [`Self::handle_key`] must leave Tab alone.
    fn in_pkg_dir_autosuggest(&self) -> bool {
        matches!(&self.page, Page::Category(p) if p.is_editing_packages_dir())
    }

    /// Insert pasted text into the page's focused text field, mirroring the
    /// focus logic of each page's key handler so the paste lands in the same
    /// buffer a typed char would. Pages with no open field (or no field at
    /// all) drop the paste.
    fn paste(&mut self, text: &str) {
        // Computed up front (reads `config_path`/`picker_cwd`) so the
        // packages-dir autosuggest refresh below doesn't conflict with the
        // `&mut self.page` borrow held across the match.
        let cwd = self.agents_cwd();
        match &mut self.page {
            Page::Root { .. } => {}
            Page::Providers(p) => {
                if let Some(field) = p.active_text_field() {
                    field.paste(text);
                }
            }
            Page::Agents(p) => {
                if let Some(editor) = p.editing.as_mut() {
                    editor.paste(text);
                }
            }
            Page::Tools(p) => {
                if p.editing.is_some() {
                    p.buf.paste(text);
                }
            }
            Page::Harnesses(p) => match p {
                harnesses_page::HarnessesPage::List(s) => {
                    if let Some(buf) = s.adding.as_mut() {
                        buf.paste(text);
                    }
                }
                harnesses_page::HarnessesPage::Edit(s) => {
                    if let Some(buf) = s.editing.as_mut() {
                        buf.paste(text);
                    }
                }
            },
            Page::Category(p) => {
                // Utility-model picker overlay owns input while open; else the
                // inline field, refreshing the packages-dir autosuggest as a
                // typed char would.
                if let Some(picker) = p.utility_picker.as_mut() {
                    if let Some(field) = picker.active_text_field() {
                        field.paste(text);
                    }
                } else if let Some(id) = p.editing {
                    p.buf.paste(text);
                    if id == category::SettingId::PackagesDir {
                        p.refresh_pkg_suggest(&cwd);
                    }
                }
            }
            Page::Instructions(p) => {
                if let Some(g) = p.grabbed.as_mut() {
                    g.buf.paste(text);
                }
            }
            Page::RedactPatterns(p) => {
                if let Some(g) = p.grabbed.as_mut() {
                    g.buf.paste(text);
                }
            }
            Page::StringList(p) => {
                if let Some(g) = p.grabbed.as_mut() {
                    g.buf.paste(text);
                }
            }
            Page::Skills(p) => {
                if let Some(g) = p.grabbed.as_mut() {
                    g.buf.paste(text);
                }
            }
            Page::Mcp(p) => {
                if let mcp_page::McpPage::Add(s) = p {
                    mcp_page::paste_into_add_state(s, text);
                }
            }
            Page::Lsp(p) => {
                if p.editing.is_some() {
                    p.buf.paste(text);
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Tab / Shift+Tab move between fields like ↓/↑ across settings
        // screens. The header editor owns Tab itself (the popup switches
        // name↔value; its browse list treats Tab as ↓), and the packages-dir
        // autosuggest owns Tab (accept a suggestion), so skip the rewrite
        // while either is on screen.
        let key = if self.in_header_editor() || self.in_pkg_dir_autosuggest() {
            key
        } else {
            match key.code {
                KeyCode::Tab => KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                KeyCode::BackTab => KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
                _ => key,
            }
        };
        // Esc semantics differ per page: in deep pages it goes back one
        // level; only at root does it close.
        let cursor = match &self.page {
            Page::Root { cursor } => Some(*cursor),
            _ => None,
        };
        if let Some(cursor) = cursor {
            return self.handle_root_key(key, cursor);
        }
        match &self.page {
            Page::Agents(_) => self.handle_agents_key(key),
            Page::Tools(_) => self.handle_tools_key(key),
            Page::Harnesses(_) => self.handle_harnesses_key(key),
            Page::Category(_) => self.handle_category_key(key),
            Page::Instructions(_) => self.handle_instructions_key(key),
            Page::RedactPatterns(_) => self.handle_redact_patterns_key(key),
            Page::StringList(_) => self.handle_string_list_key(key),
            Page::Skills(_) => self.handle_skills_key(key),
            Page::Mcp(_) => self.handle_mcp_key(key),
            Page::Lsp(_) => self.handle_lsp_key(key),
            Page::Providers(_) => self.handle_providers_key(key),
            Page::Root { .. } => unreachable!("handled above"),
        }
    }

    fn handle_root_key(&mut self, key: KeyEvent, mut cursor: usize) -> bool {
        let children = root_nodes();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace
                if self.picker_cwd.is_some() =>
            {
                self.back_to_picker = true;
                return true;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                cursor = crate::tui::nav::wrap_prev(cursor, children.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                cursor = crate::tui::nav::wrap_next(cursor, children.len());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let chosen = children.get(cursor).map(|n| n.title).unwrap_or("");
                self.last_root_cursor = cursor;
                match chosen {
                    PROVIDERS_TITLE => self.enter_providers(),
                    "Agents" => {
                        self.page = Page::Agents(AgentsPage::new(&self.agents_cwd()));
                    }
                    "Interface" => self.enter_category(Category::Interface),
                    "Behavior" => self.enter_category(Category::Behavior),
                    "Privacy & Safety" => self.enter_category(Category::Privacy),
                    "Translation" => self.enter_category(Category::Translation),
                    "Profile" => self.enter_category(Category::Profile),
                    "Tools" => {
                        self.reload_extended();
                        self.page = Page::Tools(ToolsPage {
                            cursor: 0,
                            setup: None,
                            editing: None,
                            buf: TextField::default(),
                            edit_target: None,
                            status: None,
                            reset: ResetButton::default(),
                        });
                    }
                    "Harnesses" => {
                        self.reload_extended();
                        let status = self.extended_warnings.first().cloned();
                        self.page = Page::Harnesses(harnesses_page::HarnessesPage::List(
                            harnesses_page::ListState {
                                cursor: 0,
                                status,
                                delete_pending: false,
                                reset: ResetButton::default(),
                                adding: None,
                            },
                        ));
                    }
                    "Skills" => {
                        self.reload_extended();
                        self.page = Page::Skills(skills_page::SkillsPage {
                            cursor: 0,
                            grabbed: None,
                            status: None,
                            reset: ResetButton::default(),
                        });
                    }
                    "MCP" => {
                        self.enter_mcp();
                    }
                    "LSP" => {
                        self.reload_extended();
                        self.page = Page::Lsp(LspPage {
                            cursor: 0,
                            editing: None,
                            buf: TextField::default(),
                            status: None,
                            reset: ResetButton::default(),
                        });
                    }
                    _ => {}
                }
                return false;
            }
            _ => {}
        }
        self.page = Page::Root { cursor };
        false
    }

    fn handle_lsp_key(&mut self, key: KeyEvent) -> bool {
        let Page::Lsp(mut p) = std::mem::replace(&mut self.page, Page::Root { cursor: 0 }) else {
            unreachable!("not on LSP page");
        };
        let row_count = LSP_SERVER_ROW_START
            + self
                .project_context()
                .project_root()
                .map(|cwd| crate::daemon::lsp::builtin_server_views(cwd, &self.extended).len())
                .unwrap_or(1);
        if let Some(edit) = p.editing {
            match key.code {
                KeyCode::Esc => {
                    p.editing = None;
                    p.buf = TextField::default();
                }
                KeyCode::Enter => {
                    let raw = p.buf.text().trim();
                    match raw.parse::<u64>() {
                        Ok(v) => {
                            match edit {
                                LspEdit::OtherFilesLimit => {
                                    self.extended.lsp.diagnostics.other_files_limit = v as usize
                                }
                                LspEdit::PerFileLimit => {
                                    self.extended.lsp.diagnostics.per_file_limit = v as usize
                                }
                                LspEdit::DebounceMs => {
                                    self.extended.lsp.diagnostics.debounce_ms = v
                                }
                                LspEdit::DocumentTimeoutMs => {
                                    self.extended.lsp.diagnostics.document_timeout_ms = v
                                }
                                LspEdit::WorkspaceTimeoutMs => {
                                    self.extended.lsp.diagnostics.workspace_timeout_ms = v
                                }
                            }
                            p.status = save_status(self.save_extended());
                            p.editing = None;
                            p.buf = TextField::default();
                        }
                        Err(_) => p.status = Some("enter a non-negative integer".into()),
                    }
                }
                _ => {
                    let _ = p.buf.handle_key(key);
                }
            }
            self.page = Page::Lsp(p);
            return false;
        }

        match key.code {
            KeyCode::Esc => {
                p.reset.disarm();
                return true;
            }
            KeyCode::Char('h') | KeyCode::Left => {
                p.reset.disarm();
                self.page = Page::Root {
                    cursor: self.last_root_cursor,
                };
                return false;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, row_count);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_next(p.cursor, row_count);
            }
            KeyCode::Char('r') => {
                self.activate_lsp_reset(&mut p);
            }
            KeyCode::Char('i') if p.cursor >= LSP_SERVER_ROW_START => {
                p.reset.disarm();
                self.queue_lsp_action(
                    p.cursor - LSP_SERVER_ROW_START,
                    LspControlAction::Install,
                    &mut p,
                );
            }
            KeyCode::Char('u') if p.cursor >= LSP_SERVER_ROW_START => {
                p.reset.disarm();
                self.queue_lsp_action(
                    p.cursor - LSP_SERVER_ROW_START,
                    LspControlAction::Uninstall,
                    &mut p,
                );
            }
            KeyCode::Char('R') if p.cursor >= LSP_SERVER_ROW_START => {
                p.reset.disarm();
                self.queue_lsp_action(
                    p.cursor - LSP_SERVER_ROW_START,
                    LspControlAction::Restart,
                    &mut p,
                );
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                match lsp_row_for_cursor(p.cursor) {
                    LspRow::Enabled => {
                        p.reset.disarm();
                        self.extended.lsp.enabled = !self.extended.lsp.enabled;
                        p.status = save_status(self.save_extended());
                    }
                    LspRow::AutoInstall => {
                        p.reset.disarm();
                        self.extended.lsp.auto_install = self.extended.lsp.auto_install.cycled();
                        p.status = save_status(self.save_extended());
                    }
                    LspRow::Diagnostics => {
                        p.reset.disarm();
                        self.extended.lsp.diagnostics.enabled =
                            !self.extended.lsp.diagnostics.enabled;
                        p.status = save_status(self.save_extended());
                    }
                    LspRow::OtherFilesLimit => {
                        p.reset.disarm();
                        start_lsp_edit(
                            &mut p,
                            LspEdit::OtherFilesLimit,
                            self.extended.lsp.diagnostics.other_files_limit,
                        );
                    }
                    LspRow::PerFileLimit => {
                        p.reset.disarm();
                        start_lsp_edit(
                            &mut p,
                            LspEdit::PerFileLimit,
                            self.extended.lsp.diagnostics.per_file_limit,
                        );
                    }
                    LspRow::DebounceMs => {
                        p.reset.disarm();
                        start_lsp_edit(
                            &mut p,
                            LspEdit::DebounceMs,
                            self.extended.lsp.diagnostics.debounce_ms,
                        );
                    }
                    LspRow::DocumentTimeoutMs => {
                        p.reset.disarm();
                        start_lsp_edit(
                            &mut p,
                            LspEdit::DocumentTimeoutMs,
                            self.extended.lsp.diagnostics.document_timeout_ms,
                        );
                    }
                    LspRow::WorkspaceTimeoutMs => {
                        p.reset.disarm();
                        start_lsp_edit(
                            &mut p,
                            LspEdit::WorkspaceTimeoutMs,
                            self.extended.lsp.diagnostics.workspace_timeout_ms,
                        );
                    }
                    LspRow::Reset => {
                        self.activate_lsp_reset(&mut p);
                    }
                    LspRow::Server(idx) => {
                        p.reset.disarm();
                        self.queue_lsp_action(idx, LspControlAction::Check, &mut p);
                    }
                }
            }
            _ => {}
        }
        self.page = Page::Lsp(p);
        false
    }

    fn activate_lsp_reset(&mut self, p: &mut LspPage) {
        match p.reset.activate() {
            ResetOutcome::Armed => {
                p.status = None;
            }
            ResetOutcome::Apply => {
                self.extended.lsp = crate::config::extended::LspConfig::default();
                p.status = save_status(self.save_extended());
            }
        }
    }

    fn queue_lsp_action(&mut self, server_idx: usize, action: LspControlAction, p: &mut LspPage) {
        let Some(cwd) = self.project_context().project_root().cloned() else {
            p.status = Some(PROJECT_CONTEXT_UNAVAILABLE.to_string());
            return;
        };
        let Some(server) = crate::daemon::lsp::builtin_server_views(&cwd, &self.extended)
            .into_iter()
            .nth(server_idx)
        else {
            return;
        };
        self.pending_daemon_request = Some(Request::LspControl {
            project_root: cwd.display().to_string(),
            server_id: server.id.clone(),
            action,
        });
        p.status = Some(format!(
            "requested {:?} for {}; result will appear as a daemon notice",
            action, server.id
        ));
    }

    fn render_lsp_page(&self, frame: &mut Frame, area: Rect, p: &LspPage) {
        let (rows, selected_line) = lsp_rows(self, p);
        let rows = window_lines(&rows, Some(selected_line), area.height);
        frame.render_widget(Paragraph::new(rows).wrap(Wrap { trim: false }), area);
    }

    // ── Rendering ────────────────────────────────────────────────────────

    fn render(&self, frame: &mut Frame, area: Rect) {
        let title = self.title();
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Settings — {title} "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);

        match &self.page {
            Page::Root { cursor } => render_root(frame, layout[0], *cursor),
            Page::Agents(p) => self.render_agents_page(frame, layout[0], p),
            Page::Tools(p) => self.render_tools_page(frame, layout[0], p),
            Page::Harnesses(p) => self.render_harnesses_page(frame, layout[0], p),
            Page::Category(p) => self.render_category_page(frame, layout[0], p),
            Page::Instructions(p) => self.render_instructions_page(frame, layout[0], p),
            Page::RedactPatterns(p) => self.render_redact_patterns_page(frame, layout[0], p),
            Page::StringList(p) => self.render_string_list_page(frame, layout[0], p),
            Page::Skills(p) => self.render_skills_page(frame, layout[0], p),
            Page::Mcp(p) => self.render_mcp_page(frame, layout[0], p),
            Page::Lsp(p) => self.render_lsp_page(frame, layout[0], p),
            Page::Providers(p) => self.render_providers_page(frame, layout[0], p),
        }
        frame.render_widget(help_line(self.help_text()), layout[1]);
    }

    fn title(&self) -> String {
        let crumbs = match &self.page {
            Page::Root { .. } => String::new(),
            Page::Agents(_) => " › Agents".into(),
            Page::Tools(_) => " › Tools".into(),
            Page::Harnesses(HarnessesPage::List(_)) => " › Harnesses".into(),
            Page::Harnesses(HarnessesPage::Edit(s)) => format!(" › Harnesses › {}", s.name),
            Page::Category(p) => format!(" › {}", p.category.crumb()),
            Page::Skills(_) => " › Skills".into(),
            Page::Mcp(McpPage::List(_)) => " › MCP".into(),
            Page::Mcp(McpPage::Add(_)) => " › MCP › Add".into(),
            Page::Lsp(_) => " › LSP".into(),
            Page::Instructions(_) => " › Behavior › Instructions Files".into(),
            Page::RedactPatterns(_) => " › Privacy & Safety › Environment File Patterns".into(),
            Page::StringList(p) => format!(" › {}", p.crumb()),
            Page::Providers(ProvidersPage::List { .. }) => format!(" › {PROVIDERS_TITLE}"),
            Page::Providers(ProvidersPage::Add(_)) => format!(" › {PROVIDERS_TITLE} › Add"),
            Page::Providers(ProvidersPage::Edit(s)) => {
                format!(" › {PROVIDERS_TITLE} › {}", s.provider_id)
            }
            Page::Providers(ProvidersPage::Headers { parent, .. }) => {
                format!(" › {PROVIDERS_TITLE} › {} › Headers", parent.provider_id)
            }
            Page::Providers(ProvidersPage::Models { parent, .. }) => {
                format!(" › {PROVIDERS_TITLE} › {} › Models", parent.provider_id)
            }
            Page::Providers(ProvidersPage::ModelSettings { parent, .. }) => {
                format!(
                    " › {PROVIDERS_TITLE} › {} › Model Settings",
                    parent.provider_id
                )
            }
            Page::Providers(ProvidersPage::ProviderSettings { parent, .. }) => {
                format!(" › {PROVIDERS_TITLE} › {} › Settings", parent.provider_id)
            }
            Page::Providers(ProvidersPage::FetchAll(_)) => {
                format!(" › {PROVIDERS_TITLE} › refetch all")
            }
            Page::Providers(ProvidersPage::FetchOnePrompt(s)) => {
                format!(" › {PROVIDERS_TITLE} › {} › refetch", s.provider_id)
            }
            Page::Providers(ProvidersPage::FetchFallbackPrompt(s)) => {
                format!(" › {PROVIDERS_TITLE} › {} › fallback", s.provider_id)
            }
            Page::Providers(ProvidersPage::CopilotSetup { .. }) => {
                format!(" › {PROVIDERS_TITLE} › Copilot setup")
            }
            Page::Providers(ProvidersPage::GrokOAuthSetup { .. }) => {
                format!(" › {PROVIDERS_TITLE} › Grok OAuth")
            }
            Page::Providers(ProvidersPage::CodexOAuthSetup { .. }) => {
                format!(" › {PROVIDERS_TITLE} › Codex OAuth")
            }
        };
        format!(
            "{}{}",
            crate::welcome::display_path(&self.config_path),
            crumbs
        )
    }

    fn help_text(&self) -> &'static str {
        match &self.page {
            Page::Root { .. } => {
                if self.picker_cwd.is_some() {
                    "↑/↓/Tab/Shift+Tab  enter: open  h: back to picker  esc/q: close"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: open  esc/q: close"
                }
            }
            Page::Agents(p) => p.help_text(),
            Page::Instructions(p) => {
                if p.grabbed.is_some() {
                    "type to rename  ↑/↓: reorder  enter: drop & save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  enter: grab to rename/reorder  d: delete  esc/h: back  q: close"
                }
            }
            Page::RedactPatterns(p) => {
                if p.grabbed.is_some() {
                    "type to edit pattern  ↑/↓: reorder  enter: drop & save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  enter: grab to edit/reorder  d: delete (x2)  esc/h: back  q: close"
                }
            }
            Page::StringList(p) => {
                if p.grabbed.is_some() {
                    "type to edit  ↑/↓: reorder  enter: drop & save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  enter: grab to edit/reorder  d: delete  esc/h: back  q: close"
                }
            }
            Page::Tools(p) => {
                if p.editing.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit  t: toggle  r: reset  esc/h: back  q: close"
                }
            }
            Page::Harnesses(HarnessesPage::List(s)) => {
                if s.adding.is_some() {
                    "type harness name  enter: create & edit  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit/seed  a: add  d: delete (×2)  esc/h: back  q: close"
                }
            }
            Page::Harnesses(HarnessesPage::Edit(s)) => {
                if s.editing.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit / cycle  esc/h: back to list  q: close"
                }
            }
            Page::Category(p) => {
                if p.utility_picker.is_some() {
                    "↑/↓  enter: select  esc: back / cancel"
                } else if p.is_editing() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit / cycle / drill  esc/h: back  q: close"
                }
            }
            Page::Skills(p) => {
                if p.grabbed.is_some() {
                    "type to edit dir  enter: save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: toggle / edit  a: add dir  d: delete  esc/h: back  q: close"
                }
            }
            Page::Mcp(McpPage::List(_)) => {
                "↑/↓/Tab/Shift+Tab  space: toggle  m: mode  a: authenticate  d: delete (×2)  enter: add  esc/h: back  q: close"
            }
            Page::Mcp(McpPage::Add(_)) => {
                "↑/↓/Tab  enter: cycle / save  type to edit name/endpoint  esc: back"
            }
            Page::Lsp(p) => {
                if p.editing.is_some() {
                    "type value  enter: save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: toggle / edit  r: reset  esc/h: back  q: close"
                }
            }
            Page::Providers(ProvidersPage::List { .. }) => {
                "↑/↓/Tab/Shift+Tab  enter: edit/refetch-all  R: refetch all  m: unlisted policy  a: add  d: delete (×2)  esc/h: back  q: close"
            }
            Page::Providers(ProvidersPage::Add(s)) => match &s.step {
                AddStep::PickTemplate { .. } => "↑/↓  enter: choose  esc: cancel",
                AddStep::EditId | AddStep::EditUrl => "type to edit  enter: next  esc: cancel",
                AddStep::EditHeaders => {
                    if s.headers.is_editing() {
                        "type to edit  Tab: switch field  enter: save  esc: cancel"
                    } else {
                        "↑/↓  a: add  enter: edit  d: delete (x2)  enter on continue: save  esc: back"
                    }
                }
                AddStep::CopilotAuth(_) => "enter: apply  s: skip  esc: cancel",
                AddStep::GrokOAuthAuth(state) => {
                    providers::oauth_setup_help_text(providers::oauth_setup_confirming_logged_in(
                        state.logged_in,
                        state.pending,
                        state.manual_mode,
                    ))
                }
                AddStep::CodexOAuthAuth(state) => {
                    providers::oauth_setup_help_text(providers::oauth_setup_confirming_logged_in(
                        state.logged_in,
                        state.polling,
                        false,
                    ))
                }
                AddStep::Saving | AddStep::Fetching => "(in progress)  esc: cancel",
                AddStep::Done => "enter: back to list",
            },
            Page::Providers(ProvidersPage::Edit(s)) => {
                if s.editing_field.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit  s: save  r: refetch  f: favorite  d: delete (x2)  h: back  q: close"
                }
            }
            Page::Providers(ProvidersPage::Headers { editor, .. }) => {
                if editor.is_editing() {
                    "type to edit  Tab: switch field  enter: save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  enter: edit  d: delete (x2)  h: back  q: close"
                }
            }
            Page::Providers(ProvidersPage::Models { editor, .. }) => {
                if editor.is_editing() {
                    "type to edit  Tab: switch field  enter: save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  r: rename  enter: settings  d: delete (x2)  h: back  q: close"
                }
            }
            Page::Providers(ProvidersPage::ModelSettings { editor, .. }) => {
                if editor.editing.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit/cycle  x: clear to inherit  h: back  q: close"
                }
            }
            Page::Providers(ProvidersPage::ProviderSettings { editor, .. }) => {
                if editor.editing.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit/cycle  h: back  q: close"
                }
            }
            Page::Providers(ProvidersPage::FetchAll(s)) => {
                if s.is_fetching() {
                    "fetching all providers…  esc: cancel"
                } else if s.unlisted.is_empty() {
                    "press any key to return"
                } else {
                    "↑/↓/Tab/Shift+Tab  space: toggle don't-ask  enter: apply  esc: cancel"
                }
            }
            Page::Providers(ProvidersPage::FetchOnePrompt(_)) => {
                "↑/↓/Tab/Shift+Tab  space: toggle don't-ask  enter: apply  esc: cancel"
            }
            Page::Providers(ProvidersPage::FetchFallbackPrompt(_)) => {
                "↑/↓/Tab/Shift+Tab  enter: choose  esc: cancel"
            }
            Page::Providers(ProvidersPage::CopilotSetup { .. }) => "enter: apply  esc: cancel",
            Page::Providers(ProvidersPage::GrokOAuthSetup { .. }) => {
                "↑/↓/Tab/Shift+Tab  enter: choose  esc: back"
            }
            Page::Providers(ProvidersPage::CodexOAuthSetup { .. }) => {
                "↑/↓/Tab/Shift+Tab  enter: choose  esc: back"
            }
        }
    }
}

// ── Helpers / freestanding renderers ─────────────────────────────────────

/// The Providers & Provider Models menu node title (also the dispatch key).
const PROVIDERS_TITLE: &str = "Providers & Provider Models";

/// The reorganized top-level menu (implementation note).
/// The first ten nodes are the locked scheme, in order; MCP/LSP are kept as
/// extra nodes so integration settings stay reachable from the menu.
fn root_nodes() -> [NavNode; 12] {
    [
        NavNode {
            title: PROVIDERS_TITLE,
            description: "Provider setup and request controls: endpoints, headers, model lists, default model, context/cache, fallback, wire API, and per-provider/per-model inline-<think> extraction overrides.",
        },
        NavNode {
            title: "Agents",
            description: "Manage agent definitions, presets, and per-agent overrides.",
        },
        NavNode {
            title: "Interface",
            description: "Display & input only: vim mode, thinking display for stored reasoning, markdown rendering, mouse, diff style, banner, chrome toggles, emojis, and exit scrollback.",
        },
        NavNode {
            title: "Behavior",
            description: "Session & agent behavior: default agent, llm mode, approval mode, plan isolation, prediction, shell compression, the utility model, instructions files, and (Advanced) tuning + plan-execution knobs.",
        },
        NavNode {
            title: "Privacy & Safety",
            description: "Redaction (master switch + every source), the prompt-injection guard, and the remote-config opt-in. Advanced holds the redaction internals.",
        },
        NavNode {
            title: "Translation",
            description: "Round-trip utility-model translation: your language and the model's language.",
        },
        NavNode {
            title: "Tools",
            description: "Custom bash-command tools (webfetch, websearch, …) the agent can invoke.",
        },
        NavNode {
            title: "Harnesses",
            description: "External coding harnesses (claude, codex, opencode, grok, …) Build/Plan can delegate to via harness_invoke.",
        },
        NavNode {
            title: "Skills",
            description: "Skill scan directories and the auto-! command toggle (Claude vs Codex mode).",
        },
        NavNode {
            title: "Profile",
            description: "Your display name, shown on the startup banner.",
        },
        NavNode {
            title: "MCP",
            description: "Model Context Protocol servers: transport, auth, and enabled state.",
        },
        NavNode {
            title: "LSP",
            description: "Language servers, diagnostics surfacing, semantic navigation, and install behavior.",
        },
    ]
}

struct NavNode {
    title: &'static str,
    description: &'static str,
}

pub(super) fn save_status(r: Result<(), String>) -> Option<String> {
    match r {
        Ok(()) => Some("saved".into()),
        Err(e) => Some(format!("save failed: {e}")),
    }
}

/// A bottom-of-list `[label]` save-button row, styled exactly like MCP
/// Add's `[ save ]` row: reverse-video when the cursor is on it, plain
/// otherwise. Shared so every manual-save page renders an identical
/// affordance (MCP Add uses `[ save ]`, Providers uses `[save changes]`).
pub(super) fn save_button_line(label: &str, selected: bool) -> Line<'static> {
    let style = if selected {
        Style::default().add_modifier(Modifier::REVERSED)
    } else {
        Style::default()
    };
    Line::from(Span::styled(label.to_string(), style))
}

fn render_root(frame: &mut Frame, area: Rect, cursor: usize) {
    let children = root_nodes();
    let cursor = cursor.min(children.len().saturating_sub(1));
    let rows = Layout::vertical([
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(3),
    ])
    .split(area);

    let list_lines: Vec<Line<'static>> = children
        .iter()
        .enumerate()
        .map(|(i, node)| {
            let selected = i == cursor;
            Line::from(vec![
                Span::raw(marker(selected)),
                Span::styled(node.title.to_string(), selected_or_field(selected)),
            ])
        })
        .collect();
    let list_lines = window_lines(&list_lines, Some(cursor), rows[0].height);
    frame.render_widget(Paragraph::new(list_lines), rows[0]);

    let desc = children[cursor].description;
    frame.render_widget(
        Paragraph::new(desc.to_string())
            .wrap(Wrap { trim: false })
            .style(muted_style()),
        rows[2],
    );
}

fn start_lsp_edit<T: ToString>(p: &mut LspPage, edit: LspEdit, value: T) {
    p.editing = Some(edit);
    p.buf.set(value.to_string());
}

fn lsp_rows(dialog: &SettingsDialog, p: &LspPage) -> (Vec<Line<'static>>, usize) {
    let d = &dialog.extended.lsp.diagnostics;
    let project_context = dialog.project_context();
    let mut rows = vec![
        lsp_row(
            row_index(LspRow::Enabled),
            p.cursor,
            "enabled",
            on_off(dialog.extended.lsp.enabled),
        ),
        lsp_row(
            row_index(LspRow::AutoInstall),
            p.cursor,
            "auto install",
            dialog.extended.lsp.auto_install.as_str(),
        ),
        lsp_row(
            row_index(LspRow::Diagnostics),
            p.cursor,
            "diagnostics",
            on_off(d.enabled),
        ),
        lsp_edit_row(
            row_index(LspRow::OtherFilesLimit),
            p,
            LspEdit::OtherFilesLimit,
            "other files limit",
            d.other_files_limit,
        ),
        lsp_edit_row(
            row_index(LspRow::PerFileLimit),
            p,
            LspEdit::PerFileLimit,
            "per-file limit",
            d.per_file_limit,
        ),
        lsp_info_row("severity", "error (errors only)"),
        lsp_edit_row(
            row_index(LspRow::DebounceMs),
            p,
            LspEdit::DebounceMs,
            "debounce ms",
            d.debounce_ms,
        ),
        lsp_edit_row(
            row_index(LspRow::DocumentTimeoutMs),
            p,
            LspEdit::DocumentTimeoutMs,
            "document timeout ms",
            d.document_timeout_ms,
        ),
        lsp_edit_row(
            row_index(LspRow::WorkspaceTimeoutMs),
            p,
            LspEdit::WorkspaceTimeoutMs,
            "workspace timeout ms",
            d.workspace_timeout_ms,
        ),
        p.reset
            .render_line(p.cursor == row_index(LspRow::Reset), "restore LSP defaults"),
    ];
    if let Some(cwd) = project_context.project_root() {
        for (idx, server) in crate::daemon::lsp::builtin_server_views(cwd, &dialog.extended)
            .into_iter()
            .enumerate()
        {
            let status = match server.status {
                crate::daemon::lsp::LspServerStatus::Installed => "installed",
                crate::daemon::lsp::LspServerStatus::Missing => "missing",
                crate::daemon::lsp::LspServerStatus::Disabled => "disabled",
                crate::daemon::lsp::LspServerStatus::Broken => "broken",
                crate::daemon::lsp::LspServerStatus::Installing => "installing",
            };
            let command = server.command.join(" ");
            let install = server
                .install_command
                .as_ref()
                .map(|c| c.join(" "))
                .unwrap_or_else(|| "manual".to_string());
            let uninstall = server
                .uninstall_command
                .as_ref()
                .map(|c| c.join(" "))
                .unwrap_or_else(|| "manual".to_string());
            rows.push(lsp_row(
                LSP_SERVER_ROW_START + idx,
                p.cursor,
                &server.id,
                format!(
                    "{status}; enter=check i=install u=uninstall R=restart; cockpit-installed: {}; cmd: {command}; install: {install}; uninstall: {uninstall}; {}",
                    on_off(server.cockpit_installed),
                    server.manual_guidance
                ),
            ));
        }
    } else {
        rows.push(lsp_row(
            LSP_SERVER_ROW_START,
            p.cursor,
            "project actions",
            PROJECT_CONTEXT_UNAVAILABLE,
        ));
    }
    if let Some(status) = &p.status {
        rows.push(Line::from(vec![Span::styled(
            status.clone(),
            muted_style(),
        )]));
    }
    let selected_line = lsp_selected_line_for_cursor(p.cursor).min(rows.len().saturating_sub(1));
    (rows, selected_line)
}

fn row_index(row: LspRow) -> usize {
    LSP_NAV_ROWS
        .iter()
        .position(|r| *r == row)
        .expect("fixed LSP row")
}

fn lsp_row(
    idx: usize,
    cursor: usize,
    label: impl Into<String>,
    value: impl Into<String>,
) -> Line<'static> {
    let selected = idx == cursor;
    Line::from(vec![
        Span::raw(marker(selected)),
        Span::styled(format!("{:<24}", label.into()), selected_or_field(selected)),
        Span::styled(value.into(), muted_style()),
    ])
}

fn lsp_info_row(label: impl Into<String>, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{:<24}", label.into()), muted_style()),
        Span::styled(value.into(), muted_style()),
    ])
}

fn lsp_edit_row<T: ToString>(
    idx: usize,
    p: &LspPage,
    edit: LspEdit,
    label: &str,
    value: T,
) -> Line<'static> {
    if p.editing == Some(edit) {
        let text = p.buf.text();
        let cursor = shell::clamp_to_char_boundary(text, p.buf.cursor());
        let (before, after) = text.split_at(cursor);
        lsp_row(idx, p.cursor, label, format!("{before}▎{after}"))
    } else {
        lsp_row(idx, p.cursor, label, value.to_string())
    }
}

fn lsp_selected_line_for_cursor(cursor: usize) -> usize {
    let severity_insert_at = row_index(LspRow::DebounceMs);
    cursor + usize::from(cursor >= severity_insert_at)
}

fn on_off(v: bool) -> &'static str {
    if v { "on" } else { "off" }
}

const PROJECT_CONTEXT_UNAVAILABLE: &str =
    "unavailable: no active project context for project-scoped actions";

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProjectContext {
    Available(PathBuf),
    Unavailable,
}

impl ProjectContext {
    fn project_root(&self) -> Option<&PathBuf> {
        match self {
            Self::Available(root) => Some(root),
            Self::Unavailable => None,
        }
    }
}

impl SettingsDialog {
    fn project_context(&self) -> ProjectContext {
        project_context_for_config(&self.config_path, self.active_project_root.as_deref())
    }
}

fn project_context_for_config(
    config_path: &Path,
    active_project_root: Option<&Path>,
) -> ProjectContext {
    if let Some(project_root) = project_root_for_project_config(config_path) {
        return ProjectContext::Available(project_root);
    }
    active_project_root
        .map(|p| ProjectContext::Available(p.to_path_buf()))
        .unwrap_or(ProjectContext::Unavailable)
}

fn project_root_for_project_config(config_path: &Path) -> Option<PathBuf> {
    if config_path.file_name()? != crate::config::dirs::CONFIG_FILE {
        return None;
    }
    let config_dir = config_path.parent()?;
    if config_dir.file_name()? != ".cockpit" {
        return None;
    }
    if dirs::home_dir().is_some_and(|home| config_dir == home.join(".cockpit")) {
        return None;
    }
    config_dir.parent().map(PathBuf::from)
}

enum ListAction {
    Stay,
    Close,
    Select(usize),
}

fn list_key_action(key: KeyEvent, cursor: &mut usize, len: usize) -> ListAction {
    match key.code {
        KeyCode::Esc => ListAction::Close,
        KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
            *cursor = crate::tui::nav::wrap_prev(*cursor, len);
            ListAction::Stay
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
            *cursor = crate::tui::nav::wrap_next(*cursor, len);
            ListAction::Stay
        }
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') if *cursor < len => {
            ListAction::Select(*cursor)
        }
        _ => ListAction::Stay,
    }
}

fn render_picker(
    frame: &mut Frame,
    area: Rect,
    subtitle: &str,
    entries: &[ConfigDir],
    cursor: usize,
    status: Option<&str>,
    help: &str,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Settings — {subtitle} "));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);

    let mut lines: Vec<Line<'static>> = Vec::new();
    if entries.is_empty() {
        lines.push(Line::from(Span::styled(
            "  (no candidates)",
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
        )));
    } else {
        let path_w = entries
            .iter()
            .map(|e| crate::welcome::display_path(&e.path).chars().count())
            .max()
            .unwrap_or(0);
        for (i, entry) in entries.iter().enumerate() {
            let marker = if i == cursor { "▸ " } else { "  " };
            let path_str = crate::welcome::display_path(&entry.path);
            let kind_str = kind_label(&entry.kind);
            let mut spans: Vec<Span<'static>> = Vec::new();
            spans.push(Span::raw(marker));
            spans.push(Span::styled(
                pad_right(&path_str, path_w),
                if i == cursor {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                },
            ));
            spans.push(Span::raw("   "));
            spans.push(Span::styled(
                kind_str.to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ));
            lines.push(Line::from(spans));
        }
    }
    if let Some(msg) = status {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            msg.to_string(),
            Style::default().fg(Color::Yellow),
        )));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line(help), layout[1]);
}

fn help_line(text: &str) -> Paragraph<'static> {
    Paragraph::new(Line::from(Span::styled(
        text.to_string(),
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
    )))
}

/// The `config.json` path of the **nearest project** `.cockpit/` layer for
/// `cwd` (the deepest ancestor with a project layer), scaffolding
/// `cwd/.cockpit/config.json` when none exists. Used by `/gitignore-allow` so
/// the read-allowlist always lands in the project layer
/// (implementation note).
fn nearest_project_config_path(cwd: &std::path::Path) -> PathBuf {
    if let Some(dir) = discover_config_dirs(cwd)
        .into_iter()
        .rfind(|d| d.kind == ConfigDirKind::Project)
    {
        return dir.path.join(crate::config::dirs::CONFIG_FILE);
    }
    let project = cwd.join(".cockpit");
    // Best-effort scaffold; if it fails the doc loader still writes on save.
    let _ = scaffold_config_dir(&project);
    project.join(crate::config::dirs::CONFIG_FILE)
}

fn scaffold_error(path: &std::path::Path, error: &dyn std::fmt::Display) -> String {
    format!("failed to create {}: {error}", path.display())
}

fn kind_label(kind: &ConfigDirKind) -> &'static str {
    match kind {
        ConfigDirKind::HomeXdg => "(home / XDG)",
        ConfigDirKind::HomeDot => "(home / dotfile)",
        ConfigDirKind::MachineLocal => "(machine-local, scoped to cwd)",
        ConfigDirKind::Project => "(project — shareable with team)",
    }
}

fn pad_right(s: &str, target: usize) -> String {
    let len = s.chars().count();
    if len >= target {
        s.to_string()
    } else {
        let mut out = s.to_string();
        for _ in len..target {
            out.push(' ');
        }
        out
    }
}

// ── Public API for slash-command-triggered flows ─────────────────────────

/// Start a /fetch-models workflow against the currently-loaded config.
/// The caller wires this in from the slash command handler.
#[allow(dead_code)]
pub fn fetch_all_unlisted_dialog(
    config: &ProvidersConfig,
    finished: Vec<(String, Result<FetchOutcome, String>)>,
    store_default_decision: Option<OnUnlistedModelsFetch>,
) -> (Vec<(String, String)>, bool) {
    // Build the unlisted (config-model not present in remote-list) set.
    let mut unlisted: Vec<(String, String)> = Vec::new();
    for (pid, outcome) in &finished {
        if let Ok(FetchOutcome::Models { models: remote, .. }) = outcome
            && let Some(entry) = config.providers.get(pid)
        {
            for m in &entry.models {
                // Manual entries are intentionally absent from upstream —
                // they're retained by the merge, not "drifted out".
                if !m.manual && !remote.iter().any(|r| r.id == m.id) {
                    unlisted.push((pid.clone(), m.id.clone()));
                }
            }
        }
    }
    let needs_prompt = !unlisted.is_empty()
        && matches!(
            store_default_decision,
            Some(OnUnlistedModelsFetch::Ask) | None
        );
    (unlisted, needs_prompt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ModelEntry, ProviderEntry};
    use providers::{FetchAllState, valid_url};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn entry(id_models: &[&str]) -> ProviderEntry {
        ProviderEntry {
            url: "https://x.example/v1".into(),
            models: id_models
                .iter()
                .map(|id| ModelEntry {
                    id: (*id).into(),
                    name: None,
                    thinking_modes: vec![],
                    inputs: None,
                    context_length: None,
                    favorite: false,
                    manual: false,
                    trust: None,
                    location: None,
                    quality_rank: None,
                    cost_rank: None,
                    subagent_invokable: None,
                    availability: Default::default(),
                    cache: None,
                    shrink: None,
                    context: None,
                    auto_prune: None,
                    timeout: None,
                    backup: None,
                    mode: None,
                    inline_think: None,
                    hint_tool_call_corrections: None,
                    text_embedded_recovery: None,
                    thinking_params: Default::default(),
                    wire_api: Default::default(),
                    extra: Default::default(),
                    capabilities: Default::default(),
                    provider_metadata: Default::default(),
                })
                .collect(),
            ..ProviderEntry::default()
        }
    }

    #[test]
    fn valid_url_accepts_http_and_https() {
        assert!(valid_url("https://x.example"));
        assert!(valid_url("http://localhost:1234"));
        assert!(!valid_url("foo.example"));
        assert!(!valid_url(""));
    }

    #[test]
    fn list_key_action_wraps_at_both_ends() {
        use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
        fn k(code: KeyCode) -> KeyEvent {
            KeyEvent {
                code,
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            }
        }
        let mut cursor = 0usize;
        let len = 3usize;
        // Up from the first row wraps to the last.
        list_key_action(k(KeyCode::Up), &mut cursor, len);
        assert_eq!(cursor, 2);
        // Down from the last row wraps to the first.
        list_key_action(k(KeyCode::Down), &mut cursor, len);
        assert_eq!(cursor, 0);
        // `j`/`k` navigate identically on this non-typing list.
        list_key_action(k(KeyCode::Char('k')), &mut cursor, len);
        assert_eq!(cursor, 2);
        list_key_action(k(KeyCode::Char('j')), &mut cursor, len);
        assert_eq!(cursor, 0);
        // A single-item list stays put.
        let mut one = 0usize;
        list_key_action(k(KeyCode::Up), &mut one, 1);
        assert_eq!(one, 0);
        list_key_action(k(KeyCode::Down), &mut one, 1);
        assert_eq!(one, 0);
    }

    #[test]
    fn fetch_all_unlisted_picks_only_drifted_ids() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers
            .insert("p1".into(), entry(&["m1", "m2", "stale"]));
        let remote_outcome = FetchOutcome::Models {
            models: vec![
                ModelEntry {
                    id: "m1".into(),
                    name: None,
                    thinking_modes: vec![],
                    inputs: None,
                    context_length: None,
                    favorite: false,
                    manual: false,
                    trust: None,
                    location: None,
                    quality_rank: None,
                    cost_rank: None,
                    subagent_invokable: None,
                    availability: Default::default(),
                    cache: None,
                    shrink: None,
                    context: None,
                    auto_prune: None,
                    timeout: None,
                    backup: None,
                    mode: None,
                    inline_think: None,
                    hint_tool_call_corrections: None,
                    text_embedded_recovery: None,
                    thinking_params: Default::default(),
                    wire_api: Default::default(),
                    extra: Default::default(),
                    capabilities: Default::default(),
                    provider_metadata: Default::default(),
                },
                ModelEntry {
                    id: "m2".into(),
                    name: None,
                    thinking_modes: vec![],
                    inputs: None,
                    context_length: None,
                    favorite: false,
                    manual: false,
                    trust: None,
                    location: None,
                    quality_rank: None,
                    cost_rank: None,
                    subagent_invokable: None,
                    availability: Default::default(),
                    cache: None,
                    shrink: None,
                    context: None,
                    auto_prune: None,
                    timeout: None,
                    backup: None,
                    mode: None,
                    inline_think: None,
                    hint_tool_call_corrections: None,
                    text_embedded_recovery: None,
                    thinking_params: Default::default(),
                    wire_api: Default::default(),
                    extra: Default::default(),
                    capabilities: Default::default(),
                    provider_metadata: Default::default(),
                },
            ],
            catalog: crate::config::providers::ProviderModelCatalog::Live,
        };
        let (unlisted, prompt) =
            fetch_all_unlisted_dialog(&cfg, vec![("p1".into(), Ok(remote_outcome))], None);
        assert_eq!(unlisted, vec![("p1".to_string(), "stale".to_string())]);
        assert!(prompt);
    }

    #[test]
    fn fetch_all_unlisted_skips_prompt_when_user_has_chosen() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert("p1".into(), entry(&["stale"]));
        let remote_outcome = FetchOutcome::Models {
            models: vec![],
            catalog: crate::config::providers::ProviderModelCatalog::Live,
        };
        let (_unlisted, prompt) = fetch_all_unlisted_dialog(
            &cfg,
            vec![("p1".into(), Ok(remote_outcome))],
            Some(OnUnlistedModelsFetch::Remove),
        );
        assert!(!prompt);
    }

    // ── Regression: navigation must survive the swap-back ──────────────

    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use tempfile::TempDir;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn fresh_dialog(tmp: &TempDir) -> SettingsDialog {
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        SettingsDialog::open(path)
    }

    fn write_provider_file(config_path: &std::path::Path, provider_id: &str, json: &str) {
        let path =
            crate::config::providers::provider_file_path_for_config(config_path, provider_id)
                .unwrap();
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, json).unwrap();
    }

    fn on_add_page(d: &SettingsDialog) -> bool {
        matches!(&d.page, Page::Providers(ProvidersPage::Add(_)))
    }

    fn on_list_page(d: &SettingsDialog) -> bool {
        matches!(&d.page, Page::Providers(ProvidersPage::List { .. }))
    }

    fn on_root_page(d: &SettingsDialog) -> bool {
        matches!(&d.page, Page::Root { .. })
    }

    #[cfg(unix)]
    #[test]
    fn save_extended_repairs_private_config_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        std::fs::set_permissions(&d.extended_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();

        d.extended.redact.denylist = vec!["secret-value".to_string()];
        d.save_extended().unwrap();

        let file_mode = std::fs::metadata(&d.extended_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let dir_mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn pressing_a_from_providers_list_enters_add_wizard() {
        // Reproduces the "dialog freezes on a" bug — the original
        // implementation swapped the page out, then the inner handler
        // wrote `self.page = Add(...)` into the placeholder slot, and
        // the outer's unconditional swap-back discarded that write.
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_providers();
        assert!(on_list_page(&d));
        let close = d.handle_key(press(KeyCode::Char('a')));
        assert!(!close);
        assert!(
            on_add_page(&d),
            "after pressing `a` the dialog should be on the Add wizard, not stuck on List"
        );
    }

    #[test]
    fn pressing_esc_in_add_wizard_returns_to_list() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_providers();
        d.handle_key(press(KeyCode::Char('a')));
        assert!(on_add_page(&d));
        d.handle_key(press(KeyCode::Esc));
        assert!(on_list_page(&d), "Esc from Add should return to List");
    }

    #[test]
    fn pressing_left_from_providers_list_returns_to_root() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_providers();
        d.handle_key(press(KeyCode::Left));
        assert!(on_root_page(&d), "Left from Providers should land on Root");
    }

    #[test]
    fn oauth_add_step_help_collapses_after_login() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        let mut codex = providers::CodexOAuthSetupState::new();
        codex.logged_in = true;
        d.page = Page::Providers(ProvidersPage::Add(providers::AddState {
            step: AddStep::CodexOAuthAuth(Box::new(codex)),
            template: None,
            id_field: TextField::default(),
            url_field: TextField::default(),
            headers: providers::HeaderEditor::new(Vec::new(), true),
            error: None,
            fetch: None,
            saved_provider_id: None,
        }));
        assert_eq!(d.help_text(), "enter: continue  esc: back");

        let mut grok = providers::GrokOAuthSetupState::new();
        grok.logged_in = false;
        d.page = Page::Providers(ProvidersPage::Add(providers::AddState {
            step: AddStep::GrokOAuthAuth(Box::new(grok)),
            template: None,
            id_field: TextField::default(),
            url_field: TextField::default(),
            headers: providers::HeaderEditor::new(Vec::new(), true),
            error: None,
            fetch: None,
            saved_provider_id: None,
        }));
        assert_eq!(
            d.help_text(),
            "↑/↓  enter: choose  s: skip/continue  esc: back"
        );
    }

    #[test]
    fn paste_routes_to_add_grok_oauth_manual_input() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        let mut grok = providers::GrokOAuthSetupState::new();
        grok.manual_mode = true;
        d.page = Page::Providers(ProvidersPage::Add(providers::AddState {
            step: AddStep::GrokOAuthAuth(Box::new(grok)),
            template: None,
            id_field: TextField::default(),
            url_field: TextField::default(),
            headers: providers::HeaderEditor::new(Vec::new(), true),
            error: None,
            fetch: None,
            saved_provider_id: None,
        }));

        d.paste("http://127.0.0.1/callback?code=abc123&state=s\nignored");

        let Page::Providers(ProvidersPage::Add(add)) = &d.page else {
            panic!("expected Add provider page");
        };
        let AddStep::GrokOAuthAuth(grok) = &add.step else {
            panic!("expected Grok OAuth add step");
        };
        assert_eq!(
            grok.manual_input.text(),
            "http://127.0.0.1/callback?code=abc123&state=s"
        );
    }

    #[test]
    fn paste_routes_to_standalone_grok_oauth_manual_input() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        let mut grok = providers::GrokOAuthSetupState::new();
        grok.manual_mode = true;
        d.page = Page::Providers(ProvidersPage::GrokOAuthSetup {
            state: Box::new(grok),
            parent: Box::new(providers::EditState::new(
                "grok-oauth".to_string(),
                Default::default(),
            )),
        });

        d.paste("manual-code");

        let Page::Providers(ProvidersPage::GrokOAuthSetup { state, .. }) = &d.page else {
            panic!("expected standalone Grok OAuth page");
        };
        assert_eq!(state.manual_input.text(), "manual-code");
    }

    // ── Category-page tests (reorganized /settings) ────────────────────

    use category::{Category, SettingId};

    /// Open a category page on `d` with the cursor on `id`'s row.
    fn open_category_on(d: &mut SettingsDialog, category: Category, id: SettingId) {
        d.enter_category(category);
        if let Page::Category(p) = &mut d.page {
            p.cursor = p
                .cursor_of(id)
                .unwrap_or_else(|| panic!("setting {id:?} not on {category:?}"));
        } else {
            panic!("not on a category page");
        }
    }

    fn category_cursor(d: &SettingsDialog) -> Option<usize> {
        match &d.page {
            Page::Category(p) => Some(p.cursor),
            _ => None,
        }
    }

    fn line_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn render_settings_rows(d: &SettingsDialog, width: u16, height: u16) -> Vec<String> {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| d.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(usize::from(width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect()
    }

    fn rendered_char(row: &str, x: u16) -> char {
        row.chars().nth(usize::from(x)).unwrap_or(' ')
    }

    fn settings_body_area(width: u16, height: u16) -> Rect {
        Rect::new(1, 1, width.saturating_sub(2), height.saturating_sub(3))
    }

    #[test]
    fn category_short_viewport_keeps_bottom_reset_row_visible() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_category(Category::Behavior);
        if let Page::Category(p) = &mut d.page {
            p.cursor = p.cursor_of_reset().expect("reset row");
        }
        let rendered = render_settings_rows(&d, 92, 12).join("\n");
        assert!(
            rendered.contains("reset behavior settings"),
            "selected reset row should be visible:\n{rendered}"
        );
        assert!(
            rendered.contains("↑"),
            "window should disclose hidden rows above:\n{rendered}"
        );
    }

    #[test]
    fn category_wrapped_values_continue_under_value_column() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_category(Category::Behavior);
        if let Page::Category(p) = &mut d.page {
            p.cursor = p.cursor_of(SettingId::LlmMode).expect("llm mode");
        }
        let rendered = render_settings_rows(&d, 62, 18).join("\n");
        let continuation = rendered
            .lines()
            .find(|line| line.contains("default) uses"))
            .unwrap_or_else(|| panic!("expected wrapped llm-mode value:\n{rendered}"));
        assert!(
            continuation.starts_with("│     "),
            "continuation should stay in the value column, not column 0:\n{rendered}"
        );
        assert!(
            !continuation.starts_with("│defensive") && !continuation.starts_with("│default"),
            "continuation must not restart at the far left:\n{rendered}"
        );
    }

    #[test]
    fn category_two_column_render_reserves_blank_gutter() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_category(Category::Interface);

        let width = 92;
        let height = 16;
        let rendered = render_settings_rows(&d, width, height);
        let shell::TextColumnLayout::Two { left, right } =
            shell::settings_text_columns(settings_body_area(width, height))
        else {
            panic!("expected representative width to use two columns");
        };

        assert_eq!(
            right.x,
            left.x + left.width + shell::TEXT_COLUMN_GUTTER_WIDTH
        );
        for y in left.y..left.y + left.height {
            let row = &rendered[usize::from(y)];
            for x in left.x + left.width..right.x {
                assert_eq!(
                    rendered_char(row, x),
                    ' ',
                    "expected blank gutter at x={x}, y={y}:\n{}",
                    rendered.join("\n")
                );
            }
        }
    }

    #[test]
    fn category_narrow_render_stacks_help_below_settings() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_category(Category::Interface);

        let width = 48;
        let height = 18;
        let rendered = render_settings_rows(&d, width, height);
        let shell::TextColumnLayout::Stacked { top, bottom } =
            shell::settings_text_columns(settings_body_area(width, height))
        else {
            panic!("expected narrow width to use stacked layout");
        };

        assert!(bottom.y > top.y + top.height);
        let help_region =
            rendered[usize::from(bottom.y)..usize::from(bottom.y + bottom.height)].join("\n");
        assert!(
            help_region.contains("How the terminal UI"),
            "help pane should remain visible below the settings list:\n{}",
            rendered.join("\n")
        );
    }

    #[test]
    fn lsp_server_row_windows_into_short_viewport() {
        let tmp = TempDir::new().unwrap();
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        let mut d = SettingsDialog::open(cockpit_dir.join("config.json"));
        d.page = Page::Lsp(LspPage {
            cursor: LSP_SERVER_ROW_START,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });
        let rendered = render_settings_rows(&d, 110, 10).join("\n");
        assert!(
            rendered.contains("cockpit-installed") || rendered.contains("project actions"),
            "selected LSP action/server row should be visible:\n{rendered}"
        );
        assert!(
            rendered.contains("↑"),
            "LSP viewport should show hidden rows:\n{rendered}"
        );
    }

    #[test]
    fn shared_single_line_field_and_text_area_render_caret_and_hint() {
        let mut lines = Vec::new();
        shell::push_text_field(&mut lines, 24, "name", "alpha", true, None);
        let rendered = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(rendered.contains("name: alpha▎"));

        let area = shell::text_area_lines(
            "editing agent".to_string(),
            "insert".to_string(),
            "ctrl+s: save  enter: newline  esc: cancel",
            "one\ntwo",
            (1, 1),
        );
        let rendered = area.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(rendered.contains("ctrl+s: save  enter: newline  esc: cancel"));
        assert!(rendered.contains("t▎wo"));
    }

    #[test]
    fn representative_footer_hints_match_tab_and_back_close_behavior() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        assert!(d.help_text().contains("Tab/Shift+Tab"));
        d.enter_category(Category::Interface);
        let help = d.help_text();
        assert!(help.contains("Tab/Shift+Tab"), "{help}");
        assert!(help.contains("esc/h: back"), "{help}");
        assert!(help.contains("q: close"), "{help}");
        if let Page::Category(p) = &mut d.page {
            p.editing = Some(SettingId::Name);
        }
        assert!(
            !d.help_text().contains("Tab/Shift+Tab"),
            "text editing contexts should not advertise Tab navigation"
        );
    }

    #[test]
    fn behavior_llm_mode_row_toggles_and_persists() {
        use crate::config::extended::{ExtendedConfigDoc, LlmMode};
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        assert_eq!(d.extended.llm_mode, LlmMode::Defensive);
        open_category_on(&mut d, Category::Behavior, SettingId::LlmMode);
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.llm_mode, LlmMode::Normal);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.llm_mode, LlmMode::Normal);
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.llm_mode, LlmMode::Frontier);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.llm_mode, LlmMode::Frontier);
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.llm_mode, LlmMode::Defensive);
    }

    #[test]
    fn behavior_default_agent_row_cycles_and_persists() {
        use crate::config::extended::{DefaultPrimaryAgent, ExtendedConfigDoc};
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Auto);
        open_category_on(&mut d, Category::Behavior, SettingId::DefaultPrimaryAgent);
        // Experimental on so the full Auto→Build→Plan cycle is reachable (the
        // gate constraint is exercised by the off-mode test below). Set after
        // entering the category, since `enter_category` reloads `extended`
        // from disk.
        d.extended.experimental_mode = true;
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Build);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.default_primary_agent, DefaultPrimaryAgent::Build);
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Plan);
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Auto);
    }

    /// Experimental-mode gate (implementation note): the
    /// `ExperimentalMode` toggle flips + persists, and while it is off the
    /// `DefaultPrimaryAgent` cycle never lands on a gated agent.
    #[test]
    fn behavior_experimental_mode_toggle_and_gated_default_cycle() {
        use crate::config::extended::{DefaultPrimaryAgent, ExtendedConfigDoc};
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        // Fresh dialog: experimental off by default.
        assert!(!d.extended.experimental_mode);

        // Toggle on → flips + persists.
        open_category_on(&mut d, Category::Behavior, SettingId::ExperimentalMode);
        d.handle_key(press(KeyCode::Enter));
        assert!(d.extended.experimental_mode);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert!(reloaded.experimental_mode);

        // While on, pin the default to a gated agent (Plan), then toggle
        // experimental back off: the toggle pins the default to Build so it
        // never points at a now-hidden gated agent.
        d.extended.default_primary_agent = DefaultPrimaryAgent::Plan;
        d.handle_key(press(KeyCode::Enter)); // experimental → off
        assert!(!d.extended.experimental_mode);
        assert_eq!(d.extended.default_primary_agent, DefaultPrimaryAgent::Build);

        // With experimental off, cycling the default agent never lands on a
        // gated value — it stays on Build.
        open_category_on(&mut d, Category::Behavior, SettingId::DefaultPrimaryAgent);
        for _ in 0..4 {
            d.handle_key(press(KeyCode::Enter));
            assert_eq!(
                d.extended.default_primary_agent,
                DefaultPrimaryAgent::Build,
                "cycle must stay on the only enabled value while experimental off"
            );
        }
    }

    #[test]
    fn behavior_packages_dir_text_edit_persists() {
        use crate::config::extended::ExtendedConfigDoc;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        open_category_on(&mut d, Category::Behavior, SettingId::PackagesDir);
        d.handle_key(press(KeyCode::Enter)); // open edit
        type_chars(&mut d, "/tmp/pkgs");
        d.handle_key(press(KeyCode::Enter)); // commit
        assert_eq!(
            d.extended.packages_directory.as_deref(),
            Some(std::path::Path::new("/tmp/pkgs"))
        );
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(
            reloaded.packages_directory,
            Some(std::path::PathBuf::from("/tmp/pkgs"))
        );
    }

    #[test]
    fn behavior_jobs_max_concurrent_rejects_zero() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        let before = d.extended.schedule.max_concurrent;
        open_category_on(&mut d, Category::Behavior, SettingId::ScheduleMaxConcurrent);
        d.handle_key(press(KeyCode::Enter)); // open edit (seeded with current)
        // Clear and type 0.
        for _ in 0..6 {
            d.handle_key(press(KeyCode::Backspace));
        }
        type_chars(&mut d, "0");
        d.handle_key(press(KeyCode::Enter)); // reject
        match &d.page {
            Page::Category(p) => {
                assert!(p.is_editing(), "stays open on invalid input");
                assert!(p.status.as_deref().unwrap_or("").contains(">="));
            }
            _ => panic!("not on category page"),
        }
        assert_eq!(
            d.extended.schedule.max_concurrent, before,
            "garbage not persisted"
        );
    }

    #[test]
    fn privacy_redaction_rows_toggle_and_persist() {
        use crate::config::extended::ExtendedConfigDoc;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        assert!(d.extended.redact.scan_environment);
        assert!(d.extended.redact.scan_dotenv);
        open_category_on(&mut d, Category::Privacy, SettingId::RedactScanEnvironment);
        d.handle_key(press(KeyCode::Enter));
        assert!(!d.extended.redact.scan_environment);
        // The env-file row is the next one down.
        d.handle_key(press(KeyCode::Down));
        let want = match &d.page {
            Page::Category(p) => p.cursor_of(SettingId::RedactScanDotenv),
            _ => None,
        };
        assert_eq!(category_cursor(&d), want);
        d.handle_key(press(KeyCode::Enter));
        assert!(!d.extended.redact.scan_dotenv);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert!(!reloaded.redact.scan_environment);
        assert!(!reloaded.redact.scan_dotenv);
    }

    #[test]
    fn privacy_redact_min_secret_length_rejects_non_numeric() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        let before = d.extended.redact.min_secret_length;
        open_category_on(&mut d, Category::Privacy, SettingId::RedactMinSecretLength);
        d.handle_key(press(KeyCode::Enter));
        for _ in 0..4 {
            d.handle_key(press(KeyCode::Backspace));
        }
        type_chars(&mut d, "abc");
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Category(p) => assert!(p.is_editing(), "stays open on bad input"),
            _ => panic!("not on category page"),
        }
        assert_eq!(d.extended.redact.min_secret_length, before);
    }

    #[test]
    fn translation_languages_edit_and_persist() {
        use crate::config::extended::ExtendedConfigDoc;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        open_category_on(
            &mut d,
            Category::Translation,
            SettingId::TranslationUserLanguage,
        );
        d.handle_key(press(KeyCode::Enter));
        type_chars(&mut d, "English");
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.translation.user_language, "English");
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.translation.user_language, "English");
    }

    #[test]
    fn profile_name_edit_and_persist() {
        use crate::config::extended::ExtendedConfigDoc;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        open_category_on(&mut d, Category::Profile, SettingId::Name);
        d.handle_key(press(KeyCode::Enter));
        type_chars(&mut d, "Ada");
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.name.as_deref(), Some("Ada"));
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.name.as_deref(), Some("Ada"));
    }

    #[test]
    fn global_name_edit_prompts_to_remove_shadowing_project_value() {
        use crate::config::extended::ExtendedConfigDoc;
        let tmp = TempDir::new().unwrap();
        let global = tmp.path().join(".config/cockpit/config.json");
        let project = tmp.path().join("repo");
        let project_config = project.join(".cockpit/config.json");
        std::fs::create_dir_all(global.parent().unwrap()).unwrap();
        std::fs::create_dir_all(project_config.parent().unwrap()).unwrap();
        std::fs::write(&global, r#"{"name":"Global"}"#).unwrap();
        std::fs::write(
            &project_config,
            r#"{"name":"Project","tui":{"show_cwd":false}}"#,
        )
        .unwrap();

        let mut d = SettingsDialog::open_from_picker(global.clone(), project.clone());
        open_category_on(&mut d, Category::Profile, SettingId::Name);
        d.handle_key(press(KeyCode::Enter));
        for _ in 0..20 {
            d.handle_key(press(KeyCode::Backspace));
        }
        type_chars(&mut d, "Ada");
        d.handle_key(press(KeyCode::Enter));

        match &d.page {
            Page::Category(p) => {
                assert!(p.shadowed_global.is_some());
                assert!(
                    p.status
                        .as_deref()
                        .unwrap_or("")
                        .contains("Remove that project value")
                );
            }
            _ => panic!("not on category page"),
        }

        d.handle_key(press(KeyCode::Char('y')));
        let global_cfg = ExtendedConfigDoc::load(&global).unwrap().config();
        let project_raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&project_config).unwrap()).unwrap();
        assert_eq!(global_cfg.name.as_deref(), Some("Ada"));
        assert!(project_raw.get("name").is_none());
        assert_eq!(project_raw["tui"]["show_cwd"], false);
    }

    fn dialog_with_one_provider(tmp: &TempDir) -> SettingsDialog {
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        write_provider_file(&path, "vendor", r#"{"url":"https://x","headers":[]}"#);
        let mut d = SettingsDialog::open(path);
        d.enter_providers();
        d
    }

    #[test]
    fn pressing_d_once_arms_delete_and_keeps_provider() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            d.config.providers.contains_key("vendor"),
            "single `d` press must not delete"
        );
        match &d.page {
            Page::Providers(ProvidersPage::List {
                delete_pending,
                status,
                ..
            }) => {
                assert!(delete_pending);
                assert!(
                    status.as_deref().unwrap_or("").contains("press d again"),
                    "expected confirm hint, got {status:?}"
                );
            }
            other => panic!("expected ProvidersPage::List, got {other:?}"),
        }
    }

    #[test]
    fn pressing_d_twice_deletes_the_provider() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Char('d')));
        d.handle_key(press(KeyCode::Char('d')));
        assert!(
            !d.config.providers.contains_key("vendor"),
            "double `d` press must delete"
        );
        // Persisted to disk.
        let reloaded = crate::config::providers::ConfigDoc::load(&d.config_path)
            .unwrap()
            .providers();
        assert!(!reloaded.providers.contains_key("vendor"));
    }

    #[test]
    fn arrow_after_d_clears_delete_pending() {
        // Vim-style safety: moving the cursor should disarm a pending
        // delete so the second press doesn't nuke a different row.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        // Arm the focused provider row, then move — the move must disarm it.
        d.handle_key(press(KeyCode::Char('d')));
        d.handle_key(press(KeyCode::Up));
        match &d.page {
            Page::Providers(ProvidersPage::List { delete_pending, .. }) => {
                assert!(!delete_pending, "arrow key should clear pending-delete");
            }
            other => panic!("expected List, got {other:?}"),
        }
    }

    // ── Providers save-UX (visible button + no-loss-on-exit) ───────────

    /// Enter the Edit page for the single provider in `dialog_with_one_provider`.
    fn enter_edit_first_provider(d: &mut SettingsDialog) {
        d.handle_key(press(KeyCode::Enter)); // open Edit
        assert!(
            matches!(&d.page, Page::Providers(ProvidersPage::Edit(_))),
            "expected to be on the Edit page"
        );
    }

    fn disk_url(d: &SettingsDialog, id: &str) -> Option<String> {
        crate::config::providers::ConfigDoc::load(&d.config_path)
            .unwrap()
            .providers()
            .providers
            .get(id)
            .map(|e| e.url.clone())
    }

    /// The Edit page's `[save changes]` row (cursor 7) commits the staged
    /// entry to disk and stays on the page with a `saved` confirmation.
    #[test]
    fn edit_save_changes_row_commits_and_stays() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        enter_edit_first_provider(&mut d);
        // Stage a URL edit, then move the cursor to the `[save changes]`
        // row (index 7) and activate it.
        if let Page::Providers(ProvidersPage::Edit(s)) = &mut d.page {
            s.entry.url = "https://new".to_string();
            s.cursor = 7;
        } else {
            panic!("not on Edit page");
        }
        d.handle_key(press(KeyCode::Enter));
        // Still on the Edit page, with a `saved` status.
        match &d.page {
            Page::Providers(ProvidersPage::Edit(s)) => {
                assert_eq!(s.status.as_deref(), Some("saved"));
            }
            other => panic!("expected to stay on Edit, got {other:?}"),
        }
        assert_eq!(disk_url(&d, "vendor").as_deref(), Some("https://new"));
    }

    /// Single-line field edit (the Edit page URL row): Enter commits the
    /// field straight to disk — no manual save step.
    #[test]
    fn edit_url_field_enter_commits_to_disk() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        enter_edit_first_provider(&mut d);
        // Cursor 0 is the URL row; Enter opens the inline field pre-filled
        // with the current value. Clear it, type a new URL, Enter commits.
        d.handle_key(press(KeyCode::Enter));
        for _ in 0..40 {
            d.handle_key(press(KeyCode::Backspace));
        }
        type_chars(&mut d, "https://committed");
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(disk_url(&d, "vendor").as_deref(), Some("https://committed"));
    }

    /// Leaving the Edit page via Esc auto-commits a staged URL edit — no
    /// silent data loss even without pressing save.
    #[test]
    fn edit_esc_persists_staged_url() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        enter_edit_first_provider(&mut d);
        // Stage a URL edit directly on the EditState (no manual save).
        if let Page::Providers(ProvidersPage::Edit(s)) = &mut d.page {
            s.entry.url = "https://staged".to_string();
        } else {
            panic!("not on Edit page");
        }
        // Esc back to the list must persist the staged edit to disk.
        d.handle_key(press(KeyCode::Esc));
        assert!(on_list_page(&d), "Esc returns to the provider list");
        assert_eq!(disk_url(&d, "vendor").as_deref(), Some("https://staged"));
    }

    /// The Headers sub-page `s` accelerator commits the provider entry —
    /// including the in-flight header edits — directly to disk and stays.
    #[test]
    fn headers_save_accelerator_commits_and_stays() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        enter_edit_first_provider(&mut d);
        // Open the Headers sub-page (Edit cursor 1 → Enter).
        if let Page::Providers(ProvidersPage::Edit(s)) = &mut d.page {
            s.cursor = 1;
        } else {
            panic!("not on Edit page");
        }
        d.handle_key(press(KeyCode::Enter));
        assert!(matches!(
            &d.page,
            Page::Providers(ProvidersPage::Headers { .. })
        ));
        // Stage a header row directly on the editor, then press `s`.
        if let Page::Providers(ProvidersPage::Headers { editor, .. }) = &mut d.page {
            editor.rows.push(crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer x".into(),
            });
        } else {
            panic!("not on Headers page");
        }
        d.handle_key(press(KeyCode::Char('s')));
        // Stayed on the Headers page, committed to disk.
        assert!(
            matches!(&d.page, Page::Providers(ProvidersPage::Headers { .. })),
            "`s` keeps us on the Headers sub-page"
        );
        let reloaded = crate::config::providers::ConfigDoc::load(&d.config_path)
            .unwrap()
            .providers();
        let entry = reloaded.providers.get("vendor").unwrap();
        assert_eq!(entry.headers.len(), 1);
        assert_eq!(entry.headers[0].name, "Authorization");
    }

    /// Leaving the Headers sub-page via Esc auto-commits the header edits —
    /// no silent data loss.
    #[test]
    fn headers_esc_persists_edits() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        enter_edit_first_provider(&mut d);
        if let Page::Providers(ProvidersPage::Edit(s)) = &mut d.page {
            s.cursor = 1;
        } else {
            panic!("not on Edit page");
        }
        d.handle_key(press(KeyCode::Enter));
        if let Page::Providers(ProvidersPage::Headers { editor, .. }) = &mut d.page {
            editor.rows.push(crate::config::providers::HeaderSpec {
                name: "X-Test".into(),
                value: "1".into(),
            });
        } else {
            panic!("not on Headers page");
        }
        // Esc back to Edit must persist.
        d.handle_key(press(KeyCode::Esc));
        assert!(matches!(&d.page, Page::Providers(ProvidersPage::Edit(_))));
        let reloaded = crate::config::providers::ConfigDoc::load(&d.config_path)
            .unwrap()
            .providers();
        let entry = reloaded.providers.get("vendor").unwrap();
        assert_eq!(entry.headers.len(), 1, "header edit persisted on Esc");
        assert_eq!(entry.headers[0].name, "X-Test");
    }

    /// Leaving the Models sub-page via Esc auto-commits a staged model row.
    #[test]
    fn models_esc_persists_edits() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        enter_edit_first_provider(&mut d);
        if let Page::Providers(ProvidersPage::Edit(s)) = &mut d.page {
            s.cursor = 2; // Models row
        } else {
            panic!("not on Edit page");
        }
        d.handle_key(press(KeyCode::Enter));
        if let Page::Providers(ProvidersPage::Models { editor, .. }) = &mut d.page {
            editor.rows.push(crate::config::providers::ModelEntry {
                id: "m-new".into(),
                name: None,
                thinking_modes: Vec::new(),
                inputs: None,
                context_length: None,
                favorite: false,
                manual: true,
                trust: None,
                location: None,
                quality_rank: None,
                cost_rank: None,
                subagent_invokable: None,
                availability: Default::default(),
                cache: None,
                shrink: None,
                context: None,
                auto_prune: None,
                timeout: None,
                backup: None,
                mode: None,
                inline_think: None,
                hint_tool_call_corrections: None,
                text_embedded_recovery: None,
                thinking_params: Default::default(),
                wire_api: Default::default(),
                extra: Default::default(),
                capabilities: Default::default(),
                provider_metadata: Default::default(),
            });
        } else {
            panic!("not on Models page");
        }
        d.handle_key(press(KeyCode::Esc));
        let reloaded = crate::config::providers::ConfigDoc::load(&d.config_path)
            .unwrap()
            .providers();
        let entry = reloaded.providers.get("vendor").unwrap();
        assert_eq!(entry.models.len(), 1, "model edit persisted on Esc");
        assert_eq!(entry.models[0].id, "m-new");
    }

    fn on_fetch_all_page(d: &SettingsDialog) -> bool {
        matches!(&d.page, Page::Providers(ProvidersPage::FetchAll(_)))
    }

    #[tokio::test]
    async fn providers_list_initial_enter_edits_first_provider() {
        // Providers configured: initial focus is the first provider row,
        // not the `[refetch provider models]` button.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter));
        assert!(
            matches!(&d.page, Page::Providers(ProvidersPage::Edit(_))),
            "initial Enter should edit the first provider, got {:?}",
            d.page
        );
    }

    #[tokio::test]
    async fn refetch_all_button_enters_fetch_all_with_providers() {
        // The visible `[refetch provider models]` button remains reachable by
        // moving to row 0 and pressing Enter.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Up));
        d.handle_key(press(KeyCode::Enter));
        assert!(
            on_fetch_all_page(&d),
            "Enter on the refetch-all button should enter FetchAll, got {:?}",
            d.page
        );
        if let Page::Providers(ProvidersPage::FetchAll(s)) = &d.page {
            assert_eq!(
                s.in_flight.len() + s.finished.len(),
                1,
                "exactly one provider should be accounted for"
            );
        }
    }

    #[tokio::test]
    async fn refetch_all_via_capital_r_enters_fetch_all() {
        // `R` triggers the same flow from any row on the list.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Char('R')));
        assert!(
            on_fetch_all_page(&d),
            "`R` on the list should enter FetchAll, got {:?}",
            d.page
        );
    }

    #[test]
    fn refetch_all_with_no_providers_is_a_noop_with_status() {
        // No providers: the button is reachable but activating it must
        // not error or navigate — just set a status on the List page.
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.enter_providers();
        assert!(d.config.providers.is_empty());
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Providers(ProvidersPage::List { status, .. }) => {
                assert_eq!(
                    status.as_deref(),
                    Some("no providers configured"),
                    "expected the no-op status, got {status:?}"
                );
            }
            other => panic!("expected to stay on List, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_all_in_flight_ignores_keys_except_esc() {
        // While the per-provider fetches are running, a stray Enter must
        // not navigate away (which is how a second concurrent all-fetch
        // would otherwise be stacked). Only Esc cancels.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        // Force a state with a live in-flight handle, independent of how
        // fast the spawned task completes (we never tick, so in_flight
        // stays populated).
        let state = ProvidersPage::FetchAll(FetchAllState::spawn(&d.config));
        d.page = Page::Providers(state);
        if let Page::Providers(ProvidersPage::FetchAll(s)) = &d.page {
            assert!(s.is_fetching(), "expected an in-flight fetch");
        }
        // A non-Esc key is ignored — we stay on FetchAll.
        let closed = d.handle_key(press(KeyCode::Enter));
        assert!(!closed);
        assert!(
            on_fetch_all_page(&d),
            "Enter during an in-flight fetch must not navigate, got {:?}",
            d.page
        );
    }

    #[test]
    fn has_no_providers_true_when_config_dir_empty() {
        // discover_config_dirs walks up from `cwd`, so a tempdir with
        // no `.cockpit/` or local config should fall back to the user's
        // config (which may or may not exist). The cleanest assertion
        // we can make portably is the symmetry: open_providers_add
        // produces a non-Settings dialog when has_no_providers reports
        // no config — i.e. the function doesn't panic and is honest
        // about what it found.
        let tmp = TempDir::new().unwrap();
        // Just exercising the codepath — the answer depends on the
        // host's $HOME, so we only assert it returns *some* bool.
        let _ = Dialog::has_no_providers(tmp.path());
    }

    #[test]
    fn open_providers_add_lands_on_add_page_when_config_exists() {
        let tmp = TempDir::new().unwrap();
        // Create a `.cockpit/config.json` so the dialog has a layer to
        // open without falling through to CreateConfig.
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
        let d = Dialog::open_providers_add(tmp.path());
        let Dialog::Settings(s) = d else {
            panic!("expected Settings dialog");
        };
        assert!(
            matches!(s.page, Page::Providers(ProvidersPage::Add(_))),
            "expected Add page, got {:?}",
            s.page
        );
    }

    #[test]
    fn lsp_server_rows_queue_daemon_actions() {
        let tmp = TempDir::new().unwrap();
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        let mut d = SettingsDialog::open(cockpit_dir.join("config.json"));
        d.page = Page::Lsp(LspPage {
            cursor: LSP_SERVER_ROW_START,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });

        d.handle_key(press(KeyCode::Enter));
        match d.pending_daemon_request.take() {
            Some(Request::LspControl {
                project_root,
                server_id,
                action,
            }) => {
                assert_eq!(project_root, tmp.path().display().to_string());
                assert_eq!(server_id, "rust-analyzer");
                assert_eq!(action, LspControlAction::Check);
            }
            other => panic!("expected LSP check request, got {other:?}"),
        }

        d.handle_key(press(KeyCode::Char('i')));
        match d.pending_daemon_request.take() {
            Some(Request::LspControl {
                server_id, action, ..
            }) => {
                assert_eq!(server_id, "rust-analyzer");
                assert_eq!(action, LspControlAction::Install);
            }
            other => panic!("expected LSP install request, got {other:?}"),
        }
    }

    fn lsp_snapshot(
        lsp: &crate::config::extended::LspConfig,
    ) -> (bool, String, bool, usize, usize, u64, u64, u64) {
        (
            lsp.enabled,
            lsp.auto_install.as_str().to_string(),
            lsp.diagnostics.enabled,
            lsp.diagnostics.other_files_limit,
            lsp.diagnostics.per_file_limit,
            lsp.diagnostics.debounce_ms,
            lsp.diagnostics.document_timeout_ms,
            lsp.diagnostics.workspace_timeout_ms,
        )
    }

    #[test]
    fn lsp_reset_r_once_arms_without_wiping() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = Page::Lsp(LspPage {
            cursor: 0,
            editing: None,
            buf: TextField::default(),
            status: Some("old status".into()),
            reset: ResetButton::default(),
        });
        d.extended.lsp.enabled = false;
        d.extended.lsp.diagnostics.other_files_limit = 17;
        let before = lsp_snapshot(&d.extended.lsp);

        d.handle_key(press(KeyCode::Char('r')));

        assert_eq!(
            lsp_snapshot(&d.extended.lsp),
            before,
            "first r must not reset"
        );
        match &d.page {
            Page::Lsp(p) => {
                assert!(p.reset.is_pending());
                assert!(p.status.is_none(), "arming clears stale status");
            }
            other => panic!("expected LSP page, got {other:?}"),
        }
    }

    #[test]
    fn lsp_reset_r_twice_restores_defaults() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = Page::Lsp(LspPage {
            cursor: 0,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });
        d.extended.lsp.enabled = false;
        d.extended.lsp.diagnostics.other_files_limit = 17;

        d.handle_key(press(KeyCode::Char('r')));
        d.handle_key(press(KeyCode::Char('r')));

        assert_eq!(
            lsp_snapshot(&d.extended.lsp),
            lsp_snapshot(&crate::config::extended::LspConfig::default())
        );
        match &d.page {
            Page::Lsp(p) => {
                assert!(!p.reset.is_pending());
                assert!(p.status.is_some(), "applying reports save status");
            }
            other => panic!("expected LSP page, got {other:?}"),
        }
    }

    #[test]
    fn lsp_reset_pending_cancelled_by_navigation() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = Page::Lsp(LspPage {
            cursor: 0,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });
        d.extended.lsp.enabled = false;
        let before = lsp_snapshot(&d.extended.lsp);

        d.handle_key(press(KeyCode::Char('r')));
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Char('r')));

        assert_eq!(
            lsp_snapshot(&d.extended.lsp),
            before,
            "navigation disarms, so the next r arms again instead of applying"
        );
        match &d.page {
            Page::Lsp(p) => assert!(p.reset.is_pending()),
            other => panic!("expected LSP page, got {other:?}"),
        }
    }

    #[test]
    fn lsp_reset_row_and_accelerator_share_confirm_state() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = Page::Lsp(LspPage {
            cursor: row_index(LspRow::Reset),
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });
        d.extended.lsp.enabled = false;

        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Lsp(p) => assert!(p.reset.is_pending()),
            other => panic!("expected LSP page, got {other:?}"),
        }
        d.handle_key(press(KeyCode::Char('r')));
        assert_eq!(
            lsp_snapshot(&d.extended.lsp),
            lsp_snapshot(&crate::config::extended::LspConfig::default())
        );

        d.extended.lsp.enabled = false;
        d.handle_key(press(KeyCode::Char('r')));
        match &d.page {
            Page::Lsp(p) => assert!(p.reset.is_pending()),
            other => panic!("expected LSP page, got {other:?}"),
        }
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(
            lsp_snapshot(&d.extended.lsp),
            lsp_snapshot(&crate::config::extended::LspConfig::default())
        );
    }

    #[test]
    fn lsp_selected_line_is_derived_from_row_data_not_marker_text() {
        assert_eq!(lsp_selected_line_for_cursor(row_index(LspRow::Enabled)), 0);
        assert_eq!(
            lsp_selected_line_for_cursor(row_index(LspRow::DebounceMs)),
            row_index(LspRow::DebounceMs) + 1
        );
        assert_eq!(
            lsp_selected_line_for_cursor(LSP_SERVER_ROW_START),
            LSP_SERVER_ROW_START + 1
        );
    }

    #[test]
    fn lsp_edit_row_places_caret_at_textfield_cursor() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = Page::Lsp(LspPage {
            cursor: row_index(LspRow::DebounceMs),
            editing: Some(LspEdit::DebounceMs),
            buf: TextField::new("1234"),
            status: None,
            reset: ResetButton::default(),
        });
        let Page::Lsp(p) = &mut d.page else {
            panic!("expected LSP page")
        };
        p.buf.handle_key(press(KeyCode::Home));
        p.buf.handle_key(press(KeyCode::Right));
        p.buf.handle_key(press(KeyCode::Right));
        let Page::Lsp(p) = &d.page else {
            panic!("expected LSP page")
        };
        let (rows, selected_line) = lsp_rows(&d, p);

        assert_eq!(selected_line, row_index(LspRow::DebounceMs) + 1);
        assert!(line_text(&rows[selected_line]).contains("12▎34"));
    }

    #[test]
    fn lsp_severity_is_muted_non_selectable_info_line() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.page = Page::Lsp(LspPage {
            cursor: 0,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });

        let Page::Lsp(p) = &d.page else {
            panic!("expected LSP page");
        };
        let (rows, _) = lsp_rows(&d, p);
        let severity = rows
            .iter()
            .find(|line| line.to_string().contains("severity"))
            .expect("severity info line is rendered");
        assert!(severity.to_string().contains("error (errors only)"));
        assert!(
            severity
                .spans
                .iter()
                .any(|span| span.style.fg == Some(Color::Indexed(MUTED_COLOR_INDEX))),
            "severity info line is muted"
        );

        for _ in 0..(LSP_NAV_ROWS.len() * 2) {
            let Page::Lsp(p) = &d.page else {
                panic!("expected LSP page");
            };
            let selected = lsp_rows(&d, p)
                .0
                .into_iter()
                .find(|line| line.to_string().starts_with("▸ "))
                .expect("one selected row");
            assert!(
                !selected.to_string().contains("severity"),
                "severity line must never be selected"
            );
            d.handle_key(press(KeyCode::Down));
        }
    }

    #[test]
    fn project_context_uses_project_config_root() {
        let tmp = TempDir::new().unwrap();
        let project = tmp.path().join("project");
        let config = project.join(".cockpit/config.json");

        assert_eq!(
            project_context_for_config(&config, None),
            ProjectContext::Available(project)
        );
    }

    #[test]
    fn project_context_uses_active_root_for_global_config() {
        let tmp = TempDir::new().unwrap();
        let active = tmp.path().join("work");
        let global = tmp.path().join(".config/cockpit/config.json");

        assert_eq!(
            project_context_for_config(&global, Some(&active)),
            ProjectContext::Available(active)
        );
    }

    #[test]
    fn project_context_global_config_without_active_root_is_unavailable() {
        let tmp = TempDir::new().unwrap();
        let global = tmp.path().join(".config/cockpit/config.json");

        assert_eq!(
            project_context_for_config(&global, None),
            ProjectContext::Unavailable
        );
    }

    #[test]
    fn project_context_does_not_treat_config_parent_as_project_root() {
        let tmp = TempDir::new().unwrap();
        let config_parent = tmp.path().join(".config");
        let global = config_parent.join("cockpit/config.json");

        assert_ne!(
            project_context_for_config(&global, None),
            ProjectContext::Available(config_parent)
        );
    }

    #[test]
    fn lsp_action_from_global_settings_uses_active_project_context() {
        let tmp = TempDir::new().unwrap();
        let active = tmp.path().join("active-project");
        let global = tmp.path().join(".config/cockpit/config.json");
        let mut d = SettingsDialog::open_from_picker(global, active.clone());
        d.page = Page::Lsp(LspPage {
            cursor: LSP_SERVER_ROW_START,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });

        d.handle_key(press(KeyCode::Enter));

        match d.pending_daemon_request.take() {
            Some(Request::LspControl { project_root, .. }) => {
                assert_eq!(project_root, active.display().to_string());
            }
            other => panic!("expected LSP check request, got {other:?}"),
        }
    }

    #[test]
    fn lsp_action_without_project_context_is_disabled() {
        let tmp = TempDir::new().unwrap();
        let global = tmp.path().join(".config/cockpit/config.json");
        let mut d = SettingsDialog::open(global);
        d.page = Page::Lsp(LspPage {
            cursor: LSP_SERVER_ROW_START,
            editing: None,
            buf: TextField::default(),
            status: None,
            reset: ResetButton::default(),
        });

        d.handle_key(press(KeyCode::Enter));

        assert!(d.pending_daemon_request.is_none());
        let Page::Lsp(p) = &d.page else {
            panic!("expected LSP page");
        };
        assert_eq!(p.status.as_deref(), Some(PROJECT_CONTEXT_UNAVAILABLE));
    }

    impl std::fmt::Debug for Page {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Page::Root { cursor } => write!(f, "Root({cursor})"),
                Page::Agents(_) => f.write_str("Agents"),
                Page::Tools(_) => f.write_str("Tools"),
                Page::Harnesses(_) => f.write_str("Harnesses"),
                Page::Providers(_) => f.write_str("Providers"),
                Page::Category(p) => write!(f, "Category({:?})", p.category),
                Page::Instructions(_) => f.write_str("Instructions"),
                Page::RedactPatterns(_) => f.write_str("RedactPatterns"),
                Page::StringList(p) => write!(f, "StringList({:?})", p.kind),
                Page::Skills(_) => f.write_str("Skills"),
                Page::Mcp(_) => f.write_str("Mcp"),
                Page::Lsp(_) => f.write_str("Lsp"),
            }
        }
    }

    /// The root-menu index of a node by its title, so tests don't hardcode
    /// the (locked but long) ordering.
    fn root_index(title: &str) -> usize {
        root_nodes()
            .iter()
            .position(|n| n.title == title)
            .unwrap_or_else(|| panic!("no root node titled `{title}`"))
    }

    fn enter_root_node(d: &mut SettingsDialog, title: &str) {
        d.page = Page::Root {
            cursor: root_index(title),
        };
        d.handle_key(press(KeyCode::Enter));
    }

    fn enter_tools_from_root(d: &mut SettingsDialog) {
        enter_root_node(d, "Tools");
    }

    fn enter_harnesses_from_root(d: &mut SettingsDialog) {
        enter_root_node(d, "Harnesses");
    }

    #[test]
    fn harnesses_page_opens_and_seeds_presets() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        // Pretend every preset command is installed so the result doesn't
        // depend on what's on the CI machine's PATH.
        d.command_installed = |_| true;
        enter_harnesses_from_root(&mut d);
        assert!(
            matches!(d.page, Page::Harnesses(_)),
            "expected Harnesses page, got {:?}",
            d.page
        );
        // Fresh: no harnesses configured.
        assert!(d.extended.harnesses.is_empty());
        // Navigate to the `[seed installed presets]` row: with 0 harnesses
        // it's at cursor 1 (after `[+ add harness]` at 0), then activate.
        d.handle_key(press(KeyCode::Down)); // -> [seed installed presets]
        d.handle_key(press(KeyCode::Enter));
        // The verified presets are now configured.
        for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
            assert!(
                d.extended.harnesses.contains_key(name),
                "missing seeded preset `{name}`"
            );
        }
    }

    #[test]
    fn seeded_harnesses_reappear_after_settings_disk_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();

        let mut d = SettingsDialog::open(path.clone());
        d.command_installed = |_| true;
        seed_via_keys(&mut d);
        assert_eq!(harness_status(&d).as_deref(), Some("saved"));

        let mut reopened = SettingsDialog::open(path);
        enter_harnesses_from_root(&mut reopened);
        for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
            assert!(
                reopened.extended.harnesses.contains_key(name),
                "missing seeded preset `{name}` after reopening settings"
            );
        }
    }

    #[test]
    fn harnesses_page_shows_rows_and_warning_when_unrelated_field_is_malformed() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(
            &path,
            r#"{
                "harnesses": {
                    "codex": { "command": "codex", "args": ["exec"] }
                },
                "tui": "not an object"
            }"#,
        )
        .unwrap();

        let mut d = SettingsDialog::open(path);
        enter_harnesses_from_root(&mut d);
        assert!(d.extended.harnesses.contains_key("codex"));
        assert!(
            harness_status(&d)
                .as_deref()
                .is_some_and(|s| s.contains("ignored malformed `tui`")),
            "expected malformed-field warning, got {:?}",
            harness_status(&d)
        );
    }

    /// Move to the `[seed installed presets]` row and activate it. Assumes
    /// the cursor starts at row 0; with `n` harnesses already configured,
    /// the seed row is at `n + 1` (after the harness rows and `[+ add]`).
    fn seed_via_keys(d: &mut SettingsDialog) {
        enter_harnesses_from_root(d);
        let n = d.extended.harnesses.len();
        for _ in 0..(n + 1) {
            d.handle_key(press(KeyCode::Down));
        }
        d.handle_key(press(KeyCode::Enter));
    }

    fn harness_status(d: &SettingsDialog) -> Option<String> {
        match &d.page {
            Page::Harnesses(HarnessesPage::List(s)) => s.status.clone(),
            _ => None,
        }
    }

    #[test]
    fn seeds_only_installed_presets() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        // Only `codex` and `goose` are on PATH.
        d.command_installed = |cmd| matches!(cmd, "codex" | "goose");
        seed_via_keys(&mut d);
        for name in ["codex", "goose"] {
            assert!(
                d.extended.harnesses.contains_key(name),
                "missing installed preset `{name}`"
            );
        }
        for name in ["claude", "opencode", "copilot", "grok"] {
            assert!(
                !d.extended.harnesses.contains_key(name),
                "seeded uninstalled preset `{name}`"
            );
        }
        assert_eq!(harness_status(&d).as_deref(), Some("saved"));
    }

    #[test]
    fn seeds_nothing_and_reports_when_none_installed() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.command_installed = |_| false;
        seed_via_keys(&mut d);
        assert!(
            d.extended.harnesses.is_empty(),
            "seeded a preset with nothing on PATH"
        );
        assert_eq!(
            harness_status(&d).as_deref(),
            Some("no known harnesses found on `PATH`")
        );
    }

    #[test]
    fn reset_with_partial_install_drops_uninstalled() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        // Seed the full set first (everything installed).
        d.command_installed = |_| true;
        seed_via_keys(&mut d);
        for name in ["claude", "codex", "opencode", "copilot", "goose", "grok"] {
            assert!(d.extended.harnesses.contains_key(name));
        }
        // Now only `claude` is on PATH; reset clears all then re-seeds
        // only the installed presets.
        d.command_installed = |cmd| cmd == "claude";
        // Reset row sits two below the seed row; navigate from the current
        // List page. n harnesses + [+ add] + [seed] = reset at n + 2.
        let n = d.extended.harnesses.len();
        // Re-enter to reset cursor to a known position.
        enter_harnesses_from_root(&mut d);
        for _ in 0..(n + 2) {
            d.handle_key(press(KeyCode::Down));
        }
        // Reset is a two-step confirm.
        d.handle_key(press(KeyCode::Enter));
        d.handle_key(press(KeyCode::Enter));
        assert!(d.extended.harnesses.contains_key("claude"));
        for name in ["codex", "opencode", "copilot", "goose", "grok"] {
            assert!(
                !d.extended.harnesses.contains_key(name),
                "reset kept uninstalled preset `{name}`"
            );
        }
        assert_eq!(harness_status(&d).as_deref(), Some("saved"));
    }

    #[test]
    fn seeding_never_clobbers_existing_entry() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        // A user-edited `claude` entry with a custom command that isn't on
        // PATH; seeding must not overwrite it even though we only seed
        // installed presets.
        let mut custom = crate::config::extended::builtin_harness_presets()
            .into_iter()
            .find(|(n, _)| n == "claude")
            .map(|(_, hc)| hc)
            .unwrap();
        custom.command = "my-claude-wrapper".to_string();
        d.extended.harnesses.insert("claude".to_string(), custom);
        // Persist so it survives the reload-from-disk when the page opens.
        d.save_extended().unwrap();
        d.command_installed = |_| true;
        seed_via_keys(&mut d);
        assert_eq!(
            d.extended.harnesses.get("claude").unwrap().command,
            "my-claude-wrapper",
            "seeding clobbered an existing entry"
        );
    }

    #[test]
    fn harnesses_page_h_returns_to_root() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_harnesses_from_root(&mut d);
        d.handle_key(press(KeyCode::Char('h')));
        assert!(on_root_page(&d), "h from Harnesses should return to Root");
    }

    #[test]
    fn pressing_h_in_category_returns_to_root() {
        // Regression for the swap-back bug: the page wrappers used to
        // clobber inner `self.page = Root` writes with the placeholder
        // swap-back, so `h` from those pages did nothing.
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, "Interface");
        assert!(
            matches!(d.page, Page::Category(_)),
            "expected Category, got {:?}",
            d.page
        );
        d.handle_key(press(KeyCode::Char('h')));
        assert!(
            on_root_page(&d),
            "h from a category should return to Root, got {:?}",
            d.page
        );
    }

    fn type_chars(d: &mut SettingsDialog, s: &str) {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
        for ch in s.chars() {
            d.handle_key(KeyEvent {
                code: KeyCode::Char(ch),
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            });
        }
    }

    /// Open the Behavior page on the utility-model row and open the picker.
    fn open_utility_picker(d: &mut SettingsDialog) {
        open_category_on(d, Category::Behavior, SettingId::UtilityModel);
        d.handle_key(press(KeyCode::Enter)); // open picker
    }

    fn utility_picker(d: &SettingsDialog) -> &ui_page::UtilityModelPicker {
        match &d.page {
            Page::Category(p) => p.utility_picker.as_ref().expect("picker open"),
            other => panic!("expected Category page, got {other:?}"),
        }
    }

    /// With no configured models, opening the field drops straight into
    /// the free-text fallback (Custom mode), and a typed `provider:model-id`
    /// is accepted + persisted.
    #[test]
    fn utility_picker_no_models_falls_back_to_free_text() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        open_utility_picker(&mut d);
        // No providers → no entries → Custom mode immediately.
        let picker = utility_picker(&d);
        assert!(picker.entries.is_empty(), "no models configured");
        assert!(
            matches!(picker.mode, ui_page::PickerMode::Custom { .. }),
            "empty list opens straight into free-text entry"
        );
        type_chars(&mut d, "anthropic:claude-haiku");
        d.handle_key(press(KeyCode::Enter)); // accept
        assert_eq!(
            d.extended.utility_model.as_deref(),
            Some("anthropic:claude-haiku")
        );
        // Picker closed, status reflects the save.
        match &d.page {
            Page::Category(p) => {
                assert!(p.utility_picker.is_none(), "picker closes on accept");
                assert_eq!(p.status.as_deref(), Some("saved"));
            }
            other => panic!("expected Category, got {other:?}"),
        }
        let reloaded = crate::config::extended::ExtendedConfigDoc::load(&d.extended_path)
            .unwrap()
            .config();
        assert_eq!(
            reloaded.utility_model.as_deref(),
            Some("anthropic:claude-haiku"),
            "free-text utility model must persist to disk"
        );
    }

    fn dialog_with_models(tmp: &TempDir) -> SettingsDialog {
        let path = tmp.path().join("config.json");
        // Two providers, each with two models, in natural (stored) order.
        std::fs::write(&path, "{}").unwrap();
        write_provider_file(
            &path,
            "anthropic",
            r#"{"url":"https://a","headers":[],
                "models":[{"id":"opus"},{"id":"haiku","name":"Haiku"}]}"#,
        );
        write_provider_file(
            &path,
            "openai",
            r#"{"url":"https://o","headers":[],"models":[{"id":"gpt-5"}]}"#,
        );
        SettingsDialog::open(path)
    }

    /// The picker builds a grouped list across all configured providers,
    /// each as `provider:model-id`, in provider-then-natural order.
    #[test]
    fn utility_picker_builds_grouped_list() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        open_utility_picker(&mut d);
        let picker = utility_picker(&d);
        let values: Vec<String> = picker.entries.iter().map(|e| e.value()).collect();
        // Providers iterate in BTreeMap order (anthropic, openai); each
        // provider's models keep their stored order. No ranking.
        assert_eq!(
            values,
            vec![
                "anthropic:opus".to_string(),
                "anthropic:haiku".to_string(),
                "openai:gpt-5".to_string(),
            ]
        );
        // With no current value, the cursor lands on the first model row
        // (past the [clear] + [custom] action rows), and the human name
        // is carried for display.
        assert!(matches!(
            picker.mode,
            ui_page::PickerMode::List { cursor: 2, .. }
        ));
        assert_eq!(
            picker.entries[1].display_name.as_deref(),
            Some("Haiku"),
            "human name is preserved for display"
        );
    }

    /// Selecting a model row sets + saves `provider:model-id`.
    #[test]
    fn utility_picker_select_sets_and_saves() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        open_utility_picker(&mut d);
        // Cursor starts on the first model row (anthropic:opus); Enter picks it.
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.utility_model.as_deref(), Some("anthropic:opus"));
        match &d.page {
            Page::Category(p) => assert!(p.utility_picker.is_none(), "picker closes on select"),
            other => panic!("expected Ui, got {other:?}"),
        }
        let reloaded = crate::config::extended::ExtendedConfigDoc::load(&d.extended_path)
            .unwrap()
            .config();
        assert_eq!(reloaded.utility_model.as_deref(), Some("anthropic:opus"));
    }

    /// The current value is pre-selected (highlighted) when the picker opens.
    #[test]
    fn utility_picker_preselects_current_value() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        d.extended.utility_model = Some("openai:gpt-5".into());
        // Persist so entering the UI page (which reloads extended-config)
        // preserves the value.
        d.save_extended().unwrap();
        open_utility_picker(&mut d);
        let picker = utility_picker(&d);
        // openai:gpt-5 is entry index 2; +2 action rows = cursor 4.
        match &picker.mode {
            ui_page::PickerMode::List { cursor, .. } => assert_eq!(*cursor, 4),
            _ => panic!("expected List mode"),
        }
        assert_eq!(picker.current.as_deref(), Some("openai:gpt-5"));
    }

    /// Free-text fallback from a populated list: the `[custom…]` action
    /// switches to typing, and an id absent from every provider is accepted.
    #[test]
    fn utility_picker_custom_accepts_unlisted_id() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        open_utility_picker(&mut d);
        // Move up from the first model row to the [custom] action (row 1).
        d.handle_key(press(KeyCode::Up)); // → [custom]
        match &utility_picker(&d).mode {
            ui_page::PickerMode::List { cursor, .. } => assert_eq!(*cursor, 1),
            _ => panic!("expected List mode on the custom row"),
        }
        d.handle_key(press(KeyCode::Enter)); // → Custom mode
        assert!(matches!(
            utility_picker(&d).mode,
            ui_page::PickerMode::Custom { .. }
        ));
        type_chars(&mut d, "local:my-llama");
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.utility_model.as_deref(), Some("local:my-llama"));
    }

    /// Clearing: the `[clear]` action unsets the value back to `None`.
    #[test]
    fn utility_picker_clear_unsets_value() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        d.extended.utility_model = Some("anthropic:opus".into());
        d.save_extended().unwrap();
        open_utility_picker(&mut d);
        // Move up to the [clear] action (row 0) and pick it.
        // From the preselected current (anthropic:opus = cursor 2), Up twice
        // lands on [clear] (0).
        d.handle_key(press(KeyCode::Up));
        d.handle_key(press(KeyCode::Up));
        match &utility_picker(&d).mode {
            ui_page::PickerMode::List { cursor, .. } => assert_eq!(*cursor, 0),
            _ => panic!("expected List mode on the clear row"),
        }
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.utility_model, None, "clear unsets the value");
        let reloaded = crate::config::extended::ExtendedConfigDoc::load(&d.extended_path)
            .unwrap()
            .config();
        assert_eq!(reloaded.utility_model, None);
    }

    /// A blank custom entry also clears the value (unset).
    #[test]
    fn utility_picker_blank_custom_clears() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_models(&tmp);
        d.extended.utility_model = Some("anthropic:opus".into());
        d.save_extended().unwrap();
        open_utility_picker(&mut d);
        d.handle_key(press(KeyCode::Up)); // → [custom]
        d.handle_key(press(KeyCode::Enter)); // → Custom (pre-filled with current)
        // Clear the pre-filled buffer, then accept empty.
        for _ in 0..40 {
            d.handle_key(press(KeyCode::Backspace));
        }
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.utility_model, None, "blank custom clears");
    }

    #[test]
    fn pressing_h_in_tools_returns_to_root() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_tools_from_root(&mut d);
        assert!(matches!(d.page, Page::Tools(_)));
        d.handle_key(press(KeyCode::Char('h')));
        assert!(
            on_root_page(&d),
            "h from Tools should return to Root, got {:?}",
            d.page
        );
    }

    #[test]
    fn enter_on_instructions_row_opens_instructions_page() {
        // The `instructions files` row on the Behavior page drills into the
        // Instructions sub-page.
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
        d.handle_key(press(KeyCode::Enter));
        assert!(
            matches!(d.page, Page::Instructions(_)),
            "expected Instructions page after Enter on the instructions row, got {:?}",
            d.page
        );
    }

    #[test]
    fn back_from_behavior_restores_root_cursor() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, "Behavior");
        d.handle_key(press(KeyCode::Char('h')));
        match &d.page {
            Page::Root { cursor } => {
                assert_eq!(
                    *cursor,
                    root_index("Behavior"),
                    "cursor should be on the Behavior row after return"
                )
            }
            other => panic!("expected Root, got {other:?}"),
        }
    }

    #[test]
    fn back_from_tools_restores_root_cursor() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_tools_from_root(&mut d);
        d.handle_key(press(KeyCode::Char('h')));
        match &d.page {
            Page::Root { cursor } => {
                assert_eq!(
                    *cursor,
                    root_index("Tools"),
                    "cursor should be on the Tools row after return"
                )
            }
            other => panic!("expected Root, got {other:?}"),
        }
    }

    #[test]
    fn root_children_restore_their_own_root_cursor() {
        let root_children = [
            PROVIDERS_TITLE,
            "Agents",
            "Interface",
            "Behavior",
            "Privacy & Safety",
            "Translation",
            "Profile",
            "Tools",
            "Harnesses",
            "Skills",
            "MCP",
            "LSP",
        ];
        for title in root_children {
            let tmp = TempDir::new().unwrap();
            let mut d = fresh_dialog(&tmp);
            enter_root_node(&mut d, title);
            assert!(
                !matches!(d.page, Page::Root { .. }),
                "`{title}` should open a child page"
            );

            d.handle_key(press(KeyCode::Char('h')));

            match &d.page {
                Page::Root { cursor } => assert_eq!(
                    *cursor,
                    root_index(title),
                    "`{title}` should return to its own root row"
                ),
                other => panic!("expected `{title}` to return to Root, got {other:?}"),
            }
        }
    }

    #[test]
    fn pressing_a_on_picker_opens_scoped_create_dialog() {
        // The new affordance: `a` on Dialog::PickConfig opens the
        // "where should this config live?" sub-dialog.
        let tmp = TempDir::new().unwrap();
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
        let mut d = Dialog::open(tmp.path());
        assert!(matches!(d, Dialog::PickConfig { .. }));
        let close = d.handle_key(press(KeyCode::Char('a')));
        assert!(!close);
        assert!(
            matches!(d, Dialog::CreateScopedConfig { .. }),
            "after `a` the dialog should be on CreateScopedConfig"
        );
    }

    #[test]
    fn esc_from_scoped_create_returns_to_picker() {
        let tmp = TempDir::new().unwrap();
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
        let mut d = Dialog::open(tmp.path());
        d.handle_key(press(KeyCode::Char('a')));
        assert!(matches!(d, Dialog::CreateScopedConfig { .. }));
        d.handle_key(press(KeyCode::Esc));
        assert!(
            matches!(d, Dialog::PickConfig { .. }),
            "Esc from CreateScopedConfig should return to PickConfig"
        );
    }

    #[test]
    fn create_config_scaffold_failure_stays_open_with_path_status() {
        let tmp = TempDir::new().unwrap();
        let blocked = tmp.path().join("not-a-dir");
        std::fs::write(&blocked, "file blocks directory creation").unwrap();
        let mut d = Dialog::CreateConfig {
            choices: vec![ConfigDir {
                kind: ConfigDirKind::Project,
                path: blocked.clone(),
            }],
            cursor: 0,
            cwd: tmp.path().to_path_buf(),
            status: None,
        };

        let close = d.handle_key(press(KeyCode::Enter));
        assert!(!close, "scaffold failure must not close the dialog");
        match d {
            Dialog::CreateConfig { status, .. } => {
                let status = status.expect("failure should set inline status");
                assert!(status.contains("failed to create"));
                assert!(status.contains(&blocked.display().to_string()));
            }
            _ => panic!("expected CreateConfig after failure"),
        }
    }

    #[test]
    fn create_config_success_opens_settings_editor() {
        let tmp = TempDir::new().unwrap();
        let target = tmp.path().join(".cockpit");
        let mut d = Dialog::CreateConfig {
            choices: vec![ConfigDir {
                kind: ConfigDirKind::Project,
                path: target.clone(),
            }],
            cursor: 0,
            cwd: tmp.path().to_path_buf(),
            status: Some("old error".into()),
        };

        let close = d.handle_key(press(KeyCode::Enter));
        assert!(!close);
        match d {
            Dialog::Settings(settings) => {
                assert_eq!(settings.config_path, target.join("config.json"))
            }
            _ => panic!("expected Settings after scaffold success"),
        }
    }

    #[test]
    fn scoped_create_scaffold_failure_still_returns_to_picker_with_path_status() {
        let tmp = TempDir::new().unwrap();
        let existing = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&existing).unwrap();
        std::fs::write(existing.join("config.json"), "{}").unwrap();
        let blocked = tmp.path().join("not-a-dir");
        std::fs::write(&blocked, "file blocks directory creation").unwrap();
        let mut d = Dialog::CreateScopedConfig {
            choices: vec![ConfigDir {
                kind: ConfigDirKind::Project,
                path: blocked.clone(),
            }],
            cursor: 0,
            cwd: tmp.path().to_path_buf(),
        };

        let close = d.handle_key(press(KeyCode::Enter));
        assert!(!close);
        match d {
            Dialog::PickConfig { status, .. } => {
                let status = status.expect("failure should set picker status");
                assert!(status.contains("failed to create"));
                assert!(status.contains(&blocked.display().to_string()));
            }
            _ => panic!("expected PickConfig after scoped failure"),
        }
    }

    #[test]
    fn h_from_settings_root_returns_to_picker() {
        // After picking a config, the user should be able to back out
        // of the settings root with h/← and land on the picker again.
        let tmp = TempDir::new().unwrap();
        let cockpit_dir = tmp.path().join(".cockpit");
        std::fs::create_dir_all(&cockpit_dir).unwrap();
        std::fs::write(cockpit_dir.join("config.json"), "{}").unwrap();
        let mut d = Dialog::open(tmp.path());
        // Step into the (only) config.
        d.handle_key(press(KeyCode::Enter));
        assert!(matches!(d, Dialog::Settings(_)));
        d.handle_key(press(KeyCode::Char('h')));
        assert!(
            matches!(d, Dialog::PickConfig { .. }),
            "h from Settings Root should reopen the picker"
        );
    }

    #[test]
    fn settings_nested_esc_backs_out_but_q_closes() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
        assert!(matches!(d.page, Page::Category(_)));
        assert!(!d.handle_key(press(KeyCode::Esc)));
        assert!(on_root_page(&d), "Esc from category returns to root");

        open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
        assert!(d.handle_key(press(KeyCode::Char('q'))));
    }

    fn fresh_instructions_dialog(tmp: &TempDir) -> SettingsDialog {
        let mut d = fresh_dialog(tmp);
        open_category_on(&mut d, Category::Behavior, SettingId::Instructions);
        d.handle_key(press(KeyCode::Enter));
        assert!(matches!(d.page, Page::Instructions(_)));
        d
    }

    #[test]
    fn instructions_a_starts_grab_with_empty_buffer() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_instructions_dialog(&tmp);
        d.handle_key(press(KeyCode::Char('a')));
        match &d.page {
            Page::Instructions(p) => {
                let g = p.grabbed.as_ref().expect("expected grabbed state");
                assert!(g.buf.text().is_empty());
                assert!(g.original_name.is_none(), "new row has no original name");
                assert_eq!(p.cursor, d.extended.agent_guidance_files.len() - 1);
            }
            other => panic!("expected Instructions, got {other:?}"),
        }
    }

    #[test]
    fn instructions_esc_on_freshly_added_row_removes_it() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_instructions_dialog(&tmp);
        let before = d.extended.agent_guidance_files.len();
        d.handle_key(press(KeyCode::Char('a')));
        d.handle_key(press(KeyCode::Esc));
        match &d.page {
            Page::Instructions(p) => {
                assert!(p.grabbed.is_none(), "esc should drop the grab");
                assert_eq!(
                    d.extended.agent_guidance_files.len(),
                    before,
                    "esc on a freshly-added row should delete it"
                );
            }
            other => panic!("expected Instructions, got {other:?}"),
        }
    }

    #[test]
    fn instructions_enter_grabs_existing_row_then_arrow_swaps() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_instructions_dialog(&tmp);
        // Seed two known rows.
        d.extended.agent_guidance_files = vec!["AGENTS.md".into(), "project guidance".into()];
        // Reset to row 0 and grab it.
        d.page = Page::Instructions(InstructionsPage {
            cursor: 0,
            grabbed: None,
            status: None,
        });
        d.handle_key(press(KeyCode::Enter));
        // Now grabbed at idx 0. Press ↓ to swap with row 1.
        d.handle_key(press(KeyCode::Down));
        assert_eq!(
            d.extended.agent_guidance_files,
            vec!["project guidance".to_string(), "AGENTS.md".to_string()]
        );
        // Drop with Enter → save.
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Instructions(p) => assert!(p.grabbed.is_none()),
            other => panic!("expected Instructions, got {other:?}"),
        }
    }

    #[test]
    fn instructions_esc_after_swap_restores_original_order() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_instructions_dialog(&tmp);
        d.extended.agent_guidance_files = vec!["AGENTS.md".into(), "project guidance".into()];
        d.page = Page::Instructions(InstructionsPage {
            cursor: 0,
            grabbed: None,
            status: None,
        });
        d.handle_key(press(KeyCode::Enter));
        d.handle_key(press(KeyCode::Down));
        // Mid-grab the list is mutated. Esc must restore.
        d.handle_key(press(KeyCode::Esc));
        assert_eq!(
            d.extended.agent_guidance_files,
            vec!["AGENTS.md".to_string(), "project guidance".to_string()],
            "esc should restore original order"
        );
    }

    #[test]
    fn instructions_typing_while_grabbed_edits_filename() {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_instructions_dialog(&tmp);
        d.extended.agent_guidance_files = vec!["X".into()];
        d.page = Page::Instructions(InstructionsPage {
            cursor: 0,
            grabbed: None,
            status: None,
        });
        d.handle_key(press(KeyCode::Enter));
        for ch in "Y".chars() {
            d.handle_key(KeyEvent {
                code: KeyCode::Char(ch),
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            });
        }
        // Commit with Enter.
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.agent_guidance_files, vec!["XY".to_string()]);
    }

    #[test]
    fn string_list_delete_requires_second_press_and_first_press_does_not_persist() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.extended.redact.denylist = vec!["secret-value".to_string(), "other-value".to_string()];
        d.save_extended().unwrap();
        d.page = Page::StringList(Box::new(StringListPage::redact_denylist()));

        d.handle_key(press(KeyCode::Char('d')));
        match &d.page {
            Page::StringList(p) => {
                assert_eq!(
                    d.extended.redact.denylist,
                    vec!["secret-value".to_string(), "other-value".to_string()],
                    "first press only arms"
                );
                assert!(p.delete.is_pending_for(0));
                let status = p.status.as_deref().unwrap_or("");
                assert!(status.contains(secret_display::MASKED_VALUE));
                assert!(!status.contains("secret-value"));
            }
            other => panic!("expected StringList, got {other:?}"),
        }
        let on_disk = std::fs::read_to_string(&d.extended_path).unwrap();
        assert!(
            on_disk.contains("secret-value"),
            "single delete press must not persist removal:\n{on_disk}"
        );

        d.handle_key(press(KeyCode::Down));
        match &d.page {
            Page::StringList(p) => {
                assert!(!p.delete.is_pending_for(0), "navigation disarms");
            }
            other => panic!("expected StringList, got {other:?}"),
        }
        d.handle_key(press(KeyCode::Char('d')));
        assert_eq!(
            d.extended.redact.denylist.len(),
            2,
            "fresh first press on row 1 only arms"
        );
        d.handle_key(press(KeyCode::Char('d')));
        assert_eq!(d.extended.redact.denylist, vec!["secret-value".to_string()]);
        let on_disk = std::fs::read_to_string(&d.extended_path).unwrap();
        assert!(!on_disk.contains("other-value"), "{on_disk}");
    }

    #[test]
    fn redact_denylist_values_are_masked_in_summary_and_list_render() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.extended.redact.denylist = vec!["secret-value".to_string(), "other-value".to_string()];
        d.save_extended().unwrap();

        open_category_on(&mut d, Category::Privacy, SettingId::RedactDenylist);
        let rendered = render_settings_rows(&d, 100, 45).join("\n");
        assert!(rendered.contains("2 value(s) masked"), "{rendered}");
        assert!(!rendered.contains("secret-value"), "{rendered}");
        assert!(!rendered.contains("other-value"), "{rendered}");

        d.page = Page::StringList(Box::new(StringListPage::redact_denylist()));
        let rendered = render_settings_rows(&d, 100, 22).join("\n");
        assert!(
            rendered.contains(secret_display::MASKED_VALUE),
            "{rendered}"
        );
        assert!(!rendered.contains("secret-value"), "{rendered}");
        assert!(!rendered.contains("other-value"), "{rendered}");
    }

    #[test]
    fn redact_denylist_existing_edit_is_replacement_only() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.extended.redact.denylist = vec!["secret-value".to_string()];
        d.save_extended().unwrap();
        d.page = Page::StringList(Box::new(StringListPage::redact_denylist()));

        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::StringList(p) => {
                let grabbed = p.grabbed.as_ref().expect("grabbed denylist row");
                assert_eq!(grabbed.buf.text(), "");
                assert_eq!(grabbed.original_name.as_deref(), Some("secret-value"));
            }
            other => panic!("expected StringList, got {other:?}"),
        }
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.redact.denylist, vec!["secret-value".to_string()]);

        d.handle_key(press(KeyCode::Enter));
        for ch in "replacement".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(press(KeyCode::Enter));
        assert_eq!(d.extended.redact.denylist, vec!["replacement".to_string()]);
    }

    #[test]
    fn enter_on_headers_row_navigates_to_headers_subpage() {
        // Provider Edit page → cursor on row 1 (Headers) → Enter
        // should land on the dedicated Headers sub-page, not open an
        // overlay on the Edit page.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // List → Edit(vendor)
        match &d.page {
            Page::Providers(ProvidersPage::Edit(_)) => {}
            other => panic!("expected Edit, got {other:?}"),
        }
        // Move to Headers row (idx 1).
        d.handle_key(press(KeyCode::Char('j')));
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Providers(ProvidersPage::Headers { parent, .. }) => {
                assert_eq!(parent.provider_id, "vendor");
            }
            other => panic!("expected Headers sub-page, got {other:?}"),
        }
    }

    #[test]
    fn back_from_headers_returns_to_edit_with_updated_headers() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('j'))); // cursor → row 1 (Headers)
        d.handle_key(press(KeyCode::Enter)); // → Headers sub-page
        // Add a header via the Browse-mode `a` action, which opens the
        // name/value popup focused on the name field.
        d.handle_key(press(KeyCode::Char('a')));
        // Type a name — a new header with an empty name is discarded on
        // save — then Enter commits and closes the popup.
        d.handle_key(press(KeyCode::Char('x')));
        d.handle_key(press(KeyCode::Enter));
        // `h` from Browse mode returns to the Edit page.
        d.handle_key(press(KeyCode::Char('h')));
        match &d.page {
            Page::Providers(ProvidersPage::Edit(s)) => {
                assert_eq!(s.provider_id, "vendor");
                assert_eq!(s.cursor, 1, "cursor returns to the Headers row");
                assert_eq!(
                    s.entry.headers.len(),
                    1,
                    "headers added on the sub-page should be on the parent EditState"
                );
            }
            other => panic!("expected Edit after back, got {other:?}"),
        }
    }

    #[test]
    fn cancel_add_leaves_no_header() {
        // Opening the add popup and pressing Esc must not leave a blank
        // row behind — the row is only committed on Enter.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('j'))); // cursor → Headers row
        d.handle_key(press(KeyCode::Enter)); // → Headers sub-page
        let before = match &d.page {
            Page::Providers(ProvidersPage::Headers { editor, .. }) => editor.rows().len(),
            other => panic!("expected Headers sub-page, got {other:?}"),
        };
        d.handle_key(press(KeyCode::Char('a'))); // open add popup
        d.handle_key(press(KeyCode::Char('x'))); // type a name
        d.handle_key(press(KeyCode::Esc)); // cancel — discards the add
        match &d.page {
            Page::Providers(ProvidersPage::Headers { editor, .. }) => {
                assert_eq!(editor.rows().len(), before, "cancelled add leaves no row");
                assert!(!editor.is_editing(), "popup is closed after cancel");
            }
            other => panic!("expected Headers sub-page, got {other:?}"),
        }
    }

    #[test]
    fn popup_tab_routes_typing_to_value_field() {
        // In the add/edit popup, Tab switches focus from name to value
        // so subsequent keystrokes land in the value field.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('j'))); // cursor → Headers row
        d.handle_key(press(KeyCode::Enter)); // → Headers sub-page
        d.handle_key(press(KeyCode::Char('a'))); // open add popup (name focus)
        d.handle_key(press(KeyCode::Char('n'))); // → name buffer
        d.handle_key(press(KeyCode::Tab)); // focus → value
        d.handle_key(press(KeyCode::Char('v'))); // → value buffer
        d.handle_key(press(KeyCode::Enter)); // commit
        match &d.page {
            Page::Providers(ProvidersPage::Headers { editor, .. }) => {
                let row = editor.rows().last().expect("a header row was added");
                assert_eq!(row.name, "n");
                assert_eq!(row.value, "v");
            }
            other => panic!("expected Headers sub-page, got {other:?}"),
        }
    }

    #[test]
    fn enter_on_models_row_navigates_to_models_subpage() {
        // Provider Edit page → cursor on row 2 (Models) → Enter lands on
        // the dedicated Models sub-page.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // List → Edit(vendor)
        d.handle_key(press(KeyCode::Char('j'))); // → row 1 (Headers)
        d.handle_key(press(KeyCode::Char('j'))); // → row 2 (Models)
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Providers(ProvidersPage::Models { parent, .. }) => {
                assert_eq!(parent.provider_id, "vendor");
            }
            other => panic!("expected Models sub-page, got {other:?}"),
        }
    }

    #[test]
    fn add_manual_model_then_back_lands_on_edit_with_manual_entry() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('j'))); // → Headers
        d.handle_key(press(KeyCode::Char('j'))); // → Models
        d.handle_key(press(KeyCode::Enter)); // → Models sub-page
        // Add a manual entry: `a` opens the popup focused on the id field.
        d.handle_key(press(KeyCode::Char('a')));
        for ch in "gpt-x".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(press(KeyCode::Enter)); // commit
        // Back to Edit.
        d.handle_key(press(KeyCode::Char('h')));
        match &d.page {
            Page::Providers(ProvidersPage::Edit(s)) => {
                assert_eq!(s.cursor, 2, "cursor returns to the Models row");
                assert_eq!(s.entry.models.len(), 1);
                assert_eq!(s.entry.models[0].id, "gpt-x");
                assert!(s.entry.models[0].manual, "added entry is flagged manual");
            }
            other => panic!("expected Edit after back, got {other:?}"),
        }
    }

    #[test]
    fn add_model_empty_id_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('j'))); // → Headers
        d.handle_key(press(KeyCode::Char('j'))); // → Models
        d.handle_key(press(KeyCode::Enter)); // → Models sub-page
        d.handle_key(press(KeyCode::Char('a'))); // open popup
        d.handle_key(press(KeyCode::Enter)); // commit with empty id
        match &d.page {
            Page::Providers(ProvidersPage::Models { editor, .. }) => {
                assert!(editor.is_editing(), "popup stays open on empty id");
                assert!(editor.rows().is_empty(), "no row added");
                assert!(editor.status.as_deref().unwrap_or("").contains("empty"));
            }
            other => panic!("expected Models sub-page, got {other:?}"),
        }
    }

    #[test]
    fn add_model_duplicate_id_is_rejected() {
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('j'))); // → Headers
        d.handle_key(press(KeyCode::Char('j'))); // → Models
        d.handle_key(press(KeyCode::Enter)); // → Models sub-page
        // Add `dup` once.
        d.handle_key(press(KeyCode::Char('a')));
        for ch in "dup".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(press(KeyCode::Enter));
        // Try to add `dup` again.
        d.handle_key(press(KeyCode::Char('a')));
        for ch in "dup".chars() {
            d.handle_key(press(KeyCode::Char(ch)));
        }
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Providers(ProvidersPage::Models { editor, .. }) => {
                assert!(editor.is_editing(), "popup stays open on duplicate id");
                assert_eq!(editor.rows().len(), 1, "no duplicate row added");
                assert!(
                    editor
                        .status
                        .as_deref()
                        .unwrap_or("")
                        .contains("already exists")
                );
            }
            other => panic!("expected Models sub-page, got {other:?}"),
        }
    }

    #[test]
    fn h_on_edit_page_returns_to_list() {
        // `h` on the Edit page is back-to-list — it must not open the
        // (now-removed) inline header editor.
        let tmp = TempDir::new().unwrap();
        let mut d = dialog_with_one_provider(&tmp);
        d.handle_key(press(KeyCode::Enter)); // → Edit
        d.handle_key(press(KeyCode::Char('h')));
        match &d.page {
            Page::Providers(ProvidersPage::List { .. }) => {}
            other => panic!("expected List after `h`, got {other:?}"),
        }
    }

    #[test]
    fn instructions_esc_after_rename_restores_original_name() {
        use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_instructions_dialog(&tmp);
        d.extended.agent_guidance_files = vec!["AGENTS.md".into()];
        d.page = Page::Instructions(InstructionsPage {
            cursor: 0,
            grabbed: None,
            status: None,
        });
        d.handle_key(press(KeyCode::Enter));
        // Type some junk.
        for ch in "ZZZ".chars() {
            d.handle_key(KeyEvent {
                code: KeyCode::Char(ch),
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            });
        }
        d.handle_key(press(KeyCode::Esc));
        assert_eq!(
            d.extended.agent_guidance_files,
            vec!["AGENTS.md".to_string()],
            "esc should restore the original filename"
        );
    }

    // ── Page-level "reset to defaults" buttons ─────────────────────────

    /// Move the cursor to a row by issuing `n` Down keys from the top.
    fn cursor_down(d: &mut SettingsDialog, n: usize) {
        for _ in 0..n {
            d.handle_key(press(KeyCode::Down));
        }
    }

    fn tools_setup_row() -> usize {
        builtin_tool_names().len() * 3
    }

    fn tools_reset_row() -> usize {
        tools_setup_row() + 1
    }

    #[test]
    fn tools_reset_arms_then_restores_builtins_and_drops_custom() {
        use crate::config::extended::ToolCommandTemplate;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_tools_from_root(&mut d);

        // Diverge a built-in and add a custom user tool.
        d.extended.tools.insert(
            "webfetch".into(),
            ToolCommandTemplate {
                enabled: false,
                command: "mangled".into(),
                description: Some("mangled".into()),
            },
        );
        d.extended.tools.insert(
            "my_custom".into(),
            ToolCommandTemplate {
                enabled: true,
                command: "echo hi".into(),
                description: None,
            },
        );

        cursor_down(&mut d, tools_reset_row());

        // First activation arms (no change yet).
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Tools(p) => assert!(p.reset.is_pending(), "first activation arms"),
            other => panic!("expected Tools, got {other:?}"),
        }
        assert_eq!(
            d.extended.tools.get("webfetch").map(|e| e.command.as_str()),
            Some("mangled"),
            "arming must not mutate config"
        );
        assert!(d.extended.tools.contains_key("my_custom"));

        // Second activation applies + saves.
        d.handle_key(press(KeyCode::Enter));
        match &d.page {
            Page::Tools(p) => assert!(!p.reset.is_pending(), "applying disarms"),
            other => panic!("expected Tools, got {other:?}"),
        }
        assert!(
            !d.extended.tools.contains_key("my_custom"),
            "custom tool removed"
        );
        for name in builtin_tool_names() {
            let got = d.extended.tools.get(*name).expect("built-in present");
            let want = default_template_for(name);
            assert_eq!(got.enabled, want.enabled, "{name} enabled restored");
            assert_eq!(got.command, want.command, "{name} command restored");
            assert_eq!(
                got.description, want.description,
                "{name} description restored"
            );
        }
        // Persisted to disk.
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert!(!reloaded.tools.contains_key("my_custom"));
        let wf = reloaded.tools.get("webfetch").expect("webfetch persisted");
        assert_eq!(wf.command, default_template_for("webfetch").command);
    }

    #[test]
    fn tools_reset_pending_cancelled_by_navigation() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_tools_from_root(&mut d);
        cursor_down(&mut d, tools_reset_row());
        d.handle_key(press(KeyCode::Enter)); // arm
        match &d.page {
            Page::Tools(p) => assert!(p.reset.is_pending()),
            other => panic!("expected Tools, got {other:?}"),
        }
        // Navigate away → disarm.
        d.handle_key(press(KeyCode::Up));
        match &d.page {
            Page::Tools(p) => assert!(!p.reset.is_pending(), "navigation disarms reset"),
            other => panic!("expected Tools, got {other:?}"),
        }
    }

    #[test]
    fn tools_page_wraps_long_values_under_value_column() {
        use crate::config::extended::ToolCommandTemplate;

        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_tools_from_root(&mut d);
        d.extended.tools.insert(
            "webfetch".into(),
            ToolCommandTemplate {
                enabled: true,
                command: "curl --header very-long-header --max-time 20 --retry 4 -- {url}".into(),
                description: Some(
                    "Fetch a URL with a deliberately long description that must wrap under value."
                        .into(),
                ),
            },
        );

        let p = match &d.page {
            Page::Tools(p) => p,
            other => panic!("expected Tools, got {other:?}"),
        };
        let rendered: Vec<String> = d
            .build_tools_page_lines(38, p)
            .into_iter()
            .map(|line| {
                line.spans
                    .iter()
                    .map(|span| span.content.as_ref())
                    .collect::<String>()
            })
            .collect();

        let command_row = rendered
            .iter()
            .position(|line| line.contains("  command"))
            .expect("command row rendered");
        assert!(
            rendered[command_row + 1].starts_with("                  "),
            "command continuation should align under value column: {:?}",
            rendered[command_row + 1]
        );
        assert!(
            !rendered[command_row + 1].starts_with("curl"),
            "command continuation must not restart at column 0"
        );

        let description_row = rendered
            .iter()
            .position(|line| line.contains("  description"))
            .expect("description row rendered");
        assert!(
            rendered[description_row + 1].starts_with("                  "),
            "description continuation should align under value column: {:?}",
            rendered[description_row + 1]
        );
        assert!(
            !rendered[description_row + 1].starts_with("Fetch"),
            "description continuation must not restart at column 0"
        );
    }

    #[test]
    fn tools_web_setup_firecrawl_applies_fetch_and_search_templates() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.command_installed = |cmd| cmd == "firecrawl";
        enter_tools_from_root(&mut d);

        cursor_down(&mut d, tools_setup_row());
        d.handle_key(press(KeyCode::Enter));
        d.handle_key(press(KeyCode::Enter));

        let fetch = d.extended.tools.get("webfetch").expect("webfetch set");
        let search = d.extended.tools.get("websearch").expect("websearch set");
        assert_eq!(fetch.command, "firecrawl scrape --format markdown {url}");
        assert_eq!(search.command, "firecrawl search --json --limit 8 {query}");
        assert!(fetch.enabled);
        assert!(search.enabled);
        match &d.page {
            Page::Tools(p) => {
                assert!(p.setup.is_none(), "provider setup should close");
                assert_eq!(p.cursor, 0);
            }
            other => panic!("expected Tools, got {other:?}"),
        }
    }

    #[test]
    fn tools_web_setup_missing_provider_shows_docs_without_mutating() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.command_installed = |_| false;
        enter_tools_from_root(&mut d);

        cursor_down(&mut d, tools_setup_row());
        d.handle_key(press(KeyCode::Enter));
        d.handle_key(press(KeyCode::Enter));

        assert!(
            d.extended.tools.is_empty(),
            "missing provider must not write templates"
        );
        match &d.page {
            Page::Tools(p) => {
                assert!(p.setup.is_some(), "setup should stay open");
                assert_eq!(
                    p.status.as_deref(),
                    Some("firecrawl is not on PATH. Install: https://github.com/firecrawl/cli")
                );
            }
            other => panic!("expected Tools, got {other:?}"),
        }
    }

    #[test]
    fn tools_web_setup_agent_browser_prompts_for_search_engine() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        d.command_installed = |cmd| cmd == "agent-browser";
        enter_tools_from_root(&mut d);

        cursor_down(&mut d, tools_setup_row());
        d.handle_key(press(KeyCode::Enter));
        cursor_down(&mut d, 2);
        d.handle_key(press(KeyCode::Enter));

        let fetch = d.extended.tools.get("webfetch").expect("webfetch set");
        assert_eq!(
            fetch.command,
            "agent-browser --session cockpit-webfetch open {url} && agent-browser --session cockpit-webfetch get text body"
        );
        assert!(
            !d.extended.tools.contains_key("websearch"),
            "search waits for engine choice"
        );
        match &d.page {
            Page::Tools(p) => {
                assert!(p.setup.is_some(), "engine setup should be open");
                assert_eq!(p.cursor, 0);
            }
            other => panic!("expected Tools, got {other:?}"),
        }

        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Enter));
        let search = d.extended.tools.get("websearch").expect("websearch set");
        assert_eq!(
            search.command,
            "agent-browser --session cockpit-websearch open \"https://www.bing.com/search?q={query}\" && agent-browser --session cockpit-websearch get text body"
        );
        match &d.page {
            Page::Tools(p) => assert!(p.setup.is_none(), "engine setup should close"),
            other => panic!("expected Tools, got {other:?}"),
        }
    }

    /// Move a category page's cursor onto its reset button row (the last
    /// selectable row).
    fn move_to_reset_row(d: &mut SettingsDialog) {
        let target = match &d.page {
            Page::Category(p) => p.cursor_of_reset().expect("category has a reset button"),
            _ => panic!("not on a category page"),
        };
        if let Page::Category(p) = &mut d.page {
            p.cursor = target;
        }
    }

    #[test]
    fn interface_reset_restores_display_toggles_but_preserves_other_fields() {
        use crate::config::extended::{ThinkingDisplay, TuiConfig, VimModeSetting};
        use std::path::PathBuf;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, "Interface");

        // Mutate display toggles away from their defaults.
        d.extended.tui.vim_mode = VimModeSetting::Disabled;
        d.extended.tui.thinking = ThinkingDisplay::Verbose;
        d.extended.tui.render_agent_markdown = false;
        d.extended.tui.render_user_markdown = true;
        d.extended.tui.mouse_capture = false;
        d.extended.tui.rich_text_copy = false;
        d.extended.tui.use_emojis = true;
        d.extended.tui.caffeinate_display_awake = true;
        // Set NON-display fields the Interface reset must preserve.
        d.extended.utility_model = Some("openai:gpt-tiny".into());
        d.extended.name = Some("Ada".into());
        d.extended.packages_directory = Some(PathBuf::from("/tmp/pkgs"));
        d.extended.agent_guidance_files = vec!["MINE.md".into()];

        move_to_reset_row(&mut d);
        d.handle_key(press(KeyCode::Enter)); // arm
        match &d.page {
            Page::Category(p) => assert!(p.reset.is_pending()),
            other => panic!("expected Category, got {other:?}"),
        }
        // Arming must not change anything.
        assert_eq!(d.extended.tui.vim_mode, VimModeSetting::Disabled);

        d.handle_key(press(KeyCode::Enter)); // apply
        match &d.page {
            Page::Category(p) => {
                assert!(!p.reset.is_pending(), "applying disarms");
                assert_eq!(
                    p.pending_mouse_capture,
                    Some(TuiConfig::default().mouse_capture),
                    "reset signals the App to reconcile mouse capture"
                );
            }
            other => panic!("expected Category, got {other:?}"),
        }

        let def = TuiConfig::default();
        assert_eq!(d.extended.tui.vim_mode, def.vim_mode);
        assert_eq!(d.extended.tui.thinking, def.thinking);
        assert_eq!(
            d.extended.tui.render_agent_markdown,
            def.render_agent_markdown
        );
        assert_eq!(
            d.extended.tui.render_user_markdown,
            def.render_user_markdown
        );
        assert_eq!(d.extended.tui.mouse_capture, def.mouse_capture);
        assert_eq!(d.extended.tui.rich_text_copy, def.rich_text_copy);
        assert_eq!(d.extended.tui.use_emojis, def.use_emojis);
        assert_eq!(
            d.extended.tui.caffeinate_display_awake,
            def.caffeinate_display_awake
        );

        // Non-display fields preserved.
        assert_eq!(d.extended.utility_model.as_deref(), Some("openai:gpt-tiny"));
        assert_eq!(d.extended.name.as_deref(), Some("Ada"));
        assert_eq!(
            d.extended.packages_directory,
            Some(PathBuf::from("/tmp/pkgs"))
        );
        assert_eq!(d.extended.agent_guidance_files, vec!["MINE.md".to_string()]);

        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.tui.vim_mode, def.vim_mode);
        assert_eq!(reloaded.utility_model.as_deref(), Some("openai:gpt-tiny"));
        assert_eq!(reloaded.name.as_deref(), Some("Ada"));
    }

    #[test]
    fn privacy_reset_restores_knobs_but_preserves_redaction_content() {
        use crate::config::extended::{ExtendedConfig, InjectionThreshold};
        use std::path::PathBuf;

        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, "Privacy & Safety");

        d.extended.redact.enabled = false;
        d.extended.redact.scan_environment = false;
        d.extended.redact.scan_dotenv = false;
        d.extended.redact.scan_ssh_keys = false;
        d.extended.redact.ssh_key_dir = Some(PathBuf::from("/tmp/custom-ssh"));
        d.extended.redact.min_secret_length = 42;
        d.extended.redact.placeholder = "MASKED".into();
        d.extended.prompt_injection_guard.threshold = InjectionThreshold::Low;
        d.extended.prompt_injection_guard.check_prompt = Some("custom check".into());
        d.extended.prompt_injection_guard.model = Some("openai:guard".into());
        d.extended.allow_remote_config = true;

        d.extended.redact.dotenv_patterns = vec![".env.secret".into(), "config/*.env".into()];
        d.extended.redact.extra_dotenv_paths =
            vec![PathBuf::from("/secure/app.env"), PathBuf::from("local.env")];
        d.extended.redact.denylist = vec!["must-redact".into(), "also-redact".into()];
        d.extended.redact.allowlist = vec!["SAFE_ENV".into(), "PUBLIC_TOKEN".into()];
        d.extended.gitignore_allow = vec!["fixtures/secrets.env".into(), "docs/*.md".into()];

        move_to_reset_row(&mut d);
        d.handle_key(press(KeyCode::Enter)); // arm
        d.handle_key(press(KeyCode::Enter)); // apply

        let def = ExtendedConfig::default();
        assert_eq!(d.extended.redact.enabled, def.redact.enabled);
        assert_eq!(
            d.extended.redact.scan_environment,
            def.redact.scan_environment
        );
        assert_eq!(d.extended.redact.scan_dotenv, def.redact.scan_dotenv);
        assert_eq!(d.extended.redact.scan_ssh_keys, def.redact.scan_ssh_keys);
        assert_eq!(d.extended.redact.ssh_key_dir, def.redact.ssh_key_dir);
        assert_eq!(
            d.extended.redact.min_secret_length,
            def.redact.min_secret_length
        );
        assert_eq!(d.extended.redact.placeholder, def.redact.placeholder);
        assert_eq!(
            d.extended.prompt_injection_guard.threshold,
            def.prompt_injection_guard.threshold
        );
        assert_eq!(d.extended.prompt_injection_guard.check_prompt, None);
        assert_eq!(d.extended.prompt_injection_guard.model, None);
        assert!(!d.extended.allow_remote_config);

        assert_eq!(
            d.extended.redact.dotenv_patterns,
            vec![".env.secret".to_string(), "config/*.env".to_string()]
        );
        assert_eq!(
            d.extended.redact.extra_dotenv_paths,
            vec![PathBuf::from("/secure/app.env"), PathBuf::from("local.env")]
        );
        assert_eq!(
            d.extended.redact.denylist,
            vec!["must-redact".to_string(), "also-redact".to_string()]
        );
        assert_eq!(
            d.extended.redact.allowlist,
            vec!["SAFE_ENV".to_string(), "PUBLIC_TOKEN".to_string()]
        );
        assert_eq!(
            d.extended.gitignore_allow,
            vec!["fixtures/secrets.env".to_string(), "docs/*.md".to_string()]
        );

        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.redact.denylist, d.extended.redact.denylist);
        assert_eq!(reloaded.redact.allowlist, d.extended.redact.allowlist);
        assert_eq!(reloaded.gitignore_allow, d.extended.gitignore_allow);
        assert!(!reloaded.allow_remote_config);
    }

    #[test]
    fn category_reset_pending_cancelled_by_navigation() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_dialog(&tmp);
        enter_root_node(&mut d, "Interface");
        move_to_reset_row(&mut d);
        d.handle_key(press(KeyCode::Enter)); // arm
        match &d.page {
            Page::Category(p) => assert!(p.reset.is_pending()),
            other => panic!("expected Category, got {other:?}"),
        }
        d.handle_key(press(KeyCode::Up)); // navigate away
        match &d.page {
            Page::Category(p) => assert!(!p.reset.is_pending(), "navigation disarms reset"),
            other => panic!("expected Category, got {other:?}"),
        }
    }
}
