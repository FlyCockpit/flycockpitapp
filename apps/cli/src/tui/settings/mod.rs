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
mod descriptor;
mod grab;
mod harnesses_page;
mod lsp_page;
mod mcp_page;
mod providers;
mod reset;
pub(crate) mod secret_display;
mod settings_editor;
mod shell;
mod skills_page;
mod string_list;
mod tools_page;
mod ui_page;

use std::any::Any;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::config::dirs::{
    CONFIG_FILE, ConfigDir, ConfigDirKind, config_write_target_for_provider, creatable_config_dirs,
    cwd_scoped_creatable_dirs, discover_config_dirs, scaffold_config_dir,
};
use crate::config::extended::{ExtendedConfig, ExtendedConfigDoc};
use crate::config::providers::{
    AuthKind, ConfigDoc, OnUnlistedModelsFetch, ProviderEntry, ProvidersConfig,
};
use crate::daemon::proto::Request;
use crate::providers::models_fetch::FetchOutcome;
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use shell::{SettingsScrollStates, marker, muted_style, selected_or_field};

/// Height (in rows) the dialog wants when active.
pub const DIALOG_HEIGHT: u16 = 20;

pub enum Dialog {
    None,
    WorkspaceTrust {
        root: crate::config::trust::TrustRoot,
        cursor: usize,
        chosen: Option<crate::db::workspace_trust::WorkspaceTrustMode>,
    },
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
    WizardMenu {
        wizards: Vec<crate::wizard::WizardDescriptor>,
        cursor: usize,
        cwd: PathBuf,
    },
    SetupWizard(Box<SetupWizardDialog>),
    FirstRunComplete,
    /// Boxed because [`SettingsDialog`] dwarfs the other variants
    /// (~1.1KB vs <100 bytes), which would otherwise bloat every
    /// [`Dialog`] on the stack.
    Settings(Box<SettingsDialog>),
}

pub struct SetupWizardDialog {
    run: crate::wizard::WizardRun,
    cursor: usize,
    text: TextField,
    multi: std::collections::BTreeSet<String>,
    multi_touched: bool,
    cwd: PathBuf,
    status: Option<String>,
}

pub struct SettingsDialog {
    pub(super) page: PageBox,
    /// Live parent pages for drill-down navigation. Popping restores the
    /// exact boxed page object, including cursor and scroll state.
    stack: Vec<PageBox>,
    cx: SettingsCx,
}

fn setup_wizard_dialog(
    cwd: &std::path::Path,
    descriptor: crate::wizard::WizardDescriptor,
    status: Option<String>,
) -> Result<Dialog, String> {
    let run = crate::wizard::WizardRun::new(descriptor).map_err(|e| e.to_string())?;
    let mut cursor = 0;
    let mut text = TextField::new("");
    let mut multi = std::collections::BTreeSet::new();
    let mut multi_touched = false;
    sync_setup_wizard_inputs(&run, &mut cursor, &mut text, &mut multi, &mut multi_touched);
    Ok(Dialog::SetupWizard(Box::new(SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        cwd: cwd.to_path_buf(),
        status,
    })))
}

impl Deref for SettingsDialog {
    type Target = SettingsCx;

    fn deref(&self) -> &Self::Target {
        &self.cx
    }
}

impl DerefMut for SettingsDialog {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.cx
    }
}

pub(super) type PageBox = Box<dyn SettingsPage>;

pub(super) struct RootPage {
    cursor: usize,
}

/// Stateful `/settings` page behavior.
///
/// Adding a page should require one localized implementation:
///
/// 1. Define the page state type.
/// 2. Implement [`SettingsPage`] for that type.
/// 3. Construct a boxed page at the navigation site that opens it.
///
/// Page code uses [`SettingsCx`] for shared configuration, persistence,
/// pending requests, and scroll state; it returns [`Nav`] instead of touching
/// the navigation stack directly. The outer [`SettingsDialog`] stores the
/// current page and stack as boxed trait objects, so pushing and popping
/// preserves the live concrete page state without adding central render,
/// title, help, or key-dispatch arms.
pub(super) trait SettingsPage: Any {
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav;
    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect);
    fn render_with_links(
        &self,
        cx: &SettingsCx,
        frame: &mut Frame,
        area: Rect,
        _links: &mut crate::tui::links::LinkRegistry,
    ) {
        self.render(cx, frame, area);
    }
    fn title(&self, cx: &SettingsCx) -> String;
    fn help_text(&self, cx: &SettingsCx) -> &'static str;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    #[cfg(test)]
    fn test_name(&self) -> &'static str;
}

impl std::fmt::Debug for dyn SettingsPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(test)]
        {
            return f.write_str(self.test_name());
        }
        #[cfg(not(test))]
        {
            f.write_str("SettingsPage")
        }
    }
}

impl dyn SettingsPage {
    fn downcast_ref<T: SettingsPage>(&self) -> Option<&T> {
        self.as_any().downcast_ref::<T>()
    }

    fn downcast_mut<T: SettingsPage>(&mut self) -> Option<&mut T> {
        self.as_any_mut().downcast_mut::<T>()
    }
}

#[cfg(test)]
enum Page {
    Root { cursor: usize },
    Agents(AgentsPage),
    Tools(ToolsPage),
    Harnesses(HarnessesPage),
    Providers(ProvidersPage),
    Category(Box<CategoryPage>),
    Instructions(InstructionsPage),
    RedactPatterns(RedactPatternsPage),
    StringList(Box<StringListPage>),
    Skills(SkillsPage),
    Mcp(McpPage),
    Lsp(LspPage),
}

#[cfg(test)]
fn boxed_page(page: Page) -> PageBox {
    match page {
        Page::Root { cursor } => root_page(cursor),
        Page::Agents(page) => agents_page(page),
        Page::Tools(page) => tools_page(page),
        Page::Harnesses(page) => harnesses_page(page),
        Page::Providers(page) => providers_page(page),
        Page::Category(page) => category_page(*page),
        Page::Instructions(page) => instructions_page(page),
        Page::RedactPatterns(page) => redact_patterns_page(page),
        Page::StringList(page) => string_list_page(*page),
        Page::Skills(page) => skills_page(page),
        Page::Mcp(page) => mcp_page(page),
        Page::Lsp(page) => lsp_page(page),
    }
}

#[allow(private_interfaces)]
#[cfg(test)]
enum TestPageRef<'a> {
    Root { cursor: usize },
    Agents(&'a AgentsPage),
    Tools(&'a ToolsPage),
    Harnesses(&'a HarnessesPage),
    Providers(&'a ProvidersPage),
    Category(&'a CategoryPage),
    Instructions(&'a InstructionsPage),
    RedactPatterns(&'a RedactPatternsPage),
    StringList(&'a StringListPage),
    Skills(&'a SkillsPage),
    Mcp(&'a McpPage),
    Lsp(&'a LspPage),
}

#[cfg(test)]
enum TestPageMut<'a> {
    Root { cursor: &'a mut usize },
    Agents(&'a mut AgentsPage),
    Tools(&'a mut ToolsPage),
    Harnesses(&'a mut HarnessesPage),
    Providers(&'a mut ProvidersPage),
    Category(&'a mut CategoryPage),
    Instructions(&'a mut InstructionsPage),
    RedactPatterns(&'a mut RedactPatternsPage),
    StringList(&'a mut StringListPage),
    Skills(&'a mut SkillsPage),
    Mcp(&'a mut McpPage),
    Lsp(&'a mut LspPage),
}

#[cfg(test)]
impl std::fmt::Debug for TestPageRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root { cursor } => write!(f, "Root({cursor})"),
            Self::Agents(_) => f.write_str("Agents"),
            Self::Tools(_) => f.write_str("Tools"),
            Self::Harnesses(_) => f.write_str("Harnesses"),
            Self::Providers(_) => f.write_str("Providers"),
            Self::Category(_) => f.write_str("Category"),
            Self::Instructions(_) => f.write_str("Instructions"),
            Self::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Self::StringList(_) => f.write_str("StringList"),
            Self::Skills(_) => f.write_str("Skills"),
            Self::Mcp(_) => f.write_str("Mcp"),
            Self::Lsp(_) => f.write_str("Lsp"),
        }
    }
}

#[cfg(test)]
impl std::fmt::Debug for TestPageMut<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root { cursor } => write!(f, "Root({})", **cursor),
            Self::Agents(_) => f.write_str("Agents"),
            Self::Tools(_) => f.write_str("Tools"),
            Self::Harnesses(_) => f.write_str("Harnesses"),
            Self::Providers(_) => f.write_str("Providers"),
            Self::Category(_) => f.write_str("Category"),
            Self::Instructions(_) => f.write_str("Instructions"),
            Self::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Self::StringList(_) => f.write_str("StringList"),
            Self::Skills(_) => f.write_str("Skills"),
            Self::Mcp(_) => f.write_str("Mcp"),
            Self::Lsp(_) => f.write_str("Lsp"),
        }
    }
}

pub struct SettingsCx {
    pub config_path: PathBuf,
    /// Path to the cockpit-only config keys. Same `config.json` as
    /// [`config_path`](Self::config_path) (GOALS §2a) — the provider/model
    /// keys and the former-`ExtendedConfig` keys share one file. Loaded
    /// lazily when the UI / Tools pages open; saved on each edit there.
    pub(super) extended_path: PathBuf,
    scroll_states: SettingsScrollStates,
    /// Cached config state; reloaded on entry into the Providers list
    /// and after each successful save.
    pub(super) config: ProvidersConfig,
    /// Snapshot loaded when the dialog opened or last saved. Used to merge only
    /// keys this dialog changed over a fresh disk read.
    original_config: ProvidersConfig,
    /// Cached cockpit-only `config.json` state. Read by the UI page and the
    /// Tools page; written back on each edit.
    pub(super) extended: ExtendedConfig,
    /// Malformed known extended-config fields skipped during the most
    /// recent load. Unknown raw keys are preserved separately by
    /// [`ExtendedConfigDoc`].
    pub(super) extended_warnings: Vec<String>,
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
    pub(super) env_lookup: fn(&str) -> Option<String>,
    pub(super) credential_store_path: Option<PathBuf>,
    /// Disclosure produced when a provider save moved literal header values
    /// into the credential store. Consumed by the provider page's status line.
    pub(super) last_secret_notice: Option<String>,
    pending_daemon_request: Option<Request>,
    pending_oauth_action: Option<OAuthFlowRequest>,
}

fn root_page(cursor: usize) -> PageBox {
    Box::new(RootPage { cursor })
}

fn agents_page(page: AgentsPage) -> PageBox {
    Box::new(page)
}

fn tools_page(page: ToolsPage) -> PageBox {
    Box::new(page)
}

fn harnesses_page(page: HarnessesPage) -> PageBox {
    Box::new(page)
}

fn providers_page(page: ProvidersPage) -> PageBox {
    Box::new(page)
}

fn category_page(page: CategoryPage) -> PageBox {
    Box::new(page)
}

fn instructions_page(page: InstructionsPage) -> PageBox {
    Box::new(page)
}

fn redact_patterns_page(page: RedactPatternsPage) -> PageBox {
    Box::new(page)
}

fn string_list_page(page: StringListPage) -> PageBox {
    Box::new(page)
}

fn skills_page(page: SkillsPage) -> PageBox {
    Box::new(page)
}

fn mcp_page(page: McpPage) -> PageBox {
    Box::new(page)
}

fn lsp_page(page: LspPage) -> PageBox {
    Box::new(page)
}

#[cfg(test)]
use crate::daemon::proto::LspControlAction;
use agents_page::AgentsPage;
use category::{Category, CategoryPage};
use harnesses_page::HarnessesPage;
use lsp_page::LspPage;
#[cfg(test)]
use lsp_page::{
    LSP_NAV_ROWS, LSP_SERVER_ROW_START, LspEdit, LspRow, PROJECT_CONTEXT_UNAVAILABLE,
    ProjectContext, lsp_rows, lsp_selected_line_for_cursor, project_context_for_config, row_index,
};
use mcp_page::McpPage;
pub(crate) use mcp_page::row_color as mcp_row_color;
use providers::{AddState, EditState, ProvidersPage};
pub(crate) use providers::{
    GrokBrowserStart, OAuthBeginResult, OAuthEffects, OAuthFlowOp, OAuthFlowRequest, OAuthProvider,
    prepare_grok_browser_start,
};
use reset::ResetButton;
use skills_page::SkillsPage;
use string_list::StringListPage;
use tools_page::ToolsPage;

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

/// Navigation intent returned by a settings page. Page handlers return boxed
/// pages to keep the outer dialog as the only owner of stack mutation.
pub(super) enum Nav {
    /// Stay on the current page; sub-state mutations have already been
    /// applied to the borrowed `&mut SubState`.
    Stay,
    /// Navigate without preserving the current page.
    Replace(PageBox),
    /// Push the current page and navigate to another page.
    Push(PageBox),
    /// Pop one page from the navigation stack.
    Back,
    /// Close the whole dialog.
    Close,
}

// ── Dialog top-level ─────────────────────────────────────────────────────

impl Dialog {
    pub fn is_active(&self) -> bool {
        !matches!(self, Dialog::None)
    }

    pub fn is_workspace_trust(&self) -> bool {
        matches!(self, Dialog::WorkspaceTrust { .. })
    }

    #[cfg(test)]
    pub(crate) fn test_page_name(&self) -> Option<&'static str> {
        match self {
            Dialog::Settings(settings) => Some(settings.page.test_name()),
            Dialog::WorkspaceTrust { .. } => Some("workspace_trust"),
            Dialog::WizardMenu { .. } => Some("wizard_menu"),
            Dialog::SetupWizard(wizard) => Some(wizard.run.descriptor().id),
            Dialog::FirstRunComplete => Some("first_run_complete"),
            _ => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_provider_surface(&self) -> Option<&'static str> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        let page = settings.page.as_any().downcast_ref::<ProvidersPage>()?;
        Some(match page {
            ProvidersPage::OAuthSetup { .. } => "oauth",
            ProvidersPage::Edit(_) => "edit",
            _ => "other",
        })
    }

    #[cfg(test)]
    pub(crate) fn test_provider_is_add(&self) -> bool {
        let Dialog::Settings(settings) = self else {
            return false;
        };
        matches!(
            settings.page.as_any().downcast_ref::<ProvidersPage>(),
            Some(ProvidersPage::Add(_))
        )
    }

    #[cfg(test)]
    pub(crate) fn test_mark_provider_add_done(&mut self, provider_id: &str) {
        let Dialog::Settings(settings) = self else {
            panic!("expected settings dialog");
        };
        let page = settings
            .page
            .downcast_mut::<ProvidersPage>()
            .expect("expected providers page");
        let ProvidersPage::Add(add) = page else {
            panic!("expected provider add page");
        };
        add.saved_provider_id = Some(provider_id.to_string());
        add.run
            .return_to("done")
            .expect("provider done step exists");
    }

    #[cfg(test)]
    pub(crate) fn test_setup_answer(&self, step_id: &str) -> Option<crate::wizard::WizardAnswer> {
        let Dialog::SetupWizard(wizard) = self else {
            return None;
        };
        wizard.run.answer(step_id).cloned()
    }

    #[cfg(test)]
    pub(crate) fn test_setup_prefill(&self) -> Option<crate::wizard::WizardAnswer> {
        let Dialog::SetupWizard(wizard) = self else {
            return None;
        };
        wizard.run.prefill()
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

    pub fn open_workspace_trust(root: crate::config::trust::TrustRoot) -> Self {
        Dialog::WorkspaceTrust {
            root,
            cursor: 0,
            chosen: None,
        }
    }

    pub fn take_workspace_trust_choice(
        &mut self,
    ) -> Option<(
        crate::config::trust::TrustRoot,
        crate::db::workspace_trust::WorkspaceTrustMode,
    )> {
        let Dialog::WorkspaceTrust { root, chosen, .. } = self else {
            return None;
        };
        chosen.take().map(|mode| (root.clone(), mode))
    }

    /// Open directly into the MCP page (`/mcp settings`, GOALS §18a).
    pub fn open_mcp(cwd: &std::path::Path) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join(CONFIG_FILE);
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
            let path = dir.path.join(CONFIG_FILE);
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
        if let Some(g) = glob.filter(|g| !g.trim().is_empty()) {
            s.quick_add_gitignore_allow(g);
        }
        s.enter_gitignore_allow();
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
        Self::open_providers_add_with_status(cwd, None)
    }

    pub fn open_providers_add_with_status(cwd: &std::path::Path, status: Option<String>) -> Self {
        let mut d = Self::open(cwd);
        if let Dialog::PickConfig { dirs, .. } = &d
            && let Some(dir) = dirs.first()
        {
            let path = dir.path.join(CONFIG_FILE);
            let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
            let mut add = AddState::new();
            add.error = status;
            s.page = providers_page(ProvidersPage::Add(add));
            d = Dialog::Settings(Box::new(s));
        }
        d
    }

    pub fn open_setup(cwd: &std::path::Path) -> Self {
        Dialog::WizardMenu {
            wizards: crate::wizard::registry(),
            cursor: 0,
            cwd: cwd.to_path_buf(),
        }
    }

    pub fn open_setup_wizard(cwd: &std::path::Path, wizard_id: &str) -> Result<Self, String> {
        match wizard_id {
            crate::wizard::PROVIDER_WIZARD_ID => Ok(Self::open_providers_add(cwd)),
            crate::wizard::SECURITY_WIZARD_ID | crate::wizard::MODEL_WIZARD_ID => {
                let descriptor = crate::commands::setup::descriptor_for_cwd(wizard_id, cwd)
                    .ok_or_else(|| format!("unknown setup wizard `{wizard_id}`"))?;
                setup_wizard_dialog(cwd, descriptor, None)
            }
            other => Err(format!("unknown setup wizard `{other}`")),
        }
    }

    pub fn open_model_setup_preselected(
        cwd: &std::path::Path,
        provider_id: &str,
        model_id: &str,
        status: Option<String>,
    ) -> Result<Self, String> {
        let descriptor =
            crate::commands::setup::model_descriptor_for_cwd(cwd, Some((provider_id, model_id)));
        setup_wizard_dialog(cwd, descriptor, status)
    }

    pub fn open_first_run_complete() -> Self {
        Dialog::FirstRunComplete
    }

    pub fn take_completed_provider_id(&mut self) -> Option<String> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        let page = settings.page.downcast_mut::<ProvidersPage>()?;
        let ProvidersPage::Add(add) = page else {
            return None;
        };
        if add.run.is_complete() || add.is_step("done") {
            return add.saved_provider_id.clone();
        }
        None
    }

    pub fn setup_wizard_is_complete(&self, wizard_id: &str) -> bool {
        matches!(
            self,
            Dialog::SetupWizard(wizard)
                if wizard.run.descriptor().id == wizard_id && wizard.run.is_complete()
        )
    }

    /// Open directly on one configured provider. OAuth-expired failures for a
    /// known OAuth template land in its login flow; custom/template-less
    /// providers land on the ordinary edit page.
    pub fn open_provider_settings(
        cwd: &std::path::Path,
        provider_id: &str,
        oauth_expired: bool,
    ) -> Self {
        let cfg = crate::secret_ref::load_effective(cwd);
        let Some(entry) = cfg.providers.get(provider_id).cloned() else {
            return Self::open(cwd);
        };
        let Some(path) = config_write_target_for_provider(cwd, provider_id) else {
            return Self::open(cwd);
        };
        let mut settings = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
        let parent = EditState::new(provider_id.to_string(), entry.clone());
        let oauth_provider = if oauth_expired {
            match entry.effective_template(provider_id) {
                Some(crate::auth::codex_oauth::CREDENTIAL_KEY | "codex") => {
                    Some(OAuthProvider::Codex)
                }
                Some(crate::auth::xai_oauth::CREDENTIAL_KEY | "grok") => Some(OAuthProvider::Grok),
                _ => None,
            }
        } else {
            None
        };
        settings.page = if let Some(provider) = oauth_provider {
            providers_page(ProvidersPage::OAuthSetup {
                state: Box::new(providers::OAuthFlowState::new(provider)),
                parent: Box::new(parent),
            })
        } else {
            providers_page(ProvidersPage::Edit(parent))
        };
        Dialog::Settings(Box::new(settings))
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
        s.page
            .downcast_mut::<CategoryPage>()
            .and_then(|p| p.pending_mouse_capture.take())
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
        s.page
            .downcast_mut::<AgentsPage>()
            .and_then(|p| p.pending_external_edit.take())
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
        if let Some(p) = s.page.downcast_mut::<AgentsPage>() {
            p.finish_external_edit(&cwd, editor_error);
        }
    }

    /// Drain a pending category setting `$EDITOR` request. The category page
    /// retains the temp path until [`Self::finish_category_setting_edit`] reads
    /// it back and drops it.
    pub fn take_pending_category_setting_edit(&mut self) -> Option<PathBuf> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        s.take_pending_category_external_edit()
    }

    /// Apply the result of a category-setting `$EDITOR` round trip.
    pub fn finish_category_setting_edit(&mut self, editor_error: Option<String>) {
        let Dialog::Settings(s) = self else {
            return;
        };
        s.finish_category_external_edit(editor_error);
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
            Dialog::FirstRunComplete => {
                matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'))
            }
            Dialog::WorkspaceTrust { cursor, chosen, .. } => {
                match workspace_trust_key_action(key, cursor) {
                    WorkspaceTrustAction::Stay => false,
                    WorkspaceTrustAction::Choose(mode) => {
                        *chosen = Some(mode);
                        true
                    }
                }
            }
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
                        let chosen = dirs[idx].path.join(CONFIG_FILE);
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
            Dialog::WizardMenu {
                wizards,
                cursor,
                cwd,
            } => match list_key_action(key, cursor, wizards.len()) {
                ListAction::Stay => false,
                ListAction::Close => true,
                ListAction::Select(idx) => {
                    let wizard_id = wizards[idx].id;
                    match Self::open_setup_wizard(cwd, wizard_id) {
                        Ok(dialog) => *self = dialog,
                        Err(_) => *self = Dialog::open(cwd),
                    }
                    false
                }
            },
            Dialog::SetupWizard(wizard) => handle_setup_wizard_key(wizard, key),
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

    pub fn take_oauth_action(&mut self) -> Option<OAuthFlowRequest> {
        match self {
            Dialog::Settings(s) => s.pending_oauth_action.take(),
            _ => None,
        }
    }

    pub fn apply_oauth_begin(&mut self, provider: OAuthProvider, result: OAuthBeginResult) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_begin(provider, result);
        }
    }

    pub fn apply_oauth_complete(&mut self, provider: OAuthProvider, result: Result<bool, String>) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_complete(provider, result);
        }
    }

    pub fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        match self {
            Dialog::None => {}
            Dialog::WorkspaceTrust { root, cursor, .. } => {
                render_workspace_trust(frame, area, root, *cursor)
            }
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
            Dialog::WizardMenu {
                wizards, cursor, ..
            } => render_wizard_menu(frame, area, wizards, *cursor),
            Dialog::SetupWizard(wizard) => render_setup_wizard(frame, area, wizard),
            Dialog::FirstRunComplete => render_first_run_complete(frame, area),
            Dialog::Settings(s) => s.render(frame, area, links),
        }
    }
}

// ── SettingsDialog ───────────────────────────────────────────────────────

impl SettingsDialog {
    #[cfg(test)]
    fn set_test_page(&mut self, page: Page) {
        self.page = boxed_page(page);
    }

    #[cfg(test)]
    fn test_page(&self) -> TestPageRef<'_> {
        if let Some(p) = self.page.downcast_ref::<RootPage>() {
            return TestPageRef::Root { cursor: p.cursor };
        }
        if let Some(p) = self.page.downcast_ref::<AgentsPage>() {
            return TestPageRef::Agents(p);
        }
        if let Some(p) = self.page.downcast_ref::<ToolsPage>() {
            return TestPageRef::Tools(p);
        }
        if let Some(p) = self.page.downcast_ref::<HarnessesPage>() {
            return TestPageRef::Harnesses(p);
        }
        if let Some(p) = self.page.downcast_ref::<ProvidersPage>() {
            return TestPageRef::Providers(p);
        }
        if let Some(p) = self.page.downcast_ref::<CategoryPage>() {
            return TestPageRef::Category(p);
        }
        if let Some(p) = self.page.downcast_ref::<InstructionsPage>() {
            return TestPageRef::Instructions(p);
        }
        if let Some(p) = self.page.downcast_ref::<RedactPatternsPage>() {
            return TestPageRef::RedactPatterns(p);
        }
        if let Some(p) = self.page.downcast_ref::<StringListPage>() {
            return TestPageRef::StringList(p);
        }
        if let Some(p) = self.page.downcast_ref::<SkillsPage>() {
            return TestPageRef::Skills(p);
        }
        if let Some(p) = self.page.downcast_ref::<McpPage>() {
            return TestPageRef::Mcp(p);
        }
        if let Some(p) = self.page.downcast_ref::<LspPage>() {
            return TestPageRef::Lsp(p);
        }
        unreachable!("unknown settings page")
    }

    #[cfg(test)]
    fn test_page_mut(&mut self) -> TestPageMut<'_> {
        if self.page.as_any().is::<RootPage>() {
            let p = self.page.downcast_mut::<RootPage>().unwrap();
            return TestPageMut::Root {
                cursor: &mut p.cursor,
            };
        }
        if self.page.as_any().is::<AgentsPage>() {
            return TestPageMut::Agents(self.page.downcast_mut::<AgentsPage>().unwrap());
        }
        if self.page.as_any().is::<ToolsPage>() {
            return TestPageMut::Tools(self.page.downcast_mut::<ToolsPage>().unwrap());
        }
        if self.page.as_any().is::<HarnessesPage>() {
            return TestPageMut::Harnesses(self.page.downcast_mut::<HarnessesPage>().unwrap());
        }
        if self.page.as_any().is::<ProvidersPage>() {
            return TestPageMut::Providers(self.page.downcast_mut::<ProvidersPage>().unwrap());
        }
        if self.page.as_any().is::<CategoryPage>() {
            return TestPageMut::Category(self.page.downcast_mut::<CategoryPage>().unwrap());
        }
        if self.page.as_any().is::<InstructionsPage>() {
            return TestPageMut::Instructions(
                self.page.downcast_mut::<InstructionsPage>().unwrap(),
            );
        }
        if self.page.as_any().is::<RedactPatternsPage>() {
            return TestPageMut::RedactPatterns(
                self.page.downcast_mut::<RedactPatternsPage>().unwrap(),
            );
        }
        if self.page.as_any().is::<StringListPage>() {
            return TestPageMut::StringList(self.page.downcast_mut::<StringListPage>().unwrap());
        }
        if self.page.as_any().is::<SkillsPage>() {
            return TestPageMut::Skills(self.page.downcast_mut::<SkillsPage>().unwrap());
        }
        if self.page.as_any().is::<McpPage>() {
            return TestPageMut::Mcp(self.page.downcast_mut::<McpPage>().unwrap());
        }
        if self.page.as_any().is::<LspPage>() {
            return TestPageMut::Lsp(self.page.downcast_mut::<LspPage>().unwrap());
        }
        unreachable!("unknown settings page")
    }
}

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
            page: root_page(0),
            stack: Vec::new(),
            cx: SettingsCx {
                config_path,
                extended_path,
                scroll_states: SettingsScrollStates::default(),
                original_config: config.clone(),
                config,
                extended,
                extended_warnings,
                picker_cwd: None,
                active_project_root: None,
                back_to_picker: false,
                command_installed: |cmd| crate::harness::preflight::which_on_path(cmd).is_some(),
                env_lookup: |name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()),
                credential_store_path: None,
                last_secret_notice: None,
                pending_daemon_request: None,
                pending_oauth_action: None,
            },
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
        self.page = providers_page(ProvidersPage::List {
            cursor: providers::initial_list_cursor(&self.config),
            status: None,
            delete_pending: false,
        });
    }

    /// Enter a reorganized category page, reloading the cached
    /// extended-config first so the rows reflect on-disk state.
    fn enter_category(&mut self, category: Category) {
        self.reload_extended();
        self.page = category_page(CategoryPage::new(category));
    }

    /// Navigate to the active model's model-settings sub-dialog
    /// (implementation note). Falls back to the providers
    /// list with an inline status when no model is active or the active
    /// (provider, model) can't be found.
    fn enter_model_settings(&mut self) {
        self.page = providers_page(providers::active_model_settings_page(&self.config));
    }

    fn save_config(&mut self) -> Result<(), String> {
        let mut doc = ConfigDoc::load(&self.config_path).map_err(|e| e.to_string())?;
        let mut merged = doc.providers();
        merge_dialog_provider_config(&mut merged, &self.original_config, &self.config);
        let notice = crate::secret_ref::protect_literal_headers(
            &mut merged.providers,
            self.credential_store_path.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        doc.write(&merged).map_err(|e| e.to_string())?;
        self.config = merged.clone();
        self.original_config = merged;
        self.last_secret_notice = notice.map(|notice| notice.render());
        Ok(())
    }

    fn delete_provider_and_stored_secrets(
        &mut self,
        provider_id: &str,
        delete_stored_secrets: bool,
    ) -> Result<usize, String> {
        let mut names = self
            .config
            .providers
            .get(provider_id)
            .into_iter()
            .flat_map(|provider| &provider.headers)
            .flat_map(|header| crate::envref::referenced_names(&header.value))
            .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
            .collect::<std::collections::BTreeSet<_>>();
        let mut credential_refs = self
            .config
            .providers
            .get(provider_id)
            .into_iter()
            .filter(|provider| provider.auth == Some(AuthKind::OAuth))
            .filter_map(|provider| provider.credential_ref.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for (other_id, provider) in &self.config.providers {
            if other_id == provider_id {
                continue;
            }
            for name in provider
                .headers
                .iter()
                .flat_map(|header| crate::envref::referenced_names(&header.value))
                .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
            {
                names.remove(&name);
            }
            if let Some(credential_ref) = provider.credential_ref.as_deref() {
                credential_refs.remove(credential_ref);
            }
        }

        if !delete_stored_secrets {
            names.clear();
        }

        self.config.providers.remove(provider_id);
        self.save_config()?;
        if names.is_empty() && credential_refs.is_empty() {
            return Ok(0);
        }

        let mut store = match &self.credential_store_path {
            Some(path) => crate::credentials::CredentialStore::open(path.clone()),
            None => crate::credentials::CredentialStore::open_default(),
        }
        .map_err(|error| format!("provider deleted; stored-secret cleanup failed: {error}"))?;
        for name in &names {
            store.remove_named_secret(name);
        }
        for credential_ref in &credential_refs {
            store.remove(credential_ref);
        }
        store
            .save()
            .map_err(|error| format!("provider deleted; stored-secret cleanup failed: {error}"))?;
        Ok(names.len() + credential_refs.len())
    }

    fn tick(&mut self) {
        let pending = self
            .page
            .downcast_mut::<ProvidersPage>()
            .and_then(|page| match page {
                ProvidersPage::Add(s) => s.fetch.clone(),
                ProvidersPage::Edit(s) => s.fetch.clone(),
                ProvidersPage::Headers { parent, .. } => parent.fetch.clone(),
                ProvidersPage::Models { parent, .. } => parent.fetch.clone(),
                ProvidersPage::ModelSettings { parent, .. } => parent.fetch.clone(),
                ProvidersPage::ProviderSettings { parent, .. } => parent.fetch.clone(),
                _ => None,
            });
        if let Some(handle) = pending
            && let Some(result) = handle.take()
        {
            self.apply_fetch_result(&handle.provider_id, result);
        }

        self.drain_fetch_all();
        if let Some(page) = self.page.downcast_mut::<ProvidersPage>() {
            match page {
                ProvidersPage::OAuthSetup { state, .. } if state.pending || state.polling => {
                    state.spinner_tick = state.spinner_tick.wrapping_add(1);
                }
                ProvidersPage::Add(state)
                    if state
                        .oauth_auth
                        .as_ref()
                        .is_some_and(|oauth| oauth.pending || oauth.polling) =>
                {
                    let oauth = state.oauth_auth.as_mut().expect("guarded OAuth state");
                    oauth.spinner_tick = oauth.spinner_tick.wrapping_add(1);
                }
                _ => {}
            }
        }
    }

    fn apply_oauth_begin(&mut self, provider: OAuthProvider, result: OAuthBeginResult) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        self.pending_oauth_action =
            state.apply_begin(result, providers::OAuthEffects::production());
    }

    fn apply_oauth_complete(&mut self, provider: OAuthProvider, result: Result<bool, String>) {
        let Some(state) = self.oauth_flow_state_mut(provider) else {
            return;
        };
        state.apply_complete(result);
    }

    fn oauth_flow_state_mut(
        &mut self,
        provider: OAuthProvider,
    ) -> Option<&mut providers::OAuthFlowState> {
        let page = self.page.downcast_mut::<ProvidersPage>()?;
        match page {
            ProvidersPage::OAuthSetup { state, .. } if state.provider == provider => Some(state),
            ProvidersPage::Add(add)
                if add
                    .oauth_auth
                    .as_ref()
                    .is_some_and(|state| state.provider == provider) =>
            {
                add.oauth_auth.as_deref_mut()
            }
            _ => None,
        }
    }

    /// True while a header or model add/edit popup or its browsing list
    /// is on screen — those editors own `Tab`/`Shift+Tab` themselves (the
    /// popup switches between fields; the browse list treats Tab as ↓), so
    /// the field-nav rewrite in [`Self::handle_key`] must leave them alone.
    fn in_header_editor(&self) -> bool {
        let Some(page) = self.page.downcast_ref::<ProvidersPage>() else {
            return false;
        };
        match page {
            ProvidersPage::Headers { .. } | ProvidersPage::Models { .. } => true,
            ProvidersPage::Add(s) => s.is_step("headers"),
            _ => false,
        }
    }

    /// True while a category page is inline-editing the packages-dir field —
    /// there Tab accepts a directory suggestion, so the field-nav Tab→Down
    /// rewrite in [`Self::handle_key`] must leave Tab alone.
    fn in_pkg_dir_autosuggest(&self) -> bool {
        self.page
            .downcast_ref::<CategoryPage>()
            .is_some_and(|p| p.is_path_editing())
    }

    /// Insert pasted text into the page's focused text field, mirroring the
    /// focus logic of each page's key handler so the paste lands in the same
    /// buffer a typed char would. Pages with no open field (or no field at
    /// all) drop the paste.
    fn paste(&mut self, text: &str) {
        let cwd = self.agents_cwd();
        if let Some(p) = self.page.downcast_mut::<ProvidersPage>() {
            if p.paste_oauth(text) {
                return;
            }
            if let Some(field) = p.active_text_field() {
                field.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<AgentsPage>() {
            if let Some(editor) = p.editing.as_mut() {
                editor.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<ToolsPage>() {
            if p.editing.is_some() {
                p.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<HarnessesPage>() {
            match p {
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
            }
        } else if let Some(p) = self.page.downcast_mut::<CategoryPage>() {
            if let Some(editor) = p.path_editor.as_mut() {
                editor.paste(text, &cwd);
            } else if let Some(editor) = p.text_editor.as_mut() {
                editor.paste(text);
            } else if let Some(picker) = p.utility_picker.as_mut() {
                if let Some(field) = picker.active_text_field() {
                    field.paste(text);
                }
            } else if p.editing.is_some() {
                p.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<InstructionsPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<RedactPatternsPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<StringListPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<SkillsPage>() {
            if let Some(g) = p.grabbed.as_mut() {
                g.buf.paste(text);
            }
        } else if let Some(p) = self.page.downcast_mut::<McpPage>() {
            if let mcp_page::McpPage::Add(s) = p {
                mcp_page::paste_into_add_state(s, text);
            }
        } else if let Some(p) = self.page.downcast_mut::<LspPage>()
            && p.editing.is_some()
        {
            p.buf.paste(text);
        }
    }

    fn apply_nav(&mut self, nav: Nav) -> bool {
        match nav {
            Nav::Stay => false,
            Nav::Replace(new) => {
                self.page = new;
                false
            }
            Nav::Push(new) => {
                let current = std::mem::replace(&mut self.page, new);
                self.stack.push(current);
                false
            }
            Nav::Back => {
                self.page = self.stack.pop().unwrap_or_else(|| root_page(0));
                false
            }
            Nav::Close => true,
        }
    }

    fn handle_key(&mut self, key: KeyEvent) -> bool {
        // Tab / Shift+Tab move between fields like ↓/↑ across settings
        // screens. Editors that own Tab themselves opt out through page state.
        let key = if self.in_header_editor() || self.in_pkg_dir_autosuggest() {
            key
        } else {
            match key.code {
                KeyCode::Tab => KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
                KeyCode::BackTab => KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
                _ => key,
            }
        };
        let nav = self.page.handle_key(&mut self.cx, key);
        self.apply_nav(nav)
    }

    fn enter_mcp(&mut self) {
        self.page = mcp_page(mcp_page::McpPage::List(mcp_page::ListState {
            cursor: 0,
            status: None,
            delete_pending: false,
        }));
    }

    fn enter_gitignore_allow(&mut self) {
        self.cx.reload_extended();
        self.page = string_list_page(StringListPage::gitignore_allow());
    }

    fn take_pending_category_external_edit(&mut self) -> Option<PathBuf> {
        self.page
            .downcast_mut::<CategoryPage>()
            .and_then(|p| p.pending_external_edit.as_mut()?.service_path())
    }

    fn finish_category_external_edit(&mut self, editor_error: Option<String>) {
        let Some(p) = self.page.downcast_mut::<CategoryPage>() else {
            return;
        };
        self.cx.finish_category_page_external_edit(p, editor_error);
    }

    // ── Rendering ────────────────────────────────────────────────────────

    fn render(&self, frame: &mut Frame, area: Rect, links: &mut crate::tui::links::LinkRegistry) {
        let title = self.title();
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Settings — {title} "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        self.page
            .render_with_links(&self.cx, frame, layout[0], links);
        if let Some(cursor) = shell::park_cursor_from_markers(frame, layout[0]) {
            frame.set_cursor_position(cursor);
        }
        frame.render_widget(help_line(self.help_text()), layout[1]);
    }

    fn title(&self) -> String {
        self.page.title(&self.cx)
    }

    fn help_text(&self) -> &'static str {
        self.page.help_text(&self.cx)
    }
}

impl SettingsPage for RootPage {
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        let children = root_nodes();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return Nav::Close,
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace if cx.picker_cwd.is_some() => {
                cx.back_to_picker = true;
                return Nav::Close;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, children.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.cursor = crate::tui::nav::wrap_next(self.cursor, children.len());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let chosen = children.get(self.cursor).map(|n| n.title).unwrap_or("");
                let next = match chosen {
                    PROVIDERS_TITLE => Some(providers_page(ProvidersPage::List {
                        cursor: providers::initial_list_cursor(&cx.config),
                        status: None,
                        delete_pending: false,
                    })),
                    "Agents" => Some(agents_page(AgentsPage::new(&cx.agents_cwd()))),
                    "Interface" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Interface)))
                    }
                    "Behavior" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Behavior)))
                    }
                    "Privacy & Safety" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Privacy)))
                    }
                    "Translation" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Translation)))
                    }
                    "Profile" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Profile)))
                    }
                    "Tools" => {
                        cx.reload_extended();
                        Some(tools_page(ToolsPage {
                            cursor: 0,
                            setup: None,
                            editing: None,
                            buf: TextField::default(),
                            edit_target: None,
                            status: None,
                            reset: ResetButton::default(),
                        }))
                    }
                    "Harnesses" => {
                        cx.reload_extended();
                        let status = cx.extended_warnings.first().cloned();
                        Some(harnesses_page(harnesses_page::HarnessesPage::List(
                            harnesses_page::ListState {
                                cursor: 0,
                                status,
                                delete_pending: false,
                                reset: ResetButton::default(),
                                adding: None,
                            },
                        )))
                    }
                    "Skills" => {
                        cx.reload_extended();
                        Some(skills_page(skills_page::SkillsPage {
                            cursor: 0,
                            grabbed: None,
                            status: None,
                            reset: ResetButton::default(),
                        }))
                    }
                    "MCP" => Some(mcp_page(mcp_page::McpPage::List(mcp_page::ListState {
                        cursor: 0,
                        status: None,
                        delete_pending: false,
                    }))),
                    "LSP" => {
                        cx.reload_extended();
                        Some(lsp_page(LspPage {
                            cursor: 0,
                            editing: None,
                            buf: TextField::default(),
                            status: None,
                            reset: ResetButton::default(),
                        }))
                    }
                    _ => None,
                };
                if let Some(next) = next {
                    return Nav::Push(next);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        render_root(frame, area, self.cursor, &cx.scroll_states);
    }

    fn title(&self, cx: &SettingsCx) -> String {
        crate::welcome::display_path(&cx.config_path)
    }

    fn help_text(&self, cx: &SettingsCx) -> &'static str {
        if cx.picker_cwd.is_some() {
            "↑/↓/Tab/Shift+Tab  enter: open  h: back to picker  esc/q: close"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: open  esc/q: close"
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Root"
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

fn render_root(frame: &mut Frame, area: Rect, cursor: usize, scroll_states: &SettingsScrollStates) {
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
    scroll_states.render_lines(frame, rows[0], "root", list_lines, Some(cursor));

    let desc = children[cursor].description;
    frame.render_widget(
        Paragraph::new(desc.to_string())
            .wrap(Wrap { trim: false })
            .style(muted_style()),
        rows[2],
    );
}

impl SettingsCx {
    fn reload_extended(&mut self) {
        if let Ok(doc) = ExtendedConfigDoc::load(&self.extended_path) {
            let (extended, warnings) = doc.config_with_warnings();
            self.extended = extended;
            self.extended_warnings = warnings;
        }
    }

    pub(super) fn save_extended(&mut self) -> Result<(), String> {
        let mut doc = ExtendedConfigDoc::load(&self.extended_path).map_err(|e| e.to_string())?;
        doc.write(&self.extended).map_err(|e| e.to_string())?;
        Ok(())
    }

    fn save_config(&mut self) -> Result<(), String> {
        let mut doc = ConfigDoc::load(&self.config_path).map_err(|e| e.to_string())?;
        let mut merged = doc.providers();
        merge_dialog_provider_config(&mut merged, &self.original_config, &self.config);
        let notice = crate::secret_ref::protect_literal_headers(
            &mut merged.providers,
            self.credential_store_path.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        doc.write(&merged).map_err(|e| e.to_string())?;
        self.config = merged.clone();
        self.original_config = merged;
        self.last_secret_notice = notice.map(|notice| notice.render());
        Ok(())
    }

    fn delete_provider_and_stored_secrets(
        &mut self,
        provider_id: &str,
        delete_stored_secrets: bool,
    ) -> Result<usize, String> {
        let mut names = self
            .config
            .providers
            .get(provider_id)
            .into_iter()
            .flat_map(|provider| &provider.headers)
            .flat_map(|header| crate::envref::referenced_names(&header.value))
            .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
            .collect::<std::collections::BTreeSet<_>>();
        let mut credential_refs = self
            .config
            .providers
            .get(provider_id)
            .into_iter()
            .filter(|provider| provider.auth == Some(AuthKind::OAuth))
            .filter_map(|provider| provider.credential_ref.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for (other_id, provider) in &self.config.providers {
            if other_id == provider_id {
                continue;
            }
            for name in provider
                .headers
                .iter()
                .flat_map(|header| crate::envref::referenced_names(&header.value))
                .filter_map(|name| name.strip_prefix("secret:").map(str::to_string))
            {
                names.remove(&name);
            }
            if let Some(credential_ref) = provider.credential_ref.as_deref() {
                credential_refs.remove(credential_ref);
            }
        }

        if !delete_stored_secrets {
            names.clear();
        }

        self.config.providers.remove(provider_id);
        self.save_config()?;
        if names.is_empty() && credential_refs.is_empty() {
            return Ok(0);
        }

        let mut store = match &self.credential_store_path {
            Some(path) => crate::credentials::CredentialStore::open(path.clone()),
            None => crate::credentials::CredentialStore::open_default(),
        }
        .map_err(|error| format!("provider deleted; stored-secret cleanup failed: {error}"))?;
        for name in &names {
            store.remove_named_secret(name);
        }
        for credential_ref in &credential_refs {
            store.remove(credential_ref);
        }
        store
            .save()
            .map_err(|error| format!("provider deleted; stored-secret cleanup failed: {error}"))?;
        Ok(names.len() + credential_refs.len())
    }
}

fn merge_dialog_provider_config(
    disk: &mut ProvidersConfig,
    original: &ProvidersConfig,
    current: &ProvidersConfig,
) {
    if current.active_model != original.active_model {
        disk.active_model = current.active_model.clone();
    }
    if current.category_defaults != original.category_defaults {
        disk.category_defaults = current.category_defaults.clone();
    }
    if current.on_unlisted_models_fetch != original.on_unlisted_models_fetch {
        disk.on_unlisted_models_fetch = current.on_unlisted_models_fetch;
    }

    for provider_id in original.providers.keys() {
        if !current.providers.contains_key(provider_id) {
            disk.providers.remove(provider_id);
        }
    }
    for (provider_id, entry) in &current.providers {
        let original_entry = original.providers.get(provider_id);
        if original_entry.is_none_or(|old| !provider_entries_equal(old, entry)) {
            disk.providers.insert(provider_id.clone(), entry.clone());
        }
    }
}

fn provider_entries_equal(left: &ProviderEntry, right: &ProviderEntry) -> bool {
    match (serde_json::to_value(left), serde_json::to_value(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn handle_setup_wizard_key(wizard: &mut SetupWizardDialog, key: KeyEvent) -> bool {
    let SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        cwd,
        status,
    } = wizard;
    if run.is_complete() {
        return matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'));
    }
    let Some(step) = run.current_step().cloned() else {
        return false;
    };
    match step.kind {
        crate::wizard::StepKind::Select { options } => {
            match list_key_action(key, cursor, options.len()) {
                ListAction::Close => return true,
                ListAction::Stay => {}
                ListAction::Select(index) => {
                    submit_setup_wizard_answer(
                        run,
                        cursor,
                        text,
                        multi,
                        multi_touched,
                        status,
                        crate::wizard::WizardAnswer::Select(options[index].id.to_string()),
                    );
                }
            }
        }
        crate::wizard::StepKind::Confirm => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                let answer = run
                    .prefill()
                    .unwrap_or(crate::wizard::WizardAnswer::Confirm(false));
                submit_setup_wizard_answer(run, cursor, text, multi, multi_touched, status, answer);
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => submit_setup_wizard_answer(
                run,
                cursor,
                text,
                multi,
                multi_touched,
                status,
                crate::wizard::WizardAnswer::Confirm(true),
            ),
            KeyCode::Char('n') | KeyCode::Char('N') => submit_setup_wizard_answer(
                run,
                cursor,
                text,
                multi,
                multi_touched,
                status,
                crate::wizard::WizardAnswer::Confirm(false),
            ),
            _ => {}
        },
        crate::wizard::StepKind::Text => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                submit_setup_wizard_answer(
                    run,
                    cursor,
                    text,
                    multi,
                    multi_touched,
                    status,
                    crate::wizard::WizardAnswer::Text(text.text().to_string()),
                );
            }
            _ => {
                text.handle_key(key);
            }
        },
        crate::wizard::StepKind::Info => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                submit_setup_wizard_answer(
                    run,
                    cursor,
                    text,
                    multi,
                    multi_touched,
                    status,
                    crate::wizard::WizardAnswer::Acknowledged,
                );
            }
            _ => {}
        },
        crate::wizard::StepKind::Action { .. } => {
            if step.id == "security-save" {
                match crate::commands::setup::apply_security_answers(cwd, run) {
                    Ok(Some(path)) => *status = Some(format!("Saved {}", path.display())),
                    Ok(None) => *status = Some("Security settings unchanged.".to_string()),
                    Err(error) => {
                        *status = Some(error.to_string());
                        return false;
                    }
                }
            } else if step.id == "model-save" {
                match crate::commands::setup::apply_model_answers(cwd, run) {
                    Ok(Some(path)) => *status = Some(format!("Saved {}", path.display())),
                    Ok(None) => *status = Some("Model settings unchanged.".to_string()),
                    Err(error) => {
                        *status = Some(error.to_string());
                        return false;
                    }
                }
            }
            submit_setup_wizard_answer(
                run,
                cursor,
                text,
                multi,
                multi_touched,
                status,
                crate::wizard::WizardAnswer::Acknowledged,
            );
        }
        crate::wizard::StepKind::MultiToggle { options } => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *cursor = crate::tui::nav::wrap_prev(*cursor, options.len());
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *cursor = crate::tui::nav::wrap_next(*cursor, options.len());
            }
            KeyCode::Char(' ') if *cursor < options.len() => {
                if !*multi_touched {
                    multi.clear();
                    if let Some(crate::wizard::WizardAnswer::MultiToggle(values)) = run.prefill() {
                        multi.extend(values);
                    }
                    *multi_touched = true;
                }
                let id = options[*cursor].id.to_string();
                if !multi.remove(&id) {
                    multi.insert(id);
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                let answer = if !*multi_touched
                    && let Some(crate::wizard::WizardAnswer::MultiToggle(values)) = run.prefill()
                {
                    crate::wizard::WizardAnswer::MultiToggle(values)
                } else {
                    crate::wizard::WizardAnswer::MultiToggle(multi.iter().cloned().collect())
                };
                submit_setup_wizard_answer(run, cursor, text, multi, multi_touched, status, answer);
            }
            _ => {}
        },
        crate::wizard::StepKind::Secret => {}
    }
    false
}

fn submit_setup_wizard_answer(
    run: &mut crate::wizard::WizardRun,
    cursor: &mut usize,
    text: &mut TextField,
    multi: &mut std::collections::BTreeSet<String>,
    multi_touched: &mut bool,
    status: &mut Option<String>,
    answer: crate::wizard::WizardAnswer,
) {
    match run.submit(answer) {
        Ok(()) => sync_setup_wizard_inputs(run, cursor, text, multi, multi_touched),
        Err(error) => *status = Some(error),
    }
}

fn sync_setup_wizard_inputs(
    run: &crate::wizard::WizardRun,
    cursor: &mut usize,
    text: &mut TextField,
    multi: &mut std::collections::BTreeSet<String>,
    multi_touched: &mut bool,
) {
    *cursor = setup_wizard_cursor_for_current_prefill(run);
    multi.clear();
    *multi_touched = false;
    let Some(step) = run.current_step() else {
        return;
    };
    match step.kind {
        crate::wizard::StepKind::Text => {
            let value = match run.prefill() {
                Some(crate::wizard::WizardAnswer::Text(value)) => value,
                _ => String::new(),
            };
            text.set(value);
        }
        crate::wizard::StepKind::MultiToggle { .. } => {
            if let Some(crate::wizard::WizardAnswer::MultiToggle(values)) = run.prefill() {
                multi.extend(values);
            }
        }
        _ => {}
    }
}

fn setup_wizard_cursor_for_current_prefill(run: &crate::wizard::WizardRun) -> usize {
    let Some(step) = run.current_step() else {
        return 0;
    };
    let crate::wizard::StepKind::Select { options } = &step.kind else {
        return 0;
    };
    let Some(crate::wizard::WizardAnswer::Select(value)) = run.prefill() else {
        return 0;
    };
    options
        .iter()
        .position(|option| option.id == value)
        .unwrap_or(0)
}

enum WorkspaceTrustAction {
    Stay,
    Choose(crate::db::workspace_trust::WorkspaceTrustMode),
}

fn workspace_trust_key_action(key: KeyEvent, cursor: &mut usize) -> WorkspaceTrustAction {
    use crate::db::workspace_trust::WorkspaceTrustMode;
    const LEN: usize = 3;
    match key.code {
        KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
            *cursor = crate::tui::nav::wrap_prev(*cursor, LEN);
            WorkspaceTrustAction::Stay
        }
        KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
            *cursor = crate::tui::nav::wrap_next(*cursor, LEN);
            WorkspaceTrustAction::Stay
        }
        KeyCode::Char('1') => WorkspaceTrustAction::Choose(WorkspaceTrustMode::Trust),
        KeyCode::Char('2') => WorkspaceTrustAction::Choose(WorkspaceTrustMode::IgnoreConfig),
        KeyCode::Char('3') | KeyCode::Esc => {
            WorkspaceTrustAction::Choose(WorkspaceTrustMode::Untrusted)
        }
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            WorkspaceTrustAction::Choose(match *cursor {
                0 => WorkspaceTrustMode::Trust,
                1 => WorkspaceTrustMode::IgnoreConfig,
                _ => WorkspaceTrustMode::Untrusted,
            })
        }
        _ => WorkspaceTrustAction::Stay,
    }
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

fn render_workspace_trust(
    frame: &mut Frame,
    area: Rect,
    root: &crate::config::trust::TrustRoot,
    cursor: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Workspace trust ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let options = [
        (
            "trust",
            "open and honor project .cockpit config",
            crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        ),
        (
            "ignore-config",
            "open but ignore project .cockpit config and approvals",
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig,
        ),
        (
            "untrusted",
            "refuse to open",
            crate::db::workspace_trust::WorkspaceTrustMode::Untrusted,
        ),
    ];
    let mut lines = vec![
        Line::from(Span::styled(
            "Cockpit has not seen this workspace before:",
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw(format!("  {}", root.root.display()))),
        Line::default(),
        Line::from(Span::styled("Choose workspace trust:", muted)),
    ];
    for (index, (label, description, _)) in options.iter().enumerate() {
        let marker = if index == cursor { "▸ " } else { "  " };
        let style = if index == cursor {
            selected
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("{}. {label}", index + 1), style),
            Span::raw(" - "),
            Span::styled((*description).to_string(), muted),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line("↑/↓  enter: choose  esc: untrusted"), layout[1]);
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

fn render_wizard_menu(
    frame: &mut Frame,
    area: Rect,
    wizards: &[crate::wizard::WizardDescriptor],
    cursor: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup — choose a wizard ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = Vec::new();
    if wizards.is_empty() {
        lines.push(Line::from(Span::styled("  (no wizards registered)", muted)));
    } else {
        for (index, wizard) in wizards.iter().enumerate() {
            let marker = if index == cursor { "▸ " } else { "  " };
            let style = if index == cursor {
                selected
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(wizard.id.to_string(), style),
                Span::raw("  "),
                Span::styled(wizard.description.to_string(), muted),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(help_line("↑/↓  enter: select  esc: close"), layout[1]);
}

fn render_setup_wizard(frame: &mut Frame, area: Rect, wizard: &SetupWizardDialog) {
    let SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        status,
        ..
    } = wizard;
    let block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Setup — {} ", run.descriptor().title));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = Vec::new();
    lines.push(Line::from(Span::styled(
        run.descriptor().description.to_string(),
        muted,
    )));
    lines.push(Line::default());

    if run.is_complete() {
        lines.push(Line::from("Security setup complete."));
    } else if let Some(step) = run.current_step() {
        lines.push(Line::from(Span::styled(
            step.prompt.to_string(),
            Style::default().fg(Color::White),
        )));
        let help = run.help();
        if !help.is_empty() {
            lines.push(Line::from(Span::styled(help.into_owned(), muted)));
        }
        lines.push(Line::default());
        match &step.kind {
            crate::wizard::StepKind::Select { options } => {
                for (index, option) in options.iter().enumerate() {
                    let marker = if index == *cursor { "▸ " } else { "  " };
                    let style = if index == *cursor {
                        selected
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(option.label.to_string(), style),
                        Span::raw("  "),
                        Span::styled(option.description.to_string(), muted),
                    ]));
                }
            }
            crate::wizard::StepKind::Confirm => {
                let current = match run.prefill() {
                    Some(crate::wizard::WizardAnswer::Confirm(true)) => "yes",
                    _ => "no",
                };
                lines.push(Line::from(format!("Current/default: {current}")));
            }
            crate::wizard::StepKind::Text => {
                lines.push(Line::from(format!("Value: {}", text.text())));
            }
            crate::wizard::StepKind::Info => {
                lines.push(Line::from("Press Enter to continue."));
            }
            crate::wizard::StepKind::Action { progress } => {
                lines.push(Line::from(*progress));
            }
            crate::wizard::StepKind::MultiToggle { options } => {
                let prefill_values = if *multi_touched {
                    None
                } else {
                    match run.prefill() {
                        Some(crate::wizard::WizardAnswer::MultiToggle(values)) => Some(values),
                        _ => None,
                    }
                };
                for (index, option) in options.iter().enumerate() {
                    let marker = if index == *cursor { "▸ " } else { "  " };
                    let checked = prefill_values
                        .as_ref()
                        .map(|values| values.iter().any(|value| value == option.id.as_ref()))
                        .unwrap_or_else(|| multi.contains(option.id.as_ref()));
                    let check = if checked { "[x]" } else { "[ ]" };
                    let style = if index == *cursor {
                        selected
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(check.to_string(), style),
                        Span::raw(" "),
                        Span::styled(option.label.to_string(), style),
                        Span::raw("  "),
                        Span::styled(option.description.to_string(), muted),
                    ]));
                }
            }
            crate::wizard::StepKind::Secret => {
                lines.push(Line::from("Unsupported setup step."));
            }
        }
    }
    if let Some(status) = status.as_deref() {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(status.to_string(), muted)));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), layout[0]);
    frame.render_widget(
        help_line("↑/↓  space: toggle  enter: select/continue  y/n: confirm  esc: close"),
        layout[1],
    );
}

fn render_first_run_complete(frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup complete ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let lines = vec![
        Line::from("Cockpit is ready."),
        Line::default(),
        Line::from("Next: run /setup security to choose project trust and approval defaults."),
        Line::from("Use /help any time to see available commands."),
        Line::default(),
        Line::from(Span::styled("Press Enter to start.", muted)),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), inner);
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
mod tests;
