#![allow(dead_code)]
#![allow(private_interfaces)]
//! `/settings` dialog state machine + rendering.
//!
//! Lifecycle:
//!   - `Dialog::None`            no overlay; viewport renders normally
//!   - `Dialog::PickConfig`      choose an existing config to edit
//!   - `Dialog::CreateConfig`    no config yet — pick a location to scaffold
//!   - `Dialog::Settings`        navigate the settings tree
//!
//! The Settings page tree (root has 16 nodes; see `root_nodes()`):
//!
//! ```text
//! Root
//!  ├── Default model for new sessions
//!  ├── Providers
//!  │    ├── List ──── Add Provider wizard ─── (template -> URL -> Auth -> save)
//!  │    │           └── Edit Provider page
//!  │    └── FetchAll dialog (triggered by /fetch-models)
//!  ├── Dependencies (read-only health)
//!  ├── Agents
//!  ├── Interface          ┐
//!  ├── Behavior           │ category pages
//!  ├── Privacy & Safety   │ (descriptor list + optional picker)
//!  ├── Translation        │
//!  ├── Profile            ┘
//!  ├── Image spend budgets
//!  ├── Generation
//!  ├── Tools
//!  ├── Harnesses
//!  ├── Skills
//!  ├── MCP
//!  └── LSP
//! ```
//!
//! Async fetches (the `/models` endpoint after Save, or via the Edit
//! page's `r`=refetch action) use [`FetchHandle`] — a shared cell the
//! background task writes into and the event loop reads on each tick.

mod agent_editor;
mod agents_page;
mod auth;
mod category;
mod dependencies_page;
mod descriptor;
mod grab;
mod harnesses_page;
mod image_generation;
mod image_spend;
mod lsp_page;
mod mcp_page;
mod multimodal_capability_editor;
#[cfg(test)]
mod pointer_acceptance_tests;
#[cfg(test)]
mod pointer_action_fixtures;
#[allow(dead_code)] // The registry is consumed incrementally by page fixture matrices.
pub(crate) mod pointer_actions;
mod providers;
mod reset;
pub(crate) mod secret_display;
mod settings_editor;
pub(crate) mod shell;
mod skills_page;
mod string_list;
mod tools_page;
mod ui_page;

use std::any::Any;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::dirs::{
    CONFIG_FILE, ConfigDir, ConfigDirKind, config_write_target_for_provider, creatable_config_dirs,
    cwd_scoped_creatable_dirs, discover_config_dirs, scaffold_config_dir,
};
use cockpit_config::extended::{ExtendedConfig, ExtendedConfigDoc};
use cockpit_config::providers::{
    AuthKind, ConfigDoc, OnUnlistedModelsFetch, ProviderEntry, ProvidersConfig,
};
use cockpit_core::daemon::proto::Request;
use cockpit_core::providers::models_fetch::FetchOutcome;
use shell::{
    SettingsHeaderAction, SettingsPointerAction, SettingsPointerSurface, SettingsPointerTarget,
    SettingsScrollStates, marker, muted_style, selected_or_field,
};

/// Height (in rows) the dialog wants when active.
pub const DIALOG_HEIGHT: u16 = 20;

pub enum Dialog {
    None,
    WorkspaceTrust {
        root: cockpit_config::trust::TrustRoot,
        cursor: usize,
        chosen: Option<cockpit_config::WorkspaceTrustMode>,
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
        wizards: Vec<cockpit_core::wizard::WizardDescriptor>,
        cursor: usize,
        cwd: PathBuf,
    },
    /// Entry point for `/setup model`. Only a confirmed session model may
    /// seed configuration; a pending selection is never treated as confirmed.
    ModelSetupChoice {
        cwd: PathBuf,
        confirmed: Option<(String, String)>,
        pending: Option<(String, String)>,
        cursor: usize,
    },
    SetupWizard(Box<SetupWizardDialog>),
    FirstRunComplete {
        summary: String,
    },
    /// Boxed because [`SettingsDialog`] dwarfs the other variants
    /// (~1.1KB vs <100 bytes), which would otherwise bloat every
    /// [`Dialog`] on the stack.
    Settings(Box<SettingsDialog>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u64)]
pub(crate) enum SettingsPointerOutcome {
    Consumed,
    Close,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SettingsPointerSurfaceKind {
    Root,
    DefaultModel,
    Agents,
    Tools,
    Harnesses,
    Providers,
    Category,
    Instructions,
    RedactPatterns,
    StringList,
    Skills,
    Mcp,
    Lsp,
    Dependencies,
    GenerationList,
    EndpointEditor,
    TargetEditor,
    WorkflowEditor,
    BudgetEditor,
    GrantList,
    JobList,
    JobDetail,
    LateResultAction,
}

impl SettingsPointerSurfaceKind {
    pub(super) const ALL: [Self; 23] = [
        Self::Root,
        Self::DefaultModel,
        Self::Agents,
        Self::Tools,
        Self::Harnesses,
        Self::Providers,
        Self::Category,
        Self::Instructions,
        Self::RedactPatterns,
        Self::StringList,
        Self::Skills,
        Self::Mcp,
        Self::Lsp,
        Self::Dependencies,
        Self::GenerationList,
        Self::EndpointEditor,
        Self::TargetEditor,
        Self::WorkflowEditor,
        Self::BudgetEditor,
        Self::GrantList,
        Self::JobList,
        Self::JobDetail,
        Self::LateResultAction,
    ];
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SettingsLocalBack {
    NoLocalBack,
    LocalBack,
}

pub struct SetupWizardDialog {
    run: cockpit_core::wizard::WizardRun,
    cursor: usize,
    text: TextField,
    multi: std::collections::BTreeSet<String>,
    multi_touched: bool,
    tool_surface: cockpit_core::agents::ToolSurfaceSelection,
    tool_surface_touched: bool,
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
    descriptor: cockpit_core::wizard::WizardDescriptor,
    status: Option<String>,
) -> Result<Dialog, String> {
    let run = cockpit_core::wizard::WizardRun::new(descriptor).map_err(|e| e.to_string())?;
    let mut cursor = 0;
    let mut text = TextField::new("");
    let mut multi = std::collections::BTreeSet::new();
    let mut multi_touched = false;
    let mut tool_surface = cockpit_core::agents::ToolSurfaceSelection::default();
    let mut tool_surface_touched = false;
    sync_setup_wizard_inputs(
        &run,
        SetupWizardInputs {
            cursor: &mut cursor,
            text: &mut text,
            multi: &mut multi,
            multi_touched: &mut multi_touched,
            tool_surface: &mut tool_surface,
            tool_surface_touched: &mut tool_surface_touched,
        },
    );
    Ok(Dialog::SetupWizard(Box::new(SetupWizardDialog {
        run,
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
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
#[allow(private_interfaces)]
pub(super) trait SettingsPage: Any {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind;
    fn pointer_surface_token(&self) -> u64 {
        self.pointer_surface_kind() as u64
    }
    /// Declare whether Back first cancels/leaves page-local state. The
    /// dialog only pops its navigation stack for `NoLocalBack`.
    fn resolve_header_back(&self) -> SettingsLocalBack {
        SettingsLocalBack::NoLocalBack
    }
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
    /// Resolve a semantic control registered by this page. Implementations
    /// must validate the stable identity against current state before
    /// mutating; stale targets therefore become inert after reloads.
    fn handle_pointer_control(
        &mut self,
        _cx: &mut SettingsCx,
        _action: pointer_actions::SettingsPointerAction,
    ) -> Nav {
        Nav::Stay
    }
    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: pointer_actions::SettingsPointerAction,
        _column: u16,
        _row: u16,
    ) -> Nav {
        self.handle_pointer_control(cx, action)
    }
    /// Move only the independently scrollable region under the pointer.
    /// `delta` is measured in selectable controls and is already normalized
    /// to the settings wheel step (three per notch).
    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        _region: shell::SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        let key = if delta < 0 {
            KeyCode::Up
        } else {
            KeyCode::Down
        };
        for _ in 0..delta.unsigned_abs() {
            let nav = self.handle_key(cx, KeyEvent::new(key, KeyModifiers::NONE));
            if !matches!(nav, Nav::Stay) {
                return nav;
            }
        }
        Nav::Stay
    }
    /// Invalidate pointer-only confirmations/effects whose hit geometry or
    /// identity is no longer trustworthy after a terminal resize.
    fn cancel_pointer_transients(&mut self) {}
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    #[cfg(test)]
    fn test_name(&self) -> &'static str;
}

impl std::fmt::Debug for dyn SettingsPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(test)]
        {
            f.write_str(self.test_name())
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
#[allow(clippy::large_enum_variant)]
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
pub(crate) enum TestPageRef<'a> {
    Root { cursor: usize },
    DefaultModel(&'a DefaultModelPage),
    Agents(&'a AgentsPage),
    Tools(&'a ToolsPage),
    Harnesses(&'a HarnessesPage),
    Providers(&'a ProvidersPage),
    Category(&'a CategoryPage),
    ImageSpend(&'a image_spend::ImageSpendPage),
    Instructions(&'a InstructionsPage),
    RedactPatterns(&'a RedactPatternsPage),
    StringList(&'a StringListPage),
    Skills(&'a SkillsPage),
    Mcp(&'a McpPage),
    Lsp(&'a LspPage),
    GenerationList(&'a image_generation::GenerationListPage),
    EndpointEditor(&'a image_generation::EndpointEditorPage),
    TargetEditor(&'a image_generation::TargetEditorPage),
    WorkflowEditor(&'a image_generation::WorkflowEditorPage),
    BudgetEditor(&'a image_generation::BudgetEditorPage),
    GrantList(&'a image_generation::GrantListPage),
    JobList(&'a image_generation::JobListPage),
    JobDetail(&'a image_generation::JobDetailPage),
    LateResultAction(&'a image_generation::LateResultActionPage),
}

#[cfg(test)]
enum TestPageMut<'a> {
    Root { cursor: &'a mut usize },
    Agents(&'a mut AgentsPage),
    Tools(&'a mut ToolsPage),
    Harnesses(&'a mut HarnessesPage),
    Providers(&'a mut ProvidersPage),
    Category(&'a mut CategoryPage),
    ImageSpend(&'a mut image_spend::ImageSpendPage),
    Instructions(&'a mut InstructionsPage),
    RedactPatterns(&'a mut RedactPatternsPage),
    StringList(&'a mut StringListPage),
    Skills(&'a mut SkillsPage),
    Mcp(&'a mut McpPage),
    Lsp(&'a mut LspPage),
    GenerationList(&'a mut image_generation::GenerationListPage),
    EndpointEditor(&'a mut image_generation::EndpointEditorPage),
    TargetEditor(&'a mut image_generation::TargetEditorPage),
    WorkflowEditor(&'a mut image_generation::WorkflowEditorPage),
    BudgetEditor(&'a mut image_generation::BudgetEditorPage),
    GrantList(&'a mut image_generation::GrantListPage),
    JobList(&'a mut image_generation::JobListPage),
    JobDetail(&'a mut image_generation::JobDetailPage),
    LateResultAction(&'a mut image_generation::LateResultActionPage),
}

#[cfg(test)]
impl std::fmt::Debug for TestPageRef<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Root { cursor } => write!(f, "Root({cursor})"),
            Self::DefaultModel(_) => f.write_str("DefaultModel"),
            Self::Agents(_) => f.write_str("Agents"),
            Self::Tools(_) => f.write_str("Tools"),
            Self::Harnesses(_) => f.write_str("Harnesses"),
            Self::Providers(_) => f.write_str("Providers"),
            Self::Category(_) => f.write_str("Category"),
            Self::ImageSpend(_) => f.write_str("ImageSpend"),
            Self::Instructions(_) => f.write_str("Instructions"),
            Self::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Self::StringList(_) => f.write_str("StringList"),
            Self::Skills(_) => f.write_str("Skills"),
            Self::Mcp(_) => f.write_str("Mcp"),
            Self::Lsp(_) => f.write_str("Lsp"),
            Self::GenerationList(_) => f.write_str("GenerationList"),
            Self::EndpointEditor(_) => f.write_str("EndpointEditor"),
            Self::TargetEditor(_) => f.write_str("TargetEditor"),
            Self::WorkflowEditor(_) => f.write_str("WorkflowEditor"),
            Self::BudgetEditor(_) => f.write_str("BudgetEditor"),
            Self::GrantList(_) => f.write_str("GrantList"),
            Self::JobList(_) => f.write_str("JobList"),
            Self::JobDetail(_) => f.write_str("JobDetail"),
            Self::LateResultAction(_) => f.write_str("LateResultAction"),
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
            Self::ImageSpend(_) => f.write_str("ImageSpend"),
            Self::Instructions(_) => f.write_str("Instructions"),
            Self::RedactPatterns(_) => f.write_str("RedactPatterns"),
            Self::StringList(_) => f.write_str("StringList"),
            Self::Skills(_) => f.write_str("Skills"),
            Self::Mcp(_) => f.write_str("Mcp"),
            Self::Lsp(_) => f.write_str("Lsp"),
            Self::GenerationList(_) => f.write_str("GenerationList"),
            Self::EndpointEditor(_) => f.write_str("EndpointEditor"),
            Self::TargetEditor(_) => f.write_str("TargetEditor"),
            Self::WorkflowEditor(_) => f.write_str("WorkflowEditor"),
            Self::BudgetEditor(_) => f.write_str("BudgetEditor"),
            Self::GrantList(_) => f.write_str("GrantList"),
            Self::JobList(_) => f.write_str("JobList"),
            Self::JobDetail(_) => f.write_str("JobDetail"),
            Self::LateResultAction(_) => f.write_str("LateResultAction"),
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
    pointer_surface: SettingsPointerSurface,
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
    /// Per-session launch policy (`false` for `--no-sandbox`) used by
    /// dependency applicability. This is runtime state, never persisted.
    pub(super) sandbox_enabled: bool,
    /// Set by Root's back action to ask the outer [`Dialog`] to
    /// re-open the picker on the next `true` return from `handle_key`.
    pub(super) back_to_picker: bool,
    /// PATH-presence resolver for harness-preset seeding: returns whether a
    /// harness `command` is installed (found on `PATH`). Defaults to the
    /// real [`cockpit_core::harness::preflight::which_on_path`]; tests inject a
    /// stub so seeding doesn't depend on the CI machine's installed tools.
    pub(super) command_installed: fn(&str) -> bool,
    pub(super) env_lookup: fn(&str) -> Option<String>,
    pub(super) credential_store_path: Option<PathBuf>,
    pub(super) mcp_cache_dir: Option<PathBuf>,
    /// Disclosure produced when a provider save moved literal header values
    /// into the credential store. Consumed by the provider page's status line.
    pub(super) last_secret_notice: Option<String>,
    pending_daemon_request: Option<Request>,
    pending_oauth_action: Option<OAuthFlowRequest>,
    /// Close settings and open the model picker for default-only mutation.
    pub(super) pending_default_model_picker: bool,
    /// Correlation id of a staged `SetDefaultModel`, so the app can match the
    /// terminal `DefaultModelUpdateResult` to this exact operation.
    pub(super) pending_default_model_update_id: Option<uuid::Uuid>,
}

fn root_page(cursor: usize) -> PageBox {
    Box::new(RootPage { cursor })
}

fn default_model_page(page: DefaultModelPage) -> PageBox {
    Box::new(page)
}

/// `/settings` -> **Default model for new sessions**.
///
/// Shows the currently effective default (or an explicit unset state) and its
/// safe scope label, opens the same provider-scoped model picker `/model`
/// uses, and can clear the context default. Every mutation goes through the
/// daemon's one authoritative effective-default operation; this page never
/// writes `active_model` and never changes a running session.
pub(super) struct DefaultModelPage {
    pub(super) status: Option<String>,
    /// Resolved once when the page opens, alongside the *effective* default
    /// below — both are layered resolutions and must not run per frame.
    pub(super) scope_label: String,
    /// The default a new session would actually resolve, i.e. the merge of
    /// every applicable layer. `cx.config` is only the single layer this
    /// dialog edits, so showing it here would misreport the default whenever
    /// a higher-precedence layer overrides it (AC9).
    pub(super) effective_default: Option<cockpit_config::providers::ActiveModelRef>,
}

impl SettingsPage for DefaultModelPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::DefaultModel
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        match key.code {
            KeyCode::Esc
            | KeyCode::Char('q')
            | KeyCode::Left
            | KeyCode::Char('h')
            | KeyCode::Backspace => Nav::Back,
            KeyCode::Enter | KeyCode::Char('c') => {
                cx.pending_default_model_picker = true;
                Nav::Close
            }
            // Clearing is a daemon-verified operation: it succeeds only when
            // the reloaded effective configuration still resolves to a
            // deterministic inherited default or an explicit no-default state.
            KeyCode::Char('x') => {
                if self.effective_default.is_none() {
                    self.status =
                        Some("No default is set in this configuration context.".to_string());
                    return Nav::Stay;
                }
                let default_update_id = uuid::Uuid::new_v4();
                // Correlate the terminal event with this exact operation so
                // the confirmation names the resulting effective state.
                cx.pending_default_model_update_id = Some(default_update_id);
                cx.pending_daemon_request = Some(Request::SetDefaultModel {
                    default_update_id,
                    provider: None,
                    model: None,
                    reasoning_effort: None,
                    thinking_mode: None,
                    prompt_cache_retention: None,
                    clear: true,
                });
                self.status = Some(
                    "Clearing the default for new sessions… the result names the resulting effective state."
                        .to_string(),
                );
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: pointer_actions::SettingsPointerAction,
    ) -> Nav {
        match action {
            pointer_actions::SettingsPointerAction::DefaultModel(
                pointer_actions::DefaultModelAction::Choose,
            ) => self.handle_key(cx, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
            pointer_actions::SettingsPointerAction::DefaultModel(
                pointer_actions::DefaultModelAction::Clear,
            ) if self.effective_default.is_some() => {
                self.handle_key(cx, KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE))
            }
            _ => Nav::Stay,
        }
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        // Both values are resolved when the page opens: each is a layered
        // resolution and must not run per frame.
        let default = self.effective_default.as_ref();
        let scope = &self.scope_label;
        let mut lines = vec![Line::from("Default model for new sessions"), Line::from("")];
        match default {
            Some(active) => {
                lines.push(Line::from(format!(
                    "Effective default: {}/{}",
                    active.provider, active.model
                )));
                if let Some(effort) = active.reasoning_effort.as_ref() {
                    lines.push(Line::from(format!("  reasoning: {}", effort.value)));
                }
            }
            None => lines.push(Line::from(
                "Effective default: (unset — a new session resolves its model at creation)",
            )),
        }
        lines.push(Line::from(format!("Scope: {scope}")));
        lines.push(Line::from(""));
        let choose_line = lines.len();
        lines.push(Line::default());
        let clear_line = lines.len();
        lines.push(Line::default());
        lines.push(Line::from("Applies to newly created sessions only."));
        lines.push(Line::from(
            "Reopening an existing session keeps its own saved model.",
        ));
        if let Some(status) = &self.status {
            lines.push(Line::from(""));
            lines.push(Line::from(status.clone()));
        }
        let para = Paragraph::new(lines).wrap(ratatui::widgets::Wrap { trim: false });
        frame.render_widget(para, area);
        for (line, action, enabled, label) in [
            (
                choose_line,
                pointer_actions::SettingsPointerAction::DefaultModel(
                    pointer_actions::DefaultModelAction::Choose,
                ),
                true,
                "Choose default model",
            ),
            (
                clear_line,
                pointer_actions::SettingsPointerAction::DefaultModel(
                    pointer_actions::DefaultModelAction::Clear,
                ),
                self.effective_default.is_some(),
                "Clear default for this scope",
            ),
        ] {
            cx.pointer_surface.paint_page_button(
                frame,
                area.x,
                area.y.saturating_add(line as u16),
                area.width,
                action,
                label,
                enabled,
                false,
            );
        }
    }

    fn title(&self, _cx: &SettingsCx) -> String {
        "Default model for new sessions".into()
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        "enter: change default  x: clear  esc/h: back"
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "DefaultModel"
    }
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

use agents_page::AgentsPage;
use category::{Category, CategoryPage};
#[cfg(test)]
use cockpit_core::daemon::proto::LspControlAction;
use harnesses_page::HarnessesPage;
use lsp_page::LspPage;
#[cfg(test)]
use lsp_page::{
    LSP_NAV_ROWS, LSP_SERVER_ROW_START, LspEdit, LspRow, PROJECT_CONTEXT_UNAVAILABLE,
    ProjectContext, lsp_rows, lsp_selected_line_for_cursor, project_context_for_config, row_index,
};
use mcp_page::McpPage;
pub(crate) use mcp_page::row_color as mcp_row_color;
use providers::{AddState, EditState, ModelEditor, ProvidersPage};
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
    pub(crate) fn handle_settings_pointer(
        &mut self,
        mouse: MouseEvent,
    ) -> Option<SettingsPointerOutcome> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        // App-level z-order may route Settings before chat affordances only
        // after the dialog has actually rendered a pointer surface. A newly
        // constructed, not-yet-rendered dialog has no geometry to own and
        // must not swallow suggestion/selection events underneath it.
        settings.pointer_surface.area.get()?;
        Some(settings.handle_pointer(mouse))
    }

    pub(crate) fn clear_settings_pointer_hover(&self) {
        if let Dialog::Settings(settings) = self {
            *settings.pointer_surface.hover.borrow_mut() = None;
        }
    }
    pub(crate) fn cancel_settings_pointer_transients(&mut self) {
        if let Dialog::Settings(settings) = self {
            *settings.pointer_surface.hover.borrow_mut() = None;
            settings.pointer_surface.header_hover.set(None);
            *settings.pointer_surface.pressed.borrow_mut() = None;
            settings.page.cancel_pointer_transients();
        }
    }
    pub fn is_active(&self) -> bool {
        !matches!(self, Dialog::None)
    }

    pub fn is_workspace_trust(&self) -> bool {
        matches!(self, Dialog::WorkspaceTrust { .. })
    }

    pub(crate) fn set_runtime_sandbox_enabled(&mut self, enabled: bool) {
        if let Dialog::Settings(settings) = self {
            settings.cx.sandbox_enabled = enabled;
        }
    }

    #[cfg(test)]
    pub(crate) fn test_page_name(&self) -> Option<&'static str> {
        match self {
            Dialog::Settings(settings) => Some(settings.page.test_name()),
            Dialog::WorkspaceTrust { .. } => Some("workspace_trust"),
            Dialog::WizardMenu { .. } => Some("wizard_menu"),
            Dialog::SetupWizard(wizard) => Some(wizard.run.descriptor().id),
            Dialog::FirstRunComplete { .. } => Some("first_run_complete"),
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
    pub(crate) fn test_provider_add_status(&self) -> Option<&str> {
        let Dialog::Settings(settings) = self else {
            return None;
        };
        let page = settings.page.as_any().downcast_ref::<ProvidersPage>()?;
        let ProvidersPage::Add(add) = page else {
            return None;
        };
        add.error.as_deref()
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
    pub(crate) fn test_mark_setup_complete(&mut self, step_id: &str) {
        let Dialog::SetupWizard(wizard) = self else {
            panic!("expected setup wizard");
        };
        wizard
            .run
            .return_to(step_id)
            .expect("setup completion step exists");
        wizard
            .run
            .submit(cockpit_core::wizard::WizardAnswer::Acknowledged)
            .expect("setup completion step accepts acknowledgement");
    }

    #[cfg(test)]
    pub(crate) fn test_setup_answer(
        &self,
        step_id: &str,
    ) -> Option<cockpit_core::wizard::WizardAnswer> {
        let Dialog::SetupWizard(wizard) = self else {
            return None;
        };
        wizard.run.answer(step_id).cloned()
    }

    #[cfg(test)]
    pub(crate) fn test_setup_prefill(&self) -> Option<cockpit_core::wizard::WizardAnswer> {
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

    pub fn open_workspace_trust(root: cockpit_config::trust::TrustRoot) -> Self {
        Dialog::WorkspaceTrust {
            root,
            cursor: 0,
            chosen: None,
        }
    }

    pub fn take_workspace_trust_choice(
        &mut self,
    ) -> Option<(
        cockpit_config::trust::TrustRoot,
        cockpit_config::WorkspaceTrustMode,
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
        // The provider wizard is the first-run destination, not the generic
        // config-location picker. A clean install has no discovered layer,
        // so materialize the normal first global layer before opening Add.
        // This deliberately does not create project config and is reached
        // only after the caller has obtained an explicit trust decision.
        let path = match discover_config_dirs(cwd).first() {
            Some(dir) => Ok(dir.path.join(CONFIG_FILE)),
            None => creatable_config_dirs()
                .first()
                .ok_or_else(|| std::io::Error::other("no Cockpit config directory is available"))
                .and_then(|dir| scaffold_config_dir(&dir.path)),
        };

        match path {
            Ok(path) => {
                let mut s = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
                let mut add = AddState::new();
                add.error = status;
                s.page = providers_page(ProvidersPage::Add(add));
                Dialog::Settings(Box::new(s))
            }
            Err(error) => Dialog::CreateConfig {
                choices: creatable_config_dirs(),
                cursor: 0,
                cwd: cwd.to_path_buf(),
                status: Some(format!("could not create initial Cockpit config: {error}")),
            },
        }
    }

    pub fn open_setup(cwd: &std::path::Path) -> Self {
        Dialog::WizardMenu {
            wizards: cockpit_core::wizard::registry(),
            cursor: 0,
            cwd: cwd.to_path_buf(),
        }
    }

    pub fn open_setup_wizard(cwd: &std::path::Path, wizard_id: &str) -> Result<Self, String> {
        match wizard_id {
            cockpit_core::wizard::PROVIDER_WIZARD_ID => Ok(Self::open_providers_add(cwd)),
            cockpit_core::wizard::SECURITY_WIZARD_ID | cockpit_core::wizard::MODEL_WIZARD_ID => {
                let descriptor = cockpit_core::wizard::descriptor_for_cwd(wizard_id, cwd)
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
            cockpit_core::wizard::model_descriptor_for_cwd(cwd, Some((provider_id, model_id)));
        setup_wizard_dialog(cwd, descriptor, status)
    }

    pub fn open_model_setup_choice(
        cwd: &std::path::Path,
        confirmed: Option<(String, String)>,
        pending: Option<(String, String)>,
    ) -> Self {
        Self::ModelSetupChoice {
            cwd: cwd.to_path_buf(),
            confirmed,
            pending,
            cursor: 0,
        }
    }

    pub fn open_first_run_complete(summary: String) -> Self {
        Dialog::FirstRunComplete { summary }
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
        // The provider settings editor mutates and persists config to a
        // specific write-target file; it needs the full (unredacted) entry to
        // seed the edit form, which the daemon's redacted snapshot cannot
        // supply. Load the layered provider config directly (NOT
        // `load_effective`): no credential resolution happens here, and the
        // resulting write is signalled to the daemon on dialog close
        // (`resync_config_after_local_write`).
        let paths = cockpit_config::dirs::config_file_paths_for_load(cwd);
        let cfg = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
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
                Some(cockpit_core::auth::codex_oauth::CREDENTIAL_KEY | "codex") => {
                    Some(OAuthProvider::Codex)
                }
                Some(cockpit_core::auth::xai_oauth::CREDENTIAL_KEY | "grok") => {
                    Some(OAuthProvider::Grok)
                }
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

    /// Open the existing provider-model editor directly for one configured provider.
    /// This is the canonical add-model surface used by scoped model recovery.
    pub fn open_provider_models(cwd: &std::path::Path, provider_id: &str) -> Self {
        let paths = cockpit_config::dirs::config_file_paths_for_load(cwd);
        let cfg = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
        let Some(entry) = cfg.providers.get(provider_id).cloned() else {
            return Self::open(cwd);
        };
        let Some(path) = config_write_target_for_provider(cwd, provider_id) else {
            return Self::open(cwd);
        };
        let mut settings = SettingsDialog::open_from_picker(path, cwd.to_path_buf());
        let parent = EditState::new(provider_id.to_string(), entry.clone());
        settings.page = providers_page(ProvidersPage::Models {
            editor: Box::new(ModelEditor::new(
                entry.effective_template(provider_id).map(str::to_owned),
                entry.models.clone(),
            )),
            parent: Box::new(parent),
        });
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
    pub(crate) fn take_pending_agent_edit(
        &mut self,
    ) -> Option<agents_page::AgentExternalEditEffect> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        s.page
            .downcast_mut::<AgentsPage>()
            .and_then(AgentsPage::take_external_edit_request)
    }

    /// Apply the result of an external-editor session the event loop ran on
    /// behalf of the Agents page: re-read the file from disk, re-parse it,
    /// surface any parse error inline, and refresh the row markers/model.
    /// The host reports a typed Saved/Cancelled/Failed terminal outcome;
    /// only Saved may atomically replace the real agent path.
    pub(crate) fn finish_agent_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Dialog::Settings(s) = self else {
            return;
        };
        s.finish_agent_external_edit(operation_id, outcome, detail);
    }

    /// Drain a pending category setting `$EDITOR` request. The category page
    /// retains the temp path until [`Self::finish_category_setting_edit`] reads
    /// it back and drops it.
    pub(crate) fn take_pending_category_setting_edit(
        &mut self,
    ) -> Option<(shell::PointerOperationId, PathBuf)> {
        let Dialog::Settings(s) = self else {
            return None;
        };
        s.take_pending_category_external_edit()
    }

    /// Apply the result of a category-setting `$EDITOR` round trip.
    pub(crate) fn finish_category_setting_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Dialog::Settings(s) = self else {
            return;
        };
        s.finish_category_external_edit(operation_id, outcome, detail);
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
            Dialog::FirstRunComplete { .. } => {
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
            Dialog::ModelSetupChoice {
                cwd,
                confirmed,
                cursor,
                ..
            } => {
                let choices = if confirmed.is_some() { 2 } else { 1 };
                match list_key_action(key, cursor, choices) {
                    ListAction::Stay => false,
                    ListAction::Close => true,
                    ListAction::Select(index) => {
                        let next = if confirmed.is_some() && index == 0 {
                            let (provider, model) = confirmed
                                .as_ref()
                                .expect("confirmed choice must have a pair");
                            Self::open_model_setup_preselected(cwd, provider, model, None)
                        } else {
                            Self::open_setup_wizard(cwd, cockpit_core::wizard::MODEL_WIZARD_ID)
                        };
                        if let Ok(next) = next {
                            *self = next;
                        }
                        false
                    }
                }
            }
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

    /// Correlation id of the default-model request most recently staged by
    /// this dialog, taken alongside the request itself.
    pub fn take_pending_default_model_update_id(&mut self) -> Option<uuid::Uuid> {
        match self {
            Dialog::Settings(s) => s.pending_default_model_update_id.take(),
            _ => None,
        }
    }

    pub fn take_pending_default_model_picker(&mut self) -> bool {
        match self {
            Dialog::Settings(s) => {
                let pending = s.pending_default_model_picker;
                s.pending_default_model_picker = false;
                pending
            }
            _ => false,
        }
    }

    pub(crate) fn take_oauth_action(&mut self) -> Option<OAuthFlowRequest> {
        match self {
            Dialog::Settings(s) => s.pending_oauth_action.take(),
            _ => None,
        }
    }

    pub(crate) fn apply_oauth_begin(&mut self, provider: OAuthProvider, result: OAuthBeginResult) {
        if let Dialog::Settings(s) = self {
            s.apply_oauth_begin(provider, result);
        }
    }

    pub(crate) fn apply_oauth_complete(
        &mut self,
        provider: OAuthProvider,
        result: Result<bool, String>,
    ) {
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
            Dialog::ModelSetupChoice {
                confirmed,
                pending,
                cursor,
                ..
            } => render_model_setup_choice(
                frame,
                area,
                confirmed.as_ref(),
                pending.as_ref(),
                *cursor,
            ),
            Dialog::SetupWizard(wizard) => render_setup_wizard(frame, area, wizard),
            Dialog::FirstRunComplete { summary } => render_first_run_complete(frame, area, summary),
            Dialog::Settings(s) => s.render(frame, area, links),
        }
    }
}

// ── SettingsDialog ───────────────────────────────────────────────────────

fn settings_action_from_button_id(
    id: crate::tui::button::ButtonId,
) -> Option<SettingsPointerAction> {
    match id {
        crate::tui::button::ButtonId::SettingsHeader(action) => {
            Some(SettingsPointerAction::Header(action))
        }
        crate::tui::button::ButtonId::Settings(action) => Some(SettingsPointerAction::Page(action)),
        _ => None,
    }
}

fn dispatch_from_settings_action(
    action: SettingsPointerAction,
) -> crate::tui::button::ButtonDispatch {
    match action {
        SettingsPointerAction::Header(action) => {
            crate::tui::button::ButtonDispatch::SettingsHeader(action)
        }
        SettingsPointerAction::Page(action) => crate::tui::button::ButtonDispatch::Settings(action),
    }
}

impl SettingsDialog {
    #[cfg(test)]
    pub(crate) fn pointer_test_target_rects(&self) -> Vec<Rect> {
        self.cx
            .pointer_surface
            .targets
            .borrow()
            .iter()
            .map(|target| target.rect)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn pointer_test_hover_is_none(&self) -> bool {
        self.cx.pointer_surface.hover.borrow().is_none()
    }

    #[cfg(test)]
    pub(crate) fn pointer_test_button_targets(&self) -> Vec<crate::tui::button::RegisteredButton> {
        self.cx.pointer_surface.buttons.borrow().targets().to_vec()
    }

    #[cfg(test)]
    pub(crate) fn pointer_test_row_targets(&self) -> Vec<crate::tui::button::RowTarget> {
        self.cx.pointer_surface.rows.borrow().targets().to_vec()
    }

    #[cfg(test)]
    pub(crate) fn test_enter_root_node(&mut self, title: &str) {
        tests::enter_root_node(self, title);
    }

    #[cfg(test)]
    fn set_test_page(&mut self, page: Page) {
        self.page = boxed_page(page);
    }

    #[cfg(test)]
    pub(crate) fn test_page(&self) -> TestPageRef<'_> {
        if let Some(p) = self.page.downcast_ref::<RootPage>() {
            return TestPageRef::Root { cursor: p.cursor };
        }
        if let Some(p) = self.page.downcast_ref::<DefaultModelPage>() {
            return TestPageRef::DefaultModel(p);
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
        if let Some(p) = self.page.downcast_ref::<image_spend::ImageSpendPage>() {
            return TestPageRef::ImageSpend(p);
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
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::GenerationListPage>()
        {
            return TestPageRef::GenerationList(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::EndpointEditorPage>()
        {
            return TestPageRef::EndpointEditor(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::TargetEditorPage>()
        {
            return TestPageRef::TargetEditor(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::WorkflowEditorPage>()
        {
            return TestPageRef::WorkflowEditor(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::BudgetEditorPage>()
        {
            return TestPageRef::BudgetEditor(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_generation::GrantListPage>() {
            return TestPageRef::GrantList(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_generation::JobListPage>() {
            return TestPageRef::JobList(p);
        }
        if let Some(p) = self.page.downcast_ref::<image_generation::JobDetailPage>() {
            return TestPageRef::JobDetail(p);
        }
        if let Some(p) = self
            .page
            .downcast_ref::<image_generation::LateResultActionPage>()
        {
            return TestPageRef::LateResultAction(p);
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
        if self.page.as_any().is::<image_spend::ImageSpendPage>() {
            return TestPageMut::ImageSpend(
                self.page
                    .downcast_mut::<image_spend::ImageSpendPage>()
                    .unwrap(),
            );
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
        if self
            .page
            .as_any()
            .is::<image_generation::GenerationListPage>()
        {
            return TestPageMut::GenerationList(
                self.page
                    .downcast_mut::<image_generation::GenerationListPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::EndpointEditorPage>()
        {
            return TestPageMut::EndpointEditor(
                self.page
                    .downcast_mut::<image_generation::EndpointEditorPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::TargetEditorPage>()
        {
            return TestPageMut::TargetEditor(
                self.page
                    .downcast_mut::<image_generation::TargetEditorPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::WorkflowEditorPage>()
        {
            return TestPageMut::WorkflowEditor(
                self.page
                    .downcast_mut::<image_generation::WorkflowEditorPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::BudgetEditorPage>()
        {
            return TestPageMut::BudgetEditor(
                self.page
                    .downcast_mut::<image_generation::BudgetEditorPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<image_generation::GrantListPage>() {
            return TestPageMut::GrantList(
                self.page
                    .downcast_mut::<image_generation::GrantListPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<image_generation::JobListPage>() {
            return TestPageMut::JobList(
                self.page
                    .downcast_mut::<image_generation::JobListPage>()
                    .unwrap(),
            );
        }
        if self.page.as_any().is::<image_generation::JobDetailPage>() {
            return TestPageMut::JobDetail(
                self.page
                    .downcast_mut::<image_generation::JobDetailPage>()
                    .unwrap(),
            );
        }
        if self
            .page
            .as_any()
            .is::<image_generation::LateResultActionPage>()
        {
            return TestPageMut::LateResultAction(
                self.page
                    .downcast_mut::<image_generation::LateResultActionPage>()
                    .unwrap(),
            );
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
            extended.skills.scan_dirs = cockpit_config::extended::SEEDED_SCAN_DIRS
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
                pointer_surface: SettingsPointerSurface::default(),
                original_config: config.clone(),
                config,
                extended,
                extended_warnings,
                picker_cwd: None,
                active_project_root: None,
                sandbox_enabled: true,
                back_to_picker: false,
                command_installed: |cmd| {
                    cockpit_core::harness::preflight::which_on_path(cmd).is_some()
                },
                env_lookup: |name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()),
                credential_store_path: None,
                mcp_cache_dir: None,
                last_secret_notice: None,
                pending_daemon_request: None,
                pending_oauth_action: None,
                pending_default_model_picker: false,
                pending_default_model_update_id: None,
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
        for (provider_id, entry) in &merged.providers {
            cockpit_config::config::providers::validate_provider_headers(
                provider_id,
                &entry.headers,
            )
            .map_err(|error| error.to_string())?;
        }
        let notice = cockpit_core::secret_ref::protect_literal_headers(
            &mut merged.providers,
            self.credential_store_path.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        // The layer-wide default is never part of this file write; it goes to
        // the daemon's authoritative effective-default operation, and the
        // dialog only shows the new value once that verified result arrives.
        self.stage_default_model_change();
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
            .flat_map(|header| cockpit_core::envref::referenced_names(&header.value))
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
                .flat_map(|header| cockpit_core::envref::referenced_names(&header.value))
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
            Some(path) => cockpit_core::credentials::CredentialStore::open(path.clone()),
            None => cockpit_core::credentials::CredentialStore::open_default(),
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
        if let Some(page) = self.page.downcast_mut::<image_spend::ImageSpendPage>() {
            page.poll();
        }
        if let Some(page) = self
            .page
            .downcast_mut::<dependencies_page::DependenciesPage>()
        {
            page.tick();
        }
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
        self.drain_deep_fetch();
        if let Some(page) = self.page.downcast_mut::<ProvidersPage>() {
            match page {
                ProvidersPage::OAuthSetup { state, .. } if state.pending || state.polling => {
                    state.spinner_tick = state.spinner_tick.wrapping_add(1);
                }
                ProvidersPage::DeepFetch { state, .. } => state.advance_spinner(),
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

    fn handle_pointer(&mut self, mouse: MouseEvent) -> SettingsPointerOutcome {
        let Some(area) = self.pointer_surface.area.get() else {
            return SettingsPointerOutcome::Consumed;
        };
        if mouse.column < area.x
            || mouse.column >= area.right()
            || mouse.row < area.y
            || mouse.row >= area.bottom()
        {
            if matches!(mouse.kind, MouseEventKind::Moved) {
                *self.pointer_surface.hover.borrow_mut() = None;
                self.pointer_surface.header_hover.set(None);
            }
            return SettingsPointerOutcome::Consumed;
        }
        match mouse.kind {
            MouseEventKind::Moved => {
                let button_outcome = self
                    .pointer_surface
                    .buttons
                    .borrow_mut()
                    .handle_mouse(mouse);
                let action = match button_outcome {
                    Some(_) => self
                        .pointer_surface
                        .buttons
                        .borrow()
                        .hover()
                        .cloned()
                        .and_then(settings_action_from_button_id),
                    None => self
                        .pointer_surface
                        .hit(mouse.column, mouse.row)
                        .filter(|target| target.enabled)
                        .map(|target| target.action),
                };
                *self.pointer_surface.hover.borrow_mut() = match &action {
                    Some(SettingsPointerAction::Page(action)) => Some(action.clone()),
                    _ => None,
                };
                self.pointer_surface.header_hover.set(match action {
                    Some(SettingsPointerAction::Header(action)) => Some(action),
                    _ => None,
                });
            }
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                *self.pointer_surface.hover.borrow_mut() = None;
                self.pointer_surface.header_hover.set(None);
                self.pointer_surface
                    .buttons
                    .borrow_mut()
                    .clear_hover_and_pressed();
                if let Some(region) = self
                    .pointer_surface
                    .scroll_region_at(mouse.column, mouse.row)
                {
                    let delta = if matches!(mouse.kind, MouseEventKind::ScrollUp) {
                        -3
                    } else {
                        3
                    };
                    let nav = self.page.handle_pointer_scroll(&mut self.cx, region, delta);
                    let _ = self.apply_nav(nav);
                }
            }
            MouseEventKind::Down(MouseButton::Left) | MouseEventKind::Up(MouseButton::Left) => {
                let button_outcome = self
                    .pointer_surface
                    .buttons
                    .borrow_mut()
                    .handle_mouse(mouse);
                if let Some(outcome) = button_outcome {
                    match outcome {
                        crate::tui::button::ButtonPointerOutcome::Activated(dispatch) => {
                            *self.pointer_surface.pressed.borrow_mut() = None;
                            return self.dispatch_button(dispatch, mouse.column, mouse.row);
                        }
                        crate::tui::button::ButtonPointerOutcome::Pressed(id) => {
                            if let Some(action) = settings_action_from_button_id(id) {
                                *self.pointer_surface.pressed.borrow_mut() = Some(action);
                            }
                            return SettingsPointerOutcome::Consumed;
                        }
                        crate::tui::button::ButtonPointerOutcome::Cancelled
                        | crate::tui::button::ButtonPointerOutcome::Consumed
                        | crate::tui::button::ButtonPointerOutcome::HoverChanged => {}
                    }
                }
                if matches!(mouse.kind, MouseEventKind::Up(MouseButton::Left)) {
                    let pressed = self.pointer_surface.pressed.borrow_mut().take();
                    if let Some(action) = pressed {
                        let is_button = matches!(action, SettingsPointerAction::Header(_))
                            || matches!(&action, SettingsPointerAction::Page(page) if page.is_button());
                        let still_over = self
                            .pointer_surface
                            .hit(mouse.column, mouse.row)
                            .is_some_and(|target| target.enabled && target.action == action);
                        if is_button && still_over {
                            return self.dispatch_button(
                                dispatch_from_settings_action(action),
                                mouse.column,
                                mouse.row,
                            );
                        }
                    }
                    return SettingsPointerOutcome::Consumed;
                }
                let Some(target) = self.pointer_surface.hit(mouse.column, mouse.row) else {
                    return SettingsPointerOutcome::Consumed;
                };
                if !target.enabled {
                    return SettingsPointerOutcome::Consumed;
                }
                let is_button_target = matches!(target.action, SettingsPointerAction::Header(_))
                    || matches!(&target.action, SettingsPointerAction::Page(action) if action.is_button());
                if is_button_target {
                    *self.pointer_surface.pressed.borrow_mut() = Some(target.action);
                    return SettingsPointerOutcome::Consumed;
                }
                if self
                    .pointer_surface
                    .pressed
                    .borrow_mut()
                    .replace(target.action.clone())
                    .is_some()
                {
                    return SettingsPointerOutcome::Consumed;
                }
                if let SettingsPointerAction::Page(action) = target.action {
                    let nav = self.page.handle_pointer_control_at(
                        &mut self.cx,
                        action.clone(),
                        mouse.column,
                        mouse.row,
                    );
                    let close = self.apply_nav(nav);
                    #[cfg(test)]
                    pointer_acceptance_tests::record_dispatched_action(&action);
                    if close {
                        return SettingsPointerOutcome::Close;
                    }
                }
            }
            _ => {}
        }
        SettingsPointerOutcome::Consumed
    }

    fn dispatch_button(
        &mut self,
        dispatch: crate::tui::button::ButtonDispatch,
        column: u16,
        row: u16,
    ) -> SettingsPointerOutcome {
        match dispatch {
            crate::tui::button::ButtonDispatch::SettingsHeader(SettingsHeaderAction::Close) => {
                SettingsPointerOutcome::Close
            }
            crate::tui::button::ButtonDispatch::SettingsHeader(
                SettingsHeaderAction::BackToConfigPicker,
            ) => {
                self.back_to_picker = true;
                SettingsPointerOutcome::Close
            }
            crate::tui::button::ButtonDispatch::SettingsHeader(SettingsHeaderAction::Back) => {
                let nav = match self.page.resolve_header_back() {
                    SettingsLocalBack::LocalBack => self.page.handle_key(
                        &mut self.cx,
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                    ),
                    SettingsLocalBack::NoLocalBack => Nav::Back,
                };
                let _ = self.apply_nav(nav);
                SettingsPointerOutcome::Consumed
            }
            crate::tui::button::ButtonDispatch::Settings(action) => {
                let nav =
                    self.page
                        .handle_pointer_control_at(&mut self.cx, action.clone(), column, row);
                let close = self.apply_nav(nav);
                #[cfg(test)]
                pointer_acceptance_tests::record_dispatched_action(&action);
                if close {
                    SettingsPointerOutcome::Close
                } else {
                    SettingsPointerOutcome::Consumed
                }
            }
            _ => SettingsPointerOutcome::Consumed,
        }
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

    fn take_pending_category_external_edit(
        &mut self,
    ) -> Option<(shell::PointerOperationId, PathBuf)> {
        self.page.downcast_mut::<CategoryPage>().and_then(|p| {
            let pending = p.pending_external_edit.as_mut()?;
            let id = pending.operation_id;
            pending.service_path().map(|path| (id, path))
        })
    }

    fn finish_category_external_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let Some(p) = self.page.downcast_mut::<CategoryPage>() else {
            return;
        };
        self.cx
            .finish_category_page_external_edit(p, operation_id, outcome, detail);
    }

    fn finish_agent_external_edit(
        &mut self,
        operation_id: shell::PointerOperationId,
        outcome: pointer_actions::ExternalEditOutcome,
        detail: Option<String>,
    ) {
        let cwd = self.agents_cwd();
        let Some(page) = self.page.downcast_mut::<AgentsPage>() else {
            return;
        };
        page.finish_external_edit(&cwd, operation_id, outcome, detail);
    }

    // ── Rendering ────────────────────────────────────────────────────────

    pub(crate) fn render(
        &self,
        frame: &mut Frame,
        area: Rect,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        let surface_token = self.page.pointer_surface_token();
        #[cfg(test)]
        pointer_acceptance_tests::record_rendered_surface(self.page.pointer_surface_kind());
        self.pointer_surface
            .enabled
            .set(self.extended.tui.mouse_capture);
        if !self.extended.tui.mouse_capture {
            *self.pointer_surface.hover.borrow_mut() = None;
        }
        self.pointer_surface.clear_for_page(area, surface_token);
        let title = self.title();
        let block = Block::default()
            .borders(Borders::ALL)
            .title(format!(" Settings — {title} "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(inner);
        let close_rect = self.pointer_surface.paint_header_button(
            frame,
            layout[0].x,
            layout[0].y,
            layout[0].width,
            SettingsHeaderAction::Close,
            "Close settings",
        );
        let root = self.page.as_any().is::<RootPage>();
        if !root || !self.stack.is_empty() {
            let x = close_rect
                .map(|rect| rect.right().saturating_add(2))
                .unwrap_or(layout[0].x.saturating_add(18));
            let max_width = layout[0].right().saturating_sub(x);
            self.pointer_surface.paint_header_button(
                frame,
                x,
                layout[0].y,
                max_width,
                SettingsHeaderAction::Back,
                "Back",
            );
        } else if self.picker_cwd.is_some() {
            let x = close_rect
                .map(|rect| rect.right().saturating_add(2))
                .unwrap_or(layout[0].x.saturating_add(18));
            let max_width = layout[0].right().saturating_sub(x);
            self.pointer_surface.paint_header_button(
                frame,
                x,
                layout[0].y,
                max_width,
                SettingsHeaderAction::BackToConfigPicker,
                "Back to config picker",
            );
        }
        self.page
            .render_with_links(&self.cx, frame, layout[1], links);
        #[cfg(test)]
        for target in self.pointer_surface.targets.borrow().iter() {
            if let SettingsPointerAction::Page(action) = &target.action {
                pointer_acceptance_tests::record_rendered_action(action, target.enabled);
            }
        }
        self.pointer_surface.buttons.borrow_mut().end_frame();
        if let Some(cursor) = shell::park_cursor_from_markers(frame, layout[1]) {
            frame.set_cursor_position(cursor);
        }
        let help = if self.pointer_surface.enabled.get() {
            format!("{}  click: activate  wheel: scroll", self.help_text())
        } else {
            self.help_text().to_string()
        };
        frame.render_widget(help_line(&help), layout[2]);
    }

    fn title(&self) -> String {
        self.page.title(&self.cx)
    }

    fn help_text(&self) -> &'static str {
        self.page.help_text(&self.cx)
    }
}

impl SettingsPage for RootPage {
    fn pointer_surface_kind(&self) -> SettingsPointerSurfaceKind {
        SettingsPointerSurfaceKind::Root
    }

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
                    DEFAULT_MODEL_TITLE => Some(default_model_page(DefaultModelPage {
                        status: None,
                        scope_label: cx.effective_default_scope_label(),
                        effective_default: cx.effective_default_model(),
                    })),
                    PROVIDERS_TITLE => Some(providers_page(ProvidersPage::List {
                        cursor: providers::initial_list_cursor(&cx.config),
                        status: None,
                        delete_pending: false,
                    })),
                    "Dependencies" => {
                        Some(dependencies_page::page(cx.agents_cwd(), cx.sandbox_enabled))
                    }
                    "Agents" => Some(agents_page(AgentsPage::new(&cx.agents_cwd()))),
                    "Interface" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Interface)))
                    }
                    "Behavior" => {
                        cx.reload_extended();
                        Some(category_page(CategoryPage::new(Category::Behavior)))
                    }
                    "Image spend budgets" => Some(image_spend::page(
                        cx.active_project_root
                            .as_ref()
                            .unwrap_or(&cx.extended_path)
                            .to_string_lossy()
                            .into_owned(),
                    )),
                    "Generation" => Some(image_generation::generation_list_page(
                        image_generation::GenerationPrincipal::local_owner(),
                    )),
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
                            editing: None,
                            buf: TextField::default(),
                            status: None,
                            reset: ResetButton::default(),
                            delete_pending: None,
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
                            pointer_delete_pending: None,
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
        render_root(frame, area, self.cursor, cx);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let pointer_actions::SettingsPointerAction::Root(pointer_actions::RootAction::Open(id)) =
            action
        else {
            return Nav::Stay;
        };
        let Some(index) = root_nodes().iter().position(|node| node.id == id) else {
            return Nav::Stay;
        };
        self.cursor = index;
        self.handle_key(cx, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    fn handle_pointer_scroll(
        &mut self,
        _cx: &mut SettingsCx,
        region: shell::SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region != shell::SettingsScrollRegionId("root") {
            return Nav::Stay;
        }
        let last = root_nodes().len().saturating_sub(1);
        self.cursor = self.cursor.saturating_add_signed(delta).min(last);
        Nav::Stay
    }

    fn title(&self, cx: &SettingsCx) -> String {
        cockpit_core::welcome::display_path(&cx.config_path)
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
pub(super) const PROVIDERS_TITLE: &str = "Providers & Provider Models";
pub(super) const DEFAULT_MODEL_TITLE: &str = "Default model for new sessions";

/// The reorganized top-level menu (implementation note).
/// `Default model for new sessions` leads, then the locked scheme in order;
/// MCP/LSP are kept as extra nodes so integration settings stay reachable
/// from the menu.
fn root_nodes() -> [NavNode; 16] {
    [
        NavNode {
            id: pointer_actions::RootNodeId::DefaultModel,
            title: pointer_actions::RootNodeId::DefaultModel.title(),
            description: "Default model for newly created sessions in the current configuration context. Does not change the model of an already-running session.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Providers,
            title: pointer_actions::RootNodeId::Providers.title(),
            description: "Provider setup and request controls: endpoints, headers, model lists, default model, context/cache, fallback, wire API, and per-provider/per-model inline-<think> extraction overrides.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Dependencies,
            title: "Dependencies",
            description: "Read-only dependency health grouped by safety, selected features, optional integrations, and accelerators.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Agents,
            title: "Agents",
            description: "Manage agent definitions, presets, and per-agent overrides.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Interface,
            title: "Interface",
            description: "Display & input only: vim mode, thinking display for stored reasoning, markdown rendering, mouse, diff style, banner, chrome toggles, emojis, and exit scrollback.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Behavior,
            title: "Behavior",
            description: "Session & agent behavior: default agent, llm mode, approval mode, plan isolation, prediction, shell compression, the utility model, instructions files, and (Advanced) tuning + plan-execution knobs.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::ImageSpend,
            title: "Image spend budgets",
            description: "Explicit request, session, and project image-generation budgets and project window. Suggestions do not authorize dispatch until reviewed and saved.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Generation,
            title: "Generation",
            description: "Image-generation endpoints, targets, workflows, budget, destination grants, and job management. Visibility follows the control-plane authorization matrix.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Privacy,
            title: "Privacy & Safety",
            description: "Redaction (master switch + every source), the prompt-injection guard, and the remote-config opt-in. Advanced holds the redaction internals.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Translation,
            title: "Translation",
            description: "Round-trip utility-model translation: your language and the model's language.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Tools,
            title: "Tools",
            description: "Tool inventory and configuration: web providers, builtin tools, user-defined command tools, and MCP catalogs.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Harnesses,
            title: "Harnesses",
            description: "External coding harnesses (claude, codex, opencode, grok, …) Build/Plan can delegate to via harness_invoke.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Skills,
            title: "Skills",
            description: "Skill scan directories and the auto-! command toggle (Claude vs Codex mode).",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Profile,
            title: "Profile",
            description: "Your display name, shown on the startup banner.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Mcp,
            title: "MCP",
            description: "Model Context Protocol servers: transport, auth, and enabled state.",
        },
        NavNode {
            id: pointer_actions::RootNodeId::Lsp,
            title: "LSP",
            description: "Language servers, diagnostics surfacing, semantic navigation, and install behavior.",
        },
    ]
}

struct NavNode {
    id: pointer_actions::RootNodeId,
    title: &'static str,
    description: &'static str,
}

pub(super) fn save_status(r: Result<(), String>) -> Option<String> {
    match r {
        Ok(()) => Some("saved".into()),
        Err(e) => Some(format!("save failed: {e}")),
    }
}

/// A bottom-of-list `[label]` save-button row. The glyphs are a placeholder;
/// `render_control_lines` paints the exact `[label]` cells through
/// `ButtonRegistry` so the hit rect is the painted label, not the list row.
pub(super) fn save_button_line(label: &str, selected: bool) -> Line<'static> {
    let text = label.trim_start_matches('[').trim_end_matches(']');
    let spec = crate::tui::button::ButtonSpec::new(
        crate::tui::button::ButtonId::Settings(pointer_actions::SettingsPointerAction::Mcp(
            pointer_actions::McpAction::Save,
        )),
        text,
        crate::tui::button::ButtonDispatch::Settings(pointer_actions::SettingsPointerAction::Mcp(
            pointer_actions::McpAction::Save,
        )),
    )
    .focused(selected);
    Line::from(Span::styled(
        crate::tui::button::bracketed_label(text),
        crate::tui::button::button_style(&spec, false, false),
    ))
}

fn render_root(frame: &mut Frame, area: Rect, cursor: usize, cx: &SettingsCx) {
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
    let controls = children
        .iter()
        .map(|node| {
            Some((
                pointer_actions::SettingsPointerAction::Root(pointer_actions::RootAction::Open(
                    node.id,
                )),
                true,
                None,
            ))
        })
        .collect();
    cx.scroll_states.render_control_lines(
        frame,
        rows[0],
        "root",
        (list_lines, Some(cursor)),
        controls,
        (&cx.pointer_surface, shell::SettingsScrollRegionId("root")).into(),
    );

    let desc = children[cursor].description;
    frame.render_widget(
        Paragraph::new(desc.to_string())
            .wrap(Wrap { trim: false })
            .style(muted_style()),
        rows[2],
    );
}

impl SettingsCx {
    /// Safe, non-secret label for the layer that governs the effective
    /// default in this dialog's configuration context. Never a filesystem
    /// path.
    /// The default a newly created session would resolve in this dialog's
    /// configuration context — the layered merge, not the single edited layer.
    pub(super) fn effective_default_model(
        &self,
    ) -> Option<cockpit_config::providers::ActiveModelRef> {
        let cwd = self
            .active_project_root
            .clone()
            .or_else(|| self.picker_cwd.clone());
        match cwd {
            Some(cwd) => cockpit_config::providers::ConfigDoc::load_effective(&cwd).active_model,
            None => self.config.active_model.clone(),
        }
    }

    pub(super) fn effective_default_scope_label(&self) -> String {
        let cwd = self
            .active_project_root
            .clone()
            .or_else(|| self.picker_cwd.clone());
        match cwd
            .as_deref()
            .map(cockpit_config::providers::resolve_effective_default_write_target)
        {
            Some(Ok(target)) => target.scope_label(),
            _ => "current configuration context".to_string(),
        }
    }

    /// Stage the one authoritative default-model request when a Settings edit
    /// changed the layer-wide `active_model`.
    ///
    /// `/settings` never writes `active_model` to a `config.json`: the daemon
    /// owns target-layer selection, locking, the journal, and reload
    /// verification, and it changes no running session.
    fn stage_default_model_change(&mut self) -> bool {
        if self.config.active_model == self.original_config.active_model {
            return false;
        }
        let default_update_id = uuid::Uuid::new_v4();
        let request = match self.config.active_model.clone() {
            Some(active) => Request::SetDefaultModel {
                default_update_id,
                provider: Some(active.provider),
                model: Some(active.model),
                reasoning_effort: active.reasoning_effort.map(|effort| effort.value),
                thinking_mode: active.thinking_mode,
                prompt_cache_retention: active.prompt_cache_retention,
                clear: false,
            },
            None => Request::SetDefaultModel {
                default_update_id,
                provider: None,
                model: None,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
                clear: true,
            },
        };
        self.pending_default_model_update_id = Some(default_update_id);
        self.pending_daemon_request = Some(request);
        true
    }

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
        let notice = cockpit_core::secret_ref::protect_literal_headers(
            &mut merged.providers,
            self.credential_store_path.as_deref(),
        )
        .map_err(|e| e.to_string())?;
        // The layer-wide default is never part of this file write; it goes to
        // the daemon's authoritative effective-default operation, and the
        // dialog only shows the new value once that verified result arrives.
        self.stage_default_model_change();
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
            .flat_map(|header| cockpit_core::envref::referenced_names(&header.value))
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
                .flat_map(|header| cockpit_core::envref::referenced_names(&header.value))
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
            Some(path) => cockpit_core::credentials::CredentialStore::open(path.clone()),
            None => cockpit_core::credentials::CredentialStore::open_default(),
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
    // `active_model` is deliberately not merged here. It is layer-wide default
    // policy owned by the daemon's one effective-default mutation, so Settings
    // stages a `SetDefaultModel` request instead of writing the file directly.
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
        tool_surface,
        tool_surface_touched,
        cwd,
        status,
    } = wizard;
    macro_rules! submit_answer {
        ($answer:expr $(,)?) => {
            let answer = $answer;
            submit_setup_wizard_answer(
                SetupWizardSubmit {
                    run,
                    inputs: SetupWizardInputs {
                        cursor,
                        text,
                        multi,
                        multi_touched,
                        tool_surface,
                        tool_surface_touched,
                    },
                    status,
                },
                answer,
            );
        };
    }
    if run.is_complete() {
        return matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q'));
    }
    let Some(step) = run.current_step().cloned() else {
        return false;
    };
    match step.kind {
        cockpit_core::wizard::StepKind::Select { .. } => {
            let options = run.select_options();
            match list_key_action(key, cursor, options.len()) {
                ListAction::Close => return true,
                ListAction::Stay => {}
                ListAction::Select(index) => {
                    submit_answer!(cockpit_core::wizard::WizardAnswer::Select(
                        options[index].id.to_string()
                    ),);
                }
            }
        }
        cockpit_core::wizard::StepKind::Confirm => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                let answer = run
                    .prefill()
                    .unwrap_or(cockpit_core::wizard::WizardAnswer::Confirm(false));
                submit_answer!(answer);
            }
            KeyCode::Char('y') | KeyCode::Char('Y') => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Confirm(true));
            }
            KeyCode::Char('n') | KeyCode::Char('N') => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Confirm(false));
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::Text => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Text(
                    text.text().to_string()
                ),);
            }
            _ => {
                text.handle_key(key);
            }
        },
        cockpit_core::wizard::StepKind::Info => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                submit_answer!(cockpit_core::wizard::WizardAnswer::Acknowledged);
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::Action { .. } => {
            if step.id == "security-save" {
                match cockpit_core::wizard::apply_security_answers(cwd, run) {
                    Ok(Some(path)) => *status = Some(format!("Saved {}", path.display())),
                    Ok(None) => *status = Some("Security settings unchanged.".to_string()),
                    Err(error) => {
                        *status = Some(error.to_string());
                        return false;
                    }
                }
            } else if step.id == "model-save" {
                match cockpit_core::wizard::apply_model_answers(cwd, run) {
                    Ok(outcome) if outcome.changed_nothing() => {
                        *status = Some("No model-setting changes were needed.".to_string())
                    }
                    Ok(outcome) => {
                        let mut parts = Vec::new();
                        if let Some(path) = outcome.model_file.as_ref() {
                            parts.push(format!("Saved model settings to {}.", path.display()));
                        }
                        // Layer-wide default policy names a safe scope label,
                        // never a filesystem path.
                        if let Some(scope) = outcome.default_scope.as_ref() {
                            parts.push(format!(
                                "Set the default model for new sessions ({scope}); running sessions are unchanged."
                            ));
                        }
                        *status = Some(parts.join(" "));
                    }
                    Err(error) => {
                        *status = Some(format!("Could not save model settings: {error}"));
                        return false;
                    }
                }
            }
            submit_answer!(cockpit_core::wizard::WizardAnswer::Acknowledged);
        }
        cockpit_core::wizard::StepKind::MultiToggle { options } => match key.code {
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
                    if let Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) =
                        run.prefill()
                    {
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
                    && let Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) =
                        run.prefill()
                {
                    cockpit_core::wizard::WizardAnswer::MultiToggle(values)
                } else {
                    cockpit_core::wizard::WizardAnswer::MultiToggle(multi.iter().cloned().collect())
                };
                submit_answer!(answer);
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::ToolSurface => match key.code {
            KeyCode::Esc => return true,
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                *cursor = crate::tui::nav::wrap_prev(
                    *cursor,
                    cockpit_core::agents::tool_surface_catalog().len(),
                );
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                *cursor = crate::tui::nav::wrap_next(
                    *cursor,
                    cockpit_core::agents::tool_surface_catalog().len(),
                );
            }
            KeyCode::Char(' ') => {
                touch_tool_surface(run, tool_surface, tool_surface_touched);
                if let Some(tool) = cockpit_core::agents::tool_surface_catalog().get(*cursor) {
                    if tool_surface
                        .tools
                        .iter()
                        .any(|existing| existing == tool.name)
                    {
                        tool_surface.tools.retain(|existing| existing != tool.name);
                    } else {
                        tool_surface.tools.push(tool.name.to_string());
                        tool_surface.tools.sort();
                    }
                    if !tool_surface
                        .tools
                        .iter()
                        .any(|existing| existing == tool.name)
                    {
                        tool_surface.tool_tiers.remove(tool.name);
                    }
                }
            }
            KeyCode::Char('t') => {
                touch_tool_surface(run, tool_surface, tool_surface_touched);
                if let Some(tool) = cockpit_core::agents::tool_surface_catalog().get(*cursor) {
                    if !tool_surface
                        .tools
                        .iter()
                        .any(|existing| existing == tool.name)
                    {
                        tool_surface.tools.push(tool.name.to_string());
                        tool_surface.tools.sort();
                    }
                    let current = tool_surface
                        .tool_tiers
                        .get(tool.name)
                        .copied()
                        .unwrap_or(cockpit_core::agents::ToolTier::Enabled);
                    let tiers = cockpit_core::agents::legal_tool_tiers(tool.name);
                    let index = tiers.iter().position(|tier| *tier == current).unwrap_or(0);
                    let next = tiers[(index + 1) % tiers.len()];
                    if next == cockpit_core::agents::ToolTier::Enabled {
                        tool_surface.tool_tiers.remove(tool.name);
                    } else {
                        tool_surface.tool_tiers.insert(tool.name.to_string(), next);
                    }
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                touch_tool_surface(run, tool_surface, tool_surface_touched);
                submit_answer!(cockpit_core::wizard::WizardAnswer::ToolSurface(
                    tool_surface.clone()
                ),);
            }
            _ => {}
        },
        cockpit_core::wizard::StepKind::Secret => {}
    }
    false
}

struct SetupWizardInputs<'a> {
    cursor: &'a mut usize,
    text: &'a mut TextField,
    multi: &'a mut std::collections::BTreeSet<String>,
    multi_touched: &'a mut bool,
    tool_surface: &'a mut cockpit_core::agents::ToolSurfaceSelection,
    tool_surface_touched: &'a mut bool,
}

struct SetupWizardSubmit<'a> {
    run: &'a mut cockpit_core::wizard::WizardRun,
    inputs: SetupWizardInputs<'a>,
    status: &'a mut Option<String>,
}

fn submit_setup_wizard_answer(
    state: SetupWizardSubmit<'_>,
    answer: cockpit_core::wizard::WizardAnswer,
) {
    let SetupWizardSubmit {
        run,
        inputs,
        status,
    } = state;
    match run.submit(answer) {
        Ok(()) => sync_setup_wizard_inputs(run, inputs),
        Err(error) => *status = Some(error),
    }
}

fn sync_setup_wizard_inputs(run: &cockpit_core::wizard::WizardRun, inputs: SetupWizardInputs<'_>) {
    let SetupWizardInputs {
        cursor,
        text,
        multi,
        multi_touched,
        tool_surface,
        tool_surface_touched,
    } = inputs;
    *cursor = setup_wizard_cursor_for_current_prefill(run);
    multi.clear();
    *multi_touched = false;
    *tool_surface = cockpit_core::agents::ToolSurfaceSelection::default();
    *tool_surface_touched = false;
    let Some(step) = run.current_step() else {
        return;
    };
    match step.kind {
        cockpit_core::wizard::StepKind::Text => {
            let value = match run.prefill() {
                Some(cockpit_core::wizard::WizardAnswer::Text(value)) => value,
                _ => String::new(),
            };
            text.set(value);
        }
        cockpit_core::wizard::StepKind::MultiToggle { .. } => {
            if let Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) = run.prefill() {
                multi.extend(values);
            }
        }
        cockpit_core::wizard::StepKind::ToolSurface => {
            if let Some(cockpit_core::wizard::WizardAnswer::ToolSurface(value)) = run.prefill() {
                *tool_surface = value;
            }
        }
        _ => {}
    }
}

fn setup_wizard_cursor_for_current_prefill(run: &cockpit_core::wizard::WizardRun) -> usize {
    let Some(step) = run.current_step() else {
        return 0;
    };
    let cockpit_core::wizard::StepKind::Select { .. } = &step.kind else {
        return 0;
    };
    let Some(cockpit_core::wizard::WizardAnswer::Select(value)) = run.prefill() else {
        return 0;
    };
    run.select_options()
        .iter()
        .position(|option| option.id == value)
        .unwrap_or(0)
}

fn touch_tool_surface(
    run: &cockpit_core::wizard::WizardRun,
    tool_surface: &mut cockpit_core::agents::ToolSurfaceSelection,
    touched: &mut bool,
) {
    if *touched {
        return;
    }
    if let Some(cockpit_core::wizard::WizardAnswer::ToolSurface(value)) = run.prefill() {
        *tool_surface = value;
    }
    *touched = true;
}

enum WorkspaceTrustAction {
    Stay,
    Choose(cockpit_config::WorkspaceTrustMode),
}

fn workspace_trust_key_action(key: KeyEvent, cursor: &mut usize) -> WorkspaceTrustAction {
    use cockpit_config::WorkspaceTrustMode;
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
    root: &cockpit_config::trust::TrustRoot,
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
            cockpit_config::WorkspaceTrustMode::Trust,
        ),
        (
            "ignore-config",
            "open but ignore project .cockpit config and approvals",
            cockpit_config::WorkspaceTrustMode::IgnoreConfig,
        ),
        (
            "untrusted",
            "refuse to open",
            cockpit_config::WorkspaceTrustMode::Untrusted,
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
            .map(|e| cockpit_core::welcome::display_path(&e.path).chars().count())
            .max()
            .unwrap_or(0);
        for (i, entry) in entries.iter().enumerate() {
            let marker = if i == cursor { "▸ " } else { "  " };
            let path_str = cockpit_core::welcome::display_path(&entry.path);
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
    wizards: &[cockpit_core::wizard::WizardDescriptor],
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

fn render_model_setup_choice(
    frame: &mut Frame,
    area: Rect,
    confirmed: Option<&(String, String)>,
    pending: Option<&(String, String)>,
    cursor: usize,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup — model ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let selected = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    let mut lines: Vec<Line<'static>> = vec![
        Line::from(Span::styled(
            "Configure which model?",
            Style::default().fg(Color::White),
        )),
        Line::default(),
    ];
    if let Some((provider, model)) = confirmed {
        for (index, (label, description)) in [
            (
                format!("Use the currently selected model: {provider}/{model}"),
                "Configure this exact pair; it does not change the live session model.".to_string(),
            ),
            (
                "Choose a different model".to_string(),
                "Choose a provider, then one of that provider’s models.".to_string(),
            ),
        ]
        .into_iter()
        .enumerate()
        {
            let marker = if index == cursor { "▸ " } else { "  " };
            let style = if index == cursor {
                selected
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label, style),
                Span::raw("  "),
                Span::styled(description, muted),
            ]));
        }
    } else {
        if let Some((provider, model)) = pending {
            lines.push(Line::from(Span::styled(
                format!("{provider}/{model} is still being selected. Wait for confirmation or choose a different model."),
                muted,
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "No model is confirmed for this session; choose a provider and model to configure.",
                muted,
            )));
        }
        lines.push(Line::default());
        let style = if cursor == 0 {
            selected
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(if cursor == 0 { "▸ " } else { "  " }),
            Span::styled("Choose a different model", style),
            Span::raw("  "),
            Span::styled(
                "Choose a provider, then one of that provider’s models.",
                muted,
            ),
        ]));
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
        tool_surface,
        tool_surface_touched,
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
        let complete = match run.descriptor().id {
            cockpit_core::wizard::MODEL_WIZARD_ID => "Model setup complete.",
            "security" => "Security setup complete.",
            _ => "Setup complete.",
        };
        lines.push(Line::from(complete));
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
            cockpit_core::wizard::StepKind::Select { .. } => {
                let options = run.select_options();
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
            cockpit_core::wizard::StepKind::Confirm => {
                let current = match run.prefill() {
                    Some(cockpit_core::wizard::WizardAnswer::Confirm(true)) => "yes",
                    _ => "no",
                };
                lines.push(Line::from(format!("Current/default: {current}")));
            }
            cockpit_core::wizard::StepKind::Text => {
                lines.push(Line::from(format!("Value: {}", text.text())));
            }
            cockpit_core::wizard::StepKind::Info => {
                lines.push(Line::from("Press Enter to continue."));
            }
            cockpit_core::wizard::StepKind::Action { progress } => {
                lines.push(Line::from(*progress));
            }
            cockpit_core::wizard::StepKind::MultiToggle { options } => {
                let prefill_values = if *multi_touched {
                    None
                } else {
                    match run.prefill() {
                        Some(cockpit_core::wizard::WizardAnswer::MultiToggle(values)) => {
                            Some(values)
                        }
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
            cockpit_core::wizard::StepKind::ToolSurface => {
                let surface = if *tool_surface_touched {
                    tool_surface.clone()
                } else {
                    match run.prefill() {
                        Some(cockpit_core::wizard::WizardAnswer::ToolSurface(value)) => value,
                        _ => cockpit_core::agents::ToolSurfaceSelection::default(),
                    }
                };
                let mut last_family = "";
                for (index, item) in cockpit_core::agents::tool_surface_catalog()
                    .into_iter()
                    .enumerate()
                {
                    if item.family != last_family {
                        if !last_family.is_empty() {
                            lines.push(Line::default());
                        }
                        lines.push(Line::from(Span::styled(item.family.to_string(), muted)));
                        last_family = item.family;
                    }
                    let marker = if index == *cursor { "▸ " } else { "  " };
                    let checked = surface.tools.iter().any(|tool| tool == item.name);
                    let tier = if checked {
                        surface
                            .tool_tiers
                            .get(item.name)
                            .copied()
                            .unwrap_or(cockpit_core::agents::ToolTier::Enabled)
                            .label()
                    } else {
                        "-"
                    };
                    let style = if index == *cursor {
                        selected
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(if checked { "[x]" } else { "[ ]" }.to_string(), style),
                        Span::raw(" "),
                        Span::styled(item.name.to_string(), style),
                        Span::raw("  "),
                        Span::styled(format!("tier: {tier}"), muted),
                    ]));
                }
            }
            cockpit_core::wizard::StepKind::Secret => {
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
        help_line("↑/↓  space: toggle  t: tier  enter: select/continue  y/n: confirm  esc: close"),
        layout[1],
    );
}

fn render_first_run_complete(frame: &mut Frame, area: Rect, summary: &str) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" Setup complete ");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let lines = vec![
        Line::from("Cockpit is ready."),
        Line::from(summary.to_string()),
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
        return dir.path.join(cockpit_config::dirs::CONFIG_FILE);
    }
    let project = cwd.join(".cockpit");
    // Best-effort scaffold; if it fails the doc loader still writes on save.
    let _ = scaffold_config_dir(&project);
    project.join(cockpit_config::dirs::CONFIG_FILE)
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
pub(super) mod tests;
