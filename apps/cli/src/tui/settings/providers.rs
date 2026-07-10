//! `/settings → Providers`: the largest settings page tree.
//!
//! Lives here so the `mod.rs` dispatcher and the unrelated UI/Tools
//! pages aren't drowned by ~2K lines of provider-specific state
//! machine. Owns:
//!   - the [`ProvidersPage`] state enum (List, Add wizard, Edit page,
//!     Headers sub-page, FetchAll, CopilotSetup)
//!   - per-page state types (`AddState` + `AddStep`, `EditState` +
//!     `EditField`, `HeaderEditor` + modes, `FetchAllState`,
//!     `CopilotSetupState`)
//!   - the corresponding handlers + renderers on [`SettingsDialog`]
//!     (multiple `impl` blocks across this file and `mod.rs`)
//!   - provider-only free helpers (`render_header_editor`,
//!     `render_field_row`, `valid_url`, `valid_id`,
//!     `apply_copilot_setup`, `render_copilot_setup_body`).

use std::path::PathBuf;

use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};

use crate::auth::{
    codex_oauth,
    copilot_setup::{self, Shell as CopilotShell},
    xai_oauth,
};
use crate::config::providers::{
    AuthKind, HeaderSpec, ModelEntry, ModelFetchStatusKind, ModelMergePolicy,
    OnUnlistedModelsFetch, ProviderEntry, ProviderModelCatalog, WireApi,
    apply_template_model_defaults, format_model_fetch_age, merge_fetched_models_with_policy,
    provider_model_fetch_display_state, provider_model_fetch_reason_display,
    redact_model_fetch_reason,
};
use crate::envref;
use crate::providers::models_fetch::{self, FetchOutcome};
use crate::providers::{self as templates, ProviderTemplate};
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;

use super::auth::FetchHandle;
use super::settings_editor::{SettingsEditor, SettingsResult};
use super::shell::{clamp_to_char_boundary, selected_line_from_marker};
use super::{Nav, Page, RowDeleteConfirm, SettingsDialog, save_button_line};

/// One selectable action on the Edit-provider menu. The menu is built
/// dynamically (see [`edit_menu_actions`]) so render and key handling
/// share a single source of truth and stay index-correct when the
/// conditional "Copilot auth" row is present or absent.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum EditAction {
    Url,
    Headers,
    /// Only present for Copilot providers (see [`is_github_copilot_provider`]).
    CopilotAuth,
    /// Present for xAI SuperGrok OAuth providers.
    GrokOAuthAuth,
    CodexOAuthAuth,
    Models,
    Settings,
    Favorite,
    Refetch,
    Delete,
    Save,
    Back,
}

/// Build the ordered Edit-menu action list for `entry`. The "Copilot
/// auth" row is included only when `entry` is a Copilot provider. This is
/// the single source of truth for both [`Self::render_edit`] and
/// [`Self::handle_edit_key`]: the cursor indexes into the returned `Vec`
/// and the handler dispatches on the action, never a literal index.
fn edit_menu_actions(provider_id: &str, entry: &ProviderEntry) -> Vec<EditAction> {
    let mut actions = vec![EditAction::Url, EditAction::Headers];
    if models_fetch::is_github_copilot_provider(provider_id, entry) {
        actions.push(EditAction::CopilotAuth);
    }
    if models_fetch::is_xai_oauth_provider(provider_id, entry) {
        actions.push(EditAction::GrokOAuthAuth);
    }
    if models_fetch::is_codex_oauth_provider(provider_id, entry) {
        actions.push(EditAction::CodexOAuthAuth);
    }
    actions.extend([
        EditAction::Models,
        EditAction::Settings,
        EditAction::Favorite,
        EditAction::Refetch,
        EditAction::Delete,
        EditAction::Save,
        EditAction::Back,
    ]);
    actions
}

fn provider_settings_summary(entry: &ProviderEntry) -> String {
    let ctx = &entry.context;
    let mode = match entry.mode {
        Some(crate::config::extended::LlmMode::Defensive) => "defensive",
        Some(crate::config::extended::LlmMode::Normal) => "normal",
        Some(crate::config::extended::LlmMode::Frontier) => "frontier",
        None => "inherit",
    };
    let prune = match entry.auto_prune {
        Some(false) => "prune off".to_string(),
        _ => format!(
            "prune {}%/{}%",
            ctx.auto_prune_pct, ctx.auto_prune_prunable_pct
        ),
    };
    let mut summary = format!(
        "compact {}% · {prune} · cache {}s · ttft {}s · idle {}s · mode {mode}",
        ctx.auto_compact_pct,
        entry.cache.ttl_secs,
        entry.timeout.ttft_secs,
        entry.timeout.idle_secs,
    );
    summary.push_str(&format!(
        " · trust {} · quality {} · cost {} · subagents {}",
        match entry.trust {
            Some(crate::config::providers::ModelTrust::Trusted) => "trusted",
            Some(crate::config::providers::ModelTrust::Untrusted) | None => "untrusted",
        },
        entry
            .quality_rank
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        entry
            .cost_rank
            .map(|v| v.to_string())
            .unwrap_or_else(|| "0".to_string()),
        if entry.subagent_invokable.unwrap_or(false) {
            "on"
        } else {
            "off"
        },
    ));
    match entry.wire_api {
        WireApi::Auto => {}
        WireApi::Completions => summary.push_str(" · wire completions"),
        WireApi::Responses => summary.push_str(" · wire responses"),
    }
    if entry.backup.is_some() {
        summary.push_str(" · backup set");
    }
    summary
}

fn provider_catalog_suffix(catalog: ProviderModelCatalog) -> &'static str {
    match catalog {
        ProviderModelCatalog::Live => "",
        ProviderModelCatalog::CodexFallback => " · fallback catalog active",
    }
}

fn provider_catalog_suffix_for_entry(entry: &ProviderEntry) -> String {
    match entry.model_catalog {
        ProviderModelCatalog::Live => String::new(),
        ProviderModelCatalog::CodexFallback => {
            let mut suffix = format!(
                " · fallback catalog active ({} model(s))",
                entry.models.len()
            );
            if entry.last_model_fetch.as_ref().is_some_and(|status| {
                status.status == ModelFetchStatusKind::Fallback
                    && status
                        .reason
                        .as_deref()
                        .is_some_and(|reason| reason.contains("empty model list"))
            }) {
                suffix.push_str(" — live /models returned empty list; using hardcoded fallback");
            }
            suffix
        }
    }
}

fn fetch_success_message(count: usize, catalog: ProviderModelCatalog) -> String {
    match catalog {
        ProviderModelCatalog::Live => format!("fetched {count} model(s) from /models"),
        ProviderModelCatalog::CodexFallback => {
            format!("using fallback Codex catalog ({count} model(s)); live /models fetch failed")
        }
    }
}

fn refetch_summary(entry: &ProviderEntry) -> String {
    format!(
        "{} model(s){}{}",
        entry.models.len(),
        provider_catalog_suffix_for_entry(entry),
        entry
            .models_fetched_at
            .map(|t| format!(" — last {}", t.format("%Y-%m-%d %H:%M UTC")))
            .unwrap_or_default()
    )
}

/// Cycle the global on-unlisted-models-fetch policy (the `m` key on the
/// providers list): `ask → keep → remove → ask`. `None` (unset) starts the
/// cycle at `ask`. Governs what a `/fetch-models` run does with config
/// models that are absent from the freshly-fetched upstream list.
fn cycle_on_unlisted(cur: Option<OnUnlistedModelsFetch>) -> OnUnlistedModelsFetch {
    match cur {
        None | Some(OnUnlistedModelsFetch::Ask) => OnUnlistedModelsFetch::Keep,
        Some(OnUnlistedModelsFetch::Keep) => OnUnlistedModelsFetch::Remove,
        Some(OnUnlistedModelsFetch::Remove) => OnUnlistedModelsFetch::Ask,
    }
}

/// Human label for the on-unlisted-models-fetch policy, including the
/// unset (defaults-to-ask) case.
fn on_unlisted_label(v: Option<OnUnlistedModelsFetch>) -> &'static str {
    match v {
        None => "ask (default — prompt each fetch)",
        Some(OnUnlistedModelsFetch::Ask) => "ask (prompt each fetch)",
        Some(OnUnlistedModelsFetch::Keep) => "keep (retain drifted-out models)",
        Some(OnUnlistedModelsFetch::Remove) => "remove (drop drifted-out models)",
    }
}

fn display_header_value(name: &str, value: &str) -> String {
    if value.trim().is_empty() {
        return String::new();
    }
    if header_value_is_env_only(value) {
        return value.to_string();
    }
    if is_sensitive_header_name(name) || looks_like_literal_secret(value) {
        return mask_header_value(value);
    }
    value.to_string()
}

fn is_sensitive_header_name(name: &str) -> bool {
    let normalized = name.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "authorization"
            | "proxy-authorization"
            | "x-api-key"
            | "api-key"
            | "openai-organization"
            | "x-openai-organization"
    ) || normalized.contains("api-key")
        || normalized.contains("apikey")
        || normalized.contains("token")
        || normalized.contains("secret")
}

fn header_value_is_env_only(value: &str) -> bool {
    let resolved = envref::resolve(value);
    if resolved.referenced.is_empty() {
        return false;
    }
    let mut literal = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let at_dollar = bytes[i] == b'$';
        let prev_ok = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if at_dollar
            && prev_ok
            && let Some((_, rest)) = take_env_var_name(&bytes[i + 1..])
        {
            i = bytes.len() - rest.len();
            continue;
        }
        let ch_len = utf8_char_len(bytes[i]);
        literal.push_str(&value[i..i + ch_len]);
        i += ch_len;
    }
    let lower = literal.to_ascii_lowercase();
    lower
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '-'))
        .filter(|part| !part.is_empty())
        .all(|part| {
            matches!(
                part,
                "bearer" | "basic" | "token" | "key" | "apikey" | "api-key"
            )
        })
}

fn looks_like_literal_secret(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() >= 20 {
        return true;
    }
    let compact_len = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .count();
    compact_len >= 12
}

fn mask_header_value(value: &str) -> String {
    let trimmed = value.trim();
    let tail: String = trimmed
        .chars()
        .rev()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(4)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let suffix = if tail.is_empty() {
        "...".to_string()
    } else {
        format!("...{tail}")
    };
    let lower = trimmed.to_ascii_lowercase();
    for scheme in ["Bearer", "Basic"] {
        if lower.starts_with(&scheme.to_ascii_lowercase())
            && trimmed
                .get(scheme.len()..)
                .is_some_and(|rest| rest.starts_with(char::is_whitespace))
        {
            return format!("{scheme} {suffix}");
        }
    }
    suffix
}

fn take_env_var_name(rest: &[u8]) -> Option<(&str, &[u8])> {
    if rest.is_empty() {
        return None;
    }
    let first = rest[0];
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return None;
    }
    let end = rest
        .iter()
        .position(|b| !(b.is_ascii_alphanumeric() || *b == b'_'))
        .unwrap_or(rest.len());
    let name = std::str::from_utf8(&rest[..end]).ok()?;
    Some((name, &rest[end..]))
}

fn utf8_char_len(first: u8) -> usize {
    if first < 0xC0 {
        1
    } else if first < 0xE0 {
        2
    } else if first < 0xF0 {
        3
    } else {
        4
    }
}

pub(super) fn initial_list_cursor(config: &crate::config::providers::ProvidersConfig) -> usize {
    if config.providers.is_empty() { 0 } else { 1 }
}

fn list_provider_idx(cursor: usize, provider_count: usize) -> Option<usize> {
    cursor.checked_sub(1).filter(|idx| *idx < provider_count)
}

#[allow(private_interfaces)]
pub(super) enum ProvidersPage {
    /// Top-level list of configured providers + the "add new" affordance.
    List {
        cursor: usize,
        status: Option<String>,
        /// True after the first `d` press while the cursor is on a
        /// provider row. The next `d` confirms the delete; any other
        /// key clears it. Mirrors the same affordance on the Edit page.
        delete_pending: bool,
    },
    /// Add-provider wizard.
    Add(AddState),
    /// Edit a specific provider.
    Edit(EditState),
    /// Edit the headers list for the provider whose Edit state is in
    /// `parent`. Reached by Enter on the "Headers" row of the Edit
    /// page. The whole pane is the header editor; back navigation
    /// returns to `Edit(parent)` with `parent.entry.headers` set from
    /// `editor.rows`.
    Headers {
        editor: HeaderEditor,
        parent: Box<EditState>,
    },
    /// Manage the model list for the provider whose Edit state is in
    /// `parent`. Reached by Enter on the "Models" row of the Edit page.
    /// Browse rows; add a manual entry; edit a manual entry; delete any
    /// entry. Back navigation returns to `Edit(parent)` with
    /// `parent.entry.models` set from `editor.rows`. The editor is boxed
    /// because [`ModelEditor`] is large enough to bloat the settings
    /// `Page` enum otherwise.
    Models {
        editor: Box<ModelEditor>,
        parent: Box<EditState>,
    },
    /// Edit a single model's `Option<…>` settings overrides
    /// (implementation note). Reached by Enter/l/→ on a
    /// model row in the Models sub-page (every model, fetched or manual).
    /// Back navigation returns to `Models { parent }` with the model's
    /// override fields written back into the editor's rows.
    ModelSettings {
        editor: SettingsEditor,
        models: Box<ModelEditor>,
        parent: Box<EditState>,
    },
    /// Edit the provider's concrete settings values
    /// (implementation note). Reached by the "Settings" row
    /// on the Edit page. Back navigation returns to `Edit(parent)` with the
    /// concrete values written into `parent.entry`.
    ProviderSettings {
        editor: SettingsEditor,
        parent: Box<EditState>,
    },
    /// Triggered by /fetch-models — prompts on unlisted models.
    FetchAll(FetchAllState),
    /// Per-provider refetch prompt when configured non-manual models are
    /// absent from the upstream /models response and policy is Ask.
    FetchOnePrompt(FetchOnePromptState),
    /// Per-provider live fetch failed but a fallback catalog is available.
    FetchFallbackPrompt(FetchFallbackPromptState),
    /// One-button "Set up GitHub Copilot auth" confirm screen for the
    /// Copilot provider whose Edit state is in `parent`. Reached by Enter
    /// on the "Copilot auth" row of the Edit page (Copilot providers
    /// only). Appends `export GH_TOKEN=$(gh auth token)` to the user's
    /// shell rc and sets `GH_TOKEN` in the running process so Copilot
    /// works without a restart. Back navigation returns to `Edit(parent)`
    /// with the parent's cursor/status/unsaved edits intact.
    CopilotSetup {
        state: CopilotSetupState,
        parent: Box<EditState>,
    },
    GrokOAuthSetup {
        state: Box<GrokOAuthSetupState>,
        parent: Box<EditState>,
    },
    CodexOAuthSetup {
        state: Box<CodexOAuthSetupState>,
        parent: Box<EditState>,
    },
}

impl ProvidersPage {
    /// The text field a paste should land in for the page's current focus,
    /// or `None` while no field is open. Mirrors the char-dispatch focus
    /// logic in the page's key handlers so paste targets the same buffer.
    pub(super) fn active_text_field(&mut self) -> Option<&mut TextField> {
        match self {
            ProvidersPage::List { .. }
            | ProvidersPage::FetchAll(_)
            | ProvidersPage::FetchOnePrompt(_)
            | ProvidersPage::FetchFallbackPrompt(_)
            | ProvidersPage::CopilotSetup { .. } => None,
            ProvidersPage::GrokOAuthSetup { state, .. } => {
                state.manual_mode.then_some(&mut state.manual_input)
            }
            ProvidersPage::CodexOAuthSetup { .. } => None,
            ProvidersPage::Add(s) => match &mut s.step {
                AddStep::EditId => Some(&mut s.id_field),
                AddStep::EditUrl => Some(&mut s.url_field),
                AddStep::EditHeaders => s.headers.active_text_field(),
                AddStep::GrokOAuthAuth(state) => {
                    state.manual_mode.then_some(&mut state.manual_input)
                }
                AddStep::PickTemplate { .. }
                | AddStep::CopilotAuth(_)
                | AddStep::CodexOAuthAuth(_)
                | AddStep::Saving
                | AddStep::Fetching
                | AddStep::Done => None,
            },
            ProvidersPage::Edit(s) => s.editing_field.is_some().then_some(&mut s.field_buf),
            ProvidersPage::Headers { editor, .. } => editor.active_text_field(),
            ProvidersPage::Models { editor, .. } => editor.active_text_field(),
            ProvidersPage::ModelSettings { editor, .. }
            | ProvidersPage::ProviderSettings { editor, .. } => editor.active_text_field(),
        }
    }
}

/// State for the "Set up GitHub Copilot auth" sub-page.
pub(super) struct CopilotSetupState {
    /// Detected shell. `None` means we'll show manual instructions
    /// instead of a write button.
    pub(super) shell: Option<CopilotShell>,
    /// Absolute rc-file path we'd append to. `None` when shell is None.
    pub(super) rc_path: Option<PathBuf>,
    /// `Some(true)` if our marker is already in the rc file. The
    /// confirm prompt collapses to a "remove and re-add" hint.
    pub(super) already_configured: bool,
    /// Action result after the user confirms. On success, we also
    /// inject `GH_TOKEN` into the running process so the resolver
    /// picks it up before the user restarts.
    pub(super) outcome: Option<Result<String, String>>,
}

impl CopilotSetupState {
    pub(super) fn new() -> Self {
        let shell = copilot_setup::detect_shell();
        let rc_path = shell.and_then(copilot_setup::rc_path);
        let already_configured = rc_path
            .as_deref()
            .and_then(|p| copilot_setup::rc_already_configured(p).ok())
            .unwrap_or(false);
        Self {
            shell,
            rc_path,
            already_configured,
            outcome: None,
        }
    }
}

pub(super) struct GrokOAuthSetupState {
    pub(super) cursor: usize,
    pub(super) logged_in: bool,
    pub(super) status: Option<Result<String, String>>,
    pub(super) manual_mode: bool,
    pub(super) manual_input: TextField,
    pub(super) manual_login: Option<xai_oauth::ManualLogin>,
    pub(super) authorize_url: Option<String>,
    pub(super) pending: bool,
    pub(super) ssh_manual_only: bool,
    pub(super) spinner_tick: usize,
}

pub(super) struct CodexOAuthSetupState {
    pub(super) cursor: usize,
    pub(super) logged_in: bool,
    pub(super) status: Option<Result<String, String>>,
    pub(super) pending: Option<codex_oauth::DeviceLogin>,
    pub(super) polling: bool,
    pub(super) spinner_tick: usize,
}

impl CodexOAuthSetupState {
    pub(super) fn new() -> Self {
        Self {
            cursor: 0,
            logged_in: codex_oauth::is_logged_in(),
            status: None,
            pending: None,
            polling: false,
            spinner_tick: 0,
        }
    }
}

impl GrokOAuthSetupState {
    pub(super) fn new() -> Self {
        Self {
            cursor: 0,
            logged_in: xai_oauth::is_logged_in(),
            status: None,
            manual_mode: false,
            manual_input: TextField::default(),
            manual_login: None,
            authorize_url: None,
            pending: false,
            ssh_manual_only: crate::clipboard::is_ssh(),
            spinner_tick: 0,
        }
    }
}

pub(super) fn oauth_setup_confirming_logged_in(
    logged_in: bool,
    in_progress: bool,
    manual_mode: bool,
) -> bool {
    logged_in && !in_progress && !manual_mode
}

pub(super) fn oauth_setup_help_text(logged_in_confirmation: bool) -> &'static str {
    if logged_in_confirmation {
        "enter: continue  esc: back"
    } else {
        "↑/↓  enter: choose  s: skip/continue  esc: back"
    }
}

fn oauth_option_cursor_prev(cursor: usize, len: usize) -> usize {
    if cursor >= len {
        0
    } else {
        crate::tui::nav::wrap_prev(cursor, len)
    }
}

fn oauth_option_cursor_next(cursor: usize, len: usize) -> usize {
    if cursor >= len {
        0
    } else {
        crate::tui::nav::wrap_next(cursor, len)
    }
}

pub(crate) enum OAuthActionRequest {
    CodexBegin,
    CodexPoll(codex_oauth::DeviceLogin),
    CodexCancel,
    GrokBegin {
        is_ssh: bool,
    },
    GrokComplete {
        login: xai_oauth::ManualLogin,
        input: String,
    },
    GrokCancel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrokLoginSelection {
    ManualOnly,
    Auto,
}

fn grok_login_selection(is_ssh: bool) -> GrokLoginSelection {
    if is_ssh {
        GrokLoginSelection::ManualOnly
    } else {
        GrokLoginSelection::Auto
    }
}

fn copy_oauth_url_with(
    url: Option<&str>,
    status: &mut Option<Result<String, String>>,
    copy: impl FnOnce(&str) -> Result<crate::clipboard::CopyOutcome, crate::clipboard::CopyError>,
) {
    let Some(url) = url else {
        *status = Some(Ok("no OAuth URL yet".to_string()));
        return;
    };
    *status = Some(match copy(url) {
        Ok(_) => Ok("copied OAuth URL".to_string()),
        Err(e) => Err(e.to_string()),
    });
}

pub(super) struct AddState {
    pub(super) step: AddStep,
    pub(super) template: Option<&'static ProviderTemplate>,
    pub(super) id_field: TextField,
    pub(super) url_field: TextField,
    pub(super) headers: HeaderEditor,
    pub(super) error: Option<String>,
    pub(super) fetch: Option<FetchHandle>,
    pub(super) saved_provider_id: Option<String>,
}

pub(super) enum AddStep {
    /// Pick from `templates::TEMPLATES`. The user spec says
    /// `openai-compatible` is the first/default choice.
    PickTemplate { cursor: usize },
    /// Set the provider id (config-map key). Pre-filled from template.
    EditId,
    /// Set the base URL.
    EditUrl,
    /// Add/remove HTTP headers (`Authorization: Bearer $TOKEN`, etc.).
    EditHeaders,
    /// GitHub Copilot's auth-setup step — surfaces the "append
    /// `export GH_TOKEN=$(gh auth token)` to your shell rc" action (or
    /// the manual-instructions fallback) before saving. Replaces the
    /// EditHeaders step for the Copilot template; the canonical
    /// Authorization header is fixed by the template anyway.
    CopilotAuth(CopilotSetupState),
    /// xAI SuperGrok OAuth setup step for the `grok-oauth` template.
    GrokOAuthAuth(Box<GrokOAuthSetupState>),
    /// OpenAI Codex device-code OAuth setup step for the `codex-oauth` template.
    CodexOAuthAuth(Box<CodexOAuthSetupState>),
    /// Saving config + kicking off /models fetch.
    Saving,
    /// Background fetch is in flight.
    Fetching,
    /// Fetch finished (success or error); user must press Enter to return.
    Done,
}

pub(super) struct EditState {
    pub(super) provider_id: String,
    pub(super) entry: Box<ProviderEntry>,
    /// Index into the action list built by [`edit_menu_actions`].
    pub(super) cursor: usize,
    pub(super) editing_field: Option<EditField>,
    pub(super) field_buf: TextField,
    pub(super) status: Option<String>,
    pub(super) fetch: Option<FetchHandle>,
    pub(super) delete_pending: bool,
}

#[derive(Copy, Clone)]
pub(super) enum EditField {
    Url,
}

/// Multi-row header list. Browsing the rows is inline; adding or
/// editing a header opens a name/value popup (see
/// [`render_header_edit_popup`]).
///
/// Layout (visible "rows" the cursor can land on):
///   - 0..n               actual header rows
///   - n                  `[+ add header]`
///   - n+1                `[continue →]` (used by the Add wizard)
///
/// In Browse mode the cursor selects a row and `Tab`/`Shift+Tab` move
/// like `↓`/`↑`. With the popup open, `Tab`/`Shift+Tab` switch between
/// the name and value fields, `enter` saves, and `esc` cancels.
pub(super) struct HeaderEditor {
    pub(super) rows: Vec<HeaderSpec>,
    pub(super) cursor: usize,
    pub(super) mode: HeaderMode,
    pub(super) name_buf: TextField,
    pub(super) value_buf: TextField,
    /// Row the popup is editing; `None` while adding a brand-new header.
    /// A new header is committed to `rows` only on save, so cancelling
    /// an add leaves no blank row behind.
    pub(super) edit_target: Option<usize>,
    /// If false, the synthetic `[continue →]` row is suppressed (used
    /// from the Edit page, where there's no next step).
    pub(super) show_continue: bool,
    pub(super) delete: RowDeleteConfirm,
    pub(super) status: Option<String>,
}

pub(super) enum HeaderMode {
    Browse,
    /// Popup open, focused on the name field.
    EditName,
    /// Popup open, focused on the value field.
    EditValue,
}

pub(super) enum HeaderResult {
    Stay,
    Continue,
    Back,
    /// `[save changes]` row / `s` accelerator (Edit-page sub-page only):
    /// commit the provider entry to disk and stay on the page.
    Save,
}

impl HeaderEditor {
    pub(super) fn new(rows: Vec<HeaderSpec>, show_continue: bool) -> Self {
        Self {
            rows,
            cursor: 0,
            mode: HeaderMode::Browse,
            name_buf: TextField::default(),
            value_buf: TextField::default(),
            edit_target: None,
            show_continue,
            delete: RowDeleteConfirm::default(),
            status: None,
        }
    }

    fn n_rows(&self) -> usize {
        self.rows.len()
    }

    fn add_row_idx(&self) -> usize {
        self.n_rows()
    }

    fn continue_idx(&self) -> Option<usize> {
        if self.show_continue {
            Some(self.n_rows() + 1)
        } else {
            None
        }
    }

    /// The `[save changes]` row index (Edit-page sub-page only — mutually
    /// exclusive with `[continue →]`, which only the Add wizard shows).
    fn save_idx(&self) -> Option<usize> {
        if self.show_continue {
            None
        } else {
            Some(self.n_rows() + 1)
        }
    }

    fn max_cursor(&self) -> usize {
        self.continue_idx()
            .or_else(|| self.save_idx())
            .unwrap_or(self.add_row_idx())
    }

    /// Open the popup to add a brand-new header. The row is committed to
    /// `rows` only on save (see [`Self::commit_edit`]).
    fn begin_add(&mut self) {
        self.delete.disarm();
        self.status = None;
        self.edit_target = None;
        self.name_buf = TextField::default();
        self.value_buf = TextField::default();
        self.mode = HeaderMode::EditName;
    }

    /// Open the popup to edit an existing row.
    fn begin_edit(&mut self, i: usize) {
        if let Some(row) = self.rows.get(i) {
            self.delete.disarm();
            self.status = None;
            self.edit_target = Some(i);
            self.name_buf = TextField::new(row.name.clone());
            self.value_buf = TextField::new(row.value.clone());
            // Start on the value — the field most often changed when
            // editing an existing header.
            self.mode = HeaderMode::EditValue;
        }
    }

    /// Save the popup buffers and close it. A new header with an empty
    /// name is discarded so a stray `a` leaves no blank row; edits to an
    /// existing row are always written so a field can be cleared.
    fn commit_edit(&mut self) {
        let name = self.name_buf.text().trim().to_string();
        let value = self.value_buf.text().to_string();
        match self.edit_target {
            Some(i) => {
                if let Some(row) = self.rows.get_mut(i) {
                    row.name = name;
                    row.value = value;
                    self.cursor = i;
                }
            }
            None => {
                if !name.is_empty() {
                    self.rows.push(HeaderSpec { name, value });
                    self.cursor = self.rows.len() - 1;
                }
            }
        }
        self.edit_target = None;
        self.mode = HeaderMode::Browse;
        self.delete.disarm();
        self.status = None;
    }

    /// Close the popup without saving.
    fn cancel_edit(&mut self) {
        self.edit_target = None;
        self.mode = HeaderMode::Browse;
        self.delete.disarm();
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> HeaderResult {
        match self.mode {
            HeaderMode::Browse => self.handle_browse_key(key),
            HeaderMode::EditName | HeaderMode::EditValue => self.handle_edit_key(key),
        }
    }

    fn handle_browse_key(&mut self, key: KeyEvent) -> HeaderResult {
        match key.code {
            // `Tab`/`Shift+Tab` move like `↓`/`↑` while browsing rows.
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, self.max_cursor() + 1);
                self.delete.disarm();
                self.status = None;
                HeaderResult::Stay
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = crate::tui::nav::wrap_next(self.cursor, self.max_cursor() + 1);
                self.delete.disarm();
                self.status = None;
                HeaderResult::Stay
            }
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.delete.disarm();
                HeaderResult::Back
            }
            KeyCode::Char('a') => {
                self.begin_add();
                HeaderResult::Stay
            }
            // `s` accelerator: commit (Edit-page sub-page only — the Add
            // wizard has no save row).
            KeyCode::Char('s') if self.save_idx().is_some() => HeaderResult::Save,
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.cursor < self.rows.len() {
                    let label = self.rows[self.cursor].name.clone();
                    if self.delete.arm_or_confirm(self.cursor) {
                        self.rows.remove(self.cursor);
                        if self.cursor > 0 && self.cursor >= self.rows.len() {
                            self.cursor -= 1;
                        }
                        self.status = None;
                    } else {
                        self.status = Some(format!("press d/Delete again to delete `{label}`"));
                    }
                } else {
                    self.delete.disarm();
                    self.status = None;
                }
                HeaderResult::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if self.cursor < self.rows.len() {
                    self.delete.disarm();
                    self.begin_edit(self.cursor);
                    HeaderResult::Stay
                } else if self.cursor == self.add_row_idx() {
                    self.delete.disarm();
                    self.begin_add();
                    HeaderResult::Stay
                } else if Some(self.cursor) == self.continue_idx() {
                    self.delete.disarm();
                    HeaderResult::Continue
                } else if Some(self.cursor) == self.save_idx() {
                    self.delete.disarm();
                    HeaderResult::Save
                } else {
                    HeaderResult::Stay
                }
            }
            _ => {
                self.delete.disarm();
                self.status = None;
                HeaderResult::Stay
            }
        }
    }

    fn handle_edit_key(&mut self, key: KeyEvent) -> HeaderResult {
        match key.code {
            KeyCode::Esc => {
                self.cancel_edit();
                HeaderResult::Stay
            }
            KeyCode::Enter => {
                self.commit_edit();
                HeaderResult::Stay
            }
            // Two fields, so forward and backward both toggle focus.
            KeyCode::Tab | KeyCode::BackTab => {
                self.mode = match self.mode {
                    HeaderMode::EditName => HeaderMode::EditValue,
                    _ => HeaderMode::EditName,
                };
                HeaderResult::Stay
            }
            _ => {
                match self.mode {
                    HeaderMode::EditName => {
                        self.name_buf.handle_key(key);
                    }
                    HeaderMode::EditValue => {
                        self.value_buf.handle_key(key);
                    }
                    HeaderMode::Browse => {}
                }
                HeaderResult::Stay
            }
        }
    }

    /// The field a paste should land in: the name/value buffer matching the
    /// popup focus (`mode`), or `None` while browsing (no field is open).
    pub(super) fn active_text_field(&mut self) -> Option<&mut TextField> {
        match self.mode {
            HeaderMode::EditName => Some(&mut self.name_buf),
            HeaderMode::EditValue => Some(&mut self.value_buf),
            HeaderMode::Browse => None,
        }
    }

    pub(super) fn rows(&self) -> &[HeaderSpec] {
        &self.rows
    }

    pub(super) fn is_editing(&self) -> bool {
        !matches!(self.mode, HeaderMode::Browse)
    }
}

/// Multi-row model list manager for the provider Edit page. Browsing the
/// rows is inline; adding or editing a *manual* entry opens an
/// id/name/context popup (see [`render_model_edit_popup`]).
///
/// Layout (visible "rows" the cursor can land on):
///   - 0..n   actual model rows (fetched + manual, in list order)
///   - n      `[+ add model]`
///
/// Only manual entries can be edited (id / name / context). Any entry —
/// fetched or manual — can be deleted; a deleted fetched entry reappears
/// on the next `/models` refetch.
pub(super) struct ModelEditor {
    /// Effective template identity of the provider whose models are being
    /// edited ([`ProviderEntry::effective_template`]), resolved from the
    /// loaded config at construction. Only scopes template-specific defaults
    /// applied to newly added manual entries ([`apply_template_model_defaults`]);
    /// `None` for providers with no known template.
    pub(super) template: Option<String>,
    pub(super) rows: Vec<ModelEntry>,
    pub(super) cursor: usize,
    pub(super) mode: ModelMode,
    pub(super) id_buf: TextField,
    pub(super) name_buf: TextField,
    pub(super) context_buf: TextField,
    /// Row the popup is editing; `None` while adding a brand-new entry.
    pub(super) edit_target: Option<usize>,
    /// Field the popup is focused on while editing.
    pub(super) focus: ModelField,
    /// Transient validation/status message shown under the editor.
    pub(super) status: Option<String>,
    pub(super) delete: RowDeleteConfirm,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub(super) enum ModelField {
    Id,
    Name,
    Context,
}

pub(super) enum ModelMode {
    Browse,
    /// id/name/context popup open (add or edit).
    Edit,
}

pub(super) enum ModelResult {
    Stay,
    Back,
    /// `[save changes]` row / `s` accelerator: commit the provider entry
    /// (with the live model rows) to disk and stay on the page.
    Save,
    /// Open the model-settings sub-dialog for the row at this index
    /// (implementation note). Works on every model — these
    /// are overrides, not edits to fetched data.
    OpenSettings(usize),
}

impl ModelEditor {
    pub(super) fn new(template: Option<String>, rows: Vec<ModelEntry>) -> Self {
        Self {
            template,
            rows,
            cursor: 0,
            mode: ModelMode::Browse,
            id_buf: TextField::default(),
            name_buf: TextField::default(),
            context_buf: TextField::default(),
            edit_target: None,
            focus: ModelField::Id,
            status: None,
            delete: RowDeleteConfirm::default(),
        }
    }

    fn n_rows(&self) -> usize {
        self.rows.len()
    }

    fn add_row_idx(&self) -> usize {
        self.n_rows()
    }

    /// The `[save changes]` row index (always present — the Models page is
    /// only reached from the provider Edit page).
    fn save_idx(&self) -> usize {
        self.n_rows() + 1
    }

    fn selected_enter_hint(&self) -> &'static str {
        if self.cursor < self.rows.len() {
            if self.rows[self.cursor].manual {
                "enter: settings"
            } else {
                "enter: read-only settings"
            }
        } else if self.cursor == self.add_row_idx() {
            "enter: add model"
        } else if self.cursor == self.save_idx() {
            "enter: save changes"
        } else {
            "enter: settings"
        }
    }

    fn max_cursor(&self) -> usize {
        self.save_idx()
    }

    /// Open the popup to add a brand-new manual entry. The row is
    /// committed to `rows` only on a valid save.
    fn begin_add(&mut self) {
        self.delete.disarm();
        self.edit_target = None;
        self.id_buf = TextField::default();
        self.name_buf = TextField::default();
        self.context_buf = TextField::default();
        self.focus = ModelField::Id;
        self.status = None;
        self.mode = ModelMode::Edit;
    }

    /// Open the popup to edit an existing manual entry. Fetched entries
    /// are not editable; the caller gates on `rows[i].manual`.
    fn begin_edit(&mut self, i: usize) {
        if let Some(row) = self.rows.get(i) {
            self.delete.disarm();
            self.edit_target = Some(i);
            self.id_buf = TextField::new(row.id.clone());
            self.name_buf = TextField::new(row.name.clone().unwrap_or_default());
            self.context_buf = TextField::new(
                row.context_length
                    .map(|c| c.to_string())
                    .unwrap_or_default(),
            );
            self.focus = ModelField::Id;
            self.status = None;
            self.mode = ModelMode::Edit;
        }
    }

    /// Validate the popup buffers and, if valid, commit them to `rows`.
    /// Returns `Err(message)` on validation failure (kept open) and
    /// `Ok(())` on a successful commit (popup closed).
    fn commit_edit(&mut self) -> Result<(), String> {
        let id = self.id_buf.text().trim().to_string();
        if id.is_empty() {
            return Err("model id cannot be empty".to_string());
        }
        // Reject a duplicate id within this provider, ignoring the row
        // being edited so a no-op id keeps validating.
        let dup = self
            .rows
            .iter()
            .enumerate()
            .any(|(i, m)| m.id == id && Some(i) != self.edit_target);
        if dup {
            return Err(format!("a model with id `{id}` already exists"));
        }
        let name_raw = self.name_buf.text().trim();
        let name = if name_raw.is_empty() {
            None
        } else {
            Some(name_raw.to_string())
        };
        let context_raw = self.context_buf.text().trim();
        let context_length = if context_raw.is_empty() {
            None
        } else {
            match context_raw.parse::<u32>() {
                Ok(n) => Some(n),
                Err(_) => return Err("context length must be a number".to_string()),
            }
        };

        match self.edit_target {
            Some(i) => {
                if let Some(row) = self.rows.get_mut(i) {
                    row.id = id;
                    row.name = name;
                    row.context_length = context_length;
                    self.cursor = i;
                }
            }
            None => {
                let mut entry = ModelEntry {
                    id,
                    name,
                    thinking_modes: Vec::new(),
                    inputs: None,
                    context_length,
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
                };
                // A hand-added model gets the same template-scoped defaults
                // a `/models` discovery would apply (z.ai has no `/models`
                // endpoint, so manual add IS its discovery).
                apply_template_model_defaults(self.template.as_deref(), &mut entry);
                self.rows.push(entry);
                self.cursor = self.rows.len() - 1;
            }
        }
        self.edit_target = None;
        self.status = None;
        self.mode = ModelMode::Browse;
        self.delete.disarm();
        Ok(())
    }

    /// Close the popup without saving.
    fn cancel_edit(&mut self) {
        self.edit_target = None;
        self.status = None;
        self.mode = ModelMode::Browse;
        self.delete.disarm();
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> ModelResult {
        match self.mode {
            ModelMode::Browse => self.handle_browse_key(key),
            ModelMode::Edit => self.handle_edit_key(key),
        }
    }

    fn handle_browse_key(&mut self, key: KeyEvent) -> ModelResult {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') | KeyCode::BackTab => {
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, self.max_cursor() + 1);
                self.status = None;
                self.delete.disarm();
                ModelResult::Stay
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::Tab => {
                self.cursor = crate::tui::nav::wrap_next(self.cursor, self.max_cursor() + 1);
                self.status = None;
                self.delete.disarm();
                ModelResult::Stay
            }
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.delete.disarm();
                ModelResult::Back
            }
            KeyCode::Char('a') => {
                self.begin_add();
                ModelResult::Stay
            }
            // `s` accelerator: commit the provider entry to disk.
            KeyCode::Char('s') => {
                self.delete.disarm();
                ModelResult::Save
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if self.cursor < self.rows.len() {
                    let label = self.rows[self.cursor].id.clone();
                    if self.delete.arm_or_confirm(self.cursor) {
                        self.rows.remove(self.cursor);
                        if self.cursor > 0 && self.cursor >= self.rows.len() {
                            self.cursor -= 1;
                        }
                        self.status = None;
                    } else {
                        self.status = Some(format!("press d/Delete again to delete `{label}`"));
                    }
                } else {
                    self.delete.disarm();
                    self.status = None;
                }
                ModelResult::Stay
            }
            // `r` renames (id/name/context) — manual entries only, as before.
            KeyCode::Char('r') => {
                if self.cursor < self.rows.len() {
                    self.delete.disarm();
                    if self.rows[self.cursor].manual {
                        self.begin_edit(self.cursor);
                    } else {
                        self.status =
                            Some("fetched models can't be renamed (settings: enter)".to_string());
                    }
                }
                ModelResult::Stay
            }
            // Enter/l/→ opens the model-settings sub-dialog (every model) or
            // the add affordance on the synthetic row.
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if self.cursor < self.rows.len() {
                    self.delete.disarm();
                    ModelResult::OpenSettings(self.cursor)
                } else if self.cursor == self.add_row_idx() {
                    self.delete.disarm();
                    self.begin_add();
                    ModelResult::Stay
                } else if self.cursor == self.save_idx() {
                    self.delete.disarm();
                    ModelResult::Save
                } else {
                    ModelResult::Stay
                }
            }
            _ => {
                self.delete.disarm();
                self.status = None;
                ModelResult::Stay
            }
        }
    }

    fn handle_edit_key(&mut self, key: KeyEvent) -> ModelResult {
        match key.code {
            KeyCode::Esc => {
                self.cancel_edit();
                ModelResult::Stay
            }
            KeyCode::Enter => {
                if let Err(msg) = self.commit_edit() {
                    self.status = Some(msg);
                }
                ModelResult::Stay
            }
            // Three fields cycled by Tab / Shift+Tab.
            KeyCode::Tab => {
                self.focus = match self.focus {
                    ModelField::Id => ModelField::Name,
                    ModelField::Name => ModelField::Context,
                    ModelField::Context => ModelField::Id,
                };
                ModelResult::Stay
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    ModelField::Id => ModelField::Context,
                    ModelField::Name => ModelField::Id,
                    ModelField::Context => ModelField::Name,
                };
                ModelResult::Stay
            }
            _ => {
                match self.focus {
                    ModelField::Id => {
                        self.id_buf.handle_key(key);
                    }
                    ModelField::Name => {
                        self.name_buf.handle_key(key);
                    }
                    ModelField::Context => {
                        self.context_buf.handle_key(key);
                    }
                }
                ModelResult::Stay
            }
        }
    }

    /// The field a paste should land in: the id/name/context buffer matching
    /// the popup focus, or `None` while browsing (no popup open).
    pub(super) fn active_text_field(&mut self) -> Option<&mut TextField> {
        match self.mode {
            ModelMode::Browse => None,
            ModelMode::Edit => Some(match self.focus {
                ModelField::Id => &mut self.id_buf,
                ModelField::Name => &mut self.name_buf,
                ModelField::Context => &mut self.context_buf,
            }),
        }
    }

    pub(super) fn rows(&self) -> &[ModelEntry] {
        &self.rows
    }

    pub(super) fn is_editing(&self) -> bool {
        matches!(self.mode, ModelMode::Edit)
    }
}

pub(super) struct FetchAllState {
    pub(super) providers: Vec<String>,
    pub(super) in_flight: Vec<FetchHandle>,
    pub(super) finished: Vec<FetchedSummary>,
    pub(super) pre_fetch_models: std::collections::BTreeMap<String, Vec<ModelEntry>>,
    pub(super) policy_resolved: bool,
    /// 0 = Keep (default), 1 = Remove, 2 = Save & close
    pub(super) cursor: usize,
    pub(super) dont_ask_again: bool,
    /// Aggregated set of (provider_id, missing_model_id) the user must rule on.
    pub(super) unlisted: Vec<(String, String)>,
}

impl FetchAllState {
    /// Kick off one background `/models` fetch per configured provider,
    /// reusing the same [`FetchHandle`] machinery the Add/Edit pages use.
    /// Providers whose request can't even be resolved (missing
    /// env/credentials) land directly in `finished` as an error so one
    /// bad provider never blocks the rest — `tick` drains the live
    /// handles as they complete.
    pub(super) fn spawn(providers: &crate::config::providers::ProvidersConfig) -> Self {
        let mut ids: Vec<String> = providers.providers.keys().cloned().collect();
        ids.sort();
        let mut in_flight = Vec::new();
        let finished = Vec::new();
        let mut pre_fetch_models = std::collections::BTreeMap::new();
        for id in &ids {
            let Some(entry) = providers.providers.get(id) else {
                continue;
            };
            pre_fetch_models.insert(id.clone(), entry.models.clone());
            in_flight.push(FetchHandle::spawn(id.clone(), entry.clone()));
        }
        Self {
            providers: ids,
            in_flight,
            finished,
            pre_fetch_models,
            policy_resolved: false,
            cursor: 0,
            dont_ask_again: false,
            unlisted: Vec::new(),
        }
    }

    /// True while at least one per-provider fetch is still running.
    pub(super) fn is_fetching(&self) -> bool {
        !self.in_flight.is_empty()
    }
}

pub(super) struct FetchedSummary {
    pub(super) provider_id: String,
    pub(super) outcome: Result<FetchOutcome, String>,
}

enum FetchDegradedStatus {
    Unsupported,
    Failed(String),
}

pub(super) struct FetchOnePromptState {
    pub(super) provider_id: String,
    pub(super) remote: Vec<ModelEntry>,
    pub(super) catalog: ProviderModelCatalog,
    pub(super) pre_fetch_models: Vec<ModelEntry>,
    pub(super) unlisted: Vec<String>,
    /// 0 = Keep, 1 = Remove, 2 = Do not show again.
    pub(super) cursor: usize,
    pub(super) dont_ask_again: bool,
}

pub(super) struct FetchFallbackPromptState {
    pub(super) provider_id: String,
    pub(super) models: Vec<ModelEntry>,
    pub(super) catalog: ProviderModelCatalog,
    pub(super) reason: String,
    /// 0 = retry live, 1 = keep existing, 2 = use fallback, 3 = cancel.
    pub(super) cursor: usize,
}

impl AddState {
    pub(super) fn new() -> Self {
        Self {
            step: AddStep::PickTemplate { cursor: 0 },
            template: None,
            id_field: TextField::default(),
            url_field: TextField::default(),
            headers: HeaderEditor::new(Vec::new(), true),
            error: None,
            fetch: None,
            saved_provider_id: None,
        }
    }
}

fn provider_entry_from_add(
    s: &AddState,
    template: &'static ProviderTemplate,
    headers: Vec<HeaderSpec>,
) -> ProviderEntry {
    let auth =
        if template.id == xai_oauth::CREDENTIAL_KEY || template.id == codex_oauth::CREDENTIAL_KEY {
            Some(AuthKind::OAuth)
        } else {
            Some(template.auth)
        };
    let credential_ref = if template.id == xai_oauth::CREDENTIAL_KEY {
        Some(xai_oauth::CREDENTIAL_KEY.to_string())
    } else if template.id == codex_oauth::CREDENTIAL_KEY {
        Some(codex_oauth::CREDENTIAL_KEY.to_string())
    } else {
        None
    };
    ProviderEntry {
        name: Some(template.display.to_string()),
        template: Some(template.id.to_string()),
        url: s.url_field.text().trim_end_matches('/').to_string(),
        headers,
        models_fetched_at: None,
        model_catalog: ProviderModelCatalog::Live,
        favorite: None,
        allow_insecure_http: false,
        credential_ref,
        auth,
        trust: None,
        location: None,
        quality_rank: None,
        cost_rank: None,
        subagent_invokable: None,
        availability: Default::default(),
        cache: Default::default(),
        shrink: Default::default(),
        context: Default::default(),
        auto_prune: None,
        timeout: Default::default(),
        wire_api: template.default_wire_api,
        backup: None,
        mode: None,
        inline_think: None,
        hint_tool_call_corrections: None,
        text_embedded_recovery: None,
        thinking_params: Default::default(),
        models: vec![],
        capabilities: Default::default(),
        provider_metadata: Default::default(),
        last_model_fetch: None,
    }
}

impl EditState {
    pub(super) fn new(provider_id: String, entry: ProviderEntry) -> Self {
        Self {
            provider_id,
            entry: Box::new(entry),
            cursor: 0,
            editing_field: None,
            field_buf: TextField::default(),
            status: None,
            fetch: None,
            delete_pending: false,
        }
    }
}

// ── Handlers ─────────────────────────────────────────────────────────────

impl SettingsDialog {
    pub(super) fn apply_fetch_result(
        &mut self,
        provider_id: &str,
        result: Result<FetchOutcome, String>,
    ) {
        let mut message = String::new();
        if let Ok(FetchOutcome::Models { models, catalog }) = result {
            let Some(pre_fetch_models) = self
                .config
                .providers
                .get(provider_id)
                .map(|entry| entry.models.clone())
            else {
                return;
            };
            let unlisted = compute_unlisted_for_models(&pre_fetch_models, &models);
            let stored = self.config.on_unlisted_models_fetch;
            if matches!(stored, None | Some(OnUnlistedModelsFetch::Ask)) && !unlisted.is_empty() {
                self.clear_fetch_handle(provider_id);
                self.page = Page::Providers(ProvidersPage::FetchOnePrompt(FetchOnePromptState {
                    provider_id: provider_id.to_string(),
                    remote: models,
                    catalog,
                    pre_fetch_models,
                    unlisted,
                    cursor: 0,
                    dont_ask_again: false,
                }));
                return;
            }
            let policy = match stored.unwrap_or(OnUnlistedModelsFetch::Keep) {
                OnUnlistedModelsFetch::Remove => ModelMergePolicy::RemoveUnlisted,
                OnUnlistedModelsFetch::Ask | OnUnlistedModelsFetch::Keep => {
                    ModelMergePolicy::KeepUnlisted
                }
            };
            if let Some(entry) = self.config.providers.get_mut(provider_id) {
                entry.models = merge_fetched_models_with_policy(
                    entry.effective_template(provider_id),
                    &pre_fetch_models,
                    models,
                    policy,
                );
                entry.models_fetched_at = Some(Utc::now());
                entry.model_catalog = catalog;
                entry.mark_model_fetch_success(catalog);
                let count = entry.models.len();
                message = match self.save_config() {
                    Ok(()) => fetch_success_message(count, catalog),
                    Err(e) => format!("save failed: {e}"),
                };
            }
        } else if let Ok(FetchOutcome::FallbackAvailable {
            models,
            catalog,
            reason,
        }) = result
        {
            if self.config.providers.contains_key(provider_id) {
                self.clear_fetch_handle(provider_id);
                self.page = Page::Providers(ProvidersPage::FetchFallbackPrompt(
                    FetchFallbackPromptState {
                        provider_id: provider_id.to_string(),
                        models,
                        catalog,
                        reason: redact_model_fetch_reason(reason),
                        cursor: 0,
                    },
                ));
                return;
            }
        } else if self.config.providers.contains_key(provider_id) {
            match result {
                Ok(FetchOutcome::Unsupported) => {
                    if let Some(entry) = self.config.providers.get_mut(provider_id) {
                        entry.mark_model_fetch_unsupported();
                    }
                    let _ = self.save_config();
                    message = "provider has no /models endpoint (skipped)".to_string();
                }
                Err(e) => {
                    let reason = redact_model_fetch_reason(e.as_str());
                    if let Some(entry) = self.config.providers.get_mut(provider_id) {
                        entry.mark_model_fetch_failed_kept_existing(reason.clone());
                    }
                    let _ = self.save_config();
                    message = format!("fetch failed: {reason}");
                }
                Ok(FetchOutcome::Models { .. }) | Ok(FetchOutcome::FallbackAvailable { .. }) => {
                    unreachable!()
                }
            }
        }

        match &mut self.page {
            Page::Providers(ProvidersPage::Add(s)) => {
                s.error = Some(message);
                s.fetch = None;
                s.step = AddStep::Done;
            }
            Page::Providers(ProvidersPage::Edit(s)) => {
                s.status = Some(message);
                s.fetch = None;
                // Refresh only the fetch-owned fields; keep staged edits on
                // the live EditState intact.
                if let Some(entry) = self.config.providers.get(provider_id) {
                    s.entry.models = entry.models.clone();
                    s.entry.models_fetched_at = entry.models_fetched_at;
                    s.entry.model_catalog = entry.model_catalog;
                }
            }
            Page::Providers(ProvidersPage::Headers { parent, .. }) => {
                parent.status = Some(message);
                parent.fetch = None;
                // Don't clobber the in-flight header edits — only
                // refresh non-header fields from the saved entry.
                if let Some(entry) = self.config.providers.get(provider_id) {
                    parent.entry.models = entry.models.clone();
                    parent.entry.models_fetched_at = entry.models_fetched_at;
                    parent.entry.model_catalog = entry.model_catalog;
                }
            }
            Page::Providers(ProvidersPage::Models { parent, .. }) => {
                // A refetch finished while the user is managing the model
                // list. The model editor owns the live (unsaved) rows, so
                // we don't touch them here — just record the outcome on
                // the parent so it surfaces when they return to Edit.
                parent.status = Some(message);
                parent.fetch = None;
            }
            Page::Providers(ProvidersPage::ModelSettings { parent, .. })
            | Page::Providers(ProvidersPage::ProviderSettings { parent, .. }) => {
                // Same as Models: the settings editors own their live state,
                // so just clear the in-flight handle and record the outcome.
                parent.status = Some(message);
                parent.fetch = None;
            }
            _ => {}
        }
    }

    fn clear_fetch_handle(&mut self, provider_id: &str) {
        match &mut self.page {
            Page::Providers(ProvidersPage::Add(s))
                if s.saved_provider_id.as_deref() == Some(provider_id) =>
            {
                s.fetch = None;
            }
            Page::Providers(ProvidersPage::Edit(s)) if s.provider_id == provider_id => {
                s.fetch = None;
            }
            Page::Providers(ProvidersPage::Headers { parent, .. })
            | Page::Providers(ProvidersPage::Models { parent, .. })
            | Page::Providers(ProvidersPage::ModelSettings { parent, .. })
            | Page::Providers(ProvidersPage::ProviderSettings { parent, .. })
                if parent.provider_id == provider_id =>
            {
                parent.fetch = None;
            }
            _ => {}
        }
    }

    /// Poll the in-flight handles of an active all-providers refetch.
    /// Each finished handle is removed from `in_flight` and recorded in
    /// `finished`; model config is not mutated until the unlisted-model
    /// policy is resolved. When `in_flight` empties, the aggregated
    /// unlisted-models set is built so [`Self::render_fetch_all`] can show
    /// the Keep/Remove prompt when needed.
    /// A per-provider failure is just an `Err` summary — it never aborts
    /// the others.
    pub(super) fn drain_fetch_all(&mut self) {
        let Page::Providers(ProvidersPage::FetchAll(s)) = &mut self.page else {
            return;
        };
        if s.in_flight.is_empty() {
            if !s.finished.is_empty() && !s.policy_resolved {
                self.finish_fetch_all_if_ready();
            }
            return;
        }

        // Collect the results of any handles that have completed, leaving
        // the still-running ones in place.
        let mut newly_done: Vec<FetchedSummary> = Vec::new();
        s.in_flight.retain(|handle| match handle.take() {
            Some(outcome) => {
                newly_done.push(FetchedSummary {
                    provider_id: handle.provider_id.clone(),
                    outcome,
                });
                false
            }
            None => true,
        });
        if newly_done.is_empty() {
            return;
        }

        let all_done = {
            let Page::Providers(ProvidersPage::FetchAll(s)) = &mut self.page else {
                return;
            };
            s.finished.extend(newly_done);
            s.in_flight.is_empty()
        };

        // Once every provider has reported, aggregate the set of
        // configured-but-unlisted models for the Keep/Remove prompt.
        // Done as a free function so it doesn't hold `self.page` and
        // `self.config` borrowed at once.
        if all_done {
            self.finish_fetch_all_if_ready();
        }
    }

    fn finish_fetch_all_if_ready(&mut self) {
        let Page::Providers(ProvidersPage::FetchAll(_)) = &self.page else {
            return;
        };
        {
            let unlisted = compute_unlisted(self);
            let degraded = fetch_all_degraded_statuses(self);
            let auto_policy = match self.config.on_unlisted_models_fetch {
                Some(OnUnlistedModelsFetch::Keep) => Some(ModelMergePolicy::KeepUnlisted),
                Some(OnUnlistedModelsFetch::Remove) => Some(ModelMergePolicy::RemoveUnlisted),
                Some(OnUnlistedModelsFetch::Ask) | None if unlisted.is_empty() => {
                    Some(ModelMergePolicy::KeepUnlisted)
                }
                Some(OnUnlistedModelsFetch::Ask) | None => None,
            };
            if let Some(policy) = auto_policy {
                let merges = {
                    let Page::Providers(ProvidersPage::FetchAll(s)) = &self.page else {
                        return;
                    };
                    fetch_all_merges(s)
                };
                self.apply_fetch_all_policy(merges, policy);
            }
            self.apply_fetch_all_degraded_statuses(degraded);
            let _ = self.save_config();
            if let Page::Providers(ProvidersPage::FetchAll(s)) = &mut self.page {
                s.unlisted = if auto_policy.is_some() {
                    Vec::new()
                } else {
                    unlisted
                };
                s.policy_resolved = true;
            }
        }
    }

    fn apply_fetch_all_policy(
        &mut self,
        merges: Vec<(
            String,
            Vec<ModelEntry>,
            Vec<ModelEntry>,
            ProviderModelCatalog,
        )>,
        policy: ModelMergePolicy,
    ) {
        for (provider_id, pre_fetch_models, remote, catalog) in merges {
            if let Some(entry) = self.config.providers.get_mut(&provider_id) {
                entry.models = merge_fetched_models_with_policy(
                    entry.effective_template(&provider_id),
                    &pre_fetch_models,
                    remote,
                    policy,
                );
                entry.models_fetched_at = Some(Utc::now());
                entry.model_catalog = catalog;
                entry.mark_model_fetch_success(catalog);
            }
        }
    }

    fn apply_fetch_all_degraded_statuses(&mut self, degraded: Vec<(String, FetchDegradedStatus)>) {
        for (provider_id, status) in degraded {
            let Some(entry) = self.config.providers.get_mut(&provider_id) else {
                continue;
            };
            match status {
                FetchDegradedStatus::Unsupported => entry.mark_model_fetch_unsupported(),
                FetchDegradedStatus::Failed(reason) => {
                    entry.mark_model_fetch_failed_kept_existing(reason)
                }
            }
        }
    }

    pub(super) fn handle_providers_key(&mut self, key: KeyEvent) -> bool {
        // Detach the providers page so its `&mut SubState` doesn't alias
        // `&mut self`. Inner handlers communicate navigation via the
        // returned [`Nav`] rather than writing `self.page`, because the
        // swap-back below would otherwise discard those writes.
        let placeholder = Page::Providers(ProvidersPage::List {
            cursor: initial_list_cursor(&self.config),
            status: None,
            delete_pending: false,
        });
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::Providers(p) = &mut page {
            self.handle_providers_page_key(key, p)
        } else {
            Nav::Stay
        };
        self.apply_nav(page, nav)
    }

    fn handle_providers_page_key(&mut self, key: KeyEvent, page: &mut ProvidersPage) -> Nav {
        match page {
            ProvidersPage::List {
                cursor,
                status,
                delete_pending,
            } => {
                // Row 0 is the synthetic `[refetch provider models]` button;
                // provider rows are offset by one (1..=ids.len()). The
                // policy summary is rendered as non-selectable text.
                let ids: Vec<String> = self.config.providers.keys().cloned().collect();
                let row_count = ids.len() + 1;
                let provider_idx = list_provider_idx(*cursor, ids.len());
                let pressed_d = matches!(key.code, KeyCode::Char('d'));
                match key.code {
                    KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                        return Nav::Back;
                    }
                    KeyCode::Char('q') => return Nav::Close,
                    KeyCode::Up | KeyCode::Char('k') => {
                        *cursor = crate::tui::nav::wrap_prev(*cursor, row_count);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        *cursor = crate::tui::nav::wrap_next(*cursor, row_count);
                    }
                    KeyCode::Char('a') => {
                        return Nav::Replace(Page::Providers(ProvidersPage::Add(AddState::new())));
                    }
                    // `R` triggers the all-providers refetch from anywhere
                    // on the list; Enter on the button row does the same.
                    KeyCode::Char('R') => {
                        return self.start_fetch_all();
                    }
                    // `m` cycles the global on-unlisted-models-fetch policy
                    // (ask → keep → remove → ask): what a `/fetch-models` run
                    // does with config models that vanished from upstream.
                    KeyCode::Char('m') => {
                        self.config.on_unlisted_models_fetch =
                            Some(cycle_on_unlisted(self.config.on_unlisted_models_fetch));
                        *status = Some(match self.save_config() {
                            Ok(()) => format!(
                                "on unlisted models: {}",
                                on_unlisted_label(self.config.on_unlisted_models_fetch)
                            ),
                            Err(e) => format!("save failed: {e}"),
                        });
                        return Nav::Stay;
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                        if *cursor == 0 {
                            return self.start_fetch_all();
                        }
                        if let Some(idx) = provider_idx
                            && let Some(id) = ids.get(idx).cloned()
                            && let Some(entry) = self.config.providers.get(&id)
                        {
                            return Nav::Replace(Page::Providers(ProvidersPage::Edit(
                                EditState::new(id, entry.clone()),
                            )));
                        }
                    }
                    KeyCode::Char('d') => {
                        // Only arm/confirm when the cursor is on a
                        // provider row (not the refetch-all button).
                        if let Some(idx) = provider_idx {
                            if *delete_pending {
                                let id = ids[idx].clone();
                                self.config.providers.remove(&id);
                                let msg = match self.save_config() {
                                    Ok(()) => format!("deleted `{id}`"),
                                    Err(e) => format!("delete failed: {e}"),
                                };
                                let new_len = self.config.providers.len();
                                // Keep the cursor on a valid provider row, or
                                // the refetch button if none remain.
                                let new_cursor = if new_len == 0 {
                                    0
                                } else {
                                    (*cursor).min(new_len)
                                };
                                return Nav::Replace(Page::Providers(ProvidersPage::List {
                                    cursor: new_cursor,
                                    status: Some(msg),
                                    delete_pending: false,
                                }));
                            } else {
                                *delete_pending = true;
                                *status = Some(format!("press d again to delete `{}`", ids[idx]));
                                return Nav::Stay;
                            }
                        }
                        // Drop through to the post-match cleanup.
                    }
                    _ => {}
                }
                // Any non-`d` key (or `d` on a non-provider row) clears
                // the pending-delete arm and the transient status.
                if !pressed_d {
                    *delete_pending = false;
                    *status = None;
                }
                Nav::Stay
            }
            ProvidersPage::Add(state) => self.handle_add_key(key, state),
            ProvidersPage::Edit(state) => self.handle_edit_key(key, state),
            ProvidersPage::Headers { editor, parent } => {
                self.handle_headers_key(key, editor, parent)
            }
            ProvidersPage::Models { editor, parent } => self.handle_models_key(key, editor, parent),
            ProvidersPage::ModelSettings {
                editor,
                models,
                parent,
            } => self.handle_model_settings_key(key, editor, models, parent),
            ProvidersPage::ProviderSettings { editor, parent } => {
                self.handle_provider_settings_key(key, editor, parent)
            }
            ProvidersPage::FetchAll(state) => self.handle_fetch_all_key(key, state),
            ProvidersPage::FetchOnePrompt(state) => self.handle_fetch_one_prompt_key(key, state),
            ProvidersPage::FetchFallbackPrompt(state) => {
                self.handle_fetch_fallback_prompt_key(key, state)
            }
            ProvidersPage::CopilotSetup { state, parent } => {
                self.handle_copilot_setup_key(key, state, parent)
            }
            ProvidersPage::GrokOAuthSetup { state, parent } => {
                let (close, action) = handle_grok_oauth_setup_key(key, state);
                self.pending_oauth_action = action;
                if close {
                    let owned = std::mem::replace(
                        parent,
                        Box::new(EditState::new(String::new(), ProviderEntry::default())),
                    );
                    Nav::Replace(Page::Providers(ProvidersPage::Edit(*owned)))
                } else {
                    Nav::Stay
                }
            }
            ProvidersPage::CodexOAuthSetup { state, parent } => {
                let (close, action) = handle_codex_oauth_setup_key(key, state);
                self.pending_oauth_action = action;
                if close {
                    let owned = std::mem::replace(
                        parent,
                        Box::new(EditState::new(String::new(), ProviderEntry::default())),
                    );
                    Nav::Replace(Page::Providers(ProvidersPage::Edit(*owned)))
                } else {
                    Nav::Stay
                }
            }
        }
    }

    /// Shared "save the provider, then spawn a /models fetch" sequence.
    /// Pulled out so the Headers step and the Copilot-auth step can
    /// both finalize without duplicating the error-handling.
    fn save_and_fetch_provider(
        &mut self,
        s: &mut AddState,
        id: String,
        entry: ProviderEntry,
        template: &'static ProviderTemplate,
    ) {
        self.config.providers.insert(id.clone(), entry.clone());
        match self.save_config() {
            Ok(()) => {
                s.saved_provider_id = Some(id.clone());
                s.error = Some("saved. Fetching /models…".into());
                if !template.supports_models_endpoint {
                    s.error = Some("saved. provider has no /models endpoint".into());
                    s.step = AddStep::Done;
                } else {
                    s.fetch = Some(FetchHandle::spawn(id, entry));
                    s.step = AddStep::Fetching;
                }
            }
            Err(e) => {
                s.error = Some(format!("save failed: {e}"));
            }
        }
    }

    fn handle_add_key(&mut self, key: KeyEvent, s: &mut AddState) -> Nav {
        // Back/escape unconditionally returns to the list.
        if matches!(key.code, KeyCode::Esc)
            && !matches!(
                s.step,
                AddStep::GrokOAuthAuth(_) | AddStep::CodexOAuthAuth(_)
            )
        {
            return Nav::Replace(Page::Providers(ProvidersPage::List {
                cursor: initial_list_cursor(&self.config),
                status: None,
                delete_pending: false,
            }));
        }

        match &mut s.step {
            AddStep::PickTemplate { cursor } => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    *cursor = crate::tui::nav::wrap_prev(*cursor, templates::TEMPLATES.len());
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    *cursor = crate::tui::nav::wrap_next(*cursor, templates::TEMPLATES.len());
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                    let t = &templates::TEMPLATES[*cursor];
                    s.template = Some(t);
                    // Pre-fill id only for templates that map 1:1 to a
                    // single vendor; for `openai-compatible` the user
                    // must choose a unique name (they may add several).
                    if t.use_id_as_default {
                        s.id_field.set(t.id);
                    } else {
                        s.id_field.set("");
                    }
                    s.url_field.set(t.url);
                    s.headers = HeaderEditor::new(
                        templates::default_headers_for(t),
                        /* show_continue */ true,
                    );
                    s.error = None;
                    s.step = AddStep::EditId;
                }
                _ => {}
            },
            AddStep::EditId => match key.code {
                KeyCode::Enter => {
                    let id = s.id_field.text().trim().to_string();
                    if id.is_empty() {
                        s.error = Some("id cannot be empty".into());
                    } else if !valid_id(&id) {
                        s.error = Some("id must be lowercase letters, digits, `-`, or `_`".into());
                    } else if self.config.providers.contains_key(&id) {
                        s.error = Some(format!("a provider with id `{id}` already exists"));
                    } else {
                        s.error = None;
                        s.step = AddStep::EditUrl;
                    }
                }
                _ => {
                    s.id_field.handle_key(key);
                }
            },
            AddStep::EditUrl => match key.code {
                KeyCode::Enter => {
                    if !valid_url(s.url_field.text()) {
                        s.error = Some("url must start with http:// or https://".into());
                    } else {
                        s.error = None;
                        // GitHub Copilot's auth is documented env-var
                        // tokens, not custom headers — route to the
                        // dedicated Copilot-auth screen so the
                        // GH_TOKEN setup button lives next to the
                        // provider it actually configures.
                        if matches!(s.template.map(|t| t.id), Some("copilot")) {
                            s.step = AddStep::CopilotAuth(CopilotSetupState::new());
                        } else if matches!(s.template.map(|t| t.id), Some("grok-oauth")) {
                            s.step = AddStep::GrokOAuthAuth(Box::new(GrokOAuthSetupState::new()));
                        } else if matches!(s.template.map(|t| t.id), Some("codex-oauth")) {
                            s.step = AddStep::CodexOAuthAuth(Box::new(CodexOAuthSetupState::new()));
                        } else {
                            s.step = AddStep::EditHeaders;
                        }
                    }
                }
                _ => {
                    s.url_field.handle_key(key);
                }
            },
            AddStep::EditHeaders => {
                match s.headers.handle_key(key) {
                    // `Save` is unreachable in the Add wizard (it shows the
                    // `[continue →]` row, never `[save changes]`), but the
                    // match stays exhaustive.
                    HeaderResult::Stay | HeaderResult::Save => return Nav::Stay,
                    HeaderResult::Back => {
                        s.error = None;
                        s.step = AddStep::EditUrl;
                        return Nav::Stay;
                    }
                    HeaderResult::Continue => {
                        // fall through to the save+fetch block below
                    }
                }

                let template = s.template.expect("template chosen");
                let id = s.id_field.text().trim().to_string();
                let headers: Vec<HeaderSpec> = s.headers.rows().to_vec();
                let entry = provider_entry_from_add(s, template, headers);
                self.save_and_fetch_provider(s, id, entry, template);
            }
            AddStep::CopilotAuth(state) => match key.code {
                KeyCode::Enter => {
                    if state.outcome.is_some() {
                        // Outcome already shown — Enter advances to
                        // save + fetch.
                        let template = s.template.expect("template chosen");
                        let id = s.id_field.text().trim().to_string();
                        let entry = provider_entry_from_add(
                            s,
                            template,
                            templates::default_headers_for(template),
                        );
                        self.save_and_fetch_provider(s, id, entry, template);
                        return Nav::Stay;
                    }
                    // No outcome yet. Apply the action if we can; else
                    // jump straight to save + fetch (manual / already-
                    // configured paths are informational only).
                    let can_apply = state.shell.is_some()
                        && state.rc_path.is_some()
                        && !state.already_configured;
                    if can_apply {
                        let shell = state.shell.unwrap();
                        let rc_path = state.rc_path.clone().unwrap();
                        state.outcome = Some(apply_copilot_setup(shell, &rc_path));
                    } else {
                        // Skip — move to save + fetch.
                        let template = s.template.expect("template chosen");
                        let id = s.id_field.text().trim().to_string();
                        let entry = provider_entry_from_add(
                            s,
                            template,
                            templates::default_headers_for(template),
                        );
                        self.save_and_fetch_provider(s, id, entry, template);
                    }
                }
                KeyCode::Char('s') => {
                    // Skip the GH_TOKEN action and go straight to save
                    // + fetch — useful when the env var is already set
                    // elsewhere (e.g. via direnv).
                    let template = s.template.expect("template chosen");
                    let id = s.id_field.text().trim().to_string();
                    let entry = provider_entry_from_add(
                        s,
                        template,
                        templates::default_headers_for(template),
                    );
                    self.save_and_fetch_provider(s, id, entry, template);
                }
                _ => {}
            },
            AddStep::GrokOAuthAuth(state) => {
                let (close, action) = handle_grok_oauth_setup_key(key, state);
                self.pending_oauth_action = action;
                if close {
                    s.step = AddStep::EditUrl;
                    return Nav::Stay;
                }
                if matches!(key.code, KeyCode::Char('s'))
                    || (matches!(key.code, KeyCode::Enter)
                        && grok_oauth_setup_is_confirmation(state))
                    || (matches!(key.code, KeyCode::Enter)
                        && state.cursor == 2
                        && !state.manual_mode)
                {
                    let template = s.template.expect("template chosen");
                    let id = s.id_field.text().trim().to_string();
                    let entry = provider_entry_from_add(s, template, Vec::new());
                    self.save_and_fetch_provider(s, id, entry, template);
                }
            }
            AddStep::CodexOAuthAuth(state) => {
                let (close, action) = handle_codex_oauth_setup_key(key, state);
                self.pending_oauth_action = action;
                if close {
                    s.step = AddStep::EditUrl;
                    return Nav::Stay;
                }
                if matches!(key.code, KeyCode::Char('s'))
                    || (matches!(key.code, KeyCode::Enter)
                        && codex_oauth_setup_is_confirmation(state))
                    || (matches!(key.code, KeyCode::Enter)
                        && state.cursor == 1
                        && state.pending.is_none())
                {
                    let template = s.template.expect("template chosen");
                    let id = s.id_field.text().trim().to_string();
                    let entry = provider_entry_from_add(s, template, Vec::new());
                    self.save_and_fetch_provider(s, id, entry, template);
                }
            }
            AddStep::Saving | AddStep::Fetching => {
                // Disable input while in-flight, except Esc (handled above).
            }
            AddStep::Done => {
                if matches!(key.code, KeyCode::Enter) {
                    return Nav::Replace(Page::Providers(ProvidersPage::List {
                        cursor: initial_list_cursor(&self.config),
                        status: s.error.clone(),
                        delete_pending: false,
                    }));
                }
            }
        }
        Nav::Stay
    }

    /// Commit a staged provider [`EditState`] to disk: insert its entry
    /// into the config map under its id and persist. Returns the `saved`
    /// (or `save failed: …`) status. This is the single sink every commit
    /// path — the `[save changes]` row, the `s` accelerator, and
    /// auto-commit-on-exit — routes through, so no Providers edit is ever
    /// dropped (no silent data loss).
    fn commit_edit_entry(&mut self, s: &EditState) -> Option<String> {
        self.config
            .providers
            .insert(s.provider_id.clone(), (*s.entry).clone());
        super::save_status(self.save_config())
    }

    fn handle_edit_key(&mut self, key: KeyEvent, s: &mut EditState) -> Nav {
        // Inline-edit mode: keystrokes go to the field until Enter/Esc.
        if let Some(field) = s.editing_field {
            match key.code {
                KeyCode::Enter => {
                    let new = s.field_buf.text().to_string();
                    match field {
                        EditField::Url => {
                            if valid_url(&new) {
                                s.entry.url = new.trim_end_matches('/').to_string();
                                // Single-line field edit: Enter commits the
                                // field straight to disk (no manual `s`).
                                s.status = self.commit_edit_entry(s);
                            } else {
                                s.status = Some("url must start with http:// or https://".into());
                                return Nav::Stay;
                            }
                        }
                    }
                    s.editing_field = None;
                }
                KeyCode::Esc => {
                    s.editing_field = None;
                }
                _ => {
                    s.field_buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        // Action menu, built dynamically so render and key handling share
        // one source of truth (the "Copilot auth" row is conditional).
        // `h` / `←` / Backspace all go back to the list — header editing
        // lives on its own sub-page reached by cursor → Enter on the
        // "Headers" row. Leaving auto-commits any staged edit so nothing
        // is silently lost.
        let actions = edit_menu_actions(&s.provider_id, &s.entry);
        let menu_len = actions.len();
        match key.code {
            KeyCode::Char('q') => {
                let _ = self.commit_edit_entry(s);
                return Nav::Close;
            }
            KeyCode::Esc | KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                let status = self.commit_edit_entry(s);
                return Nav::Replace(Page::Providers(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status,
                    delete_pending: false,
                }));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, menu_len);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, menu_len);
            }
            KeyCode::Char('s') => {
                // Bare-`s` accelerator: identical to the `[save changes]`
                // row — commit to disk and stay on the page.
                s.status = self.commit_edit_entry(s);
            }
            KeyCode::Char('r') => {
                let status = self.commit_edit_entry(s);
                s.fetch = Some(FetchHandle::spawn(
                    s.provider_id.clone(),
                    (*s.entry).clone(),
                ));
                s.status = if status
                    .as_deref()
                    .is_some_and(|msg| msg.starts_with("save failed:"))
                {
                    status
                } else {
                    Some("refetching /models…".into())
                };
            }
            KeyCode::Char('f') => {
                let new = !s.entry.favorite.unwrap_or(false);
                s.entry.favorite = if new { Some(true) } else { None };
                s.status = Some(if new {
                    "favorite ✓ (unsaved — s to save)".into()
                } else {
                    "favorite removed (unsaved — s to save)".into()
                });
            }
            KeyCode::Char('d') => {
                if s.delete_pending {
                    self.config.providers.remove(&s.provider_id);
                    let saved = self.save_config();
                    let msg = match saved {
                        Ok(()) => format!("deleted `{}`", s.provider_id),
                        Err(e) => format!("delete failed: {e}"),
                    };
                    return Nav::Replace(Page::Providers(ProvidersPage::List {
                        cursor: initial_list_cursor(&self.config),
                        status: Some(msg),
                        delete_pending: false,
                    }));
                } else {
                    s.delete_pending = true;
                    s.status = Some("press d again to confirm delete".into());
                }
                return Nav::Stay;
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                match actions.get(s.cursor).copied() {
                    Some(EditAction::Url) => {
                        s.field_buf = TextField::new(s.entry.url.clone());
                        s.editing_field = Some(EditField::Url);
                    }
                    Some(EditAction::Headers) => {
                        // Hand off to the Headers sub-page. We move
                        // the EditState out via `mem::replace` so the
                        // Headers page can return it intact on back.
                        let editor = HeaderEditor::new(
                            s.entry.headers.clone(),
                            /* show_continue */ false,
                        );
                        let owned = std::mem::replace(
                            s,
                            EditState::new(String::new(), ProviderEntry::default()),
                        );
                        return Nav::Replace(Page::Providers(ProvidersPage::Headers {
                            editor,
                            parent: Box::new(owned),
                        }));
                    }
                    Some(EditAction::CopilotAuth) => {
                        // Hand off to the Copilot-auth screen, moving the
                        // EditState out so it returns intact on back
                        // (mirrors the Headers/Models/Settings rows). Same
                        // screen the Add wizard's Copilot step shows.
                        let state = CopilotSetupState::new();
                        let owned = std::mem::replace(
                            s,
                            EditState::new(String::new(), ProviderEntry::default()),
                        );
                        return Nav::Replace(Page::Providers(ProvidersPage::CopilotSetup {
                            state,
                            parent: Box::new(owned),
                        }));
                    }
                    Some(EditAction::GrokOAuthAuth) => {
                        let state = Box::new(GrokOAuthSetupState::new());
                        let owned = std::mem::replace(
                            s,
                            EditState::new(String::new(), ProviderEntry::default()),
                        );
                        return Nav::Replace(Page::Providers(ProvidersPage::GrokOAuthSetup {
                            state,
                            parent: Box::new(owned),
                        }));
                    }
                    Some(EditAction::CodexOAuthAuth) => {
                        let state = Box::new(CodexOAuthSetupState::new());
                        let owned = std::mem::replace(
                            s,
                            EditState::new(String::new(), ProviderEntry::default()),
                        );
                        return Nav::Replace(Page::Providers(ProvidersPage::CodexOAuthSetup {
                            state,
                            parent: Box::new(owned),
                        }));
                    }
                    Some(EditAction::Models) => {
                        // Hand off to the Models sub-page, moving the
                        // EditState out so the sub-page can return it
                        // intact on back (mirrors the Headers row).
                        let editor = Box::new(ModelEditor::new(
                            s.entry
                                .effective_template(&s.provider_id)
                                .map(str::to_owned),
                            s.entry.models.clone(),
                        ));
                        let owned = std::mem::replace(
                            s,
                            EditState::new(String::new(), ProviderEntry::default()),
                        );
                        return Nav::Replace(Page::Providers(ProvidersPage::Models {
                            editor,
                            parent: Box::new(owned),
                        }));
                    }
                    Some(EditAction::Settings) => {
                        // Hand off to the provider-settings sub-page, moving
                        // the EditState out so it returns intact on back
                        // (mirrors the Headers/Models rows).
                        let settings = SettingsEditor::for_provider(&s.provider_id, &s.entry)
                            .with_trust_confirm_lockout_ms(self.extended.dialog.lockout_ms);
                        let owned = std::mem::replace(
                            s,
                            EditState::new(String::new(), ProviderEntry::default()),
                        );
                        return Nav::Replace(Page::Providers(ProvidersPage::ProviderSettings {
                            editor: settings,
                            parent: Box::new(owned),
                        }));
                    }
                    Some(EditAction::Favorite) => {
                        let new = !s.entry.favorite.unwrap_or(false);
                        s.entry.favorite = if new { Some(true) } else { None };
                        s.status = Some(if new {
                            "favorite ✓ (unsaved — s to save)".into()
                        } else {
                            "favorite removed (unsaved — s to save)".into()
                        });
                    }
                    Some(EditAction::Refetch) => {
                        // Same as 'r'
                        let status = self.commit_edit_entry(s);
                        s.fetch = Some(FetchHandle::spawn(
                            s.provider_id.clone(),
                            (*s.entry).clone(),
                        ));
                        s.status = if status
                            .as_deref()
                            .is_some_and(|msg| msg.starts_with("save failed:"))
                        {
                            status
                        } else {
                            Some("refetching /models…".into())
                        };
                    }
                    Some(EditAction::Delete) => {
                        if s.delete_pending {
                            self.config.providers.remove(&s.provider_id);
                            let saved = self.save_config();
                            let msg = match saved {
                                Ok(()) => format!("deleted `{}`", s.provider_id),
                                Err(e) => format!("delete failed: {e}"),
                            };
                            return Nav::Replace(Page::Providers(ProvidersPage::List {
                                cursor: initial_list_cursor(&self.config),
                                status: Some(msg),
                                delete_pending: false,
                            }));
                        } else {
                            s.delete_pending = true;
                            s.status = Some("press Enter again to confirm delete".into());
                            return Nav::Stay;
                        }
                    }
                    Some(EditAction::Save) => {
                        // `[save changes]` — commit to disk and stay.
                        s.status = self.commit_edit_entry(s);
                    }
                    Some(EditAction::Back) => {
                        // Back to list — auto-commit so nothing is lost.
                        let status = self.commit_edit_entry(s);
                        return Nav::Replace(Page::Providers(ProvidersPage::List {
                            cursor: initial_list_cursor(&self.config),
                            status,
                            delete_pending: false,
                        }));
                    }
                    None => {}
                }
            }
            _ => {}
        }
        s.delete_pending = matches!(key.code, KeyCode::Char('d')) && s.delete_pending;
        Nav::Stay
    }

    /// Handle keys on the Headers sub-page. All keys go to the
    /// [`HeaderEditor`] until it signals `Back`; on back, copy the
    /// editor's rows into `parent.entry.headers` and return to the
    /// Edit page with the parent intact (so its cursor, status, and
    /// any unsaved entry-level edits survive the round trip).
    fn handle_headers_key(
        &mut self,
        key: KeyEvent,
        editor: &mut HeaderEditor,
        parent: &mut Box<EditState>,
    ) -> Nav {
        if matches!(editor.mode, HeaderMode::Browse) && matches!(key.code, KeyCode::Char('q')) {
            parent.entry.headers = editor.rows.clone();
            let _ = self.commit_edit_entry(parent);
            return Nav::Close;
        }
        match editor.handle_key(key) {
            HeaderResult::Stay | HeaderResult::Continue => Nav::Stay,
            HeaderResult::Save => {
                // `[save changes]` / `s`: fold the live header rows into the
                // parent entry, commit to disk, and STAY on the sub-page.
                parent.entry.headers = editor.rows.clone();
                parent.status = self.commit_edit_entry(parent);
                Nav::Stay
            }
            HeaderResult::Back => {
                // Move both the editor's rows and the parent state
                // out by swapping with placeholders, then build the
                // restored Edit page. Leaving auto-commits so the header
                // edits are never silently lost.
                let rows = std::mem::take(&mut editor.rows);
                let mut owned = std::mem::replace(
                    parent.as_mut(),
                    EditState::new(String::new(), ProviderEntry::default()),
                );
                owned.entry.headers = rows;
                owned.cursor = 1;
                owned.status = self.commit_edit_entry(&owned);
                Nav::Replace(Page::Providers(ProvidersPage::Edit(owned)))
            }
        }
    }

    /// Handle keys on the Models sub-page. All keys go to the
    /// [`ModelEditor`] until it signals `Back`; on back, copy the
    /// editor's rows into `parent.entry.models` and return to the Edit
    /// page with the parent intact (so its cursor, status, and any
    /// unsaved entry-level edits survive the round trip). The user still
    /// commits to disk with `s` on the Edit page, like every other edit.
    fn handle_models_key(
        &mut self,
        key: KeyEvent,
        editor: &mut ModelEditor,
        parent: &mut Box<EditState>,
    ) -> Nav {
        if matches!(editor.mode, ModelMode::Browse) && matches!(key.code, KeyCode::Char('q')) {
            parent.entry.models = editor.rows.clone();
            let _ = self.commit_edit_entry(parent);
            return Nav::Close;
        }
        match editor.handle_key(key) {
            ModelResult::Stay => Nav::Stay,
            ModelResult::Save => {
                // `[save changes]` / `s`: fold the live model rows into the
                // parent entry, commit to disk, and STAY on the sub-page.
                parent.entry.models = editor.rows.clone();
                parent.status = self.commit_edit_entry(parent);
                Nav::Stay
            }
            ModelResult::Back => {
                let rows = std::mem::take(&mut editor.rows);
                let mut owned = std::mem::replace(
                    parent.as_mut(),
                    EditState::new(String::new(), ProviderEntry::default()),
                );
                owned.entry.models = rows;
                // Put the cursor back on the Models row; leaving
                // auto-commits so the model edits are never lost.
                owned.cursor = 2;
                owned.status = self.commit_edit_entry(&owned);
                Nav::Replace(Page::Providers(ProvidersPage::Edit(owned)))
            }
            ModelResult::OpenSettings(idx) => {
                let Some(model_id) = editor.rows.get(idx).map(|m| m.id.clone()) else {
                    return Nav::Stay;
                };
                // Seed the settings editor from the provider entry carrying
                // the *live* (unsaved) model rows so inherited values resolve
                // correctly. The ModelEditor and parent are moved into the
                // sub-page so they're recalled intact on back.
                let mut seed_entry = parent.entry.clone();
                seed_entry.models = editor.rows.clone();
                let settings =
                    SettingsEditor::for_model(&parent.provider_id, &seed_entry, &model_id)
                        .with_trust_confirm_lockout_ms(self.extended.dialog.lockout_ms);
                let models = Box::new(std::mem::replace(
                    editor,
                    ModelEditor::new(None, Vec::new()),
                ));
                let owned = std::mem::replace(
                    parent.as_mut(),
                    EditState::new(String::new(), ProviderEntry::default()),
                );
                Nav::Replace(Page::Providers(ProvidersPage::ModelSettings {
                    editor: settings,
                    models,
                    parent: Box::new(owned),
                }))
            }
        }
    }

    /// Handle keys on the model-settings sub-dialog
    /// (implementation note). Keys go to the
    /// [`SettingsEditor`] until it signals `Back`; on back, write the model's
    /// override fields into the live model rows and return to the Models
    /// sub-page (which returns to Edit on its own back, where `s` persists).
    fn handle_model_settings_key(
        &mut self,
        key: KeyEvent,
        editor: &mut SettingsEditor,
        models: &mut ModelEditor,
        parent: &mut Box<EditState>,
    ) -> Nav {
        if editor.active_text_field().is_none() && matches!(key.code, KeyCode::Char('q')) {
            let mut tmp = parent.entry.clone();
            tmp.models = models.rows.clone();
            editor.write_into(&mut tmp);
            parent.entry.models = tmp.models;
            let _ = self.commit_edit_entry(parent);
            return Nav::Close;
        }
        match editor.handle_key(key) {
            SettingsResult::Stay => Nav::Stay,
            SettingsResult::Save => {
                // `[save changes]` / `s`: write the overrides into the live
                // model rows, commit to disk, and STAY on the sub-dialog.
                let mut tmp = parent.entry.clone();
                tmp.models = models.rows.clone();
                editor.write_into(&mut tmp);
                parent.entry.models = tmp.models;
                parent.status = self.commit_edit_entry(parent);
                Nav::Stay
            }
            SettingsResult::Back => {
                // Write the overrides into a provider entry carrying the live
                // model rows, then lift the updated rows back into the model
                // editor so the Models page sees them.
                let mut tmp = parent.entry.clone();
                tmp.models = std::mem::take(&mut models.rows);
                editor.write_into(&mut tmp);
                let mut owned = std::mem::replace(
                    parent.as_mut(),
                    EditState::new(String::new(), ProviderEntry::default()),
                );
                // Persist immediately: "editing a field and leaving the
                // dialog persists it" (implementation note).
                // The model-row edit is a self-contained override write, so
                // we save rather than wait for the Edit page's `s`.
                owned.entry.models = tmp.models.clone();
                owned.status = self.commit_edit_entry(&owned);
                let new_models = Box::new(ModelEditor::new(
                    owned
                        .entry
                        .effective_template(&owned.provider_id)
                        .map(str::to_owned),
                    tmp.models,
                ));
                Nav::Replace(Page::Providers(ProvidersPage::Models {
                    editor: new_models,
                    parent: Box::new(owned),
                }))
            }
        }
    }

    /// Handle keys on the provider-settings sub-dialog. Keys go to the
    /// [`SettingsEditor`] until it signals `Back`; on back, write the concrete
    /// values into `parent.entry` and return to the Edit page (where `s`
    /// persists), mirroring the Headers/Models round trip.
    fn handle_provider_settings_key(
        &mut self,
        key: KeyEvent,
        editor: &mut SettingsEditor,
        parent: &mut Box<EditState>,
    ) -> Nav {
        if editor.active_text_field().is_none() && matches!(key.code, KeyCode::Char('q')) {
            editor.write_into(&mut parent.entry);
            let _ = self.commit_edit_entry(parent);
            return Nav::Close;
        }
        match editor.handle_key(key) {
            SettingsResult::Stay => Nav::Stay,
            SettingsResult::Save => {
                // `[save changes]` / `s`: write the concrete values into the
                // parent entry, commit to disk, and STAY on the sub-dialog.
                editor.write_into(&mut parent.entry);
                parent.status = self.commit_edit_entry(parent);
                Nav::Stay
            }
            SettingsResult::Back => {
                let mut owned = std::mem::replace(
                    parent.as_mut(),
                    EditState::new(String::new(), ProviderEntry::default()),
                );
                editor.write_into(&mut owned.entry);
                owned.cursor = 3;
                // Persist immediately on leaving the dialog
                // (implementation note).
                owned.status = self.commit_edit_entry(&owned);
                Nav::Replace(Page::Providers(ProvidersPage::Edit(owned)))
            }
        }
    }

    /// Enter the all-providers refetch flow, reusing the existing
    /// [`FetchAll`](ProvidersPage::FetchAll) page and its per-provider
    /// [`FetchHandle`] machinery. No-op (with a status) when no providers
    /// are configured; never stacks a second concurrent run because the
    /// only entry point is the List page and entering replaces it.
    fn start_fetch_all(&mut self) -> Nav {
        if self.config.providers.is_empty() {
            return Nav::Replace(Page::Providers(ProvidersPage::List {
                cursor: 0,
                status: Some("no providers configured".into()),
                delete_pending: false,
            }));
        }
        let state = FetchAllState::spawn(&self.config);
        Nav::Replace(Page::Providers(ProvidersPage::FetchAll(state)))
    }

    fn handle_fetch_all_key(&mut self, key: KeyEvent, s: &mut FetchAllState) -> Nav {
        // While the per-provider fetches are still running, the only
        // accepted key is Esc (cancel + return). The prompt rows aren't
        // live yet — `tick`/`drain_fetch_all` populates them once every
        // handle has reported.
        if s.is_fetching() {
            if matches!(key.code, KeyCode::Char('q')) {
                return Nav::Close;
            }
            if matches!(key.code, KeyCode::Esc) {
                return Nav::Replace(Page::Providers(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some("refetch-all cancelled".into()),
                    delete_pending: false,
                }));
            }
            return Nav::Stay;
        }

        // If the fetch finished but no model drifted out of the upstream
        // list, there's nothing to rule on — any key returns to the list
        // with a per-provider summary.
        if s.unlisted.is_empty() {
            return Nav::Replace(Page::Providers(ProvidersPage::List {
                cursor: initial_list_cursor(&self.config),
                status: Some(fetch_all_summary(s)),
                delete_pending: false,
            }));
        }

        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc => {
                return Nav::Replace(Page::Providers(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some("refetch-all cancelled".into()),
                    delete_pending: false,
                }));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                // 3 rows: confirm / cancel / "don't ask again".
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, 3);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, 3);
            }
            KeyCode::Char(' ') if s.cursor == 2 => {
                s.dont_ask_again = !s.dont_ask_again;
            }
            KeyCode::Enter => {
                let pick = match s.cursor {
                    0 => OnUnlistedModelsFetch::Keep,
                    1 => OnUnlistedModelsFetch::Remove,
                    _ => OnUnlistedModelsFetch::Keep,
                };
                let policy = match pick {
                    OnUnlistedModelsFetch::Remove => ModelMergePolicy::RemoveUnlisted,
                    OnUnlistedModelsFetch::Ask | OnUnlistedModelsFetch::Keep => {
                        ModelMergePolicy::KeepUnlisted
                    }
                };
                self.apply_fetch_all_policy(fetch_all_merges(s), policy);
                if s.dont_ask_again {
                    self.config.on_unlisted_models_fetch = Some(pick);
                }
                let summary = fetch_all_summary(s);
                let status = match self.save_config() {
                    Ok(()) => summary,
                    Err(e) => format!("save failed: {e}"),
                };
                return Nav::Replace(Page::Providers(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some(status),
                    delete_pending: false,
                }));
            }
            _ => {}
        }
        Nav::Stay
    }

    fn handle_fetch_one_prompt_key(&mut self, key: KeyEvent, s: &mut FetchOnePromptState) -> Nav {
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc => {
                return Nav::Replace(Page::Providers(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some("refetch cancelled".into()),
                    delete_pending: false,
                }));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, 3);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, 3);
            }
            KeyCode::Char(' ') if s.cursor == 2 => {
                s.dont_ask_again = !s.dont_ask_again;
            }
            KeyCode::Enter => {
                let pick = match s.cursor {
                    0 => OnUnlistedModelsFetch::Keep,
                    1 => OnUnlistedModelsFetch::Remove,
                    _ => OnUnlistedModelsFetch::Keep,
                };
                let policy = match pick {
                    OnUnlistedModelsFetch::Remove => ModelMergePolicy::RemoveUnlisted,
                    OnUnlistedModelsFetch::Ask | OnUnlistedModelsFetch::Keep => {
                        ModelMergePolicy::KeepUnlisted
                    }
                };
                if let Some(entry) = self.config.providers.get_mut(&s.provider_id) {
                    entry.models = merge_fetched_models_with_policy(
                        entry.effective_template(&s.provider_id),
                        &s.pre_fetch_models,
                        s.remote.clone(),
                        policy,
                    );
                    entry.models_fetched_at = Some(Utc::now());
                    entry.model_catalog = s.catalog;
                    entry.mark_model_fetch_success(s.catalog);
                }
                if s.dont_ask_again {
                    self.config.on_unlisted_models_fetch = Some(pick);
                }
                let count = self
                    .config
                    .providers
                    .get(&s.provider_id)
                    .map(|entry| entry.models.len())
                    .unwrap_or(0);
                let status = match self.save_config() {
                    Ok(()) => fetch_success_message(count, s.catalog),
                    Err(e) => format!("save failed: {e}"),
                };
                let entry = self
                    .config
                    .providers
                    .get(&s.provider_id)
                    .cloned()
                    .unwrap_or_default();
                let mut edit = EditState::new(s.provider_id.clone(), entry);
                edit.status = Some(status);
                return Nav::Replace(Page::Providers(ProvidersPage::Edit(edit)));
            }
            _ => {}
        }
        Nav::Stay
    }

    fn handle_fetch_fallback_prompt_key(
        &mut self,
        key: KeyEvent,
        s: &mut FetchFallbackPromptState,
    ) -> Nav {
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc => {
                return Nav::Replace(Page::Providers(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some("refetch cancelled".into()),
                    delete_pending: false,
                }));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                s.cursor = crate::tui::nav::wrap_prev(s.cursor, 4);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                s.cursor = crate::tui::nav::wrap_next(s.cursor, 4);
            }
            KeyCode::Enter => match s.cursor {
                0 => {
                    let Some(entry) = self.config.providers.get(&s.provider_id).cloned() else {
                        return Nav::Replace(Page::Providers(ProvidersPage::List {
                            cursor: initial_list_cursor(&self.config),
                            status: Some("provider no longer exists".into()),
                            delete_pending: false,
                        }));
                    };
                    let mut edit = EditState::new(s.provider_id.clone(), entry.clone());
                    edit.status = Some("retrying live model fetch...".into());
                    edit.fetch = Some(FetchHandle::spawn(s.provider_id.clone(), entry));
                    return Nav::Replace(Page::Providers(ProvidersPage::Edit(edit)));
                }
                1 => {
                    if let Some(entry) = self.config.providers.get_mut(&s.provider_id) {
                        entry.mark_model_fetch_failed_kept_existing(s.reason.clone());
                    }
                    let status = match self.save_config() {
                        Ok(()) => "kept existing catalog after live fetch failure".to_string(),
                        Err(e) => format!("save failed: {e}"),
                    };
                    let entry = self
                        .config
                        .providers
                        .get(&s.provider_id)
                        .cloned()
                        .unwrap_or_default();
                    let mut edit = EditState::new(s.provider_id.clone(), entry);
                    edit.status = Some(status);
                    return Nav::Replace(Page::Providers(ProvidersPage::Edit(edit)));
                }
                2 => {
                    if let Some(entry) = self.config.providers.get_mut(&s.provider_id) {
                        entry.models = merge_fetched_models_with_policy(
                            entry.effective_template(&s.provider_id),
                            &entry.models,
                            s.models.clone(),
                            ModelMergePolicy::KeepUnlisted,
                        );
                        entry.models_fetched_at = Some(Utc::now());
                        entry.model_catalog = s.catalog;
                        entry.mark_model_fetch_fallback(s.reason.clone());
                    }
                    let count = self
                        .config
                        .providers
                        .get(&s.provider_id)
                        .map(|entry| entry.models.len())
                        .unwrap_or(0);
                    let status = match self.save_config() {
                        Ok(()) => fetch_success_message(count, s.catalog),
                        Err(e) => format!("save failed: {e}"),
                    };
                    let entry = self
                        .config
                        .providers
                        .get(&s.provider_id)
                        .cloned()
                        .unwrap_or_default();
                    let mut edit = EditState::new(s.provider_id.clone(), entry);
                    edit.status = Some(status);
                    return Nav::Replace(Page::Providers(ProvidersPage::Edit(edit)));
                }
                _ => {
                    return Nav::Replace(Page::Providers(ProvidersPage::List {
                        cursor: initial_list_cursor(&self.config),
                        status: Some("refetch cancelled".into()),
                        delete_pending: false,
                    }));
                }
            },
            _ => {}
        }
        Nav::Stay
    }

    /// Handle keys on the "Set up GitHub Copilot auth" confirm screen.
    /// Enter applies the action (or, in the manual / already-configured
    /// case, returns to the parent Edit page). Esc always returns to the
    /// parent Edit page. The screen is only ever reached from the Edit
    /// page of a Copilot provider (or the Add wizard, which has its own
    /// inline step), so it round-trips the `parent` EditState back intact.
    fn handle_copilot_setup_key(
        &mut self,
        key: KeyEvent,
        s: &mut CopilotSetupState,
        parent: &mut Box<EditState>,
    ) -> Nav {
        // Restore the parent Edit page, optionally surfacing `status` on it
        // (the outcome of an applied setup). Moves the parent out via
        // `mem::replace` so its cursor/unsaved-entry edits survive the trip.
        let back_to_edit = |parent: &mut Box<EditState>, status: Option<String>| {
            let mut owned = std::mem::replace(
                parent.as_mut(),
                EditState::new(String::new(), ProviderEntry::default()),
            );
            if let Some(status) = status {
                owned.status = Some(status);
            }
            Nav::Replace(Page::Providers(ProvidersPage::Edit(owned)))
        };
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc => {
                return back_to_edit(parent, None);
            }
            KeyCode::Enter => {
                // If we've already shown the user a result, Enter closes.
                if s.outcome.is_some() {
                    let status = match &s.outcome {
                        Some(Ok(msg)) => Some(msg.clone()),
                        Some(Err(e)) => Some(e.clone()),
                        None => None,
                    };
                    return back_to_edit(parent, status);
                }

                // If we can't auto-write (unsupported shell, marker
                // already present), Enter just returns to the Edit page —
                // the screen was informational only.
                let Some(shell) = s.shell else {
                    return back_to_edit(parent, None);
                };
                if s.already_configured {
                    return back_to_edit(parent, None);
                }
                let Some(rc_path) = s.rc_path.clone() else {
                    return back_to_edit(parent, None);
                };

                s.outcome = Some(apply_copilot_setup(shell, &rc_path));
            }
            _ => {}
        }
        Nav::Stay
    }
}

// ── Rendering ────────────────────────────────────────────────────────────

impl SettingsDialog {
    pub(super) fn render_providers_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        page: &ProvidersPage,
    ) {
        match page {
            ProvidersPage::List {
                cursor,
                status,
                delete_pending,
            } => {
                self.render_providers_list(frame, area, *cursor, status.as_deref(), *delete_pending)
            }
            ProvidersPage::Add(s) => self.render_add(frame, area, s),
            ProvidersPage::Edit(s) => self.render_edit(frame, area, s),
            ProvidersPage::Headers { editor, parent } => {
                self.render_headers_page(frame, area, editor, parent.as_ref())
            }
            ProvidersPage::Models { editor, parent } => {
                self.render_models_page(frame, area, editor, parent.as_ref())
            }
            ProvidersPage::ModelSettings { editor, parent, .. } => {
                self.render_settings_editor(frame, area, editor, parent.as_ref())
            }
            ProvidersPage::ProviderSettings { editor, parent } => {
                self.render_settings_editor(frame, area, editor, parent.as_ref())
            }
            ProvidersPage::FetchAll(s) => self.render_fetch_all(frame, area, s),
            ProvidersPage::FetchOnePrompt(s) => self.render_fetch_one_prompt(frame, area, s),
            ProvidersPage::FetchFallbackPrompt(s) => {
                self.render_fetch_fallback_prompt(frame, area, s)
            }
            ProvidersPage::CopilotSetup { state, .. } => {
                self.render_copilot_setup(frame, area, state)
            }
            ProvidersPage::GrokOAuthSetup { state, .. } => {
                render_grok_oauth_setup(frame, area, state)
            }
            ProvidersPage::CodexOAuthSetup { state, .. } => {
                render_codex_oauth_setup(frame, area, state)
            }
        }
    }

    fn render_providers_list(
        &self,
        frame: &mut Frame,
        area: Rect,
        cursor: usize,
        status: Option<&str>,
        delete_pending: bool,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let red = Style::default().fg(Color::Red);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let ids: Vec<&String> = self.config.providers.keys().collect();

        // Row 0: the `[refetch provider models]` button. Provider rows follow
        // at cursor indices 1..=ids.len().
        let button_selected = cursor == 0;
        let button_style = if button_selected {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            muted
        };
        lines.push(Line::from(vec![
            Span::raw(if button_selected { "▸ " } else { "  " }),
            Span::styled("[refetch provider models]".to_string(), button_style),
        ]));
        // Read-only summary of the global on-unlisted-models policy. Cycled
        // with `m`; it has no own cursor row so the provider list keeps its
        // simple index map.
        lines.push(Line::from(vec![
            Span::styled("  on unlisted models (m): ".to_string(), muted),
            Span::styled(
                on_unlisted_label(self.config.on_unlisted_models_fetch).to_string(),
                muted,
            ),
        ]));
        lines.push(Line::default());

        if ids.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (no providers configured)".to_string(),
                muted,
            )));
        } else {
            let id_w = ids.iter().map(|s| s.chars().count()).max().unwrap_or(0);
            for (i, id) in ids.iter().enumerate() {
                let row = i + 1;
                let entry = self.config.providers.get(*id).unwrap();
                let marker = if row == cursor { "▸ " } else { "  " };
                let label = format!("{:<width$}", id, width = id_w);
                let star = if entry.favorite.unwrap_or(false) {
                    " ★"
                } else {
                    "  "
                };
                let style = if row == cursor && delete_pending {
                    red.add_modifier(Modifier::BOLD)
                } else if row == cursor {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                let model_count = format!("{} models", entry.models.len());
                lines.push(Line::from(vec![
                    Span::raw(marker),
                    Span::styled(label, style),
                    Span::raw(star.to_string()),
                    Span::raw("  "),
                    Span::styled(entry.url.clone(), muted),
                    Span::raw("  "),
                    Span::styled(model_count, muted),
                ]));
            }
        }
        if let Some(msg) = status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                msg.to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:list", lines, selected_line);
    }

    fn render_copilot_setup(&self, frame: &mut Frame, area: Rect, s: &CopilotSetupState) {
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(Span::styled(
            "Set up GitHub Copilot auth".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());
        render_copilot_setup_body(&mut lines, s);
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_lines(
            frame,
            area,
            "providers:copilot-setup",
            lines,
            selected_line,
        );
    }

    fn render_add(&self, frame: &mut Frame, area: Rect, s: &AddState) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let red = Style::default().fg(Color::Red);
        let mut lines: Vec<Line<'static>> = Vec::new();

        match &s.step {
            AddStep::PickTemplate { cursor } => {
                lines.push(Line::from(Span::styled(
                    "Which provider would you like to add?".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::default());
                for (i, t) in templates::TEMPLATES.iter().enumerate() {
                    let marker = if i == *cursor { "▸ " } else { "  " };
                    let style = if i == *cursor {
                        yellow.add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(t.display.to_string(), style),
                        Span::raw("  "),
                        Span::styled(format!("({})", t.id), muted),
                    ]));
                }
                if let Some(t) = templates::TEMPLATES.get(*cursor)
                    && let Some(hint) = t.hint
                {
                    lines.push(Line::default());
                    lines.push(Line::from(Span::styled(hint.to_string(), muted)));
                }
            }
            AddStep::EditId | AddStep::EditUrl | AddStep::EditHeaders => {
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                render_field_row(
                    &mut lines,
                    "id",
                    &s.id_field,
                    matches!(s.step, AddStep::EditId),
                );
                render_field_row(
                    &mut lines,
                    "url",
                    &s.url_field,
                    matches!(s.step, AddStep::EditUrl),
                );
                if matches!(s.step, AddStep::EditHeaders) {
                    lines.push(Line::default());
                    render_header_editor(&mut lines, &s.headers);
                }
                if matches!(s.step, AddStep::EditUrl)
                    && let Some(hint) = t.hint
                {
                    lines.push(Line::default());
                    lines.push(Line::from(Span::styled(hint.to_string(), muted)));
                }
            }
            AddStep::CopilotAuth(state) => {
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                lines.push(Line::from(vec![
                    Span::styled("id:  ", muted),
                    Span::styled(
                        s.id_field.text().to_string(),
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::styled("API url: ", muted),
                    Span::styled(
                        s.url_field.text().to_string(),
                        Style::default().fg(Color::White),
                    ),
                ]));
                lines.push(Line::default());
                render_copilot_setup_body(&mut lines, state);
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "After this step we'll fetch the model list automatically. \
                     Press `s` to skip the GH_TOKEN setup if your token is \
                     already in the environment."
                        .to_string(),
                    muted,
                )));
            }
            AddStep::GrokOAuthAuth(state) => {
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "Uses your SuperGrok subscription quota via xAI's sanctioned OAuth flow."
                        .to_string(),
                    muted,
                )));
                lines.push(Line::default());
                render_grok_oauth_setup_body(&mut lines, state);
            }
            AddStep::CodexOAuthAuth(state) => {
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "Uses your ChatGPT Plus/Pro subscription quota via OpenAI's documented Codex agent login."
                        .to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "Uses a separate credential store from the Codex CLI; re-login if inference fails after CLI use."
                        .to_string(),
                    muted,
                )));
                lines.push(Line::default());
                render_codex_oauth_setup_body(&mut lines, state);
            }
            AddStep::Saving | AddStep::Fetching => {
                lines.push(Line::from(Span::styled(
                    if matches!(s.step, AddStep::Saving) {
                        "Saving config…"
                    } else {
                        "Fetching /models…"
                    }
                    .to_string(),
                    yellow,
                )));
            }
            AddStep::Done => {
                lines.push(Line::from(Span::styled(
                    "Done.".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
            }
        }
        if let Some(err) = &s.error {
            lines.push(Line::default());
            let style = if err.contains("failed") {
                red
            } else if err.starts_with("saved") || err.starts_with("Done") {
                muted
            } else {
                yellow
            };
            lines.push(Line::from(Span::styled(err.clone(), style)));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:add", lines, selected_line);
        if matches!(s.step, AddStep::EditHeaders) && s.headers.is_editing() {
            render_header_edit_popup(frame, area, &s.headers);
        }
    }

    fn render_edit(&self, frame: &mut Frame, area: Rect, s: &EditState) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = Vec::new();

        lines.push(Line::from(vec![
            Span::styled("Provider: ", muted),
            Span::styled(
                s.provider_id.clone(),
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw("  "),
            Span::styled(
                if s.entry.favorite.unwrap_or(false) {
                    "★ favorite"
                } else {
                    ""
                }
                .to_string(),
                yellow,
            ),
        ]));
        lines.push(Line::default());

        let headers_summary = if s.entry.headers.is_empty() {
            "(none)".to_string()
        } else {
            format!(
                "{} header(s): {}",
                s.entry.headers.len(),
                s.entry
                    .headers
                    .iter()
                    .map(|h| h.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        let manual_count = s.entry.models.iter().filter(|m| m.manual).count();
        let models_summary = if manual_count > 0 {
            format!(
                "{} model(s) ({} manual)",
                s.entry.models.len(),
                manual_count
            )
        } else {
            format!("{} model(s)", s.entry.models.len())
        };
        let settings_summary = provider_settings_summary(&s.entry);
        // Build the (label, value) for each menu action. The action list
        // (built by `edit_menu_actions`) is the single source of truth for
        // ordering and which rows exist — `s.cursor` indexes into it, and
        // the "Copilot auth" row is present only for Copilot providers.
        let actions = edit_menu_actions(&s.provider_id, &s.entry);
        let row = |action: EditAction| -> (&'static str, String) {
            match action {
                EditAction::Url => ("URL", s.entry.url.clone()),
                EditAction::Headers => ("Headers", headers_summary.clone()),
                EditAction::CopilotAuth => ("Copilot auth", String::new()),
                EditAction::GrokOAuthAuth => (
                    "Grok subscription auth",
                    if xai_oauth::is_logged_in() {
                        "logged in"
                    } else {
                        "not logged in"
                    }
                    .to_string(),
                ),
                EditAction::CodexOAuthAuth => (
                    "Codex subscription auth",
                    if codex_oauth::is_logged_in() {
                        "logged in"
                    } else {
                        "not logged in"
                    }
                    .to_string(),
                ),
                EditAction::Models => ("Models", models_summary.clone()),
                EditAction::Settings => ("Settings", settings_summary.clone()),
                EditAction::Favorite => (
                    "Favorite",
                    if s.entry.favorite.unwrap_or(false) {
                        "yes"
                    } else {
                        "no"
                    }
                    .to_string(),
                ),
                EditAction::Refetch => ("Refetch /models", refetch_summary(&s.entry)),
                EditAction::Delete => (
                    "Delete",
                    if s.delete_pending {
                        "(press Enter again to confirm)".to_string()
                    } else {
                        String::new()
                    },
                ),
                // Rendered specially (the save button) — never via the
                // label/value path below.
                EditAction::Save => ("", String::new()),
                EditAction::Back => ("Back to list", String::new()),
            }
        };

        let label_w = actions
            .iter()
            .filter(|a| **a != EditAction::Save)
            .map(|a| row(*a).0.chars().count())
            .max()
            .unwrap_or(0);

        for (idx, action) in actions.iter().enumerate() {
            let selected = idx == s.cursor;
            if *action == EditAction::Save {
                lines.push(save_button_line("[save changes]", selected));
                continue;
            }
            let (label, value) = row(*action);
            let marker = if selected { "▸ " } else { "  " };
            let style = if selected {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(format!("{:<width$}", label, width = label_w), style),
                Span::raw("  "),
                Span::styled(value, muted),
            ]));
        }

        if let Some(field) = s.editing_field {
            let prompt = match field {
                EditField::Url => "URL: ",
            };
            lines.push(Line::default());
            lines.push(Line::from(vec![
                Span::styled(prompt.to_string(), muted),
                Span::styled(
                    s.field_buf.text().to_string(),
                    Style::default().fg(Color::White),
                ),
            ]));
        }

        if let Some(status) = &s.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }

        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Slow model? Open Settings for first-token/idle thresholds. Without a backup they warn and keep waiting; with a backup they retry there.",
            muted,
        )));

        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:edit", lines, selected_line);
    }

    /// Full-pane render for the Headers sub-page. The header rows are
    /// the entire content; the parent Edit state is recalled on back.
    fn render_headers_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        editor: &HeaderEditor,
        parent: &EditState,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(vec![
                Span::styled("Provider: ", muted),
                Span::styled(
                    parent.provider_id.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::default(),
        ];
        render_header_editor(&mut lines, editor);
        if let Some(status) = &editor.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:headers", lines, selected_line);
        if editor.is_editing() {
            render_header_edit_popup(frame, area, editor);
        }
    }

    /// Full-pane render for the Models sub-page. Lists every model row
    /// (fetched + manual) plus the `[+ add model]` affordance; the parent
    /// Edit state is recalled on back.
    fn render_models_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        editor: &ModelEditor,
        parent: &EditState,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(vec![
                Span::styled("Provider: ", muted),
                Span::styled(
                    parent.provider_id.clone(),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::default(),
        ];
        render_model_editor(&mut lines, editor);
        render_model_fetch_status_block(&mut lines, &parent.entry, Utc::now());
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            format!(
                "a: add manual model   {}   r: rename manual   d: delete (x2)   esc: back",
                editor.selected_enter_hint()
            ),
            muted,
        )));
        if let Some(status) = &editor.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:models", lines, selected_line);
        if editor.is_editing() {
            render_model_edit_popup(frame, area, editor);
        }
    }

    /// Full-pane render for the model/provider settings sub-dialog
    /// (implementation note). Lists the scope's current
    /// settings fields with their working values; an inherited
    /// (non-overridden) model-scope field is dimmed with an `(inherited)` tag.
    /// The active numeric/text edit shows its buffer inline.
    fn render_settings_editor(
        &self,
        frame: &mut Frame,
        area: Rect,
        editor: &SettingsEditor,
        parent: &EditState,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let scope_label = match &editor.scope {
            super::settings_editor::SettingsScope::Model { model_id } => {
                format!("{} › {}", parent.provider_id, model_id)
            }
            super::settings_editor::SettingsScope::Provider => parent.provider_id.clone(),
        };
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(vec![
                Span::styled("Settings: ", muted),
                Span::styled(scope_label, Style::default().add_modifier(Modifier::BOLD)),
            ]),
            Line::default(),
        ];

        // Scope-aware field list: provider scope includes provider-only
        // transport security, while model scope omits provider-only rows and
        // can hide the wire-API row for native Anthropic providers.
        let fields = editor.fields();
        let label_w = fields
            .iter()
            .map(|f| f.label().chars().count())
            .max()
            .unwrap_or(0);

        for (i, field) in fields.iter().enumerate() {
            let selected = i == editor.cursor;
            let marker = if selected { "▸ " } else { "  " };
            let label_style = if selected {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let overridden = editor.is_overridden(*field);
            let value_style = if !overridden {
                muted
            } else if selected {
                Style::default().fg(Color::White)
            } else {
                muted
            };
            let mut spans = vec![
                Span::raw(marker),
                Span::styled(
                    format!("{:<width$}", field.label(), width = label_w),
                    label_style,
                ),
                Span::raw("  "),
            ];
            // While editing a numeric field, show the live buffer with a
            // caret at the text-field cursor; otherwise the formatted value.
            if editor.editing == Some(*field) {
                let (before, after) = editor.buf.split_at_cursor();
                spans.push(Span::styled(before.to_string(), value_style));
                spans.push(super::shell::cursor_marker_span());
                spans.push(Span::styled(after.to_string(), value_style));
            } else {
                spans.push(Span::styled(editor.value_str(*field), value_style));
            }
            if !overridden {
                spans.push(Span::styled("  (inherited)".to_string(), muted));
            }
            lines.push(Line::from(spans));
        }

        // `[save changes]` row, styled like MCP Add's button.
        lines.push(save_button_line("[save changes]", editor.on_save_row()));

        // Read-only model metadata, surfaced (not hidden) for completeness:
        // the `manual` marker and any preserved provider `extra` keys. These
        // are not editable here — `extra` is opaque vendor metadata kept
        // round-trip — so they render as plain dimmed rows.
        if let super::settings_editor::SettingsScope::Model { model_id } = &editor.scope
            && let Some(m) = parent.entry.models.iter().find(|m| &m.id == model_id)
        {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!(
                    "manual entry: {}  (read-only)",
                    if m.manual { "yes" } else { "no" }
                ),
                muted,
            )));
            let extra = if m.extra.is_empty() {
                "extra metadata: (none)  (read-only)".to_string()
            } else {
                let keys: Vec<&str> = m.extra.keys().map(String::as_str).collect();
                format!("extra metadata: {}  (read-only)", keys.join(", "))
            };
            lines.push(Line::from(Span::styled(extra, muted)));
        }

        if editor.shows_xai_multi_agent_tools_beta() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Without this entitlement, Cockpit blocks tool-using agent runs on Grok multi-agent models before sending a request.",
                muted,
            )));
            if parent
                .entry
                .models
                .iter()
                .any(|m| m.id.to_ascii_lowercase().contains("multi-agent"))
            {
                lines.push(Line::from(Span::styled(
                    "Grok multi-agent models are present; leave this off unless xAI has enabled beta tool access for the account.",
                    muted,
                )));
            }
        }

        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "auto uses provider defaults and learned endpoint; completions POSTs /chat/completions; responses POSTs /responses. OpenAI-compatible providers only.",
            muted,
        )));
        lines.push(Line::from(Span::styled(
            "Without a backup model, exceeding thresholds shows a slow-stream warning and keeps waiting (Ctrl+C cancels). With a backup model, the turn retries on the backup at the threshold.",
            muted,
        )));
        if let Some(help) = editor.selected_help() {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(help.to_string(), muted)));
        }

        if let Some(status) = &editor.status {
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        } else if matches!(
            editor.scope,
            super::settings_editor::SettingsScope::Model { .. }
        ) {
            lines.push(Line::from(Span::styled(
                "enter: edit/cycle   x: clear to inherit   h: back".to_string(),
                muted,
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "enter: edit/cycle   h: back".to_string(),
                muted,
            )));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:settings", lines, selected_line);
    }

    fn render_fetch_all(&self, frame: &mut Frame, area: Rect, s: &FetchAllState) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let green = Style::default().fg(Color::Green);
        let red = Style::default().fg(Color::Red);
        let mut lines: Vec<Line<'static>> = Vec::new();

        // Progress view while fetches are in flight, plus the running
        // per-provider results so the user sees outcomes land one by one.
        if s.is_fetching() {
            let done = s.finished.len();
            let total = done + s.in_flight.len();
            lines.push(Line::from(Span::styled(
                format!("Refetching provider /models catalogs… ({done}/{total})"),
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::default());
            render_fetch_all_results(&mut lines, s, muted, green, red);
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("esc: cancel".to_string(), muted)));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
            return;
        }

        // Fetch complete with no drifted models: show the per-provider
        // summary and wait for a keypress to return.
        if s.unlisted.is_empty() {
            lines.push(Line::from(Span::styled(
                "Refetch complete.".to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::default());
            render_fetch_all_results(&mut lines, s, muted, green, red);
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press any key to return.".to_string(),
                muted,
            )));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
            return;
        }

        lines.push(Line::from(Span::styled(
            "Some configured models are not in the upstream /models list:".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for (pid, mid) in s.unlisted.iter().take(10) {
            lines.push(Line::from(Span::styled(format!("  {pid} › {mid}"), muted)));
        }
        if s.unlisted.len() > 10 {
            lines.push(Line::from(Span::styled(
                format!("  … and {} more", s.unlisted.len() - 10),
                muted,
            )));
        }
        lines.push(Line::default());
        let opts = [
            "Don't remove unlisted models (default)",
            "Remove unlisted models",
        ];
        for (i, label) in opts.iter().enumerate() {
            let marker = if i == s.cursor { "▸ " } else { "  " };
            let style = if i == s.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label.to_string(), style),
            ]));
        }
        let check = if s.dont_ask_again { "[x]" } else { "[ ]" };
        let style = if s.cursor == 2 {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(if s.cursor == 2 { "▸ " } else { "  " }),
            Span::styled(format!("{check} Do not show again"), style),
        ]));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn render_fetch_one_prompt(&self, frame: &mut Frame, area: Rect, s: &FetchOnePromptState) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = Vec::new();

        lines.push(Line::from(Span::styled(
            format!(
                "`{}` has configured models not in the upstream /models list:",
                s.provider_id
            ),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for mid in s.unlisted.iter().take(10) {
            lines.push(Line::from(Span::styled(format!("  {mid}"), muted)));
        }
        if s.unlisted.len() > 10 {
            lines.push(Line::from(Span::styled(
                format!("  … and {} more", s.unlisted.len() - 10),
                muted,
            )));
        }
        lines.push(Line::default());
        let opts = [
            "Don't remove unlisted models (default)",
            "Remove unlisted models",
        ];
        for (i, label) in opts.iter().enumerate() {
            let marker = if i == s.cursor { "▸ " } else { "  " };
            let style = if i == s.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label.to_string(), style),
            ]));
        }
        let check = if s.dont_ask_again { "[x]" } else { "[ ]" };
        let style = if s.cursor == 2 {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(if s.cursor == 2 { "▸ " } else { "  " }),
            Span::styled(format!("{check} Do not show again"), style),
        ]));
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn render_fetch_fallback_prompt(
        &self,
        frame: &mut Frame,
        area: Rect,
        s: &FetchFallbackPromptState,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = Vec::new();

        lines.push(Line::from(Span::styled(
            format!("`{}` live /models fetch failed.", s.provider_id),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::from(Span::styled(
            format!("reason: {}", s.reason),
            muted,
        )));
        lines.push(Line::default());
        let opts = [
            "Retry live fetch",
            "Keep existing catalog",
            "Use fallback catalog",
            "Cancel",
        ];
        for (i, label) in opts.iter().enumerate() {
            let marker = if i == s.cursor { "▸ " } else { "  " };
            let style = if i == s.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label.to_string(), style),
            ]));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}

// ── Free helpers ─────────────────────────────────────────────────────────

/// Render the body of the Copilot auth-setup affordance (everything
/// after the bold title). Used both by the standalone CopilotSetup
/// page and by the embedded panel inside the Add-Provider Copilot flow.
fn render_copilot_setup_body(lines: &mut Vec<Line<'static>>, s: &CopilotSetupState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);
    let green = Style::default().fg(Color::Green);
    let cyan = Style::default().fg(Color::Cyan);

    if let Some(outcome) = &s.outcome {
        // Post-action result screen.
        match outcome {
            Ok(msg) => {
                lines.push(Line::from(Span::styled(msg.clone(), green)));
            }
            Err(e) => {
                lines.push(Line::from(Span::styled(format!("Failed: {e}"), red)));
            }
        }
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Press Enter to continue.".to_string(),
            muted,
        )));
        return;
    }

    match (s.shell, &s.rc_path, s.already_configured) {
        (Some(shell), Some(rc_path), false) => {
            lines.push(Line::from(Span::styled(
                format!("Detected shell: {}", shell.name()),
                muted,
            )));
            lines.push(Line::from(vec![
                Span::styled("Will append to: ".to_string(), muted),
                Span::styled(rc_path.display().to_string(), cyan),
            ]));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Lines to be added:".to_string(),
                muted,
            )));
            for line in copilot_setup::append_block(shell).lines() {
                if line.is_empty() {
                    lines.push(Line::default());
                } else {
                    lines.push(Line::from(Span::styled(format!("    {line}"), cyan)));
                }
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "We'll also run `gh auth token` once and set GH_TOKEN in this \
                     cockpit session so Copilot works without restarting."
                    .to_string(),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter to apply, Esc to cancel.".to_string(),
                yellow,
            )));
        }
        (Some(shell), Some(rc_path), true) => {
            lines.push(Line::from(Span::styled(
                format!(
                    "{} already contains the cockpit Copilot-auth export.",
                    rc_path.display()
                ),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                format!(
                    "To re-apply: remove the marker block from your {} and try again.",
                    shell.rc_filename()
                ),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter or Esc to return.".to_string(),
                yellow,
            )));
        }
        _ => {
            // Unsupported shell or unknown $HOME — show manual
            // instructions instead of a write button.
            lines.push(Line::from(Span::styled(
                "Couldn't detect a supported shell ($SHELL is unset, or it's \
                     not zsh/bash/fish). Set GH_TOKEN manually with one of:"
                    .to_string(),
                muted,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "  POSIX shell (zsh/bash/sh):".to_string(),
                muted,
            )));
            lines.push(Line::from(Span::styled(
                "    export GH_TOKEN=$(gh auth token)".to_string(),
                cyan,
            )));
            lines.push(Line::default());
            lines.push(Line::from(Span::styled("  fish:".to_string(), muted)));
            lines.push(Line::from(Span::styled(
                "    set -Ux GH_TOKEN (gh auth token)".to_string(),
                cyan,
            )));
            if cfg!(windows) {
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "  Windows PowerShell ($PROFILE):".to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "    $env:GH_TOKEN = (gh auth token)".to_string(),
                    cyan,
                )));
                lines.push(Line::from(Span::styled(
                    "  Windows persistent (User scope):".to_string(),
                    muted,
                )));
                lines.push(Line::from(Span::styled(
                    "    [Environment]::SetEnvironmentVariable(\"GH_TOKEN\", \
                         (gh auth token), \"User\")"
                        .to_string(),
                    cyan,
                )));
            }
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                "Press Enter or Esc to return.".to_string(),
                yellow,
            )));
        }
    }
}

fn handle_grok_oauth_setup_key(
    key: KeyEvent,
    s: &mut GrokOAuthSetupState,
) -> (bool, Option<OAuthActionRequest>) {
    if s.pending && matches!(key.code, KeyCode::Esc) {
        s.pending = false;
        s.status = Some(Ok("OAuth login cancelled".to_string()));
        return (false, Some(OAuthActionRequest::GrokCancel));
    }
    if s.manual_mode {
        match key.code {
            KeyCode::Esc => {
                s.manual_mode = false;
                s.manual_input.set("");
                s.pending = false;
                return (false, Some(OAuthActionRequest::GrokCancel));
            }
            KeyCode::Enter => {
                let Some(login) = s.manual_login.clone() else {
                    s.status = Some(Err("manual OAuth session was not initialized".into()));
                    s.manual_mode = false;
                    return (false, None);
                };
                let input = s.manual_input.text().to_string();
                if input.trim().is_empty() {
                    s.status = Some(Err("paste callback URL or code first".to_string()));
                    return (false, None);
                }
                s.pending = true;
                s.status = Some(Ok("Completing xAI OAuth login...".to_string()));
                return (
                    false,
                    Some(OAuthActionRequest::GrokComplete { login, input }),
                );
            }
            _ => {
                s.manual_input.handle_key(key);
                return (false, None);
            }
        }
    }

    if matches!(key.code, KeyCode::Char('c')) {
        copy_oauth_url_with(
            s.authorize_url.as_deref(),
            &mut s.status,
            crate::clipboard::copy_plain,
        );
        return (false, None);
    }

    match key.code {
        KeyCode::Esc => (true, Some(OAuthActionRequest::GrokCancel)),
        KeyCode::Up | KeyCode::Char('k') => {
            let len = if grok_oauth_setup_is_confirmation(s) {
                1
            } else {
                3
            };
            s.cursor = oauth_option_cursor_prev(s.cursor, len);
            (false, None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let len = if grok_oauth_setup_is_confirmation(s) {
                1
            } else {
                3
            };
            s.cursor = oauth_option_cursor_next(s.cursor, len);
            (false, None)
        }
        KeyCode::Enter => {
            if grok_oauth_setup_is_confirmation(s) {
                s.cursor = 0;
                return (false, None);
            }
            if s.pending {
                return (false, None);
            }
            if s.cursor == 0 || s.cursor == 1 {
                let selection = if s.cursor == 1 {
                    GrokLoginSelection::ManualOnly
                } else {
                    grok_login_selection(s.ssh_manual_only)
                };
                s.pending = true;
                s.manual_mode = matches!(selection, GrokLoginSelection::ManualOnly);
                s.manual_input.set("");
                s.status = Some(Ok(if s.cursor == 0 && !s.ssh_manual_only {
                    "Preparing xAI OAuth login...".to_string()
                } else if s.ssh_manual_only {
                    "SSH detected; browser auto-open is unavailable here".to_string()
                } else {
                    "Preparing manual xAI OAuth login...".to_string()
                }));
                return (
                    false,
                    Some(OAuthActionRequest::GrokBegin {
                        is_ssh: matches!(selection, GrokLoginSelection::ManualOnly),
                    }),
                );
            }
            (false, None)
        }
        _ => (false, None),
    }
}

fn grok_oauth_setup_is_confirmation(s: &GrokOAuthSetupState) -> bool {
    oauth_setup_confirming_logged_in(s.logged_in, s.pending, s.manual_mode)
}

fn render_grok_oauth_setup(frame: &mut Frame, area: Rect, s: &GrokOAuthSetupState) {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "Set up Grok subscription auth".to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::default());
    render_grok_oauth_setup_body(&mut lines, s);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn render_grok_oauth_setup_body(lines: &mut Vec<Line<'static>>, s: &GrokOAuthSetupState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    let red = Style::default().fg(Color::Red);
    let cyan = Style::default().fg(Color::Cyan);

    lines.push(Line::from(vec![
        Span::styled("Status: ", muted),
        Span::styled(
            if s.logged_in {
                "logged in"
            } else {
                "not logged in"
            }
            .to_string(),
            if s.logged_in { green } else { red },
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "Uses your SuperGrok subscription quota via xAI's sanctioned OAuth flow.".to_string(),
        muted,
    )));
    lines.push(Line::default());
    if let Some(status) = &s.status {
        match status {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), cyan))),
            Err(msg) => lines.push(Line::from(Span::styled(format!("Failed: {msg}"), red))),
        }
        lines.push(Line::default());
    }
    if s.pending {
        lines.push(Line::from(Span::styled(
            format!(
                "{} Waiting for OAuth response...",
                spinner_glyph(s.spinner_tick)
            ),
            yellow,
        )));
        lines.push(Line::default());
    }
    if let Some(url) = &s.authorize_url {
        lines.push(Line::from(Span::styled(
            "Open this URL in a browser, then paste the callback URL or code below.".to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(url.clone(), cyan),
        ]));
        lines.push(Line::from(Span::styled("c copy URL".to_string(), muted)));
        lines.push(Line::default());
    }
    if s.manual_mode {
        lines.push(Line::from(Span::styled(
            "Paste callback URL, ?code=...&state=..., or bare code:".to_string(),
            muted,
        )));
        lines.push(Line::from(Span::styled(
            s.manual_input.text().to_string(),
            cyan,
        )));
        return;
    }
    let opts: &[&str] = if grok_oauth_setup_is_confirmation(s) {
        &["continue"]
    } else {
        &["log in", "manual paste", "skip / continue"]
    };
    for (i, label) in opts.iter().enumerate() {
        let marker = if i == s.cursor { "▸ " } else { "  " };
        let style = if i == s.cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("[{label}]"), style),
        ]));
    }
}

fn handle_codex_oauth_setup_key(
    key: KeyEvent,
    s: &mut CodexOAuthSetupState,
) -> (bool, Option<OAuthActionRequest>) {
    if matches!(key.code, KeyCode::Char('c')) {
        copy_oauth_url_with(
            s.pending
                .as_ref()
                .map(|login| login.verification_uri.as_str()),
            &mut s.status,
            crate::clipboard::copy_plain,
        );
        return (false, None);
    }
    if s.polling && matches!(key.code, KeyCode::Esc) {
        s.polling = false;
        s.status = Some(Ok("Codex OAuth polling cancelled".to_string()));
        return (false, Some(OAuthActionRequest::CodexCancel));
    }
    match key.code {
        KeyCode::Esc => (true, Some(OAuthActionRequest::CodexCancel)),
        KeyCode::Up | KeyCode::Char('k') => {
            let len = if codex_oauth_setup_is_confirmation(s) {
                1
            } else {
                2
            };
            s.cursor = oauth_option_cursor_prev(s.cursor, len);
            (false, None)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            let len = if codex_oauth_setup_is_confirmation(s) {
                1
            } else {
                2
            };
            s.cursor = oauth_option_cursor_next(s.cursor, len);
            (false, None)
        }
        KeyCode::Enter => {
            if codex_oauth_setup_is_confirmation(s) {
                s.cursor = 0;
                return (false, None);
            }
            if s.cursor == 0 {
                if s.polling {
                    return (false, None);
                }
                if let Some(login) = s.pending.clone() {
                    s.polling = true;
                    s.status = Some(Ok("Waiting for Codex approval...".to_string()));
                    return (false, Some(OAuthActionRequest::CodexPoll(login)));
                } else {
                    s.polling = true;
                    s.status = Some(Ok("Requesting Codex device code...".to_string()));
                    return (false, Some(OAuthActionRequest::CodexBegin));
                }
            }
            (false, None)
        }
        _ => (false, None),
    }
}

fn codex_oauth_setup_is_confirmation(s: &CodexOAuthSetupState) -> bool {
    oauth_setup_confirming_logged_in(s.logged_in, s.polling, false)
}

fn render_codex_oauth_setup(frame: &mut Frame, area: Rect, s: &CodexOAuthSetupState) {
    let mut lines = Vec::new();
    lines.push(Line::from(Span::styled(
        "Set up Codex subscription auth".to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::default());
    render_codex_oauth_setup_body(&mut lines, s);
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}

fn render_codex_oauth_setup_body(lines: &mut Vec<Line<'static>>, s: &CodexOAuthSetupState) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    let red = Style::default().fg(Color::Red);
    let cyan = Style::default().fg(Color::Cyan);

    lines.push(Line::from(vec![
        Span::styled("Status: ", muted),
        Span::styled(
            if s.logged_in {
                "logged in"
            } else {
                "not logged in"
            }
            .to_string(),
            if s.logged_in { green } else { red },
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "Uses your ChatGPT Plus/Pro subscription quota via OpenAI's documented Codex agent login."
            .to_string(),
        muted,
    )));
    lines.push(Line::from(Span::styled(
        "Separate from the Codex CLI credential store; re-login if CLI use causes refresh-token contention."
            .to_string(),
        muted,
    )));
    lines.push(Line::default());
    if let Some(status) = &s.status {
        match status {
            Ok(msg) => lines.push(Line::from(Span::styled(msg.clone(), cyan))),
            Err(msg) => lines.push(Line::from(Span::styled(format!("Failed: {msg}"), red))),
        }
        lines.push(Line::default());
    }
    if let Some(login) = &s.pending {
        lines.push(Line::from(Span::styled(
            "Open this URL in any browser, including a different machine from this terminal."
                .to_string(),
            muted,
        )));
        lines.push(Line::from(vec![
            Span::styled("Open: ", muted),
            Span::styled(login.verification_uri.clone(), cyan),
        ]));
        lines.push(Line::from(vec![
            Span::styled("Code: ", muted),
            Span::styled(login.user_code.clone(), yellow.add_modifier(Modifier::BOLD)),
        ]));
        lines.push(Line::from(Span::styled(
            "After approving, poll here; Cockpit waits for the full 15 minute device-code window. c copies the URL."
                .to_string(),
            muted,
        )));
        lines.push(Line::default());
    }
    if s.polling {
        lines.push(Line::from(Span::styled(
            format!("{} Waiting for approval...", spinner_glyph(s.spinner_tick)),
            yellow,
        )));
        lines.push(Line::default());
    }
    let opts: &[&str] = if codex_oauth_setup_is_confirmation(s) {
        &["continue"]
    } else if s.pending.is_some() {
        &["poll for approval", "skip / continue"]
    } else {
        &["log in", "skip / continue"]
    };
    for (i, label) in opts.iter().enumerate() {
        let marker = if i == s.cursor { "▸ " } else { "  " };
        let style = if i == s.cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(format!("[{label}]"), style),
        ]));
    }
}

fn spinner_glyph(tick: usize) -> &'static str {
    ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"][tick % 10]
}

/// Render a [`HeaderEditor`] as rows + `[+ add header]` + (optional)
/// `[continue →]`. The active cursor row is highlighted in yellow; the
/// in-flight name/value buffer (when editing) replaces the row's value.
fn render_header_editor(lines: &mut Vec<Line<'static>>, h: &HeaderEditor) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    lines.push(Line::from(Span::styled(
        "Headers:".to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    let name_w = h
        .rows()
        .iter()
        .map(|r| r.name.chars().count())
        .max()
        .unwrap_or(0)
        .max(13);

    for (i, row) in h.rows().iter().enumerate() {
        let cursor_here = h.cursor == i;
        let marker = if cursor_here { "  ▸ " } else { "    " };
        let name_style = if cursor_here {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker.to_string()),
            Span::styled(format!("{:<width$}", row.name, width = name_w), name_style),
            Span::raw("  "),
            Span::styled(display_header_value(&row.name, &row.value), muted),
        ]));
    }

    let add_idx = h.add_row_idx();
    let add_cursor = h.cursor == add_idx;
    let add_marker = if add_cursor { "  ▸ " } else { "    " };
    let add_style = if add_cursor {
        yellow.add_modifier(Modifier::BOLD)
    } else {
        muted
    };
    lines.push(Line::from(vec![
        Span::raw(add_marker.to_string()),
        Span::styled("[+ add header]".to_string(), add_style),
    ]));

    if let Some(cont_idx) = h.continue_idx() {
        let cont_cursor = h.cursor == cont_idx;
        let marker = if cont_cursor { "  ▸ " } else { "    " };
        let style = if cont_cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            muted
        };
        lines.push(Line::from(vec![
            Span::raw(marker.to_string()),
            Span::styled("[continue → save & fetch /models]".to_string(), style),
        ]));
    }

    // `[save changes]` row on the Edit-page sub-page (mutually exclusive
    // with `[continue →]`). Styled like MCP Add's button.
    if let Some(save_idx) = h.save_idx() {
        lines.push(save_button_line("[save changes]", h.cursor == save_idx));
    }
}

/// Centered name/value popup for adding or editing a header. Drawn on
/// top of the header list when the editor is in `EditName`/`EditValue`
/// mode. The `Clear` widget wipes the cells underneath so the list
/// doesn't bleed through.
fn render_header_edit_popup(frame: &mut Frame, area: Rect, h: &HeaderEditor) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);

    let name_focus = matches!(h.mode, HeaderMode::EditName);

    let mut body: Vec<Line<'static>> = Vec::new();
    render_field_row(&mut body, "Name ", &h.name_buf, name_focus);
    render_field_row(&mut body, "Value", &h.value_buf, !name_focus);

    // Env-var status for the value (headers commonly reference `$VAR`).
    let resolved = envref::resolve(h.value_buf.text());
    if resolved.has_missing() {
        body.push(Line::from(Span::styled(
            format!(
                "  Environment variable not detected, make sure to set it: ${}",
                resolved.missing.join(", $")
            ),
            yellow,
        )));
    } else if !resolved.referenced.is_empty() {
        body.push(Line::from(Span::styled(
            format!(
                "  env var(s) detected: ${}",
                resolved.referenced.join(", $")
            ),
            muted,
        )));
    } else {
        body.push(Line::default());
    }
    body.push(Line::default());
    body.push(Line::from(Span::styled(
        "Tab: switch field   enter: save   esc: cancel".to_string(),
        muted,
    )));

    let title = if h.edit_target.is_some() {
        " Edit header "
    } else {
        " Add header "
    };
    let width = area.width.saturating_sub(6).clamp(24, 70);
    let height = (body.len() as u16) + 2; // +2 for the top/bottom border
    let rect = centered_rect(area, width, height);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(yellow)
        .title(title);
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }), inner);
}

/// Render a [`ModelEditor`] as rows + `[+ add model]`. Each row shows the
/// model id, an `M` tag for manual entries, the display name, and the
/// context length when set. The active cursor row is highlighted.
fn render_model_editor(lines: &mut Vec<Line<'static>>, m: &ModelEditor) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    lines.push(Line::from(Span::styled(
        "Provider models:".to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));

    if m.rows().is_empty() {
        lines.push(Line::from(Span::styled(
            "    (no models — add one by hand or refetch `/models`)".to_string(),
            muted,
        )));
    } else {
        let id_w = m
            .rows()
            .iter()
            .map(|r| r.id.chars().count())
            .max()
            .unwrap_or(0);
        for (i, row) in m.rows().iter().enumerate() {
            let cursor_here = m.cursor == i;
            let marker = if cursor_here { "  ▸ " } else { "    " };
            let id_style = if cursor_here {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let tag = if row.manual { "M" } else { " " };
            let mut detail = row.name.clone().unwrap_or_default();
            if let Some(ctx) = row.context_length {
                if !detail.is_empty() {
                    detail.push_str("  ");
                }
                detail.push_str(&format!("ctx {ctx}"));
            }
            lines.push(Line::from(vec![
                Span::raw(marker.to_string()),
                Span::styled(format!("{tag} "), green),
                Span::styled(format!("{:<width$}", row.id, width = id_w), id_style),
                Span::raw("  "),
                Span::styled(detail, muted),
            ]));
        }
    }

    let add_idx = m.rows().len();
    let add_cursor = m.cursor == add_idx;
    let add_marker = if add_cursor { "  ▸ " } else { "    " };
    let add_style = if add_cursor {
        yellow.add_modifier(Modifier::BOLD)
    } else {
        muted
    };
    lines.push(Line::from(vec![
        Span::raw(add_marker.to_string()),
        Span::styled("[+ add model]".to_string(), add_style),
    ]));

    // `[save changes]` row, styled like MCP Add's button.
    lines.push(save_button_line("[save changes]", m.cursor == m.save_idx()));
}

fn render_model_fetch_status_block(
    lines: &mut Vec<Line<'static>>,
    entry: &ProviderEntry,
    now: chrono::DateTime<Utc>,
) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let state = provider_model_fetch_display_state(entry);
    let state_style = match state {
        crate::config::providers::ProviderModelFetchDisplayState::Live => {
            Style::default().fg(Color::Green)
        }
        crate::config::providers::ProviderModelFetchDisplayState::Fallback
        | crate::config::providers::ProviderModelFetchDisplayState::Preserved
        | crate::config::providers::ProviderModelFetchDisplayState::Unsupported => {
            Style::default().fg(Color::Yellow)
        }
        crate::config::providers::ProviderModelFetchDisplayState::Failed
        | crate::config::providers::ProviderModelFetchDisplayState::AuthFailed => {
            Style::default().fg(Color::Red)
        }
    };

    lines.push(Line::default());
    lines.push(Line::from(Span::styled(
        "Catalog status:".to_string(),
        Style::default().add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(vec![
        Span::styled("  state:   ", muted),
        Span::styled(state.label().to_string(), state_style),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  count:   ", muted),
        Span::styled(entry.models.len().to_string(), muted),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  fetched: ", muted),
        Span::styled(format_model_fetch_age(entry.models_fetched_at, now), muted),
    ]));
    lines.push(Line::from(vec![
        Span::styled("  reason:  ", muted),
        Span::styled(provider_model_fetch_reason_display(entry), muted),
    ]));
}

/// Centered id/name/context popup for adding or editing a manual model.
/// Drawn on top of the model list while the editor is in `Edit` mode.
fn render_model_edit_popup(frame: &mut Frame, area: Rect, m: &ModelEditor) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let red = Style::default().fg(Color::Red);

    let mut body: Vec<Line<'static>> = Vec::new();
    render_field_row(&mut body, "Id     ", &m.id_buf, m.focus == ModelField::Id);
    render_field_row(
        &mut body,
        "Name   ",
        &m.name_buf,
        m.focus == ModelField::Name,
    );
    render_field_row(
        &mut body,
        "Context",
        &m.context_buf,
        m.focus == ModelField::Context,
    );
    body.push(Line::default());
    if let Some(status) = &m.status {
        body.push(Line::from(Span::styled(format!("  {status}"), red)));
    } else {
        body.push(Line::from(Span::styled(
            "  id required · name falls back to id · context optional (number)".to_string(),
            muted,
        )));
    }
    body.push(Line::from(Span::styled(
        "  Tab: switch field   enter: save   esc: cancel".to_string(),
        muted,
    )));

    let title = if m.edit_target.is_some() {
        " Edit model "
    } else {
        " Add model "
    };
    let width = area.width.saturating_sub(6).clamp(24, 70);
    let height = (body.len() as u16) + 2; // +2 for the top/bottom border
    let rect = centered_rect(area, width, height);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(yellow)
        .title(title);
    let inner = block.inner(rect);
    frame.render_widget(Clear, rect);
    frame.render_widget(block, rect);
    frame.render_widget(Paragraph::new(body).wrap(Wrap { trim: false }), inner);
}

/// A `width`×`height` rect centered within `area`, clamped to fit.
fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width);
    let height = height.min(area.height);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn render_field_row(lines: &mut Vec<Line<'static>>, label: &str, field: &TextField, active: bool) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let value_style = if active {
        Style::default().fg(Color::White)
    } else {
        muted
    };
    let marker = if active { "▸ " } else { "  " };
    let mut spans = vec![
        Span::raw(marker),
        Span::styled(
            format!("{label}: "),
            if active {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                muted
            },
        ),
    ];
    if active {
        let text = field.text();
        let cursor = clamp_to_char_boundary(text, field.cursor());
        let (before, after) = text.split_at(cursor);
        spans.push(Span::styled(before.to_string(), value_style));
        spans.push(super::shell::cursor_marker_span());
        spans.push(Span::styled(after.to_string(), value_style));
    } else {
        spans.push(Span::styled(field.text().to_string(), value_style));
    }
    lines.push(Line::from(spans));
}

/// Render the per-provider outcome rows of an all-providers refetch:
/// `✓ provider — N model(s)`, `· provider — no /models endpoint`, or
/// `✗ provider — <error>`. Shared by the in-flight and completed views.
fn render_fetch_all_results(
    lines: &mut Vec<Line<'static>>,
    s: &FetchAllState,
    muted: Style,
    green: Style,
    red: Style,
) {
    for f in &s.finished {
        let (glyph, text, style) = match &f.outcome {
            Ok(FetchOutcome::Models { models, catalog }) => (
                "✓",
                format!(
                    "{} — {} model(s){}",
                    f.provider_id,
                    models.len(),
                    provider_catalog_suffix(*catalog)
                ),
                green,
            ),
            Ok(FetchOutcome::Unsupported) => (
                "·",
                format!("{} — no /models endpoint (skipped)", f.provider_id),
                muted,
            ),
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => (
                "✗",
                format!(
                    "{} — live fetch failed; fallback available: {reason}",
                    f.provider_id,
                    reason = redact_model_fetch_reason(reason.as_str())
                ),
                red,
            ),
            Err(e) => (
                "✗",
                format!(
                    "{} — {}",
                    f.provider_id,
                    redact_model_fetch_reason(e.as_str())
                ),
                red,
            ),
        };
        lines.push(Line::from(vec![
            Span::raw(format!("  {glyph} ")),
            Span::styled(text, style),
        ]));
    }
}

/// One-line per-provider summary of a finished all-providers refetch:
/// how many succeeded, how many failed, and (when any did) the first
/// failing provider so the user has a thread to pull on.
fn fetch_all_summary(s: &FetchAllState) -> String {
    let total = s.finished.len();
    let failed: Vec<&FetchedSummary> = s
        .finished
        .iter()
        .filter(|f| {
            f.outcome.is_err() || matches!(f.outcome, Ok(FetchOutcome::FallbackAvailable { .. }))
        })
        .collect();
    let ok = total - failed.len();
    if failed.is_empty() {
        format!("refetched /models for {ok}/{total} provider(s)")
    } else {
        let first = &failed[0];
        let reason = match &first.outcome {
            Err(e) => redact_model_fetch_reason(e.as_str()),
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => {
                redact_model_fetch_reason(reason.as_str())
            }
            Ok(_) => String::new(),
        };
        format!(
            "refetched {ok}/{total} provider(s); {} failed (e.g. `{}`: {reason})",
            failed.len(),
            first.provider_id,
        )
    }
}

fn fetch_all_merges(
    s: &FetchAllState,
) -> Vec<(
    String,
    Vec<ModelEntry>,
    Vec<ModelEntry>,
    ProviderModelCatalog,
)> {
    s.finished
        .iter()
        .filter_map(|summary| match &summary.outcome {
            Ok(FetchOutcome::Models { models, catalog }) => Some((
                summary.provider_id.clone(),
                s.pre_fetch_models
                    .get(&summary.provider_id)
                    .cloned()
                    .unwrap_or_default(),
                models.clone(),
                *catalog,
            )),
            _ => None,
        })
        .collect()
}

fn fetch_all_degraded_statuses(dialog: &SettingsDialog) -> Vec<(String, FetchDegradedStatus)> {
    let Page::Providers(ProvidersPage::FetchAll(s)) = &dialog.page else {
        return Vec::new();
    };
    s.finished
        .iter()
        .filter_map(|summary| match &summary.outcome {
            Ok(FetchOutcome::Unsupported) => Some((
                summary.provider_id.clone(),
                FetchDegradedStatus::Unsupported,
            )),
            Ok(FetchOutcome::FallbackAvailable { reason, .. }) => Some((
                summary.provider_id.clone(),
                FetchDegradedStatus::Failed(redact_model_fetch_reason(reason.as_str())),
            )),
            Err(error) => Some((
                summary.provider_id.clone(),
                FetchDegradedStatus::Failed(redact_model_fetch_reason(error.as_str())),
            )),
            Ok(FetchOutcome::Models { .. }) => None,
        })
        .collect()
}

/// Build the (provider_id, model_id) set of configured models that are
/// absent from the freshly-fetched upstream list, across every provider
/// that reported a successful `Models` outcome in the active FetchAll.
fn compute_unlisted(dialog: &SettingsDialog) -> Vec<(String, String)> {
    let Page::Providers(ProvidersPage::FetchAll(s)) = &dialog.page else {
        return Vec::new();
    };
    let mut unlisted: Vec<(String, String)> = Vec::new();
    for summary in &s.finished {
        if let Ok(FetchOutcome::Models { models: remote, .. }) = &summary.outcome
            && let Some(existing) = s.pre_fetch_models.get(&summary.provider_id)
        {
            for model_id in compute_unlisted_for_models(existing, remote) {
                unlisted.push((summary.provider_id.clone(), model_id));
            }
        }
    }
    unlisted
}

fn compute_unlisted_for_models(existing: &[ModelEntry], remote: &[ModelEntry]) -> Vec<String> {
    existing
        .iter()
        .filter(|m| !m.manual)
        .filter(|m| !remote.iter().any(|r| r.id == m.id))
        .map(|m| m.id.clone())
        .collect()
}

/// Build the `ProvidersPage` for `/model-settings`: the active model's
/// model-settings sub-dialog (implementation note). Falls
/// back to the providers list with an inline status when no model is active
/// or the active (provider, model) can't be resolved in config.
pub(super) fn active_model_settings_page(
    config: &crate::config::providers::ProvidersConfig,
) -> ProvidersPage {
    let no_model = |msg: &str| ProvidersPage::List {
        cursor: initial_list_cursor(config),
        status: Some(msg.to_string()),
        delete_pending: false,
    };
    let Some(active) = config.active_model.as_ref() else {
        return no_model("no model selected — pick one with `/model` first");
    };
    let Some(entry) = config.providers.get(&active.provider) else {
        return no_model(&format!(
            "active provider `{}` not found in config",
            active.provider
        ));
    };
    if !entry.models.iter().any(|m| m.id == active.model) {
        return no_model(&format!(
            "active model `{}/{}` not found in config",
            active.provider, active.model
        ));
    }
    let settings = SettingsEditor::for_model(&active.provider, entry, &active.model);
    let models = Box::new(ModelEditor::new(
        entry
            .effective_template(&active.provider)
            .map(str::to_owned),
        entry.models.clone(),
    ));
    let parent = EditState::new(active.provider.clone(), entry.clone());
    ProvidersPage::ModelSettings {
        editor: settings,
        models,
        parent: Box::new(parent),
    }
}

pub(super) fn valid_url(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("http://") || s.starts_with("https://")
}

/// Execute the "Set up Copilot auth" action: append the export to the
/// shell rc file and inject `GH_TOKEN` into the running process so the
/// resolver picks it up without a restart. Returns a user-facing
/// status string on success, or an error message on failure.
fn apply_copilot_setup(shell: CopilotShell, rc_path: &std::path::Path) -> Result<String, String> {
    // Fetch the token first — if `gh` isn't installed or the user
    // isn't logged in, we want to fail before mutating the rc file.
    let token = copilot_setup::fetch_gh_token().map_err(|e| e.to_string())?;
    let wrote = copilot_setup::append_to_rc(rc_path, shell).map_err(|e| e.to_string())?;

    // SAFETY: `set_var` mutates process-global env state. The settings
    // dialog runs on the main thread before any inference request fires
    // for this session, so no concurrent reader observes the racy state.
    unsafe {
        std::env::set_var("GH_TOKEN", &token);
    }

    let suffix = if wrote {
        format!("added export to {}", rc_path.display())
    } else {
        format!("export already in {}", rc_path.display())
    };
    Ok(format!(
        "Copilot auth ready — {suffix}; GH_TOKEN set for this session"
    ))
}

/// Provider ids are config-map keys. Restrict to a conservative
/// shell/filename-safe set so they're easy to reference from the CLI.
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::ProvidersConfig;
    use crate::config::providers::{ConfigDoc, ProviderEntry};
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use std::collections::BTreeMap;

    fn provider_with_models(models: Vec<ModelEntry>) -> ProviderEntry {
        ProviderEntry {
            url: "https://api.example.com/v1".to_string(),
            models,
            ..Default::default()
        }
    }

    fn model(id: &str, manual: bool) -> ModelEntry {
        ModelEntry {
            id: id.to_string(),
            manual,
            ..Default::default()
        }
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn dialog_with_config(config: ProvidersConfig) -> (tempfile::TempDir, SettingsDialog) {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        let mut doc = ConfigDoc::load(&path).unwrap();
        doc.write(&config).unwrap();
        let dialog = SettingsDialog::open(path);
        (tmp, dialog)
    }

    fn break_config_saving(dialog: &SettingsDialog) {
        if let Some(parent) = dialog.config_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&dialog.config_path, "[").unwrap();
    }

    fn load_provider(path: &std::path::Path, id: &str) -> ProviderEntry {
        ConfigDoc::load(path).unwrap().providers().providers[id].clone()
    }

    fn one_provider_config(policy: Option<OnUnlistedModelsFetch>) -> ProvidersConfig {
        let mut providers = BTreeMap::new();
        providers.insert(
            "p".to_string(),
            provider_with_models(vec![model("stale", false), model("current", false)]),
        );
        ProvidersConfig {
            providers,
            on_unlisted_models_fetch: policy,
            ..Default::default()
        }
    }

    fn line_text(line: &Line<'static>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    fn rendered_text(lines: &[Line<'static>]) -> String {
        lines.iter().map(line_text).collect::<Vec<_>>().join("\n")
    }

    fn option_row_count(rendered: &str) -> usize {
        rendered.lines().filter(|line| line.contains('[')).count()
    }

    #[test]
    fn single_fetch_error_is_redacted_in_status_and_saved_state() {
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            provider_with_models(vec![model("existing", true)]),
        );
        let (_tmp, mut dialog) = dialog_with_config(cfg);
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        let secret = "sk-proj-abcdefghijklmnopqrstuvwxyz123456";
        dialog.apply_fetch_result(
            "p",
            Err(format!("fetch failed with Authorization: Bearer {secret}")),
        );

        let status = match &dialog.page {
            Page::Providers(ProvidersPage::Edit(s)) => s.status.as_deref().unwrap_or(""),
            other => panic!("expected Edit page, got {other:?}"),
        };
        assert!(!status.contains(secret), "status leaked secret: {status}");
        let reason = dialog.config.providers["p"]
            .last_model_fetch
            .as_ref()
            .and_then(|status| status.reason.as_deref())
            .unwrap_or("");
        assert!(
            !reason.contains(secret),
            "saved reason leaked secret: {reason}"
        );
    }

    #[test]
    fn grok_oauth_template_materializes_oauth_credential_ref() {
        let template = templates::template_by_id("grok-oauth").unwrap();
        let mut state = AddState::new();
        state.id_field.set("grok-oauth");
        state.url_field.set(template.url);

        let entry = provider_entry_from_add(&state, template, Vec::new());

        assert_eq!(entry.auth, Some(AuthKind::OAuth));
        assert_eq!(
            entry.credential_ref.as_deref(),
            Some(crate::auth::xai_oauth::CREDENTIAL_KEY)
        );
        assert!(entry.headers.is_empty());
        assert_eq!(entry.wire_api, WireApi::Responses);
    }

    #[test]
    fn codex_oauth_template_materializes_oauth_credential_ref() {
        let template = templates::template_by_id("codex-oauth").unwrap();
        let mut state = AddState::new();
        state.id_field.set("codex-oauth");
        state.url_field.set(template.url);

        let entry = provider_entry_from_add(&state, template, Vec::new());

        assert_eq!(entry.auth, Some(AuthKind::OAuth));
        assert_eq!(
            entry.credential_ref.as_deref(),
            Some(crate::auth::codex_oauth::CREDENTIAL_KEY)
        );
        assert!(entry.headers.is_empty());
        assert_eq!(entry.wire_api, WireApi::Responses);
    }

    #[test]
    fn header_display_masks_literal_authorization_secret() {
        let shown = display_header_value("Authorization", "Bearer sk-abcdef123456");
        assert_eq!(shown, "Bearer ...3456");
        assert!(!shown.contains("sk-abcdef123456"));
    }

    #[test]
    fn header_display_keeps_env_only_authorization_visible() {
        assert_eq!(
            display_header_value("Authorization", "Bearer $OPENAI_API_KEY"),
            "Bearer $OPENAI_API_KEY"
        );
    }

    #[test]
    fn header_display_masks_mixed_env_and_literal_material() {
        let shown = display_header_value("Authorization", "Bearer $OPENAI_API_KEY literal123456");
        assert_eq!(shown, "Bearer ...3456");
        assert!(!shown.contains("$OPENAI_API_KEY"));
        assert!(!shown.contains("literal123456"));
    }

    #[test]
    fn header_display_masks_short_sensitive_header_literals() {
        let shown = display_header_value("X-API-Key", "short");
        assert_eq!(shown, "...hort");
    }

    #[test]
    fn header_display_masks_common_sensitive_header_names() {
        let shown = display_header_value("OpenAI-Organization", "org-abcdef123456");
        assert_eq!(shown, "...3456");
        assert!(!shown.contains("org-abcdef123456"));
    }

    #[test]
    fn header_editor_list_masks_values_but_keeps_env_refs_visible() {
        let editor = HeaderEditor::new(
            vec![
                HeaderSpec {
                    name: "Authorization".to_string(),
                    value: "Bearer sk-abcdef123456".to_string(),
                },
                HeaderSpec {
                    name: "Authorization".to_string(),
                    value: "Bearer $OPENAI_API_KEY".to_string(),
                },
            ],
            false,
        );
        let mut lines = Vec::new();
        render_header_editor(&mut lines, &editor);
        let rendered = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");

        assert!(rendered.contains("Bearer ...3456"), "{rendered}");
        assert!(!rendered.contains("sk-abcdef123456"), "{rendered}");
        assert!(rendered.contains("Bearer $OPENAI_API_KEY"), "{rendered}");
    }

    #[test]
    fn header_delete_requires_second_press_on_same_row() {
        let mut editor = HeaderEditor::new(
            vec![
                HeaderSpec {
                    name: "X-One".to_string(),
                    value: "1".to_string(),
                },
                HeaderSpec {
                    name: "X-Two".to_string(),
                    value: "2".to_string(),
                },
            ],
            false,
        );

        assert!(matches!(
            editor.handle_key(press(KeyCode::Char('d'))),
            HeaderResult::Stay
        ));
        assert_eq!(editor.rows().len(), 2, "first press only arms");
        assert!(editor.delete.is_pending_for(0));
        assert!(editor.status.as_deref().unwrap_or("").contains("X-One"));

        editor.handle_key(press(KeyCode::Down));
        assert!(!editor.delete.is_pending_for(0), "navigation disarms");
        editor.handle_key(press(KeyCode::Char('d')));
        assert_eq!(editor.rows().len(), 2, "fresh first press on row 1 arms");
        assert!(editor.delete.is_pending_for(1));

        editor.handle_key(press(KeyCode::Char('d')));
        assert_eq!(editor.rows().len(), 1, "second press deletes row 1");
        assert_eq!(editor.rows()[0].name, "X-One");
    }

    /// A Copilot-shaped provider (detected by URL) gets the "Copilot auth"
    /// row in its Edit menu; a generic provider does not. The action list
    /// is the single source of truth render and key handling share, so
    /// asserting on it covers both.
    #[test]
    fn edit_menu_copilot_auth_row_only_for_copilot_providers() {
        let copilot = ProviderEntry {
            url: "https://api.githubcopilot.com".to_string(),
            ..Default::default()
        };
        let actions = edit_menu_actions("my-copilot", &copilot);
        assert!(
            actions.contains(&EditAction::CopilotAuth),
            "Copilot-shaped provider must expose the Copilot-auth row"
        );

        let generic = ProviderEntry {
            url: "https://api.example.com/v1".to_string(),
            ..Default::default()
        };
        let generic_actions = edit_menu_actions("openai-compatible", &generic);
        assert!(
            !generic_actions.contains(&EditAction::CopilotAuth),
            "generic provider must not expose the Copilot-auth row"
        );
        // The conditional row is the only difference in menu length.
        assert_eq!(actions.len(), generic_actions.len() + 1);
    }

    #[test]
    fn provider_settings_summary_surfaces_timeout_values() {
        let provider = ProviderEntry {
            url: "https://api.example.com/v1".to_string(),
            timeout: crate::config::providers::TimeoutConfig {
                ttft_secs: 240,
                idle_secs: 180,
            },
            backup: Some(crate::config::providers::BackupConfig {
                provider: "backup".to_string(),
                model: "model".to_string(),
            }),
            ..Default::default()
        };

        let summary = provider_settings_summary(&provider);

        assert!(summary.contains("ttft 240s"));
        assert!(summary.contains("idle 180s"));
        assert!(summary.contains("backup set"));
    }

    #[test]
    fn model_editor_enter_hints_match_selected_row_actions() {
        let mut editor =
            ModelEditor::new(None, vec![model("fetched", false), model("manual", true)]);

        editor.cursor = 0;
        assert_eq!(editor.selected_enter_hint(), "enter: read-only settings");

        editor.cursor = 1;
        assert_eq!(editor.selected_enter_hint(), "enter: settings");

        editor.cursor = editor.add_row_idx();
        assert_eq!(editor.selected_enter_hint(), "enter: add model");

        editor.cursor = editor.save_idx();
        assert_eq!(editor.selected_enter_hint(), "enter: save changes");
    }

    #[test]
    fn enter_on_fetched_and_manual_model_rows_opens_settings() {
        let mut editor =
            ModelEditor::new(None, vec![model("fetched", false), model("manual", true)]);

        editor.cursor = 0;
        assert!(matches!(
            editor.handle_key(press(KeyCode::Enter)),
            ModelResult::OpenSettings(0)
        ));

        editor.cursor = 1;
        assert!(matches!(
            editor.handle_key(press(KeyCode::Enter)),
            ModelResult::OpenSettings(1)
        ));
    }

    #[test]
    fn enter_on_model_action_rows_matches_hints() {
        let mut editor = ModelEditor::new(None, vec![model("manual", true)]);

        editor.cursor = editor.add_row_idx();
        assert_eq!(editor.selected_enter_hint(), "enter: add model");
        assert!(matches!(
            editor.handle_key(press(KeyCode::Enter)),
            ModelResult::Stay
        ));
        assert!(editor.is_editing());

        editor.cancel_edit();
        editor.cursor = editor.save_idx();
        assert_eq!(editor.selected_enter_hint(), "enter: save changes");
        assert!(matches!(
            editor.handle_key(press(KeyCode::Enter)),
            ModelResult::Save
        ));
    }

    #[test]
    fn model_delete_requires_second_press_on_same_row() {
        let mut editor =
            ModelEditor::new(None, vec![model("fetched", false), model("manual", true)]);

        editor.handle_key(press(KeyCode::Delete));
        assert_eq!(editor.rows().len(), 2, "first press only arms");
        assert!(editor.delete.is_pending_for(0));
        assert!(editor.status.as_deref().unwrap_or("").contains("fetched"));

        editor.handle_key(press(KeyCode::Down));
        assert!(!editor.delete.is_pending_for(0), "navigation disarms");
        editor.handle_key(press(KeyCode::Delete));
        assert_eq!(editor.rows().len(), 2, "fresh first press on row 1 arms");
        assert!(editor.delete.is_pending_for(1));

        editor.handle_key(press(KeyCode::Delete));
        assert_eq!(editor.rows().len(), 1, "second press deletes row 1");
        assert_eq!(editor.rows()[0].id, "fetched");
    }

    #[test]
    fn fetch_all_prompt_remove_drops_only_non_manual_unlisted_models() {
        let mut providers = BTreeMap::new();
        providers.insert(
            "p".to_string(),
            provider_with_models(vec![
                model("stale", false),
                model("manual-only", true),
                model("current", false),
            ]),
        );
        let (_, mut dialog) = dialog_with_config(ProvidersConfig {
            providers,
            on_unlisted_models_fetch: Some(OnUnlistedModelsFetch::Ask),
            ..Default::default()
        });
        dialog.page = Page::Providers(ProvidersPage::FetchAll(FetchAllState {
            providers: vec!["p".to_string()],
            in_flight: Vec::new(),
            finished: vec![FetchedSummary {
                provider_id: "p".to_string(),
                outcome: Ok(FetchOutcome::Models {
                    models: vec![model("current", false)],
                    catalog: ProviderModelCatalog::Live,
                }),
            }],
            pre_fetch_models: [(
                "p".to_string(),
                vec![
                    model("stale", false),
                    model("manual-only", true),
                    model("current", false),
                ],
            )]
            .into_iter()
            .collect(),
            policy_resolved: false,
            cursor: 1,
            dont_ask_again: false,
            unlisted: vec![("p".to_string(), "stale".to_string())],
        }));

        let mut page = std::mem::replace(&mut dialog.page, Page::Root { cursor: 0 });
        if let Page::Providers(ProvidersPage::FetchAll(state)) = &mut page {
            let nav = dialog.handle_fetch_all_key(press(KeyCode::Enter), state);
            assert!(matches!(
                nav,
                Nav::Replace(Page::Providers(ProvidersPage::List { .. }))
            ));
        } else {
            panic!("expected fetch-all page");
        }

        let ids: Vec<&str> = dialog.config.providers["p"]
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(ids, vec!["current", "manual-only"]);
    }

    #[test]
    fn fetch_all_stored_remove_applies_without_prompt() {
        let (_, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Remove)));
        dialog.page = Page::Providers(ProvidersPage::FetchAll(FetchAllState {
            providers: vec!["p".to_string()],
            in_flight: Vec::new(),
            finished: vec![FetchedSummary {
                provider_id: "p".to_string(),
                outcome: Ok(FetchOutcome::Models {
                    models: vec![model("current", false)],
                    catalog: ProviderModelCatalog::Live,
                }),
            }],
            pre_fetch_models: [(
                "p".to_string(),
                vec![model("stale", false), model("current", false)],
            )]
            .into_iter()
            .collect(),
            policy_resolved: false,
            cursor: 0,
            dont_ask_again: false,
            unlisted: Vec::new(),
        }));

        dialog.drain_fetch_all();

        let state = match &dialog.page {
            Page::Providers(ProvidersPage::FetchAll(s)) => s,
            _ => panic!("expected fetch-all page"),
        };
        assert!(state.unlisted.is_empty());
        let ids: Vec<&str> = dialog.config.providers["p"]
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(ids, vec!["current"]);
    }

    #[test]
    fn fetch_all_stored_keep_applies_without_prompt() {
        let (_, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
        dialog.page = Page::Providers(ProvidersPage::FetchAll(FetchAllState {
            providers: vec!["p".to_string()],
            in_flight: Vec::new(),
            finished: vec![FetchedSummary {
                provider_id: "p".to_string(),
                outcome: Ok(FetchOutcome::Models {
                    models: vec![model("current", false)],
                    catalog: ProviderModelCatalog::Live,
                }),
            }],
            pre_fetch_models: [(
                "p".to_string(),
                vec![model("stale", false), model("current", false)],
            )]
            .into_iter()
            .collect(),
            policy_resolved: false,
            cursor: 0,
            dont_ask_again: false,
            unlisted: Vec::new(),
        }));

        dialog.drain_fetch_all();

        let ids: Vec<&str> = dialog.config.providers["p"]
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(ids, vec!["current", "stale"]);
    }

    #[test]
    fn per_provider_refetch_prompt_remove_returns_to_edit_page() {
        let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        dialog.page = Page::Providers(ProvidersPage::FetchOnePrompt(FetchOnePromptState {
            provider_id: "p".to_string(),
            remote: vec![model("current", false)],
            catalog: ProviderModelCatalog::Live,
            pre_fetch_models: vec![model("stale", false), model("current", false)],
            unlisted: vec!["stale".to_string()],
            cursor: 1,
            dont_ask_again: false,
        }));

        let mut page = std::mem::replace(&mut dialog.page, Page::Root { cursor: 0 });
        if let Page::Providers(ProvidersPage::FetchOnePrompt(state)) = &mut page {
            let nav = dialog.handle_fetch_one_prompt_key(press(KeyCode::Enter), state);
            assert!(matches!(
                nav,
                Nav::Replace(Page::Providers(ProvidersPage::Edit(_)))
            ));
        } else {
            panic!("expected per-provider prompt page");
        }

        let ids: Vec<&str> = dialog.config.providers["p"]
            .models
            .iter()
            .map(|m| m.id.as_str())
            .collect();
        assert_eq!(ids, vec!["current"]);
    }

    #[test]
    fn fetch_one_prompt_save_failure_surfaces() {
        let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        dialog.page = Page::Providers(ProvidersPage::FetchOnePrompt(FetchOnePromptState {
            provider_id: "p".to_string(),
            remote: vec![model("current", false)],
            catalog: ProviderModelCatalog::Live,
            pre_fetch_models: vec![model("stale", false), model("current", false)],
            unlisted: vec!["stale".to_string()],
            cursor: 0,
            dont_ask_again: false,
        }));
        break_config_saving(&dialog);

        let mut page = std::mem::replace(&mut dialog.page, Page::Root { cursor: 0 });
        let nav = if let Page::Providers(ProvidersPage::FetchOnePrompt(state)) = &mut page {
            dialog.handle_fetch_one_prompt_key(press(KeyCode::Enter), state)
        } else {
            panic!("expected per-provider prompt page");
        };

        match nav {
            Nav::Replace(Page::Providers(ProvidersPage::Edit(edit))) => {
                assert!(
                    edit.status
                        .as_deref()
                        .is_some_and(|s| s.starts_with("save failed:")),
                    "status was {:?}",
                    edit.status
                );
            }
            _ => panic!("expected edit replacement"),
        }
    }

    #[test]
    fn fetch_all_save_failure_surfaces() {
        let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        dialog.page = Page::Providers(ProvidersPage::FetchAll(FetchAllState {
            providers: vec!["p".to_string()],
            in_flight: Vec::new(),
            finished: vec![FetchedSummary {
                provider_id: "p".to_string(),
                outcome: Ok(FetchOutcome::Models {
                    models: vec![model("current", false)],
                    catalog: ProviderModelCatalog::Live,
                }),
            }],
            pre_fetch_models: [(
                "p".to_string(),
                vec![model("stale", false), model("current", false)],
            )]
            .into_iter()
            .collect(),
            policy_resolved: false,
            cursor: 0,
            dont_ask_again: false,
            unlisted: vec![("p".to_string(), "stale".to_string())],
        }));
        break_config_saving(&dialog);

        let mut page = std::mem::replace(&mut dialog.page, Page::Root { cursor: 0 });
        let nav = if let Page::Providers(ProvidersPage::FetchAll(state)) = &mut page {
            dialog.handle_fetch_all_key(press(KeyCode::Enter), state)
        } else {
            panic!("expected fetch-all page");
        };

        match nav {
            Nav::Replace(Page::Providers(ProvidersPage::List { status, .. })) => {
                assert!(
                    status
                        .as_deref()
                        .is_some_and(|s| s.starts_with("save failed:")),
                    "status was {status:?}"
                );
            }
            _ => panic!("expected list replacement"),
        }
    }

    #[test]
    fn render_field_row_places_caret_at_textfield_cursor() {
        let mut field = TextField::new("alpha");
        field.handle_key(press(KeyCode::Home));
        field.handle_key(press(KeyCode::Right));
        field.handle_key(press(KeyCode::Right));
        let mut lines = Vec::new();

        render_field_row(&mut lines, "Name", &field, true);

        assert_eq!(line_text(&lines[0]), "▸ Name: al\u{E000}pha");
    }

    #[test]
    fn edit_delete_enter_requires_second_enter_to_confirm() {
        let (_, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        let mut state = EditState::new("p".into(), entry.clone());
        state.cursor = edit_menu_actions("p", &entry)
            .iter()
            .position(|action| matches!(action, EditAction::Delete))
            .expect("delete row");
        dialog.page = Page::Providers(ProvidersPage::Edit(state));

        dialog.handle_providers_key(press(KeyCode::Enter));
        assert!(dialog.config.providers.contains_key("p"));
        let Page::Providers(ProvidersPage::Edit(state)) = &dialog.page else {
            panic!("expected edit page");
        };
        assert!(state.delete_pending);
        assert_eq!(
            state.status.as_deref(),
            Some("press Enter again to confirm delete")
        );

        dialog.handle_providers_key(press(KeyCode::Enter));

        assert!(!dialog.config.providers.contains_key("p"));
        assert!(matches!(
            dialog.page,
            Page::Providers(ProvidersPage::List { .. })
        ));
    }

    #[test]
    fn edit_delete_d_requires_second_d_to_confirm() {
        let (_, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        dialog.handle_providers_key(press(KeyCode::Char('d')));
        assert!(dialog.config.providers.contains_key("p"));
        let Page::Providers(ProvidersPage::Edit(state)) = &dialog.page else {
            panic!("expected edit page");
        };
        assert!(state.delete_pending);
        assert_eq!(
            state.status.as_deref(),
            Some("press d again to confirm delete")
        );

        dialog.handle_providers_key(press(KeyCode::Char('d')));

        assert!(!dialog.config.providers.contains_key("p"));
        assert!(matches!(
            dialog.page,
            Page::Providers(ProvidersPage::List { .. })
        ));
    }

    #[test]
    fn favorite_toggle_status_is_unsaved() {
        let (_, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        dialog.handle_providers_key(press(KeyCode::Char('f')));
        let Page::Providers(ProvidersPage::Edit(state)) = &dialog.page else {
            panic!("expected edit page");
        };
        assert_eq!(
            state.status.as_deref(),
            Some("favorite ✓ (unsaved — s to save)")
        );
        assert_eq!(state.entry.favorite, Some(true));
    }

    #[test]
    fn q_commits_favorite_from_edit_page() {
        let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        dialog.handle_providers_key(press(KeyCode::Char('f')));
        assert!(dialog.handle_providers_key(press(KeyCode::Char('q'))));

        assert_eq!(
            load_provider(&tmp.path().join("config.json"), "p").favorite,
            Some(true)
        );
    }

    #[test]
    fn q_commit_failure_after_favorite_does_not_panic() {
        let (_tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));
        dialog.handle_providers_key(press(KeyCode::Char('f')));
        break_config_saving(&dialog);

        assert!(dialog.handle_providers_key(press(KeyCode::Char('q'))));
    }

    #[test]
    fn q_commits_headers_subpage() {
        let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        let parent = EditState::new("p".into(), entry);
        let editor = HeaderEditor::new(
            vec![HeaderSpec {
                name: "X-Test".into(),
                value: "one".into(),
            }],
            false,
        );
        dialog.page = Page::Providers(ProvidersPage::Headers {
            editor,
            parent: Box::new(parent),
        });

        assert!(dialog.handle_providers_key(press(KeyCode::Char('q'))));

        assert_eq!(
            load_provider(&tmp.path().join("config.json"), "p").headers,
            vec![HeaderSpec {
                name: "X-Test".into(),
                value: "one".into(),
            }]
        );
    }

    #[tokio::test]
    async fn refetch_commits_staged_entry_first() {
        let (tmp, mut dialog) = dialog_with_config(one_provider_config(None));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        dialog.handle_providers_key(press(KeyCode::Char('f')));
        dialog.handle_providers_key(press(KeyCode::Char('r')));

        assert_eq!(
            load_provider(&tmp.path().join("config.json"), "p").favorite,
            Some(true)
        );
    }

    #[test]
    fn refetch_result_preserves_staged_favorite() {
        let (_tmp, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
        let entry = dialog.config.providers["p"].clone();
        let mut edit = EditState::new("p".into(), entry);
        edit.entry.favorite = Some(true);
        dialog.page = Page::Providers(ProvidersPage::Edit(edit));

        dialog.apply_fetch_result(
            "p",
            Ok(FetchOutcome::Models {
                models: vec![model("new", false)],
                catalog: ProviderModelCatalog::Live,
            }),
        );

        let Page::Providers(ProvidersPage::Edit(state)) = &dialog.page else {
            panic!("expected edit page");
        };
        assert_eq!(state.entry.favorite, Some(true));
        assert_eq!(
            state
                .entry
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["new", "stale", "current"]
        );
    }

    #[test]
    fn refetch_result_marks_codex_fallback_catalog_active() {
        let (_tmp, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        dialog.apply_fetch_result(
            "p",
            Ok(FetchOutcome::Models {
                models: vec![model("gpt-5.5", false)],
                catalog: ProviderModelCatalog::CodexFallback,
            }),
        );

        let provider = &dialog.config.providers["p"];
        assert_eq!(provider.model_catalog, ProviderModelCatalog::CodexFallback);
        let Page::Providers(ProvidersPage::Edit(state)) = &dialog.page else {
            panic!("expected edit page");
        };
        assert_eq!(
            state.entry.model_catalog,
            ProviderModelCatalog::CodexFallback
        );
        assert!(
            state
                .status
                .as_deref()
                .is_some_and(|s| s.contains("fallback Codex catalog"))
        );
    }

    #[test]
    fn refetch_result_with_fallback_available_opens_explicit_prompt() {
        let (_tmp, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));

        dialog.apply_fetch_result(
            "p",
            Ok(FetchOutcome::FallbackAvailable {
                models: vec![model("fallback", false)],
                catalog: ProviderModelCatalog::CodexFallback,
                reason:
                    "GET /models returned 500. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                        .into(),
            }),
        );

        let Page::Providers(ProvidersPage::FetchFallbackPrompt(state)) = &dialog.page else {
            panic!("expected fallback prompt");
        };
        assert_eq!(state.provider_id, "p");
        assert!(state.reason.contains("returned 500"));
        assert!(state.reason.contains("[redacted]"));
        assert!(!state.reason.contains("sk-test-token"));
        let provider = &dialog.config.providers["p"];
        assert_eq!(provider.model_catalog, ProviderModelCatalog::Live);
        assert_eq!(
            provider
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["stale", "current"]
        );
    }

    #[test]
    fn fetch_fallback_prompt_use_fallback_records_degraded_status() {
        let (_tmp, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
        dialog.page = Page::Providers(ProvidersPage::FetchFallbackPrompt(
            FetchFallbackPromptState {
                provider_id: "p".to_string(),
                models: vec![model("fallback", false)],
                catalog: ProviderModelCatalog::CodexFallback,
                reason:
                    "GET /models returned 500. Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                        .into(),
                cursor: 2,
            },
        ));

        let mut page = std::mem::replace(&mut dialog.page, Page::Root { cursor: 0 });
        let nav = if let Page::Providers(ProvidersPage::FetchFallbackPrompt(state)) = &mut page {
            dialog.handle_fetch_fallback_prompt_key(press(KeyCode::Enter), state)
        } else {
            panic!("expected fallback prompt");
        };

        assert!(matches!(
            nav,
            Nav::Replace(Page::Providers(ProvidersPage::Edit(_)))
        ));
        let provider = &dialog.config.providers["p"];
        assert_eq!(provider.model_catalog, ProviderModelCatalog::CodexFallback);
        assert_eq!(
            provider
                .models
                .iter()
                .map(|m| m.id.as_str())
                .collect::<Vec<_>>(),
            vec!["fallback", "stale", "current"]
        );
        let status = provider.last_model_fetch.as_ref().unwrap();
        assert_eq!(
            status.status,
            crate::config::providers::ModelFetchStatusKind::Fallback
        );
        assert_eq!(
            status.source,
            crate::config::providers::ModelFetchSource::Fallback
        );
        let reason = status.reason.as_ref().unwrap();
        assert!(reason.contains("returned 500"));
        assert!(reason.contains("[redacted]"));
        assert!(!reason.contains("sk-test-token"));
    }

    #[test]
    fn refetch_summary_names_empty_codex_fallback_catalog() {
        let mut entry = ProviderEntry {
            models: vec![
                model("gpt-5.5", false),
                model("gpt-5.4", false),
                model("gpt-5.4-mini", false),
            ],
            model_catalog: ProviderModelCatalog::CodexFallback,
            ..ProviderEntry::default()
        };
        entry.mark_model_fetch_fallback(
            "https://chatgpt.com/backend-api/codex/models?client_version=0.0.0 returned an empty model list (status 200 OK)",
        );

        let summary = refetch_summary(&entry);

        assert!(summary.contains("fallback catalog active (3 model(s))"));
        assert!(summary.contains("live /models returned empty list"));
        assert!(summary.contains("using hardcoded fallback"));
    }

    #[test]
    fn model_fetch_status_block_renders_redacted_status_details() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entry = ProviderEntry {
            models: vec![model("gpt-5-mini", false)],
            models_fetched_at: Some(
                chrono::DateTime::parse_from_rfc3339("2026-06-19T11:00:00Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            last_model_fetch: Some(crate::config::providers::ModelFetchStatus {
                status: crate::config::providers::ModelFetchStatusKind::FailedKeptExisting,
                at: now,
                source: crate::config::providers::ModelFetchSource::Live,
                reason: Some(
                    "GET /models returned 500 Authorization Bearer sk-test-token-abcdefghijklmnopqrstuvwxyz123456"
                        .to_string(),
                ),
            }),
            ..ProviderEntry::default()
        };
        let mut lines = Vec::new();

        render_model_fetch_status_block(&mut lines, &entry, now);
        let rendered = rendered_text(&lines);

        assert!(rendered.contains("Catalog status:"));
        assert!(rendered.contains("state:   Preserved"));
        assert!(rendered.contains("count:   1"));
        assert!(rendered.contains("fetched: 1 hour ago"));
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("sk-test-token"));
    }

    #[test]
    fn model_fetch_status_block_uses_never_and_dash_for_missing_fetch() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-06-19T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let entry = ProviderEntry::default();
        let mut lines = Vec::new();

        render_model_fetch_status_block(&mut lines, &entry, now);
        let rendered = rendered_text(&lines);

        assert!(rendered.contains("state:   Live"));
        assert!(rendered.contains("count:   0"));
        assert!(rendered.contains("fetched: never"));
        assert!(rendered.contains("reason:  —"));
    }

    #[test]
    fn apply_fetch_result_save_failure_surfaces() {
        let (_tmp, mut dialog) =
            dialog_with_config(one_provider_config(Some(OnUnlistedModelsFetch::Keep)));
        let entry = dialog.config.providers["p"].clone();
        dialog.page = Page::Providers(ProvidersPage::Edit(EditState::new("p".into(), entry)));
        break_config_saving(&dialog);

        dialog.apply_fetch_result(
            "p",
            Ok(FetchOutcome::Models {
                models: vec![model("new", false)],
                catalog: ProviderModelCatalog::Live,
            }),
        );

        let Page::Providers(ProvidersPage::Edit(state)) = &dialog.page else {
            panic!("expected edit page");
        };
        assert!(
            state
                .status
                .as_deref()
                .is_some_and(|s| s.starts_with("save failed:")),
            "status was {:?}",
            state.status
        );
    }

    #[test]
    fn grok_login_selection_is_ssh_aware() {
        assert_eq!(grok_login_selection(true), GrokLoginSelection::ManualOnly);
        assert_eq!(grok_login_selection(false), GrokLoginSelection::Auto);
    }

    #[test]
    fn copy_oauth_url_reports_success_error_and_missing_url() {
        let mut status = None;
        let copied = crate::clipboard::CopyOutcome {
            osc52_written: true,
            local_clipboard_written: false,
        };
        copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
            Ok(copied)
        });
        assert_eq!(status, Some(Ok("copied OAuth URL".to_string())));

        copy_oauth_url_with(None, &mut status, |_| Ok(copied));
        assert_eq!(status, Some(Ok("no OAuth URL yet".to_string())));

        copy_oauth_url_with(Some("https://example.test/oauth"), &mut status, |_| {
            Err(crate::clipboard::CopyError::Backend("denied".to_string()))
        });
        assert_eq!(
            status,
            Some(Err("clipboard backend error: denied".to_string()))
        );
    }

    #[test]
    fn add_grok_oauth_manual_mode_reports_active_text_field() {
        let mut state = AddState::new();
        state.step = AddStep::GrokOAuthAuth(Box::new(GrokOAuthSetupState::new()));
        let mut page = ProvidersPage::Add(state);

        assert!(page.active_text_field().is_none());

        let ProvidersPage::Add(add) = &mut page else {
            unreachable!();
        };
        let AddStep::GrokOAuthAuth(grok) = &mut add.step else {
            unreachable!();
        };
        grok.manual_mode = true;

        let field = page
            .active_text_field()
            .expect("manual Grok OAuth input should own paste focus");
        field.paste("callback-code");

        let ProvidersPage::Add(add) = &page else {
            unreachable!();
        };
        let AddStep::GrokOAuthAuth(grok) = &add.step else {
            unreachable!();
        };
        assert_eq!(grok.manual_input.text(), "callback-code");
    }

    #[test]
    fn grok_manual_mode_char_c_inserts_instead_of_copying_url() {
        let mut state = GrokOAuthSetupState::new();
        state.manual_mode = true;
        state.authorize_url = Some("https://example.test/oauth".to_string());

        let (_close, action) = handle_grok_oauth_setup_key(press(KeyCode::Char('c')), &mut state);

        assert!(action.is_none());
        assert_eq!(state.manual_input.text(), "c");
        assert_ne!(state.status, Some(Ok("copied OAuth URL".to_string())));
    }

    #[test]
    fn grok_manual_mode_char_by_char_callback_keeps_shortcut_letters() {
        let mut state = GrokOAuthSetupState::new();
        state.manual_mode = true;
        let callback = "http://127.0.0.1:56121/callback?code=abc123&state=s";

        for ch in callback.chars() {
            handle_grok_oauth_setup_key(press(KeyCode::Char(ch)), &mut state);
        }

        assert_eq!(state.manual_input.text(), callback);
    }

    #[test]
    fn codex_oauth_logged_in_renders_single_continue_row() {
        let mut state = CodexOAuthSetupState::new();
        state.logged_in = true;
        state.status = Some(Ok("Codex OAuth login complete".to_string()));
        let mut lines = Vec::new();

        render_codex_oauth_setup_body(&mut lines, &state);
        let rendered = rendered_text(&lines);

        assert!(rendered.contains("continue"), "{rendered}");
        assert_eq!(option_row_count(&rendered), 1, "{rendered}");
        assert!(!rendered.contains("log in"), "{rendered}");
        assert!(!rendered.contains("skip / continue"), "{rendered}");
        assert!(!rendered.contains("manual paste"), "{rendered}");
    }

    #[test]
    fn codex_oauth_logged_out_renders_start_or_poll_menu() {
        let mut state = CodexOAuthSetupState::new();
        state.logged_in = false;
        let mut lines = Vec::new();

        render_codex_oauth_setup_body(&mut lines, &state);
        let rendered = rendered_text(&lines);
        assert!(rendered.contains("log in"), "{rendered}");
        assert!(rendered.contains("skip / continue"), "{rendered}");

        state.pending = Some(crate::auth::codex_oauth::DeviceLogin::for_test(
            "https://example.test/device",
            "ABCD-EFGH",
        ));
        lines.clear();
        render_codex_oauth_setup_body(&mut lines, &state);
        let rendered = rendered_text(&lines);
        assert!(rendered.contains("poll for approval"), "{rendered}");
        assert!(rendered.contains("skip / continue"), "{rendered}");
        assert!(!rendered.contains("[continue]"), "{rendered}");
    }

    #[test]
    fn grok_oauth_logged_in_renders_single_continue_row() {
        let mut state = GrokOAuthSetupState::new();
        state.logged_in = true;
        state.status = Some(Ok("xAI OAuth login complete".to_string()));
        let mut lines = Vec::new();

        render_grok_oauth_setup_body(&mut lines, &state);
        let rendered = rendered_text(&lines);

        assert!(rendered.contains("continue"), "{rendered}");
        assert_eq!(option_row_count(&rendered), 1, "{rendered}");
        assert!(!rendered.contains("log in"), "{rendered}");
        assert!(!rendered.contains("manual paste"), "{rendered}");
        assert!(!rendered.contains("skip / continue"), "{rendered}");
    }

    #[test]
    fn grok_oauth_logged_out_renders_full_menu() {
        let mut state = GrokOAuthSetupState::new();
        state.logged_in = false;
        let mut lines = Vec::new();

        render_grok_oauth_setup_body(&mut lines, &state);
        let rendered = rendered_text(&lines);

        assert!(rendered.contains("log in"), "{rendered}");
        assert!(rendered.contains("manual paste"), "{rendered}");
        assert!(rendered.contains("skip / continue"), "{rendered}");
        assert_eq!(option_row_count(&rendered), 3, "{rendered}");
    }

    #[test]
    fn logged_in_oauth_navigation_clamps_to_single_continue_row() {
        let mut codex = CodexOAuthSetupState::new();
        codex.logged_in = true;
        codex.cursor = 99;
        handle_codex_oauth_setup_key(press(KeyCode::Down), &mut codex);
        assert_eq!(codex.cursor, 0);

        let mut grok = GrokOAuthSetupState::new();
        grok.logged_in = true;
        grok.cursor = 99;
        handle_grok_oauth_setup_key(press(KeyCode::Up), &mut grok);
        assert_eq!(grok.cursor, 0);
    }

    #[test]
    fn grok_oauth_logged_out_enter_still_begins_login() {
        let mut state = GrokOAuthSetupState::new();
        state.logged_in = false;
        state.ssh_manual_only = false;
        state.cursor = 0;
        let (_close, action) = handle_grok_oauth_setup_key(press(KeyCode::Enter), &mut state);

        assert!(matches!(
            action,
            Some(OAuthActionRequest::GrokBegin { is_ssh: false })
        ));
        assert!(state.pending);
    }

    #[tokio::test]
    async fn logged_in_oauth_enter_advances_add_wizard() {
        for template_id in ["codex-oauth", "grok-oauth"] {
            let template = templates::template_by_id(template_id).unwrap();
            let (_, mut dialog) = dialog_with_config(ProvidersConfig::default());
            let mut state = AddState::new();
            state.template = Some(template);
            state.id_field.set(template_id);
            state.url_field.set(template.url);
            state.step = match template_id {
                "codex-oauth" => {
                    let mut oauth = CodexOAuthSetupState::new();
                    oauth.logged_in = true;
                    oauth.cursor = 0;
                    AddStep::CodexOAuthAuth(Box::new(oauth))
                }
                "grok-oauth" => {
                    let mut oauth = GrokOAuthSetupState::new();
                    oauth.logged_in = true;
                    oauth.cursor = 0;
                    AddStep::GrokOAuthAuth(Box::new(oauth))
                }
                _ => unreachable!(),
            };

            dialog.handle_add_key(press(KeyCode::Enter), &mut state);

            assert!(
                !matches!(
                    state.step,
                    AddStep::CodexOAuthAuth(_) | AddStep::GrokOAuthAuth(_)
                ),
                "{template_id} should advance past the OAuth confirmation step"
            );
        }
    }

    fn template_cursor(template_id: &str) -> usize {
        templates::TEMPLATES
            .iter()
            .position(|t| t.id == template_id)
            .unwrap()
    }

    /// Every template — including the frontier-defaults ones — now goes through
    /// the editable-id step. The id is no longer locked, so a user can rename a
    /// first-party connection (e.g. `anthropic-work`) and still add a second one.
    #[test]
    fn all_templates_offer_edit_id_step() {
        for t in templates::TEMPLATES {
            let (_tmp, mut dialog) = dialog_with_config(ProvidersConfig::default());
            let mut state = AddState::new();
            state.step = AddStep::PickTemplate {
                cursor: template_cursor(t.id),
            };

            dialog.handle_add_key(press(KeyCode::Enter), &mut state);

            assert!(
                matches!(state.step, AddStep::EditId),
                "{} should land on the EditId step",
                t.id
            );
            // The chosen template is committed and the id is pre-filled for
            // single-vendor templates.
            assert_eq!(state.template.map(|c| c.id), Some(t.id));
            let expected_id = if t.use_id_as_default { t.id } else { "" };
            assert_eq!(state.id_field.text(), expected_id, "{}", t.id);
            assert!(state.error.is_none(), "{}: {:?}", t.id, state.error);
        }
    }

    /// A second connection to a first-party vendor is allowed: the EditId step
    /// rejects the exact-duplicate default id but accepts a renamed key, so the
    /// user can keep e.g. separate work and personal Anthropic keys.
    #[test]
    fn second_first_party_connection_under_custom_id_works() {
        let mut providers = BTreeMap::new();
        providers.insert("anthropic".to_string(), provider_with_models(Vec::new()));
        let (_tmp, mut dialog) = dialog_with_config(ProvidersConfig {
            providers,
            ..Default::default()
        });
        let mut state = AddState::new();
        state.step = AddStep::PickTemplate {
            cursor: template_cursor("anthropic"),
        };

        // Pick the template — lands on EditId with the default `anthropic` id.
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(matches!(state.step, AddStep::EditId));
        assert_eq!(state.id_field.text(), "anthropic");

        // The default id collides with the existing provider.
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(
            matches!(state.step, AddStep::EditId),
            "collision keeps EditId"
        );
        assert!(
            state
                .error
                .as_deref()
                .unwrap_or("")
                .contains("already exists"),
            "{:?}",
            state.error
        );

        // Renaming to a unique key advances past EditId with no error.
        state.id_field.set("anthropic-work");
        dialog.handle_add_key(press(KeyCode::Enter), &mut state);
        assert!(
            matches!(state.step, AddStep::EditUrl),
            "unique renamed id advances the wizard"
        );
        assert!(state.error.is_none(), "{:?}", state.error);
    }

    /// The committed entry records the template identity (not the config-map
    /// key), so a renamed first-party connection still resolves to its vendor
    /// template and receives the frontier defaults.
    #[test]
    fn committed_entry_records_template_identity() {
        let anthropic = templates::template_by_id("anthropic").unwrap();
        let mut state = AddState::new();
        state.template = Some(anthropic);
        state.url_field.set(anthropic.url);

        let entry =
            provider_entry_from_add(&state, anthropic, templates::default_headers_for(anthropic));

        assert_eq!(entry.template.as_deref(), Some("anthropic"));
        // Even under a renamed config key the vendor identity is preserved.
        assert_eq!(
            entry.effective_template("anthropic-work"),
            Some("anthropic")
        );
    }
}
