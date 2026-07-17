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
//!     `apply_copilot_setup`, `render_copilot_body`).

mod fetch;
mod oauth_flow;
mod row_editor;

use std::path::PathBuf;

#[cfg(test)]
pub(super) use fetch::FetchedSummary;
pub(super) use fetch::{
    FetchAllState, FetchFallbackPromptState, FetchOnePromptState, compute_unlisted_for_models,
    render_fetch_all_results,
};
#[cfg(test)]
use oauth_flow::handle_oauth_flow_key_with;
pub(crate) use oauth_flow::{
    OAuthBeginResult, OAuthEffects, OAuthFlowOp, OAuthFlowRequest, OAuthFlowState, OAuthProvider,
};
use oauth_flow::{
    OAuthFlowView, handle_oauth_flow_key, oauth_setup_lines, render_oauth_body, render_oauth_setup,
};

use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

use crate::auth::{
    codex_oauth,
    copilot_setup::{self, Shell as CopilotShell},
    xai_oauth,
};
use crate::config::providers::{
    AuthKind, HeaderSpec, ModelEntry, ModelFetchStatusKind, ModelMergePolicy,
    OnUnlistedModelsFetch, ProviderEntry, ProviderModelCatalog, WireApi, format_model_fetch_age,
    merge_fetched_models_with_policy, provider_model_fetch_display_state,
    provider_model_fetch_reason_display, redact_model_fetch_reason,
};
use crate::envref;
use crate::providers::models_fetch::FetchOutcome;
use crate::providers::{self as templates, ProviderTemplate};
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;

pub(super) use row_editor::{
    HeaderEditor, HeaderMode, HeaderResult, ModelEditor, ModelField, ModelMode, ModelResult,
};

use super::auth::FetchHandle;
use super::settings_editor::{SettingsEditor, SettingsResult};
use super::shell::selected_line_from_marker;
use super::{Nav, SettingsCx, SettingsDialog, SettingsPage, save_button_line};
#[cfg(test)]
use super::{Page, TestPageRef};

/// One selectable action on the Edit-provider menu. The menu is built
/// dynamically (see [`edit_menu_actions`]) so render and key handling
/// share a single source of truth and stay index-correct when the
/// conditional "Copilot auth" row is present or absent.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum EditAction {
    Url,
    Headers,
    /// Only present for Copilot providers.
    CopilotAuth,
    /// Present for third-party OAuth-backed providers.
    OAuthAuth(OAuthProvider),
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
    let registry = templates::ProviderRegistry::standard();
    let provider = registry.provider_for(provider_id, entry);
    match provider.id() {
        "copilot" => actions.push(EditAction::CopilotAuth),
        crate::auth::xai_oauth::CREDENTIAL_KEY => {
            actions.push(EditAction::OAuthAuth(OAuthProvider::Grok))
        }
        crate::auth::codex_oauth::CREDENTIAL_KEY => {
            actions.push(EditAction::OAuthAuth(OAuthProvider::Codex))
        }
        _ => {}
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
    let shadow = if ctx.compact_shadow {
        format!("shadow −{}%", ctx.compact_shadow_margin_pct)
    } else {
        "shadow off".to_string()
    };
    let mut summary = format!(
        "compact {}% ({shadow}) · {prune} · cache {}s · ttft {}s · idle {}s · mode {mode}",
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
        if at_dollar && prev_ok {
            if value[i..].starts_with("$secret:") {
                let rest = &bytes[i + "$secret:".len()..];
                let name_len = rest
                    .iter()
                    .position(|byte| {
                        !(byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-'))
                    })
                    .unwrap_or(rest.len());
                if name_len > 0 {
                    i += "$secret:".len() + name_len;
                    continue;
                }
            } else if let Some((_, rest)) = take_env_var_name(&bytes[i + 1..]) {
                i = bytes.len() - rest.len();
                continue;
            }
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
    crate::secret_ref::looks_like_literal_secret(value)
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
    OAuthSetup {
        state: Box<OAuthFlowState>,
        parent: Box<EditState>,
    },
}

impl ProvidersPage {
    pub(super) fn paste_oauth(&mut self, text: &str) -> bool {
        let state = match self {
            Self::OAuthSetup { state, .. }
            | Self::Add(AddState {
                step: AddStep::OAuthAuth(state),
                ..
            }) if state.has_browser_session() => state,
            _ => return false,
        };
        state.paste_focused = true;
        state.manual_input.paste(text);
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RenderedLinkRegion {
    row: usize,
    x_offset: u16,
    width: u16,
    url: String,
    label: String,
}

fn prepare_oauth_link_regions(
    lines: &mut [Line<'static>],
    area: Rect,
    flow: OAuthFlowView<'_>,
    links: Option<&crate::tui::links::LinkRegistry>,
) -> Option<Vec<RenderedLinkRegion>> {
    let (url, raw_label) = oauth_link_target(flow)?;
    let row = lines.iter().position(|line| {
        line.spans
            .iter()
            .any(|span| span.content.as_ref() == raw_label)
    })?;
    let line = lines.get_mut(row)?;
    let span_index = line
        .spans
        .iter()
        .position(|span| span.content.as_ref() == raw_label)?;
    let x_offset = line.spans[..span_index]
        .iter()
        .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
        .sum::<usize>();
    let available = usize::from(area.width).saturating_sub(x_offset);
    let painted = crate::tui::links::clipped_label(raw_label, available as u16);
    let width = UnicodeWidthStr::width(painted.as_str()).min(available) as u16;
    let hovered = links
        .and_then(crate::tui::links::LinkRegistry::hovered_url)
        .is_some_and(|hovered| hovered == url);
    line.spans[span_index].content = painted.clone().into();
    line.spans[span_index].style = crate::tui::links::link_style(hovered);
    Some(vec![RenderedLinkRegion {
        row,
        x_offset: x_offset as u16,
        width,
        url: url.to_string(),
        label: painted,
    }])
}

fn register_visible_link_regions(
    links: &mut crate::tui::links::LinkRegistry,
    area: Rect,
    scroll_offset: usize,
    regions: Vec<RenderedLinkRegion>,
) {
    let visible_end = scroll_offset.saturating_add(usize::from(area.height));
    for region in regions {
        if region.row < scroll_offset || region.row >= visible_end || region.width == 0 {
            continue;
        }
        let y = area
            .y
            .saturating_add(region.row.saturating_sub(scroll_offset) as u16);
        links.register(
            Rect::new(area.x.saturating_add(region.x_offset), y, region.width, 1),
            region.url,
            region.label,
        );
    }
}

fn oauth_link_target(flow: OAuthFlowView<'_>) -> Option<(&str, &str)> {
    match flow {
        OAuthFlowView::OAuth(state) if state.provider == OAuthProvider::Grok => {
            Some((state.authorize_url()?, "open xai.com authorization page"))
        }
        OAuthFlowView::OAuth(state) if state.provider == OAuthProvider::Codex => {
            let uri = state.device_login()?.verification_uri.as_str();
            Some((uri, uri))
        }
        OAuthFlowView::Copilot(_) => None,
        OAuthFlowView::OAuth(_) => None,
    }
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
            ProvidersPage::OAuthSetup { state, .. } => {
                state.paste_focused.then_some(&mut state.manual_input)
            }
            ProvidersPage::Add(s) => match &mut s.step {
                AddStep::EditId => Some(&mut s.id_field),
                AddStep::EditUrl => Some(&mut s.url_field),
                AddStep::EditHeaders => s.headers.active_text_field(),
                AddStep::OAuthAuth(state) => state.paste_focused.then_some(&mut state.manual_input),
                AddStep::PickTemplate { .. }
                | AddStep::CopilotAuth(_)
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

pub(super) fn oauth_setup_confirming_logged_in(
    logged_in: bool,
    in_progress: bool,
    paste_focused: bool,
) -> bool {
    logged_in && !in_progress && !paste_focused
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
    /// Shared OAuth setup step for provider templates that need browser or device auth.
    OAuthAuth(Box<OAuthFlowState>),
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
        embeddings: None,
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
                self.page =
                    super::providers_page(ProvidersPage::FetchOnePrompt(FetchOnePromptState {
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
                self.page = super::providers_page(ProvidersPage::FetchFallbackPrompt(
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

        let refreshed = self.config.providers.get(provider_id).map(|entry| {
            (
                entry.models.clone(),
                entry.models_fetched_at,
                entry.model_catalog,
            )
        });
        if let Some(page) = self.page.downcast_mut::<ProvidersPage>() {
            match page {
                ProvidersPage::Add(s) => {
                    s.error = Some(message);
                    s.fetch = None;
                    s.step = AddStep::Done;
                }
                ProvidersPage::Edit(s) => {
                    s.status = Some(message);
                    s.fetch = None;
                    if let Some((models, fetched_at, catalog)) = &refreshed {
                        s.entry.models = models.clone();
                        s.entry.models_fetched_at = *fetched_at;
                        s.entry.model_catalog = *catalog;
                    }
                }
                ProvidersPage::Headers { parent, .. } => {
                    parent.status = Some(message);
                    parent.fetch = None;
                    if let Some((models, fetched_at, catalog)) = &refreshed {
                        parent.entry.models = models.clone();
                        parent.entry.models_fetched_at = *fetched_at;
                        parent.entry.model_catalog = *catalog;
                    }
                }
                ProvidersPage::Models { parent, .. } => {
                    parent.status = Some(message);
                    parent.fetch = None;
                }
                ProvidersPage::ModelSettings { parent, .. }
                | ProvidersPage::ProviderSettings { parent, .. } => {
                    parent.status = Some(message);
                    parent.fetch = None;
                }
                _ => {}
            }
        }
    }

    fn clear_fetch_handle(&mut self, provider_id: &str) {
        let Some(page) = self.page.downcast_mut::<ProvidersPage>() else {
            return;
        };
        match page {
            ProvidersPage::Add(s) if s.saved_provider_id.as_deref() == Some(provider_id) => {
                s.fetch = None;
            }
            ProvidersPage::Edit(s) if s.provider_id == provider_id => {
                s.fetch = None;
            }
            ProvidersPage::Headers { parent, .. }
            | ProvidersPage::Models { parent, .. }
            | ProvidersPage::ModelSettings { parent, .. }
            | ProvidersPage::ProviderSettings { parent, .. }
                if parent.provider_id == provider_id =>
            {
                parent.fetch = None;
            }
            _ => {}
        }
    }
}
impl SettingsCx {
    fn handle_provider_list_key(
        &mut self,
        key: KeyEvent,
        cursor: &mut usize,
        status: &mut Option<String>,
        delete_pending: &mut bool,
    ) -> Nav {
        // Row 0 is the synthetic `[refetch provider models]` button;
        // provider rows are offset by one (1..=ids.len()). The
        // policy summary is rendered as non-selectable text.
        let ids: Vec<String> = self.config.providers.keys().cloned().collect();
        let row_count = ids.len() + 1;
        let provider_idx = list_provider_idx(*cursor, ids.len());
        let delete_choice_key = matches!(key.code, KeyCode::Char('d') | KeyCode::Char('n'));
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
                return Nav::Replace(super::providers_page(ProvidersPage::Add(AddState::new())));
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
            KeyCode::Char('n') if *delete_pending => {
                if let Some(idx) = provider_idx {
                    let id = ids[idx].clone();
                    let msg = match self.delete_provider_and_stored_secrets(&id, false) {
                        Ok(_) => format!("deleted `{id}`; kept stored secret(s)"),
                        Err(e) => format!("delete failed: {e}"),
                    };
                    return Nav::Replace(super::providers_page(ProvidersPage::List {
                        cursor: (*cursor).min(self.config.providers.len()),
                        status: Some(msg),
                        delete_pending: false,
                    }));
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if *cursor == 0 {
                    return self.start_fetch_all();
                }
                if let Some(idx) = provider_idx
                    && let Some(id) = ids.get(idx).cloned()
                    && let Some(entry) = self.config.providers.get(&id)
                {
                    return Nav::Replace(super::providers_page(ProvidersPage::Edit(
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
                        let msg = match self.delete_provider_and_stored_secrets(&id, true) {
                            Ok(0) => format!("deleted `{id}`"),
                            Ok(count) => format!("deleted `{id}` and {count} stored secret(s)"),
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
                        return Nav::Replace(super::providers_page(ProvidersPage::List {
                            cursor: new_cursor,
                            status: Some(msg),
                            delete_pending: false,
                        }));
                    } else {
                        *delete_pending = true;
                        *status = Some(format!(
                            "press d again to delete `{}` + stored secrets (default); n: keep secrets",
                            ids[idx]
                        ));
                        return Nav::Stay;
                    }
                }
                // Drop through to the post-match cleanup.
            }
            _ => {}
        }
        // Any non-choice key (or choice on a non-provider row) clears
        // the pending-delete arm and the transient status.
        if !delete_choice_key {
            *delete_pending = false;
            *status = None;
        }
        Nav::Stay
    }
    fn handle_providers_page_key(&mut self, key: KeyEvent, page: &mut ProvidersPage) -> Nav {
        match page {
            ProvidersPage::List {
                cursor,
                status,
                delete_pending,
            } => self.handle_provider_list_key(key, cursor, status, delete_pending),
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
            ProvidersPage::OAuthSetup { state, parent } => {
                let (close, action) = handle_oauth_flow_key(key, state);
                self.pending_oauth_action = action;
                if close {
                    let owned = std::mem::replace(
                        parent,
                        Box::new(EditState::new(String::new(), ProviderEntry::default())),
                    );
                    Nav::Replace(super::providers_page(ProvidersPage::Edit(*owned)))
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
                let notice = self.last_secret_notice.take();
                if !template.supports_models_endpoint {
                    s.error = Some(match notice {
                        Some(notice) => {
                            format!("saved. {notice} Provider has no /models endpoint")
                        }
                        None => "saved. provider has no /models endpoint".into(),
                    });
                    s.step = AddStep::Done;
                } else {
                    s.error = Some(match notice {
                        Some(notice) => format!("saved. {notice} Fetching /models…"),
                        None => "saved. Fetching /models…".into(),
                    });
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
        if matches!(key.code, KeyCode::Esc) && !matches!(s.step, AddStep::OAuthAuth(_)) {
            return Nav::Replace(super::providers_page(ProvidersPage::List {
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
                            s.step = AddStep::OAuthAuth(Box::new(OAuthFlowState::new(
                                OAuthProvider::Grok,
                            )));
                        } else if matches!(s.template.map(|t| t.id), Some("codex-oauth")) {
                            s.step = AddStep::OAuthAuth(Box::new(OAuthFlowState::new(
                                OAuthProvider::Codex,
                            )));
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
            AddStep::OAuthAuth(state) => {
                let (close, action) = handle_oauth_flow_key(key, state);
                self.pending_oauth_action = action;
                if close {
                    s.step = AddStep::EditUrl;
                    return Nav::Stay;
                }
                if (matches!(key.code, KeyCode::Char('s')) && !state.paste_focused)
                    || (matches!(key.code, KeyCode::Enter)
                        && OAuthFlowView::OAuth(state).confirming())
                    || (matches!(key.code, KeyCode::Enter)
                        && ((state.provider == OAuthProvider::Grok
                            && state.cursor == 2
                            && !state.paste_focused)
                            || (state.provider == OAuthProvider::Codex
                                && state.cursor == 1
                                && state.device_login().is_none())))
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
                    return Nav::Replace(super::providers_page(ProvidersPage::List {
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
        match self.save_config() {
            Ok(()) => Some(
                self.last_secret_notice
                    .take()
                    .map(|notice| format!("saved. {notice}"))
                    .unwrap_or_else(|| "saved".to_string()),
            ),
            Err(error) => Some(format!("save failed: {error}")),
        }
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
                return Nav::Replace(super::providers_page(ProvidersPage::List {
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
            KeyCode::Char('n') if s.delete_pending => {
                let saved = self.delete_provider_and_stored_secrets(&s.provider_id, false);
                let msg = match saved {
                    Ok(_) => format!("deleted `{}`; kept stored secret(s)", s.provider_id),
                    Err(e) => format!("delete failed: {e}"),
                };
                return Nav::Replace(super::providers_page(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status: Some(msg),
                    delete_pending: false,
                }));
            }
            KeyCode::Char('d') => {
                if s.delete_pending {
                    let saved = self.delete_provider_and_stored_secrets(&s.provider_id, true);
                    let msg = match saved {
                        Ok(0) => format!("deleted `{}`", s.provider_id),
                        Ok(count) => {
                            format!("deleted `{}` and {count} stored secret(s)", s.provider_id)
                        }
                        Err(e) => format!("delete failed: {e}"),
                    };
                    return Nav::Replace(super::providers_page(ProvidersPage::List {
                        cursor: initial_list_cursor(&self.config),
                        status: Some(msg),
                        delete_pending: false,
                    }));
                } else {
                    s.delete_pending = true;
                    s.status = Some(
                        "press d again to delete + stored secrets (default); n: keep secrets"
                            .into(),
                    );
                }
                return Nav::Stay;
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                return self.handle_edit_menu_action(s, actions.get(s.cursor).copied());
            }
            _ => {}
        }
        s.delete_pending =
            matches!(key.code, KeyCode::Char('d') | KeyCode::Char('n')) && s.delete_pending;
        Nav::Stay
    }

    fn handle_edit_menu_action(&mut self, s: &mut EditState, action: Option<EditAction>) -> Nav {
        match action {
            Some(EditAction::Url) => {
                s.field_buf = TextField::new(s.entry.url.clone());
                s.editing_field = Some(EditField::Url);
            }
            Some(EditAction::Headers) => {
                // Hand off to the Headers sub-page. We move
                // the EditState out via `mem::replace` so the
                // Headers page can return it intact on back.
                let editor =
                    HeaderEditor::new(s.entry.headers.clone(), /* show_continue */ false);
                let owned =
                    std::mem::replace(s, EditState::new(String::new(), ProviderEntry::default()));
                return Nav::Replace(super::providers_page(ProvidersPage::Headers {
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
                let owned =
                    std::mem::replace(s, EditState::new(String::new(), ProviderEntry::default()));
                return Nav::Replace(super::providers_page(ProvidersPage::CopilotSetup {
                    state,
                    parent: Box::new(owned),
                }));
            }
            Some(EditAction::OAuthAuth(provider)) => {
                let state = Box::new(OAuthFlowState::new(provider));
                let owned =
                    std::mem::replace(s, EditState::new(String::new(), ProviderEntry::default()));
                return Nav::Replace(super::providers_page(ProvidersPage::OAuthSetup {
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
                let owned =
                    std::mem::replace(s, EditState::new(String::new(), ProviderEntry::default()));
                return Nav::Replace(super::providers_page(ProvidersPage::Models {
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
                let owned =
                    std::mem::replace(s, EditState::new(String::new(), ProviderEntry::default()));
                return Nav::Replace(super::providers_page(ProvidersPage::ProviderSettings {
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
                    let saved = self.delete_provider_and_stored_secrets(&s.provider_id, true);
                    let msg = match saved {
                        Ok(0) => format!("deleted `{}`", s.provider_id),
                        Ok(count) => {
                            format!("deleted `{}` and {count} stored secret(s)", s.provider_id)
                        }
                        Err(e) => format!("delete failed: {e}"),
                    };
                    return Nav::Replace(super::providers_page(ProvidersPage::List {
                        cursor: initial_list_cursor(&self.config),
                        status: Some(msg),
                        delete_pending: false,
                    }));
                } else {
                    s.delete_pending = true;
                    s.status = Some(
                        "press Enter again to delete + stored secrets (default); n: keep secrets"
                            .into(),
                    );
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
                return Nav::Replace(super::providers_page(ProvidersPage::List {
                    cursor: initial_list_cursor(&self.config),
                    status,
                    delete_pending: false,
                }));
            }
            None => {}
        }
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
                Nav::Replace(super::providers_page(ProvidersPage::Edit(owned)))
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
                Nav::Replace(super::providers_page(ProvidersPage::Edit(owned)))
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
                Nav::Replace(super::providers_page(ProvidersPage::ModelSettings {
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
                Nav::Replace(super::providers_page(ProvidersPage::Models {
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
                Nav::Replace(super::providers_page(ProvidersPage::Edit(owned)))
            }
        }
    }

    fn handle_fetch_one_prompt_key(&mut self, key: KeyEvent, s: &mut FetchOnePromptState) -> Nav {
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc => {
                return Nav::Replace(super::providers_page(ProvidersPage::List {
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
                return Nav::Replace(super::providers_page(ProvidersPage::Edit(edit)));
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
                return Nav::Replace(super::providers_page(ProvidersPage::List {
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
                        return Nav::Replace(super::providers_page(ProvidersPage::List {
                            cursor: initial_list_cursor(&self.config),
                            status: Some("provider no longer exists".into()),
                            delete_pending: false,
                        }));
                    };
                    let mut edit = EditState::new(s.provider_id.clone(), entry.clone());
                    edit.status = Some("retrying live model fetch...".into());
                    edit.fetch = Some(FetchHandle::spawn(s.provider_id.clone(), entry));
                    return Nav::Replace(super::providers_page(ProvidersPage::Edit(edit)));
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
                    return Nav::Replace(super::providers_page(ProvidersPage::Edit(edit)));
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
                    return Nav::Replace(super::providers_page(ProvidersPage::Edit(edit)));
                }
                _ => {
                    return Nav::Replace(super::providers_page(ProvidersPage::List {
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
            Nav::Replace(super::providers_page(ProvidersPage::Edit(owned)))
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

impl SettingsCx {
    pub(super) fn render_providers_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        page: &ProvidersPage,
        links: Option<&mut crate::tui::links::LinkRegistry>,
    ) {
        match page {
            ProvidersPage::List {
                cursor,
                status,
                delete_pending,
            } => {
                self.render_providers_list(frame, area, *cursor, status.as_deref(), *delete_pending)
            }
            ProvidersPage::Add(s) => self.render_add(frame, area, s, links),
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
            ProvidersPage::OAuthSetup { state, .. } => {
                render_oauth_setup(frame, area, OAuthFlowView::OAuth(state), links)
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
        let lines = oauth_setup_lines(OAuthFlowView::Copilot(s));
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_lines(
            frame,
            area,
            "providers:copilot-setup",
            lines,
            selected_line,
        );
    }

    fn render_add(
        &self,
        frame: &mut Frame,
        area: Rect,
        s: &AddState,
        links: Option<&mut crate::tui::links::LinkRegistry>,
    ) {
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
                render_oauth_body(&mut lines, OAuthFlowView::Copilot(state));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "After this step we'll fetch the model list automatically. \
                     Press `s` to skip the GH_TOKEN setup if your token is \
                     already in the environment."
                        .to_string(),
                    muted,
                )));
            }
            AddStep::OAuthAuth(state) => {
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                render_oauth_body(&mut lines, OAuthFlowView::OAuth(state));
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
        let oauth_flow = match &s.step {
            AddStep::OAuthAuth(state) => Some(OAuthFlowView::OAuth(state)),
            _ => None,
        };
        let link_regions = oauth_flow
            .and_then(|flow| prepare_oauth_link_regions(&mut lines, area, flow, links.as_deref()))
            .unwrap_or_default();
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "providers:add", lines, selected_line);
        if let Some(links) = links {
            register_visible_link_regions(
                links,
                area,
                self.scroll_states.offset_for("providers:add"),
                link_regions,
            );
        }
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
                EditAction::OAuthAuth(OAuthProvider::Grok) => (
                    "Grok subscription auth",
                    if xai_oauth::is_logged_in() {
                        "logged in"
                    } else {
                        "not logged in"
                    }
                    .to_string(),
                ),
                EditAction::OAuthAuth(OAuthProvider::Codex) => (
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
                        "(Enter: delete secrets; n: keep secrets)".to_string()
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

    // Dynamic-reference status for the value (headers commonly reference
    // `$VAR` or `$secret:<name>`).
    let resolved = envref::resolve(h.value_buf.text());
    if resolved.has_missing() {
        let env_missing = resolved
            .missing
            .iter()
            .filter(|name| !name.starts_with("secret:"))
            .map(|name| format!("${name}"))
            .collect::<Vec<_>>();
        let secret_missing = resolved
            .missing
            .iter()
            .filter(|name| name.starts_with("secret:"))
            .map(|name| format!("${name}"))
            .collect::<Vec<_>>();
        let message = if !secret_missing.is_empty() && env_missing.is_empty() {
            let path = crate::credentials::default_path()
                .map(|path| crate::welcome::display_path(&path))
                .unwrap_or_else(|| "the credential store".to_string());
            format!(
                "  Named secret not detected in {path}: {}",
                secret_missing.join(", ")
            )
        } else if secret_missing.is_empty() {
            format!(
                "  Environment variable not detected, make sure to set it: {}",
                env_missing.join(", ")
            )
        } else {
            format!(
                "  References not detected: {}",
                env_missing
                    .into_iter()
                    .chain(secret_missing)
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        };
        body.push(Line::from(Span::styled(message, yellow)));
    } else if !resolved.referenced.is_empty() {
        body.push(Line::from(Span::styled(
            format!(
                "  dynamic reference(s) detected: ${}",
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
        let cursor = crate::text::floor_char_boundary(text, field.cursor());
        let (before, after) = text.split_at(cursor);
        spans.push(Span::styled(before.to_string(), value_style));
        spans.push(super::shell::cursor_marker_span());
        spans.push(Span::styled(after.to_string(), value_style));
    } else {
        spans.push(Span::styled(field.text().to_string(), value_style));
    }
    lines.push(Line::from(spans));
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
mod tests;

impl SettingsPage for ProvidersPage {
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_providers_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_providers_page(frame, area, self, None);
    }

    fn render_with_links(
        &self,
        cx: &SettingsCx,
        frame: &mut Frame,
        area: Rect,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        cx.render_providers_page(frame, area, self, Some(links));
    }

    fn title(&self, cx: &SettingsCx) -> String {
        let crumbs = match self {
            ProvidersPage::List { .. } => format!(" › {}", super::PROVIDERS_TITLE),
            ProvidersPage::Add(_) => format!(" › {} › Add", super::PROVIDERS_TITLE),
            ProvidersPage::Edit(s) => format!(" › {} › {}", super::PROVIDERS_TITLE, s.provider_id),
            ProvidersPage::Headers { parent, .. } => {
                format!(
                    " › {} › {} › Headers",
                    super::PROVIDERS_TITLE,
                    parent.provider_id
                )
            }
            ProvidersPage::Models { parent, .. } => {
                format!(
                    " › {} › {} › Models",
                    super::PROVIDERS_TITLE,
                    parent.provider_id
                )
            }
            ProvidersPage::ModelSettings { parent, .. } => {
                format!(
                    " › {} › {} › Model Settings",
                    super::PROVIDERS_TITLE,
                    parent.provider_id
                )
            }
            ProvidersPage::ProviderSettings { parent, .. } => {
                format!(
                    " › {} › {} › Settings",
                    super::PROVIDERS_TITLE,
                    parent.provider_id
                )
            }
            ProvidersPage::FetchAll(_) => format!(" › {} › refetch all", super::PROVIDERS_TITLE),
            ProvidersPage::FetchOnePrompt(s) => {
                format!(
                    " › {} › {} › refetch",
                    super::PROVIDERS_TITLE,
                    s.provider_id
                )
            }
            ProvidersPage::FetchFallbackPrompt(s) => {
                format!(
                    " › {} › {} › fallback",
                    super::PROVIDERS_TITLE,
                    s.provider_id
                )
            }
            ProvidersPage::CopilotSetup { .. } => {
                format!(" › {} › Copilot setup", super::PROVIDERS_TITLE)
            }
            ProvidersPage::OAuthSetup { state, .. } => match state.provider {
                OAuthProvider::Grok => format!(" › {} › Grok OAuth", super::PROVIDERS_TITLE),
                OAuthProvider::Codex => format!(" › {} › Codex OAuth", super::PROVIDERS_TITLE),
            },
        };
        format!(
            "{}{}",
            crate::welcome::display_path(&cx.config_path),
            crumbs
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        match self {
            ProvidersPage::List { .. } => {
                "↑/↓/Tab/Shift+Tab  enter: edit/refetch-all  R: refetch all  m: unlisted policy  a: add  d: delete (×2)  esc/h: back  q: close"
            }
            ProvidersPage::Add(s) => match &s.step {
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
                AddStep::OAuthAuth(state) => match state.provider {
                    OAuthProvider::Grok => {
                        if state.paste_focused {
                            return "type/paste code  enter: submit  esc: options";
                        }
                        oauth_setup_help_text(oauth_setup_confirming_logged_in(
                            state.logged_in,
                            state.pending,
                            state.paste_focused,
                        ))
                    }
                    OAuthProvider::Codex => oauth_setup_help_text(
                        oauth_setup_confirming_logged_in(state.logged_in, state.polling, false),
                    ),
                },
                AddStep::Saving | AddStep::Fetching => "(in progress)  esc: cancel",
                AddStep::Done => "enter: back to list",
            },
            ProvidersPage::Edit(s) => {
                if s.editing_field.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit  s: save  r: refetch  f: favorite  d: delete (x2)  h: back  q: close"
                }
            }
            ProvidersPage::Headers { editor, .. } => {
                if editor.is_editing() {
                    "type to edit  Tab: switch field  enter: save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  enter: edit  d: delete (x2)  h: back  q: close"
                }
            }
            ProvidersPage::Models { editor, .. } => {
                if editor.is_editing() {
                    "type to edit  Tab: switch field  enter: save  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  a: add  r: rename  enter: settings  d: delete (x2)  h: back  q: close"
                }
            }
            ProvidersPage::ModelSettings { editor, .. } => {
                if editor.editing.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit/cycle  x: clear to inherit  h: back  q: close"
                }
            }
            ProvidersPage::ProviderSettings { editor, .. } => {
                if editor.editing.is_some() {
                    "type to edit  enter: apply  esc: cancel"
                } else {
                    "↑/↓/Tab/Shift+Tab  enter: edit/cycle  h: back  q: close"
                }
            }
            ProvidersPage::FetchAll(s) => {
                if s.is_fetching() {
                    "fetching all providers…  esc: cancel"
                } else if s.unlisted.is_empty() {
                    "press any key to return"
                } else {
                    "↑/↓/Tab/Shift+Tab  space: toggle don't-ask  enter: apply  esc: cancel"
                }
            }
            ProvidersPage::FetchOnePrompt(_) => {
                "↑/↓/Tab/Shift+Tab  space: toggle don't-ask  enter: apply  esc: cancel"
            }
            ProvidersPage::FetchFallbackPrompt(_) => {
                "↑/↓/Tab/Shift+Tab  enter: choose  esc: cancel"
            }
            ProvidersPage::CopilotSetup { .. } => "enter: apply  esc: cancel",
            ProvidersPage::OAuthSetup { state, .. } if state.paste_focused => {
                "type/paste code  enter: submit  esc: options"
            }
            ProvidersPage::OAuthSetup { state, .. } => match state.provider {
                OAuthProvider::Grok => "↑/↓/Tab/Shift+Tab  enter: choose  c: copy URL  esc: back",
                OAuthProvider::Codex => "↑/↓/Tab/Shift+Tab  enter: choose  esc: back",
            },
        }
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "Providers"
    }
}
