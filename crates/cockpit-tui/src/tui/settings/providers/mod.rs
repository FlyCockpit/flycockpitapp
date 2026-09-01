//! `/settings → Providers`: the largest settings page tree.
//!
//! Lives here so the `mod.rs` dispatcher and the unrelated UI/Tools
//! pages aren't drowned by ~2K lines of provider-specific state
//! machine. Owns:
//!   - the [`ProvidersPage`] state enum (List, Add wizard, Edit page,
//!     Headers sub-page, FetchAll, CopilotSetup)
//!   - per-page state types (`AddState` + descriptor-backed [`WizardRun`], `EditState` +
//!     `EditField`, `HeaderEditor` + modes, `FetchAllState`,
//!     `CopilotSetupState`)
//!   - the corresponding handlers + renderers on [`SettingsDialog`]
//!     (multiple `impl` blocks across this file and `mod.rs`)
//!   - provider-only free helpers (`render_header_editor`,
//!     `render_field_row`, `valid_url`, `valid_id`,
//!     `render_copilot_body`).

mod deepfetch;
mod fetch;
mod oauth_flow;
mod row_editor;

use std::path::PathBuf;

pub(super) use deepfetch::DeepFetchState;
#[cfg(test)]
pub(super) use fetch::FetchedSummary;
pub(super) use fetch::{
    FetchAllState, FetchFallbackPromptState, FetchOnePromptState, compute_unlisted_for_models,
    render_fetch_all_results,
};
#[cfg(test)]
pub(crate) use oauth_flow::CodexOAuthOption;
#[cfg(test)]
use oauth_flow::handle_oauth_flow_key_with;
#[cfg(all(test, feature = "grok-subscription"))]
pub(crate) use oauth_flow::prepare_grok_browser_start;
pub(crate) use oauth_flow::{
    OAuthBeginResult, OAuthEffects, OAuthFlowOp, OAuthFlowRequest, OAuthFlowState, OAuthOption,
    OAuthPresentationResult, OAuthProvider, OAuthPublicBegin, present_oauth_on_blocking_worker,
};
use oauth_flow::{
    OAuthFlowView, OAuthHost, OAuthNav, handle_oauth_flow_key, oauth_help_legend, oauth_options,
    oauth_setup_lines, oauth_setup_lines_with_controls, render_oauth_body,
    render_oauth_body_with_controls,
};

use chrono::Utc;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap};
use unicode_width::UnicodeWidthStr;

use crate::tui::settings::provider_entries_equal;
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::providers::{
    HeaderSpec, ModelEntry, ModelFetchStatusKind, ModelMergePolicy, OnUnlistedModelsFetch,
    ProviderEntry, ProviderModelCatalog, WireApi, format_model_fetch_age,
    merge_fetched_models_with_policy, provider_model_fetch_display_state,
    provider_model_fetch_reason_display, redact_model_fetch_reason,
};
use cockpit_core::auth::copilot_setup::Shell as CopilotShell;
use cockpit_core::providers::{self as templates, ProviderTemplate};
use cockpit_core::wizard::{WizardAnswer, WizardRun};
use cockpit_proto::ProviderModelFetchOutcome as FetchOutcome;

pub(super) use row_editor::{
    HeaderEditor, HeaderMode, HeaderResult, ModelEditor, ModelField, ModelMode, ModelResult,
};

use super::auth::FetchHandle;
use super::settings_editor::{SettingsEditor, SettingsResult};
use super::shell::{
    SettingsControlId, SettingsScrollRegionId, push_wrapped_text, selected_line_from_marker,
};
use super::{Nav, SettingsCx, SettingsDialog, SettingsPage, save_button_line};
#[cfg(test)]
use super::{Page, TestPageRef};

/// One selectable action on the Edit-provider menu. The menu is built
/// dynamically (see [`edit_menu_actions`]) so render and key handling
/// share a single source of truth and stay index-correct when the
/// conditional "Copilot auth" row is present or absent.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(super) enum EditAction {
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
    DeepFetch,
    Delete,
    Save,
    Back,
}

/// Build the ordered Edit-menu action list for `entry`. The "Copilot
/// auth" row is included only when `entry` is a Copilot provider. This is
/// the single source of truth for both [`Self::render_edit`] and
/// [`Self::handle_edit_key`]: the cursor indexes into the returned `Vec`
/// and the handler dispatches on the action, never a literal index.
pub(super) fn edit_menu_actions(provider_id: &str, entry: &ProviderEntry) -> Vec<EditAction> {
    let mut actions = vec![EditAction::Url, EditAction::Headers];
    let registry = templates::ProviderRegistry::standard();
    match registry.provider_id_for(provider_id, entry) {
        "copilot" => actions.push(EditAction::CopilotAuth),
        #[cfg(feature = "grok-subscription")]
        "grok-oauth" => actions.push(EditAction::OAuthAuth(OAuthProvider::Grok)),
        cockpit_core::auth::codex_oauth::CREDENTIAL_KEY => {
            actions.push(EditAction::OAuthAuth(OAuthProvider::Codex))
        }
        _ => {}
    }
    actions.extend([
        EditAction::Models,
        EditAction::Settings,
        EditAction::Favorite,
        EditAction::Refetch,
        EditAction::DeepFetch,
        EditAction::Delete,
        EditAction::Save,
        EditAction::Back,
    ]);
    actions
}

fn provider_settings_summary(entry: &ProviderEntry) -> String {
    let ctx = &entry.context;
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
    let compact = ctx
        .auto_compact_pct
        .map(|pct| format!("{pct}%"))
        .unwrap_or_else(|| "auto".to_string());
    let mut summary = format!(
        "compact {compact} ({shadow}) · nudge {}% · {prune} · cache {}s · ttft {}s · idle {}s",
        ctx.compact_nudge_pct,
        entry.cache.ttl_secs,
        entry.timeout.ttft_secs,
        entry.timeout.idle_secs,
    );
    let trust = match entry.trust {
        Some(cockpit_config::providers::ModelTrust::Trusted) => "trusted",
        Some(cockpit_config::providers::ModelTrust::Untrusted) | None => "untrusted",
    };
    let quality = entry
        .quality_rank
        .map(|v| v.to_string())
        .unwrap_or_else(|| "0".to_string());
    let cost = entry
        .cost_rank
        .map(|v| v.to_string())
        .unwrap_or_else(|| "0".to_string());
    let subagents = if entry.subagent_invokable.unwrap_or(false) {
        "on"
    } else {
        "off"
    };
    summary.push_str(&format!(
        " · trust {trust} · quality {quality} · cost {cost} · subagents {subagents}"
    ));
    match entry.wire_api {
        WireApi::Auto => {}
        WireApi::Completions => summary.push_str(" · wire completions"),
        WireApi::Responses => summary.push_str(" · wire responses"),
        WireApi::Anthropic => summary.push_str(" · wire anthropic"),
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
    if cockpit_core::envref::referenced_names(value).is_empty() {
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
    cockpit_core::secret_ref::looks_like_literal_secret(value)
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

pub(super) fn initial_list_cursor(config: &cockpit_config::providers::ProvidersConfig) -> usize {
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
    /// Explicitly confirmed, one-provider deep fetch. The state owns the Edit
    /// page so an unsaved edit can never be persisted by a probe run.
    DeepFetch {
        state: DeepFetchState,
        parent: Box<EditState>,
    },
    /// Informational "GitHub Copilot auth" screen. Authentication is owned
    /// by the daemon; the TUI never invokes `gh`, reads a token, or edits a
    /// shell startup file. Back navigation returns to `Edit(parent)` with
    /// the parent's cursor/status/unsaved edits intact.
    CopilotSetup {
        state: CopilotSetupState,
        parent: Box<EditState>,
    },
    OAuthSetup {
        state: Box<OAuthFlowState>,
        parent: Box<EditState>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProvidersPointerSurface {
    List,
    Add,
    Edit,
    Headers,
    Models,
    ModelSettings,
    ProviderSettings,
    FetchAll,
    FetchOnePrompt,
    FetchFallbackPrompt,
    DeepFetch,
    CopilotSetup,
    OAuthSetup,
}

impl ProvidersPointerSurface {
    /// Exhaustive token inventory used by the concrete-render acceptance
    /// gate. Adding a nested provider page requires adding it here as well.
    const ALL: [Self; 13] = [
        Self::List,
        Self::Add,
        Self::Edit,
        Self::Headers,
        Self::Models,
        Self::ModelSettings,
        Self::ProviderSettings,
        Self::FetchAll,
        Self::FetchOnePrompt,
        Self::FetchFallbackPrompt,
        Self::DeepFetch,
        Self::CopilotSetup,
        Self::OAuthSetup,
    ];
}

impl ProvidersPage {
    pub(super) fn has_unsettled_oauth_operation(&self) -> bool {
        match self {
            Self::OAuthSetup { state, .. } => state.has_unsettled_authority(),
            Self::Add(state) => state
                .oauth_auth
                .as_ref()
                .is_some_and(|oauth| oauth.has_unsettled_authority()),
            _ => false,
        }
    }

    pub(super) fn has_unsettled_authority_operation(&self) -> bool {
        match self {
            Self::OAuthSetup { state, .. } => state.has_unsettled_authority(),
            Self::Add(state) => {
                state.fetch.is_some()
                    || state
                        .oauth_auth
                        .as_ref()
                        .is_some_and(|oauth| oauth.has_unsettled_authority())
            }
            Self::Edit(state) => state.fetch.is_some(),
            Self::Headers { parent, .. }
            | Self::Models { parent, .. }
            | Self::ModelSettings { parent, .. }
            | Self::ProviderSettings { parent, .. } => parent.fetch.is_some(),
            Self::FetchAll(state) => state.is_fetching(),
            Self::DeepFetch { state, .. } => state.is_running(),
            Self::CopilotSetup { state, .. } => state.operation.pending().is_some(),
            Self::List { .. } | Self::FetchOnePrompt(_) | Self::FetchFallbackPrompt(_) => false,
        }
    }

    pub(super) fn has_unsettled_oauth_acknowledgement(&self) -> bool {
        match self {
            Self::OAuthSetup { state, .. } => state.has_unsettled_acknowledgement(),
            Self::Add(state) => state
                .oauth_auth
                .as_ref()
                .is_some_and(|oauth| oauth.has_unsettled_acknowledgement()),
            _ => false,
        }
    }

    /// Sealed compile-time inventory for provider pointer fixtures. There is
    /// intentionally no wildcard: a new provider state cannot compile until
    /// it declares which semantic pointer surface it renders.
    fn pointer_surface_kind(&self) -> ProvidersPointerSurface {
        match self {
            Self::List { .. } => ProvidersPointerSurface::List,
            Self::Add(_) => ProvidersPointerSurface::Add,
            Self::Edit(_) => ProvidersPointerSurface::Edit,
            Self::Headers { .. } => ProvidersPointerSurface::Headers,
            Self::Models { .. } => ProvidersPointerSurface::Models,
            Self::ModelSettings { .. } => ProvidersPointerSurface::ModelSettings,
            Self::ProviderSettings { .. } => ProvidersPointerSurface::ProviderSettings,
            Self::FetchAll(_) => ProvidersPointerSurface::FetchAll,
            Self::FetchOnePrompt(_) => ProvidersPointerSurface::FetchOnePrompt,
            Self::FetchFallbackPrompt(_) => ProvidersPointerSurface::FetchFallbackPrompt,
            Self::DeepFetch { .. } => ProvidersPointerSurface::DeepFetch,
            Self::CopilotSetup { .. } => ProvidersPointerSurface::CopilotSetup,
            Self::OAuthSetup { .. } => ProvidersPointerSurface::OAuthSetup,
        }
    }
}

impl ProvidersPage {
    pub(super) fn paste_oauth(&mut self, text: &str) -> bool {
        let state = match self {
            Self::OAuthSetup { state, .. } if state.has_browser_session() => state,
            Self::Add(state)
                if state.is_step("grok-oauth")
                    && state
                        .oauth_auth
                        .as_ref()
                        .is_some_and(|oauth| oauth.has_browser_session()) =>
            {
                state.oauth_auth.as_mut().expect("guarded OAuth state")
            }
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

fn wrap_oauth_render_lines(lines: Vec<Line<'static>>, width: u16) -> Vec<Line<'static>> {
    let mut wrapped = Vec::new();
    let width = width.max(1);
    for line in lines {
        if line.spans.len() == 1 {
            let span = &line.spans[0];
            if UnicodeWidthStr::width(span.content.as_ref()) > usize::from(width) {
                push_wrapped_text(&mut wrapped, width, span.content.as_ref(), span.style);
                continue;
            }
        }
        wrapped.push(line);
    }
    wrapped
}

fn wrap_oauth_render_lines_with_controls(
    lines: Vec<Line<'static>>,
    controls: Vec<(usize, usize)>,
    width: u16,
) -> (Vec<Line<'static>>, Vec<(usize, usize)>) {
    let mut wrapped = Vec::new();
    let mut remapped = Vec::new();
    let width = width.max(1);
    for (source_line, line) in lines.into_iter().enumerate() {
        let target_line = wrapped.len();
        if line.spans.len() == 1 {
            let span = &line.spans[0];
            if UnicodeWidthStr::width(span.content.as_ref()) > usize::from(width) {
                push_wrapped_text(&mut wrapped, width, span.content.as_ref(), span.style);
            } else {
                wrapped.push(line);
            }
        } else {
            wrapped.push(line);
        }
        remapped.extend(
            controls
                .iter()
                .filter(|(line, _)| *line == source_line)
                .map(|(_, control)| (target_line, *control)),
        );
    }
    (wrapped, remapped)
}

fn oauth_link_target(flow: OAuthFlowView<'_>) -> Option<(&str, &str)> {
    match flow {
        OAuthFlowView::OAuth(state) if state.provider == OAuthProvider::Grok => {
            Some((state.authorize_url()?, "open xai.com authorization page"))
        }
        OAuthFlowView::OAuth(state) if state.provider == OAuthProvider::Codex => {
            let (_, uri, _) = state.device_login()?;
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
            | ProvidersPage::DeepFetch { .. }
            | ProvidersPage::CopilotSetup { .. } => None,
            ProvidersPage::OAuthSetup { state, .. } => {
                state.paste_focused.then_some(&mut state.manual_input)
            }
            ProvidersPage::Add(s) => match s.run.current_step_id() {
                Some("id") => Some(&mut s.id_field),
                Some("url") => Some(&mut s.url_field),
                Some("api-key") => Some(s.api_key_field.as_mut()),
                Some("env-var") => Some(s.env_var_field.as_mut()),
                Some("headers") => s.headers.active_text_field(),
                Some("grok-oauth" | "codex-oauth") => s
                    .oauth_auth
                    .as_mut()
                    .and_then(|state| state.paste_focused.then_some(&mut state.manual_input)),
                _ => None,
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
    /// Retained for compatibility with the pointer fixture shape. Production
    /// never probes a shell or derives a startup-file path: Copilot auth is
    /// daemon-owned.
    pub(super) shell: Option<CopilotShell>,
    /// Always `None` in production; the TUI never writes a shell rc file.
    pub(super) rc_path: Option<PathBuf>,
    /// Retained for compatibility with existing test fixtures.
    pub(super) already_configured: bool,
    /// Action result after the user asks the daemon to inspect auth.
    pub(super) outcome: Option<Result<String, String>>,
    operation: super::shell::PointerOperationGate,
}

impl CopilotSetupState {
    pub(super) fn new() -> Self {
        Self {
            shell: None,
            rc_path: None,
            already_configured: false,
            outcome: None,
            operation: super::shell::PointerOperationGate::default(),
        }
    }

    fn submit(
        &mut self,
        credential_store_path: Option<&std::path::Path>,
        effect: &mut impl CopilotSetupEffect,
    ) {
        let (Some(shell), Some(rc_path)) = (self.shell, self.rc_path.as_deref()) else {
            self.outcome = Some(Ok(
                "Copilot authentication is daemon-owned. Set GH_TOKEN in the daemon's environment or authenticate through the daemon account; no shell files or tokens are handled by the TUI.".into(),
            ));
            return;
        };
        if self.already_configured || self.outcome.is_some() || self.operation.pending().is_some() {
            return;
        }
        let operation_id = self.operation.begin();
        let result = effect.apply(shell, rc_path, credential_store_path);
        self.complete(operation_id, result);
    }

    /// Ask the daemon to acquire and persist Copilot auth. The daemon returns
    /// only an acknowledgement; the TUI never receives or handles the token.
    fn submit_daemon(
        &mut self,
        cx: &mut super::SettingsCx,
        project_root: &std::path::Path,
        provider_id: &str,
    ) {
        if self.already_configured || self.outcome.is_some() || self.operation.pending().is_some() {
            return;
        }
        let operation_id = self.operation.begin();
        let project_root = super::canonical_project_root(project_root);
        let provider_id = provider_id.to_string();
        let client_operation_id = operation_id.0.to_string();
        let expected_request_hash = match super::local_receipt_request_hash(&(
            "setup_copilot_auth",
            &project_root,
            &provider_id,
        )) {
            Ok(hash) => hash,
            Err(error) => {
                self.complete(operation_id, Err(error));
                return;
            }
        };
        cx.queue_simple_mutation(
            super::SettingsEffectTarget {
                surface: "settings.copilot-setup",
                owner: provider_id.clone(),
                revision: Some(operation_id.0.to_string()),
            },
            cockpit_proto::Request::SetupCopilotAuth {
                client_operation_id: client_operation_id.clone(),
                project_root: project_root.clone(),
                provider_id: provider_id.clone(),
            },
            super::SettingsMutationAction::CopilotSetup {
                provider_id,
                client_operation_id,
                project_root,
                expected_request_hash,
            },
        );
        self.outcome = Some(Ok("Copilot setup pending…".into()));
    }

    pub(super) fn apply_daemon_result(&mut self, provider_id: String, result: Result<(), String>) {
        let Some(operation_id) = self.operation.pending() else {
            self.outcome = Some(Err(format!(
                "ignored stale Copilot setup receipt for {provider_id}"
            )));
            return;
        };
        self.outcome = None;
        self.complete(
            operation_id,
            result.map(|()| format!("Copilot authentication configured for {provider_id}")),
        );
    }

    fn complete(
        &mut self,
        operation_id: super::shell::PointerOperationId,
        result: Result<String, String>,
    ) {
        if self.operation.complete(operation_id) {
            self.outcome = Some(result);
        }
    }
}

trait CopilotSetupEffect {
    fn apply(
        &mut self,
        shell: CopilotShell,
        rc_path: &std::path::Path,
        credential_store_path: Option<&std::path::Path>,
    ) -> Result<String, String>;
}

pub(super) fn oauth_setup_confirming_logged_in(
    logged_in: bool,
    in_progress: bool,
    paste_focused: bool,
) -> bool {
    logged_in && !in_progress && !paste_focused
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
    copy: impl FnOnce(&str) -> Result<crate::clipboard::DeliveryResult, crate::clipboard::CopyError>,
) {
    let Some(url) = url else {
        *status = Some(Ok("no OAuth URL yet".to_string()));
        return;
    };
    *status = Some(match copy(url) {
        // `Ok(_)` used to collapse Confirmed and Unverified into the same
        // "copied OAuth URL" wording. This status has no `ToastKind` of
        // its own (unlike the chat-copy toast paths, where
        // `describe_delivered` handles this), so the fix is a wording
        // qualifier rather than a shared helper; the URL is also always
        // reachable another way (rendered directly for the device-code
        // flow, or auto-opened plus a separate "Open" trigger for the
        // browser flow — see `render_device_code_session` and the
        // `authorize_url` render block in this module), so an unverified
        // copy still leaves the user with a working path forward.
        Ok(result) if crate::clipboard::feedback::classify(&result).is_unverified() => Ok(
            "copied OAuth URL (unverified — also reachable via the Open link above)".to_string(),
        ),
        Ok(_) => Ok("copied OAuth URL".to_string()),
        Err(e) => Err(e.to_string()),
    });
}

pub(super) struct AddState {
    pub(super) onboarding: bool,
    pub(super) run: WizardRun,
    pub(super) template_cursor: usize,
    pub(super) wire_api_cursor: usize,
    pub(super) template: Option<&'static ProviderTemplate>,
    pub(super) id_field: TextField,
    pub(super) url_field: TextField,
    pub(super) auth_method_cursor: usize,
    pub(super) api_key_field: Box<TextField>,
    pub(super) env_var_field: Box<TextField>,
    pub(super) test_choice_cursor: usize,
    pub(super) headers: Box<HeaderEditor>,
    pub(super) error: Option<String>,
    pub(super) fetch: Option<FetchHandle>,
    pub(super) saved_provider_id: Option<String>,
    pub(super) copilot_auth: Option<CopilotSetupState>,
    pub(super) oauth_auth: Option<Box<OAuthFlowState>>,
    pub(super) detected_env_offer: Option<String>,
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

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum EditField {
    Url,
}

impl AddState {
    pub(super) fn new() -> Self {
        Self::new_with_onboarding(false)
    }

    pub(super) fn new_with_onboarding(onboarding: bool) -> Self {
        Self {
            onboarding,
            run: WizardRun::new(cockpit_core::wizard::provider_descriptor())
                .expect("built-in provider wizard descriptor is valid"),
            template_cursor: 0,
            wire_api_cursor: 0,
            template: None,
            id_field: TextField::default(),
            url_field: TextField::default(),
            auth_method_cursor: 0,
            api_key_field: Box::new(TextField::default()),
            env_var_field: Box::new(TextField::default()),
            test_choice_cursor: 0,
            headers: Box::new(HeaderEditor::new(Vec::new(), true)),
            error: None,
            fetch: None,
            saved_provider_id: None,
            copilot_auth: None,
            oauth_auth: None,
            detected_env_offer: None,
        }
    }

    pub(super) fn is_step(&self, step: &str) -> bool {
        self.run.current_step_id() == Some(step)
    }

    #[cfg(test)]
    pub(super) fn enter_oauth_for_test(&mut self, state: OAuthFlowState) {
        let step = match state.provider {
            OAuthProvider::Grok => "grok-oauth",
            OAuthProvider::Codex => "codex-oauth",
        };
        self.run.return_to(step).unwrap();
        self.oauth_auth = Some(Box::new(state));
    }

    #[cfg(test)]
    pub(super) fn enter_template_for_test(&mut self, cursor: usize) {
        self.run.return_to("template").unwrap();
        self.template_cursor = cursor;
    }

    pub(super) fn resume_onboarding_validation(&mut self, provider_id: &str) {
        self.run
            .return_to("test-key-choice")
            .expect("provider validation step exists");
        self.saved_provider_id = Some(provider_id.to_string());
        self.error = Some("Resume setup: test the saved credential with the daemon.".into());
    }
}

fn provider_entry_from_add(
    s: &AddState,
    template: &'static ProviderTemplate,
    headers: Vec<HeaderSpec>,
) -> ProviderEntry {
    let wire_api = cockpit_core::wizard::provider_wire_api_for_template(&s.run, template);
    cockpit_core::wizard::provider_entry_for_template_with_wire_api(
        template,
        s.url_field.text().trim_end_matches('/').to_string(),
        headers,
        wire_api,
    )
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
        let referenced_environment = self
            .config
            .providers
            .get(provider_id)
            .into_iter()
            .flat_map(|entry| &entry.headers)
            .flat_map(|header| cockpit_core::envref::referenced_names(&header.value))
            .filter(|name| !name.starts_with("secret:"))
            .collect::<Vec<_>>();
        let daemon_visibility_guidance = result.as_ref().err().and_then(|error| {
            daemon_visibility_guidance(&referenced_environment, error)
        });
        let onboarding_validation = self
            .page
            .downcast_ref::<ProvidersPage>()
            .is_some_and(|page| {
                matches!(
                    page,
                    ProvidersPage::Add(state)
                        if state.onboarding
                            && state.is_step("test-key")
                            && state.saved_provider_id.as_deref() == Some(provider_id)
                )
            });
        let live_validation_succeeded = matches!(
            &result,
            Ok(FetchOutcome::Models { .. } | FetchOutcome::Unsupported)
        );
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
            if matches!(stored, None | Some(OnUnlistedModelsFetch::Ask))
                && !unlisted.is_empty()
                && !onboarding_validation
            {
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
                    Ok(()) => format!(
                        "{}; saving provider catalog…",
                        fetch_success_message(count, catalog)
                    ),
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
                let reason = redact_model_fetch_reason(reason);
                if onboarding_validation {
                    message = format!("live validation unavailable: {reason}");
                } else {
                    self.clear_fetch_handle(provider_id);
                    self.page = super::providers_page(ProvidersPage::FetchFallbackPrompt(
                        FetchFallbackPromptState {
                            provider_id: provider_id.to_string(),
                            models,
                            catalog,
                            reason,
                            cursor: 0,
                        },
                    ));
                    return;
                }
            }
        } else if self.config.providers.contains_key(provider_id) {
            match result {
                Ok(FetchOutcome::Unsupported) => {
                    if let Some(entry) = self.config.providers.get_mut(provider_id) {
                        entry.mark_model_fetch_unsupported();
                    }
                    message = match self.save_config() {
                        Ok(()) => "provider has no /models endpoint; saving fetch status…".into(),
                        Err(error) => format!("fetch status save failed: {error}"),
                    };
                }
                Err(e) => {
                    let reason = redact_model_fetch_reason(e.as_str());
                    if let Some(entry) = self.config.providers.get_mut(provider_id) {
                        entry.mark_model_fetch_failed_kept_existing(reason.clone());
                    }
                    message = match self.save_config() {
                        Ok(()) if daemon_visibility_guidance.is_some() => format!(
                            "{}; saving failure status…",
                            daemon_visibility_guidance.as_deref().unwrap_or_default()
                        ),
                        Ok(()) => format!("fetch failed: {reason}; saving failure status…"),
                        Err(error) => {
                            format!("fetch failed: {reason}; status save failed: {error}")
                        }
                    };
                }
                Ok(FetchOutcome::Models { .. }) | Ok(FetchOutcome::FallbackAvailable { .. }) => {
                    unreachable!()
                }
                Ok(FetchOutcome::UnlistedModelsPreview { .. } | FetchOutcome::Error { .. }) => {
                    unreachable!("FetchHandle converts protocol-only outcomes into errors")
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
                    if s.is_step("fetching") {
                        let _ = s.run.submit(WizardAnswer::Acknowledged);
                    } else if s.is_step("test-key") && live_validation_succeeded {
                        let _ = s.run.submit(WizardAnswer::Acknowledged);
                    }
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

fn daemon_visibility_guidance(referenced: &[String], error: &str) -> Option<String> {
    if referenced.is_empty()
        || !(error.contains("references missing environment variable")
            || error.contains("Configured Authorization refs were unset"))
    {
        return None;
    }
    Some(format!(
        "The daemon cannot resolve {}. Go back and choose ‘Copy detected value into vault’, or export the variable where the daemon starts",
        referenced
            .iter()
            .map(|name| format!("${name}"))
            .collect::<Vec<_>>()
            .join(", ")
    ))
}
impl SettingsCx {
    /// All provider side effects use the project selected for this dialog;
    /// config editing must never silently retarget to the process cwd.
    fn provider_fetch_root(&self) -> String {
        self.active_project_root
            .as_deref()
            .or(self.picker_cwd.as_deref())
            .or_else(|| self.config_path.parent())
            .unwrap_or_else(|| std::path::Path::new("."))
            .display()
            .to_string()
    }

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
                        "saving on-unlisted-models policy ({})…",
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
                            Ok(0) => {
                                format!("deleted `{id}`; stored secret cleanup completed")
                            }
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
            ProvidersPage::DeepFetch { state, parent } => {
                self.handle_deep_fetch_key(key, state, parent)
            }
            ProvidersPage::CopilotSetup { state, parent } => {
                self.handle_copilot_setup_key(key, state, parent)
            }
            ProvidersPage::OAuthSetup { state, parent } => {
                let outcome = handle_oauth_flow_key(key, state, OAuthHost::Standalone);
                self.pending_oauth_action = outcome.action;
                match outcome.nav {
                    OAuthNav::Stay => Nav::Stay,
                    OAuthNav::Back | OAuthNav::Confirm => {
                        let owned = std::mem::replace(
                            parent,
                            Box::new(EditState::new(String::new(), ProviderEntry::default())),
                        );
                        Nav::Replace(super::providers_page(ProvidersPage::Edit(*owned)))
                    }
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
        self.save_and_fetch_provider_with_detected_env(s, id, entry, template, None);
    }

    fn save_and_fetch_provider_with_detected_env(
        &mut self,
        s: &mut AddState,
        id: String,
        entry: ProviderEntry,
        template: &'static ProviderTemplate,
        detected_env: Option<String>,
    ) {
        // The daemon owns the save and may finish after this dialog (or the
        // process) is gone. Persist its validation continuation before the
        // mutation is handed off so Escape can never detach a committed
        // provider from first-run onboarding.
        if s.onboarding
            && let Err(error) =
                cockpit_core::welcome::persist_onboarding_provider_pending_validation(&id)
        {
            s.error = Some(format!(
                "could not record setup progress before saving provider: {error}"
            ));
            return;
        }
        self.config.providers.insert(id.clone(), entry.clone());
        self.pending_provider_add = Some(super::PendingProviderAdd {
            id,
            entry,
            supports_models_endpoint: template.supports_models_endpoint,
            detected_environment_copy: detected_env.map(|variable| {
                super::DetectedEnvironmentCopy {
                    template_id: template.id.to_string(),
                    variable,
                }
            }),
            onboarding: s.onboarding,
        });
        match self.save_config() {
            Ok(()) => {
                // The mutation now owns the wizard. Advance to the explicit
                // saving step as soon as it is queued, rather than leaving
                // the completed OAuth confirmation actionable until the
                // daemon receipt happens to arrive. The completion reducer
                // advances from `saving` to the fetch/test terminal path.
                let _ = s.run.submit(WizardAnswer::Acknowledged);
                s.error = Some("saving provider…".into());
            }
            Err(e) => {
                self.reject_pending_provider_add(e);
            }
        }
    }

    pub(super) fn adopt_provider_add_completion(
        &mut self,
        s: &mut AddState,
        completion: Result<(String, ProviderEntry, bool), String>,
    ) {
        let (id, entry, supports_models_endpoint) = match completion {
            Ok(committed) => committed,
            Err(error) => {
                s.run
                    .return_to("template")
                    .expect("provider template step exists");
                s.saved_provider_id = None;
                s.fetch = None;
                s.error = Some(format!(
                    "save failed: {error}. Choose a provider to try again."
                ));
                return;
            }
        };
        s.saved_provider_id = Some(id.clone());
        let notice = self.last_secret_notice.take();
        if !s.is_step("saving") {
            let _ = s.run.submit(WizardAnswer::Acknowledged);
        }
        if s.is_step("saving") {
            let _ = s.run.submit(WizardAnswer::Acknowledged);
        }
        if s.is_step("fetching") {
            s.error = Some(match notice {
                Some(notice) => format!("saved. {notice} Fetching /models…"),
                None => "saved. Fetching /models…".into(),
            });
            s.fetch = Some(FetchHandle::spawn(
                self.lifecycle.clone(),
                id,
                entry,
                self.provider_fetch_root(),
            ));
            let _ = s.run.submit(WizardAnswer::Acknowledged);
        } else if s.is_step("test-key-choice") {
            s.error = Some(match notice {
                Some(notice) => format!("saved. {notice}"),
                None => "saved.".into(),
            });
        } else if !supports_models_endpoint {
            s.error = Some(match notice {
                Some(notice) => format!("saved. {notice} Provider has no /models endpoint"),
                None => "saved. provider has no /models endpoint".into(),
            });
        } else {
            s.error = Some(match notice {
                Some(notice) => format!("saved. {notice}"),
                None => "saved.".into(),
            });
        }
    }

    fn handle_add_key(&mut self, key: KeyEvent, s: &mut AddState) -> Nav {
        // Back/escape unconditionally returns to the list.
        let oauth_step = matches!(s.run.current_step_id(), Some("grok-oauth" | "codex-oauth"));
        if matches!(key.code, KeyCode::Esc) && !oauth_step {
            s.run.abort();
            return Nav::Replace(super::providers_page(ProvidersPage::List {
                cursor: initial_list_cursor(&self.config),
                status: None,
                delete_pending: false,
            }));
        }

        match s.run.current_step_id() {
            Some("template") => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    s.template_cursor = crate::tui::nav::wrap_prev(
                        s.template_cursor,
                        onboarding_ordered_templates().len(),
                    );
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    s.template_cursor = crate::tui::nav::wrap_next(
                        s.template_cursor,
                        onboarding_ordered_templates().len(),
                    );
                }
                KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                    let ordered = onboarding_ordered_templates();
                    let t = ordered[s.template_cursor];
                    if let Some(reason) = t.disabled_reason() {
                        s.error = Some(reason.to_string());
                        return Nav::Stay;
                    }
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
                    *s.headers = HeaderEditor::new_for_provider(
                        s.id_field.text(),
                        templates::default_headers_for(t),
                        /* show_continue */ true,
                    );
                    s.env_var_field.set(
                        cockpit_core::providers::detected_env_var(t)
                            .or(t.default_env_var)
                            .or_else(|| t.env_var_candidates.first().copied())
                            .unwrap_or("API_KEY"),
                    );
                    if let Some(detected) = cockpit_core::providers::detected_env_var(t) {
                        s.auth_method_cursor = 1;
                        s.detected_env_offer = Some(detected.to_string());
                    }
                    s.wire_api_cursor = 0;
                    s.error = None;
                    s.run
                        .submit(WizardAnswer::Select(t.id.to_string()))
                        .expect("provider template is a valid select answer");
                }
                _ => {}
            },
            Some("wire-api") => {
                const WIRE_APIS: [&str; 4] = ["auto", "completions", "responses", "anthropic"];
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        s.wire_api_cursor =
                            crate::tui::nav::wrap_prev(s.wire_api_cursor, WIRE_APIS.len());
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        s.wire_api_cursor =
                            crate::tui::nav::wrap_next(s.wire_api_cursor, WIRE_APIS.len());
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                        if let Err(error) = s.run.submit(WizardAnswer::Select(
                            WIRE_APIS[s.wire_api_cursor].to_string(),
                        )) {
                            s.error = Some(error);
                        } else {
                            s.error = None;
                        }
                    }
                    _ => {}
                }
            }
            Some("id") => match key.code {
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
                        s.headers.set_provider_id(&id);
                        if let Err(error) = s.run.submit(WizardAnswer::Text(id)) {
                            s.error = Some(error);
                        }
                    }
                }
                _ => {
                    s.id_field.handle_key(key);
                }
            },
            Some("url") => match key.code {
                KeyCode::Enter => {
                    if !valid_url(s.url_field.text()) {
                        s.error = Some("url must start with http:// or https://".into());
                    } else {
                        s.error = None;
                        let url = s.url_field.text().to_string();
                        if let Err(error) = s.run.submit(WizardAnswer::Text(url)) {
                            s.error = Some(error);
                        } else {
                            match s.run.current_step_id() {
                                Some("copilot-auth") => {
                                    s.copilot_auth = Some(CopilotSetupState::new());
                                }
                                #[cfg(feature = "grok-subscription")]
                                Some("grok-oauth") => {
                                    s.oauth_auth =
                                        Some(Box::new(OAuthFlowState::new(OAuthProvider::Grok)));
                                }
                                Some("codex-oauth") => {
                                    s.oauth_auth =
                                        Some(Box::new(OAuthFlowState::new(OAuthProvider::Codex)));
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {
                    s.url_field.handle_key(key);
                }
            },
            Some("auth-method") => {
                const AUTH_METHODS: [&str; 4] = [
                    "paste-key",
                    "env-var",
                    "advanced-headers",
                    "copy-detected-env",
                ];
                let choice_count = if s.detected_env_offer.is_some() { 4 } else { 3 };
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        s.auth_method_cursor =
                            crate::tui::nav::wrap_prev(s.auth_method_cursor, choice_count);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        s.auth_method_cursor =
                            crate::tui::nav::wrap_next(s.auth_method_cursor, choice_count);
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                        let choice = AUTH_METHODS[s.auth_method_cursor];
                        if choice == "copy-detected-env" {
                            if let Err(error) =
                                s.run.submit(WizardAnswer::Select(choice.to_string()))
                            {
                                s.error = Some(error);
                                return Nav::Stay;
                            }
                            let env_var = s
                                .detected_env_offer
                                .as_deref()
                                .expect("copy choice requires detected env");
                            let template = s.template.expect("template chosen");
                            let id = s.id_field.text().trim().to_string();
                            // This process detected the variable, so it owns
                            // the fallback copy. Asking the daemon to read it
                            // again would make this option useless precisely
                            // when a long-lived daemon cannot see a shell-local
                            // export. Keep the bytes zeroizing while building
                            // the same staged-secret mutation as a pasted key.
                            let value = match std::env::var(env_var) {
                                Ok(value) if !value.trim().is_empty() => {
                                    zeroize::Zeroizing::new(value)
                                }
                                _ => {
                                    s.error = Some(format!(
                                        "${env_var} is no longer available in this process; paste the key instead"
                                    ));
                                    return Nav::Stay;
                                }
                            };
                            let headers =
                                templates::headers_for_pasted_key(template, value.as_str());
                            let entry = provider_entry_from_add(s, template, headers);
                            self.save_and_fetch_provider(s, id, entry, template);
                            return Nav::Stay;
                        }
                        if let Err(error) = s.run.submit(WizardAnswer::Select(choice.to_string())) {
                            s.error = Some(error);
                        } else {
                            s.error = None;
                        }
                    }
                    _ => {}
                }
            }
            Some("api-key") => match key.code {
                KeyCode::Enter => {
                    let key_text = s.api_key_field.text().trim().to_string();
                    if key_text.is_empty() {
                        s.error = Some("paste a non-empty API key".into());
                    } else if let Err(error) = s.run.submit(WizardAnswer::Secret(key_text.clone()))
                    {
                        s.error = Some(error);
                    } else {
                        let template = s.template.expect("template chosen");
                        let id = s.id_field.text().trim().to_string();
                        let entry = provider_entry_from_add(
                            s,
                            template,
                            templates::headers_for_pasted_key(template, &key_text),
                        );
                        self.save_and_fetch_provider(s, id, entry, template);
                    }
                }
                _ => {
                    s.api_key_field.handle_key(key);
                }
            },
            Some("env-var") => match key.code {
                KeyCode::Enter => {
                    let env_var = s.env_var_field.text().trim().to_string();
                    if env_var.is_empty() {
                        s.error = Some("environment variable name cannot be empty".into());
                    } else if let Err(error) = s.run.submit(WizardAnswer::Text(env_var.clone())) {
                        s.error = Some(error);
                    } else {
                        let template = s.template.expect("template chosen");
                        let id = s.id_field.text().trim().to_string();
                        let entry = provider_entry_from_add(
                            s,
                            template,
                            templates::headers_for_env_var(template, &env_var),
                        );
                        self.save_and_fetch_provider(s, id, entry, template);
                    }
                }
                _ => {
                    s.env_var_field.handle_key(key);
                }
            },
            Some("headers") => {
                match s.headers.handle_key(key) {
                    // `Save` is unreachable in the Add wizard (it shows the
                    // `[continue →]` row, never `[save changes]`), but the
                    // match stays exhaustive.
                    HeaderResult::Stay | HeaderResult::Save => return Nav::Stay,
                    HeaderResult::Back => {
                        s.error = None;
                        s.run.return_to("url").expect("provider URL step exists");
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
            Some("copilot-auth") => match key.code {
                KeyCode::Enter => {
                    let state = s
                        .copilot_auth
                        .as_mut()
                        .expect("Copilot descriptor step initializes state");
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
                    // A newly-added provider is not persisted until this
                    // wizard completes. Save it first, then use the Edit
                    // page's daemon-owned Copilot action if configuration is
                    // available in the daemon environment.
                    let template = s.template.expect("template chosen");
                    let id = s.id_field.text().trim().to_string();
                    let entry = provider_entry_from_add(
                        s,
                        template,
                        templates::default_headers_for(template),
                    );
                    self.save_and_fetch_provider(s, id, entry, template);
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
            Some("grok-oauth" | "codex-oauth") => {
                let nav = {
                    let state = s
                        .oauth_auth
                        .as_mut()
                        .expect("OAuth descriptor step initializes state");
                    let outcome = handle_oauth_flow_key(key, state, OAuthHost::AddWizard);
                    self.pending_oauth_action = outcome.action;
                    outcome.nav
                };
                match nav {
                    OAuthNav::Stay => {}
                    OAuthNav::Back => {
                        s.run.return_to("url").expect("provider URL step exists");
                        s.oauth_auth = None;
                        return Nav::Stay;
                    }
                    OAuthNav::Confirm => {
                        let template = s.template.expect("template chosen");
                        let id = s.id_field.text().trim().to_string();
                        let entry = provider_entry_from_add(s, template, Vec::new());
                        self.save_and_fetch_provider(s, id, entry, template);
                    }
                }
            }
            Some("test-key-choice") => {
                const TEST_CHOICES: [&str; 2] = ["test", "skip-test"];
                let choice_count = if s.onboarding { 1 } else { TEST_CHOICES.len() };
                match key.code {
                    KeyCode::Up | KeyCode::Char('k') => {
                        s.test_choice_cursor =
                            crate::tui::nav::wrap_prev(s.test_choice_cursor, choice_count);
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        s.test_choice_cursor =
                            crate::tui::nav::wrap_next(s.test_choice_cursor, choice_count);
                    }
                    KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                        let choice = TEST_CHOICES[s.test_choice_cursor];
                        if s.onboarding && choice == "skip-test" {
                            s.error = Some(
                                "Onboarding requires a successful live credential validation. Press Esc to cancel and resume later."
                                    .into(),
                            );
                        } else if let Err(error) =
                            s.run.submit(WizardAnswer::Select(choice.to_string()))
                        {
                            s.error = Some(error);
                        } else if choice == "skip-test" {
                            s.error = Some(
                                "key saved but unverified — it will be tested on your first message."
                                    .into(),
                            );
                        } else if let Some(id) = s.saved_provider_id.clone() {
                            if let Some(entry) = self.config.providers.get(&id).cloned() {
                                s.error = Some("Testing key via /models…".into());
                                s.fetch = Some(FetchHandle::spawn(
                                    self.lifecycle.clone(),
                                    id,
                                    entry,
                                    self.provider_fetch_root(),
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Some("test-skipped") => {
                if matches!(key.code, KeyCode::Enter) {
                    let _ = s.run.submit(WizardAnswer::Acknowledged);
                }
            }
            // A failed probe is explicit evidence that this setup is offline
            // or otherwise unable to validate now. First-run onboarding may
            // continue through the manual model path in that limited state.
            Some("test-key") if s.fetch.is_none() => {
                if matches!(key.code, KeyCode::Char('o') | KeyCode::Char('O')) {
                    s.error = Some(
                        "Live validation was attempted but setup is continuing offline; validate before first use."
                            .into(),
                    );
                    let _ = s.run.submit(WizardAnswer::Acknowledged);
                }
            }
            Some("saving" | "fetching") => {
                // Disable input while in-flight, except Esc (handled above).
            }
            Some("done") | None if s.run.is_complete() || s.is_step("done") => {
                if matches!(key.code, KeyCode::Enter) {
                    return Nav::Replace(super::providers_page(ProvidersPage::List {
                        cursor: initial_list_cursor(&self.config),
                        status: s.error.clone(),
                        delete_pending: false,
                    }));
                }
            }
            Some(other) => {
                s.error = Some(format!("unsupported provider wizard step `{other}`"));
            }
            None => {}
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
        // Transactional: keep the prior entry so a failed disk write leaves
        // effective in-memory config unchanged (failed multimodal saves must
        // not publish drafts as authoritative).
        let previous = self.config.providers.get(&s.provider_id).cloned();
        self.config
            .providers
            .insert(s.provider_id.clone(), (*s.entry).clone());
        let provider_is_unchanged = self
            .original_config
            .providers
            .get(&s.provider_id)
            .is_some_and(|original| provider_entries_equal(original, s.entry.as_ref()));
        match self.save_config() {
            // A no-op save has no daemon effect to settle. Reporting it as
            // pending would leave the Models/Headers sub-pages permanently
            // on "saving provider…" even though their visible state is
            // already authoritative.
            Ok(()) if provider_is_unchanged => Some("saved".to_string()),
            Ok(()) => Some("saving provider…".to_string()),
            Err(error) => {
                match previous {
                    Some(entry) => {
                        self.config.providers.insert(s.provider_id.clone(), entry);
                    }
                    None => {
                        self.config.providers.remove(&s.provider_id);
                    }
                }
                Some(format!("save failed: {error}"))
            }
        }
    }

    fn apply_active_prompt_cache_retention_from_editor(&mut self, editor: &SettingsEditor) {
        let Some(retention) = editor.active_prompt_cache_retention() else {
            return;
        };
        let Some(active) = self.config.active_model.as_mut() else {
            return;
        };
        active.prompt_cache_retention = (!retention.is_default()).then_some(retention);
    }

    fn provider_oauth_logged_in(&self, provider: OAuthProvider) -> Option<bool> {
        let provider_id = match provider {
            OAuthProvider::Grok => "grok-oauth",
            OAuthProvider::Codex => cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
        };
        // The inventory is deliberately metadata-only. Rendering consumes a
        // cache miss asynchronously instead of waiting on the daemon socket.
        self.cached_secret_inventory_contains(
            provider_id,
            Some(cockpit_proto::SecretInventoryKind::CredentialRecord),
        )
    }

    fn provider_oauth_status_value(&self, provider: OAuthProvider) -> String {
        match self.provider_oauth_logged_in(provider) {
            Some(true) => "logged in — Enter: Sign out",
            Some(false) => "not logged in — Enter: Sign in",
            None => "checking daemon auth status…",
        }
        .to_string()
    }

    fn logout_provider_oauth(&mut self, provider: OAuthProvider) -> Result<(), String> {
        let provider_id = match provider {
            OAuthProvider::Grok => "grok-oauth",
            OAuthProvider::Codex => cockpit_core::auth::codex_oauth::CREDENTIAL_KEY,
        }
        .to_string();
        let project_root = self
            .active_project_root
            .as_deref()
            .or(self.picker_cwd.as_deref())
            .or_else(|| self.config_path.parent())
            .ok_or_else(|| "resolving provider logout workspace: no project context".to_string())?;
        let project_root = super::canonical_project_root(project_root);
        let client_operation_id = uuid::Uuid::new_v4().to_string();
        let expected_request_hash = super::local_receipt_request_hash(&(
            "delete_provider_credential",
            &provider_id,
            &Some(project_root.clone()),
        ))?;
        self.queue_simple_mutation(
            super::SettingsEffectTarget {
                surface: "settings.provider-logout",
                owner: provider_id.clone(),
                revision: Some(client_operation_id.clone()),
            },
            cockpit_proto::Request::DeleteProviderCredential {
                client_operation_id: client_operation_id.clone(),
                provider_id: provider_id.clone(),
                project_root: Some(project_root.clone()),
            },
            super::SettingsMutationAction::ProviderCredentialDelete {
                provider_id,
                client_operation_id,
                project_root,
                expected_request_hash,
            },
        );
        Ok(())
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
                let save_failed = status
                    .as_deref()
                    .is_some_and(|msg| msg.starts_with("save failed:"));
                if save_failed {
                    s.status = status;
                } else {
                    s.fetch = Some(FetchHandle::spawn(
                        self.lifecycle.clone(),
                        s.provider_id.clone(),
                        (*s.entry).clone(),
                        self.provider_fetch_root(),
                    ));
                    s.status = Some("refetching /models…".into());
                }
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
                        Ok(0) => {
                            format!(
                                "deleted `{}`; stored secret cleanup completed",
                                s.provider_id
                            )
                        }
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
                let editor = HeaderEditor::new_for_provider(
                    &s.provider_id,
                    s.entry.headers.clone(),
                    /* show_continue */ false,
                );
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
                if self.provider_oauth_logged_in(provider) == Some(true) {
                    s.status = Some(match self.logout_provider_oauth(provider) {
                        Ok(()) => "signing out…".into(),
                        Err(error) => format!("sign out failed: {error}"),
                    });
                    return Nav::Stay;
                }
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
                let save_failed = status
                    .as_deref()
                    .is_some_and(|msg| msg.starts_with("save failed:"));
                if save_failed {
                    s.status = status;
                } else {
                    s.fetch = Some(FetchHandle::spawn(
                        self.lifecycle.clone(),
                        s.provider_id.clone(),
                        (*s.entry).clone(),
                        self.provider_fetch_root(),
                    ));
                    s.status = Some("refetching /models…".into());
                }
            }
            Some(EditAction::DeepFetch) => {
                let owned =
                    std::mem::replace(s, EditState::new(String::new(), ProviderEntry::default()));
                match DeepFetchState::prepare_from_config(&self.config, &owned.provider_id) {
                    Ok(state) => {
                        return Nav::Replace(super::providers_page(ProvidersPage::DeepFetch {
                            state,
                            parent: Box::new(owned),
                        }));
                    }
                    Err(error) => {
                        let mut owned = owned;
                        owned.status = Some(error);
                        return Nav::Replace(super::providers_page(ProvidersPage::Edit(owned)));
                    }
                }
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
            if let Err(error) = cockpit_config::config::providers::validate_provider_headers(
                &parent.provider_id,
                &editor.rows,
            ) {
                editor.status = Some(error.to_string());
                return Nav::Stay;
            }
            parent.entry.headers = editor.rows.clone();
            let _ = self.commit_edit_entry(parent);
            return Nav::Close;
        }
        match editor.handle_key(key) {
            HeaderResult::Stay | HeaderResult::Continue => Nav::Stay,
            HeaderResult::Save => {
                if let Err(error) = cockpit_config::config::providers::validate_provider_headers(
                    &parent.provider_id,
                    &editor.rows,
                ) {
                    editor.status = Some(error.to_string());
                    return Nav::Stay;
                }
                // `[save changes]` / `s`: fold the live header rows into the
                // parent entry, commit to disk, and STAY on the sub-page.
                parent.entry.headers = editor.rows.clone();
                parent.status = self.commit_edit_entry(parent);
                Nav::Stay
            }
            HeaderResult::Back => {
                if let Err(error) = cockpit_config::config::providers::validate_provider_headers(
                    &parent.provider_id,
                    &editor.rows,
                ) {
                    editor.status = Some(error.to_string());
                    return Nav::Stay;
                }
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
                let settings = SettingsEditor::for_model_with_generation(
                    &parent.provider_id,
                    &seed_entry,
                    &model_id,
                    self.config.resolution_generation.max(1),
                )
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
        // Keep multimodal lifecycle in sync with live model rows + config gen.
        // Snapshot resolver inputs from models.rows so unsaved reappearance uses
        // the live row, not a stale parent.entry models vector.
        let mut live_entry = parent.entry.clone();
        live_entry.models = models.rows.clone();
        editor.sync_multimodal_lifecycle(
            &parent.provider_id,
            &live_entry,
            models,
            self.config.resolution_generation.max(1),
        );
        if editor.active_text_field().is_none() && matches!(key.code, KeyCode::Char('q')) {
            // Same no-auto-save rule as Back for dirty media capability drafts.
            if editor.multimodal_leave_blocked() {
                if editor
                    .status
                    .as_deref()
                    .is_some_and(|s| s.contains("discard draft and leave"))
                {
                    editor.discard_multimodal_draft(&parent.entry);
                } else {
                    editor.status = Some(
                        "media capability draft dirty: press s to save, D to discard, or q/Esc again to discard draft and leave"
                            .into(),
                    );
                    return Nav::Stay;
                }
            }
            let mut tmp = parent.entry.clone();
            tmp.models = models.rows.clone();
            editor.write_into(&mut tmp);
            parent.entry.models = tmp.models;
            self.apply_active_prompt_cache_retention_from_editor(editor);
            let _ = self.commit_edit_entry(parent);
            return Nav::Close;
        }
        // Multimodal recovery / refresh keys that need the live entry.
        if editor.active_text_field().is_none() {
            match key.code {
                KeyCode::Char('r') if editor.multimodal().is_some() => {
                    if let Some(refresh_id) = editor.begin_multimodal_refresh() {
                        // Synchronous refresh against the live entry (no network
                        // fetch in this dialog — re-resolve detected metadata).
                        editor.complete_multimodal_refresh_success(refresh_id, &parent.entry);
                    }
                    return Nav::Stay;
                }
                KeyCode::Char('D') if editor.multimodal_action("Discard", &parent.entry) => {
                    return Nav::Stay;
                }
                KeyCode::Char('R') if editor.multimodal_action("Retry", &parent.entry) => {
                    // Refresh Retry re-enters Refreshing; complete local re-resolve.
                    if let Some(mm) = editor.multimodal()
                        && let crate::tui::settings::multimodal_capability_editor::RefreshPhase::Refreshing {
                            refresh_id: rid,
                            ..
                        } = mm.refresh
                    {
                        let mut live = parent.entry.clone();
                        live.models = models.rows.clone();
                        editor.complete_multimodal_refresh_success(rid, &live);
                        return Nav::Stay;
                    }
                    // Save Retry re-enters Saving; complete the disk write now.
                    if let Some((
                        save_id,
                        provider_id,
                        model_id,
                        selection_generation,
                        base_config_generation,
                    )) = editor.pending_multimodal_save()
                    {
                        let live_gen = self.config.resolution_generation.max(1);
                        if live_gen != base_config_generation {
                            editor.complete_multimodal_save_conflict(
                                save_id,
                                &provider_id,
                                &model_id,
                                selection_generation,
                                base_config_generation,
                                live_gen,
                                &parent.entry,
                            );
                            return Nav::Stay;
                        }
                        let prior_parent_entry = parent.entry.clone();
                        let mut tmp = parent.entry.clone();
                        tmp.models = models.rows.clone();
                        editor.write_into(&mut tmp);
                        parent.entry.models = tmp.models.clone();
                        self.apply_active_prompt_cache_retention_from_editor(editor);
                        parent.status = self.commit_edit_entry(parent);
                        match &parent.status {
                            Some(msg) if msg.to_ascii_lowercase().contains("fail") => {
                                parent.entry = prior_parent_entry;
                                models.rows = parent.entry.models.clone();
                                editor.complete_multimodal_save_failure(
                                    save_id,
                                    &provider_id,
                                    &model_id,
                                    selection_generation,
                                    base_config_generation,
                                    msg.clone(),
                                );
                            }
                            _ => {
                                let saved_generation = self.config.resolution_generation.max(1);
                                editor.complete_multimodal_save_success(
                                    save_id,
                                    &provider_id,
                                    &model_id,
                                    selection_generation,
                                    base_config_generation,
                                    saved_generation,
                                    &parent.entry,
                                );
                            }
                        }
                    }
                    return Nav::Stay;
                }
                KeyCode::Char('L') if editor.multimodal_action("Reload", &parent.entry) => {
                    return Nav::Stay;
                }
                KeyCode::Char('A') if editor.multimodal_action("Reapply", &parent.entry) => {
                    return Nav::Stay;
                }
                KeyCode::Char('B') if editor.multimodal_action("Rebind", &parent.entry) => {
                    return Nav::Stay;
                }
                KeyCode::Char('U') if editor.multimodal_action("Dismiss", &parent.entry) => {
                    return Nav::Stay;
                }
                _ => {}
            }
        }
        match editor.handle_key(key) {
            SettingsResult::Stay => Nav::Stay,
            SettingsResult::Save => {
                // `[save changes]` / `s`: write the overrides into the live
                // model rows, commit to disk, and STAY on the sub-dialog.
                // Multimodal media rows use the generation-keyed save machine.
                let pending_mm = editor.begin_multimodal_save();
                // Detect concurrent config change before mutating memory.
                if let Some((
                    save_id,
                    provider_id,
                    model_id,
                    selection_generation,
                    base_config_generation,
                )) = pending_mm.as_ref()
                {
                    let live_gen = self.config.resolution_generation.max(1);
                    if live_gen != *base_config_generation {
                        editor.complete_multimodal_save_conflict(
                            *save_id,
                            provider_id,
                            model_id,
                            *selection_generation,
                            *base_config_generation,
                            live_gen,
                            &parent.entry,
                        );
                        return Nav::Stay;
                    }
                }
                // Snapshot authoritative entry before staging drafts so a failed
                // save can restore parent.entry for Reload/Discard recovery.
                let prior_parent_entry = parent.entry.clone();
                let mut tmp = parent.entry.clone();
                tmp.models = models.rows.clone();
                editor.write_into(&mut tmp);
                parent.entry.models = tmp.models.clone();
                self.apply_active_prompt_cache_retention_from_editor(editor);
                parent.status = self.commit_edit_entry(parent);
                if let Some((
                    save_id,
                    provider_id,
                    model_id,
                    selection_generation,
                    base_config_generation,
                )) = pending_mm
                {
                    match &parent.status {
                        Some(msg) if msg.to_ascii_lowercase().contains("fail") => {
                            // Leave draft in the multimodal editor; restore
                            // parent entry so recovery snapshots are authoritative.
                            parent.entry = prior_parent_entry;
                            models.rows = parent.entry.models.clone();
                            editor.complete_multimodal_save_failure(
                                save_id,
                                &provider_id,
                                &model_id,
                                selection_generation,
                                base_config_generation,
                                msg.clone(),
                            );
                        }
                        _ => {
                            let saved_generation = self.config.resolution_generation.max(1);
                            editor.complete_multimodal_save_success(
                                save_id,
                                &provider_id,
                                &model_id,
                                selection_generation,
                                base_config_generation,
                                saved_generation,
                                &parent.entry,
                            );
                        }
                    }
                }
                Nav::Stay
            }
            SettingsResult::Back => {
                // Media capability drafts never auto-save on leave: require
                // explicit `s` save, or `D` discard, or confirm discard leave.
                if editor.multimodal_leave_blocked() {
                    if editor
                        .status
                        .as_deref()
                        .is_some_and(|s| s.contains("discard draft and leave"))
                    {
                        editor.discard_multimodal_draft(&parent.entry);
                    } else {
                        editor.status = Some(
                            "media capability draft dirty: press s to save, D to discard, or Esc again to discard draft and leave"
                                .into(),
                        );
                        return Nav::Stay;
                    }
                }
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
                // Persist non-media settings immediately; multimodal drafts
                // above are either clean or explicitly discarded.
                owned.entry.models = tmp.models.clone();
                self.apply_active_prompt_cache_retention_from_editor(editor);
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
                return self.commit_provider_mutation(super::ProviderMutationNavigation::Edit {
                    provider_id: s.provider_id.clone(),
                    status: fetch_success_message(count, s.catalog),
                });
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
                    edit.fetch = Some(FetchHandle::spawn(
                        self.lifecycle.clone(),
                        s.provider_id.clone(),
                        entry,
                        self.provider_fetch_root(),
                    ));
                    return Nav::Replace(super::providers_page(ProvidersPage::Edit(edit)));
                }
                1 => {
                    if let Some(entry) = self.config.providers.get_mut(&s.provider_id) {
                        entry.mark_model_fetch_failed_kept_existing(s.reason.clone());
                    }
                    return self.commit_provider_mutation(
                        super::ProviderMutationNavigation::Edit {
                            provider_id: s.provider_id.clone(),
                            status: "kept existing catalog after live fetch failure".into(),
                        },
                    );
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
                    return self.commit_provider_mutation(
                        super::ProviderMutationNavigation::Edit {
                            provider_id: s.provider_id.clone(),
                            status: fetch_success_message(count, s.catalog),
                        },
                    );
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

                let Some(project_root) = self
                    .active_project_root
                    .as_deref()
                    .or(self.picker_cwd.as_deref())
                    .or_else(|| self.config_path.parent())
                else {
                    s.outcome = Some(Err("unable to resolve the provider workspace".into()));
                    return Nav::Stay;
                };
                let project_root = project_root.to_path_buf();
                let provider_id = parent.provider_id.clone();
                s.submit_daemon(self, &project_root, &provider_id);
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
            ProvidersPage::DeepFetch { state, .. } => self.render_deep_fetch(frame, area, state),
            ProvidersPage::CopilotSetup { state, parent } => {
                self.render_copilot_setup(frame, area, state, &parent.provider_id)
            }
            ProvidersPage::OAuthSetup { state, parent } => {
                self.render_oauth_setup(frame, area, state, &parent.provider_id, links)
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
        let mut bindings = Vec::new();
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
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::RefetchAll,
            ),
        ));
        lines.push(Line::from(vec![
            Span::raw(if button_selected { "▸ " } else { "  " }),
            Span::styled("[refetch provider models]".to_string(), button_style),
        ]));
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::Add,
            ),
        ));
        lines.push(Line::from("  [+ add provider]"));
        // Pointer/keyboard control for the global on-unlisted-models policy.
        // It has no own cursor row, so the provider list keeps its simple
        // index map.
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::CycleUnlistedPolicy,
            ),
        ));
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
                let entry = self.config.providers.get(id.as_str()).unwrap();
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
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::Open(
                            super::pointer_actions::ProviderId((*id).clone()),
                        ),
                    ),
                ));
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
            if !delete_pending
                && let Some(id) = cursor.checked_sub(1).and_then(|index| ids.get(index))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::BeginDelete(
                            super::pointer_actions::ProviderId((*id).clone()),
                        ),
                    ),
                ));
                lines.push(Line::from("  [Delete]"));
            }
        }
        if delete_pending && let Some(id) = cursor.checked_sub(1).and_then(|index| ids.get(index)) {
            lines.push(Line::default());
            lines.push(Line::from(format!("Delete {id}?")));
            for (choice, label) in [
                (
                    super::pointer_actions::ProviderDeleteChoice::RemoveSecrets,
                    "[Delete and remove secrets]",
                ),
                (
                    super::pointer_actions::ProviderDeleteChoice::KeepSecrets,
                    "[Delete but keep secrets]",
                ),
                (
                    super::pointer_actions::ProviderDeleteChoice::Cancel,
                    "[Cancel]",
                ),
            ] {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::Delete(
                            super::pointer_actions::ProviderId((*id).clone()),
                            choice,
                        ),
                    ),
                ));
                lines.push(Line::from(label));
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
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:list",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:list"),
            )
                .into(),
        );
    }

    fn render_copilot_setup(
        &self,
        frame: &mut Frame,
        area: Rect,
        s: &CopilotSetupState,
        provider_id: &str,
    ) {
        let mut lines = oauth_setup_lines(OAuthFlowView::Copilot(s), OAuthHost::Standalone);
        let mut controls = Vec::new();
        let copilot_id = || super::pointer_actions::ProviderId(provider_id.into());
        let provider_action =
            |action| super::pointer_actions::SettingsPointerAction::Providers(action);
        lines.push(Line::default());
        if s.outcome.is_some() {
            controls.push((
                lines.len(),
                provider_action(super::pointer_actions::ProvidersAction::CopilotConfirm(
                    copilot_id(),
                    super::pointer_actions::ConfirmationChoice::Confirm,
                )),
            ));
            lines.push(Line::from("[Continue]"));
        } else if s.shell.is_some() && s.rc_path.is_some() && !s.already_configured {
            controls.push((
                lines.len(),
                provider_action(super::pointer_actions::ProvidersAction::CopilotConfirm(
                    copilot_id(),
                    super::pointer_actions::ConfirmationChoice::Confirm,
                )),
            ));
            lines.push(Line::from("[Set up Copilot auth]"));
            controls.push((
                lines.len(),
                provider_action(super::pointer_actions::ProvidersAction::CopilotConfirm(
                    copilot_id(),
                    super::pointer_actions::ConfirmationChoice::Cancel,
                )),
            ));
            lines.push(Line::from("[Cancel]"));
        } else {
            controls.push((
                lines.len(),
                provider_action(super::pointer_actions::ProvidersAction::LocalBack),
            ));
            lines.push(Line::from("[Back]"));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:copilot-setup",
            (lines, selected_line),
            controls,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:copilot-setup"),
            )
                .into(),
        );
    }

    fn render_oauth_setup(
        &self,
        frame: &mut Frame,
        area: Rect,
        s: &OAuthFlowState,
        provider_id: &str,
        links: Option<&mut crate::tui::links::LinkRegistry>,
    ) {
        let flow = OAuthFlowView::OAuth(s);
        let (lines, controls) = oauth_setup_lines_with_controls(flow, OAuthHost::Standalone);
        let (mut lines, controls) =
            wrap_oauth_render_lines_with_controls(lines, controls, area.width);
        let link_regions = prepare_oauth_link_regions(&mut lines, area, flow, links.as_deref())
            .unwrap_or_default();
        let mut bindings = controls
            .into_iter()
            .filter_map(|(line, control)| {
                oauth_options(s, OAuthHost::Standalone)
                    .get(control)
                    .map(|option| {
                        (
                            line,
                            super::pointer_actions::SettingsPointerAction::Providers(
                                super::pointer_actions::ProvidersAction::OAuthOption(
                                    super::pointer_actions::ProviderId(provider_id.into()),
                                    *option,
                                ),
                            ),
                        )
                    })
            })
            .collect::<Vec<_>>();
        if s.authorize_url().is_some() {
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::CopyOAuth(
                        s.flow_id,
                        super::pointer_actions::OAuthCopyKind::AuthorizationUrl,
                    ),
                ),
            ));
            lines.push(Line::from("[copy authorization URL]"));
        }
        if s.device_login().is_some() {
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::CopyOAuth(
                        s.flow_id,
                        super::pointer_actions::OAuthCopyKind::DeviceCode,
                    ),
                ),
            ));
            lines.push(Line::from("[copy device code]"));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:oauth-setup",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:oauth-setup"),
            )
                .into(),
        );
        if let Some(links) = links {
            register_visible_link_regions(
                links,
                area,
                self.scroll_states.offset_for("providers:oauth-setup"),
                link_regions,
            );
        }
    }

    fn render_add(
        &self,
        frame: &mut Frame,
        area: Rect,
        s: &AddState,
        links: Option<&mut crate::tui::links::LinkRegistry>,
    ) {
        #[cfg(test)]
        if let Some(step) = s.run.current_provider_step() {
            super::pointer_acceptance_tests::record_rendered_wizard_step(step);
        }
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let red = Style::default().fg(Color::Red);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut controls = Vec::new();

        match s.run.current_step_id() {
            Some("template") => {
                lines.push(Line::from(Span::styled(
                    "Which provider would you like to add?".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::default());
                let ordered = onboarding_ordered_templates();
                for (i, t) in ordered.iter().enumerate() {
                    let marker = if i == s.template_cursor { "▸ " } else { "  " };
                    let style = if t.is_disabled() {
                        muted.add_modifier(Modifier::DIM)
                    } else if i == s.template_cursor {
                        yellow.add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    controls.push((lines.len(), i));
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled(t.display_label().into_owned(), style),
                        Span::raw("  "),
                        Span::styled(format!("({})", t.id), muted),
                    ]));
                }
                if let Some(t) = ordered.get(s.template_cursor)
                    && let Some(hint) = t.display_hint()
                {
                    lines.push(Line::default());
                    lines.push(Line::from(Span::styled(hint.to_string(), muted)));
                }
            }
            Some("wire-api") => {
                lines.push(Line::from(Span::styled(
                    "Which request wire does this endpoint accept?".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                lines.push(Line::default());
                for (index, (label, description)) in [
                    ("Auto", "let Cockpit select the request wire"),
                    (
                        "Chat Completions",
                        "use the OpenAI-compatible /chat/completions API",
                    ),
                    ("Responses", "use the OpenAI Responses API"),
                    ("Anthropic", "use Anthropic's native Messages API"),
                ]
                .iter()
                .enumerate()
                {
                    let marker = if index == s.wire_api_cursor {
                        "▸ "
                    } else {
                        "  "
                    };
                    let style = if index == s.wire_api_cursor {
                        yellow.add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    controls.push((lines.len(), index));
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled((*label).to_string(), style),
                        Span::raw(" — "),
                        Span::styled((*description).to_string(), muted),
                    ]));
                }
            }
            Some("id" | "url" | "auth-method" | "api-key" | "env-var" | "headers") => {
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                let id_line = render_field_row(&mut lines, "id", &s.id_field, s.is_step("id"));
                let url_line = render_field_row(&mut lines, "url", &s.url_field, s.is_step("url"));
                if s.is_step("id") {
                    controls.push((id_line, 0));
                } else if s.is_step("url") {
                    controls.push((url_line, 0));
                }
                if s.is_step("auth-method") {
                    lines.push(Line::default());
                    let vault = crate::tui::capability_gate::secret_store_row_value(
                        &self.host_capabilities,
                    );
                    let mut options = vec![
                        (
                            "Paste key".to_string(),
                            format!("copy into {vault}"),
                        ),
                        (
                            "Use env var".to_string(),
                            "keep a $VAR reference; the daemon validates visibility".to_string(),
                        ),
                        (
                            "Advanced headers".to_string(),
                            "edit raw HTTP headers".to_string(),
                        ),
                    ];
                    if s.detected_env_offer.is_some() {
                        options.push((
                            "Copy detected value into vault".to_string(),
                            format!("copy this process's value into {vault}"),
                        ));
                    }
                    for (index, (label, description)) in options.iter().enumerate() {
                        let marker = if index == s.auth_method_cursor {
                            "▸ "
                        } else {
                            "  "
                        };
                        let style = if index == s.auth_method_cursor {
                            yellow.add_modifier(Modifier::BOLD)
                        } else {
                            Style::default().fg(Color::White)
                        };
                        controls.push((lines.len(), index));
                        lines.push(Line::from(vec![
                            Span::raw(marker),
                            Span::styled(label.clone(), style),
                            Span::raw(" — "),
                            Span::styled(description.clone(), muted),
                        ]));
                    }
                }
                if let Some(detected) = &s.detected_env_offer {
                    lines.push(Line::from(Span::styled(
                        format!("Detected ${detected}; keep the reference or copy its value into the daemon vault."),
                        muted,
                    )));
                }
                if self.host_capabilities.secret_store.effective_placement
                    == cockpit_proto::SecretStorePlacement::Database
                {
                    lines.push(Line::from(Span::styled(
                        "Local vault mode is machine-bound; losing its private wrapping-key file makes stored credentials unrecoverable.",
                        muted,
                    )));
                }
                if s.is_step("api-key") {
                    lines.push(Line::default());
                    let masked = if s.api_key_field.text().is_empty() {
                        ""
                    } else {
                        "••••••••"
                    };
                    controls.push((lines.len(), 0));
                    lines.push(Line::from(vec![
                        Span::styled("api key: ", muted),
                        Span::styled(masked.to_string(), Style::default().fg(Color::White)),
                    ]));
                    if let Some(meta) = t.api_key {
                        lines.push(Line::from(Span::styled(
                            format!("Hint: {} · {}", meta.format_hint, meta.console_url),
                            muted,
                        )));
                    }
                }
                if s.is_step("env-var") {
                    lines.push(Line::default());
                    let line = render_field_row(&mut lines, "env var", &s.env_var_field, true);
                    controls.push((line, 0));
                }
                if s.is_step("headers") {
                    lines.push(Line::default());
                    let header_controls = render_header_editor(&mut lines, &s.headers);
                    if !s.headers.is_editing() {
                        controls.extend(
                            header_controls
                                .into_iter()
                                .map(|(line, id)| (line, id.0 as usize)),
                        );
                    }
                }
                if s.is_step("url")
                    && let Some(hint) = t.display_hint()
                {
                    lines.push(Line::default());
                    lines.push(Line::from(Span::styled(hint.to_string(), muted)));
                }
            }
            Some("copilot-auth") => {
                let state = s
                    .copilot_auth
                    .as_ref()
                    .expect("Copilot descriptor step initializes state");
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
                render_oauth_body(
                    &mut lines,
                    OAuthFlowView::Copilot(state),
                    OAuthHost::AddWizard,
                );
                controls.push((lines.len(), 0));
                let primary_label = if state.outcome.is_none()
                    && state.shell.is_some()
                    && state.rc_path.is_some()
                    && !state.already_configured
                {
                    "[Set up Copilot auth]"
                } else {
                    "[Continue]"
                };
                lines.push(Line::from(primary_label));
                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "After this step we'll fetch the model list automatically. \
                     Press `s` to skip the GH_TOKEN setup if your token is \
                     already in the environment."
                        .to_string(),
                    muted,
                )));
            }
            Some("grok-oauth" | "codex-oauth") => {
                let state = s
                    .oauth_auth
                    .as_ref()
                    .expect("OAuth descriptor step initializes state");
                let t = s.template.expect("template chosen");
                lines.push(Line::from(vec![
                    Span::styled("Template: ", muted),
                    Span::styled(t.display.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                controls.extend(render_oauth_body_with_controls(
                    &mut lines,
                    OAuthFlowView::OAuth(state),
                    OAuthHost::AddWizard,
                ));
            }
            Some("test-key-choice") => {
                lines.push(Line::from(Span::styled(
                    "Test key now?".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                for (index, (label, description)) in [
                    ("Test key", "validate credentials now"),
                    ("Skip test", "save now and validate on first use"),
                ]
                .iter()
                .take(if s.onboarding { 1 } else { 2 })
                .enumerate()
                {
                    let marker = if index == s.test_choice_cursor {
                        "▸ "
                    } else {
                        "  "
                    };
                    let style = if index == s.test_choice_cursor {
                        yellow.add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    controls.push((lines.len(), index));
                    lines.push(Line::from(vec![
                        Span::raw(marker),
                        Span::styled((*label).to_string(), style),
                        Span::raw(" — "),
                        Span::styled((*description).to_string(), muted),
                    ]));
                }
            }
            Some("test-skipped") => {
                lines.push(Line::from(Span::styled(
                    "key saved but unverified — it will be tested on your first message."
                        .to_string(),
                    muted,
                )));
                controls.push((lines.len(), 0));
                lines.push(Line::from("[Continue]"));
            }
            Some("saving" | "fetching" | "test-key") => {
                lines.push(Line::from(Span::styled(
                    if s.is_step("saving") {
                        "Saving config…"
                    } else if s.is_step("test-key") {
                        "Testing key…"
                    } else {
                        "Fetching /models…"
                    }
                    .to_string(),
                    yellow,
                )));
                if s.is_step("test-key") && s.fetch.is_none() {
                    lines.push(Line::from(Span::styled(
                        "Validation failed or the network is offline. Press o to continue with manual model setup, or Esc to cancel and resume later.",
                        muted,
                    )));
                }
            }
            Some("done") | None => {
                lines.push(Line::from(Span::styled(
                    "Done.".to_string(),
                    Style::default().add_modifier(Modifier::BOLD),
                )));
                if s.is_step("done") {
                    controls.push((lines.len(), 0));
                    lines.push(Line::from("[Continue]"));
                }
            }
            Some(other) => {
                lines.push(Line::from(Span::styled(
                    format!("Unsupported wizard step: {other}"),
                    red,
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
        let oauth_flow = matches!(s.run.current_step_id(), Some("grok-oauth" | "codex-oauth"))
            .then(|| s.oauth_auth.as_deref())
            .flatten()
            .map(OAuthFlowView::OAuth);
        if oauth_flow.is_some() {
            let (wrapped, remapped) =
                wrap_oauth_render_lines_with_controls(lines, controls, area.width);
            lines = wrapped;
            controls = remapped;
        }
        let link_regions = oauth_flow
            .and_then(|flow| prepare_oauth_link_regions(&mut lines, area, flow, links.as_deref()))
            .unwrap_or_default();
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:add",
            (lines, selected_line),
            controls.into_iter().filter_map(|(line, control)| {
                provider_add_pointer_action(s, control).map(|action| (line, action))
            }),
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:add"),
            )
                .into(),
        );
        if let Some(links) = links {
            register_visible_link_regions(
                links,
                area,
                self.scroll_states.offset_for("providers:add"),
                link_regions,
            );
        }
        if s.is_step("headers") && s.headers.is_editing() {
            render_header_edit_popup(self, frame, area, &s.headers);
        }
    }

    fn render_edit(&self, frame: &mut Frame, area: Rect, s: &EditState) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut bindings = Vec::new();

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
                    self.provider_oauth_status_value(OAuthProvider::Grok),
                ),
                EditAction::OAuthAuth(OAuthProvider::Codex) => (
                    "Codex subscription auth",
                    self.provider_oauth_status_value(OAuthProvider::Codex),
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
                EditAction::DeepFetch => (
                    "Deep fetch",
                    "live endpoint/context probes; confirmation required".to_string(),
                ),
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
            bindings.push((lines.len(), provider_edit_pointer_action(s, *action)));
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

        if s.delete_pending {
            lines.push(Line::default());
            lines.push(Line::from(format!("Delete {}?", s.provider_id)));
            for (choice, label) in [
                (
                    super::pointer_actions::ProviderDeleteChoice::RemoveSecrets,
                    "[Delete and remove secrets]",
                ),
                (
                    super::pointer_actions::ProviderDeleteChoice::KeepSecrets,
                    "[Delete but keep secrets]",
                ),
                (
                    super::pointer_actions::ProviderDeleteChoice::Cancel,
                    "[Cancel]",
                ),
            ] {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::Delete(
                            super::pointer_actions::ProviderId(s.provider_id.clone()),
                            choice,
                        ),
                    ),
                ));
                lines.push(Line::from(label));
            }
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
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:edit",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:edit"),
            )
                .into(),
        );
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
        let mut bindings = render_header_editor(&mut lines, editor)
            .into_iter()
            .filter_map(|(line, control)| {
                provider_header_pointer_action(editor, control.0 as usize)
                    .map(|action| (line, action))
            })
            .collect::<Vec<_>>();
        if editor.is_editing() {
            bindings.clear();
        }
        if let Some(status) = &editor.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(
                status.clone(),
                Style::default().fg(Color::Yellow),
            )));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:headers",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:headers"),
            )
                .into(),
        );
        if editor.is_editing() {
            render_header_edit_popup(self, frame, area, editor);
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
        let mut bindings = render_model_editor(&mut lines, editor)
            .into_iter()
            .filter_map(|(line, control)| {
                provider_model_pointer_action(editor, control.0 as usize)
                    .map(|action| (line, action))
            })
            .collect::<Vec<_>>();
        if !editor.is_editing() {
            let provider = super::pointer_actions::ProviderId(parent.provider_id.clone());
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::AddModel(provider.clone()),
                ),
            ));
            lines.push(Line::from("[Add model]"));
            if let Some(model) = editor.rows().get(editor.cursor) {
                let model_id = super::pointer_actions::ModelId(model.id.clone());
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelSettings(
                            provider.clone(),
                            model_id.clone(),
                        ),
                    ),
                ));
                lines.push(Line::from("[Model settings]"));
                if model.manual {
                    bindings.push((
                        lines.len(),
                        super::pointer_actions::SettingsPointerAction::Providers(
                            super::pointer_actions::ProvidersAction::RenameModel(
                                provider.clone(),
                                model_id.clone(),
                            ),
                        ),
                    ));
                    lines.push(Line::from("[Rename model]"));
                    bindings.push((
                        lines.len(),
                        super::pointer_actions::SettingsPointerAction::Providers(
                            super::pointer_actions::ProvidersAction::DeleteModel(
                                provider, model_id,
                            ),
                        ),
                    ));
                    lines.push(Line::from("[Delete model]"));
                }
            }
        }
        if editor.is_editing() {
            bindings.clear();
        }
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
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:models",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:models"),
            )
                .into(),
        );
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
        let mut bindings = Vec::new();

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
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::RowEditor(
                        super::pointer_actions::ProviderRowEditorAction::SettingEdit(*field),
                    ),
                ),
            ));
            lines.push(Line::from(spans));
        }

        // `[save changes]` row, styled like MCP Add's button.
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::RowEditor(
                    super::pointer_actions::ProviderRowEditorAction::SettingSave,
                ),
            ),
        ));
        lines.push(save_button_line("[save changes]", editor.on_save_row()));

        if let (Some(_), super::settings_editor::SettingsScope::Model { model_id }) =
            (editor.multimodal(), &editor.scope)
        {
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::ModelLifecycle(
                        super::pointer_actions::ModelLifecycleAction::Refresh(
                            super::pointer_actions::ProviderId(parent.provider_id.clone()),
                            super::pointer_actions::ModelId(model_id.clone()),
                        ),
                    ),
                ),
            ));
            lines.push(Line::from("[refresh detected media capabilities]"));
            if editor
                .multimodal()
                .is_some_and(|multimodal| multimodal.available_actions().contains(&"Discard"))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelLifecycle(
                            super::pointer_actions::ModelLifecycleAction::Discard(
                                super::pointer_actions::ProviderId(parent.provider_id.clone()),
                                super::pointer_actions::ModelId(model_id.clone()),
                            ),
                        ),
                    ),
                ));
                lines.push(Line::from("[discard media capability draft]"));
            }
            if editor
                .multimodal()
                .is_some_and(|multimodal| multimodal.available_actions().contains(&"Retry"))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelLifecycle(
                            super::pointer_actions::ModelLifecycleAction::Retry(
                                super::pointer_actions::ProviderId(parent.provider_id.clone()),
                                super::pointer_actions::ModelId(model_id.clone()),
                            ),
                        ),
                    ),
                ));
                lines.push(Line::from("[retry media capability action]"));
            }
            if editor
                .multimodal()
                .is_some_and(|multimodal| multimodal.available_actions().contains(&"Reload"))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelLifecycle(
                            super::pointer_actions::ModelLifecycleAction::Reload(
                                super::pointer_actions::ProviderId(parent.provider_id.clone()),
                                super::pointer_actions::ModelId(model_id.clone()),
                            ),
                        ),
                    ),
                ));
                lines.push(Line::from("[reload media capability draft]"));
            }
            if editor
                .multimodal()
                .is_some_and(|multimodal| multimodal.available_actions().contains(&"Reapply"))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelLifecycle(
                            super::pointer_actions::ModelLifecycleAction::Reapply(
                                super::pointer_actions::ProviderId(parent.provider_id.clone()),
                                super::pointer_actions::ModelId(model_id.clone()),
                            ),
                        ),
                    ),
                ));
                lines.push(Line::from("[reapply media capability draft]"));
            }
            if editor
                .multimodal()
                .is_some_and(|multimodal| multimodal.available_actions().contains(&"Rebind"))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelLifecycle(
                            super::pointer_actions::ModelLifecycleAction::Rebind(
                                super::pointer_actions::ProviderId(parent.provider_id.clone()),
                                super::pointer_actions::ModelId(model_id.clone()),
                            ),
                        ),
                    ),
                ));
                lines.push(Line::from("[rebind media capability draft]"));
            }
            if editor
                .multimodal()
                .is_some_and(|multimodal| multimodal.available_actions().contains(&"Dismiss"))
            {
                bindings.push((
                    lines.len(),
                    super::pointer_actions::SettingsPointerAction::Providers(
                        super::pointer_actions::ProvidersAction::ModelLifecycle(
                            super::pointer_actions::ModelLifecycleAction::Dismiss(
                                super::pointer_actions::ProviderId(parent.provider_id.clone()),
                                super::pointer_actions::ModelId(model_id.clone()),
                            ),
                        ),
                    ),
                ));
                lines.push(Line::from("[dismiss media capability refresh failure]"));
            }
        }

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
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:settings",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:settings"),
            )
                .into(),
        );
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
        let mut bindings = Vec::new();
        for (i, label) in opts.iter().enumerate() {
            let marker = if i == s.cursor { "▸ " } else { "  " };
            let style = if i == s.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::FetchAllConfirm(if i == 0 {
                        super::pointer_actions::FetchAllChoice::Apply
                    } else {
                        super::pointer_actions::FetchAllChoice::Cancel
                    }),
                ),
            ));
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
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::CycleUnlistedPolicy,
            ),
        ));
        lines.push(Line::from(vec![
            Span::raw(if s.cursor == 2 { "▸ " } else { "  " }),
            Span::styled(format!("{check} Do not show again"), style),
        ]));
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:fetch-all",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:fetch-all"),
            )
                .into(),
        );
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
        let mut bindings = Vec::new();
        for (i, label) in opts.iter().enumerate() {
            let marker = if i == s.cursor { "▸ " } else { "  " };
            let style = if i == s.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::FetchOneConfirm(
                        super::pointer_actions::ProviderId(s.provider_id.clone()),
                        if i == 0 {
                            super::pointer_actions::FetchOneChoice::KeepLocal
                        } else {
                            super::pointer_actions::FetchOneChoice::Apply
                        },
                    ),
                ),
            ));
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label.to_string(), style),
            ]));
        }
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::FetchOneConfirm(
                    super::pointer_actions::ProviderId(s.provider_id.clone()),
                    super::pointer_actions::FetchOneChoice::Cancel,
                ),
            ),
        ));
        lines.push(Line::from("[Cancel]"));
        let check = if s.dont_ask_again { "[x]" } else { "[ ]" };
        let style = if s.cursor == 2 {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        bindings.push((
            lines.len(),
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::CycleUnlistedPolicy,
            ),
        ));
        lines.push(Line::from(vec![
            Span::raw(if s.cursor == 2 { "▸ " } else { "  " }),
            Span::styled(format!("{check} Do not show again"), style),
        ]));
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:fetch-one",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:fetch-one"),
            )
                .into(),
        );
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
        let mut bindings = Vec::new();
        for (i, label) in opts.iter().enumerate() {
            let marker = if i == s.cursor { "▸ " } else { "  " };
            let style = if i == s.cursor {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let choice = match i {
                0 => super::pointer_actions::FetchFallbackChoice::Retry,
                1 => super::pointer_actions::FetchFallbackChoice::KeepLocal,
                2 => super::pointer_actions::FetchFallbackChoice::UseFallback,
                _ => super::pointer_actions::FetchFallbackChoice::Cancel,
            };
            bindings.push((
                lines.len(),
                super::pointer_actions::SettingsPointerAction::Providers(
                    super::pointer_actions::ProvidersAction::FetchFallbackConfirm(
                        super::pointer_actions::ProviderId(s.provider_id.clone()),
                        choice,
                    ),
                ),
            ));
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled(label.to_string(), style),
            ]));
        }
        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "providers:fetch-fallback",
            (lines, selected_line),
            bindings,
            (
                &self.pointer_surface,
                SettingsScrollRegionId("providers:fetch-fallback"),
            )
                .into(),
        );
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
fn render_header_editor(
    lines: &mut Vec<Line<'static>>,
    h: &HeaderEditor,
) -> Vec<(usize, SettingsControlId)> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let mut bindings = Vec::new();
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
        bindings.push((lines.len(), SettingsControlId(i as u64)));
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
    bindings.push((lines.len(), SettingsControlId(add_idx as u64)));
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
        bindings.push((lines.len(), SettingsControlId(cont_idx as u64)));
        lines.push(Line::from(vec![
            Span::raw(marker.to_string()),
            Span::styled("[continue → save & fetch /models]".to_string(), style),
        ]));
    }

    // `[save changes]` row on the Edit-page sub-page (mutually exclusive
    // with `[continue →]`). Styled like MCP Add's button.
    if let Some(save_idx) = h.save_idx() {
        bindings.push((lines.len(), SettingsControlId(save_idx as u64)));
        lines.push(save_button_line("[save changes]", h.cursor == save_idx));
    }
    if let Some(status) = &h.status {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(status.clone(), yellow)));
    }
    bindings
}

fn provider_header_pointer_action(
    editor: &HeaderEditor,
    index: usize,
) -> Option<super::pointer_actions::SettingsPointerAction> {
    use super::pointer_actions::{
        HeaderName, ProviderRowEditorAction, ProvidersAction, SettingsPointerAction,
    };
    let control = if let Some(row) = editor.rows().get(index) {
        ProviderRowEditorAction::HeaderOpen(HeaderName(row.name.clone()))
    } else if index == editor.add_row_idx() {
        ProviderRowEditorAction::HeaderAdd
    } else if editor.save_idx() == Some(index) {
        ProviderRowEditorAction::HeaderSave
    } else {
        return None;
    };
    Some(SettingsPointerAction::Providers(
        ProvidersAction::RowEditor(control),
    ))
}

/// Centered name/value popup for adding or editing a header. Drawn on
/// top of the header list when the editor is in `EditName`/`EditValue`
/// mode. The `Clear` widget wipes the cells underneath so the list
/// doesn't bleed through.
fn render_header_edit_popup(cx: &SettingsCx, frame: &mut Frame, area: Rect, h: &HeaderEditor) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);

    let name_focus = matches!(h.mode, HeaderMode::EditName);

    let mut body: Vec<Line<'static>> = Vec::new();
    render_field_row(&mut body, "Name ", &h.name_buf, name_focus);
    render_field_row(&mut body, "Value", &h.value_buf, !name_focus);

    // Dynamic-reference status for the value (headers commonly reference
    // `$VAR` or `$secret:<name>`).  This is deliberately syntax-only: the
    // TUI never expands env refs or opens/inspects the local credential
    // store. Named-secret presence is metadata returned by the daemon and
    // cached by SettingsCx.
    let references = cockpit_core::envref::referenced_names(h.value_buf.text());
    let env_refs = references
        .iter()
        .filter(|name| !name.starts_with("secret:"))
        .map(|name| format!("${name}"))
        .collect::<Vec<_>>();
    let secret_refs = references
        .iter()
        .filter_map(|name| name.strip_prefix("secret:"))
        .map(str::to_string)
        .collect::<Vec<_>>();
    let secret_missing = secret_refs
        .iter()
        .filter(|name| {
            matches!(
                cx.cached_secret_inventory_contains(
                    name,
                    Some(cockpit_proto::SecretInventoryKind::NamedSecret),
                ),
                Some(false)
            )
        })
        .map(|name| format!("$secret:{name}"))
        .collect::<Vec<_>>();
    if !secret_missing.is_empty() {
        body.push(Line::from(Span::styled(
            format!("  Named secret not detected: {}", secret_missing.join(", ")),
            yellow,
        )));
    } else if !env_refs.is_empty() && !secret_refs.is_empty() {
        body.push(Line::from(Span::styled(
            format!(
                "  dynamic references detected (daemon resolves values): {} {}",
                env_refs.join(", "),
                secret_refs
                    .iter()
                    .map(|name| format!("$secret:{name}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            muted,
        )));
    } else if !env_refs.is_empty() {
        body.push(Line::from(Span::styled(
            format!(
                "  environment reference(s) detected (daemon resolves values): {}",
                env_refs.join(", ")
            ),
            muted,
        )));
    } else if !secret_refs.is_empty() {
        body.push(Line::from(Span::styled(
            format!(
                "  named secret reference(s) detected (daemon resolves values): {}",
                secret_refs
                    .iter()
                    .map(|name| format!("$secret:{name}"))
                    .collect::<Vec<_>>()
                    .join(", ")
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
fn render_model_editor(
    lines: &mut Vec<Line<'static>>,
    m: &ModelEditor,
) -> Vec<(usize, SettingsControlId)> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let green = Style::default().fg(Color::Green);
    let mut bindings = Vec::new();
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
            bindings.push((lines.len(), SettingsControlId(i as u64)));
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
    bindings.push((lines.len(), SettingsControlId(add_idx as u64)));
    lines.push(Line::from(vec![
        Span::raw(add_marker.to_string()),
        Span::styled("[+ add model]".to_string(), add_style),
    ]));

    // `[save changes]` row, styled like MCP Add's button.
    bindings.push((lines.len(), SettingsControlId(m.save_idx() as u64)));
    lines.push(save_button_line("[save changes]", m.cursor == m.save_idx()));
    bindings
}

fn provider_model_pointer_action(
    editor: &ModelEditor,
    index: usize,
) -> Option<super::pointer_actions::SettingsPointerAction> {
    use super::pointer_actions::{
        ModelId, ProviderRowEditorAction, ProvidersAction, SettingsPointerAction,
    };
    let control = if let Some(row) = editor.rows().get(index) {
        ProviderRowEditorAction::ModelOpen(ModelId(row.id.clone()))
    } else if index == editor.add_row_idx() {
        ProviderRowEditorAction::ModelAdd
    } else if index == editor.save_idx() {
        ProviderRowEditorAction::ModelSave
    } else {
        return None;
    };
    Some(SettingsPointerAction::Providers(
        ProvidersAction::RowEditor(control),
    ))
}

fn render_model_fetch_status_block(
    lines: &mut Vec<Line<'static>>,
    entry: &ProviderEntry,
    now: chrono::DateTime<Utc>,
) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let state = provider_model_fetch_display_state(entry);
    let state_style = match state {
        cockpit_config::providers::ProviderModelFetchDisplayState::Live => {
            Style::default().fg(Color::Green)
        }
        cockpit_config::providers::ProviderModelFetchDisplayState::Fallback
        | cockpit_config::providers::ProviderModelFetchDisplayState::Preserved
        | cockpit_config::providers::ProviderModelFetchDisplayState::Unsupported => {
            Style::default().fg(Color::Yellow)
        }
        cockpit_config::providers::ProviderModelFetchDisplayState::Failed
        | cockpit_config::providers::ProviderModelFetchDisplayState::AuthFailed => {
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

fn render_field_row(
    lines: &mut Vec<Line<'static>>,
    label: &str,
    field: &TextField,
    active: bool,
) -> usize {
    let line = lines.len();
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
        let cursor = cockpit_host::text::floor_char_boundary(text, field.cursor());
        let (before, after) = text.split_at(cursor);
        spans.push(Span::styled(before.to_string(), value_style));
        spans.push(super::shell::cursor_marker_span());
        spans.push(Span::styled(after.to_string(), value_style));
    } else {
        spans.push(Span::styled(field.text().to_string(), value_style));
    }
    lines.push(Line::from(spans));
    line
}

/// Build the `ProvidersPage` for `/model-settings`: the active model's
/// model-settings sub-dialog (implementation note). Falls
/// back to the providers list with an inline status when no model is active
/// or the active (provider, model) can't be resolved in config.
pub(super) fn active_model_settings_page(
    config: &cockpit_config::providers::ProvidersConfig,
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
    let retention_status = config
        .resolve_effective_model_capabilities(
            &active.provider,
            &active.model,
            config.resolution_generation,
        )
        .prompt_cache_retention;
    let settings = SettingsEditor::for_model_with_generation(
        &active.provider,
        entry,
        &active.model,
        config.resolution_generation.max(1),
    )
    .with_active_prompt_cache_retention(
        active.prompt_cache_retention.unwrap_or_default(),
        retention_status,
    );
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

/// Provider ids are config-map keys. Restrict to a conservative
/// shell/filename-safe set so they're easy to reference from the CLI.
fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
}

fn provider_edit_pointer_action(
    state: &EditState,
    action: EditAction,
) -> super::pointer_actions::SettingsPointerAction {
    use super::pointer_actions::{ProviderId, ProvidersAction, SettingsPointerAction};
    let id = ProviderId(state.provider_id.clone());
    let action = match action {
        EditAction::Url => ProvidersAction::EditField(id, EditField::Url),
        EditAction::Headers => ProvidersAction::EditHeaders(id),
        EditAction::CopilotAuth => ProvidersAction::CopilotSetup(id),
        EditAction::OAuthAuth(provider) => ProvidersAction::BeginOAuth(id, provider),
        EditAction::Models => ProvidersAction::ManageModels(id),
        EditAction::Settings => ProvidersAction::ProviderSettings(id),
        EditAction::Favorite => ProvidersAction::Favorite(id),
        EditAction::Refetch => ProvidersAction::Refetch(id),
        EditAction::DeepFetch => ProvidersAction::DeepFetchConfirm(id),
        EditAction::Delete => ProvidersAction::BeginDelete(id),
        EditAction::Save => ProvidersAction::SaveProvider(id),
        EditAction::Back => ProvidersAction::LocalBack,
    };
    SettingsPointerAction::Providers(action)
}

fn provider_add_pointer_action(
    state: &AddState,
    index: usize,
) -> Option<super::pointer_actions::SettingsPointerAction> {
    use super::pointer_actions::{
        HeaderName, ProvidersAction, SettingsPointerAction, WizardAuthMethod, WizardControlId,
        WizardStepId, WizardTestChoice,
    };
    let step = state.run.current_provider_step()?;
    let control = match step {
        WizardStepId::Template => {
            WizardControlId::Template(onboarding_ordered_templates().get(index)?.id.to_string())
        }
        WizardStepId::WireApi => WizardControlId::WireApi(
            (*["auto", "completions", "responses", "anthropic"].get(index)?).to_string(),
        ),
        WizardStepId::AuthMethod => WizardControlId::AuthMethod(
            *[
                WizardAuthMethod::PasteKey,
                WizardAuthMethod::EnvVar,
                WizardAuthMethod::AdvancedHeaders,
            ]
            .get(index)?,
        ),
        WizardStepId::TestKeyChoice => WizardControlId::TestChoice(
            *[WizardTestChoice::TestKey, WizardTestChoice::SkipTest].get(index)?,
        ),
        WizardStepId::GrokOAuth | WizardStepId::CodexOAuth => {
            WizardControlId::OAuth(state.oauth_auth.as_deref().and_then(|oauth| {
                oauth_options(oauth, OAuthHost::AddWizard)
                    .into_iter()
                    .nth(index)
            })?)
        }
        WizardStepId::Headers => {
            if let Some(row) = state.headers.rows().get(index) {
                WizardControlId::Header(HeaderName(row.name.clone()))
            } else if index == state.headers.add_row_idx() {
                WizardControlId::AddHeader
            } else if state.headers.continue_idx() == Some(index) {
                WizardControlId::ContinueHeaders
            } else {
                return None;
            }
        }
        WizardStepId::ProviderId
        | WizardStepId::Url
        | WizardStepId::ApiKey
        | WizardStepId::EnvVar => WizardControlId::EditText,
        WizardStepId::CopilotAuth => (index == 0).then_some(WizardControlId::CopilotContinue)?,
        WizardStepId::TestSkipped => {
            (index == 0).then_some(WizardControlId::TestSkippedContinue)?
        }
        WizardStepId::Done => (index == 0).then_some(WizardControlId::DoneContinue)?,
        WizardStepId::Saving | WizardStepId::TestKey | WizardStepId::Fetching => return None,
    };
    Some(SettingsPointerAction::Providers(
        ProvidersAction::WizardControl(step, control),
    ))
}

#[cfg(test)]
pub(super) mod tests;

impl SettingsPage for ProvidersPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Providers
    }

    fn pointer_surface_token(&self) -> u64 {
        let surface = ProvidersPage::pointer_surface_kind(self);
        debug_assert!(ProvidersPointerSurface::ALL.contains(&surface));
        100 + surface as u64
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        match self {
            ProvidersPage::List { .. } => super::SettingsLocalBack::NoLocalBack,
            ProvidersPage::Add(_)
            | ProvidersPage::Edit(_)
            | ProvidersPage::Headers { .. }
            | ProvidersPage::Models { .. }
            | ProvidersPage::ModelSettings { .. }
            | ProvidersPage::ProviderSettings { .. }
            | ProvidersPage::FetchAll(_)
            | ProvidersPage::FetchOnePrompt(_)
            | ProvidersPage::FetchFallbackPrompt(_)
            | ProvidersPage::DeepFetch { .. }
            | ProvidersPage::CopilotSetup { .. }
            | ProvidersPage::OAuthSetup { .. } => super::SettingsLocalBack::LocalBack,
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_providers_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        let _surface = self.pointer_surface_kind();
        cx.render_providers_page(frame, area, self, None);
    }

    fn render_with_links(
        &self,
        cx: &SettingsCx,
        frame: &mut Frame,
        area: Rect,
        links: &mut crate::tui::links::LinkRegistry,
    ) {
        let _surface = self.pointer_surface_kind();
        cx.render_providers_page(frame, area, self, Some(links));
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Providers(provider_action) = action
        else {
            return Nav::Stay;
        };
        if let super::pointer_actions::ProvidersAction::Delete(id, choice) = provider_action {
            let pending_matches = match self {
                ProvidersPage::List {
                    cursor,
                    delete_pending,
                    ..
                } if *delete_pending => {
                    cursor
                        .checked_sub(1)
                        .and_then(|index| cx.config.providers.keys().nth(index))
                        == Some(&id.0)
                }
                ProvidersPage::Edit(state) if state.delete_pending => state.provider_id == id.0,
                _ => false,
            };
            if !pending_matches {
                return Nav::Stay;
            }
            match choice {
                super::pointer_actions::ProviderDeleteChoice::RemoveSecrets => {
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                        self,
                    );
                }
                super::pointer_actions::ProviderDeleteChoice::KeepSecrets => {
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE),
                        self,
                    );
                }
                super::pointer_actions::ProviderDeleteChoice::Cancel => {
                    if let ProvidersPage::List {
                        status,
                        delete_pending,
                        ..
                    } = self
                    {
                        *delete_pending = false;
                        *status = None;
                    } else if let ProvidersPage::Edit(state) = self {
                        state.delete_pending = false;
                        state.status = None;
                    }
                    return Nav::Stay;
                }
            }
        }
        // Copilot setup controls are commands, not cursor positions.  Reduce
        // them directly from their rendered identity so a fresh dispatch does
        // not depend on the number or ordering of lines in the prompt.
        if let ProvidersPage::CopilotSetup { parent, .. } = self {
            match provider_action {
                super::pointer_actions::ProvidersAction::CopilotConfirm(id, choice)
                    if parent.provider_id == id.0 =>
                {
                    let code = match choice {
                        super::pointer_actions::ConfirmationChoice::Confirm => KeyCode::Enter,
                        super::pointer_actions::ConfirmationChoice::Cancel => KeyCode::Esc,
                    };
                    return cx
                        .handle_providers_page_key(KeyEvent::new(code, KeyModifiers::NONE), self);
                }
                super::pointer_actions::ProvidersAction::LocalBack => {
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                        self,
                    );
                }
                _ => return Nav::Stay,
            }
        }
        if let ProvidersPage::Models { editor, parent } = self {
            let legacy = match &provider_action {
                super::pointer_actions::ProvidersAction::AddModel(provider) => {
                    Some((provider, None, KeyCode::Char('a')))
                }
                super::pointer_actions::ProvidersAction::RenameModel(provider, model) => {
                    Some((provider, Some(model), KeyCode::Char('r')))
                }
                super::pointer_actions::ProvidersAction::DeleteModel(provider, model) => {
                    Some((provider, Some(model), KeyCode::Char('d')))
                }
                super::pointer_actions::ProvidersAction::ModelSettings(provider, model) => {
                    Some((provider, Some(model), KeyCode::Enter))
                }
                _ => None,
            };
            if let Some((provider, model, key)) = legacy {
                if parent.provider_id != provider.0 || editor.is_editing() {
                    return Nav::Stay;
                }
                if let Some(model) = model {
                    let Some(index) = editor.rows().iter().position(|row| row.id == model.0) else {
                        return Nav::Stay;
                    };
                    editor.cursor = index;
                }
                return cx.handle_providers_page_key(KeyEvent::new(key, KeyModifiers::NONE), self);
            }
        }
        if let (
            ProvidersPage::OAuthSetup { state, .. },
            super::pointer_actions::ProvidersAction::CopyOAuth(flow_id, kind),
        ) = (&mut *self, &provider_action)
        {
            if let Some(action) = state.submit_pointer_copy(*flow_id, *kind) {
                cx.pending_oauth_action = Some(action);
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Refresh(provider, model),
            ),
        ) = (&*self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                );
            if matches_source {
                return cx.handle_providers_page_key(
                    KeyEvent::new(KeyCode::Char('r'), KeyModifiers::NONE),
                    self,
                );
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Dismiss(provider, model),
            ),
        ) = (&*self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                )
                && editor
                    .multimodal()
                    .is_some_and(|multimodal| multimodal.available_actions().contains(&"Dismiss"));
            if matches_source {
                return cx.handle_providers_page_key(
                    KeyEvent::new(KeyCode::Char('U'), KeyModifiers::NONE),
                    self,
                );
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Rebind(provider, model),
            ),
        ) = (&*self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                )
                && editor
                    .multimodal()
                    .is_some_and(|multimodal| multimodal.available_actions().contains(&"Rebind"));
            if matches_source {
                return cx.handle_providers_page_key(
                    KeyEvent::new(KeyCode::Char('B'), KeyModifiers::NONE),
                    self,
                );
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Reapply(provider, model),
            ),
        ) = (&*self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                )
                && editor
                    .multimodal()
                    .is_some_and(|multimodal| multimodal.available_actions().contains(&"Reapply"));
            if matches_source {
                return cx.handle_providers_page_key(
                    KeyEvent::new(KeyCode::Char('A'), KeyModifiers::NONE),
                    self,
                );
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Reload(provider, model),
            ),
        ) = (&*self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                )
                && editor
                    .multimodal()
                    .is_some_and(|multimodal| multimodal.available_actions().contains(&"Reload"));
            if matches_source {
                return cx.handle_providers_page_key(
                    KeyEvent::new(KeyCode::Char('L'), KeyModifiers::NONE),
                    self,
                );
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Retry(provider, model),
            ),
        ) = (&*self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                )
                && editor
                    .multimodal()
                    .is_some_and(|multimodal| multimodal.available_actions().contains(&"Retry"));
            if matches_source {
                return cx.handle_providers_page_key(
                    KeyEvent::new(KeyCode::Char('R'), KeyModifiers::NONE),
                    self,
                );
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::ModelSettings { editor, parent, .. },
            super::pointer_actions::ProvidersAction::ModelLifecycle(
                super::pointer_actions::ModelLifecycleAction::Discard(provider, model),
            ),
        ) = (&mut *self, &provider_action)
        {
            let matches_source = parent.provider_id == provider.0
                && matches!(
                    &editor.scope,
                    super::settings_editor::SettingsScope::Model { model_id }
                        if model_id == &model.0
                );
            if matches_source
                && editor
                    .multimodal()
                    .is_some_and(|multimodal| multimodal.available_actions().contains(&"Discard"))
            {
                editor.multimodal_action("Discard", &parent.entry);
            }
            return Nav::Stay;
        }
        if let (
            ProvidersPage::FetchOnePrompt(state),
            super::pointer_actions::ProvidersAction::FetchOneConfirm(
                id,
                super::pointer_actions::FetchOneChoice::Cancel,
            ),
        ) = (&*self, &provider_action)
            && state.provider_id == id.0
        {
            return cx
                .handle_providers_page_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE), self);
        }
        if matches!(&*self, ProvidersPage::List { .. }) {
            match &provider_action {
                super::pointer_actions::ProvidersAction::Add => {
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE),
                        self,
                    );
                }
                super::pointer_actions::ProvidersAction::CycleUnlistedPolicy => {
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Char('m'), KeyModifiers::NONE),
                        self,
                    );
                }
                super::pointer_actions::ProvidersAction::BeginDelete(id) => {
                    let Some(index) = cx
                        .config
                        .providers
                        .keys()
                        .position(|candidate| candidate == &id.0)
                    else {
                        return Nav::Stay;
                    };
                    if let ProvidersPage::List { cursor, .. } = self {
                        *cursor = index + 1;
                    }
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
                        self,
                    );
                }
                _ => {}
            }
        }
        let index = match (&*self, &provider_action) {
            (ProvidersPage::List { .. }, super::pointer_actions::ProvidersAction::RefetchAll) => 0,
            (ProvidersPage::List { .. }, super::pointer_actions::ProvidersAction::Open(id)) => {
                let Some(index) = cx
                    .config
                    .providers
                    .keys()
                    .position(|candidate| candidate == &id.0)
                else {
                    return Nav::Stay;
                };
                index + 1
            }
            (ProvidersPage::Edit(state), action) => {
                let Some(index) = edit_menu_actions(&state.provider_id, &state.entry)
                    .iter()
                    .position(|source| {
                        provider_edit_pointer_action(state, *source)
                            == super::pointer_actions::SettingsPointerAction::Providers(
                                action.clone(),
                            )
                    })
                else {
                    return Nav::Stay;
                };
                index
            }
            (
                ProvidersPage::Headers { editor, .. },
                super::pointer_actions::ProvidersAction::RowEditor(control),
            ) => match control {
                super::pointer_actions::ProviderRowEditorAction::HeaderOpen(id) => {
                    let Some(index) = editor.rows().iter().position(|row| row.name == id.0) else {
                        return Nav::Stay;
                    };
                    index
                }
                super::pointer_actions::ProviderRowEditorAction::HeaderAdd => editor.add_row_idx(),
                super::pointer_actions::ProviderRowEditorAction::HeaderSave => {
                    let Some(index) = editor.save_idx() else {
                        return Nav::Stay;
                    };
                    index
                }
                _ => return Nav::Stay,
            },
            (
                ProvidersPage::Models { editor, .. },
                super::pointer_actions::ProvidersAction::RowEditor(control),
            ) => match control {
                super::pointer_actions::ProviderRowEditorAction::ModelOpen(id) => {
                    let Some(index) = editor.rows().iter().position(|row| row.id == id.0) else {
                        return Nav::Stay;
                    };
                    index
                }
                super::pointer_actions::ProviderRowEditorAction::ModelAdd => editor.add_row_idx(),
                super::pointer_actions::ProviderRowEditorAction::ModelSave => editor.save_idx(),
                _ => return Nav::Stay,
            },
            (
                ProvidersPage::ModelSettings { editor, .. }
                | ProvidersPage::ProviderSettings { editor, .. },
                super::pointer_actions::ProvidersAction::RowEditor(control),
            ) => match control {
                super::pointer_actions::ProviderRowEditorAction::SettingEdit(id) => {
                    let Some(index) = editor.fields().iter().position(|field| field == id) else {
                        return Nav::Stay;
                    };
                    index
                }
                super::pointer_actions::ProviderRowEditorAction::SettingSave => {
                    editor.fields().len()
                }
                _ => return Nav::Stay,
            },
            (
                ProvidersPage::OAuthSetup { state, parent },
                super::pointer_actions::ProvidersAction::OAuthOption(id, option),
            ) if parent.provider_id == id.0 => {
                let Some(index) = oauth_options(state, OAuthHost::Standalone)
                    .iter()
                    .position(|candidate| candidate == option)
                else {
                    return Nav::Stay;
                };
                index
            }
            (
                ProvidersPage::Add(state),
                super::pointer_actions::ProvidersAction::WizardControl(step, control),
            ) if state.run.current_step_id() == Some(step.source_id()) => {
                let Some(index) = (0..256).position(|index| {
                    provider_add_pointer_action(state, index)
                        == Some(super::pointer_actions::SettingsPointerAction::Providers(
                            super::pointer_actions::ProvidersAction::WizardControl(
                                *step,
                                control.clone(),
                            ),
                        ))
                }) else {
                    return Nav::Stay;
                };
                index
            }
            (
                ProvidersPage::FetchAll(_),
                super::pointer_actions::ProvidersAction::FetchAllConfirm(choice),
            ) => match choice {
                super::pointer_actions::FetchAllChoice::Apply => 0,
                super::pointer_actions::FetchAllChoice::Cancel => 1,
            },
            (
                ProvidersPage::FetchAll(_),
                super::pointer_actions::ProvidersAction::CycleUnlistedPolicy,
            ) => 2,
            (
                ProvidersPage::FetchOnePrompt(_),
                super::pointer_actions::ProvidersAction::FetchOneConfirm(_, choice),
            ) => match choice {
                super::pointer_actions::FetchOneChoice::KeepLocal => 0,
                super::pointer_actions::FetchOneChoice::Apply => 1,
                super::pointer_actions::FetchOneChoice::Cancel => return Nav::Stay,
            },
            (
                ProvidersPage::FetchOnePrompt(_),
                super::pointer_actions::ProvidersAction::CycleUnlistedPolicy,
            ) => 2,
            (
                ProvidersPage::FetchFallbackPrompt(_),
                super::pointer_actions::ProvidersAction::FetchFallbackConfirm(_, choice),
            ) => match choice {
                super::pointer_actions::FetchFallbackChoice::Retry => 0,
                super::pointer_actions::FetchFallbackChoice::KeepLocal => 1,
                super::pointer_actions::FetchFallbackChoice::UseFallback => 2,
                super::pointer_actions::FetchFallbackChoice::Cancel => 3,
            },
            (
                ProvidersPage::DeepFetch { .. },
                super::pointer_actions::ProvidersAction::DeepFetchChoice(_, choice),
            ) => match choice {
                super::pointer_actions::DeepFetchChoice::Fetch => 0,
                super::pointer_actions::DeepFetchChoice::Cancel => 1,
            },
            _ => return Nav::Stay,
        };
        match self {
            ProvidersPage::List { cursor, .. } if index <= cx.config.providers.len() => {
                *cursor = index;
            }
            ProvidersPage::Edit(state)
                if index < edit_menu_actions(&state.provider_id, &state.entry).len() =>
            {
                state.cursor = index;
            }
            ProvidersPage::ModelSettings { editor, .. }
            | ProvidersPage::ProviderSettings { editor, .. }
                if index <= editor.fields().len() =>
            {
                editor.cursor = index;
            }
            ProvidersPage::Headers { editor, .. }
                if !editor.is_editing()
                    && index
                        <= editor
                            .save_idx()
                            .or_else(|| editor.continue_idx())
                            .unwrap_or_else(|| editor.add_row_idx()) =>
            {
                editor.cursor = index;
            }
            ProvidersPage::Models { editor, .. }
                if !editor.is_editing() && index <= editor.save_idx() =>
            {
                editor.cursor = index;
            }
            ProvidersPage::FetchAll(state)
                if !state.is_fetching() && !state.unlisted.is_empty() && index <= 2 =>
            {
                state.cursor = index;
            }
            ProvidersPage::FetchOnePrompt(state) if index <= 2 => state.cursor = index,
            ProvidersPage::FetchFallbackPrompt(state) if index <= 3 => state.cursor = index,
            ProvidersPage::DeepFetch { state, .. } => {
                if !state.set_pointer_choice(index) {
                    return Nav::Stay;
                }
            }
            ProvidersPage::OAuthSetup { state, .. }
                if !state.paste_focused && index < state.option_count(OAuthHost::Standalone) =>
            {
                state.cursor = index;
            }
            ProvidersPage::Add(state) => match state.run.current_step_id() {
                Some("template") if index < onboarding_ordered_templates().len() => {
                    state.template_cursor = index;
                }
                Some("wire-api") if index < 4 => state.wire_api_cursor = index,
                Some("auth-method")
                    if index
                        < if state.detected_env_offer.is_some() {
                            4
                        } else {
                            3
                        } =>
                {
                    state.auth_method_cursor = index;
                }
                Some("headers") if !state.headers.is_editing() => {
                    let last = state
                        .headers
                        .continue_idx()
                        .unwrap_or_else(|| state.headers.add_row_idx());
                    if index > last {
                        return Nav::Stay;
                    }
                    state.headers.cursor = index;
                }
                Some("test-key-choice") if index < if state.onboarding { 1 } else { 2 } => {
                    state.test_choice_cursor = index;
                }
                Some("copilot-auth") if index == 0 => {}
                Some("test-skipped") if index == 0 => {}
                Some("done") if index == 0 => {}
                Some("grok-oauth" | "codex-oauth")
                    if state.oauth_auth.as_ref().is_some_and(|oauth| {
                        !oauth.paste_focused && index < oauth.option_count(OAuthHost::AddWizard)
                    }) =>
                {
                    state
                        .oauth_auth
                        .as_mut()
                        .expect("guarded OAuth state")
                        .cursor = index;
                }
                Some("id" | "url" | "api-key" | "env-var") => return Nav::Stay,
                _ => return Nav::Stay,
            },
            ProvidersPage::CopilotSetup { state, .. } => match index {
                0 if state.outcome.is_some()
                    || (state.shell.is_some()
                        && state.rc_path.is_some()
                        && !state.already_configured) => {}
                1 => {
                    return cx.handle_providers_page_key(
                        KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
                        self,
                    );
                }
                _ => return Nav::Stay,
            },
            _ => return Nav::Stay,
        }
        cx.handle_providers_page_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), self)
    }

    fn handle_pointer_control_at(
        &mut self,
        cx: &mut SettingsCx,
        action: super::pointer_actions::SettingsPointerAction,
        column: u16,
        _row: u16,
    ) -> Nav {
        let super::pointer_actions::SettingsPointerAction::Providers(_) = &action else {
            return Nav::Stay;
        };
        if let (
            ProvidersPage::ModelSettings { editor, .. }
            | ProvidersPage::ProviderSettings { editor, .. },
            super::pointer_actions::SettingsPointerAction::Providers(
                super::pointer_actions::ProvidersAction::RowEditor(
                    super::pointer_actions::ProviderRowEditorAction::SettingEdit(id),
                ),
            ),
        ) = (&mut *self, &action)
            && editor.editing.is_some_and(|field| field == *id)
        {
            let label_width = editor
                .fields()
                .iter()
                .map(|field| field.label().chars().count())
                .max()
                .unwrap_or(0) as u16;
            let value_x = cx.pointer_surface.area.get().map_or(0, |area| {
                area.x
                    .saturating_add(2)
                    .saturating_add(label_width)
                    .saturating_add(2)
            });
            editor
                .buf
                .set_cursor_display_col(usize::from(column.saturating_sub(value_x)));
            return Nav::Stay;
        }
        if let ProvidersPage::Add(state) = self {
            let (label, field): (&str, &mut TextField) = match state.run.current_step_id() {
                Some("id") => ("id", &mut state.id_field),
                Some("url") => ("url", &mut state.url_field),
                Some("api-key") => ("api key", state.api_key_field.as_mut()),
                Some("env-var") => ("env var", state.env_var_field.as_mut()),
                _ => {
                    return self.handle_pointer_control(cx, action);
                }
            };
            let value_x = cx
                .pointer_surface
                .area
                .get()
                .map_or(label.len() as u16 + 2, |area| {
                    area.x.saturating_add(label.len() as u16 + 2)
                });
            field.set_cursor_display_col(usize::from(column.saturating_sub(value_x)));
            return Nav::Stay;
        }
        self.handle_pointer_control(cx, action)
    }

    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        region: SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region == SettingsScrollRegionId("providers:list")
            && let ProvidersPage::List {
                cursor,
                delete_pending,
                ..
            } = self
        {
            *delete_pending = false;
            *cursor = cursor
                .saturating_add_signed(delta)
                .min(cx.config.providers.len());
        } else if region == SettingsScrollRegionId("providers:edit")
            && let ProvidersPage::Edit(state) = self
            && state.editing_field.is_none()
        {
            state.delete_pending = false;
            state.cursor = state
                .cursor
                .saturating_add_signed(delta)
                .min(edit_menu_actions(&state.provider_id, &state.entry).len() - 1);
        } else if region == SettingsScrollRegionId("providers:settings") {
            match self {
                ProvidersPage::ModelSettings { editor, .. }
                | ProvidersPage::ProviderSettings { editor, .. }
                    if editor.editing.is_none() =>
                {
                    editor.cursor = editor
                        .cursor
                        .saturating_add_signed(delta)
                        .min(editor.fields().len());
                }
                _ => {}
            }
        } else if region == SettingsScrollRegionId("providers:headers")
            && let ProvidersPage::Headers { editor, .. } = self
            && !editor.is_editing()
        {
            let last = editor
                .save_idx()
                .or_else(|| editor.continue_idx())
                .unwrap_or_else(|| editor.add_row_idx());
            editor.cursor = editor.cursor.saturating_add_signed(delta).min(last);
        } else if region == SettingsScrollRegionId("providers:models")
            && let ProvidersPage::Models { editor, .. } = self
            && !editor.is_editing()
        {
            editor.cursor = editor
                .cursor
                .saturating_add_signed(delta)
                .min(editor.save_idx());
        } else {
            match self {
                ProvidersPage::FetchAll(state)
                    if region == SettingsScrollRegionId("providers:fetch-all")
                        && !state.is_fetching()
                        && !state.unlisted.is_empty() =>
                {
                    state.cursor = state.cursor.saturating_add_signed(delta).min(2);
                }
                ProvidersPage::FetchOnePrompt(state)
                    if region == SettingsScrollRegionId("providers:fetch-one") =>
                {
                    state.cursor = state.cursor.saturating_add_signed(delta).min(2);
                }
                ProvidersPage::FetchFallbackPrompt(state)
                    if region == SettingsScrollRegionId("providers:fetch-fallback") =>
                {
                    state.cursor = state.cursor.saturating_add_signed(delta).min(3);
                }
                ProvidersPage::DeepFetch { state, .. }
                    if region == SettingsScrollRegionId("providers:deep-fetch") =>
                {
                    state.scroll_pointer_choice(delta);
                }
                ProvidersPage::OAuthSetup { state, .. }
                    if region == SettingsScrollRegionId("providers:oauth-setup")
                        && !state.paste_focused =>
                {
                    let last = state.option_count(OAuthHost::Standalone).saturating_sub(1);
                    state.cursor = state.cursor.saturating_add_signed(delta).min(last);
                }
                ProvidersPage::Add(state) if region == SettingsScrollRegionId("providers:add") => {
                    match state.run.current_step_id() {
                        Some("template") => {
                            state.template_cursor = state
                                .template_cursor
                                .saturating_add_signed(delta)
                                .min(onboarding_ordered_templates().len().saturating_sub(1));
                        }
                        Some("auth-method") => {
                            let last = if state.detected_env_offer.is_some() {
                                3
                            } else {
                                2
                            };
                            state.auth_method_cursor = state
                                .auth_method_cursor
                                .saturating_add_signed(delta)
                                .min(last);
                        }
                        Some("headers") if !state.headers.is_editing() => {
                            let last = state
                                .headers
                                .continue_idx()
                                .unwrap_or_else(|| state.headers.add_row_idx());
                            state.headers.cursor =
                                state.headers.cursor.saturating_add_signed(delta).min(last);
                        }
                        Some("test-key-choice") => {
                            let last = if state.onboarding { 0 } else { 1 };
                            state.test_choice_cursor = state
                                .test_choice_cursor
                                .saturating_add_signed(delta)
                                .min(last);
                        }
                        Some("grok-oauth" | "codex-oauth") => {
                            if let Some(oauth) = state.oauth_auth.as_mut()
                                && !oauth.paste_focused
                            {
                                let last =
                                    oauth.option_count(OAuthHost::AddWizard).saturating_sub(1);
                                oauth.cursor = oauth.cursor.saturating_add_signed(delta).min(last);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        Nav::Stay
    }

    fn cancel_pointer_transients(&mut self) {
        match self {
            ProvidersPage::CopilotSetup { state, .. } => state.operation.cancel(),
            ProvidersPage::OAuthSetup { state, .. } => state.cancel_copy_effect(),
            ProvidersPage::Add(state) => {
                if let Some(oauth) = state.oauth_auth.as_mut() {
                    oauth.cancel_copy_effect();
                }
            }
            ProvidersPage::List { delete_pending, .. } => *delete_pending = false,
            ProvidersPage::Edit(state) => state.delete_pending = false,
            _ => {}
        }
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
            ProvidersPage::DeepFetch { state, .. } => format!(
                " › {} › {} › Deep fetch",
                super::PROVIDERS_TITLE,
                state.provider_id
            ),
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
            cockpit_core::welcome::display_path(&cx.config_path),
            crumbs
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        match self {
            ProvidersPage::List { .. } => {
                "↑/↓/Tab/Shift+Tab  enter: edit/refetch-all  R: refetch all  m: unlisted policy  a: add  d: delete (×2)  esc/h: back  q: close"
            }
            ProvidersPage::Add(s) => match s.run.current_step_id() {
                Some("template") => "↑/↓  enter: choose  esc: cancel",
                Some("id" | "url") => "type to edit  enter: next  esc: cancel",
                Some("auth-method" | "test-key-choice") => "↑/↓  enter: choose  esc: cancel",
                Some("api-key" | "env-var") => "type/paste  enter: save  esc: cancel",
                Some("headers") => {
                    if s.headers.is_editing() {
                        "type to edit  Tab: switch field  enter: save  esc: cancel"
                    } else {
                        "↑/↓  a: add  enter: edit  d: delete (x2)  enter on continue: save  esc: back"
                    }
                }
                Some("copilot-auth") => "enter: apply  s: skip  esc: cancel",
                Some("grok-oauth" | "codex-oauth") => match s
                    .oauth_auth
                    .as_ref()
                    .expect("OAuth descriptor step initializes state")
                    .provider
                {
                    OAuthProvider::Grok => {
                        let state = s.oauth_auth.as_ref().expect("OAuth state");
                        oauth_help_legend(OAuthHost::AddWizard, state)
                    }
                    OAuthProvider::Codex => {
                        let state = s.oauth_auth.as_ref().expect("OAuth state");
                        oauth_help_legend(OAuthHost::AddWizard, state)
                    }
                },
                Some("test-key") if s.fetch.is_none() => "o: continue offline  esc: cancel",
                Some("saving" | "fetching" | "test-key") => "(in progress)  esc: cancel",
                Some("test-skipped") => "enter: continue",
                Some("done") | None => "enter: back to list",
                Some(_) => "esc: cancel",
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
            ProvidersPage::DeepFetch { state, .. } => state.help_text(),
            ProvidersPage::CopilotSetup { .. } => "enter: apply  esc: cancel",
            ProvidersPage::OAuthSetup { state, .. } => {
                oauth_help_legend(OAuthHost::Standalone, state)
            }
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
fn onboarding_ordered_templates() -> Vec<&'static ProviderTemplate> {
    let mut ordered = templates::TEMPLATES.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|template| match template.id {
        "codex-oauth" | "copilot" | "grok-oauth" => 0,
        _ => 1,
    });
    ordered
}
