//! `/model` picker dialog.
//!
//! Opens over the chat surface. Lists every model across every
//! configured provider as `provider/model-id`, with favorites pinned
//! at the top. The user can filter by typing; arrow keys move; Enter
//! selects.
//!
//! If the chosen model carries rich reasoning-effort capabilities, a
//! follow-up "level" picker appears using the provider-native values. Legacy
//! `thinking_modes` still get their original `off` / `low` / `medium` /
//! `high` picker. The result is sent to the daemon, which owns the active
//! model transaction and performs a config write only for an explicit
//! make-default action.
//!
//! The dialog is independent of `tui/settings.rs` to keep that file’s state
//! machine focused on configuration editing. Enter is **always** session-only:
//! it never writes `active_model` in any layer, even when no default exists
//! yet. Ctrl+Enter asks the daemon for one
//! all-or-nothing transaction that switches this session **and** sets the
//! default for **new sessions** in the current configuration context. It
//! never changes the persisted model of an already-existing session, and the
//! completion line appears only after the daemon reports a verified result.

use std::collections::HashMap;
use std::path::Path;

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation,
    ScrollbarState, StatefulWidget, Wrap,
};

use crate::tui::pane::Pane;
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use cockpit_config::dirs::{COCKPIT_CONFIG_ENV, config_file_paths_for_load};
use cockpit_config::providers::{
    ActiveModelRef, ActiveReasoningEffort, CapabilityValue, ModelEntry, PromptCacheRetention,
    ProviderEntry, ProvidersConfig, ReasoningEffortCapability, ThinkingMode,
};
#[cfg(test)]
use cockpit_config::providers::{
    CapabilityStatus, ConfigDoc, EndpointReasoningEffortRequestMapping, ModelCapabilities,
    ReasoningEffortRequestMapping, WireApi,
};
use unicode_width::UnicodeWidthStr;

pub const DIALOG_HEIGHT: u16 = 18;

/// Visible model rows in the pick step. The dialog reserves the rest of
/// its height for the border, filter line, section headers, and help
/// line. Drives the scroll window (same scrolloff=1 behavior as the
/// composer `@`-popup).
const MODEL_WINDOW: usize = 11;

fn list_state(selected: usize, offset: usize) -> ListState {
    let mut state = ListState::default().with_selected(Some(selected));
    *state.offset_mut() = offset;
    state
}

fn list_cursor(state: &ListState) -> usize {
    state.selected().unwrap_or(0)
}

fn move_list_selection(state: &mut ListState, delta: isize, total: usize) {
    if total == 0 {
        state.select(None);
        *state.offset_mut() = 0;
        return;
    }
    let current = list_cursor(state);
    let selected = if delta < 0 {
        crate::tui::nav::wrap_prev(current, total)
    } else {
        crate::tui::nav::wrap_next(current, total)
    };
    state.select(Some(selected));
    *state.offset_mut() =
        crate::tui::nav::windowed_scroll(selected, state.offset(), total, MODEL_WINDOW);
}

#[cfg(test)]
trait PickerListStateTestExt {
    fn cursor(&self) -> usize;
    fn scroll(&self) -> usize;
    fn set_cursor(&mut self, cursor: usize);
}

#[cfg(test)]
impl PickerListStateTestExt for ListState {
    fn cursor(&self) -> usize {
        list_cursor(self)
    }
    fn scroll(&self) -> usize {
        self.offset()
    }
    fn set_cursor(&mut self, cursor: usize) {
        self.select(Some(cursor));
    }
}

pub struct ModelPickerDialog {
    cfg: ProvidersConfig,
    entries: Vec<Entry>,
    active_model: Option<(String, String)>,
    slot_models: Vec<(String, String)>,
    slot_default: Option<(String, String)>,
    scope_provider: Option<String>,
    add_model_provider: Option<String>,
    drift: Option<ModelPickerDrift>,
    filter: TextField,
    /// Durable ratatui selection/viewport state for the filtered model rows.
    pick: ListState,
    /// Domain identity survives filter/refresh/reorder independently of row indices.
    selected_model: Option<(String, String)>,
    step: Step,
    error: Option<String>,
    done: bool,
    persist_as_default: bool,
    row_hits: Vec<Option<RowHit>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelPickerDrift {
    pub session_label: String,
    pub config_label: String,
    pub config_model: Option<ActiveModelRef>,
}

#[derive(Clone)]
struct Entry {
    provider_id: String,
    model_id: String,
    display_name: Option<String>,
    is_favorite: bool,
    reasoning_effort: Option<ReasoningEffortCapability>,
    thinking_modes: Vec<ThinkingMode>,
    failure_annotation: Option<String>,
    trust: cockpit_config::providers::ModelTrust,
}

impl Entry {
    fn label(&self) -> String {
        format!("{}/{}", self.provider_id, self.model_id)
    }

    fn matches(&self, q: &str) -> bool {
        let q = q.trim().to_ascii_lowercase();
        if q.is_empty() {
            return true;
        }
        let label = self.label().to_ascii_lowercase();
        if label.contains(&q) {
            return true;
        }
        self.display_name
            .as_deref()
            .map(|n| n.to_ascii_lowercase().contains(&q))
            .unwrap_or(false)
    }
}

fn picker_entry(provider_id: &str, provider: &ProviderEntry, model: &ModelEntry) -> Entry {
    let native_anthropic = cockpit_config::providers::is_anthropic_native_base_url(&provider.url);
    let wire_api = if !model.wire_api.is_auto() && model.wire_api_provenance.is_user_configured() {
        model.wire_api
    } else if !provider.wire_api.is_auto() {
        provider.wire_api
    } else if let Some(wire_api) = model.capabilities.preferred_wire_api() {
        wire_api
    } else if !model.wire_api.is_auto() {
        // A recovered endpoint remains useful when no fresh catalog declares
        // an endpoint, but never outranks that catalog above.
        model.wire_api
    } else {
        cockpit_config::providers::WireApi::detect_for_provider_entry(
            provider_id,
            provider,
            &model.id,
        )
    };
    let reasoning_effort = if native_anthropic
        && cockpit_config::providers::validate_anthropic_model_configuration(provider, &model.id)
            .is_err()
    {
        None
    } else {
        model
            .capabilities
            .reasoning_effort
            .clone()
            .filter(|capability| native_anthropic || capability.supports_wire_api(wire_api))
    };
    Entry {
        provider_id: provider_id.to_string(),
        model_id: model.id.clone(),
        display_name: model.name.clone(),
        is_favorite: model.favorite,
        reasoning_effort,
        // Legacy free-form thinking mappings are never valid on Anthropic's
        // native wire. Keeping this empty prevents the picker from advertising
        // a control the request path must drop.
        thinking_modes: if native_anthropic {
            Vec::new()
        } else {
            model.thinking_modes.clone()
        },
        failure_annotation: None,
        trust: cockpit_config::providers::ModelTrust::Untrusted,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    pub provider_id: String,
    pub model_id: String,
    pub label: String,
    pub is_favorite: bool,
    pub trust: cockpit_config::providers::ModelTrust,
}

/// Build ordered model choices from a daemon inventory-bundle model list.
/// Does not read credentials or the local provider config tree.
pub fn ordered_model_choices_from_inventory(
    models: &[cockpit_proto::ModelSummary],
    counts: &HashMap<String, u64>,
) -> Vec<ModelChoice> {
    let mut entries: Vec<Entry> = models
        .iter()
        .map(|m| Entry {
            provider_id: m.provider.clone(),
            model_id: m.id.clone(),
            display_name: m.display_name.clone(),
            is_favorite: m.favorite,
            reasoning_effort: m.reasoning_effort.clone(),
            thinking_modes: m.thinking_modes.clone(),
            failure_annotation: None,
            trust: m.trust,
        })
        .collect();
    sort_entries(&mut entries, counts, &[]);
    entries
        .into_iter()
        .map(|e| {
            let label = e.label();
            ModelChoice {
                label,
                provider_id: e.provider_id,
                model_id: e.model_id,
                is_favorite: e.is_favorite,
                trust: e.trust,
            }
        })
        .collect()
}

fn sort_entries(
    entries: &mut [Entry],
    counts: &HashMap<String, u64>,
    slot_first: &[(String, String)],
) {
    entries.sort_by(|a, b| {
        let a_slot = slot_first
            .iter()
            .position(|(provider, model)| provider == &a.provider_id && model == &a.model_id);
        let b_slot = slot_first
            .iter()
            .position(|(provider, model)| provider == &b.provider_id && model == &b.model_id);
        a_slot
            .unwrap_or(usize::MAX)
            .cmp(&b_slot.unwrap_or(usize::MAX))
            .then_with(|| b.is_favorite.cmp(&a.is_favorite))
            .then_with(|| {
                let ca = counts.get(&a.label()).copied().unwrap_or(0);
                let cb = counts.get(&b.label()).copied().unwrap_or(0);
                cb.cmp(&ca)
            })
            .then_with(|| a.label().cmp(&b.label()))
    });
}

enum Step {
    /// Picking the model.
    Pick,
    /// Model picked; choose a thinking mode.
    ChooseThinking {
        provider_id: String,
        model_id: String,
        modes: Vec<ThinkingMode>,
        cursor: usize,
    },
    /// Model picked; choose a provider-native reasoning effort value.
    ChooseReasoning {
        provider_id: String,
        model_id: String,
        capability: ReasoningEffortCapability,
        cursor: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RowHit {
    Pick { cursor: usize },
    Thinking { index: usize },
    Reasoning { index: usize },
}

impl ModelPickerDialog {
    /// Build the model picker from the held daemon provider snapshot
    /// (`tui-config-single-source`). The redacted projection carries all model
    /// metadata (ids, favorites, trust, capabilities) the picker renders.
    pub fn open_with_failures(
        cfg: cockpit_config::providers::ProvidersConfig,
        session_active_model: Option<(String, String)>,
        counts: &HashMap<String, u64>,
        failures: &crate::tui::auth_failure::AuthFailureAnnotations,
        now_epoch_secs: i64,
    ) -> Result<Self, String> {
        let mut entries: Vec<Entry> = Vec::new();
        for (pid, entry) in &cfg.providers {
            for model in &entry.models {
                let mut picker = picker_entry(pid, entry, model);
                picker.failure_annotation =
                    failures
                        .get(&(pid.clone(), model.id.clone()))
                        .map(|failure| {
                            crate::tui::auth_failure::annotation_suffix(failure, now_epoch_secs)
                        });
                picker.trust = cfg.resolve_trust(pid, &model.id);
                entries.push(picker);
            }
        }
        // Slot models first (default marked by the caller), then favorites,
        // then 30-day usage count desc, then label asc. Favorites stay
        // pinned above a more-frequent non-favorite once slot models are
        // placed.
        sort_entries(&mut entries, counts, &[]);
        let active_model = session_active_model.or_else(|| {
            cfg.active_model
                .as_ref()
                .map(|active| (active.provider.clone(), active.model.clone()))
        });
        let (cursor, scroll) =
            initial_pick_position(&entries, active_model.as_ref(), "", MODEL_WINDOW);

        Ok(Self {
            cfg,
            entries,
            active_model: active_model.clone(),
            slot_models: Vec::new(),
            slot_default: None,
            scope_provider: None,
            add_model_provider: None,
            drift: None,
            filter: TextField::default(),
            pick: list_state(cursor, scroll),
            selected_model: active_model.clone(),
            step: Step::Pick,
            error: None,
            done: false,
            persist_as_default: false,
            row_hits: Vec::new(),
        })
    }

    /// Apply the daemon-owned active slot envelope. Pairs retain the daemon's
    /// declared order; the default identity is presentation-only and never
    /// inferred from provider configuration.
    pub fn set_active_slot_models(
        &mut self,
        allowed: Vec<(String, String)>,
        default: Option<(String, String)>,
        counts: &HashMap<String, u64>,
    ) {
        self.slot_models = allowed;
        self.slot_default = default.filter(|identity| self.slot_models.contains(identity));
        sort_entries(&mut self.entries, counts, &self.slot_models);
        self.retarget_pick_position();
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    /// Consume an explicit request to edit models for the scoped provider.
    pub fn take_add_model_provider(&mut self) -> Option<String> {
        self.add_model_provider.take()
    }

    pub fn open_for_provider_with_failures(
        cfg: cockpit_config::providers::ProvidersConfig,
        provider: &str,
        session_active_model: Option<(String, String)>,
        counts: &HashMap<String, u64>,
        failures: &crate::tui::auth_failure::AuthFailureAnnotations,
        now_epoch_secs: i64,
    ) -> Result<Self, String> {
        let mut picker =
            Self::open_with_failures(cfg, session_active_model, counts, failures, now_epoch_secs)?;
        picker.entries.retain(|entry| entry.provider_id == provider);
        picker.scope_provider = Some(provider.to_string());
        picker.active_model = picker
            .active_model
            .filter(|(active_provider, _)| active_provider == provider);
        picker.retarget_pick_position();
        Ok(picker)
    }

    pub fn set_config_drift(&mut self, drift: Option<ModelPickerDrift>) {
        if self.drift == drift {
            return;
        }
        self.drift = drift;
        self.retarget_pick_position();
    }

    /// Re-focus a picker on a previously requested pair after the daemon
    /// rejects its correlated selection. This is visual intent only: it never
    /// changes the daemon-confirmed active model or persisted configuration.
    pub fn highlight_requested_model(&mut self, provider: &str, model: &str) {
        self.filter = TextField::default();
        let requested = Some((provider.to_string(), model.to_string()));
        let (cursor, scroll) =
            initial_pick_position(&self.entries, requested.as_ref(), "", MODEL_WINDOW);
        self.pick = list_state(cursor, scroll);
        self.selected_model = Some((provider.to_string(), model.to_string()));
    }

    /// Restore the complete rejected request as the picker draft so retrying keeps
    /// reasoning, thinking, and cache preferences instead of silently clearing them.
    /// This mutates only the dialog draft; the daemon-confirmed app state remains
    /// authoritative until a subsequent selection result is applied.
    pub fn restore_requested_selection(&mut self, requested: &ActiveModelRef) {
        self.cfg.active_model = Some(requested.clone());
        self.highlight_requested_model(&requested.provider, &requested.model);
    }

    /// Show an actionable failure without discarding the user's highlighted
    /// selection or reopening an unrelated modal.
    pub fn set_error(&mut self, message: impl Into<String>) {
        self.error = Some(message.into());
    }

    #[cfg(test)]
    pub fn error_text(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub(crate) fn draft_active_model(&self) -> Option<&ActiveModelRef> {
        self.cfg.active_model.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn has_model(&self, provider: &str, model: &str) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.provider_id == provider && entry.model_id == model)
    }

    fn filtered_indices(&self) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.matches(self.filter.text()))
            .map(|(i, _)| i)
            .collect()
    }

    /// Returns true if the dialog should close.
    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        if matches!(key.code, KeyCode::Char('a'))
            && key
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL)
            && matches!(self.step, Step::Pick)
            && let Some(provider) = self.scope_provider.clone()
        {
            self.add_model_provider = Some(provider);
            self.done = true;
            return true;
        }
        if matches!(key.code, KeyCode::Esc) {
            return true;
        }
        match &mut self.step {
            Step::Pick => self.handle_pick_key(key),
            Step::ChooseThinking { .. } => self.handle_thinking_key(key),
            Step::ChooseReasoning { .. } => self.handle_reasoning_key(key),
        }
    }

    pub fn handle_mouse_row(&mut self, row: u16) -> bool {
        let Some(Some(hit)) = self.row_hits.get(row as usize).copied() else {
            return false;
        };
        match hit {
            RowHit::Pick { cursor } => {
                self.pick.select(Some(cursor));
                self.remember_pick_identity();
                self.handle_pick_key(KeyEvent::from(KeyCode::Enter))
            }
            RowHit::Thinking { index } => {
                if let Step::ChooseThinking { cursor, .. } = &mut self.step {
                    *cursor = index;
                }
                self.handle_thinking_key(KeyEvent::from(KeyCode::Enter))
            }
            RowHit::Reasoning { index } => {
                if let Step::ChooseReasoning { cursor, .. } = &mut self.step {
                    *cursor = index;
                }
                self.handle_reasoning_key(KeyEvent::from(KeyCode::Enter))
            }
        }
    }

    /// Insert pasted text into the filter (the only text field), mirroring
    /// the typing path: paste applies on the `Pick` step and resets the
    /// cursor/scroll when the visible set changes. Other steps have no text
    /// field, so the paste is dropped.
    pub fn paste(&mut self, text: &str) {
        if matches!(self.step, Step::Pick) {
            let before = self.filter.text().to_string();
            self.filter.paste(text);
            if before != self.filter.text() {
                self.retarget_pick_position();
            }
        }
    }

    fn handle_pick_key(&mut self, key: KeyEvent) -> bool {
        let visible = self.filtered_indices();
        let drift_offset = usize::from(self.drift_switch_model().is_some());
        let total = visible.len() + drift_offset;
        // Arrow keys navigate (with wrap); `j`/`k` stay literal text for
        // the filter, since this step is typing-driven.
        match key.code {
            KeyCode::Up => {
                move_list_selection(&mut self.pick, -1, total);
                self.remember_pick_identity();
            }
            KeyCode::Char('p')
                if key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                move_list_selection(&mut self.pick, -1, total);
                self.remember_pick_identity();
            }
            KeyCode::Down => {
                move_list_selection(&mut self.pick, 1, total);
                self.remember_pick_identity();
            }
            KeyCode::Char('n')
                if key
                    .modifiers
                    .contains(crossterm::event::KeyModifiers::CONTROL) =>
            {
                move_list_selection(&mut self.pick, 1, total);
                self.remember_pick_identity();
            }
            KeyCode::Enter => {
                if list_cursor(&self.pick) == 0
                    && let Some(active) = self.drift_switch_model().cloned()
                {
                    return self.commit_active_model(
                        active.provider,
                        active.model,
                        active.reasoning_effort,
                        active.thinking_mode,
                        active.prompt_cache_retention,
                        key.modifiers
                            .contains(crossterm::event::KeyModifiers::CONTROL),
                    );
                }
                let entry_cursor = list_cursor(&self.pick).saturating_sub(drift_offset);
                if let Some(&i) = visible.get(entry_cursor) {
                    let entry = self.entries[i].clone();
                    if let Some(capability) = entry
                        .reasoning_effort
                        .clone()
                        .filter(|capability| !capability.values.is_empty())
                    {
                        let cursor = self.initial_reasoning_cursor(
                            &entry.provider_id,
                            &entry.model_id,
                            &capability,
                        );
                        self.step = Step::ChooseReasoning {
                            provider_id: entry.provider_id,
                            model_id: entry.model_id,
                            capability,
                            cursor,
                        };
                    } else if entry.thinking_modes.is_empty() {
                        let retention = self
                            .retained_prompt_cache_retention(&entry.provider_id, &entry.model_id);
                        return self.commit_active_model(
                            entry.provider_id,
                            entry.model_id,
                            None,
                            None,
                            retention,
                            key.modifiers
                                .contains(crossterm::event::KeyModifiers::CONTROL),
                        );
                    } else {
                        let modes = entry.thinking_modes.clone();
                        let cursor = self.initial_thinking_cursor(
                            &entry.provider_id,
                            &entry.model_id,
                            &modes,
                        );
                        self.step = Step::ChooseThinking {
                            provider_id: entry.provider_id,
                            model_id: entry.model_id,
                            modes,
                            cursor,
                        };
                    }
                }
            }
            _ => {
                // Typing filters the list. Reset the cursor when the
                // visible set changes to avoid pointing past the end.
                let before = self.filter.text().to_string();
                self.filter.handle_key(key);
                if before != self.filter.text() {
                    self.retarget_pick_position();
                }
            }
        }
        false
    }

    fn retarget_pick_position(&mut self) {
        if self.drift_switch_model().is_some() {
            self.pick = list_state(0, 0);
            return;
        }
        let preferred = self.selected_model.as_ref().or(self.active_model.as_ref());
        let (cursor, scroll) =
            initial_pick_position(&self.entries, preferred, self.filter.text(), MODEL_WINDOW);
        self.pick = list_state(cursor, scroll);
    }

    fn remember_pick_identity(&mut self) {
        if self.drift_switch_model().is_some() && list_cursor(&self.pick) == 0 {
            self.selected_model = None;
            return;
        }
        let drift_offset = usize::from(self.drift_switch_model().is_some());
        let entry_cursor = list_cursor(&self.pick).saturating_sub(drift_offset);
        let visible = self.filtered_indices();
        self.selected_model = visible.get(entry_cursor).map(|index| {
            let entry = &self.entries[*index];
            (entry.provider_id.clone(), entry.model_id.clone())
        });
    }

    fn handle_thinking_key(&mut self, key: KeyEvent) -> bool {
        let (provider_id, model_id, modes, cursor) = match &mut self.step {
            Step::ChooseThinking {
                provider_id,
                model_id,
                modes,
                cursor,
            } => (provider_id, model_id, modes, cursor),
            _ => return false,
        };
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                *cursor = crate::tui::nav::wrap_prev(*cursor, modes.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                *cursor = crate::tui::nav::wrap_next(*cursor, modes.len());
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.step = Step::Pick;
            }
            KeyCode::Enter => {
                let mode = modes.get(*cursor).copied();
                let p = provider_id.clone();
                let m = model_id.clone();
                let retention = self.retained_prompt_cache_retention(&p, &m);
                return self.commit_active_model(
                    p,
                    m,
                    None,
                    mode,
                    retention,
                    key.modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL),
                );
            }
            _ => {}
        }
        false
    }

    fn handle_reasoning_key(&mut self, key: KeyEvent) -> bool {
        let (provider_id, model_id, capability, cursor) = match &mut self.step {
            Step::ChooseReasoning {
                provider_id,
                model_id,
                capability,
                cursor,
            } => (provider_id, model_id, capability, cursor),
            _ => return false,
        };
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => {
                *cursor = crate::tui::nav::wrap_prev(*cursor, capability.values.len());
            }
            KeyCode::Down | KeyCode::Char('j') => {
                *cursor = crate::tui::nav::wrap_next(*cursor, capability.values.len());
            }
            KeyCode::Left | KeyCode::Char('h') | KeyCode::Backspace => {
                self.step = Step::Pick;
            }
            KeyCode::Enter => {
                let effort = capability
                    .values
                    .get(*cursor)
                    .map(|value| ActiveReasoningEffort {
                        value: value.value.clone(),
                    });
                let p = provider_id.clone();
                let m = model_id.clone();
                let retention = self.retained_prompt_cache_retention(&p, &m);
                return self.commit_active_model(
                    p,
                    m,
                    effort,
                    None,
                    retention,
                    key.modifiers
                        .contains(crossterm::event::KeyModifiers::CONTROL),
                );
            }
            _ => {}
        }
        false
    }

    fn commit_active_model(
        &mut self,
        provider_id: String,
        model_id: String,
        reasoning_effort: Option<ActiveReasoningEffort>,
        thinking_mode: Option<ThinkingMode>,
        prompt_cache_retention: Option<PromptCacheRetention>,
        persist_as_default: bool,
    ) -> bool {
        self.cfg.active_model = Some(ActiveModelRef {
            provider: provider_id,
            model: model_id,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
        });
        self.persist_as_default = persist_as_default;
        self.done = true;
        true
    }

    pub fn persists_as_default(&self) -> bool {
        self.done && self.persist_as_default
    }

    pub fn selected_active_model(&self) -> Option<ActiveModelRef> {
        self.done.then(|| self.cfg.active_model.clone()).flatten()
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.row_hits.clear();
        self.row_hits
            .resize(area.y.saturating_add(area.height) as usize, None);
        let title = self
            .scope_provider
            .as_deref()
            .map(|provider| format!(" /model — {provider} models "))
            .unwrap_or_else(|| " /model — pick the active model ".to_string());
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        match &self.step {
            Step::Pick => self.render_pick(frame, layout[0]),
            Step::ChooseThinking { .. } => self.render_thinking(frame, layout[0]),
            Step::ChooseReasoning { .. } => self.render_reasoning(frame, layout[0]),
        }
        let help = match &self.step {
            Step::Pick if self.scope_provider.is_some() => {
                "type to filter  ↑/↓  enter: session  Ctrl+enter: session + default  Ctrl+a: add model  esc: cancel"
            }
            Step::Pick => {
                "type to filter  ↑/↓ or Ctrl+n/Ctrl+p  enter: session  Ctrl+enter: session + default  esc: cancel"
            }
            Step::ChooseThinking { .. } => {
                "↑/↓  enter: session  Ctrl+enter: session + default  ←: back  esc: cancel"
            }
            Step::ChooseReasoning { .. } => {
                "↑/↓  enter: session  Ctrl+enter: session + default  ←: back  esc: cancel"
            }
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(
                help.to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            ))),
            layout[1],
        );
    }

    fn render_pick(&mut self, frame: &mut Frame, area: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Indexed(178));
        let (filter_before, filter_after) = self.filter.split_at_cursor();
        let error_height = u16::from(self.error.is_some());
        let regions = Layout::vertical([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(error_height),
        ])
        .split(area);
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("filter: ", muted),
                Span::styled(filter_before.to_string(), Style::default().fg(Color::White)),
                Span::styled(filter_after.to_string(), Style::default().fg(Color::White)),
            ])),
            regions[0],
        );

        let drift_offset = usize::from(self.drift_switch_model().is_some());
        let mut items: Vec<ListItem<'static>> = Vec::new();
        let mut item_heights: Vec<u16> = Vec::new();
        if let Some(drift) = &self.drift {
            if let Some(active) = &drift.config_model {
                items.push(ListItem::new(vec![
                    Line::from(Span::styled(
                        format!(
                            "This session is running {}, but your config's active model is {}.",
                            drift.session_label, drift.config_label
                        ),
                        Style::default().fg(Color::Indexed(178)),
                    )),
                    Line::from(format!(
                        "Switch to config model: {}/{}",
                        active.provider, active.model
                    )),
                ]));
                item_heights.push(2);
            }
        }

        let visible = self.filtered_indices();
        if visible.is_empty() {
            let body = if self.entries.is_empty() {
                match self.scope_provider.as_deref() {
                    Some(provider) => {
                        format!(
                            "(no models configured for {provider} — press Ctrl+A to add a model)"
                        )
                    }
                    None => "(no models — run `/fetch-models` or add a provider via `/settings`)"
                        .to_string(),
                }
            } else {
                "(no matches — try a different filter)".to_string()
            };
            items.push(ListItem::new(Line::from(Span::styled(body, muted))));
            item_heights.push(1);
            self.pick.select(None);
        } else {
            let mut seen_fav = false;
            let mut seen_other = false;
            for &idx in &visible {
                let e = &self.entries[idx];
                let mut item_lines = Vec::new();
                if e.is_favorite && !seen_fav {
                    item_lines.push(Line::from(Span::styled(
                        "favorites".to_string(),
                        muted.add_modifier(Modifier::ITALIC),
                    )));
                    seen_fav = true;
                }
                if !e.is_favorite && !seen_other {
                    item_lines.push(Line::from(Span::styled(
                        "all models".to_string(),
                        muted.add_modifier(Modifier::ITALIC),
                    )));
                    seen_other = true;
                }
                let is_active_model = self.is_active_entry(e);
                let label_style = if e.is_favorite {
                    yellow
                } else {
                    Style::default().fg(Color::White)
                };
                let mut spans = vec![Span::styled(e.label(), label_style)];
                spans.push(Span::raw("  "));
                spans.push(Span::styled(
                    match e.trust {
                        cockpit_config::providers::ModelTrust::Trusted => "[trusted]".to_string(),
                        cockpit_config::providers::ModelTrust::Untrusted => {
                            "[untrusted]".to_string()
                        }
                    },
                    muted,
                ));
                if let Some(name) = &e.display_name {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(name.clone(), muted));
                }
                if let Some(capability) = e
                    .reasoning_effort
                    .as_ref()
                    .filter(|capability| !capability.values.is_empty())
                {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(
                        format!("[reasoning: {}]", reasoning_summary(capability)),
                        muted,
                    ));
                } else if !e.thinking_modes.is_empty() {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(
                        format!("[thinking: {}]", thinking_summary(&e.thinking_modes)),
                        muted,
                    ));
                }
                if is_active_model {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled("[active]".to_string(), muted));
                }
                if self.slot_default.as_ref().is_some_and(|(provider, model)| {
                    provider == &e.provider_id && model == &e.model_id
                }) {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled("[default]".to_string(), muted));
                }
                if let Some(failure) = &e.failure_annotation {
                    spans.push(Span::raw("  "));
                    spans.push(Span::styled(
                        failure.clone(),
                        Style::default().fg(Color::Red),
                    ));
                }
                item_lines.push(Line::from(spans));
                let visible_pos = visible
                    .iter()
                    .position(|&visible_idx| visible_idx == idx)
                    .unwrap_or(0);
                if visible_pos + drift_offset == list_cursor(&self.pick) {
                    for line in &mut item_lines {
                        line.spans.insert(0, Span::raw("> "));
                    }
                }
                item_heights.push(item_lines.len() as u16);
                items.push(ListItem::new(item_lines));
            }
        }
        let total = visible.len() + drift_offset;
        if total > 0 {
            let selected = list_cursor(&self.pick).min(total - 1);
            self.pick.select(Some(selected));
        }
        let list_area = regions[1];
        let list = List::new(items)
            .highlight_symbol("")
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            )
            .scroll_padding(1);
        StatefulWidget::render(list, list_area, frame.buffer_mut(), &mut self.pick);

        let offset = self.pick.offset().min(item_heights.len());
        let row_offset: usize = item_heights[..offset]
            .iter()
            .map(|height| *height as usize)
            .sum();
        let total_rows: usize = item_heights.iter().map(|height| *height as usize).sum();
        if total > 0 {
            let mut y = list_area.y;
            for (item_index, height) in item_heights.iter().copied().enumerate().skip(offset) {
                if y >= list_area.bottom() {
                    break;
                }
                let selectable_row = y.saturating_add(height.saturating_sub(1));
                if selectable_row < list_area.bottom()
                    && let Some(slot) = self.row_hits.get_mut(selectable_row as usize)
                {
                    *slot = Some(RowHit::Pick { cursor: item_index });
                }
                y = y.saturating_add(height);
            }
        }
        if total_rows > list_area.height as usize && list_area.width > 1 {
            let mut scrollbar = ScrollbarState::new(total_rows)
                .position(row_offset)
                .viewport_content_length(list_area.height as usize);
            frame.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight),
                list_area,
                &mut scrollbar,
            );
        }
        if let Some(error) = self.error.as_deref() {
            frame.render_widget(
                Paragraph::new(Line::from(Span::styled(error.to_string(), Color::Red)))
                    .wrap(Wrap { trim: false }),
                regions[2],
            );
        }
        if area.height > 0 && area.width > 0 {
            let col = "filter: ".width() + filter_before.width();
            let col = col.min(area.width.saturating_sub(1) as usize) as u16;
            frame.set_cursor_position(Position::new(area.x + col, area.y));
        }
    }

    fn render_thinking(&mut self, frame: &mut Frame, area: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let (provider_id, model_id, modes, cursor) = match &self.step {
            Step::ChooseThinking {
                provider_id,
                model_id,
                modes,
                cursor,
            } => (provider_id, model_id, modes, cursor),
            _ => return,
        };
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("model: ".to_string(), muted),
            Span::styled(
                format!("{provider_id}/{model_id}"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Provider thinking mode: (request parameter)".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for (i, m) in modes.iter().enumerate() {
            let marker = if i == *cursor { "> " } else { "  " };
            let style = if i == *cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            lines.push(Line::from(vec![
                Span::raw(marker.to_string()),
                Span::styled(thinking_label(*m), style),
            ]));
            let row = area.y + lines.len() as u16 - 1;
            if row < area.y + area.height
                && let Some(slot) = self.row_hits.get_mut(row as usize)
            {
                *slot = Some(RowHit::Thinking { index: i });
            }
        }
        push_error_line(&mut lines, self.error.as_deref());
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn render_reasoning(&mut self, frame: &mut Frame, area: Rect) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let (provider_id, model_id, capability, cursor) = match &self.step {
            Step::ChooseReasoning {
                provider_id,
                model_id,
                capability,
                cursor,
            } => (provider_id, model_id, capability, cursor),
            _ => return,
        };
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(vec![
            Span::styled("model: ".to_string(), muted),
            Span::styled(
                format!("{provider_id}/{model_id}"),
                Style::default().add_modifier(Modifier::BOLD),
            ),
        ]));
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "Reasoning effort: (provider request parameter)".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        for (i, value) in capability.values.iter().enumerate() {
            let marker = if i == *cursor { "> " } else { "  " };
            let style = if i == *cursor {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let mut spans = vec![
                Span::raw(marker.to_string()),
                Span::styled(reasoning_value_label(value), style),
            ];
            if value
                .label
                .as_deref()
                .is_some_and(|label| label != value.value)
            {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(value.value.clone(), muted));
            }
            if let Some(description) = &value.description {
                spans.push(Span::raw("  "));
                spans.push(Span::styled(description.clone(), muted));
            }
            lines.push(Line::from(spans));
            let row = area.y + lines.len() as u16 - 1;
            if row < area.y + area.height
                && let Some(slot) = self.row_hits.get_mut(row as usize)
            {
                *slot = Some(RowHit::Reasoning { index: i });
            }
        }
        push_error_line(&mut lines, self.error.as_deref());
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }

    fn is_active_entry(&self, entry: &Entry) -> bool {
        self.active_model
            .as_ref()
            .map(|(provider, model)| provider == &entry.provider_id && model == &entry.model_id)
            .unwrap_or(false)
    }

    fn drift_switch_model(&self) -> Option<&ActiveModelRef> {
        self.drift
            .as_ref()
            .and_then(|drift| drift.config_model.as_ref())
    }

    fn initial_thinking_cursor(
        &self,
        provider_id: &str,
        model_id: &str,
        modes: &[ThinkingMode],
    ) -> usize {
        self.cfg
            .active_model
            .as_ref()
            .filter(|active| active.provider == provider_id && active.model == model_id)
            .and_then(|active| active.thinking_mode)
            .and_then(|selected| modes.iter().position(|mode| *mode == selected))
            .unwrap_or(0)
    }

    fn retained_prompt_cache_retention(
        &self,
        provider_id: &str,
        model_id: &str,
    ) -> Option<PromptCacheRetention> {
        let selected = self
            .cfg
            .active_model
            .as_ref()
            .filter(|active| active.provider == provider_id && active.model == model_id)
            .and_then(|active| active.prompt_cache_retention)
            .filter(|retention| !retention.is_default());
        selected.filter(|retention| {
            self.cfg
                .resolve_prompt_cache_retention(provider_id, model_id, Some(*retention))
                .is_some()
        })
    }

    fn initial_reasoning_cursor(
        &self,
        provider_id: &str,
        model_id: &str,
        capability: &ReasoningEffortCapability,
    ) -> usize {
        let selected = self
            .cfg
            .active_model
            .as_ref()
            .filter(|active| active.provider == provider_id && active.model == model_id)
            .and_then(|active| active.reasoning_effort.as_ref())
            .map(|effort| effort.value.as_str())
            .or(capability.default.as_deref());
        selected
            .and_then(|selected| {
                capability
                    .values
                    .iter()
                    .position(|value| value.value == selected)
            })
            .unwrap_or(0)
    }
}

impl Pane for ModelPickerDialog {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        ModelPickerDialog::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        ModelPickerDialog::render(self, frame, area);
    }
}

fn push_error_line(lines: &mut Vec<Line<'static>>, error: Option<&str>) {
    if let Some(err) = error {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            err.to_string(),
            Style::default().fg(Color::Red),
        )));
    }
}

fn initial_pick_position(
    entries: &[Entry],
    active_model: Option<&(String, String)>,
    filter: &str,
    window: usize,
) -> (usize, usize) {
    let visible: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.matches(filter))
        .map(|(i, _)| i)
        .collect();
    let cursor = active_model
        .and_then(|(provider, model)| {
            visible.iter().position(|&idx| {
                let e = &entries[idx];
                &e.provider_id == provider && &e.model_id == model
            })
        })
        .unwrap_or(0);
    let scroll = crate::tui::nav::windowed_scroll(cursor, 0, visible.len(), window);
    (cursor, scroll)
}

fn thinking_label(m: ThinkingMode) -> String {
    match m {
        ThinkingMode::Off => "off",
        ThinkingMode::Low => "low",
        ThinkingMode::Medium => "medium",
        ThinkingMode::High => "high",
    }
    .to_string()
}

fn thinking_summary(modes: &[ThinkingMode]) -> String {
    modes
        .iter()
        .copied()
        .map(thinking_label)
        .collect::<Vec<_>>()
        .join("/")
}

fn reasoning_value_label(value: &CapabilityValue) -> String {
    value.label.clone().unwrap_or_else(|| value.value.clone())
}

fn reasoning_summary(capability: &ReasoningEffortCapability) -> String {
    capability
        .values
        .iter()
        .map(|value| value.value.clone())
        .collect::<Vec<_>>()
        .join("/")
}

pub fn cycle_active_favorite(
    cfg: &cockpit_config::providers::ProvidersConfig,
    active: Option<&ActiveModelRef>,
    counts: &HashMap<String, u64>,
    forward: bool,
) -> Result<Option<ActiveModelRef>, String> {
    let active_key = active.map(|active| (active.provider.clone(), active.model.clone()));
    let mut entries: Vec<Entry> = Vec::new();
    for (pid, entry) in &cfg.providers {
        for model in &entry.models {
            if model.favorite {
                let mut picker = picker_entry(pid, entry, model);
                picker.trust = cfg.resolve_trust(pid, &model.id);
                entries.push(picker);
            }
        }
    }
    sort_entries(&mut entries, counts, &[]);
    if entries.is_empty() {
        return Ok(None);
    }
    if entries.len() == 1
        && active_key.as_ref().is_some_and(|(provider, model)| {
            entries[0].provider_id == *provider && entries[0].model_id == *model
        })
    {
        return Ok(None);
    }
    let current = active_key.as_ref().and_then(|(p, m)| {
        entries
            .iter()
            .position(|e| &e.provider_id == p && &e.model_id == m)
    });
    let target_idx = match (current, forward) {
        (Some(idx), true) => (idx + 1) % entries.len(),
        (Some(0), false) => entries.len() - 1,
        (Some(idx), false) => idx - 1,
        (None, _) => 0,
    };
    let target = &entries[target_idx];
    let mut selection = ActiveModelRef {
        provider: target.provider_id.clone(),
        model: target.model_id.clone(),
        reasoning_effort: None,
        thinking_mode: None,
        prompt_cache_retention: None,
    };
    if let Some(current) = active {
        selection.reasoning_effort = current.reasoning_effort.clone().filter(|effort| {
            target.reasoning_effort.as_ref().is_some_and(|capability| {
                capability
                    .values
                    .iter()
                    .any(|candidate| candidate.value == effort.value)
            })
        });
        selection.thinking_mode = current
            .thinking_mode
            .filter(|mode| target.thinking_modes.contains(mode));
        selection.prompt_cache_retention = current.prompt_cache_retention.filter(|retention| {
            retention.is_default()
                || cfg
                    .resolve_prompt_cache_retention(
                        &target.provider_id,
                        &target.model_id,
                        Some(*retention),
                    )
                    .is_some()
        });
    }
    Ok(Some(selection))
}

#[allow(dead_code)]
fn ensure_config_reachable(cwd: &Path) -> Result<(), String> {
    if std::env::var_os(COCKPIT_CONFIG_ENV).is_some() {
        return Ok(());
    }
    if config_file_paths_for_load(cwd)
        .into_iter()
        .any(|path| path.exists())
    {
        Ok(())
    } else {
        Err("no cockpit config found — run `/settings` to create one".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use std::collections::{BTreeMap, HashMap};
    use std::fs;

    /// Load the layered provider config for a test tree the same way the held
    /// daemon snapshot's projection is derived (uncounted, no credential
    /// resolution) — stands in for the pushed snapshot in unit tests.
    fn providers_at(cwd: &std::path::Path) -> cockpit_config::providers::ProvidersConfig {
        let paths = cockpit_config::dirs::config_file_paths_for_load(cwd);
        let mut cfg = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
        if cfg.providers.is_empty() {
            let providers_dir = cwd.join(".cockpit").join("providers");
            if let Ok(entries) = fs::read_dir(providers_dir) {
                for entry in entries.flatten() {
                    let Ok(contents) = fs::read_to_string(entry.path()) else {
                        continue;
                    };
                    let Ok(provider) =
                        serde_json::from_str::<cockpit_config::providers::ProviderEntry>(&contents)
                    else {
                        continue;
                    };
                    let path = entry.path();
                    let Some(id) = path.file_stem().and_then(|name| name.to_str()) else {
                        continue;
                    };
                    cfg.providers.insert(id.to_string(), provider);
                }
            }
        }
        cfg
    }

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn ctrl_press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn empty_dialog() -> ModelPickerDialog {
        // Build a dialog with no entries — exercises only key routing.
        ModelPickerDialog {
            cfg: ProvidersConfig::default(),
            entries: Vec::new(),
            active_model: None,
            slot_models: Vec::new(),
            slot_default: None,
            scope_provider: None,
            add_model_provider: None,
            drift: None,
            filter: TextField::default(),
            pick: ListState::default(),
            selected_model: None,
            step: Step::Pick,
            error: None,
            done: false,
            persist_as_default: false,
            row_hits: Vec::new(),
        }
    }

    /// Typing while the picker is open must not bubble out. The picker
    /// returns `false` from `handle_key` (don't close) but App must
    /// still swallow the key so it never reaches the composer.
    #[test]
    fn typing_a_filter_char_does_not_request_close() {
        let mut d = empty_dialog();
        // `j` was the original repro: in handle_pick_key it lands in
        // the `_` arm and feeds the filter. The return value tells App
        // "stay open"; App is responsible for not propagating the key.
        assert!(!d.handle_key(press(KeyCode::Char('j'))));
        assert_eq!(d.filter.text(), "j");
        assert!(!d.handle_key(press(KeyCode::Char('k'))));
        assert_eq!(d.filter.text(), "jk");
    }

    #[test]
    fn esc_signals_close() {
        let mut d = empty_dialog();
        assert!(d.handle_key(press(KeyCode::Esc)));
    }

    fn entry(model: &str) -> Entry {
        Entry {
            provider_id: "p".into(),
            model_id: model.into(),
            display_name: None,
            is_favorite: false,
            reasoning_effort: None,
            thinking_modes: Vec::new(),
            failure_annotation: None,
            trust: cockpit_config::providers::ModelTrust::Untrusted,
        }
    }

    fn favorite_entry(model: &str) -> Entry {
        let mut entry = entry(model);
        entry.is_favorite = true;
        entry
    }

    fn reasoning_capability() -> ReasoningEffortCapability {
        ReasoningEffortCapability {
            values: vec![
                CapabilityValue {
                    value: "minimal".into(),
                    label: Some("Minimal".into()),
                    description: Some("shortest reasoning".into()),
                },
                CapabilityValue {
                    value: "xhigh".into(),
                    label: Some("Extra high".into()),
                    description: Some("deepest reasoning".into()),
                },
            ],
            default: Some("xhigh".into()),
            request_mapping: Some(
                cockpit_config::providers::ReasoningEffortRequestMapping::JsonField {
                    field: "reasoning_effort".into(),
                    values: BTreeMap::from([
                        ("minimal".into(), serde_json::json!("minimal")),
                        ("xhigh".into(), serde_json::json!("xhigh")),
                    ]),
                },
            ),
            endpoint_request_mappings: Vec::new(),
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        }
    }

    #[test]
    fn native_anthropic_picker_hides_legacy_and_invalid_reasoning_controls() {
        let model = ModelEntry {
            id: "claude-test".into(),
            thinking_modes: vec![ThinkingMode::High],
            capabilities: cockpit_config::providers::ModelCapabilities {
                max_output_tokens: Some(8_192),
                reasoning_effort: Some(reasoning_capability()),
                ..cockpit_config::providers::ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };
        let provider = ProviderEntry {
            url: "https://api.anthropic.com/v1".into(),
            models: vec![model.clone()],
            ..ProviderEntry::default()
        };
        let entry = picker_entry("anthropic", &provider, &model);
        assert!(entry.thinking_modes.is_empty());
        assert!(entry.reasoning_effort.is_none());
    }

    #[test]
    fn copilot_gpt5_favorite_uses_responses_fallback_for_effort_picker() {
        let responses_only_effort = ReasoningEffortCapability {
            values: vec![CapabilityValue {
                value: "ultra".into(),
                label: None,
                description: None,
            }],
            default: Some("ultra".into()),
            request_mapping: None,
            endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".into(), "effort".into()],
                    values: BTreeMap::from([("ultra".into(), serde_json::json!("ultra"))]),
                },
            }],
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        };
        let model = ModelEntry {
            id: "gpt-5.6-terra".into(),
            favorite: true,
            capabilities: ModelCapabilities {
                reasoning_effort: Some(responses_only_effort),
                // No catalog endpoint is present: this must follow the same
                // Copilot GPT-5 fallback as the request resolver.
                supported_wire_apis: Vec::new(),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };
        let provider = ProviderEntry::default();

        let entry = picker_entry("copilot", &provider, &model);

        assert!(entry.is_favorite);
        assert!(
            entry.reasoning_effort.is_some(),
            "the favorite must expose its Responses-only effort picker"
        );
    }

    #[test]
    fn renamed_copilot_gpt5_uses_responses_fallback_for_effort_picker() {
        let responses_only_effort = ReasoningEffortCapability {
            values: vec![CapabilityValue {
                value: "ultra".into(),
                label: None,
                description: None,
            }],
            default: Some("ultra".into()),
            request_mapping: None,
            endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".into(), "effort".into()],
                    values: BTreeMap::from([("ultra".into(), serde_json::json!("ultra"))]),
                },
            }],
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        };
        let model = ModelEntry {
            id: "gpt-5.6-terra".into(),
            capabilities: ModelCapabilities {
                reasoning_effort: Some(responses_only_effort),
                supported_wire_apis: Vec::new(),
                ..ModelCapabilities::default()
            },
            ..ModelEntry::default()
        };
        let provider = ProviderEntry {
            template: Some("copilot".into()),
            ..ProviderEntry::default()
        };

        assert!(
            picker_entry("team-github", &provider, &model)
                .reasoning_effort
                .is_some()
        );
    }

    fn reasoning_entry(model: &str) -> Entry {
        let mut entry = entry(model);
        entry.reasoning_effort = Some(reasoning_capability());
        entry
    }

    fn dialog_with(entries: Vec<Entry>) -> ModelPickerDialog {
        ModelPickerDialog {
            cfg: ProvidersConfig::default(),
            entries,
            active_model: None,
            slot_models: Vec::new(),
            slot_default: None,
            scope_provider: None,
            add_model_provider: None,
            drift: None,
            filter: TextField::default(),
            pick: ListState::default(),
            selected_model: None,
            step: Step::Pick,
            error: None,
            done: false,
            persist_as_default: false,
            row_hits: Vec::new(),
        }
    }

    fn dialog_with_cwd(_cwd: std::path::PathBuf, entries: Vec<Entry>) -> ModelPickerDialog {
        ModelPickerDialog {
            cfg: ProvidersConfig::default(),
            entries,
            active_model: None,
            slot_models: Vec::new(),
            slot_default: None,
            scope_provider: None,
            add_model_provider: None,
            drift: None,
            filter: TextField::default(),
            pick: ListState::default(),
            selected_model: None,
            step: Step::Pick,
            error: None,
            done: false,
            persist_as_default: false,
            row_hits: Vec::new(),
        }
    }

    fn rendered_text(d: &mut ModelPickerDialog, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| d.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw");
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .filter_map(|cell| {
                let symbol = cell.symbol();
                (!symbol.is_empty()).then_some(symbol)
            })
            .collect::<String>();
        // Wide CJK glyphs occupy two TestBackend cells; the continuation
        // cell is sometimes a space. Drop those so unicode identity asserts
        // see "模型" rather than "模 型".
        let mut compact = String::new();
        for ch in rendered.chars() {
            if ch == ' '
                && compact
                    .chars()
                    .last()
                    .is_some_and(|prev| unicode_width::UnicodeWidthChar::width(prev) == Some(2))
            {
                continue;
            }
            compact.push(ch);
        }
        compact
    }

    #[test]
    fn pick_filter_caret_follows_textfield_cursor_after_mid_insert() {
        let mut d = dialog_with(vec![entry("alpha")]);
        d.handle_key(press(KeyCode::Char('a')));
        d.handle_key(press(KeyCode::Char('b')));
        d.handle_key(press(KeyCode::Left));
        d.handle_key(press(KeyCode::Char('X')));

        let rendered = rendered_text(&mut d, 60, 12);

        assert!(rendered.contains("filter: aXb"), "{rendered}");
    }

    #[test]
    fn model_picker_can_switch_session_to_config_model() {
        let mut normal = dialog_with(vec![entry("a")]);
        let rendered = rendered_text(&mut normal, 100, 20);
        assert!(!rendered.contains("This session is running"), "{rendered}");
        assert!(!rendered.contains("Switch to config model"), "{rendered}");

        let mut drifted = dialog_with(vec![entry("a")]);
        drifted.set_config_drift(Some(ModelPickerDrift {
            session_label: "other/old".to_string(),
            config_label: "p/a".to_string(),
            config_model: Some(ActiveModelRef {
                provider: "p".to_string(),
                model: "a".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
        }));
        let rendered = rendered_text(&mut drifted, 100, 20);
        assert!(
            rendered.contains("This session is running other/old"),
            "{rendered}"
        );
        assert!(
            rendered.contains("Switch to config model: p/a"),
            "{rendered}"
        );

        assert!(drifted.handle_key(press(KeyCode::Enter)));
        let active = drifted
            .selected_active_model()
            .expect("selected active model");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "a");
    }

    #[test]
    fn config_drift_model_picker_refresh_preserves_cursor_when_unchanged() {
        let drift = ModelPickerDrift {
            session_label: "other/old".to_string(),
            config_label: "p/config".to_string(),
            config_model: Some(ActiveModelRef {
                provider: "p".to_string(),
                model: "config".to_string(),
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            }),
        };
        let mut dialog = dialog_with(vec![entry("a"), entry("b")]);
        dialog.set_config_drift(Some(drift.clone()));
        assert!(!dialog.handle_key(press(KeyCode::Down)));

        dialog.set_config_drift(Some(drift));
        assert!(dialog.handle_key(press(KeyCode::Enter)));
        let active = dialog
            .selected_active_model()
            .expect("selected active model");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "a");
    }

    #[test]
    fn picker_annotates_last_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(
            &config_path,
            r#"{"providers":{"p":{"url":"https://example.test","models":[{"id":"claude"}]}}}"#,
        )
        .unwrap();
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            provider_path,
            r#"{"url":"https://example.test","models":[{"id":"claude"}]}"#,
        )
        .unwrap();
        let failures = [(
            ("p".to_string(), "claude".to_string()),
            crate::tui::auth_failure::AuthFailureRecord {
                kind: cockpit_proto::AuthFailureKind::CredentialsRejected { status: 403 },
                failed_at_epoch_secs: 10_000,
            },
        )]
        .into_iter()
        .collect();
        let mut dialog = ModelPickerDialog::open_with_failures(
            providers_at(tmp.path()),
            None,
            &HashMap::new(),
            &failures,
            17_200,
        )
        .unwrap();

        let rendered = rendered_text(&mut dialog, 80, 12);

        assert!(
            rendered.contains("p/claude  [untrusted]  failed 403 · 2h ago"),
            "{rendered}"
        );
    }

    #[test]
    fn pick_filter_caret_handles_wide_unicode_cursor() {
        let mut d = dialog_with(vec![entry("alpha")]);
        d.filter.set("中a");
        d.filter.handle_key(press(KeyCode::Home));
        d.filter.handle_key(press(KeyCode::Right));

        let rendered = rendered_text(&mut d, 60, 12);

        assert!(rendered.contains("filter: 中 a"), "{rendered}");
    }

    #[test]
    fn short_picker_keeps_highlighted_last_row_visible() {
        let mut entries = vec![favorite_entry("fav")];
        entries.extend((0..13).map(|i| entry(&format!("m{i:02}"))));
        let mut d = dialog_with(entries);
        d.pick.set_cursor(d.filtered_indices().len() - 1);

        let rendered = rendered_text(&mut d, 80, 10);

        assert!(
            rendered.contains("> p/m12"),
            "highlighted row should be visible:\n{rendered}"
        );
    }

    #[test]
    fn short_picker_with_error_keeps_highlighted_row_visible() {
        let mut entries = vec![favorite_entry("fav")];
        entries.extend((0..13).map(|i| entry(&format!("m{i:02}"))));
        let mut d = dialog_with(entries);
        d.pick.set_cursor(d.filtered_indices().len() - 1);
        d.error = Some("save failed: test".to_string());

        let rendered = rendered_text(&mut d, 80, 10);

        assert!(
            rendered.contains("> p/m12"),
            "highlighted row should win over error chrome:\n{rendered}"
        );
    }

    /// The pick step (arrow-only nav; `j`/`k` are filter text) wraps at
    /// both ends like every other selectable list.
    #[test]
    fn pick_step_arrows_wrap() {
        let mut d = dialog_with(vec![entry("a"), entry("b"), entry("c")]);
        assert_eq!(d.pick.cursor(), 0);
        // Up from the first item wraps to the last.
        d.handle_key(press(KeyCode::Up));
        assert_eq!(d.pick.cursor(), 2);
        // Down from the last item wraps to the first.
        d.handle_key(press(KeyCode::Down));
        assert_eq!(d.pick.cursor(), 0);
    }

    #[test]
    fn model_identity_survives_filter_and_reorder() {
        let mut d = dialog_with_active(vec![entry("alpha"), entry("beta")], "p", "beta");
        d.filter.set("alpha");
        d.retarget_pick_position();
        assert_eq!(d.pick.cursor(), 0);

        d.entries.reverse();
        d.filter.set("");
        d.retarget_pick_position();

        let visible = d.filtered_indices();
        assert_eq!(d.entries[visible[d.pick.cursor()]].model_id, "beta");
    }

    #[test]
    fn list_backend_matrix_keeps_unicode_selection_and_hits_aligned() {
        for (width, height) in [(24, 8), (60, 12), (120, 20)] {
            let mut unicode = entry("模型-e\u{301}");
            unicode.display_name = Some("wide 中 combining e\u{301}".to_string());
            let mut dialog = dialog_with(vec![unicode, entry("second")]);
            dialog.error = (width == 24).then(|| "loading failed".to_string());
            let rendered = rendered_text(&mut dialog, width, height);
            assert!(rendered.contains("模型"), "{width}x{height}: {rendered}");
            assert!(dialog.row_hits.iter().any(Option::is_some));
        }

        let mut empty = empty_dialog();
        assert!(rendered_text(&mut empty, 24, 8).contains("no models"));
    }

    #[test]
    fn selection_closes_without_writing_config() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{not json").unwrap();
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![entry("a")]);

        assert!(d.handle_key(press(KeyCode::Enter)));

        assert!(d.is_done());
        let active = d.selected_active_model().expect("selected active model");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "a");
        assert_eq!(d.error, None);
        assert!(ConfigDoc::load(&config_path).is_err());
    }

    #[test]
    fn model_picker_session_only_does_not_write_config() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(
            &config_path,
            r#"{"providers":{"p":{"url":"https://example.test","models":[{"id":"claude"}]}}}"#,
        )
        .unwrap();
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            provider_path,
            r#"{"url":"https://example.test","models":[{"id":"a"}]}"#,
        )
        .unwrap();
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![entry("a")]);

        assert!(d.handle_key(press(KeyCode::Enter)));

        assert!(d.is_done());
        assert_eq!(d.error, None);
        let active = d.selected_active_model().expect("selected active model");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "a");
        let saved = ConfigDoc::load(&config_path).unwrap().providers();
        assert_eq!(saved.active_model, None);
    }

    #[test]
    fn model_picker_ctrl_enter_marks_selection_for_default_write() {
        let mut dialog = dialog_with(vec![entry("a")]);
        assert!(dialog.handle_key(ctrl_press(KeyCode::Enter)));
        assert!(dialog.persists_as_default());
    }

    #[test]
    fn model_picker_help_mentions_session_and_default() {
        let mut dialog = dialog_with(vec![entry("a")]);
        let backend = TestBackend::new(160, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal
            .draw(|frame| dialog.render(frame, frame.area()))
            .unwrap();
        let text = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(text.contains("session"));
        assert!(text.contains("default"));
    }

    #[test]
    fn scoped_picker_ctrl_a_adds_model_while_plain_a_filters() {
        let mut picker = dialog_with(vec![entry("existing")]);
        picker.scope_provider = Some("p".to_string());

        assert!(picker.handle_key(ctrl_press(KeyCode::Char('a'))));
        assert_eq!(picker.take_add_model_provider(), Some("p".to_string()));

        let mut typing = dialog_with(Vec::new());
        typing.scope_provider = Some("p".to_string());
        assert!(!typing.handle_key(press(KeyCode::Char('a'))));
        assert_eq!(typing.filter.text(), "a");
        assert_eq!(typing.take_add_model_provider(), None);
    }

    fn seed_active_model(config_path: &std::path::Path, provider: &str, model: &str) {
        let mut raw: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(config_path).unwrap()).unwrap();
        raw["active_model"] = serde_json::json!({ "provider": provider, "model": model });
        fs::write(
            config_path,
            format!("{}\n", serde_json::to_string_pretty(&raw).unwrap()),
        )
        .unwrap();
    }

    #[test]
    fn cycle_active_favorite_skips_nonfavorites_and_wraps() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        let _home = cockpit_test_support::TestEnvGuard::isolate_cockpit_home_at(tmp.path());
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, r#"{"providers":{"p":{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"},{"id":"c","favorite":true}]}}}"#).unwrap();
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            &provider_path,
            r#"{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"},{"id":"c","favorite":true}]}"#,
        )
        .unwrap();
        // `active_model` is only ever written by the authoritative
        // effective-default operation; this fixture seeds the layer directly.
        seed_active_model(&config_path, "p", "a");

        let mut cfg = providers_at(tmp.path());
        cfg.active_model = Some(ActiveModelRef {
            provider: "p".into(),
            model: "a".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        });
        let next = cycle_active_favorite(&cfg, cfg.active_model.as_ref(), &HashMap::new(), true)
            .unwrap()
            .expect("next favorite");
        assert_eq!(next.provider, "p");
        assert_eq!(next.model, "c");
        seed_active_model(&config_path, &next.provider, &next.model);

        cfg.active_model = Some(next.clone());
        let prev = cycle_active_favorite(&cfg, cfg.active_model.as_ref(), &HashMap::new(), false)
            .unwrap()
            .expect("previous favorite");
        assert_eq!(prev.provider, "p");
        assert_eq!(prev.model, "a");
    }

    #[test]
    fn cycle_active_favorite_selects_sole_favorite_when_active_model_differs() {
        let mut cfg = cockpit_config::providers::ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            cockpit_config::providers::ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "active".into(),
                        ..Default::default()
                    },
                    ModelEntry {
                        id: "favorite".into(),
                        favorite: true,
                        ..Default::default()
                    },
                ],
                ..Default::default()
            },
        );
        let active = ActiveModelRef {
            provider: "p".into(),
            model: "active".into(),
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        };

        let next = cycle_active_favorite(&cfg, Some(&active), &HashMap::new(), true)
            .unwrap()
            .expect("the different sole favorite is a valid target");
        assert_eq!(next.provider, "p");
        assert_eq!(next.model, "favorite");
    }

    #[test]
    fn cycle_active_favorite_filters_responses_only_effort_on_completions_pin() {
        let responses_only_effort = ReasoningEffortCapability {
            values: vec![CapabilityValue {
                value: "ultra".into(),
                label: None,
                description: None,
            }],
            default: Some("ultra".into()),
            request_mapping: None,
            endpoint_request_mappings: vec![EndpointReasoningEffortRequestMapping {
                wire_api: WireApi::Responses,
                request_mapping: ReasoningEffortRequestMapping::JsonPath {
                    path: vec!["reasoning".into(), "effort".into()],
                    values: BTreeMap::from([("ultra".into(), serde_json::json!("ultra"))]),
                },
            }],
            source: Some(cockpit_config::providers::CapabilitySource::Live),
        };
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![
                    ModelEntry {
                        id: "active".into(),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "favorite".into(),
                        favorite: true,
                        wire_api: WireApi::Completions,
                        capabilities: ModelCapabilities {
                            reasoning_effort: Some(responses_only_effort),
                            ..ModelCapabilities::default()
                        },
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        let active = ActiveModelRef {
            provider: "p".into(),
            model: "active".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "ultra".into(),
            }),
            thinking_mode: None,
            prompt_cache_retention: None,
        };

        let next = cycle_active_favorite(&cfg, Some(&active), &HashMap::new(), true)
            .unwrap()
            .expect("favorite target");
        assert_eq!(next.model, "favorite");
        assert_eq!(
            next.reasoning_effort, None,
            "Responses-only effort must not survive onto a Completions-pinned favorite"
        );
    }

    /// The think step is a non-typing list: `j`/`k` (and arrows) navigate
    /// and wrap.
    #[test]
    fn think_step_jk_wraps() {
        let mut d = dialog_with(vec![entry("a")]);
        d.step = Step::ChooseThinking {
            provider_id: "p".into(),
            model_id: "a".into(),
            modes: vec![ThinkingMode::Off, ThinkingMode::Low, ThinkingMode::High],
            cursor: 0,
        };
        // `k` (Up) from the first wraps to the last.
        d.handle_key(press(KeyCode::Char('k')));
        match &d.step {
            Step::ChooseThinking { cursor, .. } => assert_eq!(*cursor, 2),
            _ => panic!("left the think step"),
        }
        // `j` (Down) from the last wraps to the first.
        d.handle_key(press(KeyCode::Char('j')));
        match &d.step {
            Step::ChooseThinking { cursor, .. } => assert_eq!(*cursor, 0),
            _ => panic!("left the think step"),
        }
        let rendered = rendered_text(&mut d, 100, 20);
        assert!(
            rendered.contains("Provider thinking mode: (request parameter)"),
            "rendered:\n{rendered}"
        );
    }

    #[test]
    fn rich_reasoning_model_opens_reasoning_step_without_legacy_modes() {
        let mut d = dialog_with(vec![reasoning_entry("codex")]);

        assert!(!d.handle_key(press(KeyCode::Enter)));

        match &d.step {
            Step::ChooseReasoning {
                provider_id,
                model_id,
                cursor,
                ..
            } => {
                assert_eq!(provider_id, "p");
                assert_eq!(model_id, "codex");
                assert_eq!(*cursor, 1, "provider default should be selected");
            }
            _ => panic!("expected reasoning step"),
        }
        let rendered = rendered_text(&mut d, 100, 20);
        assert!(
            rendered.contains("Reasoning effort: (provider request parameter)"),
            "rendered:\n{rendered}"
        );
        assert!(rendered.contains("minimal"), "rendered:\n{rendered}");
        assert!(rendered.contains("xhigh"), "rendered:\n{rendered}");
        assert!(rendered.contains("Extra high"), "rendered:\n{rendered}");
        assert!(
            rendered.contains("deepest reasoning"),
            "rendered:\n{rendered}"
        );
    }

    #[test]
    fn model_picker_commit_preserves_reasoning_and_thinking() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(
            &config_path,
            r#"{"providers":{"p":{"url":"https://example.test","models":[{"id":"claude"}]}}}"#,
        )
        .unwrap();
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            provider_path,
            r#"{"url":"https://example.test","models":[{"id":"codex"}]}"#,
        )
        .unwrap();
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![reasoning_entry("codex")]);

        assert!(!d.handle_key(press(KeyCode::Enter)));
        assert!(d.handle_key(press(KeyCode::Enter)));

        let active = d.selected_active_model().expect("selected active model");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "codex");
        assert_eq!(
            active.reasoning_effort.expect("reasoning effort").value,
            "xhigh"
        );
        assert_eq!(active.thinking_mode, None);

        let mut legacy = entry("legacy");
        legacy.thinking_modes = vec![ThinkingMode::Off, ThinkingMode::Low, ThinkingMode::High];
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![legacy]);

        assert!(!d.handle_key(press(KeyCode::Enter)));
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Down));
        assert!(d.handle_key(press(KeyCode::Enter)));

        let active = d.selected_active_model().expect("selected active model");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "legacy");
        assert_eq!(active.reasoning_effort, None);
        assert_eq!(active.thinking_mode, Some(ThinkingMode::High));
    }

    #[test]
    fn rejected_selection_retry_preserves_supported_preferences() {
        let mut reasoning = reasoning_entry("codex");
        let mut cfg = ProvidersConfig::default();
        cfg.providers.insert(
            "p".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "codex".into(),
                    capabilities: ModelCapabilities {
                        reasoning_effort: reasoning.reasoning_effort.clone(),
                        prompt_cache_retention: CapabilityStatus::Supported,
                        ..ModelCapabilities::default()
                    },
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        reasoning.thinking_modes.clear();
        let mut dialog = dialog_with(vec![reasoning]);
        dialog.cfg = cfg;
        let requested = ActiveModelRef {
            provider: "p".into(),
            model: "codex".into(),
            reasoning_effort: Some(ActiveReasoningEffort {
                value: "minimal".into(),
            }),
            thinking_mode: None,
            prompt_cache_retention: Some(PromptCacheRetention::Extended),
        };

        dialog.restore_requested_selection(&requested);
        assert_eq!(dialog.draft_active_model(), Some(&requested));
        assert!(!dialog.handle_key(press(KeyCode::Enter)));
        match &dialog.step {
            Step::ChooseReasoning { cursor, .. } => assert_eq!(*cursor, 0),
            _ => panic!("expected reasoning step"),
        }
        assert!(dialog.handle_key(press(KeyCode::Enter)));
        assert_eq!(dialog.selected_active_model(), Some(requested));

        let mut legacy = entry("legacy");
        legacy.thinking_modes = vec![ThinkingMode::Off, ThinkingMode::Low, ThinkingMode::High];
        let mut dialog = dialog_with(vec![legacy]);
        let requested = ActiveModelRef {
            provider: "p".into(),
            model: "legacy".into(),
            reasoning_effort: None,
            thinking_mode: Some(ThinkingMode::High),
            prompt_cache_retention: None,
        };
        dialog.restore_requested_selection(&requested);
        assert!(!dialog.handle_key(press(KeyCode::Enter)));
        match &dialog.step {
            Step::ChooseThinking { cursor, .. } => assert_eq!(*cursor, 2),
            _ => panic!("expected thinking step"),
        }
        assert!(dialog.handle_key(press(KeyCode::Enter)));
        assert_eq!(dialog.selected_active_model(), Some(requested));
    }

    #[test]
    fn fallback_reasoning_capability_without_values_does_not_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(
            &config_path,
            r#"{"providers":{"p":{"url":"https://example.test","models":[{"id":"claude"}]}}}"#,
        )
        .unwrap();
        let provider_path =
            cockpit_config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            provider_path,
            r#"{"url":"https://example.test","models":[{"id":"fallback"}]}"#,
        )
        .unwrap();
        let mut fallback = entry("fallback");
        fallback.reasoning_effort = Some(ReasoningEffortCapability {
            source: Some(cockpit_config::providers::CapabilitySource::Fallback),
            ..ReasoningEffortCapability::default()
        });
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![fallback]);

        assert!(d.handle_key(press(KeyCode::Enter)));
        assert!(d.is_done());
        match d.step {
            Step::Pick => {}
            _ => panic!("fallback model should not open a reasoning step"),
        }
        let active = d.selected_active_model().expect("selected active model");
        assert_eq!(active.reasoning_effort, None);
        assert_eq!(active.thinking_mode, None);
    }

    fn dialog_with_active(entries: Vec<Entry>, provider: &str, model: &str) -> ModelPickerDialog {
        let active_model = Some((provider.to_string(), model.to_string()));
        let (cursor, scroll) =
            initial_pick_position(&entries, active_model.as_ref(), "", MODEL_WINDOW);
        ModelPickerDialog {
            cfg: ProvidersConfig::default(),
            entries,
            active_model: active_model.clone(),
            slot_models: Vec::new(),
            slot_default: None,
            scope_provider: None,
            add_model_provider: None,
            drift: None,
            filter: TextField::default(),
            pick: list_state(cursor, scroll),
            selected_model: active_model.clone(),
            step: Step::Pick,
            error: None,
            done: false,
            persist_as_default: false,
            row_hits: Vec::new(),
        }
    }

    #[test]
    fn open_targets_active_model_when_present() {
        let d = dialog_with_active(
            vec![entry("first"), entry("active"), entry("last")],
            "p",
            "active",
        );
        assert_eq!(d.pick.cursor(), 1);
        assert_eq!(d.pick.scroll(), 0);
    }

    #[test]
    fn open_targets_active_model_when_not_first() {
        let mut entries = (0..14)
            .map(|i| entry(&format!("m{i:02}")))
            .collect::<Vec<_>>();
        entries.push(entry("active"));
        let d = dialog_with_active(entries, "p", "active");
        assert_eq!(d.pick.cursor(), 14);
        assert!(
            d.pick.scroll() > 0,
            "active row should be scrolled into view"
        );
    }

    #[test]
    fn filter_targets_active_model_when_visible() {
        let mut d = dialog_with_active(
            vec![entry("alpha"), entry("active"), entry("beta-active")],
            "p",
            "active",
        );
        d.handle_key(press(KeyCode::Char('a')));
        d.handle_key(press(KeyCode::Char('c')));
        d.handle_key(press(KeyCode::Char('t')));
        assert_eq!(d.filter.text(), "act");
        assert_eq!(d.pick.cursor(), 0);
        let visible = d.filtered_indices();
        assert_eq!(d.entries[visible[d.pick.cursor()]].model_id, "active");
    }

    #[test]
    fn active_missing_falls_back_to_first_visible_row() {
        let d = dialog_with_active(vec![entry("first"), entry("second")], "p", "missing");
        assert_eq!(d.pick.cursor(), 0);
        assert_eq!(d.pick.scroll(), 0);
    }

    #[test]
    fn active_marker_renders_independent_of_highlight() {
        let mut d = dialog_with_active(vec![entry("first"), entry("active")], "p", "active");
        d.handle_key(press(KeyCode::Up));
        assert_eq!(d.pick.cursor(), 0);

        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| d.render(frame, Rect::new(0, 0, 80, 20)))
            .expect("draw");
        let rendered = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(rendered.contains("> p/first"));
        assert!(rendered.contains("p/active  [untrusted]  [active]"));
    }

    #[test]
    fn active_slot_pairs_sort_first_in_declared_order_and_render_default() {
        let mut d = dialog_with(vec![entry("other"), entry("second"), entry("first")]);
        d.set_active_slot_models(
            vec![
                ("p".to_string(), "first".to_string()),
                ("p".to_string(), "second".to_string()),
            ],
            Some(("p".to_string(), "second".to_string())),
            &HashMap::new(),
        );
        assert_eq!(
            d.entries
                .iter()
                .map(|entry| entry.model_id.as_str())
                .collect::<Vec<_>>(),
            vec!["first", "second", "other"]
        );

        let rendered = rendered_text(&mut d, 80, 20);
        assert!(rendered.contains("p/second  [untrusted]  [default]"));
        assert!(!rendered.contains("p/first  [untrusted]  [default]"));
    }

    #[test]
    fn default_outside_daemon_allowed_slot_is_not_rendered() {
        let mut d = dialog_with(vec![entry("allowed"), entry("forged")]);
        d.set_active_slot_models(
            vec![("p".to_string(), "allowed".to_string())],
            Some(("p".to_string(), "forged".to_string())),
            &HashMap::new(),
        );
        assert!(!rendered_text(&mut d, 80, 20).contains("[default]"));
    }

    #[test]
    fn mouse_row_selects_rendered_pick_item() {
        let mut second = entry("second");
        second.thinking_modes = vec![ThinkingMode::Low];
        let mut d = dialog_with(vec![entry("first"), second]);
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| d.render(frame, Rect::new(0, 0, 80, 20)))
            .expect("draw");

        assert!(!d.handle_mouse_row(5));
        assert!(matches!(d.step, Step::ChooseThinking { model_id, .. } if model_id == "second"));
    }
}
