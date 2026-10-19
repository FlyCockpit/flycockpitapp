//! Searchable first-run model picker and optional model policy editor.

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Padding, Paragraph, Wrap};

use super::ui::{self, ListNav, STAR};
use crate::tui::textfield::TextField;
use crate::tui::theme::{BAD, BRASS, FOG, INK, NIGHT};
use cockpit_config::config::providers::{CapabilityStatus, ModelTrust, ProvidersConfig};

const CAPABILITIES: [(&str, &str, &str); 4] = [
    ("images", "image input", "Supports image input parts"),
    ("tools", "tool calling", "Supports tool/function calling"),
    (
        "reasoning",
        "reasoning",
        "Supports reasoning and thinking controls",
    ),
    (
        "structured_outputs",
        "structured outputs",
        "Supports JSON-schema structured outputs",
    ),
];
const THINKING: [(&str, &str); 5] = [
    ("inherit", "No model-level default"),
    ("off", "Disable legacy thinking mode"),
    ("low", "Low thinking mode"),
    ("medium", "Medium thinking mode"),
    ("high", "High thinking mode"),
];
const DELEGATION: [(&str, &str, &str); 2] = [
    (
        "subagent_invokable",
        "spawn as subagent",
        "This model may be selected for subagents",
    ),
    (
        "can_delegate",
        "can spawn subagents",
        "This model receives delegation affordances",
    ),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelPhase {
    DefaultModel,
    Trust,
    Capabilities,
    Limits,
    Thinking,
    Delegation,
}

impl ModelPhase {
    pub(crate) const ALL: [Self; 6] = [
        Self::DefaultModel,
        Self::Trust,
        Self::Capabilities,
        Self::Limits,
        Self::Thinking,
        Self::Delegation,
    ];

    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|phase| *phase == self)
            .unwrap_or(0)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PickerFocus {
    Search,
    List,
    Provider,
    Manual,
}

pub(crate) struct ModelScreen {
    phase: ModelPhase,
    short_path: bool,
    search: TextField,
    focus: PickerFocus,
    filtered: Vec<usize>,
    refresh_requested: bool,
    refreshing: bool,
    rejected_providers: std::collections::BTreeSet<String>,
    config: ProvidersConfig,
    catalog: Vec<(String, String)>,
    selected_model: usize,
    provider_id: String,
    model_id: TextField,
    trust: usize,
    capabilities: [bool; 4],
    context_tokens: TextField,
    max_output_tokens: TextField,
    thinking: usize,
    delegation: [bool; 2],
    nav: ListNav,
    row_rects: Vec<Rect>,
    field_rects: Vec<Rect>,
    error: Option<String>,
}

impl ModelScreen {
    pub(crate) fn new(config: &ProvidersConfig, preselect: Option<(&str, &str)>) -> Self {
        let catalog = config
            .providers
            .iter()
            .flat_map(|(provider, entry)| {
                entry
                    .models
                    .iter()
                    .map(move |model| (provider.clone(), model.id.clone()))
            })
            .collect::<Vec<_>>();
        let selected_model = preselect
            .and_then(|pair| {
                catalog
                    .iter()
                    .position(|item| (item.0.as_str(), item.1.as_str()) == pair)
            })
            .unwrap_or(0);
        let (provider_id, model_id) = catalog
            .get(selected_model)
            .cloned()
            .or_else(|| {
                preselect.map(|(provider, model)| (provider.to_string(), model.to_string()))
            })
            .or_else(|| {
                config
                    .providers
                    .keys()
                    .next()
                    .map(|provider| (provider.clone(), String::new()))
            })
            .unwrap_or_default();
        let mut screen = Self {
            phase: ModelPhase::DefaultModel,
            short_path: false,
            search: TextField::new(String::new()),
            focus: PickerFocus::Search,
            filtered: (0..catalog.len()).collect(),
            refresh_requested: false,
            refreshing: false,
            rejected_providers: std::collections::BTreeSet::new(),
            config: config.clone(),
            catalog,
            selected_model,
            provider_id,
            model_id: TextField::new(model_id),
            trust: 0,
            capabilities: [false; 4],
            context_tokens: TextField::new(String::new()),
            max_output_tokens: TextField::new(String::new()),
            thinking: 0,
            delegation: [false, true],
            nav: ListNav::new(),
            row_rects: Vec::new(),
            field_rects: Vec::new(),
            error: None,
        };
        screen.seed_policy();
        screen.reset_nav_for_phase();
        screen
    }

    pub(crate) fn short(config: &ProvidersConfig, preselect: Option<(&str, &str)>) -> Self {
        let mut screen = Self::new(config, preselect);
        screen.short_path = true;
        screen.refilter();
        screen
    }

    fn refilter(&mut self) {
        let query = self.search.text().to_lowercase();
        self.filtered = self
            .catalog
            .iter()
            .enumerate()
            .filter_map(|(index, (provider, model))| {
                (provider == &self.provider_id
                    && format!("{provider}/{model}")
                        .to_lowercase()
                        .contains(&query))
                .then_some(index)
            })
            .collect();
        self.nav.cursor = self
            .filtered
            .iter()
            .position(|index| *index == self.selected_model)
            .unwrap_or(0);
        self.nav.offset = 0;
        self.nav.ensure_visible(self.filtered.len());
    }

    fn catalog_index(&self) -> Option<usize> {
        if self.short_path {
            self.filtered.get(self.nav.cursor).copied()
        } else {
            (self.nav.cursor < self.catalog.len()).then_some(self.nav.cursor)
        }
    }

    fn cycle_provider(&mut self, delta: isize) {
        let providers = self.config.providers.keys().cloned().collect::<Vec<_>>();
        if providers.is_empty() {
            return;
        }
        let current = providers
            .iter()
            .position(|id| id == &self.provider_id)
            .unwrap_or(0);
        self.provider_id = providers
            [(current as isize + delta).rem_euclid(providers.len() as isize) as usize]
            .clone();
        self.model_id = TextField::new(String::new());
        self.refreshing = false;
        self.error = None;
        self.search = TextField::new(String::new());
        self.refilter();
        if let Some(index) = self.filtered.first().copied() {
            self.select_catalog_model(index);
        }
    }

    pub(crate) fn take_refresh(&mut self) -> Option<String> {
        if std::mem::take(&mut self.refresh_requested) {
            Some(self.provider_id.clone())
        } else {
            None
        }
    }

    pub(crate) fn apply_refresh(
        &mut self,
        provider: &str,
        outcome: super::VerifyOutcome,
        config: &ProvidersConfig,
    ) {
        if self.provider_id != provider {
            return;
        }
        self.refreshing = false;
        match outcome {
            super::VerifyOutcome::Models(_) | super::VerifyOutcome::NoEndpoint => {
                let selection = self.model_id.text().to_string();
                let mut rejected = std::mem::take(&mut self.rejected_providers);
                rejected.remove(provider);
                *self = Self::short(config, Some((provider, &selection)));
                self.rejected_providers = rejected;
            }
            error => {
                if matches!(error, super::VerifyOutcome::Unauthorized(_)) {
                    self.rejected_providers.insert(provider.to_string());
                }
                self.error = Some(match error {
                    super::VerifyOutcome::Unauthorized(status) => format!(
                        "Credential rejected ({status}). Go Back to Provider to update the key, then refresh."
                    ),
                    other => format!(
                        "Refresh failed: {other:?}. Ctrl+R retries; Back returns to Provider."
                    ),
                });
            }
        }
    }

    fn seed_policy(&mut self) {
        if self.provider_id.is_empty() || self.model_id.text().is_empty() {
            return;
        }
        let provider = self.provider_id.as_str();
        let model = self.model_id.text();
        self.trust = usize::from(self.config.resolve_trust(provider, model) == ModelTrust::Trusted);
        let caps = self.config.resolve_effective_model_capabilities(
            provider,
            model,
            self.config.resolution_generation,
        );
        self.capabilities = [
            caps.supports_image_input(),
            matches!(caps.tool_calling, CapabilityStatus::Supported),
            matches!(caps.reasoning, CapabilityStatus::Supported),
            matches!(caps.structured_outputs, CapabilityStatus::Supported),
        ];
        self.context_tokens = TextField::new(
            caps.context_tokens
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        self.max_output_tokens = TextField::new(
            caps.max_output_tokens
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        self.thinking = match self.config.resolve_default_thinking_mode(provider, model) {
            None => 0,
            Some(cockpit_config::config::providers::ThinkingMode::Off) => 1,
            Some(cockpit_config::config::providers::ThinkingMode::Low) => 2,
            Some(cockpit_config::config::providers::ThinkingMode::Medium) => 3,
            Some(cockpit_config::config::providers::ThinkingMode::High) => 4,
        };
        self.delegation = [
            self.config.resolve_subagent_invokable(provider, model),
            self.config.resolve_can_delegate(provider, model),
        ];
    }

    fn reset_nav_for_phase(&mut self) {
        self.nav = ListNav::new();
        self.nav.cursor = match self.phase {
            ModelPhase::DefaultModel => self.selected_model,
            ModelPhase::Trust => self.trust,
            ModelPhase::Thinking => self.thinking,
            ModelPhase::Capabilities | ModelPhase::Limits | ModelPhase::Delegation => 0,
        };
    }

    fn select_catalog_model(&mut self, index: usize) {
        let Some((provider, model)) = self.catalog.get(index).cloned() else {
            return;
        };
        self.selected_model = index;
        if self.provider_id == provider && self.model_id.text() == model {
            return;
        }
        self.provider_id = provider;
        self.model_id = TextField::new(model);
        self.seed_policy();
    }

    #[cfg(test)]
    pub(crate) fn refreshing(&self) -> bool {
        self.refreshing
    }

    #[cfg(test)]
    pub(crate) fn phase(&self) -> ModelPhase {
        self.phase
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn set_phase_for_golden(&mut self, phase: ModelPhase) {
        self.phase = phase;
        self.reset_nav_for_phase();
    }

    pub(crate) fn title(&self) -> &'static str {
        match self.phase {
            ModelPhase::DefaultModel => "Choose your default model",
            ModelPhase::Trust => "Provider trust",
            ModelPhase::Capabilities => "Model capabilities",
            ModelPhase::Limits => "Model limits",
            ModelPhase::Thinking => "Default thinking",
            ModelPhase::Delegation => "Delegation",
        }
    }

    pub(crate) fn subtitle(&self) -> &'static str {
        match self.phase {
            ModelPhase::DefaultModel => {
                "Choose one model. Advanced options are available later in /settings or /setup."
            }
            ModelPhase::Trust => "Choose the model's data-custody policy.",
            ModelPhase::Capabilities => "Grant only capabilities this model supports.",
            ModelPhase::Limits => "Keep detected token limits or enter an override.",
            ModelPhase::Thinking => "Choose the model-level thinking default.",
            ModelPhase::Delegation => "Choose how this model participates in delegation.",
        }
    }

    pub(crate) fn help_text(&self) -> &'static str {
        if self.short_path {
            return "tab focus   ↑↓ / home/end/page move   ctrl+r refresh   enter choose";
        }
        match self.phase {
            ModelPhase::DefaultModel if self.catalog.is_empty() => {
                "type model id   enter continue   esc options"
            }
            ModelPhase::DefaultModel => {
                "↑↓ move   space set default   enter continue   esc options"
            }
            ModelPhase::Limits => "tab switch field   type value   enter continue   esc back",
            ModelPhase::Capabilities | ModelPhase::Delegation => {
                "↑↓ move   space toggle   enter continue   esc back"
            }
            _ => "↑↓ move   space choose   enter continue   esc back",
        }
    }

    pub(crate) fn back(&mut self) -> bool {
        let index = self.phase.index();
        if index == 0 {
            return false;
        }
        self.phase = ModelPhase::ALL[index - 1];
        self.reset_nav_for_phase();
        self.error = None;
        true
    }

    pub(crate) fn advance(&mut self) -> Option<cockpit_core::wizard::OnboardingModelSubmission> {
        if self.short_path
            && (self.refreshing || self.rejected_providers.contains(&self.provider_id))
        {
            return None;
        }
        match self.phase {
            ModelPhase::DefaultModel
                if !self.catalog.is_empty()
                    && (!self.short_path
                        || self.catalog.iter().any(|(p, _)| p == &self.provider_id)) =>
            {
                if let Some(index) = self.catalog_index() {
                    self.select_catalog_model(index);
                } else {
                    self.error = Some(
                        "No matching models. Change the search or refresh the catalog.".into(),
                    );
                    return None;
                }
            }
            ModelPhase::Trust => self.trust = self.nav.cursor.min(1),
            ModelPhase::Thinking => self.thinking = self.nav.cursor.min(THINKING.len() - 1),
            _ => {}
        }
        if self.phase == ModelPhase::DefaultModel
            && (self.provider_id.trim().is_empty() || self.model_id.text().trim().is_empty())
        {
            self.error = Some("Choose a provider and enter a model ID.".to_string());
            return None;
        }
        if self.phase == ModelPhase::Limits
            && [self.context_tokens.text(), self.max_output_tokens.text()]
                .into_iter()
                .any(|value| {
                    !value.trim().is_empty() && !value.trim().parse::<u32>().is_ok_and(|v| v > 0)
                })
        {
            self.error = Some("Token limits must be positive numbers or blank.".to_string());
            return None;
        }
        if self.short_path
            && self
                .catalog
                .iter()
                .all(|(provider, _)| provider != &self.provider_id)
        {
            self.seed_policy();
        }
        self.error = None;
        let index = self.phase.index();
        if !self.short_path && index + 1 < ModelPhase::ALL.len() {
            self.phase = ModelPhase::ALL[index + 1];
            self.reset_nav_for_phase();
            return None;
        }
        Some(cockpit_core::wizard::OnboardingModelSubmission {
            provider_id: self.provider_id.clone(),
            model_id: self.model_id.text().trim().to_string(),
            trust: if self.trust == 0 {
                "untrusted"
            } else {
                "trusted"
            }
            .to_string(),
            capabilities: CAPABILITIES
                .iter()
                .zip(self.capabilities)
                .filter(|(_, enabled)| *enabled)
                .map(|((id, _, _), _)| (*id).to_string())
                .collect(),
            context_tokens: self.context_tokens.text().trim().to_string(),
            max_output_tokens: self.max_output_tokens.text().trim().to_string(),
            thinking: THINKING[self.thinking].0.to_string(),
            subagent_flags: DELEGATION
                .iter()
                .zip(self.delegation)
                .filter(|(_, enabled)| *enabled)
                .map(|((id, _, _), _)| (*id).to_string())
                .collect(),
        })
    }

    fn row_count(&self) -> usize {
        match self.phase {
            ModelPhase::DefaultModel if self.short_path => self.filtered.len(),
            ModelPhase::DefaultModel => self.catalog.len(),
            ModelPhase::Trust => 2,
            ModelPhase::Capabilities => CAPABILITIES.len(),
            ModelPhase::Limits => 2,
            ModelPhase::Thinking => THINKING.len(),
            ModelPhase::Delegation => DELEGATION.len(),
        }
    }

    fn activate_row(&mut self) {
        match self.phase {
            ModelPhase::DefaultModel if !self.catalog.is_empty() => {
                if let Some(index) = self.catalog_index() {
                    self.select_catalog_model(index);
                }
            }
            ModelPhase::Trust => self.trust = self.nav.cursor.min(1),
            ModelPhase::Capabilities => {
                self.capabilities[self.nav.cursor.min(CAPABILITIES.len() - 1)] ^= true;
            }
            ModelPhase::Limits => {}
            ModelPhase::Thinking => self.thinking = self.nav.cursor.min(THINKING.len() - 1),
            ModelPhase::Delegation => {
                self.delegation[self.nav.cursor.min(DELEGATION.len() - 1)] ^= true;
            }
            ModelPhase::DefaultModel => {}
        }
        self.error = None;
    }

    pub(crate) fn handle_key(&mut self, key: KeyEvent) {
        if self.short_path && self.phase == ModelPhase::DefaultModel {
            if key
                .modifiers
                .contains(crossterm::event::KeyModifiers::CONTROL)
                && key.code == KeyCode::Char('r')
            {
                if !self.provider_id.is_empty() && !self.refreshing {
                    self.refresh_requested = true;
                    self.refreshing = true;
                    self.error = None;
                }
                return;
            }
            match key.code {
                KeyCode::Tab | KeyCode::BackTab => {
                    let order = [
                        PickerFocus::Search,
                        PickerFocus::List,
                        PickerFocus::Provider,
                        PickerFocus::Manual,
                    ];
                    let count = if self.filtered.is_empty()
                        && self.catalog.iter().all(|(p, _)| p != &self.provider_id)
                    {
                        4
                    } else {
                        3
                    };
                    let index = order
                        .iter()
                        .position(|focus| *focus == self.focus)
                        .unwrap_or(0);
                    let delta = if key.code == KeyCode::Tab { 1 } else { -1 };
                    self.focus = order[(index as isize + delta).rem_euclid(count) as usize];
                }
                KeyCode::Left | KeyCode::Up if self.focus == PickerFocus::Provider => {
                    self.cycle_provider(-1)
                }
                KeyCode::Right | KeyCode::Down if self.focus == PickerFocus::Provider => {
                    self.cycle_provider(1)
                }
                _ if self.focus == PickerFocus::Search
                    && !matches!(
                        key.code,
                        KeyCode::Down | KeyCode::Up | KeyCode::PageDown | KeyCode::PageUp
                    ) =>
                {
                    self.search.handle_key(key);
                    self.refilter();
                }
                _ if self.focus == PickerFocus::Manual => {
                    self.model_id.handle_key(key);
                }
                KeyCode::Char('j' | 'k') if self.focus == PickerFocus::Provider => {}
                code => {
                    self.focus = PickerFocus::List;
                    let total = self.row_count();
                    match code {
                        KeyCode::Up | KeyCode::Char('k') => self.nav.move_by(-1, total),
                        KeyCode::Down | KeyCode::Char('j') => self.nav.move_by(1, total),
                        KeyCode::Home => {
                            self.nav.cursor = 0;
                            self.nav.ensure_visible(total);
                        }
                        KeyCode::End => {
                            self.nav.cursor = total.saturating_sub(1);
                            self.nav.ensure_visible(total);
                        }
                        KeyCode::PageUp => self.nav.page(false, total),
                        KeyCode::PageDown => self.nav.page(true, total),
                        KeyCode::Char(' ') => self.activate_row(),
                        _ => {}
                    }
                }
            }
            return;
        }
        if self.phase == ModelPhase::Limits {
            match key.code {
                KeyCode::Tab | KeyCode::Down => self.nav.cursor = (self.nav.cursor + 1) % 2,
                KeyCode::BackTab | KeyCode::Up => {
                    self.nav.cursor = self.nav.cursor.checked_sub(1).unwrap_or(1)
                }
                _ if self.nav.cursor == 0 => {
                    self.context_tokens.handle_key(key);
                }
                _ => {
                    self.max_output_tokens.handle_key(key);
                }
            }
            self.error = None;
            return;
        }
        if self.phase == ModelPhase::DefaultModel && self.catalog.is_empty() {
            self.model_id.handle_key(key);
            self.error = None;
            return;
        }
        match key.code {
            KeyCode::Up | KeyCode::BackTab | KeyCode::Char('k') => {
                self.nav.move_by(-1, self.row_count())
            }
            KeyCode::Down | KeyCode::Tab | KeyCode::Char('j') => {
                self.nav.move_by(1, self.row_count())
            }
            KeyCode::PageUp => self.nav.page(false, self.row_count()),
            KeyCode::PageDown => self.nav.page(true, self.row_count()),
            KeyCode::Char(' ') => self.activate_row(),
            _ => {}
        }
    }

    pub(crate) fn handle_mouse(&mut self, mouse: MouseEvent) {
        let pos = (mouse.column, mouse.row).into();
        match mouse.kind {
            MouseEventKind::ScrollUp => self.nav.move_by(-1, self.row_count()),
            MouseEventKind::ScrollDown => self.nav.move_by(1, self.row_count()),
            MouseEventKind::Down(MouseButton::Left) => {
                if let Some(index) = self.row_rects.iter().position(|rect| rect.contains(pos)) {
                    let index = self.nav.offset + index;
                    let was_focused = self.nav.cursor == index;
                    self.nav.cursor = index;
                    if self.short_path {
                        self.focus = PickerFocus::List;
                    }
                    if was_focused
                        || !matches!(
                            self.phase,
                            ModelPhase::Capabilities | ModelPhase::Delegation
                        )
                    {
                        self.activate_row();
                    }
                } else if let Some(index) =
                    self.field_rects.iter().position(|rect| rect.contains(pos))
                {
                    if self.short_path {
                        self.focus = [
                            PickerFocus::Provider,
                            PickerFocus::Search,
                            PickerFocus::Manual,
                        ][index.min(2)];
                    } else {
                        self.nav.cursor = index;
                    }
                }
            }
            _ => {}
        }
    }

    pub(crate) fn paste(&mut self, text: &str) {
        match self.phase {
            ModelPhase::DefaultModel if self.short_path && self.focus == PickerFocus::Search => {
                self.search.paste(text);
                self.refilter();
            }
            ModelPhase::DefaultModel => self.model_id.paste(text),
            ModelPhase::Limits if self.nav.cursor == 0 => self.context_tokens.paste(text),
            ModelPhase::Limits => self.max_output_tokens.paste(text),
            _ => {}
        }
    }

    pub(crate) fn selection(&self) -> (&str, &str) {
        (&self.provider_id, self.model_id.text())
    }

    #[cfg(test)]
    pub(crate) fn test_row_rects(&self) -> &[Rect] {
        &self.row_rects
    }

    /// Forget the previous frame's clickable rows and fields.
    pub(crate) fn clear_hit_geometry(&mut self) {
        self.row_rects.clear();
        self.field_rects.clear();
    }

    pub(crate) fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.clear_hit_geometry();
        match self.phase {
            ModelPhase::DefaultModel => self.render_default(frame, area),
            ModelPhase::Limits => self.render_limits(frame, area),
            _ => self.render_list(frame, area),
        }
    }

    fn render_default(&mut self, frame: &mut Frame, area: Rect) {
        if self.short_path {
            let rows = ratatui::layout::Layout::vertical([
                ratatui::layout::Constraint::Length(3),
                ratatui::layout::Constraint::Length(3),
                ratatui::layout::Constraint::Length(1),
                ratatui::layout::Constraint::Min(0),
            ])
            .split(area);
            self.field_rects.extend([rows[0], rows[1]]);
            let provider = TextField::new(if self.provider_id.is_empty() {
                "No provider configured"
            } else {
                &self.provider_id
            });
            ui::render_field(
                frame,
                rows[0],
                "Provider · Tab then ←/→ to switch · Ctrl+R refresh",
                &provider,
                self.focus == PickerFocus::Provider,
                "",
            );
            if let Some(caret) = ui::render_field(
                frame,
                rows[1],
                "Search models",
                &self.search,
                self.focus == PickerFocus::Search,
                "Type a model name",
            ) {
                frame.set_cursor_position(caret);
            }
            let selected = if self.model_id.text().is_empty() {
                "none"
            } else {
                self.model_id.text()
            };
            frame.render_widget(
                Paragraph::new(format!(
                    "{STAR} Selected: {} / {selected}{}",
                    self.provider_id,
                    if self.refreshing {
                        " · refreshing…"
                    } else {
                        ""
                    }
                ))
                .style(Style::new().fg(BRASS)),
                rows[2],
            );
            if self.catalog.iter().any(|(p, _)| p == &self.provider_id) {
                self.render_list(frame, rows[3]);
            } else {
                let parts = ratatui::layout::Layout::vertical([
                    ratatui::layout::Constraint::Length(3),
                    ratatui::layout::Constraint::Min(0),
                ])
                .split(rows[3]);
                self.field_rects.push(parts[0]);
                if let Some(caret) = ui::render_field(
                    frame,
                    parts[0],
                    "Model ID · no saved catalog; Ctrl+R to fetch",
                    &self.model_id,
                    self.focus == PickerFocus::Manual,
                    "Exact provider model ID",
                ) {
                    frame.set_cursor_position(caret);
                }
                self.render_detail(frame, parts[1]);
            }
            return;
        }
        if self.catalog.is_empty() {
            let field = Rect {
                height: 3.min(area.height),
                ..area
            };
            self.field_rects.push(field);
            if let Some(caret) = ui::render_field(
                frame,
                field,
                "Model ID",
                &self.model_id,
                true,
                "provider model id",
            ) {
                frame.set_cursor_position(caret);
            }
            self.render_detail(
                frame,
                Rect {
                    x: area.x,
                    y: field.bottom().min(area.bottom()),
                    width: area.width,
                    height: area.bottom().saturating_sub(field.bottom()),
                },
            );
            return;
        }
        self.render_list(frame, area);
    }

    fn render_limits(&mut self, frame: &mut Frame, area: Rect) {
        let first = Rect {
            height: 3.min(area.height),
            ..area
        };
        let second = Rect {
            x: area.x,
            y: first.bottom().min(area.bottom()),
            width: area.width,
            height: 3.min(area.bottom().saturating_sub(first.bottom())),
        };
        self.field_rects.extend([first, second]);
        let first_caret = ui::render_field(
            frame,
            first,
            "Context window tokens",
            &self.context_tokens,
            self.nav.cursor == 0,
            "Auto",
        );
        let second_caret = ui::render_field(
            frame,
            second,
            "Max output tokens",
            &self.max_output_tokens,
            self.nav.cursor == 1,
            "Auto",
        );
        if let Some(caret) = first_caret.or(second_caret) {
            frame.set_cursor_position(caret);
        }
        self.render_detail(
            frame,
            Rect {
                x: area.x,
                y: second.bottom().min(area.bottom()),
                width: area.width,
                height: area.bottom().saturating_sub(second.bottom()),
            },
        );
    }

    fn render_list(&mut self, frame: &mut Frame, area: Rect) {
        let detail_height = 3.min(area.height.saturating_sub(3));
        let list_area = Rect {
            height: area.height.saturating_sub(detail_height),
            ..area
        };
        let detail_area = Rect {
            x: area.x,
            y: list_area.bottom(),
            width: area.width,
            height: detail_height,
        };
        let title = match self.phase {
            ModelPhase::DefaultModel => " Models ",
            ModelPhase::Trust => " Trust ",
            ModelPhase::Capabilities => " Capabilities ",
            ModelPhase::Thinking => " Thinking ",
            ModelPhase::Delegation => " Delegation ",
            ModelPhase::Limits => unreachable!(),
        };
        let block = Block::bordered()
            .border_type(crate::tui::chrome::rounded_border_type())
            .border_style(Style::new().fg(NIGHT))
            .title(Span::styled(title, Style::new().fg(INK)))
            .padding(Padding::horizontal(1));
        let inner = block.inner(list_area);
        frame.render_widget(block, list_area);
        let total = self.row_count();
        self.nav.set_view_h(usize::from(inner.height));
        self.nav.clamp(total);
        let overflow = total > usize::from(inner.height);
        let row_width = inner.width.saturating_sub(u16::from(overflow));
        for row in 0..usize::from(inner.height) {
            let index = self.nav.offset + row;
            if index >= total {
                break;
            }
            let rect = Rect {
                x: inner.x,
                y: inner.y + row as u16,
                width: row_width,
                height: 1,
            };
            self.row_rects.push(rect);
            frame.render_widget(Paragraph::new(self.row_line(index)), rect);
        }
        if overflow {
            ui::render_scrollbar(
                frame,
                Rect {
                    x: inner.right() - 1,
                    y: inner.y,
                    width: 1,
                    height: inner.height,
                },
                total,
                usize::from(inner.height),
                self.nav.offset,
                false,
            );
        }
        if let Some(error) = &self.error {
            frame.render_widget(
                Paragraph::new(error.as_str()),
                Rect {
                    x: inner.x,
                    y: inner.bottom().saturating_sub(1),
                    width: inner.width,
                    height: 1,
                },
            );
        }
        self.render_detail(frame, detail_area);
    }

    fn row_line(&self, index: usize) -> Line<'static> {
        let focused = self.nav.cursor == index;
        let style = if focused {
            Style::new().fg(BRASS).add_modifier(Modifier::BOLD)
        } else {
            Style::new().fg(INK)
        };
        match self.phase {
            ModelPhase::DefaultModel => {
                let catalog_index = if self.short_path {
                    self.filtered[index]
                } else {
                    index
                };
                let (provider, model) = &self.catalog[catalog_index];
                Line::from(vec![
                    ui::radio_mark(focused, focused),
                    Span::styled(
                        if catalog_index == self.selected_model {
                            format!("{STAR} ")
                        } else {
                            "  ".to_string()
                        },
                        Style::new().fg(BRASS),
                    ),
                    Span::styled(model.clone(), style),
                    Span::styled(format!("  {provider}"), Style::new().fg(FOG)),
                ])
            }
            ModelPhase::Trust => {
                let labels = ["untrusted", "trusted"];
                Line::from(vec![
                    ui::radio_mark(focused, focused),
                    Span::styled(labels[index], style),
                ])
            }
            ModelPhase::Capabilities => Line::from(vec![
                ui::check_mark(self.capabilities[index], focused),
                Span::styled(CAPABILITIES[index].1, style),
            ]),
            ModelPhase::Thinking => Line::from(vec![
                ui::radio_mark(focused, focused),
                Span::styled(THINKING[index].0, style),
            ]),
            ModelPhase::Delegation => Line::from(vec![
                ui::check_mark(self.delegation[index], focused),
                Span::styled(DELEGATION[index].1, style),
            ]),
            ModelPhase::Limits => unreachable!(),
        }
    }

    fn render_detail(&self, frame: &mut Frame, area: Rect) {
        let (text, color) =
            if let Some(error) = &self.error {
                (error.clone(), BAD)
            } else {
                (match self.phase {
            ModelPhase::DefaultModel if self.catalog.is_empty() => {
                "Enter the exact model ID for the provider configured in the previous step."
                    .to_string()
            }
            ModelPhase::DefaultModel => self
                .catalog
                .get(self.catalog_index().unwrap_or(usize::MAX))
                .map(|(provider, model)| format!("{provider} / {model}"))
                .unwrap_or_default(),
            ModelPhase::Trust if self.nav.cursor == 0 => {
                "Redact secrets and sealed values from inference requests.".to_string()
            }
            ModelPhase::Trust => {
                "Permit host-mediated secret capture; inference stays reference-only.".to_string()
            }
            ModelPhase::Capabilities => CAPABILITIES[self.nav.cursor.min(CAPABILITIES.len() - 1)]
                .2
                .to_string(),
            ModelPhase::Thinking => THINKING[self.nav.cursor.min(THINKING.len() - 1)]
                .1
                .to_string(),
            ModelPhase::Delegation => DELEGATION[self.nav.cursor.min(DELEGATION.len() - 1)]
                .2
                .to_string(),
            ModelPhase::Limits => {
                "Blank keeps Auto; overrides must be positive numbers.".to_string()
            }
            }, FOG)
            };
        frame.render_widget(
            Paragraph::new(text)
                .style(Style::new().fg(color))
                .wrap(Wrap { trim: true }),
            area,
        );
    }
}
