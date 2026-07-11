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
//! `high` picker. The result is written to `active_model` in config.json.
//!
//! The dialog is independent of `tui/settings.rs` to keep that file's
//! state machine focused on settings editing.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::config::dirs::{
    COCKPIT_CONFIG_ENV, config_file_paths_for_load, config_write_target_for_provider,
    most_specific_config_write_target,
};
use crate::config::providers::{
    ActiveModelRef, ActiveReasoningEffort, CapabilityValue, ConfigDoc, ProvidersConfig,
    ReasoningEffortCapability, ThinkingMode,
};
use crate::tui::pane::{Pane, ScrollList};
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;
use unicode_width::UnicodeWidthStr;

pub const DIALOG_HEIGHT: u16 = 18;

/// Visible model rows in the pick step. The dialog reserves the rest of
/// its height for the border, filter line, section headers, and help
/// line. Drives the scroll window (same scrolloff=1 behavior as the
/// composer `@`-popup).
const MODEL_WINDOW: usize = 11;
const PICK_FIXED_CHROME: usize = 2;
const PICK_ERROR_LINES: usize = 2;

pub struct ModelPickerDialog {
    cwd: PathBuf,
    cfg: ProvidersConfig,
    entries: Vec<Entry>,
    active_model: Option<(String, String)>,
    filter: TextField,
    /// Cursor and top visible index of the scroll window over the filtered list.
    pick: ScrollList,
    step: Step,
    error: Option<String>,
    done: bool,
    row_hits: Vec<Option<RowHit>>,
}

#[derive(Clone)]
struct Entry {
    provider_id: String,
    model_id: String,
    display_name: Option<String>,
    is_favorite: bool,
    reasoning_effort: Option<ReasoningEffortCapability>,
    thinking_modes: Vec<ThinkingMode>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelChoice {
    pub provider_id: String,
    pub model_id: String,
    pub label: String,
    pub is_favorite: bool,
    pub trust: crate::config::providers::ModelTrust,
    pub mode: crate::config::extended::LlmMode,
}

pub fn ordered_model_choices(
    cwd: &Path,
    counts: &HashMap<String, u64>,
) -> Result<Vec<ModelChoice>, String> {
    ensure_config_reachable(cwd)?;
    let cfg = ConfigDoc::load_effective(cwd);
    let mut entries: Vec<Entry> = Vec::new();
    for (pid, entry) in &cfg.providers {
        for model in &entry.models {
            entries.push(Entry {
                provider_id: pid.clone(),
                model_id: model.id.clone(),
                display_name: model.name.clone(),
                is_favorite: model.favorite,
                reasoning_effort: model.capabilities.reasoning_effort.clone(),
                thinking_modes: model.thinking_modes.clone(),
            });
        }
    }
    sort_entries(&mut entries, counts);
    let global_mode = crate::config::extended::load_for_cwd(cwd).llm_mode;
    Ok(entries
        .into_iter()
        .map(|e| {
            let label = e.label();
            let trust = cfg.resolve_trust(&e.provider_id, &e.model_id);
            let mode = cfg.resolve_mode(&e.provider_id, &e.model_id, global_mode);
            ModelChoice {
                label,
                provider_id: e.provider_id,
                model_id: e.model_id,
                is_favorite: e.is_favorite,
                trust,
                mode,
            }
        })
        .collect())
}

fn sort_entries(entries: &mut [Entry], counts: &HashMap<String, u64>) {
    entries.sort_by(|a, b| {
        b.is_favorite
            .cmp(&a.is_favorite)
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
    /// Try to open the picker for the given cwd. Returns `Err` if no
    /// config is reachable; callers should show the message inline.
    pub fn open(cwd: &Path, counts: &HashMap<String, u64>) -> Result<Self, String> {
        ensure_config_reachable(cwd)?;
        let cfg = ConfigDoc::load_effective(cwd);

        let mut entries: Vec<Entry> = Vec::new();
        for (pid, entry) in &cfg.providers {
            for model in &entry.models {
                entries.push(Entry {
                    provider_id: pid.clone(),
                    model_id: model.id.clone(),
                    display_name: model.name.clone(),
                    is_favorite: model.favorite,
                    reasoning_effort: model.capabilities.reasoning_effort.clone(),
                    thinking_modes: model.thinking_modes.clone(),
                });
            }
        }
        // Stable order: favorites first, then 30-day usage count desc,
        // then label asc (the original alphabetical fallback). Favorites
        // stay pinned above a more-frequent non-favorite.
        sort_entries(&mut entries, counts);
        let active_model = cfg
            .active_model
            .as_ref()
            .map(|active| (active.provider.clone(), active.model.clone()));
        let (cursor, scroll) =
            initial_pick_position(&entries, active_model.as_ref(), "", MODEL_WINDOW);

        Ok(Self {
            cwd: cwd.to_path_buf(),
            cfg,
            entries,
            active_model,
            filter: TextField::default(),
            pick: ScrollList::at(cursor, scroll),
            step: Step::Pick,
            error: None,
            done: false,
            row_hits: Vec::new(),
        })
    }

    pub fn is_done(&self) -> bool {
        self.done
    }

    #[cfg(test)]
    pub fn error_text(&self) -> Option<&str> {
        self.error.as_deref()
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
                self.pick.set_cursor(cursor);
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
        // Arrow keys navigate (with wrap); `j`/`k` stay literal text for
        // the filter, since this step is typing-driven.
        match key.code {
            KeyCode::Up => {
                self.pick.move_by(-1, visible.len());
                self.pick.clamp_windowed(visible.len(), MODEL_WINDOW);
            }
            KeyCode::Down => {
                self.pick.move_by(1, visible.len());
                self.pick.clamp_windowed(visible.len(), MODEL_WINDOW);
            }
            KeyCode::Enter => {
                if let Some(&i) = visible.get(self.pick.cursor()) {
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
                        return self.commit_active_model(
                            entry.provider_id,
                            entry.model_id,
                            None,
                            None,
                        );
                    } else {
                        let modes = entry.thinking_modes.clone();
                        self.step = Step::ChooseThinking {
                            provider_id: entry.provider_id,
                            model_id: entry.model_id,
                            modes,
                            cursor: 0,
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
        let (cursor, scroll) = initial_pick_position(
            &self.entries,
            self.active_model.as_ref(),
            self.filter.text(),
            MODEL_WINDOW,
        );
        self.pick = ScrollList::at(cursor, scroll);
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
                return self.commit_active_model(p, m, None, mode);
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
                return self.commit_active_model(p, m, effort, None);
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
    ) -> bool {
        let previous = self.cfg.active_model.clone();
        self.cfg.active_model = Some(ActiveModelRef {
            provider: provider_id,
            model: model_id,
            reasoning_effort,
            thinking_mode,
        });
        if let Err(e) = self.save() {
            self.cfg.active_model = previous;
            self.error = Some(format!("save failed: {e}"));
            self.done = false;
            return false;
        }
        self.done = true;
        true
    }

    fn save(&mut self) -> Result<(), String> {
        let Some(active) = self.cfg.active_model.clone() else {
            return Ok(());
        };
        let path = config_write_target_for_provider(&self.cwd, &active.provider)
            .or_else(|| most_specific_config_write_target(&self.cwd))
            .ok_or_else(|| "no cockpit config found — run `/settings` to create one".to_string())?;
        let mut doc = ConfigDoc::load(&path).map_err(|e| e.to_string())?;
        doc.write_active_model(Some(&active))
            .map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.row_hits.clear();
        self.row_hits
            .resize(area.y.saturating_add(area.height) as usize, None);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" /model — pick the active model ");
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        match &self.step {
            Step::Pick => self.render_pick(frame, layout[0]),
            Step::ChooseThinking { .. } => self.render_thinking(frame, layout[0]),
            Step::ChooseReasoning { .. } => self.render_reasoning(frame, layout[0]),
        }
        let help = match &self.step {
            Step::Pick => "type to filter  ↑/↓  enter: pick  esc: cancel",
            Step::ChooseThinking { .. } => "↑/↓  enter: confirm  ←: back  esc: cancel",
            Step::ChooseReasoning { .. } => "↑/↓  enter: confirm  ←: back  esc: cancel",
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
        let mut lines: Vec<Line<'static>> = Vec::new();
        let (filter_before, filter_after) = self.filter.split_at_cursor();
        lines.push(Line::from(vec![
            Span::styled("filter: ".to_string(), muted),
            Span::styled(filter_before.to_string(), Style::default().fg(Color::White)),
            Span::styled(filter_after.to_string(), Style::default().fg(Color::White)),
        ]));
        lines.push(Line::default());

        let visible = self.filtered_indices();
        if visible.is_empty() {
            let body = if self.entries.is_empty() {
                "(no models — run `/fetch-models` or add a provider via `/settings`)"
            } else {
                "(no matches — try a different filter)"
            };
            lines.push(Line::from(Span::styled(body.to_string(), muted)));
        } else {
            let mut seen_fav = false;
            let mut seen_other = false;
            let both_sections = visible.iter().any(|&idx| self.entries[idx].is_favorite)
                && visible.iter().any(|&idx| !self.entries[idx].is_favorite);
            let window = pick_window(area.height, self.error.is_some(), both_sections);
            // Scroll window: same scrolloff=1 behavior as the @-popup.
            let offset = crate::tui::nav::windowed_scroll(
                self.pick.cursor(),
                self.pick.scroll(),
                visible.len(),
                window,
            );
            for (i, &idx) in visible.iter().enumerate().skip(offset).take(window) {
                let e = &self.entries[idx];
                if e.is_favorite && !seen_fav {
                    lines.push(Line::from(Span::styled(
                        "favorites".to_string(),
                        muted.add_modifier(Modifier::ITALIC),
                    )));
                    seen_fav = true;
                }
                if !e.is_favorite && !seen_other {
                    lines.push(Line::from(Span::styled(
                        "all models".to_string(),
                        muted.add_modifier(Modifier::ITALIC),
                    )));
                    seen_other = true;
                }
                let highlighted = i == self.pick.cursor();
                let is_active_model = self.is_active_entry(e);
                let marker = if highlighted { "▸ " } else { "  " };
                let label_style = if highlighted {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else if e.is_favorite {
                    yellow
                } else {
                    Style::default().fg(Color::White)
                };
                let mut spans = vec![
                    Span::raw(marker.to_string()),
                    Span::styled(e.label(), label_style),
                ];
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
                lines.push(Line::from(spans));
                let row = area.y + lines.len() as u16 - 1;
                if row < area.y + area.height
                    && let Some(slot) = self.row_hits.get_mut(row as usize)
                {
                    *slot = Some(RowHit::Pick { cursor: i });
                }
            }
        }
        push_error_line(&mut lines, self.error.as_deref());
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
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
            let marker = if i == *cursor { "▸ " } else { "  " };
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
            let marker = if i == *cursor { "▸ " } else { "  " };
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

fn pick_window(body_height: u16, has_error: bool, both_sections: bool) -> usize {
    let header_lines = if both_sections { 2 } else { 1 };
    let error_lines = if has_error { PICK_ERROR_LINES } else { 0 };
    let chrome = PICK_FIXED_CHROME + header_lines + error_lines;
    usize::from(body_height)
        .saturating_sub(chrome)
        .clamp(1, MODEL_WINDOW)
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

/// Toggle the favorite flag on the currently-active model, persisting
/// the change to `config.json`. Returns the new favorite state, or
/// `Err` if there's no active model or no config to write to.
pub fn toggle_active_favorite(cwd: &Path) -> Result<(bool, String, String), String> {
    ensure_config_reachable(cwd).map_err(|_| "no cockpit config found".to_string())?;
    let mut cfg = ConfigDoc::load_effective(cwd);
    let active = cfg
        .active_model
        .clone()
        .ok_or_else(|| "no active model — run `/model` first".to_string())?;
    let entry = cfg
        .providers
        .get_mut(&active.provider)
        .ok_or_else(|| format!("provider `{}` not in config", active.provider))?;
    let model = entry
        .models
        .iter_mut()
        .find(|m| m.id == active.model)
        .ok_or_else(|| {
            format!(
                "model `{}` not in provider `{}` — refetch `/models` first",
                active.model, active.provider
            )
        })?;
    model.favorite = !model.favorite;
    let new = model.favorite;
    let p = active.provider.clone();
    let m = active.model.clone();
    let path = config_write_target_for_provider(cwd, &p)
        .ok_or_else(|| "no cockpit config found".to_string())?;
    let mut doc = ConfigDoc::load(&path).map_err(|e| e.to_string())?;
    doc.write_model_favorite(&p, &m, new)
        .map_err(|e| e.to_string())?;
    Ok((new, p, m))
}

pub fn cycle_active_favorite(
    cwd: &Path,
    counts: &HashMap<String, u64>,
    forward: bool,
) -> Result<Option<(String, String)>, String> {
    ensure_config_reachable(cwd).map_err(|_| "no cockpit config found".to_string())?;
    let cfg = ConfigDoc::load_effective(cwd);
    let active = cfg
        .active_model
        .as_ref()
        .map(|active| (active.provider.clone(), active.model.clone()));
    let mut entries: Vec<Entry> = Vec::new();
    for (pid, entry) in &cfg.providers {
        for model in &entry.models {
            if model.favorite {
                entries.push(Entry {
                    provider_id: pid.clone(),
                    model_id: model.id.clone(),
                    display_name: model.name.clone(),
                    is_favorite: model.favorite,
                    reasoning_effort: model.capabilities.reasoning_effort.clone(),
                    thinking_modes: model.thinking_modes.clone(),
                });
            }
        }
    }
    sort_entries(&mut entries, counts);
    if entries.len() < 2 {
        return Ok(None);
    }
    let current = active.as_ref().and_then(|(p, m)| {
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
    let active = ActiveModelRef {
        provider: target.provider_id.clone(),
        model: target.model_id.clone(),
        reasoning_effort: None,
        thinking_mode: None,
    };
    let path = config_write_target_for_provider(cwd, &active.provider)
        .or_else(|| most_specific_config_write_target(cwd))
        .ok_or_else(|| "no cockpit config found — run `/settings` to create one".to_string())?;
    let mut doc = ConfigDoc::load(&path).map_err(|e| e.to_string())?;
    doc.write_active_model(Some(&active))
        .map_err(|e| e.to_string())?;
    Ok(Some((active.provider, active.model)))
}

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

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn empty_dialog() -> ModelPickerDialog {
        // Build a dialog with no entries — exercises only key routing.
        ModelPickerDialog {
            cwd: PathBuf::from("/tmp/cockpit.test"),
            cfg: ProvidersConfig::default(),
            entries: Vec::new(),
            active_model: None,
            filter: TextField::default(),
            pick: ScrollList::new(),
            step: Step::Pick,
            error: None,
            done: false,
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
                crate::config::providers::ReasoningEffortRequestMapping::JsonField {
                    field: "reasoning_effort".into(),
                    values: BTreeMap::from([
                        ("minimal".into(), serde_json::json!("minimal")),
                        ("xhigh".into(), serde_json::json!("xhigh")),
                    ]),
                },
            ),
            source: Some(crate::config::providers::CapabilitySource::Live),
        }
    }

    fn reasoning_entry(model: &str) -> Entry {
        let mut entry = entry(model);
        entry.reasoning_effort = Some(reasoning_capability());
        entry
    }

    fn dialog_with(entries: Vec<Entry>) -> ModelPickerDialog {
        ModelPickerDialog {
            cwd: PathBuf::from("/tmp/cockpit.test"),
            cfg: ProvidersConfig::default(),
            entries,
            active_model: None,
            filter: TextField::default(),
            pick: ScrollList::new(),
            step: Step::Pick,
            error: None,
            done: false,
            row_hits: Vec::new(),
        }
    }

    fn dialog_with_cwd(cwd: PathBuf, entries: Vec<Entry>) -> ModelPickerDialog {
        ModelPickerDialog {
            cwd,
            cfg: ProvidersConfig::default(),
            entries,
            active_model: None,
            filter: TextField::default(),
            pick: ScrollList::new(),
            step: Step::Pick,
            error: None,
            done: false,
            row_hits: Vec::new(),
        }
    }

    fn rendered_text(d: &mut ModelPickerDialog, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).expect("terminal");
        terminal
            .draw(|frame| d.render(frame, Rect::new(0, 0, width, height)))
            .expect("draw");
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>()
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
    fn pick_filter_caret_handles_wide_unicode_cursor() {
        let mut d = dialog_with(vec![entry("alpha")]);
        d.filter.set("中a");
        d.filter.handle_key(press(KeyCode::Home));
        d.filter.handle_key(press(KeyCode::Right));

        let rendered = rendered_text(&mut d, 60, 12);

        assert!(rendered.contains("filter: 中 a"), "{rendered}");
    }

    #[test]
    fn pick_window_accounts_for_body_chrome() {
        assert_eq!(pick_window(40, false, true), MODEL_WINDOW);
        assert_eq!(
            pick_window((MODEL_WINDOW + PICK_FIXED_CHROME + 2) as u16, false, true),
            MODEL_WINDOW
        );
        assert_eq!(
            pick_window(
                (MODEL_WINDOW + PICK_FIXED_CHROME + 2).saturating_sub(1) as u16,
                false,
                true
            ),
            MODEL_WINDOW - 1
        );
        assert_eq!(pick_window(15, true, true), MODEL_WINDOW - PICK_ERROR_LINES);
        assert_eq!(pick_window(3, true, true), 1);
        assert_eq!(
            pick_window(10, false, false),
            pick_window(10, false, true) + 1
        );
    }

    #[test]
    fn short_picker_keeps_highlighted_last_row_visible() {
        let mut entries = vec![favorite_entry("fav")];
        entries.extend((0..13).map(|i| entry(&format!("m{i:02}"))));
        let mut d = dialog_with(entries);
        d.pick.set_cursor(d.filtered_indices().len() - 1);

        let rendered = rendered_text(&mut d, 80, 10);

        assert!(
            rendered.contains("▸ p/m12"),
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
            rendered.contains("▸ p/m12"),
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
    fn failed_save_keeps_picker_open_with_error() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        fs::write(cockpit.join("config.json"), "{not json").unwrap();
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![entry("a")]);

        assert!(!d.handle_key(press(KeyCode::Enter)));

        assert!(!d.is_done());
        assert_eq!(d.cfg.active_model, None);
        let err = d.error.as_deref().unwrap_or_default();
        assert!(err.contains("save failed"), "got: {err}");
    }

    #[test]
    fn successful_save_closes_and_marks_done() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
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
        let saved = ConfigDoc::load(&config_path).unwrap().providers();
        let active = saved.active_model.expect("active model persisted");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "a");
    }

    #[test]
    fn cycle_active_favorite_skips_nonfavorites_and_wraps() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            &provider_path,
            r#"{"url":"https://example.test","models":[{"id":"a","favorite":true},{"id":"b"},{"id":"c","favorite":true}]}"#,
        )
        .unwrap();
        ConfigDoc::load(&config_path)
            .unwrap()
            .write_active_model(Some(&ActiveModelRef {
                provider: "p".into(),
                model: "a".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }))
            .unwrap();

        let next = cycle_active_favorite(tmp.path(), &HashMap::new(), true)
            .unwrap()
            .expect("next favorite");
        assert_eq!(next, ("p".to_string(), "c".to_string()));
        let saved = ConfigDoc::load(&config_path).unwrap().providers();
        assert_eq!(saved.active_model.unwrap().model, "c");

        let prev = cycle_active_favorite(tmp.path(), &HashMap::new(), false)
            .unwrap()
            .expect("previous favorite");
        assert_eq!(prev, ("p".to_string(), "a".to_string()));
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
    fn rich_reasoning_selection_persists_native_value() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            provider_path,
            r#"{"url":"https://example.test","models":[{"id":"codex"}]}"#,
        )
        .unwrap();
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![reasoning_entry("codex")]);

        assert!(!d.handle_key(press(KeyCode::Enter)));
        assert!(d.handle_key(press(KeyCode::Enter)));

        let saved = ConfigDoc::load(&config_path).unwrap().providers();
        let active = saved.active_model.expect("active model persisted");
        assert_eq!(active.provider, "p");
        assert_eq!(active.model, "codex");
        assert_eq!(
            active.reasoning_effort.expect("reasoning effort").value,
            "xhigh"
        );
        assert_eq!(active.thinking_mode, None);
    }

    #[test]
    fn fallback_reasoning_capability_without_values_does_not_prompt() {
        let tmp = tempfile::tempdir().unwrap();
        let cockpit = tmp.path().join(".cockpit");
        fs::create_dir(&cockpit).unwrap();
        let config_path = cockpit.join("config.json");
        fs::write(&config_path, "{}").unwrap();
        let provider_path =
            crate::config::providers::provider_file_path_for_config(&config_path, "p").unwrap();
        fs::create_dir_all(provider_path.parent().unwrap()).unwrap();
        fs::write(
            provider_path,
            r#"{"url":"https://example.test","models":[{"id":"fallback"}]}"#,
        )
        .unwrap();
        let mut fallback = entry("fallback");
        fallback.reasoning_effort = Some(ReasoningEffortCapability {
            source: Some(crate::config::providers::CapabilitySource::Fallback),
            ..ReasoningEffortCapability::default()
        });
        let mut d = dialog_with_cwd(tmp.path().to_path_buf(), vec![fallback]);

        assert!(d.handle_key(press(KeyCode::Enter)));
        assert!(d.is_done());
        match d.step {
            Step::Pick => {}
            _ => panic!("fallback model should not open a reasoning step"),
        }
        let saved = ConfigDoc::load(&config_path).unwrap().providers();
        let active = saved.active_model.expect("active model persisted");
        assert_eq!(active.reasoning_effort, None);
        assert_eq!(active.thinking_mode, None);
    }

    fn dialog_with_active(entries: Vec<Entry>, provider: &str, model: &str) -> ModelPickerDialog {
        let active_model = Some((provider.to_string(), model.to_string()));
        let (cursor, scroll) =
            initial_pick_position(&entries, active_model.as_ref(), "", MODEL_WINDOW);
        ModelPickerDialog {
            cwd: PathBuf::from("/tmp/cockpit.test"),
            cfg: ProvidersConfig::default(),
            entries,
            active_model,
            filter: TextField::default(),
            pick: ScrollList::at(cursor, scroll),
            step: Step::Pick,
            error: None,
            done: false,
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
        assert!(rendered.contains("▸ p/first"));
        assert!(rendered.contains("p/active  [active]"));
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
