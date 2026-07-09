//! Shared sub-pages drilled into from the category settings pages
//! (implementation note):
//!
//!   - [`InstructionsPage`] — grab/reorder editor for
//!     `extended.agent_guidance_files` (drilled from Behavior),
//!   - [`RedactPatternsPage`] — grab/reorder editor for
//!     `extended.redact.dotenv_patterns` (drilled from Privacy & Safety),
//!   - [`UtilityModelPicker`] — the utility-model overlay opened on the
//!     Behavior page's `utility model` row.
//!
//! These were originally hung off the old flat `UiPage`; that page was split
//! into the five [`super::category`] pages, and these drill-ins were
//! re-homed under the categories where their fields now live.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Paragraph, Wrap};

use crate::config::providers::ProvidersConfig;
use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;

use super::category::{Category, CategoryPage};
use super::grab;
use super::{Nav, Page, SettingsDialog, save_status};

// ── Utility-model picker ─────────────────────────────────────────────────

/// A single selectable model row in the utility-model picker, shown as
/// `provider:model-id` plus the human `name` when present. Built from the
/// configured providers in their natural order — no ranking.
#[derive(Clone)]
pub(crate) struct UtilityModelEntry {
    pub(super) provider_id: String,
    pub(super) model_id: String,
    pub(super) display_name: Option<String>,
}

impl UtilityModelEntry {
    /// The stored form: `provider:model-id`.
    pub(crate) fn value(&self) -> String {
        format!("{}:{}", self.provider_id, self.model_id)
    }
}

/// Number of model rows visible at once in the picker's scroll window.
const UTILITY_MODEL_WINDOW: usize = 10;

/// The utility-model picker overlay. Two modes:
///   - **List** — navigate the configured models (grouped by provider),
///     plus the synthetic `[clear]` and `[custom…]` actions.
///   - **Custom** — a free-text field for a `provider:model-id` not in any
///     provider's list (the fallback the spec requires).
///
/// Opens in Custom mode when there are no models to list, so the field still
/// works with an empty/unfetched config.
pub(crate) struct UtilityModelPicker {
    /// Configured models in provider-grouped natural order.
    pub(crate) entries: Vec<UtilityModelEntry>,
    /// `provider:model-id` currently stored, if any. Indicated in the list
    /// and pre-filled into the custom field.
    pub(crate) current: Option<String>,
    pub(crate) mode: PickerMode,
}

pub(crate) enum PickerMode {
    /// Navigating the list. `cursor` indexes the synthetic navigable list
    /// (`[clear]`, `[custom…]`, then the model entries); `scroll` is the top
    /// of the visible window over the *model* entries.
    List { cursor: usize, scroll: usize },
    /// Typing a custom `provider:model-id`.
    Custom { buf: TextField },
}

/// Synthetic action rows that precede the model entries in List mode.
/// `[clear]` unsets the value; `[custom…]` switches to free-text entry.
pub(super) const PICKER_ACTION_ROWS: usize = 2;
pub(super) const PICKER_CLEAR_ROW: usize = 0;
pub(super) const PICKER_CUSTOM_ROW: usize = 1;

impl UtilityModelPicker {
    /// Build the picker from the configured providers. Models are listed in
    /// provider order (the config's `BTreeMap` iteration), each provider's
    /// models in their stored order — no sort/rank. With no models
    /// configured the picker opens straight into free-text entry (pre-filled
    /// with the current value) so the field still works.
    pub(crate) fn new(config: &ProvidersConfig, current: Option<String>) -> Self {
        let mut entries: Vec<UtilityModelEntry> = Vec::new();
        for (pid, entry) in &config.providers {
            for model in &entry.models {
                entries.push(UtilityModelEntry {
                    provider_id: pid.clone(),
                    model_id: model.id.clone(),
                    display_name: model.name.clone(),
                });
            }
        }
        let mode = if entries.is_empty() {
            PickerMode::Custom {
                buf: TextField::new(current.clone().unwrap_or_default()),
            }
        } else {
            let cursor = current
                .as_ref()
                .and_then(|cur| entries.iter().position(|e| &e.value() == cur))
                .map(|i| i + PICKER_ACTION_ROWS)
                .unwrap_or(PICKER_ACTION_ROWS);
            let scroll = crate::tui::app::windowed_scroll(
                cursor.saturating_sub(PICKER_ACTION_ROWS),
                0,
                entries.len(),
                UTILITY_MODEL_WINDOW,
            );
            PickerMode::List { cursor, scroll }
        };
        Self {
            entries,
            current,
            mode,
        }
    }

    /// The free-text buffer while in Custom mode, else `None` (the list has
    /// no text field).
    pub(crate) fn active_text_field(&mut self) -> Option<&mut TextField> {
        match &mut self.mode {
            PickerMode::Custom { buf } => Some(buf),
            PickerMode::List { .. } => None,
        }
    }

    /// Switch from Custom mode back to the List, re-selecting the current
    /// value (or the first model row).
    pub(crate) fn back_to_list(&mut self) {
        let cursor = self
            .current
            .as_ref()
            .and_then(|cur| self.entries.iter().position(|e| &e.value() == cur))
            .map(|i| i + PICKER_ACTION_ROWS)
            .unwrap_or(PICKER_ACTION_ROWS);
        let scroll = picker_window_scroll(cursor, 0, self.entries.len());
        self.mode = PickerMode::List { cursor, scroll };
    }
}

/// Recompute the model-entry scroll offset from a List-mode `cursor` that
/// includes the two synthetic action rows. Free function (not a method) so
/// callers can compute it while holding a mutable borrow into the picker's
/// `mode`.
pub(super) fn picker_window_scroll(cursor: usize, scroll: usize, entries_len: usize) -> usize {
    let selected = cursor.saturating_sub(PICKER_ACTION_ROWS);
    crate::tui::app::windowed_scroll(selected, scroll, entries_len, UTILITY_MODEL_WINDOW)
}

// ── Grab/reorder list sub-pages ──────────────────────────────────────────

/// `Instructions` sub-page — edits `extended.agent_guidance_files`. Drilled
/// from the Behavior page's `instructions files` row.
pub(crate) struct InstructionsPage {
    pub(super) cursor: usize,
    pub(super) grabbed: Option<GrabState>,
    pub(super) status: Option<String>,
}

impl InstructionsPage {
    pub(super) fn new() -> Self {
        Self {
            cursor: 0,
            grabbed: None,
            status: None,
        }
    }
}

/// `Environment File Patterns` sub-page — edits
/// `extended.redact.dotenv_patterns` (gitignore-style globs matched
/// cwd-downward, §7). Drilled from the Privacy & Safety page.
pub(crate) struct RedactPatternsPage {
    pub(super) cursor: usize,
    pub(super) grabbed: Option<GrabState>,
    pub(super) status: Option<String>,
}

impl RedactPatternsPage {
    pub(super) fn new() -> Self {
        Self {
            cursor: 0,
            grabbed: None,
            status: None,
        }
    }
}

/// Per-row state while a row is grabbed (held for rename + reorder).
pub(crate) struct GrabState {
    /// Live text buffer for the grabbed row's value.
    pub(super) buf: TextField,
    /// Index the row had when grabbed, restored on Esc.
    pub(super) origin: usize,
    /// Original value. `Some` for rows that already existed (Esc restores
    /// it); `None` for rows freshly created by `a` / Enter-on-`[+ add]` (Esc
    /// deletes them).
    pub(super) original_name: Option<String>,
}

impl GrabState {
    /// Grab an existing row at `origin` with its current `value`.
    pub(super) fn existing(value: String, origin: usize) -> Self {
        Self {
            buf: TextField::new(value.clone()),
            origin,
            original_name: Some(value),
        }
    }

    /// Grab a freshly-appended (empty) row at `origin`.
    pub(super) fn fresh(origin: usize) -> Self {
        Self {
            buf: TextField::default(),
            origin,
            original_name: None,
        }
    }
}

impl SettingsDialog {
    // ── Instructions sub-page ────────────────────────────────────────────

    pub(super) fn handle_instructions_key(&mut self, key: KeyEvent) -> bool {
        let placeholder = Page::Instructions(InstructionsPage::new());
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::Instructions(p) = &mut page {
            self.handle_instructions_page_key(key, p)
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

    fn handle_instructions_page_key(&mut self, key: KeyEvent, p: &mut InstructionsPage) -> Nav {
        if p.grabbed.is_some() {
            match key.code {
                KeyCode::Enter => self.commit_instructions_grab(p),
                KeyCode::Esc => self.cancel_instructions_grab(p),
                KeyCode::Up if p.cursor > 0 => {
                    self.extended
                        .agent_guidance_files
                        .swap(p.cursor, p.cursor - 1);
                    p.cursor -= 1;
                }
                KeyCode::Down if p.cursor + 1 < self.extended.agent_guidance_files.len() => {
                    self.extended
                        .agent_guidance_files
                        .swap(p.cursor, p.cursor + 1);
                    p.cursor += 1;
                }
                _ => {
                    if let Some(g) = p.grabbed.as_mut() {
                        g.buf.handle_key(key);
                    }
                }
            }
            return Nav::Stay;
        }

        let rows = self.extended.agent_guidance_files.len();
        let nav_len = rows + 1;
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Replace(Page::Category(Box::new(CategoryPage::new(
                    Category::Behavior,
                ))));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, nav_len);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.cursor = crate::tui::nav::wrap_next(p.cursor, nav_len);
            }
            KeyCode::Char('a') => self.start_instructions_grab_on_new(p),
            KeyCode::Char('d') | KeyCode::Delete
                if p.cursor < self.extended.agent_guidance_files.len() =>
            {
                self.extended.agent_guidance_files.remove(p.cursor);
                let total = self.extended.agent_guidance_files.len();
                p.cursor = p.cursor.min(total.saturating_sub(1));
                p.status = save_status(self.save_extended());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if p.cursor < self.extended.agent_guidance_files.len() {
                    let cur = self.extended.agent_guidance_files[p.cursor].clone();
                    p.grabbed = Some(GrabState::existing(cur, p.cursor));
                    p.status = None;
                } else if p.cursor == rows {
                    self.start_instructions_grab_on_new(p);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn start_instructions_grab_on_new(&mut self, p: &mut InstructionsPage) {
        self.extended.agent_guidance_files.push(String::new());
        let idx = self.extended.agent_guidance_files.len() - 1;
        p.cursor = idx;
        p.grabbed = Some(GrabState::fresh(idx));
        p.status = None;
    }

    fn commit_instructions_grab(&mut self, p: &mut InstructionsPage) {
        let Some(g) = p.grabbed.take() else { return };
        let trimmed = g.buf.text().trim().to_string();
        if trimmed.is_empty() {
            if p.cursor < self.extended.agent_guidance_files.len() {
                self.extended.agent_guidance_files.remove(p.cursor);
            }
        } else if let Some(slot) = self.extended.agent_guidance_files.get_mut(p.cursor) {
            *slot = trimmed;
        }
        let total = self.extended.agent_guidance_files.len();
        p.cursor = if total == 0 {
            0
        } else {
            p.cursor.min(total - 1)
        };
        p.status = save_status(self.save_extended());
    }

    fn cancel_instructions_grab(&mut self, p: &mut InstructionsPage) {
        let Some(g) = p.grabbed.take() else { return };
        match g.original_name {
            Some(name) => {
                if let Some(slot) = self.extended.agent_guidance_files.get_mut(p.cursor) {
                    *slot = name;
                }
                let target = g
                    .origin
                    .min(self.extended.agent_guidance_files.len().saturating_sub(1));
                while p.cursor > target {
                    self.extended
                        .agent_guidance_files
                        .swap(p.cursor, p.cursor - 1);
                    p.cursor -= 1;
                }
                while p.cursor < target {
                    self.extended
                        .agent_guidance_files
                        .swap(p.cursor, p.cursor + 1);
                    p.cursor += 1;
                }
            }
            None => {
                if p.cursor < self.extended.agent_guidance_files.len() {
                    self.extended.agent_guidance_files.remove(p.cursor);
                }
                let total = self.extended.agent_guidance_files.len();
                p.cursor = if total == 0 {
                    0
                } else {
                    p.cursor.min(total - 1)
                };
            }
        }
        p.status = None;
    }

    pub(super) fn render_instructions_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        p: &InstructionsPage,
    ) {
        render_grab_list(
            frame,
            area,
            "Instructions Files",
            "Only the first matching file (in this order) is injected into \
             prompts. Walks up from cwd to the git root.",
            &self.extended.agent_guidance_files,
            p.cursor,
            p.grabbed.as_ref(),
            "[+ add filename]",
            "  (type filename)",
            p.status.as_deref(),
        );
    }

    // ── Environment File Patterns sub-page ───────────────────────────────

    pub(super) fn handle_redact_patterns_key(&mut self, key: KeyEvent) -> bool {
        let placeholder = Page::RedactPatterns(RedactPatternsPage::new());
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::RedactPatterns(p) = &mut page {
            self.handle_redact_patterns_page_key(key, p)
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

    fn handle_redact_patterns_page_key(
        &mut self,
        key: KeyEvent,
        p: &mut RedactPatternsPage,
    ) -> Nav {
        if p.grabbed.is_some() {
            match key.code {
                KeyCode::Enter => self.commit_redact_pattern_grab(p),
                KeyCode::Esc => self.cancel_redact_pattern_grab(p),
                KeyCode::Up if p.cursor > 0 => {
                    self.extended
                        .redact
                        .dotenv_patterns
                        .swap(p.cursor, p.cursor - 1);
                    p.cursor -= 1;
                }
                KeyCode::Down if p.cursor + 1 < self.extended.redact.dotenv_patterns.len() => {
                    self.extended
                        .redact
                        .dotenv_patterns
                        .swap(p.cursor, p.cursor + 1);
                    p.cursor += 1;
                }
                _ => {
                    if let Some(g) = p.grabbed.as_mut() {
                        g.buf.handle_key(key);
                    }
                }
            }
            return Nav::Stay;
        }

        let rows = self.extended.redact.dotenv_patterns.len();
        let nav_len = rows + 1;
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Replace(Page::Category(Box::new(CategoryPage::new(
                    Category::Privacy,
                ))));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, nav_len);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.cursor = crate::tui::nav::wrap_next(p.cursor, nav_len);
            }
            KeyCode::Char('a') => self.start_redact_pattern_grab_on_new(p),
            KeyCode::Char('d') | KeyCode::Delete
                if p.cursor < self.extended.redact.dotenv_patterns.len() =>
            {
                self.extended.redact.dotenv_patterns.remove(p.cursor);
                let total = self.extended.redact.dotenv_patterns.len();
                p.cursor = p.cursor.min(total.saturating_sub(1));
                p.status = save_status(self.save_extended());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if p.cursor < self.extended.redact.dotenv_patterns.len() {
                    let cur = self.extended.redact.dotenv_patterns[p.cursor].clone();
                    p.grabbed = Some(GrabState::existing(cur, p.cursor));
                    p.status = None;
                } else if p.cursor == rows {
                    self.start_redact_pattern_grab_on_new(p);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    fn start_redact_pattern_grab_on_new(&mut self, p: &mut RedactPatternsPage) {
        self.extended.redact.dotenv_patterns.push(String::new());
        let idx = self.extended.redact.dotenv_patterns.len() - 1;
        p.cursor = idx;
        p.grabbed = Some(GrabState::fresh(idx));
        p.status = None;
    }

    fn commit_redact_pattern_grab(&mut self, p: &mut RedactPatternsPage) {
        let Some(g) = p.grabbed.take() else { return };
        let trimmed = g.buf.text().trim().to_string();
        if trimmed.is_empty() {
            if p.cursor < self.extended.redact.dotenv_patterns.len() {
                self.extended.redact.dotenv_patterns.remove(p.cursor);
            }
        } else if let Some(slot) = self.extended.redact.dotenv_patterns.get_mut(p.cursor) {
            *slot = trimmed;
        }
        let total = self.extended.redact.dotenv_patterns.len();
        p.cursor = if total == 0 {
            0
        } else {
            p.cursor.min(total - 1)
        };
        p.status = save_status(self.save_extended());
    }

    fn cancel_redact_pattern_grab(&mut self, p: &mut RedactPatternsPage) {
        let Some(g) = p.grabbed.take() else { return };
        match g.original_name {
            Some(name) => {
                if let Some(slot) = self.extended.redact.dotenv_patterns.get_mut(p.cursor) {
                    *slot = name;
                }
                let target = g
                    .origin
                    .min(self.extended.redact.dotenv_patterns.len().saturating_sub(1));
                while p.cursor > target {
                    self.extended
                        .redact
                        .dotenv_patterns
                        .swap(p.cursor, p.cursor - 1);
                    p.cursor -= 1;
                }
                while p.cursor < target {
                    self.extended
                        .redact
                        .dotenv_patterns
                        .swap(p.cursor, p.cursor + 1);
                    p.cursor += 1;
                }
            }
            None => {
                if p.cursor < self.extended.redact.dotenv_patterns.len() {
                    self.extended.redact.dotenv_patterns.remove(p.cursor);
                }
                let total = self.extended.redact.dotenv_patterns.len();
                p.cursor = if total == 0 {
                    0
                } else {
                    p.cursor.min(total - 1)
                };
            }
        }
        p.status = None;
    }

    pub(super) fn render_redact_patterns_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        p: &RedactPatternsPage,
    ) {
        render_grab_list(
            frame,
            area,
            "Environment File Patterns",
            "Gitignore-style globs. Matched from cwd downward through \
             subdirectories; each matched file's format is auto-detected \
             (KEY=VALUE / JSON / YAML / TOML) and its secret values scrubbed.",
            &self.extended.redact.dotenv_patterns,
            p.cursor,
            p.grabbed.as_ref(),
            "[+ add pattern]",
            "  (type pattern)",
            p.status.as_deref(),
        );
    }

    // ── Utility-model picker render ──────────────────────────────────────

    pub(super) fn render_utility_picker(
        &self,
        frame: &mut Frame,
        area: Rect,
        picker: &UtilityModelPicker,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = Vec::new();

        lines.push(Line::from(Span::styled(
            "Utility model — picks the cheap background model".to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )));
        lines.push(Line::default());

        match &picker.mode {
            PickerMode::Custom { buf } => {
                lines.push(Line::from(Span::styled(
                    "custom provider:model-id".to_string(),
                    muted,
                )));
                let (before, after) = buf.split_at_cursor();
                lines.push(Line::from(vec![
                    Span::styled("› ".to_string(), muted),
                    Span::styled(before.to_string(), Style::default().fg(Color::White)),
                    Span::styled("▎".to_string(), yellow),
                    Span::styled(after.to_string(), Style::default().fg(Color::White)),
                ]));
                lines.push(Line::default());
                if picker.entries.is_empty() {
                    lines.push(Line::from(Span::styled(
                        "No models fetched yet — type a provider:model-id, or fetch \
                         models from the Providers page."
                            .to_string(),
                        muted,
                    )));
                }
                lines.push(Line::from(Span::styled(
                    "enter: accept (blank clears)  esc: back".to_string(),
                    muted,
                )));
            }
            PickerMode::List { cursor, scroll } => {
                let cur_label = |value: &str| -> &'static str {
                    if picker.current.as_deref() == Some(value) {
                        "  (current)"
                    } else {
                        ""
                    }
                };
                let clear_active = *cursor == PICKER_CLEAR_ROW;
                let custom_active = *cursor == PICKER_CUSTOM_ROW;
                let action_style = |active: bool| {
                    if active {
                        yellow.add_modifier(Modifier::BOLD)
                    } else {
                        muted
                    }
                };
                let clear_suffix = if picker.current.is_none() {
                    "  (current)"
                } else {
                    ""
                };
                lines.push(Line::from(vec![
                    Span::raw(if clear_active { "▸ " } else { "  " }),
                    Span::styled(
                        format!("[clear — unset]{clear_suffix}"),
                        action_style(clear_active),
                    ),
                ]));
                lines.push(Line::from(vec![
                    Span::raw(if custom_active { "▸ " } else { "  " }),
                    Span::styled(
                        "[custom provider:model-id…]".to_string(),
                        action_style(custom_active),
                    ),
                ]));

                let mut last_provider: Option<&str> = None;
                for (i, e) in picker
                    .entries
                    .iter()
                    .enumerate()
                    .skip(*scroll)
                    .take(UTILITY_MODEL_WINDOW)
                {
                    if last_provider != Some(e.provider_id.as_str()) {
                        lines.push(Line::from(Span::styled(
                            e.provider_id.clone(),
                            muted.add_modifier(Modifier::ITALIC),
                        )));
                        last_provider = Some(e.provider_id.as_str());
                    }
                    let active = *cursor == i + PICKER_ACTION_ROWS;
                    let marker = if active { "▸ " } else { "  " };
                    let label_style = if active {
                        yellow.add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    let value = e.value();
                    let mut spans = vec![
                        Span::raw(marker.to_string()),
                        Span::styled(value.clone(), label_style),
                    ];
                    if let Some(name) = &e.display_name {
                        spans.push(Span::raw("  "));
                        spans.push(Span::styled(name.clone(), muted));
                    }
                    let suffix = cur_label(&value);
                    if !suffix.is_empty() {
                        spans.push(Span::styled(suffix.to_string(), yellow));
                    }
                    lines.push(Line::from(spans));
                }

                lines.push(Line::default());
                lines.push(Line::from(Span::styled(
                    "↑/↓  enter: select  esc: cancel".to_string(),
                    muted,
                )));
            }
        }

        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
    }
}

/// Shared full-pane renderer for the two grab/reorder list sub-pages.
#[allow(clippy::too_many_arguments)]
fn render_grab_list(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    intro: &str,
    items: &[String],
    cursor: usize,
    grabbed: Option<&GrabState>,
    add_label: &str,
    empty_hint: &str,
    status: Option<&str>,
) {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let yellow = Style::default().fg(Color::Yellow);
    let mut lines: Vec<Line<'static>> = vec![
        Line::from(Span::styled(
            title.to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        Line::from(Span::styled(intro.to_string(), muted)),
        Line::default(),
    ];

    for (i, item) in items.iter().enumerate() {
        let is_grabbed = grabbed.is_some() && i == cursor;
        let on_cursor = i == cursor;
        if is_grabbed {
            let grabbed = grabbed.unwrap();
            lines.push(Line::from(grab::grabbed_row_spans(
                grabbed.buf.text(),
                grabbed.buf.cursor(),
                empty_hint,
            )));
            continue;
        }
        let marker = if on_cursor {
            grab::CURSOR_MARKER
        } else {
            grab::IDLE_MARKER
        };
        let style = if on_cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(item.clone(), style),
        ]));
    }

    if grabbed.is_none() {
        let add_idx = items.len();
        let add_selected = cursor == add_idx;
        let marker = if add_selected {
            grab::CURSOR_MARKER
        } else {
            grab::IDLE_MARKER
        };
        let style = if add_selected {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            muted
        };
        lines.push(Line::from(vec![
            Span::raw(marker),
            Span::styled(add_label.to_string(), style),
        ]));
    }

    if grabbed.is_some() {
        lines.push(Line::default());
        lines.push(grab::grab_hint_line(grab::GRAB_HINT));
    }

    if let Some(status) = status {
        lines.push(Line::default());
        lines.push(Line::from(Span::styled(status.to_string(), yellow)));
    }

    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), area);
}
