//! Searchable provider catalog for the onboarding shell.
//!
//! The list is a *projection* over the canonical template registry
//! (`cockpit_core::providers`). Filtering normalizes the query for display
//! matching only; a selection always resolves back to the original
//! `'static` template, so the canonical provider identity that reaches the
//! daemon mutation authority is never derived from the filtered view.

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use super::theme::{BRASS, FOG, INK};
use crate::tui::textfield::TextField;
use cockpit_core::providers::ProviderTemplate;

/// Ordered onboarding catalog: subscription logins first, then the rest of
/// the built-in registry (stable sort keeps registry order within groups).
pub(crate) fn onboarding_catalog() -> Vec<&'static ProviderTemplate> {
    crate::tui::settings::providers::onboarding_ordered_templates()
}

/// Unicode-aware, case-insensitive containment used for query matching.
/// Applies to labels/ids for display only; it never rewrites the template
/// identity that a selection resolves to.
fn normalized(haystack: &str) -> String {
    haystack.to_lowercase()
}

/// Templates whose id or display label matches `query` (case-insensitive).
/// An empty query matches everything, preserving catalog order. The
/// returned references are the canonical `'static` registry entries, so a
/// selection always resolves the original template identity.
pub(crate) fn filter_catalog(
    catalog: &[&'static ProviderTemplate],
    query: &str,
) -> Vec<&'static ProviderTemplate> {
    let query = normalized(query.trim());
    if query.is_empty() {
        return catalog.to_vec();
    }
    catalog
        .iter()
        .copied()
        .filter(|template| {
            normalized(template.id).contains(&query)
                || normalized(template.display).contains(&query)
        })
        .collect()
}

/// One rendered row of the filtered catalog.
pub(crate) struct ProviderRow<'a> {
    pub(crate) template: &'a ProviderTemplate,
    pub(crate) selected: bool,
}

/// State for the provider search screen.
pub(crate) struct ProviderSearchScreen {
    query: TextField,
    /// Cursor index into the *filtered* list. A query edit re-anchors this
    /// index to the previously selected canonical template id (see
    /// [`ProviderSearchScreen::remap_selection`]) so filtering can never
    /// silently move the selection onto a different visible row.
    cursor: usize,
    selection_started: bool,
    /// First visible row index of the viewport.
    offset: usize,
    /// Row capacity observed at the last render; used to clamp scrolling
    /// whenever the list or the terminal size changes.
    viewport_capacity: usize,
    status: Option<String>,
    scrollbar_area: Rect,
    dragging_scrollbar: bool,
}

impl ProviderSearchScreen {
    pub(crate) fn new() -> Self {
        Self {
            query: TextField::default(),
            cursor: 0,
            selection_started: false,
            offset: 0,
            viewport_capacity: 0,
            status: None,
            scrollbar_area: Rect::default(),
            dragging_scrollbar: false,
        }
    }

    pub(crate) fn set_status(&mut self, status: Option<String>) {
        self.status = status;
    }

    pub(crate) fn query_field(&self) -> &TextField {
        &self.query
    }

    pub(crate) fn offset_for_scroll(&self) -> usize {
        self.offset
    }

    pub(crate) fn activate_focused(&mut self) -> Option<&'static ProviderTemplate> {
        if !self.selection_started {
            self.status = Some("Select a provider first.".to_string());
            return None;
        }
        self.activate(self.selected_template())
    }

    #[cfg(test)]
    pub(crate) fn query(&self) -> &str {
        self.query.text()
    }

    /// The filtered view of the catalog for the current query.
    pub(crate) fn filtered(&self) -> Vec<&'static ProviderTemplate> {
        let catalog = onboarding_catalog();
        filter_catalog(&catalog, self.query.text())
    }

    /// The template under the keyboard cursor, if the filtered list is
    /// non-empty. The reference is the canonical registry entry: filtering
    /// cannot change what a selection resolves to.
    pub(crate) fn selected_template(&self) -> Option<&'static ProviderTemplate> {
        self.filtered().get(self.cursor).copied()
    }

    /// Clamp cursor and viewport to the current filtered list. Called after
    /// every key move, pointer selection, and viewport resize observation
    /// so the two indices can never dangle past the list. Query edits use
    /// [`Self::remap_selection`] instead: an index clamp alone can move the
    /// cursor onto a *different* template when the list shrinks around it.
    fn clamp(&mut self) {
        let len = self.filtered().len();
        self.cursor = self.cursor.min(len.saturating_sub(1));
        let capacity = self.viewport_capacity.max(1);
        self.offset = self.offset.min(len.saturating_sub(capacity));
        if self.selection_started {
            if self.cursor < self.offset {
                self.offset = self.cursor;
            } else if self.cursor >= self.offset + capacity {
                self.offset = self.cursor + 1 - capacity;
            }
        }
    }

    fn clamp_viewport(&mut self) {
        let len = self.filtered().len();
        let capacity = self.viewport_capacity.max(1);
        self.cursor = self.cursor.min(len.saturating_sub(1));
        self.offset = self.offset.min(len.saturating_sub(capacity));
    }

    /// Re-anchor the cursor to the previously selected canonical template
    /// after a query edit. While the entry stays visible, the selected
    /// template id is unchanged by construction (the cursor is moved to the
    /// entry's new index); only when it no longer matches does the cursor
    /// fall back to an index clamp over the remaining rows.
    fn remap_selection(&mut self, previous: Option<&'static ProviderTemplate>) {
        if let Some(previous) = previous
            && let Some(index) = self
                .filtered()
                .iter()
                .position(|candidate| candidate.id == previous.id)
        {
            self.cursor = index;
        } else {
            self.cursor = self.cursor.min(self.filtered().len().saturating_sub(1));
        }
        self.clamp();
    }

    /// A filter edit re-anchors the cursor to the previously selected
    /// canonical template (see [`Self::remap_selection`]); movement keys
    /// re-clamp, and Enter resolves the cursor's canonical registry entry.
    pub(crate) fn handle_key(&mut self, key: KeyEvent) -> Option<&'static ProviderTemplate> {
        match key.code {
            KeyCode::Down | KeyCode::Tab => {
                self.selection_started = true;
                let len = self.filtered().len();
                self.cursor = crate::tui::nav::wrap_next(self.cursor, len);
                self.status = None;
                self.clamp();
            }
            KeyCode::Up | KeyCode::BackTab => {
                self.selection_started = true;
                let len = self.filtered().len();
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, len);
                self.status = None;
                self.clamp();
            }
            KeyCode::PageDown => {
                self.selection_started = true;
                let capacity = self.viewport_capacity.max(1);
                self.cursor = (self.cursor + capacity).min(self.filtered().len().saturating_sub(1));
                self.clamp();
            }
            KeyCode::PageUp => {
                self.selection_started = true;
                let capacity = self.viewport_capacity.max(1);
                self.cursor = self.cursor.saturating_sub(capacity);
                self.clamp();
            }
            KeyCode::Enter => {
                return self.activate_focused();
            }
            _ => {
                let previous = self.selected_template();
                if self.query.handle_key(key) {
                    self.status = None;
                    self.remap_selection(previous);
                }
            }
        }
        None
    }

    /// Attempt to select `template`: disabled templates surface their reason
    /// and never produce a selection.
    fn activate(
        &mut self,
        template: Option<&'static ProviderTemplate>,
    ) -> Option<&'static ProviderTemplate> {
        let Some(template) = template else {
            self.status = Some("No provider matches this search.".to_string());
            return None;
        };
        if let Some(reason) = template.disabled_reason() {
            self.status = Some(reason.to_string());
            return None;
        }
        Some(template)
    }

    /// Pointer handling for the list body. Returns the activated template
    /// when a left click lands on a row (disabled rows only move the
    /// cursor and surface their reason).
    pub(crate) fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        row_rects: &[Rect],
    ) -> Option<&'static ProviderTemplate> {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left)
                if self
                    .scrollbar_area
                    .contains((mouse.column, mouse.row).into()) =>
            {
                self.dragging_scrollbar = true;
                self.drag_scrollbar(mouse.row);
                None
            }
            MouseEventKind::Drag(MouseButton::Left) if self.dragging_scrollbar => {
                self.drag_scrollbar(mouse.row);
                None
            }
            MouseEventKind::Up(MouseButton::Left) => {
                self.dragging_scrollbar = false;
                None
            }
            MouseEventKind::ScrollUp => {
                self.offset = self.offset.saturating_sub(1);
                self.clamp_viewport();
                None
            }
            MouseEventKind::ScrollDown => {
                let len = self.filtered().len();
                let capacity = self.viewport_capacity.max(1);
                let max_offset = len.saturating_sub(capacity);
                if self.offset < max_offset {
                    self.offset += 1;
                }
                self.clamp_viewport();
                None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let index = row_rects
                    .iter()
                    .position(|rect| rect.contains((mouse.column, mouse.row).into()))?;
                let next = self.offset + index;
                if self.selection_started && self.cursor == next {
                    self.status = None;
                    self.activate(self.selected_template())
                } else {
                    self.cursor = next;
                    self.selection_started = true;
                    self.status = None;
                    None
                }
            }
            _ => None,
        }
    }

    fn drag_scrollbar(&mut self, row: u16) {
        let len = self.filtered().len();
        let capacity = self.viewport_capacity.max(1);
        let max_offset = len.saturating_sub(capacity);
        if self.scrollbar_area.height <= 1 || max_offset == 0 {
            self.offset = 0;
            return;
        }
        let relative = row
            .saturating_sub(self.scrollbar_area.y)
            .min(self.scrollbar_area.height - 1) as usize;
        self.offset = relative * max_offset / usize::from(self.scrollbar_area.height - 1);
        self.clamp_viewport();
    }

    pub(crate) fn set_scrollbar_area(&mut self, area: Rect) {
        self.scrollbar_area = area;
        if area.is_empty() {
            self.dragging_scrollbar = false;
        }
    }

    pub(crate) fn dragging_scrollbar(&self) -> bool {
        self.dragging_scrollbar
    }

    #[cfg(test)]
    pub(crate) fn scrollbar_area(&self) -> Rect {
        self.scrollbar_area
    }

    pub(crate) fn choose_enabled(&self) -> bool {
        self.selection_started
            && self
                .selected_template()
                .is_some_and(|template| !template.is_disabled())
    }

    pub(crate) fn selected_detail(&self) -> Option<Vec<Line<'static>>> {
        if !self.selection_started {
            return None;
        }
        let template = self.selected_template()?;
        let auth = match template.auth {
            cockpit_config::providers::AuthKind::ApiKey => "API key",
            cockpit_config::providers::AuthKind::OAuth => "OAuth login",
            cockpit_config::providers::AuthKind::Command => "auth command",
            cockpit_config::providers::AuthKind::None => "no authentication",
        };
        let mut lines = vec![Line::from(vec![
            Span::styled(auth, Style::default().fg(BRASS)),
            Span::styled("  ·  ", Style::default().fg(FOG)),
            Span::styled(template.id.to_string(), Style::default().fg(FOG)),
        ])];
        if let Some(hint) = template.hint {
            lines.push(Line::from(Span::styled(
                hint.to_string(),
                Style::default().fg(FOG),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                template.url.to_string(),
                Style::default().fg(FOG),
            )));
        }
        Some(lines)
    }

    /// Record the rendered row capacity so scrolling and clamping track the
    /// live terminal size (resize-safe).
    pub(crate) fn observe_viewport(&mut self, capacity: usize) {
        self.viewport_capacity = capacity;
        self.clamp();
    }

    /// Rows to render for `capacity` visible rows.
    pub(crate) fn visible_rows(&self, capacity: usize) -> Vec<ProviderRow<'static>> {
        self.filtered()
            .iter()
            .enumerate()
            .skip(self.offset)
            .take(capacity)
            .map(|(index, template)| ProviderRow {
                template,
                selected: self.selection_started && index == self.cursor,
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    #[cfg(test)]
    pub(crate) fn cursor(&self) -> usize {
        self.cursor
    }

    /// Render one catalog row.
    pub(crate) fn render_row(&self, row: &ProviderRow<'_>) -> Line<'static> {
        let template = row.template;
        let marker = if row.selected { "› " } else { "  " };
        let auth = match template.auth {
            cockpit_config::providers::AuthKind::ApiKey => "API key",
            cockpit_config::providers::AuthKind::OAuth => "OAuth login",
            cockpit_config::providers::AuthKind::Command => "auth command",
            cockpit_config::providers::AuthKind::None => "no auth",
        };
        let disabled = template.is_disabled();
        let label_style = if disabled {
            Style::default().fg(FOG)
        } else if row.selected {
            Style::default().fg(BRASS).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(INK)
        };
        let mut spans = vec![
            Span::raw(marker),
            Span::styled(template.display_label().into_owned(), label_style),
            Span::raw("  "),
            Span::styled(format!("({auth})"), Style::default().fg(FOG)),
        ];
        if disabled {
            spans.push(Span::styled(
                "  — unavailable in this build",
                Style::default().fg(FOG),
            ));
        }
        Line::from(spans)
    }

    /// Paste into the query field. The cursor re-anchors to the previously
    /// selected canonical template like any other query edit.
    pub(crate) fn paste_query(&mut self, text: &str) {
        let previous = self.selected_template();
        self.query.paste(text);
        self.status = None;
        self.remap_selection(previous);
    }

    /// Help text under the list.
    pub(crate) fn help_text(&self) -> &'static str {
        "type to filter   ↑↓ move   click select · dbl-click choose   enter choose   esc back"
    }

    /// Muted status paragraph, when present.
    pub(crate) fn status_paragraph(&self) -> Option<Paragraph<'static>> {
        self.status.as_ref().map(|status| {
            Paragraph::new(Line::from(Span::styled(
                status.clone(),
                Style::default().fg(super::theme::BAD),
            )))
        })
    }
}
