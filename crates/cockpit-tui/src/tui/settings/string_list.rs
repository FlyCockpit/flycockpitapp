//! Generic grab/reorder string-list editor drilled into from the category
//! pages (implementation note).
//!
//! Four `Vec`-shaped config fields share one editor here, distinguished by
//! [`StringListKind`]:
//!   - `agent_dirs` (extra agent-definition directories) → Behavior,
//!   - `redact.extra_dotenv_paths` (extra env files to scan) → Privacy,
//!   - `redact.denylist` (always-redact literals) → Privacy / Advanced,
//!   - `redact.allowlist` (env vars exempt from redaction) → Privacy /
//!     Advanced.
//!
//! The interaction model is the same grab/rename/reorder one the
//! Instructions and Environment-File-Patterns sub-pages use: `a` or Enter on
//! `[+ add]` appends a row and grabs it; while grabbed, typing edits the
//! value and ↑/↓ reorder; Enter commits (an empty value deletes the row),
//! Esc reverts both text and position; `d` deletes a row in browse mode.
//! Each commit/delete persists `config.json`.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

use crate::tui::theme::MUTED_COLOR_INDEX;

use super::grab;
use super::pointer_actions::{ListAction, ListKind, ListRowId, SettingsPointerAction};
use super::secret_display;
use super::shell::{
    SettingsPointerTarget, SettingsScrollRegionId, push_wrapped_text, selected_line_from_marker,
};
use super::ui_page::GrabState;
use super::{Nav, RowDeleteConfirm, SettingsCx, SettingsPage, save_status};

/// Which config list this editor is bound to. Each variant names its
/// back-target category (so Esc/h lands on the page it was drilled from),
/// its title, and a one-line intro.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum StringListKind {
    AgentDirs,
    ExtraDotenvPaths,
    RedactDenylist,
    RedactAllowlist,
    GitignoreAllow,
}

impl StringListKind {
    fn title(self) -> &'static str {
        match self {
            StringListKind::AgentDirs => "Agent Directories",
            StringListKind::ExtraDotenvPaths => "Extra Environment Files",
            StringListKind::RedactDenylist => "Always-Redact Denylist",
            StringListKind::RedactAllowlist => "Environment Variable Allowlist",
            StringListKind::GitignoreAllow => "Gitignore Read Allowlist",
        }
    }

    fn crumb(self) -> &'static str {
        self.title()
    }

    fn intro(self) -> &'static str {
        match self {
            StringListKind::AgentDirs => {
                "Extra directories searched for agent-definition files, on top of \
                 the built-in locations. Paths are tilde-expanded."
            }
            StringListKind::ExtraDotenvPaths => {
                "Explicit env-file paths scanned for secrets in addition to the \
                 glob patterns. Each file's format is auto-detected and its values \
                 added to the redaction table."
            }
            StringListKind::RedactDenylist => {
                "Literal values that must ALWAYS be redacted, even if shorter than \
                 the minimum length or from an allowlisted variable. \
                 Security-sensitive: everything here is scrubbed everywhere."
            }
            StringListKind::RedactAllowlist => {
                "Environment-variable names to EXCLUDE from redaction, on top of \
                 the built-in allowlist. Security-sensitive: an allowlisted var's \
                 value reaches the provider unredacted."
            }
            StringListKind::GitignoreAllow => {
                "Gitignore-style globs that re-permit otherwise-gitignored paths for \
                 the agent's read tools (e.g. allow `target/` while `.env` stays \
                 blocked). Allowed paths also reappear in file search and the @-tag \
                 popup. Saved to this project's config."
            }
        }
    }

    /// The placeholder hint while a freshly-added row is empty.
    fn empty_hint(self) -> &'static str {
        match self {
            StringListKind::AgentDirs | StringListKind::ExtraDotenvPaths => "  (type path)",
            StringListKind::RedactDenylist => "  (type replacement)",
            StringListKind::RedactAllowlist => "  (type variable name)",
            StringListKind::GitignoreAllow => "  (type glob, e.g. target/)",
        }
    }
}

/// Grab/reorder editor state for one config list.
pub(super) struct StringListPage {
    pub(super) kind: StringListKind,
    pub(super) cursor: usize,
    pub(super) grabbed: Option<GrabState>,
    pub(super) status: Option<String>,
    pub(super) delete: RowDeleteConfirm,
}

impl StringListPage {
    fn new(kind: StringListKind) -> Self {
        Self {
            kind,
            cursor: 0,
            grabbed: None,
            status: None,
            delete: RowDeleteConfirm::default(),
        }
    }

    pub(super) fn agent_dirs() -> Self {
        Self::new(StringListKind::AgentDirs)
    }
    pub(super) fn extra_dotenv_paths() -> Self {
        Self::new(StringListKind::ExtraDotenvPaths)
    }
    pub(super) fn redact_denylist() -> Self {
        Self::new(StringListKind::RedactDenylist)
    }
    pub(super) fn redact_allowlist() -> Self {
        Self::new(StringListKind::RedactAllowlist)
    }
    pub(super) fn gitignore_allow() -> Self {
        Self::new(StringListKind::GitignoreAllow)
    }

    pub(super) fn crumb(&self) -> &'static str {
        self.kind.crumb()
    }
}

fn string_list_display_value(kind: StringListKind, index: usize, value: &str) -> String {
    if kind == StringListKind::RedactDenylist && !value.trim().is_empty() {
        secret_display::masked_list_item(index)
    } else {
        value.to_string()
    }
}

fn string_list_existing_grab(kind: StringListKind, value: String, origin: usize) -> GrabState {
    if kind == StringListKind::RedactDenylist {
        let mut grabbed = GrabState::existing(value, origin);
        grabbed.buf.set("");
        grabbed
    } else {
        GrabState::existing(value, origin)
    }
}

impl SettingsCx {
    /// Read the current list for `kind` as owned strings (paths render via
    /// `display()`).
    fn string_list_values(&self, kind: StringListKind) -> Vec<String> {
        match kind {
            StringListKind::AgentDirs => self
                .extended
                .agent_dirs
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            StringListKind::ExtraDotenvPaths => self
                .extended
                .redact
                .extra_dotenv_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            StringListKind::RedactDenylist => self.extended.redact.denylist.clone(),
            StringListKind::RedactAllowlist => self.extended.redact.allowlist.clone(),
            StringListKind::GitignoreAllow => self.extended.gitignore_allow.clone(),
        }
    }

    fn string_list_len(&self, kind: StringListKind) -> usize {
        match kind {
            StringListKind::AgentDirs => self.extended.agent_dirs.len(),
            StringListKind::ExtraDotenvPaths => self.extended.redact.extra_dotenv_paths.len(),
            StringListKind::RedactDenylist => self.extended.redact.denylist.len(),
            StringListKind::RedactAllowlist => self.extended.redact.allowlist.len(),
            StringListKind::GitignoreAllow => self.extended.gitignore_allow.len(),
        }
    }

    fn string_list_push_empty(&mut self, kind: StringListKind) {
        match kind {
            StringListKind::AgentDirs => self.extended.agent_dirs.push(Default::default()),
            StringListKind::ExtraDotenvPaths => self
                .extended
                .redact
                .extra_dotenv_paths
                .push(Default::default()),
            StringListKind::RedactDenylist => self.extended.redact.denylist.push(String::new()),
            StringListKind::RedactAllowlist => self.extended.redact.allowlist.push(String::new()),
            StringListKind::GitignoreAllow => self.extended.gitignore_allow.push(String::new()),
        }
    }

    fn string_list_remove(&mut self, kind: StringListKind, idx: usize) {
        match kind {
            StringListKind::AgentDirs => {
                if idx < self.extended.agent_dirs.len() {
                    self.extended.agent_dirs.remove(idx);
                }
            }
            StringListKind::ExtraDotenvPaths => {
                if idx < self.extended.redact.extra_dotenv_paths.len() {
                    self.extended.redact.extra_dotenv_paths.remove(idx);
                }
            }
            StringListKind::RedactDenylist => {
                if idx < self.extended.redact.denylist.len() {
                    self.extended.redact.denylist.remove(idx);
                }
            }
            StringListKind::RedactAllowlist => {
                if idx < self.extended.redact.allowlist.len() {
                    self.extended.redact.allowlist.remove(idx);
                }
            }
            StringListKind::GitignoreAllow => {
                if idx < self.extended.gitignore_allow.len() {
                    self.extended.gitignore_allow.remove(idx);
                }
            }
        }
    }

    fn string_list_swap(&mut self, kind: StringListKind, a: usize, b: usize) {
        match kind {
            StringListKind::AgentDirs => self.extended.agent_dirs.swap(a, b),
            StringListKind::ExtraDotenvPaths => self.extended.redact.extra_dotenv_paths.swap(a, b),
            StringListKind::RedactDenylist => self.extended.redact.denylist.swap(a, b),
            StringListKind::RedactAllowlist => self.extended.redact.allowlist.swap(a, b),
            StringListKind::GitignoreAllow => self.extended.gitignore_allow.swap(a, b),
        }
    }

    /// Set element `idx` from a committed buffer value (paths parse via
    /// `PathBuf::from`).
    fn string_list_set(&mut self, kind: StringListKind, idx: usize, value: String) {
        match kind {
            StringListKind::AgentDirs => {
                if let Some(slot) = self.extended.agent_dirs.get_mut(idx) {
                    *slot = std::path::PathBuf::from(value);
                }
            }
            StringListKind::ExtraDotenvPaths => {
                if let Some(slot) = self.extended.redact.extra_dotenv_paths.get_mut(idx) {
                    *slot = std::path::PathBuf::from(value);
                }
            }
            StringListKind::RedactDenylist => {
                if let Some(slot) = self.extended.redact.denylist.get_mut(idx) {
                    *slot = value;
                }
            }
            StringListKind::RedactAllowlist => {
                if let Some(slot) = self.extended.redact.allowlist.get_mut(idx) {
                    *slot = value;
                }
            }
            StringListKind::GitignoreAllow => {
                if let Some(slot) = self.extended.gitignore_allow.get_mut(idx) {
                    *slot = value;
                }
            }
        }
    }

    // `/gitignore-allow` opens this list after reloading extended config,
    // mirroring category entry so rows reflect on-disk state.
    /// Quick-add `glob` to the project gitignore allowlist and persist, then
    /// open the editor (`/gitignore-allow <glob>`). A blank/duplicate glob is
    /// a no-op add; the editor still opens.
    pub(super) fn quick_add_gitignore_allow(&mut self, glob: &str) {
        let glob = glob.trim();
        if !glob.is_empty() && !self.extended.gitignore_allow.iter().any(|g| g == glob) {
            self.extended.gitignore_allow.push(glob.to_string());
            match self.save_extended() {
                Ok(super::SettingsSaveOutcome::Saved | super::SettingsSaveOutcome::Queued) => {}
                Ok(super::SettingsSaveOutcome::CommittedRefreshNeeded(warning)) | Err(warning) => {
                    self.extended_warnings = vec![warning];
                }
            }
        }
    }

    fn handle_string_list_page_key(&mut self, key: KeyEvent, p: &mut StringListPage) -> Nav {
        let kind = p.kind;
        // ── Grab mode ───────────────────────────────────────────────
        if p.grabbed.is_some() {
            match key.code {
                KeyCode::Enter => self.commit_string_list_grab(p),
                KeyCode::Esc => {
                    p.delete.disarm();
                    self.cancel_string_list_grab(p);
                }
                KeyCode::Up if p.cursor > 0 => {
                    p.delete.disarm();
                    self.string_list_swap(kind, p.cursor, p.cursor - 1);
                    p.cursor -= 1;
                }
                KeyCode::Down if p.cursor + 1 < self.string_list_len(kind) => {
                    p.delete.disarm();
                    self.string_list_swap(kind, p.cursor, p.cursor + 1);
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

        let rows = self.string_list_len(kind);
        let nav_len = rows + 1; // + the synthetic `[+ add]` row
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                p.delete.disarm();
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, nav_len);
                p.delete.disarm();
                p.status = None;
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.cursor = crate::tui::nav::wrap_next(p.cursor, nav_len);
                p.delete.disarm();
                p.status = None;
            }
            KeyCode::Char('a') => {
                p.delete.disarm();
                self.start_string_list_grab_on_new(p);
            }
            KeyCode::Char('d') | KeyCode::Delete if p.cursor < rows => {
                p.delete.disarm();
                self.string_list_remove(kind, p.cursor);
                let total = self.string_list_len(kind);
                p.cursor = p.cursor.min(total.saturating_sub(1));
                p.status = save_status(self.save_extended());
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                p.delete.disarm();
                if p.cursor < rows {
                    let cur = self.string_list_values(kind)[p.cursor].clone();
                    p.grabbed = Some(string_list_existing_grab(kind, cur, p.cursor));
                    p.status = None;
                } else if p.cursor == rows {
                    self.start_string_list_grab_on_new(p);
                }
            }
            _ => {
                p.delete.disarm();
                p.status = None;
            }
        }
        Nav::Stay
    }

    fn start_string_list_grab_on_new(&mut self, p: &mut StringListPage) {
        self.string_list_push_empty(p.kind);
        p.delete.disarm();
        let idx = self.string_list_len(p.kind) - 1;
        p.cursor = idx;
        p.grabbed = Some(GrabState::fresh(idx));
        p.status = None;
    }

    fn commit_string_list_grab(&mut self, p: &mut StringListPage) {
        let Some(g) = p.grabbed.take() else { return };
        p.delete.disarm();
        let trimmed = g.buf.text().trim().to_string();
        if trimmed.is_empty() {
            if p.kind == StringListKind::RedactDenylist && g.original_name.is_some() {
                if let Some(original) = g.original_name {
                    self.string_list_set(p.kind, p.cursor, original);
                }
            } else {
                self.string_list_remove(p.kind, p.cursor);
            }
        } else {
            self.string_list_set(p.kind, p.cursor, trimmed);
        }
        let total = self.string_list_len(p.kind);
        p.cursor = if total == 0 {
            0
        } else {
            p.cursor.min(total - 1)
        };
        p.status = save_status(self.save_extended());
    }

    fn cancel_string_list_grab(&mut self, p: &mut StringListPage) {
        let Some(g) = p.grabbed.take() else { return };
        p.delete.disarm();
        match g.original_name {
            Some(name) => {
                self.string_list_set(p.kind, p.cursor, name);
                let target = g.origin.min(self.string_list_len(p.kind).saturating_sub(1));
                while p.cursor > target {
                    self.string_list_swap(p.kind, p.cursor, p.cursor - 1);
                    p.cursor -= 1;
                }
                while p.cursor < target {
                    self.string_list_swap(p.kind, p.cursor, p.cursor + 1);
                    p.cursor += 1;
                }
            }
            None => {
                self.string_list_remove(p.kind, p.cursor);
                let total = self.string_list_len(p.kind);
                p.cursor = if total == 0 {
                    0
                } else {
                    p.cursor.min(total - 1)
                };
            }
        }
        p.status = None;
    }

    pub(super) fn render_string_list_page(
        &self,
        frame: &mut Frame,
        area: Rect,
        p: &StringListPage,
    ) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(Span::styled(
                p.kind.title().to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::default(),
        ];
        let mut controls = vec![None; lines.len()];
        let mut confirmation_lines = Vec::new();
        push_wrapped_text(&mut lines, area.width, p.kind.intro(), muted);
        controls.resize(lines.len(), None);
        lines.push(Line::default());
        controls.push(None);

        let values = self.string_list_values(p.kind);
        for (i, val) in values.iter().enumerate() {
            let is_grabbed = p.grabbed.is_some() && i == p.cursor;
            let on_cursor = i == p.cursor;
            if is_grabbed {
                lines.push(Line::from(grab::grabbed_row_spans(
                    p.grabbed.as_ref().unwrap().buf.text(),
                    p.grabbed.as_ref().unwrap().buf.cursor(),
                    p.kind.empty_hint(),
                )));
                // The row is already in edit/grab mode. Save and Cancel below
                // own its terminal pointer actions; publishing another Edit
                // identity here merely aliases Save and is especially
                // misleading for a newly-added empty row.
                controls.push(None);
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
                Span::styled(string_list_display_value(p.kind, i, val), style),
            ]));
            controls.push(Some((
                SettingsPointerAction::List(ListAction::Edit(string_list_row_id(p.kind, i, val))),
                true,
                None,
            )));
            let pending = p.delete.is_pending_for(i);
            let display = string_list_display_value(p.kind, i, val);
            lines.push(Line::from(if pending {
                format!("    Delete {display}? [Delete] [Cancel]")
            } else {
                format!("    [Delete {display}]")
            }));
            if pending {
                controls.push(None);
                confirmation_lines.push((
                    lines.len() - 1,
                    13 + display.as_str().width(),
                    string_list_row_id(p.kind, i, val),
                ));
            } else {
                controls.push(Some((
                    SettingsPointerAction::List(ListAction::Delete(string_list_row_id(
                        p.kind, i, val,
                    ))),
                    true,
                    None,
                )));
            }
        }

        if p.grabbed.is_none() {
            let add_idx = values.len();
            let add_selected = p.cursor == add_idx;
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
                Span::styled("[+ add]".to_string(), style),
            ]));
            controls.push(Some((
                SettingsPointerAction::List(ListAction::Add),
                true,
                None,
            )));
        }

        if p.grabbed.is_some() {
            lines.push(Line::default());
            controls.push(None);
            let can_up = p.cursor > 0;
            let can_down = p.cursor + 1 < values.len();
            lines.push(Line::from("[Move up]"));
            controls.push(Some((
                SettingsPointerAction::List(ListAction::MoveUp(string_list_row_id(
                    p.kind,
                    p.cursor,
                    &values[p.cursor],
                ))),
                can_up,
                (!can_up).then_some("already first"),
            )));
            lines.push(Line::from("[Move down]"));
            controls.push(Some((
                SettingsPointerAction::List(ListAction::MoveDown(string_list_row_id(
                    p.kind,
                    p.cursor,
                    &values[p.cursor],
                ))),
                can_down,
                (!can_down).then_some("already last"),
            )));
            lines.push(Line::from("[Save]"));
            controls.push(Some((
                SettingsPointerAction::List(ListAction::Save),
                true,
                None,
            )));
            lines.push(Line::from("[Cancel]"));
            controls.push(Some((
                SettingsPointerAction::List(ListAction::Cancel),
                true,
                None,
            )));
            lines.push(grab::grab_hint_line(grab::GRAB_HINT));
            controls.push(None);
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            controls.push(None);
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
            controls.push(None);
        }

        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_control_lines(
            frame,
            area,
            format!("string-list:{:?}", p.kind),
            (lines, selected_line),
            controls,
            (&self.pointer_surface, SettingsScrollRegionId("string-list")).into(),
        );
        let key = format!("string-list:{:?}", p.kind);
        let offset = self.scroll_states.offset_for(&key);
        for (line, delete_column, id) in confirmation_lines {
            if let Some(row) = line
                .checked_sub(offset)
                .filter(|row| *row < usize::from(area.height))
            {
                for (column, action) in [
                    (delete_column, ListAction::Delete(id.clone())),
                    (delete_column + 9, ListAction::Cancel),
                ] {
                    self.pointer_surface.register(SettingsPointerTarget {
                        rect: Rect::new(
                            area.x.saturating_add(column as u16),
                            area.y.saturating_add(row as u16),
                            8,
                            1,
                        ),
                        action: super::shell::SettingsPointerAction::Page(
                            SettingsPointerAction::List(action),
                        ),
                        enabled: true,
                        disabled_reason: None,
                    });
                }
            }
        }
    }
}

impl SettingsPage for StringListPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::StringList
    }

    fn pointer_surface_token(&self) -> u64 {
        500 + self.kind as u64 * 2 + u64::from(self.grabbed.is_some())
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        if self.grabbed.is_some() {
            super::SettingsLocalBack::LocalBack
        } else {
            super::SettingsLocalBack::NoLocalBack
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_string_list_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_string_list_page(frame, area, self);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        let SettingsPointerAction::List(action) = action else {
            return Nav::Stay;
        };
        if self.grabbed.is_some() {
            let key = match action {
                ListAction::MoveUp(id) if self.current_row_id(cx).as_ref() == Some(&id) => {
                    KeyCode::Up
                }
                ListAction::MoveDown(id) if self.current_row_id(cx).as_ref() == Some(&id) => {
                    KeyCode::Down
                }
                ListAction::Save => KeyCode::Enter,
                ListAction::Cancel => KeyCode::Esc,
                _ => return Nav::Stay,
            };
            return cx.handle_string_list_page_key(KeyEvent::new(key, KeyModifiers::NONE), self);
        }
        let values = cx.string_list_values(self.kind);
        let index =
            match action {
                ListAction::Add => values.len(),
                ListAction::Edit(id) => values
                    .iter()
                    .enumerate()
                    .position(|(index, value)| string_list_row_id(self.kind, index, value) == id)
                    .unwrap_or(values.len().saturating_add(1)),
                ListAction::Delete(id) => {
                    let Some(index) = values.iter().enumerate().position(|(index, value)| {
                        string_list_row_id(self.kind, index, value) == id
                    }) else {
                        return Nav::Stay;
                    };
                    self.cursor = index;
                    if self.delete.arm_or_confirm(index) {
                        cx.string_list_remove(self.kind, index);
                        self.cursor = index.min(cx.string_list_len(self.kind).saturating_sub(1));
                        self.status = save_status(cx.save_extended());
                    } else {
                        self.status = Some("confirm deletion or cancel".into());
                    }
                    return Nav::Stay;
                }
                ListAction::Cancel if self.delete.is_pending_for(self.cursor) => {
                    self.delete.disarm();
                    self.status = None;
                    return Nav::Stay;
                }
                _ => return Nav::Stay,
            };
        if index > values.len() {
            return Nav::Stay;
        }
        self.cursor = index;
        cx.handle_string_list_page_key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE), self)
    }

    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        region: SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region == SettingsScrollRegionId("string-list") && self.grabbed.is_none() {
            let last = cx.string_list_values(self.kind).len();
            self.delete.disarm();
            self.cursor = self.cursor.saturating_add_signed(delta).min(last);
        }
        Nav::Stay
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › {}",
            cockpit_core::welcome::display_path(&cx.config_path),
            self.crumb()
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        if self.grabbed.is_some() {
            "type to edit  ↑/↓: reorder  enter: drop & save  esc: cancel"
        } else {
            "↑/↓/Tab/Shift+Tab  a: add  enter: grab to edit/reorder  d: delete  esc/h: back  q: close"
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
        "StringList"
    }
}

fn string_list_row_id(kind: StringListKind, index: usize, value: &str) -> ListRowId {
    ListRowId {
        kind: ListKind::String(kind),
        index,
        value: value.into(),
    }
}

impl StringListPage {
    fn current_row_id(&self, cx: &SettingsCx) -> Option<ListRowId> {
        let values = cx.string_list_values(self.kind);
        values
            .get(self.cursor)
            .map(|value| string_list_row_id(self.kind, self.cursor, value))
    }
}
