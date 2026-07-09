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

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::theme::MUTED_COLOR_INDEX;

use super::category::{Category, CategoryPage};
use super::grab;
use super::secret_display;
use super::shell::{push_wrapped_text, selected_line_from_marker};
use super::ui_page::GrabState;
use super::{Nav, Page, RowDeleteConfirm, SettingsDialog, save_status};

/// Which config list this editor is bound to. Each variant names its
/// back-target category (so Esc/h lands on the page it was drilled from),
/// its title, and a one-line intro.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
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

    /// The category page this editor returns to on back-nav.
    fn back_category(self) -> Category {
        match self {
            StringListKind::AgentDirs => Category::Behavior,
            StringListKind::ExtraDotenvPaths
            | StringListKind::RedactDenylist
            | StringListKind::RedactAllowlist
            | StringListKind::GitignoreAllow => Category::Privacy,
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

impl SettingsDialog {
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

    /// Open the dialog directly on the gitignore read-allowlist string-list
    /// editor (`/gitignore-allow`). Reloads the cached extended-config first
    /// so the rows reflect on-disk state, mirroring [`Self::enter_category`].
    pub(super) fn enter_gitignore_allow(&mut self) {
        self.reload_extended();
        self.page = Page::StringList(Box::new(StringListPage::gitignore_allow()));
    }

    /// Quick-add `glob` to the project gitignore allowlist and persist, then
    /// open the editor (`/gitignore-allow <glob>`). A blank/duplicate glob is
    /// a no-op add; the editor still opens.
    pub(super) fn quick_add_gitignore_allow(&mut self, glob: &str) {
        let glob = glob.trim();
        if !glob.is_empty() && !self.extended.gitignore_allow.iter().any(|g| g == glob) {
            self.extended.gitignore_allow.push(glob.to_string());
            let _ = self.save_extended();
        }
        self.enter_gitignore_allow();
    }

    pub(super) fn handle_string_list_key(&mut self, key: KeyEvent) -> bool {
        let kind = match &self.page {
            Page::StringList(p) => p.kind,
            _ => return false,
        };
        let placeholder = Page::StringList(Box::new(StringListPage::new(kind)));
        let mut page = std::mem::replace(&mut self.page, placeholder);
        let nav = if let Page::StringList(p) = &mut page {
            self.handle_string_list_page_key(key, p)
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
                return Nav::Replace(Page::Category(Box::new(CategoryPage::new(
                    kind.back_category(),
                ))));
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
                let label = string_list_display_value(
                    kind,
                    p.cursor,
                    &self.string_list_values(kind)[p.cursor],
                );
                if p.delete.arm_or_confirm(p.cursor) {
                    self.string_list_remove(kind, p.cursor);
                    let total = self.string_list_len(kind);
                    p.cursor = p.cursor.min(total.saturating_sub(1));
                    p.status = save_status(self.save_extended());
                } else {
                    p.status = Some(format!("press d/Delete again to delete `{label}`"));
                }
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
        push_wrapped_text(&mut lines, area.width, p.kind.intro(), muted);
        lines.push(Line::default());

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
        }

        if p.grabbed.is_some() {
            lines.push(Line::default());
            lines.push(grab::grab_hint_line(grab::GRAB_HINT));
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }

        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states.render_lines(
            frame,
            area,
            format!("string-list:{:?}", p.kind),
            lines,
            selected_line,
        );
    }
}
