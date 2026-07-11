//! `/permissions` pane — view and delete persisted tool approvals.
//!
//! Lists the grants recorded in the two *file* approval scopes —
//! **Project** (machine-local hashed-cwd `approvals.json`) and **Global**
//! (`~/.config/cockpit/approvals.json`) — grouped by scope and, within
//! each scope, by grant kind (commands, paths, loop always-accept, loop
//! always-reject). Session-scope grants live in SQLite and expire with the
//! session, so they are intentionally **not** shown here.
//!
//! The one mutating action is **delete**: the focused grant row, on the
//! delete/remove key, is dropped from its scope's `approvals.json` via
//! [`crate::approval::store::delete_managed_grant`], which reloads the file
//! and rewrites it atomically (the same load→mutate→store path the store
//! uses to *record* grants — so a concurrent edit to a different entry is
//! preserved, never clobbered). Removal takes effect on the next approval
//! check, which re-reads the file; no restart. There is no add, edit,
//! scope-change, or bulk-delete in v1 (low blast radius — per-grant only).
//!
//! Mirrors the read-only pane pattern ([`crate::tui::skills_pane`] /
//! [`crate::tui::permissions_pane`]): `open` / `handle_key` / `render` into the
//! chat body, Esc/`q` to dismiss. The grant collection + grouping and the
//! delete-the-focused-row logic are factored into pure helpers so they're
//! unit-testable without a terminal.

use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::approval::store::{
    ManagedGrantKind, ManagedGrants, delete_managed_grant, global_approvals_dir,
    list_managed_grants, project_approvals_dir,
};
use crate::tui::pane::{Pane, ScrollList};
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};

/// The two persisted *file* scopes the pane manages. Session scope is
/// deliberately excluded (it lives in SQLite and expires with the
/// session).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Project,
    Global,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::Project => "Project",
            Scope::Global => "Global",
        }
    }
}

/// One scope's approvals dir plus its loaded grants. The dir is the
/// directory *containing* `approvals.json`, so it feeds straight into the
/// store's load/delete helpers.
struct ScopeView {
    scope: Scope,
    /// The directory holding this scope's `approvals.json`, or `None` when
    /// the scope can't be resolved (cwd not in a git worktree → no project
    /// root; no home dir → no global dir). A `None` dir renders as an
    /// explicit "unavailable" note rather than a missing section.
    dir: Option<PathBuf>,
    grants: ManagedGrants,
}

/// One selectable, deletable grant row: which scope's dir to rewrite, the
/// bucket it lives in, and the entry key to drop. Resolved from the flat
/// row index so delete targets exactly the focused grant.
#[derive(Debug, Clone)]
struct DeletableRow {
    dir: PathBuf,
    kind: ManagedGrantKind,
    key: String,
}

pub struct PermissionsPane {
    scopes: Vec<ScopeView>,
    /// Cursor into the flat deletable-row list plus rendered-row scroll.
    list: ScrollList,
    /// A transient status line (e.g. "removed `gh pr`"), shown until the
    /// next key. Cleared on the next navigation.
    status: Option<String>,
    /// Rendered body height + total content rows at last draw — scroll clamp.
    last_body_height: usize,
    last_content_rows: usize,
}

impl PermissionsPane {
    /// Open the pane, loading project + global grants for `cwd`. Both
    /// scopes always appear (even when empty / unresolvable) so the user
    /// sees an explicit state per scope. Pure file reads — no daemon
    /// round-trip.
    pub fn open(cwd: &Path) -> Self {
        let project_dir = crate::git::find_worktree_root(cwd)
            .filter(|root| crate::config::trust::project_config_allowed(&root.join(".cockpit")))
            .and_then(|root| project_approvals_dir(&root));
        let global_dir = global_approvals_dir();
        let scopes = vec![
            load_scope(Scope::Project, project_dir),
            load_scope(Scope::Global, global_dir),
        ];
        Self {
            scopes,
            list: ScrollList::new(),
            status: None,
            last_body_height: 0,
            last_content_rows: 0,
        }
    }

    /// Handle a key. Returns `true` when the pane should close.
    /// The which-key descriptor for this pane (`crate::tui::keys_overlay`).
    /// Static + data-driven so the overlay never scrapes the help line.
    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Permissions",
            bindings: &[
                KeyBinding {
                    key: "↑/↓",
                    action: "move",
                    desc: "highlight a grant",
                },
                KeyBinding {
                    key: "d · Del",
                    action: "delete",
                    desc: "remove the highlighted grant",
                },
                KeyBinding {
                    key: "q · Esc",
                    action: "close",
                    desc: "close the pane",
                },
            ],
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => return true,
            KeyCode::Up | KeyCode::Char('k') => {
                self.status = None;
                self.move_cursor(-1);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.status = None;
                self.move_cursor(1);
            }
            // Delete the focused grant. `d`, Delete, and Backspace all bind
            // it (the conventional removal keys for a list).
            KeyCode::Char('d') | KeyCode::Delete | KeyCode::Backspace => self.delete_focused(),
            KeyCode::PageUp => {
                self.status = None;
                self.list.set_scroll(
                    self.list
                        .scroll()
                        .saturating_sub(self.last_body_height.max(1)),
                );
            }
            KeyCode::PageDown => {
                self.status = None;
                let max = self.last_content_rows.saturating_sub(self.last_body_height);
                self.list
                    .set_scroll((self.list.scroll() + self.last_body_height.max(1)).min(max));
            }
            _ => {}
        }
        false
    }

    pub fn scroll_up(&mut self) {
        self.list.set_scroll(self.list.scroll().saturating_sub(1));
    }

    pub fn scroll_down(&mut self) {
        let max = self.last_content_rows.saturating_sub(self.last_body_height);
        self.list.set_scroll((self.list.scroll() + 1).min(max));
    }

    /// The flat list of deletable rows in render order (scope-major, then
    /// kind, then sorted entries). The cursor indexes into this; the empty-
    /// state / heading lines are *not* selectable, so this is the single
    /// source of truth for "what does delete target".
    fn deletable_rows(&self) -> Vec<DeletableRow> {
        let mut rows = Vec::new();
        for sv in &self.scopes {
            let Some(dir) = &sv.dir else { continue };
            for kind in KIND_ORDER {
                for key in sv.grants.entries(kind) {
                    rows.push(DeletableRow {
                        dir: dir.clone(),
                        kind,
                        key: key.clone(),
                    });
                }
            }
        }
        rows
    }

    fn move_cursor(&mut self, delta: isize) {
        self.list.move_clamped(delta, self.deletable_rows().len());
    }

    /// Remove the focused grant from its backing JSON file. Reloads the
    /// in-memory scope view afterward so the listing reflects the write,
    /// and clamps the cursor (the row count shrank). No-op when nothing is
    /// selected.
    fn delete_focused(&mut self) {
        let rows = self.deletable_rows();
        let Some(row) = rows.get(self.list.cursor()).cloned() else {
            self.status = Some("Nothing to remove.".to_string());
            return;
        };
        match delete_managed_grant(&row.dir, row.kind, &row.key) {
            Ok(_) => {
                self.status = Some(format!("Removed `{}`.", row.key));
                self.reload();
                let count = self.deletable_rows().len();
                if count == 0 {
                    self.list.set_cursor(0);
                } else if self.list.cursor() >= count {
                    self.list.set_cursor(count - 1);
                }
            }
            Err(e) => self.status = Some(format!("Remove failed: {e}")),
        }
    }

    /// Re-read both scopes from disk (after a delete) so the pane shows the
    /// post-write state. A concurrent external edit is picked up here too.
    fn reload(&mut self) {
        for sv in &mut self.scopes {
            sv.grants = match &sv.dir {
                Some(dir) => list_managed_grants(dir),
                None => ManagedGrants::default(),
            };
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        let block = Block::default()
            .borders(Borders::ALL)
            .title(Line::from(" /permissions "));
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([Constraint::Min(0), Constraint::Length(1)]).split(inner);
        let body = layout[0];
        let help_area = layout[1];

        let lines = self.body_lines();
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        self.sync_scroll_to_focus();
        frame.render_widget(
            Paragraph::new(lines).scroll((self.list.scroll() as u16, 0)),
            body,
        );

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let help = match &self.status {
            Some(s) => s.clone(),
            None => "q quit  ↑/↓ move  d/del remove".to_string(),
        };
        frame.render_widget(
            Paragraph::new(Line::from(Span::styled(help, muted))),
            help_area,
        );
    }

    /// Assemble every body row as owned [`Line`]s. The highlighted grant
    /// (by flat row index) is rendered selected. Pure aside from reading
    /// `self`, so the grouping + empty-state are unit-testable without a
    /// terminal.
    fn body_lines(&self) -> Vec<Line<'static>> {
        let mut lines: Vec<Line<'static>> = Vec::new();
        // Running flat index of deletable rows, to match the cursor.
        let mut row_idx = 0usize;
        for (si, sv) in self.scopes.iter().enumerate() {
            if si > 0 {
                lines.push(Line::default());
            }
            lines.push(scope_heading(sv));

            let Some(_dir) = &sv.dir else {
                lines.push(unavailable_line(sv.scope));
                continue;
            };
            if sv.grants.is_empty() {
                lines.push(empty_scope_line());
                continue;
            }
            for kind in KIND_ORDER {
                let entries = sv.grants.entries(kind);
                if entries.is_empty() {
                    continue;
                }
                lines.push(kind_heading(kind));
                for key in entries {
                    let selected = row_idx == self.list.cursor();
                    lines.push(grant_row(key, selected));
                    row_idx += 1;
                }
            }
        }
        lines
    }

    /// Body-line index of the currently focused grant row (the cursor walks
    /// deletable rows, but headings/blanks also occupy body lines, so the
    /// flat cursor index and the body-line index differ). `None` when there
    /// are no deletable rows. Used to keep the focused row in view as ↑/↓
    /// move the cursor — without this a long grant list scrolls the focus off
    /// the bottom (same overflow class as the answering dialog).
    fn selected_line_index(&self) -> Option<usize> {
        let mut line_idx = 0usize;
        let mut row_idx = 0usize;
        for (si, sv) in self.scopes.iter().enumerate() {
            if si > 0 {
                line_idx += 1; // inter-scope blank
            }
            line_idx += 1; // scope heading
            if sv.dir.is_none() || sv.grants.is_empty() {
                line_idx += 1; // unavailable / empty line
                continue;
            }
            for kind in KIND_ORDER {
                let entries = sv.grants.entries(kind);
                if entries.is_empty() {
                    continue;
                }
                line_idx += 1; // kind heading
                for _ in entries {
                    if row_idx == self.list.cursor() {
                        return Some(line_idx);
                    }
                    line_idx += 1;
                    row_idx += 1;
                }
            }
        }
        None
    }

    /// Keep the focused grant row within the scroll window and clamp scroll to
    /// content (viewport-sync-before-render). ↑/↓ move the flat cursor, so
    /// scroll must follow it — without this a long grant list scrolls the
    /// focus off the bottom (same overflow class as the answering dialog).
    /// Uses `last_body_height` / `last_content_rows` measured this frame.
    fn sync_scroll_to_focus(&mut self) {
        if let Some(focus) = self.selected_line_index() {
            let vh = self.last_body_height.max(1);
            if focus < self.list.scroll() {
                self.list.set_scroll(focus);
            } else if focus >= self.list.scroll() + vh {
                self.list.set_scroll(focus + 1 - vh);
            }
        }
        let max_scroll = self.last_content_rows.saturating_sub(self.last_body_height);
        if self.list.scroll() > max_scroll {
            self.list.set_scroll(max_scroll);
        }
    }
}

impl Pane for PermissionsPane {
    type Outcome = bool;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        PermissionsPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        PermissionsPane::render(self, frame, area);
    }
}

/// The kind sections, in the order the pane renders (and the order the
/// flat row index walks) them.
const KIND_ORDER: [ManagedGrantKind; 4] = [
    ManagedGrantKind::Command,
    ManagedGrantKind::Path,
    ManagedGrantKind::LoopAccept,
    ManagedGrantKind::LoopReject,
];

fn load_scope(scope: Scope, dir: Option<PathBuf>) -> ScopeView {
    let grants = match &dir {
        Some(d) => list_managed_grants(d),
        None => ManagedGrants::default(),
    };
    ScopeView { scope, dir, grants }
}

// ---- pure render helpers ----------------------------------------------------

fn scope_heading(sv: &ScopeView) -> Line<'static> {
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let mut spans = vec![Span::styled(
        sv.scope.label().to_string(),
        Style::default()
            .fg(Color::Indexed(ACCENT_BLUE_INDEX))
            .add_modifier(Modifier::BOLD),
    )];
    if let Some(dir) = &sv.dir {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            dir.join("approvals.json").display().to_string(),
            muted,
        ));
    }
    Line::from(spans)
}

fn unavailable_line(scope: Scope) -> Line<'static> {
    let msg = match scope {
        Scope::Project => "  (no project root for the current directory)".to_string(),
        Scope::Global => "  (no user config directory available)".to_string(),
    };
    Line::from(Span::styled(
        msg,
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
    ))
}

fn empty_scope_line() -> Line<'static> {
    Line::from(Span::styled(
        "  No grants in this scope.".to_string(),
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
    ))
}

fn kind_heading(kind: ManagedGrantKind) -> Line<'static> {
    Line::from(Span::styled(
        format!("  {}", kind.label()),
        Style::default().fg(Color::Yellow),
    ))
}

fn grant_row(key: &str, selected: bool) -> Line<'static> {
    if selected {
        Line::from(vec![
            Span::styled(
                "  › ".to_string(),
                Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX)),
            ),
            Span::styled(
                key.to_string(),
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            ),
        ])
    } else {
        Line::from(vec![
            Span::raw("    "),
            Span::styled(key.to_string(), Style::default().fg(Color::White)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// Build a pane directly over two on-disk dirs, bypassing git/home
    /// resolution so the grouping + delete are exercised hermetically.
    fn pane_over(project: Option<PathBuf>, global: Option<PathBuf>) -> PermissionsPane {
        PermissionsPane {
            scopes: vec![
                load_scope(Scope::Project, project),
                load_scope(Scope::Global, global),
            ],
            list: ScrollList::new(),
            status: None,
            last_body_height: 100,
            last_content_rows: 0,
        }
    }

    fn write_grants(dir: &Path, grants: &ManagedGrants) {
        // Round-trip through the store's record path so the file shape is
        // production-accurate: use a real store pointed at this dir.
        std::fs::create_dir_all(dir).unwrap();
        let file = serde_json::json!({
            "commands": grants.commands,
            "paths": grants.paths,
            "loop_accept": grants.loop_accept,
            "loop_reject": grants.loop_reject,
        });
        std::fs::write(dir.join("approvals.json"), file.to_string()).unwrap();
    }

    fn grants(commands: &[&str], paths: &[&str]) -> ManagedGrants {
        ManagedGrants {
            commands: commands.iter().map(|s| s.to_string()).collect(),
            paths: paths.iter().map(|s| s.to_string()).collect(),
            loop_accept: Vec::new(),
            loop_reject: Vec::new(),
        }
    }

    fn render_text(pane: &PermissionsPane) -> String {
        pane.body_lines()
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|s| s.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn groups_by_scope_then_kind() {
        let proj = tempfile::tempdir().unwrap();
        let glob = tempfile::tempdir().unwrap();
        write_grants(proj.path(), &grants(&["gh pr"], &["/tmp/work"]));
        write_grants(glob.path(), &grants(&["cargo build"], &[]));
        let pane = pane_over(
            Some(proj.path().to_path_buf()),
            Some(glob.path().to_path_buf()),
        );
        let text = render_text(&pane);
        // Scope headings present, project before global.
        let p = text.find("Project").unwrap();
        let g = text.find("Global").unwrap();
        assert!(p < g, "project scope renders before global");
        // Kind sub-headings + entries.
        assert!(text.contains("Commands"));
        assert!(text.contains("gh pr"));
        assert!(text.contains("Paths"));
        assert!(text.contains("/tmp/work"));
        assert!(text.contains("cargo build"));
    }

    #[test]
    fn empty_scope_shows_explicit_state() {
        let proj = tempfile::tempdir().unwrap();
        let glob = tempfile::tempdir().unwrap();
        // Project has a grant; global is empty (no file).
        write_grants(proj.path(), &grants(&["ls"], &[]));
        let pane = pane_over(
            Some(proj.path().to_path_buf()),
            Some(glob.path().to_path_buf()),
        );
        let text = render_text(&pane);
        assert!(
            text.contains("No grants in this scope."),
            "empty scope is explicit"
        );
    }

    #[test]
    fn unresolved_scope_shows_unavailable_note() {
        // No project root resolvable → an explicit note, not a blank.
        let glob = tempfile::tempdir().unwrap();
        write_grants(glob.path(), &grants(&["ls"], &[]));
        let pane = pane_over(None, Some(glob.path().to_path_buf()));
        let text = render_text(&pane);
        assert!(
            text.contains("no project root"),
            "project scope marked unavailable"
        );
    }

    #[test]
    fn long_grant_list_keeps_focus_in_view() {
        // A long grant list with a small body window: moving the cursor down
        // past the window must scroll so the focused row stays visible.
        let proj = tempfile::tempdir().unwrap();
        let cmds: Vec<String> = (0..40).map(|i| format!("cmd-{i:02}")).collect();
        let refs: Vec<&str> = cmds.iter().map(|s| s.as_str()).collect();
        write_grants(proj.path(), &grants(&refs, &[]));
        let mut pane = pane_over(Some(proj.path().to_path_buf()), None);
        // Simulate a render measuring a tiny 6-row body.
        pane.last_content_rows = pane.body_lines().len();
        pane.last_body_height = 6;
        // Move the cursor well past the initial window, syncing each step like
        // the render loop does.
        for _ in 0..30 {
            pane.handle_key(press(KeyCode::Down));
            pane.sync_scroll_to_focus();
        }
        let focus = pane.selected_line_index().expect("a focused row");
        assert!(focus >= pane.list.scroll(), "focus above the window");
        assert!(
            focus < pane.list.scroll() + pane.last_body_height,
            "focus below the window (scroll={}, focus={focus})",
            pane.list.scroll()
        );
        assert!(pane.list.scroll() > 0, "list should have scrolled");
        // Moving back to the top brings the focus (and scroll) back up so the
        // first grant is visible again.
        for _ in 0..30 {
            pane.handle_key(press(KeyCode::Up));
            pane.sync_scroll_to_focus();
        }
        assert_eq!(pane.list.cursor(), 0);
        let focus = pane.selected_line_index().expect("a focused row");
        assert!(
            focus >= pane.list.scroll(),
            "focus above the window after scrolling up"
        );
        assert!(
            focus < pane.list.scroll() + pane.last_body_height,
            "focus visible after scrolling back up"
        );
    }

    #[test]
    fn esc_and_q_close() {
        let pane_keys = [KeyCode::Esc, KeyCode::Char('q')];
        for code in pane_keys {
            let mut pane = pane_over(None, None);
            assert!(pane.handle_key(press(code)));
        }
    }

    #[test]
    fn delete_removes_focused_row_from_backing_file() {
        let proj = tempfile::tempdir().unwrap();
        // Two commands; cursor starts at the first (sorted: "cargo build").
        write_grants(proj.path(), &grants(&["gh pr", "cargo build"], &[]));
        let mut pane = pane_over(Some(proj.path().to_path_buf()), None);
        // Sanity: sorted order puts "cargo build" first.
        let rows = pane.deletable_rows();
        assert_eq!(rows[0].key, "cargo build");
        assert_eq!(rows.len(), 2);

        pane.handle_key(press(KeyCode::Char('d')));
        // The focused grant is gone from the file...
        let after = list_managed_grants(proj.path());
        assert_eq!(after.commands, vec!["gh pr".to_string()]);
        // ...and from the in-memory view; the other remains.
        let text = render_text(&pane);
        assert!(text.contains("gh pr"));
        assert!(!text.contains("cargo build"));
        // Status reflects the removal.
        assert!(pane.status.as_deref().unwrap().contains("cargo build"));
    }

    #[test]
    fn delete_clamps_cursor_when_last_row_removed() {
        let proj = tempfile::tempdir().unwrap();
        write_grants(proj.path(), &grants(&["a", "b"], &[]));
        let mut pane = pane_over(Some(proj.path().to_path_buf()), None);
        // Move to the last row, delete it, cursor must clamp into range.
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.list.cursor(), 1);
        pane.handle_key(press(KeyCode::Delete));
        assert_eq!(
            pane.list.cursor(),
            0,
            "cursor clamps after deleting the last row"
        );
        assert_eq!(pane.deletable_rows().len(), 1);
    }

    #[test]
    fn delete_with_no_grants_is_noop() {
        let mut pane = pane_over(None, None);
        // Nothing selectable; delete just sets a status, never panics.
        pane.handle_key(press(KeyCode::Char('d')));
        assert!(pane.status.is_some());
    }
}
