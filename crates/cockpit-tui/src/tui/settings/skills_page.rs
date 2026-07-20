//! `/settings → Skills` page (GOALS §5).
//!
//! Edits `extended.skills`:
//!   - the **auto-`!`-command** toggle (`auto_bang_commands`) — Claude
//!     mode (run inline `` !`command` `` directives) vs Codex mode
//!     (inject verbatim; default).
//!   - the **scan-directory list** (`scan_dirs`) — add / edit / remove
//!     entries with the shared grab editor; unlike the Instructions page
//!     this grab is edit-only (no `↑`/`↓` reorder). Each entry supports
//!     `~`, `$VAR`, and relative paths.
//!
//! Layout: rows 0..[`TOGGLE_ROWS`] are the two toggles (auto-`!`, then
//! ancestor-walk); rows `TOGGLE_ROWS..=TOGGLE_ROWS+N-1` are the scan-dir
//! entries; the last row is the synthetic `[+ add directory]`. Toggling
//! and list edits both persist via `save_extended()`.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};

use crate::tui::textfield::TextField;
use crate::tui::theme::MUTED_COLOR_INDEX;

use super::grab;
use super::reset::{ResetButton, ResetOutcome};
use super::shell::{push_wrapped_text, selected_line_from_marker};
use super::{Nav, SettingsCx, SettingsPage, save_status};
#[cfg(test)]
use super::{Page, SettingsDialog, TestPageMut, TestPageRef};

/// Number of leading toggle rows before the scan-dir list: row 0 is the
/// auto-`!`-command toggle, row 1 is the ancestor-walk toggle.
const TOGGLE_ROWS: usize = 2;

/// `/settings → Skills` state. The grab editor mirrors the Instructions
/// page: while a scan-dir row is grabbed, typing edits it and Enter
/// commits / Esc reverts.
pub(super) struct SkillsPage {
    pub(super) cursor: usize,
    pub(super) grabbed: Option<GrabState>,
    pub(super) status: Option<String>,
    /// Page-level "reset to defaults" confirm state (the last navigable
    /// row, below the `[+ add directory]` synthetic row).
    pub(super) reset: ResetButton,
}

pub(super) struct GrabState {
    pub(super) buf: TextField,
    /// Original value; `Some` for existing rows (Esc restores it), `None`
    /// for a freshly-added row (Esc deletes it).
    pub(super) original: Option<String>,
}

impl SettingsCx {
    /// Toggles occupy cursors `0..TOGGLE_ROWS`; scan-dir rows occupy
    /// `TOGGLE_ROWS..TOGGLE_ROWS+len`; the `[+ add]` synthetic row is at
    /// `TOGGLE_ROWS + len`.
    fn handle_skills_page_key(&mut self, key: KeyEvent, p: &mut SkillsPage) -> Nav {
        // ── Grab mode: editing a scan-dir entry's text ──────────────
        if p.grabbed.is_some() {
            match key.code {
                KeyCode::Enter => self.commit_skills_grab(p),
                KeyCode::Esc => self.cancel_skills_grab(p),
                _ => {
                    if let Some(g) = p.grabbed.as_mut() {
                        g.buf.handle_key(key);
                    }
                }
            }
            return Nav::Stay;
        }

        let dir_count = self.extended.skills.scan_dirs.len();
        // Rows: 0,1 = toggles, TOGGLE_ROWS..TOGGLE_ROWS+dir_count =
        // entries, then the `[+ add]` synthetic row, then the
        // `[reset to defaults]` button (the last navigable index).
        let add_cursor = TOGGLE_ROWS + dir_count;
        let reset_cursor = add_cursor + 1;
        let nav_len = reset_cursor + 1;
        match key.code {
            KeyCode::Char('q') => return Nav::Close,
            KeyCode::Esc | KeyCode::Left | KeyCode::Backspace | KeyCode::Char('h') => {
                return Nav::Back;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_prev(p.cursor, nav_len);
            }
            KeyCode::Down | KeyCode::Char('j') => {
                p.reset.disarm();
                p.cursor = crate::tui::nav::wrap_next(p.cursor, nav_len);
            }
            KeyCode::Char('a') => {
                p.reset.disarm();
                self.start_skills_grab_on_new(p);
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                p.reset.disarm();
                if let Some(idx) = dir_index(p.cursor, dir_count) {
                    self.extended.skills.scan_dirs.remove(idx);
                    // Keep the cursor on a valid row.
                    let new_count = self.extended.skills.scan_dirs.len();
                    p.cursor = p.cursor.min(TOGGLE_ROWS + new_count);
                    p.status = save_status(self.save_extended());
                }
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                if p.cursor == reset_cursor {
                    // Page-level reset: arm on first activation, apply on
                    // the second.
                    if p.reset.activate() == ResetOutcome::Apply {
                        self.extended.skills =
                            cockpit_config::extended::SkillsConfig::seeded_default();
                        p.cursor = p
                            .cursor
                            .min(TOGGLE_ROWS + self.extended.skills.scan_dirs.len());
                        p.status = save_status(self.save_extended());
                    } else {
                        p.status = None;
                    }
                } else if p.cursor == 0 {
                    // Toggle auto-`!`.
                    self.extended.skills.auto_bang_commands =
                        !self.extended.skills.auto_bang_commands;
                    p.status = save_status(self.save_extended());
                } else if p.cursor == 1 {
                    // Toggle ancestor walk.
                    self.extended.skills.ancestor_walk = !self.extended.skills.ancestor_walk;
                    p.status = save_status(self.save_extended());
                } else if let Some(idx) = dir_index(p.cursor, dir_count) {
                    let cur = self.extended.skills.scan_dirs[idx].clone();
                    p.grabbed = Some(GrabState {
                        buf: TextField::new(cur.clone()),
                        original: Some(cur),
                    });
                    p.status = None;
                } else if p.cursor == add_cursor {
                    self.start_skills_grab_on_new(p);
                }
            }
            _ => {}
        }
        Nav::Stay
    }

    /// Append an empty scan-dir row, move the cursor to it, and grab it.
    fn start_skills_grab_on_new(&mut self, p: &mut SkillsPage) {
        self.extended.skills.scan_dirs.push(String::new());
        let idx = self.extended.skills.scan_dirs.len() - 1;
        p.cursor = idx + TOGGLE_ROWS; // skip the leading toggle rows
        p.grabbed = Some(GrabState {
            buf: TextField::default(),
            original: None,
        });
        p.status = None;
    }

    /// Drop the grabbed row, writing its buffer back. An empty trimmed
    /// value deletes the row instead.
    fn commit_skills_grab(&mut self, p: &mut SkillsPage) {
        let Some(g) = p.grabbed.take() else { return };
        let dir_count = self.extended.skills.scan_dirs.len();
        let Some(idx) = dir_index(p.cursor, dir_count) else {
            p.status = None;
            return;
        };
        let trimmed = g.buf.text().trim().to_string();
        if trimmed.is_empty() {
            self.extended.skills.scan_dirs.remove(idx);
        } else if let Some(slot) = self.extended.skills.scan_dirs.get_mut(idx) {
            *slot = trimmed;
        }
        let new_count = self.extended.skills.scan_dirs.len();
        p.cursor = p.cursor.min(TOGGLE_ROWS + new_count);
        p.status = save_status(self.save_extended());
    }

    /// Drop the grabbed row without saving: restore an existing row's
    /// original value, or remove a freshly-added row.
    fn cancel_skills_grab(&mut self, p: &mut SkillsPage) {
        let Some(g) = p.grabbed.take() else { return };
        let dir_count = self.extended.skills.scan_dirs.len();
        let idx = dir_index(p.cursor, dir_count);
        match g.original {
            Some(name) => {
                if let Some(i) = idx
                    && let Some(slot) = self.extended.skills.scan_dirs.get_mut(i)
                {
                    *slot = name;
                }
            }
            None => {
                if let Some(i) = idx {
                    self.extended.skills.scan_dirs.remove(i);
                }
            }
        }
        let new_count = self.extended.skills.scan_dirs.len();
        p.cursor = p.cursor.min(TOGGLE_ROWS + new_count);
        p.status = None;
    }

    pub(super) fn render_skills_page(&self, frame: &mut Frame, area: Rect, p: &SkillsPage) {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let yellow = Style::default().fg(Color::Yellow);
        let mut lines: Vec<Line<'static>> = vec![
            Line::from(Span::styled(
                "Skills".to_string(),
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::default(),
        ];
        push_wrapped_text(
            &mut lines,
            area.width,
            "Scan dirs hold `<name>/SKILL.md` skills. Entries support \
             `~`, `$VAR`, and relative paths. The list ships pre-seeded \
             (~/.agents/skills + ./.agents/skills); an empty list scans \
             nothing. Ancestor walk extends relative entries to every \
             dir up to the git root.",
            muted,
        );
        lines.push(Line::default());

        // Row 0: auto-`!` toggle.
        let toggle_on_cursor = p.cursor == 0;
        let toggle_marker = if toggle_on_cursor { "▸ " } else { "  " };
        let toggle_label_style = if toggle_on_cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let toggle_value = if self.extended.skills.auto_bang_commands {
            "Claude mode (run inline !`command`; output scrubbed)"
        } else {
            "Codex mode (default — inject !`command` verbatim; never runs)"
        };
        lines.push(Line::from(vec![
            Span::raw(toggle_marker),
            Span::styled("auto-! commands  ", toggle_label_style),
            Span::styled(toggle_value.to_string(), muted),
        ]));

        // Row 1: ancestor-walk toggle.
        let walk_on_cursor = p.cursor == 1;
        let walk_marker = if walk_on_cursor { "▸ " } else { "  " };
        let walk_label_style = if walk_on_cursor {
            yellow.add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let walk_value = if self.extended.skills.ancestor_walk {
            "on (relative entries also scan ancestors up to the git root)"
        } else {
            "off (default — relative entries resolve against cwd only)"
        };
        lines.push(Line::from(vec![
            Span::raw(walk_marker),
            Span::styled("ancestor walk    ", walk_label_style),
            Span::styled(walk_value.to_string(), muted),
        ]));

        lines.push(Line::default());
        lines.push(Line::from(Span::styled(
            "scan directories".to_string(),
            muted,
        )));

        for (i, dir) in self.extended.skills.scan_dirs.iter().enumerate() {
            let row_cursor = i + TOGGLE_ROWS; // skip the leading toggle rows
            let is_grabbed = p.grabbed.is_some() && row_cursor == p.cursor;
            let on_cursor = row_cursor == p.cursor;
            if is_grabbed {
                lines.push(Line::from(grab::grabbed_row_spans(
                    p.grabbed.as_ref().unwrap().buf.text(),
                    p.grabbed.as_ref().unwrap().buf.cursor(),
                    "  (type directory)",
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
                Span::styled(dir.clone(), style),
            ]));
        }

        // `[+ add directory]` row — hidden while a row is grabbed.
        if p.grabbed.is_none() {
            let add_idx = TOGGLE_ROWS + self.extended.skills.scan_dirs.len();
            let add_selected = p.cursor == add_idx;
            let marker = if add_selected { "▸ " } else { "  " };
            let style = if add_selected {
                yellow.add_modifier(Modifier::BOLD)
            } else {
                muted
            };
            lines.push(Line::from(vec![
                Span::raw(marker),
                Span::styled("[+ add directory]".to_string(), style),
            ]));

            // `[reset to defaults]` button — the last navigable row, just
            // below `[+ add directory]`. Hidden (like `[+ add]`) while a
            // row is grabbed.
            let reset_idx = TOGGLE_ROWS + self.extended.skills.scan_dirs.len() + 1;
            lines.push(
                p.reset
                    .render_line(p.cursor == reset_idx, "reset to defaults"),
            );
        }

        if p.grabbed.is_some() {
            lines.push(Line::default());
            lines.push(grab::grab_hint_line(grab::GRAB_HINT_EDIT));
        }

        if let Some(status) = &p.status {
            lines.push(Line::default());
            lines.push(Line::from(Span::styled(status.clone(), yellow)));
        }

        let selected_line = selected_line_from_marker(&lines);
        self.scroll_states
            .render_lines(frame, area, "skills", lines, selected_line);
    }
}

/// Map a page cursor to a `scan_dirs` index. Cursors `0..TOGGLE_ROWS` are
/// the toggles; the `[+ add]` synthetic row is past the end. Returns
/// `None` for all of those.
fn dir_index(cursor: usize, dir_count: usize) -> Option<usize> {
    let idx = cursor.checked_sub(TOGGLE_ROWS)?;
    if idx < dir_count { Some(idx) } else { None }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_config::extended::ExtendedConfigDoc;
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use tempfile::TempDir;

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    /// A genuinely fresh install: no `config.json` on disk yet — so
    /// [`SettingsDialog::open`] seeds the two default scan-dir entries. The
    /// first persist materializes the file. Tests that want an empty list
    /// clear it.
    fn fresh_skills_dialog(tmp: &TempDir) -> SettingsDialog {
        let path = tmp.path().join("config.json");
        let mut d = SettingsDialog::open(path);
        d.set_test_page(Page::Skills(SkillsPage {
            cursor: 0,
            grabbed: None,
            status: None,
            reset: ResetButton::default(),
        }));
        d
    }

    /// An existing on-disk `config.json` that has no `scan_dirs` — must NOT
    /// be re-seeded (clean break).
    fn existing_empty_skills_dialog(tmp: &TempDir) -> SettingsDialog {
        let path = tmp.path().join("config.json");
        std::fs::write(&path, "{}").unwrap();
        let mut d = SettingsDialog::open(path);
        d.set_test_page(Page::Skills(SkillsPage {
            cursor: 0,
            grabbed: None,
            status: None,
            reset: ResetButton::default(),
        }));
        d
    }

    #[test]
    fn fresh_install_seeds_two_entries() {
        let tmp = TempDir::new().unwrap();
        let d = fresh_skills_dialog(&tmp);
        assert_eq!(
            d.extended.skills.scan_dirs,
            vec![
                "~/.agents/skills".to_string(),
                "./.agents/skills".to_string()
            ],
            "a fresh install seeds the two default scan dirs"
        );
        assert!(
            !d.extended.skills.ancestor_walk,
            "ancestor walk defaults off"
        );
    }

    #[test]
    fn existing_empty_config_stays_empty() {
        let tmp = TempDir::new().unwrap();
        let d = existing_empty_skills_dialog(&tmp);
        assert!(
            d.extended.skills.scan_dirs.is_empty(),
            "an existing config with absent scan_dirs is not re-seeded"
        );
    }

    #[test]
    fn toggling_auto_bang_persists() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        assert!(
            !d.extended.skills.auto_bang_commands,
            "default is Codex mode"
        );
        // Cursor is at 0 (auto-! toggle). Enter flips it.
        d.handle_key(press(KeyCode::Enter));
        assert!(d.extended.skills.auto_bang_commands);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert!(
            reloaded.skills.auto_bang_commands,
            "toggle must persist to disk"
        );
    }

    #[test]
    fn toggling_ancestor_walk_persists() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        assert!(!d.extended.skills.ancestor_walk, "default off");
        // Move to row 1 (ancestor-walk toggle) and flip it.
        d.handle_key(press(KeyCode::Down));
        d.handle_key(press(KeyCode::Enter));
        assert!(d.extended.skills.ancestor_walk);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert!(
            reloaded.skills.ancestor_walk,
            "ancestor-walk toggle must persist to disk"
        );
    }

    #[test]
    fn add_edit_and_remove_scan_dir() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        // Start from an empty list to exercise add/remove cleanly.
        d.extended.skills.scan_dirs.clear();
        d.handle_key(press(KeyCode::Char('a')));
        match d.test_page() {
            TestPageRef::Skills(p) => assert!(p.grabbed.is_some(), "expected a grabbed new row"),
            other => panic!("expected Skills page, got {other:?}"),
        }
        for ch in "~/skills".chars() {
            d.handle_key(KeyEvent {
                code: KeyCode::Char(ch),
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            });
        }
        d.handle_key(press(KeyCode::Enter)); // commit
        assert_eq!(d.extended.skills.scan_dirs, vec!["~/skills".to_string()]);
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.skills.scan_dirs, vec!["~/skills".to_string()]);

        // Delete it: cursor is on the entry (first dir row = TOGGLE_ROWS).
        d.set_test_page(Page::Skills(SkillsPage {
            cursor: TOGGLE_ROWS,
            grabbed: None,
            status: None,
            reset: ResetButton::default(),
        }));
        d.handle_key(press(KeyCode::Char('d')));
        assert!(d.extended.skills.scan_dirs.is_empty());
        let reloaded2 = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert!(reloaded2.skills.scan_dirs.is_empty());
    }

    #[test]
    fn esc_on_fresh_row_removes_it() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        d.extended.skills.scan_dirs.clear();
        d.handle_key(press(KeyCode::Char('a')));
        d.handle_key(press(KeyCode::Esc));
        match d.test_page() {
            TestPageRef::Skills(p) => assert!(p.grabbed.is_none()),
            other => panic!("expected Skills page, got {other:?}"),
        }
        assert!(
            d.extended.skills.scan_dirs.is_empty(),
            "esc on a freshly-added row deletes it"
        );
    }

    #[test]
    fn esc_after_editing_existing_restores_value() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        d.extended.skills.scan_dirs = vec!["orig".into()];
        d.set_test_page(Page::Skills(SkillsPage {
            cursor: TOGGLE_ROWS, // first dir row
            grabbed: None,
            status: None,
            reset: ResetButton::default(),
        }));
        d.handle_key(press(KeyCode::Enter)); // grab existing
        for ch in "XYZ".chars() {
            d.handle_key(KeyEvent {
                code: KeyCode::Char(ch),
                modifiers: KeyModifiers::empty(),
                kind: KeyEventKind::Press,
                state: KeyEventState::empty(),
            });
        }
        d.handle_key(press(KeyCode::Esc));
        assert_eq!(
            d.extended.skills.scan_dirs,
            vec!["orig".to_string()],
            "esc restores the original value"
        );
    }

    #[test]
    fn dir_index_maps_correctly() {
        // Cursors 0,1 = toggles, no dir.
        assert_eq!(dir_index(0, 2), None);
        assert_eq!(dir_index(1, 2), None);
        // Cursor TOGGLE_ROWS = first dir.
        assert_eq!(dir_index(TOGGLE_ROWS, 2), Some(0));
        assert_eq!(dir_index(TOGGLE_ROWS + 1, 2), Some(1));
        // Cursor TOGGLE_ROWS + 2 = `[+ add]` synthetic row.
        assert_eq!(dir_index(TOGGLE_ROWS + 2, 2), None);
    }

    /// Place the cursor on the `[reset to defaults]` row for the current
    /// scan-dir count.
    fn put_on_reset_row(d: &mut SettingsDialog) {
        let reset_cursor = TOGGLE_ROWS + d.extended.skills.scan_dirs.len() + 1;
        if let TestPageMut::Skills(p) = d.test_page_mut() {
            p.cursor = reset_cursor;
        } else {
            panic!("expected Skills page");
        }
    }

    #[test]
    fn skills_reset_arms_then_restores_seeded_default() {
        use cockpit_config::extended::SkillsConfig;
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        // Diverge from the seeded default.
        d.extended.skills.scan_dirs = vec!["weird/dir".into()];
        d.extended.skills.ancestor_walk = true;
        d.extended.skills.auto_bang_commands = true;

        put_on_reset_row(&mut d);

        // First activation arms only.
        d.handle_key(press(KeyCode::Enter));
        match d.test_page() {
            TestPageRef::Skills(p) => assert!(p.reset.is_pending(), "first activation arms"),
            other => panic!("expected Skills, got {other:?}"),
        }
        assert_eq!(
            d.extended.skills.scan_dirs,
            vec!["weird/dir".to_string()],
            "arming must not mutate config"
        );

        // Second activation applies + saves.
        d.handle_key(press(KeyCode::Enter));
        match d.test_page() {
            TestPageRef::Skills(p) => assert!(!p.reset.is_pending(), "applying disarms"),
            other => panic!("expected Skills, got {other:?}"),
        }
        let want = SkillsConfig::seeded_default();
        assert_eq!(d.extended.skills.scan_dirs, want.scan_dirs);
        assert!(!d.extended.skills.ancestor_walk, "ancestor walk reset off");
        assert!(
            !d.extended.skills.auto_bang_commands,
            "auto-! reset to Codex mode"
        );
        // Persisted.
        let reloaded = ExtendedConfigDoc::load(&d.extended_path).unwrap().config();
        assert_eq!(reloaded.skills.scan_dirs, want.scan_dirs);
        assert!(!reloaded.skills.ancestor_walk);
    }

    #[test]
    fn skills_reset_pending_cancelled_by_navigation() {
        let tmp = TempDir::new().unwrap();
        let mut d = fresh_skills_dialog(&tmp);
        put_on_reset_row(&mut d);
        d.handle_key(press(KeyCode::Enter)); // arm
        match d.test_page() {
            TestPageRef::Skills(p) => assert!(p.reset.is_pending()),
            other => panic!("expected Skills, got {other:?}"),
        }
        d.handle_key(press(KeyCode::Up)); // navigate away
        match d.test_page() {
            TestPageRef::Skills(p) => assert!(!p.reset.is_pending(), "navigation disarms reset"),
            other => panic!("expected Skills, got {other:?}"),
        }
    }
}

impl SettingsPage for SkillsPage {
    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        cx.handle_skills_page_key(key, self)
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_skills_page(frame, area, self);
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › Skills",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        if self.grabbed.is_some() {
            "type to edit dir  enter: save  esc: cancel"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: toggle / edit  a: add dir  d: delete  esc/h: back  q: close"
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
        "Skills"
    }
}
