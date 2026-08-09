use std::any::Any;
use std::path::{Path, PathBuf};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};

use crate::tui::textfield::TextField;
use cockpit_core::daemon::proto::{LspControlAction, Request};

use super::pointer_actions::{
    LspAction as PointerLspAction, LspEdit as PointerLspEdit, LspServerId, SettingsPointerAction,
};
use super::reset::{ResetButton, ResetOutcome};
use super::shell::{self, marker, muted_style, selected_or_field};
use super::{Nav, SettingsCx, SettingsPage, save_status};

pub(super) struct LspPage {
    pub(super) cursor: usize,
    pub(super) editing: Option<LspEdit>,
    pub(super) buf: TextField,
    pub(super) status: Option<String>,
    pub(super) reset: ResetButton,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LspEdit {
    OtherFilesLimit,
    PerFileLimit,
    DebounceMs,
    DocumentTimeoutMs,
    WorkspaceTimeoutMs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LspRow {
    Enabled,
    AutoInstall,
    Diagnostics,
    OtherFilesLimit,
    PerFileLimit,
    DebounceMs,
    DocumentTimeoutMs,
    WorkspaceTimeoutMs,
    Reset,
    Server(usize),
}

pub(super) const LSP_NAV_ROWS: [LspRow; 9] = [
    LspRow::Enabled,
    LspRow::AutoInstall,
    LspRow::Diagnostics,
    LspRow::OtherFilesLimit,
    LspRow::PerFileLimit,
    LspRow::DebounceMs,
    LspRow::DocumentTimeoutMs,
    LspRow::WorkspaceTimeoutMs,
    LspRow::Reset,
];

pub(super) const LSP_SERVER_ROW_START: usize = LSP_NAV_ROWS.len();

fn pointer_edit(edit: LspEdit) -> PointerLspEdit {
    match edit {
        LspEdit::OtherFilesLimit => PointerLspEdit::OtherFilesLimit,
        LspEdit::PerFileLimit => PointerLspEdit::PerFileLimit,
        LspEdit::DebounceMs => PointerLspEdit::DebounceMs,
        LspEdit::DocumentTimeoutMs => PointerLspEdit::DocumentTimeoutMs,
        LspEdit::WorkspaceTimeoutMs => PointerLspEdit::WorkspaceTimeoutMs,
    }
}

fn lsp_row_for_cursor(cursor: usize) -> LspRow {
    LSP_NAV_ROWS
        .get(cursor)
        .copied()
        .unwrap_or_else(|| LspRow::Server(cursor - LSP_SERVER_ROW_START))
}
impl SettingsPage for LspPage {
    fn pointer_surface_kind(&self) -> super::SettingsPointerSurfaceKind {
        super::SettingsPointerSurfaceKind::Lsp
    }

    fn resolve_header_back(&self) -> super::SettingsLocalBack {
        if self.editing.is_some() {
            super::SettingsLocalBack::LocalBack
        } else {
            super::SettingsLocalBack::NoLocalBack
        }
    }

    fn handle_key(&mut self, cx: &mut SettingsCx, key: KeyEvent) -> Nav {
        let row_count = LSP_SERVER_ROW_START
            + cx.project_context()
                .project_root()
                .map(|cwd| cockpit_core::daemon::lsp::builtin_server_views(cwd, &cx.extended).len())
                .unwrap_or(1);
        if let Some(edit) = self.editing {
            match key.code {
                KeyCode::Esc => {
                    self.editing = None;
                    self.buf = TextField::default();
                }
                KeyCode::Enter => {
                    let raw = self.buf.text().trim();
                    match raw.parse::<u64>() {
                        Ok(v) => {
                            match edit {
                                LspEdit::OtherFilesLimit => {
                                    cx.extended.lsp.diagnostics.other_files_limit = v as usize
                                }
                                LspEdit::PerFileLimit => {
                                    cx.extended.lsp.diagnostics.per_file_limit = v as usize
                                }
                                LspEdit::DebounceMs => cx.extended.lsp.diagnostics.debounce_ms = v,
                                LspEdit::DocumentTimeoutMs => {
                                    cx.extended.lsp.diagnostics.document_timeout_ms = v
                                }
                                LspEdit::WorkspaceTimeoutMs => {
                                    cx.extended.lsp.diagnostics.workspace_timeout_ms = v
                                }
                            }
                            self.status = save_status(cx.save_extended());
                            self.editing = None;
                            self.buf = TextField::default();
                        }
                        Err(_) => self.status = Some("enter a non-negative integer".into()),
                    }
                }
                _ => {
                    let _ = self.buf.handle_key(key);
                }
            }
            return Nav::Stay;
        }

        match key.code {
            KeyCode::Esc => {
                self.reset.disarm();
                Nav::Back
            }
            KeyCode::Char('h') | KeyCode::Left => {
                self.reset.disarm();
                Nav::Back
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.reset.disarm();
                self.cursor = crate::tui::nav::wrap_prev(self.cursor, row_count);
                Nav::Stay
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.reset.disarm();
                self.cursor = crate::tui::nav::wrap_next(self.cursor, row_count);
                Nav::Stay
            }
            KeyCode::Char('r') => {
                cx.activate_lsp_reset(self);
                Nav::Stay
            }
            KeyCode::Char('i') if self.cursor >= LSP_SERVER_ROW_START => {
                self.reset.disarm();
                cx.queue_lsp_action(
                    self.cursor - LSP_SERVER_ROW_START,
                    LspControlAction::Install,
                    self,
                );
                Nav::Stay
            }
            KeyCode::Char('u') if self.cursor >= LSP_SERVER_ROW_START => {
                self.reset.disarm();
                cx.queue_lsp_action(
                    self.cursor - LSP_SERVER_ROW_START,
                    LspControlAction::Uninstall,
                    self,
                );
                Nav::Stay
            }
            KeyCode::Char('R') if self.cursor >= LSP_SERVER_ROW_START => {
                self.reset.disarm();
                cx.queue_lsp_action(
                    self.cursor - LSP_SERVER_ROW_START,
                    LspControlAction::Restart,
                    self,
                );
                Nav::Stay
            }
            KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
                match lsp_row_for_cursor(self.cursor) {
                    LspRow::Enabled => {
                        self.reset.disarm();
                        cx.extended.lsp.enabled = !cx.extended.lsp.enabled;
                        self.status = save_status(cx.save_extended());
                    }
                    LspRow::AutoInstall => {
                        self.reset.disarm();
                        cx.extended.lsp.auto_install = cx.extended.lsp.auto_install.cycled();
                        self.status = save_status(cx.save_extended());
                    }
                    LspRow::Diagnostics => {
                        self.reset.disarm();
                        cx.extended.lsp.diagnostics.enabled = !cx.extended.lsp.diagnostics.enabled;
                        self.status = save_status(cx.save_extended());
                    }
                    LspRow::OtherFilesLimit => {
                        self.reset.disarm();
                        start_lsp_edit(
                            self,
                            LspEdit::OtherFilesLimit,
                            cx.extended.lsp.diagnostics.other_files_limit,
                        );
                    }
                    LspRow::PerFileLimit => {
                        self.reset.disarm();
                        start_lsp_edit(
                            self,
                            LspEdit::PerFileLimit,
                            cx.extended.lsp.diagnostics.per_file_limit,
                        );
                    }
                    LspRow::DebounceMs => {
                        self.reset.disarm();
                        start_lsp_edit(
                            self,
                            LspEdit::DebounceMs,
                            cx.extended.lsp.diagnostics.debounce_ms,
                        );
                    }
                    LspRow::DocumentTimeoutMs => {
                        self.reset.disarm();
                        start_lsp_edit(
                            self,
                            LspEdit::DocumentTimeoutMs,
                            cx.extended.lsp.diagnostics.document_timeout_ms,
                        );
                    }
                    LspRow::WorkspaceTimeoutMs => {
                        self.reset.disarm();
                        start_lsp_edit(
                            self,
                            LspEdit::WorkspaceTimeoutMs,
                            cx.extended.lsp.diagnostics.workspace_timeout_ms,
                        );
                    }
                    LspRow::Reset => cx.activate_lsp_reset(self),
                    LspRow::Server(idx) => {
                        self.reset.disarm();
                        cx.queue_lsp_action(idx, LspControlAction::Check, self);
                    }
                }
                Nav::Stay
            }
            _ => Nav::Stay,
        }
    }

    fn render(&self, cx: &SettingsCx, frame: &mut Frame, area: Rect) {
        cx.render_lsp_page(frame, area, self);
    }

    fn handle_pointer_control(
        &mut self,
        cx: &mut SettingsCx,
        action: SettingsPointerAction,
    ) -> Nav {
        let SettingsPointerAction::Lsp(action) = action else {
            return Nav::Stay;
        };
        let server_action = match &action {
            PointerLspAction::Check(id) => Some((id, LspControlAction::Check)),
            PointerLspAction::Install(id) => Some((id, LspControlAction::Install)),
            PointerLspAction::Uninstall(id) => Some((id, LspControlAction::Uninstall)),
            PointerLspAction::Restart(id) => Some((id, LspControlAction::Restart)),
            _ => None,
        };
        if let Some((LspServerId(id), control_action)) = server_action {
            let Some(cwd) = cx.project_context().project_root().cloned() else {
                return Nav::Stay;
            };
            let Some(server_idx) =
                cockpit_core::daemon::lsp::builtin_server_views(&cwd, &cx.extended)
                    .iter()
                    .position(|server| &server.id == id)
            else {
                return Nav::Stay;
            };
            self.cursor = LSP_SERVER_ROW_START + server_idx;
            self.reset.disarm();
            cx.queue_lsp_action(server_idx, control_action, self);
            return Nav::Stay;
        }
        let row_count = LSP_SERVER_ROW_START
            + cx.project_context()
                .project_root()
                .map(|cwd| cockpit_core::daemon::lsp::builtin_server_views(cwd, &cx.extended).len())
                .unwrap_or(1);
        let index = match action {
            PointerLspAction::ToggleEnabled => row_index(LspRow::Enabled),
            PointerLspAction::CycleAutoInstall => row_index(LspRow::AutoInstall),
            PointerLspAction::ToggleDiagnostics => row_index(LspRow::Diagnostics),
            PointerLspAction::Edit(edit) | PointerLspAction::SaveEdit(edit) => match edit {
                PointerLspEdit::OtherFilesLimit => row_index(LspRow::OtherFilesLimit),
                PointerLspEdit::PerFileLimit => row_index(LspRow::PerFileLimit),
                PointerLspEdit::DebounceMs => row_index(LspRow::DebounceMs),
                PointerLspEdit::DocumentTimeoutMs => row_index(LspRow::DocumentTimeoutMs),
                PointerLspEdit::WorkspaceTimeoutMs => row_index(LspRow::WorkspaceTimeoutMs),
            },
            PointerLspAction::CancelEdit(edit) => {
                if self.editing.map(pointer_edit) == Some(edit) {
                    self.editing = None;
                    self.buf = TextField::default();
                }
                return Nav::Stay;
            }
            PointerLspAction::Reset => row_index(LspRow::Reset),
            PointerLspAction::Check(_)
            | PointerLspAction::Install(_)
            | PointerLspAction::Uninstall(_)
            | PointerLspAction::Restart(_) => return Nav::Stay,
        };
        debug_assert!(index < row_count);
        self.cursor = index;
        self.handle_key(cx, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    fn handle_pointer_scroll(
        &mut self,
        cx: &mut SettingsCx,
        region: shell::SettingsScrollRegionId,
        delta: isize,
    ) -> Nav {
        if region == shell::SettingsScrollRegionId("lsp") && self.editing.is_none() {
            let row_count = LSP_SERVER_ROW_START
                + cx.project_context()
                    .project_root()
                    .map(|cwd| {
                        cockpit_core::daemon::lsp::builtin_server_views(cwd, &cx.extended).len()
                    })
                    .unwrap_or(1);
            self.reset.disarm();
            self.cursor = self
                .cursor
                .saturating_add_signed(delta)
                .min(row_count.saturating_sub(1));
        }
        Nav::Stay
    }

    fn title(&self, cx: &SettingsCx) -> String {
        format!(
            "{} › LSP",
            cockpit_core::welcome::display_path(&cx.config_path)
        )
    }

    fn help_text(&self, _cx: &SettingsCx) -> &'static str {
        if self.editing.is_some() {
            "type value  enter: save  esc: cancel"
        } else {
            "↑/↓/Tab/Shift+Tab  enter: toggle / edit  r: reset  esc/h: back  q: close"
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    #[cfg(test)]
    fn test_name(&self) -> &'static str {
        "LSP"
    }
}

// ── Helpers / freestanding renderers ─────────────────────────────────────

fn start_lsp_edit<T: ToString>(p: &mut LspPage, edit: LspEdit, value: T) {
    p.editing = Some(edit);
    p.buf.set(value.to_string());
}

pub(super) fn lsp_rows(dialog: &SettingsCx, p: &LspPage) -> (Vec<Line<'static>>, usize) {
    let d = &dialog.extended.lsp.diagnostics;
    let project_context = dialog.project_context();
    let mut rows = vec![
        lsp_row(
            row_index(LspRow::Enabled),
            p.cursor,
            "enabled",
            on_off(dialog.extended.lsp.enabled),
        ),
        lsp_row(
            row_index(LspRow::AutoInstall),
            p.cursor,
            "auto install",
            dialog.extended.lsp.auto_install.as_str(),
        ),
        lsp_row(
            row_index(LspRow::Diagnostics),
            p.cursor,
            "diagnostics",
            on_off(d.enabled),
        ),
        lsp_edit_row(
            row_index(LspRow::OtherFilesLimit),
            p,
            LspEdit::OtherFilesLimit,
            "other files limit",
            d.other_files_limit,
        ),
        lsp_edit_row(
            row_index(LspRow::PerFileLimit),
            p,
            LspEdit::PerFileLimit,
            "per-file limit",
            d.per_file_limit,
        ),
        lsp_info_row("severity", "error (errors only)"),
        lsp_edit_row(
            row_index(LspRow::DebounceMs),
            p,
            LspEdit::DebounceMs,
            "debounce ms",
            d.debounce_ms,
        ),
        lsp_edit_row(
            row_index(LspRow::DocumentTimeoutMs),
            p,
            LspEdit::DocumentTimeoutMs,
            "document timeout ms",
            d.document_timeout_ms,
        ),
        lsp_edit_row(
            row_index(LspRow::WorkspaceTimeoutMs),
            p,
            LspEdit::WorkspaceTimeoutMs,
            "workspace timeout ms",
            d.workspace_timeout_ms,
        ),
        p.reset
            .render_line(p.cursor == row_index(LspRow::Reset), "restore LSP defaults"),
    ];
    if let Some(cwd) = project_context.project_root() {
        for (idx, server) in cockpit_core::daemon::lsp::builtin_server_views(cwd, &dialog.extended)
            .into_iter()
            .enumerate()
        {
            let status = match server.status {
                cockpit_core::daemon::lsp::LspServerStatus::Installed => "installed",
                cockpit_core::daemon::lsp::LspServerStatus::Missing => "missing",
                cockpit_core::daemon::lsp::LspServerStatus::Disabled => "disabled",
                cockpit_core::daemon::lsp::LspServerStatus::Broken => "broken",
                cockpit_core::daemon::lsp::LspServerStatus::Installing => "installing",
            };
            let command = server.command.join(" ");
            let install = server
                .install_command
                .as_ref()
                .map(|c| c.join(" "))
                .unwrap_or_else(|| "manual".to_string());
            let uninstall = server
                .uninstall_command
                .as_ref()
                .map(|c| c.join(" "))
                .unwrap_or_else(|| "manual".to_string());
            rows.push(lsp_row(
                LSP_SERVER_ROW_START + idx,
                p.cursor,
                &server.id,
                format!(
                    "[Check] [Install] [Uninstall] [Restart]  {status}; cockpit-installed: {}; cmd: {command}; install: {install}; uninstall: {uninstall}; {}",
                    on_off(server.cockpit_installed),
                    server.manual_guidance
                ),
            ));
        }
    } else {
        rows.push(lsp_row(
            LSP_SERVER_ROW_START,
            p.cursor,
            "project actions",
            PROJECT_CONTEXT_UNAVAILABLE,
        ));
    }
    if let Some(status) = &p.status {
        rows.push(Line::from(vec![Span::styled(
            status.clone(),
            muted_style(),
        )]));
    }
    let selected_line = lsp_selected_line_for_cursor(p.cursor).min(rows.len().saturating_sub(1));
    (rows, selected_line)
}

pub(super) fn row_index(row: LspRow) -> usize {
    LSP_NAV_ROWS
        .iter()
        .position(|r| *r == row)
        .expect("fixed LSP row")
}

fn lsp_row(
    idx: usize,
    cursor: usize,
    label: impl Into<String>,
    value: impl Into<String>,
) -> Line<'static> {
    let selected = idx == cursor;
    Line::from(vec![
        Span::raw(marker(selected)),
        Span::styled(format!("{:<24}", label.into()), selected_or_field(selected)),
        Span::styled(value.into(), muted_style()),
    ])
}

fn lsp_info_row(label: impl Into<String>, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::raw("  "),
        Span::styled(format!("{:<24}", label.into()), muted_style()),
        Span::styled(value.into(), muted_style()),
    ])
}

fn lsp_edit_row<T: ToString>(
    idx: usize,
    p: &LspPage,
    edit: LspEdit,
    label: &str,
    value: T,
) -> Line<'static> {
    if p.editing == Some(edit) {
        let selected = idx == p.cursor;
        let text = p.buf.text();
        let cursor = cockpit_core::text::floor_char_boundary(text, p.buf.cursor());
        let (before, after) = text.split_at(cursor);
        Line::from(vec![
            Span::raw(marker(selected)),
            Span::styled(format!("{label:<24}"), selected_or_field(selected)),
            Span::styled(before.to_string(), muted_style()),
            shell::cursor_marker_span(),
            Span::styled(after.to_string(), muted_style()),
        ])
    } else {
        lsp_row(idx, p.cursor, label, value.to_string())
    }
}

pub(super) fn lsp_selected_line_for_cursor(cursor: usize) -> usize {
    let severity_insert_at = row_index(LspRow::DebounceMs);
    cursor + usize::from(cursor >= severity_insert_at)
}

fn on_off(v: bool) -> &'static str {
    if v { "on" } else { "off" }
}

pub(super) const PROJECT_CONTEXT_UNAVAILABLE: &str =
    "unavailable: no active project context for project-scoped actions";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum ProjectContext {
    Available(PathBuf),
    Unavailable,
}

impl ProjectContext {
    fn project_root(&self) -> Option<&PathBuf> {
        match self {
            Self::Available(root) => Some(root),
            Self::Unavailable => None,
        }
    }
}

impl SettingsCx {
    fn project_context(&self) -> ProjectContext {
        project_context_for_config(&self.config_path, self.active_project_root.as_deref())
    }
}

impl SettingsCx {
    fn activate_lsp_reset(&mut self, p: &mut LspPage) {
        match p.reset.activate() {
            ResetOutcome::Armed => p.status = None,
            ResetOutcome::Apply => {
                self.extended.lsp = cockpit_config::extended::LspConfig::default();
                p.status = save_status(self.save_extended());
            }
        }
    }

    fn queue_lsp_action(&mut self, server_idx: usize, action: LspControlAction, p: &mut LspPage) {
        let Some(cwd) = self.project_context().project_root().cloned() else {
            p.status = Some(PROJECT_CONTEXT_UNAVAILABLE.to_string());
            return;
        };
        let Some(server) = cockpit_core::daemon::lsp::builtin_server_views(&cwd, &self.extended)
            .into_iter()
            .nth(server_idx)
        else {
            return;
        };
        self.pending_daemon_request = Some(Request::LspControl {
            project_root: cwd.display().to_string(),
            server_id: server.id.clone(),
            action,
        });
        p.status = Some(format!(
            "requested {:?} for {}; result will appear as a daemon notice",
            action, server.id
        ));
    }

    fn render_lsp_page(&self, frame: &mut Frame, area: Rect, p: &LspPage) {
        let (rows, selected_line) = lsp_rows(self, p);
        let row_count = LSP_SERVER_ROW_START
            + self
                .project_context()
                .project_root()
                .map(|cwd| {
                    cockpit_core::daemon::lsp::builtin_server_views(cwd, &self.extended).len()
                })
                .unwrap_or(1);
        let servers = self
            .project_context()
            .project_root()
            .map(|cwd| cockpit_core::daemon::lsp::builtin_server_views(cwd, &self.extended));
        let bindings = (0..row_count).filter_map(|cursor| {
            let action = match lsp_row_for_cursor(cursor) {
                LspRow::Enabled => Some(PointerLspAction::ToggleEnabled),
                LspRow::AutoInstall => Some(PointerLspAction::CycleAutoInstall),
                LspRow::Diagnostics => Some(PointerLspAction::ToggleDiagnostics),
                LspRow::OtherFilesLimit => {
                    Some(lsp_edit_pointer_action(p, PointerLspEdit::OtherFilesLimit))
                }
                LspRow::PerFileLimit => {
                    Some(lsp_edit_pointer_action(p, PointerLspEdit::PerFileLimit))
                }
                LspRow::DebounceMs => Some(lsp_edit_pointer_action(p, PointerLspEdit::DebounceMs)),
                LspRow::DocumentTimeoutMs => Some(lsp_edit_pointer_action(
                    p,
                    PointerLspEdit::DocumentTimeoutMs,
                )),
                LspRow::WorkspaceTimeoutMs => Some(lsp_edit_pointer_action(
                    p,
                    PointerLspEdit::WorkspaceTimeoutMs,
                )),
                LspRow::Reset => Some(PointerLspAction::Reset),
                // The unavailable sentinel is explanatory text, not an
                // enabled Check control. A real project source below supplies
                // stable server identities and actionable controls.
                LspRow::Server(index) => servers
                    .as_ref()
                    .and_then(|items| items.get(index))
                    .map(|server| PointerLspAction::Check(LspServerId(server.id.clone()))),
            }?;
            Some((
                lsp_selected_line_for_cursor(cursor),
                SettingsPointerAction::Lsp(action),
            ))
        });
        self.scroll_states.render_bound_lines(
            frame,
            area,
            "lsp",
            rows,
            Some(selected_line),
            bindings,
            &self.pointer_surface,
            shell::SettingsScrollRegionId("lsp"),
        );
        let offset = self.scroll_states.offset_for("lsp");
        let server_count = row_count.saturating_sub(LSP_SERVER_ROW_START);
        for server_idx in 0..server_count {
            let Some(server) = servers.as_ref().and_then(|items| items.get(server_idx)) else {
                continue;
            };
            let line = lsp_selected_line_for_cursor(LSP_SERVER_ROW_START + server_idx);
            let Some(screen_row) = line.checked_sub(offset) else {
                continue;
            };
            if screen_row >= usize::from(area.height) {
                continue;
            }
            let y = area.y.saturating_add(screen_row as u16);
            for (action, (x, width)) in [
                (
                    PointerLspAction::Check(LspServerId(server.id.clone())),
                    (26, 7),
                ),
                (
                    PointerLspAction::Install(LspServerId(server.id.clone())),
                    (34, 9),
                ),
                (
                    PointerLspAction::Uninstall(LspServerId(server.id.clone())),
                    (44, 11),
                ),
                (
                    PointerLspAction::Restart(LspServerId(server.id.clone())),
                    (56, 9),
                ),
            ] {
                if x >= area.width {
                    continue;
                }
                self.pointer_surface.register(shell::SettingsPointerTarget {
                    rect: Rect::new(
                        area.x.saturating_add(x),
                        y,
                        width.min(area.width.saturating_sub(x)),
                        1,
                    ),
                    action: shell::SettingsPointerAction::Page(SettingsPointerAction::Lsp(action)),
                    enabled: true,
                    disabled_reason: None,
                });
            }
        }
    }
}

fn lsp_edit_pointer_action(p: &LspPage, edit: PointerLspEdit) -> PointerLspAction {
    if p.editing.map(pointer_edit) == Some(edit) {
        PointerLspAction::SaveEdit(edit)
    } else {
        PointerLspAction::Edit(edit)
    }
}

pub(super) fn project_context_for_config(
    config_path: &Path,
    active_project_root: Option<&Path>,
) -> ProjectContext {
    if let Some(project_root) = project_root_for_project_config(config_path) {
        return ProjectContext::Available(project_root);
    }
    active_project_root
        .map(|p| ProjectContext::Available(p.to_path_buf()))
        .unwrap_or(ProjectContext::Unavailable)
}

fn project_root_for_project_config(config_path: &Path) -> Option<PathBuf> {
    if config_path.file_name()? != cockpit_config::dirs::CONFIG_FILE {
        return None;
    }
    let config_dir = config_path.parent()?;
    if config_dir.file_name()? != ".cockpit" {
        return None;
    }
    if dirs::home_dir().is_some_and(|home| config_dir == home.join(".cockpit")) {
        return None;
    }
    config_dir.parent().map(PathBuf::from)
}
