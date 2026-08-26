use super::terminal_suspend::{
    EditorCancel, ExternalEditorSessionOutcome, LiveTerminalSuspendHost, ProcessExternalEditorHost,
    TerminalSuspendHost, format_external_editor_notice, run_external_editor_with_guard,
};
use super::*;

impl App {
    /// Suspend terminal modes (including mouse capture), run `$EDITOR`, and
    /// restore the exact pre-editor snapshot through one finish guard.
    async fn run_external_editor_command(
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
        mouse_capture: bool,
        editor: &std::ffi::OsStr,
        path: &std::path::Path,
    ) -> (ExternalEditorSessionOutcome, bool) {
        // Host is seeded with the App's live TTY capture flag (updated only on
        // successful enable/disable). Snapshot that observed host state rather
        // than a separate preference so restore cannot invent capture.
        let mut host = LiveTerminalSuspendHost::new(terminal, terminal_input, mouse_capture);
        let snapshot = host.state();
        let mut editor_host = ProcessExternalEditorHost;
        let cancel = EditorCancel::new();
        let outcome = run_external_editor_with_guard(
            &mut host,
            &mut editor_host,
            snapshot,
            editor,
            path,
            &cancel,
        )
        .await;
        let live_mouse = host.state().mouse_capture;
        (outcome, live_mouse)
    }

    /// Ctrl+G was pressed: pop the composer text out into `$EDITOR`,
    /// then reload whatever the user wrote back into the buffer. Quits
    /// raw mode for the duration so the editor owns the terminal.
    ///
    /// Returns `true` when a redraw is required after the handoff.
    pub(super) async fn maybe_service_external_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<bool> {
        if !self.pending_external_edit {
            return Ok(false);
        }
        self.pending_external_edit = false;

        let Some(editor) = std::env::var_os("EDITOR") else {
            // Defensive — we re-check here because env state can shift
            // between the keypress and now. The handler already
            // surfaced a toast when EDITOR was unset, so just bail.
            return Ok(false);
        };

        // Stash the buffer in a random Markdown tempfile so editor syntax
        // detection still works without a predictable shared-temp path.
        let mut temp = match new_external_editor_tempfile() {
            Ok(temp) => temp,
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: failed to create temp file: {e}"),
                });
                return Ok(true);
            }
        };
        let editor_text = self.composer.editor_text();
        let paste_snapshot = self.composer.editor_snapshot();
        if let Err(e) = temp.write_all(editor_text.as_bytes()) {
            self.history.push(HistoryEntry::CommandError {
                line: format!("editor: failed to write temp file: {e}"),
            });
            return Ok(true);
        }
        if let Err(e) = temp.flush() {
            self.history.push(HistoryEntry::CommandError {
                line: format!("editor: failed to flush temp file: {e}"),
            });
            return Ok(true);
        }
        let path = temp.path().to_path_buf();

        let (outcome, live_mouse) = Self::run_external_editor_command(
            terminal,
            terminal_input,
            self.mouse_capture,
            &editor,
            &path,
        )
        .await;
        // Keep App.mouse_capture aligned with post-restore TTY state (e.g. when
        // restore failed to re-enable capture).
        self.mouse_capture = live_mouse;
        let redraw = outcome.redraw;

        match &outcome.status {
            Ok(s) if s.success() => match std::fs::read_to_string(&path) {
                Ok(text) => {
                    // Drop a single trailing newline — most editors
                    // write one even when the user didn't add one.
                    let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
                    self.composer.rebuild_from_editor(&text, &paste_snapshot);
                    if let Err(restore) = &outcome.restore {
                        self.history.push(HistoryEntry::CommandError {
                            line: format!("editor: terminal restore: {restore}"),
                        });
                    }
                }
                Err(e) => {
                    let mut line = format!("editor: failed to read temp file back: {e}");
                    if let Err(restore) = &outcome.restore {
                        line = format!("{line}; terminal restore: {restore}");
                    }
                    self.history.push(HistoryEntry::CommandError { line });
                }
            },
            _ => {
                if let Some(line) = format_external_editor_notice(&editor, &outcome) {
                    self.history.push(HistoryEntry::CommandError { line });
                }
            }
        }
        Ok(redraw)
    }

    /// The `/settings → Agents` page asked to edit an agent file in
    /// `$EDITOR` (implementation note). The page owns a private temporary
    /// directory plus a retained directory handle; this host effect receives
    /// only its staging pathname, never the authoritative agent pathname.
    /// After suspension the page reads the leaf relative to that retained
    /// handle and submits the bytes under the daemon editor lease. Process or
    /// RPC failure preserves a recovery draft and cannot partially write the
    /// authoritative definition. Reuses the same suspension guard as Ctrl+G.
    pub(super) async fn maybe_service_agent_file_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<bool> {
        let Some(effect) = self.dialog.take_pending_agent_edit() else {
            return Ok(false);
        };
        let operation_id = effect.operation_id;
        let path = effect.path;

        let Some(editor) = std::env::var_os("EDITOR") else {
            // Env shifted between the page deciding to defer and now; the
            // page only defers when EDITOR was set, so this is defensive.
            self.dialog.finish_agent_edit(
                operation_id,
                crate::tui::settings::pointer_actions::ExternalEditOutcome::Failed,
                Some("$EDITOR is no longer set".to_string()),
            );
            return Ok(true);
        };

        let (outcome, live_mouse) = Self::run_external_editor_command(
            terminal,
            terminal_input,
            self.mouse_capture,
            &editor,
            &path,
        )
        .await;
        // Keep App.mouse_capture aligned with post-restore TTY state (e.g. when
        // restore failed to re-enable capture).
        self.mouse_capture = live_mouse;
        let redraw = outcome.redraw;

        use crate::tui::settings::pointer_actions::ExternalEditOutcome;
        let (completion, detail) = match (&outcome.status, &outcome.restore) {
            (Ok(status), Ok(())) if status.success() => (ExternalEditOutcome::Saved, None),
            (Ok(status), Err(restore)) if status.success() => (
                ExternalEditOutcome::Saved,
                Some(format!("terminal restore: {restore}")),
            ),
            (Ok(status), Ok(())) if status.code() == Some(130) => (
                ExternalEditOutcome::Cancelled,
                Some("external editor cancelled".into()),
            ),
            (Ok(status), Err(restore)) if status.code() == Some(130) => (
                ExternalEditOutcome::Cancelled,
                Some(format!(
                    "external editor cancelled; terminal restore: {restore}"
                )),
            ),
            (Ok(status), Ok(())) => (
                ExternalEditOutcome::Failed,
                Some(format!("editor exited with {status}")),
            ),
            (Ok(status), Err(restore)) => (
                ExternalEditOutcome::Failed,
                Some(format!(
                    "editor exited with {status}; terminal restore: {restore}"
                )),
            ),
            (Err(error), Ok(())) => (
                ExternalEditOutcome::Failed,
                Some(format!("invoking `{}`: {error}", editor.to_string_lossy())),
            ),
            (Err(error), Err(restore)) => (
                ExternalEditOutcome::Failed,
                Some(format!(
                    "invoking `{}`: {error}; terminal restore: {restore}",
                    editor.to_string_lossy()
                )),
            ),
        };
        self.dialog
            .finish_agent_edit(operation_id, completion, detail);
        Ok(redraw)
    }

    /// A category setting requested a `$EDITOR` round trip against a private
    /// tempfile. The dialog owns the temp path and validation; the app only
    /// suspends the terminal and reports process success/failure.
    pub(super) async fn maybe_service_category_setting_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<bool> {
        let Some((operation_id, path)) = self.dialog.take_pending_category_setting_edit() else {
            return Ok(false);
        };

        let Some(editor) = std::env::var_os("EDITOR") else {
            self.dialog.finish_category_setting_edit(
                operation_id,
                crate::tui::settings::pointer_actions::ExternalEditOutcome::Failed,
                Some("$EDITOR is no longer set".to_string()),
            );
            return Ok(true);
        };

        let (outcome, live_mouse) = Self::run_external_editor_command(
            terminal,
            terminal_input,
            self.mouse_capture,
            &editor,
            &path,
        )
        .await;
        // Keep App.mouse_capture aligned with post-restore TTY state (e.g. when
        // restore failed to re-enable capture).
        self.mouse_capture = live_mouse;
        let redraw = outcome.redraw;

        use crate::tui::settings::pointer_actions::ExternalEditOutcome;
        let (completion, detail) = match (&outcome.status, &outcome.restore) {
            (Ok(status), Ok(())) if status.success() => (ExternalEditOutcome::Saved, None),
            (Ok(status), Err(restore)) if status.success() => (
                ExternalEditOutcome::Saved,
                Some(format!("terminal restore: {restore}")),
            ),
            (Ok(status), Ok(())) if status.code() == Some(130) => (
                ExternalEditOutcome::Cancelled,
                Some("external editor cancelled".into()),
            ),
            (Ok(status), Err(restore)) if status.code() == Some(130) => (
                ExternalEditOutcome::Cancelled,
                Some(format!(
                    "external editor cancelled; terminal restore: {restore}"
                )),
            ),
            (Ok(status), Ok(())) => (
                ExternalEditOutcome::Failed,
                Some(format!(
                    "editor exited with {status} - value left unchanged"
                )),
            ),
            (Ok(status), Err(restore)) => (
                ExternalEditOutcome::Failed,
                Some(format!(
                    "editor exited with {status}; terminal restore: {restore} - value left unchanged"
                )),
            ),
            (Err(error), Ok(())) => (
                ExternalEditOutcome::Failed,
                Some(format!(
                    "invoking `{}`: {error} - value left unchanged",
                    editor.to_string_lossy()
                )),
            ),
            (Err(error), Err(restore)) => (
                ExternalEditOutcome::Failed,
                Some(format!(
                    "invoking `{}`: {error}; terminal restore: {restore} - value left unchanged",
                    editor.to_string_lossy()
                )),
            ),
        };
        self.dialog
            .finish_category_setting_edit(operation_id, completion, detail);
        Ok(redraw)
    }

    /// Open `$EDITOR` in an embedded pane (GOALS §1i). No-op if a pane
    /// is already open (one at a time). `side` is `Full` for the bare
    /// `/editor`, or a split side.
    pub(super) fn open_editor(&mut self, side: PaneSide) {
        self.open_editor_target(side, None);
    }

    pub(super) fn open_editor_target(&mut self, side: PaneSide, target: Option<&str>) {
        if self.pane.is_some() {
            return;
        }
        let Some(editor) = std::env::var_os("EDITOR") else {
            self.push_plain("/editor: no `$EDITOR` set".to_string());
            return;
        };
        let argv = match target {
            Some(path) => editor_argv_for_target(&editor, path),
            None => editor_argv_for_cwd(&editor, &self.launch.cwd),
        };
        if argv.is_empty() {
            self.history.push(HistoryEntry::CommandError {
                line: "/editor: `$EDITOR` is empty".to_string(),
            });
            return;
        }
        self.spawn_pane(crate::tui::pty::PaneKind::Editor, &argv, side);
    }

    /// Open `lazygit` fullscreen in an embedded pane (GOALS §1j).
    pub(super) fn open_lazygit(&mut self) {
        if self.pane.is_some() {
            return;
        }
        if !program_on_path("lazygit") {
            self.history.push(HistoryEntry::CommandError {
                line: "/lazygit: `lazygit` not found on `PATH`".to_string(),
            });
            return;
        }
        self.spawn_pane(
            crate::tui::pty::PaneKind::Lazygit,
            &["lazygit".to_string()],
            PaneSide::Full,
        );
    }

    /// Spawn a pane. Initial PTY size is a placeholder corrected by the
    /// first render's resize. Focus moves to the new pane.
    fn spawn_pane(&mut self, kind: crate::tui::pty::PaneKind, argv: &[String], side: PaneSide) {
        match crate::tui::pty::PtyPane::spawn(kind, argv, &self.launch.cwd, 24, 80) {
            Ok(pane) => {
                self.pane = Some(pane);
                self.pane_side = side;
                self.pane_focused = true;
                self.dragging_divider = false;
                self.invalidate_primary_paste();
            }
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("/{}: {e}", kind.label()),
                });
            }
        }
    }

    /// Close the open pane and return focus to the composer. `force`
    /// terminates a still-running child (Ctrl+X); otherwise the child
    /// has already exited and we just reap it (auto-close).
    pub(super) fn close_pane(&mut self, force: bool) {
        if let Some(mut pane) = self.pane.take() {
            if force {
                pane.terminate();
            } else {
                pane.reap();
            }
        }
        self.pane_focused = false;
        self.dragging_divider = false;
        self.invalidate_primary_paste();
        self.pane_rect = None;
        self.divider = None;
    }

    /// Service the open pane once per event-loop tick: auto-close when
    /// the child has exited (GOALS §1i).
    pub(super) fn service_pane(&mut self) {
        let exited = self.pane.as_mut().is_some_and(|p| p.has_exited());
        if exited {
            self.close_pane(false);
        }
    }

    /// `!` shell mode (GOALS §1k): run a one-shot command via the shell,
    /// capture stdout+stderr, and render it locally. Never sent to the
    /// agent.
    pub(super) fn run_shell_command(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return;
        }
        let cmd = cmd.to_string();
        let cwd = self.launch.cwd.clone();
        self.start_local_command_action(format!("! {cmd}"), None, move || {
            exec_capture_shell(&cmd, &cwd)
        });
    }

    /// `/git` (GOALS §1l): run `git <args>` locally, render it now, and
    /// buffer a `<git>` block (~2k-token cap) for the next user message.
    pub(super) fn run_git_command(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() {
            self.push_plain("/git: usage `/git <args>` (e.g. `/git status`)".to_string());
            return;
        }
        let args = args.to_string();
        let cwd = self.launch.cwd.clone();
        self.start_local_command_action(format!("/git {args}"), Some(args.clone()), move || {
            exec_capture_git(&args, &cwd)
        });
    }

    pub(super) fn start_local_command_action<F>(
        &mut self,
        label: String,
        git_args: Option<String>,
        work: F,
    ) where
        F: FnOnce() -> (String, bool) + Send + 'static,
    {
        self.push_plain(format!(
            "{label}: running (local command; cancellation unavailable)"
        ));
        self.pin_chat_to_tail();
        self.async_actions.start_blocking(
            AsyncActionKind::Blocking("local.command"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                let (raw_output, failed) = work();
                Ok(AsyncActionPayload::LocalCommand {
                    label,
                    raw_output,
                    failed,
                    git_args,
                })
            },
        );
    }
}
