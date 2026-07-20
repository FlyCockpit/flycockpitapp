use super::*;

impl App {
    fn run_external_editor_command(
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
        editor: &std::ffi::OsStr,
        path: &std::path::Path,
    ) -> Result<std::io::Result<std::process::ExitStatus>> {
        with_input_suspended(terminal_input, |_| {
            // Suspend ratatui's input handling for the editor invocation.
            // We disable the keyboard-enhancement flags / cursor styles
            // crossterm pushed for us, leave raw mode, and let the editor
            // own the TTY. Re-enable everything after it exits.
            use crossterm::terminal::{
                EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
            };
            let _ = crossterm::execute!(stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();

            let status = std::process::Command::new(editor).arg(path).status();

            let _ = enable_raw_mode();
            let _ = crossterm::execute!(stdout(), EnterAlternateScreen);
            terminal.clear()?;

            Ok(status)
        })
    }

    /// Ctrl+G was pressed: pop the composer text out into `$EDITOR`,
    /// then reload whatever the user wrote back into the buffer. Quits
    /// raw mode for the duration so the editor owns the terminal.
    pub(super) fn maybe_service_external_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<()> {
        if !self.pending_external_edit {
            return Ok(());
        }
        self.pending_external_edit = false;

        let Some(editor) = std::env::var_os("EDITOR") else {
            // Defensive — we re-check here because env state can shift
            // between the keypress and now. The handler already
            // surfaced a toast when EDITOR was unset, so just bail.
            return Ok(());
        };

        // Stash the buffer in a random Markdown tempfile so editor syntax
        // detection still works without a predictable shared-temp path.
        let mut temp = match new_external_editor_tempfile() {
            Ok(temp) => temp,
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: failed to create temp file: {e}"),
                });
                return Ok(());
            }
        };
        let editor_text = self.paste_registry.expand_editor(self.composer.text());
        let retained_images = self.paste_registry.image_payloads_by_number();
        if let Err(e) = temp.write_all(editor_text.as_bytes()) {
            self.history.push(HistoryEntry::CommandError {
                line: format!("editor: failed to write temp file: {e}"),
            });
            return Ok(());
        }
        if let Err(e) = temp.flush() {
            self.history.push(HistoryEntry::CommandError {
                line: format!("editor: failed to flush temp file: {e}"),
            });
            return Ok(());
        }
        let path = temp.path().to_path_buf();

        let status = Self::run_external_editor_command(terminal, terminal_input, &editor, &path)?;

        match status {
            Ok(s) if s.success() => match std::fs::read_to_string(&path) {
                Ok(text) => {
                    // Drop a single trailing newline — most editors
                    // write one even when the user didn't add one.
                    let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
                    let rebuilt = crate::tui::paste::PasteRegistry::rebuild_from_editor(
                        &text,
                        &retained_images,
                        crate::tokens::count,
                    );
                    self.composer.set(rebuilt.buffer);
                    self.paste_registry = rebuilt.registry;
                }
                Err(e) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("editor: failed to read temp file back: {e}"),
                    });
                }
            },
            Ok(s) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: exited with {s}"),
                });
            }
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: invoking `{}`: {e}", editor.to_string_lossy()),
                });
            }
        }
        Ok(())
    }

    /// The `/settings → Agents` page asked to edit an agent file in
    /// `$EDITOR` (implementation note). The page can't
    /// suspend the TUI from inside a key handler, so it records the path
    /// and we service it here: suspend ratatui, run `$EDITOR <file>`, then
    /// hand the outcome back so the page re-reads + re-parses the file
    /// (surfacing a parse error inline, never silently accepting a broken
    /// agent). External-process failure leaves the file untouched and is
    /// reported inline. Reuses the same raw-mode/alt-screen toggle dance as
    /// the composer's Ctrl+G handoff.
    pub(super) fn maybe_service_agent_file_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<()> {
        let Some(path) = self.dialog.take_pending_agent_edit() else {
            return Ok(());
        };

        let Some(editor) = std::env::var_os("EDITOR") else {
            // Env shifted between the page deciding to defer and now; the
            // page only defers when EDITOR was set, so this is defensive.
            self.dialog
                .finish_agent_edit(Some("$EDITOR is no longer set".to_string()));
            return Ok(());
        };

        let status = Self::run_external_editor_command(terminal, terminal_input, &editor, &path)?;

        let editor_error = match status {
            Ok(s) if s.success() => None,
            Ok(s) => Some(format!("editor exited with {s} — file left unchanged")),
            Err(e) => Some(format!(
                "invoking `{}`: {e} — file left unchanged",
                editor.to_string_lossy()
            )),
        };
        self.dialog.finish_agent_edit(editor_error);
        Ok(())
    }

    /// A category setting requested a `$EDITOR` round trip against a private
    /// tempfile. The dialog owns the temp path and validation; the app only
    /// suspends the terminal and reports process success/failure.
    pub(super) fn maybe_service_category_setting_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<()> {
        let Some(path) = self.dialog.take_pending_category_setting_edit() else {
            return Ok(());
        };

        let Some(editor) = std::env::var_os("EDITOR") else {
            self.dialog
                .finish_category_setting_edit(Some("$EDITOR is no longer set".to_string()));
            return Ok(());
        };

        let status = Self::run_external_editor_command(terminal, terminal_input, &editor, &path)?;
        let editor_error = match status {
            Ok(s) if s.success() => None,
            Ok(s) => Some(format!("editor exited with {s} - value left unchanged")),
            Err(e) => Some(format!(
                "invoking `{}`: {e} - value left unchanged",
                editor.to_string_lossy()
            )),
        };
        self.dialog.finish_category_setting_edit(editor_error);
        Ok(())
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
        self.chat_scroll_offset = 0;
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
