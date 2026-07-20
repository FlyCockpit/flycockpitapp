use super::*;

impl App {
    pub(super) fn copy_persistent_notice_fix_command(&mut self) {
        let Some(command) = self.persistent_notice_fix_command().map(str::to_string) else {
            return;
        };
        match crate::clipboard::copy_plain(&command) {
            Ok(_) => self.show_copy_ok_or_tmux_hint("Copied fix command.".to_string()),
            Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
        }
    }

    /// Execute one of the context-menu actions. Called both when the
    /// user clicks an item and when they hit Enter on a focused item.
    /// `clicked_chat_row` is the chat-relative row that was
    /// right-clicked — used by "Copy as rich text" to find which
    /// agent message was under the click; ignored by the other
    /// actions.
    pub(super) fn execute_context_menu_action(
        &mut self,
        action: crate::tui::context_menu::ContextMenuAction,
        clicked_chat_row: usize,
    ) {
        use crate::tui::context_menu::ContextMenuAction;
        if matches!(action, ContextMenuAction::OpenInEditor) {
            let Some(path) = self
                .chat_row_meta
                .get(clicked_chat_row)
                .and_then(|meta| meta.diff_path.as_deref())
                .map(str::to_string)
            else {
                self.show_toast("No diff file under that row.", ToastKind::Info);
                return;
            };
            if std::env::var_os("EDITOR").is_none() {
                self.push_plain("Open in $EDITOR: `$EDITOR` is no longer set".to_string());
                self.show_toast("$EDITOR is no longer set.", ToastKind::Error);
                return;
            }
            self.open_editor_target(PaneSide::Full, Some(&path));
            return;
        }
        let copy_pick_target = self
            .copy_pick
            .is_some()
            .then(|| self.copy_target_text())
            .flatten();
        let Some((title, text, shape)) = copy_pick_target.or_else(|| {
            self.message_at_chat_row(clicked_chat_row)
                .map(|(title, text)| (title, text, pins::CopyShape::Message))
        }) else {
            self.show_toast("No message under that row.", ToastKind::Info);
            return;
        };
        if text.trim().is_empty() {
            self.show_toast("/copy-pick: that message has no text", ToastKind::Info);
            return;
        }
        let (msg, kind) = match action {
            ContextMenuAction::OpenInEditor => unreachable!("handled before copy actions"),
            ContextMenuAction::CopyAsRichText => {
                let rich_source = match shape {
                    pins::CopyShape::Message => text.clone(),
                    pins::CopyShape::CodeBlock => format!("```\n{text}```\n"),
                };
                let html = crate::clipboard::markdown_to_html(&rich_source);
                match crate::clipboard::copy_rich(&rich_source, &html) {
                    Ok(_) => (format!("Copied {title} as rich text."), ToastKind::Success),
                    Err(crate::clipboard::CopyError::UnsupportedOverSsh) => {
                        // Shouldn't normally happen because the menu
                        // builder hides this option over SSH, but
                        // guard anyway so a stale menu doesn't error.
                        match crate::clipboard::copy_plain(&text) {
                            Ok(_) => (
                                format!(
                                    "SSH — copied {title} as plain text \
                                     (rich-text unavailable over SSH)."
                                ),
                                ToastKind::Success,
                            ),
                            Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                        }
                    }
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            ContextMenuAction::CopyAsMarkdown => match crate::clipboard::copy_plain(&text) {
                Ok(_) => (format!("Copied {title} as markdown."), ToastKind::Success),
                Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
            },
            ContextMenuAction::CopyAsPlainText => {
                let plain = match shape {
                    pins::CopyShape::Message => crate::clipboard::markdown_to_plain(&text),
                    pins::CopyShape::CodeBlock => text.clone(),
                };
                match crate::clipboard::copy_plain(&plain) {
                    Ok(_) => (format!("Copied {title} as plain text."), ToastKind::Success),
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
        };
        self.show_toast(msg, kind);
        self.copy_pick = None;
    }

    /// Resolve the exact message owned by a visible chat row.
    pub(super) fn message_at_chat_row(&self, clicked_chat_row: usize) -> Option<(String, String)> {
        let meta = self.chat_row_meta.get(clicked_chat_row)?;
        let render::ChatCopyTarget::Message { history_index } = meta.copy_target?;
        match self.history.get(history_index)? {
            HistoryEntry::User { text, .. } if !text.trim().is_empty() => {
                Some(("user message".to_string(), text.clone()))
            }
            HistoryEntry::Agent { name, text, .. } if !text.trim().is_empty() => {
                Some((format!("{name} message"), text.clone()))
            }
            _ => None,
        }
    }

    /// Build the plaintext of the active drag-selection from the
    /// cached chat grid and push it to the system clipboard via
    /// `clipboard::copy_plain` (OSC52 + arboard locally). No-op when
    /// the selection is empty or stale (chat_area moved between
    /// selection and copy).
    /// On a successful copy, show the one-time-per-session tmux OSC52
    /// discoverability hint (first cockpit copy while `$TMUX` is set,
    /// independent of whether OSC52 was acknowledged); otherwise show
    /// the plain success toast.
    fn show_copy_ok_or_tmux_hint(&mut self, success_msg: String) {
        if !self.tmux_copy_hint_shown && std::env::var_os("TMUX").is_some() {
            self.tmux_copy_hint_shown = true;
            self.show_toast(
                "Copied via OSC52. If it didn't reach your clipboard, your terminal must allow OSC52 (tmux: set -g set-clipboard on).",
                ToastKind::Info,
            );
        } else {
            self.show_toast(success_msg, ToastKind::Success);
        }
    }

    pub(super) fn copy_selection_plaintext(&mut self) {
        self.copy_selection_plaintext_with(crate::clipboard::copy_plain);
    }

    pub(super) fn copy_selection_plaintext_with(
        &mut self,
        copy_plain: impl FnOnce(
            &str,
        )
            -> Result<crate::clipboard::CopyOutcome, crate::clipboard::CopyError>,
    ) {
        let Some(sel) = self.selection else {
            return;
        };
        let Some(area) = self.chat_area else {
            return;
        };
        let (start, end) = sel.ordered();
        // Stale guard: if either selection endpoint is outside the
        // current chat area, the snapshot we have no longer
        // corresponds. Clear the selection and bail.
        if start.1 < area.y
            || end.1 >= area.y + area.height
            || start.0 < area.x
            || end.0 >= area.x + area.width
        {
            self.selection = None;
            return;
        }
        if self.chat_text_grid.len() != area.height as usize
            || self
                .chat_text_grid
                .iter()
                .any(|row| row.len() != area.width as usize)
        {
            return;
        }
        let text_to_copy =
            extract_selection_markdown_source(&self.history, &self.chat_row_meta, area, sel)
                .unwrap_or_else(|| {
                    extract_selection_plaintext(
                        &self.chat_text_grid,
                        &self.chat_row_meta,
                        area,
                        sel,
                    )
                });
        if text_to_copy.is_empty() {
            return;
        }
        match copy_plain(&text_to_copy) {
            Ok(_) => {
                self.show_copy_ok_or_tmux_hint(format!(
                    "Copied {} chars to clipboard.",
                    text_to_copy.chars().count()
                ));
                // Clear selection after an accepted copy — the user got
                // what they wanted; leaving it highlighted just gets in the
                // way of the next interaction.
                self.selection = None;
            }
            Err(crate::clipboard::CopyError::TooLarge { .. }) => {
                self.show_toast(
                    "Selection too large to copy over OSC52 (max ~73 KB) — copy a smaller range.",
                    ToastKind::Error,
                );
            }
            Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
        }
    }

    /// Copy the most recent agent message to the system clipboard as
    /// rich text (HTML + plain alt). Surfaces feedback via a toast
    /// (TUI-design-philosophy §7). No-op when `tui.rich_text_copy`
    /// is off or no agent messages exist.
    pub(super) fn copy_last_agent_message_as_rich_text(&mut self) {
        if !self.rich_text_copy {
            self.show_toast(
                "Rich-text copy is disabled (toggle in /settings → ui).",
                ToastKind::Info,
            );
            return;
        }
        let last_agent_text = self.history.iter().rev().find_map(|e| match e {
            HistoryEntry::Agent { text, .. } if !text.trim().is_empty() => Some(text.clone()),
            _ => None,
        });
        let Some(text) = last_agent_text else {
            self.show_toast("No agent message to copy yet.", ToastKind::Info);
            return;
        };
        let html = crate::clipboard::markdown_to_html(&text);
        match crate::clipboard::copy_rich(&text, &html) {
            Ok(_) => self
                .show_copy_ok_or_tmux_hint("Copied last agent message as rich text.".to_string()),
            Err(crate::clipboard::CopyError::UnsupportedOverSsh) => {
                // SSH session — fall back to plain text via OSC52 so
                // the user gets at least something on the local
                // clipboard.
                match crate::clipboard::copy_plain(&text) {
                    Ok(_) => self.show_copy_ok_or_tmux_hint(
                        "SSH — copied as plain text (rich-text unavailable over SSH).".to_string(),
                    ),
                    Err(crate::clipboard::CopyError::TooLarge { .. }) => self.show_toast(
                        "Selection too large to copy over OSC52 (max ~73 KB) — copy a smaller range.",
                        ToastKind::Error,
                    ),
                    Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
        }
    }
}
