use super::*;

impl App {
    pub(super) fn reset_session_live_state(&mut self) {
        self.queue.clear();
        self.pending = None;
        self.pending_render_cache = None;
        self.prunable_tokens = 0;
        self.elided_event_ids.clear();
        self.active_schedules.clear();
        self.pending_stop_confirm = None;
        self.chat_scroll_offset = 0;
        self.end_working_span();
        self.prediction_state.begin_turn();
        // prompt_history is shell-style across sessions; only the active
        // recall cursor and hidden draft belong to the outgoing session.
        self.prompt_history_cursor = 0;
        self.staged_draft = None;
        self.pending_git_blocks.clear();
        self.accepted_tags.clear();
        self.pending_edit_args.clear();
        self.pin_count = 0;
        self.pin_count_session = None;
        self.pinned_seqs_cache.clear();
        self.pinned_seqs_session = None;
    }

    pub(super) fn cancel_outgoing_turn_if_busy(&self) {
        if self.busy {
            self.interrupt_agent();
        }
    }

    /// `/new` was invoked: clear chat history and drop the daemon-
    /// attached runner so the next user message opens a fresh session.
    /// In alt-screen mode the chat pane is the whole canvas, so the
    /// "fresh session" visual is simply an empty pane.
    pub(super) fn maybe_service_new_session(
        &mut self,
        terminal: &mut DefaultTerminal,
    ) -> Result<bool> {
        self.maybe_service_new_session_with_clear(|| terminal.clear().map_err(Into::into))
    }

    pub(super) fn maybe_service_new_session_with_clear(
        &mut self,
        mut clear_terminal: impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        if !self.pending_new_session {
            return Ok(false);
        }
        self.pending_new_session = false;

        self.cancel_outgoing_turn_if_busy();

        // `/new` from inside a side conversation: discard the ephemeral fork
        // first (no orphan), then proceed to open a fresh session. We don't
        // restore the main session's view — `/new` is clearing everything
        // anyway — but the discard must still fire and the chrome flag clear.
        if self.side_conversation.is_some() {
            self.end_side_conversation(false);
        }

        // Alt-screen mode: the chat pane is the whole canvas, and
        // there's no terminal scrollback to spill into. Clearing
        // history makes the chat pane empty — that's the "new
        // session" visual.
        self.finalize_pending();

        // Reset transcript state.
        self.history.clear();
        self.reset_session_live_state();
        self.clickable_rows.clear();
        self.box_rows.clear();
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        self.affordance_scroll_regions.clear();
        self.chat_row_meta.clear();
        self.chat_area = None;
        self.chat_text_grid.clear();
        self.chat_cont_rows.clear();
        self.selection = None;
        // Reload from disk in case settings changed.
        self.reload_launch_info();
        self.reload_tui_config();

        // Drop the runner so the next submit re-attaches the daemon
        // with `session_id: None`, opening a fresh session.
        self.agent_runner = None;
        self.reset_display_attach_backoff();
        // The fresh session is deferred-persistence until its first message
        // (session-id-display-and-lazy-persist).
        self.current_session_persisted = false;

        // Reset the autocomplete tally so the next attach re-seeds it
        // fresh (additive merge would otherwise double-count). The
        // daemon re-fetch picks up everything recorded this session.
        self.usage_models.clear();
        self.usage_slash.clear();
        self.usage_tags.clear();
        self.project_id = None;
        self.pending_usage.clear();
        // Clear the provider usage so the fresh-chat instruction-file
        // estimate re-triggers on the new (empty) session.
        self.last_usage = None;
        self.estimate_at_last_usage = 0;

        // Repaint the cleared canvas on the next draw. `Terminal::clear`
        // invalidates ratatui's buffers on success, but crossterm may fail
        // its cursor-position probe. That UI cleanup must never abort the
        // already-completed fresh-session state transition.
        if let Err(error) = clear_terminal() {
            tracing::warn!(error = %error, "terminal clear after /new failed; continuing with redraw");
        }

        Ok(true)
    }
}
