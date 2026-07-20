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
        self.pending_control_requests.clear();
        self.pin_count = 0;
        self.pin_count_session = None;
        self.pinned_seqs_cache.clear();
        self.pinned_seqs_session = None;
    }

    pub(super) fn cancel_outgoing_turn_if_busy(&mut self) {
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
        // No client-side config re-read on a session swap: the swapped-in
        // session's attach delivers a fresh `ConfigSnapshot`
        // (`tui-config-single-source`), which replaces the held one.

        let switch_task = match self.agent_runner.as_ref() {
            Some(Ok(runner)) if runner.can_switch_session() => {
                Some(runner.switch_session_task(agent_runner::SessionTarget::New))
            }
            _ => None,
        };
        if let Some(switch_task) = switch_task {
            self.async_actions.start(
                AsyncActionKind::Internal("session.switch"),
                AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
                async move {
                    switch_task
                        .await
                        .map(|outcome| AsyncActionPayload::SessionSwitched(Box::new(outcome)))
                },
            );
        } else {
            // No live runner exists, so the next submit/attach path still
            // creates a fresh session with `session_id: None`.
            self.agent_runner.take();
            self.reset_display_attach_backoff();
        }
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

    pub(super) fn apply_session_switch_outcome(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
    ) {
        self.apply_session_switch_outcome_inner(outcome, true);
    }

    pub(super) fn apply_session_switch_outcome_without_resume_chrome(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
    ) {
        self.apply_session_switch_outcome_inner(outcome, false);
    }

    pub(super) fn apply_session_switch_outcome_preserving_history(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
        current_session_persisted: bool,
    ) {
        if let Some(Ok(runner)) = &mut self.agent_runner {
            runner.apply_session_switch_outcome(&outcome);
        }
        self.launch.session_id = Some(outcome.session_id);
        self.launch.session_short_id = Some(outcome.short_id);
        self.project_id = Some(outcome.project_id);
        self.foreground_input_target = outcome.foreground_target;
        if let Some(state) = outcome.active_model_state {
            self.apply_active_model_state(
                state.provider,
                state.model,
                state.diverged,
                state.generation,
            );
        }
        self.current_session_persisted = current_session_persisted;
    }

    fn apply_session_switch_outcome_inner(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
        resume_chrome: bool,
    ) {
        let resume_history = matches!(outcome.target, agent_runner::SessionTarget::Resume { .. })
            .then(|| wire_history_to_entries(outcome.history.clone()));
        let short_id = outcome.short_id.clone();
        let paused_work = outcome.paused_work.clone();
        let repair_required = outcome.repair_required.clone();
        let btw_fork = outcome.btw_fork.clone();
        let daemon_version = outcome.daemon_version.clone();
        let daemon_compatible = outcome.daemon_compatible;
        if let Some(Ok(runner)) = &mut self.agent_runner {
            runner.apply_session_switch_outcome(&outcome);
        }
        if let Some(restored) = resume_history {
            self.history.clear();
            self.reset_session_live_state();
            self.history.extend(restored);
            self.current_session_persisted = true;
        }
        self.launch.session_id = Some(outcome.session_id);
        self.launch.session_short_id = Some(outcome.short_id.clone());
        self.project_id = Some(outcome.project_id);
        self.foreground_input_target = outcome.foreground_target;
        if let Some(state) = outcome.active_model_state {
            self.apply_active_model_state(
                state.provider,
                state.model,
                state.diverged,
                state.generation,
            );
        }
        match outcome.target {
            agent_runner::SessionTarget::New => {
                self.current_session_persisted = false;
            }
            agent_runner::SessionTarget::Resume { session_id, .. } => {
                if resume_chrome {
                    if let Some(info) = btw_fork {
                        self.open_btw_pane_from_info(info, true);
                    }
                    let label = if short_id.is_empty() {
                        session_id.to_string()
                    } else {
                        short_id
                    };
                    self.push_plain(format!("/resume: switched to session {label}."));
                    if let Some(repair) = repair_required {
                        self.maybe_prompt_resume_repair(repair);
                    }
                    self.maybe_prompt_paused_work(session_id, paused_work);
                    self.maybe_show_daemon_version_chip(&daemon_version, daemon_compatible);
                }
            }
        }
    }
}
