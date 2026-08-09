use super::*;

impl App {
    pub(super) fn session_switch_action_key() -> AsyncActionKey {
        AsyncActionKey::new("session.switch")
    }

    /// All in-process attaches mutate the runner's shared transport before
    /// App can adopt their authoritative snapshot. Keep that interval a
    /// single, non-replaceable transaction: a later switch request may reuse
    /// the pending action, but must never abort it and start another attach.
    pub(super) fn session_switch_action_policy() -> AsyncActionPolicy {
        AsyncActionPolicy::Dedupe(Self::session_switch_action_key())
    }

    /// Session-switch calls all run on App's single event-loop thread. This
    /// keyed preflight is therefore also the claim: no other caller can pass
    /// it before this caller synchronously installs its action. The pending
    /// entry remains keyed even when its future has completed but App has not
    /// adopted the result yet, preserving that especially important window.
    pub(super) fn session_switch_in_progress(&self) -> bool {
        self.async_actions
            .has_pending_key(&Self::session_switch_action_key())
    }

    pub(super) fn report_session_switch_busy(&mut self, command: &str) {
        self.history.push(HistoryEntry::CommandError {
            line: format!(
                "{command}: another session change is still finishing; retry when it completes"
            ),
        });
    }

    pub(super) fn reset_session_live_state(&mut self) {
        // Session reset begins a new runner epoch. Cancel model controls
        // before clearing general request bookkeeping so a held exact wire
        // submission cannot be stranded if the attach later fails.
        self.cancel_model_controls_for_epoch_change(None);
        self.queue.clear();
        self.folded_queue_item_ids.clear();
        self.folded_queue_item_order.clear();
        self.retained_user_submission_ids.clear();
        self.pending = None;
        self.pending_render_cache = None;
        self.prunable_tokens = 0;
        self.elided_event_ids.clear();
        self.active_schedules.clear();
        self.pending_stop_confirm = None;
        self.pin_chat_to_tail();
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
        let changed = self.clear_terminal_after_committed_new_session(&mut clear_terminal);
        if !self.pending_new_session {
            return Ok(changed);
        }
        if self.has_pending_session_switch_action() {
            if let Some((sequence, _)) = self.pending_session_switch_order.take() {
                self.submission_order.cancel(sequence);
                self.dispatch_next_ready_paste_fence();
            }
            self.pending_new_session = false;
            self.report_session_switch_busy("/new");
            return Ok(true);
        }
        let (switch_sequence, switch_id) = match self.pending_session_switch_order {
            Some(existing) => existing,
            None => {
                let switch_id = uuid::Uuid::new_v4();
                let sequence = self
                    .submission_order
                    .enqueue(crate::tui::structured_paste::OrderedIntent::SessionSwitch(
                        switch_id,
                    ))
                    .map_err(|error| anyhow::anyhow!(error))?;
                self.pending_session_switch_order = Some((sequence, switch_id));
                (sequence, switch_id)
            }
        };
        let cancelled = self
            .submission_fences
            .iter()
            .filter_map(|(id, fence)| {
                (fence.fence_sequence < switch_sequence
                    && matches!(
                        fence.lifecycle,
                        crate::tui::structured_paste::FenceLifecycle::AwaitingProbes
                            | crate::tui::structured_paste::FenceLifecycle::Ready
                    ))
                .then_some((*id, fence.fence_sequence))
            })
            .collect::<Vec<_>>();
        let cancelled_any = !cancelled.is_empty();
        for (id, sequence) in cancelled {
            self.submission_fences.remove(&id);
            self.deferred_fence_dispatches.remove(&id);
            self.pending_paste_probes
                .retain(|_, probe| probe.owner_fence != Some(id));
            self.submission_order.cancel(sequence);
        }
        if cancelled_any {
            self.show_toast("Paste unavailable", super::ToastKind::Error);
        }
        if !matches!(
            self.submission_order.front(),
            Some((sequence, crate::tui::structured_paste::OrderedIntent::SessionSwitch(id)))
                if sequence == switch_sequence && id == switch_id
        ) {
            return Ok(changed);
        }
        self.pending_new_session = false;

        let switch_task = match self.agent_runner.as_ref() {
            Some(Ok(runner)) if runner.can_switch_session() => {
                Some(runner.switch_new_session_task(self.busy))
            }
            _ => None,
        };
        if let Some(switch_task) = switch_task {
            let start = self.async_actions.start(
                AsyncActionKind::Internal("session.switch"),
                Self::session_switch_action_policy(),
                async move {
                    switch_task
                        .await
                        .map(|outcome| AsyncActionPayload::SessionSwitched(Box::new(outcome)))
                },
            );
            debug_assert!(matches!(start, AsyncActionStart::Started(_)));
            self.begin_session_switch_submission_target(agent_runner::SessionTarget::New);
        } else {
            // Without a replaceable attachment there is no old durable
            // runner/view transaction to protect. Commit the local reset
            // immediately and let the normal display/first-submit attach
            // create a fresh session from `session_id: None`.
            self.commit_new_session_without_swappable_runner();
            let _ = self.submission_order.complete(switch_sequence);
            self.pending_session_switch_order = None;
            self.dispatch_next_ready_paste_fence();
            self.clear_terminal_after_committed_new_session(&mut clear_terminal);
        }
        Ok(true)
    }

    fn clear_terminal_after_committed_new_session(
        &mut self,
        clear_terminal: &mut impl FnMut() -> Result<()>,
    ) -> bool {
        if !self.new_session_terminal_clear_pending {
            return false;
        }
        self.new_session_terminal_clear_pending = false;
        // `Terminal::clear` invalidates ratatui's buffers on success, but
        // crossterm may fail its cursor-position probe. The in-memory commit
        // is already complete, so terminal cleanup is always best-effort.
        if let Err(error) = clear_terminal() {
            tracing::warn!(error = %error, "terminal clear after /new failed; continuing with redraw");
        }
        true
    }

    fn reset_new_session_view(&mut self) {
        self.finalize_pending();
        self.history.clear();
        self.reset_session_live_state();
        self.history_render_versions.clear();
        self.history_render_fingerprints.clear();
        self.history_render_cache_clear();
        self.clickable_rows.clear();
        self.box_rows.clear();
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        self.affordance_scroll_regions.clear();
        self.chat_row_meta.clear();
        self.chat_area = None;
        self.chat_geometry = render::ChatGeometry::default();
        self.mark_chat_geometry_dirty_from(0);
        self.chat_find_lines.clear();
        self.chat_find_lines_query = None;
        self.transcript_find = None;
        self.chat_text_grid.clear();
        self.chat_cont_rows.clear();
        self.selection = None;

        // The next attach supplies the authoritative config and usage
        // snapshots; clearing additive tallies prevents double-counting.
        self.usage_models.clear();
        self.usage_slash.clear();
        self.usage_tags.clear();
        self.project_id = None;
        self.pending_usage.clear();
        self.last_usage = None;
        self.estimate_at_last_usage = 0;
        self.current_session_persisted = false;
        self.new_session_terminal_clear_pending = true;
    }

    fn commit_new_session_without_swappable_runner(&mut self) {
        self.cancel_outgoing_turn_if_busy();
        if self.side_conversation.is_some() {
            self.discard_side_conversation_for_replacement(false);
        }
        self.reset_new_session_view();
        self.agent_runner.take();
        self.launch.session_id = None;
        self.launch.session_short_id = None;
        self.foreground_input_target = None;
        self.reset_display_attach_backoff();
    }

    /// Commit a successful `/new` while the switch outcome still owns the
    /// runner transition guard. Old events are drained first; only optimistic
    /// rows created for submissions staged during the attach survive the
    /// outgoing-view reset.
    pub(super) fn commit_new_session_switch_outcome(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
    ) {
        debug_assert!(matches!(outcome.target, agent_runner::SessionTarget::New));
        self.drain_agent_events();
        self.cancel_older_history_page_request();
        let staged_history = self
            .pending_session_switch_submissions
            .iter()
            .flat_map(|pending| pending.optimistic_history.iter().cloned())
            .collect::<Vec<_>>();
        let staged_queue = self
            .pending_session_switch_submissions
            .iter()
            .filter_map(|pending| pending.optimistic_queue_item.clone())
            .collect::<Vec<_>>();
        let owns_working_span = self
            .pending_session_switch_submissions
            .iter()
            .any(|pending| pending.owns_working_span);

        self.reset_new_session_view();
        self.history.extend(staged_history);
        self.queue.extend(staged_queue);
        self.adopt_session_switch_identity(&outcome);
        self.current_session_persisted = false;
        if self.side_conversation.is_some() {
            self.discard_side_conversation_for_replacement(false);
        }
        if owns_working_span {
            self.begin_working_span();
        }
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
        self.drain_agent_events();
        self.cancel_older_history_page_request();
        self.adopt_session_switch_identity(&outcome);
        self.current_session_persisted = current_session_persisted;
    }

    /// Adopt the daemon's completed attach as one ordered identity change.
    /// App's old-epoch controls/config/model state must be cancelled before
    /// AgentRunner publishes the new submission binding. The outcome retains
    /// its transition guard for this entire synchronous adoption.
    fn adopt_session_switch_identity(&mut self, outcome: &agent_runner::SessionSwitchOutcome) {
        self.start_model_state_epoch(
            Some(outcome.session_id),
            outcome.active_model_state.as_ref(),
        );
        if let Some(Ok(runner)) = &mut self.agent_runner {
            runner.apply_session_switch_outcome(outcome);
        }
        self.launch.session_id = Some(outcome.session_id);
        self.launch.session_short_id = Some(outcome.short_id.clone());
        self.project_id = Some(outcome.project_id.clone());
        self.foreground_input_target = outcome.foreground_target.clone();
    }

    fn apply_session_switch_outcome_inner(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
        resume_chrome: bool,
    ) {
        self.drain_agent_events();
        self.cancel_older_history_page_request();
        let resume_history = matches!(outcome.target, agent_runner::SessionTarget::Resume { .. })
            .then(|| wire_history_to_entries(outcome.history.clone()));
        let short_id = outcome.short_id.clone();
        let paused_work = outcome.paused_work.clone();
        let repair_required = outcome.repair_required.clone();
        let btw_fork = outcome.btw_fork.clone();
        let daemon_version = outcome.daemon_version.clone();
        let daemon_compatible = outcome.daemon_compatible;
        if let Some(restored) = resume_history {
            let staged_history = self
                .pending_session_switch_submissions
                .iter()
                .flat_map(|pending| pending.optimistic_history.iter().cloned())
                .collect::<Vec<_>>();
            let staged_queue = self
                .pending_session_switch_submissions
                .iter()
                .filter_map(|pending| pending.optimistic_queue_item.clone())
                .collect::<Vec<_>>();
            let owns_working_span = self
                .pending_session_switch_submissions
                .iter()
                .any(|pending| pending.owns_working_span);
            self.history.clear();
            self.reset_session_live_state();
            self.history.extend(restored);
            self.history.extend(staged_history);
            self.queue.extend(staged_queue);
            if owns_working_span {
                self.begin_working_span();
            }
            self.current_session_persisted = true;
        }
        self.adopt_session_switch_identity(&outcome);
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
