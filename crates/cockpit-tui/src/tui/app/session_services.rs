use super::*;

impl App {
    pub(super) fn mark_submission_fence_handed_off(
        &mut self,
        client_submission_id: uuid::Uuid,
        wire_digest: [u8; 32],
    ) {
        if let Some(fence) = self.submission_fences.get_mut(&client_submission_id)
            && matches!(
                fence.lifecycle,
                crate::tui::structured_paste::FenceLifecycle::Ready
                    | crate::tui::structured_paste::FenceLifecycle::AwaitingProbes
            )
        {
            fence.assembled_wire_digest = Some(wire_digest);
            fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::PossiblySent;
        }
    }

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

    pub(super) fn mark_delivery_unconfirmed(&mut self, ids: &[uuid::Uuid]) -> Result<(), ()> {
        let attachment_epoch = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| {
                runner
                    .attachment_epoch
                    .load(std::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or_default();
        let records = ids
            .iter()
            .map(|id| {
                let fence = self.submission_fences.get(id)?;
                Some(super::DeliveryUnconfirmedRecord {
                    client_submission_id: *id,
                    session_id: fence.host.session_id,
                    text: fence.captured_composer.clone(),
                    wire_digest: fence.assembled_wire_digest?,
                    fence_sequence: fence.fence_sequence,
                    surfaced: false,
                    probe_in_flight: false,
                    next_probe_at: self.event_loop_monotonic_now,
                    probe_deadline: self.event_loop_monotonic_now
                        + std::time::Duration::from_secs(2),
                    probe_attachment_epoch: attachment_epoch,
                    probe_exhausted: false,
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or(())?;
        for (id, record) in ids.iter().copied().zip(records) {
            if let Some(fence) = self.submission_fences.get_mut(&id) {
                fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::Reconciling;
                self.delivery_unconfirmed_records
                    .entry(id)
                    .or_insert(record);
            }
        }
        Ok(())
    }

    pub(super) fn service_delivery_unconfirmed_reconciliation(&mut self) -> bool {
        let socket = self
            .sessions_daemon_socket()
            .map(std::path::Path::to_path_buf);
        let attachment_epoch = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(|runner| {
                runner
                    .attachment_epoch
                    .load(std::sync::atomic::Ordering::Relaxed)
            })
            .unwrap_or_default();
        let now = self.event_loop_monotonic_now;
        for record in self.delivery_unconfirmed_records.values_mut() {
            if record.probe_attachment_epoch != attachment_epoch {
                record.probe_attachment_epoch = attachment_epoch;
                record.probe_deadline = now + std::time::Duration::from_secs(2);
                record.next_probe_at = now;
                record.probe_exhausted = false;
                record.probe_in_flight = false;
            }
            if now >= record.probe_deadline {
                record.probe_exhausted = true;
                record.probe_in_flight = false;
            }
        }
        let Some(socket) = socket else {
            for record in self
                .delivery_unconfirmed_records
                .values_mut()
                .filter(|record| !record.probe_exhausted)
            {
                record.next_probe_at = now + std::time::Duration::from_millis(250);
            }
            return false;
        };
        let pending = self
            .delivery_unconfirmed_records
            .values_mut()
            .filter(|record| {
                !record.probe_exhausted && !record.probe_in_flight && now >= record.next_probe_at
            })
            .map(|record| {
                record.probe_in_flight = true;
                (
                    record.client_submission_id,
                    record.session_id,
                    socket.clone(),
                )
            })
            .collect::<Vec<_>>();
        for (client_submission_id, session_id, socket) in &pending {
            let client_submission_id = *client_submission_id;
            let session_id = *session_id;
            let socket = socket.clone();
            self.async_actions.start(
                AsyncActionKind::Blocking("paste.delivery_receipt"),
                AsyncActionPolicy::AllowConcurrent,
                async move {
                    let result = tokio::task::spawn_blocking(move || {
                        agent_runner::read_client_submission_receipt_blocking(
                            &socket,
                            session_id,
                            client_submission_id,
                        )
                    })
                    .await
                    .map_err(|error| error.to_string())
                    .and_then(|result| result);
                    Ok(AsyncActionPayload::ClientSubmissionReceipt {
                        client_submission_id,
                        result,
                    })
                },
            );
        }
        !pending.is_empty()
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

    /// Force a full alt-screen clear after the `/leaks` reveal buffer was
    /// zeroized (close/hide/detach/timeout), so the revealed plaintext can't
    /// persist in stale backbuffer cells. Best-effort, mirroring the `/new`
    /// clear: the in-memory zeroize already happened, so a failed clear only
    /// degrades to the next full redraw. Returns whether a clear was performed.
    pub(super) fn maybe_service_leaks_reveal_clear(
        &mut self,
        terminal: &mut DefaultTerminal,
    ) -> bool {
        if !self.leaks_reveal_clear_pending {
            return false;
        }
        self.leaks_reveal_clear_pending = false;
        if let Err(error) = terminal.clear() {
            tracing::warn!(
                error = %error,
                "terminal clear after leak-reveal zeroize failed; continuing with redraw"
            );
        }
        true
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
            self.pending_session_switch_reconcile_started_at = None;
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
        let possibly_sent = self
            .submission_fences
            .iter()
            .filter_map(|(id, fence)| {
                (fence.fence_sequence < switch_sequence
                    && matches!(
                        fence.lifecycle,
                        crate::tui::structured_paste::FenceLifecycle::PossiblySent
                            | crate::tui::structured_paste::FenceLifecycle::Reconciling
                    )
                    && !self.delivery_unconfirmed_records.contains_key(id))
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        if !possibly_sent.is_empty() {
            let daemon_link_alive = self.agent_runner.as_ref().is_some_and(|runner| {
                runner
                    .as_ref()
                    .is_ok_and(|runner| runner.can_switch_session())
            });
            let now = self.event_loop_monotonic_now;
            let started = *self
                .pending_session_switch_reconcile_started_at
                .get_or_insert(now);
            match crate::tui::structured_paste::session_switch_reconciliation_gate(
                true,
                daemon_link_alive,
                now.saturating_sub(started),
            ) {
                crate::tui::structured_paste::SessionSwitchReconciliationGate::DaemonLinkLost => {
                    if self.mark_delivery_unconfirmed(&possibly_sent).is_err() {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/new: an earlier submission lacks a reconciliation digest; old session preserved"
                                .to_string(),
                        });
                    }
                    self.pending_new_session = false;
                    self.pending_session_switch_order = None;
                    self.pending_session_switch_reconcile_started_at = None;
                    self.submission_order.cancel(switch_sequence);
                    self.history.push(HistoryEntry::CommandError {
                        line: concat!(
                            "/new: daemon connection lost while reconciling an earlier ",
                            "submission; old session preserved"
                        )
                        .to_string(),
                    });
                    self.dispatch_next_ready_paste_fence();
                    return Ok(true);
                }
                crate::tui::structured_paste::SessionSwitchReconciliationGate::Waiting => {
                    return Ok(changed);
                }
                crate::tui::structured_paste::SessionSwitchReconciliationGate::TimedOut => {}
                crate::tui::structured_paste::SessionSwitchReconciliationGate::Ready => {
                    unreachable!("possibly-sent fences were supplied to the reconciliation gate")
                }
            }
            if self.mark_delivery_unconfirmed(&possibly_sent).is_err() {
                self.pending_new_session = false;
                self.pending_session_switch_order = None;
                self.pending_session_switch_reconcile_started_at = None;
                self.submission_order.cancel(switch_sequence);
                self.history.push(HistoryEntry::CommandError {
                    line: "/new: an earlier submission lacks a reconciliation digest; old session preserved"
                        .to_string(),
                });
                self.dispatch_next_ready_paste_fence();
                return Ok(true);
            }
        }
        self.pending_session_switch_reconcile_started_at = None;
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
            self.cancel_paste_probes_matching(|probe| probe.owner_fence == Some(id));
            self.retained_pre_dispatch_submissions
                .retain(|retained| retained.pending.optimistic_submission_id != id);
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
        self.invalidate_mouse_gesture(
            MouseGestureInvalidation::TerminalChange,
            self.event_loop_monotonic_now,
        );

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
        let mut records = self
            .delivery_unconfirmed_records
            .values_mut()
            .filter(|record| !record.surfaced)
            .collect::<Vec<_>>();
        records.sort_by_key(|record| record.fence_sequence);
        let notices = records
            .into_iter()
            .map(|record| {
                record.surfaced = true;
                let wire_digest = record
                    .wire_digest
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                HistoryEntry::CommandError {
                    line: format!(
                        "Delivery unconfirmed for message {} in session {} (wire {}): {}",
                        record.client_submission_id, record.session_id, wire_digest, record.text
                    ),
                }
            })
            .collect::<Vec<_>>();
        self.history.extend(notices);
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
        // Session navigation changes the owner view before any authoritative
        // replacement state is installed. Blocking results from the previous
        // view are cancelled and cannot mutate the new transcript or chrome.
        self.async_actions.advance_view_generation();
        self.invalidate_mouse_gesture(
            MouseGestureInvalidation::ViewChange,
            self.event_loop_monotonic_now,
        );
        self.at_suggestions_loading = false;
        self.at_suggestions_error = None;
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
