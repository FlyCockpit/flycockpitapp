use super::*;

fn mcp_server_requires_layer_credentials(server: &cockpit_core::mcp::config::ServerConfig) -> bool {
    !server.env_credential_refs.is_empty()
        || server
            .env
            .values()
            .any(|value| !value.trim().is_empty() && !value.trim_start().starts_with('$'))
        || matches!(server.auth, cockpit_core::mcp::config::Auth::Oauth(_))
        || matches!(
            &server.auth,
            cockpit_core::mcp::config::Auth::Header(header)
                if header.credential_ref.is_some()
                    || (!header.value.trim().is_empty()
                        && !header.value.trim_start().starts_with('$'))
        )
        || matches!(
            &server.auth,
            cockpit_core::mcp::config::Auth::Env(env)
                if !env.credential_refs.is_empty()
                    || env.vars.values().any(|value| !value.trim().is_empty()
                        && !value.trim_start().starts_with('$'))
        )
}

fn mcp_mutation_intent_hash(
    project_root: &str,
    patch: &cockpit_proto::McpConfigPatch,
) -> Option<String> {
    use sha2::Digest as _;

    let wire = serde_json::to_string(patch).ok()?;
    let encoded = serde_json::to_vec(&("save_mcp_config", project_root, wire)).ok()?;
    Some(
        sha2::Sha256::digest(&encoded)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    )
}

impl App {
    pub(super) fn apply_local_command_result(
        &mut self,
        label: String,
        raw_output: String,
        failed: bool,
        git_args: Option<String>,
    ) {
        let clean = strip_ansi(&raw_output);
        self.history.push(HistoryEntry::LocalCommand {
            label,
            output: cap_display_lines(&clean),
            failed,
        });
        self.pin_chat_to_tail();
        if let Some(args) = git_args {
            let capped = cap_tokens(&clean, GIT_AGENT_TOKEN_CAP);
            self.pending_git_blocks.push(format!(
                "<git cmd=\"{}\">\n{}\n</git>",
                xml_escape(&args),
                capped
            ));
        }
    }

    /// Resolve a closed `/init` existing-file prompt. `selected_id` is the
    /// chosen option id (or `None` on Esc/cancel). Update/overwrite
    /// dispatch the corresponding agent turn; cancel leaves the file
    /// untouched.
    pub(super) fn resolve_init_choice(&mut self, pending: PendingInit, selected_id: Option<&str>) {
        let mode = match selected_id {
            Some("update") => cockpit_core::init::InitMode::Update,
            Some("overwrite") => cockpit_core::init::InitMode::Overwrite,
            _ => {
                self.push_plain(format!(
                    "/init: cancelled — `{}` left untouched",
                    pending.display
                ));
                return;
            }
        };
        let prompt = cockpit_core::init::build_init_prompt(&pending.display, mode);
        self.dispatch_init_turn(&pending.display, prompt);
    }

    pub(super) fn pending_local_choice_matches(&self, interrupt_id: uuid::Uuid) -> bool {
        self.pending_local_choice
            .as_ref()
            .is_some_and(|choice| choice.interrupt_id() == interrupt_id)
    }

    pub(super) fn pending_local_choice_is_multi(&self) -> bool {
        self.pending_local_choice
            .as_ref()
            .is_some_and(LocalChoice::is_multi)
    }

    pub(super) fn has_pending_session_switch_action(&self) -> bool {
        self.session_switch_in_progress() || !self.pending_session_switch_submissions.is_empty()
    }

    /// Cleared `/new` view is still waiting for a successful adoption (pending
    /// attach or post-failure barrier). Outgoing dispatch must stay suppressed.
    pub(super) fn blocks_outgoing_dispatch_for_cleared_new_session(&self) -> bool {
        self.provisional_new_session && !self.session_switch_in_progress()
    }

    fn session_switch_targets_match(
        left: agent_runner::SessionTarget,
        right: agent_runner::SessionTarget,
    ) -> bool {
        match (left, right) {
            (agent_runner::SessionTarget::New, agent_runner::SessionTarget::New) => true,
            (
                agent_runner::SessionTarget::Resume {
                    session_id: left, ..
                },
                agent_runner::SessionTarget::Resume {
                    session_id: right, ..
                },
            ) => left == right,
            _ => false,
        }
    }

    pub(super) fn begin_session_switch_submission_target(
        &mut self,
        target: agent_runner::SessionTarget,
    ) {
        debug_assert!(self.pending_session_switch_target.is_none());
        debug_assert!(self.pending_ephemeral_session_switch_intent.is_none());
        self.pending_session_switch_target = Some(target);
        if let Some(index) = self
            .retained_session_switch_submissions
            .iter()
            .position(|retained| {
                retained.retry_intent.is_none()
                    && retained.target.is_some_and(|retained_target| {
                        Self::session_switch_targets_match(retained_target, target)
                    })
            })
        {
            let mut retained = self.retained_session_switch_submissions.remove(index);
            self.pending_session_switch_submissions
                .append(&mut retained.submissions);
        }
    }

    pub(super) fn begin_ephemeral_session_switch_submission_target(
        &mut self,
        target: agent_runner::SessionTarget,
        retry_intent: EphemeralSessionSwitchIntent,
    ) {
        debug_assert!(self.pending_session_switch_target.is_none());
        debug_assert!(self.pending_ephemeral_session_switch_intent.is_none());
        self.pending_session_switch_target = Some(target);
        self.pending_ephemeral_session_switch_intent = Some(retry_intent);
        if let Some(index) = self
            .retained_session_switch_submissions
            .iter()
            .position(|retained| retained.retry_intent == Some(retry_intent))
        {
            let mut retained = self.retained_session_switch_submissions.remove(index);
            self.pending_session_switch_submissions
                .append(&mut retained.submissions);
        }
    }

    #[cfg(test)]
    pub(super) fn queue_pending_session_switch_submission(
        &mut self,
        submission: ClientUserSubmission,
        error_prefix: &str,
        optimistic_tag_entries: usize,
        owns_working_span: bool,
    ) {
        self.queue_pending_session_switch_submission_with_optimistic_state(
            submission,
            error_prefix,
            owns_working_span,
            OptimisticSubmissionState {
                id: uuid::Uuid::new_v4(),
                tag_entries: optimistic_tag_entries,
                history: Vec::new(),
                queue_item: None,
            },
        );
    }

    pub(super) fn queue_pending_session_switch_submission_with_optimistic_state(
        &mut self,
        submission: ClientUserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        optimistic: OptimisticSubmissionState,
    ) {
        self.pending_session_switch_submissions
            .push(PendingSessionSwitchSubmission {
                submission,
                optimistic_submission_id: optimistic.id,
                error_prefix: error_prefix.to_string(),
                optimistic_tag_entries: optimistic.tag_entries,
                owns_working_span,
                optimistic_history: optimistic.history,
                optimistic_queue_item: optimistic.queue_item,
            });
    }

    pub(super) fn flush_pending_session_switch_submissions(&mut self) {
        // Cleared `/new` barrier (pending attach or post-failure): never
        // dispatch staged payloads through the still-attached outgoing runner.
        // Successful adoption clears `provisional_new_session` before flush.
        if self.provisional_new_session {
            return;
        }
        let mut pending = std::mem::take(&mut self.pending_session_switch_submissions);
        if pending.is_empty() {
            self.pending_session_switch_target = None;
            self.pending_ephemeral_session_switch_intent = None;
            return;
        }
        let wire_digests = pending
            .iter()
            .map(|pending| {
                (
                    pending.optimistic_submission_id,
                    crate::tui::structured_paste::user_submission_wire_digest(&pending.submission),
                )
            })
            .collect::<Vec<_>>();
        let submissions = pending
            .iter_mut()
            .map(|pending| {
                (
                    pending.optimistic_submission_id,
                    std::mem::take(&mut pending.submission),
                )
            })
            .collect();
        let result = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.try_send_session_switch_inputs(submissions),
            Some(Err(_)) => Err((agent_runner::InputNotDelivered::RunnerClosed, submissions)),
            None => Err((agent_runner::InputNotDelivered::RunnerClosed, submissions)),
        };
        match result {
            Ok(()) => {
                for (id, digest) in wire_digests {
                    self.mark_submission_fence_handed_off(id, digest);
                }
                self.pending_session_switch_target = None;
                self.pending_ephemeral_session_switch_intent = None;
                self.current_session_persisted = true;
                if let Some(pending) = pending.iter().find(|pending| pending.owns_working_span) {
                    self.fresh_queue_ack =
                        FreshQueueAck::AwaitingAck(pending.optimistic_submission_id);
                }
            }
            Err((agent_runner::InputNotDelivered::QueueFull, submissions)) => {
                // A switch task's FIFO flush normally guarantees capacity for
                // the single batch item. If a synthetic runner or future
                // producer violates that invariant, retain every payload and
                // retry on the next App tick; capacity alone is never a
                // delivery failure.
                for (pending, (optimistic_submission_id, submission)) in
                    pending.iter_mut().zip(submissions)
                {
                    debug_assert_eq!(pending.optimistic_submission_id, optimistic_submission_id);
                    pending.submission = submission;
                }
                self.pending_session_switch_submissions = pending;
            }
            Err((agent_runner::InputNotDelivered::RunnerClosed, submissions)) => {
                for (pending, (optimistic_submission_id, submission)) in
                    pending.iter_mut().zip(submissions)
                {
                    debug_assert_eq!(pending.optimistic_submission_id, optimistic_submission_id);
                    pending.submission = submission;
                }
                self.retain_failed_session_switch_submissions(
                    pending,
                    DispatchOutcome::DriverClosed,
                );
            }
        }
    }

    /// Retry only the exceptional backpressure case from the lossless
    /// post-switch batch transfer. Returns whether the pending count changed.
    pub(super) fn retry_pending_session_switch_submissions(&mut self) -> bool {
        if self.provisional_new_session
            || self.session_switch_in_progress()
            || self.pending_session_switch_submissions.is_empty()
        {
            return false;
        }
        let before = self.pending_session_switch_submissions.len();
        self.flush_pending_session_switch_submissions();
        self.pending_session_switch_submissions.len() != before
    }

    pub(super) fn fail_pending_session_switch_submissions(&mut self) {
        let pending = std::mem::take(&mut self.pending_session_switch_submissions);
        self.retain_failed_session_switch_submissions(pending, DispatchOutcome::SessionSwitching);
    }

    pub(super) fn retain_failed_session_switch_submissions(
        &mut self,
        pending: Vec<PendingSessionSwitchSubmission>,
        outcome: DispatchOutcome,
    ) {
        let target = self.pending_session_switch_target.take();
        let retry_intent = self.pending_ephemeral_session_switch_intent.take();
        if pending.is_empty() {
            return;
        }
        for submission in &pending {
            self.reconcile_pending_session_switch_submission(submission, outcome);
        }
        if let Some(group) = self
            .retained_session_switch_submissions
            .iter_mut()
            .find(|group| {
                if let Some(retry_intent) = retry_intent {
                    group.retry_intent == Some(retry_intent)
                } else {
                    group.retry_intent.is_none() && group.target == target
                }
            })
        {
            group.target = target;
            group.submissions.extend(pending);
        } else {
            self.retained_session_switch_submissions
                .push(RetainedSessionSwitchSubmissions {
                    target,
                    retry_intent,
                    submissions: pending,
                });
        }
    }

    fn reconcile_pending_session_switch_submission(
        &mut self,
        pending: &PendingSessionSwitchSubmission,
        outcome: DispatchOutcome,
    ) {
        if self.provisional_new_session {
            // Provisional `/new` already discarded the outgoing view. Keep the
            // exact payloads for retry without reintroducing outgoing-session
            // inference/history rows into the cleared surface.
            if pending.owns_working_span {
                self.fresh_queue_ack = FreshQueueAck::None;
                self.end_working_span();
            }
            return;
        }
        if pending.optimistic_queue_item.is_some()
            && let Some(pos) = self
                .queue
                .iter()
                .position(|item| item.id == pending.optimistic_submission_id)
        {
            self.queue.remove(pos);
        }
        if pending.owns_working_span {
            self.fresh_queue_ack = FreshQueueAck::None;
            self.reconcile_failed_dispatch_by_id(
                outcome,
                &pending.error_prefix,
                pending.optimistic_tag_entries,
                pending.optimistic_submission_id,
            );
            if outcome.span_orphaned() {
                self.end_working_span();
            }
        } else {
            let summary = format!("{}: queued message could not be sent", pending.error_prefix);
            self.history.push(HistoryEntry::InferenceError {
                detail: summary.clone(),
                summary,
                expanded: false,
            });
        }
    }

    pub(super) fn retain_pre_dispatch_submission(
        &mut self,
        intended_session_id: Option<uuid::Uuid>,
        pending: PendingSessionSwitchSubmission,
        outcome: DispatchOutcome,
    ) {
        self.reconcile_pending_session_switch_submission(&pending, outcome);
        self.retained_pre_dispatch_submissions
            .push(RetainedPreDispatchSubmission {
                intended_session_id,
                pending,
            });
    }

    /// Retry app-owned payloads only after the same durable session has an
    /// accepting dispatcher again. A full channel blocks later payloads for
    /// that attachment so FIFO order cannot be inverted.
    pub(super) fn retry_retained_pre_dispatch_submissions(&mut self) -> bool {
        // Cleared `/new` (pending attach or post-failure) must not flush
        // QueueFull leftovers through the still-attached outgoing runner.
        if self.provisional_new_session
            || self.session_switch_in_progress()
            || self.retained_pre_dispatch_submissions.is_empty()
        {
            return false;
        }
        let current_session_id = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.session_id(),
            _ => return false,
        };
        let retained = std::mem::take(&mut self.retained_pre_dispatch_submissions);
        let mut remaining = Vec::with_capacity(retained.len());
        let mut current_attachment_blocked = false;
        let mut changed = false;
        for mut retained in retained {
            if retained.intended_session_id.is_none() {
                retained.intended_session_id = Some(current_session_id);
            }
            if retained.intended_session_id != Some(current_session_id)
                || current_attachment_blocked
            {
                remaining.push(retained);
                continue;
            }
            let submission = std::mem::take(&mut retained.pending.submission);
            let wire_digest =
                crate::tui::structured_paste::user_submission_wire_digest(&submission);
            let result = match self.agent_runner.as_ref() {
                Some(Ok(runner)) => runner.try_send_optimistic_input(
                    submission,
                    retained.pending.optimistic_submission_id,
                ),
                _ => unreachable!("runner checked before retry loop"),
            };
            match result {
                Ok(()) => {
                    self.mark_submission_fence_handed_off(
                        retained.pending.optimistic_submission_id,
                        wire_digest,
                    );
                    changed = true;
                    self.current_session_persisted = true;
                    if retained.pending.owns_working_span {
                        if let Some(HistoryEntry::User { persist_failed, .. }) =
                            self.history.iter_mut().rev().find(|entry| {
                                matches!(
                                    entry,
                                    HistoryEntry::User {
                                        optimistic_submission_id: Some(id),
                                        ..
                                    } if *id == retained.pending.optimistic_submission_id
                                )
                            })
                        {
                            *persist_failed = false;
                        }
                        if !self.busy {
                            self.begin_working_span();
                        }
                        self.fresh_queue_ack =
                            FreshQueueAck::AwaitingAck(retained.pending.optimistic_submission_id);
                    }
                }
                Err((_outcome, submission)) => {
                    retained.pending.submission = *submission;
                    current_attachment_blocked = true;
                    remaining.push(retained);
                }
            }
        }
        self.retained_pre_dispatch_submissions = remaining;
        changed
    }

    pub(super) fn resolve_local_choice(&mut self, selection: LocalChoiceSelection) {
        match self.pending_local_choice.take() {
            Some(LocalChoice::Init(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_init_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::PausedWork(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_paused_work_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::ResumeRepair(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_resume_repair_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::RedactionToggle(_)) => {
                let LocalChoiceSelection::Multi(selected) = selection else {
                    return;
                };
                self.resolve_redaction_toggle(selected.as_deref());
            }
            Some(LocalChoice::ModelComparison(_)) => {
                let LocalChoiceSelection::Multi(selected) = selection else {
                    return;
                };
                self.resolve_model_comparison_select(selected.as_deref());
            }
            None => {}
        }
    }

    /// Send an `/init` turn to the agent: render `/init <target>` as the
    /// user's turn (display side) and hand the full exploration+write
    /// instruction to the agent as the wire (wire/user split, GOALS §14).
    /// Reuses the runner input channel `submit_input` uses, including the
    /// working-span bookkeeping so an orphaned dispatch never hangs the
    /// indicator.
    pub(super) fn dispatch_init_turn(&mut self, display: &str, wire: String) {
        self.pin_chat_to_tail();
        self.begin_working_span();
        let submission = ClientUserSubmission::text(wire);
        self.dispatch_optimistic_user_submission(
            format!("/init {display}"),
            submission,
            "/init",
            true,
            &[],
        );
    }

    pub(super) fn dispatch_optimistic_user_submission(
        &mut self,
        display: String,
        submission: ClientUserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        tag_expansions: &[cockpit_proto::TagExpansionMeta],
    ) -> DispatchOutcome {
        self.dispatch_optimistic_user_submission_with_id(
            uuid::Uuid::new_v4(),
            display,
            submission,
            error_prefix,
            owns_working_span,
            tag_expansions,
        )
    }

    pub(super) fn dispatch_optimistic_user_submission_with_id(
        &mut self,
        optimistic_submission_id: uuid::Uuid,
        display: String,
        mut submission: ClientUserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        tag_expansions: &[cockpit_proto::TagExpansionMeta],
    ) -> DispatchOutcome {
        if submission.display_text.is_none() && submission.text != display {
            submission.display_text = Some(display.clone());
        }
        if submission.tag_expansions.is_empty() && !tag_expansions.is_empty() {
            submission.tag_expansions = tag_expansions.to_vec();
        }
        // Cleared `/new` barrier after a failed/cancelled switch: retain the
        // exact payload for retry without presentation into the discarded view
        // and without dispatching to the outgoing runner.
        if self.blocks_outgoing_dispatch_for_cleared_new_session() {
            if self.pending_session_switch_target.is_none() {
                self.pending_session_switch_target = Some(agent_runner::SessionTarget::New);
            }
            self.retain_failed_session_switch_submissions(
                vec![PendingSessionSwitchSubmission {
                    submission,
                    optimistic_submission_id,
                    error_prefix: error_prefix.to_string(),
                    optimistic_tag_entries: tag_expansions.len(),
                    owns_working_span,
                    optimistic_history: Vec::new(),
                    optimistic_queue_item: None,
                }],
                DispatchOutcome::SessionSwitching,
            );
            // Must not report Sent: structured-paste callers treat Sent as a
            // real daemon dispatch and mark fences PossiblySent.
            return DispatchOutcome::SessionSwitching;
        }
        self.lock_pending_agent_switch_log();
        let optimistic_history_start = self.history.len();
        self.history.push(HistoryEntry::User {
            text: display,
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            optimistic_submission_id: Some(optimistic_submission_id),
            preflight_pending: false,
            persist_failed: false,
        });
        self.push_tag_call_entries(tag_expansions);
        let optimistic_history = self
            .history
            .iter()
            .skip(optimistic_history_start)
            .cloned()
            .collect();
        if self.has_pending_session_switch_action() {
            self.queue_pending_session_switch_submission_with_optimistic_state(
                submission,
                error_prefix,
                owns_working_span,
                OptimisticSubmissionState {
                    id: optimistic_submission_id,
                    tag_entries: tag_expansions.len(),
                    history: optimistic_history,
                    queue_item: None,
                },
            );
            return DispatchOutcome::Sent;
        }
        self.ensure_agent_runner();
        let intended_session_id = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(agent_runner::AgentRunner::session_id)
            .or(self.launch.session_id);
        let (outcome, undelivered_submission) = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => match runner
                .try_send_optimistic_input(submission, optimistic_submission_id)
            {
                Ok(_) => {
                    self.current_session_persisted = true;
                    if owns_working_span {
                        self.fresh_queue_ack = FreshQueueAck::AwaitingAck(optimistic_submission_id);
                    }
                    (DispatchOutcome::Sent, None)
                }
                Err((agent_runner::InputNotDelivered::QueueFull, submission)) => {
                    (DispatchOutcome::QueueFull, Some(*submission))
                }
                Err((agent_runner::InputNotDelivered::RunnerClosed, submission)) => {
                    (DispatchOutcome::DriverClosed, Some(*submission))
                }
            },
            Some(Err(_)) => (DispatchOutcome::RunnerFailed, Some(submission)),
            None => (DispatchOutcome::NoRunner, Some(submission)),
        };
        if let Some(submission) = undelivered_submission {
            if owns_working_span {
                self.fresh_queue_ack = FreshQueueAck::None;
            }
            self.retain_pre_dispatch_submission(
                intended_session_id,
                PendingSessionSwitchSubmission {
                    submission,
                    optimistic_submission_id,
                    error_prefix: error_prefix.to_string(),
                    optimistic_tag_entries: tag_expansions.len(),
                    owns_working_span,
                    optimistic_history,
                    optimistic_queue_item: None,
                },
                outcome,
            );
        }
        outcome
    }

    #[cfg(test)]
    pub(super) fn reconcile_failed_dispatch(
        &mut self,
        outcome: DispatchOutcome,
        error_prefix: &str,
        optimistic_tag_entries: usize,
    ) {
        let Some(optimistic_submission_id) = self.history.iter().rev().find_map(|entry| {
            if let HistoryEntry::User {
                optimistic_submission_id: Some(id),
                seq: None,
                persist_failed: false,
                ..
            } = entry
            {
                Some(*id)
            } else {
                None
            }
        }) else {
            self.history.push(HistoryEntry::CommandError {
                line: failed_dispatch_line(error_prefix, outcome),
            });
            return;
        };
        self.reconcile_failed_dispatch_by_id(
            outcome,
            error_prefix,
            optimistic_tag_entries,
            optimistic_submission_id,
        );
    }

    fn reconcile_failed_dispatch_by_id(
        &mut self,
        outcome: DispatchOutcome,
        error_prefix: &str,
        optimistic_tag_entries: usize,
        optimistic_submission_id: uuid::Uuid,
    ) {
        if let Some(idx) = self.history.iter().position(|entry| {
            matches!(
                entry,
                HistoryEntry::User {
                    optimistic_submission_id: Some(id),
                    seq: None,
                    persist_failed: false,
                    ..
                } if *id == optimistic_submission_id
            )
        }) {
            for _ in 0..optimistic_tag_entries {
                if idx + 1 < self.history.len() {
                    self.history.remove(idx + 1);
                }
            }
            if let HistoryEntry::User {
                preflight_pending,
                persist_failed,
                ..
            } = self.history.get_mut(idx).expect("matched history index")
            {
                *preflight_pending = false;
                *persist_failed = true;
            }
        }
        self.history.push(HistoryEntry::CommandError {
            line: failed_dispatch_line(error_prefix, outcome),
        });
    }

    pub(super) fn resolve_paused_work_choice(
        &mut self,
        pending: PendingPausedWork,
        selected_id: Option<&str>,
    ) {
        let request = match selected_id {
            Some("resume") => {
                self.push_plain("/resume: resuming paused daemon work.".to_string());
                cockpit_proto::Request::ResumePausedWork {
                    session_id: pending.session_id,
                }
            }
            Some("cancel") | None => {
                self.push_plain("/resume: cancelled paused daemon work.".to_string());
                cockpit_proto::Request::CancelPausedWork {
                    session_id: pending.session_id,
                }
            }
            Some(_) => return,
        };
        self.send_daemon_request("/resume", request, ControlApplied::None);
    }

    pub(super) fn show_goal_status(&mut self) {
        let Some(session_id) = self.goal_session_id("/goal") else {
            return;
        };
        self.start_goal_request(
            "goal.disposition",
            cockpit_proto::Request::GoalStatus { session_id },
        );
    }

    pub(super) fn create_goal(&mut self, objective: String, token_budget: Option<i64>) {
        let Some(session_id) = self.goal_session_id("/goal") else {
            return;
        };
        self.start_goal_request(
            "goal.create",
            cockpit_proto::Request::CreateGoal {
                session_id,
                objective,
                token_budget,
            },
        );
    }

    pub(super) fn set_goal_status(&mut self, status: cockpit_proto::GoalDisposition, label: &str) {
        let Some(session_id) = self.goal_session_id(label) else {
            return;
        };
        self.start_goal_request(
            "goal.set",
            cockpit_proto::Request::SetGoalStatus { session_id, status },
        );
    }

    pub(super) fn clear_goal(&mut self) {
        let Some(session_id) = self.goal_session_id("/goal clear") else {
            return;
        };
        self.start_goal_request(
            "goal.clear",
            cockpit_proto::Request::ClearGoal { session_id },
        );
    }

    fn goal_session_id(&mut self, label: &str) -> Option<uuid::Uuid> {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id()),
            _ => {
                self.report_control_not_delivered(
                    label,
                    cockpit_client::presentation::ControlRequestNotDelivered::NoRunner,
                );
                None
            }
        }
    }

    fn start_goal_request(&mut self, kind: &'static str, request: cockpit_proto::Request) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            unreachable!("goal_session_id checks the attached runner first");
        };
        let attached_request = runner.attached_request_binding();
        self.async_actions.start(
            AsyncActionKind::DaemonRpc(kind),
            AsyncActionPolicy::AllowConcurrent,
            async move {
                let response = attached_request.request(request).await?;
                match response {
                    cockpit_proto::Response::GoalStatus { goal: Some(goal) } => {
                        let phase = goal.phase.map(|phase| format!("/{phase:?}")).unwrap_or_default();
                        let detail = goal.latest_gap_or_blocker.as_deref().unwrap_or("no actionable gap");
                        Ok(AsyncActionPayload::Text(format!(
                            "/goal: {}{} · {} · contract {} · pause {} · verification {}/{} · tokens {}/{} ({} remaining) · active {}ms · {} transitions · {} · subcommands: status, pause, resume, clear, edit",
                            goal.disposition.as_str(),
                            phase.to_ascii_lowercase(),
                            goal.objective,
                            if goal.contract_available { "ready" } else { "planning" },
                            goal.pause_reason
                                .map(|reason| reason.as_str())
                                .unwrap_or("none"),
                            goal.verification_attempts,
                            goal.max_verification_attempts,
                            goal.tokens_used,
                            goal.token_budget,
                            goal.remaining_tokens,
                            goal.elapsed_active_ms,
                            goal.lifecycle_history.len(),
                            detail,
                        )))
                    }
                    cockpit_proto::Response::GoalStatus { goal: None } => Ok(
                        AsyncActionPayload::Text(
                            "/goal: no goal. Usage: /goal <objective> | status | pause | resume | clear | edit"
                                .to_string(),
                        ),
                    ),
                    cockpit_proto::Response::GoalUpdated { goal } => {
                        let state = match goal.disposition {
                            cockpit_proto::GoalDisposition::Running => "active",
                            cockpit_proto::GoalDisposition::UserPaused => "paused",
                            cockpit_proto::GoalDisposition::InfraPaused => {
                                "paused by infrastructure"
                            }
                            cockpit_proto::GoalDisposition::Blocked => "blocked",
                            cockpit_proto::GoalDisposition::NoProgressPaused => {
                                "paused for no progress"
                            }
                            cockpit_proto::GoalDisposition::BudgetLimited => {
                                "budget limited"
                            }
                            cockpit_proto::GoalDisposition::Complete => "complete",
                            cockpit_proto::GoalDisposition::Cleared => "cleared",
                        };
                        Ok(AsyncActionPayload::Text(format!(
                            "/goal: goal is now {state}."
                        )))
                    }
                    cockpit_proto::Response::GoalCleared { cleared: true } => Ok(
                        AsyncActionPayload::Text("/goal clear: cleared current goal.".to_string()),
                    ),
                    cockpit_proto::Response::GoalCleared { cleared: false } => Ok(
                        AsyncActionPayload::Text("/goal clear: no open goal.".to_string()),
                    ),
                    other => Err(format!("unexpected goal response: {other:?}")),
                }
            },
        );
    }

    /// Dispatch a user-issued skill slash command
    /// (implementation note): seed a deterministic `skill`
    /// tool call for `name` before the turn's inference and forward `args`
    /// (possibly empty) as the accompanying task input.
    ///
    /// `display` is the user-facing turn label (`/<name> args` for the bare
    /// form, `/skill <name> args` for the dispatcher). The seed itself rides
    /// in `UserSubmission::forced_skill`, so the harness — not the model —
    /// loads the skill body (priority #1). Reuses the runner-input dispatch
    /// `dispatch_init_turn` uses, including the working-span bookkeeping.
    pub(super) fn dispatch_skill_invocation(&mut self, display: String, name: &str, args: &str) {
        self.pin_chat_to_tail();
        self.begin_working_span();
        let submission = ClientUserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_client::submission::UserSubmissionKind::User,
            origin: cockpit_client::submission::SubmissionOrigin::ExternalRoot,
            text: args.trim().to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: Some(name.to_string()),
            ..Default::default()
        };
        self.dispatch_optimistic_user_submission(display, submission, "/skill", true, &[]);
    }

    /// The id of the session this client is attached to (live runner if
    /// connected, else the last-attached id from launch info). `None`
    /// before the first session exists. Same resolution `/rename` uses.
    pub(super) fn current_session_id(&self) -> Option<uuid::Uuid> {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id()),
            _ => self.launch.session_id,
        }
    }

    /// Job ids in `active_schedules` that belong to the current session, in the
    /// map's (stable, job-id) order. The single filter `/ps` and `/stop`
    /// share so the listed set, the cancel set, and the confirm count can
    /// never disagree. Empty when there's no current session or no jobs.
    pub(super) fn current_session_job_ids(&self) -> Vec<String> {
        match self.current_session_id() {
            Some(sid) => session_schedule_ids(&self.active_schedules, sid),
            None => Vec::new(),
        }
    }

    /// Send a `CancelSchedule` for one job over the response-bearing control
    /// channel. `cmd` is the command label for the rendered line.
    pub(super) fn cancel_schedule(&mut self, job_id: &str, cmd: &str) {
        self.send_daemon_request(
            cmd,
            cockpit_proto::Request::CancelSchedule {
                job_id: job_id.to_string(),
            },
            ControlApplied::ScheduleCancel {
                command: cmd.to_string(),
                job_id: job_id.to_string(),
            },
        );
    }

    /// Bare `/stop`: count the current-session jobs and arm the `[y/N]`
    /// confirm (mirrors `/prune`'s arm-then-commit). With zero jobs it
    /// says so and arms nothing.
    pub(super) fn arm_stop_confirm(&mut self) {
        let ids = self.current_session_job_ids();
        if ids.is_empty() {
            self.push_plain("No background jobs in this session.".to_string());
            self.pending_stop_confirm = None;
            return;
        }
        let n = ids.len();
        self.push_plain(format!("/stop: Stop {n} job(s) in this session? [y/N]"));
        self.pending_stop_confirm = Some(ids);
    }

    /// Commit an armed bare `/stop`: cancel every job captured at arm
    /// time. A job that already ended (no longer in `active_schedules`) is
    /// skipped silently — its strip entry is already gone.
    pub(super) fn commit_stop(&mut self) {
        let Some(ids) = self.pending_stop_confirm.take() else {
            return;
        };
        let mut cancelled = 0;
        for job_id in ids {
            if self.active_schedules.contains_key(&job_id) {
                self.cancel_schedule(&job_id, "/stop");
                cancelled += 1;
            }
        }
        if cancelled == 0 {
            self.push_plain("/stop: those jobs already ended.".to_string());
        }
    }

    /// Cancel an armed bare `/stop`.
    pub(super) fn cancel_stop(&mut self) {
        self.pending_stop_confirm = None;
        self.push_plain("/stop: cancelled.".to_string());
    }

    /// Last asynchronously published daemon projection. Rendering and slash
    /// ranking may inspect this cache but never start an RPC.
    pub(super) fn mcp_snapshot(&self) -> Option<cockpit_core::mcp::config::McpConfig> {
        #[cfg(test)]
        MCP_LOAD_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.mcp_local_snapshot.clone()
    }

    fn replace_mcp_local_action(
        &mut self,
        operation_id: uuid::Uuid,
        project_root: String,
        intent: McpLocalIntent,
        phase: McpLocalPhase,
        config: Option<cockpit_core::mcp::config::McpConfig>,
        mutation_intent_hash: Option<String>,
        authority: Option<McpLocalAuthority>,
        request: cockpit_proto::Request,
    ) {
        self.slash_menu_cache.borrow_mut().take();
        if let Some(pending) = self.pending_mcp_local.take() {
            self.async_actions.abort_id(pending.action_id);
        }
        let transport = crate::tui::settings::capture_settings_daemon(self.lifecycle.clone());
        let completion_project_root = project_root.clone();
        let completion_intent = intent.clone();
        let completion_phase = phase.clone();
        let settlement_probe = matches!(phase, McpLocalPhase::Settlement);
        let action_id = self
            .async_actions
            .start(
                crate::tui::async_action::AsyncActionKind::DaemonRpc("mcp.local"),
                crate::tui::async_action::AsyncActionPolicy::Replace(
                    crate::tui::async_action::AsyncActionKey::new("mcp.local"),
                ),
                async move {
                    if settlement_probe {
                        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                    }
                    let response = transport.request(request).await;
                    Ok(crate::tui::async_action::AsyncActionPayload::McpLocal(
                        McpLocalCompletion {
                            operation_id,
                            project_root: completion_project_root,
                            intent: completion_intent,
                            phase: completion_phase,
                            response,
                        },
                    ))
                },
            )
            .id();
        self.pending_mcp_local = Some(PendingMcpLocal {
            action_id,
            operation_id,
            project_root,
            intent,
            phase,
            config,
            mutation_intent_hash,
            authority,
        });
    }

    fn start_mcp_settlement(&mut self, pending: PendingMcpLocal, announce: bool) {
        if announce {
            self.push_plain(
                "/mcp: save response was not observed; checking its durable receipt…".to_string(),
            );
        }
        self.replace_mcp_local_action(
            pending.operation_id,
            pending.project_root.clone(),
            pending.intent,
            McpLocalPhase::Settlement,
            pending.config,
            pending.mutation_intent_hash,
            pending.authority,
            cockpit_proto::Request::GetLocalOperationSettlement {
                client_operation_id: pending.operation_id.to_string(),
            },
        );
    }

    fn retry_mcp_refresh(&mut self, pending: PendingMcpLocal) {
        let snapshot_session_id = match &pending.phase {
            McpLocalPhase::Refresh {
                snapshot_session_id,
                ..
            } => snapshot_session_id.clone(),
            _ => {
                self.start_mcp_settlement(pending, false);
                return;
            }
        };
        self.replace_mcp_local_action(
            pending.operation_id,
            pending.project_root.clone(),
            pending.intent,
            pending.phase.clone(),
            pending.config,
            pending.mutation_intent_hash,
            pending.authority,
            cockpit_proto::Request::GetProviderCatalogSnapshot {
                project_root: pending.project_root,
                provider_id: None,
                snapshot_session_id,
            },
        );
    }

    fn render_mcp_list(&mut self, cfg: &cockpit_core::mcp::config::McpConfig) {
        if cfg.servers.is_empty() {
            self.push_plain("No MCP servers configured.".to_string());
            return;
        }
        for (name, s) in &cfg.servers {
            let color = crate::tui::settings::mcp_row_color(name, s);
            let dot = match color {
                ratatui::style::Color::Green => "●",
                ratatui::style::Color::Yellow => "○",
                _ => "✗",
            };
            self.push_plain(format!(
                "{dot} {name}  {}  {}  auth={}",
                s.transport.as_str(),
                if s.enabled { "enabled" } else { "disabled" },
                s.auth.kind_str(),
            ));
        }
    }

    fn start_mcp_snapshot(&mut self, intent: McpLocalIntent) {
        if self.pending_mcp_local.is_some() {
            self.push_plain(
                "/mcp: another MCP operation is pending; wait for durable settlement before issuing a new command."
                    .to_string(),
            );
            return;
        }
        let operation_id = uuid::Uuid::new_v4();
        let project_root = self.launch.cwd.display().to_string();
        let snapshot_session_id = uuid::Uuid::new_v4().to_string();
        self.push_plain("/mcp: loading daemon-owned configuration…".to_string());
        self.replace_mcp_local_action(
            operation_id,
            project_root.clone(),
            intent,
            McpLocalPhase::Snapshot {
                snapshot_session_id: snapshot_session_id.clone(),
            },
            None,
            None,
            None,
            cockpit_proto::Request::GetProviderCatalogSnapshot {
                project_root,
                provider_id: None,
                snapshot_session_id,
            },
        );
    }

    pub(super) fn mcp_list(&mut self) {
        self.start_mcp_snapshot(McpLocalIntent::List);
    }

    /// `/mcp on|off|toggle [id]`. `enable=None` toggles; a mixed set toggled
    /// in bulk turns all **off** (spec). `id=None` applies to every server.
    pub(super) fn mcp_set_enabled(&mut self, id: Option<&str>, enable: Option<bool>) {
        self.start_mcp_snapshot(McpLocalIntent::SetEnabled {
            server_id: id.map(str::to_string),
            enabled: enable,
        });
    }

    pub(super) fn apply_mcp_local_completion(
        &mut self,
        action_id: crate::tui::async_action::AsyncActionId,
        completion: McpLocalCompletion,
    ) {
        let Some(pending) = self.pending_mcp_local.as_ref() else {
            return;
        };
        if pending.action_id != action_id
            || pending.operation_id != completion.operation_id
            || pending.project_root != completion.project_root
            || pending.intent != completion.intent
            || pending.phase != completion.phase
        {
            return;
        }
        let pending = self.pending_mcp_local.take().expect("matched above");
        let response = match completion.response {
            Ok(response) => response,
            Err(error) => {
                match &pending.phase {
                    McpLocalPhase::Save | McpLocalPhase::Settlement => self.start_mcp_settlement(
                        pending,
                        matches!(completion.phase, McpLocalPhase::Save),
                    ),
                    McpLocalPhase::Refresh { .. } => {
                        self.push_plain(format!(
                            "/mcp: committed refresh was interrupted ({error}); retrying…"
                        ));
                        self.retry_mcp_refresh(pending);
                    }
                    McpLocalPhase::Snapshot { .. } => self.push_plain(format!("/mcp: {error}")),
                }
                return;
            }
        };

        match pending.phase {
            McpLocalPhase::Snapshot {
                snapshot_session_id,
            } => {
                let cockpit_proto::Response::ProviderCatalogSnapshot {
                    config,
                    snapshot_session_id: returned_session_id,
                    ..
                } = response
                else {
                    self.push_plain("/mcp: unexpected daemon snapshot response".to_string());
                    return;
                };
                if returned_session_id != snapshot_session_id {
                    self.push_plain("/mcp: stale daemon snapshot was rejected".to_string());
                    return;
                }
                let Some(raw) = config.mcp_config_json else {
                    self.push_plain("/mcp: daemon snapshot omitted MCP configuration".to_string());
                    return;
                };
                let Some(authored_raw) = config.mcp_authored_config_json else {
                    self.push_plain(
                        "/mcp: daemon snapshot omitted authored MCP configuration".to_string(),
                    );
                    return;
                };
                let Ok(authored) = cockpit_core::mcp::config::McpConfig::parse(&authored_raw)
                else {
                    self.push_plain(
                        "/mcp: daemon returned an invalid authored MCP layer".to_string(),
                    );
                    return;
                };
                let (
                    Some(owner_root),
                    Some(config_path),
                    Some(snapshot_capability),
                    Some(revision),
                ) = (
                    config.mcp_owner_root,
                    config.mcp_config_path,
                    config.mcp_edit_capability,
                    config.mcp_revision,
                )
                else {
                    self.push_plain(
                        "/mcp: daemon snapshot omitted edit authority; reload required".to_string(),
                    );
                    return;
                };
                let authority = McpLocalAuthority {
                    snapshot_capability,
                    owner_root,
                    config_path,
                    revision,
                };
                let Ok(mut mcp) = cockpit_core::mcp::config::McpConfig::parse(&raw) else {
                    self.push_plain("/mcp: daemon returned an invalid MCP projection".to_string());
                    return;
                };
                self.mcp_local_snapshot = Some(mcp.clone());
                self.slash_menu_cache.borrow_mut().take();
                match pending.intent.clone() {
                    McpLocalIntent::List => self.render_mcp_list(&mcp),
                    McpLocalIntent::SetEnabled { server_id, enabled } => {
                        let original = mcp.clone();
                        if let Some(server_id) = server_id {
                            let Some(server) = mcp.servers.get_mut(&server_id) else {
                                self.push_plain(format!("Unknown MCP server `{server_id}`"));
                                return;
                            };
                            server.enabled = enabled.unwrap_or(!server.enabled);
                        } else {
                            let target = enabled.unwrap_or_else(|| {
                                !mcp.servers.values().any(|server| server.enabled)
                            });
                            for server in mcp.servers.values_mut() {
                                server.enabled = target;
                            }
                        }
                        if let Some((name, _)) = mcp.servers.iter().find(|(name, server)| {
                            original.servers.get(*name) != Some(*server)
                                && !authored.servers.contains_key(*name)
                                && mcp_server_requires_layer_credentials(server)
                        }) {
                            self.push_plain(format!(
                                "/mcp: `{name}` inherits credentials; re-enter them in this layer before overriding it"
                            ));
                            return;
                        }
                        let operations = mcp
                            .servers
                            .iter()
                            .filter(|(name, server)| original.servers.get(*name) != Some(*server))
                            .map(|(name, server)| {
                                if authored.servers.contains_key(name) {
                                    Ok(cockpit_proto::McpConfigPatchOperation::UpdateAuthoredServer {
                                        name: name.clone(),
                                        set_fields_json: serde_json::json!({
                                            "enabled": server.enabled,
                                        })
                                        .to_string()
                                        .into(),
                                        unset_fields: Vec::new(),
                                    })
                                } else {
                                    serde_json::to_string(server).map(|server_json| {
                                        cockpit_proto::McpConfigPatchOperation::MaterializeInheritedServer {
                                            name: name.clone(),
                                            server_json: server_json.into(),
                                        }
                                    })
                                }
                            })
                            .collect::<std::result::Result<Vec<_>, _>>();
                        let patch = match operations {
                            Ok(operations) => cockpit_proto::McpConfigPatch { operations },
                            Err(error) => {
                                self.push_plain(format!(
                                    "/mcp: failed to serialize daemon projection: {error}"
                                ));
                                return;
                            }
                        };
                        self.push_plain("/mcp: saving configuration…".to_string());
                        let Some(mutation_intent_hash) =
                            mcp_mutation_intent_hash(&pending.project_root, &patch)
                        else {
                            self.push_plain(
                                "/mcp: failed to bind the save mutation intent".to_string(),
                            );
                            return;
                        };
                        let patch_wire = match serde_json::to_string(&patch) {
                            Ok(wire) => wire,
                            Err(error) => {
                                self.push_plain(format!(
                                    "/mcp: failed to encode the typed mutation: {error}"
                                ));
                                return;
                            }
                        };
                        let request = cockpit_proto::Request::SaveMcpConfig {
                            client_operation_id: pending.operation_id.to_string(),
                            project_root: pending.project_root.clone(),
                            snapshot_capability: authority.snapshot_capability.clone(),
                            owner_root: authority.owner_root.clone(),
                            config_path: authority.config_path.clone(),
                            expected_revision: authority.revision.clone(),
                            mutation_intent_hash: mutation_intent_hash.clone(),
                            patch: cockpit_proto::SensitiveWirePayload::new(patch_wire),
                            secret_values_json: cockpit_proto::SensitiveWirePayload::new(
                                "{}".to_string(),
                            ),
                        };
                        self.replace_mcp_local_action(
                            pending.operation_id,
                            pending.project_root.clone(),
                            pending.intent,
                            McpLocalPhase::Save,
                            Some(mcp),
                            Some(mutation_intent_hash),
                            Some(authority),
                            request,
                        );
                    }
                }
            }
            McpLocalPhase::Save => {
                let cockpit_proto::Response::McpConfigCommitted {
                    client_operation_id,
                    request_hash,
                    mutation_intent_hash,
                    project_root,
                    owner_root,
                    config_path,
                    consumed_revision,
                    result_revision,
                    config_generation,
                    ..
                } = response
                else {
                    self.start_mcp_settlement(pending, true);
                    return;
                };
                if client_operation_id != pending.operation_id.to_string()
                    || project_root != pending.project_root
                    || request_hash.len() != 64
                    || !request_hash
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                    || pending.mutation_intent_hash.as_deref()
                        != Some(mutation_intent_hash.as_str())
                    || pending.authority.as_ref().is_none_or(|authority| {
                        authority.owner_root != owner_root
                            || authority.config_path != config_path
                            || authority.revision != consumed_revision
                    })
                {
                    self.start_mcp_settlement(pending, true);
                    return;
                }
                let snapshot_session_id = uuid::Uuid::new_v4().to_string();
                self.replace_mcp_local_action(
                    pending.operation_id,
                    pending.project_root.clone(),
                    pending.intent,
                    McpLocalPhase::Refresh {
                        snapshot_session_id: snapshot_session_id.clone(),
                        result_revision,
                        config_generation,
                    },
                    pending.config,
                    pending.mutation_intent_hash,
                    pending.authority,
                    cockpit_proto::Request::GetProviderCatalogSnapshot {
                        project_root: pending.project_root,
                        provider_id: None,
                        snapshot_session_id,
                    },
                );
            }
            McpLocalPhase::Settlement => {
                let cockpit_proto::Response::LocalOperationSettlement {
                    client_operation_id,
                    operation_kind,
                    request_hash,
                    pending: is_pending,
                    response,
                    terminal_error,
                    terminal_cancelled,
                } = response
                else {
                    self.start_mcp_settlement(pending, false);
                    return;
                };
                if client_operation_id != pending.operation_id.to_string()
                    || operation_kind != "save_mcp_config"
                    || request_hash.len() != 64
                    || !request_hash
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
                {
                    self.push_plain(
                        "/mcp: durable settlement response did not match the save request; editing remains unsafe."
                            .to_string(),
                    );
                    self.start_mcp_settlement(pending, false);
                    return;
                }
                if is_pending {
                    self.start_mcp_settlement(pending, false);
                    return;
                }
                if terminal_cancelled {
                    self.push_plain("/mcp: save was durably cancelled.".to_string());
                    return;
                }
                if let Some(error) = terminal_error {
                    self.push_plain(format!("/mcp: save rejected by daemon: {}", error.message));
                    return;
                }
                let Some(receipt) = response else {
                    self.push_plain(
                        "/mcp: durable settlement was terminal without a save receipt.".to_string(),
                    );
                    self.start_mcp_settlement(pending, false);
                    return;
                };
                let cockpit_proto::Response::McpConfigCommitted {
                    client_operation_id,
                    request_hash: receipt_request_hash,
                    mutation_intent_hash,
                    project_root,
                    owner_root,
                    config_path,
                    consumed_revision,
                    result_revision,
                    config_generation,
                    ..
                } = *receipt
                else {
                    self.push_plain(
                        "/mcp: durable settlement returned the wrong receipt type.".to_string(),
                    );
                    self.start_mcp_settlement(pending, false);
                    return;
                };
                if client_operation_id != pending.operation_id.to_string()
                    || project_root != pending.project_root
                    || receipt_request_hash != request_hash
                    || pending.mutation_intent_hash.as_deref()
                        != Some(mutation_intent_hash.as_str())
                    || pending.authority.as_ref().is_none_or(|authority| {
                        authority.owner_root != owner_root
                            || authority.config_path != config_path
                            || authority.revision != consumed_revision
                    })
                {
                    self.push_plain(
                        "/mcp: durable save receipt did not match the requested target."
                            .to_string(),
                    );
                    self.start_mcp_settlement(pending, false);
                    return;
                }
                let snapshot_session_id = uuid::Uuid::new_v4().to_string();
                self.replace_mcp_local_action(
                    pending.operation_id,
                    pending.project_root.clone(),
                    pending.intent,
                    McpLocalPhase::Refresh {
                        snapshot_session_id: snapshot_session_id.clone(),
                        result_revision,
                        config_generation,
                    },
                    pending.config,
                    pending.mutation_intent_hash,
                    pending.authority,
                    cockpit_proto::Request::GetProviderCatalogSnapshot {
                        project_root: pending.project_root,
                        provider_id: None,
                        snapshot_session_id,
                    },
                );
            }
            McpLocalPhase::Refresh {
                ref snapshot_session_id,
                ref result_revision,
                config_generation,
            } => {
                let cockpit_proto::Response::ProviderCatalogSnapshot {
                    config,
                    snapshot_session_id: returned_session_id,
                    config_generation: returned_generation,
                    ..
                } = response
                else {
                    self.push_plain(
                        "/mcp: saved, but the refreshed configuration is unavailable; retrying"
                            .to_string(),
                    );
                    self.retry_mcp_refresh(pending);
                    return;
                };
                if returned_session_id != snapshot_session_id.as_str()
                    || returned_generation < config_generation
                {
                    self.push_plain(
                        "/mcp: saved, but the refreshed configuration did not match its receipt"
                            .to_string(),
                    );
                    self.retry_mcp_refresh(pending);
                    return;
                }
                if pending.authority.as_ref().is_none_or(|authority| {
                    config.mcp_owner_root.as_deref() != Some(authority.owner_root.as_str())
                        || config.mcp_config_path.as_deref() != Some(authority.config_path.as_str())
                        || config.mcp_revision.as_deref() != Some(result_revision.as_str())
                        || config
                            .mcp_edit_capability
                            .as_deref()
                            .is_none_or(str::is_empty)
                }) {
                    self.push_plain(
                        "/mcp: committed refresh did not carry matching edit authority; retrying"
                            .to_string(),
                    );
                    self.retry_mcp_refresh(pending);
                    return;
                }
                let Some(raw) = config.mcp_config_json else {
                    self.push_plain(
                        "/mcp: saved, but the refreshed MCP projection was absent".to_string(),
                    );
                    self.retry_mcp_refresh(pending);
                    return;
                };
                let Ok(mcp) = cockpit_core::mcp::config::McpConfig::parse(&raw) else {
                    self.push_plain(
                        "/mcp: saved, but the refreshed MCP projection was invalid".to_string(),
                    );
                    self.retry_mcp_refresh(pending);
                    return;
                };
                self.mcp_local_snapshot = Some(mcp.clone());
                self.slash_menu_cache.borrow_mut().take();
                self.push_plain("/mcp: configuration saved.".to_string());
                self.render_mcp_list(&mcp);
            }
        }
    }

    pub(super) fn apply_mcp_local_cancellation(
        &mut self,
        action_id: crate::tui::async_action::AsyncActionId,
    ) {
        if self
            .pending_mcp_local
            .as_ref()
            .is_some_and(|pending| pending.action_id == action_id)
        {
            let pending = self.pending_mcp_local.take().expect("matched above");
            if !matches!(pending.phase, McpLocalPhase::Snapshot { .. }) {
                self.push_plain(
                    "/mcp: operation interrupted; retaining the mutation fence while durable settlement is checked."
                        .to_string(),
                );
                self.start_mcp_settlement(pending, false);
            } else {
                self.push_plain("/mcp: operation cancelled.".to_string());
            }
        }
    }

    /// Shared cache-break warning helper. Returns the one-line warning to
    /// show when an action busts the cached system prefix. Returns `None` when the warning is
    /// meaningless because the active model/provider does not cache: reuses
    /// the pruning-policy no-cache predicate
    /// ([`cockpit_core::engine::prune::cache_state`] →
    /// [`cockpit_core::engine::prune::ColdReason::NoCacheProvider`]) rather than
    /// re-deriving "does this provider cache."
    pub(super) fn cache_break_warning(&self) -> Option<String> {
        if self.active_provider_caches() {
            Some(
                "Heads up: switching busts the prompt cache — the next call re-sends the \
                 full prefix uncached."
                    .to_string(),
            )
        } else {
            // No-cache provider: nothing to bust, so no warning.
            None
        }
    }

    pub(super) fn llm_mode_switch_warning(&self) -> Option<String> {
        if self.active_provider_caches() {
            Some(
                "Heads up: switching LLM mode forces a prune, updates tool descriptions, \
                 and busts the prompt cache — the next call re-sends the full prefix uncached."
                    .to_string(),
            )
        } else {
            None
        }
    }

    /// Whether the active model/provider has a prompt cache at all. Reuses
    /// the pruning-policy no-cache predicate: the resolved
    /// [`cockpit_config::providers::CacheConfig`] is fed to
    /// [`cockpit_core::engine::prune::cache_state`]; a `NoCacheProvider` cold reason
    /// means it never caches. Best-effort — an unresolvable model is treated
    /// as caching so the warning errs on the side of showing.
    pub(super) fn active_provider_caches(&self) -> bool {
        let Some((provider, model)) = self.launch.active_model.as_ref() else {
            return true;
        };
        let providers = &self.config_snapshot.providers;
        let cache = providers.resolve_cache(provider, model);
        cache_config_caches(&cache)
    }

    /// Whether inline `<think>` stripping runs for the active session model,
    /// resolved through the three-tier toggle (model `inline_think` → provider
    /// `inline_think` → global `inlineThink`,
    /// implementation note). Loaded fresh from
    /// the layered config at each turn start so model swaps and `/settings`
    /// edits take effect on the next turn without a restart. An unresolvable
    /// model falls through to the global default (on).
    pub(super) fn strip_inline_think(&self) -> bool {
        let (extended, providers) = cockpit_core::auto_title::load_configs_for(&self.launch.cwd);
        match self.launch.active_model.as_ref() {
            Some((provider, model)) => {
                providers.resolve_inline_think(provider, model, extended.inline_think)
            }
            None => extended.inline_think,
        }
    }

    pub(super) fn pending_or_insert_with_strip<F>(
        &mut self,
        agent: String,
        resolve_strip: F,
    ) -> &mut PendingMsg
    where
        F: FnOnce(&Self) -> bool,
    {
        if self.pending.is_none() {
            let strip_think = resolve_strip(self);
            self.pending = Some(new_pending(agent, strip_think));
        }
        self.pending.as_mut().expect("pending initialized")
    }

    /// True when `attempt_id` does not match the live typed-display attempt
    /// that currently owns provisional UI (after Reset, that is the
    /// replacement — so late failed-attempt events stay inert).
    pub(super) fn display_attempt_is_stale(
        &self,
        attempt_id: cockpit_client::presentation::AssistantAttemptId,
    ) -> bool {
        self.active_display_attempt_id
            .is_some_and(|active| active != attempt_id)
    }

    /// Bare-`/<skill-name>` sugar (implementation note):
    /// the composer holds `/<name>` optionally followed by trailing args. Seed
    /// a deterministic skill invocation, forwarding the trailing text as the
    /// task input. Tallies under the `/skill` dispatcher for frequency ranking
    /// (the bare names aren't builtins, so they share one counter). Always
    /// returns `false` (the TUI stays open).
    pub(super) fn invoke_skill_slash(&mut self, name: &str) -> bool {
        let raw = self.composer.text().to_string();
        let args = slash_args(&raw);
        self.clear_composer_buffer();
        self.reset_slash_window();
        self.record_usage(cockpit_proto::UsageKind::Slash, "skill".to_string(), None);
        let display = if args.trim().is_empty() {
            format!("/{name}")
        } else {
            format!("/{name} {}", args.trim())
        };
        self.dispatch_skill_invocation(display, name, &args);
        false
    }
}
