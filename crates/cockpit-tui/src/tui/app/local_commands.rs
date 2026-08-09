use super::*;

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
        submission: cockpit_core::engine::message::UserSubmission,
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
        submission: cockpit_core::engine::message::UserSubmission,
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
        let mut pending = std::mem::take(&mut self.pending_session_switch_submissions);
        if pending.is_empty() {
            self.pending_session_switch_target = None;
            self.pending_ephemeral_session_switch_intent = None;
            return;
        }
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
        if self.session_switch_in_progress() || self.pending_session_switch_submissions.is_empty() {
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

    fn retain_failed_session_switch_submissions(
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
        if self.session_switch_in_progress() || self.retained_pre_dispatch_submissions.is_empty() {
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
            let result = match self.agent_runner.as_ref() {
                Some(Ok(runner)) => runner.try_send_optimistic_input(
                    submission,
                    retained.pending.optimistic_submission_id,
                ),
                _ => unreachable!("runner checked before retry loop"),
            };
            match result {
                Ok(()) => {
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
        let submission = cockpit_core::engine::message::UserSubmission::text(wire);
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
        submission: cockpit_core::engine::message::UserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        tag_expansions: &[cockpit_core::daemon::proto::TagExpansionMeta],
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
        mut submission: cockpit_core::engine::message::UserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        tag_expansions: &[cockpit_core::daemon::proto::TagExpansionMeta],
    ) -> DispatchOutcome {
        if submission.display_text.is_none() && submission.text != display {
            submission.display_text = Some(display.clone());
        }
        if submission.tag_expansions.is_empty() && !tag_expansions.is_empty() {
            submission.tag_expansions = tag_expansions.to_vec();
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
                cockpit_core::daemon::proto::Request::ResumePausedWork {
                    session_id: pending.session_id,
                }
            }
            Some("cancel") | None => {
                self.push_plain("/resume: cancelled paused daemon work.".to_string());
                cockpit_core::daemon::proto::Request::CancelPausedWork {
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
            "goal.status",
            cockpit_core::daemon::proto::Request::GoalStatus { session_id },
        );
    }

    pub(super) fn set_goal_status(
        &mut self,
        status: cockpit_core::daemon::proto::GoalStatus,
        label: &str,
    ) {
        let Some(session_id) = self.goal_session_id(label) else {
            return;
        };
        self.start_goal_request(
            "goal.set",
            cockpit_core::daemon::proto::Request::SetGoalStatus { session_id, status },
        );
    }

    pub(super) fn clear_goal(&mut self) {
        let Some(session_id) = self.goal_session_id("/goal clear") else {
            return;
        };
        self.start_goal_request(
            "goal.clear",
            cockpit_core::daemon::proto::Request::ClearGoal { session_id },
        );
    }

    fn goal_session_id(&mut self, label: &str) -> Option<uuid::Uuid> {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id()),
            _ => {
                self.report_control_not_delivered(
                    label,
                    cockpit_core::engine::ControlRequestNotDelivered::NoRunner,
                );
                None
            }
        }
    }

    fn start_goal_request(
        &mut self,
        kind: &'static str,
        request: cockpit_core::daemon::proto::Request,
    ) {
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
                    cockpit_core::daemon::proto::Response::GoalStatus { goal: Some(goal) } => {
                        let budget = goal
                            .token_budget
                            .map(|n| n.to_string())
                            .unwrap_or_else(|| "none".to_string());
                        Ok(AsyncActionPayload::Text(format!(
                            "/goal: {} · {} · tokens {}/{} · subcommands: status, pause, resume, clear, edit",
                            goal.status.as_str(),
                            goal.objective,
                            goal.tokens_used,
                            budget
                        )))
                    }
                    cockpit_core::daemon::proto::Response::GoalStatus { goal: None } => Ok(
                        AsyncActionPayload::Text(
                            "/goal: no goal. Usage: /goal <objective> | status | pause | resume | clear | edit"
                                .to_string(),
                        ),
                    ),
                    cockpit_core::daemon::proto::Response::GoalUpdated { goal } => {
                        Ok(AsyncActionPayload::Text(format!(
                            "/goal: goal is now {}.",
                            goal.status.as_str()
                        )))
                    }
                    cockpit_core::daemon::proto::Response::GoalCleared { cleared: true } => Ok(
                        AsyncActionPayload::Text("/goal clear: cleared current goal.".to_string()),
                    ),
                    cockpit_core::daemon::proto::Response::GoalCleared { cleared: false } => Ok(
                        AsyncActionPayload::Text("/goal clear: no open goal.".to_string()),
                    ),
                    other => Err(format!("unexpected goal response: {other:?}")),
                }
            },
        );
    }

    pub(super) fn dispatch_goal_turn(&mut self, display: &str, wire: String) {
        self.pin_chat_to_tail();
        self.begin_working_span();
        let submission = cockpit_core::engine::message::UserSubmission::text(wire);
        self.dispatch_optimistic_user_submission(
            format!("/goal {display}"),
            submission,
            "/goal",
            true,
            &[],
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
        let submission = cockpit_core::engine::message::UserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_core::engine::message::UserSubmissionKind::User,
            origin: cockpit_core::engine::message::SubmissionOrigin::ExternalRoot,
            text: args.trim().to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: Some(name.to_string()),
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            client_submissions: Vec::new(),
            queue_target: None,
            pending_terminal_disposition: None,
            run_invocation_id: None,
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
            cockpit_core::daemon::proto::Request::CancelSchedule {
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

    /// Resolve the layered `mcp.json` path for the cwd (first discovered
    /// `.cockpit/`), preferring an existing file, else the first creatable.
    pub(super) fn mcp_config_path(&self) -> Option<std::path::PathBuf> {
        let cwd = &self.launch.cwd;
        for d in cockpit_config::dirs::discover_config_dirs(cwd) {
            let p = d.path.join("mcp.json");
            if p.exists() {
                return Some(p);
            }
        }
        cockpit_config::dirs::cwd_scoped_creatable_dirs(cwd)
            .into_iter()
            .next()
            .map(|d| d.path.join("mcp.json"))
    }

    pub(super) fn mcp_load(&self) -> cockpit_core::mcp::config::McpConfig {
        #[cfg(test)]
        MCP_LOAD_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        cockpit_core::mcp::config::McpConfig::discover(&self.launch.cwd)
    }

    pub(super) fn mcp_save(&mut self, cfg: &cockpit_core::mcp::config::McpConfig) -> bool {
        self.slash_menu_cache.borrow_mut().take();
        let Some(path) = self.mcp_config_path() else {
            self.push_plain("No writable .cockpit/ directory for MCP config".to_string());
            return false;
        };
        match cfg.write_private(&path) {
            Ok(_) => true,
            Err(_) => {
                self.push_plain("Failed to write mcp.json".to_string());
                false
            }
        }
    }

    pub(super) fn mcp_list(&mut self) {
        let cfg = self.mcp_load();
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

    /// `/mcp on|off|toggle [id]`. `enable=None` toggles; a mixed set toggled
    /// in bulk turns all **off** (spec). `id=None` applies to every server.
    pub(super) fn mcp_set_enabled(&mut self, id: Option<&str>, enable: Option<bool>) {
        let mut cfg = self.mcp_load();
        if let Some(id) = id {
            let Some(server) = cfg.servers.get_mut(id) else {
                self.push_plain(format!("Unknown MCP server `{id}`"));
                return;
            };
            server.enabled = enable.unwrap_or(!server.enabled);
        } else {
            let target = match enable {
                Some(v) => v,
                None => {
                    // Bulk toggle: if any is enabled (mixed/all-on), turn all
                    // off; only when all are off do we turn all on.
                    !cfg.servers.values().any(|s| s.enabled)
                }
            };
            for s in cfg.servers.values_mut() {
                s.enabled = target;
            }
        }
        if self.mcp_save(&cfg) {
            self.mcp_list();
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

    /// Bare-`/<skill-name>` sugar (implementation note):
    /// the composer holds `/<name>` optionally followed by trailing args. Seed
    /// a deterministic skill invocation, forwarding the trailing text as the
    /// task input. Tallies under the `/skill` dispatcher for frequency ranking
    /// (the bare names aren't builtins, so they share one counter). Always
    /// returns `false` (the TUI stays open).
    pub(super) fn invoke_skill_slash(&mut self, name: &str) -> bool {
        let raw = self.composer.text().to_string();
        let args = slash_args(&raw);
        self.composer.clear();
        self.paste_registry.clear();
        self.reset_slash_window();
        self.record_usage(
            cockpit_core::daemon::proto::UsageKind::Slash,
            "skill".to_string(),
            None,
        );
        let display = if args.trim().is_empty() {
            format!("/{name}")
        } else {
            format!("/{name} {}", args.trim())
        };
        self.dispatch_skill_invocation(display, name, &args);
        false
    }
}
