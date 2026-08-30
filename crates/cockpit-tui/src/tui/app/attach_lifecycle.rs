use super::*;

impl App {
    /// Attach the session eagerly once the daemon is reachable so the
    /// startup graphic can show its id (session-id-display-and-lazy-persist).
    /// The attach creates a deferred (un-persisted) session in the daemon;
    /// the first user message is what writes the `sessions` row. Runs each
    /// event-loop tick.
    ///
    /// Gates (all must hold):
    /// - No live runner yet. A successful attach (`Some(Ok)`) stops the
    ///   eager loop; a poisoned `Some(Err)` from a *previous first-message*
    ///   attempt would too, so this also short-circuits then — only the
    ///   `None` state retries here.
    /// - The "daemon not running" prompt is closed — we don't spawn a
    ///   daemon out from under the user's choice.
    /// - The canonical daemon probe is allowed to start. After "Start and
    ///   connect" the just-spawned socket isn't bound for a beat; probing in
    ///   the background lets us wait quietly and attach the instant it's up
    ///   without blocking this tick.
    pub(super) fn ensure_session_for_display(&mut self) {
        // Evaluate the cheap struct-only gates first; the daemon probe is the
        // only costly check, so only start it when everything else already
        // permits an attach (`probe_when` is lazy for exactly this reason).
        let should_probe = should_attempt_display_attach(
            self.agent_runner.is_some(),
            self.daemon_prompt.is_some(),
            self.daemon_connected,
            || true,
        );
        if should_probe && self.display_attach_backoff.can_attempt(Instant::now()) {
            self.try_attach_for_display();
        }
    }

    #[cfg(test)]
    pub(super) fn start_display_daemon_probe_action<F>(&mut self, work: F)
    where
        F: FnOnce() -> cockpit_core::daemon::DaemonStatus + Send + 'static,
    {
        let cwd = self.launch.cwd.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("display.daemon.probe"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("display.daemon.probe")),
            move || {
                Ok(AsyncActionPayload::DaemonProbe {
                    cwd,
                    status: work(),
                })
            },
        );
    }

    #[cfg(test)]
    pub(super) fn apply_display_daemon_probe_result(
        &mut self,
        cwd: PathBuf,
        status: cockpit_core::daemon::DaemonStatus,
    ) {
        if cwd != self.launch.cwd {
            return;
        }
        if !matches!(status, cockpit_core::daemon::DaemonStatus::Running) {
            return;
        }
        let attach = should_attempt_display_attach(
            self.agent_runner.is_some(),
            self.daemon_prompt.is_some(),
            self.daemon_connected,
            || true,
        );
        if attach && self.display_attach_backoff.can_attempt(Instant::now()) {
            self.try_attach_for_display();
        }
    }

    /// The TUI attaches to the current ledger owner, preferring the selected
    /// lifetime only when it must create that owner.
    pub(super) fn lifecycle_intent(&self) -> cockpit_client::LifecycleIntent {
        if self.ephemeral_preference {
            cockpit_client::LifecycleIntent::AttachOrEphemeral
        } else {
            cockpit_client::LifecycleIntent::AttachOrPersistent
        }
    }

    /// Spawn (or attach to) the daemon and **latch** the result —
    /// including a failure. The first-message path
    /// (`src/tui/app/input.rs`) calls this: a user-initiated submit must
    /// surface a spawn error in history, and storing `Some(Err)` keeps it
    /// visible. The opportunistic display attach uses
    /// [`Self::try_attach_for_display`] instead, which never latches an
    /// error.
    pub(super) fn ensure_agent_runner(&mut self) {
        #[cfg(feature = "remote")]
        {
            if !self.startup_disclosures_ready {
                self.start_startup_disclosures_fetch();
                self.show_toast(
                    "Startup disclosures Unavailable — waiting for the daemon; Retry",
                    ToastKind::Warning,
                );
                return;
            }
        }
        if matches!(self.agent_runner, Some(Ok(_))) {
            return;
        }
        self.start_runner_attach(true, RunnerAttachContinuation::RetryRetainedSubmissions);
    }

    /// Start the sole foreground runner attachment without waiting in the
    /// reducer. Requests for the same launch identity coalesce behind one
    /// operation; their typed continuations run only after that exact
    /// operation is accepted by [`Self::apply_runner_attach_result`].
    pub(super) fn start_runner_attach(
        &mut self,
        latch_error: bool,
        continuation: RunnerAttachContinuation,
    ) {
        if matches!(self.agent_runner, Some(Ok(_))) {
            self.apply_runner_attach_continuation(continuation);
            return;
        }
        let requested_session_id = self.launch.session_id;
        if let Some(pending) = self.pending_runner_attach.as_mut()
            && pending.cwd == self.launch.cwd
            && pending.requested_session_id == requested_session_id
            && pending.model_state_generation == self.active_model_state_generation
            && pending.config_generation == self.config_snapshot.generation
        {
            pending.latch_error |= latch_error;
            let duplicate = matches!(
                continuation,
                RunnerAttachContinuation::RetryRetainedSubmissions
            ) && pending
                .continuations
                .iter()
                .any(|queued| matches!(queued, RunnerAttachContinuation::RetryRetainedSubmissions));
            if !duplicate {
                pending.continuations.push(continuation);
            }
            return;
        }

        let initial_model = match &continuation {
            RunnerAttachContinuation::SelectModel { active, .. } => Some(active.clone()),
            _ => None,
        };
        let cwd = self.launch.cwd.clone();
        let no_sandbox = self.no_sandbox;
        let intent = self.lifecycle_intent();
        let lifecycle = self.lifecycle.clone();
        let worker_cwd = cwd.clone();
        // Route selection is structural: Code uses the closed Code-root API,
        // while generic attach can represent only Assistant/Computer.
        let requested_session_entry_mode =
            Some(self.session_mode.unwrap_or(SessionMode::Code));
        let action_id = self
            .async_actions
            .start(
                AsyncActionKind::Internal("runner.attach"),
                AsyncActionPolicy::Replace(AsyncActionKey::new("runner.attach")),
                async move {
                    let runner = match initial_model {
                        Some(model) => {
                            agent_runner::try_spawn_with_model_and_entry_mode(
                                &worker_cwd,
                                requested_session_id,
                                model,
                                no_sandbox,
                                lifecycle,
                                intent,
                                requested_session_entry_mode,
                            )
                            .await
                        }
                        None => {
                            agent_runner::try_spawn(&worker_cwd, no_sandbox, lifecycle, intent)
                                .await
                        }
                    }?;
                    Ok(AsyncActionPayload::AgentRunnerAttached(Box::new(runner)))
                },
            )
            .id();
        let generation = self.next_runner_attach_generation;
        self.next_runner_attach_generation = generation.wrapping_add(1).max(1);
        self.pending_runner_attach = Some(PendingRunnerAttach {
            action_id,
            generation,
            cwd,
            requested_session_id,
            model_state_generation: self.active_model_state_generation,
            config_generation: self.config_snapshot.generation,
            latch_error,
            continuations: vec![continuation],
        });
    }

    pub(super) fn apply_runner_attach_result(
        &mut self,
        action_id: crate::tui::async_action::AsyncActionId,
        payload: Result<AsyncActionPayload, String>,
    ) {
        let Some(pending) = self.pending_runner_attach.as_ref() else {
            return;
        };
        if pending.action_id != action_id {
            return;
        }
        let identity_matches = pending.cwd == self.launch.cwd
            && pending.requested_session_id == self.launch.session_id
            && pending.model_state_generation == self.active_model_state_generation
            && pending.config_generation == self.config_snapshot.generation;
        let pending = self
            .pending_runner_attach
            .take()
            .expect("runner attach pending checked");
        if !identity_matches {
            tracing::debug!(
                generation = pending.generation,
                "discarded stale runner attach"
            );
            let mut continuations = pending.continuations.into_iter();
            if let Some(first) = continuations.next() {
                self.start_runner_attach(pending.latch_error, first);
                for continuation in continuations {
                    self.start_runner_attach(pending.latch_error, continuation);
                }
            }
            return;
        }
        match payload {
            Ok(AsyncActionPayload::AgentRunnerAttached(runner)) => {
                self.adopt_runner(Ok(*runner));
                for continuation in pending.continuations {
                    self.apply_runner_attach_continuation(continuation);
                }
            }
            Ok(_) => {
                let error = "runner attach returned an unexpected payload".to_string();
                if pending.latch_error {
                    self.adopt_runner(Err(error.clone()));
                } else {
                    self.display_attach_backoff.record_failure(Instant::now());
                }
                self.apply_runner_attach_failure(&pending.continuations, &error);
            }
            Err(error) => {
                if pending.latch_error {
                    self.adopt_runner(Err(error.clone()));
                } else {
                    self.display_attach_backoff.record_failure(Instant::now());
                }
                self.apply_runner_attach_failure(&pending.continuations, &error);
            }
        }
    }

    fn apply_runner_attach_failure(
        &mut self,
        continuations: &[RunnerAttachContinuation],
        error: &str,
    ) {
        for continuation in continuations {
            match continuation {
                RunnerAttachContinuation::SelectModel {
                    active, trigger, ..
                } => self.show_model_selection_error(
                    active,
                    *trigger,
                    format!("Could not start a session — {error}"),
                ),
                RunnerAttachContinuation::BtwCommand(_) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("/btw: {error}"),
                    })
                }
                RunnerAttachContinuation::Compact => {
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("/compact: {error}"),
                    })
                }
                RunnerAttachContinuation::RetryRetainedSubmissions => {}
            }
        }
    }

    fn apply_runner_attach_continuation(&mut self, continuation: RunnerAttachContinuation) {
        match continuation {
            RunnerAttachContinuation::RetryRetainedSubmissions => {
                let _ = self.retry_retained_pre_dispatch_submissions();
            }
            RunnerAttachContinuation::SelectModel {
                label,
                active,
                persist_as_default,
                trigger,
            } => {
                let _ = self.request_model_selection(&label, active, persist_as_default, trigger);
            }
            RunnerAttachContinuation::BtwCommand(args) => self.handle_btw_command(&args),
            RunnerAttachContinuation::Compact => self.start_compact(),
        }
    }

    /// Adopt a freshly-spawned runner: on success, record its identity
    /// (session id + short id for the startup graphic), seed the usage
    /// tallies, flush buffered usage records, and refresh the guidance
    /// estimate from the now-live daemon. Always stores the result (`Ok`
    /// or `Err`) so the caller's latch semantics hold. Shared by the
    /// first-message path and the eager display attach.
    pub(super) fn adopt_runner(&mut self, runner: Result<AgentRunner, String>) {
        let mut runner = runner;
        if let Ok(r) = &mut runner {
            // The daemon, not the CLI parser, is authoritative after Attach.
            self.session_mode = Some(r.session_entry_mode);
            self.start_model_state_epoch(Some(r.session_id()), r.active_model_state.as_ref());
            let live_btw_fork = r.btw_fork.clone();
            self.reset_display_attach_backoff();
            // Record the daemon-assigned session id so the startup graphic
            // shows it and `/new` re-renders with the fresh one
            // (session-id-display-and-lazy-persist).
            self.launch.session_id = Some(r.session_id());
            self.launch.session_short_id = Some(r.short_id.clone());
            // Seed the in-memory tally from the daemon's authoritative
            // counts. Additive: any optimistic increments made before
            // attach (held in the maps) stay on top of the historical
            // counts; the daemon's value isn't double-counted because we
            // only fetch once per session.
            merge_counts(&mut self.usage_models, &r.usage.models);
            merge_counts(&mut self.usage_slash, &r.usage.slash);
            merge_counts(&mut self.usage_tags, &r.usage.tags);
            self.project_id = Some(r.project_id.clone());
            self.foreground_input_target = r.foreground_target.clone();
            self.maybe_show_daemon_version_chip(&r.daemon_version, r.daemon_compatible);
            self.startup_background.daemon_socket = Some(r.socket.clone());
            self.startup_background.daemon_endpoint = Some(r.endpoint.clone());
            // Flush records buffered before the runner existed,
            // backfilling tag project ids now that we know the project.
            let pid = self.project_id.clone();
            for mut req in std::mem::take(&mut self.pending_usage) {
                if let cockpit_proto::Request::RecordUsage {
                    kind: cockpit_proto::UsageKind::Tag,
                    project_id,
                    ..
                } = &mut req
                    && project_id.is_none()
                {
                    *project_id = pid.clone();
                }
                let _ = r.record_tx.try_send(req);
            }
            // Refresh the fresh-chat guidance estimate from the daemon now
            // that one is guaranteed up (lazy spawn / attach just completed).
            // The launch-time figure was a local raw-cl100k fallback computed
            // before any daemon existed; the daemon answers with the active
            // model's calibrated tokenizer and the same file-resolution the
            // engine then injects, so the indicator matches what's actually
            // sent. Best-effort: a daemon that can't answer leaves the
            // launch-time estimate in place (no regression). Targets the
            // runner's endpoint so it reuses the established ledger owner
            // without another discovery or spawn.
            self.refresh_guidance_estimate_from_daemon(r.endpoint.clone());
            if let Some(info) = live_btw_fork {
                self.open_btw_pane_from_info(info, true);
            }
        }
        let refresh_skills = runner.is_ok();
        let attach_ids = runner.as_ref().ok().map(|r| {
            let session_id = *cockpit_core::sync::lock_or_recover(&r.session_id_state);
            let connection_epoch = r
                .attachment_epoch
                .load(std::sync::atomic::Ordering::Relaxed);
            (session_id, connection_epoch)
        });
        self.agent_runner = Some(runner);
        if let Some((session_id, connection_epoch)) = attach_ids {
            self.bootstrap_inventory_after_attach(
                uuid::Uuid::nil(), // single TUI instance
                connection_epoch,
                session_id,
                self.config_snapshot.generation,
            );
        }
        if refresh_skills {
            self.refresh_skill_commands();
            self.send_daemon_request(
                "/capabilities",
                cockpit_proto::Request::GetHostCapabilities,
                crate::tui::app::ControlApplied::None,
            );
        }
    }

    /// Start a new worker-local state epoch and apply the attach model snapshot
    /// as authoritative state. Fresh runner adoption, same-runner socket
    /// reconnect, and in-process session switching all use this path so neither
    /// model nor config generation zero can ever be compared to a prior worker
    /// epoch.
    pub(super) fn start_model_state_epoch(
        &mut self,
        new_session_id: Option<uuid::Uuid>,
        state: Option<&cockpit_proto::ActiveModelState>,
    ) {
        for operation in self.pending_sealed_operations.values() {
            operation.invalidate();
        }
        // A submission held by the pending model transaction is not an
        // independently dispatchable paste fence. Keep it intact while the
        // model control is converted into a session-scoped retry below; that
        // path parks its order sequence and recreates it behind the retried
        // model switch. Generic epoch cleanup would otherwise delete the
        // fence first and leave the retained payload with nothing to release.
        let model_held_fence = self
            .pending_model_selection
            .as_ref()
            .and_then(|pending| pending.queued_submission.as_ref())
            .map(|queued| queued.client_submission_id);
        let mut cancelled_sequences = Vec::new();
        let mut cancelled_fences = Vec::new();
        let reconciling_fences = self
            .submission_fences
            .iter()
            .filter_map(|(id, fence)| {
                matches!(
                    fence.lifecycle,
                    crate::tui::structured_paste::FenceLifecycle::PossiblySent
                        | crate::tui::structured_paste::FenceLifecycle::Reconciling
                )
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        self.submission_fences
            .retain(|id, fence| match fence.lifecycle {
                crate::tui::structured_paste::FenceLifecycle::AwaitingProbes
                | crate::tui::structured_paste::FenceLifecycle::Ready => {
                    if Some(*id) == model_held_fence {
                        return true;
                    }
                    cancelled_sequences.push(fence.fence_sequence);
                    cancelled_fences.push(*id);
                    false
                }
                crate::tui::structured_paste::FenceLifecycle::PossiblySent => {
                    fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::Reconciling;
                    true
                }
                crate::tui::structured_paste::FenceLifecycle::Reconciling => true,
                _ => false,
            });
        let cancelled_any_fence = !cancelled_fences.is_empty();
        for sequence in cancelled_sequences {
            self.submission_order.cancel(sequence);
        }
        for id in cancelled_fences {
            self.deferred_fence_dispatches.remove(&id);
            self.cancel_paste_probes_matching(|probe| probe.owner_fence == Some(id));
            self.retained_pre_dispatch_submissions
                .retain(|retained| retained.pending.optimistic_submission_id != id);
        }
        let _ = self.mark_delivery_unconfirmed(&reconciling_fences);
        if cancelled_any_fence {
            self.show_toast("Paste unavailable", super::ToastKind::Error);
        }
        self.cancel_paste_probes_matching(|probe| probe.owner_fence.is_none());
        self.cancel_model_controls_for_epoch_change(new_session_id);
        self.clear_model_and_config_chrome_for_empty_session();
        if let Some(state) = state {
            self.apply_active_model_state(
                state.selection.clone(),
                state.default_selection.clone(),
                state.diverged,
                state.generation,
            );
        }
    }

    /// Drop outgoing active-model projection and daemon config chrome the same
    /// way a true empty session waits for attach. Used by provisional `/new`
    /// (immediate clear) and by `start_model_state_epoch` before applying a
    /// replacement snapshot. Failure must not restore the cleared chrome.
    pub(super) fn clear_model_and_config_chrome_for_empty_session(&mut self) {
        self.start_config_snapshot_epoch();
        self.active_model_state_generation = 0;
        self.active_model_state_confirmed = false;
        self.active_model_selection = None;
        self.launch.provider_line.clear();
        self.launch.active_model = None;
        self.launch.active_model_diverged = false;
        self.config_drift = None;
        self.refresh_config_drift_surfaces();
        self.refresh_active_model_projection();
    }

    /// Invalidate every daemon-resolved config projection before accepting
    /// events from a newly adopted worker. Config generations are worker-local
    /// just like active-model generations: retaining generation (or values)
    /// from the previous attachment can both reject the new worker's
    /// generation-zero snapshot and briefly expose the old session's provider
    /// catalog, capabilities, trust projection, or daemon behavior settings.
    ///
    /// Use an intentionally authority-empty, non-daemon seed while waiting for
    /// the authoritative snapshot. Presentation-only settings stay stable so
    /// a reconnect cannot transiently reinterpret input or approval debounce;
    /// provider, trust, model, skill, and engine settings do not cross the
    /// epoch. Re-reading local config here would create a competing resolver.
    fn start_config_snapshot_epoch(&mut self) {
        let waiting_extended = cockpit_config::extended::ExtendedConfig {
            tui: self.config_snapshot.extended.tui.clone(),
            dialog: self.config_snapshot.extended.dialog.clone(),
            predict_next_message: self.config_snapshot.extended.predict_next_message,
            ..cockpit_config::extended::ExtendedConfig::default()
        };
        self.config_snapshot = super::HeldConfig::from_view(
            0,
            false,
            waiting_extended,
            cockpit_proto::ProviderConfigView::default(),
        );
        self.apply_tui_config_from_snapshot();
        self.refresh_active_model_projection();
    }

    /// Cancel control work that cannot survive an attach/session transition,
    /// without resetting the confirmed model snapshot before a replacement
    /// attach has actually succeeded.
    pub(super) fn cancel_model_controls_for_epoch_change(
        &mut self,
        new_session_id: Option<uuid::Uuid>,
    ) {
        self.cancel_model_controls_for_epoch_change_with_presentation(new_session_id, true);
    }

    /// Cancel pending model controls for an attach/session transition.
    ///
    /// When `present_notice` is false (emptied `/new` views), keep internal
    /// cancellation and retry retention but do not append a history row —
    /// the cleared transcript admits only authorized delivery notices and
    /// the `/new` command error.
    pub(super) fn cancel_model_controls_for_epoch_change_with_presentation(
        &mut self,
        new_session_id: Option<uuid::Uuid>,
        present_notice: bool,
    ) {
        let previous_session_id = self.launch.session_id;
        if let Some(pending) = self.cancel_model_controls_for_runner_epoch() {
            let reason = match new_session_id {
                Some(session_id) if previous_session_id == Some(session_id) => "runner reconnect",
                Some(_) => "session replacement",
                None => "session transition",
            };
            tracing::warn!(
                old_session_id = ?pending.session_id,
                new_session_id = ?new_session_id,
                selection_id = %pending.selection_id,
                provider = %pending.requested.provider,
                model = %pending.requested.model,
                trigger = ?pending.trigger,
                generation = pending.minimum_generation,
                reason,
                present_notice,
                "model selection cancelled by runner epoch change"
            );
            if present_notice {
                self.push_plain(format!(
                    "Model selection was cancelled by {reason}; your draft and exact queued message were retained for retry."
                ));
            }
        }
    }

    /// Opportunistic display attach: attach a deferred session so the
    /// welcome box can show its short id before the first message, but —
    /// unlike [`Self::ensure_agent_runner`] — **never latch a failure**. A
    /// transient `try_spawn` error (e.g. the just-started daemon's socket
    /// isn't bound yet) leaves no latched runner so the next event-loop
    /// tick retries, rather than poisoning the runner to `Some(Err)` and
    /// permanently disabling the eager display. On success the runner is
    /// the same one the first-message path then reuses (it early-returns on
    /// `is_some()`), so the id shown in the welcome box is exactly the
    /// session persisted on first message.
    pub(super) fn try_attach_for_display(&mut self) {
        #[cfg(feature = "remote")]
        {
            if !self.startup_disclosures_ready {
                return;
            }
        }
        self.start_runner_attach(false, RunnerAttachContinuation::RetryRetainedSubmissions);
        // On `Err`, drop it silently: leave `agent_runner` as `None` so a
        // later tick can retry once the daemon is actually reachable.
    }

    pub(super) fn reset_display_attach_backoff(&mut self) {
        self.display_attach_backoff.reset();
    }

    /// Re-fetch the fresh-chat guidance estimate from the daemon at `socket`
    /// (the attached runner's own socket) and adopt it when it carries a
    /// resolved file or a non-zero system-prompt size. Called once the lazy
    /// daemon spawn/attach completes so the indicator reflects the daemon's
    /// calibrated figure rather than staying stuck on the launch-time local
    /// fallback (which is computed before any daemon exists). A daemon that
    /// can't answer, or a degenerate all-zero/no-file reply, is ignored so a
    /// transient miss never blanks a correct local estimate. Touches only the
    /// indicator — never the cached system prompt — so the prompt cache is
    /// undisturbed.
    pub(super) fn refresh_guidance_estimate_from_daemon(
        &mut self,
        endpoint: cockpit_client::ClientEndpoint,
    ) {
        let (provider, model) = match &self.launch.active_model {
            Some((p, m)) => (Some(p.clone()), Some(m.clone())),
            None => (None, None),
        };
        let project_root = self.launch.cwd.to_string_lossy().into_owned();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("guidance.estimate"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("guidance.estimate")),
            move || {
                let resp = agent_runner::daemon_request_at_blocking(
                    &endpoint,
                    cockpit_proto::Request::GuidanceEstimate {
                        project_root,
                        provider,
                        model,
                    },
                )?;
                match resp {
                    cockpit_proto::Response::GuidanceEstimate {
                        file,
                        tokens,
                        system_tokens,
                        model_instruction_tokens,
                    } if file.is_some() || system_tokens > 0 || model_instruction_tokens > 0 => Ok(
                        AsyncActionPayload::GuidanceEstimate(agent_runner::GuidanceEstimate {
                            file,
                            guidance_tokens: tokens,
                            system_tokens,
                            model_instruction_tokens,
                        }),
                    ),
                    _ => Err("empty guidance estimate".to_string()),
                }
            },
        );
    }

    /// Record one accepted autocomplete pick: bump the in-memory count
    /// optimistically (so the current session reflects it without a
    /// round-trip) and forward it to the daemon, buffering until the
    /// runner exists.
    pub(super) fn record_usage(
        &mut self,
        kind: cockpit_proto::UsageKind,
        key: String,
        project_id: Option<String>,
    ) {
        use cockpit_proto::UsageKind;
        let map = match kind {
            UsageKind::Model => &mut self.usage_models,
            UsageKind::Slash => &mut self.usage_slash,
            UsageKind::Tag => &mut self.usage_tags,
        };
        *map.entry(key.clone()).or_insert(0) += 1;
        let req = cockpit_proto::Request::RecordUsage {
            kind,
            key,
            project_id,
        };
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => {
                let _ = runner.record_tx.try_send(req);
            }
            _ => self.pending_usage.push(req),
        }
    }
}
