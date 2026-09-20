use super::*;

pub(super) const MODEL_SELECTION_TIMEOUT: Duration = Duration::from_secs(60);

impl App {
    pub(super) fn swap_primary_agent(&mut self, name: &str) {
        if cockpit_core::agents::is_hidden_primary(name) {
            self.push_plain(format!(
                "`{name}` is hidden — start it with `/multireview`."
            ));
            return;
        }
        self.send_daemon_request(
            "/agent",
            cockpit_proto::Request::SetAgent {
                name: name.to_string(),
            },
            ControlApplied::PrimaryAgentSwitch {
                name: name.to_string(),
            },
        );
    }

    pub(super) fn record_primary_switch_confirmation(&mut self, name: &str) {
        let line_to_record = format!("Switched primary agent to `{name}`");
        if let Some(pending) = self.pending_agent_switch_log.as_mut()
            && let Some(HistoryEntry::Plain { line }) =
                self.history.get_mut(pending.confirmation_index)
        {
            *line = line_to_record;
            pending.target = name.to_string();
            return;
        }
        self.push_plain(line_to_record);
        self.pending_agent_switch_log = Some(PendingAgentSwitchLog {
            confirmation_index: self.history.len().saturating_sub(1),
            target: name.to_string(),
        });
    }

    pub(super) fn lock_pending_agent_switch_log(&mut self) {
        let Some(pending) = self.pending_agent_switch_log.take() else {
            return;
        };
        if let Some(warning) = primary_swap_warning(&pending.target) {
            let idx = pending.confirmation_index.min(self.history.len());
            self.history.insert(
                idx,
                HistoryEntry::Plain {
                    line: warning.to_string(),
                },
            );
        }
    }

    pub(super) fn start_multireview(&mut self, kickoff: String) {
        self.send_daemon_request(
            "/multireview",
            cockpit_proto::Request::SetAgent {
                name: "Multireview".to_string(),
            },
            ControlApplied::Multireview { kickoff },
        );
    }

    /// `Shift+Tab` — advance the active primary to the next agent in the
    /// wrapping cycle `Plan → Build → <user primaries alpha> → Plan`
    /// (implementation note). Routes through
    /// [`Self::swap_primary_agent`], so it carries the same confirmation
    /// line and start-a-session-first guard `/plan`/`/build` have.
    pub(super) fn cycle_primary_agent(&mut self) {
        let order = self.inventory_agent_names();
        let next = cockpit_core::agents::next_primary_in_cycle(&self.launch.agent_name, &order);
        self.swap_primary_agent(&next);
    }

    pub(super) fn open_model_menu(&mut self) {
        self.default_model_settings_mode = false;
        self.open_model_menu_highlighting(None);
        // Slot ordering is daemon-owned session state. `/model` is available
        // without first visiting `/session-setup`, so refresh that snapshot
        // whenever the ordinary menu opens; the completion updates this
        // already-open menu in place.
        self.request_session_setup_snapshot_refresh();
    }

    pub(super) fn open_default_model_from_settings(&mut self) {
        if self.config_snapshot.providers.providers.is_empty() {
            // First-paint startup can show attached runner chrome before the
            // daemon provider catalog lands in `config_snapshot`. Read the
            // bootstrap layer so the default-model menu can open immediately
            // after settings closes instead of waiting for a later push.
            self.refresh_bootstrap_config_snapshot();
        }
        let current = self.config_snapshot.providers.active_model.clone();
        self.open_model_menu_highlighting(current.as_ref());
        self.default_model_settings_mode = true;
        self.push_plain(
            "Choose the default model for new sessions (does not switch this session).",
        );
    }

    pub(super) fn open_model_menu_highlighting(
        &mut self,
        requested: Option<&cockpit_config::providers::ActiveModelRef>,
    ) {
        let expired = self.expire_stale_model_selection();
        let requested = requested.cloned().or(expired).or_else(|| {
            self.current_model_selection_retry()
                .map(|retry| retry.requested.clone())
        });
        if let Some(requested) = requested.as_ref() {
            self.open_composer_model_menu_for_provider(&requested.provider);
            self.restore_composer_model_menu_selection(requested);
        } else {
            self.open_composer_picker_from_chord(
                crate::tui::composer_controls::ComposerControlKind::Model,
            );
        }
    }

    pub(super) fn expire_stale_model_selection(
        &mut self,
    ) -> Option<cockpit_config::providers::ActiveModelRef> {
        let expired = self
            .pending_model_selection
            .as_ref()
            .is_some_and(|pending| pending.started_at.elapsed() >= MODEL_SELECTION_TIMEOUT);
        if !expired {
            return None;
        }
        let selection_id = self
            .pending_model_selection
            .as_ref()
            .expect("expired pending selection exists")
            .selection_id;
        let composer_owns_expired =
            self.composer_controls
                .pending
                .as_ref()
                .is_some_and(|pending| {
                    pending.request_id.is_some_and(|request_id| {
                        self.pending_control_requests
                            .get(&request_id)
                            .is_some_and(|request| {
                                matches!(
                                    request.applied,
                                    ControlApplied::ModelSelection {
                                        selection_id: pending_id
                                    } if pending_id == selection_id
                                )
                            })
                    })
                });
        let pending = self
            .clear_pending_model_selection(Some(selection_id))
            .expect("expired pending selection exists");
        let pending = self.preserve_failed_model_selection(pending);
        if composer_owns_expired {
            self.invalidate_composer_control_ownership(true, true);
        }
        self.push_plain(
            "The previous model selection timed out. Choose a model to retry; your queued message is retained."
                .to_string(),
        );
        Some(pending.requested)
    }

    pub(super) fn open_composer_model_menu_for_provider(&mut self, provider: &str) {
        self.open_composer_picker_from_chord(
            crate::tui::composer_controls::ComposerControlKind::Model,
        );
        if let Some(picker) = self.composer_controls.picker.as_mut()
            && let Some(index) = picker
                .categories
                .iter()
                .position(|category| category.id == provider && category.label != "Config drift")
        {
            picker.cursor = index;
            picker.category = index;
            picker.level = 1;
            picker.cursor = picker
                .categories
                .get(index)
                .and_then(|category| {
                    category.items.iter().position(|item| {
                        self.launch
                            .active_model
                            .as_ref()
                            .is_some_and(|(active_provider, model)| {
                                active_provider == &category.id && &item.id == model
                            })
                    })
                })
                .unwrap_or(0);
        }
    }

    pub(super) fn restore_composer_model_menu_selection(
        &mut self,
        requested: &cockpit_config::providers::ActiveModelRef,
    ) {
        let Some(picker) = self.composer_controls.picker.as_mut() else {
            return;
        };
        if let Some(index) = picker.categories.iter().position(|category| {
            category.id == requested.provider && category.label != "Config drift"
        }) {
            picker.category = index;
            picker.level = 1;
            let item_count = picker.categories[index].items.len();
            picker.cursor = picker
                .categories
                .get(index)
                .and_then(|category| {
                    category
                        .items
                        .iter()
                        .position(|item| item.id == requested.model)
                })
                .unwrap_or(picker.cursor)
                .min(item_count.saturating_sub(1));
        }
    }

    pub(super) fn handle_tools_outcome(&mut self, outcome: crate::tui::tools_pane::ToolsOutcome) {
        match outcome {
            crate::tui::tools_pane::ToolsOutcome::Close => {}
            crate::tui::tools_pane::ToolsOutcome::Pending => {}
            crate::tui::tools_pane::ToolsOutcome::RefreshSnapshot => {
                if let Some(correlation) = self.request_session_setup_snapshot_refresh() {
                    self.bind_tool_surface_snapshot_wait(correlation);
                }
            }
            crate::tui::tools_pane::ToolsOutcome::Apply {
                override_json,
                persist_session,
                cache_break,
                monty_nudge,
            } => {
                if persist_session && let Overlay::Tools(pane) = &mut self.overlay {
                    pane.mark_session_override_pending();
                }
                self.send_daemon_request(
                    "/tools",
                    cockpit_proto::Request::SetToolSurfaceOverride {
                        override_json,
                        persist_session,
                        cache_break_acknowledged: cache_break,
                        monty_nudge,
                    },
                    ControlApplied::ToolSurfaceOverride { cache_break },
                );
            }
        }
    }

    pub(super) fn handle_goal_settings_outcome(
        &mut self,
        outcome: crate::tui::goal_settings_pane::GoalSettingsOutcome,
    ) {
        match outcome {
            crate::tui::goal_settings_pane::GoalSettingsOutcome::Close => {}
            crate::tui::goal_settings_pane::GoalSettingsOutcome::Pending => {}
            crate::tui::goal_settings_pane::GoalSettingsOutcome::Apply {
                override_json,
                persist_session,
            } => {
                self.send_daemon_request(
                    "/goal-settings",
                    cockpit_proto::Request::SetGoalSettingsOverride {
                        override_json,
                        persist_session,
                    },
                    ControlApplied::None,
                );
            }
        }
    }

    pub(super) fn refresh_config_drift_surfaces(&mut self) {
        self.refresh_open_composer_model_menu();
    }

    pub(super) fn model_drift(&self) -> Option<crate::tui::model_choice::ModelDrift> {
        let state = self.config_drift.as_ref()?;
        Some(crate::tui::model_choice::ModelDrift {
            session_label: self.session_model_label(),
            config_label: state.config_label(),
            config_model: state.config_active_model(),
        })
    }

    pub(super) fn session_model_label(&self) -> String {
        self.launch
            .active_model
            .as_ref()
            .map(|(provider, model)| format!("{provider}/{model}"))
            .unwrap_or_else(|| "session model unknown".to_string())
    }

    pub(super) fn record_auth_failure(
        &mut self,
        provider: String,
        model: String,
        kind: cockpit_proto::AuthFailureKind,
        failed_at_epoch_secs: i64,
    ) {
        self.auth_failure_annotations.insert(
            (provider.clone(), model.clone()),
            crate::tui::auth_failure::AuthFailureRecord {
                kind: kind.clone(),
                failed_at_epoch_secs,
            },
        );
        self.auth_failure_fingerprints.insert(
            provider.clone(),
            crate::tui::auth_failure::provider_auth_fingerprint(
                &self.config_snapshot.provider_view,
                &provider,
            ),
        );
        self.auth_failure_notice = Some(crate::tui::auth_failure::AuthFailureNotice {
            provider,
            model,
            kind,
        });
    }

    pub(super) fn clear_auth_failure_for_model(&mut self, provider: &str, model: &str) {
        self.auth_failure_annotations
            .remove(&(provider.to_string(), model.to_string()));
        if self
            .auth_failure_notice
            .as_ref()
            .is_some_and(|notice| notice.provider == provider && notice.model == model)
        {
            self.auth_failure_notice = None;
        }
        if !self
            .auth_failure_annotations
            .keys()
            .any(|(failed_provider, _)| failed_provider == provider)
        {
            self.auth_failure_fingerprints.remove(provider);
        }
    }

    pub(super) fn clear_auth_failures_for_provider(&mut self, provider: &str) {
        self.auth_failure_annotations
            .retain(|(failed_provider, _), _| failed_provider != provider);
        self.auth_failure_fingerprints.remove(provider);
        if self
            .auth_failure_notice
            .as_ref()
            .is_some_and(|notice| notice.provider == provider)
        {
            self.auth_failure_notice = None;
        }
    }

    pub(super) fn clear_changed_provider_auth_failures(&mut self) {
        let changed = self
            .auth_failure_fingerprints
            .iter()
            .filter_map(|(provider, fingerprint)| {
                (*fingerprint
                    != crate::tui::auth_failure::provider_auth_fingerprint(
                        &self.config_snapshot.provider_view,
                        provider,
                    ))
                .then_some(provider.clone())
            })
            .collect::<Vec<_>>();
        for provider in changed {
            self.clear_auth_failures_for_provider(&provider);
        }
    }

    pub(super) fn open_auth_failure_provider(&mut self) {
        let Some(notice) = self.auth_failure_notice.clone() else {
            return;
        };
        let oauth_expired = matches!(
            notice.kind,
            cockpit_proto::AuthFailureKind::OAuthExpired { .. }
        );
        self.dialog = crate::tui::settings::Dialog::open_provider_settings(
            &self.launch.cwd,
            &notice.provider,
            oauth_expired,
        );
    }

    pub(super) fn notify_active_model_selected(
        &mut self,
        active: cockpit_config::providers::ActiveModelRef,
        persist_as_default: bool,
        trigger: cockpit_proto::ActiveModelSwitchTrigger,
    ) -> bool {
        let provider = active.provider.clone();
        let model = active.model.clone();
        self.record_usage(
            cockpit_proto::UsageKind::Model,
            format!("{provider}/{model}"),
            None,
        );
        self.request_model_selection("/model", active, persist_as_default, trigger)
    }

    pub(super) fn request_model_selection(
        &mut self,
        label: &str,
        active: cockpit_config::providers::ActiveModelRef,
        persist_as_default: bool,
        trigger: cockpit_proto::ActiveModelSwitchTrigger,
    ) -> bool {
        if self.has_pending_session_switch_action() {
            self.show_model_selection_error(
                &active,
                trigger,
                format!(
                    "{label}: session switch in progress; retry after the new session is attached"
                ),
            );
            return false;
        }
        // Every model-selection entry point shares the same stale-request
        // expiry. A hung daemon must not leave `/quick`, footer cycling, or a
        // picker recommit blocked until the user happens to reopen `/model`.
        self.expire_stale_model_selection();
        if self.pending_model_selection.is_some() {
            let message =
                "Another model selection is still in progress; wait for it to finish.".to_string();
            self.show_model_selection_error(&active, trigger, message);
            return false;
        }
        if self.pending_runner_attach.as_ref().is_some_and(|pending| {
            pending.continuations.iter().any(|continuation| {
                matches!(continuation, RunnerAttachContinuation::SelectModel { .. })
            })
        }) {
            self.show_model_selection_error(
                &active,
                trigger,
                "A model selection is waiting for the daemon connection; wait for it to finish."
                    .to_string(),
            );
            return false;
        }
        if let Some(retry) = self.current_model_selection_retry()
            && retry.requested != active
            && !matches!(trigger, cockpit_proto::ActiveModelSwitchTrigger::Picker)
        {
            self.push_plain(format!(
                "A failed {:?} selection for {}/{} and its queued message are waiting for retry; open `/model` to retry it or explicitly choose a replacement.",
                retry.trigger, retry.requested.provider, retry.requested.model
            ));
            return false;
        }
        if !matches!(self.agent_runner.as_ref(), Some(Ok(_))) {
            self.start_runner_attach(
                true,
                RunnerAttachContinuation::SelectModel {
                    label: label.to_string(),
                    active,
                    persist_as_default,
                    trigger,
                },
            );
            return true;
        }
        let selection_id = uuid::Uuid::new_v4();
        let Ok(sequence) = self.submission_order.enqueue(
            crate::tui::structured_paste::OrderedIntent::ModelSwitch(selection_id),
        ) else {
            self.show_model_selection_error(
                &active,
                trigger,
                "Model switching is unavailable because local ordering was exhausted".to_string(),
            );
            return false;
        };
        let mut parked = self
            .deferred_fence_dispatches
            .iter()
            .filter_map(|(id, deferred)| {
                (deferred.waiting_model_selection == Some(uuid::Uuid::nil()))
                    .then_some((*id, deferred.parked_fence_sequence.unwrap_or(u64::MAX)))
            })
            .collect::<Vec<_>>();
        parked.sort_by_key(|(_, old_sequence)| *old_sequence);
        for (id, _) in parked {
            let Ok(fence_sequence) = self
                .submission_order
                .enqueue(crate::tui::structured_paste::OrderedIntent::Fence(id))
            else {
                continue;
            };
            if let Some(fence) = self.submission_fences.get_mut(&id) {
                fence.fence_sequence = fence_sequence;
            }
            if let Some(deferred) = self.deferred_fence_dispatches.get_mut(&id) {
                deferred.waiting_model_selection = Some(selection_id);
                deferred.parked_fence_sequence = None;
            }
        }
        let retry = self.take_current_model_selection_retry();
        let queued_submission = retry.and_then(|retry| retry.queued_submission);
        if let Some(queued) = queued_submission.as_ref() {
            let Ok(fence_sequence) =
                self.submission_order
                    .enqueue(crate::tui::structured_paste::OrderedIntent::Fence(
                        queued.client_submission_id,
                    ))
            else {
                self.submission_order.cancel(sequence);
                self.set_model_selection_retry(super::ModelSelectionRetry {
                    session_id: self.launch.session_id,
                    requested: active.clone(),
                    trigger,
                    queued_submission,
                });
                self.show_model_selection_error(
                    &active,
                    trigger,
                    "Model switching is unavailable because local ordering was exhausted"
                        .to_string(),
                );
                return false;
            };
            if let Some(fence) = self.submission_fences.get_mut(&queued.client_submission_id) {
                fence.fence_sequence = fence_sequence;
            }
        }
        self.pending_model_selection = Some(super::PendingModelSelection {
            order_sequence: sequence,
            session_id: self.launch.session_id,
            selection_id,
            requested: active.clone(),
            trigger,
            minimum_generation: self.active_model_state_generation,
            started_at: std::time::Instant::now(),
            queued_submission,
        });
        self.send_daemon_request(
            label,
            active_model_request(selection_id, active, persist_as_default, trigger),
            ControlApplied::ModelSelection { selection_id },
        );
        self.pending_model_selection
            .as_ref()
            .is_some_and(|pending| pending.selection_id == selection_id)
    }
    pub(super) fn show_model_selection_error(
        &mut self,
        active: &cockpit_config::providers::ActiveModelRef,
        trigger: cockpit_proto::ActiveModelSwitchTrigger,
        message: String,
    ) {
        if matches!(trigger, cockpit_proto::ActiveModelSwitchTrigger::Picker) {
            self.open_model_menu_highlighting(Some(active));
            if let Some(picker) = self.composer_controls.picker.as_mut() {
                picker.status = super::composer_controls::ComposerPickerStatus::Unavailable;
                picker.status_text = Some(message);
            }
            return;
        }
        self.push_plain(message);
    }

    pub(super) fn open_quick_dialog(&mut self) {
        let models = crate::tui::model_choice::ordered_model_choices_from_inventory(
            &self.inventory_models(),
            &self.usage_models,
        )
        .into_iter()
        .filter(|choice| choice.is_favorite)
        .map(crate::tui::quick_dialog::QuickModelChoice::from)
        .collect();
        let current = crate::tui::quick_dialog::QuickCurrent {
            recursion_enabled: self.delegation_recursion_enabled,
            recursion_depth: self.delegation_recursion_depth,
            sandbox_mode: self.sandbox_mode,
            container_network_enabled: self.container_network_enabled,
            container_availability: self.container_availability.clone(),
            host_capabilities: self.host_capabilities.clone(),
            approval_mode: self.approval_mode,
            active_model: self.launch.active_model.clone(),
            prompt_cache_retention: self
                .active_model_selection
                .as_ref()
                .and_then(|active| active.prompt_cache_retention)
                .unwrap_or_default(),
            prompt_cache_retention_status: self
                .launch
                .active_model
                .as_ref()
                .map(|(provider, model)| {
                    self.config_snapshot
                        .providers
                        .resolve_effective_model_capabilities(
                            provider,
                            model,
                            self.config_snapshot.generation,
                        )
                        .prompt_cache_retention
                })
                .unwrap_or_default(),
        };
        self.overlay = Overlay::Quick(crate::tui::quick_dialog::QuickDialog::open(current, models));
    }

    pub(super) fn apply_quick_commit(&mut self, commit: crate::tui::quick_dialog::QuickCommit) {
        if let Some((enabled, default_depth)) = commit.recursion {
            self.send_daemon_request(
                "/quick",
                cockpit_proto::Request::SetDelegationRecursion {
                    enabled,
                    default_depth,
                },
                ControlApplied::None,
            );
        }
        if commit.sandbox_mode.is_some() || commit.container_network_enabled.is_some() {
            self.send_daemon_request(
                "/quick",
                cockpit_proto::Request::SetSandbox {
                    mode: commit.sandbox_mode,
                    container_network_enabled: commit.container_network_enabled,
                },
                ControlApplied::None,
            );
        }
        if let Some(mode) = commit.approval_mode {
            self.send_daemon_request(
                "/quick",
                cockpit_proto::Request::SetApprovalMode { mode },
                ControlApplied::None,
            );
        }
        let retention = commit.prompt_cache_retention;
        let requested_model = commit.active_model;
        let model_changed = requested_model.is_some();
        let mut active = match requested_model {
            Some((provider, model)) => {
                let mut selection = self.active_model_selection.clone().unwrap_or(
                    cockpit_config::providers::ActiveModelRef {
                        provider: provider.clone(),
                        model: model.clone(),
                        reasoning_effort: None,
                        thinking_mode: None,
                        prompt_cache_retention: None,
                    },
                );
                selection.provider = provider;
                selection.model = model;
                Some(selection)
            }
            None => retention.and_then(|_| self.active_model_selection.clone()),
        };
        if retention.is_some() && active.is_none() {
            self.push_plain("/quick: no session model is active".to_string());
            return;
        }
        if let (Some(retention), Some(active)) = (retention, active.as_mut()) {
            active.prompt_cache_retention = (!retention.is_default()).then_some(retention);
        }
        if let Some(active) = active {
            let provider = active.provider.clone();
            let model = active.model.clone();
            if model_changed {
                self.record_usage(
                    cockpit_proto::UsageKind::Model,
                    format!("{provider}/{model}"),
                    None,
                );
            }
            self.request_model_selection(
                "/quick",
                active,
                false,
                cockpit_proto::ActiveModelSwitchTrigger::Quick,
            );
        }
    }

    pub(super) fn send_daemon_request(
        &mut self,
        label: &str,
        req: cockpit_proto::Request,
        applied: ControlApplied,
    ) {
        let tool_surface_override = matches!(applied, ControlApplied::ToolSurfaceOverride { .. });
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            let message =
                Self::control_not_delivered_message(label, ControlRequestNotDelivered::NoRunner);
            let selection_id = match applied {
                ControlApplied::ModelSelection { selection_id } => Some(selection_id),
                _ => None,
            };
            if tool_surface_override {
                self.refuse_tool_surface_override(message.clone());
            }
            if let Some(pending) = self.clear_pending_model_selection(selection_id) {
                self.show_failed_model_selection(pending, message.clone());
            } else if !tool_surface_override {
                self.push_plain(message.clone());
            }
            if self.composer_controls.dispatch_armed {
                self.refuse_unbound_composer_control(
                    &message,
                    super::composer_controls::ComposerPickerStatus::Unavailable,
                );
            }
            return;
        };
        // Clone the send handles before mutating `self`. Binding the composer
        // request takes `&mut self`, which cannot overlap the `runner` borrow.
        let control_tx = runner.control_tx.clone();
        let events = runner.events.clone();
        let event_notify = runner.event_notify.clone();
        let session_id = runner.session_id();
        let attachment_epoch = runner.attachment_epoch();
        self.next_control_request_seq = self.next_control_request_seq.saturating_add(1);
        let request_id = ControlRequestId(self.next_control_request_seq);
        self.pending_control_requests.insert(
            request_id,
            PendingControlRequest::new(label.to_string(), applied),
        );
        self.bind_composer_control_request(request_id);
        let result = agent_runner::send_control_request(
            &control_tx,
            &events,
            &event_notify,
            request_id,
            session_id,
            attachment_epoch,
            req,
        );
        if let Err(reason) = result {
            let removed = self.pending_control_requests.remove(&request_id);
            let tool_surface_override = removed.as_ref().is_some_and(|pending| {
                matches!(pending.applied, ControlApplied::ToolSurfaceOverride { .. })
            });
            let selection_id = removed.and_then(|pending| match pending.applied {
                ControlApplied::ModelSelection { selection_id } => Some(selection_id),
                _ => None,
            });
            let message = Self::control_not_delivered_message(label, reason);
            if tool_surface_override {
                self.refuse_tool_surface_override(message.clone());
            }
            if let Some(pending) = self.clear_pending_model_selection(selection_id) {
                self.show_failed_model_selection(pending, message.clone());
            } else if !tool_surface_override {
                self.push_plain(message.clone());
            }
            self.refuse_composer_control_for_request(
                request_id,
                &message,
                super::composer_controls::ComposerPickerStatus::Unavailable,
            );
        }
    }

    pub(super) fn fence_pending_control_request(&mut self, request_id: ControlRequestId) {
        if let Some(pending) = self.pending_control_requests.get_mut(&request_id) {
            pending.fenced = true;
        }
    }

    /// Completions for `send_control_request` are stamped with the sending
    /// attachment epoch and dropped once visibility advances. Drain those
    /// owners here so reconnect, resync, or session-switch cannot leave them
    /// pending with no remaining settlement path. Every `ControlApplied`
    /// variant is classified by `epoch_abandon_action`; adding a variant
    /// without an arm is a compile error.
    pub(super) fn abandon_epoch_bound_control_receipts(
        &mut self,
        reason: super::ControlEpochAbandonment,
    ) {
        let pending = std::mem::take(&mut self.pending_control_requests);
        let mut refresh_snapshot = false;
        let interruption = match reason {
            super::ControlEpochAbandonment::SameSession => "reconnect",
            super::ControlEpochAbandonment::SessionTransition => "session change",
            super::ControlEpochAbandonment::TerminalDisconnect => "the daemon connection ending",
        };
        for (id, request) in pending {
            // Fenced correlations still swallow late receipts without
            // confirming; dropping them would lose that settlement path.
            if request.fenced {
                self.pending_control_requests.insert(id, request);
                continue;
            }
            match request.applied.epoch_abandon_action(reason) {
                super::ControlEpochAbandonAction::Silent
                | super::ControlEpochAbandonAction::ModelSelection => {}
                super::ControlEpochAbandonAction::RefreshSnapshot => {
                    refresh_snapshot = true;
                }
                super::ControlEpochAbandonAction::FailTokenizer => {
                    if let ControlApplied::ResponseMetricsTokenizer { confirm_id } = request.applied
                        && let Some(tok) = self.pending_tokenizer_confirm.take()
                    {
                        let outcome = tok.on_response(confirm_id, 0, false, Some("refresh_failed"));
                        self.apply_tokenizer_confirm_outcome(outcome);
                    }
                }
                super::ControlEpochAbandonAction::DaemonOwnedNotice => {
                    self.push_plain(format!(
                        "{}: confirmation was interrupted by {interruption}; daemon state is authoritative",
                        request.label
                    ));
                }
                super::ControlEpochAbandonAction::DropFollowOn => {
                    self.push_plain(format!(
                        "{}: was not confirmed; retry after {interruption}",
                        request.label
                    ));
                }
                super::ControlEpochAbandonAction::ParkRepairResume => {
                    self.parked_control_follow_ons.repair_resume = true;
                }
                super::ControlEpochAbandonAction::ParkExitGuard => {
                    self.parked_control_follow_ons.exit_guard = true;
                }
                super::ControlEpochAbandonAction::ParkExitAfterStop => {
                    self.parked_control_follow_ons.exit_after_stop = true;
                }
                super::ControlEpochAbandonAction::ParkExitAfterBackground => {
                    self.parked_control_follow_ons.exit_after_background = true;
                }
                super::ControlEpochAbandonAction::CompleteExitLocally => {
                    self.exit_requested = true;
                }
                super::ControlEpochAbandonAction::CompleteExitAfterBackground => {
                    self.exit_notice = Some(format!(
                        "This session is still running in the background; reattach with {}",
                        self.exit_reattach_command()
                    ));
                    self.exit_requested = true;
                }
            }
        }
        if let Overlay::Tools(pane) = &mut self.overlay
            && pane.mark_session_override_refreshing()
        {
            refresh_snapshot = true;
        }
        if refresh_snapshot && let Some(correlation) = self.request_session_setup_snapshot_refresh()
        {
            self.begin_tool_surface_snapshot_wait(correlation);
        }
    }

    pub(super) fn retry_parked_control_follow_ons(&mut self) {
        let parked = std::mem::take(&mut self.parked_control_follow_ons);
        let has_runner = self
            .agent_runner
            .as_ref()
            .is_some_and(|runner| runner.is_ok());
        if parked.repair_resume {
            let session_id = self
                .agent_runner
                .as_ref()
                .and_then(|runner| runner.as_ref().ok())
                .map(|runner| runner.session_id())
                .or(self.launch.session_id);
            if let Some(session_id) = session_id {
                self.send_daemon_request(
                    "/resume",
                    cockpit_proto::Request::RepairResume { session_id },
                    ControlApplied::RepairResume,
                );
            } else {
                self.push_plain(
                    "/resume: repair confirmation was interrupted; retry /resume repair"
                        .to_string(),
                );
            }
        }
        if parked.exit_guard {
            if has_runner {
                self.send_daemon_request(
                    "exit check",
                    cockpit_proto::Request::ExitGuardStatus,
                    ControlApplied::ExitGuardStatus,
                );
            } else {
                self.exit_requested = true;
            }
        }
        if parked.exit_after_stop {
            if has_runner {
                self.send_daemon_request(
                    "stop all",
                    cockpit_proto::Request::CancelAllSessionWork,
                    ControlApplied::ExitAfterStoppingWork,
                );
            } else {
                self.exit_requested = true;
            }
        }
        if parked.exit_after_background {
            if has_runner {
                self.send_daemon_request(
                    "run in background",
                    cockpit_proto::Request::PromoteToPersistent,
                    ControlApplied::ExitAfterBackgroundPromotion,
                );
            } else {
                self.exit_notice = Some(format!(
                    "This session is still running in the background; reattach with {}",
                    self.exit_reattach_command()
                ));
                self.exit_requested = true;
            }
        }
    }

    pub(super) fn apply_control_request_outcome(
        &mut self,
        request_id: ControlRequestId,
        outcome: ControlRequestOutcome,
    ) {
        let Some(pending) = self.pending_control_requests.remove(&request_id) else {
            return;
        };
        let skip_confirmation =
            pending.fenced || self.discard_stale_composer_control_receipt(request_id);
        let selection_id = match pending.applied {
            ControlApplied::ModelSelection { selection_id } => Some(selection_id),
            _ => None,
        };
        let tokenizer_confirm_id = match pending.applied {
            ControlApplied::ResponseMetricsTokenizer { confirm_id } => Some(confirm_id),
            _ => None,
        };
        let refresh_tool_surface_on_failure =
            matches!(pending.applied, ControlApplied::ToolSurfaceOverride { .. });
        match outcome {
            ControlRequestOutcome::ConfigRefreshed {
                applied_generation,
                changed,
            } => {
                if let Some(confirm_id) = tokenizer_confirm_id
                    && let Some(tok) = self.pending_tokenizer_confirm.take()
                {
                    let outcome = tok.on_response(confirm_id, applied_generation, changed, None);
                    self.apply_tokenizer_confirm_outcome(outcome);
                } else if !skip_confirmation {
                    self.apply_control_success(pending.applied);
                    self.apply_composer_control_outcome(request_id, None, false);
                }
            }
            ControlRequestOutcome::Applied => {
                if !skip_confirmation {
                    self.apply_control_success(pending.applied);
                    self.apply_composer_control_outcome(request_id, None, false);
                }
            }
            ControlRequestOutcome::HostCapabilities { snapshot } => {
                self.apply_host_capabilities(*snapshot);
                if !skip_confirmation {
                    self.apply_control_success(pending.applied);
                    self.apply_composer_control_outcome(request_id, None, false);
                }
            }
            ControlRequestOutcome::ExitGuardStatus {
                ephemeral_owner,
                has_live_work,
            } => {
                if skip_confirmation {
                    return;
                }
                if matches!(pending.applied, ControlApplied::ExitGuardStatus) {
                    self.apply_exit_guard_status(ephemeral_owner, has_live_work);
                } else {
                    self.push_plain(format!(
                        "{}: daemon returned an unexpected exit-guard response",
                        pending.label
                    ));
                }
            }
            ControlRequestOutcome::Rejected(error) => {
                if refresh_tool_surface_on_failure {
                    self.refuse_tool_surface_override(format!(
                        "Tool surface update was refused: {error}"
                    ));
                }
                if matches!(pending.applied, ControlApplied::PrimaryAgentSwitch { .. }) {
                    self.request_session_setup_snapshot_refresh();
                    self.set_session_setup_notice(format!("Agent switch was refused: {error}"));
                }
                if let Some(confirm_id) = tokenizer_confirm_id
                    && let Some(tok) = self.pending_tokenizer_confirm.take()
                {
                    let code = if error.contains("invalid_response_metrics_tokenizer") {
                        Some("invalid_response_metrics_tokenizer")
                    } else {
                        Some("refresh_failed")
                    };
                    let outcome = tok.on_response(confirm_id, 0, false, code);
                    self.apply_tokenizer_confirm_outcome(outcome);
                } else {
                    let message = format!("{}: daemon rejected request: {error}", pending.label);
                    self.finish_control_failure(
                        skip_confirmation,
                        selection_id,
                        request_id,
                        message,
                        &error,
                        false,
                    );
                }
            }
            ControlRequestOutcome::NotDelivered(reason) => {
                if refresh_tool_surface_on_failure {
                    self.refuse_tool_surface_override(
                        "Tool surface update was not delivered; restored daemon state.".to_string(),
                    );
                }
                if let Some(confirm_id) = tokenizer_confirm_id
                    && let Some(tok) = self.pending_tokenizer_confirm.take()
                {
                    let outcome = tok.on_response(confirm_id, 0, false, Some("refresh_failed"));
                    self.apply_tokenizer_confirm_outcome(outcome);
                } else {
                    let message = Self::control_not_delivered_message(&pending.label, reason);
                    self.finish_control_failure(
                        skip_confirmation,
                        selection_id,
                        request_id,
                        message.clone(),
                        &message,
                        true,
                    );
                }
            }
        }
    }

    fn finish_control_failure(
        &mut self,
        skip_confirmation: bool,
        selection_id: Option<uuid::Uuid>,
        request_id: ControlRequestId,
        message: String,
        composer_error: &str,
        unavailable: bool,
    ) {
        if skip_confirmation {
            if let Some(selection) = self.clear_pending_model_selection(selection_id) {
                let _ = self.preserve_failed_model_selection(selection);
            }
            return;
        }
        if let Some(selection) = self.clear_pending_model_selection(selection_id) {
            self.show_failed_model_selection(selection, message);
        } else {
            self.push_plain(message);
        }
        self.apply_composer_control_outcome(request_id, Some(composer_error), unavailable);
    }

    fn refuse_tool_surface_override(&mut self, message: String) {
        self.request_session_setup_snapshot_refresh();
        self.set_session_setup_notice(message.clone());
        if let Overlay::Tools(pane) = &mut self.overlay {
            pane.refuse_session_override(message);
        }
    }

    pub(super) fn clear_pending_model_selection(
        &mut self,
        selection_id: Option<uuid::Uuid>,
    ) -> Option<super::PendingModelSelection> {
        let pending = self.pending_model_selection.as_ref()?;
        if Some(pending.selection_id) != selection_id {
            return None;
        }
        let selection_id = pending.selection_id;
        self.pending_control_requests.retain(|_, request| {
            !matches!(
                request.applied,
                ControlApplied::ModelSelection {
                    selection_id: pending_id
                } if pending_id == selection_id
            )
        });
        let pending = self.pending_model_selection.take();
        if let Some(pending) = pending.as_ref() {
            let _ = self.submission_order.complete(pending.order_sequence);
        }
        self.dispatch_next_ready_paste_fence();
        pending
    }

    pub(super) fn preserve_failed_model_selection(
        &mut self,
        mut pending: super::PendingModelSelection,
    ) -> super::PendingModelSelection {
        if let Some(queued) = pending.queued_submission.as_ref()
            && let Some(fence) = self.submission_fences.get_mut(&queued.client_submission_id)
        {
            self.submission_order.cancel(fence.fence_sequence);
            fence.fence_sequence = 0;
        }
        self.set_model_selection_retry(super::ModelSelectionRetry {
            session_id: pending.session_id,
            requested: pending.requested.clone(),
            trigger: pending.trigger,
            queued_submission: pending.queued_submission.take(),
        });
        pending
    }

    fn set_model_selection_retry(&mut self, mut retry: super::ModelSelectionRetry) {
        let session_id = retry.session_id;
        self.retry_model_selections
            .entry(session_id)
            .or_insert_with(|| {
                retry.session_id = session_id;
                retry
            });
    }

    pub(super) fn current_model_selection_retry(&self) -> Option<&super::ModelSelectionRetry> {
        let session_id = self.launch.session_id;
        self.retry_model_selections
            .get(&session_id)
            .filter(|retry| retry.session_id == session_id)
    }

    pub(super) fn take_current_model_selection_retry(
        &mut self,
    ) -> Option<super::ModelSelectionRetry> {
        let session_id = self.launch.session_id;
        self.retry_model_selections
            .remove(&session_id)
            .filter(|retry| retry.session_id == session_id)
    }

    /// Start a fresh runner/session model-state epoch. Every pending model
    /// control belongs to the runner being replaced, even when the daemon
    /// reattached to the same durable session id. Preserve its exact held
    /// submission for an explicit retry and remove request bookkeeping that
    /// can no longer receive a meaningful ACK.
    pub(super) fn cancel_model_controls_for_runner_epoch(
        &mut self,
    ) -> Option<super::PendingModelSelection> {
        let pending = self.pending_model_selection.take();
        if let Some(pending) = pending.as_ref() {
            self.submission_order.cancel(pending.order_sequence);
            let parked = self
                .deferred_fence_dispatches
                .iter()
                .filter_map(|(id, deferred)| {
                    (deferred.waiting_model_selection == Some(pending.selection_id)).then_some(*id)
                })
                .collect::<Vec<_>>();
            for id in parked {
                if let Some(fence) = self.submission_fences.get_mut(&id) {
                    let old_sequence = fence.fence_sequence;
                    self.submission_order.cancel(fence.fence_sequence);
                    fence.fence_sequence = 0;
                    if let Some(deferred) = self.deferred_fence_dispatches.get_mut(&id) {
                        deferred.parked_fence_sequence = Some(old_sequence);
                    }
                }
                if let Some(deferred) = self.deferred_fence_dispatches.get_mut(&id) {
                    deferred.waiting_model_selection = Some(uuid::Uuid::nil());
                }
            }
        }
        let pending = pending.map(|pending| self.preserve_failed_model_selection(pending));
        self.pending_control_requests
            .retain(|_, request| !matches!(request.applied, ControlApplied::ModelSelection { .. }));
        pending
    }

    pub(super) fn cancel_model_controls_for_terminal_link(&mut self) {
        self.invalidate_composer_control_ownership(true, false);
        self.abandon_epoch_bound_control_receipts(
            super::ControlEpochAbandonment::TerminalDisconnect,
        );
        if let Some(pending) = self.cancel_model_controls_for_runner_epoch() {
            tracing::warn!(
                session_id = ?pending.session_id,
                selection_id = %pending.selection_id,
                provider = %pending.requested.provider,
                model = %pending.requested.model,
                trigger = ?pending.trigger,
                generation = pending.minimum_generation,
                "model selection cancelled because the daemon link terminated"
            );
            self.push_plain(
                "The daemon connection ended during model selection; your complete selection, draft, and exact queued message were retained for retry."
                    .to_string(),
            );
        }
    }

    pub(super) fn retry_parked_model_selection_after_reconnect(&mut self) {
        if self.pending_model_selection.is_some() {
            return;
        }
        let Some(retry) = self.current_model_selection_retry() else {
            return;
        };
        let requested = retry.requested.clone();
        let trigger = retry.trigger;
        let _ = self.request_model_selection("model reconnect retry", requested, false, trigger);
    }

    fn show_failed_model_selection(
        &mut self,
        pending: super::PendingModelSelection,
        message: String,
    ) {
        let pending = self.preserve_failed_model_selection(pending);
        self.show_model_selection_error(&pending.requested, pending.trigger, message);
    }

    fn apply_control_success(&mut self, applied: ControlApplied) {
        match applied {
            ControlApplied::None => {}
            ControlApplied::ModelSelection { .. } => {}
            // ExitGuardStatus has a dedicated response payload that controls
            // the exit path in `apply_control_request_outcome`.
            ControlApplied::ExitGuardStatus => {}
            ControlApplied::PrimaryAgentSwitch { name } => {
                self.record_primary_switch_confirmation(&name);
                self.request_session_setup_snapshot_refresh();
            }
            ControlApplied::ToolSurfaceOverride { cache_break } => {
                if cache_break && let Some(warning) = self.cache_break_warning() {
                    self.push_plain(warning);
                }
                if let Overlay::Tools(pane) = &mut self.overlay {
                    pane.mark_session_override_awaiting_snapshot();
                }
                if let Some(correlation) = self.request_session_setup_snapshot_refresh() {
                    self.begin_tool_surface_snapshot_wait(correlation);
                }
            }
            ControlApplied::Multireview { kickoff } => {
                self.push_plain(MULTIREVIEW_TOKEN_BURN_WARNING.to_string());
                self.begin_working_span();
                let submission = ClientUserSubmission {
                    expected_model_state_generation: None,
                    expected_model: None,
                    kind: cockpit_client::submission::UserSubmissionKind::User,
                    origin: cockpit_client::submission::SubmissionOrigin::ExternalRoot,
                    text: kickoff.clone(),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    images: Vec::new(),
                    media: Vec::new(),
                    forced_skill: None,
                    ..Default::default()
                };
                self.dispatch_optimistic_user_submission(
                    kickoff,
                    submission,
                    "/multireview",
                    true,
                    &[],
                );
            }
            ControlApplied::ScheduleCancel { command, job_id } => {
                self.push_plain(format!("{command}: cancel requested for {job_id}"));
            }
            ControlApplied::ModelFavorite {
                provider,
                model,
                favorite,
            } => {
                let verb = if favorite { "marked" } else { "unmarked" };
                self.push_plain(format!("/favorite: {verb} {provider}/{model} as favorite"));
            }
            ControlApplied::PinContext { text } => {
                self.push_plain(format!(
                    "/pin-context: pinned (survives /compact verbatim): {text}"
                ));
            }
            ControlApplied::RepairResume => {
                if let Some(Ok(runner)) = self.agent_runner.as_ref() {
                    runner.retry_retained_user_submissions();
                }
            }
            ControlApplied::ExitAfterStoppingWork => {
                self.exit_requested = true;
            }
            ControlApplied::ExitAfterBackgroundPromotion => {
                self.exit_notice = Some(format!(
                    "This session is still running in the background; reattach with {}",
                    self.exit_reattach_command()
                ));
                self.exit_requested = true;
            }
            ControlApplied::ResponseMetricsTokenizer { .. } => {
                // Confirmation is driven by ConfigRefreshed / snapshot arms.
            }
        }
    }

    pub(super) fn report_control_not_delivered(
        &mut self,
        label: &str,
        reason: ControlRequestNotDelivered,
    ) {
        self.push_plain(Self::control_not_delivered_message(label, reason));
    }

    fn control_not_delivered_message(label: &str, reason: ControlRequestNotDelivered) -> String {
        match reason {
            ControlRequestNotDelivered::NoRunner => {
                format!("{label}: send a message first to start a session")
            }
            ControlRequestNotDelivered::ChannelFull => {
                format!("{label}: request not sent - daemon control queue is full; try again")
            }
            ControlRequestNotDelivered::ChannelClosed
            | ControlRequestNotDelivered::RunnerTeardown => {
                format!("{label}: request not sent - daemon control channel closed; try again")
            }
        }
    }

    /// Arm anti-misfire protection only when the user edited the composer
    /// within the configured lockout window. The timestamp is consumed by
    /// the first dialog, so queued approvals remain immediately answerable
    /// until the user types again.
    pub(super) fn dialog_lockout(&mut self) -> Duration {
        let configured = Duration::from_millis(self.config_snapshot.extended.dialog.lockout_ms);
        self.last_composer_edit_at
            .take()
            .filter(|edited_at| edited_at.elapsed() <= configured)
            .map(|_| configured)
            .unwrap_or(crate::tui::dialog::DialogState::NO_LOCKOUT)
    }

    /// Rehydration follows the same recent-edit rule. An authoritative attach
    /// alone is not evidence that a keystroke is in flight.
    pub(super) fn rehydrated_dialog_lockout(&mut self) -> Duration {
        self.dialog_lockout()
    }
}

impl super::App {
    pub(super) fn request_default_model_only(
        &mut self,
        active: cockpit_config::providers::ActiveModelRef,
    ) {
        let default_update_id = uuid::Uuid::new_v4();
        let provider = active.provider.clone();
        let model = active.model.clone();
        self.push_plain(format!("Saving default for {provider}/{model}…"));
        let req = cockpit_proto::Request::SetDefaultModel {
            default_update_id,
            provider: Some(active.provider),
            model: Some(active.model),
            reasoning_effort: active.reasoning_effort.map(|effort| effort.value),
            thinking_mode: active.thinking_mode,
            prompt_cache_retention: active.prompt_cache_retention,
            clear: false,
        };
        self.send_daemon_request("/settings default model", req, ControlApplied::None);
        // Stash id for terminal handling.
        self.pending_default_model_update_id = Some(default_update_id);
    }
}

fn active_model_request(
    selection_id: uuid::Uuid,
    active: cockpit_config::providers::ActiveModelRef,
    persist_as_default: bool,
    trigger: cockpit_proto::ActiveModelSwitchTrigger,
) -> cockpit_proto::Request {
    cockpit_proto::Request::SetActiveModel {
        selection_id,
        provider: active.provider,
        model: active.model,
        persist_as_default,
        trigger,
        reasoning_effort: active.reasoning_effort.map(|effort| effort.value),
        thinking_mode: active.thinking_mode,
        prompt_cache_retention: active.prompt_cache_retention,
    }
}
