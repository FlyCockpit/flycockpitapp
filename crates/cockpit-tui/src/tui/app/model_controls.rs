use super::*;

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
            cockpit_core::daemon::proto::Request::SetAgent {
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
            cockpit_core::daemon::proto::Request::SetAgent {
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
        let order = cockpit_core::agents::chat_ownable_primaries(&self.launch.cwd);
        let next = cockpit_core::agents::next_primary_in_cycle(&self.launch.agent_name, &order);
        self.swap_primary_agent(&next);
    }

    pub(super) fn open_footer_agent_picker(&mut self) {
        self.footer_mode_picker = None;
        let order = cockpit_core::agents::chat_ownable_primaries(&self.launch.cwd);
        let current = self
            .agent_path
            .first()
            .map(String::as_str)
            .unwrap_or(self.launch.agent_name.as_str());
        self.footer_agent_picker = Some(FooterAgentPicker::new(current, order));
    }

    pub(super) fn commit_footer_agent_picker(&mut self, picker: &FooterAgentPicker) {
        if self.agent_path.len() > 1 {
            self.push_plain(
                "Agent switch is disabled while an interactive subagent is active.".to_string(),
            );
            self.footer_agent_picker = Some(picker.clone());
            return;
        }
        if let Some(name) = picker.selected_agent() {
            self.footer_agent_picker = None;
            self.footer_selection = None;
            self.swap_primary_agent(name);
        } else {
            self.footer_agent_picker = Some(picker.clone());
        }
    }

    pub(super) fn open_footer_mode_picker(&mut self) {
        self.footer_agent_picker = None;
        self.footer_mode_picker = Some(FooterModePicker::new(self.llm_mode));
    }

    pub(super) fn open_model_picker(&mut self) {
        self.open_model_picker_highlighting(None);
    }

    pub(super) fn open_model_picker_highlighting(
        &mut self,
        requested: Option<&cockpit_config::providers::ActiveModelRef>,
    ) {
        let expired = self.expire_stale_model_selection();
        let requested = requested.or(expired.as_ref());
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        match crate::tui::model_picker::ModelPickerDialog::open_with_failures(
            self.config_snapshot.providers.clone(),
            self.launch.active_model.clone(),
            &self.usage_models,
            &self.auth_failure_annotations,
            chrono::Utc::now().timestamp(),
        ) {
            Ok(mut picker) => {
                picker.set_config_drift(self.model_picker_drift());
                if let Some(requested) = requested {
                    picker.restore_requested_selection(requested);
                }
                self.overlay = Overlay::ModelPicker(picker);
            }
            Err(e) => {
                self.push_plain(format!("/model: {e}"));
            }
        }
    }

    fn expire_stale_model_selection(
        &mut self,
    ) -> Option<cockpit_config::providers::ActiveModelRef> {
        let expired = self
            .pending_model_selection
            .as_ref()
            .is_some_and(|pending| {
                pending.started_at.elapsed() >= std::time::Duration::from_secs(60)
            });
        if !expired {
            return None;
        }
        let pending = self
            .pending_model_selection
            .take()
            .expect("expired pending selection exists");
        if self.retry_model_submission.is_none() {
            self.retry_model_submission = pending.queued_submission;
        }
        self.push_plain(
            "The previous model selection timed out. Choose a model to retry; your queued message is retained."
                .to_string(),
        );
        Some(pending.requested)
    }

    pub(super) fn open_model_picker_for_provider(&mut self, provider: &str) {
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        match crate::tui::model_picker::ModelPickerDialog::open_for_provider_with_failures(
            self.config_snapshot.providers.clone(),
            provider,
            self.launch.active_model.clone(),
            &self.usage_models,
            &self.auth_failure_annotations,
            chrono::Utc::now().timestamp(),
        ) {
            Ok(mut picker) => {
                picker.set_config_drift(self.model_picker_drift());
                self.overlay = Overlay::ModelPicker(picker);
            }
            Err(error) => self.push_plain(format!("/model: {error}")),
        }
    }

    pub(super) fn handle_tools_outcome(&mut self, outcome: crate::tui::tools_pane::ToolsOutcome) {
        match outcome {
            crate::tui::tools_pane::ToolsOutcome::Close => {}
            crate::tui::tools_pane::ToolsOutcome::Apply {
                override_json,
                persist_session,
                cache_break,
                monty_nudge,
            } => {
                let applied = if cache_break {
                    ControlApplied::CacheBreakWarning
                } else {
                    ControlApplied::None
                };
                self.send_daemon_request(
                    "/tools",
                    cockpit_core::daemon::proto::Request::SetToolSurfaceOverride {
                        override_json,
                        persist_session,
                        prune_after_switch: cache_break,
                        monty_nudge,
                    },
                    applied,
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
            crate::tui::goal_settings_pane::GoalSettingsOutcome::Apply {
                override_json,
                persist_session,
            } => {
                self.send_daemon_request(
                    "/goal-settings",
                    cockpit_core::daemon::proto::Request::SetGoalSettingsOverride {
                        override_json,
                        persist_session,
                    },
                    ControlApplied::None,
                );
            }
        }
    }

    pub(super) fn refresh_config_drift_surfaces(&mut self) {
        let drift = self.model_picker_drift();
        if let Overlay::ModelPicker(picker) = &mut self.overlay {
            picker.set_config_drift(drift);
        }
    }

    pub(super) fn model_picker_drift(&self) -> Option<crate::tui::model_picker::ModelPickerDrift> {
        let state = self.config_drift.as_ref()?;
        Some(crate::tui::model_picker::ModelPickerDrift {
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
        kind: cockpit_core::daemon::proto::AuthFailureKind,
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
            cockpit_core::daemon::proto::AuthFailureKind::OAuthExpired { .. }
        );
        self.dialog = crate::tui::settings::Dialog::open_provider_settings(
            &self.launch.cwd,
            &notice.provider,
            oauth_expired,
        );
    }

    pub(super) fn close_model_picker(&mut self, accepted: bool) {
        if !accepted {
            self.submit_after_model_selection = false;
        }
        let selected = match std::mem::take(&mut self.overlay) {
            Overlay::ModelPicker(picker) if accepted => picker
                .selected_active_model()
                .map(|active| (active, picker.persists_as_default())),
            other => {
                self.overlay = other;
                None
            }
        };
        self.overlay = Overlay::None;
        if selected.is_none() {
            self.submit_after_model_selection = false;
        }
        if let Some((active, explicitly_persist_as_default)) = selected {
            let persist_as_default =
                explicitly_persist_as_default || self.default_model_selection.is_none();
            let provider = active.provider.clone();
            let model = active.model.clone();
            if self.notify_active_model_selected(
                active,
                persist_as_default,
                cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker,
            ) {
                let scope = if persist_as_default {
                    " for this session and saving it as the default"
                } else {
                    " for this session"
                };
                self.push_plain(format!("Selecting {provider}/{model}{scope}…"));
                if self.submit_after_model_selection {
                    self.submit_after_model_selection = false;
                    let _ = self.submit_input();
                }
            }
        }
    }

    pub(super) fn notify_active_model_selected(
        &mut self,
        active: cockpit_config::providers::ActiveModelRef,
        persist_as_default: bool,
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger,
    ) -> bool {
        let provider = active.provider.clone();
        let model = active.model.clone();
        self.record_usage(
            cockpit_core::daemon::proto::UsageKind::Model,
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
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger,
    ) -> bool {
        if self.pending_model_selection.is_some() {
            let message =
                "Another model selection is still in progress; wait for it to finish.".to_string();
            self.show_model_selection_error(&active, trigger, message);
            return false;
        }
        if !matches!(self.agent_runner.as_ref(), Some(Ok(_))) {
            let runner = agent_runner::try_spawn_with_model(
                &self.launch.cwd,
                self.launch.session_id,
                active.clone(),
                self.no_sandbox,
                self.lifecycle_mode(),
            );
            match runner {
                Ok(runner) => self.adopt_runner(Ok(runner)),
                Err(error) => {
                    let message = format!("{label}: could not start a session — {error}");
                    self.show_model_selection_error(&active, trigger, message);
                    return false;
                }
            }
        }
        let selection_id = uuid::Uuid::new_v4();
        self.pending_model_selection = Some(super::PendingModelSelection {
            session_id: self.launch.session_id,
            selection_id,
            requested: active.clone(),
            trigger,
            minimum_generation: self.active_model_state_generation,
            started_at: std::time::Instant::now(),
            queued_submission: self.retry_model_submission.take(),
        });
        self.send_daemon_request(
            label,
            active_model_request(selection_id, active, persist_as_default, trigger),
            ControlApplied::ModelSelection { selection_id },
        );
        true
    }
    pub(super) fn show_model_selection_error(
        &mut self,
        active: &cockpit_config::providers::ActiveModelRef,
        trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger,
        message: String,
    ) {
        if matches!(
            trigger,
            cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Picker
        ) {
            self.open_model_picker_highlighting(Some(active));
            if let Overlay::ModelPicker(picker) = &mut self.overlay {
                picker.set_error(message);
            }
            return;
        }
        self.push_plain(message);
    }

    pub(super) fn cycle_footer_model(&mut self, forward: bool) {
        match crate::tui::model_picker::cycle_active_favorite(
            &self.config_snapshot.providers,
            self.active_model_selection.as_ref(),
            &self.usage_models,
            forward,
        ) {
            Ok(Some(active)) => {
                let provider = active.provider.clone();
                let model = active.model.clone();
                if self.notify_active_model_selected(
                    active,
                    false,
                    cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Cycle,
                ) {
                    self.push_plain(format!("/model: selecting {provider}/{model} ★"));
                }
            }
            Ok(None) => {
                self.push_plain(
                    "No other favorite model to cycle to; open `/model` for the full list."
                        .to_string(),
                );
            }
            Err(e) => {
                self.push_plain(format!("/model: {e}"));
            }
        }
    }

    pub(super) fn open_quick_dialog(&mut self) {
        let models = match crate::tui::model_picker::ordered_model_choices(
            &self.launch.cwd,
            self.config_snapshot.extended.llm_mode,
            &self.usage_models,
        ) {
            Ok(choices) => choices
                .into_iter()
                .filter(|choice| choice.is_favorite)
                .map(crate::tui::quick_dialog::QuickModelChoice::from)
                .collect(),
            Err(_) => Vec::new(),
        };
        let current = crate::tui::quick_dialog::QuickCurrent {
            llm_mode: self.llm_mode,
            recursion_enabled: self.delegation_recursion_enabled,
            recursion_depth: self.delegation_recursion_depth,
            sandbox_mode: self.sandbox_mode,
            container_network_enabled: self.container_network_enabled,
            container_availability: self.container_availability.clone(),
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
                        .resolve_capabilities(provider, model)
                        .prompt_cache_retention
                })
                .unwrap_or_default(),
        };
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        self.overlay = Overlay::Quick(crate::tui::quick_dialog::QuickDialog::open(current, models));
    }

    pub(super) fn apply_quick_commit(&mut self, commit: crate::tui::quick_dialog::QuickCommit) {
        if let Some(mode) = commit.llm_mode {
            self.send_daemon_request(
                "/quick",
                cockpit_core::daemon::proto::Request::SetSessionLlmMode { mode },
                ControlApplied::CacheBreakWarning,
            );
        }
        if let Some((enabled, default_depth)) = commit.recursion {
            self.send_daemon_request(
                "/quick",
                cockpit_core::daemon::proto::Request::SetDelegationRecursion {
                    enabled,
                    default_depth,
                },
                ControlApplied::None,
            );
        }
        if commit.sandbox_mode.is_some() || commit.container_network_enabled.is_some() {
            self.send_daemon_request(
                "/quick",
                cockpit_core::daemon::proto::Request::SetSandbox {
                    mode: commit.sandbox_mode,
                    container_network_enabled: commit.container_network_enabled,
                },
                ControlApplied::None,
            );
        }
        if let Some(mode) = commit.approval_mode {
            self.send_daemon_request(
                "/quick",
                cockpit_core::daemon::proto::Request::SetApprovalMode { mode },
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
                    cockpit_core::daemon::proto::UsageKind::Model,
                    format!("{provider}/{model}"),
                    None,
                );
            }
            self.request_model_selection(
                "/quick",
                active,
                false,
                cockpit_core::daemon::proto::ActiveModelSwitchTrigger::Quick,
            );
        }
    }

    pub(super) fn footer_cycle_agent(&mut self) {
        if self.agent_path.len() > 1 {
            self.push_plain(
                "Agent cycle is disabled while an interactive subagent is active.".to_string(),
            );
            return;
        }
        self.cycle_primary_agent();
    }

    pub(super) fn set_footer_llm_mode(&mut self, target: cockpit_config::extended::LlmMode) {
        self.handle_llm_mode_command(target.as_str());
    }

    pub(super) fn previous_llm_mode(
        mode: cockpit_config::extended::LlmMode,
    ) -> cockpit_config::extended::LlmMode {
        match mode {
            cockpit_config::extended::LlmMode::Defensive => {
                cockpit_config::extended::LlmMode::Frontier
            }
            cockpit_config::extended::LlmMode::Normal => {
                cockpit_config::extended::LlmMode::Defensive
            }
            cockpit_config::extended::LlmMode::Frontier => {
                cockpit_config::extended::LlmMode::Normal
            }
        }
    }

    pub(super) fn send_daemon_request(
        &mut self,
        label: &str,
        req: cockpit_core::daemon::proto::Request,
        applied: ControlApplied,
    ) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            self.report_control_not_delivered(label, ControlRequestNotDelivered::NoRunner);
            return;
        };
        self.next_control_request_seq = self.next_control_request_seq.saturating_add(1);
        let request_id = ControlRequestId(self.next_control_request_seq);
        self.pending_control_requests.insert(
            request_id,
            PendingControlRequest {
                label: label.to_string(),
                applied,
            },
        );
        let result = agent_runner::send_control_request(
            &runner.control_tx,
            &runner.events,
            &runner.event_notify,
            request_id,
            req,
        );
        if let Err(reason) = result {
            let selection_id =
                self.pending_control_requests
                    .remove(&request_id)
                    .and_then(|pending| match pending.applied {
                        ControlApplied::ModelSelection { selection_id } => Some(selection_id),
                        _ => None,
                    });
            let message = Self::control_not_delivered_message(label, reason);
            if let Some(pending) = self.clear_pending_model_selection(selection_id) {
                self.show_failed_model_selection(pending, message);
            } else {
                self.push_plain(message);
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
        let selection_id = match pending.applied {
            ControlApplied::ModelSelection { selection_id } => Some(selection_id),
            _ => None,
        };
        match outcome {
            ControlRequestOutcome::Applied => self.apply_control_success(pending.applied),
            ControlRequestOutcome::Rejected(error) => {
                let message = format!("{}: daemon rejected request: {error}", pending.label);
                if let Some(selection) = self.clear_pending_model_selection(selection_id) {
                    self.show_failed_model_selection(selection, message);
                } else {
                    self.push_plain(message);
                }
            }
            ControlRequestOutcome::NotDelivered(reason) => {
                let message = Self::control_not_delivered_message(&pending.label, reason);
                if let Some(selection) = self.clear_pending_model_selection(selection_id) {
                    self.show_failed_model_selection(selection, message);
                } else {
                    self.push_plain(message);
                }
            }
        }
    }

    fn clear_pending_model_selection(
        &mut self,
        selection_id: Option<uuid::Uuid>,
    ) -> Option<super::PendingModelSelection> {
        let pending = self.pending_model_selection.as_ref()?;
        if Some(pending.selection_id) != selection_id {
            return None;
        }
        self.pending_model_selection.take()
    }

    fn show_failed_model_selection(
        &mut self,
        pending: super::PendingModelSelection,
        message: String,
    ) {
        self.show_model_selection_error(&pending.requested, pending.trigger, message);
    }

    fn apply_control_success(&mut self, applied: ControlApplied) {
        match applied {
            ControlApplied::None => {}
            ControlApplied::ModelSelection { .. } => {}
            ControlApplied::CacheBreakWarning => {
                if let Some(warning) = self.cache_break_warning() {
                    self.push_plain(warning);
                }
            }
            ControlApplied::LlmModeSwitchWarning => {
                if let Some(warning) = self.llm_mode_switch_warning() {
                    self.push_plain(warning);
                }
            }
            ControlApplied::PrimaryAgentSwitch { name } => {
                self.record_primary_switch_confirmation(&name);
            }
            ControlApplied::Multireview { kickoff } => {
                self.push_plain(MULTIREVIEW_TOKEN_BURN_WARNING.to_string());
                self.begin_working_span();
                let submission = cockpit_core::engine::message::UserSubmission {
                    kind: cockpit_core::engine::message::UserSubmissionKind::User,
                    text: kickoff.clone(),
                    display_text: None,
                    tag_expansions: Vec::new(),
                    images: Vec::new(),
                    forced_skill: None,
                    origin_principal: None,
                    job_id: None,
                    preflight_cleaned: None,
                    queue_item_ids: Vec::new(),
                    queue_target: None,
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

    /// The anti-misfire lockout to stamp on a question dialog about to be
    /// installed (implementation note). Returns the
    /// configured `lockout_ms` only on the genuine composer→dialog edge —
    /// the composer has actually been the active input surface since the
    /// last dialog closed (`composer_active_since_dialog`) — and
    /// [`Duration::ZERO`] (immediately answerable) for a direct
    /// continuation, where one dialog succeeds another without the composer
    /// ever regaining focus (including the same resolve/poll cycle). Either
    /// way the composer is now displaced, so the flag is consumed; a render
    /// pass with no dialog re-arms it.
    pub(super) fn dialog_lockout(&mut self) -> Duration {
        let lockout = if self.composer_active_since_dialog {
            Duration::from_millis(self.config_snapshot.extended.dialog.lockout_ms)
        } else {
            crate::tui::dialog::DialogState::NO_LOCKOUT
        };
        self.composer_active_since_dialog = false;
        lockout
    }

    /// Full lockout for a daemon-authoritative interrupt restored after
    /// attach/reconnect. Unlike FIFO queue advancement, rehydration can put a
    /// dialog under input that was intended for the composer or another
    /// surface, so it deliberately starts a new anti-misfire window.
    pub(super) fn rehydrated_dialog_lockout(&mut self) -> Duration {
        self.composer_active_since_dialog = false;
        Duration::from_millis(self.config_snapshot.extended.dialog.lockout_ms)
    }
}

fn active_model_request(
    selection_id: uuid::Uuid,
    active: cockpit_config::providers::ActiveModelRef,
    persist_as_default: bool,
    trigger: cockpit_core::daemon::proto::ActiveModelSwitchTrigger,
) -> cockpit_core::daemon::proto::Request {
    cockpit_core::daemon::proto::Request::SetActiveModel {
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
