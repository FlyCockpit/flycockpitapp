use super::*;

impl App {
    pub(super) fn swap_primary_agent(&mut self, name: &str) {
        if crate::agents::is_hidden_primary(name) {
            self.push_plain(format!(
                "`{name}` is hidden — start it with `/multireview`."
            ));
            return;
        }
        // Experimental-mode gate (implementation note):
        // with the flag off, a swap that targets a gated builtin
        // (`Auto`/`Plan`/`Swarm`/`Build`) is rejected with a one-line
        // history message and does NOT swap. Routed through the same
        // `is_experimental_primary` predicate the hiding uses (no duplicated
        // name list). This is the single chokepoint every swap route
        // (`/plan`/`/swarm`/`/build`, `/agent <gated>`, `Shift+Tab`)
        // passes through; the gated names are already hidden from the cycle /
        // `/agent` list, so this guards a direct `/plan`-style invocation.
        if crate::agents::is_experimental_primary(name)
            && !crate::config::extended::load_for_cwd(&self.launch.cwd).experimental_mode
        {
            self.push_plain(format!(
                "`{name}` requires experimental mode — enable it in `/settings`."
            ));
            return;
        }
        let sent = self.send_daemon_request(crate::daemon::proto::Request::SetAgent {
            name: name.to_string(),
        });
        if sent {
            self.record_primary_switch_confirmation(name);
        } else {
            self.push_plain(
                "Send a message first to start a session, then switch agents".to_string(),
            );
        }
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
        let sent = self.send_daemon_request(crate::daemon::proto::Request::SetAgent {
            name: "Multireview".to_string(),
        });
        if !sent {
            self.push_plain(
                "Send a message first to start a session, then run `/multireview`".to_string(),
            );
            return;
        }
        self.push_plain(MULTIREVIEW_TOKEN_BURN_WARNING.to_string());
        self.begin_working_span();
        let submission = crate::engine::message::UserSubmission {
            kind: crate::engine::message::UserSubmissionKind::User,
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
        self.dispatch_optimistic_user_submission(kickoff, submission, "/multireview", true, &[]);
    }

    /// `Shift+Tab` — advance the active primary to the next agent in the
    /// wrapping cycle `Auto → Plan → Build → Swarm → <user primaries alpha> → Auto`
    /// (implementation note). Routes through
    /// [`Self::swap_primary_agent`], so it carries the same confirmation
    /// line and start-a-session-first guard `/plan`/`/build` have.
    pub(super) fn cycle_primary_agent(&mut self) {
        let order = crate::agents::chat_ownable_primaries(&self.launch.cwd);
        let next = crate::agents::next_primary_in_cycle(&self.launch.agent_name, &order);
        self.swap_primary_agent(&next);
    }

    pub(super) fn open_footer_agent_picker(&mut self) {
        self.footer_mode_picker = None;
        let order = crate::agents::chat_ownable_primaries(&self.launch.cwd);
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
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        match crate::tui::model_picker::ModelPickerDialog::open_with_failures(
            &self.launch.cwd,
            &self.usage_models,
            &self.auth_failure_annotations,
            chrono::Utc::now().timestamp(),
        ) {
            Ok(picker) => {
                self.overlay = Overlay::ModelPicker(picker);
            }
            Err(e) => {
                self.push_plain(format!("/model: {e}"));
            }
        }
    }

    pub(super) fn record_auth_failure(
        &mut self,
        provider: String,
        model: String,
        kind: crate::daemon::proto::AuthFailureKind,
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
            crate::tui::auth_failure::provider_auth_fingerprint(&self.launch.cwd, &provider),
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
                        &self.launch.cwd,
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
            crate::daemon::proto::AuthFailureKind::OAuthExpired { .. }
        );
        self.dialog = crate::tui::settings::Dialog::open_provider_settings(
            &self.launch.cwd,
            &notice.provider,
            oauth_expired,
        );
    }

    pub(super) fn close_model_picker(&mut self, accepted: bool) {
        self.overlay = Overlay::None;
        self.reload_launch_info();
        if accepted && let Some((p, m)) = self.launch.active_model.clone() {
            self.notify_active_model_selected(p, m);
        }
        let line = self.model_summary_history_line();
        self.push_plain(line);
    }

    pub(super) fn notify_active_model_selected(&mut self, provider: String, model: String) {
        self.record_usage(
            crate::daemon::proto::UsageKind::Model,
            format!("{provider}/{model}"),
            None,
        );
        self.send_daemon_request(crate::daemon::proto::Request::SetActiveModel { provider, model });
    }

    pub(super) fn cycle_footer_model(&mut self, forward: bool) {
        match crate::tui::model_picker::cycle_active_favorite(
            &self.launch.cwd,
            &self.usage_models,
            forward,
        ) {
            Ok(Some((provider, model))) => {
                self.reload_launch_info();
                self.notify_active_model_selected(provider.clone(), model.clone());
                self.push_plain(format!("/model: active model is now {provider}/{model} ★"));
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
            trusted_only: self.trusted_only_enabled,
            sandbox_mode: self.sandbox_mode,
            container_network_enabled: self.container_network_enabled,
            container_availability: self.container_availability.clone(),
            approval_mode: self.approval_mode,
            active_model: self.launch.active_model.clone(),
        };
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        self.overlay = Overlay::Quick(crate::tui::quick_dialog::QuickDialog::open(current, models));
    }

    pub(super) fn apply_quick_commit(&mut self, commit: crate::tui::quick_dialog::QuickCommit) {
        let mut any_failed = false;
        if let Some(mode) = commit.llm_mode {
            if self.send_daemon_request(crate::daemon::proto::Request::SetSessionLlmMode { mode }) {
                if let Some(warning) = self.cache_break_warning() {
                    self.push_plain(warning);
                }
            } else {
                any_failed = true;
            }
        }
        if let Some((enabled, default_depth)) = commit.recursion
            && !self.send_daemon_request(crate::daemon::proto::Request::SetDelegationRecursion {
                enabled,
                default_depth,
            })
        {
            any_failed = true;
        }
        if let Some(enabled) = commit.trusted_only
            && !self.send_daemon_request(crate::daemon::proto::Request::SetTrustedOnly {
                enabled: Some(enabled),
            })
        {
            any_failed = true;
        }
        if (commit.sandbox_mode.is_some() || commit.container_network_enabled.is_some())
            && !self.send_daemon_request(crate::daemon::proto::Request::SetSandbox {
                mode: commit.sandbox_mode,
                container_network_enabled: commit.container_network_enabled,
            })
        {
            any_failed = true;
        }
        if let Some(mode) = commit.approval_mode
            && !self.send_daemon_request(crate::daemon::proto::Request::SetApprovalMode { mode })
        {
            any_failed = true;
        }
        if let Some((provider, model)) = commit.active_model {
            self.record_usage(
                crate::daemon::proto::UsageKind::Model,
                format!("{provider}/{model}"),
                None,
            );
            if self.send_daemon_request(crate::daemon::proto::Request::SetActiveModel {
                provider: provider.clone(),
                model: model.clone(),
            }) {
                self.launch.active_model = Some((provider.clone(), model.clone()));
                self.push_plain(format!("/quick: active model is now {provider}/{model}"));
            } else {
                any_failed = true;
            }
        }
        if any_failed {
            self.push_plain("/quick: send a message first to start a session".to_string());
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

    pub(super) fn set_footer_llm_mode(&mut self, target: crate::config::extended::LlmMode) {
        self.handle_llm_mode_command(target.as_str());
    }

    pub(super) fn previous_llm_mode(
        mode: crate::config::extended::LlmMode,
    ) -> crate::config::extended::LlmMode {
        match mode {
            crate::config::extended::LlmMode::Defensive => {
                crate::config::extended::LlmMode::Frontier
            }
            crate::config::extended::LlmMode::Normal => crate::config::extended::LlmMode::Defensive,
            crate::config::extended::LlmMode::Frontier => crate::config::extended::LlmMode::Normal,
        }
    }

    /// Send a fire-and-forget daemon request over the runner's record
    /// channel (same path `/schedule cancel` uses). Returns whether a runner
    /// was connected to receive it.
    pub(super) fn send_daemon_request(&self, req: crate::daemon::proto::Request) -> bool {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.record_tx.try_send(req).is_ok(),
            _ => false,
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
            Duration::from_millis(load_dialog_config(&self.launch.cwd).lockout_ms)
        } else {
            crate::tui::dialog::DialogState::NO_LOCKOUT
        };
        self.composer_active_since_dialog = false;
        lockout
    }

    /// Fresh lockout for daemon-authoritative interrupt re-install paths:
    /// queue advance and attach re-hydration. The old zero-lockout branch is
    /// still valid for a genuine same-flow continuation, but FIFO advance and
    /// re-hydration are new dialogs from the user's perspective and must not
    /// be immediately answerable.
    pub(super) fn fresh_dialog_lockout(&mut self) -> Duration {
        self.composer_active_since_dialog = false;
        Duration::from_millis(load_dialog_config(&self.launch.cwd).lockout_ms)
    }
}
