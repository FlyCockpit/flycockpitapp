use super::*;

impl App {
    /// If the user has no providers configured in the active config
    /// layer, open onboarding directly. No-op when
    /// providers already exist or when the settings dialog is already
    /// open. Evaluated each launch so emptying the providers list
    /// re-triggers the wizard on the next start.
    pub(super) fn maybe_open_add_provider_wizard(&mut self) {
        if self.dialog.is_active() {
            return;
        }
        if !self.has_no_providers_at_startup {
            return;
        }
        self.first_run_flow = FirstRunFlow::AwaitWelcome;
        self.dialog = crate::tui::settings::Dialog::open_onboarding_welcome(&self.launch.cwd);
    }

    pub(super) fn service_first_run_flow(&mut self) -> bool {
        match self.first_run_flow {
            FirstRunFlow::None => false,
            FirstRunFlow::AwaitWelcome => {
                if !self.dialog.setup_wizard_is_active(
                    cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
                ) {
                    return false;
                }
                self.first_run_flow = FirstRunFlow::AwaitProfile;
                true
            }
            FirstRunFlow::AwaitProfile => {
                if !self.dialog.setup_wizard_is_complete(
                    cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
                ) {
                    return false;
                }
                self.refresh_bootstrap_config_snapshot();
                self.dialog = crate::tui::settings::Dialog::open_providers_add_with_status(
                    &self.launch.cwd,
                    Some("Choose a subscription or API provider. Press Esc for ‘I’ll do this later’; setup will return next launch.".to_string()),
                );
                self.first_run_flow = FirstRunFlow::AwaitProvider;
                true
            }
            FirstRunFlow::AwaitProvider => {
                let Some(provider_id) = self.dialog.take_completed_provider_id() else {
                    return false;
                };
                self.refresh_bootstrap_config_snapshot();
                let model_id =
                    first_provider_model_id(&self.config_snapshot.providers, &provider_id);
                let dialog = match model_id.as_deref() {
                    Some(model_id) => crate::tui::settings::Dialog::open_model_setup_preselected(
                        &self.launch.cwd,
                        &provider_id,
                        model_id,
                        Some("Choose the model Cockpit should use by default.".to_string()),
                    ),
                    None => crate::tui::settings::Dialog::open_setup_wizard(
                        &self.launch.cwd,
                        cockpit_core::wizard::MODEL_WIZARD_ID,
                    ),
                };
                match dialog {
                    Ok(dialog) => {
                        self.dialog = dialog;
                        self.first_run_flow = FirstRunFlow::AwaitModel;
                    }
                    Err(error) => {
                        self.first_run_flow = FirstRunFlow::None;
                        self.show_toast(error, super::ToastKind::Error);
                    }
                }
                true
            }
            FirstRunFlow::AwaitModel => {
                if !self
                    .dialog
                    .setup_wizard_is_complete(cockpit_core::wizard::MODEL_WIZARD_ID)
                {
                    return false;
                }
                self.refresh_bootstrap_config_snapshot();
                let configured_model = self.config_snapshot.providers.active_model.clone();
                let summary = configured_model
                    .as_ref()
                    .map(|active| {
                        format!(
                            "Configured {}/{} as the default model for future sessions.",
                            active.provider, active.model
                        )
                    })
                    .unwrap_or_else(|| {
                        "Model configuration finished; no default model was selected.".to_string()
                    });
                self.dialog = crate::tui::settings::Dialog::open_first_run_complete(format!(
                    "{summary} Add another provider any time with /provider add. Suggested first prompt: ‘Help me understand this codebase.’"
                ));
                self.first_run_flow = FirstRunFlow::AwaitFinish;
                if self.submit_after_model_selection {
                    match configured_model {
                        Some(active) => {
                            if self.notify_active_model_selected(
                                active,
                                false,
                                cockpit_proto::ActiveModelSwitchTrigger::Picker,
                            ) {
                                self.submit_after_model_selection = false;
                                let _ = self.submit_input();
                            }
                        }
                        None => {
                            self.submit_after_model_selection = false;
                            self.push_plain(
                                "Your draft is still here; choose a model before sending."
                                    .to_string(),
                            );
                        }
                    }
                }
                true
            }
            FirstRunFlow::AwaitFinish => {
                let Some(choice) = self.dialog.take_first_run_choice() else {
                    return false;
                };
                match choice {
                    crate::tui::settings::FirstRunChoice::AddAnotherProvider => {
                        self.dialog =
                            crate::tui::settings::Dialog::open_providers_add(&self.launch.cwd);
                        self.first_run_flow = FirstRunFlow::AwaitProvider;
                    }
                    crate::tui::settings::FirstRunChoice::StartCoding => {
                        self.dialog = crate::tui::settings::Dialog::None;
                        self.first_run_flow = FirstRunFlow::None;
                    }
                }
                true
            }
        }
    }

    pub(super) fn apply_startup_guidance_estimate(
        &mut self,
        cwd: PathBuf,
        active_model: Option<(String, String)>,
        estimate: agent_runner::GuidanceEstimate,
    ) {
        if cwd == self.launch.cwd && active_model == self.launch.active_model {
            self.guidance_estimate = Some(estimate);
        }
    }

    pub(super) fn start_startup_background_tasks(&mut self) {
        if self.startup_background.started {
            return;
        }
        self.startup_background.started = true;

        tokio::task::spawn_blocking(cockpit_core::tokens::warm_cl100k);

        let cwd = self.launch.cwd.clone();
        let active_model = self.launch.active_model.clone();
        let endpoint = self.attached_daemon_endpoint();
        let providers = self.config_snapshot.providers.clone();
        self.async_actions.start(
            AsyncActionKind::Internal("startup.guidance.estimate"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("startup.guidance.estimate")),
            async move {
                let (provider, model) = match &active_model {
                    Some((p, m)) => (Some(p.clone()), Some(m.clone())),
                    None => (None, None),
                };
                let estimate = agent_runner::fetch_guidance_estimate_with_endpoint(
                    &cwd, providers, provider, model, endpoint,
                )
                .await;
                Ok(AsyncActionPayload::StartupGuidanceEstimate {
                    cwd,
                    active_model,
                    estimate,
                })
            },
        );

        // Pre-daemon / in-process doctor snapshot for Settings before attach.
        // This is not the daemon capability authority. After the daemon is
        // up, clients must consult `GetHostCapabilities` /
        // `HostCapabilitySnapshot` instead of this TUI-process compose.
        let dependency_cwd = self.launch.cwd.clone();
        let sandbox_enabled = !self.no_sandbox;
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("startup.dependencies"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("startup.dependencies")),
            move || {
                cockpit_core::diagnostics::dependency_projection_with_deadline_and_publish_for_run(
                    dependency_cwd,
                    std::time::Duration::from_secs(2),
                    sandbox_enabled,
                )
                .map(AsyncActionPayload::StartupDependencyProjection)
                .map_err(|error| error.to_string())
            },
        );

        #[cfg(feature = "remote")]
        self.start_startup_disclosures_fetch();
    }

    #[cfg(feature = "remote")]
    pub(super) fn start_startup_disclosures_fetch(&mut self) {
        self.startup_disclosures_generation = self.startup_disclosures_generation.wrapping_add(1);
        let request_generation = self.startup_disclosures_generation;
        let disclosure_root = self.launch.cwd.to_string_lossy().into_owned();
        let disclosure_endpoint = self.attached_daemon_endpoint();
        let launch_session_id = self.launch.session_id;
        let (session_id, attachment_epoch) = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .filter(|runner| runner.has_attached_client())
            .map(|runner| (Some(runner.session_id()), Some(runner.attachment_epoch())))
            .unwrap_or((None, None));
        let request_socket = self.startup_background.daemon_socket.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("startup.remote_disclosures"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("startup.remote_disclosures")),
            move || {
                let request = cockpit_proto::Request::GetStartupDisclosures {
                    project_root: disclosure_root.clone(),
                };
                let endpoint = disclosure_endpoint.ok_or_else(|| {
                    "daemon endpoint unavailable for startup disclosures".to_string()
                })?;
                let response = agent_runner::daemon_request_at_blocking(&endpoint, request)?;
                match response {
                    cockpit_proto::Response::StartupDisclosures {
                        org_sync,
                        connector,
                        ..
                    } => Ok(AsyncActionPayload::RemoteDisclosures {
                        project_root: disclosure_root,
                        request_generation,
                        socket: request_socket,
                        launch_session_id,
                        session_id,
                        attachment_epoch,
                        org: org_sync,
                        connector,
                    }),
                    other => Err(format!(
                        "unexpected startup disclosures response: {other:?}"
                    )),
                }
            },
        );
    }

    pub(super) fn geometry(&self) -> PaneGeometry {
        let dialog = if self.dialog.is_active() {
            settings::DIALOG_HEIGHT
        } else if self.overlay.dialog_height() > 0 {
            self.overlay.dialog_height()
        } else if self.footer_agent_picker.is_some() {
            footer_agent_picker_height(self.footer_agent_picker.as_ref())
        } else {
            0
        };
        // The answering dialog (GOALS §3b) is a compact, bottom-anchored
        // overlay sized to its content (capped), not a fullscreen modal.
        let compact = self
            .question_dialog
            .as_ref()
            .map(|d| d.desired_height())
            .unwrap_or_else(|| 0);
        PaneGeometry::compute(
            self.input_height(),
            self.indicator_lines(),
            self.queue_lines(),
            self.suggestion_box_lines(),
            self.pins_indicator_lines(),
            self.sandbox_notice_lines(),
            self.total_history_lines(),
            dialog,
            compact,
        )
    }

    /// Height of the below-input pin-count indicator (`pinned-messages`):
    /// one row when the session has ≥1 pin, hidden (zero) otherwise.
    pub(super) fn pins_indicator_lines(&self) -> u16 {
        if self.pin_count > 0 { 1 } else { 0 }
    }

    /// Full text of the persistent sandbox-down notice (§6.5), or `None` when
    /// the sandbox is fine. Combines the diagnosed remedy (incl. the `sudo
    /// sysctl …=0` command when present) with the deterministic `/sandbox off`
    /// instruction the user must act on. Pure UI chrome — never enters history
    /// or any inference request.
    pub(super) fn sandbox_down_notice_text(&self) -> Option<String> {
        self.sandbox_down_notice.as_ref().map(|notice| {
            if let Some(banner) = crate::tui::capability_gate::sandbox_intent_effective_banner(
                self.sandbox_intent,
                self.sandbox_mode,
                &self.host_capabilities,
            ) {
                return banner;
            }
            let intent = if self.sandbox_intent != self.sandbox_mode {
                Some(self.sandbox_intent)
            } else {
                None
            };
            super::sandbox_down_notice_text_with_intent(
                &notice.remedy,
                notice.fix_command.as_deref(),
                notice.fix_command.is_some(),
                intent,
            )
        })
    }

    pub(super) fn command_capability_notice_text(&self) -> Option<String> {
        self.command_capability_notice.as_ref().map(|notice| {
            command_capability_notice_text(
                &notice.text,
                notice.fix_command.as_deref(),
                notice.fix_command.is_some(),
            )
        })
    }

    pub(super) fn persistent_notice_fix_command(&self) -> Option<&str> {
        self.sandbox_down_notice
            .as_ref()
            .and_then(|notice| notice.fix_command.as_deref())
            .or_else(|| {
                self.command_capability_notice
                    .as_ref()
                    .and_then(|notice| notice.fix_command.as_deref())
            })
    }

    pub(super) fn persistent_notice_text(&self) -> Option<String> {
        // Sandbox recovery is safety-critical, so it keeps the shared notice
        // row while active. Command-capability startup notices are next; the
        // auth notice remains queued until higher-priority remedies clear.
        self.sandbox_down_notice_text()
            .or_else(|| self.command_capability_notice_text())
            .or_else(|| {
                self.auth_failure_notice
                    .as_ref()
                    .map(|notice| crate::tui::auth_failure::notice_text(notice, true))
            })
    }

    /// Height of the persistent below-input sandbox-down notice (§6.5): its
    /// wrapped row count (capped) when the sandbox can't initialize, zero
    /// otherwise. Persistent — never times out like a toast.
    pub(super) fn sandbox_notice_lines(&self) -> u16 {
        let Some(text) = self.persistent_notice_text() else {
            return 0;
        };
        let (term_w, _) = crossterm::terminal::size().unwrap_or((80, 24));
        sandbox_notice_wrapped_rows(&text, term_w)
    }
}

fn first_provider_model_id(
    providers: &cockpit_config::providers::ProvidersConfig,
    provider_id: &str,
) -> Option<String> {
    providers
        .providers
        .get(provider_id)?
        .models
        .first()
        .map(|model| model.id.clone())
}
