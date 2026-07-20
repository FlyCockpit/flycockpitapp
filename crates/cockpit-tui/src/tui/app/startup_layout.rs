use super::*;

impl App {
    /// If the user has no providers configured in the active config
    /// layer, open `/settings → Providers → Add` directly. No-op when
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
        self.first_run_flow = FirstRunFlow::AwaitProvider;
        self.dialog = crate::tui::settings::Dialog::open_providers_add(&self.launch.cwd);
    }

    pub(super) fn service_first_run_flow(&mut self) -> bool {
        match self.first_run_flow {
            FirstRunFlow::None => false,
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
                self.dialog = crate::tui::settings::Dialog::open_first_run_complete();
                self.first_run_flow = FirstRunFlow::None;
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
        let socket = self.startup_background.daemon_socket.clone();
        let providers = self.config_snapshot.providers.clone();
        self.async_actions.start(
            AsyncActionKind::Internal("startup.guidance.estimate"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("startup.guidance.estimate")),
            async move {
                let (provider, model) = match &active_model {
                    Some((p, m)) => (Some(p.clone()), Some(m.clone())),
                    None => (None, None),
                };
                let estimate = agent_runner::fetch_guidance_estimate_with_socket(
                    &cwd, providers, provider, model, socket,
                )
                .await;
                Ok(AsyncActionPayload::StartupGuidanceEstimate {
                    cwd,
                    active_model,
                    estimate,
                })
            },
        );

        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("container.availability"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("container.availability")),
            || {
                Ok(AsyncActionPayload::ContainerAvailability(
                    cockpit_core::container::availability_snapshot(),
                ))
            },
        );

        let db = self.startup_background.db.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("startup.remote_disclosures"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("startup.remote_disclosures")),
            move || {
                let Some(credential) = cockpit_core::auth::flycockpit::maybe_load_credential()
                else {
                    return Ok(AsyncActionPayload::RemoteDisclosures {
                        org: None,
                        connector: None,
                    });
                };
                let db = match db {
                    Some(db) => db,
                    None => cockpit_db::Db::open_default().map_err(|e| e.to_string())?,
                };
                let org = db
                    .org_sync_disclosure_for_server(&credential.server_url)
                    .map_err(|e| e.to_string())?;
                let connector = db
                    .connector_disclosure(&credential.server_url, &credential.instance_id)
                    .map_err(|e| e.to_string())?;
                Ok(AsyncActionPayload::RemoteDisclosures { org, connector })
            },
        );
    }

    pub(super) fn geometry(&self) -> PaneGeometry {
        let dialog = if self.daemon_prompt.is_some() {
            crate::tui::daemon_prompt::DIALOG_HEIGHT
        } else if self.dialog.is_active() {
            settings::DIALOG_HEIGHT
        } else if self.overlay.dialog_height() > 0 {
            self.overlay.dialog_height()
        } else if self.footer_agent_picker.is_some() {
            footer_agent_picker_height(self.footer_agent_picker.as_ref())
        } else if self.footer_mode_picker.is_some() {
            FOOTER_MODE_ORDER.len() as u16 + 4
        } else {
            0
        };
        // The answering dialog (GOALS §3b) is a compact, bottom-anchored
        // overlay sized to its content (capped), not a fullscreen modal.
        let compact = self
            .question_dialog
            .as_ref()
            .map(|d| d.desired_height())
            .unwrap_or(0);
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
            sandbox_down_notice_text(
                &notice.remedy,
                notice.fix_command.as_deref(),
                self.mouse_capture && notice.fix_command.is_some(),
            )
        })
    }

    pub(super) fn command_capability_notice_text(&self) -> Option<String> {
        self.command_capability_notice.as_ref().map(|notice| {
            command_capability_notice_text(
                &notice.text,
                notice.fix_command.as_deref(),
                self.mouse_capture && notice.fix_command.is_some(),
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
                    .map(|notice| crate::tui::auth_failure::notice_text(notice, self.mouse_capture))
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
