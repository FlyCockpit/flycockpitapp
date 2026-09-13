use super::*;

fn onboarding_ready_construction_retry_required(error: &cockpit_proto::ErrorPayload) -> bool {
    error.code == cockpit_proto::ErrorCode::Internal
        && error.message.contains("retry ready construction")
}

async fn retry_onboarding_ready_construction_snapshot(
    lifecycle: &cockpit_client::LifecycleClient,
) -> Result<Option<cockpit_proto::OnboardingBootstrapSnapshot>, String> {
    let client = crate::tui::settings::settings_daemon_client(lifecycle)
        .await
        .map_err(|error| error.to_string())?;
    match client
        .retry_onboarding_ready_construction()
        .await
        .map_err(|error| error.to_string())?
    {
        Ok(snapshot) => Ok(Some(snapshot)),
        Err(error) => Err(error.to_string()),
    }
}

async fn onboarding_snapshot_after_secure_intent(
    lifecycle: &cockpit_client::LifecycleClient,
    request: cockpit_proto::ApplyOnboardingSecureIntent,
) -> Result<Option<cockpit_proto::OnboardingBootstrapSnapshot>, String> {
    let resolved = lifecycle
        .resolve_default()
        .await
        .map_err(|error| error.to_string())?;
    let client = cockpit_client::DaemonClient::connect_endpoint(&resolved.endpoint)
        .await
        .map_err(|error| error.to_string())?;
    match client
        .apply_onboarding_secure_intent(&resolved.endpoint, request)
        .await
        .map_err(|error| error.to_string())?
    {
        Ok(result) => Ok(Some(result.snapshot)),
        Err(error) if onboarding_ready_construction_retry_required(&error) => {
            retry_onboarding_ready_construction_snapshot(lifecycle).await
        }
        Err(error) => Err(error.to_string()),
    }
}

impl App {
    pub fn configure_onboarding_launch(&mut self, skip: bool, force: bool) {
        self.onboarding_skip = skip;
        self.onboarding_force = force;
        if skip {
            self.onboarding_snapshot = None;
            self.onboarding_shell = None;
            self.dialog = crate::tui::settings::Dialog::None;
        }
    }

    pub(super) fn start_onboarding_bootstrap_fetch(&mut self) {
        if self.onboarding_skip {
            return;
        }
        let lifecycle = self.lifecycle.clone();
        let force = self.onboarding_force;
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.bootstrap"),
            ),
            async move {
                let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                    .await
                    .map_err(|error| error.to_string())?;
                let current = match client
                    .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot)) => snapshot,
                    Ok(other) => return Err(format!("unexpected onboarding response: {other:?}")),
                    Err(error) => return Err(error.to_string()),
                };
                if current.as_ref().is_some_and(|snapshot| {
                    snapshot.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
                }) {
                    return retry_onboarding_ready_construction_snapshot(&lifecycle)
                        .await
                        .map(crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap);
                }
                if current.as_ref().is_some_and(|snapshot| {
                    !force && snapshot.stage == cockpit_proto::OnboardingStage::Complete
                }) {
                    return Ok(
                        crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(current),
                    );
                }
                let request = cockpit_proto::BeginOrReopenOnboarding {
                    expected_revision: current.as_ref().map(|snapshot| snapshot.revision),
                    client_operation_id: uuid::Uuid::new_v4().to_string(),
                    reentry: force || current.is_some(),
                };
                match client
                    .request(cockpit_proto::Request::BeginOrReopenOnboarding(request))
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Ok(cockpit_proto::Response::OnboardingTransition(result)) => Ok(
                        crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(Some(
                            result.snapshot,
                        )),
                    ),
                    Ok(other) => Err(format!("unexpected onboarding response: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
    }

    pub(super) fn apply_onboarding_bootstrap_snapshot(
        &mut self,
        snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
    ) {
        if snapshot.as_ref().is_some_and(|current| {
            current.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
        }) {
            self.start_onboarding_ready_construction_retry();
            return;
        }
        self.onboarding_snapshot = snapshot;
        if let Some(snapshot) = self.onboarding_snapshot.clone() {
            self.sync_onboarding_shell(&snapshot);
        } else {
            self.onboarding_shell = None;
        }
    }

    /// Activate, update, or retire the full-screen onboarding shell so it
    /// always mirrors the authoritative daemon snapshot. This is the single
    /// onboarding entry/exit point: fresh launch, resume, deferred resume,
    /// and post-transition refreshes all flow through here.
    ///
    /// A user-dismissed shell never reopens from a snapshot alone: Cancel,
    /// close, and late authority results stay inert for occupancy while
    /// still updating the stored snapshot (committed daemon progress is
    /// never lost). Explicit re-entry (the no-provider send guard, or a
    /// fresh launch) clears the dismissal.
    ///
    /// A deferred run (`limited_mode`) does not auto-open the shell: defer
    /// means "limited mode now"; the shell reopens through the no-provider
    /// send guard or an explicit re-entry. A snapshot that commits the
    /// deferral closes a currently open shell.
    pub(super) fn sync_onboarding_shell(
        &mut self,
        snapshot: &cockpit_proto::OnboardingBootstrapSnapshot,
    ) {
        if self.onboarding_skip {
            self.onboarding_shell = None;
            return;
        }
        if self.onboarding_dismissed {
            // The user closed the shell; a snapshot alone must not reopen
            // it (an in-flight transition result arriving after Cancel
            // stays inert for occupancy).
            return;
        }
        if snapshot.stage == cockpit_proto::OnboardingStage::Complete {
            // A completed run presents no onboarding surface to a fresh
            // launch. A shell that is still open just committed its own
            // terminal transition: present the completion screen from the
            // summary recorded when the lifetime stage settled. "Add
            // another provider" is a local detour on top of that screen and
            // never reaches this branch.
            if let Some(shell) = self.onboarding_shell.as_mut() {
                if shell.note_authoritative_complete(snapshot) {
                    self.dialog = crate::tui::settings::Dialog::None;
                }
            } else {
                self.onboarding_shell = None;
                self.dialog = crate::tui::settings::Dialog::None;
            }
            return;
        }
        if snapshot.limited_mode {
            // Deferred limited mode: the ordinary composer is the surface,
            // guarded by the existing no-provider send rule.
            self.onboarding_shell = None;
            self.dialog = crate::tui::settings::Dialog::None;
            return;
        }
        let remount_engine = if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.sync_snapshot(snapshot)
        } else {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
            true
        };
        if remount_engine {
            self.mount_onboarding_engine(snapshot.stage);
        }
    }

    /// User-initiated reopen (the no-provider send guard): present the
    /// authoritative stage through the shell even in deferred limited mode.
    /// Explicit re-entry clears the dismissal fence.
    pub(super) fn reopen_onboarding_shell(
        &mut self,
        snapshot: &cockpit_proto::OnboardingBootstrapSnapshot,
    ) {
        if self.onboarding_skip || snapshot.stage == cockpit_proto::OnboardingStage::Complete {
            return;
        }
        self.onboarding_dismissed = false;
        if self.onboarding_shell.is_none() {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
            self.mount_onboarding_engine(snapshot.stage);
        }
    }

    /// Read-only refresh of the authoritative bootstrap snapshot. Used by
    /// the daemon-global `OnboardingBootstrap` broadcast so concurrent
    /// clients follow authority changes; unlike the initial fetch it never
    /// begins or reopens a run (a reopen would supersede the active
    /// attempt and invalidate in-flight transition revisions).
    pub(super) fn refresh_onboarding_bootstrap_snapshot(&mut self) {
        if self.onboarding_skip {
            return;
        }
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap_refresh"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.bootstrap_refresh"),
            ),
            async move {
                let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                    .await
                    .map_err(|error| error.to_string())?;
                let current = match client
                    .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot)) => snapshot,
                    Ok(other) => return Err(format!("unexpected onboarding response: {other:?}")),
                    Err(error) => return Err(error.to_string()),
                };
                if current.as_ref().is_some_and(|snapshot| {
                    snapshot.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
                }) {
                    return retry_onboarding_ready_construction_snapshot(&lifecycle)
                        .await
                        .map(crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap);
                }
                Ok(crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(current))
            },
        );
    }

    /// Mount the settings-dialog engine for wizard stages. The engine stays
    /// in `App.dialog` so every daemon-effect, OAuth, paste, and pointer
    /// accessor keeps flowing through the ordinary `Dialog` dispatch; the
    /// shell only records the pairing via `present_engine`.
    fn mount_onboarding_engine(&mut self, stage: cockpit_proto::OnboardingStage) {
        use cockpit_proto::OnboardingStage;
        match stage {
            OnboardingStage::Welcome | OnboardingStage::SecureStore => {
                self.dialog = crate::tui::settings::Dialog::None;
            }
            OnboardingStage::Profile => {
                self.mount_onboarding_wizard(
                    cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
                    None,
                    None,
                );
            }
            OnboardingStage::Provider => {
                if self.dialog.is_provider_add() {
                    if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.present_engine(crate::tui::onboarding::EngineStage::Provider);
                    }
                } else {
                    self.dialog = crate::tui::settings::Dialog::None;
                    if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.present_provider_search(Some(
                            "Pick a provider and sign in; setup resumes here.".to_string(),
                        ));
                    }
                }
            }
            OnboardingStage::Model => {
                // Seed the model wizard with the committed provider's first
                // catalog model when one exists; manual entry stays available
                // when it does not.
                let preselected = self
                    .config_snapshot
                    .providers
                    .providers
                    .iter()
                    .next()
                    .and_then(|(provider_id, entry)| {
                        entry
                            .models
                            .first()
                            .map(|model| (provider_id.clone(), model.id.clone()))
                    });
                let preselected = preselected.as_ref().map(|(p, m)| (p.as_str(), m.as_str()));
                self.mount_onboarding_wizard(
                    cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID,
                    preselected,
                    if preselected.is_some() {
                        Some("Choose the model Cockpit should use by default.".to_string())
                    } else {
                        Some("No model catalog is available. Enter the exact model ID and context settings manually.".to_string())
                    },
                );
            }
            OnboardingStage::Agent => {
                self.mount_onboarding_wizard(
                    cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID,
                    None,
                    Some(
                        "Install an agent and confirm its model, tools, trust, and sidecar."
                            .to_string(),
                    ),
                );
            }
            OnboardingStage::Lifetime => {
                self.mount_onboarding_wizard(
                    cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
                    None,
                    Some("Choose what happens when the last Cockpit window closes.".to_string()),
                );
            }
            OnboardingStage::Complete => {}
        }
    }

    fn mount_onboarding_wizard(
        &mut self,
        wizard_id: &str,
        preselected_model: Option<(&str, &str)>,
        status: Option<String>,
    ) {
        match crate::tui::settings::Dialog::onboarding_wizard_engine(
            wizard_id,
            preselected_model,
            status,
        ) {
            Ok(dialog) => {
                self.dialog = dialog;
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_engine(match wizard_id {
                        cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID => {
                            crate::tui::onboarding::EngineStage::Profile
                        }
                        cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID => {
                            crate::tui::onboarding::EngineStage::Agent
                        }
                        cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID => {
                            crate::tui::onboarding::EngineStage::Lifetime
                        }
                        _ => crate::tui::onboarding::EngineStage::Model,
                    });
                }
            }
            Err(error) => {
                // Fail visibly: the stage has no native screen, so surface
                // the construction failure and drop the engine.
                self.dialog = crate::tui::settings::Dialog::None;
                self.show_toast(error, super::ToastKind::Error);
            }
        }
    }

    fn start_onboarding_ready_construction_retry(&mut self) {
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.ready_retry"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.ready_retry"),
            ),
            async move {
                retry_onboarding_ready_construction_snapshot(&lifecycle)
                    .await
                    .map(crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap)
            },
        );
    }

    fn request_onboarding_transition(
        &mut self,
        transition: cockpit_proto::OnboardingTransitionKind,
        settlement: Option<cockpit_proto::OnboardingStageSettlement>,
    ) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        // Latch the in-flight transition on the shell so a duplicate stage
        // completion cannot request a second advance before the
        // authoritative revision lands.
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.latch_transition(snapshot.revision, transition);
        }
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.transition"),
            // A superseding user intent owns the slot: Replace aborts the
            // in-flight transition RPC before the new one starts, so a
            // Back chosen while an Advance is in flight is never silently
            // dropped by dedupe. The daemon's revision CAS is the final
            // arbiter; losers reconcile through the error-path refresh.
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("onboarding.transition"),
            ),
            async move {
                let client = crate::tui::settings::settings_daemon_client(&lifecycle)
                    .await
                    .map_err(|error| error.to_string())?;
                let request = cockpit_proto::ApplyOnboardingTransition {
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    client_operation_id: uuid::Uuid::new_v4().to_string(),
                    transition,
                    settlement,
                };
                match client
                    .request(cockpit_proto::Request::ApplyOnboardingTransition(request))
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Ok(cockpit_proto::Response::OnboardingTransition(result)) => Ok(
                        crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap(Some(
                            result.snapshot,
                        )),
                    ),
                    Ok(other) => Err(format!("unexpected onboarding response: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
    }

    /// Map a shell intent onto its daemon operation. The shell never writes
    /// config, credential, or onboarding state itself.
    pub(super) fn apply_onboarding_shell_action(
        &mut self,
        action: Option<crate::tui::onboarding::OnboardingShellAction>,
    ) {
        use crate::tui::onboarding::OnboardingShellAction;
        match action {
            None => {}
            Some(OnboardingShellAction::Transition(kind, settlement)) => {
                // A duplicate of the already in-flight intent is dropped:
                // repeated completions (poller + user key) must not abort
                // and resend the same RPC. A *different* kind supersedes
                // the slot — `request_onboarding_transition` replaces the
                // in-flight action.
                let already_in_flight = self
                    .onboarding_shell
                    .as_ref()
                    .is_some_and(|shell| shell.pending_transition_kind() == Some(kind));
                if already_in_flight {
                    return;
                }
                self.request_onboarding_transition(kind, settlement);
            }
            Some(OnboardingShellAction::SecureIntent(submission)) => {
                self.apply_onboarding_secure_intent(submission);
            }
            Some(OnboardingShellAction::SelectTemplate(template)) => {
                // Mount the provider engine seeded with the canonical
                // template chosen from the searchable catalog.
                self.dialog = crate::tui::settings::Dialog::onboarding_provider_engine(
                    &self.launch.cwd,
                    None,
                );
                self.dialog.seed_provider_template(template);
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_engine(crate::tui::onboarding::EngineStage::Provider);
                }
            }
            Some(OnboardingShellAction::ReturnToCompletion) => {
                // Shell-local: leave the completion screen's "add another
                // provider" detour. The detour engine's in-flight provider
                // authority work (if any) is not discardable — the escape
                // menu offering this choice is suppressed while any is
                // pending.
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.return_to_completion();
                }
                self.dialog = crate::tui::settings::Dialog::None;
            }
            Some(OnboardingShellAction::Close) => {
                // Cancel/exit preserves committed daemon progress and drops
                // only the local engine state; a later reopen resumes from
                // the authoritative snapshot. The dismissal fence keeps
                // late authority results (an in-flight transition, a
                // concurrent client's broadcast) from reopening the shell;
                // only explicit re-entry clears it.
                self.onboarding_dismissed = true;
                self.onboarding_shell = None;
                self.dialog = crate::tui::settings::Dialog::None;
            }
        }
    }

    fn apply_onboarding_secure_intent(
        &mut self,
        submission: crate::tui::onboarding::SecureStoreSubmission,
    ) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let request = cockpit_proto::ApplyOnboardingSecureIntent {
            run_id: snapshot.run_id,
            attempt_id: snapshot.attempt_id,
            expected_revision: snapshot.revision,
            client_operation_id: uuid::Uuid::new_v4().to_string(),
            placement: submission.placement,
            passphrase: submission.passphrase,
        };
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.secure_intent"),
            // A later explicit placement choice owns the slot: Replace
            // aborts an in-flight secure intent the same way transitions
            // are superseded. The daemon's revision CAS plus the one-shot
            // receipt keep a loser inert.
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("onboarding.secure_intent"),
            ),
            async move {
                onboarding_snapshot_after_secure_intent(&lifecycle, request)
                    .await
                    .map(crate::tui::async_action::AsyncActionPayload::OnboardingBootstrap)
            },
        );
    }

    /// Service the full-screen onboarding shell each wake: reconcile the
    /// provider-engine pairing, advance stages whose engine settled,
    /// commit the terminal transition once the lifetime stage settles, and
    /// end the completion detour when its provider finishes. Key-driven
    /// intents are applied inline in `handle_onboarding_shell_key`; this
    /// poll covers completions that the engine reaches asynchronously.
    pub(super) fn service_onboarding_shell(&mut self) -> bool {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            return false;
        };
        let Some(shell) = self.onboarding_shell.as_mut() else {
            return false;
        };
        // The provider engine can leave its Add page from pointer input and
        // its own async completions, not only keys; reconcile here so every
        // path shares one abandon detector.
        shell.reconcile_provider_engine(&self.dialog);
        if shell.transition_pending() {
            return false;
        }
        match shell.stage() {
            cockpit_proto::OnboardingStage::Complete => {
                // The completion screen's "add another provider" detour:
                // the added provider settles through the ordinary provider
                // mutation authority; once its engine reaches its done page
                // the detour ends and the stored summary is presented again.
                if shell.completion_detour_active()
                    && shell.screen_is_engine(crate::tui::onboarding::EngineStage::Provider)
                    && self.dialog.take_completed_provider_id().is_some()
                {
                    shell.return_to_completion();
                    self.dialog = crate::tui::settings::Dialog::None;
                    return true;
                }
                false
            }
            cockpit_proto::OnboardingStage::Welcome
            | cockpit_proto::OnboardingStage::SecureStore => false,
            cockpit_proto::OnboardingStage::Profile => {
                if !shell.screen_is_engine(crate::tui::onboarding::EngineStage::Profile)
                    || !self.dialog.setup_wizard_is_complete(
                        cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
                    )
                {
                    return false;
                }
                self.refresh_bootstrap_config_snapshot();
                self.request_onboarding_transition(
                    cockpit_proto::OnboardingTransitionKind::Advance,
                    None,
                );
                true
            }
            cockpit_proto::OnboardingStage::Provider => {
                if !shell.screen_is_engine(crate::tui::onboarding::EngineStage::Provider) {
                    return false;
                }
                let settlement = self.dialog.onboarding_provider_settlement(
                    snapshot.run_id,
                    snapshot.attempt_id,
                    snapshot.revision,
                );
                let Some(settlement) = settlement else {
                    return false;
                };
                self.refresh_bootstrap_config_snapshot();
                self.request_onboarding_transition(
                    cockpit_proto::OnboardingTransitionKind::Advance,
                    Some(settlement),
                );
                true
            }
            cockpit_proto::OnboardingStage::Model => {
                if !shell.screen_is_engine(crate::tui::onboarding::EngineStage::Model)
                    || !self
                        .dialog
                        .setup_wizard_is_complete(cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID)
                {
                    return false;
                }
                self.refresh_bootstrap_config_snapshot();
                let config_generation = self.config_snapshot.providers.resolution_generation;
                let settlement = self.dialog.onboarding_wizard_settlement(
                    cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID,
                    config_generation,
                    snapshot.run_id,
                    snapshot.attempt_id,
                    snapshot.revision,
                );
                if settlement.is_none() {
                    return false;
                }
                self.request_onboarding_transition(
                    cockpit_proto::OnboardingTransitionKind::Advance,
                    settlement,
                );
                true
            }
            cockpit_proto::OnboardingStage::Agent => {
                if !shell.screen_is_engine(crate::tui::onboarding::EngineStage::Agent)
                    || !self
                        .dialog
                        .setup_wizard_is_complete(cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID)
                {
                    return false;
                }
                self.refresh_bootstrap_config_snapshot();
                let config_generation = self.config_snapshot.providers.resolution_generation;
                let settlement = self.dialog.onboarding_wizard_settlement(
                    cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID,
                    config_generation,
                    snapshot.run_id,
                    snapshot.attempt_id,
                    snapshot.revision,
                );
                if settlement.is_none() {
                    return false;
                }
                self.request_onboarding_transition(
                    cockpit_proto::OnboardingTransitionKind::Advance,
                    settlement,
                );
                true
            }
            cockpit_proto::OnboardingStage::Lifetime => {
                if shell.screen_is_complete() {
                    return false;
                }
                if !shell.screen_is_engine(crate::tui::onboarding::EngineStage::Lifetime)
                    || !self.dialog.setup_wizard_is_complete(
                        cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
                    )
                {
                    return false;
                }
                self.refresh_bootstrap_config_snapshot();
                let configured_model = self.config_snapshot.providers.active_model.clone();
                let summary = self.onboarding_completion_summary();
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.note_completion_summary(summary);
                }
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
                // Commit the terminal transition now that the lifetime
                // stage settled: completion becomes an authoritative stage.
                // The completion screen is presented from the stored
                // summary when the resulting snapshot lands.
                self.request_onboarding_transition(
                    cockpit_proto::OnboardingTransitionKind::Complete,
                    None,
                );
                true
            }
        }
    }

    /// Route a key through the full-screen onboarding shell. Returns
    /// `false` (consume): while onboarding, no other surface sees keys.
    pub(super) fn handle_onboarding_shell_key(&mut self, key: crossterm::event::KeyEvent) -> bool {
        self.dialog.bind_lifecycle(self.lifecycle.clone());
        let action = match self.onboarding_shell.as_mut() {
            Some(shell) => shell.handle_key(key, &mut self.dialog),
            None => None,
        };
        // The engine may have queued OAuth or effect requests with the key.
        self.drain_oauth_actions();
        self.apply_onboarding_shell_action(action);
        false
    }

    fn onboarding_completion_summary(&self) -> String {
        let configured_model = &self.config_snapshot.providers.active_model;
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
        let sandbox = self
            .host_capabilities
            .feature("sandbox.host")
            .map(|row| format!("Sandbox: {:?} ({})", row.state, row.reason))
            .unwrap_or_else(|| "Sandbox: capability check pending".to_string());
        let missing_dependencies = self
            .host_capabilities
            .dependencies
            .iter()
            .filter(|row| {
                !matches!(
                    row.state,
                    cockpit_proto::CatalogDependencyState::Available
                        | cockpit_proto::CatalogDependencyState::NotApplicable
                )
            })
            .map(|row| row.id.as_str())
            .collect::<Vec<_>>();
        let dependencies = if missing_dependencies.is_empty() {
            "Dependencies: ready".to_string()
        } else {
            format!(
                "Dependencies needing attention: {}",
                missing_dependencies.join(", ")
            )
        };
        let platform_warning = onboarding_platform_warning();
        format!(
            "{summary} {sandbox}. {dependencies}.{platform_warning} Add another provider any time with /provider add. Suggested first prompt: ‘Help me understand this codebase.’"
        )
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

        // First paint has already occurred before this entry point. Acquire
        // the lifecycle-selected owner now and ask its global authority for
        // the resumable checkpoint; this never pre-promotes an ephemeral owner.
        self.start_onboarding_bootstrap_fetch();

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
            .or_else(|| self.update_disabled_notice_text().map(str::to_string))
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

#[cfg(windows)]
fn onboarding_platform_warning() -> &'static str {
    " Windows: bash will run unsandboxed; bubblewrap is unavailable."
}

#[cfg(not(windows))]
fn onboarding_platform_warning() -> &'static str {
    ""
}
