use super::*;

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "current_thread")]
    async fn coverage_postpaint_integration_uses_existing_upstream_firstpaint_seam() {
        let namespace = tempfile::tempdir().expect("isolated startup trace root");
        let workspace = namespace.path().join("workspace");
        let runtime = namespace.path().join("runtime");
        std::fs::create_dir_all(&workspace).expect("workspace fixture");
        std::fs::create_dir_all(&runtime).expect("runtime fixture");
        let trace = crate::tui::app::startup_first_paint_tests::run_startup_trace_case(
            &workspace, &runtime, false, true,
        )
        .await;

        let mut cursor = 0usize;
        for event in [
            "first-paint",
            "coverage-phase-start",
            "coverage-phase-complete",
            "daemon-ready",
            "first-model-request",
        ] {
            let relative = trace[cursor..]
                .find(event)
                .unwrap_or_else(|| panic!("missing `{event}` in startup trace: {trace}"));
            cursor += relative + event.len();
        }
        assert!(trace.contains("scope_class=\"daemon_global\""));
        assert!(trace.contains("correlation=\"opaque-test-correlation\""));
        for forbidden in ["candidate", "matcher", "fingerprint", "source_inventory"] {
            assert!(!trace.contains(forbidden), "trace exposed {forbidden}");
        }
    }
}

fn onboarding_ready_construction_retry_required(error: &cockpit_proto::ErrorPayload) -> bool {
    error.code == cockpit_proto::ErrorCode::Internal
        && error.message.contains("retry ready construction")
}

/// Resolve the daemon endpoint for an onboarding authority operation. The
/// startup machine's resolved lifecycle endpoint is used when present;
/// otherwise the app's lifecycle client resolves it — the same funnel the
/// settings surfaces use. An onboarding request is never silently dropped
/// because the startup machine has not pinned its selection yet.
async fn onboarding_authority_endpoint(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
) -> Result<cockpit_client::ClientEndpoint, String> {
    match selected_endpoint {
        Some(endpoint) => Ok(endpoint.clone()),
        None => lifecycle
            .resolve_default()
            .await
            .map(|resolved| resolved.endpoint)
            .map_err(|error| error.to_string()),
    }
}

async fn retry_onboarding_ready_construction_snapshot(
    lifecycle: &cockpit_client::LifecycleClient,
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
) -> Result<Option<cockpit_proto::OnboardingBootstrapSnapshot>, String> {
    let endpoint = onboarding_authority_endpoint(lifecycle, selected_endpoint).await?;
    let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
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
    selected_endpoint: Option<&cockpit_client::ClientEndpoint>,
    request: cockpit_proto::ApplyOnboardingSecureIntent,
) -> Result<
    (
        Option<cockpit_proto::OnboardingBootstrapSnapshot>,
        Option<cockpit_proto::OnboardingTransitionReceipt>,
    ),
    String,
> {
    let endpoint = onboarding_authority_endpoint(lifecycle, selected_endpoint).await?;
    let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
        .await
        .map_err(|error| error.to_string())?;
    let receipt_query = cockpit_proto::OnboardingReceiptQuery {
        run_id: request.run_id,
        attempt_id: request.attempt_id,
        client_operation_id: request.client_operation_id.clone(),
    };
    match client
        .apply_onboarding_secure_intent(&endpoint, request)
        .await
        .map_err(|error| error.to_string())?
    {
        Ok(result) => Ok((Some(result.snapshot), Some(result.receipt))),
        Err(error) if onboarding_ready_construction_retry_required(&error) => {
            let snapshot =
                retry_onboarding_ready_construction_snapshot(lifecycle, selected_endpoint).await?;
            let receipt = match client
                .request(cockpit_proto::Request::GetOnboardingTransitionReceipt(
                    receipt_query,
                ))
                .await
                .map_err(|error| error.to_string())?
            {
                Ok(cockpit_proto::Response::OnboardingTransitionReceipt(Some(receipt))) => receipt,
                Ok(cockpit_proto::Response::OnboardingTransitionReceipt(None)) => {
                    return Err("secure onboarding receipt is unavailable".to_string());
                }
                Ok(other) => {
                    return Err(format!("unexpected onboarding receipt response: {other:?}"));
                }
                Err(error) => return Err(error.to_string()),
            };
            Ok((snapshot, Some(receipt)))
        }
        Err(error) => Err(error.to_string()),
    }
}

impl App {
    pub(super) fn mark_startup_trace_milestone(&mut self, event: &'static str) -> bool {
        self.startup_background.trace_milestones.insert(event)
    }

    pub(super) fn start_startup_lifecycle_resolution(&mut self) {
        let generation = self.startup_background.generation;
        let lifecycle = self.lifecycle.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Internal("startup.lifecycle"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.lifecycle"),
            ),
            async move {
                let result = lifecycle.resolve_default().await.map(Into::into);
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupLifecycleResolved {
                        generation,
                        result,
                    },
                )
            },
        );
    }

    pub fn configure_onboarding_launch(&mut self, skip: bool, force: bool) {
        self.configure_onboarding_launch_with_setup_wizard(skip, force, None, None);
    }

    pub fn configure_onboarding_launch_with_setup_wizard(
        &mut self,
        skip: bool,
        force: bool,
        setup_wizard: Option<String>,
        provider_add_template: Option<String>,
    ) {
        self.onboarding_skip = skip;
        self.onboarding_force = force;
        self.pending_setup_wizard = setup_wizard;
        self.pending_provider_add_template = provider_add_template;
        if skip {
            self.onboarding_snapshot = None;
            self.onboarding_shell = None;
            self.dialog = crate::tui::settings::Dialog::None;
        }
    }

    /// After a committed authored-agent apply, the daemon publishes sidecar
    /// config and bumps the inventory generation. Keep the held snapshot in
    /// sync so onboarding settlement fences match the authority.
    pub(super) fn sync_config_generation_after_authored_agent_apply(&mut self, generation: u64) {
        self.config_snapshot.generation = self.config_snapshot.generation.max(generation);
        self.config_snapshot
            .providers
            .set_resolution_generation(self.config_snapshot.generation);
    }

    fn onboarding_agent_operation_id_for_attempt(attempt_id: uuid::Uuid) -> String {
        format!("onboarding-agent-{attempt_id}")
    }

    fn require_onboarding_snapshot_for_named_route(&mut self, wizard_id: &str) -> bool {
        if self.onboarding_snapshot.is_some() {
            return true;
        }
        self.pending_setup_wizard = Some(wizard_id.to_string());
        self.start_onboarding_bootstrap_fetch();
        false
    }

    fn snapshot_matches_named_wizard_stage(
        wizard_id: &str,
        stage: cockpit_proto::OnboardingStage,
    ) -> bool {
        if cockpit_core::wizard::named_setup_wizard_allows_complete_stage(wizard_id)
            && stage == cockpit_proto::OnboardingStage::Complete
        {
            return true;
        }
        cockpit_core::wizard::named_setup_wizard_authoritative_stage(wizard_id)
            .map(|required| stage == required)
            .unwrap_or(false)
    }

    fn focus_named_setup_wizard(&mut self, wizard_id: &str) -> bool {
        let snapshot = self
            .onboarding_snapshot
            .clone()
            .expect("named setup wizard routes require an authoritative onboarding snapshot");
        if !Self::snapshot_matches_named_wizard_stage(wizard_id, snapshot.stage) {
            if snapshot.stage == cockpit_proto::OnboardingStage::Complete {
                self.push_plain(format!(
                    "`{wizard_id}` requires an active onboarding run at its authoritative stage."
                ));
                return false;
            }
            self.reopen_onboarding_shell(&snapshot);
            return false;
        }
        true
    }

    fn maybe_open_pending_setup_wizard(&mut self) {
        if !self.startup_background.workspace_ready {
            return;
        }
        if let Some(wizard) = self.pending_setup_wizard.take() {
            let template = self.pending_provider_add_template.take();
            self.open_onboarding_setup(Some(&wizard));
            if wizard == cockpit_core::wizard::PROVIDER_WIZARD_ID {
                self.maybe_seed_pending_provider_template(template);
            }
        }
    }

    fn maybe_seed_pending_provider_template(&mut self, template: Option<String>) {
        let Some(template_id) = template else {
            return;
        };
        let template = cockpit_core::providers::template_by_id(&template_id).or_else(|| {
            self.push_plain(format!(
                "Unknown provider template `{template_id}`; pick one from the catalog."
            ));
            None
        });
        if template.is_none() {
            return;
        }
        let template = template.unwrap();
        if !self.dialog.is_provider_add() {
            self.dialog =
                crate::tui::settings::Dialog::onboarding_provider_engine(&self.launch.cwd, None);
            if let Some(shell) = self.onboarding_shell.as_mut() {
                shell.present_engine(crate::tui::onboarding::EngineStage::Provider);
            }
        }
        self.dialog.seed_provider_template(template);
    }

    /// Route `/setup` and equivalent interactive onboarding entrypoints through
    /// the full-screen shell instead of the legacy settings-modal wizards.
    pub(super) fn open_onboarding_setup(&mut self, wizard_id: Option<&str>) {
        if self.onboarding_skip {
            self.push_plain("Onboarding is skipped for this launch (`--skip-setup`).");
            return;
        }
        self.onboarding_dismissed = false;
        self.onboarding_force = wizard_id.is_none();
        match wizard_id {
            None => {
                if self.onboarding_shell.is_none() {
                    if let Some(snapshot) = self.onboarding_snapshot.clone() {
                        self.reopen_onboarding_shell(&snapshot);
                    } else {
                        self.start_onboarding_bootstrap_fetch();
                    }
                }
            }
            Some(cockpit_core::wizard::PROVIDER_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::PROVIDER_WIZARD_ID,
                ) {
                    return;
                }
                if self.onboarding_snapshot.as_ref().is_some_and(|snapshot| {
                    snapshot.stage == cockpit_proto::OnboardingStage::Complete
                }) {
                    let snapshot = self.onboarding_snapshot.clone().expect(
                        "named provider route requires an authoritative onboarding snapshot",
                    );
                    if self.onboarding_shell.is_none() {
                        self.onboarding_shell =
                            Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                                &snapshot,
                                crate::tui::onboarding::reduced_motion_enabled(),
                            )));
                        if let Some(shell) = self.onboarding_shell.as_mut() {
                            shell.present_completion("Cockpit is ready.".to_string());
                            shell.begin_completion_provider_detour(None);
                        }
                    } else if let Some(shell) = self.onboarding_shell.as_mut() {
                        shell.begin_completion_provider_detour(None);
                    }
                } else {
                    let snapshot = self.onboarding_snapshot.clone().expect(
                        "named provider route requires an authoritative onboarding snapshot",
                    );
                    self.reopen_onboarding_shell(&snapshot);
                }
            }
            Some(cockpit_core::wizard::SECURITY_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::SECURITY_WIZARD_ID,
                ) {
                    return;
                }
                if !self.focus_named_setup_wizard(cockpit_core::wizard::SECURITY_WIZARD_ID) {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::SECURITY_WIZARD_ID,
                    None,
                );
            }
            Some(cockpit_core::wizard::MODEL_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::MODEL_WIZARD_ID,
                ) {
                    return;
                }
                if !self.focus_named_setup_wizard(cockpit_core::wizard::MODEL_WIZARD_ID) {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::MODEL_WIZARD_ID,
                    None,
                );
            }
            Some(cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID,
                ) {
                    return;
                }
                if !self.focus_named_setup_wizard(cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID)
                {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID,
                    None,
                );
            }
            Some(cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
                ) {
                    return;
                }
                if !self
                    .focus_named_setup_wizard(cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID)
                {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID,
                    None,
                );
            }
            Some(cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
                ) {
                    return;
                }
                if !self
                    .focus_named_setup_wizard(cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID)
                {
                    return;
                }
                self.mount_named_setup_wizard_in_onboarding_shell(
                    cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID,
                    None,
                );
            }
            Some(cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID) => {
                if !self.require_onboarding_snapshot_for_named_route(
                    cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID,
                ) {
                    return;
                }
                if !self.focus_named_setup_wizard(cockpit_core::wizard::ONBOARDING_AGENT_WIZARD_ID)
                {
                    return;
                }
                self.mount_onboarding_agent_authoring();
            }
            Some(other) => {
                self.push_plain(format!(
                    "Unknown setup wizard `{other}`; run `/setup` to list named wizards."
                ));
            }
        }
    }

    fn mount_named_setup_wizard_in_onboarding_shell(
        &mut self,
        wizard_id: &str,
        preselected_model: Option<(&str, &str)>,
    ) {
        let snapshot = self
            .onboarding_snapshot
            .clone()
            .expect("named setup wizard routes require an authoritative onboarding snapshot");
        if self.onboarding_shell.is_none() {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                &snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
        }
        match Dialog::onboarding_wizard_engine(wizard_id, preselected_model, None) {
            Ok(dialog) => {
                self.dialog = dialog;
                if let Some(shell) = self.onboarding_shell.as_mut() {
                    shell.present_engine(match wizard_id {
                        cockpit_core::wizard::SECURITY_WIZARD_ID
                        | cockpit_core::wizard::ONBOARDING_PROFILE_WIZARD_ID => {
                            crate::tui::onboarding::EngineStage::Profile
                        }
                        cockpit_core::wizard::MODEL_WIZARD_ID
                        | cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID => {
                            crate::tui::onboarding::EngineStage::Model
                        }
                        cockpit_core::wizard::ONBOARDING_LIFETIME_WIZARD_ID => {
                            crate::tui::onboarding::EngineStage::Lifetime
                        }
                        _ => crate::tui::onboarding::EngineStage::Model,
                    });
                }
            }
            Err(error) => self.show_toast(error, super::ToastKind::Error),
        }
    }

    pub(super) fn start_onboarding_bootstrap_fetch(&mut self) {
        let generation = self.startup_background.generation;
        let force = self.onboarding_force;
        let skip = self.onboarding_skip;
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.bootstrap"),
            ),
            async move {
                let bootstrap_request_id = request_id.clone();
                let endpoint =
                    match onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref())
                        .await
                    {
                        Ok(endpoint) => endpoint,
                        Err(error) => {
                            return Ok(
                                crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                                    generation,
                                    error,
                                },
                            );
                        }
                    };
                let client = match cockpit_client::DaemonClient::connect_endpoint(&endpoint).await {
                    Ok(client) => client,
                    Err(error) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: error.to_string(),
                        });
                    }
                };
                let current = match client
                    .request(cockpit_proto::Request::GetOnboardingBootstrapSnapshot)
                    .await
                {
                    Ok(Ok(cockpit_proto::Response::OnboardingBootstrapSnapshot(snapshot))) => snapshot,
                    Ok(Ok(other)) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: format!("unexpected onboarding response: {other:?}"),
                        });
                    }
                    Ok(Err(error)) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: error.to_string(),
                        });
                    }
                    Err(error) => {
                        return Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                            generation,
                            error: error.to_string(),
                        });
                    }
                };
                if current.as_ref().is_some_and(|snapshot| {
                    snapshot.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
                }) {
                    return match retry_onboarding_ready_construction_snapshot(
                        &lifecycle,
                        selected_endpoint.as_ref(),
                    )
                    .await
                    {
                        Ok(snapshot) => Ok(
                            crate::tui::async_action::AsyncActionPayload::StartupOnboardingBootstrap {
                                generation,
                                request_id,
                                receipt: None,
                                snapshot,
                            },
                        ),
                        Err(error) => Ok(
                            crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                                generation,
                                error,
                            },
                        ),
                    };
                }
                if current.as_ref().is_some_and(|snapshot| {
                    !force && snapshot.stage == cockpit_proto::OnboardingStage::Complete
                }) || skip
                {
                    return Ok(
                        crate::tui::async_action::AsyncActionPayload::StartupOnboardingBootstrap {
                            generation,
                            request_id,
                            receipt: None,
                            snapshot: current,
                        },
                    );
                }
                let request = cockpit_proto::BeginOrReopenOnboarding {
                    expected_revision: current.as_ref().map(|snapshot| snapshot.revision),
                    client_operation_id: bootstrap_request_id,
                    reentry: force || current.is_some(),
                };
                match client.request(cockpit_proto::Request::BeginOrReopenOnboarding(request)).await {
                    Ok(Ok(cockpit_proto::Response::OnboardingTransition(result))) => Ok(
                            crate::tui::async_action::AsyncActionPayload::StartupOnboardingBootstrap {
                                generation,
                                request_id,
                                receipt: Some(result.receipt),
                                snapshot: Some(result.snapshot),
                        },
                    ),
                    Ok(Ok(other)) => Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                        generation,
                        error: format!("unexpected onboarding response: {other:?}"),
                    }),
                    Ok(Err(error)) => Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                        generation,
                        error: error.to_string(),
                    }),
                    Err(error) => Ok(crate::tui::async_action::AsyncActionPayload::StartupOnboardingFailed {
                        generation,
                        error: error.to_string(),
                    }),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    pub(super) fn apply_onboarding_bootstrap_snapshot(
        &mut self,
        snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
    ) {
        // A bootstrap projection is global authority only, so it is recorded
        // and presented immediately: the ordered onboarding screens
        // (Welcome/Profile/SecureStore) deliberately run while the daemon is
        // still locked and no vault exists, before any workspace trust has
        // been decided. The workspace ride-along below still resolves the
        // project root and its daemon-owned trust decision — the
        // session-attach reducer and every project-touching path stay fenced
        // behind `workspace_ready` until that lands, so an eager attach can
        // never read a project config under the safe shell's `.` placeholder.
        if !self.startup_background.workspace_ready {
            self.start_workspace_resolution(snapshot.clone());
        }
        if let Some(incoming) = snapshot.as_ref()
            && let Some(recorded) = self.onboarding_snapshot.as_ref()
            && incoming.run_id == recorded.run_id
            && incoming.attempt_id == recorded.attempt_id
            && incoming.revision < recorded.revision
        {
            // The workspace ride-along carries the projection the first
            // fetch observed; by the time it lands, transitions may have
            // advanced the same run past it. Authority application is
            // monotonic: a same-run stale projection never regresses the
            // recorded one.
            return;
        }
        if snapshot.as_ref().is_some_and(|current| {
            current.bootstrap_state == cockpit_proto::OnboardingBootstrapState::Failed
        }) {
            self.onboarding_snapshot = snapshot;
            self.start_onboarding_ready_construction_retry();
            return;
        }
        if let (Some(incoming), Some(recorded)) =
            (snapshot.as_ref(), self.onboarding_snapshot.as_ref())
            && incoming.attempt_id != recorded.attempt_id
        {
            self.onboarding_agent_operation_id = None;
            self.pending_startup_agent_authoring_receipt = None;
        }
        self.onboarding_snapshot = snapshot;
        if let Some(snapshot) = self.onboarding_snapshot.clone() {
            self.sync_onboarding_shell(&snapshot);
        } else {
            self.onboarding_shell = None;
        }
        self.maybe_open_pending_setup_wizard();
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
            // another provider" is a local detour on top of that screen;
            // `note_authoritative_complete` treats detour occupancy like
            // dismissal occupancy and never unmounts it for an authority
            // refresh.
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
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.bootstrap_refresh"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.bootstrap_refresh"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
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
                    return retry_onboarding_ready_construction_snapshot(
                        &lifecycle,
                        selected_endpoint.as_ref(),
                    )
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
                self.dialog = crate::tui::settings::Dialog::None;
                self.mount_onboarding_agent_authoring();
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

    fn start_workspace_resolution(
        &mut self,
        snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
    ) {
        let generation = self.startup_background.generation;
        let requested_project = self.launch.cwd.clone();
        let endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let failure_snapshot = snapshot.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("startup.workspace"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.workspace"),
            ),
            async move {
                let result: Result<StartupWorkspaceCompletion, String> = async move {
                    let opened = if requested_project == std::path::Path::new(".") {
                        std::env::current_dir()
                            .map_err(|error| format!("resolving workspace: {error}"))?
                    } else {
                        requested_project
                    };
                    let root = cockpit_config::trust::resolve_trust_root(&opened)
                        .map_err(|error| format!("resolving workspace trust root: {error}"))?;
                    let project_root = root.root.to_string_lossy().into_owned();
                    let endpoint = endpoint
                        .ok_or_else(|| "selected startup daemon is unavailable".to_string())?;
                    let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                        .await
                        .map_err(|error| error.to_string())?;
                    let response = client
                        .request(cockpit_proto::Request::GetWorkspaceTrust { project_root })
                        .await
                        .map_err(|error| error.to_string())?;
                    let (mode, config_generation) = match response {
                        Ok(cockpit_proto::Response::WorkspaceTrust {
                            mode,
                            config_generation,
                        }) => (mode, config_generation),
                        Ok(other) => {
                            return Err(format!("unexpected workspace trust response: {other:?}"));
                        }
                        Err(error) => return Err(error.to_string()),
                    };
                    Ok(StartupWorkspaceCompletion {
                        generation,
                        opened,
                        root,
                        mode,
                        config_generation,
                        snapshot,
                    })
                }
                .await;
                Ok(match result {
                    Ok(completion) => {
                        crate::tui::async_action::AsyncActionPayload::StartupWorkspace(completion)
                    }
                    Err(error) => {
                        crate::tui::async_action::AsyncActionPayload::StartupWorkspaceFailed {
                            generation,
                            snapshot: failure_snapshot,
                            error,
                        }
                    }
                })
            },
        );
    }

    pub(super) fn apply_startup_workspace_completion(
        &mut self,
        completion: StartupWorkspaceCompletion,
    ) {
        if completion.generation != self.startup_background.generation || self.exit_requested {
            return;
        }
        self.startup_background.retry = None;
        let mode = match completion.mode {
            Some(cockpit_proto::WorkspaceTrustMode::Trust) => {
                cockpit_config::WorkspaceTrustMode::Trust
            }
            Some(cockpit_proto::WorkspaceTrustMode::IgnoreConfig) => {
                cockpit_config::WorkspaceTrustMode::IgnoreConfig
            }
            None => {
                // An unset daemon decision is not an accepted IgnoreConfig
                // choice. Install the restrictive runtime policy while the
                // modal is open, but do not expose config, onboarding, or a
                // session until the correlated SetWorkspaceTrust receipt.
                cockpit_config::trust::set_runtime_policy(
                    completion.root.clone(),
                    cockpit_config::WorkspaceTrustMode::IgnoreConfig,
                );
                self.launch.cwd = completion.opened;
                self.config_snapshot.generation = self
                    .config_snapshot
                    .generation
                    .max(completion.config_generation);
                self.config_snapshot
                    .providers
                    .set_resolution_generation(self.config_snapshot.generation);
                self.startup_pending_trust = Some(StartupPendingTrust {
                    generation: completion.generation,
                    snapshot: completion.snapshot,
                });
                self.dialog = crate::tui::settings::Dialog::open_workspace_trust(completion.root);
                return;
            }
            Some(cockpit_proto::WorkspaceTrustMode::Untrusted) => {
                if self.mark_startup_trace_milestone("trust-error") {
                    tracing::warn!(target: cockpit_core::startup::TARGET, event = "trust-error", "startup");
                }
                self.push_plain("workspace is untrusted and cannot be opened".to_string());
                self.exit_requested = true;
                return;
            }
        };
        cockpit_config::trust::set_runtime_policy(completion.root, mode);
        self.launch.cwd = completion.opened;
        self.config_snapshot.generation = self
            .config_snapshot
            .generation
            .max(completion.config_generation);
        self.config_snapshot
            .providers
            .set_resolution_generation(self.config_snapshot.generation);
        if self.startup_debug_last_message {
            cockpit_core::engine::model::enable_debug_last_message(
                self.launch.cwd.join(".lastmessage"),
            );
        }
        self.startup_background.workspace_ready = true;
        if self.mark_startup_trace_milestone("trust-ready") {
            tracing::info!(target: cockpit_core::startup::TARGET, event = "trust-ready", "startup");
        }
        self.apply_onboarding_bootstrap_snapshot(completion.snapshot);
        self.start_post_trust_cleanup();
    }

    pub(super) fn start_post_trust_cleanup(&mut self) {
        let exports_dir = self.launch.cwd.join(".cockpit").join("exports");
        self.schedule_startup_export_recovery(async move {
            crate::tui::app::export_actions::recover_deferred_export_cleanup(&exports_dir).await;
        });

        // These projections used to be queued with startup construction. They
        // are retained, but are intentionally downstream of the accepted
        // workspace trust fence because they inspect the opened project.
        crate::tui::async_action::spawn_blocking_action_task(cockpit_core::tokens::warm_cl100k);

        let cwd = self.launch.cwd.clone();
        let active_model = self.launch.active_model.clone();
        let endpoint = self.attached_daemon_endpoint();
        let providers = self.config_snapshot.providers.clone();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Internal("startup.guidance.estimate"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.guidance.estimate"),
            ),
            async move {
                let (provider, model) = match &active_model {
                    Some((provider, model)) => (Some(provider.clone()), Some(model.clone())),
                    None => (None, None),
                };
                let estimate = agent_runner::fetch_guidance_estimate_with_endpoint(
                    &cwd, providers, provider, model, endpoint,
                )
                .await;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupGuidanceEstimate {
                        cwd,
                        active_model,
                        estimate,
                    },
                )
            },
        );

        let dependency_cwd = self.launch.cwd.clone();
        let sandbox_enabled = !self.no_sandbox;
        self.async_actions.start_blocking(
            crate::tui::async_action::AsyncActionKind::Internal("startup.dependencies"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.dependencies"),
            ),
            move || {
                cockpit_core::diagnostics::dependency_projection_with_deadline_and_publish_for_run(
                    dependency_cwd,
                    std::time::Duration::from_secs(2),
                    sandbox_enabled,
                )
                .map(crate::tui::async_action::AsyncActionPayload::StartupDependencyProjection)
                .map_err(|error| error.to_string())
            },
        );

        let lifecycle = self.lifecycle.clone();
        let cwd = self.launch.cwd.clone();
        let repo_status = Arc::clone(&self.repo_status);
        let _git_refresh = super::spawn_git_refresh(cwd.clone(), lifecycle.clone(), repo_status);
        let worktree_root = Arc::clone(&self.worktree_root);
        let _worktree_resolve = super::spawn_worktree_root_resolve(cwd, lifecycle, worktree_root);

        #[cfg(feature = "remote")]
        self.start_startup_disclosures_fetch();
    }

    pub(super) fn schedule_startup_export_recovery<F>(&mut self, work: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let generation = self.startup_background.generation;
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Internal("startup.export_recovery"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.export_recovery"),
            ),
            async move {
                work.await;
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupExportRecovery {
                        generation,
                    },
                )
            },
        );
    }
}

#[derive(Debug)]
pub(crate) struct StartupWorkspaceCompletion {
    pub(crate) generation: u64,
    pub(crate) opened: std::path::PathBuf,
    pub(crate) root: cockpit_config::trust::TrustRoot,
    pub(crate) mode: Option<cockpit_proto::WorkspaceTrustMode>,
    pub(crate) config_generation: u64,
    pub(crate) snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
}

#[derive(Debug)]
pub(crate) struct StartupPendingTrust {
    pub(crate) generation: u64,
    pub(crate) snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
}

#[derive(Debug)]
pub(crate) struct StartupOnboardingCompletion {
    pub(crate) generation: u64,
    pub(crate) run_id: uuid::Uuid,
    pub(crate) attempt_id: uuid::Uuid,
    pub(crate) expected_revision: u64,
    pub(crate) request_id: String,
    pub(crate) receipt: Option<cockpit_proto::OnboardingTransitionReceipt>,
    pub(crate) snapshot: Option<cockpit_proto::OnboardingBootstrapSnapshot>,
}

impl App {
    fn start_onboarding_ready_construction_retry(&mut self) {
        let generation = self.startup_background.generation;
        let Some(current) = self.onboarding_snapshot.as_ref() else {
            return;
        };
        let (run_id, attempt_id, expected_revision) =
            (current.run_id, current.attempt_id, current.revision);
        let request_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.ready_retry"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("onboarding.ready_retry"),
            ),
            async move {
                retry_onboarding_ready_construction_snapshot(&lifecycle, selected_endpoint.as_ref())
                    .await
                    .map(|snapshot| {
                        crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                            StartupOnboardingCompletion {
                                generation,
                                run_id,
                                attempt_id,
                                expected_revision,
                                request_id,
                                receipt: None,
                                snapshot,
                            },
                        )
                    })
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
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
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = uuid::Uuid::new_v4().to_string();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        // Latch the in-flight transition on the shell so a duplicate stage
        // completion cannot request a second advance before the
        // authoritative revision lands. The latch belongs to the settled
        // stage, not to the transport: it is taken whenever the authority
        // checkpoint exists, and the action below resolves the daemon
        // through the pinned startup endpoint or the app's lifecycle funnel.
        if let Some(shell) = self.onboarding_shell.as_mut() {
            shell.latch_transition(snapshot.revision, transition);
        }
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
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
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error.to_string())?;
                let request = cockpit_proto::ApplyOnboardingTransition {
                    run_id: snapshot.run_id,
                    attempt_id: snapshot.attempt_id,
                    expected_revision: snapshot.revision,
                    client_operation_id: request_id.clone(),
                    transition,
                    settlement,
                };
                match client
                    .request(cockpit_proto::Request::ApplyOnboardingTransition(request))
                    .await
                    .map_err(|error| error.to_string())?
                {
                    Ok(cockpit_proto::Response::OnboardingTransition(result)) => Ok(
                        crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                            StartupOnboardingCompletion {
                                generation,
                                run_id,
                                attempt_id,
                                expected_revision,
                                request_id,
                                receipt: Some(result.receipt),
                                snapshot: Some(result.snapshot),
                            },
                        ),
                    ),
                    Ok(other) => Err(format!("unexpected onboarding response: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
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
            Some(OnboardingShellAction::AgentAuthoring(action)) => {
                self.dispatch_onboarding_agent_authoring(action);
            }
        }
    }

    fn mount_onboarding_agent_authoring(&mut self) {
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            return;
        };
        if self.onboarding_shell.is_none() {
            self.onboarding_shell = Some(Box::new(crate::tui::onboarding::OnboardingShell::new(
                &snapshot,
                crate::tui::onboarding::reduced_motion_enabled(),
            )));
        }
        let operation_id = self
            .onboarding_agent_operation_id
            .get_or_insert_with(|| {
                Self::onboarding_agent_operation_id_for_attempt(snapshot.attempt_id)
            })
            .clone();
        if self
            .onboarding_shell
            .as_ref()
            .is_some_and(|shell| shell.screen_is_agent_authoring())
        {
            return;
        }
        self.request_agent_authoring_receipt(operation_id.clone());
        self.request_agent_authoring_projection(operation_id);
    }

    fn request_agent_authoring_receipt(&mut self, client_operation_id: String) {
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("agent_authoring.receipt"),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("agent_authoring.receipt"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error.to_string())?;
                let response = client
                    .request(cockpit_proto::Request::GetAuthoredAgentPackageReceipt(
                        cockpit_proto::AuthoredAgentPackageReceiptQuery {
                            client_operation_id,
                        },
                    ))
                    .await
                    .map_err(|error| error.to_string())?;
                match response {
                    Ok(cockpit_proto::Response::AuthoredAgentPackageReceipt(Some(receipt))) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringReceipt {
                            request_id,
                            receipt,
                        })
                    }
                    Ok(cockpit_proto::Response::AuthoredAgentPackageReceipt(None)) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringReceiptMiss {
                            request_id,
                        })
                    }
                    Ok(other) => Err(format!("unexpected agent authoring receipt: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn request_agent_authoring_projection(&mut self, client_operation_id: String) {
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("agent_authoring.projection"),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("agent_authoring.projection"),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error.to_string())?;
                let response = client
                    .request(cockpit_proto::Request::GetAgentAuthoringProjection)
                    .await
                    .map_err(|error| error.to_string())?;
                match response {
                    Ok(cockpit_proto::Response::AgentAuthoringProjection(projection)) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringProjection {
                            client_operation_id,
                            request_id,
                            projection,
                        })
                    }
                    Ok(other) => Err(format!("unexpected agent authoring projection: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
    }

    fn dispatch_onboarding_agent_authoring(
        &mut self,
        action: crate::tui::onboarding::agent::AgentAuthoringShellAction,
    ) {
        use crate::tui::onboarding::agent::AgentAuthoringAction;
        let Some(snapshot) = self.onboarding_snapshot.clone() else {
            self.show_toast(
                "Onboarding checkpoint is unavailable",
                super::ToastKind::Error,
            );
            return;
        };
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let request_id = uuid::Uuid::new_v4().to_string();
        let pending_request_id = request_id.clone();
        let operation_id = self
            .onboarding_agent_operation_id
            .get_or_insert_with(|| {
                Self::onboarding_agent_operation_id_for_attempt(snapshot.attempt_id)
            })
            .clone();
        let (validate_only, package, replace_key, rpc_operation_id) = match action {
            AgentAuthoringAction::PreviewPackage(package) => (
                true,
                package,
                "agent_authoring.preview",
                format!("{operation_id}-preview"),
            ),
            AgentAuthoringAction::ApplyPackage {
                client_operation_id,
                package,
            } => (false, package, "agent_authoring.apply", client_operation_id),
            AgentAuthoringAction::RefreshProjection => {
                self.request_agent_authoring_projection(operation_id);
                return;
            }
        };
        let correlation = cockpit_proto::AuthoredAgentOnboardingCorrelation {
            run_id: snapshot.run_id,
            attempt_id: snapshot.attempt_id,
            stage_revision: snapshot.revision,
        };
        let request = cockpit_proto::ApplyAuthoredAgentPackageRequest {
            client_operation_id: rpc_operation_id,
            expected_policy_revision: package.policy_revision.clone(),
            package,
            onboarding: Some(correlation),
            validate_only,
        };
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(replace_key),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(replace_key),
            ),
            async move {
                let endpoint =
                    onboarding_authority_endpoint(&lifecycle, selected_endpoint.as_ref()).await?;
                let client = cockpit_client::DaemonClient::connect_endpoint(&endpoint)
                    .await
                    .map_err(|error| error.to_string())?;
                let response = client
                    .request(cockpit_proto::Request::ApplyAuthoredAgentPackage(request))
                    .await
                    .map_err(|error| error.to_string())?;
                match response {
                    Ok(cockpit_proto::Response::AuthoredAgentPackage(outcome)) => {
                        Ok(crate::tui::async_action::AsyncActionPayload::StartupAgentAuthoringOutcome {
                            request_id,
                            outcome: Ok(outcome),
                        })
                    }
                    Ok(other) => Err(format!("unexpected agent authoring response: {other:?}")),
                    Err(error) => Err(error.to_string()),
                }
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
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
        let generation = self.startup_background.generation;
        let run_id = snapshot.run_id;
        let attempt_id = snapshot.attempt_id;
        let expected_revision = snapshot.revision;
        let request_id = request.client_operation_id.clone();
        let lifecycle = self.lifecycle.clone();
        let selected_endpoint = self
            .startup_lifecycle
            .as_ref()
            .map(|selected| selected.endpoint.clone());
        let pending_request_id = request_id.clone();
        let started = self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("onboarding.secure_intent"),
            // A later explicit placement choice owns the slot: Replace
            // aborts an in-flight secure intent the same way transitions
            // are superseded. The daemon's revision CAS plus the one-shot
            // receipt keep a loser inert.
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("onboarding.secure_intent"),
            ),
            async move {
                onboarding_snapshot_after_secure_intent(
                    &lifecycle,
                    selected_endpoint.as_ref(),
                    request,
                )
                .await
                .map(|(snapshot, receipt)| {
                    crate::tui::async_action::AsyncActionPayload::StartupOnboardingTransition(
                        StartupOnboardingCompletion {
                            generation,
                            run_id,
                            attempt_id,
                            expected_revision,
                            request_id,
                            receipt,
                            snapshot,
                        },
                    )
                })
            },
        );
        if let crate::tui::async_action::AsyncActionStart::Started(id) = started {
            self.pending_startup_onboarding_operations
                .insert(id, pending_request_id);
        }
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
                let settlement = self.dialog.onboarding_wizard_settlement(
                    cockpit_core::wizard::ONBOARDING_MODEL_WIZARD_ID,
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
                let (agent_action, settlement) = {
                    let Some(shell) = self.onboarding_shell.as_mut() else {
                        return false;
                    };
                    let action = shell.take_agent_authoring_action();
                    let settlement = shell.agent_authoring_settlement(
                        snapshot.run_id,
                        snapshot.attempt_id,
                        snapshot.revision,
                        self.config_snapshot.generation,
                    );
                    (action, settlement)
                };
                if let Some(action) = agent_action {
                    self.dispatch_onboarding_agent_authoring(action);
                }
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
        self.start_startup_background_tasks_with_policy(async {
            cockpit_config::extended::load_global_daemon_lifetime_policy()
                .map_err(|error| error.to_string())
        });
    }

    pub(super) fn start_startup_background_tasks_with_policy<F>(&mut self, policy: F)
    where
        F: std::future::Future<Output = Result<bool, String>> + Send + 'static,
    {
        if !self.first_paint_completed {
            return;
        }
        if self.startup_background.started {
            return;
        }
        self.startup_background.started = true;
        let generation = self.startup_background.generation;
        // The first authority operation is isolated in the action runner so
        // an exit before the worker begins has no configuration I/O.  It
        // reads only `daemon.background_agents`; project configuration is not
        // available until the daemon has returned onboarding and trust.
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Blocking("startup.lifetime-policy"),
            crate::tui::async_action::AsyncActionPolicy::Dedupe(
                crate::tui::async_action::AsyncActionKey::new("startup.lifetime-policy"),
            ),
            async move {
                Ok(
                    crate::tui::async_action::AsyncActionPayload::StartupLifetimePolicy {
                        generation,
                        result: policy.await,
                    },
                )
            },
        );
    }

    /// True while the post-paint startup machine has not yet accepted a workspace.
    /// Composer input stays live, but runner/session effects and project I/O must
    /// remain blocked until this clears.
    pub(super) fn blocks_startup_workspace_effects(&self) -> bool {
        (self.first_paint_completed || self.startup_background.started)
            && !self.startup_background.workspace_ready
    }

    /// Gate runner attach, slash/`!` dispatch, scratchpad/notes RPC,
    /// `@`-autocomplete project walks, and other project-touching paths behind
    /// the accepted-workspace fence. Returns `false` when blocked.
    pub(super) fn guard_startup_workspace_effects(&mut self) -> bool {
        if !self.blocks_startup_workspace_effects() {
            return true;
        }
        self.show_toast(
            "Command unavailable until startup accepts the workspace",
            ToastKind::Info,
        );
        self.retry_startup_background();
        false
    }

    pub(super) fn retry_startup_background(&mut self) {
        let Some(retry) = self.startup_background.retry.take() else {
            return;
        };
        match retry {
            StartupRetry::LifetimePolicy => {
                self.startup_background.started = false;
                self.start_startup_background_tasks();
            }
            StartupRetry::Lifecycle => self.start_startup_lifecycle_resolution(),
            StartupRetry::Onboarding => self.start_onboarding_bootstrap_fetch(),
            StartupRetry::Workspace(snapshot) => self.start_workspace_resolution(snapshot),
            StartupRetry::NamedAssistant => {
                if let Some(name) = self.startup_assistant_name.clone() {
                    self.start_named_assistant_resolution(name);
                }
            }
        }
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
