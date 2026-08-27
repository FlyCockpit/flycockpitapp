//! App-side wiring for the session-setup overlay and inline panel: open,
//! fetch the daemon-owned snapshot, apply results, and dispatch mutations.

use super::*;

use crate::tui::session_setup::{SessionSetupOutcome, SessionSetupPane};

/// Async-action name for the session-setup snapshot fetch. `Replace` policy
/// keyed on this name coalesces bursts (e.g. repeated `AgentTreeChanged`
/// invalidations) into a single in-flight request.
const SESSION_SETUP_SNAPSHOT_ACTION: &str = "session_setup.snapshot";

impl App {
    /// Open the session-setup overlay and schedule its first snapshot fetch.
    /// The daemon owns the snapshot; before attach the pane shows a fixed
    /// unavailable message rather than any local guess.
    pub(super) fn open_session_setup(&mut self) {
        // Colour is supplementary here; render with styling and let the
        // terminal honour NO_COLOR. The plain projection is exercised by tests.
        self.overlay = Overlay::SessionSetup(SessionSetupPane::loading(true));
        self.request_session_setup_snapshot_refresh();
    }

    /// Dispatch a pane outcome. `as_overlay` keeps the overlay open on Stay.
    pub(super) fn apply_session_setup_outcome(
        &mut self,
        outcome: SessionSetupOutcome,
        mut pane: SessionSetupPane,
        as_overlay: bool,
    ) {
        match outcome {
            SessionSetupOutcome::Close => {
                if as_overlay {
                    // Overlay dismissed; inline panel (if still expanded) is unchanged.
                }
            }
            SessionSetupOutcome::Stay => {
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
            }
            SessionSetupOutcome::SelectAgent { name } => {
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
                self.swap_primary_agent(&name);
                self.request_session_setup_snapshot_refresh();
            }
            SessionSetupOutcome::SelectModel {
                slot_id,
                choice_id,
            } => {
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
                self.submit_session_setup_model_override(slot_id, choice_id);
            }
            SessionSetupOutcome::SetToolSurface { override_json } => {
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
                self.submit_session_setup_tool_surface(override_json);
            }
            SessionSetupOutcome::AddMcp {
                scope,
                name,
                transport,
                endpoint,
                command,
                auth,
            } => {
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
                self.submit_session_setup_add_mcp(
                    scope, name, transport, endpoint, command, auth,
                );
            }
            SessionSetupOutcome::Notice { message } => {
                pane.set_notice(message);
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
            }
        }
    }

    fn submit_session_setup_model_override(&mut self, _slot_id: String, _choice_id: String) {
        // Wired in the model-section stage; kept as a named seam so Enter on
        // a choice row is never a silent no-op at the outcome layer.
    }

    fn submit_session_setup_tool_surface(&mut self, _override_json: String) {
        // Wired in the tools-section stage.
    }

    fn submit_session_setup_add_mcp(
        &mut self,
        _scope: crate::tui::session_setup::SessionSetupMcpScope,
        _name: String,
        _transport: String,
        _endpoint: Option<String>,
        _command: Option<String>,
        _auth: String,
    ) {
        // Wired in the MCP-section stage.
    }

    /// Schedule an async `GetSessionSetupSnapshot` fetch for the attached
    /// session. A no-op (with a fixed error surfaced in the pane) when there is
    /// no attached runner, since the snapshot is daemon-owned.
    pub(super) fn request_session_setup_snapshot_refresh(&mut self) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            let message = "Session setup is only available once attached to a session.";
            if let Overlay::SessionSetup(pane) = &mut self.overlay {
                pane.set_error(message);
            }
            if let Some(pane) = self.session_setup_inline.as_mut() {
                pane.set_error(message);
            }
            return;
        };
        let attached = runner.attached_request_binding();
        let session_id = attached.session_id();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc(SESSION_SETUP_SNAPSHOT_ACTION),
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new(SESSION_SETUP_SNAPSHOT_ACTION),
            ),
            async move {
                let response = attached
                    .request(cockpit_proto::Request::GetSessionSetupSnapshot { session_id })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(crate::tui::async_action::AsyncActionPayload::SessionSetupSnapshot(response))
            },
        );
    }

    /// Apply a completed `GetSessionSetupSnapshot` response into the open
    /// overlay. Inert if the overlay was closed or already replaced.
    pub(super) fn apply_session_setup_snapshot_response(
        &mut self,
        response: cockpit_proto::Response,
    ) {
        let cockpit_proto::Response::SessionSetupSnapshot { snapshot } = response else {
            return;
        };
        self.prepared_slot_models.clear();
        self.prepared_slot_default = None;
        if snapshot.config_generation == self.config_snapshot.generation
            && let Some(selected) = snapshot.selected_installation_id.as_deref()
            && let Some(candidate) = snapshot
                .candidates
                .iter()
                .find(|candidate| candidate.installation.installation_id == selected)
            && let Some(primary) = candidate
                .slots
                .iter()
                .find(|slot| slot.slot_id == "primary")
        {
            self.prepared_slot_models = primary
                .choices
                .iter()
                .filter(|choice| primary.allowed_choice_ids.contains(&choice.choice_id))
                .filter_map(|choice| {
                    let route = primary
                        .choice_routes
                        .iter()
                        .find(|route| route.choice_id == choice.choice_id)?;
                    resolve_setup_config_model(&self.config_snapshot.providers, route, choice)
                })
                .collect();
            self.prepared_slot_default = primary.default_choice_id.as_ref().and_then(|choice_id| {
                primary
                    .choices
                    .iter()
                    .find(|choice| &choice.choice_id == choice_id)
                    .and_then(|choice| {
                        let route = primary
                            .choice_routes
                            .iter()
                            .find(|route| route.choice_id == choice.choice_id)?;
                        resolve_setup_config_model(&self.config_snapshot.providers, route, choice)
                    })
            });
        }
        if let Overlay::ModelPicker(picker) = &mut self.overlay {
            picker.set_active_slot_models(
                self.prepared_slot_models.clone(),
                self.prepared_slot_default.clone(),
                &self.usage_models,
            );
        }
        if let Overlay::SessionSetup(pane) = &mut self.overlay {
            pane.apply_snapshot(snapshot.clone());
        }
        if let Some(pane) = self.session_setup_inline.as_mut() {
            pane.apply_snapshot(snapshot);
        }
    }

    /// Surface a fixed error into the open session-setup overlay/inline panel.
    pub(super) fn apply_session_setup_snapshot_error(&mut self, error: String) {
        let message = format!("Session setup could not be loaded: {error}");
        if let Overlay::SessionSetup(pane) = &mut self.overlay {
            pane.set_error(message.clone());
        }
        if let Some(pane) = self.session_setup_inline.as_mut() {
            pane.set_error(message);
        }
    }
}

/// Join one daemon setup choice to the exact provider entry in the same held
/// config generation. The ordered index is nonsecret and avoids reversing a
/// display template/model pair, which is ambiguous when multiple credential
/// profiles share the same provider template.
fn resolve_setup_config_model(
    providers: &cockpit_config::providers::ProvidersConfig,
    route: &cockpit_proto::SessionSetupModelChoiceRouteV1,
    choice: &cockpit_proto::AgentInstallationChoiceV1,
) -> Option<(String, String)> {
    let index = usize::try_from(route.config_provider_index).ok()?;
    let (handle, entry) = providers.providers.iter().nth(index)?;
    entry
        .models
        .iter()
        .any(|model| model.id == choice.model_id)
        .then(|| (handle.clone(), choice.model_id.clone()))
}

#[cfg(test)]
mod tests {
    use super::resolve_setup_config_model;
    use cockpit_config::providers::{ModelEntry, ProviderEntry, ProvidersConfig};

    fn route(index: u32) -> cockpit_proto::SessionSetupModelChoiceRouteV1 {
        cockpit_proto::SessionSetupModelChoiceRouteV1 {
            choice_id: format!("choice-{index}"),
            route_choice_id: format!("route-{index}"),
            config_provider_index: index,
        }
    }

    fn choice(index: u32, provider: &str, model: &str) -> cockpit_proto::AgentInstallationChoiceV1 {
        cockpit_proto::AgentInstallationChoiceV1 {
            choice_id: format!("choice-{index}"),
            slot_id: "primary".into(),
            offering_id: format!("offering-{index}"),
            provider_id: provider.into(),
            model_id: model.into(),
            recommendation_id: None,
            canonical_upstream_identity: None,
            author_label: None,
            rationale: None,
            author_suggested: false,
            exact_alias_match: false,
        }
    }

    #[test]
    fn custom_setup_display_token_maps_to_exact_picker_handle() {
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "a-template".into(),
            ProviderEntry {
                template: Some("openai".into()),
                models: vec![ModelEntry {
                    id: "shared".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );
        providers.providers.insert(
            "private-profile-handle".into(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "custom-model".into(),
                    ..ModelEntry::default()
                }],
                ..ProviderEntry::default()
            },
        );

        assert_eq!(
            resolve_setup_config_model(
                &providers,
                &route(1),
                &choice(1, "configured-provider-1", "custom-model"),
            ),
            Some(("private-profile-handle".into(), "custom-model".into()))
        );
        assert_eq!(
            resolve_setup_config_model(&providers, &route(0), &choice(0, "openai", "shared"),),
            Some(("a-template".into(), "shared".into()))
        );
    }

    #[test]
    fn same_template_and_model_profiles_keep_exact_setup_order_and_default_identity() {
        let mut providers = ProvidersConfig::default();
        for handle in ["first", "second"] {
            providers.providers.insert(
                handle.into(),
                ProviderEntry {
                    template: Some("shared-template".into()),
                    models: vec![ModelEntry {
                        id: "same-model".into(),
                        ..ModelEntry::default()
                    }],
                    ..ProviderEntry::default()
                },
            );
        }
        assert_eq!(
            [0, 1].map(|index| resolve_setup_config_model(
                &providers,
                &route(index),
                &choice(index, "shared-template", "same-model"),
            )),
            [
                Some(("first".into(), "same-model".into())),
                Some(("second".into(), "same-model".into())),
            ],
            "the DTO's exact config indices preserve both slot entries instead of dropping an ambiguous display reverse-map"
        );
    }
}
