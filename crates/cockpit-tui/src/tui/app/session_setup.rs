//! App-side wiring for the read-only session-setup overlay: open, fetch the
//! daemon-owned snapshot, and apply the result into the open pane.

use super::*;

/// Async-action name for the session-setup snapshot fetch. `Replace` policy
/// keyed on this name coalesces bursts (e.g. repeated `AgentTreeChanged`
/// invalidations) into a single in-flight request.
const SESSION_SETUP_SNAPSHOT_ACTION: &str = "session_setup.snapshot";

impl App {
    /// Open the read-only session-setup overlay and schedule its first
    /// snapshot fetch. The daemon owns the snapshot; before attach the pane
    /// shows a fixed unavailable message rather than any local guess.
    pub(super) fn open_session_setup(&mut self) {
        // Colour is supplementary here; render with styling and let the
        // terminal honour NO_COLOR. The plain projection is exercised by tests.
        self.overlay =
            Overlay::SessionSetup(crate::tui::session_setup::SessionSetupPane::loading(true));
        self.request_session_setup_snapshot_refresh();
    }

    /// Schedule an async `GetSessionSetupSnapshot` fetch for the attached
    /// session. A no-op (with a fixed error surfaced in the pane) when there is
    /// no attached runner, since the snapshot is daemon-owned.
    pub(super) fn request_session_setup_snapshot_refresh(&mut self) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            if let Overlay::SessionSetup(pane) = &mut self.overlay {
                pane.set_error("Session setup is only available once attached to a session.");
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
                    resolve_setup_wire_model(
                        &self.config_snapshot.providers,
                        &choice.provider_id,
                        &choice.model_id,
                    )
                })
                .collect();
            self.prepared_slot_default = primary.default_choice_id.as_ref().and_then(|choice_id| {
                primary
                    .choices
                    .iter()
                    .find(|choice| &choice.choice_id == choice_id)
                    .and_then(|choice| {
                        resolve_setup_wire_model(
                            &self.config_snapshot.providers,
                            &choice.provider_id,
                            &choice.model_id,
                        )
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
            pane.apply_snapshot(snapshot);
        }
    }

    /// Surface a fixed error into the open session-setup overlay.
    pub(super) fn apply_session_setup_snapshot_error(&mut self, error: String) {
        if let Overlay::SessionSetup(pane) = &mut self.overlay {
            pane.set_error(format!("Session setup could not be loaded: {error}"));
        }
    }
}

/// Translate a redacted setup provider identity into the config-map handle the
/// picker uses. Custom-provider handles stay local to the held config snapshot;
/// the daemon's `configured-provider-N` token is accepted only when that exact
/// ordered entry is custom and offers the named model. Ambiguity fails closed.
fn resolve_setup_wire_model(
    providers: &cockpit_config::providers::ProvidersConfig,
    wire_provider_id: &str,
    model_id: &str,
) -> Option<(String, String)> {
    let matches = providers
        .providers
        .iter()
        .enumerate()
        .filter(|(index, (handle, entry))| {
            entry.models.iter().any(|model| model.id == model_id)
                && (handle.as_str() == wire_provider_id
                    || entry.template.as_deref() == Some(wire_provider_id)
                    || entry.template.is_none()
                        && wire_provider_id == format!("configured-provider-{index}"))
        })
        .map(|(_, (handle, _))| (handle.clone(), model_id.to_string()))
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [resolved] => Some(resolved.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_setup_wire_model;
    use cockpit_config::providers::{ModelEntry, ProviderEntry, ProvidersConfig};

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
            resolve_setup_wire_model(&providers, "configured-provider-1", "custom-model"),
            Some(("private-profile-handle".into(), "custom-model".into()))
        );
        assert_eq!(
            resolve_setup_wire_model(&providers, "configured-provider-0", "shared"),
            None,
            "a display token must not select a templated provider at that index"
        );
    }

    #[test]
    fn setup_provider_alias_ambiguity_fails_closed() {
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
            resolve_setup_wire_model(&providers, "shared-template", "same-model"),
            None
        );
    }
}
