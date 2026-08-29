//! App-side wiring for the session-setup overlay and inline panel: open,
//! fetch the daemon-owned snapshot, apply results, and dispatch mutations.

use super::*;

use crate::tui::session_setup::{SessionSetupOutcome, SessionSetupPane};

/// Async-action name for the session-setup snapshot fetch. `Replace` policy
/// keyed on this name coalesces bursts (e.g. repeated `AgentTreeChanged`
/// invalidations) into a single in-flight request.
const SESSION_SETUP_SNAPSHOT_ACTION: &str = "session_setup.snapshot";

pub(super) const SESSION_SETUP_COLLAPSE_HINT: &str =
    "Agent: /agents or /tree · Model: node override · Tools: /tools · MCP: /settings";

impl App {
    /// Open the session-setup overlay and schedule its first snapshot fetch.
    /// The daemon owns the snapshot; before attach the pane shows a fixed
    /// unavailable message rather than any local guess.
    pub(super) fn open_session_setup(&mut self) {
        // Colour is supplementary here; render with styling and let the
        // terminal honour NO_COLOR. The plain projection is exercised by tests.
        let mut pane = SessionSetupPane::loading(true);
        if let Some(inline) = self.session_setup_inline.as_ref() {
            pane.adopt_frozen_session(inline);
        }
        self.overlay = Overlay::SessionSetup(pane);
        self.request_session_setup_snapshot_refresh();
    }

    pub(super) fn session_setup_inline_visible(&self) -> bool {
        !self.session_setup_collapsed && self.session_setup_inline.is_some()
    }

    pub(super) fn prepare_session_setup_for_fresh_session(&mut self) {
        self.session_setup_collapsed = false;
        self.session_setup_focused = true;
        self.session_setup_collapse_hint = None;
        self.session_setup_inline = Some(SessionSetupPane::loading_inline(true));
        self.request_session_setup_snapshot_refresh();
    }

    pub(super) fn prepare_session_setup_for_resume(&mut self, has_user_history: bool) {
        if has_user_history {
            self.session_setup_collapsed = true;
            self.session_setup_focused = false;
            self.session_setup_collapse_hint = Some(SESSION_SETUP_COLLAPSE_HINT.to_string());
            if self.session_setup_inline.is_none() {
                self.session_setup_inline = Some(SessionSetupPane::loading_inline(true));
            }
            self.request_session_setup_snapshot_refresh();
        } else {
            self.prepare_session_setup_for_fresh_session();
        }
    }

    pub(super) fn collapse_session_setup_on_first_submit(&mut self) {
        if self.session_setup_collapsed {
            return;
        }
        self.session_setup_collapsed = true;
        self.session_setup_focused = false;
        self.session_setup_collapse_hint = Some(SESSION_SETUP_COLLAPSE_HINT.to_string());
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
                } else {
                    self.session_setup_focused = false;
                    self.session_setup_inline = Some(pane);
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
                if pane
                    .snapshot()
                    .is_some_and(|snapshot| !snapshot.root_foreground)
                {
                    pane.set_notice(
                        "Agent changes are unavailable while an interactive subagent holds the foreground."
                            .to_string(),
                    );
                    if as_overlay {
                        self.overlay = Overlay::SessionSetup(pane);
                    } else {
                        self.session_setup_inline = Some(pane);
                    }
                    return;
                }
                if as_overlay {
                    self.overlay = Overlay::SessionSetup(pane);
                } else {
                    self.session_setup_inline = Some(pane);
                }
                self.swap_primary_agent(&name);
                self.request_session_setup_snapshot_refresh();
            }
            SessionSetupOutcome::SelectModel { slot_id, choice_id } => {
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
                self.submit_session_setup_add_mcp(scope, name, transport, endpoint, command, auth);
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

    fn submit_session_setup_model_override(&mut self, slot_id: String, choice_id: String) {
        let snapshot = self
            .session_setup_inline
            .as_ref()
            .and_then(|pane| pane.snapshot())
            .cloned()
            .or_else(|| {
                if let Overlay::SessionSetup(pane) = &self.overlay {
                    pane.snapshot().cloned()
                } else {
                    None
                }
            });
        let Some(snapshot) = snapshot else {
            return;
        };
        let Some(id) = snapshot
            .root_agent_instance_id
            .as_deref()
            .and_then(|value| uuid::Uuid::parse_str(value).ok())
        else {
            self.set_session_setup_notice(
                "Model override needs the root agent node; retry after the session finishes starting."
                    .to_string(),
            );
            self.request_session_setup_snapshot_refresh();
            return;
        };
        // Slot-allowed and root out-of-set picks share this CAS. The daemon
        // stores a live binding when the choice is bound, or a derived-def
        // handle for a root-compatible unbound choice (`resolve_node_model_override`).
        self.submit_agent_session_override(
            id,
            snapshot.override_revision,
            cockpit_proto::AgentSessionOverrideFieldV1::Model { slot_id, choice_id },
        );
        self.request_session_setup_snapshot_refresh();
    }

    fn submit_session_setup_tool_surface(&mut self, override_json: String) {
        self.send_daemon_request(
            "/session-setup",
            cockpit_proto::Request::SetToolSurfaceOverride {
                override_json,
                persist_session: true,
                prune_after_switch: false,
                monty_nudge: None,
            },
            ControlApplied::SessionSetupToolSurface,
        );
    }

    fn submit_session_setup_add_mcp(
        &mut self,
        scope: crate::tui::session_setup::SessionSetupMcpScope,
        name: String,
        transport: String,
        endpoint: Option<String>,
        command: Option<String>,
        auth: String,
    ) {
        match scope {
            crate::tui::session_setup::SessionSetupMcpScope::Agent => {
                if session_setup_auth_is_oauth(&auth) {
                    self.set_session_setup_notice(
                        "OAuth MCPs must use global or workspace scope so the daemon can own the device/browser flow."
                            .to_string(),
                    );
                    return;
                }
                // Agent-scope MCP writes the agent package (one MutateAgent journal).
                self.start_session_setup_agent_mcp_save(name, transport, endpoint, command, auth);
            }
            crate::tui::session_setup::SessionSetupMcpScope::Global
            | crate::tui::session_setup::SessionSetupMcpScope::Workspace => {
                self.start_session_setup_scoped_mcp_save(
                    scope.as_str().to_string(),
                    name,
                    transport,
                    endpoint,
                    command,
                    auth,
                );
            }
        }
    }

    fn start_session_setup_scoped_mcp_save(
        &mut self,
        target_scope: String,
        name: String,
        transport: String,
        endpoint: Option<String>,
        command: Option<String>,
        auth: String,
    ) {
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            self.set_session_setup_notice("Add MCP requires an attached session.".to_string());
            return;
        };
        let attached = runner.attached_request_binding();
        let project_root = self.launch.cwd.display().to_string();
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("session_setup.add_mcp"),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            async move {
                let oauth = session_setup_auth_is_oauth(&auth);
                let oauth_server = name.clone();
                let snapshot_session_id = uuid::Uuid::new_v4().to_string();
                let snapshot = attached
                    .request(cockpit_proto::Request::GetProviderCatalogSnapshot {
                        project_root: project_root.clone(),
                        provider_id: None,
                        snapshot_session_id: snapshot_session_id.clone(),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                let cockpit_proto::Response::ProviderCatalogSnapshot { config, .. } = snapshot
                else {
                    return Err("unexpected MCP authority snapshot".to_string());
                };
                let server = session_setup_mcp_server_json(&transport, endpoint, command, &auth)?;
                let expected_revision = config
                    .mcp_scope_revisions
                    .get(&target_scope)
                    .cloned()
                    .ok_or_else(|| format!("MCP {target_scope} scope is unavailable"))?;
                let patch = cockpit_proto::McpConfigPatch {
                    operations: vec![cockpit_proto::McpConfigPatchOperation::AddServer {
                        name,
                        server_json: server.into(),
                    }],
                };
                let patch_wire =
                    serde_json::to_string(&patch).map_err(|error| error.to_string())?;
                let mutation_intent_hash = cockpit_proto::mcp_mutation_intent_hash_for_scope(
                    &project_root,
                    &patch_wire,
                    Some(&target_scope),
                );
                let response = attached
                    .request(cockpit_proto::Request::SaveMcpConfig {
                        client_operation_id: uuid::Uuid::new_v4().to_string(),
                        project_root: project_root.clone(),
                        snapshot_capability: config.mcp_edit_capability.unwrap_or_default(),
                        owner_root: config
                            .mcp_owner_root
                            .unwrap_or_else(|| project_root.clone()),
                        config_path: config.mcp_config_path.unwrap_or_default(),
                        expected_revision,
                        mutation_intent_hash,
                        patch: cockpit_proto::SensitiveWirePayload::new(patch_wire),
                        secret_values_json: cockpit_proto::SensitiveWirePayload::new("{}".into()),
                        target_scope: Some(target_scope),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                if oauth {
                    return attached
                        .request(cockpit_proto::Request::BeginMcpOAuth {
                            client_operation_id: uuid::Uuid::new_v4().to_string(),
                            project_root,
                            server: oauth_server,
                            profile: cockpit_core::mcp::config::DEFAULT_PROFILE.to_string(),
                            agent: None,
                        })
                        .await
                        .map(crate::tui::async_action::AsyncActionPayload::SessionSetupSnapshot)
                        .map_err(|error| error.to_string());
                }
                Ok(crate::tui::async_action::AsyncActionPayload::SessionSetupSnapshot(response))
            },
        );
    }

    fn start_session_setup_agent_mcp_save(
        &mut self,
        name: String,
        transport: String,
        endpoint: Option<String>,
        command: Option<String>,
        auth: String,
    ) {
        let active_agent = self
            .session_setup_inline
            .as_ref()
            .and_then(|pane| pane.snapshot())
            .and_then(|snapshot| snapshot.resolved_agent.clone())
            .or_else(|| {
                if let Overlay::SessionSetup(pane) = &self.overlay {
                    pane.snapshot()
                        .and_then(|snapshot| snapshot.resolved_agent.clone())
                } else {
                    None
                }
            })
            .unwrap_or_else(|| self.launch.agent_name.clone());
        if cockpit_core::agents::is_builtin_agent(&active_agent) {
            self.set_session_setup_notice(
                "Built-in agents cannot own package MCPs; choose workspace scope or eject the agent first."
                    .to_string(),
            );
            return;
        }
        let Some(Ok(runner)) = self.agent_runner.as_ref() else {
            self.set_session_setup_notice("Add MCP requires an attached session.".to_string());
            return;
        };
        let attached = runner.attached_request_binding();
        let project_root = self.launch.cwd.display().to_string();
        let agent_name = active_agent;
        self.async_actions.start(
            crate::tui::async_action::AsyncActionKind::DaemonRpc("session_setup.add_mcp_agent"),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            async move {
                let snapshot = attached
                    .request(cockpit_proto::Request::GetAgentEditSnapshot {
                        project_root: project_root.clone(),
                        name: agent_name.clone(),
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                let expected_revision = match snapshot {
                    cockpit_proto::Response::AgentEditSnapshot(snapshot) => Some(snapshot.revision),
                    _ => None,
                };
                let server = session_setup_mcp_server_json(&transport, endpoint, command, &auth)?;
                let mutation = cockpit_proto::AgentMutation::AddMcpServer {
                    name: agent_name.clone(),
                    server: name,
                    server_json: server,
                    profile: "default".to_string(),
                    secret_values: std::collections::BTreeMap::new(),
                };
                let mutation_intent_hash = cockpit_proto::agent_mutation_intent_hash(
                    &project_root,
                    &mutation,
                    expected_revision.as_deref(),
                );
                let response = attached
                    .request(cockpit_proto::Request::MutateAgent {
                        client_operation_id: uuid::Uuid::new_v4().to_string(),
                        mutation_intent_hash,
                        project_root: project_root.clone(),
                        mutation,
                        expected_revision,
                    })
                    .await
                    .map_err(|error| error.to_string())?;
                Ok(crate::tui::async_action::AsyncActionPayload::SessionSetupSnapshot(response))
            },
        );
    }

    pub(super) fn set_session_setup_notice(&mut self, message: String) {
        if let Overlay::SessionSetup(pane) = &mut self.overlay {
            pane.set_notice(message.clone());
        }
        if let Some(pane) = self.session_setup_inline.as_mut() {
            pane.set_notice(message);
        }
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
        let snapshot = match response {
            cockpit_proto::Response::SessionSetupSnapshot { snapshot } => snapshot,
            cockpit_proto::Response::McpOAuthStarted {
                authorize_url,
                user_code,
                verification_uri,
                ..
            } => {
                let destination = verification_uri.unwrap_or(authorize_url);
                let code = user_code
                    .map(|code| format!(" with code `{code}`"))
                    .unwrap_or_default();
                self.set_session_setup_notice(format!(
                    "MCP OAuth started{code}: open {destination}. Finish or poll it in /settings."
                ));
                self.request_session_setup_snapshot_refresh();
                return;
            }
            _ => {
                self.request_session_setup_snapshot_refresh();
                return;
            }
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

    /// Lease, staleness, and other Add-MCP refusals stay on the Ready panel
    /// as a notice so the user can see the existing rows and retry.
    pub(super) fn apply_session_setup_add_mcp_error(&mut self, error: String) {
        self.set_session_setup_notice(format!("Add MCP was refused: {error}"));
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

fn session_setup_mcp_server_json(
    transport: &str,
    endpoint: Option<String>,
    command: Option<String>,
    auth: &str,
) -> Result<String, String> {
    let auth_block = if auth.trim_start().starts_with('{') {
        serde_json::from_str(auth).map_err(|error| format!("invalid MCP auth: {error}"))?
    } else {
        match auth {
            "oauth" => serde_json::json!({"kind": "oauth"}),
            "header" => {
                serde_json::json!({"kind": "header", "header": "Authorization", "value": ""})
            }
            "env" => serde_json::json!({"kind": "env"}),
            _ => serde_json::json!({"kind": "none"}),
        }
    };
    let value = serde_json::json!({
        "transport": transport,
        "endpoint": endpoint,
        "command": command,
        "auth": auth_block,
        "enabled": true,
    });
    serde_json::to_string(&value).map_err(|error| error.to_string())
}

fn session_setup_auth_is_oauth(auth: &str) -> bool {
    auth == "oauth"
        || serde_json::from_str::<serde_json::Value>(auth)
            .ok()
            .and_then(|value| {
                value
                    .get("kind")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            })
            .as_deref()
            == Some("oauth")
}

#[cfg(test)]
mod tests {
    use super::*;
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

    #[test]
    fn modes_session_setup_fresh_session_shows_inline_until_first_submit() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        assert!(app.session_setup_inline_visible());
        assert!(!app.session_setup_collapsed);
        app.collapse_session_setup_on_first_submit();
        assert!(!app.session_setup_inline_visible());
        assert!(app.session_setup_collapsed);
        assert_eq!(
            app.session_setup_collapse_hint.as_deref(),
            Some(SESSION_SETUP_COLLAPSE_HINT)
        );
        assert!(
            app.session_setup_inline.is_some(),
            "collapse must not drop pane state so /session-setup can reopen current values"
        );
        app.collapse_session_setup_on_first_submit();
        assert!(app.session_setup_collapsed, "second submit is a no-op");
    }

    #[test]
    fn modes_session_setup_reopen_overlay_copies_frozen_tool_order() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let snapshot = cockpit_proto::SessionSetupSnapshotV1 {
            dto_version: cockpit_proto::SESSION_SETUP_DTO_VERSION,
            session_id: "11111111-1111-4111-8111-111111111111".to_string(),
            config_generation: 1,
            revision: 1,
            selected_installation_id: None,
            candidates: Vec::new(),
            resolved_agent: None,
            last_used_agent: None,
            available_agents: Vec::new(),
            root_agent_instance_id: None,
            override_revision: 0,
            root_foreground: true,
            model: Default::default(),
            tools: vec![
                cockpit_proto::SessionSetupToolV1 {
                    name: "read".into(),
                    tier: "enabled".into(),
                    locked: false,
                    legal_tiers: vec!["enabled".into(), "discoverable".into()],
                    family: "test".into(),
                },
                cockpit_proto::SessionSetupToolV1 {
                    name: "bash".into(),
                    tier: "discoverable".into(),
                    locked: false,
                    legal_tiers: vec!["enabled".into(), "discoverable".into()],
                    family: "test".into(),
                },
            ],
            mcps: Vec::new(),
        };
        app.apply_session_setup_snapshot_response(cockpit_proto::Response::SessionSetupSnapshot {
            snapshot,
        });
        let frozen = app
            .session_setup_inline
            .as_ref()
            .expect("inline pane")
            .frozen_tool_order()
            .to_vec();
        assert_eq!(frozen, vec!["read".to_string(), "bash".to_string()]);
        app.collapse_session_setup_on_first_submit();
        app.open_session_setup();
        let Overlay::SessionSetup(pane) = &app.overlay else {
            panic!("reopen must construct the overlay pane");
        };
        assert_eq!(pane.frozen_tool_order(), frozen.as_slice());
    }

    #[test]
    fn modes_session_setup_add_mcp_error_keeps_ready_rows() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let snapshot = cockpit_proto::SessionSetupSnapshotV1 {
            dto_version: cockpit_proto::SESSION_SETUP_DTO_VERSION,
            session_id: "11111111-1111-4111-8111-111111111111".to_string(),
            config_generation: 1,
            revision: 1,
            selected_installation_id: None,
            candidates: Vec::new(),
            resolved_agent: None,
            last_used_agent: None,
            available_agents: Vec::new(),
            root_agent_instance_id: None,
            override_revision: 0,
            root_foreground: true,
            model: Default::default(),
            tools: vec![cockpit_proto::SessionSetupToolV1 {
                name: "read".into(),
                tier: "enabled".into(),
                locked: false,
                legal_tiers: vec!["enabled".into(), "discoverable".into()],
                family: "test".into(),
            }],
            mcps: Vec::new(),
        };
        app.apply_session_setup_snapshot_response(cockpit_proto::Response::SessionSetupSnapshot {
            snapshot,
        });
        app.apply_session_setup_add_mcp_error("lease held by another editor".to_string());
        let pane = app.session_setup_inline.as_ref().expect("inline pane");
        let lines: Vec<String> = pane
            .inline_lines()
            .into_iter()
            .map(|line| line.to_string())
            .collect();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Add MCP was refused") && line.contains("lease held")),
            "open-lease/staleness must surface as a notice from the RPC: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("read")),
            "an Add-MCP refusal must not replace Ready rows with a load-failure screen: {lines:?}"
        );
        assert!(
            !lines
                .iter()
                .any(|line| line.contains("Session setup could not be loaded")),
            "Add-MCP Err must not take the snapshot-load failure path: {lines:?}"
        );

        app.apply_session_setup_snapshot_error("transport reset".to_string());
        let pane = app.session_setup_inline.as_ref().expect("inline pane");
        let lines: Vec<String> = pane
            .inline_lines()
            .into_iter()
            .map(|line| line.to_string())
            .collect();
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Session setup could not be loaded")),
            "snapshot fetch Err still uses the load-failure screen: {lines:?}"
        );
        assert!(
            !lines.iter().any(|line| line.contains("read")),
            "a snapshot load failure drops Ready rows: {lines:?}"
        );
    }

    #[test]
    fn modes_session_setup_missing_root_notice_reaches_overlay_and_inline() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        let snapshot = cockpit_proto::SessionSetupSnapshotV1 {
            dto_version: cockpit_proto::SESSION_SETUP_DTO_VERSION,
            session_id: "11111111-1111-4111-8111-111111111111".to_string(),
            config_generation: 1,
            revision: 1,
            selected_installation_id: None,
            candidates: Vec::new(),
            resolved_agent: None,
            last_used_agent: None,
            available_agents: Vec::new(),
            root_agent_instance_id: None,
            override_revision: 0,
            root_foreground: true,
            model: Default::default(),
            tools: Vec::new(),
            mcps: Vec::new(),
        };
        app.overlay = Overlay::SessionSetup(SessionSetupPane::loading(true));
        app.apply_session_setup_snapshot_response(cockpit_proto::Response::SessionSetupSnapshot {
            snapshot,
        });
        app.submit_session_setup_model_override("primary".into(), "choice".into());
        let inline = app.session_setup_inline.as_ref().expect("inline pane");
        assert!(
            inline
                .notice()
                .is_some_and(|notice| notice.contains("root agent node")),
            "inline setup must surface a missing-root model apply, not stay silent"
        );
        let Overlay::SessionSetup(pane) = &app.overlay else {
            panic!("overlay pane must stay SessionSetup");
        };
        assert!(
            pane.notice()
                .is_some_and(|notice| notice.contains("root agent node")),
            "overlay-only users must see the same missing-root notice"
        );
        app.apply_event(cockpit_client::presentation::TurnEvent::AgentTreeChanged {
            session_id: uuid::Uuid::nil(),
        });
        let inline = app.session_setup_inline.as_ref().expect("inline pane");
        assert!(
            inline
                .error_message()
                .is_some_and(|error| error.contains("only available once attached")),
            "AgentTreeChanged must schedule a snapshot refresh for the inline pane"
        );
        let Overlay::SessionSetup(pane) = &app.overlay else {
            panic!("overlay pane must stay SessionSetup");
        };
        assert!(
            pane.error_message()
                .is_some_and(|error| error.contains("only available once attached")),
            "AgentTreeChanged must schedule a snapshot refresh for the overlay pane"
        );
        let mapper = include_str!("../agent_runner.rs");
        assert!(
            mapper.contains(
                "AgentTreeChanged { session_id, .. } => TurnEvent::AgentTreeChanged { session_id }"
            ),
            "AgentTreeChanged must keep mapping into TurnEvent so setup refresh runs"
        );
        let events = include_str!("events.rs");
        let refresh = events
            .split("TurnEvent::AgentTreeChanged")
            .nth(1)
            .expect("AgentTreeChanged apply arm");
        assert!(
            refresh.contains("request_session_setup_snapshot_refresh"),
            "AgentTreeChanged must refresh an open setup overlay/inline pane"
        );
    }

    #[test]
    fn modes_session_setup_resume_with_user_history_starts_collapsed() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = App::new(Some(tmp.path()), false);
        app.prepare_session_setup_for_resume(true);
        assert!(app.session_setup_collapsed);
        assert!(!app.session_setup_inline_visible());
        app.prepare_session_setup_for_resume(false);
        assert!(!app.session_setup_collapsed);
        assert!(app.session_setup_inline_visible());
    }
}
