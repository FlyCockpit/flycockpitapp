//! Enrich the session-setup snapshot with last-used agent, computed tool
//! tiers, and the scope-aware MCP catalog. Presentation only — mutations
//! stay on existing RPCs.

use cockpit_db::db::agent_tree_decisions::{AgentOverrideState, StoredModelBinding};
use cockpit_proto::{
    AgentInstallationChoiceV1, AgentModelControlV1, AgentModelRefV1, SessionSetupMcpV1,
    SessionSetupModelSlotV1, SessionSetupSnapshotV1, SessionSetupToolV1,
};

use crate::agents::{self, AgentDef, ToolSurfaceSelection};
use crate::mcp::resolver::{CatalogEntry, McpScope};

/// Prefer a pending session-only model apply, then a consumed effective binding.
pub fn model_override_from_state(
    state: Option<AgentOverrideState>,
) -> (u64, Option<StoredModelBinding>) {
    let Some(state) = state else {
        return (0, None);
    };
    let model = state
        .pending
        .and_then(|pending| pending.model)
        .or_else(|| state.effective.and_then(|effective| effective.model));
    (state.override_revision.max(0) as u64, model)
}

pub fn enrich_session_setup_snapshot(
    mut snapshot: SessionSetupSnapshotV1,
    project_root: &std::path::Path,
    active_agent: &str,
    last_used_agent: Option<String>,
    tool_surface_override_json: Option<&str>,
    root_foreground: bool,
    root_agent_instance_id: Option<String>,
    override_revision: u64,
    model_override: Option<StoredModelBinding>,
) -> anyhow::Result<SessionSetupSnapshotV1> {
    let available = agents::chat_ownable_primaries(project_root);
    snapshot.available_agents = available.clone();
    snapshot.last_used_agent = last_used_agent;
    snapshot.resolved_agent = Some(active_agent.to_string());
    snapshot.root_foreground = root_foreground;
    snapshot.root_agent_instance_id = root_agent_instance_id;
    snapshot.override_revision = override_revision;

    let mut def = agents::resolve(project_root, active_agent)?
        .or_else(|| agents::embedded_default(active_agent))
        // Session-setup is a projection of a durable prepared profile.  A
        // profile may retain a package-backed primary whose source package is
        // no longer present at the mutable workspace path; keep rendering the
        // durable candidate/model evidence with the stable built-in surface
        // instead of turning a read-only setup query into an internal error.
        .or_else(|| agents::embedded_default("Build"))
        .ok_or_else(|| anyhow::anyhow!("embedded Build agent is unavailable"))?;
    if let Some(json) = tool_surface_override_json
        && let Ok(selection) = serde_json::from_str::<ToolSurfaceSelection>(json)
    {
        let _ = agents::apply_tool_surface_override(&mut def, &selection);
    }
    snapshot.tools = project_tools(&def);
    snapshot.mcps = project_mcps(project_root, &def);
    snapshot.model = project_model(&snapshot, active_agent);
    if let Some(binding) = model_override {
        snapshot.model.effective = Some(model_ref_from_override(&snapshot, &binding));
    }
    Ok(snapshot)
}

fn project_tools(def: &AgentDef) -> Vec<SessionSetupToolV1> {
    let granted = def.tools.as_deref().unwrap_or_default();
    agents::tool_surface_catalog()
        .into_iter()
        .filter(|item| {
            item.name != "escalate"
                && (granted.iter().any(|tool| tool == item.name)
                    || tool_can_be_added(def, item.name))
        })
        .map(|item| {
            let tier = if agents::is_safety_tool(item.name) {
                crate::agents::ToolTier::Enabled
            } else if granted.iter().any(|tool| tool == item.name) {
                agents::computed_tool_tier(def, item.name)
            } else {
                crate::agents::ToolTier::Disabled
            };
            SessionSetupToolV1 {
                name: item.name.to_string(),
                tier: tier.label().to_string(),
                locked: agents::is_safety_tool(item.name),
                legal_tiers: agents::legal_tool_tiers(item.name)
                    .iter()
                    .map(|tier| tier.label().to_string())
                    .collect(),
                family: item.family.to_string(),
            }
        })
        .collect()
}

fn tool_can_be_added(def: &AgentDef, tool: &str) -> bool {
    let mut tools = def.tools.clone().unwrap_or_default();
    if !tools.iter().any(|name| name == tool) {
        tools.push(tool.to_string());
    }
    let mut candidate = def.clone();
    agents::apply_tool_surface_override(
        &mut candidate,
        &ToolSurfaceSelection {
            tools,
            tool_tiers: def.tool_tiers.clone(),
        },
    )
    .is_ok()
}

fn project_mcps(project_root: &std::path::Path, def: &AgentDef) -> Vec<SessionSetupMcpV1> {
    let (agent_layer, _) = agent_mcp_layer(def);
    let catalog = crate::mcp::resolver::discover_effective_catalog_with_agent(
        project_root,
        agent_layer.as_ref(),
    );
    let mut entries: Vec<&CatalogEntry> = catalog.entries().map(|(_, entry)| entry).collect();
    entries.extend(catalog.shadowed_entries());
    entries.sort_by(|left, right| {
        scope_rank(left.source())
            .cmp(&scope_rank(right.source()))
            .then_with(|| left.name().cmp(right.name()))
    });
    entries
        .into_iter()
        .filter(|entry| entry.is_enabled())
        .map(|entry| SessionSetupMcpV1 {
            name: entry.name().to_string(),
            scope: entry.source().as_str().to_string(),
            enabled: entry.is_enabled(),
            shadowed_by: entry.shadowed_by.map(|scope| scope.as_str().to_string()),
            profile: Some(entry.profile.clone()).filter(|profile| !profile.is_empty()),
        })
        .collect()
}

fn agent_mcp_layer(def: &AgentDef) -> (Option<crate::mcp::config::McpConfig>, bool) {
    let Some(files) = def.package_files.as_ref() else {
        return (None, false);
    };
    let Some(bytes) = files.get("mcp.json") else {
        return (None, false);
    };
    let Ok(raw) = std::str::from_utf8(bytes) else {
        return (None, false);
    };
    match crate::mcp::config::McpConfig::parse(raw) {
        Ok(cfg) => (Some(cfg), false),
        Err(_) => (None, true),
    }
}

fn scope_rank(scope: McpScope) -> u8 {
    match scope {
        McpScope::Builtin => 0,
        McpScope::Global => 0,
        McpScope::Agent => 1,
        McpScope::Workspace => 2,
    }
}

fn project_model(snapshot: &SessionSetupSnapshotV1, active_agent: &str) -> AgentModelControlV1 {
    let candidate = snapshot
        .candidates
        .iter()
        .find(|candidate| {
            candidate
                .installation
                .source_agent_id
                .rsplit('/')
                .next()
                .is_some_and(|name| name == active_agent)
        })
        .or_else(|| {
            snapshot
                .candidates
                .iter()
                .find(|candidate| candidate.selected)
        });
    let Some(candidate) = candidate else {
        return AgentModelControlV1::default();
    };
    let Some(slot) = candidate
        .slots
        .iter()
        .find(|slot| slot.slot_id == "primary")
        .or_else(|| candidate.slots.first())
    else {
        return AgentModelControlV1 {
            locked_reason: candidate
                .locked_reason
                .map(|_| cockpit_proto::AgentControlLockedReasonV1::InheritedFromProfile),
            ..Default::default()
        };
    };
    if slot.unavailable_reason.is_some() {
        return AgentModelControlV1 {
            locked_reason: Some(cockpit_proto::AgentControlLockedReasonV1::InheritedFromProfile),
            ..Default::default()
        };
    }
    let allowed: Vec<AgentModelRefV1> = slot
        .choices
        .iter()
        .filter(|choice| slot.allowed_choice_ids.contains(&choice.choice_id))
        .map(|choice| model_ref_for_choice(slot, choice))
        .collect();
    let effective = allowed
        .iter()
        .find(|model| model.is_default)
        .cloned()
        .or_else(|| allowed.first().cloned());
    AgentModelControlV1 {
        effective,
        allowed,
        pending: None,
        locked_reason: None,
    }
}

fn model_ref_for_choice(
    slot: &SessionSetupModelSlotV1,
    choice: &AgentInstallationChoiceV1,
) -> AgentModelRefV1 {
    let choice_id = slot
        .choice_routes
        .iter()
        .find(|route| route.choice_id == choice.choice_id)
        .map(|route| route.route_choice_id.clone())
        .unwrap_or_else(|| choice.choice_id.clone());
    AgentModelRefV1 {
        choice_id,
        provider_id: choice.provider_id.clone(),
        model_id: choice.model_id.clone(),
        is_default: slot.default_choice_id.as_deref() == Some(choice.choice_id.as_str()),
    }
}

fn model_ref_from_override(
    snapshot: &SessionSetupSnapshotV1,
    binding: &StoredModelBinding,
) -> AgentModelRefV1 {
    let slot = snapshot.candidates.iter().find_map(|candidate| {
        candidate
            .slots
            .iter()
            .find(|slot| slot.slot_id == binding.slot_id)
            .or_else(|| {
                candidate
                    .slots
                    .first()
                    .filter(|_| binding.slot_id == "primary")
            })
    });
    if let Some(slot) = slot {
        for choice in &slot.choices {
            if choice.model_id != binding.model {
                continue;
            }
            if let Some(route) = slot
                .choice_routes
                .iter()
                .find(|route| route.choice_id == choice.choice_id)
            {
                let expected = cockpit_proto::focused_model_binding_choice_id(
                    &binding.provider,
                    &choice.provider_id,
                    &binding.model,
                );
                if route.route_choice_id == expected {
                    return model_ref_for_choice(slot, choice);
                }
            } else if choice.provider_id == binding.provider {
                return model_ref_for_choice(slot, choice);
            }
        }
        if let Some(choice) = slot
            .choices
            .iter()
            .find(|choice| choice.model_id == binding.model)
        {
            return model_ref_for_choice(slot, choice);
        }
    }
    AgentModelRefV1 {
        choice_id: cockpit_proto::focused_model_binding_choice_id(
            &binding.provider,
            &binding.provider,
            &binding.model,
        ),
        provider_id: binding.provider.clone(),
        model_id: binding.model.clone(),
        is_default: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_tools_omit_escalate_and_pin_safety() {
        let def = agents::embedded_default("Build").expect("Build");
        let tools = project_tools(&def);
        assert!(tools.iter().all(|tool| tool.name != "escalate"));
        assert!(
            tools
                .iter()
                .any(|tool| tool.locked && tool.name == "question")
        );
    }

    fn entry(
        name: &str,
        source: crate::mcp::resolver::PersistentMcpScope,
        shadowed_by: Option<McpScope>,
    ) -> CatalogEntry {
        let server: crate::mcp::config::ServerConfig = serde_json::from_value(serde_json::json!({
            "transport": "streamable",
            "enabled": true
        }))
        .expect("server");
        let mut cfg = crate::mcp::config::McpConfig::default();
        cfg.servers.insert(name.to_string(), server);
        let mut entry =
            crate::mcp::resolver::EffectiveCatalog::from_mcp_config_with_scope(&cfg, source)
                .get(name)
                .expect("fixture server is admitted")
                .clone();
        entry.shadowed_by = shadowed_by;
        entry
    }

    #[test]
    fn setup_mcp_groups_global_then_agent_then_workspace() {
        let mut entries = vec![
            entry(
                "w",
                crate::mcp::resolver::PersistentMcpScope::Workspace,
                None,
            ),
            entry("a", crate::mcp::resolver::PersistentMcpScope::Agent, None),
            entry("g", crate::mcp::resolver::PersistentMcpScope::Global, None),
            entry(
                "g-shadow",
                crate::mcp::resolver::PersistentMcpScope::Global,
                Some(McpScope::Workspace),
            ),
        ];
        entries.sort_by(|left, right| {
            scope_rank(left.source())
                .cmp(&scope_rank(right.source()))
                .then_with(|| left.name().cmp(right.name()))
        });
        let scopes: Vec<_> = entries.iter().map(|e| e.source().as_str()).collect();
        assert_eq!(scopes, vec!["global", "global", "agent", "workspace"]);
        assert_eq!(entries[1].shadowed_by, Some(McpScope::Workspace));
    }

    fn setup_choice(
        provider: &str,
        model: &str,
        suggested: bool,
    ) -> cockpit_proto::AgentInstallationChoiceV1 {
        cockpit_proto::AgentInstallationChoiceV1 {
            choice_id: format!("{provider}/{model}"),
            slot_id: "primary".to_string(),
            offering_id: format!("{provider}:{model}"),
            provider_id: provider.to_string(),
            model_id: model.to_string(),
            recommendation_id: None,
            canonical_upstream_identity: None,
            author_label: None,
            rationale: None,
            author_suggested: suggested,
            exact_alias_match: suggested,
        }
    }

    fn setup_snapshot_with_slot(slot: SessionSetupModelSlotV1) -> SessionSetupSnapshotV1 {
        SessionSetupSnapshotV1 {
            dto_version: cockpit_proto::SESSION_SETUP_DTO_VERSION,
            session_id: "11111111-1111-4111-8111-111111111111".to_string(),
            config_generation: 1,
            revision: 1,
            selected_installation_id: None,
            candidates: vec![cockpit_proto::SessionSetupAgentCandidateV1 {
                installation: cockpit_proto::AgentInstallationRecordV1 {
                    installation_id: "authored/reviewer-global".to_string(),
                    scope: cockpit_proto::AgentInstallationScopeWire::Global,
                    source_agent_id: "authored/reviewer".to_string(),
                    source_identity: "publisher/repo:agents/reviewer.md".to_string(),
                    source_revision: None,
                    source_digest: "a".repeat(64),
                    installation_revision: 1,
                    bindings: Vec::new(),
                },
                selected: true,
                slots: vec![slot],
                locked_reason: None,
            }],
            resolved_agent: Some("reviewer".to_string()),
            last_used_agent: None,
            available_agents: vec!["reviewer".to_string()],
            root_agent_instance_id: None,
            override_revision: 0,
            root_foreground: true,
            model: AgentModelControlV1::default(),
            tools: Vec::new(),
            mcps: Vec::new(),
        }
    }

    #[test]
    fn setup_model_allowed_is_live_binding_set_not_author_suggestion() {
        let slot = SessionSetupModelSlotV1 {
            slot_id: "primary".to_string(),
            choices: vec![
                setup_choice("local", "suggested-unbound", true),
                setup_choice("local", "bound", false),
            ],
            choice_routes: Vec::new(),
            allowed_choice_ids: vec!["local/bound".to_string()],
            unmatched_recommendations: Vec::new(),
            unavailable_reason: None,
            default_choice_id: Some("local/bound".to_string()),
        };
        let snap = setup_snapshot_with_slot(slot);
        let control = project_model(&snap, "reviewer");
        assert_eq!(
            control
                .allowed
                .iter()
                .map(|model| model.model_id.as_str())
                .collect::<Vec<_>>(),
            vec!["bound"]
        );
        assert_eq!(
            control
                .effective
                .as_ref()
                .map(|model| model.model_id.as_str()),
            Some("bound")
        );
        assert!(
            control
                .allowed
                .iter()
                .all(|model| !model.choice_id.is_empty())
        );
    }

    #[test]
    fn setup_model_override_projects_choice_id_and_effective_row() {
        let slot = SessionSetupModelSlotV1 {
            slot_id: "primary".to_string(),
            choices: vec![
                setup_choice("local", "default", true),
                setup_choice("local", "session", false),
            ],
            choice_routes: Vec::new(),
            allowed_choice_ids: vec!["local/default".to_string(), "local/session".to_string()],
            unmatched_recommendations: Vec::new(),
            unavailable_reason: None,
            default_choice_id: Some("local/default".to_string()),
        };
        let snap = setup_snapshot_with_slot(slot);
        let projected = project_model(&snap, "reviewer");
        assert_eq!(
            projected
                .effective
                .as_ref()
                .map(|model| model.model_id.as_str()),
            Some("default")
        );
        let overlaid = model_ref_from_override(
            &snap,
            &StoredModelBinding {
                slot_id: "primary".to_string(),
                provider: "local".to_string(),
                model: "session".to_string(),
            },
        );
        assert_eq!(overlaid.model_id, "session");
        assert_eq!(overlaid.provider_id, "local");
        assert!(!overlaid.choice_id.is_empty());
        assert!(!overlaid.is_default);
    }

    #[test]
    fn setup_model_override_prefers_pending_then_effective() {
        let pending = StoredModelBinding {
            slot_id: "primary".to_string(),
            provider: "pending-profile".to_string(),
            model: "pending-model".to_string(),
        };
        let effective = StoredModelBinding {
            slot_id: "primary".to_string(),
            provider: "effective-profile".to_string(),
            model: "effective-model".to_string(),
        };
        let (revision, model) = model_override_from_state(Some(AgentOverrideState {
            state: cockpit_db::db::agent_tree_decisions::AgentInstanceState::Running,
            override_revision: 4,
            pending: Some(
                cockpit_db::db::agent_tree_decisions::StoredSessionOverride {
                    model: Some(pending.clone()),
                    sandbox: None,
                    verification: Vec::new(),
                    question: None,
                },
            ),
            effective: Some(
                cockpit_db::db::agent_tree_decisions::StoredSessionOverride {
                    model: Some(effective.clone()),
                    sandbox: None,
                    verification: Vec::new(),
                    question: None,
                },
            ),
            resolved_profile_snapshot_id: None,
            resolved_installation_id: None,
        }));
        assert_eq!(revision, 4);
        assert_eq!(model, Some(pending));

        let (revision, model) = model_override_from_state(Some(AgentOverrideState {
            state: cockpit_db::db::agent_tree_decisions::AgentInstanceState::Running,
            override_revision: 2,
            pending: None,
            effective: Some(
                cockpit_db::db::agent_tree_decisions::StoredSessionOverride {
                    model: Some(effective.clone()),
                    sandbox: None,
                    verification: Vec::new(),
                    question: None,
                },
            ),
            resolved_profile_snapshot_id: None,
            resolved_installation_id: None,
        }));
        assert_eq!(revision, 2);
        assert_eq!(model, Some(effective));
    }
}
