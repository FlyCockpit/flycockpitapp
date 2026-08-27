//! Enrich the session-setup snapshot with last-used agent, computed tool
//! tiers, and the scope-aware MCP catalog. Presentation only — mutations
//! stay on existing RPCs.

use cockpit_proto::{
    AgentModelControlV1, AgentModelRefV1, SessionSetupMcpV1, SessionSetupSnapshotV1,
    SessionSetupToolV1,
};

use crate::agents::{self, AgentDef, ToolSurfaceSelection};
use crate::mcp::resolver::{CatalogEntry, McpScope};

pub fn enrich_session_setup_snapshot(
    mut snapshot: SessionSetupSnapshotV1,
    project_root: &std::path::Path,
    active_agent: &str,
    last_used_agent: Option<String>,
    tool_surface_override_json: Option<&str>,
    root_foreground: bool,
    root_agent_instance_id: Option<String>,
    override_revision: u64,
    model_override: Option<cockpit_db::db::agent_tree_decisions::StoredModelBinding>,
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
        .ok_or_else(|| anyhow::anyhow!("active agent `{active_agent}` could not be resolved"))?;
    if let Some(json) = tool_surface_override_json
        && let Ok(selection) = serde_json::from_str::<ToolSurfaceSelection>(json)
    {
        let _ = agents::apply_tool_surface_override(&mut def, &selection);
    }
    snapshot.tools = project_tools(&def);
    snapshot.mcps = project_mcps(project_root, &def);
    snapshot.model = project_model(&snapshot, active_agent);
    if let Some(binding) = model_override {
        snapshot.model.effective = Some(AgentModelRefV1 {
            provider_id: binding.provider,
            model_id: binding.model,
            is_default: false,
        });
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
    let mut entries: Vec<CatalogEntry> = catalog.servers.into_values().collect();
    entries.extend(catalog.shadowed);
    entries.sort_by(|left, right| {
        scope_rank(left.source)
            .cmp(&scope_rank(right.source))
            .then_with(|| left.name.cmp(&right.name))
    });
    entries
        .into_iter()
        .filter(|entry| entry.server.enabled)
        .map(|entry| SessionSetupMcpV1 {
            name: entry.name,
            scope: entry.source.as_str().to_string(),
            enabled: entry.server.enabled,
            shadowed_by: entry.shadowed_by.map(|scope| scope.as_str().to_string()),
            profile: Some(entry.profile).filter(|profile| !profile.is_empty()),
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
    let mut allowed: Vec<AgentModelRefV1> = slot
        .choices
        .iter()
        .filter(|choice| {
            choice.author_suggested
                || slot.default_choice_id.as_deref() == Some(choice.choice_id.as_str())
        })
        .map(|choice| AgentModelRefV1 {
            provider_id: choice.provider_id.clone(),
            model_id: choice.model_id.clone(),
            is_default: slot.default_choice_id.as_deref() == Some(choice.choice_id.as_str()),
        })
        .collect();
    if allowed.is_empty() {
        allowed = slot
            .choices
            .iter()
            .map(|choice| AgentModelRefV1 {
                provider_id: choice.provider_id.clone(),
                model_id: choice.model_id.clone(),
                is_default: slot.default_choice_id.as_deref() == Some(choice.choice_id.as_str()),
            })
            .collect();
    }
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

    fn entry(name: &str, source: McpScope, shadowed_by: Option<McpScope>) -> CatalogEntry {
        let server: crate::mcp::config::ServerConfig = serde_json::from_value(serde_json::json!({
            "transport": "streamable",
            "enabled": true
        }))
        .expect("server");
        CatalogEntry {
            name: name.to_string(),
            server,
            source,
            shadowed_by,
            profile: crate::mcp::resolver::DEFAULT_PROFILE.to_string(),
            agent_bound: source == McpScope::Agent,
        }
    }

    #[test]
    fn setup_mcp_groups_global_then_agent_then_workspace() {
        let mut entries = vec![
            entry("w", McpScope::Workspace, None),
            entry("a", McpScope::Agent, None),
            entry("g", McpScope::Global, None),
            entry("g-shadow", McpScope::Global, Some(McpScope::Workspace)),
        ];
        entries.sort_by(|left, right| {
            scope_rank(left.source)
                .cmp(&scope_rank(right.source))
                .then_with(|| left.name.cmp(&right.name))
        });
        let scopes: Vec<_> = entries.iter().map(|e| e.source.as_str()).collect();
        assert_eq!(scopes, vec!["global", "global", "agent", "workspace"]);
        assert_eq!(entries[1].shadowed_by, Some(McpScope::Workspace));
    }
}
