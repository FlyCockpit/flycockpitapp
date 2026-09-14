//! TUI-facing agent authoring draft and canonical package construction.
//!
//! The onboarding agent editor accumulates an [`AgentAuthoringDraft`] against a
//! daemon [`AgentAuthoringProjection`]. [`build_package_draft`] is the only
//! supported path from that local state into an [`AuthoredAgentPackageDraft`];
//! the TUI never hand-assembles markdown or config files.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail, ensure};
use cockpit_proto::{
    AGENT_AUTHORING_DTO_VERSION, AgentAuthoringProjection, AgentAuthoringSourceKind,
    AuthoredAgentChild, AuthoredAgentPackageDraft, AuthoredAgentSource, AuthoredSidecarDeclaration,
    ModelTrustConfirmation,
};

use crate::agents::{
    AgentDefinitionFrontmatter, AgentRole, AllowedChild, DelegationPolicy, DelegationTarget,
    GoalSkepticsPolicy, ModelCapability, ModelLocality, ModelSlot, SCHEMA_VERSION,
    SelectorPredicate, SlotModelRef, ToolClass, ToolTier, VerificationAction, VerificationPolicy,
    VerificationRule, VerificationSelector, known_tool_names, legal_tool_tiers,
};

/// How the user chose the agent identity/source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceSelection {
    /// A catalog row from [`AgentAuthoringProjection::sources`].
    Catalog,
    /// Free-form authored name (no catalog template).
    Authored,
    /// Third-party pinned source locator.
    ThirdParty,
}

/// Per-route grant toggle aligned with [`AgentAuthoringProjection::policy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteGrantDraft {
    pub enabled: bool,
}

/// Nested subagent draft edited on the subagent stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildAuthoringDraft {
    pub name: String,
    pub route_grants: Vec<RouteGrantDraft>,
    pub default_route_index: usize,
    pub trust_confirmations: Vec<bool>,
    pub tool_tiers: BTreeMap<String, ToolTier>,
    pub children: Vec<ChildAuthoringDraft>,
}

/// Editable agent authoring state for the onboarding TUI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentAuthoringDraft {
    pub name: String,
    pub source_selection: SourceSelection,
    /// Index into `projection.sources` when [`source_selection`] is `Catalog`.
    pub source_index: usize,
    pub third_party_locator: String,
    pub third_party_trust_confirmed: bool,
    pub route_grants: Vec<RouteGrantDraft>,
    pub default_route_index: usize,
    /// Parallel to enabled grants that require confirmation.
    pub trust_confirmations: Vec<bool>,
    pub interactive_subagents: bool,
    pub goal_skeptics: GoalSkepticsPolicy,
    pub verification_enabled: bool,
    pub tool_tiers: BTreeMap<String, ToolTier>,
    pub children: Vec<ChildAuthoringDraft>,
    pub sidecar_route_index: Option<usize>,
    pub sidecar_egress_confirmed: bool,
    pub make_default: bool,
}

impl AgentAuthoringDraft {
    /// Construct defaults from the authoritative projection.
    pub fn from_projection(projection: &AgentAuthoringProjection) -> Self {
        let route_count = projection.policy.routes.len();
        let mut route_grants = vec![RouteGrantDraft { enabled: false }];
        route_grants.resize(route_count, RouteGrantDraft { enabled: false });
        if route_count > 0 {
            route_grants[0].enabled = true;
        }
        let source_index = projection
            .sources
            .iter()
            .position(|source| source.kind == AgentAuthoringSourceKind::BundledFrontier)
            .unwrap_or(0);
        let catalog_name = projection
            .sources
            .get(source_index)
            .and_then(|source| source.slug.clone())
            .unwrap_or_else(|| "pilot".to_string());
        Self {
            name: catalog_name,
            source_selection: if projection.sources.is_empty() {
                SourceSelection::Authored
            } else {
                SourceSelection::Catalog
            },
            source_index,
            third_party_locator: String::new(),
            third_party_trust_confirmed: false,
            route_grants,
            default_route_index: 0,
            trust_confirmations: vec![false; route_count],
            interactive_subagents: true,
            goal_skeptics: GoalSkepticsPolicy::Count { count: 2 },
            verification_enabled: true,
            tool_tiers: default_tool_tiers(),
            children: Vec::new(),
            sidecar_route_index: preferred_sidecar_route_index(projection),
            sidecar_egress_confirmed: false,
            make_default: true,
        }
    }

    /// Routes that require an explicit trust confirmation before apply.
    pub fn pending_trust_route_indices(&self, projection: &AgentAuthoringProjection) -> Vec<usize> {
        self.route_grants
            .iter()
            .enumerate()
            .filter_map(|(index, grant)| {
                if !grant.enabled {
                    return None;
                }
                let route = projection.policy.routes.get(index)?;
                if route.confirmation_required
                    && !self
                        .trust_confirmations
                        .get(index)
                        .copied()
                        .unwrap_or(false)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }

    pub fn enabled_route_count(&self) -> usize {
        self.route_grants
            .iter()
            .filter(|grant| grant.enabled)
            .count()
    }
}

impl ChildAuthoringDraft {
    pub fn pending_trust_route_indices(&self, projection: &AgentAuthoringProjection) -> Vec<usize> {
        self.route_grants
            .iter()
            .enumerate()
            .filter_map(|(index, grant)| {
                if !grant.enabled {
                    return None;
                }
                let route = projection.policy.routes.get(index)?;
                if route.confirmation_required
                    && !self
                        .trust_confirmations
                        .get(index)
                        .copied()
                        .unwrap_or(false)
                {
                    Some(index)
                } else {
                    None
                }
            })
            .collect()
    }
}

fn preferred_sidecar_route_index(projection: &AgentAuthoringProjection) -> Option<usize> {
    projection
        .policy
        .routes
        .iter()
        .position(|route| route.sidecar_eligible && !route.remote_sidecar_egress_required)
}

fn default_tool_tiers() -> BTreeMap<String, ToolTier> {
    let mut tiers = BTreeMap::new();
    for tool in known_tool_names() {
        let legal = legal_tool_tiers(tool);
        let tier = if crate::engine::builtin::author_tool_tier_preference_is_reserved(tool) {
            // Host-owned placement tools must not appear in toolTierPreferences.
            ToolTier::Disabled
        } else if crate::agents::is_safety_tool(tool) {
            ToolTier::Enabled
        } else if legal.len() == 2 {
            ToolTier::Enabled
        } else {
            ToolTier::Disabled
        };
        tiers.insert(tool.to_string(), tier);
    }
    tiers
}

fn author_placeable_tool_tier_preferences(
    tool_tiers: &BTreeMap<String, ToolTier>,
) -> BTreeMap<String, ToolTier> {
    tool_tiers
        .iter()
        .filter(|(tool, tier)| {
            matches!(*tier, ToolTier::Enabled | ToolTier::Discoverable)
                && !crate::engine::builtin::author_tool_tier_preference_is_reserved(tool)
        })
        .map(|(tool, tier)| (tool.clone(), *tier))
        .collect()
}

fn child_default_tool_tiers() -> BTreeMap<String, ToolTier> {
    let mut tiers = default_tool_tiers();
    for tool in ["search", "timer", "background", "task"] {
        if legal_tool_tiers(tool).contains(&ToolTier::Enabled) {
            tiers.insert(tool.to_string(), ToolTier::Enabled);
        }
    }
    tiers
}

/// Build the wire package draft from local editing state and the pinned projection.
pub fn build_package_draft(
    projection: &AgentAuthoringProjection,
    draft: &AgentAuthoringDraft,
) -> Result<AuthoredAgentPackageDraft> {
    ensure!(
        projection.dto_version == AGENT_AUTHORING_DTO_VERSION,
        "unsupported agent authoring projection DTO version"
    );
    let enabled: Vec<usize> = draft
        .route_grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| grant.enabled.then_some(index))
        .collect();
    ensure!(!enabled.is_empty(), "at least one model grant is required");
    ensure!(
        enabled.contains(&draft.default_route_index),
        "default model must be an enabled grant"
    );
    for index in draft.pending_trust_route_indices(projection) {
        let route = &projection.policy.routes[index];
        bail!(
            "model trust confirmation is required for {}/{}",
            route.provider_id,
            route.model_id
        );
    }
    if draft.source_selection == SourceSelection::ThirdParty && !draft.third_party_trust_confirmed {
        bail!("third-party publisher trust confirmation is required");
    }
    if let Some(index) = draft.sidecar_route_index {
        let route = projection
            .policy
            .routes
            .get(index)
            .context("sidecar route index out of range")?;
        if route.remote_sidecar_egress_required && !draft.sidecar_egress_confirmed {
            bail!("remote sidecar egress confirmation is required");
        }
    }
    validate_child_tree(&draft.children, projection, 1)?;

    let (source, name, body) = resolve_source(projection, draft)?;
    validate_authored_agent_name(&name)?;
    let frontmatter = build_frontmatter(projection, draft, &name)?;
    let yaml = serde_yaml::to_string(&frontmatter)?;
    let markdown = format!("---\n{}---\n{body}", yaml.trim_start_matches("---\n"));

    let children = collect_child_package_files(projection, &draft.children)?;

    let sidecars = draft
        .sidecar_route_index
        .map(|index| {
            let route = &projection.policy.routes[index];
            vec![AuthoredSidecarDeclaration {
                provider_id: route.provider_id.clone(),
                model_id: route.model_id.clone(),
                remote_image_egress_confirmed: draft.sidecar_egress_confirmed
                    || !route.remote_sidecar_egress_required,
            }]
        })
        .unwrap_or_default();

    let mut model_trust_confirmations = collect_model_trust_confirmations(
        projection,
        &draft.route_grants,
        &draft.trust_confirmations,
    );
    append_child_model_trust_confirmations(
        projection,
        &draft.children,
        &mut model_trust_confirmations,
    );

    Ok(AuthoredAgentPackageDraft {
        dto_version: AGENT_AUTHORING_DTO_VERSION,
        name,
        markdown,
        source,
        children,
        mcp_json: None,
        sidecars,
        policy_revision: projection.policy.policy_revision.clone(),
        model_trust_confirmations,
        make_default: draft.make_default,
        draft_revision: None,
    })
}

fn resolve_source(
    projection: &AgentAuthoringProjection,
    draft: &AgentAuthoringDraft,
) -> Result<(AuthoredAgentSource, String, String)> {
    match draft.source_selection {
        SourceSelection::Catalog => {
            let source = projection
                .sources
                .get(draft.source_index)
                .context("catalog source index out of range")?;
            let locator = source
                .source_locator
                .clone()
                .context("catalog source is missing a locator")?;
            let name = draft.name.trim();
            let name = if name.is_empty() {
                source.slug.clone().unwrap_or_else(|| "pilot".to_string())
            } else {
                name.to_string()
            };
            let body = format!("You are the `{name}` Cockpit agent.\n");
            Ok((
                AuthoredAgentSource {
                    kind: source.kind,
                    source_locator: locator,
                    pin: None,
                    third_party_trust_confirmed: false,
                },
                name,
                body,
            ))
        }
        SourceSelection::Authored => {
            let name = draft.name.trim();
            let name = if name.is_empty() {
                "pilot".to_string()
            } else {
                name.to_string()
            };
            let body = format!("You are the `{name}` Cockpit agent.\n");
            Ok((
                AuthoredAgentSource {
                    kind: AgentAuthoringSourceKind::Authored,
                    source_locator: format!("authored/{name}"),
                    pin: None,
                    third_party_trust_confirmed: false,
                },
                name,
                body,
            ))
        }
        SourceSelection::ThirdParty => {
            let locator = draft.third_party_locator.trim();
            ensure!(
                !locator.is_empty(),
                "third-party source locator is required"
            );
            let parsed = crate::daemon::agent_installation::CanonicalAgentSource::parse(locator)?;
            let agent_name = parsed.agent_name()?.to_string();
            let body = format!("You are the `{agent_name}` Cockpit agent.\n");
            Ok((
                AuthoredAgentSource {
                    kind: AgentAuthoringSourceKind::ThirdParty,
                    source_locator: locator.to_string(),
                    pin: parsed.requested_revision.clone(),
                    third_party_trust_confirmed: draft.third_party_trust_confirmed,
                },
                agent_name,
                body,
            ))
        }
    }
}

fn build_frontmatter(
    projection: &AgentAuthoringProjection,
    draft: &AgentAuthoringDraft,
    name: &str,
) -> Result<AgentDefinitionFrontmatter> {
    let models = draft
        .route_grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| {
            if !grant.enabled {
                return None;
            }
            let route = projection.policy.routes.get(index)?;
            Some(SlotModelRef {
                provider_id: route.provider_id.clone(),
                model_id: route.model_id.clone(),
                default: index == draft.default_route_index,
            })
        })
        .collect::<Vec<_>>();

    let tool_tier_preferences = author_placeable_tool_tier_preferences(&draft.tool_tiers);

    let delegation = if draft.children.is_empty() {
        None
    } else {
        let allowed_children = draft
            .children
            .iter()
            .map(|child| {
                let slug = child_slug(child);
                AllowedChild::portable_ref(&slug)
            })
            .collect::<Vec<_>>();
        Some(DelegationPolicy {
            allowed_children,
            max_descendant_depth: Some(2),
            max_concurrent_children: Some(3),
            targets: vec![DelegationTarget::SameRoot],
            default_child: draft.children.first().map(|child| child_slug(child)),
            interactive_subagents: draft.interactive_subagents,
        })
    };

    let verification = if draft.verification_enabled || !draft.goal_skeptics.is_off() {
        let mut rules = Vec::new();
        if draft.verification_enabled {
            rules.push(VerificationRule {
                selector: VerificationSelector {
                    all_of: vec![],
                    any_of: vec![SelectorPredicate::ToolClass {
                        tool_class: ToolClass::ArtifactWrite,
                    }],
                },
                action: VerificationAction::Verify,
                adjudicator_slot: Some("primary".into()),
                ..Default::default()
            });
        }
        Some(VerificationPolicy {
            rules,
            goal_skeptics: draft.goal_skeptics,
        })
    } else {
        None
    };

    Ok(AgentDefinitionFrontmatter {
        schema_version: SCHEMA_VERSION,
        agent_id: format!("authored/{name}"),
        roles: vec![AgentRole::Code],
        model_slots: BTreeMap::from([(
            "primary".into(),
            ModelSlot {
                purpose: "Primary model".into(),
                min_context_tokens: 1_u64,
                required_capabilities: vec![ModelCapability::TextGeneration],
                locality: ModelLocality::Any,
                allow_default_fallback: false,
                suggested_models: Vec::new(),
                models,
            },
        )]),
        delegation,
        questions: None,
        verification,
        allowed_knowledge_bases: None,
        tool_tier_preferences,
        requested_network_hosts: Default::default(),
        requests_requested: false,
        description: name.to_string(),
        capabilities: Default::default(),
        tool_steering: None,
        context_policy: None,
        mcp_bindings: Vec::new(),
    })
}

fn validate_authored_agent_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && !name.contains('/')
            && !name.contains('\\')
            && !name.contains('.')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "authored agent name must be ASCII alphanumeric with '-' or '_' only"
    );
    Ok(())
}

const AUTHORED_MAX_DESCENDANT_DEPTH: u16 = 2;

fn collect_model_trust_confirmations(
    projection: &AgentAuthoringProjection,
    route_grants: &[RouteGrantDraft],
    trust_confirmations: &[bool],
) -> Vec<ModelTrustConfirmation> {
    route_grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| {
            if !grant.enabled {
                return None;
            }
            let route = projection.policy.routes.get(index)?;
            if !route.confirmation_required {
                return None;
            }
            Some(ModelTrustConfirmation {
                provider_id: route.provider_id.clone(),
                model_id: route.model_id.clone(),
                confirmed: trust_confirmations.get(index).copied().unwrap_or(false),
            })
        })
        .collect()
}

fn append_child_model_trust_confirmations(
    projection: &AgentAuthoringProjection,
    children: &[ChildAuthoringDraft],
    out: &mut Vec<ModelTrustConfirmation>,
) {
    for child in children {
        out.extend(collect_model_trust_confirmations(
            projection,
            &child.route_grants,
            &child.trust_confirmations,
        ));
        append_child_model_trust_confirmations(projection, &child.children, out);
    }
}

fn validate_child_tree(
    children: &[ChildAuthoringDraft],
    projection: &AgentAuthoringProjection,
    depth: u16,
) -> Result<()> {
    ensure!(
        depth <= AUTHORED_MAX_DESCENDANT_DEPTH,
        "subagent tree exceeds the canonical max descendant depth of {AUTHORED_MAX_DESCENDANT_DEPTH}"
    );
    let mut seen = std::collections::BTreeSet::new();
    for child in children {
        let slug = child_slug(child);
        ensure!(seen.insert(slug.clone()), "duplicate child name `{slug}`");
        validate_authored_agent_name(&slug)?;
        for index in child.pending_trust_route_indices(projection) {
            let route = &projection.policy.routes[index];
            bail!(
                "model trust confirmation is required for subagent `{slug}` route {}/{}",
                route.provider_id,
                route.model_id
            );
        }
        validate_child_tree(&child.children, projection, depth.saturating_add(1))?;
    }
    Ok(())
}

fn collect_child_package_files(
    projection: &AgentAuthoringProjection,
    children: &[ChildAuthoringDraft],
) -> Result<Vec<AuthoredAgentChild>> {
    let mut files = Vec::new();
    for child in children {
        files.extend(collect_child_package_files_recursive(
            projection, child, "",
        )?);
    }
    Ok(files)
}

fn collect_child_package_files_recursive(
    projection: &AgentAuthoringProjection,
    child: &ChildAuthoringDraft,
    parent_prefix: &str,
) -> Result<Vec<AuthoredAgentChild>> {
    let (relative_path, markdown) = build_child_markdown(projection, child, parent_prefix)?;
    let mut files = vec![AuthoredAgentChild {
        relative_path,
        markdown,
    }];
    let slug = child_slug(child);
    let nested_prefix = if parent_prefix.is_empty() {
        slug
    } else {
        format!("{parent_prefix}/{slug}")
    };
    for nested in &child.children {
        files.extend(collect_child_package_files_recursive(
            projection,
            nested,
            &nested_prefix,
        )?);
    }
    Ok(files)
}

fn build_child_markdown(
    projection: &AgentAuthoringProjection,
    child: &ChildAuthoringDraft,
    parent_prefix: &str,
) -> Result<(String, String)> {
    let name = child_slug(child);
    let relative_path = if parent_prefix.is_empty() {
        format!("subagents/{name}.md")
    } else {
        format!("subagents/{parent_prefix}/{name}.md")
    };
    let models = child
        .route_grants
        .iter()
        .enumerate()
        .filter_map(|(index, grant)| {
            if !grant.enabled {
                return None;
            }
            let route = projection.policy.routes.get(index)?;
            Some(SlotModelRef {
                provider_id: route.provider_id.clone(),
                model_id: route.model_id.clone(),
                default: index == child.default_route_index,
            })
        })
        .collect::<Vec<_>>();
    ensure!(
        !models.is_empty(),
        "subagent `{name}` requires a model grant"
    );
    let tool_tier_preferences = author_placeable_tool_tier_preferences(&child.tool_tiers);
    let frontmatter = AgentDefinitionFrontmatter {
        schema_version: SCHEMA_VERSION,
        agent_id: format!("authored/{name}"),
        roles: vec![AgentRole::Code],
        model_slots: BTreeMap::from([(
            "primary".into(),
            ModelSlot {
                purpose: "Primary model".into(),
                min_context_tokens: 1_u64,
                required_capabilities: vec![ModelCapability::TextGeneration],
                locality: ModelLocality::Any,
                allow_default_fallback: false,
                suggested_models: Vec::new(),
                models,
            },
        )]),
        delegation: if child.children.is_empty() {
            None
        } else {
            let allowed_children = child
                .children
                .iter()
                .map(|nested| AllowedChild::portable_ref(&child_slug(nested)))
                .collect();
            Some(DelegationPolicy {
                allowed_children,
                max_descendant_depth: Some(2),
                max_concurrent_children: Some(3),
                targets: vec![DelegationTarget::SameRoot],
                default_child: child.children.first().map(|nested| child_slug(nested)),
                interactive_subagents: false,
            })
        },
        questions: None,
        verification: None,
        allowed_knowledge_bases: None,
        tool_tier_preferences,
        requested_network_hosts: Default::default(),
        requests_requested: false,
        description: name.clone(),
        capabilities: Default::default(),
        tool_steering: None,
        context_policy: None,
        mcp_bindings: Vec::new(),
    };
    let yaml = serde_yaml::to_string(&frontmatter)?;
    let markdown = format!(
        "---\n{}---\nYou are the `{name}` subagent.\n",
        yaml.trim_start_matches("---\n")
    );
    Ok((relative_path, markdown))
}

fn child_slug(child: &ChildAuthoringDraft) -> String {
    let trimmed = child.name.trim();
    if trimmed.is_empty() {
        "unnamed".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Construct a fresh nested subagent draft with runner-like defaults.
pub fn default_child_draft(projection: &AgentAuthoringProjection) -> ChildAuthoringDraft {
    let route_count = projection.policy.routes.len();
    let mut route_grants = vec![RouteGrantDraft { enabled: false }];
    route_grants.resize(route_count, RouteGrantDraft { enabled: false });
    if route_count > 0 {
        route_grants[0].enabled = true;
    }
    ChildAuthoringDraft {
        name: "runner".to_string(),
        route_grants,
        default_route_index: 0,
        trust_confirmations: vec![false; route_count],
        tool_tiers: child_default_tool_tiers(),
        children: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::{
        AgentAuthoringCatalogOrigin, AgentAuthoringCompatibleRoute, AgentAuthoringSource,
        AgentAuthoringSourceKind, AgentPolicyRoute, AgentPolicySnapshot,
        AgentPolicyTrustClassification,
    };

    fn sample_projection() -> AgentAuthoringProjection {
        AgentAuthoringProjection {
            dto_version: AGENT_AUTHORING_DTO_VERSION,
            policy: AgentPolicySnapshot {
                policy_revision: "rev-test".into(),
                routes: vec![
                    AgentPolicyRoute {
                        provider_id: "vendor".into(),
                        model_id: "exact-a".into(),
                        trust: AgentPolicyTrustClassification::Unset,
                        confirmation_required: true,
                        trust_is_shared: true,
                        capabilities: vec!["text_generation".into()],
                        location: Some("remote".into()),
                        auto_prune: false,
                        sidecar_eligible: false,
                        remote_sidecar_egress_required: false,
                    },
                    AgentPolicyRoute {
                        provider_id: "vendor".into(),
                        model_id: "exact-b".into(),
                        trust: AgentPolicyTrustClassification::Trusted,
                        confirmation_required: false,
                        trust_is_shared: true,
                        capabilities: vec!["text_generation".into()],
                        location: Some("remote".into()),
                        auto_prune: false,
                        sidecar_eligible: true,
                        remote_sidecar_egress_required: true,
                    },
                ],
                catalog_origin: AgentAuthoringCatalogOrigin::Cached,
                catalog_revision: "catalog-rev".into(),
                bundled_frontier_slug: "frontier".into(),
            },
            sources: vec![AgentAuthoringSource {
                kind: AgentAuthoringSourceKind::BundledFrontier,
                slug: Some("frontier".into()),
                display_name: "Frontier".into(),
                source_locator: Some("catalog/frontier@rev".into()),
                compatible_routes: vec![AgentAuthoringCompatibleRoute {
                    provider_id: "vendor".into(),
                    model_id: "exact-a".into(),
                }],
                definition_frontmatter_yaml: None,
            }],
            review_trust_disclosure: "shared trust".into(),
        }
    }

    #[test]
    fn build_package_draft_requires_trust_confirmation() {
        let projection = sample_projection();
        let draft = AgentAuthoringDraft::from_projection(&projection);
        let err = build_package_draft(&projection, &draft).unwrap_err();
        assert!(err.to_string().contains("trust confirmation"));
    }

    #[test]
    fn build_package_draft_omits_host_placement_tool_tier_preferences() {
        let projection = sample_projection();
        let mut draft = AgentAuthoringDraft::from_projection(&projection);
        draft.trust_confirmations[0] = true;
        let package = build_package_draft(&projection, &draft).unwrap();
        assert!(
            !package.markdown.contains("extract_audio:"),
            "host-placement tools must not be written into toolTierPreferences"
        );
    }

    #[test]
    fn build_package_draft_emits_enabled_grants_and_default() {
        let projection = sample_projection();
        let mut draft = AgentAuthoringDraft::from_projection(&projection);
        draft.trust_confirmations[0] = true;
        draft.route_grants[1].enabled = true;
        draft.default_route_index = 1;
        let package = build_package_draft(&projection, &draft).unwrap();
        assert_eq!(package.policy_revision, "rev-test");
        assert!(package.make_default);
        assert!(package.markdown.contains("exact-b"));
    }
}
