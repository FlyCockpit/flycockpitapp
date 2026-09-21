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
    AgentCapability, AgentDefinitionFrontmatter, AgentRole, AllowedChild, DelegationPolicy,
    DelegationTarget, GoalSkepticsPolicy, ModelCapability, ModelLocality, ModelSlot,
    SCHEMA_VERSION, SELF_CHILD_REF, SelectorPredicate, SlotModelRef, ToolClass, ToolSteering,
    ToolTier, VerificationAction, VerificationAdjudicator, VerificationPolicy, VerificationRule,
    VerificationSelector, known_tool_names, legal_tool_tiers,
};

/// Risky action surfaces configured independently by agent authoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationSurface {
    ArtifactWrite,
    Command,
    Monty,
}

impl VerificationSurface {
    pub const ALL: [Self; 3] = [Self::ArtifactWrite, Self::Command, Self::Monty];

    pub fn label(self) -> &'static str {
        match self {
            Self::ArtifactWrite => "Writes & edits",
            Self::Command => "Commands",
            Self::Monty => "Monty",
        }
    }
}

/// Copy counts parallel to the projection's model-route catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SurfaceVerificationDraft {
    pub surface: VerificationSurface,
    pub copies: Vec<u8>,
}

impl SurfaceVerificationDraft {
    pub fn is_off(&self) -> bool {
        self.copies.iter().all(|copies| *copies == 0)
    }

    pub fn total_copies(&self) -> u32 {
        self.copies.iter().map(|copies| u32::from(*copies)).sum()
    }
}

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
    /// UI-only model selections for tools that require a dedicated model.
    pub tool_models: BTreeMap<String, usize>,
    pub interactive_subagents: bool,
    pub auto_prune: bool,
    pub max_subagent_recursion: u8,
    pub tool_steering: ToolSteering,
    pub goal_skeptics: GoalSkepticsPolicy,
    pub self_verification: Vec<SurfaceVerificationDraft>,
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
    pub auto_prune: bool,
    pub max_subagent_recursion: u8,
    pub tool_steering: ToolSteering,
    pub goal_skeptics: GoalSkepticsPolicy,
    pub self_verification: Vec<SurfaceVerificationDraft>,
    pub tool_tiers: BTreeMap<String, ToolTier>,
    /// UI-only model selections for tools that require a dedicated model.
    pub tool_models: BTreeMap<String, usize>,
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
            auto_prune: false,
            max_subagent_recursion: 2,
            tool_steering: ToolSteering::Terse,
            goal_skeptics: GoalSkepticsPolicy::Count { count: 2 },
            self_verification: VerificationSurface::ALL
                .into_iter()
                .enumerate()
                .map(|(surface_index, surface)| {
                    let mut copies = vec![0; route_count];
                    if surface_index == 0 && route_count > 0 {
                        copies[0] = 1;
                    }
                    SurfaceVerificationDraft { surface, copies }
                })
                .collect(),
            tool_tiers: default_tool_tiers(),
            tool_models: BTreeMap::new(),
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

/// Keep `default_route_index` aligned with an enabled grant when any exist.
pub fn reconcile_route_grant_default(grants: &[RouteGrantDraft], default_route_index: &mut usize) {
    if grants
        .get(*default_route_index)
        .is_some_and(|grant| grant.enabled)
    {
        return;
    }
    if let Some(index) = grants.iter().position(|grant| grant.enabled) {
        *default_route_index = index;
    }
}

/// Toggle the route grant at `cursor`, updating `default_route_index`.
/// The sole remaining enabled grant cannot be disabled.
pub fn toggle_route_grant_draft(
    grants: &mut [RouteGrantDraft],
    cursor: usize,
    default_route_index: &mut usize,
) {
    let enabled_count = grants.iter().filter(|entry| entry.enabled).count();
    let Some(grant) = grants.get_mut(cursor) else {
        return;
    };
    if grant.enabled && enabled_count <= 1 {
        return;
    }
    let was_default = cursor == *default_route_index;
    grant.enabled = !grant.enabled;
    if !grant.enabled && was_default {
        if let Some(next_default) = grants.iter().position(|entry| entry.enabled) {
            *default_route_index = next_default;
        }
    } else if grant.enabled && grants.iter().filter(|entry| entry.enabled).count() == 1 {
        *default_route_index = cursor;
    }
    reconcile_route_grant_default(grants, default_route_index);
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
    diagnostics: &mut Vec<String>,
) -> BTreeMap<String, ToolTier> {
    let mut preferences = BTreeMap::new();
    for (tool, tier) in tool_tiers {
        let diagnostic = if !known_tool_names().contains(&tool.as_str()) {
            Some(format!("Ignored unknown tool preference `{tool}`."))
        } else if !matches!(*tier, ToolTier::Enabled | ToolTier::Discoverable) {
            None
        } else if !legal_tool_tiers(tool).contains(tier) {
            Some(format!(
                "Ignored illegal tier for tool preference `{tool}`."
            ))
        } else if crate::engine::builtin::author_tool_tier_preference_is_reserved(tool) {
            Some(format!("Ignored reserved tool preference `{tool}`."))
        } else {
            preferences.insert(tool.clone(), *tier);
            None
        };
        if let Some(diagnostic) = diagnostic {
            diagnostics.push(diagnostic);
        }
    }
    preferences
}

fn child_default_tool_tiers() -> BTreeMap<String, ToolTier> {
    let mut tiers = default_tool_tiers();
    for tool in ["search", "schedule", "task"] {
        if legal_tool_tiers(tool).contains(&ToolTier::Enabled) {
            tiers.insert(tool.to_string(), ToolTier::Enabled);
        }
    }
    tiers
}

/// Canonical package plus non-fatal warnings discovered while normalizing an
/// authored draft for preview or apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuiltAuthoredAgentPackageDraft {
    pub package: AuthoredAgentPackageDraft,
    pub diagnostics: Vec<String>,
}

/// Build the wire package draft from local editing state and the pinned projection.
pub fn build_package_draft(
    projection: &AgentAuthoringProjection,
    draft: &AgentAuthoringDraft,
) -> Result<AuthoredAgentPackageDraft> {
    Ok(build_package_draft_with_diagnostics(projection, draft)?.package)
}

/// Build the wire package draft and retain warnings for preferences that were
/// deliberately excluded from the canonical package.
pub fn build_package_draft_with_diagnostics(
    projection: &AgentAuthoringProjection,
    draft: &AgentAuthoringDraft,
) -> Result<BuiltAuthoredAgentPackageDraft> {
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
    let mut diagnostics = Vec::new();
    let frontmatter = build_frontmatter(projection, draft, &name, &mut diagnostics)?;
    let yaml = serde_yaml::to_string(&frontmatter)?;
    let markdown = format!("---\n{}---\n{body}", yaml.trim_start_matches("---\n"));

    let children = collect_child_package_files(projection, &draft.children, &mut diagnostics)?;

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
        crate::agents::PACKAGE_ROOT_FILE,
    );
    append_child_model_trust_confirmations(
        projection,
        &draft.children,
        "",
        &mut model_trust_confirmations,
    );

    Ok(BuiltAuthoredAgentPackageDraft {
        package: AuthoredAgentPackageDraft {
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
        },
        diagnostics,
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
    diagnostics: &mut Vec<String>,
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

    let tool_tier_preferences =
        author_placeable_tool_tier_preferences(&draft.tool_tiers, diagnostics);

    let delegation = {
        let mut allowed_children = draft
            .children
            .iter()
            .map(|child| {
                let slug = child_slug(child);
                AllowedChild::portable_ref(&slug)
            })
            .collect::<Vec<_>>();
        if allowed_children.is_empty() {
            allowed_children.push(AllowedChild::portable_ref(SELF_CHILD_REF));
        }
        Some(DelegationPolicy {
            allowed_children,
            // Definition depth includes the directly delegated child; the UI
            // value counts only subagent-on-subagent recursion.
            max_descendant_depth: Some(u16::from(draft.max_subagent_recursion) + 1),
            max_concurrent_children: Some(3),
            targets: vec![DelegationTarget::SameRoot],
            default_child: Some(
                draft
                    .children
                    .first()
                    .map(child_slug)
                    .unwrap_or_else(|| SELF_CHILD_REF.to_string()),
            ),
            interactive_subagents: draft.interactive_subagents,
        })
    };

    let rules = draft
        .self_verification
        .iter()
        .filter(|surface| !surface.is_off())
        .map(|surface| verification_rule(projection, draft.default_route_index, surface))
        .collect::<Result<Vec<_>>>()?;
    let verification = if !rules.is_empty() || !draft.goal_skeptics.is_off() {
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
        capabilities: if draft.auto_prune {
            [AgentCapability::AutoPrune].into_iter().collect()
        } else {
            Default::default()
        },
        tool_steering: Some(draft.tool_steering),
        context_policy: None,
        mcp_bindings: Vec::new(),
    })
}

fn verification_rule(
    projection: &AgentAuthoringProjection,
    default_route_index: usize,
    surface: &SurfaceVerificationDraft,
) -> Result<VerificationRule> {
    ensure!(
        surface.copies.len() == projection.policy.routes.len(),
        "verification copy counts are stale for the model catalog"
    );
    let mut order = (0..projection.policy.routes.len()).collect::<Vec<_>>();
    order.sort_by_key(|index| usize::from(*index != default_route_index));
    let adjudicators = order
        .into_iter()
        .map(|index| {
            let copies = surface.copies[index];
            let route = &projection.policy.routes[index];
            VerificationAdjudicator {
                model_ref: SlotModelRef {
                    provider_id: route.provider_id.clone(),
                    model_id: route.model_id.clone(),
                    default: index == default_route_index,
                },
                copies,
            }
        })
        .collect();
    let predicate = match surface.surface {
        VerificationSurface::ArtifactWrite => SelectorPredicate::ToolClass {
            tool_class: ToolClass::ArtifactWrite,
        },
        VerificationSurface::Command => SelectorPredicate::ToolClass {
            tool_class: ToolClass::Command,
        },
        VerificationSurface::Monty => SelectorPredicate::ToolClass {
            tool_class: ToolClass::Monty,
        },
    };
    Ok(VerificationRule {
        selector: VerificationSelector {
            all_of: Vec::new(),
            any_of: vec![predicate],
        },
        action: VerificationAction::Verify,
        adjudicators,
        adjudicator_slot: Some("primary".into()),
        ..Default::default()
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
    grant_scope: &str,
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
                grant_scope: grant_scope.to_string(),
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
    parent_prefix: &str,
    out: &mut Vec<ModelTrustConfirmation>,
) {
    for child in children {
        let slug = child_slug(child);
        let grant_scope = if parent_prefix.is_empty() {
            format!("subagents/{slug}.md")
        } else {
            format!("subagents/{parent_prefix}/{slug}.md")
        };
        out.extend(collect_model_trust_confirmations(
            projection,
            &child.route_grants,
            &child.trust_confirmations,
            &grant_scope,
        ));
        let nested_prefix = if parent_prefix.is_empty() {
            slug
        } else {
            format!("{parent_prefix}/{slug}")
        };
        append_child_model_trust_confirmations(projection, &child.children, &nested_prefix, out);
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
    diagnostics: &mut Vec<String>,
) -> Result<Vec<AuthoredAgentChild>> {
    let mut files = Vec::new();
    for child in children {
        files.extend(collect_child_package_files_recursive(
            projection,
            child,
            "",
            diagnostics,
        )?);
    }
    Ok(files)
}

fn collect_child_package_files_recursive(
    projection: &AgentAuthoringProjection,
    child: &ChildAuthoringDraft,
    parent_prefix: &str,
    diagnostics: &mut Vec<String>,
) -> Result<Vec<AuthoredAgentChild>> {
    let (relative_path, markdown) =
        build_child_markdown(projection, child, parent_prefix, diagnostics)?;
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
            diagnostics,
        )?);
    }
    Ok(files)
}

fn build_child_markdown(
    projection: &AgentAuthoringProjection,
    child: &ChildAuthoringDraft,
    parent_prefix: &str,
    diagnostics: &mut Vec<String>,
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
    let tool_tier_preferences =
        author_placeable_tool_tier_preferences(&child.tool_tiers, diagnostics);
    let rules = child
        .self_verification
        .iter()
        .filter(|surface| !surface.is_off())
        .map(|surface| verification_rule(projection, child.default_route_index, surface))
        .collect::<Result<Vec<_>>>()?;
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
        delegation: {
            let mut allowed_children = child
                .children
                .iter()
                .map(|nested| AllowedChild::portable_ref(&child_slug(nested)))
                .collect::<Vec<_>>();
            if allowed_children.is_empty() {
                allowed_children.push(AllowedChild::portable_ref(SELF_CHILD_REF));
            }
            Some(DelegationPolicy {
                allowed_children,
                max_descendant_depth: Some(u16::from(child.max_subagent_recursion) + 1),
                max_concurrent_children: Some(3),
                targets: vec![DelegationTarget::SameRoot],
                default_child: Some(
                    child
                        .children
                        .first()
                        .map(child_slug)
                        .unwrap_or_else(|| SELF_CHILD_REF.to_string()),
                ),
                interactive_subagents: child.interactive_subagents,
            })
        },
        questions: None,
        verification: if rules.is_empty() && child.goal_skeptics.is_off() {
            None
        } else {
            Some(VerificationPolicy {
                rules,
                goal_skeptics: child.goal_skeptics,
            })
        },
        allowed_knowledge_bases: None,
        tool_tier_preferences,
        requested_network_hosts: Default::default(),
        requests_requested: false,
        description: name.clone(),
        capabilities: if child.auto_prune {
            [AgentCapability::AutoPrune].into_iter().collect()
        } else {
            Default::default()
        },
        tool_steering: Some(child.tool_steering),
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
        tool_models: BTreeMap::new(),
        interactive_subagents: true,
        auto_prune: false,
        max_subagent_recursion: 2,
        tool_steering: ToolSteering::Terse,
        goal_skeptics: GoalSkepticsPolicy::Count { count: 2 },
        self_verification: VerificationSurface::ALL
            .into_iter()
            .enumerate()
            .map(|(surface_index, surface)| {
                let mut copies = vec![0; route_count];
                if surface_index == 0 && route_count > 0 {
                    copies[0] = 1;
                }
                SurfaceVerificationDraft { surface, copies }
            })
            .collect(),
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
    fn prepared_runner_child_markdown_loads_as_workspace_package() {
        let projection = sample_projection();
        let mut child = default_child_draft(&projection);
        child.trust_confirmations[0] = true;
        let mut diagnostics = Vec::new();
        let (_path, markdown) =
            build_child_markdown(&projection, &child, "", &mut diagnostics).unwrap();
        assert!(
            diagnostics.is_empty(),
            "runner defaults must need no repair"
        );
        let files = BTreeMap::from([(
            crate::agents::PACKAGE_ROOT_FILE.to_string(),
            markdown.into_bytes(),
        )]);
        crate::agents::load_workspace_package_from_files("runner", files).unwrap();
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
    fn child_default_tool_tiers_only_contain_registered_tools() {
        for tool in child_default_tool_tiers().keys() {
            assert!(
                known_tool_names().contains(&tool.as_str()),
                "child default `{tool}` must be a registered tool"
            );
        }
    }

    #[test]
    fn unknown_user_tool_preference_warns_and_is_dropped() {
        let projection = sample_projection();
        let mut draft = AgentAuthoringDraft::from_projection(&projection);
        draft.trust_confirmations[0] = true;
        draft.children.clear();
        draft
            .tool_tiers
            .insert("misspelled_tool".into(), ToolTier::Enabled);

        let built = build_package_draft_with_diagnostics(&projection, &draft).unwrap();
        assert!(
            !built.package.markdown.contains("misspelled_tool"),
            "unknown preferences must not enter the canonical package"
        );
        assert_eq!(
            built.diagnostics,
            vec!["Ignored unknown tool preference `misspelled_tool`."],
            "the user-authored typo must remain visible as a warning"
        );
    }

    #[test]
    fn default_tool_preferences_need_no_diagnostics() {
        let projection = sample_projection();
        let mut draft = AgentAuthoringDraft::from_projection(&projection);
        draft.trust_confirmations[0] = true;
        let mut child = default_child_draft(&projection);
        child.trust_confirmations[0] = true;
        draft.children = vec![child];

        let built = build_package_draft_with_diagnostics(&projection, &draft).unwrap();
        assert!(
            built.diagnostics.is_empty(),
            "hardcoded defaults must not be silently repaired"
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

    #[test]
    fn authoring_draft_emits_seven_optimization_values_and_surface_copies() {
        let projection = sample_projection();
        let mut draft = AgentAuthoringDraft::from_projection(&projection);
        draft.trust_confirmations[0] = true;
        draft.route_grants[1].enabled = true;
        draft.default_route_index = 1;
        draft.auto_prune = true;
        draft.interactive_subagents = false;
        draft.max_subagent_recursion = 4;
        draft.tool_steering = ToolSteering::Verbose;
        draft.goal_skeptics = GoalSkepticsPolicy::Count { count: 3 };
        draft.self_verification[0].copies = vec![2, 1];
        draft.self_verification[1].copies = vec![0, 3];
        draft.self_verification[2].copies = vec![1, 0];
        let mut child = default_child_draft(&projection);
        child.trust_confirmations[0] = true;
        draft.children = vec![child];
        draft.make_default = false;

        let package = build_package_draft(&projection, &draft).unwrap();
        assert!(!package.make_default);
        let yaml = package
            .markdown
            .strip_prefix("---\n")
            .unwrap()
            .split_once("---\n")
            .unwrap()
            .0;
        let frontmatter: AgentDefinitionFrontmatter = serde_yaml::from_str(yaml).unwrap();
        assert!(
            frontmatter
                .capabilities
                .contains(&AgentCapability::AutoPrune)
        );
        assert_eq!(frontmatter.tool_steering, Some(ToolSteering::Verbose));
        let delegation = frontmatter.delegation.unwrap();
        assert!(!delegation.interactive_subagents);
        assert_eq!(delegation.max_descendant_depth, Some(5));
        let verification = frontmatter.verification.unwrap();
        assert_eq!(
            verification.goal_skeptics,
            GoalSkepticsPolicy::Count { count: 3 }
        );
        assert_eq!(verification.rules.len(), 3);
        assert_eq!(
            verification.rules[0].adjudicators[0].model_ref.model_id,
            "exact-b"
        );
        assert_eq!(verification.rules[0].adjudicators[0].copies, 1);
        assert_eq!(verification.rules[0].adjudicators[1].copies, 2);
        assert_eq!(verification.rules[1].adjudicators[0].copies, 3);
        assert_eq!(verification.rules[2].adjudicators[0].copies, 0);
        assert_eq!(verification.rules[2].adjudicators[1].copies, 1);
    }

    #[test]
    fn surface_is_off_only_when_every_copy_count_is_zero() {
        let mut surface = SurfaceVerificationDraft {
            surface: VerificationSurface::Command,
            copies: vec![0, 0, 0],
        };
        assert!(surface.is_off());
        surface.copies[2] = 1;
        assert!(!surface.is_off());
        surface.copies[2] = 0;
        assert!(surface.is_off());
    }

    #[test]
    fn all_zero_surface_emits_no_verification_rule() {
        let projection = sample_projection();
        let mut draft = AgentAuthoringDraft::from_projection(&projection);
        draft.trust_confirmations[0] = true;
        draft.self_verification[1].copies.fill(0);
        let package = build_package_draft(&projection, &draft).unwrap();
        let yaml = package
            .markdown
            .strip_prefix("---\n")
            .unwrap()
            .split_once("---\n")
            .unwrap()
            .0;
        let frontmatter: AgentDefinitionFrontmatter = serde_yaml::from_str(yaml).unwrap();
        let verification = frontmatter
            .verification
            .expect("default writes rule remains");
        assert_eq!(verification.rules.len(), 1);
        assert_eq!(
            verification.rules[0].selector.any_of,
            vec![SelectorPredicate::ToolClass {
                tool_class: ToolClass::ArtifactWrite
            }]
        );
    }

    #[test]
    fn toggle_route_grant_draft_replaces_disabled_default() {
        let mut grants = vec![
            RouteGrantDraft { enabled: true },
            RouteGrantDraft { enabled: true },
        ];
        let mut default_route_index = 0;
        toggle_route_grant_draft(&mut grants, 0, &mut default_route_index);
        assert!(!grants[0].enabled);
        assert!(grants[1].enabled);
        assert_eq!(default_route_index, 1);
    }

    #[test]
    fn toggle_route_grant_draft_refuses_disabling_sole_enabled_grant() {
        let mut grants = vec![
            RouteGrantDraft { enabled: true },
            RouteGrantDraft { enabled: false },
        ];
        let mut default_route_index = 0;
        toggle_route_grant_draft(&mut grants, 0, &mut default_route_index);
        assert!(grants[0].enabled);
        assert_eq!(default_route_index, 0);
    }
}
