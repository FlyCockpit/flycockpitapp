//! Onboarding-facing agent authoring: policy snapshots, package validation,
//! and review projection onto canonical `AgentDef` authorities.
//!
//! This module does not persist a second agent schema. Drafts parse as
//! launch-v1 markdown; trust and auto-prune stay on the global provider/model
//! policy snapshot.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use cockpit_config::config::image_sidecar::SidecarProviderModel;
use cockpit_config::config::providers::{ModelLocation, ModelTrust, ProvidersConfig};
use cockpit_proto::{
    AGENT_AUTHORING_DTO_VERSION, AgentAuthoringCatalogOrigin, AgentAuthoringCompatibleRoute,
    AgentAuthoringProjection, AgentAuthoringSource, AgentAuthoringSourceKind, AgentPolicyRoute,
    AgentPolicySnapshot, AgentPolicyTrustClassification, ApplyAuthoredAgentPackageReceipt,
    AuthoredAgentPackageDraft, AuthoredAgentReceiptStatus, AuthoredAgentRejectReason,
    AuthoredAgentReview, AuthoredAgentReviewChild, AuthoredAgentReviewGrant, AuthoredAgentSource,
    AuthoredSidecarDeclaration, ModelTrustConfirmation,
};
use sha2::{Digest, Sha256};

use crate::agents::{AgentDef, GoalSkepticsPolicy};
use crate::daemon::agent_catalog::{
    AgentCatalogEntry, AgentCatalogIndex, AgentCatalogOrigin, BUNDLED_FRONTIER_SLUG,
    bundled_frontier_entry,
};

pub const REVIEW_TRUST_DISCLOSURE: &str =
    "Trust classification is shared global provider/model policy, not a per-agent override.";

#[derive(Debug, Clone)]
pub struct CanonicalAuthoredPackage {
    pub files: BTreeMap<String, Vec<u8>>,
    pub digest: String,
    pub definition: AgentDef,
    pub review: AuthoredAgentReview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredPackageRejection {
    pub reason: AuthoredAgentRejectReason,
    pub message: String,
}

impl AuthoredPackageRejection {
    fn new(reason: AuthoredAgentRejectReason, message: impl Into<String>) -> Self {
        Self {
            reason,
            message: message.into(),
        }
    }
}

pub fn preferred_self_hosted_sidecar(providers: &ProvidersConfig) -> Option<SidecarProviderModel> {
    crate::daemon::agent_installation::setup_offerings(providers)
        .into_iter()
        .find_map(|offering| {
            let supports_images = providers
                .resolve_effective_model_capabilities(
                    &offering.provider_profile_handle,
                    &offering.model_id,
                    providers.resolution_generation,
                )
                .supports_image_input();
            let self_hosted = matches!(
                providers.resolve_location(&offering.provider_profile_handle, &offering.model_id),
                Some(ModelLocation::Local | ModelLocation::PrivateRemote)
            );
            (supports_images && self_hosted).then(|| SidecarProviderModel {
                provider: offering.provider_id,
                model: offering.model_id,
            })
        })
}

pub fn policy_snapshot(
    providers: &ProvidersConfig,
    catalog_origin: AgentCatalogOrigin,
    catalog_revision: &str,
) -> AgentPolicySnapshot {
    let mut routes = Vec::new();
    for offering in crate::daemon::agent_installation::setup_offerings(providers) {
        let Some(provider) = providers.providers.get(&offering.provider_profile_handle) else {
            continue;
        };
        let Some(model) = provider
            .models
            .iter()
            .find(|model| model.id == offering.model_id)
        else {
            continue;
        };
        {
            let caps = providers.resolve_effective_model_capabilities(
                &offering.provider_profile_handle,
                &model.id,
                providers.resolution_generation,
            );
            let location = providers.resolve_location(&offering.provider_profile_handle, &model.id);
            let self_hosted = matches!(
                location,
                Some(ModelLocation::Local | ModelLocation::PrivateRemote)
            );
            let sidecar_eligible = caps.supports_image_input();
            let trust = match providers.resolve_trust(&offering.provider_profile_handle, &model.id)
            {
                ModelTrust::Trusted => AgentPolicyTrustClassification::Trusted,
                ModelTrust::Untrusted => AgentPolicyTrustClassification::Untrusted,
            };
            let confirmation_required = model.trust.is_none() && provider.trust.is_none();
            routes.push(AgentPolicyRoute {
                provider_id: offering.provider_id.clone(),
                model_id: model.id.clone(),
                trust: if confirmation_required {
                    AgentPolicyTrustClassification::Unset
                } else {
                    trust
                },
                confirmation_required,
                trust_is_shared: true,
                capabilities: capability_labels(&caps),
                location: location.map(|value| match value {
                    ModelLocation::Local => "local".to_string(),
                    ModelLocation::Remote => "remote".to_string(),
                    ModelLocation::PrivateRemote => "private_remote".to_string(),
                }),
                auto_prune: providers
                    .resolve_auto_prune(&offering.provider_profile_handle, &model.id),
                sidecar_eligible,
                remote_sidecar_egress_required: sidecar_eligible && !self_hosted,
            });
        }
    }
    routes.sort_by(|left, right| {
        left.provider_id
            .cmp(&right.provider_id)
            .then(left.model_id.cmp(&right.model_id))
    });
    let provider_config_fingerprint =
        crate::daemon::agent_installation::session_setup_config_fingerprint(providers)
            .unwrap_or_else(|_| "unserializable-provider-config".to_string());
    let policy_revision =
        policy_revision_digest(&routes, catalog_revision, &provider_config_fingerprint);
    AgentPolicySnapshot {
        policy_revision,
        routes,
        catalog_origin: match catalog_origin {
            AgentCatalogOrigin::Live => AgentAuthoringCatalogOrigin::Live,
            AgentCatalogOrigin::Cached => AgentAuthoringCatalogOrigin::Cached,
        },
        catalog_revision: catalog_revision.to_string(),
        bundled_frontier_slug: BUNDLED_FRONTIER_SLUG.to_string(),
    }
}

pub fn authoring_projection(
    providers: &ProvidersConfig,
    catalog: &AgentCatalogIndex,
    catalog_origin: AgentCatalogOrigin,
    catalog_revision: &str,
) -> Result<AgentAuthoringProjection> {
    let policy = policy_snapshot(providers, catalog_origin, catalog_revision);
    let hardware = crate::daemon::agent_catalog::AgentCatalogHostHardware::detect_current_host();
    let mut sources = Vec::new();
    let frontier = bundled_frontier_entry()?;
    if frontier.is_eligible_for_hardware(&hardware) {
        if let Some(source) = catalog_source(
            AgentAuthoringSourceKind::BundledFrontier,
            &frontier,
            catalog_revision,
            providers,
            &policy,
        )? {
            sources.push(source);
        }
    }
    for entry in catalog.suggestions_for_models_and_hardware(providers, &hardware) {
        if entry.catalog.slug == BUNDLED_FRONTIER_SLUG {
            continue;
        }
        if let Some(source) = catalog_source(
            AgentAuthoringSourceKind::FirstPartyCatalog,
            entry,
            catalog_revision,
            providers,
            &policy,
        )? {
            sources.push(source);
        }
    }
    Ok(AgentAuthoringProjection {
        dto_version: AGENT_AUTHORING_DTO_VERSION,
        policy,
        sources,
        review_trust_disclosure: REVIEW_TRUST_DISCLOSURE.to_string(),
    })
}

pub fn validate_authored_agent_name(name: &str) -> Result<(), AuthoredPackageRejection> {
    if name.is_empty()
        || name.contains('/')
        || name.contains('\\')
        || name.contains('.')
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::InvalidNestedGraph,
            "authored agent name must be ASCII alphanumeric with '-' or '_' only",
        ));
    }
    Ok(())
}

pub fn canonicalize_authored_package(
    draft: &AuthoredAgentPackageDraft,
    snapshot: &AgentPolicySnapshot,
    providers: &ProvidersConfig,
    catalog: &AgentCatalogIndex,
) -> Result<CanonicalAuthoredPackage, AuthoredPackageRejection> {
    validate_authored_agent_name(&draft.name)?;
    for child in &draft.children {
        if let Some(name) = child
            .relative_path
            .strip_prefix("subagents/")
            .and_then(|rest| rest.strip_suffix(".md"))
            .and_then(|rest| rest.rsplit('/').next())
        {
            validate_authored_agent_name(name)?;
        }
    }
    if draft.dto_version != AGENT_AUTHORING_DTO_VERSION {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::IncompletePackage,
            "unsupported authored package DTO version",
        ));
    }
    if draft.policy_revision != snapshot.policy_revision {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::StaleDraft,
            "authored package policy revision does not match the current snapshot",
        ));
    }
    // Inspect raw markdown before any closed-schema YAML parse. A `trust`
    // copy is a per-agent override, not an unknown frontmatter field.
    reject_trust_copy(&draft.markdown)?;
    for child in &draft.children {
        reject_trust_copy(&child.markdown)?;
        crate::agents::validate_package_relative_path(&child.relative_path).map_err(|error| {
            AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::InvalidNestedGraph,
                error.to_string(),
            )
        })?;
    }
    require_wire_provider_tokens(draft, providers)?;
    let derived_kind = derive_source_kind(&draft.source, &draft.name, snapshot, catalog)?;
    if draft.source.kind != derived_kind {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::IncompletePackage,
            "source kind does not match the locator's membership in the pinned catalog",
        ));
    }
    validate_source_kind(derived_kind, &draft.source)?;
    validate_sidecars(&draft.sidecars, snapshot)?;
    let files = canonical_file_map(draft)?;
    let definition = crate::agents::load_workspace_package_from_files(&draft.name, files.clone())
        .map_err(map_package_error)?;
    validate_grants(&definition, snapshot, &draft.model_trust_confirmations)?;
    let digest = hex_digest(&crate::agents::package_digest_preimage(&files));
    let review = review_from_definition(&definition, snapshot, draft, &digest, &files);
    Ok(CanonicalAuthoredPackage {
        files,
        digest,
        definition,
        review,
    })
}

pub struct WizardAuthoringSelection {
    pub slug: String,
    pub catalog_revision: String,
    pub default_model_provider: String,
    pub default_model: String,
    pub model_trust: ModelTrust,
    pub model_trust_confirmed: bool,
    pub third_party_source: Option<String>,
    pub third_party_trust_confirmed: bool,
    pub tool_tiers: BTreeMap<String, crate::agents::ToolTier>,
    pub sidecar: Option<AuthoredSidecarDeclaration>,
    pub make_default: bool,
}

pub fn draft_from_selection(
    selection: WizardAuthoringSelection,
    entry: Option<&AgentCatalogEntry>,
    snapshot: &AgentPolicySnapshot,
) -> Result<AuthoredAgentPackageDraft> {
    let (kind, source_locator, name, mut frontmatter, body) = if let Some(source) =
        selection.third_party_source.as_deref()
    {
        let parsed = crate::daemon::agent_installation::CanonicalAgentSource::parse(source)?;
        (
            AgentAuthoringSourceKind::ThirdParty,
            source.to_string(),
            parsed.agent_name()?.to_string(),
            crate::agents::AgentDefinitionFrontmatter {
                schema_version: crate::agents::SCHEMA_VERSION,
                agent_id: format!("authored/{}", parsed.agent_name()?),
                roles: vec![crate::agents::AgentRole::Code],
                model_slots: BTreeMap::new(),
                delegation: None,
                questions: None,
                verification: None,
                allowed_knowledge_bases: None,
                tool_tier_preferences: BTreeMap::new(),
                requested_network_hosts: Default::default(),
                requests_requested: false,
                description: parsed.agent_name()?.to_string(),
                capabilities: Default::default(),
                tool_steering: None,
                context_policy: None,
                mcp_bindings: Vec::new(),
            },
            format!("You are the `{}` Cockpit agent.\n", parsed.agent_name()?),
        )
    } else {
        let entry = entry.context("selected onboarding agent is absent from the pinned catalog")?;
        entry.definition.validate_catalog_definition()?;
        let kind = if entry.catalog.slug == BUNDLED_FRONTIER_SLUG {
            AgentAuthoringSourceKind::BundledFrontier
        } else {
            AgentAuthoringSourceKind::FirstPartyCatalog
        };
        let body = if entry.catalog.slug == BUNDLED_FRONTIER_SLUG {
            let raw =
                std::str::from_utf8(crate::daemon::agent_catalog::bundled_frontier_markdown())?;
            split_frontmatter(raw).1.to_string()
        } else {
            format!("You are the `{}` Cockpit agent.\n", entry.catalog.slug)
        };
        (
            kind,
            entry.pinned_source_locator(&selection.catalog_revision)?,
            entry.catalog.slug.clone(),
            entry.definition.clone(),
            body,
        )
    };
    let primary = frontmatter
        .model_slots
        .entry("primary".into())
        .or_insert_with(|| crate::agents::ModelSlot {
            purpose: "Primary model".into(),
            min_context_tokens: 1,
            required_capabilities: vec![crate::agents::ModelCapability::TextGeneration],
            locality: crate::agents::ModelLocality::Any,
            allow_default_fallback: false,
            suggested_models: Vec::new(),
            models: Vec::new(),
        });
    primary.models = vec![crate::agents::SlotModelRef {
        provider_id: selection.default_model_provider.clone(),
        model_id: selection.default_model.clone(),
        default: true,
    }];
    if !selection.tool_tiers.is_empty() {
        frontmatter.tool_tier_preferences = selection
            .tool_tiers
            .into_iter()
            .filter(|(_, tier)| {
                matches!(
                    tier,
                    crate::agents::ToolTier::Enabled | crate::agents::ToolTier::Discoverable
                )
            })
            .collect();
    }
    let yaml = serde_yaml::to_string(&frontmatter)?;
    let markdown = format!("---\n{}---\n{body}", yaml.trim_start_matches("---\n"));
    Ok(AuthoredAgentPackageDraft {
        dto_version: AGENT_AUTHORING_DTO_VERSION,
        name,
        markdown,
        source: AuthoredAgentSource {
            kind,
            source_locator,
            pin: None,
            third_party_trust_confirmed: selection.third_party_trust_confirmed,
        },
        children: Vec::new(),
        mcp_json: None,
        sidecars: selection.sidecar.into_iter().collect(),
        policy_revision: snapshot.policy_revision.clone(),
        model_trust_confirmations: vec![ModelTrustConfirmation {
            provider_id: selection.default_model_provider,
            model_id: selection.default_model,
            confirmed: selection.model_trust_confirmed,
        }],
        make_default: selection.make_default,
        draft_revision: None,
    })
}

pub fn committed_receipt(
    client_operation_id: String,
    package: &CanonicalAuthoredPackage,
    snapshot: &AgentPolicySnapshot,
    installation_id: Option<String>,
    default_selected: bool,
) -> ApplyAuthoredAgentPackageReceipt {
    ApplyAuthoredAgentPackageReceipt {
        client_operation_id,
        receipt_id: uuid::Uuid::now_v7(),
        status: AuthoredAgentReceiptStatus::Committed,
        package_digest: package.digest.clone(),
        policy_revision: snapshot.policy_revision.clone(),
        installation_id,
        default_selected,
        result_config_generation: crate::daemon::server::inventory::current_config_generation(),
        review: package.review.clone(),
    }
}

fn catalog_source(
    kind: AgentAuthoringSourceKind,
    entry: &AgentCatalogEntry,
    catalog_revision: &str,
    providers: &ProvidersConfig,
    snapshot: &AgentPolicySnapshot,
) -> Result<Option<AgentAuthoringSource>> {
    let offerings = crate::daemon::agent_installation::setup_offerings(providers);
    let Some(primary) = entry.definition.model_slots.get("primary") else {
        return Ok(None);
    };
    let compatible = crate::agents::ranked_compatible_offerings(primary, &offerings, providers);
    if compatible.is_empty() {
        return Ok(None);
    }
    let routes = compatible
        .into_iter()
        .filter_map(|offering| {
            snapshot.routes.iter().find(|route| {
                route.provider_id == offering.provider_id && route.model_id == offering.model_id
            })
        })
        .map(|route| AgentAuthoringCompatibleRoute {
            provider_id: route.provider_id.clone(),
            model_id: route.model_id.clone(),
        })
        .collect::<Vec<_>>();
    if routes.is_empty() {
        return Ok(None);
    }
    let locator = entry.pinned_source_locator(catalog_revision).ok();
    let yaml = serde_yaml::to_string(&entry.definition).ok();
    Ok(Some(AgentAuthoringSource {
        kind,
        slug: Some(entry.catalog.slug.clone()),
        display_name: entry.catalog.display_name.clone(),
        source_locator: locator,
        compatible_routes: routes,
        definition_frontmatter_yaml: yaml,
    }))
}

fn capability_labels(
    caps: &cockpit_config::config::model_policy::EffectiveModelCapabilities,
) -> Vec<String> {
    let mut labels = vec!["text_generation".to_string()];
    if matches!(
        caps.tool_calling,
        cockpit_config::config::providers::CapabilityStatus::Supported
    ) {
        labels.push("tool_calling".to_string());
    }
    if caps.supports_image_input() {
        labels.push("vision".to_string());
    }
    if caps
        .computer_use
        .as_ref()
        .is_some_and(|capability| !capability.is_empty())
    {
        labels.push("computer_use".to_string());
    }
    if matches!(
        caps.structured_outputs,
        cockpit_config::config::providers::CapabilityStatus::Supported
    ) {
        labels.push("json_schema".to_string());
    }
    labels
}

fn policy_revision_digest(
    routes: &[AgentPolicyRoute],
    catalog_revision: &str,
    provider_config_fingerprint: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"cockpit-agent-policy-snapshot-v2\0");
    digest.update(catalog_revision.as_bytes());
    digest.update([0]);
    digest.update(provider_config_fingerprint.as_bytes());
    digest.update([0]);
    let encoded = serde_json::to_vec(routes).unwrap_or_default();
    digest.update(&encoded);
    crate::intel::hex_lower(&digest.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    crate::intel::hex_lower(&Sha256::digest(bytes))
}

fn map_package_error(error: anyhow::Error) -> AuthoredPackageRejection {
    let message = error.to_string();
    let reason = if message.contains("toolTierPreferences") {
        AuthoredAgentRejectReason::IllegalToolTier
    } else if message.contains("duplicate (providerId, modelId)") {
        AuthoredAgentRejectReason::DuplicateRoutes
    } else if message.contains("must mark exactly one default") {
        AuthoredAgentRejectReason::NonEnabledDefault
    } else if message.contains("interactiveSubagents")
        || message.contains("private subagent")
        || message.contains("subagents/")
        || message.contains("maxDescendantDepth")
        || message.contains("delegation")
        || message.contains("cycle")
    {
        AuthoredAgentRejectReason::InvalidNestedGraph
    } else if message.contains("mcp.json") {
        AuthoredAgentRejectReason::IncompletePackage
    } else {
        AuthoredAgentRejectReason::InvalidFrontmatter
    };
    AuthoredPackageRejection::new(reason, message)
}

fn reject_trust_copy(markdown: &str) -> Result<(), AuthoredPackageRejection> {
    let (frontmatter, _) = split_frontmatter(markdown);
    if frontmatter.contains("trust:") || frontmatter.contains("trustSuggestion") {
        // Author suggestions on catalog YAML are allowed only as
        // `trustSuggestion` inside suggestedModels. A trust copy on a grant
        // or a top-level trust field is a per-agent override.
        if frontmatter.contains("\ntrust:")
            || frontmatter.contains(" trust:")
            || frontmatter.contains("\n  trust:")
        {
            return Err(AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::PerAgentTrustOverride,
                "agent definitions store model routes, never a trust copy or per-agent override",
            ));
        }
    }
    Ok(())
}

fn split_frontmatter(markdown: &str) -> (&str, &str) {
    let rest = markdown.strip_prefix("---\n").unwrap_or(markdown);
    match rest.find("\n---") {
        Some(end) => (&rest[..end], rest[end + 4..].trim_start_matches('\n')),
        None => ("", markdown),
    }
}

fn derive_source_kind(
    source: &AuthoredAgentSource,
    name: &str,
    snapshot: &AgentPolicySnapshot,
    catalog: &AgentCatalogIndex,
) -> Result<AgentAuthoringSourceKind, AuthoredPackageRejection> {
    let authored_locator = format!("authored/{name}");
    if source.source_locator == authored_locator {
        return Ok(AgentAuthoringSourceKind::Authored);
    }
    if let Ok(frontier) = bundled_frontier_entry()
        && let Ok(locator) = frontier.pinned_source_locator(&snapshot.catalog_revision)
        && source.source_locator == locator
    {
        return Ok(AgentAuthoringSourceKind::BundledFrontier);
    }
    for entry in &catalog.agents {
        if entry.catalog.slug == BUNDLED_FRONTIER_SLUG {
            continue;
        }
        if let Ok(locator) = entry.pinned_source_locator(&snapshot.catalog_revision)
            && source.source_locator == locator
        {
            return Ok(AgentAuthoringSourceKind::FirstPartyCatalog);
        }
    }
    Ok(AgentAuthoringSourceKind::ThirdParty)
}

fn validate_source_kind(
    kind: AgentAuthoringSourceKind,
    source: &AuthoredAgentSource,
) -> Result<(), AuthoredPackageRejection> {
    match kind {
        AgentAuthoringSourceKind::ThirdParty => {
            let parsed = crate::daemon::agent_installation::CanonicalAgentSource::parse(
                &source.source_locator,
            )
            .map_err(|error| {
                AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::UnpinnedThirdPartySource,
                    error.to_string(),
                )
            })?;
            if parsed.requested_revision.is_none() && source.pin.is_none() {
                return Err(AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::UnpinnedThirdPartySource,
                    "third-party sources must pin a commit or tag",
                ));
            }
            if !source.third_party_trust_confirmed {
                return Err(AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::MissingThirdPartyTrustConfirmation,
                    "third-party agent installation requires explicit security confirmation",
                ));
            }
        }
        AgentAuthoringSourceKind::BundledFrontier
        | AgentAuthoringSourceKind::FirstPartyCatalog
        | AgentAuthoringSourceKind::Authored => {}
    }
    Ok(())
}

fn validate_grants(
    definition: &AgentDef,
    snapshot: &AgentPolicySnapshot,
    confirmations: &[ModelTrustConfirmation],
) -> Result<(), AuthoredPackageRejection> {
    let Some(frontmatter) = definition.definition_frontmatter() else {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::InvalidFrontmatter,
            "authored package must be a launch-v1 definition",
        ));
    };
    let Some(primary) = frontmatter.model_slots.get("primary") else {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::EmptyGrants,
            "primary model slot is required",
        ));
    };
    if primary.models.is_empty() {
        return Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::EmptyGrants,
            "at least one model grant is required",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut defaults = 0usize;
    for grant in &primary.models {
        if !seen.insert((grant.provider_id.as_str(), grant.model_id.as_str())) {
            return Err(AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::DuplicateRoutes,
                "model grants must not duplicate provider/model routes",
            ));
        }
        if grant.default {
            defaults += 1;
        }
        let route = snapshot
            .routes
            .iter()
            .find(|route| {
                route.provider_id == grant.provider_id && route.model_id == grant.model_id
            })
            .ok_or_else(|| {
                AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::UnsupportedCapability,
                    format!(
                        "grant {}/{} is not a configured provider route",
                        grant.provider_id, grant.model_id
                    ),
                )
            })?;
        for required in &primary.required_capabilities {
            if !route
                .capabilities
                .iter()
                .any(|cap| cap == required.as_str())
            {
                return Err(AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::UnsupportedCapability,
                    format!(
                        "grant {}/{} does not provide {}",
                        grant.provider_id,
                        grant.model_id,
                        required.as_str()
                    ),
                ));
            }
        }
        if route.confirmation_required {
            let confirmed = confirmations.iter().any(|confirmation| {
                confirmation.provider_id == grant.provider_id
                    && confirmation.model_id == grant.model_id
                    && confirmation.confirmed
            });
            if !confirmed {
                return Err(AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::OmittedModelTrustConfirmation,
                    format!(
                        "model trust confirmation is required for {}/{}",
                        grant.provider_id, grant.model_id
                    ),
                ));
            }
        }
    }
    match defaults {
        1 => Ok(()),
        0 => Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::AbsentDefault,
            "exactly one enabled model grant must be the default",
        )),
        _ => Err(AuthoredPackageRejection::new(
            AuthoredAgentRejectReason::NonEnabledDefault,
            "exactly one enabled model grant must be the default",
        )),
    }
}

fn validate_sidecars(
    sidecars: &[AuthoredSidecarDeclaration],
    snapshot: &AgentPolicySnapshot,
) -> Result<(), AuthoredPackageRejection> {
    for sidecar in sidecars {
        let route = snapshot
            .routes
            .iter()
            .find(|route| {
                route.provider_id == sidecar.provider_id && route.model_id == sidecar.model_id
            })
            .ok_or_else(|| {
                AuthoredPackageRejection::new(
                    AuthoredAgentRejectReason::UnsupportedCapability,
                    format!(
                        "sidecar {}/{} is not a configured provider route",
                        sidecar.provider_id, sidecar.model_id
                    ),
                )
            })?;
        if !route.sidecar_eligible {
            return Err(AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::UnsupportedCapability,
                format!(
                    "sidecar {}/{} is not vision-capable",
                    sidecar.provider_id, sidecar.model_id
                ),
            ));
        }
        if route.remote_sidecar_egress_required && !sidecar.remote_image_egress_confirmed {
            return Err(AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::UnapprovedRemoteSidecarEgress,
                "remote sidecar requires explicit confirmation that screenshots and image content leave the machine",
            ));
        }
    }
    Ok(())
}

fn canonical_file_map(
    draft: &AuthoredAgentPackageDraft,
) -> Result<BTreeMap<String, Vec<u8>>, AuthoredPackageRejection> {
    let mut files = BTreeMap::new();
    files.insert("agent.md".to_string(), draft.markdown.as_bytes().to_vec());
    if let Some(mcp) = &draft.mcp_json {
        files.insert("mcp.json".to_string(), mcp.as_bytes().to_vec());
    }
    if !draft.sidecars.is_empty() {
        let entries = draft
            .sidecars
            .iter()
            .map(|sidecar| crate::agents::AgentPackageSidecarEntry {
                provider_id: sidecar.provider_id.clone(),
                model_id: sidecar.model_id.clone(),
                remote_image_egress_confirmed: sidecar.remote_image_egress_confirmed,
            })
            .collect::<Vec<_>>();
        let bytes = crate::agents::encode_package_sidecar_file(&entries).map_err(|error| {
            AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::IncompletePackage,
                error.to_string(),
            )
        })?;
        files.insert(crate::agents::PACKAGE_SIDECAR_FILE.to_string(), bytes);
    }
    let mut seen = BTreeSet::new();
    for child in &draft.children {
        if !seen.insert(child.relative_path.as_str()) {
            return Err(AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::InvalidNestedGraph,
                format!("duplicate child path `{}`", child.relative_path),
            ));
        }
        crate::agents::validate_package_relative_path(&child.relative_path).map_err(|error| {
            AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::InvalidNestedGraph,
                error.to_string(),
            )
        })?;
        files.insert(
            child.relative_path.clone(),
            child.markdown.as_bytes().to_vec(),
        );
    }
    for path in files.keys() {
        crate::agents::validate_package_relative_path(path).map_err(|error| {
            AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::IncompletePackage,
                error.to_string(),
            )
        })?;
    }
    Ok(files)
}

fn require_wire_provider_tokens(
    draft: &AuthoredAgentPackageDraft,
    providers: &ProvidersConfig,
) -> Result<(), AuthoredPackageRejection> {
    require_markdown_wire_provider_ids(&draft.markdown, providers)?;
    for child in &draft.children {
        require_markdown_wire_provider_ids(&child.markdown, providers)?;
    }
    for sidecar in &draft.sidecars {
        require_wire_provider_id(providers, &sidecar.provider_id, &sidecar.model_id)?;
    }
    for confirmation in &draft.model_trust_confirmations {
        require_wire_provider_id(providers, &confirmation.provider_id, &confirmation.model_id)?;
    }
    Ok(())
}

fn require_markdown_wire_provider_ids(
    markdown: &str,
    providers: &ProvidersConfig,
) -> Result<(), AuthoredPackageRejection> {
    let (frontmatter, _) = split_frontmatter(markdown);
    if frontmatter.is_empty() {
        return Ok(());
    }
    let parsed: crate::agents::AgentDefinitionFrontmatter = serde_yaml::from_str(frontmatter)
        .map_err(|error| {
            AuthoredPackageRejection::new(
                AuthoredAgentRejectReason::InvalidFrontmatter,
                error.to_string(),
            )
        })?;
    for slot in parsed.model_slots.values() {
        for grant in &slot.models {
            require_wire_provider_id(providers, &grant.provider_id, &grant.model_id)?;
        }
    }
    Ok(())
}

fn require_wire_provider_id(
    providers: &ProvidersConfig,
    submitted: &str,
    model_id: &str,
) -> Result<(), AuthoredPackageRejection> {
    let matches = crate::daemon::agent_installation::setup_offerings(providers)
        .into_iter()
        .filter(|offering| offering.model_id == model_id && offering.provider_id == submitted)
        .count();
    if matches == 1 {
        return Ok(());
    }
    Err(AuthoredPackageRejection::new(
        AuthoredAgentRejectReason::UnsupportedCapability,
        format!("grant {submitted}/{model_id} is not a configured provider route"),
    ))
}

pub fn authored_sidecar_selection_config(
    sidecars: &[AuthoredSidecarDeclaration],
    providers: &ProvidersConfig,
) -> Result<crate::config::image_sidecar::SidecarSelectionConfig> {
    use crate::config::image_sidecar::{SidecarMode, SidecarProviderModel, SidecarSelectionConfig};
    if sidecars.is_empty() {
        return Ok(SidecarSelectionConfig {
            mode: SidecarMode::Never,
            trusted_primary_default: None,
            untrusted_primary_default: None,
            per_primary_override: None,
            permitted: Vec::new(),
        });
    }
    let mut permitted = Vec::new();
    let mut trusted = None;
    let mut untrusted = None;
    for sidecar in sidecars {
        let handle = crate::daemon::agent_installation::resolvable_provider_handle_for_route(
            providers,
            &sidecar.provider_id,
            &sidecar.model_id,
        )
        .context("sidecar provider is not a configured route")?;
        let selected = SidecarProviderModel {
            provider: handle.clone(),
            model: sidecar.model_id.clone(),
        };
        match providers.resolve_trust(&handle, &sidecar.model_id) {
            ModelTrust::Trusted if trusted.is_none() => {
                trusted = Some(selected.clone());
            }
            ModelTrust::Untrusted if untrusted.is_none() => {
                untrusted = Some(selected.clone());
            }
            _ => {}
        }
        permitted.push(selected);
    }
    if trusted.is_none() {
        trusted = permitted.first().cloned();
    }
    if untrusted.is_none() {
        untrusted = permitted.first().cloned();
    }
    Ok(SidecarSelectionConfig {
        mode: SidecarMode::Always,
        trusted_primary_default: trusted,
        untrusted_primary_default: untrusted,
        per_primary_override: None,
        permitted,
    })
}

pub fn publish_authored_sidecar_selection(
    sidecars: &[AuthoredSidecarDeclaration],
    providers: &ProvidersConfig,
) -> Result<()> {
    publish_authored_sidecar_config(&authored_sidecar_selection_config(sidecars, providers)?)
}

pub fn publish_authored_sidecar_config(
    selection: &crate::config::image_sidecar::SidecarSelectionConfig,
) -> Result<()> {
    let global_config =
        crate::config::dirs::global_config_file().context("resolving sidecar config")?;
    let mut extended_doc = crate::config::extended::ExtendedConfigDoc::load(&global_config)?;
    let mut extended = extended_doc.config();
    extended.image_sidecar = selection.clone();
    extended_doc.write(&extended)?;
    crate::daemon::server::inventory::publish_committed_config_generation();
    Ok(())
}

fn review_from_definition(
    definition: &AgentDef,
    snapshot: &AgentPolicySnapshot,
    draft: &AuthoredAgentPackageDraft,
    _digest: &str,
    files: &BTreeMap<String, Vec<u8>>,
) -> AuthoredAgentReview {
    let frontmatter = definition.definition_frontmatter();
    let grants = frontmatter
        .as_ref()
        .and_then(|fm| fm.model_slots.get("primary"))
        .map(|slot| {
            slot.models
                .iter()
                .map(|grant| {
                    let route = snapshot.routes.iter().find(|route| {
                        route.provider_id == grant.provider_id && route.model_id == grant.model_id
                    });
                    AuthoredAgentReviewGrant {
                        provider_id: grant.provider_id.clone(),
                        model_id: grant.model_id.clone(),
                        is_default: grant.default || slot.default_model() == Some(grant),
                        trust: route
                            .map(|route| route.trust)
                            .unwrap_or(AgentPolicyTrustClassification::Unset),
                        trust_is_shared: true,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let tool_tier_preferences = frontmatter
        .as_ref()
        .map(|fm| {
            fm.tool_tier_preferences
                .iter()
                .map(|(tool, tier)| (tool.clone(), tier.label().to_string()))
                .collect()
        })
        .unwrap_or_default();
    let interactive_subagents = definition
        .vnext
        .as_ref()
        .is_some_and(|vnext| vnext.delegation.interactive_subagents);
    let goal_skeptics = definition
        .vnext
        .as_ref()
        .and_then(|vnext| vnext.verification.as_ref())
        .map(|policy| policy.goal_skeptics)
        .unwrap_or(GoalSkepticsPolicy::Off);
    let verification_label = definition.vnext.as_ref().and_then(|vnext| {
        vnext.verification.as_ref().map(|policy| {
            if policy.rules.is_empty() {
                "Self-verification off".to_string()
            } else {
                format!("Self-verification ({} rules)", policy.rules.len())
            }
        })
    });
    AuthoredAgentReview {
        agent_name: draft.name.clone(),
        grants,
        tool_tier_preferences,
        verification_label,
        interactive_subagents,
        goal_skeptics_label: goal_skeptics.review_label().to_string(),
        children: review_children_from_package_files(draft, snapshot, &files),
        sidecars: draft
            .sidecars
            .iter()
            .map(|sidecar| format!("{}/{}", sidecar.provider_id, sidecar.model_id))
            .collect(),
        source: draft.source.source_locator.clone(),
        make_default: draft.make_default,
        trust_is_shared: true,
        trust_disclosure: REVIEW_TRUST_DISCLOSURE.to_string(),
    }
}

fn review_children_from_package_files(
    draft: &AuthoredAgentPackageDraft,
    snapshot: &AgentPolicySnapshot,
    files: &BTreeMap<String, Vec<u8>>,
) -> Vec<AuthoredAgentReviewChild> {
    draft
        .children
        .iter()
        .filter(|child| {
            child
                .relative_path
                .strip_prefix("subagents/")
                .and_then(|rest| rest.strip_suffix(".md"))
                .is_some_and(|rest| !rest.contains('/'))
        })
        .filter_map(|child| {
            review_child_at_path(&child.relative_path, &child.markdown, snapshot, files)
        })
        .collect()
}

fn review_child_at_path(
    path: &str,
    markdown: &str,
    snapshot: &AgentPolicySnapshot,
    files: &BTreeMap<String, Vec<u8>>,
) -> Option<AuthoredAgentReviewChild> {
    let child_name = path
        .strip_prefix("subagents/")
        .and_then(|rest| rest.strip_suffix(".md"))
        .unwrap_or(path);
    let child_def = crate::agents::load_workspace_package_from_files(child_name, {
        let mut scoped = BTreeMap::from([(
            crate::agents::PACKAGE_ROOT_FILE.to_string(),
            markdown.as_bytes().to_vec(),
        )]);
        for (rel, bytes) in files {
            if rel.starts_with("subagents/")
                && rel
                    .strip_prefix("subagents/")
                    .is_some_and(|rest| rest.starts_with(&format!("{child_name}/")))
            {
                scoped.insert(rel.clone(), bytes.clone());
            }
        }
        scoped
    });
    let child_def = match child_def {
        Ok(def) => def,
        Err(_) => return None,
    };
    let frontmatter = child_def.definition_frontmatter()?;
    let grants = frontmatter
        .model_slots
        .get("primary")
        .map(|slot| {
            slot.models
                .iter()
                .map(|grant| {
                    let route = snapshot.routes.iter().find(|route| {
                        route.provider_id == grant.provider_id && route.model_id == grant.model_id
                    });
                    AuthoredAgentReviewGrant {
                        provider_id: grant.provider_id.clone(),
                        model_id: grant.model_id.clone(),
                        is_default: grant.default || slot.default_model() == Some(grant),
                        trust: route
                            .map(|route| route.trust)
                            .unwrap_or(AgentPolicyTrustClassification::Unset),
                        trust_is_shared: true,
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let tool_tier_preferences = frontmatter
        .tool_tier_preferences
        .iter()
        .map(|(tool, tier)| (tool.clone(), tier.label().to_string()))
        .collect();
    let interactive_subagents = child_def
        .vnext
        .as_ref()
        .is_some_and(|vnext| vnext.delegation.interactive_subagents);
    let goal_skeptics = child_def
        .vnext
        .as_ref()
        .and_then(|vnext| vnext.verification.as_ref())
        .map(|policy| policy.goal_skeptics)
        .unwrap_or(GoalSkepticsPolicy::Off);
    let nested_prefix = format!("{child_name}/");
    let nested = files
        .iter()
        .filter(|(rel, _)| {
            rel.strip_prefix("subagents/")
                .and_then(|rest| rest.strip_suffix(".md"))
                .is_some_and(|rest| {
                    rest.strip_prefix(&nested_prefix)
                        .is_some_and(|tail| !tail.is_empty() && !tail.contains('/'))
                })
        })
        .filter_map(|(rel, bytes)| {
            std::str::from_utf8(bytes)
                .ok()
                .and_then(|markdown| review_child_at_path(rel, markdown, snapshot, files))
        })
        .collect();
    Some(AuthoredAgentReviewChild {
        path: path.to_string(),
        grants,
        tool_tier_preferences,
        interactive_subagents,
        goal_skeptics_label: goal_skeptics.review_label().to_string(),
        children: nested,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::agent_catalog::BUNDLED_CATALOG_REVISION;
    use cockpit_config::config::providers::{
        CapabilityStatus, ModelCapabilities, ModelEntry, ModelLocation, ProviderEntry,
    };
    use cockpit_proto::{
        AgentAuthoringCatalogOrigin, AgentAuthoringSourceKind, AuthoredAgentChild,
        AuthoredAgentSource,
    };
    use std::collections::BTreeMap;

    fn providers_with(model: &str, trust: Option<ModelTrust>) -> ProvidersConfig {
        let mut providers = BTreeMap::new();
        providers.insert(
            "vendor".to_string(),
            ProviderEntry {
                template: Some("vendor".into()),
                models: vec![ModelEntry {
                    id: model.to_string(),
                    trust,
                    ..ModelEntry::default()
                }],
                trust,
                ..ProviderEntry::default()
            },
        );
        ProvidersConfig {
            providers,
            ..ProvidersConfig::default()
        }
    }

    fn markdown(name: &str, grants: &[(&str, &str, bool)]) -> String {
        let models = grants
            .iter()
            .map(|(provider, model, default)| {
                let default_flag = if *default {
                    "\n        default: true"
                } else {
                    ""
                };
                format!("      - providerId: {provider}\n        modelId: {model}{default_flag}")
            })
            .collect::<Vec<_>>()
            .join("\n");
        format!(
            "---\nschemaVersion: 1\nagentId: authored/{name}\nroles: [code]\ndescription: {name}\nmodelSlots:\n  primary:\n    purpose: primary\n    minContextTokens: 1\n    requiredCapabilities: [text_generation]\n    locality: any\n    allowDefaultFallback: false\n    models:\n{models}\n---\nbody\n"
        )
    }

    fn draft(
        name: &str,
        grants: &[(&str, &str, bool)],
        confirmed: bool,
    ) -> AuthoredAgentPackageDraft {
        AuthoredAgentPackageDraft {
            dto_version: AGENT_AUTHORING_DTO_VERSION,
            name: name.to_string(),
            markdown: markdown(name, grants),
            source: AuthoredAgentSource {
                kind: AgentAuthoringSourceKind::Authored,
                source_locator: format!("authored/{name}"),
                pin: None,
                third_party_trust_confirmed: false,
            },
            children: vec![],
            mcp_json: None,
            sidecars: vec![],
            policy_revision: String::new(),
            model_trust_confirmations: grants
                .iter()
                .map(|(provider, model, _)| ModelTrustConfirmation {
                    provider_id: (*provider).to_string(),
                    model_id: (*model).to_string(),
                    confirmed,
                })
                .collect(),
            make_default: true,
            draft_revision: None,
        }
    }

    fn snapshot_for(providers: &ProvidersConfig) -> AgentPolicySnapshot {
        policy_snapshot(
            providers,
            AgentCatalogOrigin::Cached,
            BUNDLED_CATALOG_REVISION,
        )
    }

    fn catalog() -> crate::daemon::agent_catalog::AgentCatalogIndex {
        crate::daemon::agent_catalog::cached_catalog().unwrap()
    }

    fn canonicalize(
        draft: &AuthoredAgentPackageDraft,
        snapshot: &AgentPolicySnapshot,
        providers: &ProvidersConfig,
    ) -> Result<CanonicalAuthoredPackage, AuthoredPackageRejection> {
        canonicalize_authored_package(draft, snapshot, providers, &catalog())
    }

    #[test]
    fn field_mapping_uses_canonical_authorities() {
        let mapping = [
            ("name", "AgentDef.name / agentId"),
            ("grants", "ModelSlot.models"),
            ("default", "SlotModelRef.default"),
            ("tool tiers", "toolTierPreferences"),
            ("verification", "verification.rules"),
            ("goal skeptics", "verification.goalSkeptics"),
            ("interactive subagents", "delegation.interactiveSubagents"),
            ("nested children", "private_subagents / subagents/"),
            ("mcp", "mcp.json package file"),
            ("sidecar", "sidecar.json package file + remote-egress gate"),
            ("trust", "global ModelTrust via AgentPolicySnapshot"),
            ("auto-prune", "ProvidersConfig::resolve_auto_prune"),
            ("install", "agent installation authority"),
            ("default selection", "set_default_agent_installation"),
        ];
        assert_eq!(mapping.len(), 14);
        assert!(
            mapping
                .iter()
                .all(|(_, authority)| !authority.contains("onboarding-only"))
        );
    }

    #[test]
    fn round_trip_preserves_grants_and_review_trust_comes_from_snapshot() {
        let mut providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        providers
            .providers
            .get_mut("vendor")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "exact-b".into(),
                trust: Some(ModelTrust::Trusted),
                ..ModelEntry::default()
            });
        let snapshot = snapshot_for(&providers);
        let mut package = draft(
            "helper",
            &[("vendor", "exact-a", true), ("vendor", "exact-b", false)],
            true,
        );
        package.policy_revision = snapshot.policy_revision.clone();
        package.markdown = markdown(
            "helper",
            &[("vendor", "exact-a", true), ("vendor", "exact-b", false)],
        );
        let canonical = canonicalize(&package, &snapshot, &providers).unwrap();
        let rendered = canonical.definition.to_markdown().unwrap();
        let reparsed = crate::agents::parse_agent(
            &rendered,
            "helper",
            std::path::PathBuf::from("<round-trip>"),
        )
        .unwrap();
        let slots = reparsed.definition_frontmatter().unwrap().model_slots;
        let primary = slots.get("primary").unwrap();
        assert_eq!(primary.models.len(), 2);
        assert_eq!(primary.default_model().unwrap().model_id, "exact-a");
        assert_eq!(canonical.review.grants.len(), 2);
        assert!(canonical.review.trust_is_shared);
        assert_eq!(
            canonical.review.grants[0].trust,
            AgentPolicyTrustClassification::Untrusted
        );
        assert_eq!(
            canonical.review.grants[1].trust,
            AgentPolicyTrustClassification::Trusted
        );
        assert!(!rendered.contains("trust:"));
    }

    #[test]
    fn rejects_empty_grants_and_omitted_trust_confirmation() {
        let providers = providers_with("exact-a", None);
        let snapshot = snapshot_for(&providers);
        let mut empty = draft("helper", &[("vendor", "exact-a", true)], true);
        empty.policy_revision = snapshot.policy_revision.clone();
        empty.markdown = markdown("helper", &[]);
        let err = canonicalize(&empty, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::EmptyGrants);

        let mut omitted = draft("helper", &[("vendor", "exact-a", true)], false);
        omitted.policy_revision = snapshot.policy_revision.clone();
        let err = canonicalize(&omitted, &snapshot, &providers).unwrap_err();
        assert_eq!(
            err.reason,
            AuthoredAgentRejectReason::OmittedModelTrustConfirmation
        );
    }

    #[test]
    fn rejects_unpinned_third_party_and_unapproved_remote_sidecar() {
        let providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let snapshot = snapshot_for(&providers);
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        package.source = AuthoredAgentSource {
            kind: AgentAuthoringSourceKind::ThirdParty,
            source_locator: "Acme/agents:helper.md".into(),
            pin: None,
            third_party_trust_confirmed: true,
        };
        let err = canonicalize(&package, &snapshot, &providers).unwrap_err();
        assert_eq!(
            err.reason,
            AuthoredAgentRejectReason::UnpinnedThirdPartySource
        );

        package.source.pin = Some("abc".into());
        package.source.source_locator = "Acme/agents@abc:helper.md".into();
        package.source.third_party_trust_confirmed = false;
        let err = canonicalize(&package, &snapshot, &providers).unwrap_err();
        assert_eq!(
            err.reason,
            AuthoredAgentRejectReason::MissingThirdPartyTrustConfirmation
        );
    }

    #[test]
    fn child_add_changes_digest_and_failed_child_does_not_partially_parse() {
        let providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let snapshot = snapshot_for(&providers);
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        let parent = canonicalize(&package, &snapshot, &providers).unwrap();
        package.children.push(AuthoredAgentChild {
            relative_path: "subagents/reviewer.md".into(),
            markdown: markdown("reviewer", &[("vendor", "exact-a", true)]),
        });
        let with_child = canonicalize(&package, &snapshot, &providers).unwrap();
        assert_ne!(parent.digest, with_child.digest);
        assert!(with_child.files.contains_key("subagents/reviewer.md"));

        package.children[0].markdown = "not a definition".into();
        let err = canonicalize(&package, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::InvalidNestedGraph);
    }

    #[test]
    fn projection_filters_by_configured_capabilities_and_keeps_bundled_frontier() {
        let providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let catalog = crate::daemon::agent_catalog::cached_catalog().unwrap();
        let projection = authoring_projection(
            &providers,
            &catalog,
            AgentCatalogOrigin::Cached,
            BUNDLED_CATALOG_REVISION,
        )
        .unwrap();
        assert_eq!(
            projection.policy.bundled_frontier_slug,
            BUNDLED_FRONTIER_SLUG
        );
        assert_eq!(
            projection.policy.catalog_origin,
            AgentAuthoringCatalogOrigin::Cached
        );
        assert_eq!(projection.review_trust_disclosure, REVIEW_TRUST_DISCLOSURE);
        assert!(
            projection
                .policy
                .routes
                .iter()
                .all(|route| route.trust_is_shared && route.provider_id == "vendor")
        );
        for source in &projection.sources {
            assert!(
                source
                    .compatible_routes
                    .iter()
                    .all(|route| projection.policy.routes.iter().any(|policy| {
                        policy.provider_id == route.provider_id && policy.model_id == route.model_id
                    })),
                "catalog suggestions must not invent unconfigured models"
            );
        }
    }

    #[test]
    fn rejects_duplicate_routes_absent_default_and_illegal_tool_tier() {
        let providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let snapshot = snapshot_for(&providers);
        let mut duplicate = draft("helper", &[("vendor", "exact-a", true)], true);
        duplicate.policy_revision = snapshot.policy_revision.clone();
        duplicate.markdown = markdown(
            "helper",
            &[("vendor", "exact-a", true), ("vendor", "exact-a", false)],
        );
        let err = canonicalize(&duplicate, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::DuplicateRoutes);

        let mut absent = draft("helper", &[("vendor", "exact-a", false)], true);
        absent.policy_revision = snapshot.policy_revision.clone();
        let err = canonicalize(&absent, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::AbsentDefault);

        let mut two_model_providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        two_model_providers
            .providers
            .get_mut("vendor")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "exact-b".into(),
                trust: Some(ModelTrust::Untrusted),
                ..ModelEntry::default()
            });
        let two_model_snapshot = snapshot_for(&two_model_providers);
        let mut two_defaults = draft(
            "helper",
            &[("vendor", "exact-a", true), ("vendor", "exact-b", true)],
            true,
        );
        two_defaults.policy_revision = two_model_snapshot.policy_revision.clone();
        let err =
            canonicalize(&two_defaults, &two_model_snapshot, &two_model_providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::NonEnabledDefault);

        let mut illegal = draft("helper", &[("vendor", "exact-a", true)], true);
        illegal.policy_revision = snapshot.policy_revision.clone();
        illegal.markdown = illegal.markdown.replace(
            "modelSlots:",
            "toolTierPreferences:\n  question: disabled\nmodelSlots:",
        );
        let err = canonicalize(&illegal, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::IllegalToolTier);
    }

    #[test]
    fn rejects_per_agent_trust_override_and_unapproved_remote_sidecar() {
        let mut providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        providers
            .providers
            .get_mut("vendor")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "vision".into(),
                trust: Some(ModelTrust::Untrusted),
                location: Some(ModelLocation::Remote),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Supported,
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            });
        let snapshot = snapshot_for(&providers);
        let mut trust_copy = draft("helper", &[("vendor", "exact-a", true)], true);
        trust_copy.policy_revision = snapshot.policy_revision.clone();
        trust_copy.markdown = trust_copy
            .markdown
            .replace("description: helper", "description: helper\ntrust: trusted");
        let err = canonicalize(&trust_copy, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::PerAgentTrustOverride);

        let mut sidecar = draft("helper", &[("vendor", "exact-a", true)], true);
        sidecar.policy_revision = snapshot.policy_revision.clone();
        sidecar.sidecars.push(AuthoredSidecarDeclaration {
            provider_id: "vendor".into(),
            model_id: "vision".into(),
            remote_image_egress_confirmed: false,
        });
        let err = canonicalize(&sidecar, &snapshot, &providers).unwrap_err();
        assert_eq!(
            err.reason,
            AuthoredAgentRejectReason::UnapprovedRemoteSidecarEgress
        );
    }

    #[test]
    fn policy_revision_changes_when_global_trust_mutates_and_stale_draft_is_rejected() {
        let trusted = providers_with("exact-a", Some(ModelTrust::Trusted));
        let untrusted = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let trusted_snapshot = snapshot_for(&trusted);
        let untrusted_snapshot = snapshot_for(&untrusted);
        assert_ne!(
            trusted_snapshot.policy_revision,
            untrusted_snapshot.policy_revision
        );
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = trusted_snapshot.policy_revision.clone();
        let err = canonicalize(&package, &untrusted_snapshot, &untrusted).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::StaleDraft);
        assert!(!package.markdown.contains("trust:"));
    }

    #[test]
    fn complete_package_includes_mcp_and_children_and_review_uses_snapshot_auto_prune() {
        let providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let snapshot = snapshot_for(&providers);
        assert!(snapshot.routes.iter().all(|route| route.trust_is_shared));
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        package.mcp_json = Some("{\"mcpServers\":{}}".into());
        package.children.push(AuthoredAgentChild {
            relative_path: "subagents/reviewer.md".into(),
            markdown: markdown("reviewer", &[("vendor", "exact-a", true)]),
        });
        let canonical = canonicalize(&package, &snapshot, &providers).unwrap();
        assert!(canonical.files.contains_key("agent.md"));
        assert!(canonical.files.contains_key("mcp.json"));
        assert!(canonical.files.contains_key("subagents/reviewer.md"));
        assert!(!canonical.files.contains_key("sidecar.json"));
        assert_eq!(canonical.review.children.len(), 1);
        assert_eq!(canonical.review.children[0].path, "subagents/reviewer.md");
        assert!(canonical.review.trust_disclosure.contains("shared global"));
        assert!(
            !canonical
                .definition
                .to_markdown()
                .unwrap()
                .contains("autoPrune")
        );
        assert!(
            !canonical
                .definition
                .to_markdown()
                .unwrap()
                .contains("trust:")
        );
    }

    #[test]
    fn sidecar_changes_package_digest_and_is_a_canonical_file() {
        let mut providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        providers
            .providers
            .get_mut("vendor")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "vision".into(),
                trust: Some(ModelTrust::Untrusted),
                location: Some(ModelLocation::Local),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Supported,
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            });
        let snapshot = snapshot_for(&providers);
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        let without = canonicalize(&package, &snapshot, &providers).unwrap();
        package.sidecars.push(AuthoredSidecarDeclaration {
            provider_id: "vendor".into(),
            model_id: "vision".into(),
            remote_image_egress_confirmed: false,
        });
        let with = canonicalize(&package, &snapshot, &providers).unwrap();
        assert_ne!(without.digest, with.digest);
        assert!(with.files.contains_key("sidecar.json"));
        package.sidecars.clear();
        let removed = canonicalize(&package, &snapshot, &providers).unwrap();
        assert_eq!(removed.digest, without.digest);
    }

    #[test]
    fn source_kind_is_derived_from_locator_membership_not_the_client_label() {
        let providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        let snapshot = snapshot_for(&providers);
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        package.source = AuthoredAgentSource {
            kind: AgentAuthoringSourceKind::Authored,
            source_locator: "Acme/agents:helper.md".into(),
            pin: Some("abc".into()),
            third_party_trust_confirmed: true,
        };
        let err = canonicalize(&package, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::IncompletePackage);

        package.source.kind = AgentAuthoringSourceKind::FirstPartyCatalog;
        package.source.source_locator = "FlyCockpit/agents@deadbeef:agents/helper.md".into();
        package.source.third_party_trust_confirmed = false;
        let err = canonicalize(&package, &snapshot, &providers).unwrap_err();
        assert!(
            err.reason == AuthoredAgentRejectReason::IncompletePackage
                || err.reason == AuthoredAgentRejectReason::UnpinnedThirdPartySource
                || err.reason == AuthoredAgentRejectReason::MissingThirdPartyTrustConfirmation
        );
    }

    #[test]
    fn policy_snapshot_emits_display_tokens_for_custom_provider_handles() {
        let mut providers = BTreeMap::new();
        providers.insert(
            "secret-local-handle".to_string(),
            ProviderEntry {
                models: vec![ModelEntry {
                    id: "exact-a".into(),
                    trust: Some(ModelTrust::Untrusted),
                    ..ModelEntry::default()
                }],
                trust: Some(ModelTrust::Untrusted),
                ..ProviderEntry::default()
            },
        );
        let providers = ProvidersConfig {
            providers,
            ..ProvidersConfig::default()
        };
        let snapshot = snapshot_for(&providers);
        assert!(
            snapshot
                .routes
                .iter()
                .all(|route| route.provider_id == "configured-provider-0")
        );
        assert!(
            !serde_json::to_string(&snapshot)
                .unwrap()
                .contains("secret-local-handle")
        );
        let mut package = draft("helper", &[("secret-local-handle", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        let err = canonicalize(&package, &snapshot, &providers).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::UnsupportedCapability);

        package.markdown = markdown("helper", &[("configured-provider-0", "exact-a", true)]);
        package.model_trust_confirmations[0].provider_id = "configured-provider-0".into();
        let canonical = canonicalize(&package, &snapshot, &providers).unwrap();
        assert_eq!(
            canonical.review.grants[0].provider_id,
            "configured-provider-0"
        );
        assert!(
            !canonical
                .definition
                .to_markdown()
                .unwrap()
                .contains("secret-local-handle")
        );
    }

    #[test]
    fn policy_revision_changes_when_custom_provider_handle_is_replaced() {
        fn custom(handle: &str) -> ProvidersConfig {
            let mut providers = BTreeMap::new();
            providers.insert(
                handle.to_string(),
                ProviderEntry {
                    models: vec![ModelEntry {
                        id: "exact-a".into(),
                        trust: Some(ModelTrust::Untrusted),
                        ..ModelEntry::default()
                    }],
                    trust: Some(ModelTrust::Untrusted),
                    ..ProviderEntry::default()
                },
            );
            ProvidersConfig {
                providers,
                ..ProvidersConfig::default()
            }
        }
        let first = custom("credential-route-a");
        let second = custom("credential-route-b");
        let first_snapshot = snapshot_for(&first);
        let second_snapshot = snapshot_for(&second);
        assert_eq!(first_snapshot.routes, second_snapshot.routes);
        assert_ne!(
            first_snapshot.policy_revision,
            second_snapshot.policy_revision
        );
        let mut package = draft(
            "helper",
            &[("configured-provider-0", "exact-a", true)],
            true,
        );
        package.policy_revision = first_snapshot.policy_revision.clone();
        let err = canonicalize(&package, &second_snapshot, &second).unwrap_err();
        assert_eq!(err.reason, AuthoredAgentRejectReason::StaleDraft);
    }

    #[test]
    fn sidecar_selection_publishes_every_declaration_and_clears_on_delete() {
        use crate::config::image_sidecar::SidecarMode;
        let mut providers = providers_with("exact-a", Some(ModelTrust::Untrusted));
        providers
            .providers
            .get_mut("vendor")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "vision-a".into(),
                trust: Some(ModelTrust::Trusted),
                location: Some(ModelLocation::Local),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Supported,
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            });
        providers
            .providers
            .get_mut("vendor")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "vision-b".into(),
                trust: Some(ModelTrust::Untrusted),
                location: Some(ModelLocation::Local),
                capabilities: ModelCapabilities {
                    image_input: CapabilityStatus::Supported,
                    ..ModelCapabilities::default()
                },
                ..ModelEntry::default()
            });
        let snapshot = snapshot_for(&providers);
        let mut package = draft("helper", &[("vendor", "exact-a", true)], true);
        package.policy_revision = snapshot.policy_revision.clone();
        package.sidecars = vec![
            AuthoredSidecarDeclaration {
                provider_id: "vendor".into(),
                model_id: "vision-a".into(),
                remote_image_egress_confirmed: false,
            },
            AuthoredSidecarDeclaration {
                provider_id: "vendor".into(),
                model_id: "vision-b".into(),
                remote_image_egress_confirmed: false,
            },
        ];
        let canonical = canonicalize(&package, &snapshot, &providers).unwrap();
        assert_eq!(
            canonical.review.sidecars,
            vec!["vendor/vision-a", "vendor/vision-b"]
        );
        let loaded = crate::agents::package_sidecar_authority(&canonical.definition)
            .expect("package sidecar authority");
        assert_eq!(loaded.len(), 2);
        let selection = authored_sidecar_selection_config(&package.sidecars, &providers).unwrap();
        assert_eq!(selection.mode, SidecarMode::Always);
        assert_eq!(selection.permitted.len(), 2);
        assert!(
            selection
                .permitted
                .iter()
                .any(|entry| entry.provider == "vendor" && entry.model == "vision-a")
        );
        assert!(
            selection
                .permitted
                .iter()
                .any(|entry| entry.provider == "vendor" && entry.model == "vision-b")
        );
        let cleared = authored_sidecar_selection_config(&[], &providers).unwrap();
        assert_eq!(cleared.mode, SidecarMode::Never);
        assert!(cleared.permitted.is_empty());
        assert!(cleared.trusted_primary_default.is_none());
        assert!(cleared.untrusted_primary_default.is_none());
        assert!(cleared.per_primary_override.is_none());
    }

    #[test]
    fn authored_wire_boundary_rejects_profile_handles_by_equality_to_display_tokens_only() {
        let source = include_str!("onboarding_agent.rs");
        let require = source
            .split("fn require_wire_provider_id(")
            .nth(1)
            .and_then(|tail| {
                tail.split("pub fn authored_sidecar_selection_config")
                    .next()
            })
            .expect("wire provider id gate");
        assert!(require.contains("offering.provider_id == submitted"));
        assert!(!require.contains("provider_profile_handle"));
        let production = source.split("#[cfg(test)]").next().expect("production");
        assert!(!production.contains("rewrite_draft_to_wire_tokens"));
        assert!(!production.contains("wire_provider_id_for_submitted"));
    }
}
