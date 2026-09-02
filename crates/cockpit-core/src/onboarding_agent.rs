//! Renderer-independent agent-install onboarding decisions.
//!
//! This module validates every security-sensitive answer before a front end
//! submits the pinned install and publishes configuration. It deliberately
//! has no "reasonable default" for model trust or remote image egress.

use std::collections::BTreeMap;

use anyhow::{Context, Result, ensure};
use cockpit_config::config::extended::ExtendedConfig;
use cockpit_config::config::image_sidecar::{
    SidecarMode, SidecarProviderModel, SidecarSelectionConfig,
};
use cockpit_config::config::providers::{
    ActiveModelRef, ModelLocation, ModelTrust, ProvidersConfig,
};

use crate::agents::{ToolSurfaceSelection, ToolTier};
use crate::daemon::agent_catalog::AgentCatalogEntry;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingModelTrust {
    Trusted,
    Untrusted,
}

impl From<OnboardingModelTrust> for ModelTrust {
    fn from(value: OnboardingModelTrust) -> Self {
        match value {
            OnboardingModelTrust::Trusted => Self::Trusted,
            OnboardingModelTrust::Untrusted => Self::Untrusted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnboardingToolMode {
    Enabled,
    Disabled,
    MontyOnly,
}

impl From<OnboardingToolMode> for ToolTier {
    fn from(value: OnboardingToolMode) -> Self {
        match value {
            OnboardingToolMode::Enabled => Self::Enabled,
            OnboardingToolMode::Disabled => Self::Disabled,
            OnboardingToolMode::MontyOnly => Self::Discoverable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingToolConfiguration {
    /// Preserve the definition author's direct/Monty placement preferences.
    AuthorDefaults,
    /// Explicitly place every named tool. Omitted tools retain the author
    /// default so the advanced toggle does not silently broaden grants.
    Advanced(BTreeMap<String, OnboardingToolMode>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnboardingSidecarSelection {
    Disabled,
    Model {
        provider: String,
        model: String,
        /// Must be true for public-cloud or unknown-location destinations.
        remote_image_egress_confirmed: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingAgentAnswers {
    pub catalog_revision: String,
    pub default_model_provider: String,
    pub default_model: String,
    /// Trust classification is never inherited or inferred during onboarding.
    pub model_trust: OnboardingModelTrust,
    pub model_trust_confirmed: bool,
    /// A manually supplied third-party source is deliberately separate from
    /// catalog selection: it must carry an explicit tag/commit and the user
    /// must pass the warning gate below.
    pub third_party_source: Option<String>,
    pub third_party_trust_confirmed: bool,
    pub tools: OnboardingToolConfiguration,
    pub sidecar: OnboardingSidecarSelection,
    pub make_default: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OnboardingAgentPlan {
    pub source_locator: String,
    pub agent_name: String,
    pub default_model: ActiveModelRef,
    pub model_trust: ModelTrust,
    pub tool_surface: ToolSurfaceSelection,
    pub sidecar: SidecarSelectionConfig,
    pub make_default: bool,
    pub third_party_trust_confirmed: bool,
}

impl OnboardingAgentPlan {
    /// Apply the already-confirmed plan to local config snapshots. Persistence
    /// remains with the caller's coordinated config transaction.
    pub fn apply_to_configs(
        &self,
        providers: &mut ProvidersConfig,
        extended: &mut ExtendedConfig,
    ) -> Result<()> {
        let provider = providers
            .providers
            .get_mut(&self.default_model.provider)
            .context("onboarding default provider disappeared")?;
        let model = provider
            .models
            .iter_mut()
            .find(|model| model.id == self.default_model.model)
            .context("onboarding default model disappeared")?;
        model.trust = Some(self.model_trust);
        if self.make_default {
            providers.active_model = Some(self.default_model.clone());
            extended.default_agent = Some(self.agent_name.clone());
        }
        extended.agent_runtime_defaults.insert(
            self.agent_name.clone(),
            crate::config::extended::AgentRuntimeDefaults {
                tool_tiers: self
                    .tool_surface
                    .tool_tiers
                    .iter()
                    .map(|(tool, tier)| {
                        let tier = match tier {
                            ToolTier::Enabled => {
                                crate::config::extended::AgentRuntimeToolTier::Enabled
                            }
                            ToolTier::Discoverable => {
                                crate::config::extended::AgentRuntimeToolTier::MontyOnly
                            }
                            ToolTier::Disabled => {
                                crate::config::extended::AgentRuntimeToolTier::Disabled
                            }
                        };
                        (tool.clone(), tier)
                    })
                    .collect(),
            },
        );
        extended.image_sidecar = self.sidecar.clone();
        Ok(())
    }
}

pub fn build_onboarding_agent_plan(
    entry: Option<&AgentCatalogEntry>,
    answers: OnboardingAgentAnswers,
    providers: &ProvidersConfig,
) -> Result<OnboardingAgentPlan> {
    ensure!(
        answers.model_trust_confirmed,
        "model trust classification requires explicit user confirmation"
    );
    ensure!(
        valid_commit_sha(&answers.catalog_revision),
        "agent catalog revision must be an immutable commit SHA"
    );
    if let Some(source_locator) = answers.third_party_source.as_deref() {
        let source =
            crate::daemon::agent_installation::CanonicalAgentSource::parse(source_locator)?;
        ensure!(
            !(source.owner == "FlyCockpit" && source.repository == "agents"),
            "first-party agents must be selected from the signed onboarding catalog"
        );
        ensure!(
            source.requested_revision.is_some(),
            "third-party onboarding sources must pin a commit or tag"
        );
        ensure!(
            answers.third_party_trust_confirmed,
            "third-party agent installation requires explicit security confirmation"
        );
        let provider = providers
            .providers
            .get(&answers.default_model_provider)
            .context("selected third-party default provider is not configured")?;
        ensure!(
            provider
                .models
                .iter()
                .any(|model| model.id == answers.default_model),
            "selected third-party default model is not configured"
        );
        let sidecar = resolve_sidecar_selection(&answers.sidecar, providers)?;
        return Ok(OnboardingAgentPlan {
            source_locator: source_locator.to_string(),
            agent_name: source.agent_name()?.to_string(),
            default_model: ActiveModelRef {
                provider: answers.default_model_provider,
                model: answers.default_model,
                reasoning_effort: None,
                thinking_mode: None,
                prompt_cache_retention: None,
            },
            model_trust: answers.model_trust.into(),
            // The fetched third-party definition remains the authority for
            // author tiers. It is not safe to invent an advanced surface
            // before parsing that pinned definition.
            tool_surface: ToolSurfaceSelection::default(),
            sidecar,
            make_default: answers.make_default,
            third_party_trust_confirmed: true,
        });
    }
    let entry = entry.context("selected onboarding agent is absent from the pinned catalog")?;
    entry
        .definition
        .validate_catalog_definition()
        .context("selected catalog definition is invalid")?;

    let offerings = crate::daemon::agent_installation::setup_offerings(providers);
    let primary = entry
        .definition
        .model_slots
        .get("primary")
        .context("selected agent has no primary model slot")?;
    let compatible = crate::agents::ranked_compatible_offerings(primary, &offerings, providers);
    ensure!(
        compatible.iter().any(|offering| {
            offering.provider_profile_handle == answers.default_model_provider
                && offering.model_id == answers.default_model
        }),
        "selected default model is not compatible with the agent's primary slot"
    );

    let tool_tiers = match answers.tools {
        OnboardingToolConfiguration::AuthorDefaults => {
            entry.definition.tool_tier_preferences.clone()
        }
        OnboardingToolConfiguration::Advanced(overrides) => {
            let mut tiers = entry.definition.tool_tier_preferences.clone();
            for (tool, mode) in overrides {
                ensure!(
                    crate::agents::known_tool_names().contains(&tool.as_str()),
                    "advanced tool configuration names unknown tool `{tool}`"
                );
                let tier: ToolTier = mode.into();
                ensure!(
                    crate::agents::legal_tool_tiers(&tool).contains(&tier),
                    "tool `{tool}` does not support requested onboarding tier"
                );
                tiers.insert(tool, tier);
            }
            tiers
        }
    };
    let tools = tool_tiers
        .iter()
        .filter(|(_, tier)| **tier != ToolTier::Disabled)
        .map(|(tool, _)| tool.clone())
        .collect();

    let sidecar = resolve_sidecar_selection(&answers.sidecar, providers)?;
    let agent_name = entry.catalog.slug.clone();
    Ok(OnboardingAgentPlan {
        source_locator: entry.pinned_source_locator(&answers.catalog_revision)?,
        agent_name,
        default_model: ActiveModelRef {
            provider: answers.default_model_provider,
            model: answers.default_model,
            reasoning_effort: None,
            thinking_mode: None,
            prompt_cache_retention: None,
        },
        model_trust: answers.model_trust.into(),
        tool_surface: ToolSurfaceSelection { tools, tool_tiers },
        sidecar,
        make_default: answers.make_default,
        third_party_trust_confirmed: false,
    })
}

/// Default sidecar choice. Only local/private self-hosted vision models are
/// eligible for silent preference. A cloud-only catalog deliberately returns
/// `None` so the UI must ask or offer disable.
pub fn preferred_self_hosted_sidecar(providers: &ProvidersConfig) -> Option<SidecarProviderModel> {
    providers
        .providers
        .iter()
        .find_map(|(provider_id, provider)| {
            provider.models.iter().find_map(|model| {
                let supports_images = providers
                    .resolve_effective_model_capabilities(
                        provider_id,
                        &model.id,
                        providers.resolution_generation,
                    )
                    .supports_image_input();
                let self_hosted = matches!(
                    providers.resolve_location(provider_id, &model.id),
                    Some(ModelLocation::Local | ModelLocation::PrivateRemote)
                );
                (supports_images && self_hosted).then(|| SidecarProviderModel {
                    provider: provider_id.clone(),
                    model: model.id.clone(),
                })
            })
        })
}

fn resolve_sidecar_selection(
    selection: &OnboardingSidecarSelection,
    providers: &ProvidersConfig,
) -> Result<SidecarSelectionConfig> {
    let OnboardingSidecarSelection::Model {
        provider,
        model,
        remote_image_egress_confirmed,
    } = selection
    else {
        return Ok(SidecarSelectionConfig {
            mode: SidecarMode::Never,
            ..SidecarSelectionConfig::default()
        });
    };
    ensure!(
        providers
            .providers
            .get(provider)
            .is_some_and(|entry| { entry.models.iter().any(|candidate| candidate.id == *model) }),
        "selected sidecar model is not configured"
    );
    ensure!(
        providers
            .resolve_effective_model_capabilities(provider, model, providers.resolution_generation,)
            .supports_image_input(),
        "selected sidecar model is not vision-capable"
    );
    let self_hosted = matches!(
        providers.resolve_location(provider, model),
        Some(ModelLocation::Local | ModelLocation::PrivateRemote)
    );
    ensure!(
        self_hosted || *remote_image_egress_confirmed,
        "remote sidecar requires explicit confirmation that screenshots and image content leave the machine"
    );
    let selected = SidecarProviderModel {
        provider: provider.clone(),
        model: model.clone(),
    };
    Ok(SidecarSelectionConfig {
        mode: SidecarMode::Always,
        trusted_primary_default: Some(selected.clone()),
        untrusted_primary_default: Some(selected),
        per_primary_override: None,
    })
}

fn valid_commit_sha(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
