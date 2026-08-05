//! Model policy selection and capability resolution.

use crate::config::providers::{
    CapabilityStatus, ComputerUseCapability, Inputs, ModelCapabilityOverrides, ModelEntry,
    ModelLocation, ModelTrust, ProvidersConfig,
};

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ModelOptimization {
    Quality,
    Cost,
    #[default]
    Balanced,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredModelCapability {
    ToolCalling,
    /// Image input for chat/multimodal understanding.
    ImageInput,
    /// Audio input. Independent of image/video.
    AudioInput,
    /// Video input. Independent of image/audio.
    VideoInput,
    Reasoning,
    StructuredOutputs,
    Embeddings,
}

impl RequiredModelCapability {
    /// Stable machine error code for a failed requirement check.
    pub fn error_code(self, outcome: RequiredModelCapabilityOutcome) -> Option<&'static str> {
        match outcome {
            RequiredModelCapabilityOutcome::Allow => None,
            RequiredModelCapabilityOutcome::Unsupported => Some("model_capability_unsupported"),
            RequiredModelCapabilityOutcome::RequiresEntitlement => {
                Some("model_capability_requires_entitlement")
            }
            RequiredModelCapabilityOutcome::Unknown => Some("model_capability_unknown"),
        }
    }
}

/// Result of checking a [`RequiredModelCapability`] against effective caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredModelCapabilityOutcome {
    Allow,
    Unsupported,
    RequiresEntitlement,
    Unknown,
}

/// Winning provenance for one resolved input capability dimension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectiveCapabilitySource {
    /// Explicit per-model override (Auto is absent and never a source).
    Override,
    /// Fetched or checked-in model metadata on `ModelCapabilities`.
    Model,
    /// Provider-level model default on `ProviderCapabilities`.
    Provider,
    /// Legacy `inputs` membership (listed=Supported only).
    Legacy,
    #[default]
    None,
}

/// One independent input capability with status, provenance, and generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ResolvedInputCapability {
    pub status: CapabilityStatus,
    pub source: EffectiveCapabilitySource,
    /// Config/source generation supplied by the caller at resolve time. Stale
    /// cached results for a different generation must not fill a new identity.
    pub source_generation: u64,
}

impl Default for ResolvedInputCapability {
    fn default() -> Self {
        Self {
            status: CapabilityStatus::Unknown,
            source: EffectiveCapabilitySource::None,
            source_generation: 0,
        }
    }
}

impl ResolvedInputCapability {
    pub fn is_supported(self) -> bool {
        matches!(self.status, CapabilityStatus::Supported)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelPolicySelector<'a> {
    Exact(&'a str),
    Trust(ModelTrust),
    Category(&'a str),
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ModelPolicyRequest<'a> {
    pub selector: ModelPolicySelector<'a>,
    pub trust: Option<ModelTrust>,
    pub required_capabilities: Vec<RequiredModelCapability>,
    pub min_context_tokens: Option<u32>,
    pub require_subagent_invokable: bool,
    pub optimize: ModelOptimization,
    pub role: Option<&'a str>,
    pub agent: Option<&'a str>,
}

#[allow(dead_code)]
impl<'a> ModelPolicyRequest<'a> {
    pub fn subagent_category(category: &'a str) -> Self {
        Self {
            selector: ModelPolicySelector::Category(category),
            trust: None,
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::default(),
            role: Some(category),
            agent: None,
        }
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModelPolicy {
    pub provider: String,
    pub model: String,
    pub trust: ModelTrust,
    pub location: Option<ModelLocation>,
    pub quality_rank: i64,
    pub cost_rank: i64,
}

#[allow(dead_code)]
impl ResolvedModelPolicy {
    pub fn selector(&self) -> String {
        format!("{}:{}", self.provider, self.model)
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedEmbeddingModel {
    pub provider: String,
    pub model: String,
    pub embedding_dimensions: Option<u32>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EmbeddingModelResolutionError {
    NoConfiguredOrEligibleModel,
    Policy(ModelPolicyError),
}

impl std::fmt::Display for EmbeddingModelResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoConfiguredOrEligibleModel => {
                write!(
                    f,
                    "no configured or eligible embedding_model with embeddings capability"
                )
            }
            Self::Policy(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for EmbeddingModelResolutionError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ModelPolicyError {
    MalformedSelector(String),
    UnknownProvider(String),
    UnknownModel {
        provider: String,
        model: String,
    },
    NotSubagentInvokable {
        provider: String,
        model: String,
    },
    /// Required capability is known-unsupported for this model.
    CapabilityUnsupported {
        provider: String,
        model: String,
        capability: RequiredModelCapability,
    },
    /// Required capability status is unknown (no authoritative source).
    CapabilityUnknown {
        provider: String,
        model: String,
        capability: RequiredModelCapability,
    },
    /// Required capability needs an entitlement the model advertises.
    CapabilityRequiresEntitlement {
        provider: String,
        model: String,
        capability: RequiredModelCapability,
    },
    ContextTooSmall {
        provider: String,
        model: String,
        min: u32,
        actual: Option<u32>,
    },
    RestrictedByAvailability {
        provider: String,
        model: String,
    },
    NoEligibleModel(String),
}

impl ModelPolicyError {
    /// Map a failed required-capability outcome onto the distinct policy error.
    pub fn from_required_capability(
        provider: impl Into<String>,
        model: impl Into<String>,
        capability: RequiredModelCapability,
        outcome: RequiredModelCapabilityOutcome,
    ) -> Option<Self> {
        let provider = provider.into();
        let model = model.into();
        match outcome {
            RequiredModelCapabilityOutcome::Allow => None,
            RequiredModelCapabilityOutcome::Unsupported => Some(Self::CapabilityUnsupported {
                provider,
                model,
                capability,
            }),
            RequiredModelCapabilityOutcome::Unknown => Some(Self::CapabilityUnknown {
                provider,
                model,
                capability,
            }),
            RequiredModelCapabilityOutcome::RequiresEntitlement => {
                Some(Self::CapabilityRequiresEntitlement {
                    provider,
                    model,
                    capability,
                })
            }
        }
    }

    /// Machine-stable error code for capability failures (for remediation).
    pub fn capability_error_code(&self) -> Option<&'static str> {
        match self {
            Self::CapabilityUnsupported { capability, .. } => {
                capability.error_code(RequiredModelCapabilityOutcome::Unsupported)
            }
            Self::CapabilityUnknown { capability, .. } => {
                capability.error_code(RequiredModelCapabilityOutcome::Unknown)
            }
            Self::CapabilityRequiresEntitlement { capability, .. } => {
                capability.error_code(RequiredModelCapabilityOutcome::RequiresEntitlement)
            }
            _ => None,
        }
    }
}

impl std::fmt::Display for ModelPolicyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedSelector(selector) => write!(f, "malformed model selector `{selector}`"),
            Self::UnknownProvider(provider) => write!(f, "unknown provider `{provider}`"),
            Self::UnknownModel { provider, model } => {
                write!(f, "unknown model `{provider}:{model}`")
            }
            Self::NotSubagentInvokable { provider, model } => {
                write!(f, "model `{provider}:{model}` is not subagent-invokable")
            }
            Self::CapabilityUnsupported {
                provider,
                model,
                capability,
            } => {
                write!(
                    f,
                    "model `{provider}:{model}` does not support required capability {capability:?}"
                )
            }
            Self::CapabilityUnknown {
                provider,
                model,
                capability,
            } => {
                write!(
                    f,
                    "model `{provider}:{model}` has unknown support for required capability {capability:?}"
                )
            }
            Self::CapabilityRequiresEntitlement {
                provider,
                model,
                capability,
            } => {
                write!(
                    f,
                    "model `{provider}:{model}` requires entitlement for required capability {capability:?}"
                )
            }
            Self::ContextTooSmall {
                provider,
                model,
                min,
                actual,
            } => write!(
                f,
                "model `{provider}:{model}` context too small: required {min}, actual {actual:?}"
            ),
            Self::RestrictedByAvailability { provider, model } => {
                write!(
                    f,
                    "model `{provider}:{model}` is restricted by availability"
                )
            }
            Self::NoEligibleModel(selector) => write!(f, "no eligible model for `{selector}`"),
        }
    }
}

impl std::error::Error for ModelPolicyError {}

#[allow(dead_code)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EffectiveModelCapabilities {
    pub tool_calling: CapabilityStatus,
    pub image_input: ResolvedInputCapability,
    pub audio_input: ResolvedInputCapability,
    pub video_input: ResolvedInputCapability,
    pub context_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub reasoning: CapabilityStatus,
    pub structured_outputs: CapabilityStatus,
    pub prompt_cache_retention: CapabilityStatus,
    pub embeddings: Option<bool>,
    pub embedding_dimensions: Option<u32>,
    pub computer_use: Option<ComputerUseCapability>,
    /// Generation stamped on every resolved dimension for this call.
    pub config_generation: u64,
}

impl EffectiveModelCapabilities {
    /// True when image input is effectively supported. Does not imply audio,
    /// video, or computer-use eligibility.
    pub fn supports_image_input(&self) -> bool {
        self.image_input.is_supported()
    }

    pub fn supports_audio_input(&self) -> bool {
        self.audio_input.is_supported()
    }

    pub fn supports_video_input(&self) -> bool {
        self.video_input.is_supported()
    }
}

#[allow(dead_code)]
fn parse_policy_selector(selector: &str) -> Result<(String, String), ModelPolicyError> {
    let selector = selector.trim();
    if let Some((provider, model)) = selector.split_once(':') {
        if provider.trim().is_empty() || model.trim().is_empty() {
            return Err(ModelPolicyError::MalformedSelector(selector.to_string()));
        }
        return Ok((provider.trim().to_string(), model.trim().to_string()));
    }
    if let Some((provider, model)) = crate::config::provider::split_provider_model(selector) {
        return Ok((provider, model));
    }
    Err(ModelPolicyError::MalformedSelector(selector.to_string()))
}

/// Map an effective capability status onto the consumer-facing requirement
/// outcome table (allow / unsupported / requires-entitlement / unknown).
pub fn required_model_capability_outcome(
    caps: &EffectiveModelCapabilities,
    required: RequiredModelCapability,
) -> RequiredModelCapabilityOutcome {
    let status = match required {
        RequiredModelCapability::ToolCalling => caps.tool_calling,
        RequiredModelCapability::ImageInput => caps.image_input.status,
        RequiredModelCapability::AudioInput => caps.audio_input.status,
        RequiredModelCapability::VideoInput => caps.video_input.status,
        RequiredModelCapability::Reasoning => caps.reasoning,
        RequiredModelCapability::StructuredOutputs => caps.structured_outputs,
        RequiredModelCapability::Embeddings => match caps.embeddings {
            Some(true) => CapabilityStatus::Supported,
            Some(false) => CapabilityStatus::Unsupported,
            None => CapabilityStatus::Unknown,
        },
    };
    status_to_required_outcome(status)
}

pub fn status_to_required_outcome(status: CapabilityStatus) -> RequiredModelCapabilityOutcome {
    match status {
        CapabilityStatus::Supported => RequiredModelCapabilityOutcome::Allow,
        CapabilityStatus::Unsupported => RequiredModelCapabilityOutcome::Unsupported,
        CapabilityStatus::RequiresEntitlement => {
            RequiredModelCapabilityOutcome::RequiresEntitlement
        }
        CapabilityStatus::Unknown => RequiredModelCapabilityOutcome::Unknown,
    }
}

#[allow(dead_code)]
fn capability_satisfied(
    caps: &EffectiveModelCapabilities,
    required: RequiredModelCapability,
) -> bool {
    matches!(
        required_model_capability_outcome(caps, required),
        RequiredModelCapabilityOutcome::Allow
    )
}

/// Resolve one independent input dimension through the authoritative
/// precedence table:
///
/// 1. explicit model override Supported/Unsupported
/// 2. fetched/checked-in model metadata (any non-Unknown status)
/// 3. provider model default
/// 4. legacy `inputs` membership (listed=Supported; absence never Unsupported)
/// 5. Unknown / none
fn resolve_input_capability(
    override_status: Option<CapabilityStatus>,
    model_status: CapabilityStatus,
    provider_status: CapabilityStatus,
    legacy_listed: bool,
    config_generation: u64,
) -> ResolvedInputCapability {
    // Manual overrides are only Auto/Supported/Unsupported. Treat other
    // override values as Auto so RequiresEntitlement cannot be user-asserted.
    let manual = match override_status {
        Some(CapabilityStatus::Supported) => Some(CapabilityStatus::Supported),
        Some(CapabilityStatus::Unsupported) => Some(CapabilityStatus::Unsupported),
        Some(CapabilityStatus::RequiresEntitlement | CapabilityStatus::Unknown) | None => None,
    };
    if let Some(status) = manual {
        return ResolvedInputCapability {
            status,
            source: EffectiveCapabilitySource::Override,
            source_generation: config_generation,
        };
    }
    if !model_status.is_unknown() {
        return ResolvedInputCapability {
            status: model_status,
            source: EffectiveCapabilitySource::Model,
            source_generation: config_generation,
        };
    }
    if !provider_status.is_unknown() {
        return ResolvedInputCapability {
            status: provider_status,
            source: EffectiveCapabilitySource::Provider,
            source_generation: config_generation,
        };
    }
    if legacy_listed {
        return ResolvedInputCapability {
            status: CapabilityStatus::Supported,
            source: EffectiveCapabilitySource::Legacy,
            source_generation: config_generation,
        };
    }
    ResolvedInputCapability {
        status: CapabilityStatus::Unknown,
        source: EffectiveCapabilitySource::None,
        source_generation: config_generation,
    }
}

fn legacy_input_listed(inputs: Option<&Inputs>, modality: fn(&Inputs) -> Option<bool>) -> bool {
    inputs.and_then(modality) == Some(true)
}

#[allow(dead_code)]
fn sort_policy_candidates(candidates: &mut [ResolvedModelPolicy], optimize: ModelOptimization) {
    candidates.sort_by(|a, b| {
        let rank = match optimize {
            ModelOptimization::Quality | ModelOptimization::Balanced => b
                .quality_rank
                .cmp(&a.quality_rank)
                .then_with(|| a.cost_rank.cmp(&b.cost_rank)),
            ModelOptimization::Cost => a
                .cost_rank
                .cmp(&b.cost_rank)
                .then_with(|| b.quality_rank.cmp(&a.quality_rank)),
        };
        rank.then_with(|| b.trust.is_trusted().cmp(&a.trust.is_trusted()))
            .then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.model.cmp(&b.model))
    });
}

#[allow(dead_code)]
fn policy_selector_label(request: &ModelPolicyRequest<'_>) -> String {
    match request.selector {
        ModelPolicySelector::Exact(selector) => selector.to_string(),
        ModelPolicySelector::Trust(trust) => format!("{trust:?}"),
        ModelPolicySelector::Category(category) => category.to_string(),
    }
}

impl ProvidersConfig {
    /// Authoritative source-aware capability resolution for every consumer.
    ///
    /// `config_generation` is stamped onto each resolved dimension so late
    /// metadata for a previous selection cannot fill a new provider/model
    /// identity. Pass the caller's current config-snapshot generation.
    pub fn resolve_effective_model_capabilities(
        &self,
        provider: &str,
        model: &str,
        config_generation: u64,
    ) -> EffectiveModelCapabilities {
        let Some(entry) = self.providers.get(provider) else {
            // Provider removal/missing: every dimension is Unknown/none at the
            // caller's generation so late results cannot look like gen-0 stale
            // data for a different identity.
            let unknown = ResolvedInputCapability {
                status: CapabilityStatus::Unknown,
                source: EffectiveCapabilitySource::None,
                source_generation: config_generation,
            };
            return EffectiveModelCapabilities {
                image_input: unknown,
                audio_input: unknown,
                video_input: unknown,
                config_generation,
                ..EffectiveModelCapabilities::default()
            };
        };
        let model_entry = entry.models.iter().find(|m| m.id == model);
        let model_caps = model_entry.map(|m| &m.capabilities);
        let overrides = model_entry.map(|m| &m.capability_overrides);
        let empty_overrides = ModelCapabilityOverrides::default();
        let overrides = overrides.unwrap_or(&empty_overrides);
        let provider_caps = &entry.capabilities;
        let legacy_inputs = model_entry.and_then(|m| m.inputs.as_ref());

        let detected_reasoning = model_caps
            .map(|c| c.reasoning)
            .filter(|s| !s.is_unknown())
            .unwrap_or(provider_caps.reasoning);
        let detected_reasoning = if detected_reasoning.is_unknown()
            && model_entry.is_some_and(|m| {
                !m.thinking_modes.is_empty()
                    || m.capabilities
                        .reasoning_effort
                        .as_ref()
                        .is_some_and(|cap| !cap.values.is_empty())
            }) {
            CapabilityStatus::Supported
        } else {
            detected_reasoning
        };

        let status = |model_status: Option<CapabilityStatus>, provider_status| {
            model_status
                .filter(|s| !s.is_unknown())
                .unwrap_or(provider_status)
        };

        EffectiveModelCapabilities {
            tool_calling: overrides.tool_calling.unwrap_or_else(|| {
                status(
                    model_caps.map(|c| c.tool_calling),
                    provider_caps.tool_calling,
                )
            }),
            image_input: resolve_input_capability(
                overrides.image_input,
                model_caps
                    .map(|c| c.image_input)
                    .unwrap_or(CapabilityStatus::Unknown),
                provider_caps.image_input,
                legacy_input_listed(legacy_inputs, |i| i.images),
                config_generation,
            ),
            audio_input: resolve_input_capability(
                overrides.audio_input,
                model_caps
                    .map(|c| c.audio_input)
                    .unwrap_or(CapabilityStatus::Unknown),
                provider_caps.audio_input,
                legacy_input_listed(legacy_inputs, |i| i.audio),
                config_generation,
            ),
            video_input: resolve_input_capability(
                overrides.video_input,
                model_caps
                    .map(|c| c.video_input)
                    .unwrap_or(CapabilityStatus::Unknown),
                provider_caps.video_input,
                legacy_input_listed(legacy_inputs, |i| i.video),
                config_generation,
            ),
            context_tokens: overrides
                .context_tokens
                .or_else(|| model_caps.and_then(|c| c.context_tokens))
                .or(provider_caps.context_tokens)
                .or_else(|| model_entry.and_then(|m| m.context_length)),
            max_output_tokens: overrides
                .max_output_tokens
                .or_else(|| model_caps.and_then(|c| c.max_output_tokens))
                .or(provider_caps.max_output_tokens),
            reasoning: overrides.reasoning.unwrap_or(detected_reasoning),
            structured_outputs: overrides.structured_outputs.unwrap_or_else(|| {
                status(
                    model_caps.map(|c| c.structured_outputs),
                    provider_caps.structured_outputs,
                )
            }),
            prompt_cache_retention: overrides.prompt_cache_retention.unwrap_or_else(|| {
                status(
                    model_caps.map(|c| c.prompt_cache_retention),
                    provider_caps.prompt_cache_retention,
                )
            }),
            embeddings: overrides
                .embeddings
                .or_else(|| model_caps.and_then(|c| c.embeddings))
                .or_else(|| model_entry.and_then(|m| m.embeddings))
                .or(provider_caps.embeddings)
                .or(entry.embeddings),
            embedding_dimensions: overrides
                .embedding_dimensions
                .or_else(|| model_caps.and_then(|c| c.embedding_dimensions))
                .or_else(|| model_entry.and_then(|m| m.embedding_dimensions))
                .or(provider_caps.embedding_dimensions),
            computer_use: model_caps
                .and_then(|c| (!c.computer_use.is_empty()).then(|| c.computer_use.clone()))
                .or_else(|| {
                    (!provider_caps.computer_use.is_empty())
                        .then(|| provider_caps.computer_use.clone())
                }),
            config_generation,
        }
    }

    #[allow(dead_code)]
    pub fn resolve_model_policy(
        &self,
        request: &ModelPolicyRequest<'_>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        match request.selector {
            ModelPolicySelector::Exact(selector) => {
                let (provider, model) = parse_policy_selector(selector)?;
                self.resolve_exact_policy(&provider, &model, request)
            }
            ModelPolicySelector::Trust(trust) => {
                self.resolve_best_policy_candidate(request, Some(trust), None)
            }
            ModelPolicySelector::Category(category) => {
                if let Some(default) = self.category_defaults.get(category)
                    && let Ok(resolved) =
                        self.resolve_exact_policy(&default.provider, &default.model, request)
                {
                    return Ok(resolved);
                }
                self.resolve_best_policy_candidate(request, request.trust, Some(category))
            }
        }
    }

    #[allow(dead_code)]
    fn resolve_exact_policy(
        &self,
        provider: &str,
        model: &str,
        request: &ModelPolicyRequest<'_>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        let Some(entry) = self.providers.get(provider) else {
            return Err(ModelPolicyError::UnknownProvider(provider.to_string()));
        };
        let Some(model_entry) = entry.models.iter().find(|m| m.id == model) else {
            return Err(ModelPolicyError::UnknownModel {
                provider: provider.to_string(),
                model: model.to_string(),
            });
        };
        self.check_policy_candidate(provider, model_entry, request)?;
        Ok(self.resolved_policy(provider, model))
    }

    #[allow(dead_code)]
    fn resolve_best_policy_candidate(
        &self,
        request: &ModelPolicyRequest<'_>,
        trust_filter: Option<ModelTrust>,
        category: Option<&str>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        let mut candidates = Vec::new();
        for (provider, entry) in &self.providers {
            for model in &entry.models {
                let effective_trust_filter = trust_filter.or(request.trust);
                if effective_trust_filter
                    .is_some_and(|trust| self.resolve_trust(provider, &model.id) != trust)
                {
                    continue;
                }
                if category.is_some()
                    && !entry
                        .availability
                        .permits(category, request.role, request.agent)
                {
                    continue;
                }
                if category.is_some()
                    && !model
                        .availability
                        .permits(category, request.role, request.agent)
                {
                    continue;
                }
                if self
                    .check_policy_candidate(provider, model, request)
                    .is_ok()
                {
                    candidates.push(self.resolved_policy(provider, &model.id));
                }
            }
        }
        sort_policy_candidates(&mut candidates, request.optimize);
        candidates
            .into_iter()
            .next()
            .ok_or_else(|| ModelPolicyError::NoEligibleModel(policy_selector_label(request)))
    }

    #[allow(dead_code)]
    fn check_policy_candidate(
        &self,
        provider: &str,
        model: &ModelEntry,
        request: &ModelPolicyRequest<'_>,
    ) -> Result<(), ModelPolicyError> {
        if request.require_subagent_invokable
            && !self.resolve_subagent_invokable(provider, &model.id)
        {
            return Err(ModelPolicyError::NotSubagentInvokable {
                provider: provider.to_string(),
                model: model.id.clone(),
            });
        }
        if !self.providers.get(provider).is_some_and(|entry| {
            entry.availability.permits(
                match request.selector {
                    ModelPolicySelector::Category(category) => Some(category),
                    _ => None,
                },
                request.role,
                request.agent,
            )
        }) || !model.availability.permits(
            match request.selector {
                ModelPolicySelector::Category(category) => Some(category),
                _ => None,
            },
            request.role,
            request.agent,
        ) {
            return Err(ModelPolicyError::RestrictedByAvailability {
                provider: provider.to_string(),
                model: model.id.clone(),
            });
        }
        if request
            .trust
            .is_some_and(|trust| self.resolve_trust(provider, &model.id) != trust)
        {
            return Err(ModelPolicyError::NoEligibleModel(policy_selector_label(
                request,
            )));
        }
        let caps = self.resolve_effective_model_capabilities(
            provider,
            &model.id,
            self.resolution_generation,
        );
        for capability in &request.required_capabilities {
            let outcome = required_model_capability_outcome(&caps, *capability);
            if let Some(err) = ModelPolicyError::from_required_capability(
                provider,
                model.id.clone(),
                *capability,
                outcome,
            ) {
                return Err(err);
            }
        }
        if let Some(min) = request.min_context_tokens {
            let actual = caps.context_tokens;
            if actual.is_none_or(|actual| actual < min) {
                return Err(ModelPolicyError::ContextTooSmall {
                    provider: provider.to_string(),
                    model: model.id.clone(),
                    min,
                    actual,
                });
            }
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn resolved_policy(&self, provider: &str, model: &str) -> ResolvedModelPolicy {
        ResolvedModelPolicy {
            provider: provider.to_string(),
            model: model.to_string(),
            trust: self.resolve_trust(provider, model),
            location: self.resolve_location(provider, model),
            quality_rank: self.resolve_quality_rank(provider, model),
            cost_rank: self.resolve_cost_rank(provider, model),
        }
    }

    #[allow(dead_code)]
    pub fn resolve_embedding_model(
        &self,
        extended: &crate::config::extended::ExtendedConfig,
    ) -> Result<ResolvedEmbeddingModel, EmbeddingModelResolutionError> {
        if let Some(selector) = extended.embedding_model_ref() {
            let request = ModelPolicyRequest {
                selector: ModelPolicySelector::Exact(selector),
                trust: None,
                required_capabilities: vec![RequiredModelCapability::Embeddings],
                min_context_tokens: None,
                require_subagent_invokable: false,
                optimize: ModelOptimization::Balanced,
                role: Some("embedding_model"),
                agent: None,
            };
            let resolved = self
                .resolve_model_policy(&request)
                .map_err(EmbeddingModelResolutionError::Policy)?;
            let caps = self.resolve_effective_model_capabilities(
                &resolved.provider,
                &resolved.model,
                self.resolution_generation,
            );
            return Ok(ResolvedEmbeddingModel {
                provider: resolved.provider,
                model: resolved.model,
                embedding_dimensions: caps.embedding_dimensions,
            });
        }

        let mut candidates = Vec::new();
        for (provider, entry) in &self.providers {
            for model in &entry.models {
                let caps = self.resolve_effective_model_capabilities(
                    provider,
                    &model.id,
                    self.resolution_generation,
                );
                if caps.embeddings == Some(true) {
                    candidates.push(ResolvedModelPolicy {
                        provider: provider.clone(),
                        model: model.id.clone(),
                        trust: self.resolve_trust(provider, &model.id),
                        location: self.resolve_location(provider, &model.id),
                        quality_rank: self.resolve_quality_rank(provider, &model.id),
                        cost_rank: self.resolve_cost_rank(provider, &model.id),
                    });
                }
            }
        }
        sort_policy_candidates(&mut candidates, ModelOptimization::Balanced);
        let Some(resolved) = candidates.into_iter().next() else {
            return Err(EmbeddingModelResolutionError::NoConfiguredOrEligibleModel);
        };
        let caps = self.resolve_effective_model_capabilities(
            &resolved.provider,
            &resolved.model,
            self.resolution_generation,
        );
        Ok(ResolvedEmbeddingModel {
            provider: resolved.provider,
            model: resolved.model,
            embedding_dimensions: caps.embedding_dimensions,
        })
    }
}
