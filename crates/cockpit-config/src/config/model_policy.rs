//! Model policy selection and capability resolution.

use crate::config::providers::{
    CapabilityStatus, ModelEntry, ModelLocation, ModelTrust, ProvidersConfig,
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
    Images,
    Reasoning,
    StructuredOutputs,
    Embeddings,
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
    pub trusted_only: bool,
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
            trusted_only: false,
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
    Untrusted {
        provider: String,
        model: String,
    },
    MissingCapability {
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
            Self::Untrusted { provider, model } => {
                write!(f, "model `{provider}:{model}` is untrusted")
            }
            Self::MissingCapability {
                provider,
                model,
                capability,
            } => {
                write!(
                    f,
                    "model `{provider}:{model}` is missing required capability {capability:?}"
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
    pub images: Option<bool>,
    pub context_tokens: Option<u32>,
    pub max_output_tokens: Option<u32>,
    pub reasoning: CapabilityStatus,
    pub structured_outputs: CapabilityStatus,
    pub embeddings: Option<bool>,
    pub embedding_dimensions: Option<u32>,
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

#[allow(dead_code)]
fn capability_satisfied(
    caps: &EffectiveModelCapabilities,
    required: RequiredModelCapability,
) -> bool {
    match required {
        RequiredModelCapability::ToolCalling => {
            matches!(caps.tool_calling, CapabilityStatus::Supported)
        }
        RequiredModelCapability::Images => caps.images == Some(true),
        RequiredModelCapability::Reasoning => matches!(caps.reasoning, CapabilityStatus::Supported),
        RequiredModelCapability::StructuredOutputs => {
            matches!(caps.structured_outputs, CapabilityStatus::Supported)
        }
        RequiredModelCapability::Embeddings => caps.embeddings == Some(true),
    }
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
    #[allow(dead_code)]
    pub fn resolve_capabilities(&self, provider: &str, model: &str) -> EffectiveModelCapabilities {
        let Some(entry) = self.providers.get(provider) else {
            return EffectiveModelCapabilities::default();
        };
        let model_entry = entry.models.iter().find(|m| m.id == model);
        let model_caps = model_entry.map(|m| &m.capabilities);
        let overrides = model_entry.map(|m| &m.capability_overrides);
        let provider_caps = &entry.capabilities;

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
            tool_calling: overrides.and_then(|o| o.tool_calling).unwrap_or_else(|| {
                status(
                    model_caps.map(|c| c.tool_calling),
                    provider_caps.tool_calling,
                )
            }),
            images: overrides
                .and_then(|o| o.images)
                .or_else(|| model_caps.and_then(|c| c.images))
                .or(provider_caps.images)
                .or_else(|| model_entry.and_then(|m| m.inputs.as_ref()?.images)),
            context_tokens: overrides
                .and_then(|o| o.context_tokens)
                .or_else(|| model_caps.and_then(|c| c.context_tokens))
                .or(provider_caps.context_tokens)
                .or_else(|| model_entry.and_then(|m| m.context_length)),
            max_output_tokens: overrides
                .and_then(|o| o.max_output_tokens)
                .or_else(|| model_caps.and_then(|c| c.max_output_tokens))
                .or(provider_caps.max_output_tokens),
            reasoning: overrides
                .and_then(|o| o.reasoning)
                .unwrap_or(detected_reasoning),
            structured_outputs: overrides
                .and_then(|o| o.structured_outputs)
                .unwrap_or_else(|| {
                    status(
                        model_caps.map(|c| c.structured_outputs),
                        provider_caps.structured_outputs,
                    )
                }),
            embeddings: overrides
                .and_then(|o| o.embeddings)
                .or_else(|| model_caps.and_then(|c| c.embeddings))
                .or_else(|| model_entry.and_then(|m| m.embeddings))
                .or(provider_caps.embeddings)
                .or(entry.embeddings),
            embedding_dimensions: overrides
                .and_then(|o| o.embedding_dimensions)
                .or_else(|| model_caps.and_then(|c| c.embedding_dimensions))
                .or_else(|| model_entry.and_then(|m| m.embedding_dimensions))
                .or(provider_caps.embedding_dimensions),
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
        if request.trusted_only && !self.resolve_trust(provider, &model.id).is_trusted() {
            return Err(ModelPolicyError::Untrusted {
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
        let caps = self.resolve_capabilities(provider, &model.id);
        for capability in &request.required_capabilities {
            if !capability_satisfied(&caps, *capability) {
                return Err(ModelPolicyError::MissingCapability {
                    provider: provider.to_string(),
                    model: model.id.clone(),
                    capability: *capability,
                });
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
                trusted_only: false,
                optimize: ModelOptimization::Balanced,
                role: Some("embedding_model"),
                agent: None,
            };
            let resolved = self
                .resolve_model_policy(&request)
                .map_err(EmbeddingModelResolutionError::Policy)?;
            let caps = self.resolve_capabilities(&resolved.provider, &resolved.model);
            return Ok(ResolvedEmbeddingModel {
                provider: resolved.provider,
                model: resolved.model,
                embedding_dimensions: caps.embedding_dimensions,
            });
        }

        let mut candidates = Vec::new();
        for (provider, entry) in &self.providers {
            for model in &entry.models {
                let caps = self.resolve_capabilities(provider, &model.id);
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
        let caps = self.resolve_capabilities(&resolved.provider, &resolved.model);
        Ok(ResolvedEmbeddingModel {
            provider: resolved.provider,
            model: resolved.model,
            embedding_dimensions: caps.embedding_dimensions,
        })
    }
}
