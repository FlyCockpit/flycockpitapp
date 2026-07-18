use std::path::Path;
use std::sync::Arc;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::{
    CapabilityStatus, EffectiveModelCapabilities, ModelOptimization, ModelPolicyError,
    ModelPolicyRequest, ModelPolicySelector, ModelTrust, ProvidersConfig, RequiredModelCapability,
    ResolvedModelPolicy,
};
use crate::engine::model::Model;
use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodingModelRole {
    Translation,
    CheapCode,
    SmartCode,
    Reasoning,
}

impl CodingModelRole {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "translation" => Some(Self::Translation),
            "cheap_code" => Some(Self::CheapCode),
            "smart_code" => Some(Self::SmartCode),
            "reasoning" => Some(Self::Reasoning),
            _ => None,
        }
    }

    pub fn configured_ref(self, extended: &ExtendedConfig) -> Option<&str> {
        match self {
            Self::Translation => extended.translation_model.as_deref(),
            Self::CheapCode => extended.cheap_code.as_deref(),
            Self::SmartCode => extended.smart_code.as_deref(),
            Self::Reasoning => extended.reasoning.as_deref(),
        }
        .map(str::trim)
        .filter(|s| !s.is_empty())
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Translation => "translation",
            Self::CheapCode => "cheap_code",
            Self::SmartCode => "smart_code",
            Self::Reasoning => "reasoning",
        }
    }
}

pub fn default_role_for_agent(agent: &str) -> Option<CodingModelRole> {
    match agent {
        "explore" | "docs" | "scout" => Some(CodingModelRole::CheapCode),
        "plan-author" | "deepthink" => Some(CodingModelRole::Reasoning),
        "builder" | "coder" | "bee" => Some(CodingModelRole::SmartCode),
        _ => None,
    }
}

fn default_required_capabilities_for_agent(agent: &str) -> Vec<RequiredModelCapability> {
    if agent == "deepthink" {
        vec![RequiredModelCapability::Reasoning]
    } else {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectorResolution {
    Unset,
    InvalidLiteral(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationModelSelector {
    Exact {
        selector: String,
        required_capabilities: Vec<RequiredModelCapability>,
        min_context_tokens: Option<u32>,
    },
    Category {
        category: Option<String>,
        trust: Option<ModelTrust>,
        optimize: ModelOptimization,
        required_capabilities: Vec<RequiredModelCapability>,
        min_context_tokens: Option<u32>,
    },
}

impl DelegationModelSelector {
    pub fn from_value(value: Option<&Value>) -> Result<Option<Self>, String> {
        let Some(value) = value else {
            return Ok(None);
        };
        if value.is_null() {
            return Ok(None);
        }
        if let Some(s) = value.as_str()
            && s.trim().is_empty()
        {
            return Ok(None);
        }
        let object = value.as_object().ok_or_else(|| {
            "`model` must be a structured selector object, e.g. {\"kind\":\"exact\",\"selector\":\"provider:model\"} or {\"kind\":\"category\",\"category\":\"cheap_code\"}".to_string()
        })?;
        let kind = object
            .get("kind")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "`model.kind` is required".to_string())?;
        let required_capabilities = parse_required_capabilities(object.get("requires"))?;
        let min_context_tokens = parse_min_context_tokens(object.get("min_context_tokens"))?;
        match kind {
            "exact" => {
                let selector = object
                    .get("selector")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        "`model.selector` is required for exact selectors".to_string()
                    })?;
                Ok(Some(Self::Exact {
                    selector: selector.to_string(),
                    required_capabilities,
                    min_context_tokens,
                }))
            }
            "category" => Ok(Some(Self::Category {
                category: object
                    .get("category")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string),
                trust: parse_trust(object.get("trust"))?,
                optimize: parse_optimization(object.get("optimize"))?,
                required_capabilities,
                min_context_tokens,
            })),
            other => Err(format!(
                "`model.kind` `{other}` is not supported; use `exact` or `category`"
            )),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            Self::Exact {
                selector,
                required_capabilities,
                min_context_tokens,
            } => selector_json(
                "exact",
                Some(("selector", selector.as_str())),
                None,
                ModelOptimization::Balanced,
                required_capabilities,
                *min_context_tokens,
            ),
            Self::Category {
                category,
                trust,
                optimize,
                required_capabilities,
                min_context_tokens,
            } => selector_json(
                "category",
                category.as_deref().map(|category| ("category", category)),
                *trust,
                *optimize,
                required_capabilities,
                *min_context_tokens,
            ),
        }
    }

    pub fn display_selector(&self) -> String {
        self.to_json().to_string()
    }
}

pub fn resolve_selector(
    selector: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<Arc<Model>, SelectorResolution> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(SelectorResolution::Unset);
    }
    if let Some(role) = CodingModelRole::from_name(selector) {
        let Some(model_ref) = role.configured_ref(extended) else {
            return Err(SelectorResolution::Unset);
        };
        return build_model(model_ref, providers, session_model)
            .map_err(|_| SelectorResolution::Unset);
    }
    build_model(selector, providers, session_model)
        .map_err(|_| SelectorResolution::InvalidLiteral(selector.to_string()))
}

pub fn resolve_policy_selector(
    selector: &DelegationModelSelector,
    agent_name: &str,
    _extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<Arc<Model>, SelectorResolution> {
    let default_category = default_role_for_agent(agent_name).map(CodingModelRole::as_str);
    let mut default_required = default_required_capabilities_for_agent(agent_name);
    let request = match selector {
        DelegationModelSelector::Exact {
            selector,
            required_capabilities,
            min_context_tokens,
        } => {
            let mut required_capabilities = required_capabilities.clone();
            for capability in default_required.drain(..) {
                if !required_capabilities.contains(&capability) {
                    required_capabilities.push(capability);
                }
            }
            ModelPolicyRequest {
                selector: ModelPolicySelector::Exact(selector),
                trust: None,
                required_capabilities,
                min_context_tokens: *min_context_tokens,
                require_subagent_invokable: true,
                trusted_only: false,
                optimize: ModelOptimization::Balanced,
                role: default_category,
                agent: Some(agent_name),
            }
        }
        DelegationModelSelector::Category {
            category,
            trust,
            optimize,
            required_capabilities,
            min_context_tokens,
        } => {
            let mut required_capabilities = required_capabilities.clone();
            for capability in default_required.drain(..) {
                if !required_capabilities.contains(&capability) {
                    required_capabilities.push(capability);
                }
            }
            let category = category.as_deref().or(default_category).ok_or_else(|| {
                SelectorResolution::InvalidLiteral(
                    "category model selector needs `category` for agents without a default model role"
                        .to_string(),
                )
            })?;
            ModelPolicyRequest {
                selector: if let Some(trust) = trust {
                    if category.is_empty() {
                        ModelPolicySelector::Trust(*trust)
                    } else {
                        ModelPolicySelector::Category(category)
                    }
                } else {
                    ModelPolicySelector::Category(category)
                },
                trust: *trust,
                required_capabilities,
                min_context_tokens: *min_context_tokens,
                require_subagent_invokable: true,
                trusted_only: trust.is_some_and(ModelTrust::is_trusted),
                optimize: *optimize,
                role: Some(category),
                agent: Some(agent_name),
            }
        }
    };
    build_policy_model(&request, providers, session_model)
}

pub fn resolve_delegated_model(
    agent_name: &str,
    frontmatter_model: Option<&str>,
    caller_model: Option<&DelegationModelSelector>,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<Arc<Model>, SelectorResolution> {
    if let Some(selector) = frontmatter_model.map(str::trim).filter(|s| !s.is_empty()) {
        return build_model(selector, providers, session_model)
            .map_err(|_| SelectorResolution::InvalidLiteral(selector.to_string()));
    }
    if extended.agent_chooses_subagent_model
        && let Some(selector) = caller_model
    {
        match resolve_policy_selector(selector, agent_name, extended, providers, session_model) {
            Ok(model) => return Ok(model),
            Err(SelectorResolution::Unset) => {}
            Err(err) => return Err(err),
        }
    }
    if let Some(role) = default_role_for_agent(agent_name)
        && let Some(model_ref) = role.configured_ref(extended)
        && let Ok(model) = build_model(model_ref, providers, session_model)
    {
        return Ok(model);
    }
    if let Some(role) = default_role_for_agent(agent_name) {
        let request = ModelPolicyRequest {
            selector: ModelPolicySelector::Category(role.as_str()),
            trust: None,
            required_capabilities: default_required_capabilities_for_agent(agent_name),
            min_context_tokens: None,
            require_subagent_invokable: true,
            trusted_only: false,
            optimize: ModelOptimization::Balanced,
            role: Some(role.as_str()),
            agent: Some(agent_name),
        };
        if let Ok(model) = build_policy_model(&request, providers, session_model) {
            return Ok(model);
        }
    }
    Ok(session_model.clone())
}

pub fn load_model_role_config(cwd: &Path) -> (ExtendedConfig, ProvidersConfig) {
    let extended = crate::config::extended::load_for_cwd(cwd);
    let providers = crate::secret_ref::load_effective(cwd);
    (extended, providers)
}

fn build_model(
    selector: &str,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> anyhow::Result<Arc<Model>> {
    let selector = selector.trim();
    if let Some((provider, model)) = selector.split_once(':') {
        return Model::for_provider_trusted_only(
            providers,
            provider,
            model,
            session_model.session_redact_table(),
            session_model.trusted_only_flag(),
        )
        .map(Arc::new);
    }
    let Some((provider, model)) = crate::config::provider::split_provider_model(selector) else {
        anyhow::bail!("model selector `{selector}` must be provider:model or provider/model");
    };
    Model::for_provider_trusted_only(
        providers,
        &provider,
        &model,
        session_model.session_redact_table(),
        session_model.trusted_only_flag(),
    )
    .map(Arc::new)
}

fn build_policy_model(
    request: &ModelPolicyRequest<'_>,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<Arc<Model>, SelectorResolution> {
    let resolved = providers
        .resolve_model_policy(request)
        .map_err(policy_error_message)
        .map_err(SelectorResolution::InvalidLiteral)?;
    Model::for_provider_trusted_only(
        providers,
        &resolved.provider,
        &resolved.model,
        session_model.session_redact_table(),
        session_model.trusted_only_flag(),
    )
    .map(Arc::new)
    .map_err(|e| SelectorResolution::InvalidLiteral(format!("{e:#}")))
}

pub fn render_model_discovery(caller_agent: &str, providers: &ProvidersConfig) -> String {
    let mut lines = vec![
        "subagent model discovery: use `task` with `payload.model` as one of these selector objects."
            .to_string(),
    ];
    let mut categories = std::collections::BTreeSet::new();
    categories.extend(["translation", "cheap_code", "smart_code", "reasoning"].map(str::to_string));
    categories.extend(providers.category_defaults.keys().cloned());
    for provider in providers.providers.values() {
        categories.extend(provider.availability.categories.iter().cloned());
        for model in &provider.models {
            categories.extend(model.availability.categories.iter().cloned());
        }
    }

    let mut category_lines = Vec::new();
    for category in categories {
        let request = ModelPolicyRequest {
            selector: ModelPolicySelector::Category(&category),
            trust: None,
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: true,
            trusted_only: false,
            optimize: ModelOptimization::Balanced,
            role: Some(&category),
            agent: Some(caller_agent),
        };
        if let Ok(resolved) = providers.resolve_model_policy(&request) {
            category_lines.push(format!(
                "- category {} -> {} ({}) selector={}",
                category,
                resolved.selector(),
                policy_summary(providers, &resolved),
                selector_json(
                    "category",
                    Some(("category", category.as_str())),
                    None,
                    ModelOptimization::Balanced,
                    &[],
                    None,
                )
            ));
        }
    }
    if !category_lines.is_empty() {
        lines.push("categories:".to_string());
        lines.extend(category_lines.into_iter().take(12));
    }

    let mut exact_lines = Vec::new();
    for (provider_id, provider) in &providers.providers {
        for model in &provider.models {
            let selector = format!("{provider_id}:{}", model.id);
            let request = ModelPolicyRequest {
                selector: ModelPolicySelector::Exact(&selector),
                trust: None,
                required_capabilities: Vec::new(),
                min_context_tokens: None,
                require_subagent_invokable: true,
                trusted_only: false,
                optimize: ModelOptimization::Balanced,
                role: None,
                agent: Some(caller_agent),
            };
            if let Ok(resolved) = providers.resolve_model_policy(&request) {
                let label = model.name.as_deref().unwrap_or(model.id.as_str());
                exact_lines.push(format!(
                    "- exact {} label={} ({}) selector={}",
                    resolved.selector(),
                    label,
                    policy_summary(providers, &resolved),
                    selector_json(
                        "exact",
                        Some(("selector", selector.as_str())),
                        None,
                        ModelOptimization::Balanced,
                        &[],
                        None,
                    )
                ));
            }
        }
    }
    if !exact_lines.is_empty() {
        lines.push("exact models:".to_string());
        lines.extend(exact_lines.into_iter().take(20));
    }
    if lines.len() == 1 {
        lines.push(
            "- none available; configure provider models with `subagent_invokable: true`"
                .to_string(),
        );
    } else {
        lines.insert(
            1,
            "models with context_tokens=unknown cannot satisfy an explicit min_context_tokens; omit the constraint unless the task truly requires a minimum context size."
                .to_string(),
        );
    }
    lines.join("\n")
}

fn parse_trust(value: Option<&Value>) -> Result<Option<ModelTrust>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(value) = value.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
        return Err("`model.trust` must be `trusted` or `untrusted`".to_string());
    };
    match value {
        "trusted" => Ok(Some(ModelTrust::Trusted)),
        "untrusted" => Ok(Some(ModelTrust::Untrusted)),
        other => Err(format!(
            "`model.trust` `{other}` is not supported; use `trusted` or `untrusted`"
        )),
    }
}

fn parse_optimization(value: Option<&Value>) -> Result<ModelOptimization, String> {
    let Some(value) = value else {
        return Ok(ModelOptimization::Balanced);
    };
    if value.is_null() {
        return Ok(ModelOptimization::Balanced);
    }
    let Some(value) = value.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
        return Err("`model.optimize` must be `quality`, `cost`, or `balanced`".to_string());
    };
    match value {
        "quality" => Ok(ModelOptimization::Quality),
        "cost" => Ok(ModelOptimization::Cost),
        "balanced" => Ok(ModelOptimization::Balanced),
        other => Err(format!(
            "`model.optimize` `{other}` is not supported; use `quality`, `cost`, or `balanced`"
        )),
    }
}

fn parse_required_capabilities(
    value: Option<&Value>,
) -> Result<Vec<RequiredModelCapability>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }
    let Some(items) = value.as_array() else {
        return Err("`model.requires` must be an array of capability names".to_string());
    };
    let mut out = Vec::new();
    for item in items {
        let Some(name) = item.as_str().map(str::trim).filter(|s| !s.is_empty()) else {
            return Err("`model.requires` entries must be strings".to_string());
        };
        let capability = match name {
            "tool_calling" => RequiredModelCapability::ToolCalling,
            "images" => RequiredModelCapability::Images,
            "reasoning" => RequiredModelCapability::Reasoning,
            "structured_outputs" => RequiredModelCapability::StructuredOutputs,
            other => {
                return Err(format!(
                    "`model.requires` capability `{other}` is not supported"
                ));
            }
        };
        if !out.contains(&capability) {
            out.push(capability);
        }
    }
    Ok(out)
}

fn parse_min_context_tokens(value: Option<&Value>) -> Result<Option<u32>, String> {
    let Some(value) = value else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let Some(n) = value.as_u64() else {
        return Err("`model.min_context_tokens` must be a positive integer".to_string());
    };
    if n == 0 {
        return Err("`model.min_context_tokens` must be at least 1; omit the field (or send null) when context size is not a requirement".to_string());
    }
    u32::try_from(n)
        .map(Some)
        .map_err(|_| "`model.min_context_tokens` is too large".to_string())
}

fn selector_json(
    kind: &str,
    string_field: Option<(&str, &str)>,
    trust: Option<ModelTrust>,
    optimize: ModelOptimization,
    required_capabilities: &[RequiredModelCapability],
    min_context_tokens: Option<u32>,
) -> Value {
    let mut object = serde_json::Map::from_iter([("kind".to_string(), Value::String(kind.into()))]);
    if let Some((key, value)) = string_field {
        object.insert(key.to_string(), Value::String(value.to_string()));
    }
    if let Some(trust) = trust {
        object.insert(
            "trust".to_string(),
            Value::String(
                match trust {
                    ModelTrust::Trusted => "trusted",
                    ModelTrust::Untrusted => "untrusted",
                }
                .to_string(),
            ),
        );
    }
    if optimize != ModelOptimization::Balanced {
        object.insert(
            "optimize".to_string(),
            Value::String(
                match optimize {
                    ModelOptimization::Quality => "quality",
                    ModelOptimization::Cost => "cost",
                    ModelOptimization::Balanced => "balanced",
                }
                .to_string(),
            ),
        );
    }
    if !required_capabilities.is_empty() {
        object.insert(
            "requires".to_string(),
            Value::Array(
                required_capabilities
                    .iter()
                    .map(|capability| {
                        Value::String(
                            match capability {
                                RequiredModelCapability::ToolCalling => "tool_calling",
                                RequiredModelCapability::Images => "images",
                                RequiredModelCapability::Reasoning => "reasoning",
                                RequiredModelCapability::StructuredOutputs => "structured_outputs",
                                RequiredModelCapability::Embeddings => "embeddings",
                            }
                            .to_string(),
                        )
                    })
                    .collect(),
            ),
        );
    }
    if let Some(min_context_tokens) = min_context_tokens {
        object.insert(
            "min_context_tokens".to_string(),
            Value::Number(serde_json::Number::from(min_context_tokens)),
        );
    }
    Value::Object(object)
}

fn policy_summary(providers: &ProvidersConfig, resolved: &ResolvedModelPolicy) -> String {
    let caps = providers.resolve_capabilities(&resolved.provider, &resolved.model);
    format!(
        "trust={} location={} quality_rank={} cost_rank={} capabilities={} context_tokens={}",
        match resolved.trust {
            ModelTrust::Trusted => "trusted",
            ModelTrust::Untrusted => "untrusted",
        },
        resolved
            .location
            .map(|location| format!("{location:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".to_string()),
        resolved.quality_rank,
        resolved.cost_rank,
        capability_summary(&caps),
        caps.context_tokens
            .map(|value| value.to_string())
            .unwrap_or_else(|| "unknown".to_string()),
    )
}

fn capability_summary(caps: &EffectiveModelCapabilities) -> String {
    let mut out = Vec::new();
    if caps.tool_calling == CapabilityStatus::Supported {
        out.push("tool_calling");
    }
    if caps.images == Some(true) {
        out.push("images");
    }
    if caps.reasoning == CapabilityStatus::Supported {
        out.push("reasoning");
    }
    if caps.structured_outputs == CapabilityStatus::Supported {
        out.push("structured_outputs");
    }
    if out.is_empty() {
        "none".to_string()
    } else {
        out.join(",")
    }
}

fn policy_error_message(error: ModelPolicyError) -> String {
    match error {
        ModelPolicyError::MalformedSelector(selector) => {
            format!("model selector `{selector}` must be provider:model or provider/model")
        }
        ModelPolicyError::UnknownProvider(provider) => {
            format!("model selector names unknown provider `{provider}`")
        }
        ModelPolicyError::UnknownModel { provider, model } => {
            format!("model selector `{provider}:{model}` is not configured")
        }
        ModelPolicyError::NotSubagentInvokable { provider, model } => {
            format!("model `{provider}:{model}` is not available for subagent invocation")
        }
        ModelPolicyError::Untrusted { provider, model } => {
            format!("model `{provider}:{model}` is untrusted")
        }
        ModelPolicyError::MissingCapability {
            provider,
            model,
            capability,
        } => {
            format!("model `{provider}:{model}` is missing required capability `{capability:?}`")
        }
        ModelPolicyError::ContextTooSmall {
            provider,
            model,
            min,
            actual,
        } => match actual {
            Some(actual) => format!(
                "model `{provider}:{model}` context window is too small: need at least {min}, got {actual}"
            ),
            None => format!(
                "model `{provider}:{model}` has an unreported context window and cannot satisfy min_context_tokens={min}; omit `min_context_tokens` (or send null) to allow this model, or use `task` with `intent=models` to list eligible models and known metadata"
            ),
        },
        ModelPolicyError::RestrictedByAvailability { provider, model } => {
            format!("model `{provider}:{model}` is hidden by availability policy")
        }
        ModelPolicyError::NoEligibleModel(selector) => {
            format!("no eligible subagent model matched `{selector}`")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::providers::{ActiveModelRef, ModelEntry, ProviderEntry, ProviderModelRef};
    use std::collections::BTreeMap;

    fn providers() -> ProvidersConfig {
        let mut providers = BTreeMap::new();
        providers.insert(
            "minimax".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                models: vec![
                    ModelEntry {
                        id: "MiniMax-M2".into(),
                        subagent_invokable: Some(true),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "MiniMax-M2.7".into(),
                        subagent_invokable: Some(true),
                        quality_rank: Some(10),
                        ..ModelEntry::default()
                    },
                    ModelEntry {
                        id: "hidden".into(),
                        subagent_invokable: Some(false),
                        ..ModelEntry::default()
                    },
                ],
                ..ProviderEntry::default()
            },
        );
        providers.insert(
            "openrouter".to_string(),
            ProviderEntry {
                url: "http://localhost:1/v1".into(),
                headers: vec![],
                ..ProviderEntry::default()
            },
        );
        ProvidersConfig {
            providers,
            active_model: Some(ActiveModelRef {
                provider: "openrouter".into(),
                model: "session".into(),
                reasoning_effort: None,
                thinking_mode: None,
            }),
            ..ProvidersConfig::default()
        }
    }

    fn session_model(cfg: &ProvidersConfig) -> Arc<Model> {
        Arc::new(Model::from_config(cfg, Arc::new(crate::redact::RedactionTable::empty())).unwrap())
    }

    #[test]
    fn resolver_ladder_frontmatter_choice_slot_session() {
        let mut providers = providers();
        providers.category_defaults.insert(
            "cheap_code".into(),
            ProviderModelRef {
                provider: "minimax".into(),
                model: "MiniMax-M2".into(),
            },
        );
        let session = session_model(&providers);
        let mut extended = ExtendedConfig {
            cheap_code: Some("minimax/MiniMax-M2".into()),
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        };

        let model = resolve_delegated_model(
            "explore",
            Some("minimax/MiniMax-M2.7"),
            None,
            &extended,
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "MiniMax-M2.7");

        let caller_selector = DelegationModelSelector::Exact {
            selector: "minimax:MiniMax-M2".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        let model = resolve_delegated_model(
            "builder",
            None,
            Some(&caller_selector),
            &extended,
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "MiniMax-M2");

        let category_selector = DelegationModelSelector::Category {
            category: Some("cheap_code".into()),
            trust: None,
            optimize: ModelOptimization::Quality,
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        let model = resolve_delegated_model(
            "explore",
            None,
            Some(&category_selector),
            &extended,
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "MiniMax-M2");

        let hidden_selector = DelegationModelSelector::Exact {
            selector: "minimax:hidden".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        match resolve_delegated_model(
            "explore",
            None,
            Some(&hidden_selector),
            &extended,
            &providers,
            &session,
        ) {
            Err(SelectorResolution::InvalidLiteral(_)) => {}
            Ok(model) => panic!(
                "hidden selector unexpectedly resolved to {}",
                model.model_id_ref()
            ),
            Err(other) => panic!("unexpected selector error: {other:?}"),
        }

        extended.agent_chooses_subagent_model = false;
        let model = resolve_delegated_model(
            "explore",
            None,
            Some(&caller_selector),
            &extended,
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "MiniMax-M2");

        let model = resolve_delegated_model("unknown", None, None, &extended, &providers, &session)
            .unwrap();
        assert!(Arc::ptr_eq(&model, &session));
    }

    #[test]
    fn parses_structured_selector_and_discovery_hides_uninvokable_models() {
        let providers = providers();
        let parsed = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "category",
            "category": "cheap_code",
            "trust": "trusted",
            "optimize": "cost",
            "requires": ["tool_calling"],
            "min_context_tokens": 2048
        })))
        .unwrap()
        .unwrap();
        assert!(matches!(
            parsed,
            DelegationModelSelector::Category {
                category: Some(_),
                trust: Some(ModelTrust::Trusted),
                optimize: ModelOptimization::Cost,
                ..
            }
        ));

        let discovery = render_model_discovery("Build", &providers);
        assert!(discovery.contains("minimax:MiniMax-M2"));
        assert!(!discovery.contains("minimax:hidden"));
        assert!(
            DelegationModelSelector::from_value(Some(&serde_json::json!("cheap_code"))).is_err()
        );
    }

    #[test]
    fn parse_min_context_and_optional_selector_fields_treat_null_as_absent() {
        assert_eq!(parse_min_context_tokens(Some(&Value::Null)).unwrap(), None);
        assert_eq!(parse_trust(Some(&Value::Null)).unwrap(), None);
        assert_eq!(
            parse_optimization(Some(&Value::Null)).unwrap(),
            ModelOptimization::Balanced
        );
        assert!(
            parse_required_capabilities(Some(&Value::Null))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn min_context_tokens_zero_rejected() {
        let error = parse_min_context_tokens(Some(&serde_json::json!(0))).unwrap_err();
        assert!(error.contains("at least 1"), "got: {error}");
        assert!(error.contains("omit"), "got: {error}");
        assert_eq!(
            parse_min_context_tokens(Some(&serde_json::json!(1))).unwrap(),
            Some(1)
        );
    }

    #[test]
    fn zero_min_rejected_for_known_context_model_too() {
        let error = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:MiniMax-M2",
            "min_context_tokens": 0
        })))
        .unwrap_err();
        assert!(error.contains("at least 1"), "got: {error}");
    }

    #[test]
    fn context_too_small_unknown_error_carries_recovery_path() {
        let unknown = policy_error_message(ModelPolicyError::ContextTooSmall {
            provider: "minimax".to_string(),
            model: "MiniMax-M2".to_string(),
            min: 1,
            actual: None,
        });
        for expected in ["min_context_tokens", "omit", "null", "intent=models"] {
            assert!(
                unknown.contains(expected),
                "missing `{expected}` in: {unknown}"
            );
        }

        let known = policy_error_message(ModelPolicyError::ContextTooSmall {
            provider: "minimax".to_string(),
            model: "MiniMax-M2".to_string(),
            min: 16_384,
            actual: Some(8_192),
        });
        assert!(known.contains("need at least 16384"), "got: {known}");
        assert!(known.contains("got 8192"), "got: {known}");
        assert!(!known.contains("omit"), "got: {known}");
    }

    #[test]
    fn explicit_min_with_unknown_context_still_rejects() {
        let providers = providers();
        let session = session_model(&providers);
        let extended = ExtendedConfig {
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        };
        let constrained = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:MiniMax-M2",
            "min_context_tokens": 1
        })))
        .unwrap()
        .unwrap();
        let error = match resolve_delegated_model(
            "explore",
            None,
            Some(&constrained),
            &extended,
            &providers,
            &session,
        ) {
            Err(error) => error,
            Ok(model) => panic!(
                "constrained unknown-context model unexpectedly resolved to {}",
                model.model_id_ref()
            ),
        };
        let SelectorResolution::InvalidLiteral(error) = error else {
            panic!("expected guidance error, got {error:?}");
        };
        assert!(error.contains("omit `min_context_tokens`"), "got: {error}");

        let unconstrained = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:MiniMax-M2"
        })))
        .unwrap()
        .unwrap();
        let resolved = resolve_delegated_model(
            "explore",
            None,
            Some(&unconstrained),
            &extended,
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(resolved.model_id_ref(), "MiniMax-M2");
    }

    #[test]
    fn discovery_warns_about_unknown_context_minimums() {
        let discovery = render_model_discovery("Build", &providers());
        assert!(discovery.contains("context_tokens=unknown"));
        assert!(discovery.contains("omit the constraint"));
        assert_eq!(discovery.matches("cannot satisfy").count(), 1);

        let empty = render_model_discovery("Build", &ProvidersConfig::default());
        assert!(empty.contains("none available"));
        assert!(!empty.contains("omit the constraint"));
    }

    #[test]
    fn minimal_exact_selector_with_nulled_optionals_resolves() {
        let minimal = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:MiniMax-M2"
        })))
        .unwrap()
        .unwrap();
        let nulled = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:MiniMax-M2",
            "category": null,
            "trust": null,
            "optimize": null,
            "requires": null,
            "min_context_tokens": null
        })))
        .unwrap()
        .unwrap();
        assert_eq!(nulled, minimal);

        let providers = providers();
        assert_eq!(
            providers
                .resolve_capabilities("minimax", "MiniMax-M2")
                .context_tokens,
            None,
            "regression requires an unknown context window"
        );
        let session = session_model(&providers);
        let resolved = resolve_delegated_model(
            "explore",
            None,
            Some(&nulled),
            &ExtendedConfig {
                agent_chooses_subagent_model: true,
                ..ExtendedConfig::default()
            },
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(resolved.model_id_ref(), "MiniMax-M2");
    }

    #[test]
    fn deepthink_defaults_to_reasoning_without_requiring_tool_calling() {
        let mut providers = providers();
        providers
            .providers
            .get_mut("minimax")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "reasoning-no-tools".into(),
                subagent_invokable: Some(true),
                availability: crate::config::providers::ModelAvailability {
                    categories: vec!["reasoning".to_string()],
                    ..Default::default()
                },
                capabilities: crate::config::providers::ModelCapabilities {
                    reasoning: CapabilityStatus::Supported,
                    tool_calling: CapabilityStatus::Unsupported,
                    ..Default::default()
                },
                ..Default::default()
            });
        providers.category_defaults.insert(
            "reasoning".into(),
            ProviderModelRef {
                provider: "minimax".into(),
                model: "reasoning-no-tools".into(),
            },
        );
        let session = session_model(&providers);

        let model = resolve_delegated_model(
            "deepthink",
            None,
            None,
            &ExtendedConfig::default(),
            &providers,
            &session,
        )
        .unwrap();

        assert_eq!(model.model_id_ref(), "reasoning-no-tools");
    }

    #[test]
    fn deepthink_honors_trusted_model_selector_filter() {
        let mut providers = providers();
        providers
            .providers
            .get_mut("minimax")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "untrusted-reasoning".into(),
                subagent_invokable: Some(true),
                trust: Some(ModelTrust::Untrusted),
                availability: crate::config::providers::ModelAvailability {
                    categories: vec!["reasoning".to_string()],
                    ..Default::default()
                },
                capabilities: crate::config::providers::ModelCapabilities {
                    reasoning: CapabilityStatus::Supported,
                    ..Default::default()
                },
                ..Default::default()
            });
        let session = session_model(&providers);
        let selector = DelegationModelSelector::Category {
            category: Some("reasoning".into()),
            trust: Some(ModelTrust::Trusted),
            optimize: ModelOptimization::Balanced,
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };

        match resolve_delegated_model(
            "deepthink",
            None,
            Some(&selector),
            &ExtendedConfig {
                agent_chooses_subagent_model: true,
                ..ExtendedConfig::default()
            },
            &providers,
            &session,
        ) {
            Err(SelectorResolution::InvalidLiteral(_)) => {}
            Ok(model) => panic!(
                "trusted selector unexpectedly resolved to {}",
                model.model_id_ref()
            ),
            Err(other) => panic!("unexpected selector error: {other:?}"),
        }
    }
}
