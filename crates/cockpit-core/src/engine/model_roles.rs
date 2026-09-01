use std::sync::Arc;

use crate::config::extended::ExtendedConfig;
use crate::config::providers::{
    AvailabilityScope, CapabilityStatus, EffectiveModelCapabilities, ModelCustody, ModelLocation,
    ModelOptimization, ModelPolicyCriteria, ModelPolicyError, ModelPolicySelector, ModelTrust,
    NonSensitiveModelPolicyRequest, ProvidersConfig, RedactedRendering, RequiredModelCapability,
    ResolvedModelPolicy, SensitiveModelPolicyRequest, SensitivePayload, TrustedCustodyGrant,
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

/// A model-originated delegation selector.
///
/// It carries capability/category/cost intent only. Data custody is host
/// policy: every selection made from one of these is routed under a forced
/// [`ModelCustody::Untrusted`] filter, so an untrusted parent can never pull a
/// sensitive brief onto a capture-capable child. The only trusted-child path is
/// the separately host-authorized [`resolve_trusted_child_model`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DelegationModelSelector {
    Exact {
        selector: String,
        required_capabilities: Vec<RequiredModelCapability>,
        min_context_tokens: Option<u32>,
    },
    Category {
        category: Option<String>,
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
        reject_trust_selector(object.get("trust"))?;
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
                ModelOptimization::Balanced,
                required_capabilities,
                *min_context_tokens,
            ),
            Self::Category {
                category,
                optimize,
                required_capabilities,
                min_context_tokens,
            } => selector_json(
                "category",
                category.as_deref().map(|category| ("category", category)),
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

/// Resolve a **model-originated** `spawn` model argument.
///
/// `spawn` is a model-authored fan-out selector exactly like `task.payload.model`,
/// so it gets exactly the same treatment: the forced redacted-untrusted custody
/// filter plus the subagent-invokable and capability checks. Naming a
/// trusted-custody model here is a custody error, not an escalation — host
/// policy owns which children may hold raw content.
pub fn resolve_spawn_selector(
    selector: &str,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    resolve_spawn_selector_with_store(
        selector,
        agent_name,
        extended,
        providers,
        session_model,
        None,
    )
}

pub fn resolve_spawn_selector_with_store(
    selector: &str,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(SelectorResolution::Unset);
    }
    let target = match CodingModelRole::from_name(selector) {
        Some(role) => match role.configured_ref(extended) {
            Some(model_ref) => model_ref.to_string(),
            None => return Err(SelectorResolution::Unset),
        },
        None => selector.to_string(),
    };
    let criteria = ModelPolicyCriteria {
        selector: ModelPolicySelector::Exact(&target),
        required_capabilities: default_required_capabilities_for_agent(agent_name),
        min_context_tokens: None,
        require_subagent_invokable: true,
        optimize: ModelOptimization::Balanced,
        role: default_role_for_agent(agent_name).map(CodingModelRole::as_str),
        agent: Some(agent_name),
        availability: AvailabilityScope::Discovery,
    };
    build_redacted_policy_model(criteria, providers, session_model, store)
}

/// Resolve a **host-config** spawn model selector.
///
/// The host wrote this selector in a config file (`goalSupervision.coldSkepticModel`),
/// so custody is the target's own configured class — a self-hosted skeptic
/// stays trusted instead of hard-failing against the model-directed filter.
pub fn resolve_host_config_spawn_selector(
    selector: &str,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    resolve_host_config_spawn_selector_with_store(
        selector,
        agent_name,
        extended,
        providers,
        session_model,
        None,
    )
}

pub fn resolve_host_config_spawn_selector_with_store(
    selector: &str,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    let selector = selector.trim();
    if selector.is_empty() {
        return Err(SelectorResolution::Unset);
    }
    let target = match CodingModelRole::from_name(selector) {
        Some(role) => match role.configured_ref(extended) {
            Some(model_ref) => model_ref.to_string(),
            None => return Err(SelectorResolution::Unset),
        },
        None => selector.to_string(),
    };
    build_host_selected_policy_model(
        &target,
        "host_config_spawn_model",
        true,
        agent_name,
        extended,
        providers,
        session_model,
        store,
    )
}

pub fn resolve_policy_selector(
    selector: &DelegationModelSelector,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    resolve_policy_selector_with_store(
        selector,
        agent_name,
        extended,
        providers,
        session_model,
        None,
    )
}

pub fn resolve_policy_selector_with_store(
    selector: &DelegationModelSelector,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    let default_category = default_role_for_agent(agent_name).map(CodingModelRole::as_str);
    let mut default_required = default_required_capabilities_for_agent(agent_name);
    let criteria = match selector {
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
            ModelPolicyCriteria {
                selector: ModelPolicySelector::Exact(selector),
                required_capabilities,
                min_context_tokens: *min_context_tokens,
                require_subagent_invokable: true,
                optimize: ModelOptimization::Balanced,
                role: default_category,
                agent: Some(agent_name),
                // `HostNamedTarget` is the exemption for a target the *host*
                // named, and this selector is model-authored — the model
                // being specific about which model it wants is not a reason
                // to drop the host's allowlist. Availability and custody are
                // orthogonal controls: custody keeps this off a trusted
                // endpoint, `Discovery` keeps it inside the provider/model
                // allowlists the host configured (including `agents`, which
                // is exactly how a host scopes a model to one agent). This
                // matches the model-authored `spawn.model` path.
                availability: AvailabilityScope::Discovery,
            }
        }
        DelegationModelSelector::Category {
            category,
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
            ModelPolicyCriteria {
                selector: ModelPolicySelector::Category(category),
                required_capabilities,
                min_context_tokens: *min_context_tokens,
                require_subagent_invokable: true,
                optimize: *optimize,
                role: Some(category),
                agent: Some(agent_name),
                availability: AvailabilityScope::Discovery,
            }
        }
    };
    build_redacted_policy_model(criteria, providers, session_model, store)
}

pub fn resolve_delegated_model(
    agent_name: &str,
    frontmatter_model: Option<&str>,
    caller_model: Option<&DelegationModelSelector>,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
) -> Result<Arc<Model>, SelectorResolution> {
    resolve_delegated_model_with_store(
        agent_name,
        frontmatter_model,
        caller_model,
        extended,
        providers,
        session_model,
        None,
    )
}

pub fn resolve_delegated_model_with_store(
    agent_name: &str,
    frontmatter_model: Option<&str>,
    caller_model: Option<&DelegationModelSelector>,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<Arc<Model>, SelectorResolution> {
    resolve_delegated_model_with_custody(
        agent_name,
        frontmatter_model,
        caller_model,
        extended,
        providers,
        session_model,
        store,
    )
    .map(|(model, custody)| {
        for diagnostic in custody.diagnostics() {
            tracing::debug!(
                stage = diagnostic.stage,
                outcome = diagnostic.outcome,
                reason = %diagnostic.reason,
                "delegation custody"
            );
        }
        model
    })
}

/// The full delegation resolution: the child model plus the custody decision it
/// was routed under, including a diagnostic for every branch that was skipped
/// on custody grounds. `resolve_delegated_model` is the thin wrapper that logs
/// and drops the custody record.
pub fn resolve_delegated_model_with_custody(
    agent_name: &str,
    frontmatter_model: Option<&str>,
    caller_model: Option<&DelegationModelSelector>,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    let mut diagnostics = Vec::new();

    // 1. Agent-file frontmatter: host-authored, so custody is the target's own
    //    configured class.
    if let Some(selector) = frontmatter_model.map(str::trim).filter(|s| !s.is_empty()) {
        return build_host_selected_policy_model(
            selector,
            "frontmatter_model",
            false,
            agent_name,
            extended,
            providers,
            session_model,
            store.clone(),
        )
        .map_err(|_| SelectorResolution::InvalidLiteral(selector.to_string()))
        .map(|(model, mut custody)| {
            custody.prepend_diagnostics(diagnostics);
            (model, custody)
        });
    }

    // 2. Model-originated selector: forced redacted-untrusted custody.
    if extended.agent_chooses_subagent_model
        && let Some(selector) = caller_model
    {
        match resolve_policy_selector_with_store(
            selector,
            agent_name,
            extended,
            providers,
            session_model,
            store.clone(),
        ) {
            Ok((model, mut custody)) => {
                custody.prepend_diagnostics(diagnostics);
                return Ok((model, custody));
            }
            Err(SelectorResolution::Unset) => {}
            Err(err) => return Err(err),
        }
    }

    // 3. Configured role default: host-authored, custody is the target's class.
    if let Some(role) = default_role_for_agent(agent_name)
        && let Some(model_ref) = role.configured_ref(extended)
    {
        match build_host_selected_policy_model(
            model_ref,
            "configured_role_default",
            false,
            agent_name,
            extended,
            providers,
            session_model,
            store.clone(),
        ) {
            Ok((model, mut custody)) => {
                custody.prepend_diagnostics(diagnostics);
                return Ok((model, custody));
            }
            Err(error) => diagnostics.push(CustodyDiagnostic::skipped(
                "configured_role_default",
                format!(
                    "`{model_ref}` was not routable: {}",
                    selector_reason(&error)
                ),
            )),
        }
    }

    // 4. Category default / best candidate for the role. This is reached
    //    without a host-named target, so it keeps the forced redacted-untrusted
    //    filter — a trusted category default is skipped here rather than
    //    silently taken, and the skip is recorded.
    if let Some(role) = default_role_for_agent(agent_name) {
        let criteria = ModelPolicyCriteria {
            selector: ModelPolicySelector::Category(role.as_str()),
            required_capabilities: default_required_capabilities_for_agent(agent_name),
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Balanced,
            role: Some(role.as_str()),
            agent: Some(agent_name),
            availability: AvailabilityScope::Discovery,
        };
        match build_redacted_policy_model(criteria, providers, session_model, store.clone()) {
            Ok((model, mut custody)) => {
                custody.prepend_diagnostics(diagnostics);
                return Ok((model, custody));
            }
            Err(error) => diagnostics.push(CustodyDiagnostic::skipped(
                "role_category_default",
                format!(
                    "no candidate passed the forced untrusted custody filter for role `{}`: {}",
                    role.as_str(),
                    selector_reason(&error)
                ),
            )),
        }
    }

    // 5. Session model. Host-chosen (the user picked it), so it is kept, but
    //    the fallthrough is never silent: the skipped branches above are
    //    recorded and the session model's own custody class is resolved.
    diagnostics.push(CustodyDiagnostic::fallback(
        "session_model",
        format!(
            "fell back to the host-selected session model `{}:{}`",
            session_model.provider_id(),
            session_model.model_id_ref()
        ),
    ));
    let custody = host_selected_custody_for_model(providers, session_model, extended, diagnostics);
    Ok((session_model.clone(), custody))
}

/// Host-authorized trusted-child selection.
///
/// This is the host-authorized selection path for the sealed-acquisition
/// coordinator. Nothing a model can write reaches it: the caller must already
/// hold host authority, and the returned [`TrustedCustodyGrant`] identifies a
/// capture-capable destination. It is not a model egress capability.
///
/// A grant is minted only when the resolved model's [`ModelLocation`] is
/// `Local`. A trusted child on a `Remote`, `PrivateRemote`, or unknown
/// location fails closed with no capture grant. Custody/trust and location are
/// both required; harness mode is never consulted.
pub fn resolve_trusted_child_model(
    category: &str,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, TrustedCustodyGrant), SelectorResolution> {
    let criteria = ModelPolicyCriteria {
        selector: if category.is_empty() {
            ModelPolicySelector::Any
        } else {
            ModelPolicySelector::Category(category)
        },
        required_capabilities: default_required_capabilities_for_agent(agent_name),
        min_context_tokens: None,
        require_subagent_invokable: true,
        optimize: ModelOptimization::Quality,
        role: (!category.is_empty()).then_some(category),
        agent: Some(agent_name),
        // This is a *scan* (`Any`/`Category`), not an exact host-named target,
        // so allowlists gate it. `HostNamedTarget` is only ever correct for an
        // explicitly named `provider:model`.
        availability: AvailabilityScope::Discovery,
    };
    let request = SensitiveModelPolicyRequest::new(
        criteria,
        ModelCustody::Trusted,
        SensitivePayload::redacted_for_custody(
            ModelCustody::Trusted,
            Arc::new(SessionTableRedaction::new(
                &session_model.session_redact_table(),
            )),
        ),
    )
    .map_err(|error| SelectorResolution::InvalidLiteral(policy_error_message(error)))?;
    let resolved = providers
        .resolve_sensitive_model_policy(&request)
        .map_err(policy_error_message)
        .map_err(SelectorResolution::InvalidLiteral)?;
    // AC5: capture-capable child selection requires a host-`Local` model. A
    // `Remote`, `PrivateRemote`, or missing location fails closed before a
    // capture grant can be returned. The child still receives only the
    // enforced redacted rendering.
    if resolved.policy.location != Some(ModelLocation::Local) {
        return Err(SelectorResolution::InvalidLiteral(
            "trusted-child capture requires a host-local model location".to_string(),
        ));
    }
    let grant = resolved.trusted_custody_grant().cloned().ok_or_else(|| {
        SelectorResolution::InvalidLiteral(
            "trusted-child selection did not produce a trusted custody grant".to_string(),
        )
    })?;
    let model = Model::for_provider_optional_store(
        providers,
        &resolved.policy.provider,
        &resolved.policy.model,
        session_model.session_redact_table(),
        store,
    )
    .map(Arc::new)
    .map_err(|e| SelectorResolution::InvalidLiteral(format!("{e:#}")))?;
    Ok((model, grant))
}

pub fn load_model_role_config(
    config: &crate::daemon::session_worker::SessionConfigHandle,
) -> (ExtendedConfig, ProvidersConfig) {
    config.configs()
}

// `build_model` is gone on purpose. It built a `Model` straight from a selector
// string with no custody decision, no availability check, and no
// subagent-invokable check — the escalation seam `spawn` used to reach. Every
// route now goes through `build_redacted_policy_model` (model-originated) or
// `build_host_selected_policy_model` (host-authored).

/// Renders a delegation brief for one untrusted target through the session
/// redaction table. There is no raw variant here on purpose: model-directed
/// delegation only ever produces redacted renderings.
pub(crate) struct SessionTableRedaction(Arc<crate::redact::RedactionTable>);

impl SessionTableRedaction {
    /// Wrap the session table for untrusted delegation. The table is taken in
    /// its *enforced* view, so `redact.enabled = false` cannot turn this
    /// rendering into a passthrough: the config opt-out is honored for trusted
    /// routes only, and this type exists solely to render for untrusted ones.
    /// The field is private so no caller can install a non-enforcing table.
    pub(crate) fn new(session_redact: &Arc<crate::redact::RedactionTable>) -> Self {
        Self(crate::redact::RedactionTable::enforced_arc(
            session_redact.clone(),
        ))
    }
}

impl RedactedRendering for SessionTableRedaction {
    fn render_redacted(&self, _provider: &str, _model: &str, source: &str) -> String {
        self.0.scrub(source)
    }
}

/// One custody decision recorded for a delegation branch. Carries no payload
/// material and no redacted literals — only the branch, the outcome, and why.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CustodyDiagnostic {
    pub stage: &'static str,
    pub outcome: &'static str,
    pub reason: String,
}

impl CustodyDiagnostic {
    pub(crate) fn skipped(stage: &'static str, reason: String) -> Self {
        Self {
            stage,
            outcome: "skipped",
            reason,
        }
    }

    pub(crate) fn fallback(stage: &'static str, reason: String) -> Self {
        Self {
            stage,
            outcome: "fallback",
            reason,
        }
    }

    pub(crate) fn selected(stage: &'static str, reason: String) -> Self {
        Self {
            stage,
            outcome: "selected",
            reason,
        }
    }
}

/// The custody decision a delegated route was resolved under, plus the payload
/// rendering policy that decision requires.
///
/// Production dispatch renders the child's brief through
/// [`DelegationCustody::render_brief`], so the typed payload sits on the real
/// delegation path rather than only in tests.
#[derive(Clone)]
pub struct DelegationCustody {
    payload: SensitivePayload,
    route: ResolvedModelPolicy,
    grant: Option<TrustedCustodyGrant>,
    /// Fail-closed rendering when no payload rendering applies.
    session_redact: Arc<crate::redact::RedactionTable>,
    diagnostics: Vec<CustodyDiagnostic>,
}

impl std::fmt::Debug for DelegationCustody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DelegationCustody")
            .field("custody", &self.payload.custody())
            .field("route", &self.route.selector())
            .field("granted", &self.grant.is_some())
            .field("diagnostics", &self.diagnostics)
            .finish()
    }
}

impl DelegationCustody {
    pub fn custody(&self) -> ModelCustody {
        self.payload.custody()
    }

    pub fn route(&self) -> &ResolvedModelPolicy {
        &self.route
    }

    pub fn diagnostics(&self) -> &[CustodyDiagnostic] {
        &self.diagnostics
    }

    pub(crate) fn prepend_diagnostics(&mut self, mut earlier: Vec<CustodyDiagnostic>) {
        if earlier.is_empty() {
            return;
        }
        earlier.append(&mut self.diagnostics);
        self.diagnostics = earlier;
    }

    /// Render the child's brief for the resolved destination.
    ///
    /// Every destination receives the enforced session-redaction rendering.
    /// A trusted grant can authorize host-mediated capture, but never lets a
    /// model receive a sealed literal in its brief.
    pub fn render_brief(&self, brief: &str) -> String {
        self.session_redact.enforced().scrub(brief)
    }

    /// Routing diagnostics for this delegation: trust, the explicit custody
    /// filter and its reason, and the per-branch custody record.
    pub fn routing_diagnostics_json(&self) -> Value {
        let routing = self.route.routing_diagnostics();
        serde_json::json!({
            "provider": routing.provider,
            "model": routing.model,
            "trust": routing.trust,
            "custody_filter": routing.custody_filter,
            "custody_filter_reason": routing.custody_filter_reason,
            "custody_branches": self.diagnostics,
        })
    }
}

/// Resolve a delegated model under a forced [`ModelCustody::Untrusted`]
/// filter. Every model-originated delegation route (`task.payload.model`,
/// `spawn.model`) and the role/category default go through here, so a brief
/// authored by a model can only ever reach a redacted-custody child.
fn build_redacted_policy_model(
    criteria: ModelPolicyCriteria<'_>,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    let session_redact = session_model.session_redact_table();
    let payload = SensitivePayload::redacted_for_custody(
        ModelCustody::Untrusted,
        Arc::new(SessionTableRedaction::new(&session_redact)),
    );
    let request = SensitiveModelPolicyRequest::new(criteria, ModelCustody::Untrusted, payload)
        .map_err(|error| SelectorResolution::InvalidLiteral(policy_error_message(error)))?;
    let resolved = providers
        .resolve_sensitive_model_policy(&request)
        .map_err(policy_error_message)
        .map_err(SelectorResolution::InvalidLiteral)?;
    let model = Model::for_provider_optional_store(
        providers,
        &resolved.policy.provider,
        &resolved.policy.model,
        session_redact.clone(),
        store,
    )
    .map(Arc::new)
    .map_err(|e| SelectorResolution::InvalidLiteral(format!("{e:#}")))?;
    let custody = DelegationCustody {
        payload: SensitivePayload::redacted_for_custody(
            ModelCustody::Untrusted,
            Arc::new(SessionTableRedaction::new(&session_redact)),
        ),
        route: resolved.policy.clone(),
        grant: resolved.trusted_custody_grant().cloned(),
        session_redact,
        diagnostics: vec![CustodyDiagnostic::selected(
            "model_directed_selector",
            format!(
                "routed `{}` under the forced untrusted custody filter",
                resolved.policy.selector()
            ),
        )],
    };
    Ok((model, custody))
}

pub(crate) fn split_selector(selector: &str) -> Option<(String, String)> {
    let selector = selector.trim();
    if let Some((provider, model)) = selector.split_once(':') {
        if provider.trim().is_empty() || model.trim().is_empty() {
            return None;
        }
        return Some((provider.trim().to_string(), model.trim().to_string()));
    }
    crate::config::provider::split_provider_model(selector)
}

pub(crate) fn custody_payload_for(
    custody: ModelCustody,
    session_redact: &Arc<crate::redact::RedactionTable>,
) -> SensitivePayload {
    SensitivePayload::redacted_for_custody(
        custody,
        Arc::new(SessionTableRedaction::new(session_redact)),
    )
}

pub(crate) fn custody_for_trust(trust: ModelTrust) -> ModelCustody {
    match trust {
        ModelTrust::Trusted => ModelCustody::Trusted,
        ModelTrust::Untrusted => ModelCustody::Untrusted,
    }
}

/// Resolve a **host-authored** selection (agent-file frontmatter, a configured
/// role default, or the session's own model).
///
/// The host named the target, so custody is the target's own configured trust
/// class — host-authorized rather than a forced filter. The route is still
/// custody-typed, so nothing reaches dispatch with an undecided custody class.
#[allow(clippy::too_many_arguments)]
fn build_host_selected_policy_model(
    selector: &str,
    stage: &'static str,
    require_subagent_invokable: bool,
    agent_name: &str,
    extended: &ExtendedConfig,
    providers: &ProvidersConfig,
    session_model: &Arc<Model>,
    store: Option<crate::credentials::CredentialStore>,
) -> Result<(Arc<Model>, DelegationCustody), SelectorResolution> {
    let Some((provider, model_id)) = split_selector(selector) else {
        return Err(SelectorResolution::InvalidLiteral(format!(
            "model selector `{selector}` must be provider:model or provider/model"
        )));
    };
    let custody = custody_for_trust(providers.resolve_trust(&provider, &model_id));
    let session_redact = session_model.session_redact_table();
    let normalized = format!("{provider}:{model_id}");
    let criteria = ModelPolicyCriteria {
        selector: ModelPolicySelector::Exact(&normalized),
        required_capabilities: default_required_capabilities_for_agent(agent_name),
        min_context_tokens: None,
        require_subagent_invokable,
        optimize: ModelOptimization::Balanced,
        role: default_role_for_agent(agent_name).map(CodingModelRole::as_str),
        agent: Some(agent_name),
        // The host named this exact provider/model, so `availability` (which
        // scopes discovery) does not gate it.
        availability: AvailabilityScope::HostNamedTarget,
    };
    let request = SensitiveModelPolicyRequest::new(
        criteria,
        custody,
        custody_payload_for(custody, &session_redact),
    )
    .map_err(|error| SelectorResolution::InvalidLiteral(policy_error_message(error)))?;
    let resolved = providers
        .resolve_sensitive_model_policy(&request)
        .map_err(policy_error_message)
        .map_err(SelectorResolution::InvalidLiteral)?;
    let model = Model::for_provider_optional_store(
        providers,
        &resolved.policy.provider,
        &resolved.policy.model,
        session_redact.clone(),
        store,
    )
    .map(Arc::new)
    .map_err(|e| SelectorResolution::InvalidLiteral(format!("{e:#}")))?;
    let custody_record = DelegationCustody {
        payload: custody_payload_for(custody, &session_redact),
        route: resolved.policy.clone(),
        grant: resolved.trusted_custody_grant().cloned(),
        session_redact,
        diagnostics: vec![CustodyDiagnostic::selected(
            stage,
            format!(
                "host-authored target `{}` routed under its configured {} custody",
                resolved.policy.selector(),
                custody.as_str()
            ),
        )],
    };
    Ok((model, custody_record))
}

/// The custody record for an already-built, host-chosen model (the session
/// model fallback). No re-resolution happens: the user picked this model, so
/// its own configured trust class is the custody class.
fn host_selected_custody_for_model(
    providers: &ProvidersConfig,
    model: &Arc<Model>,
    extended: &ExtendedConfig,
    mut diagnostics: Vec<CustodyDiagnostic>,
) -> DelegationCustody {
    let provider = model.provider_id().to_string();
    let model_id = model.model_id_ref().to_string();
    let trust = providers.resolve_trust(&provider, &model_id);
    let custody = custody_for_trust(trust);
    let session_redact = model.session_redact_table();
    // A host-chosen trusted model can be capture-capable. Re-run the host-named
    // typed request to obtain its route-bound capture grant rather than
    // fabricating one. `render_brief` always uses the session scrub.
    let grant = if custody == ModelCustody::Trusted {
        let selector = format!("{provider}:{model_id}");
        let criteria = ModelPolicyCriteria {
            selector: ModelPolicySelector::Exact(&selector),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: false,
            optimize: ModelOptimization::Balanced,
            role: None,
            agent: None,
            availability: AvailabilityScope::HostNamedTarget,
        };
        SensitiveModelPolicyRequest::new(
            criteria,
            custody,
            custody_payload_for(custody, &session_redact),
        )
        .ok()
        .and_then(|request| providers.resolve_sensitive_model_policy(&request).ok())
        .and_then(|resolved| resolved.trusted_custody_grant().cloned())
    } else {
        None
    };
    let route = ResolvedModelPolicy {
        provider: provider.clone(),
        model: model_id.clone(),
        trust,
        location: providers.resolve_location(&provider, &model_id),
        quality_rank: providers.resolve_quality_rank(&provider, &model_id),
        cost_rank: providers.resolve_cost_rank(&provider, &model_id),
        custody_filter: Some(custody),
    };
    diagnostics.push(CustodyDiagnostic::selected(
        "host_selected_model",
        format!(
            "host-chosen model `{provider}:{model_id}` runs under its configured {} custody",
            custody.as_str()
        ),
    ));
    DelegationCustody {
        payload: custody_payload_for(custody, &session_redact),
        grant,
        route,
        session_redact,
        diagnostics,
    }
}

/// Render a delegation brief for an already-resolved child model.
///
/// The child's route was decided by [`resolve_delegated_model_with_custody`];
/// this renders the brief for that destination at dispatch time. Every child,
/// including a capture-capable trusted child, receives the session
/// redaction-table rendering.
pub fn render_brief_for_model(
    providers: &ProvidersConfig,
    model: &Arc<Model>,
    extended: &ExtendedConfig,
    brief: &str,
) -> String {
    inherited_custody_for_model(providers, model, extended).render_brief(brief)
}

/// The custody record for a child that inherits an already-built, host-chosen
/// parent model (no selector supplied). Custody is that model's own configured
/// trust class.
pub fn inherited_custody_for_model(
    providers: &ProvidersConfig,
    model: &Arc<Model>,
    extended: &ExtendedConfig,
) -> DelegationCustody {
    host_selected_custody_for_model(providers, model, extended, Vec::new())
}

fn selector_reason(error: &SelectorResolution) -> String {
    match error {
        SelectorResolution::Unset => "selector unset".to_string(),
        SelectorResolution::InvalidLiteral(message) => message.clone(),
    }
}

pub fn render_model_discovery(caller_agent: &str, providers: &ProvidersConfig) -> String {
    let mut lines = vec![
        "subagent model discovery: use `task` with `payload.model` as one of these selector objects."
            .to_string(),
        "data custody is host policy: selectors cannot request a capture-capable child, and delegated routing always applies the redacted untrusted filter."
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

    // Discovery listing carries no payload at all, so it is the one delegation
    // surface that legitimately proves non-sensitivity and omits custody.
    let header_lines = lines.len();
    // Trusted (host-policy-only) models are deliberately NOT advertised here.
    // Delegated routing applies the forced untrusted filter, so listing them
    // would hand the model copy-paste selectors that always fail.
    let mut host_policy_only = 0usize;
    let mut category_lines = Vec::new();
    for category in categories {
        let request = NonSensitiveModelPolicyRequest::proven_non_sensitive(ModelPolicyCriteria {
            selector: ModelPolicySelector::Category(&category),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::Balanced,
            role: Some(&category),
            agent: Some(caller_agent),
            availability: AvailabilityScope::Discovery,
        });
        if let Ok(resolved) = providers.resolve_non_sensitive_model_policy(&request) {
            if resolved.trust.is_trusted() {
                host_policy_only += 1;
                continue;
            }
            category_lines.push(format!(
                "- category {} -> {} ({}) selector={}",
                category,
                resolved.selector(),
                policy_summary(providers, &resolved),
                selector_json(
                    "category",
                    Some(("category", category.as_str())),
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
            let request =
                NonSensitiveModelPolicyRequest::proven_non_sensitive(ModelPolicyCriteria {
                    selector: ModelPolicySelector::Exact(&selector),
                    required_capabilities: Vec::new(),
                    min_context_tokens: None,
                    require_subagent_invokable: true,
                    optimize: ModelOptimization::Balanced,
                    role: None,
                    agent: Some(caller_agent),
                    availability: AvailabilityScope::Discovery,
                });
            if let Ok(resolved) = providers.resolve_non_sensitive_model_policy(&request) {
                if resolved.trust.is_trusted() {
                    host_policy_only += 1;
                    continue;
                }
                let label = model.name.as_deref().unwrap_or(model.id.as_str());
                exact_lines.push(format!(
                    "- exact {} label={} ({}) selector={}",
                    resolved.selector(),
                    label,
                    policy_summary(providers, &resolved),
                    selector_json(
                        "exact",
                        Some(("selector", selector.as_str())),
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
    if lines.len() == header_lines {
        lines.push(
            "- none available; configure provider models with `subagent_invokable: true`"
                .to_string(),
        );
    } else {
        lines.insert(
            header_lines,
            "models with context_tokens=unknown cannot satisfy an explicit min_context_tokens; omit the constraint unless the task truly requires a minimum context size."
                .to_string(),
        );
    }
    if host_policy_only > 0 {
        lines.push(format!(
            "{host_policy_only} configured model(s) run under trusted custody and are host-policy-only: they are not listed here, are not selectable, and naming one is rejected."
        ));
    }
    lines.join("\n")
}

/// A model-originated selector may not name a custody class. Host policy owns
/// data custody, so `trust` is refused outright rather than quietly ignored;
/// `null` still means "field absent".
fn reject_trust_selector(value: Option<&Value>) -> Result<(), String> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    Err(
        "`model.trust` is not a delegation selector: data custody is host policy, and delegated routing always applies the redacted untrusted filter"
            .to_string(),
    )
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
            // Breaking multimodal names only — no legacy `images`/`audio`/`video`
            // aliases (pre-release: convert configs to image_input/audio_input/video_input).
            "image_input" => RequiredModelCapability::ImageInput,
            "audio_input" => RequiredModelCapability::AudioInput,
            "video_input" => RequiredModelCapability::VideoInput,
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
    optimize: ModelOptimization,
    required_capabilities: &[RequiredModelCapability],
    min_context_tokens: Option<u32>,
) -> Value {
    let mut object = serde_json::Map::from_iter([("kind".to_string(), Value::String(kind.into()))]);
    if let Some((key, value)) = string_field {
        object.insert(key.to_string(), Value::String(value.to_string()));
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
                                RequiredModelCapability::ImageInput => "image_input",
                                RequiredModelCapability::AudioInput => "audio_input",
                                RequiredModelCapability::VideoInput => "video_input",
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

/// Routing diagnostics for model selection and data custody.
fn policy_summary(providers: &ProvidersConfig, resolved: &ResolvedModelPolicy) -> String {
    let caps = providers.resolve_effective_model_capabilities(
        &resolved.provider,
        &resolved.model,
        providers.resolution_generation,
    );
    let diagnostics = resolved.routing_diagnostics();
    format!(
        "trust={} custody_filter={} location={} quality_rank={} cost_rank={} capabilities={} context_tokens={}",
        diagnostics.trust,
        diagnostics.custody_filter.unwrap_or("none"),
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
    if caps.supports_image_input() {
        out.push("image_input");
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
        ModelPolicyError::CapabilityUnsupported {
            provider,
            model,
            capability,
        } => {
            format!(
                "model `{provider}:{model}` does not support required capability `{capability:?}`"
            )
        }
        ModelPolicyError::CapabilityUnknown {
            provider,
            model,
            capability,
        } => {
            format!(
                "model `{provider}:{model}` has unknown support for required capability `{capability:?}`"
            )
        }
        ModelPolicyError::CapabilityRequiresEntitlement {
            provider,
            model,
            capability,
        } => {
            format!(
                "model `{provider}:{model}` requires entitlement for required capability `{capability:?}`"
            )
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
        // Deliberately non-discriminating: naming the provider/model (or its
        // trust class) would let a model enumerate the host's trusted
        // identities one probe at a time. The typed error keeps the full
        // detail for logs and diagnostics.
        ModelPolicyError::CustodyMismatch { .. } => {
            "the requested model is not selectable for delegation; data custody is host policy and delegation never falls back to another model"
                .to_string()
        }
        ModelPolicyError::CustodyPayloadMismatch { requested, payload } => format!(
            "requested {} custody but the payload was built for {} custody",
            requested.as_str(),
            payload.as_str()
        ),
        // Also non-discriminating: a failover downgrade refusal must not name
        // the candidate to a model-facing surface.
        ModelPolicyError::CustodyDowngradeRefused { .. } => {
            "failover is upgrade-only and refused this candidate; data custody is host policy"
                .to_string()
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
                prompt_cache_retention: None,
            }),
            ..ProvidersConfig::default()
        }
    }

    fn session_model(cfg: &ProvidersConfig) -> Arc<Model> {
        Arc::new(Model::from_config(cfg, Arc::new(crate::redact::RedactionTable::empty())).unwrap())
    }

    #[test]
    fn delegated_frontmatter_model_resolves_vault_named_secret() {
        let db = crate::db::Db::open_in_memory().unwrap();
        let vault = crate::secure_key::vault_for_db(&db).unwrap();
        let mut store = crate::credentials::CredentialStore::from_vault(vault).unwrap();
        store.set_named_secret("child-token", "vault-only-delegated-secret-xyz");
        store.save().unwrap();

        let mut providers = providers();
        let session = session_model(&providers);
        providers.providers.get_mut("minimax").unwrap().headers =
            vec![crate::config::providers::HeaderSpec {
                name: "Authorization".into(),
                value: "Bearer $secret:child-token".into(),
            }];
        assert!(
            resolve_delegated_model(
                "explore",
                Some("minimax:MiniMax-M2"),
                None,
                &ExtendedConfig::default(),
                &providers,
                &session,
            )
            .is_err(),
            "frontmatter $secret model must fail without a store"
        );
        let model = resolve_delegated_model_with_store(
            "explore",
            Some("minimax:MiniMax-M2"),
            None,
            &ExtendedConfig::default(),
            &providers,
            &session,
            Some(store),
        )
        .expect("frontmatter $secret model must resolve through the injected store");
        assert_eq!(model.provider_id(), "minimax");
        assert_eq!(model.model_id_ref(), "MiniMax-M2");
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
                optimize: ModelOptimization::Cost,
                ..
            }
        ));

        let discovery = render_model_discovery("Build", &providers);
        assert!(discovery.contains("minimax:MiniMax-M2"));
        assert!(!discovery.contains("minimax:hidden"));
        assert!(discovery.contains("trust="));
        assert!(
            DelegationModelSelector::from_value(Some(&serde_json::json!("cheap_code"))).is_err()
        );
    }

    #[test]
    fn parse_min_context_and_optional_selector_fields_treat_null_as_absent() {
        assert_eq!(parse_min_context_tokens(Some(&Value::Null)).unwrap(), None);
        // `trust: null` still means "field absent"; a *value* is refused.
        assert!(reject_trust_selector(Some(&Value::Null)).is_ok());
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
                .resolve_effective_model_capabilities(
                    "minimax",
                    "MiniMax-M2",
                    providers.resolution_generation,
                )
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

    /// AC7. Replaces `deepthink_honors_trusted_model_selector_filter`, which
    /// asserted the now-rejected behavior that a model-authored selector could
    /// name `trust: trusted` and have routing honor it. Host policy owns data
    /// custody: a model-originated selector can no longer express a custody
    /// class at all, and every delegated route is filtered to redacted
    /// untrusted custody, so an untrusted parent can neither choose nor fall
    /// through to a trusted child for sensitive context.
    #[test]
    fn model_directed_delegation_cannot_escalate_to_trusted_custody() {
        let mut providers = providers();
        providers
            .providers
            .get_mut("minimax")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "trusted-reasoning".into(),
                subagent_invokable: Some(true),
                trust: Some(ModelTrust::Trusted),
                // AC5: the coordinator mints a capture grant only for a
                // host-local trusted child, so this trusted child is
                // `Local`. The `Remote`/`PrivateRemote`/missing fail-closed
                // paths are proven separately in `trusted_child_*` below.
                location: Some(ModelLocation::Local),
                quality_rank: Some(1_000),
                // Deliberately *not* availability-restricted. This test is
                // about custody, so the trusted child must be fully permitted
                // by availability — otherwise step 3 would be rejected by the
                // allowlist and would prove nothing about custody. Availability
                // scoping of model-authored exact selectors is covered
                // separately by
                // `model_authored_exact_selector_cannot_bypass_agent_allowlist`.
                capabilities: crate::config::providers::ModelCapabilities {
                    reasoning: CapabilityStatus::Supported,
                    ..Default::default()
                },
                ..Default::default()
            });
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
        let extended = ExtendedConfig {
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        };

        // 1. The selector schema no longer accepts a custody class at all.
        let error = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "category",
            "category": "reasoning",
            "trust": "trusted"
        })))
        .unwrap_err();
        assert!(error.contains("host policy"), "got: {error}");
        let error = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:trusted-reasoning",
            "trust": "untrusted"
        })))
        .unwrap_err();
        assert!(error.contains("`model.trust`"), "got: {error}");

        // 2. A category selector cannot fall through to the trusted child even
        //    though it outranks every untrusted candidate on quality.
        let category = DelegationModelSelector::Category {
            category: Some("reasoning".into()),
            optimize: ModelOptimization::Quality,
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        let model = resolve_delegated_model(
            "deepthink",
            None,
            Some(&category),
            &extended,
            &providers,
            &session,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "untrusted-reasoning");

        // 3. An exact selector naming the trusted child is rejected before
        //    dispatch and never falls back to a different model.
        let exact = DelegationModelSelector::Exact {
            selector: "minimax:trusted-reasoning".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        match resolve_delegated_model(
            "deepthink",
            None,
            Some(&exact),
            &extended,
            &providers,
            &session,
        ) {
            Err(SelectorResolution::InvalidLiteral(message)) => {
                assert!(message.contains("custody"), "got: {message}");
                assert!(message.contains("never falls back"), "got: {message}");
            }
            Ok(model) => panic!(
                "exact trusted selector unexpectedly resolved to {}",
                model.model_id_ref()
            ),
            Err(other) => panic!("unexpected selector error: {other:?}"),
        }

        // 4. Only the separately host-authorized coordinator may take the
        //    trusted child, and it is the sole minter of a custody grant.
        let (trusted, grant) = resolve_trusted_child_model(
            "reasoning",
            "deepthink",
            &extended,
            &providers,
            &session,
            None,
        )
        .unwrap();
        assert_eq!(trusted.model_id_ref(), "trusted-reasoning");
        assert_eq!(grant.provider(), "minimax");
        assert_eq!(grant.model(), "trusted-reasoning");
    }

    /// Regression: a model-authored `exact` selector is **not** a host-named
    /// target, so it stays inside the host's availability allowlists.
    ///
    /// `AvailabilityScope::HostNamedTarget` skips both the provider-level and
    /// the model-level allowlist, so granting it to a model-authored selector
    /// let a subagent name any configured model by `provider:model` and reach
    /// it regardless of the `agents`/`roles`/`categories` scoping the host
    /// wrote. Custody still held, so this was never a custody escalation — it
    /// was an availability-policy bypass, which is its own control.
    ///
    /// The target here is deliberately **untrusted** and subagent-invokable
    /// with no capability or context floor, so custody, invokability and
    /// capabilities all pass: availability is the only control that can
    /// reject it, and the positive control below proves it is otherwise
    /// selectable through the very same production entry point.
    #[test]
    fn model_authored_exact_selector_cannot_bypass_agent_allowlist() {
        let mut providers = providers();
        providers
            .providers
            .get_mut("minimax")
            .unwrap()
            .models
            .push(ModelEntry {
                id: "explore-only".into(),
                subagent_invokable: Some(true),
                trust: Some(ModelTrust::Untrusted),
                // The host scoped this model to a single agent.
                availability: crate::config::providers::ModelAvailability {
                    agents: vec!["explore".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            });
        let session = session_model(&providers);
        let extended = ExtendedConfig {
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        };

        // The selector is built from model-authored JSON through the real
        // parser, not hand-constructed, so the test rides the production path
        // a subagent actually takes.
        let exact = DelegationModelSelector::from_value(Some(&serde_json::json!({
            "kind": "exact",
            "selector": "minimax:explore-only"
        })))
        .expect("selector parses")
        .expect("selector is present");

        // `builder` is outside the allowlist: the delegation must be refused.
        match resolve_delegated_model(
            "builder",
            None,
            Some(&exact),
            &extended,
            &providers,
            &session,
        ) {
            Err(SelectorResolution::InvalidLiteral(message)) => {
                assert!(message.contains("availability"), "got: {message}");
                assert!(message.contains("minimax:explore-only"), "got: {message}");
            }
            Ok(model) => panic!(
                "model-authored exact selector bypassed the agent allowlist and resolved to {}",
                model.model_id_ref()
            ),
            Err(other) => panic!("unexpected selector error: {other:?}"),
        }

        // Positive control: the same selector from the allowlisted agent
        // resolves. Without this, the assertion above would still pass if the
        // model were unreachable for some unrelated reason.
        let allowed = resolve_delegated_model(
            "explore",
            None,
            Some(&exact),
            &extended,
            &providers,
            &session,
        )
        .expect("the allowlisted agent may select the model it is scoped to");
        assert_eq!(allowed.model_id_ref(), "explore-only");
    }

    const REDACTION_TEST_SECRET: &str = "sk-live-delegation-secret";

    fn session_model_with_secret(cfg: &ProvidersConfig) -> Arc<Model> {
        let table = crate::redact::RedactionTable::empty()
            .with_forced_literal(REDACTION_TEST_SECRET.to_string(), "TEST".to_string())
            .expect("forced literal");
        Arc::new(Model::from_config(cfg, Arc::new(table)).unwrap())
    }

    fn trust_mode_providers() -> ProvidersConfig {
        let mut providers = providers();
        let minimax = providers.providers.get_mut("minimax").unwrap();
        minimax.models.push(ModelEntry {
            id: "trusted-code".into(),
            subagent_invokable: Some(true),
            trust: Some(ModelTrust::Trusted),
            ..Default::default()
        });
        providers
    }

    /// AC5. Trust — not posture — decides redaction posture.
    ///
    /// The test dispatches a real delegation and asserts:
    /// (a) the resolved custody class and the model's effective redaction table
    ///     follow trust only — a trusted (self-hosted / no-log) destination
    ///     resolves to the empty pass-through table, an untrusted one keeps the
    ///     session table;
    /// (b) the brief rendered for the destination is redacted for untrusted and
    ///     unchanged for trusted.
    #[test]
    fn model_trust_controls_redaction_not_mode() {
        let providers = trust_mode_providers();
        let session = session_model_with_secret(&providers);
        let brief = format!("deploy with {REDACTION_TEST_SECRET} now");
        let extended = ExtendedConfig {
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        };

        // (a) Redaction posture follows trust only.
        let untrusted_model = Model::for_provider(
            &providers,
            "minimax",
            "MiniMax-M2",
            session.session_redact_table(),
        )
        .unwrap();
        let trusted_model = Model::for_provider(
            &providers,
            "minimax",
            "trusted-code",
            session.session_redact_table(),
        )
        .unwrap();
        assert!(!untrusted_model.is_trusted());
        assert!(trusted_model.is_trusted());
        assert!(
            !untrusted_model.redact_table().is_empty(),
            "an untrusted destination keeps the session table"
        );
        assert!(
            !trusted_model.redact_table().is_empty(),
            "a trusted destination keeps the enforced session table"
        );

        // (b) Dispatch a real delegation and render its brief through the
        //     resolved custody. Untrusted is redacted.
        let untrusted_selector = DelegationModelSelector::Exact {
            selector: "minimax:MiniMax-M2".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        let (model, custody) = resolve_delegated_model_with_custody(
            "explore",
            None,
            Some(&untrusted_selector),
            &extended,
            &providers,
            &session,
            None,
        )
        .expect("untrusted delegation resolves");
        assert_eq!(model.model_id_ref(), "MiniMax-M2");
        assert_eq!(custody.custody(), ModelCustody::Untrusted);
        let untrusted_render = custody.render_brief(&brief);
        assert!(
            !untrusted_render.contains(REDACTION_TEST_SECRET),
            "{untrusted_render}"
        );

        // Trusted is host-authored, but the brief remains reference-only.
        let (trusted_child, trusted_custody) = resolve_delegated_model_with_custody(
            "explore",
            Some("minimax:trusted-code"),
            None,
            &extended,
            &providers,
            &session,
            None,
        )
        .expect("host-authored trusted delegation resolves");
        assert_eq!(trusted_child.model_id_ref(), "trusted-code");
        assert_eq!(trusted_custody.custody(), ModelCustody::Trusted);
        let trusted_render = trusted_custody.render_brief(&brief);
        assert!(!trusted_render.contains(REDACTION_TEST_SECRET));
    }

    /// F1/AC7 (spawn surface). `spawn.model` is a model-authored selector, so
    /// it takes the same forced redacted-untrusted route as `task`: it cannot
    /// name a trusted-custody child, cannot reach a non-subagent-invokable
    /// model, and cannot fall through to a trusted candidate.
    #[test]
    fn model_directed_spawn_cannot_escalate_to_trusted_custody() {
        let mut providers = providers();
        let minimax = providers.providers.get_mut("minimax").unwrap();
        minimax.models.push(ModelEntry {
            id: "trusted-code".into(),
            subagent_invokable: Some(true),
            trust: Some(ModelTrust::Trusted),
            quality_rank: Some(1_000),
            ..Default::default()
        });
        let session = session_model(&providers);
        let extended = ExtendedConfig {
            smart_code: Some("minimax:trusted-code".into()),
            ..ExtendedConfig::default()
        };

        // 1. Naming a trusted model is a custody error, not an escalation.
        let error = resolve_spawn_selector(
            "minimax:trusted-code",
            "bee",
            &extended,
            &providers,
            &session,
        )
        .map(|(model, _)| model.model_id_ref().to_string())
        .expect_err("a trusted spawn target must be refused");
        let SelectorResolution::InvalidLiteral(message) = error else {
            panic!("expected a custody refusal, got {error:?}");
        };
        assert!(message.contains("custody"), "{message}");
        assert!(message.contains("never falls back"), "{message}");

        // 2. A role name that resolves to a trusted model is refused too: the
        //    choice to use the role is still model-originated.
        let error = resolve_spawn_selector("smart_code", "bee", &extended, &providers, &session)
            .map(|(model, _)| model.model_id_ref().to_string())
            .expect_err("a role naming a trusted model must be refused");
        assert!(matches!(error, SelectorResolution::InvalidLiteral(_)));

        // 3. Hidden (non-subagent-invokable) models are now refused; the old
        //    path built them with no eligibility check at all.
        let error =
            resolve_spawn_selector("minimax:hidden", "bee", &extended, &providers, &session)
                .map(|(model, _)| model.model_id_ref().to_string())
                .expect_err("a hidden spawn target must be refused");
        let SelectorResolution::InvalidLiteral(message) = error else {
            panic!("expected a refusal, got {error:?}");
        };
        assert!(message.contains("subagent"), "{message}");

        // 4. An untrusted, invokable model resolves and carries the forced
        //    untrusted custody decision.
        let (model, custody) =
            resolve_spawn_selector("minimax:MiniMax-M2", "bee", &extended, &providers, &session)
                .expect("an untrusted spawn target resolves");
        assert_eq!(model.model_id_ref(), "MiniMax-M2");
        assert_eq!(custody.custody(), ModelCustody::Untrusted);
        assert_eq!(
            custody.route().custody_filter,
            Some(ModelCustody::Untrusted)
        );
    }

    /// Provenance decides custody, not the selector string. The identical
    /// `provider:model` value is refused when a model wrote it and accepted
    /// when the host wrote it in a config file — so a self-hosted
    /// `goalSupervision.coldSkepticModel` stops hard-failing every round.
    #[test]
    fn spawn_selector_custody_follows_provenance() {
        let providers = trust_mode_providers();
        let session = session_model(&providers);
        let extended = ExtendedConfig::default();

        let model_directed = resolve_spawn_selector(
            "minimax:trusted-code",
            "scout",
            &extended,
            &providers,
            &session,
        )
        .map(|(model, _)| model.model_id_ref().to_string())
        .expect_err("a model-authored selector may not name a trusted child");
        let SelectorResolution::InvalidLiteral(message) = model_directed else {
            panic!("expected a custody refusal");
        };
        assert!(message.contains("custody"), "{message}");

        let (model, custody) = resolve_host_config_spawn_selector(
            "minimax:trusted-code",
            "scout",
            &extended,
            &providers,
            &session,
        )
        .expect("host config may name a trusted skeptic");
        assert_eq!(model.model_id_ref(), "trusted-code");
        assert_eq!(custody.custody(), ModelCustody::Trusted);
        assert_eq!(
            custody.diagnostics().first().map(|d| d.stage),
            Some("host_config_spawn_model")
        );
        // Its brief is scrubbed even though the destination is trusted.
        assert_eq!(custody.render_brief("raw brief"), "raw brief");

        // Host provenance is not a bypass of the other checks.
        assert!(
            resolve_host_config_spawn_selector(
                "minimax:hidden",
                "scout",
                &extended,
                &providers,
                &session
            )
            .is_err(),
            "a non-subagent-invokable skeptic is still refused"
        );
    }

    /// Discovery must not advertise what the forced filter always rejects.
    #[test]
    fn discovery_hides_host_policy_only_trusted_models() {
        let providers = trust_mode_providers();
        let discovery = render_model_discovery("Build", &providers);
        assert!(
            !discovery.contains("trusted-code"),
            "a trusted model must not be offered as a copy-paste selector: {discovery}"
        );
        assert!(
            discovery.contains("host-policy-only"),
            "their existence is annotated instead: {discovery}"
        );
        assert!(discovery.contains("minimax:MiniMax-M2"));
    }

    /// F4. The typed payload is exercised through the production rendering
    /// implementation (`SessionTableRedaction` over a real `RedactionTable`),
    /// not a test double: the brief a delegated untrusted child receives is
    /// scrubbed by the session table.
    #[test]
    fn delegated_brief_is_rendered_through_the_session_redaction_table() {
        let providers = providers();
        let session = session_model_with_secret(&providers);
        let extended = ExtendedConfig {
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        };
        let selector = DelegationModelSelector::Exact {
            selector: "minimax:MiniMax-M2".into(),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
        };
        let (_, custody) = resolve_delegated_model_with_custody(
            "explore",
            None,
            Some(&selector),
            &extended,
            &providers,
            &session,
            None,
        )
        .unwrap();

        let brief = format!("token is {REDACTION_TEST_SECRET}; use it");
        let rendered = custody.render_brief(&brief);
        assert!(!rendered.contains(REDACTION_TEST_SECRET), "{rendered}");
        assert_eq!(
            rendered,
            session.session_redact_table().scrub(&brief),
            "production rendering must be the session table scrub"
        );

        let diagnostics = custody.routing_diagnostics_json();
        assert_eq!(diagnostics["trust"], "untrusted");
        assert_eq!(diagnostics["custody_filter"], "untrusted");
        assert!(
            !diagnostics.to_string().contains(REDACTION_TEST_SECRET),
            "diagnostics must never carry payload material"
        );
    }

    /// Item 3 (round 4), helper semantics only.
    ///
    /// This pins `render_brief_for_model` itself — the seam the batch path, the
    /// single noninteractive delegation, and the interactive primary handoff
    /// each call. It does **not** drive those dispatch paths; that they call
    /// this seam is verified by reading the three call sites, not by this test.
    #[test]
    fn render_brief_for_model_renders_for_the_childs_custody_class() {
        let providers = trust_mode_providers();
        let session = session_model_with_secret(&providers);
        let extended = ExtendedConfig::default();
        let brief = format!("ship it with {REDACTION_TEST_SECRET}");

        let untrusted_child = Arc::new(
            Model::for_provider(
                &providers,
                "minimax",
                "MiniMax-M2",
                session.session_redact_table(),
            )
            .unwrap(),
        );
        let rendered = render_brief_for_model(&providers, &untrusted_child, &extended, &brief);
        assert!(!rendered.contains(REDACTION_TEST_SECRET), "{rendered}");
        assert_eq!(rendered, session.session_redact_table().scrub(&brief));

        let trusted_child = Arc::new(
            Model::for_provider(
                &providers,
                "minimax",
                "trusted-code",
                session.session_redact_table(),
            )
            .unwrap(),
        );
        assert_eq!(
            render_brief_for_model(&providers, &trusted_child, &extended, &brief),
            session.session_redact_table().scrub(&brief),
            "a trusted child remains reference-only"
        );

        // Rendering is idempotent, so a path that renders twice (batch entry
        // already rendered, then re-rendered at dispatch) cannot corrupt it.
        let once = render_brief_for_model(&providers, &untrusted_child, &extended, &brief);
        let twice = render_brief_for_model(&providers, &untrusted_child, &extended, &once);
        assert_eq!(once, twice);
    }

    /// F8. The role-default branch keeps its session-model fallback (the
    /// session model is host-chosen), but the fallthrough is no longer silent:
    /// a trusted category default is skipped under the forced untrusted filter
    /// and the skip is recorded as a custody diagnostic.
    #[test]
    fn trusted_category_default_is_skipped_with_a_recorded_diagnostic() {
        let mut providers = providers();
        let minimax = providers.providers.get_mut("minimax").unwrap();
        minimax.models.push(ModelEntry {
            id: "trusted-cheap".into(),
            subagent_invokable: Some(true),
            trust: Some(ModelTrust::Trusted),
            quality_rank: Some(1_000),
            availability: crate::config::providers::ModelAvailability {
                categories: vec!["cheap_code".to_string()],
                ..Default::default()
            },
            ..Default::default()
        });
        providers.category_defaults.insert(
            "cheap_code".into(),
            ProviderModelRef {
                provider: "minimax".into(),
                model: "trusted-cheap".into(),
            },
        );
        // Every remaining candidate is category-restricted away, so the role
        // branch has no admissible untrusted candidate and must fall back.
        for model in &mut providers.providers.get_mut("minimax").unwrap().models {
            if model.id != "trusted-cheap" {
                model.availability.categories = vec!["other".to_string()];
            }
        }
        let session = session_model(&providers);

        // No frontmatter, no caller selector: the role-default branch runs.
        let (model, custody) = resolve_delegated_model_with_custody(
            "explore",
            None,
            None,
            &ExtendedConfig::default(),
            &providers,
            &session,
            None,
        )
        .unwrap();

        assert_eq!(
            model.model_id_ref(),
            session.model_id_ref(),
            "the fallback lands deterministically on the host-chosen session model"
        );
        let stages: Vec<(&str, &str)> = custody
            .diagnostics()
            .iter()
            .map(|d| (d.stage, d.outcome))
            .collect();
        assert!(
            stages.contains(&("role_category_default", "skipped")),
            "the trusted category default must be recorded as skipped: {stages:?}"
        );
        assert!(
            stages.contains(&("session_model", "fallback")),
            "the fallthrough must be recorded: {stages:?}"
        );
        let skip = custody
            .diagnostics()
            .iter()
            .find(|d| d.stage == "role_category_default")
            .unwrap();
        assert!(
            skip.reason.contains("untrusted custody filter"),
            "the skip must name the custody filter: {}",
            skip.reason
        );
    }

    /// F10. Host-authored selections (agent-file frontmatter, configured role
    /// defaults, the session model) are custody-typed too, but their custody is
    /// the target's own configured class — the host named the target, so this
    /// is not the forced filter that applies to model-originated selectors.
    #[test]
    fn host_authored_selections_carry_the_targets_own_custody() {
        let providers = trust_mode_providers();
        let session = session_model(&providers);

        // Frontmatter naming a trusted model is host-authored and permitted.
        let (model, custody) = resolve_delegated_model_with_custody(
            "explore",
            Some("minimax:trusted-code"),
            None,
            &ExtendedConfig::default(),
            &providers,
            &session,
            None,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "trusted-code");
        assert_eq!(custody.custody(), ModelCustody::Trusted);
        assert_eq!(custody.route().trust, ModelTrust::Trusted);
        assert_eq!(
            custody.diagnostics().first().map(|d| d.stage),
            Some("frontmatter_model")
        );

        // A configured role default naming a trusted model is host-authored too.
        let extended = ExtendedConfig {
            cheap_code: Some("minimax/trusted-code".into()),
            ..ExtendedConfig::default()
        };
        let (model, custody) = resolve_delegated_model_with_custody(
            "explore", None, None, &extended, &providers, &session, None,
        )
        .unwrap();
        assert_eq!(model.model_id_ref(), "trusted-code");
        assert_eq!(custody.custody(), ModelCustody::Trusted);
        assert_eq!(
            custody.diagnostics().first().map(|d| d.stage),
            Some("configured_role_default")
        );

        // Item 4 (round 4). The call sites, not just the config layer: a model
        // scoped by a category allowlist must still be resolvable when the host
        // names it exactly. `build_host_selected_policy_model` used to pass
        // `Discovery`, which made every allowlisted model unreachable from
        // frontmatter and role defaults.
        let mut scoped = trust_mode_providers();
        for model in &mut scoped.providers.get_mut("minimax").unwrap().models {
            model.availability = crate::config::providers::ModelAvailability {
                categories: vec!["reasoning".to_string()],
                ..Default::default()
            };
        }
        let scoped_session = session_model(&scoped);

        // Frontmatter path.
        let (model, custody) = resolve_delegated_model_with_custody(
            "explore",
            Some("minimax:MiniMax-M2"),
            None,
            &ExtendedConfig::default(),
            &scoped,
            &scoped_session,
            None,
        )
        .expect("a category-scoped model is still resolvable by exact host reference");
        assert_eq!(model.model_id_ref(), "MiniMax-M2");
        assert_eq!(custody.custody(), ModelCustody::Untrusted);

        // Configured role-default path.
        let (model, custody) = resolve_delegated_model_with_custody(
            "explore",
            None,
            None,
            &ExtendedConfig {
                cheap_code: Some("minimax:trusted-code".into()),
                ..ExtendedConfig::default()
            },
            &scoped,
            &scoped_session,
            None,
        )
        .expect("a category-scoped role default is still resolvable");
        assert_eq!(model.model_id_ref(), "trusted-code");
        assert_eq!(custody.custody(), ModelCustody::Trusted);

        // Host-config spawn path (`goalSupervision.coldSkepticModel`).
        let (model, _) = resolve_host_config_spawn_selector(
            "minimax:trusted-code",
            "scout",
            &ExtendedConfig::default(),
            &scoped,
            &scoped_session,
        )
        .expect("a category-scoped skeptic is still resolvable");
        assert_eq!(model.model_id_ref(), "trusted-code");

        // The session-model fallback also carries a decided custody class.
        let custody = inherited_custody_for_model(&providers, &session, &ExtendedConfig::default());
        assert_eq!(custody.route().provider, session.provider_id());
        assert_eq!(custody.route().model, session.model_id_ref());
        assert!(
            custody
                .diagnostics()
                .iter()
                .any(|d| d.stage == "host_selected_model")
        );
    }

    // ---- AC5 (2c-1): trusted-child capture is trust + LOCATION only ----

    /// Providers carrying a single trusted `reasoning` child at `location`, plus
    /// an untrusted `reasoning` alternative so the forced-`Trusted` scan has to
    /// *choose* the trusted child rather than being the only candidate.
    fn trusted_child_providers(location: Option<ModelLocation>) -> ProvidersConfig {
        let mut providers = providers();
        let minimax = providers.providers.get_mut("minimax").unwrap();
        minimax.models.push(ModelEntry {
            id: "trusted-reasoning".into(),
            subagent_invokable: Some(true),
            trust: Some(ModelTrust::Trusted),
            quality_rank: Some(1_000),
            location,
            capabilities: crate::config::providers::ModelCapabilities {
                reasoning: CapabilityStatus::Supported,
                ..Default::default()
            },
            ..Default::default()
        });
        minimax.models.push(ModelEntry {
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
        providers
    }

    fn extended_mode() -> ExtendedConfig {
        ExtendedConfig {
            agent_chooses_subagent_model: true,
            ..ExtendedConfig::default()
        }
    }

    /// AC5. A trusted child resolved to a `Remote` location must fail closed:
    /// no capture grant is minted. Fails against pre-gate code, where a Remote
    /// trusted child mints a grant.
    #[test]
    fn trusted_child_capture_requires_local_location() {
        let providers = trusted_child_providers(Some(ModelLocation::Remote));
        let session = session_model(&providers);
        match resolve_trusted_child_model(
            "reasoning",
            "deepthink",
            &extended_mode(),
            &providers,
            &session,
            None,
        ) {
            Err(SelectorResolution::InvalidLiteral(message)) => {
                assert!(
                    message.contains("local"),
                    "the fail-closed reason must name the location gate: {message}"
                );
                assert!(
                    !message.contains("secret"),
                    "the fail-closed reason must be content-free: {message}"
                );
            }
            Err(other) => panic!("unexpected error shape: {other:?}"),
            Ok((model, _grant)) => panic!(
                "a trusted Remote child must not mint a grant; got {}",
                model.model_id_ref()
            ),
        }
    }

    /// AC5 positive control. A trusted, host-`Local` child mints a capture
    /// grant; its model egress remains redacted by the normal model boundary.
    #[test]
    fn trusted_child_local_is_capture_capable() {
        let providers = trusted_child_providers(Some(ModelLocation::Local));
        let session = session_model(&providers);
        let (model, grant) = resolve_trusted_child_model(
            "reasoning",
            "deepthink",
            &extended_mode(),
            &providers,
            &session,
            None,
        )
        .expect("a trusted host-local child must mint a grant");
        assert_eq!(model.provider_id(), "minimax");
        assert_eq!(model.model_id_ref(), "trusted-reasoning");
        assert_eq!(grant.provider(), "minimax");
        assert_eq!(grant.model(), "trusted-reasoning");
    }

    /// AC5. `PrivateRemote` and a MISSING location each fail closed exactly like
    /// `Remote`: only `Local` permits trusted capture. Both fail against pre-gate
    /// code (both minted a grant).
    #[test]
    fn trusted_child_non_local_locations_fail_closed() {
        for location in [Some(ModelLocation::PrivateRemote), None] {
            let providers = trusted_child_providers(location);
            let session = session_model(&providers);
            assert!(
                resolve_trusted_child_model(
                    "reasoning",
                    "deepthink",
                    &extended_mode(),
                    &providers,
                    &session,
                    None,
                )
                .is_err(),
                "a trusted child at {location:?} must fail closed (no grant minted)"
            );
        }
    }

    /// AC5 regression guard. Only an untrusted `reasoning` candidate exists, at
    /// a `Local` location. The coordinator forces `ModelCustody::Trusted`, so
    /// the scan finds no eligible trusted model and mints nothing — a local
    /// untrusted child is still no trusted grant. Passes today; must keep
    /// passing.
    #[test]
    fn untrusted_child_gets_no_trusted_grant() {
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
                location: Some(ModelLocation::Local),
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
        assert!(
            resolve_trusted_child_model(
                "reasoning",
                "deepthink",
                &extended_mode(),
                &providers,
                &session,
                None,
            )
            .is_err(),
            "an untrusted child must never receive a trusted custody grant"
        );
    }

    /// AC5. Trusted selection is independent of harness posture; only local
    /// selection is capture-capable and neither selection changes model egress.
    #[test]
    fn trusted_child_custody_ignores_harness_mode() {
        let providers = trusted_child_providers(Some(ModelLocation::Local));
        let session = session_model(&providers);
        let (model, grant) = resolve_trusted_child_model(
            "reasoning",
            "deepthink",
            &extended_mode(),
            &providers,
            &session,
            None,
        )
        .expect("a local trusted child must route");
        assert_eq!(grant.provider(), model.provider_id());
        assert_eq!(grant.model(), model.model_id_ref());

        let providers = trusted_child_providers(Some(ModelLocation::Remote));
        let session = session_model(&providers);
        assert!(
            resolve_trusted_child_model(
                "reasoning",
                "deepthink",
                &extended_mode(),
                &providers,
                &session,
                None,
            )
            .is_err(),
            "a trusted Remote child must fail closed"
        );
    }

    #[test]
    fn canonical_delegation_selector_prefers_provider_colon_model() {
        assert_eq!(
            split_selector(" display-provider:model/with/slash "),
            Some(("display-provider".into(), "model/with/slash".into()))
        );
        assert_eq!(
            split_selector("display-provider/model"),
            Some(("display-provider".into(), "model".into()))
        );
        assert_eq!(split_selector("display-provider:"), None);
    }
}
