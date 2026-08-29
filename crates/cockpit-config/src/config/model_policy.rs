//! Model policy selection and capability resolution.
//!
//! Trust is a provider/model data-custody classification and stays that way:
//!
//! - [`ModelTrust`] is a provider/model **data-custody** classification.
//!   `Trusted` marks a self-hosted / no-log endpoint that may hold raw
//!   secret/environment values; raw content reaching it is the intended,
//!   supported outcome. `Untrusted` marks a cloud endpoint that must receive a
//!   redacted rendering. The enforced invariant is one-directional:
//!   unredacted content must never reach an untrusted endpoint.
//! - Harness-steering posture is agent-definition-scoped and is no longer a
//!   dimension of model routing; it never filtered provider eligibility,
//!   custody, or redaction here.
//!
//! Custody is never inferred from locality. Ranking therefore uses only the
//! documented intelligence/cost/capability criteria plus deterministic
//! identity; custody filters candidates exclusively through
//! [`SensitiveModelPolicyRequest::custody`].

use std::sync::Arc;

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

/// Candidate scope for a policy lookup. Deliberately carries **no** trust
/// variant: custody is not a selector, it is the typed filter supplied by
/// [`SensitiveModelPolicyRequest`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelPolicySelector<'a> {
    Exact(&'a str),
    Category(&'a str),
    /// Every configured model, narrowed only by the request's capability,
    /// context, availability, subagent-invokable, and custody requirements.
    Any,
}

/// How `availability` allowlists apply to a request.
///
/// `availability` is a **discovery-scoping** mechanism: it says which
/// categories/roles/agents a model may be *found* for. It was never meant to
/// veto an explicit host reference to one provider/model.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AvailabilityScope {
    /// Policy-driven discovery. The model was reached by scanning, so its
    /// allowlists gate it on every axis.
    #[default]
    Discovery,
    /// The host explicitly named this provider/model — agent-file frontmatter,
    /// a configured role default, a configured backup or enumerated failover
    /// candidate, or the session's own model. Allowlists do not gate an
    /// explicit host reference; every other check (subagent-invokable,
    /// capabilities, context, custody) still applies.
    HostNamedTarget,
}

/// The documented, custody-free selection criteria. Every field here is an
/// intelligence/cost/capability/availability concern; none of them may encode
/// data custody or harness posture.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct ModelPolicyCriteria<'a> {
    pub selector: ModelPolicySelector<'a>,
    pub required_capabilities: Vec<RequiredModelCapability>,
    pub min_context_tokens: Option<u32>,
    pub require_subagent_invokable: bool,
    pub optimize: ModelOptimization,
    pub role: Option<&'a str>,
    pub agent: Option<&'a str>,
    /// Whether `availability` allowlists gate this request. Host-named exact
    /// targets are not discovery, so they are not gated.
    pub availability: AvailabilityScope,
}

#[allow(dead_code)]
impl<'a> ModelPolicyCriteria<'a> {
    pub fn subagent_category(category: &'a str) -> Self {
        Self {
            selector: ModelPolicySelector::Category(category),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: true,
            optimize: ModelOptimization::default(),
            role: Some(category),
            agent: None,
            availability: AvailabilityScope::Discovery,
        }
    }
}

/// Data custody required of the provider/model that will receive a payload.
///
/// This is the *only* way trust may narrow routing. It is independent of
/// harness-steering posture: no posture implies a custody class and no
/// custody class implies a posture.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelCustody {
    /// The selected endpoint may receive raw secret/environment values.
    Trusted,
    /// The selected endpoint must receive a redacted rendering.
    Untrusted,
}

#[allow(dead_code)]
impl ModelCustody {
    /// The provider/model trust class this custody requirement admits.
    pub fn required_trust(self) -> ModelTrust {
        match self {
            Self::Trusted => ModelTrust::Trusted,
            Self::Untrusted => ModelTrust::Untrusted,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

/// Custody posture of an **external OS harness**.
///
/// It carries the same meaning as [`ModelCustody`] — trusted may hold raw
/// secrets, untrusted must be handed redacted material — but it is a separate
/// type on purpose: an external harness is not a provider/model route, so this
/// value must never reach model routing. There is deliberately no conversion
/// into [`ModelCustody`] or [`ModelTrust`].
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessCustodyTrust {
    Trusted,
    Untrusted,
}

#[allow(dead_code)]
impl HarnessCustodyTrust {
    pub fn is_trusted(self) -> bool {
        matches!(self, Self::Trusted)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Untrusted => "untrusted",
        }
    }
}

/// Renders potentially sensitive material for exactly one untrusted target.
///
/// Implementations own the redaction. There is no raw passthrough: the trait
/// only ever returns an owned, target-specific rendering.
pub trait RedactedRendering: Send + Sync {
    fn render_redacted(&self, provider: &str, model: &str, source: &str) -> String;
}

#[derive(Clone)]
enum PayloadRendering {
    /// Raw provider bytes. Reachable only through
    /// [`SensitivePayload::raw_for_trusted_custody`] and only unlockable with a
    /// [`TrustedCustodyGrant`].
    Raw,
    /// Target-specific redacted rendering. Has no raw-byte conversion.
    Redacted(Arc<dyn RedactedRendering>),
}

/// The rendering policy for a payload that may contain sensitive material.
///
/// The custody class is part of the value, so a caller cannot construct a
/// sensitive request without first deciding custody. `Trusted` construction
/// yields raw provider bytes only after routing hands back a
/// [`TrustedCustodyGrant`]; `Untrusted` construction requires a
/// target-specific redacted rendering and exposes no raw-byte conversion.
#[derive(Clone)]
pub struct SensitivePayload {
    custody: ModelCustody,
    rendering: PayloadRendering,
}

impl std::fmt::Debug for SensitivePayload {
    /// Never prints payload material — diagnostics carry the class only.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SensitivePayload")
            .field("custody", &self.custody)
            .field(
                "rendering",
                &match self.rendering {
                    PayloadRendering::Raw => "raw",
                    PayloadRendering::Redacted(_) => "redacted",
                },
            )
            .finish()
    }
}

#[allow(dead_code)]
impl SensitivePayload {
    /// Raw provider bytes may reach the selected endpoint. Fixes custody to
    /// [`ModelCustody::Trusted`].
    pub fn raw_for_trusted_custody() -> Self {
        Self {
            custody: ModelCustody::Trusted,
            rendering: PayloadRendering::Raw,
        }
    }

    /// The payload exists only as a target-specific redacted rendering. Fixes
    /// custody to [`ModelCustody::Untrusted`].
    pub fn redacted_for_untrusted_custody(rendering: Arc<dyn RedactedRendering>) -> Self {
        Self {
            custody: ModelCustody::Untrusted,
            rendering: PayloadRendering::Redacted(rendering),
        }
    }

    pub fn custody(&self) -> ModelCustody {
        self.custody
    }

    /// Raw provider bytes, unlocked by the grant routing mints after a
    /// `Trusted` selection.
    ///
    /// The grant is bound to the destination it was minted for: it unlocks raw
    /// bytes only for that exact `(provider, model)`. A grant for one trusted
    /// route can therefore never be replayed to send raw bytes to a different
    /// route. Always `None` for an untrusted payload — a redacted rendering has
    /// no raw-byte conversion.
    pub fn raw_provider_bytes<'s>(
        &self,
        grant: &TrustedCustodyGrant,
        route: &ResolvedModelPolicy,
        source: &'s str,
    ) -> Option<&'s str> {
        if !grant.authorizes(route) {
            return None;
        }
        match self.rendering {
            PayloadRendering::Raw => Some(source),
            PayloadRendering::Redacted(_) => None,
        }
    }

    /// Target-specific redacted rendering for the resolved untrusted target.
    /// Always `None` for a raw/trusted payload.
    pub fn render_for_untrusted(
        &self,
        resolved: &ResolvedModelPolicy,
        source: &str,
    ) -> Option<String> {
        match &self.rendering {
            PayloadRendering::Raw => None,
            PayloadRendering::Redacted(rendering) => {
                Some(rendering.render_redacted(&resolved.provider, &resolved.model, source))
            }
        }
    }
}

/// Proof that routing selected a provider/model under `Trusted` custody. Only
/// [`ProvidersConfig::resolve_sensitive_model_policy`] mints one, so raw
/// provider bytes cannot be produced without a completed trusted selection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedCustodyGrant {
    provider: String,
    model: String,
}

#[allow(dead_code)]
impl TrustedCustodyGrant {
    pub fn provider(&self) -> &str {
        &self.provider
    }

    pub fn model(&self) -> &str {
        &self.model
    }

    /// Whether this grant was minted for `route`. Raw bytes are unlocked only
    /// for the exact destination the trusted selection resolved to.
    pub fn authorizes(&self, route: &ResolvedModelPolicy) -> bool {
        self.provider == route.provider && self.model == route.model && route.trust.is_trusted()
    }
}

/// The single place a [`TrustedCustodyGrant`] comes into existence.
///
/// Every custody-routing entry point funnels through here, so "raw provider
/// bytes were released" and "a custody selection completed under
/// [`ModelCustody::Trusted`]" are the same event by construction. An
/// `Untrusted` selection never mints one, which is what makes a missing grant
/// mean *redact*, not *unknown*.
fn seal_custody_selection(
    policy: ResolvedModelPolicy,
    custody: ModelCustody,
) -> ResolvedSensitiveModelPolicy {
    let grant = matches!(custody, ModelCustody::Trusted).then(|| TrustedCustodyGrant {
        provider: policy.provider.clone(),
        model: policy.model.clone(),
    });
    ResolvedSensitiveModelPolicy {
        policy,
        custody,
        grant,
    }
}

/// Custody rule for backup/failover routing.
///
/// Failover is **upgrade-only**. An untrusted primary may fail over to an
/// untrusted or a trusted candidate — moving work onto a self-hosted/no-log
/// endpoint is never a regression. A trusted primary may fail over only to
/// another trusted candidate; a downgrade would push content that was routed
/// under raw custody onto a cloud endpoint, so it is a typed refusal rather
/// than a silent substitution.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailoverCustody {
    primary: ModelTrust,
}

#[allow(dead_code)]
impl FailoverCustody {
    pub fn for_primary(primary: ModelTrust) -> Self {
        Self { primary }
    }

    pub fn primary(self) -> ModelTrust {
        self.primary
    }

    /// Whether a candidate of this trust class is an admissible failover
    /// target: the primary's own class, or an upgrade to trusted.
    pub fn admits(self, candidate: ModelTrust) -> bool {
        match self.primary {
            ModelTrust::Trusted => candidate.is_trusted(),
            ModelTrust::Untrusted => true,
        }
    }

    /// The custody class this candidate must be routed under, or the typed
    /// refusal when it would be a downgrade.
    pub fn custody_for(
        self,
        provider: &str,
        model: &str,
        candidate: ModelTrust,
    ) -> Result<ModelCustody, ModelPolicyError> {
        if !self.admits(candidate) {
            return Err(ModelPolicyError::CustodyDowngradeRefused {
                provider: provider.to_string(),
                model: model.to_string(),
                primary: self.primary,
                candidate,
            });
        }
        Ok(match candidate {
            ModelTrust::Trusted => ModelCustody::Trusted,
            ModelTrust::Untrusted => ModelCustody::Untrusted,
        })
    }
}

/// The request every potentially sensitive route must construct. Custody has
/// no default and no `Option`, so it cannot be omitted.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct SensitiveModelPolicyRequest<'a> {
    criteria: ModelPolicyCriteria<'a>,
    custody: ModelCustody,
    payload: SensitivePayload,
}

#[allow(dead_code)]
impl<'a> SensitiveModelPolicyRequest<'a> {
    /// `custody` and `payload` must agree; a payload built for one class can
    /// never be routed under the other.
    pub fn new(
        criteria: ModelPolicyCriteria<'a>,
        custody: ModelCustody,
        payload: SensitivePayload,
    ) -> Result<Self, ModelPolicyError> {
        if payload.custody() != custody {
            return Err(ModelPolicyError::CustodyPayloadMismatch {
                requested: custody,
                payload: payload.custody(),
            });
        }
        Ok(Self {
            criteria,
            custody,
            payload,
        })
    }

    pub fn criteria(&self) -> &ModelPolicyCriteria<'a> {
        &self.criteria
    }

    pub fn custody(&self) -> ModelCustody {
        self.custody
    }

    pub fn payload(&self) -> &SensitivePayload {
        &self.payload
    }
}

/// The sole request type allowed to omit custody. Constructing one asserts the
/// caller proved the payload carries no sensitive material.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct NonSensitiveModelPolicyRequest<'a> {
    criteria: ModelPolicyCriteria<'a>,
}

#[allow(dead_code)]
impl<'a> NonSensitiveModelPolicyRequest<'a> {
    pub fn proven_non_sensitive(criteria: ModelPolicyCriteria<'a>) -> Self {
        Self { criteria }
    }

    pub fn criteria(&self) -> &ModelPolicyCriteria<'a> {
        &self.criteria
    }
}

/// A selection made under an explicit custody filter.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedSensitiveModelPolicy {
    pub policy: ResolvedModelPolicy,
    pub custody: ModelCustody,
    grant: Option<TrustedCustodyGrant>,
}

#[allow(dead_code)]
impl ResolvedSensitiveModelPolicy {
    /// `Some` only for a completed `Trusted` selection.
    pub fn trusted_custody_grant(&self) -> Option<&TrustedCustodyGrant> {
        self.grant.as_ref()
    }
}

#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedModelPolicy {
    pub provider: String,
    pub model: String,
    /// Resolved data-custody class. Reported, never ranked on.
    pub trust: ModelTrust,
    pub location: Option<ModelLocation>,
    pub quality_rank: i64,
    pub cost_rank: i64,
    /// The explicit custody filter this selection passed. `None` when the
    /// caller proved the payload non-sensitive.
    pub custody_filter: Option<ModelCustody>,
}

#[allow(dead_code)]
impl ResolvedModelPolicy {
    pub fn selector(&self) -> String {
        format!("{}:{}", self.provider, self.model)
    }

    /// Routing diagnostics. Trust is a separate field, the explicit trust
    /// filter carries its reason, and no payload material appears.
    pub fn routing_diagnostics(&self) -> RoutingDiagnostics {
        RoutingDiagnostics {
            provider: self.provider.clone(),
            model: self.model.clone(),
            trust: match self.trust {
                ModelTrust::Trusted => "trusted",
                ModelTrust::Untrusted => "untrusted",
            },
            custody_filter: self.custody_filter.map(ModelCustody::as_str),
            custody_filter_reason: match self.custody_filter {
                Some(ModelCustody::Trusted) => {
                    "explicit trusted-custody filter: caller requested raw-custody routing"
                }
                Some(ModelCustody::Untrusted) => {
                    "explicit untrusted-custody filter: caller requested redacted routing"
                }
                None => "no custody filter: caller proved the payload is non-sensitive",
            },
            quality_rank: self.quality_rank,
            cost_rank: self.cost_rank,
        }
    }
}

/// Separate-field routing diagnostics. Never carries redacted literals or raw
/// payload material.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RoutingDiagnostics {
    pub provider: String,
    pub model: String,
    pub trust: &'static str,
    pub custody_filter: Option<&'static str>,
    pub custody_filter_reason: &'static str,
    pub quality_rank: i64,
    pub cost_rank: i64,
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
    /// An exact selection whose resolved custody class is not the one the
    /// caller required. Rejected before dispatch; never falls back.
    CustodyMismatch {
        provider: String,
        model: String,
        required: ModelCustody,
        actual: ModelTrust,
    },
    /// A payload built for one custody class was paired with the other.
    CustodyPayloadMismatch {
        requested: ModelCustody,
        payload: ModelCustody,
    },
    /// A trusted primary's backup/failover candidate is untrusted. Failover is
    /// upgrade-only, so this refuses instead of silently downgrading custody.
    CustodyDowngradeRefused {
        provider: String,
        model: String,
        primary: ModelTrust,
        candidate: ModelTrust,
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
            Self::CustodyMismatch {
                provider,
                model,
                required,
                actual,
            } => write!(
                f,
                "model `{provider}:{model}` is {} and cannot serve a request that requires {} custody",
                match actual {
                    ModelTrust::Trusted => "trusted",
                    ModelTrust::Untrusted => "untrusted",
                },
                required.as_str()
            ),
            Self::CustodyPayloadMismatch { requested, payload } => write!(
                f,
                "requested {} custody but the payload was built for {} custody",
                requested.as_str(),
                payload.as_str()
            ),
            Self::CustodyDowngradeRefused {
                provider,
                model,
                primary,
                candidate,
            } => write!(
                f,
                "failover candidate `{provider}:{model}` is {} but the primary runs under {} custody; failover is upgrade-only and never downgrades custody",
                match candidate {
                    ModelTrust::Trusted => "trusted",
                    ModelTrust::Untrusted => "untrusted",
                },
                match primary {
                    ModelTrust::Trusted => "trusted",
                    ModelTrust::Untrusted => "untrusted",
                }
            ),
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
    pub transcription: CapabilityStatus,
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

/// Rank candidates by the documented intelligence/cost criteria, then by
/// stable provider/model identity.
///
/// Trust is intentionally absent. A custody classification is not a quality
/// signal, so letting it break ties obscured *why* a model was selected and
/// made ordinary routing depend on an unrelated dimension. Custody narrows the
/// candidate set earlier, through [`SensitiveModelPolicyRequest::custody`], and
/// nothing else.
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
        rank.then_with(|| a.provider.cmp(&b.provider))
            .then_with(|| a.model.cmp(&b.model))
    });
}

#[allow(dead_code)]
fn policy_selector_label(criteria: &ModelPolicyCriteria<'_>) -> String {
    match criteria.selector {
        ModelPolicySelector::Exact(selector) => selector.to_string(),
        ModelPolicySelector::Category(category) => category.to_string(),
        ModelPolicySelector::Any => "any".to_string(),
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
            transcription: overrides.transcription.unwrap_or_else(|| {
                status(
                    model_caps.map(|c| c.transcription),
                    provider_caps.transcription,
                )
            }),
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

    /// Route a payload the caller proved carries no sensitive material. This
    /// is the only entry point that omits a custody filter.
    #[allow(dead_code)]
    pub fn resolve_non_sensitive_model_policy(
        &self,
        request: &NonSensitiveModelPolicyRequest<'_>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        self.resolve_policy(request.criteria(), None)
    }

    /// Route a potentially sensitive payload under its required custody class.
    /// A `Trusted` selection mints the [`TrustedCustodyGrant`] that unlocks raw
    /// provider bytes; an `Untrusted` selection never does.
    #[allow(dead_code)]
    pub fn resolve_sensitive_model_policy(
        &self,
        request: &SensitiveModelPolicyRequest<'_>,
    ) -> Result<ResolvedSensitiveModelPolicy, ModelPolicyError> {
        let custody = request.custody();
        let policy = self.resolve_policy(request.criteria(), Some(custody))?;
        Ok(seal_custody_selection(policy, custody))
    }

    /// Route an already-configured target — the active model, a configured
    /// utility model, the configured embedding model — under the custody class
    /// the host's provider configuration assigns it.
    ///
    /// Custody for a configured target is a **host** decision: the caller does
    /// not get to ask for `Trusted`. What the caller also does not get is a way
    /// *around* this call. The only artifact that releases raw provider bytes
    /// is the [`TrustedCustodyGrant`] on the returned route, nothing else mints
    /// one, and a grant unlocks raw bytes only for the exact `(provider,
    /// model)` it names. A caller that skips custody routing therefore has
    /// nothing to unlock raw bytes with and falls closed to the redacted
    /// rendering.
    ///
    /// Unlike discovery routing this does not require the model to appear in
    /// the provider's model list: a configured target names a real endpoint
    /// whether or not the model registry happens to enumerate it. Custody is
    /// resolved for it either way, and an unknown provider is a hard error
    /// rather than a silent custody guess.
    ///
    /// Mode is never consulted.
    #[allow(dead_code)]
    pub fn route_configured_model_custody(
        &self,
        provider: &str,
        model: &str,
        redacted: Arc<dyn RedactedRendering>,
    ) -> Result<ResolvedSensitiveModelPolicy, ModelPolicyError> {
        if !self.providers.contains_key(provider) {
            return Err(ModelPolicyError::UnknownProvider(provider.to_string()));
        }
        let custody = match self.resolve_trust(provider, model) {
            ModelTrust::Trusted => ModelCustody::Trusted,
            ModelTrust::Untrusted => ModelCustody::Untrusted,
        };
        let payload = match custody {
            ModelCustody::Trusted => SensitivePayload::raw_for_trusted_custody(),
            ModelCustody::Untrusted => SensitivePayload::redacted_for_untrusted_custody(redacted),
        };
        let selector = format!("{provider}:{model}");
        let criteria = ModelPolicyCriteria {
            selector: ModelPolicySelector::Exact(&selector),
            required_capabilities: Vec::new(),
            min_context_tokens: None,
            require_subagent_invokable: false,
            optimize: ModelOptimization::Balanced,
            role: None,
            agent: None,
            // The host named this exact provider/model; `availability` scopes
            // discovery, not host-named targets.
            availability: AvailabilityScope::HostNamedTarget,
        };
        // Constructing the request is the type-enforced step: custody has no
        // default and no `Option`, and the payload must agree with it.
        let request = SensitiveModelPolicyRequest::new(criteria, custody, payload)?;
        let policy =
            self.resolved_policy(provider, model, request.criteria(), Some(request.custody()));
        Ok(seal_custody_selection(policy, request.custody()))
    }

    /// Custody **eligibility** only: does a route to this target exist under
    /// `custody`?
    ///
    /// No payload is constructed and no grant is minted, so an eligibility
    /// decision can never be used to render or release anything. Use this when
    /// deciding *whether* a route exists (candidate scans, reachability
    /// checks); use [`Self::resolve_sensitive_model_policy`] when you are about
    /// to send on it.
    #[allow(dead_code)]
    pub fn resolve_sensitive_model_policy_eligibility(
        &self,
        criteria: &ModelPolicyCriteria<'_>,
        custody: ModelCustody,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        self.resolve_policy(criteria, Some(custody))
    }

    fn resolve_policy(
        &self,
        criteria: &ModelPolicyCriteria<'_>,
        custody: Option<ModelCustody>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        match criteria.selector {
            ModelPolicySelector::Exact(selector) => {
                let (provider, model) = parse_policy_selector(selector)?;
                // Exact stays exact: a custody mismatch rejects here and never
                // falls through to a different model.
                self.resolve_exact_policy(&provider, &model, criteria, custody)
            }
            ModelPolicySelector::Any => self.resolve_best_policy_candidate(criteria, custody, None),
            ModelPolicySelector::Category(category) => {
                if let Some(default) = self.category_defaults.get(category)
                    && let Ok(resolved) = self.resolve_exact_policy(
                        &default.provider,
                        &default.model,
                        criteria,
                        custody,
                    )
                {
                    return Ok(resolved);
                }
                self.resolve_best_policy_candidate(criteria, custody, Some(category))
            }
        }
    }

    #[allow(dead_code)]
    fn resolve_exact_policy(
        &self,
        provider: &str,
        model: &str,
        criteria: &ModelPolicyCriteria<'_>,
        custody: Option<ModelCustody>,
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
        self.check_policy_candidate(provider, model_entry, criteria, custody)?;
        Ok(self.resolved_policy(provider, model, criteria, custody))
    }

    #[allow(dead_code)]
    fn resolve_best_policy_candidate(
        &self,
        criteria: &ModelPolicyCriteria<'_>,
        custody: Option<ModelCustody>,
        category: Option<&str>,
    ) -> Result<ResolvedModelPolicy, ModelPolicyError> {
        // Two tiers: models that explicitly allowlist the requested category
        // are preferred over models with no category restriction at all (an
        // unrestricted `availability` matches every category by default, but
        // that openness is a fallback, not a declared fit). Without this
        // split, a category query non-deterministically loses the
        // purpose-scoped model to whichever unrestricted model sorts first.
        let mut explicit = Vec::new();
        let mut open = Vec::new();
        for (provider, entry) in &self.providers {
            for model in &entry.models {
                if category.is_some()
                    && !entry
                        .availability
                        .permits(category, criteria.role, criteria.agent)
                {
                    continue;
                }
                if category.is_some()
                    && !model
                        .availability
                        .permits(category, criteria.role, criteria.agent)
                {
                    continue;
                }
                if self
                    .check_policy_candidate(provider, model, criteria, custody)
                    .is_ok()
                {
                    let resolved = self.resolved_policy(provider, &model.id, criteria, custody);
                    let is_explicit = category
                        .is_some_and(|c| model.availability.categories.iter().any(|cat| cat == c));
                    if is_explicit {
                        explicit.push(resolved);
                    } else {
                        open.push(resolved);
                    }
                }
            }
        }
        sort_policy_candidates(&mut explicit, criteria.optimize);
        sort_policy_candidates(&mut open, criteria.optimize);
        explicit
            .into_iter()
            .chain(open)
            .next()
            .ok_or_else(|| ModelPolicyError::NoEligibleModel(policy_selector_label(criteria)))
    }

    #[allow(dead_code)]
    fn check_policy_candidate(
        &self,
        provider: &str,
        model: &ModelEntry,
        criteria: &ModelPolicyCriteria<'_>,
        custody: Option<ModelCustody>,
    ) -> Result<(), ModelPolicyError> {
        if criteria.require_subagent_invokable
            && !self.resolve_subagent_invokable(provider, &model.id)
        {
            return Err(ModelPolicyError::NotSubagentInvokable {
                provider: provider.to_string(),
                model: model.id.clone(),
            });
        }
        // `availability` scopes *discovery*. An explicit host reference to one
        // provider/model is not discovery, so allowlists do not veto it — that
        // would make a category-scoped model unusable from agent-file
        // frontmatter, a configured role default, or a configured backup.
        if criteria.availability == AvailabilityScope::Discovery {
            let category = match criteria.selector {
                ModelPolicySelector::Category(category) => Some(category),
                _ => None,
            };
            let permitted =
                self.providers.get(provider).is_some_and(|entry| {
                    entry
                        .availability
                        .permits(category, criteria.role, criteria.agent)
                }) && model
                    .availability
                    .permits(category, criteria.role, criteria.agent);
            if !permitted {
                return Err(ModelPolicyError::RestrictedByAvailability {
                    provider: provider.to_string(),
                    model: model.id.clone(),
                });
            }
        } else if !self.providers.contains_key(provider) {
            return Err(ModelPolicyError::UnknownProvider(provider.to_string()));
        }
        if let Some(custody) = custody {
            let actual = self.resolve_trust(provider, &model.id);
            if actual != custody.required_trust() {
                return Err(ModelPolicyError::CustodyMismatch {
                    provider: provider.to_string(),
                    model: model.id.clone(),
                    required: custody,
                    actual,
                });
            }
        }
        let caps = self.resolve_effective_model_capabilities(
            provider,
            &model.id,
            self.resolution_generation,
        );
        for capability in &criteria.required_capabilities {
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
        if let Some(min) = criteria.min_context_tokens {
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
    fn resolved_policy(
        &self,
        provider: &str,
        model: &str,
        criteria: &ModelPolicyCriteria<'_>,
        custody: Option<ModelCustody>,
    ) -> ResolvedModelPolicy {
        ResolvedModelPolicy {
            provider: provider.to_string(),
            model: model.to_string(),
            trust: self.resolve_trust(provider, model),
            location: self.resolve_location(provider, model),
            quality_rank: self.resolve_quality_rank(provider, model),
            cost_rank: self.resolve_cost_rank(provider, model),
            custody_filter: custody,
        }
    }

    /// Resolve the configured embedding model.
    ///
    /// Embedding routing is host-owned: the *configured* `embedding_model`
    /// entry fixes the custody class rather than a caller choosing it, and the
    /// send boundary (`cockpit-core/src/embeddings.rs`) renders the request for
    /// the resolved class. It therefore resolves without a custody filter. This
    /// is not a caller-supplied custody hole — no caller-facing request type
    /// reaches this path.
    #[allow(dead_code)]
    pub fn resolve_embedding_model(
        &self,
        extended: &crate::config::extended::ExtendedConfig,
    ) -> Result<ResolvedEmbeddingModel, EmbeddingModelResolutionError> {
        if let Some(selector) = extended.embedding_model_ref() {
            let criteria = ModelPolicyCriteria {
                selector: ModelPolicySelector::Exact(selector),
                required_capabilities: vec![RequiredModelCapability::Embeddings],
                min_context_tokens: None,
                require_subagent_invokable: false,
                optimize: ModelOptimization::Balanced,
                role: Some("embedding_model"),
                agent: None,
                // The host configured this exact embedding model by name.
                availability: AvailabilityScope::HostNamedTarget,
            };
            let resolved = self
                .resolve_policy(&criteria, None)
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
                        custody_filter: None,
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
