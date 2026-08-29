//! Image-sidecar selection, destination grants, and accounting.
//!
//! This module resolves an explicit image-capable sidecar and requires narrow
//! revocable media-egress authority and exact accounting independently of
//! provider trust/redaction classification. It is split into three pure,
//! injectable phases joined by immutable identity:
//!
//! 1. **Selection** ([`SidecarResolver`]): a pure resolver that returns a
//!    structured trace covering every mode, trust-class default, per-primary
//!    override, capability evidence, and exact fallback rule. It consumes the
//!    central media policy's `sidecar_invocations_per_session` dimension — it
//!    never defines a second cap.
//! 2. **Destination policy** ([`DestinationPolicy`], [`DestinationPolicyDigest`]):
//!    a versioned SHA-256 canonical digest of only security-relevant effective
//!    identity. Grant equality uses only this semantic digest and separately
//!    rechecks current capability freshness/health at handoff.
//! 3. **Grant lifecycle** ([`DestinationGrant`], [`DestinationGrantStore`]):
//!    exact `once`/`session`/`project` scopes with atomic consumption,
//!    coalescing, revocation, and per-use session authorization. Global is
//!    not representable.
//!
//! The purpose body ([`PurposeBody`]) enforces the exact request boundary:
//! `dossier` uses one fixed versioned instruction with no caller text, while
//! `ask_image` uses one trimmed non-empty question bounded to 2,048 Unicode
//! scalar values and 8,192 UTF-8 bytes. The provider never receives
//! transcript, system/developer messages, memories, other attachments,
//! computer history, or hidden context.
//!
//! ## Design constraints (from the prompt)
//!
//! - Only explicitly configured, freshly image-capable models can be sidecars.
//!   No best-model discovery, alias, primary-chat fallback, or third candidate.
//! - Trust classification never stands in for egress consent. Existing generic
//!   trust is not egress consent.
//! - No global grant, trust-as-consent, sessionless project use, third-model
//!   fallback, transcript leakage, or Yolo-created standing grant.
//! - Authorization, budget/rate/provider failure never selects another model.
//! - Sidecar availability never qualifies a text-only primary for computer use.
//!
//! ## What this module deliberately does NOT own
//!
//! The central media policy owns the `sidecar_invocations_per_session`
//! default, hard ceiling, and durable handoff lifecycle. This module consumes
//! that dimension via [`SidecarInvocationCap`] and never defines a sidecar-local
//! cap field or fallback.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::config::media_budget::{MediaDimension, MediaLimitSource, MediaResourcePolicy};
use crate::config::config::model_policy::{EffectiveCapabilitySource, ResolvedInputCapability};
use crate::config::config::providers::{
    CapabilityStatus, ModelLocation, ModelTrust, ProvidersConfig,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The canonical serialization version for [`DestinationPolicyDigest`].
/// Bumping this invalidates every existing grant — a deliberate, visible
/// break that forces re-authorization after a security-relevant schema change.
pub const DESTINATION_POLICY_DIGEST_VERSION: u8 = 1;

/// The fixed instruction schema version for the `dossier` purpose body.
pub const DOSSIER_INSTRUCTION_VERSION: u8 = 1;

/// The fixed instruction schema version for the `ask_image` purpose body.
pub const ASK_IMAGE_INSTRUCTION_VERSION: u8 = 1;

/// Maximum Unicode scalar value count for an `ask_image` question.
pub const ASK_IMAGE_MAX_UNICODE_SCALARS: usize = 2_048;

/// Maximum UTF-8 byte count for an `ask_image` question.
pub const ASK_IMAGE_MAX_UTF8_BYTES: usize = 8_192;

/// The canonical capability-contract revision stamped onto digest inputs so a
/// capability-contract change invalidates grants even when the effective value
/// is identical.
pub const CAPABILITY_CONTRACT_REVISION: u8 = 1;

/// The fixed, versioned dossier instruction. It contains no caller text.
/// Changing this string bumps [`DOSSIER_INSTRUCTION_VERSION`].
pub const DOSSIER_FIXED_INSTRUCTION: &str = "Describe the provided image for the dossier. Report only what is visibly \
     present. Do not speculate. Do not include caller-supplied text.";

// ---------------------------------------------------------------------------
// Credential identity fingerprint
// ---------------------------------------------------------------------------

/// A SHA-256 fingerprint of credential identity. Computed from credential
/// bytes without persisting them. The inner bytes are never exposed in
/// diagnostics, DB, journal, audit, events, logs, export, or diagnostics.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialFingerprint([u8; 32]);

impl CredentialFingerprint {
    /// Compute a fingerprint from credential identity material. The caller
    /// passes a stable identity string (e.g. credential-ref id + provider);
    /// raw credential bytes are never stored.
    pub fn from_identity(material: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit:image-sidecar:credential-fingerprint:v1\n");
        hasher.update(material.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hex encoding for use inside the canonical digest input. This is only
    /// ever fed into another SHA-256; it is never persisted or printed alone.
    fn canonical_hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Debug for CredentialFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CredentialFingerprint(<redacted>)")
    }
}

/// The canonical hex form of a [`CredentialFingerprint`], as a type-enforced
/// newtype for binding into request digests and audit provenance.
///
/// The inner string is private, and the sole production constructor is
/// [`CredentialFingerprintDigest::from_fingerprint`], which routes through the
/// real fingerprint computation ([`CredentialFingerprint::from_identity`] then
/// the module-private canonical hex). This makes a raw credential TOKEN (or any
/// other arbitrary string) unrepresentable here: only a genuine 64-hex
/// credential *fingerprint* digest — never the credential itself — can be placed
/// in a field of this type and reach a bound digest, audit log, or prompt sink.
/// Mirrors [`crate::audio_transcription::authorization::MediaEgressRequestDigest`].
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct CredentialFingerprintDigest(String);

impl CredentialFingerprintDigest {
    /// The sole production constructor: bind to the real credential-fingerprint
    /// computation. The value is the canonical hex of the fingerprint bytes, an
    /// opaque digest of credential identity — not the credential material.
    pub fn from_fingerprint(fingerprint: &CredentialFingerprint) -> Self {
        Self(fingerprint.canonical_hex())
    }

    /// The full lowercase 64-hex fingerprint digest, for binding and for the
    /// redacted authorization audit. Read-only.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only raw constructor. `#[cfg(test)]`-gated so production code cannot
    /// bypass [`Self::from_fingerprint`].
    #[cfg(test)]
    pub(crate) fn from_raw_for_test(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

impl fmt::Debug for CredentialFingerprintDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The digest is an opaque fingerprint (not the credential); show it so
        // the bound value is debuggable, mirroring `MediaEgressRequestDigest`.
        write!(f, "CredentialFingerprintDigest({})", self.0)
    }
}

// ---------------------------------------------------------------------------
// Normalized endpoint origin
// ---------------------------------------------------------------------------

/// A normalized endpoint origin: scheme + host + port (if non-default).
/// Path, query, and fragment are excluded — they are request-scoped, not
/// destination identity. This is a security-relevant digest input.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NormalizedEndpointOrigin {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
}

impl NormalizedEndpointOrigin {
    /// Normalize a raw origin URL into its security-relevant origin tuple.
    /// Returns `None` for unparseable or schemeless origins.
    pub fn parse(raw: &str) -> Option<Self> {
        let parsed = reqwest::Url::parse(raw.trim_end_matches('/')).ok()?;
        let scheme = parsed.scheme().to_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let host = parsed.host_str()?.to_lowercase();
        let port = parsed.port();
        Some(Self { scheme, host, port })
    }

    /// Canonical string for digest input. Deterministic across platforms.
    fn canonical(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme, self.host, port),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

// ---------------------------------------------------------------------------
// Connected location class
// ---------------------------------------------------------------------------

/// The connected location class of the destination endpoint. This is a
/// security-relevant digest input: it changes where data is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ConnectedLocationClass {
    #[default]
    Local,
    PrivateNetwork,
    PublicCloud,
}

impl ConnectedLocationClass {
    pub fn from_model_location(location: Option<ModelLocation>) -> Self {
        match location {
            Some(ModelLocation::Local) | None => Self::Local,
            Some(ModelLocation::Remote) => Self::PublicCloud,
            Some(ModelLocation::PrivateRemote) => Self::PrivateNetwork,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::PrivateNetwork => "private_network",
            Self::PublicCloud => "public_cloud",
        }
    }
}

// ---------------------------------------------------------------------------
// Sidecar selection mode
// ---------------------------------------------------------------------------

pub use cockpit_config::config::image_sidecar::SidecarMode;

// ---------------------------------------------------------------------------
// Sidecar invocation cap (consumed from central media policy)
// ---------------------------------------------------------------------------

/// The effective `sidecar_invocations_per_session` value and provenance,
/// supplied by the central media policy evaluator. This module consumes it;
/// it never defines a sidecar-local cap field or fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SidecarInvocationCap {
    pub value: u64,
    pub provenance: SidecarInvocationCapProvenance,
}

/// Provenance of the effective sidecar invocation cap. Mirrors the central
/// media policy's limit-source hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarInvocationCapProvenance {
    CompiledCeiling,
    Configured,
    Profile,
    Adapter,
    Request,
}

impl From<MediaLimitSource> for SidecarInvocationCapProvenance {
    fn from(source: MediaLimitSource) -> Self {
        match source {
            MediaLimitSource::CompiledCeiling => Self::CompiledCeiling,
            MediaLimitSource::Configured => Self::Configured,
            MediaLimitSource::Profile => Self::Profile,
            MediaLimitSource::Adapter => Self::Adapter,
            MediaLimitSource::Request => Self::Request,
        }
    }
}

impl SidecarInvocationCap {
    /// Resolve the effective cap from the central media resource policy. This
    /// is the only way this module learns the cap — there is no sidecar-local
    /// fallback.
    pub fn from_media_policy(policy: &MediaResourcePolicy) -> Self {
        let plan = policy.evaluate(
            crate::config::config::media_budget::MediaEvaluationRequest {
                dimension: MediaDimension::SidecarInvocationsPerSession,
                requested: Some(1),
                current_scope: 0,
                profile: None,
                adapter_limit: None,
                request_limit: None,
            },
        );
        match plan {
            Ok(plan) => Self {
                value: plan.effective_limit,
                provenance: plan.source.into(),
            },
            // The central policy always returns Ok for a valid dimension with
            // a non-zero requested value; this branch is defensive only.
            Err(_) => Self {
                value: policy.limits().sidecar_invocations_per_session,
                provenance: SidecarInvocationCapProvenance::Configured,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Sidecar configuration
// ---------------------------------------------------------------------------

pub use cockpit_config::config::image_sidecar::{SidecarProviderModel, SidecarSelectionConfig};

// ---------------------------------------------------------------------------
// Capability evidence
// ---------------------------------------------------------------------------

/// Capability evidence for a candidate or primary. Carries the effective
/// image-input status, source, and the config/source generation used for
/// stale-operation rejection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageCapabilityEvidence {
    pub status: CapabilityStatus,
    pub source: EffectiveCapabilitySource,
    pub source_generation: u64,
    /// Whether the capability is freshly supported at resolution time.
    pub fresh: bool,
}

impl ImageCapabilityEvidence {
    pub fn from_resolved(cap: &ResolvedInputCapability, fresh: bool) -> Self {
        Self {
            status: cap.status,
            source: cap.source,
            source_generation: cap.source_generation,
            fresh,
        }
    }

    pub fn is_freshly_image_capable(&self) -> bool {
        self.fresh && self.status == CapabilityStatus::Supported
    }

    pub fn is_image_capable(&self) -> bool {
        self.status == CapabilityStatus::Supported
    }
}

// ---------------------------------------------------------------------------
// Selection source
// ---------------------------------------------------------------------------

/// Where the sidecar selection came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionSource {
    /// `never` mode: no sidecar.
    NeverMode,
    /// A per-primary override was configured and selected.
    PerPrimaryOverride,
    /// The trust-class default was selected.
    TrustClassDefault,
    /// Fallback to the already-selected image-capable primary.
    PrimaryFallback,
}

impl SelectionSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeverMode => "never_mode",
            Self::PerPrimaryOverride => "per_primary_override",
            Self::TrustClassDefault => "trust_class_default",
            Self::PrimaryFallback => "primary_fallback",
        }
    }
}

// ---------------------------------------------------------------------------
// Sidecar resolution outcome
// ---------------------------------------------------------------------------

/// The outcome of sidecar resolution. Carries the exact selected pair (or
/// none), capability evidence, trust/redaction class, normalized endpoint
/// origin, connected location class, credential fingerprint, selection source,
/// config generation for stale-operation rejection, the destination policy
/// digest, availability, and a stable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarResolution {
    /// The selected sidecar, or `None` when mode is `never` or no candidate
    /// is available and the primary is not image-capable.
    pub selected: Option<SelectedSidecar>,
    /// The effective invocation cap/value provenance from the central media
    /// policy. This module never defines a second cap.
    pub invocation_cap: SidecarInvocationCap,
    /// Stable, machine-readable reason for the outcome.
    pub reason: SidecarReason,
    /// Whether a visible fallback warning should be surfaced.
    pub fallback_warning: Option<FallbackWarning>,
}

/// A selected sidecar candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedSidecar {
    pub provider: String,
    pub model: String,
    pub trust: ModelTrust,
    pub location: ConnectedLocationClass,
    pub endpoint_origin: NormalizedEndpointOrigin,
    pub credential_fingerprint: CredentialFingerprint,
    pub capability_evidence: ImageCapabilityEvidence,
    pub selection_source: SelectionSource,
    pub config_generation: u64,
    pub destination_policy_digest: DestinationPolicyDigest,
}

/// Stable reason codes for sidecar resolution outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SidecarReason {
    NeverMode,
    Selected,
    PrimaryImageCapableAutomatic,
    NoCandidate,
    CandidateUnavailable,
    PrimaryFallback,
    MissingCandidate,
    StaleCapability,
    MissingCredential,
    InvalidConfig,
}

impl SidecarReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NeverMode => "never_mode",
            Self::Selected => "selected",
            Self::PrimaryImageCapableAutomatic => "primary_image_capable_automatic",
            Self::NoCandidate => "no_candidate",
            Self::CandidateUnavailable => "candidate_unavailable",
            Self::PrimaryFallback => "primary_fallback",
            Self::MissingCandidate => "missing_candidate",
            Self::StaleCapability => "stale_capability",
            Self::MissingCredential => "missing_credential",
            Self::InvalidConfig => "invalid_config",
        }
    }
}

/// A visible fallback warning. Exactly one is permitted per resolution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FallbackWarning {
    pub reason: FallbackWarningReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FallbackWarningReason {
    /// The selected candidate was absent/unavailable; falling back to the
    /// image-capable primary.
    CandidateUnavailableFallbackToPrimary,
}

impl FallbackWarningReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CandidateUnavailableFallbackToPrimary => {
                "candidate_unavailable_fallback_to_primary"
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Sidecar resolver
// ---------------------------------------------------------------------------

/// Pure sidecar resolver. It takes the central media policy (for the cap),
/// the providers config (for capability resolution), and the sidecar selection
/// config, and returns a structured trace. No I/O, no clocks, no network.
pub struct SidecarResolver<'a> {
    providers: &'a ProvidersConfig,
    media_policy: &'a MediaResourcePolicy,
    config: &'a SidecarSelectionConfig,
    config_generation: u64,
}

impl<'a> SidecarResolver<'a> {
    pub fn new(
        providers: &'a ProvidersConfig,
        media_policy: &'a MediaResourcePolicy,
        config: &'a SidecarSelectionConfig,
        config_generation: u64,
    ) -> Self {
        Self {
            providers,
            media_policy,
            config,
            config_generation,
        }
    }

    /// Resolve the sidecar for a given primary provider/model and its
    /// image-input capability.
    ///
    /// Resolution order is exact:
    /// 1. `never`: no sidecar.
    /// 2. A per-primary override, if configured, is the only candidate.
    /// 3. Otherwise choose the default for the primary's trust class.
    /// 4. `automatic` uses an image-capable primary directly and selects the
    ///    candidate only when the primary lacks image input.
    /// 5. `always` selects the candidate even when the primary is
    ///    image-capable.
    /// 6. If the selected candidate is absent/unavailable, fallback is
    ///    permitted only to the already-selected primary when that primary is
    ///    image-capable, with one visible warning. Never choose a third model.
    pub fn resolve(
        &self,
        primary_provider: &str,
        primary_model: &str,
        primary_image_capable: bool,
    ) -> SidecarResolution {
        let invocation_cap = SidecarInvocationCap::from_media_policy(self.media_policy);

        // 1. never
        if self.config.mode == SidecarMode::Never {
            return SidecarResolution {
                selected: None,
                invocation_cap,
                reason: SidecarReason::NeverMode,
                fallback_warning: None,
            };
        }

        // 2. per-primary override is the only candidate
        // 3. otherwise the trust-class default
        let candidate = self.config.per_primary_override.clone().or_else(|| {
            let trust = self
                .providers
                .resolve_trust(primary_provider, primary_model);
            let default = match trust {
                ModelTrust::Trusted => &self.config.trusted_primary_default,
                ModelTrust::Untrusted => &self.config.untrusted_primary_default,
            };
            default.clone()
        });

        let Some(candidate) = candidate else {
            // No candidate configured. Fallback only to a capable primary.
            return self.fallback_to_primary(
                primary_provider,
                primary_model,
                primary_image_capable,
                invocation_cap,
                SidecarReason::MissingCandidate,
            );
        };

        // 4. automatic: use image-capable primary directly
        if self.config.mode == SidecarMode::Automatic && primary_image_capable {
            return SidecarResolution {
                selected: None,
                invocation_cap,
                reason: SidecarReason::PrimaryImageCapableAutomatic,
                fallback_warning: None,
            };
        }

        // 5. always (or automatic with non-capable primary): select the candidate
        // 6. If the candidate is absent/unavailable, fallback to capable primary
        let candidate_evidence = self.resolve_candidate_evidence(&candidate);
        if !candidate_evidence.is_freshly_image_capable() {
            return self.fallback_to_primary(
                primary_provider,
                primary_model,
                primary_image_capable,
                invocation_cap,
                SidecarReason::CandidateUnavailable,
            );
        }

        let selected = match self.build_selected_sidecar(&candidate, candidate_evidence) {
            Some(s) => s,
            None => {
                return self.fallback_to_primary(
                    primary_provider,
                    primary_model,
                    primary_image_capable,
                    invocation_cap,
                    SidecarReason::MissingCredential,
                );
            }
        };

        SidecarResolution {
            selected: Some(selected),
            invocation_cap,
            reason: SidecarReason::Selected,
            fallback_warning: None,
        }
    }

    fn fallback_to_primary(
        &self,
        primary_provider: &str,
        primary_model: &str,
        primary_image_capable: bool,
        invocation_cap: SidecarInvocationCap,
        fail_reason: SidecarReason,
    ) -> SidecarResolution {
        if primary_image_capable {
            let primary_evidence = self.resolve_candidate_evidence(&SidecarProviderModel {
                provider: primary_provider.to_string(),
                model: primary_model.to_string(),
            });
            if primary_evidence.is_freshly_image_capable()
                && let Some(selected) = self.build_selected_sidecar(
                    &SidecarProviderModel {
                        provider: primary_provider.to_string(),
                        model: primary_model.to_string(),
                    },
                    primary_evidence,
                )
            {
                return SidecarResolution {
                    selected: Some(selected),
                    invocation_cap,
                    reason: SidecarReason::PrimaryFallback,
                    fallback_warning: Some(FallbackWarning {
                        reason: FallbackWarningReason::CandidateUnavailableFallbackToPrimary,
                    }),
                };
            }
        }
        SidecarResolution {
            selected: None,
            invocation_cap,
            reason: fail_reason,
            fallback_warning: None,
        }
    }

    fn resolve_candidate_evidence(
        &self,
        candidate: &SidecarProviderModel,
    ) -> ImageCapabilityEvidence {
        let caps = self.providers.resolve_effective_model_capabilities(
            &candidate.provider,
            &candidate.model,
            self.config_generation,
        );
        ImageCapabilityEvidence::from_resolved(&caps.image_input, true)
    }

    fn build_selected_sidecar(
        &self,
        candidate: &SidecarProviderModel,
        evidence: ImageCapabilityEvidence,
    ) -> Option<SelectedSidecar> {
        let entry = self.providers.providers.get(&candidate.provider)?;
        let _model_entry = entry.models.iter().find(|m| m.id == candidate.model)?;
        let trust = self
            .providers
            .resolve_trust(&candidate.provider, &candidate.model);
        let location = ConnectedLocationClass::from_model_location(
            self.providers
                .resolve_location(&candidate.provider, &candidate.model),
        );
        let endpoint_origin = NormalizedEndpointOrigin::parse(&entry.url)?;
        let credential_fingerprint = match &entry.credential_ref {
            Some(cred) => CredentialFingerprint::from_identity(&format!(
                "{}:{}:{}",
                candidate.provider, candidate.model, cred
            )),
            None => CredentialFingerprint::from_identity(&format!(
                "{}:{}:no-credential-ref",
                candidate.provider, candidate.model
            )),
        };
        let project_identity = ProjectIdentity::default();
        let destination_policy = DestinationPolicy {
            provider: candidate.provider.clone(),
            model: candidate.model.clone(),
            endpoint_origin: endpoint_origin.clone(),
            connected_location: location,
            credential_fingerprint: credential_fingerprint.clone(),
            project_identity,
            image_capability_value: evidence.status,
            capability_contract_revision: CAPABILITY_CONTRACT_REVISION,
            egress_fields: EgressFields::default(),
        };
        let selection_source = if self.config.per_primary_override.as_ref() == Some(candidate) {
            SelectionSource::PerPrimaryOverride
        } else {
            SelectionSource::TrustClassDefault
        };
        Some(SelectedSidecar {
            provider: candidate.provider.clone(),
            model: candidate.model.clone(),
            trust,
            location,
            endpoint_origin,
            credential_fingerprint,
            capability_evidence: evidence,
            selection_source,
            config_generation: self.config_generation,
            destination_policy_digest: destination_policy.digest(),
        })
    }
}

// ---------------------------------------------------------------------------
// Destination policy and digest
// ---------------------------------------------------------------------------

/// Project identity for destination grants. Machine-local.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct ProjectIdentity {
    /// Hashed project root path. Never the raw path.
    pub project_hash: String,
}

impl ProjectIdentity {
    pub fn from_root(root: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit:image-sidecar:project-identity:v1\n");
        hasher.update(root.as_bytes());
        let digest = hasher.finalize();
        let mut hex = String::with_capacity(64);
        for byte in digest.iter() {
            hex.push_str(&format!("{byte:02x}"));
        }
        Self { project_hash: hex }
    }
}

/// Effective egress/routing fields that can change where or what is sent.
/// These are security-relevant digest inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EgressFields {
    /// Routing path or prefix, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_prefix: Option<String>,
    /// Whether insecure transport is allowed.
    pub allow_insecure_transport: bool,
    /// Additional routing headers count (not the values — values may carry
    /// secrets; only the count is a routing-relevant digest input).
    pub header_count: usize,
}

/// The immutable destination tuple for grant identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationPolicy {
    pub provider: String,
    pub model: String,
    pub endpoint_origin: NormalizedEndpointOrigin,
    pub connected_location: ConnectedLocationClass,
    pub credential_fingerprint: CredentialFingerprint,
    pub project_identity: ProjectIdentity,
    pub image_capability_value: CapabilityStatus,
    pub capability_contract_revision: u8,
    pub egress_fields: EgressFields,
}

impl DestinationPolicy {
    /// Compute the versioned SHA-256 canonical digest of only
    /// security-relevant effective identity.
    ///
    /// It includes: provider, model, normalized endpoint origin, connected
    /// location class, credential fingerprint, project identity, effective
    /// image-input capability value plus capability-contract revision, and
    /// every effective egress/routing field.
    ///
    /// It excludes: display names, list order, unrelated settings, raw config
    /// generation, capability probe timestamps/freshness, health observations,
    /// and presentation metadata.
    pub fn digest(&self) -> DestinationPolicyDigest {
        let canonical = self.canonical_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit:image-sidecar:destination-policy-digest:v");
        hasher.update([DESTINATION_POLICY_DIGEST_VERSION]);
        hasher.update(b"\n");
        hasher.update(&canonical);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        DestinationPolicyDigest {
            version: DESTINATION_POLICY_DIGEST_VERSION,
            bytes,
        }
    }

    /// Canonical byte encoding of only the security-relevant fields. The
    /// ordering is fixed and deterministic.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        // Provider
        buf.extend(b"provider=");
        buf.extend(self.provider.as_bytes());
        buf.push(0);
        // Model
        buf.extend(b"model=");
        buf.extend(self.model.as_bytes());
        buf.push(0);
        // Endpoint origin
        buf.extend(b"origin=");
        buf.extend(self.endpoint_origin.canonical().as_bytes());
        buf.push(0);
        // Connected location class
        buf.extend(b"location=");
        buf.extend(self.connected_location.as_str().as_bytes());
        buf.push(0);
        // Credential fingerprint (hex of the fingerprint, not raw credential)
        buf.extend(b"cred=");
        buf.extend(self.credential_fingerprint.canonical_hex().as_bytes());
        buf.push(0);
        // Project identity
        buf.extend(b"project=");
        buf.extend(self.project_identity.project_hash.as_bytes());
        buf.push(0);
        // Image capability value
        buf.extend(b"image_cap=");
        buf.extend(capability_status_str(self.image_capability_value).as_bytes());
        buf.push(0);
        // Capability contract revision
        buf.extend(b"cap_contract_rev=");
        buf.push(self.capability_contract_revision);
        buf.push(0);
        // Egress fields
        buf.extend(b"egress:path_prefix=");
        buf.extend(
            self.egress_fields
                .path_prefix
                .as_deref()
                .unwrap_or("")
                .as_bytes(),
        );
        buf.push(0);
        buf.extend(b"egress:allow_insecure=");
        buf.push(if self.egress_fields.allow_insecure_transport {
            1
        } else {
            0
        });
        buf.push(0);
        buf.extend(b"egress:header_count=");
        buf.extend(self.egress_fields.header_count.to_le_bytes());
        buf.push(0);
        buf
    }
}

/// A versioned SHA-256 canonical digest of destination policy identity.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DestinationPolicyDigest {
    pub version: u8,
    bytes: [u8; 32],
}

impl DestinationPolicyDigest {
    pub const fn from_bytes(version: u8, bytes: [u8; 32]) -> Self {
        Self { version, bytes }
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Debug for DestinationPolicyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DestinationPolicyDigest")
            .field("version", &self.version)
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl fmt::Display for DestinationPolicyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{}:{}", self.version, self.hex())
    }
}

fn capability_status_str(status: CapabilityStatus) -> &'static str {
    match status {
        CapabilityStatus::Supported => "supported",
        CapabilityStatus::Unsupported => "unsupported",
        CapabilityStatus::RequiresEntitlement => "requires_entitlement",
        CapabilityStatus::Unknown => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Purpose
// ---------------------------------------------------------------------------

/// The closed purpose for a sidecar invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Purpose {
    /// Dossier: one fixed versioned instruction with no caller text.
    Dossier,
    /// Ask-image: one trimmed non-empty question.
    AskImage,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Dossier => "dossier",
            Self::AskImage => "ask_image",
        }
    }

    pub fn instruction_version(self) -> u8 {
        match self {
            Self::Dossier => DOSSIER_INSTRUCTION_VERSION,
            Self::AskImage => ASK_IMAGE_INSTRUCTION_VERSION,
        }
    }
}

/// The media class for a reference grant. Always `image` for sidecars.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaClass {
    Image,
}

impl MediaClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Image => "image",
        }
    }
}

/// The purpose body sent to the provider. Exactly one purpose media artifact
/// and one purpose body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PurposeBody {
    pub purpose: Purpose,
    /// The versioned instruction (dossier) or trimmed question (ask_image).
    pub body: String,
    pub instruction_version: u8,
    /// Unicode scalar value count.
    pub unicode_scalar_len: usize,
    /// UTF-8 byte count.
    pub utf8_byte_len: usize,
}

/// Errors that can arise when constructing a purpose body.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PurposeBodyError {
    #[error("ask_image question must be non-empty after trimming")]
    EmptyQuestion,
    #[error("ask_image question exceeds {ASK_IMAGE_MAX_UNICODE_SCALARS} Unicode scalar values")]
    TooManyUnicodeScalars,
    #[error("ask_image question exceeds {ASK_IMAGE_MAX_UTF8_BYTES} UTF-8 bytes")]
    TooManyUtf8Bytes,
}

impl PurposeBody {
    /// Build the fixed dossier purpose body. No caller text.
    pub fn dossier() -> Self {
        let body = DOSSIER_FIXED_INSTRUCTION;
        let unicode_scalar_len = body.chars().count();
        let utf8_byte_len = body.len();
        Self {
            purpose: Purpose::Dossier,
            body: body.to_string(),
            instruction_version: DOSSIER_INSTRUCTION_VERSION,
            unicode_scalar_len,
            utf8_byte_len,
        }
    }

    /// Build an ask_image purpose body from a caller question. The question
    /// is trimmed, must be non-empty, and is bounded to 2,048 Unicode scalar
    /// values and 8,192 UTF-8 bytes.
    pub fn ask_image(question: &str) -> Result<Self, PurposeBodyError> {
        let trimmed = question.trim();
        if trimmed.is_empty() {
            return Err(PurposeBodyError::EmptyQuestion);
        }
        let unicode_scalar_len = trimmed.chars().count();
        if unicode_scalar_len > ASK_IMAGE_MAX_UNICODE_SCALARS {
            return Err(PurposeBodyError::TooManyUnicodeScalars);
        }
        let utf8_byte_len = trimmed.len();
        if utf8_byte_len > ASK_IMAGE_MAX_UTF8_BYTES {
            return Err(PurposeBodyError::TooManyUtf8Bytes);
        }
        Ok(Self {
            purpose: Purpose::AskImage,
            body: trimmed.to_string(),
            instruction_version: ASK_IMAGE_INSTRUCTION_VERSION,
            unicode_scalar_len,
            utf8_byte_len,
        })
    }

    /// Compute the SHA-256 of the versioned canonical purpose body, computed
    /// from the exact body before dispatch. The body itself is never persisted.
    pub fn digest(&self) -> PurposeBodyDigest {
        let mut hasher = Sha256::new();
        hasher.update(b"cockpit:image-sidecar:purpose-body:v");
        hasher.update([self.instruction_version]);
        hasher.update([0]);
        hasher.update(self.purpose.as_str().as_bytes());
        hasher.update(b"\n");
        hasher.update(self.body.as_bytes());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        PurposeBodyDigest { bytes }
    }
}

/// SHA-256 of the versioned canonical purpose body. The body is never
/// persisted; only this digest is stored.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PurposeBodyDigest {
    bytes: [u8; 32],
}

impl PurposeBodyDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self { bytes }
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn hex(&self) -> String {
        let mut out = String::with_capacity(64);
        for byte in self.bytes {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }
}

impl fmt::Debug for PurposeBodyDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PurposeBodyDigest")
            .field("bytes", &"<redacted>")
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Destination grant scope
// ---------------------------------------------------------------------------

/// Grant scope for a destination grant. Global is not representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    /// One immutable invocation ID and destination/purpose tuple; consumed
    /// atomically on handoff.
    Once,
    /// Exact session ID, project, destination, media class, and purpose; every
    /// invocation has a separate audit/accounting record.
    Session,
    /// Exact machine-local project, destination, media class, and purpose; no
    /// session wildcard. Every use separately requires the invoking
    /// principal's current session authorization for that project.
    Project,
}

impl GrantScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Project => "project",
        }
    }
}

// ---------------------------------------------------------------------------
// Destination grant
// ---------------------------------------------------------------------------

/// The destination/purpose tuple bound to a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationTuple {
    pub provider: String,
    pub model: String,
    pub endpoint_origin: NormalizedEndpointOrigin,
    pub connected_location: ConnectedLocationClass,
    pub credential_fingerprint: CredentialFingerprint,
    pub project_identity: ProjectIdentity,
    pub destination_policy_digest: DestinationPolicyDigest,
    pub media_class: MediaClass,
    pub purpose: Purpose,
}

/// A destination grant. Persisted binding and use rules are scope-dependent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestinationGrant {
    pub id: String,
    pub scope: GrantScope,
    pub tuple: DestinationTuple,
    pub created_at_ms: u64,
    pub revoked: bool,
    /// For `once` scope: whether this grant has been consumed.
    pub consumed: bool,
    /// For `session` scope: the exact session ID.
    pub session_id: Option<String>,
    /// For `project` scope: the exact machine-local project identity.
    pub project: Option<ProjectIdentity>,
}

impl DestinationGrant {
    /// Check whether this grant authorizes the given destination/purpose
    /// tuple at the given scope. Uses only the semantic digest for equality.
    pub fn authorizes(
        &self,
        tuple: &DestinationTuple,
        scope: GrantScope,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
    ) -> bool {
        if self.revoked {
            return false;
        }
        if self.scope != scope {
            return false;
        }
        // Grant equality uses only the semantic digest.
        if self.tuple.destination_policy_digest != tuple.destination_policy_digest {
            return false;
        }
        if self.tuple.media_class != tuple.media_class {
            return false;
        }
        if self.tuple.purpose != tuple.purpose {
            return false;
        }
        match scope {
            GrantScope::Once => !self.consumed,
            GrantScope::Session => self.session_id.as_deref() == session_id,
            GrantScope::Project => self.project.as_ref() == project,
        }
    }
}

// ---------------------------------------------------------------------------
// Destination grant store
// ---------------------------------------------------------------------------

/// In-memory destination grant store. Supports atomic once consumption,
/// coalescing of concurrent first use, and revocation.
///
/// In production this would be backed by SQLite; for the pure policy layer we
/// keep it in-memory behind a trait so tests can inject fakes.
pub struct DestinationGrantStore {
    grants: Mutex<HashMap<String, DestinationGrant>>,
    /// Coalescing: waiters for a pending first-use decision on a tuple.
    pending: Mutex<HashMap<TupleKey, Vec<String>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TupleKey {
    digest_hex: String,
    media_class: MediaClass,
    purpose: Purpose,
    scope: GrantScope,
    session_id: Option<String>,
    project_hash: Option<String>,
}

impl TupleKey {
    fn from(
        tuple: &DestinationTuple,
        scope: GrantScope,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
    ) -> Self {
        Self {
            digest_hex: tuple.destination_policy_digest.hex(),
            media_class: tuple.media_class,
            purpose: tuple.purpose,
            scope,
            session_id: session_id.map(str::to_owned),
            project_hash: project.map(|p| p.project_hash.clone()),
        }
    }
}

/// Outcome of a grant authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantAuthorizationOutcome {
    /// The grant authorizes this use.
    Authorized { grant_id: String, scope: GrantScope },
    /// The grant was found but has been revoked.
    Revoked,
    /// No grant found for this tuple/scope.
    NotFound,
    /// A `once` grant was already consumed.
    Consumed,
    /// Session authorization failed for a project-scoped grant.
    SessionAuthorizationFailed,
}

/// Outcome of a first-use decision coalescing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FirstUseOutcome {
    /// This caller won the coalescing race and must perform the prompt.
    Leader,
    /// Another caller is already prompting; this caller waits.
    Follower,
}

/// Errors from the grant store.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GrantStoreError {
    #[error("grant not found")]
    NotFound,
    #[error("grant already consumed")]
    AlreadyConsumed,
    #[error("grant already revoked")]
    AlreadyRevoked,
    #[error("global scope is not representable")]
    GlobalNotRepresentable,
}

impl Default for DestinationGrantStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DestinationGrantStore {
    pub fn new() -> Self {
        Self {
            grants: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// Record a new grant. Returns an error if a global scope is attempted.
    pub fn record(
        &self,
        scope: GrantScope,
        tuple: DestinationTuple,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
        created_at_ms: u64,
    ) -> Result<DestinationGrant, GrantStoreError> {
        let id = format!(
            "grant-{}-{}",
            scope.as_str(),
            tuple.destination_policy_digest.hex()
        );
        let grant = DestinationGrant {
            id: id.clone(),
            scope,
            tuple,
            created_at_ms,
            revoked: false,
            consumed: false,
            session_id: session_id.map(str::to_owned),
            project: project.cloned(),
        };
        self.grants
            .lock()
            .unwrap()
            .insert(id.clone(), grant.clone());
        Ok(grant)
    }

    /// Check whether a grant authorizes the given tuple/scope. Does not
    /// consume.
    pub fn check(
        &self,
        tuple: &DestinationTuple,
        scope: GrantScope,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
    ) -> GrantAuthorizationOutcome {
        let grants = self.grants.lock().unwrap();
        for grant in grants.values() {
            if grant.tuple.destination_policy_digest != tuple.destination_policy_digest {
                continue;
            }
            if grant.revoked {
                return GrantAuthorizationOutcome::Revoked;
            }
            if grant.scope != scope {
                continue;
            }
            if grant.tuple.media_class != tuple.media_class || grant.tuple.purpose != tuple.purpose
            {
                continue;
            }
            match scope {
                GrantScope::Once => {
                    if grant.consumed {
                        return GrantAuthorizationOutcome::Consumed;
                    }
                    return GrantAuthorizationOutcome::Authorized {
                        grant_id: grant.id.clone(),
                        scope,
                    };
                }
                GrantScope::Session => {
                    if grant.session_id.as_deref() == session_id {
                        return GrantAuthorizationOutcome::Authorized {
                            grant_id: grant.id.clone(),
                            scope,
                        };
                    }
                }
                GrantScope::Project => {
                    if grant.project.as_ref() == project {
                        // Per-use current session authorization is rechecked
                        // at handoff by the caller; the store confirms the
                        // project-scoped grant exists.
                        return GrantAuthorizationOutcome::Authorized {
                            grant_id: grant.id.clone(),
                            scope,
                        };
                    }
                }
            }
        }
        GrantAuthorizationOutcome::NotFound
    }

    /// Atomically consume a `once` grant. Returns the grant id on success.
    pub fn consume_once(&self, grant_id: &str) -> Result<String, GrantStoreError> {
        let mut grants = self.grants.lock().unwrap();
        let grant = grants.get_mut(grant_id).ok_or(GrantStoreError::NotFound)?;
        if grant.revoked {
            return Err(GrantStoreError::AlreadyRevoked);
        }
        if grant.consumed {
            return Err(GrantStoreError::AlreadyConsumed);
        }
        grant.consumed = true;
        Ok(grant_id.to_string())
    }

    /// Revoke a grant. Revocation-first means zero call; handoff-first
    /// remains journaled/accounted and cannot dispatch twice.
    pub fn revoke(&self, grant_id: &str) -> Result<(), GrantStoreError> {
        let mut grants = self.grants.lock().unwrap();
        let grant = grants.get_mut(grant_id).ok_or(GrantStoreError::NotFound)?;
        grant.revoked = true;
        Ok(())
    }

    /// Begin first-use coalescing for a tuple. Returns whether this caller is
    /// the leader (must prompt) or a follower (must wait).
    pub fn begin_first_use(
        &self,
        waiter_id: &str,
        tuple: &DestinationTuple,
        scope: GrantScope,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
    ) -> FirstUseOutcome {
        let key = TupleKey::from(tuple, scope, session_id, project);
        let mut pending = self.pending.lock().unwrap();
        match pending.entry(key) {
            std::collections::hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().push(waiter_id.to_string());
                FirstUseOutcome::Follower
            }
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(vec![waiter_id.to_string()]);
                FirstUseOutcome::Leader
            }
        }
    }

    /// Complete first-use coalescing, returning all waiter IDs that were
    /// waiting on this tuple. The leader's decision applies to all.
    pub fn complete_first_use(
        &self,
        tuple: &DestinationTuple,
        scope: GrantScope,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
    ) -> Vec<String> {
        let key = TupleKey::from(tuple, scope, session_id, project);
        self.pending
            .lock()
            .unwrap()
            .remove(&key)
            .unwrap_or_default()
    }

    /// Cancel first-use coalescing for a tuple (e.g. the leader cancelled).
    /// Returns all waiter IDs so they can be failed.
    pub fn cancel_first_use(
        &self,
        tuple: &DestinationTuple,
        scope: GrantScope,
        session_id: Option<&str>,
        project: Option<&ProjectIdentity>,
    ) -> Vec<String> {
        let key = TupleKey::from(tuple, scope, session_id, project);
        self.pending
            .lock()
            .unwrap()
            .remove(&key)
            .unwrap_or_default()
    }

    /// List all grants (for inspection/testing).
    pub fn list(&self) -> Vec<DestinationGrant> {
        self.grants.lock().unwrap().values().cloned().collect()
    }
}

// ---------------------------------------------------------------------------
// Invocation record (accounting)
// ---------------------------------------------------------------------------

/// The state of a sidecar invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationState {
    Pending,
    Authorized,
    Dispatched,
    Accepted,
    Completed,
    Failed,
    Cancelled,
    Ambiguous,
}

impl InvocationState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Authorized => "authorized",
            Self::Dispatched => "dispatched",
            Self::Accepted => "accepted",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Ambiguous => "ambiguous",
        }
    }
}

/// The disposition of a sidecar invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationDisposition {
    Granted,
    Denied,
    Revoked,
    AgentDiscretion,
}

impl InvocationDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Granted => "granted",
            Self::Denied => "denied",
            Self::Revoked => "revoked",
            Self::AgentDiscretion => "agent_discretion",
        }
    }
}

/// A sidecar invocation record. Every dispatch is visibly disclosed and has
/// invocation ID, parent operation, purpose, provider/model/destination,
/// timestamps, state, usage/cost status, resource charge, grant/disposition,
/// and redacted error.
///
/// Durable metadata contains no prompt/question text or preview. It records
/// only the closed purpose, fixed instruction/schema version, SHA-256 of the
/// versioned canonical purpose body, Unicode-scalar length, UTF-8-byte length,
/// and safe operational fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationRecord {
    pub invocation_id: String,
    pub parent_operation: String,
    pub purpose: Purpose,
    pub provider: String,
    pub model: String,
    pub destination_policy_digest_hex: String,
    pub created_at_ms: u64,
    pub dispatched_at_ms: Option<u64>,
    pub terminal_at_ms: Option<u64>,
    pub state: InvocationState,
    pub usage_status: UsageStatus,
    pub resource_charge: ResourceCharge,
    pub disposition: InvocationDisposition,
    pub grant_id: Option<String>,
    /// Purpose body metadata only — never the body itself.
    pub purpose_body_meta: PurposeBodyMeta,
    /// Redacted error, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_error: Option<String>,
}

/// Safe purpose-body metadata. Contains only version, digest, scalar length,
/// and byte length — never the body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PurposeBodyMeta {
    pub purpose: Purpose,
    pub instruction_version: u8,
    pub body_digest_hex: String,
    pub unicode_scalar_len: usize,
    pub utf8_byte_len: usize,
}

impl PurposeBodyMeta {
    pub fn from_body(body: &PurposeBody) -> Self {
        Self {
            purpose: body.purpose,
            instruction_version: body.instruction_version,
            body_digest_hex: body.digest().hex(),
            unicode_scalar_len: body.unicode_scalar_len,
            utf8_byte_len: body.utf8_byte_len,
        }
    }
}

/// Usage/cost status for an invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageStatus {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_micro_usd: Option<u64>,
}

/// Resource charge for an invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCharge {
    pub sidecar_invocation_charged: bool,
    pub media_reservation_id: Option<String>,
    pub provider_concurrency_slot: Option<String>,
}

// ---------------------------------------------------------------------------
// Approval mode (Ask / Yolo)
// ---------------------------------------------------------------------------

/// The approval mode for sidecar egress authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalMode {
    /// Ask mode: first-use authority prompting; may save once/session/project.
    #[default]
    Ask,
    /// Yolo mode: no human prompt; may use the current invocation under
    /// audited `agent_discretion` after hard gates. Does not silently create
    /// a standing grant.
    Yolo,
}

impl ApprovalMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ask => "ask",
            Self::Yolo => "yolo",
        }
    }
}

/// The egress authorization decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EgressDecision {
    /// In Ask mode, the user granted authority at the given scope.
    AskGranted { scope: GrantScope, grant_id: String },
    /// In Ask mode, the user denied authority.
    AskDenied,
    /// In Yolo mode, the invocation is allowed under audited
    /// `agent_discretion` after hard gates. No standing grant is created.
    YoloAgentDiscretion { invocation_id: String },
    /// A hard gate failed (destination denial, cap exhaustion, missing
    /// credential, stale capability). Trust classification never changes this.
    HardGateFailed { reason: HardGateFailureReason },
}

/// Hard gate failure reasons. Authorization, budget/rate/provider failure
/// never selects another model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardGateFailureReason {
    DestinationDenied,
    CapExhausted,
    ProviderConcurrencyExhausted,
    MediaReservationDenied,
    MissingCredential,
    StaleCapability,
    UnavailableCandidate,
    SessionAuthorizationFailed,
    InvalidCentralPolicy,
}

impl HardGateFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DestinationDenied => "destination_denied",
            Self::CapExhausted => "cap_exhausted",
            Self::ProviderConcurrencyExhausted => "provider_concurrency_exhausted",
            Self::MediaReservationDenied => "media_reservation_denied",
            Self::MissingCredential => "missing_credential",
            Self::StaleCapability => "stale_capability",
            Self::UnavailableCandidate => "unavailable_candidate",
            Self::SessionAuthorizationFailed => "session_authorization_failed",
            Self::InvalidCentralPolicy => "invalid_central_policy",
        }
    }
}

/// Evaluate egress authority given the approval mode and grant state. This is
/// the hard-gate chokepoint that applies identically to trusted and untrusted
/// destinations — trust classification never changes this requirement.
pub fn evaluate_egress_authority(
    mode: ApprovalMode,
    grant_outcome: &GrantAuthorizationOutcome,
    session_authorized: bool,
    invocation_id: &str,
) -> EgressDecision {
    match mode {
        ApprovalMode::Ask => match grant_outcome {
            GrantAuthorizationOutcome::Authorized { grant_id, scope } => {
                if *scope == GrantScope::Project && !session_authorized {
                    return EgressDecision::HardGateFailed {
                        reason: HardGateFailureReason::SessionAuthorizationFailed,
                    };
                }
                EgressDecision::AskGranted {
                    scope: *scope,
                    grant_id: grant_id.clone(),
                }
            }
            GrantAuthorizationOutcome::Revoked => EgressDecision::HardGateFailed {
                reason: HardGateFailureReason::DestinationDenied,
            },
            GrantAuthorizationOutcome::Consumed => EgressDecision::HardGateFailed {
                reason: HardGateFailureReason::DestinationDenied,
            },
            GrantAuthorizationOutcome::NotFound => EgressDecision::AskDenied,
            GrantAuthorizationOutcome::SessionAuthorizationFailed => {
                EgressDecision::HardGateFailed {
                    reason: HardGateFailureReason::SessionAuthorizationFailed,
                }
            }
        },
        ApprovalMode::Yolo => {
            // Yolo opens no human prompt. Hard gates still apply identically.
            match grant_outcome {
                GrantAuthorizationOutcome::Authorized { scope, .. } => {
                    if *scope == GrantScope::Project && !session_authorized {
                        return EgressDecision::HardGateFailed {
                            reason: HardGateFailureReason::SessionAuthorizationFailed,
                        };
                    }
                    // Yolo may use the current invocation under audited
                    // agent_discretion. It does not silently create a
                    // standing grant.
                    EgressDecision::YoloAgentDiscretion {
                        invocation_id: invocation_id.to_string(),
                    }
                }
                GrantAuthorizationOutcome::Revoked => EgressDecision::HardGateFailed {
                    reason: HardGateFailureReason::DestinationDenied,
                },
                GrantAuthorizationOutcome::Consumed => EgressDecision::HardGateFailed {
                    reason: HardGateFailureReason::DestinationDenied,
                },
                GrantAuthorizationOutcome::NotFound => {
                    // No prior grant. In Yolo, first-use still requires a
                    // hard-gate pass but no human prompt. The caller must
                    // have pre-authorized (e.g. via a once/session/project
                    // grant recorded earlier in Ask mode). If none exists,
                    // this is a hard gate failure, not a silent grant.
                    EgressDecision::HardGateFailed {
                        reason: HardGateFailureReason::DestinationDenied,
                    }
                }
                GrantAuthorizationOutcome::SessionAuthorizationFailed => {
                    EgressDecision::HardGateFailed {
                        reason: HardGateFailureReason::SessionAuthorizationFailed,
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Captured provider request
// ---------------------------------------------------------------------------

/// A captured provider request for verification. Contains exactly one
/// authorized image plus either the fixed versioned dossier instruction or
/// one question at both exact bounds, and no transcript/system/memory/
/// unrelated/computer content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedProviderRequest {
    pub purpose: Purpose,
    pub instruction_version: u8,
    pub body: String,
    pub image_count: usize,
    /// The only context fields permitted. Everything else is excluded.
    pub permitted_context: PermittedContext,
}

/// The only context fields a sidecar provider request may carry. It never
/// receives transcript, system/developer messages, memories, other
/// attachments, computer history, or hidden context.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermittedContext {
    /// Exactly one authorized image.
    pub image_artifact_id: Option<String>,
}

impl CapturedProviderRequest {
    /// Verify that the captured request contains exactly one authorized image
    /// and either the fixed versioned dossier instruction or one question at
    /// both exact bounds, and no transcript/system/memory/unrelated/computer
    /// content.
    pub fn verify(&self) -> Result<(), CapturedRequestViolation> {
        if self.image_count != 1 {
            return Err(CapturedRequestViolation::ImageCount {
                actual: self.image_count,
                expected: 1,
            });
        }
        if self.permitted_context.image_artifact_id.is_none() {
            return Err(CapturedRequestViolation::MissingImageArtifact);
        }
        match self.purpose {
            Purpose::Dossier => {
                if self.body != DOSSIER_FIXED_INSTRUCTION {
                    return Err(CapturedRequestViolation::DossierInstructionMismatch);
                }
                if self.instruction_version != DOSSIER_INSTRUCTION_VERSION {
                    return Err(CapturedRequestViolation::InstructionVersion {
                        actual: self.instruction_version,
                        expected: DOSSIER_INSTRUCTION_VERSION,
                    });
                }
            }
            Purpose::AskImage => {
                if self.instruction_version != ASK_IMAGE_INSTRUCTION_VERSION {
                    return Err(CapturedRequestViolation::InstructionVersion {
                        actual: self.instruction_version,
                        expected: ASK_IMAGE_INSTRUCTION_VERSION,
                    });
                }
                if self.body.trim().is_empty() {
                    return Err(CapturedRequestViolation::EmptyQuestion);
                }
                let scalars = self.body.chars().count();
                if scalars > ASK_IMAGE_MAX_UNICODE_SCALARS {
                    return Err(CapturedRequestViolation::ScalarBound {
                        actual: scalars,
                        max: ASK_IMAGE_MAX_UNICODE_SCALARS,
                    });
                }
                let bytes = self.body.len();
                if bytes > ASK_IMAGE_MAX_UTF8_BYTES {
                    return Err(CapturedRequestViolation::ByteBound {
                        actual: bytes,
                        max: ASK_IMAGE_MAX_UTF8_BYTES,
                    });
                }
            }
        }
        Ok(())
    }
}

/// Violations of the captured-provider-request contract.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapturedRequestViolation {
    #[error("image count is {actual}, expected {expected}")]
    ImageCount { actual: usize, expected: usize },
    #[error("missing image artifact id")]
    MissingImageArtifact,
    #[error("dossier instruction does not match the fixed versioned instruction")]
    DossierInstructionMismatch,
    #[error("instruction version is {actual}, expected {expected}")]
    InstructionVersion { actual: u8, expected: u8 },
    #[error("ask_image question is empty after trimming")]
    EmptyQuestion,
    #[error("ask_image question has {actual} Unicode scalar values, max {max}")]
    ScalarBound { actual: usize, max: usize },
    #[error("ask_image question has {actual} UTF-8 bytes, max {max}")]
    ByteBound { actual: usize, max: usize },
}

// ---------------------------------------------------------------------------
// Concurrency / reservation
// ---------------------------------------------------------------------------

/// The outcome of atomically acquiring session cap, provider concurrency,
/// and media reservation before journaled handoff. All-or-none: either all
/// reservations commit or none.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservationAcquisition {
    /// All reservations committed.
    Committed {
        invocation_id: String,
        sidecar_invocation_charged: bool,
        media_reservation_id: String,
        provider_concurrency_slot: String,
    },
    /// At least one reservation failed; none committed.
    RolledBack { reason: ReservationFailureReason },
}

/// Distinct safe reasons for reservation failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReservationFailureReason {
    CapExhausted,
    ProviderConcurrencyExhausted,
    MediaReservationDenied,
    StaleCapability,
    MissingCredential,
    DestinationDenied,
}

impl ReservationFailureReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CapExhausted => "cap_exhausted",
            Self::ProviderConcurrencyExhausted => "provider_concurrency_exhausted",
            Self::MediaReservationDenied => "media_reservation_denied",
            Self::StaleCapability => "stale_capability",
            Self::MissingCredential => "missing_credential",
            Self::DestinationDenied => "destination_denied",
        }
    }
}

/// A terminalization failure: the reservation could not be settled/released.
/// The caller MUST fail closed rather than report success over a leaked row.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("reservation settlement failed: {message}")]
pub struct ReservationSettleError {
    pub message: String,
}

impl ReservationSettleError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// An injected reservation acquirer. Implementations own the atomic
/// all-or-none acquisition logic.
///
/// The lifecycle in this tree is deliberately simple: [`acquire`](Self::acquire)
/// reserves, and [`settle`](Self::settle) terminally releases the reservation on
/// the terminal outcome (success OR failure) so no queued row ever leaks.
/// `settle` returns a `Result` so the caller can fail closed on a
/// terminalization failure rather than silently leaking a reserved row.
///
/// The methods are `async` because the production implementation
/// ([`crate::image_sidecar::pipeline::LedgerReservationAcquirer`]) is backed by
/// the async, `Db`-transaction-threaded media-reservation ledger. Breaking this
/// pure-module API to force the real ledger is preferred (pre-release) over
/// leaving a sync footgun that cannot call the real ledger.
///
/// The real `AtHandoff` per-session charge, provider-concurrency enforcement,
/// and ambiguous-handoff (keep-charge) accounting are deferred to the
/// real-`SidecarProviderTransport` follow-up (see the `TODO` on
/// [`LedgerReservationAcquirer::settle`]); the stubbed transport performs no
/// real external egress, so there is nothing to charge or keep in this tree.
#[async_trait]
pub trait ReservationAcquirer: Send + Sync {
    async fn acquire(&self, request: ReservationRequest) -> ReservationAcquisition;
    /// Terminally settle (release) the reservation identified by
    /// `reservation_id` so no queued row leaks. Returns `Err` if terminalization
    /// failed.
    async fn settle(&self, reservation_id: &str) -> Result<(), ReservationSettleError>;
}

/// Request for atomic reservation acquisition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservationRequest {
    pub invocation_id: String,
    pub session_id: String,
    pub sidecar_invocation_cap: SidecarInvocationCap,
    pub current_session_usage: u64,
    pub provider_concurrency_max: u64,
    pub current_provider_concurrency: u64,
}

/// A fake reservation acquirer for tests. All-or-none, no overcommit,
/// exactly-once settle.
///
/// This is `#[cfg(test)]`: production composition never constructs it. The
/// production acquirer is
/// [`crate::image_sidecar::pipeline::LedgerReservationAcquirer`].
#[cfg(test)]
pub struct FakeReservationAcquirer {
    state: Mutex<FakeReservationState>,
    provider_concurrency_max: u64,
}

#[cfg(test)]
use std::collections::{BTreeMap, BTreeSet};

#[cfg(test)]
#[derive(Debug, Default)]
struct FakeReservationState {
    acquired: BTreeMap<String, FakeReservation>,
    settled: BTreeSet<String>,
    session_usage: u64,
    provider_concurrency: u64,
}

#[cfg(test)]
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct FakeReservation {
    invocation_id: String,
    sidecar_invocation_charged: bool,
    media_reservation_id: String,
    provider_concurrency_slot: String,
}

#[cfg(test)]
impl FakeReservationAcquirer {
    pub fn new(provider_concurrency_max: u64) -> Self {
        Self {
            state: Mutex::new(FakeReservationState::default()),
            provider_concurrency_max,
        }
    }

    pub fn acquired_count(&self) -> usize {
        self.state.lock().unwrap().acquired.len()
    }

    pub fn settled_count(&self) -> usize {
        self.state.lock().unwrap().settled.len()
    }

    pub fn is_acquired(&self, invocation_id: &str) -> bool {
        self.state
            .lock()
            .unwrap()
            .acquired
            .contains_key(invocation_id)
    }
}

#[cfg(test)]
#[async_trait]
impl ReservationAcquirer for FakeReservationAcquirer {
    async fn acquire(&self, request: ReservationRequest) -> ReservationAcquisition {
        let mut state = self.state.lock().unwrap();
        // All-or-none: check every reservation before committing any.
        if request.current_session_usage >= request.sidecar_invocation_cap.value {
            return ReservationAcquisition::RolledBack {
                reason: ReservationFailureReason::CapExhausted,
            };
        }
        if state.provider_concurrency >= self.provider_concurrency_max {
            return ReservationAcquisition::RolledBack {
                reason: ReservationFailureReason::ProviderConcurrencyExhausted,
            };
        }
        // Commit all.
        state.session_usage += 1;
        state.provider_concurrency += 1;
        let media_reservation_id = format!("media-{}", request.invocation_id);
        let provider_concurrency_slot = format!("slot-{}", request.invocation_id);
        let reservation = FakeReservation {
            invocation_id: request.invocation_id.clone(),
            sidecar_invocation_charged: true,
            media_reservation_id: media_reservation_id.clone(),
            provider_concurrency_slot: provider_concurrency_slot.clone(),
        };
        state
            .acquired
            .insert(request.invocation_id.clone(), reservation);
        ReservationAcquisition::Committed {
            invocation_id: request.invocation_id,
            sidecar_invocation_charged: true,
            media_reservation_id,
            provider_concurrency_slot,
        }
    }

    async fn settle(&self, reservation_id: &str) -> Result<(), ReservationSettleError> {
        let mut state = self.state.lock().unwrap();
        if let Some(reservation) = state.acquired.remove(reservation_id) {
            // Exactly-once terminal settlement releases the reservation.
            if state.settled.insert(reservation_id.to_string()) {
                state.session_usage = state.session_usage.saturating_sub(1);
                state.provider_concurrency = state.provider_concurrency.saturating_sub(1);
                let _ = reservation;
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Computer-use eligibility
// ---------------------------------------------------------------------------

/// Sidecar availability never changes computer-use eligibility. This function
/// is the explicit guard: it returns the primary's computer-use eligibility
/// unchanged regardless of sidecar availability.
pub fn computer_use_eligibility_unchanged(
    primary_computer_use_capable: bool,
    sidecar_available: bool,
) -> bool {
    // Sidecar availability is intentionally ignored.
    let _ = sidecar_available;
    primary_computer_use_capable
}

pub mod dossier;
pub mod pipeline;

#[cfg(test)]
mod tests;
