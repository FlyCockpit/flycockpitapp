//! Renderer-independent agent-authoring projection and apply contracts.
//!
//! These DTOs are redacted: they never carry credentials, raw provider profile
//! handles, secret content, or filesystem paths. Trust classification is
//! always the revision-pinned global policy snapshot, never a copy stored on
//! an agent definition.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const AGENT_AUTHORING_DTO_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthoringCatalogOrigin {
    Bundled,
    Cached,
    Live,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthoringSourceKind {
    BundledFrontier,
    FirstPartyCatalog,
    ThirdParty,
    Authored,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPolicyTrustClassification {
    Trusted,
    Untrusted,
    Unset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredAgentReceiptStatus {
    Pending,
    Committed,
    Rejected,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthoredAgentRejectReason {
    EmptyGrants,
    DuplicateRoutes,
    AbsentDefault,
    NonEnabledDefault,
    UnsupportedCapability,
    OmittedModelTrustConfirmation,
    IllegalToolTier,
    InvalidNestedGraph,
    UnpinnedThirdPartySource,
    MissingThirdPartyTrustConfirmation,
    UnapprovedRemoteSidecarEgress,
    PerAgentTrustOverride,
    InvalidFrontmatter,
    IncompletePackage,
    StaleDraft,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicyRoute {
    pub provider_id: String,
    pub model_id: String,
    pub trust: AgentPolicyTrustClassification,
    pub confirmation_required: bool,
    /// Custody is always the global provider/model policy. Review must disclose
    /// that two agents sharing a route share this classification.
    pub trust_is_shared: bool,
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub auto_prune: bool,
    pub sidecar_eligible: bool,
    pub remote_sidecar_egress_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPolicySnapshot {
    /// Opaque digest of the global provider/model policy used for this
    /// projection. Apply requires this exact revision.
    pub policy_revision: String,
    pub routes: Vec<AgentPolicyRoute>,
    pub catalog_origin: AgentAuthoringCatalogOrigin,
    pub catalog_revision: String,
    pub bundled_frontier_slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthoringCompatibleRoute {
    pub provider_id: String,
    pub model_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthoringSource {
    pub kind: AgentAuthoringSourceKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
    pub display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_locator: Option<String>,
    pub compatible_routes: Vec<AgentAuthoringCompatibleRoute>,
    /// Canonical launch-v1 frontmatter YAML, redacted of secrets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub definition_frontmatter_yaml: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthoringProjection {
    pub dto_version: u32,
    pub policy: AgentPolicySnapshot,
    pub sources: Vec<AgentAuthoringSource>,
    /// Stable disclosure that trust is shared global policy, not per-agent.
    pub review_trust_disclosure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentSource {
    pub kind: AgentAuthoringSourceKind,
    pub source_locator: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pin: Option<String>,
    #[serde(default)]
    pub third_party_trust_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentChild {
    /// POSIX relative path under the package root, e.g. `subagents/helper.md`.
    pub relative_path: String,
    /// Canonical child markdown (frontmatter + body). No secrets.
    pub markdown: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredSidecarDeclaration {
    pub provider_id: String,
    pub model_id: String,
    pub remote_image_egress_confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelTrustConfirmation {
    pub provider_id: String,
    pub model_id: String,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentPackageDraft {
    pub dto_version: u32,
    pub name: String,
    /// Canonical parent markdown (frontmatter + body). No secrets.
    pub markdown: String,
    pub source: AuthoredAgentSource,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<AuthoredAgentChild>,
    /// Exact `mcp.json` bytes as UTF-8 text. Absent when the package has none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_json: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<AuthoredSidecarDeclaration>,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub model_trust_confirmations: Vec<ModelTrustConfirmation>,
    pub make_default: bool,
    /// Last authoritative package digest for edit/delete/retry of this name.
    /// Absent on the first submit. A failed child does not advance it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub draft_revision: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentOnboardingCorrelation {
    pub run_id: Uuid,
    pub attempt_id: Uuid,
    pub stage_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyAuthoredAgentPackageRequest {
    pub client_operation_id: String,
    pub expected_policy_revision: String,
    pub package: AuthoredAgentPackageDraft,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onboarding: Option<AuthoredAgentOnboardingCorrelation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentReviewGrant {
    pub provider_id: String,
    pub model_id: String,
    pub is_default: bool,
    pub trust: AgentPolicyTrustClassification,
    pub trust_is_shared: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentReview {
    pub agent_name: String,
    pub grants: Vec<AuthoredAgentReviewGrant>,
    pub tool_tier_preferences: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verification_label: Option<String>,
    pub interactive_subagents: bool,
    pub goal_skeptics_label: String,
    pub children: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sidecars: Vec<String>,
    pub source: String,
    pub trust_is_shared: bool,
    pub trust_disclosure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyAuthoredAgentPackageReceipt {
    pub client_operation_id: String,
    pub receipt_id: Uuid,
    pub status: AuthoredAgentReceiptStatus,
    pub package_digest: String,
    pub policy_revision: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
    pub default_selected: bool,
    pub review: AuthoredAgentReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ApplyAuthoredAgentPackageOutcome {
    Receipt(ApplyAuthoredAgentPackageReceipt),
    PolicyRevisionConflict {
        projection: AgentAuthoringProjection,
    },
    Rejected {
        reason: AuthoredAgentRejectReason,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        projection: Option<AgentAuthoringProjection>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthoredAgentPackageReceiptQuery {
    pub client_operation_id: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn draft_and_receipt_never_name_secret_fields() {
        let encoded = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/agent_authoring.rs"
        ));
        for needle in [
            "api_key",
            "apiKey",
            "password",
            "passphrase",
            "credential",
            "profile_handle",
            "profileHandle",
        ] {
            assert!(
                !encoded.contains(&format!("pub {needle}")),
                "authoring DTO must not declare a secret field named {needle}"
            );
        }
    }
}
