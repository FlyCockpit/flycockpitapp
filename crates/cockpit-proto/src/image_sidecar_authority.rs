//! Exact-v1 local RPC projections for daemon-owned image-sidecar authority.
//!
//! These types deliberately expose safe identifiers and timestamps only. The
//! pipeline has no production dispatch adapter yet, so an empty invocation
//! list means no handoff record exists; it never means a local UI simulation.

use serde::{Deserialize, Serialize};

/// The effective approval posture for a sidecar invocation. This deliberately
/// projects the session's broader approval mode into the two sidecar-relevant
/// choices, rather than asking a settings client to infer it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSidecarApprovalModeV1 {
    Ask,
    Yolo,
}

/// Provenance of the effective central sidecar-invocation cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSidecarInvocationCapSourceV1 {
    CompiledCeiling,
    Configured,
    Profile,
    Adapter,
    Request,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageSidecarGrantScopeV1 {
    Once,
    Session,
    Project,
}

impl ImageSidecarGrantScopeV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Session => "session",
            Self::Project => "project",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarGrantV1 {
    pub grant_id: String,
    pub version: u64,
    pub project_id: String,
    pub destination: String,
    pub purpose: String,
    pub scope: ImageSidecarGrantScopeV1,
    pub session_id: Option<String>,
    pub invocation_id: Option<String>,
    pub created_at_unix_ms: i64,
    pub last_used_at_unix_ms: Option<i64>,
    pub revoked_at_unix_ms: Option<i64>,
    pub consumed_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarInvocationV1 {
    pub invocation_id: String,
    pub state: String,
    pub created_at_unix_ms: i64,
}

/// A configured model the daemon has freshly classified for sidecar selection.
/// This is deliberately a projection, not provider catalog discovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarModelOptionV1 {
    pub provider: String,
    pub model: String,
    /// This entry was explicitly configured by the user, rather than merely
    /// discovered in a provider catalog.
    pub configured: bool,
    pub image_capable: bool,
    pub fresh: bool,
}

/// Safe identity of the attached session's current primary. Missing means the
/// daemon had no primary to resolve against and did not invent a trust class.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarPrimaryV1 {
    pub provider: String,
    pub model: String,
    pub trust: String,
    pub location: String,
    pub credential_fingerprint: String,
}

/// A daemon-derived, safe explanation of the current selection. This is a
/// projection of [`SidecarResolver`] output, not a client-side match. A
/// candidate is issued only when the live handoff can honor it; callers never
/// submit a destination URL back to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarResolutionV1 {
    pub provider: Option<String>,
    pub model: Option<String>,
    pub origin: Option<String>,
    pub available: bool,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_candidate_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary: Option<ImageSidecarPrimaryV1>,
    pub matched_source: String,
    pub capability_source: String,
    pub capability_freshness: String,
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback_outcome: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarAuthoritySnapshotV1 {
    pub schema_version: u8,
    /// Stable for one daemon boot. A TUI must discard a completion from a
    /// different daemon, even when its client-generated selection id matches.
    pub daemon_instance_id: String,
    /// The attached local session that owned this projection.
    pub session_id: String,
    pub project_id: String,
    pub config_generation: u64,
    pub selection_id: String,
    pub entity_version: u64,
    /// Effective session mode, projected by the daemon. `yolo` means no
    /// prompt and no standing-grant creation UI.
    pub approval_mode: ImageSidecarApprovalModeV1,
    /// The effective central policy value. Sidecar settings never invent a
    /// local fallback for this limit.
    pub central_invocation_cap: u64,
    pub central_invocation_cap_source: ImageSidecarInvocationCapSourceV1,
    pub central_invocation_cap_hard_ceiling: u64,
    pub pipeline_available: bool,
    pub health_reason: String,
    pub models: Vec<ImageSidecarModelOptionV1>,
    pub resolution: ImageSidecarResolutionV1,
    pub grants: Vec<ImageSidecarGrantV1>,
    pub invocations: Vec<ImageSidecarInvocationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarGrantMutationV1 {
    pub schema_version: u8,
    pub daemon_instance_id: String,
    pub session_id: String,
    pub config_generation: u64,
    pub selection_id: String,
    pub entity_version: u64,
    pub grant: ImageSidecarGrantV1,
}
