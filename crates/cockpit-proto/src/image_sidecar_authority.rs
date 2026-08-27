//! Exact-v1 local RPC projections for daemon-owned image-sidecar authority.
//!
//! These types deliberately expose safe identifiers and timestamps only. The
//! pipeline has no production dispatch adapter yet, so an empty invocation
//! list means no handoff record exists; it never means a local UI simulation.

use serde::{Deserialize, Serialize};

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

/// A daemon-derived, safe explanation of the current selection. A candidate
/// is issued only when the live handoff can honor it; callers never submit a
/// destination URL back to the daemon.
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
