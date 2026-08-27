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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarAuthoritySnapshotV1 {
    pub schema_version: u8,
    pub project_id: String,
    pub config_generation: u64,
    pub selection_id: String,
    pub entity_version: u64,
    pub pipeline_available: bool,
    pub health_reason: String,
    pub grants: Vec<ImageSidecarGrantV1>,
    pub invocations: Vec<ImageSidecarInvocationV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageSidecarGrantMutationV1 {
    pub schema_version: u8,
    pub config_generation: u64,
    pub selection_id: String,
    pub entity_version: u64,
    pub grant: ImageSidecarGrantV1,
}
