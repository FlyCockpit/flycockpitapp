//! Session-scoped transcription media-egress verdict projections.

use serde::{Deserialize, Serialize};

/// One live session-scoped media-egress verdict row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaEgressVerdictV1 {
    pub grant_id: String,
    pub purpose: String,
    pub request_digest: String,
    pub verdict: String,
    pub granted_at_unix_ms: u64,
}
