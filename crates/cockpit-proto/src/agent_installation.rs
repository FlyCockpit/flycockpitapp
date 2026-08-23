//! Versioned, credential-free agent-installation daemon DTOs.
//!
//! These types deliberately contain daemon-resolved workspace identifiers and
//! display metadata only.  A client may submit a workspace path to the daemon,
//! but a response never echoes it; source credentials and filesystem paths are
//! outside this contract.

use serde::{Deserialize, Serialize};

pub const AGENT_INSTALLATION_DTO_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallationOperationKind {
    Install,
    Update,
    Bind,
    Create,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallationScopeWire {
    Global,
    WorkspacePrivate,
    WorkspaceShared,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentInstallationExecutionKindV1 {
    Assistant,
    Coding,
    Computer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationBeginV1 {
    pub dto_version: u32,
    pub idempotency_key: String,
    pub operation: AgentInstallationOperationKind,
    pub scope: AgentInstallationScopeWire,
    /// Request-only path. The daemon canonicalizes/authorizes it; the value is
    /// never placed in a response, journal, or terminal receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
    /// Canonical `OWNER/REPO[@REV]:PATH` for install/update, an installation
    /// id for bind, or the client-provided requested filename for daemon-owned
    /// create. The daemon alone validates/derives Create identity; this value
    /// is never returned in a response or persisted outside its fingerprint.
    pub source_locator: String,
    #[serde(default)]
    pub replace_acknowledged: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_slot: Option<String>,
    /// Create-only explicit template choices. They are declarative AgentDef
    /// fields, never provider/profile or credential routes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_kind: Option<AgentInstallationExecutionKindV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_slot_id: Option<String>,
    /// Non-interactive callers may ask the daemon to select only the first
    /// exact, author-suggested compatible route. The daemon never falls back
    /// to a merely compatible or unsuggested offering.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub auto_select_first_exact: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationSubmitChoiceV1 {
    pub dto_version: u32,
    pub continuation_token: String,
    /// Present for an explicit daemon-issued choice.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice_id: Option<String>,
    /// Finish the continuation without a binding. The daemon chooses the
    /// terminal optional-unbound/primary-unusable receipt from the durable
    /// choice set, rather than trusting a client-provided status.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub defer: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationReadV1 {
    pub dto_version: u32,
    pub scope: AgentInstallationScopeWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationRecordV1 {
    pub installation_id: String,
    pub scope: AgentInstallationScopeWire,
    pub source_agent_id: String,
    pub source_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub source_digest: String,
    pub installation_revision: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationChoiceV1 {
    pub choice_id: String,
    pub slot_id: String,
    pub offering_id: String,
    pub provider_id: String,
    pub model_id: String,
    /// Preserves the author's stable recommendation identity.  It is absent
    /// for a locally configured, compatible offering that was not suggested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_id: Option<String>,
    /// Advisory upstream identity for display only. It never becomes a
    /// provider alias or route.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_upstream_identity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
    pub author_suggested: bool,
    pub exact_alias_match: bool,
}

/// A portable author recommendation for which the local daemon has no exact
/// hard-compatible alias.  It remains visible to a client but is never a
/// selectable provider route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationUnmatchedRecommendationV1 {
    pub recommendation_id: String,
    pub canonical_upstream_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case", deny_unknown_fields)]
pub enum AgentInstallationResultV1 {
    NeedsChoice {
        continuation_token: String,
        choices: Vec<AgentInstallationChoiceV1>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        unmatched_recommendations: Vec<AgentInstallationUnmatchedRecommendationV1>,
        expires_at_unix_ms: i64,
    },
    Receipt {
        operation_id: String,
        status: AgentInstallationReceiptStatusV1,
        installation_id: Option<String>,
        source_revision: Option<String>,
        /// Present only when an Install/Update `--yes` composite operation
        /// also drove a daemon-owned binding continuation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        binding_outcome: Option<AgentInstallationBindingOutcomeV1>,
    },
    Listed {
        installations: Vec<AgentInstallationRecordV1>,
    },
    Inspected {
        installation: Option<AgentInstallationRecordV1>,
    },
    Error {
        error: AgentInstallationErrorV1,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallationReceiptStatusV1 {
    Installed,
    Updated,
    Bound,
    Created,
    OptionalUnbound,
    PrimaryUnusable,
    TimedOut,
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallationBindingOutcomeV1 {
    Bound,
    OptionalUnbound,
    PrimaryUnusable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentInstallationErrorV1 {
    pub code: AgentInstallationErrorCodeV1,
    /// Fixed redacted explanation; it must never include a credential, local
    /// filesystem path, request URL, or provider-profile handle.
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallationErrorCodeV1 {
    InvalidRequest,
    UnauthorizedWorkspace,
    SourceRefused,
    PrivateSourceUnauthorized,
    FetchFailed,
    InvalidDefinition,
    Collision,
    DirtySharedFile,
    StaleBinding,
    ContinuationExpired,
    IdempotencyConflict,
    UnknownChoice,
    IncompatibleModel,
    Internal,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_installation_daemon_wire_dtos_are_redacted_and_versioned() {
        let result = AgentInstallationResultV1::NeedsChoice {
            continuation_token: "continuation".into(),
            choices: vec![AgentInstallationChoiceV1 {
                choice_id: "choice".into(),
                slot_id: "primary".into(),
                offering_id: "local-offering".into(),
                provider_id: "openai".into(),
                model_id: "gpt".into(),
                recommendation_id: Some("author-choice".into()),
                canonical_upstream_identity: Some("upstream/model".into()),
                author_label: Some("Recommended".into()),
                rationale: None,
                author_suggested: true,
                exact_alias_match: true,
            }],
            unmatched_recommendations: vec![],
            expires_at_unix_ms: 10,
        };
        let json = serde_json::to_string(&result).unwrap();
        assert!(!json.contains("workspace_path"));
        assert!(!json.contains("credential"));
        assert!(serde_json::from_str::<AgentInstallationResultV1>(&json).is_ok());
        assert_eq!(AGENT_INSTALLATION_DTO_VERSION, 1);
    }
}
