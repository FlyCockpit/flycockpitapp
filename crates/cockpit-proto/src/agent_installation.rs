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
    /// id for bind, or the declarative `authored/NAME` identity for daemon-owned
    /// create. The daemon alone validates/derives Create filename/path; this value
    /// is never returned in a response or persisted outside its fingerprint.
    pub source_locator: String,
    /// Update-only durable target. The daemon verifies that this exact
    /// installation belongs to the requested scope/workspace and has the
    /// same canonical source identity before replacing it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_installation_id: Option<String>,
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
pub struct AgentInstallationReadV1 {
    pub dto_version: u32,
    pub scope: AgentInstallationScopeWire,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub installation_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallationRecordV1 {
    pub installation_id: String,
    pub scope: AgentInstallationScopeWire,
    pub source_agent_id: String,
    pub source_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
    pub source_digest: String,
    pub installation_revision: u64,
    /// Redacted daemon-derived current slot state. Profile handles and
    /// credentials are intentionally never represented here.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bindings: Vec<AgentInstallationSlotStatusV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentInstallationSlotBindingStateV1 {
    Bound,
    PrimaryUnusable,
    OptionalUnbound,
    RebindRequired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentInstallationSlotStatusV1 {
    pub slot_id: String,
    pub state: AgentInstallationSlotBindingStateV1,
    pub model_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
pub struct AgentInstallationUnmatchedRecommendationV1 {
    pub recommendation_id: String,
    pub canonical_upstream_identity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rationale: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
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

    #[test]
    fn agent_installation_dtos_are_forward_open_but_keep_required_type_checks() {
        let begin = serde_json::json!({
            "dto_version": 1,
            "idempotency_key": "key",
            "operation": "create",
            "scope": "global",
            "source_locator": "authored/reviewer",
            "future_field": true,
        });
        assert!(serde_json::from_value::<AgentInstallationBeginV1>(begin).is_ok());
        assert!(
            serde_json::from_value::<AgentInstallationBeginV1>(serde_json::json!({
                "dto_version": 1,
                "idempotency_key": "key",
                "operation": "create",
                "scope": "global",
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<AgentInstallationBeginV1>(serde_json::json!({
                "dto_version": "one",
                "idempotency_key": "key",
                "operation": "create",
                "scope": "global",
                "source_locator": "authored/reviewer",
            }))
            .is_err()
        );

        assert!(
            serde_json::from_value::<AgentInstallationSubmitChoiceV1>(serde_json::json!({
                "dto_version": 1,
                "continuation_token": "token",
                "future_field": true,
            }))
            .is_ok()
        );
        assert!(
            serde_json::from_value::<AgentInstallationReadV1>(serde_json::json!({
                "dto_version": 1,
                "scope": "global",
                "future_field": true,
            }))
            .is_ok()
        );

        let result = serde_json::json!({
            "outcome": "needs_choice",
            "continuation_token": "token",
            "expires_at_unix_ms": 1,
            "choices": [{
                "choice_id": "choice",
                "slot_id": "primary",
                "offering_id": "offering",
                "provider_id": "provider",
                "model_id": "model",
                "author_suggested": true,
                "exact_alias_match": true,
                "future_choice_field": true,
            }],
            "unmatched_recommendations": [{
                "recommendation_id": "recommendation",
                "canonical_upstream_identity": "upstream/model",
                "future_recommendation_field": true,
            }],
            "future_result_field": true,
        });
        assert!(serde_json::from_value::<AgentInstallationResultV1>(result).is_ok());

        let listed = serde_json::json!({
            "outcome": "listed",
            "installations": [{
                "installation_id": "installation",
                "scope": "global",
                "source_agent_id": "authored/reviewer",
                "source_identity": "authored/reviewer",
                "source_digest": "digest",
                "installation_revision": 1,
                "bindings": [{
                    "slot_id": "primary",
                    "state": "bound",
                    "model_id": "model",
                    "future_binding_field": true,
                }],
                "future_record_field": true,
            }],
        });
        assert!(serde_json::from_value::<AgentInstallationResultV1>(listed).is_ok());
        assert!(
            serde_json::from_value::<AgentInstallationErrorV1>(serde_json::json!({
                "code": "invalid_request",
                "message": "invalid request",
                "future_error_field": true,
            }))
            .is_ok()
        );
    }
}
