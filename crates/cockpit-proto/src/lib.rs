//! Wire protocol — NDJSON envelopes carried over any byte stream.
//!
//! One envelope per newline-terminated frame. Same shape on the
//! in-process channel (today), the Unix socket (P3), and the future
//! WebSocket relay for `cockpit connect` (GOALS §8c, §8d).
//!
//! Layout:
//!
//! ```text
//! { "v": 10, "kind": "req"|"res"|"evt"|"err", ... }
//! ```
//!
//! - **`req`** — client → daemon. Carries a uuid `id` the daemon
//!   echoes on the matching `res` / `err`.
//! - **`res`** — daemon → client. Pairs with `req` by `id`.
//! - **`evt`** — daemon → client. Unsolicited stream event (assistant
//!   text deltas, tool starts/ends, interrupt-raised, …). No id; the
//!   client routes events by `session_id` payload.
//! - **`err`** — daemon → client. Used both as a paired response to a
//!   failed `req` (carries the matching `id`) and as an
//!   out-of-band notification (`id = null`).
//!
//! The schema version (`v`) sits on every envelope so a future bump
//! can be detected on a per-line basis without buffering. Clients
//! refuse envelopes whose `v` is outside the supported range.

pub mod acp;
pub mod agent_installation;
pub mod agent_management;
pub mod capability_ceiling;
pub mod config_management;
#[cfg(feature = "remote")]
pub mod es256;
pub use acp::{
    AcpForwardedMcpDeclarationV1, AcpForwardedMcpIngressV1, AcpForwardedMcpProvenanceV1,
    AcpForwardedMcpTransportV1, AcpNameValuePairV1, AcpSessionAdmissionMethodV1,
    ResolveCodeRootInterruptResultV1, ResolveCodeRootInterruptV1,
};
pub use agent_installation::{
    AGENT_INSTALLATION_DTO_VERSION, AgentInstallationBeginV1, AgentInstallationBindingOutcomeV1,
    AgentInstallationChoiceV1, AgentInstallationErrorCodeV1, AgentInstallationErrorV1,
    AgentInstallationExecutionKindV1, AgentInstallationOperationKind, AgentInstallationReadV1,
    AgentInstallationReceiptStatusV1, AgentInstallationRecordV1, AgentInstallationResultV1,
    AgentInstallationScopeWire, AgentInstallationSlotBindingStateV1, AgentInstallationSlotStatusV1,
    AgentInstallationSubmitChoiceV1, AgentInstallationUnmatchedRecommendationV1,
};
pub use agent_management::{
    AgentEditSnapshot, AgentEditTarget, AgentEditorCompletion, AgentEditorLease,
    AgentEditorSettlementStatus, AgentEntryKind, AgentInventoryEntry, AgentMutation,
    AgentMutationExpectations, AgentMutationOutcome, AgentMutationResult, AgentSourceLayer,
    GoalSupervisionPatch, MAX_AGENT_MARKDOWN_BYTES, MAX_AGENT_METADATA_BYTES, MAX_AGENT_NAME_BYTES,
    MAX_ASSISTANT_CONFIG_BYTES, MAX_ASSISTANT_DIAGNOSTIC_BYTES, MAX_ASSISTANT_HOME_BYTES,
    agent_edit_projection_material, agent_inventory_entry_projection_material,
    agent_mutation_intent_hash, agent_mutation_name, assistant_mutation_intent_hash,
    mcp_mutation_intent_hash, mcp_mutation_intent_hash_for_scope, validate_agent_edit_snapshot,
    validate_agent_editor_completion, validate_agent_mutation_envelope,
    validate_agent_source_identity, validate_goal_supervision_projection,
};
pub use config_management::{
    CockpitConfigLayer, CommittedDenylistEntry, ConfigCommitStatus, ConfigPublicationStatus,
    DesiredDenylistEntry, ExtendedConfigField, ExtendedConfigLayerSnapshot, ExtendedConfigPatch,
    ExtendedConfigPathMutation, OPAQUE_AUTHORITY_TOKEN_BYTES, REDACTED_DENYLIST_MASK,
    RedactedDenylistEntry, RedactedOccurrenceMutation, is_opaque_authority_token,
};
pub mod bulk_transfer;
pub mod host_capabilities;
pub mod image_control;
pub mod image_sidecar_authority;
pub use image_sidecar_authority::{
    ImageSidecarApprovalModeV1, ImageSidecarAuthoritySnapshotV1, ImageSidecarGrantMutationV1,
    ImageSidecarGrantScopeV1, ImageSidecarGrantV1, ImageSidecarInvocationCapSourceV1,
    ImageSidecarInvocationV1, ImageSidecarModelOptionV1, ImageSidecarPrimaryV1,
    ImageSidecarResolutionV1,
};
pub mod launch;
pub mod provider_management;
pub use host_capabilities::{
    CatalogDependencyImportance, CatalogDependencyRow, CatalogDependencyState,
    CatalogExecutionTarget, FeatureCapabilityRow, FeatureCapabilityState, HostCapabilitySnapshot,
    SecretStoreIntent, SecretStorePlacement, SecretStoreSnapshot,
};
pub use launch::{LaunchBundle, LaunchInfo, RepoStatus};
pub use provider_management::{
    ProviderLayerMetadataPatch, ProviderMutationBatch, ProviderMutationDelete,
    ProviderMutationUpsert, ProviderSecretValue,
};
pub mod session_setup;
pub use session_setup::{
    SESSION_SETUP_DTO_VERSION, SessionSetupAgentCandidateV1, SessionSetupLockedReasonV1,
    SessionSetupMcpV1, SessionSetupModelChoiceRouteV1, SessionSetupModelSlotV1,
    SessionSetupSnapshotV1, SessionSetupToolV1, SessionSetupUnavailableReasonV1,
};
pub mod session_override;
pub use session_override::{
    AGENT_EFFECTIVE_SETTINGS_DTO_VERSION, AgentControlLockedReasonV1, AgentEffectiveSettingsV1,
    AgentModelControlV1, AgentModelRefV1, AgentQuestionControlV1, AgentQuestionEffectiveV1,
    AgentQuestionOverrideV1, AgentSandboxControlV1, AgentSessionOverrideFieldV1,
    AgentSessionOverrideStatusV1, AgentVerificationControlV1, AgentVerificationReductionV1,
    AgentVerificationRegionV1, focused_model_binding_choice_id,
};
#[cfg(feature = "remote")]
pub mod remote_connection_metadata;
#[cfg(feature = "remote")]
pub mod remote_device_identity_enrollment;
#[cfg(feature = "remote")]
pub mod remote_enterprise_connection_policy;
#[cfg(feature = "remote")]
pub mod remote_identity_protocol;
#[cfg(feature = "remote")]
pub mod remote_ip_consent;
#[cfg(feature = "remote")]
pub mod remote_operation_fcor;
#[cfg(feature = "remote")]
pub mod remote_protocol_id;
#[cfg(feature = "remote")]
pub mod remote_public_service_policy;
#[cfg(feature = "remote")]
pub mod remote_session_continuity;
#[cfg(feature = "remote")]
pub mod remote_signaling_attempt_store;
#[cfg(feature = "remote")]
pub mod remote_tenant_authority_protocol;
#[cfg(feature = "remote")]
pub mod remote_transport;
#[cfg(feature = "remote")]
pub mod remote_transport_selection;
#[cfg(feature = "remote")]
pub mod remote_turn_ice_policy;
#[cfg(feature = "remote")]
pub mod remote_version;
#[cfg(feature = "remote")]
pub mod remote_wire_magic_registry;
pub mod send_user_message_v2;
pub mod terminal;
pub mod wire_scalar;

/// Payload ceiling for latency-sensitive local daemon RPC responses.
pub const MAX_INTERACTIVE_RPC_PAYLOAD_BYTES: usize = 512 * 1024;

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io;

use anyhow::{Context, Result, bail};
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio_util::codec::{Framed, FramedRead, FramedWrite, LinesCodec, LinesCodecError};
use uuid::Uuid;

/// Source-preserving image spend settings shared by daemon clients.
pub type ImageSpendPolicyView = cockpit_config::config::image_spend::ImageSpendSettings;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSpendPreflightView {
    pub policy: ImageSpendPolicyView,
    pub blocked: Option<cockpit_config::config::image_spend::BudgetBlockReason>,
    pub policy_version: Option<u64>,
    pub epoch_policy_version: Option<u64>,
    pub epoch_sequence: Option<u64>,
}

#[cfg(all(test, feature = "remote"))]
mod owner_credential_bounds_tests {
    use super::*;

    fn credential() -> StoredFlycockpitCredential {
        StoredFlycockpitCredential {
            server_url: "https://cockpit.example.test".into(),
            instance_id: "instance".into(),
            instance_token: "token".into(),
            account: AccountInfo {
                user_id: "user".into(),
                email: "user@example.test".into(),
            },
            display_name: None,
            relay_choice: None,
        }
    }

    #[test]
    fn owner_credential_bounds_cover_token_and_all_relay_strings() {
        let mut too_long_token = credential();
        too_long_token.instance_token = "x".repeat(MAX_OWNER_INSTANCE_TOKEN_BYTES + 1);
        assert!(too_long_token.validate().is_err());

        let too_long = "x".repeat(MAX_OWNER_RELAY_ID_BYTES + 1);
        assert!(
            RelayChoice {
                relay_id: too_long,
                region: Some("region".into()),
                ws_url: "wss://relay.example.test/ws".into(),
                rtt_ms: None,
                chosen_at: 1,
            }
            .validate()
            .is_err()
        );
        let too_long = "x".repeat(MAX_OWNER_RELAY_REGION_BYTES + 1);
        assert!(
            RelayChoice {
                relay_id: "relay".into(),
                region: Some(too_long),
                ws_url: "wss://relay.example.test/ws".into(),
                rtt_ms: None,
                chosen_at: 1,
            }
            .validate()
            .is_err()
        );
        let too_long = "x".repeat(MAX_OWNER_RELAY_URL_BYTES + 1);
        assert!(
            RelayChoice {
                relay_id: "relay".into(),
                region: Some("region".into()),
                ws_url: too_long,
                rtt_ms: None,
                chosen_at: 1,
            }
            .validate()
            .is_err()
        );

        let mut view = FlycockpitAccountView {
            server_url: "https://cockpit.example.test".into(),
            instance_id: "instance".into(),
            account: AccountInfo {
                user_id: "user".into(),
                email: "user@example.test".into(),
            },
            display_name: None,
            relay_choice: Some(RelayChoice {
                relay_id: String::new(),
                region: None,
                ws_url: "wss://relay.example.test/ws".into(),
                rtt_ms: None,
                chosen_at: 1,
            }),
            token_fingerprint: "fingerprint".into(),
        };
        assert!(view.validate().is_err());
        view.relay_choice = None;
        view.validate().expect("valid account view");
    }

    #[test]
    fn owner_view_url_redaction_removes_userinfo_query_and_fragment() {
        let raw = "wss://user:token@relay.example.test/ws?access_token=secret#fragment";
        let redacted = redact_url_for_owner_view(raw);
        assert_eq!(redacted, "wss://relay.example.test/ws");
        assert!(!redacted.contains("token"));
        assert_eq!(
            redact_url_for_owner_view("not a URL?token=secret"),
            "[redacted]"
        );
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvSnapshotSource {
    DaemonStart,
    TuiShell,
    TuiProcessFallback,
    ExplicitCli,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSnapshotMeta {
    pub source: EnvSnapshotSource,
    pub digest: String,
    pub key_count: usize,
    pub path_entry_count: usize,
}

/// Opaque, stable pagination position for daemon-owned agent-tree reads.
/// Timestamp plus UUID avoids drops when several lifecycle transitions share a
/// clock tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTreeCursor {
    pub created_at_unix_ms: i64,
    pub id: Uuid,
}

/// Public, resolver-context-free projection of one durable agent node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTreeNode {
    pub agent_instance_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_agent_instance_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    pub state: String,
    pub revision: i64,
    pub created_at_unix_ms: i64,
    pub updated_at_unix_ms: i64,
}

/// Typed attention projection. All contracts were allowlisted and redacted by
/// the daemon before persistence; no resolver prompt, credential, live tool
/// handle, or approval operation appears on this wire type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDecisionAttention {
    pub attention_id: Uuid,
    pub decision_request_id: Uuid,
    pub agent_instance_id: Uuid,
    pub state: String,
    pub decision_state: String,
    pub decision_class: String,
    /// Bounded opaque task lineage derived by the daemon from the owning
    /// agent, never from caller presentation metadata.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_call_id: Option<String>,
    /// Bounded opaque daemon-owned workspace reference for the owner.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_ref: Option<String>,
    pub options_contract_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_text_contract_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommendation_json: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_unix_ms: Option<i64>,
    pub revision: i64,
    pub raised_at_unix_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_unix_ms: Option<i64>,
}

/// A client answer is validated against the durable bounded/free-text
/// contract by the daemon and reduced to a redacted receipt before storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentDecisionAnswer {
    Option {
        option_id: String,
    },
    FreeText {
        text: String,
    },
    /// Exact wire continuation for a linked QuestionTool interrupt.  It has
    /// the same serde envelope as `ResolveResponse`, but lives in the
    /// protocol crate so clients never depend on the daemon storage crate.
    InterruptResponse {
        response: AgentInterruptResponse,
    },
}

/// A QuestionTool continuation supplied through `ResolveAgentDecision`.
/// Keeping this typed rather than accepting JSON means the session worker can
/// validate the durable redacted question contract before it releases the
/// parked continuation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", content = "data")]
pub enum AgentInterruptResponse {
    Single {
        selected_id: String,
    },
    Multi {
        selected_ids: Vec<String>,
    },
    Freetext {
        text: String,
    },
    Batch {
        responses: Vec<AgentInterruptResponse>,
    },
    Cancel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvSnapshotWire {
    pub source: EnvSnapshotSource,
    pub digest: String,
    pub vars: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigSnapshot {
    pub session_id: Uuid,
    pub generation: u64,
    pub extended: cockpit_config::config::extended::ExtendedConfig,
    pub providers: ProviderConfigView,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderConfigView {
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderEntryView>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub category_defaults: BTreeMap<String, cockpit_config::config::providers::ProviderModelRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_unlisted_models_fetch: Option<cockpit_config::config::providers::OnUnlistedModelsFetch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    /// Optional daemon-redacted MCP layer projection. The string is JSON so
    /// the MCP config crate remains a client/core implementation detail; it
    /// contains no header/env literals or credential values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_config_json: Option<String>,
    /// Daemon-redacted contents of the single authored MCP layer selected by
    /// `mcp_config_path`. This is deliberately separate from the effective
    /// projection above: clients may render inherited servers, but mutations
    /// are computed against and applied only to this document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_authored_config_json: Option<String>,
    /// Daemon-selected canonical MCP authority root and write target for this
    /// snapshot. These bind a later save receipt without making the frontend
    /// rediscover layered config paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_owner_root: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_config_path: Option<String>,
    /// Opaque, daemon-issued capability binding the MCP owner, target path,
    /// target-layer revision, and authenticated client that received this
    /// snapshot. A save must present it unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_edit_capability: Option<String>,
    /// SHA-256 revision of the authoritative target layer (not the merged
    /// effective projection in `mcp_config_json`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_revision: Option<String>,
    /// Revisions for explicit Add-MCP targets, minted with the same edit
    /// capability so a scoped write retains optimistic concurrency.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub mcp_scope_revisions: BTreeMap<String, String>,
    /// Optional daemon-redacted extended settings projection. JSON keeps the
    /// settings crate out of the wire/core protocol while ensuring clients do
    /// not load legacy config.json literals locally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_config_json: Option<String>,
}

/// A target-layer MCP edit. The daemon applies these operations to the raw
/// authored document under its config lock; it never persists a client's
/// flattened effective projection.
#[derive(Clone, Serialize, Deserialize)]
pub struct McpConfigPatch {
    pub operations: Vec<McpConfigPatchOperation>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum McpConfigPatchOperation {
    AddServer {
        name: String,
        /// A redacted/reference-bearing `ServerConfig` JSON object. Keeping
        /// the core type out of this crate preserves the protocol boundary.
        server_json: SensitiveWirePayload,
    },
    /// Copy an inherited effective server into this authored layer with an
    /// intentional override. This is distinct from add so ownership changes
    /// cannot happen accidentally.
    MaterializeInheritedServer {
        name: String,
        server_json: SensitiveWirePayload,
    },
    /// Change known fields on a server already authored in this layer. Values
    /// are a JSON object keyed by `ServerConfig` field; omitted raw/unknown
    /// sibling fields are preserved by the daemon.
    UpdateAuthoredServer {
        name: String,
        set_fields_json: SensitiveWirePayload,
        unset_fields: Vec<String>,
    },
    /// Delete an entry authored in the selected layer. The daemon rejects
    /// deletion of an inherited-only server; MCP has no tombstone syntax.
    DeleteAuthoredServer { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderHeaderView {
    pub name: String,
    pub value: String,
    #[serde(default)]
    pub redacted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderEntryView {
    pub entry: cockpit_config::config::providers::ProviderEntry,
    #[serde(default)]
    pub headers: Vec<ProviderHeaderView>,
    #[serde(default)]
    pub credential_configured: bool,
}

/// Secret-free provider model discovery result returned by the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProviderModelFetchOutcome {
    Models {
        models: Vec<cockpit_config::config::providers::ModelEntry>,
        catalog: cockpit_config::config::providers::ProviderModelCatalog,
    },
    FallbackAvailable {
        models: Vec<cockpit_config::config::providers::ModelEntry>,
        catalog: cockpit_config::config::providers::ProviderModelCatalog,
        reason: String,
    },
    /// The effective unlisted-model policy is `ask` and the fetched catalog
    /// would drop one or more configured models.  This is a no-write preview:
    /// callers must retry explicitly with `keep` or `remove`.
    UnlistedModelsPreview {
        unlisted_count: u32,
    },
    Unsupported,
    Error {
        message: String,
    },
}

/// One provider result from a daemon-owned catalog refresh.  The request can
/// intentionally target one provider or the complete configured catalog.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderModelFetchResult {
    pub provider_id: String,
    pub outcome: ProviderModelFetchOutcome,
}

/// Safe provider usage data. No credential, header, or opaque response body
/// is represented by this wire type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderUsageSnapshotView {
    pub provider_id: String,
    pub display_name: String,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
    pub availability: ProviderUsageAvailabilityView,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ProviderUsageAvailabilityView {
    Fetched {
        source: String,
        plan: Option<String>,
        windows: Vec<ProviderUsageWindowView>,
        details: Vec<String>,
    },
    Unsupported {
        reason: String,
    },
    Unavailable {
        reason: String,
        hint_url: Option<String>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderUsageWindowView {
    pub label: String,
    pub used_percent: Option<f64>,
    pub reset_at: Option<chrono::DateTime<chrono::Utc>>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum EnvDriftPolicy {
    #[default]
    Daemon,
    Client,
    UpdateDaemon,
    ErrorOnDrift,
}

/// Daemon-owned setup presentation selected when a session is created.
///
/// This is deliberately not an execution, model, sandbox, or agent-authority
/// setting. It is immutable session setup metadata: later attaches reload it
/// from the daemon rather than changing the session's entry contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEntryMode {
    Code,
    Assistant,
    Computer,
}

impl SessionEntryMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Code => "code",
            Self::Assistant => "assistant",
            Self::Computer => "computer",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Code => "Code",
            Self::Assistant => "Assistant",
            Self::Computer => "Computer",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvDiffSummary {
    pub baseline_digest: String,
    pub candidate_digest: String,
    pub added_keys: usize,
    pub removed_keys: usize,
    pub changed_keys: usize,
    pub changed_secret_keys: Vec<String>,
    pub path_added: Vec<String>,
    pub path_removed: Vec<String>,
}

impl EnvDiffSummary {
    pub fn meaningful(&self) -> bool {
        self.added_keys > 0
            || self.removed_keys > 0
            || self.changed_keys > 0
            || !self.path_added.is_empty()
            || !self.path_removed.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequirements {
    pub pools: BTreeMap<String, u32>,
}

impl ResourceRequirements {
    pub fn new(pools: impl IntoIterator<Item = (impl Into<String>, u32)>) -> Self {
        Self {
            pools: pools
                .into_iter()
                .filter_map(|(name, count)| (count > 0).then(|| (name.into(), count)))
                .collect(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pools.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRequestMetadata {
    pub session_id: Option<Uuid>,
    pub agent_id: Option<String>,
    pub tool_call_id: Option<String>,
    pub command_label: Option<String>,
    pub declared_requirements: ResourceRequirements,
    pub policy_requirements: ResourceRequirements,
    pub reviewer_requirements: ResourceRequirements,
    pub effective_requirements: ResourceRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceSchedulerSnapshot {
    pub enabled: bool,
    pub pools: Vec<ResourcePoolSnapshot>,
    pub running: Vec<ResourceRunningSnapshot>,
    pub queued: Vec<ResourceQueuedSnapshot>,
    pub max_queued: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePoolSnapshot {
    pub name: String,
    pub capacity: u32,
    pub used: u32,
    pub available: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRunningSnapshot {
    pub id: Uuid,
    pub display_id: String,
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
    pub queued_at_ms: i64,
    pub started_at_ms: i64,
    pub wait_ms: u64,
    pub promoted_by: Option<String>,
    pub promoted_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceQueuedSnapshot {
    pub id: Uuid,
    pub display_id: String,
    pub resources: ResourceRequirements,
    pub metadata: ResourceRequestMetadata,
    pub queued_at_ms: i64,
    pub wait_ms: u64,
    pub promoted_by: Option<String>,
    pub promoted_at_ms: Option<i64>,
    pub state: ResourceQueuedState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduledJobSchedule {
    Cron {
        expr: String,
    },
    Every {
        seconds: u64,
    },
    Once {
        at: i64,
    },
    Idle {
        min_idle_seconds: u64,
        max_age_seconds: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ScheduledJobPayload {
    RunPrompt {
        assistant: String,
        prompt: String,
        project_root: String,
    },
    Callback {
        subsystem: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MissedRunPolicy {
    #[default]
    Skip,
    RunOnceOnStart,
}

impl MissedRunPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::RunOnceOnStart => "run_once_on_start",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJobCreate {
    pub id: String,
    pub owner: String,
    pub schedule: ScheduledJobSchedule,
    pub payload: ScheduledJobPayload,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub missed_run_policy: MissedRunPolicy,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJobLastResult {
    pub ok: bool,
    pub summary: String,
    pub finished_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScheduledJobSummary {
    pub id: String,
    pub owner: String,
    pub schedule: ScheduledJobSchedule,
    pub payload: ScheduledJobPayload,
    pub enabled: bool,
    pub missed_run_policy: MissedRunPolicy,
    pub last_run_at: Option<i64>,
    pub next_run_at: Option<i64>,
    pub last_result: Option<ScheduledJobLastResult>,
    pub failure_count: u32,
    pub backoff_until: Option<i64>,
    pub disabled_notice: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceQueuedState {
    Queued,
    Promoted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerRuntimeKind {
    Docker,
    Podman,
}

impl ContainerRuntimeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerUnavailableReason {
    NoRuntime,
    HarnessInContainer,
    /// Engine CLI present but permission denied talking to the daemon/socket.
    PermissionDenied,
    /// Engine CLI present but the daemon socket is missing/unreachable.
    SocketUnavailable,
    /// Engine CLI present but the daemon/service is not running or not usable.
    DaemonUnavailable,
}

impl ContainerUnavailableReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoRuntime => "no_runtime",
            Self::HarnessInContainer => "harness_in_container",
            Self::PermissionDenied => "permission_denied",
            Self::SocketUnavailable => "socket_unavailable",
            Self::DaemonUnavailable => "daemon_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerAvailability {
    pub runtime: Option<ContainerRuntimeKind>,
    pub harness_in_container: bool,
    pub available: bool,
    pub reason: Option<ContainerUnavailableReason>,
}

impl ContainerAvailability {
    pub fn unpublished() -> Self {
        Self {
            runtime: None,
            harness_in_container: false,
            available: false,
            reason: Some(ContainerUnavailableReason::NoRuntime),
        }
    }
}

impl Default for ContainerAvailability {
    fn default() -> Self {
        Self {
            runtime: None,
            harness_in_container: false,
            available: false,
            reason: Some(ContainerUnavailableReason::NoRuntime),
        }
    }
}

impl ContainerAvailability {
    pub fn unavailable_reason_text(&self) -> Option<String> {
        self.reason.map(|reason| match reason {
            ContainerUnavailableReason::NoRuntime => {
                "no healthy docker or podman engine available".to_string()
            }
            ContainerUnavailableReason::HarnessInContainer => {
                "cockpit is already running inside a container".to_string()
            }
            ContainerUnavailableReason::PermissionDenied => {
                "permission denied talking to the container engine daemon".to_string()
            }
            ContainerUnavailableReason::SocketUnavailable => {
                "container engine daemon socket is unavailable".to_string()
            }
            ContainerUnavailableReason::DaemonUnavailable => {
                "container engine daemon is not running or not usable".to_string()
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaffeinateMode {
    Toggle,
    On,
    Off,
    UntilIdle,
}

impl CaffeinateMode {
    pub fn parse(arg: &str) -> std::result::Result<Self, String> {
        match arg.trim() {
            "" | "toggle" => Ok(Self::Toggle),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            "until-idle" | "until_idle" | "untilidle" => Ok(Self::UntilIdle),
            other => Err(other.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IdleReason {
    Completed,
    GoalComplete,
    NeedsIntervention { code: String },
    BudgetLimited,
    UsageLimited,
    Error { class: InferenceErrorClass },
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolFailKind {
    Invocation,
    Execution,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AccountInfo {
    pub user_id: String,
    pub email: String,
}

impl AccountInfo {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.user_id.is_empty(),
            "account user id must not be empty"
        );
        anyhow::ensure!(!self.email.is_empty(), "account email must not be empty");
        anyhow::ensure!(
            self.user_id.len() <= MAX_OWNER_ACCOUNT_FIELD_BYTES,
            "account user id exceeds maximum length"
        );
        anyhow::ensure!(
            self.email.len() <= MAX_OWNER_ACCOUNT_FIELD_BYTES,
            "account email exceeds maximum length"
        );
        Ok(())
    }
}

impl<'de> Deserialize<'de> for AccountInfo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            user_id: String,
            email: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            user_id: wire.user_id,
            email: wire.email,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

/// Secret inventory metadata. Values are intentionally not represented here;
/// this type is safe to return over owner-remoted RPCs.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SecretInventoryKind {
    NamedSecret,
    CredentialRecord,
    SubscriptionAck,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretInventoryEntry {
    pub name: String,
    pub kind: SecretInventoryKind,
    pub configured: bool,
}

/// Redacted projection of a stored Flycockpit account. The instance token is
/// deliberately absent; the fingerprint is only an opaque change detector.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FlycockpitAccountView {
    pub server_url: String,
    pub instance_id: String,
    pub account: AccountInfo,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_choice: Option<RelayChoice>,
    pub token_fingerprint: String,
}

impl FlycockpitAccountView {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.server_url.len() <= MAX_OWNER_SERVER_URL_BYTES,
            "account server URL exceeds maximum length"
        );
        anyhow::ensure!(
            self.instance_id.len() <= MAX_OWNER_INSTANCE_ID_BYTES,
            "account instance id exceeds maximum length"
        );
        if let Some(display_name) = &self.display_name {
            anyhow::ensure!(
                display_name.len() <= MAX_OWNER_DISPLAY_NAME_BYTES,
                "account display name exceeds maximum length"
            );
        }
        anyhow::ensure!(
            self.token_fingerprint.len() <= MAX_OWNER_TOKEN_FINGERPRINT_BYTES,
            "account token fingerprint exceeds maximum length"
        );
        self.account.validate()?;
        if let Some(relay) = &self.relay_choice {
            relay.validate()?;
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for FlycockpitAccountView {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            server_url: String,
            instance_id: String,
            account: AccountInfo,
            #[serde(default)]
            display_name: Option<String>,
            #[serde(default)]
            relay_choice: Option<RelayChoice>,
            token_fingerprint: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            server_url: wire.server_url,
            instance_id: wire.instance_id,
            account: wire.account,
            display_name: wire.display_name,
            relay_choice: wire.relay_choice,
            token_fingerprint: wire.token_fingerprint,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

pub fn normalize_server_url(raw: &str) -> anyhow::Result<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    anyhow::ensure!(!trimmed.is_empty(), "server URL cannot be empty");
    let url = url::Url::parse(trimmed)
        .map_err(|_| anyhow::anyhow!("server URL must be an absolute URL"))?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "server URL must not include credentials"
    );
    anyhow::ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "server URL must not include a query string or fragment"
    );
    anyhow::ensure!(
        matches!(url.path(), "" | "/"),
        "server URL must be an origin, not a path"
    );
    let loopback = matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "::1" | "[::1]")
    );
    anyhow::ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "server URL must use HTTPS except for localhost development"
    );
    Ok(url.origin().ascii_serialization())
}

/// Produce a safe display-only URL for an owner-remoted response.
///
/// Provider and relay URLs are configuration metadata, but query strings and
/// user-info routinely contain bearer tokens.  Keep the endpoint shape useful
/// to the UI while making those credential-bearing components impossible to
/// export.  An unparseable value is not safe to echo either.
pub fn redact_url_for_owner_view(raw: &str) -> String {
    let Ok(mut url) = url::Url::parse(raw) else {
        return "[redacted]".to_string();
    };
    if url.set_username("").is_err() || url.set_password(None).is_err() {
        return "[redacted]".to_string();
    }
    url.set_query(None);
    url.set_fragment(None);
    url.to_string()
}

#[derive(Clone, Serialize, PartialEq, Eq)]
pub struct StoredFlycockpitCredential {
    pub server_url: String,
    pub instance_id: String,
    pub instance_token: String,
    pub account: AccountInfo,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_choice: Option<RelayChoice>,
}

impl<'de> Deserialize<'de> for StoredFlycockpitCredential {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Wire {
            server_url: String,
            instance_id: String,
            instance_token: String,
            account: AccountInfo,
            #[serde(default)]
            display_name: Option<String>,
            #[serde(default)]
            relay_choice: Option<RelayChoice>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            server_url: wire.server_url,
            instance_id: wire.instance_id,
            instance_token: wire.instance_token,
            account: wire.account,
            display_name: wire.display_name,
            relay_choice: wire.relay_choice,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl StoredFlycockpitCredential {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            normalize_server_url(&self.server_url)? == self.server_url,
            "server URL must be normalized"
        );
        anyhow::ensure!(
            !self.instance_id.is_empty(),
            "instance id must not be empty"
        );
        anyhow::ensure!(
            !self.instance_token.is_empty(),
            "instance token must not be empty"
        );
        anyhow::ensure!(
            self.instance_token.len() <= MAX_OWNER_INSTANCE_TOKEN_BYTES,
            "instance token exceeds maximum length"
        );
        anyhow::ensure!(
            self.server_url.len() <= MAX_OWNER_SERVER_URL_BYTES,
            "server URL exceeds maximum length"
        );
        anyhow::ensure!(
            self.instance_id.len() <= MAX_OWNER_INSTANCE_ID_BYTES,
            "instance id exceeds maximum length"
        );
        self.account.validate()?;
        if let Some(display_name) = &self.display_name {
            anyhow::ensure!(
                display_name.len() <= MAX_OWNER_DISPLAY_NAME_BYTES,
                "display name exceeds maximum length"
            );
        }
        if let Some(relay) = &self.relay_choice {
            relay.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RelayChoice {
    pub relay_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    pub ws_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u64>,
    pub chosen_at: i64,
}

impl RelayChoice {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.relay_id.is_empty(), "relay id must not be empty");
        anyhow::ensure!(
            self.relay_id.len() <= MAX_OWNER_RELAY_ID_BYTES,
            "relay id exceeds maximum length"
        );
        anyhow::ensure!(
            !self.ws_url.is_empty(),
            "relay websocket URL must not be empty"
        );
        anyhow::ensure!(
            self.ws_url.len() <= MAX_OWNER_RELAY_URL_BYTES,
            "relay websocket URL exceeds maximum length"
        );
        if let Some(region) = &self.region {
            anyhow::ensure!(!region.is_empty(), "relay region must not be empty");
            anyhow::ensure!(
                region.len() <= MAX_OWNER_RELAY_REGION_BYTES,
                "relay region exceeds maximum length"
            );
        }
        Ok(())
    }

    pub fn is_fresh_at(&self, now_ms: i64) -> bool {
        const TTL_MS: i64 = 30 * 60 * 1000;
        now_ms.saturating_sub(self.chosen_at) < TTL_MS
    }
}

impl<'de> Deserialize<'de> for RelayChoice {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            relay_id: String,
            #[serde(default)]
            region: Option<String>,
            ws_url: String,
            #[serde(default)]
            rtt_ms: Option<u64>,
            chosen_at: i64,
        }
        let wire = Wire::deserialize(deserializer)?;
        let value = Self {
            relay_id: wire.relay_id,
            region: wire.region,
            ws_url: wire.ws_url,
            rtt_ms: wire.rtt_ms,
            chosen_at: wire.chosen_at,
        };
        value.validate().map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}

impl fmt::Debug for StoredFlycockpitCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StoredFlycockpitCredential")
            .field("server_url", &self.server_url)
            .field("instance_id", &self.instance_id)
            .field("instance_token", &"<redacted>")
            .field("account", &self.account)
            .field("display_name", &self.display_name)
            .field("relay_choice", &self.relay_choice)
            .finish()
    }
}

/// Current wire schema version. v21 includes the V2 tagged ingress envelope,
/// queued-message delivery classes, local queue controls, MCP credential
/// profiles, agent-dimensioned MCP scopes, bounded base64 media previews, and
/// the rolling-precompaction resume choice.
pub const PROTOCOL_VERSION: u32 = 21;

/// Oldest wire schema version this binary accepts. Exact-match only until a
/// compacted v1 ships. v21 is current-only: all pre-launch wire changes are
/// edited in place, with no compatibility shim.
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 21;

/// Version string the daemon advertises to clients on attach/status.
pub const DAEMON_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Max length of a single local NDJSON frame.
///
/// Successor to the retired 8 MiB `MAX_FRAME_BYTES`. Every application payload
/// above 512 KiB now travels as typed windowed bulk chunks
/// ([`remote_transport::bulk`]), so the largest legal NDJSON frame carries a
/// 512 KiB (524,288-byte) binary payload. That base64-inflates to
/// 4 × ⌈524,288 / 3⌉ = 699,052 bytes; the JSON envelope (field names, ids,
/// escaping) fits comfortably in the remaining 349,524 bytes. 1 MiB is the
/// smallest clean power-of-two bound with that headroom.
pub const MAX_NDJSON_FRAME_BYTES: usize = 1_048_576;
/// Maximum serialized daemon response envelope, including its trailing NDJSON
/// newline. This deliberately leaves transport headroom beneath the codec's
/// hard frame ceiling for escaping and envelope metadata.
pub const MAX_SERIALIZED_RESPONSE_BYTES: usize = 900 * 1024;
pub const MAX_AGENT_INVENTORY_ENTRIES: usize = 1_024;
pub const MAX_ASSISTANT_SUMMARIES: usize = 512;
pub const MAX_EXTENDED_CONFIG_LAYERS: usize = 32;
pub const MAX_EXTENDED_CONFIG_SOURCE_BYTES: usize = 512 * 1024;

/// Bounds for owner-only secret-management RPC fields. These are deliberately
/// below the NDJSON frame limit so a single request cannot consume the whole
/// transport budget with one field (and so typed/in-process callers have the
/// same contract as decoded wire callers).
pub const MAX_OWNER_SECRET_NAME_BYTES: usize = 256;
pub const MAX_OWNER_SECRET_VALUE_BYTES: usize = 256 * 1024;
pub const MAX_OWNER_PROVIDER_ID_BYTES: usize = 256;
pub const MAX_OWNER_PROVIDER_RECORD_BYTES: usize = 512 * 1024;
pub const RESERVED_OWNER_PROVIDER_ID_PREFIX: &str = "subscription-oauth-ack:";
/// Inventory item ids include the reserved subscription-ack prefix. Keep the
/// cursor decoder large enough for the longest valid id in any inventory kind.
pub const MAX_OWNER_INVENTORY_ITEM_ID_BYTES: usize =
    MAX_OWNER_SECRET_NAME_BYTES + RESERVED_OWNER_PROVIDER_ID_PREFIX.len();
/// Reserved for the dedicated FlyCockpit credential RPCs; generic provider
/// credential mutations must never overwrite or remove this record.
pub const RESERVED_FLYCOCKPIT_PROVIDER_ID: &str = "flycockpit";
pub const MAX_OWNER_INVENTORY_CURSOR_BYTES: usize = 1024;
pub const MAX_OWNER_INVENTORY_PAGE_ENTRIES: usize = 128;
pub const MAX_OWNER_INVENTORY_TOTAL_ENTRIES: usize = 4096;
pub const MAX_OWNER_INVENTORY_PAGE_BYTES: usize = 512 * 1024;
pub const MAX_OWNER_SERVER_URL_BYTES: usize = 2048;
pub const MAX_OWNER_INSTANCE_ID_BYTES: usize = 256;
pub const MAX_OWNER_INSTANCE_TOKEN_BYTES: usize = 4096;
pub const MAX_OWNER_ACCOUNT_FIELD_BYTES: usize = 512;
pub const MAX_OWNER_DISPLAY_NAME_BYTES: usize = 512;
pub const MAX_OWNER_TOKEN_FINGERPRINT_BYTES: usize = 128;
pub const MAX_OWNER_RELAY_ID_BYTES: usize = 256;
pub const MAX_OWNER_RELAY_URL_BYTES: usize = 2048;
pub const MAX_OWNER_RELAY_REGION_BYTES: usize = 256;
/// Owner-RPC provider metadata is kept comfortably below the 512 KiB remote
/// interactive-lane cap, including JSON envelope overhead.
pub const MAX_OWNER_PROVIDER_METADATA_JSON_BYTES: usize = 256 * 1024;
pub const MAX_OWNER_PROVIDER_URL_BYTES: usize = 8 * 1024;
pub const MAX_OWNER_PROVIDER_MODEL_ID_BYTES: usize = 1024;
pub const MAX_OWNER_PROJECT_ROOT_BYTES: usize = 16 * 1024;
pub const MAX_OWNER_ORG_ID_BYTES: usize = 256;
/// Maximum canonical JSON size accepted for one provider configuration entry.
pub const MAX_OWNER_PROVIDER_ENTRY_BYTES: usize = 256 * 1024;
/// Maximum canonical JSON size accepted for one MCP config patch, secret
/// envelope, or agent-scope MCP server payload. Kept below the 512 KiB
/// remote interactive-lane cap, including JSON envelope overhead.
pub const MAX_OWNER_MCP_PATCH_BYTES: usize = 256 * 1024;

/// Pasted-image upload limits. Chunks are base64 strings inside JSON frames,
/// so keep the base64 payload below the bulk lane's 512 KiB logical cap.
pub const MAX_SINGLE_IMAGE_BYTES: usize =
    cockpit_config::config::media_budget::PASTE_MAX_SINGLE_IMAGE_BYTES;
pub const MAX_TOTAL_IMAGE_BYTES: usize =
    cockpit_config::config::media_budget::PASTE_MAX_TOTAL_IMAGE_BYTES;
pub const MAX_IMAGE_DIMENSION_PIXELS: u32 =
    cockpit_config::config::media_budget::PASTE_MAX_EDGE_PIXELS;
/// One attachment chunk's base64 body. Sized so the encoded chunk frame fits
/// inside a single 512 KiB bulk-lane logical payload with envelope headroom.
pub const MAX_ATTACHMENT_CHUNK_BASE64_BYTES: usize = 256 * 1024;
pub const PENDING_ATTACHMENT_TTL_SECS: u64 = 10 * 60;
pub const IMAGE_ATTACHMENT_MIME_PNG: &str = "image/png";
pub const IMAGE_PART_SENTINEL: &str = "\u{0}<cockpit-image-part>\u{0}";

pub fn is_protocol_compatible(v: u32) -> bool {
    (MIN_SUPPORTED_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&v)
}

pub fn version_mismatch_message(v: u32) -> String {
    format!(
        "wire protocol version mismatch: peer sent v{v}, this binary speaks v{} (supported {}..={})",
        PROTOCOL_VERSION, MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonHello {
    pub daemon_version: String,
    pub protocol_version: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatedProtocol {
    pub version: u32,
    pub daemon_version: String,
    pub daemon_protocol_version: u32,
}

impl NegotiatedProtocol {
    pub fn current() -> Self {
        Self {
            version: PROTOCOL_VERSION,
            daemon_version: "unknown".to_string(),
            daemon_protocol_version: PROTOCOL_VERSION,
        }
    }

    pub fn from_hello(hello: &DaemonHello) -> std::result::Result<Self, ErrorPayload> {
        if hello.protocol_version != PROTOCOL_VERSION {
            return Err(ErrorPayload {
                code: ErrorCode::ProtocolVersion,
                message: incompatible_daemon_protocol_message(hello.protocol_version),
            });
        }
        Ok(Self {
            version: PROTOCOL_VERSION,
            daemon_version: hello.daemon_version.clone(),
            daemon_protocol_version: hello.protocol_version,
        })
    }
}

pub fn incompatible_daemon_protocol_message(daemon_protocol_version: u32) -> String {
    format!(
        "daemon speaks protocol v{daemon_protocol_version}; this client supports v{}..=v{}. run `cockpit daemon restart`",
        MIN_SUPPORTED_PROTOCOL_VERSION, PROTOCOL_VERSION
    )
}

pub fn daemon_hello_from_envelope(env: &Envelope) -> Option<DaemonHello> {
    let Body::Response { id, response } = &env.body else {
        return None;
    };
    if !id.is_nil() {
        return None;
    }
    let Response::DaemonStatus {
        daemon_version,
        protocol_version,
        ..
    } = response.as_ref()
    else {
        return None;
    };
    Some(DaemonHello {
        daemon_version: daemon_version.clone(),
        protocol_version: *protocol_version,
    })
}

pub fn parse_daemon_hello_line(line: &str) -> Result<Option<DaemonHello>> {
    let env: Envelope = serde_json::from_str(line).context("deserializing daemon hello")?;
    Ok(daemon_hello_from_envelope(&env))
}

// ---- Envelope --------------------------------------------------------------

/// Top-level frame. Always carries the protocol version and one of four
/// body variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    #[serde(flatten)]
    pub body: Body,
}

#[derive(Debug, Clone)]
pub enum RecvFrame {
    Envelope(Box<Envelope>),
    Unknown {
        v: u32,
        kind: String,
        tag: Option<String>,
        id: Option<Uuid>,
    },
    VersionMismatch {
        v: u32,
        kind: String,
        id: Option<Uuid>,
    },
}

impl Envelope {
    pub fn request(id: Uuid, request: Request) -> Self {
        Self::request_at(PROTOCOL_VERSION, id, request)
    }

    pub fn request_at(v: u32, id: Uuid, request: Request) -> Self {
        Self {
            v,
            body: Body::Request {
                id,
                #[cfg(feature = "remote")]
                operation: None,
                request,
            },
        }
    }

    #[cfg(feature = "remote")]
    pub fn remote_request(
        id: Uuid,
        operation: RemoteOperationIdentityV1,
        request: Request,
    ) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            body: Body::Request {
                id,
                operation: Some(operation),
                request,
            },
        }
    }

    pub fn response(id: Uuid, response: Response) -> Self {
        Self::response_at(PROTOCOL_VERSION, id, response)
    }

    pub fn response_at(v: u32, id: Uuid, response: Response) -> Self {
        Self {
            v,
            body: Body::Response {
                id,
                response: Box::new(response),
            },
        }
    }

    pub fn event(event: Event) -> Self {
        Self::event_at(PROTOCOL_VERSION, event)
    }

    pub fn event_at(v: u32, event: Event) -> Self {
        Self {
            v,
            body: Body::Event { event },
        }
    }

    pub fn error(id: Option<Uuid>, error: ErrorPayload) -> Self {
        Self::error_at(PROTOCOL_VERSION, id, error)
    }

    pub fn error_at(v: u32, id: Option<Uuid>, error: ErrorPayload) -> Self {
        Self {
            v,
            body: Body::Error { id, error },
        }
    }
}

// `Body::Request` is inherently the largest variant: it flattens the full
// `Request` command enum (hundreds of bytes) whereas `Event`/`Error` are
// small. This is a frozen wire type — boxing the flattened field would
// perturb the serde(flatten) shape — so the size skew is accepted by design
// rather than restructured.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum Body {
    #[serde(rename = "req")]
    Request {
        id: Uuid,
        #[cfg(feature = "remote")]
        #[serde(default, skip_serializing_if = "Option::is_none")]
        operation: Option<RemoteOperationIdentityV1>,
        #[serde(flatten)]
        request: Request,
    },
    #[serde(rename = "res")]
    Response {
        id: Uuid,
        #[serde(flatten)]
        response: Box<Response>,
    },
    #[serde(rename = "evt")]
    Event {
        #[serde(flatten)]
        event: Event,
    },
    #[serde(rename = "err")]
    Error {
        /// `Some` when this `err` pairs with a `req`; `None` for
        /// out-of-band errors.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<Uuid>,
        error: ErrorPayload,
    },
    #[cfg(feature = "remote")]
    #[serde(rename = "replay_req")]
    RemoteReplayRequest(RemoteReplayRequestV2),
    #[cfg(feature = "remote")]
    #[serde(rename = "replay_res")]
    RemoteReplayResponse(RemoteReplayResponseV2),
    #[cfg(feature = "remote")]
    #[serde(rename = "replay_ack")]
    RemoteReplayAck(RemoteReplayAckV2),
    #[cfg(feature = "remote")]
    #[serde(rename = "replay_ack_res")]
    RemoteReplayAckResponse(RemoteReplayAckResponseV2),
    #[serde(other)]
    Unknown,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteReplayRequestV2 {
    pub id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_event_seq: Option<crate::remote_protocol_id::CanonicalU64DecimalStringV1>,
    pub limit: RemoteReplayLimit,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteReplayResponseV2 {
    pub id: Uuid,
    pub events: Vec<RemoteOutboxDeliveryV1>,
    pub high_water_mark: crate::remote_protocol_id::CanonicalU64DecimalStringV1,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteReplayAckV2 {
    pub id: Uuid,
    pub delivery_id: CanonicalRfcUuidV1,
    pub lease_token: CanonicalRfcUuidV1,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteReplayAckResponseV2 {
    pub id: Uuid,
    pub acked: bool,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteOutboxDeliveryV1 {
    pub event_seq: crate::remote_protocol_id::CanonicalU64DecimalStringV1,
    pub delivery_id: CanonicalRfcUuidV1,
    pub kind: String,
    pub canonical_payload: Vec<u8>,
    pub lease_token: CanonicalRfcUuidV1,
    pub lease_expires_at_ms: i64,
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanonicalRfcUuidV1(Uuid);

#[cfg(feature = "remote")]
impl CanonicalRfcUuidV1 {
    pub fn new(value: Uuid) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !value.is_nil() && value.get_variant() == uuid::Variant::RFC4122,
            "UUID must be nonnil RFC variant"
        );
        Ok(Self(value))
    }
    pub fn get(self) -> Uuid {
        self.0
    }
}

#[cfg(feature = "remote")]
impl Serialize for CanonicalRfcUuidV1 {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0.hyphenated().to_string())
    }
}

#[cfg(feature = "remote")]
impl<'de> Deserialize<'de> for CanonicalRfcUuidV1 {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let value = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
        if value.hyphenated().to_string() != text {
            return Err(serde::de::Error::custom(
                "UUID must use canonical lowercase hyphenated spelling",
            ));
        }
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RemoteReplayLimit(u16);

#[cfg(feature = "remote")]
impl RemoteReplayLimit {
    pub fn new(value: u16) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=256).contains(&value), "replay limit must be 1..=256");
        Ok(Self(value))
    }
    pub fn get(self) -> u16 {
        self.0
    }
}

#[cfg(feature = "remote")]
impl<'de> Deserialize<'de> for RemoteReplayLimit {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        Self::new(u16::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteOperationIdentityV1 {
    pub schema_version: u8,
    pub logical_attachment_id: Uuid,
    pub operation_id: Uuid,
}

#[cfg(feature = "remote")]
impl RemoteOperationIdentityV1 {
    pub fn new(logical_attachment_id: Uuid, operation_id: Uuid) -> Result<Self> {
        anyhow::ensure!(
            !logical_attachment_id.is_nil()
                && logical_attachment_id.get_variant() == uuid::Variant::RFC4122,
            "logical attachment id must be a nonnil RFC UUID"
        );
        anyhow::ensure!(
            !operation_id.is_nil() && operation_id.get_variant() == uuid::Variant::RFC4122,
            "operation id must be a nonnil RFC UUID"
        );
        anyhow::ensure!(
            operation_id.get_version_num() == 7,
            "operation id must be UUIDv7"
        );
        Ok(Self {
            schema_version: 1,
            logical_attachment_id,
            operation_id,
        })
    }
}

#[cfg(feature = "remote")]
impl<'de> Deserialize<'de> for RemoteOperationIdentityV1 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            schema_version: u8,
            logical_attachment_id: String,
            operation_id: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        if wire.schema_version != 1 {
            return Err(serde::de::Error::custom(
                "remote operation identity schemaVersion must be 1",
            ));
        }
        let parse_canonical = |text: String| {
            let value = Uuid::parse_str(&text).map_err(serde::de::Error::custom)?;
            if value.hyphenated().to_string() != text {
                return Err(serde::de::Error::custom(
                    "UUID must use canonical lowercase hyphenated spelling",
                ));
            }
            Ok(value)
        };
        Self::new(
            parse_canonical(wire.logical_attachment_id)?,
            parse_canonical(wire.operation_id)?,
        )
        .map_err(serde::de::Error::custom)
    }
}

// ---- Requests --------------------------------------------------------------

mod request;
pub use request::{
    ActiveModelSwitchTrigger, AttachmentPurpose, ImageIngressSourceV1, LspControlAction, Request,
    RunInvocationOptions, UsageKind, UserMessageOrigin,
};
#[cfg(feature = "remote")]
pub use request::{
    MAX_UUID_V7_UNIX_MS, RemoteAdapterEvidenceV1, RemoteAdapterRecoveryContractV1,
    RemoteAdapterRecoveryStrategy, RemoteOperationClass, UnknownRemoteOperationClass,
    canonical_remote_operation_fcor_schema_for_tag, remote_adapter_recovery_contract_for_tag,
    remote_adapter_recovery_strategy_for_tag, remote_operation_class_for_tag,
    remote_operation_fcor_schema_for_tag, remote_operation_uuid_v7_from_parts,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsEntryKind {
    File,
    Directory,
    Symlink,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsReadKind {
    Text,
    Binary,
    Image,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FsEntry {
    pub name: String,
    pub path: String,
    pub kind: FsEntryKind,
    pub size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtime_ms: Option<i64>,
    pub gitignored: bool,
    pub blocked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitStatusEntry {
    pub raw: String,
}

/// Read-only Git projection requested by a daemon client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "value")]
pub enum GitReadSource {
    Worktree,
    Staged,
    Unstaged,
    Unpushed,
    PullRequest(String),
}

/// Display-safe result for one independently requested review source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitReviewSourceResult {
    pub source: GitReadSource,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    pub has_changes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationSteerStatus {
    Queued,
    NotSteerable,
    InternalError,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationSteerResult {
    pub status: DelegationSteerStatus,
    pub task_call_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub message: String,
    #[serde(default)]
    pub pending_steers: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_principal: Option<String>,
    #[serde(default)]
    pub scrubbed: bool,
}

impl DelegationSteerResult {
    pub fn queued(
        task_call_id: String,
        label: String,
        pending_steers: i64,
        origin_principal: String,
        scrubbed: bool,
    ) -> Self {
        Self {
            status: DelegationSteerStatus::Queued,
            task_call_id,
            label: Some(label),
            message: "steer queued".to_string(),
            pending_steers,
            origin_principal: Some(origin_principal),
            scrubbed,
        }
    }

    pub fn not_steerable(task_call_id: String, label: Option<String>, reason: String) -> Self {
        Self {
            status: DelegationSteerStatus::NotSteerable,
            task_call_id,
            label,
            message: reason,
            pending_steers: 0,
            origin_principal: None,
            scrubbed: false,
        }
    }

    pub fn internal(message: String) -> Self {
        Self {
            status: DelegationSteerStatus::InternalError,
            task_call_id: String::new(),
            label: None,
            message,
            pending_steers: 0,
            origin_principal: None,
            scrubbed: false,
        }
    }

    pub fn to_task_envelope_value(&self) -> serde_json::Value {
        match self.status {
            DelegationSteerStatus::Queued => {
                let label = self.label.clone().unwrap_or_default();
                serde_json::json!({
                    "state": "steer_queued",
                    "task_call_id": self.task_call_id,
                    "label": label,
                    "blocking": false,
                    "tool_call_closed": false,
                    "result_pending": false,
                    "report_available": false,
                    "report_delivered": false,
                    "actionable": true,
                    "applies_at": "next_child_turn_boundary",
                    "applies_if": "child_still_running_actionable",
                    "origin_principal": self.origin_principal,
                    "scrubbed": self.scrubbed,
                    "children": [{
                        "task_call_id": self.task_call_id,
                        "label": label,
                        "pending_steers": self.pending_steers,
                        "actionable": true,
                    }],
                })
            }
            DelegationSteerStatus::NotSteerable => serde_json::json!({
                "state": "refused",
                "task_call_id": self.task_call_id,
                "label": self.label,
                "reason": self.message,
                "actionable": false,
            }),
            DelegationSteerStatus::InternalError => serde_json::json!({
                "state": "error",
                "reason": self.message,
                "actionable": false,
            }),
        }
    }
}

mod response;
pub use response::{
    ActiveModelState, BtwForkInfo, ClientSubmissionReceiptStatus, ImageIngressAdmissionReceiptV1,
    Response, ResumeCompactionDefault, ResumeCompactionOffer, RunInvocationCancelOutcome,
    RunInvocationCancelResultV1, RunInvocationLifecycleState, RunInvocationStatusV1,
    RunInvocationTerminalReason,
};
#[cfg(feature = "remote")]
pub use response::{RemoteGoalOutcomeV1, RemoteOperationStateV1, RemoteOperationStatusV1};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuidanceProposalDecision {
    Reject,
    AcceptSession,
    AcceptPersistent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingGuidanceProposal {
    pub proposal_id: Uuid,
    pub rules: Vec<[u8; 3]>,
    pub rationale: Option<String>,
    pub expires_at_unix_ms: i64,
    /// The daemon has confirmed that the proposal's current scope still
    /// permits machine-local persistent acceptance. The server remains the
    /// authority at review time; clients use this only to hide the action.
    pub persistent_acceptance_allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ResumeRepairState {
    pub session_id: Uuid,
    #[serde(default)]
    pub short_id: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub wire_api: String,
    pub failure_kind: String,
    #[serde(default)]
    pub failing_tool_call_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub safe_last_turn_seq: Option<i64>,
    #[serde(default)]
    pub suggested_actions: Vec<ResumeRepairAction>,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePromoteStatus {
    Promoted,
    NotQueued,
    NotFound,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResumeRepairAction {
    OpenReadOnly,
    ForkFromLastProviderValidTurn,
    RepairSyntheticToolResults,
    ExportDebugBundle,
    Cancel,
}

fn default_daemon_version() -> String {
    DAEMON_VERSION.to_string()
}

fn default_client_protocol_version() -> u32 {
    MIN_SUPPORTED_PROTOCOL_VERSION
}

// (The wire event variant for the same state change lives on `Event`
// below, carrying `session_id` so the client can route it.)

mod event;
pub use event::{
    AgentTreeEventSubject, AgentTreeTransition, AuthFailureKind, DefaultModelStandaloneOutcome,
    DefaultModelUpdateOutcome, Event, InferenceErrorClass, ModelSelectionActiveState,
    ModelSelectionOutcome, ResponsePerformance, UserMessageTerminalDisposition,
    WorkspaceTrustReconciliationState,
};

// ---- Errors ----------------------------------------------------------------

/// Structured error response. The model and the TUI both render
/// `message` directly; `code` lets the client branch on
/// machine-readable kinds without parsing the message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct ErrorPayload {
    pub code: ErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCode {
    /// Request payload didn't parse / failed validation.
    BadRequest,
    /// Daemon doesn't speak this protocol version.
    ProtocolVersion,
    /// Peer sent a request variant this daemon does not know.
    UnsupportedRequest,
    /// No active session — `Attach` first.
    NotAttached,
    /// Session id unknown.
    UnknownSession,
    /// Interrupt id unknown / already resolved.
    UnknownInterrupt,
    /// Daemon is shutting down.
    Shutdown,
    /// Principal is not authorized for the requested operation.
    Authorization,
    /// Principal has read-only access to this session.
    ReadOnly,
    /// Project root is missing or not a directory.
    RootMissing,
    /// Requested path escapes the project root.
    PathOutsideRoot,
    /// Optimistic-concurrency base hash did not match current content.
    HashMismatch,
    /// Requested path is locked by another writer.
    LockConflict,
    /// Optimistic generation/version did not match authoritative state.
    Conflict,
    /// The daemon refused this request because a short-lived, self-resolving
    /// condition owns the authority it would have read (today: a workspace-trust
    /// reconciliation in flight). Unlike [`Self::Conflict`], re-sending the
    /// exact same request *is* the documented recovery — no reattach, no
    /// generation refresh, no user action. Clients bound their retries; the
    /// daemon never promises a deadline.
    RetryLater,
    /// Workspace trust is unset or explicitly refuses access.
    WorkspaceTrust,
    /// A user message was deterministically rejected before entering the
    /// driver queue. Retrying the exact client submission id and payload is
    /// safe after the reported session condition is resolved.
    UserMessageNotAccepted,
    /// A fenced TUI submission captured a model generation/identity that is
    /// no longer authoritative. The message had zero queue/provider effect.
    ModelGenerationStale,
    /// This exact client submission id reached a durable terminal disposition
    /// (removed, cancelled, or rejected by preflight) and must never be
    /// executed by a later worker epoch.
    UserMessageTerminated,
    /// Requested agent is not a chat-ownable primary in the acquired snapshot.
    UnknownAgent,
    /// An inventory collection exceeded a hard response bound.
    InventoryTooLarge,
    /// Config is invalid; the daemon retained the last valid snapshot and
    /// cannot build a fresh inventory from the broken config.
    InvalidConfig,
    /// The response-metrics tokenizer is explicitly present but invalid.
    InvalidResponseMetricsTokenizer,
    /// A dependency required to serve inventory is temporarily unavailable.
    Unavailable,
    /// Same-principal start/replay used a client_submission_id with different
    /// message or immutable run options. Content-free; does not mutate state.
    IdempotencyConflict,
    /// A client_submission_id is reserved by another principal, a tombstone,
    /// or is otherwise unavailable for a new start. Content-free.
    ClientSubmissionIdUnavailable,
    /// Authoritative unknown or unauthorized run-invocation lookup. Content-free;
    /// shared by never-seen, wrong-principal, tombstoned, and expired UUIDs.
    InvocationNotFound,
    /// New start rejected because session/principal quota is full. Retryable,
    /// content-free; no receipt or partial row is written.
    InvocationCapacityExceeded,
    /// Status/cancel for an unknown id could not install a tombstone because
    /// quota is full. Non-authoritative Busy; content-free.
    InvocationLookupBusy,
    /// Content-free terminal binding/operation rejection.
    InvalidIngress,
    /// An operation id was reused with different immutable metadata.
    IngressConflict,
    /// The host cannot safely represent the private path for this shell.
    IngressPathUnavailable,
    /// The operation belongs to a terminal generation that no longer exists.
    TerminalGenerationGone,
    /// `SetSandbox` asked for a mode the host capability snapshot cannot honor.
    SandboxCapabilityMissing,
    /// SQLite could not extend durable storage. Commit outcome may be unknown.
    StorageFull,
    /// SQLite could not allocate memory for durable work. Outcome may be unknown.
    StorageMemory,
    /// The database or its directory is not writable.
    StorageReadOnly,
    /// SQLite reported a storage-device/filesystem I/O failure. Outcome may be unknown.
    StorageIo,
    /// SQLite reported database corruption or a non-database file.
    StorageCorrupt,
    /// Anything else.
    Internal,
    /// Error code from a future peer that this binary does not know yet.
    Other(String),
}

impl Serialize for ErrorCode {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for ErrorCode {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "bad_request" => Self::BadRequest,
            "protocol_version" => Self::ProtocolVersion,
            "unsupported_request" => Self::UnsupportedRequest,
            "not_attached" => Self::NotAttached,
            "unknown_session" => Self::UnknownSession,
            "unknown_interrupt" => Self::UnknownInterrupt,
            "shutdown" => Self::Shutdown,
            "authorization" => Self::Authorization,
            "read_only" => Self::ReadOnly,
            "root_missing" => Self::RootMissing,
            "path_outside_root" => Self::PathOutsideRoot,
            "hash_mismatch" => Self::HashMismatch,
            "lock_conflict" => Self::LockConflict,
            "conflict" => Self::Conflict,
            "retry_later" => Self::RetryLater,
            "workspace_trust" => Self::WorkspaceTrust,
            "user_message_not_accepted" => Self::UserMessageNotAccepted,
            "model_generation_stale" => Self::ModelGenerationStale,
            "user_message_terminated" => Self::UserMessageTerminated,
            "unknown_agent" => Self::UnknownAgent,
            "inventory_too_large" => Self::InventoryTooLarge,
            "invalid_config" => Self::InvalidConfig,
            "invalid_response_metrics_tokenizer" => Self::InvalidResponseMetricsTokenizer,
            "unavailable" => Self::Unavailable,
            "idempotency_conflict" => Self::IdempotencyConflict,
            "client_submission_id_unavailable" => Self::ClientSubmissionIdUnavailable,
            "invocation_not_found" => Self::InvocationNotFound,
            "invocation_capacity_exceeded" => Self::InvocationCapacityExceeded,
            "invocation_lookup_busy" => Self::InvocationLookupBusy,
            "invalid_ingress" => Self::InvalidIngress,
            "ingress_conflict" => Self::IngressConflict,
            "ingress_path_unavailable" => Self::IngressPathUnavailable,
            "terminal_generation_gone" => Self::TerminalGenerationGone,
            "sandbox_capability_missing" => Self::SandboxCapabilityMissing,
            "storage_full" => Self::StorageFull,
            "storage_memory" => Self::StorageMemory,
            "storage_read_only" => Self::StorageReadOnly,
            "storage_io" => Self::StorageIo,
            "storage_corrupt" => Self::StorageCorrupt,
            "internal" => Self::Internal,
            _ => Self::Other(raw),
        })
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::BadRequest => "bad_request",
            Self::ProtocolVersion => "protocol_version",
            Self::UnsupportedRequest => "unsupported_request",
            Self::NotAttached => "not_attached",
            Self::UnknownSession => "unknown_session",
            Self::UnknownInterrupt => "unknown_interrupt",
            Self::Shutdown => "shutdown",
            Self::Authorization => "authorization",
            Self::ReadOnly => "read_only",
            Self::RootMissing => "root_missing",
            Self::PathOutsideRoot => "path_outside_root",
            Self::HashMismatch => "hash_mismatch",
            Self::LockConflict => "lock_conflict",
            Self::Conflict => "conflict",
            Self::RetryLater => "retry_later",
            Self::WorkspaceTrust => "workspace_trust",
            Self::UserMessageNotAccepted => "user_message_not_accepted",
            Self::ModelGenerationStale => "model_generation_stale",
            Self::UserMessageTerminated => "user_message_terminated",
            Self::UnknownAgent => "unknown_agent",
            Self::InventoryTooLarge => "inventory_too_large",
            Self::InvalidConfig => "invalid_config",
            Self::InvalidResponseMetricsTokenizer => "invalid_response_metrics_tokenizer",
            Self::Unavailable => "unavailable",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::ClientSubmissionIdUnavailable => "client_submission_id_unavailable",
            Self::InvocationNotFound => "invocation_not_found",
            Self::InvocationCapacityExceeded => "invocation_capacity_exceeded",
            Self::InvocationLookupBusy => "invocation_lookup_busy",
            Self::InvalidIngress => "invalid_ingress",
            Self::IngressConflict => "ingress_conflict",
            Self::IngressPathUnavailable => "ingress_path_unavailable",
            Self::TerminalGenerationGone => "terminal_generation_gone",
            Self::SandboxCapabilityMissing => "sandbox_capability_missing",
            Self::StorageFull => "storage_full",
            Self::StorageMemory => "storage_memory",
            Self::StorageReadOnly => "storage_read_only",
            Self::StorageIo => "storage_io",
            Self::StorageCorrupt => "storage_corrupt",
            Self::Internal => "internal",
            Self::Other(raw) => raw,
        };
        f.write_str(s)
    }
}

pub fn unsupported_request_error(v: u32, tag: Option<&str>) -> ErrorPayload {
    let tag = tag.unwrap_or("unknown");
    ErrorPayload {
        code: ErrorCode::UnsupportedRequest,
        message: format!(
            "unsupported request \"{tag}\" in protocol v{v}; this daemon speaks v{PROTOCOL_VERSION}"
        ),
    }
}

// ---- Shared payload types --------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum HistoryEntry {
    InterruptDecision {
        decision: InterruptDecision,
        #[serde(default)]
        seq: i64,
    },
    User {
        text: String,
        /// User-facing transcript form. Legacy rows omit it and display
        /// `text` unchanged.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        display_text: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        tag_expansions: Vec<TagExpansionMeta>,
        /// Stable client submission ids represented by this durable row.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        client_submission_ids: Vec<Uuid>,
        /// `session_events.ts_ms` of this message (epoch millis) — the wall
        /// clock the TUI stamps on the restored row so a resumed transcript
        /// shows the original send time, not the resume time.
        #[serde(default)]
        ts_ms: i64,
        /// `session_events.seq` of this message — the stable id a pin
        /// references (`pinned-messages`) and the chronological ordering key.
        #[serde(default)]
        seq: i64,
        /// Principal that authored this user row (`flycockpit:<user_id>` for
        /// remote sharees). `None` is the local machine owner / legacy rows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        origin_principal: Option<String>,
    },
    /// Display-only `/note` transcript annotation restored into attach/export
    /// history. It never enters model-bound rehydration context.
    UserNote {
        text: String,
        #[serde(default)]
        ts_ms: i64,
        #[serde(default)]
        seq: i64,
    },
    Assistant {
        agent: String,
        /// Body text with inline `<think>` blocks stripped (the clean,
        /// stored form). Never carries reasoning tags.
        text: String,
        /// The exact final text shown to users when it differs from `text`
        /// (translation success). `None` for legacy/fallback/identical —
        /// consumers display `presentation_text.unwrap_or(text)`. Model
        /// context continues to use `text` only.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation_text: Option<String>,
        /// The turn's (channel + inline) reasoning, repopulating the
        /// thinking chip on resume (implementation note).
        /// Empty when the turn had none. UI/DB-only — never re-enters the
        /// model's context.
        #[serde(default)]
        reasoning: String,
        /// Optional durable response-performance snapshot. Absent for
        /// empty/think-only/no-visible-body/zero-duration responses and
        /// legacy rows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        response_performance: Option<ResponsePerformance>,
        /// `session_events.ts_ms` of this turn (epoch millis).
        #[serde(default)]
        ts_ms: i64,
        /// `session_events.seq` of this turn — pin id + ordering key.
        #[serde(default)]
        seq: i64,
    },
    /// Tool calls appear inline in history so the TUI re-renders the
    /// turn faithfully on reconnect. The shape mirrors the
    /// `tool_call_events` row (GOALS §15b): the user transcript sees
    /// `original_input` and the recovery chip; the model on its next
    /// inference call sees `wire_input` (which equals
    /// `original_input` unless §12 repair or §13c cascade rewrite
    /// fired).
    ToolCall {
        /// `session_events.seq` of this tool-call timeline row.
        #[serde(default)]
        seq: i64,
        agent: String,
        call_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_call_id: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_child_index: Option<i64>,
        tool: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_server: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_builtin: Option<bool>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mcp_kind: Option<String>,
        original_input: Value,
        wire_input: Value,
        recovery_kind: Option<String>,
        recovery_stage: Option<String>,
        output: String,
        hard_fail: bool,
        truncated: bool,
        /// Post-result hint text (`engine::bash_hints`, the user-side
        /// `data.hint.text`) when a rule fired on this `bash` call; `None`
        /// otherwise. `#[serde(default)]` keeps the restore wire backward-
        /// compatible with rows/peers that predate the hint layer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hint: Option<String>,
    },
    /// Display-only terminal inference failure restored into attach history.
    /// Never enters model-bound rehydration context.
    InferenceError {
        /// `session_events.seq` of this inference-failure timeline row.
        #[serde(default)]
        seq: i64,
        summary: String,
        #[serde(default)]
        detail: String,
    },
    CompactBoundary {
        /// `session_events.seq` of this compaction timeline row.
        #[serde(default)]
        seq: i64,
        predecessor_short_id: String,
        seed_tool_count: usize,
        seed_tool_tokens: u64,
        #[serde(default)]
        source: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trigger_ctx_pct: Option<f64>,
        #[serde(default)]
        tokens_before: u64,
        #[serde(default)]
        tokens_after: u64,
        #[serde(default)]
        turns_summarized: usize,
        #[serde(default)]
        tail_kept: usize,
        #[serde(default)]
        tail_trimmed: usize,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        brief: Option<String>,
        /// Exact handoff (brief + deterministic appendix) installed on wire.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff: Option<String>,
    },
    Subagent {
        /// `session_events.seq` of this subagent-spawn timeline row.
        #[serde(default)]
        seq: i64,
        parent: String,
        child: String,
        task_call_id: String,
        label: String,
    },
}

/// One session's live in-daemon status, from the per-session
/// `ScheduleAuthority` + worker turn-state. Drives the browser's tiers 1-2
/// (GOALS §17f). Only emitted for sessions with a live worker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveStatus {
    pub session_id: Uuid,
    /// At least one loop/timer/background job is live.
    pub has_active_schedules: bool,
    /// A turn is in flight (between `ThinkingStarted` and `AgentIdle`).
    pub processing: bool,
    /// v10-only: the session's canonical project root, so a `cockpit run
    /// --session <id>` client can validate it matches `--cwd`/`--project`
    /// before attaching. Absent for v9 clients (the field is a v10
    /// extension on the existing v9 `session_live_status` response tag).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project_root: Option<String>,
}

#[allow(unused_imports)]
pub use cockpit_config::{
    config::extended::ApprovalMode,
    config::providers::{ActiveModelRef, PromptCacheRetention, ThinkingMode},
    config::sandbox_mode::SandboxMode,
};

#[allow(unused_imports)]
pub use cockpit_db::wire::{
    CharSpan, CommandDetail, GrantKind, ImageBudgetDisposition, ImagePlanReview, InterruptDecision,
    InterruptDecisionLine, InterruptOption, InterruptQuestion, InterruptQuestionSet, MessageRole,
    ResolveResponse, SandboxDenialConfidence, SandboxDenialEvidence, SandboxDenialReport,
    SandboxEscalation, SessionActivityState, SessionMessage, SessionSummary, WriteContentPreview,
};

pub use cockpit_db::db::session_goals::{
    GoalContract, GoalDisposition, GoalLifecycleHistoryEntry, GoalPauseReason, GoalPhase,
};
pub use cockpit_db::stats::{
    HardFailShapeRow, LanguageRow, LanguageSection, NonFileRow, PriceTable, RecoveryRow,
    RecoverySection, RecoveryStageRow, RecoveryToolRow, StatsRollup, StatsScope, TokenRow,
    TokenSpend,
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GoalSummary {
    pub id: Uuid,
    pub session_id: Uuid,
    pub project_id: String,
    pub objective: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub disposition: GoalDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<GoalPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_phase: Option<GoalPhase>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause_reason: Option<GoalPauseReason>,
    pub contract_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_gap_or_blocker: Option<String>,
    pub verification_attempts: i64,
    /// Inclusive configured cap for started verification panels.
    pub max_verification_attempts: u64,
    pub attempt_generation: i64,
    pub token_budget: i64,
    pub tokens_used: i64,
    pub remaining_tokens: i64,
    /// Wall-clock milliseconds spent in the running disposition.
    pub elapsed_active_ms: i64,
    /// Bounded, oldest-to-newest durable lifecycle audit trail.
    #[serde(default)]
    pub lifecycle_history: Vec<GoalLifecycleHistoryEntry>,
    pub blocked_attempts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_read_at: Option<i64>,
    pub created_at: i64,
    pub updated_at: i64,
}

fn deserialize_present_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantSummary {
    pub name: String,
    pub created_at: i64,
    pub home_dir: String,
    pub config_json: String,
    /// Vault-keyed identity of the already-redacted definition presentation.
    /// It is opaque to clients and cannot be used as an offline markdown
    /// guessing oracle.
    #[serde(deserialize_with = "deserialize_present_option")]
    pub definition_presentation_hash: Option<String>,
    /// Opaque CAS token for the raw registry binding itself. It is request-bound
    /// through projection and consumed-revision receipts and is deliberately
    /// not recomputable from this potentially redacted summary.
    pub registration_revision: String,
    /// Daemon-read exact authored definition; absent when the registered file
    /// cannot be safely opened or parsed.
    #[serde(deserialize_with = "deserialize_present_option")]
    pub definition_markdown: Option<String>,
    /// Opaque CAS token for the raw definition authority. Clients validate its
    /// format and receipt binding, not equality to redacted presentation bytes.
    #[serde(deserialize_with = "deserialize_present_option")]
    pub definition_revision: Option<String>,
    #[serde(deserialize_with = "deserialize_present_option")]
    pub definition_diagnostic: Option<String>,
    /// Vault-keyed identity over the exact already-redacted presentation.
    pub projection_digest: String,
}

/// Validate the self-contained invariants of a daemon assistant snapshot.
/// Parsing the agent markdown remains an application-layer responsibility,
/// but every client can enforce revision/diagnostic coherence and the exact
/// redacted presentation digest without depending on `cockpit-core`.
pub fn validate_assistant_summary(summary: &AssistantSummary) -> Result<(), &'static str> {
    fn lower_hex_digest(value: &str) -> bool {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    }
    if summary.name.is_empty()
        || summary.name.len() > MAX_AGENT_NAME_BYTES
        || summary.home_dir.len() > MAX_ASSISTANT_HOME_BYTES
        || summary.config_json.len() > MAX_ASSISTANT_CONFIG_BYTES
        || !lower_hex_digest(&summary.registration_revision)
    {
        return Err("assistant summary has no name or registration revision");
    }
    if !serde_json::from_str::<serde_json::Value>(&summary.config_json)
        .is_ok_and(|value| value.is_object())
    {
        return Err("assistant config projection is not a JSON object");
    }
    if summary
        .definition_markdown
        .as_ref()
        .is_some_and(|value| value.len() > MAX_AGENT_MARKDOWN_BYTES)
        || summary
            .definition_diagnostic
            .as_ref()
            .is_some_and(|value| value.is_empty() || value.len() > MAX_ASSISTANT_DIAGNOSTIC_BYTES)
        || summary
            .definition_presentation_hash
            .as_deref()
            .is_some_and(|value| !lower_hex_digest(value))
    {
        return Err("assistant definition projection exceeds its wire bounds");
    }
    match (
        summary.definition_markdown.as_deref(),
        summary.definition_revision.as_deref(),
        summary.definition_diagnostic.as_deref(),
    ) {
        (Some(_), Some(revision), None)
            if lower_hex_digest(revision) && summary.definition_presentation_hash.is_some() => {}
        (None, None, Some(diagnostic))
            if !diagnostic.trim().is_empty() && summary.definition_presentation_hash.is_none() => {}
        _ => return Err("assistant definition snapshot is incoherent"),
    }
    // Both identities are vault-keyed and intentionally unrecomputable by a
    // client. Their opaque shape and response/receipt binding are the public
    // contract.
    if !lower_hex_digest(&summary.projection_digest) {
        return Err("assistant projection identity is invalid");
    }
    Ok(())
}

/// Lowercase hex-encode a byte slice without relying on `hybrid-array`'s
/// `LowerHex` impl (absent in `sha2` 0.11).
pub(crate) fn hex_lower(bytes: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    let bytes = bytes.as_ref();
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut out, "{byte:02x}").expect("writing to String cannot fail");
    }
    out
}

#[doc(hidden)]
pub fn assistant_projection_material(summary: &AssistantSummary) -> String {
    use sha2::Digest as _;
    let mut digest = sha2::Sha256::new();
    digest.update(b"cockpit-assistant-projection-v1\0");
    digest.update(summary.created_at.to_le_bytes());
    for value in [
        Some(summary.name.as_str()),
        Some(summary.home_dir.as_str()),
        Some(summary.config_json.as_str()),
        summary.definition_presentation_hash.as_deref(),
        Some(summary.registration_revision.as_str()),
        summary.definition_markdown.as_deref(),
        summary.definition_revision.as_deref(),
        summary.definition_diagnostic.as_deref(),
    ] {
        match value {
            Some(value) => {
                digest.update([1]);
                assistant_revision_field(&mut digest, value);
            }
            None => digest.update([0]),
        }
    }
    hex_lower(digest.finalize())
}

fn assistant_revision_field(digest: &mut sha2::Sha256, value: &str) {
    use sha2::Digest as _;
    digest.update((value.len() as u64).to_le_bytes());
    digest.update(value.as_bytes());
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinnedMessage {
    pub seq: i64,
    pub is_assistant: bool,
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PinState {
    pub count: i64,
    pub seqs: Vec<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectNote {
    pub id: Uuid,
    pub project_root: String,
    pub name: String,
    pub content: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceTrustMode {
    Trust,
    IgnoreConfig,
    Untrusted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgSyncDisclosure {
    pub org_id: String,
    pub cursor_seq: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_at_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorDisclosure {
    pub enabled: bool,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Secret-free outcome of a daemon-owned organization policy synchronization.
/// The daemon retains the credential and performs all network/SQLite work;
/// only the policy state needed by the CLI enrollment prompt crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlycockpitOrgSyncOutcome {
    NoCredential,
    Disabled,
    EnrollmentRequired { org_id: String },
    Idle,
    Filtered { cursor_seq: i64 },
    Uploaded { events: usize, cursor_seq: i64 },
    Revoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppFlagKey {
    DaemonAutostartNotice,
    StorageManagementHint,
}

/// A daemon-owned storage bucket. Bytes are measured on disk, never estimated
/// from database row counts, so the settings surface can explain the actual
/// local footprint before proposing a cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageCategory {
    Ledger,
    SessionsByAge,
    WorkspaceScratch,
    LocalConfigs,
    Worktrees,
    TaskArtifacts,
    ComputerCapture,
    ResultBlobs,
    SessionShims,
    SessionTmp,
}

/// One category in the daemon's local storage report. `reclaimable_bytes`
/// measures data that an available user-confirmed cleanup can release; it is
/// accounting only and never deletion authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCategoryUsage {
    pub category: StorageCategory,
    pub total_bytes: u64,
    pub reclaimable_bytes: u64,
}

/// A filesystem item in a dry-run cleanup preview. Paths are daemon-generated
/// display values; callers never send filesystem paths back as deletion
/// authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCleanupItem {
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<Uuid>,
    pub bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at_unix_ms: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "data")]
pub enum StorageCleanupTarget {
    ArchiveSessionsOlderThan {
        age_days: u32,
        include_renamed_or_pinned: bool,
    },
    PermanentlyDeleteSessions {
        session_ids: Vec<Uuid>,
    },
    PermanentlyDeleteArchivedSessionsOlderThan {
        age_days: u32,
        include_renamed_or_pinned: bool,
    },
    RemoveOrphanedWorkspaceStorage {
        project_ids: Vec<String>,
    },
}

/// A daemon-generated, single-use cleanup plan. The caller must present its
/// `preview_id` to execute; arbitrary paths and byte counts are never trusted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageCleanupPreview {
    pub preview_id: Uuid,
    pub target: StorageCleanupTarget,
    pub items: Vec<StorageCleanupItem>,
    pub bytes_to_free: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistantSessionResolutionMode {
    MostRecentOrCreate,
}

#[cfg(test)]
mod tui_ownership_rpc_contract_tests {
    use super::*;

    #[test]
    fn missing_rpc_protocol_contract_rejects_open_ended_policy_values() {
        assert!(serde_json::from_str::<WorkspaceTrustMode>(r#""future-mode""#).is_err());
        assert!(
            serde_json::from_str::<AssistantSessionResolutionMode>(r#""create-always""#).is_err()
        );
    }

    #[test]
    fn missing_rpc_protocol_contract_has_exact_request_fields() {
        let trust = serde_json::to_value(Request::SetWorkspaceTrust {
            project_root: "/workspace".into(),
            mode: WorkspaceTrustMode::IgnoreConfig,
            expected_config_generation: 9,
        })
        .unwrap();
        assert_eq!(trust["request"], "set_workspace_trust");
        assert_eq!(trust["params"]["project_root"], "/workspace");
        assert_eq!(trust["params"]["mode"], "ignore_config");
        assert_eq!(trust["params"]["expected_config_generation"], 9);

        let get_trust = serde_json::to_value(Request::GetWorkspaceTrust {
            project_root: "/workspace".into(),
        })
        .unwrap();
        assert_eq!(get_trust["request"], "get_workspace_trust");
        assert_eq!(get_trust["params"]["project_root"], "/workspace");

        let assistant = serde_json::to_value(Request::ResolveAssistantSession {
            assistant_id: "helper".into(),
            project_root: "/workspace".into(),
            mode: AssistantSessionResolutionMode::MostRecentOrCreate,
        })
        .unwrap();
        assert_eq!(assistant["params"]["assistant_id"], "helper");
        assert_eq!(assistant["params"]["mode"], "most_recent_or_create");
    }
}

/// The maximum sealed-value plaintext literal carried on one sensitive wire
/// frame, in bytes. Mirrors
/// `cockpit_core::sealed::owner::MAX_SENSITIVE_FRAME_BYTES`; a larger literal
/// fails closed on deserialize before it reaches any handler.
pub const MAX_SENSITIVE_FRAME_BYTES: usize = 16 * 1024;

/// A secret-bearing JSON/string payload transported over the owner wire.
///
/// The serialized shape remains a JSON string, while the in-memory buffer is
/// zeroized on drop and `Debug` never exposes its contents. Field-specific
/// deserializers remain responsible for their tighter size/shape bounds.
#[derive(Clone, PartialEq, Eq)]
pub struct SensitiveWirePayload(zeroize::Zeroizing<String>);

impl SensitiveWirePayload {
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_zeroizing(self) -> zeroize::Zeroizing<String> {
        self.0
    }
}

impl From<String> for SensitiveWirePayload {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<&str> for SensitiveWirePayload {
    fn from(value: &str) -> Self {
        Self::new(value.to_owned())
    }
}

impl std::ops::Deref for SensitiveWirePayload {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl fmt::Debug for SensitiveWirePayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SensitiveWirePayload([REDACTED; {} bytes])",
            self.0.len()
        )
    }
}

impl Serialize for SensitiveWirePayload {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for SensitiveWirePayload {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self::new)
    }
}

#[cfg(feature = "remote")]
impl crate::remote_operation_fcor::CanonicalFcorValueV1 for SensitiveWirePayload {
    fn encode_fcor_value_v1(
        &self,
        out: &mut crate::remote_operation_fcor::CanonicalParamsV1,
    ) -> Result<()> {
        use sha2::Digest as _;

        // Preserve replay identity without copying plaintext into FCOR's
        // ordinary byte buffer. A different secret payload produces a
        // different operation digest; only this one-way digest leaves the
        // zeroizing wrapper.
        let digest = sha2::Sha256::digest(self.as_str().as_bytes());
        out.push_bytes(digest.as_slice())
    }
}

/// Opaque one-use token for the local leak-reveal channel.
///
/// Although this is not the revealed plaintext, possession authorizes a
/// plaintext read. It therefore has the same memory/logging discipline as a
/// secret: zeroizing storage, redacted `Debug`, and no conversion API that
/// produces an ordinary `String` copy.
#[derive(Clone, PartialEq, Eq)]
pub struct LeakRevealToken(zeroize::Zeroizing<String>);

impl LeakRevealToken {
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    pub fn from_zeroizing(value: zeroize::Zeroizing<String>) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_zeroizing(self) -> zeroize::Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for LeakRevealToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "LeakRevealToken([REDACTED; {} bytes])",
            self.0.len()
        )
    }
}

impl Serialize for LeakRevealToken {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for LeakRevealToken {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        // Historical response fixtures used an empty placeholder before the
        // live v16 contract required canonical tokens. Keep deserialization
        // bounded and zeroizing; live request semantics and the reveal frame
        // enforce the exact 64-byte lowercase-hex shape.
        if value.len() > 64 {
            return Err(serde::de::Error::custom(
                "leak reveal token exceeds 64 bytes",
            ));
        }
        Ok(Self(zeroize::Zeroizing::new(value)))
    }
}

#[cfg(feature = "remote")]
impl crate::remote_operation_fcor::CanonicalFcorValueV1 for LeakRevealToken {
    fn encode_fcor_value_v1(
        &self,
        out: &mut crate::remote_operation_fcor::CanonicalParamsV1,
    ) -> Result<()> {
        // CancelLeakReveal is local-only, but the command registry still
        // verifies every parameter has a closed canonical codec. Never copy a
        // bearer token into the ordinary FCOR byte buffer.
        out.push_bytes(b"[leak-reveal-token-redacted]")
    }
}

/// A sealed-value plaintext literal on the sensitive owner channel.
///
/// It rides exactly two wire frames and nowhere else: the apply request
/// (owner → daemon) for create/replace/rotate, and the recover-apply success
/// response (daemon → owner). It never appears on inventory, begin, cancel,
/// edit-description, action-admin, or error payloads. The newtype:
///
/// * **redacts** its own `Debug` (prints only a byte length, never the
///   plaintext) — so a `{:?}` of any enclosing `Request`/`Response` is
///   secret-free by construction;
/// * **zeroizes** its backing buffer on drop; and
/// * is **bounded** by [`MAX_SENSITIVE_FRAME_BYTES`] on deserialize — a larger
///   frame fails closed at the single wire construction funnel, before any
///   handler runs.
#[derive(Clone)]
pub struct SensitiveWireLiteral(zeroize::Zeroizing<String>);

impl SensitiveWireLiteral {
    /// Wrap an in-process literal. In-process requests bypass deserialization,
    /// so callers must independently honor [`MAX_SENSITIVE_FRAME_BYTES`]
    /// (`Request::validate_semantics` enforces it before dispatch).
    pub fn new(value: String) -> Self {
        Self(zeroize::Zeroizing::new(value))
    }

    /// Wrap an already-zeroizing literal by moving it, with no intermediate
    /// plaintext copy. The recover reveal path resolves the literal into a
    /// [`zeroize::Zeroizing`] buffer and hands it straight to the wire type this
    /// way, so the plaintext never lands in a non-zeroizing `String`.
    pub fn from_zeroizing(value: zeroize::Zeroizing<String>) -> Self {
        Self(value)
    }

    /// The plaintext, borrowed. Never log this.
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// The plaintext byte length. Safe to log.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the literal is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Move the plaintext out inside a zeroizing buffer, with no intermediate
    /// plaintext copy.
    pub fn into_zeroizing(self) -> zeroize::Zeroizing<String> {
        self.0
    }
}

impl fmt::Debug for SensitiveWireLiteral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SensitiveWireLiteral([REDACTED; {} bytes])",
            self.0.len()
        )
    }
}

impl Serialize for SensitiveWireLiteral {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for SensitiveWireLiteral {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        if value.len() > MAX_SENSITIVE_FRAME_BYTES {
            return Err(serde::de::Error::custom(format!(
                "sensitive frame literal exceeds {MAX_SENSITIVE_FRAME_BYTES} bytes"
            )));
        }
        Ok(Self(zeroize::Zeroizing::new(value)))
    }
}

/// A fixed, content-free placeholder canonicalized in place of a sealed-value
/// literal. It carries no plaintext and no length, so the sealed plaintext never
/// enters the (non-zeroizing) FCOR canonical digest buffer, its staging buffers,
/// or the bytes handed to the hasher.
#[cfg(feature = "remote")]
const SEALED_LITERAL_FCOR_PLACEHOLDER: &[u8] = b"[sealed-literal-redacted-from-fcor]";

// The apply request is an owner-remoted nonrepeatable mutation, so its params
// are canonicalized for the remote-operation key. Unlike `put_named_secret`
// (whose `value` IS the operation's identity), the apply's replay/dedup identity
// is the single-use `capability_id` + the atomic CAS, so the literal is
// redundant in the FCOR key. We therefore deliberately EXCLUDE the plaintext
// from canonicalization — encoding only a fixed placeholder — so the sealed
// plaintext is never copied into the plain `Vec<u8>` canonical buffer (which
// frees without zeroizing). This keeps the zeroization guarantee intact end to
// end; the redacted disposition is reflected in the `option<redacted>` canonical
// codec (see `canonical_fcor_codec_for_rust_type`).
#[cfg(feature = "remote")]
impl crate::remote_operation_fcor::CanonicalFcorValueV1 for SensitiveWireLiteral {
    fn encode_fcor_value_v1(
        &self,
        out: &mut crate::remote_operation_fcor::CanonicalParamsV1,
    ) -> Result<()> {
        out.push_bytes(SEALED_LITERAL_FCOR_PLACEHOLDER)
    }
}

/// The safe scope kind of a sealed value, for the sealed-owner begin and
/// inventory wire shapes. Carries no key material; the key is a separate
/// `scope_key` field (a session id or canonical project key).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SealedOwnerScopeKind {
    Session,
    Project,
    Global,
}

/// One safe row of the sealed-owner inventory. The plaintext literal is
/// deliberately absent from this wire type; a recover apply is the only path
/// that reveals a literal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedOwnerInventoryItem {
    pub record_id: String,
    pub name: String,
    pub description: String,
    pub scope_kind: SealedOwnerScopeKind,
    pub scope_key: String,
    pub active_version: u32,
    pub created_at_ms: i64,
}

/// Safe metadata for one sealed action instance. Carries no origin allowlist,
/// path template, credential placement, or projection blob — only the owner
/// inventory projection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SealedActionSummaryWire {
    pub action_id: String,
    pub revision: u32,
    pub enabled: bool,
    pub description: String,
    pub project_key: String,
}

/// Maximum rows carried in one `SealedOwnerInventory` / `SealedActions`
/// response. Each row is bounded metadata (a 64-scalar name and a 512-scalar
/// description at most), so this cap keeps the worst-case frame well under the
/// `BoundedRequestResponse` 512 KiB ceiling. The daemon directory funnel clamps
/// to this via [`Response::sealed_owner_inventory`] /
/// [`Response::sealed_actions`], making the `Bounded` classification honest by
/// construction.
pub const MAX_SEALED_OWNER_INVENTORY_ROWS: usize = 128;

/// The closed rotation plan proposed for a leak record. Derived from the
/// closed report `source`, `category`, and connector ID enums only; the Owner
/// never enters arbitrary plan text.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LeakRotationPlan {
    RevokeConnectorCredential,
    RotateNamedSecret,
    InvalidateSession,
    OwnerReviewRequired,
}

/// The rotation disposition the Owner may set on a leak record. Metadata-only
/// and reversible; a fresh re-report clears it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LeakRotationDisposition {
    Accept,
    Dismiss,
    Rotated,
}

/// The rotation-state filter for `ListLeakReports`. A closed enum mirroring the
/// stored rotation disposition, used to narrow the machine-wide list to one
/// rotation state (and bound into the list cursor MAC). Distinct from
/// [`LeakRotationDisposition`], which is the *action* the Owner takes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum LeakRotationState {
    None,
    PendingUser,
    Rotated,
    NotApplicable,
}

/// One safe metadata-only leak report row. Contains no plaintext, ciphertext,
/// masked prefix, length-derived identity, or keyed fingerprint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeakReportMetadata {
    pub report_id: String,
    pub session_id: Uuid,
    pub source: String,
    pub category: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connector_id: Option<String>,
    pub status: String,
    pub rotation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_plan: Option<LeakRotationPlan>,
    pub seen_count: i64,
    pub first_reported_ms: i64,
    pub last_reported_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contained_at_ms: Option<i64>,
}

/// A page of leak report metadata. Never carries plaintext.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeakReportsPage {
    pub reports: Vec<LeakReportMetadata>,
    /// Opaque cursor for the next page; `None` if this was the last page.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    pub has_more: bool,
}

/// A fresh one-use capability minted by BeginLeakReveal and bound to exactly
/// one report id. Secret-free.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LeakRevealCapability {
    /// The opaque capability token; never derived from the secret.
    pub capability: LeakRevealToken,
    /// The single report id this capability is bound to.
    pub report_id: String,
    /// When this capability expires (unix ms). A reveal after this is
    /// rejected.
    pub expires_at_ms: i64,
}

#[cfg(test)]
mod sensitive_wire_literal_tests {
    use super::*;

    #[test]
    fn sensitive_wire_literal_debug_redacts_the_plaintext() {
        let marker = "PLAINTEXT-MARKER-must-not-print";
        let literal = SensitiveWireLiteral::new(marker.to_string());
        let debug = format!("{literal:?}");
        assert!(
            !debug.contains(marker),
            "Debug of a sensitive literal must never print the plaintext: {debug}"
        );
        assert!(debug.contains("REDACTED"));
        // The plaintext is still available through the explicit accessor.
        assert_eq!(literal.as_str(), marker);
    }

    #[test]
    fn sensitive_wire_literal_serializes_as_a_plain_string() {
        let literal = SensitiveWireLiteral::new("s3cr3t".to_string());
        assert_eq!(serde_json::to_string(&literal).unwrap(), "\"s3cr3t\"");
        let back: SensitiveWireLiteral = serde_json::from_str("\"s3cr3t\"").unwrap();
        assert_eq!(back.as_str(), "s3cr3t");
    }

    #[test]
    fn leak_reveal_token_redacts_debug_and_keeps_zeroizing_ownership() {
        let marker = "0123456789abcdef".repeat(4);
        let token = LeakRevealToken::new(marker.clone());
        let debug = format!("{token:?}");
        assert!(!debug.contains(&marker));
        assert!(debug.contains("REDACTED"));
        let owned = token.into_zeroizing();
        assert_eq!(owned.as_str(), marker);
    }

    #[test]
    fn sensitive_wire_literal_over_the_bound_fails_closed_on_deserialize() {
        let oversized = "x".repeat(MAX_SENSITIVE_FRAME_BYTES + 1);
        let json = serde_json::to_string(&oversized).unwrap();
        let parsed: std::result::Result<SensitiveWireLiteral, _> = serde_json::from_str(&json);
        assert!(
            parsed.is_err(),
            "a literal larger than MAX_SENSITIVE_FRAME_BYTES must be rejected at deserialize"
        );
        // The exact-bound literal is accepted.
        let at_bound = "y".repeat(MAX_SENSITIVE_FRAME_BYTES);
        let json = serde_json::to_string(&at_bound).unwrap();
        let parsed: SensitiveWireLiteral = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), MAX_SENSITIVE_FRAME_BYTES);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssistantSessionCreated {
    pub session_id: Uuid,
    pub short_id: String,
    pub project_root: String,
    pub project_id: String,
    pub assistant_name: String,
    pub active_agent: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportSessionKind {
    TranscriptJson,
    DebugBundle,
}

/// Export metadata plus a bounded reference to the exported bytes.
///
/// The bytes themselves never ride an application frame: they travel as a
/// bulk-lane begin/chunk/complete transfer, and `transfer` names it. This is
/// what keeps a debug-bundle export from starving the control lane.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExportSessionData {
    pub session_id: Uuid,
    pub kind: ExportSessionKind,
    pub filename_extension: String,
    pub mime: String,
    /// Typed bulk transfer reference; carries the length and SHA-256 digest.
    pub transfer: bulk_transfer::BulkTransferRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_count: Option<usize>,
    #[serde(default)]
    pub redacted: bool,
}

impl ExportSessionData {
    /// Length of the exported payload, from the transfer reference.
    pub fn byte_len(&self) -> u64 {
        self.transfer.total_length_value()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum CuratorAction {
    Status,
    Run {
        #[serde(default)]
        dry_run: bool,
        #[serde(default)]
        consolidate: bool,
    },
    Pin {
        name: String,
    },
    Unpin {
        name: String,
    },
    Restore {
        name: String,
    },
    Rollback {
        #[serde(default)]
        list: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CuratorResult {
    Status {
        status: CuratorStatus,
    },
    Run {
        report: CuratorRunReport,
    },
    Pinned {
        name: String,
        pinned: bool,
    },
    Restored {
        name: String,
    },
    Snapshots {
        snapshots: Vec<CuratorSnapshotStatus>,
    },
    RolledBack {
        snapshot: CuratorSnapshotStatus,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorRunReport {
    pub dry_run: bool,
    pub scanned: usize,
    pub stale: Vec<String>,
    pub archived: Vec<String>,
    pub reactivated: Vec<String>,
    pub skipped: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consolidation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorStatus {
    pub skills: Vec<CuratorSkillStatus>,
    pub snapshots: Vec<CuratorSnapshotStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorSkillStatus {
    pub name: String,
    pub state: String,
    pub created_by: String,
    pub use_count: u64,
    pub view_count: u64,
    pub pinned: bool,
    pub source_path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub archive_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CuratorSnapshotStatus {
    pub id: String,
    pub path: String,
    pub reason: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StatsRange {
    Last7Days,
    AllTime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PausedWorkSummary {
    pub session_id: Uuid,
    pub active_agent: String,
    pub project_root: String,
    pub reason: String,
    pub pending_tool_count: i64,
    pub daemon_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ActiveSubagent {
    pub parent: String,
    pub child: String,
    pub task_call_id: String,
    pub label: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueDeliveryClass {
    /// Delivered at the focused agent's next turn boundary (mid-run).
    #[default]
    Steering,
    /// Delivered after the run completes.
    Held,
}

impl QueueDeliveryClass {
    pub fn from_steering_setting(queued_messages_as_steering: bool) -> Self {
        if queued_messages_as_steering {
            Self::Steering
        } else {
            Self::Held
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Steering => Self::Held,
            Self::Held => Self::Steering,
        }
    }

    pub fn is_steering(self) -> bool {
        matches!(self, Self::Steering)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueItem {
    pub id: Uuid,
    pub status: QueueItemStatus,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
    #[serde(default)]
    pub target: QueueTarget,
    /// Per-message delivery class. Defaults to steering so older wire
    /// snapshots and struct literals stay valid; enqueue overwrites this
    /// from `queuedMessagesAsSteering`.
    #[serde(default)]
    pub delivery_class: QueueDeliveryClass,
    /// True after the item has been escalated for the next safe boundary.
    /// This is projected on the wire because it changes both delivery and
    /// visual order; it is not a third persisted delivery class.
    #[serde(default)]
    pub send_now: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueItemReplacement {
    /// Stable identity for the complete reserve/commit/release lifecycle.
    /// Retrying any phase with this id is idempotent.
    pub operation_id: Uuid,
    pub action: QueueEditAction,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
    #[serde(default)]
    pub tag_expansions: Vec<TagExpansionMeta>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QueueEditAction {
    Reserve,
    Commit,
    Release,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagExpansionMeta {
    pub tool: String,
    pub path: String,
    pub detail: String,
    pub ok: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueueTarget {
    pub id: String,
    pub agent: String,
    pub depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_call_id: Option<String>,
}

impl Default for QueueTarget {
    fn default() -> Self {
        Self::root("")
    }
}

impl QueueTarget {
    pub fn root(agent: impl Into<String>) -> Self {
        Self {
            id: "root".to_string(),
            agent: agent.into(),
            depth: 0,
            task_call_id: None,
        }
    }

    pub fn child(
        agent: impl Into<String>,
        depth: usize,
        task_call_id: impl Into<String>,
        label: impl AsRef<str>,
    ) -> Self {
        let task_call_id = task_call_id.into();
        Self {
            id: format!("task:{task_call_id}:{}", label.as_ref()),
            agent: agent.into(),
            depth,
            task_call_id: Some(task_call_id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueItemStatus {
    Queued,
    Folding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoveQueuedUserMessageReason {
    Removed,
    AlreadyStarted,
    NotFound,
    /// Another edit lifecycle owns the item, or the supplied edit operation
    /// does not own the active lease.
    EditConflict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveQueuedUserMessageResult {
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_item: Option<QueueItem>,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoveQueuedUserMessagesResult {
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    pub removed_items: Vec<QueueItem>,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetQueuedUserMessageClassResult {
    pub queue_item_id: Uuid,
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit_operation_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub edit_action: Option<QueueEditAction>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<QueueItem>,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromoteQueuedUserMessagesResult {
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendNowQueuedUserMessageResult {
    pub applied: bool,
    pub reason: RemoveQueuedUserMessageReason,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item: Option<QueueItem>,
    pub queue: Vec<QueueItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SkillSummary {
    pub name: String,
    pub description: String,
    pub source: String,
    pub user_invocable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSummary {
    pub name: String,
    pub description: String,
    pub mode: String,
    pub source: String,
    /// `true` for the built-in cast (`Build`, `builder`,
    /// `explore`, …).
    pub builtin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSummary {
    pub provider: String,
    pub id: String,
    pub display_name: Option<String>,
    pub favorite: bool,
    /// Daemon-resolved trust for the picker; never credentials.
    pub trust: cockpit_config::config::providers::ModelTrust,
    /// Reasoning-effort capability projection for the picker, already
    /// restricted for native-provider validity (e.g. Anthropic native).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<cockpit_config::config::providers::ReasoningEffortCapability>,
    /// Thinking modes the picker may offer for this model. Empty for
    /// native Anthropic (no free-form thinking modes on that wire).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub thinking_modes: Vec<cockpit_config::config::providers::ThinkingMode>,
    /// Whether availability policy permits selecting this model in the
    /// current inventory context.
    pub available: bool,
    /// False when the provider/model pair fails native-provider validation
    /// (for example Anthropic native with an invalid model configuration).
    pub native_provider_valid: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InterruptRaiseReason {
    Initial,
    Advance,
    Rehydration,
}

/// Return the first protocol version that can carry a typed body. This gate
/// is intentionally applied after negotiation and before serialization: a
/// A compatibility-window client must never serialize a newer RPC with an
/// older envelope and leave an older daemon to interpret it.
fn body_required_protocol_version(body: &Body) -> (u32, &'static str) {
    match body {
        Body::Request { request, .. } => {
            let tag = request.wire_tag();
            let version = match tag {
                "begin_provider_oauth"
                | "complete_provider_oauth"
                | "cancel_provider_oauth"
                | "begin_mcp_oauth"
                | "complete_mcp_oauth"
                | "cancel_mcp_oauth"
                | "put_provider_credential"
                | "delete_provider_credential"
                | "save_mcp_config"
                | "apply_extended_config_patch"
                | "get_local_operation_settlement"
                | "setup_copilot_auth"
                | "put_subscription_ack"
                | "apply_provider_mutation"
                | "save_image_spend_policy"
                | "begin_agent_editor_lease"
                | "complete_agent_editor_lease"
                | "get_agent_editor_lease_settlement" => 17,
                "mutate_agent" | "save_assistant_definition" | "delete_assistant" => 17,
                "cancel_leak_reveal" => 16,
                "get_provider_catalog_snapshot" => 15,
                "list_secret_inventory"
                | "put_named_secret"
                | "delete_named_secret"
                | "get_flycockpit_account"
                | "set_flycockpit_connector_enabled"
                | "sync_flycockpit_org_policy"
                | "enroll_flycockpit_org_sync"
                | "fetch_provider_models"
                | "get_provider_usage_snapshot"
                | "upsert_provider_config"
                | "delete_provider_config"
                | "set_provider_layer_metadata"
                | "save_provider_config"
                | "apply_setup_wizard"
                | "get_agent_inventory"
                | "get_agent_edit_snapshot"
                | "get_extended_config_snapshot"
                | "get_image_sidecar_authority_snapshot"
                | "create_image_sidecar_grant"
                | "revoke_image_sidecar_grant"
                | "save_extended_config"
                | "export_policy"
                | "import_policy"
                | "get_image_spend_policy"
                | "list_packages"
                | "add_package"
                | "import_package"
                | "prune_packages"
                | "import_kcl_packages"
                | "get_connector_state"
                | "get_org_sync_status"
                | "list_failed_tool_calls"
                | "get_session_compactions"
                | "purge_ended_sessions"
                | "get_assistant"
                | "diagnose_media_reservation"
                | "repair_media_reservation"
                | "get_doctor_snapshot"
                | "docs_ask"
                | "agent_installation_begin"
                | "agent_installation_submit_choice"
                | "agent_installation_list"
                | "agent_installation_inspect"
                // The reclassified session export now returns the v10-only
                // `redacted_export` bulk kind and requires the v10-only
                // `ReadRedactedExportChunk` reader, so the WHOLE tag is v10: a v9
                // peer is refused rather than handed an enum value it cannot
                // decode / a transfer it cannot read.
                | "export_session_data"
                | "read_redacted_export_chunk"
                | "begin_sealed_owner_operation"
                | "apply_sealed_owner_operation"
                | "cancel_sealed_owner_operation"
                | "sealed_owner_inventory"
                | "edit_sealed_owner_description"
                | "list_sealed_actions"
                | "create_sealed_action"
                | "revise_sealed_action_description"
                | "revise_sealed_action_enabled"
                | "retire_sealed_action" => 10,
                _ => 9,
            };
            // Extended v10-only shapes on existing v9 tags: the base tag
            // remains v9-compatible, but the new optional field bumps the
            // required version when present so a v9 envelope carrying the
            // extended body is rejected by the gate.
            if version == 9
                && let Request::ListSessions {
                    assistant_id: Some(_),
                    ..
                } = request
            {
                return (10, tag);
            }
            (version, tag)
        }
        Body::Response { response, .. } => {
            let tag = response.wire_tag();
            let version = match tag {
                "provider_oauth_started"
                | "provider_oauth_completed"
                | "provider_oauth_cancelled"
                | "mcp_oauth_started"
                | "mcp_oauth_completed"
                | "mcp_oauth_cancelled"
                | "provider_credential_committed"
                | "subscription_ack_committed"
                | "local_operation_settlement"
                | "copilot_auth_committed"
                | "mcp_config_committed"
                | "provider_catalog_snapshot"
                | "provider_mutation_committed"
                | "image_spend_policy_saved"
                | "agent_editor_lease_begun"
                | "agent_editor_lease_completed"
                | "extended_config_saved" => 17,
                "agent_mutated" | "assistant_definition_saved" | "assistant_deleted" => 17,
                "leak_reveal_cancelled" => 16,
                "flycockpit_org_sync"
                | "provider_models_fetched"
                | "provider_usage_snapshot"
                | "provider_config_upserted"
                | "secret_inventory"
                | "flycockpit_account"
                | "setup_wizard_applied"
                | "policy_exported"
                | "policy_imported"
                | "image_spend_policy"
                | "packages"
                | "package_added"
                | "package_imported"
                | "packages_pruned"
                | "kcl_packages_imported"
                | "connector_state"
                | "org_sync_status"
                | "failed_tool_calls"
                | "session_compactions"
                | "ended_sessions_purged"
                | "assistant"
                | "media_reservation_diagnosis"
                | "media_reservation_repaired"
                | "doctor_snapshot"
                | "docs_answer"
                | "agent_installation"
                | "sealed_owner_operation_begun"
                | "sealed_owner_operation_applied"
                | "sealed_owner_operation_cancelled"
                | "sealed_owner_inventory"
                | "sealed_owner_description_edited"
                | "sealed_actions"
                | "sealed_action_created"
                | "sealed_action_revised"
                | "sealed_action_retired"
                // The export response carries the v10-only `redacted_export`
                // bulk kind; refuse to hand a v9 peer a transfer reference it
                // cannot read back through the v10-only reader.
                | "export_session_data" => 10,
                _ => 9,
            };
            // Extended v10-only shapes on existing v9 response tags: the base
            // tag remains v9-compatible, but the new optional field bumps the
            // required version when present so a v9 envelope carrying the
            // extended body is rejected by the gate.
            if version == 9
                && let Response::SessionLiveStatus { statuses } = &**response
                && statuses.iter().any(|status| status.project_root.is_some())
            {
                return (10, tag);
            }
            (version, tag)
        }
        Body::Event { event } => (9, event.wire_tag()),
        Body::Error { .. } => (9, "unknown"),
        #[cfg(feature = "remote")]
        Body::RemoteReplayRequest(_)
        | Body::RemoteReplayResponse(_)
        | Body::RemoteReplayAck(_)
        | Body::RemoteReplayAckResponse(_) => (9, "unknown"),
        Body::Unknown => (9, "unknown"),
    }
}

fn ensure_body_supported(version: u32, body: &Body) -> Result<()> {
    let (required, tag) = body_required_protocol_version(body);
    if required > version {
        bail!(
            "protocol payload {tag:?} requires v{required}, but negotiated daemon protocol is v{version}; run `cockpit daemon restart`"
        );
    }
    Ok(())
}

// ---- Codec -----------------------------------------------------------------

/// NDJSON framed codec over an arbitrary byte stream. Use the same
/// type for both ends — the schema is symmetric, only the legal
/// `Body` variants differ per direction.
pub struct ProtoStream<S> {
    framed: Framed<S, LinesCodec>,
    version: u32,
}

impl<S> ProtoStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    pub fn new(stream: S) -> Self {
        Self::with_version(stream, PROTOCOL_VERSION)
    }

    pub fn with_version(stream: S, version: u32) -> Self {
        Self {
            framed: Framed::new(
                stream,
                LinesCodec::new_with_max_length(MAX_NDJSON_FRAME_BYTES),
            ),
            version,
        }
    }

    pub fn into_split(self) -> (ProtoReadHalf<ReadHalf<S>>, ProtoWriteHalf<WriteHalf<S>>) {
        let version = self.version;
        let (read, write) = tokio::io::split(self.framed.into_inner());
        (
            ProtoReadHalf {
                framed: FramedRead::new(
                    read,
                    LinesCodec::new_with_max_length(MAX_NDJSON_FRAME_BYTES),
                ),
            },
            ProtoWriteHalf {
                framed: FramedWrite::new(
                    write,
                    LinesCodec::new_with_max_length(MAX_NDJSON_FRAME_BYTES),
                ),
                version,
            },
        )
    }

    pub fn negotiated_version(&self) -> u32 {
        self.version
    }

    pub fn set_negotiated_version(&mut self, version: u32) {
        self.version = version;
    }

    /// Send one envelope. Serializes to a compact single-line JSON
    /// string and writes a trailing newline (`LinesCodec` adds the
    /// newline).
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let mut env = env.clone();
        env.v = self.version;
        ensure_body_supported(self.version, &env.body)?;
        let line = serde_json::to_string(&env).context("serializing envelope")?;
        self.framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing envelope")?;
        Ok(())
    }

    pub async fn send_raw_line(&mut self, line: String) -> Result<()> {
        self.framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing raw envelope")?;
        Ok(())
    }

    pub async fn recv(&mut self) -> Result<Option<RecvFrame>> {
        recv_frame(&mut self.framed).await
    }

    pub async fn recv_raw_line(&mut self) -> Result<Option<String>> {
        recv_raw_line(&mut self.framed).await
    }
}

pub struct ProtoReadHalf<R> {
    framed: FramedRead<R, LinesCodec>,
}

impl<R> ProtoReadHalf<R>
where
    R: AsyncRead + Unpin,
{
    /// Receive the next frame. Returns `Ok(None)` on clean EOF;
    /// returns `Err` on framing failure (frame too large, invalid UTF-8)
    /// or JSON/header deserialization failure.
    pub async fn recv(&mut self) -> Result<Option<RecvFrame>> {
        recv_frame(&mut self.framed).await
    }
}

pub struct ProtoWriteHalf<W> {
    framed: FramedWrite<W, LinesCodec>,
    version: u32,
}

impl<W> ProtoWriteHalf<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn set_negotiated_version(&mut self, version: u32) {
        self.version = version;
    }

    /// Send one envelope. Serializes to a compact single-line JSON
    /// string and writes a trailing newline (`LinesCodec` adds the
    /// newline).
    pub async fn send(&mut self, env: &Envelope) -> Result<()> {
        let mut env = env.clone();
        env.v = self.version;
        ensure_body_supported(self.version, &env.body)?;
        let line = serde_json::to_string(&env).context("serializing envelope")?;
        self.framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing envelope")?;
        Ok(())
    }

    pub async fn send_raw_line(&mut self, line: String) -> Result<()> {
        self.framed
            .send(line)
            .await
            .map_err(codec_error)
            .context("writing raw envelope")?;
        Ok(())
    }
}

async fn recv_raw_line<T>(framed: &mut T) -> Result<Option<String>>
where
    T: futures::Stream<Item = std::result::Result<String, LinesCodecError>> + Unpin,
{
    match framed.next().await {
        None => Ok(None),
        Some(Err(e)) => Err(codec_error(e)).context("reading envelope"),
        Some(Ok(line)) => Ok(Some(line)),
    }
}

async fn recv_frame<T>(framed: &mut T) -> Result<Option<RecvFrame>>
where
    T: futures::Stream<Item = std::result::Result<String, LinesCodecError>> + Unpin,
{
    match recv_raw_line(framed).await? {
        None => Ok(None),
        Some(line) => {
            let value: serde_json::Value =
                serde_json::from_str(&line).context("deserializing envelope")?;
            let v = value
                .get("v")
                .and_then(serde_json::Value::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .context("deserializing envelope: missing or invalid v")?;
            if !is_protocol_compatible(v) {
                let kind = value
                    .get("kind")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("")
                    .to_string();
                let id = value
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|raw| Uuid::parse_str(raw).ok());
                return Ok(Some(RecvFrame::VersionMismatch { v, kind, id }));
            }
            let kind = value
                .get("kind")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .to_string();
            let tag = unknown_variant_tag(&value);
            let id = value
                .get("id")
                .and_then(serde_json::Value::as_str)
                .and_then(|raw| Uuid::parse_str(raw).ok());
            if payload_tag_is_unknown(&kind, tag.as_deref()) {
                return Ok(Some(RecvFrame::Unknown { v, kind, tag, id }));
            }
            let env: Envelope = serde_json::from_value(value).context("deserializing envelope")?;
            if envelope_contains_unknown(&env) {
                return Ok(Some(RecvFrame::Unknown { v, kind, tag, id }));
            }
            // Negotiation permits a v10 peer to keep a v9 connection alive
            // for the frozen v9 surface.  Do not let a raw/skewed peer label a
            // v10-only body as v9 and bypass the corresponding send gate.
            if body_required_protocol_version(&env.body).0 > v {
                return Ok(Some(RecvFrame::VersionMismatch { v, kind, id }));
            }
            Ok(Some(RecvFrame::Envelope(Box::new(env))))
        }
    }
}

fn unknown_variant_tag(value: &serde_json::Value) -> Option<String> {
    for key in ["request", "response", "event"] {
        if let Some(tag) = value.get(key).and_then(serde_json::Value::as_str) {
            return Some(tag.to_string());
        }
    }
    if let Some(tag) = value
        .get("error")
        .and_then(|error| error.get("code"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(tag.to_string());
    }
    None
}

fn payload_tag_is_unknown(kind: &str, tag: Option<&str>) -> bool {
    let Some(tag) = tag else {
        return false;
    };
    match kind {
        "req" => serde_json::from_value::<Request>(json!({ "request": tag }))
            .is_ok_and(|request| matches!(request, Request::Unknown)),
        "res" => serde_json::from_value::<Response>(json!({ "response": tag }))
            .is_ok_and(|response| matches!(response, Response::Unknown)),
        "evt" => serde_json::from_value::<Event>(json!({ "event": tag }))
            .is_ok_and(|event| matches!(event, Event::Unknown)),
        "err" => serde_json::from_value::<ErrorCode>(json!(tag))
            .is_ok_and(|code| matches!(code, ErrorCode::Other(_))),
        _ => false,
    }
}

fn envelope_contains_unknown(env: &Envelope) -> bool {
    match &env.body {
        Body::Request { request, .. } => matches!(request, Request::Unknown),
        Body::Response { response, .. } => matches!(**response, Response::Unknown),
        Body::Event { event } => matches!(event, Event::Unknown),
        Body::Error { error, .. } => matches!(error.code, ErrorCode::Other(_)),
        #[cfg(feature = "remote")]
        Body::RemoteReplayRequest(_)
        | Body::RemoteReplayResponse(_)
        | Body::RemoteReplayAck(_)
        | Body::RemoteReplayAckResponse(_) => false,
        Body::Unknown => true,
    }
}

fn codec_error(err: LinesCodecError) -> io::Error {
    match err {
        LinesCodecError::Io(e) => e,
        LinesCodecError::MaxLineLengthExceeded => io::Error::new(
            io::ErrorKind::InvalidData,
            "NDJSON frame exceeded MAX_NDJSON_FRAME_BYTES",
        ),
    }
}

#[cfg(all(test, feature = "remote"))]
mod proto_fixture_tests {
    //! Protocol fixtures cover every version accepted by this build. When the
    //! supported range changes, add or remove the corresponding `vN/`
    //! directories together with `SUPPORTED_PROTOCOL_VERSIONS`.

    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use serde::Serialize;
    use serde::de::DeserializeOwned;
    use serde_json::{Map, Value};

    use super::*;

    const UNKNOWN_SENTINEL: &str = "__unknown";
    const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[21];
    const ARCHIVED_PROTOCOL_VERSIONS: &[u32] = &[12, 13, 14, 15, 16, 17, 18, 19, 20];
    const DAEMON_PROTO_FIXTURE_FILES: &[&str] = &["event.json", "request.json", "response.json"];

    #[test]
    fn proto_fixture_request_full_shapes_round_trip() {
        assert_enum_fixture::<Request>(
            "request",
            "request.json",
            fixture_expected_kinds(request_variant_tags()),
        );
    }

    #[test]
    fn proto_fixture_response_full_shapes_round_trip() {
        assert_enum_fixture::<Response>(
            "response",
            "response.json",
            fixture_expected_kinds(response_variant_tags()),
        );
    }

    #[test]
    fn proto_fixture_event_full_shapes_round_trip() {
        assert_enum_fixture::<Event>(
            "event",
            "event.json",
            fixture_expected_kinds(event_variant_tags()),
        );
    }

    #[test]
    fn wire_tag_matches_serde_tag_for_every_request_fixture() {
        assert_fixture_wire_tags::<Request>("request", "request.json", Request::wire_tag);
    }

    #[test]
    fn wire_tag_matches_serde_tag_for_every_response_fixture() {
        assert_fixture_wire_tags::<Response>("response", "response.json", Response::wire_tag);
    }

    #[test]
    fn wire_tag_matches_serde_tag_for_every_event_fixture() {
        assert_fixture_wire_tags::<Event>("event", "event.json", Event::wire_tag);
    }

    #[test]
    fn wire_tag_unknown_sentinel_appears_once_per_enum_and_is_never_a_fixture_key() {
        for (name, file_name, tags) in [
            ("request", "request.json", request_variant_tags()),
            ("response", "response.json", response_variant_tags()),
            ("event", "event.json", event_variant_tags()),
        ] {
            assert_eq!(
                tags.iter().filter(|tag| **tag == UNKNOWN_SENTINEL).count(),
                1,
                "{name} table must contain exactly one unknown sentinel"
            );
            let fixture_keys = read_fixture(file_name)
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>();
            assert!(
                !fixture_keys.contains(UNKNOWN_SENTINEL),
                "{name} fixture must not include the unknown sentinel"
            );
        }
    }

    #[test]
    fn frozen_fixture_every_supported_version_still_deserializes() {
        for version in SUPPORTED_PROTOCOL_VERSIONS.iter().copied() {
            assert!(version >= MIN_SUPPORTED_PROTOCOL_VERSION);
            assert_frozen_fixture_deserializes::<Request>(version, "request.json");
            assert_frozen_fixture_deserializes::<Response>(version, "response.json");
            assert_frozen_fixture_deserializes::<Event>(version, "event.json");
        }
    }

    #[test]
    fn frozen_fixture_directories_are_well_formed_without_expanding_compatibility() {
        let listed = SUPPORTED_PROTOCOL_VERSIONS
            .iter()
            .chain(ARCHIVED_PROTOCOL_VERSIONS)
            .copied()
            .collect::<BTreeSet<_>>();
        assert!(
            !listed.is_empty(),
            "supported protocol version list is empty"
        );
        let directories = supported_fixture_directories();
        assert!(
            !directories.is_empty(),
            "daemon_proto has no v*/ fixture directories"
        );
        assert!(
            directories.is_superset(&listed),
            "every live protocol version needs a daemon_proto/vN fixture directory"
        );
        // Older vN directories are migration archaeology. They deliberately
        // remain in-tree as frozen wire evidence, but their presence must not
        // widen the live protocol-compatibility window.
        for version in directories {
            assert_fixture_directory_files(version);
        }
    }

    #[test]
    fn frozen_fixture_current_version_directory_exists() {
        assert!(
            SUPPORTED_PROTOCOL_VERSIONS.contains(&PROTOCOL_VERSION),
            "current protocol v{PROTOCOL_VERSION} must be listed as supported"
        );
        let root = fixture_root_for(PROTOCOL_VERSION);
        assert!(
            root.is_dir(),
            "current protocol fixture directory must exist: {}",
            root.display()
        );
    }

    fn assert_enum_fixture<T>(tag: &str, file_name: &str, expected_kinds: Vec<String>)
    where
        T: DeserializeOwned + Serialize,
    {
        let fixtures = read_fixture(file_name);
        let expected = expected_kinds.into_iter().collect::<BTreeSet<_>>();
        let actual = fixtures.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "{file_name} must contain exactly one full-shape fixture per {tag} variant"
        );

        for (kind, value) in fixtures {
            assert_eq!(
                value.get(tag).and_then(Value::as_str),
                Some(kind.as_str()),
                "{file_name}:{kind} must carry its serde tag"
            );
            let parsed: T = serde_json::from_value(value.clone())
                .unwrap_or_else(|error| panic!("deserialize {file_name}:{kind}: {error}"));
            let serialized = serde_json::to_value(parsed)
                .unwrap_or_else(|error| panic!("serialize {file_name}:{kind}: {error}"));
            assert_eq!(
                canonical(serialized),
                canonical(value),
                "{file_name}:{kind} must round-trip byte-equivalent after canonicalization"
            );
        }
    }

    fn assert_frozen_fixture_deserializes<T>(version: u32, file_name: &str)
    where
        T: DeserializeOwned,
    {
        for (kind, value) in read_fixture_for(version, file_name) {
            let _: T = serde_json::from_value(value).unwrap_or_else(|error| {
                panic!(
                    "frozen fixture v{version}/{file_name}:{kind} no longer deserializes — this is a breaking wire change; bump MIN_SUPPORTED_PROTOCOL_VERSION deliberately or restore compatibility: {error}"
                )
            });
        }
    }

    fn assert_fixture_wire_tags<T>(
        tag: &str,
        file_name: &str,
        wire_tag: impl Fn(&T) -> &'static str,
    ) where
        T: DeserializeOwned,
    {
        for (kind, value) in read_fixture(file_name) {
            assert_eq!(
                value.get(tag).and_then(Value::as_str),
                Some(kind.as_str()),
                "{file_name}:{kind} must carry its serde tag"
            );
            let parsed: T = serde_json::from_value(value)
                .unwrap_or_else(|error| panic!("deserialize {file_name}:{kind}: {error}"));
            assert_eq!(
                wire_tag(&parsed),
                kind,
                "{file_name}:{kind} table wire tag must match serde tag"
            );
        }
    }

    pub(super) fn read_fixture(file_name: &str) -> Map<String, Value> {
        read_fixture_for(PROTOCOL_VERSION, file_name)
    }

    pub(crate) fn read_fixture_for(version: u32, file_name: &str) -> Map<String, Value> {
        let path = fixture_root_for(version).join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }

    fn fixture_expected_kinds(tags: Vec<&'static str>) -> Vec<String> {
        assert_eq!(
            tags.iter().filter(|tag| **tag == UNKNOWN_SENTINEL).count(),
            1,
            "variant table must contain exactly one unknown sentinel"
        );
        tags.into_iter()
            .filter(|tag| *tag != UNKNOWN_SENTINEL)
            .map(str::to_string)
            .collect()
    }

    fn request_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {{
                let mut tags = Vec::new();
                $($(#[$row_attr])* tags.push($tag);)+
                tags
            }};
        }
        crate::request_variants!(collect_tags)
    }

    fn response_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {{
                let mut tags = Vec::new();
                $($(#[$row_attr])* tags.push($tag);)+
                tags
            }};
        }
        crate::response_variants!(collect_tags)
    }

    fn event_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {{
                let mut tags = Vec::new();
                $($(#[$row_attr])* tags.push($tag);)+
                tags
            }};
        }
        crate::event_variants!(collect_tags)
    }

    fn fixture_root_for(version: u32) -> PathBuf {
        let path = daemon_proto_fixture_root().join(format!("v{version}"));
        if !path.is_dir() {
            panic!(
                "missing daemon proto fixture directory for protocol v{version}: {}",
                path.display()
            );
        }
        path
    }

    fn daemon_proto_fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("daemon_proto")
    }

    fn supported_fixture_directories() -> BTreeSet<u32> {
        let root = daemon_proto_fixture_root();
        let entries = std::fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("read {}: {error}", root.display()));
        let mut versions = BTreeSet::new();
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|error| panic!("read {} entry: {error}", root.display()));
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            assert!(
                path.is_dir(),
                "unexpected file directly under daemon_proto fixtures: {}",
                path.display()
            );
            let Some(raw) = name.strip_prefix('v') else {
                panic!(
                    "unexpected non-version directory under daemon_proto fixtures: {}",
                    path.display()
                );
            };
            let version = raw.parse::<u32>().unwrap_or_else(|error| {
                panic!(
                    "unexpected non-numeric daemon_proto fixture directory {}: {error}",
                    path.display()
                )
            });
            versions.insert(version);
        }
        versions
    }

    fn assert_fixture_directory_files(version: u32) {
        let root = fixture_root_for(version);
        let entries = std::fs::read_dir(&root)
            .unwrap_or_else(|error| panic!("read {}: {error}", root.display()));
        let mut actual = BTreeSet::new();
        for entry in entries {
            let entry =
                entry.unwrap_or_else(|error| panic!("read {} entry: {error}", root.display()));
            let path = entry.path();
            assert!(
                path.is_file(),
                "unexpected non-file under frozen daemon_proto v{version}: {}",
                path.display()
            );
            actual.insert(entry.file_name().to_string_lossy().to_string());
        }
        let expected = DAEMON_PROTO_FIXTURE_FILES
            .iter()
            .map(|name| (*name).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "frozen daemon_proto v{version} must contain exactly the known fixture files"
        );
    }

    fn canonical(value: Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
            Value::Object(map) => {
                let mut sorted = Map::new();
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), canonical(map.get(&key).unwrap().clone()));
                }
                Value::Object(sorted)
            }
            other => other,
        }
    }
}

#[cfg(all(test, feature = "remote"))]
mod golden_wire_fixtures {
    use std::collections::BTreeSet;
    use std::path::{Path, PathBuf};

    use serde_json::{Map, Value};

    use super::*;

    const UPDATE_ENV: &str = "COCKPIT_UPDATE_GOLDEN";
    const UNKNOWN_SENTINEL: &str = "__unknown";
    const SENTINEL_UUID: &str = "11111111-1111-4111-8111-111111111111";
    const GOLDEN_DIR: &str = "../../packages/cockpit-protocol/fixtures/daemon-wire";
    const README: &str = "\
# Daemon Wire Fixtures

This directory is generated by `cockpit-proto` golden wire tests.
Do not hand edit these files.

Regenerate from the repository root with:

```sh
COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto golden_wire_
```
";

    const REQUEST_ALLOWLIST: &[&str] = &[
        "archive_session",
        // Migrated to a typed bulk transfer reference by
        // `remote-transport-logical-lanes`; mirrored so the TypeScript schemas
        // see the post-migration shape.
        "import_session_archive",
        "read_bulk_transfer_chunk",
        "write_bulk_transfer_chunk",
        "attach",
        "cancel_paused_work",
        "cancel_run_invocation",
        "delete_session",
        "fork_session",
        "fs_create_dir",
        "fs_delete",
        "fs_list",
        "fs_read",
        "fs_rename",
        "fs_stat",
        "fs_write",
        "get_run_invocation_status",
        "git_diff_file",
        "git_status",
        "get_inventory_bundle",
        "get_startup_disclosures",
        "get_session_setup_snapshot",
        "list_guidance_proposals",
        "get_guidance_enablement_trace",
        "review_guidance_proposal",
        "list_sessions",
        "read_history_page",
        "read_session_messages",
        "read_subagent_history_page",
        "read_agent_attention",
        "read_agent_tree",
        "rename_session",
        "resolve_interrupt",
        "resolve_agent_decision",
        "resolve_assistant_session",
        "restart_if_idle",
        "exit_guard_status",
        "release_exit_guard",
        "resume_paused_work",
        "send_user_message",
        "send_user_message_bulk",
        "session_live_status",
        "set_active_model",
        "set_workspace_trust",
        "set_workspace_history_scope",
        "get_workspace_history_scope",
        "set_agent",
        "set_default_model",
        "set_model_favorite",
        "share_session",
        "stats_rollup",
        "unarchive_session",
    ];

    const RESPONSE_ALLOWLIST: &[&str] = &[
        "ack",
        "config_refreshed",
        "bulk_transfer_chunk",
        "bulk_transfer_chunk_accepted",
        // Migrated to a typed bulk transfer reference.
        "export_session_data",
        "attached",
        "assistant_session_resolved",
        "forked",
        "fs_list",
        "fs_read",
        "fs_stat",
        "fs_write",
        "git_diff_file",
        "git_status",
        "history_page",
        "inventory_bundle",
        "restart_decision",
        "exit_guard_status",
        "run_invocation_cancel_result",
        "run_invocation_status",
        "session_messages",
        "sessions",
        "session_setup_snapshot",
        "guidance_proposals",
        "guidance_enablement_trace",
        "guidance_proposal_reviewed",
        "stats_rollup",
        "startup_disclosures",
        "subagent_history_page",
        "agent_attention_page",
        "agent_decision_steered",
        "agent_tree_page",
        "user_message_queued",
        "workspace_trust_set",
        "workspace_history_scope",
    ];

    #[test]
    fn golden_wire_requests_match_checked_in() {
        let generated = generated_requests();
        assert_allowlist_exact("requests", &generated, REQUEST_ALLOWLIST);
        assert_checked_in("requests.json", generated);
    }

    #[test]
    fn golden_wire_responses_match_checked_in() {
        let generated = generated_responses();
        assert_allowlist_exact("responses", &generated, RESPONSE_ALLOWLIST);
        assert_checked_in("responses.json", generated);
    }

    #[test]
    fn golden_wire_events_cover_every_kind_and_match_checked_in() {
        let generated = generated_events();
        let expected = fixture_expected_kinds(event_variant_tags())
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual = object_keys(&generated);
        assert_eq!(
            actual, expected,
            "events.json must contain exactly one evt frame per Event variant"
        );
        for (name, envelope) in generated.as_object().expect("events fixture is an object") {
            assert_eq!(
                envelope.get("event").and_then(Value::as_str),
                Some(name.as_str()),
                "events.json:{name} key must match its serialized event tag"
            );
        }
        assert_checked_in("events.json", generated);
    }

    #[test]
    fn golden_wire_errors_match_checked_in() {
        let generated = generated_errors();
        let errors = generated.as_object().expect("errors fixture is an object");
        assert!(
            errors
                .values()
                .any(|value| value.get("id").is_some_and(|id| id.is_string())),
            "errors.json must include a request-paired err frame"
        );
        assert!(
            errors.values().any(|value| value.get("id").is_none()),
            "errors.json must include an out-of-band err frame with id omitted"
        );
        for code in [
            "authorization",
            "protocol_version",
            "bad_request",
            "user_message_not_accepted",
            "model_generation_stale",
            "user_message_terminated",
            "idempotency_conflict",
            "client_submission_id_unavailable",
            "invocation_not_found",
            "invocation_capacity_exceeded",
            "invocation_lookup_busy",
            "invalid_ingress",
            "ingress_conflict",
            "ingress_path_unavailable",
            "terminal_generation_gone",
        ] {
            assert!(
                errors.values().any(|value| value
                    .pointer("/error/code")
                    .and_then(Value::as_str)
                    == Some(code)),
                "errors.json must include ErrorCode::{code}"
            );
        }
        assert_checked_in("errors.json", generated);
    }

    #[test]
    fn golden_wire_interrupts_cover_every_question_and_resolve_variant() {
        let generated = generated_interrupts();
        let fixtures = generated
            .as_object()
            .expect("interrupts fixture is an object");

        for (key, expected_kind) in [
            ("event_single_command_detail_present", "single"),
            ("event_multi", "multi"),
            ("event_freetext_masked_true", "freetext"),
            ("event_freetext_masked_false", "freetext"),
        ] {
            assert_eq!(
                question(fixtures, key).get("kind").and_then(Value::as_str),
                Some(expected_kind),
                "{key} must cover InterruptQuestion::{expected_kind}"
            );
        }
        assert_eq!(
            question(fixtures, "event_freetext_masked_true")
                .pointer("/data/masked")
                .and_then(Value::as_bool),
            Some(true),
            "masked:true freetext fixture must carry masked:true"
        );
        assert!(
            question(fixtures, "event_freetext_masked_false")
                .pointer("/data/masked")
                .is_none(),
            "masked:false freetext fixture must omit the additive masked key"
        );
        for (key, value) in fixtures {
            let Some(question) = value.pointer("/data/question") else {
                continue;
            };
            let data = question
                .get("data")
                .unwrap_or_else(|| panic!("{key} question must carry data"));
            if data.get("permission").and_then(Value::as_bool) == Some(true) {
                assert!(
                    data.get("options")
                        .and_then(Value::as_array)
                        .is_some_and(|options| !options.is_empty()),
                    "{key} permission interrupt must carry at least one option"
                );
            }
        }

        for (key, expected_kind) in [
            ("request_resolve_single", "single"),
            ("request_resolve_multi", "multi"),
            ("request_resolve_freetext", "freetext"),
            ("request_resolve_batch", "batch"),
            ("request_resolve_cancel", "cancel"),
        ] {
            assert_eq!(
                resolve_response(fixtures, key)
                    .get("kind")
                    .and_then(Value::as_str),
                Some(expected_kind),
                "{key} must cover ResolveResponse::{expected_kind}"
            );
        }
        assert_eq!(
            resolve_response(fixtures, "request_resolve_batch")
                .pointer("/data/responses/0/kind")
                .and_then(Value::as_str),
            Some("single"),
            "ResolveResponse::Batch must nest at least one non-batch response"
        );
        assert_checked_in("interrupts.json", generated);
    }

    #[test]
    fn golden_wire_command_detail_present_and_absent() {
        let generated = generated_interrupts();
        let fixtures = generated
            .as_object()
            .expect("interrupts fixture is an object");

        let present = question_data(fixtures, "event_single_command_detail_present");
        assert!(
            present.get("command_detail").is_some(),
            "command_detail-present fixture must carry command_detail"
        );
        let command_detail = present
            .get("command_detail")
            .and_then(Value::as_object)
            .expect("command_detail is an object");
        for field in [
            "affected_targets",
            "cwd",
            "full_command",
            "highlight",
            "native_tool_hints",
            "offered_scopes",
            "policy_cap",
            "remembered_key",
            "risk_reasons",
            "risk_tier",
            "step",
            "step_count",
            "write_content",
        ] {
            assert!(
                command_detail.contains_key(field),
                "command_detail-present fixture must carry {field}"
            );
        }
        assert!(
            question_data(fixtures, "event_single_command_detail_absent")
                .get("command_detail")
                .is_none(),
            "command_detail-absent fixture must omit command_detail"
        );

        let denial_present = question_data(fixtures, "event_single_sandbox_denial_present")
            .pointer("/sandbox_escalation/denial")
            .expect("sandbox denial report is present");
        assert_eq!(
            denial_present
                .pointer("/confidence")
                .and_then(Value::as_str),
            Some("high")
        );
        let evidence = denial_present
            .pointer("/evidence")
            .and_then(Value::as_array)
            .expect("denial evidence is an array");
        assert!(
            evidence
                .iter()
                .any(|item| item.get("kind").and_then(Value::as_str)
                    == Some("write_outside_allowlist")),
            "denial evidence must include write_outside_allowlist"
        );
        assert!(
            evidence
                .iter()
                .any(|item| item.get("kind").and_then(Value::as_str)
                    == Some("stderr_permission_marker")),
            "denial evidence must include stderr_permission_marker"
        );
        assert!(
            question_data(fixtures, "event_single_sandbox_denial_absent")
                .pointer("/sandbox_escalation/denial")
                .is_none(),
            "sandbox denial absent fixture must omit denial"
        );
    }

    #[test]
    fn golden_wire_grant_kinds_all_present() {
        let generated = generated_interrupts();
        let fixtures = generated
            .as_object()
            .expect("interrupts fixture is an object");
        let actual = [
            "event_single_grant_command",
            "event_single_grant_path",
            "event_single_grant_mcp_tool",
        ]
        .into_iter()
        .map(|key| {
            question_data(fixtures, key)
                .get("approval_class")
                .and_then(Value::as_str)
                .unwrap_or_else(|| panic!("{key} must carry approval_class"))
                .to_string()
        })
        .collect::<BTreeSet<_>>();
        let expected = ["command", "path", "mcp_tool"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>();
        assert_eq!(actual, expected, "all GrantKind values must be goldenized");
    }

    #[test]
    fn golden_wire_envelope_v_equals_protocol_version() {
        for (file_name, fixture) in [
            ("requests.json", generated_requests()),
            ("responses.json", generated_responses()),
            ("events.json", generated_events()),
            ("errors.json", generated_errors()),
            ("interrupts.json", generated_interrupts()),
        ] {
            for (name, envelope) in fixture.as_object().expect("fixture is an object") {
                assert_eq!(
                    envelope.get("v").and_then(Value::as_u64),
                    Some(u64::from(PROTOCOL_VERSION)),
                    "{file_name}:{name} must carry v=PROTOCOL_VERSION"
                );
            }
        }
    }

    fn generated_requests() -> Value {
        let bare = read_bare_fixture("request.json");
        let mut generated = Map::new();
        for name in REQUEST_ALLOWLIST {
            let value = bare.get(*name).unwrap_or_else(|| {
                panic!("request allowlist entry {name} is missing from bare fixture")
            });
            let request: Request = serde_json::from_value(value.clone())
                .unwrap_or_else(|error| panic!("deserialize bare request {name}: {error}"));
            generated.insert(
                (*name).to_string(),
                envelope_value(Envelope::request(sentinel_uuid(), request)),
            );
        }
        Value::Object(generated)
    }

    fn generated_responses() -> Value {
        let bare = read_bare_fixture("response.json");
        let mut generated = Map::new();
        for name in RESPONSE_ALLOWLIST {
            let value = bare.get(*name).unwrap_or_else(|| {
                panic!("response allowlist entry {name} is missing from bare fixture")
            });
            let response: Response = serde_json::from_value(value.clone())
                .unwrap_or_else(|error| panic!("deserialize bare response {name}: {error}"));
            generated.insert(
                (*name).to_string(),
                envelope_value(Envelope::response(sentinel_uuid(), response)),
            );
        }
        Value::Object(generated)
    }

    fn generated_events() -> Value {
        let bare = read_bare_fixture("event.json");
        let expected = fixture_expected_kinds(event_variant_tags())
            .into_iter()
            .collect::<BTreeSet<_>>();
        let actual = bare.keys().cloned().collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "bare event fixtures must contain every Event variant before envelope generation"
        );

        let mut generated = Map::new();
        for (name, value) in bare {
            let event: Event = serde_json::from_value(value)
                .unwrap_or_else(|error| panic!("deserialize bare event {name}: {error}"));
            generated.insert(name, envelope_value(Envelope::event(event)));
        }
        Value::Object(generated)
    }

    fn generated_errors() -> Value {
        let mut generated = Map::new();
        for (name, id, code, message) in [
            (
                "authorization_paired",
                Some(sentinel_uuid()),
                ErrorCode::Authorization,
                "principal cannot access this session",
            ),
            (
                "protocol_version_paired",
                Some(sentinel_uuid()),
                ErrorCode::ProtocolVersion,
                "wire protocol version mismatch",
            ),
            (
                "bad_request_out_of_band",
                None,
                ErrorCode::BadRequest,
                "malformed daemon frame",
            ),
            (
                "user_message_not_accepted_paired",
                Some(sentinel_uuid()),
                ErrorCode::UserMessageNotAccepted,
                "user message was not accepted by the session driver",
            ),
            (
                "user_message_terminated_paired",
                Some(sentinel_uuid()),
                ErrorCode::UserMessageTerminated,
                "user message reached a durable terminal disposition",
            ),
            (
                "idempotency_conflict_paired",
                Some(sentinel_uuid()),
                ErrorCode::IdempotencyConflict,
                "client_submission_id was already used with different content",
            ),
            (
                "client_submission_id_unavailable_paired",
                Some(sentinel_uuid()),
                ErrorCode::ClientSubmissionIdUnavailable,
                "client_submission_id is unavailable",
            ),
            (
                "invocation_not_found_paired",
                Some(sentinel_uuid()),
                ErrorCode::InvocationNotFound,
                "invocation not found",
            ),
            (
                "invocation_capacity_exceeded_paired",
                Some(sentinel_uuid()),
                ErrorCode::InvocationCapacityExceeded,
                "invocation capacity exceeded",
            ),
            (
                "invocation_lookup_busy_paired",
                Some(sentinel_uuid()),
                ErrorCode::InvocationLookupBusy,
                "invocation lookup busy",
            ),
            (
                "invalid_ingress_paired",
                Some(sentinel_uuid()),
                ErrorCode::InvalidIngress,
                "invalid terminal ingress",
            ),
            (
                "ingress_conflict_paired",
                Some(sentinel_uuid()),
                ErrorCode::IngressConflict,
                "terminal ingress metadata conflict",
            ),
            (
                "ingress_path_unavailable_paired",
                Some(sentinel_uuid()),
                ErrorCode::IngressPathUnavailable,
                "terminal ingress path unavailable",
            ),
            (
                "terminal_generation_gone_paired",
                Some(sentinel_uuid()),
                ErrorCode::TerminalGenerationGone,
                "terminal generation is gone",
            ),
            (
                "invalid_response_metrics_tokenizer_paired",
                Some(sentinel_uuid()),
                ErrorCode::InvalidResponseMetricsTokenizer,
                "configuration value is invalid",
            ),
            (
                "model_generation_stale_paired",
                Some(sentinel_uuid()),
                ErrorCode::ModelGenerationStale,
                "captured model generation is no longer active",
            ),
        ] {
            generated.insert(
                name.to_string(),
                envelope_value(Envelope::error(
                    id,
                    ErrorPayload {
                        code,
                        message: message.to_string(),
                    },
                )),
            );
        }
        Value::Object(generated)
    }

    fn generated_interrupts() -> Value {
        let mut generated = Map::new();
        for (name, question) in [
            (
                "event_single_command_detail_present",
                single_question(
                    "Run `cargo test --locked`?",
                    Some(full_command_detail()),
                    Some(GrantKind::Command),
                    Some(sandbox_escalation_with_denial()),
                ),
            ),
            (
                "event_single_command_detail_absent",
                single_question(
                    "Run `cargo fmt --check`?",
                    None,
                    Some(GrantKind::Command),
                    None,
                ),
            ),
            (
                "event_single_sandbox_denial_present",
                single_question(
                    "Retry outside the sandbox?",
                    None,
                    Some(GrantKind::Path),
                    Some(sandbox_escalation_with_denial()),
                ),
            ),
            (
                "event_single_sandbox_denial_absent",
                single_question(
                    "Retry with broader access?",
                    None,
                    Some(GrantKind::Path),
                    Some(sandbox_escalation_without_denial()),
                ),
            ),
            (
                "event_single_grant_command",
                single_question("Approve command?", None, Some(GrantKind::Command), None),
            ),
            (
                "event_single_grant_path",
                single_question("Approve path?", None, Some(GrantKind::Path), None),
            ),
            (
                "event_single_grant_mcp_tool",
                single_question("Approve MCP tool?", None, Some(GrantKind::McpTool), None),
            ),
            (
                "event_multi",
                InterruptQuestion::Multi {
                    prompt: "Select checks to run".into(),
                    options: vec![option("fmt", "Format"), option("test", "Test")],
                    allow_freetext: false,
                },
            ),
            (
                "event_freetext_masked_true",
                InterruptQuestion::Freetext {
                    prompt: "Enter token".into(),
                    masked: true,
                },
            ),
            (
                "event_freetext_masked_false",
                InterruptQuestion::Freetext {
                    prompt: "Explain the decision".into(),
                    masked: false,
                },
            ),
        ] {
            generated.insert(name.to_string(), interrupt_event(question));
        }

        for (name, response) in [
            (
                "request_resolve_single",
                ResolveResponse::Single {
                    selected_id: "approve_once".into(),
                },
            ),
            (
                "request_resolve_multi",
                ResolveResponse::Multi {
                    selected_ids: vec!["fmt".into(), "test".into()],
                },
            ),
            (
                "request_resolve_freetext",
                ResolveResponse::Freetext {
                    text: "Use the existing design".into(),
                },
            ),
            (
                "request_resolve_batch",
                ResolveResponse::Batch {
                    responses: vec![ResolveResponse::Single {
                        selected_id: "approve_once".into(),
                    }],
                },
            ),
            ("request_resolve_cancel", ResolveResponse::Cancel),
        ] {
            generated.insert(name.to_string(), resolve_interrupt_request(response));
        }

        Value::Object(generated)
    }

    fn interrupt_event(question: InterruptQuestion) -> Value {
        envelope_value(Envelope::event(Event::InterruptRaised {
            session_id: sentinel_uuid(),
            interrupt_id: interrupt_uuid(),
            agent: "builder".into(),
            description: "Fixture interrupt".into(),
            question: Some(question),
            questions: None,
            pending_count: 1,
            reason: InterruptRaiseReason::Initial,
        }))
    }

    fn resolve_interrupt_request(response: ResolveResponse) -> Value {
        envelope_value(Envelope::request(
            sentinel_uuid(),
            Request::ResolveInterrupt {
                interrupt_id: interrupt_uuid(),
                response,
            },
        ))
    }

    fn single_question(
        prompt: &str,
        command_detail: Option<CommandDetail>,
        approval_class: Option<GrantKind>,
        sandbox_escalation: Option<SandboxEscalation>,
    ) -> InterruptQuestion {
        InterruptQuestion::Single {
            prompt: prompt.into(),
            options: vec![option("approve_once", "Approve once")],
            allow_freetext: false,
            command_detail: command_detail.map(Box::new),
            permission: true,
            approval_class,
            sandbox_escalation,
        }
    }

    fn option(id: &str, label: &str) -> InterruptOption {
        InterruptOption {
            id: id.into(),
            label: label.into(),
            description: Some(format!("{label} for this fixture")),
            secondary: false,
        }
    }

    fn full_command_detail() -> CommandDetail {
        CommandDetail {
            full_command: "cargo test --locked".into(),
            highlight: Some(CharSpan { start: 0, end: 5 }),
            step: 1,
            step_count: 2,
            cwd: Some("/workspace/flycockpitapp".into()),
            remembered_key: Some("cargo-test".into()),
            write_content: Some(WriteContentPreview {
                content: "fixture body".into(),
                dynamic: true,
            }),
            risk_tier: Some("medium".into()),
            risk_reasons: vec!["runs tests".into()],
            affected_targets: vec!["crates/cockpit-proto/src/lib.rs".into()],
            native_tool_hints: vec!["cargo".into()],
            offered_scopes: vec!["session".into()],
            policy_cap: Some("ask".into()),
            image_plan_review: None,
        }
    }

    fn sandbox_escalation_with_denial() -> SandboxEscalation {
        SandboxEscalation {
            confined_exit: 13,
            confined_stderr: "Permission denied".into(),
            suggested_paths: vec!["/workspace/flycockpitapp/target".into()],
            suggested_access: Some("write".into()),
            denial: Some(SandboxDenialReport {
                confidence: SandboxDenialConfidence::High,
                evidence: vec![
                    SandboxDenialEvidence::WriteOutsideAllowlist {
                        path: "/workspace/flycockpitapp/target".into(),
                    },
                    SandboxDenialEvidence::StderrPermissionMarker,
                ],
            }),
        }
    }

    fn sandbox_escalation_without_denial() -> SandboxEscalation {
        SandboxEscalation {
            confined_exit: 13,
            confined_stderr: "Permission denied".into(),
            suggested_paths: vec!["/workspace/flycockpitapp/target".into()],
            suggested_access: Some("write".into()),
            denial: None,
        }
    }

    fn assert_checked_in(file_name: &str, generated: Value) {
        let canonical_generated = canonical(generated);
        let path = golden_root().join(file_name);
        if update_golden() {
            let _guard = update_lock()
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            std::fs::create_dir_all(golden_root()).unwrap_or_else(|error| {
                panic!(
                    "create golden fixture directory {}: {error}",
                    golden_root().display()
                )
            });
            std::fs::write(golden_root().join("README.md"), README).unwrap_or_else(|error| {
                panic!(
                    "write golden fixture README {}: {error}",
                    golden_root().join("README.md").display()
                )
            });
            let mut pretty = serde_json::to_string_pretty(&canonical_generated)
                .unwrap_or_else(|error| panic!("serialize {file_name}: {error}"));
            pretty.push('\n');
            std::fs::write(&path, pretty)
                .unwrap_or_else(|error| panic!("write {}: {error}", path.display()));
            format_golden_json(&path);
            return;
        }

        let raw = std::fs::read_to_string(&path).unwrap_or_else(|error| {
            panic!(
                "read {}: {error}; regenerate with COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto golden_wire_",
                path.display()
            )
        });
        let checked_in: Value = serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()));
        assert_eq!(
            canonical(checked_in),
            canonical_generated,
            "{} drifted; regenerate with COCKPIT_UPDATE_GOLDEN=1 cargo test -p cockpit-proto golden_wire_",
            path.display()
        );
    }

    fn assert_allowlist_exact(surface: &str, generated: &Value, allowlist: &[&str]) {
        let actual = object_keys(generated);
        let expected = allowlist
            .iter()
            .map(|name| (*name).to_string())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            actual, expected,
            "{surface}.json emitted keys must exactly match the explicit allowlist"
        );
    }

    fn read_bare_fixture(file_name: &str) -> Map<String, Value> {
        let path = bare_fixture_root().join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }

    fn envelope_value(envelope: Envelope) -> Value {
        let value = serde_json::to_value(envelope).expect("serialize envelope");
        let parsed: Envelope =
            serde_json::from_value(value.clone()).expect("deserialize generated envelope");
        let reparsed = serde_json::to_value(parsed).expect("re-serialize generated envelope");
        assert_eq!(
            canonical(reparsed),
            canonical(value.clone()),
            "generated envelope must round-trip canonically"
        );
        value
    }

    fn question<'a>(fixtures: &'a Map<String, Value>, key: &str) -> &'a Value {
        fixtures
            .get(key)
            .unwrap_or_else(|| panic!("missing interrupt fixture {key}"))
            .pointer("/data/question")
            .unwrap_or_else(|| panic!("{key} must carry data.question"))
    }

    fn question_data<'a>(fixtures: &'a Map<String, Value>, key: &str) -> &'a Value {
        question(fixtures, key)
            .get("data")
            .unwrap_or_else(|| panic!("{key} question must carry data"))
    }

    fn resolve_response<'a>(fixtures: &'a Map<String, Value>, key: &str) -> &'a Value {
        fixtures
            .get(key)
            .unwrap_or_else(|| panic!("missing interrupt fixture {key}"))
            .pointer("/params/response")
            .unwrap_or_else(|| panic!("{key} must carry params.response"))
    }

    fn object_keys(value: &Value) -> BTreeSet<String> {
        value
            .as_object()
            .expect("fixture value is an object")
            .keys()
            .cloned()
            .collect()
    }

    fn fixture_expected_kinds(tags: Vec<&'static str>) -> Vec<String> {
        assert_eq!(
            tags.iter().filter(|tag| **tag == UNKNOWN_SENTINEL).count(),
            1,
            "variant table must contain exactly one unknown sentinel"
        );
        tags.into_iter()
            .filter(|tag| *tag != UNKNOWN_SENTINEL)
            .map(str::to_string)
            .collect()
    }

    fn event_variant_tags() -> Vec<&'static str> {
        macro_rules! collect_tags {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $tag:expr);)+]) => {{
                let mut tags = Vec::new();
                $($(#[$row_attr])* tags.push($tag);)+
                tags
            }};
        }
        crate::event_variants!(collect_tags)
    }

    fn canonical(value: Value) -> Value {
        match value {
            Value::Array(items) => Value::Array(items.into_iter().map(canonical).collect()),
            Value::Object(map) => {
                let mut sorted = Map::new();
                let mut keys = map.keys().cloned().collect::<Vec<_>>();
                keys.sort();
                for key in keys {
                    sorted.insert(key.clone(), canonical(map.get(&key).unwrap().clone()));
                }
                Value::Object(sorted)
            }
            other => other,
        }
    }

    fn golden_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN_DIR)
    }

    fn bare_fixture_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("daemon_proto")
            .join(format!("v{PROTOCOL_VERSION}"))
    }

    fn sentinel_uuid() -> Uuid {
        Uuid::parse_str(SENTINEL_UUID).expect("sentinel UUID parses")
    }

    fn interrupt_uuid() -> Uuid {
        Uuid::parse_str("22222222-2222-4222-8222-222222222222").expect("interrupt UUID parses")
    }

    fn update_golden() -> bool {
        std::env::var(UPDATE_ENV).is_ok()
    }

    fn update_lock() -> &'static std::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
    }

    fn format_golden_json(path: &Path) {
        let status = std::process::Command::new(biome_bin())
            .args(["format", "--write"])
            .arg(path)
            .current_dir(workspace_root())
            .status()
            .unwrap_or_else(|error| {
                panic!(
                    "format golden fixture {} with biome: {error}",
                    path.display()
                )
            });
        assert!(
            status.success(),
            "format golden fixture {} with biome exited with {status}",
            path.display()
        );
    }

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
    }

    fn biome_bin() -> PathBuf {
        let executable = if cfg!(windows) { "biome.cmd" } else { "biome" };
        let local = workspace_root()
            .join("node_modules")
            .join(".bin")
            .join(executable);
        if local.is_file() {
            local
        } else {
            PathBuf::from(executable)
        }
    }
}

#[cfg(test)]
mod forward_open_guard_tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use tokio::io::duplex;

    #[test]
    fn forward_open_guard_no_deny_unknown_fields_in_proto_src() {
        let mut violations = Vec::new();
        collect_deny_unknown_fields_violations(&src_root(), &mut violations);
        assert!(
            violations.is_empty(),
            "cockpit-proto wire structs must stay forward-open for additive compatibility \
             (see proto-additive-forward-compat); remove serde deny_unknown_fields from: {}",
            violations.join(", ")
        );
    }

    #[test]
    fn forward_open_guard_struct_payload_accepts_unknown_field() {
        let value = read_forward_fixture("response-extra-field.json");
        let response: Response =
            serde_json::from_value(value).expect("future response fixture should parse");
        match response {
            Response::ApprovalModeState { mode } => assert_eq!(mode, ApprovalMode::Auto),
            other => panic!("expected approval mode response, got {other:?}"),
        }
    }

    #[test]
    fn image_ingress_payloads_remain_forward_open_for_additive_fields() {
        let session_id = Uuid::new_v4();
        let admission_id = Uuid::new_v4();
        let request = Envelope {
            v: PROTOCOL_VERSION,
            body: Body::Request {
                id: Uuid::new_v4(),
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::AdmitImageIngress {
                    session_id,
                    source: ImageIngressSourceV1::PrivateTerminalCapability {
                        capability: "opaque-test-capability".into(),
                    },
                    admission_id,
                },
            },
        };
        let mut request_value = serde_json::to_value(request).expect("serialize request envelope");
        request_value["params"]["source"]["futureCapabilityBinding"] = serde_json::json!("v2");
        let request: Envelope = serde_json::from_value(request_value)
            .expect("additive nested request field should parse");
        assert!(matches!(
            request.body,
            Body::Request {
                request: Request::AdmitImageIngress {
                    source: ImageIngressSourceV1::PrivateTerminalCapability { .. },
                    ..
                },
                ..
            }
        ));

        let response = Envelope {
            v: PROTOCOL_VERSION,
            body: Body::Response {
                id: Uuid::new_v4(),
                response: Box::new(Response::ImageIngressAdmitted(
                    ImageIngressAdmissionReceiptV1 {
                        schema_version: 1,
                        kind: "retained_image".into(),
                        admission_id,
                        session_id,
                        attachment: crate::send_user_message_v2::MessageAttachmentIdentity {
                            attachment_id: Uuid::new_v4(),
                            attachment_version: 1,
                            checksum: [0; 32],
                            kind: cockpit_db::media_attachments::MediaKind::Image,
                        },
                        availability_generation: 1,
                        reservation_id: "reservation-1".into(),
                        normalized_sha256: "00".repeat(32),
                        normalized_byte_length: 4,
                        width: 1,
                        height: 1,
                    },
                )),
            },
        };
        let mut response_value =
            serde_json::to_value(response).expect("serialize response envelope");
        response_value["data"]["futureRetentionProof"] = serde_json::json!({ "version": 2 });
        let response: Envelope = serde_json::from_value(response_value)
            .expect("additive nested response field should parse");
        assert!(matches!(
            response.body,
            Body::Response { response, .. }
                if matches!(*response, Response::ImageIngressAdmitted(ref receipt) if receipt.schema_version == 1)
        ));
    }

    #[tokio::test]
    async fn forward_open_guard_frame_accepts_unknown_top_level_variant() {
        let mut value = read_forward_fixture("unknown-top-level-variant.json");
        value["v"] = serde_json::json!(PROTOCOL_VERSION);
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.send_raw_line(value.to_string()).await.unwrap();

        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::Unknown { v, kind, tag, id } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(kind, "req");
                assert_eq!(tag.as_deref(), Some("future_request"));
                assert_eq!(
                    id,
                    Some(Uuid::parse_str("11111111-1111-4111-8111-111111111111").unwrap())
                );
            }
            other => panic!("expected unknown frame, got {other:?}"),
        }
    }

    fn collect_deny_unknown_fields_violations(path: &Path, violations: &mut Vec<String>) {
        for entry in std::fs::read_dir(path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
        {
            let entry = entry.unwrap_or_else(|error| panic!("read dir entry: {error}"));
            let path = entry.path();
            if path.is_dir() {
                collect_deny_unknown_fields_violations(&path, violations);
                continue;
            }
            if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
                continue;
            }
            let source = std::fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
            let mut in_serde_attr = false;
            for (index, line) in source.lines().enumerate() {
                if line.trim_start().starts_with("#[serde") {
                    in_serde_attr = true;
                }
                if in_serde_attr && line.contains("deny_unknown_fields") {
                    violations.push(format!("{}:{}", path.display(), index + 1));
                }
                if in_serde_attr && line.contains(']') {
                    in_serde_attr = false;
                }
            }
        }
    }

    fn src_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
    }

    fn read_forward_fixture(file_name: &str) -> serde_json::Value {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("forward_compat")
            .join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }
}

#[cfg(test)]
mod errorcode_forward_tests {
    use super::*;

    #[test]
    fn errorcode_forward_unknown_string_deserializes_to_catch_all() {
        let code: ErrorCode = serde_json::from_str("\"future_code\"").unwrap();
        assert_eq!(code, ErrorCode::Other("future_code".to_string()));
        assert_eq!(code.to_string(), "future_code");
    }

    #[test]
    fn errorcode_forward_known_string_still_deserializes_to_specific_variant() {
        let code: ErrorCode = serde_json::from_str("\"protocol_version\"").unwrap();
        assert_eq!(code, ErrorCode::ProtocolVersion);
    }

    #[test]
    fn errorcode_forward_catch_all_round_trips() {
        let original = ErrorCode::Other("future_code".to_string());
        let serialized = serde_json::to_string(&original).unwrap();
        assert_eq!(serialized, "\"future_code\"");
        let parsed: ErrorCode = serde_json::from_str(&serialized).unwrap();
        assert_eq!(parsed, original);
    }
}

// ---- Tests -----------------------------------------------------------------

/// Retained daemon-wire fixtures from versions this binary deliberately does
/// not support. Keep this separate from the remote-gated supported-version
/// table: fixture retention must never widen the live compatibility window.
#[cfg(test)]
const ARCHIVED_PROTOCOL_VERSIONS: &[u32] = &[12, 13, 14, 15, 16, 17, 18, 19, 20];

/// Fixture-file reader shared by tests that run in the default (non-`remote`)
/// profile. The full `proto_fixture_tests` module is `remote`-gated because its
/// round-trip coverage deserializes remote-only variants; this thin reader has
/// no remote-type dependency and stays available so local-protocol fixture
/// freezing checks keep running without `--features remote`.
#[cfg(test)]
mod proto_fixture_files {
    use serde_json::{Map, Value};
    use std::path::Path;

    pub(super) fn read_fixture(file_name: &str) -> Map<String, Value> {
        read_fixture_for(super::PROTOCOL_VERSION, file_name)
    }

    pub(super) fn read_fixture_for(version: u32, file_name: &str) -> Map<String, Value> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("daemon_proto")
            .join(format!("v{version}"))
            .join(file_name);
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::send_user_message_v2::MessageIngressV2;

    #[cfg(feature = "remote")]
    #[test]
    fn remote_operation_identity_requires_strict_uuid_v7_wire_form() {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-operation-identity-v1.json"
        ))
        .unwrap();
        assert!(
            serde_json::from_value::<RemoteOperationIdentityV1>(fixture["valid"].clone()).is_ok()
        );
        for malformed in fixture["invalid"].as_array().unwrap() {
            assert!(
                serde_json::from_value::<RemoteOperationIdentityV1>(malformed.clone()).is_err()
            );
        }
    }
    use serde_json::json;
    use tokio::io::duplex;

    fn hello(protocol_version: u32) -> DaemonHello {
        DaemonHello {
            daemon_version: "0.0.test-daemon".to_string(),
            protocol_version,
        }
    }

    #[test]
    fn goal_lifecycle_proto_round_trips_elapsed_and_history() {
        let summary = GoalSummary {
            id: Uuid::new_v4(),
            session_id: Uuid::new_v4(),
            project_id: "project".into(),
            objective: "ship".into(),
            context: None,
            disposition: GoalDisposition::UserPaused,
            phase: None,
            resume_phase: Some(GoalPhase::Executing),
            pause_reason: Some(GoalPauseReason::User),
            contract_available: true,
            latest_gap_or_blocker: None,
            verification_attempts: 2,
            max_verification_attempts: 4,
            attempt_generation: 4,
            token_budget: 100,
            tokens_used: 25,
            remaining_tokens: 75,
            elapsed_active_ms: 12_345,
            lifecycle_history: vec![GoalLifecycleHistoryEntry {
                at: 7,
                disposition: GoalDisposition::UserPaused,
                phase: None,
                reason: Some(GoalPauseReason::User),
            }],
            blocked_attempts: 0,
            last_read_at: None,
            created_at: 1,
            updated_at: 7,
        };
        let encoded = serde_json::to_value(&summary).unwrap();
        assert_eq!(encoded["elapsed_active_ms"], 12_345);
        assert_eq!(encoded["max_verification_attempts"], 4);
        assert_eq!(encoded["lifecycle_history"][0]["reason"]["kind"], "user");
        assert_eq!(
            serde_json::from_value::<GoalSummary>(encoded).unwrap(),
            summary
        );
    }

    #[test]
    fn negotiated_version_requires_an_exact_daemon_match() {
        let current = NegotiatedProtocol::from_hello(&hello(PROTOCOL_VERSION)).unwrap();
        assert_eq!(current.version, PROTOCOL_VERSION);
        assert_eq!(current.daemon_protocol_version, PROTOCOL_VERSION);

        for incompatible in [
            PROTOCOL_VERSION.saturating_sub(1),
            PROTOCOL_VERSION.saturating_add(1),
        ] {
            let err = NegotiatedProtocol::from_hello(&hello(incompatible))
                .expect_err("any protocol mismatch must be rejected");
            assert_eq!(err.code, ErrorCode::ProtocolVersion);
            assert_eq!(
                err.message,
                incompatible_daemon_protocol_message(incompatible)
            );
        }
    }

    #[test]
    fn negotiated_version_below_min_supported_is_rejected() {
        let below_min = MIN_SUPPORTED_PROTOCOL_VERSION.saturating_sub(1);
        let err = NegotiatedProtocol::from_hello(&hello(below_min))
            .expect_err("below-min daemon protocol must be rejected");
        assert_eq!(err.code, ErrorCode::ProtocolVersion);
        assert_eq!(err.message, incompatible_daemon_protocol_message(below_min));
    }

    #[test]
    fn set_active_model_rejects_unknown_thinking_mode_during_deserialization() {
        let raw = json!({
            "request": "set_active_model",
            "params": {
                "selection_id": "11111111-1111-4111-8111-111111111111",
                "provider": "openai",
                "model": "gpt-5",
                "persist_as_default": false,
                "thinking_mode": "turbo"
            }
        });

        let error = serde_json::from_value::<Request>(raw)
            .expect_err("unknown thinking mode must fail at the wire boundary");
        assert!(error.to_string().contains("unknown variant"));
    }

    #[test]
    fn set_active_model_rejects_empty_reasoning_effort_during_deserialization() {
        let raw = json!({
            "request": "set_active_model",
            "params": {
                "selection_id": "11111111-1111-4111-8111-111111111111",
                "provider": "openai",
                "model": "gpt-5",
                "persist_as_default": false,
                "reasoning_effort": ""
            }
        });

        let error = serde_json::from_value::<Request>(raw)
            .expect_err("empty reasoning effort must fail at the wire boundary");
        assert!(error.to_string().contains("must not be empty"));
    }

    #[test]
    fn set_active_model_rejects_empty_provider_or_model_during_deserialization() {
        for (field, provider, model) in [("provider", "", "gpt-5"), ("model", "openai", "")] {
            let raw = json!({
                "request": "set_active_model",
                "params": {
                    "selection_id": "11111111-1111-4111-8111-111111111111",
                    "provider": provider,
                    "model": model,
                    "persist_as_default": false
                }
            });

            let error = serde_json::from_value::<Request>(raw)
                .expect_err("empty model identity must fail at the wire boundary");
            assert!(
                error.to_string().contains("must not be empty"),
                "{field}: {error}"
            );
        }
    }

    #[test]
    fn active_model_state_rejects_removed_flat_v5_shape() {
        let raw = json!({
            "event": "active_model_state",
            "data": {
                "session_id": "11111111-1111-4111-8111-111111111111",
                "provider": "openai",
                "model": "gpt-5",
                "diverged": false,
                "generation": 1
            }
        });

        serde_json::from_value::<Event>(raw)
            .expect_err("protocol v6 must reject the removed flat active-model shape");
    }

    #[test]
    fn model_selection_result_rejects_unknown_thinking_mode() {
        let raw = json!({
            "event": "model_selection_result",
            "data": {
                "session_id": "11111111-1111-4111-8111-111111111111",
                "selection_id": "22222222-2222-4222-8222-222222222222",
                "provider": "openai",
                "model": "gpt-5",
                "thinking_mode": "turbo",
                "outcome": {
                    "status": "rejected",
                    "user_message": "invalid selection",
                    "diagnostic_code": "invalid_selection"
                }
            }
        });

        let error = serde_json::from_value::<Event>(raw)
            .expect_err("unknown result thinking mode must fail at the wire boundary");
        assert!(error.to_string().contains("unknown variant"));
    }

    #[tokio::test]
    async fn envelope_constructors_stamp_the_negotiated_version() {
        let negotiated = MIN_SUPPORTED_PROTOCOL_VERSION;
        let (left, right) = duplex(4096);
        let mut sender = ProtoStream::with_version(left, negotiated);
        let mut receiver = ProtoStream::new(right);

        let request = Envelope::request(Uuid::new_v4(), Request::DaemonStatus);
        assert_eq!(request.v, PROTOCOL_VERSION);
        sender.send(&request).await.unwrap();

        match receiver.recv().await.unwrap().expect("frame") {
            RecvFrame::Envelope(env) => assert_eq!(env.v, negotiated),
            other => panic!("expected envelope, got {other:?}"),
        }

        assert_eq!(
            Envelope::request_at(negotiated, Uuid::new_v4(), Request::DaemonStatus).v,
            negotiated
        );
        assert_eq!(
            Envelope::response_at(negotiated, Uuid::new_v4(), Response::Ack).v,
            negotiated
        );
        assert_eq!(
            Envelope::event_at(
                negotiated,
                Event::LspNotice {
                    text: "notice".to_string()
                }
            )
            .v,
            negotiated
        );
        assert_eq!(
            Envelope::error_at(
                negotiated,
                None,
                ErrorPayload {
                    code: ErrorCode::Internal,
                    message: "error".to_string()
                }
            )
            .v,
            negotiated
        );
    }

    #[test]
    fn request_round_trip() {
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SendUserMessageV2 {
                ingress: MessageIngressV2::local_direct(
                    Uuid::now_v7(),
                    "session",
                    None,
                    None,
                    None,
                    crate::send_user_message_v2::SendUserMessageV2 {
                        client_submission_id: Uuid::new_v4(),
                        origin: Default::default(),
                        text: "hello".into(),
                        display_text: None,
                        tag_expansions: Vec::new(),
                        forced_skill: None,
                        delivery_class_override: None,
                        resolved_delivery_class: None,
                        resolved_queue_target: None,
                        attachments: Vec::new(),
                    },
                ),
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Request {
                request: Request::SendUserMessageV2 { ingress },
                ..
            } => assert_eq!(ingress.request().text, "hello"),
            other => panic!("expected SendUserMessageV2, got {other:?}"),
        }
    }

    #[test]
    fn read_history_page_request_round_trips_without_before_seq() {
        let session_id = Uuid::new_v4();
        let value = serde_json::to_value(Request::ReadHistoryPage {
            session_id,
            before_seq: None,
            limit: 25,
        })
        .unwrap();
        assert_eq!(
            value,
            json!({
                "request": "read_history_page",
                "params": {
                    "session_id": session_id,
                    "limit": 25,
                }
            })
        );

        let back: Request = serde_json::from_value(value).unwrap();
        match back {
            Request::ReadHistoryPage {
                session_id: got,
                before_seq,
                limit,
            } => {
                assert_eq!(got, session_id);
                assert_eq!(before_seq, None);
                assert_eq!(limit, 25);
            }
            other => panic!("expected ReadHistoryPage, got {other:?}"),
        }
    }

    #[test]
    fn send_user_message_v2_serializes_typed_attachment_identity_without_raw_bytes() {
        let attachment_id = Uuid::now_v7();
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SendUserMessageV2 {
                ingress: MessageIngressV2::local_direct(
                    Uuid::now_v7(),
                    "session",
                    None,
                    None,
                    None,
                    crate::send_user_message_v2::SendUserMessageV2 {
                        client_submission_id: Uuid::new_v4(),
                        origin: Default::default(),
                        text: IMAGE_PART_SENTINEL.to_string(),
                        display_text: None,
                        tag_expansions: Vec::new(),
                        forced_skill: None,
                        delivery_class_override: None,
                        resolved_delivery_class: None,
                        resolved_queue_target: None,
                        attachments: vec![crate::send_user_message_v2::MessageAttachmentIdentity {
                            attachment_id,
                            attachment_version: 1,
                            checksum: [7; 32],
                            kind: cockpit_db::media_attachments::MediaKind::Image,
                        }],
                    },
                ),
            },
        );
        let json = serde_json::to_value(&env).unwrap();
        let params = &json["params"];
        assert!(params.get("image_refs").is_none());
        let attachments = &params["ingress"]["request"]["attachments"];
        assert!(attachments.is_array());
        assert_eq!(attachments[0]["attachment_id"], attachment_id.to_string());
        assert!(
            !serde_json::to_string(attachments)
                .unwrap()
                .contains("[1,2,3]")
        );
    }

    /// Replaces `attachment_chunk_frame_stays_below_max_frame_with_headroom`.
    ///
    /// The retired test asserted only `json.len() < MAX_FRAME_BYTES / 4`, i.e.
    /// under 2 MiB of an 8 MiB budget. That bound is four times the bulk lane's
    /// 512 KiB logical payload cap, so it passed for every frame that could
    /// starve authorization, cancellation, or terminal input — it could not
    /// have caught the behaviour this prompt exists to fix. The corrected
    /// expectation is the lane cap itself, and the pre-migration constants fail
    /// it.
    #[cfg(feature = "remote")]
    #[test]
    fn remote_transport_correct_legacy_frame_tests_first() {
        use remote_transport::lane::{MAX_LOGICAL_PAYLOAD_BYTES, RemoteLane};

        // The 8 MiB frame budget is gone; the settled successor is 1 MiB.
        assert_eq!(MAX_NDJSON_FRAME_BYTES, 1_048_576);
        assert_eq!(MAX_NDJSON_FRAME_BYTES, 1024 * 1024);
        const { assert!(MAX_NDJSON_FRAME_BYTES < 8 * 1024 * 1024) };

        let data_base64 = "A".repeat(MAX_ATTACHMENT_CHUNK_BASE64_BYTES);
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::UploadAttachmentChunk {
                upload_id: Uuid::new_v4(),
                offset: 0,
                data_base64,
            },
        );
        let json = serde_json::to_string(&env).unwrap();

        // The old assertion is still satisfied — which is exactly why it was
        // worthless: it cannot distinguish a compliant frame from one four
        // times the lane cap.
        assert!(json.len() < 2 * 1024 * 1024);

        // Corrected: an attachment chunk fits one bulk-lane logical payload,
        // so it occupies exactly one scheduled frame and cannot monopolise
        // the carrier.
        assert!(json.len() <= MAX_LOGICAL_PAYLOAD_BYTES);
        assert!(json.len() <= RemoteLane::Bulk.max_payload_bytes());
        assert!(json.len() < MAX_NDJSON_FRAME_BYTES);

        // Proof the old production behaviour fails the corrected assertion:
        // the pre-migration 512 KiB base64 chunk plus its envelope exceeded
        // the lane cap.
        let legacy_env = Envelope::request(
            Uuid::new_v4(),
            Request::UploadAttachmentChunk {
                upload_id: Uuid::new_v4(),
                offset: 0,
                data_base64: "A".repeat(512 * 1024),
            },
        );
        let legacy_json = serde_json::to_string(&legacy_env).unwrap();
        assert!(
            legacy_json.len() > MAX_LOGICAL_PAYLOAD_BYTES,
            "the retired 512 KiB base64 chunk must exceed the 512 KiB lane cap"
        );
        // It also would not have fit the successor NDJSON cap's headroom rule
        // once base64 inflation is accounted for at the old 8 MiB sizes.
        assert!(legacy_json.len() < MAX_NDJSON_FRAME_BYTES);
    }

    #[test]
    fn event_round_trip() {
        let sid = Uuid::new_v4();
        let env = Envelope::event(Event::AssistantTextDelta {
            session_id: sid,
            agent: "builder".into(),
            delta: "patch ".into(),
        });
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::AssistantTextDelta {
                        session_id,
                        agent,
                        delta,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(agent, "builder");
                assert_eq!(delta, "patch ");
            }
            other => panic!("expected AssistantTextDelta, got {other:?}"),
        }
    }

    #[test]
    fn error_without_id_omits_id_key() {
        let env = Envelope::error(
            None,
            ErrorPayload {
                code: ErrorCode::Shutdown,
                message: "daemon shutting down".into(),
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        let value: Value = serde_json::from_str(&s).unwrap();
        assert!(value.get("id").is_none());
        let back: Envelope = serde_json::from_str(&s).unwrap();
        assert!(matches!(
            back.body,
            Body::Error {
                id: None,
                error: ErrorPayload {
                    code: ErrorCode::Shutdown,
                    ..
                }
            }
        ));
    }

    #[test]
    fn session_live_status_round_trip() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SessionLiveStatus {
                session_ids: vec![a, b],
            },
        );
        let s = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Request {
                request: Request::SessionLiveStatus { session_ids },
                ..
            } => assert_eq!(session_ids, vec![a, b]),
            other => panic!("expected SessionLiveStatus, got {other:?}"),
        }

        // Response side.
        let res = Envelope::response(
            Uuid::new_v4(),
            Response::SessionLiveStatus {
                statuses: vec![LiveStatus {
                    session_id: a,
                    has_active_schedules: true,
                    processing: false,
                    project_root: None,
                }],
            },
        );
        let s = serde_json::to_string(&res).unwrap();
        let back: Envelope = serde_json::from_str(&s).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::SessionLiveStatus { statuses } => {
                    assert_eq!(statuses.len(), 1);
                    assert!(statuses[0].has_active_schedules);
                    assert!(!statuses[0].processing);
                }
                other => panic!("expected SessionLiveStatus response, got {other:?}"),
            },
            other => panic!("expected SessionLiveStatus response, got {other:?}"),
        }
    }

    #[test]
    fn set_caffeinate_round_trip() {
        use super::CaffeinateMode;

        // Request side: each mode survives the wire.
        for mode in [
            CaffeinateMode::Toggle,
            CaffeinateMode::On,
            CaffeinateMode::Off,
            CaffeinateMode::UntilIdle,
        ] {
            let env = Envelope::request(Uuid::new_v4(), Request::SetCaffeinate { mode });
            let s = serde_json::to_string(&env).unwrap();
            let back: Envelope = serde_json::from_str(&s).unwrap();
            match back.body {
                Body::Request {
                    request: Request::SetCaffeinate { mode: got },
                    ..
                } => assert_eq!(got, mode),
                other => panic!("expected SetCaffeinate, got {other:?}"),
            }
        }
        // `until-idle` serializes as snake_case `until_idle`.
        let env = Envelope::request(
            Uuid::new_v4(),
            Request::SetCaffeinate {
                mode: CaffeinateMode::UntilIdle,
            },
        );
        let v: Value = serde_json::from_str(&serde_json::to_string(&env).unwrap()).unwrap();
        assert_eq!(v["params"]["mode"], json!("until_idle"));

        // Response side carries the honest message + lid-close flag.
        let res = Envelope::response(
            Uuid::new_v4(),
            Response::CaffeinateState {
                active: true,
                lid_close_guaranteed: false,
                message: "caffeinate on — note: lid-close not guaranteed".into(),
            },
        );
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&res).unwrap()).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::CaffeinateState {
                    active,
                    lid_close_guaranteed,
                    message,
                } => {
                    assert!(active);
                    assert!(!lid_close_guaranteed);
                    assert!(message.contains("note:"));
                }
                other => panic!("expected CaffeinateState response, got {other:?}"),
            },
            other => panic!("expected CaffeinateState response, got {other:?}"),
        }

        // Event side is the daemon-global broadcast (no session_id, no
        // message for non-originating clients).
        let evt = Envelope::event(Event::CaffeinateState {
            active: false,
            lid_close_guaranteed: false,
            message: None,
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::CaffeinateState {
                        active, message, ..
                    },
            } => {
                assert!(!active);
                assert!(message.is_none());
            }
            other => panic!("expected CaffeinateState event, got {other:?}"),
        }
    }

    /// The `WaitingForLock` event (`readlock-wait-and-lock-expiry.md`
    /// historical prompt slug) is a per-session transient: it carries
    /// `session_id`, the contended `path`, the `holder_agent`, and the
    /// `waiting` start/clear flag, and survives a wire roundtrip intact.
    #[test]
    fn waiting_for_lock_event_roundtrips() {
        let sid = Uuid::new_v4();
        let evt = Envelope::event(Event::WaitingForLock {
            session_id: sid,
            path: "/repo/src/main.rs".to_string(),
            holder_agent: "builder".to_string(),
            waiting: true,
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::WaitingForLock {
                        session_id,
                        path,
                        holder_agent,
                        waiting,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(path, "/repo/src/main.rs");
                assert_eq!(holder_agent, "builder");
                assert!(waiting);
            }
            other => panic!("expected WaitingForLock event, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_unavailable_event_round_trips_with_remedy() {
        // §6.5: the user-facing sandbox-down broadcast carries the session_id
        // and the diagnosed remedy verbatim across the wire.
        let sid = Uuid::new_v4();
        let remedy = "unprivileged user namespaces are restricted by AppArmor (Ubuntu 23.10+); \
             `sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0` re-enables confinement";
        let evt = Envelope::event(Event::SandboxUnavailable {
            session_id: sid,
            remedy: remedy.into(),
            fix_command: Some(
                "sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0".to_string(),
            ),
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::SandboxUnavailable {
                        session_id,
                        remedy: r,
                        fix_command,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(r, remedy);
                assert_eq!(
                    fix_command.as_deref(),
                    Some("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
                );
            }
            other => panic!("expected SandboxUnavailable event, got {other:?}"),
        }
    }

    #[test]
    fn command_capability_unavailable_event_round_trips_with_fix_command() {
        let sid = Uuid::new_v4();
        let text = "Required command capability unavailable: `demo` missing for `tool`.";
        let fix_command = "sudo apt-get install demo";
        let evt = Envelope::event(Event::CommandCapabilityUnavailable {
            session_id: sid,
            text: text.to_string(),
            fix_command: Some(fix_command.to_string()),
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&evt).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::CommandCapabilityUnavailable {
                        session_id,
                        text: got_text,
                        fix_command: got_fix_command,
                    },
            } => {
                assert_eq!(session_id, sid);
                assert_eq!(got_text, text);
                assert_eq!(got_fix_command.as_deref(), Some(fix_command));
            }
            other => panic!("expected CommandCapabilityUnavailable event, got {other:?}"),
        }
    }

    #[test]
    fn interrupt_question_serializes_as_tagged() {
        let q = InterruptQuestion::Single {
            prompt: "Backfill strategy?".into(),
            options: vec![
                InterruptOption {
                    id: "now".into(),
                    label: "Backfill now".into(),
                    description: None,
                    secondary: false,
                },
                InterruptOption {
                    id: "later".into(),
                    label: "Defer".into(),
                    description: None,
                    secondary: false,
                },
            ],
            allow_freetext: true,
            command_detail: None,
            permission: false,
            approval_class: None,
            sandbox_escalation: None,
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["kind"], json!("single"));
        assert_eq!(v["data"]["options"].as_array().unwrap().len(), 2);
        // A `None` command_detail is omitted from the wire (back-compat).
        assert!(v["data"].get("command_detail").is_none());
        // A `false` permission is omitted (back-compat: un-annotated `Single`
        // is a question).
        assert!(v["data"].get("permission").is_none());
    }

    #[test]
    fn permission_flag_round_trips_and_is_additive() {
        // A permission `Single` serializes the flag; a legacy shape (no
        // `permission` key) deserializes to `false` (a question).
        let q = InterruptQuestion::Single {
            prompt: "Run `cargo build`?".into(),
            options: vec![InterruptOption {
                id: "once".into(),
                label: "Yes, once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            command_detail: None,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["data"]["permission"], json!(true));
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single { permission, .. } => assert!(permission),
            other => panic!("expected Single, got {other:?}"),
        }
        // Legacy shape (no `permission` field) deserializes to `false`.
        let legacy = json!({
            "kind": "single",
            "data": { "prompt": "?", "options": [], "allow_freetext": false }
        });
        let back: InterruptQuestion = serde_json::from_value(legacy).unwrap();
        match back {
            InterruptQuestion::Single { permission, .. } => assert!(!permission),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn command_detail_round_trips_and_is_additive() {
        // A populated command_detail survives the wire and an old-shape
        // `Single` (no command_detail key) still deserializes.
        let q = InterruptQuestion::Single {
            prompt: "Run `cargo build`?".into(),
            options: vec![InterruptOption {
                id: "once".into(),
                label: "Yes, once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            permission: true,
            approval_class: None,
            sandbox_escalation: None,
            command_detail: Some(Box::new(CommandDetail {
                full_command: "git push && cargo build".into(),
                highlight: Some(CharSpan { start: 11, end: 22 }),
                step: 2,
                step_count: 2,
                cwd: None,
                remembered_key: None,
                write_content: None,
                risk_tier: None,
                risk_reasons: Vec::new(),
                affected_targets: Vec::new(),
                native_tool_hints: Vec::new(),
                offered_scopes: Vec::new(),
                policy_cap: None,
                image_plan_review: None,
            })),
        };
        let s = serde_json::to_string(&q).unwrap();
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single { command_detail, .. } => {
                let cd = command_detail.expect("command_detail survives");
                assert_eq!(cd.full_command, "git push && cargo build");
                assert_eq!(cd.highlight, Some(CharSpan { start: 11, end: 22 }));
                assert_eq!((cd.step, cd.step_count), (2, 2));
            }
            other => panic!("expected Single, got {other:?}"),
        }

        // Legacy shape (no command_detail field) deserializes to `None`.
        let legacy = json!({
            "kind": "single",
            "data": {
                "prompt": "Run `ls`?",
                "options": [{ "id": "once", "label": "Yes, once" }],
                "allow_freetext": false
            }
        });
        let back: InterruptQuestion = serde_json::from_value(legacy).unwrap();
        match back {
            InterruptQuestion::Single { command_detail, .. } => {
                assert!(command_detail.is_none());
            }
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[test]
    fn sandbox_escalation_round_trips_and_is_additive() {
        // A populated sandbox_escalation survives the wire; an old-shape
        // `Single` (no key) deserializes to `None` (a first-time approval).
        let q = InterruptQuestion::Single {
            prompt: "Re-run `cargo test` without the sandbox?".into(),
            options: vec![InterruptOption {
                id: "once".into(),
                label: "Yes, once".into(),
                description: None,
                secondary: false,
            }],
            allow_freetext: false,
            permission: true,
            approval_class: None,
            command_detail: None,
            sandbox_escalation: Some(SandboxEscalation {
                confined_exit: 101,
                confined_stderr: "permission denied".into(),
                suggested_paths: vec!["/var/cache/tool".into()],
                suggested_access: Some("read-write".into()),
                denial: None,
            }),
        };
        let s = serde_json::to_string(&q).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["data"]["sandbox_escalation"]["confined_exit"], json!(101));
        assert_eq!(
            v["data"]["sandbox_escalation"]["suggested_paths"],
            json!(["/var/cache/tool"])
        );
        assert_eq!(
            v["data"]["sandbox_escalation"]["suggested_access"],
            json!("read-write")
        );
        let back: InterruptQuestion = serde_json::from_str(&s).unwrap();
        match back {
            InterruptQuestion::Single {
                sandbox_escalation, ..
            } => {
                let esc = sandbox_escalation.expect("sandbox_escalation survives");
                assert_eq!(esc.confined_exit, 101);
                assert_eq!(esc.confined_stderr, "permission denied");
                assert_eq!(esc.suggested_paths, vec!["/var/cache/tool"]);
                assert_eq!(esc.suggested_access.as_deref(), Some("read-write"));
            }
            other => panic!("expected Single, got {other:?}"),
        }

        // Legacy shape (no sandbox_escalation field) → None (first-time).
        let legacy = json!({
            "kind": "single",
            "data": {
                "prompt": "Run `ls`?",
                "options": [{ "id": "once", "label": "Yes, once" }],
                "allow_freetext": false
            }
        });
        let back: InterruptQuestion = serde_json::from_value(legacy).unwrap();
        match back {
            InterruptQuestion::Single {
                sandbox_escalation, ..
            } => assert!(sandbox_escalation.is_none()),
            other => panic!("expected Single, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn codec_round_trip_over_duplex() {
        let (a, b) = duplex(64 * 1024);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        let id = Uuid::new_v4();
        let out = Envelope::request(id, Request::DaemonStatus);
        left.send(&out).await.unwrap();

        let got = right.recv().await.unwrap().expect("EOF unexpected");
        let RecvFrame::Envelope(got) = got else {
            panic!("expected envelope, got {got:?}");
        };
        match got.body {
            Body::Request {
                id: got_id,
                request: Request::DaemonStatus,
                ..
            } => assert_eq!(got_id, id),
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[test]
    fn unknown_variant_request_tag_deserializes_to_catch_all() {
        let request: Request = serde_json::from_value(json!({
            "request": "definitely_not_a_real_request",
        }))
        .unwrap();
        assert!(matches!(request, Request::Unknown));
    }

    #[test]
    fn unknown_variant_event_tag_deserializes_to_catch_all() {
        let event: Event = serde_json::from_value(json!({
            "event": "future_event",
        }))
        .unwrap();
        assert!(matches!(event, Event::Unknown));
    }

    #[test]
    fn unknown_variant_body_kind_deserializes_to_catch_all() {
        let env: Envelope = serde_json::from_value(json!({
            "v": PROTOCOL_VERSION,
            "kind": "future_kind",
            "id": Uuid::new_v4(),
        }))
        .unwrap();
        assert!(matches!(env.body, Body::Unknown));
    }

    #[tokio::test]
    async fn unknown_variant_recv_yields_unknown_frame_with_tag_and_id() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        let id = Uuid::new_v4();
        left.send_raw_line(
            serde_json::to_string(&json!({
                "v": PROTOCOL_VERSION,
                "kind": "req",
                "id": id,
                "request": "definitely_not_a_real_request",
                "params": { "future": true },
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::Unknown {
                v,
                kind,
                tag,
                id: got_id,
            } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(kind, "req");
                assert_eq!(tag.as_deref(), Some("definitely_not_a_real_request"));
                assert_eq!(got_id, Some(id));
            }
            other => panic!("expected unknown frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_variant_recv_still_errors_on_malformed_json() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.send_raw_line("{not json".to_string()).await.unwrap();

        let error = right
            .recv()
            .await
            .expect_err("malformed JSON remains fatal");
        assert!(
            error.to_string().contains("deserializing envelope"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn unknown_variant_recv_still_errors_on_known_variant_with_bad_params() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.send_raw_line(
            serde_json::to_string(&json!({
                "v": PROTOCOL_VERSION,
                "kind": "req",
                "id": Uuid::new_v4(),
                "request": "read_history_page",
                "params": {
                    "session_id": 7,
                    "limit": 25,
                },
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        let error = right
            .recv()
            .await
            .expect_err("known bad params remain fatal");
        assert!(
            error.to_string().contains("deserializing envelope"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn unknown_variant_recv_yields_unknown_frame_for_unknown_error_code() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        let id = Uuid::new_v4();
        left.send_raw_line(
            serde_json::to_string(&json!({
                "v": PROTOCOL_VERSION,
                "kind": "err",
                "id": id,
                "error": {
                    "code": "future_error",
                    "message": "future error shape"
                },
            }))
            .unwrap(),
        )
        .await
        .unwrap();

        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::Unknown {
                v,
                kind,
                tag,
                id: got_id,
            } => {
                assert_eq!(v, PROTOCOL_VERSION);
                assert_eq!(kind, "err");
                assert_eq!(tag.as_deref(), Some("future_error"));
                assert_eq!(got_id, Some(id));
            }
            other => panic!("expected unknown frame, got {other:?}"),
        }
    }

    #[test]
    fn queued_user_message_wire_shapes_round_trip() {
        let session_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let item = QueueItem {
            id: item_id,
            status: QueueItemStatus::Queued,
            text: "queued text".to_string(),
            display_text: Some("queued @file".to_string()),
            target: QueueTarget {
                id: "root".to_string(),
                agent: "Build".to_string(),
                depth: 0,
                task_call_id: None,
            },
            delivery_class: QueueDeliveryClass::Held,
            send_now: false,
        };

        let response = Envelope::response(
            Uuid::new_v4(),
            Response::UserMessageQueued {
                item: item.clone(),
                queue: vec![item.clone()],
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::UserMessageQueued { item: got, queue } => {
                    assert_eq!(got.id, item_id);
                    assert_eq!(got.status, QueueItemStatus::Queued);
                    assert_eq!(got.display_text.as_deref(), Some("queued @file"));
                    assert_eq!(got.target.id, "root");
                    assert_eq!(got.delivery_class, QueueDeliveryClass::Held);
                    assert_eq!(queue.len(), 1);
                }
                other => panic!("unexpected response: {other:?}"),
            },
            other => panic!("unexpected response: {other:?}"),
        }

        let event = Envelope::event(Event::QueueUpdated {
            session_id,
            queue: vec![item.clone()],
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::QueueUpdated {
                        session_id: got_session,
                        queue,
                    },
            } => {
                assert_eq!(got_session, session_id);
                assert_eq!(queue[0].id, item_id);
                assert_eq!(queue[0].target.agent, "Build");
                assert_eq!(queue[0].delivery_class, QueueDeliveryClass::Held);
            }
            other => panic!("unexpected event: {other:?}"),
        }

        let event = Envelope::event(Event::ForegroundInputTarget {
            session_id,
            target: QueueTarget {
                id: "task:call-1:default".to_string(),
                agent: "Explore".to_string(),
                depth: 1,
                task_call_id: Some("call-1".to_string()),
            },
        });
        let back: Envelope = serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        match back.body {
            Body::Event {
                event:
                    Event::ForegroundInputTarget {
                        session_id: got_session,
                        target,
                    },
            } => {
                assert_eq!(got_session, session_id);
                assert_eq!(target.id, "task:call-1:default");
                assert_eq!(target.agent, "Explore");
                assert_eq!(target.task_call_id.as_deref(), Some("call-1"));
            }
            other => panic!("unexpected foreground event: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::RemoveQueuedUserMessage {
                queue_item_id: item_id,
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::RemoveQueuedUserMessage { queue_item_id },
                ..
            } => assert_eq!(queue_item_id, item_id),
            other => panic!("unexpected request: {other:?}"),
        }

        let edit_operation_id = Uuid::new_v4();
        let request = Envelope::request(
            Uuid::new_v4(),
            Request::SetQueuedUserMessageClass {
                queue_item_id: item_id,
                delivery_class: QueueDeliveryClass::Held,
                replacement: Some(QueueItemReplacement {
                    operation_id: edit_operation_id,
                    action: QueueEditAction::Reserve,
                    text: "editable".to_string(),
                    display_text: None,
                    tag_expansions: Vec::new(),
                }),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request:
                    Request::SetQueuedUserMessageClass {
                        replacement: Some(replacement),
                        ..
                    },
                ..
            } => {
                assert_eq!(replacement.operation_id, edit_operation_id);
                assert_eq!(replacement.action, QueueEditAction::Reserve);
            }
            other => panic!("unexpected edit reservation: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::RemoveNewestQueuedUserMessage {
                target_id: Some("root".to_string()),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::RemoveNewestQueuedUserMessage { target_id },
                ..
            } => assert_eq!(target_id.as_deref(), Some("root")),
            other => panic!("unexpected request: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::SetQueuedUserMessageClass {
                queue_item_id: item_id,
                delivery_class: QueueDeliveryClass::Held,
                replacement: None,
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request:
                    Request::SetQueuedUserMessageClass {
                        queue_item_id,
                        delivery_class,
                        replacement: _,
                    },
                ..
            } => {
                assert_eq!(queue_item_id, item_id);
                assert_eq!(delivery_class, QueueDeliveryClass::Held);
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::PromoteQueuedUserMessages {
                delivery_class: QueueDeliveryClass::Steering,
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::PromoteQueuedUserMessages { delivery_class },
                ..
            } => assert_eq!(delivery_class, QueueDeliveryClass::Steering),
            other => panic!("unexpected request: {other:?}"),
        }

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::SendNowQueuedUserMessage {
                queue_item_id: Some(item_id),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::SendNowQueuedUserMessage { queue_item_id },
                ..
            } => assert_eq!(queue_item_id, Some(item_id)),
            other => panic!("unexpected request: {other:?}"),
        }

        let whole_queue = Envelope::request(
            Uuid::new_v4(),
            Request::SendNowQueuedUserMessage {
                queue_item_id: None,
            },
        );
        let json = serde_json::to_value(&whole_queue).unwrap();
        assert!(json["params"].get("queue_item_id").is_none());
        let back: Envelope = serde_json::from_value(json).unwrap();
        assert!(matches!(
            back.body,
            Body::Request {
                request: Request::SendNowQueuedUserMessage {
                    queue_item_id: None
                },
                ..
            }
        ));

        let missing_class: QueueItem = serde_json::from_value(serde_json::json!({
            "id": item_id,
            "status": "queued",
            "text": "legacy",
            "target": { "id": "root", "agent": "Build", "depth": 0 }
        }))
        .unwrap();
        assert_eq!(missing_class.delivery_class, QueueDeliveryClass::Steering);
        assert!(!missing_class.send_now);

        let request = Envelope::request(
            Uuid::new_v4(),
            Request::RemoveEditableQueuedUserMessages {
                target_id: Some("root".to_string()),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&request).unwrap()).unwrap();
        match back.body {
            Body::Request {
                request: Request::RemoveEditableQueuedUserMessages { target_id },
                ..
            } => assert_eq!(target_id.as_deref(), Some("root")),
            other => panic!("unexpected request: {other:?}"),
        }

        let response = Envelope::response(
            Uuid::new_v4(),
            Response::RemoveQueuedUserMessagesResult {
                applied: true,
                reason: RemoveQueuedUserMessageReason::Removed,
                removed_items: vec![item.clone()],
                queue: Vec::new(),
            },
        );
        let back: Envelope =
            serde_json::from_str(&serde_json::to_string(&response).unwrap()).unwrap();
        match back.body {
            Body::Response { response, .. } => match *response {
                Response::RemoveQueuedUserMessagesResult {
                    applied,
                    reason,
                    removed_items,
                    queue,
                } => {
                    assert!(applied);
                    assert_eq!(reason, RemoveQueuedUserMessageReason::Removed);
                    assert_eq!(removed_items[0].id, item_id);
                    assert!(queue.is_empty());
                }
                other => panic!("unexpected response: {other:?}"),
            },
            other => panic!("unexpected frame: {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_salvages_out_of_range_request() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        // Bypass the helper to inject a bad version.
        let id = Uuid::new_v4();
        let bad = serde_json::json!({
            "v": 999,
            "kind": "req",
            "id": id,
            "request": "daemon_status",
            "params": null,
        });
        let line = serde_json::to_string(&bad).unwrap();
        left.framed.send(line).await.unwrap();
        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::VersionMismatch {
                v,
                kind,
                id: got_id,
            } => {
                assert_eq!(v, 999);
                assert_eq!(kind, "req");
                assert_eq!(got_id, Some(id));
            }
            other => panic!("expected version mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn recv_salvages_out_of_range_event_without_id() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        let bad = serde_json::json!({
            "v": 999,
            "kind": "evt",
            "event": "notice",
            "data": { "message": "hi" },
        });
        left.framed
            .send(serde_json::to_string(&bad).unwrap())
            .await
            .unwrap();
        match right.recv().await.unwrap().expect("frame") {
            RecvFrame::VersionMismatch { v, kind, id } => {
                assert_eq!(v, 999);
                assert_eq!(kind, "evt");
                assert_eq!(id, None);
            }
            other => panic!("expected version mismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn v10_only_request_is_not_sent_to_v9_daemon() {
        let (a, _b) = duplex(4096);
        let mut v9 = ProtoStream::with_version(a, 9);
        let request = Envelope::request(
            Uuid::new_v4(),
            Request::ListSecretInventory {
                cursor: None,
                limit: Some(32),
            },
        );
        let error = v9
            .send(&request)
            .await
            .expect_err("v10-only payload must be gated on a v9 connection");
        assert!(error.to_string().contains("requires v10"));
        assert!(error.to_string().contains("daemon restart"));
    }

    #[tokio::test]
    async fn v17_provider_credential_receipt_is_not_sent_to_v9_daemon() {
        let (a, _b) = duplex(4096);
        let mut v9 = ProtoStream::with_version(a, 9);
        let response = Envelope::response(
            Uuid::new_v4(),
            Response::ProviderCredentialCommitted {
                client_operation_id: "put-provider".into(),
                mutation_intent_hash: "00".repeat(32),
                provider_id: "example".into(),
                project_root: None,
                owner_root: None,
                owner_scope: "global".into(),
                stored: true,
                changed: true,
                consumed_vault_generation: 6,
                result_vault_generation: 7,
                config_generation: 7,
            },
        );
        let error = v9
            .send(&response)
            .await
            .expect_err("v17 response must be gated on a v9 connection");
        assert!(error.to_string().contains("provider_credential_committed"));
        assert!(error.to_string().contains("requires v17"));
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_request_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        let forged = Envelope {
            v: 9,
            body: Body::Request {
                id,
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::ListSecretInventory {
                    cursor: None,
                    limit: Some(32),
                },
            },
        };
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_response_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        let forged = Envelope::response_at(
            9,
            id,
            Response::ProviderCredentialCommitted {
                client_operation_id: "put-provider".into(),
                mutation_intent_hash: "00".repeat(32),
                provider_id: "example".into(),
                project_root: None,
                owner_root: None,
                owner_scope: "global".into(),
                stored: true,
                changed: true,
                consumed_vault_generation: 6,
                result_vault_generation: 7,
                config_generation: 7,
            },
        );
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_list_sessions_assistant_filter_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        // The base list_sessions tag is v9-compatible, but the
        // assistant_id filter field is a v10-only extended shape.
        let forged = Envelope {
            v: 9,
            body: Body::Request {
                id,
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::ListSessions {
                    project_id: None,
                    parent_session_id: None,
                    assistant_id: Some("helper-bot".into()),
                },
            },
        };
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[test]
    fn list_sessions_assistant_filter_requires_v10() {
        // The base shape (assistant_id = None) is v9-compatible.
        assert_eq!(
            body_required_protocol_version(&Body::Request {
                id: Uuid::nil(),
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::ListSessions {
                    project_id: None,
                    parent_session_id: None,
                    assistant_id: None,
                },
            })
            .0,
            9
        );
        // The extended shape (assistant_id = Some) requires v10.
        assert_eq!(
            body_required_protocol_version(&Body::Request {
                id: Uuid::nil(),
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::ListSessions {
                    project_id: None,
                    parent_session_id: None,
                    assistant_id: Some("helper-bot".into()),
                },
            })
            .0,
            10
        );
    }

    #[test]
    fn current_protocol_gates_provider_catalog_leak_and_oauth_cancellation() {
        let provider_requests = [
            (
                Request::GetProviderCatalogSnapshot {
                    project_root: "/project".into(),
                    provider_id: None,
                    snapshot_session_id: "snapshot".into(),
                },
                15,
            ),
            (
                Request::ApplyProviderMutation {
                    snapshot_session_id: "snapshot".into(),
                    layer_id: "layer".into(),
                    expected_revision: "revision".into(),
                    client_operation_id: "operation".into(),
                    mutation_intent_hash: "00".repeat(32),
                    mutation: ProviderMutationBatch {
                        upserts: Vec::new(),
                        deletes: Vec::new(),
                        metadata: None,
                    },
                },
                17,
            ),
        ];
        for (request, expected_version) in provider_requests {
            assert_eq!(
                body_required_protocol_version(&Body::Request {
                    id: Uuid::nil(),
                    #[cfg(feature = "remote")]
                    operation: None,
                    request,
                })
                .0,
                expected_version
            );
        }
        for (response, expected_version) in [
            (
                Response::ProviderCatalogSnapshot {
                    config: ProviderConfigView::default(),
                    snapshot_session_id: "snapshot".into(),
                    layer_id: "layer".into(),
                    owner_root: "/project".into(),
                    base_revision: "revision".into(),
                    config_generation: 1,
                },
                17,
            ),
            (
                Response::ProviderMutationCommitted {
                    client_operation_id: "operation".into(),
                    snapshot_session_id: "snapshot".into(),
                    layer_id: "layer".into(),
                    owner_root: "/project".into(),
                    mutation_intent_hash: "00".repeat(32),
                    consumed_revision: "revision".into(),
                    result_revision: "next".into(),
                    config_generation: 2,
                    config: ProviderConfigView::default(),
                    status: ConfigCommitStatus::Committed,
                    publication: ConfigPublicationStatus::Published,
                },
                17,
            ),
        ] {
            assert_eq!(
                body_required_protocol_version(&Body::Response {
                    id: Uuid::nil(),
                    response: Box::new(response),
                })
                .0,
                expected_version
            );
        }

        assert_eq!(
            body_required_protocol_version(&Body::Request {
                id: Uuid::nil(),
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::CancelLeakReveal {
                    capability: LeakRevealToken::new("00".repeat(32)),
                },
            })
            .0,
            16
        );
        assert_eq!(
            body_required_protocol_version(&Body::Request {
                id: Uuid::nil(),
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::CancelProviderOAuth {
                    client_operation_id: "cancel".into(),
                    begin_client_operation_id: "begin".into(),
                    flow_id: Some("flow".into()),
                },
            })
            .0,
            17
        );
        assert_eq!(
            body_required_protocol_version(&Body::Response {
                id: Uuid::nil(),
                response: Box::new(Response::LeakRevealCancelled {
                    report_id: "report".into(),
                }),
            })
            .0,
            16
        );
    }

    #[test]
    fn redacted_export_request_response_and_reader_require_v10() {
        // #3: even the DEFAULT (redacted) export request is v10-only now — it
        // returns the v10-only `redacted_export` bulk kind and requires the
        // v10-only reader — so a v9 peer is refused rather than handed an
        // undecodable enum value / an unreadable transfer.
        let default_export = Request::ExportSessionData {
            session_id: Uuid::nil(),
            kind: ExportSessionKind::DebugBundle,
            include_generated_artifacts: false,
            include_sensitive: false,
        };
        assert_eq!(
            body_required_protocol_version(&Body::Request {
                id: Uuid::nil(),
                #[cfg(feature = "remote")]
                operation: None,
                request: default_export,
            })
            .0,
            10,
            "the default redacted export request must be v10-only"
        );

        let reader = Request::ReadRedactedExportChunk {
            transfer_id: crate::bulk_transfer::transfer_id_from_bytes([3u8; 16]).unwrap(),
            chunk_index: 0,
        };
        assert_eq!(
            body_required_protocol_version(&Body::Request {
                id: Uuid::nil(),
                #[cfg(feature = "remote")]
                operation: None,
                request: reader,
            })
            .0,
            10
        );

        let transfer_id = crate::bulk_transfer::transfer_id_from_bytes([7u8; 16]).unwrap();
        let response = Response::ExportSessionData {
            data: ExportSessionData {
                session_id: Uuid::nil(),
                kind: ExportSessionKind::TranscriptJson,
                filename_extension: "json".into(),
                mime: "application/json".into(),
                transfer: crate::bulk_transfer::BulkTransferRef::new(
                    transfer_id,
                    5,
                    [0u8; 32],
                    crate::bulk_transfer::BulkMimeClass::RedactedExport,
                )
                .unwrap(),
                session_count: Some(1),
                redacted: true,
            },
        };
        assert_eq!(
            body_required_protocol_version(&Body::Response {
                id: Uuid::nil(),
                response: Box::new(response),
            })
            .0,
            10,
            "the export response carrying redacted_export must be v10-only"
        );
    }

    #[test]
    fn durable_owner_receipts_and_mutations_require_v17() {
        for request in [
            Request::PutProviderCredential {
                client_operation_id: "put-provider".into(),
                provider_id: "example".into(),
                record: SensitiveWirePayload::new("{}".into()),
            },
            Request::DeleteProviderCredential {
                client_operation_id: "delete-provider".into(),
                provider_id: "example".into(),
                project_root: None,
            },
            Request::GetLocalOperationSettlement {
                client_operation_id: "settlement".into(),
            },
            Request::SaveMcpConfig {
                client_operation_id: "save-mcp".into(),
                project_root: "/tmp/project".into(),
                snapshot_capability: "snapshot".into(),
                owner_root: "/tmp/project".into(),
                config_path: "/tmp/project/.cockpit/mcp.json".into(),
                expected_revision: "00".repeat(32),
                mutation_intent_hash: "11".repeat(32),
                patch: r#"{"operations":[]}"#.into(),
                secret_values_json: SensitiveWirePayload::new("{}".into()),
                target_scope: None,
            },
            Request::ApplyExtendedConfigPatch {
                client_operation_id: "patch-config".into(),
                project_root: "/tmp/project".into(),
                layer_id: "layer".into(),
                patch: ExtendedConfigPatch {
                    operations: Vec::new(),
                    materialize: true,
                    denylist: Vec::new(),
                    redacted_mutations: Vec::new(),
                },
                expected_revision: "00".repeat(32),
                snapshot_session_id: "snapshot".into(),
            },
            Request::BeginProviderOAuth {
                client_operation_id: "begin-provider".into(),
                provider_id: "codex-oauth".into(),
            },
            Request::CompleteProviderOAuth {
                client_operation_id: "complete-provider".into(),
                flow_id: "flow".into(),
                input: None,
            },
            Request::CancelProviderOAuth {
                client_operation_id: "cancel-provider".into(),
                begin_client_operation_id: "begin-provider".into(),
                flow_id: Some("flow".into()),
            },
            Request::BeginMcpOAuth {
                client_operation_id: "begin-mcp".into(),
                project_root: "/tmp/project".into(),
                server: "server".into(),
                profile: String::new(),
                agent: None,
            },
            Request::CompleteMcpOAuth {
                client_operation_id: "complete-mcp".into(),
                flow_id: "flow".into(),
                input: None,
            },
            Request::CancelMcpOAuth {
                client_operation_id: "cancel-mcp".into(),
                begin_client_operation_id: "begin-mcp".into(),
                flow_id: Some("flow".into()),
            },
            #[cfg(feature = "extended")]
            Request::SaveImageSpendPolicy {
                client_operation_id: "save-image-spend".into(),
                project_key: "project".into(),
                settings_json: "{}".into(),
                expected_policy_version: None,
            },
            Request::SetupCopilotAuth {
                client_operation_id: "setup-copilot".into(),
                project_root: "/tmp/project".into(),
                provider_id: "copilot".into(),
            },
            Request::BeginAgentEditorLease {
                client_operation_id: "begin-editor".into(),
                project_root: "/tmp/project".into(),
                name: "build".into(),
                expected_revision: "00".repeat(32),
            },
            Request::CompleteAgentEditorLease {
                client_operation_id: "complete-editor".into(),
                project_root: "/tmp/project".into(),
                lease_id: Uuid::nil().to_string(),
                markdown: Some(SensitiveWirePayload::new(
                    "---\nschemaVersion: 2\n---\nBe helpful.\n".into(),
                )),
            },
            Request::GetAgentEditorLeaseSettlement {
                client_operation_id: "complete-editor".into(),
                project_root: "/tmp/project".into(),
                lease_id: Uuid::nil().to_string(),
            },
            Request::MutateAgent {
                client_operation_id: "mutate-agent".into(),
                mutation_intent_hash: agent_mutation_intent_hash(
                    "/tmp/project",
                    &AgentMutation::ResetAllBuiltins,
                    Some(&"00".repeat(32)),
                ),
                project_root: "/tmp/project".into(),
                mutation: AgentMutation::ResetAllBuiltins,
                expected_revision: Some("00".repeat(32)),
            },
            Request::SaveAssistantDefinition {
                client_operation_id: "save-assistant".into(),
                mutation_intent_hash: assistant_mutation_intent_hash(
                    "/tmp/project",
                    "save",
                    "build",
                    &"00".repeat(32),
                    Some("# build"),
                ),
                project_root: "/tmp/project".into(),
                name: "build".into(),
                markdown: "# build".into(),
                expected_revision: "00".repeat(32),
                expected_config_generation: 7,
            },
            Request::DeleteAssistant {
                client_operation_id: "delete-assistant".into(),
                mutation_intent_hash: assistant_mutation_intent_hash(
                    "/tmp/project",
                    "delete",
                    "build",
                    &"00".repeat(32),
                    None,
                ),
                project_root: "/tmp/project".into(),
                name: "build".into(),
                expected_revision: "00".repeat(32),
                expected_config_generation: 7,
            },
        ] {
            assert_eq!(
                body_required_protocol_version(&Body::Request {
                    id: Uuid::nil(),
                    #[cfg(feature = "remote")]
                    operation: None,
                    request,
                })
                .0,
                17
            );
        }
        for response in [
            Response::ProviderOAuthStarted {
                client_operation_id: "begin-provider".into(),
                request_hash: "00".repeat(32),
                flow_id: "flow".into(),
                authorize_url: "https://example.test".into(),
                user_code: None,
            },
            Response::ProviderOAuthCompleted {
                client_operation_id: "complete-provider".into(),
                request_hash: "00".repeat(32),
                flow_id: "flow".into(),
                logged_in: true,
                retry_after_seconds: None,
            },
            Response::ProviderOAuthCancelled {
                client_operation_id: "cancel-provider".into(),
                request_hash: "00".repeat(32),
                flow_id: Some("flow".into()),
                cancelled: true,
            },
            Response::McpOAuthStarted {
                client_operation_id: "begin-mcp".into(),
                request_hash: "00".repeat(32),
                flow_id: "flow".into(),
                authorize_url: "https://example.test".into(),
                user_code: None,
                verification_uri: None,
                verification_uri_complete: None,
            },
            Response::McpOAuthCompleted {
                client_operation_id: "complete-mcp".into(),
                request_hash: "00".repeat(32),
                flow_id: "flow".into(),
                authenticated: true,
            },
            Response::McpOAuthCancelled {
                client_operation_id: "cancel-mcp".into(),
                request_hash: "00".repeat(32),
                flow_id: Some("flow".into()),
                cancelled: true,
            },
            Response::McpConfigCommitted {
                client_operation_id: "save-mcp".into(),
                request_hash: "22".repeat(32),
                mutation_intent_hash: "33".repeat(32),
                project_root: "/workspace".into(),
                owner_root: "/workspace".into(),
                config_path: "/workspace/.cockpit/mcp.json".into(),
                consumed_revision: "00".repeat(32),
                result_revision: "11".repeat(32),
                config_generation: 7,
                credential_count: 0,
            },
            #[cfg(feature = "extended")]
            Response::ImageSpendPolicySaved {
                client_operation_id: "save-image-spend".into(),
                project_key: "project".into(),
                request_hash: "99".repeat(32),
                consumed_policy_version: None,
                result_policy_version: 1,
            },
            Response::ProviderCredentialCommitted {
                client_operation_id: "delete-provider".into(),
                mutation_intent_hash: "22".repeat(32),
                provider_id: "example".into(),
                project_root: None,
                owner_root: None,
                owner_scope: "global".into(),
                stored: false,
                changed: true,
                consumed_vault_generation: 6,
                result_vault_generation: 7,
                config_generation: 7,
            },
            Response::SubscriptionAckCommitted {
                client_operation_id: "subscription-ack".into(),
                provider_id: "codex-oauth".into(),
                request_hash: "33".repeat(32),
                changed: true,
                consumed_vault_generation: 6,
                result_vault_generation: 7,
            },
            Response::ExtendedConfigSaved {
                client_operation_id: "patch-config".into(),
                request_hash: "44".repeat(32),
                mutation_intent_hash: "45".repeat(32),
                hash: "55".repeat(32),
                config_generation: 7,
                layer_id: "layer".into(),
                layer: CockpitConfigLayer::Project,
                consumed_revision: "66".repeat(32),
                result_revision: "77".repeat(32),
                status: ConfigCommitStatus::Committed,
                publication: ConfigPublicationStatus::Published,
                denylist: Vec::new(),
            },
            Response::CopilotAuthCommitted {
                client_operation_id: "setup-copilot".into(),
                mutation_intent_hash: "78".repeat(32),
                project_root: "/tmp/project".into(),
                owner_root: "/tmp/project".into(),
                owner_scope: "project:/tmp/project".into(),
                provider_id: "copilot".into(),
                consumed_vault_generation: 6,
                result_vault_generation: 7,
                config_generation: 7,
            },
            Response::LocalOperationSettlement {
                client_operation_id: "settlement".into(),
                operation_kind: "save_mcp_config".into(),
                request_hash: "88".repeat(32),
                pending: true,
                response: None,
                terminal_error: None,
                terminal_cancelled: false,
            },
            Response::AgentMutated(AgentMutationResult {
                client_operation_id: "mutate-agent".into(),
                mutation_intent_hash: "98".repeat(32),
                project_root: "/tmp/project".into(),
                requested_project_root: "/tmp/project".into(),
                owner_scope: "project:/tmp/project".into(),
                agent_name: None,
                changed: true,
                affected: 1,
                snapshot: None,
                consumed_config_generation: 6,
                result_config_generation: 7,
                config_generation: 7,
                inventory_revision: Some("99".repeat(32)),
                consumed_revision: Some("00".repeat(32)),
                result_revision: "99".repeat(32),
                completed_lease_id: None,
                outcome: AgentMutationOutcome::Reconciled,
            }),
            Response::AssistantDefinitionSaved {
                client_operation_id: "save-assistant".into(),
                mutation_intent_hash: "aa".repeat(32),
                project_root: "/tmp/project".into(),
                requested_project_root: "/tmp/project".into(),
                name: "build".into(),
                assistant: None,
                consumed_revision: "00".repeat(32),
                result_revision: "11".repeat(32),
                consumed_config_generation: 6,
                result_config_generation: 7,
                outcome: AgentMutationOutcome::Reconciled,
            },
            Response::AssistantDeleted {
                client_operation_id: "delete-assistant".into(),
                mutation_intent_hash: "bb".repeat(32),
                project_root: "/tmp/project".into(),
                requested_project_root: "/tmp/project".into(),
                name: "build".into(),
                consumed_revision: "00".repeat(32),
                result_revision: "22".repeat(32),
                consumed_config_generation: 6,
                result_config_generation: 7,
                outcome: AgentMutationOutcome::Reconciled,
            },
        ] {
            assert_eq!(
                body_required_protocol_version(&Body::Response {
                    id: Uuid::nil(),
                    response: Box::new(response),
                })
                .0,
                17
            );
        }
    }

    #[test]
    fn every_new_cli_surface_shape_requires_v10() {
        #[cfg_attr(not(feature = "remote"), allow(unused_mut))]
        let mut requests: Vec<Request> = vec![
            Request::ListPackages,
            Request::AddPackage {
                project_root: "/tmp/project".into(),
                identifier: "tokio".into(),
                git: None,
                branch: None,
                local_path: Some("/tmp/pkg".into()),
                deep: false,
            },
            Request::ImportPackage {
                project_root: "/tmp/project".into(),
                dir: Some("deps".into()),
                package: None,
                id: None,
                as_path: false,
            },
            Request::PrunePackages {
                project_root: "/tmp/project".into(),
                days: 30,
                dry_run: false,
            },
            Request::ImportKclPackages {
                project_root: "/tmp/project".into(),
            },
            Request::ListFailedToolCalls {
                since_epoch: 0,
                tool: None,
                model: None,
                project_id: None,
                include_recovered: false,
                limit: 50,
            },
            Request::GetSessionCompactions {
                session_id: Uuid::nil(),
            },
            Request::PurgeEndedSessions { before: 0 },
            Request::GetAssistant {
                name: "helper-bot".into(),
            },
            Request::DiagnoseMediaReservation {
                scope: "session".into(),
                id: "abc".into(),
            },
            Request::RepairMediaReservation {
                scope: "session".into(),
                id: "abc".into(),
                expected_block_generation: 1,
                repair_plan_digest: "digest".into(),
                idempotency_key: "key".into(),
            },
            Request::GetDoctorSnapshot {
                project_root: None,
                no_sandbox: false,
                offline: false,
            },
            Request::DocsAsk {
                question: "how do tasks work?".into(),
                package: Some("tokio".into()),
                project_root: None,
            },
        ];
        #[cfg(feature = "remote")]
        {
            requests.extend([Request::GetConnectorState, Request::GetOrgSyncStatus]);
        }
        for request in requests {
            let tag = request.wire_tag();
            assert_eq!(
                body_required_protocol_version(&Body::Request {
                    id: Uuid::nil(),
                    #[cfg(feature = "remote")]
                    operation: None,
                    request,
                })
                .0,
                10,
                "{tag} must be gated to v10"
            );
        }
        #[cfg_attr(not(feature = "remote"), allow(unused_mut))]
        let mut responses: Vec<Response> = vec![
            Response::Packages {
                packages_json: "[]".into(),
            },
            Response::PackageAdded {
                package_json: "{}".into(),
            },
            Response::PackageImported {
                summary_json: "{}".into(),
            },
            Response::PackagesPruned {
                report_json: "{}".into(),
            },
            Response::KclPackagesImported {
                result_json: "{}".into(),
            },
            Response::FailedToolCalls {
                calls_json: "[]".into(),
            },
            Response::SessionCompactions {
                session_id: Uuid::nil(),
                compactions_json: "[]".into(),
            },
            Response::EndedSessionsPurged {
                purged: 0,
                session_ids_json: "[]".into(),
            },
            Response::Assistant { assistant: None },
            Response::MediaReservationDiagnosis {
                diagnosis_json: "{}".into(),
            },
            Response::MediaReservationRepaired {
                outcome: "accounting_repair_committed".into(),
            },
            Response::DoctorSnapshot {
                rendered: String::new(),
                has_failures: false,
            },
            Response::DocsAnswer {
                answer: String::new(),
            },
        ];
        #[cfg(feature = "remote")]
        {
            responses.extend([
                Response::ConnectorState {
                    connector_json: "null".into(),
                },
                Response::OrgSyncStatus {
                    org_states_json: "[]".into(),
                    audit_states_json: "[]".into(),
                },
            ]);
        }
        for response in responses {
            let tag = response.wire_tag();
            assert_eq!(
                body_required_protocol_version(&Body::Response {
                    id: Uuid::nil(),
                    response: Box::new(response),
                })
                .0,
                10,
                "{tag} must be gated to v10"
            );
        }
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_get_doctor_snapshot_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        let forged = Envelope {
            v: 9,
            body: Body::Request {
                id,
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::GetDoctorSnapshot {
                    project_root: None,
                    no_sandbox: false,
                    offline: false,
                },
            },
        };
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_docs_ask_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        let forged = Envelope {
            v: 9,
            body: Body::Request {
                id,
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::DocsAsk {
                    question: "how do tasks work?".into(),
                    package: Some("tokio".into()),
                    project_root: None,
                },
            },
        };
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[test]
    fn every_new_sealed_owner_shape_requires_v10() {
        // AC1/AC3: every new sealed-owner request and response shape is gated to
        // protocol v10 (a v9 envelope carrying it is rejected — see the
        // `recv_rejects_v10_only_*` test below).
        for request in [
            Request::BeginSealedOwnerOperation {
                disposition: "create".into(),
                record_id: None,
                name: Some("token".into()),
                description: Some("safe".into()),
                scope_kind: Some("global".into()),
                scope_key: Some(String::new()),
            },
            Request::ApplySealedOwnerOperation {
                capability_id: "cap".into(),
                literal: Some(SensitiveWireLiteral::new("s3cr3t".into())),
            },
            Request::CancelSealedOwnerOperation {
                capability_id: "cap".into(),
            },
            Request::SealedOwnerInventory {
                scope_kind: None,
                scope_key: None,
            },
            Request::EditSealedOwnerDescription {
                record_id: "rec".into(),
                description: "desc".into(),
            },
            Request::ListSealedActions,
            Request::CreateSealedAction {
                kind_id: "k".into(),
                project_id: "p".into(),
                description: "d".into(),
                origin_id: "0".into(),
                projection_id: "none".into(),
            },
            Request::ReviseSealedActionDescription {
                action_id: "a".into(),
                description: "d".into(),
            },
            Request::ReviseSealedActionEnabled {
                action_id: "a".into(),
                enabled: false,
            },
            Request::RetireSealedAction {
                action_id: "a".into(),
                confirm: "a".into(),
            },
        ] {
            let tag = request.wire_tag();
            assert_eq!(
                body_required_protocol_version(&Body::Request {
                    id: Uuid::nil(),
                    #[cfg(feature = "remote")]
                    operation: None,
                    request,
                })
                .0,
                10,
                "{tag} must be gated to v10"
            );
        }
        for response in [
            Response::SealedOwnerOperationBegun {
                capability_id: "cap".into(),
                expires_at_ms: 1,
            },
            Response::SealedOwnerOperationApplied {
                revealed_literal: Some(SensitiveWireLiteral::new("s3cr3t".into())),
            },
            Response::SealedOwnerOperationCancelled { spent: true },
            Response::SealedOwnerInventory { items: Vec::new() },
            Response::SealedOwnerDescriptionEdited {
                record_id: "rec".into(),
            },
            Response::SealedActions {
                actions: Vec::new(),
            },
            Response::SealedActionCreated {
                action_id: "a".into(),
                revision: 1,
            },
            Response::SealedActionRevised {
                action_id: "a".into(),
                revision: 2,
            },
            Response::SealedActionRetired {
                action_id: "a".into(),
                retired: true,
            },
        ] {
            let tag = response.wire_tag();
            assert_eq!(
                body_required_protocol_version(&Body::Response {
                    id: Uuid::nil(),
                    response: Box::new(response),
                })
                .0,
                10,
                "{tag} must be gated to v10"
            );
        }
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_apply_sealed_owner_operation_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        let forged = Envelope {
            v: 9,
            body: Body::Request {
                id,
                #[cfg(feature = "remote")]
                operation: None,
                request: Request::ApplySealedOwnerOperation {
                    capability_id: "cap".into(),
                    literal: Some(SensitiveWireLiteral::new("s3cr3t".into())),
                },
            },
        };
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[tokio::test]
    async fn recv_rejects_v10_only_docs_answer_labeled_as_v9() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 9);
        let mut receiver = ProtoStream::with_version(b, 9);
        let id = Uuid::new_v4();
        let forged = Envelope::response_at(
            9,
            id,
            Response::DocsAnswer {
                answer: "cited answer".into(),
            },
        );
        sender
            .framed
            .send(serde_json::to_string(&forged).unwrap())
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 9, id: Some(actual), .. }) if actual == id
        ));
    }

    #[tokio::test]
    async fn v10_request_is_rejected_after_the_current_only_v21_cutover() {
        let (a, b) = duplex(4096);
        let mut sender = ProtoStream::with_version(a, 10);
        let mut receiver = ProtoStream::with_version(b, 10);
        sender
            .send(&Envelope::request(
                Uuid::new_v4(),
                Request::ListSecretInventory {
                    cursor: None,
                    limit: Some(32),
                },
            ))
            .await
            .unwrap();
        assert!(matches!(
            receiver.recv().await.unwrap(),
            Some(RecvFrame::VersionMismatch { v: 10, .. })
        ));
    }

    #[test]
    fn modes_session_setup_entry_mode_has_exact_three_value_wire_contract() {
        assert_eq!(
            serde_json::to_value(SessionEntryMode::Code).unwrap(),
            "code"
        );
        assert_eq!(
            serde_json::to_value(SessionEntryMode::Assistant).unwrap(),
            "assistant"
        );
        assert_eq!(
            serde_json::to_value(SessionEntryMode::Computer).unwrap(),
            "computer"
        );
        assert!(serde_json::from_value::<SessionEntryMode>(json!("unknown")).is_err());
    }

    #[tokio::test]
    async fn recv_rejects_non_object_and_missing_v() {
        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);

        left.framed.send("[]".to_string()).await.unwrap();
        assert!(right.recv().await.is_err());

        let (a, b) = duplex(4096);
        let mut left = ProtoStream::new(a);
        let mut right = ProtoStream::new(b);
        left.framed
            .send(r#"{"kind":"req","request":"daemon_status"}"#.to_string())
            .await
            .unwrap();
        assert!(right.recv().await.is_err());
    }

    #[test]
    fn is_protocol_compatible_window() {
        assert!(is_protocol_compatible(MIN_SUPPORTED_PROTOCOL_VERSION));
        assert!(is_protocol_compatible(PROTOCOL_VERSION));
        assert!(!is_protocol_compatible(PROTOCOL_VERSION + 1));
        if MIN_SUPPORTED_PROTOCOL_VERSION > 0 {
            assert!(!is_protocol_compatible(MIN_SUPPORTED_PROTOCOL_VERSION - 1));
        }
    }

    #[test]
    fn config_refreshed_response_is_frozen_in_current_fixture() {
        assert_eq!(PROTOCOL_VERSION, 21);
        assert_eq!(MIN_SUPPORTED_PROTOCOL_VERSION, 21);
        let fixture = proto_fixture_files::read_fixture("response.json");
        let response: Response = serde_json::from_value(
            fixture
                .get("config_refreshed")
                .expect("current v21 config_refreshed fixture")
                .clone(),
        )
        .unwrap();
        assert!(matches!(
            response,
            Response::ConfigRefreshed {
                applied_generation: 3,
                changed: true
            }
        ));
    }

    #[test]
    fn goal_summary_cap_is_present_in_every_current_response_fixture() {
        assert_eq!(PROTOCOL_VERSION, 21);
        assert_eq!(MIN_SUPPORTED_PROTOCOL_VERSION, 21);
        let fixture = proto_fixture_files::read_fixture("response.json");

        for response_name in ["goal_status", "goal_updated"] {
            let response = fixture
                .get(response_name)
                .unwrap_or_else(|| panic!("current v21 {response_name} fixture"));
            assert_eq!(
                response["data"]["goal"]["max_verification_attempts"], 4,
                "current v21 {response_name} must freeze the inclusive verification cap"
            );
            serde_json::from_value::<Response>(response.clone()).unwrap_or_else(|error| {
                panic!("current v21 {response_name} must deserialize: {error}")
            });
        }
    }

    #[test]
    fn assistant_registration_revision_is_present_in_current_response_fixtures() {
        let fixture = proto_fixture_files::read_fixture("response.json");
        for response_name in ["assistant_upserted", "assistant_definition_saved"] {
            let summary: AssistantSummary =
                serde_json::from_value(fixture[response_name]["data"]["assistant"].clone())
                    .unwrap();
            validate_assistant_summary(&summary).unwrap_or_else(|error| {
                panic!("current v21 {response_name} assistant identity is invalid: {error}")
            });
        }
        let summary: AssistantSummary =
            serde_json::from_value(fixture["assistants"]["data"]["assistants"][0].clone()).unwrap();
        validate_assistant_summary(&summary)
            .expect("current v21 assistant inventory must carry bounded opaque revisions");
        assert_eq!(fixture["assistants"]["data"]["config_generation"], 7);
        assert_eq!(
            fixture["agent_inventory"]["data"]["config_generation"],
            fixture["assistants"]["data"]["config_generation"]
        );
        assert_eq!(
            fixture["agent_inventory"]["data"]["project_root"],
            fixture["agent_inventory"]["data"]["requested_project_root"]
        );
    }

    #[test]
    fn authority_commit_receipts_are_frozen_in_current_response_fixtures() {
        let fixture = proto_fixture_files::read_fixture("response.json");
        let denylist = &fixture["extended_config_saved"]["data"]["denylist"];
        assert_eq!(
            denylist[0]["consumed_entry_id"],
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );
        assert!(denylist[0]["client_nonce"].is_null());
        assert!(denylist[1]["consumed_entry_id"].is_null());
        assert_eq!(
            denylist[1]["client_nonce"],
            "33333333-3333-4333-8333-333333333333"
        );
        assert_eq!(
            fixture["agent_mutated"]["data"]["outcome"]["status"],
            "reconciled"
        );
        for receipt in ["assistant_definition_saved", "assistant_deleted"] {
            let data = &fixture[receipt]["data"];
            assert!(data["client_operation_id"].is_string());
            assert_eq!(data["mutation_intent_hash"].as_str().unwrap().len(), 64);
            assert!(data["project_root"].is_string());
            assert!(data["requested_project_root"].is_string());
            assert!(data["name"].is_string());
            assert!(data["consumed_revision"].is_string());
            assert!(data["result_revision"].is_string());
            assert!(
                data["result_config_generation"].as_u64().unwrap()
                    > data["consumed_config_generation"].as_u64().unwrap()
            );
        }
        let agent = &fixture["agent_mutated"]["data"];
        assert!(agent["client_operation_id"].is_string());
        assert_eq!(
            agent["mutation_intent_hash"].as_str().map(str::len),
            Some(64)
        );
        assert!(agent["project_root"].is_string());
        assert!(agent["requested_project_root"].is_string());
        assert_eq!(agent["owner_scope"], "project:/tmp/project");
        assert!(agent["result_revision"].is_string());
        assert_eq!(agent["consumed_config_generation"], 7);
        assert_eq!(agent["result_config_generation"], 8);
        assert_eq!(agent["config_generation"], 8);
        assert_eq!(
            fixture["agent_editor_lease_completed"]["data"]["status"]["outcome"]["status"],
            "reconciled"
        );
    }

    #[test]
    fn oauth_v17_receipts_are_correlated_and_recoverable() {
        let requests = proto_fixture_files::read_fixture("request.json");
        for tag in [
            "begin_provider_oauth",
            "complete_provider_oauth",
            "cancel_provider_oauth",
            "begin_mcp_oauth",
            "complete_mcp_oauth",
            "cancel_mcp_oauth",
        ] {
            assert!(requests[tag]["params"]["client_operation_id"].is_string());
        }
        let mcp = &requests["save_mcp_config"]["params"];
        for field in [
            "snapshot_capability",
            "owner_root",
            "config_path",
            "expected_revision",
            "mutation_intent_hash",
        ] {
            assert!(
                mcp[field].is_string(),
                "current v21 MCP CAS fixture must carry {field}"
            );
        }
        assert_eq!(mcp["expected_revision"].as_str().map(str::len), Some(64));
        assert_eq!(mcp["mutation_intent_hash"].as_str().map(str::len), Some(64));
        let patch: McpConfigPatch = serde_json::from_str(
            mcp["patch"]
                .as_str()
                .expect("MCP patch must use the zeroizing wire envelope"),
        )
        .expect("current MCP patch fixture must be typed");
        assert!(!patch.operations.is_empty());
        assert!(mcp.get("config_json").is_none());
        assert!(mcp.get("cleanup_names_json").is_none());
        for tag in ["cancel_provider_oauth", "cancel_mcp_oauth"] {
            assert!(requests[tag]["params"]["begin_client_operation_id"].is_string());
        }

        let responses = proto_fixture_files::read_fixture("response.json");
        for tag in [
            "provider_oauth_started",
            "provider_oauth_completed",
            "provider_oauth_cancelled",
            "mcp_oauth_started",
            "mcp_oauth_completed",
            "mcp_oauth_cancelled",
        ] {
            assert!(responses[tag]["data"]["client_operation_id"].is_string());
            assert_eq!(
                responses[tag]["data"]["request_hash"]
                    .as_str()
                    .map(str::len),
                Some(64)
            );
        }
    }

    #[test]
    fn settings_v17_receipts_bind_exact_operations_and_content() {
        let requests = proto_fixture_files::read_fixture("request.json");
        for tag in [
            "put_provider_credential",
            "delete_provider_credential",
            "save_mcp_config",
            "apply_extended_config_patch",
            "get_local_operation_settlement",
            "setup_copilot_auth",
        ] {
            assert!(
                requests[tag]["params"]["client_operation_id"].is_string(),
                "current v21 fixture must carry an operation id for {tag}"
            );
        }
        let responses = proto_fixture_files::read_fixture("response.json");
        let receipt = &responses["extended_config_saved"]["data"];
        assert!(receipt["client_operation_id"].is_string());
        assert_eq!(receipt["request_hash"].as_str().map(str::len), Some(64));
        let mcp = &responses["mcp_config_committed"]["data"];
        assert_eq!(mcp["request_hash"].as_str().map(str::len), Some(64));
    }

    #[test]
    fn editor_v17_settlement_is_correlated_and_document_free() {
        let requests = proto_fixture_files::read_fixture("request.json");
        for tag in [
            "complete_agent_editor_lease",
            "get_agent_editor_lease_settlement",
        ] {
            assert!(requests[tag]["params"]["client_operation_id"].is_string());
            assert!(requests[tag]["params"]["lease_id"].is_string());
        }
        assert!(requests["complete_agent_editor_lease"]["params"]["markdown"].is_string());
        assert!(
            requests["get_agent_editor_lease_settlement"]["params"]
                .get("markdown")
                .is_none()
        );

        let responses = proto_fixture_files::read_fixture("response.json");
        let begun = &responses["agent_editor_lease_begun"]["data"];
        assert!(begun["client_operation_id"].is_string());
        let receipt = &responses["agent_editor_lease_completed"]["data"];
        assert!(receipt["client_operation_id"].is_string());
        assert!(receipt["lease_id"].is_string());
        assert!(receipt["consumed_revision"].is_string());
        assert_eq!(receipt["consumed_config_generation"], 7);
        assert_eq!(receipt["result_config_generation"], 8);
        assert!(receipt["status"]["result_revision"].is_string());
        assert!(receipt.get("markdown").is_none());
        assert!(receipt.get("snapshot").is_none());
    }

    #[test]
    fn archived_fixtures_are_retained_but_not_in_the_live_compatibility_window() {
        for version in ARCHIVED_PROTOCOL_VERSIONS.iter().copied() {
            assert!(
                version < MIN_SUPPORTED_PROTOCOL_VERSION,
                "archived fixture v{version} must remain older than the live support window"
            );
            assert!(!is_protocol_compatible(version));
            let archived = proto_fixture_files::read_fixture_for(version, "response.json");
            assert!(archived.contains_key("config_refreshed"));
            assert!(archived.contains_key("goal_status"));
            assert!(archived.contains_key("goal_updated"));
        }
    }
}
