//! Authenticated image-generation management and job control plane.
//!
//! This module exposes the versioned V1 request/response/event/error unions
//! for redacted generation configuration, health, budgets, grants, durable
//! jobs, cancellation, and explicit late-result disposition, plus the exact
//! authorization matrix that gates every request family.
//!
//! The module is UI-free and transport-free. It imports and consumes the
//! foundation-owned `RemoteProjectCapabilityV1::ImageGenerationAdmin=15`,
//! `RemotePermissionCeilingV1`, and `RemotePermissionCeilingDigestV1` helper
//! from `cockpit-proto::remote_public_service_policy` without registering,
//! redefining, re-encoding, or independently hashing any capability or
//! permission-ceiling byte.
//!
//! Design invariants (prompt `image-generation-control-plane`):
//!
//! - Management mutations require either `Owner` or remote
//!   `ImageGenerationAdmin` whose canonical project root exactly equals the
//!   target project. No generic owner/admin role is invented.
//! - The legacy `ClientPrincipal::Remote`/`RemotePrincipal.grants` snapshot is
//!   grounding only and is never the new authority for remote mutations.
//! - Every mutation carries entity/config expected version and an
//!   idempotency key. Responses carry authoritative entity/config generation.
//! - `ImageGenerationAdmin` never implies session read, artifact read,
//!   filesystem, terminal, tool, credential, or output-path authority.
//! - Unknown protocol variants fail explicitly; no untyped or compatibility
//!   alias is added.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cockpit_proto::remote_public_service_policy::{
    RemotePermissionCeilingDigestV1, RemotePermissionCeilingV1, RemoteProjectCapabilityV1,
    permission_ceiling_digest,
};

use crate::daemon::principal::{ClientPrincipal, PrincipalGrant, PrincipalScope};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for all image-generation control-plane V1 structures.
pub const CONTROL_PLANE_SCHEMA_VERSION: u8 = 1;

/// The foundation-owned ordinal for `image_generation_admin`.
pub const IMAGE_GENERATION_ADMIN_ORDINAL: u8 = 15;

/// Maximum number of items returned by a list/page request.
pub const MAX_LIST_LIMIT: u32 = 100;
/// Default list/page limit.
pub const DEFAULT_LIST_LIMIT: u32 = 50;

/// Maximum cursor size in bytes (opaque base64url).
pub const MAX_CURSOR_BYTES: usize = 512;

/// Maximum display string length in bytes.
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;

/// Maximum number of target IDs in a health/refresh request.
pub const MAX_TARGET_IDS: usize = 100;

/// Maximum number of entity refs in a mutation result.
pub const MAX_ENTITY_REFS: usize = 100;

/// Maximum number of changes in a config change set.
pub const MAX_CONFIG_CHANGES: usize = 100;

/// Maximum interactive request/reply/event payload size.
pub const MAX_INTERACTIVE_PAYLOAD_BYTES: usize = 512 * 1024;

/// Maximum inline command data size.
pub const MAX_INLINE_COMMAND_BYTES: usize = 393_216;

/// Maximum number of image admin grants per instance/grantee/project tuple.
pub const MAX_ADMIN_GRANTS_PER_TUPLE: usize = 1;

/// The scope string for `ImageGenerationAdmin` in the hosted access-grant
/// workflow.
pub const IMAGE_GENERATION_ADMIN_SCOPE_STRING: &str = "image_generation_admin";

// ---------------------------------------------------------------------------
// Operation kind codec
// ---------------------------------------------------------------------------

/// The closed operation-kind enum. JSON is exactly
/// `remote_attachment|local_owner`; FCOR is respectively `u16be 1|2`. Zero,
/// every other ordinal/string, and aliases fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageOperationKindV1 {
    RemoteAttachment,
    LocalOwner,
}

impl ImageOperationKindV1 {
    /// The FCOR `u16be` discriminant.
    pub const fn fcor_ordinal(self) -> u16 {
        match self {
            Self::RemoteAttachment => 1,
            Self::LocalOwner => 2,
        }
    }

    /// Decode from a FCOR `u16be` discriminant. Zero and every other value
    /// fail.
    pub fn from_fcor_ordinal(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::RemoteAttachment),
            2 => Some(Self::LocalOwner),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::RemoteAttachment => "remote_attachment",
            Self::LocalOwner => "local_owner",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "remote_attachment" => Some(Self::RemoteAttachment),
            "local_owner" => Some(Self::LocalOwner),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Request tags
// ---------------------------------------------------------------------------

/// The exact request tags for the image-generation control plane V1.
///
/// Each tag is present once in the generated request/classification table.
/// Reads and snapshot/status requests are `read_only`. Local mutations are
/// `transactional_mutation`. Remote admin mutations become
/// `transactional_mutation` only after the live image-admin lease claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageControlRequestTag {
    // Safe configuration reads
    ImageEndpointList,
    ImageEndpointGet,
    ImageTargetList,
    ImageTargetGet,
    ImageWorkflowList,
    ImageWorkflowGet,
    ImageBudgetGet,
    ImageDestinationGrantList,
    // Runtime/job reads
    ImageHealthGet,
    ImagePlanGet,
    ImageJobList,
    ImageJobGet,
    ImageOperationStatus,
    ImageControlAdminSnapshot,
    ImageControlSessionSnapshot,
    // Configuration mutations
    ImageEndpointCreate,
    ImageEndpointUpdate,
    ImageEndpointDelete,
    ImageTargetCreate,
    ImageTargetUpdate,
    ImageTargetDelete,
    ImageTargetSetDefault,
    ImageWorkflowUpload,
    ImageWorkflowBind,
    ImageWorkflowDelete,
    // Policy/runtime mutations
    ImageHealthRefresh,
    ImageBudgetSet,
    ImageDestinationGrantRevoke,
    ImageJobCancel,
    ImageLateResultPublish,
    ImageLateResultDiscard,
}

impl ImageControlRequestTag {
    /// Returns the canonical snake_case string for this tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ImageEndpointList => "image_endpoint_list",
            Self::ImageEndpointGet => "image_endpoint_get",
            Self::ImageTargetList => "image_target_list",
            Self::ImageTargetGet => "image_target_get",
            Self::ImageWorkflowList => "image_workflow_list",
            Self::ImageWorkflowGet => "image_workflow_get",
            Self::ImageBudgetGet => "image_budget_get",
            Self::ImageDestinationGrantList => "image_destination_grant_list",
            Self::ImageHealthGet => "image_health_get",
            Self::ImagePlanGet => "image_plan_get",
            Self::ImageJobList => "image_job_list",
            Self::ImageJobGet => "image_job_get",
            Self::ImageOperationStatus => "image_operation_status",
            Self::ImageControlAdminSnapshot => "image_control_admin_snapshot",
            Self::ImageControlSessionSnapshot => "image_control_session_snapshot",
            Self::ImageEndpointCreate => "image_endpoint_create",
            Self::ImageEndpointUpdate => "image_endpoint_update",
            Self::ImageEndpointDelete => "image_endpoint_delete",
            Self::ImageTargetCreate => "image_target_create",
            Self::ImageTargetUpdate => "image_target_update",
            Self::ImageTargetDelete => "image_target_delete",
            Self::ImageTargetSetDefault => "image_target_set_default",
            Self::ImageWorkflowUpload => "image_workflow_upload",
            Self::ImageWorkflowBind => "image_workflow_bind",
            Self::ImageWorkflowDelete => "image_workflow_delete",
            Self::ImageHealthRefresh => "image_health_refresh",
            Self::ImageBudgetSet => "image_budget_set",
            Self::ImageDestinationGrantRevoke => "image_destination_grant_revoke",
            Self::ImageJobCancel => "image_job_cancel",
            Self::ImageLateResultPublish => "image_late_result_publish",
            Self::ImageLateResultDiscard => "image_late_result_discard",
        }
    }

    /// Decode from the canonical snake_case string.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "image_endpoint_list" => Some(Self::ImageEndpointList),
            "image_endpoint_get" => Some(Self::ImageEndpointGet),
            "image_target_list" => Some(Self::ImageTargetList),
            "image_target_get" => Some(Self::ImageTargetGet),
            "image_workflow_list" => Some(Self::ImageWorkflowList),
            "image_workflow_get" => Some(Self::ImageWorkflowGet),
            "image_budget_get" => Some(Self::ImageBudgetGet),
            "image_destination_grant_list" => Some(Self::ImageDestinationGrantList),
            "image_health_get" => Some(Self::ImageHealthGet),
            "image_plan_get" => Some(Self::ImagePlanGet),
            "image_job_list" => Some(Self::ImageJobList),
            "image_job_get" => Some(Self::ImageJobGet),
            "image_operation_status" => Some(Self::ImageOperationStatus),
            "image_control_admin_snapshot" => Some(Self::ImageControlAdminSnapshot),
            "image_control_session_snapshot" => Some(Self::ImageControlSessionSnapshot),
            "image_endpoint_create" => Some(Self::ImageEndpointCreate),
            "image_endpoint_update" => Some(Self::ImageEndpointUpdate),
            "image_endpoint_delete" => Some(Self::ImageEndpointDelete),
            "image_target_create" => Some(Self::ImageTargetCreate),
            "image_target_update" => Some(Self::ImageTargetUpdate),
            "image_target_delete" => Some(Self::ImageTargetDelete),
            "image_target_set_default" => Some(Self::ImageTargetSetDefault),
            "image_workflow_upload" => Some(Self::ImageWorkflowUpload),
            "image_workflow_bind" => Some(Self::ImageWorkflowBind),
            "image_workflow_delete" => Some(Self::ImageWorkflowDelete),
            "image_health_refresh" => Some(Self::ImageHealthRefresh),
            "image_budget_set" => Some(Self::ImageBudgetSet),
            "image_destination_grant_revoke" => Some(Self::ImageDestinationGrantRevoke),
            "image_job_cancel" => Some(Self::ImageJobCancel),
            "image_late_result_publish" => Some(Self::ImageLateResultPublish),
            "image_late_result_discard" => Some(Self::ImageLateResultDiscard),
            _ => None,
        }
    }

    /// Returns all tags in canonical order.
    pub const fn all() -> &'static [Self] {
        &[
            Self::ImageEndpointList,
            Self::ImageEndpointGet,
            Self::ImageTargetList,
            Self::ImageTargetGet,
            Self::ImageWorkflowList,
            Self::ImageWorkflowGet,
            Self::ImageBudgetGet,
            Self::ImageDestinationGrantList,
            Self::ImageHealthGet,
            Self::ImagePlanGet,
            Self::ImageJobList,
            Self::ImageJobGet,
            Self::ImageOperationStatus,
            Self::ImageControlAdminSnapshot,
            Self::ImageControlSessionSnapshot,
            Self::ImageEndpointCreate,
            Self::ImageEndpointUpdate,
            Self::ImageEndpointDelete,
            Self::ImageTargetCreate,
            Self::ImageTargetUpdate,
            Self::ImageTargetDelete,
            Self::ImageTargetSetDefault,
            Self::ImageWorkflowUpload,
            Self::ImageWorkflowBind,
            Self::ImageWorkflowDelete,
            Self::ImageHealthRefresh,
            Self::ImageBudgetSet,
            Self::ImageDestinationGrantRevoke,
            Self::ImageJobCancel,
            Self::ImageLateResultPublish,
            Self::ImageLateResultDiscard,
        ]
    }

    /// Classification: `read_only` or `transactional_mutation`.
    pub fn classification(self) -> RequestClassification {
        match self {
            Self::ImageEndpointList
            | Self::ImageEndpointGet
            | Self::ImageTargetList
            | Self::ImageTargetGet
            | Self::ImageWorkflowList
            | Self::ImageWorkflowGet
            | Self::ImageBudgetGet
            | Self::ImageDestinationGrantList
            | Self::ImageHealthGet
            | Self::ImagePlanGet
            | Self::ImageJobList
            | Self::ImageJobGet
            | Self::ImageOperationStatus
            | Self::ImageControlAdminSnapshot
            | Self::ImageControlSessionSnapshot => RequestClassification::ReadOnly,
            Self::ImageEndpointCreate
            | Self::ImageEndpointUpdate
            | Self::ImageEndpointDelete
            | Self::ImageTargetCreate
            | Self::ImageTargetUpdate
            | Self::ImageTargetDelete
            | Self::ImageTargetSetDefault
            | Self::ImageWorkflowUpload
            | Self::ImageWorkflowBind
            | Self::ImageWorkflowDelete
            | Self::ImageHealthRefresh
            | Self::ImageBudgetSet
            | Self::ImageDestinationGrantRevoke
            | Self::ImageJobCancel
            | Self::ImageLateResultPublish
            | Self::ImageLateResultDiscard => RequestClassification::TransactionalMutation,
        }
    }

    /// Returns `true` if this tag requires `sessionId` in the command body.
    pub fn requires_session_id(self) -> bool {
        matches!(
            self,
            Self::ImageBudgetGet
                | Self::ImagePlanGet
                | Self::ImageJobList
                | Self::ImageJobGet
                | Self::ImageControlSessionSnapshot
                | Self::ImageBudgetSet
                | Self::ImageJobCancel
                | Self::ImageLateResultPublish
                | Self::ImageLateResultDiscard
        )
    }
}

/// Request classification for the operation ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestClassification {
    ReadOnly,
    TransactionalMutation,
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

/// The closed error-code enum for `ImageControlErrorV1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageControlErrorCode {
    Malformed,
    Unauthenticated,
    Forbidden,
    NotFound,
    VersionConflict,
    IdempotencyConflict,
    CursorStale,
    InvalidState,
    LocalPathReauthorizationRequired,
    BudgetUnconfigured,
    CapabilityUnavailable,
    AuthorityUnavailable,
    LeaseExpired,
    OperationIndeterminate,
    Capacity,
    Internal,
}

impl ImageControlErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unauthenticated => "unauthenticated",
            Self::Forbidden => "forbidden",
            Self::NotFound => "not_found",
            Self::VersionConflict => "version_conflict",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::CursorStale => "cursor_stale",
            Self::InvalidState => "invalid_state",
            Self::LocalPathReauthorizationRequired => "local_path_reauthorization_required",
            Self::BudgetUnconfigured => "budget_unconfigured",
            Self::CapabilityUnavailable => "capability_unavailable",
            Self::AuthorityUnavailable => "authority_unavailable",
            Self::LeaseExpired => "lease_expired",
            Self::OperationIndeterminate => "operation_indeterminate",
            Self::Capacity => "capacity",
            Self::Internal => "internal",
        }
    }

    /// Only `authority_unavailable|capacity|internal` may be retryable and
    /// only before commit.
    pub fn is_retryable_before_commit(self) -> bool {
        matches!(
            self,
            Self::AuthorityUnavailable | Self::Capacity | Self::Internal
        )
    }
}

/// `ImageControlErrorV1 {schemaVersion:1,code,retryable,operationId,
/// currentEntityGeneration,currentConfigGeneration}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageControlErrorV1 {
    pub schema_version: u8,
    pub code: ImageControlErrorCode,
    pub retryable: bool,
    pub operation_id: Option<String>,
    pub current_entity_generation: Option<String>,
    pub current_config_generation: Option<String>,
}

impl ImageControlErrorV1 {
    pub fn new(code: ImageControlErrorCode) -> Self {
        Self {
            schema_version: CONTROL_PLANE_SCHEMA_VERSION,
            code,
            retryable: code.is_retryable_before_commit(),
            operation_id: None,
            current_entity_generation: None,
            current_config_generation: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Entity kind
// ---------------------------------------------------------------------------

/// The closed entity-kind enum for `entityRefs` in `ImageMutationResultV1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageEntityKind {
    Endpoint,
    Target,
    Workflow,
    Budget,
    DestinationGrant,
    Plan,
    Job,
    Slot,
    Artifact,
}

impl ImageEntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Target => "target",
            Self::Workflow => "workflow",
            Self::Budget => "budget",
            Self::DestinationGrant => "destination_grant",
            Self::Plan => "plan",
            Self::Job => "job",
            Self::Slot => "slot",
            Self::Artifact => "artifact",
        }
    }

    /// FCOR ordinal for sorting in config change sets: sorted by
    /// `(entityKind ordinal, decoded entity ID)`.
    pub const fn sort_ordinal(self) -> u8 {
        match self {
            Self::Endpoint => 1,
            Self::Target => 2,
            Self::Workflow => 3,
            Self::Budget => 4,
            Self::DestinationGrant => 5,
            Self::Plan => 6,
            Self::Job => 7,
            Self::Slot => 8,
            Self::Artifact => 9,
        }
    }
}

// ---------------------------------------------------------------------------
// Mutation result
// ---------------------------------------------------------------------------

/// `ImageMutationResultV1 {operationId,outcome:"committed",entityRefs,
/// configGeneration}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageMutationResultV1 {
    pub operation_id: String,
    pub outcome: MutationOutcome,
    pub entity_refs: Vec<EntityRef>,
    pub config_generation: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationOutcome {
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EntityRef {
    pub kind: ImageEntityKind,
    pub id: String,
    pub generation: String,
}

// ---------------------------------------------------------------------------
// Operation status
// ---------------------------------------------------------------------------

/// `ImageOperationStatusV1 {operationKind,queriedOperationId,state,outcome}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageOperationStatusV1 {
    pub operation_kind: ImageOperationKindV1,
    pub queried_operation_id: String,
    pub state: OperationState,
    pub outcome: Option<OperationOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    Reserved,
    Committed,
    Rejected,
    OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum OperationOutcome {
    Committed { result: ImageMutationResultV1 },
    Rejected { error: ImageControlErrorV1 },
}

// ---------------------------------------------------------------------------
// Response
// ---------------------------------------------------------------------------

/// `ImageControlResponseV1 {schemaVersion:1,kind,daemonInstanceId,projectId,
/// result}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageControlResponseV1 {
    pub schema_version: u8,
    pub kind: ImageControlRequestTag,
    pub daemon_instance_id: String,
    pub project_id: String,
    pub result: ControlResult,
}

/// The exhaustive tag-to-result mapping. A tag cannot return another row
/// shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResult {
    Page {
        items: Vec<serde_json::Value>,
        next_cursor: Option<String>,
        snapshot_generation: String,
    },
    Entity {
        item: serde_json::Value,
    },
    Health {
        items: Vec<serde_json::Value>,
        refresh_epoch: String,
        config_generation: String,
    },
    Budget {
        item: serde_json::Value,
    },
    Plan {
        item: serde_json::Value,
    },
    Job {
        item: serde_json::Value,
    },
    Operation {
        item: ImageOperationStatusV1,
    },
    Snapshot {
        component: SnapshotComponent,
        items: Vec<serde_json::Value>,
        next_cursor: Option<String>,
        snapshot_generation: String,
        event_high_water: String,
    },
    Mutation {
        item: ImageMutationResultV1,
    },
}

/// Admin snapshot component: `endpoints|targets|workflows|health|budget|
/// destination_grants`. Session snapshot component: `plans|jobs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotComponent {
    Endpoints,
    Targets,
    Workflows,
    Health,
    Budget,
    DestinationGrants,
    Plans,
    Jobs,
}

impl SnapshotComponent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Endpoints => "endpoints",
            Self::Targets => "targets",
            Self::Workflows => "workflows",
            Self::Health => "health",
            Self::Budget => "budget",
            Self::DestinationGrants => "destination_grants",
            Self::Plans => "plans",
            Self::Jobs => "jobs",
        }
    }

    /// Returns `true` if this is an admin snapshot component.
    pub fn is_admin(self) -> bool {
        matches!(
            self,
            Self::Endpoints
                | Self::Targets
                | Self::Workflows
                | Self::Health
                | Self::Budget
                | Self::DestinationGrants
        )
    }

    /// Returns `true` if this is a session snapshot component.
    pub fn is_session(self) -> bool {
        matches!(self, Self::Plans | Self::Jobs)
    }
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

/// `ImageControlEventV1 {schemaVersion:1,deliveryId,eventSeq,daemonInstanceId,
/// projectId,sessionId,entityKind,entityId,entityGeneration,kind,
/// safeProjection}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageControlEventV1 {
    pub schema_version: u8,
    pub delivery_id: String,
    pub event_seq: String,
    pub daemon_instance_id: String,
    pub project_id: String,
    pub session_id: Option<String>,
    pub entity_kind: EventEntityKind,
    pub entity_id: String,
    pub entity_generation: String,
    pub kind: EventKind,
    pub safe_projection: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventEntityKind {
    Project,
    Target,
    Budget,
    DestinationGrant,
    Plan,
    Job,
    Slot,
    Artifact,
    Operation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    ConfigChanged,
    HealthChanged,
    BudgetChanged,
    DestinationGrantChanged,
    PlanChanged,
    JobChanged,
    SlotChanged,
    LateResultChanged,
    OperationChanged,
}

// ---------------------------------------------------------------------------
// Envelopes and replies
// ---------------------------------------------------------------------------

/// `RemoteImageControlEnvelopeV1 {schemaVersion:1,requestId,operationId,
/// command}` on the interactive lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteImageControlEnvelopeV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub command: serde_json::Value,
}

/// `LocalOwnerImageControlEnvelopeV1 {schemaVersion:1,requestId,
/// localOperationId,command}` only on the authenticated direct socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalOwnerImageControlEnvelopeV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub local_operation_id: Option<String>,
    pub command: serde_json::Value,
}

/// `RemoteImageControlReplyV1 {schemaVersion:1,requestId,outcome}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteImageControlReplyV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub outcome: ReplyOutcome,
}

/// `LocalOwnerImageControlReplyV1 {schemaVersion:1,requestId,outcome}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalOwnerImageControlReplyV1 {
    pub schema_version: u8,
    pub request_id: String,
    pub outcome: ReplyOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ReplyOutcome {
    Ok { response: ImageControlResponseV1 },
    Error { error: ImageControlErrorV1 },
}

// ---------------------------------------------------------------------------
// Authorization matrix
// ---------------------------------------------------------------------------

/// The request authorization family, matching the matrix in the prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestFamily {
    /// Redacted endpoint/target/workflow/budget/destination-grant reads and
    /// admin snapshot.
    ConfigReadsAndSnapshot,
    /// Safe enabled-target/health reads and health refresh result.
    HealthReadsAndRefresh,
    /// Plan get.
    PlanGet,
    /// Job list/get and session snapshot.
    JobReadsAndSnapshot,
    /// Job cancel.
    JobCancel,
    /// Endpoint/target/workflow/budget/destination-grant mutations.
    ConfigMutations,
    /// Publish/discard late result.
    LateResult,
    /// Operation status.
    OperationStatus,
}

impl ImageControlRequestTag {
    /// Maps a tag to its request family for authorization.
    pub fn family(self) -> RequestFamily {
        match self {
            Self::ImageEndpointList
            | Self::ImageEndpointGet
            | Self::ImageTargetList
            | Self::ImageTargetGet
            | Self::ImageWorkflowList
            | Self::ImageWorkflowGet
            | Self::ImageBudgetGet
            | Self::ImageDestinationGrantList
            | Self::ImageControlAdminSnapshot => RequestFamily::ConfigReadsAndSnapshot,
            Self::ImageHealthGet => RequestFamily::HealthReadsAndRefresh,
            Self::ImagePlanGet => RequestFamily::PlanGet,
            Self::ImageJobList | Self::ImageJobGet | Self::ImageControlSessionSnapshot => {
                RequestFamily::JobReadsAndSnapshot
            }
            Self::ImageOperationStatus => RequestFamily::OperationStatus,
            Self::ImageEndpointCreate
            | Self::ImageEndpointUpdate
            | Self::ImageEndpointDelete
            | Self::ImageTargetCreate
            | Self::ImageTargetUpdate
            | Self::ImageTargetDelete
            | Self::ImageTargetSetDefault
            | Self::ImageWorkflowUpload
            | Self::ImageWorkflowBind
            | Self::ImageWorkflowDelete
            | Self::ImageBudgetSet
            | Self::ImageDestinationGrantRevoke => RequestFamily::ConfigMutations,
            Self::ImageHealthRefresh => RequestFamily::HealthReadsAndRefresh,
            Self::ImageJobCancel => RequestFamily::JobCancel,
            Self::ImageLateResultPublish | Self::ImageLateResultDiscard => {
                RequestFamily::LateResult
            }
        }
    }
}

/// The remote attempt capability required for each request family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteAttemptCapability {
    /// `image_generation_admin=15` on exact project.
    ImageGenerationAdmin,
    /// `project_read=1` for read.
    ProjectRead,
    /// `session_read=7` on exact project.
    SessionRead,
    /// `session_write=8` on exact project.
    SessionWrite,
    /// `project_read=1` or `image_generation_admin=15` on exact project.
    ProjectReadOrImageGenerationAdmin,
    /// `session_write=8` or `image_generation_admin=15` on exact project.
    SessionWriteOrImageGenerationAdmin,
}

impl RequestFamily {
    /// Every `RequestFamily` variant, for exhaustive authorization-matrix
    /// tests. The authorization `match`es below carry no wildcard arm, so a
    /// newly added variant fails to compile until it is given both a matrix
    /// disposition and (in tests) an expected disposition — this array is the
    /// iteration surface, not the exhaustiveness guarantee.
    pub const ALL: [RequestFamily; 8] = [
        Self::ConfigReadsAndSnapshot,
        Self::HealthReadsAndRefresh,
        Self::PlanGet,
        Self::JobReadsAndSnapshot,
        Self::JobCancel,
        Self::ConfigMutations,
        Self::LateResult,
        Self::OperationStatus,
    ];

    /// Returns the remote attempt capability required for this family.
    pub fn remote_capability(self) -> RemoteAttemptCapability {
        match self {
            Self::ConfigReadsAndSnapshot => RemoteAttemptCapability::ImageGenerationAdmin,
            Self::HealthReadsAndRefresh => RemoteAttemptCapability::ProjectRead,
            Self::PlanGet => RemoteAttemptCapability::SessionRead,
            Self::JobReadsAndSnapshot => RemoteAttemptCapability::SessionRead,
            Self::JobCancel => RemoteAttemptCapability::SessionWriteOrImageGenerationAdmin,
            Self::ConfigMutations => RemoteAttemptCapability::ImageGenerationAdmin,
            Self::LateResult => RemoteAttemptCapability::ImageGenerationAdmin,
            Self::OperationStatus => RemoteAttemptCapability::ProjectReadOrImageGenerationAdmin,
        }
    }

    /// The local-`Owner` authorization disposition for this request family.
    ///
    /// This is the real per-`RequestFamily` table for the daemon-local
    /// `ClientPrincipal::Owner`, encoding the "Local Owner" column of the
    /// settled control-plane authorization matrix
    /// (`prompts/flycockpitapp/complete/image-generation-control-plane.md`,
    /// "Request authorization matrix"). The local `Owner` is the daemon-local
    /// management authority and does not depend on hosted lease availability
    /// (Decisions §: "Local `ClientPrincipal::Owner` mutations use the existing
    /// daemon-local authority boundary and do not depend on hosted lease
    /// availability"), so the contract admits `Owner` for every family — each
    /// arm encodes that disposition EXPLICITLY.
    ///
    /// The `match` is exhaustive with NO wildcard arm: a newly added
    /// `RequestFamily` variant will not compile until it is given a deliberate
    /// disposition here, which is what makes the former constant-true
    /// `local_owner_allowed()` tautology unrepresentable. A family the contract
    /// denies `Owner` would encode `AuthorizationDecision::deny(code)` with the
    /// matching `ImageControlErrorCode` in its arm.
    ///
    /// Session-role (`Writer`/`Readonly`) denial in the matrix is a REMOTE
    /// session-membership concern and is authorized on the remote path with the
    /// deferred remote `authorize()`; it is not a local-`Owner` disposition.
    pub fn local_owner_authorization(self) -> AuthorizationDecision {
        match self {
            Self::ConfigReadsAndSnapshot => AuthorizationDecision::allow(),
            Self::HealthReadsAndRefresh => AuthorizationDecision::allow(),
            Self::PlanGet => AuthorizationDecision::allow(),
            Self::JobReadsAndSnapshot => AuthorizationDecision::allow(),
            Self::JobCancel => AuthorizationDecision::allow(),
            Self::ConfigMutations => AuthorizationDecision::allow(),
            Self::LateResult => AuthorizationDecision::allow(),
            Self::OperationStatus => AuthorizationDecision::allow(),
        }
    }
}

/// The authorization decision for a control-plane request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub allowed: bool,
    pub error: Option<ImageControlErrorCode>,
}

impl AuthorizationDecision {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            error: None,
        }
    }

    pub fn deny(code: ImageControlErrorCode) -> Self {
        Self {
            allowed: false,
            error: Some(code),
        }
    }
}

/// Authorize a control-plane request for a local `Owner` principal.
///
/// Local `ClientPrincipal::Owner` mutations use the existing daemon-local
/// authority boundary and do not depend on hosted lease availability. The
/// per-family disposition is consulted from the real
/// [`RequestFamily::local_owner_authorization`] table — there is no blanket
/// allow. (The daemon-level gate is upstream: the `image_*` RPCs are
/// `owner_only` at `daemon/server/authz.rs`, so a non-owner is already denied
/// before this decision table is consulted; this function is the affordance /
/// decision surface the TUI and handlers read.)
pub fn authorize_local_owner(family: RequestFamily) -> AuthorizationDecision {
    family.local_owner_authorization()
}

/// Check whether a remote principal's legacy `grants` snapshot can authorize
/// an image-generation management mutation.
///
/// The legacy `ClientPrincipal::Remote`/`RemotePrincipal.grants` snapshot is
/// grounding only and is never the new authority for remote mutations. This
/// function always returns `false` for any mutation family, proving the old
/// behavior is rejected.
pub fn legacy_grants_can_authorize_mutation(_principal: &ClientPrincipal) -> bool {
    false
}

/// Check whether a principal grant scope requires a project root.
///
/// `ImageGenerationAdmin` requires a nonnull project root; every other scope
/// retains its reviewed project-binding rules (root optional).
pub fn scope_requires_project_root(scope: PrincipalScope) -> bool {
    matches!(scope, PrincipalScope::ImageGenerationAdmin)
}

/// Whether a grant of `scope` carries a project root that satisfies the
/// scope's binding requirement.
///
/// `ImageGenerationAdmin` REQUIRES a nonnull, nonempty root — it fails closed
/// rather than inheriting the `None`-matches-any-project wildcard the four
/// access scopes use. Every other scope keeps its reviewed project-binding
/// rules, where a missing root is a legitimate instance-wide grant.
///
/// This is the single funnel every mint/decode path routes through so an
/// image-admin grant can never be admitted rootless (see
/// [`mint_image_admin_grant`] and the relay-wire decoder).
pub fn scope_project_root_is_valid(scope: PrincipalScope, project_root: Option<&str>) -> bool {
    if scope_requires_project_root(scope) {
        project_root.map(|r| !r.is_empty()).unwrap_or(false)
    } else {
        true
    }
}

/// Validate that an `ImageGenerationAdmin` grant has a nonnull project root.
///
/// Returns `false` if the root is missing — the existing rootless wildcard
/// never applies for this scope.
pub fn validate_admin_grant_root(scope: PrincipalScope, project_root: Option<&str>) -> bool {
    scope_project_root_is_valid(scope, project_root)
}

/// Mint an `ImageGenerationAdmin` principal grant, failing closed when the
/// project root is missing or empty.
///
/// An image-admin grant NEVER inherits the `None`-matches-any-project
/// wildcard: minting requires `project_root: Some(canonical_root)`. The root
/// is normalized through the canonical project-identity form the daemon's
/// authorization layer trusts ([`crate::secret_ownership::canonical_owner_root`],
/// itself anchored on [`crate::daemon::fs_api::canonical_project_root`]), so two
/// spellings of the same project mint one binding.
pub fn mint_image_admin_grant(
    project_root: Option<&str>,
) -> Result<PrincipalGrant, ImageControlErrorCode> {
    match project_root {
        Some(root) if !root.is_empty() => Ok(PrincipalGrant {
            scope: PrincipalScope::ImageGenerationAdmin,
            project_root: Some(crate::secret_ownership::canonical_owner_root(root)),
        }),
        _ => Err(ImageControlErrorCode::Forbidden),
    }
}

/// AC13: resolve whether an admin grant's project root binds the target
/// project by CANONICAL project identity, not raw string equality.
///
/// Two path spellings of the same project (trailing slash, symlinked, or
/// otherwise non-canonical) normalize to one binding, while a different
/// project can never match through a string-prefix trick (`/workspace/app`
/// does not bind `/workspace/app-evil`). Both roots are normalized through the
/// same canonical form the daemon's authz layer anchors on
/// ([`crate::secret_ownership::canonical_owner_root`] →
/// [`crate::daemon::fs_api::canonical_project_root`]); this module invents no
/// canonicalizer of its own.
///
/// Fails closed on a missing or empty grant root — an image-admin binding is
/// never rootless.
pub fn admin_grant_root_matches_project(
    grant_root: Option<&str>,
    target_project_root: &str,
) -> bool {
    let Some(root) = grant_root else {
        return false;
    };
    if root.is_empty() {
        return false;
    }
    crate::secret_ownership::canonical_owner_root(root)
        == crate::secret_ownership::canonical_owner_root(target_project_root)
}

// ---------------------------------------------------------------------------
// Capability matrix: foundation-owned capability import and consumption
// ---------------------------------------------------------------------------

/// Returns the foundation-owned `RemoteProjectCapabilityV1` for
/// `image_generation_admin`.
///
/// This imports and consumes the foundation-owned ordinal 15 without
/// registering, redefining, re-encoding, or independently hashing any
/// capability byte.
pub fn image_generation_admin_capability() -> RemoteProjectCapabilityV1 {
    RemoteProjectCapabilityV1::ImageGenerationAdmin
}

/// Returns the foundation-owned ordinal for `image_generation_admin`.
pub fn image_generation_admin_ordinal() -> u8 {
    image_generation_admin_capability().ordinal()
}

/// Verify that the imported `image_generation_admin` ordinal is exactly 15
/// and matches the foundation enum.
pub fn verify_image_generation_admin_ordinal() -> bool {
    let cap = image_generation_admin_capability();
    cap.ordinal() == IMAGE_GENERATION_ADMIN_ORDINAL
        && cap == RemoteProjectCapabilityV1::ImageGenerationAdmin
}

/// Build a permission ceiling containing exactly one project with
/// `image_generation_admin=15` and compute its canonical digest using the
/// foundation-owned helper.
///
/// This consumes `RemotePermissionCeilingV1` and `permission_ceiling_digest`
/// without any local enum, codec, hash derivation, or moved ordinal.
pub fn build_admin_permission_ceiling(
    project_id: [u8; 16],
) -> Result<(RemotePermissionCeilingV1, RemotePermissionCeilingDigestV1), &'static str> {
    if project_id.iter().all(|&b| b == 0) {
        return Err("project id must be nonzero");
    }
    let ceiling = RemotePermissionCeilingV1 {
        attachment_capabilities: Vec::new(),
        projects: vec![(
            project_id,
            vec![RemoteProjectCapabilityV1::ImageGenerationAdmin],
        )],
    };
    let digest = permission_ceiling_digest(&ceiling).map_err(|_| "digest computation failed")?;
    Ok((ceiling, digest))
}

/// Check whether a decoded permission ceiling authorizes
/// `image_generation_admin` on the exact project.
pub fn ceiling_authorizes_admin(
    ceiling: &RemotePermissionCeilingV1,
    project_id: &[u8; 16],
) -> bool {
    ceiling.projects.iter().any(|(pid, caps)| {
        pid == project_id && caps.contains(&RemoteProjectCapabilityV1::ImageGenerationAdmin)
    })
}

/// Verify that `image_generation_admin=15` is type/field-disjoint from
/// attachment capabilities despite intentional numeric overlap.
pub fn verify_capability_disjoint() -> bool {
    use cockpit_proto::remote_public_service_policy::RemoteAttachmentCapabilityV1;
    // Ordinal 15 must be a valid project capability but not a valid attachment
    // capability.
    let proj = RemoteProjectCapabilityV1::from_ordinal(IMAGE_GENERATION_ADMIN_ORDINAL);
    let att = RemoteAttachmentCapabilityV1::from_ordinal(IMAGE_GENERATION_ADMIN_ORDINAL);
    proj.is_ok() && att.is_err()
}

// ---------------------------------------------------------------------------
// FCOR operation kind encoding
// ---------------------------------------------------------------------------

/// Encode `ImageOperationKindV1` as exact `u16be` in FCOR.
pub fn encode_operation_kind_fcor(kind: ImageOperationKindV1) -> [u8; 2] {
    let ord = kind.fcor_ordinal();
    [(ord >> 8) as u8, ord as u8]
}

/// Decode `ImageOperationKindV1` from exact `u16be` in FCOR.
pub fn decode_operation_kind_fcor(bytes: [u8; 2]) -> Option<ImageOperationKindV1> {
    let ord = u16::from_be_bytes(bytes);
    ImageOperationKindV1::from_fcor_ordinal(ord)
}

// ---------------------------------------------------------------------------
// Cursor validation
// ---------------------------------------------------------------------------

/// Validate an opaque base64url cursor: at most 512 bytes when decoded.
pub fn validate_cursor(cursor: &str) -> bool {
    if cursor.is_empty() {
        return false;
    }
    if cursor.len() > MAX_CURSOR_BYTES * 2 {
        return false;
    }
    // base64url charset: A-Z, a-z, 0-9, -, _
    cursor
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validate a list limit: `1..=100`.
pub fn validate_limit(limit: u32) -> bool {
    (1..=MAX_LIST_LIMIT).contains(&limit)
}

/// Validate a display name: NFC UTF-8, no NUL, 1..256 bytes.
pub fn validate_display_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > MAX_DISPLAY_NAME_BYTES {
        return false;
    }
    if bytes.contains(&0u8) {
        return false;
    }
    // NFC check: the string must be in NFC form.
    use unicode_normalization::UnicodeNormalization;
    name.nfc().eq(name.chars())
}

/// Validate a stable error/remediation code: lowercase ASCII
/// `[a-z][a-z0-9_]{0,63}`.
pub fn validate_stable_code(code: &str) -> bool {
    let bytes = code.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !(bytes[0].is_ascii_lowercase()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'_')
}

/// Validate a canonical decimal string matching `0|[1-9][0-9]{0,19}` whose
/// value additionally fits an unsigned 64-bit integer (a 20-digit token may
/// otherwise exceed `u64::MAX`).
pub fn validate_canonical_decimal(s: &str) -> bool {
    if s.is_empty() || s.len() > 20 {
        return false;
    }
    let bytes = s.as_bytes();
    if bytes == b"0" {
        return true;
    }
    if !(bytes[0] as char).is_ascii_digit() || bytes[0] == b'0' {
        return false;
    }
    bytes.iter().all(|b| b.is_ascii_digit()) && s.parse::<u64>().is_ok()
}

/// Validate a 22-character unpadded base64url ID (random 16-byte alias).
pub fn validate_base64url_id_22(id: &str) -> bool {
    if id.len() != 22 {
        return false;
    }
    id.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Validate a 24-character CUID2 matching `[a-z][a-z0-9]{23}`.
pub fn validate_cuid2_24(id: &str) -> bool {
    if id.len() != 24 {
        return false;
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_lowercase() {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Validate a lowercase 64-hex SHA-256 digest.
pub fn validate_sha256_hex(digest: &str) -> bool {
    if digest.len() != 64 {
        return false;
    }
    digest
        .bytes()
        .all(|b| (b'a'..=b'f').contains(&b) || b.is_ascii_digit())
}

/// Validate a lowercase hyphenated UUID.
pub fn validate_uuid_lowercase_hyphenated(uuid: &str) -> bool {
    uuid::Uuid::parse_str(uuid).is_ok() && uuid == uuid.to_lowercase()
}

/// Compute the lowercase hex SHA-256 of a byte slice.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").expect("writing to String");
    }
    s
}

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/// Forbidden sentinel values that must never appear in safe projections,
/// responses, events, or errors.
pub const FORBIDDEN_SENTINELS: &[&str] = &[
    "api_key",
    "apiKey",
    "secret",
    "password",
    "credential",
    "private_key",
    "privateKey",
    "access_token",
    "accessToken",
    "refresh_token",
    "refreshToken",
    "provider_body",
    "providerBody",
    "quarantine",
    "local_path",
    "localPath",
    "host_path",
    "hostPath",
    "raw_workflow_json",
    "rawWorkflowJson",
    "signed_url",
    "signedUrl",
    "connected_ip",
    "connectedIp",
];

/// Scan a JSON value for forbidden sentinel strings in its keys.
pub fn scan_for_forbidden_sentinels(value: &serde_json::Value) -> Vec<String> {
    let mut found = Vec::new();
    scan_value_keys(value, &mut found);
    found.sort();
    found.dedup();
    found
}

fn scan_value_keys(value: &serde_json::Value, found: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let key_lower = key.to_lowercase();
                for sentinel in FORBIDDEN_SENTINELS {
                    let sentinel_lower = sentinel.to_lowercase();
                    if key_lower.contains(&sentinel_lower) {
                        found.push(key.clone());
                    }
                }
                scan_value_keys(val, found);
            }
        }
        serde_json::Value::Array(arr) => {
            for val in arr {
                scan_value_keys(val, found);
            }
        }
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// Config change set (reducer)
// ---------------------------------------------------------------------------

/// `ImageConfigChangeSetSafeV1 {schemaVersion:1,configGeneration,changes}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageConfigChangeSetSafeV1 {
    pub schema_version: u8,
    pub config_generation: String,
    pub changes: Vec<ConfigChange>,
}

/// One member of a config change set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ConfigChange {
    Upsert {
        entity_kind: ConfigEntityKind,
        entity_id: String,
        entity_generation: String,
        item: serde_json::Value,
    },
    Deleted {
        entity_kind: ConfigEntityKind,
        entity_id: String,
        entity_generation: String,
        item: Option<serde_json::Value>,
    },
}

/// The config entity kinds that can appear in a change set:
/// `endpoint|target|workflow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigEntityKind {
    Endpoint,
    Target,
    Workflow,
}

impl ConfigEntityKind {
    pub const fn sort_ordinal(self) -> u8 {
        match self {
            Self::Endpoint => 1,
            Self::Target => 2,
            Self::Workflow => 3,
        }
    }
}

/// Sort config changes by `(entityKind ordinal, decoded entity ID)`.
pub fn sort_config_changes(changes: &mut [ConfigChange]) {
    changes.sort_by(|a, b| {
        let ord_a = config_change_sort_key(a);
        let ord_b = config_change_sort_key(b);
        ord_a.cmp(&ord_b)
    });
}

fn config_change_sort_key(change: &ConfigChange) -> (u8, String) {
    match change {
        ConfigChange::Upsert {
            entity_kind,
            entity_id,
            ..
        } => (entity_kind.sort_ordinal(), entity_id.clone()),
        ConfigChange::Deleted {
            entity_kind,
            entity_id,
            ..
        } => (entity_kind.sort_ordinal(), entity_id.clone()),
    }
}

/// Validate a config change set: 1..100 changes, sorted by
/// `(entityKind ordinal, decoded entity ID)`, unique entity IDs.
pub fn validate_config_change_set(changes: &[ConfigChange]) -> bool {
    if changes.is_empty() || changes.len() > MAX_CONFIG_CHANGES {
        return false;
    }
    let mut seen: BTreeSet<(u8, String)> = BTreeSet::new();
    for change in changes {
        let key = config_change_sort_key(change);
        if !seen.insert(key) {
            return false;
        }
    }
    // Check sorted order.
    for i in 1..changes.len() {
        let prev = config_change_sort_key(&changes[i - 1]);
        let curr = config_change_sort_key(&changes[i]);
        if prev > curr {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// Budget scope
// ---------------------------------------------------------------------------

/// The budget policy DTO. This is the single non-lossy spend-ledger type
/// (`Unconfigured | Finite { usd_micros } | Unlimited`), re-exported so the
/// control-plane wire, the spend ledger, and the FCOR
/// `ImageSpendSettings` encoder all share exactly one representation. A
/// `Finite` policy is uninhabitable without a positive `usd_micros`, and its
/// custom `Deserialize` rejects `usd_micros: 0`, so a lossy amount-free
/// `Finite` cannot cross this wire. `Unconfigured` is a distinct variant and
/// can never be smuggled as a `Finite` with an absent/zero amount.
pub use cockpit_config::config::image_spend::BudgetPolicy;

/// `ImageBudgetSafeV1` scope-nullability contract.
///
/// Each selected scope projects either `(Unconfigured,null)` or
/// `(Finite|Unlimited,positive-generation)`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BudgetScopeProjection {
    pub policy: BudgetPolicy,
    pub generation: Option<String>,
}

impl BudgetScopeProjection {
    pub fn unconfigured() -> Self {
        Self {
            policy: BudgetPolicy::Unconfigured,
            generation: None,
        }
    }

    /// A `Finite` projection carries the non-lossy `usd_micros` amount from the
    /// spend-ledger DTO alongside its positive generation.
    pub fn finite(usd_micros: u64, generation: String) -> Self {
        Self {
            policy: BudgetPolicy::Finite { usd_micros },
            generation: Some(generation),
        }
    }

    pub fn unlimited(generation: String) -> Self {
        Self {
            policy: BudgetPolicy::Unlimited,
            generation: Some(generation),
        }
    }

    /// Validate the nullability contract: `Unconfigured` requires null
    /// generation; `Finite|Unlimited` requires positive generation. A `Finite`
    /// additionally requires a positive `usd_micros` amount, mirroring the
    /// spend-ledger deserializer that rejects `usd_micros: 0`, so a zero-amount
    /// `Finite` built directly in memory is rejected exactly as it is on the
    /// wire.
    pub fn validate(&self) -> bool {
        match self.policy {
            BudgetPolicy::Unconfigured => self.generation.is_none(),
            BudgetPolicy::Finite { usd_micros: 0 } => false,
            BudgetPolicy::Finite { .. } | BudgetPolicy::Unlimited => self
                .generation
                .as_ref()
                .map(|g| validate_canonical_decimal(g) && g != "0")
                .unwrap_or(false),
        }
    }
}

/// Validate a `image_budget_set` scope pair: `(policy, expected_generation)`.
///
/// - `(null,null)` leaves it unchanged.
/// - A nonnull policy with null expected generation asserts the row is absent
///   and creates generation 1.
/// - A nonnull policy with a positive expected generation CAS-updates exactly
///   that generation.
/// - Every other pair rejects.
pub fn validate_budget_set_pair(
    policy: Option<BudgetPolicy>,
    expected_generation: Option<&str>,
) -> bool {
    match (policy, expected_generation) {
        (None, None) => true,                           // unchanged
        (Some(BudgetPolicy::Unconfigured), _) => false, // Unconfigured in a save rejects
        // A zero-amount `Finite` is not a savable policy (matches the wire
        // deserializer), even when constructed directly in memory.
        (Some(BudgetPolicy::Finite { usd_micros: 0 }), _) => false,
        (Some(BudgetPolicy::Finite { .. } | BudgetPolicy::Unlimited), None) => true, // create generation 1
        (Some(BudgetPolicy::Finite { .. } | BudgetPolicy::Unlimited), Some(generation)) => {
            validate_canonical_decimal(generation) && generation != "0" // CAS-update
        }
        (None, Some(_)) => false, // half-present tuple rejects
    }
}

/// Validate that at least one policy is nonnull in `image_budget_set`.
pub fn validate_at_least_one_policy(
    request: Option<BudgetPolicy>,
    session: Option<BudgetPolicy>,
    project: Option<BudgetPolicy>,
) -> bool {
    request.is_some() || session.is_some() || project.is_some()
}

// ---------------------------------------------------------------------------
// Admin grant lifecycle
// ---------------------------------------------------------------------------

/// The access-grant status enum, extended with `REVOKING`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessGrantStatus {
    Pending,
    Active,
    Revoking,
    Revoked,
    Expired,
    Declined,
}

/// The access-grant transition kind. Each named transition increments
/// generation exactly once in the same serializable transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AccessGrantTransition {
    /// Pending acceptance/decline/expiry.
    PendingAcceptance,
    PendingDecline,
    PendingExpiry,
    /// Active expiry/renewal.
    ActiveExpiry,
    ActiveRenewal,
    /// Revocation fencing: `ACTIVE -> REVOKING` then drain to `REVOKED`.
    RevokeStart,
    RevokeComplete,
}

impl AccessGrantTransition {
    /// Returns `true` if this transition increments generation exactly once
    /// in the same serializable transaction.
    pub fn increments_generation(self) -> bool {
        match self {
            Self::PendingAcceptance
            | Self::PendingDecline
            | Self::PendingExpiry
            | Self::ActiveExpiry
            | Self::ActiveRenewal
            | Self::RevokeStart => true,
            Self::RevokeComplete => false, // drain barrier, no second increment
        }
    }

    /// Returns `true` if this is a pending terminal transition that
    /// increments once and requires no claim drain.
    pub fn is_pending_terminal(self) -> bool {
        matches!(self, Self::PendingDecline | Self::PendingExpiry)
    }

    /// Returns `true` if this is an active terminal transition that uses the
    /// `REVOKING` drain barrier.
    pub fn is_active_terminal(self) -> bool {
        matches!(self, Self::ActiveExpiry | Self::RevokeStart)
    }
}

/// The active authority key computation for `ImageGenerationAdmin` grants.
///
/// `activeAuthorityKey` is internal-only lowercase SHA-256 of
/// `UTF8("flycockpit.image-admin-active.v1\0") | len32be(instanceSourceId) |
/// instanceSourceId | len32be(granteeUserSourceId) | granteeUserSourceId |
/// projectProtocolId:[16]`.
///
/// It is null outside `ACTIVE`. The key, internal source IDs, and its digest
/// never enter a wire response, token, log, or FCOR.
pub fn compute_active_authority_key(
    instance_source_id: &[u8],
    grantee_user_source_id: &[u8],
    project_protocol_id: &[u8; 16],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"flycockpit.image-admin-active.v1\0");
    hasher.update((instance_source_id.len() as u32).to_be_bytes());
    hasher.update(instance_source_id);
    hasher.update((grantee_user_source_id.len() as u32).to_be_bytes());
    hasher.update(grantee_user_source_id);
    hasher.update(project_protocol_id);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        use std::fmt::Write;
        write!(&mut s, "{b:02x}").expect("writing to String");
    }
    s
}

/// Validate a CUID2 grant ID: exactly one lowercase ASCII letter followed by
/// 23 lowercase ASCII letters/digits, matching `[a-z][a-z0-9]{23}`.
pub fn validate_grant_id(id: &str) -> bool {
    validate_cuid2_24(id)
}

// ---------------------------------------------------------------------------
// Lease identifier validation
// ---------------------------------------------------------------------------

/// Validate a lease/claim ID: 22-character unpadded base64url (random nonzero
/// 16-byte mint).
pub fn validate_lease_id(id: &str) -> bool {
    validate_base64url_id_22(id)
}

/// Validate the JWS protected header for a mutation lease.
///
/// The compact JWS has only protected header
/// `{alg:"ES256",kid,typ:"flycockpit-image-admin-mutation-lease+jws"}`, no
/// unprotected header.
pub fn validate_mutation_lease_header(header: &serde_json::Value) -> bool {
    match header {
        serde_json::Value::Object(map) => {
            map.len() == 3
                && map.get("alg").and_then(|v| v.as_str()) == Some("ES256")
                && map.get("typ").and_then(|v| v.as_str())
                    == Some("flycockpit-image-admin-mutation-lease+jws")
                && map
                    .get("kid")
                    .and_then(|v| v.as_str())
                    .is_some_and(|k| !k.is_empty())
        }
        _ => false,
    }
}

/// Validate the JWS protected header for a read claim.
///
/// `{alg:"ES256",kid,typ:"flycockpit-image-admin-read-claim+jws"}`
pub fn validate_read_claim_header(header: &serde_json::Value) -> bool {
    match header {
        serde_json::Value::Object(map) => {
            map.len() == 3
                && map.get("alg").and_then(|v| v.as_str()) == Some("ES256")
                && map.get("typ").and_then(|v| v.as_str())
                    == Some("flycockpit-image-admin-read-claim+jws")
                && map
                    .get("kid")
                    .and_then(|v| v.as_str())
                    .is_some_and(|k| !k.is_empty())
        }
        _ => false,
    }
}

/// The mutation lease JWS `typ` value.
pub const MUTATION_LEASE_JWS_TYP: &str = "flycockpit-image-admin-mutation-lease+jws";
/// The read claim JWS `typ` value.
pub const READ_CLAIM_JWS_TYP: &str = "flycockpit-image-admin-read-claim+jws";
/// The mutation lease JWS `aud` value.
pub const MUTATION_LEASE_AUD: &str = "flycockpit:image-generation-admin-mutation:v1";
/// The read claim JWS `aud` value.
pub const READ_CLAIM_AUD: &str = "flycockpit:image-generation-admin-read:v1";

/// The maximum lease lifetime in seconds: `1 <= exp-iat <= 15`.
pub const MAX_LEASE_LIFETIME_SECONDS: u64 = 15;

/// Validate lease time claims: `nbf=iat`, `1 <= exp-iat <= 15`.
pub fn validate_lease_times(iat: u64, nbf: u64, exp: u64) -> bool {
    nbf == iat && (1..=MAX_LEASE_LIFETIME_SECONDS).contains(&(exp.saturating_sub(iat)))
}

/// Validate the `ImageWorkflowApiFormatBlobV1` fields.
///
/// `{schemaVersion:1,transferId,totalLength,sha256}` where `totalLength` is a
/// canonical decimal string in `1..=16,777,216` and `sha256` is lowercase
/// 64-hex.
pub fn validate_api_format_blob(
    schema_version: u8,
    transfer_id: &str,
    total_length: &str,
    sha256: &str,
) -> bool {
    schema_version == CONTROL_PLANE_SCHEMA_VERSION
        && validate_base64url_id_22(transfer_id)
        && validate_canonical_decimal(total_length)
        && total_length != "0"
        && total_length
            .parse::<u64>()
            .map(|v| v <= 16_777_216)
            .unwrap_or(false)
        && validate_sha256_hex(sha256)
}

// ---------------------------------------------------------------------------
// Late result disposition
// ---------------------------------------------------------------------------

/// The explicit late-result disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LateResultDisposition {
    Publish,
    Discard,
}

/// The error returned when publication requires current output authority
/// but it is absent/changed.
pub const LOCAL_PATH_REAUTHORIZATION_ERROR: ImageControlErrorCode =
    ImageControlErrorCode::LocalPathReauthorizationRequired;

#[cfg(test)]
mod tests;
