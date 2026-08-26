//! Safe, redacted projections for the LOCAL image-generation control-plane
//! READ surface (`image-generation-control-plane` inc3a).
//!
//! The image-generation config is SECRET-BEARING: endpoint `credential_ref`s
//! and `headers` carry auth material, registered workflow `graph_json` is an
//! opaque blob where a token can hide anywhere, and target price/capability
//! evidence carries `source_url`s that can be signed/bearer URLs. These
//! projections are the single redaction funnel every LOCAL read routes
//! through: they field-drop or count-summarize every secret-bearing member so
//! no credential, header value, raw workflow JSON, or source URL can cross the
//! wire. The only route FROM domain data to a projection is the `project`
//! associated functions below (there is no `From<serde_json::Value>` or
//! config-typed `From` conversion), so a projection built from a domain value
//! is always built by dropping/summarizing the secret-bearing fields. The wire
//! structs keep public fields for `Deserialize`/round-trip; that is not a
//! redaction bypass, because a hand-built literal carries no domain secret —
//! only a domain value routed through `project` can, and `project` is the sole
//! such route.
//!
//! Per-entity `entity_generation` is supplied by the daemon handler from the
//! process config generation. Per-entity version tracking is a later increment
//! (config mutations); until it lands, every entity in one read shares the
//! config generation, which advances on every config mutation.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageBillableUnit, ImageDimensionDescriptor, ImageEndpoint, ImageFormat,
    ImageGenerationTarget, ImageLocationClass, ImageParameterDescriptor, ImagePrice,
    ImagePriceMethod, ImageTargetIdentity, OpenRouterImageRouting, ReferenceImageSupport,
    RegisteredComfyWorkflow, SafeWorkflowProjection,
};

/// The schema version for every image-control-plane V1 wire structure.
pub const IMAGE_CONTROL_SCHEMA_VERSION: u8 = 1;

/// Opaque daemon-issued authority for one exact image-config document state.
///
/// The daemon keys this value over the canonical project root, authoritative
/// target path, target revision, and config generation. Clients must treat it
/// as an indivisible bearer value and return it with the matching CAS fields.
#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ImageConfigMutationCapabilityV1(pub String);

const IMAGE_MUTATION_CAPABILITY_HEX_BYTES: usize = 64;

fn valid_mutation_capability(value: &str) -> bool {
    value.len() == IMAGE_MUTATION_CAPABILITY_HEX_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

impl ImageConfigMutationCapabilityV1 {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for ImageConfigMutationCapabilityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ImageConfigMutationCapabilityV1([REDACTED])")
    }
}

impl<'de> Deserialize<'de> for ImageConfigMutationCapabilityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct CapabilityVisitor;

        impl<'de> serde::de::Visitor<'de> for CapabilityVisitor {
            type Value = ImageConfigMutationCapabilityV1;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("exactly 64 lowercase hexadecimal characters")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if !valid_mutation_capability(value) {
                    return Err(E::invalid_value(serde::de::Unexpected::Str(value), &self));
                }
                Ok(ImageConfigMutationCapabilityV1(value.to_owned()))
            }

            fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(value)
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if !valid_mutation_capability(&value) {
                    return Err(E::invalid_value(serde::de::Unexpected::Str(&value), &self));
                }
                Ok(ImageConfigMutationCapabilityV1(value))
            }
        }

        deserializer.deserialize_str(CapabilityVisitor)
    }
}

#[cfg(feature = "remote")]
impl crate::remote_operation_fcor::CanonicalFcorValueV1 for ImageConfigMutationCapabilityV1 {
    fn encode_fcor_value_v1(
        &self,
        out: &mut crate::remote_operation_fcor::CanonicalParamsV1,
    ) -> anyhow::Result<()> {
        let digest = Sha256::digest(self.as_str().as_bytes());
        out.push_bytes(digest.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Endpoint
// ---------------------------------------------------------------------------

/// `ImageEndpointSafeV1` — the redacted endpoint projection.
///
/// SECURITY: `credential_ref` and `headers` (auth material) are NOT members.
/// They are reduced to `credential_configured` (a bool) and
/// `header_reference_count` (a count) so no secret value or header name/value
/// crosses the wire. `allow_insecure_transport` and `exclusive_server` are
/// omitted (not part of the safe contract).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageEndpointSafeV1 {
    pub schema_version: u8,
    pub endpoint_id: String,
    pub entity_generation: String,
    pub display_name: Option<String>,
    pub adapter_kind: ImageAdapterKind,
    pub normalized_origin: String,
    pub normalized_path_prefix: Option<String>,
    pub enabled: bool,
    pub route_profile_version: u32,
    pub declared_location_class: ImageLocationClass,
    pub credential_configured: bool,
    pub header_reference_count: u32,
}

impl ImageEndpointSafeV1 {
    /// Project a domain [`ImageEndpoint`] to its safe wire form. This is the
    /// single funnel: `credential_ref`/`headers` are never copied, only
    /// summarized.
    pub fn project(endpoint: &ImageEndpoint, entity_generation: String) -> Self {
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            endpoint_id: endpoint.id.clone(),
            entity_generation,
            // The domain endpoint has no display name; the id is the local
            // display handle until a mutation increment adds one.
            display_name: None,
            adapter_kind: endpoint.adapter,
            normalized_origin: endpoint.origin.clone(),
            normalized_path_prefix: endpoint.path_prefix.clone(),
            enabled: endpoint.enabled,
            route_profile_version: endpoint.route_profile_version,
            declared_location_class: endpoint.location,
            credential_configured: endpoint.credential_ref.is_some(),
            header_reference_count: endpoint.headers.len() as u32,
        }
    }
}

// ---------------------------------------------------------------------------
// Target
// ---------------------------------------------------------------------------

/// A redacted cost summary. SECURITY: the domain [`ImagePrice`] carries
/// [`cockpit_config::config::image_generation::ImageEvidence`] with a
/// `source_url` (a discovered/signed URL). This summary DROPS the evidence
/// entirely, keeping only the non-secret price scalars.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageCostSummaryV1 {
    pub known: bool,
    pub usd_micros: Option<u64>,
    pub unit: Option<ImageBillableUnit>,
    pub method: Option<ImagePriceMethod>,
    pub variant: Option<String>,
}

impl ImageCostSummaryV1 {
    fn project(price: &ImagePrice) -> Self {
        match price {
            ImagePrice::Unknown => Self {
                known: false,
                usd_micros: None,
                unit: None,
                method: None,
                variant: None,
            },
            // `evidence` (with its `source_url`) is intentionally not read here.
            ImagePrice::Known {
                usd_micros,
                unit,
                variant,
                method,
                evidence: _,
            } => Self {
                known: true,
                usd_micros: Some(*usd_micros),
                unit: Some(*unit),
                method: Some(*method),
                variant: Some(variant.clone()),
            },
        }
    }
}

/// `ImageTargetSafeV1` — the redacted target projection.
///
/// SECURITY: the target's `generation_capability` (an `ImageCapabilityEvidence`
/// carrying a `source_url`) is NOT a member, and `price` is reduced to
/// [`ImageCostSummaryV1`] which drops its evidence `source_url`. The remaining
/// members (dimensions, typed parameters, OpenRouter routing) are non-secret
/// configuration shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageTargetSafeV1 {
    pub schema_version: u8,
    pub target_id: String,
    pub entity_generation: String,
    pub endpoint_id: String,
    pub display_name: Option<String>,
    pub enabled: bool,
    pub is_default: bool,
    pub adapter_kind: Option<ImageAdapterKind>,
    pub hosted_identity: Option<String>,
    pub workflow_id: Option<String>,
    pub workflow_digest: Option<String>,
    pub formats: Vec<ImageFormat>,
    pub reference_support: ReferenceImageSupport,
    pub max_references: u64,
    pub max_samples: u64,
    pub dimension_descriptor: ImageDimensionDescriptor,
    pub typed_parameter_schema: Vec<ImageParameterDescriptor>,
    pub open_router_routing: Option<OpenRouterImageRouting>,
    pub cost_evidence: ImageCostSummaryV1,
}

impl ImageTargetSafeV1 {
    /// Project a domain [`ImageGenerationTarget`] to its safe wire form.
    /// `adapter_kind` is resolved by the caller from the referenced endpoint
    /// (`None` when a disabled target references no live endpoint).
    pub fn project(
        target: &ImageGenerationTarget,
        adapter_kind: Option<ImageAdapterKind>,
        entity_generation: String,
    ) -> Self {
        let (hosted_identity, workflow_id, workflow_digest) = match &target.identity {
            ImageTargetIdentity::HostedModel { model } => (Some(model.clone()), None, None),
            ImageTargetIdentity::Workflow {
                workflow_id,
                workflow_digest,
            } => (
                None,
                Some(workflow_id.clone()),
                Some(workflow_digest.clone()),
            ),
        };
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            target_id: target.id.clone(),
            entity_generation,
            endpoint_id: target.endpoint_id.clone(),
            display_name: target.display_name.clone(),
            enabled: target.enabled,
            is_default: target.is_default,
            adapter_kind,
            hosted_identity,
            workflow_id,
            workflow_digest,
            formats: target.formats.clone(),
            reference_support: target.reference_support,
            max_references: target.max_reference_images,
            max_samples: target.max_samples,
            dimension_descriptor: target.dimensions.clone(),
            typed_parameter_schema: target.parameters.clone(),
            open_router_routing: target.openrouter_routing.clone(),
            cost_evidence: ImageCostSummaryV1::project(&target.price),
        }
    }
}

// ---------------------------------------------------------------------------
// Workflow
// ---------------------------------------------------------------------------

/// `ImageWorkflowSafeV1` — the redacted workflow projection.
///
/// SECURITY: the domain [`RegisteredComfyWorkflow`] carries an opaque
/// `graph_json` blob (a token can hide anywhere inside it). It is NEVER a
/// member. `binding_schema` is the existing
/// [`RegisteredComfyWorkflow::safe_projection`] which drops `graph_json` and
/// exposes only the binding/output type shape; only `graph_digest` (a hash)
/// crosses the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageWorkflowSafeV1 {
    pub schema_version: u8,
    pub workflow_id: String,
    pub entity_generation: String,
    pub display_name: Option<String>,
    pub workflow_digest: String,
    pub binding_schema: SafeWorkflowProjection,
    pub referencing_target_ids: Vec<String>,
}

impl ImageWorkflowSafeV1 {
    /// Project a domain [`RegisteredComfyWorkflow`] to its safe wire form.
    /// `referencing_target_ids` is the ID-sorted-unique set of target ids that
    /// bind this workflow, resolved by the caller.
    pub fn project(
        workflow: &RegisteredComfyWorkflow,
        referencing_target_ids: Vec<String>,
        entity_generation: String,
    ) -> Self {
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            workflow_id: workflow.id.clone(),
            entity_generation,
            display_name: None,
            workflow_digest: workflow.graph_digest.clone(),
            // `safe_projection()` drops `graph_json`.
            binding_schema: workflow.safe_projection(),
            referencing_target_ids,
        }
    }
}

// ---------------------------------------------------------------------------
// Read response
// ---------------------------------------------------------------------------

/// The result body of a LOCAL image-control read. The `type` tag distinguishes
/// a paged list from a single-entity get, per entity class. Only safe
/// projections ever appear inside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ImageControlReadResultV1 {
    EndpointPage {
        items: Vec<ImageEndpointSafeV1>,
        next_cursor: Option<String>,
        snapshot_generation: String,
    },
    EndpointEntity {
        item: ImageEndpointSafeV1,
    },
    TargetPage {
        items: Vec<ImageTargetSafeV1>,
        next_cursor: Option<String>,
        snapshot_generation: String,
    },
    TargetEntity {
        item: ImageTargetSafeV1,
    },
    WorkflowPage {
        items: Vec<ImageWorkflowSafeV1>,
        next_cursor: Option<String>,
        snapshot_generation: String,
    },
    WorkflowEntity {
        item: ImageWorkflowSafeV1,
    },
}

/// The daemon reply for a LOCAL image-control read: the redacted result plus
/// the daemon instance and project the snapshot was taken under. Mirrors the
/// settled authority envelope for the read subset. Requested and canonical
/// roots remain distinct, and the mutation capability is bound to the exact
/// target path/revision/generation returned alongside it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageControlReadResponseV1 {
    pub schema_version: u8,
    pub daemon_instance_id: String,
    /// Caller-supplied project spelling retained for correlation/display.
    pub requested_project_root: String,
    /// Canonical workspace identity authenticated and used by the daemon.
    pub canonical_project_root: String,
    pub target_path: String,
    pub target_revision: String,
    pub mutation_capability: ImageConfigMutationCapabilityV1,
    pub config_generation: u64,
    pub result: ImageControlReadResultV1,
}

impl ImageControlReadResponseV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        daemon_instance_id: String,
        requested_project_root: String,
        canonical_project_root: String,
        target_path: String,
        target_revision: String,
        mutation_capability: ImageConfigMutationCapabilityV1,
        config_generation: u64,
        result: ImageControlReadResultV1,
    ) -> Self {
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            daemon_instance_id,
            requested_project_root,
            canonical_project_root,
            target_path,
            target_revision,
            mutation_capability,
            config_generation,
            result,
        }
    }
}

// ---------------------------------------------------------------------------
// Config mutation change set + `config_changed` event
// ---------------------------------------------------------------------------

/// One member of a LOCAL image-config change set. SECURITY: every member
/// carries ONLY the safe projection of the affected entity — the same redacting
/// [`ImageEndpointSafeV1`]/[`ImageTargetSafeV1`]/[`ImageWorkflowSafeV1`] funnel
/// the read surface uses — so no raw `credential_ref`, `headers`, or
/// `graph_json` ever rides a change set or the event that carries it. A deleted
/// member carries no `item` (only the tombstone id + generation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum ImageConfigChangeV1 {
    EndpointUpserted {
        entity_id: String,
        entity_generation: String,
        item: ImageEndpointSafeV1,
    },
    EndpointDeleted {
        entity_id: String,
        entity_generation: String,
    },
    TargetUpserted {
        entity_id: String,
        entity_generation: String,
        item: ImageTargetSafeV1,
    },
    TargetDeleted {
        entity_id: String,
        entity_generation: String,
    },
    WorkflowUpserted {
        entity_id: String,
        entity_generation: String,
        item: ImageWorkflowSafeV1,
    },
    WorkflowDeleted {
        entity_id: String,
        entity_generation: String,
    },
}

/// The safe, atomic change set applied by one config mutation. `changes` is the
/// full sorted delta the mutation produced (e.g. a `set_default` carries both
/// the prior and the new default target). Only safe projections appear inside.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageConfigChangeSetSafeV1 {
    pub schema_version: u8,
    pub config_generation: String,
    pub changes: Vec<ImageConfigChangeV1>,
}

/// Canonical, secret-free identity of one image registry mutation. Clients and
/// the daemon use the same typed projection so the public receipt hash cannot
/// accidentally absorb endpoint credentials, headers, evidence URLs, or raw
/// workflow graph bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageConfigMutationIntentV1 {
    pub project_id: String,
    pub expected_config_generation: u64,
    pub expected_config_revision: String,
    pub changes: Vec<ImageConfigChangeV1>,
}

impl ImageConfigMutationIntentV1 {
    pub fn sha256(&self) -> Result<String, serde_json::Error> {
        let encoded = serde_json::to_vec(&(
            "image_config_mutation_v1",
            &self.project_id,
            self.expected_config_generation,
            &self.expected_config_revision,
            &self.changes,
        ))?;
        let digest = Sha256::digest(encoded);
        Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
    }
}

impl ImageConfigChangeSetSafeV1 {
    pub fn new(config_generation: String, changes: Vec<ImageConfigChangeV1>) -> Self {
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            config_generation,
            changes,
        }
    }
}

/// The replayable `config_changed` event kind. A closed enum so an unknown kind
/// fails rather than silently degrading.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageControlEventKindV1 {
    ConfigChanged,
}

/// The daemon → client `config_changed` replay event emitted by a LOCAL
/// image-config mutation. SECURITY: it carries only the safe
/// [`ImageConfigChangeSetSafeV1`] — never a raw credential, header, or workflow
/// blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageControlEventV1 {
    pub schema_version: u8,
    pub daemon_instance_id: String,
    pub requested_project_root: String,
    pub canonical_project_root: String,
    pub target_path: String,
    pub result_revision: String,
    pub mutation_capability: ImageConfigMutationCapabilityV1,
    pub config_generation: u64,
    pub kind: ImageControlEventKindV1,
    pub change_set: ImageConfigChangeSetSafeV1,
}

impl ImageControlEventV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn config_changed(
        daemon_instance_id: String,
        requested_project_root: String,
        canonical_project_root: String,
        target_path: String,
        result_revision: String,
        mutation_capability: ImageConfigMutationCapabilityV1,
        config_generation: u64,
        change_set: ImageConfigChangeSetSafeV1,
    ) -> Self {
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            daemon_instance_id,
            requested_project_root,
            canonical_project_root,
            target_path,
            result_revision,
            mutation_capability,
            config_generation,
            kind: ImageControlEventKindV1::ConfigChanged,
            change_set,
        }
    }
}

/// The daemon reply for a successful LOCAL image-config mutation: the
/// authoritative new config generation plus the safe change set that was
/// applied and emitted. Carries only safe projections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageControlMutationResponseV1 {
    pub schema_version: u8,
    pub client_operation_id: String,
    /// Hash of the public, redacted mutation intent. Secret-bearing endpoint
    /// headers, credential references, and workflow graph bytes are excluded.
    pub mutation_intent_hash: String,
    pub daemon_instance_id: String,
    pub requested_project_root: String,
    pub canonical_project_root: String,
    pub target_path: String,
    pub consumed_revision: String,
    pub result_revision: String,
    pub consumed_config_generation: u64,
    pub result_config_generation: u64,
    pub mutation_capability: ImageConfigMutationCapabilityV1,
    pub status: crate::ConfigCommitStatus,
    pub publication: crate::ConfigPublicationStatus,
    pub change_set: ImageConfigChangeSetSafeV1,
}

impl ImageControlMutationResponseV1 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_operation_id: String,
        mutation_intent_hash: String,
        daemon_instance_id: String,
        requested_project_root: String,
        canonical_project_root: String,
        target_path: String,
        consumed_revision: String,
        result_revision: String,
        consumed_config_generation: u64,
        result_config_generation: u64,
        mutation_capability: ImageConfigMutationCapabilityV1,
        change_set: ImageConfigChangeSetSafeV1,
    ) -> Self {
        Self {
            schema_version: IMAGE_CONTROL_SCHEMA_VERSION,
            client_operation_id,
            mutation_intent_hash,
            daemon_instance_id,
            requested_project_root,
            canonical_project_root,
            target_path,
            consumed_revision,
            result_revision,
            consumed_config_generation,
            result_config_generation,
            mutation_capability,
            status: crate::ConfigCommitStatus::Committed,
            publication: crate::ConfigPublicationStatus::Published,
            change_set,
        }
    }
}

#[cfg(test)]
mod tests;
