//! Immutable provider-neutral image-generation preflight plans.
//!
//! The planner emits this closed DTO only after resolving every target and
//! output slot. Its canonical bytes are the authorization, queue, spend, and
//! provider-dispatch binding; no dispatcher may reinterpret caller input.

use std::collections::BTreeMap;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::image_generation_runtime::ImageHealthSnapshot;
use cockpit_config::config::media_budget::MediaReservationPlan;
use cockpit_db::db::sealed_scope::SealedActionGrantRow;
use cockpit_db::image_spend::{AttemptMaximum, SpendReservation};
use cockpit_db::media_attachments::AcquiredMediaComponentLease;

pub const MAX_IMAGE_GENERATION_TARGETS: usize = 16;
pub const MAX_IMAGE_GENERATION_SLOTS: usize = 256;
pub const MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT: u32 = 8;
pub const MAX_IMAGE_GENERATION_DIMENSION: u32 = 16_384;
const MAX_PLAN_STRING_BYTES: usize = 1_024;
const MAX_PLAN_LIST_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ImageGenerationPlanV1 {
    pub schema_version: u8,
    pub kind: String,
    pub job_id: Uuid,
    pub owner_session_id: Uuid,
    pub owner_principal_digest: String,
    pub project_identity_digest: String,
    pub config_generation: u64,
    pub enqueue_started_monotonic_ms: u64,
    pub operation_deadline_monotonic_ms: u64,
    pub required_grants: Vec<GrantRequirementV1>,
    pub central_resources: Vec<ResourceReservationV1>,
    pub spend: SpendReservationPlanV1,
    pub output_authority: OutputDirectoryAuthorityV1,
    pub targets: Vec<TargetPlanV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantRequirementV1 {
    pub grant_kind: String,
    pub authority_digest: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceReservationV1 {
    pub resource_kind: String,
    pub units: u64,
    pub reservation_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SpendReservationPlanV1 {
    pub required: bool,
    pub policy_version: u64,
    pub reservation_id: String,
    pub maximum_usd_micros: Option<u64>,
    pub plan_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputDirectoryAuthorityV1 {
    pub canonical_destination_digest: String,
    pub parent_identity_digest: String,
    pub authority_generation: u64,
    pub filename_prefix: String,
    pub extension: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetPlanV1 {
    pub target_id: String,
    pub target_config_generation: u64,
    pub normalized_config_digest: String,
    pub capability_provenance: CapabilityProvenanceV1,
    pub destination: TargetDestinationV1,
    pub reference_artifacts: Vec<ReferenceArtifactV1>,
    pub requested: RequestedOutputV1,
    pub resolved: ResolvedOutputV1,
    pub typed_parameters: BTreeMap<String, TypedParameterV1>,
    pub sample_count: u32,
    pub max_attempts: u32,
    pub slots: Vec<OutputSlotPlanV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityProvenanceV1 {
    pub capability_generation: u64,
    pub capability_digest: String,
    pub health_observed_at_monotonic_ms: u64,
    pub health_expires_at_monotonic_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TargetDestinationV1 {
    pub adapter_kind: String,
    pub endpoint_identity_digest: String,
    pub credential_identity_digest: String,
    pub destination_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferenceArtifactV1 {
    pub attachment_id: Uuid,
    pub attachment_version: u64,
    pub component_id: Uuid,
    pub component_generation: u64,
    pub media_kind: String,
    pub identity_digest: String,
    pub sha256: String,
    pub byte_length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestedOutputV1 {
    pub width: u32,
    pub height: u32,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolvedOutputV1 {
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub mime: String,
    pub vector_sanitization_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TypedParameterV1 {
    Boolean(bool),
    Integer(i64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OutputSlotPlanV1 {
    pub slot_id: Uuid,
    pub slot_index: u32,
    pub sample_index: u32,
    pub managed_artifact_id: Uuid,
    pub publication_name: String,
    pub attempts: Vec<AttemptPlanV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AttemptPlanV1 {
    pub attempt_number: u32,
    pub provider_request_identity: String,
    pub provider_idempotency_identity: String,
    pub resource_maximum: Vec<ResourceReservationV1>,
    pub maximum_usd_micros: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTargetAuthorityV1 {
    pub target_id: String,
    pub target_config_generation: u64,
    pub normalized_config_digest: String,
    pub capability_provenance: CapabilityProvenanceV1,
    pub destination: TargetDestinationV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutputDirectoryAuthority(OutputDirectoryAuthorityV1);
impl VerifiedOutputDirectoryAuthority {
    pub(crate) fn from_held_directory(
        canonical_destination_digest: String,
        parent_identity_digest: String,
        authority_generation: u64,
        filename_prefix: String,
        extension: String,
    ) -> Result<Self> {
        let value = OutputDirectoryAuthorityV1 {
            canonical_destination_digest,
            parent_identity_digest,
            authority_generation,
            filename_prefix,
            extension,
        };
        validate_digest(&value.canonical_destination_digest)?;
        validate_digest(&value.parent_identity_digest)?;
        ensure!(
            value.authority_generation > 0
                && valid_path_component(&value.filename_prefix)
                && valid_path_component(&value.extension),
            "output directory authority is invalid"
        );
        Ok(Self(value))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationPreflightTargetV1 {
    pub authority: RuntimeTargetAuthorityV1,
    pub reference_artifacts: Vec<ReferenceArtifactV1>,
    pub requested: RequestedOutputV1,
    pub resolved: ResolvedOutputV1,
    pub typed_parameters: BTreeMap<String, TypedParameterV1>,
    pub slot_ids: Vec<(Uuid, Uuid)>,
    pub max_attempts: u32,
    pub attempt_resource_maximum: Vec<ResourceReservationV1>,
    pub attempt_maximum_usd_micros: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationPreflightInputV1 {
    pub job_id: Uuid,
    pub owner_session_id: Uuid,
    pub owner_principal_digest: String,
    pub project_identity_digest: String,
    pub config_generation: u64,
    pub enqueue_started_monotonic_ms: u64,
    pub operation_deadline_monotonic_ms: u64,
    pub required_grants: Vec<GrantRequirementV1>,
    pub central_resources: Vec<ResourceReservationV1>,
    pub spend: SpendReservationPlanV1,
    pub output_authority: VerifiedOutputDirectoryAuthority,
    pub targets: Vec<ImageGenerationPreflightTargetV1>,
}

pub fn plan_image_generation(
    input: ImageGenerationPreflightInputV1,
) -> Result<ImageGenerationPlanV1> {
    ensure!(
        input
            .targets
            .windows(2)
            .all(|pair| pair[0].authority.target_id < pair[1].authority.target_id),
        "preflight targets must be unique and sorted"
    );
    let mut global_slot_index = 0_u32;
    let mut targets = Vec::with_capacity(input.targets.len());
    for target in input.targets {
        ensure!(
            target.slot_ids.len() > 0,
            "target has no resolved output slots"
        );
        let mut slots = Vec::with_capacity(target.slot_ids.len());
        for (sample_index, (slot_id, artifact_id)) in target.slot_ids.into_iter().enumerate() {
            let publication_name = format!(
                "{}-{:03}.{}",
                input.output_authority.0.filename_prefix,
                global_slot_index + 1,
                input.output_authority.0.extension
            );
            let attempts = (1..=target.max_attempts)
                .map(|attempt_number| {
                    let identity = digest_fields(&[
                        &input.job_id.to_string(),
                        &slot_id.to_string(),
                        &attempt_number.to_string(),
                    ]);
                    AttemptPlanV1 {
                        attempt_number,
                        provider_request_identity: format!("request:{identity}"),
                        provider_idempotency_identity: format!("idempotency:{identity}"),
                        resource_maximum: target.attempt_resource_maximum.clone(),
                        maximum_usd_micros: target.attempt_maximum_usd_micros,
                    }
                })
                .collect();
            slots.push(OutputSlotPlanV1 {
                slot_id,
                slot_index: global_slot_index,
                sample_index: u32::try_from(sample_index)?,
                managed_artifact_id: artifact_id,
                publication_name,
                attempts,
            });
            global_slot_index = global_slot_index
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("slot index overflow"))?;
        }
        targets.push(TargetPlanV1 {
            target_id: target.authority.target_id,
            target_config_generation: target.authority.target_config_generation,
            normalized_config_digest: target.authority.normalized_config_digest,
            capability_provenance: target.authority.capability_provenance,
            destination: target.authority.destination,
            reference_artifacts: target.reference_artifacts,
            requested: target.requested,
            resolved: target.resolved,
            typed_parameters: target.typed_parameters,
            sample_count: u32::try_from(slots.len())?,
            max_attempts: target.max_attempts,
            slots,
        });
    }
    let mut plan = ImageGenerationPlanV1 {
        schema_version: 1,
        kind: "imageGenerationPlan".into(),
        job_id: input.job_id,
        owner_session_id: input.owner_session_id,
        owner_principal_digest: input.owner_principal_digest,
        project_identity_digest: input.project_identity_digest,
        config_generation: input.config_generation,
        enqueue_started_monotonic_ms: input.enqueue_started_monotonic_ms,
        operation_deadline_monotonic_ms: input.operation_deadline_monotonic_ms,
        required_grants: input.required_grants,
        central_resources: input.central_resources,
        spend: input.spend,
        output_authority: input.output_authority.0,
        targets,
    };
    plan.required_grants.sort();
    plan.central_resources.sort();
    plan.validate()?;
    Ok(plan)
}

impl RuntimeTargetAuthorityV1 {
    pub fn from_registry_snapshot(
        snapshot: &ImageHealthSnapshot,
        operation_deadline_monotonic_ms: u64,
    ) -> Result<Self> {
        ensure!(
            snapshot.dispatchable_at(snapshot.retrieved_at),
            "runtime target is not dispatchable"
        );
        ensure!(
            snapshot.expires_at >= operation_deadline_monotonic_ms,
            "runtime health expires before operation deadline"
        );
        let capability = snapshot
            .capability
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime capability is missing"))?;
        ensure!(
            capability.expires_at >= operation_deadline_monotonic_ms,
            "runtime capability expires before operation deadline"
        );
        let credential = snapshot
            .credential_identity_digest
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("runtime credential identity is missing"))?;
        Ok(Self {
            target_id: snapshot.target_id.clone(),
            target_config_generation: snapshot.config_generation,
            normalized_config_digest: digest_fields(&[&snapshot.target_immutable_identity]),
            capability_provenance: CapabilityProvenanceV1 {
                capability_generation: snapshot.refresh_epoch,
                capability_digest: digest_fields(&[
                    &capability.target_id,
                    &capability.model_or_workflow_digest,
                ]),
                health_observed_at_monotonic_ms: snapshot.retrieved_at,
                health_expires_at_monotonic_ms: snapshot.expires_at.min(capability.expires_at),
            },
            destination: TargetDestinationV1 {
                adapter_kind: match snapshot.adapter_kind {
                    cockpit_config::config::image_generation::ImageAdapterKind::OpenaiImages => "openai_images",
                    cockpit_config::config::image_generation::ImageAdapterKind::OpenrouterImages => "openrouter_images",
                    cockpit_config::config::image_generation::ImageAdapterKind::GeminiImages => "gemini_images",
                    cockpit_config::config::image_generation::ImageAdapterKind::Comfyui => "comfyui",
                }.into(),
                endpoint_identity_digest: digest_fields(&[
                    &snapshot.endpoint_id,
                    &snapshot.endpoint_origin,
                    &snapshot.target_immutable_identity,
                ]),
                credential_identity_digest: credential.plan_identity_hex(),
                destination_generation: snapshot.config_generation,
            },
        })
    }
}

impl ReferenceArtifactV1 {
    pub fn from_acquired_media_lease(lease: &AcquiredMediaComponentLease) -> Result<Self> {
        ensure!(
            lease.component.lifecycle_state == "ready",
            "reference component is not ready"
        );
        ensure!(
            lease.component.attachment_id == lease.attachment_id
                && lease.component.attachment_version == lease.attachment_version,
            "reference lease identity mismatch"
        );
        Ok(Self {
            attachment_id: lease.attachment_id,
            attachment_version: lease.attachment_version,
            component_id: lease.component.component_id,
            component_generation: lease.component.component_generation,
            media_kind: lease.component.component_kind.clone(),
            identity_digest: lease.component.stable_identity_digest.clone(),
            sha256: lease.component.sha256.clone(),
            byte_length: lease.component.byte_length,
        })
    }
}

impl GrantRequirementV1 {
    pub fn from_sealed_grant(grant: &SealedActionGrantRow, now_ms: i64) -> Result<Self> {
        ensure!(
            grant.revoked_at_ms.is_none()
                && grant.expires_at_ms.is_none_or(|expiry| expiry >= now_ms),
            "sealed grant is not current"
        );
        let generation = u64::try_from(grant.use_epoch)?;
        Ok(Self {
            grant_kind: grant.action_id.clone(),
            authority_digest: digest_fields(&[
                &grant.grant_id,
                &grant.record_id,
                &grant.project_key,
                &grant.session_id,
                &grant.action_id,
            ]),
            generation,
        })
    }
}

impl ResourceReservationV1 {
    pub fn from_media_reservation(
        plan: &MediaReservationPlan,
        reservation_identity: String,
    ) -> Result<Self> {
        ensure!(
            plan.requested > 0 && valid_string(&reservation_identity),
            "media reservation is invalid"
        );
        Ok(Self {
            resource_kind: serde_json::to_value(plan.dimension)?
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("media dimension is not a string"))?
                .to_owned(),
            units: plan.requested,
            reservation_identity,
        })
    }
}

impl SpendReservationPlanV1 {
    pub fn from_spend_reservation(
        reservation: &SpendReservation,
        attempts: &[AttemptMaximum],
    ) -> Result<Self> {
        ensure!(!attempts.is_empty(), "spend attempt graph is empty");
        let maximum =
            attempts
                .iter()
                .try_fold(Some(0_u64), |total, attempt| -> Result<Option<u64>> {
                    match (total, attempt.usd_micros) {
                        (Some(total), Some(value)) => {
                            Ok(Some(total.checked_add(value).ok_or_else(|| {
                                anyhow::anyhow!("spend maximum overflow")
                            })?))
                        }
                        _ => Ok(None),
                    }
                })?;
        ensure!(
            reservation.reserved_usd_micros == maximum
                || reservation.cost_unknown && maximum.is_none(),
            "spend reservation does not cover attempt graph"
        );
        let mut fields = vec![reservation.reservation_id.as_str()];
        for attempt in attempts {
            fields.push(attempt.attempt_id.as_str());
        }
        Ok(Self {
            required: maximum.is_none_or(|value| value > 0),
            policy_version: reservation.policy_version,
            reservation_id: reservation.reservation_id.clone(),
            maximum_usd_micros: maximum,
            plan_digest: digest_fields(&fields),
        })
    }
}

impl ImageGenerationPlanV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }

    pub fn digest(&self) -> Result<String> {
        Ok(crate::intel::hex_lower(&Sha256::digest(
            self.canonical_bytes()?,
        )))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.kind == "imageGenerationPlan",
            "invalid plan envelope"
        );
        ensure!(
            self.job_id.get_version_num() == 7 && !self.owner_session_id.is_nil(),
            "invalid plan authority ids"
        );
        validate_digest(&self.owner_principal_digest)?;
        validate_digest(&self.project_identity_digest)?;
        ensure!(
            self.config_generation > 0,
            "config generation must be positive"
        );
        ensure!(
            self.operation_deadline_monotonic_ms > self.enqueue_started_monotonic_ms,
            "operation deadline must follow enqueue start"
        );
        ensure!(
            !self.required_grants.is_empty()
                && self.required_grants.len() <= MAX_PLAN_LIST_ITEMS
                && strictly_sorted(&self.required_grants),
            "grants must be nonempty, unique, and sorted"
        );
        for grant in &self.required_grants {
            ensure!(
                valid_string(&grant.grant_kind) && grant.generation > 0,
                "grant authority is incomplete"
            );
            validate_digest(&grant.authority_digest)?;
        }
        ensure!(
            !self.central_resources.is_empty()
                && self.central_resources.len() <= MAX_PLAN_LIST_ITEMS
                && strictly_sorted(&self.central_resources),
            "resources must be nonempty, unique, and sorted"
        );
        validate_resources(&self.central_resources)?;
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= MAX_IMAGE_GENERATION_TARGETS,
            "plan target count is out of bounds"
        );
        ensure!(
            self.targets
                .windows(2)
                .all(|pair| pair[0].target_id < pair[1].target_id),
            "targets must be unique and sorted"
        );
        ensure!(
            valid_path_component(&self.output_authority.filename_prefix)
                && valid_path_component(&self.output_authority.extension)
                && self.output_authority.authority_generation > 0,
            "output authority is incomplete"
        );
        validate_digest(&self.output_authority.canonical_destination_digest)?;
        validate_digest(&self.output_authority.parent_identity_digest)?;
        validate_digest(&self.spend.plan_digest)?;
        ensure!(
            self.spend.policy_version > 0 && valid_string(&self.spend.reservation_id),
            "spend authority is incomplete"
        );
        let mut total_maximum = Some(0_u64);
        let mut slot_ids = std::collections::BTreeSet::new();
        let mut artifact_ids = std::collections::BTreeSet::new();
        let mut publication_names = std::collections::BTreeSet::new();
        let mut provider_requests = std::collections::BTreeSet::new();
        let mut provider_idempotencies = std::collections::BTreeSet::new();
        let mut reference_identities = std::collections::BTreeSet::new();
        let mut resource_totals = BTreeMap::<(String, String), u64>::new();
        let mut total_slots = 0_usize;
        for target in &self.targets {
            target.validate(self.operation_deadline_monotonic_ms)?;
            for reference in &target.reference_artifacts {
                ensure!(
                    reference_identities.insert((
                        reference.attachment_id,
                        reference.attachment_version,
                        reference.component_id,
                        reference.component_generation
                    )),
                    "references must be globally unique"
                );
            }
            ensure!(
                target.resolved.format == self.output_authority.extension
                    || (target.resolved.format == "jpeg"
                        && self.output_authority.extension == "jpg")
                    || (target.resolved.format == "jpg"
                        && self.output_authority.extension == "jpeg"),
                "resolved format disagrees with publication extension"
            );
            for (local_index, slot) in target.slots.iter().enumerate() {
                ensure!(
                    slot.slot_index as usize == total_slots + local_index,
                    "global slot order is not canonical"
                );
                ensure!(
                    slot_ids.insert(slot.slot_id) && artifact_ids.insert(slot.managed_artifact_id),
                    "slot/artifact identities must be globally unique"
                );
                ensure!(
                    publication_names.insert(slot.publication_name.clone()),
                    "publication names must be globally unique"
                );
                ensure!(
                    slot.publication_name
                        .starts_with(&self.output_authority.filename_prefix)
                        && slot
                            .publication_name
                            .ends_with(&format!(".{}", self.output_authority.extension)),
                    "publication name is outside the sealed output naming contract"
                );
                for attempt in &slot.attempts {
                    ensure!(
                        provider_requests.insert(attempt.provider_request_identity.clone())
                            && provider_idempotencies
                                .insert(attempt.provider_idempotency_identity.clone()),
                        "provider attempt identities must be globally unique"
                    );
                    for resource in &attempt.resource_maximum {
                        let total = resource_totals
                            .entry((
                                resource.resource_kind.clone(),
                                resource.reservation_identity.clone(),
                            ))
                            .or_default();
                        *total = total
                            .checked_add(resource.units)
                            .ok_or_else(|| anyhow::anyhow!("resource maximum overflow"))?;
                    }
                    total_maximum = match (total_maximum, attempt.maximum_usd_micros) {
                        (Some(total), Some(value)) => Some(
                            total
                                .checked_add(value)
                                .ok_or_else(|| anyhow::anyhow!("spend maximum overflow"))?,
                        ),
                        _ => None,
                    };
                }
            }
            total_slots = total_slots
                .checked_add(target.slots.len())
                .ok_or_else(|| anyhow::anyhow!("slot count overflow"))?;
        }
        ensure!(
            total_slots <= MAX_IMAGE_GENERATION_SLOTS,
            "plan slot count is out of bounds"
        );
        let central_totals = self
            .central_resources
            .iter()
            .map(|resource| {
                (
                    (
                        resource.resource_kind.clone(),
                        resource.reservation_identity.clone(),
                    ),
                    resource.units,
                )
            })
            .collect::<BTreeMap<_, _>>();
        ensure!(
            central_totals == resource_totals,
            "central resources must cover the complete attempt graph exactly"
        );
        ensure!(
            self.spend.maximum_usd_micros == total_maximum,
            "spend maximum must cover the complete attempt graph"
        );
        ensure!(
            self.spend.maximum_usd_micros.unwrap_or(0) == 0 || self.spend.required,
            "known paid maximum requires spend reservation"
        );
        Ok(())
    }
}

pub fn verify_canonical_image_generation_plan(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<ImageGenerationPlanV1> {
    validate_digest(expected_digest)?;
    let plan: ImageGenerationPlanV1 = serde_json::from_slice(bytes)?;
    plan.validate()?;
    ensure!(
        serde_json::to_vec(&plan)? == bytes,
        "plan bytes are not canonical"
    );
    ensure!(
        crate::intel::hex_lower(&Sha256::digest(bytes)) == expected_digest,
        "plan digest mismatch"
    );
    Ok(plan)
}

impl TargetPlanV1 {
    fn validate(&self, operation_deadline_monotonic_ms: u64) -> Result<()> {
        ensure!(
            valid_string(&self.target_id) && self.target_config_generation > 0,
            "target identity is incomplete"
        );
        validate_digest(&self.normalized_config_digest)?;
        validate_digest(&self.capability_provenance.capability_digest)?;
        ensure!(
            self.capability_provenance.capability_generation > 0
                && self.capability_provenance.health_expires_at_monotonic_ms
                    > self.capability_provenance.health_observed_at_monotonic_ms
                && self.capability_provenance.health_expires_at_monotonic_ms
                    >= operation_deadline_monotonic_ms,
            "capability provenance is incomplete"
        );
        validate_digest(&self.destination.endpoint_identity_digest)?;
        validate_digest(&self.destination.credential_identity_digest)?;
        ensure!(
            valid_string(&self.destination.adapter_kind)
                && self.destination.destination_generation > 0,
            "destination authority is incomplete"
        );
        ensure!(
            self.requested.width > 0
                && self.requested.height > 0
                && self.resolved.width > 0
                && self.resolved.height > 0
                && self.requested.width <= MAX_IMAGE_GENERATION_DIMENSION
                && self.requested.height <= MAX_IMAGE_GENERATION_DIMENSION
                && self.resolved.width <= MAX_IMAGE_GENERATION_DIMENSION
                && self.resolved.height <= MAX_IMAGE_GENERATION_DIMENSION,
            "dimensions must be positive"
        );
        ensure!(
            valid_string(&self.requested.format)
                && valid_string(&self.resolved.format)
                && valid_string(&self.resolved.mime),
            "format resolution is incomplete"
        );
        let (expected_mime, requires_vector_sanitizer) = match self.resolved.format.as_str() {
            "png" => ("image/png", false),
            "jpeg" | "jpg" => ("image/jpeg", false),
            "webp" => ("image/webp", false),
            "svg" => ("image/svg+xml", true),
            _ => anyhow::bail!("resolved output format is unsupported"),
        };
        ensure!(
            self.resolved.mime == expected_mime
                && self.resolved.vector_sanitization_required == requires_vector_sanitizer,
            "resolved format, MIME, and sanitizer contract disagree"
        );
        ensure!(
            self.sample_count > 0
                && self.sample_count as usize <= MAX_IMAGE_GENERATION_SLOTS
                && self.max_attempts > 0
                && self.max_attempts <= MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT,
            "sample and attempt counts must be positive"
        );
        ensure!(
            self.slots.len() == self.sample_count as usize,
            "sample count must equal slot count"
        );
        ensure!(
            self.reference_artifacts.len() <= MAX_PLAN_LIST_ITEMS
                && strictly_sorted(&self.reference_artifacts),
            "references must be unique and sorted"
        );
        ensure!(
            self.typed_parameters.len() <= MAX_PLAN_LIST_ITEMS
                && self
                    .typed_parameters
                    .iter()
                    .all(|(key, value)| valid_string(key)
                        && match value {
                            TypedParameterV1::Text(text) => valid_string(text),
                            _ => true,
                        }),
            "typed parameters exceed plan bounds"
        );
        for reference in &self.reference_artifacts {
            ensure!(
                reference.attachment_id.get_version_num() == 7
                    && reference.component_id.get_version_num() == 7
                    && reference.attachment_version > 0
                    && reference.component_generation > 0
                    && reference.byte_length > 0
                    && valid_string(&reference.media_kind),
                "reference authority is incomplete"
            );
            validate_digest(&reference.identity_digest)?;
            validate_digest(&reference.sha256)?;
        }
        for (index, slot) in self.slots.iter().enumerate() {
            ensure!(
                slot.slot_id.get_version_num() == 7
                    && slot.managed_artifact_id.get_version_num() == 7
                    && valid_path_component(&slot.publication_name),
                "slot identity is incomplete"
            );
            ensure!(
                slot.sample_index as usize == index,
                "slot order is not canonical"
            );
            ensure!(
                slot.attempts.len() == self.max_attempts as usize,
                "attempt graph is incomplete"
            );
            for (attempt_index, attempt) in slot.attempts.iter().enumerate() {
                ensure!(
                    attempt.attempt_number as usize == attempt_index + 1,
                    "attempt numbers must be contiguous from one"
                );
                ensure!(
                    valid_string(&attempt.provider_request_identity)
                        && valid_string(&attempt.provider_idempotency_identity),
                    "attempt provider identity is incomplete"
                );
                ensure!(
                    strictly_sorted(&attempt.resource_maximum),
                    "attempt resources must be unique and sorted"
                );
                validate_resources(&attempt.resource_maximum)?;
            }
        }
        Ok(())
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
        "invalid digest"
    );
    Ok(())
}

fn digest_fields(fields: &[&str]) -> String {
    let mut digest = Sha256::new();
    for field in fields {
        digest.update((field.len() as u64).to_be_bytes());
        digest.update(field.as_bytes());
    }
    crate::intel::hex_lower(&digest.finalize())
}

fn valid_string(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_PLAN_STRING_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_path_component(value: &str) -> bool {
    valid_string(value) && value != "." && value != ".." && !value.contains(['/', '\\'])
}

fn validate_resources(resources: &[ResourceReservationV1]) -> Result<()> {
    ensure!(
        resources.len() <= MAX_PLAN_LIST_ITEMS,
        "resource list exceeds plan bound"
    );
    for resource in resources {
        ensure!(
            valid_string(&resource.resource_kind)
                && resource.units > 0
                && valid_string(&resource.reservation_identity),
            "resource reservation is incomplete"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(tail: u128) -> Uuid {
        Uuid::from_u128(0x018f3f247a107cc28000000000000000 | tail)
    }
    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }
    fn plan() -> ImageGenerationPlanV1 {
        let resources = vec![ResourceReservationV1 {
            resource_kind: "gpu".into(),
            units: 1,
            reservation_identity: "gpu:1".into(),
        }];
        ImageGenerationPlanV1 {
            schema_version: 1,
            kind: "imageGenerationPlan".into(),
            job_id: id(1),
            owner_session_id: Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa),
            owner_principal_digest: digest('1'),
            project_identity_digest: digest('2'),
            config_generation: 7,
            enqueue_started_monotonic_ms: 100,
            operation_deadline_monotonic_ms: 400,
            required_grants: vec![GrantRequirementV1 {
                grant_kind: "image_generation".into(),
                authority_digest: digest('3'),
                generation: 2,
            }],
            central_resources: resources.clone(),
            spend: SpendReservationPlanV1 {
                required: true,
                policy_version: 3,
                reservation_id: "spend:job".into(),
                maximum_usd_micros: Some(10),
                plan_digest: digest('4'),
            },
            output_authority: OutputDirectoryAuthorityV1 {
                canonical_destination_digest: digest('5'),
                parent_identity_digest: digest('6'),
                authority_generation: 4,
                filename_prefix: "generated".into(),
                extension: "png".into(),
            },
            targets: vec![TargetPlanV1 {
                target_id: "target-a".into(),
                target_config_generation: 9,
                normalized_config_digest: digest('7'),
                capability_provenance: CapabilityProvenanceV1 {
                    capability_generation: 5,
                    capability_digest: digest('8'),
                    health_observed_at_monotonic_ms: 90,
                    health_expires_at_monotonic_ms: 900,
                },
                destination: TargetDestinationV1 {
                    adapter_kind: "fixture".into(),
                    endpoint_identity_digest: digest('9'),
                    credential_identity_digest: digest('a'),
                    destination_generation: 6,
                },
                reference_artifacts: vec![],
                requested: RequestedOutputV1 {
                    width: 512,
                    height: 512,
                    format: "png".into(),
                },
                resolved: ResolvedOutputV1 {
                    width: 512,
                    height: 512,
                    format: "png".into(),
                    mime: "image/png".into(),
                    vector_sanitization_required: false,
                },
                typed_parameters: BTreeMap::from([(
                    "quality".into(),
                    TypedParameterV1::Integer(90),
                )]),
                sample_count: 1,
                max_attempts: 1,
                slots: vec![OutputSlotPlanV1 {
                    slot_id: id(2),
                    slot_index: 0,
                    sample_index: 0,
                    managed_artifact_id: id(3),
                    publication_name: "generated-001.png".into(),
                    attempts: vec![AttemptPlanV1 {
                        attempt_number: 1,
                        provider_request_identity: "request:1".into(),
                        provider_idempotency_identity: "idem:1".into(),
                        resource_maximum: resources,
                        maximum_usd_micros: Some(10),
                    }],
                }],
            }],
        }
    }

    #[test]
    fn canonical_plan_is_stable_and_every_authority_family_changes_digest() {
        let original = plan();
        let bytes = original.canonical_bytes().unwrap();
        assert_eq!(bytes, original.canonical_bytes().unwrap());
        let baseline = original.digest().unwrap();
        assert_eq!(
            baseline,
            "3e7894cab2e1fb43b2fdba8b9144e88f1394904130bd177a08c29e06f4a843b4"
        );
        assert_eq!(
            verify_canonical_image_generation_plan(&bytes, &baseline).unwrap(),
            original
        );
        let mut noncanonical = bytes.clone();
        noncanonical.push(b' ');
        assert!(verify_canonical_image_generation_plan(&noncanonical, &baseline).is_err());
        let mut mutations: Vec<Box<dyn Fn(&mut ImageGenerationPlanV1)>> = vec![
            Box::new(|p| p.job_id = id(4)),
            Box::new(|p| {
                p.owner_session_id = Uuid::from_u128(0xbbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb)
            }),
            Box::new(|p| p.owner_principal_digest = digest('b')),
            Box::new(|p| p.project_identity_digest = digest('c')),
            Box::new(|p| p.config_generation += 1),
            Box::new(|p| p.enqueue_started_monotonic_ms += 1),
            Box::new(|p| p.operation_deadline_monotonic_ms += 1),
            Box::new(|p| p.required_grants[0].generation += 1),
            Box::new(|p| {
                p.central_resources[0].units += 1;
                p.targets[0].slots[0].attempts[0].resource_maximum[0].units += 1;
            }),
            Box::new(|p| p.spend.policy_version += 1),
            Box::new(|p| p.output_authority.authority_generation += 1),
            Box::new(|p| p.targets[0].target_config_generation += 1),
            Box::new(|p| p.targets[0].normalized_config_digest = digest('d')),
            Box::new(|p| p.targets[0].destination.destination_generation += 1),
            Box::new(|p| p.targets[0].capability_provenance.capability_generation += 1),
            Box::new(|p| {
                p.targets[0].reference_artifacts.push(ReferenceArtifactV1 {
                    attachment_id: id(5),
                    attachment_version: 1,
                    component_id: id(6),
                    component_generation: 1,
                    media_kind: "image".into(),
                    identity_digest: digest('d'),
                    sha256: digest('e'),
                    byte_length: 1,
                })
            }),
            Box::new(|p| p.targets[0].requested.width += 1),
            Box::new(|p| p.targets[0].resolved.height += 1),
            Box::new(|p| {
                p.targets[0]
                    .typed_parameters
                    .insert("seed".into(), TypedParameterV1::Integer(1));
            }),
            Box::new(|p| p.targets[0].slots[0].publication_name = "generated-x-001.png".into()),
            Box::new(|p| p.targets[0].slots[0].managed_artifact_id = id(7)),
            Box::new(|p| {
                p.targets[0].slots[0].attempts[0]
                    .provider_request_identity
                    .push('x')
            }),
            Box::new(|p| {
                p.targets[0].slots[0].attempts[0]
                    .provider_idempotency_identity
                    .push('x')
            }),
        ];
        for mutate in mutations.drain(..) {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(changed.digest().unwrap(), baseline);
        }
    }

    #[test]
    fn plan_rejects_every_ambiguous_boundary_before_hashing() {
        let rejects: Vec<Box<dyn Fn(&mut ImageGenerationPlanV1)>> = vec![
            Box::new(|p| p.output_authority.authority_generation = 0),
            Box::new(|p| {
                p.targets[0]
                    .capability_provenance
                    .health_expires_at_monotonic_ms = p.operation_deadline_monotonic_ms - 1
            }),
            Box::new(|p| p.targets[0].slots[0].publication_name = "../generated.png".into()),
            Box::new(|p| p.targets[0].resolved.mime = "image/jpeg".into()),
            Box::new(|p| p.targets[0].resolved.vector_sanitization_required = true),
            Box::new(|p| p.targets[0].resolved.width = MAX_IMAGE_GENERATION_DIMENSION + 1),
            Box::new(|p| p.central_resources[0].units += 1),
            Box::new(|p| p.spend.maximum_usd_micros = Some(9)),
            Box::new(|p| p.targets[0].max_attempts = MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT + 1),
        ];
        for reject in rejects {
            let mut invalid = plan();
            reject(&mut invalid);
            assert!(invalid.digest().is_err());
        }
        let mut exact = plan();
        exact.targets[0].resolved.width = MAX_IMAGE_GENERATION_DIMENSION;
        assert!(exact.digest().is_ok());
    }
}
