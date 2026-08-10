//! Immutable provider-neutral image-generation preflight plans.
//!
//! The planner emits this closed DTO only after resolving every target and
//! output slot. Its canonical bytes are the authorization, queue, spend, and
//! provider-dispatch binding; no dispatcher may reinterpret caller input.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Result, ensure};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::image_generation_runtime::ImageHealthSnapshot;
use cockpit_config::config::media_budget::MediaReservationPlan;
use cockpit_db::db::sealed_scope::SealedActionGrantRow;
use cockpit_db::image_spend::{AttemptMaximum, SpendReservation};
use cockpit_db::media_attachments::AcquiredMediaComponentLease;

pub use cockpit_db::image_generation_plan::{
    AttemptPlanV1, CapabilityProvenanceV1, GrantRequirementV1, ImageGenerationPlanV1,
    MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT, MAX_IMAGE_GENERATION_DIMENSION,
    MAX_IMAGE_GENERATION_SLOTS, MAX_IMAGE_GENERATION_TARGETS, OutputDirectoryAuthorityV1,
    OutputSlotPlanV1, ReferenceArtifactV1, RequestedOutputV1, ResolvedOutputV1,
    ResourceReservationV1, SpendReservationPlanV1, TargetDestinationV1, TargetPlanV1,
    TypedParameterV1,
};

const MAX_AUTHORITY_STRING_BYTES: usize = 1_024;

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

#[derive(Debug)]
pub struct HeldImageGenerationOutputDirectory {
    guard: crate::external_journal::fsguard::DirGuard,
    authority: VerifiedOutputDirectoryAuthority,
}
impl HeldImageGenerationOutputDirectory {
    pub fn authority(&self) -> &VerifiedOutputDirectoryAuthority {
        &self.authority
    }
    pub fn path(&self) -> &Path {
        self.guard.path()
    }
}
pub fn open_image_generation_output_directory(
    path: &Path,
    authority_generation: u64,
    filename_prefix: String,
    extension: String,
) -> Result<HeldImageGenerationOutputDirectory> {
    let guard = crate::external_journal::fsguard::DirGuard::open_root(path, false)
        .map_err(anyhow::Error::new)?;
    guard.verify_private().map_err(anyhow::Error::new)?;
    let parent_identity_digest = guard.stable_identity_digest().map_err(anyhow::Error::new)?;
    let canonical_destination_digest =
        digest_fields(&["held-output-directory-v1", &parent_identity_digest]);
    let authority = VerifiedOutputDirectoryAuthority::from_held_directory(
        canonical_destination_digest,
        parent_identity_digest,
        authority_generation,
        filename_prefix,
        extension,
    )?;
    Ok(HeldImageGenerationOutputDirectory { guard, authority })
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
            !target.slot_ids.is_empty(),
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

pub fn reference_artifact_from_acquired_media_lease(
    lease: &AcquiredMediaComponentLease,
) -> Result<ReferenceArtifactV1> {
    ensure!(
        lease.component.lifecycle_state == "ready",
        "reference component is not ready"
    );
    ensure!(
        lease.component.attachment_id == lease.attachment_id
            && lease.component.attachment_version == lease.attachment_version,
        "reference lease identity mismatch"
    );
    Ok(ReferenceArtifactV1 {
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

pub fn grant_requirement_from_sealed_grant(
    grant: &SealedActionGrantRow,
    now_ms: i64,
) -> Result<GrantRequirementV1> {
    ensure!(
        grant.revoked_at_ms.is_none() && grant.expires_at_ms.is_none_or(|expiry| expiry >= now_ms),
        "sealed grant is not current"
    );
    let generation = u64::try_from(grant.use_epoch)?;
    Ok(GrantRequirementV1 {
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

pub fn resource_reservation_from_media_reservation(
    plan: &MediaReservationPlan,
    reservation_identity: String,
) -> Result<ResourceReservationV1> {
    ensure!(
        plan.requested > 0 && valid_string(&reservation_identity),
        "media reservation is invalid"
    );
    Ok(ResourceReservationV1 {
        resource_kind: serde_json::to_value(plan.dimension)?
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("media dimension is not a string"))?
            .to_owned(),
        units: plan.requested,
        reservation_identity,
    })
}

pub fn spend_plan_from_spend_reservation(
    reservation: &SpendReservation,
    attempts: &[AttemptMaximum],
) -> Result<SpendReservationPlanV1> {
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
        reservation.reserved_usd_micros == maximum || reservation.cost_unknown && maximum.is_none(),
        "spend reservation does not cover attempt graph"
    );
    let mut fields = vec![reservation.reservation_id.as_str()];
    for attempt in attempts {
        fields.push(attempt.attempt_id.as_str());
    }
    Ok(SpendReservationPlanV1 {
        required: maximum.is_none_or(|value| value > 0),
        policy_version: reservation.policy_version,
        reservation_id: reservation.reservation_id.clone(),
        maximum_usd_micros: maximum,
        plan_digest: digest_fields(&fields),
    })
}

pub fn verify_canonical_image_generation_plan(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<ImageGenerationPlanV1> {
    ImageGenerationPlanV1::from_canonical(bytes, expected_digest)
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
        && value.len() <= MAX_AUTHORITY_STRING_BYTES
        && !value.chars().any(char::is_control)
}

fn valid_path_component(value: &str) -> bool {
    valid_string(value) && value != "." && value != ".." && !value.contains(['/', '\\'])
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

    #[test]
    fn slot_and_dimension_bounds_are_exact_below_equal_above() {
        fn with_slots(count: usize) -> ImageGenerationPlanV1 {
            let mut value = plan();
            let template = value.targets[0].slots[0].clone();
            value.targets[0].slots = (0..count)
                .map(|index| {
                    let mut slot = template.clone();
                    slot.slot_id = id(100 + index as u128);
                    slot.managed_artifact_id = id(1000 + index as u128);
                    slot.slot_index = index as u32;
                    slot.sample_index = index as u32;
                    slot.publication_name = format!("generated-{:03}.png", index + 1);
                    slot.attempts[0].provider_request_identity = format!("request:{index}");
                    slot.attempts[0].provider_idempotency_identity = format!("idem:{index}");
                    slot
                })
                .collect();
            value.targets[0].sample_count = count as u32;
            value.central_resources[0].units = count as u64;
            value.spend.maximum_usd_micros = Some((count as u64) * 10);
            value
        }
        for count in [MAX_IMAGE_GENERATION_SLOTS - 1, MAX_IMAGE_GENERATION_SLOTS] {
            assert!(with_slots(count).validate().is_ok());
        }
        assert!(
            with_slots(MAX_IMAGE_GENERATION_SLOTS + 1)
                .validate()
                .is_err()
        );
        for dimension in [
            MAX_IMAGE_GENERATION_DIMENSION - 1,
            MAX_IMAGE_GENERATION_DIMENSION,
        ] {
            let mut value = plan();
            value.targets[0].requested.width = dimension;
            value.targets[0].resolved.width = dimension;
            assert!(value.validate().is_ok());
        }
        let mut above = plan();
        above.targets[0].requested.width = MAX_IMAGE_GENERATION_DIMENSION + 1;
        assert!(above.validate().is_err());
    }

    #[test]
    fn every_serialized_scalar_and_list_element_changes_canonical_digest() {
        fn paths(
            value: &serde_json::Value,
            path: String,
            scalars: &mut Vec<String>,
            arrays: &mut Vec<String>,
        ) {
            match value {
                serde_json::Value::Object(map) => {
                    for (key, value) in map {
                        paths(
                            value,
                            format!("{path}/{}", key.replace('~', "~0").replace('/', "~1")),
                            scalars,
                            arrays,
                        )
                    }
                }
                serde_json::Value::Array(values) => {
                    arrays.push(path.clone());
                    for (index, value) in values.iter().enumerate() {
                        paths(value, format!("{path}/{index}"), scalars, arrays)
                    }
                }
                _ => scalars.push(path),
            }
        }
        let mut source = plan();
        source.targets[0]
            .reference_artifacts
            .push(ReferenceArtifactV1 {
                attachment_id: id(10),
                attachment_version: 1,
                component_id: id(11),
                component_generation: 1,
                media_kind: "image_model".into(),
                identity_digest: digest('b'),
                sha256: digest('c'),
                byte_length: 1,
            });
        let value = serde_json::to_value(source).unwrap();
        let baseline = serde_json::to_vec(&value).unwrap();
        let baseline_digest = Sha256::digest(&baseline);
        let mut scalars = Vec::new();
        let mut arrays = Vec::new();
        paths(&value, String::new(), &mut scalars, &mut arrays);
        for path in scalars {
            let mut changed = value.clone();
            let leaf = changed.pointer_mut(&path).unwrap();
            *leaf = match leaf {
                serde_json::Value::Bool(value) => serde_json::Value::Bool(!*value),
                serde_json::Value::Number(value) => {
                    serde_json::json!(value.as_i64().unwrap_or(0) + 1)
                }
                serde_json::Value::String(value) => serde_json::Value::String(format!("{value}x")),
                serde_json::Value::Null => serde_json::Value::Bool(true),
                _ => unreachable!(),
            };
            assert_ne!(
                Sha256::digest(serde_json::to_vec(&changed).unwrap()),
                baseline_digest,
                "{path}"
            );
        }
        for path in arrays {
            let length = value
                .pointer(&path)
                .and_then(serde_json::Value::as_array)
                .map_or(0, Vec::len);
            for index in 0..length {
                let mut changed = value.clone();
                changed
                    .pointer_mut(&path)
                    .unwrap()
                    .as_array_mut()
                    .unwrap()
                    .remove(index);
                assert_ne!(
                    Sha256::digest(serde_json::to_vec(&changed).unwrap()),
                    baseline_digest,
                    "{path}/{index}"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn output_authority_is_held_private_and_nofollow() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temporary = tempfile::TempDir::new().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held =
            open_image_generation_output_directory(&output, 1, "generated".into(), "png".into())
                .unwrap();
        assert_eq!(held.path(), output.canonicalize().unwrap());
        let replacement = temporary.path().join("replacement");
        std::fs::create_dir(&replacement).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&output, temporary.path().join("moved")).unwrap();
        std::fs::rename(&replacement, &output).unwrap();
        assert_ne!(
            held.authority().0.parent_identity_digest,
            open_image_generation_output_directory(&output, 1, "generated".into(), "png".into())
                .unwrap()
                .authority()
                .0
                .parent_identity_digest
        );
        let widened = temporary.path().join("widened");
        std::fs::create_dir(&widened).unwrap();
        std::fs::set_permissions(&widened, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            open_image_generation_output_directory(&widened, 1, "generated".into(), "png".into())
                .is_err()
        );
        let link = temporary.path().join("link");
        symlink(&output, &link).unwrap();
        assert!(
            open_image_generation_output_directory(&link, 1, "generated".into(), "png".into())
                .is_err()
        );
    }

    #[cfg(windows)]
    #[test]
    fn output_authority_requires_protected_dacl_and_rejects_reparse() {
        use std::os::windows::fs::symlink_dir;
        let temporary = tempfile::TempDir::new().unwrap();
        let output = temporary.path().join("output");
        std::fs::create_dir(&output).unwrap();
        crate::goal_scratch::set_private(&output).unwrap();
        assert!(
            open_image_generation_output_directory(&output, 1, "generated".into(), "png".into())
                .is_ok()
        );
        let link = temporary.path().join("link");
        if symlink_dir(&output, &link).is_ok() {
            assert!(
                open_image_generation_output_directory(&link, 1, "generated".into(), "png".into())
                    .is_err()
            );
        }
    }
}
