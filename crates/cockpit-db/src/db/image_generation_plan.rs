//! Closed canonical image-generation plan shared by planning and persistence.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const MAX_IMAGE_GENERATION_TARGETS: usize = 16;
pub const MAX_IMAGE_GENERATION_SLOTS: usize = 256;
pub const MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT: u32 = 8;
pub const MAX_IMAGE_GENERATION_DIMENSION: u32 = 16_384;
pub const MAX_PLAN_STRING_BYTES: usize = 1_024;
pub const MAX_PLAN_LIST_ITEMS: usize = 64;

macro_rules! dto {($name:ident{$($field:ident:$ty:ty),*$(,)?})=>{#[derive(Debug,Clone,PartialEq,Eq,Serialize,Deserialize)]#[serde(rename_all="camelCase",deny_unknown_fields)]pub struct $name{$(pub $field:$ty),*}}}
dto!(ImageGenerationPlanV1{schema_version:u8,kind:String,job_id:Uuid,owner_session_id:Uuid,owner_principal_digest:String,project_identity_digest:String,config_generation:u64,enqueue_started_monotonic_ms:u64,operation_deadline_monotonic_ms:u64,required_grants:Vec<GrantRequirementV1>,central_resources:Vec<ResourceReservationV1>,spend:SpendReservationPlanV1,output_authority:OutputDirectoryAuthorityV1,targets:Vec<TargetPlanV1>});
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
dto!(SpendReservationPlanV1{required:bool,policy_version:u64,reservation_id:String,maximum_usd_micros:Option<u64>,plan_digest:String});
dto!(OutputDirectoryAuthorityV1 {
    canonical_destination_digest: String,
    parent_identity_digest: String,
    authority_generation: u64,
    filename_prefix: String,
    extension: String
});
dto!(TargetPlanV1{target_id:String,target_config_generation:u64,normalized_config_digest:String,capability_provenance:CapabilityProvenanceV1,destination:TargetDestinationV1,reference_artifacts:Vec<ReferenceArtifactV1>,requested:RequestedOutputV1,resolved:ResolvedOutputV1,typed_parameters:BTreeMap<String,TypedParameterV1>,sample_count:u32,max_attempts:u32,slots:Vec<OutputSlotPlanV1>});
dto!(CapabilityProvenanceV1 {
    capability_generation: u64,
    capability_digest: String,
    health_observed_at_monotonic_ms: u64,
    health_expires_at_monotonic_ms: u64
});
dto!(TargetDestinationV1 {
    adapter_kind: String,
    endpoint_identity_digest: String,
    credential_identity_digest: String,
    destination_generation: u64
});
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
dto!(RequestedOutputV1 {
    width: u32,
    height: u32,
    format: String
});
dto!(ResolvedOutputV1 {
    width: u32,
    height: u32,
    format: String,
    mime: String,
    vector_sanitization_required: bool,
    vector_sanitizer: Option<VectorSanitizerProvenanceV1>
});
dto!(VectorSanitizerProvenanceV1 {
    schema_version: u8,
    sanitizer_kind: String,
    policy_digest: String
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum TypedParameterV1 {
    Boolean(bool),
    Integer(i64),
    Text(String),
}
dto!(OutputSlotPlanV1{slot_id:Uuid,slot_index:u32,sample_index:u32,managed_artifact_id:Uuid,publication_name:String,attempts:Vec<AttemptPlanV1>});
dto!(AttemptPlanV1{attempt_number:u32,provider_request_identity:String,provider_idempotency_identity:String,resource_maximum:Vec<ResourceReservationV1>,maximum_usd_micros:Option<u64>});

impl ImageGenerationPlanV1 {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        Ok(serde_json::to_vec(self)?)
    }
    pub fn digest(&self) -> Result<String> {
        Ok(hex(&Sha256::digest(self.canonical_bytes()?)))
    }
    pub fn from_canonical(bytes: &[u8], expected_digest: &str) -> Result<Self> {
        digest(expected_digest)?;
        let plan: Self = serde_json::from_slice(bytes)?;
        plan.validate()?;
        ensure!(
            serde_json::to_vec(&plan)? == bytes,
            "plan bytes are not canonical"
        );
        ensure!(
            hex(&Sha256::digest(bytes)) == expected_digest,
            "plan digest mismatch"
        );
        Ok(plan)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && self.kind == "imageGenerationPlan",
            "invalid plan envelope"
        );
        ensure!(
            self.job_id.get_version_num() == 7 && !self.owner_session_id.is_nil(),
            "invalid authority ids"
        );
        digest(&self.owner_principal_digest)?;
        digest(&self.project_identity_digest)?;
        ensure!(
            self.config_generation > 0
                && self.operation_deadline_monotonic_ms > self.enqueue_started_monotonic_ms,
            "invalid generation/deadline"
        );
        ensure!(
            !self.required_grants.is_empty()
                && self.required_grants.len() <= MAX_PLAN_LIST_ITEMS
                && sorted(&self.required_grants),
            "invalid grants"
        );
        for value in &self.required_grants {
            ensure!(
                text(&value.grant_kind) && value.generation > 0,
                "invalid grant"
            );
            digest(&value.authority_digest)?;
        }
        ensure!(
            !self.central_resources.is_empty()
                && self.central_resources.len() <= MAX_PLAN_LIST_ITEMS
                && sorted(&self.central_resources),
            "invalid resources"
        );
        resources(&self.central_resources)?;
        ensure!(
            !self.targets.is_empty()
                && self.targets.len() <= MAX_IMAGE_GENERATION_TARGETS
                && self
                    .targets
                    .windows(2)
                    .all(|p| p[0].target_id < p[1].target_id),
            "invalid targets"
        );
        ensure!(
            component(&self.output_authority.filename_prefix)
                && component(&self.output_authority.extension)
                && self.output_authority.authority_generation > 0,
            "invalid output authority"
        );
        digest(&self.output_authority.canonical_destination_digest)?;
        digest(&self.output_authority.parent_identity_digest)?;
        digest(&self.spend.plan_digest)?;
        ensure!(
            self.spend.policy_version > 0 && text(&self.spend.reservation_id),
            "invalid spend authority"
        );
        let mut ids = BTreeSet::new();
        let mut artifacts = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut requests = BTreeSet::new();
        let mut idempotencies = BTreeSet::new();
        let mut references = BTreeSet::new();
        let mut resource_totals = BTreeMap::new();
        let mut spend = Some(0u64);
        let mut slot_index = 0usize;
        for target in &self.targets {
            target.validate(self.operation_deadline_monotonic_ms)?;
            ensure!(
                target.resolved.format == self.output_authority.extension
                    || (target.resolved.format == "jpeg"
                        && self.output_authority.extension == "jpg")
                    || (target.resolved.format == "jpg"
                        && self.output_authority.extension == "jpeg"),
                "format/extension mismatch"
            );
            for reference in &target.reference_artifacts {
                ensure!(
                    references.insert((
                        reference.attachment_id,
                        reference.attachment_version,
                        reference.component_id,
                        reference.component_generation
                    )),
                    "duplicate reference"
                );
            }
            for slot in &target.slots {
                ensure!(
                    slot.slot_index as usize == slot_index,
                    "noncanonical slot order"
                );
                slot_index += 1;
                ensure!(
                    ids.insert(slot.slot_id)
                        && artifacts.insert(slot.managed_artifact_id)
                        && names.insert(slot.publication_name.clone()),
                    "duplicate slot identity"
                );
                ensure!(
                    slot.publication_name
                        .starts_with(&self.output_authority.filename_prefix)
                        && slot
                            .publication_name
                            .ends_with(&format!(".{}", self.output_authority.extension)),
                    "invalid publication name"
                );
                for attempt in &slot.attempts {
                    ensure!(
                        requests.insert(attempt.provider_request_identity.clone())
                            && idempotencies.insert(attempt.provider_idempotency_identity.clone()),
                        "duplicate provider identity"
                    );
                    for resource in &attempt.resource_maximum {
                        let total = resource_totals
                            .entry((
                                resource.resource_kind.clone(),
                                resource.reservation_identity.clone(),
                            ))
                            .or_insert(0u64);
                        *total = total
                            .checked_add(resource.units)
                            .ok_or_else(|| anyhow::anyhow!("resource overflow"))?;
                    }
                    spend = match (spend, attempt.maximum_usd_micros) {
                        (Some(a), Some(b)) => Some(
                            a.checked_add(b)
                                .ok_or_else(|| anyhow::anyhow!("spend overflow"))?,
                        ),
                        _ => None,
                    };
                }
            }
        }
        ensure!(slot_index <= MAX_IMAGE_GENERATION_SLOTS, "too many slots");
        let central = self
            .central_resources
            .iter()
            .map(|r| {
                (
                    (r.resource_kind.clone(), r.reservation_identity.clone()),
                    r.units,
                )
            })
            .collect::<BTreeMap<_, _>>();
        ensure!(
            central == resource_totals && spend == self.spend.maximum_usd_micros,
            "aggregate reservation mismatch"
        );
        ensure!(
            spend.unwrap_or(0) == 0 || self.spend.required,
            "paid plan lacks spend reservation"
        );
        Ok(())
    }
}
impl TargetPlanV1 {
    fn validate(&self, deadline: u64) -> Result<()> {
        ensure!(
            text(&self.target_id) && self.target_config_generation > 0,
            "invalid target"
        );
        digest(&self.normalized_config_digest)?;
        digest(&self.capability_provenance.capability_digest)?;
        ensure!(
            self.capability_provenance.capability_generation > 0
                && self.capability_provenance.health_expires_at_monotonic_ms
                    > self.capability_provenance.health_observed_at_monotonic_ms
                && self.capability_provenance.health_expires_at_monotonic_ms >= deadline,
            "expired capability"
        );
        digest(&self.destination.endpoint_identity_digest)?;
        digest(&self.destination.credential_identity_digest)?;
        ensure!(
            text(&self.destination.adapter_kind) && self.destination.destination_generation > 0,
            "invalid destination"
        );
        ensure!(
            [
                self.requested.width,
                self.requested.height,
                self.resolved.width,
                self.resolved.height
            ]
            .into_iter()
            .all(|v| v > 0 && v <= MAX_IMAGE_GENERATION_DIMENSION),
            "invalid dimensions"
        );
        let contract = match self.resolved.format.as_str() {
            "png" => ("image/png", false),
            "jpeg" | "jpg" => ("image/jpeg", false),
            "webp" => ("image/webp", false),
            "svg" => ("image/svg+xml", true),
            _ => anyhow::bail!("unsupported format"),
        };
        ensure!(
            text(&self.requested.format)
                && self.resolved.mime == contract.0
                && self.resolved.vector_sanitization_required == contract.1,
            "invalid output contract"
        );
        match (&self.resolved.vector_sanitizer, contract.1) {
            (Some(provenance), true) => {
                ensure!(
                    provenance.schema_version == 1
                        && provenance.sanitizer_kind == "generated_svg_closed_policy",
                    "invalid vector sanitizer schema"
                );
                digest(&provenance.policy_digest)?;
            }
            (None, false) => {}
            _ => anyhow::bail!("vector sanitizer provenance disagrees with output format"),
        }
        ensure!(
            self.sample_count > 0
                && self.sample_count as usize <= MAX_IMAGE_GENERATION_SLOTS
                && self.max_attempts > 0
                && self.max_attempts <= MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT
                && self.slots.len() == self.sample_count as usize,
            "invalid sample graph"
        );
        ensure!(
            self.reference_artifacts.len() <= MAX_PLAN_LIST_ITEMS
                && sorted(&self.reference_artifacts)
                && self.typed_parameters.len() <= MAX_PLAN_LIST_ITEMS,
            "invalid references/parameters"
        );
        for reference in &self.reference_artifacts {
            ensure!(
                reference.attachment_id.get_version_num() == 7
                    && reference.component_id.get_version_num() == 7
                    && reference.attachment_version > 0
                    && reference.component_generation > 0
                    && reference.byte_length > 0
                    && text(&reference.media_kind),
                "invalid reference"
            );
            digest(&reference.identity_digest)?;
            digest(&reference.sha256)?;
        }
        for (index, slot) in self.slots.iter().enumerate() {
            ensure!(
                slot.slot_id.get_version_num() == 7
                    && slot.managed_artifact_id.get_version_num() == 7
                    && component(&slot.publication_name)
                    && slot.sample_index as usize == index
                    && slot.attempts.len() == self.max_attempts as usize,
                "invalid slot"
            );
            for (index, attempt) in slot.attempts.iter().enumerate() {
                ensure!(
                    attempt.attempt_number as usize == index + 1
                        && text(&attempt.provider_request_identity)
                        && text(&attempt.provider_idempotency_identity)
                        && sorted(&attempt.resource_maximum),
                    "invalid attempt"
                );
                resources(&attempt.resource_maximum)?;
            }
        }
        Ok(())
    }
}
fn sorted<T: Ord>(v: &[T]) -> bool {
    v.windows(2).all(|p| p[0] < p[1])
}
fn text(v: &str) -> bool {
    !v.is_empty() && v.len() <= MAX_PLAN_STRING_BYTES && !v.chars().any(char::is_control)
}
fn component(v: &str) -> bool {
    text(v) && v != "." && v != ".." && !v.contains(['/', '\\'])
}
fn digest(v: &str) -> Result<()> {
    ensure!(
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
        "invalid digest"
    );
    Ok(())
}
fn resources(v: &[ResourceReservationV1]) -> Result<()> {
    ensure!(v.len() <= MAX_PLAN_LIST_ITEMS, "too many resources");
    for r in v {
        ensure!(
            text(&r.resource_kind) && r.units > 0 && text(&r.reservation_identity),
            "invalid resource"
        );
    }
    Ok(())
}
fn hex(v: &[u8]) -> String {
    const H: &[u8; 16] = b"0123456789abcdef";
    let mut o = String::with_capacity(v.len() * 2);
    for b in v {
        o.push(H[(b >> 4) as usize] as char);
        o.push(H[(b & 15) as usize] as char)
    }
    o
}
