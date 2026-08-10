//! Immutable provider-neutral image-generation preflight plans.
//!
//! The planner emits this closed DTO only after resolving every target and
//! output slot. Its canonical bytes are the authorization, queue, spend, and
//! provider-dispatch binding; no dispatcher may reinterpret caller input.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::daemon::principal::ClientPrincipal;
use crate::image_generation_runtime::ImageHealthSnapshot;
use cockpit_config::config::media_budget::MediaReservationPlan;
use cockpit_db::db::external_journal::{
    ExternalJournalDigest, ExternalJournalToken, PrepareExternalOperation, ProviderIdempotency,
};
use cockpit_db::db::image_generation::{
    AdvanceImageGenerationLatePublication, BlockVerifiedImageGenerationLatePublication,
    CreateImageGenerationArtifact, CreateImageGenerationArtifactComponent,
    DispatchingImageGenerationAttempt, ImageGenerationArtifactComponentKind,
    ImageGenerationArtifactComponentState, ImageGenerationArtifactConsumerPurpose,
    ImageGenerationArtifactConsumerRoute, ImageGenerationArtifactState,
    ImageGenerationDispatchCandidate, ImageGenerationLatePublicationEvidenceV1,
    ImageGenerationLatePublicationState, PreparedImageGenerationDispatch,
    ReserveImageGenerationLatePublication, TransitionImageGenerationArtifact,
    TransitionImageGenerationArtifactComponent, image_generation_component_set_binding,
};
use cockpit_db::db::sealed_scope::SealedActionGrantRow;
use cockpit_db::image_spend::{AttemptMaximum, ImageSpendDispatchEvidence, SpendReservation};
use cockpit_db::media_attachments::AcquiredMediaComponentLease;

use crate::media_reservation::{
    MediaExternalHandoffOutcome, ReservationReceipt, ReservationState,
    finish_external_handoff_conn, handoff_external_conn,
};

pub use crate::private_fs::held_directory::{
    HeldArtifactEvidence, HeldDirectoryEffectEvidence, HeldDirectoryEffectOutcome,
    HeldDirectoryRecovery, HeldSealedArtifact, HeldTemporaryArtifact,
};
pub use cockpit_db::image_generation_plan::{
    AttemptPlanV1, CapabilityProvenanceV1, GrantRequirementV1, ImageGenerationPlanV1,
    MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT, MAX_IMAGE_GENERATION_DIMENSION,
    MAX_IMAGE_GENERATION_SLOTS, MAX_IMAGE_GENERATION_TARGETS, OutputDirectoryAuthorityV1,
    OutputSlotPlanV1, ReferenceArtifactV1, RequestedOutputV1, ResolvedOutputV1,
    ResourceReservationV1, SpendReservationPlanV1, TargetDestinationV1, TargetPlanV1,
    TypedParameterV1, VectorSanitizerProvenanceV1,
};

const MAX_AUTHORITY_STRING_BYTES: usize = 1_024;
const MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_IMAGE_MEDIA_PLAN_SNAPSHOT_BYTES: usize = 64 * 1024;

pub fn canonical_media_plan_snapshot(plan: &MediaReservationPlan) -> Result<(Vec<u8>, String)> {
    let bytes = serde_json::to_vec(plan)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_IMAGE_MEDIA_PLAN_SNAPSHOT_BYTES,
        "image generation media plan snapshot is outside its bound"
    );
    let digest = crate::intel::hex_lower(&Sha256::digest(&bytes));
    Ok((bytes, digest))
}

pub fn decode_media_plan_snapshot(
    bytes: &[u8],
    expected_digest: &str,
) -> Result<MediaReservationPlan> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_IMAGE_MEDIA_PLAN_SNAPSHOT_BYTES,
        "image generation media plan snapshot is outside its bound"
    );
    ensure!(
        crate::intel::hex_lower(&Sha256::digest(bytes)) == expected_digest,
        "image generation media plan snapshot digest differs"
    );
    let plan: MediaReservationPlan = serde_json::from_slice(bytes)?;
    ensure!(
        serde_json::to_vec(&plan)? == bytes,
        "image generation media plan snapshot is not canonical"
    );
    Ok(plan)
}

mod image_generation_adapter_sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationHandoffRequest {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub external_operation_id: Uuid,
    pub provider_request_identity: String,
    pub provider_idempotency_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationHandoffResult {
    Accepted { evidence: Vec<u8> },
    DefinitivelyRejected { evidence: Vec<u8> },
    SubmissionUnknown { evidence: Vec<u8> },
}

impl ImageGenerationHandoffResult {
    fn validate(&self) -> Result<()> {
        let evidence = match self {
            Self::Accepted { evidence }
            | Self::DefinitivelyRejected { evidence }
            | Self::SubmissionUnknown { evidence } => evidence,
        };
        ensure!(
            !evidence.is_empty() && evidence.len() <= MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES,
            "image generation handoff evidence is outside its bound"
        );
        Ok(())
    }

    const fn spend_evidence(&self) -> ImageSpendDispatchEvidence {
        match self {
            Self::Accepted { .. } => ImageSpendDispatchEvidence::Accepted,
            Self::DefinitivelyRejected { .. } => ImageSpendDispatchEvidence::DefinitivelyRejected,
            Self::SubmissionUnknown { .. } => ImageSpendDispatchEvidence::SubmissionUnknown,
        }
    }
}

#[async_trait::async_trait]
pub trait ImageGenerationAdapter: image_generation_adapter_sealed::Sealed + Send + Sync {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult;
}

#[cfg(test)]
pub(crate) struct DeterministicImageGenerationAdapter {
    outcomes: std::sync::Mutex<std::collections::VecDeque<ImageGenerationHandoffResult>>,
    requests: std::sync::Mutex<Vec<ImageGenerationHandoffRequest>>,
}

#[cfg(test)]
impl DeterministicImageGenerationAdapter {
    pub(crate) fn new(outcomes: Vec<ImageGenerationHandoffResult>) -> Self {
        Self {
            outcomes: std::sync::Mutex::new(outcomes.into()),
            requests: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn requests(&self) -> Vec<ImageGenerationHandoffRequest> {
        self.requests.lock().expect("fake lock poisoned").clone()
    }
}

#[cfg(test)]
impl image_generation_adapter_sealed::Sealed for DeterministicImageGenerationAdapter {}

#[cfg(test)]
#[async_trait::async_trait]
impl ImageGenerationAdapter for DeterministicImageGenerationAdapter {
    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        self.requests
            .lock()
            .expect("fake lock poisoned")
            .push(request.clone());
        self.outcomes
            .lock()
            .expect("fake lock poisoned")
            .pop_front()
            .expect("deterministic image adapter has no configured outcome")
    }
}

/// Owns the single transaction that advances image, spend, journal, and media
/// reservation state across an external provider handoff.
#[derive(Clone)]
pub struct ImageGenerationDispatcher {
    db: cockpit_db::Db,
}

pub struct DecodedImageGenerationDispatchCandidate {
    pub candidate: ImageGenerationDispatchCandidate,
    pub plan: ImageGenerationPlanV1,
    pub media_plan: MediaReservationPlan,
}

#[derive(Debug, Default)]
pub struct ImageGenerationSchedulerPass {
    pub scanned: u32,
    pub claimed: u32,
    pub dispatched: u32,
    pub skipped: u32,
    #[cfg(test)]
    pub trace: Vec<String>,
}

fn record_scheduler_error(
    pass: &mut ImageGenerationSchedulerPass,
    stage: &str,
    error: &anyhow::Error,
) {
    #[cfg(test)]
    pass.trace.push(format!("{stage}:{error:#}"));
    #[cfg(not(test))]
    let _ = (pass, stage, error);
}

impl ImageGenerationDispatcher {
    pub fn new(db: cockpit_db::Db) -> Self {
        Self { db }
    }

    pub async fn scan_dispatch_candidates(
        &self,
        now_monotonic_ms: u64,
        limit: u32,
    ) -> Result<Vec<DecodedImageGenerationDispatchCandidate>> {
        self.db
            .read(move |conn| {
                cockpit_db::Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    now_monotonic_ms,
                    limit,
                )?
                .into_iter()
                .map(|candidate| {
                    let plan = ImageGenerationPlanV1::from_canonical(
                        &candidate.canonical_plan,
                        &candidate.plan_digest,
                    )?;
                    ensure!(
                        plan.job_id == candidate.job_id,
                        "scheduler candidate plan identity differs"
                    );
                    let media_plan = decode_media_plan_snapshot(
                        &candidate.canonical_media_plan,
                        &candidate.media_plan_digest,
                    )?;
                    Ok(DecodedImageGenerationDispatchCandidate {
                        candidate,
                        plan,
                        media_plan,
                    })
                })
                .collect()
            })
            .await
    }

    async fn prepare_claimed_candidate(
        &self,
        candidate: DecodedImageGenerationDispatchCandidate,
        worker_boot_id: Uuid,
        claim_generation: u64,
        at_unix_ms: i64,
        now_monotonic_ms: u64,
    ) -> Result<(PreparedImageGenerationDispatch, Vec<MediaReservationPlan>)> {
        self.db.transaction(move |conn| {
            let c=&candidate.candidate;
            ensure!(conn.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_scheduler_claims WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND worker_boot_id=?4 AND claim_generation=?5 AND expires_at_unix_ms>CAST(unixepoch('subsec')*1000 AS INTEGER))",params![c.job_id.to_string(),c.slot_id.to_string(),i64::from(c.attempt_number),worker_boot_id.to_string(),i64::try_from(claim_generation)?],|row|row.get::<_,bool>(0))?,"image generation scheduler claim is stale");
            let attempt=candidate.plan.targets.iter().flat_map(|target|target.slots.iter()).find(|slot|slot.slot_id==c.slot_id).and_then(|slot|slot.attempts.iter().find(|attempt|attempt.attempt_number==c.attempt_number)).context("scheduler attempt is absent from immutable plan")?;
            let media_id=candidate.plan.central_resources.first().context("scheduler media reservation is absent")?.reservation_identity.clone();
            let media_version=u64::try_from(conn.query_row::<i64,_,_>("SELECT version FROM media_reservations WHERE reservation_id=?1 AND state='executing_local' AND owner_session_key=?2 AND deadline_monotonic_ms>?3",params![media_id,candidate.plan.owner_session_id.to_string(),i64::try_from(now_monotonic_ms)?],|row|row.get(0))?)?;
            let spend_exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM image_spend_reservations r JOIN image_spend_attempts a USING(reservation_id) WHERE r.reservation_id=?1 AND a.attempt_id=?2 AND r.state='reserved')",params![candidate.plan.spend.reservation_id,attempt.provider_idempotency_identity],|row|row.get(0))?;
            ensure!(spend_exists,"scheduler spend reservation is unavailable");
            let token=ExternalJournalToken::parse(&crate::intel::hex_lower(&Sha256::digest(attempt.provider_idempotency_identity.as_bytes())))?;
            let journal=PrepareExternalOperation{operation_kind:ExternalJournalToken::parse("image_generation")?,owner_session_id:ExternalJournalToken::for_session(candidate.plan.owner_session_id),idempotency_key:token.clone(),payload_digest:ExternalJournalDigest::of(&c.canonical_plan),payload_len:c.canonical_plan.len(),provider_idempotency:Some(ProviderIdempotency{key:token,contract:ExternalJournalToken::parse("image_generation_v1")?})};
            let prepared=cockpit_db::Db::prepare_image_generation_dispatch_conn(conn,&cockpit_db::db::image_generation::PrepareImageGenerationDispatch{job_id:c.job_id,slot_id:c.slot_id,attempt_number:c.attempt_number,expected_job_version:c.job_version,expected_slot_version:c.slot_version,expected_attempt_version:c.attempt_version,spend_reservation_id:&candidate.plan.spend.reservation_id,spend_attempt_id:&attempt.provider_idempotency_identity,media_reservation_id:&media_id,expected_media_reservation_version:media_version,journal:&journal,at_unix_ms,now_monotonic_ms,worker_boot_id,claim_generation})?;
            Ok((prepared,vec![candidate.media_plan]))
        }).await
    }

    pub async fn run_scheduler_pass<A>(
        &self,
        adapter: &A,
        worker_boot_id: Uuid,
        now_monotonic_ms: u64,
        at_unix_ms: i64,
        media_wall_ms: u64,
        limit: u32,
    ) -> Result<ImageGenerationSchedulerPass>
    where
        A: ImageGenerationAdapter,
    {
        self.run_scheduler_pass_with_hook(
            adapter,
            worker_boot_id,
            now_monotonic_ms,
            at_unix_ms,
            media_wall_ms,
            limit,
            |_| Ok(()),
        )
        .await
    }

    async fn run_scheduler_pass_with_hook<A, H>(
        &self,
        adapter: &A,
        worker_boot_id: Uuid,
        now_monotonic_ms: u64,
        at_unix_ms: i64,
        media_wall_ms: u64,
        limit: u32,
        mut before_claim: H,
    ) -> Result<ImageGenerationSchedulerPass>
    where
        A: ImageGenerationAdapter,
        H: FnMut(&DecodedImageGenerationDispatchCandidate) -> Result<()>,
    {
        let candidates = self
            .scan_dispatch_candidates(now_monotonic_ms, limit)
            .await?;
        let mut pass = ImageGenerationSchedulerPass {
            scanned: u32::try_from(candidates.len())?,
            ..Default::default()
        };
        for candidate in candidates {
            before_claim(&candidate)?;
            let claim = cockpit_db::db::image_generation::ClaimImageGenerationDispatch {
                job_id: candidate.candidate.job_id,
                slot_id: candidate.candidate.slot_id,
                attempt_number: candidate.candidate.attempt_number,
                worker_boot_id,
                claim_generation: candidate.candidate.next_claim_generation,
            };
            if let Err(error) = self
                .db
                .transaction(move |conn| {
                    cockpit_db::Db::claim_image_generation_dispatch_conn(conn, &claim)
                })
                .await
            {
                record_scheduler_error(&mut pass, "claim", &error);
                pass.skipped += 1;
                continue;
            }
            pass.claimed += 1;
            let generation = candidate.candidate.next_claim_generation;
            let prepared_result = self
                .prepare_claimed_candidate(
                    candidate,
                    worker_boot_id,
                    generation,
                    at_unix_ms,
                    now_monotonic_ms,
                )
                .await;
            let (prepared, plans) = match prepared_result {
                Ok(value) => value,
                Err(error) => {
                    record_scheduler_error(&mut pass, "prepare", &error);
                    pass.skipped += 1;
                    continue;
                }
            };
            if let Err(error) = self
                .dispatch_once(
                    adapter,
                    prepared,
                    plans,
                    at_unix_ms,
                    now_monotonic_ms,
                    media_wall_ms,
                )
                .await
            {
                record_scheduler_error(&mut pass, "dispatch", &error);
                pass.skipped += 1;
            } else {
                pass.dispatched += 1;
            }
        }
        Ok(pass)
    }

    pub async fn begin_external_handoff(
        &self,
        prepared: PreparedImageGenerationDispatch,
        handoff_plans: Vec<MediaReservationPlan>,
        at_unix_ms: i64,
        now_monotonic_ms: u64,
        media_wall_ms: u64,
    ) -> Result<DispatchingImageGenerationAttempt> {
        self.db
            .transaction(move |conn| {
                let dispatching = cockpit_db::Db::begin_image_generation_handoff_conn(
                    conn,
                    prepared,
                    at_unix_ms,
                    now_monotonic_ms,
                )?;
                let operation_id = dispatching.operation().operation_id.to_string();
                let (reservation_id, dispatching_version) = dispatching.media_reservation();
                let expected_version = dispatching_version
                    .checked_sub(1)
                    .context("image generation media handoff version underflow")?;
                handoff_external_conn(
                    conn,
                    reservation_id,
                    expected_version,
                    &operation_id,
                    &handoff_plans,
                    now_monotonic_ms,
                    media_wall_ms,
                )?;
                Ok(dispatching)
            })
            .await
    }

    pub async fn finish_external_handoff(
        &self,
        dispatching: DispatchingImageGenerationAttempt,
        evidence: ImageSpendDispatchEvidence,
        evidence_bytes: Vec<u8>,
        at_unix_ms: i64,
    ) -> Result<()> {
        let operation_id = dispatching.operation().operation_id.to_string();
        let (reservation_id, reservation_version) = dispatching.media_reservation();
        let reservation_id = reservation_id.to_owned();
        let media_outcome = match evidence {
            ImageSpendDispatchEvidence::Accepted => MediaExternalHandoffOutcome::Accepted,
            ImageSpendDispatchEvidence::DefinitivelyRejected => {
                MediaExternalHandoffOutcome::DefinitivelyRejected
            }
            ImageSpendDispatchEvidence::SubmissionUnknown => {
                MediaExternalHandoffOutcome::SubmissionUnknown
            }
        };
        self.db
            .transaction(move |conn| {
                cockpit_db::Db::finish_image_generation_handoff_conn(
                    conn,
                    dispatching,
                    cockpit_db::db::image_generation::ImageGenerationProviderHandoffEvidence {
                        outcome: evidence,
                        bytes: &evidence_bytes,
                    },
                    at_unix_ms,
                )?;
                finish_external_handoff_conn(
                    conn,
                    &reservation_id,
                    reservation_version,
                    &operation_id,
                    media_outcome,
                )?;
                Ok(())
            })
            .await
    }

    /// Performs exactly one provider call after the durable dispatch token is
    /// committed, then atomically records the closed handoff result.
    pub async fn dispatch_once<A: ImageGenerationAdapter>(
        &self,
        adapter: &A,
        prepared: PreparedImageGenerationDispatch,
        handoff_plans: Vec<MediaReservationPlan>,
        at_unix_ms: i64,
        now_monotonic_ms: u64,
        media_wall_ms: u64,
    ) -> Result<ImageGenerationHandoffResult> {
        let dispatching = self
            .begin_external_handoff(
                prepared,
                handoff_plans,
                at_unix_ms,
                now_monotonic_ms,
                media_wall_ms,
            )
            .await?;
        let (job_id, slot_id, attempt_number, _) = dispatching.identity();
        let (provider_request_identity, provider_idempotency_identity) =
            dispatching.provider_dispatch_identity();
        let request = ImageGenerationHandoffRequest {
            job_id,
            slot_id,
            attempt_number,
            external_operation_id: dispatching.operation().operation_id,
            provider_request_identity: provider_request_identity.to_owned(),
            provider_idempotency_identity: provider_idempotency_identity.to_owned(),
        };
        let result = adapter.handoff(&request).await;
        result.validate()?;
        let evidence_bytes = match &result {
            ImageGenerationHandoffResult::Accepted { evidence }
            | ImageGenerationHandoffResult::DefinitivelyRejected { evidence }
            | ImageGenerationHandoffResult::SubmissionUnknown { evidence } => evidence.clone(),
        };
        self.finish_external_handoff(
            dispatching,
            result.spend_evidence(),
            evidence_bytes,
            at_unix_ms,
        )
        .await?;
        Ok(result)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeTargetAuthorityV1 {
    target_id: String,
    target_config_generation: u64,
    normalized_config_digest: String,
    capability_provenance: CapabilityProvenanceV1,
    destination: TargetDestinationV1,
    supported_formats: BTreeMap<String, String>,
    maximum_width: u32,
    maximum_height: u32,
    allowed_parameters: BTreeMap<String, String>,
    max_attempts: u32,
    required_grant: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationRequestV1 {
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub samples_per_target: u32,
    pub target_ids: Vec<String>,
    pub parameters: BTreeMap<String, TypedParameterV1>,
    pub reference_attachment_ids: Vec<Uuid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationTargetResolutionAuthorityV1 {
    runtime: RuntimeTargetAuthorityV1,
    references: Vec<ReferenceArtifactV1>,
    slot_artifact_ids: Vec<(Uuid, Uuid)>,
    max_attempts: u32,
    attempt_resources: Vec<ResourceReservationV1>,
    attempt_maximum_usd_micros: Vec<Option<u64>>,
    spend_attempt_identities: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationResolutionAuthorityV1 {
    job_id: Uuid,
    owner: ImageGenerationOwnerContextAuthority,
    enqueue_started_monotonic_ms: u64,
    operation_deadline_monotonic_ms: u64,
    required_grants: Vec<GrantRequirementV1>,
    central_resources: Vec<ResourceReservationV1>,
    spend: SpendReservationPlanV1,
    output_authority: VerifiedOutputDirectoryAuthority,
    targets: Vec<ImageGenerationTargetResolutionAuthorityV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationOwnerContextAuthority {
    session_id: Uuid,
    project_id: String,
    principal_digest: String,
    project_identity_digest: String,
    config_generation: u64,
}

impl ImageGenerationOwnerContextAuthority {
    fn revalidate_live_session(&self, conn: &Connection) -> Result<()> {
        let session = cockpit_db::Db::get_session_conn(conn, self.session_id)?
            .context("image generation owner session is unavailable")?;
        ensure!(
            session.ended_at.is_none()
                && session.project_id == self.project_id
                && crate::intel::hex_lower(&Sha256::digest(session.project_root.as_bytes()))
                    == self.project_identity_digest,
            "image generation owner session is unavailable"
        );
        Ok(())
    }

    pub fn from_attached_session(
        conn: &Connection,
        session_id: Uuid,
        principal: &ClientPrincipal,
        config_generation: u64,
    ) -> Result<Self> {
        let unavailable = || anyhow::anyhow!("image generation unavailable");
        ensure!(config_generation > 0, unavailable());
        let session =
            cockpit_db::Db::get_session_conn(conn, session_id)?.ok_or_else(unavailable)?;
        ensure!(session.ended_at.is_none(), unavailable());
        ensure!(
            principal.can_agent_write_project(&session.project_root),
            unavailable()
        );
        let principal_json = serde_json::to_vec(principal)?;
        Ok(Self {
            session_id,
            project_id: session.project_id.clone(),
            principal_digest: crate::intel::hex_lower(&Sha256::digest(principal_json)),
            project_identity_digest: crate::intel::hex_lower(&Sha256::digest(
                session.project_root.as_bytes(),
            )),
            config_generation,
        })
    }

    pub fn authorize_artifact_route(
        &self,
        conn: &Connection,
        request: &AuthorizeImageGenerationArtifactRoute,
    ) -> Result<String> {
        ensure!(
            route_authority_pair_valid(request.purpose, request.route),
            "image artifact route is unavailable"
        );
        let row=conn.query_row("SELECT a.generation,j.version,s.version,p.canonical_plan,p.plan_digest FROM image_generation_artifacts a JOIN image_generation_jobs j ON j.job_id=a.job_id JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_plans p ON p.job_id=a.job_id WHERE a.artifact_id=?1 AND a.job_id=?2 AND a.slot_id=?3 AND a.state='retained' AND s.state='published'",params![request.artifact_id.to_string(),request.job_id.to_string(),request.slot_id.to_string()],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,i64>(1)?,row.get::<_,i64>(2)?,row.get::<_,Vec<u8>>(3)?,row.get::<_,String>(4)?))).optional()?.ok_or_else(||anyhow::anyhow!("image artifact route is unavailable"))?;
        let plan = ImageGenerationPlanV1::from_canonical(&row.3, &row.4)?;
        ensure!(
            plan.owner_session_id == self.session_id
                && plan.owner_principal_digest == self.principal_digest
                && plan.project_identity_digest == self.project_identity_digest
                && plan.config_generation == self.config_generation,
            "image artifact route is unavailable"
        );
        ensure!(
            row.0 == i64::try_from(request.artifact_generation)?
                && row.1 == i64::try_from(request.job_generation)?
                && row.2 == i64::try_from(request.slot_generation)?,
            "image artifact route is unavailable"
        );
        let canonical = serde_json::to_vec(
            &serde_json::json!({"artifactId":request.artifact_id,"artifactGeneration":request.artifact_generation,"configGeneration":self.config_generation,"jobGeneration":request.job_generation,"jobId":request.job_id,"principalDigest":self.principal_digest,"projectId":self.project_id,"projectIdentityDigest":self.project_identity_digest,"purpose":request.purpose.as_str(),"route":request.route.as_str(),"sessionId":self.session_id,"slotGeneration":request.slot_generation,"slotId":request.slot_id}),
        )?;
        let digest = crate::intel::hex_lower(&Sha256::digest(canonical));
        conn.execute("INSERT INTO image_generation_artifact_authorization_facts(authorization_digest,artifact_id,artifact_generation,job_id,job_generation,slot_id,slot_generation,consumer_purpose,consumer_route,principal_digest,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![digest,request.artifact_id.to_string(),i64::try_from(request.artifact_generation)?,request.job_id.to_string(),i64::try_from(request.job_generation)?,request.slot_id.to_string(),i64::try_from(request.slot_generation)?,request.purpose.as_str(),request.route.as_str(),self.principal_digest,request.created_at_unix_ms])?;
        Ok(digest)
    }

    pub fn revoke_artifact_route(
        &self,
        conn: &Connection,
        authorization_digest: &str,
        revoked_at_unix_ms: i64,
    ) -> Result<()> {
        let stored=conn.query_row("SELECT p.canonical_plan,p.plan_digest FROM image_generation_artifact_authorization_facts f JOIN image_generation_artifacts a ON a.artifact_id=f.artifact_id JOIN image_generation_plans p ON p.job_id=a.job_id WHERE f.authorization_digest=?1 AND f.principal_digest=?2 AND f.revoked_at_unix_ms IS NULL",params![authorization_digest,self.principal_digest],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,String>(1)?))).optional()?.ok_or_else(||anyhow::anyhow!("image artifact route is unavailable"))?;
        let plan = ImageGenerationPlanV1::from_canonical(&stored.0, &stored.1)?;
        ensure!(
            plan.owner_session_id == self.session_id
                && plan.owner_principal_digest == self.principal_digest
                && plan.project_identity_digest == self.project_identity_digest
                && plan.config_generation == self.config_generation,
            "image artifact route is unavailable"
        );
        let changed=conn.execute("UPDATE image_generation_artifact_authorization_facts SET revoked_at_unix_ms=?1 WHERE authorization_digest=?2 AND principal_digest=?3 AND revoked_at_unix_ms IS NULL",params![revoked_at_unix_ms,authorization_digest,self.principal_digest])?;
        ensure!(changed == 1, "image artifact route is unavailable");
        Ok(())
    }

    pub fn authorize_late_publication(
        &self,
        conn: &Connection,
        output: &HeldImageGenerationOutputDirectory,
        artifact_id: Uuid,
        destination_name: &str,
        temporary_name: &str,
        created_at_unix_ms: i64,
    ) -> Result<ImageGenerationLatePublicationAuthority> {
        self.revalidate_live_session(conn)?;
        ensure!(
            valid_path_component(destination_name)
                && valid_path_component(temporary_name)
                && temporary_name.starts_with('.'),
            "late publication is unavailable"
        );
        let (job_id, slot_id, artifact_generation, slot_generation, component_set_digest, canonical, plan_digest): (String, String, i64, i64, String, Vec<u8>, String) = conn.query_row(
            "SELECT a.job_id,a.slot_id,a.generation,s.version,a.component_set_digest,p.canonical_plan,p.plan_digest FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_plans p ON p.job_id=a.job_id WHERE a.artifact_id=?1 AND a.state='late_quarantined' AND a.active_lease_count=0 AND s.state='late_quarantined' AND s.result_after_cancel=1 AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id)",
            [artifact_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
        ).optional()?.context("late publication is unavailable")?;
        let plan = ImageGenerationPlanV1::from_canonical(&canonical, &plan_digest)?;
        let output_authority = &output.authority.0;
        ensure!(
            plan.owner_session_id == self.session_id
                && plan.owner_principal_digest == self.principal_digest
                && plan.project_identity_digest == self.project_identity_digest
                && plan.config_generation == self.config_generation
                && plan.output_authority == *output_authority,
            "late publication is unavailable"
        );
        let mut statement = conn.prepare("SELECT component_id,component_kind,relative_storage_key,byte_length_hi,byte_length_lo,sha256,resource_reservation_id,release_operation_id FROM image_generation_artifact_components WHERE artifact_id=?1 AND state='ready' ORDER BY component_id")?;
        let components = statement
            .query_map([artifact_id.to_string()], |row| {
                let high = row.get::<_, i64>(3)?;
                let low = row.get::<_, i64>(4)?;
                Ok(CreateImageGenerationArtifactComponent {
                    component_id: Uuid::parse_str(&row.get::<_, String>(0)?).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            0,
                            rusqlite::types::Type::Text,
                            Box::new(error),
                        )
                    })?,
                    kind: ImageGenerationArtifactComponentKind::parse(&row.get::<_, String>(1)?)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    relative_storage_key: row.get(2)?,
                    byte_length: (u64::try_from(high).map_err(|error| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            rusqlite::types::Type::Integer,
                            Box::new(error),
                        )
                    })? << 32)
                        | u64::try_from(low).map_err(|error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                4,
                                rusqlite::types::Type::Integer,
                                Box::new(error),
                            )
                        })?,
                    sha256: row.get(5)?,
                    resource_reservation_id: row.get(6)?,
                    release_operation_id: Uuid::parse_str(&row.get::<_, String>(7)?).map_err(
                        |error| {
                            rusqlite::Error::FromSqlConversionFailure(
                                7,
                                rusqlite::types::Type::Text,
                                Box::new(error),
                            )
                        },
                    )?,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let (component_set_json, derived_digest) =
            image_generation_component_set_binding(&components)?;
        ensure!(
            derived_digest == component_set_digest,
            "late publication is unavailable"
        );
        let authorization_digest = digest_fields(&[
            &artifact_id.to_string(),
            &artifact_generation.to_string(),
            &job_id,
            &slot_id,
            &slot_generation.to_string(),
            &component_set_digest,
            &output_authority.canonical_destination_digest,
            &output_authority.authority_generation.to_string(),
            destination_name,
            temporary_name,
            &self.principal_digest,
        ]);
        conn.execute("INSERT INTO image_generation_late_publication_authorization_facts(authorization_digest,artifact_id,artifact_generation,job_id,slot_id,slot_generation,component_set_digest,output_authority_digest,output_authority_generation,destination_name,temporary_name,principal_digest,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)", params![authorization_digest,artifact_id.to_string(),artifact_generation,job_id,slot_id,slot_generation,component_set_digest,output_authority.canonical_destination_digest, i64::try_from(output_authority.authority_generation)?,destination_name,temporary_name,self.principal_digest,created_at_unix_ms])?;
        Ok(ImageGenerationLatePublicationAuthority {
            artifact_id,
            artifact_generation: u64::try_from(artifact_generation)?,
            job_id: Uuid::parse_str(&job_id)?,
            slot_id: Uuid::parse_str(&slot_id)?,
            slot_generation: u64::try_from(slot_generation)?,
            component_set_digest,
            component_set_json,
            authorization_digest,
            output_authority_digest: output_authority.canonical_destination_digest.clone(),
            output_authority_generation: output_authority.authority_generation,
            destination_name: destination_name.into(),
            temporary_name: temporary_name.into(),
        })
    }
}

pub struct ImageGenerationLatePublicationAuthority {
    artifact_id: Uuid,
    artifact_generation: u64,
    job_id: Uuid,
    slot_id: Uuid,
    slot_generation: u64,
    component_set_digest: String,
    component_set_json: String,
    authorization_digest: String,
    output_authority_digest: String,
    output_authority_generation: u64,
    destination_name: String,
    temporary_name: String,
}

impl ImageGenerationLatePublicationAuthority {
    pub fn reserve(&self, conn: &Connection, publication_operation_id: Uuid) -> Result<bool> {
        cockpit_db::Db::reserve_image_generation_late_publication_conn(
            conn,
            &ReserveImageGenerationLatePublication {
                publication_operation_id,
                artifact_id: self.artifact_id,
                expected_artifact_generation: self.artifact_generation,
                job_id: self.job_id,
                slot_id: self.slot_id,
                expected_slot_version: self.slot_generation,
                component_set_digest: &self.component_set_digest,
                component_set_json: &self.component_set_json,
                authorization_digest: &self.authorization_digest,
                output_authority_digest: &self.output_authority_digest,
                output_authority_generation: self.output_authority_generation,
                destination_name: &self.destination_name,
                temporary_name: &self.temporary_name,
            },
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeImageGenerationArtifactRoute {
    pub artifact_id: Uuid,
    pub artifact_generation: u64,
    pub job_id: Uuid,
    pub job_generation: u64,
    pub slot_id: Uuid,
    pub slot_generation: u64,
    pub purpose: ImageGenerationArtifactConsumerPurpose,
    pub route: ImageGenerationArtifactConsumerRoute,
    pub created_at_unix_ms: i64,
}

const fn route_authority_pair_valid(
    purpose: ImageGenerationArtifactConsumerPurpose,
    route: ImageGenerationArtifactConsumerRoute,
) -> bool {
    use ImageGenerationArtifactConsumerPurpose as P;
    use ImageGenerationArtifactConsumerRoute as R;
    matches!(
        (purpose, route),
        (P::ServeArtifact, R::ArtifactFull | R::ArtifactRange)
            | (P::ServeThumbnail, R::Thumbnail)
            | (P::ToolInput, R::Tool)
            | (P::ModelInput, R::ModelPayload)
            | (P::InternalVerification, R::Verification)
            | (P::InternalCleanup, R::Cleanup)
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageArtifactSecurityRecoveryDisposition {
    RetainBlocked,
    ResumeVerifiedCleanup,
    RemoveVerifiedExternalCopy,
    CompleteVerifiedLatePublication,
}

#[derive(Debug)]
pub struct DaemonLocalOwnerRecoveryAuthority(());
impl DaemonLocalOwnerRecoveryAuthority {
    pub(crate) fn from_local_direct(principal: &ClientPrincipal) -> Result<Self> {
        ensure!(
            principal.is_owner(),
            "image artifact recovery is unavailable"
        );
        Ok(Self(()))
    }
}
impl ImageArtifactSecurityRecoveryDisposition {
    fn as_str(self) -> &'static str {
        match self {
            Self::RetainBlocked => "retain_blocked",
            Self::ResumeVerifiedCleanup => "resume_verified_cleanup",
            Self::RemoveVerifiedExternalCopy => "remove_verified_external_copy",
            Self::CompleteVerifiedLatePublication => "complete_verified_late_publication",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordImageArtifactSecurityRecovery {
    pub operation_id: Uuid,
    pub artifact_id: Uuid,
    pub artifact_generation: u64,
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub slot_generation: u64,
    pub component_set_digest: String,
    pub components: Vec<RecoverImageArtifactComponentIdentity>,
    pub publication_operation_id: Option<Uuid>,
    pub publication_lease_version: Option<u64>,
    pub output_identity_digest: Option<String>,
    pub disposition: ImageArtifactSecurityRecoveryDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RecoverImageArtifactComponentIdentity {
    pub component_id: Uuid,
    pub kind: ImageGenerationArtifactComponentKind,
    pub generation: u64,
    pub stable_identity_digest: String,
    pub security_digest: String,
    pub sha256: String,
}

#[derive(Debug)]
pub struct RecordedImageArtifactSecurityRecovery {
    operation_id: Uuid,
    disposition: ImageArtifactSecurityRecoveryDisposition,
    artifact_id: Uuid,
    artifact_generation: u64,
    component_set_digest: String,
    component_identity_digest: String,
    publication_operation_id: Option<Uuid>,
    publication_lease_version: Option<u64>,
    output_identity_digest: Option<String>,
}

#[derive(Debug)]
pub enum VerifiedExternalCopyRemovalOutcome {
    RemovedDurably,
    RecoveryRequired(HeldDirectoryRecovery),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageArtifactSecurityRecoveryReplay {
    Recorded,
    Applied { outcome_digest: String },
    Denied { outcome_digest: String },
    ProofFailed { outcome_digest: String },
    Stale { outcome_digest: String },
}

fn component_recovery_identity_digest(
    components: &[RecoverImageArtifactComponentIdentity],
) -> Result<String> {
    let canonical = components
        .iter()
        .map(|component| {
            serde_json::json!({
                "componentId": component.component_id,
                "generation": component.generation,
                "kind": component.kind.as_str(),
                "stableIdentityDigest": component.stable_identity_digest,
                "securityDigest": component.security_digest,
                "sha256": component.sha256,
            })
        })
        .collect::<Vec<_>>();
    Ok(crate::intel::hex_lower(&Sha256::digest(
        serde_json::to_vec(&canonical)?,
    )))
}

fn security_recovery_request_digest(input: &RecordImageArtifactSecurityRecovery) -> Result<String> {
    let components = input
        .components
        .iter()
        .map(|component| {
            serde_json::json!({
                "componentId": component.component_id,
                "generation": component.generation,
                "kind": component.kind.as_str(),
                "stableIdentityDigest": component.stable_identity_digest,
                "securityDigest": component.security_digest,
                "sha256": component.sha256,
            })
        })
        .collect::<Vec<_>>();
    let canonical = serde_json::json!({
        "artifactGeneration": input.artifact_generation,
        "artifactId": input.artifact_id,
        "componentSetDigest": input.component_set_digest,
        "components": components,
        "disposition": input.disposition.as_str(),
        "jobId": input.job_id,
        "operationId": input.operation_id,
        "outputIdentityDigest": input.output_identity_digest,
        "publicationLeaseVersion": input.publication_lease_version,
        "publicationOperationId": input.publication_operation_id,
        "slotGeneration": input.slot_generation,
        "slotId": input.slot_id,
    });
    Ok(crate::intel::hex_lower(&Sha256::digest(
        serde_json::to_vec(&canonical)?,
    )))
}

impl ImageGenerationOwnerContextAuthority {
    pub fn replay_image_artifact_security_recovery_outcome(
        &self,
        conn: &Connection,
        operation_id: Uuid,
    ) -> Result<ImageArtifactSecurityRecoveryReplay> {
        let (state, outcome) = conn
            .query_row(
                "SELECT state,outcome_digest FROM image_generation_artifact_security_recovery_audits WHERE recovery_operation_id=?1 AND principal_digest=?2",
                params![operation_id.to_string(), self.principal_digest],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
            )
            .optional()?
            .context("security recovery audit is unavailable")?;
        Ok(match state.as_str() {
            "recorded" => {
                ensure!(outcome.is_none(), "recorded recovery has terminal evidence");
                ImageArtifactSecurityRecoveryReplay::Recorded
            }
            "applied" => ImageArtifactSecurityRecoveryReplay::Applied {
                outcome_digest: outcome.context("applied recovery evidence is absent")?,
            },
            "denied" => ImageArtifactSecurityRecoveryReplay::Denied {
                outcome_digest: outcome.context("denied recovery evidence is absent")?,
            },
            "proof_failed" => ImageArtifactSecurityRecoveryReplay::ProofFailed {
                outcome_digest: outcome.context("failed recovery evidence is absent")?,
            },
            "stale" => ImageArtifactSecurityRecoveryReplay::Stale {
                outcome_digest: outcome.context("stale recovery evidence is absent")?,
            },
            _ => anyhow::bail!("security recovery outcome is invalid"),
        })
    }

    pub fn record_image_artifact_security_recovery(
        &self,
        conn: &Connection,
        principal: &ClientPrincipal,
        input: &RecordImageArtifactSecurityRecovery,
    ) -> Result<RecordedImageArtifactSecurityRecovery> {
        ensure!(
            conn.is_autocommit(),
            "security recovery must begin outside a transaction"
        );
        let request_digest = security_recovery_request_digest(input)?;
        let presented_principal_digest =
            crate::intel::hex_lower(&Sha256::digest(serde_json::to_vec(principal)?));
        let now: i64 = conn.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        let inserted = conn.execute(
            "INSERT OR IGNORE INTO image_generation_artifact_security_recovery_attempts(recovery_operation_id,principal_digest,request_digest,state,created_at_unix_ms) VALUES(?1,?2,?3,'received',?4)",
            params![input.operation_id.to_string(), presented_principal_digest, request_digest, now],
        )?;
        if inserted == 0 {
            let replay = conn
                .query_row(
                    "SELECT request_digest,state FROM image_generation_artifact_security_recovery_attempts WHERE recovery_operation_id=?1 AND principal_digest=?2",
                    params![input.operation_id.to_string(), presented_principal_digest],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                )
                .optional()?
                .context("security recovery attempt is unavailable")?;
            ensure!(
                replay.0 == request_digest && replay.1 == "validated",
                "security recovery replay differs"
            );
            return self.replay_recorded_security_recovery(conn, input);
        }
        if let Err(error) = DaemonLocalOwnerRecoveryAuthority::from_local_direct(principal) {
            let digest = crate::intel::hex_lower(&Sha256::digest(error.to_string()));
            conn.execute("UPDATE image_generation_artifact_security_recovery_attempts SET state='denied',outcome_digest=?1,decided_at_unix_ms=?2 WHERE recovery_operation_id=?3 AND principal_digest=?4 AND state='received'",params![digest,now,input.operation_id.to_string(),presented_principal_digest])?;
            return Err(error);
        }
        match self.record_image_artifact_security_recovery_inner(conn, input) {
            Ok(recorded) => {
                self.close_security_recovery_attempt(
                    conn,
                    input.operation_id,
                    "validated",
                    recorded.component_identity_digest.as_bytes(),
                )?;
                Ok(recorded)
            }
            Err(error) => {
                let _ = self.close_security_recovery_attempt(
                    conn,
                    input.operation_id,
                    "denied",
                    error.to_string().as_bytes(),
                );
                Err(error)
            }
        }
    }

    fn record_image_artifact_security_recovery_inner(
        &self,
        conn: &Connection,
        input: &RecordImageArtifactSecurityRecovery,
    ) -> Result<RecordedImageArtifactSecurityRecovery> {
        let owner_digest = crate::intel::hex_lower(&Sha256::digest(serde_json::to_vec(
            &ClientPrincipal::Owner,
        )?));
        ensure!(
            self.principal_digest == owner_digest,
            "image artifact recovery is unavailable"
        );
        let row=conn.query_row("SELECT a.state,a.component_set_digest,p.canonical_plan,p.plan_digest,COALESCE(lp.state,''),lp.version,lp.output_evidence_json,a.expected_component_count FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_plans p ON p.job_id=a.job_id LEFT JOIN image_generation_late_publication_leases lp ON lp.publication_operation_id=?1 WHERE a.artifact_id=?2 AND a.generation=?3 AND a.job_id=?4 AND a.slot_id=?5 AND s.version=?6",params![input.publication_operation_id.map(|id|id.to_string()),input.artifact_id.to_string(),i64::try_from(input.artifact_generation)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.slot_generation)?],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,Option<i64>>(5)?,row.get::<_,Option<String>>(6)?,row.get::<_,i64>(7)?))).optional()?.ok_or_else(||anyhow::anyhow!("image artifact recovery is unavailable"))?;
        let plan = ImageGenerationPlanV1::from_canonical(&row.2, &row.3)?;
        ensure!(
            plan.owner_session_id == self.session_id
                && plan.owner_principal_digest == self.principal_digest
                && plan.project_identity_digest == self.project_identity_digest
                && plan.config_generation == self.config_generation
                && row.1 == input.component_set_digest,
            "image artifact recovery is unavailable"
        );
        ensure!(
            row.0 == "security_blocked" || row.4 == "security_blocked",
            "image artifact recovery is unavailable"
        );
        let mut components = input.components.clone();
        components.sort();
        ensure!(
            components.len() == usize::try_from(row.7)?,
            "security recovery component set is incomplete"
        );
        ensure!(
            components == input.components,
            "security recovery components are not canonical"
        );
        ensure!(
            components
                .windows(2)
                .all(|pair| pair[0].component_id != pair[1].component_id)
                && components.iter().all(|component| {
                    component.generation > 0
                        && component.stable_identity_digest.len() == 64
                        && component.security_digest.len() == 64
                        && component.sha256.len() == 64
                        && component
                            .stable_identity_digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        && component
                            .security_digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                        && component
                            .sha256
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                }),
            "security recovery component identity is invalid"
        );
        let component_identity_digest = component_recovery_identity_digest(&components)?;
        ensure!(
            matches!(
                (
                    input.disposition,
                    input.publication_operation_id,
                    input.publication_lease_version,
                    input.output_identity_digest.as_deref()
                ),
                (
                    ImageArtifactSecurityRecoveryDisposition::CompleteVerifiedLatePublication,
                    Some(_),
                    Some(_),
                    Some(_)
                ) | (
                    ImageArtifactSecurityRecoveryDisposition::RemoveVerifiedExternalCopy,
                    Some(_),
                    Some(_),
                    Some(_)
                ) | (
                    ImageArtifactSecurityRecoveryDisposition::RetainBlocked
                        | ImageArtifactSecurityRecoveryDisposition::ResumeVerifiedCleanup,
                    None,
                    None,
                    None
                )
            ),
            "image artifact recovery disposition is unavailable"
        );
        if let Some(expected_identity) = input.output_identity_digest.as_deref() {
            ensure!(
                row.5.map(u64::try_from).transpose()? == input.publication_lease_version,
                "security recovery publication version differs"
            );
            let evidence = cockpit_db::db::image_generation::ImageGenerationLatePublicationEvidenceV1::from_canonical_json(
                row.6.as_deref().context("security recovery output evidence is absent")?,
            )?;
            ensure!(
                matches!(evidence, cockpit_db::db::image_generation::ImageGenerationLatePublicationEvidenceV1::OutputDurable { identity_digest, .. } if identity_digest == expected_identity),
                "security recovery output identity differs"
            );
        }
        let now: i64 = conn.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        let tx = conn.unchecked_transaction()?;
        tx.execute("INSERT INTO image_generation_artifact_security_recovery_audits(recovery_operation_id,artifact_id,artifact_generation,job_id,slot_id,slot_generation,principal_digest,component_set_digest,component_identity_digest,publication_operation_id,publication_lease_version,output_identity_digest,disposition,state,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,'recorded',?14)",params![input.operation_id.to_string(),input.artifact_id.to_string(),i64::try_from(input.artifact_generation)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.slot_generation)?,self.principal_digest,input.component_set_digest,component_identity_digest,input.publication_operation_id.map(|id|id.to_string()),input.publication_lease_version.map(i64::try_from).transpose()?,input.output_identity_digest.as_deref(),input.disposition.as_str(),now])?;
        for component in &components {
            tx.execute("INSERT INTO image_generation_artifact_security_recovery_components(recovery_operation_id,artifact_id,component_id,component_kind,component_generation,stable_identity_digest,security_digest,sha256) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![input.operation_id.to_string(),input.artifact_id.to_string(),component.component_id.to_string(),component.kind.as_str(),i64::try_from(component.generation)?,component.stable_identity_digest,component.security_digest,component.sha256])?;
        }
        tx.commit()?;
        Ok(RecordedImageArtifactSecurityRecovery {
            operation_id: input.operation_id,
            disposition: input.disposition,
            artifact_id: input.artifact_id,
            artifact_generation: input.artifact_generation,
            component_set_digest: input.component_set_digest.clone(),
            component_identity_digest,
            publication_operation_id: input.publication_operation_id,
            publication_lease_version: input.publication_lease_version,
            output_identity_digest: input.output_identity_digest.clone(),
        })
    }

    fn replay_recorded_security_recovery(
        &self,
        conn: &Connection,
        input: &RecordImageArtifactSecurityRecovery,
    ) -> Result<RecordedImageArtifactSecurityRecovery> {
        let row = conn
            .query_row(
                "SELECT component_set_digest,component_identity_digest,publication_operation_id,publication_lease_version,output_identity_digest,disposition FROM image_generation_artifact_security_recovery_audits WHERE recovery_operation_id=?1 AND artifact_id=?2 AND artifact_generation=?3 AND job_id=?4 AND slot_id=?5 AND slot_generation=?6 AND principal_digest=?7",
                params![input.operation_id.to_string(), input.artifact_id.to_string(), i64::try_from(input.artifact_generation)?, input.job_id.to_string(), input.slot_id.to_string(), i64::try_from(input.slot_generation)?, self.principal_digest],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, Option<i64>>(3)?, row.get::<_, Option<String>>(4)?, row.get::<_, String>(5)?)),
            )
            .optional()?
            .context("security recovery record is unavailable")?;
        ensure!(
            row.0 == input.component_set_digest
                && row.2 == input.publication_operation_id.map(|id| id.to_string())
                && row.3.map(u64::try_from).transpose()? == input.publication_lease_version
                && row.4 == input.output_identity_digest
                && row.5 == input.disposition.as_str(),
            "security recovery replay differs"
        );
        Ok(RecordedImageArtifactSecurityRecovery {
            operation_id: input.operation_id,
            disposition: input.disposition,
            artifact_id: input.artifact_id,
            artifact_generation: input.artifact_generation,
            component_set_digest: row.0,
            component_identity_digest: row.1,
            publication_operation_id: input.publication_operation_id,
            publication_lease_version: input.publication_lease_version,
            output_identity_digest: row.4,
        })
    }

    fn close_security_recovery_attempt(
        &self,
        conn: &Connection,
        operation_id: Uuid,
        state: &str,
        evidence: &[u8],
    ) -> Result<()> {
        let now: i64 = conn.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        let digest = crate::intel::hex_lower(&Sha256::digest(evidence));
        ensure!(
            conn.execute(
                "UPDATE image_generation_artifact_security_recovery_attempts SET state=?1,outcome_digest=?2,decided_at_unix_ms=?3 WHERE recovery_operation_id=?4 AND principal_digest=?5 AND state='received'",
                params![state, digest, now, operation_id.to_string(), self.principal_digest],
            )? == 1,
            "security recovery attempt is unavailable"
        );
        Ok(())
    }

    pub fn retain_image_artifact_security_block(
        &self,
        conn: &Connection,
        recorded: RecordedImageArtifactSecurityRecovery,
    ) -> Result<()> {
        self.revalidate_live_session(conn)?;
        ensure!(
            recorded.disposition == ImageArtifactSecurityRecoveryDisposition::RetainBlocked,
            "security recovery disposition differs"
        );
        let now: i64 = conn.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        let outcome = crate::intel::hex_lower(&Sha256::digest(format!(
            "retain:{}:{}",
            recorded.operation_id, self.principal_digest
        )));
        ensure!(conn.execute("UPDATE image_generation_artifact_security_recovery_audits SET state='applied',outcome_digest=?1,decided_at_unix_ms=?2 WHERE recovery_operation_id=?3 AND principal_digest=?4 AND state='recorded'",params![outcome,now,recorded.operation_id.to_string(),self.principal_digest])?==1,"security recovery audit is unavailable");
        Ok(())
    }

    pub fn resume_verified_image_artifact_cleanup(
        &self,
        conn: &Connection,
        recorded: RecordedImageArtifactSecurityRecovery,
        cleanup_operation_id: Uuid,
        components: &[VerifiedManagedComponentForRecovery],
    ) -> Result<()> {
        let operation_id = recorded.operation_id;
        let result = self.resume_verified_image_artifact_cleanup_inner(
            conn,
            &recorded,
            cleanup_operation_id,
            components,
        );
        if let Err(error) = result {
            let _ = self.close_security_recovery_audit(
                conn,
                operation_id,
                "proof_failed",
                format!("proof_failed:{operation_id}").as_bytes(),
            );
            return Err(error);
        }
        Ok(())
    }

    fn resume_verified_image_artifact_cleanup_inner(
        &self,
        conn: &Connection,
        recorded: &RecordedImageArtifactSecurityRecovery,
        cleanup_operation_id: Uuid,
        components: &[VerifiedManagedComponentForRecovery],
    ) -> Result<()> {
        self.revalidate_live_session(conn)?;
        ensure!(
            recorded.disposition == ImageArtifactSecurityRecoveryDisposition::ResumeVerifiedCleanup,
            "security recovery disposition differs"
        );
        let tx = conn.unchecked_transaction()?;
        let expected:i64=tx.query_row("SELECT expected_component_count FROM image_generation_artifacts WHERE artifact_id=?1 AND generation=?2 AND state='security_blocked' AND component_set_digest=?3 AND active_lease_count=0 AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_references r WHERE r.artifact_id=image_generation_artifacts.artifact_id AND r.released_at_unix_ms IS NULL) AND NOT EXISTS(SELECT 1 FROM image_generation_late_publication_leases p WHERE p.artifact_id=image_generation_artifacts.artifact_id AND p.state IN ('reserved','copy_authorized','copy_committed','security_blocked','delete_authorized'))",params![recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?,recorded.component_set_digest],|row|row.get(0))?;
        ensure!(
            usize::try_from(expected)? == components.len(),
            "security recovery component set differs"
        );
        let mut identities = Vec::with_capacity(components.len());
        for component in components {
            let (kind,generation,stable_identity,hi,lo,checksum,state):(String,i64,String,i64,i64,String,String)=tx.query_row("SELECT component_kind,generation,stable_identity_json,byte_length_hi,byte_length_lo,sha256,state FROM image_generation_artifact_components WHERE artifact_id=?1 AND component_id=?2",params![recorded.artifact_id.to_string(),component.component_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?,row.get(6)?)))?;
            let length = (u64::try_from(hi)? << 32) | u64::try_from(lo)?;
            let held = component.held.evidence();
            ensure!(
                matches!(state.as_str(), "ready" | "security_blocked")
                    && component.kind.as_str() == kind
                    && component.generation == u64::try_from(generation)?
                    && held.byte_length() == length
                    && held.sha256() == checksum
                    && held_artifact_evidence_json(held)? == stable_identity,
                "security recovery held component differs"
            );
            ensure!(tx.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_artifact_security_recovery_components WHERE recovery_operation_id=?1 AND artifact_id=?2 AND component_id=?3 AND component_kind=?4 AND component_generation=?5 AND stable_identity_digest=?6 AND security_digest=?7 AND sha256=?8)",params![recorded.operation_id.to_string(),recorded.artifact_id.to_string(),component.component_id.to_string(),component.kind.as_str(),i64::try_from(component.generation)?,held.identity_digest(),held.security_digest(),held.sha256()],|row|row.get::<_,bool>(0))?,"security recovery normalized component authority differs");
            identities.push(RecoverImageArtifactComponentIdentity {
                component_id: component.component_id,
                kind: component.kind,
                generation: component.generation,
                stable_identity_digest: held.identity_digest().to_owned(),
                security_digest: held.security_digest().to_owned(),
                sha256: held.sha256().to_owned(),
            });
        }
        identities.sort();
        ensure!(
            component_recovery_identity_digest(&identities)? == recorded.component_identity_digest,
            "security recovery component identity set differs"
        );
        let now: i64 = tx.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        let next_generation = recorded
            .artifact_generation
            .checked_add(1)
            .context("security recovery generation overflow")?;
        tx.execute("INSERT INTO image_generation_artifact_cleanup_intents(cleanup_operation_id,artifact_id,expected_artifact_generation,reason,state,version,created_at_unix_ms) VALUES(?1,?2,?3,'owner_recovery','pending',1,?4)",params![cleanup_operation_id.to_string(),recorded.artifact_id.to_string(),i64::try_from(next_generation)?,now])?;
        ensure!(tx.execute("UPDATE image_generation_artifacts SET state='cleanup_pending',generation=generation+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND state='security_blocked' AND generation=?3 AND active_lease_count=0",params![now,recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?])?==1,"security recovery artifact compare-and-set lost");
        for component in components {
            ensure!(tx.execute("UPDATE image_generation_artifact_components SET state='cleanup_pending',generation=generation+1 WHERE artifact_id=?1 AND component_id=?2 AND state IN ('ready','security_blocked')",params![recorded.artifact_id.to_string(),component.component_id.to_string()])?==1,"security recovery component compare-and-set lost");
        }
        let outcome = crate::intel::hex_lower(&Sha256::digest(format!(
            "cleanup:{}:{}",
            recorded.operation_id, recorded.component_set_digest
        )));
        ensure!(tx.execute("UPDATE image_generation_artifact_security_recovery_audits SET state='applied',outcome_digest=?1,decided_at_unix_ms=?2 WHERE recovery_operation_id=?3 AND principal_digest=?4 AND state='recorded'",params![outcome,now,recorded.operation_id.to_string(),self.principal_digest])?==1,"security recovery audit compare-and-set lost");
        tx.commit()?;
        Ok(())
    }

    pub fn complete_verified_late_publication(
        &self,
        conn: &Connection,
        recorded: RecordedImageArtifactSecurityRecovery,
        output: &HeldImageGenerationOutputDirectory,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<()> {
        let operation_id = recorded.operation_id;
        let result =
            self.complete_verified_late_publication_inner(conn, &recorded, output, recovery);
        if let Err(error) = result {
            let _ = self.close_security_recovery_audit(
                conn,
                operation_id,
                "proof_failed",
                format!("publication_proof_failed:{operation_id}").as_bytes(),
            );
            return Err(error);
        }
        Ok(())
    }

    pub fn remove_verified_external_copy(
        &self,
        conn: &Connection,
        recorded: RecordedImageArtifactSecurityRecovery,
        output: &HeldImageGenerationOutputDirectory,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<VerifiedExternalCopyRemovalOutcome> {
        self.revalidate_live_session(conn)?;
        ensure!(
            recorded.disposition
                == ImageArtifactSecurityRecoveryDisposition::RemoveVerifiedExternalCopy,
            "security recovery disposition differs"
        );
        let operation = recorded
            .publication_operation_id
            .context("security recovery publication identity is absent")?;
        let version = recorded
            .publication_lease_version
            .context("security recovery publication version is absent")?;
        ensure!(
            recovery.artifact().identity_digest()
                == recorded
                    .output_identity_digest
                    .as_deref()
                    .context("security recovery output identity is absent")?,
            "security recovery output identity differs"
        );
        let authorized_version = version
            .checked_add(1)
            .context("external publication recovery version overflow")?;
        let pre_effect = conn.unchecked_transaction()?;
        let changed = pre_effect.execute("UPDATE image_generation_late_publication_leases SET state='delete_authorized',version=version+1,decided_at_unix_ms=NULL WHERE publication_operation_id=?1 AND artifact_id=?2 AND artifact_generation=?3 AND state='security_blocked' AND version=?4 AND output_evidence_json IS NOT NULL AND recovery_evidence_json IS NOT NULL AND decided_at_unix_ms IS NOT NULL AND EXISTS(SELECT 1 FROM image_generation_artifact_security_recovery_audits r WHERE r.recovery_operation_id=?5 AND r.publication_operation_id=image_generation_late_publication_leases.publication_operation_id AND r.publication_lease_version=image_generation_late_publication_leases.version AND r.output_identity_digest=?6 AND r.disposition='remove_verified_external_copy' AND r.state='recorded')",params![operation.to_string(),recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?,i64::try_from(version)?,recorded.operation_id.to_string(),recorded.output_identity_digest])?;
        if changed == 0 {
            ensure!(pre_effect.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_late_publication_leases WHERE publication_operation_id=?1 AND artifact_id=?2 AND artifact_generation=?3 AND state='delete_authorized' AND version=?4)",params![operation.to_string(),recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?,i64::try_from(authorized_version)?],|row|row.get::<_,bool>(0))?,"external publication deletion authority is unavailable");
        }
        pre_effect.commit()?;
        let deleted = match output.delete_recovered_publication(recovery)? {
            HeldDirectoryEffectOutcome::AppliedDurable(deleted) => deleted,
            HeldDirectoryEffectOutcome::AppliedUnknown(recovery)
            | HeldDirectoryEffectOutcome::SecurityAmbiguous(recovery) => {
                return Ok(VerifiedExternalCopyRemovalOutcome::RecoveryRequired(
                    recovery,
                ));
            }
            HeldDirectoryEffectOutcome::ProvenNotApplied(_) => {
                anyhow::bail!("external publication deletion was not applied")
            }
        };
        let authority = &output.authority.0;
        let evidence = ImageGenerationLatePublicationEvidenceV1::TemporaryDeleted {
            schema_version: 1,
            identity_digest: deleted.artifact().identity_digest().to_owned(),
            deletion_digest: crate::intel::hex_lower(&Sha256::digest(format!(
                "deleted:{}:{}",
                operation,
                deleted.artifact().identity_digest()
            ))),
            parent_sync_digest: authority.parent_identity_digest.clone(),
        }
        .canonical_json()?;
        let tx = conn.unchecked_transaction()?;
        let now: i64 = tx.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        ensure!(tx.execute("UPDATE image_generation_late_publication_leases SET state='aborted',version=version+1,recovery_evidence_json=?1,decided_at_unix_ms=?2 WHERE publication_operation_id=?3 AND artifact_id=?4 AND artifact_generation=?5 AND state='delete_authorized' AND version=?6 AND output_evidence_json IS NOT NULL",params![evidence,now,operation.to_string(),recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?,i64::try_from(authorized_version)?])?==1,"external publication recovery compare-and-set lost");
        let outcome =
            crate::intel::hex_lower(&Sha256::digest(format!("removed:{operation}:{evidence}")));
        ensure!(tx.execute("UPDATE image_generation_artifact_security_recovery_audits SET state='applied',outcome_digest=?1,decided_at_unix_ms=?2 WHERE recovery_operation_id=?3 AND principal_digest=?4 AND disposition='remove_verified_external_copy' AND state='recorded'",params![outcome,now,recorded.operation_id.to_string(),self.principal_digest])?==1,"security recovery audit compare-and-set lost");
        tx.commit()?;
        Ok(VerifiedExternalCopyRemovalOutcome::RemovedDurably)
    }

    pub fn reconcile_verified_external_copy_removal(
        &self,
        conn: &Connection,
        recorded: RecordedImageArtifactSecurityRecovery,
        output: &HeldImageGenerationOutputDirectory,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<VerifiedExternalCopyRemovalOutcome> {
        self.remove_verified_external_copy(conn, recorded, output, recovery)
    }

    fn complete_verified_late_publication_inner(
        &self,
        conn: &Connection,
        recorded: &RecordedImageArtifactSecurityRecovery,
        output: &HeldImageGenerationOutputDirectory,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<()> {
        self.revalidate_live_session(conn)?;
        ensure!(
            recorded.disposition
                == ImageArtifactSecurityRecoveryDisposition::CompleteVerifiedLatePublication,
            "security recovery disposition differs"
        );
        let publication_operation_id = recorded
            .publication_operation_id
            .context("security recovery publication identity is absent")?;
        let expected_lease_version = recorded
            .publication_lease_version
            .context("security recovery publication version is absent")?;
        let expected_output_identity = recorded
            .output_identity_digest
            .as_deref()
            .context("security recovery output identity is absent")?;
        let effect = output.reconcile_publication(recovery)?;
        let HeldDirectoryEffectOutcome::AppliedDurable(effect) = effect else {
            anyhow::bail!("late publication held outcome is not durably applied")
        };
        let destination = effect
            .destination_name()
            .context("late publication destination evidence is absent")?;
        let authority = &output.authority.0;
        let evidence=cockpit_db::db::image_generation::ImageGenerationLatePublicationEvidenceV1::OutputDurable{schema_version:1,identity_digest:effect.artifact().identity_digest().to_owned(),security_digest:effect.artifact().security_digest().to_owned(),byte_length:effect.artifact().byte_length().to_string(),sha256:effect.artifact().sha256().to_owned(),parent_sync_digest:authority.parent_identity_digest.clone()}.canonical_json()?;
        let tx = conn.unchecked_transaction()?;
        let row=tx.query_row("SELECT p.version,p.destination_name,p.output_authority_digest,p.output_authority_generation,p.expected_slot_version,a.state,p.output_evidence_json,g.canonical_plan,g.plan_digest FROM image_generation_late_publication_leases p JOIN image_generation_artifacts a ON a.artifact_id=p.artifact_id JOIN image_generation_plans g ON g.job_id=a.job_id JOIN image_generation_late_publication_authorization_facts f ON f.authorization_digest=p.authorization_digest WHERE p.publication_operation_id=?1 AND p.artifact_id=?2 AND p.artifact_generation=?3 AND p.state='security_blocked' AND f.revoked_at_unix_ms IS NULL AND f.principal_digest=?4 AND f.artifact_generation=p.artifact_generation AND f.slot_generation=p.expected_slot_version AND f.output_authority_digest=p.output_authority_digest AND f.output_authority_generation=p.output_authority_generation AND f.destination_name=p.destination_name",params![publication_operation_id.to_string(),recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?,self.principal_digest],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,i64>(3)?,row.get::<_,i64>(4)?,row.get::<_,String>(5)?,row.get::<_,String>(6)?,row.get::<_,Vec<u8>>(7)?,row.get::<_,String>(8)?))).optional()?.context("security-blocked publication is unavailable")?;
        let current_plan = ImageGenerationPlanV1::from_canonical(&row.7, &row.8)?;
        let prior = cockpit_db::db::image_generation::ImageGenerationLatePublicationEvidenceV1::from_canonical_json(&row.6)?;
        let prior_identity = match prior {
            cockpit_db::db::image_generation::ImageGenerationLatePublicationEvidenceV1::OutputDurable { identity_digest, .. } => identity_digest,
            _ => anyhow::bail!("security-blocked publication has no durable output identity"),
        };
        ensure!(
            u64::try_from(row.0)? == expected_lease_version
                && prior_identity == expected_output_identity
                && effect.artifact().identity_digest() == expected_output_identity
                && row.1 == destination
                && row.2 == authority.canonical_destination_digest
                && row.3 == i64::try_from(authority.authority_generation)?
                && current_plan.owner_session_id == self.session_id
                && current_plan.owner_principal_digest == self.principal_digest
                && current_plan.project_identity_digest == self.project_identity_digest
                && current_plan.config_generation == self.config_generation
                && matches!(row.5.as_str(), "late_quarantined" | "security_blocked"),
            "late publication authority differs"
        );
        let now: i64 = tx.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        tx.execute("INSERT INTO image_generation_user_published_outputs(publication_operation_id,artifact_id,artifact_generation,output_authority_digest,output_authority_generation,destination_name,output_evidence_json,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![publication_operation_id.to_string(),recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?,row.2,row.3,row.1,evidence,now])?;
        ensure!(tx.execute("UPDATE image_generation_late_publication_leases SET state='published',version=version+1,output_evidence_json=?1,decided_at_unix_ms=?2 WHERE publication_operation_id=?3 AND state='security_blocked' AND version=?4",params![evidence,now,publication_operation_id.to_string(),row.0])?==1,"security publication lease compare-and-set lost");
        let outcome = crate::intel::hex_lower(&Sha256::digest(format!(
            "published:{publication_operation_id}:{evidence}"
        )));
        ensure!(tx.execute("UPDATE image_generation_artifact_security_recovery_audits SET state='applied',outcome_digest=?1,decided_at_unix_ms=?2 WHERE recovery_operation_id=?3 AND principal_digest=?4 AND state='recorded'",params![outcome,now,recorded.operation_id.to_string(),self.principal_digest])?==1,"security recovery audit compare-and-set lost");
        ensure!(tx.execute("UPDATE image_generation_artifacts SET state='retained',generation=generation+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND state IN ('late_quarantined','security_blocked') AND generation=?3",params![now,recorded.artifact_id.to_string(),i64::try_from(recorded.artifact_generation)?])?==1,"security publication artifact compare-and-set lost");
        ensure!(tx.execute("UPDATE image_generation_slots SET state='published',version=version+1,published_disposition='late_authorized',published_disposition_generation=version+1 WHERE job_id=(SELECT job_id FROM image_generation_artifacts WHERE artifact_id=?1) AND slot_id=(SELECT slot_id FROM image_generation_artifacts WHERE artifact_id=?1) AND state='late_quarantined' AND version=?2 AND result_after_cancel=1",params![recorded.artifact_id.to_string(),row.4])?==1,"security publication slot compare-and-set lost");
        tx.commit()?;
        Ok(())
    }

    fn close_security_recovery_audit(
        &self,
        conn: &Connection,
        operation_id: Uuid,
        state: &str,
        evidence: &[u8],
    ) -> Result<()> {
        let now: i64 = conn.query_row(
            "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
            [],
            |row| row.get(0),
        )?;
        let digest = crate::intel::hex_lower(&Sha256::digest(evidence));
        ensure!(conn.execute("UPDATE image_generation_artifact_security_recovery_audits SET state=?1,outcome_digest=?2,decided_at_unix_ms=?3 WHERE recovery_operation_id=?4 AND principal_digest=?5 AND state='recorded'",params![state,digest,now,operation_id.to_string(),self.principal_digest])?==1,"security recovery audit is unavailable");
        Ok(())
    }
}

pub struct ImageGenerationResolutionProofs<'a> {
    pub runtime_snapshots: &'a [ImageHealthSnapshot],
    pub grants: &'a [SealedActionGrantRow],
    pub central_reservation: &'a MediaReservationPlan,
    pub central_reservation_receipt: &'a ReservationReceipt,
    pub spend_reservation: &'a SpendReservation,
    pub spend_attempts: &'a [AttemptMaximum],
    pub reference_leases: &'a [AcquiredMediaComponentLease],
    pub output: &'a HeldImageGenerationOutputDirectory,
    pub enqueue_started_monotonic_ms: u64,
    pub operation_deadline_monotonic_ms: u64,
    pub now_unix_ms: i64,
}

impl ImageGenerationResolutionAuthorityV1 {
    pub fn from_proofs(
        owner: ImageGenerationOwnerContextAuthority,
        request: &ImageGenerationRequestV1,
        proofs: ImageGenerationResolutionProofs<'_>,
    ) -> Result<Self> {
        ensure!(
            !request.target_ids.is_empty() && request.samples_per_target > 0,
            "image generation request has no outputs"
        );
        ensure!(
            proofs.operation_deadline_monotonic_ms > proofs.enqueue_started_monotonic_ms,
            "image generation deadline is invalid"
        );
        ensure!(
            proofs.central_reservation_receipt.state == ReservationState::ExecutingLocal
                && proofs.central_reservation_receipt.version > 0
                && proofs.central_reservation_receipt.deadline_monotonic_ms
                    >= proofs.operation_deadline_monotonic_ms
                && !proofs.central_reservation_receipt.reservation_id.is_empty(),
            "image generation media reservation receipt is not live"
        );
        let mut grants = proofs
            .grants
            .iter()
            .map(|grant| {
                ensure!(
                    grant.session_id == owner.session_id.to_string()
                        && grant.project_key == owner.project_id,
                    "grant authority does not belong to owner context"
                );
                grant_requirement_from_sealed_grant(grant, proofs.now_unix_ms)
            })
            .collect::<Result<Vec<_>>>()?;
        grants.sort();
        let references = proofs
            .reference_leases
            .iter()
            .map(|lease| {
                let required_lease_deadline = proofs
                    .now_unix_ms
                    .checked_add(i64::try_from(
                        proofs.operation_deadline_monotonic_ms
                            - proofs.enqueue_started_monotonic_ms,
                    )?)
                    .ok_or_else(|| anyhow::anyhow!("model input lease deadline overflow"))?;
                ensure!(
                    lease.owner_session_id == owner.session_id
                        && lease.canonical_project_digest == owner.project_identity_digest
                        && lease.lease_purpose == "model_input"
                        && lease.lease_expires_at_unix_ms >= required_lease_deadline
                        && lease.captured_capability_generation > 0,
                    "retained media lease does not belong to image generation authority"
                );
                reference_artifact_from_acquired_media_lease(lease)
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            references
                .iter()
                .map(|reference| reference.attachment_id)
                .eq(request.reference_attachment_ids.iter().copied()),
            "retained media proof set does not exactly match requested model inputs"
        );
        let mut runtimes = proofs
            .runtime_snapshots
            .iter()
            .map(|snapshot| {
                RuntimeTargetAuthorityV1::from_registry_snapshot(
                    snapshot,
                    proofs.operation_deadline_monotonic_ms,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        runtimes.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        ensure!(
            runtimes
                .iter()
                .map(|runtime| &runtime.target_id)
                .eq(request.target_ids.iter()),
            "runtime target authority does not exactly match request"
        );
        let expected_grants = runtimes
            .iter()
            .map(|runtime| runtime.required_grant.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        let actual_grants = grants
            .iter()
            .map(|grant| grant.grant_kind.as_str())
            .collect::<std::collections::BTreeSet<_>>();
        ensure!(
            expected_grants == actual_grants && grants.len() == expected_grants.len(),
            "image generation grant set does not exactly match target requirements"
        );
        let attempts_per_slot = runtimes
            .iter()
            .map(|runtime| runtime.max_attempts)
            .collect::<Vec<_>>();
        let total_attempts = attempts_per_slot
            .iter()
            .try_fold(0_usize, |total, attempts| {
                total
                    .checked_add(*attempts as usize * request.samples_per_target as usize)
                    .ok_or_else(|| anyhow::anyhow!("attempt graph overflow"))
            })?;
        ensure!(
            proofs.spend_attempts.len() == total_attempts,
            "spend proof does not match attempt graph"
        );
        ensure!(
            proofs.central_reservation.requested % total_attempts as u64 == 0,
            "central reservation cannot be allocated exactly"
        );
        let per_attempt_units = proofs.central_reservation.requested / total_attempts as u64;
        let reservation_identity = proofs.central_reservation_receipt.reservation_id.clone();
        let per_attempt_resource = resource_reservation_from_media_reservation(
            &MediaReservationPlan {
                requested: per_attempt_units,
                ..proofs.central_reservation.clone()
            },
            reservation_identity,
        )?;
        let central_resources = vec![resource_reservation_from_media_reservation(
            proofs.central_reservation,
            per_attempt_resource.reservation_identity.clone(),
        )?];
        let spend =
            spend_plan_from_spend_reservation(proofs.spend_reservation, proofs.spend_attempts)?;
        let mut spend_index = 0_usize;
        let mut targets = Vec::new();
        for (runtime, max_attempts) in runtimes.into_iter().zip(attempts_per_slot) {
            let mut slot_artifact_ids = Vec::new();
            for _ in 0..request.samples_per_target {
                slot_artifact_ids.push((Uuid::now_v7(), Uuid::now_v7()));
                spend_index += max_attempts as usize;
            }
            let first_attempt =
                spend_index - max_attempts as usize * request.samples_per_target as usize;
            let sealed_spend_attempts = &proofs.spend_attempts[first_attempt..spend_index];
            let attempt_maximum_usd_micros = sealed_spend_attempts
                .iter()
                .map(|attempt| attempt.usd_micros)
                .collect();
            let spend_attempt_identities = sealed_spend_attempts
                .iter()
                .map(|attempt| attempt.attempt_id.clone())
                .collect();
            targets.push(ImageGenerationTargetResolutionAuthorityV1 {
                runtime,
                references: references.clone(),
                slot_artifact_ids,
                max_attempts,
                attempt_resources: vec![per_attempt_resource.clone()],
                attempt_maximum_usd_micros,
                spend_attempt_identities,
            });
        }
        Ok(Self {
            job_id: Uuid::now_v7(),
            owner,
            enqueue_started_monotonic_ms: proofs.enqueue_started_monotonic_ms,
            operation_deadline_monotonic_ms: proofs.operation_deadline_monotonic_ms,
            required_grants: grants,
            central_resources,
            spend,
            output_authority: proofs.output.authority().clone(),
            targets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationTargetAlternativeV1 {
    pub target_id: String,
    pub supported_formats: Vec<String>,
    pub maximum_width: u32,
    pub maximum_height: u32,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationResolutionV1 {
    Ready(ImageGenerationPlanV1),
    Incompatible(Vec<ImageGenerationTargetAlternativeV1>),
}

pub fn resolve_image_generation(
    request: ImageGenerationRequestV1,
    authority: ImageGenerationResolutionAuthorityV1,
) -> Result<ImageGenerationResolutionV1> {
    ensure!(
        request.target_ids.windows(2).all(|pair| pair[0] < pair[1]),
        "requested targets must be unique and sorted"
    );
    ensure!(
        request
            .reference_attachment_ids
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "requested references must be unique and sorted"
    );
    let mut alternatives = Vec::new();
    let mut targets = Vec::new();
    for target_id in &request.target_ids {
        let Some(target) = authority
            .targets
            .iter()
            .find(|item| item.runtime.target_id == *target_id)
        else {
            alternatives.push(ImageGenerationTargetAlternativeV1 {
                target_id: target_id.clone(),
                supported_formats: vec![],
                maximum_width: 0,
                maximum_height: 0,
                reason: "target is not authorized".into(),
            });
            continue;
        };
        let compatible = target.runtime.supported_formats.get(&request.format);
        let parameters_valid = request.parameters.iter().all(|(key, value)| {
            match (
                target
                    .runtime
                    .allowed_parameters
                    .get(key)
                    .map(String::as_str),
                value,
            ) {
                (Some("boolean"), TypedParameterV1::Boolean(_))
                | (Some("integer"), TypedParameterV1::Integer(_)) => true,
                (Some("text"), TypedParameterV1::Text(text)) => valid_string(text),
                _ => false,
            }
        });
        if compatible.is_none()
            || request.width > target.runtime.maximum_width
            || request.height > target.runtime.maximum_height
            || !parameters_valid
            || target.slot_artifact_ids.len() != request.samples_per_target as usize
        {
            alternatives.push(ImageGenerationTargetAlternativeV1 {
                target_id: target_id.clone(),
                supported_formats: target.runtime.supported_formats.keys().cloned().collect(),
                maximum_width: target.runtime.maximum_width,
                maximum_height: target.runtime.maximum_height,
                reason: "request is incompatible with sealed target capability".into(),
            });
            continue;
        }
        let format = request.format.clone();
        targets.push(ImageGenerationPreflightTargetV1 {
            authority: target.runtime.clone(),
            reference_artifacts: target.references.clone(),
            requested: RequestedOutputV1 {
                width: request.width,
                height: request.height,
                format: format.clone(),
            },
            resolved: ResolvedOutputV1 {
                width: request.width,
                height: request.height,
                format: format.clone(),
                mime: compatible.unwrap().clone(),
                vector_sanitization_required: format == "svg",
                vector_sanitizer: (format == "svg")
                    .then(crate::generated_svg::sanitizer_provenance),
            },
            typed_parameters: request.parameters.clone(),
            slot_ids: target.slot_artifact_ids.clone(),
            max_attempts: target.max_attempts,
            attempt_resource_maximum: target.attempt_resources.clone(),
            attempt_maximum_usd_micros: target.attempt_maximum_usd_micros.clone(),
            spend_attempt_identities: target.spend_attempt_identities.clone(),
        });
    }
    if !alternatives.is_empty() {
        return Ok(ImageGenerationResolutionV1::Incompatible(alternatives));
    }
    let plan = plan_image_generation(ImageGenerationPreflightInputV1 {
        job_id: authority.job_id,
        owner_session_id: authority.owner.session_id,
        owner_principal_digest: authority.owner.principal_digest,
        project_identity_digest: authority.owner.project_identity_digest,
        config_generation: authority.owner.config_generation,
        enqueue_started_monotonic_ms: authority.enqueue_started_monotonic_ms,
        operation_deadline_monotonic_ms: authority.operation_deadline_monotonic_ms,
        required_grants: authority.required_grants,
        central_resources: authority.central_resources,
        spend: authority.spend,
        output_authority: authority.output_authority,
        targets,
    })?;
    Ok(ImageGenerationResolutionV1::Ready(plan))
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
    guard: crate::private_fs::held_directory::HeldDirectoryAuthority,
    authority: VerifiedOutputDirectoryAuthority,
}

#[derive(Debug)]
pub struct HeldImageGenerationArtifactRoot {
    guard: crate::private_fs::held_directory::HeldDirectoryAuthority,
}

impl HeldImageGenerationArtifactRoot {
    pub fn create_component_temporary(&self, name: &str) -> Result<HeldTemporaryArtifact> {
        self.guard.create_file_exclusive(name)
    }
    pub fn seal_component(&self, temporary: HeldTemporaryArtifact) -> Result<HeldSealedArtifact> {
        self.guard.seal(temporary)
    }
    pub fn retain_component_noreplace(
        &self,
        temporary: HeldSealedArtifact,
        name: &str,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.rename_noreplace(temporary, name)
    }
    pub fn open_verified_component(
        &self,
        name: &str,
        evidence: &HeldArtifactEvidence,
    ) -> Result<HeldSealedArtifact> {
        self.guard.open_verified(name, evidence)
    }
    pub fn open_component_for_owner_recovery(
        &self,
        component_id: Uuid,
        kind: ImageGenerationArtifactComponentKind,
        generation: u64,
        name: &str,
        evidence: &HeldArtifactEvidence,
    ) -> Result<VerifiedManagedComponentForRecovery> {
        ensure!(generation > 0, "component recovery generation is invalid");
        Ok(VerifiedManagedComponentForRecovery {
            component_id,
            kind,
            generation,
            held: self.guard.open_verified(name, evidence)?,
        })
    }
    pub fn remove_verified_component(
        &self,
        component: HeldSealedArtifact,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.unlink(component)
    }
    pub fn reconcile_component(
        &self,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.reconcile(recovery)
    }
}

#[derive(Debug)]
pub struct VerifiedManagedComponentForRecovery {
    component_id: Uuid,
    kind: ImageGenerationArtifactComponentKind,
    generation: u64,
    held: HeldSealedArtifact,
}

pub struct AdoptVerifiedCopyAuthorizedPublication<'a> {
    pub publication_operation_id: Uuid,
    pub expected_lease_version: u64,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
    pub recovery: &'a HeldDirectoryRecovery,
}

pub fn adopt_verified_copy_authorized_publication(
    conn: &Connection,
    owner: &ImageGenerationOwnerContextAuthority,
    output: &HeldImageGenerationOutputDirectory,
    input: &AdoptVerifiedCopyAuthorizedPublication<'_>,
) -> Result<()> {
    owner.revalidate_live_session(conn)?;
    let HeldDirectoryEffectOutcome::AppliedDurable(effect) =
        output.reconcile_publication(input.recovery)?
    else {
        anyhow::bail!("copy-authorized publication is not durably present")
    };
    let destination = effect
        .destination_name()
        .context("copy-authorized publication destination is absent")?;
    let authority = &output.authority.0;
    let binding = conn
        .query_row(
            "SELECT l.destination_name,l.output_authority_digest,l.output_authority_generation,p.canonical_plan,p.plan_digest FROM image_generation_late_publication_leases l JOIN image_generation_artifacts a ON a.artifact_id=l.artifact_id JOIN image_generation_plans p ON p.job_id=a.job_id JOIN image_generation_late_publication_authorization_facts f ON f.authorization_digest=l.authorization_digest WHERE l.publication_operation_id=?1 AND l.state='copy_authorized' AND l.version=?2 AND f.revoked_at_unix_ms IS NULL AND f.principal_digest=?3",
            params![input.publication_operation_id.to_string(), i64::try_from(input.expected_lease_version)?, owner.principal_digest],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, i64>(2)?, row.get::<_, Vec<u8>>(3)?, row.get::<_, String>(4)?)),
        )
        .optional()?
        .context("copy-authorized publication authority is unavailable")?;
    let plan = ImageGenerationPlanV1::from_canonical(&binding.3, &binding.4)?;
    ensure!(
        binding.0 == destination
            && binding.1 == authority.canonical_destination_digest
            && binding.2 == i64::try_from(authority.authority_generation)?
            && plan.owner_session_id == owner.session_id
            && plan.owner_principal_digest == owner.principal_digest
            && plan.project_identity_digest == owner.project_identity_digest
            && plan.config_generation == owner.config_generation,
        "copy-authorized publication authority differs"
    );
    let evidence = ImageGenerationLatePublicationEvidenceV1::OutputDurable {
        schema_version: 1,
        identity_digest: effect.artifact().identity_digest().to_owned(),
        security_digest: effect.artifact().security_digest().to_owned(),
        byte_length: effect.artifact().byte_length().to_string(),
        sha256: effect.artifact().sha256().to_owned(),
        parent_sync_digest: authority.parent_identity_digest.clone(),
    }
    .canonical_json()?;
    cockpit_db::Db::advance_image_generation_late_publication_conn(
        conn,
        &AdvanceImageGenerationLatePublication {
            publication_operation_id: input.publication_operation_id,
            expected_version: input.expected_lease_version,
            worker_boot_id: input.worker_boot_id,
            claim_generation: input.claim_generation,
            from: ImageGenerationLatePublicationState::CopyAuthorized,
            to: ImageGenerationLatePublicationState::CopyCommitted,
            evidence_json: &evidence,
        },
    )
}

pub fn block_verified_copy_authorized_publication(
    conn: &Connection,
    output: &HeldImageGenerationOutputDirectory,
    input: &AdoptVerifiedCopyAuthorizedPublication<'_>,
) -> Result<HeldArtifactEvidence> {
    let HeldDirectoryEffectOutcome::AppliedDurable(effect) =
        output.reconcile_publication(input.recovery)?
    else {
        anyhow::bail!("copy-authorized publication identity is ambiguous")
    };
    let destination = effect
        .destination_name()
        .context("copy-authorized publication destination is absent")?;
    let authority = &output.authority.0;
    let binding: (String, String, i64) = conn
        .query_row(
            "SELECT destination_name,output_authority_digest,output_authority_generation FROM image_generation_late_publication_leases WHERE publication_operation_id=?1 AND state='copy_authorized' AND version=?2 AND worker_boot_id=?3 AND claim_generation=?4",
            params![input.publication_operation_id.to_string(), i64::try_from(input.expected_lease_version)?, input.worker_boot_id.to_string(), i64::try_from(input.claim_generation)?],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .context("copy-authorized publication authority is unavailable")?;
    ensure!(
        binding.0 == destination
            && binding.1 == authority.canonical_destination_digest
            && binding.2 == i64::try_from(authority.authority_generation)?,
        "copy-authorized publication authority differs"
    );
    let artifact = effect.artifact().clone();
    let evidence = ImageGenerationLatePublicationEvidenceV1::OutputDurable {
        schema_version: 1,
        identity_digest: artifact.identity_digest().into(),
        security_digest: artifact.security_digest().into(),
        byte_length: artifact.byte_length().to_string(),
        sha256: artifact.sha256().into(),
        parent_sync_digest: authority.parent_identity_digest.clone(),
    }
    .canonical_json()?;
    let recovery_evidence = ImageGenerationLatePublicationEvidenceV1::SecurityAmbiguous {
        schema_version: 1,
        recovery_digest: crate::intel::hex_lower(&Sha256::digest(format!(
            "verified-output-block:{}:{}:{}",
            input.publication_operation_id,
            artifact.identity_digest(),
            artifact.security_digest()
        ))),
    }
    .canonical_json()?;
    cockpit_db::Db::block_verified_image_generation_late_publication_conn(
        conn,
        &BlockVerifiedImageGenerationLatePublication {
            publication_operation_id: input.publication_operation_id,
            expected_version: input.expected_lease_version,
            worker_boot_id: input.worker_boot_id,
            claim_generation: input.claim_generation,
            output_evidence_json: &evidence,
            recovery_evidence_json: &recovery_evidence,
        },
    )?;
    Ok(artifact)
}

fn held_artifact_evidence_json(evidence: &HeldArtifactEvidence) -> Result<String> {
    Ok(serde_json::to_string(&serde_json::json!({
        "byteLength": evidence.byte_length().to_string(),
        "identityDigest": evidence.identity_digest(),
        "securityDigest": evidence.security_digest(),
        "sha256": evidence.sha256(),
    }))?)
}

pub fn open_image_generation_artifact_root(path: &Path) -> Result<HeldImageGenerationArtifactRoot> {
    Ok(HeldImageGenerationArtifactRoot {
        guard: crate::private_fs::held_directory::HeldDirectoryAuthority::open_existing(path)?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedImageArtifactFormat {
    Png,
    Jpeg,
    Webp,
    Svg,
}

pub struct RetainGeneratedImageArtifact<'a> {
    pub artifact_id: Uuid,
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub component_id: Uuid,
    pub format: GeneratedImageArtifactFormat,
    pub expected_width: u32,
    pub expected_height: u32,
    pub bytes: &'a [u8],
    pub resource_reservation_id: String,
    pub release_operation_id: Uuid,
    pub late_quarantined: bool,
    pub now_unix_ms: i64,
}

pub fn retain_generated_image_artifact(
    conn: &Connection,
    root: &HeldImageGenerationArtifactRoot,
    input: &RetainGeneratedImageArtifact<'_>,
) -> Result<HeldArtifactEvidence> {
    let canonical = validate_generated_image_bytes(
        input.format,
        input.expected_width,
        input.expected_height,
        input.bytes,
    )?;
    let checksum = crate::intel::hex_lower(&Sha256::digest(&canonical));
    let final_name = format!("{}-{}.artifact", input.artifact_id, input.component_id);
    let temporary_name = format!(".{}-{}.partial", input.artifact_id, input.component_id);
    let component = CreateImageGenerationArtifactComponent {
        component_id: input.component_id,
        kind: ImageGenerationArtifactComponentKind::Primary,
        relative_storage_key: final_name.clone(),
        byte_length: u64::try_from(canonical.len())?,
        sha256: checksum,
        resource_reservation_id: input.resource_reservation_id.clone(),
        release_operation_id: input.release_operation_id,
    };
    let component_set_digest =
        image_generation_component_set_binding(std::slice::from_ref(&component))?.1;
    cockpit_db::Db::create_image_generation_artifact_conn(
        conn,
        &CreateImageGenerationArtifact {
            artifact_id: input.artifact_id,
            job_id: input.job_id,
            slot_id: input.slot_id,
            component_set_digest,
            components: vec![component],
            now_unix_ms: input.now_unix_ms,
        },
    )?;
    cockpit_db::Db::transition_image_generation_artifact_conn(
        conn,
        &TransitionImageGenerationArtifact {
            artifact_id: input.artifact_id,
            expected_generation: 1,
            from: ImageGenerationArtifactState::Allocating,
            to: ImageGenerationArtifactState::Writing,
            now_unix_ms: input.now_unix_ms,
            terminal_reason: None,
        },
    )?;
    cockpit_db::Db::transition_image_generation_artifact_component_conn(
        conn,
        &TransitionImageGenerationArtifactComponent {
            artifact_id: input.artifact_id,
            component_id: input.component_id,
            expected_generation: 1,
            from: ImageGenerationArtifactComponentState::Planned,
            to: ImageGenerationArtifactComponentState::Writing,
            stable_identity_json: None,
            deletion_evidence_digest: None,
        },
    )?;
    let mut temporary = root.create_component_temporary(&temporary_name)?;
    use std::io::Write as _;
    temporary.file_mut().write_all(&canonical)?;
    let sealed = root.seal_component(temporary)?;
    let HeldDirectoryEffectOutcome::AppliedDurable(effect) =
        root.retain_component_noreplace(sealed, &final_name)?
    else {
        anyhow::bail!("managed artifact publication requires reconciliation")
    };
    let evidence = effect.artifact().clone();
    let evidence_json = held_artifact_evidence_json(&evidence)?;
    cockpit_db::Db::transition_image_generation_artifact_component_conn(
        conn,
        &TransitionImageGenerationArtifactComponent {
            artifact_id: input.artifact_id,
            component_id: input.component_id,
            expected_generation: 2,
            from: ImageGenerationArtifactComponentState::Writing,
            to: ImageGenerationArtifactComponentState::Ready,
            stable_identity_json: Some(evidence_json),
            deletion_evidence_digest: None,
        },
    )?;
    cockpit_db::Db::transition_image_generation_artifact_conn(
        conn,
        &TransitionImageGenerationArtifact {
            artifact_id: input.artifact_id,
            expected_generation: 2,
            from: ImageGenerationArtifactState::Writing,
            to: if input.late_quarantined {
                ImageGenerationArtifactState::LateQuarantined
            } else {
                ImageGenerationArtifactState::Retained
            },
            now_unix_ms: input.now_unix_ms,
            terminal_reason: None,
        },
    )?;
    Ok(evidence)
}

fn validate_generated_image_bytes(
    format: GeneratedImageArtifactFormat,
    width: u32,
    height: u32,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        width > 0
            && height > 0
            && width <= MAX_IMAGE_GENERATION_DIMENSION
            && height <= MAX_IMAGE_GENERATION_DIMENSION,
        "generated image dimensions exceed plan limits"
    );
    if format == GeneratedImageArtifactFormat::Svg {
        return Ok(crate::generated_svg::sanitize_generated_svg(bytes)
            .map_err(|error| anyhow::anyhow!(error.to_string()))?
            .into_bytes());
    }
    use image::{ImageDecoder as _, ImageFormat, ImageReader, Limits};
    let image_format = match format {
        GeneratedImageArtifactFormat::Png => ImageFormat::Png,
        GeneratedImageArtifactFormat::Jpeg => ImageFormat::Jpeg,
        GeneratedImageArtifactFormat::Webp => ImageFormat::WebP,
        GeneratedImageArtifactFormat::Svg => unreachable!(),
    };
    let mut reader = ImageReader::with_format(std::io::Cursor::new(bytes), image_format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_GENERATION_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_GENERATION_DIMENSION);
    limits.max_alloc = Some(160_000_000);
    reader.limits(limits);
    let decoder = reader
        .into_decoder()
        .context("generated raster decode failed")?;
    ensure!(
        decoder.dimensions() == (width, height),
        "generated raster dimensions differ from sealed plan"
    );
    let _ = image::DynamicImage::from_decoder(decoder)
        .context("generated raster pixels are invalid")?;
    Ok(bytes.to_vec())
}
impl HeldImageGenerationOutputDirectory {
    pub fn authority(&self) -> &VerifiedOutputDirectoryAuthority {
        &self.authority
    }
    pub fn path(&self) -> &Path {
        self.guard.diagnostic_path()
    }
    pub fn create_temporary_exclusive(&self, name: &str) -> Result<HeldTemporaryArtifact> {
        self.guard.create_file_exclusive(name)
    }
    pub fn seal_temporary(&self, temporary: HeldTemporaryArtifact) -> Result<HeldSealedArtifact> {
        self.guard.seal(temporary)
    }
    pub fn publish_temporary_noreplace(
        &self,
        temporary: HeldSealedArtifact,
        output: &str,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.rename_noreplace(temporary, output)
    }
    pub fn remove_temporary(
        &self,
        temporary: HeldSealedArtifact,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.unlink(temporary)
    }
    pub fn reconcile_publication(
        &self,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.reconcile(recovery)
    }
    fn delete_recovered_publication(
        &self,
        recovery: &HeldDirectoryRecovery,
    ) -> Result<HeldDirectoryEffectOutcome> {
        self.guard.delete_recovered_destination(recovery)
    }
    #[cfg(test)]
    fn force_next_directory_sync_failure(&self) {
        self.guard.force_next_directory_sync_failure();
    }
}
pub fn open_image_generation_output_directory(
    path: &Path,
    authority_generation: u64,
    filename_prefix: String,
    extension: String,
) -> Result<HeldImageGenerationOutputDirectory> {
    let guard = crate::private_fs::held_directory::HeldDirectoryAuthority::open_existing(path)?;
    let parent_identity_digest = guard.identity().stable_digest.clone();
    let canonical_destination_digest = digest_fields(&[
        guard.identity().platform,
        &guard.identity().canonical_binding_digest,
    ]);
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
pub(crate) struct ImageGenerationPreflightTargetV1 {
    pub authority: RuntimeTargetAuthorityV1,
    pub reference_artifacts: Vec<ReferenceArtifactV1>,
    pub requested: RequestedOutputV1,
    pub resolved: ResolvedOutputV1,
    pub typed_parameters: BTreeMap<String, TypedParameterV1>,
    pub slot_ids: Vec<(Uuid, Uuid)>,
    pub max_attempts: u32,
    pub attempt_resource_maximum: Vec<ResourceReservationV1>,
    pub attempt_maximum_usd_micros: Vec<Option<u64>>,
    pub spend_attempt_identities: Vec<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageGenerationPreflightInputV1 {
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

pub(crate) fn plan_image_generation(
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
        let sealed_attempt_count = target.slot_ids.len() * target.max_attempts as usize;
        ensure!(
            target.attempt_maximum_usd_micros.len() == sealed_attempt_count
                && target.spend_attempt_identities.len() == sealed_attempt_count,
            "target spend attempt graph is incomplete"
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
                    let spend_identity = &target.spend_attempt_identities
                        [sample_index * target.max_attempts as usize + attempt_number as usize - 1];
                    let identity = digest_fields(&[
                        &input.job_id.to_string(),
                        &slot_id.to_string(),
                        &attempt_number.to_string(),
                        spend_identity,
                    ]);
                    AttemptPlanV1 {
                        attempt_number,
                        provider_request_identity: format!("request:{identity}"),
                        provider_idempotency_identity: spend_identity.clone(),
                        resource_maximum: target.attempt_resource_maximum.clone(),
                        maximum_usd_micros: target.attempt_maximum_usd_micros[sample_index
                            * target.max_attempts as usize
                            + attempt_number as usize
                            - 1],
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
        ensure!(
            capability.constraints.keys().all(|key| matches!(
                key.as_str(),
                "formats"
                    | "max_width"
                    | "max_height"
                    | "parameters"
                    | "max_attempts"
                    | "required_grant"
            )),
            "capability contains an unknown constraint"
        );
        let formats = capability
            .constraints
            .get("formats")
            .ok_or_else(|| anyhow::anyhow!("capability formats are missing"))?
            .split(',')
            .map(|format| {
                let mime = match format {
                    "png" => "image/png",
                    "jpeg" | "jpg" => "image/jpeg",
                    "webp" => "image/webp",
                    "svg" => "image/svg+xml",
                    _ => anyhow::bail!("unknown capability format"),
                };
                Ok((format.to_owned(), mime.to_owned()))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        ensure!(!formats.is_empty(), "capability formats are empty");
        let canonical_constraints = serde_json::to_string(&capability.constraints)?;
        Ok(Self {
            target_id: snapshot.target_id.clone(),
            target_config_generation: snapshot.config_generation,
            normalized_config_digest: digest_fields(&[&snapshot.target_immutable_identity]),
            capability_provenance: CapabilityProvenanceV1 {
                capability_generation: snapshot.refresh_epoch,
                capability_digest: digest_fields(&[
                    &capability.target_id,
                    &capability.model_or_workflow_digest,
                    &canonical_constraints,
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
            supported_formats: formats,
            maximum_width: capability
                .constraints
                .get("max_width")
                .ok_or_else(|| anyhow::anyhow!("capability maximum width is missing"))?
                .parse()?,
            maximum_height: capability
                .constraints
                .get("max_height")
                .ok_or_else(|| anyhow::anyhow!("capability maximum height is missing"))?
                .parse()?,
            allowed_parameters: capability
                .constraints
                .get("parameters")
                .into_iter()
                .flat_map(|value| value.split(','))
                .map(|entry| {
                    let (name, kind) = entry
                        .split_once(':')
                        .ok_or_else(|| anyhow::anyhow!("invalid parameter capability"))?;
                    ensure!(
                        valid_string(name) && matches!(kind, "boolean" | "integer" | "text"),
                        "unknown parameter capability"
                    );
                    Ok((name.to_owned(), kind.to_owned()))
                })
                .collect::<Result<_>>()?,
            max_attempts: capability
                .constraints
                .get("max_attempts")
                .ok_or_else(|| anyhow::anyhow!("capability attempt bound is missing"))?
                .parse::<u32>()?,
            required_grant: capability
                .constraints
                .get("required_grant")
                .filter(|grant| valid_string(grant))
                .ok_or_else(|| anyhow::anyhow!("capability required grant is missing"))?
                .clone(),
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
    use std::sync::Arc;

    struct SchedulerClock;
    impl crate::media_reservation::MonotonicClock for SchedulerClock {
        fn now_ms(&self) -> u64 {
            100
        }
    }

    #[tokio::test]
    async fn deterministic_adapter_records_one_closed_handoff() {
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted".to_vec(),
            },
        ]);
        let request = ImageGenerationHandoffRequest {
            job_id: Uuid::now_v7(),
            slot_id: Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: Uuid::now_v7(),
            provider_request_identity: "request:1".into(),
            provider_idempotency_identity: "idempotency:1".into(),
        };
        assert!(matches!(
            adapter.handoff(&request).await,
            ImageGenerationHandoffResult::Accepted { .. }
        ));
        assert_eq!(adapter.requests(), vec![request]);
    }

    struct RealLedgerSchedulerFixture {
        db: cockpit_db::Db,
        owner_session_id: Uuid,
        job_id: Uuid,
        slot_id: Uuid,
        artifact_id: Uuid,
        spend_reservation_id: String,
        media_reservation_id: String,
    }

    async fn setup_real_ledger_scheduler_job(
        db: cockpit_db::Db,
        suffix: &str,
    ) -> RealLedgerSchedulerFixture {
        setup_real_ledger_scheduler_job_with_output(db, suffix, None).await
    }

    async fn setup_real_ledger_scheduler_job_with_output(
        db: cockpit_db::Db,
        suffix: &str,
        output: Option<VerifiedOutputDirectoryAuthority>,
    ) -> RealLedgerSchedulerFixture {
        use crate::media_reservation::{
            MediaOwner, MediaReservationLedger, ReservationState, ReserveRequest,
        };
        use cockpit_config::config::media_budget::{
            MediaDimension, MediaEvaluationRequest, MediaResourcePolicy,
        };
        use cockpit_db::db::image_generation::{
            CreateImageGenerationAttempt, CreateImageGenerationJob, CreateImageGenerationSlot,
            ImageGenerationMediaPlanSnapshot,
        };
        use cockpit_db::image_spend::{
            AttemptMaximum, BudgetPolicy, ImageSpendSettings, ProjectEpochPolicy, SpendScopeKeys,
        };
        let mut sealed = plan();
        let project_id = format!("fixture-project-{suffix}");
        let project_root = format!("/fixture-project-{suffix}");
        let session = db
            .create_session(&project_id, &project_root, "Image generation fixture")
            .await
            .unwrap();
        sealed.owner_session_id = session.session_id;
        sealed.owner_principal_digest = crate::intel::hex_lower(&Sha256::digest(
            serde_json::to_vec(&ClientPrincipal::Owner).unwrap(),
        ));
        sealed.project_identity_digest =
            crate::intel::hex_lower(&Sha256::digest(project_root.as_bytes()));
        if let Some(output) = output {
            sealed.output_authority = output.0;
        }
        let suffix_id = suffix
            .bytes()
            .fold(0_u128, |sum, byte| sum.wrapping_add(u128::from(byte)));
        sealed.job_id = id(1_000 + suffix_id * 3);
        sealed.targets[0].slots[0].slot_id = id(1_001 + suffix_id * 3);
        sealed.targets[0].slots[0].managed_artifact_id = id(1_002 + suffix_id * 3);
        let resource_identity = format!("gpu:{suffix}");
        sealed.central_resources[0].reservation_identity = resource_identity.clone();
        sealed.targets[0].slots[0].attempts[0].resource_maximum[0].reservation_identity =
            resource_identity;
        sealed.spend.reservation_id = format!("spend:{suffix}");
        let provider_request_identity = format!("request:{suffix}");
        let provider_idempotency_identity = format!("idem:{suffix}");
        sealed.targets[0].slots[0].attempts[0].provider_request_identity =
            provider_request_identity.clone();
        sealed.targets[0].slots[0].attempts[0].provider_idempotency_identity =
            provider_idempotency_identity.clone();
        let canonical = sealed.canonical_bytes().unwrap();
        let plan_digest = sealed.digest().unwrap();
        let policy = MediaResourcePolicy::default();
        let evaluated = |dimension, requested| {
            policy
                .evaluate(MediaEvaluationRequest {
                    dimension,
                    requested: Some(requested),
                    current_scope: 0,
                    profile: None,
                    adapter_limit: None,
                    request_limit: None,
                })
                .unwrap()
        };
        let deadline = evaluated(MediaDimension::OperationDeadlineSeconds, 1);
        let queued_global = evaluated(MediaDimension::QueuedOperationsGlobal, 1);
        let queued_session = evaluated(MediaDimension::QueuedOperationsPerSession, 1);
        let local = evaluated(MediaDimension::LocalCpuJobsGlobal, 1);
        let handoff = evaluated(MediaDimension::OutboundSubmissionsGlobal, 1);
        let ledger = MediaReservationLedger::new(db.clone(), Arc::new(SchedulerClock));
        let receipt = ledger
            .reserve(ReserveRequest {
                reservation_id: sealed.central_resources[0].reservation_identity.clone(),
                recovery_id: format!("scheduler-recovery-{suffix}"),
                owner: MediaOwner {
                    project_id: project_id.clone(),
                    session_id: sealed.owner_session_id.to_string(),
                },
                operation: "image_generation".into(),
                purpose: format!("scheduler_fixture_{suffix}"),
                plans: vec![
                    deadline,
                    queued_global,
                    queued_session,
                    local.clone(),
                    handoff.clone(),
                ],
                wall_ms: 1,
            })
            .await
            .unwrap();
        ledger
            .mark_execution_ready(&receipt.reservation_id, 2)
            .await
            .unwrap();
        let executing = ledger
            .claim_ready_fair(&receipt.reservation_id, local, 3)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(executing.state, ReservationState::ExecutingLocal);
        db.save_image_spend_policy(
            project_id.clone(),
            ImageSpendSettings {
                request: BudgetPolicy::Finite { usd_micros: 100 },
                session: BudgetPolicy::Finite { usd_micros: 100 },
                project: BudgetPolicy::Finite { usd_micros: 100 },
                project_epoch: Some(ProjectEpochPolicy::CalendarMonth {
                    time_zone: "UTC".into(),
                }),
            },
            None,
            1,
        )
        .await
        .unwrap();
        db.reserve_image_spend(
            sealed.spend.reservation_id.clone(),
            SpendScopeKeys {
                plan_digest: plan_digest.clone(),
                session_id: sealed.owner_session_id.to_string(),
                project_key: project_id,
            },
            vec![AttemptMaximum {
                attempt_id: provider_idempotency_identity.clone(),
                usd_micros: Some(10),
            }],
            1,
            1,
        )
        .await
        .unwrap();
        let fixture_job_id = sealed.job_id;
        let fixture_owner_session_id = sealed.owner_session_id;
        let fixture_slot_id = sealed.targets[0].slots[0].slot_id;
        let fixture_artifact_id = sealed.targets[0].slots[0].managed_artifact_id;
        let fixture_spend = sealed.spend.reservation_id.clone();
        let fixture_media = sealed.central_resources[0].reservation_identity.clone();
        db.transaction(move |conn| {
            let verified = CreateImageGenerationJob::from_verified_canonical_plan(
                &canonical,
                &plan_digest,
                1,
            )?;
            let slot = &sealed.targets[0].slots[0];
            cockpit_db::Db::create_image_generation_graph_conn(
                conn,
                &verified,
                &[CreateImageGenerationSlot {
                    slot_id: slot.slot_id,
                    slot_index: 0,
                    sample_index: 0,
                    managed_artifact_id: slot.managed_artifact_id,
                    attempts: vec![CreateImageGenerationAttempt {
                        attempt_number: 1,
                        provider_request_identity,
                        provider_idempotency_identity,
                    }],
                }],
            )?;
            let authority =
                cockpit_db::Db::image_generation_queue_authority_conn(conn, sealed.job_id)?;
            let (bytes, digest) = canonical_media_plan_snapshot(&handoff)?;
            cockpit_db::Db::queue_image_generation_job_conn(
                conn,
                authority,
                &ImageGenerationMediaPlanSnapshot {
                    canonical_bytes: &bytes,
                    digest: &digest,
                },
                1,
            )
        })
        .await
        .unwrap();
        RealLedgerSchedulerFixture {
            db,
            owner_session_id: fixture_owner_session_id,
            job_id: fixture_job_id,
            slot_id: fixture_slot_id,
            artifact_id: fixture_artifact_id,
            spend_reservation_id: fixture_spend,
            media_reservation_id: fixture_media,
        }
    }

    async fn run_real_ledger_scheduler_fixture(suffix: &str) {
        let fixture =
            setup_real_ledger_scheduler_job(cockpit_db::Db::open_in_memory().unwrap(), suffix)
                .await;
        let job_id = fixture.job_id;
        let slot_id = fixture.slot_id;
        let db = fixture.db;
        let dispatcher = ImageGenerationDispatcher::new(db.clone());
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted".to_vec(),
            },
        ]);
        let first = dispatcher
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(first.dispatched, 1, "{first:#?}");
        assert_eq!(adapter.requests().len(), 1);
        db.blocking_for_sync_cli(move |conn| {
            let replay = cockpit_db::Db::replay_image_generation_handoff_evidence_conn(
                conn, job_id, slot_id, 1,
            )?;
            assert_eq!(replay.outcome, ImageSpendDispatchEvidence::Accepted);
            assert_eq!(replay.bytes, b"accepted");
            assert!(
                conn.execute(
                    "UPDATE image_generation_handoff_evidence SET evidence=X'00' WHERE job_id=?1",
                    [job_id.to_string()]
                )
                .is_err()
            );
            assert!(
                conn.execute(
                    "DELETE FROM image_generation_handoff_evidence WHERE job_id=?1",
                    [job_id.to_string()]
                )
                .is_err()
            );
            Ok(())
        })
        .unwrap();
        let second = dispatcher
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 3, 3, 8)
            .await
            .unwrap();
        assert_eq!(second.dispatched, 0, "{second:#?}");
        assert_eq!(adapter.requests().len(), 1);
    }

    #[tokio::test]
    async fn scheduler_dispatches_one_real_ledger_job_once() {
        run_real_ledger_scheduler_fixture("once").await;
    }

    #[tokio::test]
    async fn handoff_evidence_survives_file_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("image.db");
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open(&path).unwrap(),
            "evidence-reopen",
        )
        .await;
        let job = fixture.job_id;
        let slot = fixture.slot_id;
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"ambiguous".to_vec(),
            },
        ]);
        ImageGenerationDispatcher::new(fixture.db)
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 2, 2, 8)
            .await
            .unwrap();
        let reopened = cockpit_db::Db::open(&path).unwrap();
        reopened
            .blocking_for_sync_cli(move |conn| {
                let replay = cockpit_db::Db::replay_image_generation_handoff_evidence_conn(
                    conn, job, slot, 1,
                )?;
                assert_eq!(
                    replay.outcome,
                    ImageSpendDispatchEvidence::SubmissionUnknown
                );
                assert_eq!(replay.bytes, b"ambiguous");
                Ok(())
            })
            .unwrap();
    }

    #[tokio::test]
    async fn handoff_evidence_finish_failure_rolls_back_every_projection() {
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open_in_memory().unwrap(),
            "evidence-cut",
        )
        .await;
        let job = fixture.job_id;
        let slot = fixture.slot_id;
        fixture.db.blocking_for_sync_cli(|conn|{conn.execute_batch("CREATE TEMP TRIGGER cut_handoff_evidence AFTER INSERT ON image_generation_handoff_evidence BEGIN SELECT RAISE(ABORT,'cut'); END")?;Ok(())}).unwrap();
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted-cut".to_vec(),
            },
        ]);
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 0);
        assert_eq!(adapter.requests().len(), 1);
        fixture.db.blocking_for_sync_cli(move|conn|{let row:(String,String,i64)=conn.query_row("SELECT a.state,o.state,(SELECT count(*) FROM image_generation_handoff_evidence e WHERE e.job_id=a.job_id AND e.slot_id=a.slot_id) FROM image_generation_attempts a JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE a.job_id=?1 AND a.slot_id=?2",rusqlite::params![job.to_string(),slot.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;assert_eq!(row,("dispatching".into(),"dispatching".into(),0));Ok(())}).unwrap();
    }

    struct LatePublicationRecoveryFixture {
        _temporary: tempfile::TempDir,
        db: cockpit_db::Db,
        output: HeldImageGenerationOutputDirectory,
        output_path: std::path::PathBuf,
        owner_session_id: Uuid,
        job_id: Uuid,
        slot_id: Uuid,
        slot_generation: u64,
        artifact_id: Uuid,
        artifact_generation: u64,
        component_set_digest: String,
        components: Vec<RecoverImageArtifactComponentIdentity>,
        publication_operation_id: Uuid,
        worker_boot_id: Uuid,
        publication_recovery: HeldDirectoryRecovery,
    }

    async fn setup_accepted_late_publication_recovery_fixture(
        suffix: &str,
    ) -> LatePublicationRecoveryFixture {
        use cockpit_db::db::image_generation::{
            AdoptImageGenerationResponse, AdvanceImageGenerationLatePublication,
            BeginImageGenerationDownload, ClaimImageGenerationLatePublication,
            CommitImageGenerationValidation, ImageGenerationLatePublicationEvidenceV1,
            ImageGenerationLatePublicationState, RequestImageGenerationCancellation,
        };
        let temporary = tempfile::TempDir::new().unwrap();
        let output_path = temporary.path().join("output");
        std::fs::create_dir(&output_path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&output_path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let output = open_image_generation_output_directory(
            &output_path,
            4,
            "generated".into(),
            "png".into(),
        )
        .unwrap();
        let fixture = setup_real_ledger_scheduler_job_with_output(
            cockpit_db::Db::open_in_memory().unwrap(),
            suffix,
            Some(output.authority().clone()),
        )
        .await;
        assert!(
            !fixture.spend_reservation_id.is_empty() && !fixture.media_reservation_id.is_empty()
        );
        let dispatcher = ImageGenerationDispatcher::new(fixture.db.clone());
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted-late".to_vec(),
            },
        ]);
        let pass = dispatcher
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 1, "{pass:#?}");
        let request = adapter.requests().into_iter().next().unwrap();
        let job_id = fixture.job_id;
        let slot_id = fixture.slot_id;
        fixture.db.transaction(move|conn|{
            cockpit_db::Db::begin_image_generation_download_conn(conn,&BeginImageGenerationDownload{job_id,slot_id,attempt_number:1,expected_job_version:5,expected_slot_version:4,expected_attempt_version:5,at_unix_ms:3})?;
            cockpit_db::Db::adopt_image_generation_response_conn(conn,&AdoptImageGenerationResponse{job_id,slot_id,attempt_number:1,expected_attempt_version:6,expected_slot_version:5,external_operation_id:request.external_operation_id,expected_journal_version:3,response_digest:&"a".repeat(64),now_unix_ms:4})?;
            cockpit_db::Db::request_image_generation_cancellation_conn(conn,&RequestImageGenerationCancellation{job_id,cancellation_version:1,request_operation_id:"cancel:late",requested_at_unix_ms:5})?;
            let state=cockpit_db::Db::commit_image_generation_validation_conn(conn,&CommitImageGenerationValidation{job_id,slot_id,expected_slot_version:7,at_unix_ms:6})?;
            assert_eq!(state,cockpit_db::db::image_generation::ImageGenerationSlotState::LateQuarantined);
            let persisted:(String,String)=conn.query_row("SELECT s.state,j.state FROM image_generation_slots s JOIN image_generation_jobs j USING(job_id) WHERE s.job_id=?1 AND s.slot_id=?2",rusqlite::params![job_id.to_string(),slot_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
            assert_eq!(persisted,("late_quarantined".into(),"completed_after_cancel".into()));
            Ok(())
        }).await.unwrap();
        let managed = temporary.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let root = open_image_generation_artifact_root(&managed).unwrap();
        let artifact_id = fixture.artifact_id;
        let component_id = Uuid::now_v7();
        let release_operation_id = Uuid::now_v7();
        let resource = fixture.media_reservation_id.clone();
        let component_evidence = fixture.db.write(move|conn|{
            let evidence=retain_generated_image_artifact(conn,&root,&RetainGeneratedImageArtifact{artifact_id,job_id,slot_id,component_id,format:GeneratedImageArtifactFormat::Svg,expected_width:1,expected_height:1,bytes:br#"<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1"><path d="M0 0h1v1z"/></svg>"#,resource_reservation_id:resource,release_operation_id,late_quarantined:true,now_unix_ms:7})?;
            let state:String=conn.query_row("SELECT state FROM image_generation_artifacts WHERE artifact_id=?1",[artifact_id.to_string()],|row|row.get(0))?;
            assert_eq!(state,"late_quarantined");
            let ordinary:i64=conn.query_row("SELECT count(*) FROM image_generation_artifact_authorization_facts WHERE artifact_id=?1",[artifact_id.to_string()],|row|row.get(0))?;
            assert_eq!(ordinary,0);
            Ok(evidence)
        }).await.unwrap();
        let component = CreateImageGenerationArtifactComponent {
            component_id,
            kind: ImageGenerationArtifactComponentKind::Primary,
            relative_storage_key: format!("{artifact_id}-{component_id}.artifact"),
            byte_length: component_evidence.byte_length(),
            sha256: component_evidence.sha256().into(),
            resource_reservation_id: fixture.media_reservation_id.clone(),
            release_operation_id,
        };
        let component_set_digest =
            image_generation_component_set_binding(std::slice::from_ref(&component))
                .unwrap()
                .1;
        let components = vec![RecoverImageArtifactComponentIdentity {
            component_id,
            kind: ImageGenerationArtifactComponentKind::Primary,
            generation: 3,
            stable_identity_digest: component_evidence.identity_digest().into(),
            security_digest: component_evidence.security_digest().into(),
            sha256: component_evidence.sha256().into(),
        }];

        let publication_operation_id = Uuid::now_v7();
        let worker_boot_id = Uuid::now_v7();
        let owner_session_id = fixture.owner_session_id;
        let mut publication_temporary = output
            .create_temporary_exclusive(".generated-late.partial")
            .unwrap();
        use std::io::Write as _;
        publication_temporary
            .file_mut()
            .write_all(b"late publication bytes")
            .unwrap();
        let publication_temporary = output.seal_temporary(publication_temporary).unwrap();
        let prepared = ImageGenerationLatePublicationEvidenceV1::TemporaryPrepared {
            schema_version: 1,
            identity_digest: publication_temporary.evidence().identity_digest().into(),
            security_digest: publication_temporary.evidence().security_digest().into(),
            byte_length: publication_temporary.evidence().byte_length().to_string(),
            sha256: publication_temporary.evidence().sha256().into(),
        }
        .canonical_json()
        .unwrap();
        let output = fixture
            .db
            .write(move |conn| {
                let owner = ImageGenerationOwnerContextAuthority::from_attached_session(
                    conn,
                    owner_session_id,
                    &ClientPrincipal::Owner,
                    7,
                )?;
                let authority = owner.authorize_late_publication(
                    conn,
                    &output,
                    artifact_id,
                    "generated-late.png",
                    ".generated-late.partial",
                    8,
                )?;
                assert!(authority.reserve(conn, publication_operation_id)?);
                cockpit_db::Db::claim_image_generation_late_publication_conn(
                    conn,
                    &ClaimImageGenerationLatePublication {
                        publication_operation_id,
                        expected_version: 1,
                        worker_boot_id,
                        claim_generation: 1,
                    },
                )?;
                cockpit_db::Db::advance_image_generation_late_publication_conn(
                    conn,
                    &AdvanceImageGenerationLatePublication {
                        publication_operation_id,
                        expected_version: 2,
                        worker_boot_id,
                        claim_generation: 1,
                        from: ImageGenerationLatePublicationState::Reserved,
                        to: ImageGenerationLatePublicationState::CopyAuthorized,
                        evidence_json: &prepared,
                    },
                )?;
                Ok(output)
            })
            .await
            .unwrap();
        output.force_next_directory_sync_failure();
        let HeldDirectoryEffectOutcome::AppliedUnknown(recovery) = output
            .publish_temporary_noreplace(publication_temporary, "generated-late.png")
            .unwrap()
        else {
            panic!("post-effect sync cut did not yield restart recovery")
        };
        LatePublicationRecoveryFixture {
            _temporary: temporary,
            db: fixture.db,
            output,
            output_path,
            owner_session_id,
            job_id,
            slot_id,
            slot_generation: 8,
            artifact_id,
            artifact_generation: 3,
            component_set_digest,
            components,
            publication_operation_id,
            worker_boot_id,
            publication_recovery: recovery,
        }
    }

    async fn consume_late_publication_fixture_as_adoption(fixture: LatePublicationRecoveryFixture) {
        let LatePublicationRecoveryFixture {
            db,
            output,
            output_path,
            owner_session_id,
            job_id,
            slot_id,
            slot_generation,
            artifact_id,
            artifact_generation,
            component_set_digest,
            components,
            publication_operation_id,
            worker_boot_id,
            publication_recovery,
            ..
        } = fixture;
        db.write(move |conn| {
            let owner = ImageGenerationOwnerContextAuthority::from_attached_session(
                conn,
                owner_session_id,
                &ClientPrincipal::Owner,
                7,
            )?;
            adopt_verified_copy_authorized_publication(
                conn,
                &owner,
                &output,
                &AdoptVerifiedCopyAuthorizedPublication {
                    publication_operation_id,
                    expected_lease_version: 3,
                    worker_boot_id,
                    claim_generation: 1,
                    recovery: &publication_recovery,
                },
            )?;
            cockpit_db::Db::finalize_image_generation_late_publication_conn(
                conn,
                publication_operation_id,
                4,
            )?;
            let states: (String, String, String) = conn.query_row(
                "SELECT p.state,a.state,s.state FROM image_generation_late_publication_leases p JOIN image_generation_artifacts a ON a.artifact_id=p.artifact_id JOIN image_generation_slots s ON s.job_id=p.job_id AND s.slot_id=p.slot_id WHERE p.publication_operation_id=?1",
                [publication_operation_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(states, ("published".into(), "retained".into(), "published".into()));
            assert!(block_verified_copy_authorized_publication(
                conn,
                &output,
                &AdoptVerifiedCopyAuthorizedPublication {
                    publication_operation_id,
                    expected_lease_version: 5,
                    worker_boot_id,
                    claim_generation: 1,
                    recovery: &publication_recovery,
                },
            )
            .is_err());
            assert!(owner
                .record_image_artifact_security_recovery(
                    conn,
                    &ClientPrincipal::Owner,
                    &RecordImageArtifactSecurityRecovery {
                        operation_id: Uuid::now_v7(),
                        artifact_id,
                        artifact_generation: artifact_generation + 1,
                        job_id,
                        slot_id,
                        slot_generation: slot_generation + 1,
                        component_set_digest,
                        components,
                        publication_operation_id: Some(publication_operation_id),
                        publication_lease_version: Some(5),
                        output_identity_digest: Some(
                            publication_recovery.artifact().identity_digest().into(),
                        ),
                        disposition:
                            ImageArtifactSecurityRecoveryDisposition::RemoveVerifiedExternalCopy,
                    },
                )
                .is_err());
            Ok(())
        }).await.unwrap();
        assert_eq!(
            std::fs::read(output_path.join("generated-late.png")).unwrap(),
            b"late publication bytes"
        );
    }

    #[tokio::test]
    async fn accepted_result_cancelled_during_validation_is_late_quarantined() {
        let fixture = setup_accepted_late_publication_recovery_fixture("late-result").await;
        consume_late_publication_fixture_as_adoption(fixture).await;
    }

    #[tokio::test]
    async fn owner_removal_recovers_post_unlink_sync_cut_after_restart() {
        use cockpit_db::db::image_generation::{
            ImageGenerationLatePublicationReplay, ImageGenerationLatePublicationState,
        };

        let fixture =
            setup_accepted_late_publication_recovery_fixture("late-delete-recovery").await;
        let output_evidence = fixture
            .db
            .write({
                let publication_recovery = fixture.publication_recovery.clone();
                let publication_operation_id = fixture.publication_operation_id;
                let worker_boot_id = fixture.worker_boot_id;
                let output = fixture.output;
                move |conn| {
                    let evidence = block_verified_copy_authorized_publication(
                        conn,
                        &output,
                        &AdoptVerifiedCopyAuthorizedPublication {
                            publication_operation_id,
                            expected_lease_version: 3,
                            worker_boot_id,
                            claim_generation: 1,
                            recovery: &publication_recovery,
                        },
                    )?;
                    Ok((output, evidence))
                }
            })
            .await
            .unwrap();
        let (output, output_evidence) = output_evidence;
        let recovery_operation_id = Uuid::now_v7();
        let request = RecordImageArtifactSecurityRecovery {
            operation_id: recovery_operation_id,
            artifact_id: fixture.artifact_id,
            artifact_generation: fixture.artifact_generation,
            job_id: fixture.job_id,
            slot_id: fixture.slot_id,
            slot_generation: fixture.slot_generation,
            component_set_digest: fixture.component_set_digest.clone(),
            components: fixture.components.clone(),
            publication_operation_id: Some(fixture.publication_operation_id),
            publication_lease_version: Some(4),
            output_identity_digest: Some(output_evidence.identity_digest().into()),
            disposition: ImageArtifactSecurityRecoveryDisposition::RemoveVerifiedExternalCopy,
        };
        let owner_session_id = fixture.owner_session_id;
        let recorded = fixture
            .db
            .write({
                let request = request.clone();
                move |conn| {
                    let owner = ImageGenerationOwnerContextAuthority::from_attached_session(
                        conn,
                        owner_session_id,
                        &ClientPrincipal::Owner,
                        7,
                    )?;
                    owner.record_image_artifact_security_recovery(
                        conn,
                        &ClientPrincipal::Owner,
                        &request,
                    )
                }
            })
            .await
            .unwrap();
        let publication_recovery = fixture.publication_recovery.clone();
        let removal = fixture
            .db
            .write(move |conn| {
                let owner = ImageGenerationOwnerContextAuthority::from_attached_session(
                    conn,
                    owner_session_id,
                    &ClientPrincipal::Owner,
                    7,
                )?;
                output.force_next_directory_sync_failure();
                owner.remove_verified_external_copy(conn, recorded, &output, &publication_recovery)
            })
            .await
            .unwrap();
        let VerifiedExternalCopyRemovalOutcome::RecoveryRequired(delete_recovery) = removal else {
            panic!("post-unlink sync cut did not require restart recovery")
        };
        let publication_operation_id = fixture.publication_operation_id;
        fixture
            .db
            .read(move |conn| {
                let state: (String, bool, bool, Option<i64>) = conn.query_row(
                    "SELECT state,output_evidence_json IS NOT NULL,recovery_evidence_json IS NOT NULL,decided_at_unix_ms FROM image_generation_late_publication_leases WHERE publication_operation_id=?1",
                    [publication_operation_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )?;
                anyhow::ensure!(
                    state == ("delete_authorized".into(), true, true, None),
                    "deletion authority was not durable before the filesystem effect"
                );
                Ok(())
            })
            .await
            .unwrap();

        let reopened = open_image_generation_output_directory(
            &fixture.output_path,
            4,
            "generated".into(),
            "png".into(),
        )
        .unwrap();
        let replay_recorded = fixture
            .db
            .write({
                let request = request.clone();
                move |conn| {
                    let owner = ImageGenerationOwnerContextAuthority::from_attached_session(
                        conn,
                        owner_session_id,
                        &ClientPrincipal::Owner,
                        7,
                    )?;
                    owner.record_image_artifact_security_recovery(
                        conn,
                        &ClientPrincipal::Owner,
                        &request,
                    )
                }
            })
            .await
            .unwrap();
        fixture
            .db
            .write(move |conn| {
                let owner = ImageGenerationOwnerContextAuthority::from_attached_session(
                    conn,
                    owner_session_id,
                    &ClientPrincipal::Owner,
                    7,
                )?;
                let outcome = owner.reconcile_verified_external_copy_removal(
                    conn,
                    replay_recorded,
                    &reopened,
                    &delete_recovery,
                )?;
                anyhow::ensure!(
                    matches!(outcome, VerifiedExternalCopyRemovalOutcome::RemovedDurably),
                    "exact-absence reconciliation did not close deletion"
                );
                anyhow::ensure!(matches!(
                    owner.replay_image_artifact_security_recovery_outcome(
                        conn,
                        recovery_operation_id
                    )?,
                    ImageArtifactSecurityRecoveryReplay::Applied { .. }
                ));
                anyhow::ensure!(matches!(
                    cockpit_db::Db::replay_image_generation_late_publication_conn(
                        conn,
                        publication_operation_id
                    )?,
                    ImageGenerationLatePublicationReplay::Terminal {
                        state: ImageGenerationLatePublicationState::Aborted,
                        ..
                    }
                ));
                let closed = owner.record_image_artifact_security_recovery(
                    conn,
                    &ClientPrincipal::Owner,
                    &request,
                )?;
                anyhow::ensure!(
                    owner
                        .reconcile_verified_external_copy_removal(
                            conn,
                            closed,
                            &reopened,
                            &delete_recovery,
                        )
                        .is_err(),
                    "terminal external-copy removal replay reopened deletion"
                );
                Ok(())
            })
            .await
            .unwrap();
        assert!(!fixture.output_path.join("generated-late.png").exists());
    }

    #[tokio::test]
    async fn scheduler_skips_stolen_first_claim_without_head_of_line_blocking() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let first = setup_real_ledger_scheduler_job(db.clone(), "stolen-first").await;
        let second = setup_real_ledger_scheduler_job(db.clone(), "dispatch-second").await;
        let stolen_boot = Uuid::now_v7();
        db.transaction(move |conn| {
            cockpit_db::Db::claim_image_generation_dispatch_conn(
                conn,
                &cockpit_db::db::image_generation::ClaimImageGenerationDispatch {
                    job_id: first.job_id,
                    slot_id: first.slot_id,
                    attempt_number: 1,
                    worker_boot_id: stolen_boot,
                    claim_generation: 1,
                },
            )
        })
        .await
        .unwrap();
        let dispatcher = ImageGenerationDispatcher::new(db);
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted-second".to_vec(),
            },
        ]);
        let pass = dispatcher
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 1, "{pass:#?}");
        let requests = adapter.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].job_id, second.job_id);
        let replay = dispatcher
            .run_scheduler_pass(&adapter, Uuid::now_v7(), 100, 3, 3, 8)
            .await
            .unwrap();
        assert_eq!(replay.dispatched, 0, "{replay:#?}");
        assert_eq!(adapter.requests().len(), 1);
    }

    #[test]
    fn owner_recovery_authority_rejects_every_remote_write_mode() {
        use crate::daemon::principal::{PrincipalGrant, PrincipalScope, RemotePrincipal};
        for scope in [
            PrincipalScope::Agent,
            PrincipalScope::AgentReadonly,
            PrincipalScope::ProjectFiles,
            PrincipalScope::Terminal,
        ] {
            let remote = ClientPrincipal::Remote(RemotePrincipal {
                user_id: format!("remote-{scope:?}"),
                grants: vec![PrincipalGrant {
                    scope,
                    project_root: Some("/project".into()),
                }],
            });
            assert!(DaemonLocalOwnerRecoveryAuthority::from_local_direct(&remote).is_err());
        }
        assert!(
            DaemonLocalOwnerRecoveryAuthority::from_local_direct(&ClientPrincipal::Owner).is_ok()
        );
    }

    #[test]
    fn recovery_attempt_digest_binds_every_authority_identity() {
        let component = RecoverImageArtifactComponentIdentity {
            component_id: id(91),
            kind: ImageGenerationArtifactComponentKind::Primary,
            generation: 3,
            stable_identity_digest: digest('a'),
            security_digest: digest('d'),
            sha256: digest('e'),
        };
        let original = RecordImageArtifactSecurityRecovery {
            operation_id: id(90),
            artifact_id: id(92),
            artifact_generation: 4,
            job_id: id(93),
            slot_id: id(94),
            slot_generation: 5,
            component_set_digest: digest('b'),
            components: vec![component],
            publication_operation_id: Some(id(95)),
            publication_lease_version: Some(6),
            output_identity_digest: Some(digest('c')),
            disposition: ImageArtifactSecurityRecoveryDisposition::RemoveVerifiedExternalCopy,
        };
        let expected = security_recovery_request_digest(&original).unwrap();
        let mutations: Vec<Box<dyn Fn(&mut RecordImageArtifactSecurityRecovery)>> = vec![
            Box::new(|v| v.operation_id = id(190)),
            Box::new(|v| v.artifact_id = id(191)),
            Box::new(|v| v.artifact_generation += 1),
            Box::new(|v| v.job_id = id(192)),
            Box::new(|v| v.slot_id = id(193)),
            Box::new(|v| v.slot_generation += 1),
            Box::new(|v| v.component_set_digest = digest('d')),
            Box::new(|v| v.components[0].component_id = id(194)),
            Box::new(|v| v.components[0].kind = ImageGenerationArtifactComponentKind::Thumbnail),
            Box::new(|v| v.components[0].generation += 1),
            Box::new(|v| v.components[0].stable_identity_digest = digest('e')),
            Box::new(|v| v.components[0].security_digest = digest('f')),
            Box::new(|v| v.components[0].sha256 = digest('0')),
            Box::new(|v| v.publication_operation_id = Some(id(195))),
            Box::new(|v| v.publication_lease_version = Some(7)),
            Box::new(|v| v.output_identity_digest = Some(digest('f'))),
            Box::new(|v| {
                v.disposition =
                    ImageArtifactSecurityRecoveryDisposition::CompleteVerifiedLatePublication
            }),
        ];
        for mutate in mutations {
            let mut changed = original.clone();
            mutate(&mut changed);
            assert_ne!(
                security_recovery_request_digest(&changed).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn artifact_route_authority_pairs_are_closed() {
        use ImageGenerationArtifactConsumerPurpose as P;
        use ImageGenerationArtifactConsumerRoute as R;
        let allowed = [
            (P::ServeArtifact, R::ArtifactFull),
            (P::ServeArtifact, R::ArtifactRange),
            (P::ServeThumbnail, R::Thumbnail),
            (P::ToolInput, R::Tool),
            (P::ModelInput, R::ModelPayload),
            (P::InternalVerification, R::Verification),
            (P::InternalCleanup, R::Cleanup),
        ];
        for &purpose in P::ALL {
            for &route in R::ALL {
                assert_eq!(
                    route_authority_pair_valid(purpose, route),
                    allowed.contains(&(purpose, route))
                );
            }
        }
    }

    type ResolverCase = (
        &'static str,
        Box<dyn Fn(&mut ImageGenerationRequestV1, &mut ImageGenerationResolutionAuthorityV1)>,
    );
    type AuthorityCase = (
        &'static str,
        Box<dyn Fn(&mut ImageGenerationResolutionAuthorityV1)>,
    );

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
                    vector_sanitizer: None,
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

    fn resolver_fixture() -> (
        ImageGenerationRequestV1,
        ImageGenerationResolutionAuthorityV1,
    ) {
        let sealed = plan();
        let target = &sealed.targets[0];
        (
            ImageGenerationRequestV1 {
                width: target.requested.width,
                height: target.requested.height,
                format: target.requested.format.clone(),
                samples_per_target: 1,
                target_ids: vec![target.target_id.clone()],
                parameters: target.typed_parameters.clone(),
                reference_attachment_ids: vec![],
            },
            ImageGenerationResolutionAuthorityV1 {
                job_id: sealed.job_id,
                owner: ImageGenerationOwnerContextAuthority {
                    session_id: sealed.owner_session_id,
                    project_id: "fixture-project".into(),
                    principal_digest: sealed.owner_principal_digest,
                    project_identity_digest: sealed.project_identity_digest,
                    config_generation: sealed.config_generation,
                },
                enqueue_started_monotonic_ms: sealed.enqueue_started_monotonic_ms,
                operation_deadline_monotonic_ms: sealed.operation_deadline_monotonic_ms,
                required_grants: sealed.required_grants,
                central_resources: sealed.central_resources,
                spend: sealed.spend,
                output_authority: VerifiedOutputDirectoryAuthority(sealed.output_authority),
                targets: vec![ImageGenerationTargetResolutionAuthorityV1 {
                    runtime: RuntimeTargetAuthorityV1 {
                        target_id: target.target_id.clone(),
                        target_config_generation: target.target_config_generation,
                        normalized_config_digest: target.normalized_config_digest.clone(),
                        capability_provenance: target.capability_provenance.clone(),
                        destination: target.destination.clone(),
                        supported_formats: BTreeMap::from([("png".into(), "image/png".into())]),
                        maximum_width: 512,
                        maximum_height: 512,
                        allowed_parameters: BTreeMap::from([("quality".into(), "integer".into())]),
                        max_attempts: 1,
                        required_grant: "image_generation".into(),
                    },
                    references: target.reference_artifacts.clone(),
                    slot_artifact_ids: vec![(
                        target.slots[0].slot_id,
                        target.slots[0].managed_artifact_id,
                    )],
                    max_attempts: 1,
                    attempt_resources: target.slots[0].attempts[0].resource_maximum.clone(),
                    attempt_maximum_usd_micros: vec![Some(10)],
                    spend_attempt_identities: vec!["idem:1".into()],
                }],
            },
        )
    }

    fn image_row_count(db: &cockpit_db::Db) -> i64 {
        db.blocking_for_sync_cli(|conn| {
            conn.query_row("SELECT COUNT(*) FROM image_generation_jobs", [], |row| {
                row.get(0)
            })
            .map_err(Into::into)
        })
        .unwrap()
    }

    #[test]
    fn resolver_is_deterministic_pure_and_returns_structured_incompatibilities() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let before = image_row_count(&db);
        let (request, authority) = resolver_fixture();
        let first = resolve_image_generation(request.clone(), authority.clone()).unwrap();
        let second = resolve_image_generation(request.clone(), authority.clone()).unwrap();
        let (ImageGenerationResolutionV1::Ready(first), ImageGenerationResolutionV1::Ready(second)) =
            (first, second)
        else {
            panic!("compatible authority did not resolve")
        };
        assert_eq!(first, second);
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        assert_eq!(image_row_count(&db), before);

        let cases: Vec<ResolverCase> = vec![
            (
                "target",
                Box::new(|request, _| request.target_ids[0] = "missing".into()),
            ),
            (
                "format",
                Box::new(|request, _| request.format = "webp".into()),
            ),
            ("width", Box::new(|request, _| request.width = 513)),
            ("height", Box::new(|request, _| request.height = 513)),
            (
                "parameter",
                Box::new(|request, _| {
                    request
                        .parameters
                        .insert("unsealed".into(), TypedParameterV1::Boolean(true));
                }),
            ),
            (
                "samples",
                Box::new(|request, _| request.samples_per_target = 2),
            ),
        ];
        for (family, mutate) in cases {
            let (mut request, mut authority) = resolver_fixture();
            mutate(&mut request, &mut authority);
            let ImageGenerationResolutionV1::Incompatible(alternatives) =
                resolve_image_generation(request, authority).unwrap()
            else {
                panic!("{family} mismatch was accepted")
            };
            assert_eq!(alternatives.len(), 1, "{family}");
            assert!(!alternatives[0].reason.is_empty(), "{family}");
            assert_eq!(image_row_count(&db), before, "{family}");
        }
    }

    #[test]
    fn resolver_rejects_invalid_sealed_authority_before_persistence() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let before = image_row_count(&db);
        let mutations: Vec<AuthorityCase> = vec![
            (
                "reference",
                Box::new(|a| {
                    a.targets[0].references.push(ReferenceArtifactV1 {
                        attachment_id: id(10),
                        attachment_version: 0,
                        component_id: id(11),
                        component_generation: 1,
                        media_kind: "image".into(),
                        identity_digest: digest('b'),
                        sha256: digest('c'),
                        byte_length: 1,
                    })
                }),
            ),
            ("grant", Box::new(|a| a.required_grants[0].generation = 0)),
            ("resource", Box::new(|a| a.central_resources[0].units += 1)),
            ("spend", Box::new(|a| a.spend.maximum_usd_micros = Some(11))),
            (
                "slot identity",
                Box::new(|a| a.targets[0].slot_artifact_ids[0].0 = Uuid::nil()),
            ),
        ];
        for (family, mutate) in mutations {
            let (request, mut authority) = resolver_fixture();
            mutate(&mut authority);
            assert!(
                resolve_image_generation(request, authority).is_err(),
                "{family}"
            );
            assert_eq!(image_row_count(&db), before, "{family}");
        }
    }

    #[test]
    fn resolver_source_has_no_adapter_or_network_contact_seam() {
        let source = include_str!("image_generation_job.rs");
        let start = source.find("pub fn resolve_image_generation(").unwrap();
        let end = source[start..]
            .find("\nimpl RuntimeTargetAuthorityV1")
            .unwrap()
            + start;
        let body = &source[start..end];
        for forbidden in [
            "adapter.generate",
            "reqwest",
            "TcpStream",
            "create_image_generation",
        ] {
            assert!(
                !body.contains(forbidden),
                "resolver acquired side-effect seam: {forbidden}"
            );
        }
    }

    #[test]
    fn owner_context_hides_missing_and_invalid_authority() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let principal = ClientPrincipal::owner();
            let missing = ImageGenerationOwnerContextAuthority::from_attached_session(
                conn,
                id(90),
                &principal,
                1,
            )
            .unwrap_err()
            .to_string();
            let invalid = ImageGenerationOwnerContextAuthority::from_attached_session(
                conn,
                id(90),
                &principal,
                0,
            )
            .unwrap_err()
            .to_string();
            assert_eq!(missing, "image generation unavailable");
            assert_eq!(invalid, missing);
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn canonical_plan_is_stable_and_every_authority_family_changes_digest() {
        let original = plan();
        let bytes = original.canonical_bytes().unwrap();
        assert_eq!(bytes, original.canonical_bytes().unwrap());
        let baseline = original.digest().unwrap();
        assert_eq!(
            baseline,
            "d58c8a7a1a22f1709bbafeef63e935f19d89fd1bea0ffccf4da50cb8713710ce"
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

    #[cfg(unix)]
    #[test]
    fn managed_artifact_root_writes_reopens_and_rejects_mutation() {
        use std::io::{Read as _, Seek as _, Write as _};
        use std::os::unix::fs::PermissionsExt;
        let temporary = tempfile::TempDir::new().unwrap();
        let root = temporary.path().join("managed");
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let held = open_image_generation_artifact_root(&root).unwrap();
        let mut staged = held.create_component_temporary("component.tmp").unwrap();
        staged.file_mut().write_all(b"canonical-image").unwrap();
        let sealed = held.seal_component(staged).unwrap();
        let retained = held
            .retain_component_noreplace(sealed, "component.bin")
            .unwrap();
        let HeldDirectoryEffectOutcome::AppliedDurable(effect) = retained else {
            panic!("retention was not durable")
        };
        let evidence = effect.artifact().clone();
        let mut reopened = held
            .open_verified_component("component.bin", &evidence)
            .unwrap();
        let mut bytes = Vec::new();
        reopened.file_mut().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"canonical-image");
        reopened.file_mut().rewind().unwrap();
        assert!(matches!(
            held.remove_verified_component(reopened).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));

        let mut staged = held.create_component_temporary("mutated.tmp").unwrap();
        staged.file_mut().write_all(b"trusted").unwrap();
        let sealed = held.seal_component(staged).unwrap();
        let evidence = sealed.evidence().clone();
        assert!(matches!(
            held.retain_component_noreplace(sealed, "mutated.bin")
                .unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
        std::fs::write(root.join("mutated.bin"), b"changed").unwrap();
        assert!(
            held.open_verified_component("mutated.bin", &evidence)
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
