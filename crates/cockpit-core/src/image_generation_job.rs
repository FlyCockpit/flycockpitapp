//! Immutable provider-neutral image-generation preflight plans.
//!
//! The planner emits this closed DTO only after resolving every target and
//! output slot. Its canonical bytes are the authorization, queue, spend, and
//! provider-dispatch binding; no dispatcher may reinterpret caller input.

use std::collections::{BTreeMap, HashMap};
use std::future::Future;
use std::io::{Read as _, Seek as _, SeekFrom, Write};
use std::path::Path;
use std::pin::Pin;

use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::daemon::principal::ClientPrincipal;
use crate::image_generation_runtime::{
    CredentialIdentityDigest, DispatchProofBinding, ImageHealthSnapshot, ImageRuntimeRegistry,
    RuntimeError, RuntimeErrorCode,
};
use cockpit_config::config::image_generation::{ImageAdapterKind, ImageEndpoint};
use cockpit_config::config::media_budget::{MediaReservationPlan, MediaResourcePolicy};
use cockpit_db::db::external_journal::{
    ExternalJournalDigest, ExternalJournalToken, PrepareExternalOperation, ProviderIdempotency,
};
use cockpit_db::db::image_generation::{
    AcquireImageGenerationArtifactLease, AcquiredImageGenerationArtifactLease,
    AdvanceImageGenerationLatePublication, BeginImageGenerationArtifactComponentWrite,
    BeginImageGenerationArtifactWrite, BlockVerifiedImageGenerationLatePublication,
    CommitImageGenerationArtifactComponentReady, CommitImageGenerationArtifactRetention,
    CommitImageGenerationSecurityCleanup, CommitImageGenerationSecurityPublication,
    CreateImageGenerationArtifact, CreateImageGenerationArtifactComponent,
    DispatchingImageGenerationAttempt, ImageGenerationArtifactComponentKind,
    ImageGenerationArtifactConsumerPurpose, ImageGenerationArtifactConsumerRoute,
    ImageGenerationDispatchCandidate, ImageGenerationHandoffFinishDisposition,
    ImageGenerationLatePublicationEvidenceV1, ImageGenerationLatePublicationState,
    PreparedImageGenerationDispatch, RecoverImageGenerationArtifactComponent,
    ReserveImageGenerationLatePublication, image_generation_attempt_media_reservation_id,
    image_generation_component_set_binding,
};
use cockpit_db::db::sealed_scope::SealedActionGrantRow;
use cockpit_db::image_spend::{AttemptMaximum, ImageSpendDispatchEvidence, SpendReservation};
use cockpit_db::image_spend::{ProjectKey, SessionId, SpendScopeKeys};
use cockpit_db::media_attachments::{
    AcquireMediaComponentLeaseInput, AcquireMediaReferenceInput, AcquiredMediaComponentLease,
    MediaComponentLeaseKind, MediaReferenceConsumerKind,
};

use crate::media_reservation::{
    LedgerError, MediaExternalHandoffOutcome, MediaOwner, MediaReservationLedger,
    ReservationReceipt, ReservationState, ReserveRequest, definitive_rejection_retry_conn,
    finish_external_handoff_conn, handoff_external_conn,
};

pub use cockpit_db::image_generation_plan::{
    AttemptPlanV1, CapabilityProvenanceV1, GrantRequirementV1, ImageGenerationPlanV1,
    MAX_IMAGE_GENERATION_ATTEMPTS_PER_SLOT, MAX_IMAGE_GENERATION_DIMENSION,
    MAX_IMAGE_GENERATION_SLOTS, MAX_IMAGE_GENERATION_TARGETS, OutputDirectoryAuthorityV1,
    OutputSlotPlanV1, ReferenceArtifactV1, RequestedOutputV1, ResolvedOutputV1,
    ResourceReservationV1, SealedImageGenerationPromptV1, SpendReservationPlanV1,
    TargetDestinationV1, TargetPlanV1, TypedParameterV1, VectorSanitizerProvenanceV1,
};
use cockpit_host::private_fs::held_directory::{
    HeldArtifactEvidence, HeldDirectoryEffectOutcome, HeldDirectoryRecovery, HeldSealOutcome,
    HeldSealedArtifact, HeldTemporaryArtifact,
};

const MAX_AUTHORITY_STRING_BYTES: usize = 1_024;
const MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_IMAGE_MEDIA_PLAN_SNAPSHOT_BYTES: usize = 64 * 1024;
#[cfg(all(test, feature = "extended"))]
static FORCE_ACCEPTED_RESPONSE_POST_RENAME_CUT: std::sync::LazyLock<
    std::sync::Mutex<std::collections::BTreeSet<Uuid>>,
> = std::sync::LazyLock::new(Default::default);

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

pub(crate) mod image_generation_adapter_sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationHandoffRequest {
    pub job_id: Uuid,
    /// Durable owner of the plan. Provider adapters use this only to select the
    /// live session-owned configuration authority; it is never provider data.
    pub owner_session_id: Uuid,
    /// The exact configured target containing `slot_id`. One adapter kind may
    /// have several targets with different endpoint credentials, so this is
    /// part of the dispatch routing identity.
    pub target_id: String,
    /// Generation observed by the scheduler's live revalidation and sealed in
    /// the prepared attempt. The owner router checks this under the same gate
    /// as adapter selection so a reload cannot swap in a different adapter
    /// between proof and provider handoff.
    pub dispatch_config_generation: u64,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub external_operation_id: Uuid,
    /// Injected worker wall clock used for short-lived reference leases.
    pub now_unix_ms: i64,
    pub provider_request_identity: String,
    pub provider_idempotency_identity: String,
    /// Protected payload read only from the sealed immutable plan immediately
    /// before provider handoff. Its digest is part of the plan digest and it is
    /// never included in status, audit, or scheduler evidence.
    pub sealed_prompt: SealedImageGenerationPromptV1,
}

/// Immutable target material recovered by a daemon-owned provider plan source.
/// The database remains the authority for the plan; callers must additionally
/// bind this result to the live session configuration before constructing a
/// credential-bearing transport.
#[derive(Debug, Clone)]
pub(crate) struct ResolvedImageGenerationHandoffTarget {
    pub target: TargetPlanV1,
}

pub(crate) async fn resolve_image_generation_handoff_target(
    db: &cockpit_db::Db,
    request: &ImageGenerationHandoffRequest,
) -> Result<ResolvedImageGenerationHandoffTarget> {
    let job_id = request.job_id;
    let owner_session_id = request.owner_session_id;
    let target_id = request.target_id.clone();
    let slot_id = request.slot_id;
    db.read(move |conn| {
        let (canonical, digest): (Vec<u8>, String) = conn.query_row(
            "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
            [job_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let plan = ImageGenerationPlanV1::from_canonical(&canonical, &digest)?;
        ensure!(
            plan.owner_session_id == owner_session_id,
            "image generation handoff owner differs from immutable plan"
        );
        let target = plan
            .targets
            .into_iter()
            .find(|target| target.target_id == target_id)
            .context("image generation handoff target is absent from immutable plan")?;
        ensure!(
            target.slots.iter().any(|slot| slot.slot_id == slot_id),
            "image generation handoff slot is outside its target"
        );
        Ok(ResolvedImageGenerationHandoffTarget { target })
    })
    .await
}

/// Read every sealed input component through the media ledger's verified,
/// short-lived Model lease. The query proves that the current ready component
/// still equals the sealed attachment/component identity before the storage
/// primitive opens it; a changed, removed, or unavailable attachment fails
/// closed before a provider request is encoded.
pub(crate) async fn read_image_generation_handoff_references(
    db: &cockpit_db::Db,
    storage: &crate::media_storage::MediaStorageRecovery,
    target: &TargetPlanV1,
    now_unix_ms: i64,
) -> Result<Vec<(String, Vec<u8>)>> {
    let mut output = Vec::with_capacity(target.reference_artifacts.len());
    for reference in &target.reference_artifacts {
        let attachment_id = reference.attachment_id;
        let component_id = reference.component_id;
        let attachment_version = reference.attachment_version;
        let component_generation = reference.component_generation;
        let identity_digest = reference.identity_digest.clone();
        let checksum = reference.sha256.clone();
        let byte_length = reference.byte_length;
        let (availability_generation, capability_generation, mime): (u64, u64, String) = db
            .read(move |conn| {
                let row: (String, String, String, String, String, String, String) = conn.query_row(
                    "SELECT a.availability_generation,a.captured_capability_generation,a.canonical_mime,c.component_generation,c.stable_identity_digest,c.sha256,c.byte_length FROM media_attachments a JOIN media_attachment_components c ON c.attachment_id=a.attachment_id WHERE a.attachment_id=?1 AND a.attachment_version=?2 AND a.availability='ready' AND c.component_id=?3 AND c.lifecycle_state='ready'",
                    params![attachment_id.to_string(), i64::try_from(attachment_version)?, component_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?, row.get(5)?, row.get(6)?)),
                )?;
                ensure!(
                    row.3.parse::<u64>()? == component_generation
                        && row.4 == identity_digest
                        && row.5 == checksum
                        && row.6.parse::<u64>()? == byte_length,
                    "image generation reference component differs from immutable plan"
                );
                Ok((row.0.parse()?, row.1.parse()?, row.2))
            })
            .await?;
        let lease = storage
            .acquire_component_lease(crate::media_storage::AcquireComponentLeaseInput {
                lease_id: Uuid::now_v7(),
                attachment_id,
                attachment_version,
                availability_generation,
                capability_generation,
                kind: MediaComponentLeaseKind::Model,
                now_unix_ms,
            })
            .await?;
        output.push((mime, lease.read_verified(now_unix_ms).await?));
    }
    Ok(output)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationHandoffResult {
    Accepted {
        evidence: Vec<u8>,
    },
    AcceptedWithOutput {
        evidence: Vec<u8>,
        output: ImageGenerationAcceptedOutput,
    },
    DefinitivelyRejected {
        evidence: Vec<u8>,
    },
    SubmissionUnknown {
        evidence: Vec<u8>,
    },
}

/// Provider result material bound to an accepted paid submission. Immediate
/// bytes are durably retained by the worker before the slot can become
/// published. Deferred operations carry the exact provider operation identity
/// needed for reconciliation and cancellation; it is persisted atomically with
/// the accepted handoff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationAcceptedOutput {
    Immediate {
        bytes: Vec<u8>,
    },
    Deferred {
        provider_operation_id: String,
        /// Provider-specific, non-secret reconciliation authority sealed by
        /// the adapter at acceptance time. This is persisted with the
        /// operation id so later config changes cannot alter output selection.
        reconciliation_context: Vec<u8>,
    },
}

/// Provider-free routing readiness checked before a scheduler claim is
/// consumed. `Deferred` means owner/config/adapter authority is temporarily
/// absent; the queued attempt remains untouched and can be retried later.
/// Destination identity (adapter kind, endpoint identity, credential) is the
/// readiness fence — a later session snapshot whose image destination identity
/// is unchanged is Ready, even when the session-wide generation integer moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationHandoffReadiness {
    Ready,
    Deferred { evidence: Vec<u8> },
}

pub struct ImageGenerationHandoffReadinessRequest<'a> {
    pub owner_session_id: Uuid,
    pub target_id: &'a str,
    /// Sealed plan destination identity. Readiness compares this to the live
    /// target, not to the session-wide config generation integer.
    pub destination: &'a TargetDestinationV1,
}

impl ImageGenerationHandoffResult {
    fn validate(&self) -> Result<()> {
        let evidence = match self {
            Self::Accepted { evidence }
            | Self::AcceptedWithOutput { evidence, .. }
            | Self::DefinitivelyRejected { evidence }
            | Self::SubmissionUnknown { evidence } => evidence,
        };
        ensure!(
            !evidence.is_empty() && evidence.len() <= MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES,
            "image generation handoff evidence is outside its bound"
        );
        if let Self::AcceptedWithOutput { output, .. } = self {
            match output {
                ImageGenerationAcceptedOutput::Immediate { bytes } => ensure!(
                    !bytes.is_empty() && bytes.len() <= 64 * 1024 * 1024,
                    "accepted image output bytes are outside their bound"
                ),
                ImageGenerationAcceptedOutput::Deferred {
                    provider_operation_id,
                    reconciliation_context,
                } => {
                    ensure!(
                        !provider_operation_id.is_empty()
                            && provider_operation_id.len() <= MAX_AUTHORITY_STRING_BYTES
                            && !provider_operation_id.chars().any(char::is_control),
                        "accepted provider operation identity is invalid"
                    );
                    ensure!(
                        !reconciliation_context.is_empty()
                            && reconciliation_context.len() <= 64 * 1024,
                        "accepted provider reconciliation context is invalid"
                    );
                }
            }
        }
        Ok(())
    }

    const fn spend_evidence(&self) -> ImageSpendDispatchEvidence {
        match self {
            Self::Accepted { .. } | Self::AcceptedWithOutput { .. } => {
                ImageSpendDispatchEvidence::Accepted
            }
            Self::DefinitivelyRejected { .. } => ImageSpendDispatchEvidence::DefinitivelyRejected,
            Self::SubmissionUnknown { .. } => ImageSpendDispatchEvidence::SubmissionUnknown,
        }
    }
}

#[async_trait::async_trait]
pub trait ImageGenerationAdapter: image_generation_adapter_sealed::Sealed + Send + Sync {
    fn handoff_readiness(
        &self,
        _request: &ImageGenerationHandoffReadinessRequest<'_>,
    ) -> ImageGenerationHandoffReadiness {
        ImageGenerationHandoffReadiness::Ready
    }

    async fn handoff(
        &self,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult;
    async fn reconcile(
        &self,
        request: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        let _ = request;
        ImageGenerationReconcileResult::OutcomeUnknown {
            evidence: b"reconcile_unavailable".to_vec(),
        }
    }
    async fn cancel(&self, request: &ImageGenerationCancelRequest) -> ImageGenerationCancelResult {
        let _ = request;
        ImageGenerationCancelResult::OutcomeUnknown {
            evidence: b"cancel_unavailable".to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationReconcileRequest {
    pub job_id: Uuid,
    pub owner_session_id: Uuid,
    pub target_id: String,
    pub adapter_kind: ImageAdapterKind,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub external_operation_id: Uuid,
    pub provider_request_identity: String,
    pub provider_idempotency_identity: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationReconcileResult {
    AuthoritativeNonacceptance { evidence: Vec<u8> },
    AuthoritativeAccepted { evidence: Vec<u8> },
    AuthoritativeAcceptedWithOutput { evidence: Vec<u8>, bytes: Vec<u8> },
    AuthoritativeFailure { evidence: Vec<u8> },
    OutcomeUnknown { evidence: Vec<u8> },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationCancelRequest {
    pub job_id: Uuid,
    pub owner_session_id: Uuid,
    pub target_id: String,
    pub adapter_kind: ImageAdapterKind,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub external_operation_id: Uuid,
    pub provider_request_identity: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationCancelResult {
    Cancelled { evidence: Vec<u8> },
    TooLateOrAccepted { evidence: Vec<u8> },
    OutcomeUnknown { evidence: Vec<u8> },
}

mod accepted_response_fetch_sealed {
    pub trait Sealed {}
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedImageResponseFetchRequest {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub provider_request_identity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedImageResponseFetchOutcome {
    Fetched {
        bytes: Vec<u8>,
        evidence: Vec<u8>,
    },
    DefinitiveFailure {
        safe_reason: String,
        evidence: Vec<u8>,
    },
    OutcomeUnknown {
        evidence: Vec<u8>,
    },
}

#[async_trait::async_trait]
pub trait AcceptedImageResponseFetcher:
    accepted_response_fetch_sealed::Sealed + Send + Sync
{
    async fn fetch(
        &self,
        request: &AcceptedImageResponseFetchRequest,
    ) -> AcceptedImageResponseFetchOutcome;
    async fn reconcile(
        &self,
        request: &AcceptedImageResponseFetchRequest,
        prior_evidence: &[u8],
    ) -> AcceptedImageResponseFetchOutcome;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptedImageResponseProgress {
    Retained,
    LateQuarantined,
    DefinitiveFailure,
    OutcomeUnknown,
}

#[cfg(all(test, feature = "extended"))]
pub(crate) struct DeterministicImageGenerationAdapter {
    outcomes: std::sync::Mutex<std::collections::VecDeque<ImageGenerationHandoffResult>>,
    requests: std::sync::Mutex<Vec<ImageGenerationHandoffRequest>>,
    reconciliation_outcomes:
        std::sync::Mutex<std::collections::VecDeque<ImageGenerationReconcileResult>>,
    reconciliation_requests: std::sync::Mutex<Vec<ImageGenerationReconcileRequest>>,
    cancellation_outcomes:
        std::sync::Mutex<std::collections::VecDeque<ImageGenerationCancelResult>>,
    cancellation_requests: std::sync::Mutex<Vec<ImageGenerationCancelRequest>>,
}

#[cfg(all(test, feature = "extended"))]
impl DeterministicImageGenerationAdapter {
    pub(crate) fn new(outcomes: Vec<ImageGenerationHandoffResult>) -> Self {
        Self {
            outcomes: std::sync::Mutex::new(outcomes.into()),
            requests: std::sync::Mutex::new(Vec::new()),
            reconciliation_outcomes: std::sync::Mutex::new(Vec::new().into()),
            reconciliation_requests: std::sync::Mutex::new(Vec::new()),
            cancellation_outcomes: std::sync::Mutex::new(Vec::new().into()),
            cancellation_requests: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn with_recovery(
        reconciliation: Vec<ImageGenerationReconcileResult>,
        cancellation: Vec<ImageGenerationCancelResult>,
    ) -> Self {
        let adapter = Self::new(Vec::new());
        *adapter
            .reconciliation_outcomes
            .lock()
            .expect("fake lock poisoned") = reconciliation.into();
        *adapter
            .cancellation_outcomes
            .lock()
            .expect("fake lock poisoned") = cancellation.into();
        adapter
    }

    pub(crate) fn requests(&self) -> Vec<ImageGenerationHandoffRequest> {
        self.requests.lock().expect("fake lock poisoned").clone()
    }
    pub(crate) fn reconciliation_requests(&self) -> Vec<ImageGenerationReconcileRequest> {
        self.reconciliation_requests
            .lock()
            .expect("fake lock poisoned")
            .clone()
    }
    pub(crate) fn cancellation_requests(&self) -> Vec<ImageGenerationCancelRequest> {
        self.cancellation_requests
            .lock()
            .expect("fake lock poisoned")
            .clone()
    }
}

#[cfg(all(test, feature = "extended"))]
struct ScriptedAcceptedResponseFetcher {
    fetches: std::sync::Mutex<std::collections::VecDeque<AcceptedImageResponseFetchOutcome>>,
    reconciliations:
        std::sync::Mutex<std::collections::VecDeque<AcceptedImageResponseFetchOutcome>>,
    fetch_count: std::sync::atomic::AtomicUsize,
    reconcile_count: std::sync::atomic::AtomicUsize,
}

#[cfg(all(test, feature = "extended"))]
impl accepted_response_fetch_sealed::Sealed for ScriptedAcceptedResponseFetcher {}

#[cfg(all(test, feature = "extended"))]
#[async_trait::async_trait]
impl AcceptedImageResponseFetcher for ScriptedAcceptedResponseFetcher {
    async fn fetch(
        &self,
        _: &AcceptedImageResponseFetchRequest,
    ) -> AcceptedImageResponseFetchOutcome {
        self.fetch_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.fetches
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing scripted fetch")
    }
    async fn reconcile(
        &self,
        _: &AcceptedImageResponseFetchRequest,
        _: &[u8],
    ) -> AcceptedImageResponseFetchOutcome {
        self.reconcile_count
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.reconciliations
            .lock()
            .unwrap()
            .pop_front()
            .expect("missing scripted reconciliation")
    }
}

#[cfg(all(test, feature = "extended"))]
impl ScriptedAcceptedResponseFetcher {
    fn new(
        fetches: Vec<AcceptedImageResponseFetchOutcome>,
        reconciliations: Vec<AcceptedImageResponseFetchOutcome>,
    ) -> Self {
        Self {
            fetches: std::sync::Mutex::new(fetches.into()),
            reconciliations: std::sync::Mutex::new(reconciliations.into()),
            fetch_count: std::sync::atomic::AtomicUsize::new(0),
            reconcile_count: std::sync::atomic::AtomicUsize::new(0),
        }
    }
}

#[cfg(all(test, feature = "extended"))]
impl image_generation_adapter_sealed::Sealed for DeterministicImageGenerationAdapter {}

#[cfg(all(test, feature = "extended"))]
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
    async fn reconcile(
        &self,
        request: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        self.reconciliation_requests
            .lock()
            .expect("fake lock poisoned")
            .push(request.clone());
        self.reconciliation_outcomes
            .lock()
            .expect("fake lock poisoned")
            .pop_front()
            .expect("deterministic image adapter has no reconciliation outcome")
    }
    async fn cancel(&self, request: &ImageGenerationCancelRequest) -> ImageGenerationCancelResult {
        self.cancellation_requests
            .lock()
            .expect("fake lock poisoned")
            .push(request.clone());
        self.cancellation_outcomes
            .lock()
            .expect("fake lock poisoned")
            .pop_front()
            .expect("deterministic image adapter has no cancellation outcome")
    }
}

/// Owns the single transaction that advances image, spend, journal, and media
/// reservation state across an external provider handoff.
#[derive(Clone)]
pub struct ImageGenerationDispatcher {
    db: cockpit_db::Db,
    artifact_root: Option<std::sync::Arc<HeldImageGenerationArtifactRoot>>,
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
}

/// What a dispatch revalidation needs to identify the destination it must probe.
/// Carries only the sealed plan target identity -- never credential material.
pub struct DispatchRevalidationRequest<'a> {
    /// Target names are scoped to the plan's durable owner session. The daemon
    /// worker must never resolve one against another session's configuration.
    pub owner_session_id: Uuid,
    pub target_id: &'a str,
    pub destination: &'a TargetDestinationV1,
}

/// Produces the dispatch-time destination/health proof for a claimed candidate, or
/// fails closed. `prepare_claimed_candidate` calls this INSIDE the prepare flow and
/// refuses to journal `dispatching` (or contact any provider) unless it returns a
/// binding. The binding is always re-derived from a live revalidation -- a stored
/// proof is never read back, so a stale or location-changed proof cannot be reused.
pub trait ImageDispatchProofSource: Send + Sync {
    fn revalidate<'a>(
        &'a self,
        request: DispatchRevalidationRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchProofBinding, RuntimeError>> + Send + 'a>>;
}

/// The endpoint and identities a target resolves to for revalidation. In production
/// the worker builds this from the same materialized config that sealed the plan;
/// `adapter_kind` and `endpoint_identity_digest` are the destination identity that
/// config resolution produced (identical spelling to `TargetDestinationV1`), and
/// they are checked against the sealed plan before any provider contact.
#[derive(Clone)]
pub struct ResolvedDispatchDestination {
    pub adapter_kind: String,
    pub endpoint: ImageEndpoint,
    pub endpoint_identity_digest: String,
    pub credential_identity_digest: CredentialIdentityDigest,
}

/// The production dispatch-proof source: it resolves the plan target's destination
/// to a live endpoint/credential, verifies the resolved identity equals the identity
/// the plan sealed, and calls `ImageRuntimeRegistry::revalidate_dispatch` (via the
/// binding wrapper) with the registry's own injected clock.
///
/// It fails closed (`Obsolete`) when the target is not configured or when the
/// resolved destination identity (`adapter_kind` / `endpoint_identity_digest` /
/// `credential_identity_digest`) differs from the sealed plan. A later session
/// snapshot whose destination identity is unchanged is not Obsolete: the live
/// health generation is stored on the prepared attempt and fenced at provider
/// handoff, not compared to the plan's enqueue-time `destination_generation`.
///
/// The live registry compares its target identity and effective credentials
/// before it returns a snapshot. The checks below bind that result to the
/// destination sealed in the durable plan, so a config replacement cannot make
/// an old health cache authorize a different destination.
pub struct RegistryDispatchProofSource {
    registry: ImageRuntimeRegistry,
    destinations: HashMap<String, ResolvedDispatchDestination>,
}

impl RegistryDispatchProofSource {
    pub fn new(
        registry: ImageRuntimeRegistry,
        destinations: HashMap<String, ResolvedDispatchDestination>,
    ) -> Self {
        Self {
            registry,
            destinations,
        }
    }
}

impl ImageDispatchProofSource for RegistryDispatchProofSource {
    fn revalidate<'a>(
        &'a self,
        request: DispatchRevalidationRequest<'a>,
    ) -> Pin<Box<dyn Future<Output = Result<DispatchProofBinding, RuntimeError>> + Send + 'a>> {
        Box::pin(async move {
            let destination = self.destinations.get(request.target_id).ok_or_else(|| {
                RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "Refresh after image generation target configuration changes.",
                )
            })?;
            let live_credential_identity = self
                .registry
                .effective_credential_identity(&destination.endpoint)?;
            // Bind the proof to the SEALED destination identity before any provider
            // contact: the resolved adapter kind, endpoint identity digest, and
            // credential identity digest must equal what the plan sealed. This fails
            // closed on a map/plan divergence even at the same configuration
            // generation, so a proof can never be issued for a different endpoint,
            // adapter, or credential than the one the plan authorized.
            if destination.adapter_kind != request.destination.adapter_kind
                || destination.endpoint_identity_digest
                    != request.destination.endpoint_identity_digest
                || live_credential_identity != destination.credential_identity_digest
                || destination.credential_identity_digest.plan_identity_hex()
                    != request.destination.credential_identity_digest
            {
                return Err(RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "Refresh after image generation destination identity changes.",
                ));
            }
            self.registry
                .revalidate_dispatch_binding(
                    &destination.endpoint,
                    request.target_id,
                    &destination.credential_identity_digest,
                )
                .await
        })
    }
}

/// Map a sealed plan destination `adapter_kind` string onto the typed
/// [`ImageAdapterKind`]. The spellings are the canonical wire strings the
/// planner seals into `TargetDestinationV1::adapter_kind`. An unrecognized
/// spelling returns `None`, which the scheduler pass turns into a typed
/// `adapter_missing` skip rather than a panic.
fn parse_image_adapter_kind(adapter_kind: &str) -> Option<ImageAdapterKind> {
    match adapter_kind {
        "openai_images" => Some(ImageAdapterKind::OpenaiImages),
        "openrouter_images" => Some(ImageAdapterKind::OpenrouterImages),
        "gemini_images" => Some(ImageAdapterKind::GeminiImages),
        "comfyui" => Some(ImageAdapterKind::Comfyui),
        _ => None,
    }
}

/// A typed multi-provider adapter registry the daemon image-generation worker
/// consults per dispatch candidate. Keyed by [`ImageAdapterKind`]; a claimed
/// candidate whose sealed destination kind is absent from the map yields a typed
/// `adapter_missing` skip (recorded via the scheduler-error path — never a panic
/// or a silent no-op). Production may ship with zero or partial kinds until
/// `wire-image-generation-adapters-to-dispatch` installs the concrete provider
/// adapters; tests inject `DeterministicImageGenerationAdapter` / scripted fakes.
#[derive(Clone, Default)]
pub struct ImageGenerationAdapterMap {
    adapters: HashMap<ImageAdapterKind, std::sync::Arc<dyn ImageGenerationAdapter>>,
    target_adapters:
        HashMap<(ImageAdapterKind, String), std::sync::Arc<dyn ImageGenerationAdapter>>,
}

impl ImageGenerationAdapterMap {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register (or replace) the adapter for a kind, builder-style.
    #[must_use]
    pub fn with(
        mut self,
        kind: ImageAdapterKind,
        adapter: std::sync::Arc<dyn ImageGenerationAdapter>,
    ) -> Self {
        self.adapters.insert(kind, adapter);
        self
    }

    pub fn insert(
        &mut self,
        kind: ImageAdapterKind,
        adapter: std::sync::Arc<dyn ImageGenerationAdapter>,
    ) {
        self.adapters.insert(kind, adapter);
    }

    /// Register an adapter for one configured target. This is the production
    /// form: targets of the same provider kind may use different origins,
    /// credentials, and provider-specific sealed-plan sources. The kind-only
    /// registration above remains the intentionally broad test seam.
    pub fn insert_target(
        &mut self,
        kind: ImageAdapterKind,
        target_id: impl Into<String>,
        adapter: std::sync::Arc<dyn ImageGenerationAdapter>,
    ) {
        self.target_adapters
            .insert((kind, target_id.into()), adapter);
    }

    pub fn get(
        &self,
        kind: ImageAdapterKind,
    ) -> Option<&std::sync::Arc<dyn ImageGenerationAdapter>> {
        self.adapters.get(&kind)
    }

    pub fn get_target(
        &self,
        kind: ImageAdapterKind,
        target_id: &str,
    ) -> Option<&std::sync::Arc<dyn ImageGenerationAdapter>> {
        self.target_adapters
            .get(&(kind, target_id.to_owned()))
            .or_else(|| self.get(kind))
    }

    pub fn len(&self) -> usize {
        self.adapters.len() + self.target_adapters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.adapters.is_empty() && self.target_adapters.is_empty()
    }
}

/// Resolves which [`ImageGenerationAdapter`] handles a claimed dispatch
/// candidate. `Ok(None)` is a typed adapter_missing skip; `Err` is an internal
/// decode failure (the scan already guarantees the slot is in the plan). Two
/// public entry points feed it: `run_scheduler_pass` (one adapter, any kind —
/// existing single-provider tests) and `run_scheduler_pass_with_adapters` (the
/// typed [`ImageGenerationAdapterMap`] the daemon worker holds).
trait CandidateDispatch: Sync {
    fn adapter_for<'a>(
        &'a self,
        plan: &ImageGenerationPlanV1,
        slot_id: Uuid,
    ) -> Result<Option<&'a dyn ImageGenerationAdapter>>;
}

/// Dispatch every candidate through a single adapter regardless of its sealed
/// kind (the historical `run_scheduler_pass` contract).
struct SingleAdapterDispatch<'a>(&'a dyn ImageGenerationAdapter);

impl CandidateDispatch for SingleAdapterDispatch<'_> {
    fn adapter_for<'a>(
        &'a self,
        _plan: &ImageGenerationPlanV1,
        _slot_id: Uuid,
    ) -> Result<Option<&'a dyn ImageGenerationAdapter>> {
        Ok(Some(self.0))
    }
}

/// Route each candidate to the adapter registered for its sealed destination
/// kind, or `None` (typed adapter_missing) when no adapter is installed for it.
struct MapAdapterDispatch<'a>(&'a ImageGenerationAdapterMap);

impl CandidateDispatch for MapAdapterDispatch<'_> {
    fn adapter_for<'a>(
        &'a self,
        plan: &ImageGenerationPlanV1,
        slot_id: Uuid,
    ) -> Result<Option<&'a dyn ImageGenerationAdapter>> {
        let target = plan
            .targets
            .iter()
            .find(|target| target.slots.iter().any(|slot| slot.slot_id == slot_id))
            .context("scheduler candidate slot is absent from immutable plan")?;
        Ok(parse_image_adapter_kind(&target.destination.adapter_kind)
            .and_then(|kind| self.0.get_target(kind, &target.target_id))
            .map(std::sync::Arc::as_ref))
    }
}

/// Outcome of the worker's prior-boot reconciliation sweep (AC2). Runs BEFORE
/// this boot claims any scheduler work so a pre-crash boot's artifact read
/// leases can never gate — or be revived by — the current boot. Immutable claim
/// tables self-expire on their wall-clock TTL and are not swept (see
/// [`ImageGenerationDispatcher::run_prior_boot_reconciliation`]).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PriorBootReconciliation {
    /// Prior-boot artifact read leases released via the foundation's
    /// boot-scoped repair (a prior boot's monotonic lease deadline is
    /// meaningless and must never be revived).
    pub artifact_leases_released: u64,
}

/// Stable, greppable identity for a scheduler-error attention row. There is no
/// dedicated `code` column on `needs_attention`; this string is the stable
/// prefix of the raised row's `description` and its `agent_id`.
const IMAGE_GENERATION_SCHEDULER_ATTENTION_CODE: &str = "image_generation_scheduler";
/// Raise a single attention row once the SAME
/// `(worker_boot_id, job_id, slot_id, attempt_number, stage)` tuple has recorded
/// this many failures. Failures 1 and 2 log only; failure 3 logs and raises;
/// later failures update the existing row rather than inserting duplicates.
const IMAGE_GENERATION_SCHEDULER_ATTENTION_THRESHOLD: u32 = 3;

/// The durable identity a scheduler error is recorded against.
struct SchedulerErrorIdentity {
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    owner_session_id: Uuid,
}

impl ImageGenerationDispatcher {
    pub fn new(db: cockpit_db::Db) -> Self {
        Self {
            db,
            artifact_root: None,
        }
    }

    #[must_use]
    pub fn with_artifact_root(
        mut self,
        artifact_root: std::sync::Arc<HeldImageGenerationArtifactRoot>,
    ) -> Self {
        self.artifact_root = Some(artifact_root);
        self
    }

    pub async fn reconcile_pending_accepted_response_publications(
        &self,
        now_unix_ms: i64,
    ) -> Result<u64> {
        let Some(root) = self.artifact_root.clone() else {
            return Ok(0);
        };
        crate::image_generation_job::reconcile_pending_accepted_response_publications(
            self.db.clone(),
            root,
            now_unix_ms,
        )
        .await
    }

    async fn recovery_routing_identity(
        &self,
        job_id: Uuid,
        slot_id: Uuid,
    ) -> Result<(Uuid, String, ImageAdapterKind)> {
        self.db
            .read(move |conn| {
                let (canonical, digest): (Vec<u8>, String) = conn.query_row(
                    "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
                    [job_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let plan = ImageGenerationPlanV1::from_canonical(&canonical, &digest)?;
                let target = plan
                    .targets
                    .iter()
                    .find(|target| target.slots.iter().any(|slot| slot.slot_id == slot_id))
                    .context("image generation recovery slot is absent from immutable plan")?;
                let kind = match target.destination.adapter_kind.as_str() {
                    "openai_images" => ImageAdapterKind::OpenaiImages,
                    "openrouter_images" => ImageAdapterKind::OpenrouterImages,
                    "gemini_images" => ImageAdapterKind::GeminiImages,
                    "comfyui" => ImageAdapterKind::Comfyui,
                    _ => anyhow::bail!("image generation recovery adapter kind is invalid"),
                };
                Ok((plan.owner_session_id, target.target_id.clone(), kind))
            })
            .await
    }

    /// Record a scheduler-pass failure: emit a structured log AND durably bump
    /// the per-tuple failure counter, raising a single `needs_attention` row at
    /// the threshold. This is production-real (no `#[cfg(test)]` gating).
    ///
    /// Redaction: the underlying `_error` value is deliberately NEVER logged or
    /// persisted. Claim/prepare/dispatch errors can transitively carry
    /// reservation, journal, or destination detail, so the emitted surface is
    /// restricted to opaque identifiers (job/slot/attempt/boot ids and the
    /// stage) plus the failure count. This guarantees no prompt text, credential
    /// header, or destination secret can cross the log or attention boundary.
    async fn record_scheduler_error(
        &self,
        worker_boot_id: Uuid,
        identity: &SchedulerErrorIdentity,
        stage: &'static str,
        _error: &anyhow::Error,
        at_unix_ms: i64,
    ) {
        let job_id = identity.job_id;
        let slot_id = identity.slot_id;
        let attempt_number = identity.attempt_number;
        let owner_session_id = identity.owner_session_id;
        let outcome = self
            .db
            .transaction(move |conn| {
                let (failure_count, existing_interrupt): (i64, Option<String>) = conn.query_row(
                    "INSERT INTO image_generation_scheduler_error_counts(worker_boot_id,job_id,slot_id,attempt_number,stage,failure_count,first_failed_at_unix_ms,last_failed_at_unix_ms) \
                     VALUES(?1,?2,?3,?4,?5,1,?6,?6) \
                     ON CONFLICT(worker_boot_id,job_id,slot_id,attempt_number,stage) \
                     DO UPDATE SET failure_count=failure_count+1,last_failed_at_unix_ms=?6 \
                     RETURNING failure_count,attention_interrupt_id",
                    params![
                        worker_boot_id.to_string(),
                        job_id.to_string(),
                        slot_id.to_string(),
                        i64::from(attempt_number),
                        stage,
                        at_unix_ms
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let failure_count = u32::try_from(failure_count)?;
                let raised = failure_count >= IMAGE_GENERATION_SCHEDULER_ATTENTION_THRESHOLD
                    && existing_interrupt.is_none();
                if raised {
                    let interrupt_id = Uuid::new_v4();
                    conn.execute(
                        "INSERT INTO needs_attention(interrupt_id,session_id,agent_id,description,raised_at) VALUES(?1,?2,?3,?4,?5)",
                        params![
                            interrupt_id.to_string(),
                            owner_session_id.to_string(),
                            IMAGE_GENERATION_SCHEDULER_ATTENTION_CODE,
                            format!(
                                "{IMAGE_GENERATION_SCHEDULER_ATTENTION_CODE}: repeated scheduler pass failure (stage={stage}) for slot {slot_id} attempt {attempt_number}"
                            ),
                            at_unix_ms
                        ],
                    )?;
                    conn.execute(
                        "UPDATE image_generation_scheduler_error_counts SET attention_interrupt_id=?1 \
                         WHERE worker_boot_id=?2 AND job_id=?3 AND slot_id=?4 AND attempt_number=?5 AND stage=?6",
                        params![
                            interrupt_id.to_string(),
                            worker_boot_id.to_string(),
                            job_id.to_string(),
                            slot_id.to_string(),
                            i64::from(attempt_number),
                            stage
                        ],
                    )?;
                }
                Ok((failure_count, raised))
            })
            .await;
        match outcome {
            Ok((failure_count, attention_raised)) => tracing::warn!(
                target: "image_generation_scheduler",
                stage,
                job_id = %job_id,
                slot_id = %slot_id,
                attempt_number,
                worker_boot_id = %worker_boot_id,
                failure_count,
                attention_raised,
                "image generation scheduler pass error"
            ),
            Err(record_error) => tracing::error!(
                target: "image_generation_scheduler",
                stage,
                job_id = %job_id,
                slot_id = %slot_id,
                worker_boot_id = %worker_boot_id,
                error = %record_error,
                "failed to persist image generation scheduler error"
            ),
        }
    }

    /// Release resources owned by *other* daemon boots before this boot accepts
    /// new scheduler work (AC2). The one boot-scoped resource the foundation
    /// models with a *monotonic* deadline — an artifact read lease — is released
    /// through the foundation's boot-scoped repair, because a prior boot's
    /// monotonic lease deadline is meaningless (and must never be revived) across
    /// a restart. The claim tables (scheduler / reconciliation / provider-cancel)
    /// are immutable by construction (delete/update triggers) and instead carry a
    /// bounded *wall-clock* TTL (`expires_at_unix_ms ≤ claimed+60s`), so a
    /// pre-crash boot's claim simply expires on wall time and cannot be — and
    /// need not be — swept here. Must run BEFORE the first `run_scheduler_pass*`
    /// of this boot.
    pub async fn run_prior_boot_reconciliation(
        &self,
        worker_boot_id: Uuid,
    ) -> Result<PriorBootReconciliation> {
        ensure!(
            !worker_boot_id.is_nil(),
            "prior-boot reconciliation requires a boot id"
        );
        // The boot-scoped artifact-lease repair opens its own transaction, so it
        // runs on a bare (non-transaction) writer connection.
        let artifact_leases_released = self
            .db
            .write(move |conn| {
                cockpit_db::Db::repair_image_generation_artifact_leases_for_boot_conn(
                    conn,
                    worker_boot_id,
                )
            })
            .await?;
        Ok(PriorBootReconciliation {
            artifact_leases_released,
        })
    }

    pub async fn run_reconciliation_pass<A: ImageGenerationAdapter + ?Sized>(
        &self,
        adapter: &A,
        worker_boot_id: Uuid,
        now_unix_ms: i64,
        now_monotonic_ms: u64,
        limit: u32,
    ) -> Result<u32> {
        ensure!(
            !worker_boot_id.is_nil() && (1..=64).contains(&limit),
            "invalid reconciliation pass"
        );
        let candidates=self.db.read(move|conn|{
            let mut statement=conn.prepare("SELECT a.job_id,a.slot_id,a.attempt_number,COALESCE((SELECT MAX(c.claim_generation)+1 FROM image_generation_reconciliation_claims c WHERE c.job_id=a.job_id AND c.slot_id=a.slot_id AND c.attempt_number=a.attempt_number),1) FROM image_generation_attempts a WHERE a.state IN ('submission_unknown','reconciling','cancellation_requested') AND EXISTS(SELECT 1 FROM image_generation_handoff_evidence h WHERE h.job_id=a.job_id AND h.slot_id=a.slot_id AND h.attempt_number=a.attempt_number AND h.outcome='submission_unknown') AND NOT EXISTS(SELECT 1 FROM image_generation_reconciliation_claims c LEFT JOIN image_generation_reconciliation_claim_completions d ON d.job_id=c.job_id AND d.slot_id=c.slot_id AND d.attempt_number=c.attempt_number AND d.claim_generation=c.claim_generation WHERE c.job_id=a.job_id AND c.slot_id=a.slot_id AND c.attempt_number=a.attempt_number AND d.claim_generation IS NULL AND c.expires_at_unix_ms>?1) ORDER BY a.job_id,a.slot_id,a.attempt_number LIMIT ?2")?;
            Ok(statement.query_map(rusqlite::params![now_unix_ms,i64::from(limit)],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,i64>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)
        }).await?;
        let mut completed = 0;
        for (job, slot, attempt, generation) in candidates {
            let job_id = Uuid::parse_str(&job)?;
            let slot_id = Uuid::parse_str(&slot)?;
            let attempt_number = u32::try_from(attempt)?;
            let claim_generation = u64::try_from(generation)?;
            let authority = match self
                .db
                .transaction(move |conn| {
                    cockpit_db::Db::claim_image_generation_reconciliation_conn(
                        conn,
                        &cockpit_db::db::image_generation::ClaimImageGenerationReconciliation {
                            job_id,
                            slot_id,
                            attempt_number,
                            worker_boot_id,
                            claim_generation,
                            now_unix_ms,
                        },
                    )
                })
                .await
            {
                Ok(value) => value,
                Err(_) => continue,
            };
            let (
                job_id,
                slot_id,
                attempt_number,
                external_operation_id,
                journal_version,
                provider_request_ref,
                provider_idempotency_ref,
                payload_digest_ref,
            ) = authority.adapter_identity();
            let provider_request = provider_request_ref.to_owned();
            let provider_idempotency = provider_idempotency_ref.to_owned();
            let payload_digest = payload_digest_ref.to_owned();
            let (owner_session_id, target_id, adapter_kind) =
                self.recovery_routing_identity(job_id, slot_id).await?;
            let result = adapter
                .reconcile(&ImageGenerationReconcileRequest {
                    job_id,
                    owner_session_id,
                    target_id,
                    adapter_kind,
                    slot_id,
                    attempt_number,
                    external_operation_id,
                    provider_request_identity: provider_request.clone(),
                    provider_idempotency_identity: provider_idempotency.clone(),
                })
                .await;
            let(outcome,prefix,evidence)=match result{ImageGenerationReconcileResult::AuthoritativeNonacceptance{evidence}=>(cockpit_db::db::image_generation::ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance,b"nonacceptance\0".as_slice(),evidence),ImageGenerationReconcileResult::AuthoritativeAccepted{evidence}|ImageGenerationReconcileResult::AuthoritativeAcceptedWithOutput{evidence,..}=>(cockpit_db::db::image_generation::ImageGenerationReconciliationOutcome::AuthoritativeAccepted,b"accepted\0".as_slice(),evidence),ImageGenerationReconcileResult::AuthoritativeFailure{evidence}=>(cockpit_db::db::image_generation::ImageGenerationReconciliationOutcome::AuthoritativeFailure,b"postacceptance_failure\0".as_slice(),evidence),ImageGenerationReconcileResult::OutcomeUnknown{..}=>continue};
            ensure!(
                !evidence.is_empty() && evidence.len() <= MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES,
                "reconciliation evidence is outside its bound"
            );
            let mut bound = prefix.to_vec();
            bound.extend_from_slice(&evidence);
            let proof = authority.verify(
                cockpit_db::db::image_generation::ImageGenerationReconciliationObservation {
                    provider_request_identity: &provider_request,
                    provider_idempotency_identity: &provider_idempotency,
                    external_operation_id,
                    journal_version,
                    journal_payload_digest: &payload_digest,
                    evidence_bytes: &bound,
                    outcome,
                    now_unix_ms,
                },
            )?;
            self.db.transaction(move|conn|{
                let disposition=cockpit_db::Db::reconcile_image_generation_attempt_conn(conn,&proof)?;
                match disposition {
                    cockpit_db::db::image_generation::ImageGenerationReconciliationDisposition::RetryQueued{external_operation_id,media_reservation_id,media_reservation_version,sealed_media_reservation_id,current_media_plan,current_media_plan_digest,next_media_plan,next_media_plan_digest}=>{
                        let current=decode_media_plan_snapshot(&current_media_plan,&current_media_plan_digest)?;
                        let next=decode_media_plan_snapshot(&next_media_plan,&next_media_plan_digest)?;
                        let next_reservation_id=image_generation_attempt_media_reservation_id(&sealed_media_reservation_id,slot_id,attempt_number.checked_add(1).context("image generation retry attempt overflow")?);
                        if let Err(error)=definitive_rejection_retry_conn(conn,&media_reservation_id,media_reservation_version,&external_operation_id.to_string(),&[current],&[next],u64::try_from(now_unix_ms)?,&next_reservation_id,now_monotonic_ms) {
                            if !error.to_string().contains("deadline_expired") { return Err(error); }
                            finish_external_handoff_conn(conn,&media_reservation_id,media_reservation_version,&external_operation_id.to_string(),MediaExternalHandoffOutcome::DefinitivelyRejected)?;
                        }
                    }
                    cockpit_db::db::image_generation::ImageGenerationReconciliationDisposition::Settled{external_operation_id,media_reservation_id,media_reservation_version,outcome:cockpit_db::db::image_generation::ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance}=>{
                        finish_external_handoff_conn(conn,&media_reservation_id,media_reservation_version,&external_operation_id.to_string(),MediaExternalHandoffOutcome::DefinitivelyRejected)?;
                    }
                    cockpit_db::db::image_generation::ImageGenerationReconciliationDisposition::Settled{..}=>{}
                }
                conn.execute("INSERT INTO image_generation_reconciliation_claim_completions(job_id,slot_id,attempt_number,claim_generation,completed_at_unix_ms) VALUES(?1,?2,?3,?4,?5)",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),i64::try_from(claim_generation)?,now_unix_ms])?;Ok(())}).await?;
            completed += 1;
        }
        Ok(completed)
    }

    pub async fn run_accepted_provider_operation_pass<A: ImageGenerationAdapter + ?Sized>(
        &self,
        adapter: &A,
        now_unix_ms: i64,
        limit: u32,
    ) -> Result<u32> {
        ensure!((1..=64).contains(&limit), "invalid accepted operation pass");
        let candidates=self.db.read(move|conn|{let mut statement=conn.prepare("SELECT a.job_id,a.slot_id,a.attempt_number,a.external_operation_id,a.provider_request_identity,a.provider_idempotency_identity FROM image_generation_attempts a JOIN image_generation_provider_operation_bindings b USING(job_id,slot_id,attempt_number) WHERE a.state IN ('accepted','cancellation_requested') AND NOT EXISTS(SELECT 1 FROM image_generation_response_fetches f WHERE f.job_id=a.job_id AND f.slot_id=a.slot_id AND f.attempt_number=a.attempt_number) ORDER BY a.job_id,a.slot_id,a.attempt_number LIMIT ?1")?;Ok(statement.query_map([i64::from(limit)],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,String>(5)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)}).await?;
        let mut completed = 0;
        for (job, slot, attempt, operation, provider_request, provider_idempotency) in candidates {
            let job_id = Uuid::parse_str(&job)?;
            let slot_id = Uuid::parse_str(&slot)?;
            let attempt_number = u32::try_from(attempt)?;
            let (owner_session_id, target_id, adapter_kind) =
                self.recovery_routing_identity(job_id, slot_id).await?;
            match adapter
                .reconcile(&ImageGenerationReconcileRequest {
                    job_id,
                    owner_session_id,
                    target_id,
                    adapter_kind,
                    slot_id,
                    attempt_number,
                    external_operation_id: Uuid::parse_str(&operation)?,
                    provider_request_identity: provider_request,
                    provider_idempotency_identity: provider_idempotency,
                })
                .await
            {
                ImageGenerationReconcileResult::AuthoritativeAcceptedWithOutput {
                    bytes, ..
                } => {
                    self.coordinate_immediate_accepted_output(
                        job_id,
                        slot_id,
                        attempt_number,
                        bytes,
                        now_unix_ms,
                    )
                    .await?;
                    completed += 1;
                }
                ImageGenerationReconcileResult::AuthoritativeFailure { .. } => {
                    terminalize_accepted_response_failure(
                        &self.db,
                        job_id,
                        slot_id,
                        attempt_number,
                        "provider_output_failed".to_string(),
                        now_unix_ms,
                    )
                    .await?;
                    completed += 1;
                }
                _ => {}
            }
        }
        Ok(completed)
    }

    pub async fn run_provider_cancel_pass<A: ImageGenerationAdapter + ?Sized>(
        &self,
        adapter: &A,
        worker_boot_id: Uuid,
        now_unix_ms: i64,
        limit: u32,
    ) -> Result<u32> {
        ensure!(
            !worker_boot_id.is_nil() && (1..=64).contains(&limit),
            "invalid provider cancel pass"
        );
        let candidates=self.db.read(move|conn|{let mut statement=conn.prepare("SELECT a.job_id,a.slot_id,a.attempt_number,a.external_operation_id,a.provider_request_identity,COALESCE((SELECT MAX(c.claim_generation)+1 FROM image_generation_provider_cancel_claims c WHERE c.job_id=a.job_id AND c.slot_id=a.slot_id AND c.attempt_number=a.attempt_number),1) FROM image_generation_attempts a WHERE a.state='cancellation_requested' AND a.external_operation_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM image_generation_provider_cancel_evidence e WHERE e.job_id=a.job_id AND e.slot_id=a.slot_id AND e.attempt_number=a.attempt_number) AND NOT EXISTS(SELECT 1 FROM image_generation_provider_cancel_claims c WHERE c.job_id=a.job_id AND c.slot_id=a.slot_id AND c.attempt_number=a.attempt_number AND c.expires_at_unix_ms>?1) ORDER BY a.job_id,a.slot_id,a.attempt_number LIMIT ?2")?;Ok(statement.query_map(rusqlite::params![now_unix_ms,i64::from(limit)],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,i64>(2)?,row.get::<_,String>(3)?,row.get::<_,String>(4)?,row.get::<_,i64>(5)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)}).await?;
        let mut recorded = 0;
        for (job, slot, attempt, operation, provider, generation) in candidates {
            let job_id = Uuid::parse_str(&job)?;
            let slot_id = Uuid::parse_str(&slot)?;
            let attempt_number = u32::try_from(attempt)?;
            let claim_generation = u64::try_from(generation)?;
            let external_operation_id = Uuid::parse_str(&operation)?;
            let expires = now_unix_ms
                .checked_add(60_000)
                .context("provider cancel claim overflow")?;
            let claimed=self.db.transaction(move|conn|Ok(conn.execute("INSERT INTO image_generation_provider_cancel_claims(job_id,slot_id,attempt_number,claim_generation,worker_boot_id,claimed_at_unix_ms,expires_at_unix_ms) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE EXISTS(SELECT 1 FROM image_generation_attempts a WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state='cancellation_requested' AND a.external_operation_id=?8) AND NOT EXISTS(SELECT 1 FROM image_generation_provider_cancel_evidence e WHERE e.job_id=?1 AND e.slot_id=?2 AND e.attempt_number=?3)",rusqlite::params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),i64::try_from(claim_generation)?,worker_boot_id.to_string(),now_unix_ms,expires,external_operation_id.to_string()])?==1)).await?;
            if !claimed {
                continue;
            }
            let (owner_session_id, target_id, adapter_kind) =
                self.recovery_routing_identity(job_id, slot_id).await?;
            let result = adapter
                .cancel(&ImageGenerationCancelRequest {
                    job_id,
                    owner_session_id,
                    target_id,
                    adapter_kind,
                    slot_id,
                    attempt_number,
                    external_operation_id,
                    provider_request_identity: provider,
                })
                .await;
            let (outcome, evidence) = match result {
                ImageGenerationCancelResult::Cancelled { evidence } => ("cancelled", evidence),
                ImageGenerationCancelResult::TooLateOrAccepted { evidence } => {
                    ("too_late_or_accepted", evidence)
                }
                // Do not terminalize a durable cancellation claim merely
                // because its owner/configured adapter is temporarily absent
                // or the provider outcome is unknown. Let the claim expire
                // and retry through the real owner-session router.
                ImageGenerationCancelResult::OutcomeUnknown { .. } => continue,
            };
            ensure!(
                !evidence.is_empty() && evidence.len() <= MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES,
                "provider cancel evidence is outside its bound"
            );
            let digest = crate::intel::hex_lower(&Sha256::digest(&evidence));
            let inserted=self.db.transaction(move|conn|Ok(conn.execute("INSERT INTO image_generation_provider_cancel_evidence(job_id,slot_id,attempt_number,external_operation_id,outcome,evidence_digest,recorded_at_unix_ms) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE EXISTS(SELECT 1 FROM image_generation_attempts a WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state='cancellation_requested' AND a.external_operation_id=?4) AND EXISTS(SELECT 1 FROM image_generation_provider_cancel_claims c WHERE c.job_id=?1 AND c.slot_id=?2 AND c.attempt_number=?3 AND c.claim_generation=?8 AND c.worker_boot_id=?9)",rusqlite::params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),external_operation_id.to_string(),outcome,digest,now_unix_ms,i64::try_from(claim_generation)?,worker_boot_id.to_string()])?==1)).await?;
            if inserted {
                recorded += 1;
            }
        }
        Ok(recorded)
    }

    pub async fn scan_dispatch_candidates(
        &self,
        worker_boot_id: Uuid,
        now_monotonic_ms: u64,
        limit: u32,
    ) -> Result<Vec<DecodedImageGenerationDispatchCandidate>> {
        self.db
            .read(move |conn| {
                cockpit_db::Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    cockpit_db::db::image_generation::DeadlineObservationV1::new(
                        worker_boot_id,
                        now_monotonic_ms,
                    )?,
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
                    let attempt = plan
                        .targets
                        .iter()
                        .flat_map(|target| &target.slots)
                        .find(|slot| slot.slot_id == candidate.slot_id)
                        .and_then(|slot| {
                            slot.attempts
                                .iter()
                                .find(|attempt| attempt.attempt_number == candidate.attempt_number)
                        })
                        .context("scheduler attempt is absent from immutable plan")?;
                    let bound = resource_reservation_from_media_reservation(
                        &media_plan,
                        attempt
                            .resource_maximum
                            .first()
                            .context("scheduler attempt resource maximum is absent")?
                            .reservation_identity
                            .clone(),
                    )?;
                    ensure!(
                        attempt.resource_maximum.as_slice() == [bound],
                        "scheduler media plan differs from attempt resource maximum"
                    );
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
        proof_source: &dyn ImageDispatchProofSource,
        worker_boot_id: Uuid,
        claim_generation: u64,
        at_unix_ms: i64,
        now_monotonic_ms: u64,
    ) -> Result<(PreparedImageGenerationDispatch, Vec<MediaReservationPlan>)> {
        // Prove the destination is dispatchable BEFORE the prepare transaction can
        // commit. `revalidate` uses the registry's own injected clock (never a
        // snapshot's `retrieved_at`) and fails closed on a stale epoch or an
        // identity or location-class change. A later session snapshot whose
        // destination identity is unchanged is not a prepare failure: the live
        // health generation is stored on the attempt and fenced at provider
        // handoff. On failure we return before opening the transaction, so the
        // attempt never reaches `prepared`/`dispatching` and no provider is
        // contacted. The binding is re-derived here every time -- a prior proof
        // is never read back, so a stale or location-changed proof cannot be reused.
        let slot_id = candidate.candidate.slot_id;
        let target = candidate
            .plan
            .targets
            .iter()
            .find(|target| target.slots.iter().any(|slot| slot.slot_id == slot_id))
            .context("scheduler candidate slot is absent from immutable plan")?;
        let binding = proof_source
            .revalidate(DispatchRevalidationRequest {
                owner_session_id: candidate.plan.owner_session_id,
                target_id: &target.target_id,
                destination: &target.destination,
            })
            .await
            .map_err(|error| {
                // Only the opaque runtime error code crosses this boundary; the
                // remediation is a fixed string and no credential/prompt text is
                // present. `record_scheduler_error` discards even this.
                anyhow::anyhow!(
                    "image generation dispatch revalidation rejected (code={:?})",
                    error.code
                )
            })?;
        let proof_endpoint_id = binding.endpoint_id;
        let proof_config_generation = binding.config_generation;
        let proof_refresh_epoch = binding.refresh_epoch;
        let proof_connected_ip = binding.connected_ip.to_string();
        let proof_location_class = binding.location_class.as_canonical_str();
        let proof_hops_digest = binding.hops_digest;
        self.db.transaction(move |conn| {
            let c=&candidate.candidate;
            ensure!(conn.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_scheduler_claims WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND worker_boot_id=?4 AND claim_generation=?5 AND expires_at_unix_ms>CAST(unixepoch('subsec')*1000 AS INTEGER))",params![c.job_id.to_string(),c.slot_id.to_string(),i64::from(c.attempt_number),worker_boot_id.to_string(),i64::try_from(claim_generation)?],|row|row.get::<_,bool>(0))?,"image generation scheduler claim is stale");
            let attempt=candidate.plan.targets.iter().flat_map(|target|target.slots.iter()).find(|slot|slot.slot_id==c.slot_id).and_then(|slot|slot.attempts.iter().find(|attempt|attempt.attempt_number==c.attempt_number)).context("scheduler attempt is absent from immutable plan")?;
            let sealed_media_id=candidate.plan.central_resources.first().context("scheduler media reservation is absent")?.reservation_identity.clone();
            let media_id=image_generation_attempt_media_reservation_id(&sealed_media_id,c.slot_id,c.attempt_number);
            let media_version=u64::try_from(conn.query_row::<i64,_,_>("SELECT version FROM media_reservations WHERE reservation_id=?1 AND state='executing_local' AND owner_session_key=?2 AND deadline_monotonic_ms>?3",params![media_id,candidate.plan.owner_session_id.to_string(),i64::try_from(now_monotonic_ms)?],|row|row.get(0))?)?;
            let spend_exists:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM image_spend_reservations r JOIN image_spend_attempts a USING(reservation_id) WHERE r.reservation_id=?1 AND a.attempt_id=?2 AND r.state='reserved')",params![candidate.plan.spend.reservation_id,attempt.provider_idempotency_identity],|row|row.get(0))?;
            ensure!(spend_exists,"scheduler spend reservation is unavailable");
            let token=ExternalJournalToken::parse(&crate::intel::hex_lower(&Sha256::digest(attempt.provider_idempotency_identity.as_bytes())))?;
            let journal=PrepareExternalOperation{operation_kind:ExternalJournalToken::parse("image_generation")?,owner_session_id:ExternalJournalToken::for_session(candidate.plan.owner_session_id),idempotency_key:token.clone(),payload_digest:ExternalJournalDigest::of(&c.canonical_plan),payload_len:c.canonical_plan.len(),provider_idempotency:Some(ProviderIdempotency{key:token,contract:ExternalJournalToken::parse("image_generation_v1")?})};
            let dispatch_proof=cockpit_db::db::image_generation::DispatchConnectionProofV1{endpoint_id:&proof_endpoint_id,config_generation:proof_config_generation,refresh_epoch:proof_refresh_epoch,connected_ip:&proof_connected_ip,location_class:proof_location_class,hops_digest:&proof_hops_digest};
            let prepared=cockpit_db::Db::prepare_image_generation_dispatch_conn(conn,&cockpit_db::db::image_generation::PrepareImageGenerationDispatch{job_id:c.job_id,slot_id:c.slot_id,attempt_number:c.attempt_number,expected_job_version:c.job_version,expected_slot_version:c.slot_version,expected_attempt_version:c.attempt_version,spend_reservation_id:&candidate.plan.spend.reservation_id,spend_attempt_id:&attempt.provider_idempotency_identity,media_reservation_id:&media_id,media_plan_digest:&c.media_plan_digest,expected_media_reservation_version:media_version,journal:&journal,at_unix_ms,deadline_observation:cockpit_db::db::image_generation::DeadlineObservationV1::new(worker_boot_id,now_monotonic_ms)?,worker_boot_id,claim_generation,dispatch_proof})?;
            Ok((prepared,vec![candidate.media_plan]))
        }).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn run_scheduler_pass<A>(
        &self,
        adapter: &A,
        proof_source: &dyn ImageDispatchProofSource,
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
            &SingleAdapterDispatch(adapter),
            proof_source,
            worker_boot_id,
            now_monotonic_ms,
            at_unix_ms,
            media_wall_ms,
            limit,
            |_| Ok(()),
        )
        .await
    }

    /// Drive one scheduler pass routing each candidate through the typed
    /// [`ImageGenerationAdapterMap`]. A candidate whose sealed destination kind
    /// has no registered adapter is a typed `adapter_missing` skip (AC11): it
    /// increments `skipped`, records a scheduler error, and never panics. Used
    /// by the daemon worker.
    #[allow(clippy::too_many_arguments)]
    pub async fn run_scheduler_pass_with_adapters(
        &self,
        adapters: &ImageGenerationAdapterMap,
        proof_source: &dyn ImageDispatchProofSource,
        worker_boot_id: Uuid,
        now_monotonic_ms: u64,
        at_unix_ms: i64,
        media_wall_ms: u64,
        limit: u32,
    ) -> Result<ImageGenerationSchedulerPass> {
        self.run_scheduler_pass_with_hook(
            &MapAdapterDispatch(adapters),
            proof_source,
            worker_boot_id,
            now_monotonic_ms,
            at_unix_ms,
            media_wall_ms,
            limit,
            |_| Ok(()),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_scheduler_pass_with_hook<H>(
        &self,
        dispatch: &dyn CandidateDispatch,
        proof_source: &dyn ImageDispatchProofSource,
        worker_boot_id: Uuid,
        now_monotonic_ms: u64,
        at_unix_ms: i64,
        media_wall_ms: u64,
        limit: u32,
        mut before_claim: H,
    ) -> Result<ImageGenerationSchedulerPass>
    where
        H: FnMut(&DecodedImageGenerationDispatchCandidate) -> Result<()>,
    {
        let candidates = self
            .scan_dispatch_candidates(worker_boot_id, now_monotonic_ms, limit)
            .await?;
        let mut pass = ImageGenerationSchedulerPass {
            scanned: u32::try_from(candidates.len())?,
            ..Default::default()
        };
        for candidate in candidates {
            before_claim(&candidate)?;
            // Capture the durable identity before `candidate` is moved into
            // prepare, so prepare/dispatch errors record against the same tuple.
            let identity = SchedulerErrorIdentity {
                job_id: candidate.candidate.job_id,
                slot_id: candidate.candidate.slot_id,
                attempt_number: candidate.candidate.attempt_number,
                owner_session_id: candidate.plan.owner_session_id,
            };
            // Resolve the adapter for this candidate's sealed kind BEFORE
            // claiming. A missing adapter is a typed `adapter_missing` skip
            // (AC11): record it and move on without consuming a claim
            // generation or contacting any provider.
            let adapter =
                match dispatch.adapter_for(&candidate.plan, candidate.candidate.slot_id)? {
                    Some(adapter) => adapter,
                    None => {
                        self.record_scheduler_error(
                            worker_boot_id,
                            &identity,
                            "adapter_missing",
                            &anyhow::anyhow!(
                                "no image generation adapter registered (code={:?})",
                                RuntimeErrorCode::AdapterMissing
                            ),
                            at_unix_ms,
                        )
                        .await;
                        pass.skipped += 1;
                        continue;
                    }
                };
            let target = candidate
                .plan
                .targets
                .iter()
                .find(|target| {
                    target
                        .slots
                        .iter()
                        .any(|slot| slot.slot_id == candidate.candidate.slot_id)
                })
                .context("scheduler candidate target is absent from immutable plan")?;
            if let ImageGenerationHandoffReadiness::Deferred { evidence } = adapter
                .handoff_readiness(&ImageGenerationHandoffReadinessRequest {
                    owner_session_id: candidate.plan.owner_session_id,
                    target_id: &target.target_id,
                    destination: &target.destination,
                })
            {
                let reason = String::from_utf8_lossy(&evidence);
                self.record_scheduler_error(
                    worker_boot_id,
                    &identity,
                    "handoff_deferred",
                    &anyhow::anyhow!("image generation handoff deferred: {reason}"),
                    at_unix_ms,
                )
                .await;
                pass.skipped += 1;
                continue;
            }
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
                self.record_scheduler_error(worker_boot_id, &identity, "claim", &error, at_unix_ms)
                    .await;
                pass.skipped += 1;
                continue;
            }
            pass.claimed += 1;
            let generation = candidate.candidate.next_claim_generation;
            let prepared_result = self
                .prepare_claimed_candidate(
                    candidate,
                    proof_source,
                    worker_boot_id,
                    generation,
                    at_unix_ms,
                    now_monotonic_ms,
                )
                .await;
            let (prepared, plans) = match prepared_result {
                Ok(value) => value,
                Err(error) => {
                    self.record_scheduler_error(
                        worker_boot_id,
                        &identity,
                        "prepare",
                        &error,
                        at_unix_ms,
                    )
                    .await;
                    pass.skipped += 1;
                    continue;
                }
            };
            if let Err(error) = self
                .dispatch_once(
                    adapter,
                    prepared,
                    plans,
                    worker_boot_id,
                    at_unix_ms,
                    now_monotonic_ms,
                    media_wall_ms,
                )
                .await
            {
                self.record_scheduler_error(
                    worker_boot_id,
                    &identity,
                    "dispatch",
                    &error,
                    at_unix_ms,
                )
                .await;
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
        worker_boot_id: Uuid,
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
                    cockpit_db::db::image_generation::DeadlineObservationV1::new(
                        worker_boot_id,
                        now_monotonic_ms,
                    )?,
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

    #[allow(clippy::too_many_arguments)]
    pub async fn finish_external_handoff(
        &self,
        dispatching: DispatchingImageGenerationAttempt,
        evidence: ImageSpendDispatchEvidence,
        evidence_bytes: Vec<u8>,
        provider_operation_id: Option<String>,
        provider_reconciliation_context: Option<Vec<u8>>,
        prior_handoff_plans: Vec<MediaReservationPlan>,
        at_unix_ms: i64,
        media_wall_ms: u64,
        now_monotonic_ms: u64,
    ) -> Result<()> {
        let operation_id = dispatching.operation().operation_id.to_string();
        let (reservation_id, reservation_version) = dispatching.media_reservation();
        let reservation_id = reservation_id.to_owned();
        let (job_id, slot_id, attempt_number, _) = dispatching.identity();
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
                let disposition = cockpit_db::Db::finish_image_generation_handoff_conn(
                    conn,
                    dispatching,
                    cockpit_db::db::image_generation::ImageGenerationProviderHandoffEvidence {
                        outcome: evidence,
                        bytes: &evidence_bytes,
                    },
                    at_unix_ms,
                )?;
                ensure!(
                    provider_operation_id.is_some() == provider_reconciliation_context.is_some(),
                    "provider operation binding is incomplete"
                );
                if let (Some(provider_operation_id), Some(provider_reconciliation_context)) =
                    (provider_operation_id, provider_reconciliation_context)
                {
                    conn.execute(
                        "INSERT INTO image_generation_provider_operation_bindings \
                         (job_id,slot_id,attempt_number,external_operation_id,provider_operation_id,reconciliation_context,recorded_at_unix_ms) \
                         VALUES(?1,?2,?3,?4,?5,?6,?7) \
                         ON CONFLICT(job_id,slot_id,attempt_number) DO NOTHING",
                        params![
                            job_id.to_string(),
                            slot_id.to_string(),
                            i64::from(attempt_number),
                            &operation_id,
                            &provider_operation_id,
                            &provider_reconciliation_context,
                            at_unix_ms,
                        ],
                    )?;
                    let bound: (String, Vec<u8>) = conn.query_row(
                        "SELECT provider_operation_id,reconciliation_context FROM image_generation_provider_operation_bindings WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",
                        params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number)],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )?;
                    ensure!(
                        bound == (provider_operation_id, provider_reconciliation_context),
                        "provider operation binding differs"
                    );
                }
                match disposition {
                    ImageGenerationHandoffFinishDisposition::RetryQueued {
                        next_attempt_number,
                        canonical_media_plan,
                        media_plan_digest,
                    } => {
                        let next =
                            decode_media_plan_snapshot(&canonical_media_plan, &media_plan_digest)?;
                        let (canonical_plan, plan_digest): (Vec<u8>, String) = conn.query_row(
                            "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
                            [job_id.to_string()],
                            |row| Ok((row.get(0)?, row.get(1)?)),
                        )?;
                        let plan = ImageGenerationPlanV1::from_canonical(&canonical_plan, &plan_digest)?;
                        let sealed = plan
                            .central_resources
                            .first()
                            .context("image generation sealed media reservation is absent")?
                            .reservation_identity
                            .clone();
                        let next_reservation_id = image_generation_attempt_media_reservation_id(
                            &sealed,
                            slot_id,
                            next_attempt_number,
                        );
                        if let Err(error) = definitive_rejection_retry_conn(
                            conn,
                            &reservation_id,
                            reservation_version,
                            &operation_id,
                            &prior_handoff_plans,
                            &[next],
                            media_wall_ms,
                            &next_reservation_id,
                            now_monotonic_ms,
                        ) {
                            if !error.to_string().contains("deadline_expired") {
                                return Err(error);
                            }
                            finish_external_handoff_conn(
                                conn,
                                &reservation_id,
                                reservation_version,
                                &operation_id,
                                MediaExternalHandoffOutcome::DefinitivelyRejected,
                            )?;
                        }
                    }
                    ImageGenerationHandoffFinishDisposition::Settled => {
                        finish_external_handoff_conn(
                            conn,
                            &reservation_id,
                            reservation_version,
                            &operation_id,
                            media_outcome,
                        )?;
                    }
                    ImageGenerationHandoffFinishDisposition::Replay => {}
                }
                Ok(())
            })
            .await
    }

    async fn coordinate_immediate_accepted_output(
        &self,
        job_id: Uuid,
        slot_id: Uuid,
        attempt_number: u32,
        bytes: Vec<u8>,
        now_unix_ms: i64,
    ) -> Result<AcceptedImageResponseProgress> {
        let root = self
            .artifact_root
            .clone()
            .context("image generation artifact retention authority is unavailable")?;
        let response_digest = crate::intel::hex_lower(&Sha256::digest(&bytes));
        let fetch_evidence = b"adapter_inline_output_v1".to_vec();
        let evidence_digest = crate::intel::hex_lower(&Sha256::digest(&fetch_evidence));
        let persisted_bytes = bytes.clone();
        self.db
            .transaction(move |conn| {
                conn.execute(
                    "INSERT OR IGNORE INTO image_generation_response_fetch_outcomes \
                     (job_id,slot_id,attempt_number,outcome,safe_reason,evidence,evidence_digest,recorded_at_unix_ms) \
                     VALUES(?1,?2,?3,'fetched',NULL,?4,?5,?6)",
                    params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number), fetch_evidence, evidence_digest, now_unix_ms],
                )?;
                conn.execute(
                    "INSERT OR IGNORE INTO image_generation_response_fetches \
                     (job_id,slot_id,attempt_number,response_digest,response_bytes,fetch_evidence,fetch_evidence_digest,fetched_at_unix_ms) \
                     VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number), response_digest, persisted_bytes, b"adapter_inline_output_v1".as_slice(), crate::intel::hex_lower(&Sha256::digest(b"adapter_inline_output_v1")), now_unix_ms],
                )?;
                let stored: String = conn.query_row(
                    "SELECT response_digest FROM image_generation_response_fetches WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",
                    params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number)],
                    |row| row.get(0),
                )?;
                ensure!(stored == response_digest, "accepted response replay differs");
                Ok(())
            })
            .await?;
        let authority = self
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT j.version,s.version,a.version,a.external_operation_id,o.version \
                     FROM image_generation_jobs j \
                     JOIN image_generation_slots s ON s.job_id=j.job_id \
                     JOIN image_generation_attempts a ON a.job_id=s.job_id AND a.slot_id=s.slot_id \
                     JOIN external_journal_operations o ON o.operation_id=a.external_operation_id \
                     WHERE j.job_id=?1 AND s.slot_id=?2 AND a.attempt_number=?3",
                    params![
                        job_id.to_string(),
                        slot_id.to_string(),
                        i64::from(attempt_number)
                    ],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, String>(3)?,
                            row.get::<_, i64>(4)?,
                        ))
                    },
                )
                .map_err(Into::into)
            })
            .await?;
        coordinate_persisted_accepted_image_response(
            self.db.clone(),
            root,
            CoordinateAcceptedImageResponse {
                job_id,
                slot_id,
                attempt_number,
                expected_job_version: u64::try_from(authority.0)?,
                expected_slot_version: u64::try_from(authority.1)?,
                expected_attempt_version: u64::try_from(authority.2)?,
                external_operation_id: Uuid::parse_str(&authority.3)?,
                expected_journal_version: u64::try_from(authority.4)?,
                component_id: Uuid::now_v7(),
                release_operation_id: Uuid::now_v7(),
                bytes,
                now_unix_ms,
            },
        )
        .await
    }

    /// Performs exactly one provider call after the durable dispatch token is
    /// committed, then atomically records the closed handoff result.
    #[allow(clippy::too_many_arguments)]
    pub async fn dispatch_once<A: ImageGenerationAdapter + ?Sized>(
        &self,
        adapter: &A,
        prepared: PreparedImageGenerationDispatch,
        handoff_plans: Vec<MediaReservationPlan>,
        worker_boot_id: Uuid,
        at_unix_ms: i64,
        now_monotonic_ms: u64,
        media_wall_ms: u64,
    ) -> Result<ImageGenerationHandoffResult> {
        let prior_handoff_plans_for_finish = handoff_plans.clone();
        let dispatching = self
            .begin_external_handoff(
                prepared,
                handoff_plans,
                worker_boot_id,
                at_unix_ms,
                now_monotonic_ms,
                media_wall_ms,
            )
            .await?;
        let (job_id, slot_id, attempt_number, _) = dispatching.identity();
        let (provider_request_identity, provider_idempotency_identity) =
            dispatching.provider_dispatch_identity();
        let (owner_session_id, target_id, sealed_prompt, dispatch_config_generation) = self
            .db
            .read(move |conn| {
                let (canonical, digest): (Vec<u8>, String) = conn.query_row(
                    "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
                    [job_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let plan = ImageGenerationPlanV1::from_canonical(&canonical, &digest)?;
                let target = plan
                    .targets
                    .iter()
                    .find(|target| target.slots.iter().any(|slot| slot.slot_id == slot_id))
                    .context("image generation handoff slot is absent from immutable plan")?;
                let dispatch_config_generation: i64 = conn.query_row(
                    "SELECT dispatch_proof_config_generation FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND state='dispatching'",
                    params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number)],
                    |row| row.get(0),
                )?;
                Ok((
                    plan.owner_session_id,
                    target.target_id.clone(),
                    plan.sealed_prompt,
                    u64::try_from(dispatch_config_generation)?,
                ))
            })
            .await?;
        let request = ImageGenerationHandoffRequest {
            job_id,
            owner_session_id,
            target_id,
            dispatch_config_generation,
            slot_id,
            attempt_number,
            external_operation_id: dispatching.operation().operation_id,
            now_unix_ms: at_unix_ms,
            provider_request_identity: provider_request_identity.to_owned(),
            provider_idempotency_identity: provider_idempotency_identity.to_owned(),
            sealed_prompt,
        };
        let result = adapter.handoff(&request).await;
        result.validate()?;
        let evidence_bytes = match &result {
            ImageGenerationHandoffResult::Accepted { evidence }
            | ImageGenerationHandoffResult::AcceptedWithOutput { evidence, .. }
            | ImageGenerationHandoffResult::DefinitivelyRejected { evidence }
            | ImageGenerationHandoffResult::SubmissionUnknown { evidence } => evidence.clone(),
        };
        let provider_operation_binding = match &result {
            ImageGenerationHandoffResult::AcceptedWithOutput {
                output:
                    ImageGenerationAcceptedOutput::Deferred {
                        provider_operation_id,
                        reconciliation_context,
                    },
                ..
            } => Some((
                provider_operation_id.clone(),
                reconciliation_context.clone(),
            )),
            _ => None,
        };
        let immediate_output = match &result {
            ImageGenerationHandoffResult::AcceptedWithOutput {
                output: ImageGenerationAcceptedOutput::Immediate { bytes },
                ..
            } => Some(bytes.clone()),
            _ => None,
        };
        self.finish_external_handoff(
            dispatching,
            result.spend_evidence(),
            evidence_bytes,
            provider_operation_binding
                .as_ref()
                .map(|(provider_operation_id, _)| provider_operation_id.clone()),
            provider_operation_binding.map(|(_, reconciliation_context)| reconciliation_context),
            prior_handoff_plans_for_finish,
            at_unix_ms,
            media_wall_ms,
            now_monotonic_ms,
        )
        .await?;
        if let Some(bytes) = immediate_output {
            self.coordinate_immediate_accepted_output(
                job_id,
                slot_id,
                attempt_number,
                bytes,
                at_unix_ms,
            )
            .await?;
        }
        Ok(result)
    }
}

/// The daemon worker's reconcile/cancel adapter until
/// `image-generation-real-dispatch-and-chokepoint-integration` installs
/// per-kind reconcilers. Reconcile/cancel requests do not carry an adapter
/// kind, so this increment cannot route them per-provider; it uses the trait's
/// retry-safe `OutcomeUnknown` defaults (identical to shipping no adapter),
/// leaving a submission-unknown attempt to be re-observed on a later pass.
/// `handoff` is never reached from the reconcile/cancel passes and fails closed
/// to `SubmissionUnknown` (never a panic) if it somehow were.
pub(crate) struct DeferredImageReconciler;

impl image_generation_adapter_sealed::Sealed for DeferredImageReconciler {}

#[async_trait::async_trait]
impl ImageGenerationAdapter for DeferredImageReconciler {
    async fn handoff(
        &self,
        _request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        ImageGenerationHandoffResult::SubmissionUnknown {
            evidence: b"deferred_reconciler_handoff_unavailable".to_vec(),
        }
    }
}

/// One canonical media-reservation-plan snapshot bound to a slot/attempt. The
/// caller supplies these from the media reservation it already authorized; the
/// service does not re-open the media ledger.
#[derive(Debug, Clone)]
pub struct ImageGenerationMediaSnapshotInput {
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub canonical_bytes: Vec<u8>,
    pub digest: String,
}

/// Outcome of [`ImageGenerationJobService::create_queued_job`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationJobCreation {
    /// The plan was committed; its slots/attempts are `queued` and claimable by
    /// the daemon worker's scheduler pass.
    Queued { job_id: Uuid },
    /// Preflight rejected the request; nothing was persisted.
    Incompatible(Vec<ImageGenerationTargetAlternativeV1>),
}

/// Session-scoped funnel that turns an already-authorized image-generation
/// request into a durable, `queued` job the daemon worker can dispatch (AC10).
///
/// It runs the pure preflight (`resolve_image_generation`) and then commits
/// plan → job → slots → attempts inside a single transaction, leaving every
/// attempt `queued`. Spend and media reservations must already be authorized by
/// the caller (their handles arrive as `spend`/`central_resources` on the
/// authority and as `media_snapshots`); the service never re-opens a reservation
/// transaction. It calls no agent tool and no Approver — the chokepoint prompt
/// (`image-generation-real-dispatch-and-chokepoint-integration`) drives this
/// service after it authorizes.
pub struct ImageGenerationJobService {
    db: cockpit_db::Db,
}

/// A remembered approval that is committed in the same SQLite transaction as
/// the queued image job. Keeping this write beside the graph insert prevents a
/// post-commit grant failure from returning an error for a job that a retry
/// could duplicate.
#[derive(Debug, Clone)]
pub struct ImageGenerationStandingGrant {
    pub scope: crate::approval::store::Scope,
    pub session_id: Uuid,
    pub project_id: String,
    pub destination_binding_digest: String,
    pub output_path_authority: String,
    pub reference_egress: bool,
    pub maximum_fanout: u32,
    pub maximum_total_outputs: u32,
    pub maximum_known_cost_usd_micros: Option<u64>,
    pub unknown_cost_allowed: bool,
}

impl ImageGenerationJobService {
    pub fn new(db: cockpit_db::Db) -> Self {
        Self { db }
    }

    /// Retire preflight-only component leases when a job never reaches the
    /// transactional ownership transfer. This is deliberately idempotent at
    /// the caller boundary: failed queue creation and incompatible preflight
    /// must not pin user media until daemon restart recovery.
    async fn release_untransferred_reference_leases(
        db: cockpit_db::Db,
        leases: Vec<AcquiredMediaComponentLease>,
        now_unix_ms: i64,
    ) -> Result<()> {
        db.transaction(move |conn| {
            for lease in leases {
                cockpit_db::Db::release_media_component_lease_conn(
                    conn,
                    lease.lease_id,
                    now_unix_ms,
                )?;
            }
            Ok(())
        })
        .await
    }

    /// Resolve preflight, then commit the plan as a `queued` job. Returns
    /// [`ImageGenerationJobCreation::Incompatible`] (persisting nothing) when the
    /// request cannot be sealed against its sealed target capability.
    pub async fn create_queued_job(
        &self,
        request: ImageGenerationRequestV1,
        authority: ImageGenerationResolutionAuthorityV1,
        media_snapshots: Vec<ImageGenerationMediaSnapshotInput>,
        reference_leases: Vec<AcquiredMediaComponentLease>,
        standing_grant: Option<ImageGenerationStandingGrant>,
        created_at_unix_ms: i64,
    ) -> Result<ImageGenerationJobCreation> {
        let plan = match resolve_image_generation(request, authority)? {
            ImageGenerationResolutionV1::Ready(plan) => *plan,
            ImageGenerationResolutionV1::Incompatible(alternatives) => {
                return Ok(ImageGenerationJobCreation::Incompatible(alternatives));
            }
        };
        let job_id = plan.job_id;
        let canonical = plan.canonical_bytes()?;
        let plan_digest = plan.digest()?;
        self.db
            .transaction(move |conn| {
                let verified =
                    cockpit_db::db::image_generation::CreateImageGenerationJob::from_verified_canonical_plan(
                        &canonical,
                        &plan_digest,
                        created_at_unix_ms,
                    )?;
                let slots = plan
                    .targets
                    .iter()
                    .flat_map(|target| &target.slots)
                    .map(|slot| cockpit_db::db::image_generation::CreateImageGenerationSlot {
                        slot_id: slot.slot_id,
                        slot_index: slot.slot_index,
                        sample_index: slot.sample_index,
                        managed_artifact_id: slot.managed_artifact_id,
                        attempts: slot
                            .attempts
                            .iter()
                            .map(|attempt| {
                                cockpit_db::db::image_generation::CreateImageGenerationAttempt {
                                    attempt_number: attempt.attempt_number,
                                    provider_request_identity: attempt
                                        .provider_request_identity
                                        .clone(),
                                    provider_idempotency_identity: attempt
                                        .provider_idempotency_identity
                                        .clone(),
                                }
                            })
                            .collect(),
                    })
                    .collect::<Vec<_>>();
                cockpit_db::Db::create_image_generation_graph_conn(conn, &verified, &slots)?;
                let queue_authority =
                    cockpit_db::Db::image_generation_queue_authority_conn(conn, job_id)?;
                let media = media_snapshots
                    .iter()
                    .map(|snapshot| {
                        cockpit_db::db::image_generation::ImageGenerationMediaPlanSnapshot {
                            slot_id: snapshot.slot_id,
                            attempt_number: snapshot.attempt_number,
                            canonical_bytes: &snapshot.canonical_bytes,
                            digest: &snapshot.digest,
                        }
                    })
                    .collect::<Vec<_>>();
                cockpit_db::Db::queue_image_generation_job_conn(
                    conn,
                    queue_authority,
                    &media,
                    created_at_unix_ms,
                )?;
                // Preflight leases are only short-lived evidence. Transfer
                // their ownership to job-scoped durable references before the
                // queued graph becomes visible, then retire every lease in
                // this same transaction.
                let job_consumer_id = job_id.to_string();
                for lease in &reference_leases {
                    cockpit_db::Db::acquire_media_reference_conn(
                        conn,
                        AcquireMediaReferenceInput {
                            reference_id: Uuid::now_v7(),
                            attachment_id: lease.attachment_id,
                            expected_version: lease.attachment_version,
                            session_id: lease.owner_session_id,
                            project_digest: &lease.canonical_project_digest,
                            consumer_kind: MediaReferenceConsumerKind::Job,
                            consumer_id: &job_consumer_id,
                            now_unix_ms: created_at_unix_ms,
                        },
                    )?;
                    cockpit_db::Db::release_media_component_lease_conn(
                        conn,
                        lease.lease_id,
                        created_at_unix_ms,
                    )?;
                }
                if let Some(grant) = standing_grant {
                    let session_id = match grant.scope {
                        crate::approval::store::Scope::Session => Some(grant.session_id.to_string()),
                        crate::approval::store::Scope::Project => None,
                        crate::approval::store::Scope::Once
                        | crate::approval::store::Scope::Global => {
                            anyhow::bail!("image generation standing grant scope is invalid")
                        }
                    };
                    conn.execute(
                        "INSERT OR REPLACE INTO image_generation_grants \
                         (grant_id,scope,session_id,project_id,destination_binding_digest,output_path_authority,reference_egress,maximum_fanout,maximum_total_outputs,maximum_known_cost_usd_micros,unknown_cost_allowed,verdict,granted_at_unix_ms,revoked_at_unix_ms) \
                         VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,'allow',?12,NULL)",
                        params![
                            Uuid::now_v7().to_string(),
                            grant.scope.as_str(),
                            session_id,
                            grant.project_id,
                            grant.destination_binding_digest,
                            grant.output_path_authority,
                            i64::from(grant.reference_egress),
                            i64::from(grant.maximum_fanout),
                            i64::from(grant.maximum_total_outputs),
                            grant.maximum_known_cost_usd_micros.map(i64::try_from).transpose()?,
                            i64::from(grant.unknown_cost_allowed),
                            created_at_unix_ms,
                        ],
                    )?;
                }
                Ok(ImageGenerationJobCreation::Queued { job_id })
            })
            .await
    }
}

use crate::approval::{Approver, AuthorizationRequest, Decision};
use crate::image_generation_agent_tools::{
    BudgetDisposition, ImageGenerationPlanProjection, ImageReferenceTag, LocationClass, PlanDigest,
    ProjectionDestination, ProjectionReference, ProjectionSize, ProjectionTargetRequest,
    SpendPolicyChoice, TypedParameter, plan_projection_digest,
};
use cockpit_db::image_spend::{
    BudgetBlockReason, BudgetPolicy, CurrentImageSpendPolicy, ImageSpendSettings,
};

/// Redacted, model-safe refusal copy. None of these carries a prompt, a raw
/// filesystem path, a provider secret, or reference bytes.
const DISPATCH_NO_TARGETS: &str = "image generation requires at least one target.";
/// Latched dispatch path after a failed reconcile or unpublished generation.
const DISPATCH_PREFLIGHT_UNAVAILABLE: &str = "image generation is temporarily unavailable: \
     dispatch is withheld until configuration is refreshed. Retry later; configuring new endpoints \
     will not fix a latched dispatch path in this session.";
/// Model-safe copy for `list_image_generation_targets` when dispatch is latched
/// unavailable. Distinct from an empty configured registry.
pub const DISPATCH_DISCOVERY_UNAVAILABLE: &str = "image generation is temporarily unavailable: \
     target discovery is withheld until configuration is refreshed. Retry later; configuring new \
     endpoints will not fix a latched dispatch path in this session.";
const DISPATCH_NOT_CONFIGURED: &str = "No image-generation targets are currently configured. \
     Configure an image endpoint and target before calling `generate_image`.";
const DISPATCH_NO_DEFAULT_TARGET: &str = "No default image-generation target is configured. \
     Specify an explicit `target_id` or call `list_image_generation_targets` to choose a target.";
const DISPATCH_UNKNOWN_TARGET: &str = "Unknown or removed image-generation target id. Call \
     `list_image_generation_targets` and retry with a valid `target_id`.";
const DISPATCH_TARGET_NOT_DISPATCH_READY: &str = "image generation is unavailable: the selected \
     target is not dispatch-ready. Call `list_image_generation_targets` and retry with a healthy \
     target.";
const DISPATCH_HARD_GATE_DISABLED_TARGET: &str = "image generation is unavailable: the selected \
     target is disabled. Call `list_image_generation_targets` with `include_disabled: true` to \
     inspect disabled targets.";
const DISPATCH_HARD_GATE_STALE_CAPABILITY: &str = "image generation is unavailable: target \
     capability is stale. Call `list_image_generation_targets` and retry with a healthy target.";
const DISPATCH_HARD_GATE_OUTPUT_WRITE: &str = "image generation is unavailable: the output \
     directory is not authorized for normal writes in this session.";
const DISPATCH_HARD_GATE_PATH_READ: &str = "image generation is unavailable: local reference \
     paths are not read-authorized in this session.";
const DISPATCH_HARD_GATE_INSECURE_TRANSPORT: &str = "image generation is unavailable: insecure \
     transport to a remote target is not permitted for this endpoint.";
const DISPATCH_HARD_GATE_UNKNOWN_COST: &str = "image generation is unavailable: unknown maximum \
     cost requires Unlimited spend policy at request, session, and project scope.";
const DISPATCH_SPEND_POLICY_UNAVAILABLE: &str = "image generation is unavailable: an image spend \
     budget has not been configured for this project.";
const DISPATCH_SPEND_RESERVATION_BLOCKED: &str = "image generation is unavailable: the image spend \
     budget could not be reserved. Adjust spend limits, wait for in-flight reservations to \
     complete, or retry later.";
const DISPATCH_SPEND_POLICY_CHANGED: &str = "image generation is unavailable: the image spend \
     policy changed since this request was authorized. Retry the request.";
const DISPATCH_MEDIA_RESERVATION_BLOCKED: &str = "image generation is unavailable: a media \
     resource limit could not be reserved. Wait for in-flight image generation to complete, lower \
     concurrency or output size, or adjust media limits in configuration.";
const DISPATCH_MEDIA_ACCOUNTING_BLOCKED: &str = "image generation is temporarily unavailable: \
     media accounting is blocked for this project or session. Retry later after accounting \
     recovery completes.";
const DISPATCH_OUTPUT_DIR_UNAVAILABLE: &str = "image generation is unavailable: the output \
     directory could not be opened as a write destination.";
const DISPATCH_OWNER_UNAVAILABLE: &str =
    "image generation is unavailable: this session is no longer authorized for the project.";
const DISPATCH_COMMIT_UNAVAILABLE: &str = "image generation is temporarily unavailable: the job \
     could not be queued. Try again after image generation target configuration is refreshed.";
/// Internal tool/service marker for an omitted `targets` argument. It is
/// resolved to the configured default before any authorization fact, digest,
/// reservation, or durable plan is made.
pub const DEFAULT_IMAGE_TARGET_MARKER: &str = "@configured_default";

/// Owned, already-parsed `generate_image` tool arguments. The tool/schema layer
/// (owned separately) validates the raw JSON, resolves shared-vs-per-target
/// width/height/format, defaults `samples`, and produces this DTO; the dispatch
/// service never re-parses raw tool input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateImageDispatchArgs {
    /// The generation prompt. Held only so the tool layer can hand it through;
    /// it is NEVER placed in a projection, an Approver fact, or a refusal.
    pub prompt: String,
    /// The requested output directory (a daemon-local path). Never surfaced to
    /// the model: only its opened write-authority digest reaches the Approver.
    pub directory: String,
    /// The output filename stem (a validated path component, not a full path).
    pub base_stem: String,
    /// Per-target entries (already distinct and resolved).
    pub targets: Vec<GenerateImageDispatchTarget>,
    /// Typed reference tags (attachment id or daemon-local path). Raw URLs and
    /// provider JSON are rejected upstream at the schema layer.
    pub references: Vec<ImageReferenceTag>,
    /// Internal capability minted only by the native tool's normal write-path
    /// authority check. It binds that check to the exact effective directory;
    /// callers that bypass the tool cannot turn an opened directory into an
    /// authorization fact.
    pub(crate) normal_write_path_digest: Option<String>,
}

/// One resolved per-target entry inside [`GenerateImageDispatchArgs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateImageDispatchTarget {
    pub target_id: String,
    pub samples: u32,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub parameters: BTreeMap<String, TypedParameter>,
    /// Reference tags bound to this target (by index into
    /// [`GenerateImageDispatchArgs::references`]).
    pub reference_indices: Vec<usize>,
}

/// Terminal outcome of [`ImageGenerationDispatchService::dispatch_generate_image`].
///
/// `Refused` is the fail-closed terminal for every rejection path (Approver deny
/// / ask-cancel / standing reject, unconfigured budget, unresolved destination,
/// unavailable output authority): no job is created, no spend or media is
/// reserved, and no provider is contacted. Its `reason` is model-safe (never a
/// prompt, raw path, secret, or reference byte).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenerateImageDispatchOutcome {
    /// The request was authorized and committed as a durable `queued` job.
    Queued { job_id: Uuid },
    /// The request was refused before any spend/media reservation or provider
    /// contact. `reason` is redacted, model-safe copy.
    Refused { reason: String },
    /// Preflight rejected the request against sealed target capability. The
    /// alternatives carry only redacted per-target capability facts.
    Incompatible {
        alternatives: Vec<ImageGenerationTargetAlternativeV1>,
    },
}

/// Redacted, session-safe outcome of
/// [`ImageGenerationDispatchService::job_status`]. `NotFound` hides both a
/// missing job and one owned by another session (existence-hiding). `Status`
/// carries only the durable lifecycle state, plan slot count, cancellation flag,
/// and — once terminal — the safe disjoint slot counts. It NEVER carries a
/// prompt, path, cost, destination, credential, or artifact identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GetImageJobStatusOutcome {
    Status {
        state: String,
        slot_count: u32,
        cancellation_requested: bool,
        terminal: Option<ImageGenerationJobTerminalSummary>,
    },
    NotFound,
}

/// The safe, disjoint terminal slot counts of a finished job. Every count is a
/// non-identifying integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationJobTerminalSummary {
    pub terminal_state: String,
    pub published: u32,
    pub failed: u32,
    pub cancelled: u32,
    pub late_published: u32,
    pub late_quarantined: u32,
    pub discarded: u32,
}

/// Redacted, idempotent outcome of
/// [`ImageGenerationDispatchService::cancel_job`]. `NotFound` hides both a
/// missing job and one owned by another session; `AlreadyTerminal` means the
/// owned job has no cancellable slots left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CancelImageJobOutcome {
    CancellationRequested,
    NotFound,
    AlreadyTerminal,
}

/// Session-scoped funnel that authorizes a `generate_image` tool call through the
/// central [`Approver`] chokepoint and, on `Allow`, turns it into a durable
/// `queued` [`ImageGenerationJobService`] job.
///
/// It lives in this module (alongside the private-field
/// [`ImageGenerationResolutionAuthorityV1`]) so it can assemble the sealed
/// authority directly without any public constructor leaking elsewhere. The
/// pipeline mirrors the chokepoint prompt order: preflight (resolve targets to
/// their sealed destination + capability via the registry) -> authorize (build
/// the immutable plan projection, digest it, and call
/// `Approver::authorize(AuthorizationRequest::ImageGeneration { .. })`) ->
/// spend/media reservation -> job creation. Every fallible real call uses `?`;
/// no `unwrap`/`expect` on a fallible call. Refusal copy is always redacted.
///
/// Redacted identity of the output-path write authority, threaded into
/// [`crate::approval::AuthorizationRequest::ImageGeneration`]. Its private inner
/// string is the opened directory's canonical-destination digest; the ONLY
/// production constructor is [`OutputPathAuthorityId::from_verified_output_directory`],
/// so a raw absolute path can never be wrapped as an authority id and reach the
/// persisted interrupt-prompt sink (`approval/policy.rs`), which reads only
/// [`OutputPathAuthorityId::as_str`]. This is the second half of the inc1-review
/// hard constraint (the first is [`crate::image_generation_agent_tools::PlanDigest`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutputPathAuthorityId(String);

impl OutputPathAuthorityId {
    /// The sole production constructor: the opened, verified output directory's
    /// canonical-destination digest — never a raw path.
    pub(crate) fn from_verified_output_directory(
        authority: &VerifiedOutputDirectoryAuthority,
    ) -> Self {
        Self(authority.0.canonical_destination_digest.clone())
    }

    /// The redacted authority digest, for display at the authz boundary.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only raw constructor. `#[cfg(test)]`-gated so production code
    /// cannot bypass the verified-output-directory constructor.
    #[cfg(test)]
    pub(crate) fn from_raw_for_test(value: impl Into<String>) -> Self {
        Self(value.into())
    }
}

pub struct ImageGenerationDispatchService {
    db: cockpit_db::Db,
    registry: std::sync::RwLock<std::sync::Arc<ImageRuntimeRegistry>>,
    boot_id: uuid::Uuid,
    principal: ClientPrincipal,
    config_generation: std::sync::atomic::AtomicU64,
    base_tier_known_cost_threshold_usd_micros: std::sync::atomic::AtomicU64,
    media_policy: std::sync::RwLock<MediaResourcePolicy>,
    image_config:
        std::sync::RwLock<cockpit_config::config::image_generation::ImageGenerationConfig>,
    media_storage_recovery: Option<std::sync::Arc<crate::media_storage::MediaStorageRecovery>>,
    adapters: std::sync::RwLock<ImageGenerationAdapterMap>,
    /// A failed reload must never leave the prior credential/configuration
    /// pair dispatchable. The service stays installed solely so the next valid
    /// snapshot can repair it without rebuilding session ownership.
    available: std::sync::atomic::AtomicBool,
    config_gate: tokio::sync::RwLock<()>,
    clock: std::sync::Arc<dyn ImageGenerationDispatchClock>,
}

/// Two-domain clock used by session-owned image dispatch. Monotonic time is
/// exclusively for deadlines and leases; Unix time is exclusively for durable
/// epoch columns and spend/accounting records.
pub trait ImageGenerationDispatchClock:
    crate::media_reservation::MonotonicClock + Send + Sync
{
    fn now_unix_ms(&self) -> i64;
}

/// Owns reference-component leases until a queued job transaction takes them
/// over. Every error/refusal path after acquisition must release the durable
/// rows; `Drop` schedules that release for `?` and early-return paths that
/// cannot await cleanup directly. Successful queueing explicitly disarms it.
struct UntransferredReferenceLeases {
    db: cockpit_db::Db,
    leases: Option<Vec<AcquiredMediaComponentLease>>,
    now_unix_ms: i64,
}

impl UntransferredReferenceLeases {
    fn new(db: cockpit_db::Db, leases: Vec<AcquiredMediaComponentLease>, now_unix_ms: i64) -> Self {
        Self {
            db,
            leases: Some(leases),
            now_unix_ms,
        }
    }

    fn leases(&self) -> &[AcquiredMediaComponentLease] {
        self.leases.as_deref().unwrap_or_default()
    }

    fn disarm(&mut self) {
        self.leases = None;
    }

    async fn release_now(&mut self) -> Result<()> {
        let Some(leases) = self.leases.as_ref() else {
            return Ok(());
        };
        ImageGenerationJobService::release_untransferred_reference_leases(
            self.db.clone(),
            leases.clone(),
            self.now_unix_ms,
        )
        .await?;
        // Retain leases until the durable release succeeds. If it fails, Drop
        // still owns them and can schedule the retry path.
        self.leases = None;
        Ok(())
    }
}

impl Drop for UntransferredReferenceLeases {
    fn drop(&mut self) {
        let Some(leases) = self.leases.take() else {
            return;
        };
        let db = self.db.clone();
        let now_unix_ms = self.now_unix_ms;
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            std::mem::drop(handle.spawn(async move {
                if let Err(error) =
                    ImageGenerationJobService::release_untransferred_reference_leases(
                        db,
                        leases,
                        now_unix_ms,
                    )
                    .await
                {
                    tracing::error!(%error, "image generation reference lease cleanup failed");
                }
            }));
        } else {
            tracing::error!("image generation reference leases could not be scheduled for cleanup");
        }
    }
}

impl ImageGenerationDispatchService {
    fn runtime_registry(&self) -> std::sync::Arc<ImageRuntimeRegistry> {
        self.registry
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// `config_generation` must be a published snapshot (`> 0`). Generation `0`
    /// installs the service as unavailable so owner/plan/output-directory gates
    /// cannot be reached with an unpublished snapshot; a later
    /// [`Self::reconcile_config`] with a published generation repairs it.
    pub fn new(
        db: cockpit_db::Db,
        registry: std::sync::Arc<ImageRuntimeRegistry>,
        boot_id: uuid::Uuid,
        principal: ClientPrincipal,
        config_generation: u64,
        base_tier_known_cost_threshold_usd_micros: u64,
        media_policy: MediaResourcePolicy,
        clock: std::sync::Arc<dyn ImageGenerationDispatchClock>,
        media_storage_recovery: Option<std::sync::Arc<crate::media_storage::MediaStorageRecovery>>,
        image_config: cockpit_config::config::image_generation::ImageGenerationConfig,
        adapters: ImageGenerationAdapterMap,
    ) -> Self {
        Self {
            db,
            registry: std::sync::RwLock::new(registry),
            boot_id,
            principal,
            config_generation: std::sync::atomic::AtomicU64::new(config_generation),
            base_tier_known_cost_threshold_usd_micros: std::sync::atomic::AtomicU64::new(
                base_tier_known_cost_threshold_usd_micros,
            ),
            media_policy: std::sync::RwLock::new(media_policy),
            image_config: std::sync::RwLock::new(image_config),
            media_storage_recovery,
            adapters: std::sync::RwLock::new(adapters),
            // Generation 0 is unpublished. Owner, plan, and output-directory
            // gates reject it, so the service must not look available until a
            // published snapshot (`> 0`) is installed.
            available: std::sync::atomic::AtomicBool::new(config_generation > 0),
            config_gate: tokio::sync::RwLock::new(()),
            clock,
        }
    }

    /// Atomically advance the service to a newly published session config
    /// generation. A fresh runtime registry is configured, refreshed, and
    /// used to construct its adapters before it replaces the live pair. A
    /// failed candidate consequently leaves the previous registry/adapters
    /// coherent and retryable; a successful swap makes removed, disabled, or
    /// credential-rotated targets unavailable to subsequent dispatches.
    pub async fn reconcile_config(
        &self,
        config: &cockpit_config::config::image_generation::ImageGenerationConfig,
        media_policy: MediaResourcePolicy,
        generation: u64,
        refresh_epoch: u64,
        credential_store: Result<crate::credentials::CredentialStore>,
    ) -> Result<()> {
        let _gate = self.config_gate.write().await;
        if generation == 0 {
            self.available
                .store(false, std::sync::atomic::Ordering::Release);
            anyhow::bail!("image generation config generation is unpublished");
        }
        let credential_store = match credential_store {
            Ok(store) => store,
            Err(error) => {
                self.available
                    .store(false, std::sync::atomic::Ordering::Release);
                return Err(error
                    .context("refreshed image-generation provider credentials are unavailable"));
            }
        };
        let staged_registry = match self.runtime_registry().staged_for_config(
            config,
            generation,
            refresh_epoch,
            credential_store,
        ) {
            Ok(registry) => std::sync::Arc::new(registry),
            Err(error) => {
                self.available
                    .store(false, std::sync::atomic::Ordering::Release);
                return Err(error.into());
            }
        };
        staged_registry
            .refresh_configured_targets(config, generation, refresh_epoch)
            .await;
        let Some(storage) = self.media_storage_recovery.as_ref().cloned() else {
            self.available
                .store(false, std::sync::atomic::Ordering::Release);
            anyhow::bail!("image generation media storage is unavailable");
        };
        let adapters =
            match crate::daemon::image_generation_adapters::configured_image_generation_adapters(
                self.db.clone(),
                storage,
                staged_registry.clone(),
                config,
            ) {
                Ok(adapters) => adapters,
                Err(error) => {
                    self.available
                        .store(false, std::sync::atomic::Ordering::Release);
                    return Err(error);
                }
            };
        *self
            .registry
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = staged_registry;
        *self
            .image_config
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = config.clone();
        *self
            .adapters
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = adapters;
        self.base_tier_known_cost_threshold_usd_micros.store(
            config.base_tier_known_cost_threshold_usd_micros(),
            std::sync::atomic::Ordering::Release,
        );
        *self
            .media_policy
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = media_policy;
        self.config_generation
            .store(generation, std::sync::atomic::Ordering::Release);
        self.available
            .store(true, std::sync::atomic::Ordering::Release);
        Ok(())
    }

    /// Publish a later session generation without changing destination identity.
    /// Test-only: production publishes generation only through
    /// [`Self::reconcile_config`], which takes this same write lock.
    #[cfg(all(test, feature = "extended"))]
    pub(crate) async fn publish_identity_stable_generation_for_test(&self, generation: u64) {
        let _gate = self.config_gate.write().await;
        self.config_generation
            .store(generation, std::sync::atomic::Ordering::Release);
    }

    /// Safe, redacted, model-facing discovery projections for every configured
    /// image-generation target, for `list_image_generation_targets`. Delegates
    /// to the live runtime registry: disabled targets are excluded by default
    /// (`include_disabled = false`); secrets, headers, raw workflow JSON,
    /// endpoint origins, connected IPs, credential digests, and target
    /// immutable identities are never surfaced. An empty configuration yields
    /// an empty list (not an error). When dispatch is latched unavailable after
    /// a failed reconcile, discovery is withheld explicitly rather than
    /// masquerading as an empty registry.
    pub fn list_targets(
        &self,
        include_disabled: bool,
    ) -> crate::image_generation_agent_tools::ImageGenerationTargetDiscovery {
        if !self.available.load(std::sync::atomic::Ordering::Acquire) {
            return crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::DispatchUnavailable;
        }
        crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::Targets(
            self.runtime_registry()
                .list_target_projections(include_disabled),
        )
    }

    /// Revalidate one queued plan through this session's reconciled runtime.
    /// The daemon lifecycle worker reaches this only through its owner-session
    /// directory, so provider credentials and destinations are never taken
    /// from a process default or another project session.
    pub async fn revalidate_dispatch(
        &self,
        request: DispatchRevalidationRequest<'_>,
    ) -> std::result::Result<DispatchProofBinding, RuntimeError> {
        if !self.available.load(std::sync::atomic::Ordering::Acquire) {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after image generation configuration recovery.",
            ));
        }
        let registry = self.runtime_registry();
        let snapshot = registry
            .current_target_snapshot(request.target_id)
            .ok_or_else(|| {
                RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "Refresh after image generation target configuration changes.",
                )
            })?;
        let endpoint = self
            .image_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .endpoints()
            .iter()
            .find(|endpoint| endpoint.id == snapshot.endpoint_id)
            .cloned()
            .ok_or_else(|| {
                RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "Refresh after image generation target configuration changes.",
                )
            })?;
        let credential = snapshot
            .credential_identity_digest
            .as_ref()
            .ok_or_else(|| {
                RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "Refresh after image generation credentials change.",
                )
            })?;
        if endpoint.origin != snapshot.endpoint_origin
            || !sealed_destination_matches_snapshot(&snapshot, request.destination)
        {
            return Err(RuntimeError::new(
                RuntimeErrorCode::Obsolete,
                "Refresh after image generation destination identity changes.",
            ));
        }
        registry
            .revalidate_dispatch_binding(&endpoint, request.target_id, credential)
            .await
    }

    /// Route a worker handoff through this owner's freshly reconciled target
    /// registry. The daemon-global worker never holds endpoint credentials or
    /// a session-default adapter itself.
    pub(crate) async fn handoff_to_configured_adapter(
        &self,
        kind: ImageAdapterKind,
        request: &ImageGenerationHandoffRequest,
    ) -> ImageGenerationHandoffResult {
        let _gate = self.config_gate.read().await;
        if !self.available.load(std::sync::atomic::Ordering::Acquire) {
            return ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            };
        }
        if self
            .config_generation
            .load(std::sync::atomic::Ordering::Acquire)
            != request.dispatch_config_generation
        {
            return ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"dispatch_proof_config_generation_obsolete".to_vec(),
            };
        }
        let adapter = self
            .adapters
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_target(kind, &request.target_id)
            .cloned();
        match adapter {
            Some(adapter) => adapter.handoff(request).await,
            None => ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            },
        }
    }

    pub(crate) fn configured_handoff_readiness(
        &self,
        kind: ImageAdapterKind,
        request: &ImageGenerationHandoffReadinessRequest<'_>,
    ) -> ImageGenerationHandoffReadiness {
        if !self.available.load(std::sync::atomic::Ordering::Acquire)
            || self
                .adapters
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get_target(kind, request.target_id)
                .is_none()
        {
            return ImageGenerationHandoffReadiness::Deferred {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            };
        }
        let Some(snapshot) = self
            .runtime_registry()
            .current_target_snapshot(request.target_id)
        else {
            return ImageGenerationHandoffReadiness::Deferred {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            };
        };
        if !sealed_destination_matches_snapshot(&snapshot, request.destination) {
            return ImageGenerationHandoffReadiness::Deferred {
                evidence: b"destination_identity_changed".to_vec(),
            };
        }
        ImageGenerationHandoffReadiness::Ready
    }

    /// Recovery operations use the same owner-scoped, target-specific adapter
    /// map as a new handoff. A missing/latched service returns OutcomeUnknown:
    /// it records no invented terminal provider result and remains retryable.
    pub(crate) async fn reconcile_with_configured_adapter(
        &self,
        kind: ImageAdapterKind,
        request: &ImageGenerationReconcileRequest,
    ) -> ImageGenerationReconcileResult {
        let _gate = self.config_gate.read().await;
        if !self.available.load(std::sync::atomic::Ordering::Acquire) {
            return ImageGenerationReconcileResult::OutcomeUnknown {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            };
        }
        match self
            .adapters
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_target(kind, &request.target_id)
            .cloned()
        {
            Some(adapter) => adapter.reconcile(request).await,
            None => ImageGenerationReconcileResult::OutcomeUnknown {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            },
        }
    }

    pub(crate) async fn cancel_with_configured_adapter(
        &self,
        kind: ImageAdapterKind,
        request: &ImageGenerationCancelRequest,
    ) -> ImageGenerationCancelResult {
        let _gate = self.config_gate.read().await;
        if !self.available.load(std::sync::atomic::Ordering::Acquire) {
            return ImageGenerationCancelResult::OutcomeUnknown {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            };
        }
        match self
            .adapters
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_target(kind, &request.target_id)
            .cloned()
        {
            Some(adapter) => adapter.cancel(request).await,
            None => ImageGenerationCancelResult::OutcomeUnknown {
                evidence: b"configured_target_adapter_unavailable".to_vec(),
            },
        }
    }

    /// Convert daemon-local paths that have already passed native read
    /// authorization into owned typed attachments.  This is deliberately part
    /// of the session dispatch authority: it has the same project identity,
    /// media policy, and monotonic clock as the later lease/job transaction.
    /// The durable image request receives only the resulting attachment ids.
    pub async fn register_local_references(
        &self,
        session: &crate::session::Session,
        references: &mut [ImageReferenceTag],
    ) -> Result<()> {
        let Some(storage) = self.media_storage_recovery.as_ref() else {
            anyhow::bail!("image generation media storage is unavailable");
        };
        let canonical_project_digest = crate::intel::hex_lower(&Sha256::digest(
            session.project_root.as_os_str().as_encoded_bytes(),
        ));
        let owner_principal_digest =
            crate::intel::hex_lower(&Sha256::digest(serde_json::to_vec(&self.principal)?));
        let policy = self
            .media_policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let now_monotonic_ms = self.clock.now_ms();
        let now_unix_ms = self.clock.now_unix_ms();
        for reference in references {
            let ImageReferenceTag::LocalPath { local_path } = reference else {
                continue;
            };
            let canonical = Path::new(local_path);
            let relative = canonical
                .strip_prefix(&session.project_root)
                .context("local image reference is outside the session project")?;
            let path = relative
                .to_str()
                .context("local image reference is not valid UTF-8")?
                .to_owned();
            let receipt = storage
                .register_local_path(
                    cockpit_db::media_attachments::RegisterLocalPathMediaV1 {
                        schema_version: 1,
                        kind: "registerLocalPathMedia".into(),
                        local_operation_id: Uuid::now_v7(),
                        owner_principal_digest: owner_principal_digest.clone(),
                        session_id: session.id,
                        canonical_project_digest: canonical_project_digest.clone(),
                        client_draft_id: Uuid::now_v7(),
                        requested_media_kind:
                            cockpit_db::media_attachments::RequestedLocalPathMediaKind::Image,
                        path,
                    },
                    &session.project_root,
                    &policy,
                    now_monotonic_ms,
                    now_unix_ms,
                )
                .await?;
            let cockpit_db::media_attachments::LocalPathRegistrationResultV1::Registered {
                attachment_id,
                ..
            } = receipt.result
            else {
                anyhow::bail!("local image reference could not be registered");
            };
            *reference = ImageReferenceTag::Attachment {
                attachment_id: attachment_id.to_string(),
            };
        }
        Ok(())
    }

    /// Authorize and (on `Allow`) commit a `generate_image` request.
    pub async fn dispatch_generate_image(
        &self,
        session: &crate::session::Session,
        approver: &Approver,
        args: &GenerateImageDispatchArgs,
    ) -> Result<GenerateImageDispatchOutcome> {
        // Take only a short snapshot lock. Human approval can wait indefinitely;
        // retaining the config lock while it is parked would block reload and
        // make every later queue operation observe stale configuration.
        let dispatch_config_generation = {
            let _gate = self.config_gate.read().await;
            if !self.available.load(std::sync::atomic::Ordering::Acquire) {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_PREFLIGHT_UNAVAILABLE.to_string(),
                });
            }
            self.config_generation
                .load(std::sync::atomic::Ordering::Acquire)
        };
        let mut resolved_args = args.clone();
        if resolved_args.targets.len() == 1
            && resolved_args.targets[0].target_id == DEFAULT_IMAGE_TARGET_MARKER
        {
            let Some(target_id) = self.runtime_registry().configured_default_target_id() else {
                let reason = if self
                    .runtime_registry()
                    .list_target_projections(false)
                    .is_empty()
                {
                    DISPATCH_NOT_CONFIGURED
                } else {
                    DISPATCH_NO_DEFAULT_TARGET
                };
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: reason.to_string(),
                });
            };
            resolved_args.targets[0].target_id = target_id;
        }
        if resolved_args.targets.is_empty()
            || resolved_args
                .targets
                .iter()
                .any(|target| target.target_id == DEFAULT_IMAGE_TARGET_MARKER)
        {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_NO_TARGETS.to_string(),
            });
        }
        // (1) Preflight: resolve every requested target to its sealed
        // destination (adapter kind + connected location class) via the image
        // runtime registry.
        let Some(destinations) = self.resolve_projection_destinations(&resolved_args)? else {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_UNKNOWN_TARGET.to_string(),
            });
        };

        // Resolve the exact format, dimensions, and typed parameters against
        // the sealed live capability before an approval can be requested. An
        // incompatible request has no stable executable plan/digest to show a
        // human, and must never turn into a standing grant.
        let capability_preflight = match self.preflight_target_capabilities(&resolved_args) {
            Ok(result) => result,
            Err(_) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_TARGET_NOT_DISPATCH_READY.to_string(),
                });
            }
        };
        if let Some(alternatives) = capability_preflight {
            return Ok(GenerateImageDispatchOutcome::Incompatible { alternatives });
        }

        // (2) Hold the output directory as the write authority. Its opened
        // canonical-destination digest is the ONLY output-path fact that reaches
        // the Approver — never the raw path. A failure to open is a redacted
        // refusal, never a raw-path error surfaced to the model.
        let held = match open_image_generation_output_directory(
            Path::new(&resolved_args.directory),
            dispatch_config_generation,
            resolved_args.base_stem.clone(),
        ) {
            Ok(held) => held,
            Err(_) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_OUTPUT_DIR_UNAVAILABLE.to_string(),
                });
            }
        };
        let output_path_authority = held.authority().0.canonical_destination_digest.clone();
        let output_path_authority_id =
            OutputPathAuthorityId::from_verified_output_directory(held.authority());
        let effective_output_path_digest =
            crate::intel::hex_lower(&Sha256::digest(resolved_args.directory.as_bytes()));
        let output_write_authorized = resolved_args.normal_write_path_digest.as_deref()
            == Some(effective_output_path_digest.as_str());
        // Local-path references are not read-authorized at this seam yet; an
        // attachment-only reference set needs no local read authority.
        let path_read_authorized = resolved_args
            .references
            .iter()
            .all(|reference| matches!(reference, ImageReferenceTag::Attachment { .. }));
        let reference_identity_digests = self
            .reference_identity_digests(session, &resolved_args.references)
            .await?;

        // (3) Spend policy choices. An unconfigured scope is a hard block: refuse
        // before contacting the Approver, reserving spend, or contacting any
        // provider.
        let Some(policy) = self
            .db
            .current_image_spend_policy(session.project_id.clone())
            .await?
        else {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_SPEND_POLICY_UNAVAILABLE.to_string(),
            });
        };
        let Some((spend_request, spend_session, spend_project)) =
            Self::spend_policy_choices(&policy.settings)
        else {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_SPEND_POLICY_UNAVAILABLE.to_string(),
            });
        };

        // (4) Build the immutable plan projection and digest it. The projection
        // carries only redacted facts (destination classes, sizes, formats,
        // parameters, counts) and the output write-authority digest — no prompt
        // text, raw path, provider secret, or reference bytes.
        let fanout = destinations.len() as u32;
        let total_outputs: u32 = resolved_args
            .targets
            .iter()
            .map(|target| target.samples)
            .fold(0_u32, |total, samples| total.saturating_add(samples));
        // Prices are part of the target configuration and include freshness
        // evidence. Calculate the conservative maximum from the exact target,
        // output dimensions, sample count, and retry bound. Any stale,
        // unsupported-unit, missing, or overflowing price remains unknown and
        // therefore follows the existing fail-closed unknown-cost policy.
        let target_attempt_costs = self.estimated_target_attempt_costs(&resolved_args);
        let cost_maximum = target_attempt_costs
            .as_ref()
            .and_then(|costs| self.estimated_cost_maximum(&resolved_args, costs));
        let budget_disposition = Self::budget_disposition(&policy.settings, cost_maximum);
        let reference_egress = !resolved_args.references.is_empty()
            && destinations
                .iter()
                .any(|destination| !matches!(destination.location_class, LocationClass::Local));
        let projection = ImageGenerationPlanProjection {
            destinations: destinations.clone(),
            prompt_collapsed: true,
            prompt_digest: crate::intel::hex_lower(&Sha256::digest(args.prompt.as_bytes())),
            references: resolved_args
                .targets
                .iter()
                .flat_map(|target| {
                    reference_identity_digests
                        .iter()
                        .map(move |identity_digest| {
                            ProjectionReference {
                                // Bind every reference to every target it can
                                // egress to. The target association is not merely
                                // display data: it is part of the approval digest.
                                identity_digest: identity_digest.clone(),
                                thumbnail: false,
                                destination_target_id: target.target_id.clone(),
                            }
                        })
                })
                .collect(),
            target_requests: resolved_args
                .targets
                .iter()
                .map(|target| ProjectionTargetRequest {
                    target_id: target.target_id.clone(),
                    width: target.width,
                    height: target.height,
                    format: target.format.clone(),
                    samples: target.samples,
                    parameters: target.parameters.clone(),
                })
                .collect(),
            sizes: resolved_args
                .targets
                .iter()
                .map(|target| ProjectionSize {
                    target_id: target.target_id.clone(),
                    width: target.width,
                    height: target.height,
                })
                .collect(),
            formats: {
                let mut formats: Vec<String> = resolved_args
                    .targets
                    .iter()
                    .map(|target| target.format.clone())
                    .collect();
                formats.sort();
                formats.dedup();
                formats
            },
            parameters: {
                let mut parameters = BTreeMap::new();
                for target in &resolved_args.targets {
                    for (key, value) in &target.parameters {
                        parameters.insert(key.clone(), value.clone());
                    }
                }
                parameters
            },
            fanout,
            total_outputs,
            cost_maximum,
            budget_disposition,
            output_directory: output_path_authority.clone(),
            output_base_stem: resolved_args.base_stem.clone(),
            digest: String::new(),
        };
        let plan_digest = plan_projection_digest(&projection)?;

        let target_ids: Vec<String> = resolved_args
            .targets
            .iter()
            .map(|target| target.target_id.clone())
            .collect();
        let Some(destination_grant_binding_digest) = self
            .runtime_registry()
            .destination_grant_binding_digest(&target_ids)
        else {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_TARGET_NOT_DISPATCH_READY.to_string(),
            });
        };

        // (5) Hard gates sourced from the registry health / capability /
        // transport snapshot per resolved destination.
        let (destination_enabled, capability_fresh, insecure_transport_allowed) =
            self.resolve_destination_gates(&destinations)?;

        // (6) Central authorization chokepoint. Never a faked allow.
        let decision = approver
            .authorize(AuthorizationRequest::ImageGeneration {
                plan_digest: &plan_digest,
                destination_grant_binding_digest: &destination_grant_binding_digest,
                destinations: destinations.as_slice(),
                fanout,
                total_outputs,
                cost_maximum,
                reference_egress,
                base_threshold_usd_micros: self
                    .base_tier_known_cost_threshold_usd_micros
                    .load(std::sync::atomic::Ordering::Acquire),
                spend_request,
                spend_session,
                spend_project,
                path_read_authorized,
                output_write_authorized,
                destination_enabled,
                capability_fresh,
                insecure_transport_allowed,
                output_path_authority: &output_path_authority_id,
            })
            .await?;
        if !matches!(decision, Decision::Allow { .. }) {
            // Deny / ask-cancel / standing reject: no job, no spend, no media, no
            // provider contact.
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: Self::image_generation_authorize_refusal(
                    &decision,
                    destination_enabled,
                    capability_fresh,
                    path_read_authorized,
                    output_write_authorized,
                    insecure_transport_allowed,
                    cost_maximum,
                    budget_disposition,
                ),
            });
        }

        // Reacquire only after the human decision. Destination identity is the
        // commit fence: adapter kind, location class, and the grant-binding
        // digest (endpoint origin, target immutable identity, workflow, and
        // credential). A later snapshot whose identity is unchanged must not
        // discard Allow or skip grant persist — session-wide `config_generation`
        // also moves for hooks, providers, other extended fields, and trust.
        // Removal, credential rotation, or a latched-unavailable reload still
        // refuse. `config_gate` is held here and through `commit_queued_job`;
        // `reconcile_config` writes under the same gate. Do not add a lock.
        let _commit_gate = self.config_gate.read().await;
        if !self.available.load(std::sync::atomic::Ordering::Acquire)
            || self.resolve_projection_destinations(&resolved_args)? != Some(destinations.clone())
            || self
                .runtime_registry()
                .destination_grant_binding_digest(&target_ids)
                != Some(destination_grant_binding_digest.clone())
        {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_PREFLIGHT_UNAVAILABLE.to_string(),
            });
        }

        // (7) Allow: reserve spend + media, resolve, and commit the queued job.
        let standing_grant = match decision {
            Decision::Allow {
                scope:
                    scope @ (crate::approval::store::Scope::Session
                    | crate::approval::store::Scope::Project),
            } => Some(ImageGenerationStandingGrant {
                scope,
                session_id: session.id,
                project_id: session.project_id.clone(),
                destination_binding_digest: destination_grant_binding_digest,
                output_path_authority,
                reference_egress,
                maximum_fanout: fanout,
                maximum_total_outputs: total_outputs,
                maximum_known_cost_usd_micros: cost_maximum,
                unknown_cost_allowed: cost_maximum.is_none()
                    && matches!(budget_disposition, BudgetDisposition::UnknownCostAllowed),
            }),
            Decision::Allow {
                scope: crate::approval::store::Scope::Once,
            }
            | Decision::Deny
            | Decision::NoninteractiveDeny
            | Decision::StandingReject { .. } => None,
            Decision::Allow {
                scope: crate::approval::store::Scope::Global,
            } => unreachable!("image generation never offers global approval"),
        };
        self.commit_queued_job(
            session,
            &resolved_args,
            &policy,
            &plan_digest,
            held,
            standing_grant,
            cost_maximum,
            target_attempt_costs,
        )
        .await
    }

    /// Return the redacted, session-authorized status of an image-generation job.
    ///
    /// The live attached session's owner identity is derived exactly as
    /// [`Self::commit_queued_job`] derives it (session id + principal, revalidated
    /// against the durable session), then handed to the owner-scoped cockpit-db
    /// reader. A job that does not exist, or that belongs to another session, is
    /// reported as [`GetImageJobStatusOutcome::NotFound`] — the two are
    /// indistinguishable (existence-hiding). An owner-context that cannot be
    /// established for this session is likewise `NotFound`. No prompt, path, cost,
    /// destination, credential, or artifact identity is ever surfaced, and no
    /// content is opened.
    pub async fn job_status(
        &self,
        session: &crate::session::Session,
        job_id: Uuid,
    ) -> Result<GetImageJobStatusOutcome> {
        let principal = self.principal.clone();
        let session_id = session.id;
        let config_generation = self
            .config_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let outcome = self
            .db
            .read(move |conn| {
                let owner = match ImageGenerationOwnerContextAuthority::from_attached_session(
                    conn,
                    session_id,
                    &principal,
                    config_generation,
                ) {
                    Ok(owner) => owner,
                    Err(_) => {
                        return Ok(cockpit_db::db::image_generation::OwnedImageGenerationJobStatus::NotFound);
                    }
                };
                let scope = cockpit_db::db::image_generation::ImageGenerationJobOwnerScope {
                    owner_session_id: owner.session_id,
                    owner_principal_digest: &owner.principal_digest,
                    project_identity_digest: &owner.project_identity_digest,
                };
                cockpit_db::Db::read_owned_image_generation_job_status_conn(conn, job_id, &scope)
            })
            .await?;
        Ok(match outcome {
            cockpit_db::db::image_generation::OwnedImageGenerationJobStatus::Status(safe) => {
                GetImageJobStatusOutcome::Status {
                    state: safe.state.as_str().to_string(),
                    slot_count: safe.slot_count,
                    cancellation_requested: safe.cancellation_requested,
                    terminal: safe
                        .terminal
                        .map(|counts| ImageGenerationJobTerminalSummary {
                            terminal_state: counts.terminal_state.as_str().to_string(),
                            published: counts.published_count,
                            failed: counts.failed_count,
                            cancelled: counts.cancelled_count,
                            late_published: counts.late_published_count,
                            late_quarantined: counts.late_quarantined_count,
                            discarded: counts.discarded_count,
                        }),
                }
            }
            cockpit_db::db::image_generation::OwnedImageGenerationJobStatus::NotFound => {
                GetImageJobStatusOutcome::NotFound
            }
        })
    }

    /// Request idempotent, owner-checked cancellation of an image-generation job.
    ///
    /// Owner identity is derived from the live attached session exactly as
    /// [`Self::job_status`], then handed to the owner-scoped cockpit-db cancel
    /// wrapper (which verifies ownership before invoking the existing
    /// cancellation CAS). A missing job, a job owned by another session, or an
    /// owner-context that cannot be established is reported as
    /// [`CancelImageJobOutcome::NotFound`] (existence-hiding);
    /// `AlreadyTerminal` means the owned job has no cancellable slots. No prompt,
    /// path, cost, or another session's data is surfaced.
    pub async fn cancel_job(
        &self,
        session: &crate::session::Session,
        job_id: Uuid,
    ) -> Result<CancelImageJobOutcome> {
        let principal = self.principal.clone();
        let session_id = session.id;
        let config_generation = self
            .config_generation
            .load(std::sync::atomic::Ordering::Acquire);
        let requested_at_unix_ms = self.clock.now_unix_ms();
        // A deterministic per-job operation id: the first cancellation of the job
        // consumes it, and any later owner request is reported idempotently
        // without re-invoking the CAS.
        let request_operation_id = format!("agent-cancel:{job_id}");
        let outcome = self
            .db
            .transaction(move |conn| {
                let owner = match ImageGenerationOwnerContextAuthority::from_attached_session(
                    conn,
                    session_id,
                    &principal,
                    config_generation,
                ) {
                    Ok(owner) => owner,
                    Err(_) => {
                        return Ok(cockpit_db::db::image_generation::OwnedImageGenerationCancellation::NotFound);
                    }
                };
                let scope = cockpit_db::db::image_generation::ImageGenerationJobOwnerScope {
                    owner_session_id: owner.session_id,
                    owner_principal_digest: &owner.principal_digest,
                    project_identity_digest: &owner.project_identity_digest,
                };
                cockpit_db::Db::request_owned_image_generation_cancellation_conn(
                    conn,
                    &cockpit_db::db::image_generation::OwnedImageGenerationCancellationRequest {
                        job_id,
                        scope,
                        cancellation_version: 1,
                        request_operation_id: &request_operation_id,
                        requested_at_unix_ms,
                    },
                )
            })
            .await?;
        Ok(match outcome {
            cockpit_db::db::image_generation::OwnedImageGenerationCancellation::CancellationRequested => {
                CancelImageJobOutcome::CancellationRequested
            }
            cockpit_db::db::image_generation::OwnedImageGenerationCancellation::NotFound => {
                CancelImageJobOutcome::NotFound
            }
            cockpit_db::db::image_generation::OwnedImageGenerationCancellation::AlreadyTerminal => {
                CancelImageJobOutcome::AlreadyTerminal
            }
        })
    }

    /// Resolve each requested target to its sealed [`ProjectionDestination`]
    /// (adapter kind + connected location class) via the image runtime registry.
    ///
    /// Returns `Ok(None)` (fail closed) when any requested target has no resolved
    /// sealed destination, so the caller refuses without contacting the Approver.
    ///
    /// The registry is reconciled from the live session config at startup and
    /// on every accepted `ReplaceConfigSnapshot`; it supplies the current
    /// target/endpoint association and rejects removed or stale targets.
    fn resolve_projection_destinations(
        &self,
        args: &GenerateImageDispatchArgs,
    ) -> Result<Option<Vec<ProjectionDestination>>> {
        let mut destinations = Vec::with_capacity(args.targets.len());
        for target in &args.targets {
            let Some((destination, _, _, _)) = self
                .runtime_registry()
                .resolve_dispatch_target(&target.target_id)
            else {
                return Ok(None);
            };
            destinations.push(destination);
        }
        if destinations.len() != args.targets.len() {
            return Ok(None);
        }
        Ok(Some(destinations))
    }

    /// Resolve the `destination_enabled` / `capability_fresh` /
    /// `insecure_transport_allowed` hard gates from the registry health +
    /// transport snapshot for each resolved destination.
    ///
    /// Every value comes from the reconciled registry snapshot. A missing,
    /// disabled, stale, or replaced target fails the complete gate tuple.
    fn resolve_destination_gates(
        &self,
        destinations: &[ProjectionDestination],
    ) -> Result<(bool, bool, bool)> {
        let mut enabled = true;
        let mut fresh = true;
        let mut transport_allowed = true;
        for destination in destinations {
            let Some((_, target_enabled, capability_fresh, insecure_transport_allowed)) = self
                .runtime_registry()
                .resolve_dispatch_target(&destination.target_id)
            else {
                return Ok((false, false, false));
            };
            enabled &= target_enabled;
            fresh &= capability_fresh;
            transport_allowed &= insecure_transport_allowed;
        }
        Ok((enabled, fresh, transport_allowed))
    }

    /// Check the part of `resolve_image_generation` that depends solely on the
    /// current sealed target capabilities. This deliberately runs before the
    /// Approver; the later full resolver repeats it with owner, lease, spend,
    /// and output authorities immediately before durable queueing.
    fn preflight_target_capabilities(
        &self,
        args: &GenerateImageDispatchArgs,
    ) -> Result<Option<Vec<ImageGenerationTargetAlternativeV1>>> {
        let policy = self
            .media_policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let deadline_seconds = image_generation_media_plans(&policy, 1)?
            .into_iter()
            .find(|plan| {
                plan.dimension
                    == cockpit_config::config::media_budget::MediaDimension::OperationDeadlineSeconds
            })
            .context("image generation media policy omits an operation deadline")?
            .requested;
        let now = self.clock.now_ms();
        let deadline = now
            .checked_add(deadline_seconds.saturating_mul(1_000))
            .context("image generation operation deadline overflow")?;
        let reference_attachment_ids = args
            .references
            .iter()
            .map(|reference| match reference {
                ImageReferenceTag::Attachment { attachment_id } => Uuid::parse_str(attachment_id)
                    .context("image generation reference identifier is invalid"),
                ImageReferenceTag::LocalPath { .. } => {
                    anyhow::bail!("local image reference is not registered")
                }
            })
            .collect::<Result<Vec<_>>>()?;
        let registry = self.runtime_registry();
        let mut alternatives = Vec::new();
        for target in &args.targets {
            let snapshot = registry
                .current_target_snapshot(&target.target_id)
                .context("image generation target is no longer dispatchable")?;
            let runtime =
                RuntimeTargetAuthorityV1::from_registry_snapshot(&snapshot, now, deadline)?;
            let request = ImageGenerationTargetRequestV1 {
                target_id: target.target_id.clone(),
                width: target.width,
                height: target.height,
                format: target.format.clone(),
                samples: target.samples,
                parameters: Self::to_plan_parameters(&target.parameters),
            };
            if let Some(alternative) =
                runtime.capability_incompatibility(&request, &reference_attachment_ids)
            {
                alternatives.push(alternative);
            }
        }
        Ok((!alternatives.is_empty()).then_some(alternatives))
    }

    /// Return the known conservative cost of one provider submission for each
    /// selected target. `None` is intentionally infectious: the configured
    /// price source has an explicit unknown/stale state and a seconds-priced
    /// operation has no sealed duration bound in v1.
    fn estimated_target_attempt_costs(
        &self,
        args: &GenerateImageDispatchArgs,
    ) -> Option<BTreeMap<String, u64>> {
        use cockpit_config::config::image_generation::{ImageBillableUnit, ImagePrice};

        let config = self
            .image_config
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let now = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(self.clock.now_unix_ms())?;
        args.targets
            .iter()
            .map(|requested| {
                let target = config
                    .targets()
                    .iter()
                    .find(|target| target.id == requested.target_id)?;
                let ImagePrice::Known {
                    usd_micros, unit, ..
                } = target.price.effective_at(now.clone())
                else {
                    return None;
                };
                let units = match unit {
                    ImageBillableUnit::Image => 1,
                    ImageBillableUnit::Megapixel => u64::from(requested.width)
                        .checked_mul(u64::from(requested.height))?
                        .div_ceil(1_000_000),
                    ImageBillableUnit::Second => return None,
                };
                Some((requested.target_id.clone(), usd_micros.checked_mul(units)?))
            })
            .collect()
    }

    fn estimated_cost_maximum(
        &self,
        args: &GenerateImageDispatchArgs,
        target_attempt_costs: &BTreeMap<String, u64>,
    ) -> Option<u64> {
        let registry = self.runtime_registry();
        args.targets.iter().try_fold(0_u64, |total, requested| {
            let attempt_cost = *target_attempt_costs.get(&requested.target_id)?;
            let max_attempts = u64::from(
                registry
                    .current_target_snapshot(&requested.target_id)?
                    .capability?
                    .constraints
                    .get("max_attempts")?
                    .parse::<u32>()
                    .ok()?,
            );
            total.checked_add(
                attempt_cost
                    .checked_mul(u64::from(requested.samples))?
                    .checked_mul(max_attempts)?,
            )
        })
    }

    /// Read the exact owned attachment identity/version/checksum before the
    /// approval prompt. This is read-only (a deny creates no lease, job, spend,
    /// or media reservation), but makes an approval digest specific to the
    /// immutable reference material that a later commit must lease again.
    async fn reference_identity_digests(
        &self,
        session: &crate::session::Session,
        references: &[ImageReferenceTag],
    ) -> Result<Vec<String>> {
        let owner = {
            let principal = self.principal.clone();
            let generation = self
                .config_generation
                .load(std::sync::atomic::Ordering::Acquire);
            let session_id = session.id;
            self.db
                .read(move |conn| {
                    ImageGenerationOwnerContextAuthority::from_attached_session(
                        conn, session_id, &principal, generation,
                    )
                })
                .await?
        };
        let references = references.to_vec();
        let attachment_ids = references
            .iter()
            .map(|reference| match reference {
                ImageReferenceTag::Attachment { attachment_id } => Uuid::parse_str(attachment_id)
                    .context("image generation reference identifier is invalid")
                    .map(Some),
                // Local paths cannot reach authorization because the normal
                // read-authority gate is not installed at this seam yet.
                ImageReferenceTag::LocalPath { .. } => Ok(None),
            })
            .collect::<Result<Vec<_>>>()?;
        self.db
            .read(move |conn| {
                references
                    .iter()
                    .zip(attachment_ids)
                    .map(|(reference, attachment_id)| match reference {
                        ImageReferenceTag::Attachment { .. } => {
                            let attachment_id = attachment_id
                                .context("image generation reference identifier is invalid")?;
                            let attachment = cockpit_db::Db::media_attachment_for_owner_conn(
                                conn,
                                attachment_id,
                                owner.session_id,
                                &owner.project_identity_digest,
                            )?
                            .context("image generation reference is unavailable")?;
                            Ok(digest_fields(&[
                                "attachment",
                                &attachment.attachment_id.to_string(),
                                &attachment.attachment_version.to_string(),
                                &attachment.source_identity_digest,
                                &attachment.source_sha256,
                            ]))
                        }
                        ImageReferenceTag::LocalPath { local_path } => {
                            Ok(digest_fields(&["local_path", local_path]))
                        }
                    })
                    .collect::<Result<Vec<_>>>()
            })
            .await
    }

    /// Map the three [`BudgetPolicy`] scopes onto [`SpendPolicyChoice`]. An
    /// `Unconfigured` scope is a hard block (returns `None`).
    fn spend_policy_choices(
        settings: &ImageSpendSettings,
    ) -> Option<(SpendPolicyChoice, SpendPolicyChoice, SpendPolicyChoice)> {
        Some((
            Self::budget_policy_choice(&settings.request)?,
            Self::budget_policy_choice(&settings.session)?,
            Self::budget_policy_choice(&settings.project)?,
        ))
    }

    fn budget_policy_choice(policy: &BudgetPolicy) -> Option<SpendPolicyChoice> {
        match policy {
            BudgetPolicy::Unlimited => Some(SpendPolicyChoice::Unlimited),
            BudgetPolicy::Finite { usd_micros } => Some(SpendPolicyChoice::Finite {
                usd_micros: *usd_micros,
            }),
            BudgetPolicy::Unconfigured => None,
        }
    }

    fn budget_disposition(
        settings: &ImageSpendSettings,
        cost_maximum: Option<u64>,
    ) -> BudgetDisposition {
        match cost_maximum {
            Some(_) => BudgetDisposition::WithinBudget,
            None => {
                if settings.request == BudgetPolicy::Unlimited
                    && settings.session == BudgetPolicy::Unlimited
                    && settings.project == BudgetPolicy::Unlimited
                {
                    BudgetDisposition::UnknownCostAllowed
                } else {
                    BudgetDisposition::UnknownCostBlocked
                }
            }
        }
    }

    fn image_generation_authorize_refusal(
        decision: &Decision,
        destination_enabled: bool,
        capability_fresh: bool,
        path_read_authorized: bool,
        output_write_authorized: bool,
        insecure_transport_allowed: bool,
        cost_maximum: Option<u64>,
        budget_disposition: BudgetDisposition,
    ) -> String {
        if matches!(decision, Decision::Deny) {
            if let Some(reason) = Self::image_generation_hard_gate_refusal(
                destination_enabled,
                capability_fresh,
                path_read_authorized,
                output_write_authorized,
                insecure_transport_allowed,
                cost_maximum,
                budget_disposition,
            ) {
                return reason.to_string();
            }
        }
        Self::refusal_reason(decision)
    }

    fn image_generation_hard_gate_refusal(
        destination_enabled: bool,
        capability_fresh: bool,
        path_read_authorized: bool,
        output_write_authorized: bool,
        insecure_transport_allowed: bool,
        cost_maximum: Option<u64>,
        budget_disposition: BudgetDisposition,
    ) -> Option<&'static str> {
        if !destination_enabled {
            return Some(DISPATCH_HARD_GATE_DISABLED_TARGET);
        }
        if !capability_fresh {
            return Some(DISPATCH_HARD_GATE_STALE_CAPABILITY);
        }
        if !output_write_authorized {
            return Some(DISPATCH_HARD_GATE_OUTPUT_WRITE);
        }
        if !path_read_authorized {
            return Some(DISPATCH_HARD_GATE_PATH_READ);
        }
        if !insecure_transport_allowed {
            return Some(DISPATCH_HARD_GATE_INSECURE_TRANSPORT);
        }
        if cost_maximum.is_none() && budget_disposition != BudgetDisposition::UnknownCostAllowed {
            return Some(DISPATCH_HARD_GATE_UNKNOWN_COST);
        }
        None
    }

    fn refusal_reason(decision: &Decision) -> String {
        match decision {
            Decision::Allow { .. } => String::new(),
            Decision::Deny => "image generation was declined at the approval prompt.".to_string(),
            Decision::NoninteractiveDeny => crate::approval::NONINTERACTIVE_RUN_DENIAL.to_string(),
            Decision::StandingReject { .. } => {
                "image generation is disallowed by a saved user decision.".to_string()
            }
        }
    }

    fn dispatch_spend_reservation_refusal(error: &anyhow::Error) -> &'static str {
        error
            .downcast_ref::<BudgetBlockReason>()
            .map(|reason| match reason {
                BudgetBlockReason::PolicyVersionChanged
                | BudgetBlockReason::InvalidProjectEpoch => DISPATCH_SPEND_POLICY_CHANGED,
                BudgetBlockReason::RequestUnconfigured
                | BudgetBlockReason::SessionUnconfigured
                | BudgetBlockReason::ProjectUnconfigured
                | BudgetBlockReason::ProjectEpochUnconfigured => DISPATCH_SPEND_POLICY_UNAVAILABLE,
                BudgetBlockReason::RequestExhausted
                | BudgetBlockReason::SessionExhausted
                | BudgetBlockReason::ProjectExhausted
                | BudgetBlockReason::RequestDebt
                | BudgetBlockReason::SessionDebt
                | BudgetBlockReason::ProjectDebt => DISPATCH_SPEND_RESERVATION_BLOCKED,
                BudgetBlockReason::UnknownMaximumWithFinitePolicy => {
                    DISPATCH_HARD_GATE_UNKNOWN_COST
                }
                BudgetBlockReason::ArithmeticOverflow
                | BudgetBlockReason::ReservationTerminal
                | BudgetBlockReason::EmptyPlan => DISPATCH_COMMIT_UNAVAILABLE,
            })
            .unwrap_or(DISPATCH_COMMIT_UNAVAILABLE)
    }

    fn dispatch_media_reservation_refusal(error: &LedgerError) -> &'static str {
        match error {
            LedgerError::Denied(_) => DISPATCH_MEDIA_RESERVATION_BLOCKED,
            LedgerError::AccountingBlocked => DISPATCH_MEDIA_ACCOUNTING_BLOCKED,
            LedgerError::StaleVersion
            | LedgerError::InvalidTransition
            | LedgerError::Overflow
            | LedgerError::Storage(_) => DISPATCH_COMMIT_UNAVAILABLE,
        }
    }

    fn to_plan_parameters(
        source: &BTreeMap<String, TypedParameter>,
    ) -> BTreeMap<String, TypedParameterV1> {
        source
            .iter()
            .map(|(key, value)| {
                let converted = match value {
                    TypedParameter::Boolean(flag) => TypedParameterV1::Boolean(*flag),
                    TypedParameter::Integer(number) => TypedParameterV1::Integer(*number),
                    TypedParameter::Text(text) => TypedParameterV1::Text(text.clone()),
                };
                (key.clone(), converted)
            })
            .collect()
    }

    /// On `Allow`: build the immutable request (ids sorted + deduped exactly as
    /// [`resolve_image_generation`] requires), assemble the sealed
    /// [`ImageGenerationResolutionAuthorityV1`], reserve spend + media, resolve,
    /// and commit the queued job via [`ImageGenerationJobService::create_queued_job`].
    async fn commit_queued_job(
        &self,
        session: &crate::session::Session,
        args: &GenerateImageDispatchArgs,
        policy: &CurrentImageSpendPolicy,
        plan_digest: &PlanDigest,
        held: HeldImageGenerationOutputDirectory,
        standing_grant: Option<ImageGenerationStandingGrant>,
        cost_maximum: Option<u64>,
        target_attempt_costs: Option<BTreeMap<String, u64>>,
    ) -> Result<GenerateImageDispatchOutcome> {
        // Immutable request: target envelopes + reference ids strictly increasing.
        let mut targets: Vec<ImageGenerationTargetRequestV1> = args
            .targets
            .iter()
            .map(|target| ImageGenerationTargetRequestV1 {
                target_id: target.target_id.clone(),
                width: target.width,
                height: target.height,
                format: target.format.clone(),
                samples: target.samples,
                parameters: Self::to_plan_parameters(&target.parameters),
            })
            .collect();
        targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        let mut reference_attachment_ids: Vec<Uuid> = args
            .references
            .iter()
            .filter_map(|reference| match reference {
                ImageReferenceTag::Attachment { attachment_id } => {
                    Uuid::parse_str(attachment_id).ok()
                }
                ImageReferenceTag::LocalPath { .. } => None,
            })
            .collect();
        reference_attachment_ids.sort();
        reference_attachment_ids.dedup();
        let request = ImageGenerationRequestV1 {
            targets,
            reference_attachment_ids,
        };

        // Owner context authority, revalidated against the live attached session.
        let owner = {
            let principal = self.principal.clone();
            let session_id = session.id;
            let config_generation = self
                .config_generation
                .load(std::sync::atomic::Ordering::Acquire);
            self.db
                .read(move |conn| {
                    ImageGenerationOwnerContextAuthority::from_attached_session(
                        conn,
                        session_id,
                        &principal,
                        config_generation,
                    )
                })
                .await
        };
        let owner = match owner {
            Ok(owner) => owner,
            Err(_) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_OWNER_UNAVAILABLE.to_string(),
                });
            }
        };

        let now_monotonic_ms = self.clock.now_ms();
        let created_at_unix_ms = self.clock.now_unix_ms();
        let reference_attachment_ids = request.reference_attachment_ids.clone();
        let reference_leases = {
            let owner = owner.clone();
            self.db
                .transaction(move |conn| {
                    reference_attachment_ids
                        .into_iter()
                        .map(|attachment_id| {
                            let attachment = cockpit_db::Db::media_attachment_for_owner_conn(
                                conn,
                                attachment_id,
                                owner.session_id,
                                &owner.project_identity_digest,
                            )?
                            .context("image generation reference is unavailable")?;
                            cockpit_db::Db::acquire_media_component_lease_conn(
                                conn,
                                AcquireMediaComponentLeaseInput {
                                    lease_id: Uuid::now_v7(),
                                    attachment_id,
                                    expected_version: attachment.attachment_version,
                                    expected_availability_generation: attachment
                                        .availability_generation,
                                    expected_capability_generation: attachment
                                        .captured_capability_generation,
                                    kind: MediaComponentLeaseKind::Model,
                                    now_unix_ms: created_at_unix_ms,
                                },
                            )
                        })
                        .collect::<Result<Vec<_>>>()
                })
                .await
        };
        let reference_leases = match reference_leases {
            Ok(leases) => leases,
            Err(_) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_PREFLIGHT_UNAVAILABLE.to_string(),
                });
            }
        };
        let mut reference_lease_cleanup = UntransferredReferenceLeases::new(
            self.db.clone(),
            reference_leases,
            created_at_unix_ms,
        );
        let references = reference_lease_cleanup
            .leases()
            .iter()
            .map(reference_artifact_from_acquired_media_lease)
            .collect::<Result<Vec<_>>>()?;
        let media_policy = self
            .media_policy
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let media_plan = image_generation_media_plans(&media_policy, 1)?;
        let deadline_plan = media_plan
            .iter()
            .find(|plan| {
                plan.dimension
                    == cockpit_config::config::media_budget::MediaDimension::OperationDeadlineSeconds
            })
            .context("image generation media policy omits an operation deadline")?
            .clone();
        let operation_deadline_monotonic_ms = now_monotonic_ms
            .checked_add(deadline_plan.requested.saturating_mul(1_000))
            .context("image generation operation deadline overflow")?;

        let snapshots = request
            .targets
            .iter()
            .map(|target| {
                self.runtime_registry()
                    .current_target_snapshot(&target.target_id)
                    .context("image generation target is no longer dispatchable")
            })
            .collect::<Result<Vec<_>>>();
        let snapshots = match snapshots {
            Ok(snapshots) => snapshots,
            Err(_) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_PREFLIGHT_UNAVAILABLE.to_string(),
                });
            }
        };
        let runtimes = snapshots
            .iter()
            .map(|snapshot| {
                RuntimeTargetAuthorityV1::from_registry_snapshot(
                    snapshot,
                    now_monotonic_ms,
                    operation_deadline_monotonic_ms,
                )
            })
            .collect::<Result<Vec<_>>>();
        let runtimes = match runtimes {
            Ok(runtimes) => runtimes,
            Err(_) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_PREFLIGHT_UNAVAILABLE.to_string(),
                });
            }
        };
        let total_attempts = runtimes.iter().zip(&request.targets).try_fold(
            0usize,
            |total, (runtime, requested)| {
                total
                    .checked_add(runtime.max_attempts as usize * requested.samples as usize)
                    .context("image generation attempt graph overflow")
            },
        )?;
        if total_attempts == 0 {
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: DISPATCH_PREFLIGHT_UNAVAILABLE.to_string(),
            });
        }
        let media_plan = image_generation_media_plans(&media_policy, total_attempts as u64)?;

        // The human authorization is the sole authority for this dispatch. Seal
        // its immutable digest into the durable plan; the capability's
        // `required_grant` remains an adapter constraint, not an invented
        // standing sealed-value grant.
        let approval_grant = GrantRequirementV1 {
            grant_kind: "image_generation_approval".to_string(),
            authority_digest: plan_digest.as_str().to_string(),
            generation: self
                .config_generation
                .load(std::sync::atomic::Ordering::Acquire),
        };
        let media_reservation_id = format!("image-generation-media:{}", Uuid::now_v7());
        let spend_reservation_id = format!("image-generation-spend:{}", Uuid::now_v7());
        let mut attempt_maxima = Vec::with_capacity(total_attempts);
        let mut targets = Vec::with_capacity(runtimes.len());
        let outbound_plan = media_plan
                .iter()
                .find(|plan| {
                    plan.dimension
                        == cockpit_config::config::media_budget::MediaDimension::OutboundSubmissionsGlobal
                })
                .context("image generation media policy omits outbound submission accounting")?;
        let per_attempt_media = resource_reservation_from_media_reservation(
            &MediaReservationPlan {
                requested: 1,
                ..outbound_plan.clone()
            },
            media_reservation_id.clone(),
        )?;
        let central_media = resource_reservation_from_media_reservation(
            outbound_plan,
            media_reservation_id.clone(),
        )?;
        for (runtime, requested) in runtimes.into_iter().zip(&request.targets) {
            let max_attempts = runtime.max_attempts;
            let attempt_cost = target_attempt_costs
                .as_ref()
                .and_then(|costs| costs.get(&runtime.target_id).copied());
            let mut slot_artifact_ids = Vec::with_capacity(requested.samples as usize);
            let mut spend_attempt_identities = Vec::new();
            for sample in 0..requested.samples {
                slot_artifact_ids.push((Uuid::now_v7(), Uuid::now_v7()));
                for attempt in 1..=max_attempts {
                    let attempt_id =
                        format!("image-generation:{}:{sample}:{attempt}", Uuid::now_v7());
                    attempt_maxima.push(AttemptMaximum {
                        attempt_id: attempt_id.clone(),
                        usd_micros: attempt_cost,
                    });
                    spend_attempt_identities.push(attempt_id);
                }
            }
            targets.push(ImageGenerationTargetResolutionAuthorityV1 {
                runtime,
                references: references.clone(),
                slot_artifact_ids,
                max_attempts,
                attempt_resources: vec![per_attempt_media.clone()],
                attempt_maximum_usd_micros: vec![attempt_cost; spend_attempt_identities.len()],
                spend_attempt_identities,
            });
        }
        let spend_plan = SpendReservationPlanV1 {
            required: true,
            policy_version: policy.policy_version,
            reservation_id: spend_reservation_id.clone(),
            maximum_usd_micros: cost_maximum,
            plan_digest: digest_fields(
                &std::iter::once(spend_reservation_id.as_str())
                    .chain(
                        attempt_maxima
                            .iter()
                            .map(|attempt| attempt.attempt_id.as_str()),
                    )
                    .collect::<Vec<_>>(),
            ),
        };
        let authority = ImageGenerationResolutionAuthorityV1 {
            job_id: Uuid::now_v7(),
            owner: owner.clone(),
            deadline_boot_id: self.boot_id,
            enqueue_started_monotonic_ms: now_monotonic_ms,
            operation_deadline_monotonic_ms,
            required_grants: vec![approval_grant],
            central_resources: vec![central_media],
            spend: spend_plan,
            output_authority: held.authority().clone(),
            sealed_prompt: SealedImageGenerationPromptV1::bind(args.prompt.clone())?,
            targets,
        };
        let ImageGenerationResolutionV1::Ready(preflight) =
            resolve_image_generation(request.clone(), authority.clone())?
        else {
            return Ok(GenerateImageDispatchOutcome::Incompatible {
                alternatives: match resolve_image_generation(request, authority)? {
                    ImageGenerationResolutionV1::Incompatible(alternatives) => alternatives,
                    ImageGenerationResolutionV1::Ready(_) => {
                        unreachable!("preflight changed without mutation")
                    }
                },
            });
        };
        let sealed_plan_digest = preflight.digest()?;
        let ledger = MediaReservationLedger::new(self.db.clone(), self.clock.clone());
        let receipt = match ledger
            .reserve(ReserveRequest {
                reservation_id: media_reservation_id.clone(),
                recovery_id: format!("image-generation-job:{}", preflight.job_id),
                owner: MediaOwner {
                    project_id: owner.project_id.clone(),
                    session_id: owner.session_id.to_string(),
                },
                operation: "image_generation".to_string(),
                purpose: "image_generation_dispatch".to_string(),
                plans: media_plan.clone(),
                wall_ms: u64::try_from(created_at_unix_ms)
                    .context("image generation wall clock is before the Unix epoch")?,
            })
            .await
        {
            Ok(receipt) => receipt,
            Err(error) => {
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: Self::dispatch_media_reservation_refusal(&error).to_string(),
                });
            }
        };
        if let Err(error) = ledger
            .mark_execution_ready(&receipt.reservation_id, now_monotonic_ms)
            .await
        {
            Self::cancel_unqueued_media(&ledger, &receipt, now_monotonic_ms).await?;
            return Ok(GenerateImageDispatchOutcome::Refused {
                reason: Self::dispatch_media_reservation_refusal(&error).to_string(),
            });
        }
        let local_plan = media_plan
            .iter()
            .find(|plan| {
                plan.dimension
                    == cockpit_config::config::media_budget::MediaDimension::LocalCpuJobsGlobal
            })
            .context("image generation media policy omits local execution accounting")?
            .clone();
        let media_claim = match ledger
            .claim_ready_fair(&receipt.reservation_id, local_plan, now_monotonic_ms)
            .await
        {
            Ok(Some(claim)) => claim,
            Ok(None) => {
                // This operation never started local execution. Release the queued
                // reservation before reporting contention so a later retry is not
                // charged for a job that was never created.
                Self::cancel_unqueued_media(&ledger, &receipt, now_monotonic_ms).await?;
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_COMMIT_UNAVAILABLE.to_string(),
                });
            }
            Err(error) => {
                Self::cancel_unqueued_media(&ledger, &receipt, now_monotonic_ms).await?;
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: Self::dispatch_media_reservation_refusal(&error).to_string(),
                });
            }
        };
        let spend = match self
            .db
            .reserve_image_spend(
                spend_reservation_id,
                SpendScopeKeys {
                    plan_digest: sealed_plan_digest,
                    session_id: SessionId::new(owner.session_id.to_string())?,
                    project_key: ProjectKey::new(owner.project_id.clone())?,
                },
                attempt_maxima,
                policy.policy_version,
                created_at_unix_ms,
            )
            .await
        {
            Ok(spend) => spend,
            Err(error) => {
                Self::cancel_unqueued_media(&ledger, &media_claim, now_monotonic_ms).await?;
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: Self::dispatch_spend_reservation_refusal(&error).to_string(),
                });
            }
        };
        let per_attempt_handoff_plan = MediaReservationPlan {
            requested: 1,
            ..media_plan
                .iter()
                .find(|plan| {
                    plan.dimension
                        == cockpit_config::config::media_budget::MediaDimension::OutboundSubmissionsGlobal
                })
                .context("image generation media policy omits outbound submission accounting")?
                .clone()
        };
        let (media_bytes, media_digest) = canonical_media_plan_snapshot(&per_attempt_handoff_plan)?;
        let media_snapshots = preflight
            .targets
            .iter()
            .flat_map(|target| &target.slots)
            .flat_map(|slot| {
                (1..=slot.attempts.len() as u32).map(|attempt_number| {
                    ImageGenerationMediaSnapshotInput {
                        slot_id: slot.slot_id,
                        attempt_number,
                        canonical_bytes: media_bytes.clone(),
                        digest: media_digest.clone(),
                    }
                })
            })
            .collect();
        let creation = ImageGenerationJobService::new(self.db.clone())
            .create_queued_job(
                request,
                authority,
                media_snapshots,
                reference_lease_cleanup.leases().to_vec(),
                standing_grant,
                created_at_unix_ms,
            )
            .await;
        match creation {
            Err(_error) => {
                reference_lease_cleanup.release_now().await?;
                Self::cancel_unqueued_media(&ledger, &media_claim, now_monotonic_ms).await?;
                self.db
                    .cancel_image_spend_before_dispatch(spend.reservation_id, created_at_unix_ms)
                    .await?;
                return Ok(GenerateImageDispatchOutcome::Refused {
                    reason: DISPATCH_COMMIT_UNAVAILABLE.to_string(),
                });
            }
            Ok(ImageGenerationJobCreation::Queued { job_id }) => {
                reference_lease_cleanup.disarm();
                Ok(GenerateImageDispatchOutcome::Queued { job_id })
            }
            Ok(ImageGenerationJobCreation::Incompatible(alternatives)) => {
                reference_lease_cleanup.release_now().await?;
                Self::cancel_unqueued_media(&ledger, &media_claim, now_monotonic_ms).await?;
                self.db
                    .cancel_image_spend_before_dispatch(spend.reservation_id, created_at_unix_ms)
                    .await?;
                Ok(GenerateImageDispatchOutcome::Incompatible { alternatives })
            }
        }
    }

    /// Roll back a pre-dispatch media reservation after an admission/queueing
    /// failure. No local output or provider handoff can exist at this point,
    /// but an executing-local reservation still needs a durable zero-material
    /// attestation before the ledger can release it.
    async fn cancel_unqueued_media(
        ledger: &MediaReservationLedger,
        receipt: &ReservationReceipt,
        wall_ms: u64,
    ) -> Result<()> {
        let cancelled = ledger
            .request_cancellation(&receipt.reservation_id, receipt.version, wall_ms)
            .await
            .map_err(anyhow::Error::from)?;
        if cancelled.state == ReservationState::CancellationRequested {
            let cleanup_checksum = digest_fields(&[
                "image-generation-pre-dispatch-abort",
                cancelled.reservation_id.as_str(),
            ]);
            ledger
                .destroy_local_artifacts(
                    &cancelled.reservation_id,
                    cancelled.version,
                    &cleanup_checksum,
                    wall_ms,
                )
                .await
                .map_err(anyhow::Error::from)?;
        }
        Ok(())
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
    reference_support: String,
    maximum_reference_images: u64,
    max_attempts: u32,
    required_grant: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationRequestV1 {
    pub targets: Vec<ImageGenerationTargetRequestV1>,
    pub reference_attachment_ids: Vec<Uuid>,
}

/// One immutable requested output envelope. The target id and every override
/// that changes provider bytes travel together through preflight, reservation,
/// and the canonical plan; no target can inherit another target's settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationTargetRequestV1 {
    pub target_id: String,
    pub width: u32,
    pub height: u32,
    pub format: String,
    pub samples: u32,
    pub parameters: BTreeMap<String, TypedParameterV1>,
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
    deadline_boot_id: Uuid,
    enqueue_started_monotonic_ms: u64,
    operation_deadline_monotonic_ms: u64,
    required_grants: Vec<GrantRequirementV1>,
    central_resources: Vec<ResourceReservationV1>,
    spend: SpendReservationPlanV1,
    output_authority: VerifiedOutputDirectoryAuthority,
    sealed_prompt: SealedImageGenerationPromptV1,
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
            session.ended_at_unix_ms.is_none()
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
        ensure!(session.ended_at_unix_ms.is_none(), unavailable());
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
        let outcome = crate::intel::hex_lower(&Sha256::digest(format!(
            "cleanup:{}:{}",
            recorded.operation_id, recorded.component_set_digest
        )));
        let component_transitions = components
            .iter()
            .map(|component| RecoverImageGenerationArtifactComponent {
                component_id: component.component_id,
                expected_generation: component.generation,
            })
            .collect::<Vec<_>>();
        cockpit_db::Db::commit_image_generation_security_cleanup_conn(
            &tx,
            &CommitImageGenerationSecurityCleanup {
                recovery_operation_id: recorded.operation_id,
                principal_digest: &self.principal_digest,
                artifact_id: recorded.artifact_id,
                expected_artifact_generation: recorded.artifact_generation,
                component_set_digest: &recorded.component_set_digest,
                cleanup_operation_id,
                components: &component_transitions,
                outcome_digest: &outcome,
                now_unix_ms: now,
            },
        )?;
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
        self.commit_verified_external_copy_removal(conn, &recorded, &evidence)?;
        Ok(VerifiedExternalCopyRemovalOutcome::RemovedDurably)
    }

    fn commit_verified_external_copy_removal(
        &self,
        conn: &Connection,
        recorded: &RecordedImageArtifactSecurityRecovery,
        evidence: &str,
    ) -> Result<()> {
        ensure!(
            matches!(
                ImageGenerationLatePublicationEvidenceV1::from_canonical_json(evidence)?,
                ImageGenerationLatePublicationEvidenceV1::TemporaryDeleted { .. }
                    | ImageGenerationLatePublicationEvidenceV1::ExactAbsence { .. }
            ),
            "external publication removal evidence kind differs"
        );
        let operation = recorded
            .publication_operation_id
            .context("security recovery publication identity is absent")?;
        let authorized_version = recorded
            .publication_lease_version
            .context("security recovery publication version is absent")?
            .checked_add(1)
            .context("external publication recovery version overflow")?;
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
        Ok(())
    }

    pub fn reconcile_verified_external_copy_removal(
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
        ensure!(
            recovery.destination_name().is_none()
                && recovery.artifact().identity_digest()
                    == recorded
                        .output_identity_digest
                        .as_deref()
                        .context("security recovery output identity is absent")?,
            "restart deletion recovery identity differs"
        );
        let reconciled = match output.reconcile_publication(recovery)? {
            HeldDirectoryEffectOutcome::AppliedDurable(evidence) => evidence,
            HeldDirectoryEffectOutcome::AppliedUnknown(recovery)
            | HeldDirectoryEffectOutcome::SecurityAmbiguous(recovery) => {
                return Ok(VerifiedExternalCopyRemovalOutcome::RecoveryRequired(
                    recovery,
                ));
            }
            HeldDirectoryEffectOutcome::ProvenNotApplied(_) => {
                anyhow::bail!("external publication deletion is proven not applied")
            }
        };
        ensure!(
            reconciled.destination_name().is_none(),
            "restart deletion reconciliation unexpectedly retained a destination"
        );
        let operation = recorded
            .publication_operation_id
            .context("security recovery publication identity is absent")?;
        let authority = &output.authority.0;
        let evidence = ImageGenerationLatePublicationEvidenceV1::ExactAbsence {
            schema_version: 1,
            absence_digest: crate::intel::hex_lower(&Sha256::digest(format!(
                "absent:{}:{}",
                operation,
                reconciled.artifact().identity_digest()
            ))),
            parent_identity_digest: authority.parent_identity_digest.clone(),
        }
        .canonical_json()?;
        self.commit_verified_external_copy_removal(conn, &recorded, &evidence)?;
        Ok(VerifiedExternalCopyRemovalOutcome::RemovedDurably)
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
        let outcome = crate::intel::hex_lower(&Sha256::digest(format!(
            "published:{publication_operation_id}:{evidence}"
        )));
        cockpit_db::Db::commit_image_generation_security_publication_conn(
            &tx,
            &CommitImageGenerationSecurityPublication {
                recovery_operation_id: recorded.operation_id,
                principal_digest: &self.principal_digest,
                publication_operation_id,
                expected_lease_version,
                artifact_id: recorded.artifact_id,
                expected_artifact_generation: recorded.artifact_generation,
                expected_slot_version: u64::try_from(row.4)?,
                output_authority_digest: &row.2,
                output_authority_generation: u64::try_from(row.3)?,
                destination_name: &row.1,
                output_evidence_json: &evidence,
                outcome_digest: &outcome,
                now_unix_ms: now,
            },
        )?;
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
    pub sealed_prompt: SealedImageGenerationPromptV1,
    pub deadline_boot_id: Uuid,
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
            !request.targets.is_empty() && request.targets.iter().all(|target| target.samples > 0),
            "image generation request has no outputs"
        );
        ensure!(
            !proofs.deadline_boot_id.is_nil()
                && proofs.operation_deadline_monotonic_ms > proofs.enqueue_started_monotonic_ms,
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
                    // The operation's monotonic start is an independent "now"
                    // reading: health retrieved before enqueue whose TTL has
                    // since elapsed is no longer dispatchable.
                    proofs.enqueue_started_monotonic_ms,
                    proofs.operation_deadline_monotonic_ms,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        runtimes.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        ensure!(
            runtimes
                .iter()
                .map(|runtime| &runtime.target_id)
                .eq(request.targets.iter().map(|target| &target.target_id)),
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
        let total_attempts = attempts_per_slot.iter().zip(&request.targets).try_fold(
            0_usize,
            |total, (attempts, requested)| {
                total
                    .checked_add(*attempts as usize * requested.samples as usize)
                    .ok_or_else(|| anyhow::anyhow!("attempt graph overflow"))
            },
        )?;
        ensure!(
            proofs.spend_attempts.len() == total_attempts,
            "spend proof does not match attempt graph"
        );
        ensure!(
            proofs
                .central_reservation
                .requested
                .is_multiple_of(total_attempts as u64),
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
        for ((runtime, max_attempts), requested) in runtimes
            .into_iter()
            .zip(attempts_per_slot)
            .zip(&request.targets)
        {
            let mut slot_artifact_ids = Vec::new();
            for _ in 0..requested.samples {
                slot_artifact_ids.push((Uuid::now_v7(), Uuid::now_v7()));
                spend_index += max_attempts as usize;
            }
            let first_attempt = spend_index - max_attempts as usize * requested.samples as usize;
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
            deadline_boot_id: proofs.deadline_boot_id,
            enqueue_started_monotonic_ms: proofs.enqueue_started_monotonic_ms,
            operation_deadline_monotonic_ms: proofs.operation_deadline_monotonic_ms,
            required_grants: grants,
            central_resources,
            spend,
            output_authority: proofs.output.authority().clone(),
            sealed_prompt: proofs.sealed_prompt,
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
    Ready(Box<ImageGenerationPlanV1>),
    Incompatible(Vec<ImageGenerationTargetAlternativeV1>),
}

pub fn resolve_image_generation(
    request: ImageGenerationRequestV1,
    authority: ImageGenerationResolutionAuthorityV1,
) -> Result<ImageGenerationResolutionV1> {
    ensure!(
        request
            .targets
            .windows(2)
            .all(|pair| pair[0].target_id < pair[1].target_id),
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
    for requested in &request.targets {
        let target_id = &requested.target_id;
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
        let compatible = target.runtime.supported_formats.get(&requested.format);
        if let Some(alternative) = target
            .runtime
            .capability_incompatibility(requested, &request.reference_attachment_ids)
        {
            alternatives.push(alternative);
            continue;
        }
        if target.slot_artifact_ids.len() != requested.samples as usize {
            alternatives.push(ImageGenerationTargetAlternativeV1 {
                target_id: target_id.clone(),
                supported_formats: target.runtime.supported_formats.keys().cloned().collect(),
                maximum_width: target.runtime.maximum_width,
                maximum_height: target.runtime.maximum_height,
                reason: "request is incompatible with sealed target capability".into(),
            });
            continue;
        }
        let format = requested.format.clone();
        targets.push(ImageGenerationPreflightTargetV1 {
            authority: target.runtime.clone(),
            reference_artifacts: target.references.clone(),
            requested: RequestedOutputV1 {
                width: requested.width,
                height: requested.height,
                format: format.clone(),
            },
            resolved: ResolvedOutputV1 {
                width: requested.width,
                height: requested.height,
                format: format.clone(),
                mime: compatible.unwrap().clone(),
                vector_sanitization_required: format == "svg",
                vector_sanitizer: (format == "svg")
                    .then(crate::generated_svg::sanitizer_provenance),
            },
            typed_parameters: requested.parameters.clone(),
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
        deadline_boot_id: authority.deadline_boot_id,
        enqueue_started_monotonic_ms: authority.enqueue_started_monotonic_ms,
        operation_deadline_monotonic_ms: authority.operation_deadline_monotonic_ms,
        required_grants: authority.required_grants,
        central_resources: authority.central_resources,
        spend: authority.spend,
        output_authority: authority.output_authority,
        sealed_prompt: authority.sealed_prompt,
        targets,
    })?;
    Ok(ImageGenerationResolutionV1::Ready(Box::new(plan)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutputDirectoryAuthority(OutputDirectoryAuthorityV1);
impl VerifiedOutputDirectoryAuthority {
    pub(crate) fn from_held_directory(
        canonical_destination_digest: String,
        parent_identity_digest: String,
        authority_generation: u64,
        filename_prefix: String,
    ) -> Result<Self> {
        let value = OutputDirectoryAuthorityV1 {
            canonical_destination_digest,
            parent_identity_digest,
            authority_generation,
            filename_prefix,
        };
        validate_digest(&value.canonical_destination_digest)?;
        validate_digest(&value.parent_identity_digest)?;
        ensure!(
            value.authority_generation > 0 && valid_path_component(&value.filename_prefix),
            "output directory authority is invalid"
        );
        Ok(Self(value))
    }
}

#[derive(Debug)]
pub struct HeldImageGenerationOutputDirectory {
    guard: cockpit_host::private_fs::held_directory::HeldDirectoryAuthority,
    authority: VerifiedOutputDirectoryAuthority,
}

#[derive(Debug)]
pub struct HeldImageGenerationArtifactRoot {
    guard: cockpit_host::private_fs::held_directory::HeldDirectoryAuthority,
}

impl HeldImageGenerationArtifactRoot {
    #[cfg(all(test, feature = "extended"))]
    fn force_next_directory_sync_failure(&self) {
        self.guard.force_next_directory_sync_failure();
    }
    #[cfg(all(test, feature = "extended"))]
    fn force_accepted_response_post_rename_cut(&self, component_id: Uuid) {
        FORCE_ACCEPTED_RESPONSE_POST_RENAME_CUT
            .lock()
            .unwrap()
            .insert(component_id);
    }
    pub fn create_component_temporary(&self, name: &str) -> Result<HeldTemporaryArtifact> {
        self.guard.create_file_exclusive(name)
    }
    pub fn seal_component(&self, temporary: HeldTemporaryArtifact) -> Result<HeldSealedArtifact> {
        self.guard.seal(temporary)
    }
    pub fn seal_component_recoverable(&self, temporary: HeldTemporaryArtifact) -> HeldSealOutcome {
        self.guard.seal_recoverable(temporary)
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

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PersistedHeldArtifactEvidence {
    byte_length: String,
    identity_digest: String,
    security_digest: String,
    sha256: String,
}

fn decode_held_artifact_evidence(value: &str) -> Result<HeldArtifactEvidence> {
    let persisted: PersistedHeldArtifactEvidence = serde_json::from_str(value)?;
    let byte_length = persisted.byte_length.parse::<u64>()?;
    ensure!(
        persisted.byte_length == byte_length.to_string()
            && persisted.identity_digest.len() == 64
            && persisted.security_digest.len() == 64
            && persisted.sha256.len() == 64,
        "component held evidence is invalid"
    );
    Ok(HeldArtifactEvidence {
        identity_digest: persisted.identity_digest,
        security_digest: persisted.security_digest,
        byte_length,
        sha256: persisted.sha256,
    })
}

fn write_verified_artifact_component<W: Write>(
    root: &HeldImageGenerationArtifactRoot,
    lease: &AcquiredImageGenerationArtifactLease,
    expected_checksum: &str,
    writer: &mut W,
) -> Result<()> {
    let evidence = decode_held_artifact_evidence(&lease.stable_identity_json)?;
    ensure!(
        evidence.byte_length() == lease.byte_length && evidence.sha256() == expected_checksum,
        "component held evidence differs from lease"
    );
    let mut held = root.open_verified_component(&lease.relative_storage_key, &evidence)?;
    ensure!(held.evidence() == &evidence, "component held proof differs");
    held.file_mut().seek(SeekFrom::Start(lease.range_start))?;
    let mut remaining = lease.requested_length;
    let mut buffer = [0_u8; 64 * 1024];
    while remaining != 0 {
        let wanted = usize::try_from(remaining.min(buffer.len() as u64))?;
        let count = held.file_mut().read(&mut buffer[..wanted])?;
        ensure!(count != 0, "component ended before leased range");
        writer.write_all(&buffer[..count])?;
        remaining -= u64::try_from(count)?;
    }
    Ok(())
}

/// Acquires the durable route lease, proves and reads one no-follow held
/// component, then releases the lease exactly once even when the consumer
/// disconnects (`Write::write` returns an error).
pub fn serve_image_generation_artifact_component<W: Write>(
    conn: &Connection,
    owner: &ImageGenerationOwnerContextAuthority,
    root: &HeldImageGenerationArtifactRoot,
    input: &AcquireImageGenerationArtifactLease<'_>,
    released_at_monotonic: u64,
    writer: &mut W,
) -> Result<()> {
    owner.revalidate_live_session(conn)?;
    let authenticated: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM image_generation_artifact_authorization_facts WHERE authorization_digest=?1 AND principal_digest=?2 AND revoked_at_unix_ms IS NULL)",
        params![input.authorization_digest, owner.principal_digest],
        |row| row.get(0),
    )?;
    ensure!(authenticated, "image artifact route is unavailable");
    let lease = cockpit_db::Db::acquire_image_generation_artifact_lease_conn(conn, input)?;
    let served =
        write_verified_artifact_component(root, &lease, input.expected_component_checksum, writer);
    let released = cockpit_db::Db::release_image_generation_artifact_lease_conn(
        conn,
        lease.lease_id,
        released_at_monotonic,
    );
    match (served, released) {
        (Err(error), _) => Err(error),
        (Ok(()), Ok(true)) => Ok(()),
        (Ok(()), Ok(false)) => anyhow::bail!("artifact lease was not active at release"),
        (Ok(()), Err(error)) => Err(error).context("releasing image artifact lease"),
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
        guard: cockpit_host::private_fs::held_directory::HeldDirectoryAuthority::open_existing(
            path,
        )?,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedImageArtifactFormat {
    Png,
    Jpeg,
    Webp,
    Svg,
}

async fn terminalize_accepted_response_failure(
    db: &cockpit_db::Db,
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    safe_reason: String,
    now_unix_ms: i64,
) -> Result<()> {
    db.write(move |conn| {
        let state:String=conn.query_row("SELECT state FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|row.get(0))?;
        if state=="failed_after_acceptance" { return Ok(()); }
        let (attempt_version,slot_version,operation,journal_version):(i64,i64,String,i64)=conn.query_row("SELECT a.version,s.version,a.external_operation_id,a.observed_journal_version FROM image_generation_attempts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
        cockpit_db::Db::commit_accepted_image_response_failure_conn(conn,&cockpit_db::db::image_generation::CommitAcceptedImageResponseFailure{job_id,slot_id,attempt_number,expected_attempt_version:u64::try_from(attempt_version)?,expected_slot_version:u64::try_from(slot_version)?,external_operation_id:Uuid::parse_str(&operation)?,expected_journal_version:u64::try_from(journal_version)?,safe_reason:&safe_reason,at_unix_ms:now_unix_ms})
    }).await
}

pub async fn fetch_accepted_image_response<F: AcceptedImageResponseFetcher>(
    db: cockpit_db::Db,
    fetcher: &F,
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    now_unix_ms: i64,
) -> Result<AcceptedImageResponseFetchOutcome> {
    let existing = db
        .read(move |conn| {
            conn.query_row(
                "SELECT o.outcome,o.safe_reason,o.evidence,f.response_bytes FROM image_generation_response_fetch_outcomes o LEFT JOIN image_generation_response_fetches f USING(job_id,slot_id,attempt_number) WHERE o.job_id=?1 AND o.slot_id=?2 AND o.attempt_number=?3",
                params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number)],
                |row| Ok((row.get::<_, String>(0)?,row.get::<_, Option<String>>(1)?,row.get::<_, Vec<u8>>(2)?,row.get::<_, Option<Vec<u8>>>(3)?)),
            )
            .optional()
            .map_err(Into::into)
        })
        .await?;
    if let Some((outcome, safe_reason, evidence, bytes)) = existing {
        let replay_result: Result<AcceptedImageResponseFetchOutcome> = match outcome.as_str() {
            "fetched" => Ok(AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.context("fetched response bytes are absent")?,
                evidence,
            }),
            "definitive_failure" => Ok(AcceptedImageResponseFetchOutcome::DefinitiveFailure {
                safe_reason: safe_reason.context("response failure reason is absent")?,
                evidence,
            }),
            "outcome_unknown" => Ok(AcceptedImageResponseFetchOutcome::OutcomeUnknown { evidence }),
            _ => anyhow::bail!("unknown accepted response fetch outcome"),
        };
        let replay = replay_result?;
        if let AcceptedImageResponseFetchOutcome::DefinitiveFailure { safe_reason, .. } = &replay {
            terminalize_accepted_response_failure(
                &db,
                job_id,
                slot_id,
                attempt_number,
                safe_reason.clone(),
                now_unix_ms,
            )
            .await?;
        }
        return Ok(replay);
    }
    let provider_request_identity = db
        .read(move |conn| {
            conn.query_row(
                "SELECT a.provider_request_identity FROM image_generation_attempts a JOIN image_generation_handoff_evidence h USING(job_id,slot_id,attempt_number) WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state IN ('accepted','downloading','cancellation_requested') AND h.outcome='accepted'",
                params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number)],
                |row| row.get(0),
            )
            .context("accepted response authority is unavailable")
        })
        .await?;
    let outcome = fetcher
        .fetch(&AcceptedImageResponseFetchRequest {
            job_id,
            slot_id,
            attempt_number,
            provider_request_identity,
        })
        .await;
    let (outcome_name, safe_reason, evidence, bytes) = match &outcome {
        AcceptedImageResponseFetchOutcome::Fetched { bytes, evidence } => {
            ensure!(
                !bytes.is_empty() && bytes.len() <= 64 * 1024 * 1024,
                "accepted response bytes exceed their bound"
            );
            ("fetched", None, evidence.clone(), Some(bytes.clone()))
        }
        AcceptedImageResponseFetchOutcome::DefinitiveFailure {
            safe_reason,
            evidence,
        } => {
            ensure!(
                !safe_reason.is_empty()
                    && safe_reason.len() <= 128
                    && safe_reason
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
                "accepted response failure reason is invalid"
            );
            (
                "definitive_failure",
                Some(safe_reason.clone()),
                evidence.clone(),
                None,
            )
        }
        AcceptedImageResponseFetchOutcome::OutcomeUnknown { evidence } => {
            ("outcome_unknown", None, evidence.clone(), None)
        }
    };
    ensure!(
        !evidence.is_empty() && evidence.len() <= MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES,
        "accepted response evidence exceeds its bound"
    );
    let evidence_digest = crate::intel::hex_lower(&Sha256::digest(&evidence));
    let response_digest = bytes
        .as_ref()
        .map(|bytes| crate::intel::hex_lower(&Sha256::digest(bytes)));
    db.write(move |conn| {
            let tx=conn.unchecked_transaction()?;
            tx.execute("INSERT INTO image_generation_response_fetch_outcomes(job_id,slot_id,attempt_number,outcome,safe_reason,evidence,evidence_digest,recorded_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),outcome_name,safe_reason,evidence,evidence_digest,now_unix_ms])?;
            if let (Some(bytes),Some(response_digest))=(bytes,response_digest) {
            tx.execute(
                "INSERT INTO image_generation_response_fetches(job_id,slot_id,attempt_number,response_digest,response_bytes,fetch_evidence,fetch_evidence_digest,fetched_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),response_digest,bytes,tx.query_row::<Vec<u8>,_,_>("SELECT evidence FROM image_generation_response_fetch_outcomes WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|row.get(0))?,tx.query_row::<String,_,_>("SELECT evidence_digest FROM image_generation_response_fetch_outcomes WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|row.get(0))?,now_unix_ms],
            )?;
            }
            tx.commit()?; Ok(())
        }).await?;
    if let AcceptedImageResponseFetchOutcome::DefinitiveFailure { safe_reason, .. } = &outcome {
        terminalize_accepted_response_failure(
            &db,
            job_id,
            slot_id,
            attempt_number,
            safe_reason.clone(),
            now_unix_ms,
        )
        .await?;
    }
    Ok(outcome)
}

pub async fn reconcile_unknown_accepted_image_response<F: AcceptedImageResponseFetcher>(
    db: cockpit_db::Db,
    fetcher: &F,
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    worker_boot_id: Uuid,
    now_unix_ms: i64,
) -> Result<AcceptedImageResponseFetchOutcome> {
    ensure!(
        !worker_boot_id.is_nil(),
        "response reconciliation boot is nil"
    );
    let authority=db.write(move|conn|{
        let (provider,evidence):(String,Vec<u8>)=conn.query_row("SELECT a.provider_request_identity,o.evidence FROM image_generation_attempts a JOIN image_generation_response_fetch_outcomes o USING(job_id,slot_id,attempt_number) WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND o.outcome='outcome_unknown'",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|Ok((row.get(0)?,row.get(1)?)))?;
        if let Some(row)=conn.query_row("SELECT outcome,safe_reason,evidence,response_bytes FROM image_generation_response_reconciliations WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND outcome!='outcome_unknown' ORDER BY claim_generation DESC LIMIT 1",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|Ok((row.get::<_,String>(0)?,row.get::<_,Option<String>>(1)?,row.get::<_,Vec<u8>>(2)?,row.get::<_,Option<Vec<u8>>>(3)?))).optional()? { return Ok((provider,evidence,0,Some(row))); }
        let generation:i64=conn.query_row("SELECT COALESCE(MAX(claim_generation),0)+1 FROM image_generation_response_reconciliation_claims WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|row.get(0))?;
        let inserted=conn.execute("INSERT INTO image_generation_response_reconciliation_claims(job_id,slot_id,attempt_number,claim_generation,worker_boot_id,claimed_at_unix_ms,expires_at_unix_ms) SELECT ?1,?2,?3,?4,?5,?6,?6+60000 WHERE NOT EXISTS(SELECT 1 FROM image_generation_response_reconciliation_claims c WHERE c.job_id=?1 AND c.slot_id=?2 AND c.attempt_number=?3 AND c.expires_at_unix_ms>?6)",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),generation,worker_boot_id.to_string(),now_unix_ms])?;
        ensure!(inserted==1,"response reconciliation is already claimed"); Ok((provider,evidence,generation,None))
    }).await?;
    if let Some((kind, reason, evidence, bytes)) = authority.3 {
        return Ok(match kind.as_str() {
            "fetched" => AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.context("reconciled response bytes absent")?,
                evidence,
            },
            "definitive_failure" => AcceptedImageResponseFetchOutcome::DefinitiveFailure {
                safe_reason: reason.context("reconciled failure reason absent")?,
                evidence,
            },
            _ => anyhow::bail!("invalid terminal response reconciliation"),
        });
    }
    let request = AcceptedImageResponseFetchRequest {
        job_id,
        slot_id,
        attempt_number,
        provider_request_identity: authority.0,
    };
    let outcome = fetcher.reconcile(&request, &authority.1).await;
    let (kind, reason, evidence, bytes) = match &outcome {
        AcceptedImageResponseFetchOutcome::Fetched { bytes, evidence } => {
            ("fetched", None, evidence.clone(), Some(bytes.clone()))
        }
        AcceptedImageResponseFetchOutcome::DefinitiveFailure {
            safe_reason,
            evidence,
        } => (
            "definitive_failure",
            Some(safe_reason.clone()),
            evidence.clone(),
            None,
        ),
        AcceptedImageResponseFetchOutcome::OutcomeUnknown { evidence } => {
            ("outcome_unknown", None, evidence.clone(), None)
        }
    };
    if let Some(reason) = &reason {
        ensure!(
            !reason.is_empty()
                && reason.len() <= 128
                && reason
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_'),
            "response reconciliation failure reason is invalid"
        );
    }
    if let Some(bytes) = &bytes {
        ensure!(
            !bytes.is_empty() && bytes.len() <= 64 * 1024 * 1024,
            "reconciled response bytes exceed bound"
        );
    }
    ensure!(
        !evidence.is_empty() && evidence.len() <= MAX_PROVIDER_HANDOFF_EVIDENCE_BYTES,
        "response reconciliation evidence exceeds bound"
    );
    let evidence_digest = crate::intel::hex_lower(&Sha256::digest(&evidence));
    let response_digest = bytes
        .as_ref()
        .map(|value| crate::intel::hex_lower(&Sha256::digest(value)));
    let generation = authority.2;
    db.write(move|conn|{conn.execute("INSERT INTO image_generation_response_reconciliations(job_id,slot_id,attempt_number,claim_generation,outcome,safe_reason,evidence,evidence_digest,response_digest,response_bytes,recorded_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),generation,kind,reason,evidence,evidence_digest,response_digest,bytes,now_unix_ms])?;Ok(())}).await?;
    if let AcceptedImageResponseFetchOutcome::DefinitiveFailure { safe_reason, .. } = &outcome {
        terminalize_accepted_response_failure(
            &db,
            job_id,
            slot_id,
            attempt_number,
            safe_reason.clone(),
            now_unix_ms,
        )
        .await?;
    }
    Ok(outcome)
}

pub struct CoordinateAcceptedImageResponse {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_job_version: u64,
    pub expected_slot_version: u64,
    pub expected_attempt_version: u64,
    pub external_operation_id: Uuid,
    pub expected_journal_version: u64,
    pub component_id: Uuid,
    pub release_operation_id: Uuid,
    pub bytes: Vec<u8>,
    pub now_unix_ms: i64,
}

pub fn retain_accepted_image_response_conn(
    conn: &Connection,
    root: &HeldImageGenerationArtifactRoot,
    input: &CoordinateAcceptedImageResponse,
) -> Result<AcceptedImageResponseProgress> {
    let (canonical, digest, artifact_id): (Vec<u8>, String, String) = conn.query_row(
        "SELECT p.canonical_plan,p.plan_digest,s.managed_artifact_id FROM image_generation_plans p JOIN image_generation_slots s ON s.job_id=p.job_id WHERE p.job_id=?1 AND s.slot_id=?2",
        params![input.job_id.to_string(), input.slot_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    let plan = ImageGenerationPlanV1::from_canonical(&canonical, &digest)?;
    let target = plan
        .targets
        .iter()
        .find(|target| {
            target
                .slots
                .iter()
                .any(|slot| slot.slot_id == input.slot_id)
        })
        .context("accepted response target is absent")?;
    let format = match target.resolved.format.as_str() {
        "png" => GeneratedImageArtifactFormat::Png,
        "jpeg" | "jpg" => GeneratedImageArtifactFormat::Jpeg,
        "webp" => GeneratedImageArtifactFormat::Webp,
        "svg" => GeneratedImageArtifactFormat::Svg,
        _ => anyhow::bail!("accepted response format is unsupported"),
    };
    let attempt_state: String = conn.query_row(
        "SELECT state FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",
        params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],
        |row| row.get(0),
    )?;
    let downloaded = attempt_state == "accepted";
    if downloaded {
        cockpit_db::Db::begin_image_generation_download_conn(
            conn,
            &cockpit_db::db::image_generation::BeginImageGenerationDownload {
                job_id: input.job_id,
                slot_id: input.slot_id,
                attempt_number: input.attempt_number,
                expected_job_version: input.expected_job_version,
                expected_slot_version: input.expected_slot_version,
                expected_attempt_version: input.expected_attempt_version,
                at_unix_ms: input.now_unix_ms,
            },
        )?;
    } else {
        ensure!(
            attempt_state == "cancellation_requested",
            "accepted response is unavailable"
        );
    }
    // Prefer the live external-journal version. Cancellation advances the
    // journal without rewriting attempt.observed_journal_version, so binding
    // only the attempt column loses the adopt compare-and-set after cancel.
    let (bound_operation_id, observed_journal_version): (String, i64) = conn.query_row(
        "SELECT a.external_operation_id, o.version FROM image_generation_attempts a JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3",
        params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    ensure!(
        Uuid::parse_str(&bound_operation_id)? == input.external_operation_id,
        "accepted response journal authority differs"
    );
    let observed_journal_version = u64::try_from(observed_journal_version)?;
    ensure!(
        observed_journal_version >= input.expected_journal_version,
        "accepted response journal authority predates the request"
    );
    let response_digest = crate::intel::hex_lower(&Sha256::digest(&input.bytes));
    cockpit_db::Db::adopt_image_generation_response_conn(
        conn,
        &cockpit_db::db::image_generation::AdoptImageGenerationResponse {
            job_id: input.job_id,
            slot_id: input.slot_id,
            attempt_number: input.attempt_number,
            expected_attempt_version: input.expected_attempt_version
                + if downloaded { 1 } else { 0 },
            expected_slot_version: input.expected_slot_version + if downloaded { 1 } else { 0 },
            external_operation_id: input.external_operation_id,
            expected_journal_version: observed_journal_version,
            response_digest: &response_digest,
            now_unix_ms: input.now_unix_ms,
        },
    )?;
    let (slot_version, after_cancel): (i64, bool) = conn.query_row(
        "SELECT version,result_after_cancel=1 FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2",
        params![input.job_id.to_string(), input.slot_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    retain_generated_image_artifact(
        conn,
        root,
        &RetainGeneratedImageArtifact {
            artifact_id: Uuid::parse_str(&artifact_id)?,
            job_id: input.job_id,
            slot_id: input.slot_id,
            component_id: input.component_id,
            format,
            expected_width: target.resolved.width,
            expected_height: target.resolved.height,
            bytes: &input.bytes,
            resource_reservation_id: image_generation_attempt_media_reservation_id(
                &plan.central_resources[0].reservation_identity,
                input.slot_id,
                input.attempt_number,
            ),
            release_operation_id: input.release_operation_id,
            late_quarantined: after_cancel,
            now_unix_ms: input.now_unix_ms,
        },
    )?;
    let state = cockpit_db::Db::commit_image_generation_validation_conn(
        conn,
        &cockpit_db::db::image_generation::CommitImageGenerationValidation {
            job_id: input.job_id,
            slot_id: input.slot_id,
            expected_slot_version: u64::try_from(slot_version)?,
            at_unix_ms: input.now_unix_ms,
        },
    )?;
    Ok(
        if state == cockpit_db::db::image_generation::ImageGenerationSlotState::LateQuarantined {
            AcceptedImageResponseProgress::LateQuarantined
        } else {
            AcceptedImageResponseProgress::Retained
        },
    )
}

pub async fn coordinate_persisted_accepted_image_response(
    db: cockpit_db::Db,
    root: std::sync::Arc<HeldImageGenerationArtifactRoot>,
    input: CoordinateAcceptedImageResponse,
) -> Result<AcceptedImageResponseProgress> {
    let operation_id = Uuid::now_v7();
    let component_id = input.component_id;
    let query_job = input.job_id;
    let query_slot = input.slot_id;
    let query_attempt = input.attempt_number;
    let decided_at = input.now_unix_ms;
    let (artifact_id,response_digest):(String,String)=db.read(move|conn|conn.query_row("SELECT s.managed_artifact_id,f.response_digest FROM image_generation_slots s JOIN image_generation_response_fetches f ON f.job_id=s.job_id AND f.slot_id=s.slot_id WHERE s.job_id=?1 AND s.slot_id=?2 AND f.attempt_number=?3",params![query_job.to_string(),query_slot.to_string(),i64::from(query_attempt)],|row|Ok((row.get(0)?,row.get(1)?))).map_err(Into::into)).await?;
    let artifact_id = Uuid::parse_str(&artifact_id)?;
    ensure!(
        crate::intel::hex_lower(&Sha256::digest(&input.bytes)) == response_digest,
        "accepted response bytes differ from durable fetch"
    );
    let temporary_name = format!(".{artifact_id}-{component_id}.partial");
    let destination_name = format!("{artifact_id}-{component_id}.artifact");
    let reserve_job = input.job_id;
    let reserve_slot = input.slot_id;
    let reserve_attempt = input.attempt_number;
    let reserve_digest = response_digest.clone();
    db.write(move |conn| {
        cockpit_db::Db::reserve_accepted_response_publication_conn(
            conn,
            &cockpit_db::db::image_generation::ReserveAcceptedResponsePublication {
                publication_operation_id: operation_id,
                job_id: reserve_job,
                slot_id: reserve_slot,
                attempt_number: reserve_attempt,
                artifact_id,
                component_id,
                temporary_name: &temporary_name,
                destination_name: &destination_name,
                response_digest: &reserve_digest,
                at_unix_ms: decided_at,
            },
        )
    })
    .await?;
    // One outer transaction so a post-rename cut rolls back adopt/download and
    // the sealed artifact graph, while the durable publication intent (reserved
    // above) and any held filesystem artifact remain for restart recovery.
    let result = db
        .transaction(move |conn| retain_accepted_image_response_conn(conn, &root, &input))
        .await;
    match result {
        Ok(progress) => {
            db.write(move|conn|{let evidence:String=conn.query_row("SELECT c.stable_identity_json FROM image_generation_response_publication_intents i JOIN image_generation_artifact_components c ON c.artifact_id=i.artifact_id AND c.component_id=i.component_id WHERE i.publication_operation_id=?1",[operation_id.to_string()],|row|row.get(0))?;cockpit_db::Db::finish_accepted_response_publication_conn(conn,operation_id,&evidence,decided_at)}).await?;
            Ok(progress)
        }
        Err(error) => {
            let failure = crate::intel::hex_lower(&Sha256::digest(format!("{error:#}").as_bytes()));
            let held_recovery = error
                .chain()
                .find_map(|cause| cause.downcast_ref::<RecoverableHeldArtifactPublication>())
                .map(|error| error.evidence_json.clone());
            db.write(move |conn| {
                let names:(String,String)=conn.query_row("SELECT temporary_name,destination_name FROM image_generation_response_publication_intents WHERE publication_operation_id=?1",[operation_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
                let recovery=held_recovery.unwrap_or(serde_json::to_string(&serde_json::json!({"destinationName":names.1,"kind":"held_publication_failure","temporaryName":names.0}))?);
                cockpit_db::Db::block_accepted_response_publication_conn(
                    conn,
                    operation_id,
                    &recovery,
                    &failure,
                    decided_at,
                )
            })
            .await?;
            Err(error)
        }
    }
}

pub async fn reconcile_pending_accepted_response_publications(
    db: cockpit_db::Db,
    root: std::sync::Arc<HeldImageGenerationArtifactRoot>,
    now_unix_ms: i64,
) -> Result<u64> {
    let pending=db.read(|conn|{let mut statement=conn.prepare("SELECT i.publication_operation_id,i.destination_name,c.stable_identity_json FROM image_generation_response_publication_intents i LEFT JOIN image_generation_artifact_components c ON c.artifact_id=i.artifact_id AND c.component_id=i.component_id WHERE i.state='pending'")?;Ok(statement.query_map([],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,Option<String>>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?)}).await?;
    let mut reconciled = 0_u64;
    for (operation, name, evidence) in pending {
        let operation = Uuid::parse_str(&operation)?;
        let outcome = evidence
            .as_deref()
            .map(decode_held_artifact_evidence)
            .transpose()
            .and_then(|evidence| {
                evidence
                    .map(|evidence| root.open_verified_component(&name, &evidence))
                    .transpose()
            });
        match outcome {
            Ok(Some(_)) => {
                let evidence = evidence.context("pending publication evidence absent")?;
                db.write(move |conn| {
                    cockpit_db::Db::finish_accepted_response_publication_conn(
                        conn,
                        operation,
                        &evidence,
                        now_unix_ms,
                    )
                })
                .await?;
                reconciled += 1
            }
            _ => {
                let failure = crate::intel::hex_lower(&Sha256::digest(
                    b"accepted_response_publication_reconcile_failed",
                ));
                db.write(move |conn| {
                    let recovery=serde_json::to_string(&serde_json::json!({"destinationName":name,"kind":"startup_reconcile_security_blocked"}))?;
                    cockpit_db::Db::block_accepted_response_publication_conn(
                        conn,
                        operation,
                        &recovery,
                        &failure,
                        now_unix_ms,
                    )
                })
                .await?;
            }
        }
    }
    Ok(reconciled)
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

#[derive(Debug)]
struct RecoverableHeldArtifactPublication {
    evidence_json: String,
    source: anyhow::Error,
}
impl std::fmt::Display for RecoverableHeldArtifactPublication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "recoverable held artifact publication failure: {}",
            self.source
        )
    }
}
impl std::error::Error for RecoverableHeldArtifactPublication {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
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
    cockpit_db::Db::begin_image_generation_artifact_write_conn(
        conn,
        &BeginImageGenerationArtifactWrite {
            artifact_id: input.artifact_id,
            expected_generation: 1,
            now_unix_ms: input.now_unix_ms,
        },
    )?;
    cockpit_db::Db::begin_image_generation_artifact_component_write_conn(
        conn,
        &BeginImageGenerationArtifactComponentWrite {
            artifact_id: input.artifact_id,
            component_id: input.component_id,
            expected_generation: 1,
        },
    )?;
    let mut temporary = root.create_component_temporary(&temporary_name)?;
    use std::io::Write as _;
    if let Err(write_error) = temporary.file_mut().write_all(&canonical) {
        let evidence_json = serde_json::to_string(
            &serde_json::json!({"identityDigest":temporary.identity_digest(),"kind":"held_partial_write","securityDigest":temporary.security_digest(),"sourceName":temporary.name()}),
        )?;
        return Err(RecoverableHeldArtifactPublication {
            evidence_json,
            source: write_error.into(),
        }
        .into());
    }
    let sealed = match root.seal_component_recoverable(temporary) {
        HeldSealOutcome::Sealed(sealed) => sealed,
        HeldSealOutcome::Recoverable {
            artifact, error, ..
        } => {
            let evidence_json = match root.seal_component_recoverable(artifact) {
                HeldSealOutcome::Sealed(sealed) => {
                    let evidence = held_artifact_evidence_json(sealed.evidence())?;
                    let cleanup = root.remove_verified_component(sealed)?;
                    ensure!(
                        matches!(cleanup, HeldDirectoryEffectOutcome::AppliedDurable(_)),
                        "recoverable held temporary cleanup requires reconciliation"
                    );
                    serde_json::to_string(
                        &serde_json::json!({"artifact":evidence,"cleanup":"applied_durable","kind":"held_temporary"}),
                    )?
                }
                HeldSealOutcome::Recoverable { artifact, .. } => serde_json::to_string(
                    &serde_json::json!({"identityDigest":artifact.identity_digest(),"kind":"held_temporary_security_blocked","securityDigest":artifact.security_digest(),"sourceName":artifact.name()}),
                )?,
            };
            return Err(RecoverableHeldArtifactPublication {
                evidence_json,
                source: error,
            }
            .into());
        }
    };
    let effect = match root.retain_component_noreplace(sealed, &final_name)? {
        HeldDirectoryEffectOutcome::AppliedDurable(effect) => effect,
        HeldDirectoryEffectOutcome::AppliedUnknown(recovery)
        | HeldDirectoryEffectOutcome::SecurityAmbiguous(recovery) => {
            let evidence_json = serde_json::to_string(
                &serde_json::json!({"artifact":held_artifact_evidence_json(recovery.artifact())?,"destinationName":recovery.destination_name(),"kind":"held_effect_unknown","sourceCleanupRequired":recovery.source_cleanup_required(),"sourceName":recovery.source_name()}),
            )?;
            return Err(RecoverableHeldArtifactPublication {
                evidence_json,
                source: anyhow::anyhow!("managed artifact publication requires reconciliation"),
            }
            .into());
        }
        HeldDirectoryEffectOutcome::ProvenNotApplied(sealed) => {
            let evidence_json = serde_json::to_string(
                &serde_json::json!({"artifact":held_artifact_evidence_json(sealed.evidence())?,"kind":"held_proven_not_applied","sourceName":sealed.name()}),
            )?;
            return Err(RecoverableHeldArtifactPublication {
                evidence_json,
                source: anyhow::anyhow!("managed artifact publication was not applied"),
            }
            .into());
        }
    };
    let evidence = effect.artifact().clone();
    let evidence_json = held_artifact_evidence_json(&evidence)?;
    #[cfg(all(test, feature = "extended"))]
    if FORCE_ACCEPTED_RESPONSE_POST_RENAME_CUT
        .lock()
        .unwrap()
        .remove(&input.component_id)
    {
        let recovery = serde_json::to_string(
            &serde_json::json!({"artifact":evidence_json,"destinationName":final_name,"kind":"held_applied_durable"}),
        )?;
        return Err(RecoverableHeldArtifactPublication {
            evidence_json: recovery,
            source: anyhow::anyhow!("injected post-rename cut"),
        }
        .into());
    }
    cockpit_db::Db::commit_image_generation_artifact_component_ready_conn(
        conn,
        &CommitImageGenerationArtifactComponentReady {
            artifact_id: input.artifact_id,
            component_id: input.component_id,
            expected_generation: 2,
            stable_identity_json: &evidence_json,
        },
    )?;
    let retention = CommitImageGenerationArtifactRetention {
        artifact_id: input.artifact_id,
        expected_generation: 2,
        now_unix_ms: input.now_unix_ms,
    };
    if input.late_quarantined {
        cockpit_db::Db::commit_image_generation_artifact_late_quarantined_conn(conn, &retention)?;
    } else {
        cockpit_db::Db::commit_image_generation_artifact_retained_conn(conn, &retention)?;
    }
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
    #[cfg(all(test, feature = "extended"))]
    fn force_next_directory_sync_failure(&self) {
        self.guard.force_next_directory_sync_failure();
    }
}
pub fn open_image_generation_output_directory(
    path: &Path,
    authority_generation: u64,
    filename_prefix: String,
) -> Result<HeldImageGenerationOutputDirectory> {
    let guard =
        cockpit_host::private_fs::held_directory::HeldDirectoryAuthority::open_existing(path)?;
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
    pub deadline_boot_id: Uuid,
    pub enqueue_started_monotonic_ms: u64,
    pub operation_deadline_monotonic_ms: u64,
    pub required_grants: Vec<GrantRequirementV1>,
    pub central_resources: Vec<ResourceReservationV1>,
    pub spend: SpendReservationPlanV1,
    pub output_authority: VerifiedOutputDirectoryAuthority,
    pub sealed_prompt: SealedImageGenerationPromptV1,
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
            let extension = if target.resolved.format == "jpeg" {
                "jpg"
            } else {
                target.resolved.format.as_str()
            };
            let publication_name = format!(
                "{}-{:03}.{extension}",
                input.output_authority.0.filename_prefix,
                global_slot_index + 1,
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
        deadline_boot_id: input.deadline_boot_id,
        enqueue_started_monotonic_ms: input.enqueue_started_monotonic_ms,
        operation_deadline_monotonic_ms: input.operation_deadline_monotonic_ms,
        required_grants: input.required_grants,
        central_resources: input.central_resources,
        spend: input.spend,
        output_authority: input.output_authority.0,
        sealed_prompt: input.sealed_prompt,
        targets,
    };
    plan.required_grants.sort();
    plan.central_resources.sort();
    plan.validate()?;
    Ok(plan)
}

impl RuntimeTargetAuthorityV1 {
    fn capability_incompatibility(
        &self,
        request: &ImageGenerationTargetRequestV1,
        reference_attachment_ids: &[Uuid],
    ) -> Option<ImageGenerationTargetAlternativeV1> {
        let parameters_valid = request.parameters.iter().all(|(key, value)| {
            match (self.allowed_parameters.get(key).map(String::as_str), value) {
                (Some("boolean"), TypedParameterV1::Boolean(_))
                | (Some("integer"), TypedParameterV1::Integer(_)) => true,
                (Some("text"), TypedParameterV1::Text(text)) => valid_string(text),
                _ => false,
            }
        });
        (self.supported_formats.get(&request.format).is_none()
            || request.width > self.maximum_width
            || request.height > self.maximum_height
            || (reference_attachment_ids.is_empty() && self.reference_support == "required")
            || (!reference_attachment_ids.is_empty()
                && (self.reference_support == "unsupported"
                    || reference_attachment_ids.len() as u64 > self.maximum_reference_images))
            || !parameters_valid)
            .then(|| ImageGenerationTargetAlternativeV1 {
                target_id: self.target_id.clone(),
                supported_formats: self.supported_formats.keys().cloned().collect(),
                maximum_width: self.maximum_width,
                maximum_height: self.maximum_height,
                reason: "request is incompatible with sealed target capability".into(),
            })
    }

    /// Build the sealed runtime authority from a live health snapshot.
    ///
    /// `now` is the caller's monotonic clock reading at authority construction.
    /// It MUST be an independent reading -- never `snapshot.retrieved_at`, which
    /// would make the dispatchability gate a tautology (elapsed always zero). A
    /// snapshot whose capability TTL has already elapsed relative to `now`, or
    /// that has expired by `now`, is not dispatchable and is rejected here.
    pub fn from_registry_snapshot(
        snapshot: &ImageHealthSnapshot,
        now: u64,
        operation_deadline_monotonic_ms: u64,
    ) -> Result<Self> {
        ensure!(
            snapshot.dispatchable_at(now),
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
                    | "reference_support"
                    | "max_reference_images"
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
                health_observed_at_monotonic_ms: now,
                health_expires_at_monotonic_ms: snapshot.expires_at.min(capability.expires_at),
            },
            destination: TargetDestinationV1 {
                adapter_kind: crate::image_generation_runtime::adapter_kind_str(
                    snapshot.adapter_kind,
                )
                .into(),
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
            reference_support: capability
                .constraints
                .get("reference_support")
                .context("capability reference support is missing")?
                .clone(),
            maximum_reference_images: capability
                .constraints
                .get("max_reference_images")
                .context("capability reference maximum is missing")?
                .parse()?,
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

/// Live destination identity equals the sealed plan destination. Adapter kind,
/// endpoint identity, and credential identity are the stable fence; the
/// session-wide config generation integer is not.
fn sealed_destination_matches_snapshot(
    snapshot: &ImageHealthSnapshot,
    sealed: &TargetDestinationV1,
) -> bool {
    let Some(credential) = snapshot.credential_identity_digest.as_ref() else {
        return false;
    };
    crate::image_generation_runtime::adapter_kind_str(snapshot.adapter_kind) == sealed.adapter_kind
        && digest_fields(&[
            snapshot.endpoint_id.as_str(),
            snapshot.endpoint_origin.as_str(),
            snapshot.target_immutable_identity.as_str(),
        ]) == sealed.endpoint_identity_digest
        && credential.plan_identity_hex() == sealed.credential_identity_digest
}

fn valid_string(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_AUTHORITY_STRING_BYTES
        && !value.chars().any(char::is_control)
}

/// Evaluate the complete media accounting shape for an image-generation job.
/// The outbound submission dimension is sized to every sealed retry attempt;
/// each attempt receives one exact unit and the central reservation is their
/// checked aggregate. No mutable policy is consulted after this snapshot.
fn image_generation_media_plans(
    policy: &MediaResourcePolicy,
    outbound_attempts: u64,
) -> Result<Vec<MediaReservationPlan>> {
    use cockpit_config::config::media_budget::{MediaDimension, MediaEvaluationRequest};

    [
        (MediaDimension::QueuedOperationsGlobal, 1),
        (MediaDimension::QueuedOperationsPerSession, 1),
        (MediaDimension::LocalCpuJobsGlobal, 1),
        (MediaDimension::OutboundSubmissionsGlobal, outbound_attempts),
        (
            MediaDimension::OperationDeadlineSeconds,
            policy
                .limits()
                .get(MediaDimension::OperationDeadlineSeconds),
        ),
    ]
    .into_iter()
    .map(|(dimension, requested)| {
        policy
            .evaluate(MediaEvaluationRequest {
                dimension,
                requested: Some(requested),
                current_scope: 0,
                profile: None,
                adapter_limit: None,
                request_limit: None,
            })
            .map_err(anyhow::Error::new)
    })
    .collect()
}

fn valid_path_component(value: &str) -> bool {
    valid_string(value) && value != "." && value != ".." && !value.contains(['/', '\\'])
}

#[cfg(all(test, feature = "extended"))]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::image_generation_runtime::AddressClass;

    /// A canned successful dispatch proof for the many existing scheduler-pass
    /// tests that only care about the downstream dispatch, not the proof binding.
    /// The values satisfy every CHECK on `image_generation_attempts` and are
    /// distinguishable from the loopback proofs the binding tests assert on.
    fn sample_dispatch_proof_binding() -> DispatchProofBinding {
        DispatchProofBinding {
            endpoint_id: "endpoint-fixture".into(),
            config_generation: 6,
            refresh_epoch: 3,
            connected_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10)),
            location_class: AddressClass::PublicNetwork,
            hops_digest: "a".repeat(64),
        }
    }

    /// A deterministic `ImageDispatchProofSource`: either always yields a fixed
    /// binding, or always fails closed. Counts its invocations so tests can assert
    /// prepare actually consults it (never bypasses revalidation).
    struct FixedDispatchProofSource {
        binding: Option<DispatchProofBinding>,
        calls: AtomicUsize,
    }

    impl FixedDispatchProofSource {
        fn ok() -> Self {
            Self {
                binding: Some(sample_dispatch_proof_binding()),
                calls: AtomicUsize::new(0),
            }
        }

        fn failing() -> Self {
            Self {
                binding: None,
                calls: AtomicUsize::new(0),
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl ImageDispatchProofSource for FixedDispatchProofSource {
        fn revalidate<'a>(
            &'a self,
            _request: DispatchRevalidationRequest<'a>,
        ) -> Pin<Box<dyn Future<Output = Result<DispatchProofBinding, RuntimeError>> + Send + 'a>>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = match &self.binding {
                Some(binding) => Ok(binding.clone()),
                None => Err(RuntimeError::new(
                    RuntimeErrorCode::Obsolete,
                    "test dispatch revalidation refused",
                )),
            };
            Box::pin(async move { outcome })
        }
    }

    fn proof_ok() -> FixedDispatchProofSource {
        FixedDispatchProofSource::ok()
    }

    struct SchedulerClock;
    impl crate::media_reservation::MonotonicClock for SchedulerClock {
        fn now_ms(&self) -> u64 {
            100
        }
    }

    struct DeferredHandoffAdapter {
        calls: AtomicUsize,
    }

    impl image_generation_adapter_sealed::Sealed for DeferredHandoffAdapter {}

    #[async_trait::async_trait]
    impl ImageGenerationAdapter for DeferredHandoffAdapter {
        fn handoff_readiness(
            &self,
            _: &ImageGenerationHandoffReadinessRequest<'_>,
        ) -> ImageGenerationHandoffReadiness {
            ImageGenerationHandoffReadiness::Deferred {
                evidence: b"owner_session_image_adapter_unavailable".to_vec(),
            }
        }

        async fn handoff(&self, _: &ImageGenerationHandoffRequest) -> ImageGenerationHandoffResult {
            self.calls.fetch_add(1, Ordering::SeqCst);
            ImageGenerationHandoffResult::Accepted {
                evidence: b"must-not-run".to_vec(),
            }
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
            owner_session_id: Uuid::now_v7(),
            target_id: "fixture-target".into(),
            dispatch_config_generation: 1,
            slot_id: Uuid::now_v7(),
            attempt_number: 1,
            external_operation_id: Uuid::now_v7(),
            now_unix_ms: 1,
            provider_request_identity: "request:1".into(),
            provider_idempotency_identity: "idempotency:1".into(),
            sealed_prompt: SealedImageGenerationPromptV1::bind("fixture prompt".into()).unwrap(),
        };
        assert!(matches!(
            adapter.handoff(&request).await,
            ImageGenerationHandoffResult::Accepted { .. }
        ));
        assert_eq!(adapter.requests(), vec![request]);
    }

    fn dispatchable_health_snapshot() -> ImageHealthSnapshot {
        use crate::image_generation_runtime::{
            AddressClass, CapabilitySnapshot, ConnectionProof, CredentialIdentityDigest,
            ImageHealthState, SnapshotProvenance,
        };
        let constraints = BTreeMap::from([
            ("formats".to_string(), "png".to_string()),
            ("max_width".to_string(), "512".to_string()),
            ("max_height".to_string(), "512".to_string()),
            ("max_attempts".to_string(), "1".to_string()),
            ("required_grant".to_string(), "image_generation".to_string()),
        ]);
        ImageHealthSnapshot {
            endpoint_id: "endpoint".into(),
            adapter_kind: cockpit_config::config::image_generation::ImageAdapterKind::OpenaiImages,
            target_id: "target".into(),
            target_immutable_identity: "immutable".into(),
            config_generation: 1,
            refresh_epoch: 1,
            request_id: 1,
            state: ImageHealthState::Healthy,
            provenance: SnapshotProvenance::Live,
            // Retrieved at monotonic 0 and valid for a long window; a snapshot that
            // was dispatchable when retrieved but whose capability TTL has since
            // elapsed (or which has expired) must be rejected against an injected
            // later `now`.
            retrieved_at: 0,
            expires_at: 2_000_000,
            endpoint_origin: "https://example.test".into(),
            connection: Some(ConnectionProof {
                authority: "example.test".into(),
                connected_ip: "203.0.113.10".parse().unwrap(),
                location: AddressClass::PublicNetwork,
                established_at: 0,
                hops: vec![],
            }),
            model_or_workflow_digest: Some("m".repeat(64)),
            capability: Some(CapabilitySnapshot {
                target_id: "target".into(),
                model_or_workflow_digest: "m".repeat(64),
                retrieved_at: 0,
                expires_at: 2_000_000,
                provenance: SnapshotProvenance::Live,
                constraints,
            }),
            unavailable_reason: None,
            credential_identity_digest: Some(CredentialIdentityDigest::from_sha256([7; 32])),
        }
    }

    // AC7: the health gate is not a tautology. `from_registry_snapshot` takes an
    // independent `now`; a snapshot dispatchable at `retrieved_at` is rejected
    // once `now` is past its capability TTL or its expiry.
    #[test]
    fn image_generation_from_registry_snapshot_uses_injected_now() {
        let snapshot = dispatchable_health_snapshot();
        let deadline = 1_000;

        // At the retrieval instant the snapshot is dispatchable and the authority
        // builds, and it records the injected observation time (not retrieved_at).
        let now_at_retrieval = 0;
        let authority =
            RuntimeTargetAuthorityV1::from_registry_snapshot(&snapshot, now_at_retrieval, deadline)
                .expect("fresh snapshot is dispatchable");
        assert_eq!(
            authority
                .capability_provenance
                .health_observed_at_monotonic_ms,
            now_at_retrieval
        );

        // The old tautology `dispatchable_at(snapshot.retrieved_at)` would still
        // pass here, but with an independent `now` past the 15-minute capability
        // dispatch TTL the snapshot is no longer dispatchable.
        let now_ttl_elapsed = 1_000_000; // > CAPABILITY_DISPATCH_TTL (900_000 ms)
        assert!(snapshot.dispatchable_at(snapshot.retrieved_at));
        assert!(!snapshot.dispatchable_at(now_ttl_elapsed));
        assert!(
            RuntimeTargetAuthorityV1::from_registry_snapshot(&snapshot, now_ttl_elapsed, deadline)
                .is_err(),
            "capability TTL elapsed relative to injected now must reject dispatch"
        );

        // And a `now` past the snapshot's expiry is likewise not dispatchable.
        let now_past_expiry = 3_000_000;
        assert!(
            RuntimeTargetAuthorityV1::from_registry_snapshot(&snapshot, now_past_expiry, deadline)
                .is_err(),
            "expired snapshot relative to injected now must reject dispatch"
        );
    }

    // -------------------------------------------------------------------
    // AC4/5/6: prepare-time dispatch proof.
    // -------------------------------------------------------------------

    /// The persisted dispatch proof on an attempt row, plus the attempt state.
    type StoredDispatchProof = (
        Option<String>, // endpoint_id
        Option<i64>,    // config_generation
        Option<i64>,    // refresh_epoch
        Option<String>, // connected_ip
        Option<String>, // location_class
        Option<String>, // hops_digest
        String,         // state
    );

    async fn read_attempt_proof(
        db: cockpit_db::Db,
        job_id: Uuid,
        slot_id: Uuid,
        attempt_number: u32,
    ) -> StoredDispatchProof {
        db.read(move |conn| {
            conn.query_row(
                "SELECT dispatch_proof_endpoint_id,dispatch_proof_config_generation,dispatch_proof_refresh_epoch,dispatch_proof_connected_ip,dispatch_proof_location_class,dispatch_proof_hops_digest,state FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",
                params![job_id.to_string(), slot_id.to_string(), i64::from(attempt_number)],
                |row| {
                    Ok((
                        row.get::<_, Option<String>>(0)?,
                        row.get::<_, Option<i64>>(1)?,
                        row.get::<_, Option<i64>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, String>(6)?,
                    ))
                },
            )
            .map_err(Into::into)
        })
        .await
        .unwrap()
    }

    async fn prepare_error_count(db: cockpit_db::Db, job_id: Uuid, slot_id: Uuid) -> Option<i64> {
        db.read(move |conn| {
            conn.query_row(
                "SELECT failure_count FROM image_generation_scheduler_error_counts WHERE job_id=?1 AND slot_id=?2 AND stage='prepare'",
                params![job_id.to_string(), slot_id.to_string()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .map_err(Into::into)
        })
        .await
        .unwrap()
    }

    // AC4: a candidate that was dispatchable at plan time but whose revalidation
    // fails at prepare (stale epoch / identity change / not dispatchable at the
    // injected now) never journals `dispatching` or hands off, and its attempt
    // carries no successful proof. The failure is surfaced via
    // `record_scheduler_error`. Proven with a fail-closed proof source: a prepare
    // that ignored revalidation would still dispatch and record a proof.
    #[tokio::test]
    async fn image_generation_prepare_requires_revalidate_dispatch_proof() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let fixture = setup_real_ledger_scheduler_job(db.clone(), "ac4-proof").await;
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"unreachable-accepted".to_vec(),
            },
        ]);
        let proof_source = FixedDispatchProofSource::failing();
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_source, deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.claimed, 1, "the candidate is claimable at plan time");
        assert_eq!(
            pass.dispatched, 0,
            "a failed revalidation must not dispatch"
        );
        assert_eq!(pass.skipped, 1, "the failed prepare is skipped");
        assert_eq!(
            proof_source.calls(),
            1,
            "prepare must consult the revalidation source exactly once"
        );
        assert!(
            adapter.requests().is_empty(),
            "no provider handoff may occur without a dispatch proof"
        );
        let proof = read_attempt_proof(db.clone(), fixture.job_id, fixture.slot_id, 1).await;
        assert_eq!(proof.6, "planned", "the attempt never advanced to prepared");
        assert!(
            proof.0.is_none() && proof.5.is_none(),
            "no dispatch proof may be persisted on a failed revalidation"
        );
        assert_eq!(
            prepare_error_count(db, fixture.job_id, fixture.slot_id).await,
            Some(1),
            "the prepare abort must be surfaced via record_scheduler_error"
        );
    }

    /// A loopback-dispatchable registry for "target-a" (generation 6 / epoch 3,
    /// refreshed with credential `[cred_seed; 32]`) plus the resolved destination.
    /// The fixture `plan()`'s target-a destination seals adapter "fixture", endpoint
    /// identity digest `"9"*64` (== `digest('9')`), and credential identity digest
    /// `"a"*64` (== `digest('a')` == the sha256 identity of the `0xaa` credential).
    /// Pass those exact values for the honest success path; pass a divergent value to
    /// exercise the sealed-identity rejection.
    async fn loopback_target(
        cred_seed: u8,
        adapter_kind: &str,
        endpoint_identity_digest: &str,
    ) -> (ImageRuntimeRegistry, ResolvedDispatchDestination) {
        loopback_target_at_generation(cred_seed, adapter_kind, endpoint_identity_digest, 6).await
    }

    async fn loopback_target_at_generation(
        cred_seed: u8,
        adapter_kind: &str,
        endpoint_identity_digest: &str,
        generation: u64,
    ) -> (ImageRuntimeRegistry, ResolvedDispatchDestination) {
        use crate::image_generation_runtime::dispatch_proof_support::{
            FixedClock, dispatchable_registry, loopback_endpoint,
        };
        let clock = Arc::new(FixedClock(std::sync::atomic::AtomicU64::new(0)));
        let endpoint = loopback_endpoint();
        let credential = CredentialIdentityDigest::from_sha256([cred_seed; 32]);
        let registry = dispatchable_registry(
            clock,
            &endpoint,
            "target-a",
            generation,
            3,
            credential.clone(),
        )
        .await;
        let destination = ResolvedDispatchDestination {
            adapter_kind: adapter_kind.to_owned(),
            endpoint,
            endpoint_identity_digest: endpoint_identity_digest.to_owned(),
            credential_identity_digest: credential,
        };
        (registry, destination)
    }

    // AC5: a successful prepare persists the exact bound tuple observed from the
    // live registry; and a second prepare after a location-class change cannot
    // reuse the old proof -- revalidation is re-derived every time (never read
    // back from storage), so the changed destination aborts with no proof. Drives
    // the REAL `RegistryDispatchProofSource` + `ImageRuntimeRegistry` so the
    // persisted values are a genuine connection observation.
    #[tokio::test]
    async fn image_generation_prepare_persists_connection_proof_binding() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let (registry, destination) = loopback_target(0xaa, "fixture", &"9".repeat(64)).await;
        let endpoint = destination.endpoint.clone();
        let mut destinations = HashMap::new();
        destinations.insert("target-a".to_owned(), destination);
        let proof_source = RegistryDispatchProofSource::new(registry.clone(), destinations);

        // Job A: prepare succeeds and stores the bound tuple.
        let job_a = setup_real_ledger_scheduler_job(db.clone(), "ac5-a").await;
        let adapter_a = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"ac5-accepted".to_vec(),
            },
        ]);
        let pass_a = ImageGenerationDispatcher::new(db.clone())
            .run_scheduler_pass(&adapter_a, &proof_source, deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass_a.dispatched, 1, "job A dispatches with a fresh proof");
        let proof_a = read_attempt_proof(db.clone(), job_a.job_id, job_a.slot_id, 1).await;
        assert_eq!(proof_a.0.as_deref(), Some("endpoint-loopback"));
        assert_eq!(proof_a.1, Some(6), "config_generation is bound");
        assert_eq!(proof_a.2, Some(3), "refresh_epoch is bound");
        assert_eq!(
            proof_a.3.as_deref(),
            Some("127.0.0.1"),
            "connected_ip is bound"
        );
        assert_eq!(
            proof_a.4.as_deref(),
            Some("loopback"),
            "location_class is bound"
        );
        let hops_digest_a = proof_a.5.expect("hops_digest is bound");
        assert_eq!(hops_digest_a.len(), 64);
        assert!(hops_digest_a.chars().all(|c| c.is_ascii_hexdigit()));

        // The endpoint's location class changes from loopback to public. Applying
        // it invalidates the cached loopback health, so the next prepare cannot
        // reuse job A's proof.
        let mut public_endpoint = endpoint.clone();
        public_endpoint.location =
            cockpit_config::config::image_generation::ImageLocationClass::PublicCloud;
        registry.apply_endpoint(&public_endpoint, 6, 3);

        // Job B: same target, but the destination's location class no longer
        // matches -- revalidation aborts, so job B never dispatches and stores no
        // proof, while job A's stored proof is untouched.
        let job_b = setup_real_ledger_scheduler_job(db.clone(), "ac5-b").await;
        let adapter_b = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"ac5-unreachable".to_vec(),
            },
        ]);
        let pass_b = ImageGenerationDispatcher::new(db.clone())
            .run_scheduler_pass(&adapter_b, &proof_source, deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass_b.dispatched, 0,
            "a location-changed destination cannot reuse the old proof"
        );
        assert!(adapter_b.requests().is_empty(), "job B performs no handoff");
        let proof_b = read_attempt_proof(db.clone(), job_b.job_id, job_b.slot_id, 1).await;
        assert_eq!(proof_b.6, "planned");
        assert!(proof_b.0.is_none(), "job B stores no dispatch proof");
        let proof_a_again = read_attempt_proof(db.clone(), job_a.job_id, job_a.slot_id, 1).await;
        assert_eq!(
            proof_a_again.5.as_deref(),
            Some(hops_digest_a.as_str()),
            "job A's proof is per-attempt and unchanged by job B"
        );
    }

    // AC6: a plan under a loopback/private class whose connected proof becomes
    // public before prepare aborts prepare with ZERO `ImageGenerationAdapter::handoff`
    // invocations. Drives the real registry: the loopback health is invalidated by
    // the class change, so revalidation fails closed.
    #[tokio::test]
    async fn image_generation_loopback_to_public_blocks_handoff() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let (registry, destination) = loopback_target(0xaa, "fixture", &"9".repeat(64)).await;
        let endpoint = destination.endpoint.clone();
        let mut destinations = HashMap::new();
        destinations.insert("target-a".to_owned(), destination);
        let proof_source = RegistryDispatchProofSource::new(registry.clone(), destinations);

        let fixture = setup_real_ledger_scheduler_job(db.clone(), "ac6-loopback").await;

        // Before prepare, the endpoint's class transitions loopback -> public.
        let mut public_endpoint = endpoint.clone();
        public_endpoint.location =
            cockpit_config::config::image_generation::ImageLocationClass::PublicCloud;
        registry.apply_endpoint(&public_endpoint, 6, 3);

        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"ac6-unreachable".to_vec(),
            },
        ]);
        let pass = ImageGenerationDispatcher::new(db.clone())
            .run_scheduler_pass(&adapter, &proof_source, deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.dispatched, 0,
            "a loopback->public transition blocks dispatch"
        );
        assert_eq!(pass.skipped, 1);
        assert!(
            adapter.requests().is_empty(),
            "zero provider handoff invocations after a location-class change"
        );
        let proof = read_attempt_proof(db.clone(), fixture.job_id, fixture.slot_id, 1).await;
        assert_eq!(proof.6, "planned", "the attempt never advanced to prepared");
        assert!(proof.0.is_none(), "no dispatch proof persisted after abort");
        assert_eq!(
            prepare_error_count(db, fixture.job_id, fixture.slot_id).await,
            Some(1),
            "the aborted prepare is surfaced via record_scheduler_error"
        );
    }

    // AC5 (identity binding): a resolved destination whose sealed identity differs
    // from the plan -- even at the SAME configuration generation, and even when the
    // underlying registry would otherwise be dispatchable -- must fail closed before
    // any provider contact. Each variant diverges in exactly one sealed field
    // (endpoint identity digest, credential identity digest, or adapter kind); the
    // registry itself accepts the resolved credential, so a revalidation that
    // checked only the generation would dispatch all three. The fixture plan()'s
    // target-a seals adapter "fixture", endpoint digest "9"*64, credential "a"*64.
    #[tokio::test]
    async fn image_generation_prepare_rejects_unsealed_destination_identity() {
        // (label, cred_seed, adapter_kind, endpoint_identity_digest)
        let variants: [(&str, u8, &str, String); 3] = [
            ("endpoint_identity", 0xaa, "fixture", "0".repeat(64)),
            // Registry refreshed+resolved with 0xbb (so revalidation would succeed),
            // but the sealed plan credential digest is "a"*64 (the 0xaa identity).
            ("credential_identity", 0xbb, "fixture", "9".repeat(64)),
            ("adapter_kind", 0xaa, "openai_images", "9".repeat(64)),
        ];
        for (label, cred_seed, adapter_kind, endpoint_identity_digest) in variants {
            let db = cockpit_db::Db::open_in_memory().unwrap();
            let (registry, destination) =
                loopback_target(cred_seed, adapter_kind, &endpoint_identity_digest).await;
            let mut destinations = HashMap::new();
            destinations.insert("target-a".to_owned(), destination);
            let proof_source = RegistryDispatchProofSource::new(registry, destinations);

            let fixture = setup_real_ledger_scheduler_job(db.clone(), label).await;
            let adapter = DeterministicImageGenerationAdapter::new(vec![
                ImageGenerationHandoffResult::Accepted {
                    evidence: b"unsealed-unreachable".to_vec(),
                },
            ]);
            let pass = ImageGenerationDispatcher::new(db.clone())
                .run_scheduler_pass(&adapter, &proof_source, deadline_boot(), 100, 2, 2, 8)
                .await
                .unwrap();
            assert_eq!(
                pass.dispatched, 0,
                "{label}: a divergent sealed identity must not dispatch"
            );
            assert!(
                adapter.requests().is_empty(),
                "{label}: no provider handoff for an unsealed destination"
            );
            let proof = read_attempt_proof(db.clone(), fixture.job_id, fixture.slot_id, 1).await;
            assert_eq!(proof.6, "planned", "{label}: attempt never prepared");
            assert!(proof.0.is_none(), "{label}: no dispatch proof persisted");
        }
    }

    /// Prepare must not Obsolete a queued plan when only the session-wide
    /// generation integer moved. Destination identity (adapter, endpoint,
    /// credential) still matches; the live health generation is stored on the
    /// attempt for the later provider-handoff fence.
    #[tokio::test]
    async fn image_generation_prepare_accepts_identity_stable_generation_bump() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let (registry, destination) =
            loopback_target_at_generation(0xaa, "fixture", &"9".repeat(64), 7).await;
        let mut destinations = HashMap::new();
        destinations.insert("target-a".to_owned(), destination);
        let proof_source = RegistryDispatchProofSource::new(registry, destinations);

        let job = setup_real_ledger_scheduler_job(db.clone(), "gen-bump").await;
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"generation-bump-accepted".to_vec(),
            },
        ]);
        let pass = ImageGenerationDispatcher::new(db.clone())
            .run_scheduler_pass(&adapter, &proof_source, deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.dispatched, 1,
            "an identity-stable generation bump must not Obsolete prepare"
        );
        let proof = read_attempt_proof(db, job.job_id, job.slot_id, 1).await;
        assert_eq!(
            proof.1,
            Some(7),
            "the attempt stores the live health generation, not the sealed plan generation"
        );
    }

    struct DispatchServiceClock;
    impl crate::media_reservation::MonotonicClock for DispatchServiceClock {
        fn now_ms(&self) -> u64 {
            0
        }
    }
    impl ImageGenerationDispatchClock for DispatchServiceClock {
        fn now_unix_ms(&self) -> i64 {
            0
        }
    }

    fn dispatch_service_for_test(
        generation: u64,
        registry: ImageRuntimeRegistry,
        adapters: ImageGenerationAdapterMap,
    ) -> ImageGenerationDispatchService {
        ImageGenerationDispatchService::new(
            cockpit_db::Db::open_in_memory().unwrap(),
            Arc::new(registry),
            Uuid::now_v7(),
            crate::daemon::principal::ClientPrincipal::owner(),
            generation,
            250_000,
            MediaResourcePolicy::default(),
            Arc::new(DispatchServiceClock),
            None,
            cockpit_config::config::image_generation::ImageGenerationConfig::default(),
            adapters,
        )
    }

    #[tokio::test]
    async fn image_generation_dispatch_service_generation_zero_is_unavailable() {
        use crate::image_generation_runtime::dispatch_proof_support::{
            FixedClock, dispatchable_registry, loopback_endpoint,
        };
        let endpoint = loopback_endpoint();
        let credential = CredentialIdentityDigest::from_sha256([0xaa; 32]);
        let registry = dispatchable_registry(
            Arc::new(FixedClock(std::sync::atomic::AtomicU64::new(0))),
            &endpoint,
            "target-a",
            1,
            1,
            credential,
        )
        .await;
        let unpublished =
            dispatch_service_for_test(0, registry.clone(), ImageGenerationAdapterMap::new());
        let published = dispatch_service_for_test(1, registry, ImageGenerationAdapterMap::new());
        assert!(
            matches!(
                unpublished.list_targets(true),
                crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::DispatchUnavailable,
            ),
            "generation 0 must not advertise live targets"
        );
        assert!(
            matches!(
                published.list_targets(true),
                crate::image_generation_agent_tools::ImageGenerationTargetDiscovery::Targets(
                    ref projections
                ) if !projections.is_empty()
            ),
            "a published generation must list the configured target"
        );
    }

    #[tokio::test]
    async fn configured_handoff_readiness_survives_unrelated_generation_bump() {
        use crate::image_generation_runtime::dispatch_proof_support::{
            FixedClock, dispatchable_registry, loopback_endpoint,
        };
        let endpoint = loopback_endpoint();
        let credential = CredentialIdentityDigest::from_sha256([0xaa; 32]);
        let registry = dispatchable_registry(
            Arc::new(FixedClock(std::sync::atomic::AtomicU64::new(0))),
            &endpoint,
            "target-a",
            6,
            3,
            credential.clone(),
        )
        .await;
        let snapshot = registry
            .current_target_snapshot("target-a")
            .expect("loopback target snapshot");
        let destination = TargetDestinationV1 {
            adapter_kind: crate::image_generation_runtime::adapter_kind_str(snapshot.adapter_kind)
                .into(),
            endpoint_identity_digest: digest_fields(&[
                snapshot.endpoint_id.as_str(),
                snapshot.endpoint_origin.as_str(),
                snapshot.target_immutable_identity.as_str(),
            ]),
            credential_identity_digest: credential.plan_identity_hex(),
            destination_generation: 6,
        };
        let mut adapters = ImageGenerationAdapterMap::new();
        adapters.insert(
            ImageAdapterKind::OpenaiImages,
            Arc::new(DeterministicImageGenerationAdapter::new(Vec::new())),
        );
        // Service generation 99 != sealed destination_generation 6. Identity
        // still matches, so readiness must be Ready rather than Deferred.
        let service = dispatch_service_for_test(99, registry, adapters);
        let readiness = service.configured_handoff_readiness(
            ImageAdapterKind::OpenaiImages,
            &ImageGenerationHandoffReadinessRequest {
                owner_session_id: Uuid::now_v7(),
                target_id: "target-a",
                destination: &destination,
            },
        );
        assert_eq!(readiness, ImageGenerationHandoffReadiness::Ready);
        let mut changed = destination.clone();
        changed.adapter_kind = "comfyui".into();
        let mismatched = service.configured_handoff_readiness(
            ImageAdapterKind::OpenaiImages,
            &ImageGenerationHandoffReadinessRequest {
                owner_session_id: Uuid::now_v7(),
                target_id: "target-a",
                destination: &changed,
            },
        );
        assert_eq!(
            mismatched,
            ImageGenerationHandoffReadiness::Deferred {
                evidence: b"destination_identity_changed".to_vec()
            }
        );
    }

    struct DispatchGenerateClock;
    impl crate::media_reservation::MonotonicClock for DispatchGenerateClock {
        fn now_ms(&self) -> u64 {
            100
        }
    }
    impl ImageGenerationDispatchClock for DispatchGenerateClock {
        fn now_unix_ms(&self) -> i64 {
            1_700_000_000_100
        }
    }

    async fn wait_for_open_image_generation_interrupt(
        ctx: &crate::engine::tool::ToolCtx,
    ) -> crate::db::needs_attention::NeedsAttentionRow {
        loop {
            let open = ctx
                .session
                .db
                .list_open_interrupts(ctx.session.id)
                .await
                .unwrap();
            if let Some(interrupt) = open
                .iter()
                .find(|interrupt| ctx.interrupts.has_waiter(interrupt.interrupt_id))
            {
                return interrupt.clone();
            }
            tokio::task::yield_now().await;
        }
    }

    /// A parked session Allow must survive an unrelated session-generation bump
    /// that leaves destination identity unchanged, and must persist the standing
    /// grant in the same queue transaction.
    #[tokio::test]
    async fn dispatch_generate_image_session_allow_survives_identity_stable_generation_bump() {
        use crate::image_generation_runtime::dispatch_proof_support::{
            FixedClock, dispatchable_registry, loopback_endpoint,
        };
        use cockpit_db::image_spend::{BudgetPolicy, ImageSpendSettings};

        let root = tempfile::tempdir().unwrap();
        let output = root.path().join("out");
        std::fs::create_dir(&output).unwrap();
        let (ctx, db) = crate::tools::common::test_ctx_with_db(root.path());
        ctx.session
            .set_approval_mode(crate::config::extended::ApprovalMode::Manual);

        let endpoint = loopback_endpoint();
        let credential = CredentialIdentityDigest::from_sha256([0xaa; 32]);
        let registry = dispatchable_registry(
            Arc::new(FixedClock(std::sync::atomic::AtomicU64::new(0))),
            &endpoint,
            "target-a",
            1,
            1,
            credential,
        )
        .await;
        db.save_image_spend_policy(
            ctx.session.project_id.clone(),
            ImageSpendSettings {
                request: BudgetPolicy::Unlimited,
                session: BudgetPolicy::Unlimited,
                project: BudgetPolicy::Unlimited,
                project_epoch: None,
            },
            None,
            100,
        )
        .await
        .unwrap();

        let service = Arc::new(ImageGenerationDispatchService::new(
            db.clone(),
            Arc::new(registry),
            Uuid::now_v7(),
            crate::daemon::principal::ClientPrincipal::owner(),
            1,
            250_000,
            MediaResourcePolicy::default(),
            Arc::new(DispatchGenerateClock),
            None,
            cockpit_config::config::image_generation::ImageGenerationConfig::default(),
            ImageGenerationAdapterMap::new(),
        ));
        let directory = output.display().to_string();
        let args = GenerateImageDispatchArgs {
            prompt: "a test image".into(),
            directory: directory.clone(),
            base_stem: "image".into(),
            targets: vec![GenerateImageDispatchTarget {
                target_id: "target-a".into(),
                samples: 1,
                width: 512,
                height: 512,
                format: "png".into(),
                parameters: BTreeMap::new(),
                reference_indices: Vec::new(),
            }],
            references: Vec::new(),
            normal_write_path_digest: Some(crate::intel::hex_lower(&Sha256::digest(
                directory.as_bytes(),
            ))),
        };
        let approver = ctx
            .approver
            .as_ref()
            .expect("test ctx installs an Approver")
            .clone();
        let session = ctx.session.clone();

        let dispatch = service.dispatch_generate_image(&session, approver.as_ref(), &args);
        let bump_then_allow = async {
            let interrupt = wait_for_open_image_generation_interrupt(&ctx).await;
            service
                .publish_identity_stable_generation_for_test(99)
                .await;
            let response = crate::daemon::proto::ResolveResponse::Single {
                selected_id: crate::approval::ID_APPROVE_SESSION.to_string(),
            };
            ctx.session
                .db
                .resolve_interrupt(interrupt.interrupt_id, &response)
                .await
                .unwrap();
            assert!(ctx.interrupts.resolve(interrupt.interrupt_id, response));
        };
        let (outcome, _) = tokio::join!(dispatch, bump_then_allow);
        let outcome = outcome.expect("identity-stable parked Allow must commit");
        assert!(
            matches!(outcome, GenerateImageDispatchOutcome::Queued { .. }),
            "an identity-stable generation bump must not discard Allow: {outcome:?}"
        );
        let grant_count: i64 = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT COUNT(*) FROM image_generation_grants \
                     WHERE scope='session' AND revoked_at_unix_ms IS NULL",
                    [],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(
            grant_count, 1,
            "session Allow must persist the standing grant in the queue transaction"
        );

        let second = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            service.dispatch_generate_image(&session, approver.as_ref(), &args),
        )
        .await
        .expect("a matching session grant must not park on a later generate")
        .unwrap();
        assert!(
            matches!(second, GenerateImageDispatchOutcome::Queued { .. }),
            "the persisted grant must Auto-match a later identical request: {second:?}"
        );
    }

    // AC8: `record_scheduler_error` is production-real. Three failures for the
    // same tuple within one boot raise exactly one attention row; earlier
    // failures only bump the durable counter, and a fourth failure does not add
    // a second row. A different tuple keeps its own counter and raises its own
    // row. The clock is injected (at_unix_ms) -- no real-time sleeps.
    #[tokio::test]
    async fn image_generation_record_scheduler_error_logs_and_attention() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let session = db
            .create_session("attn-project", "/attn-project", "scheduler attention")
            .await
            .unwrap();
        let dispatcher = ImageGenerationDispatcher::new(db.clone());
        let worker_boot_id = Uuid::now_v7();
        let identity = SchedulerErrorIdentity {
            job_id: Uuid::now_v7(),
            slot_id: Uuid::now_v7(),
            attempt_number: 1,
            owner_session_id: session.session_id,
        };
        let error = anyhow::anyhow!("prepare failed: spend reservation is unavailable");

        let boot = worker_boot_id.to_string();
        let job = identity.job_id.to_string();
        let slot = identity.slot_id.to_string();
        let session_id = session.session_id.to_string();
        let failure_count = {
            let (boot, job, slot) = (boot.clone(), job.clone(), slot.clone());
            move |db: cockpit_db::Db, stage: &'static str| {
                let (boot, job, slot) = (boot.clone(), job.clone(), slot.clone());
                async move {
                    db.read(move |conn| {
                        conn.query_row(
                            "SELECT failure_count FROM image_generation_scheduler_error_counts WHERE worker_boot_id=?1 AND job_id=?2 AND slot_id=?3 AND attempt_number=1 AND stage=?4",
                            params![boot, job, slot, stage],
                            |row| row.get::<_, i64>(0),
                        )
                        .optional()
                        .map_err(Into::into)
                    })
                    .await
                    .unwrap()
                }
            }
        };
        let open_attention = {
            let session_id = session_id.clone();
            move |db: cockpit_db::Db| {
                let session_id = session_id.clone();
                async move {
                    db.read(move |conn| {
                        conn.query_row(
                            "SELECT count(*) FROM needs_attention WHERE session_id=?1 AND description LIKE 'image_generation_scheduler:%'",
                            params![session_id],
                            |row| row.get::<_, i64>(0),
                        )
                        .map_err(Into::into)
                    })
                    .await
                    .unwrap()
                }
            }
        };

        // Failure 1: durable counter records, no attention row yet.
        dispatcher
            .record_scheduler_error(worker_boot_id, &identity, "prepare", &error, 10)
            .await;
        assert_eq!(failure_count(db.clone(), "prepare").await, Some(1));
        assert_eq!(open_attention(db.clone()).await, 0);

        // Failure 2: still below threshold.
        dispatcher
            .record_scheduler_error(worker_boot_id, &identity, "prepare", &error, 11)
            .await;
        assert_eq!(failure_count(db.clone(), "prepare").await, Some(2));
        assert_eq!(open_attention(db.clone()).await, 0);

        // Failure 3: threshold reached -> exactly one attention row.
        dispatcher
            .record_scheduler_error(worker_boot_id, &identity, "prepare", &error, 12)
            .await;
        assert_eq!(failure_count(db.clone(), "prepare").await, Some(3));
        assert_eq!(open_attention(db.clone()).await, 1);
        let interrupt_after_third = db
            .read({
                let session_id = session_id.clone();
                move |conn| {
                    conn.query_row(
                        "SELECT interrupt_id,agent_id FROM needs_attention WHERE session_id=?1 AND description LIKE 'image_generation_scheduler:%'",
                        params![session_id],
                        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
                    )
                    .map_err(Into::into)
                }
            })
            .await
            .unwrap();
        assert_eq!(interrupt_after_third.1, "image_generation_scheduler");

        // Failure 4: same tuple updates the counter but does NOT add a second row.
        dispatcher
            .record_scheduler_error(worker_boot_id, &identity, "prepare", &error, 13)
            .await;
        assert_eq!(failure_count(db.clone(), "prepare").await, Some(4));
        assert_eq!(open_attention(db.clone()).await, 1);
        let interrupt_after_fourth = db
            .read({
                let session_id = session_id.clone();
                move |conn| {
                    conn.query_row(
                        "SELECT interrupt_id FROM needs_attention WHERE session_id=?1 AND description LIKE 'image_generation_scheduler:%'",
                        params![session_id],
                        |row| row.get::<_, String>(0),
                    )
                    .map_err(Into::into)
                }
            })
            .await
            .unwrap();
        assert_eq!(
            interrupt_after_third.0, interrupt_after_fourth,
            "the fourth failure must reuse the same attention row"
        );

        // A different tuple (distinct stage) keeps its own counter and raises its
        // own row only at its own third failure -- proving the full tuple keys the
        // threshold rather than the job alone.
        for (n, at) in [(1, 20), (2, 21)] {
            dispatcher
                .record_scheduler_error(worker_boot_id, &identity, "dispatch", &error, at)
                .await;
            assert_eq!(failure_count(db.clone(), "dispatch").await, Some(n));
            assert_eq!(open_attention(db.clone()).await, 1);
        }
        dispatcher
            .record_scheduler_error(worker_boot_id, &identity, "dispatch", &error, 22)
            .await;
        assert_eq!(failure_count(db.clone(), "dispatch").await, Some(3));
        assert_eq!(open_attention(db.clone()).await, 2);

        // The counter key is the FULL tuple, not just (boot, job, stage): a
        // sibling slot and a sibling attempt of the same (boot, job, "prepare")
        // each start their own count at 1 rather than inheriting the exhausted
        // "prepare" counter (which is already at 4). A regression that dropped
        // slot_id or attempt_number from the key would fail these.
        let count_specific = |db: cockpit_db::Db,
                              boot: String,
                              job: String,
                              slot: String,
                              attempt: i64| async move {
            db.read(move |conn| {
                    conn.query_row(
                        "SELECT failure_count FROM image_generation_scheduler_error_counts WHERE worker_boot_id=?1 AND job_id=?2 AND slot_id=?3 AND attempt_number=?4 AND stage='prepare'",
                        params![boot, job, slot, attempt],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(Into::into)
                })
                .await
                .unwrap()
        };
        let sibling_slot = SchedulerErrorIdentity {
            job_id: identity.job_id,
            slot_id: Uuid::now_v7(),
            attempt_number: identity.attempt_number,
            owner_session_id: session.session_id,
        };
        dispatcher
            .record_scheduler_error(worker_boot_id, &sibling_slot, "prepare", &error, 30)
            .await;
        assert_eq!(
            count_specific(
                db.clone(),
                worker_boot_id.to_string(),
                sibling_slot.job_id.to_string(),
                sibling_slot.slot_id.to_string(),
                1
            )
            .await,
            1,
            "a sibling slot must not inherit the exhausted prepare counter"
        );
        let sibling_attempt = SchedulerErrorIdentity {
            job_id: identity.job_id,
            slot_id: identity.slot_id,
            attempt_number: identity.attempt_number + 1,
            owner_session_id: session.session_id,
        };
        dispatcher
            .record_scheduler_error(worker_boot_id, &sibling_attempt, "prepare", &error, 31)
            .await;
        assert_eq!(
            count_specific(
                db.clone(),
                worker_boot_id.to_string(),
                sibling_attempt.job_id.to_string(),
                sibling_attempt.slot_id.to_string(),
                i64::from(sibling_attempt.attempt_number)
            )
            .await,
            1,
            "a sibling attempt must not inherit the exhausted prepare counter"
        );
        // Neither sibling crossed the threshold, so no new attention row was added.
        assert_eq!(open_attention(db.clone()).await, 2);
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
        setup_real_ledger_scheduler_job_with_attempts(db, suffix, 1).await
    }

    async fn setup_accepted_response_fixture(
        suffix: &str,
    ) -> (RealLedgerSchedulerFixture, ImageGenerationHandoffRequest) {
        setup_accepted_response_fixture_with_db(cockpit_db::Db::open_in_memory().unwrap(), suffix)
            .await
    }

    async fn setup_accepted_response_fixture_with_db(
        db: cockpit_db::Db,
        suffix: &str,
    ) -> (RealLedgerSchedulerFixture, ImageGenerationHandoffRequest) {
        let fixture = setup_real_ledger_scheduler_job(db, suffix).await;
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted-response-fixture".to_vec(),
            },
        ]);
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 1);
        (fixture, adapter.requests().into_iter().next().unwrap())
    }

    // -----------------------------------------------------------------------
    // OpenAI Images dispatch-trait wiring (AC1 / AC7-openai): drive the REAL
    // `OpenaiImagesAdapter` through `run_scheduler_pass` with a scripted
    // transport (no network) and a fixed plan source, asserting the transport
    // classification maps onto the recorded handoff evidence.
    // -----------------------------------------------------------------------

    async fn dispatch_openai_once(
        suffix: &str,
        transport_outcome: Result<
            crate::image_generation::transport::ProviderTransportOutcome,
            crate::image_generation::transport::ProviderTransportError,
        >,
    ) -> (
        Vec<(
            crate::openai_images_adapter::OpenaiImagesRoute,
            String,
            Vec<u8>,
        )>,
        String,
        String,
    ) {
        use crate::openai_images_adapter::test_support::{
            FixedPlanSource, ScriptedProviderTransport, sample_generation_plan,
        };
        use crate::openai_images_adapter::{DecodeLimit, OpenaiImagesAdapter};

        let db = cockpit_db::Db::open_in_memory().unwrap();
        let fixture = setup_real_ledger_scheduler_job(db, suffix).await;
        let transport = Arc::new(ScriptedProviderTransport::new(vec![transport_outcome]));
        let adapter = OpenaiImagesAdapter::new(
            transport.clone(),
            Arc::new(FixedPlanSource::new(sample_generation_plan())),
            DecodeLimit::canonical(),
        );
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.dispatched, 1,
            "expected exactly one dispatched attempt"
        );
        let submissions = transport.submissions();
        let job = fixture.job_id;
        let (evidence_outcome, attempt_state) = fixture
            .db
            .read(move |conn| {
                let outcome: String = conn.query_row(
                    "SELECT outcome FROM image_generation_handoff_evidence WHERE job_id=?1",
                    [job.to_string()],
                    |row| row.get(0),
                )?;
                let state: String = conn.query_row(
                    "SELECT state FROM image_generation_attempts WHERE job_id=?1",
                    [job.to_string()],
                    |row| row.get(0),
                )?;
                Ok((outcome, state))
            })
            .await
            .unwrap();
        (submissions, evidence_outcome, attempt_state)
    }

    #[tokio::test]
    async fn image_generation_adapter_impl_openai() {
        use crate::image_generation::transport::ProviderTransportOutcome;
        use crate::openai_images_adapter::OpenaiImagesRoute;
        use crate::openai_images_adapter::test_support::sample_success_body;

        let (submissions, evidence_outcome, attempt_state) = dispatch_openai_once(
            "openai-accept",
            Ok(ProviderTransportOutcome {
                status: 200,
                body: sample_success_body(),
            }),
        )
        .await;
        // Non-vacuity: the real adapter resolved the plan, encoded a request,
        // and pushed it through the transport seam. A wiring that returned a
        // canned Accepted without submitting would leave this empty.
        assert_eq!(submissions.len(), 1);
        assert_eq!(submissions[0].0, OpenaiImagesRoute::Generations);
        assert_eq!(submissions[0].1, "application/json");
        assert!(submissions[0].2.windows(6).any(|w| w == b"prompt"));
        assert_eq!(evidence_outcome, "accepted");
        assert_eq!(attempt_state, "accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_openai_definitive_rejection() {
        use crate::image_generation::transport::ProviderTransportError;

        let (submissions, evidence_outcome, attempt_state) = dispatch_openai_once(
            "openai-reject",
            Err(ProviderTransportError::Status {
                status: 400,
                body: Vec::new(),
            }),
        )
        .await;
        assert_eq!(submissions.len(), 1, "a request was built and submitted");
        assert_eq!(evidence_outcome, "definitively_rejected");
        assert_eq!(attempt_state, "rejected_not_accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_openai_submission_unknown() {
        use crate::image_generation::transport::ProviderTransportError;

        let (submissions, evidence_outcome, attempt_state) = dispatch_openai_once(
            "openai-unknown",
            Err(ProviderTransportError::AmbiguousAcceptance),
        )
        .await;
        assert_eq!(submissions.len(), 1, "a request was built and submitted");
        assert_eq!(evidence_outcome, "submission_unknown");
        assert_eq!(attempt_state, "submission_unknown");
    }

    #[tokio::test]
    async fn image_generation_openai_unresolvable_plan_sends_no_byte() {
        // When the plan cannot be resolved, no request is built or sent, so the
        // handoff is a definitive rejection with an empty submission log.
        use crate::openai_images_adapter::test_support::{
            ScriptedProviderTransport, UnresolvablePlanSource,
        };
        use crate::openai_images_adapter::{DecodeLimit, OpenaiImagesAdapter};

        let db = cockpit_db::Db::open_in_memory().unwrap();
        let fixture = setup_real_ledger_scheduler_job(db, "openai-unresolvable").await;
        let transport = Arc::new(ScriptedProviderTransport::new(Vec::new()));
        let adapter = OpenaiImagesAdapter::new(
            transport.clone(),
            Arc::new(UnresolvablePlanSource::new("plan not available")),
            DecodeLimit::canonical(),
        );
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 1);
        assert!(
            transport.submissions().is_empty(),
            "no byte may leave when the plan is unresolvable"
        );
        let job = fixture.job_id;
        let evidence_outcome: String = fixture
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT outcome FROM image_generation_handoff_evidence WHERE job_id=?1",
                    [job.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(evidence_outcome, "definitively_rejected");
    }

    // -----------------------------------------------------------------------
    // Per-kind dispatch-trait wiring (AC7-rest): drive the REAL Gemini,
    // OpenRouter, and ComfyUI adapters through `run_scheduler_pass` with a
    // scripted transport (no network), asserting the transport classification
    // maps onto the recorded handoff evidence and attempt state. The fixture
    // and dispatcher are provider-agnostic: only the adapter varies.
    // -----------------------------------------------------------------------

    async fn read_evidence_and_state(db: &cockpit_db::Db, job_id: Uuid) -> (String, String) {
        db.read(move |conn| {
            let outcome: String = conn.query_row(
                "SELECT outcome FROM image_generation_handoff_evidence WHERE job_id=?1",
                [job_id.to_string()],
                |row| row.get(0),
            )?;
            let state: String = conn.query_row(
                "SELECT state FROM image_generation_attempts WHERE job_id=?1",
                [job_id.to_string()],
                |row| row.get(0),
            )?;
            Ok((outcome, state))
        })
        .await
        .unwrap()
    }

    async fn dispatch_gemini_once(
        suffix: &str,
        transport_outcome: Result<
            crate::image_generation::transport::ProviderTransportOutcome,
            crate::image_generation::transport::ProviderTransportError,
        >,
    ) -> (usize, String, String) {
        use crate::image_generation::adapters::gemini::GeminiImagesAdapter;
        use crate::image_generation::adapters::gemini::test_support::{
            FixedGeminiPlanSource, ScriptedGeminiTransport, sample_attempt_input,
        };

        let db = cockpit_db::Db::open_in_memory().unwrap();
        let fixture = setup_real_ledger_scheduler_job(db, suffix).await;
        let transport = Arc::new(ScriptedGeminiTransport::new(vec![transport_outcome]));
        let adapter = GeminiImagesAdapter::new(
            transport.clone(),
            Arc::new(FixedGeminiPlanSource::new(sample_attempt_input())),
        );
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.dispatched, 1,
            "expected exactly one dispatched attempt"
        );
        let (outcome, state) = read_evidence_and_state(&fixture.db, fixture.job_id).await;
        (transport.submissions().len(), outcome, state)
    }

    #[tokio::test]
    async fn image_generation_dispatcher_gemini_accepted() {
        use crate::image_generation::adapters::gemini::test_support::sample_success_body;
        use crate::image_generation::transport::ProviderTransportOutcome;

        let (submissions, outcome, state) = dispatch_gemini_once(
            "gemini-accept",
            Ok(ProviderTransportOutcome {
                status: 200,
                body: sample_success_body(),
            }),
        )
        .await;
        assert_eq!(submissions, 1, "a request was built and submitted");
        assert_eq!(outcome, "accepted");
        assert_eq!(state, "accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_gemini_definitive_rejection() {
        use crate::image_generation::transport::ProviderTransportError;

        let (submissions, outcome, state) = dispatch_gemini_once(
            "gemini-reject",
            Err(ProviderTransportError::Status {
                status: 400,
                body: Vec::new(),
            }),
        )
        .await;
        assert_eq!(submissions, 1);
        assert_eq!(outcome, "definitively_rejected");
        assert_eq!(state, "rejected_not_accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_gemini_submission_unknown() {
        use crate::image_generation::transport::ProviderTransportError;

        let (submissions, outcome, state) = dispatch_gemini_once(
            "gemini-unknown",
            Err(ProviderTransportError::AmbiguousAcceptance),
        )
        .await;
        assert_eq!(submissions, 1);
        assert_eq!(outcome, "submission_unknown");
        assert_eq!(state, "submission_unknown");
    }

    async fn dispatch_openrouter_once(
        suffix: &str,
        transport_outcome: Result<
            crate::image_generation::transport::ProviderTransportOutcome,
            crate::image_generation::transport::ProviderTransportError,
        >,
    ) -> (usize, String, String) {
        use crate::image_generation::adapters::openrouter::OpenrouterImagesAdapter;
        use crate::image_generation::adapters::openrouter::test_support::{
            FixedOpenrouterPlanSource, ScriptedOpenrouterTransport, sample_attempt_input,
        };

        let db = cockpit_db::Db::open_in_memory().unwrap();
        let fixture = setup_real_ledger_scheduler_job(db, suffix).await;
        let transport = Arc::new(ScriptedOpenrouterTransport::new(vec![transport_outcome]));
        let adapter = OpenrouterImagesAdapter::new(
            transport.clone(),
            Arc::new(FixedOpenrouterPlanSource::new(sample_attempt_input())),
        );
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.dispatched, 1,
            "expected exactly one dispatched attempt"
        );
        let (outcome, state) = read_evidence_and_state(&fixture.db, fixture.job_id).await;
        (transport.submissions().len(), outcome, state)
    }

    #[tokio::test]
    async fn image_generation_dispatcher_openrouter_accepted() {
        use crate::image_generation::adapters::openrouter::test_support::sample_success_body;
        use crate::image_generation::transport::ProviderTransportOutcome;

        let (submissions, outcome, state) = dispatch_openrouter_once(
            "openrouter-accept",
            Ok(ProviderTransportOutcome {
                status: 200,
                body: sample_success_body(),
            }),
        )
        .await;
        assert_eq!(submissions, 1, "a request was built and submitted");
        assert_eq!(outcome, "accepted");
        assert_eq!(state, "accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_openrouter_definitive_rejection() {
        use crate::image_generation::transport::ProviderTransportError;

        let (submissions, outcome, state) = dispatch_openrouter_once(
            "openrouter-reject",
            Err(ProviderTransportError::Status {
                status: 400,
                body: Vec::new(),
            }),
        )
        .await;
        assert_eq!(submissions, 1);
        assert_eq!(outcome, "definitively_rejected");
        assert_eq!(state, "rejected_not_accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_openrouter_submission_unknown() {
        use crate::image_generation::transport::ProviderTransportError;

        let (submissions, outcome, state) = dispatch_openrouter_once(
            "openrouter-unknown",
            Err(ProviderTransportError::AmbiguousAcceptance),
        )
        .await;
        assert_eq!(submissions, 1);
        assert_eq!(outcome, "submission_unknown");
        assert_eq!(state, "submission_unknown");
    }

    async fn dispatch_comfyui_once(
        suffix: &str,
        transport_outcome: Result<
            crate::image_generation::transport::ProviderTransportOutcome,
            crate::image_generation::transport::ProviderTransportError,
        >,
    ) -> (usize, String, String) {
        use crate::image_generation::adapters::comfyui::ComfyuiImagesAdapter;
        use crate::image_generation::adapters::comfyui::test_support::{
            ScriptedComfyuiTransport, resolved_handoff_source,
        };

        let db = cockpit_db::Db::open_in_memory().unwrap();
        let fixture = setup_real_ledger_scheduler_job(db, suffix).await;
        let transport = Arc::new(ScriptedComfyuiTransport::new(vec![transport_outcome]));
        let adapter =
            ComfyuiImagesAdapter::new(transport.clone(), Arc::new(resolved_handoff_source()));
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.dispatched, 1,
            "expected exactly one dispatched attempt"
        );
        let (outcome, state) = read_evidence_and_state(&fixture.db, fixture.job_id).await;
        (transport.calls().len(), outcome, state)
    }

    #[tokio::test]
    async fn image_generation_dispatcher_comfyui_accepted() {
        use crate::image_generation::adapters::comfyui::test_support::sample_prompt_accept_body;
        use crate::image_generation::transport::ProviderTransportOutcome;

        let (calls, outcome, state) = dispatch_comfyui_once(
            "comfyui-accept",
            Ok(ProviderTransportOutcome {
                status: 200,
                body: sample_prompt_accept_body(),
            }),
        )
        .await;
        assert_eq!(calls, 1, "a POST /prompt was built and submitted");
        assert_eq!(outcome, "accepted");
        assert_eq!(state, "accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_comfyui_definitive_rejection() {
        use crate::image_generation::transport::ProviderTransportError;

        let (calls, outcome, state) = dispatch_comfyui_once(
            "comfyui-reject",
            Err(ProviderTransportError::Status {
                status: 400,
                body: Vec::new(),
            }),
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(outcome, "definitively_rejected");
        assert_eq!(state, "rejected_not_accepted");
    }

    #[tokio::test]
    async fn image_generation_dispatcher_comfyui_submission_unknown() {
        use crate::image_generation::transport::ProviderTransportError;

        let (calls, outcome, state) = dispatch_comfyui_once(
            "comfyui-unknown",
            Err(ProviderTransportError::AmbiguousAcceptance),
        )
        .await;
        assert_eq!(calls, 1);
        assert_eq!(outcome, "submission_unknown");
        assert_eq!(state, "submission_unknown");
    }

    async fn setup_real_ledger_scheduler_job_with_attempts(
        db: cockpit_db::Db,
        suffix: &str,
        max_attempts: u32,
    ) -> RealLedgerSchedulerFixture {
        setup_real_ledger_scheduler_job_with_output_and_attempts(db, suffix, None, max_attempts)
            .await
    }

    async fn setup_real_ledger_scheduler_job_with_output(
        db: cockpit_db::Db,
        suffix: &str,
        output: Option<VerifiedOutputDirectoryAuthority>,
    ) -> RealLedgerSchedulerFixture {
        setup_real_ledger_scheduler_job_with_output_and_attempts(db, suffix, output, 1).await
    }

    async fn setup_real_ledger_scheduler_job_with_output_and_attempts(
        db: cockpit_db::Db,
        suffix: &str,
        output: Option<VerifiedOutputDirectoryAuthority>,
        max_attempts: u32,
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
        if suffix.starts_with("svg-response") {
            sealed.targets[0].requested.format = "svg".into();
            sealed.targets[0].resolved.format = "svg".into();
            sealed.targets[0].resolved.mime = "image/svg+xml".into();
            sealed.targets[0].resolved.vector_sanitization_required = true;
            sealed.targets[0].resolved.vector_sanitizer =
                Some(crate::generated_svg::sanitizer_provenance());
            sealed.targets[0].slots[0].publication_name = "generated-000000.svg".into();
        }
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
        let template = sealed.targets[0].slots[0].attempts[0].clone();
        sealed.targets[0].max_attempts = max_attempts;
        sealed.targets[0].slots[0].attempts = (1..=max_attempts)
            .map(|number| {
                let mut attempt = template.clone();
                attempt.attempt_number = number;
                attempt.provider_request_identity = format!("{provider_request_identity}:{number}");
                attempt.provider_idempotency_identity =
                    format!("{provider_idempotency_identity}:{number}");
                attempt
            })
            .collect();
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
        let per_attempt_resource = resource_reservation_from_media_reservation(
            &handoff,
            sealed.central_resources[0].reservation_identity.clone(),
        )
        .unwrap();
        sealed.central_resources[0] = per_attempt_resource.clone();
        sealed.central_resources[0].units = u64::from(max_attempts);
        for attempt in &mut sealed.targets[0].slots[0].attempts {
            attempt.resource_maximum = vec![per_attempt_resource.clone()];
        }
        sealed.spend.maximum_usd_micros = Some(u64::from(max_attempts) * 10);
        let canonical = sealed.canonical_bytes().unwrap();
        let plan_digest = sealed.digest().unwrap();
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
                session_id: cockpit_db::image_spend::SessionId::new(
                    sealed.owner_session_id.to_string(),
                )
                .unwrap(),
                project_key: cockpit_db::image_spend::ProjectKey::new(project_id).unwrap(),
            },
            (1..=max_attempts)
                .map(|number| AttemptMaximum {
                    attempt_id: format!("{provider_idempotency_identity}:{number}"),
                    usd_micros: Some(10),
                })
                .collect(),
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
                    attempts: slot
                        .attempts
                        .iter()
                        .map(|attempt| CreateImageGenerationAttempt {
                            attempt_number: attempt.attempt_number,
                            provider_request_identity: attempt.provider_request_identity.clone(),
                            provider_idempotency_identity: attempt
                                .provider_idempotency_identity
                                .clone(),
                        })
                        .collect(),
                }],
            )?;
            let authority =
                cockpit_db::Db::image_generation_queue_authority_conn(conn, sealed.job_id)?;
            let (bytes, digest) = canonical_media_plan_snapshot(&handoff)?;
            let snapshots = (1..=max_attempts)
                .map(|attempt_number| ImageGenerationMediaPlanSnapshot {
                    slot_id: slot.slot_id,
                    attempt_number,
                    canonical_bytes: &bytes,
                    digest: &digest,
                })
                .collect::<Vec<_>>();
            cockpit_db::Db::queue_image_generation_job_conn(conn, authority, &snapshots, 1)
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

    // A fixed clock + a sleeper that begins the shutdown drain on its first call
    // so the worker runs exactly one cycle and stops (no real-time sleep).
    struct WorkerFixedClock {
        monotonic_ms: u64,
        wall_unix_ms: i64,
    }
    impl crate::daemon::image_generation_worker::ImageGenerationWorkerClock for WorkerFixedClock {
        fn monotonic_ms(&self) -> u64 {
            self.monotonic_ms
        }
        fn wall_unix_ms(&self) -> i64 {
            self.wall_unix_ms
        }
    }
    struct WorkerDrainAfterOneCycle(crate::daemon::shutdown::ShutdownSignal);
    impl crate::daemon::image_generation_worker::ImageGenerationWorkerSleeper
        for WorkerDrainAfterOneCycle
    {
        fn sleep(
            &self,
            _duration: std::time::Duration,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            self.0.begin_drain();
            Box::pin(async {})
        }
    }

    // AC11: a claimed candidate whose sealed adapter kind has no registered
    // adapter is a typed adapter_missing skip. `skipped` increments, a scheduler
    // error is recorded with adapter_missing semantics, nothing panics or
    // dispatches, and the attempt stays `planned` (re-claimable later).
    #[tokio::test]
    async fn image_generation_adapter_missing_is_typed_skip() {
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open_in_memory().unwrap(),
            "adapter-missing",
        )
        .await;
        // Empty map: the plan's sealed destination kind ("fixture") has no
        // adapter, so the candidate must skip at adapter_missing.
        let adapters = ImageGenerationAdapterMap::new();
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass_with_adapters(&adapters, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(
            pass.scanned, 1,
            "the queued candidate is visible: {pass:#?}"
        );
        assert_eq!(pass.claimed, 0, "adapter_missing skips before claiming");
        assert_eq!(pass.dispatched, 0);
        assert_eq!(pass.skipped, 1);
        let job = fixture.job_id;
        let (stage, count): (String, i64) = fixture
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT stage,failure_count FROM image_generation_scheduler_error_counts WHERE job_id=?1",
                    [job.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(stage, "adapter_missing");
        assert_eq!(count, 1);
        let state: String = fixture
            .db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT state FROM image_generation_attempts WHERE job_id=?1",
                    [job.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(state, "planned");
    }

    #[tokio::test]
    async fn unavailable_owner_route_defers_before_claim_and_preserves_attempt() {
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open_in_memory().unwrap(),
            "owner-route-deferred",
        )
        .await;
        let adapter = DeferredHandoffAdapter {
            calls: AtomicUsize::new(0),
        };
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.claimed, 0, "deferred routing must not consume a claim");
        assert_eq!(pass.dispatched, 0);
        assert_eq!(pass.skipped, 1);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 0);
        let job_id = fixture.job_id;
        let (attempt_state, stage): (String, String) = fixture
            .db
            .read(move |conn| {
                Ok((
                    conn.query_row(
                        "SELECT state FROM image_generation_attempts WHERE job_id=?1",
                        [job_id.to_string()],
                        |row| row.get(0),
                    )?,
                    conn.query_row(
                        "SELECT stage FROM image_generation_scheduler_error_counts WHERE job_id=?1",
                        [job_id.to_string()],
                        |row| row.get(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(attempt_state, "planned");
        assert_eq!(stage, "handoff_deferred");
    }

    // The prior-boot reconciliation runs its boot-scoped artifact-lease repair
    // without error on the production path. (Lease *release* of a real prior-boot
    // lease is exercised by the cockpit-db `repair_..._for_boot_conn` unit test;
    // the worker invokes exactly that helper before its loop.)
    #[tokio::test]
    async fn image_generation_prior_boot_reconciliation_runs_lease_repair() {
        let db = cockpit_db::Db::open_in_memory().unwrap();
        let swept = ImageGenerationDispatcher::new(db)
            .run_prior_boot_reconciliation(Uuid::now_v7())
            .await
            .unwrap();
        assert_eq!(swept.artifact_leases_released, 0);
    }

    // AC2: the worker runs prior-boot reconciliation BEFORE the current boot can
    // claim scheduler work, and a crashed prior boot's scheduler claim never
    // strands the current boot. Scheduler claims are immutable and carry a
    // bounded wall-clock TTL, so a prior boot's claim simply expires and does not
    // gate this boot's scan; the worker's active prior-boot step is the
    // artifact-lease repair (invoked before the loop, observed via
    // `prior_boot_swept`). The worker's boot id is the plan's deadline boot id
    // (the shared daemon boot UUID), so the queued candidate is visible on the
    // SAME boot's first scheduler pass.
    #[tokio::test]
    async fn image_generation_worker_prior_boot_reconciliation_before_schedule() {
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open_in_memory().unwrap(),
            "prior-boot",
        )
        .await;
        let other_boot = Uuid::now_v7();
        let now_ms = chrono::Utc::now().timestamp_millis();
        let job = fixture.job_id;
        let slot = fixture.slot_id;
        // A crashed prior boot left a scheduler claim whose bounded wall-clock TTL
        // has since lapsed (`expires_at_unix_ms` in the past).
        fixture
            .db
            .transaction(move |conn| {
                conn.execute(
                    "INSERT INTO image_generation_scheduler_claims(job_id,slot_id,attempt_number,worker_boot_id,claim_generation,claimed_at_unix_ms,expires_at_unix_ms) VALUES(?1,?2,1,?3,1,?4,?5)",
                    params![
                        job.to_string(),
                        slot.to_string(),
                        other_boot.to_string(),
                        now_ms - 120_000,
                        now_ms - 61_000
                    ],
                )?;
                Ok(())
            })
            .await
            .unwrap();

        let shutdown = crate::daemon::shutdown::ShutdownSignal::new();
        let worker = crate::daemon::image_generation_worker::ImageGenerationWorker::new(
            fixture.db.clone(),
            deadline_boot(),
            ImageGenerationAdapterMap::new(),
            Arc::new(proof_ok()),
            Arc::new(WorkerFixedClock {
                monotonic_ms: 100,
                wall_unix_ms: 2,
            }),
            Arc::new(WorkerDrainAfterOneCycle(shutdown.clone())),
            crate::daemon::image_generation_worker::ImageGenerationWorkerConfig::default(),
        );
        let metrics = worker.metrics();
        worker.run(shutdown).await;

        assert!(
            metrics.prior_boot_swept(),
            "prior-boot reconciliation must run before the schedule loop"
        );
        assert!(
            metrics.scanned() >= 1,
            "the queued candidate reaches the schedule pass despite the crashed prior-boot claim"
        );
        assert!(
            metrics.skipped() >= 1,
            "the empty adapter map skips the visible candidate at adapter_missing"
        );
        assert_eq!(
            metrics.dispatched(),
            0,
            "no dispatch without a registered adapter for the sealed kind"
        );
    }

    // AC10: `ImageGenerationJobService` turns an authorized request into a
    // durable `queued` job (resolve preflight, then commit graph + queue) without
    // calling any agent tool or Approver. The committed job is claimable by
    // `run_scheduler_pass` with a `DeterministicImageGenerationAdapter` and
    // reaches an `accepted` terminal.
    #[tokio::test]
    async fn image_generation_job_service_creates_queued_job_without_tool() {
        use crate::media_reservation::{
            MediaOwner, MediaReservationLedger, ReservationState, ReserveRequest,
        };
        use cockpit_config::config::media_budget::{
            MediaDimension, MediaEvaluationRequest, MediaResourcePolicy,
        };
        use cockpit_db::image_spend::{
            AttemptMaximum, BudgetPolicy, ImageSpendSettings, ProjectEpochPolicy, SpendScopeKeys,
        };

        let db = cockpit_db::Db::open_in_memory().unwrap();
        let suffix = "service";
        let project_id = format!("svc-project-{suffix}");
        let project_root = format!("/svc-project-{suffix}");
        let session = db
            .create_session(
                &project_id,
                &project_root,
                "Image generation service fixture",
            )
            .await
            .unwrap();

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
        let per_attempt_resource =
            resource_reservation_from_media_reservation(&handoff, format!("svc-gpu:{suffix}"))
                .unwrap();

        // Build request + authority: single attempt, png/quality, retargeted to
        // this session and the media-policy resource shape.
        let base = plan();
        let base_target = base.targets[0].clone();
        let request = ImageGenerationRequestV1 {
            targets: vec![ImageGenerationTargetRequestV1 {
                target_id: base_target.target_id.clone(),
                width: base_target.requested.width,
                height: base_target.requested.height,
                format: base_target.requested.format.clone(),
                samples: 1,
                parameters: base_target.typed_parameters.clone(),
            }],
            reference_attachment_ids: vec![],
        };
        let job_id = id(6_000);
        let slot_id = id(6_001);
        let artifact_id = id(6_002);
        let mut spend = base.spend.clone();
        spend.reservation_id = format!("svc-spend:{suffix}");
        spend.maximum_usd_micros = Some(10);
        let authority = ImageGenerationResolutionAuthorityV1 {
            job_id,
            owner: ImageGenerationOwnerContextAuthority {
                session_id: session.session_id,
                project_id: project_id.clone(),
                principal_digest: crate::intel::hex_lower(&Sha256::digest(
                    serde_json::to_vec(&ClientPrincipal::Owner).unwrap(),
                )),
                project_identity_digest: crate::intel::hex_lower(&Sha256::digest(
                    project_root.as_bytes(),
                )),
                config_generation: base.config_generation,
            },
            deadline_boot_id: base.deadline_boot_id,
            enqueue_started_monotonic_ms: base.enqueue_started_monotonic_ms,
            operation_deadline_monotonic_ms: base.operation_deadline_monotonic_ms,
            required_grants: base.required_grants.clone(),
            central_resources: vec![per_attempt_resource.clone()],
            spend,
            output_authority: VerifiedOutputDirectoryAuthority(base.output_authority.clone()),
            sealed_prompt: base.sealed_prompt.clone(),
            targets: vec![ImageGenerationTargetResolutionAuthorityV1 {
                runtime: RuntimeTargetAuthorityV1 {
                    target_id: base_target.target_id.clone(),
                    target_config_generation: base_target.target_config_generation,
                    normalized_config_digest: base_target.normalized_config_digest.clone(),
                    capability_provenance: base_target.capability_provenance.clone(),
                    destination: base_target.destination.clone(),
                    supported_formats: BTreeMap::from([("png".into(), "image/png".into())]),
                    maximum_width: 512,
                    maximum_height: 512,
                    allowed_parameters: BTreeMap::from([("quality".into(), "integer".into())]),
                    max_attempts: 1,
                    required_grant: "image_generation".into(),
                },
                references: base_target.reference_artifacts.clone(),
                slot_artifact_ids: vec![(slot_id, artifact_id)],
                max_attempts: 1,
                attempt_resources: vec![per_attempt_resource.clone()],
                attempt_maximum_usd_micros: vec![Some(10)],
                spend_attempt_identities: vec![format!("svc-idem:{suffix}:1")],
            }],
        };

        // Resolve once to learn the exact plan the service will commit; reserve
        // spend + media against THAT plan (no round-trip equality assumption).
        let ImageGenerationResolutionV1::Ready(resolved) =
            resolve_image_generation(request.clone(), authority.clone()).unwrap()
        else {
            panic!("service authority did not resolve")
        };
        let plan_digest = resolved.digest().unwrap();
        let media_identity = resolved.central_resources[0].reservation_identity.clone();
        let attempt_idem = resolved.targets[0].slots[0].attempts[0]
            .provider_idempotency_identity
            .clone();

        let ledger = MediaReservationLedger::new(db.clone(), Arc::new(SchedulerClock));
        let receipt = ledger
            .reserve(ReserveRequest {
                reservation_id: media_identity.clone(),
                recovery_id: format!("svc-recovery-{suffix}"),
                owner: MediaOwner {
                    project_id: project_id.clone(),
                    session_id: session.session_id.to_string(),
                },
                operation: "image_generation".into(),
                purpose: format!("svc_{suffix}"),
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
            resolved.spend.reservation_id.clone(),
            SpendScopeKeys {
                plan_digest: plan_digest.clone(),
                session_id: cockpit_db::image_spend::SessionId::new(session.session_id.to_string())
                    .unwrap(),
                project_key: cockpit_db::image_spend::ProjectKey::new(project_id).unwrap(),
            },
            vec![AttemptMaximum {
                attempt_id: attempt_idem,
                usd_micros: Some(10),
            }],
            1,
            1,
        )
        .await
        .unwrap();

        // The service commits the job (resolve + graph + queue). No tool call.
        let (media_bytes, media_digest) = canonical_media_plan_snapshot(&handoff).unwrap();
        let created = ImageGenerationJobService::new(db.clone())
            .create_queued_job(
                request,
                authority,
                vec![ImageGenerationMediaSnapshotInput {
                    slot_id,
                    attempt_number: 1,
                    canonical_bytes: media_bytes,
                    digest: media_digest,
                }],
                Vec::new(),
                None,
                1,
            )
            .await
            .unwrap();
        assert_eq!(created, ImageGenerationJobCreation::Queued { job_id });

        // The queued job is claimable and dispatches to an accepted terminal.
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"svc-accepted".to_vec(),
            },
        ]);
        let pass = ImageGenerationDispatcher::new(db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 1, "{pass:#?}");
        assert_eq!(adapter.requests().len(), 1, "exactly one provider handoff");
        let state: String = db
            .read(move |conn| {
                Ok(conn.query_row(
                    "SELECT state FROM image_generation_attempts WHERE job_id=?1",
                    [job_id.to_string()],
                    |row| row.get(0),
                )?)
            })
            .await
            .unwrap();
        assert_eq!(state, "accepted");
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
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(first.dispatched, 1, "{first:#?}");
        assert_eq!(adapter.requests().len(), 1);
        db.write(move |conn| {
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
        .await
        .unwrap();
        let second = dispatcher
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 3, 3, 8)
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
    async fn authoritative_rejection_advances_exact_attempt_and_exhaustion_is_terminal() {
        let fixture = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open_in_memory().unwrap(),
            "retry-three",
            3,
        )
        .await;
        let dispatcher = ImageGenerationDispatcher::new(fixture.db.clone());
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"reject-1".to_vec(),
            },
            ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"reject-2".to_vec(),
            },
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accept-3".to_vec(),
            },
        ]);
        for at in 2..=4 {
            let pass = dispatcher
                .run_scheduler_pass(
                    &adapter,
                    &proof_ok(),
                    deadline_boot(),
                    100,
                    at,
                    at as u64,
                    8,
                )
                .await
                .unwrap();
            assert_eq!(pass.dispatched, 1, "{pass:#?}");
        }
        assert_eq!(
            adapter
                .requests()
                .iter()
                .map(|request| request.attempt_number)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
        fixture.db.read(move|conn|{
            let states=conn.prepare("SELECT attempt_number,state FROM image_generation_attempts WHERE job_id=?1 ORDER BY attempt_number")?.query_map([fixture.job_id.to_string()],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(states,vec![(1,"rejected_not_accepted".into()),(2,"rejected_not_accepted".into()),(3,"accepted".into())]);
            let activations:i64=conn.query_row("SELECT count(*) FROM image_generation_attempt_activation_facts WHERE job_id=?1",[fixture.job_id.to_string()],|row|row.get(0))?; assert_eq!(activations,3);
            let original:String=conn.query_row("SELECT state FROM media_reservations WHERE reservation_id=?1",[fixture.media_reservation_id.clone()],|row|row.get(0))?;
            assert_eq!(original,"released");
            let retry_id=cockpit_db::db::image_generation::image_generation_attempt_media_reservation_id(&fixture.media_reservation_id,fixture.slot_id,3);
            let latest:String=conn.query_row("SELECT state FROM media_reservations WHERE reservation_id=?1",[&retry_id],|row|row.get(0))?;
            assert_eq!(latest,"external_pending");
            Ok(())
        }).await.unwrap();

        let exhausted = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open_in_memory().unwrap(),
            "retry-one",
            1,
        )
        .await;
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"final-reject".to_vec(),
            },
        ]);
        ImageGenerationDispatcher::new(exhausted.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        exhausted
            .db
            .read(move |conn| {
                let event = cockpit_db::Db::replay_image_generation_terminal_event_conn(
                    conn,
                    exhausted.job_id,
                )?
                .context("exhausted retry terminal event missing")?;
                assert_eq!(
                    event.terminal_state,
                    cockpit_db::db::image_generation::ImageGenerationJobState::Failed
                );
                assert_eq!(event.failed_count, 1);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ambiguous_handoff_never_activates_or_redispatches_retry() {
        let fixture = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open_in_memory().unwrap(),
            "retry-unknown",
            3,
        )
        .await;
        let dispatcher = ImageGenerationDispatcher::new(fixture.db.clone());
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"unknown".to_vec(),
            },
        ]);
        assert_eq!(
            dispatcher
                .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
                .await
                .unwrap()
                .dispatched,
            1
        );
        assert_eq!(
            dispatcher
                .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 3, 3, 8)
                .await
                .unwrap()
                .dispatched,
            0
        );
        assert_eq!(adapter.requests().len(), 1);
        fixture.db.read(move|conn|{let activations:i64=conn.query_row("SELECT count(*) FROM image_generation_attempt_activation_facts WHERE job_id=?1",[fixture.job_id.to_string()],|row|row.get(0))?;assert_eq!(activations,1);Ok(())}).await.unwrap();
    }

    #[tokio::test]
    async fn authoritative_retry_survives_file_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("retry.db");
        let fixture = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open(&path).unwrap(),
            "retry-reopen",
            2,
        )
        .await;
        let first = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"reopen-reject".to_vec(),
            },
        ]);
        ImageGenerationDispatcher::new(fixture.db)
            .run_scheduler_pass(&first, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        let reopened = cockpit_db::Db::open(&path).unwrap();
        let second = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"reopen-accept".to_vec(),
            },
        ]);
        assert_eq!(
            ImageGenerationDispatcher::new(reopened)
                .run_scheduler_pass(&second, &proof_ok(), deadline_boot(), 100, 3, 3, 8)
                .await
                .unwrap()
                .dispatched,
            1
        );
        assert_eq!(second.requests()[0].attempt_number, 2);
    }

    #[tokio::test]
    async fn retry_finish_fault_cuts_roll_back_every_projection() {
        for (name, trigger, max_attempts) in [
            (
                "evidence",
                "CREATE TEMP TRIGGER retry_cut BEFORE INSERT ON image_generation_handoff_evidence BEGIN SELECT RAISE(ABORT,'cut'); END",
                2,
            ),
            (
                "activation",
                "CREATE TEMP TRIGGER retry_cut BEFORE INSERT ON image_generation_attempt_activation_facts WHEN NEW.activation_reason='authoritative_retry' BEGIN SELECT RAISE(ABORT,'cut'); END",
                2,
            ),
            (
                "media",
                "CREATE TEMP TRIGGER retry_cut BEFORE UPDATE ON media_reservations WHEN NEW.state='executing_local' BEGIN SELECT RAISE(ABORT,'cut'); END",
                2,
            ),
            (
                "slot",
                "CREATE TEMP TRIGGER retry_cut BEFORE UPDATE ON image_generation_slots WHEN NEW.state IN ('queued','failed') BEGIN SELECT RAISE(ABORT,'cut'); END",
                2,
            ),
            (
                "job",
                "CREATE TEMP TRIGGER retry_cut BEFORE UPDATE ON image_generation_jobs WHEN NEW.state IN ('queued','failed') BEGIN SELECT RAISE(ABORT,'cut'); END",
                2,
            ),
            (
                "event",
                "CREATE TEMP TRIGGER retry_cut BEFORE INSERT ON image_generation_terminal_events BEGIN SELECT RAISE(ABORT,'cut'); END",
                1,
            ),
        ] {
            let fixture = setup_real_ledger_scheduler_job_with_attempts(
                cockpit_db::Db::open_in_memory().unwrap(),
                &format!("retry-cut-{name}"),
                max_attempts,
            )
            .await;
            fixture
                .db
                .write(move |conn| {
                    conn.execute_batch(trigger)?;
                    Ok(())
                })
                .await
                .unwrap();
            let adapter = DeterministicImageGenerationAdapter::new(vec![
                ImageGenerationHandoffResult::DefinitivelyRejected {
                    evidence: format!("reject-{name}").into_bytes(),
                },
            ]);
            let pass = ImageGenerationDispatcher::new(fixture.db.clone())
                .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
                .await
                .unwrap();
            assert_eq!(pass.dispatched, 0, "{name}: {pass:#?}");
            assert_eq!(adapter.requests().len(), 1, "{name}");
            fixture.db.read(move|conn|{let row:(String,String,i64,i64)=conn.query_row("SELECT a.state,o.state,(SELECT count(*) FROM image_generation_handoff_evidence e WHERE e.job_id=a.job_id),(SELECT count(*) FROM image_generation_attempt_activation_facts f WHERE f.job_id=a.job_id AND f.activation_reason='authoritative_retry') FROM image_generation_attempts a JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE a.job_id=?1 AND a.attempt_number=1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;assert_eq!(row,("dispatching".into(),"dispatching".into(),0,0),"{name}");Ok(())}).await.unwrap();
        }
    }

    #[tokio::test]
    async fn deadline_expiry_fact_replays_and_survives_reopen_without_releasing() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("deadline.db");
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open(&path).unwrap(),
            "deadline-intent",
        )
        .await;
        let job_id = fixture.job_id;
        let media_id = fixture.media_reservation_id.clone();
        let spend_id = fixture.spend_reservation_id.clone();
        let fact = fixture.db.write(move |conn| {
            assert!(cockpit_db::Db::record_image_generation_deadline_expiry_conn(
                conn,
                job_id,
                cockpit_db::db::image_generation::DeadlineObservationV1::new(
                    deadline_boot(),
                    399,
                )?,
                8,
            )
            .is_err());
            let observation = cockpit_db::db::image_generation::DeadlineObservationV1::new(
                deadline_boot(),
                400,
            )?;
            let first = cockpit_db::Db::record_image_generation_deadline_expiry_conn(
                conn, job_id, observation, 9,
            )?;
            let replay = cockpit_db::Db::record_image_generation_deadline_expiry_conn(
                conn, job_id, observation, 99,
            )?;
            assert_eq!(first, replay);
            assert!(conn.execute(
                "UPDATE image_generation_deadline_expiry_facts SET state='cancellation_requested' WHERE job_id=?1",
                [job_id.to_string()],
            ).is_err());
            Ok(first)
        }).await.unwrap();
        assert_eq!(
            fact.disposition,
            cockpit_db::db::image_generation::ImageGenerationDeadlineExpiryDisposition::CleanupRequired
        );
        drop(fixture.db);
        cockpit_db::Db::open(&path).unwrap().read(move |conn| {
            let stored:(String,String,String)=conn.query_row(
                "SELECT d.state,m.state,s.state FROM image_generation_deadline_expiry_facts d JOIN media_reservations m ON m.reservation_id=d.media_reservation_id JOIN image_spend_reservations s ON s.reservation_id=d.spend_reservation_id WHERE d.job_id=?1",
                [job_id.to_string()],
                |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
            )?;
            assert_eq!(stored.0,"cleanup_required");
            assert_eq!(stored.1,"executing_local");
            assert_eq!(stored.2,"reserved");
            assert_eq!(fact.media_reservation_id,media_id);
            assert_eq!(fact.spend_reservation_id,spend_id);
            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn deadline_expiry_after_retry_binds_live_attempt_reservation() {
        let fixture = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open_in_memory().unwrap(),
            "deadline-retry",
            2,
        )
        .await;
        let job_id = fixture.job_id;
        let sealed = fixture.media_reservation_id.clone();
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"reject-then-expire".to_vec(),
            },
        ]);
        ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        let fact = fixture
            .db
            .write(move |conn| {
                cockpit_db::Db::record_image_generation_deadline_expiry_conn(
                    conn,
                    job_id,
                    cockpit_db::db::image_generation::DeadlineObservationV1::new(
                        deadline_boot(),
                        400,
                    )?,
                    9,
                )
            })
            .await
            .unwrap();
        assert_eq!(
            fact.media_reservation_id,
            cockpit_db::db::image_generation::image_generation_attempt_media_reservation_id(
                &sealed,
                fixture.slot_id,
                2,
            )
        );
        assert_ne!(fact.media_reservation_id, sealed);
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
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        let reopened = cockpit_db::Db::open(&path).unwrap();
        reopened
            .read(move |conn| {
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
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn accepted_response_fetch_replays_without_refetch() {
        let (fixture, _) = setup_accepted_response_fixture("response-fetch-replay").await;
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: b"canonical-response".to_vec(),
                evidence: b"fetch-proof".to_vec(),
            }],
            vec![],
        );
        let first = fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let replay = fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            11,
        )
        .await
        .unwrap();
        assert_eq!(first, replay);
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        fixture
            .db
            .read(move |conn| {
                let rows: i64 = conn.query_row(
                    "SELECT count(*) FROM image_generation_response_fetch_outcomes WHERE job_id=?1",
                    [fixture.job_id.to_string()],
                    |row| row.get(0),
                )?;
                assert_eq!(rows, 1);
                Ok(())
            })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn accepted_response_unknown_reconciles_once_and_replays() {
        let (fixture, _) = setup_accepted_response_fixture("response-unknown").await;
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::OutcomeUnknown {
                evidence: b"unknown-proof".to_vec(),
            }],
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: b"reconciled-response".to_vec(),
                evidence: b"reconcile-proof".to_vec(),
            }],
        );
        assert!(matches!(
            fetch_accepted_image_response(
                fixture.db.clone(),
                &fetcher,
                fixture.job_id,
                fixture.slot_id,
                1,
                10
            )
            .await
            .unwrap(),
            AcceptedImageResponseFetchOutcome::OutcomeUnknown { .. }
        ));
        let boot = Uuid::now_v7();
        let resolved = reconcile_unknown_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            boot,
            11,
        )
        .await
        .unwrap();
        let replay = reconcile_unknown_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            boot,
            12,
        )
        .await
        .unwrap();
        assert_eq!(resolved, replay);
        assert_eq!(
            fetcher
                .fetch_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert_eq!(
            fetcher
                .reconcile_count
                .load(std::sync::atomic::Ordering::SeqCst),
            1
        );
    }

    #[tokio::test]
    async fn accepted_response_definitive_failure_terminalizes_and_replays() {
        let (fixture, _) = setup_accepted_response_fixture("response-failed").await;
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::DefinitiveFailure {
                safe_reason: "provider_response_invalid".into(),
                evidence: b"failure-proof".to_vec(),
            }],
            vec![],
        );
        let first = fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let replay = fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            11,
        )
        .await
        .unwrap();
        assert_eq!(first, replay);
        fixture.db.read(move|conn|{let state:(String,String,String)=conn.query_row("SELECT a.state,s.state,j.state FROM image_generation_attempts a JOIN image_generation_slots s USING(job_id,slot_id) JOIN image_generation_jobs j USING(job_id) WHERE a.job_id=?1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;assert_eq!(state,("failed_after_acceptance".into(),"failed".into(),"failed".into()));Ok(())}).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_raster_uses_durable_intent_and_replays_startup() {
        use std::os::unix::fs::PermissionsExt;
        let (fixture, request) = setup_accepted_response_fixture("response-raster").await;
        let mut cursor = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(512, 512)
            .write_to(&mut cursor, image::ImageFormat::Png)
            .unwrap();
        let bytes = cursor.into_inner();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"raster-fetch-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        let progress = coordinate_persisted_accepted_image_response(
            fixture.db.clone(),
            root.clone(),
            CoordinateAcceptedImageResponse {
                job_id: fixture.job_id,
                slot_id: fixture.slot_id,
                attempt_number: 1,
                expected_job_version: 5,
                expected_slot_version: 4,
                expected_attempt_version: 5,
                external_operation_id: request.external_operation_id,
                expected_journal_version: 3,
                component_id: Uuid::now_v7(),
                release_operation_id: Uuid::now_v7(),
                bytes,
                now_unix_ms: 11,
            },
        )
        .await
        .unwrap();
        assert_eq!(progress, AcceptedImageResponseProgress::Retained);
        assert_eq!(
            reconcile_pending_accepted_response_publications(fixture.db.clone(), root, 12)
                .await
                .unwrap(),
            0
        );
        fixture.db.read(move|conn|{let row:(String,i64)=conn.query_row("SELECT state,(SELECT count(*) FROM image_generation_artifact_components WHERE artifact_id=i.artifact_id) FROM image_generation_response_publication_intents i WHERE job_id=?1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;assert_eq!(row,("applied".into(),1));Ok(())}).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn retain_accepted_retry_attempt_binds_attempt_reservation() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open_in_memory().unwrap(),
            "retain-retry",
            2,
        )
        .await;
        let sealed = fixture.media_reservation_id.clone();
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::DefinitivelyRejected {
                evidence: b"reject-1".to_vec(),
            },
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accept-2".to_vec(),
            },
        ]);
        let dispatcher = ImageGenerationDispatcher::new(fixture.db.clone());
        for at in 2..=3 {
            let pass = dispatcher
                .run_scheduler_pass(
                    &adapter,
                    &proof_ok(),
                    deadline_boot(),
                    100,
                    at,
                    at as u64,
                    8,
                )
                .await
                .unwrap();
            assert_eq!(pass.dispatched, 1, "{pass:#?}");
        }
        let request = adapter
            .requests()
            .into_iter()
            .find(|request| request.attempt_number == 2)
            .expect("accepted retry attempt");
        let mut cursor = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(512, 512)
            .write_to(&mut cursor, image::ImageFormat::Png)
            .unwrap();
        let bytes = cursor.into_inner();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"retry-fetch-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            2,
            10,
        )
        .await
        .unwrap();
        let job_id = fixture.job_id;
        let slot_id = fixture.slot_id;
        let versions = fixture
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT j.version,s.version,a.version,o.version FROM image_generation_jobs j JOIN image_generation_slots s USING(job_id) JOIN image_generation_attempts a USING(job_id,slot_id) JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE j.job_id=?1 AND s.slot_id=?2 AND a.attempt_number=2",
                    rusqlite::params![job_id.to_string(), slot_id.to_string()],
                    |row| {
                        Ok((
                            row.get::<_, i64>(0)?,
                            row.get::<_, i64>(1)?,
                            row.get::<_, i64>(2)?,
                            row.get::<_, i64>(3)?,
                        ))
                    },
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        let progress = coordinate_persisted_accepted_image_response(
            fixture.db.clone(),
            root,
            CoordinateAcceptedImageResponse {
                job_id: fixture.job_id,
                slot_id: fixture.slot_id,
                attempt_number: 2,
                expected_job_version: u64::try_from(versions.0).unwrap(),
                expected_slot_version: u64::try_from(versions.1).unwrap(),
                expected_attempt_version: u64::try_from(versions.2).unwrap(),
                external_operation_id: request.external_operation_id,
                expected_journal_version: u64::try_from(versions.3).unwrap(),
                component_id: Uuid::now_v7(),
                release_operation_id: Uuid::now_v7(),
                bytes,
                now_unix_ms: 11,
            },
        )
        .await
        .unwrap();
        assert_eq!(progress, AcceptedImageResponseProgress::Retained);
        let stored = fixture
            .db
            .read(move |conn| {
                conn.query_row(
                    "SELECT resource_reservation_id FROM image_generation_artifact_components WHERE artifact_id=?1",
                    [fixture.artifact_id.to_string()],
                    |row| row.get::<_, String>(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            stored,
            cockpit_db::db::image_generation::image_generation_attempt_media_reservation_id(
                &sealed,
                fixture.slot_id,
                2,
            )
        );
        assert_ne!(stored, sealed);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_semantic_failure_closes_publication_security_blocked() {
        use std::os::unix::fs::PermissionsExt;
        let (fixture, request) = setup_accepted_response_fixture("response-invalid").await;
        let bytes = b"not-a-png".to_vec();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"invalid-fetch-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        assert!(
            coordinate_persisted_accepted_image_response(
                fixture.db.clone(),
                root,
                CoordinateAcceptedImageResponse {
                    job_id: fixture.job_id,
                    slot_id: fixture.slot_id,
                    attempt_number: 1,
                    expected_job_version: 5,
                    expected_slot_version: 4,
                    expected_attempt_version: 5,
                    external_operation_id: request.external_operation_id,
                    expected_journal_version: 3,
                    component_id: Uuid::now_v7(),
                    release_operation_id: Uuid::now_v7(),
                    bytes,
                    now_unix_ms: 11
                }
            )
            .await
            .is_err()
        );
        fixture.db.read(move|conn|{let row:(String,i64)=conn.query_row("SELECT state,(SELECT count(*) FROM image_generation_artifacts WHERE job_id=i.job_id) FROM image_generation_response_publication_intents i WHERE job_id=?1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;assert_eq!(row,("security_blocked".into(),0));Ok(())}).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_cancellation_before_validation_is_late_quarantined() {
        use std::os::unix::fs::PermissionsExt;
        let (fixture, request) = setup_accepted_response_fixture("response-cancelled").await;
        let mut cursor = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(512, 512)
            .write_to(&mut cursor, image::ImageFormat::Png)
            .unwrap();
        let bytes = cursor.into_inner();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"cancelled-fetch-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let job = fixture.job_id;
        fixture
            .db
            .write(move |conn| {
                cockpit_db::Db::request_image_generation_cancellation_conn(
                    conn,
                    &cockpit_db::db::image_generation::RequestImageGenerationCancellation {
                        job_id: job,
                        cancellation_version: 1,
                        request_operation_id: "accepted-response-cancel",
                        requested_at_unix_ms: 11,
                    },
                )?;
                Ok(())
            })
            .await
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        let progress = coordinate_persisted_accepted_image_response(
            fixture.db.clone(),
            root,
            CoordinateAcceptedImageResponse {
                job_id: fixture.job_id,
                slot_id: fixture.slot_id,
                attempt_number: 1,
                expected_job_version: 6,
                expected_slot_version: 5,
                expected_attempt_version: 6,
                external_operation_id: request.external_operation_id,
                expected_journal_version: 3,
                component_id: Uuid::now_v7(),
                release_operation_id: Uuid::now_v7(),
                bytes,
                now_unix_ms: 12,
            },
        )
        .await
        .unwrap();
        assert_eq!(progress, AcceptedImageResponseProgress::LateQuarantined);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_svg_is_sanitized_and_retained_through_intent() {
        use std::os::unix::fs::PermissionsExt;
        let (fixture, request) = setup_accepted_response_fixture("svg-response-success").await;
        let bytes=br#"<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512"><path d="M0 0h1v1z"/></svg>"#.to_vec();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"svg-fetch-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        let progress = coordinate_persisted_accepted_image_response(
            fixture.db.clone(),
            root,
            CoordinateAcceptedImageResponse {
                job_id: fixture.job_id,
                slot_id: fixture.slot_id,
                attempt_number: 1,
                expected_job_version: 5,
                expected_slot_version: 4,
                expected_attempt_version: 5,
                external_operation_id: request.external_operation_id,
                expected_journal_version: 3,
                component_id: Uuid::now_v7(),
                release_operation_id: Uuid::now_v7(),
                bytes,
                now_unix_ms: 11,
            },
        )
        .await
        .unwrap();
        assert_eq!(progress, AcceptedImageResponseProgress::Retained);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_publication_finalize_crash_reopens_exact_applied_without_duplicate() {
        use std::os::unix::fs::PermissionsExt;
        let database = tempfile::tempdir().unwrap();
        let database_path = database.path().join("image.db");
        let (fixture, request) = setup_accepted_response_fixture_with_db(
            cockpit_db::Db::open(&database_path).unwrap(),
            "response-finalize-cut",
        )
        .await;
        let mut cursor = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(512, 512)
            .write_to(&mut cursor, image::ImageFormat::Png)
            .unwrap();
        let bytes = cursor.into_inner();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"cut-fetch-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        fixture.db.write(|conn|{conn.execute_batch("CREATE TEMP TRIGGER cut_intent_finalize BEFORE UPDATE ON image_generation_response_publication_intents WHEN NEW.state='applied' BEGIN SELECT RAISE(ABORT,'cut'); END")?;Ok(())}).await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        assert!(
            coordinate_persisted_accepted_image_response(
                fixture.db.clone(),
                root.clone(),
                CoordinateAcceptedImageResponse {
                    job_id: fixture.job_id,
                    slot_id: fixture.slot_id,
                    attempt_number: 1,
                    expected_job_version: 5,
                    expected_slot_version: 4,
                    expected_attempt_version: 5,
                    external_operation_id: request.external_operation_id,
                    expected_journal_version: 3,
                    component_id: Uuid::now_v7(),
                    release_operation_id: Uuid::now_v7(),
                    bytes,
                    now_unix_ms: 11
                }
            )
            .await
            .is_err()
        );
        fixture
            .db
            .write(|conn| {
                conn.execute_batch("DROP TRIGGER cut_intent_finalize")?;
                Ok(())
            })
            .await
            .unwrap();
        let job_id = fixture.job_id;
        drop(fixture);
        let reopened = cockpit_db::Db::open(&database_path).unwrap();
        assert_eq!(
            reconcile_pending_accepted_response_publications(reopened.clone(), root, 12)
                .await
                .unwrap(),
            1
        );
        reopened.read(move|conn|{let row:(String,i64)=conn.query_row("SELECT state,(SELECT count(*) FROM image_generation_artifact_components WHERE artifact_id=i.artifact_id) FROM image_generation_response_publication_intents i WHERE job_id=?1",[job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;assert_eq!(row,("applied".into(),1));Ok(())}).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_publication_pre_intent_cut_has_no_state_or_filesystem_effect() {
        use std::os::unix::fs::PermissionsExt;
        let (fixture, request) = setup_accepted_response_fixture("response-pre-intent-cut").await;
        let bytes = b"not-yet-touched".to_vec();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"pre-intent-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        fixture.db.write(|conn|{conn.execute_batch("CREATE TEMP TRIGGER cut_before_intent BEFORE INSERT ON image_generation_response_publication_intents BEGIN SELECT RAISE(ABORT,'cut'); END")?;Ok(())}).await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        assert!(
            coordinate_persisted_accepted_image_response(
                fixture.db.clone(),
                root,
                CoordinateAcceptedImageResponse {
                    job_id: fixture.job_id,
                    slot_id: fixture.slot_id,
                    attempt_number: 1,
                    expected_job_version: 5,
                    expected_slot_version: 4,
                    expected_attempt_version: 5,
                    external_operation_id: request.external_operation_id,
                    expected_journal_version: 3,
                    component_id: Uuid::now_v7(),
                    release_operation_id: Uuid::now_v7(),
                    bytes,
                    now_unix_ms: 11
                }
            )
            .await
            .is_err()
        );
        assert_eq!(std::fs::read_dir(&managed).unwrap().count(), 0);
        fixture.db.read(move|conn|{let row:(i64,i64)=conn.query_row("SELECT (SELECT count(*) FROM image_generation_response_publication_intents),(SELECT count(*) FROM image_generation_artifacts WHERE job_id=?1)",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;assert_eq!(row,(0,0));Ok(())}).await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn accepted_post_rename_cut_reopens_exact_security_blocked_destination() {
        use std::os::unix::fs::PermissionsExt;
        let database = tempfile::tempdir().unwrap();
        let database_path = database.path().join("image.db");
        let (fixture, request) = setup_accepted_response_fixture_with_db(
            cockpit_db::Db::open(&database_path).unwrap(),
            "response-rename-cut",
        )
        .await;
        let mut cursor = std::io::Cursor::new(Vec::new());
        image::DynamicImage::new_rgba8(512, 512)
            .write_to(&mut cursor, image::ImageFormat::Png)
            .unwrap();
        let bytes = cursor.into_inner();
        let fetcher = ScriptedAcceptedResponseFetcher::new(
            vec![AcceptedImageResponseFetchOutcome::Fetched {
                bytes: bytes.clone(),
                evidence: b"rename-cut-proof".to_vec(),
            }],
            vec![],
        );
        fetch_accepted_image_response(
            fixture.db.clone(),
            &fetcher,
            fixture.job_id,
            fixture.slot_id,
            1,
            10,
        )
        .await
        .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let managed = temp.path().join("managed");
        std::fs::create_dir(&managed).unwrap();
        std::fs::set_permissions(&managed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = std::sync::Arc::new(open_image_generation_artifact_root(&managed).unwrap());
        let component_id = Uuid::now_v7();
        root.force_accepted_response_post_rename_cut(component_id);
        assert!(
            coordinate_persisted_accepted_image_response(
                fixture.db.clone(),
                root,
                CoordinateAcceptedImageResponse {
                    job_id: fixture.job_id,
                    slot_id: fixture.slot_id,
                    attempt_number: 1,
                    expected_job_version: 5,
                    expected_slot_version: 4,
                    expected_attempt_version: 5,
                    external_operation_id: request.external_operation_id,
                    expected_journal_version: 3,
                    component_id,
                    release_operation_id: Uuid::now_v7(),
                    bytes,
                    now_unix_ms: 11
                }
            )
            .await
            .is_err()
        );
        let job_id = fixture.job_id;
        let artifact_id = fixture.artifact_id;
        drop(fixture);
        let reopened = cockpit_db::Db::open(&database_path).unwrap();
        let recovery:String=reopened.read(move|conn|{let row:(String,String,i64,i64,i64)=conn.query_row("SELECT state,recovery_evidence_json,(SELECT count(*) FROM image_generation_artifacts WHERE job_id=i.job_id),(SELECT count(*) FROM image_generation_artifact_components WHERE artifact_id=i.artifact_id),(SELECT count(*) FROM image_generation_response_fetches WHERE job_id=i.job_id) FROM image_generation_response_publication_intents i WHERE job_id=?1",[job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;assert_eq!(row.0,"security_blocked");assert_eq!((row.2,row.3,row.4),(0,0,1));Ok(row.1)}).await.unwrap();
        let value: serde_json::Value = serde_json::from_str(&recovery).unwrap();
        assert_eq!(value["kind"], "held_applied_durable");
        let evidence = decode_held_artifact_evidence(value["artifact"].as_str().unwrap()).unwrap();
        let destination = format!("{artifact_id}-{component_id}.artifact");
        let reopened_root = open_image_generation_artifact_root(&managed).unwrap();
        let _held = reopened_root
            .open_verified_component(&destination, &evidence)
            .unwrap();
        assert_eq!(std::fs::read_dir(&managed).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn reconciliation_restarts_without_provider_redispatch_and_cancel_is_evidence_only() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("reconcile-worker.db");
        let fixture = setup_real_ledger_scheduler_job(
            cockpit_db::Db::open(&path).unwrap(),
            "reconcile-worker",
        )
        .await;
        let job_id = fixture.job_id;
        let slot_id = fixture.slot_id;
        let spend_id = fixture.spend_reservation_id.clone();
        let handoff = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"handoff-unknown".to_vec(),
            },
        ]);
        ImageGenerationDispatcher::new(fixture.db)
            .run_scheduler_pass(&handoff, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(handoff.requests().len(), 1);
        let reopened = cockpit_db::Db::open(&path).unwrap();
        let recovery = DeterministicImageGenerationAdapter::with_recovery(
            vec![ImageGenerationReconcileResult::AuthoritativeAccepted {
                evidence: b"provider-accepted".to_vec(),
            }],
            vec![ImageGenerationCancelResult::TooLateOrAccepted {
                evidence: b"provider-too-late".to_vec(),
            }],
        );
        let dispatcher = ImageGenerationDispatcher::new(reopened.clone());
        assert_eq!(
            dispatcher
                .run_reconciliation_pass(&recovery, Uuid::now_v7(), 10, 0, 8)
                .await
                .unwrap(),
            1
        );
        assert_eq!(recovery.reconciliation_requests().len(), 1);
        assert!(recovery.requests().is_empty());
        reopened
            .transaction(move |conn| {
                cockpit_db::Db::request_image_generation_cancellation_conn(
                    conn,
                    &cockpit_db::db::image_generation::RequestImageGenerationCancellation {
                        job_id,
                        cancellation_version: 1,
                        request_operation_id: "cancel:reconciled",
                        requested_at_unix_ms: 11,
                    },
                )?;
                Ok(())
            })
            .await
            .unwrap();
        assert_eq!(
            dispatcher
                .run_provider_cancel_pass(&recovery, Uuid::now_v7(), 12, 8)
                .await
                .unwrap(),
            1
        );
        assert_eq!(recovery.cancellation_requests().len(), 1);
        assert_eq!(
            dispatcher
                .run_provider_cancel_pass(&recovery, Uuid::now_v7(), 13, 8)
                .await
                .unwrap(),
            0
        );
        reopened.read(move|conn|{let row:(String,String,i64)=conn.query_row("SELECT a.state,s.state,(SELECT COUNT(*) FROM image_generation_provider_cancel_evidence e WHERE e.job_id=a.job_id AND e.slot_id=a.slot_id AND e.attempt_number=a.attempt_number) FROM image_generation_attempts a JOIN image_spend_reservations s ON s.reservation_id=?3 WHERE a.job_id=?1 AND a.slot_id=?2",rusqlite::params![job_id.to_string(),slot_id.to_string(),spend_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;assert_eq!(row.0,"cancellation_requested");assert_ne!(row.1,"released");assert_eq!(row.2,1);Ok(())}).await.unwrap();
    }

    #[tokio::test]
    async fn authoritative_nonacceptance_requeues_exact_retry_and_reconciles_media_and_spend() {
        let fixture = setup_real_ledger_scheduler_job_with_attempts(
            cockpit_db::Db::open_in_memory().unwrap(),
            "reconcile-retry",
            2,
        )
        .await;
        let job_id = fixture.job_id;
        let slot_id = fixture.slot_id;
        let media_id = fixture.media_reservation_id.clone();
        let spend_id = fixture.spend_reservation_id.clone();
        let handoff = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::SubmissionUnknown {
                evidence: b"retry-unknown".to_vec(),
            },
        ]);
        let dispatcher = ImageGenerationDispatcher::new(fixture.db.clone());
        dispatcher
            .run_scheduler_pass(&handoff, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        let recovery = DeterministicImageGenerationAdapter::with_recovery(
            vec![ImageGenerationReconcileResult::AuthoritativeNonacceptance {
                evidence: b"authoritative-rejection".to_vec(),
            }],
            Vec::new(),
        );
        assert_eq!(
            dispatcher
                .run_reconciliation_pass(&recovery, Uuid::now_v7(), 10, 0, 8)
                .await
                .unwrap(),
            1
        );
        assert_eq!(handoff.requests().len(), 1);
        assert_eq!(recovery.reconciliation_requests().len(), 1);
        let retry_media_id =
            cockpit_db::db::image_generation::image_generation_attempt_media_reservation_id(
                &media_id, slot_id, 2,
            );
        let original_media_id = media_id.clone();
        fixture.db.read(move|conn|{
            let row:(String,String,String,String,i64)=conn.query_row("SELECT a.state,s.state,m.state,b.state,(SELECT COUNT(*) FROM image_generation_attempt_activation_facts f WHERE f.job_id=a.job_id AND f.slot_id=a.slot_id AND f.attempt_number=2) FROM image_generation_attempts a JOIN image_generation_slots s USING(job_id,slot_id) JOIN media_reservations m ON m.reservation_id=?3 JOIN image_spend_reservations b ON b.reservation_id=?4 WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=1",rusqlite::params![job_id.to_string(),slot_id.to_string(),media_id,spend_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
            assert_eq!(row.0,"rejected_not_accepted");
            assert_eq!(row.1,"queued");
            assert_eq!(row.2,"released");
            assert_eq!(row.3,"reserved");
            assert_eq!(row.4,1);
            let retry:(String,String)=conn.query_row("SELECT reservation_id,state FROM media_reservations WHERE reservation_id=?1",[&retry_media_id],|row|Ok((row.get(0)?,row.get(1)?)))?;
            assert_eq!(retry.0,retry_media_id);
            assert_ne!(retry.0,original_media_id);
            assert_eq!(retry.1,"executing_local");
            Ok(())
        }).await.unwrap();
    }

    #[tokio::test]
    async fn reconciliation_spend_and_media_faults_roll_back_reopen_and_reclaim_without_redispatch()
    {
        for (name, trigger) in [
            (
                "spend",
                "CREATE TEMP TRIGGER reconciliation_cut BEFORE UPDATE ON image_spend_reservations BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
            (
                "media",
                "CREATE TEMP TRIGGER reconciliation_cut BEFORE UPDATE ON media_reservations BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join(format!("reconciliation-{name}.db"));
            let fixture = setup_real_ledger_scheduler_job(
                cockpit_db::Db::open(&path).unwrap(),
                &format!("reconciliation-{name}"),
            )
            .await;
            let job_id = fixture.job_id;
            let slot_id = fixture.slot_id;
            let media_id = fixture.media_reservation_id.clone();
            let spend_id = fixture.spend_reservation_id.clone();
            let reopen_media_id = media_id.clone();
            let reopen_spend_id = spend_id.clone();
            let handoff = DeterministicImageGenerationAdapter::new(vec![
                ImageGenerationHandoffResult::SubmissionUnknown {
                    evidence: b"fault-unknown".to_vec(),
                },
            ]);
            ImageGenerationDispatcher::new(fixture.db.clone())
                .run_scheduler_pass(&handoff, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
                .await
                .unwrap();
            fixture
                .db
                .write(move |conn| {
                    conn.execute_batch(trigger)?;
                    Ok(())
                })
                .await
                .unwrap();
            let recovery = DeterministicImageGenerationAdapter::with_recovery(
                vec![
                    ImageGenerationReconcileResult::AuthoritativeNonacceptance {
                        evidence: b"fault-first".to_vec(),
                    },
                    ImageGenerationReconcileResult::AuthoritativeNonacceptance {
                        evidence: b"fault-reclaimed".to_vec(),
                    },
                ],
                Vec::new(),
            );
            assert!(
                ImageGenerationDispatcher::new(fixture.db.clone())
                    .run_reconciliation_pass(&recovery, Uuid::now_v7(), 10, 0, 8)
                    .await
                    .is_err(),
                "{name} cut committed"
            );
            let after = fixture.db.read(move|conn|conn.query_row("SELECT o.state||':'||o.version||':'||a.state||':'||a.version||':'||s.state||':'||s.version||':'||j.state||':'||j.version||':'||m.state||':'||m.version||':'||b.state||':'||(SELECT COUNT(*) FROM image_generation_reconciliation_evidence e WHERE e.job_id=j.job_id)||':'||(SELECT COUNT(*) FROM image_generation_reconciliation_claim_completions c WHERE c.job_id=j.job_id) FROM image_generation_jobs j JOIN image_generation_slots s USING(job_id) JOIN image_generation_attempts a USING(job_id,slot_id) JOIN external_journal_operations o ON o.operation_id=a.external_operation_id JOIN media_reservations m ON m.reservation_id=?3 JOIN image_spend_reservations b ON b.reservation_id=?4 WHERE j.job_id=?1 AND s.slot_id=?2",rusqlite::params![job_id.to_string(),slot_id.to_string(),media_id,spend_id],|row|row.get::<_,String>(0)).map_err(Into::into)).await.unwrap();
            assert!(after.contains(":reconciling:"), "{name}: {after}");
            assert!(after.contains(":external_pending:"), "{name}: {after}");
            assert!(after.contains(":reserved:0:0"), "{name}: {after}");
            drop(fixture.db);
            let reopened = cockpit_db::Db::open(&path).unwrap();
            let reopened_snapshot = reopened.read(move|conn|conn.query_row("SELECT o.state||':'||o.version||':'||a.state||':'||a.version||':'||s.state||':'||s.version||':'||j.state||':'||j.version||':'||m.state||':'||m.version||':'||b.state||':'||(SELECT COUNT(*) FROM image_generation_reconciliation_evidence e WHERE e.job_id=j.job_id)||':'||(SELECT COUNT(*) FROM image_generation_reconciliation_claim_completions c WHERE c.job_id=j.job_id) FROM image_generation_jobs j JOIN image_generation_slots s USING(job_id) JOIN image_generation_attempts a USING(job_id,slot_id) JOIN external_journal_operations o ON o.operation_id=a.external_operation_id JOIN media_reservations m ON m.reservation_id=?3 JOIN image_spend_reservations b ON b.reservation_id=?4 WHERE j.job_id=?1 AND s.slot_id=?2",rusqlite::params![job_id.to_string(),slot_id.to_string(),reopen_media_id,reopen_spend_id],|row|row.get::<_,String>(0)).map_err(Into::into)).await.unwrap();
            assert_eq!(reopened_snapshot, after, "{name}");
            assert_eq!(
                ImageGenerationDispatcher::new(reopened.clone())
                    .run_reconciliation_pass(&recovery, Uuid::now_v7(), 60_010, 0, 8)
                    .await
                    .unwrap(),
                1,
                "{name}"
            );
            assert_eq!(handoff.requests().len(), 1, "{name}");
            assert_eq!(recovery.reconciliation_requests().len(), 2, "{name}");
        }
    }

    #[tokio::test]
    async fn cancellation_and_reconciliation_orderings_preserve_authoritative_resource_semantics() {
        for cancel_first in [true, false] {
            for outcome_name in ["accepted", "nonacceptance", "failure"] {
                let suffix = format!("race-{cancel_first}-{outcome_name}");
                let fixture = setup_real_ledger_scheduler_job(
                    cockpit_db::Db::open_in_memory().unwrap(),
                    &suffix,
                )
                .await;
                let job_id = fixture.job_id;
                let slot_id = fixture.slot_id;
                let media_id = fixture.media_reservation_id.clone();
                let spend_id = fixture.spend_reservation_id.clone();
                let handoff = DeterministicImageGenerationAdapter::new(vec![
                    ImageGenerationHandoffResult::SubmissionUnknown {
                        evidence: format!("unknown-{suffix}").into_bytes(),
                    },
                ]);
                let dispatcher = ImageGenerationDispatcher::new(fixture.db.clone());
                dispatcher
                    .run_scheduler_pass(&handoff, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
                    .await
                    .unwrap();
                if cancel_first {
                    fixture
                        .db
                        .transaction(move |conn| {
                            cockpit_db::Db::request_image_generation_cancellation_conn(
                                conn,
                                &cockpit_db::db::image_generation::RequestImageGenerationCancellation {
                                    job_id,
                                    cancellation_version: 1,
                                    request_operation_id: "cancel:before-reconcile",
                                    requested_at_unix_ms: 3,
                                },
                            )?;
                            Ok(())
                        })
                        .await
                        .unwrap();
                }
                let outcome = match outcome_name {
                    "accepted" => ImageGenerationReconcileResult::AuthoritativeAccepted {
                        evidence: b"race-accepted".to_vec(),
                    },
                    "nonacceptance" => ImageGenerationReconcileResult::AuthoritativeNonacceptance {
                        evidence: b"race-nonacceptance".to_vec(),
                    },
                    "failure" => ImageGenerationReconcileResult::AuthoritativeFailure {
                        evidence: b"race-failure".to_vec(),
                    },
                    _ => unreachable!(),
                };
                let recovery =
                    DeterministicImageGenerationAdapter::with_recovery(vec![outcome], Vec::new());
                assert_eq!(
                    dispatcher
                        .run_reconciliation_pass(&recovery, Uuid::now_v7(), 10, 0, 8)
                        .await
                        .unwrap(),
                    1,
                    "{suffix}"
                );
                let late_cancel_applied = if cancel_first {
                    true
                } else {
                    fixture
                        .db
                        .transaction(move |conn| {
                            cockpit_db::Db::request_image_generation_cancellation_conn(
                                conn,
                                &cockpit_db::db::image_generation::RequestImageGenerationCancellation {
                                    job_id,
                                    cancellation_version: 1,
                                    request_operation_id: "cancel:after-reconcile",
                                    requested_at_unix_ms: 11,
                                },
                            )?;
                            Ok(())
                        })
                        .await
                        .is_ok()
                };
                let row = fixture
                    .db
                    .read(move |conn| {
                        conn.query_row(
                            "SELECT a.state,s.state,j.state,m.state,b.state,(SELECT COUNT(*) FROM image_generation_reconciliation_evidence e WHERE e.job_id=a.job_id),(SELECT COUNT(*) FROM image_generation_reconciliation_claim_completions c WHERE c.job_id=a.job_id) FROM image_generation_attempts a JOIN image_generation_slots s USING(job_id,slot_id) JOIN image_generation_jobs j USING(job_id) JOIN media_reservations m ON m.reservation_id=?3 JOIN image_spend_reservations b ON b.reservation_id=?4 WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=1",
                            rusqlite::params![
                                job_id.to_string(),
                                slot_id.to_string(),
                                media_id,
                                spend_id
                            ],
                            |row| {
                                Ok((
                                    row.get::<_, String>(0)?,
                                    row.get::<_, String>(1)?,
                                    row.get::<_, String>(2)?,
                                    row.get::<_, String>(3)?,
                                    row.get::<_, String>(4)?,
                                    row.get::<_, i64>(5)?,
                                    row.get::<_, i64>(6)?,
                                ))
                            },
                        )
                        .map_err(Into::into)
                    })
                    .await
                    .unwrap();
                let expected = match (cancel_first, outcome_name) {
                    (true, "accepted") => (
                        "accepted",
                        "cancellation_requested",
                        "cancellation_requested",
                        "external_pending",
                        "reserved",
                        true,
                    ),
                    (false, "accepted") => (
                        "cancellation_requested",
                        "cancellation_requested",
                        "cancellation_requested",
                        "external_pending",
                        "reserved",
                        true,
                    ),
                    (true, "nonacceptance") => (
                        "cancelled",
                        "cancelled",
                        "cancelled",
                        "settling",
                        "released",
                        true,
                    ),
                    (false, "nonacceptance") => (
                        "rejected_not_accepted",
                        "failed",
                        "failed",
                        "settling",
                        "released",
                        false,
                    ),
                    (true, "failure") => (
                        "failed_after_acceptance",
                        "failed",
                        "failed",
                        "external_pending",
                        "reserved",
                        true,
                    ),
                    (false, "failure") => (
                        "failed_after_acceptance",
                        "failed",
                        "failed",
                        "external_pending",
                        "reserved",
                        false,
                    ),
                    _ => unreachable!(),
                };
                assert_eq!(
                    (
                        row.0.as_str(),
                        row.1.as_str(),
                        row.2.as_str(),
                        row.3.as_str(),
                        row.4.as_str()
                    ),
                    (expected.0, expected.1, expected.2, expected.3, expected.4),
                    "{suffix}"
                );
                assert_eq!(late_cancel_applied, expected.5, "{suffix}");
                assert_eq!((row.5, row.6), (1, 1), "{suffix}");
                assert_eq!(handoff.requests().len(), 1, "{suffix}");
                assert_eq!(recovery.reconciliation_requests().len(), 1, "{suffix}");
            }
        }
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
        fixture.db.write(|conn|{conn.execute_batch("CREATE TEMP TRIGGER cut_handoff_evidence AFTER INSERT ON image_generation_handoff_evidence BEGIN SELECT RAISE(ABORT,'cut'); END")?;Ok(())}).await.unwrap();
        let adapter = DeterministicImageGenerationAdapter::new(vec![
            ImageGenerationHandoffResult::Accepted {
                evidence: b"accepted-cut".to_vec(),
            },
        ]);
        let pass = ImageGenerationDispatcher::new(fixture.db.clone())
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 0);
        assert_eq!(adapter.requests().len(), 1);
        fixture.db.read(move|conn|{let row:(String,String,i64)=conn.query_row("SELECT a.state,o.state,(SELECT count(*) FROM image_generation_handoff_evidence e WHERE e.job_id=a.job_id AND e.slot_id=a.slot_id) FROM image_generation_attempts a JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE a.job_id=?1 AND a.slot_id=?2",rusqlite::params![job.to_string(),slot.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?)))?;assert_eq!(row,("dispatching".into(),"dispatching".into(),0));Ok(())}).await.unwrap();
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
        let output =
            open_image_generation_output_directory(&output_path, 4, "generated".into()).unwrap();
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
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
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

        let reopened =
            open_image_generation_output_directory(&fixture.output_path, 4, "generated".into())
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
                        evidence: ImageGenerationLatePublicationEvidenceV1::ExactAbsence { .. },
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
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 2, 2, 8)
            .await
            .unwrap();
        assert_eq!(pass.dispatched, 1, "{pass:#?}");
        let requests = adapter.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].job_id, second.job_id);
        let replay = dispatcher
            .run_scheduler_pass(&adapter, &proof_ok(), deadline_boot(), 100, 3, 3, 8)
            .await
            .unwrap();
        assert_eq!(replay.dispatched, 0, "{replay:#?}");
        assert_eq!(adapter.requests().len(), 1);
    }

    #[test]
    fn owner_recovery_authority_rejects_every_remote_write_mode() {
        #[cfg(feature = "remote")]
        use crate::daemon::principal::{PrincipalGrant, PrincipalScope};
        #[cfg(feature = "remote")]
        {
            for scope in [
                PrincipalScope::Agent,
                PrincipalScope::AgentReadonly,
                PrincipalScope::ProjectFiles,
                PrincipalScope::Terminal,
            ] {
                let remote = ClientPrincipal::from_verified_remote(
                    format!("remote-{scope:?}"),
                    vec![PrincipalGrant {
                        scope,
                        project_root: Some("/project".into()),
                    }],
                    None,
                );
                assert!(DaemonLocalOwnerRecoveryAuthority::from_local_direct(&remote).is_err());
            }
        }
        assert!(
            DaemonLocalOwnerRecoveryAuthority::from_local_direct(&ClientPrincipal::Owner).is_ok()
        );
    }

    #[test]
    #[allow(clippy::type_complexity)]
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
    fn deadline_boot() -> Uuid {
        Uuid::from_u128(0xbbbbbbbb_bbbb_4bbb_8bbb_bbbbbbbbbbbb)
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
            deadline_boot_id: deadline_boot(),
            enqueue_started_monotonic_ms: 100,
            operation_deadline_monotonic_ms: 400,
            sealed_prompt: SealedImageGenerationPromptV1::bind("fixture prompt".into()).unwrap(),
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
                targets: vec![ImageGenerationTargetRequestV1 {
                    target_id: target.target_id.clone(),
                    width: target.requested.width,
                    height: target.requested.height,
                    format: target.requested.format.clone(),
                    samples: 1,
                    parameters: target.typed_parameters.clone(),
                }],
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
                deadline_boot_id: sealed.deadline_boot_id,
                enqueue_started_monotonic_ms: sealed.enqueue_started_monotonic_ms,
                operation_deadline_monotonic_ms: sealed.operation_deadline_monotonic_ms,
                required_grants: sealed.required_grants,
                central_resources: sealed.central_resources,
                spend: sealed.spend,
                output_authority: VerifiedOutputDirectoryAuthority(sealed.output_authority),
                sealed_prompt: sealed.sealed_prompt,
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
        let first = *first;
        let second = *second;
        assert_eq!(first, second);
        assert_eq!(
            first.canonical_bytes().unwrap(),
            second.canonical_bytes().unwrap()
        );
        assert_eq!(image_row_count(&db), before);

        let cases: Vec<ResolverCase> = vec![
            (
                "target",
                Box::new(|request, _| request.targets[0].target_id = "missing".into()),
            ),
            (
                "format",
                Box::new(|request, _| request.targets[0].format = "webp".into()),
            ),
            (
                "width",
                Box::new(|request, _| request.targets[0].width = 513),
            ),
            (
                "height",
                Box::new(|request, _| request.targets[0].height = 513),
            ),
            (
                "parameter",
                Box::new(|request, _| {
                    request.targets[0]
                        .parameters
                        .insert("unsealed".into(), TypedParameterV1::Boolean(true));
                }),
            ),
            (
                "samples",
                Box::new(|request, _| request.targets[0].samples = 2),
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
    fn resolver_seals_heterogeneous_per_target_envelopes() {
        let (mut request, mut authority) = resolver_fixture();
        let mut requested = request.targets[0].clone();
        requested.target_id = "target-b".into();
        requested.width = 256;
        requested.height = 384;
        requested
            .parameters
            .insert("quality".into(), TypedParameterV1::Integer(80));
        request.targets.push(requested);

        let mut target = authority.targets[0].clone();
        target.runtime.target_id = "target-b".into();
        target.slot_artifact_ids = vec![(Uuid::now_v7(), Uuid::now_v7())];
        target.spend_attempt_identities = vec!["idem:2".into()];
        authority.targets.push(target);
        authority.central_resources[0].units *= 2;
        authority.spend.maximum_usd_micros = Some(20);

        let ImageGenerationResolutionV1::Ready(plan) =
            resolve_image_generation(request, authority).unwrap()
        else {
            panic!("heterogeneous target envelopes were rejected")
        };
        assert_eq!(plan.targets.len(), 2);
        assert_eq!(
            (
                plan.targets[0].requested.width,
                plan.targets[0].requested.height
            ),
            (512, 512)
        );
        assert_eq!(
            (
                plan.targets[1].requested.width,
                plan.targets[1].requested.height
            ),
            (256, 384)
        );
        assert_ne!(
            plan.targets[0].typed_parameters,
            plan.targets[1].typed_parameters
        );
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
        let brace = source[start..]
            .find('{')
            .map(|offset| start + offset)
            .unwrap();
        let mut depth = 0_i32;
        let mut end = brace;
        for (offset, ch) in source[brace..].char_indices() {
            match ch {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        end = brace + offset + 1;
                        break;
                    }
                }
                _ => {}
            }
        }
        // Only the resolver function body is pure; later retained-response
        // production code legitimately creates sealed artifact graphs.
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
    #[allow(clippy::type_complexity)]
    fn canonical_plan_is_stable_and_every_authority_family_changes_digest() {
        let original = plan();
        let bytes = original.canonical_bytes().unwrap();
        assert_eq!(bytes, original.canonical_bytes().unwrap());
        let baseline = original.digest().unwrap();
        assert_eq!(
            baseline,
            "c1cb4d4362e0375e71f7f52550d97a83ca0f9936a6f4abd565f493e9530094df"
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
            Box::new(|p| p.deadline_boot_id = id(99)),
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
    #[allow(clippy::type_complexity)]
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
        let held = open_image_generation_output_directory(&output, 1, "generated".into()).unwrap();
        assert_eq!(held.path(), output.canonicalize().unwrap());
        let replacement = temporary.path().join("replacement");
        std::fs::create_dir(&replacement).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::rename(&output, temporary.path().join("moved")).unwrap();
        std::fs::rename(&replacement, &output).unwrap();
        assert_ne!(
            held.authority().0.parent_identity_digest,
            open_image_generation_output_directory(&output, 1, "generated".into())
                .unwrap()
                .authority()
                .0
                .parent_identity_digest
        );
        let widened = temporary.path().join("widened");
        std::fs::create_dir(&widened).unwrap();
        std::fs::set_permissions(&widened, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open_image_generation_output_directory(&widened, 1, "generated".into()).is_err());
        let link = temporary.path().join("link");
        symlink(&output, &link).unwrap();
        assert!(open_image_generation_output_directory(&link, 1, "generated".into()).is_err());
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
        let mut interrupted = held.create_component_temporary("interrupted.tmp").unwrap();
        interrupted.file_mut().write_all(b"partial").unwrap();
        held.force_next_directory_sync_failure();
        let recovered = match held.seal_component_recoverable(interrupted) {
            HeldSealOutcome::Recoverable { artifact, .. } => artifact,
            _ => panic!("sync cut did not retain held authority"),
        };
        let sealed = match held.seal_component_recoverable(recovered) {
            HeldSealOutcome::Sealed(sealed) => sealed,
            _ => panic!("held retry did not seal"),
        };
        assert!(matches!(
            held.remove_verified_component(sealed).unwrap(),
            HeldDirectoryEffectOutcome::AppliedDurable(_)
        ));
        assert!(!root.join("interrupted.tmp").exists());
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
        let evidence_json = held_artifact_evidence_json(&evidence).unwrap();
        let full = AcquiredImageGenerationArtifactLease {
            lease_id: Uuid::now_v7(),
            relative_storage_key: "component.bin".into(),
            stable_identity_json: evidence_json.clone(),
            byte_length: evidence.byte_length(),
            range_start: 0,
            requested_length: evidence.byte_length(),
        };
        let mut full_bytes = Vec::new();
        write_verified_artifact_component(&held, &full, evidence.sha256(), &mut full_bytes)
            .unwrap();
        assert_eq!(full_bytes, b"canonical-image");
        let range = AcquiredImageGenerationArtifactLease {
            lease_id: Uuid::now_v7(),
            relative_storage_key: "component.bin".into(),
            stable_identity_json: evidence_json,
            byte_length: evidence.byte_length(),
            range_start: 10,
            requested_length: 5,
        };
        let mut range_bytes = Vec::new();
        write_verified_artifact_component(&held, &range, evidence.sha256(), &mut range_bytes)
            .unwrap();
        assert_eq!(range_bytes, b"image");
        struct Disconnected;
        impl std::io::Write for Disconnected {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "disconnected",
                ))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(
            write_verified_artifact_component(&held, &full, evidence.sha256(), &mut Disconnected,)
                .is_err()
        );
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
        cockpit_host::goal_scratch::set_private(&output).unwrap();
        assert!(open_image_generation_output_directory(&output, 1, "generated".into()).is_ok());
        let link = temporary.path().join("link");
        if symlink_dir(&output, &link).is_ok() {
            assert!(open_image_generation_output_directory(&link, 1, "generated".into()).is_err());
        }
    }
}
