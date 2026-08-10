//! Provider-neutral durable image-generation state vocabulary.
//!
//! Transition legality lives here so repository reducers and protocol
//! projections cannot develop separate interpretations of persisted states.

use anyhow::{Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::Db;
use super::external_journal::{
    ExternalJournalState, ExternalTransitionOutcome, transition_external_operation_conn,
};
use super::image_generation_plan::ImageGenerationPlanV1;

macro_rules! state_enum {
    ($name:ident { $($variant:ident => $text:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum $name { $($variant),+ }
        impl $name {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $text),+ }
            }
            pub fn parse(value: &str) -> Option<Self> {
                match value { $($text => Some(Self::$variant),)+ _ => None }
            }
        }
    };
}

state_enum!(ImageGenerationJobState {
    Created => "created", Validating => "validating", AwaitingAuthorization => "awaiting_authorization",
    Queued => "queued", Dispatching => "dispatching", SubmissionUnknown => "submission_unknown",
    Running => "running", CancellationRequested => "cancellation_requested", Downloading => "downloading",
    ValidatingOutput => "validating_output", Publishing => "publishing", Completed => "completed",
    CompletedAfterCancel => "completed_after_cancel", PartiallyFailed => "partially_failed",
    Failed => "failed", Cancelled => "cancelled"
});

state_enum!(ImageGenerationSlotState {
    Planned => "planned", Queued => "queued", Dispatching => "dispatching",
    SubmissionUnknown => "submission_unknown", Running => "running",
    CancellationRequested => "cancellation_requested", Downloading => "downloading",
    Validating => "validating", ReadyToPublish => "ready_to_publish", Published => "published",
    LateQuarantined => "late_quarantined", Failed => "failed", Cancelled => "cancelled",
    Discarded => "discarded"
});

state_enum!(ImageGenerationAttemptState {
    Planned => "planned", Preparing => "preparing", Prepared => "prepared", Dispatching => "dispatching",
    Accepted => "accepted", SubmissionUnknown => "submission_unknown", Reconciling => "reconciling",
    Running => "running", Downloading => "downloading", CancellationRequested => "cancellation_requested",
    ResponseAdopted => "response_adopted", FailedNotSubmitted => "failed_not_submitted",
    RejectedNotAccepted => "rejected_not_accepted", Cancelled => "cancelled", Succeeded => "succeeded",
    CompletedAfterCancel => "completed_after_cancel", FailedAfterAcceptance => "failed_after_acceptance"
});

pub const fn job_transition_allowed(
    from: ImageGenerationJobState,
    to: ImageGenerationJobState,
) -> bool {
    use ImageGenerationJobState as S;
    matches!(
        (from, to),
        (S::Created, S::Validating | S::Failed | S::Cancelled)
            | (
                S::Validating,
                S::AwaitingAuthorization | S::Queued | S::Failed | S::Cancelled
            )
            | (
                S::AwaitingAuthorization,
                S::Queued | S::Failed | S::Cancelled
            )
            | (
                S::Queued,
                S::Dispatching | S::CancellationRequested | S::Failed | S::Cancelled
            )
            | (
                S::Dispatching,
                S::SubmissionUnknown
                    | S::Running
                    | S::CancellationRequested
                    | S::Downloading
                    | S::PartiallyFailed
                    | S::Failed
                    | S::Cancelled
            )
            | (
                S::SubmissionUnknown,
                S::Running
                    | S::CancellationRequested
                    | S::Downloading
                    | S::CompletedAfterCancel
                    | S::PartiallyFailed
                    | S::Failed
            )
            | (
                S::Running,
                S::CancellationRequested | S::Downloading | S::PartiallyFailed | S::Failed
            )
            | (
                S::CancellationRequested,
                S::Cancelled
                    | S::Downloading
                    | S::CompletedAfterCancel
                    | S::PartiallyFailed
                    | S::Failed
            )
            | (
                S::Downloading,
                S::ValidatingOutput
                    | S::CancellationRequested
                    | S::CompletedAfterCancel
                    | S::PartiallyFailed
                    | S::Failed
            )
            | (
                S::ValidatingOutput,
                S::Publishing
                    | S::CancellationRequested
                    | S::CompletedAfterCancel
                    | S::PartiallyFailed
                    | S::Failed
            )
            | (
                S::Publishing,
                S::Completed
                    | S::CancellationRequested
                    | S::CompletedAfterCancel
                    | S::PartiallyFailed
                    | S::Failed
            )
    )
}

pub const fn slot_transition_allowed(
    from: ImageGenerationSlotState,
    to: ImageGenerationSlotState,
) -> bool {
    use ImageGenerationSlotState as S;
    matches!(
        (from, to),
        (S::Planned, S::Queued | S::Failed | S::Cancelled)
            | (S::Queued, S::Dispatching | S::Failed | S::Cancelled)
            | (
                S::Dispatching,
                S::SubmissionUnknown
                    | S::Running
                    | S::Downloading
                    | S::CancellationRequested
                    | S::Failed
                    | S::Cancelled
            )
            | (
                S::SubmissionUnknown,
                S::Running | S::Downloading | S::CancellationRequested | S::Failed | S::Cancelled
            )
            | (
                S::Running,
                S::Downloading | S::CancellationRequested | S::Failed
            )
            | (
                S::CancellationRequested,
                S::Cancelled | S::SubmissionUnknown | S::Downloading | S::Failed
            )
            | (
                S::Downloading,
                S::Validating | S::CancellationRequested | S::Failed
            )
            | (
                S::Validating,
                S::ReadyToPublish | S::LateQuarantined | S::CancellationRequested | S::Failed
            )
            | (
                S::ReadyToPublish,
                S::Published | S::LateQuarantined | S::Failed
            )
            | (S::LateQuarantined, S::Published | S::Discarded)
    )
}

pub const fn attempt_transition_allowed(
    from: ImageGenerationAttemptState,
    to: ImageGenerationAttemptState,
) -> bool {
    use ImageGenerationAttemptState as S;
    matches!(
        (from, to),
        (
            S::Planned,
            S::Preparing | S::Cancelled | S::FailedNotSubmitted
        ) | (
            S::Preparing,
            S::Prepared | S::Cancelled | S::FailedNotSubmitted
        ) | (
            S::Prepared,
            S::Dispatching | S::Cancelled | S::FailedNotSubmitted
        ) | (
            S::Dispatching,
            S::Accepted
                | S::SubmissionUnknown
                | S::RejectedNotAccepted
                | S::CancellationRequested
                | S::FailedNotSubmitted
        ) | (
            S::Accepted,
            S::Running
                | S::Downloading
                | S::CancellationRequested
                | S::ResponseAdopted
                | S::FailedAfterAcceptance
        ) | (
            S::SubmissionUnknown,
            S::Reconciling | S::CancellationRequested
        ) | (
            S::Reconciling,
            S::Accepted
                | S::SubmissionUnknown
                | S::RejectedNotAccepted
                | S::Downloading
                | S::CancellationRequested
                | S::FailedAfterAcceptance
        ) | (
            S::Running,
            S::Downloading | S::CancellationRequested | S::FailedAfterAcceptance
        ) | (
            S::Downloading,
            S::ResponseAdopted
                | S::CompletedAfterCancel
                | S::CancellationRequested
                | S::FailedAfterAcceptance
        ) | (
            S::CancellationRequested,
            S::Cancelled
                | S::SubmissionUnknown
                | S::Reconciling
                | S::Accepted
                | S::Downloading
                | S::CompletedAfterCancel
                | S::FailedAfterAcceptance
        ) | (
            S::ResponseAdopted,
            S::Succeeded | S::CompletedAfterCancel | S::FailedAfterAcceptance
        )
    )
}

pub const fn slot_is_job_settled(state: ImageGenerationSlotState) -> bool {
    use ImageGenerationSlotState as S;
    matches!(
        state,
        S::Published | S::Failed | S::Cancelled | S::Discarded | S::LateQuarantined
    )
}

pub fn reduce_terminal_job(
    slots: &[(ImageGenerationSlotState, bool)],
) -> Option<ImageGenerationJobState> {
    let facts = slots
        .iter()
        .map(|(state, result)| ImageGenerationSlotTerminalFact {
            state: *state,
            applied_cancellation_version: (*result
                || *state == ImageGenerationSlotState::Cancelled)
                .then_some(1),
            result_after_cancel: *result,
        })
        .collect::<Vec<_>>();
    reduce_terminal_job_facts(&facts)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGenerationSlotTerminalFact {
    pub state: ImageGenerationSlotState,
    pub applied_cancellation_version: Option<u64>,
    pub result_after_cancel: bool,
}

pub fn reduce_terminal_job_facts(
    slots: &[ImageGenerationSlotTerminalFact],
) -> Option<ImageGenerationJobState> {
    use ImageGenerationJobState as J;
    use ImageGenerationSlotState as S;
    if slots.is_empty()
        || slots
            .iter()
            .any(|slot| !slot_is_job_settled(slot.state) || !terminal_slot_vector_valid(*slot))
    {
        return None;
    }
    if slots.iter().any(|slot| slot.result_after_cancel) {
        Some(J::CompletedAfterCancel)
    } else if slots.iter().all(|slot| slot.state == S::Published) {
        Some(J::Completed)
    } else if slots.iter().any(|slot| slot.state == S::Published) {
        Some(J::PartiallyFailed)
    } else if slots.iter().any(|slot| slot.state == S::Failed) {
        Some(J::Failed)
    } else {
        Some(J::Cancelled)
    }
}

fn terminal_slot_vector_valid(slot: ImageGenerationSlotTerminalFact) -> bool {
    use ImageGenerationSlotState as S;
    match slot.state {
        S::Published => {
            (!slot.result_after_cancel && slot.applied_cancellation_version.is_none())
                || (slot.result_after_cancel && slot.applied_cancellation_version.is_some())
        }
        S::LateQuarantined | S::Discarded => {
            slot.result_after_cancel && slot.applied_cancellation_version.is_some()
        }
        S::Cancelled => !slot.result_after_cancel && slot.applied_cancellation_version.is_some(),
        S::Failed => !slot.result_after_cancel || slot.applied_cancellation_version.is_some(),
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationJob<'a> {
    job_id: Uuid,
    plan_digest: &'a str,
    canonical_plan: &'a [u8],
    slot_count: u32,
    max_attempt_count: u32,
    enqueue_started_monotonic_ms: u64,
    operation_deadline_monotonic_ms: u64,
    created_at_unix_ms: i64,
    sealed_slots: Vec<SealedSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedSlot {
    slot_id: Uuid,
    slot_index: u32,
    sample_index: u32,
    managed_artifact_id: Uuid,
    attempts: Vec<SealedAttempt>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct SealedAttempt {
    attempt_number: u32,
    provider_request_identity: String,
    provider_idempotency_identity: String,
}

impl<'a> CreateImageGenerationJob<'a> {
    pub fn from_verified_canonical_plan(
        canonical_plan: &'a [u8],
        plan_digest: &'a str,
        created_at_unix_ms: i64,
    ) -> Result<Self> {
        let plan = ImageGenerationPlanV1::from_canonical(canonical_plan, plan_digest)?;
        let mut sealed_slots = Vec::new();
        let mut max_attempt_count = 0_u32;
        for target in &plan.targets {
            max_attempt_count = max_attempt_count.max(target.max_attempts);
            for slot in &target.slots {
                sealed_slots.push(SealedSlot {
                    slot_id: slot.slot_id,
                    slot_index: slot.slot_index,
                    sample_index: slot.sample_index,
                    managed_artifact_id: slot.managed_artifact_id,
                    attempts: slot
                        .attempts
                        .iter()
                        .map(|attempt| SealedAttempt {
                            attempt_number: attempt.attempt_number,
                            provider_request_identity: attempt.provider_request_identity.clone(),
                            provider_idempotency_identity: attempt
                                .provider_idempotency_identity
                                .clone(),
                        })
                        .collect(),
                });
            }
        }
        #[cfg(not(any()))]
        {
            Ok(Self {
                job_id: plan.job_id,
                plan_digest,
                canonical_plan,
                slot_count: u32::try_from(sealed_slots.len())?,
                max_attempt_count,
                enqueue_started_monotonic_ms: plan.enqueue_started_monotonic_ms,
                operation_deadline_monotonic_ms: plan.operation_deadline_monotonic_ms,
                created_at_unix_ms,
                sealed_slots,
            })
        }

        #[cfg(any())]
        {
            ensure!(
                canonical_plan.first() == Some(&b'{')
                    && canonical_plan.last() == Some(&b'}')
                    && !json_has_unquoted_whitespace(canonical_plan),
                "plan JSON is not canonical"
            );
            reject_duplicate_json_keys(canonical_plan)?;
            ensure!(
                json_keys_are_ordered(
                    canonical_plan,
                    &[
                        "schemaVersion",
                        "kind",
                        "jobId",
                        "ownerSessionId",
                        "ownerPrincipalDigest",
                        "projectIdentityDigest",
                        "configGeneration",
                        "enqueueStartedMonotonicMs",
                        "operationDeadlineMonotonicMs",
                        "requiredGrants",
                        "centralResources",
                        "spend",
                        "outputAuthority",
                        "targets"
                    ]
                ),
                "plan JSON field order is not canonical"
            );
            let computed = hex_lower(&Sha256::digest(canonical_plan));
            ensure!(computed == plan_digest, "sealed plan digest mismatch");
            let plan: serde_json::Value = serde_json::from_slice(canonical_plan)?;
            let job_id = Uuid::parse_str(
                plan.get("jobId")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("sealed plan job identity missing"))?,
            )?;
            let targets = plan
                .get("targets")
                .and_then(serde_json::Value::as_array)
                .ok_or_else(|| anyhow::anyhow!("sealed plan targets missing"))?;
            let mut slot_count = 0_u32;
            let mut max_attempt_count = None;
            let mut sealed_slots = Vec::new();
            for target in targets {
                let attempts = u32::try_from(
                    target
                        .get("maxAttempts")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| anyhow::anyhow!("sealed retry bound missing"))?,
                )?;
                ensure!(
                    max_attempt_count.is_none_or(|value| value == attempts),
                    "target retry bounds disagree"
                );
                max_attempt_count = Some(attempts);
                let slots = target
                    .get("slots")
                    .and_then(serde_json::Value::as_array)
                    .ok_or_else(|| anyhow::anyhow!("sealed slots missing"))?;
                slot_count = slot_count
                    .checked_add(u32::try_from(slots.len())?)
                    .ok_or_else(|| anyhow::anyhow!("slot count overflow"))?;
                for slot in slots {
                    let attempt_values = slot
                        .get("attempts")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| anyhow::anyhow!("sealed attempts missing"))?;
                    let attempts = attempt_values
                        .iter()
                        .map(|attempt| {
                            Ok(SealedAttempt {
                                attempt_number: u32::try_from(
                                    attempt
                                        .get("attemptNumber")
                                        .and_then(serde_json::Value::as_u64)
                                        .ok_or_else(|| {
                                            anyhow::anyhow!("sealed attempt number missing")
                                        })?,
                                )?,
                                provider_request_identity: attempt
                                    .get("providerRequestIdentity")
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!("sealed provider request missing")
                                    })?
                                    .to_owned(),
                                provider_idempotency_identity: attempt
                                    .get("providerIdempotencyIdentity")
                                    .and_then(serde_json::Value::as_str)
                                    .ok_or_else(|| {
                                        anyhow::anyhow!("sealed provider idempotency missing")
                                    })?
                                    .to_owned(),
                            })
                        })
                        .collect::<Result<Vec<_>>>()?;
                    sealed_slots.push(SealedSlot {
                        slot_id: Uuid::parse_str(
                            slot.get("slotId")
                                .and_then(serde_json::Value::as_str)
                                .ok_or_else(|| anyhow::anyhow!("sealed slot id missing"))?,
                        )?,
                        slot_index: u32::try_from(
                            slot.get("slotIndex")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or_else(|| anyhow::anyhow!("sealed slot index missing"))?,
                        )?,
                        sample_index: u32::try_from(
                            slot.get("sampleIndex")
                                .and_then(serde_json::Value::as_u64)
                                .ok_or_else(|| anyhow::anyhow!("sealed sample index missing"))?,
                        )?,
                        managed_artifact_id: Uuid::parse_str(
                            slot.get("managedArtifactId")
                                .and_then(serde_json::Value::as_str)
                                .ok_or_else(|| anyhow::anyhow!("sealed artifact id missing"))?,
                        )?,
                        attempts,
                    });
                }
            }
            Ok(Self {
                job_id,
                plan_digest,
                canonical_plan,
                slot_count,
                max_attempt_count: max_attempt_count
                    .ok_or_else(|| anyhow::anyhow!("sealed attempts missing"))?,
                enqueue_started_monotonic_ms: plan
                    .get("enqueueStartedMonotonicMs")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("enqueue start missing"))?,
                operation_deadline_monotonic_ms: plan
                    .get("operationDeadlineMonotonicMs")
                    .and_then(serde_json::Value::as_u64)
                    .ok_or_else(|| anyhow::anyhow!("deadline missing"))?,
                created_at_unix_ms,
                sealed_slots,
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationSlot {
    pub slot_id: Uuid,
    pub slot_index: u32,
    pub sample_index: u32,
    pub managed_artifact_id: Uuid,
    pub attempts: Vec<CreateImageGenerationAttempt>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationAttempt {
    pub attempt_number: u32,
    pub provider_request_identity: String,
    pub provider_idempotency_identity: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationCasOutcome {
    Applied { version: u64 },
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseAdoptionOrdering {
    Ordinary,
    ResponseAfterCancellation { cancellation_version: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdoptImageGenerationResponse<'a> {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_attempt_version: u64,
    pub expected_slot_version: u64,
    pub external_operation_id: Uuid,
    pub expected_journal_version: u64,
    pub response_digest: &'a str,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitImageGenerationPublication {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_attempt_version: u64,
    pub expected_slot_version: u64,
    pub artifact_generation: u64,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestImageGenerationCancellation<'a> {
    pub job_id: Uuid,
    pub cancellation_version: u64,
    pub request_operation_id: &'a str,
    pub requested_at_unix_ms: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationReconciliationOutcome {
    AuthoritativeNonacceptance,
    AuthoritativeFailure,
}
pub struct ReconcileImageGenerationAttempt<'a> {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_attempt_version: u64,
    pub expected_slot_version: u64,
    pub external_operation_id: Uuid,
    pub expected_journal_version: u64,
    pub evidence_digest: &'a str,
    pub outcome: ImageGenerationReconciliationOutcome,
    pub now_unix_ms: i64,
}

impl Db {
    pub fn reconcile_image_generation_attempt_conn(
        conn: &Connection,
        input: &ReconcileImageGenerationAttempt<'_>,
    ) -> Result<ImageGenerationCasOutcome> {
        atomic_conn(conn, "image_generation_reconcile", || {
            Self::reconcile_image_generation_attempt_inner(conn, input)
        })
    }
    fn reconcile_image_generation_attempt_inner(
        conn: &Connection,
        input: &ReconcileImageGenerationAttempt<'_>,
    ) -> Result<ImageGenerationCasOutcome> {
        ensure!(
            input.evidence_digest.len() == 64
                && input
                    .evidence_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()),
            "reconciliation evidence digest is invalid"
        );
        let (journal_next, attempt_next, outcome) = match input.outcome {
            ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance => (
                ExternalJournalState::Rejected,
                ImageGenerationAttemptState::RejectedNotAccepted,
                "authoritative_nonacceptance",
            ),
            ImageGenerationReconciliationOutcome::AuthoritativeFailure => (
                ExternalJournalState::Failed,
                ImageGenerationAttemptState::FailedAfterAcceptance,
                "authoritative_failure",
            ),
        };
        match transition_external_operation_conn(
            conn,
            input.external_operation_id,
            i64::try_from(input.expected_journal_version)?,
            journal_next,
            input.now_unix_ms,
        )? {
            ExternalTransitionOutcome::Committed(_) => {}
            _ => anyhow::bail!("reconciliation lost journal compare-and-set"),
        };
        let journal_version = input
            .expected_journal_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("journal version overflow"))?;
        let evidence_inserted=conn.execute("INSERT INTO image_generation_reconciliation_evidence(job_id,slot_id,attempt_number,journal_version,evidence_digest,provider_request_identity,provider_idempotency_identity,journal_payload_digest,outcome) SELECT a.job_id,a.slot_id,a.attempt_number,?1,?2,a.provider_request_identity,a.provider_idempotency_identity,j.payload_digest,?3 FROM image_generation_attempts a JOIN external_journal_operations j ON j.operation_id=a.external_operation_id WHERE a.job_id=?4 AND a.slot_id=?5 AND a.attempt_number=?6 AND a.external_operation_id=?7",params![i64::try_from(journal_version)?,input.evidence_digest,outcome,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),input.external_operation_id.to_string()])?;
        ensure!(
            evidence_inserted == 1,
            "reconciliation evidence identity is not bound"
        );
        let attempt_changed=conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,observed_journal_version=?3,nonacceptance_evidence_digest=CASE WHEN ?4='authoritative_nonacceptance' THEN ?5 ELSE NULL END WHERE job_id=?6 AND slot_id=?7 AND attempt_number=?8 AND state='reconciling' AND version=?9 AND external_operation_id=?10",params![attempt_next.as_str(),i64::try_from(input.expected_attempt_version+1)?,i64::try_from(journal_version)?,outcome,input.evidence_digest,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version)?,input.external_operation_id.to_string()])?;
        ensure!(
            attempt_changed == 1,
            "reconciliation lost attempt compare-and-set"
        );
        let slot_changed=conn.execute("UPDATE image_generation_slots SET state='failed',version=?1,failure_reason=?2 WHERE job_id=?3 AND slot_id=?4 AND state='submission_unknown' AND version=?5",params![i64::try_from(input.expected_slot_version+1)?,outcome,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?])?;
        ensure!(
            slot_changed == 1,
            "reconciliation lost slot compare-and-set"
        );
        let mut projection_statement=conn.prepare("SELECT state,applied_cancellation_version,result_after_cancel FROM image_generation_slots WHERE job_id=?1 ORDER BY slot_index")?;
        let projection = projection_statement
            .query_map([input.job_id.to_string()], |row| {
                let state: String = row.get(0)?;
                let cancellation: Option<i64> = row.get(1)?;
                let flag: i64 = row.get(2)?;
                Ok(ImageGenerationSlotTerminalFact {
                    state: ImageGenerationSlotState::parse(&state)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    applied_cancellation_version: cancellation.map(|value| value as u64),
                    result_after_cancel: flag == 1,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if let Some(terminal) = reduce_terminal_job_facts(&projection) {
            let changed=conn.execute("UPDATE image_generation_jobs SET state=?1,version=version+1,updated_at_unix_ms=?2 WHERE job_id=?3 AND state IN ('submission_unknown','cancellation_requested')",params![terminal.as_str(),input.now_unix_ms,input.job_id.to_string()])?;
            ensure!(changed == 1, "reconciliation lost job compare-and-set");
        }
        Ok(ImageGenerationCasOutcome::Applied {
            version: input.expected_slot_version + 1,
        })
    }
    /// Inserts the sealed plan and its initial projection in the caller's
    /// transaction. Composition with grants, resources, spend and journal
    /// rows therefore needs no second connection or async boundary.
    #[cfg(test)]
    fn create_image_generation_job_conn(
        conn: &Connection,
        input: &CreateImageGenerationJob<'_>,
    ) -> Result<()> {
        atomic_conn(conn, "image_generation_create_job", || {
            Self::create_image_generation_job_inner(conn, input)
        })
    }

    fn create_image_generation_job_inner(
        conn: &Connection,
        input: &CreateImageGenerationJob<'_>,
    ) -> Result<()> {
        ensure!(input.slot_count > 0, "image generation plans need slots");
        ensure!(
            input.max_attempt_count > 0,
            "image generation plans need attempts"
        );
        ensure!(
            input.operation_deadline_monotonic_ms > input.enqueue_started_monotonic_ms,
            "image generation deadline must follow enqueue start"
        );
        let computed_digest = hex_lower(&Sha256::digest(input.canonical_plan));
        ensure!(
            computed_digest == input.plan_digest,
            "sealed plan digest mismatch"
        );
        let plan: serde_json::Value = serde_json::from_slice(input.canonical_plan)?;
        ensure!(
            plan.get("schemaVersion")
                .and_then(serde_json::Value::as_u64)
                == Some(1),
            "sealed plan schema mismatch"
        );
        ensure!(
            plan.get("jobId").and_then(serde_json::Value::as_str)
                == Some(input.job_id.as_hyphenated().to_string().as_str()),
            "sealed plan job identity mismatch"
        );
        ensure!(
            plan.get("targets")
                .and_then(serde_json::Value::as_array)
                .is_some(),
            "sealed plan targets missing"
        );
        let sealed_slot_count =
            plan["targets"]
                .as_array()
                .into_iter()
                .flatten()
                .try_fold(0_u64, |total, target| {
                    let slots = target
                        .get("slots")
                        .and_then(serde_json::Value::as_array)
                        .ok_or_else(|| anyhow::anyhow!("sealed plan slot graph missing"))?;
                    for slot in slots {
                        ensure!(
                            slot.get("attempts")
                                .and_then(serde_json::Value::as_array)
                                .is_some_and(|attempts| !attempts.is_empty()),
                            "sealed attempt graph mismatch"
                        );
                    }
                    let count = slots.len() as u64;
                    total
                        .checked_add(count)
                        .ok_or_else(|| anyhow::anyhow!("sealed plan slot count overflow"))
                })?;
        ensure!(
            sealed_slot_count == u64::from(input.slot_count),
            "sealed slot count mismatch"
        );
        let enqueue = i64::try_from(input.enqueue_started_monotonic_ms)?;
        let deadline = i64::try_from(input.operation_deadline_monotonic_ms)?;
        let slot_count = i64::from(input.slot_count);
        let max_attempt_count = i64::from(input.max_attempt_count);
        conn.execute(
            "INSERT INTO image_generation_plans(job_id,schema_version,plan_digest,canonical_plan,slot_count,max_attempt_count,enqueue_started_monotonic_ms,operation_deadline_monotonic_ms) VALUES(?1,1,?2,?3,?4,?5,?6,?7)",
            params![input.job_id.to_string(), input.plan_digest, input.canonical_plan, slot_count, max_attempt_count, enqueue, deadline],
        )?;
        conn.execute(
            "INSERT INTO image_generation_jobs(job_id,state,version,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,'created',1,?2,?2)",
            params![input.job_id.to_string(), input.created_at_unix_ms],
        )?;
        Ok(())
    }

    pub fn create_image_generation_graph_conn(
        conn: &Connection,
        input: &CreateImageGenerationJob<'_>,
        slots: &[CreateImageGenerationSlot],
    ) -> Result<()> {
        atomic_conn(conn, "image_generation_create", || {
            Self::create_image_generation_graph_inner(conn, input, slots)
        })
    }

    fn create_image_generation_graph_inner(
        conn: &Connection,
        input: &CreateImageGenerationJob<'_>,
        slots: &[CreateImageGenerationSlot],
    ) -> Result<()> {
        ensure!(
            slots.len() == input.slot_count as usize,
            "sealed slot graph does not match plan"
        );
        Self::create_image_generation_job_inner(conn, input)?;
        for (slot_index, slot) in slots.iter().enumerate() {
            let sealed = input
                .sealed_slots
                .get(slot_index)
                .ok_or_else(|| anyhow::anyhow!("slot is absent from sealed plan"))?;
            ensure!(
                (
                    slot.slot_id,
                    slot.slot_index,
                    slot.sample_index,
                    slot.managed_artifact_id
                ) == (
                    sealed.slot_id,
                    sealed.slot_index,
                    sealed.sample_index,
                    sealed.managed_artifact_id
                ),
                "slot identity differs from sealed plan"
            );
            ensure!(
                slot.slot_index as usize == slot_index,
                "slot graph is not canonical"
            );
            ensure!(
                slot.attempts.len() == sealed.attempts.len(),
                "sealed attempt graph does not match plan"
            );
            conn.execute(
                "INSERT INTO image_generation_slots(job_id,slot_id,slot_index,sample_index,managed_artifact_id,max_attempt_count,state,version) VALUES(?1,?2,?3,?4,?5,?6,'planned',1)",
                params![input.job_id.to_string(), slot.slot_id.to_string(), i64::from(slot.slot_index), i64::from(slot.sample_index), slot.managed_artifact_id.to_string(), i64::try_from(sealed.attempts.len())?],
            )?;
            for (attempt_index, attempt) in slot.attempts.iter().enumerate() {
                let sealed_attempt = sealed
                    .attempts
                    .get(attempt_index)
                    .ok_or_else(|| anyhow::anyhow!("attempt is absent from sealed plan"))?;
                ensure!(
                    attempt.attempt_number == sealed_attempt.attempt_number
                        && attempt.provider_request_identity
                            == sealed_attempt.provider_request_identity
                        && attempt.provider_idempotency_identity
                            == sealed_attempt.provider_idempotency_identity,
                    "attempt identity differs from sealed plan"
                );
                ensure!(
                    attempt.attempt_number as usize == attempt_index + 1,
                    "attempt numbers must be contiguous from one"
                );
                conn.execute(
                    "INSERT INTO image_generation_attempts(job_id,slot_id,attempt_number,provider_request_identity,provider_idempotency_identity,state,version) VALUES(?1,?2,?3,?4,?5,'planned',1)",
                    params![input.job_id.to_string(), slot.slot_id.to_string(), i64::from(attempt.attempt_number),&attempt.provider_request_identity,&attempt.provider_idempotency_identity],
                )?;
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn cas_image_generation_job_state_conn(
        conn: &Connection,
        job_id: Uuid,
        expected_state: ImageGenerationJobState,
        expected_version: u64,
        next_state: ImageGenerationJobState,
        updated_at_unix_ms: i64,
    ) -> Result<ImageGenerationCasOutcome> {
        ensure!(
            job_transition_allowed(expected_state, next_state),
            "forbidden image generation job transition"
        );
        let next_version = expected_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("image generation job version overflow"))?;
        let expected_version_sql = i64::try_from(expected_version)?;
        let next_version_sql = i64::try_from(next_version)?;
        let changed = conn.execute(
            "UPDATE image_generation_jobs SET state=?1,version=?2,updated_at_unix_ms=?3 WHERE job_id=?4 AND state=?5 AND version=?6",
            params![next_state.as_str(), next_version_sql, updated_at_unix_ms, job_id.to_string(), expected_state.as_str(), expected_version_sql],
        )?;
        Ok(if changed == 1 {
            ImageGenerationCasOutcome::Applied {
                version: next_version,
            }
        } else {
            ImageGenerationCasOutcome::Conflict
        })
    }

    #[cfg(test)]
    fn cas_image_generation_slot_state_conn(
        conn: &Connection,
        job_id: Uuid,
        slot_id: Uuid,
        expected_state: ImageGenerationSlotState,
        expected_version: u64,
        next_state: ImageGenerationSlotState,
    ) -> Result<ImageGenerationCasOutcome> {
        ensure!(
            slot_transition_allowed(expected_state, next_state),
            "forbidden image generation slot transition"
        );
        let next_version = expected_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("image generation slot version overflow"))?;
        let expected_version_sql = i64::try_from(expected_version)?;
        let next_version_sql = i64::try_from(next_version)?;
        let changed = conn.execute(
            "UPDATE image_generation_slots SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4 AND state=?5 AND version=?6",
            params![next_state.as_str(), next_version_sql, job_id.to_string(), slot_id.to_string(), expected_state.as_str(), expected_version_sql],
        )?;
        Ok(if changed == 1 {
            ImageGenerationCasOutcome::Applied {
                version: next_version,
            }
        } else {
            ImageGenerationCasOutcome::Conflict
        })
    }

    pub fn adopt_image_generation_response_conn(
        conn: &Connection,
        input: &AdoptImageGenerationResponse<'_>,
    ) -> Result<ResponseAdoptionOrdering> {
        atomic_conn(conn, "image_generation_adopt", || {
            Self::adopt_image_generation_response_inner(conn, input)
        })
    }

    fn adopt_image_generation_response_inner(
        conn: &Connection,
        input: &AdoptImageGenerationResponse<'_>,
    ) -> Result<ResponseAdoptionOrdering> {
        ensure!(
            input.response_digest.len() == 64,
            "response digest is invalid"
        );
        let cancellation: Option<i64> = conn.query_row(
            "SELECT cancellation_version FROM image_generation_cancellation_facts WHERE job_id=?1",
            [input.job_id.to_string()], |row| row.get(0),
        ).optional()?;
        let ordering = cancellation.map_or(ResponseAdoptionOrdering::Ordinary, |version| {
            ResponseAdoptionOrdering::ResponseAfterCancellation {
                cancellation_version: version as u64,
            }
        });
        let journal_next = if cancellation.is_some() {
            ExternalJournalState::CompletedAfterCancel
        } else {
            ExternalJournalState::Succeeded
        };
        match transition_external_operation_conn(
            conn,
            input.external_operation_id,
            i64::try_from(input.expected_journal_version)?,
            journal_next,
            input.now_unix_ms,
        )? {
            ExternalTransitionOutcome::Committed(_) => {}
            _ => anyhow::bail!("external journal response adoption lost its compare-and-set"),
        }
        let applied_cancellation = cancellation;
        let attempt_next = if cancellation.is_some() {
            ImageGenerationAttemptState::CompletedAfterCancel
        } else {
            ImageGenerationAttemptState::ResponseAdopted
        };
        let next_attempt_version = input
            .expected_attempt_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("attempt version overflow"))?;
        if let Some(cancellation_version) = cancellation {
            conn.execute(
                "INSERT INTO image_generation_cancelled_result_facts(job_id,slot_id,attempt_number,cancellation_version,response_digest,journal_terminal_version,ordering) VALUES(?1,?2,?3,?4,?5,?6,'response_after_cancellation')",
                params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),cancellation_version,input.response_digest,i64::try_from(input.expected_journal_version+1)?],
            )?;
        }
        let changed = conn.execute(
            "UPDATE image_generation_attempts SET state=?1,version=?2,observed_journal_version=?3,applied_cancellation_version=?4,response_digest=?5 WHERE job_id=?6 AND slot_id=?7 AND attempt_number=?8 AND state IN ('accepted','downloading','cancellation_requested') AND version=?9 AND external_operation_id=?10",
            params![attempt_next.as_str(),i64::try_from(next_attempt_version)?,i64::try_from(input.expected_journal_version+1)?,applied_cancellation,input.response_digest,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version)?,input.external_operation_id.to_string()],
        )?;
        ensure!(
            changed == 1,
            "attempt response adoption lost its compare-and-set"
        );
        let slot_next = ImageGenerationSlotState::Validating;
        let mut slot_expected_version = input.expected_slot_version;
        if cancellation.is_some() {
            let changed=conn.execute(
                "UPDATE image_generation_slots SET state='downloading',version=?1 WHERE job_id=?2 AND slot_id=?3 AND state='cancellation_requested' AND version=?4",
                params![i64::try_from(slot_expected_version+1)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(slot_expected_version)?],
            )?;
            if changed == 1 {
                slot_expected_version += 1;
            }
        }
        let changed = conn.execute(
            "UPDATE image_generation_slots SET state=?1,version=?2,applied_cancellation_version=?3,result_after_cancel=?4 WHERE job_id=?5 AND slot_id=?6 AND state='downloading' AND version=?7",
            params![slot_next.as_str(),i64::try_from(slot_expected_version+1)?,applied_cancellation,i64::from(cancellation.is_some()),input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(slot_expected_version)?],
        )?;
        ensure!(
            changed == 1,
            "slot response adoption lost its compare-and-set"
        );
        Ok(ordering)
    }

    pub fn commit_image_generation_publication_conn(
        conn: &Connection,
        input: &CommitImageGenerationPublication,
    ) -> Result<ImageGenerationCasOutcome> {
        atomic_conn(conn, "image_generation_publish", || {
            Self::commit_image_generation_publication_inner(conn, input)
        })
    }

    fn commit_image_generation_publication_inner(
        conn: &Connection,
        input: &CommitImageGenerationPublication,
    ) -> Result<ImageGenerationCasOutcome> {
        conn.execute(
            "INSERT INTO image_generation_publication_right_facts(job_id,slot_id,attempt_number,slot_version,artifact_generation,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",
            params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_slot_version)?,i64::try_from(input.artifact_generation)?,input.now_unix_ms],
        )?;
        let attempt_changed = conn.execute(
            "UPDATE image_generation_attempts SET state='succeeded',version=?1 WHERE job_id=?2 AND slot_id=?3 AND attempt_number=?4 AND state='response_adopted' AND version=?5 AND applied_cancellation_version IS NULL",
            params![i64::try_from(input.expected_attempt_version+1)?,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version)?],
        )?;
        ensure!(
            attempt_changed == 1,
            "publication attempt lost its compare-and-set"
        );
        let slot_changed = conn.execute(
            "UPDATE image_generation_slots SET state='published',version=?1 WHERE job_id=?2 AND slot_id=?3 AND state='ready_to_publish' AND version=?4 AND applied_cancellation_version IS NULL AND result_after_cancel=0",
            params![i64::try_from(input.expected_slot_version+1)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?],
        )?;
        ensure!(
            slot_changed == 1,
            "publication slot lost its compare-and-set"
        );
        Ok(ImageGenerationCasOutcome::Applied {
            version: input.expected_slot_version + 1,
        })
    }

    pub fn request_image_generation_cancellation_conn(
        conn: &Connection,
        input: &RequestImageGenerationCancellation<'_>,
    ) -> Result<ImageGenerationCasOutcome> {
        atomic_conn(conn, "image_generation_cancel", || {
            Self::request_image_generation_cancellation_inner(conn, input)
        })
    }

    fn request_image_generation_cancellation_inner(
        conn: &Connection,
        input: &RequestImageGenerationCancellation<'_>,
    ) -> Result<ImageGenerationCasOutcome> {
        let cancellation_version = i64::try_from(input.cancellation_version)?;
        let existing:Option<(i64,String)>=conn.query_row("SELECT cancellation_version,request_operation_id FROM image_generation_cancellation_facts WHERE job_id=?1",[input.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
        if let Some((version, operation_id)) = existing {
            ensure!(
                version == cancellation_version && operation_id == input.request_operation_id,
                "cancellation replay identity mismatch"
            );
            let job_version: i64 = conn.query_row(
                "SELECT version FROM image_generation_jobs WHERE job_id=?1",
                [input.job_id.to_string()],
                |row| row.get(0),
            )?;
            return Ok(ImageGenerationCasOutcome::Applied {
                version: u64::try_from(job_version)?,
            });
        }
        let cancellable_slots: i64 = conn.query_row(
            "SELECT COUNT(*) FROM image_generation_slots WHERE job_id=?1 AND state NOT IN ('published','failed','cancelled','discarded','late_quarantined')",
            [input.job_id.to_string()],
            |row| row.get(0),
        )?;
        ensure!(
            cancellable_slots > 0,
            "image generation job has no cancellable slots"
        );
        conn.execute(
            "INSERT INTO image_generation_cancellation_facts(job_id,cancellation_version,requested_at_unix_ms,request_operation_id) VALUES(?1,?2,?3,?4)",
            params![input.job_id.to_string(),cancellation_version,input.requested_at_unix_ms,input.request_operation_id],
        )?;
        let mut statement = conn.prepare(
            "SELECT slot_id,state,version FROM image_generation_slots WHERE job_id=?1 ORDER BY slot_index",
        )?;
        let slots = statement
            .query_map([input.job_id.to_string()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for (slot_id, slot_state, slot_version) in slots {
            if matches!(
                slot_state.as_str(),
                "published" | "failed" | "cancelled" | "discarded" | "late_quarantined"
            ) {
                continue;
            }
            let mut attempts_statement = conn.prepare(
                "SELECT attempt_number,state,version,external_operation_id,observed_journal_version FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 ORDER BY attempt_number",
            )?;
            let attempts = attempts_statement
                .query_map(params![input.job_id.to_string(), &slot_id], |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, i64>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<i64>>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            drop(attempts_statement);
            let response_adopted = attempts
                .iter()
                .any(|(_, state, _, _, _)| state == "response_adopted");
            let handoff_possible = attempts.iter().any(|(_, state, _, _, _)| {
                matches!(
                    state.as_str(),
                    "dispatching"
                        | "accepted"
                        | "submission_unknown"
                        | "reconciling"
                        | "running"
                        | "downloading"
                        | "cancellation_requested"
                )
            });
            for (attempt_number, state, version, operation_id, journal_version) in attempts {
                if matches!(
                    state.as_str(),
                    "failed_not_submitted"
                        | "rejected_not_accepted"
                        | "cancelled"
                        | "succeeded"
                        | "completed_after_cancel"
                        | "failed_after_acceptance"
                ) {
                    continue;
                }
                if state == "response_adopted" {
                    let operation_id = operation_id.as_deref().ok_or_else(|| {
                        anyhow::anyhow!("adopted response lacks journal identity")
                    })?;
                    let journal_version = journal_version
                        .ok_or_else(|| anyhow::anyhow!("adopted response lacks journal version"))?;
                    let response_digest:String=conn.query_row("SELECT response_digest FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![input.job_id.to_string(),&slot_id,attempt_number],|row|row.get(0))?;
                    let inserted=conn.execute("INSERT INTO image_generation_cancelled_result_facts(job_id,slot_id,attempt_number,cancellation_version,response_digest,journal_terminal_version,ordering) SELECT ?1,?2,?3,?4,?5,?6,'response_adopted_before_cancellation' WHERE EXISTS(SELECT 1 FROM external_journal_operations WHERE operation_id=?7 AND state='succeeded' AND version=?6) AND NOT EXISTS(SELECT 1 FROM image_generation_publication_right_facts WHERE job_id=?1 AND slot_id=?2)",params![input.job_id.to_string(),&slot_id,attempt_number,cancellation_version,&response_digest,journal_version,operation_id])?;
                    ensure!(
                        inserted == 1,
                        "adopted response lost cancellation/publication compare-and-set"
                    );
                    let changed=conn.execute("UPDATE image_generation_attempts SET state='completed_after_cancel',version=?1,applied_cancellation_version=?2 WHERE job_id=?3 AND slot_id=?4 AND attempt_number=?5 AND state='response_adopted' AND version=?6",params![version+1,cancellation_version,input.job_id.to_string(),&slot_id,attempt_number,version])?;
                    ensure!(
                        changed == 1,
                        "adopted response cancellation lost attempt compare-and-set"
                    );
                    continue;
                }
                let attempt_handoff_possible = matches!(
                    state.as_str(),
                    "dispatching"
                        | "accepted"
                        | "submission_unknown"
                        | "reconciling"
                        | "running"
                        | "downloading"
                        | "cancellation_requested"
                );
                if let (Some(operation_id), Some(journal_version)) =
                    (&operation_id, journal_version)
                {
                    let operation_id = Uuid::parse_str(operation_id)?;
                    let next = if attempt_handoff_possible {
                        ExternalJournalState::CancellationRequested
                    } else {
                        ExternalJournalState::Cancelled
                    };
                    match transition_external_operation_conn(
                        conn,
                        operation_id,
                        journal_version,
                        next,
                        input.requested_at_unix_ms,
                    )? {
                        ExternalTransitionOutcome::Committed(_)
                        | ExternalTransitionOutcome::Duplicate(_) => {}
                        ExternalTransitionOutcome::Conflict(_) => {
                            anyhow::bail!("cancellation lost journal compare-and-set")
                        }
                    }
                }
                let next = if attempt_handoff_possible {
                    ImageGenerationAttemptState::CancellationRequested
                } else {
                    ImageGenerationAttemptState::Cancelled
                };
                ensure!(
                    attempt_transition_allowed(
                        ImageGenerationAttemptState::parse(&state)
                            .ok_or_else(|| anyhow::anyhow!("unknown attempt state"))?,
                        next
                    ),
                    "attempt cannot accept cancellation"
                );
                let changed=conn.execute(
                    "UPDATE image_generation_attempts SET state=?1,version=?2,applied_cancellation_version=?3 WHERE job_id=?4 AND slot_id=?5 AND attempt_number=?6 AND state=?7 AND version=?8",
                    params![next.as_str(),version+1,cancellation_version,input.job_id.to_string(),&slot_id,attempt_number,&state,version],
                )?;
                ensure!(changed == 1, "cancellation lost attempt compare-and-set");
            }
            let current = ImageGenerationSlotState::parse(&slot_state)
                .ok_or_else(|| anyhow::anyhow!("unknown slot state"))?;
            if response_adopted && slot_state == "validating" {
                let changed=conn.execute("UPDATE image_generation_slots SET version=?1,applied_cancellation_version=?2,result_after_cancel=1 WHERE job_id=?3 AND slot_id=?4 AND state='validating' AND version=?5 AND applied_cancellation_version IS NULL",params![slot_version+1,cancellation_version,input.job_id.to_string(),&slot_id,slot_version])?;
                ensure!(
                    changed == 1,
                    "validating result lost cancellation compare-and-set"
                );
                continue;
            }
            let next = if response_adopted && slot_state == "ready_to_publish" {
                ImageGenerationSlotState::LateQuarantined
            } else if handoff_possible {
                ImageGenerationSlotState::CancellationRequested
            } else {
                ImageGenerationSlotState::Cancelled
            };
            ensure!(
                slot_transition_allowed(current, next),
                "slot cannot accept cancellation"
            );
            let changed=conn.execute(
                "UPDATE image_generation_slots SET state=?1,version=?2,applied_cancellation_version=?3,result_after_cancel=?4 WHERE job_id=?5 AND slot_id=?6 AND state=?7 AND version=?8",
                params![next.as_str(),slot_version+1,cancellation_version,i64::from(response_adopted),input.job_id.to_string(),&slot_id,&slot_state,slot_version],
            )?;
            ensure!(changed == 1, "cancellation lost slot compare-and-set");
        }
        let (job_state, job_version): (String, i64) = conn.query_row(
            "SELECT state,version FROM image_generation_jobs WHERE job_id=?1",
            [input.job_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        let current = ImageGenerationJobState::parse(&job_state)
            .ok_or_else(|| anyhow::anyhow!("unknown job state"))?;
        let mut projection_statement=conn.prepare("SELECT state,applied_cancellation_version,result_after_cancel FROM image_generation_slots WHERE job_id=?1 ORDER BY slot_index")?;
        let projection = projection_statement
            .query_map([input.job_id.to_string()], |row| {
                let state: String = row.get(0)?;
                let cancellation: Option<i64> = row.get(1)?;
                let flag: i64 = row.get(2)?;
                Ok(ImageGenerationSlotTerminalFact {
                    state: ImageGenerationSlotState::parse(&state)
                        .ok_or_else(|| rusqlite::Error::InvalidQuery)?,
                    applied_cancellation_version: cancellation.map(|value| value as u64),
                    result_after_cancel: flag == 1,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let reduced = reduce_terminal_job_facts(&projection);
        let next = reduced
            .filter(|terminal| job_transition_allowed(current, *terminal))
            .unwrap_or(ImageGenerationJobState::CancellationRequested);
        ensure!(
            job_transition_allowed(current, next),
            "job cannot accept cancellation"
        );
        let changed=conn.execute("UPDATE image_generation_jobs SET state=?1,version=?2,updated_at_unix_ms=?3 WHERE job_id=?4 AND state=?5 AND version=?6",params![next.as_str(),job_version+1,input.requested_at_unix_ms,input.job_id.to_string(),job_state,job_version])?;
        ensure!(changed == 1, "cancellation lost job compare-and-set");
        Ok(ImageGenerationCasOutcome::Applied {
            version: (job_version + 1) as u64,
        })
    }
}

fn atomic_conn<T>(
    conn: &Connection,
    savepoint: &str,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    conn.execute_batch(&format!("SAVEPOINT {savepoint}"))?;
    match operation() {
        Ok(value) => {
            conn.execute_batch(&format!("RELEASE SAVEPOINT {savepoint}"))?;
            Ok(value)
        }
        Err(error) => {
            let rollback = conn.execute_batch(&format!(
                "ROLLBACK TO SAVEPOINT {savepoint}; RELEASE SAVEPOINT {savepoint}"
            ));
            if let Err(rollback_error) = rollback {
                return Err(
                    error.context(format!("savepoint rollback also failed: {rollback_error}"))
                );
            }
            Err(error)
        }
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(any())]
fn json_has_unquoted_whitespace(bytes: &[u8]) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false
            } else if *byte == b'\\' {
                escaped = true
            } else if *byte == b'"' {
                quoted = false
            }
        } else if *byte == b'"' {
            quoted = true
        } else if byte.is_ascii_whitespace() {
            return true;
        }
    }
    quoted || escaped
}

#[cfg(any())]
fn json_keys_are_ordered(bytes: &[u8], keys: &[&str]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    let mut last = None;
    for key in keys {
        let needle = format!("\"{key}\":");
        if let Some(position) = text.find(&needle) {
            if last.is_some_and(|prior| position <= prior) {
                return false;
            }
            last = Some(position);
        }
    }
    true
}

#[cfg(any())]
fn reject_duplicate_json_keys(bytes: &[u8]) -> Result<()> {
    struct Checked;
    impl<'de> serde::Deserialize<'de> for Checked {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            deserializer.deserialize_any(CheckedVisitor)
        }
    }
    struct CheckedVisitor;
    impl<'de> serde::de::Visitor<'de> for CheckedVisitor {
        type Value = Checked;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("JSON without duplicate keys")
        }
        fn visit_map<A: serde::de::MapAccess<'de>>(
            self,
            mut map: A,
        ) -> std::result::Result<Checked, A::Error> {
            let mut keys = std::collections::BTreeSet::new();
            while let Some(key) = map.next_key::<String>()? {
                if !keys.insert(key) {
                    return Err(serde::de::Error::custom("duplicate JSON key"));
                }
                map.next_value::<Checked>()?;
            }
            Ok(Checked)
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> std::result::Result<Checked, A::Error> {
            while seq.next_element::<Checked>()?.is_some() {}
            Ok(Checked)
        }
        fn visit_bool<E: serde::de::Error>(self, _: bool) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_i64<E: serde::de::Error>(self, _: i64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_u64<E: serde::de::Error>(self, _: u64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_f64<E: serde::de::Error>(self, _: f64) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_str<E: serde::de::Error>(self, _: &str) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_string<E: serde::de::Error>(self, _: String) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_none<E: serde::de::Error>(self) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_unit<E: serde::de::Error>(self) -> std::result::Result<Checked, E> {
            Ok(Checked)
        }
        fn visit_some<D: serde::Deserializer<'de>>(
            self,
            d: D,
        ) -> std::result::Result<Checked, D::Error> {
            Checked::deserialize(d)
        }
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let _ = Checked::deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::image_generation_plan::*;

    fn canonical_test_plan(
        job_id: Uuid,
        slot_id: Uuid,
        artifact_id: Uuid,
        attempts: u32,
        enqueue_ms: u64,
        deadline_ms: u64,
    ) -> (Vec<u8>, String) {
        let reservation = ResourceReservationV1 {
            resource_kind: "image_samples".into(),
            units: u64::from(attempts),
            reservation_identity: "resource:fixture".into(),
        };
        let attempt_graph = (1..=attempts)
            .map(|attempt_number| AttemptPlanV1 {
                attempt_number,
                provider_request_identity: format!("request:{attempt_number}"),
                provider_idempotency_identity: format!("idem:{attempt_number}"),
                resource_maximum: vec![ResourceReservationV1 {
                    units: 1,
                    ..reservation.clone()
                }],
                maximum_usd_micros: Some(1),
            })
            .collect();
        let plan = ImageGenerationPlanV1 {
            schema_version: 1,
            kind: "imageGenerationPlan".into(),
            job_id,
            owner_session_id: Uuid::new_v4(),
            owner_principal_digest: "1".repeat(64),
            project_identity_digest: "2".repeat(64),
            config_generation: 1,
            enqueue_started_monotonic_ms: enqueue_ms,
            operation_deadline_monotonic_ms: deadline_ms,
            required_grants: vec![GrantRequirementV1 {
                grant_kind: "image.generate".into(),
                authority_digest: "3".repeat(64),
                generation: 1,
            }],
            central_resources: vec![reservation],
            spend: SpendReservationPlanV1 {
                required: true,
                policy_version: 1,
                reservation_id: "spend:fixture".into(),
                maximum_usd_micros: Some(u64::from(attempts)),
                plan_digest: "4".repeat(64),
            },
            output_authority: OutputDirectoryAuthorityV1 {
                canonical_destination_digest: "5".repeat(64),
                parent_identity_digest: "6".repeat(64),
                authority_generation: 1,
                filename_prefix: "generated".into(),
                extension: "png".into(),
            },
            targets: vec![TargetPlanV1 {
                target_id: "fixture".into(),
                target_config_generation: 1,
                normalized_config_digest: "7".repeat(64),
                capability_provenance: CapabilityProvenanceV1 {
                    capability_generation: 1,
                    capability_digest: "8".repeat(64),
                    health_observed_at_monotonic_ms: 0,
                    health_expires_at_monotonic_ms: deadline_ms,
                },
                destination: TargetDestinationV1 {
                    adapter_kind: "fixture".into(),
                    endpoint_identity_digest: "9".repeat(64),
                    credential_identity_digest: "a".repeat(64),
                    destination_generation: 1,
                },
                reference_artifacts: vec![],
                requested: RequestedOutputV1 {
                    width: 1,
                    height: 1,
                    format: "png".into(),
                },
                resolved: ResolvedOutputV1 {
                    width: 1,
                    height: 1,
                    format: "png".into(),
                    mime: "image/png".into(),
                    vector_sanitization_required: false,
                    vector_sanitizer: None,
                },
                typed_parameters: Default::default(),
                sample_count: 1,
                max_attempts: attempts,
                slots: vec![OutputSlotPlanV1 {
                    slot_id,
                    slot_index: 0,
                    sample_index: 0,
                    managed_artifact_id: artifact_id,
                    publication_name: "generated.png".into(),
                    attempts: attempt_graph,
                }],
            }],
        };
        let bytes = plan.canonical_bytes().unwrap();
        let digest = plan.digest().unwrap();
        (bytes, digest)
    }

    struct RaceFixture {
        job_id: Uuid,
        slot_id: Uuid,
        operation_id: Uuid,
    }

    fn race_fixture(conn: &Connection, adopted: bool) -> Result<RaceFixture> {
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
        let artifact_id = Uuid::now_v7();
        let (plan, digest) = canonical_test_plan(job_id, slot_id, artifact_id, 1, 1, 100);
        let verified = CreateImageGenerationJob::from_verified_canonical_plan(&plan, &digest, 1)?;
        Db::create_image_generation_graph_conn(
            conn,
            &verified,
            &[CreateImageGenerationSlot {
                slot_id,
                slot_index: 0,
                sample_index: 0,
                managed_artifact_id: artifact_id,
                attempts: vec![CreateImageGenerationAttempt {
                    attempt_number: 1,
                    provider_request_identity: "request:1".into(),
                    provider_idempotency_identity: "idem:1".into(),
                }],
            }],
        )?;
        let journal_state = if adopted { "succeeded" } else { "accepted" };
        conn.execute("INSERT INTO external_journal_operations(operation_id,operation_kind,owner_session_id,idempotency_key,payload_digest,payload_len,state,version,created_at_wall_ms,updated_at_wall_ms,terminal_at_wall_ms) VALUES(?1,'image_generation','owner','idem',?2,1,?3,1,1,1,CASE WHEN ?3='succeeded' THEN 1 ELSE NULL END)",params![operation_id.to_string(),"1".repeat(64),journal_state])?;
        for (state, version) in [
            ("preparing", 2),
            ("prepared", 3),
            ("dispatching", 4),
            ("accepted", 5),
            ("downloading", 6),
        ] {
            conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,external_operation_id=?3,observed_journal_version=1 WHERE job_id=?4 AND slot_id=?5 AND attempt_number=1",params![state,version,operation_id.to_string(),job_id.to_string(),slot_id.to_string()])?;
        }
        for (state, version) in [
            ("queued", 2),
            ("dispatching", 3),
            ("running", 4),
            ("downloading", 5),
        ] {
            conn.execute("UPDATE image_generation_slots SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4",params![state,version,job_id.to_string(),slot_id.to_string()])?;
        }
        for (state, version) in [("validating", 2), ("queued", 3), ("dispatching", 4)] {
            conn.execute(
                "UPDATE image_generation_jobs SET state=?1,version=?2 WHERE job_id=?3",
                params![state, version, job_id.to_string()],
            )?;
        }
        if adopted {
            conn.execute("UPDATE image_generation_attempts SET state='response_adopted',version=7,response_digest=?1 WHERE job_id=?2 AND slot_id=?3 AND attempt_number=1",params!["a".repeat(64),job_id.to_string(),slot_id.to_string()])?;
            conn.execute("UPDATE image_generation_slots SET state='validating',version=6 WHERE job_id=?1 AND slot_id=?2",params![job_id.to_string(),slot_id.to_string()])?;
            conn.execute("UPDATE image_generation_slots SET state='ready_to_publish',version=7 WHERE job_id=?1 AND slot_id=?2",params![job_id.to_string(),slot_id.to_string()])?;
        }
        Ok(RaceFixture {
            job_id,
            slot_id,
            operation_id,
        })
    }

    #[test]
    fn terminal_reducer_has_exact_precedence() {
        use ImageGenerationJobState as J;
        use ImageGenerationSlotState as S;
        assert_eq!(reduce_terminal_job(&[]), None);
        assert_eq!(reduce_terminal_job(&[(S::ReadyToPublish, false)]), None);
        assert_eq!(
            reduce_terminal_job(&[(S::Published, false)]),
            Some(J::Completed)
        );
        assert_eq!(
            reduce_terminal_job(&[(S::Published, false), (S::Failed, false)]),
            Some(J::PartiallyFailed)
        );
        assert_eq!(
            reduce_terminal_job(&[(S::Failed, false), (S::Cancelled, false)]),
            Some(J::Failed)
        );
        assert_eq!(
            reduce_terminal_job(&[(S::Cancelled, false), (S::Cancelled, false)]),
            Some(J::Cancelled)
        );
        assert_eq!(
            reduce_terminal_job(&[(S::Discarded, true), (S::Published, false)]),
            Some(J::CompletedAfterCancel)
        );
        assert_eq!(reduce_terminal_job(&[(S::LateQuarantined, false)]), None);
        assert_eq!(reduce_terminal_job(&[(S::Discarded, false)]), None);
    }

    #[test]
    fn terminal_reducer_rejects_every_invalid_cancellation_vector() {
        use ImageGenerationSlotState as S;
        for state in [
            S::Published,
            S::LateQuarantined,
            S::Failed,
            S::Cancelled,
            S::Discarded,
        ] {
            for cancellation in [None, Some(1)] {
                for result_after_cancel in [false, true] {
                    let fact = ImageGenerationSlotTerminalFact {
                        state,
                        applied_cancellation_version: cancellation,
                        result_after_cancel,
                    };
                    assert_eq!(
                        reduce_terminal_job_facts(&[fact]).is_some(),
                        terminal_slot_vector_valid(fact),
                        "{fact:?}"
                    );
                }
            }
        }
        for state in ImageGenerationSlotState::ALL
            .iter()
            .copied()
            .filter(|state| !slot_is_job_settled(*state))
        {
            assert_eq!(
                reduce_terminal_job_facts(&[ImageGenerationSlotTerminalFact {
                    state,
                    applied_cancellation_version: None,
                    result_after_cancel: false
                }]),
                None
            );
        }
    }

    #[test]
    fn transition_tables_reject_self_and_terminal_edges() {
        for state in ImageGenerationJobState::ALL {
            assert!(!job_transition_allowed(*state, *state));
        }
        for state in ImageGenerationSlotState::ALL {
            assert!(!slot_transition_allowed(*state, *state));
        }
        for state in ImageGenerationAttemptState::ALL {
            assert!(!attempt_transition_allowed(*state, *state));
        }
    }

    #[test]
    fn database_transition_registries_are_bijective_with_code_graphs() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let assert_graph = |table: &str,
                                states: &[&str],
                                allowed: &dyn Fn(&str, &str) -> bool|
             -> Result<()> {
                let mut statement =
                    conn.prepare(&format!("SELECT from_state,to_state FROM {table}"))?;
                let rows = statement
                    .query_map([], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                    })?
                    .collect::<rusqlite::Result<std::collections::BTreeSet<_>>>()?;
                let expected = states
                    .iter()
                    .flat_map(|from| {
                        states.iter().filter_map(|to| {
                            allowed(from, to).then(|| ((*from).to_owned(), (*to).to_owned()))
                        })
                    })
                    .collect::<std::collections::BTreeSet<_>>();
                ensure!(
                    rows == expected,
                    "{table} diverges from the shared code graph"
                );
                Ok(())
            };
            let jobs = ImageGenerationJobState::ALL
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>();
            assert_graph("image_generation_job_transitions", &jobs, &|from, to| {
                job_transition_allowed(
                    ImageGenerationJobState::parse(from).unwrap(),
                    ImageGenerationJobState::parse(to).unwrap(),
                )
            })?;
            let slots = ImageGenerationSlotState::ALL
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>();
            assert_graph("image_generation_slot_transitions", &slots, &|from, to| {
                slot_transition_allowed(
                    ImageGenerationSlotState::parse(from).unwrap(),
                    ImageGenerationSlotState::parse(to).unwrap(),
                )
            })?;
            let attempts = ImageGenerationAttemptState::ALL
                .iter()
                .map(|state| state.as_str())
                .collect::<Vec<_>>();
            assert_graph(
                "image_generation_attempt_transitions",
                &attempts,
                &|from, to| {
                    attempt_transition_allowed(
                        ImageGenerationAttemptState::parse(from).unwrap(),
                        ImageGenerationAttemptState::parse(to).unwrap(),
                    )
                },
            )?;
            Ok(())
        })
        .unwrap();
    }

    #[test]
    fn sealed_plan_token_rejects_duplicate_and_noncanonical_json() {
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        let artifact_id = Uuid::now_v7();
        let (canonical, digest) = canonical_test_plan(job_id, slot_id, artifact_id, 1, 1, 2);
        assert!(
            CreateImageGenerationJob::from_verified_canonical_plan(&canonical, &digest, 1).is_ok()
        );
        let canonical = String::from_utf8(canonical).unwrap();
        let spaced = canonical.replacen("{", "{ ", 1);
        let spaced_digest = hex_lower(&Sha256::digest(spaced.as_bytes()));
        assert!(
            CreateImageGenerationJob::from_verified_canonical_plan(
                spaced.as_bytes(),
                &spaced_digest,
                1
            )
            .is_err()
        );
        let duplicate = canonical.replacen(
            "\"jobId\":",
            &format!("\"jobId\":\"{job_id}\",\"jobId\":"),
            1,
        );
        let duplicate_digest = hex_lower(&Sha256::digest(duplicate.as_bytes()));
        assert!(
            CreateImageGenerationJob::from_verified_canonical_plan(
                duplicate.as_bytes(),
                &duplicate_digest,
                1
            )
            .is_err()
        );
        let reordered = canonical.replacen(
            r#""schemaVersion":1,"kind":"imageGenerationPlan""#,
            r#""kind":"imageGenerationPlan","schemaVersion":1"#,
            1,
        );
        assert_ne!(reordered, canonical);
        let reordered_digest = hex_lower(&Sha256::digest(reordered.as_bytes()));
        assert!(
            CreateImageGenerationJob::from_verified_canonical_plan(
                reordered.as_bytes(),
                &reordered_digest,
                1
            )
            .is_err()
        );
    }

    #[test]
    fn repository_cas_is_versioned_and_rejects_forbidden_edges() {
        let db = Db::open_in_memory().unwrap();
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        db.blocking_for_sync_cli(move |conn| {
            let artifact_id=Uuid::now_v7();
            let (canonical_plan, plan_digest) = canonical_test_plan(job_id, slot_id, artifact_id, 1, 10, 20);
            let verified=CreateImageGenerationJob::from_verified_canonical_plan(&canonical_plan,&plan_digest,30)?;
            Db::create_image_generation_job_conn(
                conn,
                &verified,
            )?;
            conn.execute(
                "INSERT INTO image_generation_slots(job_id,slot_id,slot_index,sample_index,managed_artifact_id,max_attempt_count,state,version) VALUES(?1,?2,0,0,?3,1,'planned',1)",
                params![job_id.to_string(), slot_id.to_string(), Uuid::now_v7().to_string()],
            )?;
            assert_eq!(
                Db::cas_image_generation_job_state_conn(conn, job_id, ImageGenerationJobState::Created, 1, ImageGenerationJobState::Validating, 31)?,
                ImageGenerationCasOutcome::Applied { version: 2 }
            );
            assert_eq!(
                Db::cas_image_generation_job_state_conn(conn, job_id, ImageGenerationJobState::Created, 1, ImageGenerationJobState::Validating, 31)?,
                ImageGenerationCasOutcome::Conflict
            );
            assert!(Db::cas_image_generation_slot_state_conn(conn, job_id, slot_id, ImageGenerationSlotState::Planned, 1, ImageGenerationSlotState::Published).is_err());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn cancellation_cas_settles_every_undispatched_slot_once() {
        let db = Db::open_in_memory().unwrap();
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        db.blocking_for_sync_cli(move|conn|{
            let artifact_id=Uuid::now_v7();
            let (canonical_plan, digest)=canonical_test_plan(job_id, slot_id, artifact_id, 2, 1, 10);
            let verified=CreateImageGenerationJob::from_verified_canonical_plan(&canonical_plan,&digest,1)?;
            Db::create_image_generation_graph_conn(conn,&verified,&[CreateImageGenerationSlot{slot_id,slot_index:0,sample_index:0,managed_artifact_id:artifact_id,attempts:vec![CreateImageGenerationAttempt{attempt_number:1,provider_request_identity:"request:1".into(),provider_idempotency_identity:"idem:1".into()},CreateImageGenerationAttempt{attempt_number:2,provider_request_identity:"request:2".into(),provider_idempotency_identity:"idem:2".into()}]}])?;
            assert!(matches!(Db::cas_image_generation_job_state_conn(conn,job_id,ImageGenerationJobState::Created,1,ImageGenerationJobState::Validating,2)?,ImageGenerationCasOutcome::Applied{..}));
            assert!(matches!(Db::cas_image_generation_job_state_conn(conn,job_id,ImageGenerationJobState::Validating,2,ImageGenerationJobState::Queued,3)?,ImageGenerationCasOutcome::Applied{..}));
            assert!(matches!(Db::cas_image_generation_slot_state_conn(conn,job_id,slot_id,ImageGenerationSlotState::Planned,1,ImageGenerationSlotState::Queued)?,ImageGenerationCasOutcome::Applied{..}));
            assert!(matches!(Db::request_image_generation_cancellation_conn(conn,&RequestImageGenerationCancellation{job_id,cancellation_version:1,request_operation_id:"cancel:1",requested_at_unix_ms:4})?,ImageGenerationCasOutcome::Applied{..}));
            let job_state:String=conn.query_row("SELECT state FROM image_generation_jobs WHERE job_id=?1",[job_id.to_string()],|row|row.get(0))?;
            let slot:(String,i64,i64)=conn.query_row("SELECT state,applied_cancellation_version,result_after_cancel FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2",params![job_id.to_string(),slot_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            let attempts:i64=conn.query_row("SELECT COUNT(*) FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND state='cancelled' AND applied_cancellation_version=1",params![job_id.to_string(),slot_id.to_string()],|row|row.get(0))?;
            assert_eq!((job_state,slot,attempts),("cancelled".into(),("cancelled".into(),1,0),2));
            assert!(Db::request_image_generation_cancellation_conn(conn,&RequestImageGenerationCancellation{job_id,cancellation_version:2,request_operation_id:"cancel:2",requested_at_unix_ms:5}).is_err());
            let facts:i64=conn.query_row("SELECT COUNT(*) FROM image_generation_cancellation_facts WHERE job_id=?1",[job_id.to_string()],|row|row.get(0))?;
            assert_eq!(facts,1);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn response_cancellation_publication_race_has_one_winner_in_every_order() {
        let publish_first = Db::open_in_memory().unwrap();
        publish_first
            .blocking_for_sync_cli(|conn| {
                let fixture = race_fixture(conn, true)?;
                Db::commit_image_generation_publication_conn(
                    conn,
                    &CommitImageGenerationPublication {
                        job_id: fixture.job_id,
                        slot_id: fixture.slot_id,
                        attempt_number: 1,
                        expected_attempt_version: 7,
                        expected_slot_version: 7,
                        artifact_generation: 1,
                        now_unix_ms: 10,
                    },
                )?;
                assert!(
                    Db::request_image_generation_cancellation_conn(
                        conn,
                        &RequestImageGenerationCancellation {
                            job_id: fixture.job_id,
                            cancellation_version: 1,
                            request_operation_id: "cancel",
                            requested_at_unix_ms: 11
                        }
                    )
                    .is_err()
                );
                let facts: i64 = conn.query_row(
                    "SELECT COUNT(*) FROM image_generation_cancellation_facts WHERE job_id=?1",
                    [fixture.job_id.to_string()],
                    |row| row.get(0),
                )?;
                assert_eq!(facts, 0);
                Ok(())
            })
            .unwrap();
        let cancel_first = Db::open_in_memory().unwrap();
        cancel_first.blocking_for_sync_cli(|conn|{
            let fixture=race_fixture(conn,true)?;
            Db::request_image_generation_cancellation_conn(conn,&RequestImageGenerationCancellation{job_id:fixture.job_id,cancellation_version:1,request_operation_id:"cancel",requested_at_unix_ms:11})?;
            assert!(Db::commit_image_generation_publication_conn(conn,&CommitImageGenerationPublication{job_id:fixture.job_id,slot_id:fixture.slot_id,attempt_number:1,expected_attempt_version:7,expected_slot_version:7,artifact_generation:1,now_unix_ms:12}).is_err());
            let fact:(String,String)=conn.query_row("SELECT ordering,response_digest FROM image_generation_cancelled_result_facts WHERE job_id=?1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?; assert_eq!(fact,("response_adopted_before_cancellation".into(),"a".repeat(64)));
            Ok(())
        }).unwrap();
        let response_after = Db::open_in_memory().unwrap();
        response_after.blocking_for_sync_cli(|conn|{
            let fixture=race_fixture(conn,false)?;
            Db::request_image_generation_cancellation_conn(conn,&RequestImageGenerationCancellation{job_id:fixture.job_id,cancellation_version:1,request_operation_id:"cancel",requested_at_unix_ms:10})?;
            Db::adopt_image_generation_response_conn(conn,&AdoptImageGenerationResponse{job_id:fixture.job_id,slot_id:fixture.slot_id,attempt_number:1,expected_attempt_version:7,expected_slot_version:6,external_operation_id:fixture.operation_id,expected_journal_version:2,response_digest:&"b".repeat(64),now_unix_ms:11})?;
            let fact:(String,String)=conn.query_row("SELECT ordering,response_digest FROM image_generation_cancelled_result_facts WHERE job_id=?1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?; assert_eq!(fact,("response_after_cancellation".into(),"b".repeat(64)));
            Ok(())
        }).unwrap();
    }
}
