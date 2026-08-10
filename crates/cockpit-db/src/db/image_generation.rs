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
    use ImageGenerationJobState as J;
    use ImageGenerationSlotState as S;
    if slots.is_empty()
        || slots.iter().any(|(state, result_after_cancel)| {
            !slot_is_job_settled(*state)
                || (matches!(
                    state,
                    ImageGenerationSlotState::LateQuarantined | ImageGenerationSlotState::Discarded
                ) && !result_after_cancel)
        })
    {
        return None;
    }
    if slots
        .iter()
        .any(|(_, result_after_cancel)| *result_after_cancel)
    {
        Some(J::CompletedAfterCancel)
    } else if slots.iter().all(|(state, _)| *state == S::Published) {
        Some(J::Completed)
    } else if slots.iter().any(|(state, _)| *state == S::Published) {
        Some(J::PartiallyFailed)
    } else if slots.iter().any(|(state, _)| *state == S::Failed) {
        Some(J::Failed)
    } else {
        Some(J::Cancelled)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationJob<'a> {
    pub job_id: Uuid,
    pub plan_digest: &'a str,
    pub canonical_plan: &'a [u8],
    pub slot_count: u32,
    pub max_attempt_count: u32,
    pub enqueue_started_monotonic_ms: u64,
    pub operation_deadline_monotonic_ms: u64,
    pub created_at_unix_ms: i64,
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationCasOutcome {
    Applied { version: u64 },
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGenerationAttemptEvidence<'a> {
    pub external_operation_id: &'a str,
    pub journal_version: u64,
    pub authoritative_nonacceptance_digest: Option<&'a str>,
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
pub struct CancelAdoptedImageGenerationResponse<'a> {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_attempt_version: u64,
    pub expected_slot_version: u64,
    pub cancellation_version: u64,
    pub request_operation_id: &'a str,
    pub response_digest: &'a str,
    pub journal_terminal_version: u64,
    pub requested_at_unix_ms: i64,
}

impl Db {
    /// Inserts the sealed plan and its initial projection in the caller's
    /// transaction. Composition with grants, resources, spend and journal
    /// rows therefore needs no second connection or async boundary.
    pub fn create_image_generation_job_conn(
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
                    let sealed_max = target
                        .get("maxAttempts")
                        .and_then(serde_json::Value::as_u64)
                        .ok_or_else(|| anyhow::anyhow!("sealed plan retry bound missing"))?;
                    ensure!(
                        sealed_max == u64::from(input.max_attempt_count),
                        "sealed retry bound mismatch"
                    );
                    for slot in slots {
                        ensure!(
                            slot.get("attempts")
                                .and_then(serde_json::Value::as_array)
                                .is_some_and(
                                    |attempts| attempts.len() == input.max_attempt_count as usize
                                ),
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
            ensure!(
                slot.slot_index as usize == slot_index,
                "slot graph is not canonical"
            );
            ensure!(
                slot.attempts.len() == input.max_attempt_count as usize,
                "sealed attempt graph does not match plan"
            );
            conn.execute(
                "INSERT INTO image_generation_slots(job_id,slot_id,slot_index,sample_index,managed_artifact_id,state,version) VALUES(?1,?2,?3,?4,?5,'planned',1)",
                params![input.job_id.to_string(), slot.slot_id.to_string(), i64::from(slot.slot_index), i64::from(slot.sample_index), slot.managed_artifact_id.to_string()],
            )?;
            for (attempt_index, attempt) in slot.attempts.iter().enumerate() {
                ensure!(
                    attempt.attempt_number as usize == attempt_index + 1,
                    "attempt numbers must be contiguous from one"
                );
                conn.execute(
                    "INSERT INTO image_generation_attempts(job_id,slot_id,attempt_number,state,version) VALUES(?1,?2,?3,'planned',1)",
                    params![input.job_id.to_string(), slot.slot_id.to_string(), i64::from(attempt.attempt_number)],
                )?;
            }
        }
        Ok(())
    }

    pub fn cas_image_generation_job_state_conn(
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

    pub fn cas_image_generation_slot_state_conn(
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

    pub fn cas_image_generation_attempt_state_conn(
        conn: &Connection,
        identity: (Uuid, Uuid, u32),
        expected_state: ImageGenerationAttemptState,
        expected_version: u64,
        next_state: ImageGenerationAttemptState,
        evidence: Option<ImageGenerationAttemptEvidence<'_>>,
    ) -> Result<ImageGenerationCasOutcome> {
        ensure!(
            attempt_transition_allowed(expected_state, next_state),
            "forbidden image generation attempt transition"
        );
        ensure!(
            evidence.is_some()
                || matches!(
                    next_state,
                    ImageGenerationAttemptState::Preparing
                        | ImageGenerationAttemptState::Cancelled
                        | ImageGenerationAttemptState::FailedNotSubmitted
                ),
            "attempt projection requires journal evidence"
        );
        let next_version = expected_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("image generation attempt version overflow"))?;
        let expected_version_sql = i64::try_from(expected_version)?;
        let next_version_sql = i64::try_from(next_version)?;
        let attempt_number_sql = i64::from(identity.2);
        if expected_state == ImageGenerationAttemptState::Dispatching
            && next_state == ImageGenerationAttemptState::FailedNotSubmitted
        {
            ensure!(
                evidence
                    .and_then(|item| item.authoritative_nonacceptance_digest)
                    .is_some(),
                "dispatch failure requires authoritative zero-handoff evidence"
            );
        }
        let (operation_id, journal_version, nonacceptance_digest) = match evidence {
            Some(item) => (
                Some(item.external_operation_id),
                Some(i64::try_from(item.journal_version)?),
                item.authoritative_nonacceptance_digest,
            ),
            None => (None, None, None),
        };
        let changed = conn.execute(
            "UPDATE image_generation_attempts SET state=?1,version=?2,external_operation_id=COALESCE(external_operation_id,?3),observed_journal_version=?4,nonacceptance_evidence_digest=?5 WHERE job_id=?6 AND slot_id=?7 AND attempt_number=?8 AND state=?9 AND version=?10 AND (external_operation_id IS NULL OR external_operation_id=?3) AND (observed_journal_version IS NULL OR observed_journal_version<=?4)",
            params![next_state.as_str(), next_version_sql, operation_id, journal_version, nonacceptance_digest, identity.0.to_string(), identity.1.to_string(), attempt_number_sql, expected_state.as_str(), expected_version_sql],
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
        let changed = conn.execute(
            "UPDATE image_generation_slots SET state=?1,version=?2,applied_cancellation_version=?3,result_after_cancel=?4 WHERE job_id=?5 AND slot_id=?6 AND state='downloading' AND version=?7",
            params![slot_next.as_str(),i64::try_from(input.expected_slot_version+1)?,applied_cancellation,i64::from(cancellation.is_some()),input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?],
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

    pub fn cancel_adopted_image_generation_response_conn(
        conn: &Connection,
        input: &CancelAdoptedImageGenerationResponse<'_>,
    ) -> Result<ImageGenerationCasOutcome> {
        atomic_conn(conn, "image_generation_cancel_adopted", || {
            Self::cancel_adopted_image_generation_response_inner(conn, input)
        })
    }

    fn cancel_adopted_image_generation_response_inner(
        conn: &Connection,
        input: &CancelAdoptedImageGenerationResponse<'_>,
    ) -> Result<ImageGenerationCasOutcome> {
        conn.execute(
            "INSERT INTO image_generation_cancellation_facts(job_id,cancellation_version,requested_at_unix_ms,request_operation_id) VALUES(?1,?2,?3,?4)",
            params![input.job_id.to_string(),i64::try_from(input.cancellation_version)?,input.requested_at_unix_ms,input.request_operation_id],
        )?;
        let fact_changed = conn.execute(
            "INSERT INTO image_generation_cancelled_result_facts(job_id,slot_id,attempt_number,cancellation_version,response_digest,journal_terminal_version,ordering) SELECT ?1,?2,?3,?4,?5,?6,'response_adopted_before_cancellation' WHERE EXISTS(SELECT 1 FROM image_generation_attempts a JOIN external_journal_operations j ON j.operation_id=a.external_operation_id WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state='response_adopted' AND a.version=?7 AND a.response_digest=?5 AND a.observed_journal_version=?6 AND j.state='succeeded' AND j.version=?6) AND EXISTS(SELECT 1 FROM image_generation_slots s WHERE s.job_id=?1 AND s.slot_id=?2 AND s.state='ready_to_publish' AND s.version=?8 AND s.applied_cancellation_version IS NULL AND s.result_after_cancel=0) AND NOT EXISTS(SELECT 1 FROM image_generation_publication_right_facts p WHERE p.job_id=?1 AND p.slot_id=?2)",
            params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.cancellation_version)?,input.response_digest,i64::try_from(input.journal_terminal_version)?,i64::try_from(input.expected_attempt_version)?,i64::try_from(input.expected_slot_version)?],
        )?;
        ensure!(
            fact_changed == 1,
            "cancellation lost response/publication compare-and-set"
        );
        let attempt_changed=conn.execute(
            "UPDATE image_generation_attempts SET state='completed_after_cancel',version=?1,applied_cancellation_version=?2 WHERE job_id=?3 AND slot_id=?4 AND attempt_number=?5 AND state='response_adopted' AND version=?6",
            params![i64::try_from(input.expected_attempt_version+1)?,i64::try_from(input.cancellation_version)?,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version)?],
        )?;
        ensure!(
            attempt_changed == 1,
            "cancellation lost attempt compare-and-set"
        );
        let slot_changed=conn.execute(
            "UPDATE image_generation_slots SET state='late_quarantined',version=?1,applied_cancellation_version=?2,result_after_cancel=1 WHERE job_id=?3 AND slot_id=?4 AND state='ready_to_publish' AND version=?5",
            params![i64::try_from(input.expected_slot_version+1)?,i64::try_from(input.cancellation_version)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?],
        )?;
        ensure!(slot_changed == 1, "cancellation lost slot compare-and-set");
        Ok(ImageGenerationCasOutcome::Applied {
            version: input.expected_slot_version + 1,
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn repository_cas_is_versioned_and_rejects_forbidden_edges() {
        let db = Db::open_in_memory().unwrap();
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        db.blocking_for_sync_cli(move |conn| {
            let canonical_plan = format!(
                r#"{{"schemaVersion":1,"jobId":"{job_id}","targets":[{{"maxAttempts":1,"slots":[{{"attempts":[{{}}]}}]}}]}}"#
            );
            let plan_digest = hex_lower(&Sha256::digest(canonical_plan.as_bytes()));
            Db::create_image_generation_job_conn(
                conn,
                &CreateImageGenerationJob {
                    job_id,
                    plan_digest: &plan_digest,
                    canonical_plan: canonical_plan.as_bytes(),
                    slot_count: 1,
                    max_attempt_count: 1,
                    enqueue_started_monotonic_ms: 10,
                    operation_deadline_monotonic_ms: 20,
                    created_at_unix_ms: 30,
                },
            )?;
            conn.execute(
                "INSERT INTO image_generation_slots(job_id,slot_id,slot_index,sample_index,managed_artifact_id,state,version) VALUES(?1,?2,0,0,?3,'planned',1)",
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
}
