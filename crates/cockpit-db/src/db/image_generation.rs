//! Provider-neutral durable image-generation state vocabulary.
//!
//! Transition legality lives here so repository reducers and protocol
//! projections cannot develop separate interpretations of persisted states.

use anyhow::{Result, ensure};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Db;

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
    if slots.is_empty() || slots.iter().any(|(state, _)| !slot_is_job_settled(*state)) {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationCasOutcome {
    Applied { version: u64 },
    Conflict,
}

impl Db {
    /// Inserts the sealed plan and its initial projection in the caller's
    /// transaction. Composition with grants, resources, spend and journal
    /// rows therefore needs no second connection or async boundary.
    pub fn create_image_generation_job_conn(
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
        journal_evidence: Option<(&str, u64)>,
    ) -> Result<ImageGenerationCasOutcome> {
        ensure!(
            attempt_transition_allowed(expected_state, next_state),
            "forbidden image generation attempt transition"
        );
        ensure!(
            journal_evidence.is_some()
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
        let (operation_id, journal_version) = match journal_evidence {
            Some((id, version)) => (Some(id), Some(i64::try_from(version)?)),
            None => (None, None),
        };
        let changed = conn.execute(
            "UPDATE image_generation_attempts SET state=?1,version=?2,external_operation_id=COALESCE(external_operation_id,?3),observed_journal_version=?4 WHERE job_id=?5 AND slot_id=?6 AND attempt_number=?7 AND state=?8 AND version=?9 AND (external_operation_id IS NULL OR external_operation_id=?3) AND (observed_journal_version IS NULL OR observed_journal_version<=?4)",
            params![next_state.as_str(), next_version_sql, operation_id, journal_version, identity.0.to_string(), identity.1.to_string(), attempt_number_sql, expected_state.as_str(), expected_version_sql],
        )?;
        Ok(if changed == 1 {
            ImageGenerationCasOutcome::Applied {
                version: next_version,
            }
        } else {
            ImageGenerationCasOutcome::Conflict
        })
    }
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
    fn repository_cas_is_versioned_and_rejects_forbidden_edges() {
        let db = Db::open_in_memory().unwrap();
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        db.blocking_for_sync_cli(move |conn| {
            Db::create_image_generation_job_conn(
                conn,
                &CreateImageGenerationJob {
                    job_id,
                    plan_digest: &"1".repeat(64),
                    canonical_plan: br#"{"schemaVersion":1}"#,
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
