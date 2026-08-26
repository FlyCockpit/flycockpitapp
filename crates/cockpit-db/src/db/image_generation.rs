//! Provider-neutral durable image-generation state vocabulary.
//!
//! Transition legality lives here so repository reducers and protocol
//! projections cannot develop separate interpretations of persisted states.

use anyhow::{Context as _, Result, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::Db;
use super::external_journal::{
    ExternalJournalRecord, ExternalJournalState, ExternalTransitionOutcome,
    PrepareExternalOperation, transition_external_operation_conn,
};
use super::image_generation_plan::{AttemptPlanV1, ImageGenerationPlanV1};
use super::image_spend::{
    ImageSpendDispatchEvidence, finish_reserved_image_spend_dispatch_conn,
    prepare_reserved_image_spend_dispatch_conn, settle_reconciled_image_spend_dispatch_conn,
};

const MAX_IMAGE_GENERATION_RECONCILIATION_EVIDENCE_BYTES: usize = 64 * 1024;

fn reconciliation_evidence_digest(bytes: &[u8]) -> Result<String> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_IMAGE_GENERATION_RECONCILIATION_EVIDENCE_BYTES,
        "reconciliation evidence length is invalid"
    );
    Ok(hex_lower(&Sha256::digest(bytes)))
}

/// Sealed-plan reservation identity for attempt 1; later attempts attach a
/// distinct per-slot retry reservation so the immutable plan digest is not
/// rewritten and two slots cannot collide on `{sealed}:retry:{attempt}`.
pub fn image_generation_attempt_media_reservation_id(
    sealed_reservation_id: &str,
    slot_id: Uuid,
    attempt_number: u32,
) -> String {
    if attempt_number <= 1 {
        sealed_reservation_id.to_owned()
    } else {
        format!("{sealed_reservation_id}:retry:{slot_id}:{attempt_number}")
    }
}

fn live_image_generation_attempt(conn: &Connection, job_id: Uuid) -> Result<(Uuid, u32)> {
    let (slot, attempt): (String, i64) = conn
        .query_row(
            "SELECT a.slot_id,a.attempt_number FROM image_generation_attempts a JOIN image_generation_attempt_activation_facts f ON f.job_id=a.job_id AND f.slot_id=a.slot_id AND f.attempt_number=a.attempt_number WHERE a.job_id=?1 AND a.state NOT IN ('failed_not_submitted','rejected_not_accepted','cancelled','succeeded','completed_after_cancel','failed_after_acceptance') ORDER BY a.attempt_number DESC, a.slot_id LIMIT 1",
            [job_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .context("image generation live attempt is absent")?;
    Ok((
        Uuid::parse_str(&slot).context("image generation live slot is invalid")?,
        u32::try_from(attempt).context("image generation live attempt is invalid")?,
    ))
}

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

state_enum!(ImageGenerationArtifactState {
    Allocating => "allocating", Writing => "writing", Retained => "retained",
    LateQuarantined => "late_quarantined", CleanupPending => "cleanup_pending",
    Deleting => "deleting", Tombstoned => "tombstoned", SecurityBlocked => "security_blocked"
});

state_enum!(ImageGenerationArtifactComponentState {
    Planned => "planned", Writing => "writing", Ready => "ready",
    CleanupPending => "cleanup_pending", Deleting => "deleting",
    Tombstoned => "tombstoned", SecurityBlocked => "security_blocked"
});

pub const IMAGE_ARTIFACT_STATES: &[&str] = &[
    "allocating",
    "writing",
    "retained",
    "late_quarantined",
    "cleanup_pending",
    "deleting",
    "tombstoned",
    "security_blocked",
];
pub const IMAGE_ARTIFACT_TERMINAL_STATES: &[&str] = &["tombstoned"];
pub const IMAGE_ARTIFACT_LEGAL_EDGES: &[(&str, &str)] = &[
    ("allocating", "writing"),
    ("allocating", "cleanup_pending"),
    ("allocating", "security_blocked"),
    ("writing", "retained"),
    ("writing", "late_quarantined"),
    ("writing", "cleanup_pending"),
    ("writing", "security_blocked"),
    ("retained", "cleanup_pending"),
    ("retained", "security_blocked"),
    ("late_quarantined", "retained"),
    ("late_quarantined", "cleanup_pending"),
    ("late_quarantined", "security_blocked"),
    ("cleanup_pending", "deleting"),
    ("cleanup_pending", "security_blocked"),
    ("deleting", "tombstoned"),
    ("deleting", "security_blocked"),
    ("security_blocked", "cleanup_pending"),
    ("security_blocked", "retained"),
];
pub const IMAGE_ARTIFACT_COMPONENT_STATES: &[&str] = &[
    "planned",
    "writing",
    "ready",
    "cleanup_pending",
    "deleting",
    "tombstoned",
    "security_blocked",
];
pub const IMAGE_ARTIFACT_COMPONENT_TERMINAL_STATES: &[&str] = &["tombstoned"];
pub const IMAGE_ARTIFACT_COMPONENT_LEGAL_EDGES: &[(&str, &str)] = &[
    ("planned", "writing"),
    ("planned", "cleanup_pending"),
    ("planned", "security_blocked"),
    ("writing", "ready"),
    ("writing", "cleanup_pending"),
    ("writing", "security_blocked"),
    ("ready", "cleanup_pending"),
    ("ready", "security_blocked"),
    ("cleanup_pending", "deleting"),
    ("cleanup_pending", "security_blocked"),
    ("deleting", "tombstoned"),
    ("deleting", "security_blocked"),
    ("security_blocked", "cleanup_pending"),
];

pub const IMAGE_JOB_STATES: &[&str] = &[
    "created",
    "validating",
    "awaiting_authorization",
    "queued",
    "dispatching",
    "submission_unknown",
    "running",
    "cancellation_requested",
    "downloading",
    "validating_output",
    "publishing",
    "completed",
    "completed_after_cancel",
    "partially_failed",
    "failed",
    "cancelled",
];
pub const IMAGE_JOB_TERMINAL_STATES: &[&str] = &[
    "completed",
    "completed_after_cancel",
    "partially_failed",
    "failed",
    "cancelled",
];
pub const IMAGE_JOB_CONDITIONAL_EDGES: &[(&str, &str)] =
    &[("dispatching", "queued"), ("submission_unknown", "queued")];
pub const IMAGE_JOB_LEGAL_EDGES: &[(&str, &str)] = &[
    ("created", "validating"),
    ("created", "failed"),
    ("created", "cancelled"),
    ("validating", "awaiting_authorization"),
    ("validating", "queued"),
    ("validating", "failed"),
    ("validating", "cancelled"),
    ("awaiting_authorization", "queued"),
    ("awaiting_authorization", "failed"),
    ("awaiting_authorization", "cancelled"),
    ("queued", "dispatching"),
    ("queued", "cancellation_requested"),
    ("queued", "failed"),
    ("queued", "cancelled"),
    ("dispatching", "submission_unknown"),
    ("dispatching", "running"),
    ("dispatching", "cancellation_requested"),
    ("dispatching", "downloading"),
    ("dispatching", "partially_failed"),
    ("dispatching", "failed"),
    ("dispatching", "cancelled"),
    ("submission_unknown", "running"),
    ("submission_unknown", "cancellation_requested"),
    ("submission_unknown", "downloading"),
    ("submission_unknown", "completed_after_cancel"),
    ("submission_unknown", "partially_failed"),
    ("submission_unknown", "failed"),
    ("running", "cancellation_requested"),
    ("running", "downloading"),
    ("running", "partially_failed"),
    ("running", "failed"),
    ("cancellation_requested", "cancelled"),
    ("cancellation_requested", "downloading"),
    ("cancellation_requested", "completed_after_cancel"),
    ("cancellation_requested", "partially_failed"),
    ("cancellation_requested", "failed"),
    ("downloading", "validating_output"),
    ("downloading", "cancellation_requested"),
    ("downloading", "completed_after_cancel"),
    ("downloading", "partially_failed"),
    ("downloading", "failed"),
    ("validating_output", "publishing"),
    ("validating_output", "cancellation_requested"),
    ("validating_output", "completed_after_cancel"),
    ("validating_output", "partially_failed"),
    ("validating_output", "failed"),
    ("publishing", "completed"),
    ("publishing", "cancellation_requested"),
    ("publishing", "completed_after_cancel"),
    ("publishing", "partially_failed"),
    ("publishing", "failed"),
];

pub const IMAGE_SLOT_STATES: &[&str] = &[
    "planned",
    "queued",
    "dispatching",
    "submission_unknown",
    "running",
    "cancellation_requested",
    "downloading",
    "validating",
    "ready_to_publish",
    "published",
    "late_quarantined",
    "failed",
    "cancelled",
    "discarded",
];
pub const IMAGE_SLOT_TERMINAL_STATES: &[&str] = &["published", "failed", "cancelled", "discarded"];
pub const IMAGE_SLOT_CONDITIONAL_EDGES: &[(&str, &str)] =
    &[("dispatching", "queued"), ("submission_unknown", "queued")];
pub const IMAGE_SLOT_LEGAL_EDGES: &[(&str, &str)] = &[
    ("planned", "queued"),
    ("planned", "failed"),
    ("planned", "cancelled"),
    ("queued", "dispatching"),
    ("queued", "failed"),
    ("queued", "cancelled"),
    ("dispatching", "submission_unknown"),
    ("dispatching", "running"),
    ("dispatching", "downloading"),
    ("dispatching", "cancellation_requested"),
    ("dispatching", "failed"),
    ("dispatching", "cancelled"),
    ("submission_unknown", "running"),
    ("submission_unknown", "downloading"),
    ("submission_unknown", "cancellation_requested"),
    ("submission_unknown", "failed"),
    ("submission_unknown", "cancelled"),
    ("running", "downloading"),
    ("running", "cancellation_requested"),
    ("running", "failed"),
    ("cancellation_requested", "cancelled"),
    ("cancellation_requested", "submission_unknown"),
    ("cancellation_requested", "downloading"),
    ("cancellation_requested", "failed"),
    ("downloading", "validating"),
    ("downloading", "cancellation_requested"),
    ("downloading", "failed"),
    ("validating", "ready_to_publish"),
    ("validating", "late_quarantined"),
    ("validating", "cancellation_requested"),
    ("validating", "failed"),
    ("ready_to_publish", "published"),
    ("ready_to_publish", "late_quarantined"),
    ("ready_to_publish", "failed"),
    ("late_quarantined", "published"),
    ("late_quarantined", "discarded"),
];

pub const IMAGE_ATTEMPT_STATES: &[&str] = &[
    "planned",
    "preparing",
    "prepared",
    "dispatching",
    "accepted",
    "submission_unknown",
    "reconciling",
    "running",
    "downloading",
    "cancellation_requested",
    "response_adopted",
    "failed_not_submitted",
    "rejected_not_accepted",
    "cancelled",
    "succeeded",
    "completed_after_cancel",
    "failed_after_acceptance",
];
pub const IMAGE_ATTEMPT_TERMINAL_STATES: &[&str] = &[
    "failed_not_submitted",
    "rejected_not_accepted",
    "cancelled",
    "succeeded",
    "completed_after_cancel",
    "failed_after_acceptance",
];
pub const IMAGE_ATTEMPT_LEGAL_EDGES: &[(&str, &str)] = &[
    ("planned", "preparing"),
    ("planned", "cancelled"),
    ("planned", "failed_not_submitted"),
    ("preparing", "prepared"),
    ("preparing", "cancelled"),
    ("preparing", "failed_not_submitted"),
    ("prepared", "dispatching"),
    ("prepared", "cancelled"),
    ("prepared", "failed_not_submitted"),
    ("dispatching", "accepted"),
    ("dispatching", "submission_unknown"),
    ("dispatching", "rejected_not_accepted"),
    ("dispatching", "cancellation_requested"),
    ("dispatching", "failed_not_submitted"),
    ("accepted", "running"),
    ("accepted", "downloading"),
    ("accepted", "cancellation_requested"),
    ("accepted", "response_adopted"),
    ("accepted", "failed_after_acceptance"),
    ("submission_unknown", "reconciling"),
    ("submission_unknown", "cancellation_requested"),
    ("reconciling", "accepted"),
    ("reconciling", "submission_unknown"),
    ("reconciling", "rejected_not_accepted"),
    ("reconciling", "downloading"),
    ("reconciling", "cancellation_requested"),
    ("reconciling", "failed_after_acceptance"),
    ("running", "downloading"),
    ("running", "cancellation_requested"),
    ("running", "failed_after_acceptance"),
    ("downloading", "response_adopted"),
    ("downloading", "completed_after_cancel"),
    ("downloading", "cancellation_requested"),
    ("downloading", "failed_after_acceptance"),
    ("cancellation_requested", "cancelled"),
    ("cancellation_requested", "submission_unknown"),
    ("cancellation_requested", "reconciling"),
    ("cancellation_requested", "accepted"),
    ("cancellation_requested", "downloading"),
    ("cancellation_requested", "completed_after_cancel"),
    ("cancellation_requested", "failed_after_acceptance"),
    ("response_adopted", "succeeded"),
    ("response_adopted", "completed_after_cancel"),
    ("response_adopted", "failed_after_acceptance"),
];

state_enum!(ImageGenerationArtifactComponentKind {
    Primary => "primary", NormalizedRaster => "normalized_raster",
    SanitizedSvg => "sanitized_svg", Thumbnail => "thumbnail", ModelPayload => "model_payload"
});

pub fn artifact_transition_allowed(
    from: ImageGenerationArtifactState,
    to: ImageGenerationArtifactState,
) -> bool {
    IMAGE_ARTIFACT_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}

pub fn artifact_component_transition_allowed(
    from: ImageGenerationArtifactComponentState,
    to: ImageGenerationArtifactComponentState,
) -> bool {
    IMAGE_ARTIFACT_COMPONENT_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}

pub fn job_transition_allowed(from: ImageGenerationJobState, to: ImageGenerationJobState) -> bool {
    IMAGE_JOB_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}

pub fn slot_transition_allowed(
    from: ImageGenerationSlotState,
    to: ImageGenerationSlotState,
) -> bool {
    IMAGE_SLOT_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}

pub fn attempt_transition_allowed(
    from: ImageGenerationAttemptState,
    to: ImageGenerationAttemptState,
) -> bool {
    IMAGE_ATTEMPT_LEGAL_EDGES.contains(&(from.as_str(), to.as_str()))
}

#[derive(Clone, Copy)]
enum ImageJobTransitionContext {
    Ordinary,
    AuthoritativeRetry,
    TerminalProjection,
}

fn execute_image_job_transition_conn(
    conn: &Connection,
    job_id: Uuid,
    from: ImageGenerationJobState,
    expected_version: u64,
    to: ImageGenerationJobState,
    updated_at_unix_ms: i64,
    context: ImageJobTransitionContext,
) -> Result<u64> {
    let allowed = match context {
        ImageJobTransitionContext::AuthoritativeRetry => {
            IMAGE_JOB_CONDITIONAL_EDGES.contains(&(from.as_str(), to.as_str()))
        }
        ImageJobTransitionContext::Ordinary | ImageJobTransitionContext::TerminalProjection => {
            job_transition_allowed(from, to)
        }
    };
    ensure!(allowed, "forbidden image generation job transition");
    let next_version = expected_version
        .checked_add(1)
        .context("image generation job version overflow")?;
    let changed = match context {
        ImageJobTransitionContext::TerminalProjection => conn.execute(
            "UPDATE image_generation_jobs SET state=?1,version=?2,terminal_event_version=?2,updated_at_unix_ms=?3 WHERE job_id=?4 AND state=?5 AND version=?6 AND terminal_event_version IS NULL",
            params![to.as_str(),i64::try_from(next_version)?,updated_at_unix_ms,job_id.to_string(),from.as_str(),i64::try_from(expected_version)?],
        )?,
        ImageJobTransitionContext::Ordinary | ImageJobTransitionContext::AuthoritativeRetry => conn.execute(
            "UPDATE image_generation_jobs SET state=?1,version=?2,updated_at_unix_ms=?3 WHERE job_id=?4 AND state=?5 AND version=?6",
            params![to.as_str(),i64::try_from(next_version)?,updated_at_unix_ms,job_id.to_string(),from.as_str(),i64::try_from(expected_version)?],
        )?,
    };
    ensure!(
        changed == 1,
        "image generation job transition lost compare-and-set"
    );
    Ok(next_version)
}

fn execute_basic_image_slot_transition_conn(
    conn: &Connection,
    job_id: Uuid,
    slot_id: Uuid,
    from: ImageGenerationSlotState,
    expected_version: u64,
    to: ImageGenerationSlotState,
) -> Result<u64> {
    ensure!(
        slot_transition_allowed(from, to),
        "forbidden image generation slot transition"
    );
    let next = expected_version
        .checked_add(1)
        .context("image generation slot version overflow")?;
    ensure!(conn.execute("UPDATE image_generation_slots SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4 AND state=?5 AND version=?6",params![to.as_str(),i64::try_from(next)?,job_id.to_string(),slot_id.to_string(),from.as_str(),i64::try_from(expected_version)?])?==1,"image generation slot transition lost compare-and-set");
    Ok(next)
}

fn execute_basic_image_attempt_transition_conn(
    conn: &Connection,
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    from: ImageGenerationAttemptState,
    expected_version: u64,
    to: ImageGenerationAttemptState,
) -> Result<u64> {
    ensure!(
        attempt_transition_allowed(from, to),
        "forbidden image generation attempt transition"
    );
    let next = expected_version
        .checked_add(1)
        .context("image generation attempt version overflow")?;
    ensure!(conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4 AND attempt_number=?5 AND state=?6 AND version=?7",params![to.as_str(),i64::try_from(next)?,job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),from.as_str(),i64::try_from(expected_version)?])?==1,"image generation attempt transition lost compare-and-set");
    Ok(next)
}

fn execute_queue_all_image_slots_conn(conn: &Connection, job_id: Uuid) -> Result<usize> {
    ensure!(
        slot_transition_allowed(
            ImageGenerationSlotState::Planned,
            ImageGenerationSlotState::Queued
        ),
        "queue slot transition is not canonical"
    );
    conn.execute("UPDATE image_generation_slots SET state='queued',version=version+1 WHERE job_id=?1 AND state='planned' AND version=1",[job_id.to_string()]).map_err(Into::into)
}

fn execute_image_publication_attempt_transition_conn(
    conn: &Connection,
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    expected_version: u64,
) -> Result<u64> {
    ensure!(
        attempt_transition_allowed(
            ImageGenerationAttemptState::ResponseAdopted,
            ImageGenerationAttemptState::Succeeded
        ),
        "publication attempt transition is not canonical"
    );
    let next = expected_version
        .checked_add(1)
        .context("publication attempt version overflow")?;
    ensure!(conn.execute("UPDATE image_generation_attempts SET state='succeeded',version=?1 WHERE job_id=?2 AND slot_id=?3 AND attempt_number=?4 AND state='response_adopted' AND version=?5 AND applied_cancellation_version IS NULL",params![i64::try_from(next)?,job_id.to_string(),slot_id.to_string(),i64::from(attempt_number),i64::try_from(expected_version)?])?==1,"publication attempt lost compare-and-set");
    Ok(next)
}

fn execute_image_publication_slot_transition_conn(
    conn: &Connection,
    job_id: Uuid,
    slot_id: Uuid,
    expected_version: u64,
) -> Result<u64> {
    ensure!(
        slot_transition_allowed(
            ImageGenerationSlotState::ReadyToPublish,
            ImageGenerationSlotState::Published
        ),
        "publication slot transition is not canonical"
    );
    let next = expected_version
        .checked_add(1)
        .context("publication slot version overflow")?;
    ensure!(conn.execute("UPDATE image_generation_slots SET state='published',version=?1,published_disposition='ordinary',published_disposition_generation=?1 WHERE job_id=?2 AND slot_id=?3 AND state='ready_to_publish' AND version=?4 AND applied_cancellation_version IS NULL AND result_after_cancel=0",params![i64::try_from(next)?,job_id.to_string(),slot_id.to_string(),i64::try_from(expected_version)?])?==1,"publication slot lost compare-and-set");
    Ok(next)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationTerminalEventV1 {
    pub event_id: String,
    pub job_id: Uuid,
    pub job_version: u64,
    pub terminal_state: ImageGenerationJobState,
    pub slot_count: u32,
    /// Ordinary published slots (state='published' AND result_after_cancel=0).
    pub published_count: u32,
    pub failed_count: u32,
    pub cancelled_count: u32,
    /// Slots published after a cancellation raced the result
    /// (state='published' AND result_after_cancel=1). Disjoint from
    /// `published_count`; a late-then-published slot is counted here only.
    pub late_published_count: u32,
    /// Slots that stayed quarantined after a late result (state='late_quarantined').
    pub late_quarantined_count: u32,
    /// Slots discarded after a late result (state='discarded').
    pub discarded_count: u32,
    pub emitted_at_unix_ms: i64,
}

impl Db {
    pub fn replay_image_generation_terminal_event_conn(
        conn: &Connection,
        job_id: Uuid,
    ) -> Result<Option<ImageGenerationTerminalEventV1>> {
        conn.query_row(
            "SELECT event_id,job_version,terminal_state,slot_count,published_count,failed_count,cancelled_count,late_published_count,late_quarantined_count,discarded_count,emitted_at_unix_ms FROM image_generation_terminal_events WHERE job_id=?1",
            [job_id.to_string()],
            |row| {
                let state: String = row.get(2)?;
                Ok(ImageGenerationTerminalEventV1 {
                    event_id: row.get(0)?,
                    job_id,
                    job_version: row.get::<_, i64>(1)? as u64,
                    terminal_state: ImageGenerationJobState::parse(&state)
                        .ok_or(rusqlite::Error::InvalidQuery)?,
                    slot_count: row.get::<_, i64>(3)? as u32,
                    published_count: row.get::<_, i64>(4)? as u32,
                    failed_count: row.get::<_, i64>(5)? as u32,
                    cancelled_count: row.get::<_, i64>(6)? as u32,
                    late_published_count: row.get::<_, i64>(7)? as u32,
                    late_quarantined_count: row.get::<_, i64>(8)? as u32,
                    discarded_count: row.get::<_, i64>(9)? as u32,
                    emitted_at_unix_ms: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(Into::into)
    }
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

fn commit_terminal_job_projection_conn(
    conn: &Connection,
    job_id: Uuid,
    emitted_at_unix_ms: i64,
) -> Result<Option<ImageGenerationJobState>> {
    let (current_state, current_version, existing_event): (String, i64, Option<i64>) = conn
        .query_row(
        "SELECT state,version,terminal_event_version FROM image_generation_jobs WHERE job_id=?1",
        [job_id.to_string()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    if let Some(event_version) = existing_event {
        ensure!(
            event_version == current_version,
            "terminal event version differs"
        );
        return Ok(ImageGenerationJobState::parse(&current_state));
    }
    let mut statement = conn.prepare(
        "SELECT state,applied_cancellation_version,result_after_cancel FROM image_generation_slots WHERE job_id=?1 ORDER BY slot_index",
    )?;
    let rows = statement
        .query_map([job_id.to_string()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    let facts = rows
        .iter()
        .map(|(state, cancellation, result)| {
            Ok(ImageGenerationSlotTerminalFact {
                state: ImageGenerationSlotState::parse(state)
                    .context("unknown terminal slot state")?,
                applied_cancellation_version: cancellation.map(|value| value as u64),
                result_after_cancel: *result == 1,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let Some(terminal) = reduce_terminal_job_facts(&facts) else {
        return Ok(None);
    };
    let current = ImageGenerationJobState::parse(&current_state)
        .context("terminal projection current job state is unknown")?;
    ensure!(
        job_transition_allowed(current, terminal),
        "terminal job transition is forbidden"
    );
    let next_version = current_version
        .checked_add(1)
        .context("terminal job version overflow")?;
    // Disjoint partition: each slot lands in exactly one bucket, keyed by state
    // and (for published slots) the result_after_cancel bit. This mirrors the
    // terminal-event insert-guard trigger so the projection is representable
    // without double-counting a late-then-published slot.
    let count_where = |predicate: &dyn Fn(&str, i64) -> bool| -> i64 {
        rows.iter()
            .filter(|(state, _, result)| predicate(state, *result))
            .count() as i64
    };
    let published_count = count_where(&|state, result| state == "published" && result == 0);
    let late_published_count = count_where(&|state, result| state == "published" && result == 1);
    let failed_count = count_where(&|state, _| state == "failed");
    let cancelled_count = count_where(&|state, _| state == "cancelled");
    let late_quarantined_count = count_where(&|state, _| state == "late_quarantined");
    let discarded_count = count_where(&|state, _| state == "discarded");
    let event_id = format!("image-generation-terminal:{job_id}:{next_version}");
    conn.execute(
        "INSERT INTO image_generation_terminal_events(event_id,job_id,job_version,terminal_state,slot_count,published_count,failed_count,cancelled_count,late_published_count,late_quarantined_count,discarded_count,emitted_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
        params![event_id,job_id.to_string(),next_version,terminal.as_str(),i64::try_from(rows.len())?,published_count,failed_count,cancelled_count,late_published_count,late_quarantined_count,discarded_count,emitted_at_unix_ms],
    )?;
    execute_image_job_transition_conn(
        conn,
        job_id,
        current,
        u64::try_from(current_version)?,
        terminal,
        emitted_at_unix_ms,
        ImageJobTransitionContext::TerminalProjection,
    )?;
    Ok(Some(terminal))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationJob<'a> {
    job_id: Uuid,
    plan_digest: &'a str,
    canonical_plan: &'a [u8],
    slot_count: u32,
    max_attempt_count: u32,
    deadline_boot_id: Uuid,
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
                deadline_boot_id: plan.deadline_boot_id,
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
                        "deadlineBootId",
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
                deadline_boot_id: Uuid::parse_str(
                    plan.get("deadlineBootId")
                        .and_then(serde_json::Value::as_str)
                        .ok_or_else(|| anyhow::anyhow!("deadline boot id missing"))?,
                )?,
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
pub struct BeginImageGenerationDownload {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_job_version: u64,
    pub expected_slot_version: u64,
    pub expected_attempt_version: u64,
    pub at_unix_ms: i64,
}
pub struct CommitAcceptedImageResponseFailure<'a> {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_attempt_version: u64,
    pub expected_slot_version: u64,
    pub external_operation_id: Uuid,
    pub expected_journal_version: u64,
    pub safe_reason: &'a str,
    pub at_unix_ms: i64,
}
pub struct ReserveAcceptedResponsePublication<'a> {
    pub publication_operation_id: Uuid,
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub artifact_id: Uuid,
    pub component_id: Uuid,
    pub temporary_name: &'a str,
    pub destination_name: &'a str,
    pub response_digest: &'a str,
    pub at_unix_ms: i64,
}
pub struct CommitImageGenerationValidation {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub expected_slot_version: u64,
    pub at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestImageGenerationCancellation<'a> {
    pub job_id: Uuid,
    pub cancellation_version: u64,
    pub request_operation_id: &'a str,
    pub requested_at_unix_ms: i64,
}

/// Redacted owner identity used to scope session-authorized image-generation job
/// reads and cancellation. It carries ONLY the sealed plan's owner identity
/// (session id + digests), never a raw path, prompt, credential, or cost. It is
/// assembled in `cockpit-core` from the live attached session's
/// `ImageGenerationOwnerContextAuthority` and compared against the persisted plan
/// envelope. A mismatch (or an absent job) is reported as not-found, so a job
/// owned by another session is indistinguishable from one that does not exist
/// (existence-hiding).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGenerationJobOwnerScope<'a> {
    pub owner_session_id: Uuid,
    pub owner_principal_digest: &'a str,
    pub project_identity_digest: &'a str,
    pub config_generation: u64,
}

/// Session-safe, redacted status of an image-generation job the current session
/// owns. `NotFound` is returned when the job does not exist OR belongs to another
/// session — the two are indistinguishable to the caller (existence-hiding).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnedImageGenerationJobStatus {
    Status(ImageGenerationJobSafeStatus),
    NotFound,
}

/// The only image-generation job fields ever surfaced to the model: the durable
/// lifecycle state, the job version, the plan's slot count, whether a
/// cancellation was requested, and — once terminal — the safe disjoint slot
/// counts. It NEVER carries a prompt, path, cost, destination, credential, or
/// artifact identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationJobSafeStatus {
    pub state: ImageGenerationJobState,
    pub job_version: u64,
    pub slot_count: u32,
    pub cancellation_requested: bool,
    pub terminal: Option<ImageGenerationJobSafeTerminalCounts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGenerationJobSafeTerminalCounts {
    pub terminal_state: ImageGenerationJobState,
    pub published_count: u32,
    pub failed_count: u32,
    pub cancelled_count: u32,
    pub late_published_count: u32,
    pub late_quarantined_count: u32,
    pub discarded_count: u32,
}

/// Owner-checked cancellation request. `cancellation_version` and
/// `request_operation_id` are only consumed on the first cancellation of an owned
/// job (a repeated request is reported idempotently without touching the CAS).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OwnedImageGenerationCancellationRequest<'a> {
    pub job_id: Uuid,
    pub scope: ImageGenerationJobOwnerScope<'a>,
    pub cancellation_version: u64,
    pub request_operation_id: &'a str,
    pub requested_at_unix_ms: i64,
}

/// Idempotent outcome of an owner-checked cancellation. `NotFound` hides both a
/// missing job and one owned by another session; `AlreadyTerminal` means the
/// owned job has no cancellable slots left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnedImageGenerationCancellation {
    CancellationRequested,
    NotFound,
    AlreadyTerminal,
}

pub struct PrepareImageGenerationDispatch<'a> {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub expected_job_version: u64,
    pub expected_slot_version: u64,
    pub expected_attempt_version: u64,
    pub spend_reservation_id: &'a str,
    pub spend_attempt_id: &'a str,
    pub media_reservation_id: &'a str,
    pub media_plan_digest: &'a str,
    pub expected_media_reservation_version: u64,
    pub journal: &'a PrepareExternalOperation,
    pub at_unix_ms: i64,
    pub deadline_observation: DeadlineObservationV1,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
    /// Dispatch-time destination/health proof produced by a successful
    /// revalidation at the injected clock's now. It is bound onto the attempt in
    /// the same statement that transitions it to `prepared`; there is no code
    /// path that reaches `prepared`/`dispatching` without it.
    pub dispatch_proof: DispatchConnectionProofV1<'a>,
}

/// The durable dispatch proof bound onto an attempt at prepare time. Carries only
/// opaque destination identifiers and the observed connection facts -- never a
/// credential value or any prompt text (a credential is represented, elsewhere,
/// solely by its identity digest, and none of that flows into this row).
#[derive(Debug, Clone, Copy)]
pub struct DispatchConnectionProofV1<'a> {
    pub endpoint_id: &'a str,
    pub config_generation: u64,
    pub refresh_epoch: u64,
    pub connected_ip: &'a str,
    pub location_class: &'a str,
    pub hops_digest: &'a str,
}

/// A daemon-owned observation of the monotonic clock. A value from another
/// boot can never be compared with the plan's captured monotonic deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineObservationV1 {
    daemon_boot_id: Uuid,
    now_monotonic_ms: u64,
}

impl DeadlineObservationV1 {
    pub fn new(daemon_boot_id: Uuid, now_monotonic_ms: u64) -> Result<Self> {
        ensure!(
            !daemon_boot_id.is_nil(),
            "deadline observation boot id is nil"
        );
        Ok(Self {
            daemon_boot_id,
            now_monotonic_ms,
        })
    }

    fn is_before(self, deadline_boot_id: Uuid, deadline_monotonic_ms: i64) -> Result<bool> {
        Ok(self.daemon_boot_id == deadline_boot_id
            && i64::try_from(self.now_monotonic_ms)? < deadline_monotonic_ms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationDeadlineExpiryDisposition {
    CleanupRequired,
    CancellationRequested,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageGenerationDeadlineExpiryFact {
    pub job_id: Uuid,
    pub disposition: ImageGenerationDeadlineExpiryDisposition,
    pub cancellation_version: u64,
    pub cancellation_operation_id: String,
    pub cleanup_operation_id: String,
    pub media_reservation_id: String,
    pub media_reservation_version: u64,
    pub spend_reservation_id: String,
    pub spend_reservation_version: u64,
}

pub struct ClaimImageGenerationDispatch {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
}

pub struct ImageGenerationDispatchCandidate {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub job_version: u64,
    pub slot_version: u64,
    pub attempt_version: u64,
    pub canonical_plan: Vec<u8>,
    pub plan_digest: String,
    pub canonical_media_plan: Vec<u8>,
    pub media_plan_digest: String,
    pub next_claim_generation: u64,
}

struct ImageGenerationDispatchCandidateRow {
    job_id: String,
    slot_id: String,
    attempt_number: i64,
    job_version: i64,
    slot_version: i64,
    attempt_version: i64,
    canonical_plan: Vec<u8>,
    plan_digest: String,
    canonical_media_plan: Vec<u8>,
    media_plan_digest: String,
    next_claim_generation: i64,
}

impl Db {
    pub fn scan_image_generation_dispatch_candidates_conn(
        conn: &Connection,
        deadline_observation: DeadlineObservationV1,
        limit: u32,
    ) -> Result<Vec<ImageGenerationDispatchCandidate>> {
        ensure!((1..=64).contains(&limit), "invalid scheduler scan limit");
        let database_now = database_now_unix_ms(conn)?;
        let mut statement=conn.prepare("SELECT j.job_id,s.slot_id,a.attempt_number,j.version,s.version,a.version,p.canonical_plan,p.plan_digest,m.canonical_media_plan,m.media_plan_digest,COALESCE((SELECT MAX(claim_generation)+1 FROM image_generation_scheduler_claims old WHERE old.job_id=s.job_id AND old.slot_id=s.slot_id AND old.attempt_number=a.attempt_number),1) FROM image_generation_jobs j JOIN image_generation_slots s ON s.job_id=j.job_id JOIN image_generation_attempts a ON a.job_id=s.job_id AND a.slot_id=s.slot_id JOIN image_generation_attempt_activation_facts f ON f.job_id=a.job_id AND f.slot_id=a.slot_id AND f.attempt_number=a.attempt_number JOIN image_generation_plans p ON p.job_id=j.job_id JOIN image_generation_attempt_media_snapshots m ON m.job_id=a.job_id AND m.slot_id=a.slot_id AND m.attempt_number=a.attempt_number WHERE j.state='queued' AND s.state='queued' AND a.state='planned' AND p.deadline_boot_id=?2 AND p.operation_deadline_monotonic_ms>?3 AND NOT EXISTS(SELECT 1 FROM image_generation_scheduler_claims c WHERE c.job_id=s.job_id AND c.slot_id=s.slot_id AND c.attempt_number=a.attempt_number AND c.expires_at_unix_ms>?1 AND NOT EXISTS(SELECT 1 FROM image_generation_scheduler_claim_consumptions x WHERE x.job_id=c.job_id AND x.slot_id=c.slot_id AND x.attempt_number=c.attempt_number AND x.claim_generation=c.claim_generation)) AND NOT EXISTS(SELECT 1 FROM image_generation_cancellation_facts x WHERE x.job_id=j.job_id) ORDER BY j.created_at_unix_ms,j.job_id,s.slot_index,a.attempt_number LIMIT ?4")?;
        let rows = statement.query_map(
            params![
                database_now,
                deadline_observation.daemon_boot_id.to_string(),
                i64::try_from(deadline_observation.now_monotonic_ms)?,
                i64::from(limit)
            ],
            |row| {
                Ok(ImageGenerationDispatchCandidateRow {
                    job_id: row.get(0)?,
                    slot_id: row.get(1)?,
                    attempt_number: row.get(2)?,
                    job_version: row.get(3)?,
                    slot_version: row.get(4)?,
                    attempt_version: row.get(5)?,
                    canonical_plan: row.get(6)?,
                    plan_digest: row.get(7)?,
                    canonical_media_plan: row.get(8)?,
                    media_plan_digest: row.get(9)?,
                    next_claim_generation: row.get(10)?,
                })
            },
        )?;
        rows.map(|row| {
            let row = row?;
            ImageGenerationPlanV1::from_canonical(&row.canonical_plan, &row.plan_digest)?;
            Ok(ImageGenerationDispatchCandidate {
                job_id: Uuid::parse_str(&row.job_id)?,
                slot_id: Uuid::parse_str(&row.slot_id)?,
                attempt_number: u32::try_from(row.attempt_number)?,
                job_version: u64::try_from(row.job_version)?,
                slot_version: u64::try_from(row.slot_version)?,
                attempt_version: u64::try_from(row.attempt_version)?,
                canonical_plan: row.canonical_plan,
                plan_digest: row.plan_digest,
                canonical_media_plan: row.canonical_media_plan,
                media_plan_digest: row.media_plan_digest,
                next_claim_generation: u64::try_from(row.next_claim_generation)?,
            })
        })
        .collect()
    }

    pub fn claim_image_generation_dispatch_conn(
        conn: &Connection,
        input: &ClaimImageGenerationDispatch,
    ) -> Result<()> {
        claim_image_generation_dispatch_at_conn(conn, input, database_now_unix_ms(conn)?)
    }
}

fn claim_image_generation_dispatch_at_conn(
    conn: &Connection,
    input: &ClaimImageGenerationDispatch,
    now: i64,
) -> Result<()> {
    atomic_conn(conn, "image_generation_scheduler_claim", || {
        let expires = now
            .checked_add(60_000)
            .context("scheduler claim deadline overflow")?;
        ensure!(
            input.attempt_number > 0 && input.claim_generation > 0,
            "invalid scheduler claim"
        );
        ensure!(conn.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_jobs j JOIN image_generation_slots s ON s.job_id=j.job_id JOIN image_generation_attempts a ON a.job_id=s.job_id AND a.slot_id=s.slot_id JOIN image_generation_attempt_activation_facts f ON f.job_id=a.job_id AND f.slot_id=a.slot_id AND f.attempt_number=a.attempt_number WHERE j.job_id=?1 AND s.slot_id=?2 AND a.attempt_number=?3 AND j.state='queued' AND s.state='queued' AND a.state='planned' AND NOT EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=j.job_id))",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],|row|row.get::<_,bool>(0))?,"image generation dispatch is not claimable");
        let inserted=conn.execute("INSERT OR IGNORE INTO image_generation_scheduler_claims(job_id,slot_id,attempt_number,worker_boot_id,claim_generation,claimed_at_unix_ms,expires_at_unix_ms) SELECT ?1,?2,?3,?4,?5,?6,?7 WHERE (?5=1 AND NOT EXISTS(SELECT 1 FROM image_generation_scheduler_claims c WHERE c.job_id=?1 AND c.slot_id=?2 AND c.attempt_number=?3)) OR (?5>1 AND EXISTS(SELECT 1 FROM image_generation_scheduler_claims c WHERE c.job_id=?1 AND c.slot_id=?2 AND c.attempt_number=?3 AND c.claim_generation=?5-1 AND (c.expires_at_unix_ms<=?6 OR EXISTS(SELECT 1 FROM image_generation_scheduler_claim_consumptions x WHERE x.job_id=c.job_id AND x.slot_id=c.slot_id AND x.attempt_number=c.attempt_number AND x.claim_generation=c.claim_generation)) AND c.claim_generation=(SELECT MAX(m.claim_generation) FROM image_generation_scheduler_claims m WHERE m.job_id=?1 AND m.slot_id=?2 AND m.attempt_number=?3)))",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),input.worker_boot_id.to_string(),i64::try_from(input.claim_generation)?,now,expires])?;
        ensure!(
            inserted == 1,
            "image generation dispatch is already claimed or reclaim generation differs"
        );
        Ok(())
    })
}

pub struct ImageGenerationQueueAuthority {
    job_id: Uuid,
    job_version: u64,
}

pub struct ImageGenerationMediaPlanSnapshot<'a> {
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub canonical_bytes: &'a [u8],
    pub digest: &'a str,
}

fn validate_attempt_media_snapshot(
    attempt: &AttemptPlanV1,
    media: &ImageGenerationMediaPlanSnapshot<'_>,
) -> Result<()> {
    ensure!(
        !media.canonical_bytes.is_empty()
            && media.canonical_bytes.len() <= 65_536
            && media.digest.len() == 64
            && hex_lower(&Sha256::digest(media.canonical_bytes)) == media.digest,
        "image generation media snapshot is invalid"
    );
    let value: serde_json::Value = serde_json::from_slice(media.canonical_bytes)?;
    let dimension = value
        .get("dimension")
        .and_then(serde_json::Value::as_str)
        .context("image generation media snapshot dimension is absent")?;
    let requested = value
        .get("requested")
        .and_then(serde_json::Value::as_u64)
        .context("image generation media snapshot requested maximum is absent")?;
    ensure!(
        attempt.resource_maximum.len() == 1
            && attempt.resource_maximum[0].resource_kind == dimension
            && attempt.resource_maximum[0].units == requested,
        "image generation media snapshot differs from attempt resource maximum"
    );
    Ok(())
}

pub struct PreparedImageGenerationDispatch {
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    operation: ExternalJournalRecord,
    attempt_version: u64,
    spend_reservation_id: String,
    spend_attempt_id: String,
    provider_request_identity: String,
    media_reservation_id: String,
    media_reservation_version: u64,
    slot_version: u64,
    job_version: u64,
}

pub struct DispatchingImageGenerationAttempt {
    operation: ExternalJournalRecord,
    job_id: Uuid,
    slot_id: Uuid,
    attempt_number: u32,
    attempt_version: u64,
    spend_reservation_id: String,
    spend_attempt_id: String,
    provider_request_identity: String,
    media_reservation_id: String,
    media_reservation_version: u64,
}

pub struct ImageGenerationProviderHandoffEvidence<'a> {
    pub outcome: ImageSpendDispatchEvidence,
    pub bytes: &'a [u8],
}

pub enum ImageGenerationHandoffFinishDisposition {
    Settled,
    Replay,
    RetryQueued {
        next_attempt_number: u32,
        canonical_media_plan: Vec<u8>,
        media_plan_digest: String,
    },
}
pub enum ImageGenerationReconciliationDisposition {
    Settled {
        external_operation_id: Uuid,
        media_reservation_id: String,
        media_reservation_version: u64,
        outcome: ImageGenerationReconciliationOutcome,
    },
    RetryQueued {
        external_operation_id: Uuid,
        media_reservation_id: String,
        media_reservation_version: u64,
        sealed_media_reservation_id: String,
        current_media_plan: Vec<u8>,
        current_media_plan_digest: String,
        next_media_plan: Vec<u8>,
        next_media_plan_digest: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredImageGenerationProviderHandoffEvidence {
    pub external_operation_id: Uuid,
    pub outcome: ImageSpendDispatchEvidence,
    pub bytes: Vec<u8>,
    pub digest: String,
    pub recorded_at_unix_ms: i64,
}

impl DispatchingImageGenerationAttempt {
    pub fn operation(&self) -> &ExternalJournalRecord {
        &self.operation
    }
    pub fn identity(&self) -> (Uuid, Uuid, u32, u64) {
        (
            self.job_id,
            self.slot_id,
            self.attempt_number,
            self.attempt_version,
        )
    }
    pub fn media_reservation(&self) -> (&str, u64) {
        (&self.media_reservation_id, self.media_reservation_version)
    }
    pub fn provider_dispatch_identity(&self) -> (&str, &str) {
        (&self.provider_request_identity, &self.spend_attempt_id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationReconciliationOutcome {
    AuthoritativeNonacceptance,
    AuthoritativeAccepted,
    AuthoritativeFailure,
}
pub struct ImageGenerationReconciliationObservation<'a> {
    pub provider_request_identity: &'a str,
    pub provider_idempotency_identity: &'a str,
    pub external_operation_id: Uuid,
    pub journal_version: u64,
    pub journal_payload_digest: &'a str,
    pub evidence_bytes: &'a [u8],
    pub outcome: ImageGenerationReconciliationOutcome,
    pub now_unix_ms: i64,
}
pub struct SealedImageGenerationRecoveryAuthority {
    job_id: Uuid,
    job_state: ImageGenerationJobState,
    job_version: u64,
    slot_id: Uuid,
    attempt_number: u32,
    attempt_version: u64,
    slot_version: u64,
    external_operation_id: Uuid,
    journal_version: u64,
    provider_request_identity: String,
    provider_idempotency_identity: String,
    journal_payload_digest: String,
    claim_worker_boot_id: Option<Uuid>,
    claim_generation: Option<u64>,
}
pub struct VerifiedImageGenerationReconciliationProof {
    authority: SealedImageGenerationRecoveryAuthority,
    evidence_digest: String,
    outcome: ImageGenerationReconciliationOutcome,
    now_unix_ms: i64,
}
pub struct ClaimImageGenerationReconciliation {
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub attempt_number: u32,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
    pub now_unix_ms: i64,
}
impl SealedImageGenerationRecoveryAuthority {
    pub fn adapter_identity(&self) -> (Uuid, Uuid, u32, Uuid, u64, &str, &str, &str) {
        (
            self.job_id,
            self.slot_id,
            self.attempt_number,
            self.external_operation_id,
            self.journal_version,
            &self.provider_request_identity,
            &self.provider_idempotency_identity,
            &self.journal_payload_digest,
        )
    }
}
impl SealedImageGenerationRecoveryAuthority {
    pub fn verify(
        self,
        observation: ImageGenerationReconciliationObservation<'_>,
    ) -> Result<VerifiedImageGenerationReconciliationProof> {
        ensure!(
            observation.provider_request_identity == self.provider_request_identity
                && observation.provider_idempotency_identity == self.provider_idempotency_identity
                && observation.external_operation_id == self.external_operation_id
                && observation.journal_version == self.journal_version
                && observation.journal_payload_digest == self.journal_payload_digest,
            "reconciliation observation does not match sealed recovery authority"
        );
        let outcome_prefix: &[u8] = match observation.outcome {
            ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance => b"nonacceptance\0",
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted => b"accepted\0",
            ImageGenerationReconciliationOutcome::AuthoritativeFailure => {
                b"postacceptance_failure\0"
            }
        };
        ensure!(
            observation.evidence_bytes.starts_with(outcome_prefix),
            "reconciliation evidence does not bind its closed outcome"
        );
        Ok(VerifiedImageGenerationReconciliationProof {
            authority: self,
            evidence_digest: reconciliation_evidence_digest(observation.evidence_bytes)?,
            outcome: observation.outcome,
            now_unix_ms: observation.now_unix_ms,
        })
    }
}

impl Db {
    pub fn replay_image_generation_handoff_evidence_conn(
        conn: &Connection,
        job_id: Uuid,
        slot_id: Uuid,
        attempt_number: u32,
    ) -> Result<StoredImageGenerationProviderHandoffEvidence> {
        let(operation,outcome,bytes,digest,recorded):(String,String,Vec<u8>,String,i64)=conn.query_row("SELECT external_operation_id,outcome,evidence,evidence_digest,recorded_at_unix_ms FROM image_generation_handoff_evidence WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)))?;
        ensure!(
            !bytes.is_empty()
                && bytes.len() <= 65_536
                && hex_lower(&Sha256::digest(&bytes)) == digest,
            "stored image generation handoff evidence is invalid"
        );
        let outcome = match outcome.as_str() {
            "accepted" => ImageSpendDispatchEvidence::Accepted,
            "definitively_rejected" => ImageSpendDispatchEvidence::DefinitivelyRejected,
            "submission_unknown" => ImageSpendDispatchEvidence::SubmissionUnknown,
            _ => anyhow::bail!("stored image generation handoff outcome is invalid"),
        };
        Ok(StoredImageGenerationProviderHandoffEvidence {
            external_operation_id: Uuid::parse_str(&operation)?,
            outcome,
            bytes,
            digest,
            recorded_at_unix_ms: recorded,
        })
    }
    pub fn image_generation_queue_authority_conn(
        conn: &Connection,
        job_id: Uuid,
    ) -> Result<ImageGenerationQueueAuthority> {
        let (canonical, digest, version, slots): (Vec<u8>, String, i64, i64) = conn.query_row("SELECT p.canonical_plan,p.plan_digest,j.version,(SELECT count(*) FROM image_generation_slots s WHERE s.job_id=j.job_id AND s.state='planned' AND s.version=1) FROM image_generation_jobs j JOIN image_generation_plans p ON p.job_id=j.job_id WHERE j.job_id=?1 AND j.state='created' AND j.version=1 AND NOT EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=j.job_id)",[job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).context("image generation queue authority is unavailable")?;
        let plan = ImageGenerationPlanV1::from_canonical(&canonical, &digest)?;
        let sealed_slots = plan.targets.iter().try_fold(0_i64, |sum, target| {
            sum.checked_add(i64::try_from(target.slots.len())?)
                .context("image generation slot count overflow")
        })?;
        ensure!(
            plan.job_id == job_id && slots == sealed_slots,
            "image generation queue graph differs from sealed plan"
        );
        Ok(ImageGenerationQueueAuthority {
            job_id,
            job_version: u64::try_from(version)?,
        })
    }

    pub fn queue_image_generation_job_conn(
        conn: &Connection,
        authority: ImageGenerationQueueAuthority,
        media: &[ImageGenerationMediaPlanSnapshot<'_>],
        at_unix_ms: i64,
    ) -> Result<()> {
        ensure!(
            job_transition_allowed(
                ImageGenerationJobState::Created,
                ImageGenerationJobState::Validating
            ) && job_transition_allowed(
                ImageGenerationJobState::Validating,
                ImageGenerationJobState::Queued
            ),
            "image generation queue job transitions are not canonical"
        );
        ensure!(
            slot_transition_allowed(
                ImageGenerationSlotState::Planned,
                ImageGenerationSlotState::Queued
            ),
            "image generation queue slot transition is not canonical"
        );
        atomic_conn(conn, "image_generation_queue", || {
            let (canonical_plan, plan_digest): (Vec<u8>, String) = conn.query_row(
                "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
                [authority.job_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            let plan = ImageGenerationPlanV1::from_canonical(&canonical_plan, &plan_digest)?;
            let attempts = plan
                .targets
                .iter()
                .flat_map(|target| target.slots.iter())
                .flat_map(|slot| {
                    slot.attempts
                        .iter()
                        .map(move |attempt| (slot.slot_id, attempt))
                })
                .collect::<Vec<_>>();
            ensure!(
                !attempts.is_empty() && media.len() == attempts.len(),
                "image generation media snapshot graph differs"
            );
            for ((slot_id, attempt), snapshot) in attempts.into_iter().zip(media) {
                ensure!(
                    snapshot.slot_id == slot_id
                        && snapshot.attempt_number == attempt.attempt_number,
                    "image generation media snapshot order or identity differs"
                );
                validate_attempt_media_snapshot(attempt, snapshot)?;
                conn.execute(
                    "INSERT INTO image_generation_attempt_media_snapshots(job_id,slot_id,attempt_number,plan_digest,canonical_media_plan,media_plan_digest) VALUES(?1,?2,?3,?4,?5,?6)",
                    params![authority.job_id.to_string(),slot_id.to_string(),i64::from(attempt.attempt_number),plan_digest,snapshot.canonical_bytes,snapshot.digest],
                )?;
            }
            let validating_version = execute_image_job_transition_conn(
                conn,
                authority.job_id,
                ImageGenerationJobState::Created,
                authority.job_version,
                ImageGenerationJobState::Validating,
                at_unix_ms,
                ImageJobTransitionContext::Ordinary,
            )?;
            execute_image_job_transition_conn(
                conn,
                authority.job_id,
                ImageGenerationJobState::Validating,
                validating_version,
                ImageGenerationJobState::Queued,
                at_unix_ms,
                ImageJobTransitionContext::Ordinary,
            )?;
            let changed = execute_queue_all_image_slots_conn(conn, authority.job_id)?;
            let expected: i64 = conn.query_row(
                "SELECT slot_count FROM image_generation_plans WHERE job_id=?1",
                [authority.job_id.to_string()],
                |row| row.get(0),
            )?;
            ensure!(
                i64::try_from(changed)? == expected,
                "image generation queue slot graph changed"
            );
            let activated=conn.execute("INSERT INTO image_generation_attempt_activation_facts(job_id,slot_id,attempt_number,activation_reason,prior_attempt_number,activated_at_unix_ms) SELECT job_id,slot_id,1,'initial',NULL,?1 FROM image_generation_slots WHERE job_id=?2",params![at_unix_ms,authority.job_id.to_string()])?;
            ensure!(
                activated == changed,
                "image generation initial attempt activation differs"
            );
            Ok(())
        })
    }

    pub fn prepare_image_generation_dispatch_conn(
        conn: &Connection,
        input: &PrepareImageGenerationDispatch<'_>,
    ) -> Result<PreparedImageGenerationDispatch> {
        ensure!(
            attempt_transition_allowed(
                ImageGenerationAttemptState::Planned,
                ImageGenerationAttemptState::Preparing
            ) && attempt_transition_allowed(
                ImageGenerationAttemptState::Preparing,
                ImageGenerationAttemptState::Prepared
            ),
            "image generation preparation attempt transitions are not canonical"
        );
        ensure!(
            slot_transition_allowed(
                ImageGenerationSlotState::Queued,
                ImageGenerationSlotState::Dispatching
            ),
            "image generation dispatch slot transition is not canonical"
        );
        ensure!(
            job_transition_allowed(
                ImageGenerationJobState::Queued,
                ImageGenerationJobState::Dispatching
            ),
            "image generation dispatch job transition is not canonical"
        );
        atomic_conn(conn, "image_generation_prepare_dispatch", || {
            let database_now = database_now_unix_ms(conn)?;
            ensure!(conn.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_scheduler_claims c WHERE c.job_id=?1 AND c.slot_id=?2 AND c.attempt_number=?3 AND c.worker_boot_id=?4 AND c.claim_generation=?5 AND c.expires_at_unix_ms>?6 AND NOT EXISTS(SELECT 1 FROM image_generation_scheduler_claim_consumptions x WHERE x.job_id=c.job_id AND x.slot_id=c.slot_id AND x.attempt_number=c.attempt_number AND x.claim_generation=c.claim_generation))",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),input.worker_boot_id.to_string(),i64::try_from(input.claim_generation)?,database_now],|row|row.get::<_,bool>(0))?,"image generation scheduler claim is absent, consumed, or stale");
            let projection = conn
                .query_row(
                    "SELECT j.state,s.state,a.state,p.plan_digest,p.deadline_boot_id,p.operation_deadline_monotonic_ms,a.provider_idempotency_identity FROM image_generation_jobs j JOIN image_generation_slots s ON s.job_id=j.job_id JOIN image_generation_attempts a ON a.job_id=s.job_id AND a.slot_id=s.slot_id JOIN image_generation_plans p ON p.job_id=j.job_id WHERE j.job_id=?1 AND s.slot_id=?2 AND a.attempt_number=?3 AND j.version=?4 AND s.version=?5 AND a.version=?6 AND NOT EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=j.job_id)",
                    params![input.job_id.to_string(), input.slot_id.to_string(), i64::from(input.attempt_number), i64::try_from(input.expected_job_version)?, i64::try_from(input.expected_slot_version)?, i64::try_from(input.expected_attempt_version)?],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, String>(3)?, row.get::<_, String>(4)?, row.get::<_, i64>(5)?, row.get::<_, String>(6)?)),
                )
                .optional()?
                .context("image generation dispatch authority is unavailable")?;
            ensure!(
                projection.0 == "queued" && projection.1 == "queued" && projection.2 == "planned",
                "image generation dispatch is not queued"
            );
            ensure!(
                input
                    .deadline_observation
                    .is_before(Uuid::parse_str(&projection.4)?, projection.5)?,
                "image generation operation deadline expired"
            );
            ensure!(
                projection.6 == input.spend_attempt_id,
                "image generation spend attempt identity differs"
            );
            ensure!(conn.execute("INSERT INTO image_generation_scheduler_claim_consumptions(job_id,slot_id,attempt_number,claim_generation,consumed_at_unix_ms) VALUES(?1,?2,?3,?4,?5)",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.claim_generation)?,input.at_unix_ms])?==1,"image generation scheduler claim was not consumed");
            let provider_request_identity: String = conn.query_row(
                "SELECT provider_request_identity FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",
                params![input.job_id.to_string(), input.slot_id.to_string(), i64::from(input.attempt_number)],
                |row| row.get(0),
            )?;
            let spend_plan: String = conn.query_row("SELECT plan_digest FROM image_spend_reservations WHERE reservation_id=?1 AND state='reserved'", [input.spend_reservation_id], |row| row.get(0)).context("image generation spend reservation is unavailable")?;
            ensure!(
                spend_plan == projection.3,
                "image generation spend reservation plan differs"
            );
            let operation = prepare_reserved_image_spend_dispatch_conn(
                conn,
                input.spend_reservation_id,
                input.spend_attempt_id,
                input.journal,
                input.at_unix_ms,
            )?;
            let canonical: Vec<u8> = conn.query_row(
                "SELECT canonical_plan FROM image_generation_plans WHERE job_id=?1",
                [input.job_id.to_string()],
                |row| row.get(0),
            )?;
            let plan = ImageGenerationPlanV1::from_canonical(&canonical, &projection.3)?;
            ensure!(
                plan.central_resources.iter().any(|resource| {
                    input.media_reservation_id
                        == image_generation_attempt_media_reservation_id(
                            &resource.reservation_identity,
                            input.slot_id,
                            input.attempt_number,
                        )
                }),
                "image generation media reservation differs from sealed plan"
            );
            let attempt = plan
                .targets
                .iter()
                .flat_map(|target| &target.slots)
                .find(|slot| slot.slot_id == input.slot_id)
                .and_then(|slot| {
                    slot.attempts
                        .iter()
                        .find(|attempt| attempt.attempt_number == input.attempt_number)
                })
                .context("image generation dispatch attempt differs from sealed plan")?;
            let snapshot: (Vec<u8>, String) = conn.query_row("SELECT canonical_media_plan,media_plan_digest FROM image_generation_attempt_media_snapshots WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],|row|Ok((row.get(0)?,row.get(1)?)))?;
            ensure!(
                snapshot.1 == input.media_plan_digest,
                "image generation dispatch media snapshot differs"
            );
            validate_attempt_media_snapshot(
                attempt,
                &ImageGenerationMediaPlanSnapshot {
                    slot_id: input.slot_id,
                    attempt_number: input.attempt_number,
                    canonical_bytes: &snapshot.0,
                    digest: &snapshot.1,
                },
            )?;
            ensure!(conn.execute("UPDATE image_generation_attempts SET state='preparing',version=version+1,external_operation_id=?1,observed_journal_version=?2 WHERE job_id=?3 AND slot_id=?4 AND attempt_number=?5 AND state='planned' AND version=?6",params![operation.operation_id.to_string(),operation.version,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version)?])?==1,"image generation attempt preparation lost compare-and-set");
            ensure!(conn.execute("UPDATE image_generation_attempts SET state='prepared',version=version+1,dispatch_proof_endpoint_id=?5,dispatch_proof_config_generation=?6,dispatch_proof_refresh_epoch=?7,dispatch_proof_connected_ip=?8,dispatch_proof_location_class=?9,dispatch_proof_hops_digest=?10 WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND state='preparing' AND version=?4",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version+1)?,input.dispatch_proof.endpoint_id,i64::try_from(input.dispatch_proof.config_generation)?,i64::try_from(input.dispatch_proof.refresh_epoch)?,input.dispatch_proof.connected_ip,input.dispatch_proof.location_class,input.dispatch_proof.hops_digest])?==1,"image generation attempt preparation lost compare-and-set");
            execute_basic_image_slot_transition_conn(
                conn,
                input.job_id,
                input.slot_id,
                ImageGenerationSlotState::Queued,
                input.expected_slot_version,
                ImageGenerationSlotState::Dispatching,
            )?;
            execute_image_job_transition_conn(
                conn,
                input.job_id,
                ImageGenerationJobState::Queued,
                input.expected_job_version,
                ImageGenerationJobState::Dispatching,
                input.at_unix_ms,
                ImageJobTransitionContext::Ordinary,
            )?;
            Ok(PreparedImageGenerationDispatch {
                job_id: input.job_id,
                slot_id: input.slot_id,
                attempt_number: input.attempt_number,
                operation,
                attempt_version: input.expected_attempt_version + 2,
                slot_version: input.expected_slot_version + 1,
                job_version: input.expected_job_version + 1,
                spend_reservation_id: input.spend_reservation_id.into(),
                spend_attempt_id: input.spend_attempt_id.into(),
                provider_request_identity,
                media_reservation_id: input.media_reservation_id.into(),
                media_reservation_version: input.expected_media_reservation_version,
            })
        })
    }

    pub fn begin_image_generation_handoff_conn(
        conn: &Connection,
        prepared: PreparedImageGenerationDispatch,
        at_unix_ms: i64,
        deadline_observation: DeadlineObservationV1,
    ) -> Result<DispatchingImageGenerationAttempt> {
        ensure!(
            attempt_transition_allowed(
                ImageGenerationAttemptState::Prepared,
                ImageGenerationAttemptState::Dispatching
            ),
            "image generation handoff transition is not canonical"
        );
        atomic_conn(conn, "image_generation_begin_handoff", || {
            let (deadline_boot_id,deadline):(String,i64) = conn.query_row("SELECT p.deadline_boot_id,p.operation_deadline_monotonic_ms FROM image_generation_plans p JOIN image_generation_jobs j ON j.job_id=p.job_id JOIN image_generation_slots s ON s.job_id=j.job_id WHERE j.job_id=?1 AND j.state='dispatching' AND j.version=?2 AND s.slot_id=?3 AND s.state='dispatching' AND s.version=?4 AND NOT EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=j.job_id)",params![prepared.job_id.to_string(),i64::try_from(prepared.job_version)?,prepared.slot_id.to_string(),i64::try_from(prepared.slot_version)?],|row|Ok((row.get(0)?,row.get(1)?))).context("image generation handoff authority is unavailable")?;
            ensure!(
                deadline_observation.is_before(Uuid::parse_str(&deadline_boot_id)?, deadline)?,
                "image generation operation deadline expired"
            );
            let operation = match transition_external_operation_conn(
                conn,
                prepared.operation.operation_id,
                prepared.operation.version,
                ExternalJournalState::Dispatching,
                at_unix_ms,
            )? {
                ExternalTransitionOutcome::Committed(record) => record,
                _ => anyhow::bail!("image generation journal handoff lost compare-and-set"),
            };
            ensure!(conn.execute("UPDATE image_generation_attempts SET state='dispatching',version=version+1,observed_journal_version=observed_journal_version+1 WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND state='prepared' AND version=?4 AND external_operation_id=?5",params![prepared.job_id.to_string(),prepared.slot_id.to_string(),i64::from(prepared.attempt_number),i64::try_from(prepared.attempt_version)?,prepared.operation.operation_id.to_string()])?==1,"image generation attempt handoff lost compare-and-set");
            Ok(DispatchingImageGenerationAttempt {
                operation,
                job_id: prepared.job_id,
                slot_id: prepared.slot_id,
                attempt_number: prepared.attempt_number,
                attempt_version: prepared.attempt_version + 1,
                spend_reservation_id: prepared.spend_reservation_id,
                spend_attempt_id: prepared.spend_attempt_id,
                provider_request_identity: prepared.provider_request_identity,
                media_reservation_id: prepared.media_reservation_id,
                media_reservation_version: prepared
                    .media_reservation_version
                    .checked_add(1)
                    .context("image generation media reservation version overflow")?,
            })
        })
    }

    pub fn finish_image_generation_handoff_conn(
        conn: &Connection,
        dispatching: DispatchingImageGenerationAttempt,
        evidence: ImageGenerationProviderHandoffEvidence<'_>,
        at_unix_ms: i64,
    ) -> Result<ImageGenerationHandoffFinishDisposition> {
        atomic_conn(conn, "image_generation_finish_handoff", || {
            ensure!(
                !evidence.bytes.is_empty() && evidence.bytes.len() <= 65_536,
                "image generation handoff evidence is outside its bound"
            );
            let evidence_digest = hex_lower(&Sha256::digest(evidence.bytes));
            let outcome_name = match evidence.outcome {
                ImageSpendDispatchEvidence::Accepted => "accepted",
                ImageSpendDispatchEvidence::DefinitivelyRejected => "definitively_rejected",
                ImageSpendDispatchEvidence::SubmissionUnknown => "submission_unknown",
            };
            if let Some((stored_outcome,stored_digest))=conn.query_row("SELECT outcome,evidence_digest FROM image_generation_handoff_evidence WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND external_operation_id=?4",params![dispatching.job_id.to_string(),dispatching.slot_id.to_string(),i64::from(dispatching.attempt_number),dispatching.operation.operation_id.to_string()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?))).optional()? {
                ensure!(stored_outcome==outcome_name&&stored_digest==evidence_digest,"image generation handoff replay differs");
                return Ok(ImageGenerationHandoffFinishDisposition::Replay);
            }
            let outcome = finish_reserved_image_spend_dispatch_conn(
                conn,
                &dispatching.spend_reservation_id,
                &dispatching.spend_attempt_id,
                dispatching.operation.operation_id,
                dispatching.operation.version,
                evidence.outcome,
                at_unix_ms,
            )?;
            ensure!(conn.execute("INSERT INTO image_generation_handoff_evidence(job_id,slot_id,attempt_number,external_operation_id,outcome,evidence,evidence_digest,recorded_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![dispatching.job_id.to_string(),dispatching.slot_id.to_string(),i64::from(dispatching.attempt_number),dispatching.operation.operation_id.to_string(),outcome_name,evidence.bytes,evidence_digest,at_unix_ms])?==1,"image generation handoff evidence was not recorded");
            let next_attempt_number = dispatching
                .attempt_number
                .checked_add(1)
                .context("image generation attempt number overflow")?;
            let retry = if evidence.outcome == ImageSpendDispatchEvidence::DefinitivelyRejected {
                conn.query_row("SELECT a.attempt_number,m.canonical_media_plan,m.media_plan_digest FROM image_generation_attempts a JOIN image_generation_attempt_media_snapshots m ON m.job_id=a.job_id AND m.slot_id=a.slot_id AND m.attempt_number=a.attempt_number JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state='planned' AND a.attempt_number<=s.max_attempt_count AND NOT EXISTS(SELECT 1 FROM image_generation_cancellation_facts c WHERE c.job_id=a.job_id)",params![dispatching.job_id.to_string(),dispatching.slot_id.to_string(),i64::from(next_attempt_number)],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,Vec<u8>>(1)?,row.get::<_,String>(2)?))).optional()?
            } else {
                None
            };
            let (attempt, slot, job) = match evidence.outcome {
                ImageSpendDispatchEvidence::Accepted => ("accepted", "running", "running"),
                ImageSpendDispatchEvidence::DefinitivelyRejected if retry.is_some() => {
                    ("rejected_not_accepted", "queued", "queued")
                }
                ImageSpendDispatchEvidence::DefinitivelyRejected => {
                    ("rejected_not_accepted", "failed", "failed")
                }
                ImageSpendDispatchEvidence::SubmissionUnknown => (
                    "submission_unknown",
                    "submission_unknown",
                    "submission_unknown",
                ),
            };
            let attempt_state = ImageGenerationAttemptState::parse(attempt)
                .context("handoff produced an unknown attempt state")?;
            ensure!(
                attempt_transition_allowed(ImageGenerationAttemptState::Dispatching, attempt_state),
                "image generation handoff attempt transition is not canonical"
            );
            let slot_state = ImageGenerationSlotState::parse(slot)
                .context("handoff produced an unknown slot state")?;
            let job_state = ImageGenerationJobState::parse(job)
                .context("handoff produced an unknown job state")?;
            if retry.is_none() {
                ensure!(
                    slot_transition_allowed(ImageGenerationSlotState::Dispatching, slot_state),
                    "image generation handoff slot transition is not canonical"
                );
                ensure!(
                    job_transition_allowed(ImageGenerationJobState::Dispatching, job_state),
                    "image generation handoff job transition is not canonical"
                );
            }
            ensure!(
                outcome.record().state.as_str()
                    == match evidence.outcome {
                        ImageSpendDispatchEvidence::Accepted => "accepted",
                        ImageSpendDispatchEvidence::DefinitivelyRejected => "rejected",
                        ImageSpendDispatchEvidence::SubmissionUnknown => "submission_unknown",
                    },
                "image generation handoff evidence differs"
            );
            ensure!(conn.execute("UPDATE image_generation_attempts SET state=?1,version=version+1,observed_journal_version=?2 WHERE job_id=?3 AND slot_id=?4 AND attempt_number=?5 AND state='dispatching' AND version=?6 AND external_operation_id=?7",params![attempt,outcome.record().version,dispatching.job_id.to_string(),dispatching.slot_id.to_string(),i64::from(dispatching.attempt_number),i64::try_from(dispatching.attempt_version)?,dispatching.operation.operation_id.to_string()])?==1,"image generation handoff attempt compare-and-set lost");
            if let Some((next_attempt, _, _)) = &retry {
                ensure!(
                    IMAGE_JOB_CONDITIONAL_EDGES.contains(&("dispatching", "queued"))
                        && IMAGE_SLOT_CONDITIONAL_EDGES.contains(&("dispatching", "queued")),
                    "authoritative retry edge contract is absent"
                );
                ensure!(conn.execute("INSERT INTO image_generation_attempt_activation_facts(job_id,slot_id,attempt_number,activation_reason,prior_attempt_number,activated_at_unix_ms) VALUES(?1,?2,?3,'authoritative_retry',?4,?5)",params![dispatching.job_id.to_string(),dispatching.slot_id.to_string(),next_attempt,i64::from(dispatching.attempt_number),at_unix_ms])?==1,"image generation retry activation was not recorded");
            }
            ensure!(conn.execute("UPDATE image_generation_slots SET state=?1,version=version+1,failure_reason=CASE WHEN ?1='failed' THEN 'definitively_rejected' ELSE NULL END WHERE job_id=?2 AND slot_id=?3 AND state='dispatching'",params![slot,dispatching.job_id.to_string(),dispatching.slot_id.to_string()])?==1,"image generation handoff slot compare-and-set lost");
            if job == "failed" {
                commit_terminal_job_projection_conn(conn, dispatching.job_id, at_unix_ms)?;
            } else {
                execute_image_job_transition_conn(
                    conn,
                    dispatching.job_id,
                    ImageGenerationJobState::Dispatching,
                    dispatching.job_version,
                    job_state,
                    at_unix_ms,
                    if retry.is_some() {
                        ImageJobTransitionContext::AuthoritativeRetry
                    } else {
                        ImageJobTransitionContext::Ordinary
                    },
                )?;
            }
            Ok(match retry {
                Some((attempt, canonical_media_plan, media_plan_digest)) => {
                    ImageGenerationHandoffFinishDisposition::RetryQueued {
                        next_attempt_number: u32::try_from(attempt)?,
                        canonical_media_plan,
                        media_plan_digest,
                    }
                }
                None => ImageGenerationHandoffFinishDisposition::Settled,
            })
        })
    }

    fn image_generation_recovery_authority_conn(
        conn: &Connection,
        job_id: Uuid,
        slot_id: Uuid,
        attempt_number: u32,
    ) -> Result<SealedImageGenerationRecoveryAuthority> {
        conn.query_row("SELECT a.version,s.version,a.external_operation_id,j.version,a.provider_request_identity,a.provider_idempotency_identity,j.payload_digest,g.state,g.version FROM image_generation_attempts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_jobs g ON g.job_id=a.job_id JOIN external_journal_operations j ON j.operation_id=a.external_operation_id WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state IN ('reconciling','cancellation_requested') AND s.state IN ('submission_unknown','cancellation_requested') AND g.state IN ('submission_unknown','cancellation_requested') AND j.state IN ('reconciling','cancellation_requested')",params![job_id.to_string(),slot_id.to_string(),i64::from(attempt_number)],|row|Ok(SealedImageGenerationRecoveryAuthority{job_id,job_state:ImageGenerationJobState::parse(&row.get::<_,String>(7)?).ok_or(rusqlite::Error::InvalidQuery)?,job_version:u64::try_from(row.get::<_,i64>(8)?).map_err(|_|rusqlite::Error::InvalidQuery)?,slot_id,attempt_number,attempt_version:u64::try_from(row.get::<_,i64>(0)?).map_err(|_|rusqlite::Error::InvalidQuery)?,slot_version:u64::try_from(row.get::<_,i64>(1)?).map_err(|_|rusqlite::Error::InvalidQuery)?,external_operation_id:Uuid::parse_str(&row.get::<_,String>(2)?).map_err(|_|rusqlite::Error::InvalidQuery)?,journal_version:u64::try_from(row.get::<_,i64>(3)?).map_err(|_|rusqlite::Error::InvalidQuery)?,provider_request_identity:row.get(4)?,provider_idempotency_identity:row.get(5)?,journal_payload_digest:row.get(6)?,claim_worker_boot_id:None,claim_generation:None})).context("image generation recovery authority unavailable")
    }
    pub fn claim_image_generation_reconciliation_conn(
        conn: &Connection,
        input: &ClaimImageGenerationReconciliation,
    ) -> Result<SealedImageGenerationRecoveryAuthority> {
        ensure!(
            attempt_transition_allowed(
                ImageGenerationAttemptState::SubmissionUnknown,
                ImageGenerationAttemptState::Reconciling
            ),
            "image generation reconciliation claim transition is not canonical"
        );
        atomic_conn(conn, "image_generation_reconciliation_claim", || {
            ensure!(
                !input.worker_boot_id.is_nil() && input.claim_generation > 0,
                "invalid reconciliation claim"
            );
            let expires = input
                .now_unix_ms
                .checked_add(60_000)
                .context("reconciliation claim overflow")?;
            let prior:Option<(i64,i64)>=conn.query_row("SELECT claim_generation,expires_at_unix_ms FROM image_generation_reconciliation_claims WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 ORDER BY claim_generation DESC LIMIT 1",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],|row|Ok((row.get(0)?,row.get(1)?))).optional()?;
            ensure!(
                match prior {
                    None => input.claim_generation == 1,
                    Some((generation, expiry)) =>
                        i64::try_from(input.claim_generation)? == generation + 1
                            && expiry <= input.now_unix_ms,
                },
                "reconciliation claim generation is unavailable"
            );
            conn.execute("INSERT INTO image_generation_reconciliation_claims(job_id,slot_id,attempt_number,claim_generation,worker_boot_id,claimed_at_unix_ms,expires_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.claim_generation)?,input.worker_boot_id.to_string(),input.now_unix_ms,expires])?;
            let (operation,version,attempt_version,state):(String,i64,i64,String)=conn.query_row("SELECT external_operation_id,observed_journal_version,version,state FROM image_generation_attempts WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND state IN ('submission_unknown','reconciling','cancellation_requested') AND EXISTS(SELECT 1 FROM image_generation_handoff_evidence h WHERE h.job_id=image_generation_attempts.job_id AND h.slot_id=image_generation_attempts.slot_id AND h.attempt_number=image_generation_attempts.attempt_number AND h.outcome='submission_unknown')",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?))).context("reconcilable attempt is unavailable")?;
            if state == "submission_unknown" {
                let operation_id = Uuid::parse_str(&operation)?;
                let record = match transition_external_operation_conn(
                    conn,
                    operation_id,
                    version,
                    ExternalJournalState::Reconciling,
                    input.now_unix_ms,
                )? {
                    ExternalTransitionOutcome::Committed(record) => record,
                    _ => anyhow::bail!("reconciliation claim lost journal compare-and-set"),
                };
                ensure!(conn.execute("UPDATE image_generation_attempts SET state='reconciling',version=version+1,observed_journal_version=?1 WHERE job_id=?2 AND slot_id=?3 AND attempt_number=?4 AND state='submission_unknown' AND version=?5",params![record.version,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),attempt_version])?==1,"reconciliation claim lost attempt compare-and-set");
            }
            let mut authority = Self::image_generation_recovery_authority_conn(
                conn,
                input.job_id,
                input.slot_id,
                input.attempt_number,
            )?;
            authority.claim_worker_boot_id = Some(input.worker_boot_id);
            authority.claim_generation = Some(input.claim_generation);
            Ok(authority)
        })
    }
    pub fn reconcile_image_generation_attempt_conn(
        conn: &Connection,
        proof: &VerifiedImageGenerationReconciliationProof,
    ) -> Result<ImageGenerationReconciliationDisposition> {
        atomic_conn(conn, "image_generation_reconcile", || {
            Self::reconcile_image_generation_attempt_inner(conn, proof)
        })
    }
    fn reconcile_image_generation_attempt_inner(
        conn: &Connection,
        proof: &VerifiedImageGenerationReconciliationProof,
    ) -> Result<ImageGenerationReconciliationDisposition> {
        let input = &proof.authority;
        if let (Some(worker_boot_id), Some(claim_generation)) =
            (input.claim_worker_boot_id, input.claim_generation)
        {
            ensure!(conn.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_reconciliation_claims c WHERE c.job_id=?1 AND c.slot_id=?2 AND c.attempt_number=?3 AND c.claim_generation=?4 AND c.worker_boot_id=?5 AND c.expires_at_unix_ms>?6 AND NOT EXISTS(SELECT 1 FROM image_generation_reconciliation_claims newer WHERE newer.job_id=c.job_id AND newer.slot_id=c.slot_id AND newer.attempt_number=c.attempt_number AND newer.claim_generation>c.claim_generation) AND NOT EXISTS(SELECT 1 FROM image_generation_reconciliation_claim_completions d WHERE d.job_id=c.job_id AND d.slot_id=c.slot_id AND d.attempt_number=c.attempt_number AND d.claim_generation=c.claim_generation))",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(claim_generation)?,worker_boot_id.to_string(),proof.now_unix_ms],|row|row.get::<_,i64>(0))?==1,"reconciliation proof lost its live claim fence");
        }
        let evidence_digest = &proof.evidence_digest;
        let media_authority = if input.claim_generation.is_some() {
            Some({
                let (canonical_plan, plan_digest): (Vec<u8>, String) = conn.query_row(
                    "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
                    [input.job_id.to_string()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let plan = ImageGenerationPlanV1::from_canonical(&canonical_plan, &plan_digest)?;
                let sealed_media_reservation_id = plan
                    .central_resources
                    .first()
                    .context("image generation central media reservation is absent")?
                    .reservation_identity
                    .clone();
                let media_reservation_id = image_generation_attempt_media_reservation_id(
                    &sealed_media_reservation_id,
                    input.slot_id,
                    input.attempt_number,
                );
                let media_reservation_version = u64::try_from(conn.query_row::<i64, _, _>(
                    "SELECT version FROM media_reservations WHERE reservation_id=?1",
                    [&media_reservation_id],
                    |row| row.get(0),
                )?)?;
                let current_media: (Vec<u8>, String) = conn.query_row(
            "SELECT canonical_media_plan,media_plan_digest FROM image_generation_attempt_media_snapshots WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3",
            params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],
            |row| Ok((row.get(0)?,row.get(1)?)),
        )?;
                (
                    media_reservation_id,
                    media_reservation_version,
                    current_media,
                    sealed_media_reservation_id,
                )
            })
        } else {
            None
        };
        let (
            media_reservation_id,
            media_reservation_version,
            current_media,
            sealed_media_reservation_id,
        ) = media_authority
            .unwrap_or_else(|| (String::new(), 0, (Vec::new(), String::new()), String::new()));
        let (attempt_state, slot_state, slot_version, job_state, job_version, cancellation): (String, String, i64, String, i64, Option<i64>) = conn.query_row(
            "SELECT a.state,s.state,s.version,j.state,j.version,a.applied_cancellation_version FROM image_generation_attempts a JOIN image_generation_slots s USING(job_id,slot_id) JOIN image_generation_jobs j USING(job_id) WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3",
            params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number)],
            |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)),
        )?;
        let attempt_state = ImageGenerationAttemptState::parse(&attempt_state)
            .context("reconciliation attempt state is unknown")?;
        let slot_state = ImageGenerationSlotState::parse(&slot_state)
            .context("reconciliation slot state is unknown")?;
        let job_state = ImageGenerationJobState::parse(&job_state)
            .context("reconciliation job state is unknown")?;
        ensure!(
            slot_version == i64::try_from(input.slot_version)?,
            "reconciliation slot version is stale"
        );
        ensure!(
            job_state == input.job_state && job_version == i64::try_from(input.job_version)?,
            "reconciliation job authority differs from the sealed proof"
        );
        let (journal_next, attempt_next, outcome) = match (proof.outcome, cancellation.is_some()) {
            (ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance, true) => (
                ExternalJournalState::Cancelled,
                ImageGenerationAttemptState::Cancelled,
                "authoritative_nonacceptance",
            ),
            (ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance, false) => (
                ExternalJournalState::Rejected,
                ImageGenerationAttemptState::RejectedNotAccepted,
                "authoritative_nonacceptance",
            ),
            (ImageGenerationReconciliationOutcome::AuthoritativeAccepted, _) => (
                ExternalJournalState::Accepted,
                ImageGenerationAttemptState::Accepted,
                "authoritative_accepted",
            ),
            (ImageGenerationReconciliationOutcome::AuthoritativeFailure, _) => (
                ExternalJournalState::Failed,
                ImageGenerationAttemptState::FailedAfterAcceptance,
                "authoritative_failure",
            ),
        };
        ensure!(
            attempt_transition_allowed(attempt_state, attempt_next),
            "reconciliation attempt transition is not canonical"
        );
        let next_attempt_number = input
            .attempt_number
            .checked_add(1)
            .context("image generation attempt number overflow")?;
        let retry = if proof.outcome
            == ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance
            && cancellation.is_none()
        {
            conn.query_row("SELECT m.canonical_media_plan,m.media_plan_digest FROM image_generation_attempts a JOIN image_generation_attempt_media_snapshots m USING(job_id,slot_id,attempt_number) JOIN image_generation_slots s USING(job_id,slot_id) WHERE a.job_id=?1 AND a.slot_id=?2 AND a.attempt_number=?3 AND a.state='planned' AND a.attempt_number<=s.max_attempt_count",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(next_attempt_number)],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get::<_,String>(1)?))).optional()?
        } else {
            None
        };
        let slot_next = if retry.is_some() {
            ImageGenerationSlotState::Queued
        } else if matches!(
            proof.outcome,
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted
        ) {
            if cancellation.is_some() {
                ImageGenerationSlotState::CancellationRequested
            } else {
                ImageGenerationSlotState::Running
            }
        } else if cancellation.is_some()
            && matches!(
                proof.outcome,
                ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance
            )
        {
            ImageGenerationSlotState::Cancelled
        } else {
            ImageGenerationSlotState::Failed
        };
        if retry.is_some() {
            ensure!(
                IMAGE_JOB_CONDITIONAL_EDGES
                    .contains(&(job_state.as_str(), ImageGenerationJobState::Queued.as_str()))
                    && IMAGE_SLOT_CONDITIONAL_EDGES
                        .contains(&(slot_state.as_str(), slot_next.as_str())),
                "reconciled retry edge contract is absent"
            );
        } else if !(matches!(
            proof.outcome,
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted
        ) && cancellation.is_some())
        {
            ensure!(
                slot_transition_allowed(slot_state, slot_next),
                "reconciliation slot transition is not canonical"
            );
        } else {
            ensure!(
                slot_state == ImageGenerationSlotState::CancellationRequested,
                "accepted cancellation reconciliation requires the persisted cancellation-requested slot"
            );
            ensure!(
                job_state == input.job_state && job_version == i64::try_from(input.job_version)?,
                "accepted cancellation reconciliation changed sealed job authority"
            );
        }
        if matches!(
            proof.outcome,
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted
        ) && cancellation.is_none()
        {
            ensure!(
                job_transition_allowed(job_state, ImageGenerationJobState::Running),
                "reconciliation job transition is not canonical"
            );
        }
        match transition_external_operation_conn(
            conn,
            input.external_operation_id,
            i64::try_from(input.journal_version)?,
            journal_next,
            proof.now_unix_ms,
        )? {
            ExternalTransitionOutcome::Committed(_) => {}
            _ => anyhow::bail!("reconciliation lost journal compare-and-set"),
        };
        if input.claim_generation.is_some() {
            settle_reconciled_image_spend_dispatch_conn(
                conn,
                input.external_operation_id,
                proof.now_unix_ms,
            )?;
        }
        let journal_version = input
            .journal_version
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("journal version overflow"))?;
        let evidence_inserted=conn.execute("INSERT INTO image_generation_reconciliation_evidence(job_id,slot_id,attempt_number,journal_version,evidence_digest,provider_request_identity,provider_idempotency_identity,journal_payload_digest,outcome) SELECT a.job_id,a.slot_id,a.attempt_number,?1,?2,a.provider_request_identity,a.provider_idempotency_identity,j.payload_digest,?3 FROM image_generation_attempts a JOIN external_journal_operations j ON j.operation_id=a.external_operation_id WHERE a.job_id=?4 AND a.slot_id=?5 AND a.attempt_number=?6 AND a.external_operation_id=?7",params![i64::try_from(journal_version)?,evidence_digest,outcome,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),input.external_operation_id.to_string()])?;
        ensure!(
            evidence_inserted == 1,
            "reconciliation evidence identity is not bound"
        );
        let attempt_changed=conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,observed_journal_version=?3,nonacceptance_evidence_digest=CASE WHEN ?4='authoritative_nonacceptance' THEN ?5 ELSE NULL END WHERE job_id=?6 AND slot_id=?7 AND attempt_number=?8 AND state=?9 AND version=?10 AND external_operation_id=?11",params![attempt_next.as_str(),i64::try_from(input.attempt_version+1)?,i64::try_from(journal_version)?,outcome,evidence_digest,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),attempt_state.as_str(),i64::try_from(input.attempt_version)?,input.external_operation_id.to_string()])?;
        ensure!(
            attempt_changed == 1,
            "reconciliation lost attempt compare-and-set"
        );
        if retry.is_some() {
            ensure!(conn.execute("INSERT INTO image_generation_attempt_activation_facts(job_id,slot_id,attempt_number,activation_reason,prior_attempt_number,activated_at_unix_ms) VALUES(?1,?2,?3,'authoritative_retry',?4,?5)",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(next_attempt_number),i64::from(input.attempt_number),proof.now_unix_ms])?==1,"reconciled retry activation was not recorded");
        }
        if matches!(
            proof.outcome,
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted
        ) && cancellation.is_some()
        {
            ensure!(
                slot_state == ImageGenerationSlotState::CancellationRequested
                    && slot_version == i64::try_from(input.slot_version)?,
                "accepted cancellation reconciliation lost its no-op slot authority"
            );
        } else {
            let slot_changed=conn.execute("UPDATE image_generation_slots SET state=?1,version=?2,failure_reason=CASE WHEN ?1='failed' THEN ?3 ELSE NULL END WHERE job_id=?4 AND slot_id=?5 AND state=?6 AND version=?7",params![slot_next.as_str(),i64::try_from(input.slot_version+1)?,outcome,input.job_id.to_string(),input.slot_id.to_string(),slot_state.as_str(),i64::try_from(input.slot_version)?])?;
            ensure!(
                slot_changed == 1,
                "reconciliation lost slot compare-and-set"
            );
        }
        if retry.is_some() {
            execute_image_job_transition_conn(
                conn,
                input.job_id,
                input.job_state,
                input.job_version,
                ImageGenerationJobState::Queued,
                proof.now_unix_ms,
                ImageJobTransitionContext::AuthoritativeRetry,
            )?;
        } else if matches!(
            proof.outcome,
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted
        ) {
            if cancellation.is_none() {
                execute_image_job_transition_conn(
                    conn,
                    input.job_id,
                    input.job_state,
                    input.job_version,
                    ImageGenerationJobState::Running,
                    proof.now_unix_ms,
                    ImageJobTransitionContext::Ordinary,
                )?;
            }
            return Ok(ImageGenerationReconciliationDisposition::Settled {
                external_operation_id: input.external_operation_id,
                media_reservation_id,
                media_reservation_version,
                outcome: proof.outcome,
            });
        }
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
            ensure!(
                commit_terminal_job_projection_conn(conn, input.job_id, proof.now_unix_ms)?
                    == Some(terminal),
                "reconciliation terminal projection differs"
            );
        }
        Ok(match retry {
            Some((next_media_plan, next_media_plan_digest)) => {
                ImageGenerationReconciliationDisposition::RetryQueued {
                    external_operation_id: input.external_operation_id,
                    media_reservation_id,
                    media_reservation_version,
                    sealed_media_reservation_id,
                    current_media_plan: current_media.0,
                    current_media_plan_digest: current_media.1,
                    next_media_plan,
                    next_media_plan_digest,
                }
            }
            None => ImageGenerationReconciliationDisposition::Settled {
                external_operation_id: input.external_operation_id,
                media_reservation_id,
                media_reservation_version,
                outcome: proof.outcome,
            },
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
            "INSERT INTO image_generation_plans(job_id,schema_version,plan_digest,canonical_plan,slot_count,max_attempt_count,deadline_boot_id,enqueue_started_monotonic_ms,operation_deadline_monotonic_ms) VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8)",
            params![input.job_id.to_string(), input.plan_digest, input.canonical_plan, slot_count, max_attempt_count, input.deadline_boot_id.to_string(), enqueue, deadline],
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

    pub fn begin_image_generation_download_conn(
        conn: &Connection,
        input: &BeginImageGenerationDownload,
    ) -> Result<()> {
        ensure!(
            attempt_transition_allowed(
                ImageGenerationAttemptState::Accepted,
                ImageGenerationAttemptState::Downloading
            ),
            "image generation download attempt transition is not canonical"
        );
        ensure!(
            slot_transition_allowed(
                ImageGenerationSlotState::Running,
                ImageGenerationSlotState::Downloading
            ),
            "image generation download slot transition is not canonical"
        );
        ensure!(
            job_transition_allowed(
                ImageGenerationJobState::Running,
                ImageGenerationJobState::Downloading
            ),
            "image generation download job transition is not canonical"
        );
        atomic_conn(conn, "image_generation_begin_download", || {
            execute_basic_image_attempt_transition_conn(
                conn,
                input.job_id,
                input.slot_id,
                input.attempt_number,
                ImageGenerationAttemptState::Accepted,
                input.expected_attempt_version,
                ImageGenerationAttemptState::Downloading,
            )?;
            execute_basic_image_slot_transition_conn(
                conn,
                input.job_id,
                input.slot_id,
                ImageGenerationSlotState::Running,
                input.expected_slot_version,
                ImageGenerationSlotState::Downloading,
            )?;
            execute_image_job_transition_conn(
                conn,
                input.job_id,
                ImageGenerationJobState::Running,
                input.expected_job_version,
                ImageGenerationJobState::Downloading,
                input.at_unix_ms,
                ImageJobTransitionContext::Ordinary,
            )?;
            Ok(())
        })
    }

    pub fn commit_accepted_image_response_failure_conn(
        conn: &Connection,
        input: &CommitAcceptedImageResponseFailure<'_>,
    ) -> Result<()> {
        for from in [
            ImageGenerationAttemptState::Accepted,
            ImageGenerationAttemptState::Downloading,
            ImageGenerationAttemptState::CancellationRequested,
        ] {
            ensure!(
                attempt_transition_allowed(
                    from,
                    ImageGenerationAttemptState::FailedAfterAcceptance
                ),
                "accepted response failure attempt transition is not canonical"
            );
        }
        for from in [
            ImageGenerationSlotState::Running,
            ImageGenerationSlotState::Downloading,
            ImageGenerationSlotState::CancellationRequested,
        ] {
            ensure!(
                slot_transition_allowed(from, ImageGenerationSlotState::Failed),
                "accepted response failure slot transition is not canonical"
            );
        }
        atomic_conn(conn, "image_generation_accepted_response_failure", || {
            let bound: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_response_fetch_outcomes WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND outcome='definitive_failure' AND safe_reason=?4) OR EXISTS(SELECT 1 FROM image_generation_response_reconciliations WHERE job_id=?1 AND slot_id=?2 AND attempt_number=?3 AND outcome='definitive_failure' AND safe_reason=?4)",params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),input.safe_reason],|row|row.get(0))?;
            ensure!(bound, "accepted response failure evidence is absent");
            match transition_external_operation_conn(
                conn,
                input.external_operation_id,
                i64::try_from(input.expected_journal_version)?,
                ExternalJournalState::Failed,
                input.at_unix_ms,
            )? {
                ExternalTransitionOutcome::Committed(_) => {}
                _ => anyhow::bail!("accepted response failure lost journal compare-and-set"),
            }
            ensure!(conn.execute("UPDATE image_generation_attempts SET state='failed_after_acceptance',version=version+1,observed_journal_version=?1 WHERE job_id=?2 AND slot_id=?3 AND attempt_number=?4 AND state IN ('accepted','downloading','cancellation_requested') AND version=?5 AND external_operation_id=?6",params![i64::try_from(input.expected_journal_version+1)?,input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_attempt_version)?,input.external_operation_id.to_string()])?==1,"accepted response failure lost attempt compare-and-set");
            ensure!(conn.execute("UPDATE image_generation_slots SET state='failed',version=version+1,failure_reason=?1 WHERE job_id=?2 AND slot_id=?3 AND state IN ('running','downloading','cancellation_requested') AND version=?4",params![input.safe_reason,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?])?==1,"accepted response failure lost slot compare-and-set");
            commit_terminal_job_projection_conn(conn, input.job_id, input.at_unix_ms)?;
            Ok(())
        })
    }

    pub fn reserve_accepted_response_publication_conn(
        conn: &Connection,
        input: &ReserveAcceptedResponsePublication<'_>,
    ) -> Result<()> {
        ensure_digest(input.response_digest, "response publication digest")?;
        ensure!(
            !input.temporary_name.is_empty() && !input.destination_name.is_empty(),
            "response publication names are empty"
        );
        conn.execute("INSERT INTO image_generation_response_publication_intents(publication_operation_id,job_id,slot_id,attempt_number,artifact_id,component_id,temporary_name,destination_name,response_digest,state,version,created_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',1,?10)",params![input.publication_operation_id.to_string(),input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),input.artifact_id.to_string(),input.component_id.to_string(),input.temporary_name,input.destination_name,input.response_digest,input.at_unix_ms])?;
        Ok(())
    }

    pub fn finish_accepted_response_publication_conn(
        conn: &Connection,
        operation_id: Uuid,
        held_evidence_json: &str,
        at_unix_ms: i64,
    ) -> Result<()> {
        ensure!(
            !held_evidence_json.is_empty(),
            "response publication evidence is empty"
        );
        ensure!(conn.execute("UPDATE image_generation_response_publication_intents SET state='applied',version=version+1,held_evidence_json=?1,decided_at_unix_ms=?2 WHERE publication_operation_id=?3 AND state='pending' AND version=1",params![held_evidence_json,at_unix_ms,operation_id.to_string()])?==1,"response publication intent compare-and-set lost");
        Ok(())
    }

    pub fn block_accepted_response_publication_conn(
        conn: &Connection,
        operation_id: Uuid,
        recovery_evidence_json: &str,
        failure_evidence_digest: &str,
        at_unix_ms: i64,
    ) -> Result<()> {
        ensure_digest(
            failure_evidence_digest,
            "response publication failure evidence",
        )?;
        ensure!(
            !recovery_evidence_json.is_empty(),
            "response publication recovery evidence is empty"
        );
        ensure!(conn.execute("UPDATE image_generation_response_publication_intents SET state='security_blocked',version=version+1,recovery_evidence_json=?1,failure_evidence_digest=?2,decided_at_unix_ms=?3 WHERE publication_operation_id=?4 AND state='pending' AND version=1",params![recovery_evidence_json,failure_evidence_digest,at_unix_ms,operation_id.to_string()])?==1,"response publication intent compare-and-set lost");
        Ok(())
    }

    pub fn commit_image_generation_validation_conn(
        conn: &Connection,
        input: &CommitImageGenerationValidation,
    ) -> Result<ImageGenerationSlotState> {
        atomic_conn(conn, "image_generation_validate_output", || {
            let after_cancel:bool=conn.query_row("SELECT result_after_cancel=1 AND applied_cancellation_version IS NOT NULL FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2 AND state='validating' AND version=?3",params![input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?],|row|row.get(0)).context("image generation validation authority is unavailable")?;
            let next = if after_cancel {
                ImageGenerationSlotState::LateQuarantined
            } else {
                ImageGenerationSlotState::ReadyToPublish
            };
            ensure!(
                slot_transition_allowed(ImageGenerationSlotState::Validating, next),
                "image generation validation transition is not canonical"
            );
            execute_basic_image_slot_transition_conn(
                conn,
                input.job_id,
                input.slot_id,
                ImageGenerationSlotState::Validating,
                input.expected_slot_version,
                next,
            )?;
            if after_cancel {
                commit_terminal_job_projection_conn(conn, input.job_id, input.at_unix_ms)?;
            }
            Ok(next)
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
        let attempt_sources: &[ImageGenerationAttemptState] = if cancellation.is_some() {
            &[
                ImageGenerationAttemptState::Accepted,
                ImageGenerationAttemptState::Downloading,
                ImageGenerationAttemptState::CancellationRequested,
            ]
        } else {
            &[
                ImageGenerationAttemptState::Accepted,
                ImageGenerationAttemptState::Downloading,
            ]
        };
        for &from in attempt_sources {
            ensure!(
                attempt_transition_allowed(from, attempt_next),
                "image generation response adoption attempt transition is not canonical"
            );
        }
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
        ensure!(
            slot_transition_allowed(ImageGenerationSlotState::Downloading, slot_next),
            "image generation response adoption slot transition is not canonical"
        );
        if cancellation.is_some() {
            ensure!(
                slot_transition_allowed(
                    ImageGenerationSlotState::CancellationRequested,
                    ImageGenerationSlotState::Downloading
                ),
                "image generation cancelled response transition is not canonical"
            );
        }
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
        ensure!(
            attempt_transition_allowed(
                ImageGenerationAttemptState::ResponseAdopted,
                ImageGenerationAttemptState::Succeeded
            ),
            "image generation publication attempt transition is not canonical"
        );
        ensure!(
            slot_transition_allowed(
                ImageGenerationSlotState::ReadyToPublish,
                ImageGenerationSlotState::Published
            ),
            "image generation publication slot transition is not canonical"
        );
        conn.execute(
            "INSERT INTO image_generation_publication_right_facts(job_id,slot_id,attempt_number,slot_version,artifact_generation,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6)",
            params![input.job_id.to_string(),input.slot_id.to_string(),i64::from(input.attempt_number),i64::try_from(input.expected_slot_version)?,i64::try_from(input.artifact_generation)?,input.now_unix_ms],
        )?;
        execute_image_publication_attempt_transition_conn(
            conn,
            input.job_id,
            input.slot_id,
            input.attempt_number,
            input.expected_attempt_version,
        )?;
        execute_image_publication_slot_transition_conn(
            conn,
            input.job_id,
            input.slot_id,
            input.expected_slot_version,
        )?;
        commit_terminal_job_projection_conn(conn, input.job_id, input.now_unix_ms)?;
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

    /// Session-scoped ownership predicate for an image-generation job. Returns
    /// `Ok(true)` only when the job exists AND the sealed plan envelope's owner
    /// identity matches `scope` in every field; `Ok(false)` when the job is
    /// absent OR owned by another session (existence-hiding). It reads only the
    /// persisted plan envelope and opens no artifact or content.
    fn image_generation_job_owner_matches_conn(
        conn: &Connection,
        job_id: Uuid,
        scope: &ImageGenerationJobOwnerScope<'_>,
    ) -> Result<bool> {
        let stored: Option<(Vec<u8>, String)> = conn
            .query_row(
                "SELECT canonical_plan,plan_digest FROM image_generation_plans WHERE job_id=?1",
                [job_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let Some((canonical, plan_digest)) = stored else {
            return Ok(false);
        };
        // A foreign job whose sealed plan fails to decode must be reported as a
        // non-match (existence-hiding), never propagated as an error that would
        // distinguish "exists but malformed" from "not found".
        let Ok(plan) = ImageGenerationPlanV1::from_canonical(&canonical, &plan_digest) else {
            return Ok(false);
        };
        Ok(plan.owner_session_id == scope.owner_session_id
            && plan.owner_principal_digest == scope.owner_principal_digest
            && plan.project_identity_digest == scope.project_identity_digest
            && plan.config_generation == scope.config_generation)
    }

    /// Return the redacted, session-safe status of an image-generation job the
    /// current session owns. It first enforces ownership (existence-hiding on a
    /// mismatch or an absent job), then reads only the durable lifecycle state,
    /// version, plan slot count, cancellation flag, and — once terminal — the
    /// safe disjoint slot counts. It NEVER reveals a prompt, path, cost,
    /// destination, credential, or artifact identity, and opens no content.
    pub fn read_owned_image_generation_job_status_conn(
        conn: &Connection,
        job_id: Uuid,
        scope: &ImageGenerationJobOwnerScope<'_>,
    ) -> Result<OwnedImageGenerationJobStatus> {
        if !Self::image_generation_job_owner_matches_conn(conn, job_id, scope)? {
            return Ok(OwnedImageGenerationJobStatus::NotFound);
        }
        let (state_text, job_version, slot_count): (String, i64, i64) = conn.query_row(
            "SELECT j.state,j.version,p.slot_count FROM image_generation_jobs j JOIN image_generation_plans p ON p.job_id=j.job_id WHERE j.job_id=?1",
            [job_id.to_string()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        let state = ImageGenerationJobState::parse(&state_text)
            .context("image generation job state is unknown")?;
        let cancellation_requested: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM image_generation_cancellation_facts WHERE job_id=?1)",
            [job_id.to_string()],
            |row| row.get(0),
        )?;
        let terminal =
            Self::replay_image_generation_terminal_event_conn(conn, job_id)?.map(|event| {
                ImageGenerationJobSafeTerminalCounts {
                    terminal_state: event.terminal_state,
                    published_count: event.published_count,
                    failed_count: event.failed_count,
                    cancelled_count: event.cancelled_count,
                    late_published_count: event.late_published_count,
                    late_quarantined_count: event.late_quarantined_count,
                    discarded_count: event.discarded_count,
                }
            });
        Ok(OwnedImageGenerationJobStatus::Status(
            ImageGenerationJobSafeStatus {
                state,
                job_version: u64::try_from(job_version)?,
                slot_count: u32::try_from(slot_count)?,
                cancellation_requested,
                terminal,
            },
        ))
    }

    /// Owner-checked, idempotent cancellation of an image-generation job the
    /// current session owns. It enforces ownership first (existence-hiding on a
    /// mismatch or an absent job), reports an already-recorded cancellation for
    /// the owned job idempotently, reports `AlreadyTerminal` when no cancellable
    /// slots remain, and otherwise routes through the existing
    /// [`Self::request_image_generation_cancellation_conn`] CAS. It surfaces no
    /// prompt, path, cost, or another session's data.
    pub fn request_owned_image_generation_cancellation_conn(
        conn: &Connection,
        input: &OwnedImageGenerationCancellationRequest<'_>,
    ) -> Result<OwnedImageGenerationCancellation> {
        atomic_conn(conn, "image_generation_owned_cancel", || {
            if !Self::image_generation_job_owner_matches_conn(conn, input.job_id, &input.scope)? {
                return Ok(OwnedImageGenerationCancellation::NotFound);
            }
            // Idempotent: a cancellation already recorded for this owned job is
            // reported as requested regardless of the requesting operation id, so
            // a repeat call from the owner never trips the inner replay-identity
            // guard.
            let already_requested: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM image_generation_cancellation_facts WHERE job_id=?1)",
                [input.job_id.to_string()],
                |row| row.get(0),
            )?;
            if already_requested {
                return Ok(OwnedImageGenerationCancellation::CancellationRequested);
            }
            let cancellable_slots: i64 = conn.query_row(
                "SELECT COUNT(*) FROM image_generation_slots WHERE job_id=?1 AND state NOT IN ('published','failed','cancelled','discarded','late_quarantined')",
                [input.job_id.to_string()],
                |row| row.get(0),
            )?;
            if cancellable_slots == 0 {
                return Ok(OwnedImageGenerationCancellation::AlreadyTerminal);
            }
            match Self::request_image_generation_cancellation_conn(
                conn,
                &RequestImageGenerationCancellation {
                    job_id: input.job_id,
                    cancellation_version: input.cancellation_version,
                    request_operation_id: input.request_operation_id,
                    requested_at_unix_ms: input.requested_at_unix_ms,
                },
            )? {
                ImageGenerationCasOutcome::Applied { .. } => {
                    Ok(OwnedImageGenerationCancellation::CancellationRequested)
                }
                ImageGenerationCasOutcome::Conflict => {
                    Ok(OwnedImageGenerationCancellation::AlreadyTerminal)
                }
            }
        })
    }

    pub fn record_image_generation_deadline_expiry_conn(
        conn: &Connection,
        job_id: Uuid,
        observation: DeadlineObservationV1,
        recorded_at_unix_ms: i64,
    ) -> Result<ImageGenerationDeadlineExpiryFact> {
        atomic_conn(conn, "image_generation_deadline_expiry", || {
            if let Some(existing) = load_deadline_expiry_fact(conn, job_id)? {
                return Ok(existing);
            }
            let (canonical, plan_digest, deadline_boot, deadline): (Vec<u8>, String, String, i64) = conn.query_row(
                "SELECT canonical_plan,plan_digest,deadline_boot_id,operation_deadline_monotonic_ms FROM image_generation_plans WHERE job_id=?1",
                [job_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            let deadline_boot = Uuid::parse_str(&deadline_boot)?;
            ensure!(
                !observation.is_before(deadline_boot, deadline)?,
                "image generation operation deadline has not expired"
            );
            let plan = ImageGenerationPlanV1::from_canonical(&canonical, &plan_digest)?;
            let sealed_media_reservation_id = plan
                .central_resources
                .first()
                .context("image generation central reservation is absent")?
                .reservation_identity
                .clone();
            let sealed_state: Option<String> = conn
                .query_row(
                    "SELECT state FROM media_reservations WHERE reservation_id=?1",
                    [&sealed_media_reservation_id],
                    |row| row.get(0),
                )
                .optional()?;
            let media_reservation_id = match sealed_state.as_deref() {
                Some("released") | Some("accounting_corrupt") | None => {
                    let (live_slot_id, live_attempt_number) =
                        live_image_generation_attempt(conn, job_id)?;
                    image_generation_attempt_media_reservation_id(
                        &sealed_media_reservation_id,
                        live_slot_id,
                        live_attempt_number,
                    )
                }
                Some(_) => sealed_media_reservation_id.clone(),
            };
            let media_reservation_version: i64 = conn.query_row(
                "SELECT version FROM media_reservations WHERE reservation_id=?1",
                [&media_reservation_id],
                |row| row.get(0),
            )?;
            let spend_reservation_version: i64 = conn.query_row(
                "SELECT policy_version FROM image_spend_reservations WHERE reservation_id=?1",
                [&plan.spend.reservation_id],
                |row| row.get(0),
            )?;
            let identity_digest = hex_lower(&Sha256::digest(
                format!("{job_id}:{plan_digest}").as_bytes(),
            ));
            let cancellation_operation_id = format!("deadline:{identity_digest}");
            let cleanup_operation_id = format!("deadline-cleanup:{identity_digest}");
            let handoff_possible: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM image_generation_attempts a JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE a.job_id=?1 AND o.state IN ('dispatching','accepted','submission_unknown','cancellation_requested','reconciling','succeeded','failed'))",
                [job_id.to_string()],
                |row| row.get(0),
            )?;
            if !handoff_possible {
                let mut prepared = conn.prepare(
                    "SELECT a.external_operation_id,a.observed_journal_version FROM image_generation_attempts a JOIN external_journal_operations o ON o.operation_id=a.external_operation_id WHERE a.job_id=?1 AND o.state='prepared' ORDER BY a.slot_id,a.attempt_number",
                )?;
                let operations = prepared
                    .query_map([job_id.to_string()], |row| {
                        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                drop(prepared);
                for (operation_id, version) in operations {
                    let operation_id = Uuid::parse_str(&operation_id)?;
                    let record = match transition_external_operation_conn(
                        conn,
                        operation_id,
                        version,
                        ExternalJournalState::Expired,
                        recorded_at_unix_ms,
                    )? {
                        ExternalTransitionOutcome::Committed(record)
                        | ExternalTransitionOutcome::Duplicate(record) => record,
                        ExternalTransitionOutcome::Conflict(_) => {
                            anyhow::bail!("deadline expiry lost journal compare-and-set")
                        }
                    };
                    ensure!(conn.execute("UPDATE image_generation_attempts SET observed_journal_version=?1 WHERE job_id=?2 AND external_operation_id=?3 AND observed_journal_version=?4",params![record.version,job_id.to_string(),operation_id.to_string(),version])?==1,"deadline expiry lost attempt journal binding");
                }
            }
            let cancellation_version = 1_u64;
            Self::request_image_generation_cancellation_inner(
                conn,
                &RequestImageGenerationCancellation {
                    job_id,
                    cancellation_version,
                    request_operation_id: &cancellation_operation_id,
                    requested_at_unix_ms: recorded_at_unix_ms,
                },
            )?;
            let state = if handoff_possible {
                "cancellation_requested"
            } else {
                "cleanup_required"
            };
            conn.execute("INSERT INTO image_generation_deadline_expiry_facts(job_id,schema_version,state,deadline_boot_id,deadline_monotonic_ms,observed_boot_id,observed_monotonic_ms,cancellation_version,cancellation_operation_id,cleanup_operation_id,media_reservation_id,media_reservation_version,spend_reservation_id,spend_reservation_version,recorded_at_unix_ms) VALUES(?1,1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14)",params![job_id.to_string(),state,deadline_boot.to_string(),deadline,observation.daemon_boot_id.to_string(),i64::try_from(observation.now_monotonic_ms)?,i64::try_from(cancellation_version)?,cancellation_operation_id,cleanup_operation_id,media_reservation_id,media_reservation_version,plan.spend.reservation_id,spend_reservation_version,recorded_at_unix_ms])?;
            load_deadline_expiry_fact(conn, job_id)?.context("deadline expiry fact was not stored")
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
                    let journal_state: String = conn.query_row(
                        "SELECT state FROM external_journal_operations WHERE operation_id=?1 AND version=?2",
                        params![operation_id.to_string(), journal_version],
                        |row| row.get(0),
                    )?;
                    if journal_state == "expired" && !attempt_handoff_possible {
                        // Deadline expiry owns the prepared -> expired edge.
                    } else {
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
        let next = reduced.unwrap_or(ImageGenerationJobState::CancellationRequested);
        ensure!(
            job_transition_allowed(current, next),
            "job cannot accept cancellation"
        );
        if reduced.is_some() {
            ensure!(
                commit_terminal_job_projection_conn(
                    conn,
                    input.job_id,
                    input.requested_at_unix_ms,
                )? == Some(next),
                "cancellation terminal projection differs"
            );
        } else {
            execute_image_job_transition_conn(
                conn,
                input.job_id,
                current,
                u64::try_from(job_version)?,
                next,
                input.requested_at_unix_ms,
                ImageJobTransitionContext::Ordinary,
            )?;
        }
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

fn load_deadline_expiry_fact(
    conn: &Connection,
    job_id: Uuid,
) -> Result<Option<ImageGenerationDeadlineExpiryFact>> {
    conn.query_row(
        "SELECT state,cancellation_version,cancellation_operation_id,cleanup_operation_id,media_reservation_id,media_reservation_version,spend_reservation_id,spend_reservation_version FROM image_generation_deadline_expiry_facts WHERE job_id=?1",
        [job_id.to_string()],
        |row| {
            let state: String = row.get(0)?;
            let disposition = match state.as_str() {
                "cleanup_required" => ImageGenerationDeadlineExpiryDisposition::CleanupRequired,
                "cancellation_requested" => ImageGenerationDeadlineExpiryDisposition::CancellationRequested,
                _ => return Err(rusqlite::Error::InvalidQuery),
            };
            Ok(ImageGenerationDeadlineExpiryFact {
                job_id,
                disposition,
                cancellation_version: row.get::<_, i64>(1)? as u64,
                cancellation_operation_id: row.get(2)?,
                cleanup_operation_id: row.get(3)?,
                media_reservation_id: row.get(4)?,
                media_reservation_version: row.get::<_, i64>(5)? as u64,
                spend_reservation_id: row.get(6)?,
                spend_reservation_version: row.get::<_, i64>(7)? as u64,
            })
        },
    )
    .optional()
    .map_err(Into::into)
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationArtifactComponent {
    pub component_id: Uuid,
    pub kind: ImageGenerationArtifactComponentKind,
    pub relative_storage_key: String,
    pub byte_length: u64,
    pub sha256: String,
    pub resource_reservation_id: String,
    pub release_operation_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateImageGenerationArtifact {
    pub artifact_id: Uuid,
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub component_set_digest: String,
    pub components: Vec<CreateImageGenerationArtifactComponent>,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionImageGenerationArtifact {
    pub artifact_id: Uuid,
    pub expected_generation: u64,
    pub from: ImageGenerationArtifactState,
    pub to: ImageGenerationArtifactState,
    pub now_unix_ms: i64,
    pub terminal_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionImageGenerationArtifactComponent {
    pub artifact_id: Uuid,
    pub component_id: Uuid,
    pub expected_generation: u64,
    pub from: ImageGenerationArtifactComponentState,
    pub to: ImageGenerationArtifactComponentState,
    pub stable_identity_json: Option<String>,
    pub deletion_evidence_digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageGenerationArtifactCleanupReason {
    RetentionExpired,
    DiscardLateResult,
    InvalidOutput,
    RestartRecovery,
    OwnerRecovery,
}

impl ImageGenerationArtifactCleanupReason {
    const fn as_str(self) -> &'static str {
        match self {
            Self::RetentionExpired => "retention_expired",
            Self::DiscardLateResult => "discard_late_result",
            Self::InvalidOutput => "invalid_output",
            Self::RestartRecovery => "restart_recovery",
            Self::OwnerRecovery => "owner_recovery",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginImageGenerationArtifactCleanup {
    pub cleanup_operation_id: Uuid,
    pub artifact_id: Uuid,
    pub expected_generation: u64,
    pub expected_state: ImageGenerationArtifactState,
    pub reason: ImageGenerationArtifactCleanupReason,
    pub now_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitImageGenerationComponentDeletion {
    pub artifact_id: Uuid,
    pub component_id: Uuid,
    pub expected_generation: u64,
    pub release_operation_id: Uuid,
    pub deletion_evidence_digest: String,
    pub committed_at_unix_ms: i64,
}

state_enum!(ImageGenerationArtifactPublishedDisposition {
    Ordinary => "ordinary", LateAuthorized => "late_authorized"
});

state_enum!(ImageGenerationArtifactConsumerPurpose {
    ServeArtifact => "serve_artifact", ServeThumbnail => "serve_thumbnail",
    ToolInput => "tool_input", ModelInput => "model_input",
    InternalVerification => "internal_verification", InternalCleanup => "internal_cleanup"
});

state_enum!(ImageGenerationArtifactConsumerRoute {
    ArtifactFull => "artifact_full", ArtifactRange => "artifact_range",
    Thumbnail => "thumbnail", Tool => "tool", ModelPayload => "model_payload",
    Verification => "verification", Cleanup => "cleanup"
});

state_enum!(ImageGenerationArtifactReadKind { Full => "full", Range => "range" });

state_enum!(ImageGenerationLatePublicationState {
    Reserved => "reserved", CopyAuthorized => "copy_authorized",
    CopyCommitted => "copy_committed", Published => "published", Aborted => "aborted",
    Expired => "expired", SecurityBlocked => "security_blocked",
    DeleteAuthorized => "delete_authorized"
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquireImageGenerationArtifactLease<'a> {
    pub lease_id: Uuid,
    pub artifact_id: Uuid,
    pub expected_artifact_generation: u64,
    pub job_id: Uuid,
    pub expected_job_generation: u64,
    pub slot_id: Uuid,
    pub expected_slot_generation: u64,
    pub disposition: ImageGenerationArtifactPublishedDisposition,
    pub expected_disposition_generation: u64,
    pub component_id: Uuid,
    pub expected_component_kind: ImageGenerationArtifactComponentKind,
    pub expected_component_generation: u64,
    pub expected_component_checksum: &'a str,
    pub purpose: ImageGenerationArtifactConsumerPurpose,
    pub route: ImageGenerationArtifactConsumerRoute,
    pub read_kind: ImageGenerationArtifactReadKind,
    pub range_start: u64,
    pub requested_length: u64,
    pub component_set_digest: &'a str,
    pub authorization_digest: &'a str,
    pub daemon_boot_id: Uuid,
    pub committed_at_monotonic: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcquiredImageGenerationArtifactLease {
    pub lease_id: Uuid,
    pub relative_storage_key: String,
    pub stable_identity_json: String,
    pub byte_length: u64,
    pub range_start: u64,
    pub requested_length: u64,
}

#[derive(Debug)]
struct LeaseComponentProjection {
    artifact_state: String,
    artifact_generation: i64,
    component_set_digest: String,
    job_generation: i64,
    slot_state: String,
    slot_generation: i64,
    result_after_cancel: bool,
    published_disposition: String,
    published_disposition_generation: i64,
    component_kind: String,
    component_state: String,
    component_generation: i64,
    component_checksum: String,
    component_byte_length_hi: i64,
    component_byte_length_lo: i64,
    relative_storage_key: String,
    stable_identity_json: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReserveImageGenerationLatePublication<'a> {
    pub publication_operation_id: Uuid,
    pub artifact_id: Uuid,
    pub expected_artifact_generation: u64,
    pub job_id: Uuid,
    pub slot_id: Uuid,
    pub expected_slot_version: u64,
    pub component_set_digest: &'a str,
    pub component_set_json: &'a str,
    pub authorization_digest: &'a str,
    pub output_authority_digest: &'a str,
    pub output_authority_generation: u64,
    pub destination_name: &'a str,
    pub temporary_name: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimImageGenerationLatePublication {
    pub publication_operation_id: Uuid,
    pub expected_version: u64,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvanceImageGenerationLatePublication<'a> {
    pub publication_operation_id: Uuid,
    pub expected_version: u64,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
    pub from: ImageGenerationLatePublicationState,
    pub to: ImageGenerationLatePublicationState,
    pub evidence_json: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockVerifiedImageGenerationLatePublication<'a> {
    pub publication_operation_id: Uuid,
    pub expected_version: u64,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
    pub output_evidence_json: &'a str,
    pub recovery_evidence_json: &'a str,
}

struct LatePublicationFinalizeProjection {
    artifact_id: String,
    artifact_generation: i64,
    job_id: String,
    slot_id: String,
    slot_version: i64,
    output_authority_digest: String,
    output_authority_generation: i64,
    destination_name: String,
    output_evidence_json: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolveImageGenerationLatePublication<'a> {
    pub publication_operation_id: Uuid,
    pub expected_version: u64,
    pub from: ImageGenerationLatePublicationState,
    pub to: ImageGenerationLatePublicationState,
    pub recovery_evidence_json: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReclaimImageGenerationLatePublication<'a> {
    pub publication_operation_id: Uuid,
    pub expected_version: u64,
    pub previous_claim_generation: u64,
    pub worker_boot_id: Uuid,
    pub claim_generation: u64,
    pub reconciled_cleanup_evidence_json: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ImageGenerationLatePublicationEvidenceV1 {
    TemporaryPrepared {
        schema_version: u32,
        identity_digest: String,
        security_digest: String,
        byte_length: String,
        sha256: String,
    },
    OutputDurable {
        schema_version: u32,
        identity_digest: String,
        security_digest: String,
        byte_length: String,
        sha256: String,
        parent_sync_digest: String,
    },
    TemporaryDeleted {
        schema_version: u32,
        identity_digest: String,
        deletion_digest: String,
        parent_sync_digest: String,
    },
    ExactAbsence {
        schema_version: u32,
        absence_digest: String,
        parent_identity_digest: String,
    },
    SecurityAmbiguous {
        schema_version: u32,
        recovery_digest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageGenerationLatePublicationReplay {
    InProgress {
        state: ImageGenerationLatePublicationState,
        version: u64,
        deadline_unix_ms: i64,
    },
    Terminal {
        state: ImageGenerationLatePublicationState,
        version: u64,
        evidence: ImageGenerationLatePublicationEvidenceV1,
        decided_at_unix_ms: i64,
    },
}

impl ImageGenerationLatePublicationEvidenceV1 {
    pub fn from_canonical_json(encoded: &str) -> Result<Self> {
        let parsed: Self =
            serde_json::from_str(encoded).context("decoding publication evidence")?;
        parsed.validate()?;
        ensure!(
            serde_json::to_string(&parsed)? == encoded,
            "publication evidence is not canonical"
        );
        Ok(parsed)
    }

    pub fn canonical_json(&self) -> Result<String> {
        self.validate()?;
        Ok(serde_json::to_string(self)?)
    }

    fn validate(&self) -> Result<()> {
        let (version, digests, length) = match self {
            Self::TemporaryPrepared {
                schema_version,
                identity_digest,
                security_digest,
                byte_length,
                sha256,
            } => (
                *schema_version,
                vec![identity_digest, security_digest, sha256],
                Some(byte_length),
            ),
            Self::OutputDurable {
                schema_version,
                identity_digest,
                security_digest,
                byte_length,
                sha256,
                parent_sync_digest,
            } => (
                *schema_version,
                vec![identity_digest, security_digest, sha256, parent_sync_digest],
                Some(byte_length),
            ),
            Self::TemporaryDeleted {
                schema_version,
                identity_digest,
                deletion_digest,
                parent_sync_digest,
            } => (
                *schema_version,
                vec![identity_digest, deletion_digest, parent_sync_digest],
                None,
            ),
            Self::ExactAbsence {
                schema_version,
                absence_digest,
                parent_identity_digest,
            } => (
                *schema_version,
                vec![absence_digest, parent_identity_digest],
                None,
            ),
            Self::SecurityAmbiguous {
                schema_version,
                recovery_digest,
            } => (*schema_version, vec![recovery_digest], None),
        };
        ensure!(version == 1, "late publication evidence schema differs");
        for digest in digests {
            ensure_digest(digest, "late publication evidence digest")?;
        }
        if let Some(length) = length {
            let parsed = length
                .parse::<u64>()
                .context("late publication evidence length is invalid")?;
            ensure!(
                length == &parsed.to_string(),
                "late publication evidence length is not canonical"
            );
        }
        Ok(())
    }
}

impl Db {
    /// Creates the complete expected component graph in the same transaction.
    /// No component or temporary may be introduced outside this sealed graph.
    pub fn create_image_generation_artifact_conn(
        conn: &Connection,
        input: &CreateImageGenerationArtifact,
    ) -> Result<()> {
        ensure!(
            !input.components.is_empty(),
            "artifact component set is empty"
        );
        let mut kinds = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        ensure!(
            input
                .components
                .iter()
                .any(|component| component.kind == ImageGenerationArtifactComponentKind::Primary),
            "artifact has no primary component"
        );
        for component in &input.components {
            ensure!(
                ids.insert(component.component_id),
                "duplicate component identity"
            );
            ensure!(kinds.insert(component.kind), "duplicate component kind");
            ensure_digest(&component.sha256, "component checksum")?;
            ensure!(
                !component.relative_storage_key.is_empty(),
                "component storage key is empty"
            );
            ensure!(
                !component.resource_reservation_id.is_empty(),
                "component reservation is empty"
            );
        }
        let (component_set_json, component_set_digest) =
            image_generation_component_set_binding(&input.components)?;
        ensure!(
            input.component_set_digest == component_set_digest,
            "component set digest does not bind exact graph"
        );
        // Use a savepoint so this reducer composes inside Db::transaction (needed
        // for accepted-response post-rename crash cuts) without nesting BEGIN.
        atomic_conn(conn, "image_generation_create_artifact", || {
            conn.execute(
                "INSERT INTO image_generation_artifacts(artifact_id,job_id,slot_id,state,generation,expected_component_count,component_set_digest,component_set_json,created_at_unix_ms,updated_at_unix_ms) VALUES(?1,?2,?3,'allocating',1,?4,?5,?6,?7,?7)",
                params![input.artifact_id.to_string(),input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.components.len())?,component_set_digest,component_set_json,input.now_unix_ms],
            )?;
            for component in &input.components {
                conn.execute(
                    "INSERT INTO image_generation_artifact_components(artifact_id,component_id,component_kind,state,generation,relative_storage_key,byte_length_hi,byte_length_lo,sha256,resource_reservation_id,release_operation_id) VALUES(?1,?2,?3,'planned',1,?4,?5,?6,?7,?8,?9)",
                    params![input.artifact_id.to_string(),component.component_id.to_string(),component.kind.as_str(),component.relative_storage_key,i64::from((component.byte_length>>32) as u32),i64::from(component.byte_length as u32),component.sha256,component.resource_reservation_id,component.release_operation_id.to_string()],
                )?;
            }
            Ok(())
        })
    }

    pub fn transition_image_generation_artifact_conn(
        conn: &Connection,
        input: &TransitionImageGenerationArtifact,
    ) -> Result<()> {
        ensure!(
            artifact_transition_allowed(input.from, input.to),
            "forbidden image artifact transition"
        );
        ensure!(
            !matches!(
                (input.from, input.to),
                (
                    ImageGenerationArtifactState::LateQuarantined,
                    ImageGenerationArtifactState::Retained
                ) | (
                    ImageGenerationArtifactState::SecurityBlocked,
                    ImageGenerationArtifactState::CleanupPending
                ) | (
                    ImageGenerationArtifactState::SecurityBlocked,
                    ImageGenerationArtifactState::Retained
                )
            ),
            "artifact transition requires a specialized authority CAS"
        );
        let changed=conn.execute(
            "UPDATE image_generation_artifacts SET state=?1,generation=generation+1,updated_at_unix_ms=?2,terminal_reason=COALESCE(?3,terminal_reason) WHERE artifact_id=?4 AND state=?5 AND generation=?6",
            params![input.to.as_str(),input.now_unix_ms,input.terminal_reason,input.artifact_id.to_string(),input.from.as_str(),i64::try_from(input.expected_generation)?],
        )?;
        ensure!(changed == 1, "image artifact compare-and-set lost");
        Ok(())
    }

    pub fn transition_image_generation_artifact_component_conn(
        conn: &Connection,
        input: &TransitionImageGenerationArtifactComponent,
    ) -> Result<()> {
        ensure!(
            artifact_component_transition_allowed(input.from, input.to),
            "forbidden image artifact component transition"
        );
        ensure!(
            !matches!(
                (input.from, input.to),
                (
                    ImageGenerationArtifactComponentState::SecurityBlocked,
                    ImageGenerationArtifactComponentState::CleanupPending
                )
            ),
            "component transition requires audited Owner recovery"
        );
        if let Some(digest) = &input.deletion_evidence_digest {
            ensure_digest(digest, "deletion evidence digest")?;
        }
        let changed=conn.execute(
            "UPDATE image_generation_artifact_components SET state=?1,generation=generation+1,stable_identity_json=COALESCE(?2,stable_identity_json),deletion_evidence_digest=COALESCE(?3,deletion_evidence_digest) WHERE artifact_id=?4 AND component_id=?5 AND state=?6 AND generation=?7",
            params![input.to.as_str(),input.stable_identity_json,input.deletion_evidence_digest,input.artifact_id.to_string(),input.component_id.to_string(),input.from.as_str(),i64::try_from(input.expected_generation)?],
        )?;
        ensure!(
            changed == 1,
            "image artifact component compare-and-set lost"
        );
        Ok(())
    }

    fn execute_late_publication_artifact_transition_conn(
        conn: &Connection,
        artifact_id: &str,
        expected_generation: u64,
        now_unix_ms: i64,
    ) -> Result<()> {
        ensure!(
            artifact_transition_allowed(
                ImageGenerationArtifactState::LateQuarantined,
                ImageGenerationArtifactState::Retained
            ),
            "late publication artifact transition is not canonical"
        );
        ensure!(conn.execute("UPDATE image_generation_artifacts SET state='retained',generation=generation+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND state='late_quarantined' AND generation=?3",params![now_unix_ms,artifact_id,i64::try_from(expected_generation)?])?==1,"late publication artifact compare-and-set lost");
        Ok(())
    }

    fn execute_artifact_cleanup_transition_conn(
        conn: &Connection,
        input: &BeginImageGenerationArtifactCleanup,
    ) -> Result<()> {
        ensure!(
            artifact_transition_allowed(
                input.expected_state,
                ImageGenerationArtifactState::CleanupPending
            ),
            "artifact cleanup transition is not canonical"
        );
        let changed=conn.execute("UPDATE image_generation_artifacts SET state='cleanup_pending',generation=generation+1,updated_at_unix_ms=?1 WHERE artifact_id=?2 AND state=?3 AND generation=?4 AND active_lease_count=0 AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_references r WHERE r.artifact_id=image_generation_artifacts.artifact_id AND r.released_at_unix_ms IS NULL) AND NOT EXISTS(SELECT 1 FROM image_generation_late_publication_leases p WHERE p.artifact_id=image_generation_artifacts.artifact_id AND p.state IN ('reserved','copy_authorized','copy_committed','security_blocked','delete_authorized')) AND (immediate_cleanup=1 OR (eligibility_at_unix_ms IS NOT NULL AND eligibility_at_unix_ms<=?1) OR ?5 IN ('invalid_output','restart_recovery','owner_recovery'))",params![input.now_unix_ms,input.artifact_id.to_string(),input.expected_state.as_str(),i64::try_from(input.expected_generation)?,input.reason.as_str()])?;
        ensure!(
            changed == 1,
            "artifact cleanup compare-and-set lost or is ineligible"
        );
        Ok(())
    }

    fn execute_component_tombstone_transition_conn(
        conn: &Connection,
        input: &CommitImageGenerationComponentDeletion,
    ) -> Result<()> {
        ensure!(
            artifact_component_transition_allowed(
                ImageGenerationArtifactComponentState::Deleting,
                ImageGenerationArtifactComponentState::Tombstoned
            ),
            "component tombstone transition is not canonical"
        );
        ensure!(conn.execute("UPDATE image_generation_artifact_components SET state='tombstoned',generation=generation+1 WHERE artifact_id=?1 AND component_id=?2 AND state='deleting' AND generation=?3",params![input.artifact_id.to_string(),input.component_id.to_string(),i64::try_from(input.expected_generation)?])?==1,"component tombstone compare-and-set lost");
        Ok(())
    }

    fn execute_artifact_tombstone_transition_conn(
        conn: &Connection,
        artifact_id: Uuid,
        expected_generation: u64,
        now_unix_ms: i64,
        terminal_reason: &str,
    ) -> Result<()> {
        ensure!(
            artifact_transition_allowed(
                ImageGenerationArtifactState::Deleting,
                ImageGenerationArtifactState::Tombstoned
            ),
            "artifact tombstone transition is not canonical"
        );
        ensure!(conn.execute("UPDATE image_generation_artifacts SET state='tombstoned',generation=generation+1,terminal_reason=?1,updated_at_unix_ms=?2 WHERE artifact_id=?3 AND state='deleting' AND generation=?4",params![terminal_reason,now_unix_ms,artifact_id.to_string(),i64::try_from(expected_generation)?])?==1,"artifact tombstone compare-and-set lost");
        Ok(())
    }

    pub fn acquire_image_generation_artifact_lease_conn(
        conn: &Connection,
        input: &AcquireImageGenerationArtifactLease<'_>,
    ) -> Result<AcquiredImageGenerationArtifactLease> {
        ensure_digest(input.expected_component_checksum, "component checksum")?;
        ensure_digest(input.component_set_digest, "component set digest")?;
        ensure_digest(input.authorization_digest, "authorization digest")?;
        ensure!(
            input.requested_length > 0,
            "lease read length must be positive"
        );
        ensure!(
            lease_route_valid(input.purpose, input.route, input.read_kind),
            "lease purpose, route, and read kind disagree"
        );
        let deadline = input
            .committed_at_monotonic
            .checked_add(60_000)
            .context("lease deadline overflow")?;
        let tx = conn.unchecked_transaction()?;
        let projection=tx.query_row(
            "SELECT a.state,a.generation,a.component_set_digest,j.version,s.state,s.version,s.result_after_cancel,s.published_disposition,s.published_disposition_generation,c.component_kind,c.state,c.generation,c.sha256,c.byte_length_hi,c.byte_length_lo,c.relative_storage_key,c.stable_identity_json FROM image_generation_artifacts a JOIN image_generation_jobs j ON j.job_id=a.job_id JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_artifact_components c ON c.artifact_id=a.artifact_id WHERE a.artifact_id=?1 AND a.job_id=?2 AND a.slot_id=?3 AND c.component_id=?4",
            params![input.artifact_id.to_string(),input.job_id.to_string(),input.slot_id.to_string(),input.component_id.to_string()],
            |row| Ok(LeaseComponentProjection{artifact_state:row.get(0)?,artifact_generation:row.get(1)?,component_set_digest:row.get(2)?,job_generation:row.get(3)?,slot_state:row.get(4)?,slot_generation:row.get(5)?,result_after_cancel:row.get(6)?,published_disposition:row.get(7)?,published_disposition_generation:row.get(8)?,component_kind:row.get(9)?,component_state:row.get(10)?,component_generation:row.get(11)?,component_checksum:row.get(12)?,component_byte_length_hi:row.get(13)?,component_byte_length_lo:row.get(14)?,relative_storage_key:row.get(15)?,stable_identity_json:row.get(16)?}),
        ).optional()?.context("artifact lease target is unavailable")?;
        ensure!(
            projection.artifact_state == "retained"
                && projection.artifact_generation
                    == i64::try_from(input.expected_artifact_generation)?,
            "artifact generation is not retained"
        );
        ensure!(
            projection.job_generation == i64::try_from(input.expected_job_generation)?
                && projection.slot_state == "published"
                && projection.slot_generation == i64::try_from(input.expected_slot_generation)?,
            "owning job or published slot generation differs"
        );
        ensure!(
            projection.component_set_digest == input.component_set_digest,
            "component set differs"
        );
        ensure!(
            projection.component_kind == input.expected_component_kind.as_str()
                && projection.component_state == "ready"
                && projection.component_generation
                    == i64::try_from(input.expected_component_generation)?
                && projection.component_checksum == input.expected_component_checksum,
            "component lease binding differs"
        );
        ensure!(
            matches!(
                (input.disposition, projection.result_after_cancel),
                (ImageGenerationArtifactPublishedDisposition::Ordinary, false)
                    | (
                        ImageGenerationArtifactPublishedDisposition::LateAuthorized,
                        true
                    )
            ),
            "published disposition differs"
        );
        ensure!(
            input.expected_disposition_generation == input.expected_slot_generation,
            "published disposition generation differs"
        );
        ensure!(
            projection.published_disposition == input.disposition.as_str()
                && projection.published_disposition_generation
                    == i64::try_from(input.expected_disposition_generation)?,
            "persisted publication disposition differs"
        );
        let component_length = (u64::try_from(projection.component_byte_length_hi)? << 32)
            | u64::try_from(projection.component_byte_length_lo)?;
        let stable_identity_json = projection
            .stable_identity_json
            .clone()
            .context("component held identity is absent")?;
        match input.read_kind {
            ImageGenerationArtifactReadKind::Full => ensure!(
                input.range_start == 0 && input.requested_length == component_length,
                "full lease must bind exact component length"
            ),
            ImageGenerationArtifactReadKind::Range => ensure!(
                input
                    .range_start
                    .checked_add(input.requested_length)
                    .is_some_and(|end| end <= component_length),
                "range lease exceeds component"
            ),
        }
        let authorized:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_artifact_authorization_facts f WHERE f.authorization_digest=?1 AND f.artifact_id=?2 AND f.artifact_generation=?3 AND f.job_id=?4 AND f.job_generation=?5 AND f.slot_id=?6 AND f.slot_generation=?7 AND f.consumer_purpose=?8 AND f.consumer_route=?9 AND f.revoked_at_unix_ms IS NULL)",params![input.authorization_digest,input.artifact_id.to_string(),i64::try_from(input.expected_artifact_generation)?,input.job_id.to_string(),i64::try_from(input.expected_job_generation)?,input.slot_id.to_string(),i64::try_from(input.expected_slot_generation)?,input.purpose.as_str(),input.route.as_str()],|row|row.get(0))?;
        ensure!(
            authorized,
            "artifact route authorization is absent or stale"
        );
        tx.execute("INSERT INTO image_generation_artifact_leases(lease_id,artifact_id,artifact_generation,owning_job_id,owning_job_generation,owning_slot_id,owning_slot_generation,published_disposition,published_disposition_generation,component_id,component_kind,component_generation,component_checksum,consumer_purpose,consumer_route,read_kind,range_start_hi,range_start_lo,requested_length_hi,requested_length_lo,component_set_digest,authorization_digest,daemon_boot_id,committed_at_monotonic,deadline_monotonic) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22,?23,?24,?25)",params![input.lease_id.to_string(),input.artifact_id.to_string(),i64::try_from(input.expected_artifact_generation)?,input.job_id.to_string(),i64::try_from(input.expected_job_generation)?,input.slot_id.to_string(),i64::try_from(input.expected_slot_generation)?,input.disposition.as_str(),i64::try_from(input.expected_disposition_generation)?,input.component_id.to_string(),input.expected_component_kind.as_str(),i64::try_from(input.expected_component_generation)?,input.expected_component_checksum,input.purpose.as_str(),input.route.as_str(),input.read_kind.as_str(),i64::from((input.range_start>>32) as u32),i64::from(input.range_start as u32),i64::from((input.requested_length>>32) as u32),i64::from(input.requested_length as u32),input.component_set_digest,input.authorization_digest,input.daemon_boot_id.to_string(),i64::try_from(input.committed_at_monotonic)?,i64::try_from(deadline)?])?;
        tx.commit()?;
        Ok(AcquiredImageGenerationArtifactLease {
            lease_id: input.lease_id,
            relative_storage_key: projection.relative_storage_key,
            stable_identity_json,
            byte_length: component_length,
            range_start: input.range_start,
            requested_length: input.requested_length,
        })
    }

    pub fn release_image_generation_artifact_lease_conn(
        conn: &Connection,
        lease_id: Uuid,
        released_at_monotonic: u64,
    ) -> Result<bool> {
        release_image_generation_artifact_lease_inner(conn, lease_id, released_at_monotonic, false)
    }

    pub fn expire_image_generation_artifact_lease_conn(
        conn: &Connection,
        lease_id: Uuid,
        now_monotonic: u64,
    ) -> Result<bool> {
        release_image_generation_artifact_lease_inner(conn, lease_id, now_monotonic, true)
    }

    pub fn repair_image_generation_artifact_leases_for_boot_conn(
        conn: &Connection,
        current_boot_id: Uuid,
    ) -> Result<u64> {
        let tx = conn.unchecked_transaction()?;
        let released=tx.execute("UPDATE image_generation_artifact_leases SET released_at=committed_at_monotonic WHERE released_at IS NULL AND daemon_boot_id!=?1",[current_boot_id.to_string()])?;
        tx.execute("UPDATE image_generation_artifacts SET active_lease_count=(SELECT count(*) FROM image_generation_artifact_leases l WHERE l.artifact_id=image_generation_artifacts.artifact_id AND l.released_at IS NULL)",[])?;
        tx.commit()?;
        Ok(u64::try_from(released)?)
    }

    pub fn reserve_image_generation_late_publication_conn(
        conn: &Connection,
        input: &ReserveImageGenerationLatePublication<'_>,
    ) -> Result<bool> {
        reserve_image_generation_late_publication_at_conn(conn, input, database_now_unix_ms(conn)?)
    }

    pub fn claim_image_generation_late_publication_conn(
        conn: &Connection,
        input: &ClaimImageGenerationLatePublication,
    ) -> Result<()> {
        claim_image_generation_late_publication_at_conn(conn, input, database_now_unix_ms(conn)?)
    }

    pub fn advance_image_generation_late_publication_conn(
        conn: &Connection,
        input: &AdvanceImageGenerationLatePublication<'_>,
    ) -> Result<()> {
        advance_image_generation_late_publication_at_conn(conn, input, database_now_unix_ms(conn)?)
    }

    pub fn block_verified_image_generation_late_publication_conn(
        conn: &Connection,
        input: &BlockVerifiedImageGenerationLatePublication<'_>,
    ) -> Result<()> {
        block_verified_image_generation_late_publication_at_conn(
            conn,
            input,
            database_now_unix_ms(conn)?,
        )
    }

    pub fn finalize_image_generation_late_publication_conn(
        conn: &Connection,
        publication_operation_id: Uuid,
        expected_lease_version: u64,
    ) -> Result<()> {
        finalize_image_generation_late_publication_at_conn(
            conn,
            publication_operation_id,
            expected_lease_version,
            database_now_unix_ms(conn)?,
        )
    }

    pub fn resolve_image_generation_late_publication_conn(
        conn: &Connection,
        input: &ResolveImageGenerationLatePublication<'_>,
    ) -> Result<()> {
        resolve_image_generation_late_publication_at_conn(conn, input, database_now_unix_ms(conn)?)
    }

    pub fn replay_image_generation_late_publication_conn(
        conn: &Connection,
        operation_id: Uuid,
    ) -> Result<ImageGenerationLatePublicationReplay> {
        let (state,version,deadline,recovery,output,decided):(String,i64,i64,Option<String>,Option<String>,Option<i64>)=conn.query_row("SELECT state,version,deadline_unix_ms,recovery_evidence_json,output_evidence_json,decided_at_unix_ms FROM image_generation_late_publication_leases WHERE publication_operation_id=?1",[operation_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
        let state = ImageGenerationLatePublicationState::parse(&state)
            .context("stored late publication state is invalid")?;
        let version = u64::try_from(version)?;
        if let Some(decided_at_unix_ms) = decided {
            let encoded = if state == ImageGenerationLatePublicationState::Published {
                output
            } else {
                recovery
            }
            .context("terminal late publication evidence is absent")?;
            return Ok(ImageGenerationLatePublicationReplay::Terminal {
                state,
                version,
                evidence: validate_late_evidence(&encoded)?,
                decided_at_unix_ms,
            });
        }
        Ok(ImageGenerationLatePublicationReplay::InProgress {
            state,
            version,
            deadline_unix_ms: deadline,
        })
    }

    pub fn reclaim_image_generation_late_publication_conn(
        conn: &Connection,
        input: &ReclaimImageGenerationLatePublication<'_>,
    ) -> Result<()> {
        let evidence = validate_late_evidence(input.reconciled_cleanup_evidence_json)?;
        ensure!(
            matches!(
                evidence,
                ImageGenerationLatePublicationEvidenceV1::TemporaryDeleted { .. }
                    | ImageGenerationLatePublicationEvidenceV1::ExactAbsence { .. }
            ),
            "replacement claim lacks exact cleanup evidence"
        );
        ensure!(
            input.claim_generation > input.previous_claim_generation,
            "replacement claim is not fenced"
        );
        let now = database_now_unix_ms(conn)?;
        let changed=conn.execute("UPDATE image_generation_late_publication_leases SET worker_boot_id=?1,claim_generation=?2,recovery_evidence_json=?3,version=version+1 WHERE publication_operation_id=?4 AND state='reserved' AND version=?5 AND claim_generation=?6 AND ?7<deadline_unix_ms",params![input.worker_boot_id.to_string(),i64::try_from(input.claim_generation)?,input.reconciled_cleanup_evidence_json,input.publication_operation_id.to_string(),i64::try_from(input.expected_version)?,i64::try_from(input.previous_claim_generation)?,now])?;
        ensure!(
            changed == 1,
            "late publication replacement claim lost its compare-and-set"
        );
        Ok(())
    }
}

fn reserve_image_generation_late_publication_at_conn(
    conn: &Connection,
    input: &ReserveImageGenerationLatePublication<'_>,
    database_now_unix_ms: i64,
) -> Result<bool> {
    ensure_digest(input.component_set_digest, "component set digest")?;
    ensure_digest(input.authorization_digest, "authorization digest")?;
    ensure_digest(input.output_authority_digest, "output authority digest")?;
    ensure_safe_publication_name(input.destination_name)?;
    ensure_safe_publication_name(input.temporary_name)?;
    ensure!(
        input.destination_name != input.temporary_name,
        "publication names collide"
    );
    let deadline = database_now_unix_ms
        .checked_add(300_000)
        .context("late publication deadline overflow")?;
    let tx = conn.unchecked_transaction()?;
    let replay:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_late_publication_leases WHERE publication_operation_id=?1 AND artifact_id=?2 AND artifact_generation=?3 AND job_id=?4 AND slot_id=?5 AND expected_slot_version=?6 AND component_set_digest=?7 AND component_set_json=?8 AND authorization_digest=?9 AND output_authority_digest=?10 AND output_authority_generation=?11 AND destination_name=?12 AND temporary_name=?13)",params![input.publication_operation_id.to_string(),input.artifact_id.to_string(),i64::try_from(input.expected_artifact_generation)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?,input.component_set_digest,input.component_set_json,input.authorization_digest,input.output_authority_digest,i64::try_from(input.output_authority_generation)?,input.destination_name,input.temporary_name],|row|row.get(0))?;
    if replay {
        return Ok(false);
    }
    ensure!(!tx.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_late_publication_leases WHERE publication_operation_id=?1)",[input.publication_operation_id.to_string()],|row|row.get::<_,bool>(0))?,"late publication replay differs");
    let authorized:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_late_publication_authorization_facts f WHERE f.authorization_digest=?1 AND f.artifact_id=?2 AND f.artifact_generation=?3 AND f.job_id=?4 AND f.slot_id=?5 AND f.slot_generation=?6 AND f.component_set_digest=?7 AND f.output_authority_digest=?8 AND f.output_authority_generation=?9 AND f.destination_name=?10 AND f.temporary_name=?11 AND f.revoked_at_unix_ms IS NULL)",params![input.authorization_digest,input.artifact_id.to_string(),i64::try_from(input.expected_artifact_generation)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?,input.component_set_digest,input.output_authority_digest,i64::try_from(input.output_authority_generation)?,input.destination_name,input.temporary_name],|row|row.get(0))?;
    ensure!(
        authorized,
        "late publication authorization is absent or stale"
    );
    let eligible:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id WHERE a.artifact_id=?1 AND a.generation=?2 AND a.state='late_quarantined' AND a.active_lease_count=0 AND a.component_set_digest=?3 AND a.component_set_json=?4 AND a.job_id=?5 AND a.slot_id=?6 AND s.version=?7 AND s.state='late_quarantined' AND s.result_after_cancel=1 AND s.applied_cancellation_version IS NOT NULL AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id) AND (SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=a.artifact_id AND c.state='ready')=a.expected_component_count)",params![input.artifact_id.to_string(),i64::try_from(input.expected_artifact_generation)?,input.component_set_digest,input.component_set_json,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?],|row|row.get(0))?;
    ensure!(eligible, "late publication lost quarantine compare-and-set");
    tx.execute("INSERT INTO image_generation_late_publication_leases(publication_operation_id,artifact_id,artifact_generation,job_id,slot_id,expected_slot_version,component_set_digest,component_set_json,authorization_digest,output_authority_digest,output_authority_generation,destination_name,temporary_name,created_at_unix_ms,deadline_unix_ms,state,version) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,'reserved',1)",params![input.publication_operation_id.to_string(),input.artifact_id.to_string(),i64::try_from(input.expected_artifact_generation)?,input.job_id.to_string(),input.slot_id.to_string(),i64::try_from(input.expected_slot_version)?,input.component_set_digest,input.component_set_json,input.authorization_digest,input.output_authority_digest,i64::try_from(input.output_authority_generation)?,input.destination_name,input.temporary_name,database_now_unix_ms,deadline])?;
    tx.commit()?;
    Ok(true)
}

fn claim_image_generation_late_publication_at_conn(
    conn: &Connection,
    input: &ClaimImageGenerationLatePublication,
    database_now_unix_ms: i64,
) -> Result<()> {
    ensure!(
        input.claim_generation > 0,
        "claim generation must be positive"
    );
    let changed=conn.execute("UPDATE image_generation_late_publication_leases SET worker_boot_id=?1,claim_generation=?2,version=version+1 WHERE publication_operation_id=?3 AND state='reserved' AND version=?4 AND worker_boot_id IS NULL AND claim_generation IS NULL AND ?5<deadline_unix_ms",params![input.worker_boot_id.to_string(),i64::try_from(input.claim_generation)?,input.publication_operation_id.to_string(),i64::try_from(input.expected_version)?,database_now_unix_ms])?;
    ensure!(
        changed == 1,
        "late publication claim compare-and-set lost or expired"
    );
    Ok(())
}

fn advance_image_generation_late_publication_at_conn(
    conn: &Connection,
    input: &AdvanceImageGenerationLatePublication<'_>,
    database_now_unix_ms: i64,
) -> Result<()> {
    ensure!(
        !input.evidence_json.is_empty() && input.evidence_json.len() <= 64 * 1024,
        "late publication evidence length is invalid"
    );
    let evidence = validate_late_evidence(input.evidence_json)?;
    ensure!(
        matches!(
            (input.from, input.to),
            (
                ImageGenerationLatePublicationState::Reserved,
                ImageGenerationLatePublicationState::CopyAuthorized
            ) | (
                ImageGenerationLatePublicationState::CopyAuthorized,
                ImageGenerationLatePublicationState::CopyCommitted
            )
        ),
        "late publication advance requires a specialized edge"
    );
    ensure!(
        matches!(
            (input.to, evidence),
            (
                ImageGenerationLatePublicationState::CopyAuthorized,
                ImageGenerationLatePublicationEvidenceV1::TemporaryPrepared { .. }
            ) | (
                ImageGenerationLatePublicationState::CopyCommitted,
                ImageGenerationLatePublicationEvidenceV1::OutputDurable { .. }
            )
        ),
        "late publication evidence kind differs from transition"
    );
    let evidence_column = match input.to {
        ImageGenerationLatePublicationState::CopyAuthorized => "temporary_evidence_json",
        ImageGenerationLatePublicationState::CopyCommitted => "output_evidence_json",
        _ => unreachable!(),
    };
    let sql = format!(
        "UPDATE image_generation_late_publication_leases SET state=?1,version=version+1,{evidence_column}=?2 WHERE publication_operation_id=?3 AND state=?4 AND version=?5 AND worker_boot_id=?6 AND claim_generation=?7 AND (?8<deadline_unix_ms OR state!='reserved') AND EXISTS(SELECT 1 FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_late_publication_authorization_facts f ON f.authorization_digest=image_generation_late_publication_leases.authorization_digest WHERE a.artifact_id=image_generation_late_publication_leases.artifact_id AND a.generation=image_generation_late_publication_leases.artifact_generation AND a.state='late_quarantined' AND a.active_lease_count=0 AND s.version=image_generation_late_publication_leases.expected_slot_version AND s.state='late_quarantined' AND s.result_after_cancel=1 AND f.revoked_at_unix_ms IS NULL AND f.output_authority_digest=image_generation_late_publication_leases.output_authority_digest AND f.output_authority_generation=image_generation_late_publication_leases.output_authority_generation AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id) AND (SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=a.artifact_id AND c.state='ready')=a.expected_component_count)"
    );
    let changed = conn.execute(
        &sql,
        params![
            input.to.as_str(),
            input.evidence_json,
            input.publication_operation_id.to_string(),
            input.from.as_str(),
            i64::try_from(input.expected_version)?,
            input.worker_boot_id.to_string(),
            i64::try_from(input.claim_generation)?,
            database_now_unix_ms
        ],
    )?;
    ensure!(
        changed == 1,
        "late publication advance compare-and-set lost"
    );
    Ok(())
}

fn block_verified_image_generation_late_publication_at_conn(
    conn: &Connection,
    input: &BlockVerifiedImageGenerationLatePublication<'_>,
    database_now_unix_ms: i64,
) -> Result<()> {
    let evidence = validate_late_evidence(input.output_evidence_json)?;
    ensure!(
        matches!(
            evidence,
            ImageGenerationLatePublicationEvidenceV1::OutputDurable { .. }
        ),
        "verified late publication block requires durable output evidence"
    );
    ensure!(
        matches!(
            validate_late_evidence(input.recovery_evidence_json)?,
            ImageGenerationLatePublicationEvidenceV1::SecurityAmbiguous { .. }
        ),
        "verified late publication block requires closed recovery evidence"
    );
    let changed = conn.execute(
        "UPDATE image_generation_late_publication_leases SET state='security_blocked',version=version+1,output_evidence_json=?1,recovery_evidence_json=?2,decided_at_unix_ms=?3 WHERE publication_operation_id=?4 AND state='copy_authorized' AND version=?5 AND worker_boot_id=?6 AND claim_generation=?7 AND EXISTS(SELECT 1 FROM image_generation_artifacts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_late_publication_authorization_facts f ON f.authorization_digest=image_generation_late_publication_leases.authorization_digest WHERE a.artifact_id=image_generation_late_publication_leases.artifact_id AND a.generation=image_generation_late_publication_leases.artifact_generation AND a.state='late_quarantined' AND a.active_lease_count=0 AND s.version=image_generation_late_publication_leases.expected_slot_version AND s.state='late_quarantined' AND s.result_after_cancel=1 AND f.revoked_at_unix_ms IS NULL AND f.output_authority_digest=image_generation_late_publication_leases.output_authority_digest AND f.output_authority_generation=image_generation_late_publication_leases.output_authority_generation AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id) AND (SELECT count(*) FROM image_generation_artifact_components c WHERE c.artifact_id=a.artifact_id AND c.state='ready')=a.expected_component_count)",
        params![
            input.output_evidence_json,
            input.recovery_evidence_json,
            database_now_unix_ms,
            input.publication_operation_id.to_string(),
            i64::try_from(input.expected_version)?,
            input.worker_boot_id.to_string(),
            i64::try_from(input.claim_generation)?,
        ],
    )?;
    ensure!(
        changed == 1,
        "verified late publication block lost its compare-and-set"
    );
    Ok(())
}

fn finalize_image_generation_late_publication_at_conn(
    conn: &Connection,
    publication_operation_id: Uuid,
    expected_lease_version: u64,
    now_unix_ms: i64,
) -> Result<()> {
    ensure!(
        artifact_transition_allowed(
            ImageGenerationArtifactState::LateQuarantined,
            ImageGenerationArtifactState::Retained,
        ),
        "late publication artifact transition is not canonical"
    );
    ensure!(
        slot_transition_allowed(
            ImageGenerationSlotState::LateQuarantined,
            ImageGenerationSlotState::Published,
        ),
        "late publication slot transition is not canonical"
    );
    let tx = conn.unchecked_transaction()?;
    let projection=tx.query_row("SELECT p.artifact_id,p.artifact_generation,p.job_id,p.slot_id,p.expected_slot_version,p.output_authority_digest,p.output_authority_generation,p.destination_name,p.output_evidence_json FROM image_generation_late_publication_leases p JOIN image_generation_artifacts a ON a.artifact_id=p.artifact_id JOIN image_generation_slots s ON s.job_id=p.job_id AND s.slot_id=p.slot_id JOIN image_generation_late_publication_authorization_facts f ON f.authorization_digest=p.authorization_digest WHERE p.publication_operation_id=?1 AND p.state='copy_committed' AND p.version=?2 AND a.state='late_quarantined' AND a.generation=p.artifact_generation AND s.state='late_quarantined' AND s.version=p.expected_slot_version AND s.result_after_cancel=1 AND f.revoked_at_unix_ms IS NULL AND f.output_authority_digest=p.output_authority_digest AND f.output_authority_generation=p.output_authority_generation AND NOT EXISTS(SELECT 1 FROM image_generation_artifact_cleanup_intents i WHERE i.artifact_id=a.artifact_id)",params![publication_operation_id.to_string(),i64::try_from(expected_lease_version)?],|row|Ok(LatePublicationFinalizeProjection{artifact_id:row.get(0)?,artifact_generation:row.get(1)?,job_id:row.get(2)?,slot_id:row.get(3)?,slot_version:row.get(4)?,output_authority_digest:row.get(5)?,output_authority_generation:row.get(6)?,destination_name:row.get(7)?,output_evidence_json:row.get(8)?})).optional()?.context("late publication finalization lost its lease")?;
    tx.execute("INSERT INTO image_generation_user_published_outputs(publication_operation_id,artifact_id,artifact_generation,output_authority_digest,output_authority_generation,destination_name,output_evidence_json,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![publication_operation_id.to_string(),projection.artifact_id,projection.artifact_generation,projection.output_authority_digest,projection.output_authority_generation,projection.destination_name,projection.output_evidence_json,now_unix_ms])?;
    tx.execute("UPDATE image_generation_late_publication_leases SET state='published',version=version+1,decided_at_unix_ms=?3 WHERE publication_operation_id=?1 AND state='copy_committed' AND version=?2",params![publication_operation_id.to_string(),i64::try_from(expected_lease_version)?,now_unix_ms])?;
    Db::execute_late_publication_artifact_transition_conn(
        &tx,
        &projection.artifact_id,
        u64::try_from(projection.artifact_generation)?,
        now_unix_ms,
    )?;
    ensure!(tx.execute("UPDATE image_generation_slots SET state='published',version=version+1,published_disposition='late_authorized',published_disposition_generation=version+1 WHERE job_id=?1 AND slot_id=?2 AND state='late_quarantined' AND version=?3 AND result_after_cancel=1 AND applied_cancellation_version IS NOT NULL",params![projection.job_id,projection.slot_id,projection.slot_version])?==1,"late publication slot compare-and-set lost");
    tx.commit()?;
    Ok(())
}

fn resolve_image_generation_late_publication_at_conn(
    conn: &Connection,
    input: &ResolveImageGenerationLatePublication<'_>,
    database_now_unix_ms: i64,
) -> Result<()> {
    let evidence = validate_late_evidence(input.recovery_evidence_json)?;
    ensure!(
        matches!(
            (input.from, input.to),
            (
                ImageGenerationLatePublicationState::Reserved,
                ImageGenerationLatePublicationState::Expired
            ) | (
                ImageGenerationLatePublicationState::Reserved,
                ImageGenerationLatePublicationState::Aborted
            ) | (
                ImageGenerationLatePublicationState::CopyAuthorized,
                ImageGenerationLatePublicationState::Aborted
            ) | (
                ImageGenerationLatePublicationState::Reserved
                    | ImageGenerationLatePublicationState::CopyAuthorized
                    | ImageGenerationLatePublicationState::CopyCommitted,
                ImageGenerationLatePublicationState::SecurityBlocked
            )
        ),
        "late publication resolution edge is not specialized"
    );
    ensure!(
        matches!(
            (input.to, evidence),
            (
                ImageGenerationLatePublicationState::Expired
                    | ImageGenerationLatePublicationState::Aborted,
                ImageGenerationLatePublicationEvidenceV1::TemporaryDeleted { .. }
                    | ImageGenerationLatePublicationEvidenceV1::ExactAbsence { .. }
            ) | (
                ImageGenerationLatePublicationState::SecurityBlocked,
                ImageGenerationLatePublicationEvidenceV1::SecurityAmbiguous { .. }
            )
        ),
        "late publication recovery evidence kind differs"
    );
    let deadline_clause = if input.to == ImageGenerationLatePublicationState::Expired {
        "AND ?6>=deadline_unix_ms"
    } else {
        ""
    };
    let sql = format!(
        "UPDATE image_generation_late_publication_leases SET state=?1,version=version+1,recovery_evidence_json=?2,decided_at_unix_ms=?3 WHERE publication_operation_id=?4 AND state=?5 AND version=?6 {deadline_clause}"
    );
    // The repeated version parameter keeps the SQL shape closed; expiry uses
    // a separately bound database-owned clock below.
    let sql = if input.to == ImageGenerationLatePublicationState::Expired {
        "UPDATE image_generation_late_publication_leases SET state=?1,version=version+1,recovery_evidence_json=?2,decided_at_unix_ms=?3 WHERE publication_operation_id=?4 AND state=?5 AND version=?6 AND ?7>=deadline_unix_ms"
    } else {
        sql.as_str()
    };
    let changed = if input.to == ImageGenerationLatePublicationState::Expired {
        conn.execute(
            sql,
            params![
                input.to.as_str(),
                input.recovery_evidence_json,
                database_now_unix_ms,
                input.publication_operation_id.to_string(),
                input.from.as_str(),
                i64::try_from(input.expected_version)?,
                database_now_unix_ms
            ],
        )?
    } else {
        conn.execute(
            sql,
            params![
                input.to.as_str(),
                input.recovery_evidence_json,
                database_now_unix_ms,
                input.publication_operation_id.to_string(),
                input.from.as_str(),
                i64::try_from(input.expected_version)?
            ],
        )?
    };
    ensure!(
        changed == 1,
        "late publication resolution compare-and-set lost"
    );
    Ok(())
}

fn validate_late_evidence(evidence: &str) -> Result<ImageGenerationLatePublicationEvidenceV1> {
    ensure!(
        !evidence.is_empty() && evidence.len() <= 64 * 1024,
        "late publication evidence length is invalid"
    );
    let parsed: ImageGenerationLatePublicationEvidenceV1 =
        serde_json::from_str(evidence).context("late publication evidence is invalid JSON")?;
    parsed.validate()?;
    ensure!(
        serde_json::to_string(&parsed)? == evidence,
        "late publication evidence is not canonical"
    );
    Ok(parsed)
}

impl Db {
    pub fn begin_image_generation_artifact_cleanup_conn(
        conn: &Connection,
        input: &BeginImageGenerationArtifactCleanup,
    ) -> Result<()> {
        ensure!(
            artifact_transition_allowed(
                input.expected_state,
                ImageGenerationArtifactState::CleanupPending,
            ),
            "artifact cleanup transition is not canonical"
        );
        ensure!(
            matches!(
                input.expected_state,
                ImageGenerationArtifactState::Allocating
                    | ImageGenerationArtifactState::Writing
                    | ImageGenerationArtifactState::Retained
                    | ImageGenerationArtifactState::LateQuarantined
                    | ImageGenerationArtifactState::SecurityBlocked
            ),
            "artifact state cannot begin cleanup"
        );
        ensure!(
            input.expected_state != ImageGenerationArtifactState::SecurityBlocked
                || input.reason == ImageGenerationArtifactCleanupReason::OwnerRecovery,
            "security-blocked cleanup requires Owner recovery authority"
        );
        let tx = conn.unchecked_transaction()?;
        let cleanup_generation = input
            .expected_generation
            .checked_add(1)
            .context("artifact generation overflow")?;
        tx.execute(
            "INSERT INTO image_generation_artifact_cleanup_intents(cleanup_operation_id,artifact_id,expected_artifact_generation,reason,state,version,created_at_unix_ms) VALUES(?1,?2,?3,?4,'pending',1,?5)",
            params![input.cleanup_operation_id.to_string(),input.artifact_id.to_string(),i64::try_from(cleanup_generation)?,input.reason.as_str(),input.now_unix_ms],
        )?;
        Self::execute_artifact_cleanup_transition_conn(&tx, input)?;
        tx.commit()?;
        Ok(())
    }

    /// Commits held-file deletion evidence, the exactly-once central resource
    /// release fact, and the component tombstone as one indivisible projection.
    pub fn commit_image_generation_component_deletion_conn(
        conn: &Connection,
        input: &CommitImageGenerationComponentDeletion,
    ) -> Result<()> {
        ensure!(
            artifact_component_transition_allowed(
                ImageGenerationArtifactComponentState::Deleting,
                ImageGenerationArtifactComponentState::Tombstoned,
            ),
            "component tombstone transition is not canonical"
        );
        ensure_digest(&input.deletion_evidence_digest, "deletion evidence digest")?;
        let tx = conn.unchecked_transaction()?;
        let changed = tx.execute(
            "UPDATE image_generation_artifact_components SET deletion_evidence_digest=?1 WHERE artifact_id=?2 AND component_id=?3 AND state='deleting' AND generation=?4 AND release_operation_id=?5 AND deletion_evidence_digest IS NULL",
            params![input.deletion_evidence_digest,input.artifact_id.to_string(),input.component_id.to_string(),i64::try_from(input.expected_generation)?,input.release_operation_id.to_string()],
        )?;
        ensure!(
            changed == 1,
            "component deletion evidence compare-and-set lost"
        );
        tx.execute(
            "INSERT INTO image_generation_component_release_facts(artifact_id,component_id,release_operation_id,deletion_evidence_digest,committed_at_unix_ms) VALUES(?1,?2,?3,?4,?5)",
            params![input.artifact_id.to_string(),input.component_id.to_string(),input.release_operation_id.to_string(),input.deletion_evidence_digest,input.committed_at_unix_ms],
        )?;
        Self::execute_component_tombstone_transition_conn(&tx, input)?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_image_generation_artifact_cleanup_conn(
        conn: &Connection,
        artifact_id: Uuid,
        expected_generation: u64,
        cleanup_operation_id: Uuid,
        now_unix_ms: i64,
        terminal_reason: &str,
    ) -> Result<()> {
        ensure!(
            artifact_transition_allowed(
                ImageGenerationArtifactState::Deleting,
                ImageGenerationArtifactState::Tombstoned,
            ),
            "artifact tombstone transition is not canonical"
        );
        ensure!(
            !terminal_reason.is_empty(),
            "artifact terminal reason is empty"
        );
        let tx = conn.unchecked_transaction()?;
        Self::execute_artifact_tombstone_transition_conn(
            &tx,
            artifact_id,
            expected_generation,
            now_unix_ms,
            terminal_reason,
        )?;
        let cleanup=tx.execute("UPDATE image_generation_artifact_cleanup_intents SET state='completed',version=version+1,completed_at_unix_ms=?1 WHERE cleanup_operation_id=?2 AND artifact_id=?3 AND state='deleting'",params![now_unix_ms,cleanup_operation_id.to_string(),artifact_id.to_string()])?;
        ensure!(cleanup == 1, "cleanup completion compare-and-set lost");
        tx.commit()?;
        Ok(())
    }
}

const fn lease_route_valid(
    purpose: ImageGenerationArtifactConsumerPurpose,
    route: ImageGenerationArtifactConsumerRoute,
    read_kind: ImageGenerationArtifactReadKind,
) -> bool {
    use ImageGenerationArtifactConsumerPurpose as P;
    use ImageGenerationArtifactConsumerRoute as R;
    use ImageGenerationArtifactReadKind as K;
    matches!(
        (purpose, route, read_kind),
        (P::ServeArtifact, R::ArtifactFull, K::Full)
            | (P::ServeArtifact, R::ArtifactRange, K::Range)
            | (P::ServeThumbnail, R::Thumbnail, K::Full)
            | (P::ToolInput, R::Tool, K::Full)
            | (P::ModelInput, R::ModelPayload, K::Full)
            | (P::InternalVerification, R::Verification, K::Full)
            | (P::InternalCleanup, R::Cleanup, K::Full)
    )
}

fn ensure_safe_publication_name(name: &str) -> Result<()> {
    ensure!(
        !name.is_empty()
            && name.len() <= 255
            && name != "."
            && name != ".."
            && !name.contains('/')
            && !name.contains('\\')
            && !name.contains('\0'),
        "publication name is not one safe relative component"
    );
    Ok(())
}

fn database_now_unix_ms(conn: &Connection) -> Result<i64> {
    Ok(conn.query_row(
        "SELECT CAST((julianday('now')-2440587.5)*86400000 AS INTEGER)",
        [],
        |row| row.get(0),
    )?)
}

fn release_image_generation_artifact_lease_inner(
    conn: &Connection,
    lease_id: Uuid,
    released_at_monotonic: u64,
    require_expired: bool,
) -> Result<bool> {
    let tx = conn.unchecked_transaction()?;
    let row = tx
        .query_row(
            "SELECT deadline_monotonic,released_at FROM image_generation_artifact_leases WHERE lease_id=?1",
            [lease_id.to_string()],
            |row| Ok((row.get::<_,i64>(0)?,row.get::<_,Option<i64>>(1)?)),
        )
        .optional()?;
    let Some((deadline, released)) = row else {
        return Ok(false);
    };
    if released.is_some() {
        return Ok(false);
    }
    let released_at = i64::try_from(released_at_monotonic)?;
    if require_expired && released_at < deadline {
        return Ok(false);
    }
    let changed=tx.execute("UPDATE image_generation_artifact_leases SET released_at=?1 WHERE lease_id=?2 AND released_at IS NULL",params![released_at,lease_id.to_string()])?;
    ensure!(changed == 1, "artifact lease release compare-and-set lost");
    tx.commit()?;
    Ok(true)
}

fn ensure_digest(value: &str, label: &str) -> Result<()> {
    ensure!(
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "{label} is not lowercase SHA-256"
    );
    Ok(())
}

pub fn image_generation_component_set_binding(
    components: &[CreateImageGenerationArtifactComponent],
) -> Result<(String, String)> {
    let mut rows = components
        .iter()
        .map(|component| {
            serde_json::json!({
                "byteLength": component.byte_length.to_string(),
                "componentId": component.component_id,
                "kind": component.kind.as_str(),
                "releaseOperationId": component.release_operation_id,
                "reservationId": component.resource_reservation_id,
                "sha256": component.sha256,
                "storageKey": component.relative_storage_key,
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by_key(serde_json::Value::to_string);
    let json = serde_json::to_string(&rows)?;
    let digest = hex_lower(&Sha256::digest(json.as_bytes()));
    Ok((json, digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::image_generation_plan::*;

    #[test]
    fn attempt_media_reservation_ids_are_slot_scoped_and_do_not_parse_sealed_suffix() {
        let slot_a = Uuid::from_u128(1);
        let slot_b = Uuid::from_u128(2);
        let sealed = "gpu:batch:retry:2";
        let first = image_generation_attempt_media_reservation_id(sealed, slot_a, 1);
        let retry_a = image_generation_attempt_media_reservation_id(sealed, slot_a, 2);
        let retry_b = image_generation_attempt_media_reservation_id(sealed, slot_b, 2);
        assert_eq!(first, sealed);
        assert_ne!(retry_a, retry_b);
        assert_ne!(retry_a, sealed);
        assert_ne!(retry_b, sealed);
        assert!(retry_a.contains(&slot_a.to_string()));
        assert!(retry_b.contains(&slot_b.to_string()));
        assert_eq!(
            image_generation_attempt_media_reservation_id(sealed, slot_a, 3),
            format!("{sealed}:retry:{slot_a}:3")
        );
    }

    #[test]
    fn reconciliation_evidence_has_exact_closed_bounds() {
        assert!(reconciliation_evidence_digest(&[]).is_err());
        assert!(
            reconciliation_evidence_digest(&vec![
                0;
                MAX_IMAGE_GENERATION_RECONCILIATION_EVIDENCE_BYTES
                    - 1
            ])
            .is_ok()
        );
        assert!(
            reconciliation_evidence_digest(&vec![
                0;
                MAX_IMAGE_GENERATION_RECONCILIATION_EVIDENCE_BYTES
            ])
            .is_ok()
        );
        assert!(
            reconciliation_evidence_digest(&vec![
                0;
                MAX_IMAGE_GENERATION_RECONCILIATION_EVIDENCE_BYTES
                    + 1
            ])
            .is_err()
        );
    }

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
            deadline_boot_id: Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa),
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

    struct MixedFixture {
        job_id: Uuid,
        slots: Vec<Uuid>,
        operations: Vec<Uuid>,
    }

    fn mixed_fixture(conn: &Connection) -> Result<MixedFixture> {
        let job_id = Uuid::now_v7();
        let slots = (0..4).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
        let artifacts = (0..4).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
        let (bytes, _) = canonical_test_plan(job_id, slots[0], artifacts[0], 1, 1, 100);
        let mut plan: ImageGenerationPlanV1 = serde_json::from_slice(&bytes)?;
        let template = plan.targets[0].slots[0].clone();
        plan.targets[0].slots = slots
            .iter()
            .zip(&artifacts)
            .enumerate()
            .map(|(index, (slot_id, artifact_id))| {
                let mut slot = template.clone();
                slot.slot_id = *slot_id;
                slot.managed_artifact_id = *artifact_id;
                slot.slot_index = index as u32;
                slot.sample_index = index as u32;
                slot.publication_name = format!("generated-{index}.png");
                slot.attempts[0].provider_request_identity = format!("request:{index}");
                slot.attempts[0].provider_idempotency_identity = format!("idem:{index}");
                slot
            })
            .collect();
        plan.targets[0].sample_count = 4;
        plan.central_resources[0].units = 4;
        plan.spend.maximum_usd_micros = Some(4);
        let bytes = plan.canonical_bytes()?;
        let digest = plan.digest()?;
        let verified = CreateImageGenerationJob::from_verified_canonical_plan(&bytes, &digest, 1)?;
        let graph = plan.targets[0]
            .slots
            .iter()
            .map(|slot| CreateImageGenerationSlot {
                slot_id: slot.slot_id,
                slot_index: slot.slot_index,
                sample_index: slot.sample_index,
                managed_artifact_id: slot.managed_artifact_id,
                attempts: vec![CreateImageGenerationAttempt {
                    attempt_number: 1,
                    provider_request_identity: slot.attempts[0].provider_request_identity.clone(),
                    provider_idempotency_identity: slot.attempts[0]
                        .provider_idempotency_identity
                        .clone(),
                }],
            })
            .collect::<Vec<_>>();
        Db::create_image_generation_graph_conn(conn, &verified, &graph)?;
        for (state, version) in [("validating", 2), ("queued", 3), ("dispatching", 4)] {
            conn.execute(
                "UPDATE image_generation_jobs SET state=?1,version=?2 WHERE job_id=?3",
                params![state, version, job_id.to_string()],
            )?;
        }
        let operations = (0..3).map(|_| Uuid::now_v7()).collect::<Vec<_>>();
        for (index, slot_id) in slots.iter().take(2).enumerate() {
            conn.execute("INSERT INTO external_journal_operations(operation_id,operation_kind,owner_session_id,idempotency_key,payload_digest,payload_len,state,version,created_at_wall_ms,updated_at_wall_ms,terminal_at_wall_ms) VALUES(?1,'image_generation','owner',?2,?3,1,'succeeded',1,1,1,1)",params![operations[index].to_string(),format!("idem_{index}"),"1".repeat(64)])?;
            for (state, version) in [
                ("preparing", 2),
                ("prepared", 3),
                ("dispatching", 4),
                ("accepted", 5),
                ("downloading", 6),
                ("response_adopted", 7),
            ] {
                conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,dispatch_proof_endpoint_id='seed-endpoint',dispatch_proof_config_generation=1,dispatch_proof_refresh_epoch=1,dispatch_proof_connected_ip='127.0.0.1',dispatch_proof_location_class='loopback',dispatch_proof_hops_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',external_operation_id=?3,observed_journal_version=1,response_digest=CASE WHEN ?1='response_adopted' THEN ?4 ELSE response_digest END WHERE job_id=?5 AND slot_id=?6",params![state,version,operations[index].to_string(),"a".repeat(64),job_id.to_string(),slot_id.to_string()])?;
            }
            for (state, version) in [
                ("queued", 2),
                ("dispatching", 3),
                ("running", 4),
                ("downloading", 5),
                ("validating", 6),
            ] {
                conn.execute("UPDATE image_generation_slots SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4",params![state,version,job_id.to_string(),slot_id.to_string()])?;
            }
        }
        conn.execute("UPDATE image_generation_slots SET state='ready_to_publish',version=7 WHERE job_id=?1 AND slot_id=?2",params![job_id.to_string(),slots[0].to_string()])?;
        Db::commit_image_generation_publication_conn(
            conn,
            &CommitImageGenerationPublication {
                job_id,
                slot_id: slots[0],
                attempt_number: 1,
                expected_attempt_version: 7,
                expected_slot_version: 7,
                artifact_generation: 1,
                now_unix_ms: 2,
            },
        )?;
        conn.execute("INSERT INTO external_journal_operations(operation_id,operation_kind,owner_session_id,idempotency_key,payload_digest,payload_len,state,version,created_at_wall_ms,updated_at_wall_ms) VALUES(?1,'image_generation','owner','idem_3',?2,1,'reconciling',2,1,1)",params![operations[2].to_string(),"3".repeat(64)])?;
        for (state, version) in [
            ("preparing", 2),
            ("prepared", 3),
            ("dispatching", 4),
            ("submission_unknown", 5),
            ("reconciling", 6),
        ] {
            conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,dispatch_proof_endpoint_id='seed-endpoint',dispatch_proof_config_generation=1,dispatch_proof_refresh_epoch=1,dispatch_proof_connected_ip='127.0.0.1',dispatch_proof_location_class='loopback',dispatch_proof_hops_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',external_operation_id=?3,observed_journal_version=2 WHERE job_id=?4 AND slot_id=?5",params![state,version,operations[2].to_string(),job_id.to_string(),slots[3].to_string()])?;
        }
        for (state, version) in [("queued", 2), ("dispatching", 3), ("submission_unknown", 4)] {
            conn.execute("UPDATE image_generation_slots SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4",params![state,version,job_id.to_string(),slots[3].to_string()])?;
        }
        Ok(MixedFixture {
            job_id,
            slots,
            operations,
        })
    }

    fn mixed_snapshot(conn: &Connection, job_id: Uuid) -> Result<String> {
        let queries = [
            "SELECT COALESCE(group_concat(job_id||':'||state||':'||version,'|'),'') FROM image_generation_jobs",
            "SELECT COALESCE(group_concat(slot_id||':'||state||':'||version||':'||COALESCE(applied_cancellation_version,'')||':'||result_after_cancel,'|'),'') FROM image_generation_slots",
            "SELECT COALESCE(group_concat(slot_id||':'||state||':'||version||':'||COALESCE(applied_cancellation_version,'')||':'||COALESCE(observed_journal_version,''),'|'),'') FROM image_generation_attempts",
            "SELECT COALESCE(group_concat(job_id||':'||cancellation_version||':'||request_operation_id,'|'),'') FROM image_generation_cancellation_facts",
            "SELECT COALESCE(group_concat(slot_id||':'||attempt_number||':'||cancellation_version||':'||response_digest,'|'),'') FROM image_generation_cancelled_result_facts",
            "SELECT COALESCE(group_concat(slot_id||':'||attempt_number||':'||journal_version||':'||evidence_digest,'|'),'') FROM image_generation_reconciliation_evidence",
            "SELECT COALESCE(group_concat(operation_id||':'||state||':'||version,'|'),'') FROM external_journal_operations",
        ];
        let mut snapshot = job_id.to_string();
        for query in queries {
            let value: String = conn.query_row(query, [], |row| row.get(0))?;
            snapshot.push_str(&value);
        }
        Ok(snapshot)
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
            conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,dispatch_proof_endpoint_id='seed-endpoint',dispatch_proof_config_generation=1,dispatch_proof_refresh_epoch=1,dispatch_proof_connected_ip='127.0.0.1',dispatch_proof_location_class='loopback',dispatch_proof_hops_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',external_operation_id=?3,observed_journal_version=1 WHERE job_id=?4 AND slot_id=?5 AND attempt_number=1",params![state,version,operation_id.to_string(),job_id.to_string(),slot_id.to_string()])?;
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
    fn scheduler_claim_expiry_fencing_and_sql_guards_are_exact() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let job_id=Uuid::now_v7(); let slot_id=Uuid::now_v7(); let artifact_id=Uuid::now_v7();
            let (plan,digest)=canonical_test_plan(job_id,slot_id,artifact_id,1,1,100);
            let verified=CreateImageGenerationJob::from_verified_canonical_plan(&plan,&digest,1)?;
            Db::create_image_generation_graph_conn(conn,&verified,&[CreateImageGenerationSlot{slot_id,slot_index:0,sample_index:0,managed_artifact_id:artifact_id,attempts:vec![CreateImageGenerationAttempt{attempt_number:1,provider_request_identity:"request:1".into(),provider_idempotency_identity:"idem:1".into()}]}])?;
            conn.execute("UPDATE image_generation_jobs SET state='validating',version=2 WHERE job_id=?1",[job_id.to_string()])?;
            conn.execute("UPDATE image_generation_jobs SET state='queued',version=3 WHERE job_id=?1",[job_id.to_string()])?;
            conn.execute("UPDATE image_generation_slots SET state='queued',version=2 WHERE job_id=?1 AND slot_id=?2",params![job_id.to_string(),slot_id.to_string()])?;
            conn.execute("INSERT INTO image_generation_attempt_activation_facts(job_id,slot_id,attempt_number,activation_reason,prior_attempt_number,activated_at_unix_ms) VALUES(?1,?2,1,'initial',NULL,1)",params![job_id.to_string(),slot_id.to_string()])?;
            let first=Uuid::now_v7();
            let claim=|worker_boot_id,claim_generation|ClaimImageGenerationDispatch{job_id,slot_id,attempt_number:1,worker_boot_id,claim_generation};
            claim_image_generation_dispatch_at_conn(conn,&claim(first,1),1_000)?;
            assert!(claim_image_generation_dispatch_at_conn(conn,&claim(Uuid::now_v7(),2),60_999).is_err());
            let unchanged:(String,i64)=conn.query_row("SELECT worker_boot_id,claim_generation FROM image_generation_scheduler_claims WHERE job_id=?1",[job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
            assert_eq!(unchanged,(first.to_string(),1));
            let second=Uuid::now_v7();
            claim_image_generation_dispatch_at_conn(conn,&claim(second,2),61_000)?;
            assert!(claim_image_generation_dispatch_at_conn(conn,&claim(Uuid::now_v7(),4),121_001).is_err());
            let third=Uuid::now_v7();
            claim_image_generation_dispatch_at_conn(conn,&claim(third,3),121_001)?;
            assert!(conn.execute("UPDATE image_generation_scheduler_claims SET worker_boot_id=?1,claim_generation=claim_generation+1 WHERE job_id=?2",params![Uuid::now_v7().to_string(),job_id.to_string()]).is_err());
            assert!(conn.execute("DELETE FROM image_generation_scheduler_claims WHERE job_id=?1",[job_id.to_string()]).is_err());
            assert!(conn.execute("INSERT INTO image_generation_scheduler_claim_mutation_authority(job_id,slot_id,from_generation,to_generation) VALUES(?1,?2,3,4)",params![job_id.to_string(),slot_id.to_string()]).is_err());
            let stored:(String,i64,i64,i64)=conn.query_row("SELECT worker_boot_id,claim_generation,claimed_at_unix_ms,expires_at_unix_ms FROM image_generation_scheduler_claims WHERE job_id=?1 ORDER BY claim_generation DESC LIMIT 1",[job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?)))?;
            assert_eq!(stored,(third.to_string(),3,121_001,181_001));
            assert_eq!(conn.query_row("SELECT count(*) FROM image_generation_scheduler_claims WHERE job_id=?1",[job_id.to_string()],|row|row.get::<_,i64>(0))?,3);
            let real_now=database_now_unix_ms(conn)?;
            conn.execute("INSERT INTO image_generation_scheduler_claims(job_id,slot_id,attempt_number,worker_boot_id,claim_generation,claimed_at_unix_ms,expires_at_unix_ms) VALUES(?1,?2,1,?3,4,?4,?5)",params![job_id.to_string(),slot_id.to_string(),Uuid::now_v7().to_string(),real_now,real_now+60_000])?;
            assert!(conn.execute("INSERT INTO image_generation_scheduler_claims(job_id,slot_id,attempt_number,worker_boot_id,claim_generation,claimed_at_unix_ms,expires_at_unix_ms) VALUES(?1,?2,1,?3,5,?4,?5)",params![job_id.to_string(),slot_id.to_string(),Uuid::now_v7().to_string(),real_now+1,real_now+60_001]).is_err());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn deadline_observation_has_exact_boot_and_boundary_semantics() {
        let boot = Uuid::now_v7();
        let other_boot = Uuid::now_v7();
        assert!(
            DeadlineObservationV1::new(boot, 99)
                .unwrap()
                .is_before(boot, 100)
                .unwrap()
        );
        assert!(
            !DeadlineObservationV1::new(boot, 100)
                .unwrap()
                .is_before(boot, 100)
                .unwrap()
        );
        assert!(
            !DeadlineObservationV1::new(boot, 101)
                .unwrap()
                .is_before(boot, 100)
                .unwrap()
        );
        assert!(
            !DeadlineObservationV1::new(other_boot, 0)
                .unwrap()
                .is_before(boot, 100)
                .unwrap()
        );
        assert!(DeadlineObservationV1::new(Uuid::nil(), 0).is_err());
    }

    #[test]
    fn media_dispatch_snapshot_is_immutable_and_survives_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("image.db");
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        let artifact_id = Uuid::now_v7();
        let media = br#"{"dimension":"image_samples","requested":1}"#.to_vec();
        let media_digest = hex_lower(&Sha256::digest(&media));
        {
            let db = Db::open(&path).unwrap();
            let setup_media = media.clone();
            let setup_media_digest = media_digest.clone();
            db.blocking_for_sync_cli(move |conn|{
                let(plan,digest)=canonical_test_plan(job_id,slot_id,artifact_id,1,1,100);
                let verified=CreateImageGenerationJob::from_verified_canonical_plan(&plan,&digest,1)?;
                Db::create_image_generation_graph_conn(conn,&verified,&[CreateImageGenerationSlot{slot_id,slot_index:0,sample_index:0,managed_artifact_id:artifact_id,attempts:vec![CreateImageGenerationAttempt{attempt_number:1,provider_request_identity:"request:1".into(),provider_idempotency_identity:"idem:1".into()}]}])?;
                let authority=Db::image_generation_queue_authority_conn(conn,job_id)?;
                Db::queue_image_generation_job_conn(conn,authority,&[ImageGenerationMediaPlanSnapshot{slot_id,attempt_number:1,canonical_bytes:&setup_media,digest:&setup_media_digest}],1)?;
                assert!(conn.execute("UPDATE image_generation_attempt_media_snapshots SET canonical_media_plan=X'00' WHERE job_id=?1",[job_id.to_string()]).is_err());
                assert!(conn.execute("DELETE FROM image_generation_attempt_media_snapshots WHERE job_id=?1",[job_id.to_string()]).is_err());
                Ok(())
            }).unwrap();
        }
        let reopened = Db::open(&path).unwrap();
        reopened
            .blocking_for_sync_cli(move |conn| {
                let rows = Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    DeadlineObservationV1::new(
                        Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa),
                        0,
                    )?,
                    1,
                )?;
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].job_id, job_id);
                assert_eq!(rows[0].canonical_media_plan, media);
                assert_eq!(rows[0].media_plan_digest, media_digest);
                let boot = Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa);
                assert_eq!(
                    Db::scan_image_generation_dispatch_candidates_conn(
                        conn,
                        DeadlineObservationV1::new(boot, 99)?,
                        1,
                    )?
                    .len(),
                    1
                );
                assert!(Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    DeadlineObservationV1::new(boot, 100)?,
                    1,
                )?
                .is_empty());
                assert!(Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    DeadlineObservationV1::new(boot, 101)?,
                    1,
                )?
                .is_empty());
                assert!(Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    DeadlineObservationV1::new(Uuid::now_v7(), 0)?,
                    1,
                )?
                .is_empty());
                conn.execute(
                    "UPDATE image_generation_jobs SET created_at_unix_ms=-9000000000000,updated_at_unix_ms=9000000000000 WHERE job_id=?1",
                    [job_id.to_string()],
                )?;
                assert_eq!(
                    Db::scan_image_generation_dispatch_candidates_conn(
                        conn,
                        DeadlineObservationV1::new(boot, 99)?,
                        1,
                    )?
                    .len(),
                    1
                );
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn heterogeneous_attempt_media_snapshots_bind_exact_maxima_and_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("heterogeneous.db");
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        let artifact_id = Uuid::now_v7();
        let first = br#"{"dimension":"image_samples","requested":1}"#.to_vec();
        let second = br#"{"dimension":"image_samples","requested":7}"#.to_vec();
        let first_digest = hex_lower(&Sha256::digest(&first));
        let second_digest = hex_lower(&Sha256::digest(&second));
        {
            let db = Db::open(&path).unwrap();
            let queued_first = first.clone();
            let queued_second = second.clone();
            let queued_first_digest = first_digest.clone();
            let queued_second_digest = second_digest.clone();
            db.blocking_for_sync_cli(move |conn| {
                let (canonical, digest) =
                    canonical_test_plan(job_id, slot_id, artifact_id, 2, 1, 100);
                let mut plan = ImageGenerationPlanV1::from_canonical(&canonical, &digest)?;
                plan.targets[0].slots[0].attempts[1].resource_maximum[0].units = 7;
                plan.central_resources[0].units = 8;
                let canonical = plan.canonical_bytes()?;
                let digest = plan.digest()?;
                let verified =
                    CreateImageGenerationJob::from_verified_canonical_plan(&canonical, &digest, 1)?;
                Db::create_image_generation_graph_conn(
                    conn,
                    &verified,
                    &[CreateImageGenerationSlot {
                        slot_id,
                        slot_index: 0,
                        sample_index: 0,
                        managed_artifact_id: artifact_id,
                        attempts: vec![
                            CreateImageGenerationAttempt {
                                attempt_number: 1,
                                provider_request_identity: "request:1".into(),
                                provider_idempotency_identity: "idem:1".into(),
                            },
                            CreateImageGenerationAttempt {
                                attempt_number: 2,
                                provider_request_identity: "request:2".into(),
                                provider_idempotency_identity: "idem:2".into(),
                            },
                        ],
                    }],
                )?;
                let wrong = [
                    ImageGenerationMediaPlanSnapshot {
                        slot_id,
                        attempt_number: 1,
                        canonical_bytes: &queued_first,
                        digest: &queued_first_digest,
                    },
                    ImageGenerationMediaPlanSnapshot {
                        slot_id,
                        attempt_number: 2,
                        canonical_bytes: &queued_first,
                        digest: &queued_first_digest,
                    },
                ];
                assert!(
                    Db::queue_image_generation_job_conn(
                        conn,
                        Db::image_generation_queue_authority_conn(conn, job_id)?,
                        &wrong,
                        1,
                    )
                    .is_err()
                );
                let exact = [
                    ImageGenerationMediaPlanSnapshot {
                        slot_id,
                        attempt_number: 1,
                        canonical_bytes: &queued_first,
                        digest: &queued_first_digest,
                    },
                    ImageGenerationMediaPlanSnapshot {
                        slot_id,
                        attempt_number: 2,
                        canonical_bytes: &queued_second,
                        digest: &queued_second_digest,
                    },
                ];
                Db::queue_image_generation_job_conn(
                    conn,
                    Db::image_generation_queue_authority_conn(conn, job_id)?,
                    &exact,
                    2,
                )?;
                Ok(())
            })
            .unwrap();
        }
        let reopened = Db::open(&path).unwrap();
        reopened
            .blocking_for_sync_cli(move |conn| {
                // Only the initially activated attempt is a dispatch candidate;
                // attempt 2 remains planned+snapshotted until retry activation.
                let rows = Db::scan_image_generation_dispatch_candidates_conn(
                    conn,
                    DeadlineObservationV1::new(
                        Uuid::from_u128(0xaaaaaaaa_aaaa_4aaa_8aaa_aaaaaaaaaaaa),
                        3,
                    )?,
                    2,
                )?;
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].attempt_number, 1);
                assert_eq!(rows[0].canonical_media_plan, first);
                let snapshots: Vec<(i64, Vec<u8>)> = {
                    let mut statement = conn.prepare(
                        "SELECT attempt_number,canonical_media_plan FROM image_generation_attempt_media_snapshots WHERE job_id=?1 ORDER BY attempt_number",
                    )?;
                    statement
                        .query_map([job_id.to_string()], |row| {
                            Ok((row.get(0)?, row.get(1)?))
                        })?
                        .collect::<rusqlite::Result<_>>()?
                };
                assert_eq!(
                    snapshots,
                    vec![(1, first.clone()), (2, second.clone())]
                );
                let maxima = snapshots
                    .iter()
                    .map(|(_, plan)| {
                        serde_json::from_slice::<serde_json::Value>(plan).unwrap()["requested"]
                            .as_u64()
                            .unwrap()
                    })
                    .collect::<Vec<_>>();
                assert_eq!(maxima, vec![1, 7]);
                assert_eq!(maxima.into_iter().sum::<u64>(), 8);
                assert!(conn
                    .execute(
                        "UPDATE image_generation_attempt_media_snapshots SET canonical_media_plan=?1 WHERE job_id=?2 AND attempt_number=2",
                        params![rows[0].canonical_media_plan, job_id.to_string()],
                    )
                    .is_err());
                Ok(())
            })
            .unwrap();
    }

    fn reconciliation_fixture(conn: &Connection) -> Result<RaceFixture> {
        let job_id = Uuid::now_v7();
        let slot_id = Uuid::now_v7();
        let artifact_id = Uuid::now_v7();
        let operation_id = Uuid::now_v7();
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
        conn.execute("INSERT INTO external_journal_operations(operation_id,operation_kind,owner_session_id,idempotency_key,payload_digest,payload_len,state,version,created_at_wall_ms,updated_at_wall_ms) VALUES(?1,'image_generation','owner','idem',?2,1,'reconciling',2,1,1)",params![operation_id.to_string(),"1".repeat(64)])?;
        for (state, version) in [
            ("preparing", 2),
            ("prepared", 3),
            ("dispatching", 4),
            ("submission_unknown", 5),
            ("reconciling", 6),
        ] {
            conn.execute("UPDATE image_generation_attempts SET state=?1,version=?2,dispatch_proof_endpoint_id='seed-endpoint',dispatch_proof_config_generation=1,dispatch_proof_refresh_epoch=1,dispatch_proof_connected_ip='127.0.0.1',dispatch_proof_location_class='loopback',dispatch_proof_hops_digest='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',external_operation_id=?3,observed_journal_version=2 WHERE job_id=?4 AND slot_id=?5",params![state,version,operation_id.to_string(),job_id.to_string(),slot_id.to_string()])?;
        }
        for (state, version) in [("queued", 2), ("dispatching", 3), ("submission_unknown", 4)] {
            conn.execute("UPDATE image_generation_slots SET state=?1,version=?2 WHERE job_id=?3 AND slot_id=?4",params![state,version,job_id.to_string(),slot_id.to_string()])?;
        }
        for (state, version) in [
            ("validating", 2),
            ("queued", 3),
            ("dispatching", 4),
            ("submission_unknown", 5),
        ] {
            conn.execute(
                "UPDATE image_generation_jobs SET state=?1,version=?2 WHERE job_id=?3",
                params![state, version, job_id.to_string()],
            )?;
        }
        let fixture = RaceFixture {
            job_id,
            slot_id,
            operation_id,
        };
        Ok(fixture)
    }

    fn reconciliation_snapshot(conn: &Connection, fixture: &RaceFixture) -> Result<String> {
        conn.query_row(
            "SELECT j.state||':'||j.version||':'||a.state||':'||a.version||':'||s.state||':'||s.version||':'||g.state||':'||g.version||':'||(SELECT COUNT(*) FROM image_generation_reconciliation_evidence e WHERE e.job_id=g.job_id) FROM external_journal_operations j JOIN image_generation_attempts a ON a.external_operation_id=j.operation_id JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id JOIN image_generation_jobs g ON g.job_id=s.job_id WHERE g.job_id=?1",
            [fixture.job_id.to_string()],
            |row| row.get(0),
        ).map_err(Into::into)
    }

    fn insert_submission_unknown_handoff_evidence(
        conn: &Connection,
        fixture: &RaceFixture,
    ) -> Result<()> {
        let evidence = b"submission outcome unknown";
        conn.execute(
            "INSERT INTO image_generation_handoff_evidence(job_id,slot_id,attempt_number,external_operation_id,outcome,evidence,evidence_digest,recorded_at_unix_ms) VALUES(?1,?2,1,?3,'submission_unknown',?4,?5,1)",
            params![
                fixture.job_id.to_string(),
                fixture.slot_id.to_string(),
                fixture.operation_id.to_string(),
                evidence,
                hex_lower(&Sha256::digest(evidence)),
            ],
        )?;
        Ok(())
    }

    #[test]
    fn reconciliation_claim_expiry_generation_and_boot_fence_survive_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("reconciliation-claims.db");
        let first_boot = Uuid::now_v7();
        let second_boot = Uuid::now_v7();
        let fixture;
        let stale_proof;
        {
            let db = Db::open(&path).unwrap();
            (fixture, stale_proof) = db
                .blocking_for_sync_cli(move |conn| {
                    let fixture = reconciliation_fixture(conn)?;
                    insert_submission_unknown_handoff_evidence(conn, &fixture)?;
                    let first = Db::claim_image_generation_reconciliation_conn(
                        conn,
                        &ClaimImageGenerationReconciliation {
                            job_id: fixture.job_id,
                            slot_id: fixture.slot_id,
                            attempt_number: 1,
                            worker_boot_id: first_boot,
                            claim_generation: 1,
                            now_unix_ms: 10,
                        },
                    )?;
                    let provider = first.provider_request_identity.clone();
                    let idempotency = first.provider_idempotency_identity.clone();
                    let payload = first.journal_payload_digest.clone();
                    let external_operation_id = first.external_operation_id;
                    let journal_version = first.journal_version;
                    let stale = first.verify(ImageGenerationReconciliationObservation {
                        provider_request_identity: &provider,
                        provider_idempotency_identity: &idempotency,
                        external_operation_id,
                        journal_version,
                        journal_payload_digest: &payload,
                        evidence_bytes: b"accepted\0first worker",
                        outcome: ImageGenerationReconciliationOutcome::AuthoritativeAccepted,
                        now_unix_ms: 60_011,
                    })?;
                    for now in [60_009, 60_009] {
                        assert!(
                            Db::claim_image_generation_reconciliation_conn(
                                conn,
                                &ClaimImageGenerationReconciliation {
                                    job_id: fixture.job_id,
                                    slot_id: fixture.slot_id,
                                    attempt_number: 1,
                                    worker_boot_id: second_boot,
                                    claim_generation: 2,
                                    now_unix_ms: now,
                                },
                            )
                            .is_err()
                        );
                    }
                    Ok((fixture, stale))
                })
                .unwrap();
        }
        Db::open(&path)
            .unwrap()
            .blocking_for_sync_cli(move |conn| {
                let current = Db::claim_image_generation_reconciliation_conn(
                    conn,
                    &ClaimImageGenerationReconciliation {
                        job_id: fixture.job_id,
                        slot_id: fixture.slot_id,
                        attempt_number: 1,
                        worker_boot_id: second_boot,
                        claim_generation: 2,
                        now_unix_ms: 60_010,
                    },
                )?;
                assert!(
                    Db::claim_image_generation_reconciliation_conn(
                        conn,
                        &ClaimImageGenerationReconciliation {
                            job_id: fixture.job_id,
                            slot_id: fixture.slot_id,
                            attempt_number: 1,
                            worker_boot_id: Uuid::now_v7(),
                            claim_generation: 2,
                            now_unix_ms: 60_010,
                        },
                    )
                    .is_err()
                );
                assert!(Db::reconcile_image_generation_attempt_conn(conn, &stale_proof).is_err());
                assert_eq!(current.claim_generation, Some(2));
                assert_eq!(current.claim_worker_boot_id, Some(second_boot));
                Ok(())
            })
            .unwrap();
    }

    #[test]
    fn reconciliation_changed_outcome_or_evidence_cannot_replace_committed_fact() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let fixture = reconciliation_fixture(conn)?;
            let first = verified_reconciliation(
                conn,
                fixture.job_id,
                fixture.slot_id,
                1,
                ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance,
                b"first evidence",
                20,
            )?;
            let changed = verified_reconciliation(
                conn,
                fixture.job_id,
                fixture.slot_id,
                1,
                ImageGenerationReconciliationOutcome::AuthoritativeFailure,
                b"changed evidence",
                20,
            )?;
            Db::reconcile_image_generation_attempt_conn(conn, &first)?;
            let committed: (String, String, i64) = conn.query_row(
                "SELECT outcome,evidence_digest,COUNT(*) FROM image_generation_reconciliation_evidence WHERE job_id=?1",
                [fixture.job_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(committed.0, "authoritative_nonacceptance");
            assert!(Db::reconcile_image_generation_attempt_conn(conn, &changed).is_err());
            let unchanged: (String, String, i64) = conn.query_row(
                "SELECT outcome,evidence_digest,COUNT(*) FROM image_generation_reconciliation_evidence WHERE job_id=?1",
                [fixture.job_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )?;
            assert_eq!(unchanged, committed);
            Ok(())
        })
        .unwrap();
    }

    fn verified_reconciliation(
        conn: &Connection,
        job_id: Uuid,
        slot_id: Uuid,
        attempt_number: u32,
        outcome: ImageGenerationReconciliationOutcome,
        evidence: &[u8],
        now_unix_ms: i64,
    ) -> Result<VerifiedImageGenerationReconciliationProof> {
        let authority =
            Db::image_generation_recovery_authority_conn(conn, job_id, slot_id, attempt_number)?;
        let provider = authority.provider_request_identity.clone();
        let idempotency = authority.provider_idempotency_identity.clone();
        let payload = authority.journal_payload_digest.clone();
        let prefix: &[u8] = match outcome {
            ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance => b"nonacceptance\0",
            ImageGenerationReconciliationOutcome::AuthoritativeAccepted => b"accepted\0",
            ImageGenerationReconciliationOutcome::AuthoritativeFailure => {
                b"postacceptance_failure\0"
            }
        };
        let mut bound = prefix.to_vec();
        bound.extend_from_slice(evidence);
        let observation = ImageGenerationReconciliationObservation {
            provider_request_identity: &provider,
            provider_idempotency_identity: &idempotency,
            external_operation_id: authority.external_operation_id,
            journal_version: authority.journal_version,
            journal_payload_digest: &payload,
            evidence_bytes: &bound,
            outcome,
            now_unix_ms,
        };
        authority.verify(observation)
    }

    #[test]
    fn recovery_authority_rejects_every_forged_observation_field() {
        for field in [
            "provider",
            "idempotency",
            "operation",
            "version",
            "payload",
            "outcome",
            "oversize",
        ] {
            let db = Db::open_in_memory().unwrap();
            db.blocking_for_sync_cli(move |conn| {
                let fixture = reconciliation_fixture(conn)?;
                let authority = Db::image_generation_recovery_authority_conn(
                    conn,
                    fixture.job_id,
                    fixture.slot_id,
                    1,
                )?;
                let mut provider = authority.provider_request_identity.clone();
                let mut idempotency = authority.provider_idempotency_identity.clone();
                let mut operation = authority.external_operation_id;
                let mut version = authority.journal_version;
                let mut payload = authority.journal_payload_digest.clone();
                let mut outcome = ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance;
                let mut evidence = b"nonacceptance\0evidence".to_vec();
                match field {
                    "provider" => provider.push('x'),
                    "idempotency" => idempotency.push('x'),
                    "operation" => operation = Uuid::now_v7(),
                    "version" => version += 1,
                    "payload" => payload = "f".repeat(64),
                    "outcome" => {
                        outcome = ImageGenerationReconciliationOutcome::AuthoritativeFailure
                    }
                    "oversize" => {
                        evidence =
                            vec![b'x'; MAX_IMAGE_GENERATION_RECONCILIATION_EVIDENCE_BYTES + 1]
                    }
                    _ => unreachable!(),
                }
                let observation = ImageGenerationReconciliationObservation {
                    provider_request_identity: &provider,
                    provider_idempotency_identity: &idempotency,
                    external_operation_id: operation,
                    journal_version: version,
                    journal_payload_digest: &payload,
                    evidence_bytes: &evidence,
                    outcome,
                    now_unix_ms: 20,
                };
                assert!(authority.verify(observation).is_err(), "{field}");
                Ok(())
            })
            .unwrap();
        }
    }

    #[test]
    fn reconciliation_outcomes_are_atomic_across_every_durable_cut() {
        for outcome in [
            ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance,
            ImageGenerationReconciliationOutcome::AuthoritativeFailure,
        ] {
            for (cut, trigger) in [
                (
                    "journal",
                    "CREATE TEMP TRIGGER cut BEFORE UPDATE ON external_journal_operations BEGIN SELECT RAISE(ABORT,'cut'); END",
                ),
                (
                    "evidence",
                    "CREATE TEMP TRIGGER cut BEFORE INSERT ON image_generation_reconciliation_evidence BEGIN SELECT RAISE(ABORT,'cut'); END",
                ),
                (
                    "attempt",
                    "CREATE TEMP TRIGGER cut BEFORE UPDATE ON image_generation_attempts BEGIN SELECT RAISE(ABORT,'cut'); END",
                ),
                (
                    "slot",
                    "CREATE TEMP TRIGGER cut BEFORE UPDATE ON image_generation_slots BEGIN SELECT RAISE(ABORT,'cut'); END",
                ),
                (
                    "job",
                    "CREATE TEMP TRIGGER cut BEFORE UPDATE ON image_generation_jobs BEGIN SELECT RAISE(ABORT,'cut'); END",
                ),
                (
                    "terminal_event",
                    "CREATE TEMP TRIGGER cut BEFORE INSERT ON image_generation_terminal_events BEGIN SELECT RAISE(ABORT,'cut'); END",
                ),
            ] {
                let db = Db::open_in_memory().unwrap();
                db.blocking_for_sync_cli(move |conn| {
                    let fixture = reconciliation_fixture(conn)?;
                    let before = reconciliation_snapshot(conn, &fixture)?;
                    conn.execute_batch(trigger)?;
                    let proof = verified_reconciliation(
                        conn,
                        fixture.job_id,
                        fixture.slot_id,
                        1,
                        outcome,
                        b"authoritative provider evidence",
                        20,
                    )?;
                    let result = Db::reconcile_image_generation_attempt_conn(conn, &proof);
                    ensure!(result.is_err(), "{cut} cut unexpectedly committed");
                    conn.execute_batch("DROP TRIGGER cut")?;
                    ensure!(
                        reconciliation_snapshot(conn, &fixture)? == before,
                        "{cut} cut left a partial projection"
                    );
                    Ok(())
                })
                .unwrap();
            }
        }
    }

    #[test]
    fn reconciliation_outcomes_commit_exact_bound_evidence_once() {
        for outcome in [
            ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance,
            ImageGenerationReconciliationOutcome::AuthoritativeFailure,
        ] {
            let db = Db::open_in_memory().unwrap();
            db.blocking_for_sync_cli(move|conn|{
                let fixture=reconciliation_fixture(conn)?;
                assert!(conn.execute("UPDATE image_generation_jobs SET state='failed',version=version+1,terminal_event_version=version+1 WHERE job_id=?1",[fixture.job_id.to_string()]).is_err());
                let proof=verified_reconciliation(conn,fixture.job_id,fixture.slot_id,1,outcome,b"authoritative provider evidence",20)?;
                Db::reconcile_image_generation_attempt_conn(conn,&proof)?;
                let row:(String,String,String,String,String,i64)=conn.query_row("SELECT e.evidence_digest,e.provider_request_identity,e.provider_idempotency_identity,e.journal_payload_digest,a.state,COUNT(*) FROM image_generation_reconciliation_evidence e JOIN image_generation_attempts a ON a.job_id=e.job_id AND a.slot_id=e.slot_id AND a.attempt_number=e.attempt_number WHERE e.job_id=?1",[fixture.job_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?,row.get(5)?)))?;
                let prefix:&[u8]=match outcome{ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance=>b"nonacceptance\0",ImageGenerationReconciliationOutcome::AuthoritativeAccepted=>b"accepted\0",ImageGenerationReconciliationOutcome::AuthoritativeFailure=>b"postacceptance_failure\0"};let mut expected_evidence=prefix.to_vec();expected_evidence.extend_from_slice(b"authoritative provider evidence");
                assert_eq!(row.0,hex_lower(&Sha256::digest(expected_evidence)));
                assert_eq!(row.1,"request:1");
                assert_eq!(row.2,"idem:1");
                assert_eq!(row.3,"1".repeat(64));
                assert_eq!(row.5,1);
                let expected=match outcome{ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance=>"rejected_not_accepted",ImageGenerationReconciliationOutcome::AuthoritativeAccepted=>"accepted",ImageGenerationReconciliationOutcome::AuthoritativeFailure=>"failed_after_acceptance"};
                assert_eq!(row.4,expected);
                let event=Db::replay_image_generation_terminal_event_conn(conn,fixture.job_id)?.context("terminal event missing")?;
                assert_eq!(event.job_id,fixture.job_id);
                assert_eq!(event.slot_count,1);
                assert_eq!(event.failed_count,1);
                assert_eq!(Db::replay_image_generation_terminal_event_conn(conn,fixture.job_id)?,Some(event));
                assert!(conn.execute("UPDATE image_generation_terminal_events SET emitted_at_unix_ms=21 WHERE job_id=?1",[fixture.job_id.to_string()]).is_err());
                assert!(conn.execute("DELETE FROM image_generation_terminal_events WHERE job_id=?1",[fixture.job_id.to_string()]).is_err());
                assert!(Db::image_generation_recovery_authority_conn(conn,fixture.job_id,fixture.slot_id,1).is_err());
                Ok(())
            }).unwrap();
        }
    }

    #[test]
    fn terminal_event_survives_file_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("terminal-event.db");
        let job_id;
        {
            let db = Db::open(&path).unwrap();
            job_id = db
                .blocking_for_sync_cli(|conn| {
                    let fixture = reconciliation_fixture(conn)?;
                    let proof = verified_reconciliation(
                        conn,
                        fixture.job_id,
                        fixture.slot_id,
                        1,
                        ImageGenerationReconciliationOutcome::AuthoritativeFailure,
                        b"terminal reopen evidence",
                        20,
                    )?;
                    Db::reconcile_image_generation_attempt_conn(conn, &proof)?;
                    Ok(fixture.job_id)
                })
                .unwrap();
        }
        Db::open(&path)
            .unwrap()
            .blocking_for_sync_cli(move |conn| {
                let event = Db::replay_image_generation_terminal_event_conn(conn, job_id)?
                    .context("reopened terminal event missing")?;
                assert_eq!(event.terminal_state, ImageGenerationJobState::Failed);
                assert_eq!(event.failed_count, 1);
                Ok(())
            })
            .unwrap();
    }

    /// One terminal slot for the disjoint-partition fixture. `disposition` and
    /// `disposition_generation` are only set for published slots.
    struct TerminalSlotSpec {
        state: &'static str,
        result_after_cancel: i64,
        applied_cancellation_version: Option<i64>,
        disposition: Option<&'static str>,
    }

    /// Seal a job whose slots are already in the given terminal states (INSERTed
    /// directly, which bypasses the UPDATE-only slot transition guard) so the
    /// terminal-event projection can be exercised for exotic partitions such as
    /// late-then-published. Returns the job id.
    fn seal_terminal_partition_job(conn: &Connection, specs: &[TerminalSlotSpec]) -> Result<Uuid> {
        let job_id = Uuid::now_v7();
        let slot_ids = specs.iter().map(|_| Uuid::now_v7()).collect::<Vec<_>>();
        let artifacts = specs.iter().map(|_| Uuid::now_v7()).collect::<Vec<_>>();
        let (bytes, _) = canonical_test_plan(job_id, slot_ids[0], artifacts[0], 1, 1, 100);
        let mut plan: ImageGenerationPlanV1 = serde_json::from_slice(&bytes)?;
        let template = plan.targets[0].slots[0].clone();
        plan.targets[0].slots = slot_ids
            .iter()
            .zip(&artifacts)
            .enumerate()
            .map(|(index, (slot_id, artifact_id))| {
                let mut slot = template.clone();
                slot.slot_id = *slot_id;
                slot.managed_artifact_id = *artifact_id;
                slot.slot_index = index as u32;
                slot.sample_index = index as u32;
                slot.publication_name = format!("generated-{index}.png");
                slot.attempts[0].provider_request_identity = format!("request:{index}");
                slot.attempts[0].provider_idempotency_identity = format!("idem:{index}");
                slot
            })
            .collect();
        plan.targets[0].sample_count = specs.len() as u32;
        plan.central_resources[0].units = specs.len() as u64;
        plan.spend.maximum_usd_micros = Some(specs.len() as u64);
        let bytes = plan.canonical_bytes()?;
        let digest = plan.digest()?;
        let verified = CreateImageGenerationJob::from_verified_canonical_plan(&bytes, &digest, 1)?;
        Db::create_image_generation_job_conn(conn, &verified)?;
        if specs
            .iter()
            .any(|spec| spec.applied_cancellation_version.is_some())
        {
            conn.execute(
                "INSERT INTO image_generation_cancellation_facts(job_id,cancellation_version,requested_at_unix_ms,request_operation_id) VALUES(?1,1,1,?2)",
                params![job_id.to_string(), format!("cancel:{job_id}")],
            )?;
        }
        for (index, (spec, (slot_id, artifact_id))) in specs
            .iter()
            .zip(slot_ids.iter().zip(&artifacts))
            .enumerate()
        {
            let version: i64 = 5;
            conn.execute(
                "INSERT INTO image_generation_slots(job_id,slot_id,slot_index,sample_index,managed_artifact_id,max_attempt_count,state,version,applied_cancellation_version,result_after_cancel,published_disposition,published_disposition_generation) VALUES(?1,?2,?3,?4,?5,1,?6,?7,?8,?9,?10,?11)",
                params![
                    job_id.to_string(),
                    slot_id.to_string(),
                    index as i64,
                    index as i64,
                    artifact_id.to_string(),
                    spec.state,
                    version,
                    spec.applied_cancellation_version,
                    spec.result_after_cancel,
                    spec.disposition,
                    spec.disposition.map(|_| version),
                ],
            )?;
        }
        Ok(job_id)
    }

    // AC9: terminal-event counts are a disjoint partition. A late-then-published
    // slot (published + result_after_cancel=1) is counted once, and the old
    // overlapping shape (counting it as ordinary published) is CHECK-rejected.
    #[test]
    fn image_generation_terminal_event_disjoint_partition_check() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            // Mixed after-cancel job: late-published, late-quarantined, discarded,
            // and a plain failed slot. Under the OLD formula this double-counted
            // the late-published slot (published_count AND late_count both 1), so
            // published+failed+cancelled+late = 1+1+0+3 = 5 > slot_count 4 and the
            // insert was impossible. The disjoint partition makes it representable.
            let mixed = seal_terminal_partition_job(
                conn,
                &[
                    TerminalSlotSpec {
                        state: "published",
                        result_after_cancel: 1,
                        applied_cancellation_version: Some(1),
                        disposition: Some("late_authorized"),
                    },
                    TerminalSlotSpec {
                        state: "late_quarantined",
                        result_after_cancel: 1,
                        applied_cancellation_version: Some(1),
                        disposition: None,
                    },
                    TerminalSlotSpec {
                        state: "discarded",
                        result_after_cancel: 1,
                        applied_cancellation_version: Some(1),
                        disposition: None,
                    },
                    TerminalSlotSpec {
                        state: "failed",
                        result_after_cancel: 0,
                        applied_cancellation_version: None,
                        disposition: None,
                    },
                ],
            )?;

            // (b) The old overlapping shape -- counting the late-published slot as
            // ordinary published (published_count=1) -- is rejected by the guard,
            // because published_count must equal count(published AND
            // result_after_cancel=0) = 0.
            let old_shape = conn.execute(
                "INSERT INTO image_generation_terminal_events(event_id,job_id,job_version,terminal_state,slot_count,published_count,failed_count,cancelled_count,late_published_count,late_quarantined_count,discarded_count,emitted_at_unix_ms) VALUES(?1,?2,2,'completed_after_cancel',4,1,1,0,0,1,1,9)",
                params![format!("forged:{mixed}"), mixed.to_string()],
            );
            assert!(
                old_shape.is_err(),
                "double-counting the late-published slot as ordinary published must be rejected"
            );

            // The exact numeric signature of the OLD bug -- the late-published
            // slot counted in BOTH the published bucket AND a "late" bucket -- is
            // also rejected. It both violates the disjoint per-partition guard
            // and would overflow the sum invariant (1+1+0+1+1+1 = 5 > slot_count
            // 4): under the disjoint scheme such an overlap can no longer be
            // expressed as a valid row at all, which is exactly why a
            // late-then-published job was unrepresentable under the old formula.
            let old_overlap = conn.execute(
                "INSERT INTO image_generation_terminal_events(event_id,job_id,job_version,terminal_state,slot_count,published_count,failed_count,cancelled_count,late_published_count,late_quarantined_count,discarded_count,emitted_at_unix_ms) VALUES(?1,?2,2,'completed_after_cancel',4,1,1,0,1,1,1,9)",
                params![format!("forged-overlap:{mixed}"), mixed.to_string()],
            );
            assert!(
                old_overlap.is_err(),
                "double-counting the late slot in both published and late buckets must overflow the sum CHECK"
            );

            // (a) The disjoint projection commits cleanly with completed_after_cancel.
            let terminal = commit_terminal_job_projection_conn(conn, mixed, 10)?;
            assert_eq!(terminal, Some(ImageGenerationJobState::CompletedAfterCancel));
            let event = Db::replay_image_generation_terminal_event_conn(conn, mixed)?
                .context("mixed terminal event missing")?;
            assert_eq!(event.slot_count, 4);
            assert_eq!(event.published_count, 0);
            assert_eq!(event.late_published_count, 1);
            assert_eq!(event.late_quarantined_count, 1);
            assert_eq!(event.discarded_count, 1);
            assert_eq!(event.failed_count, 1);
            assert_eq!(event.cancelled_count, 0);
            assert_eq!(
                event.terminal_state,
                ImageGenerationJobState::CompletedAfterCancel
            );
            // Sum of the disjoint partitions equals slot_count by construction.
            assert_eq!(
                event.published_count
                    + event.late_published_count
                    + event.late_quarantined_count
                    + event.discarded_count
                    + event.failed_count
                    + event.cancelled_count,
                event.slot_count
            );

            // A pure all-published job still projects to Completed.
            let all_published = seal_terminal_partition_job(
                conn,
                &[
                    TerminalSlotSpec {
                        state: "published",
                        result_after_cancel: 0,
                        applied_cancellation_version: None,
                        disposition: Some("ordinary"),
                    },
                    TerminalSlotSpec {
                        state: "published",
                        result_after_cancel: 0,
                        applied_cancellation_version: None,
                        disposition: Some("ordinary"),
                    },
                ],
            )?;
            assert_eq!(
                commit_terminal_job_projection_conn(conn, all_published, 11)?,
                Some(ImageGenerationJobState::Completed)
            );
            let completed = Db::replay_image_generation_terminal_event_conn(conn, all_published)?
                .context("all-published terminal event missing")?;
            assert_eq!(completed.published_count, 2);
            assert_eq!(completed.late_published_count, 0);

            // A pure all-cancelled job still projects to Cancelled.
            let all_cancelled = seal_terminal_partition_job(
                conn,
                &[
                    TerminalSlotSpec {
                        state: "cancelled",
                        result_after_cancel: 0,
                        applied_cancellation_version: Some(1),
                        disposition: None,
                    },
                    TerminalSlotSpec {
                        state: "cancelled",
                        result_after_cancel: 0,
                        applied_cancellation_version: Some(1),
                        disposition: None,
                    },
                ],
            )?;
            assert_eq!(
                commit_terminal_job_projection_conn(conn, all_cancelled, 12)?,
                Some(ImageGenerationJobState::Cancelled)
            );
            let cancelled = Db::replay_image_generation_terminal_event_conn(conn, all_cancelled)?
                .context("all-cancelled terminal event missing")?;
            assert_eq!(cancelled.cancelled_count, 2);
            assert_eq!(cancelled.published_count, 0);
            Ok(())
        })
        .unwrap();
    }

    fn cancel_mixed(
        conn: &Connection,
        fixture: &MixedFixture,
    ) -> Result<ImageGenerationCasOutcome> {
        Db::request_image_generation_cancellation_conn(
            conn,
            &RequestImageGenerationCancellation {
                job_id: fixture.job_id,
                cancellation_version: 1,
                request_operation_id: "cancel:mixed",
                requested_at_unix_ms: 10,
            },
        )
    }

    #[test]
    fn mixed_four_slot_cancellation_is_atomic_and_replay_exact() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn|{
            let fixture=mixed_fixture(conn)?; let outcome=cancel_mixed(conn,&fixture)?; assert_eq!(outcome,ImageGenerationCasOutcome::Applied{version:5});
            let states=conn.prepare("SELECT state,version,applied_cancellation_version,result_after_cancel FROM image_generation_slots WHERE job_id=?1 ORDER BY slot_index")?.query_map([fixture.job_id.to_string()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,i64>(3)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(states,vec![("published".into(),8,None,0),("validating".into(),7,Some(1),1),("cancelled".into(),2,Some(1),0),("cancellation_requested".into(),5,Some(1),0)]);
            let attempts=conn.prepare("SELECT state,version,applied_cancellation_version FROM image_generation_attempts WHERE job_id=?1 ORDER BY slot_id")?.query_map([fixture.job_id.to_string()],|row|Ok((row.get::<_,String>(0)?,row.get::<_,i64>(1)?,row.get::<_,Option<i64>>(2)?)))?.collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(attempts.iter().filter(|row|row.0=="completed_after_cancel"&&row.2==Some(1)).count(),1);
            assert_eq!(attempts.iter().filter(|row|row.0=="cancelled"&&row.2==Some(1)).count(),1);
            assert_eq!(attempts.iter().filter(|row|row.0=="cancellation_requested"&&row.2==Some(1)).count(),1);
            let facts:i64=conn.query_row("SELECT COUNT(*) FROM image_generation_cancelled_result_facts WHERE job_id=?1 AND cancellation_version=1 AND ordering='response_adopted_before_cancellation'",[fixture.job_id.to_string()],|row|row.get(0))?; assert_eq!(facts,1);
            let journal:(String,i64)=conn.query_row("SELECT state,version FROM external_journal_operations WHERE operation_id=?1",[fixture.operations[2].to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
            assert_eq!(journal,("cancellation_requested".into(),3));
            let before=mixed_snapshot(conn,fixture.job_id)?; assert_eq!(cancel_mixed(conn,&fixture)?,ImageGenerationCasOutcome::Applied{version:5}); assert_eq!(mixed_snapshot(conn,fixture.job_id)?,before);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn mixed_cancellation_rolls_back_at_every_write_boundary() {
        for (cut, trigger) in [
            (
                "fact",
                "CREATE TEMP TRIGGER cut BEFORE INSERT ON image_generation_cancellation_facts BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
            (
                "journal",
                "CREATE TEMP TRIGGER cut BEFORE UPDATE ON external_journal_operations BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
            (
                "result",
                "CREATE TEMP TRIGGER cut BEFORE INSERT ON image_generation_cancelled_result_facts BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
            (
                "attempt",
                "CREATE TEMP TRIGGER cut BEFORE UPDATE ON image_generation_attempts BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
            (
                "slot",
                "CREATE TEMP TRIGGER cut BEFORE UPDATE ON image_generation_slots BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
            (
                "job",
                "CREATE TEMP TRIGGER cut BEFORE UPDATE ON image_generation_jobs BEGIN SELECT RAISE(ABORT,'cut'); END",
            ),
        ] {
            let db = Db::open_in_memory().unwrap();
            db.blocking_for_sync_cli(move |conn| {
                let fixture = mixed_fixture(conn)?;
                let before = mixed_snapshot(conn, fixture.job_id)?;
                conn.execute_batch(trigger)?;
                ensure!(cancel_mixed(conn, &fixture).is_err(), "{cut}");
                conn.execute_batch("DROP TRIGGER cut")?;
                ensure!(
                    mixed_snapshot(conn, fixture.job_id)? == before,
                    "{cut} left partial state"
                );
                Ok(())
            })
            .unwrap();
        }
    }

    #[test]
    fn cancelled_reconciling_slot_accepts_both_authoritative_outcomes() {
        for outcome in [
            ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance,
            ImageGenerationReconciliationOutcome::AuthoritativeFailure,
        ] {
            let db = Db::open_in_memory().unwrap();
            db.blocking_for_sync_cli(move|conn|{let fixture=mixed_fixture(conn)?;cancel_mixed(conn,&fixture)?;let proof=verified_reconciliation(conn,fixture.job_id,fixture.slots[3],1,outcome,b"mixed reconciliation",11)?;Db::reconcile_image_generation_attempt_conn(conn,&proof)?;let row:(String,String,Option<i64>)=conn.query_row("SELECT a.state,s.state,a.applied_cancellation_version FROM image_generation_attempts a JOIN image_generation_slots s ON s.job_id=a.job_id AND s.slot_id=a.slot_id WHERE a.job_id=?1 AND a.slot_id=?2",params![fixture.job_id.to_string(),fixture.slots[3].to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;let expected=match outcome{ImageGenerationReconciliationOutcome::AuthoritativeNonacceptance=>("cancelled","cancelled"),ImageGenerationReconciliationOutcome::AuthoritativeAccepted=>("accepted","cancellation_requested"),ImageGenerationReconciliationOutcome::AuthoritativeFailure=>("failed_after_acceptance","failed")};assert_eq!((row.0.as_str(),row.1.as_str(),row.2),(expected.0,expected.1,Some(1)));Ok(())}).unwrap();
        }
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
    fn mixed_multi_slot_terminal_matrix_has_one_deterministic_projection() {
        use ImageGenerationJobState as J;
        use ImageGenerationSlotState as S;
        let cases = [
            (
                vec![
                    (S::Published, false),
                    (S::Failed, false),
                    (S::Cancelled, false),
                ],
                Some(J::PartiallyFailed),
            ),
            (
                vec![
                    (S::Published, false),
                    (S::Discarded, true),
                    (S::Cancelled, false),
                ],
                Some(J::CompletedAfterCancel),
            ),
            (
                vec![
                    (S::LateQuarantined, true),
                    (S::Discarded, true),
                    (S::Cancelled, false),
                ],
                Some(J::CompletedAfterCancel),
            ),
            (
                vec![
                    (S::Published, false),
                    (S::Planned, false),
                    (S::Dispatching, false),
                ],
                None,
            ),
            (
                vec![
                    (S::SubmissionUnknown, false),
                    (S::CancellationRequested, false),
                    (S::Downloading, false),
                ],
                None,
            ),
        ];
        for (slots, expected) in cases {
            assert_eq!(reduce_terminal_job(&slots), expected, "{slots:?}");
            let reversed = slots.iter().copied().rev().collect::<Vec<_>>();
            assert_eq!(reduce_terminal_job(&reversed), expected, "{reversed:?}");
        }
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
                        states
                            .iter()
                            .filter(|to| allowed(from, to))
                            .map(|to| ((*from).to_owned(), (*to).to_owned()))
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

    #[test]
    fn image_generation_artifact_state_tables_are_exact_and_exhaustive() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            for &from in ImageGenerationArtifactState::ALL {
                for &to in ImageGenerationArtifactState::ALL {
                    let persisted: bool = conn.query_row(
                        "SELECT EXISTS(SELECT 1 FROM image_generation_artifact_transitions WHERE from_state=?1 AND to_state=?2)",
                        params![from.as_str(),to.as_str()],
                        |row| row.get(0),
                    )?;
                    assert_eq!(persisted,artifact_transition_allowed(from,to),"artifact: {} -> {}",from.as_str(),to.as_str());
                }
            }
            for &from in ImageGenerationArtifactComponentState::ALL {
                for &to in ImageGenerationArtifactComponentState::ALL {
                        let persisted: bool = conn.query_row(
                            "SELECT EXISTS(SELECT 1 FROM image_generation_component_transitions WHERE from_state=?1 AND to_state=?2)",
                            params![from.as_str(),to.as_str()],
                            |row| row.get(0),
                        )?;
                        assert_eq!(persisted,artifact_component_transition_allowed(from,to),"component: {} -> {}",from.as_str(),to.as_str());
                }
            }
            assert!(conn.execute("INSERT INTO image_generation_artifact_transitions VALUES('forged','ready')",[]).is_err());
            assert!(conn.execute("INSERT INTO image_generation_component_transitions VALUES('forged','ready')",[]).is_err());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn raw_security_recovery_audit_mutations_fail_closed() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let operation = Uuid::now_v7().to_string();
            conn.execute("INSERT INTO image_generation_artifact_security_recovery_attempts(recovery_operation_id,principal_digest,request_digest,state,created_at_unix_ms) VALUES(?1,?2,?3,'received',1)",params![operation,"a".repeat(64),"b".repeat(64)])?;
            assert!(conn.execute("UPDATE image_generation_artifact_security_recovery_attempts SET request_digest=?1 WHERE recovery_operation_id=?2",params!["c".repeat(64),operation]).is_err());
            assert!(conn.execute("UPDATE image_generation_artifact_security_recovery_attempts SET state='validated' WHERE recovery_operation_id=?1",[operation.clone()]).is_err());
            assert!(conn.execute("DELETE FROM image_generation_artifact_security_recovery_attempts WHERE recovery_operation_id=?1",[operation.clone()]).is_err());
            assert!(conn.execute("UPDATE image_generation_artifact_security_recovery_attempts SET outcome_digest=?1 WHERE recovery_operation_id=?2",params!["d".repeat(64),operation]).is_err());
            assert!(conn.execute("INSERT INTO image_generation_artifact_security_recovery_audits(recovery_operation_id,artifact_id,artifact_generation,job_id,slot_id,slot_generation,principal_digest,component_set_digest,component_identity_digest,disposition,state,created_at_unix_ms) VALUES(?1,?2,1,?3,?4,1,?5,?6,?7,'resume_verified_cleanup','recorded',1)",params![Uuid::now_v7().to_string(),Uuid::now_v7().to_string(),Uuid::now_v7().to_string(),Uuid::now_v7().to_string(),"a".repeat(64),"b".repeat(64),"c".repeat(64)]).is_err());
            assert!(conn.execute("INSERT INTO image_generation_artifact_security_recovery_components(recovery_operation_id,artifact_id,component_id,component_kind,component_generation,stable_identity_digest,security_digest,sha256) VALUES(?1,?2,?3,'primary',1,?4,?5,?6)",params![Uuid::now_v7().to_string(),Uuid::now_v7().to_string(),Uuid::now_v7().to_string(),"a".repeat(64),"b".repeat(64),"c".repeat(64)]).is_err());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn external_deletion_has_only_owned_restartable_edges() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let mut statement = conn.prepare("SELECT from_state,to_state FROM image_generation_late_publication_transitions WHERE from_state='delete_authorized' OR to_state='delete_authorized' ORDER BY from_state,to_state")?;
            let edges = statement
                .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            assert_eq!(edges, vec![("delete_authorized".into(), "aborted".into()), ("delete_authorized".into(), "security_blocked".into()), ("security_blocked".into(), "delete_authorized".into())]);
            assert!(conn.execute("INSERT INTO image_generation_late_publication_transitions(from_state,to_state) VALUES('delete_authorized','published')",[]).is_err());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn artifact_graph_creation_is_atomic_and_exactly_bound_to_sealed_slot() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let fixture=race_fixture(conn,false)?;
            let artifact_id=Uuid::parse_str(&conn.query_row::<String,_,_>("SELECT managed_artifact_id FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2",params![fixture.job_id.to_string(),fixture.slot_id.to_string()],|row|row.get(0))?)?;
            let component=CreateImageGenerationArtifactComponent{component_id:Uuid::now_v7(),kind:ImageGenerationArtifactComponentKind::Primary,relative_storage_key:format!("{artifact_id}/primary"),byte_length:u64::MAX,sha256:"a".repeat(64),resource_reservation_id:"resource_1".into(),release_operation_id:Uuid::now_v7()};
            let component_set_digest=image_generation_component_set_binding(std::slice::from_ref(&component))?.1;
            Db::create_image_generation_artifact_conn(conn,&CreateImageGenerationArtifact{artifact_id,job_id:fixture.job_id,slot_id:fixture.slot_id,component_set_digest,components:vec![component],now_unix_ms:1})?;
            let row:(String,i64,i64)=conn.query_row("SELECT state,generation,expected_component_count FROM image_generation_artifacts WHERE artifact_id=?1",[artifact_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            assert_eq!(row,("allocating".into(),1,1));
            let byte_length:(i64,i64)=conn.query_row("SELECT byte_length_hi,byte_length_lo FROM image_generation_artifact_components WHERE artifact_id=?1",[artifact_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
            assert_eq!(byte_length,(i64::from(u32::MAX),i64::from(u32::MAX)));
            let forged_component=CreateImageGenerationArtifactComponent{component_id:Uuid::now_v7(),kind:ImageGenerationArtifactComponentKind::Primary,relative_storage_key:"forged/primary".into(),byte_length:1,sha256:"d".repeat(64),resource_reservation_id:"resource_2".into(),release_operation_id:Uuid::now_v7()};
            let forged=CreateImageGenerationArtifact{artifact_id:Uuid::now_v7(),job_id:fixture.job_id,slot_id:fixture.slot_id,component_set_digest:image_generation_component_set_binding(std::slice::from_ref(&forged_component))?.1,components:vec![forged_component],now_unix_ms:2};
            assert!(Db::create_image_generation_artifact_conn(conn,&forged).is_err());
            let count:i64=conn.query_row("SELECT count(*) FROM image_generation_artifacts",[],|row|row.get(0))?;
            assert_eq!(count,1);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn artifact_cleanup_never_releases_before_exact_deletion_evidence() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let fixture=race_fixture(conn,false)?;
            let artifact_id=Uuid::parse_str(&conn.query_row::<String,_,_>("SELECT managed_artifact_id FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2",params![fixture.job_id.to_string(),fixture.slot_id.to_string()],|row|row.get(0))?)?;
            let component_id=Uuid::now_v7();
            let release_operation_id=Uuid::now_v7();
            let component=CreateImageGenerationArtifactComponent{component_id,kind:ImageGenerationArtifactComponentKind::Primary,relative_storage_key:format!("{artifact_id}/primary"),byte_length:9,sha256:"a".repeat(64),resource_reservation_id:"resource_1".into(),release_operation_id};
            let component_set_digest=image_generation_component_set_binding(std::slice::from_ref(&component))?.1;
            Db::create_image_generation_artifact_conn(conn,&CreateImageGenerationArtifact{artifact_id,job_id:fixture.job_id,slot_id:fixture.slot_id,component_set_digest,components:vec![component],now_unix_ms:1})?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:1,from:ImageGenerationArtifactState::Allocating,to:ImageGenerationArtifactState::Writing,now_unix_ms:2,terminal_reason:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:1,from:ImageGenerationArtifactComponentState::Planned,to:ImageGenerationArtifactComponentState::Writing,stable_identity_json:None,deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:2,from:ImageGenerationArtifactComponentState::Writing,to:ImageGenerationArtifactComponentState::Ready,stable_identity_json:Some("{\"held\":true}".into()),deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:2,from:ImageGenerationArtifactState::Writing,to:ImageGenerationArtifactState::Retained,now_unix_ms:3,terminal_reason:None})?;
            let cleanup_operation_id=Uuid::now_v7();
            Db::begin_image_generation_artifact_cleanup_conn(conn,&BeginImageGenerationArtifactCleanup{cleanup_operation_id,artifact_id,expected_generation:3,expected_state:ImageGenerationArtifactState::Retained,reason:ImageGenerationArtifactCleanupReason::InvalidOutput,now_unix_ms:4})?;
            conn.execute("UPDATE image_generation_artifact_cleanup_intents SET state='deleting',version=2 WHERE cleanup_operation_id=?1",[cleanup_operation_id.to_string()])?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:4,from:ImageGenerationArtifactState::CleanupPending,to:ImageGenerationArtifactState::Deleting,now_unix_ms:5,terminal_reason:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:3,from:ImageGenerationArtifactComponentState::Ready,to:ImageGenerationArtifactComponentState::CleanupPending,stable_identity_json:None,deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:4,from:ImageGenerationArtifactComponentState::CleanupPending,to:ImageGenerationArtifactComponentState::Deleting,stable_identity_json:None,deletion_evidence_digest:None})?;
            assert!(conn.execute("INSERT INTO image_generation_component_release_facts(artifact_id,component_id,release_operation_id,deletion_evidence_digest,committed_at_unix_ms) VALUES(?1,?2,?3,?4,6)",params![artifact_id.to_string(),component_id.to_string(),release_operation_id.to_string(),"c".repeat(64)]).is_err());
            Db::commit_image_generation_component_deletion_conn(conn,&CommitImageGenerationComponentDeletion{artifact_id,component_id,expected_generation:5,release_operation_id,deletion_evidence_digest:"d".repeat(64),committed_at_unix_ms:6})?;
            Db::finish_image_generation_artifact_cleanup_conn(conn,artifact_id,5,cleanup_operation_id,7,"invalid_output")?;
            let state:String=conn.query_row("SELECT state FROM image_generation_artifacts WHERE artifact_id=?1",[artifact_id.to_string()],|row|row.get(0))?;
            assert_eq!(state,"tombstoned");
            let releases:i64=conn.query_row("SELECT count(*) FROM image_generation_component_release_facts WHERE artifact_id=?1",[artifact_id.to_string()],|row|row.get(0))?;
            assert_eq!(releases,1);
            assert!(Db::commit_image_generation_component_deletion_conn(conn,&CommitImageGenerationComponentDeletion{artifact_id,component_id,expected_generation:5,release_operation_id,deletion_evidence_digest:"d".repeat(64),committed_at_unix_ms:6}).is_err());
            Ok(())
        }).unwrap();
    }

    #[test]
    fn artifact_lease_route_matrix_is_closed() {
        use ImageGenerationArtifactConsumerPurpose as P;
        use ImageGenerationArtifactConsumerRoute as R;
        use ImageGenerationArtifactReadKind as K;
        let allowed = [
            (P::ServeArtifact, R::ArtifactFull, K::Full),
            (P::ServeArtifact, R::ArtifactRange, K::Range),
            (P::ServeThumbnail, R::Thumbnail, K::Full),
            (P::ToolInput, R::Tool, K::Full),
            (P::ModelInput, R::ModelPayload, K::Full),
            (P::InternalVerification, R::Verification, K::Full),
            (P::InternalCleanup, R::Cleanup, K::Full),
        ];
        for &purpose in P::ALL {
            for &route in R::ALL {
                for &kind in K::ALL {
                    assert_eq!(
                        lease_route_valid(purpose, route, kind),
                        allowed.contains(&(purpose, route, kind)),
                        "{purpose:?}/{route:?}/{kind:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn artifact_lease_acquire_release_expiry_and_boot_repair_are_exact() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let fixture=race_fixture(conn,true)?;
            Db::commit_image_generation_publication_conn(conn,&CommitImageGenerationPublication{job_id:fixture.job_id,slot_id:fixture.slot_id,attempt_number:1,expected_attempt_version:7,expected_slot_version:7,artifact_generation:1,now_unix_ms:1})?;
            let artifact_id=Uuid::parse_str(&conn.query_row::<String,_,_>("SELECT managed_artifact_id FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2",params![fixture.job_id.to_string(),fixture.slot_id.to_string()],|row|row.get(0))?)?;
            let component_id=Uuid::now_v7(); let release_operation_id=Uuid::now_v7();
            let component=CreateImageGenerationArtifactComponent{component_id,kind:ImageGenerationArtifactComponentKind::Primary,relative_storage_key:format!("{artifact_id}/primary"),byte_length:9,sha256:"a".repeat(64),resource_reservation_id:"resource".into(),release_operation_id};
            let component_set_digest=image_generation_component_set_binding(std::slice::from_ref(&component))?.1;
            Db::create_image_generation_artifact_conn(conn,&CreateImageGenerationArtifact{artifact_id,job_id:fixture.job_id,slot_id:fixture.slot_id,component_set_digest:component_set_digest.clone(),components:vec![component],now_unix_ms:1})?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:1,from:ImageGenerationArtifactState::Allocating,to:ImageGenerationArtifactState::Writing,now_unix_ms:2,terminal_reason:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:1,from:ImageGenerationArtifactComponentState::Planned,to:ImageGenerationArtifactComponentState::Writing,stable_identity_json:None,deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:2,from:ImageGenerationArtifactComponentState::Writing,to:ImageGenerationArtifactComponentState::Ready,stable_identity_json:Some("{\"held\":true}".into()),deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:2,from:ImageGenerationArtifactState::Writing,to:ImageGenerationArtifactState::Retained,now_unix_ms:3,terminal_reason:None})?;
            let (job_generation,slot_generation):(i64,i64)=conn.query_row("SELECT j.version,s.version FROM image_generation_jobs j JOIN image_generation_slots s ON s.job_id=j.job_id WHERE j.job_id=?1 AND s.slot_id=?2",params![fixture.job_id.to_string(),fixture.slot_id.to_string()],|row|Ok((row.get(0)?,row.get(1)?)))?;
            assert_eq!(conn.query_row::<String,_,_>("SELECT state FROM image_generation_jobs WHERE job_id=?1",[fixture.job_id.to_string()],|row|row.get(0))?,"completed");
            let authorization_digest="b".repeat(64);
            conn.execute("INSERT INTO image_generation_artifact_authorization_facts(authorization_digest,artifact_id,artifact_generation,job_id,job_generation,slot_id,slot_generation,consumer_purpose,consumer_route,principal_digest,created_at_unix_ms) VALUES(?1,?2,3,?3,?4,?5,?6,'serve_artifact','artifact_full',?7,3)",params![authorization_digest,artifact_id.to_string(),fixture.job_id.to_string(),job_generation,fixture.slot_id.to_string(),slot_generation,"c".repeat(64)])?;
            let boot=Uuid::now_v7(); let lease=Uuid::now_v7();
            let checksum="a".repeat(64);
            let acquire=AcquireImageGenerationArtifactLease{lease_id:lease,artifact_id,expected_artifact_generation:3,job_id:fixture.job_id,expected_job_generation:u64::try_from(job_generation)?,slot_id:fixture.slot_id,expected_slot_generation:u64::try_from(slot_generation)?,disposition:ImageGenerationArtifactPublishedDisposition::Ordinary,expected_disposition_generation:u64::try_from(slot_generation)?,component_id,expected_component_kind:ImageGenerationArtifactComponentKind::Primary,expected_component_generation:3,expected_component_checksum:&checksum,purpose:ImageGenerationArtifactConsumerPurpose::ServeArtifact,route:ImageGenerationArtifactConsumerRoute::ArtifactFull,read_kind:ImageGenerationArtifactReadKind::Full,range_start:0,requested_length:9,component_set_digest:&component_set_digest,authorization_digest:&authorization_digest,daemon_boot_id:boot,committed_at_monotonic:100};
            Db::acquire_image_generation_artifact_lease_conn(conn,&acquire)?;
            assert!(!Db::expire_image_generation_artifact_lease_conn(conn,lease,60_099)?);
            assert!(conn.execute("UPDATE image_generation_artifact_leases SET deadline_monotonic=999999 WHERE lease_id=?1",[lease.to_string()]).is_err());
            assert!(Db::expire_image_generation_artifact_lease_conn(conn,lease,60_100)?);
            assert!(!Db::release_image_generation_artifact_lease_conn(conn,lease,60_101)?);
            let active:i64=conn.query_row("SELECT active_lease_count FROM image_generation_artifacts WHERE artifact_id=?1",[artifact_id.to_string()],|row|row.get(0))?; assert_eq!(active,0);
            let lease2=Uuid::now_v7(); let mut acquire2=acquire.clone(); acquire2.lease_id=lease2; acquire2.committed_at_monotonic=200;
            Db::acquire_image_generation_artifact_lease_conn(conn,&acquire2)?;
            assert_eq!(Db::repair_image_generation_artifact_leases_for_boot_conn(conn,Uuid::now_v7())?,1);
            let active:i64=conn.query_row("SELECT active_lease_count FROM image_generation_artifacts WHERE artifact_id=?1",[artifact_id.to_string()],|row|row.get(0))?; assert_eq!(active,0);
            Ok(())
        }).unwrap();
    }

    #[test]
    fn late_publication_is_fenced_and_finalizes_quarantine_once() {
        let db = Db::open_in_memory().unwrap();
        db.blocking_for_sync_cli(|conn| {
            let fixture=race_fixture(conn,true)?;
            Db::request_image_generation_cancellation_conn(conn,&RequestImageGenerationCancellation{job_id:fixture.job_id,cancellation_version:1,request_operation_id:"late_cancel",requested_at_unix_ms:2})?;
            let artifact_id=Uuid::parse_str(&conn.query_row::<String,_,_>("SELECT managed_artifact_id FROM image_generation_slots WHERE job_id=?1 AND slot_id=?2",params![fixture.job_id.to_string(),fixture.slot_id.to_string()],|row|row.get(0))?)?;
            let component_id=Uuid::now_v7();
            let component=CreateImageGenerationArtifactComponent{component_id,kind:ImageGenerationArtifactComponentKind::Primary,relative_storage_key:format!("{artifact_id}/primary"),byte_length:9,sha256:"a".repeat(64),resource_reservation_id:"resource".into(),release_operation_id:Uuid::now_v7()};
            let (component_set_json,component_set_digest)=image_generation_component_set_binding(std::slice::from_ref(&component))?;
            Db::create_image_generation_artifact_conn(conn,&CreateImageGenerationArtifact{artifact_id,job_id:fixture.job_id,slot_id:fixture.slot_id,component_set_digest:component_set_digest.clone(),components:vec![component],now_unix_ms:2})?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:1,from:ImageGenerationArtifactState::Allocating,to:ImageGenerationArtifactState::Writing,now_unix_ms:3,terminal_reason:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:1,from:ImageGenerationArtifactComponentState::Planned,to:ImageGenerationArtifactComponentState::Writing,stable_identity_json:None,deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_component_conn(conn,&TransitionImageGenerationArtifactComponent{artifact_id,component_id,expected_generation:2,from:ImageGenerationArtifactComponentState::Writing,to:ImageGenerationArtifactComponentState::Ready,stable_identity_json:Some("{\"held\":true}".into()),deletion_evidence_digest:None})?;
            Db::transition_image_generation_artifact_conn(conn,&TransitionImageGenerationArtifact{artifact_id,expected_generation:2,from:ImageGenerationArtifactState::Writing,to:ImageGenerationArtifactState::LateQuarantined,now_unix_ms:4,terminal_reason:None})?;
            let authorization_digest="b".repeat(64); let output_digest="c".repeat(64); let destination="image.png"; let temporary=".image.partial";
            conn.execute("INSERT INTO image_generation_late_publication_authorization_facts(authorization_digest,artifact_id,artifact_generation,job_id,slot_id,slot_generation,component_set_digest,output_authority_digest,output_authority_generation,destination_name,temporary_name,principal_digest,created_at_unix_ms) VALUES(?1,?2,3,?3,?4,8,?5,?6,7,?7,?8,?9,5)",params![authorization_digest,artifact_id.to_string(),fixture.job_id.to_string(),fixture.slot_id.to_string(),component_set_digest,output_digest,destination,temporary,"d".repeat(64)])?;
            let operation=Uuid::now_v7();
            let base=database_now_unix_ms(conn)?;
            let reserve=ReserveImageGenerationLatePublication{publication_operation_id:operation,artifact_id,expected_artifact_generation:3,job_id:fixture.job_id,slot_id:fixture.slot_id,expected_slot_version:8,component_set_digest:&component_set_digest,component_set_json:&component_set_json,authorization_digest:&authorization_digest,output_authority_digest:&output_digest,output_authority_generation:7,destination_name:destination,temporary_name:temporary};
            let deleted=ImageGenerationLatePublicationEvidenceV1::TemporaryDeleted{schema_version:1,identity_digest:"6".repeat(64),deletion_digest:"7".repeat(64),parent_sync_digest:"8".repeat(64)}.canonical_json()?;
            let mut terminal=reserve.clone(); terminal.publication_operation_id=Uuid::now_v7();
            assert!(reserve_image_generation_late_publication_at_conn(conn,&terminal,base-300_000)?);
            assert!(conn.execute("UPDATE image_generation_late_publication_leases SET state='expired',version=2 WHERE publication_operation_id=?1",[terminal.publication_operation_id.to_string()]).is_err());
            resolve_image_generation_late_publication_at_conn(conn,&ResolveImageGenerationLatePublication{publication_operation_id:terminal.publication_operation_id,expected_version:1,from:ImageGenerationLatePublicationState::Reserved,to:ImageGenerationLatePublicationState::Expired,recovery_evidence_json:&deleted},base)?;
            terminal.publication_operation_id=Uuid::now_v7(); assert!(reserve_image_generation_late_publication_at_conn(conn,&terminal,base)?);
            resolve_image_generation_late_publication_at_conn(conn,&ResolveImageGenerationLatePublication{publication_operation_id:terminal.publication_operation_id,expected_version:1,from:ImageGenerationLatePublicationState::Reserved,to:ImageGenerationLatePublicationState::Aborted,recovery_evidence_json:&deleted},base+1)?;
            terminal.publication_operation_id=Uuid::now_v7(); assert!(reserve_image_generation_late_publication_at_conn(conn,&terminal,base)?);
            let old_worker=Uuid::now_v7(); claim_image_generation_late_publication_at_conn(conn,&ClaimImageGenerationLatePublication{publication_operation_id:terminal.publication_operation_id,expected_version:1,worker_boot_id:old_worker,claim_generation:1},base+1)?;
            Db::reclaim_image_generation_late_publication_conn(conn,&ReclaimImageGenerationLatePublication{publication_operation_id:terminal.publication_operation_id,expected_version:2,previous_claim_generation:1,worker_boot_id:Uuid::now_v7(),claim_generation:2,reconciled_cleanup_evidence_json:&deleted})?;
            resolve_image_generation_late_publication_at_conn(conn,&ResolveImageGenerationLatePublication{publication_operation_id:terminal.publication_operation_id,expected_version:3,from:ImageGenerationLatePublicationState::Reserved,to:ImageGenerationLatePublicationState::Aborted,recovery_evidence_json:&deleted},base+2)?;
            terminal.publication_operation_id=Uuid::now_v7(); assert!(reserve_image_generation_late_publication_at_conn(conn,&terminal,base)?);
            resolve_image_generation_late_publication_at_conn(conn,&ResolveImageGenerationLatePublication{publication_operation_id:terminal.publication_operation_id,expected_version:1,from:ImageGenerationLatePublicationState::Reserved,to:ImageGenerationLatePublicationState::Aborted,recovery_evidence_json:&deleted},base+1)?;
            assert!(reserve_image_generation_late_publication_at_conn(conn,&reserve,base)?);
            assert!(!reserve_image_generation_late_publication_at_conn(conn,&reserve,base+1)?);
            assert!(claim_image_generation_late_publication_at_conn(conn,&ClaimImageGenerationLatePublication{publication_operation_id:operation,expected_version:1,worker_boot_id:Uuid::now_v7(),claim_generation:1},base+300_000).is_err());
            let worker=Uuid::now_v7();
            claim_image_generation_late_publication_at_conn(conn,&ClaimImageGenerationLatePublication{publication_operation_id:operation,expected_version:1,worker_boot_id:worker,claim_generation:1},base+299_999)?;
            let prepared=ImageGenerationLatePublicationEvidenceV1::TemporaryPrepared{schema_version:1,identity_digest:"1".repeat(64),security_digest:"2".repeat(64),byte_length:"9".into(),sha256:"a".repeat(64)}.canonical_json()?;
            let durable=ImageGenerationLatePublicationEvidenceV1::OutputDurable{schema_version:1,identity_digest:"3".repeat(64),security_digest:"4".repeat(64),byte_length:"9".into(),sha256:"a".repeat(64),parent_sync_digest:"5".repeat(64)}.canonical_json()?;
            advance_image_generation_late_publication_at_conn(conn,&AdvanceImageGenerationLatePublication{publication_operation_id:operation,expected_version:2,worker_boot_id:worker,claim_generation:1,from:ImageGenerationLatePublicationState::Reserved,to:ImageGenerationLatePublicationState::CopyAuthorized,evidence_json:&prepared},base+299_999)?;
            advance_image_generation_late_publication_at_conn(conn,&AdvanceImageGenerationLatePublication{publication_operation_id:operation,expected_version:3,worker_boot_id:worker,claim_generation:1,from:ImageGenerationLatePublicationState::CopyAuthorized,to:ImageGenerationLatePublicationState::CopyCommitted,evidence_json:&durable},base+400_000)?;
            finalize_image_generation_late_publication_at_conn(conn,operation,4,base+400_001)?;
            let states:(String,String,String)=conn.query_row("SELECT p.state,a.state,s.published_disposition FROM image_generation_late_publication_leases p JOIN image_generation_artifacts a ON a.artifact_id=p.artifact_id JOIN image_generation_slots s ON s.job_id=p.job_id AND s.slot_id=p.slot_id WHERE p.publication_operation_id=?1",[operation.to_string()],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)))?;
            assert_eq!(states,("published".into(),"retained".into(),"late_authorized".into()));
            assert!(matches!(Db::replay_image_generation_late_publication_conn(conn,operation)?,ImageGenerationLatePublicationReplay::Terminal{state:ImageGenerationLatePublicationState::Published,version:5,evidence:ImageGenerationLatePublicationEvidenceV1::OutputDurable{..},..}));
            assert!(conn.execute("UPDATE image_generation_late_publication_leases SET decided_at_unix_ms=decided_at_unix_ms+1 WHERE publication_operation_id=?1",[operation.to_string()]).is_err());
            assert!(conn.execute("UPDATE image_generation_late_publication_leases SET claim_generation=claim_generation+1 WHERE publication_operation_id=?1",[operation.to_string()]).is_err());
            assert!(conn.execute("INSERT INTO image_generation_user_published_outputs(publication_operation_id,artifact_id,artifact_generation,output_authority_digest,output_authority_generation,destination_name,output_evidence_json,committed_at_unix_ms) VALUES('forged',?1,3,?2,7,'other.png',?3,1)",params![artifact_id.to_string(),output_digest,durable]).is_err());
            assert!(conn.execute("UPDATE image_generation_late_publication_authorization_facts SET revoked_at_unix_ms=4 WHERE authorization_digest=?1",[authorization_digest.clone()]).is_err());
            assert_eq!(conn.execute("UPDATE image_generation_late_publication_authorization_facts SET revoked_at_unix_ms=6 WHERE authorization_digest=?1",[authorization_digest.clone()])?,1);
            assert!(conn.execute("UPDATE image_generation_late_publication_authorization_facts SET revoked_at_unix_ms=7 WHERE authorization_digest=?1",[authorization_digest]).is_err());
            assert!(finalize_image_generation_late_publication_at_conn(conn,operation,4,base+400_001).is_err());
            Ok(())
        }).unwrap();
    }
}
