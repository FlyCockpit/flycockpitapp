//! Provider-neutral durable image-generation state vocabulary.
//!
//! Transition legality lives here so repository reducers and protocol
//! projections cannot develop separate interpretations of persisted states.

use serde::{Deserialize, Serialize};

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
}
