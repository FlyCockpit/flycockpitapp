//! Authored user-message state retained by daemon clients until acceptance.

use cockpit_proto::{ActiveModelRef, TagExpansionMeta};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::image_upload::SubmissionImage;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSubmissionKind {
    #[default]
    User,
    Compact,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionOrigin {
    ExternalRoot,
    GoalContinuation,
    ScheduledJob,
    AutoContinue,
    RetryRecovery,
    ToolResult,
    CompactNotice,
    #[default]
    Internal,
}

impl SubmissionOrigin {
    pub fn advances_activity_epoch(self) -> bool {
        matches!(self, Self::ExternalRoot)
    }

    pub fn user_prompt_submit_source(self) -> Option<&'static str> {
        match self {
            Self::ExternalRoot => Some("user"),
            Self::GoalContinuation
            | Self::ScheduledJob
            | Self::AutoContinue
            | Self::RetryRecovery
            | Self::ToolResult
            | Self::CompactNotice
            | Self::Internal => None,
        }
    }
}

impl From<SubmissionOrigin> for cockpit_proto::UserMessageOrigin {
    fn from(origin: SubmissionOrigin) -> Self {
        match origin {
            SubmissionOrigin::ExternalRoot => Self::ExternalRoot,
            SubmissionOrigin::GoalContinuation => Self::GoalContinuation,
            SubmissionOrigin::ScheduledJob => Self::ScheduledJob,
            SubmissionOrigin::AutoContinue => Self::AutoContinue,
            SubmissionOrigin::RetryRecovery => Self::RetryRecovery,
            SubmissionOrigin::ToolResult => Self::ToolResult,
            SubmissionOrigin::CompactNotice => Self::CompactNotice,
            SubmissionOrigin::Internal => Self::Internal,
        }
    }
}

impl From<cockpit_proto::UserMessageOrigin> for SubmissionOrigin {
    fn from(origin: cockpit_proto::UserMessageOrigin) -> Self {
        match origin {
            cockpit_proto::UserMessageOrigin::ExternalRoot => Self::ExternalRoot,
            cockpit_proto::UserMessageOrigin::GoalContinuation => Self::GoalContinuation,
            cockpit_proto::UserMessageOrigin::ScheduledJob => Self::ScheduledJob,
            cockpit_proto::UserMessageOrigin::AutoContinue => Self::AutoContinue,
            cockpit_proto::UserMessageOrigin::RetryRecovery => Self::RetryRecovery,
            cockpit_proto::UserMessageOrigin::ToolResult => Self::ToolResult,
            cockpit_proto::UserMessageOrigin::CompactNotice => Self::CompactNotice,
            cockpit_proto::UserMessageOrigin::Internal => Self::Internal,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientSubmissionReceipt {
    pub id: Uuid,
    pub fingerprint: String,
    pub wire_fingerprint: String,
    pub origin_principal: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingSubmissionTerminalDisposition {
    PreflightRejected,
    OversizedTextArtifact,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(default)]
pub struct ClientUserSubmission {
    #[serde(default)]
    pub kind: UserSubmissionKind,
    #[serde(default)]
    pub origin: SubmissionOrigin,
    pub expected_model_state_generation: Option<u64>,
    pub expected_model: Option<ActiveModelRef>,
    pub text: String,
    pub display_text: Option<String>,
    #[serde(default)]
    pub tag_expansions: Vec<TagExpansionMeta>,
    #[serde(default)]
    pub images: Vec<SubmissionImage>,
    pub forced_skill: Option<String>,
    pub origin_principal: Option<String>,
    pub job_id: Option<String>,
    pub preflight_cleaned: Option<String>,
    #[serde(default)]
    pub queue_item_ids: Vec<Uuid>,
    #[serde(default)]
    pub client_submissions: Vec<ClientSubmissionReceipt>,
    pub queue_target: Option<cockpit_proto::QueueTarget>,
    #[serde(default)]
    pub delivery_class: cockpit_proto::QueueDeliveryClass =
        cockpit_proto::QueueDeliveryClass::Steering,
    #[serde(skip)]
    pub pending_terminal_disposition: Option<PendingSubmissionTerminalDisposition>,
    pub run_invocation_id: Option<Uuid>,
}

impl ClientUserSubmission {
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn compact_notice() -> Self {
        Self {
            kind: UserSubmissionKind::Compact,
            origin: SubmissionOrigin::CompactNotice,
            text: "/compact: assembling handoff (prune-first, model brief, deterministic appendix, context tags)...".to_owned(),
            ..Self::default()
        }
    }

    pub fn client_fingerprint(&self) -> String {
        fn part(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }
        fn optional_part(hasher: &mut Sha256, value: Option<&str>) {
            match value {
                None => part(hasher, b"none"),
                Some(value) => {
                    part(hasher, b"some");
                    part(hasher, value.as_bytes());
                }
            }
        }

        let mut hasher = Sha256::new();
        part(
            &mut hasher,
            match self.kind {
                UserSubmissionKind::User => b"user",
                UserSubmissionKind::Compact => b"compact",
            },
        );
        part(
            &mut hasher,
            match self.origin {
                SubmissionOrigin::ExternalRoot => b"external_root",
                SubmissionOrigin::GoalContinuation => b"goal_continuation",
                SubmissionOrigin::ScheduledJob => b"scheduled_job",
                SubmissionOrigin::AutoContinue => b"auto_continue",
                SubmissionOrigin::RetryRecovery => b"retry_recovery",
                SubmissionOrigin::ToolResult => b"tool_result",
                SubmissionOrigin::CompactNotice => b"compact_notice",
                SubmissionOrigin::Internal => b"internal",
            },
        );
        part(
            &mut hasher,
            &self.expected_model_state_generation.map_or_else(
                || b"none".to_vec(),
                |generation| generation.to_be_bytes().to_vec(),
            ),
        );
        part(
            &mut hasher,
            &serde_json::to_vec(&self.expected_model).unwrap_or_default(),
        );
        part(&mut hasher, self.text.as_bytes());
        optional_part(&mut hasher, self.display_text.as_deref());
        part(
            &mut hasher,
            &serde_json::to_vec(&self.tag_expansions).unwrap_or_default(),
        );
        for image in &self.images {
            part(&mut hasher, &serde_json::to_vec(image).unwrap_or_default());
        }
        optional_part(&mut hasher, self.forced_skill.as_deref());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn is_text_only(&self) -> bool {
        self.images.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_fingerprint_binds_submission_origin() {
        let external = ClientUserSubmission {
            origin: SubmissionOrigin::ExternalRoot,
            text: "same wire text".to_owned(),
            ..Default::default()
        };
        let internal = ClientUserSubmission {
            origin: SubmissionOrigin::AutoContinue,
            ..external.clone()
        };
        assert_ne!(external.client_fingerprint(), internal.client_fingerprint());
    }
}
