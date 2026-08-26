//! Authored user-message state retained by daemon clients until acceptance.

use cockpit_proto::{ActiveModelRef, TagExpansionMeta};
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
}
