#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApprovalOptionId {
    Approve,
    Reject,
    ApproveOnce,
    ApproveSession,
    ApproveProject,
    ApproveGlobal,
    RejectSession,
    RejectProject,
    RejectGlobal,
    MoreOptions,
    ApproveAllOnce,
    EscalateGrantSession,
    EscalateGrantProject,
    EscalateGrantGlobal,
    EscalateRunUnconfinedOnce,
    GitignoreFile,
    GitignoreParent,
    GitignoreReject,
    RepeatAcceptOnce,
    RepeatRejectOnce,
    RepeatAcceptSession,
    RepeatRejectSession,
    RepeatAcceptProject,
    RepeatRejectProject,
}

impl ApprovalOptionId {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Reject => "reject",
            Self::ApproveOnce => "approve_once",
            Self::ApproveSession => "approve_session",
            Self::ApproveProject => "approve_project",
            Self::ApproveGlobal => "approve_global",
            Self::RejectSession => "reject_session",
            Self::RejectProject => "reject_project",
            Self::RejectGlobal => "reject_global",
            Self::MoreOptions => "more_options",
            Self::ApproveAllOnce => "approve_all_once",
            Self::EscalateGrantSession => "escalate_grant_session",
            Self::EscalateGrantProject => "escalate_grant_project",
            Self::EscalateGrantGlobal => "escalate_grant_global",
            Self::EscalateRunUnconfinedOnce => "escalate_run_unconfined_once",
            Self::GitignoreFile => "gitignore_file",
            Self::GitignoreParent => "gitignore_parent",
            Self::GitignoreReject => "gitignore_reject",
            Self::RepeatAcceptOnce => "approve_repeat_once",
            Self::RepeatRejectOnce => "reject_repeat_once",
            Self::RepeatAcceptSession => "approve_repeat_session",
            Self::RepeatRejectSession => "reject_repeat_session",
            Self::RepeatAcceptProject => "approve_repeat_project",
            Self::RepeatRejectProject => "reject_repeat_project",
        }
    }

    pub fn from_str(id: &str) -> Option<Self> {
        Some(match id {
            "approve" => Self::Approve,
            "reject" => Self::Reject,
            "approve_once" => Self::ApproveOnce,
            "approve_session" => Self::ApproveSession,
            "approve_project" => Self::ApproveProject,
            "approve_global" => Self::ApproveGlobal,
            "reject_session" => Self::RejectSession,
            "reject_project" => Self::RejectProject,
            "reject_global" => Self::RejectGlobal,
            "more_options" => Self::MoreOptions,
            "approve_all_once" => Self::ApproveAllOnce,
            "escalate_grant_session" => Self::EscalateGrantSession,
            "escalate_grant_project" => Self::EscalateGrantProject,
            "escalate_grant_global" => Self::EscalateGrantGlobal,
            "escalate_run_unconfined_once" => Self::EscalateRunUnconfinedOnce,
            "gitignore_file" => Self::GitignoreFile,
            "gitignore_parent" => Self::GitignoreParent,
            "gitignore_reject" => Self::GitignoreReject,
            "approve_repeat_once" => Self::RepeatAcceptOnce,
            "reject_repeat_once" => Self::RepeatRejectOnce,
            "approve_repeat_session" => Self::RepeatAcceptSession,
            "reject_repeat_session" => Self::RepeatRejectSession,
            "approve_repeat_project" => Self::RepeatAcceptProject,
            "reject_repeat_project" => Self::RepeatRejectProject,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApprovalOptionSet {
    pub kind: &'static str,
    pub accepted: Vec<ApprovalOptionId>,
}

impl ApprovalOptionSet {
    pub fn new(kind: &'static str, accepted: impl IntoIterator<Item = ApprovalOptionId>) -> Self {
        Self {
            kind,
            accepted: accepted.into_iter().collect(),
        }
    }

    pub fn contains(&self, id: ApprovalOptionId) -> bool {
        self.accepted.contains(&id)
    }

    pub fn accepted_ids(&self) -> Vec<&'static str> {
        self.accepted.iter().map(|id| id.as_str()).collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForeignOptionId {
    pub kind: &'static str,
    pub offered: Vec<&'static str>,
    pub received: String,
}

impl ForeignOptionId {
    pub fn new(set: &ApprovalOptionSet, received: impl Into<String>) -> Self {
        Self {
            kind: set.kind,
            offered: set.accepted_ids(),
            received: received.into(),
        }
    }
}
