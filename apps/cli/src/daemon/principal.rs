use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::daemon::proto::Request;
use crate::daemon::relay_envelope::{RelayGrantScope, RelayPrincipal};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientPrincipal {
    Owner,
    Remote(RemotePrincipal),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePrincipal {
    pub user_id: String,
    pub grants: Vec<PrincipalGrant>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrincipalGrant {
    pub scope: PrincipalScope,
    pub project_root: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalScope {
    Terminal,
    Agent,
    AgentReadonly,
    ProjectFiles,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAccess {
    Owner,
    Writer,
    Readonly,
    None,
}

impl ClientPrincipal {
    pub fn owner() -> Self {
        Self::Owner
    }

    pub fn from_relay(principal: RelayPrincipal) -> Self {
        Self::Remote(RemotePrincipal {
            user_id: principal.user_id,
            grants: principal
                .grants
                .into_iter()
                .map(PrincipalGrant::from)
                .collect(),
        })
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn tag(&self) -> Option<String> {
        match self {
            Self::Owner => None,
            Self::Remote(remote) => Some(format!("flycockpit:{}", remote.user_id)),
        }
    }

    pub fn steer_origin(&self) -> String {
        match self {
            Self::Owner => format!("local:{}", local_principal_name()),
            Self::Remote(remote) => format!("flycockpit:{}", remote.user_id),
        }
    }

    pub fn can_agent_write_project(&self, project_root: &str) -> bool {
        self.is_owner() || self.has_project_scope(PrincipalScope::Agent, project_root)
    }

    pub fn can_agent_read_project(&self, project_root: &str) -> bool {
        self.can_agent_write_project(project_root)
            || self.has_project_scope(PrincipalScope::AgentReadonly, project_root)
    }

    pub fn has_project_files(&self, project_root: &str) -> bool {
        self.is_owner() || self.has_project_scope(PrincipalScope::ProjectFiles, project_root)
    }

    pub fn has_terminal(&self) -> bool {
        self.is_owner() || self.has_scope(PrincipalScope::Terminal)
    }

    pub fn has_project_scope(&self, scope: PrincipalScope, project_root: &str) -> bool {
        match self {
            Self::Owner => true,
            Self::Remote(remote) => remote
                .grants
                .iter()
                .any(|grant| grant.scope == scope && grant.matches_project(project_root)),
        }
    }

    fn has_scope(&self, scope: PrincipalScope) -> bool {
        match self {
            Self::Owner => true,
            Self::Remote(remote) => remote.grants.iter().any(|grant| grant.scope == scope),
        }
    }
}

impl PrincipalGrant {
    fn matches_project(&self, project_root: &str) -> bool {
        match self.project_root.as_deref() {
            None => true,
            Some(grant_root) => roots_equal(grant_root, project_root),
        }
    }
}

impl From<crate::daemon::relay_envelope::RelayGrant> for PrincipalGrant {
    fn from(grant: crate::daemon::relay_envelope::RelayGrant) -> Self {
        let scope = match grant.scope {
            RelayGrantScope::Terminal => PrincipalScope::Terminal,
            RelayGrantScope::Agent => PrincipalScope::Agent,
            RelayGrantScope::AgentReadonly => PrincipalScope::AgentReadonly,
            RelayGrantScope::ProjectFiles => PrincipalScope::ProjectFiles,
        };
        Self {
            scope,
            project_root: grant.project_root,
        }
    }
}

fn local_principal_name() -> String {
    let raw = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "owner".to_string());
    let sanitized: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if sanitized.is_empty() {
        "owner".to_string()
    } else {
        sanitized
    }
}

fn roots_equal(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    canonical_if_exists(a) == canonical_if_exists(b)
}

fn canonical_if_exists(path: &str) -> PathBuf {
    Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
}

pub fn request_kind(request: &Request) -> &'static str {
    match request {
        Request::Attach { .. } => "attach",
        Request::SubagentTranscript { .. } => "subagent_transcript",
        Request::SendUserMessage { .. } => "send_user_message",
        Request::SteerDelegation { .. } => "steer_delegation",
        Request::BeginAttachmentUpload { .. } => "begin_attachment_upload",
        Request::UploadAttachmentChunk { .. } => "upload_attachment_chunk",
        Request::FinishAttachmentUpload { .. } => "finish_attachment_upload",
        Request::CancelAttachmentUpload { .. } => "cancel_attachment_upload",
        Request::RemoveQueuedUserMessage { .. } => "remove_queued_user_message",
        Request::RemoveNewestQueuedUserMessage { .. } => "remove_newest_queued_user_message",
        Request::RemoveEditableQueuedUserMessages { .. } => "remove_editable_queued_user_messages",
        Request::ResumePausedWork { .. } => "resume_paused_work",
        Request::CancelPausedWork { .. } => "cancel_paused_work",
        Request::RepairResume { .. } => "repair_resume",
        Request::CancelTurn => "cancel_turn",
        Request::LspControl { .. } => "lsp_control",
        Request::FsList { .. } => "fs_list",
        Request::FsStat { .. } => "fs_stat",
        Request::FsRead { .. } => "fs_read",
        Request::FsWrite { .. } => "fs_write",
        Request::FsCreateDir { .. } => "fs_create_dir",
        Request::FsRename { .. } => "fs_rename",
        Request::FsDelete { .. } => "fs_delete",
        Request::GitStatus { .. } => "git_status",
        Request::GitDiffFile { .. } => "git_diff_file",
        Request::OpenTerminal { .. } => "open_terminal",
        Request::AttachTerminal { .. } => "attach_terminal",
        Request::TerminalInput { .. } => "terminal_input",
        Request::TerminalResize { .. } => "terminal_resize",
        Request::CloseTerminal { .. } => "close_terminal",
        Request::ResolveInterrupt { .. } => "resolve_interrupt",
        Request::ListSessions { .. } => "list_sessions",
        Request::SessionLiveStatus { .. } => "session_live_status",
        Request::ArchiveSession { .. } => "archive_session",
        Request::UnarchiveSession { .. } => "unarchive_session",
        Request::ForkSession { .. } => "fork_session",
        Request::DiscardSession { .. } => "discard_session",
        Request::RenameSession { .. } => "rename_session",
        Request::RecordSessionNote { .. } => "record_session_note",
        Request::DeleteSession { .. } => "delete_session",
        Request::ListSkills { .. } => "list_skills",
        Request::ResourceSnapshot => "resource_snapshot",
        Request::PromoteResource { .. } => "promote_resource",
        Request::ListAgents => "list_agents",
        Request::ListModels { .. } => "list_models",
        Request::SetActiveModel { .. } => "set_active_model",
        Request::SetAgent { .. } => "set_agent",
        Request::SetLlmMode { .. } => "set_llm_mode",
        Request::SetSessionLlmMode { .. } => "set_session_llm_mode",
        Request::SetApprovalMode { .. } => "set_approval_mode",
        Request::SetDelegationRecursion { .. } => "set_delegation_recursion",
        Request::SetCaffeinate { .. } => "set_caffeinate",
        Request::CancelSchedule { .. } => "cancel_schedule",
        Request::SetSandbox { .. } => "set_sandbox",
        Request::SetPreflight { .. } => "set_preflight",
        Request::SetTrustedOnly { .. } => "set_trusted_only",
        Request::SetRedaction { .. } => "set_redaction",
        Request::SetTandemModels { .. } => "set_tandem_models",
        Request::Prune => "prune",
        Request::Compact => "compact",
        Request::Pin { .. } => "pin",
        Request::StoreFlycockpitCredential { .. } => "store_flycockpit_credential",
        Request::ClearFlycockpitCredential => "clear_flycockpit_credential",
        Request::DaemonStatus => "daemon_status",
        Request::RefreshEnv { .. } => "refresh_env",
        Request::RecordUsage { .. } => "record_usage",
        Request::GetUsageCounts { .. } => "get_usage_counts",
        Request::GuidanceEstimate { .. } => "guidance_estimate",
        Request::StopDaemon => "stop_daemon",
        Request::ShareSession { .. } => "share_session",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::relay_envelope::{RelayGrant, RelayGrantScope, RelayPrincipal};

    fn remote(scope: RelayGrantScope, project_root: Option<String>) -> ClientPrincipal {
        ClientPrincipal::from_relay(RelayPrincipal {
            user_id: "user-1".to_string(),
            grants: vec![RelayGrant {
                scope,
                project_root,
            }],
        })
    }

    #[test]
    fn agent_scope_allows_write_and_read_for_matching_project() {
        let principal = remote(RelayGrantScope::Agent, Some("/workspace/app".to_string()));
        assert!(principal.can_agent_write_project("/workspace/app"));
        assert!(principal.can_agent_read_project("/workspace/app"));
        assert!(!principal.can_agent_write_project("/workspace/other"));
    }

    #[test]
    fn readonly_scope_allows_read_but_not_write() {
        let principal = remote(
            RelayGrantScope::AgentReadonly,
            Some("/workspace/app".to_string()),
        );
        assert!(!principal.can_agent_write_project("/workspace/app"));
        assert!(principal.can_agent_read_project("/workspace/app"));
    }

    #[test]
    fn instance_wide_grant_matches_any_project() {
        let principal = remote(RelayGrantScope::ProjectFiles, None);
        assert!(principal.has_project_files("/workspace/app"));
        assert!(principal.has_project_files("/elsewhere"));
    }
}
