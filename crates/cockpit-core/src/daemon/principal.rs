use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::daemon::proto::{self, Request};
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

macro_rules! command_request_kind_match {
    (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
        match $request {
            $($pattern => $kind,)+
        }
    }};
}

#[allow(unused_variables)]
pub fn request_kind(request: &Request) -> &'static str {
    proto::command!(command_request_kind_match, request)
}

/// Ordering contract asserted by a daemon request table row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestOrdering {
    /// The request must execute on the serialized client executor.
    Serialized,
    /// The handler mutates no client-scoped state, and its result is
    /// correct against a client-state snapshot taken when the request was
    /// received.
    Concurrent,
}

macro_rules! command_request_ordering_value {
    (serialized) => {
        RequestOrdering::Serialized
    };
    (concurrent) => {
        RequestOrdering::Concurrent
    };
}

macro_rules! command_request_ordering_match {
    (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
        match $request {
            $($pattern => command_request_ordering_value!($ordering),)+
        }
    }};
}

#[allow(unused_variables)]
pub fn request_ordering(request: &Request) -> RequestOrdering {
    proto::command!(command_request_ordering_match, request)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::relay_envelope::{RelayGrant, RelayGrantScope, RelayPrincipal};

    macro_rules! request_ordering_rows_from_command_table {
        (($($context:ident),*) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
            &[$(($kind, command_request_ordering_value!($ordering))),+]
        }};
    }

    macro_rules! request_ordering_row_count_from_command_table {
        (($($context:ident),*) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
            0usize $(+ {
                let _ = stringify!($pattern);
                1usize
            })+
        }};
    }

    macro_rules! request_ordering_no_wildcard_check {
        (($request:ident) [$(($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?);)+]) => {{
            let classify_without_wildcard: fn(&Request) -> RequestOrdering = |$request| {
                match $request {
                    $($pattern => command_request_ordering_value!($ordering),)+
                }
            };
            let names = &[$($kind),+];
            (classify_without_wildcard, names)
        }};
    }

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

    #[test]
    fn request_ordering_concurrent_set_is_exact() {
        let rows = proto::command!(request_ordering_rows_from_command_table);
        assert!(
            rows.len() > 80,
            "command table should enumerate Request rows"
        );
        let expected = std::collections::BTreeSet::from([
            "daemon_status",
            "export_session_data",
            "fs_list",
            "fs_read",
            "fs_stat",
            "get_usage_counts",
            "git_diff_file",
            "git_status",
            "guidance_estimate",
            "list_agents",
            "list_assistants",
            "list_models",
            "list_scheduled_jobs",
            "list_sessions",
            "list_skills",
            "read_history_page",
            "read_session_messages",
            "resource_snapshot",
            "session_live_status",
            "stats_rollup",
            "subagent_transcript",
        ]);
        let actual: std::collections::BTreeSet<_> = rows
            .iter()
            .filter_map(|(kind, ordering)| {
                (*ordering == RequestOrdering::Concurrent).then_some(*kind)
            })
            .collect();
        assert_eq!(actual, expected);
        for serialized in [
            "attach",
            "begin_attachment_upload",
            "upload_attachment_chunk",
            "finish_attachment_upload",
            "cancel_attachment_upload",
            "send_user_message",
            "remove_queued_user_message",
            "remove_newest_queued_user_message",
            "remove_editable_queued_user_messages",
            "cancel_turn",
            "steer_delegation",
            "resolve_interrupt",
            "set_active_model",
            "set_agent",
            "set_llm_mode",
            "set_session_llm_mode",
            "set_approval_mode",
            "set_delegation_recursion",
            "set_sandbox",
            "set_sandbox_escalation",
            "set_preflight",
            "set_trusted_only",
            "set_redaction",
            "set_tandem_models",
        ] {
            let (_, ordering) = rows
                .iter()
                .find(|(kind, _)| *kind == serialized)
                .unwrap_or_else(|| panic!("missing request kind {serialized}"));
            assert_eq!(
                *ordering,
                RequestOrdering::Serialized,
                "{serialized} must stay serialized"
            );
        }
    }

    #[test]
    fn request_ordering_table_has_no_wildcard_arm() {
        let (_classify_without_wildcard, names) =
            proto::command!(request_ordering_no_wildcard_check, request);
        let row_count = proto::command!(request_ordering_row_count_from_command_table);
        assert_eq!(names.len(), row_count);
        assert!(
            names.len() > 80,
            "command table should enumerate Request rows"
        );
    }
}
