#[cfg(feature = "remote")]
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[cfg(feature = "remote")]
use cockpit_proto::capability_ceiling::{RemoteAttachmentCapabilityV1, RemoteProjectCapabilityV1};

use crate::daemon::proto::{self, Request};

use cockpit_host::daemon_lifecycle::ProcessStartIdentity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalClientRole {
    Tui,
    Cli,
    Acp,
    AgentChild,
    /// Socket peer that has not yet exchanged a peer-bound credential.
    Unauthenticated,
}

impl LocalClientRole {
    pub fn is_owner_class(self) -> bool {
        matches!(self, Self::Tui | Self::Cli | Self::Acp)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalPrincipal {
    pub role: LocalClientRole,
    pub peer_pid: u32,
    pub peer_uid: u32,
    pub peer_gid: u32,
    #[serde(default = "default_peer_process_start")]
    pub peer_process_start: ProcessStartIdentity,
    #[serde(default)]
    pub grants: Vec<PrincipalGrant>,
}

fn default_peer_process_start() -> ProcessStartIdentity {
    ProcessStartIdentity {
        primary: 0,
        secondary: 0,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
// large_enum_variant: the oversized variant is intentional here; not boxed to keep the value owned inline.
#[allow(clippy::large_enum_variant)]
pub enum ClientPrincipal {
    /// In-process endpoint possession. Never assigned to wire socket peers.
    Owner,
    Local(LocalPrincipal),
    #[cfg(feature = "remote")]
    Remote(RemotePrincipal),
}

#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemotePrincipal {
    pub user_id: String,
    /// Typed authorization carried by this remote principal. The legacy
    /// four-scope relay vocabulary and the device-bound attempt-grant ceiling
    /// are disjoint variants; production authorization branches on which one
    /// is present and never widens an attempt-grant ceiling through the legacy
    /// scope helpers.
    pub authorization: RemoteAuthorization,
    pub actor_binding: Option<ClientActorBindingV1>,
}

/// Transport-neutral copy of the authenticated device binding. Keeping this
/// DTO in the daemon authority layer prevents the local build from depending
/// on or compiling the legacy relay envelope crate.
#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientActorBindingV1 {
    pub schema_version: u8,
    pub device_id: uuid::Uuid,
    pub device_generation: u64,
    pub logical_attachment_id: uuid::Uuid,
}

/// The kind of authorization a remote principal carries.
///
/// USER-SETTLED: `RemotePrincipal.grants` was replaced with this typed enum so
/// an attempt-grant ceiling can never be translated (lossily) into the legacy
/// scope vocabulary. `LegacyRelayScopes` is the connector relay boundary only
/// and is deleted wholesale by `remote-standalone-relay-cutover`. `AttemptGrant`
/// is constructed only by
/// `crate::daemon::remote_attempt::construct_principal_from_grant`.
#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteAuthorization {
    /// Legacy relay-derived scopes. Connector relay boundary only.
    LegacyRelayScopes(Vec<PrincipalGrant>),
    /// Device-bound attempt grant: the typed verified permission ceiling plus
    /// the account alias and device binding derived from a verified grant.
    AttemptGrant(AttemptGrantAuthorization),
}

/// Authorization derived from a verified device-bound attempt grant. Holds the
/// typed permission ceiling verbatim (attachment capabilities + per-project
/// capability sets keyed by 16-byte project id), never a lossy projection onto
/// the legacy scope vocabulary.
#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptGrantAuthorization {
    /// Canonical 22-char base64url (no padding) alias of the grant's
    /// `account_id`; identical to the `user_id` on the enclosing principal.
    pub account_alias: String,
    /// The verified permission ceiling, keyed by control-plane project id.
    pub ceiling: RemoteCeilingAuthorization,
    /// The verified device binding (client device/certificate/generation and
    /// the logical attachment / child attempt this grant was minted for).
    pub device_binding: GrantDeviceBinding,
}

/// A typed permission ceiling: attachment capabilities plus per-project
/// capability sets keyed by the 16-byte control-plane project id. Imported
/// from the foundation policy enums; never redefined.
#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCeilingAuthorization {
    pub attachment_capabilities: Vec<RemoteAttachmentCapabilityV1>,
    pub projects: Vec<([u8; 16], Vec<RemoteProjectCapabilityV1>)>,
}

#[cfg(feature = "remote")]
impl RemoteCeilingAuthorization {
    /// True if the attachment capability set contains `cap`.
    pub fn has_attachment_capability(&self, cap: RemoteAttachmentCapabilityV1) -> bool {
        self.attachment_capabilities.contains(&cap)
    }

    /// True if the ceiling grants `cap` on the exact control-plane project id.
    /// Deny-closed: an unmapped project id yields `false`.
    pub fn project_has_capability(
        &self,
        project_id: &[u8; 16],
        cap: RemoteProjectCapabilityV1,
    ) -> bool {
        self.projects
            .iter()
            .any(|(pid, caps)| pid == project_id && caps.contains(&cap))
    }
}

/// The device/attachment binding carried by an attempt-grant principal. Sourced
/// only from verified grant claims — never from a relay envelope — so the
/// module guard scans stay green.
#[cfg(feature = "remote")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantDeviceBinding {
    pub client_device_id: [u8; 16],
    pub client_certificate_id: [u8; 16],
    pub client_generation: u64,
    pub logical_attachment_id: [u8; 16],
    pub child_attempt_id: [u8; 16],
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
    /// Image-generation management authority (foundation capability
    /// ordinal 15).
    ///
    /// This scope carries NO terminal, agent, agent-readonly, or project-file
    /// authority: the daemon's principal helpers (`has_scope`,
    /// `has_project_scope`, `can_agent_*`, `has_project_files`, `has_terminal`)
    /// only ever query the four access scopes, so an `ImageGenerationAdmin`
    /// grant is inert through every one of them — it can never be mistaken for
    /// terminal/agent/file access. Its authority is enforced solely by the
    /// image-generation control plane, and only for the exact canonical
    /// project it is bound to: a grant carrying this scope is valid only with
    /// `project_root: Some(canonical_root)` (validated by
    /// `crate::image_generation_control_plane::scope_project_root_is_valid`),
    /// never inheriting the `None`-matches-any-project wildcard.
    ImageGenerationAdmin,
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

    pub fn local_unauthenticated(peer: cockpit_host::peer_cred::PeerIdentity) -> Self {
        Self::Local(LocalPrincipal {
            role: LocalClientRole::Unauthenticated,
            peer_pid: peer.pid,
            peer_uid: peer.uid,
            peer_gid: peer.gid,
            peer_process_start: peer.process_start,
            grants: Vec::new(),
        })
    }

    pub fn local_authenticated(
        peer: cockpit_host::peer_cred::PeerIdentity,
        role: LocalClientRole,
        grants: Vec<PrincipalGrant>,
    ) -> Self {
        Self::Local(LocalPrincipal {
            role,
            peer_pid: peer.pid,
            peer_uid: peer.uid,
            peer_gid: peer.gid,
            peer_process_start: peer.process_start,
            grants,
        })
    }

    pub fn as_local(&self) -> Option<&LocalPrincipal> {
        match self {
            Self::Local(local) => Some(local),
            _ => None,
        }
    }

    pub fn peer_identity(&self) -> Option<cockpit_host::peer_cred::PeerIdentity> {
        self.as_local()
            .map(|local| cockpit_host::peer_cred::PeerIdentity {
                pid: local.peer_pid,
                uid: local.peer_uid,
                gid: local.peer_gid,
                process_start: local.peer_process_start,
            })
    }

    pub fn has_owner_level_authority(&self) -> bool {
        match self {
            Self::Owner => true,
            Self::Local(local) => local.role.is_owner_class(),
            #[cfg(feature = "remote")]
            Self::Remote(_) => false,
        }
    }

    /// Construct a daemon-verified remote principal from transport-neutral
    /// fields.
    ///
    /// This is the only sanctioned remote principal constructor after the
    /// standalone relay cutover. The legacy `ClientPrincipal::from_relay`
    /// constructor that trusted a `RelayPrincipal` wire shape has been
    /// deleted: the daemon is now the final verifier and principal
    /// constructor, building `RemotePrincipal` from claims it verified itself
    /// rather than from a relay-stamped envelope. The optional
    /// `actor_binding` is the device-bound verification artifact carried
    /// alongside the verified grants.
    #[cfg(feature = "remote")]
    pub fn from_verified_remote(
        user_id: String,
        grants: Vec<PrincipalGrant>,
        actor_binding: Option<ClientActorBindingV1>,
    ) -> Self {
        Self::Remote(RemotePrincipal {
            user_id,
            authorization: RemoteAuthorization::LegacyRelayScopes(grants),
            actor_binding,
        })
    }

    /// Construct a remote principal from a verified device-bound attempt grant.
    /// This is the only constructor that produces an
    /// `RemoteAuthorization::AttemptGrant`, and it never yields `Owner` — the
    /// authorization is exactly the grant's verified ceiling.
    #[cfg(feature = "remote")]
    pub fn from_attempt_grant(
        user_id: String,
        authorization: AttemptGrantAuthorization,
        actor_binding: Option<ClientActorBindingV1>,
    ) -> Self {
        Self::Remote(RemotePrincipal {
            user_id,
            authorization: RemoteAuthorization::AttemptGrant(authorization),
            actor_binding,
        })
    }

    /// The verified attempt-grant authorization, if this principal is an
    /// attempt-grant principal. `None` for `Owner` and legacy relay principals.
    #[cfg(feature = "remote")]
    pub fn attempt_grant_authorization(&self) -> Option<&AttemptGrantAuthorization> {
        match self {
            Self::Remote(remote) => match &remote.authorization {
                RemoteAuthorization::AttemptGrant(auth) => Some(auth),
                RemoteAuthorization::LegacyRelayScopes(_) => None,
            },
            Self::Owner => None,
            Self::Local(_) => None,
        }
    }

    pub fn is_owner(&self) -> bool {
        matches!(self, Self::Owner)
    }

    pub fn is_local(&self) -> bool {
        matches!(self, Self::Local(_))
    }

    pub fn tag(&self) -> Option<String> {
        match self {
            Self::Owner => None,
            Self::Local(local) => Some(format!("local:{}:{}", local.role_tag(), local.peer_pid)),
            #[cfg(feature = "remote")]
            Self::Remote(remote) => Some(format!("flycockpit:{}", remote.user_id)),
        }
    }

    pub fn steer_origin(&self) -> String {
        match self {
            Self::Owner => format!("local:{}", local_principal_name()),
            Self::Local(local) => format!("local:{}:{}", local.role_tag(), local.peer_pid),
            #[cfg(feature = "remote")]
            Self::Remote(remote) => format!("flycockpit:{}", remote.user_id),
        }
    }

    pub fn can_agent_write_project(&self, project_root: &str) -> bool {
        self.has_owner_level_authority()
            || self.has_project_scope(PrincipalScope::Agent, project_root)
    }

    pub fn can_agent_read_project(&self, project_root: &str) -> bool {
        self.can_agent_write_project(project_root)
            || self.has_project_scope(PrincipalScope::AgentReadonly, project_root)
    }

    pub fn has_project_files(&self, project_root: &str) -> bool {
        self.has_owner_level_authority()
            || self.has_project_scope(PrincipalScope::ProjectFiles, project_root)
    }

    pub fn has_terminal(&self) -> bool {
        self.has_owner_level_authority() || self.has_scope(PrincipalScope::Terminal)
    }

    #[cfg_attr(not(feature = "remote"), allow(unused_variables))]
    pub fn has_project_scope(&self, scope: PrincipalScope, project_root: &str) -> bool {
        match self {
            Self::Owner => true,
            Self::Local(local) => {
                if local.role.is_owner_class() {
                    return true;
                }
                local
                    .grants
                    .iter()
                    .any(|grant| grant.scope == scope && grant.matches_project(project_root))
            }
            #[cfg(feature = "remote")]
            Self::Remote(remote) => match &remote.authorization {
                RemoteAuthorization::LegacyRelayScopes(grants) => grants
                    .iter()
                    .any(|grant| grant.scope == scope && grant.matches_project(project_root)),
                // Attempt-grant principals are enforced exclusively through the
                // verified ceiling; the legacy scope vocabulary never widens
                // them. Fail closed here so no legacy-scope caller can grant an
                // attempt-grant principal a capability its ceiling omits.
                RemoteAuthorization::AttemptGrant(_) => false,
            },
        }
    }

    #[cfg_attr(not(feature = "remote"), allow(unused_variables))]
    fn has_scope(&self, scope: PrincipalScope) -> bool {
        match self {
            Self::Owner => true,
            Self::Local(local) => {
                if local.role.is_owner_class() {
                    return true;
                }
                local.grants.iter().any(|grant| grant.scope == scope)
            }
            #[cfg(feature = "remote")]
            Self::Remote(remote) => match &remote.authorization {
                RemoteAuthorization::LegacyRelayScopes(grants) => {
                    grants.iter().any(|grant| grant.scope == scope)
                }
                RemoteAuthorization::AttemptGrant(_) => false,
            },
        }
    }
}

impl LocalPrincipal {
    pub(crate) fn role_tag(&self) -> &'static str {
        match self.role {
            LocalClientRole::Tui => "tui",
            LocalClientRole::Cli => "cli",
            LocalClientRole::Acp => "acp",
            LocalClientRole::AgentChild => "agent-child",
            LocalClientRole::Unauthenticated => "unauthenticated",
        }
    }
}

impl PrincipalGrant {
    fn matches_project(&self, project_root: &str) -> bool {
        match self.project_root.as_deref() {
            // An `ImageGenerationAdmin` grant NEVER inherits the rootless
            // wildcard: a missing root fails closed here rather than matching
            // every project, even if such a grant were constructed directly
            // (bypassing the mint/decode funnel). The four access scopes keep
            // their reviewed instance-wide (`None`-matches-any) grant.
            None => self.scope != PrincipalScope::ImageGenerationAdmin,
            Some(grant_root) => roots_equal(grant_root, project_root),
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

#[cfg(not(feature = "remote"))]
fn roots_equal(a: &str, b: &str) -> bool {
    a == b
}

#[cfg(feature = "remote")]
fn roots_equal(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    canonical_if_exists(a) == canonical_if_exists(b)
}

#[cfg(feature = "remote")]
fn canonical_if_exists(path: &str) -> PathBuf {
    Path::new(path)
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(path))
}

macro_rules! command_request_kind_match {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => $kind,)+
        }
    }};
}

#[allow(unused_variables)]
pub fn request_kind(request: &Request) -> &'static str {
    proto::command!(command_request_kind_match, request)
}

/// Compile-time product surface owning a daemon request. This classification
/// is expressed in terms of the authoritative `Request` variants, never wire
/// tag spelling, so renaming a tag cannot silently widen a minimal build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestProductDomain {
    Base,
    Extended,
}

macro_rules! command_request_product_domain_match {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        #[allow(unreachable_patterns)]
        match $request {
            #[cfg(feature = "extended")]
            Request::CreateScheduledJob { .. }
            | Request::ListScheduledJobs { .. }
            | Request::DeleteScheduledJob { .. }
            | Request::SetScheduledJobEnabled { .. }
            | Request::RunScheduledJob { .. }
            | Request::ImageEndpointList { .. }
            | Request::ImageEndpointGet { .. }
            | Request::ImageTargetList { .. }
            | Request::ImageTargetGet { .. }
            | Request::ImageWorkflowList { .. }
            | Request::ImageWorkflowGet { .. }
            | Request::ImageEndpointCreate { .. }
            | Request::ImageEndpointUpdate { .. }
            | Request::ImageEndpointDelete { .. }
            | Request::ImageTargetCreate { .. }
            | Request::ImageTargetUpdate { .. }
            | Request::ImageTargetDelete { .. }
            | Request::ImageTargetSetDefault { .. }
            | Request::ImageWorkflowUpload { .. }
            | Request::ImageWorkflowBind { .. }
            | Request::ImageWorkflowDelete { .. } => RequestProductDomain::Extended,
            #[cfg(feature = "extended")]
            Request::GetImageSpendPolicy { .. } | Request::SaveImageSpendPolicy { .. } =>
                RequestProductDomain::Extended,
            // The generated typed rows are the exhaustive base fallback. This
            // deliberately duplicates the extended patterns instead of using
            // `_`: a new Request variant without an authoritative row fails
            // compilation, and domain ownership never depends on forwarded
            // literal-token rematching.
            $($(#[$row_attr])* $pattern => RequestProductDomain::Base,)+
        }
    }};
}

/// Generated from the same exhaustive command table as authorization and
/// ordering. Adding a Request variant cannot compile without adding its row,
/// and every row is classified. Extended ownership is a typed pattern; the
/// exhaustive generated base arms contain no wildcard or wire-tag matching.
#[allow(unused_variables)]
pub fn request_product_domain(request: &Request) -> RequestProductDomain {
    proto::command!(command_request_product_domain_match, request)
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
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_request_ordering_value!($ordering),)+
        }
    }};
}

#[allow(unused_variables)]
pub fn request_ordering(request: &Request) -> RequestOrdering {
    proto::command!(command_request_ordering_match, request)
}

macro_rules! command_requires_owner_capability_value {
    (owner_only) => {
        true
    };
    (public_read) => {
        false
    };
    (session_writer) => {
        false
    };
    (session_reader) => {
        false
    };
    (terminal) => {
        false
    };
    (project_files($project_root:ident)) => {
        false
    };
    (project_read($project_root:ident)) => {
        false
    };
    (session_row_writer($session_id:ident)) => {
        false
    };
    (session_row_reader($session_id:ident)) => {
        false
    };
    (custom($handler:ident)) => {
        false
    };
}

macro_rules! command_requires_owner_capability_match {
    (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
        match $request {
            $($(#[$row_attr])* $pattern => command_requires_owner_capability_value!($authz $(($authz_arg))?),)+
        }
    }};
}

/// Secret-bearing (`owner_only`) RPCs require the daemon-private owner
/// capability on the Unix-socket path (issue #296). Follow-up #337 replaces
/// blanket Owner with authenticated per-peer identity.
#[allow(unused_variables)]
pub fn request_requires_owner_capability(request: &Request) -> bool {
    proto::command!(command_requires_owner_capability_match, request)
}

#[cfg(test)]
mod tests {
    use super::*;

    macro_rules! request_ordering_rows_from_command_table {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut rows = Vec::new();
            $($(#[$row_attr])* rows.push(($kind, command_request_ordering_value!($ordering)));)+
            rows
        }};
    }

    macro_rules! request_ordering_row_count_from_command_table {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let mut count = 0usize;
            $($(#[$row_attr])* {
                let _ = stringify!($pattern);
                count += 1;
            })+
            count
        }};
    }

    macro_rules! command_kind_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$($(#[$row_attr])* $kind,)+]
        }};
    }

    macro_rules! command_product_domain_rows {
        (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            vec![$($(#[$row_attr])* ($kind, expected_product_domain($kind)),)+]
        }};
    }

    fn expected_product_domain(kind: &str) -> RequestProductDomain {
        if matches!(
            kind,
            "create_scheduled_job"
                | "list_scheduled_jobs"
                | "delete_scheduled_job"
                | "set_scheduled_job_enabled"
                | "run_scheduled_job"
                | "image_endpoint_list"
                | "image_endpoint_get"
                | "image_target_list"
                | "image_target_get"
                | "image_workflow_list"
                | "image_workflow_get"
                | "image_endpoint_create"
                | "image_endpoint_update"
                | "image_endpoint_delete"
                | "image_target_create"
                | "image_target_update"
                | "image_target_delete"
                | "image_target_set_default"
                | "image_workflow_upload"
                | "image_workflow_bind"
                | "image_workflow_delete"
                | "get_image_spend_policy"
                | "save_image_spend_policy"
        ) {
            RequestProductDomain::Extended
        } else {
            RequestProductDomain::Base
        }
    }

    #[test]
    fn extended_product_domain_inventory_is_explicit_and_complete() {
        let rows = proto::command!(command_kind_rows);
        let image_rows: std::collections::BTreeSet<_> = rows
            .iter()
            .copied()
            .filter(|kind| kind.starts_with("image_") || kind.contains("image_spend_policy"))
            .collect();
        let expected_image_rows = std::collections::BTreeSet::from([
            #[cfg(feature = "extended")]
            "image_endpoint_list",
            #[cfg(feature = "extended")]
            "image_endpoint_get",
            #[cfg(feature = "extended")]
            "image_target_list",
            #[cfg(feature = "extended")]
            "image_target_get",
            #[cfg(feature = "extended")]
            "image_workflow_list",
            #[cfg(feature = "extended")]
            "image_workflow_get",
            #[cfg(feature = "extended")]
            "image_endpoint_create",
            #[cfg(feature = "extended")]
            "image_endpoint_update",
            #[cfg(feature = "extended")]
            "image_endpoint_delete",
            #[cfg(feature = "extended")]
            "image_target_create",
            #[cfg(feature = "extended")]
            "image_target_update",
            #[cfg(feature = "extended")]
            "image_target_delete",
            #[cfg(feature = "extended")]
            "image_target_set_default",
            #[cfg(feature = "extended")]
            "image_workflow_upload",
            #[cfg(feature = "extended")]
            "image_workflow_bind",
            #[cfg(feature = "extended")]
            "image_workflow_delete",
            #[cfg(feature = "extended")]
            "get_image_spend_policy",
            #[cfg(feature = "extended")]
            "save_image_spend_policy",
        ]);
        assert_eq!(image_rows, expected_image_rows);
        #[cfg(feature = "extended")]
        for scheduler in [
            "create_scheduled_job",
            "list_scheduled_jobs",
            "delete_scheduled_job",
            "set_scheduled_job_enabled",
            "run_scheduled_job",
        ] {
            assert!(
                rows.contains(&scheduler),
                "missing classified scheduler row `{scheduler}`"
            );
        }
        let classified_extended: std::collections::BTreeSet<_> =
            proto::command!(command_product_domain_rows)
                .into_iter()
                .filter_map(|(kind, domain)| {
                    (domain == RequestProductDomain::Extended).then_some(kind)
                })
                .collect();
        let expected_extended = image_rows
            .into_iter()
            .chain({
                #[cfg(feature = "extended")]
                {
                    [
                        "create_scheduled_job",
                        "list_scheduled_jobs",
                        "delete_scheduled_job",
                        "set_scheduled_job_enabled",
                        "run_scheduled_job",
                    ]
                }
                #[cfg(not(feature = "extended"))]
                {
                    [] as [&str; 0]
                }
            })
            .collect();
        assert_eq!(classified_extended, expected_extended);
    }

    macro_rules! request_ordering_no_wildcard_check {
        (($request:ident) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
            let classify_without_wildcard: fn(&Request) -> RequestOrdering = |$request| {
                match $request {
                    $($(#[$row_attr])* $pattern => command_request_ordering_value!($ordering),)+
                }
            };
            let mut names = Vec::new();
            $($(#[$row_attr])* names.push($kind);)+
            (classify_without_wildcard, names)
        }};
    }

    #[cfg(feature = "remote")]
    fn remote(scope: PrincipalScope, project_root: Option<String>) -> ClientPrincipal {
        ClientPrincipal::from_verified_remote(
            "user-1".to_string(),
            vec![PrincipalGrant {
                scope,
                project_root,
            }],
            None,
        )
    }

    #[cfg(feature = "remote")]
    #[test]
    fn agent_scope_allows_write_and_read_for_matching_project() {
        let principal = remote(PrincipalScope::Agent, Some("/workspace/app".to_string()));
        assert!(principal.can_agent_write_project("/workspace/app"));
        assert!(principal.can_agent_read_project("/workspace/app"));
        assert!(!principal.can_agent_write_project("/workspace/other"));
    }

    #[cfg(feature = "remote")]
    #[test]
    fn readonly_scope_allows_read_but_not_write() {
        let principal = remote(
            PrincipalScope::AgentReadonly,
            Some("/workspace/app".to_string()),
        );
        assert!(!principal.can_agent_write_project("/workspace/app"));
        assert!(principal.can_agent_read_project("/workspace/app"));
    }

    #[cfg(feature = "remote")]
    #[test]
    fn instance_wide_grant_matches_any_project() {
        let principal = remote(PrincipalScope::ProjectFiles, None);
        assert!(principal.has_project_files("/workspace/app"));
        assert!(principal.has_project_files("/elsewhere"));
    }

    #[cfg(feature = "remote")]
    #[test]
    fn image_generation_admin_scope_grants_no_terminal_agent_or_file_access() {
        // AC1: `ImageGenerationAdmin` must NEVER imply terminal, agent, or
        // project-file access through any principal helper. A remote grant
        // carrying only this scope is inert through every access path, even
        // when bound to the exact project it names and even with the rootless
        // wildcard (`project_root: None`) that would widen an access scope.
        for root in [Some("/workspace/app".to_string()), None] {
            let admin = remote(PrincipalScope::ImageGenerationAdmin, root);
            assert!(!admin.has_terminal(), "admin scope must not grant terminal");
            assert!(
                !admin.can_agent_write_project("/workspace/app"),
                "admin scope must not grant agent write"
            );
            assert!(
                !admin.can_agent_read_project("/workspace/app"),
                "admin scope must not grant agent read"
            );
            assert!(
                !admin.has_project_files("/workspace/app"),
                "admin scope must not grant project files"
            );
            // It is also inert when queried directly for the four access scopes.
            assert!(!admin.has_scope(PrincipalScope::Terminal));
            assert!(!admin.has_project_scope(PrincipalScope::Agent, "/workspace/app"));
            assert!(!admin.has_project_scope(PrincipalScope::AgentReadonly, "/workspace/app"));
            assert!(!admin.has_project_scope(PrincipalScope::ProjectFiles, "/workspace/app"));
        }
    }

    #[cfg(feature = "remote")]
    #[test]
    fn rootless_image_generation_admin_grant_does_not_wildcard_match() {
        // A directly-constructed `ImageGenerationAdmin` grant with no project
        // root (bypassing the mint/decode funnel) must NOT inherit the
        // `None`-matches-any-project wildcard: `has_project_scope` fails closed
        // for it against every project, unlike a rootless access scope which
        // legitimately grants instance-wide.
        let rootless_admin = remote(PrincipalScope::ImageGenerationAdmin, None);
        assert!(!rootless_admin.has_project_scope(PrincipalScope::ImageGenerationAdmin, "/any"));
        assert!(
            !rootless_admin
                .has_project_scope(PrincipalScope::ImageGenerationAdmin, "/workspace/app")
        );
        // Contrast: a rootless ProjectFiles grant DOES match any project.
        let rootless_files = remote(PrincipalScope::ProjectFiles, None);
        assert!(rootless_files.has_project_scope(PrincipalScope::ProjectFiles, "/any"));
    }

    #[test]
    fn image_generation_admin_scope_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&PrincipalScope::ImageGenerationAdmin).unwrap(),
            "\"image_generation_admin\""
        );
        assert_eq!(
            serde_json::from_str::<PrincipalScope>("\"image_generation_admin\"").unwrap(),
            PrincipalScope::ImageGenerationAdmin
        );
    }

    #[cfg(feature = "remote")]
    #[test]
    fn from_verified_remote_is_the_only_remote_constructor() {
        // After the standalone relay cutover, the legacy
        // `ClientPrincipal::from_relay` constructor is gone. The daemon
        // builds remote principals only from transport-neutral verified
        // fields, never from a relay-stamped `RelayPrincipal`.
        let principal = remote(PrincipalScope::Agent, Some("/workspace/app".to_string()));
        let tag = principal.tag().expect("remote principal has a tag");
        assert_eq!(tag, "flycockpit:user-1");
        assert!(!principal.is_owner());
        assert!(principal.can_agent_write_project("/workspace/app"));
    }

    #[test]
    fn owner_only_requests_require_the_daemon_private_capability() {
        macro_rules! owner_capability_rows {
            (($($context:ident),*) [$($(#[$row_attr:meta])* ($pattern:pat, $kind:literal, $authz:ident $(($authz_arg:ident))?, $session:ident $(($session_arg:ident))?, $mutating:literal, $remote_class:ident, $recovery:ident $(($recovery_evidence:ident))?, $ordering:ident, $audit_path:ident $(($($audit_arg:ident),+))?, $fcor_schema:literal, [$($fcor_field:ident: $fcor_type:ty => $fcor_role:ident $(($($fcor_role_arg:ident),*))?),*]);)+]) => {{
                vec![$($(#[$row_attr])* ($kind, command_requires_owner_capability_value!($authz $(($authz_arg))?)),)+]
            }};
        }
        let rows = proto::command!(owner_capability_rows);
        assert!(
            rows.iter()
                .any(|(kind, required)| *kind == "put_named_secret" && *required)
        );
        assert!(rows.iter().any(|(kind, required)| {
            *kind == "create_code_root_with_acp_ingress_v1" && *required
        }));
        assert!(
            rows.iter()
                .any(|(kind, required)| *kind == "daemon_status" && !*required)
        );
        let required = rows.iter().filter(|(_, required)| *required).count();
        assert!(
            required >= 100,
            "secret-bearing owner_only rows must stay gated; found {required}"
        );
        assert!(request_requires_owner_capability(
            &Request::PutNamedSecret {
                name: "k".into(),
                value: "v".into(),
            }
        ));
        assert!(!request_requires_owner_capability(&Request::DaemonStatus));
    }

    #[test]
    fn request_ordering_concurrent_set_is_exact() {
        let rows = proto::command!(request_ordering_rows_from_command_table);
        assert!(
            rows.len() > 80,
            "command table should enumerate Request rows"
        );
        #[cfg_attr(not(feature = "remote"), allow(unused_mut))]
        let mut expected = std::collections::BTreeSet::from([
            "agent_installation_inspect",
            "agent_installation_list",
            "daemon_status",
            "export_policy",
            "export_session_data",
            "fs_list",
            "fs_read",
            "fs_stat",
            "find_worktree_root",
            "get_host_capabilities",
            "refresh_host_capabilities",
            #[cfg(feature = "extended")]
            "get_image_spend_policy",
            "get_agent_effective_settings",
            "get_session_setup_snapshot",
            #[cfg(feature = "extended")]
            "image_endpoint_list",
            #[cfg(feature = "extended")]
            "image_endpoint_get",
            #[cfg(feature = "extended")]
            "image_target_list",
            #[cfg(feature = "extended")]
            "image_target_get",
            #[cfg(feature = "extended")]
            "image_workflow_list",
            #[cfg(feature = "extended")]
            "image_workflow_get",
            "get_provider_catalog_snapshot",
            "get_run_invocation_status",
            "get_usage_counts",
            "git_diff",
            "git_diff_file",
            "git_repo_status",
            "git_review_sources",
            "git_status",
            "count_pinned_messages",
            "list_pinned_message_seqs",
            "list_pinned_messages_with_text",
            "list_media_egress_verdicts",
            "list_conversation_rules",
            "sealed_owner_inventory",
            "list_sealed_actions",
            "pinned_message_state",
            "guidance_estimate",
            "get_inventory_bundle",
            "list_assistants",
            "list_leak_reports",
            #[cfg(feature = "extended")]
            "list_scheduled_jobs",
            "list_sessions",
            "read_agent_attention",
            "read_agent_tree",
            "read_assistant_inbox",
            "read_bulk_transfer_chunk",
            "read_redacted_export_chunk",
            "read_client_submission_receipt",
            "read_history_page",
            "read_session_messages",
            "read_subagent_history_page",
            "resource_snapshot",
            "session_live_status",
            "stats_rollup",
            "subagent_transcript",
            "terminal_ingress_status",
            "list_packages",
            "list_failed_tool_calls",
            "get_session_compactions",
            "get_storage_report",
            "get_assistant",
            "diagnose_media_reservation",
            "get_doctor_snapshot",
            "get_agent_inventory",
            "get_agent_edit_snapshot",
            "get_extended_config_snapshot",
            "get_guidance_enablement_trace",
            "get_image_sidecar_authority_snapshot",
            "get_agent_editor_lease_settlement",
        ]);
        #[cfg(feature = "remote")]
        expected.extend(["get_connector_state", "get_org_sync_status"]);
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
            "set_queued_user_message_class",
            "promote_queued_user_messages",
            "send_now_queued_user_message",
            "cancel_turn",
            "steer_delegation",
            "resolve_interrupt",
            "set_active_model",
            "set_agent",
            "set_approval_mode",
            "set_delegation_recursion",
            "set_sandbox",
            "set_sandbox_escalation",
            "set_preflight",
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
