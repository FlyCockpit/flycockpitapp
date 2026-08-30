//! Closed ACP v1 ingress and resolve stubs consumed by the CLI transport seam.
//!
//! `AcpForwardedMcpIngressV1` holds declarations and provenance only. It does
//! not carry a code-root, capability set, epoch, or catalog binding. The CLI
//! bridge facade is the only production converter from the CLI-private DTO
//! into this type. Semantic validation, catalog lifecycle, connection, and
//! execution stay in core; this crate does not import CLI or ACP schema types.
//!
//! `ResolveCodeRootInterruptV1` is the typed first-wins resolve request the
//! outbound permission registry submits. The owning discovery contract may
//! widen the payload later; the transport seam depends only on this closed
//! shape.
//!
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;
use uuid::Uuid;

/// Maximum size of every caller-generated opaque identity in this contract.
pub const OPAQUE_ASCII_ID_128_MAX_BYTES: usize = 128;
pub const CODE_ROOT_DISCOVERY_PAGE_MAX: u16 = 100;
pub const CODE_ROOT_DELIVERY_PAGE_MAX: u16 = 256;

/// A bounded caller identity. It is deliberately not a UUID: ACP peers may
/// already have stable identifiers in another namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OpaqueAsciiId128V1(String);

impl OpaqueAsciiId128V1 {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > OPAQUE_ASCII_ID_128_MAX_BYTES
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("opaque id must contain 1..=128 printable ASCII bytes".to_string());
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OpaqueAsciiId128V1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Daemon-owned identity of a Code root. A Code root is the root Cockpit
/// session; it is never an agent/subagent identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeRootIdV1(pub Uuid);

impl CodeRootIdV1 {
    /// Stable, non-zero capture identity for this never-recycled root. Both
    /// discovery and attachment derive the value from the durable root id, so
    /// model selection and daemon-local attachment order cannot mint a second
    /// authority for the same capture.
    pub fn capture_generation(self) -> u64 {
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&self.0.as_bytes()[..8]);
        (u64::from_be_bytes(bytes) & 0x001f_ffff_ffff_ffff).max(1)
    }
}

/// Server-minted boot-local attachment authority. The value is opaque and
/// disappears with the daemon process; it is never stored in SQLite.
#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CodeRootAttachmentCapabilityV1(String);

impl std::fmt::Debug for CodeRootAttachmentCapabilityV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("CodeRootAttachmentCapabilityV1([REDACTED])")
    }
}

impl CodeRootAttachmentCapabilityV1 {
    pub fn from_daemon_random(id: Uuid) -> Self {
        Self(id.simple().to_string())
    }

    pub fn expose_opaque(&self) -> &str {
        &self.0
    }

    pub fn new_opaque(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err("attachment capability must be bounded printable ASCII".to_string());
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for CodeRootAttachmentCapabilityV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::new_opaque(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Opaque durable position in the Code-root projection. Clients may retain it
/// but cannot construct a database sequence from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CodeRootReplayCursorV1(String);

impl CodeRootReplayCursorV1 {
    pub fn from_daemon_random(id: Uuid) -> Self {
        Self(id.simple().to_string())
    }

    pub fn expose_opaque(&self) -> &str {
        &self.0
    }

    pub fn from_daemon_opaque(value: String) -> Result<Self, String> {
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("invalid daemon replay cursor".to_string());
        }
        Ok(Self(value))
    }
}

impl<'de> Deserialize<'de> for CodeRootReplayCursorV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::from_daemon_opaque(String::deserialize(deserializer)?)
            .map_err(serde::de::Error::custom)
    }
}

/// Opaque cursor into one frozen discovery snapshot. It is boot-local and is
/// not interchangeable with a durable replay cursor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CodeRootDiscoveryCursorV1(String);

impl CodeRootDiscoveryCursorV1 {
    pub fn from_daemon_random(id: Uuid) -> Self {
        Self(id.simple().to_string())
    }

    pub fn expose_opaque(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CodeRootDiscoveryCursorV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(serde::de::Error::custom("invalid discovery cursor"));
        }
        Ok(Self(value))
    }
}

/// The sole caller-supplied workspace selector. Core canonicalizes this path
/// and derives project identity; neither is accepted from the client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootWorkspaceSelectorV1 {
    pub path: String,
}

/// Parameters shared by first-party and ACP Code-root attachment. Keeping
/// these in a closed record prevents `Request::Attach` from regaining Code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootAttachOptionsV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_override: Option<cockpit_config::config::providers::ActiveModelRef>,
    #[serde(default)]
    pub no_sandbox: bool,
    #[serde(default)]
    pub interactive: bool,
    #[serde(default = "crate::default_client_protocol_version")]
    pub client_protocol_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_snapshot: Option<crate::EnvSnapshotWire>,
    #[serde(default)]
    pub env_policy: crate::EnvDriftPolicy,
}

/// The only constructor for a new Code root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCodeRootV1Request {
    pub workspace_selector: CodeRootWorkspaceSelectorV1,
    pub logical_client_id: OpaqueAsciiId128V1,
    pub client_request_id: OpaqueAsciiId128V1,
    pub options: CodeRootAttachOptionsV1,
}

/// The only route that resumes/attaches an existing Code root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachExistingCodeRootV1Request {
    pub root_id: CodeRootIdV1,
    /// The frozen discovery generation being attached. A daemon rejects a
    /// stale or forged generation before it starts a session worker.
    pub capture_generation: u64,
    pub logical_client_id: OpaqueAsciiId128V1,
    pub client_request_id: OpaqueAsciiId128V1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_cursor: Option<CodeRootReplayCursorV1>,
    /// Session-event cursor for bounded transcript rehydration. This is
    /// independent of the ACP delivery cursor above: the latter resumes
    /// root-state invalidations while this cursor resumes session history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since_seq: Option<i64>,
    pub options: CodeRootAttachOptionsV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseCodeRootAttachmentV1Request {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    pub client_request_id: OpaqueAsciiId128V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseCodeRootAttachmentV1Result {
    Closed,
    AlreadyClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverCodeRootsV1Request {
    pub workspace_selector: CodeRootWorkspaceSelectorV1,
    pub logical_client_id: OpaqueAsciiId128V1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<CodeRootDiscoveryCursorV1>,
    pub limit: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodeRootLifecycleV1 {
    Active,
    Ended,
    Archived,
}

/// Secret-free discovery row frozen at the first page read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootSummaryV1 {
    pub root_id: CodeRootIdV1,
    pub title: Option<String>,
    pub short_id: String,
    pub workspace_path: String,
    pub last_active_at_unix_ms: i64,
    pub lifecycle: CodeRootLifecycleV1,
    pub capture_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoverCodeRootsV1Result {
    pub roots: Vec<CodeRootSummaryV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<CodeRootDiscoveryCursorV1>,
}

/// Common success authority returned by create and attach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootAttachmentV1 {
    pub root_id: CodeRootIdV1,
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    pub capture_generation: u64,
    pub replay_cursor: CodeRootReplayCursorV1,
}

/// Initial immutable/read projection. Mutable tree, decisions and deliveries
/// remain separate reads and never become editor-owned state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootReadV1 {
    pub root_id: CodeRootIdV1,
    pub workspace_path: String,
    pub title: Option<String>,
    pub short_id: String,
    pub project_id: String,
    pub active_agent: String,
    pub active_agent_path: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreground_target: Option<crate::QueueTarget>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_subagent: Option<crate::ActiveSubagent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_model_state: Option<crate::ActiveModelState>,
    pub history: Vec<crate::HistoryEntry>,
    #[serde(default)]
    pub paused_work: Vec<crate::PausedWorkSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_required: Option<Box<crate::ResumeRepairState>>,
    pub daemon_version: String,
    pub compatible: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_baseline: Option<crate::EnvSnapshotMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_session: Option<crate::EnvSnapshotMeta>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_drift: Option<Box<crate::EnvDiffSummary>>,
    #[serde(default)]
    pub env_policy_applied: crate::EnvDriftPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub btw_fork: Option<crate::BtwForkInfo>,
    pub attention: Vec<crate::AgentDecisionAttention>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCodeRootV1Result {
    pub attachment: CodeRootAttachmentV1,
    pub root: CodeRootReadV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachExistingCodeRootV1Result {
    pub attachment: CodeRootAttachmentV1,
    pub root: CodeRootReadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCodeRootV1Request {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCodeRootV1Result {
    pub root: CodeRootReadV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CodeRootDeliveryPayloadV1 {
    History {
        entry: crate::HistoryEntry,
    },
    Attention {
        entry: crate::AgentDecisionAttention,
    },
    RootStateChanged,
    ClientIncompatible,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootDeliveryV1 {
    pub delivery_id: Uuid,
    pub cursor: CodeRootReplayCursorV1,
    pub payload: CodeRootDeliveryPayloadV1,
    pub created_at_unix_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCodeRootDeliveriesV1Request {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<CodeRootReplayCursorV1>,
    pub limit: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCodeRootDeliveriesV1Result {
    pub deliveries: Vec<CodeRootDeliveryV1>,
    pub high_water_cursor: CodeRootReplayCursorV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckCodeRootDeliveriesV1Request {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    pub through: CodeRootReplayCursorV1,
    pub client_request_id: OpaqueAsciiId128V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AckCodeRootDeliveriesV1Result {
    pub acked_through: CodeRootReplayCursorV1,
}

/// First-party constructor used by CLI/TUI/core call sites. ACP callers use
/// their stable editor identities directly.
#[allow(clippy::too_many_arguments)]
pub fn create_code_root_v1_request(
    project_root: String,
    initial_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    no_sandbox: bool,
    interactive: bool,
    model_override: Option<cockpit_config::config::providers::ActiveModelRef>,
    client_protocol_version: u32,
    env_snapshot: Option<crate::EnvSnapshotWire>,
    env_policy: crate::EnvDriftPolicy,
) -> crate::Request {
    let logical_client_id = OpaqueAsciiId128V1::new(format!("cockpit-{}", Uuid::new_v4()))
        .expect("generated logical client id is bounded ASCII");
    crate::Request::CreateCodeRootV1(CreateCodeRootV1Request {
        workspace_selector: CodeRootWorkspaceSelectorV1 { path: project_root },
        logical_client_id,
        client_request_id: OpaqueAsciiId128V1::new(Uuid::new_v4().to_string())
            .expect("generated request id is bounded ASCII"),
        options: CodeRootAttachOptionsV1 {
            initial_model,
            model_override,
            no_sandbox,
            interactive,
            client_protocol_version,
            env_snapshot,
            env_policy,
        },
    })
}

#[allow(clippy::too_many_arguments)]
pub fn attach_existing_code_root_v1_request(
    session_id: Uuid,
    since_seq: Option<i64>,
    initial_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    no_sandbox: bool,
    interactive: bool,
    model_override: Option<cockpit_config::config::providers::ActiveModelRef>,
    client_protocol_version: u32,
    env_snapshot: Option<crate::EnvSnapshotWire>,
    env_policy: crate::EnvDriftPolicy,
) -> crate::Request {
    let logical_client_id = OpaqueAsciiId128V1::new(format!("cockpit-{}", Uuid::new_v4()))
        .expect("generated logical client id is bounded ASCII");
    crate::Request::AttachExistingCodeRootV1(AttachExistingCodeRootV1Request {
        root_id: CodeRootIdV1(session_id),
        capture_generation: CodeRootIdV1(session_id).capture_generation(),
        logical_client_id,
        client_request_id: OpaqueAsciiId128V1::new(Uuid::new_v4().to_string())
            .expect("generated request id is bounded ASCII"),
        replay_cursor: None,
        since_seq,
        options: CodeRootAttachOptionsV1 {
            initial_model,
            model_override,
            no_sandbox,
            interactive,
            client_protocol_version,
            env_snapshot,
            env_policy,
        },
    })
}

pub const ACP_FORWARDED_MCP_VERSION_V1: u8 = 1;
pub const ACP_FORWARDED_MCP_NAME_MAX_SCALARS_V1: usize = 64;
pub const ACP_FORWARDED_MCP_NAME_MAX_BYTES_V1: usize = 256;
pub const ACP_FORWARDED_MCP_ENDPOINT_MAX_SCALARS_V1: usize = 4_096;
pub const ACP_FORWARDED_MCP_ENDPOINT_MAX_BYTES_V1: usize = 4_096;
pub const ACP_FORWARDED_MCP_ITEM_MAX_SCALARS_V1: usize = 8_192;
pub const ACP_FORWARDED_MCP_ITEM_MAX_BYTES_V1: usize = 8_192;
pub const ACP_FORWARDED_MCP_ITEMS_MAX_V1: usize = 64;
pub const ACP_FORWARDED_MCP_DECLARATIONS_MAX_V1: usize = 32;
pub const ACP_FORWARDED_MCP_DECLARATION_MAX_CANONICAL_BYTES_V1: usize = 131_072;
pub const ACP_FORWARDED_MCP_VECTOR_MAX_CANONICAL_BYTES_V1: usize = 1_048_576;

/// Closed forwarded-MCP ingress: declarations and two opaque ids, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpForwardedMcpIngressV1 {
    pub version: u8,
    pub declarations: Vec<AcpForwardedMcpDeclarationV1>,
    pub client_provenance_id: OpaqueAsciiId128V1,
    pub ingress_request_id: OpaqueAsciiId128V1,
}

/// One forwarded MCP server declaration admitted from ACP `mcpServers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcpForwardedMcpDeclarationV1 {
    pub name: String,
    pub transport: AcpForwardedMcpTransportV1,
}

/// Transport discriminant for a forwarded MCP declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AcpForwardedMcpTransportV1 {
    Stdio {
        command: String,
        args: Vec<String>,
        env: Vec<AcpNameValuePairV1>,
    },
    Http {
        url: String,
        headers: Vec<AcpNameValuePairV1>,
    },
    Sse {
        url: String,
        headers: Vec<AcpNameValuePairV1>,
    },
}

/// Explicit name/value pair used for env and headers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcpNameValuePairV1 {
    pub name: String,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcpForwardedMcpIngressV1 {
    version: u8,
    declarations: Vec<AcpForwardedMcpDeclarationV1>,
    client_provenance_id: OpaqueAsciiId128V1,
    ingress_request_id: OpaqueAsciiId128V1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAcpForwardedMcpDeclarationV1 {
    name: String,
    transport: AcpForwardedMcpTransportV1,
}

impl<'de> Deserialize<'de> for AcpForwardedMcpDeclarationV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawAcpForwardedMcpDeclarationV1::deserialize(deserializer)?;
        let mut declaration = Self {
            name: raw.name,
            transport: raw.transport,
        };
        declaration
            .normalize_and_validate()
            .map_err(serde::de::Error::custom)?;
        Ok(declaration)
    }
}

impl<'de> Deserialize<'de> for AcpForwardedMcpIngressV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawAcpForwardedMcpIngressV1::deserialize(deserializer)?;
        let ingress = Self {
            version: raw.version,
            declarations: raw.declarations,
            client_provenance_id: raw.client_provenance_id,
            ingress_request_id: raw.ingress_request_id,
        };
        ingress.validate().map_err(serde::de::Error::custom)?;
        Ok(ingress)
    }
}

impl AcpForwardedMcpDeclarationV1 {
    fn normalize_and_validate(&mut self) -> Result<(), String> {
        normalize_bounded(
            &mut self.name,
            "declaration name",
            ACP_FORWARDED_MCP_NAME_MAX_SCALARS_V1,
            ACP_FORWARDED_MCP_NAME_MAX_BYTES_V1,
            false,
        )?;
        match &mut self.transport {
            AcpForwardedMcpTransportV1::Stdio { command, args, env } => {
                normalize_bounded(
                    command,
                    "stdio command",
                    ACP_FORWARDED_MCP_ENDPOINT_MAX_SCALARS_V1,
                    ACP_FORWARDED_MCP_ENDPOINT_MAX_BYTES_V1,
                    false,
                )?;
                validate_count(args, "stdio arguments")?;
                for argument in args {
                    normalize_bounded(
                        argument,
                        "stdio argument",
                        ACP_FORWARDED_MCP_ITEM_MAX_SCALARS_V1,
                        ACP_FORWARDED_MCP_ITEM_MAX_BYTES_V1,
                        true,
                    )?;
                }
                normalize_pairs(env, "environment", false)?;
            }
            AcpForwardedMcpTransportV1::Http { url, headers }
            | AcpForwardedMcpTransportV1::Sse { url, headers } => {
                normalize_bounded(
                    url,
                    "transport URL",
                    ACP_FORWARDED_MCP_ENDPOINT_MAX_SCALARS_V1,
                    ACP_FORWARDED_MCP_ENDPOINT_MAX_BYTES_V1,
                    false,
                )?;
                normalize_pairs(headers, "header", true)?;
            }
        }
        let canonical = serde_json::to_vec(self)
            .map_err(|error| format!("serializing canonical MCP declaration: {error}"))?;
        if canonical.len() > ACP_FORWARDED_MCP_DECLARATION_MAX_CANONICAL_BYTES_V1 {
            return Err("canonical MCP declaration exceeds 131072 bytes".to_string());
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), String> {
        let mut normalized = self.clone();
        normalized.normalize_and_validate()?;
        if &normalized != self {
            return Err("forwarded MCP strings must be NFC-normalized".to_string());
        }
        Ok(())
    }
}

impl AcpForwardedMcpIngressV1 {
    pub fn validate(&self) -> Result<(), String> {
        if self.version != ACP_FORWARDED_MCP_VERSION_V1 {
            return Err("forwarded MCP ingress version must be 1".to_string());
        }
        if self.declarations.len() > ACP_FORWARDED_MCP_DECLARATIONS_MAX_V1 {
            return Err("forwarded MCP ingress exceeds 32 declarations".to_string());
        }
        let mut names = HashSet::with_capacity(self.declarations.len());
        for declaration in &self.declarations {
            declaration.validate()?;
            if !names.insert(declaration.name.clone()) {
                return Err("forwarded MCP declaration names must be unique".to_string());
            }
        }
        let canonical = serde_json::to_vec(&self.declarations)
            .map_err(|error| format!("serializing canonical MCP declaration vector: {error}"))?;
        if canonical.len() > ACP_FORWARDED_MCP_VECTOR_MAX_CANONICAL_BYTES_V1 {
            return Err("canonical MCP declaration vector exceeds 1048576 bytes".to_string());
        }
        Ok(())
    }
}

fn validate_count<T>(values: &[T], field: &str) -> Result<(), String> {
    if values.len() > ACP_FORWARDED_MCP_ITEMS_MAX_V1 {
        return Err(format!("{field} exceeds 64 entries"));
    }
    Ok(())
}

fn normalize_pairs(
    pairs: &mut [AcpNameValuePairV1],
    field: &str,
    ascii_case_insensitive: bool,
) -> Result<(), String> {
    validate_count(pairs, field)?;
    let mut names = HashSet::with_capacity(pairs.len());
    for pair in pairs {
        normalize_bounded(
            &mut pair.name,
            &format!("{field} name"),
            ACP_FORWARDED_MCP_ITEM_MAX_SCALARS_V1,
            ACP_FORWARDED_MCP_ITEM_MAX_BYTES_V1,
            false,
        )?;
        normalize_bounded(
            &mut pair.value,
            &format!("{field} value"),
            ACP_FORWARDED_MCP_ITEM_MAX_SCALARS_V1,
            ACP_FORWARDED_MCP_ITEM_MAX_BYTES_V1,
            true,
        )?;
        let semantic_name = if ascii_case_insensitive {
            pair.name.to_ascii_lowercase()
        } else {
            pair.name.clone()
        };
        if !names.insert(semantic_name) {
            return Err(format!("duplicate semantic {field} name"));
        }
    }
    Ok(())
}

fn normalize_bounded(
    value: &mut String,
    field: &str,
    max_scalars: usize,
    max_bytes: usize,
    allow_empty: bool,
) -> Result<(), String> {
    *value = value.nfc().collect();
    let scalar_count = value.chars().count();
    if (!allow_empty && value.is_empty())
        || scalar_count > max_scalars
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
    {
        return Err(format!(
            "{field} must be control-free and within {max_scalars} scalars/{max_bytes} bytes"
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCodeRootWithAcpIngressV1Request {
    pub base: CreateCodeRootV1Request,
    pub ingress: AcpForwardedMcpIngressV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCodeRootWithAcpIngressV1Result {
    pub base: CreateCodeRootV1Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachExistingCodeRootWithAcpIngressV1Request {
    pub base: AttachExistingCodeRootV1Request,
    pub ingress: AcpForwardedMcpIngressV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachExistingCodeRootWithAcpIngressV1Result {
    pub base: AttachExistingCodeRootV1Result,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseAcpCodeRootAttachmentV1Request {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    pub client_request_id: OpaqueAsciiId128V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloseAcpCodeRootAttachmentV1Outcome {
    Closed,
    AlreadyClosed,
}

impl From<CloseCodeRootAttachmentV1Result> for CloseAcpCodeRootAttachmentV1Outcome {
    fn from(value: CloseCodeRootAttachmentV1Result) -> Self {
        match value {
            CloseCodeRootAttachmentV1Result::Closed => Self::Closed,
            CloseCodeRootAttachmentV1Result::AlreadyClosed => Self::AlreadyClosed,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloseAcpCodeRootAttachmentV1Result {
    pub outcome: CloseAcpCodeRootAttachmentV1Outcome,
}

/// Typed resolve submitted at most once per selected permission response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveCodeRootInterruptV1 {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    pub attention_id: OpaqueAsciiId128V1,
    pub client_request_id: OpaqueAsciiId128V1,
    pub selected_choice: OpaqueAsciiId128V1,
}

/// First-wins durable result of [`ResolveCodeRootInterruptV1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolveCodeRootInterruptResultV1 {
    Accepted,
    AlreadyResolvedSame,
    AlreadyResolvedOther,
    Cancelled,
    Expired,
}

#[cfg(test)]
mod forwarded_mcp_tests {
    use super::*;
    use serde_json::json;

    fn pair(name: &str, value: &str) -> AcpNameValuePairV1 {
        AcpNameValuePairV1 {
            name: name.to_string(),
            value: value.to_string(),
        }
    }

    fn declaration(transport: AcpForwardedMcpTransportV1) -> AcpForwardedMcpDeclarationV1 {
        AcpForwardedMcpDeclarationV1 {
            name: "server".to_string(),
            transport,
        }
    }

    fn ingress(declarations: Vec<AcpForwardedMcpDeclarationV1>) -> AcpForwardedMcpIngressV1 {
        AcpForwardedMcpIngressV1 {
            version: 1,
            declarations,
            client_provenance_id: OpaqueAsciiId128V1::new("editor-instance").unwrap(),
            ingress_request_id: OpaqueAsciiId128V1::new("request-1").unwrap(),
        }
    }

    fn decode_declaration(value: serde_json::Value) -> Result<AcpForwardedMcpDeclarationV1, String> {
        serde_json::from_value(value).map_err(|error| error.to_string())
    }

    fn padded_declaration(name: &str, target_bytes: usize) -> AcpForwardedMcpDeclarationV1 {
        let mut declaration = AcpForwardedMcpDeclarationV1 {
            name: name.to_string(),
            transport: AcpForwardedMcpTransportV1::Stdio {
                command: "mcp".to_string(),
                args: vec![String::new(); 17],
                env: vec![],
            },
        };
        let current_bytes = serde_json::to_vec(&declaration).unwrap().len();
        let mut remaining = target_bytes
            .checked_sub(current_bytes)
            .expect("padding target covers the declaration framing");
        let AcpForwardedMcpTransportV1::Stdio { args, .. } = &mut declaration.transport else {
            unreachable!();
        };
        for argument in args {
            let bytes = remaining.min(ACP_FORWARDED_MCP_ITEM_MAX_BYTES_V1);
            argument.push_str(&"x".repeat(bytes));
            remaining -= bytes;
        }
        assert_eq!(remaining, 0, "padding fits the bounded argument vector");
        assert_eq!(serde_json::to_vec(&declaration).unwrap().len(), target_bytes);
        declaration
    }

    #[test]
    fn all_stable_transports_round_trip_with_exact_closed_shapes() {
        for transport in [
            AcpForwardedMcpTransportV1::Stdio {
                command: "mcp".to_string(),
                args: vec!["--stdio".to_string()],
                env: vec![pair("TOKEN_NAME", "not-a-credential")],
            },
            AcpForwardedMcpTransportV1::Http {
                url: "https://example.invalid/mcp".to_string(),
                headers: vec![pair("x-routing", "blue")],
            },
            AcpForwardedMcpTransportV1::Sse {
                url: "https://example.invalid/events".to_string(),
                headers: vec![],
            },
        ] {
            let value = serde_json::to_value(ingress(vec![declaration(transport)])).unwrap();
            let decoded: AcpForwardedMcpIngressV1 = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
        }
    }

    #[test]
    fn decoder_normalizes_before_applying_independent_scalar_and_byte_limits() {
        let exact_ascii = "a".repeat(64);
        let over_ascii = "a".repeat(65);
        let exact_multibyte = "é".repeat(64);
        let over_bytes = "🦀".repeat(65);
        for (name, accepted) in [
            (exact_ascii, true),
            (over_ascii, false),
            (exact_multibyte, true),
            (over_bytes, false),
        ] {
            let result = decode_declaration(json!({
                "name": name,
                "transport": {"type": "stdio", "command": "mcp", "args": [], "env": []}
            }));
            assert_eq!(result.is_ok(), accepted);
        }
        let decomposed = "e\u{301}".repeat(64);
        let normalized = decode_declaration(json!({
            "name": decomposed,
            "transport": {"type": "stdio", "command": "mcp", "args": [], "env": []}
        }))
        .unwrap();
        assert_eq!(normalized.name, "é".repeat(64));
    }

    #[test]
    fn endpoint_and_item_limits_cover_ascii_multibyte_and_controls() {
        for (exact, over) in [
            ("a".repeat(4_096), "a".repeat(4_097)),
            ("é".repeat(2_048), "é".repeat(2_049)),
        ] {
            let valid = json!({
                "name": "server",
                "transport": {"type": "stdio", "command": exact, "args": [], "env": []}
            });
            let invalid = json!({
                "name": "server",
                "transport": {"type": "stdio", "command": over, "args": [], "env": []}
            });
            assert!(decode_declaration(valid).is_ok());
            assert!(decode_declaration(invalid).is_err());
        }
        let exact_item = "x".repeat(8_192);
        let over_item = "x".repeat(8_193);
        assert!(decode_declaration(json!({
            "name": "server",
            "transport": {"type": "stdio", "command": "mcp", "args": [exact_item], "env": []}
        })).is_ok());
        assert!(decode_declaration(json!({
            "name": "server",
            "transport": {"type": "stdio", "command": "mcp", "args": [over_item], "env": []}
        })).is_err());
        assert!(decode_declaration(json!({
            "name": "server\n",
            "transport": {"type": "stdio", "command": "mcp", "args": [], "env": []}
        })).is_err());
    }

    #[test]
    fn decoder_rejects_unknowns_duplicates_counts_and_raw_json_escape_hatches() {
        let unknown_variant = json!({
            "name": "server", "transport": {"type": "websocket", "url": "wss://x"}
        });
        assert!(decode_declaration(unknown_variant).is_err());
        let extra = json!({
            "name": "server", "_meta": {},
            "transport": {"type": "stdio", "command": "mcp", "args": [], "env": []}
        });
        assert!(decode_declaration(extra).is_err());
        let duplicate_headers = json!({
            "name": "server",
            "transport": {"type": "http", "url": "https://x", "headers": [
                {"name": "Authorization", "value": "one"},
                {"name": "authorization", "value": "two"}
            ]}
        });
        assert!(decode_declaration(duplicate_headers).is_err());
        let too_many_args = vec!["x"; 65];
        assert!(decode_declaration(json!({
            "name": "server",
            "transport": {"type": "stdio", "command": "mcp", "args": too_many_args, "env": []}
        })).is_err());
        assert!(serde_json::from_str::<AcpForwardedMcpIngressV1>(r#"{
            "version":1,"declarations":[],"client_provenance_id":"p",
            "ingress_request_id":"r","metadata":{}
        }"#).is_err());
        assert!(serde_json::from_slice::<AcpForwardedMcpIngressV1>(b"\xff").is_err());
    }

    #[test]
    fn ingress_rejects_duplicate_server_names_version_and_vector_count() {
        let one = declaration(AcpForwardedMcpTransportV1::Stdio {
            command: "mcp".to_string(),
            args: vec![],
            env: vec![],
        });
        let mut duplicate = ingress(vec![one.clone(), one.clone()]);
        assert!(duplicate.validate().is_err());
        duplicate.declarations.clear();
        duplicate.version = 2;
        assert!(duplicate.validate().is_err());
        let mut too_many = Vec::new();
        for index in 0..33 {
            let mut item = one.clone();
            item.name = format!("server-{index}");
            too_many.push(item);
        }
        assert!(ingress(too_many).validate().is_err());
    }

    #[test]
    fn canonical_serialized_declaration_and_vector_limits_are_exact() {
        let exact = padded_declaration(
            "server",
            ACP_FORWARDED_MCP_DECLARATION_MAX_CANONICAL_BYTES_V1,
        );
        assert!(exact.validate().is_ok());
        let over = padded_declaration(
            "server",
            ACP_FORWARDED_MCP_DECLARATION_MAX_CANONICAL_BYTES_V1 + 1,
        );
        assert!(over.validate().is_err());

        let mut declarations = Vec::new();
        for index in 0..7 {
            declarations.push(padded_declaration(
                &format!("server-{index}"),
                ACP_FORWARDED_MCP_DECLARATION_MAX_CANONICAL_BYTES_V1,
            ));
        }
        let used = serde_json::to_vec(&declarations).unwrap().len();
        let final_target = ACP_FORWARDED_MCP_VECTOR_MAX_CANONICAL_BYTES_V1 - used - 1;
        declarations.push(padded_declaration("server-final", final_target));
        let exact_vector = ingress(declarations);
        assert_eq!(
            serde_json::to_vec(&exact_vector.declarations).unwrap().len(),
            ACP_FORWARDED_MCP_VECTOR_MAX_CANONICAL_BYTES_V1
        );
        assert!(exact_vector.validate().is_ok());

        let mut over_vector = exact_vector;
        let AcpForwardedMcpTransportV1::Stdio { args, .. } =
            &mut over_vector.declarations.last_mut().unwrap().transport
        else {
            unreachable!();
        };
        args.last_mut().unwrap().push('x');
        assert!(over_vector.declarations.last().unwrap().validate().is_ok());
        assert!(over_vector.validate().is_err());
    }
}
