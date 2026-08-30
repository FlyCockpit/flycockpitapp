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
//! TODO(acp-forwarded-mcp-proto-ingress-contract): replace these stubs with
//! the landed ingress/discovery contracts without changing the CLI codec.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Maximum size of every caller-generated opaque identity in this contract.
pub const OPAQUE_ASCII_ID_128_MAX_BYTES: usize = 128;
pub const CODE_ROOT_DISCOVERY_PAGE_MAX: u16 = 100;
pub const CODE_ROOT_DELIVERY_PAGE_MAX: u16 = 256;

/// A bounded caller identity. It is deliberately not a UUID: ACP peers may
/// already have stable identifiers in another namespace.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// Daemon-owned identity of a Code root. A Code root is the root Cockpit
/// session; it is never an agent/subagent identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeRootIdV1(pub Uuid);

/// Server-minted boot-local attachment authority. The value is opaque and
/// disappears with the daemon process; it is never stored in SQLite.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeRootAttachmentCapabilityV1(String);

impl CodeRootAttachmentCapabilityV1 {
    pub fn from_daemon_random(id: Uuid) -> Self {
        Self(id.simple().to_string())
    }

    pub fn expose_opaque(&self) -> &str {
        &self.0
    }
}

/// Opaque durable position in the Code-root projection. Clients may retain it
/// but cannot construct a database sequence from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CodeRootReplayCursorV1(String);

impl CodeRootReplayCursorV1 {
    pub fn from_daemon_random(id: Uuid) -> Self {
        Self(id.simple().to_string())
    }

    pub fn expose_opaque(&self) -> &str {
        &self.0
    }
}

/// Opaque cursor into one frozen discovery snapshot. It is boot-local and is
/// not interchangeable with a durable replay cursor.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    pub logical_client_id: OpaqueAsciiId128V1,
    pub client_request_id: OpaqueAsciiId128V1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replay_cursor: Option<CodeRootReplayCursorV1>,
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeRootReadV1 {
    pub root_id: CodeRootIdV1,
    pub workspace_path: String,
    pub title: Option<String>,
    pub active_agent: String,
    pub active_agent_path: Vec<String>,
    pub history: Vec<crate::HistoryEntry>,
    pub attention: Vec<crate::AgentDecisionAttention>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCodeRootV1Result {
    pub attachment: CodeRootAttachmentV1,
    pub root: CodeRootReadV1,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadCodeRootV1Result {
    pub root: CodeRootReadV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeRootDeliveryPayloadV1 {
    History { entry: crate::HistoryEntry },
    Attention { entry: crate::AgentDecisionAttention },
    RootStateChanged,
    ClientIncompatible,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Closed forwarded-MCP ingress: declarations plus provenance, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpForwardedMcpIngressV1 {
    pub declarations: Vec<AcpForwardedMcpDeclarationV1>,
    pub provenance: AcpForwardedMcpProvenanceV1,
}

/// One forwarded MCP server declaration admitted from ACP `mcpServers`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpForwardedMcpDeclarationV1 {
    pub name: String,
    pub transport: AcpForwardedMcpTransportV1,
}

/// Transport discriminant for a forwarded MCP declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
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
pub struct AcpNameValuePairV1 {
    pub name: String,
    pub value: String,
}

/// Provenance for an ingress batch. No root, capability, epoch, or binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcpForwardedMcpProvenanceV1 {
    pub method: AcpSessionAdmissionMethodV1,
    pub session_id: Option<String>,
}

/// ACP method that produced the ingress declarations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpSessionAdmissionMethodV1 {
    SessionNew,
    SessionLoad,
}

/// Typed resolve submitted at most once per selected permission response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveCodeRootInterruptV1 {
    pub attachment_capability: CodeRootAttachmentCapabilityV1,
    pub client_request_id: String,
    pub selected_choice: String,
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
