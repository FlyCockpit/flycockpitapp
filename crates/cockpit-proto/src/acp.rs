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
