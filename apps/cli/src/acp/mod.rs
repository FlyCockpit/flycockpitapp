//! ACP v1 stdio transport selection and conformance seam.
//!
//! jsonrpsee is the inbound JSON-RPC dispatch foundation. Cockpit owns the
//! LF codec, the duplicate-member raw parser, the session admission DTO, the
//! bridge facade, and the outbound permission registry. HTTP/WebSocket ACP
//! transports are out of launch scope.

pub mod adapter;
pub mod boundary;
pub mod bridge;
pub mod classify;
pub mod codec;
pub mod dispatch;
pub mod dto;
pub mod envelope;
pub mod raw_json;
pub mod registry;

pub use codec::{
    ACP_FORWARDED_MCP_VECTOR_MAX_BYTES_V1, ACP_JSON_FRAME_MAX_BYTES_V1, AcpFrame, AcpFrameError,
    AcpLineReader, AcpLineWriter,
};
pub use registry::{
    ACP_OUTBOUND_PERMISSION_MAX_CHARGED_BYTES_V1, ACP_OUTBOUND_PERMISSION_MAX_ENTRIES_V1,
    OutboundPermissionRegistry,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AcpTransportCounters {
    pub daemon_mutations: u64,
    pub bridge_conversions: u64,
    pub catalog_mutations: u64,
    pub dto_produced: u64,
    pub schema_decode_attempts: u64,
    pub resolve_calls: u64,
    pub approval_acks: u64,
    pub frames_rejected: u64,
    pub cancel_notifications_queued: u64,
    pub stdout_non_protocol_writes: u64,
}

impl AcpTransportCounters {
    pub fn zero_side_effects(&self) -> bool {
        self.daemon_mutations == 0
            && self.bridge_conversions == 0
            && self.catalog_mutations == 0
            && self.dto_produced == 0
            && self.resolve_calls == 0
            && self.approval_acks == 0
    }
}

#[cfg(test)]
mod tests;
