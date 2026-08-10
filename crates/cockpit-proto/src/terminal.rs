//! Transport-neutral terminal constants shared by the host parser and
//! TUI emission path.
//!
//! Parsing policy, clipboard data, and host lifecycle stay out of this
//! crate. The sole size contract for OSC 52 sequences lives here so
//! `apps/cli` and `crates/cockpit-tui` cannot drift.

/// Maximum total byte length of one OSC 52 candidate sequence, counting
/// every introducer form, selector/separators, payload, and terminator.
///
/// This is the only public OSC 52 size constant in the workspace. Host
/// filtering and TUI emission both import it; neither crate may declare
/// a local alias, literal cap, or competing decoded-payload limit.
pub const OSC52_MAX_SEQUENCE_BYTES: usize = 102_400;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const TERMINAL_INGRESS_MAX_BYTES: u64 = 10 * 1024 * 1024;
pub const TERMINAL_INGRESS_MAX_CHUNK_BYTES: usize = 48 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalImageType {
    Png,
    Jpeg,
    Gif,
    Webp,
}

impl TerminalImageType {
    pub fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Gif => "gif",
            Self::Webp => "webp",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TerminalBinding {
    pub binding_id: Uuid,
    pub binding_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalIngressMetadata {
    pub operation_id: Uuid,
    pub size: u64,
    pub media_type: TerminalImageType,
    /// Lowercase, complete SHA-256 digest. It is data identity, never authority.
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalIngressState {
    Prepared,
    Committed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminalIngressReceipt {
    pub operation_id: Uuid,
    pub state: TerminalIngressState,
    pub next_offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_sequence: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}
