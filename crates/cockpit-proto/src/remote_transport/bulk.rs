//! Typed bulk transfer payloads carried inside bulk-lane logical frames.
//!
//! Exact binary layouts, network byte order, no trailing bytes:
//!
//! ```text
//! begin    = kind:u8(1) | transferId:[16] | optionBits:u8
//!            | [totalLength:u64] | [expectedSha256:[32]]
//!            | mimeClass:u8 | maxTotalLength:u64
//! chunk    = kind:u8(2) | transferId:[16] | chunkIndex:u32 | offset:u64
//!            | byteLength:u32 | bytes
//! complete = kind:u8(3) | transferId:[16] | finalLength:u64 | sha256:[32]
//! abort    = kind:u8(4) | transferId:[16] | reason:u8
//! ```
//!
//! `optionBits` is closed to exactly `0x00` (unknown length: both optional
//! fields absent, incremental hashing) or `0x03` (known/prehashed: both
//! present). `0x01`, `0x02`, and every other bit fail, as does any
//! field/bit disagreement.

use sha2::{Digest as _, Sha256};

use crate::remote_protocol_id::{
    CanonicalU64DecimalStringV1, RemoteTransferId, kind, tag_protocol_id_bytes,
};
use crate::remote_transport::lane::{
    BULK_MAX_PAYLOAD_BYTES, RemoteLane, RemoteTransportError, RemoteTransportReason,
    RemoteTransportResult,
};

/// Message kind discriminants.
pub const BULK_KIND_BEGIN: u8 = 1;
pub const BULK_KIND_CHUNK: u8 = 2;
pub const BULK_KIND_COMPLETE: u8 = 3;
pub const BULK_KIND_ABORT: u8 = 4;

/// Unknown length: both optional begin fields absent.
pub const BULK_OPTION_BITS_UNKNOWN: u8 = 0x00;
/// Known / prehashed: both `totalLength` and `expectedSha256` present.
pub const BULK_OPTION_BITS_KNOWN: u8 = 0x03;

/// `begin` size with `optionBits == 0x00`: 1 + 16 + 1 + 1 + 8.
pub const BULK_BEGIN_BYTES_WITHOUT_OPTIONS: usize = 27;
/// `begin` size with `optionBits == 0x03`: 27 + 8 + 32.
pub const BULK_BEGIN_BYTES_WITH_OPTIONS: usize = 67;
/// `chunk` envelope: 1 + 16 + 4 + 8 + 4.
pub const BULK_CHUNK_ENVELOPE_BYTES: usize = 33;
/// `complete` size: 1 + 16 + 8 + 32.
pub const BULK_COMPLETE_BYTES: usize = 57;
/// `abort` size: 1 + 16 + 1.
pub const BULK_ABORT_BYTES: usize = 18;

/// Largest `bytes` a chunk may carry so the encoded chunk never exceeds the
/// 512 KiB logical payload cap: 524,288 − 33 = 524,255.
pub const MAX_BULK_CHUNK_PAYLOAD_BYTES: usize = BULK_MAX_PAYLOAD_BYTES - BULK_CHUNK_ENVELOPE_BYTES;

/// Receiver window ceiling.
pub const MAX_RECEIVER_WINDOW_BYTES: u64 = 4 * 1024 * 1024;
/// Global per-transfer ceiling.
pub const MAX_TRANSFER_BYTES: u64 = 512 * 1024 * 1024;

const _: () = assert!(MAX_BULK_CHUNK_PAYLOAD_BYTES == 524_255);
const _: () =
    assert!(BULK_CHUNK_ENVELOPE_BYTES + MAX_BULK_CHUNK_PAYLOAD_BYTES == BULK_MAX_PAYLOAD_BYTES);

/// Closed MIME class set. Each class carries its own authoritative ceiling;
/// the existing 4 MiB single-image and 8 MiB total-image limits are reused
/// verbatim rather than restated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteBulkMimeClass {
    /// One pasted or attached image.
    Image = 1,
    /// A set of images belonging to one user message.
    ImageSet = 2,
    /// A session archive (import/export ZIP).
    Archive = 3,
    /// Raw, unredacted exported session data. This is the explicit local
    /// `cockpit export --include-sensitive` archive: it may carry raw secrets
    /// and is served only over the owner-local generic bulk reader, never a
    /// remoted reader.
    Export = 4,
    /// Any other opaque attachment.
    Opaque = 5,
    /// Permanently-redacted exported session data (transcript JSON or debug
    /// bundle). This is the ONLY export kind the owner-remoted type-bound
    /// [`crate`] redacted-export reader will serve; a raw `Export` transfer is
    /// refused by that reader.
    RedactedExport = 6,
}

impl RemoteBulkMimeClass {
    pub const ALL: [RemoteBulkMimeClass; 6] = [
        RemoteBulkMimeClass::Image,
        RemoteBulkMimeClass::ImageSet,
        RemoteBulkMimeClass::Archive,
        RemoteBulkMimeClass::Export,
        RemoteBulkMimeClass::Opaque,
        RemoteBulkMimeClass::RedactedExport,
    ];

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(RemoteBulkMimeClass::Image),
            2 => Some(RemoteBulkMimeClass::ImageSet),
            3 => Some(RemoteBulkMimeClass::Archive),
            4 => Some(RemoteBulkMimeClass::Export),
            5 => Some(RemoteBulkMimeClass::Opaque),
            6 => Some(RemoteBulkMimeClass::RedactedExport),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteBulkMimeClass::Image => "image",
            RemoteBulkMimeClass::ImageSet => "image_set",
            RemoteBulkMimeClass::Archive => "archive",
            RemoteBulkMimeClass::Export => "export",
            RemoteBulkMimeClass::Opaque => "opaque",
            RemoteBulkMimeClass::RedactedExport => "redacted_export",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == value)
    }

    /// Authoritative per-class ceiling before the global transfer cap applies.
    pub const fn class_limit_bytes(self) -> u64 {
        match self {
            // The landed image limits stay authoritative.
            RemoteBulkMimeClass::Image => crate::MAX_SINGLE_IMAGE_BYTES as u64,
            RemoteBulkMimeClass::ImageSet => crate::MAX_TOTAL_IMAGE_BYTES as u64,
            RemoteBulkMimeClass::Archive
            | RemoteBulkMimeClass::Export
            | RemoteBulkMimeClass::Opaque
            | RemoteBulkMimeClass::RedactedExport => MAX_TRANSFER_BYTES,
        }
    }

    /// `maxTotalLength` is the minimum of the class limit and the 512 MiB cap.
    pub const fn max_total_length(self) -> u64 {
        let class = self.class_limit_bytes();
        if class < MAX_TRANSFER_BYTES {
            class
        } else {
            MAX_TRANSFER_BYTES
        }
    }
}

impl serde::Serialize for RemoteBulkMimeClass {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RemoteBulkMimeClass {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::from_str_exact(&raw)
            .ok_or_else(|| serde::de::Error::custom("unknown bulk mime class"))
    }
}

/// Closed abort reason set. `0` is deliberately invalid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteBulkAbortReason {
    Cancelled = 1,
    LimitExceeded = 2,
    IntegrityFailure = 3,
    TransportClosed = 4,
    Timeout = 5,
}

impl RemoteBulkAbortReason {
    pub const ALL: [RemoteBulkAbortReason; 5] = [
        RemoteBulkAbortReason::Cancelled,
        RemoteBulkAbortReason::LimitExceeded,
        RemoteBulkAbortReason::IntegrityFailure,
        RemoteBulkAbortReason::TransportClosed,
        RemoteBulkAbortReason::Timeout,
    ];

    pub const fn code(self) -> u8 {
        self as u8
    }

    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(RemoteBulkAbortReason::Cancelled),
            2 => Some(RemoteBulkAbortReason::LimitExceeded),
            3 => Some(RemoteBulkAbortReason::IntegrityFailure),
            4 => Some(RemoteBulkAbortReason::TransportClosed),
            5 => Some(RemoteBulkAbortReason::Timeout),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteBulkAbortReason::Cancelled => "cancelled",
            RemoteBulkAbortReason::LimitExceeded => "limit_exceeded",
            RemoteBulkAbortReason::IntegrityFailure => "integrity_failure",
            RemoteBulkAbortReason::TransportClosed => "transport_closed",
            RemoteBulkAbortReason::Timeout => "timeout",
        }
    }
}

/// `begin` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBulkBegin {
    pub transfer_id: RemoteTransferId,
    /// Present together, or absent together — never one of the two.
    pub total_length: Option<u64>,
    pub expected_sha256: Option<[u8; 32]>,
    pub mime_class: RemoteBulkMimeClass,
    pub max_total_length: u64,
}

impl RemoteBulkBegin {
    /// Unknown length: incremental hashing, `optionBits == 0x00`.
    pub fn unknown_length(transfer_id: RemoteTransferId, mime_class: RemoteBulkMimeClass) -> Self {
        Self {
            transfer_id,
            total_length: None,
            expected_sha256: None,
            mime_class,
            max_total_length: mime_class.max_total_length(),
        }
    }

    /// Known and prehashed: `optionBits == 0x03`.
    pub fn known_length(
        transfer_id: RemoteTransferId,
        mime_class: RemoteBulkMimeClass,
        total_length: u64,
        expected_sha256: [u8; 32],
    ) -> Self {
        Self {
            transfer_id,
            total_length: Some(total_length),
            expected_sha256: Some(expected_sha256),
            mime_class,
            max_total_length: mime_class.max_total_length(),
        }
    }

    pub fn option_bits(&self) -> u8 {
        match (self.total_length, self.expected_sha256) {
            (Some(_), Some(_)) => BULK_OPTION_BITS_KNOWN,
            _ => BULK_OPTION_BITS_UNKNOWN,
        }
    }

    fn validate(&self) -> RemoteTransportResult<()> {
        // Bits and fields must agree exactly.
        match (self.total_length, self.expected_sha256) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => return Err(bulk_err(RemoteTransportReason::BulkOptionBits)),
        }
        if self.max_total_length != self.mime_class.max_total_length() {
            return Err(bulk_err(RemoteTransportReason::BulkClassLimit));
        }
        if let Some(total) = self.total_length
            && total > self.max_total_length
        {
            return Err(bulk_err(RemoteTransportReason::BulkTransferLimit));
        }
        Ok(())
    }
}

/// `chunk` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBulkChunk {
    pub transfer_id: RemoteTransferId,
    pub chunk_index: u32,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

/// `complete` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBulkComplete {
    pub transfer_id: RemoteTransferId,
    pub final_length: u64,
    pub sha256: [u8; 32],
}

/// `abort` payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBulkAbort {
    pub transfer_id: RemoteTransferId,
    pub reason: RemoteBulkAbortReason,
}

/// Any bulk payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteBulkMessage {
    Begin(RemoteBulkBegin),
    Chunk(RemoteBulkChunk),
    Complete(RemoteBulkComplete),
    Abort(RemoteBulkAbort),
}

fn bulk_err(reason: RemoteTransportReason) -> RemoteTransportError {
    RemoteTransportError::with_lane(reason, RemoteLane::Bulk)
}

fn read_transfer_id(bytes: &[u8], offset: usize) -> RemoteTransportResult<RemoteTransferId> {
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&bytes[offset..offset + 16]);
    tag_protocol_id_bytes::<kind::Transfer>(raw)
        .map_err(|_| bulk_err(RemoteTransportReason::BulkUnknownTransfer))
}

fn read_u64_at(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(buf)
}

fn read_u32_at(bytes: &[u8], offset: usize) -> u32 {
    let mut buf = [0u8; 4];
    buf.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_be_bytes(buf)
}

impl RemoteBulkMessage {
    pub fn encode(&self) -> RemoteTransportResult<Vec<u8>> {
        match self {
            RemoteBulkMessage::Begin(begin) => {
                begin.validate()?;
                let bits = begin.option_bits();
                let mut out = Vec::with_capacity(if bits == BULK_OPTION_BITS_KNOWN {
                    BULK_BEGIN_BYTES_WITH_OPTIONS
                } else {
                    BULK_BEGIN_BYTES_WITHOUT_OPTIONS
                });
                out.push(BULK_KIND_BEGIN);
                out.extend_from_slice(begin.transfer_id.as_bytes());
                out.push(bits);
                if let (Some(total), Some(digest)) = (begin.total_length, begin.expected_sha256) {
                    out.extend_from_slice(&total.to_be_bytes());
                    out.extend_from_slice(&digest);
                }
                out.push(begin.mime_class.code());
                out.extend_from_slice(&begin.max_total_length.to_be_bytes());
                Ok(out)
            }
            RemoteBulkMessage::Chunk(chunk) => {
                if chunk.bytes.len() > MAX_BULK_CHUNK_PAYLOAD_BYTES {
                    return Err(RemoteTransportError::with_size(
                        RemoteTransportReason::PayloadCapExceeded,
                        RemoteLane::Bulk,
                        chunk.bytes.len(),
                    ));
                }
                let mut out = Vec::with_capacity(BULK_CHUNK_ENVELOPE_BYTES + chunk.bytes.len());
                out.push(BULK_KIND_CHUNK);
                out.extend_from_slice(chunk.transfer_id.as_bytes());
                out.extend_from_slice(&chunk.chunk_index.to_be_bytes());
                out.extend_from_slice(&chunk.offset.to_be_bytes());
                out.extend_from_slice(&(chunk.bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(&chunk.bytes);
                Ok(out)
            }
            RemoteBulkMessage::Complete(complete) => {
                let mut out = Vec::with_capacity(BULK_COMPLETE_BYTES);
                out.push(BULK_KIND_COMPLETE);
                out.extend_from_slice(complete.transfer_id.as_bytes());
                out.extend_from_slice(&complete.final_length.to_be_bytes());
                out.extend_from_slice(&complete.sha256);
                Ok(out)
            }
            RemoteBulkMessage::Abort(abort) => {
                let mut out = Vec::with_capacity(BULK_ABORT_BYTES);
                out.push(BULK_KIND_ABORT);
                out.extend_from_slice(abort.transfer_id.as_bytes());
                out.push(abort.reason.code());
                Ok(out)
            }
        }
    }

    /// Strict parse. Exact length and no trailing bytes are mandatory.
    pub fn decode(bytes: &[u8]) -> RemoteTransportResult<Self> {
        let Some(&kind_byte) = bytes.first() else {
            return Err(bulk_err(RemoteTransportReason::HeaderTooShort));
        };
        match kind_byte {
            BULK_KIND_BEGIN => Self::decode_begin(bytes),
            BULK_KIND_CHUNK => Self::decode_chunk(bytes),
            BULK_KIND_COMPLETE => Self::decode_complete(bytes),
            BULK_KIND_ABORT => Self::decode_abort(bytes),
            _ => Err(bulk_err(RemoteTransportReason::BulkUnknownKind)),
        }
    }

    fn decode_begin(bytes: &[u8]) -> RemoteTransportResult<Self> {
        // optionBits sits at a fixed offset and decides the total length.
        if bytes.len() < 18 {
            return Err(bulk_err(RemoteTransportReason::HeaderTooShort));
        }
        let transfer_id = read_transfer_id(bytes, 1)?;
        let bits = bytes[17];
        let (expected_len, has_options) = match bits {
            BULK_OPTION_BITS_UNKNOWN => (BULK_BEGIN_BYTES_WITHOUT_OPTIONS, false),
            BULK_OPTION_BITS_KNOWN => (BULK_BEGIN_BYTES_WITH_OPTIONS, true),
            // 0x01, 0x02 and every other spelling are closed out.
            _ => return Err(bulk_err(RemoteTransportReason::BulkOptionBits)),
        };
        if bytes.len() != expected_len {
            return Err(bulk_err(if bytes.len() < expected_len {
                RemoteTransportReason::BulkLengthMismatch
            } else {
                RemoteTransportReason::TrailingBytes
            }));
        }
        let (total_length, expected_sha256, cursor) = if has_options {
            let total = read_u64_at(bytes, 18);
            let mut digest = [0u8; 32];
            digest.copy_from_slice(&bytes[26..58]);
            (Some(total), Some(digest), 58usize)
        } else {
            (None, None, 18usize)
        };
        let mime_class = RemoteBulkMimeClass::from_code(bytes[cursor])
            .ok_or_else(|| bulk_err(RemoteTransportReason::BulkUnknownMimeClass))?;
        let max_total_length = read_u64_at(bytes, cursor + 1);
        let begin = RemoteBulkBegin {
            transfer_id,
            total_length,
            expected_sha256,
            mime_class,
            max_total_length,
        };
        begin.validate()?;
        Ok(RemoteBulkMessage::Begin(begin))
    }

    fn decode_chunk(bytes: &[u8]) -> RemoteTransportResult<Self> {
        if bytes.len() < BULK_CHUNK_ENVELOPE_BYTES {
            return Err(bulk_err(RemoteTransportReason::HeaderTooShort));
        }
        let transfer_id = read_transfer_id(bytes, 1)?;
        let chunk_index = read_u32_at(bytes, 17);
        let offset = read_u64_at(bytes, 21);
        let byte_length = read_u32_at(bytes, 29) as usize;
        // Bound the declared length before slicing.
        if byte_length > MAX_BULK_CHUNK_PAYLOAD_BYTES {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::PayloadCapExceeded,
                RemoteLane::Bulk,
                byte_length,
            ));
        }
        let actual = bytes.len() - BULK_CHUNK_ENVELOPE_BYTES;
        if actual > byte_length {
            return Err(bulk_err(RemoteTransportReason::TrailingBytes));
        }
        if actual < byte_length {
            return Err(bulk_err(RemoteTransportReason::BulkLengthMismatch));
        }
        Ok(RemoteBulkMessage::Chunk(RemoteBulkChunk {
            transfer_id,
            chunk_index,
            offset,
            bytes: bytes[BULK_CHUNK_ENVELOPE_BYTES..].to_vec(),
        }))
    }

    fn decode_complete(bytes: &[u8]) -> RemoteTransportResult<Self> {
        if bytes.len() != BULK_COMPLETE_BYTES {
            return Err(bulk_err(if bytes.len() < BULK_COMPLETE_BYTES {
                RemoteTransportReason::BulkLengthMismatch
            } else {
                RemoteTransportReason::TrailingBytes
            }));
        }
        let transfer_id = read_transfer_id(bytes, 1)?;
        let final_length = read_u64_at(bytes, 17);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[25..57]);
        Ok(RemoteBulkMessage::Complete(RemoteBulkComplete {
            transfer_id,
            final_length,
            sha256,
        }))
    }

    fn decode_abort(bytes: &[u8]) -> RemoteTransportResult<Self> {
        if bytes.len() != BULK_ABORT_BYTES {
            return Err(bulk_err(if bytes.len() < BULK_ABORT_BYTES {
                RemoteTransportReason::BulkLengthMismatch
            } else {
                RemoteTransportReason::TrailingBytes
            }));
        }
        let transfer_id = read_transfer_id(bytes, 1)?;
        let reason = RemoteBulkAbortReason::from_code(bytes[17])
            .ok_or_else(|| bulk_err(RemoteTransportReason::BulkUnknownAbortReason))?;
        Ok(RemoteBulkMessage::Abort(RemoteBulkAbort {
            transfer_id,
            reason,
        }))
    }
}

/// Terminal-state view of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteBulkStatus {
    Active,
    Completed,
    Aborted,
}

/// Receiver-side transfer state machine.
///
/// One terminal state per transfer: once `Completed` or `Aborted`, no chunk can
/// resurrect it — the window and queue are closed and late chunks are rejected.
#[derive(Clone)]
pub struct RemoteBulkTransferState {
    transfer_id: RemoteTransferId,
    mime_class: RemoteBulkMimeClass,
    declared_total: Option<u64>,
    expected_sha256: Option<[u8; 32]>,
    max_total_length: u64,
    next_chunk_index: u32,
    received: u64,
    unacknowledged: u64,
    window_limit: u64,
    hasher: Sha256,
    status: RemoteBulkStatus,
}

impl std::fmt::Debug for RemoteBulkTransferState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the hasher or any buffered content.
        f.debug_struct("RemoteBulkTransferState")
            .field("mime_class", &self.mime_class)
            .field("status", &self.status)
            .field("next_chunk_index", &self.next_chunk_index)
            .field("received", &self.received)
            .finish()
    }
}

impl RemoteBulkTransferState {
    pub fn begin(begin: &RemoteBulkBegin) -> RemoteTransportResult<Self> {
        begin.validate()?;
        Ok(Self {
            transfer_id: begin.transfer_id,
            mime_class: begin.mime_class,
            declared_total: begin.total_length,
            expected_sha256: begin.expected_sha256,
            max_total_length: begin.max_total_length,
            next_chunk_index: 0,
            received: 0,
            unacknowledged: 0,
            window_limit: MAX_RECEIVER_WINDOW_BYTES,
            hasher: Sha256::new(),
            status: RemoteBulkStatus::Active,
        })
    }

    pub fn status(&self) -> RemoteBulkStatus {
        self.status
    }

    pub fn received_bytes(&self) -> u64 {
        self.received
    }

    pub fn unacknowledged_bytes(&self) -> u64 {
        self.unacknowledged
    }

    pub fn mime_class(&self) -> RemoteBulkMimeClass {
        self.mime_class
    }

    /// Receiver drained `bytes` from the window.
    pub fn acknowledge(&mut self, bytes: u64) {
        self.unacknowledged = self.unacknowledged.saturating_sub(bytes);
    }

    fn ensure_active(&self) -> RemoteTransportResult<()> {
        match self.status {
            RemoteBulkStatus::Active => Ok(()),
            // A late chunk after either terminal state cannot resurrect it.
            RemoteBulkStatus::Completed => {
                Err(bulk_err(RemoteTransportReason::BulkAlreadyComplete))
            }
            RemoteBulkStatus::Aborted => Err(bulk_err(RemoteTransportReason::BulkLateChunk)),
        }
    }

    fn ensure_same_transfer(&self, transfer_id: &RemoteTransferId) -> RemoteTransportResult<()> {
        if transfer_id.as_bytes() != self.transfer_id.as_bytes() {
            return Err(bulk_err(RemoteTransportReason::BulkUnknownTransfer));
        }
        Ok(())
    }

    pub fn accept_chunk(&mut self, chunk: &RemoteBulkChunk) -> RemoteTransportResult<()> {
        self.ensure_active()?;
        self.ensure_same_transfer(&chunk.transfer_id)?;
        if chunk.bytes.len() > MAX_BULK_CHUNK_PAYLOAD_BYTES {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::PayloadCapExceeded,
                RemoteLane::Bulk,
                chunk.bytes.len(),
            ));
        }
        // Indices are contiguous from zero.
        if chunk.chunk_index != self.next_chunk_index {
            return Err(bulk_err(RemoteTransportReason::BulkChunkIndexGap));
        }
        // Offsets are contiguous and match what has already landed.
        if chunk.offset != self.received {
            return Err(bulk_err(RemoteTransportReason::BulkOffsetGap));
        }
        let len = chunk.bytes.len() as u64;
        let projected = self
            .received
            .checked_add(len)
            .ok_or_else(|| bulk_err(RemoteTransportReason::BulkTransferLimit))?;
        if projected > self.max_total_length {
            return Err(bulk_err(RemoteTransportReason::BulkClassLimit));
        }
        if projected > MAX_TRANSFER_BYTES {
            return Err(bulk_err(RemoteTransportReason::BulkTransferLimit));
        }
        if let Some(total) = self.declared_total
            && projected > total
        {
            return Err(bulk_err(RemoteTransportReason::BulkWindowOvershoot));
        }
        if self.unacknowledged + len > self.window_limit {
            return Err(bulk_err(RemoteTransportReason::BulkWindowOvershoot));
        }

        self.hasher.update(&chunk.bytes);
        self.received = projected;
        self.unacknowledged += len;
        self.next_chunk_index += 1;
        Ok(())
    }

    /// Finalize. `complete` always supplies the final length and digest, and
    /// both must match what actually landed.
    pub fn complete(&mut self, complete: &RemoteBulkComplete) -> RemoteTransportResult<()> {
        self.ensure_active()?;
        self.ensure_same_transfer(&complete.transfer_id)?;
        if complete.final_length != self.received {
            return Err(bulk_err(RemoteTransportReason::BulkLengthMismatch));
        }
        if let Some(declared) = self.declared_total
            && declared != complete.final_length
        {
            return Err(bulk_err(RemoteTransportReason::BulkLengthMismatch));
        }
        let actual = self.hasher.clone().finalize();
        if actual.as_slice() != complete.sha256 {
            return Err(bulk_err(RemoteTransportReason::BulkDigestMismatch));
        }
        if let Some(expected) = self.expected_sha256
            && expected != complete.sha256
        {
            return Err(bulk_err(RemoteTransportReason::BulkDigestMismatch));
        }
        self.status = RemoteBulkStatus::Completed;
        // Completion closes the window.
        self.unacknowledged = 0;
        Ok(())
    }

    /// Cancel. Closes the window and queue; the transfer cannot restart.
    pub fn abort(&mut self, abort: &RemoteBulkAbort) -> RemoteTransportResult<()> {
        self.ensure_same_transfer(&abort.transfer_id)?;
        match self.status {
            RemoteBulkStatus::Aborted => Ok(()),
            RemoteBulkStatus::Completed => {
                Err(bulk_err(RemoteTransportReason::BulkAlreadyComplete))
            }
            RemoteBulkStatus::Active => {
                self.status = RemoteBulkStatus::Aborted;
                self.unacknowledged = 0;
                Ok(())
            }
        }
    }

    /// Digest of everything received so far (incremental-hash flow).
    pub fn running_digest(&self) -> [u8; 32] {
        let out = self.hasher.clone().finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }
}

// --- Bounded reference carried inside JSON application messages -------------

mod hex32 {
    use serde::{Deserialize as _, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = String::with_capacity(64);
        for byte in value {
            use std::fmt::Write as _;
            let _ = write!(&mut text, "{byte:02x}");
        }
        serializer.serialize_str(&text)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom("sha256 must be 64 hex characters"));
        }
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(serde::de::Error::custom("sha256 hex must be lowercase"));
        }
        let mut out = [0u8; 32];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| serde::de::Error::custom("sha256 hex invalid"))?;
        }
        Ok(out)
    }
}

/// The bounded, typed reference that replaces inline archive/export bytes in
/// application messages.
///
/// This is what a request or response carries instead of a base64 blob: the
/// bytes themselves travel as bulk-lane begin/chunk/complete frames.
/// Wire shape of a transfer reference, before validation.
///
/// Deserialization goes through this and then `TryFrom`, so a reference that
/// arrives off the wire is bounded by exactly the same constructor every
/// in-process caller uses. Without it, `#[derive(Deserialize)]` would hand
/// consumers a reference whose `total_length` had never been checked against
/// its class limit — and a consumer that sizes a buffer from that length is
/// then allocating from an attacker-supplied number.
#[derive(serde::Deserialize)]
struct RemoteBulkTransferRefWire {
    transfer_id: RemoteTransferId,
    total_length: CanonicalU64DecimalStringV1,
    #[serde(with = "hex32")]
    sha256: [u8; 32],
    mime_class: RemoteBulkMimeClass,
}

impl TryFrom<RemoteBulkTransferRefWire> for RemoteBulkTransferRef {
    type Error = String;

    fn try_from(wire: RemoteBulkTransferRefWire) -> Result<Self, Self::Error> {
        Self::new(
            wire.transfer_id,
            wire.total_length.value(),
            wire.sha256,
            wire.mime_class,
        )
        .map_err(|error| error.to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(try_from = "RemoteBulkTransferRefWire")]
pub struct RemoteBulkTransferRef {
    /// 22-character unpadded base64url, via the landed identifier codec.
    pub transfer_id: RemoteTransferId,
    /// `CanonicalU64DecimalStringV1` — never a JSON number.
    pub total_length: CanonicalU64DecimalStringV1,
    /// Lowercase hex SHA-256 of the transferred bytes.
    #[serde(with = "hex32")]
    pub sha256: [u8; 32],
    pub mime_class: RemoteBulkMimeClass,
}

impl RemoteBulkTransferRef {
    pub fn new(
        transfer_id: RemoteTransferId,
        total_length: u64,
        sha256: [u8; 32],
        mime_class: RemoteBulkMimeClass,
    ) -> RemoteTransportResult<Self> {
        let reference = Self {
            transfer_id,
            total_length: CanonicalU64DecimalStringV1::from_u64(total_length),
            sha256,
            mime_class,
        };
        reference.validate()?;
        Ok(reference)
    }

    /// Revalidate the semantic relationship between otherwise canonical
    /// public wire fields. Binary canonicalizers call this too, so an
    /// in-process struct literal cannot bypass the class ceiling.
    pub fn validate(&self) -> RemoteTransportResult<()> {
        if self.total_length.value() > self.mime_class.max_total_length() {
            return Err(bulk_err(RemoteTransportReason::BulkClassLimit));
        }
        Ok(())
    }

    pub fn total_length_value(&self) -> u64 {
        self.total_length.value()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transfer_id(seed: u8) -> RemoteTransferId {
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        tag_protocol_id_bytes::<kind::Transfer>(bytes).expect("nonzero transfer id")
    }

    fn digest_of(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&out);
        digest
    }

    #[test]
    fn remote_bulk_window_and_integrity() {
        // --- exact envelope sizes -------------------------------------------
        assert_eq!(BULK_BEGIN_BYTES_WITHOUT_OPTIONS, 1 + 16 + 1 + 1 + 8);
        assert_eq!(BULK_BEGIN_BYTES_WITH_OPTIONS, 1 + 16 + 1 + 8 + 32 + 1 + 8);
        assert_eq!(BULK_CHUNK_ENVELOPE_BYTES, 1 + 16 + 4 + 8 + 4);
        assert_eq!(BULK_COMPLETE_BYTES, 1 + 16 + 8 + 32);
        assert_eq!(BULK_ABORT_BYTES, 1 + 16 + 1);
        assert_eq!(MAX_BULK_CHUNK_PAYLOAD_BYTES, 524_255);
        assert_eq!(MAX_RECEIVER_WINDOW_BYTES, 4 * 1024 * 1024);
        assert_eq!(MAX_TRANSFER_BYTES, 512 * 1024 * 1024);

        let tid = transfer_id(1);

        // --- optionBits is closed to 0x00 / 0x03 ----------------------------
        let unknown = RemoteBulkBegin::unknown_length(tid, RemoteBulkMimeClass::Opaque);
        assert_eq!(unknown.option_bits(), BULK_OPTION_BITS_UNKNOWN);
        let encoded_unknown = RemoteBulkMessage::Begin(unknown.clone()).encode().unwrap();
        assert_eq!(encoded_unknown.len(), BULK_BEGIN_BYTES_WITHOUT_OPTIONS);
        assert_eq!(encoded_unknown[0], BULK_KIND_BEGIN);
        assert_eq!(encoded_unknown[17], 0x00);
        assert_eq!(
            RemoteBulkMessage::decode(&encoded_unknown).unwrap(),
            RemoteBulkMessage::Begin(unknown)
        );

        let payload = b"the quick brown fox".repeat(11);
        let known = RemoteBulkBegin::known_length(
            tid,
            RemoteBulkMimeClass::Archive,
            payload.len() as u64,
            digest_of(&payload),
        );
        assert_eq!(known.option_bits(), BULK_OPTION_BITS_KNOWN);
        let encoded_known = RemoteBulkMessage::Begin(known.clone()).encode().unwrap();
        assert_eq!(encoded_known.len(), BULK_BEGIN_BYTES_WITH_OPTIONS);
        assert_eq!(encoded_known[17], 0x03);
        assert_eq!(
            RemoteBulkMessage::decode(&encoded_known).unwrap(),
            RemoteBulkMessage::Begin(known.clone())
        );

        // 0x01, 0x02 and every other spelling fail.
        for bad_bits in [0x01u8, 0x02, 0x04, 0x07, 0x80, 0xFF] {
            let mut corrupted = encoded_known.clone();
            corrupted[17] = bad_bits;
            assert_eq!(
                RemoteBulkMessage::decode(&corrupted).unwrap_err().reason,
                RemoteTransportReason::BulkOptionBits,
                "{bad_bits:#04x}"
            );
        }
        // Field/bit disagreement fails: 0x03 bits with a 0x00-sized body.
        let mut disagreeing = encoded_unknown.clone();
        disagreeing[17] = BULK_OPTION_BITS_KNOWN;
        assert_eq!(
            RemoteBulkMessage::decode(&disagreeing).unwrap_err().reason,
            RemoteTransportReason::BulkLengthMismatch
        );
        // Constructing a half-populated begin is rejected outright.
        let half = RemoteBulkBegin {
            transfer_id: tid,
            total_length: Some(10),
            expected_sha256: None,
            mime_class: RemoteBulkMimeClass::Opaque,
            max_total_length: RemoteBulkMimeClass::Opaque.max_total_length(),
        };
        assert_eq!(
            RemoteBulkMessage::Begin(half).encode().unwrap_err().reason,
            RemoteTransportReason::BulkOptionBits
        );

        // --- unknown kinds and trailing bytes -------------------------------
        for bad_kind in [0u8, 5, 200] {
            let mut corrupted = encoded_known.clone();
            corrupted[0] = bad_kind;
            assert_eq!(
                RemoteBulkMessage::decode(&corrupted).unwrap_err().reason,
                RemoteTransportReason::BulkUnknownKind
            );
        }
        let mut trailing = encoded_known.clone();
        trailing.push(0);
        assert_eq!(
            RemoteBulkMessage::decode(&trailing).unwrap_err().reason,
            RemoteTransportReason::TrailingBytes
        );
        assert_eq!(
            RemoteBulkMessage::decode(&[]).unwrap_err().reason,
            RemoteTransportReason::HeaderTooShort
        );

        // --- known / prehashed happy path -----------------------------------
        let mut state = RemoteBulkTransferState::begin(&known).unwrap();
        assert_eq!(state.status(), RemoteBulkStatus::Active);
        let mid = payload.len() / 2;
        let first = RemoteBulkChunk {
            transfer_id: tid,
            chunk_index: 0,
            offset: 0,
            bytes: payload[..mid].to_vec(),
        };
        let second = RemoteBulkChunk {
            transfer_id: tid,
            chunk_index: 1,
            offset: mid as u64,
            bytes: payload[mid..].to_vec(),
        };
        // Chunk round-trips byte-exactly.
        let encoded_chunk = RemoteBulkMessage::Chunk(first.clone()).encode().unwrap();
        assert_eq!(
            encoded_chunk.len(),
            BULK_CHUNK_ENVELOPE_BYTES + first.bytes.len()
        );
        assert_eq!(
            RemoteBulkMessage::decode(&encoded_chunk).unwrap(),
            RemoteBulkMessage::Chunk(first.clone())
        );

        state.accept_chunk(&first).unwrap();
        state.accept_chunk(&second).unwrap();
        assert_eq!(state.received_bytes(), payload.len() as u64);
        assert_eq!(state.running_digest(), digest_of(&payload));

        let complete = RemoteBulkComplete {
            transfer_id: tid,
            final_length: payload.len() as u64,
            sha256: digest_of(&payload),
        };
        let encoded_complete = RemoteBulkMessage::Complete(complete.clone())
            .encode()
            .unwrap();
        assert_eq!(encoded_complete.len(), BULK_COMPLETE_BYTES);
        assert_eq!(
            RemoteBulkMessage::decode(&encoded_complete).unwrap(),
            RemoteBulkMessage::Complete(complete.clone())
        );
        state.complete(&complete).unwrap();
        assert_eq!(state.status(), RemoteBulkStatus::Completed);

        // Late chunk cannot resurrect a completed transfer.
        assert_eq!(
            state.accept_chunk(&second).unwrap_err().reason,
            RemoteTransportReason::BulkAlreadyComplete
        );

        // --- unknown length / incremental hashing ---------------------------
        let tid2 = transfer_id(2);
        let begin2 = RemoteBulkBegin::unknown_length(tid2, RemoteBulkMimeClass::Export);
        let mut state2 = RemoteBulkTransferState::begin(&begin2).unwrap();
        let body = b"streamed export".repeat(7);
        state2
            .accept_chunk(&RemoteBulkChunk {
                transfer_id: tid2,
                chunk_index: 0,
                offset: 0,
                bytes: body.clone(),
            })
            .unwrap();
        // The digest is computed incrementally, not supplied up front.
        state2
            .complete(&RemoteBulkComplete {
                transfer_id: tid2,
                final_length: body.len() as u64,
                sha256: digest_of(&body),
            })
            .unwrap();
        assert_eq!(state2.status(), RemoteBulkStatus::Completed);

        // --- gap / duplicate / conflict / overshoot -------------------------
        let tid3 = transfer_id(3);
        let begin3 = RemoteBulkBegin::unknown_length(tid3, RemoteBulkMimeClass::Opaque);
        let mut state3 = RemoteBulkTransferState::begin(&begin3).unwrap();
        state3
            .accept_chunk(&RemoteBulkChunk {
                transfer_id: tid3,
                chunk_index: 0,
                offset: 0,
                bytes: vec![1; 10],
            })
            .unwrap();
        // Index gap.
        assert_eq!(
            state3
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid3,
                    chunk_index: 2,
                    offset: 10,
                    bytes: vec![2; 10],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkChunkIndexGap
        );
        // Duplicate index (a replay) is an index gap, not a silent accept.
        assert_eq!(
            state3
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid3,
                    chunk_index: 0,
                    offset: 0,
                    bytes: vec![1; 10],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkChunkIndexGap
        );
        // Offset gap at the right index.
        assert_eq!(
            state3
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid3,
                    chunk_index: 1,
                    offset: 99,
                    bytes: vec![2; 10],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkOffsetGap
        );
        // A chunk for a different transfer is rejected.
        assert_eq!(
            state3
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: transfer_id(9),
                    chunk_index: 1,
                    offset: 10,
                    bytes: vec![2; 10],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkUnknownTransfer
        );

        // --- declared-length overshoot --------------------------------------
        let tid4 = transfer_id(4);
        let short = vec![7u8; 16];
        let begin4 = RemoteBulkBegin::known_length(
            tid4,
            RemoteBulkMimeClass::Opaque,
            short.len() as u64,
            digest_of(&short),
        );
        let mut state4 = RemoteBulkTransferState::begin(&begin4).unwrap();
        assert_eq!(
            state4
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid4,
                    chunk_index: 0,
                    offset: 0,
                    bytes: vec![7u8; 17],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkWindowOvershoot
        );

        // --- receiver window ------------------------------------------------
        let tid5 = transfer_id(5);
        let begin5 = RemoteBulkBegin::unknown_length(tid5, RemoteBulkMimeClass::Opaque);
        let mut state5 = RemoteBulkTransferState::begin(&begin5).unwrap();
        let big = vec![0u8; MAX_BULK_CHUNK_PAYLOAD_BYTES];
        let mut index = 0u32;
        let mut offset = 0u64;
        // 4 MiB / 524,255 = 8 whole chunks before the window is exhausted.
        while state5.unacknowledged_bytes() + big.len() as u64 <= MAX_RECEIVER_WINDOW_BYTES {
            state5
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid5,
                    chunk_index: index,
                    offset,
                    bytes: big.clone(),
                })
                .unwrap();
            index += 1;
            offset += big.len() as u64;
        }
        assert_eq!(index, 8);
        assert_eq!(
            state5
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid5,
                    chunk_index: index,
                    offset,
                    bytes: big.clone(),
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkWindowOvershoot
        );
        // Draining the window lets the transfer continue — backpressure, not loss.
        state5.acknowledge(state5.unacknowledged_bytes());
        state5
            .accept_chunk(&RemoteBulkChunk {
                transfer_id: tid5,
                chunk_index: index,
                offset,
                bytes: big.clone(),
            })
            .unwrap();

        // --- class limits stay authoritative --------------------------------
        assert_eq!(
            RemoteBulkMimeClass::Image.max_total_length(),
            crate::MAX_SINGLE_IMAGE_BYTES as u64
        );
        assert_eq!(
            RemoteBulkMimeClass::ImageSet.max_total_length(),
            crate::MAX_TOTAL_IMAGE_BYTES as u64
        );
        assert_eq!(
            RemoteBulkMimeClass::Archive.max_total_length(),
            MAX_TRANSFER_BYTES
        );
        for class in RemoteBulkMimeClass::ALL {
            assert!(class.max_total_length() <= MAX_TRANSFER_BYTES);
            assert_eq!(RemoteBulkMimeClass::from_code(class.code()), Some(class));
            assert_eq!(
                RemoteBulkMimeClass::from_str_exact(class.as_str()),
                Some(class)
            );
        }
        for bad in [0u8, 7, 255] {
            assert!(RemoteBulkMimeClass::from_code(bad).is_none());
        }
        // A begin whose maxTotalLength disagrees with its class fails.
        let lying = RemoteBulkBegin {
            transfer_id: tid,
            total_length: None,
            expected_sha256: None,
            mime_class: RemoteBulkMimeClass::Image,
            max_total_length: MAX_TRANSFER_BYTES,
        };
        assert_eq!(
            RemoteBulkMessage::Begin(lying).encode().unwrap_err().reason,
            RemoteTransportReason::BulkClassLimit
        );
        // An image transfer above the 4 MiB single-image limit is refused.
        let oversized_image = RemoteBulkBegin {
            transfer_id: tid,
            total_length: Some(crate::MAX_SINGLE_IMAGE_BYTES as u64 + 1),
            expected_sha256: Some([0u8; 32]),
            mime_class: RemoteBulkMimeClass::Image,
            max_total_length: RemoteBulkMimeClass::Image.max_total_length(),
        };
        assert_eq!(
            RemoteBulkMessage::Begin(oversized_image)
                .encode()
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkTransferLimit
        );

        // --- final digest / length mismatch ---------------------------------
        let tid6 = transfer_id(6);
        let begin6 = RemoteBulkBegin::unknown_length(tid6, RemoteBulkMimeClass::Opaque);
        let mut state6 = RemoteBulkTransferState::begin(&begin6).unwrap();
        let body6 = vec![3u8; 64];
        state6
            .accept_chunk(&RemoteBulkChunk {
                transfer_id: tid6,
                chunk_index: 0,
                offset: 0,
                bytes: body6.clone(),
            })
            .unwrap();
        assert_eq!(
            state6
                .complete(&RemoteBulkComplete {
                    transfer_id: tid6,
                    final_length: 63,
                    sha256: digest_of(&body6),
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkLengthMismatch
        );
        assert_eq!(
            state6
                .complete(&RemoteBulkComplete {
                    transfer_id: tid6,
                    final_length: 64,
                    sha256: [0u8; 32],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkDigestMismatch
        );

        // --- cancel closes the window; late chunks stay dead -----------------
        let tid7 = transfer_id(7);
        let begin7 = RemoteBulkBegin::unknown_length(tid7, RemoteBulkMimeClass::Opaque);
        let mut state7 = RemoteBulkTransferState::begin(&begin7).unwrap();
        state7
            .accept_chunk(&RemoteBulkChunk {
                transfer_id: tid7,
                chunk_index: 0,
                offset: 0,
                bytes: vec![1; 32],
            })
            .unwrap();
        let abort = RemoteBulkAbort {
            transfer_id: tid7,
            reason: RemoteBulkAbortReason::Cancelled,
        };
        let encoded_abort = RemoteBulkMessage::Abort(abort.clone()).encode().unwrap();
        assert_eq!(encoded_abort.len(), BULK_ABORT_BYTES);
        assert_eq!(
            RemoteBulkMessage::decode(&encoded_abort).unwrap(),
            RemoteBulkMessage::Abort(abort.clone())
        );
        state7.abort(&abort).unwrap();
        assert_eq!(state7.status(), RemoteBulkStatus::Aborted);
        assert_eq!(state7.unacknowledged_bytes(), 0);
        // Repeated abort is idempotent; a late chunk is not.
        state7.abort(&abort).unwrap();
        assert_eq!(
            state7
                .accept_chunk(&RemoteBulkChunk {
                    transfer_id: tid7,
                    chunk_index: 1,
                    offset: 32,
                    bytes: vec![1; 32],
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkLateChunk
        );
        // A complete/cancel race resolves to the single terminal state.
        assert_eq!(
            state7
                .complete(&RemoteBulkComplete {
                    transfer_id: tid7,
                    final_length: 32,
                    sha256: digest_of(&[1u8; 32]),
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkLateChunk
        );
        // Aborting an already-completed transfer is likewise refused.
        let mut completed = RemoteBulkTransferState::begin(&RemoteBulkBegin::unknown_length(
            transfer_id(8),
            RemoteBulkMimeClass::Opaque,
        ))
        .unwrap();
        completed
            .complete(&RemoteBulkComplete {
                transfer_id: transfer_id(8),
                final_length: 0,
                sha256: digest_of(&[]),
            })
            .unwrap();
        assert_eq!(
            completed
                .abort(&RemoteBulkAbort {
                    transfer_id: transfer_id(8),
                    reason: RemoteBulkAbortReason::TransportClosed,
                })
                .unwrap_err()
                .reason,
            RemoteTransportReason::BulkAlreadyComplete
        );

        // --- abort reasons are a closed set ---------------------------------
        for reason in RemoteBulkAbortReason::ALL {
            assert_eq!(
                RemoteBulkAbortReason::from_code(reason.code()),
                Some(reason)
            );
        }
        for bad in [0u8, 6, 255] {
            assert!(RemoteBulkAbortReason::from_code(bad).is_none());
            let mut corrupted = encoded_abort.clone();
            corrupted[17] = bad;
            assert_eq!(
                RemoteBulkMessage::decode(&corrupted).unwrap_err().reason,
                RemoteTransportReason::BulkUnknownAbortReason
            );
        }

        // --- a maximal chunk still fits the 512 KiB logical payload ---------
        let maximal = RemoteBulkChunk {
            transfer_id: tid,
            chunk_index: 0,
            offset: 0,
            bytes: vec![0u8; MAX_BULK_CHUNK_PAYLOAD_BYTES],
        };
        let encoded_maximal = RemoteBulkMessage::Chunk(maximal).encode().unwrap();
        assert_eq!(encoded_maximal.len(), BULK_MAX_PAYLOAD_BYTES);
        // One byte more does not fit.
        let over = RemoteBulkChunk {
            transfer_id: tid,
            chunk_index: 0,
            offset: 0,
            bytes: vec![0u8; MAX_BULK_CHUNK_PAYLOAD_BYTES + 1],
        };
        assert_eq!(
            RemoteBulkMessage::Chunk(over).encode().unwrap_err().reason,
            RemoteTransportReason::PayloadCapExceeded
        );
    }

    /// A reference off the wire cannot carry a length above its class limit.
    ///
    /// `#[derive(Deserialize)]` alone would hand a consumer an unchecked
    /// `total_length`; a consumer that sizes a buffer from it is then
    /// allocating from an attacker-supplied number. Validation belongs at the
    /// deserialization boundary so every consumer inherits it from the one
    /// bound, rather than each restating it.
    #[test]
    fn remote_bulk_transfer_ref_rejects_an_oversized_length_on_deserialize() {
        let id_text =
            crate::remote_protocol_id::encode_protocol_id_base64url(transfer_id(21).as_bytes())
                .unwrap();
        let digest = "ab".repeat(32);

        let json_for = |mime_class: &str, total: u64| {
            format!(
                r#"{{"transfer_id":"{id_text}","total_length":"{total}","sha256":"{digest}","mime_class":"{mime_class}"}}"#
            )
        };

        // At the class limit: accepted.
        let at_limit = json_for("image", crate::MAX_SINGLE_IMAGE_BYTES as u64);
        let parsed: RemoteBulkTransferRef = serde_json::from_str(&at_limit).unwrap();
        assert_eq!(
            parsed.total_length_value(),
            crate::MAX_SINGLE_IMAGE_BYTES as u64
        );

        // One byte over the class limit: refused at deserialization.
        let over_class = json_for("image", crate::MAX_SINGLE_IMAGE_BYTES as u64 + 1);
        assert!(
            serde_json::from_str::<RemoteBulkTransferRef>(&over_class).is_err(),
            "an image reference above the single-image limit must not deserialize"
        );

        // A canonical but enormous length is refused for every class, so no
        // consumer can ever be handed it.
        for class in RemoteBulkMimeClass::ALL {
            let huge = json_for(class.as_str(), u64::MAX);
            assert!(
                serde_json::from_str::<RemoteBulkTransferRef>(&huge).is_err(),
                "{} must refuse a u64::MAX length",
                class.as_str()
            );
        }

        // The bound is the class limit itself — one constant, not a restatement.
        let over_global = json_for("archive", MAX_TRANSFER_BYTES + 1);
        assert!(serde_json::from_str::<RemoteBulkTransferRef>(&over_global).is_err());
    }

    #[test]
    fn remote_bulk_transfer_ref_json_uses_landed_codecs() {
        let tid = transfer_id(11);
        // The largest length the archive class permits, so the canonical
        // decimal spelling is exercised at the boundary.
        let reference = RemoteBulkTransferRef::new(
            tid,
            MAX_TRANSFER_BYTES,
            digest_of(b"payload"),
            RemoteBulkMimeClass::Archive,
        )
        .unwrap();
        let json = serde_json::to_value(&reference).unwrap();

        // 16-byte id => 22-character unpadded base64url, no mapping row.
        let id_text = json["transfer_id"].as_str().unwrap();
        assert_eq!(id_text.len(), 22);
        assert!(!id_text.contains('='));
        // u64 => CanonicalU64DecimalStringV1, never a JSON number.
        assert_eq!(json["total_length"], serde_json::json!("536870912"));
        assert!(json["total_length"].is_string());
        // SHA-256 => 64 lowercase hex characters.
        let digest_text = json["sha256"].as_str().unwrap();
        assert_eq!(digest_text.len(), 64);
        assert!(
            digest_text
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase())
        );
        assert_eq!(json["mime_class"], serde_json::json!("archive"));

        let back: RemoteBulkTransferRef = serde_json::from_value(json).unwrap();
        assert_eq!(back, reference);

        // A numeric length is rejected outright.
        assert!(
            serde_json::from_str::<RemoteBulkTransferRef>(
                r#"{"transfer_id":"AQIDBAUGBwgJCgsMDQ4PEA","total_length":5,"sha256":"00","mime_class":"archive"}"#
            )
            .is_err()
        );
        // The reference stays bounded by its class.
        assert_eq!(
            RemoteBulkTransferRef::new(
                tid,
                crate::MAX_SINGLE_IMAGE_BYTES as u64 + 1,
                [0u8; 32],
                RemoteBulkMimeClass::Image,
            )
            .unwrap_err()
            .reason,
            RemoteTransportReason::BulkClassLimit
        );
    }
}
