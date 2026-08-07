//! Lane identity, redaction-safe failure reasons, and size buckets.
//!
//! Everything in this module is payload-free by construction: a
//! [`RemoteTransportError`] carries a closed reason code, an optional lane, and
//! an optional size *bucket* — never a byte count, path, identifier, or payload
//! fragment. `remote_transport_no_polling_or_payload_logs` depends on that.

use std::fmt;

/// Number of logical lanes. Fixed at three for v1; adding a lane is a new
/// protocol version, never a runtime negotiation.
pub const REMOTE_LANE_COUNT: usize = 3;

/// Control-lane logical payload cap (64 KiB).
pub const CONTROL_MAX_PAYLOAD_BYTES: usize = 64 * 1024;
/// Interactive-lane logical payload cap (512 KiB).
pub const INTERACTIVE_MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// Bulk-lane logical payload cap (512 KiB per chunk frame).
pub const BULK_MAX_PAYLOAD_BYTES: usize = 512 * 1024;
/// Largest logical payload any lane may carry (512 KiB).
pub const MAX_LOGICAL_PAYLOAD_BYTES: usize = 512 * 1024;

/// The three fixed logical lanes.
///
/// Lane IDs are wire constants. `Control = 0`, `Interactive = 1`, `Bulk = 2`;
/// the negotiated SCTP channel IDs (0/2/4) live in
/// [`crate::remote_transport::channel`] and are deliberately *not* the same
/// numbers, so neither can be silently substituted for the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteLane {
    Control = 0,
    Interactive = 1,
    Bulk = 2,
}

impl RemoteLane {
    /// Every lane in wire order. Iteration order is part of the contract.
    pub const ALL: [RemoteLane; REMOTE_LANE_COUNT] = [
        RemoteLane::Control,
        RemoteLane::Interactive,
        RemoteLane::Bulk,
    ];

    pub const fn lane_id(self) -> u8 {
        self as u8
    }

    /// Strict lane decode. Unknown lane bytes fail rather than defaulting.
    pub const fn from_lane_id(value: u8) -> Option<Self> {
        match value {
            0 => Some(RemoteLane::Control),
            1 => Some(RemoteLane::Interactive),
            2 => Some(RemoteLane::Bulk),
            _ => None,
        }
    }

    /// Stable wire/JSON spelling. Shared with the TypeScript mirror.
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteLane::Control => "control",
            RemoteLane::Interactive => "interactive",
            RemoteLane::Bulk => "bulk",
        }
    }

    pub fn from_str_exact(value: &str) -> Option<Self> {
        match value {
            "control" => Some(RemoteLane::Control),
            "interactive" => Some(RemoteLane::Interactive),
            "bulk" => Some(RemoteLane::Bulk),
            _ => None,
        }
    }

    /// Per-lane logical payload cap.
    pub const fn max_payload_bytes(self) -> usize {
        match self {
            RemoteLane::Control => CONTROL_MAX_PAYLOAD_BYTES,
            RemoteLane::Interactive => INTERACTIVE_MAX_PAYLOAD_BYTES,
            RemoteLane::Bulk => BULK_MAX_PAYLOAD_BYTES,
        }
    }
}

impl fmt::Display for RemoteLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for RemoteLane {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> serde::Deserialize<'de> for RemoteLane {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        RemoteLane::from_str_exact(&raw)
            .ok_or_else(|| serde::de::Error::custom("unknown remote lane"))
    }
}

/// Closed set of failure reasons.
///
/// These strings are the only failure detail that may reach a log or metric.
/// Adding a variant is deliberate; none of them may ever be constructed from
/// caller-supplied text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteTransportReason {
    // Frame header / envelope
    UnsupportedVersion,
    UnknownLane,
    UnknownFlagBit,
    HeaderTooShort,
    TrailingBytes,
    PayloadLengthMismatch,
    PayloadCapExceeded,
    DigestMismatch,
    // Stream rules
    ZeroStreamId,
    StreamParityViolation,
    ControlStreamViolation,
    SequenceGap,
    SequenceRegression,
    SequenceWrap,
    StreamClosed,
    StreamLimitExceeded,
    // Fragmentation / reassembly
    ZeroFragmentCount,
    FragmentCountExceeded,
    FragmentIndexOutOfRange,
    FragmentPayloadCapExceeded,
    FragmentLengthMismatch,
    FragmentEndFlagMisplaced,
    FragmentConflict,
    ReassemblyFrameLimit,
    ReassemblyByteLimit,
    ReassemblyTimeout,
    // Bulk transfer
    BulkUnknownKind,
    BulkOptionBits,
    BulkLengthMismatch,
    BulkOffsetGap,
    BulkWindowOvershoot,
    BulkTransferLimit,
    BulkClassLimit,
    BulkDigestMismatch,
    BulkUnknownTransfer,
    BulkTransferConflict,
    BulkLateChunk,
    BulkAlreadyComplete,
    BulkUnknownMimeClass,
    BulkUnknownAbortReason,
    BulkChunkIndexGap,
    // Queueing / scheduling
    QueueFrameLimit,
    QueueByteLimit,
    QueueAggregateLimit,
    ControlQueueOverflow,
    /// A wire integer field was handed a value outside its fixed width.
    ///
    /// Rust gets this from its type system, so nothing here constructs it; the
    /// variant exists so the closed reason set stays identical to the
    /// TypeScript mirror, which needs it because `bigint`/`number` are not
    /// width-bounded.
    IntegerOutOfRange,
    // Classification
    UnclassifiedMessage,
    LaneNotPermittedForClass,
    ClientSelectedLaneRejected,
}

impl RemoteTransportReason {
    /// Stable snake_case reason code. Mirrored verbatim in TypeScript.
    pub const fn as_str(self) -> &'static str {
        use RemoteTransportReason::*;
        match self {
            UnsupportedVersion => "unsupported_version",
            UnknownLane => "unknown_lane",
            UnknownFlagBit => "unknown_flag_bit",
            HeaderTooShort => "header_too_short",
            TrailingBytes => "trailing_bytes",
            PayloadLengthMismatch => "payload_length_mismatch",
            PayloadCapExceeded => "payload_cap_exceeded",
            DigestMismatch => "digest_mismatch",
            ZeroStreamId => "zero_stream_id",
            StreamParityViolation => "stream_parity_violation",
            ControlStreamViolation => "control_stream_violation",
            SequenceGap => "sequence_gap",
            SequenceRegression => "sequence_regression",
            SequenceWrap => "sequence_wrap",
            StreamClosed => "stream_closed",
            StreamLimitExceeded => "stream_limit_exceeded",
            ZeroFragmentCount => "zero_fragment_count",
            FragmentCountExceeded => "fragment_count_exceeded",
            FragmentIndexOutOfRange => "fragment_index_out_of_range",
            FragmentPayloadCapExceeded => "fragment_payload_cap_exceeded",
            FragmentLengthMismatch => "fragment_length_mismatch",
            FragmentEndFlagMisplaced => "fragment_end_flag_misplaced",
            FragmentConflict => "fragment_conflict",
            ReassemblyFrameLimit => "reassembly_frame_limit",
            ReassemblyByteLimit => "reassembly_byte_limit",
            ReassemblyTimeout => "reassembly_timeout",
            BulkUnknownKind => "bulk_unknown_kind",
            BulkOptionBits => "bulk_option_bits",
            BulkLengthMismatch => "bulk_length_mismatch",
            BulkOffsetGap => "bulk_offset_gap",
            BulkWindowOvershoot => "bulk_window_overshoot",
            BulkTransferLimit => "bulk_transfer_limit",
            BulkClassLimit => "bulk_class_limit",
            BulkDigestMismatch => "bulk_digest_mismatch",
            BulkUnknownTransfer => "bulk_unknown_transfer",
            BulkTransferConflict => "bulk_transfer_conflict",
            BulkLateChunk => "bulk_late_chunk",
            BulkAlreadyComplete => "bulk_already_complete",
            BulkUnknownMimeClass => "bulk_unknown_mime_class",
            BulkUnknownAbortReason => "bulk_unknown_abort_reason",
            BulkChunkIndexGap => "bulk_chunk_index_gap",
            QueueFrameLimit => "queue_frame_limit",
            QueueByteLimit => "queue_byte_limit",
            QueueAggregateLimit => "queue_aggregate_limit",
            ControlQueueOverflow => "control_queue_overflow",
            IntegerOutOfRange => "integer_out_of_range",
            UnclassifiedMessage => "unclassified_message",
            LaneNotPermittedForClass => "lane_not_permitted_for_class",
            ClientSelectedLaneRejected => "client_selected_lane_rejected",
        }
    }
}

impl fmt::Display for RemoteTransportReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for RemoteTransportReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// Coarse size bucket. Metrics never carry exact byte counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum RemoteSizeBucket {
    Le1K,
    Le4K,
    Le16K,
    Le64K,
    Le256K,
    Le512K,
    Gt512K,
}

impl RemoteSizeBucket {
    pub const fn of(bytes: usize) -> Self {
        if bytes <= 1024 {
            RemoteSizeBucket::Le1K
        } else if bytes <= 4 * 1024 {
            RemoteSizeBucket::Le4K
        } else if bytes <= 16 * 1024 {
            RemoteSizeBucket::Le16K
        } else if bytes <= 64 * 1024 {
            RemoteSizeBucket::Le64K
        } else if bytes <= 256 * 1024 {
            RemoteSizeBucket::Le256K
        } else if bytes <= 512 * 1024 {
            RemoteSizeBucket::Le512K
        } else {
            RemoteSizeBucket::Gt512K
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteSizeBucket::Le1K => "le_1k",
            RemoteSizeBucket::Le4K => "le_4k",
            RemoteSizeBucket::Le16K => "le_16k",
            RemoteSizeBucket::Le64K => "le_64k",
            RemoteSizeBucket::Le256K => "le_256k",
            RemoteSizeBucket::Le512K => "le_512k",
            RemoteSizeBucket::Gt512K => "gt_512k",
        }
    }
}

impl fmt::Display for RemoteSizeBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl serde::Serialize for RemoteSizeBucket {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// A transport failure. Deliberately not `thiserror`-derived over a payload:
/// the whole point is that nothing beyond reason/lane/bucket can be attached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteTransportError {
    pub reason: RemoteTransportReason,
    pub lane: Option<RemoteLane>,
    pub size_bucket: Option<RemoteSizeBucket>,
}

impl RemoteTransportError {
    pub const fn new(reason: RemoteTransportReason) -> Self {
        Self {
            reason,
            lane: None,
            size_bucket: None,
        }
    }

    pub const fn with_lane(reason: RemoteTransportReason, lane: RemoteLane) -> Self {
        Self {
            reason,
            lane: Some(lane),
            size_bucket: None,
        }
    }

    pub const fn with_size(reason: RemoteTransportReason, lane: RemoteLane, bytes: usize) -> Self {
        Self {
            reason,
            lane: Some(lane),
            size_bucket: Some(RemoteSizeBucket::of(bytes)),
        }
    }
}

impl fmt::Display for RemoteTransportError {
    /// Redaction-safe rendering: `reason` plus optional `lane` and `size`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason)?;
        if let Some(lane) = self.lane {
            write!(f, " lane={lane}")?;
        }
        if let Some(bucket) = self.size_bucket {
            write!(f, " size={bucket}")?;
        }
        Ok(())
    }
}

impl std::error::Error for RemoteTransportError {}

pub type RemoteTransportResult<T> = Result<T, RemoteTransportError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_transport_lane_ids_and_caps_are_exact() {
        assert_eq!(RemoteLane::Control.lane_id(), 0);
        assert_eq!(RemoteLane::Interactive.lane_id(), 1);
        assert_eq!(RemoteLane::Bulk.lane_id(), 2);
        assert_eq!(RemoteLane::ALL.len(), REMOTE_LANE_COUNT);

        assert_eq!(RemoteLane::Control.max_payload_bytes(), 65_536);
        assert_eq!(RemoteLane::Interactive.max_payload_bytes(), 524_288);
        assert_eq!(RemoteLane::Bulk.max_payload_bytes(), 524_288);
        assert_eq!(MAX_LOGICAL_PAYLOAD_BYTES, 524_288);

        for lane in RemoteLane::ALL {
            assert_eq!(RemoteLane::from_lane_id(lane.lane_id()), Some(lane));
            assert_eq!(RemoteLane::from_str_exact(lane.as_str()), Some(lane));
        }
        // Lane 3 and above are not a future default — they fail closed.
        for bad in [3u8, 4, 255] {
            assert_eq!(RemoteLane::from_lane_id(bad), None);
        }
        assert_eq!(RemoteLane::from_str_exact("Control"), None);
    }

    #[test]
    fn remote_transport_error_display_is_redacted() {
        let err = RemoteTransportError::with_size(
            RemoteTransportReason::PayloadCapExceeded,
            RemoteLane::Bulk,
            600_000,
        );
        let rendered = err.to_string();
        assert_eq!(rendered, "payload_cap_exceeded lane=bulk size=gt_512k");
        // No exact byte count leaks through the bucket.
        assert!(!rendered.contains("600000"));
    }

    #[test]
    fn remote_transport_size_buckets_are_monotonic() {
        let boundaries = [
            (0usize, RemoteSizeBucket::Le1K),
            (1024, RemoteSizeBucket::Le1K),
            (1025, RemoteSizeBucket::Le4K),
            (4096, RemoteSizeBucket::Le4K),
            (4097, RemoteSizeBucket::Le16K),
            (16 * 1024, RemoteSizeBucket::Le16K),
            (16 * 1024 + 1, RemoteSizeBucket::Le64K),
            (64 * 1024, RemoteSizeBucket::Le64K),
            (64 * 1024 + 1, RemoteSizeBucket::Le256K),
            (256 * 1024, RemoteSizeBucket::Le256K),
            (256 * 1024 + 1, RemoteSizeBucket::Le512K),
            (512 * 1024, RemoteSizeBucket::Le512K),
            (512 * 1024 + 1, RemoteSizeBucket::Gt512K),
        ];
        for (bytes, expected) in boundaries {
            assert_eq!(RemoteSizeBucket::of(bytes), expected, "{bytes}");
        }
    }
}
