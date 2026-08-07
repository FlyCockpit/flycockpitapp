//! Transport-neutral logical lanes.
//!
//! One bounded, versioned substrate shared by WebRTC data channels and the E2E
//! WebSocket fallback. Control, interactive, and bulk traffic are separated so
//! a large file or image cannot starve authorization, cancellation, terminal
//! input, or reconnect coordination.
//!
//! Layering, lowest first:
//!
//! - [`lane`] — lane identity, redaction-safe reasons, size buckets
//! - [`frame`] — `RemoteTransportFrameV1`, the 72-byte-header logical frame
//! - [`fragment`] — `RemoteCarrierFragmentV1`, the 26-byte-header carrier split
//! - [`bulk`] — typed begin/chunk/complete/abort bulk transfer payloads
//! - [`classification`] — exhaustive application-message → lane assignment
//! - [`channel`] — the fixed three-channel contract
//! - [`scheduler`] — queue limits and deterministic lane scheduling
//! - [`lane_io`] — the carrier-agnostic reader/writer surface
//! - [`observability`] — payload-free log and metric records
//!
//! Codecs and the scheduler are pure: they take explicit inputs (including the
//! clock) and return explicit actions, so every rule is testable without a
//! transport, a timer, or a sleep.

pub mod bulk;
pub mod channel;
pub mod classification;
pub mod fragment;
pub mod frame;
pub mod lane;
pub mod lane_io;
pub mod observability;
pub mod scheduler;

pub use bulk::{
    BULK_ABORT_BYTES, BULK_BEGIN_BYTES_WITH_OPTIONS, BULK_BEGIN_BYTES_WITHOUT_OPTIONS,
    BULK_CHUNK_ENVELOPE_BYTES, BULK_COMPLETE_BYTES, BULK_OPTION_BITS_KNOWN,
    BULK_OPTION_BITS_UNKNOWN, MAX_BULK_CHUNK_PAYLOAD_BYTES, MAX_RECEIVER_WINDOW_BYTES,
    MAX_TRANSFER_BYTES, RemoteBulkAbortReason, RemoteBulkMessage, RemoteBulkMimeClass,
    RemoteBulkTransferRef, RemoteBulkTransferState,
};
pub use channel::{REMOTE_LANE_CHANNELS, RemoteLaneChannel, channel_for_lane, lane_for_channel_id};
pub use classification::{
    RemoteMessageClass, RemoteMessageClassification, classify_event_tag, classify_request_tag,
    classify_response_tag,
};
pub use fragment::{
    LANE_FRAGMENT_TOTAL_BYTES, MAX_FRAGMENT_COUNT, MAX_INCOMPLETE_FRAMES_PER_PEER,
    MAX_REASSEMBLY_BYTES_PER_PEER, REASSEMBLY_DEADLINE_MS, REMOTE_CARRIER_FRAGMENT_HEADER_BYTES,
    REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES, RemoteCarrierFragmentV1, RemoteFragmentFlags,
    RemoteFragmentReassembler, fragment_frame,
};
pub use frame::{
    CONTROL_STREAM_ID, MAX_SERIALIZED_FRAME_BYTES, REMOTE_TRANSPORT_FRAME_HEADER_BYTES,
    REMOTE_TRANSPORT_FRAME_VERSION, RemoteFrameFlags, RemoteStreamOrigin, RemoteStreamSequences,
    RemoteTransportFrameV1, client_stream_id, daemon_stream_id, payload_digest, validate_stream_id,
};
pub use lane::{
    MAX_LOGICAL_PAYLOAD_BYTES, REMOTE_LANE_COUNT, RemoteLane, RemoteSizeBucket,
    RemoteTransportError, RemoteTransportReason, RemoteTransportResult,
};
pub use lane_io::{RemoteCarrierKind, RemoteLaneReader, RemoteLaneWriter, RemoteWritability};
pub use observability::{RemoteTransportMetric, RemoteTransportRecord};
pub use scheduler::{
    LANE_SCHEDULE, RemoteLaneScheduler, RemoteQueueLimits, RemoteQueueOutcome, RemoteSendRequest,
};
