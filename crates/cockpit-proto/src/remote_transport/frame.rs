//! `RemoteTransportFrameV1` — the exact 72-byte-header logical frame.
//!
//! Wire layout, network byte order throughout:
//!
//! ```text
//! version:u8(1) | lane:u8 | flags:u16 | streamId:u64 | streamSeq:u64
//!   | frameId:[16] | payloadLength:u32 | payloadDigest:[32] | payload
//! ```
//!
//! Offsets: version 0, lane 1, flags 2, streamId 4, streamSeq 12, frameId 20,
//! payloadLength 36, payloadDigest 40, payload 72.

use sha2::{Digest as _, Sha256};

use crate::remote_protocol_id::{RemoteFrameId, kind, tag_protocol_id_bytes};
use crate::remote_transport::lane::{
    MAX_LOGICAL_PAYLOAD_BYTES, RemoteLane, RemoteTransportError, RemoteTransportReason,
    RemoteTransportResult,
};

/// Only version 1 exists.
pub const REMOTE_TRANSPORT_FRAME_VERSION: u8 = 1;

/// Exact logical frame header size.
pub const REMOTE_TRANSPORT_FRAME_HEADER_BYTES: usize = 72;

/// Largest serialized logical frame: 72-byte header + 512 KiB payload.
pub const MAX_SERIALIZED_FRAME_BYTES: usize =
    REMOTE_TRANSPORT_FRAME_HEADER_BYTES + MAX_LOGICAL_PAYLOAD_BYTES;

// Field offsets, asserted against the header size below.
pub const FRAME_OFFSET_VERSION: usize = 0;
pub const FRAME_OFFSET_LANE: usize = 1;
pub const FRAME_OFFSET_FLAGS: usize = 2;
pub const FRAME_OFFSET_STREAM_ID: usize = 4;
pub const FRAME_OFFSET_STREAM_SEQ: usize = 12;
pub const FRAME_OFFSET_FRAME_ID: usize = 20;
pub const FRAME_OFFSET_PAYLOAD_LENGTH: usize = 36;
pub const FRAME_OFFSET_PAYLOAD_DIGEST: usize = 40;

const _: () = assert!(FRAME_OFFSET_PAYLOAD_DIGEST + 32 == REMOTE_TRANSPORT_FRAME_HEADER_BYTES);
const _: () = assert!(MAX_SERIALIZED_FRAME_BYTES == 524_360);

/// The control stream. Stream 0 exists on the control lane only.
pub const CONTROL_STREAM_ID: u64 = 0;

/// Frame flags. Exactly two bits are defined; every other bit fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct RemoteFrameFlags(u16);

impl RemoteFrameFlags {
    pub const END_STREAM: u16 = 0x0001;
    pub const RESET_STREAM: u16 = 0x0002;
    /// Union of every defined bit. Anything outside this mask is invalid.
    pub const DEFINED: u16 = Self::END_STREAM | Self::RESET_STREAM;

    pub const fn empty() -> Self {
        Self(0)
    }

    /// Strict constructor: rejects undefined bits rather than masking them off.
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::DEFINED != 0 {
            None
        } else {
            Some(Self(bits))
        }
    }

    pub const fn bits(self) -> u16 {
        self.0
    }

    pub const fn end_stream(self) -> bool {
        self.0 & Self::END_STREAM != 0
    }

    pub const fn reset_stream(self) -> bool {
        self.0 & Self::RESET_STREAM != 0
    }

    pub const fn with_end_stream(self) -> Self {
        Self(self.0 | Self::END_STREAM)
    }

    pub const fn with_reset_stream(self) -> Self {
        Self(self.0 | Self::RESET_STREAM)
    }
}

/// Which peer created a stream. Parity is checked against this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteStreamOrigin {
    /// Client-created streams are nonzero and even.
    Client,
    /// Daemon-created streams are odd.
    Daemon,
}

impl RemoteStreamOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteStreamOrigin::Client => "client",
            RemoteStreamOrigin::Daemon => "daemon",
        }
    }

    /// Origin implied by a nonzero stream id's parity.
    pub const fn of_stream_id(stream_id: u64) -> Option<Self> {
        if stream_id == CONTROL_STREAM_ID {
            None
        } else if stream_id.is_multiple_of(2) {
            Some(RemoteStreamOrigin::Client)
        } else {
            Some(RemoteStreamOrigin::Daemon)
        }
    }
}

/// `nth` client stream id (0-based): 2, 4, 6, …
pub fn client_stream_id(nth: u64) -> RemoteTransportResult<u64> {
    nth.checked_add(1)
        .and_then(|n| n.checked_mul(2))
        .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::StreamParityViolation))
}

/// `nth` daemon stream id (0-based): 1, 3, 5, …
pub fn daemon_stream_id(nth: u64) -> RemoteTransportResult<u64> {
    nth.checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::StreamParityViolation))
}

/// Validate stream ownership for a frame observed from `origin` on `lane`.
pub fn validate_stream_id(
    stream_id: u64,
    origin: RemoteStreamOrigin,
    lane: RemoteLane,
) -> RemoteTransportResult<()> {
    if stream_id == CONTROL_STREAM_ID {
        // Stream 0 is control-only; no other lane may ride it.
        return if lane == RemoteLane::Control {
            Ok(())
        } else {
            Err(RemoteTransportError::with_lane(
                RemoteTransportReason::ZeroStreamId,
                lane,
            ))
        };
    }
    if RemoteStreamOrigin::of_stream_id(stream_id) == Some(origin) {
        Ok(())
    } else {
        Err(RemoteTransportError::with_lane(
            RemoteTransportReason::StreamParityViolation,
            lane,
        ))
    }
}

/// SHA-256 of a payload, as carried in `payloadDigest`.
pub fn payload_digest(payload: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    let out = hasher.finalize();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&out);
    digest
}

/// A decoded logical frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteTransportFrameV1 {
    pub lane: RemoteLane,
    pub flags: RemoteFrameFlags,
    pub stream_id: u64,
    pub stream_seq: u64,
    pub frame_id: RemoteFrameId,
    pub payload: Vec<u8>,
}

impl RemoteTransportFrameV1 {
    pub fn new(
        lane: RemoteLane,
        stream_id: u64,
        stream_seq: u64,
        frame_id: RemoteFrameId,
        payload: Vec<u8>,
    ) -> RemoteTransportResult<Self> {
        let frame = Self {
            lane,
            flags: RemoteFrameFlags::empty(),
            stream_id,
            stream_seq,
            frame_id,
            payload,
        };
        frame.validate_payload_cap()?;
        Ok(frame)
    }

    pub fn with_flags(mut self, flags: RemoteFrameFlags) -> Self {
        self.flags = flags;
        self
    }

    fn validate_payload_cap(&self) -> RemoteTransportResult<()> {
        if self.payload.len() > self.lane.max_payload_bytes() {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::PayloadCapExceeded,
                self.lane,
                self.payload.len(),
            ));
        }
        Ok(())
    }

    pub fn payload_digest(&self) -> [u8; 32] {
        payload_digest(&self.payload)
    }

    pub fn serialized_len(&self) -> usize {
        REMOTE_TRANSPORT_FRAME_HEADER_BYTES + self.payload.len()
    }

    /// Serialize to the exact wire form.
    pub fn encode(&self) -> RemoteTransportResult<Vec<u8>> {
        self.validate_payload_cap()?;
        let mut out = Vec::with_capacity(self.serialized_len());
        out.push(REMOTE_TRANSPORT_FRAME_VERSION);
        out.push(self.lane.lane_id());
        out.extend_from_slice(&self.flags.bits().to_be_bytes());
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.extend_from_slice(&self.stream_seq.to_be_bytes());
        out.extend_from_slice(self.frame_id.as_bytes());
        // Cast is bounded by the 512 KiB cap validated above.
        out.extend_from_slice(&(self.payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.payload_digest());
        out.extend_from_slice(&self.payload);
        debug_assert_eq!(out.len(), self.serialized_len());
        Ok(out)
    }

    /// Strict parse. Every fixed field is validated *before* any allocation
    /// sized from wire data.
    pub fn decode(bytes: &[u8]) -> RemoteTransportResult<Self> {
        if bytes.len() < REMOTE_TRANSPORT_FRAME_HEADER_BYTES {
            return Err(RemoteTransportError::new(
                RemoteTransportReason::HeaderTooShort,
            ));
        }
        if bytes[FRAME_OFFSET_VERSION] != REMOTE_TRANSPORT_FRAME_VERSION {
            return Err(RemoteTransportError::new(
                RemoteTransportReason::UnsupportedVersion,
            ));
        }
        let lane = RemoteLane::from_lane_id(bytes[FRAME_OFFSET_LANE])
            .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::UnknownLane))?;
        let raw_flags =
            u16::from_be_bytes([bytes[FRAME_OFFSET_FLAGS], bytes[FRAME_OFFSET_FLAGS + 1]]);
        let flags = RemoteFrameFlags::from_bits(raw_flags).ok_or_else(|| {
            RemoteTransportError::with_lane(RemoteTransportReason::UnknownFlagBit, lane)
        })?;
        let stream_id = read_u64(bytes, FRAME_OFFSET_STREAM_ID);
        let stream_seq = read_u64(bytes, FRAME_OFFSET_STREAM_SEQ);

        let mut frame_id_bytes = [0u8; 16];
        frame_id_bytes.copy_from_slice(&bytes[FRAME_OFFSET_FRAME_ID..FRAME_OFFSET_FRAME_ID + 16]);
        let frame_id = tag_protocol_id_bytes::<kind::Frame>(frame_id_bytes).map_err(|_| {
            // An all-zero frame id is the only rejection the codec can raise.
            RemoteTransportError::with_lane(RemoteTransportReason::PayloadLengthMismatch, lane)
        })?;

        let payload_length = u32::from_be_bytes([
            bytes[FRAME_OFFSET_PAYLOAD_LENGTH],
            bytes[FRAME_OFFSET_PAYLOAD_LENGTH + 1],
            bytes[FRAME_OFFSET_PAYLOAD_LENGTH + 2],
            bytes[FRAME_OFFSET_PAYLOAD_LENGTH + 3],
        ]) as usize;

        // Cap check precedes any sizing decision so a hostile length can never
        // drive an allocation.
        if payload_length > lane.max_payload_bytes() {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::PayloadCapExceeded,
                lane,
                payload_length,
            ));
        }
        let actual = bytes.len() - REMOTE_TRANSPORT_FRAME_HEADER_BYTES;
        if actual > payload_length {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::TrailingBytes,
                lane,
            ));
        }
        if actual < payload_length {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::PayloadLengthMismatch,
                lane,
            ));
        }

        let mut declared_digest = [0u8; 32];
        declared_digest.copy_from_slice(
            &bytes[FRAME_OFFSET_PAYLOAD_DIGEST..REMOTE_TRANSPORT_FRAME_HEADER_BYTES],
        );
        let payload = bytes[REMOTE_TRANSPORT_FRAME_HEADER_BYTES..].to_vec();
        if payload_digest(&payload) != declared_digest {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::DigestMismatch,
                lane,
            ));
        }

        Ok(Self {
            lane,
            flags,
            stream_id,
            stream_seq,
            frame_id,
            payload,
        })
    }
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_be_bytes(buf)
}

/// Most streams a single peer may hold open at once, per reassembler.
///
/// Without this a peer can open endlessly many streams — each one a permanent
/// map entry — and exhaust daemon memory without ever breaking a rule.
pub const MAX_ACTIVE_STREAMS_PER_PEER: usize = 256;

/// How far above the retired prefix a peer may run before it is refused.
///
/// This is what bounds the closed-ordinal set. A peer that skips an id it never
/// uses stalls its own prefix; after this many outstanding ids the lane refuses
/// new streams with a typed error instead of growing without bound.
pub const MAX_OUTSTANDING_STREAM_IDS: u64 = 1024;

/// Position of a stream id within its lane's allocation sequence.
///
/// Client ids are `2, 4, 6, …` and daemon ids are `1, 3, 5, …`, so each maps to
/// a dense ordinal. Stream 0 (control) is ordinal 0.
fn stream_ordinal(origin: RemoteStreamOrigin, stream_id: u64) -> u64 {
    if stream_id == CONTROL_STREAM_ID {
        return 0;
    }
    match origin {
        RemoteStreamOrigin::Client => stream_id / 2,
        RemoteStreamOrigin::Daemon => stream_id.div_ceil(2),
    }
}

/// Lowest ordinal that is legal on a lane. Stream 0 exists only on control, so
/// every other lane starts one ordinal higher.
const fn first_legal_ordinal(lane: RemoteLane) -> u64 {
    match lane {
        RemoteLane::Control => 0,
        RemoteLane::Interactive | RemoteLane::Bulk => 1,
    }
}

#[derive(Debug, Clone)]
struct LaneStreamState {
    /// Lowest ordinal not yet retired. Everything below it is retired.
    retire_cursor: u64,
    /// Closed ordinals at or above the cursor, waiting to join the prefix.
    /// Bounded by [`MAX_OUTSTANDING_STREAM_IDS`].
    closed: std::collections::BTreeSet<u64>,
}

/// Per-stream sequence validation, stream retirement, and the active-stream
/// budget.
///
/// Sequences start at 0, increment by exactly one, and never wrap. A stream id
/// is retired once its stream closes and may **never** be reused: that is what
/// stops a peer replaying a terminal frame to have it dispatched twice.
///
/// # Why retirement is a contiguous prefix, not a high-water mark
///
/// A stream only enters the open set when its *first frame completes*, and
/// fragmentation reorders completion relative to receipt: stream 4's large
/// first frame may still be reassembling while stream 6's small terminal frame
/// completes and closes. A high-water mark would retire everything at or below
/// 6 and drop stream 4 — a live stream — the moment it finished.
///
/// So an id is retired only when it is *explicitly* recorded closed, or when it
/// lies below a contiguous run of closed ordinals reaching back to the lane's
/// first legal ordinal. Closing a higher id never retires a lower one.
///
/// The closed set is bounded by [`MAX_OUTSTANDING_STREAM_IDS`] rather than
/// allowed to grow, so this is not the unbounded tombstone set it replaces:
/// once the prefix fills, the set collapses back to empty.
#[derive(Debug, Clone)]
pub struct RemoteStreamSequences {
    /// Currently open streams and their next expected sequence.
    next: std::collections::HashMap<(RemoteLane, u64), u64>,
    /// Retirement state per lane. Bounded by the lane count.
    lanes: std::collections::HashMap<RemoteLane, LaneStreamState>,
    origin: RemoteStreamOrigin,
    max_active: usize,
    max_outstanding: u64,
}

impl RemoteStreamSequences {
    /// Track streams belonging to a peer of `origin`.
    pub fn new(origin: RemoteStreamOrigin) -> Self {
        Self {
            next: std::collections::HashMap::new(),
            lanes: std::collections::HashMap::new(),
            origin,
            max_active: MAX_ACTIVE_STREAMS_PER_PEER,
            max_outstanding: MAX_OUTSTANDING_STREAM_IDS,
        }
    }

    /// Override the active-stream budget (tests and carrier tuning).
    pub fn with_max_active_streams(mut self, max_active: usize) -> Self {
        self.max_active = max_active;
        self
    }

    /// Override the outstanding-id window (tests and carrier tuning).
    pub fn with_max_outstanding_ids(mut self, max_outstanding: u64) -> Self {
        self.max_outstanding = max_outstanding;
        self
    }

    fn lane_state(&mut self, lane: RemoteLane) -> &mut LaneStreamState {
        self.lanes.entry(lane).or_insert_with(|| LaneStreamState {
            retire_cursor: first_legal_ordinal(lane),
            closed: std::collections::BTreeSet::new(),
        })
    }

    /// Accept `stream_seq` for `(lane, stream_id)` and advance the expectation.
    pub fn accept(
        &mut self,
        lane: RemoteLane,
        stream_id: u64,
        stream_seq: u64,
    ) -> RemoteTransportResult<()> {
        if let Some(expected) = self.next.get(&(lane, stream_id)).copied() {
            // An open stream: the sequence must be exactly the next one.
            if stream_seq < expected {
                return Err(RemoteTransportError::with_lane(
                    RemoteTransportReason::SequenceRegression,
                    lane,
                ));
            }
            if stream_seq > expected {
                return Err(RemoteTransportError::with_lane(
                    RemoteTransportReason::SequenceGap,
                    lane,
                ));
            }
            let advanced = stream_seq.checked_add(1).ok_or_else(|| {
                RemoteTransportError::with_lane(RemoteTransportReason::SequenceWrap, lane)
            })?;
            self.next.insert((lane, stream_id), advanced);
            return Ok(());
        }

        let ordinal = stream_ordinal(self.origin, stream_id);
        let max_outstanding = self.max_outstanding;
        let active = self.next.len();
        let max_active = self.max_active;
        let state = self.lane_state(lane);

        // Retired either by the contiguous prefix or by an explicit record.
        if ordinal < state.retire_cursor || state.closed.contains(&ordinal) {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::StreamClosed,
                lane,
            ));
        }
        // Running too far ahead of the prefix is what would let the closed set
        // grow without bound.
        if ordinal.saturating_sub(state.retire_cursor) >= max_outstanding {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::StreamLimitExceeded,
                lane,
            ));
        }
        // A new stream starts at sequence zero.
        if stream_seq != 0 {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::SequenceGap,
                lane,
            ));
        }
        if active >= max_active {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::StreamLimitExceeded,
                lane,
            ));
        }
        self.next.insert((lane, stream_id), 1);
        Ok(())
    }

    /// Retire a stream after END_STREAM / RESET_STREAM.
    ///
    /// The entry leaves the open set — freeing budget — and its ordinal is
    /// recorded closed. The prefix then absorbs every contiguous closed ordinal
    /// it can, which is what keeps the closed set from accumulating.
    pub fn close(&mut self, lane: RemoteLane, stream_id: u64) {
        self.next.remove(&(lane, stream_id));
        let ordinal = stream_ordinal(self.origin, stream_id);
        let state = self.lane_state(lane);
        if ordinal < state.retire_cursor {
            return;
        }
        state.closed.insert(ordinal);
        while state.closed.remove(&state.retire_cursor) {
            state.retire_cursor += 1;
        }
    }

    /// Streams currently open.
    pub fn tracked_streams(&self) -> usize {
        self.next.len()
    }

    /// Closed ordinals still held out of the prefix, across every lane.
    pub fn pending_closed_ordinals(&self) -> usize {
        self.lanes.values().map(|state| state.closed.len()).sum()
    }

    /// Budget ceiling in force.
    pub fn max_active_streams(&self) -> usize {
        self.max_active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_id(seed: u8) -> RemoteFrameId {
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        tag_protocol_id_bytes::<kind::Frame>(bytes).expect("nonzero frame id")
    }

    #[test]
    fn remote_transport_frame_layout_offsets_are_exact() {
        assert_eq!(REMOTE_TRANSPORT_FRAME_HEADER_BYTES, 72);
        // 1 + 1 + 2 + 8 + 8 + 16 + 4 + 32 == 72
        assert_eq!(1 + 1 + 2 + 8 + 8 + 16 + 4 + 32, 72);
        assert_eq!(FRAME_OFFSET_VERSION, 0);
        assert_eq!(FRAME_OFFSET_LANE, 1);
        assert_eq!(FRAME_OFFSET_FLAGS, 2);
        assert_eq!(FRAME_OFFSET_STREAM_ID, 4);
        assert_eq!(FRAME_OFFSET_STREAM_SEQ, 12);
        assert_eq!(FRAME_OFFSET_FRAME_ID, 20);
        assert_eq!(FRAME_OFFSET_PAYLOAD_LENGTH, 36);
        assert_eq!(FRAME_OFFSET_PAYLOAD_DIGEST, 40);
        assert_eq!(MAX_SERIALIZED_FRAME_BYTES, 524_360);
    }

    #[test]
    fn remote_transport_frame_encode_is_network_byte_order() {
        let frame = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            0x0102_0304_0506_0708,
            0x1112_1314_1516_1718,
            frame_id(0x20),
            b"hello".to_vec(),
        )
        .unwrap()
        .with_flags(RemoteFrameFlags::from_bits(RemoteFrameFlags::END_STREAM).unwrap());
        let encoded = frame.encode().unwrap();

        assert_eq!(encoded.len(), 72 + 5);
        assert_eq!(encoded[0], 1);
        assert_eq!(encoded[1], RemoteLane::Interactive.lane_id());
        assert_eq!(&encoded[2..4], &[0x00, 0x01]);
        // Big-endian: most significant byte first.
        assert_eq!(&encoded[4..12], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            &encoded[12..20],
            &[0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]
        );
        assert_eq!(&encoded[36..40], &[0, 0, 0, 5]);
        assert_eq!(&encoded[40..72], &payload_digest(b"hello"));
        assert_eq!(&encoded[72..], b"hello");

        let decoded = RemoteTransportFrameV1::decode(&encoded).unwrap();
        assert_eq!(decoded, frame);
    }

    #[test]
    fn remote_transport_frame_rejects_undefined_flag_bits() {
        assert!(RemoteFrameFlags::from_bits(0x0000).is_some());
        assert!(RemoteFrameFlags::from_bits(0x0001).is_some());
        assert!(RemoteFrameFlags::from_bits(0x0002).is_some());
        assert!(RemoteFrameFlags::from_bits(0x0003).is_some());
        for bad in [0x0004u16, 0x0008, 0x0100, 0x8000, 0xFFFF] {
            assert!(RemoteFrameFlags::from_bits(bad).is_none(), "{bad:#06x}");
        }

        let mut encoded = RemoteTransportFrameV1::new(
            RemoteLane::Control,
            CONTROL_STREAM_ID,
            0,
            frame_id(1),
            vec![7],
        )
        .unwrap()
        .encode()
        .unwrap();
        encoded[2] = 0x00;
        encoded[3] = 0x04;
        assert_eq!(
            RemoteTransportFrameV1::decode(&encoded).unwrap_err().reason,
            RemoteTransportReason::UnknownFlagBit
        );
    }

    #[test]
    fn remote_transport_frame_strict_parser_failures() {
        let good = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            2,
            0,
            frame_id(3),
            b"abcd".to_vec(),
        )
        .unwrap()
        .encode()
        .unwrap();

        // Short header.
        assert_eq!(
            RemoteTransportFrameV1::decode(&good[..71])
                .unwrap_err()
                .reason,
            RemoteTransportReason::HeaderTooShort
        );

        // Wrong version.
        let mut wrong_version = good.clone();
        wrong_version[0] = 2;
        assert_eq!(
            RemoteTransportFrameV1::decode(&wrong_version)
                .unwrap_err()
                .reason,
            RemoteTransportReason::UnsupportedVersion
        );

        // Unknown lane.
        let mut wrong_lane = good.clone();
        wrong_lane[1] = 3;
        assert_eq!(
            RemoteTransportFrameV1::decode(&wrong_lane)
                .unwrap_err()
                .reason,
            RemoteTransportReason::UnknownLane
        );

        // Trailing bytes.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            RemoteTransportFrameV1::decode(&trailing)
                .unwrap_err()
                .reason,
            RemoteTransportReason::TrailingBytes
        );

        // Truncated payload.
        let truncated = &good[..good.len() - 1];
        assert_eq!(
            RemoteTransportFrameV1::decode(truncated)
                .unwrap_err()
                .reason,
            RemoteTransportReason::PayloadLengthMismatch
        );

        // Digest mismatch.
        let mut corrupt = good.clone();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xFF;
        assert_eq!(
            RemoteTransportFrameV1::decode(&corrupt).unwrap_err().reason,
            RemoteTransportReason::DigestMismatch
        );

        // Declared length beyond the lane cap fails before allocation.
        let mut oversized = good.clone();
        oversized[36..40].copy_from_slice(&(600_000u32).to_be_bytes());
        assert_eq!(
            RemoteTransportFrameV1::decode(&oversized)
                .unwrap_err()
                .reason,
            RemoteTransportReason::PayloadCapExceeded
        );
    }

    #[test]
    fn remote_transport_frame_enforces_lane_payload_caps() {
        // Control caps at 64 KiB even though the frame format allows 512 KiB.
        let over_control = RemoteTransportFrameV1::new(
            RemoteLane::Control,
            CONTROL_STREAM_ID,
            0,
            frame_id(4),
            vec![0u8; 65_537],
        );
        assert_eq!(
            over_control.unwrap_err().reason,
            RemoteTransportReason::PayloadCapExceeded
        );
        assert!(
            RemoteTransportFrameV1::new(
                RemoteLane::Control,
                CONTROL_STREAM_ID,
                0,
                frame_id(4),
                vec![0u8; 65_536],
            )
            .is_ok()
        );

        for lane in [RemoteLane::Interactive, RemoteLane::Bulk] {
            let stream = if lane == RemoteLane::Interactive {
                2
            } else {
                4
            };
            assert!(
                RemoteTransportFrameV1::new(lane, stream, 0, frame_id(5), vec![0u8; 524_288])
                    .is_ok()
            );
            assert_eq!(
                RemoteTransportFrameV1::new(lane, stream, 0, frame_id(5), vec![0u8; 524_289])
                    .unwrap_err()
                    .reason,
                RemoteTransportReason::PayloadCapExceeded
            );
        }
    }

    #[test]
    fn remote_transport_frame_stream_parity_and_ownership() {
        assert_eq!(client_stream_id(0).unwrap(), 2);
        assert_eq!(client_stream_id(1).unwrap(), 4);
        assert_eq!(daemon_stream_id(0).unwrap(), 1);
        assert_eq!(daemon_stream_id(1).unwrap(), 3);

        // Client streams are nonzero and even; daemon streams are odd.
        validate_stream_id(2, RemoteStreamOrigin::Client, RemoteLane::Interactive).unwrap();
        validate_stream_id(3, RemoteStreamOrigin::Daemon, RemoteLane::Interactive).unwrap();
        assert_eq!(
            validate_stream_id(2, RemoteStreamOrigin::Daemon, RemoteLane::Interactive)
                .unwrap_err()
                .reason,
            RemoteTransportReason::StreamParityViolation
        );
        assert_eq!(
            validate_stream_id(3, RemoteStreamOrigin::Client, RemoteLane::Bulk)
                .unwrap_err()
                .reason,
            RemoteTransportReason::StreamParityViolation
        );

        // Stream 0 is control-only, from either peer.
        validate_stream_id(0, RemoteStreamOrigin::Client, RemoteLane::Control).unwrap();
        validate_stream_id(0, RemoteStreamOrigin::Daemon, RemoteLane::Control).unwrap();
        for lane in [RemoteLane::Interactive, RemoteLane::Bulk] {
            assert_eq!(
                validate_stream_id(0, RemoteStreamOrigin::Client, lane)
                    .unwrap_err()
                    .reason,
                RemoteTransportReason::ZeroStreamId
            );
        }
    }

    /// Retirement is a contiguous prefix, never "everything below the highest
    /// closed id".
    ///
    /// NOTE: this is a data-structure unit test. It deliberately does **not**
    /// claim to cover the fragmented-reassembly interleaving — calling `accept`
    /// directly cannot reproduce the ordering that makes that case dangerous.
    /// `remote_transport_fragment_live_stream_survives_higher_id_close` in
    /// `fragment.rs` drives that through the real path.
    #[test]
    fn remote_transport_frame_streams_retire_by_contiguous_prefix() {
        let mut seqs = RemoteStreamSequences::new(RemoteStreamOrigin::Client);
        // Close a higher id while a lower one has never been seen at all.
        seqs.accept(RemoteLane::Interactive, 6, 0).unwrap();
        seqs.close(RemoteLane::Interactive, 6);
        // Ordinal 3 is closed but the prefix cannot advance past ordinal 1
        // (stream 2), so stream 4 is still perfectly openable.
        assert_eq!(seqs.pending_closed_ordinals(), 1);
        seqs.accept(RemoteLane::Interactive, 4, 0).unwrap();
        // The closed id itself stays retired.
        assert_eq!(
            seqs.accept(RemoteLane::Interactive, 6, 0)
                .unwrap_err()
                .reason,
            RemoteTransportReason::StreamClosed
        );

        // Filling the prefix collapses the closed set back to nothing.
        seqs.close(RemoteLane::Interactive, 4);
        assert_eq!(seqs.pending_closed_ordinals(), 2);
        seqs.accept(RemoteLane::Interactive, 2, 0).unwrap();
        seqs.close(RemoteLane::Interactive, 2);
        assert_eq!(
            seqs.pending_closed_ordinals(),
            0,
            "a contiguous prefix must absorb the closed set, not accumulate it"
        );
        // Everything in the prefix is now retired.
        for retired in [2u64, 4, 6] {
            assert_eq!(
                seqs.accept(RemoteLane::Interactive, retired, 0)
                    .unwrap_err()
                    .reason,
                RemoteTransportReason::StreamClosed
            );
        }
        seqs.accept(RemoteLane::Interactive, 8, 0).unwrap();
    }

    #[test]
    fn remote_transport_frame_bounds_outstanding_stream_ids() {
        // A peer that never uses its first id stalls its own prefix. That must
        // fail closed at the window rather than grow the closed set forever.
        let mut seqs =
            RemoteStreamSequences::new(RemoteStreamOrigin::Client).with_max_outstanding_ids(8);
        for nth in 1..8u64 {
            let stream = (nth + 1) * 2; // skips stream 2 (ordinal 1) entirely
            seqs.accept(RemoteLane::Interactive, stream, 0).unwrap();
            seqs.close(RemoteLane::Interactive, stream);
        }
        assert!(seqs.pending_closed_ordinals() <= 8);
        assert_eq!(
            seqs.accept(RemoteLane::Interactive, 100, 0)
                .unwrap_err()
                .reason,
            RemoteTransportReason::StreamLimitExceeded,
            "running far ahead of the retired prefix must be refused"
        );
    }

    #[test]
    fn remote_transport_frame_bounds_active_streams() {
        let mut seqs =
            RemoteStreamSequences::new(RemoteStreamOrigin::Client).with_max_active_streams(3);
        assert_eq!(seqs.max_active_streams(), 3);
        for nth in 0..3u64 {
            seqs.accept(RemoteLane::Interactive, client_stream_id(nth).unwrap(), 0)
                .unwrap();
        }
        assert_eq!(
            seqs.accept(RemoteLane::Interactive, client_stream_id(3).unwrap(), 0)
                .unwrap_err()
                .reason,
            RemoteTransportReason::StreamLimitExceeded
        );
        // Closing one frees exactly one slot.
        seqs.close(RemoteLane::Interactive, client_stream_id(0).unwrap());
        seqs.accept(RemoteLane::Interactive, client_stream_id(3).unwrap(), 0)
            .unwrap();
    }

    #[test]
    fn remote_transport_frame_new_streams_start_at_zero() {
        let mut seqs = RemoteStreamSequences::new(RemoteStreamOrigin::Client);
        assert_eq!(
            seqs.accept(RemoteLane::Interactive, 2, 7)
                .unwrap_err()
                .reason,
            RemoteTransportReason::SequenceGap,
            "a peer may not open a stream mid-sequence"
        );
        seqs.accept(RemoteLane::Interactive, 2, 0).unwrap();
    }

    #[test]
    fn remote_transport_frame_sequence_rules() {
        let mut seqs = RemoteStreamSequences::new(RemoteStreamOrigin::Client);
        // Starts at zero and increments by one.
        seqs.accept(RemoteLane::Interactive, 2, 0).unwrap();
        seqs.accept(RemoteLane::Interactive, 2, 1).unwrap();
        seqs.accept(RemoteLane::Interactive, 2, 2).unwrap();

        // A gap fails.
        assert_eq!(
            seqs.accept(RemoteLane::Interactive, 2, 4)
                .unwrap_err()
                .reason,
            RemoteTransportReason::SequenceGap
        );
        // A regression (replay) fails.
        assert_eq!(
            seqs.accept(RemoteLane::Interactive, 2, 1)
                .unwrap_err()
                .reason,
            RemoteTransportReason::SequenceRegression
        );
        // Streams are tracked independently per lane.
        seqs.accept(RemoteLane::Bulk, 2, 0).unwrap();
        assert_eq!(seqs.tracked_streams(), 2);

        // Sequence never wraps.
        let mut wrapping = RemoteStreamSequences::new(RemoteStreamOrigin::Client);
        wrapping.next.insert((RemoteLane::Control, 0), u64::MAX);
        assert_eq!(
            wrapping
                .accept(RemoteLane::Control, 0, u64::MAX)
                .unwrap_err()
                .reason,
            RemoteTransportReason::SequenceWrap
        );

        seqs.close(RemoteLane::Bulk, 2);
        assert_eq!(seqs.tracked_streams(), 1);
    }
}
