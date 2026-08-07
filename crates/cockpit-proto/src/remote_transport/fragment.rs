//! `RemoteCarrierFragmentV1` — the 26-byte-header carrier fragment.
//!
//! Wire layout, network byte order throughout:
//!
//! ```text
//! version:u8(1) | lane:u8 | flags:u16 | frameId:[16]
//!   | fragmentIndex:u16 | fragmentCount:u16 | fragmentPayloadLength:u16 | bytes
//! ```
//!
//! The 65,471-byte payload bound closes exactly against the Noise carrier:
//!
//! ```text
//! 65,535 record ciphertext
//!   -  16 AEAD tag          => 65,519 plaintext
//!   -  14 Noise record header => 65,505 record payload
//!   -   8 peerSeenThrough watermark => 65,497 fragment total
//!   -  26 fragment header    => 65,471 fragment payload
//! ```
//!
//! WebRTC does not transmit the watermark, but reserves the same 8 bytes so
//! fragment fixtures stay byte-identical across both carriers.

use std::collections::HashMap;

use crate::remote_protocol_id::{RemoteFrameId, kind, tag_protocol_id_bytes};
use crate::remote_transport::frame::{
    MAX_SERIALIZED_FRAME_BYTES, REMOTE_TRANSPORT_FRAME_HEADER_BYTES, RemoteStreamOrigin,
    RemoteStreamSequences, RemoteTransportFrameV1, validate_stream_id,
};
use crate::remote_transport::lane::{
    RemoteLane, RemoteTransportError, RemoteTransportReason, RemoteTransportResult,
};

/// Only version 1 exists.
pub const REMOTE_CARRIER_FRAGMENT_VERSION: u8 = 1;

/// Exact carrier fragment header size.
pub const REMOTE_CARRIER_FRAGMENT_HEADER_BYTES: usize = 26;

// --- Noise carrier derivation (see module docs) -----------------------------
/// Maximum Noise record ciphertext, tag included.
pub const NOISE_RECORD_MAX_CIPHERTEXT_BYTES: usize = 65_535;
/// Noise AEAD tag length.
pub const NOISE_AEAD_TAG_BYTES: usize = 16;
/// Maximum Noise plaintext per record.
pub const NOISE_MAX_PLAINTEXT_BYTES: usize =
    NOISE_RECORD_MAX_CIPHERTEXT_BYTES - NOISE_AEAD_TAG_BYTES;
/// `RemoteNoiseRecordV1` header length.
pub const NOISE_RECORD_HEADER_BYTES: usize = 14;
/// Bytes available inside one Noise record after its header.
pub const NOISE_RECORD_PAYLOAD_BYTES: usize = NOISE_MAX_PLAINTEXT_BYTES - NOISE_RECORD_HEADER_BYTES;
/// Reserved `peerSeenThrough` watermark prefix. Reserved on every carrier.
pub const PEER_SEEN_THROUGH_WATERMARK_BYTES: usize = 8;
/// Total bytes a complete fragment may occupy on any carrier.
pub const LANE_FRAGMENT_TOTAL_BYTES: usize =
    NOISE_RECORD_PAYLOAD_BYTES - PEER_SEEN_THROUGH_WATERMARK_BYTES;
/// Maximum fragment payload.
pub const REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES: usize =
    LANE_FRAGMENT_TOTAL_BYTES - REMOTE_CARRIER_FRAGMENT_HEADER_BYTES;

const _: () = assert!(NOISE_MAX_PLAINTEXT_BYTES == 65_519);
const _: () = assert!(NOISE_RECORD_PAYLOAD_BYTES == 65_505);
const _: () = assert!(LANE_FRAGMENT_TOTAL_BYTES == 65_497);
const _: () = assert!(REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES == 65_471);

/// Maximum fragments per logical frame: ⌈524,360 / 65,471⌉ = 9.
pub const MAX_FRAGMENT_COUNT: u16 = 9;
const _: () = assert!(
    MAX_FRAGMENT_COUNT as usize
        == MAX_SERIALIZED_FRAME_BYTES.div_ceil(REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES)
);

/// At most 16 incomplete frames may be in flight per peer.
pub const MAX_INCOMPLETE_FRAMES_PER_PEER: usize = 16;
/// At most 8 MiB of reassembly buffer per peer.
pub const MAX_REASSEMBLY_BYTES_PER_PEER: usize = 8 * 1024 * 1024;
/// Incomplete reassembly state expires after 5 seconds.
pub const REASSEMBLY_DEADLINE_MS: u64 = 5_000;

/// Completed frame ids remembered per peer, so a replayed or reused id is
/// caught rather than treated as a brand-new frame.
///
/// Frame ids are **random** 128-bit values, so the contiguous-closed-prefix
/// trick that retires *stream* ids does not apply here: random ids have no
/// ordering, so there is no prefix to collapse and a "retired ids" set would be
/// the unbounded tombstone set that design exists to avoid. A frame id only has
/// to stay unique for the retention window, so a bounded, expiry-aligned memory
/// is the right shape instead — it is capped, and it drains on the same
/// injected deadline as incomplete state.
pub const MAX_COMPLETED_FRAME_MEMORY: usize = 64;

// Field offsets.
pub const FRAGMENT_OFFSET_VERSION: usize = 0;
pub const FRAGMENT_OFFSET_LANE: usize = 1;
pub const FRAGMENT_OFFSET_FLAGS: usize = 2;
pub const FRAGMENT_OFFSET_FRAME_ID: usize = 4;
pub const FRAGMENT_OFFSET_INDEX: usize = 20;
pub const FRAGMENT_OFFSET_COUNT: usize = 22;
pub const FRAGMENT_OFFSET_PAYLOAD_LENGTH: usize = 24;

const _: () = assert!(FRAGMENT_OFFSET_PAYLOAD_LENGTH + 2 == REMOTE_CARRIER_FRAGMENT_HEADER_BYTES);

/// Fragment flags. Only `END` exists; every other bit fails, mirroring the
/// frame-level rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct RemoteFragmentFlags(u16);

impl RemoteFragmentFlags {
    pub const END: u16 = 0x0001;
    pub const DEFINED: u16 = Self::END;

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn end() -> Self {
        Self(Self::END)
    }

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

    pub const fn is_end(self) -> bool {
        self.0 & Self::END != 0
    }
}

/// One carrier fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCarrierFragmentV1 {
    pub lane: RemoteLane,
    pub flags: RemoteFragmentFlags,
    pub frame_id: RemoteFrameId,
    pub fragment_index: u16,
    pub fragment_count: u16,
    pub bytes: Vec<u8>,
}

impl RemoteCarrierFragmentV1 {
    pub fn encoded_len(&self) -> usize {
        REMOTE_CARRIER_FRAGMENT_HEADER_BYTES + self.bytes.len()
    }

    pub fn encode(&self) -> RemoteTransportResult<Vec<u8>> {
        self.validate_shape()?;
        let mut out = Vec::with_capacity(self.encoded_len());
        out.push(REMOTE_CARRIER_FRAGMENT_VERSION);
        out.push(self.lane.lane_id());
        out.extend_from_slice(&self.flags.bits().to_be_bytes());
        out.extend_from_slice(self.frame_id.as_bytes());
        out.extend_from_slice(&self.fragment_index.to_be_bytes());
        out.extend_from_slice(&self.fragment_count.to_be_bytes());
        // Cast is bounded by the payload check in `validate_shape`.
        out.extend_from_slice(&(self.bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.bytes);
        Ok(out)
    }

    fn validate_shape(&self) -> RemoteTransportResult<()> {
        if self.bytes.len() > REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::FragmentPayloadCapExceeded,
                self.lane,
                self.bytes.len(),
            ));
        }
        if self.fragment_count == 0 {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::ZeroFragmentCount,
                self.lane,
            ));
        }
        if self.fragment_count > MAX_FRAGMENT_COUNT {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::FragmentCountExceeded,
                self.lane,
            ));
        }
        if self.fragment_index >= self.fragment_count {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::FragmentIndexOutOfRange,
                self.lane,
            ));
        }
        // The final fragment alone carries END.
        let is_final = self.fragment_index + 1 == self.fragment_count;
        if self.flags.is_end() != is_final {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::FragmentEndFlagMisplaced,
                self.lane,
            ));
        }
        Ok(())
    }

    /// Strict parse. Fixed header, count, and length are validated before the
    /// payload is copied.
    pub fn decode(bytes: &[u8]) -> RemoteTransportResult<Self> {
        if bytes.len() < REMOTE_CARRIER_FRAGMENT_HEADER_BYTES {
            return Err(RemoteTransportError::new(
                RemoteTransportReason::HeaderTooShort,
            ));
        }
        if bytes[FRAGMENT_OFFSET_VERSION] != REMOTE_CARRIER_FRAGMENT_VERSION {
            return Err(RemoteTransportError::new(
                RemoteTransportReason::UnsupportedVersion,
            ));
        }
        let lane = RemoteLane::from_lane_id(bytes[FRAGMENT_OFFSET_LANE])
            .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::UnknownLane))?;
        let raw_flags = u16::from_be_bytes([
            bytes[FRAGMENT_OFFSET_FLAGS],
            bytes[FRAGMENT_OFFSET_FLAGS + 1],
        ]);
        let flags = RemoteFragmentFlags::from_bits(raw_flags).ok_or_else(|| {
            RemoteTransportError::with_lane(RemoteTransportReason::UnknownFlagBit, lane)
        })?;

        let mut frame_id_bytes = [0u8; 16];
        frame_id_bytes
            .copy_from_slice(&bytes[FRAGMENT_OFFSET_FRAME_ID..FRAGMENT_OFFSET_FRAME_ID + 16]);
        let frame_id = tag_protocol_id_bytes::<kind::Frame>(frame_id_bytes).map_err(|_| {
            RemoteTransportError::with_lane(RemoteTransportReason::FragmentConflict, lane)
        })?;

        let fragment_index = u16::from_be_bytes([
            bytes[FRAGMENT_OFFSET_INDEX],
            bytes[FRAGMENT_OFFSET_INDEX + 1],
        ]);
        let fragment_count = u16::from_be_bytes([
            bytes[FRAGMENT_OFFSET_COUNT],
            bytes[FRAGMENT_OFFSET_COUNT + 1],
        ]);
        let declared_len = u16::from_be_bytes([
            bytes[FRAGMENT_OFFSET_PAYLOAD_LENGTH],
            bytes[FRAGMENT_OFFSET_PAYLOAD_LENGTH + 1],
        ]) as usize;

        // Bound the declared length before slicing.
        if declared_len > REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::FragmentPayloadCapExceeded,
                lane,
                declared_len,
            ));
        }
        let actual = bytes.len() - REMOTE_CARRIER_FRAGMENT_HEADER_BYTES;
        if actual > declared_len {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::TrailingBytes,
                lane,
            ));
        }
        if actual < declared_len {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::FragmentLengthMismatch,
                lane,
            ));
        }

        let fragment = Self {
            lane,
            flags,
            frame_id,
            fragment_index,
            fragment_count,
            bytes: bytes[REMOTE_CARRIER_FRAGMENT_HEADER_BYTES..].to_vec(),
        };
        fragment.validate_shape()?;
        Ok(fragment)
    }
}

/// Split a serialized logical frame into canonical carrier fragments.
///
/// Deterministic: every fragment but the last is exactly
/// [`REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES`]. This is what makes WebRTC and
/// fallback fragment fixtures byte-identical.
pub fn fragment_frame(
    lane: RemoteLane,
    frame_id: RemoteFrameId,
    serialized_frame: &[u8],
) -> RemoteTransportResult<Vec<RemoteCarrierFragmentV1>> {
    if serialized_frame.len() < REMOTE_TRANSPORT_FRAME_HEADER_BYTES {
        return Err(RemoteTransportError::with_lane(
            RemoteTransportReason::HeaderTooShort,
            lane,
        ));
    }
    if serialized_frame.len() > MAX_SERIALIZED_FRAME_BYTES {
        return Err(RemoteTransportError::with_size(
            RemoteTransportReason::PayloadCapExceeded,
            lane,
            serialized_frame.len(),
        ));
    }
    let count = serialized_frame
        .len()
        .div_ceil(REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES)
        .max(1);
    if count > MAX_FRAGMENT_COUNT as usize {
        return Err(RemoteTransportError::with_lane(
            RemoteTransportReason::FragmentCountExceeded,
            lane,
        ));
    }
    let count = count as u16;
    let mut fragments = Vec::with_capacity(count as usize);
    for index in 0..count {
        let start = index as usize * REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES;
        let end = (start + REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES).min(serialized_frame.len());
        let is_final = index + 1 == count;
        fragments.push(RemoteCarrierFragmentV1 {
            lane,
            flags: if is_final {
                RemoteFragmentFlags::end()
            } else {
                RemoteFragmentFlags::empty()
            },
            frame_id,
            fragment_index: index,
            fragment_count: count,
            bytes: serialized_frame[start..end].to_vec(),
        });
    }
    Ok(fragments)
}

#[derive(Debug, Clone)]
struct PartialFrame {
    lane: RemoteLane,
    fragment_count: u16,
    slots: Vec<Option<Vec<u8>>>,
    buffered_bytes: usize,
    first_seen_ms: u64,
}

/// Bounded per-peer fragment reassembly, and the sole receive-side gate.
///
/// The clock is injected: callers pass a monotonic millisecond reading, so the
/// 5-second expiry is testable without sleeping.
///
/// The reassembler is constructed with the origin of the peer it reads from and
/// owns that peer's [`RemoteStreamSequences`]. That is deliberate: a frame can
/// only become dispatchable by leaving [`RemoteFragmentReassembler::accept`],
/// and that exit applies stream ownership/parity and per-stream sequence rules
/// alongside the digest. There is no way to obtain a validated frame that
/// skipped them.
/// A frame that already completed, kept for the retention window.
#[derive(Debug, Clone)]
struct CompletedFrame {
    at_ms: u64,
    /// The exact 72-byte header. Comparing it distinguishes a byte-identical
    /// retry (idempotent, non-dispatching) from a different frame wearing the
    /// same id (conflicting reuse) — including one that only differs by stream
    /// sequence, which the sequence check alone would happily accept.
    header: [u8; REMOTE_TRANSPORT_FRAME_HEADER_BYTES],
}

#[derive(Debug, Clone)]
pub struct RemoteFragmentReassembler {
    /// Which peer sent these fragments. Stream parity is checked against it.
    peer_origin: RemoteStreamOrigin,
    sequences: RemoteStreamSequences,
    partials: HashMap<[u8; 16], PartialFrame>,
    /// Frame ids that completed inside the retention window.
    completed: HashMap<[u8; 16], CompletedFrame>,
    buffered_bytes: usize,
    max_frames: usize,
    max_bytes: usize,
    deadline_ms: u64,
}

impl RemoteFragmentReassembler {
    /// A reassembler reading from a peer of `peer_origin`.
    ///
    /// There is no `Default`: leaving the origin implicit is exactly the bug
    /// that lets a peer claim its counterpart's stream IDs.
    pub fn new(peer_origin: RemoteStreamOrigin) -> Self {
        Self {
            peer_origin,
            sequences: RemoteStreamSequences::new(peer_origin),
            partials: HashMap::new(),
            completed: HashMap::new(),
            buffered_bytes: 0,
            max_frames: MAX_INCOMPLETE_FRAMES_PER_PEER,
            max_bytes: MAX_REASSEMBLY_BYTES_PER_PEER,
            deadline_ms: REASSEMBLY_DEADLINE_MS,
        }
    }

    pub fn peer_origin(&self) -> RemoteStreamOrigin {
        self.peer_origin
    }

    /// Streams with live sequence expectations.
    pub fn tracked_streams(&self) -> usize {
        self.sequences.tracked_streams()
    }

    /// Override the peer's active-stream budget (tests and carrier tuning).
    pub fn with_max_active_streams(mut self, max_active: usize) -> Self {
        self.sequences = self.sequences.with_max_active_streams(max_active);
        self
    }

    /// Override the injected expiry deadline (tests and carrier tuning).
    pub fn with_deadline_ms(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = deadline_ms;
        self
    }

    pub fn incomplete_frames(&self) -> usize {
        self.partials.len()
    }

    pub fn buffered_bytes(&self) -> usize {
        self.buffered_bytes
    }

    /// Drop every partial older than the deadline. Returns how many expired.
    pub fn expire(&mut self, now_ms: u64) -> usize {
        let deadline = self.deadline_ms;
        let mut freed = 0usize;
        let before = self.partials.len();
        self.partials.retain(|_, partial| {
            let expired = now_ms.saturating_sub(partial.first_seen_ms) >= deadline;
            if expired {
                freed += partial.buffered_bytes;
            }
            !expired
        });
        self.buffered_bytes -= freed;
        // The completion memory drains on the same deadline, so the retention
        // window and the reassembly window are the same window.
        self.completed
            .retain(|_, done| now_ms.saturating_sub(done.at_ms) < deadline);
        before - self.partials.len()
    }

    /// Frame ids remembered from completed frames.
    pub fn remembered_frames(&self) -> usize {
        self.completed.len()
    }

    /// Accept one fragment. Returns the reassembled frame once the final
    /// fragment lands and the complete 72-byte frame validates.
    pub fn accept(
        &mut self,
        fragment: &RemoteCarrierFragmentV1,
        now_ms: u64,
    ) -> RemoteTransportResult<Option<RemoteTransportFrameV1>> {
        // A caller-built fragment has not been through `decode`, so validate it
        // here too: an out-of-range index would otherwise index past `slots`.
        fragment.validate_shape()?;
        self.expire(now_ms);
        let key = *fragment.frame_id.as_bytes();
        let lane = fragment.lane;

        let is_new = !self.partials.contains_key(&key);
        if is_new {
            if self.partials.len() >= self.max_frames {
                return Err(RemoteTransportError::with_lane(
                    RemoteTransportReason::ReassemblyFrameLimit,
                    lane,
                ));
            }
            self.partials.insert(
                key,
                PartialFrame {
                    lane,
                    fragment_count: fragment.fragment_count,
                    slots: vec![None; fragment.fragment_count as usize],
                    buffered_bytes: 0,
                    first_seen_ms: now_ms,
                },
            );
        }

        // Every fragment of a frame must repeat the same lane and count.
        {
            let partial = self.partials.get(&key).expect("just inserted");
            if partial.lane != lane || partial.fragment_count != fragment.fragment_count {
                if is_new {
                    self.partials.remove(&key);
                }
                return Err(RemoteTransportError::with_lane(
                    RemoteTransportReason::FragmentConflict,
                    lane,
                ));
            }
        }

        // Duplicate handling before any accounting: identical bytes are
        // idempotent, differing bytes are a conflict.
        if let Some(existing) = self.partials[&key].slots[fragment.fragment_index as usize].as_ref()
        {
            return if existing == &fragment.bytes {
                Ok(None)
            } else {
                Err(RemoteTransportError::with_lane(
                    RemoteTransportReason::FragmentConflict,
                    lane,
                ))
            };
        }

        if self.buffered_bytes + fragment.bytes.len() > self.max_bytes {
            if is_new {
                self.partials.remove(&key);
            }
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::ReassemblyByteLimit,
                lane,
                fragment.bytes.len(),
            ));
        }

        let partial = self.partials.get_mut(&key).expect("present");
        if partial.buffered_bytes + fragment.bytes.len() > MAX_SERIALIZED_FRAME_BYTES {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::ReassemblyByteLimit,
                lane,
                fragment.bytes.len(),
            ));
        }
        partial.slots[fragment.fragment_index as usize] = Some(fragment.bytes.clone());
        partial.buffered_bytes += fragment.bytes.len();
        self.buffered_bytes += fragment.bytes.len();

        if partial.slots.iter().any(|slot| slot.is_none()) {
            return Ok(None);
        }

        let partial = self.partials.remove(&key).expect("present");
        self.buffered_bytes -= partial.buffered_bytes;
        let mut serialized = Vec::with_capacity(partial.buffered_bytes);
        for slot in partial.slots {
            serialized.extend_from_slice(&slot.expect("all slots filled"));
        }
        // The complete 72-byte frame and its SHA-256 digest are validated here,
        // before anything is dispatched.
        let frame = RemoteTransportFrameV1::decode(&serialized)?;
        if frame.lane != lane || frame.frame_id.as_bytes() != &key {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::FragmentConflict,
                lane,
            ));
        }
        let mut header = [0u8; REMOTE_TRANSPORT_FRAME_HEADER_BYTES];
        header.copy_from_slice(&serialized[..REMOTE_TRANSPORT_FRAME_HEADER_BYTES]);
        if let Some(done) = self.completed.get(&key) {
            // A frame id must stay unique for the retention window. A
            // byte-identical retry is idempotent and must not be dispatched a
            // second time; anything else wearing the same id is conflicting
            // reuse. Note the stream sequence check cannot catch the latter: a
            // peer that reuses an id on the *next* sequence number satisfies it.
            return if done.header == header {
                Ok(None)
            } else {
                Err(RemoteTransportError::with_lane(
                    RemoteTransportReason::FragmentConflict,
                    lane,
                ))
            };
        }
        // Stream ownership and per-stream sequence are receive-side rules, so
        // they belong on the only path that yields a dispatchable frame. A peer
        // may not ride stream 0 off the control lane, claim its counterpart's
        // parity, skip a sequence number, or replay an old one.
        validate_stream_id(frame.stream_id, self.peer_origin, frame.lane)?;
        self.sequences
            .accept(frame.lane, frame.stream_id, frame.stream_seq)?;
        if frame.flags.end_stream() || frame.flags.reset_stream() {
            // Retires the id: it leaves the active budget but can never be
            // reused, so the terminal frame itself is not replayable.
            self.sequences.close(frame.lane, frame.stream_id);
        }
        // Remember it only now that every rule has passed, so a rejected frame
        // may still be retried. The memory is capped; when it is full the
        // oldest entry makes way, which is the retention window doing its job.
        if self.completed.len() >= MAX_COMPLETED_FRAME_MEMORY
            && let Some(oldest) = self
                .completed
                .iter()
                .min_by_key(|(_, done)| done.at_ms)
                .map(|(id, _)| *id)
        {
            self.completed.remove(&oldest);
        }
        self.completed.insert(
            key,
            CompletedFrame {
                at_ms: now_ms,
                header,
            },
        );
        Ok(Some(frame))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_transport::frame::{RemoteFrameFlags, client_stream_id, payload_digest};

    fn frame_id(seed: u8) -> RemoteFrameId {
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        tag_protocol_id_bytes::<kind::Frame>(bytes).expect("nonzero frame id")
    }

    #[test]
    fn remote_transport_fragment_bounds_close_against_noise() {
        assert_eq!(REMOTE_CARRIER_FRAGMENT_HEADER_BYTES, 26);
        assert_eq!(1 + 1 + 2 + 16 + 2 + 2 + 2, 26);
        // 65,519 - 14 - 8 - 26 = 65,471
        assert_eq!(NOISE_MAX_PLAINTEXT_BYTES, 65_519);
        assert_eq!(NOISE_RECORD_PAYLOAD_BYTES, 65_505);
        assert_eq!(PEER_SEEN_THROUGH_WATERMARK_BYTES, 8);
        assert_eq!(LANE_FRAGMENT_TOTAL_BYTES, 65_497);
        assert_eq!(REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES, 65_471);
        assert_eq!(
            NOISE_MAX_PLAINTEXT_BYTES
                - NOISE_RECORD_HEADER_BYTES
                - PEER_SEEN_THROUGH_WATERMARK_BYTES
                - REMOTE_CARRIER_FRAGMENT_HEADER_BYTES,
            65_471
        );
        assert_eq!(MAX_FRAGMENT_COUNT, 9);
    }

    #[test]
    fn remote_transport_fragment_maximal_frame_needs_nine_fragments() {
        let frame =
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, frame_id(9), vec![0xAB; 524_288])
                .unwrap();
        let serialized = frame.encode().unwrap();
        assert_eq!(serialized.len(), 524_360);

        let fragments = fragment_frame(RemoteLane::Bulk, frame.frame_id, &serialized).unwrap();
        assert_eq!(fragments.len(), 9);
        for (i, fragment) in fragments.iter().enumerate() {
            assert_eq!(fragment.fragment_index, i as u16);
            assert_eq!(fragment.fragment_count, 9);
            assert_eq!(fragment.lane, RemoteLane::Bulk);
            assert_eq!(fragment.frame_id, frame.frame_id);
            let is_final = i == 8;
            assert_eq!(fragment.flags.is_end(), is_final);
            if !is_final {
                assert_eq!(fragment.bytes.len(), 65_471);
                assert_eq!(fragment.encoded_len(), 65_497);
            }
        }
        // 8 * 65,471 = 523,768; remainder 592.
        assert_eq!(fragments[8].bytes.len(), 524_360 - 8 * 65_471);
        assert_eq!(fragments[8].bytes.len(), 592);

        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let mut out = None;
        for fragment in &fragments {
            let encoded = fragment.encode().unwrap();
            let decoded = RemoteCarrierFragmentV1::decode(&encoded).unwrap();
            assert_eq!(&decoded, fragment);
            if let Some(frame) = reassembler.accept(&decoded, 0).unwrap() {
                out = Some(frame);
            }
        }
        assert_eq!(out.unwrap(), frame);
        assert_eq!(reassembler.incomplete_frames(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);
    }

    #[test]
    fn remote_transport_fragment_single_fragment_frame() {
        let frame =
            RemoteTransportFrameV1::new(RemoteLane::Control, 0, 0, frame_id(1), b"ping".to_vec())
                .unwrap();
        let serialized = frame.encode().unwrap();
        let fragments = fragment_frame(RemoteLane::Control, frame.frame_id, &serialized).unwrap();
        assert_eq!(fragments.len(), 1);
        assert!(fragments[0].flags.is_end());
        assert_eq!(fragments[0].fragment_index, 0);
        assert_eq!(fragments[0].fragment_count, 1);

        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let rebuilt = reassembler.accept(&fragments[0], 0).unwrap().unwrap();
        assert_eq!(rebuilt, frame);
    }

    #[test]
    fn remote_transport_fragment_rejects_bad_shape() {
        let frame =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 0, frame_id(2), vec![1; 100])
                .unwrap();
        let serialized = frame.encode().unwrap();
        let good = fragment_frame(RemoteLane::Interactive, frame.frame_id, &serialized).unwrap()[0]
            .encode()
            .unwrap();

        // Undefined fragment flag bits fail, mirroring the frame rule.
        assert!(RemoteFragmentFlags::from_bits(0x0001).is_some());
        for bad in [0x0002u16, 0x0004, 0x8000, 0xFFFF] {
            assert!(RemoteFragmentFlags::from_bits(bad).is_none(), "{bad:#06x}");
        }
        let mut bad_flags = good.clone();
        bad_flags[2] = 0x00;
        bad_flags[3] = 0x02;
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&bad_flags)
                .unwrap_err()
                .reason,
            RemoteTransportReason::UnknownFlagBit
        );

        // Zero count.
        let mut zero_count = good.clone();
        zero_count[22..24].copy_from_slice(&0u16.to_be_bytes());
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&zero_count)
                .unwrap_err()
                .reason,
            RemoteTransportReason::ZeroFragmentCount
        );

        // Count above 9.
        let mut over_count = good.clone();
        over_count[22..24].copy_from_slice(&10u16.to_be_bytes());
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&over_count)
                .unwrap_err()
                .reason,
            RemoteTransportReason::FragmentCountExceeded
        );

        // Index >= count.
        let mut bad_index = good.clone();
        bad_index[20..22].copy_from_slice(&5u16.to_be_bytes());
        bad_index[22..24].copy_from_slice(&5u16.to_be_bytes());
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&bad_index)
                .unwrap_err()
                .reason,
            RemoteTransportReason::FragmentIndexOutOfRange
        );

        // Trailing bytes and truncation.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&trailing)
                .unwrap_err()
                .reason,
            RemoteTransportReason::TrailingBytes
        );
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&good[..good.len() - 1])
                .unwrap_err()
                .reason,
            RemoteTransportReason::FragmentLengthMismatch
        );
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&good[..25])
                .unwrap_err()
                .reason,
            RemoteTransportReason::HeaderTooShort
        );

        // Version and lane.
        let mut bad_version = good.clone();
        bad_version[0] = 2;
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&bad_version)
                .unwrap_err()
                .reason,
            RemoteTransportReason::UnsupportedVersion
        );
        let mut bad_lane = good.clone();
        bad_lane[1] = 7;
        assert_eq!(
            RemoteCarrierFragmentV1::decode(&bad_lane)
                .unwrap_err()
                .reason,
            RemoteTransportReason::UnknownLane
        );
    }

    #[test]
    fn remote_transport_fragment_end_flag_is_final_only() {
        let frame =
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, frame_id(3), vec![0u8; 200_000])
                .unwrap();
        let serialized = frame.encode().unwrap();
        let fragments = fragment_frame(RemoteLane::Bulk, frame.frame_id, &serialized).unwrap();
        assert_eq!(fragments.len(), 4);

        // END on a non-final fragment fails.
        let mut early_end = fragments[0].clone();
        early_end.flags = RemoteFragmentFlags::end();
        assert_eq!(
            early_end.encode().unwrap_err().reason,
            RemoteTransportReason::FragmentEndFlagMisplaced
        );

        // Missing END on the final fragment fails.
        let mut missing_end = fragments[3].clone();
        missing_end.flags = RemoteFragmentFlags::empty();
        assert_eq!(
            missing_end.encode().unwrap_err().reason,
            RemoteTransportReason::FragmentEndFlagMisplaced
        );
    }

    #[test]
    fn remote_transport_fragment_reassembly_races_and_bounds() {
        let frame =
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, frame_id(4), vec![9u8; 150_000])
                .unwrap();
        let serialized = frame.encode().unwrap();
        let fragments = fragment_frame(RemoteLane::Bulk, frame.frame_id, &serialized).unwrap();
        assert_eq!(fragments.len(), 3);

        // Exact duplicate is idempotent.
        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        assert!(reassembler.accept(&fragments[0], 0).unwrap().is_none());
        assert!(reassembler.accept(&fragments[0], 0).unwrap().is_none());
        assert_eq!(reassembler.incomplete_frames(), 1);

        // A conflicting duplicate closes the stream.
        let mut conflicting = fragments[0].clone();
        conflicting.bytes[0] ^= 0xFF;
        assert_eq!(
            reassembler.accept(&conflicting, 0).unwrap_err().reason,
            RemoteTransportReason::FragmentConflict
        );

        // A differing fragment count for the same frame id conflicts.
        let mut wrong_count = fragments[1].clone();
        wrong_count.fragment_count = 2;
        wrong_count.fragment_index = 1;
        wrong_count.flags = RemoteFragmentFlags::end();
        assert_eq!(
            reassembler.accept(&wrong_count, 0).unwrap_err().reason,
            RemoteTransportReason::FragmentConflict
        );

        // Incomplete state expires at the injected 5-second deadline.
        assert_eq!(reassembler.incomplete_frames(), 1);
        assert_eq!(reassembler.expire(4_999), 0);
        assert_eq!(reassembler.incomplete_frames(), 1);
        assert_eq!(reassembler.expire(5_000), 1);
        assert_eq!(reassembler.incomplete_frames(), 0);
        assert_eq!(reassembler.buffered_bytes(), 0);

        // 16 incomplete frames per peer is the ceiling.
        let mut bounded = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        for i in 0..MAX_INCOMPLETE_FRAMES_PER_PEER {
            let id = frame_id(100 + i as u8);
            let f = RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, id, vec![1u8; 150_000])
                .unwrap();
            let parts = fragment_frame(RemoteLane::Bulk, id, &f.encode().unwrap()).unwrap();
            assert!(bounded.accept(&parts[0], 0).unwrap().is_none());
        }
        assert_eq!(bounded.incomplete_frames(), MAX_INCOMPLETE_FRAMES_PER_PEER);
        let overflow_id = frame_id(200);
        let overflow =
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, overflow_id, vec![2u8; 150_000])
                .unwrap();
        let overflow_parts =
            fragment_frame(RemoteLane::Bulk, overflow_id, &overflow.encode().unwrap()).unwrap();
        assert_eq!(
            bounded.accept(&overflow_parts[0], 0).unwrap_err().reason,
            RemoteTransportReason::ReassemblyFrameLimit
        );

        // The 8 MiB per-peer reassembly budget is enforced.
        assert_eq!(MAX_REASSEMBLY_BYTES_PER_PEER, 8 * 1024 * 1024);
        let mut tight = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        tight.max_bytes = 65_471;
        let big_id = frame_id(210);
        let big = RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, big_id, vec![3u8; 150_000])
            .unwrap();
        let big_parts = fragment_frame(RemoteLane::Bulk, big_id, &big.encode().unwrap()).unwrap();
        assert!(tight.accept(&big_parts[0], 0).unwrap().is_none());
        assert_eq!(
            tight.accept(&big_parts[1], 0).unwrap_err().reason,
            RemoteTransportReason::ReassemblyByteLimit
        );
    }

    #[test]
    fn remote_transport_fragment_reassembly_validates_digest_before_dispatch() {
        let frame = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            2,
            0,
            frame_id(5),
            vec![4u8; 80_000],
        )
        .unwrap();
        let mut serialized = frame.encode().unwrap();
        // Corrupt a payload byte but leave the declared digest intact.
        let last = serialized.len() - 1;
        serialized[last] ^= 0xFF;
        assert_ne!(
            payload_digest(&serialized[REMOTE_TRANSPORT_FRAME_HEADER_BYTES..]),
            {
                let mut d = [0u8; 32];
                d.copy_from_slice(&serialized[40..72]);
                d
            }
        );

        let fragments =
            fragment_frame(RemoteLane::Interactive, frame.frame_id, &serialized).unwrap();
        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let mut err = None;
        for fragment in &fragments {
            match reassembler.accept(fragment, 0) {
                Ok(_) => {}
                Err(e) => err = Some(e),
            }
        }
        assert_eq!(err.unwrap().reason, RemoteTransportReason::DigestMismatch);
    }

    #[test]
    fn remote_transport_fragment_fixtures_are_carrier_identical() {
        use crate::remote_transport::lane_io::{RemoteCarrierKind, RemoteLaneEndpoint};

        let frame =
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 7, frame_id(6), vec![0x5A; 70_000])
                .unwrap()
                .with_flags(RemoteFrameFlags::from_bits(RemoteFrameFlags::END_STREAM).unwrap());
        let serialized = frame.encode().unwrap();
        let fragments = fragment_frame(RemoteLane::Bulk, frame.frame_id, &serialized).unwrap();

        // Drive the fragments through the two *different* carrier encoders, not
        // the same one twice: the fallback prefixes the 8-byte watermark and
        // WebRTC does not, so a carrier that altered fragment bytes or applied
        // its own cap would show up here.
        let mut webrtc_endpoint = RemoteLaneEndpoint::new(RemoteCarrierKind::WebRtcDataChannel);
        let mut fallback_endpoint = RemoteLaneEndpoint::new(RemoteCarrierKind::WebSocketFallback);
        webrtc_endpoint.set_peer_seen_through(0);
        fallback_endpoint.set_peer_seen_through(0xDEAD_BEEF);

        let webrtc_records: Vec<Vec<u8>> = fragments
            .iter()
            .map(|f| webrtc_endpoint.encode_record(f).unwrap())
            .collect();
        let fallback_records: Vec<Vec<u8>> = fragments
            .iter()
            .map(|f| fallback_endpoint.encode_record(f).unwrap())
            .collect();

        // The carriers genuinely differ on the wire...
        assert_ne!(
            webrtc_records, fallback_records,
            "the two carriers must not be the same encoder"
        );
        for (webrtc, fallback) in webrtc_records.iter().zip(&fallback_records) {
            assert_eq!(
                fallback.len(),
                webrtc.len() + PEER_SEEN_THROUGH_WATERMARK_BYTES
            );
        }

        // ...yet the fragment bytes each one carries are byte-identical, and
        // match the canonical fragment encoding exactly.
        let canonical: Vec<Vec<u8>> = fragments.iter().map(|f| f.encode().unwrap()).collect();
        let from_webrtc: Vec<Vec<u8>> = webrtc_records
            .iter()
            .map(|r| webrtc_endpoint.decode_record(r).unwrap())
            .collect();
        let from_fallback: Vec<Vec<u8>> = fallback_records
            .iter()
            .map(|r| fallback_endpoint.decode_record(r).unwrap())
            .collect();
        assert_eq!(from_webrtc, canonical);
        assert_eq!(from_fallback, canonical);
        assert_eq!(from_webrtc, from_fallback);

        // Every complete fragment fits the shared 65,497-byte carrier budget on
        // both carriers, watermark reservation included.
        for encoded in &canonical {
            assert!(encoded.len() <= LANE_FRAGMENT_TOTAL_BYTES);
        }
        for record in &fallback_records {
            assert!(record.len() <= LANE_FRAGMENT_TOTAL_BYTES + PEER_SEEN_THROUGH_WATERMARK_BYTES);
        }
    }

    /// Reassembly is the only door a frame can walk through, so stream
    /// ownership and per-stream sequence are enforced there — not left to a
    /// caller who might forget.
    /// A live lower-id stream must survive a higher-id stream closing while its
    /// own first frame is still being reassembled.
    ///
    /// This drives the **real** path: stream 4's first frame is genuinely
    /// fragmented and only partly delivered, so stream 4 has no sequence entry
    /// yet; stream 6's small terminal frame completes and closes first. A
    /// retirement rule that retires "everything at or below the highest closed
    /// id" drops stream 4 here. Calling `RemoteStreamSequences::accept`
    /// directly cannot reproduce this ordering, which is exactly why the
    /// earlier unit test could not catch it.
    #[test]
    fn remote_transport_fragment_live_stream_survives_higher_id_close() {
        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);

        // Stream 4: a large first frame that needs several fragments.
        let big_id = frame_id(120);
        let big =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 4, 0, big_id, vec![0xA5; 200_000])
                .unwrap();
        let big_fragments =
            fragment_frame(RemoteLane::Interactive, big_id, &big.encode().unwrap()).unwrap();
        assert!(
            big_fragments.len() > 1,
            "the interleaving needs a genuinely fragmented frame"
        );

        // Deliver everything except the final fragment: stream 4 is in flight
        // but has not yet reached the sequence tracker.
        for fragment in &big_fragments[..big_fragments.len() - 1] {
            assert!(reassembler.accept(fragment, 0).unwrap().is_none());
        }

        // Stream 6: a small terminal frame that completes and closes first.
        let small_id = frame_id(130);
        let small =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 6, 0, small_id, vec![0x5A; 32])
                .unwrap()
                .with_flags(RemoteFrameFlags::from_bits(RemoteFrameFlags::END_STREAM).unwrap());
        let small_fragments =
            fragment_frame(RemoteLane::Interactive, small_id, &small.encode().unwrap()).unwrap();
        assert_eq!(small_fragments.len(), 1);
        assert!(
            reassembler
                .accept(&small_fragments[0], 0)
                .unwrap()
                .is_some(),
            "stream 6 completes and closes while stream 4 is mid-reassembly"
        );

        // Stream 4 now finishes. It must be dispatched, not retired.
        let completed = reassembler
            .accept(big_fragments.last().unwrap(), 0)
            .expect("a live lower-id stream must not be retired by a higher-id close");
        assert_eq!(completed, Some(big));

        // Stream 6 is still genuinely retired. Proven with a frame id that was
        // never dispatched, so it cannot be in the retention memory and this
        // exercises stream retirement alone — replaying stream 6's
        // own terminal frame would instead hit frame-id retention and be
        // idempotently dropped, which is a different mechanism proven by
        // `remote_transport_fragment_frame_ids_are_unique_for_the_retention_window`.
        // Keeping the two apart is deliberate: a test that passes only because
        // two mechanisms compose cannot tell you which one broke.
        let reborn = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            6,
            0,
            frame_id(131),
            vec![0x11; 32],
        )
        .unwrap();
        let reborn_fragments = fragment_frame(
            RemoteLane::Interactive,
            reborn.frame_id,
            &reborn.encode().unwrap(),
        )
        .unwrap();
        assert_eq!(
            reassembler
                .accept(&reborn_fragments[0], 0)
                .unwrap_err()
                .reason,
            RemoteTransportReason::StreamClosed,
            "a retired stream id must stay retired"
        );
    }

    /// A frame id must stay unique for the retention window.
    ///
    /// This is the *frame-id* mechanism only. Stream retirement is a separate
    /// property with its own test
    /// (`remote_transport_fragment_live_stream_survives_higher_id_close`); the
    /// two are deliberately never asserted through one another.
    ///
    /// The reviewer's scenario exactly: the same id on stream 2 seq 0 and then
    /// stream 2 seq 1. Per-stream sequencing is satisfied by both (0 then 1),
    /// so nothing but frame-id retention can catch the second one.
    #[test]
    fn remote_transport_fragment_frame_ids_are_unique_for_the_retention_window() {
        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let reused = frame_id(140);

        let first =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 0, reused, vec![1u8; 48])
                .unwrap();
        let first_fragments =
            fragment_frame(RemoteLane::Interactive, reused, &first.encode().unwrap()).unwrap();
        assert_eq!(
            reassembler.accept(&first_fragments[0], 0).unwrap(),
            Some(first.clone())
        );
        assert_eq!(reassembler.remembered_frames(), 1);

        // Same id, next sequence number: the sequence rule is satisfied, so
        // only the retention window stands between this and a second dispatch.
        let reuse =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 1, reused, vec![2u8; 48])
                .unwrap();
        let reuse_fragments =
            fragment_frame(RemoteLane::Interactive, reused, &reuse.encode().unwrap()).unwrap();
        assert_eq!(
            reassembler
                .accept(&reuse_fragments[0], 0)
                .unwrap_err()
                .reason,
            RemoteTransportReason::FragmentConflict,
            "a reused frame id must not dispatch a second frame"
        );

        // A byte-identical retry is idempotent: permitted, but non-dispatching.
        assert_eq!(reassembler.accept(&first_fragments[0], 0).unwrap(), None);

        // A different id on the next sequence is of course fine.
        let next = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            2,
            1,
            frame_id(141),
            vec![3u8; 48],
        )
        .unwrap();
        let next_fragments = fragment_frame(
            RemoteLane::Interactive,
            next.frame_id,
            &next.encode().unwrap(),
        )
        .unwrap();
        assert!(reassembler.accept(&next_fragments[0], 0).unwrap().is_some());

        // The memory is bounded and drains on the same deadline as reassembly.
        assert!(reassembler.remembered_frames() <= MAX_COMPLETED_FRAME_MEMORY);
        reassembler.expire(REASSEMBLY_DEADLINE_MS);
        assert_eq!(
            reassembler.remembered_frames(),
            0,
            "retention must not outlive its window"
        );
    }

    #[test]
    fn remote_transport_fragment_reassembly_enforces_stream_rules() {
        fn deliver(
            reassembler: &mut RemoteFragmentReassembler,
            frame: &RemoteTransportFrameV1,
        ) -> RemoteTransportResult<Option<RemoteTransportFrameV1>> {
            let serialized = frame.encode().unwrap();
            let fragments = fragment_frame(frame.lane, frame.frame_id, &serialized).unwrap();
            let mut out = None;
            for fragment in &fragments {
                out = reassembler.accept(fragment, 0)?;
            }
            Ok(out)
        }

        // A client peer may not ride a daemon-parity (odd) stream.
        let mut from_client = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        assert_eq!(from_client.peer_origin(), RemoteStreamOrigin::Client);
        let daemon_owned =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 1, 0, frame_id(20), vec![1; 32])
                .unwrap();
        assert_eq!(
            deliver(&mut from_client, &daemon_owned).unwrap_err().reason,
            RemoteTransportReason::StreamParityViolation
        );

        // Stream 0 is control-only: a digest-valid interactive frame on it fails.
        let mut zero = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let control_stream_abuse =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 0, 0, frame_id(21), vec![2; 32])
                .unwrap();
        assert_eq!(
            deliver(&mut zero, &control_stream_abuse)
                .unwrap_err()
                .reason,
            RemoteTransportReason::ZeroStreamId
        );

        // A first frame must start at sequence 0.
        let mut gap = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let seven =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 7, frame_id(22), vec![3; 32])
                .unwrap();
        assert_eq!(
            deliver(&mut gap, &seven).unwrap_err().reason,
            RemoteTransportReason::SequenceGap
        );

        // Sequences increment by exactly one, and never go backwards.
        let mut ordered = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        for seq in 0..3u64 {
            let frame = RemoteTransportFrameV1::new(
                RemoteLane::Interactive,
                2,
                seq,
                frame_id(30 + seq as u8),
                vec![4; 32],
            )
            .unwrap();
            assert!(deliver(&mut ordered, &frame).unwrap().is_some());
        }
        assert_eq!(ordered.tracked_streams(), 1);
        let replay =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 1, frame_id(40), vec![5; 32])
                .unwrap();
        assert_eq!(
            deliver(&mut ordered, &replay).unwrap_err().reason,
            RemoteTransportReason::SequenceRegression
        );

        // A terminal frame retires its stream id. The id leaves the active
        // budget, but it can never be used again — so neither the terminal
        // frame nor anything else on that stream can be replayed.
        let mut closing = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let ended =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 0, frame_id(50), vec![6; 32])
                .unwrap()
                .with_flags(RemoteFrameFlags::from_bits(RemoteFrameFlags::END_STREAM).unwrap());
        assert!(deliver(&mut closing, &ended).unwrap().is_some());
        assert_eq!(
            closing.tracked_streams(),
            0,
            "the id leaves the active budget"
        );

        // Replaying the identical terminal frame must NOT dispatch it again.
        // A byte-identical replay is idempotent by contract, so it is accepted
        // and dropped rather than raised as an error; what matters is that it
        // does not produce a second dispatchable frame. The error path for a
        // *different* frame on the retired stream is asserted just below.
        let mut replay_reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        assert!(deliver(&mut replay_reassembler, &ended).unwrap().is_some());
        assert_eq!(
            deliver(&mut replay_reassembler, &ended).unwrap(),
            None,
            "a terminal frame must not dispatch twice"
        );
        // Nor may the retired id be reused for fresh traffic.
        let reused =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 0, frame_id(51), vec![7; 32])
                .unwrap();
        assert_eq!(
            deliver(&mut closing, &reused).unwrap_err().reason,
            RemoteTransportReason::StreamClosed,
            "a retired stream id must never be reused"
        );
        // A higher, never-used id is still perfectly acceptable.
        let fresh =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 4, 0, frame_id(52), vec![7; 32])
                .unwrap();
        assert!(deliver(&mut closing, &fresh).unwrap().is_some());

        // Endlessly opening new streams cannot exhaust memory: the active
        // budget closes the connection instead of growing without bound.
        let mut flooded =
            RemoteFragmentReassembler::new(RemoteStreamOrigin::Client).with_max_active_streams(4);
        for nth in 0..4u64 {
            let stream = client_stream_id(nth).unwrap();
            let frame = RemoteTransportFrameV1::new(
                RemoteLane::Interactive,
                stream,
                0,
                frame_id(70 + nth as u8),
                vec![1; 16],
            )
            .unwrap();
            assert!(
                deliver(&mut flooded, &frame).unwrap().is_some(),
                "stream {stream}"
            );
        }
        assert_eq!(flooded.tracked_streams(), 4);
        let over = client_stream_id(4).unwrap();
        let overflow = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            over,
            0,
            frame_id(80),
            vec![1; 16],
        )
        .unwrap();
        assert_eq!(
            deliver(&mut flooded, &overflow).unwrap_err().reason,
            RemoteTransportReason::StreamLimitExceeded,
            "an unbounded stream flood must be refused, not absorbed"
        );

        // The mirror case: a daemon peer may not claim client-parity streams,
        // but its own odd streams are fine.
        let mut from_daemon = RemoteFragmentReassembler::new(RemoteStreamOrigin::Daemon);
        let client_owned =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 2, 0, frame_id(60), vec![8; 32])
                .unwrap();
        assert_eq!(
            deliver(&mut from_daemon, &client_owned).unwrap_err().reason,
            RemoteTransportReason::StreamParityViolation
        );
        let own =
            RemoteTransportFrameV1::new(RemoteLane::Interactive, 1, 0, frame_id(61), vec![9; 32])
                .unwrap();
        assert!(deliver(&mut from_daemon, &own).unwrap().is_some());
    }
}
