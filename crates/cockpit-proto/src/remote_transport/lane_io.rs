//! The carrier-agnostic lane surface.
//!
//! Application code holds a [`RemoteLaneWriter`] and a [`RemoteLaneReader`] and
//! cannot discover, or branch on, which carrier is underneath: neither trait
//! exposes carrier identity, and both carriers move byte-identical fragments.

use std::collections::VecDeque;

use crate::remote_transport::fragment::{
    LANE_FRAGMENT_TOTAL_BYTES, PEER_SEEN_THROUGH_WATERMARK_BYTES, RemoteCarrierFragmentV1,
};
use crate::remote_transport::lane::{
    RemoteLane, RemoteTransportError, RemoteTransportReason, RemoteTransportResult,
};

/// Explicit writability, sourced from SCTP buffered-amount-low or the socket's
/// writable signal. There is no timer, sleep, or poll interval anywhere.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteWritability {
    Writable,
    BufferFull,
}

/// Which physical carrier a concrete endpoint uses.
///
/// Deliberately **not** reachable through [`RemoteLaneWriter`] or
/// [`RemoteLaneReader`]: it exists for wiring and tests, never for application
/// branching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteCarrierKind {
    WebRtcDataChannel,
    WebSocketFallback,
}

impl RemoteCarrierKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            RemoteCarrierKind::WebRtcDataChannel => "webrtc_data_channel",
            RemoteCarrierKind::WebSocketFallback => "websocket_fallback",
        }
    }

    /// Both carriers reserve the 8-byte `peerSeenThrough` watermark; only the
    /// fallback actually transmits it.
    pub const fn transmits_watermark(self) -> bool {
        matches!(self, RemoteCarrierKind::WebSocketFallback)
    }
}

/// Write side of one lane set.
pub trait RemoteLaneWriter {
    /// Current writability for a lane, from the carrier's own signal.
    fn writability(&self, lane: RemoteLane) -> RemoteWritability;

    /// Enqueue one already-encoded fragment onto a lane.
    ///
    /// Reliable frames are never silently dropped: a full buffer is reported,
    /// not swallowed.
    fn write_fragment(
        &mut self,
        lane: RemoteLane,
        fragment: &RemoteCarrierFragmentV1,
    ) -> RemoteTransportResult<()>;
}

/// Read side of one lane set.
pub trait RemoteLaneReader {
    /// Next fragment available from any lane, in carrier arrival order.
    fn read_fragment(&mut self) -> RemoteTransportResult<Option<RemoteCarrierFragmentV1>>;
}

/// An in-memory carrier used to prove WebRTC/fallback parity.
///
/// The two carriers differ only in whether the 8-byte watermark is transmitted.
/// Because that prefix is reserved on both, the fragment bytes and the total
/// record budget are identical, so application-visible behaviour cannot differ.
#[derive(Debug, Clone)]
pub struct RemoteLaneEndpoint {
    kind: RemoteCarrierKind,
    /// Records as they would appear on the wire, per lane.
    records: [VecDeque<Vec<u8>>; 3],
    /// Arrival order across lanes.
    arrival: VecDeque<RemoteLane>,
    writable: [bool; 3],
    peer_seen_through: u64,
}

impl RemoteLaneEndpoint {
    pub fn new(kind: RemoteCarrierKind) -> Self {
        Self {
            kind,
            records: [VecDeque::new(), VecDeque::new(), VecDeque::new()],
            arrival: VecDeque::new(),
            writable: [true; 3],
            peer_seen_through: 0,
        }
    }

    pub fn kind(&self) -> RemoteCarrierKind {
        self.kind
    }

    pub fn set_writable(&mut self, lane: RemoteLane, writable: bool) {
        self.writable[lane as usize] = writable;
    }

    pub fn set_peer_seen_through(&mut self, watermark: u64) {
        self.peer_seen_through = watermark;
    }

    /// Bytes actually placed on the wire for one fragment.
    pub fn encode_record(
        &self,
        fragment: &RemoteCarrierFragmentV1,
    ) -> RemoteTransportResult<Vec<u8>> {
        let payload = fragment.encode()?;
        // Both carriers budget the watermark; only the fallback sends it.
        if payload.len() + PEER_SEEN_THROUGH_WATERMARK_BYTES
            > LANE_FRAGMENT_TOTAL_BYTES + PEER_SEEN_THROUGH_WATERMARK_BYTES
        {
            return Err(RemoteTransportError::with_size(
                RemoteTransportReason::FragmentPayloadCapExceeded,
                fragment.lane,
                payload.len(),
            ));
        }
        if self.kind.transmits_watermark() {
            let mut record = Vec::with_capacity(PEER_SEEN_THROUGH_WATERMARK_BYTES + payload.len());
            record.extend_from_slice(&self.peer_seen_through.to_be_bytes());
            record.extend_from_slice(&payload);
            Ok(record)
        } else {
            Ok(payload)
        }
    }

    /// Strip the carrier framing back to fragment bytes.
    pub fn decode_record(&self, record: &[u8]) -> RemoteTransportResult<Vec<u8>> {
        if self.kind.transmits_watermark() {
            if record.len() < PEER_SEEN_THROUGH_WATERMARK_BYTES {
                return Err(RemoteTransportError::new(
                    RemoteTransportReason::HeaderTooShort,
                ));
            }
            Ok(record[PEER_SEEN_THROUGH_WATERMARK_BYTES..].to_vec())
        } else {
            Ok(record.to_vec())
        }
    }

    /// Move everything this endpoint wrote into `peer`'s read side.
    pub fn deliver_to(&mut self, peer: &mut RemoteLaneEndpoint) -> RemoteTransportResult<()> {
        while let Some(lane) = self.arrival.pop_front() {
            let record = self.records[lane as usize]
                .pop_front()
                .expect("arrival order tracks records");
            let fragment_bytes = self.decode_record(&record)?;
            let reencoded = if peer.kind.transmits_watermark() {
                let mut out =
                    Vec::with_capacity(PEER_SEEN_THROUGH_WATERMARK_BYTES + fragment_bytes.len());
                out.extend_from_slice(&peer.peer_seen_through.to_be_bytes());
                out.extend_from_slice(&fragment_bytes);
                out
            } else {
                fragment_bytes
            };
            peer.records[lane as usize].push_back(reencoded);
            peer.arrival.push_back(lane);
        }
        Ok(())
    }

    pub fn pending_records(&self) -> usize {
        self.arrival.len()
    }
}

impl RemoteLaneWriter for RemoteLaneEndpoint {
    fn writability(&self, lane: RemoteLane) -> RemoteWritability {
        if self.writable[lane as usize] {
            RemoteWritability::Writable
        } else {
            RemoteWritability::BufferFull
        }
    }

    fn write_fragment(
        &mut self,
        lane: RemoteLane,
        fragment: &RemoteCarrierFragmentV1,
    ) -> RemoteTransportResult<()> {
        if fragment.lane != lane {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::UnknownLane,
                lane,
            ));
        }
        // A full buffer is surfaced, never swallowed.
        if !self.writable[lane as usize] {
            return Err(RemoteTransportError::with_lane(
                RemoteTransportReason::QueueByteLimit,
                lane,
            ));
        }
        let record = self.encode_record(fragment)?;
        self.records[lane as usize].push_back(record);
        self.arrival.push_back(lane);
        Ok(())
    }
}

impl RemoteLaneReader for RemoteLaneEndpoint {
    fn read_fragment(&mut self) -> RemoteTransportResult<Option<RemoteCarrierFragmentV1>> {
        let Some(lane) = self.arrival.pop_front() else {
            return Ok(None);
        };
        let record = self.records[lane as usize]
            .pop_front()
            .expect("arrival order tracks records");
        let fragment_bytes = self.decode_record(&record)?;
        RemoteCarrierFragmentV1::decode(&fragment_bytes).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_protocol_id::{RemoteFrameId, kind, tag_protocol_id_bytes};
    use crate::remote_transport::fragment::RemoteFragmentReassembler;
    use crate::remote_transport::frame::{RemoteStreamOrigin, RemoteTransportFrameV1};
    use crate::remote_transport::scheduler::RemoteLaneScheduler;

    fn frame_id(seed: u8) -> RemoteFrameId {
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        tag_protocol_id_bytes::<kind::Frame>(bytes).expect("nonzero frame id")
    }

    /// The multi-lane script both carriers must reproduce identically.
    fn script() -> Vec<RemoteTransportFrameV1> {
        vec![
            RemoteTransportFrameV1::new(RemoteLane::Control, 0, 0, frame_id(1), vec![0xC0; 32])
                .unwrap(),
            RemoteTransportFrameV1::new(
                RemoteLane::Interactive,
                2,
                0,
                frame_id(2),
                vec![0x1A; 4_000],
            )
            .unwrap(),
            // Multi-fragment bulk work on two streams.
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, frame_id(3), vec![0xB1; 200_000])
                .unwrap(),
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 6, 0, frame_id(4), vec![0xB2; 140_000])
                .unwrap(),
            RemoteTransportFrameV1::new(
                RemoteLane::Interactive,
                2,
                1,
                frame_id(5),
                vec![0x1B; 900],
            )
            .unwrap(),
            RemoteTransportFrameV1::new(RemoteLane::Control, 0, 1, frame_id(6), vec![0xC1; 16])
                .unwrap(),
        ]
    }

    /// One frame as the application sees it: lane, stream, payload.
    type DeliveredFrame = (RemoteLane, u64, Vec<u8>);
    /// What one carrier run observed: delivered frames and rendered errors.
    type CarrierObservation = (Vec<DeliveredFrame>, Vec<String>);

    /// Drive the script through one carrier and record what the application sees.
    fn run(kind: RemoteCarrierKind) -> CarrierObservation {
        let mut sender = RemoteLaneEndpoint::new(kind);
        let mut receiver = RemoteLaneEndpoint::new(kind);
        let mut scheduler = RemoteLaneScheduler::default();
        let mut errors = Vec::new();

        for frame in script() {
            match scheduler.enqueue(&frame) {
                crate::remote_transport::scheduler::RemoteQueueOutcome::Enqueued => {}
                other => errors.push(other.error().unwrap().to_string()),
            }
        }
        while let Some(request) = scheduler.next_fragment() {
            if let Err(error) = sender.write_fragment(request.lane, &request.fragment) {
                errors.push(error.to_string());
                // The carrier refused after the scheduler chose: give the
                // fragment back and stop offering that lane until it signals
                // writable again. Nothing is dropped and nothing spins.
                let lane = request.lane;
                scheduler.requeue(request);
                scheduler.set_lane_writable(lane, false);
            }
        }
        sender.deliver_to(&mut receiver).expect("delivery");

        let mut reassembler = RemoteFragmentReassembler::new(RemoteStreamOrigin::Client);
        let mut delivered = Vec::new();
        loop {
            match receiver.read_fragment() {
                Ok(Some(fragment)) => match reassembler.accept(&fragment, 0) {
                    Ok(Some(frame)) => {
                        delivered.push((frame.lane, frame.stream_id, frame.payload));
                    }
                    Ok(None) => {}
                    Err(error) => errors.push(error.to_string()),
                },
                Ok(None) => break,
                Err(error) => {
                    errors.push(error.to_string());
                    break;
                }
            }
        }
        // Deliberately induce one error on each carrier and record it.
        let mut closed = RemoteLaneEndpoint::new(kind);
        closed.set_writable(RemoteLane::Bulk, false);
        let doomed =
            RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 9, frame_id(7), vec![1; 10]).unwrap();
        let fragments = crate::remote_transport::fragment::fragment_frame(
            RemoteLane::Bulk,
            doomed.frame_id,
            &doomed.encode().unwrap(),
        )
        .unwrap();
        if let Err(error) = closed.write_fragment(RemoteLane::Bulk, &fragments[0]) {
            errors.push(error.to_string());
        }
        (delivered, errors)
    }

    #[test]
    fn remote_transport_carrier_parity() {
        let (webrtc_frames, webrtc_errors) = run(RemoteCarrierKind::WebRtcDataChannel);
        let (fallback_frames, fallback_errors) = run(RemoteCarrierKind::WebSocketFallback);

        // Identical application-visible order and content.
        assert_eq!(webrtc_frames.len(), script().len());
        assert_eq!(webrtc_frames, fallback_frames);
        // Identical errors, in identical order.
        assert_eq!(webrtc_errors, fallback_errors);
        assert!(
            !webrtc_errors.is_empty(),
            "the script must exercise a failure"
        );

        // The carriers really are different on the wire: only the fallback
        // transmits the watermark, yet the fragment bytes match exactly.
        let fragment = crate::remote_transport::fragment::fragment_frame(
            RemoteLane::Bulk,
            frame_id(8),
            &RemoteTransportFrameV1::new(RemoteLane::Bulk, 4, 0, frame_id(8), vec![7; 1_000])
                .unwrap()
                .encode()
                .unwrap(),
        )
        .unwrap()[0]
            .clone();
        let webrtc = RemoteLaneEndpoint::new(RemoteCarrierKind::WebRtcDataChannel);
        let fallback = RemoteLaneEndpoint::new(RemoteCarrierKind::WebSocketFallback);
        let webrtc_record = webrtc.encode_record(&fragment).unwrap();
        let fallback_record = fallback.encode_record(&fragment).unwrap();
        assert_eq!(
            fallback_record.len(),
            webrtc_record.len() + PEER_SEEN_THROUGH_WATERMARK_BYTES
        );
        assert_eq!(
            webrtc.decode_record(&webrtc_record).unwrap(),
            fallback.decode_record(&fallback_record).unwrap()
        );
        assert!(!RemoteCarrierKind::WebRtcDataChannel.transmits_watermark());
        assert!(RemoteCarrierKind::WebSocketFallback.transmits_watermark());

        // A cross-carrier hop delivers the same fragment: the substrate is
        // genuinely transport-neutral.
        let mut a = RemoteLaneEndpoint::new(RemoteCarrierKind::WebRtcDataChannel);
        let mut b = RemoteLaneEndpoint::new(RemoteCarrierKind::WebSocketFallback);
        a.write_fragment(RemoteLane::Bulk, &fragment).unwrap();
        a.deliver_to(&mut b).unwrap();
        assert_eq!(b.read_fragment().unwrap().unwrap(), fragment);
    }

    #[test]
    fn remote_transport_lane_surface_hides_the_carrier() {
        // The trait objects expose writability and fragments — nothing that
        // identifies the carrier, so application code cannot branch on it.
        let mut endpoints: Vec<Box<dyn RemoteLaneWriter>> = vec![
            Box::new(RemoteLaneEndpoint::new(
                RemoteCarrierKind::WebRtcDataChannel,
            )),
            Box::new(RemoteLaneEndpoint::new(
                RemoteCarrierKind::WebSocketFallback,
            )),
        ];
        for writer in &mut endpoints {
            assert_eq!(
                writer.writability(RemoteLane::Control),
                RemoteWritability::Writable
            );
        }
        // A full buffer is reported identically by both.
        let mut webrtc = RemoteLaneEndpoint::new(RemoteCarrierKind::WebRtcDataChannel);
        let mut fallback = RemoteLaneEndpoint::new(RemoteCarrierKind::WebSocketFallback);
        webrtc.set_writable(RemoteLane::Interactive, false);
        fallback.set_writable(RemoteLane::Interactive, false);
        assert_eq!(
            webrtc.writability(RemoteLane::Interactive),
            fallback.writability(RemoteLane::Interactive)
        );
        assert_eq!(
            webrtc.writability(RemoteLane::Interactive),
            RemoteWritability::BufferFull
        );
    }
}
