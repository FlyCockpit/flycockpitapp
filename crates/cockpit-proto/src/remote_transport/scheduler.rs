//! Queue limits and deterministic lane scheduling.
//!
//! The scheduler is pure: it owns queues and a cursor, takes explicit enqueue
//! and writability inputs, and returns explicit actions. It never sleeps, never
//! polls, and never drops a reliable frame silently — every rejection is a
//! typed outcome the caller must handle.

use std::collections::{BTreeMap, VecDeque};

use crate::remote_transport::fragment::{
    REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES, RemoteCarrierFragmentV1, fragment_frame,
};
use crate::remote_transport::frame::RemoteTransportFrameV1;
use crate::remote_transport::lane::{
    REMOTE_LANE_COUNT, RemoteLane, RemoteTransportError, RemoteTransportReason,
};

/// The repeating eligible-lane schedule. Empty (or unwritable) slots are
/// skipped and cannot be banked.
pub const LANE_SCHEDULE: [RemoteLane; 8] = [
    RemoteLane::Control,
    RemoteLane::Interactive,
    RemoteLane::Control,
    RemoteLane::Bulk,
    RemoteLane::Interactive,
    RemoteLane::Control,
    RemoteLane::Interactive,
    RemoteLane::Bulk,
];

/// Deficit round robin quantum. Set to the maximum fragment payload so each
/// ready stream receives exactly one fragment per visit.
pub const DRR_QUANTUM_BYTES: usize = REMOTE_CARRIER_FRAGMENT_MAX_PAYLOAD_BYTES;

/// Exact queue limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteQueueLimits {
    pub control_frames: usize,
    pub control_bytes: usize,
    pub interactive_frames: usize,
    pub interactive_bytes: usize,
    pub bulk_frames: usize,
    pub bulk_bytes: usize,
    pub aggregate_bytes: usize,
    /// Aggregate space reserved for control and unavailable to other lanes.
    pub control_reserved_bytes: usize,
    pub control_reserved_frames: usize,
    /// Aggregate space reserved for interactive.
    pub interactive_reserved_bytes: usize,
}

/// The control reservation must be *deliverable*: the lane's own caps cannot
/// undercut what the aggregate promises it, or the reservation would be a
/// number nothing could honour.
const _: () = assert!(
    RemoteQueueLimits::DEFAULT.control_frames >= RemoteQueueLimits::DEFAULT.control_reserved_frames
);
const _: () = assert!(
    RemoteQueueLimits::DEFAULT.control_reserved_bytes <= RemoteQueueLimits::DEFAULT.control_bytes
);
/// Reservations cannot exceed the aggregate they are carved out of.
const _: () = assert!(
    RemoteQueueLimits::DEFAULT.control_reserved_bytes
        + RemoteQueueLimits::DEFAULT.interactive_reserved_bytes
        <= RemoteQueueLimits::DEFAULT.aggregate_bytes
);

impl RemoteQueueLimits {
    pub const DEFAULT: RemoteQueueLimits = RemoteQueueLimits {
        control_frames: 256,
        control_bytes: 2 * 1024 * 1024,
        interactive_frames: 512,
        interactive_bytes: 8 * 1024 * 1024,
        bulk_frames: 128,
        bulk_bytes: 8 * 1024 * 1024,
        aggregate_bytes: 16 * 1024 * 1024,
        control_reserved_bytes: 1024 * 1024,
        control_reserved_frames: 32,
        interactive_reserved_bytes: 2 * 1024 * 1024,
    };

    pub const fn frames_for(&self, lane: RemoteLane) -> usize {
        match lane {
            RemoteLane::Control => self.control_frames,
            RemoteLane::Interactive => self.interactive_frames,
            RemoteLane::Bulk => self.bulk_frames,
        }
    }

    pub const fn bytes_for(&self, lane: RemoteLane) -> usize {
        match lane {
            RemoteLane::Control => self.control_bytes,
            RemoteLane::Interactive => self.interactive_bytes,
            RemoteLane::Bulk => self.bulk_bytes,
        }
    }

    /// Aggregate bytes reserved for a lane and unavailable to the others.
    pub const fn reserved_bytes_for(&self, lane: RemoteLane) -> usize {
        match lane {
            RemoteLane::Control => self.control_reserved_bytes,
            RemoteLane::Interactive => self.interactive_reserved_bytes,
            RemoteLane::Bulk => 0,
        }
    }

    /// Aggregate bytes any lane may draw from after reservations.
    pub const fn shared_pool_bytes(&self) -> usize {
        self.aggregate_bytes - self.control_reserved_bytes - self.interactive_reserved_bytes
    }
}

impl Default for RemoteQueueLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// What happened to an enqueue attempt.
///
/// The three failure shapes are deliberately distinct: bulk is rejected first,
/// interactive producers are told to backpressure, and control over its own cap
/// closes the offending stream or connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteQueueOutcome {
    Enqueued,
    /// Bulk only. The producer must retry later; nothing was dropped silently.
    Rejected(RemoteTransportError),
    /// Interactive only. Stop producing until the queue drains.
    Backpressure(RemoteTransportError),
    /// Control only. A control flood closes the offending stream/connection.
    CloseStream(RemoteTransportError),
}

impl RemoteQueueOutcome {
    pub fn is_enqueued(self) -> bool {
        matches!(self, RemoteQueueOutcome::Enqueued)
    }

    pub fn error(self) -> Option<RemoteTransportError> {
        match self {
            RemoteQueueOutcome::Enqueued => None,
            RemoteQueueOutcome::Rejected(e)
            | RemoteQueueOutcome::Backpressure(e)
            | RemoteQueueOutcome::CloseStream(e) => Some(e),
        }
    }

    /// Map a limit breach to the outcome shape that lane must produce.
    fn for_lane(lane: RemoteLane, error: RemoteTransportError) -> Self {
        match lane {
            RemoteLane::Bulk => RemoteQueueOutcome::Rejected(error),
            RemoteLane::Interactive => RemoteQueueOutcome::Backpressure(error),
            RemoteLane::Control => RemoteQueueOutcome::CloseStream(error),
        }
    }
}

/// One fragment handed to a carrier, with the lane and stream it belongs to.
///
/// A request is *lent*, not given away: the carrier either accepts it, or hands
/// it back through [`RemoteLaneScheduler::requeue`]. That is what makes "a
/// reliable frame is never silently dropped" true even when a writability edge
/// races the scheduler.
///
/// Deliberately **not** `Clone`. `requeue` consumes the lease by value, so the
/// absence of `Clone` is what makes returning the same lease twice impossible
/// to express: a duplicate would double-restore the frame/byte charge *and*
/// deliver the terminal fragment twice. The type system is the enforcement
/// here — there is no runtime token to check and no way to forget the check.
#[derive(Debug, PartialEq, Eq)]
pub struct RemoteSendRequest {
    pub lane: RemoteLane,
    pub stream_id: u64,
    pub fragment: RemoteCarrierFragmentV1,
    /// Frame bytes this fragment settles, present on the final fragment only.
    ///
    /// Private: only the scheduler may mint or interpret it, so no caller can
    /// forge queue accounting.
    pub(crate) accounted_bytes: Option<usize>,
}

/// A queued fragment plus the frame accounting it settles when it leaves.
///
/// Exactly one fragment per frame — the final one — carries `accounted_bytes`.
/// Whoever removes that fragment, whether a successful send or a cancellation,
/// releases the frame's `frames`/`bytes` charge. There is no second path.
#[derive(Debug, Clone, PartialEq, Eq)]
struct QueuedFragment {
    fragment: RemoteCarrierFragmentV1,
    accounted_bytes: Option<usize>,
}

#[derive(Debug, Clone, Default)]
struct StreamQueue {
    fragments: VecDeque<QueuedFragment>,
    deficit: usize,
}

#[derive(Debug, Clone, Default)]
struct LaneQueue {
    streams: BTreeMap<u64, StreamQueue>,
    /// Round-robin order over ready streams.
    order: VecDeque<u64>,
    frames: usize,
    bytes: usize,
    writable: bool,
}

/// Deterministic multi-lane scheduler.
pub struct RemoteLaneScheduler {
    limits: RemoteQueueLimits,
    lanes: [LaneQueue; REMOTE_LANE_COUNT],
    cursor: usize,
}

impl std::fmt::Debug for RemoteLaneScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Payload-free: counts and the cursor only.
        f.debug_struct("RemoteLaneScheduler")
            .field("cursor", &self.cursor)
            .field(
                "queued_frames",
                &RemoteLane::ALL.map(|lane| self.lanes[lane as usize].frames),
            )
            .finish()
    }
}

impl Default for RemoteLaneScheduler {
    fn default() -> Self {
        Self::new(RemoteQueueLimits::DEFAULT)
    }
}

impl RemoteLaneScheduler {
    pub fn new(limits: RemoteQueueLimits) -> Self {
        let lanes = [
            LaneQueue {
                writable: true,
                ..LaneQueue::default()
            },
            LaneQueue {
                writable: true,
                ..LaneQueue::default()
            },
            LaneQueue {
                writable: true,
                ..LaneQueue::default()
            },
        ];
        Self {
            limits,
            lanes,
            cursor: 0,
        }
    }

    pub fn limits(&self) -> RemoteQueueLimits {
        self.limits
    }

    pub fn queued_frames(&self, lane: RemoteLane) -> usize {
        self.lanes[lane as usize].frames
    }

    pub fn queued_bytes(&self, lane: RemoteLane) -> usize {
        self.lanes[lane as usize].bytes
    }

    pub fn aggregate_bytes(&self) -> usize {
        RemoteLane::ALL
            .iter()
            .map(|lane| self.lanes[*lane as usize].bytes)
            .sum()
    }

    /// Bytes drawn from the shared pool: usage above each lane's reservation.
    fn shared_usage(&self) -> usize {
        RemoteLane::ALL
            .iter()
            .map(|lane| {
                self.lanes[*lane as usize]
                    .bytes
                    .saturating_sub(self.limits.reserved_bytes_for(*lane))
            })
            .sum()
    }

    /// Explicit writability signal from the carrier (SCTP buffered-amount-low
    /// or socket-writable). There is no polling and no timer anywhere here.
    pub fn set_lane_writable(&mut self, lane: RemoteLane, writable: bool) {
        self.lanes[lane as usize].writable = writable;
    }

    pub fn is_lane_writable(&self, lane: RemoteLane) -> bool {
        self.lanes[lane as usize].writable
    }

    /// Queue a logical frame, fragmenting it for the carrier.
    ///
    /// The lane comes from the frame (and therefore from classification); there
    /// is no lane or priority argument a peer could influence.
    pub fn enqueue(&mut self, frame: &RemoteTransportFrameV1) -> RemoteQueueOutcome {
        let lane = frame.lane;
        let size = frame.serialized_len();

        // Per-lane frame cap.
        if self.lanes[lane as usize].frames + 1 > self.limits.frames_for(lane) {
            return RemoteQueueOutcome::for_lane(
                lane,
                RemoteTransportError::with_lane(
                    if lane == RemoteLane::Control {
                        RemoteTransportReason::ControlQueueOverflow
                    } else {
                        RemoteTransportReason::QueueFrameLimit
                    },
                    lane,
                ),
            );
        }
        // Per-lane byte cap.
        if self.lanes[lane as usize].bytes + size > self.limits.bytes_for(lane) {
            return RemoteQueueOutcome::for_lane(
                lane,
                RemoteTransportError::with_size(
                    if lane == RemoteLane::Control {
                        RemoteTransportReason::ControlQueueOverflow
                    } else {
                        RemoteTransportReason::QueueByteLimit
                    },
                    lane,
                    size,
                ),
            );
        }
        // Aggregate cap, honouring the control and interactive reservations.
        //
        // The control reservation is a *joint* allotment: the reserved bytes
        // back the reserved frames. Once control is holding its reserved frame
        // count it stops drawing on reserved space and competes for the shared
        // pool like any other lane. Without that, `control_reserved_frames`
        // would be inert — the byte half alone would admit an unbounded number
        // of small control frames, and no outcome would ever depend on the
        // frame count.
        let reserved_bytes = if lane == RemoteLane::Control
            && self.lanes[lane as usize].frames >= self.limits.control_reserved_frames
        {
            0
        } else {
            self.limits.reserved_bytes_for(lane)
        };
        let reserved_headroom = reserved_bytes.saturating_sub(self.lanes[lane as usize].bytes);
        let from_shared = size.saturating_sub(reserved_headroom);
        if self.shared_usage() + from_shared > self.limits.shared_pool_bytes() {
            return RemoteQueueOutcome::for_lane(
                lane,
                RemoteTransportError::with_size(
                    RemoteTransportReason::QueueAggregateLimit,
                    lane,
                    size,
                ),
            );
        }

        let serialized = match frame.encode() {
            Ok(bytes) => bytes,
            Err(error) => return RemoteQueueOutcome::for_lane(lane, error),
        };
        let fragments = match fragment_frame(lane, frame.frame_id, &serialized) {
            Ok(fragments) => fragments,
            Err(error) => return RemoteQueueOutcome::for_lane(lane, error),
        };

        let queue = &mut self.lanes[lane as usize];
        let stream = queue.streams.entry(frame.stream_id).or_default();
        let was_empty = stream.fragments.is_empty();
        let last = fragments.len() - 1;
        for (index, fragment) in fragments.into_iter().enumerate() {
            // The final fragment carries this frame's whole accounting charge.
            stream.fragments.push_back(QueuedFragment {
                fragment,
                accounted_bytes: (index == last).then_some(size),
            });
        }
        if was_empty {
            queue.order.push_back(frame.stream_id);
        }
        queue.frames += 1;
        queue.bytes += size;
        RemoteQueueOutcome::Enqueued
    }

    /// Pop the next fragment to write, following the fixed lane schedule.
    ///
    /// Returns `None` only when nothing is both queued and writable.
    pub fn next_fragment(&mut self) -> Option<RemoteSendRequest> {
        // Examine each slot at most once. Advancing the cursor on a skipped
        // slot is what stops an idle lane from banking its turn.
        for _ in 0..LANE_SCHEDULE.len() {
            let lane = LANE_SCHEDULE[self.cursor];
            self.cursor = (self.cursor + 1) % LANE_SCHEDULE.len();
            if let Some(request) = self.pop_from_lane(lane) {
                return Some(request);
            }
        }
        None
    }

    fn pop_from_lane(&mut self, lane: RemoteLane) -> Option<RemoteSendRequest> {
        let queue = &mut self.lanes[lane as usize];
        if !queue.writable || queue.order.is_empty() {
            return None;
        }
        // Deficit round robin. The quantum equals the maximum fragment payload,
        // so a ready stream always clears exactly one fragment per visit.
        let stream_id = queue.order.pop_front()?;
        let stream = queue.streams.get_mut(&stream_id)?;
        stream.deficit += DRR_QUANTUM_BYTES;
        let queued = stream.fragments.pop_front()?;
        stream.deficit = stream.deficit.saturating_sub(queued.fragment.bytes.len());
        let drained = stream.fragments.is_empty();
        if drained {
            stream.deficit = 0;
            queue.streams.remove(&stream_id);
        } else {
            // Back of the line: every ready stream gets one visit per round.
            queue.order.push_back(stream_id);
        }
        // The final fragment settles the whole frame's frame/byte charge, so a
        // fully drained lane always reads back as exactly zero.
        if let Some(bytes) = queued.accounted_bytes {
            queue.frames = queue.frames.saturating_sub(1);
            queue.bytes = queue.bytes.saturating_sub(bytes);
        }
        Some(RemoteSendRequest {
            lane,
            stream_id,
            fragment: queued.fragment,
            accounted_bytes: queued.accounted_bytes,
        })
    }

    /// Hand back a fragment the carrier refused, restoring queue state exactly.
    ///
    /// `next_fragment` chooses under the writability the carrier last reported;
    /// that signal can go stale between the choice and the write. Without this,
    /// the refused fragment would be gone — a silent drop on a reliable lane.
    /// The fragment returns to the head of its stream and the stream to the head
    /// of its lane, so the retry is the very next thing that lane emits.
    pub fn requeue(&mut self, request: RemoteSendRequest) {
        let RemoteSendRequest {
            lane,
            stream_id,
            fragment,
            accounted_bytes,
        } = request;
        let queue = &mut self.lanes[lane as usize];
        if let Some(bytes) = accounted_bytes {
            queue.frames += 1;
            queue.bytes += bytes;
        }
        let stream = queue.streams.entry(stream_id).or_default();
        stream.fragments.push_front(QueuedFragment {
            fragment,
            accounted_bytes,
        });
        queue.order.retain(|id| *id != stream_id);
        queue.order.push_front(stream_id);
    }

    /// Drop everything queued for a stream (cancellation / reset).
    ///
    /// Cancellation is a *bounded* cleanup: every frame whose final fragment is
    /// still queued releases its frame and byte charge, so capacity a cancelled
    /// stream held becomes immediately reusable instead of leaking until the
    /// connection dies.
    pub fn close_stream(&mut self, lane: RemoteLane, stream_id: u64) {
        let queue = &mut self.lanes[lane as usize];
        if let Some(stream) = queue.streams.remove(&stream_id) {
            for queued in stream.fragments {
                if let Some(bytes) = queued.accounted_bytes {
                    queue.frames = queue.frames.saturating_sub(1);
                    queue.bytes = queue.bytes.saturating_sub(bytes);
                }
            }
        }
        queue.order.retain(|id| *id != stream_id);
    }

    pub fn has_pending(&self) -> bool {
        RemoteLane::ALL
            .iter()
            .any(|lane| !self.lanes[*lane as usize].order.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_protocol_id::{RemoteFrameId, kind, tag_protocol_id_bytes};

    fn frame_id(seed: u8) -> RemoteFrameId {
        let mut bytes = [0u8; 16];
        for (i, slot) in bytes.iter_mut().enumerate() {
            *slot = seed.wrapping_add(i as u8).wrapping_add(1);
        }
        tag_protocol_id_bytes::<kind::Frame>(bytes).expect("nonzero frame id")
    }

    fn frame(
        lane: RemoteLane,
        stream: u64,
        seq: u64,
        seed: u8,
        size: usize,
    ) -> RemoteTransportFrameV1 {
        RemoteTransportFrameV1::new(lane, stream, seq, frame_id(seed), vec![seed; size]).unwrap()
    }

    #[test]
    fn remote_transport_scheduler_trace() {
        assert_eq!(
            LANE_SCHEDULE,
            [
                RemoteLane::Control,
                RemoteLane::Interactive,
                RemoteLane::Control,
                RemoteLane::Bulk,
                RemoteLane::Interactive,
                RemoteLane::Control,
                RemoteLane::Interactive,
                RemoteLane::Bulk,
            ]
        );
        // Slot shares: 3 control, 3 interactive, 2 bulk.
        assert_eq!(
            LANE_SCHEDULE
                .iter()
                .filter(|l| **l == RemoteLane::Control)
                .count(),
            3
        );
        assert_eq!(
            LANE_SCHEDULE
                .iter()
                .filter(|l| **l == RemoteLane::Interactive)
                .count(),
            3
        );
        assert_eq!(
            LANE_SCHEDULE
                .iter()
                .filter(|l| **l == RemoteLane::Bulk)
                .count(),
            2
        );

        // --- every lane busy: the trace is exactly C,I,C,B,I,C,I,B ----------
        let mut scheduler = RemoteLaneScheduler::default();
        for i in 0..8u8 {
            assert!(
                scheduler
                    .enqueue(&frame(RemoteLane::Control, 0, i as u64, i, 8))
                    .is_enqueued()
            );
            assert!(
                scheduler
                    .enqueue(&frame(RemoteLane::Interactive, 2, i as u64, 40 + i, 8))
                    .is_enqueued()
            );
            assert!(
                scheduler
                    .enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 80 + i, 8))
                    .is_enqueued()
            );
        }
        let trace: Vec<RemoteLane> = (0..8)
            .map(|_| scheduler.next_fragment().unwrap().lane)
            .collect();
        assert_eq!(trace, LANE_SCHEDULE.to_vec());
        // The schedule repeats.
        let trace2: Vec<RemoteLane> = (0..8)
            .map(|_| scheduler.next_fragment().unwrap().lane)
            .collect();
        assert_eq!(trace2, LANE_SCHEDULE.to_vec());

        // --- empty slots are skipped and cannot be banked -------------------
        let mut sparse = RemoteLaneScheduler::default();
        // Only bulk has work. Its two slots are used; the six empty control and
        // interactive slots are skipped, not accumulated.
        for i in 0..4u8 {
            assert!(
                sparse
                    .enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 90 + i, 8))
                    .is_enqueued()
            );
        }
        let bulk_trace: Vec<RemoteLane> = (0..4)
            .map(|_| sparse.next_fragment().unwrap().lane)
            .collect();
        assert_eq!(bulk_trace, vec![RemoteLane::Bulk; 4]);

        // After the idle period, control does not get six banked turns: it
        // takes its next scheduled slot and no more.
        let mut banked = RemoteLaneScheduler::default();
        for i in 0..4u8 {
            assert!(
                banked
                    .enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 120 + i, 8))
                    .is_enqueued()
            );
        }
        // Two bulk fragments drain while control is idle.
        assert_eq!(banked.next_fragment().unwrap().lane, RemoteLane::Bulk);
        assert_eq!(banked.next_fragment().unwrap().lane, RemoteLane::Bulk);
        // Control now has work; it receives single slots in schedule order.
        for i in 0..4u8 {
            assert!(
                banked
                    .enqueue(&frame(RemoteLane::Control, 0, i as u64, 140 + i, 8))
                    .is_enqueued()
            );
        }
        let mixed: Vec<RemoteLane> = (0..4)
            .map(|_| banked.next_fragment().unwrap().lane)
            .collect();
        // Interleaved, never four control in a row.
        assert!(mixed.iter().filter(|l| **l == RemoteLane::Control).count() <= 3);
        assert!(mixed.contains(&RemoteLane::Bulk));

        // --- per-stream fairness within a lane ------------------------------
        let mut fair = RemoteLaneScheduler::default();
        // Three interactive streams, three frames each.
        for stream in [2u64, 4, 6] {
            for i in 0..3u8 {
                assert!(
                    fair.enqueue(&frame(
                        RemoteLane::Interactive,
                        stream,
                        i as u64,
                        (stream as u8) * 10 + i,
                        8
                    ))
                    .is_enqueued()
                );
            }
        }
        let mut order = Vec::new();
        while let Some(request) = fair.next_fragment() {
            if request.lane == RemoteLane::Interactive {
                order.push(request.stream_id);
            }
        }
        assert_eq!(order.len(), 9);
        // Each stream receives one fragment per visit: strict rotation.
        assert_eq!(&order[..3], &[2, 4, 6]);
        assert_eq!(&order[3..6], &[2, 4, 6]);
        assert_eq!(&order[6..], &[2, 4, 6]);

        // --- control keeps progressing under a bulk flood -------------------
        let mut flooded = RemoteLaneScheduler::default();
        // Saturate bulk with large frames.
        for i in 0..16u8 {
            let _ = flooded.enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 160 + i, 400_000));
        }
        assert!(
            flooded
                .enqueue(&frame(RemoteLane::Control, 0, 0, 250, 16))
                .is_enqueued()
        );
        // Control appears within one full rotation, ahead of most bulk work.
        let mut seen_control_at = None;
        for step in 0..8 {
            if flooded.next_fragment().unwrap().lane == RemoteLane::Control {
                seen_control_at = Some(step);
                break;
            }
        }
        assert!(
            seen_control_at.is_some_and(|step| step < 3),
            "control must not queue behind a bulk flood"
        );

        // --- unwritable lanes are skipped like empty ones -------------------
        let mut gated = RemoteLaneScheduler::default();
        for i in 0..2u8 {
            assert!(
                gated
                    .enqueue(&frame(RemoteLane::Control, 0, i as u64, 200 + i, 8))
                    .is_enqueued()
            );
            assert!(
                gated
                    .enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 220 + i, 8))
                    .is_enqueued()
            );
        }
        gated.set_lane_writable(RemoteLane::Control, false);
        assert!(!gated.is_lane_writable(RemoteLane::Control));
        let gated_trace: Vec<RemoteLane> = (0..2)
            .map(|_| gated.next_fragment().unwrap().lane)
            .collect();
        assert_eq!(gated_trace, vec![RemoteLane::Bulk, RemoteLane::Bulk]);
        // Nothing is writable now, so there is nothing to do — and no spin.
        gated.set_lane_writable(RemoteLane::Bulk, false);
        assert!(gated.next_fragment().is_none());
        assert!(gated.has_pending());
        // A writability edge makes the queued control work available again.
        gated.set_lane_writable(RemoteLane::Control, true);
        assert_eq!(gated.next_fragment().unwrap().lane, RemoteLane::Control);
    }

    #[test]
    fn remote_transport_scheduler_multi_fragment_streams_interleave() {
        // A multi-fragment bulk frame yields one fragment per visit, so a big
        // transfer cannot monopolise the lane against a second stream.
        let mut scheduler = RemoteLaneScheduler::default();
        assert!(
            scheduler
                .enqueue(&frame(RemoteLane::Bulk, 4, 0, 1, 400_000))
                .is_enqueued()
        );
        assert!(
            scheduler
                .enqueue(&frame(RemoteLane::Bulk, 6, 0, 2, 400_000))
                .is_enqueued()
        );
        let mut streams = Vec::new();
        for _ in 0..6 {
            if let Some(request) = scheduler.next_fragment() {
                streams.push(request.stream_id);
            }
        }
        assert_eq!(streams, vec![4, 6, 4, 6, 4, 6]);
    }

    #[test]
    fn remote_transport_queue_limit_matrix() {
        let limits = RemoteQueueLimits::DEFAULT;
        // Exact documented limits.
        assert_eq!(limits.control_frames, 256);
        assert_eq!(limits.control_bytes, 2 * 1024 * 1024);
        assert_eq!(limits.interactive_frames, 512);
        assert_eq!(limits.interactive_bytes, 8 * 1024 * 1024);
        assert_eq!(limits.bulk_frames, 128);
        assert_eq!(limits.bulk_bytes, 8 * 1024 * 1024);
        assert_eq!(limits.aggregate_bytes, 16 * 1024 * 1024);
        assert_eq!(limits.control_reserved_bytes, 1024 * 1024);
        assert_eq!(limits.control_reserved_frames, 32);
        assert_eq!(limits.interactive_reserved_bytes, 2 * 1024 * 1024);
        assert_eq!(limits.shared_pool_bytes(), 13 * 1024 * 1024);

        // --- per-lane frame caps --------------------------------------------
        // Control: 256 frames, then the offending stream is closed.
        let mut control = RemoteLaneScheduler::default();
        for i in 0..limits.control_frames {
            assert!(
                control
                    .enqueue(&frame(RemoteLane::Control, 0, i as u64, 1, 8))
                    .is_enqueued(),
                "control frame {i}"
            );
        }
        assert_eq!(control.queued_frames(RemoteLane::Control), 256);
        let overflow = control.enqueue(&frame(RemoteLane::Control, 0, 256, 1, 8));
        assert!(matches!(overflow, RemoteQueueOutcome::CloseStream(_)));
        assert_eq!(
            overflow.error().unwrap().reason,
            RemoteTransportReason::ControlQueueOverflow
        );

        // Interactive: 512 frames, then producers backpressure.
        let mut interactive = RemoteLaneScheduler::default();
        for i in 0..limits.interactive_frames {
            assert!(
                interactive
                    .enqueue(&frame(RemoteLane::Interactive, 2, i as u64, 2, 8))
                    .is_enqueued(),
                "interactive frame {i}"
            );
        }
        let backpressure = interactive.enqueue(&frame(RemoteLane::Interactive, 2, 512, 2, 8));
        assert!(matches!(backpressure, RemoteQueueOutcome::Backpressure(_)));
        assert_eq!(
            backpressure.error().unwrap().reason,
            RemoteTransportReason::QueueFrameLimit
        );

        // Bulk: 128 frames, then rejected.
        let mut bulk = RemoteLaneScheduler::default();
        for i in 0..limits.bulk_frames {
            assert!(
                bulk.enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 3, 8))
                    .is_enqueued(),
                "bulk frame {i}"
            );
        }
        let rejected = bulk.enqueue(&frame(RemoteLane::Bulk, 4, 128, 3, 8));
        assert!(matches!(rejected, RemoteQueueOutcome::Rejected(_)));
        assert_eq!(
            rejected.error().unwrap().reason,
            RemoteTransportReason::QueueFrameLimit
        );

        // --- per-lane byte caps ---------------------------------------------
        // Bulk: 8 MiB of bytes is reached before 128 frames when frames are big.
        let mut bulk_bytes = RemoteLaneScheduler::default();
        let big = 500_000usize;
        let mut queued = 0usize;
        let mut outcome = RemoteQueueOutcome::Enqueued;
        for i in 0..limits.bulk_frames {
            outcome = bulk_bytes.enqueue(&frame(RemoteLane::Bulk, 4, i as u64, 4, big));
            if !outcome.is_enqueued() {
                break;
            }
            queued += 1;
        }
        assert!(!outcome.is_enqueued());
        assert!(matches!(outcome, RemoteQueueOutcome::Rejected(_)));
        // Bulk stops at the shared pool (13 MiB) before its own 8 MiB cap only
        // if the pool is smaller; here its own 8 MiB cap binds first.
        assert!(bulk_bytes.queued_bytes(RemoteLane::Bulk) <= limits.bulk_bytes);
        assert_eq!(
            outcome.error().unwrap().reason,
            RemoteTransportReason::QueueByteLimit
        );
        assert!(queued > 0);

        // Control byte cap closes the stream.
        let mut control_bytes = RemoteLaneScheduler::default();
        let mut control_outcome = RemoteQueueOutcome::Enqueued;
        for i in 0..limits.control_frames {
            control_outcome =
                control_bytes.enqueue(&frame(RemoteLane::Control, 0, i as u64, 5, 65_536));
            if !control_outcome.is_enqueued() {
                break;
            }
        }
        assert!(matches!(
            control_outcome,
            RemoteQueueOutcome::CloseStream(_)
        ));
        assert_eq!(
            control_outcome.error().unwrap().reason,
            RemoteTransportReason::ControlQueueOverflow
        );
        // 2 MiB / ~65.6 KiB ≈ 31 frames fit under the control byte cap.
        assert!(control_bytes.queued_bytes(RemoteLane::Control) <= limits.control_bytes);

        // --- reservations: control always fits its floor under aggregate ----
        let mut reserved = RemoteLaneScheduler::default();
        // Fill interactive and bulk hard.
        let mut i = 0u64;
        while reserved
            .enqueue(&frame(RemoteLane::Interactive, 2, i, 6, 500_000))
            .is_enqueued()
        {
            i += 1;
        }
        let mut b = 0u64;
        while reserved
            .enqueue(&frame(RemoteLane::Bulk, 4, b, 7, 500_000))
            .is_enqueued()
        {
            b += 1;
        }
        assert!(reserved.aggregate_bytes() <= limits.aggregate_bytes);
        // Control's 1 MiB / 32-frame reservation survives the flood.
        let mut control_frames_admitted = 0;
        for seq in 0..limits.control_reserved_frames {
            if reserved
                .enqueue(&frame(RemoteLane::Control, 0, seq as u64, 8, 16 * 1024))
                .is_enqueued()
            {
                control_frames_admitted += 1;
            }
        }
        assert_eq!(
            control_frames_admitted, limits.control_reserved_frames,
            "control must always get its reserved 32 frames / 1 MiB"
        );
        assert!(reserved.queued_bytes(RemoteLane::Control) <= limits.control_reserved_bytes);

        // --- aggregate cap: bulk yields before its own lane cap -------------
        let mut aggregate = RemoteLaneScheduler::default();
        // Fill interactive to its own 8 MiB cap. Everything above its 2 MiB
        // reservation is drawn from the shared pool.
        let mut n = 0u64;
        while aggregate
            .enqueue(&frame(RemoteLane::Interactive, 2, n, 9, 500_000))
            .is_enqueued()
        {
            n += 1;
        }
        let interactive_bytes = aggregate.queued_bytes(RemoteLane::Interactive);
        assert!(interactive_bytes <= limits.interactive_bytes);
        assert!(interactive_bytes > limits.interactive_reserved_bytes);

        // Bulk has no reservation, so it draws entirely from what remains of
        // the shared pool and is stopped by the aggregate cap.
        let mut b = 0u64;
        let bulk_after = loop {
            let outcome = aggregate.enqueue(&frame(RemoteLane::Bulk, 4, b, 10, 500_000));
            if !outcome.is_enqueued() {
                break outcome;
            }
            b += 1;
        };
        assert!(matches!(bulk_after, RemoteQueueOutcome::Rejected(_)));
        assert_eq!(
            bulk_after.error().unwrap().reason,
            RemoteTransportReason::QueueAggregateLimit
        );
        // Bulk is rejected first: it never reaches its own 8 MiB lane cap.
        assert!(
            aggregate.queued_bytes(RemoteLane::Bulk) < limits.bulk_bytes,
            "the aggregate reservation must bind before the bulk lane cap"
        );
        // The shared pool is exhausted, but control's reservation is intact.
        assert!(
            aggregate
                .enqueue(&frame(RemoteLane::Control, 0, 0, 11, 32 * 1024))
                .is_enqueued(),
            "control must still be admissible when the shared pool is gone"
        );
        assert!(aggregate.aggregate_bytes() <= limits.aggregate_bytes);
        // Interactive, already above its reservation, now backpressures too.
        let interactive_after =
            aggregate.enqueue(&frame(RemoteLane::Interactive, 2, n, 12, 500_000));
        assert!(matches!(
            interactive_after,
            RemoteQueueOutcome::Backpressure(_)
        ));

        // --- nothing is ever silently dropped -------------------------------
        // Every non-enqueued outcome carries a typed, redaction-safe error.
        for outcome in [overflow, backpressure, rejected, bulk_after] {
            let error = outcome.error().expect("failure must be typed");
            assert!(error.lane.is_some());
            let rendered = error.to_string();
            assert!(!rendered.is_empty());
        }
    }

    /// The control reservation's *frame* half is enforced independently of its
    /// byte half.
    ///
    /// With the default limits the two are calibrated to the same point (32
    /// frames x 32 KiB = 1 MiB), so a test using them cannot tell which one
    /// admitted a frame. Here the frame budget is deliberately reached long
    /// before the byte budget, so only `control_reserved_frames` can explain
    /// the cutover from "reserved, admitted unconditionally" to "subject to the
    /// aggregate".
    #[test]
    fn remote_transport_queue_control_frame_reservation_is_enforced() {
        let limits = RemoteQueueLimits {
            control_reserved_frames: 4,
            ..RemoteQueueLimits::DEFAULT
        };
        let mut scheduler = RemoteLaneScheduler::new(limits);

        // Exhaust the shared pool with the other two lanes. The large frames
        // do most of it; the small top-up drains what the coarse ones leave, so
        // the pool really is empty rather than merely short of one big frame.
        let mut n = 0u64;
        while scheduler
            .enqueue(&frame(RemoteLane::Interactive, 2, n, 9, 500_000))
            .is_enqueued()
        {
            n += 1;
        }
        let mut b = 0u64;
        while scheduler
            .enqueue(&frame(RemoteLane::Bulk, 4, b, 10, 500_000))
            .is_enqueued()
        {
            b += 1;
        }
        while scheduler
            .enqueue(&frame(RemoteLane::Interactive, 2, n, 9, 1024))
            .is_enqueued()
        {
            n += 1;
        }

        // Control frames are tiny: 4 x 1 KiB is nowhere near the 1 MiB byte
        // reservation, so the byte half cannot be what admits them.
        for seq in 0..limits.control_reserved_frames {
            assert!(
                scheduler
                    .enqueue(&frame(RemoteLane::Control, 0, seq as u64, 11, 1024))
                    .is_enqueued(),
                "control frame {seq} is inside the reservation and must be admitted"
            );
        }
        assert!(
            scheduler.queued_bytes(RemoteLane::Control) < limits.control_reserved_bytes,
            "the byte reservation must still have ample headroom"
        );

        // One past the frame reservation: the byte headroom is unchanged, so a
        // rejection here can only come from the frame half.
        let beyond = scheduler.enqueue(&frame(
            RemoteLane::Control,
            0,
            limits.control_reserved_frames as u64,
            11,
            1024,
        ));
        assert!(matches!(beyond, RemoteQueueOutcome::CloseStream(_)));
        assert_eq!(
            beyond.error().unwrap().reason,
            RemoteTransportReason::QueueAggregateLimit,
            "past its frame reservation, control competes for the shared pool"
        );
    }

    #[test]
    fn remote_transport_queue_close_stream_discards_pending() {
        let mut scheduler = RemoteLaneScheduler::default();
        assert!(
            scheduler
                .enqueue(&frame(RemoteLane::Bulk, 4, 0, 1, 300_000))
                .is_enqueued()
        );
        assert!(
            scheduler
                .enqueue(&frame(RemoteLane::Bulk, 6, 0, 2, 300_000))
                .is_enqueued()
        );
        scheduler.close_stream(RemoteLane::Bulk, 4);
        let mut streams = Vec::new();
        while let Some(request) = scheduler.next_fragment() {
            streams.push(request.stream_id);
        }
        assert!(streams.iter().all(|id| *id == 6));
        assert!(!streams.is_empty());
    }

    /// Draining and cancelling both return capacity. Without per-frame
    /// accounting the queue stays charged forever and the lane wedges shut.
    #[test]
    fn remote_transport_queue_accounting_is_released_on_drain_and_cancel() {
        // --- a fully drained lane reads back as exactly empty ---------------
        let mut drained = RemoteLaneScheduler::default();
        let payload = 500_000usize;
        let frame_size = payload + 72;
        for i in 0..16u64 {
            assert!(
                drained
                    .enqueue(&frame(RemoteLane::Bulk, 4, i, 1, payload))
                    .is_enqueued(),
                "bulk frame {i}"
            );
        }
        assert_eq!(drained.queued_frames(RemoteLane::Bulk), 16);
        assert_eq!(drained.queued_bytes(RemoteLane::Bulk), 16 * frame_size);
        while drained.next_fragment().is_some() {}
        assert!(!drained.has_pending());
        assert_eq!(
            drained.queued_frames(RemoteLane::Bulk),
            0,
            "a drained lane must hold no frame charge"
        );
        assert_eq!(
            drained.queued_bytes(RemoteLane::Bulk),
            0,
            "a drained lane must hold no byte charge"
        );
        assert_eq!(drained.aggregate_bytes(), 0);
        // Capacity is immediately reusable.
        assert!(
            drained
                .enqueue(&frame(RemoteLane::Bulk, 4, 99, 2, payload))
                .is_enqueued(),
            "a drained lane must accept new work"
        );

        // --- cancellation releases the same accounting ----------------------
        let mut cancelled = RemoteLaneScheduler::default();
        for i in 0..27u64 {
            assert!(
                cancelled
                    .enqueue(&frame(RemoteLane::Bulk, 4, i, 3, 300_000))
                    .is_enqueued(),
                "bulk frame {i}"
            );
        }
        assert_eq!(cancelled.queued_frames(RemoteLane::Bulk), 27);
        assert!(cancelled.queued_bytes(RemoteLane::Bulk) > 8_000_000);
        cancelled.close_stream(RemoteLane::Bulk, 4);
        assert_eq!(
            cancelled.queued_frames(RemoteLane::Bulk),
            0,
            "cancellation must release the frame charge"
        );
        assert_eq!(
            cancelled.queued_bytes(RemoteLane::Bulk),
            0,
            "cancellation must release the byte charge"
        );
        assert!(!cancelled.has_pending());
        assert!(
            cancelled
                .enqueue(&frame(RemoteLane::Bulk, 6, 0, 4, 300_000))
                .is_enqueued(),
            "post-cancel capacity must be immediately reusable"
        );

        // --- a partially drained frame keeps exactly its own charge ---------
        let mut partial = RemoteLaneScheduler::default();
        assert!(
            partial
                .enqueue(&frame(RemoteLane::Bulk, 4, 0, 5, 300_000))
                .is_enqueued()
        );
        assert!(
            partial
                .enqueue(&frame(RemoteLane::Bulk, 4, 1, 6, 300_000))
                .is_enqueued()
        );
        let both = partial.queued_bytes(RemoteLane::Bulk);
        // Pull one fragment; the frame is not finished, so nothing is released.
        let first = partial.next_fragment().expect("a fragment is queued");
        assert!(!first.fragment.flags.is_end());
        assert_eq!(partial.queued_bytes(RemoteLane::Bulk), both);
        assert_eq!(partial.queued_frames(RemoteLane::Bulk), 2);
        // Finish exactly the first frame.
        loop {
            let request = partial.next_fragment().expect("more fragments");
            if request.fragment.flags.is_end() {
                break;
            }
        }
        assert_eq!(partial.queued_frames(RemoteLane::Bulk), 1);
        assert_eq!(partial.queued_bytes(RemoteLane::Bulk), both / 2);
    }

    /// A carrier that refuses a write must be able to give the fragment back.
    /// Otherwise the send loop drops a reliable frame on a writability race.
    #[test]
    fn remote_transport_scheduler_requeues_a_refused_fragment() {
        let mut scheduler = RemoteLaneScheduler::default();
        assert!(
            scheduler
                .enqueue(&frame(RemoteLane::Bulk, 4, 0, 1, 200_000))
                .is_enqueued()
        );
        let frames_before = scheduler.queued_frames(RemoteLane::Bulk);
        let bytes_before = scheduler.queued_bytes(RemoteLane::Bulk);

        // Collect the whole frame, refusing every fragment once.
        let mut delivered: Vec<Vec<u8>> = Vec::new();
        let mut refusals = 0usize;
        while let Some(request) = scheduler.next_fragment() {
            if refusals < 4 && delivered.len() == refusals {
                // The carrier refuses: hand it straight back.
                refusals += 1;
                let index = request.fragment.fragment_index;
                let expected_frames = scheduler.queued_frames(RemoteLane::Bulk);
                let expected_bytes = scheduler.queued_bytes(RemoteLane::Bulk);
                let end = request.fragment.flags.is_end();
                scheduler.requeue(request);
                // A refused final fragment restores its frame's whole charge.
                if end {
                    assert_eq!(
                        scheduler.queued_frames(RemoteLane::Bulk),
                        expected_frames + 1
                    );
                    assert!(scheduler.queued_bytes(RemoteLane::Bulk) > expected_bytes);
                }
                // The refused fragment is the very next one offered.
                let retry = scheduler.next_fragment().expect("refused fragment returns");
                assert_eq!(retry.fragment.fragment_index, index);
                delivered.push(retry.fragment.bytes.clone());
                continue;
            }
            delivered.push(request.fragment.bytes.clone());
        }
        assert_eq!(refusals, 4, "the script must exercise refusals");

        // Nothing was lost: the reassembled bytes are the original frame.
        let rebuilt: Vec<u8> = delivered.concat();
        let original = frame(RemoteLane::Bulk, 4, 0, 1, 200_000).encode().unwrap();
        assert_eq!(rebuilt, original, "a refused fragment must not be dropped");
        // And the accounting still lands exactly on zero.
        assert_eq!(scheduler.queued_frames(RemoteLane::Bulk), 0);
        assert_eq!(scheduler.queued_bytes(RemoteLane::Bulk), 0);
        assert_eq!(frames_before, 1);
        assert!(bytes_before > 200_000);
    }
}
