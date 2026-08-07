//! Payload-free transport logging and metrics.
//!
//! A record may carry a lane, a closed reason code, and a size bucket. It has
//! no field capable of holding a payload, a frame id, a stream id, a path, or a
//! secret — the types simply do not have anywhere to put them.

use crate::remote_transport::lane::{
    RemoteLane, RemoteSizeBucket, RemoteTransportError, RemoteTransportReason,
};

/// Counter names. Closed set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RemoteTransportMetric {
    FrameSent,
    FrameReceived,
    FrameRejected,
    FragmentSent,
    FragmentReceived,
    ReassemblyExpired,
    QueueRejected,
    QueueBackpressure,
    StreamClosed,
    TransferBegun,
    TransferCompleted,
    TransferAborted,
}

impl RemoteTransportMetric {
    pub const fn as_str(self) -> &'static str {
        use RemoteTransportMetric::*;
        match self {
            FrameSent => "frame_sent",
            FrameReceived => "frame_received",
            FrameRejected => "frame_rejected",
            FragmentSent => "fragment_sent",
            FragmentReceived => "fragment_received",
            ReassemblyExpired => "reassembly_expired",
            QueueRejected => "queue_rejected",
            QueueBackpressure => "queue_backpressure",
            StreamClosed => "stream_closed",
            TransferBegun => "transfer_begun",
            TransferCompleted => "transfer_completed",
            TransferAborted => "transfer_aborted",
        }
    }
}

/// One loggable transport observation.
///
/// Construction is the enforcement point: there is no `&str`, `String`, `Vec`,
/// or id field, so nothing sensitive can be attached even by mistake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RemoteTransportRecord {
    pub metric: RemoteTransportMetric,
    pub lane: Option<RemoteLane>,
    pub reason: Option<RemoteTransportReason>,
    pub size_bucket: Option<RemoteSizeBucket>,
}

impl RemoteTransportRecord {
    pub const fn new(metric: RemoteTransportMetric) -> Self {
        Self {
            metric,
            lane: None,
            reason: None,
            size_bucket: None,
        }
    }

    pub const fn lane(mut self, lane: RemoteLane) -> Self {
        self.lane = Some(lane);
        self
    }

    /// Record a size as a bucket. The exact byte count is discarded here and
    /// cannot be recovered downstream.
    pub const fn size(mut self, bytes: usize) -> Self {
        self.size_bucket = Some(RemoteSizeBucket::of(bytes));
        self
    }

    /// Build from a transport failure, carrying over only its safe fields.
    pub fn from_error(metric: RemoteTransportMetric, error: RemoteTransportError) -> Self {
        Self {
            metric,
            lane: error.lane,
            reason: Some(error.reason),
            size_bucket: error.size_bucket,
        }
    }

    /// Stable `key=value` rendering for logs.
    pub fn render(&self) -> String {
        let mut out = format!("transport.{}", self.metric.as_str());
        if let Some(lane) = self.lane {
            out.push_str(&format!(" lane={lane}"));
        }
        if let Some(reason) = self.reason {
            out.push_str(&format!(" reason={reason}"));
        }
        if let Some(bucket) = self.size_bucket {
            out.push_str(&format!(" size={bucket}"));
        }
        out
    }
}

impl std::fmt::Display for RemoteTransportRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_protocol_id::{kind, tag_protocol_id_bytes};
    use crate::remote_transport::frame::RemoteTransportFrameV1;
    use crate::remote_transport::lane_io::{
        RemoteCarrierKind, RemoteLaneEndpoint, RemoteLaneWriter, RemoteWritability,
    };
    use crate::remote_transport::scheduler::RemoteLaneScheduler;

    #[test]
    fn remote_transport_no_polling_or_payload_logs() {
        // --- readiness is event-driven, never polled ------------------------
        let mut scheduler = RemoteLaneScheduler::default();
        let secret_payload = b"AKIAIOSFODNN7EXAMPLE /home/alice/.ssh/id_ed25519 hunter2".to_vec();
        let frame_id = tag_protocol_id_bytes::<kind::Frame>([0xAB; 16]).unwrap();
        let frame = RemoteTransportFrameV1::new(
            RemoteLane::Interactive,
            0xDEAD_BEEF_0000_0002,
            0,
            frame_id,
            secret_payload.clone(),
        )
        .unwrap();
        assert!(scheduler.enqueue(&frame).is_enqueued());

        // With the lane not writable there is simply nothing to do. The
        // scheduler does not spin, sleep, or retry — it returns None.
        scheduler.set_lane_writable(RemoteLane::Interactive, false);
        for _ in 0..100 {
            assert!(scheduler.next_fragment().is_none());
        }
        assert!(scheduler.has_pending(), "work is retained, not dropped");

        // A single explicit writability edge is what makes progress possible.
        scheduler.set_lane_writable(RemoteLane::Interactive, true);
        let request = scheduler
            .next_fragment()
            .expect("writable lane yields work");
        assert_eq!(request.lane, RemoteLane::Interactive);

        // The carrier surface reports readiness as a state, not a poll result.
        let mut endpoint = RemoteLaneEndpoint::new(RemoteCarrierKind::WebRtcDataChannel);
        assert_eq!(
            endpoint.writability(RemoteLane::Interactive),
            RemoteWritability::Writable
        );
        endpoint.set_writable(RemoteLane::Interactive, false);
        assert_eq!(
            endpoint.writability(RemoteLane::Interactive),
            RemoteWritability::BufferFull
        );
        // A write against a full buffer errors immediately instead of blocking.
        let write = endpoint.write_fragment(RemoteLane::Interactive, &request.fragment);
        assert!(write.is_err());

        // --- nothing sensitive can reach a log ------------------------------
        let records = [
            RemoteTransportRecord::new(RemoteTransportMetric::FrameSent)
                .lane(RemoteLane::Interactive)
                .size(secret_payload.len()),
            RemoteTransportRecord::from_error(
                RemoteTransportMetric::FrameRejected,
                write.unwrap_err(),
            ),
            RemoteTransportRecord::from_error(
                RemoteTransportMetric::QueueRejected,
                RemoteTransportError::with_size(
                    RemoteTransportReason::PayloadCapExceeded,
                    RemoteLane::Bulk,
                    900_000,
                ),
            ),
            RemoteTransportRecord::new(RemoteTransportMetric::ReassemblyExpired)
                .lane(RemoteLane::Bulk),
        ];

        // Everything a payload, id, path, or secret could look like is absent.
        let forbidden = [
            "AKIA",
            "hunter2",
            "id_ed25519",
            "/home/alice",
            ".ssh",
            // Stream id, in decimal and hex.
            "16045690981097439234",
            "deadbeef",
            "DEADBEEF",
            // Frame id bytes, hex and base64url.
            "abababab",
            "q6urq6urq6urq6urq6urqw",
            // Exact byte counts must be bucketed away.
            "900000",
            "55",
        ];
        for record in records {
            let rendered = record.render();
            for needle in forbidden {
                assert!(
                    !rendered.contains(needle),
                    "record {rendered:?} leaked {needle:?}"
                );
            }
            // Only the allowed vocabulary appears.
            assert!(rendered.starts_with("transport."));
            for part in rendered.split(' ').skip(1) {
                let (key, _) = part.split_once('=').expect("key=value");
                assert!(
                    matches!(key, "lane" | "reason" | "size"),
                    "unexpected log key {key:?}"
                );
            }
            // Debug output is equally safe.
            let debug = format!("{record:?}");
            for needle in ["AKIA", "hunter2", "id_ed25519", "/home/alice"] {
                assert!(!debug.contains(needle));
            }
        }

        // The record type structurally cannot hold free text or bytes.
        assert_eq!(
            std::mem::size_of::<RemoteTransportRecord>(),
            4 * std::mem::size_of::<u8>(),
            "a record is four small enums: no pointer, no buffer, no id"
        );

        // The scheduler's own Debug is payload-free too.
        let scheduler_debug = format!("{scheduler:?}");
        for needle in ["AKIA", "hunter2", "/home/alice", "deadbeef"] {
            assert!(!scheduler_debug.contains(needle), "{scheduler_debug}");
        }
    }

    #[test]
    fn remote_transport_metric_and_bucket_names_are_stable() {
        for (metric, expected) in [
            (RemoteTransportMetric::FrameSent, "frame_sent"),
            (
                RemoteTransportMetric::QueueBackpressure,
                "queue_backpressure",
            ),
            (RemoteTransportMetric::TransferAborted, "transfer_aborted"),
        ] {
            assert_eq!(metric.as_str(), expected);
        }
        let record = RemoteTransportRecord::from_error(
            RemoteTransportMetric::FrameRejected,
            RemoteTransportError::with_size(
                RemoteTransportReason::DigestMismatch,
                RemoteLane::Control,
                100,
            ),
        );
        assert_eq!(
            record.render(),
            "transport.frame_rejected lane=control reason=digest_mismatch size=le_1k"
        );
    }
}
