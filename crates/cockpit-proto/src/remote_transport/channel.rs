//! The fixed three-channel contract.
//!
//! Exactly three pre-negotiated data channels exist. Their SCTP stream IDs
//! (0/2/4) and labels are wire constants: there is no channel negotiation, no
//! dynamic channel creation, and no way for a peer to request a fourth.

use crate::remote_transport::lane::{
    REMOTE_LANE_COUNT, RemoteLane, RemoteTransportError, RemoteTransportReason,
    RemoteTransportResult,
};

/// One channel's immutable settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RemoteLaneChannel {
    pub lane: RemoteLane,
    /// Negotiated SCTP stream identifier.
    pub channel_id: u16,
    pub label: &'static str,
    /// Always true: both peers create the channel with a fixed id.
    pub negotiated: bool,
    /// Always true: v1 lanes are ordered.
    pub ordered: bool,
    /// Always true: v1 lanes are reliable.
    pub reliable: bool,
    /// Always false: v1 lanes are uncompressed.
    pub compressed: bool,
    /// Per-lane logical payload cap, restated here so a channel row is
    /// self-describing for the TypeScript mirror.
    pub max_payload_bytes: usize,
}

/// The complete channel table, in lane order.
pub const REMOTE_LANE_CHANNELS: [RemoteLaneChannel; REMOTE_LANE_COUNT] = [
    RemoteLaneChannel {
        lane: RemoteLane::Control,
        channel_id: 0,
        label: "flycockpit.control.v1",
        negotiated: true,
        ordered: true,
        reliable: true,
        compressed: false,
        max_payload_bytes: crate::remote_transport::lane::CONTROL_MAX_PAYLOAD_BYTES,
    },
    RemoteLaneChannel {
        lane: RemoteLane::Interactive,
        channel_id: 2,
        label: "flycockpit.interactive.v1",
        negotiated: true,
        ordered: true,
        reliable: true,
        compressed: false,
        max_payload_bytes: crate::remote_transport::lane::INTERACTIVE_MAX_PAYLOAD_BYTES,
    },
    RemoteLaneChannel {
        lane: RemoteLane::Bulk,
        channel_id: 4,
        label: "flycockpit.bulk.v1",
        negotiated: true,
        ordered: true,
        reliable: true,
        compressed: false,
        max_payload_bytes: crate::remote_transport::lane::BULK_MAX_PAYLOAD_BYTES,
    },
];

/// Channel settings for a lane. Total — every lane has exactly one channel.
pub const fn channel_for_lane(lane: RemoteLane) -> RemoteLaneChannel {
    REMOTE_LANE_CHANNELS[lane as usize]
}

/// Reverse lookup. Unknown channel ids fail rather than opening a channel.
pub fn lane_for_channel_id(channel_id: u16) -> RemoteTransportResult<RemoteLane> {
    REMOTE_LANE_CHANNELS
        .iter()
        .find(|channel| channel.channel_id == channel_id)
        .map(|channel| channel.lane)
        .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::UnknownLane))
}

/// Reverse lookup by label. Unknown labels fail: no dynamic channel may be
/// opened by naming it.
pub fn lane_for_channel_label(label: &str) -> RemoteTransportResult<RemoteLane> {
    REMOTE_LANE_CHANNELS
        .iter()
        .find(|channel| channel.label == label)
        .map(|channel| channel.lane)
        .ok_or_else(|| RemoteTransportError::new(RemoteTransportReason::UnknownLane))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_transport_fixed_channel_contract() {
        // Exactly three channels — no more, no fewer.
        assert_eq!(REMOTE_LANE_CHANNELS.len(), 3);
        assert_eq!(REMOTE_LANE_COUNT, 3);

        // Exact ids and labels.
        let expected = [
            (
                RemoteLane::Control,
                0u16,
                "flycockpit.control.v1",
                65_536usize,
            ),
            (
                RemoteLane::Interactive,
                2,
                "flycockpit.interactive.v1",
                524_288,
            ),
            (RemoteLane::Bulk, 4, "flycockpit.bulk.v1", 524_288),
        ];
        for (index, (lane, channel_id, label, cap)) in expected.into_iter().enumerate() {
            let channel = REMOTE_LANE_CHANNELS[index];
            assert_eq!(channel.lane, lane);
            assert_eq!(channel.channel_id, channel_id);
            assert_eq!(channel.label, label);
            assert_eq!(channel.max_payload_bytes, cap);
            // Every v1 lane is pre-negotiated, ordered, reliable, uncompressed.
            assert!(channel.negotiated, "{label} must be pre-negotiated");
            assert!(channel.ordered, "{label} must be ordered");
            assert!(channel.reliable, "{label} must be reliable");
            assert!(!channel.compressed, "{label} must be uncompressed");
            assert_eq!(channel_for_lane(lane), channel);
            assert_eq!(lane_for_channel_id(channel_id).unwrap(), lane);
            assert_eq!(lane_for_channel_label(label).unwrap(), lane);
        }

        // Channel ids are even and distinct from the lane ids, so the two
        // numbering schemes cannot be silently interchanged.
        let ids: Vec<u16> = REMOTE_LANE_CHANNELS.iter().map(|c| c.channel_id).collect();
        assert_eq!(ids, vec![0, 2, 4]);
        assert!(ids.iter().all(|id| id.is_multiple_of(2)));
        assert_eq!(
            REMOTE_LANE_CHANNELS[1].lane.lane_id() as u16,
            1,
            "interactive lane id stays 1 while its channel id is 2"
        );

        // Labels are unique and versioned.
        let mut labels: Vec<&str> = REMOTE_LANE_CHANNELS.iter().map(|c| c.label).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), 3);
        assert!(
            REMOTE_LANE_CHANNELS
                .iter()
                .all(|c| c.label.starts_with("flycockpit.") && c.label.ends_with(".v1"))
        );

        // No dynamic channel: unknown ids and labels fail closed.
        for unknown in [1u16, 3, 5, 6, 65_535] {
            assert_eq!(
                lane_for_channel_id(unknown).unwrap_err().reason,
                RemoteTransportReason::UnknownLane,
                "channel id {unknown} must not resolve"
            );
        }
        for unknown in [
            "flycockpit.media.v1",
            "flycockpit.control.v2",
            "control",
            "",
        ] {
            assert_eq!(
                lane_for_channel_label(unknown).unwrap_err().reason,
                RemoteTransportReason::UnknownLane,
                "label {unknown} must not resolve"
            );
        }
    }
}
