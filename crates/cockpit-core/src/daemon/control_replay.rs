//! Authoritative control-event replay seam.
//!
//! When a daemon's control cursor pauses (gap / conflict / regression /
//! malformed), it must re-derive the cursor from an authoritative, gap-free
//! replay of the gateway-owned control outbox. This module defines the
//! compile-enforced [`ControlReplaySource`] seam through which
//! [`reconcile_authoritative_replay`](super::session_continuity::reconcile_authoritative_replay)
//! pulls that replay.
//!
//! # Ownership boundary
//!
//! This prompt lands ONLY the trait and in-memory test doubles. The single
//! production implementation — a Postgres/gateway-backed source that reads the
//! `RemoteDaemonControlOutbox` over the authenticated control socket — is owned
//! by `signaling-gateway-control-outbox-delivery` and is deliberately absent
//! here. A workspace search finds no production `impl ControlReplaySource` in
//! this landing.
//!
//! The replay caps match the gateway's replay: at most 64 events AND at most
//! 512 KiB aggregate per page.

use async_trait::async_trait;
use cockpit_proto::remote_session_continuity::{
    REMOTE_CONTROL_EVENT_REPLAY_MAX_BYTES, REMOTE_CONTROL_EVENT_REPLAY_MAX_EVENTS,
    RemoteControlEventV1,
};

/// The instance-scoped control-stream identity: the sequence scope is exactly
/// `(daemonInstanceProtocolId, daemonCertificateGeneration)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ControlStreamScope {
    pub daemon_instance_protocol_id: [u8; 16],
    pub daemon_certificate_generation: u64,
}

/// One entry in a replay page: the verified control event plus its stream
/// coordinates. The event is carried decoded (a production source verifies the
/// wrapping JWS before the event enters a page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedControlEvent {
    pub control_seq: u64,
    pub event_id: [u8; 16],
    pub event: RemoteControlEventV1,
}

/// A bounded replay page. At most [`REMOTE_CONTROL_EVENT_REPLAY_MAX_EVENTS`]
/// events and [`REMOTE_CONTROL_EVENT_REPLAY_MAX_BYTES`] aggregate bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlReplayPage {
    pub events: Vec<VerifiedControlEvent>,
    pub high_water_seq: u64,
    /// True if more pages remain after this one.
    pub truncated: bool,
}

impl ControlReplayPage {
    /// Validate the page against the gateway replay caps.
    pub fn validate_caps(&self) -> Result<(), ControlReplayError> {
        if self.events.len() > REMOTE_CONTROL_EVENT_REPLAY_MAX_EVENTS {
            return Err(ControlReplayError::Malformed);
        }
        let total: usize = self.events.iter().map(|e| e.event.encode().len()).sum();
        if total > REMOTE_CONTROL_EVENT_REPLAY_MAX_BYTES {
            return Err(ControlReplayError::Malformed);
        }
        Ok(())
    }
}

/// Replay error surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlReplayError {
    #[error("replay source is unavailable")]
    Unavailable,
    #[error("replay source rejected the request as unauthorized")]
    Unauthorized,
    #[error("replay page is malformed or exceeds caps")]
    Malformed,
    #[error("replay source reported a conflict")]
    Conflict,
}

/// An authoritative source of control-event replay pages. Injected as
/// `Arc<dyn ControlReplaySource>` (or a generic `S: ControlReplaySource`) — no
/// process-global singleton.
#[async_trait]
pub trait ControlReplaySource: Send + Sync {
    /// Read one bounded page of events with `controlSeq` strictly greater than
    /// `after_seq` (`0` reads from the start of the stream).
    async fn read_page(
        &self,
        scope: ControlStreamScope,
        after_seq: u64,
    ) -> Result<ControlReplayPage, ControlReplayError>;
}

/// An in-memory test double: scripted pages keyed by exclusive lower bound.
/// TEST-ONLY — never a production replay source.
#[derive(Debug, Default)]
pub struct MemoryControlReplaySource {
    scope: Option<ControlStreamScope>,
    events: Vec<VerifiedControlEvent>,
}

impl MemoryControlReplaySource {
    pub fn new(scope: ControlStreamScope, events: Vec<VerifiedControlEvent>) -> Self {
        Self {
            scope: Some(scope),
            events,
        }
    }
}

#[async_trait]
impl ControlReplaySource for MemoryControlReplaySource {
    async fn read_page(
        &self,
        scope: ControlStreamScope,
        after_seq: u64,
    ) -> Result<ControlReplayPage, ControlReplayError> {
        if self.scope != Some(scope) {
            return Err(ControlReplayError::Unauthorized);
        }
        let mut events: Vec<VerifiedControlEvent> = self
            .events
            .iter()
            .filter(|e| e.control_seq > after_seq)
            .cloned()
            .collect();
        events.sort_by_key(|e| e.control_seq);

        // Apply the event-count cap; the byte cap is enforced by validate_caps.
        let truncated = events.len() > REMOTE_CONTROL_EVENT_REPLAY_MAX_EVENTS;
        events.truncate(REMOTE_CONTROL_EVENT_REPLAY_MAX_EVENTS);
        let high_water_seq = events.last().map(|e| e.control_seq).unwrap_or(after_seq);
        let page = ControlReplayPage {
            events,
            high_water_seq,
            truncated,
        };
        page.validate_caps()?;
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::remote_session_continuity::RemoteControlEventPayload;

    fn scope() -> ControlStreamScope {
        ControlStreamScope {
            daemon_instance_protocol_id: [0x01; 16],
            daemon_certificate_generation: 3,
        }
    }

    fn event(seq: u64) -> VerifiedControlEvent {
        let mut id = [0u8; 16];
        id[15] = seq as u8;
        VerifiedControlEvent {
            control_seq: seq,
            event_id: id,
            event: RemoteControlEventV1::seal(
                seq,
                id,
                1,
                1,
                1,
                0,
                RemoteControlEventPayload::Drain {
                    deadline: 0,
                    reason: 0,
                },
            ),
        }
    }

    #[tokio::test]
    async fn reads_events_after_cursor_in_order() {
        let src = MemoryControlReplaySource::new(scope(), vec![event(1), event(2), event(3)]);
        let page = src.read_page(scope(), 1).await.unwrap();
        let seqs: Vec<u64> = page.events.iter().map(|e| e.control_seq).collect();
        assert_eq!(seqs, vec![2, 3]);
        assert_eq!(page.high_water_seq, 3);
        assert!(!page.truncated);
    }

    #[tokio::test]
    async fn wrong_scope_is_unauthorized() {
        let src = MemoryControlReplaySource::new(scope(), vec![event(1)]);
        let other = ControlStreamScope {
            daemon_instance_protocol_id: [0xFF; 16],
            daemon_certificate_generation: 3,
        };
        assert_eq!(
            src.read_page(other, 0).await,
            Err(ControlReplayError::Unauthorized)
        );
    }
}
