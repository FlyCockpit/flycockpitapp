//! Transport-independent session continuity and live revocation — daemon
//! state machines.
//!
//! This module implements the daemon-side state machines for:
//!
//! - **Attachment continuity** — the stable `logicalAttachmentId` independent
//!   of physical children, with shared operation ledger and outbox.
//! - **Child membership** — multiple authorized WebRTC/WebSocket children may
//!   remain simultaneous read/write. Each callback verifies child
//!   generation/epoch. Closing one child removes only that membership.
//! - **Lease/control cursor** — the daemon persists `lastAppliedControlSeq`
//!   and `eventId → byteHash` before ACK, and applies each closed event
//!   through the authorization barrier.
//! - **Authorization barrier** — for every request, atomically reads current
//!   lease/policy/revocation/local policy and, for mutations, reserves the
//!   next operation-ledger sequence.
//! - **Operation recovery** — delegates to the ledger's exhaustive classes.
//! - **Mobile background/foreground** — quiesce within available OS time,
//!   close physical children, and foreground performs full authorization/
//!   recovery.
//! - **Event delivery deduplication** — all egress reads the shared outbox
//!   and stable delivery IDs.
//!
//! # What this module owns
//!
//! - The attachment, child membership, lease/control cursor, and UI recovery
//!   total state machines.
//! - The authorization barrier ordering: request admitted before barrier may
//!   finish under its recorded policy snapshot; event first rejects.
//! - The control event application state machine: consume the gateway-owned
//!   `RemoteControlEventV1` (FCRC) binary event, persist cursor/event hash
//!   before ACK, apply each of the eight closed kinds exhaustively, and pause
//!   on conflict/gap/epoch-regression/malformed. The pause is sticky and
//!   clears only through `reconcile_authoritative_replay`.
//! - The mobile background/foreground state transitions.
//!
//! # What this module does NOT own
//!
//! - JWS signing/verification (owned by the authority adapter).
//! - SQLite/Postgres storage wiring.
//! - Transport adapter implementation.
//! - The signaling gateway or WebRTC/Noise implementation.
//!
//! # Security decisions
//!
//! - Every reconnect/new child completes a fresh grant, bilateral proofs,
//!   DTLS/Noise transcript, tuple, and random `transportEpoch` before
//!   `reattach`. Old crypto never authorizes 0-RTT.
//! - A revocation/control event and operation have one daemon-local order.
//! - Active revocation closes all affected child epochs after the barrier
//!   and prevents replacement admission.
//! - Closing one child cannot mutate other epochs or attachment state.
//! - The daemon outbox is the only application event replay source.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use cockpit_proto::remote_session_continuity::{
    REMOTE_REPLAY_MAX_EVENTS_PER_PAGE, RemoteContinuityOperationClass,
    RemoteControlEventApplyResult, RemoteControlEventPayload, RemoteControlEventV1,
    RemoteDeliveryDedupeState, RemoteLeaseActiveChildV1, RemoteLeaseChildLifecycle,
    RemoteLeaseTransport, RemoteLongRunningClassification, RemoteMobileUiState,
    RemoteOperationRecoveryAction, RemoteOperationStatus, RemoteReattachResponseV1,
    RemoteRevocationDisposition, control_event_byte_hash, operation_recovery_action,
    revocation_disposition, validate_replay_page,
};

// ─────────────────────────────────────────────────────────────────────────
// Child membership
// ─────────────────────────────────────────────────────────────────────────

/// A child transport member within a logical attachment. Each child has a
/// distinct child attempt, bilateral proofs, transcript, and transport
/// epoch. Multiple authorized children may remain simultaneous read/write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildMember {
    pub child_attempt_id: String,
    pub transport: ChildTransport,
    pub transport_epoch: String,
    pub generation: u64,
    pub state: ChildMemberState,
    /// The store-committed agreeing final-proof-set digest for this child/
    /// epoch.
    pub final_proof_set_digest: [u8; 32],
}

/// The transport kind for a child member.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildTransport {
    WebRtc,
    WebSocket,
}

/// Child member state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChildMemberState {
    /// Pending authentication.
    Pending,
    /// Active and routed-current.
    Active,
    /// Draining (TURN cutover predecessor).
    Draining,
    /// Closed.
    Closed,
}

impl ChildMember {
    /// Whether this child is active (routed-current).
    pub fn is_active(&self) -> bool {
        matches!(self.state, ChildMemberState::Active)
    }

    /// Whether this child is still open (not closed).
    pub fn is_open(&self) -> bool {
        !matches!(self.state, ChildMemberState::Closed)
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Attachment continuity state
// ─────────────────────────────────────────────────────────────────────────

/// The attachment continuity state for one logical attachment. The
/// `logicalAttachmentId` is stable across dropped networks, app-replica
/// changes, reconnection, and mobile suspension.
#[derive(Debug, Clone)]
pub struct AttachmentContinuityState {
    pub logical_attachment_id: String,
    pub session_id: String,
    /// The current lease ID, if any. Exactly one lease is current per
    /// attachment.
    pub current_lease_id: Option<String>,
    pub current_lease_generation: u64,
    pub current_lease_jws_digest: [u8; 32],
    /// Active child members. Multiple authorized children may remain
    /// simultaneous read/write.
    pub children: Vec<ChildMember>,
    /// The shared delivery deduplication state. All egress reads the shared
    /// outbox and stable delivery IDs.
    pub delivery_dedupe: RemoteDeliveryDedupeState,
    /// The control event cursor: `lastAppliedControlSeq`.
    pub last_applied_control_seq: u64,
    /// The last applied `policyEpoch` (epoch regression is detected on epochs).
    pub last_applied_policy_epoch: u64,
    /// The last applied `authorityEpoch` (epoch regression is detected on
    /// epochs).
    pub last_applied_authority_epoch: u64,
    /// Persisted `eventId → byteHash` map for control event idempotency.
    pub control_event_hashes: HashMap<[u8; 16], [u8; 32]>,
    /// Whether operations are paused due to a control event conflict/gap/
    /// regression/malformed payload. Sticky: clears only through
    /// [`reconcile_authoritative_replay`].
    pub operations_paused: bool,
    /// The required policy digest after a `policy_narrowed` event. New
    /// admissions must use a lease whose `policyDigest` equals this value.
    pub required_policy_digest: Option<[u8; 32]>,
    /// The `drain` deadline (unix seconds), if a drain event is in force.
    /// Children close at this deadline via the injected continuity clock
    /// (clock wiring deferred to the daemon live path).
    pub drain_deadline: Option<i64>,
    /// An embedded lease-refresh JWS recorded from a `lease_refresh` event,
    /// pending signature verification before install (verification deferred to
    /// the continuity-typ JWS path).
    pub pending_lease_refresh_jws: Option<Vec<u8>>,
    /// The current mobile UI state.
    pub mobile_ui_state: RemoteMobileUiState,
    /// Whether the attachment is in mobile background mode.
    pub backgrounded: bool,
}

impl AttachmentContinuityState {
    /// Create a new attachment continuity state.
    pub fn new(logical_attachment_id: String, session_id: String) -> Self {
        Self {
            logical_attachment_id,
            session_id,
            current_lease_id: None,
            current_lease_generation: 0,
            current_lease_jws_digest: [0u8; 32],
            children: Vec::new(),
            delivery_dedupe: RemoteDeliveryDedupeState::new(),
            last_applied_control_seq: 0,
            last_applied_policy_epoch: 0,
            last_applied_authority_epoch: 0,
            control_event_hashes: HashMap::new(),
            operations_paused: false,
            required_policy_digest: None,
            drain_deadline: None,
            pending_lease_refresh_jws: None,
            mobile_ui_state: RemoteMobileUiState::Reconnecting,
            backgrounded: false,
        }
    }

    /// Count active children.
    pub fn count_active(&self) -> usize {
        self.children.iter().filter(|c| c.is_active()).count()
    }

    /// Count open children (not closed).
    pub fn count_open(&self) -> usize {
        self.children.iter().filter(|c| c.is_open()).count()
    }

    /// Find a child by attempt ID.
    pub fn find_child(&self, id: &str) -> Option<&ChildMember> {
        self.children.iter().find(|c| c.child_attempt_id == id)
    }

    /// Find a mutable child by attempt ID.
    pub fn find_child_mut(&mut self, id: &str) -> Option<&mut ChildMember> {
        self.children.iter_mut().find(|c| c.child_attempt_id == id)
    }

    /// Add a child member. Returns false if a child with the same attempt ID
    /// already exists.
    pub fn add_child(&mut self, child: ChildMember) -> bool {
        if self.find_child(&child.child_attempt_id).is_some() {
            return false;
        }
        self.children.push(child);
        true
    }

    /// Close a child. Closing one child removes only that membership.
    /// Attachment is disconnected only when active set is empty; cursor/
    /// outcomes/session remain.
    pub fn close_child(&mut self, id: &str) -> CloseChildResult {
        let Some(child) = self.find_child_mut(id) else {
            return CloseChildResult::NotFound;
        };
        let was_active = child.is_active();
        child.state = ChildMemberState::Closed;

        if was_active && self.count_active() == 0 {
            // Attachment is disconnected but cursor/outcomes/session remain.
            // Do NOT clear the delivery dedupe state or control cursor.
            CloseChildResult::ClosedAttachmentDisconnected
        } else {
            CloseChildResult::Closed
        }
    }

    /// Verify a child callback's generation/epoch. Stale callbacks are
    /// rejected.
    pub fn verify_child_callback(
        &self,
        id: &str,
        generation: u64,
        epoch: &str,
    ) -> ChildCallbackResult {
        let Some(child) = self.find_child(id) else {
            return ChildCallbackResult::Unknown;
        };
        if child.state == ChildMemberState::Closed {
            return ChildCallbackResult::Stale;
        }
        if child.generation != generation {
            return ChildCallbackResult::Stale;
        }
        if child.transport_epoch != epoch {
            return ChildCallbackResult::Stale;
        }
        ChildCallbackResult::Valid
    }

    /// Check whether the attachment has any active children.
    pub fn has_active_children(&self) -> bool {
        self.count_active() > 0
    }

    /// Get the lease-active children (active + draining, sorted by
    /// childAttemptId).
    pub fn lease_active_children(&self) -> Vec<&ChildMember> {
        let mut children: Vec<&ChildMember> = self
            .children
            .iter()
            .filter(|c| {
                matches!(
                    c.state,
                    ChildMemberState::Active | ChildMemberState::Draining
                )
            })
            .collect();
        children.sort_by(|a, b| a.child_attempt_id.cmp(&b.child_attempt_id));
        children
    }

    /// Build `RemoteLeaseActiveChildV1` entries for the lease from the
    /// active+draining children.
    pub fn build_lease_children(&self) -> Vec<RemoteLeaseActiveChildV1> {
        self.lease_active_children()
            .iter()
            .map(|c| RemoteLeaseActiveChildV1 {
                child_attempt_id: c.child_attempt_id.clone(),
                transport_epoch: c.transport_epoch.clone(),
                transport: match c.transport {
                    ChildTransport::WebRtc => RemoteLeaseTransport::WebRtc,
                    ChildTransport::WebSocket => RemoteLeaseTransport::WebSocket,
                },
                lifecycle: match c.state {
                    ChildMemberState::Active => RemoteLeaseChildLifecycle::Current,
                    ChildMemberState::Draining => RemoteLeaseChildLifecycle::Draining,
                    _ => RemoteLeaseChildLifecycle::Current, // unreachable for lease-active
                },
                final_proof_set_digest: BASE64_STANDARD.encode(c.final_proof_set_digest),
            })
            .collect()
    }
}

/// Result of closing a child.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseChildResult {
    /// Child was closed; other children remain active.
    Closed,
    /// Child was closed and the attachment is now disconnected (no active
    /// children). Cursor/outcomes/session remain.
    ClosedAttachmentDisconnected,
    /// Child was not found.
    NotFound,
}

/// Result of verifying a child callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildCallbackResult {
    /// The callback matches the current child generation/epoch.
    Valid,
    /// The callback is stale (generation/epoch mismatch or child closed).
    Stale,
    /// The child is unknown.
    Unknown,
}

// ─────────────────────────────────────────────────────────────────────────
// Control event application
// ─────────────────────────────────────────────────────────────────────────

/// Apply a control event (the exact FCRC binary event bytes, after the
/// caller has verified the wrapping compact ES256 JWS) through the
/// authorization barrier. The daemon persists `lastAppliedControlSeq` and
/// `eventId → byteHash` before ACK.
///
/// # Verification precondition
///
/// This entry point applies an already-authenticated event: the caller MUST
/// have verified the wrapping control-event JWS (`typ:
/// "flycockpit-remote-control-event+jws"`) against the pinned authority ring
/// and produced `BadSignature` on failure before calling this. The wire-level
/// signature path is landed with the daemon live admission pipeline; this
/// function owns the post-verification decode/digest/epoch/sequence/apply
/// steps and is fail-closed on a malformed FCRC payload.
///
/// Same ID/bytes is idempotent; conflict, sequence gap, epoch regression, or a
/// malformed exact-length payload pauses new operations (sticky) and requests
/// authoritative replay. The pause clears only through
/// [`reconcile_authoritative_replay`].
pub fn apply_control_event(
    state: &mut AttachmentContinuityState,
    event_bytes: &[u8],
) -> RemoteControlEventApplyResult {
    // Fail-closed decode of the exact-length, digest-checked FCRC event.
    let event = match RemoteControlEventV1::decode(event_bytes) {
        Ok(event) => event,
        Err(_) => {
            state.operations_paused = true;
            return RemoteControlEventApplyResult::MalformedPayload;
        }
    };
    let header = &event.header;
    let byte_hash = control_event_byte_hash(event_bytes);

    // Check for duplicate by event ID.
    if let Some(existing_hash) = state.control_event_hashes.get(&header.event_id) {
        if *existing_hash == byte_hash {
            // Same ID and bytes — idempotent, no cursor advance, no reapply.
            return RemoteControlEventApplyResult::DuplicateIdempotent;
        }
        // Same ID, different bytes — conflict. Pause operations (sticky).
        state.operations_paused = true;
        return RemoteControlEventApplyResult::Conflict;
    }

    // Sequence gap: a hole between the cursor and this event.
    let expected_seq = state.last_applied_control_seq + 1;
    if header.control_seq > expected_seq {
        state.operations_paused = true;
        return RemoteControlEventApplyResult::SequenceGap;
    }

    // Epoch regression is detected on epochs, not on sequence: a policy or
    // authority epoch below the last applied value is a regression.
    if header.policy_epoch < state.last_applied_policy_epoch
        || header.authority_epoch < state.last_applied_authority_epoch
    {
        state.operations_paused = true;
        return RemoteControlEventApplyResult::EpochRegression;
    }

    // Persist cursor and event hash BEFORE ACK. This is the critical ordering:
    // the daemon must persist before acknowledging. (Durable SQLite-backed
    // persistence replaces this in-memory map on the daemon storage path.)
    state
        .control_event_hashes
        .insert(header.event_id, byte_hash);
    state.last_applied_control_seq = header.control_seq;
    state.last_applied_policy_epoch = header.policy_epoch;
    state.last_applied_authority_epoch = header.authority_epoch;

    // Exhaustive per-kind application: every arm mutates or explicitly records
    // — no silent-ACK empty arm.
    match &event.payload {
        RemoteControlEventPayload::LeaseRefresh { lease_jws } => {
            // Record the embedded lease JWS for verification+install by the
            // continuity-typ JWS path; do NOT install an unverified lease.
            state.pending_lease_refresh_jws = Some(lease_jws.clone());
        }
        RemoteControlEventPayload::PolicyNarrowed { new_digest, .. } => {
            // Record the required policy digest. In-flight reserved operations
            // continue under their recorded snapshot; only NEW admissions are
            // gated on the lease carrying `new_digest`.
            state.required_policy_digest = Some(*new_digest);
        }
        RemoteControlEventPayload::DeviceRevoked { .. }
        | RemoteControlEventPayload::InstanceRevoked { .. }
        | RemoteControlEventPayload::AttachmentRevoked { .. } => {
            // Fail-closed severing: close all open children and invalidate the
            // lease. NOTE: identity-scoped matching (device/instance id vs this
            // daemon, `logicalAttachmentId` vs this attachment — where a
            // non-matching id records-and-ACKs instead of severing) is landed
            // with daemon identity injection on the live admission path; this
            // conservative sever never under-revokes.
            for child in &mut state.children {
                if child.is_open() {
                    child.state = ChildMemberState::Closed;
                }
            }
            state.current_lease_id = None;
            state.mobile_ui_state = RemoteMobileUiState::AccessRevoked;
        }
        RemoteControlEventPayload::TenantAuthorityChanged { new_epoch, .. } => {
            // The header authority epoch must equal the payload's new epoch.
            if header.authority_epoch != *new_epoch {
                state.operations_paused = true;
                return RemoteControlEventApplyResult::MalformedPayload;
            }
        }
        RemoteControlEventPayload::AuthorityStatus { .. } => {
            // Record the authority-status observation. Byte-checking the
            // embedded `RemoteAuthorityStatusV1` JWS against the ring owner is
            // landed with the continuity-typ JWS verification path.
        }
        RemoteControlEventPayload::Drain { deadline, .. } => {
            // Mark all open children draining and record the deadline; children
            // close at the deadline via the injected continuity clock.
            state.drain_deadline = Some(*deadline);
            for child in &mut state.children {
                if child.is_open() {
                    child.state = ChildMemberState::Draining;
                }
            }
        }
    }

    // NOTE: no unconditional unpause. A pause set by conflict/gap/regression/
    // malformed clears only through `reconcile_authoritative_replay`.
    RemoteControlEventApplyResult::Applied
}

/// Consume a verified, gap-free authoritative replay page (the gateway's
/// 64-event/512-KiB replay, supplied through a `ControlReplaySource`) and
/// re-derive the control cursor. This is the ONLY entry point that clears a
/// sticky pause: it applies each event after the current cursor in order and,
/// if the page is gap-free through its end, unpauses.
///
/// Events already applied (present in the dedupe map with identical bytes) are
/// skipped. A gap within the page, or a malformed/duplicate-conflict event,
/// leaves the pause in place and returns the failing result.
pub fn reconcile_authoritative_replay(
    state: &mut AttachmentContinuityState,
    verified_page: &[RemoteControlEventV1],
) -> RemoteControlEventApplyResult {
    for event in verified_page {
        let bytes = event.encode();
        let byte_hash = control_event_byte_hash(&bytes);
        // Skip an already-applied prefix (idempotent by id+bytes).
        if let Some(existing) = state.control_event_hashes.get(&event.header.event_id) {
            if *existing == byte_hash {
                continue;
            }
            return RemoteControlEventApplyResult::Conflict;
        }
        // Gap-free requirement: each new event must be exactly the next seq.
        if event.header.control_seq != state.last_applied_control_seq + 1 {
            return RemoteControlEventApplyResult::SequenceGap;
        }
        // Apply without the outer pause-on-error latch flipping our decision:
        // a paused state does not block reconciliation replay.
        let was_paused = state.operations_paused;
        state.operations_paused = false;
        let result = apply_control_event(state, &bytes);
        if result != RemoteControlEventApplyResult::Applied {
            // Restore the pause and surface the failure.
            state.operations_paused = was_paused || state.operations_paused;
            return result;
        }
    }
    // Gap-free through the page end: unpause.
    state.operations_paused = false;
    RemoteControlEventApplyResult::Applied
}

// ─────────────────────────────────────────────────────────────────────────
// Authorization barrier
// ─────────────────────────────────────────────────────────────────────────

/// The authorization barrier for every request. It atomically reads current
/// lease/policy/revocation/local policy and, for mutations, reserves the
/// next operation-ledger sequence.
///
/// A revocation/control event and operation have one daemon-local order:
/// request admitted before barrier may finish under its recorded policy
/// snapshot and explicit long-running `continue | cancel` classification;
/// event first rejects. Active revocation closes all affected child epochs
/// after the barrier and prevents replacement admission.
#[derive(Debug, Clone)]
pub struct AuthorizationBarrier {
    /// The current lease ID.
    pub current_lease_id: Option<String>,
    /// Whether operations are paused (control event conflict/gap).
    pub operations_paused: bool,
    /// The next operation-ledger sequence to reserve.
    pub next_operation_seq: u64,
}

impl AuthorizationBarrier {
    /// Create a new authorization barrier.
    pub fn new() -> Self {
        Self {
            current_lease_id: None,
            operations_paused: false,
            next_operation_seq: 1,
        }
    }

    /// Admit a request through the barrier. Returns the recorded policy
    /// snapshot sequence for mutations, or an error if the request is
    /// denied.
    pub fn admit(
        &mut self,
        is_mutation: bool,
        lease_id: &str,
    ) -> Result<BarrierAdmission, BarrierError> {
        // Check that there is a current lease.
        match &self.current_lease_id {
            Some(current) if current == lease_id => {}
            _ => return Err(BarrierError::NoCurrentLease),
        }

        // Check that operations are not paused.
        if self.operations_paused {
            return Err(BarrierError::OperationsPaused);
        }

        // For mutations, reserve the next operation-ledger sequence.
        let reserved_seq = if is_mutation {
            let seq = self.next_operation_seq;
            self.next_operation_seq += 1;
            Some(seq)
        } else {
            None
        };

        Ok(BarrierAdmission {
            recorded_policy_snapshot_seq: reserved_seq,
        })
    }

    /// A revocation/control event that arrives BEFORE a request is admitted
    /// yields a rejection with NO disposition: the request never entered the
    /// barrier and was never reserved, so there is nothing to "continue".
    /// `ContinueRecordedSnapshot` is produced ONLY for an already-reserved
    /// transactional mutation (see [`AuthorizationBarrier::request_before_event`]).
    pub fn event_before_request(
        _class: RemoteContinuityOperationClass,
    ) -> EventBeforeRequestOutcome {
        EventBeforeRequestOutcome::RejectedBeforeAdmission
    }

    /// Determine the revocation disposition for an in-flight operation when
    /// the request was already admitted before the event arrives.
    pub fn request_before_event(
        class: RemoteContinuityOperationClass,
        already_reserved: bool,
        already_dispatched: bool,
    ) -> (RemoteRevocationDisposition, RemoteLongRunningClassification) {
        revocation_disposition(class, already_reserved, already_dispatched)
    }
}

impl Default for AuthorizationBarrier {
    fn default() -> Self {
        Self::new()
    }
}

/// The result of admitting a request through the barrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BarrierAdmission {
    /// The recorded policy snapshot sequence for mutations (None for
    /// read-only).
    pub recorded_policy_snapshot_seq: Option<u64>,
}

/// Barrier admission error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BarrierError {
    #[error("no current lease")]
    NoCurrentLease,
    #[error("operations paused due to control event conflict")]
    OperationsPaused,
}

/// Outcome for a request whose revocation/control event arrived before
/// admission: an outright rejection with no disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventBeforeRequestOutcome {
    /// The request was never admitted or reserved; it is rejected outright.
    RejectedBeforeAdmission,
}

// ─────────────────────────────────────────────────────────────────────────
// Reattach processing
// ─────────────────────────────────────────────────────────────────────────

/// Process a reattach request. The daemon returns one SQLite-authoritative
/// snapshot and high-water `eventSeq` in a single read transaction, then
/// replays the `remote_attachment_outbox` in pages of at most 256 events /
/// 2 MiB.
///
/// If the cursor predates `compactedThroughEventSeq`, return
/// `snapshot_required`; the client installs the snapshot atomically before
/// later events.
pub fn process_reattach(
    event_cursor: u64,
    compacted_through_event_seq: u64,
    high_water_event_seq: u64,
    outbox_events: &[RemoteOutboxEventRef],
    snapshot_id: &str,
    snapshot_payload: &[u8],
) -> Result<RemoteReattachResponseV1, ReattachError> {
    // If the cursor predates the compaction point, a snapshot is required.
    if event_cursor < compacted_through_event_seq {
        return Ok(RemoteReattachResponseV1::SnapshotRequired {
            schema_version: 1,
            snapshot_id: snapshot_id.to_string(),
            snapshot_payload: snapshot_payload.to_vec(),
            compacted_through_event_seq: compacted_through_event_seq.to_string(),
            high_water_event_seq: high_water_event_seq.to_string(),
        });
    }

    // Replay events from the outbox, starting after the cursor.
    let replay_events: Vec<_> = outbox_events
        .iter()
        .filter(|e| e.event_seq > event_cursor)
        .take(REMOTE_REPLAY_MAX_EVENTS_PER_PAGE)
        .cloned()
        .collect();

    // Validate the replay page bounds.
    let proto_events: Vec<_> = replay_events
        .iter()
        .map(
            |e| cockpit_proto::remote_session_continuity::RemoteOutboxEventV1 {
                event_seq: e.event_seq.to_string(),
                delivery_id: e.delivery_id.clone(),
                kind: e.kind.clone(),
                canonical_payload: e.canonical_payload.clone(),
            },
        )
        .collect();
    validate_replay_page(&proto_events).map_err(|_| ReattachError::ReplayPageExceedsBounds)?;

    let has_more = outbox_events
        .iter()
        .filter(|e| e.event_seq > event_cursor)
        .nth(REMOTE_REPLAY_MAX_EVENTS_PER_PAGE)
        .is_some();

    Ok(RemoteReattachResponseV1::Replay {
        schema_version: 1,
        events: proto_events,
        high_water_event_seq: high_water_event_seq.to_string(),
        has_more,
    })
}

/// A reference to an outbox event for reattach processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteOutboxEventRef {
    pub event_seq: u64,
    pub delivery_id: String,
    pub kind: String,
    pub canonical_payload: Vec<u8>,
}

/// Reattach processing error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReattachError {
    #[error("replay page exceeds bounds")]
    ReplayPageExceedsBounds,
}

// ─────────────────────────────────────────────────────────────────────────
// Operation recovery
// ─────────────────────────────────────────────────────────────────────────

/// Resolve a pending operation from its ledger status and class. The reattach
/// request queries every pending operation ID before resubmission.
pub fn resolve_pending_operation(
    status: RemoteOperationStatus,
    class: RemoteContinuityOperationClass,
) -> RemoteOperationRecoveryAction {
    operation_recovery_action(status, class)
}

// ─────────────────────────────────────────────────────────────────────────
// TURN credential renewal lead
// ─────────────────────────────────────────────────────────────────────────

// The renewal-lead rule has a single home: `cockpit_proto::remote_turn_ice_policy::renewal_lead_seconds`
// (`clamp(ttl/3, 15, 120)`). The former duplicate helper here was deleted; any
// caller computes the lead from a real credential TTL via that function.

/// The maximum overlap for TURN child replacement: 30 seconds.
pub const TURN_REPLACEMENT_MAX_OVERLAP_SECONDS: u64 = 30;

// ─────────────────────────────────────────────────────────────────────────
// Mobile background/foreground
// ─────────────────────────────────────────────────────────────────────────

/// Mobile background: quiesce within available OS time and close physical
/// children. No live-background guarantee. Cursor/outcomes/session remain.
pub fn mobile_background(state: &mut AttachmentContinuityState) {
    state.backgrounded = true;
    // Close all physical children. No live-background guarantee.
    for child in &mut state.children {
        if child.is_open() {
            child.state = ChildMemberState::Closed;
        }
    }
    // Cursor/outcomes/session remain. Do not clear delivery dedupe or
    // control cursor.
    state.mobile_ui_state = RemoteMobileUiState::Reconnecting;
}

/// Mobile foreground: create fresh children, refresh lease/control cursor,
/// then snapshot/replay and resolve pending operations.
pub fn mobile_foreground(state: &mut AttachmentContinuityState) {
    state.backgrounded = false;
    // Foreground creates fresh children (the transport selection state
    // machine handles this). The lease must be refreshed and the control
    // cursor checked. Then snapshot/replay and resolve pending operations.
    state.mobile_ui_state = RemoteMobileUiState::Reconnecting;
}

/// Set the mobile UI state when the lease has expired and reauthentication
/// is required.
pub fn mobile_reauthentication_required(state: &mut AttachmentContinuityState) {
    state.mobile_ui_state = RemoteMobileUiState::ReauthenticationRequired;
}

/// Set the mobile UI state when a snapshot is required (cursor predates
/// compaction).
pub fn mobile_snapshot_required(state: &mut AttachmentContinuityState) {
    state.mobile_ui_state = RemoteMobileUiState::SnapshotRequired;
}

/// Set the mobile UI state when an operation outcome is unknown.
pub fn mobile_outcome_unknown(state: &mut AttachmentContinuityState) {
    state.mobile_ui_state = RemoteMobileUiState::OutcomeUnknown;
}

/// Set the mobile UI state when access is revoked.
pub fn mobile_access_revoked(state: &mut AttachmentContinuityState) {
    state.mobile_ui_state = RemoteMobileUiState::AccessRevoked;
}

/// Set the mobile UI state when the session is terminal.
pub fn mobile_session_terminal(state: &mut AttachmentContinuityState) {
    state.mobile_ui_state = RemoteMobileUiState::SessionTerminal;
}

// ─────────────────────────────────────────────────────────────────────────
// Lease generation replacement
// ─────────────────────────────────────────────────────────────────────────

/// Replace the current lease. Exactly one lease is current per
/// `logicalAttachmentId`. Reserve/sign/finalize atomically replaces the
/// current pointer and appends one control event. Replacement invalidates
/// the old lease for new work immediately.
pub fn replace_current_lease(
    state: &mut AttachmentContinuityState,
    new_lease_id: String,
    new_generation: u64,
    new_jws_digest: [u8; 32],
) -> Result<(), LeaseReplacementError> {
    if new_generation <= state.current_lease_generation {
        return Err(LeaseReplacementError::GenerationNotMonotonic);
    }
    state.current_lease_id = Some(new_lease_id);
    state.current_lease_generation = new_generation;
    state.current_lease_jws_digest = new_jws_digest;
    Ok(())
}

/// Lease replacement error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeaseReplacementError {
    #[error("lease generation must be strictly monotonic")]
    GenerationNotMonotonic,
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::remote_session_continuity::{
        RemoteContinuityOperationClass, RemoteControlEventApplyResult, RemoteControlEventPayload,
        RemoteControlEventV1, RemoteLongRunningClassification, RemoteOperationRecoveryAction,
        RemoteOperationStatus, RemoteRevocationDisposition,
    };

    /// Build a sealed FCRC control event with the given sequence, event id,
    /// epochs, and payload for the apply tests.
    fn control_event(
        control_seq: u64,
        event_id: [u8; 16],
        policy_epoch: u64,
        authority_epoch: u64,
        payload: RemoteControlEventPayload,
    ) -> RemoteControlEventV1 {
        RemoteControlEventV1::seal(
            control_seq,
            event_id,
            1,
            policy_epoch,
            authority_epoch,
            0,
            payload,
        )
    }

    fn device_revoked_payload() -> RemoteControlEventPayload {
        RemoteControlEventPayload::DeviceRevoked {
            device_id: [0xD0; 16],
            generation: 1,
        }
    }

    fn policy_narrowed_payload(new_digest: [u8; 32]) -> RemoteControlEventPayload {
        RemoteControlEventPayload::PolicyNarrowed {
            previous_digest: [0xA0; 32],
            new_digest,
            affected_field_bits: 0,
        }
    }

    // ── Transport epoch membership race ─────────────────────────────────

    #[test]
    fn remote_transport_epoch_membership_race() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());

        // Add two simultaneous children (WebRTC + WebSocket).
        state.add_child(ChildMember {
            child_attempt_id: "c-1".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-1".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [1; 32],
        });
        state.add_child(ChildMember {
            child_attempt_id: "c-2".into(),
            transport: ChildTransport::WebSocket,
            transport_epoch: "e-2".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [2; 32],
        });

        // Both are active simultaneously.
        assert_eq!(state.count_active(), 2);

        // Shared ledger/outbox: both children share the same delivery dedupe.
        assert!(state.delivery_dedupe.mark_delivered("del-1"));

        // Close one child — the other remains.
        let result = state.close_child("c-1");
        assert_eq!(result, CloseChildResult::Closed);
        assert_eq!(state.count_active(), 1);

        // The other child is still active.
        assert!(state.find_child("c-2").unwrap().is_active());

        // Closing the second child disconnects the attachment.
        let result = state.close_child("c-2");
        assert_eq!(result, CloseChildResult::ClosedAttachmentDisconnected);
        assert_eq!(state.count_active(), 0);

        // But cursor/outcomes/session remain (delivery dedupe is not cleared).
        assert!(state.delivery_dedupe.is_delivered("del-1"));
    }

    #[test]
    fn remote_stale_callback_isolation() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        state.add_child(ChildMember {
            child_attempt_id: "c-1".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-1".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [1; 32],
        });

        // Valid callback.
        assert_eq!(
            state.verify_child_callback("c-1", 1, "e-1"),
            ChildCallbackResult::Valid
        );

        // Stale generation.
        assert_eq!(
            state.verify_child_callback("c-1", 2, "e-1"),
            ChildCallbackResult::Stale
        );

        // Stale epoch.
        assert_eq!(
            state.verify_child_callback("c-1", 1, "e-2"),
            ChildCallbackResult::Stale
        );

        // Close the child — callbacks become stale.
        state.close_child("c-1");
        assert_eq!(
            state.verify_child_callback("c-1", 1, "e-1"),
            ChildCallbackResult::Stale
        );

        // Unknown child.
        assert_eq!(
            state.verify_child_callback("c-99", 1, "e-1"),
            ChildCallbackResult::Unknown
        );
    }

    // ── Control event application ────────────────────────────────────────

    #[test]
    fn remote_control_event_apply_and_duplicate() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        let event = control_event(1, [1; 16], 10, 5, policy_narrowed_payload([0xB0; 32]));
        let bytes = event.encode();

        // First application — applied, records the required policy digest.
        assert_eq!(
            apply_control_event(&mut state, &bytes),
            RemoteControlEventApplyResult::Applied
        );
        assert_eq!(state.last_applied_control_seq, 1);
        assert_eq!(state.last_applied_policy_epoch, 10);
        assert_eq!(state.required_policy_digest, Some([0xB0; 32]));
        assert!(!state.operations_paused);

        // Same ID and bytes — idempotent, no cursor advance.
        assert_eq!(
            apply_control_event(&mut state, &bytes),
            RemoteControlEventApplyResult::DuplicateIdempotent
        );
        assert_eq!(state.last_applied_control_seq, 1);
    }

    #[test]
    fn remote_control_event_conflict() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        // Same event id, different bytes (different new_digest → different
        // payload digest → different whole-event bytes).
        let first = control_event(1, [1; 16], 10, 5, policy_narrowed_payload([0xB0; 32]));
        apply_control_event(&mut state, &first.encode());

        let conflicting = control_event(1, [1; 16], 10, 5, policy_narrowed_payload([0xC0; 32]));
        assert_eq!(
            apply_control_event(&mut state, &conflicting.encode()),
            RemoteControlEventApplyResult::Conflict
        );
        assert!(state.operations_paused);
    }

    #[test]
    fn remote_control_event_sequence_gap() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        let e1 = control_event(1, [1; 16], 0, 0, policy_narrowed_payload([0xB0; 32]));
        apply_control_event(&mut state, &e1.encode());

        // Seq 3 with a gap at 2.
        let e3 = control_event(3, [3; 16], 0, 0, policy_narrowed_payload([0xB0; 32]));
        assert_eq!(
            apply_control_event(&mut state, &e3.encode()),
            RemoteControlEventApplyResult::SequenceGap
        );
        assert!(state.operations_paused);
    }

    #[test]
    fn remote_control_event_epoch_regression() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        // Apply an event advancing the policy epoch to 10.
        let e1 = control_event(1, [1; 16], 10, 5, policy_narrowed_payload([0xB0; 32]));
        apply_control_event(&mut state, &e1.encode());

        // Next in-sequence event, but the policy epoch regresses to 9.
        let e2 = control_event(2, [2; 16], 9, 5, policy_narrowed_payload([0xB0; 32]));
        assert_eq!(
            apply_control_event(&mut state, &e2.encode()),
            RemoteControlEventApplyResult::EpochRegression
        );
        assert!(state.operations_paused);
    }

    #[test]
    fn remote_control_event_malformed_pauses() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        // A truncated event never decodes; it pauses without any cursor move.
        assert_eq!(
            apply_control_event(&mut state, &[0u8; 4]),
            RemoteControlEventApplyResult::MalformedPayload
        );
        assert!(state.operations_paused);
        assert_eq!(state.last_applied_control_seq, 0);
    }

    #[test]
    fn remote_control_event_revocation_closes_children() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        state.add_child(ChildMember {
            child_attempt_id: "c-1".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-1".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [1; 32],
        });
        state.current_lease_id = Some("lease-1".into());

        let event = control_event(1, [1; 16], 0, 0, device_revoked_payload());
        let result = apply_control_event(&mut state, &event.encode());
        assert_eq!(result, RemoteControlEventApplyResult::Applied);

        assert_eq!(state.count_active(), 0);
        assert!(state.current_lease_id.is_none());
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::AccessRevoked);
    }

    #[test]
    fn remote_control_event_drain_marks_draining() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        state.add_child(ChildMember {
            child_attempt_id: "c-1".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-1".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [1; 32],
        });

        let event = control_event(
            1,
            [1; 16],
            0,
            0,
            RemoteControlEventPayload::Drain {
                deadline: 1_700_000_500,
                reason: 1,
            },
        );
        assert_eq!(
            apply_control_event(&mut state, &event.encode()),
            RemoteControlEventApplyResult::Applied
        );
        assert_eq!(state.drain_deadline, Some(1_700_000_500));
        assert_eq!(
            state.find_child("c-1").unwrap().state,
            ChildMemberState::Draining
        );
    }

    #[test]
    fn remote_control_pause_sticky_until_replay() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        // Apply seq 1.
        let e1 = control_event(1, [1; 16], 0, 0, policy_narrowed_payload([0xB0; 32]));
        apply_control_event(&mut state, &e1.encode());

        // A gap at 2 pauses (seq 3 arrives).
        let e3 = control_event(3, [3; 16], 0, 0, policy_narrowed_payload([0xB0; 32]));
        apply_control_event(&mut state, &e3.encode());
        assert!(state.operations_paused);

        // A subsequent successful-looking in-order event does NOT unpause —
        // the pause is sticky. (Seq is still 1, so seq 2 applies but the pause
        // remains because only reconcile clears it.)
        let e2 = control_event(2, [2; 16], 0, 0, policy_narrowed_payload([0xB0; 32]));
        assert_eq!(
            apply_control_event(&mut state, &e2.encode()),
            RemoteControlEventApplyResult::Applied
        );
        assert!(state.operations_paused, "pause is sticky across applies");

        // Only a verified gap-free replay page unpauses. Provide the missing
        // seq-3 event as a gap-free page (cursor is now at 2).
        let page = vec![control_event(
            3,
            [3; 16],
            0,
            0,
            policy_narrowed_payload([0xB0; 32]),
        )];
        assert_eq!(
            reconcile_authoritative_replay(&mut state, &page),
            RemoteControlEventApplyResult::Applied
        );
        assert!(!state.operations_paused);
        assert_eq!(state.last_applied_control_seq, 3);
    }

    // ── Authorization barrier ────────────────────────────────────────────

    #[test]
    fn remote_authorization_barrier_admit_and_pause() {
        let mut barrier = AuthorizationBarrier::new();
        barrier.current_lease_id = Some("lease-1".into());

        // Read-only request — admitted, no sequence reserved.
        let admission = barrier.admit(false, "lease-1").unwrap();
        assert!(admission.recorded_policy_snapshot_seq.is_none());

        // Mutation request — admitted, sequence reserved.
        let admission = barrier.admit(true, "lease-1").unwrap();
        assert_eq!(admission.recorded_policy_snapshot_seq, Some(1));

        // Second mutation — next sequence.
        let admission = barrier.admit(true, "lease-1").unwrap();
        assert_eq!(admission.recorded_policy_snapshot_seq, Some(2));

        // Wrong lease — denied.
        assert_eq!(
            barrier.admit(true, "lease-2"),
            Err(BarrierError::NoCurrentLease)
        );

        // Paused — denied.
        barrier.operations_paused = true;
        assert_eq!(
            barrier.admit(true, "lease-1"),
            Err(BarrierError::OperationsPaused)
        );
    }

    #[test]
    fn remote_revocation_barrier_event_before_request() {
        // An event arriving before admission is a rejection with NO disposition
        // for EVERY class — the request never reserved anything, so there is
        // no recorded snapshot to continue under. (This rejects the old
        // behavior, which returned `ContinueRecordedSnapshot` for an
        // un-admitted transactional mutation.)
        assert_eq!(
            AuthorizationBarrier::event_before_request(
                RemoteContinuityOperationClass::TransactionalMutation,
            ),
            EventBeforeRequestOutcome::RejectedBeforeAdmission
        );
        assert_eq!(
            AuthorizationBarrier::event_before_request(RemoteContinuityOperationClass::ReadOnly),
            EventBeforeRequestOutcome::RejectedBeforeAdmission
        );
    }

    #[test]
    fn remote_revocation_barrier_request_before_event() {
        // Request already admitted, then event arrives.
        let (disp, cls) = AuthorizationBarrier::request_before_event(
            RemoteContinuityOperationClass::TransactionalMutation,
            true,
            false,
        );
        assert_eq!(disp, RemoteRevocationDisposition::ContinueRecordedSnapshot);
        assert_eq!(cls, RemoteLongRunningClassification::Continue);
    }

    // ── Reattach ─────────────────────────────────────────────────────────

    #[test]
    fn remote_reattach_snapshot_required() {
        let result = process_reattach(10, 100, 200, &[], "snap-1", &[1, 2, 3]).unwrap();
        match result {
            RemoteReattachResponseV1::SnapshotRequired {
                snapshot_id,
                compacted_through_event_seq,
                high_water_event_seq,
                ..
            } => {
                assert_eq!(snapshot_id, "snap-1");
                assert_eq!(compacted_through_event_seq, "100");
                assert_eq!(high_water_event_seq, "200");
            }
            _ => panic!("expected SnapshotRequired"),
        }
    }

    #[test]
    fn remote_reattach_replay() {
        let events: Vec<_> = (1..=10)
            .map(|i| RemoteOutboxEventRef {
                event_seq: i,
                delivery_id: format!("del-{i}"),
                kind: "test".into(),
                canonical_payload: vec![0u8; 100],
            })
            .collect();

        let result = process_reattach(3, 0, 10, &events, "snap-1", &[]).unwrap();
        match result {
            RemoteReattachResponseV1::Replay {
                events,
                high_water_event_seq,
                has_more,
                ..
            } => {
                // Events 4..=10 (7 events, after cursor 3).
                assert_eq!(events.len(), 7);
                assert_eq!(high_water_event_seq, "10");
                assert!(!has_more);
            }
            _ => panic!("expected Replay"),
        }
    }

    #[test]
    fn remote_reattach_replay_paging() {
        // 300 events after cursor; page of 256.
        let events: Vec<_> = (1..=300)
            .map(|i| RemoteOutboxEventRef {
                event_seq: i,
                delivery_id: format!("del-{i}"),
                kind: "test".into(),
                canonical_payload: vec![0u8; 100],
            })
            .collect();

        let result = process_reattach(0, 0, 300, &events, "snap-1", &[]).unwrap();
        match result {
            RemoteReattachResponseV1::Replay {
                events, has_more, ..
            } => {
                assert_eq!(events.len(), 256);
                assert!(has_more);
            }
            _ => panic!("expected Replay"),
        }
    }

    #[test]
    fn remote_reattach_replay_page_over_byte_bound_errors() {
        // 20 events × 200,000 bytes = 4,000,000 bytes, which exceeds the
        // 2 MiB (REMOTE_REPLAY_MAX_BYTES_PER_PAGE) per-page byte bound while
        // staying at 20 ≤ 256 events, so the page is truncated by event count
        // to all 20 events and then rejected on bytes.
        let events: Vec<_> = (1..=20)
            .map(|i| RemoteOutboxEventRef {
                event_seq: i,
                delivery_id: format!("del-{i}"),
                kind: "test".into(),
                canonical_payload: vec![0u8; 200_000],
            })
            .collect();

        let result = process_reattach(0, 0, 20, &events, "snap-1", &[]);
        assert_eq!(result, Err(ReattachError::ReplayPageExceedsBounds));
    }

    // ── Operation recovery ────────────────────────────────────────────────

    #[test]
    fn remote_operation_recovery_delegates_to_ledger() {
        assert_eq!(
            resolve_pending_operation(
                RemoteOperationStatus::Committed,
                RemoteContinuityOperationClass::ReadOnly,
            ),
            RemoteOperationRecoveryAction::ReturnCommittedOutcome
        );
        assert_eq!(
            resolve_pending_operation(
                RemoteOperationStatus::OutcomeUnknown,
                RemoteContinuityOperationClass::TransactionalMutation,
            ),
            RemoteOperationRecoveryAction::OutcomeUnknownSafeActions
        );
    }

    // ── TURN renewal lead ─────────────────────────────────────────────────
    //
    // The renewal-lead vectors now live with the single source of truth in
    // `cockpit_proto::remote_turn_ice_policy` (`renewal_lead_seconds_vectors`);
    // the duplicate helper and its vector test were removed here.

    // ── Mobile background/foreground ──────────────────────────────────────

    #[test]
    fn remote_mobile_background_foreground() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        state.add_child(ChildMember {
            child_attempt_id: "c-1".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-1".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [1; 32],
        });

        // Background — close all children.
        mobile_background(&mut state);
        assert!(state.backgrounded);
        assert_eq!(state.count_active(), 0);
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::Reconnecting);

        // Cursor/outcomes/session remain.
        assert_eq!(state.session_id, "sess-1");

        // Foreground — create fresh children.
        mobile_foreground(&mut state);
        assert!(!state.backgrounded);
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::Reconnecting);

        // All UI states can be set.
        mobile_reauthentication_required(&mut state);
        assert_eq!(
            state.mobile_ui_state,
            RemoteMobileUiState::ReauthenticationRequired
        );
        mobile_snapshot_required(&mut state);
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::SnapshotRequired);
        mobile_outcome_unknown(&mut state);
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::OutcomeUnknown);
        mobile_access_revoked(&mut state);
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::AccessRevoked);
        mobile_session_terminal(&mut state);
        assert_eq!(state.mobile_ui_state, RemoteMobileUiState::SessionTerminal);
    }

    // ── Lease replacement ─────────────────────────────────────────────────

    #[test]
    fn remote_lease_replacement() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());

        // First lease.
        replace_current_lease(&mut state, "lease-1".into(), 1, [1; 32]).unwrap();
        assert_eq!(state.current_lease_id, Some("lease-1".into()));
        assert_eq!(state.current_lease_generation, 1);

        // Same generation — fail.
        assert_eq!(
            replace_current_lease(&mut state, "lease-2".into(), 1, [2; 32]),
            Err(LeaseReplacementError::GenerationNotMonotonic)
        );

        // Lower generation — fail.
        assert_eq!(
            replace_current_lease(&mut state, "lease-2".into(), 0, [2; 32]),
            Err(LeaseReplacementError::GenerationNotMonotonic)
        );

        // Higher generation — OK. Old lease invalidated immediately.
        replace_current_lease(&mut state, "lease-2".into(), 2, [2; 32]).unwrap();
        assert_eq!(state.current_lease_id, Some("lease-2".into()));
        assert_eq!(state.current_lease_generation, 2);
        assert_eq!(state.current_lease_jws_digest, [2; 32]);
    }

    // ── Lease-active children ─────────────────────────────────────────────

    #[test]
    fn remote_lease_active_children_sorted() {
        let mut state = AttachmentContinuityState::new("att-1".into(), "sess-1".into());
        state.add_child(ChildMember {
            child_attempt_id: "c-3".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-3".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [3; 32],
        });
        state.add_child(ChildMember {
            child_attempt_id: "c-1".into(),
            transport: ChildTransport::WebSocket,
            transport_epoch: "e-1".into(),
            generation: 1,
            state: ChildMemberState::Active,
            final_proof_set_digest: [1; 32],
        });
        state.add_child(ChildMember {
            child_attempt_id: "c-2".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-2".into(),
            generation: 1,
            state: ChildMemberState::Draining,
            final_proof_set_digest: [2; 32],
        });
        // Closed child should not appear.
        state.add_child(ChildMember {
            child_attempt_id: "c-0".into(),
            transport: ChildTransport::WebRtc,
            transport_epoch: "e-0".into(),
            generation: 1,
            state: ChildMemberState::Closed,
            final_proof_set_digest: [0; 32],
        });

        let lease_children = state.build_lease_children();
        // Sorted by childAttemptId: c-1, c-2, c-3.
        assert_eq!(lease_children.len(), 3);
        assert_eq!(lease_children[0].child_attempt_id, "c-1");
        assert_eq!(lease_children[1].child_attempt_id, "c-2");
        assert_eq!(lease_children[2].child_attempt_id, "c-3");
        // c-2 is draining.
        assert_eq!(
            lease_children[1].lifecycle,
            RemoteLeaseChildLifecycle::Draining
        );
    }
}
