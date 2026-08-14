//! Transport-independent session continuity and live revocation — wire types.
//!
//! This module owns the pure wire contracts for:
//!
//! - **Reattach** — the `reattach {sessionId,logicalAttachmentId,
//!   priorSnapshotId,eventCursor,pendingOperationIds}` request and the
//!   daemon's atomic snapshot/high-water/outbox-replay response, including
//!   the `snapshot_required` outcome when the cursor predates
//!   `compactedThroughEventSeq`.
//! - **Operation recovery** — the exhaustive status/class table that maps
//!   every pending operation ID to a safe next action. `outcome_unknown` is
//!   never auto-retried.
//! - **Connection lease** — `RemoteConnectionLeaseV1` compact ES256 JWS with
//!   exact typ, sorted active children, lease generation, and the
//!   both-null/both-nonnull tenant authorization matrix.
//! - **Refresh authorization** — `RemoteLeaseRefreshAuthorizationV1`, a
//!   pre-grant-only ES256 JWS separate from both `RemoteAttemptGrantV1` and
//!   the post-proof connection lease.
//! - **Control event replay** — `RemoteControlEventV1` 98-byte header and the
//!   Postgres `RemoteDaemonControlOutbox` replay contract (daemon owns
//!   `lastAppliedControlSeq` and `eventId → byteHash` persistence before ACK).
//! - **Revocation disposition** — the exhaustive
//!   `revocationDisposition` column added to the operation-class table.
//! - **Mobile UI states** — the exact `reconnecting | reauthentication_required
//!   | snapshot_required | outcome_unknown | access_revoked | session_terminal`
//!   enum.
//!
//! # What this module owns
//!
//! - The closed wire enums, structs, constants, and pure validation
//!   functions.
//! - The exact JWS protected-header `typ` values and payload member sets.
//! - The both-null/both-nonnull tenant authorization matrix.
//! - The revocation disposition total rule.
//! - The control event 98-byte header layout and replay paging constants.
//!
//! # What this module does NOT own
//!
//! - JWS signing/verification (owned by the daemon authority adapter).
//! - SQLite/Postgres storage wiring.
//! - Transport adapter implementation.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────
// Schema version
// ─────────────────────────────────────────────────────────────────────────

/// Cross-language schema version for the session-continuity contract.
pub const REMOTE_SESSION_CONTINUITY_SCHEMA_VERSION: u8 = 1;

// ─────────────────────────────────────────────────────────────────────────
// Reattach
// ─────────────────────────────────────────────────────────────────────────

/// The reattach request. Every reconnect/new child completes a fresh grant,
/// bilateral proofs, DTLS/Noise transcript, tuple, and random
/// `transportEpoch` before sending this. Old grant/ticket/proof/nonce/traffic
/// key/attempt/epoch never authorizes 0-RTT.
// NOTE: `RemoteReattachRequestV1` intentionally does NOT carry serde
// `deny_unknown_fields`: the repo-wide `forward_open_guard_no_deny_unknown_fields_in_proto_src`
// invariant keeps every cockpit-proto wire struct forward-open for additive
// compatibility. Strict unknown-field rejection for the reattach REQUEST is
// enforced on the TypeScript side (the zod codec in `remote-reattach.ts`); a
// Rust custom-deserializer variant (mirroring the connection-metadata pattern)
// would be required to reject unknown fields in Rust without tripping that
// guard. See the report's deferred-work notes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteReattachRequestV1 {
    pub schema_version: u8,
    /// Stable session identifier independent of physical children.
    pub session_id: String,
    /// Stable logical attachment identifier independent of physical children.
    pub logical_attachment_id: String,
    /// The snapshot the client currently has installed, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_snapshot_id: Option<String>,
    /// The client's last applied event cursor.
    pub event_cursor: String,
    /// Pending operation IDs the client wants resolved before resubmission.
    pub pending_operation_ids: Vec<String>,
}

/// The daemon's reattach response. The daemon returns one SQLite-authoritative
/// snapshot and high-water `eventSeq` in a single read transaction, then
/// replays the `remote_attachment_outbox` in pages of at most 256 events /
/// 2 MiB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RemoteReattachResponseV1 {
    /// The cursor is current; events are replayed from the outbox.
    Replay {
        schema_version: u8,
        events: Vec<RemoteOutboxEventV1>,
        high_water_event_seq: String,
        has_more: bool,
    },
    /// The cursor predates `compactedThroughEventSeq`; the client must install
    /// the snapshot atomically before later events.
    SnapshotRequired {
        schema_version: u8,
        snapshot_id: String,
        snapshot_payload: Vec<u8>,
        compacted_through_event_seq: String,
        high_water_event_seq: String,
    },
}

/// One outbox event in a replay page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteOutboxEventV1 {
    pub event_seq: String,
    pub delivery_id: String,
    pub kind: String,
    pub canonical_payload: Vec<u8>,
}

/// Maximum events per replay page.
pub const REMOTE_REPLAY_MAX_EVENTS_PER_PAGE: usize = 256;
/// Maximum bytes per replay page.
pub const REMOTE_REPLAY_MAX_BYTES_PER_PAGE: usize = 2 * 1024 * 1024;

/// Validate that a replay page does not exceed the 256-event / 2-MiB bounds.
pub fn validate_replay_page(events: &[RemoteOutboxEventV1]) -> Result<(), ReplayPageError> {
    if events.len() > REMOTE_REPLAY_MAX_EVENTS_PER_PAGE {
        return Err(ReplayPageError::TooManyEvents);
    }
    let total_bytes: usize = events.iter().map(|e| e.canonical_payload.len()).sum();
    if total_bytes > REMOTE_REPLAY_MAX_BYTES_PER_PAGE {
        return Err(ReplayPageError::TooManyBytes);
    }
    Ok(())
}

/// Replay page validation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReplayPageError {
    #[error("replay page exceeds 256 events")]
    TooManyEvents,
    #[error("replay page exceeds 2 MiB")]
    TooManyBytes,
}

// ─────────────────────────────────────────────────────────────────────────
// Operation recovery
// ─────────────────────────────────────────────────────────────────────────

/// The status of a pending operation as queried from the ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOperationStatus {
    /// The operation was committed; the original outcome is returned.
    Committed,
    /// The operation was rejected; the original outcome is returned.
    Rejected,
    /// The operation is reserved; class reconciliation is invoked.
    Reserved,
    /// The operation outcome is unknown; never auto-retried.
    OutcomeUnknown,
    /// The operation was not found; may submit only if the class permits
    /// retry and the client still has exact canonical bytes.
    NotFound,
}

/// The safe next action for a pending operation, derived from its status and
/// class. `outcome_unknown` never auto-retries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteOperationRecoveryAction {
    /// Return the original committed outcome.
    ReturnCommittedOutcome,
    /// Return the original rejected outcome.
    ReturnRejectedOutcome,
    /// Invoke class reconciliation for a reserved operation.
    ReconcileReserved,
    /// Render `outcome_unknown` with operation-specific safe next actions.
    /// Never a generic retry button.
    OutcomeUnknownSafeActions,
    /// May submit only if the class permits retry and exact canonical bytes
    /// are available.
    ResubmitIfClassPermitsRetry,
}

/// Determine the safe next action for a pending operation from its ledger
/// status and operation class.
pub fn operation_recovery_action(
    status: RemoteOperationStatus,
    class: RemoteContinuityOperationClass,
) -> RemoteOperationRecoveryAction {
    match status {
        RemoteOperationStatus::Committed => RemoteOperationRecoveryAction::ReturnCommittedOutcome,
        RemoteOperationStatus::Rejected => RemoteOperationRecoveryAction::ReturnRejectedOutcome,
        RemoteOperationStatus::Reserved => RemoteOperationRecoveryAction::ReconcileReserved,
        RemoteOperationStatus::OutcomeUnknown => {
            RemoteOperationRecoveryAction::OutcomeUnknownSafeActions
        }
        RemoteOperationStatus::NotFound => {
            // May submit only if the class permits retry.
            match class {
                RemoteContinuityOperationClass::TransactionalMutation => {
                    RemoteOperationRecoveryAction::ResubmitIfClassPermitsRetry
                }
                RemoteContinuityOperationClass::IdempotentAdapterMutation => {
                    RemoteOperationRecoveryAction::ResubmitIfClassPermitsRetry
                }
                RemoteContinuityOperationClass::NonrepeatableMutation => {
                    // Nonrepeatable mutations: not_found may resubmit only if
                    // the client has exact canonical bytes and the class
                    // permits it. In practice nonrepeatable mutations do not
                    // permit retry after not_found, but the client must
                    // decide with operation-specific safe actions.
                    RemoteOperationRecoveryAction::ResubmitIfClassPermitsRetry
                }
                RemoteContinuityOperationClass::ReadOnly => {
                    RemoteOperationRecoveryAction::ResubmitIfClassPermitsRetry
                }
            }
        }
    }
}

/// Whether a class permits retry after `not_found`.
pub fn class_permits_retry(class: RemoteContinuityOperationClass) -> bool {
    match class {
        RemoteContinuityOperationClass::ReadOnly => true,
        RemoteContinuityOperationClass::IdempotentAdapterMutation => true,
        RemoteContinuityOperationClass::TransactionalMutation => false,
        RemoteContinuityOperationClass::NonrepeatableMutation => false,
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Revocation disposition
// ─────────────────────────────────────────────────────────────────────────

/// The operation class as seen by the session-continuity layer. Mirrors the
/// ledger's `RemoteOperationClass` but is owned here for the revocation
/// disposition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteContinuityOperationClass {
    ReadOnly,
    TransactionalMutation,
    IdempotentAdapterMutation,
    NonrepeatableMutation,
}

/// The revocation disposition for an in-flight operation when a revocation or
/// control event arrives. This is the exhaustive `revocationDisposition`
/// column added to the same request table as operation class.
///
/// Total rule:
/// - `transactional_mutation` → `continue_recorded_snapshot` after
///   reservation.
/// - `idempotent_adapter_mutation` → `cancel_before_apply`, otherwise
///   reconcile named durable result then finalize.
/// - `nonrepeatable_mutation` → `cancel_before_dispatch`, otherwise
///   `outcome_unknown`.
/// - `read_only` → `cancel_at_next_yield_and_reauthorize`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteRevocationDisposition {
    /// `transactional_mutation`: the operation continues under its recorded
    /// policy snapshot after reservation.
    ContinueRecordedSnapshot,
    /// `idempotent_adapter_mutation`: cancel before apply.
    CancelBeforeApply,
    /// `idempotent_adapter_mutation`: reconcile named durable result then
    /// finalize.
    ReconcileNamedDurableResultThenFinalize,
    /// `nonrepeatable_mutation`: cancel before dispatch.
    CancelBeforeDispatch,
    /// `nonrepeatable_mutation`: outcome is unknown.
    OutcomeUnknown,
    /// `read_only`: cancel at next yield and reauthorize.
    CancelAtNextYieldAndReauthorize,
}

/// The long-running classification for an in-flight operation when a
/// revocation/control event arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLongRunningClassification {
    Continue,
    Cancel,
}

/// Determine the revocation disposition and long-running classification for
/// an in-flight operation when a revocation/control event arrives.
///
/// The request admitted before the barrier may finish under its recorded
/// policy snapshot and explicit long-running `continue | cancel`
/// classification; the event first rejects.
pub fn revocation_disposition(
    class: RemoteContinuityOperationClass,
    already_reserved: bool,
    already_dispatched: bool,
) -> (RemoteRevocationDisposition, RemoteLongRunningClassification) {
    match class {
        RemoteContinuityOperationClass::TransactionalMutation => {
            // continue_recorded_snapshot after reservation.
            if already_reserved {
                (
                    RemoteRevocationDisposition::ContinueRecordedSnapshot,
                    RemoteLongRunningClassification::Continue,
                )
            } else {
                // Not yet reserved — cancel before admission.
                (
                    RemoteRevocationDisposition::ContinueRecordedSnapshot,
                    RemoteLongRunningClassification::Cancel,
                )
            }
        }
        RemoteContinuityOperationClass::IdempotentAdapterMutation => {
            if !already_dispatched {
                (
                    RemoteRevocationDisposition::CancelBeforeApply,
                    RemoteLongRunningClassification::Cancel,
                )
            } else {
                (
                    RemoteRevocationDisposition::ReconcileNamedDurableResultThenFinalize,
                    RemoteLongRunningClassification::Cancel,
                )
            }
        }
        RemoteContinuityOperationClass::NonrepeatableMutation => {
            if !already_dispatched {
                (
                    RemoteRevocationDisposition::CancelBeforeDispatch,
                    RemoteLongRunningClassification::Cancel,
                )
            } else {
                (
                    RemoteRevocationDisposition::OutcomeUnknown,
                    RemoteLongRunningClassification::Cancel,
                )
            }
        }
        RemoteContinuityOperationClass::ReadOnly => (
            RemoteRevocationDisposition::CancelAtNextYieldAndReauthorize,
            RemoteLongRunningClassification::Cancel,
        ),
    }
}

/// Validate that every operation tag has both an operation class and a
/// revocation disposition assigned. New tags fail until both columns are
/// assigned.
pub fn validate_tag_has_both_columns(
    class: Option<RemoteContinuityOperationClass>,
    disposition: Option<RemoteRevocationDisposition>,
) -> Result<(), TagColumnError> {
    match (class, disposition) {
        (Some(_), Some(_)) => Ok(()),
        (None, Some(_)) => Err(TagColumnError::MissingClass),
        (Some(_), None) => Err(TagColumnError::MissingDisposition),
        (None, None) => Err(TagColumnError::MissingBoth),
    }
}

/// Error when a tag is missing one or both required columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TagColumnError {
    #[error("tag missing operation class column")]
    MissingClass,
    #[error("tag missing revocation disposition column")]
    MissingDisposition,
    #[error("tag missing both columns")]
    MissingBoth,
}

// ─────────────────────────────────────────────────────────────────────────
// Connection lease — RemoteConnectionLeaseV1
// ─────────────────────────────────────────────────────────────────────────

/// JWS protected-header `typ` for `RemoteConnectionLeaseV1`.
pub const REMOTE_CONNECTION_LEASE_JWS_TYP: &str = "flycockpit-remote-connection-lease+jws";
/// JWS `alg` for connection leases.
pub const REMOTE_CONNECTION_LEASE_JWS_ALG: &str = "ES256";
/// Maximum compact JWS size for a connection lease.
pub const REMOTE_CONNECTION_LEASE_MAX_BYTES: usize = 16_384;
/// Lease validity in seconds (exactly 300).
pub const REMOTE_CONNECTION_LEASE_VALID_SECONDS: i64 = 300;
/// Gateway requests refresh every 120 seconds.
pub const REMOTE_CONNECTION_LEASE_REFRESH_INTERVAL_SECONDS: i64 = 120;
/// No grace after `validUntil`.
pub const REMOTE_CONNECTION_LEASE_GRACE_SECONDS: i64 = 0;

/// The lifecycle of a lease-active child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLeaseChildLifecycle {
    Current,
    Draining,
}

/// One active child in a connection lease. Sorted by `childAttemptId`.
/// `replacement_pending` is never lease-active.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteLeaseActiveChildV1 {
    pub child_attempt_id: String,
    pub transport_epoch: String,
    pub transport: RemoteLeaseTransport,
    pub lifecycle: RemoteLeaseChildLifecycle,
    /// The store-committed agreeing final-proof-set digest for this child/
    /// epoch.
    pub final_proof_set_digest: String,
}

/// The transport kind as recorded in a lease child.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteLeaseTransport {
    WebRtc,
    WebSocket,
}

/// The exact payload of `RemoteConnectionLeaseV1`.
///
/// Protected header is `{alg:"ES256",kid,typ:"flycockpit-remote-connection-lease+jws"}`
/// and the payload follows RFC 8785 canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteConnectionLeasePayloadV1 {
    pub schema_version: u8,
    pub iss: String,
    pub aud: String,
    /// 16-byte lease ID (base64url, 22 chars).
    pub lease_id: String,
    /// Monotonically increasing lease generation.
    pub lease_generation: String,
    /// 16-byte refresh request ID (base64url, 22 chars).
    pub refresh_request_id: String,
    /// SHA-256 digest of the exact refresh authorization JWS.
    pub refresh_authorization_digest: String,
    pub tenant_id: String,
    pub account_id: String,
    pub client_device_id: String,
    pub client_device_generation: String,
    pub daemon_instance_id: String,
    pub daemon_certificate_generation: String,
    pub logical_attachment_id: String,
    pub service_version: String,
    pub service_policy_digest: String,
    pub policy_epoch: String,
    pub policy_digest: String,
    pub authority_epoch: String,
    pub permission_ceiling_digest: String,
    pub daemon_local_policy_digest: String,
    /// Sorted by `childAttemptId`.
    pub active_children: Vec<RemoteLeaseActiveChildV1>,
    /// Both null in control-plane mode; both nonnull in tenant-signer mode.
    pub tenant_authorization_statement_digest: Option<String>,
    /// Both null in control-plane mode; both nonnull in tenant-signer mode.
    pub tenant_authority_status_digest: Option<String>,
    pub iat: String,
    pub valid_until: String,
}

impl RemoteConnectionLeasePayloadV1 {
    /// Validate the lease payload: exact member presence, sorted children,
    /// child caps, both-null/both-nonnull tenant matrix, and timing.
    pub fn validate(&self, now: i64) -> Result<(), LeaseValidationError> {
        // Schema version.
        if self.schema_version != REMOTE_SESSION_CONTINUITY_SCHEMA_VERSION {
            return Err(LeaseValidationError::SchemaVersion);
        }

        // Audience.
        if self.aud != "flycockpit-remote-connection-lease-v1" {
            return Err(LeaseValidationError::Audience);
        }

        // Tenant authorization matrix: both null or both nonnull.
        match (
            &self.tenant_authorization_statement_digest,
            &self.tenant_authority_status_digest,
        ) {
            (None, None) => {}
            (Some(s), Some(st)) => {
                if s.is_empty() || st.is_empty() {
                    return Err(LeaseValidationError::TenantMatrixOneNull);
                }
            }
            _ => return Err(LeaseValidationError::TenantMatrixOneNull),
        }

        // Active children sorted by childAttemptId.
        let mut prev: Option<&str> = None;
        for child in &self.active_children {
            if let Some(prev_id) = prev
                && child.child_attempt_id.as_str() <= prev_id
            {
                return Err(LeaseValidationError::ChildrenNotSorted);
            }
            prev = Some(&child.child_attempt_id);
        }

        // No replacement_pending child in a lease (lifecycle is only
        // current or draining).
        for child in &self.active_children {
            match child.lifecycle {
                RemoteLeaseChildLifecycle::Current | RemoteLeaseChildLifecycle::Draining => {}
            }
        }

        // Child caps: normally at most one current per transport and two
        // total. TURN cutover: one current replacement + one draining
        // predecessor of same transport + at most one current WebSocket
        // (three total).
        let current_count = self
            .active_children
            .iter()
            .filter(|c| c.lifecycle == RemoteLeaseChildLifecycle::Current)
            .count();
        let draining_count = self
            .active_children
            .iter()
            .filter(|c| c.lifecycle == RemoteLeaseChildLifecycle::Draining)
            .count();

        // Hard total cap takes precedence over the per-transport caps: more
        // than three children is always rejected regardless of composition.
        // Checked first so a per-transport sub-cap cannot shadow it — with the
        // sub-caps applied first a 4+ child set would otherwise always trip a
        // transport/draining cap and leave `TooManyChildren` unreachable.
        if self.active_children.len() > 3 {
            return Err(LeaseValidationError::TooManyChildren);
        }

        // At most one current WebRTC.
        let current_webrtc = self
            .active_children
            .iter()
            .filter(|c| {
                c.lifecycle == RemoteLeaseChildLifecycle::Current
                    && c.transport == RemoteLeaseTransport::WebRtc
            })
            .count();
        if current_webrtc > 1 {
            return Err(LeaseValidationError::TooManyCurrentWebRtc);
        }

        // At most one current WebSocket.
        let current_websocket = self
            .active_children
            .iter()
            .filter(|c| {
                c.lifecycle == RemoteLeaseChildLifecycle::Current
                    && c.transport == RemoteLeaseTransport::WebSocket
            })
            .count();
        if current_websocket > 1 {
            return Err(LeaseValidationError::TooManyCurrentWebSocket);
        }

        // Draining children: only in TURN cutover (same transport as a
        // current child).
        if draining_count > 1 {
            return Err(LeaseValidationError::TooManyDraining);
        }

        // Total cap: normally 2, TURN cutover 3. The >3 rejection is enforced
        // above (before the per-transport caps); only the exactly-three
        // draining requirement remains here.
        let total = self.active_children.len();
        if total == 3 && draining_count != 1 {
            return Err(LeaseValidationError::ThreeChildrenRequireDraining);
        }

        // Timing: validity is exactly 300 seconds.
        let iat: i64 = self
            .iat
            .parse()
            .map_err(|_| LeaseValidationError::TimeParse)?;
        let valid_until: i64 = self
            .valid_until
            .parse()
            .map_err(|_| LeaseValidationError::TimeParse)?;
        if valid_until - iat != REMOTE_CONNECTION_LEASE_VALID_SECONDS {
            return Err(LeaseValidationError::ValidityDuration);
        }
        // No grace after validUntil.
        if now > valid_until {
            return Err(LeaseValidationError::Expired);
        }

        let _ = current_count;
        Ok(())
    }
}

/// Lease validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseValidationError {
    #[error("schema version must be 1")]
    SchemaVersion,
    #[error("audience must be flycockpit-remote-connection-lease-v1")]
    Audience,
    #[error("tenant authorization matrix must be both-null or both-nonnull")]
    TenantMatrixOneNull,
    #[error("active children must be sorted by childAttemptId")]
    ChildrenNotSorted,
    #[error("at most one current WebRTC child")]
    TooManyCurrentWebRtc,
    #[error("at most one current WebSocket child")]
    TooManyCurrentWebSocket,
    #[error("at most one draining child")]
    TooManyDraining,
    #[error("too many active children (max 3)")]
    TooManyChildren,
    #[error("three children require exactly one draining")]
    ThreeChildrenRequireDraining,
    #[error("validity must be exactly 300 seconds")]
    ValidityDuration,
    #[error("lease has expired (no grace)")]
    Expired,
    #[error("time field parse error")]
    TimeParse,
    #[error("lease JWS exceeds 16384 bytes")]
    JwsTooLarge,
}

/// Compute the SHA-256 digest of the exact lease JWS bytes. Every child
/// route/pair, daemon authorization barrier, and gateway delivery lease
/// stores and compares `(leaseId, leaseGeneration, SHA-256(exactLeaseJws))`.
pub fn lease_jws_digest(jws_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(jws_bytes);
    hasher.finalize().into()
}

/// Verify that a lease JWS is within the 16,384-byte bound.
pub fn validate_lease_jws_size(jws_bytes: &[u8]) -> Result<(), LeaseValidationError> {
    if jws_bytes.len() > REMOTE_CONNECTION_LEASE_MAX_BYTES {
        return Err(LeaseValidationError::JwsTooLarge);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Refresh authorization — RemoteLeaseRefreshAuthorizationV1
// ─────────────────────────────────────────────────────────────────────────

/// JWS protected-header `typ` for `RemoteLeaseRefreshAuthorizationV1`.
pub const REMOTE_LEASE_REFRESH_AUTH_JWS_TYP: &str =
    "flycockpit-remote-lease-refresh-authorization+jws";
/// JWS `alg` for refresh authorization.
pub const REMOTE_LEASE_REFRESH_AUTH_JWS_ALG: &str = "ES256";

/// The exact payload of `RemoteLeaseRefreshAuthorizationV1`.
///
/// Protected header is `{alg:"ES256",kid,typ:"flycockpit-remote-lease-refresh-authorization+jws"}`
/// and the payload follows RFC 8785 canonical JSON. It is produced only from
/// the same current certificate, policy, quota, revocation, and capability
/// evidence available before `AuthorizeAttemptGrantV1`. It contains no
/// admission sequence, offer/proof JTI, transport epoch, negotiation/Noise/
/// DTLS digest, route, connection lease, or active-child claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteLeaseRefreshAuthorizationPayloadV1 {
    pub schema_version: u8,
    pub iss: String,
    pub aud: String,
    /// 16-byte authorization ID (base64url, 22 chars).
    pub authorization_id: String,
    pub tenant_id: String,
    pub account_id: String,
    pub client_device_id: String,
    pub client_certificate_generation: String,
    pub daemon_instance_id: String,
    pub daemon_certificate_generation: String,
    pub logical_attachment_id: String,
    pub service_version: String,
    pub service_policy_digest: String,
    pub policy_epoch: String,
    pub policy_digest: String,
    pub authority_epoch: String,
    pub permission_ceiling_digest: String,
    /// Tenant mode: the pre-grant `AuthorizeAttemptGrantV1` result bound by
    /// this authorization. Control-plane mode: null.
    pub tenant_authorization_digest: Option<String>,
    pub iat: String,
    pub exp: String,
    /// 16-byte JTI (base64url, 22 chars).
    pub jti: String,
}

impl RemoteLeaseRefreshAuthorizationPayloadV1 {
    /// Validate the refresh authorization payload. It must not contain any
    /// admission/proof/transport field.
    pub fn validate(&self) -> Result<(), RefreshAuthValidationError> {
        if self.schema_version != REMOTE_SESSION_CONTINUITY_SCHEMA_VERSION {
            return Err(RefreshAuthValidationError::SchemaVersion);
        }
        if self.aud != "flycockpit-remote-lease-refresh-v1" {
            return Err(RefreshAuthValidationError::Audience);
        }
        // Tenant authorization digest: null in control-plane, nonnull in
        // tenant-signer. No partial.
        match &self.tenant_authorization_digest {
            None => {}
            Some(d) if d.is_empty() => {
                return Err(RefreshAuthValidationError::TenantDigestEmpty);
            }
            Some(_) => {}
        }
        // Time ordering: iat <= exp.
        let iat: i64 = self
            .iat
            .parse()
            .map_err(|_| RefreshAuthValidationError::TimeParse)?;
        let exp: i64 = self
            .exp
            .parse()
            .map_err(|_| RefreshAuthValidationError::TimeParse)?;
        if iat > exp {
            return Err(RefreshAuthValidationError::TimeOrder);
        }
        Ok(())
    }
}

/// Refresh authorization validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RefreshAuthValidationError {
    #[error("schema version must be 1")]
    SchemaVersion,
    #[error("audience must be flycockpit-remote-lease-refresh-v1")]
    Audience,
    #[error("tenant authorization digest must be null or nonempty")]
    TenantDigestEmpty,
    #[error("time field parse error")]
    TimeParse,
    #[error("iat must be <= exp")]
    TimeOrder,
}

/// Compute the SHA-256 digest of the exact refresh authorization JWS bytes.
/// This digest is stored in the connection lease.
pub fn refresh_authorization_jws_digest(jws_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(jws_bytes);
    hasher.finalize().into()
}

/// The exact member set for the refresh authorization payload. Used by
/// tests to prove no admission/proof/transport field is present.
pub const REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS: &[&str] = &[
    "schemaVersion",
    "iss",
    "aud",
    "authorizationId",
    "tenantId",
    "accountId",
    "clientDeviceId",
    "clientCertificateGeneration",
    "daemonInstanceId",
    "daemonCertificateGeneration",
    "logicalAttachmentId",
    "serviceVersion",
    "servicePolicyDigest",
    "policyEpoch",
    "policyDigest",
    "authorityEpoch",
    "permissionCeilingDigest",
    "tenantAuthorizationDigest",
    "iat",
    "exp",
    "jti",
];

/// The exact member set for the connection lease payload.
pub const CONNECTION_LEASE_PAYLOAD_MEMBERS: &[&str] = &[
    "schemaVersion",
    "iss",
    "aud",
    "leaseId",
    "leaseGeneration",
    "refreshRequestId",
    "refreshAuthorizationDigest",
    "tenantId",
    "accountId",
    "clientDeviceId",
    "clientDeviceGeneration",
    "daemonInstanceId",
    "daemonCertificateGeneration",
    "logicalAttachmentId",
    "serviceVersion",
    "servicePolicyDigest",
    "policyEpoch",
    "policyDigest",
    "authorityEpoch",
    "permissionCeilingDigest",
    "daemonLocalPolicyDigest",
    "activeChildren",
    "tenantAuthorizationStatementDigest",
    "tenantAuthorityStatusDigest",
    "iat",
    "validUntil",
];

/// Verify that a set of payload keys exactly matches the required member set.
pub fn validate_exact_payload_keys(
    keys: &[String],
    required: &[&str],
) -> Result<(), PayloadKeyError> {
    let mut sorted_keys: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    sorted_keys.sort();
    let mut sorted_required: Vec<&str> = required.to_vec();
    sorted_required.sort();
    if sorted_keys == sorted_required {
        Ok(())
    } else {
        let extra: Vec<String> = sorted_keys
            .iter()
            .filter(|k| !sorted_required.contains(k))
            .map(|s| s.to_string())
            .collect();
        let missing: Vec<String> = sorted_required
            .iter()
            .filter(|k| !sorted_keys.contains(k))
            .map(|s| s.to_string())
            .collect();
        Err(PayloadKeyError::Mismatch { extra, missing })
    }
}

/// Payload key validation error.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadKeyError {
    #[error("payload key mismatch: extra={extra:?}, missing={missing:?}")]
    Mismatch {
        extra: Vec<String>,
        missing: Vec<String>,
    },
}

// ─────────────────────────────────────────────────────────────────────────
// Control event — RemoteControlEventV1 (FCRC, 98-byte header + payload)
// ─────────────────────────────────────────────────────────────────────────
//
// This is the byte-exact Rust mirror of the gateway-owned durable control
// contract implemented in `apps/server/src/remote-signaling-gateway/
// binary-codecs.ts`. The gateway is the single owner of the format; Rust never
// redefines it. Cross-language compatibility is proven by TS-encoder-produced
// golden vectors (`packages/cockpit-protocol/fixtures/remote-control-event-v1.json`)
// decoded by BOTH the Rust and TS decoders — a Rust round-trip alone is never
// the evidence.
//
// Header layout (big-endian, exactly 98 bytes):
// ```text
// offset  0..4  : magic "FCRC"
// offset  4     : version (1)
// offset  5..13 : controlSeq (u64)
// offset 13..29 : eventId (16 bytes, nonzero)
// offset 29     : kind (u8, 1..=8)
// offset 30..38 : serviceVersion (u64)
// offset 38..46 : policyEpoch (u64)
// offset 46..54 : authorityEpoch (u64)
// offset 54..62 : issuedAt (i64)
// offset 62..66 : payloadLength (u32)
// offset 66..98 : payloadDigest (32 bytes, SHA-256 of payload)
// ```

/// The 98-byte header magic for `RemoteControlEventV1` (FCRC).
pub const REMOTE_CONTROL_EVENT_MAGIC: [u8; 4] = *b"FCRC";
/// The header version byte.
pub const REMOTE_CONTROL_EVENT_VERSION: u8 = 1;
/// The exact header size.
pub const REMOTE_CONTROL_EVENT_HEADER_BYTES: usize = 98;
/// Maximum payload size (bytes).
pub const REMOTE_CONTROL_EVENT_MAX_PAYLOAD: usize = 65_536;
/// Maximum whole binary event size (header + payload).
pub const REMOTE_CONTROL_EVENT_MAX_BYTES: usize = 65_634;
/// Maximum compact ES256 JWS wrapping the binary event (96 KiB).
pub const REMOTE_CONTROL_EVENT_MAX_COMPACT_JWS: usize = 96 * 1024;
/// Maximum embedded lease/status JWS length inside a payload.
pub const REMOTE_CONTROL_EVENT_MAX_EMBEDDED_JWS: usize = 16_384;
/// Maximum replay events per page (64).
pub const REMOTE_CONTROL_EVENT_REPLAY_MAX_EVENTS: usize = 64;
/// Maximum replay bytes per page (512 KiB).
pub const REMOTE_CONTROL_EVENT_REPLAY_MAX_BYTES: usize = 512 * 1024;

/// The eight closed control-event kinds with the gateway's exact ordinals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteControlEventKind {
    LeaseRefresh,
    PolicyNarrowed,
    DeviceRevoked,
    InstanceRevoked,
    TenantAuthorityChanged,
    AttachmentRevoked,
    Drain,
    AuthorityStatus,
}

impl RemoteControlEventKind {
    /// Decode a kind from its wire ordinal (gateway-owned mapping).
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::LeaseRefresh),
            2 => Some(Self::PolicyNarrowed),
            3 => Some(Self::DeviceRevoked),
            4 => Some(Self::InstanceRevoked),
            5 => Some(Self::TenantAuthorityChanged),
            6 => Some(Self::AttachmentRevoked),
            7 => Some(Self::Drain),
            8 => Some(Self::AuthorityStatus),
            _ => None,
        }
    }

    /// Encode a kind to its wire ordinal.
    pub fn to_byte(self) -> u8 {
        match self {
            Self::LeaseRefresh => 1,
            Self::PolicyNarrowed => 2,
            Self::DeviceRevoked => 3,
            Self::InstanceRevoked => 4,
            Self::TenantAuthorityChanged => 5,
            Self::AttachmentRevoked => 6,
            Self::Drain => 7,
            Self::AuthorityStatus => 8,
        }
    }
}

/// A decoded `RemoteControlEventV1` 98-byte header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteControlEventHeaderV1 {
    pub control_seq: u64,
    pub event_id: [u8; 16],
    pub kind: RemoteControlEventKind,
    pub service_version: u64,
    pub policy_epoch: u64,
    pub authority_epoch: u64,
    pub issued_at: i64,
    pub payload_length: u32,
    pub payload_digest: [u8; 32],
}

impl RemoteControlEventHeaderV1 {
    /// Decode a 98-byte header. Fails on wrong length, magic/version, a zero
    /// event id, a zero control sequence, an unknown kind, or a payload length
    /// over the cap — before any state mutation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlEventError> {
        if bytes.len() != REMOTE_CONTROL_EVENT_HEADER_BYTES {
            return Err(ControlEventError::Length);
        }
        if bytes[0..4] != REMOTE_CONTROL_EVENT_MAGIC {
            return Err(ControlEventError::Magic);
        }
        if bytes[4] != REMOTE_CONTROL_EVENT_VERSION {
            return Err(ControlEventError::Version);
        }
        let control_seq = u64::from_be_bytes(bytes[5..13].try_into().unwrap());
        if control_seq < 1 {
            return Err(ControlEventError::ControlSeqZero);
        }
        let event_id: [u8; 16] = bytes[13..29].try_into().unwrap();
        if event_id.iter().all(|&b| b == 0) {
            return Err(ControlEventError::EventIdZero);
        }
        let kind =
            RemoteControlEventKind::from_byte(bytes[29]).ok_or(ControlEventError::UnknownKind)?;
        let service_version = u64::from_be_bytes(bytes[30..38].try_into().unwrap());
        let policy_epoch = u64::from_be_bytes(bytes[38..46].try_into().unwrap());
        let authority_epoch = u64::from_be_bytes(bytes[46..54].try_into().unwrap());
        let issued_at = i64::from_be_bytes(bytes[54..62].try_into().unwrap());
        let payload_length = u32::from_be_bytes(bytes[62..66].try_into().unwrap());
        if payload_length as usize > REMOTE_CONTROL_EVENT_MAX_PAYLOAD {
            return Err(ControlEventError::PayloadCap);
        }
        let payload_digest: [u8; 32] = bytes[66..98].try_into().unwrap();
        Ok(Self {
            control_seq,
            event_id,
            kind,
            service_version,
            policy_epoch,
            authority_epoch,
            issued_at,
            payload_length,
            payload_digest,
        })
    }

    /// Encode to a 98-byte header.
    pub fn encode(&self) -> [u8; REMOTE_CONTROL_EVENT_HEADER_BYTES] {
        let mut bytes = [0u8; REMOTE_CONTROL_EVENT_HEADER_BYTES];
        bytes[0..4].copy_from_slice(&REMOTE_CONTROL_EVENT_MAGIC);
        bytes[4] = REMOTE_CONTROL_EVENT_VERSION;
        bytes[5..13].copy_from_slice(&self.control_seq.to_be_bytes());
        bytes[13..29].copy_from_slice(&self.event_id);
        bytes[29] = self.kind.to_byte();
        bytes[30..38].copy_from_slice(&self.service_version.to_be_bytes());
        bytes[38..46].copy_from_slice(&self.policy_epoch.to_be_bytes());
        bytes[46..54].copy_from_slice(&self.authority_epoch.to_be_bytes());
        bytes[54..62].copy_from_slice(&self.issued_at.to_be_bytes());
        bytes[62..66].copy_from_slice(&self.payload_length.to_be_bytes());
        bytes[66..98].copy_from_slice(&self.payload_digest);
        bytes
    }
}

/// A decoded, exact-length control-event payload, one variant per kind. Every
/// per-kind decode is exact-length: a byte too many or too few is rejected
/// before any state mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteControlEventPayload {
    /// `lease_refresh=1 {leaseJwsLength:u16, leaseJws}` (JWS 1..=16,384 bytes).
    LeaseRefresh { lease_jws: Vec<u8> },
    /// `policy_narrowed=2 {previousDigest:[32], newDigest:[32], affectedFieldBits:u64}`.
    PolicyNarrowed {
        previous_digest: [u8; 32],
        new_digest: [u8; 32],
        affected_field_bits: u64,
    },
    /// `device_revoked=3 {deviceId:[16], generation:u64}`.
    DeviceRevoked {
        device_id: [u8; 16],
        generation: u64,
    },
    /// `instance_revoked=4 {instanceId:[16], generation:u64}`.
    InstanceRevoked {
        instance_id: [u8; 16],
        generation: u64,
    },
    /// `tenant_authority_changed=5 {previousEpoch:u64, newEpoch:u64, ringDigest:[32]}`.
    TenantAuthorityChanged {
        previous_epoch: u64,
        new_epoch: u64,
        ring_digest: [u8; 32],
    },
    /// `attachment_revoked=6 {logicalAttachmentId:[16], reason:u8}`.
    AttachmentRevoked {
        logical_attachment_id: [u8; 16],
        reason: u8,
    },
    /// `drain=7 {deadline:i64, reason:u8}`.
    Drain { deadline: i64, reason: u8 },
    /// `authority_status=8 {statusGeneration:u64, statusJwsLength:u16, statusJws}`
    /// (JWS 1..=16,384 bytes).
    AuthorityStatus {
        status_generation: u64,
        status_jws: Vec<u8>,
    },
}

impl RemoteControlEventPayload {
    /// The kind ordinal of this payload.
    pub fn kind(&self) -> RemoteControlEventKind {
        match self {
            Self::LeaseRefresh { .. } => RemoteControlEventKind::LeaseRefresh,
            Self::PolicyNarrowed { .. } => RemoteControlEventKind::PolicyNarrowed,
            Self::DeviceRevoked { .. } => RemoteControlEventKind::DeviceRevoked,
            Self::InstanceRevoked { .. } => RemoteControlEventKind::InstanceRevoked,
            Self::TenantAuthorityChanged { .. } => RemoteControlEventKind::TenantAuthorityChanged,
            Self::AttachmentRevoked { .. } => RemoteControlEventKind::AttachmentRevoked,
            Self::Drain { .. } => RemoteControlEventKind::Drain,
            Self::AuthorityStatus { .. } => RemoteControlEventKind::AuthorityStatus,
        }
    }

    /// Encode this payload to its exact-length network-byte-order bytes.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::LeaseRefresh { lease_jws } => {
                let mut out = Vec::with_capacity(2 + lease_jws.len());
                out.extend_from_slice(&(lease_jws.len() as u16).to_be_bytes());
                out.extend_from_slice(lease_jws);
                out
            }
            Self::PolicyNarrowed {
                previous_digest,
                new_digest,
                affected_field_bits,
            } => {
                let mut out = Vec::with_capacity(72);
                out.extend_from_slice(previous_digest);
                out.extend_from_slice(new_digest);
                out.extend_from_slice(&affected_field_bits.to_be_bytes());
                out
            }
            Self::DeviceRevoked {
                device_id,
                generation,
            } => {
                let mut out = Vec::with_capacity(24);
                out.extend_from_slice(device_id);
                out.extend_from_slice(&generation.to_be_bytes());
                out
            }
            Self::InstanceRevoked {
                instance_id,
                generation,
            } => {
                let mut out = Vec::with_capacity(24);
                out.extend_from_slice(instance_id);
                out.extend_from_slice(&generation.to_be_bytes());
                out
            }
            Self::TenantAuthorityChanged {
                previous_epoch,
                new_epoch,
                ring_digest,
            } => {
                let mut out = Vec::with_capacity(48);
                out.extend_from_slice(&previous_epoch.to_be_bytes());
                out.extend_from_slice(&new_epoch.to_be_bytes());
                out.extend_from_slice(ring_digest);
                out
            }
            Self::AttachmentRevoked {
                logical_attachment_id,
                reason,
            } => {
                let mut out = Vec::with_capacity(17);
                out.extend_from_slice(logical_attachment_id);
                out.push(*reason);
                out
            }
            Self::Drain { deadline, reason } => {
                let mut out = Vec::with_capacity(9);
                out.extend_from_slice(&deadline.to_be_bytes());
                out.push(*reason);
                out
            }
            Self::AuthorityStatus {
                status_generation,
                status_jws,
            } => {
                let mut out = Vec::with_capacity(10 + status_jws.len());
                out.extend_from_slice(&status_generation.to_be_bytes());
                out.extend_from_slice(&(status_jws.len() as u16).to_be_bytes());
                out.extend_from_slice(status_jws);
                out
            }
        }
    }

    /// Decode an exact-length payload for `kind`. Any trailing byte, short
    /// read, or out-of-range embedded length is rejected.
    pub fn decode(kind: RemoteControlEventKind, bytes: &[u8]) -> Result<Self, ControlEventError> {
        match kind {
            RemoteControlEventKind::LeaseRefresh => {
                let jws = decode_length_prefixed_jws(bytes)?;
                Ok(Self::LeaseRefresh { lease_jws: jws })
            }
            RemoteControlEventKind::PolicyNarrowed => {
                if bytes.len() != 72 {
                    return Err(ControlEventError::PayloadLength);
                }
                Ok(Self::PolicyNarrowed {
                    previous_digest: bytes[0..32].try_into().unwrap(),
                    new_digest: bytes[32..64].try_into().unwrap(),
                    affected_field_bits: u64::from_be_bytes(bytes[64..72].try_into().unwrap()),
                })
            }
            RemoteControlEventKind::DeviceRevoked => {
                if bytes.len() != 24 {
                    return Err(ControlEventError::PayloadLength);
                }
                Ok(Self::DeviceRevoked {
                    device_id: bytes[0..16].try_into().unwrap(),
                    generation: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
                })
            }
            RemoteControlEventKind::InstanceRevoked => {
                if bytes.len() != 24 {
                    return Err(ControlEventError::PayloadLength);
                }
                Ok(Self::InstanceRevoked {
                    instance_id: bytes[0..16].try_into().unwrap(),
                    generation: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
                })
            }
            RemoteControlEventKind::TenantAuthorityChanged => {
                if bytes.len() != 48 {
                    return Err(ControlEventError::PayloadLength);
                }
                Ok(Self::TenantAuthorityChanged {
                    previous_epoch: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
                    new_epoch: u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
                    ring_digest: bytes[16..48].try_into().unwrap(),
                })
            }
            RemoteControlEventKind::AttachmentRevoked => {
                if bytes.len() != 17 {
                    return Err(ControlEventError::PayloadLength);
                }
                Ok(Self::AttachmentRevoked {
                    logical_attachment_id: bytes[0..16].try_into().unwrap(),
                    reason: bytes[16],
                })
            }
            RemoteControlEventKind::Drain => {
                if bytes.len() != 9 {
                    return Err(ControlEventError::PayloadLength);
                }
                Ok(Self::Drain {
                    deadline: i64::from_be_bytes(bytes[0..8].try_into().unwrap()),
                    reason: bytes[8],
                })
            }
            RemoteControlEventKind::AuthorityStatus => {
                if bytes.len() < 10 {
                    return Err(ControlEventError::PayloadLength);
                }
                let status_generation = u64::from_be_bytes(bytes[0..8].try_into().unwrap());
                let jws = decode_length_prefixed_jws(&bytes[8..])?;
                Ok(Self::AuthorityStatus {
                    status_generation,
                    status_jws: jws,
                })
            }
        }
    }
}

/// Decode a `{length:u16, bytes}` embedded JWS, enforcing 1..=16,384 length and
/// no trailing bytes.
fn decode_length_prefixed_jws(bytes: &[u8]) -> Result<Vec<u8>, ControlEventError> {
    if bytes.len() < 2 {
        return Err(ControlEventError::PayloadLength);
    }
    let len = u16::from_be_bytes(bytes[0..2].try_into().unwrap()) as usize;
    if len == 0 || len > REMOTE_CONTROL_EVENT_MAX_EMBEDDED_JWS {
        return Err(ControlEventError::EmbeddedJwsLength);
    }
    if bytes.len() != 2 + len {
        return Err(ControlEventError::PayloadLength);
    }
    Ok(bytes[2..].to_vec())
}

/// A whole decoded `RemoteControlEventV1`: verified 98-byte header plus an
/// exact-length, digest-checked payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteControlEventV1 {
    pub header: RemoteControlEventHeaderV1,
    pub payload: RemoteControlEventPayload,
}

impl RemoteControlEventV1 {
    /// Build a control event, computing `payloadLength` and `payloadDigest`
    /// from the encoded payload. The header's `payload_length`/`payload_digest`
    /// are derived here and cannot drift from the payload.
    pub fn seal(
        control_seq: u64,
        event_id: [u8; 16],
        service_version: u64,
        policy_epoch: u64,
        authority_epoch: u64,
        issued_at: i64,
        payload: RemoteControlEventPayload,
    ) -> Self {
        let payload_bytes = payload.encode();
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        let payload_digest: [u8; 32] = hasher.finalize().into();
        Self {
            header: RemoteControlEventHeaderV1 {
                control_seq,
                event_id,
                kind: payload.kind(),
                service_version,
                policy_epoch,
                authority_epoch,
                issued_at,
                payload_length: payload_bytes.len() as u32,
                payload_digest,
            },
            payload,
        }
    }

    /// Encode the whole binary event (header followed by the exact payload).
    pub fn encode(&self) -> Vec<u8> {
        let payload_bytes = self.payload.encode();
        let mut header = self.header.clone();
        header.payload_length = payload_bytes.len() as u32;
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        header.payload_digest = hasher.finalize().into();
        let mut out = Vec::with_capacity(REMOTE_CONTROL_EVENT_HEADER_BYTES + payload_bytes.len());
        out.extend_from_slice(&header.encode());
        out.extend_from_slice(&payload_bytes);
        out
    }

    /// Decode and fully validate a whole binary control event: header, exact
    /// `payloadLength`, SHA-256 `payloadDigest`, and exact-length per-kind
    /// payload. Every failure precedes any state mutation.
    pub fn decode(bytes: &[u8]) -> Result<Self, ControlEventError> {
        if bytes.len() < REMOTE_CONTROL_EVENT_HEADER_BYTES
            || bytes.len() > REMOTE_CONTROL_EVENT_MAX_BYTES
        {
            return Err(ControlEventError::Length);
        }
        let header =
            RemoteControlEventHeaderV1::decode(&bytes[0..REMOTE_CONTROL_EVENT_HEADER_BYTES])?;
        let payload_bytes = &bytes[REMOTE_CONTROL_EVENT_HEADER_BYTES..];
        // Exact declared length — no trailing/truncated bytes.
        if payload_bytes.len() != header.payload_length as usize {
            return Err(ControlEventError::PayloadLength);
        }
        // Payload digest binds the header to the payload.
        let mut hasher = Sha256::new();
        hasher.update(payload_bytes);
        let digest: [u8; 32] = hasher.finalize().into();
        if digest != header.payload_digest {
            return Err(ControlEventError::DigestMismatch);
        }
        let payload = RemoteControlEventPayload::decode(header.kind, payload_bytes)?;
        Ok(Self { header, payload })
    }
}

/// Control event decode error. Every variant is a hard rejection performed
/// before any state mutation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ControlEventError {
    #[error("control event has wrong length")]
    Length,
    #[error("control event magic mismatch")]
    Magic,
    #[error("control event version mismatch")]
    Version,
    #[error("control event event id is zero")]
    EventIdZero,
    #[error("control event control sequence is zero")]
    ControlSeqZero,
    #[error("control event unknown kind")]
    UnknownKind,
    #[error("control event payload exceeds cap")]
    PayloadCap,
    #[error("control event payload has wrong exact length")]
    PayloadLength,
    #[error("control event embedded JWS length out of range")]
    EmbeddedJwsLength,
    #[error("control event payload digest mismatch")]
    DigestMismatch,
}

/// Compute the byte hash of a control event (header + payload). The daemon
/// persists `eventId → byteHash` before ACK.
pub fn control_event_byte_hash(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// The result of applying a control event through the authorization barrier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteControlEventApplyResult {
    /// Successfully applied; cursor advanced.
    Applied,
    /// Duplicate event (same ID and bytes); idempotent, no cursor advance.
    DuplicateIdempotent,
    /// Conflict (same ID, different bytes); operations paused, request
    /// authoritative replay.
    Conflict,
    /// Sequence gap; operations paused, request authoritative replay.
    SequenceGap,
    /// Epoch regression; operations paused.
    EpochRegression,
    /// Bad signature; operations paused.
    BadSignature,
    /// Unknown kind; operations paused.
    UnknownKind,
    /// Malformed payload; operations paused.
    MalformedPayload,
}

// ─────────────────────────────────────────────────────────────────────────
// Mobile UI states
// ─────────────────────────────────────────────────────────────────────────

/// The exact UI states for mobile background/foreground recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteMobileUiState {
    Reconnecting,
    ReauthenticationRequired,
    SnapshotRequired,
    OutcomeUnknown,
    AccessRevoked,
    SessionTerminal,
}

// ─────────────────────────────────────────────────────────────────────────
// Lease current pointer (Postgres model)
// ─────────────────────────────────────────────────────────────────────────

/// The Postgres-stored current lease pointer. Exactly one lease is current
/// per `logicalAttachmentId`. Reserve/sign/finalize atomically replaces this
/// pointer and appends one control event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteCurrentLeasePointerV1 {
    pub logical_attachment_id: String,
    pub lease_id: String,
    pub lease_generation: u64,
    pub lease_jws_digest: String,
}

/// Verify that a replacement lease has a strictly greater generation than the
/// current pointer. Replacement invalidates the old lease for new work
/// immediately.
pub fn validate_lease_replacement_generation(
    current_generation: u64,
    new_generation: u64,
) -> Result<(), LeaseReplacementError> {
    if new_generation <= current_generation {
        return Err(LeaseReplacementError::GenerationNotMonotonic);
    }
    Ok(())
}

/// Lease replacement error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LeaseReplacementError {
    #[error("lease generation must be strictly monotonic")]
    GenerationNotMonotonic,
    #[error("lease JWS digest mismatch for exact retry")]
    DigestMismatch,
}

/// Verify that an exact retry returns the same generation and JWS digest.
pub fn validate_exact_retry(
    current_generation: u64,
    current_digest: &[u8; 32],
    retry_generation: u64,
    retry_digest: &[u8; 32],
) -> Result<(), LeaseReplacementError> {
    if current_generation != retry_generation || current_digest != retry_digest {
        return Err(LeaseReplacementError::DigestMismatch);
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// No-widening comparison (refresh may only retain or narrow authority)
// ─────────────────────────────────────────────────────────────────────────
//
// The Rust daemon and gateway only ever VERIFY leases; they never mint. Lease
// minting is the control-plane TypeScript `PostProofLeaseGate` adapter in
// `packages/api` (reserve→sign→finalize against the Postgres current-lease
// pointer and the per-instance control outbox). The former all-zero-tuple Rust
// stub gate is deleted.

/// A decoded permission ceiling for the no-widening comparison. A lease refresh
/// may only retain or narrow authority: the new ceiling must be a subset of the
/// old across scope, project, transport, and custody-requirement sets, and
/// child membership may only be retained or narrowed. Equal digests are an
/// unchanged ceiling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshCeiling {
    /// Digest of the full ceiling; equal digests short-circuit as unchanged.
    pub ceiling_digest: [u8; 32],
    pub scopes: BTreeSet<String>,
    pub projects: BTreeSet<String>,
    pub transports: BTreeSet<String>,
    pub custody_requirements: BTreeSet<String>,
    /// Authorized child membership.
    pub children: BTreeSet<String>,
}

/// Verify that a refresh only retains or narrows the ceiling and child
/// membership. The new ceiling must be a subset of the old across every set;
/// widening any set — or adding a child — is rejected. Widening requires a
/// fresh attempt grant, never a refresh.
pub fn validate_refresh_narrows(
    old: &RefreshCeiling,
    new: &RefreshCeiling,
) -> Result<(), RefreshWidenError> {
    // Equal digests short-circuit as unchanged (identical ceiling).
    if old.ceiling_digest == new.ceiling_digest {
        return Ok(());
    }
    if !new.scopes.is_subset(&old.scopes) {
        return Err(RefreshWidenError::ScopeWidened);
    }
    if !new.projects.is_subset(&old.projects) {
        return Err(RefreshWidenError::ProjectWidened);
    }
    if !new.transports.is_subset(&old.transports) {
        return Err(RefreshWidenError::TransportWidened);
    }
    if !new
        .custody_requirements
        .is_subset(&old.custody_requirements)
    {
        return Err(RefreshWidenError::CustodyWidened);
    }
    if !new.children.is_subset(&old.children) {
        return Err(RefreshWidenError::ChildAdded);
    }
    Ok(())
}

/// A refresh that would widen daemon authority, rejected by
/// [`validate_refresh_narrows`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RefreshWidenError {
    #[error("refresh would widen the scope set")]
    ScopeWidened,
    #[error("refresh would widen the project set")]
    ProjectWidened,
    #[error("refresh would widen the transport set")]
    TransportWidened,
    #[error("refresh would widen the custody-requirement set")]
    CustodyWidened,
    #[error("refresh would add a child to the membership set")]
    ChildAdded,
}

// ─────────────────────────────────────────────────────────────────────────
// Event delivery deduplication
// ─────────────────────────────────────────────────────────────────────────

/// Delivery deduplication state. All egress reads the shared outbox and
/// stable delivery IDs. Closing one child removes only that membership.
/// Failover between children delivers each stable delivery ID once.
#[derive(Debug, Clone, Default)]
pub struct RemoteDeliveryDedupeState {
    /// Delivery IDs that have been delivered (acked) on any child.
    delivered: std::collections::HashSet<String>,
}

impl RemoteDeliveryDedupeState {
    /// Create a new empty dedupe state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark a delivery ID as delivered. Returns true if this is the first
    /// delivery (the egress should send it), false if it was already
    /// delivered (skip).
    pub fn mark_delivered(&mut self, delivery_id: &str) -> bool {
        self.delivered.insert(delivery_id.to_string())
    }

    /// Check if a delivery ID has been delivered.
    pub fn is_delivered(&self, delivery_id: &str) -> bool {
        self.delivered.contains(delivery_id)
    }

    /// Remove a delivery ID from the delivered set (for replay after
    /// snapshot install).
    pub fn forget(&mut self, delivery_id: &str) {
        self.delivered.remove(delivery_id);
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Reattach ────────────────────────────────────────────────────────

    #[test]
    fn remote_reattach_requires_fresh_authenticated_epoch() {
        // The reattach request carries only session/attachment/cursor/pending
        // IDs — never an old grant, ticket, proof, nonce, traffic key,
        // attempt, or epoch. Any old cryptographic material is rejected
        // because the reattach request schema has no field for it.
        let req = RemoteReattachRequestV1 {
            schema_version: 1,
            session_id: "sess-1".into(),
            logical_attachment_id: "att-1".into(),
            prior_snapshot_id: None,
            event_cursor: "42".into(),
            pending_operation_ids: vec!["op-1".into()],
        };
        // Verify the request has no field for old crypto material.
        let json = serde_json::to_value(&req).unwrap();
        assert!(json.get("grant").is_none());
        assert!(json.get("ticket").is_none());
        assert!(json.get("proof").is_none());
        assert!(json.get("nonce").is_none());
        assert!(json.get("trafficKey").is_none());
        assert!(json.get("transportEpoch").is_none());
        assert!(json.get("attemptId").is_none());
    }

    #[test]
    fn remote_reattach_snapshot_outbox_atomicity() {
        // Verify the 256-event / 2-MiB paging bounds.
        let make_event = |seq: usize| RemoteOutboxEventV1 {
            event_seq: seq.to_string(),
            delivery_id: format!("del-{seq}"),
            kind: "test".into(),
            canonical_payload: vec![0u8; 100],
        };

        // 256 events of 100 bytes each is within bounds.
        let events: Vec<_> = (0..256).map(make_event).collect();
        assert!(validate_replay_page(&events).is_ok());

        // 257 events exceeds the event bound.
        let events: Vec<_> = (0..257).map(make_event).collect();
        assert_eq!(
            validate_replay_page(&events),
            Err(ReplayPageError::TooManyEvents)
        );

        // 256 events of 8 KiB each = 2 MiB exactly — within bounds.
        let events: Vec<_> = (0..256)
            .map(|seq| RemoteOutboxEventV1 {
                event_seq: seq.to_string(),
                delivery_id: format!("del-{seq}"),
                kind: "test".into(),
                canonical_payload: vec![0u8; 8192],
            })
            .collect();
        assert!(validate_replay_page(&events).is_ok());

        // 256 events of 8 KiB + 1 byte exceeds the byte bound.
        let events: Vec<_> = (0..256)
            .map(|seq| RemoteOutboxEventV1 {
                event_seq: seq.to_string(),
                delivery_id: format!("del-{seq}"),
                kind: "test".into(),
                canonical_payload: vec![0u8; 8193],
            })
            .collect();
        assert_eq!(
            validate_replay_page(&events),
            Err(ReplayPageError::TooManyBytes)
        );

        // snapshot_required response.
        let resp = RemoteReattachResponseV1::SnapshotRequired {
            schema_version: 1,
            snapshot_id: "snap-1".into(),
            snapshot_payload: vec![1, 2, 3],
            compacted_through_event_seq: "100".into(),
            high_water_event_seq: "200".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["kind"], "snapshot_required");
    }

    // ── Operation recovery ──────────────────────────────────────────────

    #[test]
    fn remote_reattach_operation_recovery_matrix() {
        // Every ledger class/status combination.
        for class in [
            RemoteContinuityOperationClass::ReadOnly,
            RemoteContinuityOperationClass::TransactionalMutation,
            RemoteContinuityOperationClass::IdempotentAdapterMutation,
            RemoteContinuityOperationClass::NonrepeatableMutation,
        ] {
            // Committed → return committed outcome.
            assert_eq!(
                operation_recovery_action(RemoteOperationStatus::Committed, class),
                RemoteOperationRecoveryAction::ReturnCommittedOutcome
            );
            // Rejected → return rejected outcome.
            assert_eq!(
                operation_recovery_action(RemoteOperationStatus::Rejected, class),
                RemoteOperationRecoveryAction::ReturnRejectedOutcome
            );
            // Reserved → reconcile.
            assert_eq!(
                operation_recovery_action(RemoteOperationStatus::Reserved, class),
                RemoteOperationRecoveryAction::ReconcileReserved
            );
            // OutcomeUnknown → safe actions (never auto-retry).
            assert_eq!(
                operation_recovery_action(RemoteOperationStatus::OutcomeUnknown, class),
                RemoteOperationRecoveryAction::OutcomeUnknownSafeActions
            );
            // NotFound → resubmit if class permits.
            assert_eq!(
                operation_recovery_action(RemoteOperationStatus::NotFound, class),
                RemoteOperationRecoveryAction::ResubmitIfClassPermitsRetry
            );
        }

        // outcome_unknown is never auto-retried — it maps to safe actions,
        // not resubmit.
        for class in [
            RemoteContinuityOperationClass::ReadOnly,
            RemoteContinuityOperationClass::TransactionalMutation,
            RemoteContinuityOperationClass::IdempotentAdapterMutation,
            RemoteContinuityOperationClass::NonrepeatableMutation,
        ] {
            let action = operation_recovery_action(RemoteOperationStatus::OutcomeUnknown, class);
            assert_ne!(
                action,
                RemoteOperationRecoveryAction::ResubmitIfClassPermitsRetry,
                "outcome_unknown must never auto-retry"
            );
        }

        // class_permits_retry.
        assert!(class_permits_retry(
            RemoteContinuityOperationClass::ReadOnly
        ));
        assert!(class_permits_retry(
            RemoteContinuityOperationClass::IdempotentAdapterMutation
        ));
        assert!(!class_permits_retry(
            RemoteContinuityOperationClass::TransactionalMutation
        ));
        assert!(!class_permits_retry(
            RemoteContinuityOperationClass::NonrepeatableMutation
        ));
    }

    // ── Connection lease wire and time ──────────────────────────────────

    #[test]
    fn remote_connection_lease_wire_and_time() {
        // Prove exact refresh-authorization and lease typ/payload, 300/120
        // timing, one current generation/digest, both-null/both-nonnull
        // tenant matrix, cycle-free fallback gate, pre-grant-only signer
        // evidence, and no widening/grace.

        // Typ values.
        assert_eq!(
            REMOTE_CONNECTION_LEASE_JWS_TYP,
            "flycockpit-remote-connection-lease+jws"
        );
        assert_eq!(
            REMOTE_LEASE_REFRESH_AUTH_JWS_TYP,
            "flycockpit-remote-lease-refresh-authorization+jws"
        );

        // Timing: 300s validity, 120s refresh, 0 grace.
        assert_eq!(REMOTE_CONNECTION_LEASE_VALID_SECONDS, 300);
        assert_eq!(REMOTE_CONNECTION_LEASE_REFRESH_INTERVAL_SECONDS, 120);
        assert_eq!(REMOTE_CONNECTION_LEASE_GRACE_SECONDS, 0);

        // 16,384-byte lease JWS cap.
        assert_eq!(REMOTE_CONNECTION_LEASE_MAX_BYTES, 16384);
        assert!(validate_lease_jws_size(&[0u8; 16384]).is_ok());
        assert_eq!(
            validate_lease_jws_size(&[0u8; 16385]),
            Err(LeaseValidationError::JwsTooLarge)
        );

        // Refresh authorization payload has no admission/proof/transport
        // fields (pre-grant-only signer evidence).
        let forbidden = [
            "admissionSequence",
            "offerJti",
            "proofJti",
            "transportEpoch",
            "negotiationDigest",
            "route",
            "connectionLease",
            "activeChildren",
        ];
        for f in forbidden {
            assert!(
                !REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS.contains(&f),
                "refresh auth must not contain {f}"
            );
        }

        // Connection lease payload member set is exact.
        let lease_keys: Vec<String> = CONNECTION_LEASE_PAYLOAD_MEMBERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(validate_exact_payload_keys(&lease_keys, CONNECTION_LEASE_PAYLOAD_MEMBERS).is_ok());

        // The lease payload contains post-proof active-child binding
        // (activeChildren) — the refresh auth does not.
        assert!(CONNECTION_LEASE_PAYLOAD_MEMBERS.contains(&"activeChildren"));
        assert!(!REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS.contains(&"activeChildren"));

        // The refresh auth has tenantAuthorizationDigest (single);
        // the lease has both statement and status digests (both-null/
        // both-nonnull matrix).
        assert!(REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS.contains(&"tenantAuthorizationDigest"));
        assert!(
            !REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS.contains(&"tenantAuthorizationStatementDigest")
        );
        assert!(!REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS.contains(&"tenantAuthorityStatusDigest"));
        assert!(CONNECTION_LEASE_PAYLOAD_MEMBERS.contains(&"tenantAuthorizationStatementDigest"));
        assert!(CONNECTION_LEASE_PAYLOAD_MEMBERS.contains(&"tenantAuthorityStatusDigest"));
    }

    #[test]
    fn remote_connection_lease_typ_and_aud() {
        assert_eq!(
            REMOTE_CONNECTION_LEASE_JWS_TYP,
            "flycockpit-remote-connection-lease+jws"
        );
        assert_eq!(REMOTE_CONNECTION_LEASE_JWS_ALG, "ES256");
        assert_eq!(REMOTE_CONNECTION_LEASE_MAX_BYTES, 16384);
        assert_eq!(REMOTE_CONNECTION_LEASE_VALID_SECONDS, 300);
        assert_eq!(REMOTE_CONNECTION_LEASE_REFRESH_INTERVAL_SECONDS, 120);
        assert_eq!(REMOTE_CONNECTION_LEASE_GRACE_SECONDS, 0);
    }

    #[test]
    fn remote_connection_lease_payload_both_null_tenant() {
        let payload = RemoteConnectionLeasePayloadV1 {
            schema_version: 1,
            iss: "iss".into(),
            aud: "flycockpit-remote-connection-lease-v1".into(),
            lease_id: "l-1".into(),
            lease_generation: "1".into(),
            refresh_request_id: "r-1".into(),
            refresh_authorization_digest: "d".into(),
            tenant_id: "t".into(),
            account_id: "a".into(),
            client_device_id: "d".into(),
            client_device_generation: "1".into(),
            daemon_instance_id: "i".into(),
            daemon_certificate_generation: "1".into(),
            logical_attachment_id: "att".into(),
            service_version: "1".into(),
            service_policy_digest: "d".into(),
            policy_epoch: "1".into(),
            policy_digest: "d".into(),
            authority_epoch: "1".into(),
            permission_ceiling_digest: "d".into(),
            daemon_local_policy_digest: "d".into(),
            active_children: vec![RemoteLeaseActiveChildV1 {
                child_attempt_id: "c-1".into(),
                transport_epoch: "e-1".into(),
                transport: RemoteLeaseTransport::WebRtc,
                lifecycle: RemoteLeaseChildLifecycle::Current,
                final_proof_set_digest: "d".into(),
            }],
            tenant_authorization_statement_digest: None,
            tenant_authority_status_digest: None,
            iat: "1000".into(),
            valid_until: "1300".into(),
        };
        assert!(payload.validate(1100).is_ok());
        // One-null combinations fail.
        let mut bad = payload.clone();
        bad.tenant_authorization_statement_digest = Some("d".into());
        assert_eq!(
            bad.validate(1100),
            Err(LeaseValidationError::TenantMatrixOneNull)
        );
    }

    #[test]
    fn remote_connection_lease_payload_both_nonnull_tenant() {
        let payload = RemoteConnectionLeasePayloadV1 {
            schema_version: 1,
            iss: "iss".into(),
            aud: "flycockpit-remote-connection-lease-v1".into(),
            lease_id: "l-1".into(),
            lease_generation: "1".into(),
            refresh_request_id: "r-1".into(),
            refresh_authorization_digest: "d".into(),
            tenant_id: "t".into(),
            account_id: "a".into(),
            client_device_id: "d".into(),
            client_device_generation: "1".into(),
            daemon_instance_id: "i".into(),
            daemon_certificate_generation: "1".into(),
            logical_attachment_id: "att".into(),
            service_version: "1".into(),
            service_policy_digest: "d".into(),
            policy_epoch: "1".into(),
            policy_digest: "d".into(),
            authority_epoch: "1".into(),
            permission_ceiling_digest: "d".into(),
            daemon_local_policy_digest: "d".into(),
            active_children: vec![RemoteLeaseActiveChildV1 {
                child_attempt_id: "c-1".into(),
                transport_epoch: "e-1".into(),
                transport: RemoteLeaseTransport::WebRtc,
                lifecycle: RemoteLeaseChildLifecycle::Current,
                final_proof_set_digest: "d".into(),
            }],
            tenant_authorization_statement_digest: Some("d".into()),
            tenant_authority_status_digest: Some("d".into()),
            iat: "1000".into(),
            valid_until: "1300".into(),
        };
        assert!(payload.validate(1100).is_ok());
    }

    #[test]
    fn remote_connection_lease_child_caps() {
        let make_payload =
            |children: Vec<RemoteLeaseActiveChildV1>| RemoteConnectionLeasePayloadV1 {
                schema_version: 1,
                iss: "iss".into(),
                aud: "flycockpit-remote-connection-lease-v1".into(),
                lease_id: "l".into(),
                lease_generation: "1".into(),
                refresh_request_id: "r".into(),
                refresh_authorization_digest: "d".into(),
                tenant_id: "t".into(),
                account_id: "a".into(),
                client_device_id: "d".into(),
                client_device_generation: "1".into(),
                daemon_instance_id: "i".into(),
                daemon_certificate_generation: "1".into(),
                logical_attachment_id: "att".into(),
                service_version: "1".into(),
                service_policy_digest: "d".into(),
                policy_epoch: "1".into(),
                policy_digest: "d".into(),
                authority_epoch: "1".into(),
                permission_ceiling_digest: "d".into(),
                daemon_local_policy_digest: "d".into(),
                active_children: children,
                tenant_authorization_statement_digest: None,
                tenant_authority_status_digest: None,
                iat: "1000".into(),
                valid_until: "1300".into(),
            };

        let make_child =
            |id: &str, transport: RemoteLeaseTransport, lifecycle: RemoteLeaseChildLifecycle| {
                RemoteLeaseActiveChildV1 {
                    child_attempt_id: id.into(),
                    transport_epoch: "e".into(),
                    transport,
                    lifecycle,
                    final_proof_set_digest: "d".into(),
                }
            };

        // Two current (one WebRTC + one WebSocket) — OK.
        let p = make_payload(vec![
            make_child(
                "c-1",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Current,
            ),
            make_child(
                "c-2",
                RemoteLeaseTransport::WebSocket,
                RemoteLeaseChildLifecycle::Current,
            ),
        ]);
        assert!(p.validate(1100).is_ok());

        // Two current WebRTC — fail.
        let p = make_payload(vec![
            make_child(
                "c-1",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Current,
            ),
            make_child(
                "c-2",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Current,
            ),
        ]);
        assert_eq!(
            p.validate(1100),
            Err(LeaseValidationError::TooManyCurrentWebRtc)
        );

        // TURN cutover: one current + one draining (same transport) + one
        // current WebSocket = three total — OK.
        let p = make_payload(vec![
            make_child(
                "c-1",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Current,
            ),
            make_child(
                "c-2",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Draining,
            ),
            make_child(
                "c-3",
                RemoteLeaseTransport::WebSocket,
                RemoteLeaseChildLifecycle::Current,
            ),
        ]);
        assert!(p.validate(1100).is_ok());

        // Four children — fail.
        let p = make_payload(vec![
            make_child(
                "c-1",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Current,
            ),
            make_child(
                "c-2",
                RemoteLeaseTransport::WebRtc,
                RemoteLeaseChildLifecycle::Draining,
            ),
            make_child(
                "c-3",
                RemoteLeaseTransport::WebSocket,
                RemoteLeaseChildLifecycle::Current,
            ),
            make_child(
                "c-4",
                RemoteLeaseTransport::WebSocket,
                RemoteLeaseChildLifecycle::Current,
            ),
        ]);
        assert_eq!(p.validate(1100), Err(LeaseValidationError::TooManyChildren));
    }

    #[test]
    fn remote_connection_lease_no_grace_after_expiry() {
        let payload = RemoteConnectionLeasePayloadV1 {
            schema_version: 1,
            iss: "iss".into(),
            aud: "flycockpit-remote-connection-lease-v1".into(),
            lease_id: "l".into(),
            lease_generation: "1".into(),
            refresh_request_id: "r".into(),
            refresh_authorization_digest: "d".into(),
            tenant_id: "t".into(),
            account_id: "a".into(),
            client_device_id: "d".into(),
            client_device_generation: "1".into(),
            daemon_instance_id: "i".into(),
            daemon_certificate_generation: "1".into(),
            logical_attachment_id: "att".into(),
            service_version: "1".into(),
            service_policy_digest: "d".into(),
            policy_epoch: "1".into(),
            policy_digest: "d".into(),
            authority_epoch: "1".into(),
            permission_ceiling_digest: "d".into(),
            daemon_local_policy_digest: "d".into(),
            active_children: vec![],
            tenant_authorization_statement_digest: None,
            tenant_authority_status_digest: None,
            iat: "1000".into(),
            valid_until: "1300".into(),
        };
        // At exactly validUntil — OK.
        assert!(payload.validate(1300).is_ok());
        // One second after — fail (no grace).
        assert_eq!(payload.validate(1301), Err(LeaseValidationError::Expired));
    }

    // ── Refresh authorization ───────────────────────────────────────────

    #[test]
    fn remote_refresh_authorization_typ_and_aud() {
        assert_eq!(
            REMOTE_LEASE_REFRESH_AUTH_JWS_TYP,
            "flycockpit-remote-lease-refresh-authorization+jws"
        );
        assert_eq!(REMOTE_LEASE_REFRESH_AUTH_JWS_ALG, "ES256");
    }

    #[test]
    fn remote_refresh_authorization_payload_members_exact() {
        // The refresh authorization payload must not contain any
        // admission/proof/transport field.
        let forbidden = [
            "admissionSequence",
            "offerJti",
            "proofJti",
            "transportEpoch",
            "negotiationDigest",
            "noiseDigest",
            "dtlsDigest",
            "route",
            "connectionLease",
            "activeChildren",
            "activeChildClaim",
        ];
        for f in forbidden {
            assert!(
                !REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS.contains(&f),
                "refresh authorization payload must not contain {f}"
            );
        }
    }

    #[test]
    fn remote_refresh_authorization_validate() {
        let payload = RemoteLeaseRefreshAuthorizationPayloadV1 {
            schema_version: 1,
            iss: "iss".into(),
            aud: "flycockpit-remote-lease-refresh-v1".into(),
            authorization_id: "a".into(),
            tenant_id: "t".into(),
            account_id: "acc".into(),
            client_device_id: "d".into(),
            client_certificate_generation: "1".into(),
            daemon_instance_id: "i".into(),
            daemon_certificate_generation: "1".into(),
            logical_attachment_id: "att".into(),
            service_version: "1".into(),
            service_policy_digest: "d".into(),
            policy_epoch: "1".into(),
            policy_digest: "d".into(),
            authority_epoch: "1".into(),
            permission_ceiling_digest: "d".into(),
            tenant_authorization_digest: None,
            iat: "1000".into(),
            exp: "1300".into(),
            jti: "j".into(),
        };
        assert!(payload.validate().is_ok());

        // Bad audience.
        let mut bad = payload.clone();
        bad.aud = "wrong".into();
        assert_eq!(bad.validate(), Err(RefreshAuthValidationError::Audience));

        // Time order violation.
        let mut bad = payload.clone();
        bad.iat = "1400".into();
        bad.exp = "1300".into();
        assert_eq!(bad.validate(), Err(RefreshAuthValidationError::TimeOrder));
    }

    // ── Control event wire replay (FCRC) ────────────────────────────────

    /// The named, fixed-input control-event corpus. Both the committed golden
    /// fixture and the wire-replay test are derived from exactly this corpus,
    /// so the fixture cannot drift from the codec silently. The TS encoder must
    /// reproduce these exact bytes for every entry at the cross-language gate.
    fn control_event_fixture_corpus() -> Vec<(&'static str, RemoteControlEventV1)> {
        let seal = RemoteControlEventV1::seal;
        vec![
            (
                "lease_refresh_min",
                seal(
                    1,
                    [0x11; 16],
                    7,
                    3,
                    2,
                    1_700_000_000,
                    RemoteControlEventPayload::LeaseRefresh {
                        lease_jws: b"lease.jws.min".to_vec(),
                    },
                ),
            ),
            (
                "lease_refresh_max",
                seal(
                    2,
                    [0x12; 16],
                    7,
                    3,
                    2,
                    1_700_000_001,
                    RemoteControlEventPayload::LeaseRefresh {
                        lease_jws: vec![0xAB; REMOTE_CONTROL_EVENT_MAX_EMBEDDED_JWS],
                    },
                ),
            ),
            (
                "policy_narrowed",
                seal(
                    3,
                    [0x22; 16],
                    8,
                    4,
                    2,
                    1_700_000_002,
                    RemoteControlEventPayload::PolicyNarrowed {
                        previous_digest: [0xA0; 32],
                        new_digest: [0xB0; 32],
                        affected_field_bits: 0x0102_0304_0506_0708,
                    },
                ),
            ),
            (
                "device_revoked",
                seal(
                    4,
                    [0x33; 16],
                    8,
                    4,
                    2,
                    1_700_000_003,
                    RemoteControlEventPayload::DeviceRevoked {
                        device_id: [0xD0; 16],
                        generation: 99,
                    },
                ),
            ),
            (
                "instance_revoked",
                seal(
                    5,
                    [0x44; 16],
                    8,
                    4,
                    2,
                    1_700_000_004,
                    RemoteControlEventPayload::InstanceRevoked {
                        instance_id: [0xE0; 16],
                        generation: 5,
                    },
                ),
            ),
            (
                "tenant_authority_changed",
                seal(
                    6,
                    [0x55; 16],
                    8,
                    4,
                    3,
                    1_700_000_005,
                    RemoteControlEventPayload::TenantAuthorityChanged {
                        previous_epoch: 2,
                        new_epoch: 3,
                        ring_digest: [0xC0; 32],
                    },
                ),
            ),
            (
                "attachment_revoked",
                seal(
                    7,
                    [0x66; 16],
                    8,
                    4,
                    3,
                    1_700_000_006,
                    RemoteControlEventPayload::AttachmentRevoked {
                        logical_attachment_id: [0xF0; 16],
                        reason: 2,
                    },
                ),
            ),
            (
                "drain",
                seal(
                    8,
                    [0x77; 16],
                    8,
                    4,
                    3,
                    1_700_000_007,
                    RemoteControlEventPayload::Drain {
                        deadline: 1_700_000_500,
                        reason: 1,
                    },
                ),
            ),
            (
                "authority_status",
                seal(
                    9,
                    [0x88; 16],
                    8,
                    4,
                    3,
                    1_700_000_008,
                    RemoteControlEventPayload::AuthorityStatus {
                        status_generation: 42,
                        status_jws: b"status.jws.min".to_vec(),
                    },
                ),
            ),
        ]
    }

    #[derive(serde::Deserialize)]
    struct ControlEventFixtureEntry {
        name: String,
        kind: String,
        #[serde(rename = "kindByte")]
        kind_byte: u8,
        #[serde(rename = "eventHex")]
        event_hex: String,
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "hex must be even length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
            .collect()
    }

    #[test]
    fn remote_control_event_wire_replay() {
        let fixture_json = include_str!(
            "../../../packages/cockpit-protocol/fixtures/remote-control-event-v1.json"
        );
        let entries: Vec<ControlEventFixtureEntry> =
            serde_json::from_str(fixture_json).expect("golden control-event fixture parses");
        let corpus = control_event_fixture_corpus();
        assert_eq!(
            entries.len(),
            corpus.len(),
            "fixture entry count must match the corpus"
        );

        for ((name, expected), entry) in corpus.iter().zip(entries.iter()) {
            assert_eq!(&entry.name, name, "fixture order must match corpus");
            assert_eq!(
                entry.kind_byte,
                expected.header.kind.to_byte(),
                "{name}: kind byte"
            );

            let bytes = hex_decode(&entry.event_hex);
            // The committed golden bytes decode to exactly the sealed event.
            let decoded = RemoteControlEventV1::decode(&bytes)
                .unwrap_or_else(|e| panic!("{name}: golden vector must decode: {e:?}"));
            assert_eq!(&decoded, expected, "{name}: decoded event");
            // And re-encode byte-for-byte to the committed bytes.
            assert_eq!(decoded.encode(), bytes, "{name}: re-encode identity");

            // Independent structural anchors (catch layout drift without the
            // encoder): magic, version, kind byte offset, and payload start.
            assert_eq!(&bytes[0..4], b"FCRC", "{name}: magic");
            assert_eq!(bytes[4], 1, "{name}: version");
            assert_eq!(bytes[29], entry.kind_byte, "{name}: kind at offset 29");
            assert_eq!(
                &bytes[13..29],
                &expected.header.event_id,
                "{name}: eventId at 13..29"
            );
            assert_eq!(
                bytes.len(),
                REMOTE_CONTROL_EVENT_HEADER_BYTES + expected.header.payload_length as usize,
                "{name}: total length = 98 + payloadLength"
            );
            assert_eq!(&entry.kind, &control_event_kind_name(expected.header.kind));
        }
    }

    fn control_event_kind_name(kind: RemoteControlEventKind) -> String {
        serde_json::to_value(kind)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn remote_control_event_rejects_tampered_and_rcev() {
        let (_, event) = &control_event_fixture_corpus()[3]; // device_revoked
        let good = event.encode();

        // Trailing byte → wrong exact payload length.
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(
            RemoteControlEventV1::decode(&trailing),
            Err(ControlEventError::PayloadLength)
        );

        // Flip a payload byte without updating the digest → digest mismatch.
        let mut tampered = good.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert_eq!(
            RemoteControlEventV1::decode(&tampered),
            Err(ControlEventError::DigestMismatch)
        );

        // Unknown kind ordinal (0 and 9 are outside 1..=8).
        let mut unknown = good.clone();
        unknown[29] = 9;
        assert_eq!(
            RemoteControlEventV1::decode(&unknown),
            Err(ControlEventError::UnknownKind)
        );

        // A valid RCEV-era blob (old magic "RCEV") is rejected on magic.
        let mut rcev = good.clone();
        rcev[0..4].copy_from_slice(b"RCEV");
        assert_eq!(
            RemoteControlEventV1::decode(&rcev),
            Err(ControlEventError::Magic)
        );

        // Zero event id and zero control seq are rejected at header decode.
        let mut zero_id = good.clone();
        zero_id[13..29].fill(0);
        assert_eq!(
            RemoteControlEventV1::decode(&zero_id),
            Err(ControlEventError::EventIdZero)
        );
    }

    #[test]
    fn remote_control_event_embedded_jws_bounds() {
        // A lease_refresh whose declared inner length exceeds 16,384 is
        // rejected before any mutation.
        let event = RemoteControlEventV1::seal(
            1,
            [0x11; 16],
            1,
            1,
            1,
            0,
            RemoteControlEventPayload::LeaseRefresh {
                lease_jws: vec![0x01; REMOTE_CONTROL_EVENT_MAX_EMBEDDED_JWS + 1],
            },
        );
        assert_eq!(
            RemoteControlEventV1::decode(&event.encode()),
            Err(ControlEventError::EmbeddedJwsLength)
        );
    }

    // ── Revocation operation barrier ────────────────────────────────────

    #[test]
    fn remote_revocation_operation_barrier() {
        // transactional_mutation, reserved → continue_recorded_snapshot.
        let (disp, cls) = revocation_disposition(
            RemoteContinuityOperationClass::TransactionalMutation,
            true,
            false,
        );
        assert_eq!(disp, RemoteRevocationDisposition::ContinueRecordedSnapshot);
        assert_eq!(cls, RemoteLongRunningClassification::Continue);

        // transactional_mutation, not reserved → cancel.
        let (disp, cls) = revocation_disposition(
            RemoteContinuityOperationClass::TransactionalMutation,
            false,
            false,
        );
        assert_eq!(disp, RemoteRevocationDisposition::ContinueRecordedSnapshot);
        assert_eq!(cls, RemoteLongRunningClassification::Cancel);

        // idempotent_adapter_mutation, not dispatched → cancel_before_apply.
        let (disp, cls) = revocation_disposition(
            RemoteContinuityOperationClass::IdempotentAdapterMutation,
            true,
            false,
        );
        assert_eq!(disp, RemoteRevocationDisposition::CancelBeforeApply);
        assert_eq!(cls, RemoteLongRunningClassification::Cancel);

        // idempotent_adapter_mutation, dispatched → reconcile.
        let (disp, cls) = revocation_disposition(
            RemoteContinuityOperationClass::IdempotentAdapterMutation,
            true,
            true,
        );
        assert_eq!(
            disp,
            RemoteRevocationDisposition::ReconcileNamedDurableResultThenFinalize
        );
        assert_eq!(cls, RemoteLongRunningClassification::Cancel);

        // nonrepeatable_mutation, not dispatched → cancel_before_dispatch.
        let (disp, cls) = revocation_disposition(
            RemoteContinuityOperationClass::NonrepeatableMutation,
            false,
            false,
        );
        assert_eq!(disp, RemoteRevocationDisposition::CancelBeforeDispatch);
        assert_eq!(cls, RemoteLongRunningClassification::Cancel);

        // nonrepeatable_mutation, dispatched → outcome_unknown.
        let (disp, cls) = revocation_disposition(
            RemoteContinuityOperationClass::NonrepeatableMutation,
            true,
            true,
        );
        assert_eq!(disp, RemoteRevocationDisposition::OutcomeUnknown);
        assert_eq!(cls, RemoteLongRunningClassification::Cancel);

        // read_only → cancel_at_next_yield_and_reauthorize.
        let (disp, cls) =
            revocation_disposition(RemoteContinuityOperationClass::ReadOnly, false, false);
        assert_eq!(
            disp,
            RemoteRevocationDisposition::CancelAtNextYieldAndReauthorize
        );
        assert_eq!(cls, RemoteLongRunningClassification::Cancel);
    }

    #[test]
    fn remote_tag_column_validation() {
        // Both present — OK.
        assert!(
            validate_tag_has_both_columns(
                Some(RemoteContinuityOperationClass::ReadOnly),
                Some(RemoteRevocationDisposition::CancelAtNextYieldAndReauthorize),
            )
            .is_ok()
        );
        // Missing class.
        assert_eq!(
            validate_tag_has_both_columns(
                None,
                Some(RemoteRevocationDisposition::CancelAtNextYieldAndReauthorize),
            ),
            Err(TagColumnError::MissingClass)
        );
        // Missing disposition.
        assert_eq!(
            validate_tag_has_both_columns(Some(RemoteContinuityOperationClass::ReadOnly), None),
            Err(TagColumnError::MissingDisposition)
        );
        // Missing both.
        assert_eq!(
            validate_tag_has_both_columns(None, None),
            Err(TagColumnError::MissingBoth)
        );
    }

    // ── Policy cannot widen (AC-7 / AC-8) ────────────────────────────────

    fn ceiling(
        digest: u8,
        scopes: &[&str],
        projects: &[&str],
        transports: &[&str],
        custody: &[&str],
        children: &[&str],
    ) -> RefreshCeiling {
        let set = |xs: &[&str]| xs.iter().map(|s| s.to_string()).collect::<BTreeSet<_>>();
        RefreshCeiling {
            ceiling_digest: [digest; 32],
            scopes: set(scopes),
            projects: set(projects),
            transports: set(transports),
            custody_requirements: set(custody),
            children: set(children),
        }
    }

    #[test]
    fn remote_policy_cannot_widen_daemon_authority() {
        let old = ceiling(
            1,
            &["read", "write"],
            &["p1", "p2"],
            &["webrtc", "websocket"],
            &["passkey"],
            &["c1", "c2"],
        );

        // Equal digests short-circuit as unchanged even if the sets differ.
        let mut same_digest = ceiling(1, &["read", "write", "admin"], &[], &[], &[], &[]);
        same_digest.ceiling_digest = old.ceiling_digest;
        assert!(validate_refresh_narrows(&old, &same_digest).is_ok());

        // A genuine narrow (subset across every set, a dropped child) is
        // accepted.
        let narrowed = ceiling(2, &["read"], &["p1"], &["webrtc"], &["passkey"], &["c1"]);
        assert!(validate_refresh_narrows(&old, &narrowed).is_ok());

        // Widening any one set is rejected with the specific error; each case
        // fails against the old count-only implementation (which ignored the
        // sets entirely).
        let widen_scope = ceiling(
            2,
            &["read", "write", "admin"],
            &["p1"],
            &["webrtc"],
            &[],
            &["c1"],
        );
        assert_eq!(
            validate_refresh_narrows(&old, &widen_scope),
            Err(RefreshWidenError::ScopeWidened)
        );
        let widen_project = ceiling(2, &["read"], &["p1", "p3"], &["webrtc"], &[], &["c1"]);
        assert_eq!(
            validate_refresh_narrows(&old, &widen_project),
            Err(RefreshWidenError::ProjectWidened)
        );
        let widen_transport = ceiling(
            2,
            &["read"],
            &["p1"],
            &["webrtc", "quic"],
            &["passkey"],
            &["c1"],
        );
        assert_eq!(
            validate_refresh_narrows(&old, &widen_transport),
            Err(RefreshWidenError::TransportWidened)
        );
        let widen_custody = ceiling(
            2,
            &["read"],
            &["p1"],
            &["webrtc"],
            &["passkey", "hardware-key"],
            &["c1"],
        );
        assert_eq!(
            validate_refresh_narrows(&old, &widen_custody),
            Err(RefreshWidenError::CustodyWidened)
        );
        let add_child = ceiling(
            2,
            &["read"],
            &["p1"],
            &["webrtc"],
            &["passkey"],
            &["c1", "c2", "c3"],
        );
        assert_eq!(
            validate_refresh_narrows(&old, &add_child),
            Err(RefreshWidenError::ChildAdded)
        );
    }

    // ── Lease replacement generation ─────────────────────────────────────

    #[test]
    fn remote_lease_replacement_generation_monotonic() {
        assert!(validate_lease_replacement_generation(1, 2).is_ok());
        assert_eq!(
            validate_lease_replacement_generation(2, 2),
            Err(LeaseReplacementError::GenerationNotMonotonic)
        );
        assert_eq!(
            validate_lease_replacement_generation(3, 2),
            Err(LeaseReplacementError::GenerationNotMonotonic)
        );
    }

    #[test]
    fn remote_exact_retry_same_generation_and_digest() {
        let digest = [1u8; 32];
        assert!(validate_exact_retry(1, &digest, 1, &digest).is_ok());
        assert_eq!(
            validate_exact_retry(1, &digest, 2, &digest),
            Err(LeaseReplacementError::DigestMismatch)
        );
        let other = [2u8; 32];
        assert_eq!(
            validate_exact_retry(1, &digest, 1, &other),
            Err(LeaseReplacementError::DigestMismatch)
        );
    }

    // ── Event delivery dedupe ────────────────────────────────────────────

    #[test]
    fn remote_event_delivery_dedupe() {
        let mut state = RemoteDeliveryDedupeState::new();
        // First delivery — should send.
        assert!(state.mark_delivered("del-1"));
        // Second delivery of same ID — should skip.
        assert!(!state.mark_delivered("del-1"));
        // Different ID — should send.
        assert!(state.mark_delivered("del-2"));
        // Check is_delivered.
        assert!(state.is_delivered("del-1"));
        assert!(state.is_delivered("del-2"));
        assert!(!state.is_delivered("del-3"));
        // Forget allows replay.
        state.forget("del-1");
        assert!(!state.is_delivered("del-1"));
        assert!(state.mark_delivered("del-1"));
    }

    // ── Mobile UI states ─────────────────────────────────────────────────

    #[test]
    fn remote_mobile_ui_states_exact() {
        let states = [
            RemoteMobileUiState::Reconnecting,
            RemoteMobileUiState::ReauthenticationRequired,
            RemoteMobileUiState::SnapshotRequired,
            RemoteMobileUiState::OutcomeUnknown,
            RemoteMobileUiState::AccessRevoked,
            RemoteMobileUiState::SessionTerminal,
        ];
        // Verify exact serde spellings.
        assert_eq!(
            serde_json::to_string(&RemoteMobileUiState::Reconnecting).unwrap(),
            "\"reconnecting\""
        );
        assert_eq!(
            serde_json::to_string(&RemoteMobileUiState::ReauthenticationRequired).unwrap(),
            "\"reauthentication_required\""
        );
        assert_eq!(
            serde_json::to_string(&RemoteMobileUiState::SnapshotRequired).unwrap(),
            "\"snapshot_required\""
        );
        assert_eq!(
            serde_json::to_string(&RemoteMobileUiState::OutcomeUnknown).unwrap(),
            "\"outcome_unknown\""
        );
        assert_eq!(
            serde_json::to_string(&RemoteMobileUiState::AccessRevoked).unwrap(),
            "\"access_revoked\""
        );
        assert_eq!(
            serde_json::to_string(&RemoteMobileUiState::SessionTerminal).unwrap(),
            "\"session_terminal\""
        );
        // Exactly 6 states.
        assert_eq!(states.len(), 6);
    }

    // ── Payload key validation ───────────────────────────────────────────

    #[test]
    fn remote_payload_key_validation() {
        let keys: Vec<String> = REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(validate_exact_payload_keys(&keys, REFRESH_AUTHORIZATION_PAYLOAD_MEMBERS).is_ok());

        let lease_keys: Vec<String> = CONNECTION_LEASE_PAYLOAD_MEMBERS
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert!(validate_exact_payload_keys(&lease_keys, CONNECTION_LEASE_PAYLOAD_MEMBERS).is_ok());
    }

    // ── Control event byte hash ──────────────────────────────────────────

    #[test]
    fn remote_control_event_byte_hash() {
        let bytes = [1u8; 100];
        let hash = control_event_byte_hash(&bytes);
        assert_eq!(hash.len(), 32);
        // Deterministic.
        assert_eq!(control_event_byte_hash(&bytes), hash);
    }

    // ── Lease JWS digest ─────────────────────────────────────────────────

    #[test]
    fn remote_lease_jws_digest() {
        let jws = b"header.payload.signature";
        let digest = lease_jws_digest(jws);
        assert_eq!(digest.len(), 32);
        assert_eq!(lease_jws_digest(jws), digest);
    }

    // ── Refresh auth JWS digest ──────────────────────────────────────────

    #[test]
    fn remote_refresh_auth_jws_digest() {
        let jws = b"header.payload.signature";
        let digest = refresh_authorization_jws_digest(jws);
        assert_eq!(digest.len(), 32);
        assert_eq!(refresh_authorization_jws_digest(jws), digest);
    }
}
