//! Immutable, typed, session-scoped text artifacts.
//!
//! This module owns artifact admission, event ownership, quota reservations,
//! and their state transitions. Callers never choose an artifact identifier or
//! assemble an artifact/ref write out of separate public operations.

use anyhow::{Context, Result, anyhow, bail, ensure};
use rusqlite::{Connection, OptionalExtension, params};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

use crate::db::Db;
use crate::db::message_attachments::{
    AcceptMessageInput, AcceptMessageResult, MessageAcceptanceJoin, MessageSafeOutcome,
};
use crate::db::session_log::{
    ClientSubmissionTerminalReceipt, SessionEventContext, SessionEventKind,
};

pub const MAX_ARTIFACT_CONTENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_SESSION_ARTIFACT_CONTENT_BYTES: usize = 64 * 1024 * 1024;
pub const ARTIFACT_RESERVATION_TTL_MS: i64 = 10 * 60 * 1000;
pub const ARTIFACT_RESERVATION_RENEW_AT_REMAINING_MS: i64 = 5 * 60 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextArtifactKind {
    ToolResult,
    UserInputSource,
    UserInputProjection,
}

impl TextArtifactKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ToolResult => "tool_result",
            Self::UserInputSource => "user_input_source",
            Self::UserInputProjection => "user_input_projection",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureReason {
    DisplayTruncation,
    PruneBoundary,
    OversizedUserInput,
}

impl CaptureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DisplayTruncation => "display_truncation",
            Self::PruneBoundary => "prune_boundary",
            Self::OversizedUserInput => "oversized_user_input",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextArtifactRelation {
    SourceUserInput,
    ModelUserInputProjection,
    ModelContextToolResult,
}

impl TextArtifactRelation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SourceUserInput => "source_user_input",
            Self::ModelUserInputProjection => "model_user_input_projection",
            Self::ModelContextToolResult => "model_context_tool_result",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TextArtifactRepresentation {
    Raw,
    ExportRedacted,
}

impl TextArtifactRepresentation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::ExportRedacted => "export_redacted",
        }
    }
}

/// A candidate attached while its owning event is inserted. The identifier is
/// intentionally absent: the database mints an opaque UUID only on admission.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactCandidate {
    pub relation: TextArtifactRelation,
    pub projection_slot: Option<i64>,
    pub kind: TextArtifactKind,
    pub capture_reason: CaptureReason,
    pub content: String,
    pub host_captured_bytes: usize,
    pub host_original_bytes: usize,
    pub host_dropped_bytes: usize,
    pub stored_source_bytes: usize,
    pub provenance_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct TextArtifact {
    pub session_id: Uuid,
    pub artifact_id: Uuid,
    /// Present only for the irreversible `export_redacted` bytes admitted by
    /// archive import. Forks retain this opaque provenance rather than
    /// pretending that their copied bytes are raw.
    pub archive_import_id: Option<Uuid>,
    pub event_seq: i64,
    pub relation: TextArtifactRelation,
    pub projection_slot: Option<i64>,
    pub kind: TextArtifactKind,
    pub capture_reason: CaptureReason,
    pub representation: TextArtifactRepresentation,
    pub content: String,
    pub host_captured_bytes: usize,
    pub host_original_bytes: usize,
    pub host_dropped_bytes: usize,
    pub stored_source_bytes: usize,
    pub content_bytes: usize,
    pub provenance_json: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextArtifactAdmission {
    Stored(TextArtifact),
    ArtifactLimit,
    SessionQuota,
}

#[derive(Debug, Clone, Default)]
pub struct TextArtifactEventContext {
    pub origin_principal: Option<String>,
    pub task_call_id: Option<String>,
    pub label: Option<String>,
    pub provider_id: Option<String>,
    pub model_id: Option<String>,
    pub model_trust: Option<String>,
}

impl TextArtifactEventContext {
    fn borrowed(&self) -> SessionEventContext<'_> {
        SessionEventContext {
            origin_principal: self.origin_principal.as_deref(),
            task_call_id: self.task_call_id.as_deref(),
            label: self.label.as_deref(),
            provider_id: self.provider_id.as_deref(),
            model_id: self.model_id.as_deref(),
            model_trust: self.model_trust.as_deref(),
        }
    }
}

/// A single owning-event composition. Quota rejection is returned as a typed
/// branch and the composition itself writes the corresponding closed
/// unavailable projection state into the marker-free event JSON. Callers only
/// provide their ordinary event data; they cannot forge an artifact state.
#[derive(Debug, Clone)]
pub struct TextArtifactEventInput {
    pub session_id: Uuid,
    pub kind: SessionEventKind,
    pub agent: Option<String>,
    pub call_id: Option<String>,
    pub context: TextArtifactEventContext,
    pub ts_ms: i64,
    pub data_json: String,
    pub artifacts: Vec<TextArtifactCandidate>,
    /// A closed, durable projection that deliberately owns no artifact body.
    /// Used when safety could not authorize retaining a capture.
    pub unavailable_projection: Option<TextArtifactUnavailableProjection>,
}

#[derive(Debug, Clone)]
pub struct TextArtifactUnavailableProjection {
    pub candidate: TextArtifactCandidate,
    pub reason: TextArtifactUnavailableReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextArtifactUnavailableReason {
    PersistenceUnavailable,
}

impl TextArtifactUnavailableReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersistenceUnavailable => "persistence_unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactEventResult {
    pub event_seq: i64,
    /// Every outcome is addressed by the typed owner slot, never the caller's
    /// vector position.  In particular prune callers must not zip a SQL row
    /// order or a JSON array order to an artifact frame.
    pub slots: Vec<TextArtifactSlotAdmission>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactSlotAdmission {
    pub relation: TextArtifactRelation,
    pub projection_slot: Option<i64>,
    pub admission: TextArtifactAdmission,
}

/// Durable model-context projection identities for one session.  The text of
/// a rendered frame is never an authority: these sets are reconstructed from
/// the event-owned projection state so a hostile tool result that merely looks
/// like a frame cannot suppress capture, dim a transcript row, or enter the
/// prune ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TextArtifactProjectionCallIds {
    /// Every tool call with a durable model-context projection, including a
    /// quota-rejected/unavailable one that owns no artifact row.
    pub model_context_calls: std::collections::BTreeSet<String>,
    /// The subset owned by a `context_pruned` event.  These are the only tool
    /// projections that participate in the prune ledger/TUI elision state.
    pub prune_boundary_calls: std::collections::BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactReservation {
    pub session_id: Uuid,
    pub operation_id: [u8; 16],
    pub client_submission_id: [u8; 16],
    pub queue_item_id: [u8; 16],
    pub source_digest: [u8; 32],
    pub source_bytes: usize,
    pub reserved_bytes: usize,
    /// True only when this receipt/lease was atomically admitted with the
    /// run-invocation row keyed by the same client submission UUID.
    pub run_invocation_bound: bool,
    /// Optional explicit model fence, persisted outside the frozen FCM2 v2
    /// bytes.  The DB stores a canonical, bounded JSON representation; core
    /// owns conversion to/from the closed `ActiveModelRef` type.
    pub model_fence: Option<TextArtifactModelFence>,
    pub lease_token: Uuid,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactModelFence {
    pub generation: u64,
    pub model_json: String,
}

/// Immutable run metadata admitted with an oversized FCM2 source. This stays
/// inside the DB-owned composition so an accepted run cannot outlive a later
/// terminal message transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifactRunInvocationInput {
    pub origin_principal_digest: String,
    pub options_json: String,
    pub options_digest: String,
    pub content_digest: String,
    pub max_turns: Option<u32>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextArtifactRunInvocationReject {
    IdempotencyConflict,
    ClientSubmissionIdUnavailable,
    CapacityExceeded,
}

#[derive(Debug, Clone)]
struct RollbackRunInvocationAdmission(TextArtifactRunInvocationReject);

impl std::fmt::Display for RollbackRunInvocationAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "run invocation admission rejected: {:?}", self.0)
    }
}

impl std::error::Error for RollbackRunInvocationAdmission {}

/// The exact phase-one lease plus the opaque canonical FCM2 bytes that own its
/// source. Core decodes the bytes with the protocol-owned codec; it never
/// reconstructs source identity from a marker or a mutable queue string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedTextArtifactSubmission {
    pub reservation: TextArtifactReservation,
    pub canonical_message: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextArtifactReservationAcquire {
    Acquired(TextArtifactReservation),
    Existing(TextArtifactReservation),
    SessionQuota,
    Conflict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TextArtifactRejectReason {
    ReservationExpired,
    QuotaExhausted,
    TooLarge,
    SecurityRejected,
    PreflightRejected,
    IdempotencyConflict,
    PersistenceFailed,
}

impl TextArtifactRejectReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReservationExpired => "artifact_reservation_expired",
            Self::QuotaExhausted => "artifact_quota_exhausted",
            Self::TooLarge => "artifact_too_large",
            Self::SecurityRejected => "artifact_security_rejected",
            Self::PreflightRejected => "artifact_preflight_rejected",
            Self::IdempotencyConflict => "artifact_idempotency_conflict",
            Self::PersistenceFailed => "artifact_persistence_failed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextArtifactReservationTransition {
    Applied(TextArtifactRejectReason),
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextArtifactReservationReplay {
    Materialized {
        event_seq: i64,
        source_artifact_id: Uuid,
        projection_artifact_id: Option<Uuid>,
    },
    Terminal {
        reason: TextArtifactRejectReason,
    },
    Live(TextArtifactReservation),
    Expired(TextArtifactReservation),
    Missing,
}

/// The durable FCM2 receipt state for a submission that was admitted through
/// the text-artifact two-phase path.  This deliberately names the receipt
/// state rather than inferring a branch from an ephemeral queue item: callers
/// use it to fail closed when a lease disappears under a reaper/materializer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextArtifactSubmissionDurableState {
    Accepted,
    Materialized,
    Terminal { reason: TextArtifactRejectReason },
    Missing,
}

/// Result of the atomic FCM2 receipt admission plus oversized-source quota
/// reservation. A live lease is returned only after the accepted receipt triple
/// and its exact source identity committed together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TextArtifactPhaseOneResult {
    Reserved(TextArtifactReservation),
    Materialized {
        event_seq: i64,
        source_artifact_id: Uuid,
        projection_artifact_id: Option<Uuid>,
    },
    Terminal {
        reason: TextArtifactRejectReason,
    },
    RunInvocationRejected(TextArtifactRunInvocationReject),
    Conflict,
}

#[derive(Debug, Clone)]
pub struct ReservedUserArtifactMaterialization {
    pub reservation: TextArtifactReservation,
    pub canonical_event_json: String,
    /// Closed typed model composition. It contains an authored slot, never a
    /// duplicate authored body; the slot is rendered from the effective
    /// artifact on both the live and resumed paths.
    pub model_envelope_json: String,
    pub source_text: String,
    pub model_projection: Option<String>,
    pub agent: Option<String>,
    pub context: TextArtifactEventContext,
    pub now_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReservedUserArtifactMaterializationResult {
    Materialized(Box<ReservedUserArtifactMaterialized>),
    ProjectionTooLarge,
    Stale,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedUserArtifactMaterialized {
    pub event_seq: i64,
    pub source_artifact: TextArtifact,
    pub projection_artifact: Option<TextArtifact>,
}

/// Identity and quota inputs for phase-one oversized text reservation.
#[derive(Debug, Clone)]
pub struct TextArtifactReservationInput {
    pub session_id: Uuid,
    pub operation_id: [u8; 16],
    pub client_submission_id: [u8; 16],
    pub queue_item_id: [u8; 16],
    pub source_digest: [u8; 32],
    pub source_bytes: usize,
    pub now_ms: i64,
    pub run_invocation_bound: bool,
    pub model_fence: Option<TextArtifactModelFence>,
}

/// A preflighted import slot. Imported redacted bodies carry structural
/// metadata only; callers must still apply their current outbound safety gate.
#[derive(Debug, Clone)]
pub(crate) struct ImportedTextArtifactSlot {
    /// Source archive identity used only to remap a derived provenance edge.
    /// It is never inserted into the destination database.
    pub source_artifact_id: Uuid,
    pub session_id: Uuid,
    pub event_seq: i64,
    pub candidate: TextArtifactCandidate,
    pub representation: TextArtifactRepresentation,
}

impl Db {
    /// Inserts an owning event and every candidate in one writer transaction.
    pub async fn record_event_with_text_artifacts(
        &self,
        input: TextArtifactEventInput,
    ) -> Result<TextArtifactEventResult> {
        self.transaction(move |conn| record_event_with_text_artifacts_conn(conn, &input))
            .await
    }

    pub async fn text_artifact(
        &self,
        session_id: Uuid,
        artifact_id: Uuid,
    ) -> Result<Option<TextArtifact>> {
        self.read(move |conn| text_artifact_conn(conn, session_id, artifact_id))
            .await
    }

    pub async fn session_has_text_artifacts(&self, session_id: Uuid) -> Result<bool> {
        self.read(move |conn| {
            Ok(conn.query_row(
                "SELECT EXISTS(
                    SELECT 1
                      FROM session_text_artifacts a
                      JOIN session_text_artifact_event_refs r
                        ON r.session_id = a.session_id
                       AND r.artifact_id = a.artifact_id
                     WHERE a.session_id = ?1
                )",
                [session_id.to_string()],
                |row| row.get::<_, i64>(0),
            )? != 0)
        })
        .await
    }

    /// Read the durable event-owned identities for existing model-context
    /// projections.  This is intentionally a narrow, session-scoped read
    /// rather than marker parsing in core; unavailable projections have no
    /// artifact/ref row but remain just as authoritative as stored ones.
    pub async fn text_artifact_projection_call_ids(
        &self,
        session_id: Uuid,
    ) -> Result<TextArtifactProjectionCallIds> {
        self.read(move |conn| text_artifact_projection_call_ids_conn(conn, session_id))
            .await
    }

    pub async fn list_text_artifacts(&self, session_id: Uuid) -> Result<Vec<TextArtifact>> {
        self.read(move |conn| list_text_artifacts_conn(conn, session_id))
            .await
    }

    pub async fn session_text_artifact_bytes(&self, session_id: Uuid) -> Result<usize> {
        self.read(move |conn| session_text_artifact_bytes_conn(conn, session_id))
            .await
    }

    /// Phase one for an FCM2-admitted oversized, text-only submission.
    pub async fn acquire_text_artifact_reservation(
        &self,
        input: TextArtifactReservationInput,
    ) -> Result<TextArtifactReservationAcquire> {
        self.transaction(move |conn| acquire_reservation_conn(conn, &input))
            .await
    }

    /// Atomically creates/replays the FCM2 receipt triple and reserves worst
    /// case source-plus-derived quota. Keeping these writes in one composition
    /// means a crash cannot leave an accepted oversized message without either a
    /// live exact lease or a terminal receipt outcome.
    pub async fn accept_message_with_text_artifact_reservation(
        &self,
        input: AcceptMessageInput,
        join: Arc<dyn MessageAcceptanceJoin>,
        source_digest: [u8; 32],
        source_bytes: usize,
    ) -> Result<TextArtifactPhaseOneResult> {
        self.accept_message_with_text_artifact_reservation_with_model_fence(
            input,
            join,
            source_digest,
            source_bytes,
            None,
        )
        .await
    }

    /// FCM2 v2 intentionally has no mutable model-fence field.  Oversized
    /// admission persists an explicit fence in its DB-owned receipt/lease so
    /// a crash before the live fence check cannot turn it into an implicit
    /// request on restart.
    pub async fn accept_message_with_text_artifact_reservation_with_model_fence(
        &self,
        input: AcceptMessageInput,
        join: Arc<dyn MessageAcceptanceJoin>,
        source_digest: [u8; 32],
        source_bytes: usize,
        model_fence: Option<TextArtifactModelFence>,
    ) -> Result<TextArtifactPhaseOneResult> {
        self.transaction(move |conn| {
            accept_message_with_reservation_conn(
                conn,
                &input,
                join.as_ref(),
                source_digest,
                source_bytes,
                false,
                model_fence.as_ref(),
            )
        })
        .await
    }

    /// Phase one for an oversized `cockpit run`. The accepted FCM2 receipt,
    /// quota lease, and invocation row commit together; a capacity or
    /// idempotency rejection rolls every provisional write back.
    pub async fn accept_message_with_text_artifact_reservation_and_run_invocation(
        &self,
        input: AcceptMessageInput,
        join: Arc<dyn MessageAcceptanceJoin>,
        source_digest: [u8; 32],
        source_bytes: usize,
        invocation: TextArtifactRunInvocationInput,
    ) -> Result<TextArtifactPhaseOneResult> {
        self.accept_message_with_text_artifact_reservation_and_run_invocation_with_model_fence(
            input,
            join,
            source_digest,
            source_bytes,
            invocation,
            None,
        )
        .await
    }

    pub async fn accept_message_with_text_artifact_reservation_and_run_invocation_with_model_fence(
        &self,
        input: AcceptMessageInput,
        join: Arc<dyn MessageAcceptanceJoin>,
        source_digest: [u8; 32],
        source_bytes: usize,
        invocation: TextArtifactRunInvocationInput,
        model_fence: Option<TextArtifactModelFence>,
    ) -> Result<TextArtifactPhaseOneResult> {
        let transaction = self
            .transaction(move |conn| {
                // An exact run-id replay is a companion only when the same
                // durable artifact reservation already existed before this
                // attempt.  Without that pre-existing edge, a caller could
                // present a same-session UUID belonging to an ordinary run
                // and later terminalize or arm that unrelated invocation.
                let prior_bound_reservation = reservation_for_submission_conn(
                    conn,
                    input.session_id,
                    input.client_submission_id,
                )?
                .is_some_and(|reservation| {
                    reservation.run_invocation_bound
                        && reservation.operation_id == input.operation_id
                        && reservation.queue_item_id == input.queue_item_id
                        && reservation.source_digest == source_digest
                        && reservation.source_bytes == source_bytes
                        && reservation.model_fence.as_ref() == model_fence.as_ref()
                });
                let prior_bound_invocation = prior_bound_reservation
                    && run_invocation_binding_matches_conn(
                        conn,
                        input.session_id,
                        input.client_submission_id,
                        Uuid::from_bytes(input.client_submission_id),
                        &invocation.origin_principal_digest,
                    )?;
                let phase = accept_message_with_reservation_conn(
                    conn,
                    &input,
                    join.as_ref(),
                    source_digest,
                    source_bytes,
                    true,
                    model_fence.as_ref(),
                )?;
                if !matches!(phase, TextArtifactPhaseOneResult::Reserved(_)) {
                    return Ok(phase);
                }
                let outcome =
                    crate::db::run_invocations::accept_run_invocation_deferred_timeout_conn(
                        conn,
                        Uuid::from_bytes(input.client_submission_id),
                        &invocation.origin_principal_digest,
                        input.session_id,
                        &invocation.options_json,
                        &invocation.options_digest,
                        &invocation.content_digest,
                        invocation.max_turns,
                        invocation.timeout_ms,
                        input.now_ms,
                    )?;
                use crate::db::run_invocations::AcceptRunInvocationOutcome;
                match outcome {
                    AcceptRunInvocationOutcome::Created(_) => {
                        bind_run_invocation_conn(
                            conn,
                            input.session_id,
                            input.client_submission_id,
                            Uuid::from_bytes(input.client_submission_id),
                            &invocation.origin_principal_digest,
                        )?;
                        Ok(phase)
                    }
                    // The run-invocation identifier is globally claimed, but
                    // this composition may bind it only to the message's own
                    // session. A byte-identical run in another session is a
                    // replay of that other operation, never a companion for
                    // this reservation; otherwise a later terminal receipt
                    // could target the wrong durable run row.
                    AcceptRunInvocationOutcome::ExactReplay(existing)
                        if existing.session_id == input.session_id && prior_bound_invocation =>
                    {
                        Ok(phase)
                    }
                    AcceptRunInvocationOutcome::ExactReplay(_) => {
                        Err(anyhow!(RollbackRunInvocationAdmission(
                            TextArtifactRunInvocationReject::ClientSubmissionIdUnavailable,
                        )))
                    }
                    AcceptRunInvocationOutcome::IdempotencyConflict => {
                        Err(anyhow!(RollbackRunInvocationAdmission(
                            TextArtifactRunInvocationReject::IdempotencyConflict,
                        )))
                    }
                    AcceptRunInvocationOutcome::ClientSubmissionIdUnavailable => {
                        Err(anyhow!(RollbackRunInvocationAdmission(
                            TextArtifactRunInvocationReject::ClientSubmissionIdUnavailable,
                        )))
                    }
                    AcceptRunInvocationOutcome::CapacityExceeded => {
                        Err(anyhow!(RollbackRunInvocationAdmission(
                            TextArtifactRunInvocationReject::CapacityExceeded,
                        )))
                    }
                }
            })
            .await;
        match transaction {
            Ok(phase) => Ok(phase),
            Err(error) => match error.downcast::<RollbackRunInvocationAdmission>() {
                Ok(rejected) => Ok(TextArtifactPhaseOneResult::RunInvocationRejected(
                    rejected.0,
                )),
                Err(error) => Err(error),
            },
        }
    }

    pub async fn renew_text_artifact_reservation(
        &self,
        reservation: TextArtifactReservation,
        now_ms: i64,
    ) -> Result<Option<TextArtifactReservation>> {
        self.transaction(move |conn| renew_reservation_conn(conn, &reservation, now_ms))
            .await
    }

    /// Looks up the only live oversized-source lease for a client submission.
    /// It deliberately joins the queued FCM2 body so a later driver stage can
    /// verify the canonical source before materializing it.
    pub async fn reserved_text_artifact_submission(
        &self,
        session_id: Uuid,
        client_submission_id: [u8; 16],
    ) -> Result<Option<ReservedTextArtifactSubmission>> {
        self.read(move |conn| reserved_submission_conn(conn, session_id, client_submission_id))
            .await
    }

    /// Returns the exact invocation companion for a bound oversized source.
    /// The lookup joins both the durable binding and invocation identity, so a
    /// UUID alone can never authorize a restart or terminal transition.
    pub async fn bound_text_artifact_run_invocation(
        &self,
        session_id: Uuid,
        client_submission_id: [u8; 16],
    ) -> Result<Option<Uuid>> {
        self.read(move |conn| bound_run_invocation_conn(conn, session_id, client_submission_id))
            .await
    }

    /// Return the canonical FCM2 bytes retained with an accepted, materialized,
    /// or terminal oversized submission. This is deliberately narrow: it exists
    /// so a lost ephemeral bulk transfer can replay the durable identity after
    /// the daemon has already accepted it, without treating an absent transfer
    /// as permission to invent new source bytes.
    pub async fn text_artifact_submission_canonical_message(
        &self,
        session_id: Uuid,
        client_submission_id: [u8; 16],
    ) -> Result<Option<Vec<u8>>> {
        self.read(move |conn| {
            conn.query_row(
                "SELECT canonical_message FROM message_queue_items
                  WHERE session_id=?1 AND client_submission_id=?2",
                params![session_id.to_string(), client_submission_id.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .context("loading canonical FCM2 replay bytes")
        })
        .await
    }

    /// Return canonical FCM2 bytes only when the durable receipt belongs to
    /// the exact authenticated actor that is replaying an already-consumed
    /// opaque bulk transfer. A transfer id is merely a locator, so a
    /// session-scoped lookup without this actor gate would let another
    /// attached principal turn an expired/consumed reference into a body
    /// oracle.
    pub async fn text_artifact_submission_canonical_message_for_actor(
        &self,
        session_id: Uuid,
        client_submission_id: [u8; 16],
        actor: crate::db::message_attachments::MessageActor,
    ) -> Result<Option<Vec<u8>>> {
        self.read(move |conn| match actor {
            crate::db::message_attachments::MessageActor::LocalOwner => conn
                .query_row(
                    "SELECT q.canonical_message
                       FROM message_queue_items q
                       JOIN message_submission_receipts s
                         ON s.session_id=q.session_id
                        AND s.client_submission_id=q.client_submission_id
                       JOIN message_operation_receipts o
                         ON o.session_id=s.session_id AND o.operation_id=s.operation_id
                      WHERE q.session_id=?1 AND q.client_submission_id=?2
                        AND o.actor_kind='local_owner' AND o.actor_id IS NULL
                        AND o.actor_generation=?3",
                    params![
                        session_id.to_string(),
                        client_submission_id.as_slice(),
                        0u64.to_be_bytes().to_vec(),
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context("loading local-owner canonical FCM2 replay bytes"),
            crate::db::message_attachments::MessageActor::ExternalPrincipal { id, generation } => {
                conn.query_row(
                    "SELECT q.canonical_message
                       FROM message_queue_items q
                       JOIN message_submission_receipts s
                         ON s.session_id=q.session_id
                        AND s.client_submission_id=q.client_submission_id
                       JOIN message_operation_receipts o
                         ON o.session_id=s.session_id AND o.operation_id=s.operation_id
                      WHERE q.session_id=?1 AND q.client_submission_id=?2
                        AND o.actor_kind='external_principal' AND o.actor_id=?3
                        AND o.actor_generation=?4",
                    params![
                        session_id.to_string(),
                        client_submission_id.as_slice(),
                        id.as_slice(),
                        generation.to_be_bytes().to_vec(),
                    ],
                    |row| row.get(0),
                )
                .optional()
                .context("loading remote-device canonical FCM2 replay bytes")
            }
        })
        .await
    }

    /// Read the durable terminal/materialized/accepted state by the FCM2
    /// submission identity.  The worker/driver uses this after a reservation
    /// lookup returns `None`; that condition is never permission to send the
    /// original oversized body through a legacy provider path.
    pub async fn text_artifact_submission_durable_state(
        &self,
        session_id: Uuid,
        client_submission_id: [u8; 16],
    ) -> Result<TextArtifactSubmissionDurableState> {
        self.read(move |conn| {
            let row = conn
                .query_row(
                    "SELECT state,artifact_terminal_reason
                       FROM message_submission_receipts
                      WHERE session_id=?1 AND client_submission_id=?2",
                    params![session_id.to_string(), client_submission_id.as_slice()],
                    |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
                )
                .optional()?;
            let Some((state, terminal_reason)) = row else {
                return Ok(TextArtifactSubmissionDurableState::Missing);
            };
            match state.as_str() {
                "accepted" => Ok(TextArtifactSubmissionDurableState::Accepted),
                "materialized" => Ok(TextArtifactSubmissionDurableState::Materialized),
                "terminal_rejected" => Ok(TextArtifactSubmissionDurableState::Terminal {
                    reason: terminal_reason
                        .as_deref()
                        .ok_or_else(|| anyhow!("terminal artifact receipt lacks stable reason"))
                        .and_then(parse_reject_reason)?,
                }),
                other => bail!("unknown FCM2 text-artifact receipt state {other}"),
            }
        })
        .await
    }

    /// The sole post-acquisition terminal transition. It updates the operation,
    /// submission, and queue receipt plus lease in one transaction.
    pub async fn reject_and_release_text_artifact_reservation(
        &self,
        reservation: TextArtifactReservation,
        reason: TextArtifactRejectReason,
        now_ms: i64,
    ) -> Result<TextArtifactReservationTransition> {
        self.transaction(move |conn| reject_and_release_conn(conn, &reservation, reason, now_ms))
            .await
    }

    /// Commit generic queued-message tombstones and any matching FCM2
    /// reject-and-release transitions in one database-owned transaction.
    ///
    /// The queue is allowed to forget its in-memory item only after this
    /// succeeds: an oversized source then has a terminal FCM2 receipt and no
    /// live reservation, so restart cannot reconstruct or execute it.
    pub async fn terminalize_queued_text_artifact_submissions(
        &self,
        session_id: Uuid,
        receipts: Vec<ClientSubmissionTerminalReceipt>,
        now_ms: i64,
    ) -> Result<()> {
        self.transaction(move |conn| {
            Self::terminalize_queued_text_artifact_submissions_conn(
                conn, session_id, &receipts, now_ms,
            )
        })
        .await
    }

    /// Transaction body used by the remote-operation composition as well as
    /// the ordinary queue path. Core never reaches into reservations itself.
    pub fn terminalize_queued_text_artifact_submissions_conn(
        conn: &Connection,
        session_id: Uuid,
        receipts: &[ClientSubmissionTerminalReceipt],
        now_ms: i64,
    ) -> Result<()> {
        for receipt in receipts {
            let submission_id = *receipt.client_submission_id.as_bytes();
            if let Some(reservation) =
                reservation_for_submission_conn(conn, session_id, submission_id)?
            {
                // A user withdrawing/cancelling an accepted queue item is a
                // pre-provider terminal branch. Reuse the stable rejection
                // outcome rather than introducing an unbounded new receipt
                // vocabulary, but always consume the exact lease.
                let _ = reject_and_release_conn(
                    conn,
                    &reservation,
                    TextArtifactRejectReason::PreflightRejected,
                    now_ms,
                )?;
            }

            // Absence of a reservation is fine for ordinary (non-FCM2)
            // queued messages and for an already-terminal reaper winner. An
            // accepted FCM2 receipt without a reservation is corruption: keep
            // the staged queue removal held instead of allowing restart to
            // decide whether it may execute the source.
            let state = conn
                .query_row(
                    "SELECT state FROM message_submission_receipts
                      WHERE session_id=?1 AND client_submission_id=?2",
                    params![session_id.to_string(), submission_id.as_slice()],
                    |row| row.get::<_, String>(0),
                )
                .optional()?;
            match state.as_deref() {
                Some("accepted") => bail!(
                    "accepted FCM2 queued submission lacks its exact text-artifact reservation"
                ),
                Some("materialized") => {
                    bail!("queued removal raced a materialized FCM2 submission")
                }
                Some("terminal_rejected") | None => {}
                Some(other) => bail!("unknown FCM2 queued submission state {other}"),
            }
        }
        Db::insert_client_submission_terminal_receipts_conn(conn, session_id, receipts)
    }

    /// Reconcile only rows whose token and stored expiry still exactly match.
    pub async fn reap_expired_text_artifact_reservations(
        &self,
        now_ms: i64,
    ) -> Result<Vec<TextArtifactReservationTransition>> {
        self.transaction(move |conn| reap_expired_reservations_conn(conn, now_ms))
            .await
    }

    pub async fn text_artifact_reservation_replay(
        &self,
        session_id: Uuid,
        operation_id: [u8; 16],
        now_ms: i64,
    ) -> Result<TextArtifactReservationReplay> {
        self.read(move |conn| reservation_replay_conn(conn, session_id, operation_id, now_ms))
            .await
    }

    /// Phase two for an accepted lease. A source and optional distinct derived
    /// projection, its owning `user_message`, all receipt transitions, and lease
    /// consumption commit together.
    pub async fn materialize_reserved_user_text_artifacts(
        &self,
        input: ReservedUserArtifactMaterialization,
    ) -> Result<ReservedUserArtifactMaterializationResult> {
        self.transaction(move |conn| materialize_reserved_user_artifacts_conn(conn, &input))
            .await
    }

    /// Return the immutable model-facing composition for an oversized user
    /// event.  The value is revalidated on read so manually corrupted rows
    /// cannot be turned into provider input during a resume.
    pub fn user_message_model_envelope_conn(
        conn: &Connection,
        session_id: Uuid,
        event_seq: i64,
    ) -> Result<Option<String>> {
        let envelope = conn
            .query_row(
                "SELECT envelope_json FROM session_user_message_model_envelopes WHERE session_id=?1 AND event_seq=?2",
                params![session_id.to_string(), event_seq],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        if let Some(ref envelope) = envelope {
            validate_user_model_envelope(envelope)?;
        }
        Ok(envelope)
    }

    /// Load and validate the immutable accepted composition for live dispatch.
    pub async fn user_message_model_envelope(
        &self,
        session_id: Uuid,
        event_seq: i64,
    ) -> Result<Option<String>> {
        self.read(move |conn| Self::user_message_model_envelope_conn(conn, session_id, event_seq))
            .await
    }
}

pub fn source_digest(text: &str) -> [u8; 32] {
    Sha256::digest(text.as_bytes()).into()
}

/// Read-only helper for archive export. Unlike write helpers, this is safe to
/// use from the existing outer export read connection.
pub fn list_text_artifacts_conn(conn: &Connection, session_id: Uuid) -> Result<Vec<TextArtifact>> {
    let mut stmt = conn.prepare(
        "SELECT a.session_id,a.artifact_id,r.event_seq,r.relation,r.projection_slot,a.kind,a.capture_reason,
                a.content_representation,a.content,a.host_captured_bytes,a.host_original_bytes,a.host_dropped_bytes,
                a.stored_source_bytes,a.content_bytes,a.provenance_json,a.created_at,a.archive_import_id
           FROM session_text_artifacts a JOIN session_text_artifact_event_refs r
             ON r.session_id=a.session_id AND r.artifact_id=a.artifact_id
          WHERE a.session_id=?1 ORDER BY a.created_at,a.artifact_id",
    )?;
    stmt.query_map([session_id.to_string()], decode_artifact)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

pub fn text_artifact_conn(
    conn: &Connection,
    session_id: Uuid,
    artifact_id: Uuid,
) -> Result<Option<TextArtifact>> {
    conn.query_row(
        "SELECT a.session_id,a.artifact_id,r.event_seq,r.relation,r.projection_slot,a.kind,a.capture_reason,
                a.content_representation,a.content,a.host_captured_bytes,a.host_original_bytes,a.host_dropped_bytes,
                a.stored_source_bytes,a.content_bytes,a.provenance_json,a.created_at,a.archive_import_id
           FROM session_text_artifacts a JOIN session_text_artifact_event_refs r
             ON r.session_id=a.session_id AND r.artifact_id=a.artifact_id
          WHERE a.session_id=?1 AND a.artifact_id=?2",
        params![session_id.to_string(), artifact_id.to_string()],
        decode_artifact,
    )
    .optional()
    .context("looking up session text artifact")
}

pub fn session_text_artifact_bytes_conn(conn: &Connection, session_id: Uuid) -> Result<usize> {
    let total: i64 = conn.query_row(
        "SELECT COALESCE(SUM(a.content_bytes), 0)
           FROM session_text_artifacts a
          WHERE a.session_id=?1
            AND EXISTS (
                SELECT 1
                  FROM session_text_artifact_event_refs r
                 WHERE r.session_id=a.session_id AND r.artifact_id=a.artifact_id
            )",
        [session_id.to_string()],
        |row| row.get(0),
    )?;
    usize::try_from(total).context("negative text artifact byte total")
}

fn text_artifact_projection_call_ids_conn(
    conn: &Connection,
    session_id: Uuid,
) -> Result<TextArtifactProjectionCallIds> {
    let mut statement = conn.prepare(
        "SELECT seq,type,data_json
           FROM session_events
          WHERE session_id=?1 AND type IN ('tool_call','context_pruned')
          ORDER BY seq",
    )?;
    let mut result = TextArtifactProjectionCallIds::default();
    let rows = statement.query_map([session_id.to_string()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let events = rows.collect::<rusqlite::Result<Vec<_>>>()?;
    drop(statement);
    for (event_seq, event_type, data_json) in events {
        let artifacts = list_event_artifacts_conn(conn, session_id, event_seq)?;
        let artifacts_by_slot = artifacts
            .iter()
            .map(|artifact| {
                ensure!(
                    artifact.relation == TextArtifactRelation::ModelContextToolResult,
                    "non-model-context artifact attached to a tool projection event"
                );
                Ok((
                    artifact
                        .projection_slot
                        .ok_or_else(|| anyhow!("model-context artifact lacks a projection slot"))?,
                    artifact,
                ))
            })
            .collect::<Result<std::collections::BTreeMap<_, _>>>()?;
        let data: serde_json::Value = serde_json::from_str(&data_json)
            .context("parsing durable text-artifact projection state")?;
        let projections: Vec<(i64, &serde_json::Value)> = match event_type.as_str() {
            "tool_call" => {
                ensure!(
                    data.get("artifact_projections").is_none(),
                    "tool-call text-artifact state must not use a plural projection array"
                );
                data.get("artifact_projection")
                    .map(|projection| vec![(0, projection)])
                    .unwrap_or_default()
            }
            "context_pruned" => match data.get("artifact_projections") {
                None => Vec::new(),
                Some(serde_json::Value::Array(projections)) => {
                    ensure!(
                        data.get("artifact_projection").is_none(),
                        "context-pruned text-artifact state must not use a singular projection"
                    );
                    projections
                        .iter()
                        .enumerate()
                        .map(|(slot, projection)| {
                            Ok((
                                i64::try_from(slot)
                                    .context("context-pruned projection slot exceeds i64")?,
                                projection,
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?
                }
                Some(_) => bail!("context-pruned text-artifact projections must be an array"),
            },
            _ => unreachable!("query restricts event types"),
        };
        let mut available_slots = std::collections::BTreeSet::new();
        for (slot, projection) in projections {
            let projection =
                validate_durable_tool_projection(projection, slot, event_type.as_str())?;
            if projection.available {
                let artifact = artifacts_by_slot
                    .get(&slot)
                    .ok_or_else(|| anyhow!("available durable projection lacks an artifact"))?;
                validate_available_projection_artifact(projection.value, artifact)?;
                available_slots.insert(slot);
            }
            let call_id = projection.call_id;
            result.model_context_calls.insert(call_id.to_owned());
            if projection.capture_reason == CaptureReason::PruneBoundary {
                result.prune_boundary_calls.insert(call_id.to_owned());
            }
        }
        let actual_slots: std::collections::BTreeSet<i64> =
            artifacts_by_slot.keys().copied().collect();
        ensure!(
            actual_slots == available_slots,
            "durable projection availability and typed artifact slots are not bijective"
        );
    }
    Ok(result)
}

struct DurableToolProjection<'a> {
    available: bool,
    capture_reason: CaptureReason,
    call_id: &'a str,
    value: &'a serde_json::Value,
}

fn validate_durable_tool_projection<'a>(
    value: &'a serde_json::Value,
    expected_slot: i64,
    owner_kind: &str,
) -> Result<DurableToolProjection<'a>> {
    let projection = value
        .as_object()
        .ok_or_else(|| anyhow!("durable text-artifact projection must be an object"))?;
    ensure!(
        projection.len() == 15,
        "durable text-artifact projection has an unexpected field set"
    );
    ensure!(
        projection
            .get("version")
            .and_then(serde_json::Value::as_i64)
            == Some(1),
        "durable text-artifact projection has an invalid version"
    );
    let status = projection
        .get("status")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("durable text-artifact projection lacks status"))?;
    let available = match status {
        "available" => {
            ensure!(
                projection.get("reason") == Some(&serde_json::Value::Null),
                "available durable projection has a reason"
            );
            true
        }
        "unavailable" => {
            ensure!(
                matches!(
                    projection.get("reason").and_then(serde_json::Value::as_str),
                    Some("artifact_limit" | "session_quota" | "persistence_unavailable")
                ),
                "unavailable durable projection has an invalid reason"
            );
            false
        }
        _ => bail!("durable text-artifact projection has an invalid status"),
    };
    ensure!(
        projection.get("kind").and_then(serde_json::Value::as_str) == Some("tool_result"),
        "durable text-artifact projection has an invalid kind"
    );
    let capture_reason = match projection
        .get("capture_reason")
        .and_then(serde_json::Value::as_str)
    {
        Some("display_truncation") => CaptureReason::DisplayTruncation,
        Some("prune_boundary") => CaptureReason::PruneBoundary,
        _ => bail!("durable text-artifact projection has an invalid capture reason"),
    };
    match owner_kind {
        "tool_call" => ensure!(
            capture_reason == CaptureReason::DisplayTruncation && expected_slot == 0,
            "tool-call durable projection must use display-truncation slot zero"
        ),
        "context_pruned" => ensure!(
            capture_reason == CaptureReason::PruneBoundary,
            "context-pruned durable projection must use prune-boundary capture"
        ),
        _ => unreachable!("caller restricts durable tool projection owner"),
    }
    ensure!(
        projection
            .get("projection_slot")
            .and_then(serde_json::Value::as_i64)
            == Some(expected_slot),
        "durable text-artifact projection slot is not contiguous"
    );
    let nonnegative = |field: &str| -> Result<i64> {
        projection
            .get(field)
            .and_then(serde_json::Value::as_i64)
            .filter(|value| *value >= 0)
            .ok_or_else(|| anyhow!("durable text-artifact projection {field} is invalid"))
    };
    let host_captured = nonnegative("host_captured_bytes")?;
    let host_original = nonnegative("host_original_bytes")?;
    let host_dropped = nonnegative("host_dropped_bytes")?;
    let stored_source = nonnegative("stored_source_bytes")?;
    let content_bytes = nonnegative("content_bytes")?;
    let line_count = nonnegative("line_count")?;
    ensure!(
        host_original >= host_captured
            && host_dropped == host_original - host_captured
            && stored_source <= host_captured
            && content_bytes == stored_source
            && (line_count > 0
                || (!available
                    && projection.get("reason").and_then(serde_json::Value::as_str)
                        == Some("persistence_unavailable")
                    && stored_source == 0
                    && content_bytes == 0)),
        "durable text-artifact projection accounting is invalid"
    );
    for field in ["preview_head", "preview_tail"] {
        ensure!(
            projection
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some(),
            "durable text-artifact projection {field} is invalid"
        );
    }
    let provenance = projection
        .get("provenance")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| anyhow!("durable text-artifact projection lacks provenance"))?;
    ensure!(
        provenance.len() == 3
            && provenance.contains_key("agent_id")
            && provenance.contains_key("tool")
            && provenance.contains_key("call_id"),
        "durable text-artifact projection provenance has an invalid shape"
    );
    let call_id = provenance
        .get("call_id")
        .and_then(serde_json::Value::as_str)
        .filter(|call_id| {
            !call_id.is_empty()
                && call_id.len() <= 256
                && !call_id.bytes().any(|byte| byte.is_ascii_control())
        })
        .ok_or_else(|| anyhow!("durable text-artifact projection lacks a valid call id"))?;
    for field in ["tool", "call_id"] {
        ensure!(
            provenance
                .get(field)
                .and_then(serde_json::Value::as_str)
                .is_some_and(|value| {
                    !value.is_empty()
                        && value.len() <= 256
                        && !value.bytes().any(|byte| byte.is_ascii_control())
                }),
            "durable text-artifact projection provenance {field} is invalid"
        );
    }
    let valid_agent = match provenance.get("agent_id") {
        Some(serde_json::Value::Null) => true,
        Some(serde_json::Value::String(value)) => {
            value.len() <= 256 && !value.bytes().any(|byte| byte.is_ascii_control())
        }
        _ => false,
    };
    ensure!(
        valid_agent,
        "durable text-artifact projection provenance agent_id is invalid"
    );
    Ok(DurableToolProjection {
        available,
        capture_reason,
        call_id,
        value,
    })
}

/// The direct-SQL trigger proves the common write shape, but SQLite cannot
/// conveniently reproduce every UTF-8-safe preview slice.  Re-check the full
/// available-state projection against the immutable body before rehydration
/// can render it, so a hostile/manual SQL edit never becomes model output.
fn validate_available_projection_artifact(
    projection: &serde_json::Value,
    artifact: &TextArtifact,
) -> Result<()> {
    ensure!(
        artifact.kind == TextArtifactKind::ToolResult
            && artifact.relation == TextArtifactRelation::ModelContextToolResult,
        "available durable projection is not backed by a tool-result artifact"
    );
    ensure!(
        projection
            .get("capture_reason")
            .and_then(serde_json::Value::as_str)
            == Some(artifact.capture_reason.as_str()),
        "available durable projection capture reason differs from its artifact"
    );
    let expected_slot = artifact
        .projection_slot
        .ok_or_else(|| anyhow!("available durable projection artifact lacks slot"))?;
    ensure!(
        projection
            .get("projection_slot")
            .and_then(serde_json::Value::as_i64)
            == Some(expected_slot),
        "available durable projection slot differs from its artifact"
    );
    for (field, actual) in [
        ("host_captured_bytes", artifact.host_captured_bytes),
        ("host_original_bytes", artifact.host_original_bytes),
        ("host_dropped_bytes", artifact.host_dropped_bytes),
        ("stored_source_bytes", artifact.stored_source_bytes),
        ("content_bytes", artifact.content_bytes),
    ] {
        ensure!(
            projection
                .get(field)
                .and_then(serde_json::Value::as_u64)
                .and_then(|value| usize::try_from(value).ok())
                == Some(actual),
            "available durable projection {field} differs from its artifact"
        );
    }
    ensure!(
        projection
            .get("line_count")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            == Some(artifact.content.lines().count()),
        "available durable projection line count differs from its artifact"
    );
    let (head, tail) = artifact_preview_pair(&artifact.content);
    ensure!(
        projection
            .get("preview_head")
            .and_then(serde_json::Value::as_str)
            == Some(head)
            && projection
                .get("preview_tail")
                .and_then(serde_json::Value::as_str)
                == Some(tail),
        "available durable projection preview differs from its artifact"
    );
    let provenance: serde_json::Value = serde_json::from_str(&artifact.provenance_json)
        .context("parsing immutable tool artifact provenance")?;
    ensure!(
        projection.get("provenance") == Some(&provenance),
        "available durable projection provenance differs from its artifact"
    );
    Ok(())
}

fn record_event_with_text_artifacts_conn(
    conn: &Connection,
    input: &TextArtifactEventInput,
) -> Result<TextArtifactEventResult> {
    let mut data: serde_json::Value =
        serde_json::from_str(&input.data_json).context("invalid event JSON")?;
    ensure!(
        data.is_object(),
        "text artifact event data must be a JSON object"
    );
    ensure!(
        data.get("artifact_projection").is_none() && data.get("artifact_projections").is_none(),
        "artifact projection state is DB-owned"
    );

    // Admission is determined before the event exists, so the event itself is
    // inserted exactly once with its final, marker-free projection state. The
    // writer transaction serializes quota changes; `Store` decisions are then
    // checked again by `insert_artifact_conn` and any unexpected drift rolls
    // back the whole composition.
    validate_event_artifact_slots(input)?;
    let plans = plan_event_artifact_admissions(conn, input)?;
    let mut states = input
        .artifacts
        .iter()
        .zip(&plans)
        .map(|(candidate, plan)| projection_state(candidate, *plan))
        .collect::<Result<Vec<_>>>()?;
    if let Some(unavailable) = &input.unavailable_projection {
        let candidate = &unavailable.candidate;
        let provenance: serde_json::Value = serde_json::from_str(&candidate.provenance_json)
            .context("validating unavailable projection provenance")?;
        states.push(serde_json::json!({
            "version": 1,
            "status": "unavailable",
            "reason": unavailable.reason.as_str(),
            "projection_slot": candidate.projection_slot,
            "kind": candidate.kind.as_str(),
            "capture_reason": candidate.capture_reason.as_str(),
            "provenance": provenance,
            "host_captured_bytes": candidate.host_captured_bytes,
            "host_original_bytes": candidate.host_original_bytes,
            "host_dropped_bytes": candidate.host_dropped_bytes,
            "stored_source_bytes": 0,
            "content_bytes": 0,
            "line_count": 0,
            "preview_head": "",
            "preview_tail": "",
        }));
    }
    match input.kind {
        // The tool-call event owns precisely one model-context slot, and keeps
        // its historical singular field. A context-pruned event is always a
        // stable slot array, including its one-slot case: replay, retention,
        // and the DB-owned prune ledger must never infer an array shape from
        // marker text or vector length.
        SessionEventKind::ToolCall if !states.is_empty() => {
            data["artifact_projection"] = states.into_iter().next().expect("one artifact state");
        }
        SessionEventKind::ContextPruned if !states.is_empty() => {
            data["artifact_projections"] = serde_json::Value::Array(states);
        }
        _ => {}
    }
    let event_seq = Db::insert_session_event_json_conn(
        conn,
        input.session_id,
        input.kind,
        input.agent.as_deref(),
        input.call_id.as_deref(),
        input.context.borrowed(),
        input.ts_ms,
        &serde_json::to_string(&data)?,
    )?;
    let slots = input
        .artifacts
        .iter()
        .zip(plans)
        .map(|(candidate, plan)| {
            let admission = match plan {
                EventArtifactAdmissionPlan::ArtifactLimit => TextArtifactAdmission::ArtifactLimit,
                EventArtifactAdmissionPlan::SessionQuota => TextArtifactAdmission::SessionQuota,
                EventArtifactAdmissionPlan::Store => match insert_artifact_conn(
                    conn,
                    input.session_id,
                    event_seq,
                    candidate,
                    TextArtifactRepresentation::Raw,
                    None,
                    None,
                )? {
                    TextArtifactAdmission::Stored(artifact) => {
                        TextArtifactAdmission::Stored(artifact)
                    }
                    TextArtifactAdmission::ArtifactLimit => {
                        bail!("artifact admission changed after event preflight")
                    }
                    TextArtifactAdmission::SessionQuota => {
                        bail!("session artifact quota changed after event preflight")
                    }
                },
            };
            Ok(TextArtifactSlotAdmission {
                relation: candidate.relation,
                projection_slot: candidate.projection_slot,
                admission,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(TextArtifactEventResult { event_seq, slots })
}

#[derive(Debug, Clone, Copy)]
enum EventArtifactAdmissionPlan {
    Store,
    ArtifactLimit,
    SessionQuota,
}

fn validate_event_artifact_slots(input: &TextArtifactEventInput) -> Result<()> {
    let mut owners = std::collections::BTreeSet::new();
    for candidate in &input.artifacts {
        validate_candidate(candidate, TextArtifactRepresentation::Raw, false)?;
        ensure!(
            owners.insert((candidate.relation.as_str(), candidate.projection_slot)),
            "duplicate text artifact owner slot"
        );
    }
    match input.kind {
        SessionEventKind::ToolCall => {
            ensure!(
                input.artifacts.len() + usize::from(input.unavailable_projection.is_some()) <= 1,
                "tool_call accepts at most one artifact projection"
            );
            if let Some(candidate) = input.artifacts.first() {
                ensure!(
                    candidate.relation == TextArtifactRelation::ModelContextToolResult
                        && candidate.projection_slot == Some(0)
                        && candidate.capture_reason == CaptureReason::DisplayTruncation,
                    "tool_call artifact must use display-truncation model-context slot 0"
                );
            }
            if let Some(unavailable) = &input.unavailable_projection {
                let candidate = &unavailable.candidate;
                ensure!(
                    candidate.relation == TextArtifactRelation::ModelContextToolResult
                        && candidate.projection_slot == Some(0)
                        && candidate.kind == TextArtifactKind::ToolResult
                        && candidate.capture_reason == CaptureReason::DisplayTruncation
                        && candidate.content.is_empty()
                        && candidate.stored_source_bytes == 0,
                    "invalid unavailable tool artifact projection"
                );
            }
        }
        SessionEventKind::ContextPruned => {
            for (slot, candidate) in input.artifacts.iter().enumerate() {
                ensure!(
                    candidate.relation == TextArtifactRelation::ModelContextToolResult
                        && candidate.projection_slot == Some(slot as i64)
                        && candidate.capture_reason == CaptureReason::PruneBoundary,
                    "context_pruned artifacts must use prune-boundary stable zero-based slots"
                );
            }
        }
        _ => ensure!(
            input.artifacts.is_empty(),
            "only tool_call and context_pruned events may use generic artifact composition"
        ),
    }
    Ok(())
}

fn plan_event_artifact_admissions(
    conn: &Connection,
    input: &TextArtifactEventInput,
) -> Result<Vec<EventArtifactAdmissionPlan>> {
    let mut occupied = session_text_artifact_bytes_conn(conn, input.session_id)?
        .checked_add(active_reserved_bytes_conn(conn, input.session_id, None)?)
        .ok_or_else(|| anyhow!("text artifact quota arithmetic overflow"))?;
    input
        .artifacts
        .iter()
        .map(|candidate| {
            let content_bytes = candidate.content.len();
            if content_bytes > MAX_ARTIFACT_CONTENT_BYTES {
                return Ok(EventArtifactAdmissionPlan::ArtifactLimit);
            }
            let next = occupied
                .checked_add(content_bytes)
                .ok_or_else(|| anyhow!("text artifact quota arithmetic overflow"))?;
            if next > MAX_SESSION_ARTIFACT_CONTENT_BYTES {
                Ok(EventArtifactAdmissionPlan::SessionQuota)
            } else {
                occupied = next;
                Ok(EventArtifactAdmissionPlan::Store)
            }
        })
        .collect()
}

fn projection_state(
    candidate: &TextArtifactCandidate,
    plan: EventArtifactAdmissionPlan,
) -> Result<serde_json::Value> {
    let (status, reason) = match plan {
        EventArtifactAdmissionPlan::Store => ("available", serde_json::Value::Null),
        EventArtifactAdmissionPlan::ArtifactLimit => (
            "unavailable",
            serde_json::Value::String("artifact_limit".to_owned()),
        ),
        EventArtifactAdmissionPlan::SessionQuota => (
            "unavailable",
            serde_json::Value::String("session_quota".to_owned()),
        ),
    };
    let provenance: serde_json::Value = serde_json::from_str(&candidate.provenance_json)
        .context("validating text artifact projection provenance")?;
    ensure!(
        provenance.is_object(),
        "text artifact projection provenance must be an object"
    );
    let (preview_head, preview_tail) = artifact_preview_pair(&candidate.content);
    Ok(serde_json::json!({
        "version": 1,
        "status": status,
        "reason": reason,
        "kind": candidate.kind,
        "capture_reason": candidate.capture_reason,
        "projection_slot": candidate.projection_slot,
        "provenance": provenance,
        "host_captured_bytes": candidate.host_captured_bytes,
        "host_original_bytes": candidate.host_original_bytes,
        "host_dropped_bytes": candidate.host_dropped_bytes,
        "stored_source_bytes": candidate.stored_source_bytes,
        "content_bytes": candidate.content.len(),
        "line_count": candidate.content.lines().count(),
        "preview_head": preview_head,
        "preview_tail": preview_tail,
    }))
}

/// The durable event state stores exactly the model-frame previews so an
/// unavailable quota branch can regenerate the same frame without retaining a
/// second copy of the omitted body. Keep this byte slicing identical to the
/// core renderer's UTF-8-safe 2KiB/2KiB contract.
fn artifact_preview_pair(value: &str) -> (&str, &str) {
    const EACH: usize = 2 * 1024;
    if value.len() <= EACH * 2 {
        return (value, "");
    }
    let mut head_end = EACH;
    while !value.is_char_boundary(head_end) {
        head_end -= 1;
    }
    let mut tail_start = value.len() - EACH;
    while !value.is_char_boundary(tail_start) {
        tail_start += 1;
    }
    (&value[..head_end], &value[tail_start..])
}

fn insert_artifact_conn(
    conn: &Connection,
    session_id: Uuid,
    event_seq: i64,
    candidate: &TextArtifactCandidate,
    representation: TextArtifactRepresentation,
    reservation_exclusion: Option<&TextArtifactReservation>,
    archive_import_id: Option<Uuid>,
) -> Result<TextArtifactAdmission> {
    let content_bytes = candidate.content.len();
    if content_bytes > MAX_ARTIFACT_CONTENT_BYTES {
        return Ok(TextArtifactAdmission::ArtifactLimit);
    }
    validate_candidate(candidate, representation, archive_import_id.is_some())?;
    ensure!(
        matches!(representation, TextArtifactRepresentation::Raw) == archive_import_id.is_none(),
        "archive import provenance must accompany exactly export-redacted artifacts"
    );
    let committed = session_text_artifact_bytes_conn(conn, session_id)?;
    let reserved = active_reserved_bytes_conn(conn, session_id, reservation_exclusion)?;
    let total = committed
        .checked_add(reserved)
        .and_then(|value| value.checked_add(content_bytes))
        .ok_or_else(|| anyhow!("text artifact quota arithmetic overflow"))?;
    if total > MAX_SESSION_ARTIFACT_CONTENT_BYTES {
        return Ok(TextArtifactAdmission::SessionQuota);
    }

    let artifact_id = Uuid::new_v4();
    conn.execute(
        "INSERT INTO session_text_artifacts (
             session_id,artifact_id,kind,capture_reason,content_representation,archive_import_id,
             owner_event_seq,owner_relation,owner_slot,content,
             host_captured_bytes,host_original_bytes,host_dropped_bytes,stored_source_bytes,
             content_bytes,provenance_json,created_at
         ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
        params![
            session_id.to_string(),
            artifact_id.to_string(),
            candidate.kind.as_str(),
            candidate.capture_reason.as_str(),
            representation.as_str(),
            archive_import_id.map(|id| id.to_string()),
            event_seq,
            candidate.relation.as_str(),
            candidate.projection_slot.unwrap_or(-1),
            &candidate.content,
            as_i64(candidate.host_captured_bytes)?,
            as_i64(candidate.host_original_bytes)?,
            as_i64(candidate.host_dropped_bytes)?,
            as_i64(candidate.stored_source_bytes)?,
            as_i64(content_bytes)?,
            &candidate.provenance_json,
            candidate.created_at,
        ],
    )
    .context("inserting session text artifact")?;
    conn.execute(
        "INSERT INTO session_text_artifact_event_refs (session_id,event_seq,relation,projection_slot,owner_slot,artifact_id)
         VALUES (?1,?2,?3,?4,?5,?6)",
        params![
            session_id.to_string(), event_seq, candidate.relation.as_str(),
            candidate.projection_slot, candidate.projection_slot.unwrap_or(-1), artifact_id.to_string(),
        ],
    )
    .context("attaching session text artifact to owner event")?;
    Ok(TextArtifactAdmission::Stored(TextArtifact {
        session_id,
        artifact_id,
        archive_import_id,
        event_seq,
        relation: candidate.relation,
        projection_slot: candidate.projection_slot,
        kind: candidate.kind,
        capture_reason: candidate.capture_reason,
        representation,
        content: candidate.content.clone(),
        host_captured_bytes: candidate.host_captured_bytes,
        host_original_bytes: candidate.host_original_bytes,
        host_dropped_bytes: candidate.host_dropped_bytes,
        stored_source_bytes: candidate.stored_source_bytes,
        content_bytes,
        provenance_json: candidate.provenance_json.clone(),
        created_at: candidate.created_at,
    }))
}

fn active_reserved_bytes_conn(
    conn: &Connection,
    session_id: Uuid,
    exclusion: Option<&TextArtifactReservation>,
) -> Result<usize> {
    let total: i64 = if let Some(exclusion) = exclusion {
        conn.query_row(
            "SELECT COALESCE(SUM(reserved_bytes),0) FROM session_text_artifact_quota_reservations
              WHERE session_id=?1 AND client_submission_id<>?2",
            params![
                session_id.to_string(),
                exclusion.client_submission_id.as_slice()
            ],
            |row| row.get(0),
        )?
    } else {
        conn.query_row(
            "SELECT COALESCE(SUM(reserved_bytes),0) FROM session_text_artifact_quota_reservations WHERE session_id=?1",
            [session_id.to_string()],
            |row| row.get(0),
        )?
    };
    usize::try_from(total).context("negative text artifact reservation total")
}

fn validate_candidate(
    candidate: &TextArtifactCandidate,
    representation: TextArtifactRepresentation,
    allow_export_redacted: bool,
) -> Result<()> {
    ensure!(
        !candidate.content.is_empty(),
        "text artifact content is empty"
    );
    ensure!(
        candidate.host_original_bytes >= candidate.host_captured_bytes,
        "invalid host artifact accounting"
    );
    ensure!(
        candidate.host_dropped_bytes
            == candidate.host_original_bytes - candidate.host_captured_bytes,
        "invalid dropped byte accounting"
    );
    ensure!(
        candidate.stored_source_bytes <= candidate.host_captured_bytes,
        "stored source exceeds host capture"
    );
    ensure!(
        candidate.stored_source_bytes == candidate.content.len(),
        "stored source byte accounting differs from UTF-8 body"
    );
    ensure!(
        representation != TextArtifactRepresentation::ExportRedacted || allow_export_redacted,
        "export-redacted artifacts are import-only"
    );
    let provenance = validate_provenance(&candidate.provenance_json)?;
    match (
        candidate.kind,
        candidate.capture_reason,
        candidate.relation,
        candidate.projection_slot,
    ) {
        (
            TextArtifactKind::ToolResult,
            CaptureReason::DisplayTruncation | CaptureReason::PruneBoundary,
            TextArtifactRelation::ModelContextToolResult,
            Some(slot),
        ) if slot >= 0 => {
            validate_tool_provenance(&provenance)?;
        }
        (
            TextArtifactKind::UserInputSource,
            CaptureReason::OversizedUserInput,
            TextArtifactRelation::SourceUserInput,
            None,
        ) => {
            ensure!(
                candidate.content.len() > 64 * 1024,
                "user input source must cross the oversized threshold"
            );
            validate_source_provenance(&provenance)?;
        }
        (
            TextArtifactKind::UserInputProjection,
            CaptureReason::OversizedUserInput,
            TextArtifactRelation::ModelUserInputProjection,
            Some(0),
        ) => {}
        _ => bail!("invalid text artifact kind/reason/reference binding"),
    }
    if candidate.kind == TextArtifactKind::UserInputProjection {
        validate_projection_provenance(&provenance)?;
    }
    Ok(())
}

fn validate_provenance(
    provenance_json: &str,
) -> Result<serde_json::Map<String, serde_json::Value>> {
    ensure!(
        provenance_json.len() <= 256,
        "text artifact provenance exceeds 256 UTF-8 bytes"
    );
    let value: serde_json::Value =
        serde_json::from_str(provenance_json).context("invalid text artifact provenance")?;
    fn walk(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(text) => {
                text.len() <= 256 && !text.bytes().any(|byte| byte.is_ascii_control())
            }
            serde_json::Value::Array(values) => values.iter().all(walk),
            serde_json::Value::Object(values) => values.values().all(walk),
            _ => true,
        }
    }
    ensure!(
        walk(&value),
        "text artifact provenance has oversized or control-bearing string"
    );
    value
        .as_object()
        .cloned()
        .ok_or_else(|| anyhow!("text artifact provenance must be an object"))
}

fn only_provenance_keys(
    provenance: &serde_json::Map<String, serde_json::Value>,
    expected: &[&str],
) -> Result<()> {
    ensure!(
        provenance.len() == expected.len()
            && expected.iter().all(|key| provenance.contains_key(*key)),
        "text artifact provenance has an invalid shape"
    );
    Ok(())
}

fn bounded_provenance_text(
    provenance: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> Result<()> {
    let value = provenance
        .get(key)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("text artifact provenance lacks {key}"))?;
    ensure!(
        !value.is_empty()
            && value.len() <= 256
            && !value.bytes().any(|byte| byte.is_ascii_control()),
        "text artifact provenance {key} is invalid"
    );
    Ok(())
}

fn validate_tool_provenance(provenance: &serde_json::Map<String, serde_json::Value>) -> Result<()> {
    only_provenance_keys(provenance, &["agent_id", "tool", "call_id"])?;
    if let Some(agent_id) = provenance.get("agent_id") {
        ensure!(
            agent_id.is_null()
                || agent_id
                    .as_str()
                    .is_some_and(|value| !value.is_empty() && value.len() <= 256),
            "tool artifact provenance agent_id is invalid"
        );
    }
    bounded_provenance_text(provenance, "tool")?;
    bounded_provenance_text(provenance, "call_id")
}

fn validate_source_provenance(
    provenance: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    only_provenance_keys(provenance, &["event_seq"])?;
    ensure!(
        provenance
            .get("event_seq")
            .and_then(serde_json::Value::as_i64)
            .is_some_and(|value| value > 0),
        "source artifact provenance event_seq is invalid"
    );
    Ok(())
}

fn validate_projection_provenance(
    provenance: &serde_json::Map<String, serde_json::Value>,
) -> Result<()> {
    only_provenance_keys(provenance, &["source_artifact_id", "preprocessing_version"])?;
    let source = provenance
        .get("source_artifact_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("projection provenance lacks source artifact id"))?;
    Uuid::parse_str(source).context("projection provenance has invalid source artifact id")?;
    ensure!(
        provenance
            .get("preprocessing_version")
            .and_then(serde_json::Value::as_i64)
            == Some(1),
        "projection provenance preprocessing version is invalid"
    );
    Ok(())
}

fn accept_message_with_reservation_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
    join: &dyn MessageAcceptanceJoin,
    source_digest: [u8; 32],
    source_bytes: usize,
    run_invocation_bound: bool,
    model_fence: Option<&TextArtifactModelFence>,
) -> Result<TextArtifactPhaseOneResult> {
    validate_text_artifact_model_fence(model_fence)?;
    // This boundary deliberately owns the eligibility check too. Callers must
    // first construct/validate FCM2, but no accepted receipt is ever left for a
    // source that cannot be represented by the artifact store.
    ensure!(
        (65_537..=MAX_ARTIFACT_CONTENT_BYTES).contains(&source_bytes),
        "oversized source is outside the artifact reservation domain"
    );

    match crate::db::message_attachments::accept_conn(conn, input, join)? {
        AcceptMessageResult::Conflict => Ok(TextArtifactPhaseOneResult::Conflict),
        AcceptMessageResult::Accepted => {
            store_artifact_model_fence_conn(conn, input, model_fence)?;
            match acquire_reservation_conn(
                conn,
                &TextArtifactReservationInput {
                    session_id: input.session_id,
                    operation_id: input.operation_id,
                    client_submission_id: input.client_submission_id,
                    queue_item_id: input.queue_item_id,
                    source_digest,
                    source_bytes,
                    now_ms: input.now_ms,
                    run_invocation_bound,
                    model_fence: model_fence.cloned(),
                },
            )? {
                TextArtifactReservationAcquire::Acquired(reservation) => {
                    Ok(TextArtifactPhaseOneResult::Reserved(reservation))
                }
                // A writer transaction cannot observe an existing row after it
                // just inserted this receipt triple. Treat it as a corruption
                // rather than silently joining an ambiguous owner.
                TextArtifactReservationAcquire::Existing(_)
                | TextArtifactReservationAcquire::Conflict => {
                    bail!("new FCM2 artifact receipt did not acquire its reservation")
                }
                TextArtifactReservationAcquire::SessionQuota => {
                    terminalize_unreserved_artifact_receipt_conn(
                        conn,
                        input,
                        TextArtifactRejectReason::QuotaExhausted,
                    )?;
                    Ok(TextArtifactPhaseOneResult::Terminal {
                        reason: TextArtifactRejectReason::QuotaExhausted,
                    })
                }
            }
        }
        AcceptMessageResult::Replayed { safe_outcome } => {
            if stored_artifact_model_fence_conn(conn, input)? != model_fence.cloned() {
                return Ok(TextArtifactPhaseOneResult::Conflict);
            }
            match safe_outcome {
                MessageSafeOutcome::Accepted { queue_item_id }
                    if queue_item_id == input.queue_item_id =>
                {
                    replay_accepted_artifact_reservation_conn(
                        conn,
                        input,
                        source_digest,
                        source_bytes,
                        run_invocation_bound,
                        model_fence,
                    )
                }
                MessageSafeOutcome::Accepted { .. } => Ok(TextArtifactPhaseOneResult::Conflict),
                MessageSafeOutcome::Materialized { .. } | MessageSafeOutcome::TerminalRejected => {
                    match reservation_replay_conn(
                        conn,
                        input.session_id,
                        input.operation_id,
                        input.now_ms,
                    )? {
                        TextArtifactReservationReplay::Materialized {
                            event_seq,
                            source_artifact_id,
                            projection_artifact_id,
                        } => Ok(TextArtifactPhaseOneResult::Materialized {
                            event_seq,
                            source_artifact_id,
                            projection_artifact_id,
                        }),
                        TextArtifactReservationReplay::Terminal { reason } => {
                            Ok(TextArtifactPhaseOneResult::Terminal { reason })
                        }
                        TextArtifactReservationReplay::Live(_)
                        | TextArtifactReservationReplay::Expired(_)
                        | TextArtifactReservationReplay::Missing => {
                            bail!("replayed terminal artifact receipt has inconsistent lease state")
                        }
                    }
                }
                MessageSafeOutcome::Removed => Ok(TextArtifactPhaseOneResult::Conflict),
            }
        }
    }
}

/// Persist the extra-wire fence on the authoritative receipt in the same
/// transaction that created it.  This is deliberately separate from FCM2 so
/// version-2 bytes, digests, and vectors remain frozen.
fn store_artifact_model_fence_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
    model_fence: Option<&TextArtifactModelFence>,
) -> Result<()> {
    let changed = conn.execute(
        "UPDATE message_operation_receipts
            SET artifact_model_fence_generation=?1, artifact_model_fence_json=?2
          WHERE session_id=?3 AND operation_id=?4 AND client_submission_id=?5
            AND message_request_digest=?6 AND state='accepted'",
        params![
            model_fence.map(|fence| fence.generation.to_string()),
            model_fence.map(|fence| fence.model_json.as_str()),
            input.session_id.to_string(),
            input.operation_id.as_slice(),
            input.client_submission_id.as_slice(),
            input.message_request_digest.as_slice(),
        ],
    )?;
    ensure!(
        changed == 1,
        "accepted receipt changed before model-fence persistence"
    );
    Ok(())
}

fn stored_artifact_model_fence_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
) -> Result<Option<TextArtifactModelFence>> {
    let pair = conn
        .query_row(
            "SELECT artifact_model_fence_generation, artifact_model_fence_json
           FROM message_operation_receipts
          WHERE session_id=?1 AND operation_id=?2 AND client_submission_id=?3
            AND message_request_digest=?4",
            params![
                input.session_id.to_string(),
                input.operation_id.as_slice(),
                input.client_submission_id.as_slice(),
                input.message_request_digest.as_slice(),
            ],
            |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            },
        )
        .optional()?;
    let Some((generation, model_json)) = pair else {
        bail!("replayed message receipt disappeared");
    };
    match (generation, model_json) {
        (None, None) => Ok(None),
        (Some(generation), Some(model_json)) => Ok(Some(TextArtifactModelFence {
            generation: generation
                .parse()
                .context("invalid persisted artifact model fence generation")?,
            model_json,
        })),
        _ => bail!("persisted artifact model fence has mismatched fields"),
    }
}

fn run_invocation_binding_matches_conn(
    conn: &Connection,
    session_id: Uuid,
    client_submission_id: [u8; 16],
    run_invocation_id: Uuid,
    origin_principal_digest: &str,
) -> Result<bool> {
    let found: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
               FROM session_text_artifact_run_invocation_bindings b
               JOIN run_invocations i ON i.client_submission_id=b.run_invocation_id
              WHERE b.session_id=?1 AND b.client_submission_id=?2
                AND b.run_invocation_id=?3 AND b.origin_principal_digest=?4
                AND i.session_id=?1 AND i.origin_principal_digest=?4
         )",
        params![
            session_id.to_string(),
            client_submission_id.as_slice(),
            run_invocation_id.to_string(),
            origin_principal_digest,
        ],
        |row| row.get(0),
    )?;
    Ok(found != 0)
}

fn bind_run_invocation_conn(
    conn: &Connection,
    session_id: Uuid,
    client_submission_id: [u8; 16],
    run_invocation_id: Uuid,
    origin_principal_digest: &str,
) -> Result<()> {
    let changed = conn.execute(
        "INSERT INTO session_text_artifact_run_invocation_bindings
             (session_id,client_submission_id,run_invocation_id,origin_principal_digest)
         VALUES (?1,?2,?3,?4)",
        params![
            session_id.to_string(),
            client_submission_id.as_slice(),
            run_invocation_id.to_string(),
            origin_principal_digest,
        ],
    )?;
    ensure!(
        changed == 1,
        "oversized run invocation binding was not inserted"
    );
    Ok(())
}

fn bound_run_invocation_conn(
    conn: &Connection,
    session_id: Uuid,
    client_submission_id: [u8; 16],
) -> Result<Option<Uuid>> {
    conn.query_row(
        "SELECT b.run_invocation_id
           FROM session_text_artifact_run_invocation_bindings b
           JOIN run_invocations i ON i.client_submission_id=b.run_invocation_id
          WHERE b.session_id=?1 AND b.client_submission_id=?2
            AND i.session_id=b.session_id
            AND i.origin_principal_digest=b.origin_principal_digest",
        params![session_id.to_string(), client_submission_id.as_slice()],
        |row| row.get::<_, String>(0),
    )
    .optional()?
    .map(|value| Uuid::parse_str(&value).context("invalid bound run invocation id"))
    .transpose()
}

fn replay_accepted_artifact_reservation_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
    source_digest: [u8; 32],
    source_bytes: usize,
    run_invocation_bound: bool,
    model_fence: Option<&TextArtifactModelFence>,
) -> Result<TextArtifactPhaseOneResult> {
    let Some(reservation) =
        reservation_for_submission_conn(conn, input.session_id, input.client_submission_id)?
    else {
        // The paired API commits receipt and lease together. An accepted row
        // without a lease can therefore only be a damaged/old database; close
        // it deterministically rather than ever rerunning preprocessing.
        terminalize_unreserved_artifact_receipt_conn(
            conn,
            input,
            TextArtifactRejectReason::PersistenceFailed,
        )?;
        return Ok(TextArtifactPhaseOneResult::Terminal {
            reason: TextArtifactRejectReason::PersistenceFailed,
        });
    };
    let same_identity = reservation.operation_id == input.operation_id
        && reservation.queue_item_id == input.queue_item_id
        && reservation.source_digest == source_digest
        && reservation.source_bytes == source_bytes
        && reservation.run_invocation_bound == run_invocation_bound;
    let same_identity = same_identity && reservation.model_fence.as_ref() == model_fence;
    if !same_identity {
        return Ok(TextArtifactPhaseOneResult::Conflict);
    }
    if reservation.expires_at > input.now_ms {
        return Ok(TextArtifactPhaseOneResult::Reserved(reservation));
    }
    match reject_and_release_conn(
        conn,
        &reservation,
        TextArtifactRejectReason::ReservationExpired,
        input.now_ms,
    )? {
        TextArtifactReservationTransition::Applied(reason) => {
            Ok(TextArtifactPhaseOneResult::Terminal { reason })
        }
        TextArtifactReservationTransition::Stale => {
            // The only possible winner is a concurrent owner/terminal state;
            // this writer transaction serializes us, so reload instead of
            // performing a second terminal transition.
            match reservation_replay_conn(conn, input.session_id, input.operation_id, input.now_ms)?
            {
                TextArtifactReservationReplay::Materialized {
                    event_seq,
                    source_artifact_id,
                    projection_artifact_id,
                } => Ok(TextArtifactPhaseOneResult::Materialized {
                    event_seq,
                    source_artifact_id,
                    projection_artifact_id,
                }),
                TextArtifactReservationReplay::Terminal { reason } => {
                    Ok(TextArtifactPhaseOneResult::Terminal { reason })
                }
                TextArtifactReservationReplay::Live(reservation) => {
                    Ok(TextArtifactPhaseOneResult::Reserved(reservation))
                }
                TextArtifactReservationReplay::Expired(_)
                | TextArtifactReservationReplay::Missing => {
                    bail!("artifact reservation replay remained indeterminate")
                }
            }
        }
    }
}

/// Terminalizes a just-accepted receipt when phase one cannot create a lease.
/// This is intentionally private: all post-lease terminal outcomes go through
/// `reject_and_release_conn`, whose exact token/expiry comparison protects a
/// renewed owner from a stale handler.
fn terminalize_unreserved_artifact_receipt_conn(
    conn: &Connection,
    input: &AcceptMessageInput,
    reason: TextArtifactRejectReason,
) -> Result<()> {
    let outcome = MessageSafeOutcome::TerminalRejected.encode();
    let operation = conn.execute(
        "UPDATE message_operation_receipts
            SET state='terminal_rejected',safe_outcome=?1,artifact_terminal_reason=?2,updated_at=?3
          WHERE session_id=?4 AND operation_id=?5 AND client_submission_id=?6
            AND message_request_digest=?7 AND state='accepted'",
        params![
            outcome,
            reason.as_str(),
            input.now_ms,
            input.session_id.to_string(),
            input.operation_id.as_slice(),
            input.client_submission_id.as_slice(),
            input.message_request_digest.as_slice(),
        ],
    )?;
    ensure!(
        operation == 1,
        "accepted operation receipt changed before phase-one rejection"
    );
    let submission = conn.execute(
        "UPDATE message_submission_receipts
            SET state='terminal_rejected',safe_outcome=?1,artifact_terminal_reason=?2,updated_at=?3
          WHERE session_id=?4 AND client_submission_id=?5 AND operation_id=?6
            AND message_request_digest=?7 AND attachment_set_digest=?8 AND queue_item_id=?9
            AND state='accepted'",
        params![
            MessageSafeOutcome::TerminalRejected.encode(),
            reason.as_str(),
            input.now_ms,
            input.session_id.to_string(),
            input.client_submission_id.as_slice(),
            input.operation_id.as_slice(),
            input.message_request_digest.as_slice(),
            input.attachment_set_digest.as_slice(),
            input.queue_item_id.as_slice(),
        ],
    )?;
    ensure!(
        submission == 1,
        "accepted submission receipt changed before phase-one rejection"
    );
    let queue = conn.execute(
        "UPDATE message_queue_items
            SET state='terminal_rejected',artifact_terminal_reason=?1,updated_at=?2
          WHERE session_id=?3 AND queue_item_id=?4 AND client_submission_id=?5 AND state='accepted'",
        params![
            reason.as_str(),
            input.now_ms,
            input.session_id.to_string(),
            input.queue_item_id.as_slice(),
            input.client_submission_id.as_slice(),
        ],
    )?;
    ensure!(
        queue == 1,
        "accepted queue item changed before phase-one rejection"
    );
    Ok(())
}

fn acquire_reservation_conn(
    conn: &Connection,
    input: &TextArtifactReservationInput,
) -> Result<TextArtifactReservationAcquire> {
    validate_text_artifact_model_fence(input.model_fence.as_ref())?;
    if !(65_537..=MAX_ARTIFACT_CONTENT_BYTES).contains(&input.source_bytes) {
        bail!("oversized source is outside the artifact reservation domain");
    }
    if let Some(existing) =
        reservation_for_submission_conn(conn, input.session_id, input.client_submission_id)?
    {
        let same_identity = existing.operation_id == input.operation_id
            && existing.queue_item_id == input.queue_item_id
            && existing.source_digest == input.source_digest
            && existing.source_bytes == input.source_bytes
            && existing.run_invocation_bound == input.run_invocation_bound;
        let same_identity =
            same_identity && existing.model_fence.as_ref() == input.model_fence.as_ref();
        if !same_identity {
            return Ok(TextArtifactReservationAcquire::Conflict);
        }
        return Ok(if existing.expires_at > input.now_ms {
            TextArtifactReservationAcquire::Existing(existing)
        } else {
            TextArtifactReservationAcquire::Conflict
        });
    }
    let reserved_bytes = input
        .source_bytes
        .checked_add(MAX_ARTIFACT_CONTENT_BYTES)
        .ok_or_else(|| anyhow!("text artifact reservation overflow"))?;
    let total = session_text_artifact_bytes_conn(conn, input.session_id)?
        .checked_add(active_reserved_bytes_conn(conn, input.session_id, None)?)
        .and_then(|value| value.checked_add(reserved_bytes))
        .ok_or_else(|| anyhow!("text artifact quota arithmetic overflow"))?;
    if total > MAX_SESSION_ARTIFACT_CONTENT_BYTES {
        return Ok(TextArtifactReservationAcquire::SessionQuota);
    }
    let lease_token = Uuid::new_v4();
    let expires_at = input
        .now_ms
        .checked_add(ARTIFACT_RESERVATION_TTL_MS)
        .ok_or_else(|| anyhow!("artifact reservation expiry overflow"))?;
    let changed = conn.execute(
        "INSERT INTO session_text_artifact_quota_reservations
             (session_id,client_submission_id,operation_id,queue_item_id,source_digest,source_bytes,reserved_bytes,run_invocation_bound,model_fence_generation,model_fence_json,lease_token,expires_at,created_at,updated_at)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?13)",
        params![
            input.session_id.to_string(), input.client_submission_id.as_slice(), input.operation_id.as_slice(),
            input.queue_item_id.as_slice(), input.source_digest.as_slice(), as_i64(input.source_bytes)?,
            as_i64(reserved_bytes)?, input.run_invocation_bound,
            input.model_fence.as_ref().map(|fence| fence.generation.to_string()),
            input.model_fence.as_ref().map(|fence| fence.model_json.as_str()),
            lease_token.to_string(), expires_at, input.now_ms,
        ],
    );
    match changed {
        Ok(1) => Ok(TextArtifactReservationAcquire::Acquired(
            TextArtifactReservation {
                session_id: input.session_id,
                operation_id: input.operation_id,
                client_submission_id: input.client_submission_id,
                queue_item_id: input.queue_item_id,
                source_digest: input.source_digest,
                source_bytes: input.source_bytes,
                reserved_bytes,
                run_invocation_bound: input.run_invocation_bound,
                model_fence: input.model_fence.clone(),
                lease_token,
                expires_at,
            },
        )),
        Ok(_) => Ok(TextArtifactReservationAcquire::Conflict),
        Err(error)
            if error
                .to_string()
                .contains("receipt identity is not accepted") =>
        {
            Ok(TextArtifactReservationAcquire::Conflict)
        }
        Err(error) => Err(error.into()),
    }
}

fn validate_text_artifact_model_fence(fence: Option<&TextArtifactModelFence>) -> Result<()> {
    let Some(fence) = fence else {
        return Ok(());
    };
    ensure!(
        fence.model_json.len() <= 8 * 1024,
        "oversized model fence exceeds bounds"
    );
    let value: serde_json::Value =
        serde_json::from_str(&fence.model_json).context("oversized model fence is not JSON")?;
    ensure!(
        value.is_object(),
        "oversized model fence must be a JSON object"
    );
    ensure!(
        serde_json::to_string(&value)? == fence.model_json,
        "oversized model fence JSON is not canonical"
    );
    Ok(())
}

fn renew_reservation_conn(
    conn: &Connection,
    reservation: &TextArtifactReservation,
    now_ms: i64,
) -> Result<Option<TextArtifactReservation>> {
    // A holder that has reached its stored expiry may only observe/reload the
    // winner or let the exact-expiry reaper terminalize it. It must never turn
    // an already-expired lease back into a live one.
    if reservation.expires_at <= now_ms {
        return Ok(None);
    }
    let remaining = reservation.expires_at.checked_sub(now_ms);
    if matches!(remaining, Some(value) if value > ARTIFACT_RESERVATION_RENEW_AT_REMAINING_MS) {
        return Ok(Some(reservation.clone()));
    }
    let expiry = reservation
        .expires_at
        .max(now_ms)
        .checked_add(ARTIFACT_RESERVATION_TTL_MS)
        .ok_or_else(|| anyhow!("artifact reservation renewal overflow"))?;
    let lease_token = Uuid::new_v4();
    let changed = conn.execute(
        "UPDATE session_text_artifact_quota_reservations
            SET lease_token=?1,expires_at=?2,updated_at=?3
          WHERE session_id=?4 AND client_submission_id=?5 AND operation_id=?6 AND queue_item_id=?7
            AND source_digest=?8 AND source_bytes=?9 AND run_invocation_bound=?10
            AND lease_token=?11 AND expires_at=?12",
        params![
            lease_token.to_string(),
            expiry,
            now_ms,
            reservation.session_id.to_string(),
            reservation.client_submission_id.as_slice(),
            reservation.operation_id.as_slice(),
            reservation.queue_item_id.as_slice(),
            reservation.source_digest.as_slice(),
            as_i64(reservation.source_bytes)?,
            reservation.run_invocation_bound,
            reservation.lease_token.to_string(),
            reservation.expires_at,
        ],
    )?;
    if changed == 0 {
        return Ok(None);
    }
    let mut renewed = reservation.clone();
    renewed.lease_token = lease_token;
    renewed.expires_at = expiry;
    Ok(Some(renewed))
}

fn reject_and_release_conn(
    conn: &Connection,
    reservation: &TextArtifactReservation,
    reason: TextArtifactRejectReason,
    now_ms: i64,
) -> Result<TextArtifactReservationTransition> {
    // Normal terminal branches must own a live lease. Only the reaper is
    // permitted to consume an exact expired token/expiry pair.
    let live_at = (reason != TextArtifactRejectReason::ReservationExpired).then_some(now_ms);
    if !reservation_matches_conn(conn, reservation, live_at)? {
        return Ok(TextArtifactReservationTransition::Stale);
    }
    let safe_outcome = MessageSafeOutcome::TerminalRejected.encode();
    let session_id = reservation.session_id.to_string();
    let operation = conn.execute(
        "UPDATE message_operation_receipts SET state='terminal_rejected',safe_outcome=?1,artifact_terminal_reason=?2,updated_at=?3
          WHERE session_id=?4 AND operation_id=?5 AND client_submission_id=?6 AND state='accepted'",
        params![safe_outcome, reason.as_str(), now_ms, session_id, reservation.operation_id.as_slice(), reservation.client_submission_id.as_slice()],
    )?;
    ensure!(
        operation == 1,
        "accepted operation receipt changed during artifact rejection"
    );
    let submission = conn.execute(
        "UPDATE message_submission_receipts SET state='terminal_rejected',safe_outcome=?1,artifact_terminal_reason=?2,updated_at=?3
          WHERE session_id=?4 AND client_submission_id=?5 AND operation_id=?6 AND queue_item_id=?7 AND state='accepted'",
        params![MessageSafeOutcome::TerminalRejected.encode(), reason.as_str(), now_ms, reservation.session_id.to_string(), reservation.client_submission_id.as_slice(), reservation.operation_id.as_slice(), reservation.queue_item_id.as_slice()],
    )?;
    ensure!(
        submission == 1,
        "accepted submission receipt changed during artifact rejection"
    );
    let queue = conn.execute(
        "UPDATE message_queue_items SET state='terminal_rejected',artifact_terminal_reason=?1,updated_at=?2
          WHERE session_id=?3 AND queue_item_id=?4 AND client_submission_id=?5 AND state IN ('accepted','folding')",
        params![reason.as_str(), now_ms, reservation.session_id.to_string(), reservation.queue_item_id.as_slice(), reservation.client_submission_id.as_slice()],
    )?;
    ensure!(
        queue == 1,
        "accepted queue item changed during artifact rejection"
    );
    // A bound oversized `cockpit run` commits its invocation with this exact
    // receipt/lease in phase one.  Terminalize it in this same transaction;
    // ordinary oversized messages deliberately cannot affect an unrelated
    // global invocation that happens to reuse the UUID.
    if reservation.run_invocation_bound {
        let invocation_id = bound_run_invocation_conn(
            conn,
            reservation.session_id,
            reservation.client_submission_id,
        )?
        .context("bound oversized artifact reservation lacks its exact run invocation binding")?;
        let terminalized = crate::db::run_invocations::mark_run_invocation_terminal_conn(
            conn,
            invocation_id,
            Some(reservation.session_id),
            "failed",
            "failed",
            now_ms,
        )?;
        ensure!(
            terminalized.is_some(),
            "bound oversized artifact reservation lacks its run invocation"
        );
    }
    let deleted = conn.execute(
        "DELETE FROM session_text_artifact_quota_reservations
          WHERE session_id=?1 AND client_submission_id=?2 AND operation_id=?3 AND queue_item_id=?4
            AND source_digest=?5 AND source_bytes=?6 AND run_invocation_bound=?7
            AND lease_token=?8 AND expires_at=?9",
        params![
            reservation.session_id.to_string(),
            reservation.client_submission_id.as_slice(),
            reservation.operation_id.as_slice(),
            reservation.queue_item_id.as_slice(),
            reservation.source_digest.as_slice(),
            as_i64(reservation.source_bytes)?,
            reservation.run_invocation_bound,
            reservation.lease_token.to_string(),
            reservation.expires_at,
        ],
    )?;
    ensure!(
        deleted == 1,
        "artifact reservation changed during rejection"
    );
    Ok(TextArtifactReservationTransition::Applied(reason))
}

fn reap_expired_reservations_conn(
    conn: &Connection,
    now_ms: i64,
) -> Result<Vec<TextArtifactReservationTransition>> {
    let mut stmt = conn.prepare(
        "SELECT session_id,operation_id,client_submission_id,queue_item_id,source_digest,source_bytes,reserved_bytes,run_invocation_bound,model_fence_generation,model_fence_json,lease_token,expires_at
           FROM session_text_artifact_quota_reservations
          WHERE expires_at<=?1 ORDER BY expires_at,session_id,client_submission_id",
    )?;
    let reservations = stmt
        .query_map([now_ms], decode_reservation)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut outcomes = Vec::with_capacity(reservations.len());
    for reservation in reservations {
        outcomes.push(reject_and_release_conn(
            conn,
            &reservation,
            TextArtifactRejectReason::ReservationExpired,
            now_ms,
        )?);
    }
    Ok(outcomes)
}

fn reservation_replay_conn(
    conn: &Connection,
    session_id: Uuid,
    operation_id: [u8; 16],
    now_ms: i64,
) -> Result<TextArtifactReservationReplay> {
    let receipt = conn.query_row(
        "SELECT o.client_submission_id,o.state,o.artifact_terminal_reason,s.message_seq
           FROM message_operation_receipts o
           LEFT JOIN message_submission_receipts s ON s.session_id=o.session_id AND s.operation_id=o.operation_id
          WHERE o.session_id=?1 AND o.operation_id=?2",
        params![session_id.to_string(), operation_id.as_slice()],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, String>(1)?, row.get::<_, Option<String>>(2)?, row.get::<_, Option<i64>>(3)?)),
    ).optional()?;
    let Some((submission, state, terminal_reason, message_seq)) = receipt else {
        return Ok(TextArtifactReservationReplay::Missing);
    };
    let submission: [u8; 16] = submission
        .try_into()
        .map_err(|_| anyhow!("invalid stored submission id"))?;
    if state == "materialized" {
        let event_seq =
            message_seq.ok_or_else(|| anyhow!("materialized receipt lacks event sequence"))?;
        let artifacts = list_event_artifacts_conn(conn, session_id, event_seq)?;
        let source = artifacts
            .iter()
            .find(|artifact| artifact.relation == TextArtifactRelation::SourceUserInput)
            .ok_or_else(|| anyhow!("materialized user receipt lacks source artifact"))?;
        let projection = artifacts
            .iter()
            .find(|artifact| artifact.relation == TextArtifactRelation::ModelUserInputProjection)
            .map(|artifact| artifact.artifact_id);
        return Ok(TextArtifactReservationReplay::Materialized {
            event_seq,
            source_artifact_id: source.artifact_id,
            projection_artifact_id: projection,
        });
    }
    if state == "terminal_rejected" {
        let reason = terminal_reason
            .as_deref()
            .ok_or_else(|| anyhow!("terminal artifact receipt lacks stable reason"))
            .and_then(parse_reject_reason)?;
        return Ok(TextArtifactReservationReplay::Terminal { reason });
    }
    let reservation = reservation_for_submission_conn(conn, session_id, submission)?
        .ok_or_else(|| anyhow!("accepted artifact receipt lacks reservation"))?;
    if reservation.expires_at <= now_ms {
        Ok(TextArtifactReservationReplay::Expired(reservation))
    } else {
        Ok(TextArtifactReservationReplay::Live(reservation))
    }
}

fn materialize_reserved_user_artifacts_conn(
    conn: &Connection,
    input: &ReservedUserArtifactMaterialization,
) -> Result<ReservedUserArtifactMaterializationResult> {
    let reservation = &input.reservation;
    if input.source_text.len() != reservation.source_bytes
        || source_digest(&input.source_text) != reservation.source_digest
    {
        return Ok(ReservedUserArtifactMaterializationResult::Stale);
    }
    if !reservation_matches_conn(conn, reservation, Some(input.now_ms))? {
        return Ok(
            if reservation_for_submission_conn(
                conn,
                reservation.session_id,
                reservation.client_submission_id,
            )?
            .is_some_and(|stored| stored.expires_at <= input.now_ms)
            {
                ReservedUserArtifactMaterializationResult::Expired
            } else {
                ReservedUserArtifactMaterializationResult::Stale
            },
        );
    }
    // A derived projection that crosses the immutable artifact cap is a
    // known, durable rejection, not a caller-side follow-up.  Terminalize the
    // exact receipt triple and delete the exact lease in this same writer
    // transaction so a crash cannot leave an accepted source after a
    // translation/rewrite result has already been classified as impossible.
    if input
        .model_projection
        .as_ref()
        .is_some_and(|value| value.len() > MAX_ARTIFACT_CONTENT_BYTES)
    {
        return match reject_and_release_conn(
            conn,
            reservation,
            TextArtifactRejectReason::TooLarge,
            input.now_ms,
        )? {
            TextArtifactReservationTransition::Applied(TextArtifactRejectReason::TooLarge) => {
                Ok(ReservedUserArtifactMaterializationResult::ProjectionTooLarge)
            }
            TextArtifactReservationTransition::Applied(_) => {
                bail!("unexpected terminal reason while rejecting oversized projection")
            }
            TextArtifactReservationTransition::Stale => {
                Ok(ReservedUserArtifactMaterializationResult::Stale)
            }
        };
    }
    if input
        .model_projection
        .as_ref()
        .is_some_and(|value| value == &input.source_text)
    {
        bail!("equal user projection must be omitted");
    }
    let canonical_event: serde_json::Value = serde_json::from_str(&input.canonical_event_json)
        .context("invalid canonical user event JSON")?;
    let canonical_event = canonical_event
        .as_object()
        .ok_or_else(|| anyhow!("canonical user event JSON must be an object"))?;
    ensure!(
        canonical_event
            .get("text")
            .and_then(serde_json::Value::as_str)
            == Some(input.source_text.as_str()),
        "canonical user event text must exactly match the reserved source"
    );
    validate_user_model_envelope(&input.model_envelope_json)?;
    ensure!(
        !canonical_user_event_has_media_or_file_parts(canonical_event),
        "oversized user event cannot carry media/file parts"
    );
    let bound_invocation_id = if reservation.run_invocation_bound {
        Some(
            bound_run_invocation_conn(
                conn,
                reservation.session_id,
                reservation.client_submission_id,
            )?
            .context(
                "bound oversized artifact reservation lacks its exact run invocation binding",
            )?,
        )
    } else {
        None
    };
    // Release the exact live worst-case reservation before inserting its
    // committed bodies. This is still one writer transaction: every later
    // failure rolls the delete back, while the SQL quota trigger now sees the
    // same replacement accounting as direct SQL does.
    let deleted = conn.execute(
        "DELETE FROM session_text_artifact_quota_reservations
          WHERE session_id=?1 AND client_submission_id=?2 AND operation_id=?3 AND queue_item_id=?4
            AND source_digest=?5 AND source_bytes=?6 AND run_invocation_bound=?7
            AND lease_token=?8 AND expires_at=?9",
        params![
            reservation.session_id.to_string(),
            reservation.client_submission_id.as_slice(),
            reservation.operation_id.as_slice(),
            reservation.queue_item_id.as_slice(),
            reservation.source_digest.as_slice(),
            as_i64(reservation.source_bytes)?,
            reservation.run_invocation_bound,
            reservation.lease_token.to_string(),
            reservation.expires_at
        ],
    )?;
    ensure!(
        deleted == 1,
        "artifact reservation changed during materialization"
    );
    let event_seq = Db::insert_session_event_json_conn(
        conn,
        reservation.session_id,
        SessionEventKind::UserMessage,
        input.agent.as_deref(),
        None,
        input.context.borrowed(),
        input.now_ms,
        &input.canonical_event_json,
    )?;
    conn.execute(
        "INSERT INTO session_user_message_model_envelopes(session_id,event_seq,envelope_json) VALUES(?1,?2,?3)",
        params![reservation.session_id.to_string(), event_seq, input.model_envelope_json],
    )?;
    let source_candidate = TextArtifactCandidate {
        relation: TextArtifactRelation::SourceUserInput,
        projection_slot: None,
        kind: TextArtifactKind::UserInputSource,
        capture_reason: CaptureReason::OversizedUserInput,
        content: input.source_text.clone(),
        host_captured_bytes: input.source_text.len(),
        host_original_bytes: input.source_text.len(),
        host_dropped_bytes: 0,
        stored_source_bytes: input.source_text.len(),
        provenance_json: serde_json::json!({"event_seq": event_seq}).to_string(),
        created_at: input.now_ms,
    };
    let TextArtifactAdmission::Stored(source_artifact) = insert_artifact_conn(
        conn,
        reservation.session_id,
        event_seq,
        &source_candidate,
        TextArtifactRepresentation::Raw,
        None,
        None,
    )?
    else {
        bail!("reserved source artifact could not be admitted");
    };
    let projection_artifact = if let Some(projection) = &input.model_projection {
        let candidate = TextArtifactCandidate {
            relation: TextArtifactRelation::ModelUserInputProjection,
            projection_slot: Some(0),
            kind: TextArtifactKind::UserInputProjection,
            capture_reason: CaptureReason::OversizedUserInput,
            content: projection.clone(),
            host_captured_bytes: projection.len(),
            host_original_bytes: projection.len(),
            host_dropped_bytes: 0,
            stored_source_bytes: projection.len(),
            provenance_json: serde_json::json!({"source_artifact_id": source_artifact.artifact_id.to_string(), "preprocessing_version": 1}).to_string(),
            created_at: input.now_ms,
        };
        match insert_artifact_conn(
            conn,
            reservation.session_id,
            event_seq,
            &candidate,
            TextArtifactRepresentation::Raw,
            None,
            None,
        )? {
            TextArtifactAdmission::Stored(artifact) => Some(artifact),
            TextArtifactAdmission::ArtifactLimit => {
                // The size preflight above terminalizes known oversized derived
                // input before writing the event. Reaching this branch means a
                // supposedly admitted reservation no longer matches its
                // validation inputs, so abort the whole transaction rather
                // than persist a source-only materialization.
                bail!("reserved user projection exceeded the validated artifact limit")
            }
            TextArtifactAdmission::SessionQuota => {
                bail!("reserved user projection could not be admitted")
            }
        }
    } else {
        None
    };
    let safe_outcome = MessageSafeOutcome::Materialized {
        message_seq: event_seq as u64,
    }
    .encode();
    let operation = conn.execute(
        "UPDATE message_operation_receipts SET state='materialized',safe_outcome=?1,updated_at=?2
          WHERE session_id=?3 AND operation_id=?4 AND client_submission_id=?5 AND state='accepted'",
        params![
            safe_outcome,
            input.now_ms,
            reservation.session_id.to_string(),
            reservation.operation_id.as_slice(),
            reservation.client_submission_id.as_slice()
        ],
    )?;
    ensure!(
        operation == 1,
        "accepted operation receipt changed during artifact materialization"
    );
    let submission = conn.execute(
        "UPDATE message_submission_receipts SET state='materialized',message_seq=?1,fold_ordinal=0,safe_outcome=?2,updated_at=?3
          WHERE session_id=?4 AND client_submission_id=?5 AND operation_id=?6 AND queue_item_id=?7 AND state='accepted'",
        params![event_seq, MessageSafeOutcome::Materialized { message_seq: event_seq as u64 }.encode(), input.now_ms, reservation.session_id.to_string(), reservation.client_submission_id.as_slice(), reservation.operation_id.as_slice(), reservation.queue_item_id.as_slice()],
    )?;
    ensure!(
        submission == 1,
        "accepted submission receipt changed during artifact materialization"
    );
    let queue = conn.execute(
        "UPDATE message_queue_items SET state='materialized',updated_at=?1
          WHERE session_id=?2 AND queue_item_id=?3 AND client_submission_id=?4 AND state IN ('accepted','folding')",
        params![input.now_ms, reservation.session_id.to_string(), reservation.queue_item_id.as_slice(), reservation.client_submission_id.as_slice()],
    )?;
    ensure!(
        queue == 1,
        "accepted queue item changed during artifact materialization"
    );
    if let Some(invocation_id) = bound_invocation_id {
        // Phase one deliberately persists a bounded invocation with an
        // unarmed `remaining_ms=NULL` clock. Start the countdown only after
        // this same transaction has materialized the receipt/event/artifacts;
        // a crash or any late failure rolls both the event and clock start
        // back, leaving queued wall time uncharged.
        crate::db::run_invocations::start_deferred_run_invocation_timeout_conn(
            conn,
            invocation_id,
            reservation.session_id,
            input.now_ms,
        )?;
    }
    Ok(ReservedUserArtifactMaterializationResult::Materialized(
        Box::new(ReservedUserArtifactMaterialized {
            event_seq,
            source_artifact,
            projection_artifact,
        }),
    ))
}

/// Validate the deliberately closed durable accepted-submission envelope.
///
/// This is kept in the database leaf as JSON because the DB must not depend on
/// provider message types.  Text parts are immutable contextual/guidance
/// bytes; `authored_text_slot` is the only replaceable part.  Media and tool
/// parts are opaque canonical JSON payloads owned by the core renderer, but
/// their type and byte bounds are still checked here so direct SQL cannot
/// manufacture an ambiguous composition.
pub(crate) fn validate_user_model_envelope(raw: &str) -> Result<()> {
    let value: serde_json::Value =
        serde_json::from_str(raw).context("invalid user model envelope JSON")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow!("user model envelope must be an object"))?;
    ensure!(
        (object.len() == 2 || object.len() == 3)
            && object.get("version").and_then(serde_json::Value::as_i64) == Some(3),
        "unknown user model envelope"
    );
    ensure!(
        object
            .keys()
            .all(|key| matches!(key.as_str(), "version" | "parts" | "prelude")),
        "user model envelope has unknown fields"
    );
    if let Some(prelude) = object.get("prelude") {
        let entries = prelude
            .as_array()
            .ok_or_else(|| anyhow!("user model envelope prelude must be an array"))?;
        ensure!(
            entries.len() <= 1,
            "user model envelope has too many prelude entries"
        );
        for entry in entries {
            let entry = entry
                .as_object()
                .ok_or_else(|| anyhow!("user model envelope prelude is invalid"))?;
            ensure!(
                entry.len() == 6
                    && entry.get("type").and_then(serde_json::Value::as_str)
                        == Some("forced_skill"),
                "unknown user model envelope prelude"
            );
            ensure!(
                entry
                    .get("call_id")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| !v.is_empty() && v.len() <= 256),
                "forced prelude call id is invalid"
            );
            ensure!(
                entry
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| !v.is_empty() && v.len() <= 256),
                "forced prelude name is invalid"
            );
            let name = entry
                .get("name")
                .and_then(serde_json::Value::as_str)
                .unwrap();
            let args = entry
                .get("args")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| anyhow!("forced prelude args must be an object"))?;
            ensure!(args.len() == 1, "forced prelude args have unknown fields");
            ensure!(
                args.get("name")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|value| !value.is_empty() && value.len() <= 256 && value == name),
                "forced prelude args name is invalid"
            );
            ensure!(
                entry
                    .get("body")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|v| v.len() <= 65_536),
                "forced prelude body is invalid"
            );
            ensure!(
                entry
                    .get("hard_fail")
                    .and_then(serde_json::Value::as_bool)
                    .is_some(),
                "forced prelude hard_fail is invalid"
            );
        }
    }
    let parts = object
        .get("parts")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow!("user model envelope parts must be an array"))?;
    ensure!(
        !parts.is_empty() && parts.len() <= 64,
        "user model envelope has an invalid part count"
    );
    let mut authored_slots = 0usize;
    for part in parts {
        let part = part
            .as_object()
            .ok_or_else(|| anyhow!("user model envelope part must be an object"))?;
        let kind = part
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| anyhow!("user model envelope part lacks type"))?;
        match kind {
            "authored_text_slot" => {
                ensure!(
                    part.len() == 1,
                    "authored slot carries duplicate source data"
                );
                authored_slots += 1;
            }
            "text" => {
                ensure!(part.len() == 2, "text envelope part has unknown fields");
                let text = part
                    .get("text")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow!("text envelope part lacks text"))?;
                ensure!(
                    !text.is_empty() && text.len() <= 65_536,
                    "text envelope part exceeds bounds"
                );
            }
            "image" | "audio" | "video" | "document" | "tool_result" => {
                ensure!(part.len() == 2, "typed envelope part has unknown fields");
                let payload = part
                    .get("payload")
                    .ok_or_else(|| anyhow!("typed envelope part lacks payload"))?;
                let payload_type = payload
                    .as_object()
                    .and_then(|payload| payload.get("type"))
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| anyhow!("typed envelope payload lacks its closed codec tag"))?;
                ensure!(
                    payload_type == kind,
                    "typed envelope payload has the wrong codec tag"
                );
                ensure!(
                    serde_json::to_vec(payload)?.len() <= 65_536,
                    "typed envelope payload exceeds bounds"
                );
            }
            _ => bail!("unknown user model envelope part type"),
        }
    }
    ensure!(
        authored_slots == 1,
        "user model envelope must own exactly one authored slot"
    );
    Ok(())
}

/// Reserved source artifacts model text-only ingress. A non-array declaration
/// is malformed and rejected as well, rather than creating a durable event a
/// later importer or rehydrator cannot safely interpret.
fn canonical_user_event_has_media_or_file_parts(
    event: &serde_json::Map<String, serde_json::Value>,
) -> bool {
    const MEDIA_OR_FILE_KEYS: [&str; 5] =
        ["images", "image_refs", "attachments", "files", "file_refs"];

    MEDIA_OR_FILE_KEYS.iter().any(|key| match event.get(*key) {
        Some(serde_json::Value::Array(parts)) => !parts.is_empty(),
        Some(_) => true,
        None => false,
    })
}

/// Archive-import transaction body. The whole-archive composition owns the
/// outer transaction and destination graph; this crate-private helper only
/// inserts its already-mapped immutable artifact slots.
pub(crate) fn import_text_artifact_slots_conn(
    conn: &Connection,
    slots: &[ImportedTextArtifactSlot],
    archive_import_id: Option<Uuid>,
) -> Result<Vec<TextArtifact>> {
    let mut imported = Vec::with_capacity(slots.len());
    let mut destination_ids = std::collections::BTreeMap::<Uuid, Uuid>::new();
    let mut pending = slots.iter().collect::<Vec<_>>();
    pending.sort_by_key(|slot| match slot.candidate.kind {
        TextArtifactKind::UserInputSource => 0,
        TextArtifactKind::ToolResult => 1,
        TextArtifactKind::UserInputProjection => 2,
    });
    for slot in pending {
        let mut candidate = slot.candidate.clone();
        match candidate.kind {
            TextArtifactKind::UserInputSource => {
                // Archive event ids are source-local. The destination artifact
                // is owned by the newly imported event, so rebuild this closed
                // provenance object instead of trusting a source sequence.
                candidate.provenance_json =
                    serde_json::json!({"event_seq": slot.event_seq}).to_string();
            }
            TextArtifactKind::UserInputProjection => {
                let source_id =
                    serde_json::from_str::<serde_json::Value>(&candidate.provenance_json)
                        .ok()
                        .and_then(|value| {
                            value
                                .get("source_artifact_id")
                                .and_then(serde_json::Value::as_str)
                                .map(str::to_owned)
                        })
                        .ok_or_else(|| {
                            anyhow!("imported projection provenance lacks source artifact id")
                        })?;
                let source_id = Uuid::parse_str(&source_id)
                    .context("invalid imported projection source artifact id")?;
                let destination_source = destination_ids
                    .get(&source_id)
                    .ok_or_else(|| anyhow!("imported projection precedes its source artifact"))?;
                candidate.provenance_json = serde_json::json!({
                    "source_artifact_id": destination_source.to_string(),
                    "preprocessing_version": 1,
                })
                .to_string();
            }
            TextArtifactKind::ToolResult => {}
        }
        let admission = insert_artifact_conn(
            conn,
            slot.session_id,
            slot.event_seq,
            &candidate,
            slot.representation,
            None,
            match slot.representation {
                TextArtifactRepresentation::Raw => None,
                TextArtifactRepresentation::ExportRedacted => archive_import_id,
            },
        )?;
        match admission {
            TextArtifactAdmission::Stored(artifact) => {
                ensure!(
                    destination_ids
                        .insert(slot.source_artifact_id, artifact.artifact_id)
                        .is_none(),
                    "imported text artifact id is duplicated"
                );
                imported.push(artifact);
            }
            TextArtifactAdmission::ArtifactLimit => bail!("imported text artifact exceeds 8 MiB"),
            TextArtifactAdmission::SessionQuota => {
                bail!("imported session text artifacts exceed 64 MiB quota")
            }
        }
    }
    Ok(imported)
}

/// Clone every artifact reachable from copied parent events into a fork.
/// This is a transaction body called from `sessions::create_fork_row_conn`, so
/// a quota or graph failure rolls the child row, transcript, artifact rows, and
/// any surrounding remote-operation ledger back together. Each destination
/// artifact is newly minted by `insert_artifact_conn`; no UUID or owner edge is
/// shared with the parent.
pub(crate) fn fork_session_artifacts_conn(
    conn: &Connection,
    parent_session_id: Uuid,
    child_session_id: Uuid,
    event_seq_map: &[(i64, i64)],
) -> Result<()> {
    let event_map = event_seq_map
        .iter()
        .copied()
        .collect::<std::collections::BTreeMap<_, _>>();
    if event_map.is_empty() {
        return Ok(());
    }
    let mut artifacts = list_text_artifacts_conn(conn, parent_session_id)?
        .into_iter()
        .filter(|artifact| event_map.contains_key(&artifact.event_seq))
        .collect::<Vec<_>>();
    artifacts.sort_by_key(|artifact| match artifact.kind {
        TextArtifactKind::UserInputSource => 0,
        TextArtifactKind::ToolResult => 1,
        TextArtifactKind::UserInputProjection => 2,
    });
    let mut destination_ids = std::collections::BTreeMap::<Uuid, Uuid>::new();
    for artifact in artifacts {
        let child_event_seq = *event_map
            .get(&artifact.event_seq)
            .ok_or_else(|| anyhow!("fork artifact event was not copied"))?;
        let mut provenance: serde_json::Value = serde_json::from_str(&artifact.provenance_json)
            .context("stored text artifact provenance is invalid")?;
        match artifact.kind {
            TextArtifactKind::UserInputSource => {
                provenance
                    .as_object_mut()
                    .ok_or_else(|| anyhow!("stored source provenance is not an object"))?
                    .insert("event_seq".to_string(), serde_json::json!(child_event_seq));
            }
            TextArtifactKind::UserInputProjection => {
                let source_id = provenance
                    .get("source_artifact_id")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(|| {
                        anyhow!("stored projection provenance lacks source artifact id")
                    })?;
                let source_id = Uuid::parse_str(source_id)
                    .context("stored projection provenance has invalid source artifact id")?;
                let child_source_id = destination_ids
                    .get(&source_id)
                    .ok_or_else(|| anyhow!("fork projection source was not copied"))?;
                provenance
                    .as_object_mut()
                    .ok_or_else(|| anyhow!("stored projection provenance is not an object"))?
                    .insert(
                        "source_artifact_id".to_string(),
                        serde_json::json!(child_source_id),
                    );
            }
            TextArtifactKind::ToolResult => {}
        }
        let candidate = TextArtifactCandidate {
            relation: artifact.relation,
            projection_slot: artifact.projection_slot,
            kind: artifact.kind,
            capture_reason: artifact.capture_reason,
            content: artifact.content,
            host_captured_bytes: artifact.host_captured_bytes,
            host_original_bytes: artifact.host_original_bytes,
            host_dropped_bytes: artifact.host_dropped_bytes,
            stored_source_bytes: artifact.stored_source_bytes,
            provenance_json: serde_json::to_string(&provenance)?,
            created_at: artifact.created_at,
        };
        match insert_artifact_conn(
            conn,
            child_session_id,
            child_event_seq,
            &candidate,
            // A local fork has no raw source to recover from an irreversible
            // import. Preserve both representation and the import provenance;
            // outbound export will still re-run its current safety gate.
            artifact.representation,
            None,
            artifact.archive_import_id,
        )? {
            TextArtifactAdmission::Stored(child) => {
                destination_ids.insert(artifact.artifact_id, child.artifact_id);
            }
            TextArtifactAdmission::ArtifactLimit => {
                bail!("forked text artifact exceeds 8 MiB")
            }
            TextArtifactAdmission::SessionQuota => {
                bail!("forked text artifacts exceed child session quota")
            }
        }
    }
    // The envelope is an immutable event-owned composition, distinct from the
    // artifact rows it references. Copy it only after every child event and
    // artifact owner has been remapped, inside this same outer transaction.
    for (parent_event_seq, child_event_seq) in event_seq_map {
        let envelope: Option<String> = conn
            .query_row(
                "SELECT envelope_json FROM session_user_message_model_envelopes WHERE session_id=?1 AND event_seq=?2",
                params![parent_session_id.to_string(), parent_event_seq],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(envelope) = envelope {
            validate_user_model_envelope(&envelope)?;
            conn.execute(
                "INSERT INTO session_user_message_model_envelopes(session_id,event_seq,envelope_json) VALUES(?1,?2,?3)",
                params![child_session_id.to_string(), child_event_seq, envelope],
            )?;
        }
    }
    Ok(())
}

fn reservation_matches_conn(
    conn: &Connection,
    reservation: &TextArtifactReservation,
    now_ms: Option<i64>,
) -> Result<bool> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM session_text_artifact_quota_reservations
          WHERE session_id=?1 AND client_submission_id=?2 AND operation_id=?3 AND queue_item_id=?4
            AND source_digest=?5 AND source_bytes=?6 AND reserved_bytes=?7 AND run_invocation_bound=?8
            AND lease_token=?9 AND expires_at=?10 AND (?11 IS NULL OR expires_at>?11))",
        params![
            reservation.session_id.to_string(), reservation.client_submission_id.as_slice(),
            reservation.operation_id.as_slice(), reservation.queue_item_id.as_slice(), reservation.source_digest.as_slice(),
            as_i64(reservation.source_bytes)?, as_i64(reservation.reserved_bytes)?, reservation.run_invocation_bound,
            reservation.lease_token.to_string(),
            reservation.expires_at, now_ms,
        ],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

fn reservation_for_submission_conn(
    conn: &Connection,
    session_id: Uuid,
    client_submission_id: [u8; 16],
) -> Result<Option<TextArtifactReservation>> {
    conn.query_row(
        "SELECT session_id,operation_id,client_submission_id,queue_item_id,source_digest,source_bytes,reserved_bytes,run_invocation_bound,model_fence_generation,model_fence_json,lease_token,expires_at
           FROM session_text_artifact_quota_reservations WHERE session_id=?1 AND client_submission_id=?2",
        params![session_id.to_string(), client_submission_id.as_slice()],
        decode_reservation,
    )
    .optional()
    .context("looking up text artifact reservation")
}

fn reserved_submission_conn(
    conn: &Connection,
    session_id: Uuid,
    client_submission_id: [u8; 16],
) -> Result<Option<ReservedTextArtifactSubmission>> {
    conn.query_row(
        "SELECT r.session_id,r.operation_id,r.client_submission_id,r.queue_item_id,
                r.source_digest,r.source_bytes,r.reserved_bytes,r.run_invocation_bound,r.model_fence_generation,r.model_fence_json,r.lease_token,r.expires_at,
                q.canonical_message
           FROM session_text_artifact_quota_reservations r
           JOIN message_queue_items q
             ON q.session_id=r.session_id AND q.queue_item_id=r.queue_item_id
          WHERE r.session_id=?1 AND r.client_submission_id=?2 AND q.state='accepted'",
        params![session_id.to_string(), client_submission_id.as_slice()],
        |row| {
            Ok(ReservedTextArtifactSubmission {
                reservation: decode_reservation(row)?,
                canonical_message: row.get(12)?,
            })
        },
    )
    .optional()
    .context("looking up reserved text artifact submission")
}

fn list_event_artifacts_conn(
    conn: &Connection,
    session_id: Uuid,
    event_seq: i64,
) -> Result<Vec<TextArtifact>> {
    let mut stmt = conn.prepare(
        "SELECT a.session_id,a.artifact_id,r.event_seq,r.relation,r.projection_slot,a.kind,a.capture_reason,
                a.content_representation,a.content,a.host_captured_bytes,a.host_original_bytes,a.host_dropped_bytes,
                a.stored_source_bytes,a.content_bytes,a.provenance_json,a.created_at,a.archive_import_id
           FROM session_text_artifacts a JOIN session_text_artifact_event_refs r
             ON r.session_id=a.session_id AND r.artifact_id=a.artifact_id
          WHERE r.session_id=?1 AND r.event_seq=?2 ORDER BY r.relation,r.projection_slot,a.artifact_id",
    )?;
    stmt.query_map(params![session_id.to_string(), event_seq], decode_artifact)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(Into::into)
}

fn as_i64(value: usize) -> Result<i64> {
    i64::try_from(value).context("text artifact byte count overflow")
}

fn parse_reject_reason(value: &str) -> Result<TextArtifactRejectReason> {
    match value {
        "artifact_reservation_expired" => Ok(TextArtifactRejectReason::ReservationExpired),
        "artifact_quota_exhausted" => Ok(TextArtifactRejectReason::QuotaExhausted),
        "artifact_too_large" => Ok(TextArtifactRejectReason::TooLarge),
        "artifact_security_rejected" => Ok(TextArtifactRejectReason::SecurityRejected),
        "artifact_preflight_rejected" => Ok(TextArtifactRejectReason::PreflightRejected),
        "artifact_idempotency_conflict" => Ok(TextArtifactRejectReason::IdempotencyConflict),
        "artifact_persistence_failed" => Ok(TextArtifactRejectReason::PersistenceFailed),
        _ => bail!("unknown text artifact terminal reason"),
    }
}

fn parse_kind(value: String) -> rusqlite::Result<TextArtifactKind> {
    match value.as_str() {
        "tool_result" => Ok(TextArtifactKind::ToolResult),
        "user_input_source" => Ok(TextArtifactKind::UserInputSource),
        "user_input_projection" => Ok(TextArtifactKind::UserInputProjection),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn parse_reason(value: String) -> rusqlite::Result<CaptureReason> {
    match value.as_str() {
        "display_truncation" => Ok(CaptureReason::DisplayTruncation),
        "prune_boundary" => Ok(CaptureReason::PruneBoundary),
        "oversized_user_input" => Ok(CaptureReason::OversizedUserInput),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn parse_relation(value: String) -> rusqlite::Result<TextArtifactRelation> {
    match value.as_str() {
        "source_user_input" => Ok(TextArtifactRelation::SourceUserInput),
        "model_user_input_projection" => Ok(TextArtifactRelation::ModelUserInputProjection),
        "model_context_tool_result" => Ok(TextArtifactRelation::ModelContextToolResult),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn parse_representation(value: String) -> rusqlite::Result<TextArtifactRepresentation> {
    match value.as_str() {
        "raw" => Ok(TextArtifactRepresentation::Raw),
        "export_redacted" => Ok(TextArtifactRepresentation::ExportRedacted),
        _ => Err(rusqlite::Error::InvalidQuery),
    }
}

fn decode_artifact(row: &rusqlite::Row<'_>) -> rusqlite::Result<TextArtifact> {
    let session_id: String = row.get(0)?;
    let artifact_id: String = row.get(1)?;
    let positive = |index: usize| -> rusqlite::Result<usize> {
        let value: i64 = row.get(index)?;
        usize::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(index, value))
    };
    Ok(TextArtifact {
        session_id: Uuid::parse_str(&session_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        artifact_id: Uuid::parse_str(&artifact_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                1,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        archive_import_id: row
            .get::<_, Option<String>>(16)?
            .map(|value| {
                Uuid::parse_str(&value).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        16,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })
            })
            .transpose()?,
        event_seq: row.get(2)?,
        relation: parse_relation(row.get(3)?)?,
        projection_slot: row.get(4)?,
        kind: parse_kind(row.get(5)?)?,
        capture_reason: parse_reason(row.get(6)?)?,
        representation: parse_representation(row.get(7)?)?,
        content: row.get(8)?,
        host_captured_bytes: positive(9)?,
        host_original_bytes: positive(10)?,
        host_dropped_bytes: positive(11)?,
        stored_source_bytes: positive(12)?,
        content_bytes: positive(13)?,
        provenance_json: row.get(14)?,
        created_at: row.get(15)?,
    })
}

fn decode_reservation(row: &rusqlite::Row<'_>) -> rusqlite::Result<TextArtifactReservation> {
    let session_id: String = row.get(0)?;
    let operation_id: Vec<u8> = row.get(1)?;
    let client_submission_id: Vec<u8> = row.get(2)?;
    let queue_item_id: Vec<u8> = row.get(3)?;
    let source_digest: Vec<u8> = row.get(4)?;
    let source_bytes: i64 = row.get(5)?;
    let reserved_bytes: i64 = row.get(6)?;
    let run_invocation_bound: i64 = row.get(7)?;
    let generation: Option<String> = row.get(8)?;
    let model_json: Option<String> = row.get(9)?;
    let model_fence = match (generation, model_json) {
        (None, None) => None,
        (Some(generation), Some(model_json)) => Some(TextArtifactModelFence {
            generation: generation
                .parse()
                .map_err(|_| rusqlite::Error::InvalidQuery)?,
            model_json,
        }),
        _ => return Err(rusqlite::Error::InvalidQuery),
    };
    let token: String = row.get(10)?;
    Ok(TextArtifactReservation {
        session_id: Uuid::parse_str(&session_id).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        operation_id: operation_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        client_submission_id: client_submission_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        queue_item_id: queue_item_id
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        source_digest: source_digest
            .try_into()
            .map_err(|_| rusqlite::Error::InvalidQuery)?,
        source_bytes: usize::try_from(source_bytes)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(5, source_bytes))?,
        reserved_bytes: usize::try_from(reserved_bytes)
            .map_err(|_| rusqlite::Error::IntegralValueOutOfRange(6, reserved_bytes))?,
        run_invocation_bound: match run_invocation_bound {
            0 => false,
            1 => true,
            value => return Err(rusqlite::Error::IntegralValueOutOfRange(7, value)),
        },
        model_fence,
        lease_token: Uuid::parse_str(&token).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                10,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })?,
        expires_at: row.get(11)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::message_attachments::MessageActor;
    use crate::db::session_log::{
        ClientSubmissionTerminalDisposition, ClientSubmissionTerminalReceipt,
    };
    use rusqlite::{Connection, params};

    struct AllowMessageJoin;

    impl MessageAcceptanceJoin for AllowMessageJoin {
        fn validate_and_join(&self, _: &Connection, _: &AcceptMessageInput) -> Result<()> {
            Ok(())
        }
    }

    fn acceptance_input(session_id: Uuid, seed: u8, now_ms: i64) -> AcceptMessageInput {
        AcceptMessageInput {
            session_id,
            operation_id: [seed; 16],
            actor: MessageActor::LocalOwner,
            request_hash: [seed.wrapping_add(1); 32],
            message_request_digest: [seed.wrapping_add(2); 32],
            attachment_set_digest: [seed.wrapping_add(3); 32],
            client_submission_id: [seed.wrapping_add(4); 16],
            queue_item_id: [seed.wrapping_add(5); 16],
            canonical_message: b"FCM2\x02".to_vec(),
            attachments: Vec::new(),
            outbox_sequence: i64::from(seed),
            now_ms,
        }
    }

    async fn reserve(
        db: &Db,
        input: AcceptMessageInput,
        source_bytes: usize,
        source_digest: [u8; 32],
    ) -> TextArtifactReservation {
        match db
            .accept_message_with_text_artifact_reservation(
                input,
                Arc::new(AllowMessageJoin),
                source_digest,
                source_bytes,
            )
            .await
            .expect("phase one succeeds")
        {
            TextArtifactPhaseOneResult::Reserved(reservation) => reservation,
            other => panic!("expected a live reservation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_model_fence_is_durable_replay_identity() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 201, 1_000);
        let source = "s".repeat(65_537);
        let fence = TextArtifactModelFence {
            generation: 7,
            model_json: r#"{"model":"gpt-5","provider":"openai"}"#.to_owned(),
        };

        let accepted = db
            .accept_message_with_text_artifact_reservation_with_model_fence(
                input.clone(),
                Arc::new(AllowMessageJoin),
                source_digest(&source),
                source.len(),
                Some(fence.clone()),
            )
            .await
            .unwrap();
        assert!(matches!(accepted, TextArtifactPhaseOneResult::Reserved(_)));

        let exact_replay = db
            .accept_message_with_text_artifact_reservation_with_model_fence(
                input.clone(),
                Arc::new(AllowMessageJoin),
                source_digest(&source),
                source.len(),
                Some(fence),
            )
            .await
            .unwrap();
        assert!(matches!(
            exact_replay,
            TextArtifactPhaseOneResult::Reserved(_)
        ));

        let mismatched_fence = db
            .accept_message_with_text_artifact_reservation_with_model_fence(
                input,
                Arc::new(AllowMessageJoin),
                source_digest(&source),
                source.len(),
                Some(TextArtifactModelFence {
                    generation: 8,
                    model_json: r#"{"model":"gpt-5","provider":"openai"}"#.to_owned(),
                }),
            )
            .await
            .unwrap();
        assert_eq!(mismatched_fence, TextArtifactPhaseOneResult::Conflict);
    }

    fn run_invocation_input() -> TextArtifactRunInvocationInput {
        run_invocation_input_with_timeout(None)
    }

    fn run_invocation_input_with_timeout(
        timeout_ms: Option<u64>,
    ) -> TextArtifactRunInvocationInput {
        TextArtifactRunInvocationInput {
            origin_principal_digest: "artifact-run-principal".to_owned(),
            options_json: format!(
                r#"{{"max_turns":null,"timeout_ms":{}}}"#,
                timeout_ms.map_or_else(|| "null".to_owned(), |value| value.to_string())
            ),
            options_digest: "artifact-run-options".to_owned(),
            content_digest: "artifact-run-content".to_owned(),
            max_turns: None,
            timeout_ms,
        }
    }

    async fn reserve_run(
        db: &Db,
        input: AcceptMessageInput,
        source_bytes: usize,
        source_digest: [u8; 32],
    ) -> TextArtifactReservation {
        match db
            .accept_message_with_text_artifact_reservation_and_run_invocation(
                input,
                Arc::new(AllowMessageJoin),
                source_digest,
                source_bytes,
                run_invocation_input(),
            )
            .await
            .expect("atomic oversized run phase one succeeds")
        {
            TextArtifactPhaseOneResult::Reserved(reservation) => {
                assert!(reservation.run_invocation_bound);
                reservation
            }
            other => panic!("expected a live bound reservation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn bound_oversized_run_timeout_is_queued_until_phase_two_materialization() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let source = "s".repeat(65_537);
        let input = acceptance_input(session.session_id, 82, 1_000);
        let invocation_id = Uuid::from_bytes(input.client_submission_id);
        let invocation = run_invocation_input_with_timeout(Some(5_000));
        let reservation = match db
            .accept_message_with_text_artifact_reservation_and_run_invocation(
                input.clone(),
                Arc::new(AllowMessageJoin),
                source_digest(&source),
                source.len(),
                invocation.clone(),
            )
            .await
            .unwrap()
        {
            TextArtifactPhaseOneResult::Reserved(reservation) => reservation,
            other => panic!("expected queued bound reservation, got {other:?}"),
        };

        let replay = db
            .accept_message_with_text_artifact_reservation_and_run_invocation(
                input,
                Arc::new(AllowMessageJoin),
                source_digest(&source),
                source.len(),
                invocation,
            )
            .await
            .unwrap();
        assert!(matches!(
            replay,
            TextArtifactPhaseOneResult::Reserved(ref replayed)
                if replayed.lease_token == reservation.lease_token
                    && replayed.run_invocation_bound
        ));

        let queued = db.get_run_invocation(invocation_id).await.unwrap().unwrap();
        assert_eq!(queued.state, "accepted");
        assert_eq!(queued.remaining_ms, None);
        assert!(queued.terminal_at_wall_ms.is_none());
        assert!(crate::db::run_invocations::timeout_clock_is_deferred(
            &queued
        ));
        assert!(matches!(
            db.checkpoint_run_invocation_remaining(invocation_id, Some(1), 99_000)
                .await
                .unwrap(),
            Some(row) if row.state == "accepted" && row.remaining_ms.is_none()
        ));
        assert!(matches!(
            db.fire_run_invocation_timeout(invocation_id, 99_000)
                .await
                .unwrap(),
            crate::db::run_invocations::TimeoutFireOutcome::ClockNotStarted(_)
        ));
        assert!(matches!(
            db.reserve_run_invocation_turn(invocation_id, 99_000)
                .await
                .unwrap(),
            crate::db::run_invocations::ReserveTurnOutcome::ClockNotStarted(_)
        ));

        let materialized_at = 100_000;
        let materialized = db
            .materialize_reserved_user_text_artifacts(ReservedUserArtifactMaterialization {
                reservation,
                canonical_event_json: serde_json::json!({ "text": source.clone() }).to_string(),
                model_envelope_json: r#"{"version":3,"parts":[{"type":"authored_text_slot"}]}"#
                    .to_owned(),
                source_text: source,
                model_projection: None,
                agent: Some("Build".to_owned()),
                context: TextArtifactEventContext::default(),
                now_ms: materialized_at,
            })
            .await
            .unwrap();
        assert!(matches!(
            materialized,
            ReservedUserArtifactMaterializationResult::Materialized(_)
        ));
        let running = db.get_run_invocation(invocation_id).await.unwrap().unwrap();
        assert_eq!(running.state, "running");
        assert_eq!(running.remaining_ms, Some(5_000));
        assert_eq!(running.last_observed_wall_ms, materialized_at);
        assert_eq!(
            crate::db::run_invocations::remaining_after_restart_for_test(
                running.remaining_ms,
                running.last_observed_wall_ms,
                materialized_at + 1_000,
            ),
            "remaining:4000",
            "restart accounting begins from phase two, not phase-one acceptance"
        );
    }

    fn tool_candidate(content: &str, slot: i64, call_id: &str) -> TextArtifactCandidate {
        TextArtifactCandidate {
            relation: TextArtifactRelation::ModelContextToolResult,
            projection_slot: Some(slot),
            kind: TextArtifactKind::ToolResult,
            capture_reason: CaptureReason::DisplayTruncation,
            content: content.to_owned(),
            host_captured_bytes: content.len(),
            host_original_bytes: content.len(),
            host_dropped_bytes: 0,
            stored_source_bytes: content.len(),
            provenance_json: serde_json::json!({
                "agent_id": "Build",
                "tool": "bash",
                "call_id": call_id,
            })
            .to_string(),
            created_at: 10,
        }
    }

    fn prune_candidate(content: &str, slot: i64, call_id: &str) -> TextArtifactCandidate {
        let mut candidate = tool_candidate(content, slot, call_id);
        candidate.capture_reason = CaptureReason::PruneBoundary;
        candidate
    }

    async fn record_tool_event(
        db: &Db,
        session_id: Uuid,
        content: &str,
    ) -> (TextArtifactEventResult, TextArtifact) {
        let result = db
            .record_event_with_text_artifacts(TextArtifactEventInput {
                session_id,
                kind: SessionEventKind::ToolCall,
                agent: Some("Build".to_owned()),
                call_id: Some("call-0".to_owned()),
                context: TextArtifactEventContext::default(),
                ts_ms: 10,
                data_json: serde_json::json!({ "output": "visible" }).to_string(),
                artifacts: vec![tool_candidate(content, 0, "call-0")],
                unavailable_projection: None,
            })
            .await
            .expect("tool event composition succeeds");
        let artifact = match &result.slots[0].admission {
            TextArtifactAdmission::Stored(artifact) => artifact.clone(),
            other => panic!("expected stored tool artifact, got {other:?}"),
        };
        (result, artifact)
    }

    #[tokio::test]
    async fn persistence_unavailable_projection_retains_no_tail_body_or_artifact() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let sentinel = "IGNORE_PREVIOUS_INSTRUCTIONS_ONLY_IN_RETAINED_TAIL";
        let captured = format!("visible capped display\n{sentinel}\n");
        let mut candidate = tool_candidate(&captured, 0, "tail-safety-call");
        // The production fail-closed path clears the retained bytes before
        // composing the event, while preserving host-side accounting.
        candidate.content.clear();
        candidate.stored_source_bytes = 0;
        let result = db
            .record_event_with_text_artifacts(TextArtifactEventInput {
                session_id: session.session_id,
                kind: SessionEventKind::ToolCall,
                agent: Some("Build".to_owned()),
                call_id: Some("tail-safety-call".to_owned()),
                context: TextArtifactEventContext::default(),
                ts_ms: 11,
                data_json: serde_json::json!({"output":"visible capped display"}).to_string(),
                artifacts: Vec::new(),
                unavailable_projection: Some(TextArtifactUnavailableProjection {
                    candidate,
                    reason: TextArtifactUnavailableReason::PersistenceUnavailable,
                }),
            })
            .await
            .unwrap();
        assert!(result.slots.is_empty());
        assert!(
            db.list_text_artifacts(session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            db.session_text_artifact_bytes(session.session_id)
                .await
                .unwrap(),
            0
        );
        let state = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT data_json FROM session_events WHERE session_id=?1 AND seq=?2",
                    params![session.session_id.to_string(), result.event_seq],
                    |row| row.get::<_, String>(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert!(state.contains("persistence_unavailable"));
        assert!(!state.contains(sentinel));
    }

    fn insert_direct_artifact_copy(
        conn: &Connection,
        artifact: &TextArtifact,
        artifact_id: Uuid,
        owner_slot: i64,
        relation: TextArtifactRelation,
        capture_reason: CaptureReason,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO session_text_artifacts (
                 session_id,artifact_id,kind,capture_reason,content_representation,archive_import_id,
                 owner_event_seq,owner_relation,owner_slot,content,
                 host_captured_bytes,host_original_bytes,host_dropped_bytes,stored_source_bytes,
                 content_bytes,provenance_json,created_at
             ) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)",
            params![
                artifact.session_id.to_string(),
                artifact_id.to_string(),
                artifact.kind.as_str(),
                capture_reason.as_str(),
                artifact.representation.as_str(),
                artifact.archive_import_id.map(|id| id.to_string()),
                artifact.event_seq,
                relation.as_str(),
                owner_slot,
                artifact.content,
                artifact.host_captured_bytes as i64,
                artifact.host_original_bytes as i64,
                artifact.host_dropped_bytes as i64,
                artifact.stored_source_bytes as i64,
                artifact.content_bytes as i64,
                artifact.provenance_json,
                artifact.created_at,
            ],
        )
    }

    #[tokio::test]
    async fn direct_sql_guards_immutable_owners_slots_and_owner_cascades() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let (event, artifact) = record_tool_event(&db, session.session_id, "tool body\n").await;
        let event_seq = event.event_seq;

        let artifact_for_guards = artifact.clone();
        db.transaction(move |conn| {
            assert!(
                conn.execute(
                    "DELETE FROM session_text_artifacts WHERE session_id=?1 AND artifact_id=?2",
                    params![
                        artifact_for_guards.session_id.to_string(),
                        artifact_for_guards.artifact_id.to_string()
                    ],
                )
                .is_err(),
                "direct artifact deletion must not bypass its owning event"
            );
            assert!(
                conn.execute(
                    "DELETE FROM session_text_artifact_event_refs WHERE session_id=?1 AND artifact_id=?2",
                    params![
                        artifact_for_guards.session_id.to_string(),
                        artifact_for_guards.artifact_id.to_string()
                    ],
                )
                .is_err(),
                "direct reference deletion must not orphan an available event state"
            );
            assert!(
                conn.execute(
                    "UPDATE session_text_artifacts SET content='mutated' WHERE session_id=?1 AND artifact_id=?2",
                    params![
                        artifact_for_guards.session_id.to_string(),
                        artifact_for_guards.artifact_id.to_string()
                    ],
                )
                .is_err(),
                "artifact bodies and metadata are immutable"
            );
            assert!(
                conn.execute(
                    "UPDATE session_events SET data_json='{}' WHERE session_id=?1 AND seq=?2",
                    params![artifact_for_guards.session_id.to_string(), event_seq],
                )
                .is_err(),
                "projection JSON cannot be rewritten after ownership is established"
            );
            assert!(
                conn.execute(
                    "INSERT INTO session_text_artifacts (
                        session_id,artifact_id,kind,capture_reason,content_representation,archive_import_id,
                        owner_event_seq,owner_relation,owner_slot,content,
                        host_captured_bytes,host_original_bytes,host_dropped_bytes,stored_source_bytes,
                        content_bytes,provenance_json,created_at
                     ) VALUES (?1,?2,'tool_result','display_truncation','export_redacted',NULL,
                        ?3,'model_context_tool_result',0,'tool body\n',10,10,0,10,10,
                        '{\"agent_id\":\"Build\",\"tool\":\"bash\",\"call_id\":\"call-0\"}',10)",
                    params![
                        artifact_for_guards.session_id.to_string(),
                        Uuid::new_v4().to_string(),
                        event_seq,
                    ],
                )
                .is_err(),
                "export-redacted bodies require archive import provenance"
            );
            Ok(())
        })
        .await
        .unwrap();

        let orphan_id = Uuid::new_v4();
        let orphan_artifact = artifact.clone();
        assert!(
            db.transaction(move |conn| {
                insert_direct_artifact_copy(
                    conn,
                    &orphan_artifact,
                    orphan_id,
                    0,
                    TextArtifactRelation::ModelContextToolResult,
                    CaptureReason::DisplayTruncation,
                )?;
                Ok(())
            })
            .await
            .is_err(),
            "the deferred owner foreign key rejects a direct-SQL orphan at commit"
        );

        let duplicate_id = Uuid::new_v4();
        let duplicate_artifact = artifact.clone();
        db.transaction(move |conn| {
            insert_direct_artifact_copy(
                conn,
                &duplicate_artifact,
                duplicate_id,
                0,
                TextArtifactRelation::ModelContextToolResult,
                CaptureReason::DisplayTruncation,
            )?;
            assert!(
                conn.execute(
                    "INSERT INTO session_text_artifact_event_refs
                         (session_id,event_seq,relation,projection_slot,owner_slot,artifact_id)
                     VALUES (?1,?2,'model_context_tool_result',0,0,?3)",
                    params![
                        duplicate_artifact.session_id.to_string(),
                        duplicate_artifact.event_seq,
                        duplicate_id.to_string(),
                    ],
                )
                .is_err(),
                "a second model slot zero must fail even through direct SQL"
            );
            conn.execute(
                "DELETE FROM session_text_artifacts WHERE session_id=?1 AND artifact_id=?2",
                params![
                    duplicate_artifact.session_id.to_string(),
                    duplicate_id.to_string()
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let cascade_session = session.session_id;
        db.transaction(move |conn| {
            conn.execute(
                "DELETE FROM session_events WHERE session_id=?1 AND seq=?2",
                params![cascade_session.to_string(), event_seq],
            )?;
            Ok(())
        })
        .await
        .expect("owner event cascade remains the sole legal cleanup path");
        assert!(
            db.list_text_artifacts(session.session_id)
                .await
                .unwrap()
                .is_empty(),
            "event cascade synchronously removes its unique artifact"
        );
    }

    #[tokio::test]
    async fn direct_sql_projection_declarations_are_contiguous_and_require_owner_refs() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();

        let available = projection_state(
            &tool_candidate("declared body\n", 0, "direct-tool-call"),
            EventArtifactAdmissionPlan::Store,
        )
        .unwrap();
        let available_data = serde_json::json!({
            "output": "visible",
            "artifact_projection": available,
        })
        .to_string();
        let pending_session_id = session.session_id;
        assert!(
            db.transaction(move |conn| {
                conn.execute(
                    "INSERT INTO session_events (session_id,ts_ms,type,agent,call_id,data_json)
                     VALUES (?1,?2,'tool_call','Build','direct-tool-call',?3)",
                    params![pending_session_id.to_string(), 20, available_data],
                )?;
                let pending_event_seq = conn.last_insert_rowid();
                assert!(
                    conn.execute(
                        "DELETE FROM session_text_artifact_projection_pending_slots
                          WHERE session_id=?1 AND event_seq=?2 AND projection_slot=0",
                        params![pending_session_id.to_string(), pending_event_seq],
                    )
                    .is_err(),
                    "direct SQL cannot clear an available declaration before its owner ref exists"
                );
                assert!(
                    conn.execute(
                        "INSERT INTO session_text_artifact_projection_pending_sentinel (unresolved)
                         VALUES (1)",
                        [],
                    )
                    .is_err(),
                    "direct SQL cannot manufacture the deferred validation sentinel"
                );
                Ok(())
            })
            .await
            .is_err(),
            "a declared available projection without its matching ref cannot commit"
        );

        let malformed = projection_state(
            &prune_candidate("unavailable body\n", 1, "sparse-prune-call"),
            EventArtifactAdmissionPlan::ArtifactLimit,
        )
        .unwrap();
        let malformed_data = serde_json::json!({
            "artifact_projections": [malformed],
        })
        .to_string();
        let malformed_session_id = session.session_id;
        db.transaction(move |conn| {
            assert!(
                conn.execute(
                    "INSERT INTO session_events (session_id,ts_ms,type,agent,data_json)
                     VALUES (?1,?2,'context_pruned','Build',?3)",
                    params![malformed_session_id.to_string(), 21, malformed_data],
                )
                .is_err(),
                "a direct context-pruned declaration must use contiguous zero-based slots"
            );
            Ok(())
        })
        .await
        .unwrap();

        let unavailable = projection_state(
            &prune_candidate("quota body\n", 0, "unavailable-prune-call"),
            EventArtifactAdmissionPlan::SessionQuota,
        )
        .unwrap();
        let mut impossible_unavailable = unavailable.clone();
        impossible_unavailable["reason"] = serde_json::Value::String("artifact_limit".to_owned());
        let impossible_unavailable_data = serde_json::json!({
            "artifact_projections": [impossible_unavailable],
        })
        .to_string();
        let impossible_session_id = session.session_id;
        db.transaction(move |conn| {
            assert!(
                conn.execute(
                    "INSERT INTO session_events (session_id,ts_ms,type,agent,data_json)
                     VALUES (?1,?2,'context_pruned','Build',?3)",
                    params![
                        impossible_session_id.to_string(),
                        22,
                        impossible_unavailable_data
                    ],
                )
                .is_err(),
                "an unavailable direct-SQL state cannot call a sub-8MiB candidate artifact_limit"
            );
            Ok(())
        })
        .await
        .unwrap();
        let unavailable_data = serde_json::json!({
            "artifact_projections": [unavailable],
        })
        .to_string();
        let unavailable_session_id = session.session_id;
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO session_events (session_id,ts_ms,type,agent,data_json)
                 VALUES (?1,?2,'context_pruned','Build',?3)",
                params![unavailable_session_id.to_string(), 22, unavailable_data],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let projections = db
            .text_artifact_projection_call_ids(session.session_id)
            .await
            .unwrap();
        assert!(
            projections
                .prune_boundary_calls
                .contains("unavailable-prune-call"),
            "a structurally complete unavailable declaration remains durable without a ref"
        );
    }

    #[tokio::test]
    async fn oversized_user_artifact_materialization_rejects_media_before_durable_write() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let source = "s".repeat(65_537);
        let reservation = reserve(
            &db,
            acceptance_input(session.session_id, 10, 100),
            source.len(),
            source_digest(&source),
        )
        .await;
        let retained_reservation = reservation.clone();

        let error = db
            .materialize_reserved_user_text_artifacts(ReservedUserArtifactMaterialization {
                reservation,
                canonical_event_json: serde_json::json!({
                    "text": source.clone(),
                    "images": [{"id": Uuid::new_v4()}],
                })
                .to_string(),
                model_envelope_json: r#"{"version":3,"parts":[{"type":"authored_text_slot"}]}"#
                    .to_owned(),
                source_text: source,
                model_projection: None,
                agent: Some("Build".to_owned()),
                context: TextArtifactEventContext::default(),
                now_ms: 101,
            })
            .await
            .expect_err("an oversized source may not materialize a media-bearing event");
        assert!(
            error.to_string().contains("cannot carry media/file parts"),
            "unexpected materialization error: {error:#}"
        );
        assert!(
            db.list_session_events(session.session_id)
                .await
                .unwrap()
                .is_empty(),
            "the rejected canonical shape writes no durable event"
        );
        let reservation_count: i64 = db
            .read(move |conn| {
                conn.query_row(
                    "SELECT COUNT(*) FROM session_text_artifact_quota_reservations
                     WHERE session_id=?1 AND client_submission_id=?2",
                    params![
                        retained_reservation.session_id.to_string(),
                        retained_reservation.client_submission_id.as_slice(),
                    ],
                    |row| row.get(0),
                )
                .map_err(Into::into)
            })
            .await
            .unwrap();
        assert_eq!(
            reservation_count, 1,
            "validation runs before releasing the accepted phase-one reservation"
        );
    }

    #[tokio::test]
    async fn direct_sql_rejects_duplicate_source_and_sparse_prune_slots() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let source = "s".repeat(65_537);
        let input = acceptance_input(session.session_id, 11, 100);
        let reservation = reserve(&db, input.clone(), source.len(), source_digest(&source)).await;
        let materialized = db
            .materialize_reserved_user_text_artifacts(ReservedUserArtifactMaterialization {
                reservation,
                canonical_event_json: serde_json::json!({ "text": source }).to_string(),
                model_envelope_json: r#"{"version":3,"parts":[{"type":"authored_text_slot"}]}"#
                    .to_owned(),
                source_text: source,
                model_projection: Some("different model projection".to_owned()),
                agent: Some("Build".to_owned()),
                context: TextArtifactEventContext::default(),
                now_ms: 101,
            })
            .await
            .unwrap();
        let (source_event_seq, source_artifact) = match materialized {
            ReservedUserArtifactMaterializationResult::Materialized(materialized) => {
                (materialized.event_seq, materialized.source_artifact)
            }
            other => panic!("expected materialization, got {other:?}"),
        };
        let duplicate_source_id = Uuid::new_v4();
        db.transaction(move |conn| {
            insert_direct_artifact_copy(
                conn,
                &source_artifact,
                duplicate_source_id,
                -1,
                TextArtifactRelation::SourceUserInput,
                CaptureReason::OversizedUserInput,
            )?;
            assert!(
                conn.execute(
                    "INSERT INTO session_text_artifact_event_refs
                         (session_id,event_seq,relation,projection_slot,owner_slot,artifact_id)
                     VALUES (?1,?2,'source_user_input',NULL,-1,?3)",
                    params![
                        source_artifact.session_id.to_string(),
                        source_event_seq,
                        duplicate_source_id.to_string(),
                    ],
                )
                .is_err(),
                "the partial NULL-source slot index must reject a duplicate owner"
            );
            conn.execute(
                "DELETE FROM session_text_artifacts WHERE session_id=?1 AND artifact_id=?2",
                params![
                    source_artifact.session_id.to_string(),
                    duplicate_source_id.to_string()
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();

        let prune = db
            .record_event_with_text_artifacts(TextArtifactEventInput {
                session_id: session.session_id,
                kind: SessionEventKind::ContextPruned,
                agent: Some("Build".to_owned()),
                call_id: None,
                context: TextArtifactEventContext::default(),
                ts_ms: 110,
                data_json: serde_json::json!({ "pruned": true }).to_string(),
                artifacts: vec![
                    prune_candidate("first\n", 0, "call-prune-0"),
                    prune_candidate("second\n", 1, "call-prune-1"),
                ],
                unavailable_projection: None,
            })
            .await
            .unwrap();
        let projections = db
            .text_artifact_projection_call_ids(session.session_id)
            .await
            .unwrap();
        assert_eq!(
            projections.prune_boundary_calls,
            ["call-prune-0".to_owned(), "call-prune-1".to_owned()]
                .into_iter()
                .collect()
        );
        let existing_prune_artifact = match &prune.slots[0].admission {
            TextArtifactAdmission::Stored(artifact) => artifact.clone(),
            other => panic!("expected stored prune artifact, got {other:?}"),
        };
        let sparse_id = Uuid::new_v4();
        db.transaction(move |conn| {
            insert_direct_artifact_copy(
                conn,
                &existing_prune_artifact,
                sparse_id,
                2,
                TextArtifactRelation::ModelContextToolResult,
                CaptureReason::PruneBoundary,
            )?;
            assert!(
                conn.execute(
                    "INSERT INTO session_text_artifact_event_refs
                         (session_id,event_seq,relation,projection_slot,owner_slot,artifact_id)
                     VALUES (?1,?2,'model_context_tool_result',2,2,?3)",
                    params![
                        existing_prune_artifact.session_id.to_string(),
                        prune.event_seq,
                        sparse_id.to_string(),
                    ],
                )
                .is_err(),
                "direct SQL cannot attach an undeclared sparse prune slot"
            );
            conn.execute(
                "DELETE FROM session_text_artifacts WHERE session_id=?1 AND artifact_id=?2",
                params![
                    existing_prune_artifact.session_id.to_string(),
                    sparse_id.to_string()
                ],
            )?;
            Ok(())
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn quota_boundary_serializes_concurrent_phase_one_and_replays_exact_identity() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let source_bytes = MAX_ARTIFACT_CONTENT_BYTES;

        let first = acceptance_input(session.session_id, 21, 1_000);
        let first_reservation = reserve(&db, first.clone(), source_bytes, [21; 32]).await;
        let replay = db
            .accept_message_with_text_artifact_reservation(
                first.clone(),
                Arc::new(AllowMessageJoin),
                [21; 32],
                source_bytes,
            )
            .await
            .unwrap();
        assert!(matches!(
            replay,
            TextArtifactPhaseOneResult::Reserved(ref reservation)
                if reservation.lease_token == first_reservation.lease_token
                    && reservation.expires_at == first_reservation.expires_at
        ));
        assert!(matches!(
            db.accept_message_with_text_artifact_reservation(
                first,
                Arc::new(AllowMessageJoin),
                [99; 32],
                source_bytes,
            )
            .await
            .unwrap(),
            TextArtifactPhaseOneResult::Conflict
        ));

        // Three 16-MiB reservations are committed before the concurrent pair.
        // Exactly one of that pair can claim the fourth and final 16-MiB
        // allowance; the writer must terminalize the other receipt instead of
        // admitting both on stale aggregate accounting.
        for seed in [31, 41] {
            reserve(
                &db,
                acceptance_input(session.session_id, seed, 1_000),
                source_bytes,
                [seed; 32],
            )
            .await;
        }
        let left_input = acceptance_input(session.session_id, 51, 1_000);
        let right_input = acceptance_input(session.session_id, 61, 1_000);
        let (left, right) = tokio::join!(
            db.accept_message_with_text_artifact_reservation(
                left_input.clone(),
                Arc::new(AllowMessageJoin),
                [51; 32],
                source_bytes,
            ),
            db.accept_message_with_text_artifact_reservation(
                right_input.clone(),
                Arc::new(AllowMessageJoin),
                [61; 32],
                source_bytes,
            )
        );
        let outcomes = [left.unwrap(), right.unwrap()];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, TextArtifactPhaseOneResult::Reserved(_)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| {
                    matches!(
                        outcome,
                        TextArtifactPhaseOneResult::Terminal {
                            reason: TextArtifactRejectReason::QuotaExhausted
                        }
                    )
                })
                .count(),
            1
        );
        let terminal_input = if matches!(&outcomes[0], TextArtifactPhaseOneResult::Terminal { .. })
        {
            left_input
        } else {
            right_input
        };
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                terminal_input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Terminal {
                reason: TextArtifactRejectReason::QuotaExhausted
            }
        );
        assert_eq!(
            db.session_text_artifact_bytes(session.session_id)
                .await
                .unwrap(),
            0,
            "reservations charge quota without inventing committed bodies"
        );
    }

    #[tokio::test]
    async fn direct_sql_quota_counts_committed_bodies_and_live_reservations_together() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let body = "q".repeat(MAX_ARTIFACT_CONTENT_BYTES);
        let (_, committed) = record_tool_event(&db, session.session_id, &body).await;

        // The committed 8MiB body plus three source+projection worst-case
        // reservations is 56MiB. A direct SQL insert of one more 8MiB body is
        // exactly the hard 64MiB ceiling; one additional byte must fail before
        // any owner/reference composition can make it durable.
        for seed in [101, 111, 121] {
            reserve(
                &db,
                acceptance_input(session.session_id, seed, 1_000),
                MAX_ARTIFACT_CONTENT_BYTES,
                [seed; 32],
            )
            .await;
        }
        let exact_id = Uuid::new_v4();
        let over_id = Uuid::new_v4();
        let direct = committed.clone();
        db.transaction(move |conn| {
            insert_direct_artifact_copy(
                conn,
                &direct,
                exact_id,
                0,
                TextArtifactRelation::ModelContextToolResult,
                CaptureReason::DisplayTruncation,
            )?;
            assert!(
                insert_direct_artifact_copy(
                    conn,
                    &direct,
                    over_id,
                    0,
                    TextArtifactRelation::ModelContextToolResult,
                    CaptureReason::DisplayTruncation,
                )
                .is_err(),
                "direct SQL cannot exceed committed plus reserved session quota"
            );
            // This probe intentionally has no ref, so remove it before the
            // deferred exact-one-owner foreign key is checked at commit.
            conn.execute(
                "DELETE FROM session_text_artifacts WHERE session_id=?1 AND artifact_id=?2",
                params![direct.session_id.to_string(), exact_id.to_string()],
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            db.session_text_artifact_bytes(session.session_id)
                .await
                .unwrap(),
            MAX_ARTIFACT_CONTENT_BYTES,
            "the direct SQL probe leaves neither an ownerless body nor a quota charge"
        );
    }

    #[tokio::test]
    async fn injected_clock_renew_reap_and_exact_terminal_receipts_are_race_safe() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 71, 10_000);
        let reservation = reserve_run(&db, input.clone(), 65_537, [71; 32]).await;
        let invocation_id = Uuid::from_bytes(input.client_submission_id);
        let renew_at = reservation.expires_at - ARTIFACT_RESERVATION_RENEW_AT_REMAINING_MS;
        let renewed = db
            .renew_text_artifact_reservation(reservation.clone(), renew_at)
            .await
            .unwrap()
            .expect("renewal owns the exact live token");
        assert_ne!(renewed.lease_token, reservation.lease_token);
        assert!(renewed.expires_at > reservation.expires_at);
        assert_eq!(
            db.reject_and_release_text_artifact_reservation(
                reservation,
                TextArtifactRejectReason::PreflightRejected,
                renew_at,
            )
            .await
            .unwrap(),
            TextArtifactReservationTransition::Stale,
            "an old holder cannot terminalize the renewed lease"
        );
        assert!(
            db.reap_expired_text_artifact_reservations(renewed.expires_at - 1)
                .await
                .unwrap()
                .is_empty(),
            "injected clock before expiry leaves the exact live lease alone"
        );
        assert_eq!(
            db.reap_expired_text_artifact_reservations(renewed.expires_at)
                .await
                .unwrap(),
            vec![TextArtifactReservationTransition::Applied(
                TextArtifactRejectReason::ReservationExpired
            )]
        );
        assert_eq!(
            db.text_artifact_reservation_replay(
                session.session_id,
                input.operation_id,
                renewed.expires_at,
            )
            .await
            .unwrap(),
            TextArtifactReservationReplay::Terminal {
                reason: TextArtifactRejectReason::ReservationExpired,
            }
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Terminal {
                reason: TextArtifactRejectReason::ReservationExpired
            }
        );
        let invocation = db
            .get_run_invocation(invocation_id)
            .await
            .unwrap()
            .expect("expiry preserves a terminal invocation replay row");
        assert_eq!(invocation.state, "failed");
        assert_eq!(invocation.terminal_reason.as_deref(), Some("failed"));
    }

    #[tokio::test]
    async fn oversized_user_artifact_rejection_terminalizes_bound_run_invocation_and_replays() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 75, 12_000);
        let reservation = reserve_run(&db, input.clone(), 65_537, [75; 32]).await;
        let invocation_id = Uuid::from_bytes(input.client_submission_id);

        assert_eq!(
            db.reject_and_release_text_artifact_reservation(
                reservation,
                TextArtifactRejectReason::PreflightRejected,
                12_002,
            )
            .await
            .unwrap(),
            TextArtifactReservationTransition::Applied(TextArtifactRejectReason::PreflightRejected)
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Terminal {
                reason: TextArtifactRejectReason::PreflightRejected
            }
        );
        assert!(
            db.reserved_text_artifact_submission(session.session_id, input.client_submission_id)
                .await
                .unwrap()
                .is_none(),
            "terminal message rejection consumes its only source lease"
        );
        let invocation = db
            .get_run_invocation(invocation_id)
            .await
            .unwrap()
            .expect("matching invocation is retained as a terminal replay row");
        assert_eq!(invocation.session_id, session.session_id);
        assert_eq!(invocation.state, "failed");
        assert_eq!(invocation.terminal_reason.as_deref(), Some("failed"));
        assert_eq!(invocation.terminal_at_wall_ms, Some(12_002));

        assert_eq!(
            db.text_artifact_reservation_replay(session.session_id, input.operation_id, 12_003)
                .await
                .unwrap(),
            TextArtifactReservationReplay::Terminal {
                reason: TextArtifactRejectReason::PreflightRejected,
            },
            "a restart sees one terminal message/invocation outcome, never an accepted run"
        );
    }

    #[tokio::test]
    async fn oversized_user_artifact_unbound_uuid_collision_never_terminalizes_an_unrelated_run() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 78, 12_500);
        let reservation = reserve(&db, input.clone(), 65_537, [78; 32]).await;
        assert!(!reservation.run_invocation_bound);

        // This represents a globally unique UUID that was claimed by an
        // unrelated legacy/direct caller. A plain oversized reservation must
        // never infer ownership from that UUID and terminalize the other run.
        let invocation = run_invocation_input();
        let invocation_id = Uuid::from_bytes(input.client_submission_id);
        assert!(matches!(
            db.accept_run_invocation(
                invocation_id,
                invocation.origin_principal_digest,
                session.session_id,
                invocation.options_json,
                invocation.options_digest,
                invocation.content_digest,
                invocation.max_turns,
                invocation.timeout_ms,
                12_501,
            )
            .await
            .unwrap(),
            crate::db::run_invocations::AcceptRunInvocationOutcome::Created(_)
        ));

        assert_eq!(
            db.reject_and_release_text_artifact_reservation(
                reservation,
                TextArtifactRejectReason::PreflightRejected,
                12_502,
            )
            .await
            .unwrap(),
            TextArtifactReservationTransition::Applied(TextArtifactRejectReason::PreflightRejected)
        );
        let unrelated = db
            .get_run_invocation(invocation_id)
            .await
            .unwrap()
            .expect("the unrelated invocation remains its own durable operation");
        assert_eq!(unrelated.state, "accepted");
        assert!(unrelated.terminal_at_wall_ms.is_none());
    }

    #[tokio::test]
    async fn oversized_user_artifact_run_invocation_fault_rolls_back_message_and_lease_together() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 76, 13_000);
        let reservation = reserve_run(&db, input.clone(), 65_537, [76; 32]).await;
        let invocation_id = Uuid::from_bytes(input.client_submission_id);

        db.transaction(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER text_artifact_test_fail_run_terminalization
                   BEFORE UPDATE OF terminal_at_wall_ms ON run_invocations
                   WHEN NEW.terminal_at_wall_ms IS NOT NULL
                   BEGIN SELECT RAISE(ABORT, 'injected run terminalization fault'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
        assert!(
            db.reject_and_release_text_artifact_reservation(
                reservation.clone(),
                TextArtifactRejectReason::PreflightRejected,
                13_002,
            )
            .await
            .is_err(),
            "a run-invocation terminalization fault aborts the whole composition"
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Accepted,
            "the failed transaction cannot leave a terminal message beside an accepted run"
        );
        assert!(
            db.reserved_text_artifact_submission(session.session_id, input.client_submission_id)
                .await
                .unwrap()
                .is_some(),
            "the exact lease survives for durable replay after the fault"
        );
        let active = db
            .get_run_invocation(invocation_id)
            .await
            .unwrap()
            .expect("accepted invocation remains with the accepted message after rollback");
        assert_eq!(active.state, "accepted");
        assert!(active.terminal_at_wall_ms.is_none());

        db.transaction(|conn| {
            conn.execute_batch("DROP TRIGGER text_artifact_test_fail_run_terminalization")?;
            Ok(())
        })
        .await
        .unwrap();
        assert_eq!(
            db.reject_and_release_text_artifact_reservation(
                reservation,
                TextArtifactRejectReason::PreflightRejected,
                13_003,
            )
            .await
            .unwrap(),
            TextArtifactReservationTransition::Applied(TextArtifactRejectReason::PreflightRejected)
        );
        assert_eq!(
            db.get_run_invocation(invocation_id)
                .await
                .unwrap()
                .expect("terminal invocation survives as a replay row")
                .terminal_reason
                .as_deref(),
            Some("failed")
        );
    }

    #[tokio::test]
    async fn oversized_user_artifact_run_idempotency_rejection_rolls_back_phase_one() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 77, 14_000);
        let invocation_id = Uuid::from_bytes(input.client_submission_id);
        let existing = db
            .accept_run_invocation(
                invocation_id,
                "foreign-principal".to_owned(),
                session.session_id,
                "{}".to_owned(),
                "foreign-options".to_owned(),
                "foreign-content".to_owned(),
                None,
                None,
                13_999,
            )
            .await
            .unwrap();
        assert!(matches!(
            existing,
            crate::db::run_invocations::AcceptRunInvocationOutcome::Created(_)
        ));

        let outcome = db
            .accept_message_with_text_artifact_reservation_and_run_invocation(
                input.clone(),
                Arc::new(AllowMessageJoin),
                [77; 32],
                65_537,
                run_invocation_input(),
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            TextArtifactPhaseOneResult::RunInvocationRejected(
                TextArtifactRunInvocationReject::ClientSubmissionIdUnavailable
            )
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Missing,
            "the rejected invocation rolls the provisional FCM2 receipt back"
        );
        assert!(
            db.reserved_text_artifact_submission(session.session_id, input.client_submission_id)
                .await
                .unwrap()
                .is_none(),
            "a rejected run has no live source lease to replay"
        );
        assert!(
            db.get_run_invocation(invocation_id)
                .await
                .unwrap()
                .is_some_and(|row| row.terminal_at_wall_ms.is_none()),
            "the failed FCM2 admission cannot terminalize a pre-existing unbound invocation"
        );
    }

    #[tokio::test]
    async fn oversized_user_artifact_cross_session_exact_run_replay_rolls_back_phase_one() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let other_session = db.create_session("p", "/y", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 79, 14_500);
        let invocation_id = Uuid::from_bytes(input.client_submission_id);
        let invocation = run_invocation_input();
        assert!(matches!(
            db.accept_run_invocation(
                invocation_id,
                invocation.origin_principal_digest.clone(),
                other_session.session_id,
                invocation.options_json.clone(),
                invocation.options_digest.clone(),
                invocation.content_digest.clone(),
                invocation.max_turns,
                invocation.timeout_ms,
                14_499,
            )
            .await
            .unwrap(),
            crate::db::run_invocations::AcceptRunInvocationOutcome::Created(_)
        ));

        let outcome = db
            .accept_message_with_text_artifact_reservation_and_run_invocation(
                input.clone(),
                Arc::new(AllowMessageJoin),
                [79; 32],
                65_537,
                invocation,
            )
            .await
            .unwrap();
        assert_eq!(
            outcome,
            TextArtifactPhaseOneResult::RunInvocationRejected(
                TextArtifactRunInvocationReject::ClientSubmissionIdUnavailable
            )
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Missing,
            "a cross-session run replay cannot bind a local message reservation"
        );
        let existing = db
            .get_run_invocation(invocation_id)
            .await
            .unwrap()
            .expect("the pre-existing run survives the rolled-back composition");
        assert_eq!(existing.session_id, other_session.session_id);
        assert!(existing.terminal_at_wall_ms.is_none());
    }

    #[tokio::test]
    async fn materialization_statement_fault_rolls_back_then_replays_once() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let source = "x".repeat(65_537);
        let input = acceptance_input(session.session_id, 81, 20_000);
        let reservation = reserve(&db, input.clone(), source.len(), source_digest(&source)).await;
        db.transaction(|conn| {
            conn.execute_batch(
                "CREATE TRIGGER text_artifact_test_fail_materialization
                   BEFORE UPDATE OF state ON message_queue_items
                   WHEN NEW.state='materialized'
                   BEGIN SELECT RAISE(ABORT, 'injected materialization fault'); END;",
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let materialization = ReservedUserArtifactMaterialization {
            reservation: reservation.clone(),
            canonical_event_json: serde_json::json!({ "text": source }).to_string(),
            // Model-bound preparation is already complete at phase two. A
            // statement fault must still leave neither this forced prelude nor
            // any owner/event row durable.
            model_envelope_json: r#"{"version":3,"prelude":[{"type":"forced_skill","call_id":"forced-fault","name":"review","args":{"name":"review"},"body":"FORCED","hard_fail":false}],"parts":[{"type":"text","text":"AUTO\nTAG\n"},{"type":"authored_text_slot"}]}"#.to_owned(),
            source_text: source,
            model_projection: Some("rewritten model body".to_owned()),
            agent: Some("Build".to_owned()),
            context: TextArtifactEventContext::default(),
            now_ms: 20_001,
        };
        assert!(
            db.materialize_reserved_user_text_artifacts(materialization.clone())
                .await
                .is_err(),
            "a late statement failure rolls back receipt, event, bodies, and lease together"
        );
        assert!(
            db.reserved_text_artifact_submission(session.session_id, input.client_submission_id)
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Accepted
        );
        assert!(
            db.list_text_artifacts(session.session_id)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            db.list_session_events(session.session_id)
                .await
                .unwrap()
                .is_empty(),
            "the failed phase two must not leave a canonical event/envelope owner"
        );
        assert!(
            db.list_tool_calls_for_session(session.session_id)
                .await
                .unwrap()
                .is_empty(),
            "prepared forced contributions are not a durable skill row before phase two wins"
        );
        db.transaction(|conn| {
            conn.execute_batch("DROP TRIGGER text_artifact_test_fail_materialization")?;
            Ok(())
        })
        .await
        .unwrap();
        let committed = db
            .materialize_reserved_user_text_artifacts(materialization)
            .await
            .unwrap();
        let event_seq = match committed {
            ReservedUserArtifactMaterializationResult::Materialized(materialized) => {
                materialized.event_seq
            }
            other => panic!("expected materialization after fault removal, got {other:?}"),
        };
        assert!(matches!(
            db.text_artifact_reservation_replay(session.session_id, input.operation_id, 20_001)
                .await
                .unwrap(),
            TextArtifactReservationReplay::Materialized {
                event_seq: replayed,
                ..
            } if replayed == event_seq
        ));
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Materialized
        );
    }

    #[tokio::test]
    async fn queued_oversized_removal_is_terminal_and_releases_the_exact_lease() {
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Build").await.unwrap();
        let input = acceptance_input(session.session_id, 91, 30_000);
        let reservation = reserve(&db, input.clone(), 65_537, [91; 32]).await;
        let receipt = ClientSubmissionTerminalReceipt {
            client_submission_id: Uuid::from_bytes(input.client_submission_id),
            fingerprint: "terminal-content".to_owned(),
            wire_fingerprint: "terminal-wire".to_owned(),
            origin_principal: None,
            disposition: ClientSubmissionTerminalDisposition::Removed,
        };
        db.terminalize_queued_text_artifact_submissions(
            session.session_id,
            vec![receipt.clone()],
            30_001,
        )
        .await
        .unwrap();
        assert!(
            db.reserved_text_artifact_submission(session.session_id, input.client_submission_id)
                .await
                .unwrap()
                .is_none(),
            "queued removal does not leave an accepted source replayable after restart"
        );
        assert_eq!(
            db.text_artifact_submission_durable_state(
                session.session_id,
                input.client_submission_id,
            )
            .await
            .unwrap(),
            TextArtifactSubmissionDurableState::Terminal {
                reason: TextArtifactRejectReason::PreflightRejected
            }
        );
        assert_eq!(
            db.reject_and_release_text_artifact_reservation(
                reservation,
                TextArtifactRejectReason::PreflightRejected,
                30_001,
            )
            .await
            .unwrap(),
            TextArtifactReservationTransition::Stale,
            "the DB-owned queued composition consumed the only lease"
        );
        db.terminalize_queued_text_artifact_submissions(session.session_id, vec![receipt], 30_002)
            .await
            .expect("the same terminal queue receipt is idempotent");
    }

    #[tokio::test]
    async fn imported_redacted_fork_preserves_provenance_and_failed_import_rolls_back() {
        let db = Db::open_in_memory().unwrap();
        let parent = db.create_session("p", "/x", "Build").await.unwrap();
        let source = "*".repeat(65_537);
        let parent_id = parent.session_id;
        let event_seq = db
            .transaction(move |conn| {
                Db::insert_session_event_json_conn(
                    conn,
                    parent_id,
                    SessionEventKind::UserMessage,
                    Some("Build"),
                    None,
                    SessionEventContext::default(),
                    40_000,
                    &serde_json::json!({ "text": source }).to_string(),
                )
            })
            .await
            .unwrap();
        let archive_import_id = Uuid::new_v4();
        let import_source = "*".repeat(65_537);
        let imported_artifact = Uuid::new_v4();
        db.transaction(move |conn| {
            conn.execute(
                "INSERT INTO session_text_artifact_archive_imports (import_id,imported_at)
                 VALUES (?1,?2)",
                params![archive_import_id.to_string(), 40_001],
            )?;
            import_text_artifact_slots_conn(
                conn,
                &[ImportedTextArtifactSlot {
                    source_artifact_id: imported_artifact,
                    session_id: parent_id,
                    event_seq,
                    candidate: TextArtifactCandidate {
                        relation: TextArtifactRelation::SourceUserInput,
                        projection_slot: None,
                        kind: TextArtifactKind::UserInputSource,
                        capture_reason: CaptureReason::OversizedUserInput,
                        content: import_source.clone(),
                        host_captured_bytes: import_source.len(),
                        host_original_bytes: import_source.len(),
                        host_dropped_bytes: 0,
                        stored_source_bytes: import_source.len(),
                        provenance_json: "{}".to_owned(),
                        created_at: 40_000,
                    },
                    representation: TextArtifactRepresentation::ExportRedacted,
                }],
                Some(archive_import_id),
            )?;
            Ok(())
        })
        .await
        .unwrap();
        let parent_artifact = db
            .list_text_artifacts(parent_id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(
            parent_artifact.representation,
            TextArtifactRepresentation::ExportRedacted
        );
        assert_eq!(parent_artifact.archive_import_id, Some(archive_import_id));
        let child = db.create_fork(parent_id, None).await.unwrap();
        let child_artifact = db
            .list_text_artifacts(child.session_id)
            .await
            .unwrap()
            .pop()
            .unwrap();
        assert_ne!(child_artifact.artifact_id, parent_artifact.artifact_id);
        assert_eq!(
            child_artifact.representation,
            TextArtifactRepresentation::ExportRedacted,
            "a fork cannot falsely relabel irreversible imported bytes as raw"
        );
        assert_eq!(child_artifact.archive_import_id, Some(archive_import_id));

        let before = db.list_text_artifacts(parent_id).await.unwrap();
        let failed_import_source = "*".repeat(65_537);
        assert!(
            db.transaction(move |conn| {
                let failed_import = Uuid::new_v4();
                conn.execute(
                    "INSERT INTO session_text_artifact_archive_imports (import_id,imported_at)
                     VALUES (?1,?2)",
                    params![failed_import.to_string(), 40_002],
                )?;
                import_text_artifact_slots_conn(
                    conn,
                    &[ImportedTextArtifactSlot {
                        source_artifact_id: Uuid::new_v4(),
                        session_id: parent_id,
                        event_seq: event_seq + 99,
                        candidate: TextArtifactCandidate {
                            relation: TextArtifactRelation::SourceUserInput,
                            projection_slot: None,
                            kind: TextArtifactKind::UserInputSource,
                            capture_reason: CaptureReason::OversizedUserInput,
                            content: failed_import_source.clone(),
                            host_captured_bytes: failed_import_source.len(),
                            host_original_bytes: failed_import_source.len(),
                            host_dropped_bytes: 0,
                            stored_source_bytes: failed_import_source.len(),
                            provenance_json: "{}".to_owned(),
                            created_at: 40_002,
                        },
                        representation: TextArtifactRepresentation::ExportRedacted,
                    }],
                    Some(failed_import),
                )
            })
            .await
            .is_err(),
            "a bad import graph must not leave a partial artifact/import row"
        );
        assert_eq!(db.list_text_artifacts(parent_id).await.unwrap(), before);
    }
}
