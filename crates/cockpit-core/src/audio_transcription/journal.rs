//! Transcription handoff through the external-side-effect journal.
//!
//! The journal is the sole authority for the
//! `prepared → dispatching → terminal` matrix. This module records `prepared`
//! before any provider byte is sent, treats a journal terminal as
//! authoritative (a `completed_after_cancel` discards content), and fails
//! closed on any journal error. Cancel that wins before the `dispatching`
//! commit produces zero provider calls; cancel after that commit still
//! attempts the send (the dispatching fact is already durable) and then
//! records `completed_after_cancel` so the body never reaches history.

use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use super::dispatch::{TranscriptionEgressTransport, dispatch_multipart};
use super::request::PlannedMultipart;
use crate::external_journal::projection::{Digest, OperationBody, SafeToken, SanitizedProjection};
use crate::external_journal::{DispatchTicket, ExternalJournal, ExternalJournalError};
use cockpit_db::external_journal::{ExternalJournalRecord, ExternalJournalState};

/// Terminal handoff of one journaled transcription dispatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TranscriptionHandoff {
    /// Provider returned a 2xx body and the journal recorded `succeeded`.
    Succeeded { operation_id: Uuid, body: Vec<u8> },
    /// Cancel won before any provider byte was sent. Journal is `cancelled`.
    Cancelled { operation_id: Uuid },
    /// Provider completed after cancellation. Content is discarded.
    CompletedAfterCancel { operation_id: Uuid },
    /// The idempotency identity already completed, but provider content is not
    /// retained by the side-effect journal and therefore cannot be replayed.
    AlreadyCompleted { operation_id: Uuid },
    /// Provider/transport failed after `dispatching`. Journal is terminal
    /// `rejected` or `failed`. The reason is redacted and secret-free.
    Failed { operation_id: Uuid, reason: String },
}

impl TranscriptionHandoff {
    pub fn operation_id(&self) -> Uuid {
        match self {
            Self::Succeeded { operation_id, .. }
            | Self::Cancelled { operation_id }
            | Self::CompletedAfterCancel { operation_id }
            | Self::AlreadyCompleted { operation_id }
            | Self::Failed { operation_id, .. } => *operation_id,
        }
    }

    /// Body bytes only on a journal-authoritative `succeeded`. A
    /// `completed_after_cancel` never carries content.
    pub fn body(&self) -> Option<&[u8]> {
        match self {
            Self::Succeeded { body, .. } => Some(body),
            Self::Cancelled { .. }
            | Self::CompletedAfterCancel { .. }
            | Self::AlreadyCompleted { .. }
            | Self::Failed { .. } => None,
        }
    }
}

/// A `prepared` transcription record. Holding one is not permission to send;
/// only [`dispatch_prepared`] after a successful `begin_dispatch` may contact a
/// provider.
#[derive(Debug, Clone)]
pub struct PreparedTranscription {
    pub operation_id: Uuid,
    pub record: ExternalJournalRecord,
    projection: SanitizedProjection,
}

/// Bind a transcription source into a sanitized journal projection.
pub fn transcription_projection(source_digest: Digest, duration_ms: u64) -> SanitizedProjection {
    SanitizedProjection::new(OperationBody::Transcription {
        source_digest,
        duration_ms,
    })
}

/// Commit `prepared` for one transcription. Idempotent on
/// `(kind, owner, idempotency_key)`: a replay of the same digest identity
/// returns the existing row.
pub async fn prepare_transcription(
    journal: &ExternalJournal,
    owner_session_id: &SafeToken,
    idempotency_key: &SafeToken,
    source_digest: Digest,
    duration_ms: u64,
    now_wall_ms: i64,
) -> Result<PreparedTranscription, ExternalJournalError> {
    let projection = transcription_projection(source_digest, duration_ms);
    let record = journal
        .prepare(owner_session_id, idempotency_key, &projection, now_wall_ms)
        .await?;
    if record.state == ExternalJournalState::Cancelled
        || record.state == ExternalJournalState::CompletedAfterCancel
    {
        // A replay of a terminal cancel is still that terminal; callers must
        // not treat it as a fresh prepared admit.
        return Ok(PreparedTranscription {
            operation_id: record.operation_id,
            record,
            projection,
        });
    }
    if record.state != ExternalJournalState::Prepared && !record.state.is_terminal() {
        return Err(ExternalJournalError::State(format!(
            "transcription prepare returned {}",
            record.state.as_str()
        )));
    }
    Ok(PreparedTranscription {
        operation_id: record.operation_id,
        record,
        projection,
    })
}

/// Run the full prepared → dispatching → terminal matrix for one
/// transcription.
///
/// `already_cancelled` is the caller's view of a cancel token at entry. The
/// journal remains the authority: a racing `request_cancellation` is
/// observed through journal state, not through this flag alone.
pub async fn dispatch_prepared(
    journal: &ExternalJournal,
    prepared: &PreparedTranscription,
    now_wall_ms: i64,
    audio: &[u8],
    boundaries: &mut (dyn Iterator<Item = u128> + Send),
    build: impl Fn(&str) -> Result<PlannedMultipart>,
    transport: &dyn TranscriptionEgressTransport,
    cancel: &CancellationToken,
) -> Result<TranscriptionHandoff, ExternalJournalError> {
    let operation_id = prepared.operation_id;

    if cancel.is_cancelled() || prepared.record.state == ExternalJournalState::Cancelled {
        let record = cancel_or_load(journal, operation_id, now_wall_ms).await?;
        return Ok(handoff_from_terminal(record, None));
    }

    if prepared.record.state.is_terminal() {
        return Ok(handoff_from_terminal(prepared.record.clone(), None));
    }

    let mut ticket = match journal
        .begin_dispatch(operation_id, &prepared.projection, now_wall_ms)
        .await
    {
        Ok(ticket) => ticket,
        Err(error) => {
            return Ok(dispatch_begin_failed(journal, operation_id, now_wall_ms, error).await?);
        }
    };

    // `dispatching` is durable. The send must proceed even if a cancel races
    // now — recovery would otherwise be left with an unresolved dispatching
    // fact. The terminal after send is `completed_after_cancel` when cancel
    // won, and the body is discarded.
    let mut send_fut = Box::pin(dispatch_multipart(audio, boundaries, build, transport));
    let send = tokio::select! {
        biased;
        result = &mut send_fut => result,
        () = cancel.cancelled() => {
            // Never let a failed cancellation write drop an in-flight send:
            // `dispatching` is already durable and its outcome must still be
            // recorded. The fallback uses the ticket's preallocated capsule
            // when SQLite is unavailable.
            let _ = record_cancellation_after_dispatch(journal, &mut ticket, now_wall_ms).await;
            send_fut.await
        }
    };
    finish_after_send(journal, &mut ticket, send, now_wall_ms, cancel).await
}

/// Persist cancellation after `dispatching` without making a journal outage an
/// excuse to abandon a known provider outcome. `record_outcome` carries the
/// same spool fallback and global fail-closed latch as ordinary outcomes.
async fn record_cancellation_after_dispatch(
    journal: &ExternalJournal,
    ticket: &mut DispatchTicket,
    now_wall_ms: i64,
) -> Result<(), ExternalJournalError> {
    match journal
        .request_cancellation(ticket.operation_id, now_wall_ms)
        .await
    {
        Ok(_) => {
            ticket.note_cancellation_requested();
            Ok(())
        }
        Err(request_error) => journal
            .record_outcome(
                ticket,
                ExternalJournalState::CancellationRequested,
                now_wall_ms,
            )
            .await
            .map(|_| ())
            .map_err(|fallback_error| {
                tracing::error!(
                    operation_id = %ticket.operation_id,
                    cancellation_error = %request_error,
                    fallback_error = %fallback_error,
                    "transcription cancellation could not be made durable before outcome recording"
                );
                fallback_error
            }),
    }
}

async fn cancel_or_load(
    journal: &ExternalJournal,
    operation_id: Uuid,
    now_wall_ms: i64,
) -> Result<ExternalJournalRecord, ExternalJournalError> {
    match journal
        .request_cancellation(operation_id, now_wall_ms)
        .await
    {
        Ok(record) => Ok(record),
        Err(error) => {
            if let Ok(Some(record)) = journal.get(operation_id).await {
                return Ok(record);
            }
            Err(error)
        }
    }
}

async fn dispatch_begin_failed(
    journal: &ExternalJournal,
    operation_id: Uuid,
    now_wall_ms: i64,
    error: ExternalJournalError,
) -> Result<TranscriptionHandoff, ExternalJournalError> {
    let Some(record) = journal.get(operation_id).await? else {
        return Err(error);
    };
    if record.state == ExternalJournalState::Cancelled
        || record.state == ExternalJournalState::Expired
        || record.is_cancellation_requested()
    {
        let record = cancel_or_load(journal, operation_id, now_wall_ms).await?;
        return Ok(handoff_from_terminal(record, None));
    }
    if record.state.is_terminal() {
        return Ok(handoff_from_terminal(record, None));
    }
    Err(error)
}

async fn finish_after_send(
    journal: &ExternalJournal,
    ticket: &mut DispatchTicket,
    send: Result<super::dispatch::TranscriptionHttpResponse, anyhow::Error>,
    now_wall_ms: i64,
    cancel: &CancellationToken,
) -> Result<TranscriptionHandoff, ExternalJournalError> {
    let operation_id = ticket.operation_id;
    // Cancellation can arrive after the multipart future resolves but before
    // its accepted/terminal facts are committed. Record it first when
    // possible; a failed write is deliberately retried below, after the
    // provider outcome is known.
    let mut cancellation_observed = cancel.is_cancelled();
    if cancellation_observed {
        let _ = record_cancellation_after_dispatch(journal, ticket, now_wall_ms).await;
    }
    match send {
        Ok(response) => {
            let accepted = journal
                .record_outcome(ticket, ExternalJournalState::Accepted, now_wall_ms)
                .await;
            if cancel.is_cancelled() {
                cancellation_observed = true;
                let _ = record_cancellation_after_dispatch(journal, ticket, now_wall_ms).await;
            }
            // Do not return after a failed accepted write: an already-known
            // provider completion must still get its terminal attempt (or the
            // journal's fail-closed unresolved-fact latch).
            // The DB outcome transaction is the linearization boundary. It
            // atomically retargets `succeeded` to `completed_after_cancel` if
            // cancellation committed first, including a cancel arriving
            // after the last in-memory token sample.
            let completed = journal
                .record_outcome(ticket, ExternalJournalState::Succeeded, now_wall_ms)
                .await;
            accepted?;
            completed?;
            Ok(match ticket.state() {
                ExternalJournalState::Succeeded => TranscriptionHandoff::Succeeded {
                    operation_id,
                    body: response.body,
                },
                ExternalJournalState::CompletedAfterCancel => {
                    TranscriptionHandoff::CompletedAfterCancel { operation_id }
                }
                other => TranscriptionHandoff::Failed {
                    operation_id,
                    reason: format!(
                        "transcription_unavailable: unexpected journal terminal {}",
                        other.as_str()
                    ),
                },
            })
        }
        Err(error) => {
            let reason = error.to_string();
            let egress = error.downcast_ref::<super::dispatch::TranscriptionEgressError>();
            let ambiguous = egress.is_some_and(|error| {
                matches!(
                    error,
                    super::dispatch::TranscriptionEgressError::Timeout
                        | super::dispatch::TranscriptionEgressError::AmbiguousAcceptance
                )
            });
            let post_dispatch_failure = egress.is_some_and(|error| {
                matches!(
                    error,
                    super::dispatch::TranscriptionEgressError::Status { .. }
                )
            });
            if ambiguous {
                journal
                    .record_outcome(ticket, ExternalJournalState::SubmissionUnknown, now_wall_ms)
                    .await?;
                return Ok(TranscriptionHandoff::Failed {
                    operation_id,
                    reason,
                });
            }
            // `failed` is not a legal successor of `dispatching`. A definitive
            // provider HTTP error still has to reach a terminal, so it takes
            // the same accepted bridge as a 2xx body, then `failed`.
            if post_dispatch_failure {
                journal
                    .record_outcome(ticket, ExternalJournalState::Accepted, now_wall_ms)
                    .await?;
                if cancel.is_cancelled() {
                    record_cancellation_after_dispatch(journal, ticket, now_wall_ms).await?;
                }
                journal
                    .record_outcome(ticket, ExternalJournalState::Failed, now_wall_ms)
                    .await?;
                return Ok(TranscriptionHandoff::Failed {
                    operation_id,
                    reason,
                });
            }
            if cancellation_observed
                || ticket.state() == ExternalJournalState::CancellationRequested
                || matches!(journal.get(operation_id).await, Ok(Some(record)) if record.is_cancellation_requested())
            {
                record_cancellation_after_dispatch(journal, ticket, now_wall_ms).await?;
                journal
                    .record_outcome(ticket, ExternalJournalState::Failed, now_wall_ms)
                    .await?;
                return Ok(TranscriptionHandoff::Failed {
                    operation_id,
                    reason,
                });
            }
            journal
                .record_outcome(ticket, ExternalJournalState::Rejected, now_wall_ms)
                .await?;
            Ok(TranscriptionHandoff::Failed {
                operation_id,
                reason,
            })
        }
    }
}

fn handoff_from_terminal(
    record: ExternalJournalRecord,
    body: Option<Vec<u8>>,
) -> TranscriptionHandoff {
    match record.state {
        ExternalJournalState::Succeeded => match body {
            Some(body) => TranscriptionHandoff::Succeeded {
                operation_id: record.operation_id,
                body,
            },
            None => TranscriptionHandoff::AlreadyCompleted {
                operation_id: record.operation_id,
            },
        },
        ExternalJournalState::CompletedAfterCancel => TranscriptionHandoff::CompletedAfterCancel {
            operation_id: record.operation_id,
        },
        ExternalJournalState::Cancelled | ExternalJournalState::Expired => {
            TranscriptionHandoff::Cancelled {
                operation_id: record.operation_id,
            }
        }
        _ => TranscriptionHandoff::Failed {
            operation_id: record.operation_id,
            reason: format!(
                "transcription_unavailable: journal is {}",
                record.state.as_str()
            ),
        },
    }
}

/// Destination identity bound into authorization and the journaled dispatch.
#[derive(Debug, Clone)]
pub struct TranscriptionDestinationIdentity {
    pub provider_id: String,
    pub origin: String,
    pub resolved_location: String,
    pub credential_fingerprint: super::authorization::CredentialFingerprintDigest,
    pub endpoint_config_generation: u64,
}

/// Production (and test) binding of journal + injectable transport.
pub struct TranscriptionDispatchService {
    journal: Arc<ExternalJournal>,
    transport: Arc<dyn TranscriptionEgressTransport>,
    identity: TranscriptionDestinationIdentity,
}

impl TranscriptionDispatchService {
    /// Test-only injection seam. Production construction must use
    /// [`Self::from_http_transport`] so endpoint identity and transport target
    /// come from one vetted object.
    #[cfg(test)]
    pub fn new(
        journal: Arc<ExternalJournal>,
        transport: Arc<dyn TranscriptionEgressTransport>,
        identity: TranscriptionDestinationIdentity,
    ) -> Self {
        Self {
            journal,
            transport,
            identity,
        }
    }

    pub(crate) fn from_http_transport(
        journal: Arc<ExternalJournal>,
        egress: super::transport::VettedTranscriptionEgress,
    ) -> Self {
        let (transport, identity) = egress.into_parts();
        Self {
            journal,
            transport: Arc::new(transport),
            identity,
        }
    }

    pub fn journal(&self) -> &ExternalJournal {
        &self.journal
    }

    #[cfg(test)]
    pub(crate) fn transport(&self) -> &dyn TranscriptionEgressTransport {
        self.transport.as_ref()
    }

    pub fn identity(&self) -> &TranscriptionDestinationIdentity {
        &self.identity
    }

    /// Prepare, dispatch, and finish one transcription through the journal.
    #[cfg(test)]
    pub(crate) async fn dispatch(
        &self,
        owner_session_id: &SafeToken,
        idempotency_key: &SafeToken,
        source_digest: Digest,
        duration_ms: u64,
        now_wall_ms: i64,
        audio: &[u8],
        boundaries: &mut (dyn Iterator<Item = u128> + Send),
        build: impl Fn(&str) -> Result<PlannedMultipart>,
        cancel: &CancellationToken,
    ) -> Result<TranscriptionHandoff, ExternalJournalError> {
        let prepared = prepare_transcription(
            &self.journal,
            owner_session_id,
            idempotency_key,
            source_digest,
            duration_ms,
            now_wall_ms,
        )
        .await?;
        dispatch_prepared(
            &self.journal,
            &prepared,
            now_wall_ms,
            audio,
            boundaries,
            build,
            self.transport.as_ref(),
            cancel,
        )
        .await
    }

    /// Dispatch with durable media-budget admission. The ledger's atomic
    /// handoff is the sole source of the dispatch ticket, so no provider byte
    /// can be sent without charging the outbound/global and
    /// transcription/session dimensions against the same journal operation.
    pub async fn dispatch_reserved(
        &self,
        ledger: &crate::media_reservation::MediaReservationLedger,
        reservation: crate::media_reservation::ReservationReceipt,
        handoff_plans: Vec<cockpit_config::config::media_budget::MediaReservationPlan>,
        owner_session_id: &SafeToken,
        idempotency_key: &SafeToken,
        source_digest: Digest,
        duration_ms: u64,
        now_wall_ms: i64,
        audio: &[u8],
        boundaries: &mut (dyn Iterator<Item = u128> + Send),
        build: impl Fn(&str) -> Result<PlannedMultipart>,
        cancel: &CancellationToken,
    ) -> Result<TranscriptionHandoff> {
        let wall_ms = u64::try_from(now_wall_ms)?;
        let projection = transcription_projection(source_digest, duration_ms);
        let existing = self
            .journal
            .operation_by_identity(owner_session_id, idempotency_key, &projection)
            .await?;
        if cancel.is_cancelled() {
            ledger
                .request_cancellation(&reservation.reservation_id, reservation.version, wall_ms)
                .await?;
            return Ok(TranscriptionHandoff::Cancelled {
                operation_id: existing
                    .as_ref()
                    .map(|record| record.operation_id)
                    .unwrap_or(Uuid::nil()),
            });
        }
        // A terminal idempotency replay has no provider body to replay and no
        // accounting transition to repeat. A non-terminal identity is an
        // in-flight (or abandoned-but-still-finishing) send: starting a second
        // ticket would race the live `settle_verified` / outcome writer.
        if let Some(replay) = existing {
            if replay.state.is_terminal() {
                return Ok(handoff_from_terminal(replay, None));
            }
            return Ok(TranscriptionHandoff::Failed {
                operation_id: replay.operation_id,
                reason: format!(
                    "transcription_unavailable: journal is {}",
                    replay.state.as_str()
                ),
            });
        }
        let mut handoff_fut = Box::pin(ledger.prepare_external_handoff(
            &self.journal,
            crate::media_reservation::MediaExternalHandoffRequest {
                reservation_id: &reservation.reservation_id,
                expected_version: reservation.version,
                owner_session_id,
                idempotency_key,
                projection: &projection,
                handoff_plans,
                wall_ms,
            },
        ));
        let handoff_result = tokio::select! {
            biased;
            result = &mut handoff_fut => result,
            () = cancel.cancelled() => {
                match ledger.request_cancellation(&reservation.reservation_id, reservation.version, wall_ms).await {
                    Ok(_) => {
                        // Cancellation committed first. The still-live handoff
                        // future observes the version/state change and cannot
                        // manufacture a dispatch ticket.
                        let _ = handoff_fut.await;
                        let operation_id = self
                            .journal
                            .operation_by_identity(owner_session_id, idempotency_key, &projection)
                            .await?
                            .map(|record| record.operation_id)
                            .unwrap_or(Uuid::nil());
                        return Ok(TranscriptionHandoff::Cancelled { operation_id });
                    }
                    Err(crate::media_reservation::LedgerError::StaleVersion | crate::media_reservation::LedgerError::InvalidTransition) => {
                        // The atomic handoff transaction committed first; its
                        // dispatching fact must now be sent and finished.
                        handoff_fut.await
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        };
        let handoff = match handoff_result {
            Ok(handoff) => handoff,
            Err(error) => {
                // No ticket escaped, hence no provider call is possible. Undo
                // the queued admission so retryable pre-handoff failures do
                // not strand queue capacity. A stale version means the atomic
                // transaction committed without returning a ticket (capsule
                // materialize failed after SQLite); recovery converts leftover
                // `dispatching` and must not be raced with a second cancel.
                let cleanup = ledger
                    .request_cancellation(&reservation.reservation_id, reservation.version, wall_ms)
                    .await;
                return match cleanup {
                    Ok(_) => Err(error.into()),
                    Err(
                        crate::media_reservation::LedgerError::StaleVersion
                        | crate::media_reservation::LedgerError::InvalidTransition,
                    ) => Err(error.into()),
                    Err(cleanup_error) => Err(anyhow::anyhow!(
                        "media handoff failed ({error}); reservation cleanup failed ({cleanup_error})"
                    )),
                };
            }
        };
        let mut ticket = handoff.dispatch;
        // Once dispatching is durable, complete the send even if cancellation
        // races; `finish_after_send` atomically chooses the content-discarding
        // terminal at the journal boundary.
        let mut send_fut = Box::pin(dispatch_multipart(
            audio,
            boundaries,
            build,
            self.transport.as_ref(),
        ));
        let send = tokio::select! {
            biased;
            result = &mut send_fut => result,
            () = cancel.cancelled() => {
                let _ = record_cancellation_after_dispatch(&self.journal, &mut ticket, now_wall_ms).await;
                send_fut.await
            }
        };
        let result =
            finish_after_send(&self.journal, &mut ticket, send, now_wall_ms, cancel).await?;
        // Release the global outbound slot only when the journal is actually
        // terminal. `submission_unknown` is not terminal: the outbound charge
        // stays held and the reservation moves to `external_pending`.
        if ticket.state().is_terminal() {
            ledger
                .settle_verified(
                    &handoff.reservation.reservation_id,
                    handoff.reservation.version,
                    vec![
                        cockpit_config::config::media_budget::MediaDimension::OutboundSubmissionsGlobal,
                    ],
                    wall_ms,
                )
                .await?;
        } else if ticket.state() == ExternalJournalState::SubmissionUnknown {
            ledger
                .finish_external_handoff(
                    &handoff.reservation.reservation_id,
                    handoff.reservation.version,
                    &ticket.operation_id.to_string(),
                    crate::media_reservation::MediaExternalHandoffOutcome::SubmissionUnknown,
                )
                .await?;
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audio_transcription::dispatch::{
        TranscriptionEgressError, TranscriptionHttpResponse,
    };
    use crate::audio_transcription::request::plan_gpt_transcribe;
    use crate::external_journal::ExternalJournal;
    use crate::media_reservation::{
        MediaOwner, MediaReservationLedger, MonotonicClock, ReserveRequest,
    };
    use async_trait::async_trait;
    use cockpit_config::config::media_budget::{
        MediaDimension, MediaEvaluationRequest, MediaReservationPlan, MediaResourcePolicy,
    };
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    const T0: i64 = 1_700_000_000_000;
    const OK_BODY: &[u8] = br#"{"text":"hi","languages":[]}"#;

    struct CountingTransport {
        sends: AtomicUsize,
        response: Mutex<std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError>>,
    }

    impl CountingTransport {
        fn ok() -> Self {
            Self {
                sends: AtomicUsize::new(0),
                response: Mutex::new(Ok(TranscriptionHttpResponse {
                    status: 200,
                    body: OK_BODY.to_vec(),
                })),
            }
        }

        fn send_count(&self) -> usize {
            self.sends.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl TranscriptionEgressTransport for CountingTransport {
        async fn post_multipart(
            &self,
            _boundary: &str,
            _body: Vec<u8>,
        ) -> std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            self.response.lock().unwrap().clone()
        }
    }

    fn owner() -> SafeToken {
        SafeToken::parse("session-owner").expect("valid owner")
    }

    fn key(value: &str) -> SafeToken {
        SafeToken::parse(value).expect("valid key")
    }

    fn env_journal() -> (tempfile::TempDir, ExternalJournal) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db = cockpit_db::Db::open(&tmp.path().join("journal.db")).expect("db");
        let journal = ExternalJournal::for_test_at(db, &tmp.path().join("spool"));
        (tmp, journal)
    }

    fn build_plan(file_bytes: u64) -> impl Fn(&str) -> Result<PlannedMultipart> {
        move |boundary: &str| plan_gpt_transcribe(file_bytes, None, &[], &[], boundary)
    }

    fn source_digest() -> Digest {
        Digest::of(b"audio-bytes")
    }

    fn cancellation(cancelled: bool) -> CancellationToken {
        let token = CancellationToken::new();
        if cancelled {
            token.cancel();
        }
        token
    }

    async fn prepare_one(journal: &ExternalJournal, idem: &str) -> PreparedTranscription {
        prepare_transcription(journal, &owner(), &key(idem), source_digest(), 1_000, T0)
            .await
            .expect("prepare")
    }

    #[tokio::test]
    async fn transcription_cancel_before_admit_zero_send() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "cancel-before-admit").await;
        let cancelled = journal
            .request_cancellation(prepared.operation_id, T0 + 1)
            .await
            .expect("cancel");
        assert_eq!(cancelled.state, ExternalJournalState::Cancelled);

        let transport = CountingTransport::ok();
        let mut boundaries = [1u128].into_iter();
        let audio = b"audio";
        let handoff = dispatch_prepared(
            &journal,
            &prepared,
            T0 + 2,
            audio,
            &mut boundaries,
            build_plan(audio.len() as u64),
            &transport,
            &cancellation(true),
        )
        .await
        .expect("handoff");
        assert!(matches!(handoff, TranscriptionHandoff::Cancelled { .. }));
        assert!(handoff.body().is_none());
        assert_eq!(transport.send_count(), 0);
        let loaded = journal.get(prepared.operation_id).await.unwrap().unwrap();
        assert_eq!(loaded.state, ExternalJournalState::Cancelled);
    }

    #[tokio::test]
    async fn transcription_cancel_vs_dispatch_zero_send() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "cancel-vs-dispatch").await;
        let gate = journal.install_dispatch_gate();
        let transport = Arc::new(CountingTransport::ok());
        let journal = Arc::new(journal);
        let prepared_clone = prepared.clone();
        let journal_for_task = journal.clone();
        let transport_for_task = transport.clone();
        let task = tokio::spawn(async move {
            let audio = b"audio";
            let mut boundaries = [1u128].into_iter();
            dispatch_prepared(
                &journal_for_task,
                &prepared_clone,
                T0 + 2,
                audio,
                &mut boundaries,
                build_plan(audio.len() as u64),
                transport_for_task.as_ref(),
                &cancellation(false),
            )
            .await
        });
        gate.wait_until_reached().await;
        let cancelled = journal
            .request_cancellation(prepared.operation_id, T0 + 1)
            .await
            .expect("cancel while parked in begin_dispatch");
        assert_eq!(cancelled.state, ExternalJournalState::Cancelled);
        gate.release();
        let handoff = task.await.expect("join").expect("handoff");
        assert!(matches!(handoff, TranscriptionHandoff::Cancelled { .. }));
        assert_eq!(transport.send_count(), 0);
    }

    #[tokio::test]
    async fn transcription_cancel_completed_after_cancel_discards_content() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "completed-after-cancel").await;
        let mut ticket = journal
            .begin_dispatch(prepared.operation_id, &prepared.projection, T0 + 1)
            .await
            .expect("dispatching");
        let cancelled = journal
            .request_cancellation(prepared.operation_id, T0 + 2)
            .await
            .expect("cancel after dispatching");
        assert_eq!(cancelled.state, ExternalJournalState::CancellationRequested);

        let transport = CountingTransport::ok();
        let audio = b"audio";
        let mut boundaries = [1u128].into_iter();
        let send = dispatch_multipart(
            audio,
            &mut boundaries,
            build_plan(audio.len() as u64),
            &transport,
        )
        .await;
        let cancel = cancellation(false);
        let handoff = finish_after_send(&journal, &mut ticket, send, T0 + 3, &cancel)
            .await
            .expect("finish");
        assert!(matches!(
            handoff,
            TranscriptionHandoff::CompletedAfterCancel { .. }
        ));
        assert!(handoff.body().is_none());
        assert_eq!(transport.send_count(), 1);
        let loaded = journal.get(prepared.operation_id).await.unwrap().unwrap();
        assert_eq!(loaded.state, ExternalJournalState::CompletedAfterCancel);
    }

    #[tokio::test]
    async fn cancellation_write_failure_uses_ticket_fallback_before_terminal_outcome() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "cancellation-write-fallback").await;
        let mut ticket = journal
            .begin_dispatch(prepared.operation_id, &prepared.projection, T0 + 1)
            .await
            .expect("dispatching");
        journal.set_db_faults(crate::external_journal::DbFaults {
            fail_cancellation_commit: true,
            ..crate::external_journal::DbFaults::default()
        });

        record_cancellation_after_dispatch(&journal, &mut ticket, T0 + 2)
            .await
            .expect("ticket-backed cancellation fallback");

        assert_eq!(ticket.state(), ExternalJournalState::CancellationRequested);
        journal.set_db_faults(crate::external_journal::DbFaults::default());
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Accepted, T0 + 3)
            .await
            .expect("accepted after cancellation");
        journal
            .record_outcome(&mut ticket, ExternalJournalState::Succeeded, T0 + 4)
            .await
            .expect("terminal after cancellation");
        assert_eq!(ticket.state(), ExternalJournalState::CompletedAfterCancel);
    }

    #[tokio::test]
    async fn transcription_cancel_invalid_after_cancel() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "invalid-after-cancel").await;
        journal
            .request_cancellation(prepared.operation_id, T0 + 1)
            .await
            .expect("cancel");
        let transport = CountingTransport::ok();
        let audio = b"audio";
        let mut boundaries = [1u128].into_iter();
        let err = journal
            .begin_dispatch(prepared.operation_id, &prepared.projection, T0 + 2)
            .await
            .expect_err("dispatch after cancel is invalid");
        assert!(
            err.to_string().contains("cancelled") || err.to_string().contains("cannot begin"),
            "unexpected begin_dispatch error: {err}"
        );
        let handoff = dispatch_prepared(
            &journal,
            &prepared,
            T0 + 3,
            audio,
            &mut boundaries,
            build_plan(audio.len() as u64),
            &transport,
            &cancellation(false),
        )
        .await
        .expect("handoff maps invalid-after-cancel");
        assert!(matches!(handoff, TranscriptionHandoff::Cancelled { .. }));
        assert_eq!(transport.send_count(), 0);
    }

    #[tokio::test]
    async fn transcription_cancel_already_completed() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "already-completed").await;
        let transport = CountingTransport::ok();
        let audio = b"audio";
        let mut boundaries = [1u128].into_iter();
        let handoff = dispatch_prepared(
            &journal,
            &prepared,
            T0 + 1,
            audio,
            &mut boundaries,
            build_plan(audio.len() as u64),
            &transport,
            &cancellation(false),
        )
        .await
        .expect("success");
        assert!(matches!(handoff, TranscriptionHandoff::Succeeded { .. }));
        assert_eq!(handoff.body(), Some(OK_BODY.as_ref()));
        assert_eq!(transport.send_count(), 1);

        let after = journal
            .request_cancellation(prepared.operation_id, T0 + 2)
            .await
            .expect("cancel after succeeded is a duplicate");
        assert_eq!(after.state, ExternalJournalState::Succeeded);
        let replay = dispatch_prepared(
            &journal,
            &prepared,
            T0 + 3,
            audio,
            &mut [2u128].into_iter(),
            build_plan(audio.len() as u64),
            &transport,
            &cancellation(false),
        )
        .await
        .expect("replay of completed");
        assert!(matches!(
            replay,
            TranscriptionHandoff::AlreadyCompleted { .. }
        ));
        assert_eq!(
            transport.send_count(),
            1,
            "already_completed must not resend"
        );
    }

    #[tokio::test]
    async fn transcription_cancel_replay_digest_reuses_prepared_row() {
        let (_tmp, journal) = env_journal();
        let first = prepare_one(&journal, "replay-digest").await;
        let second = prepare_one(&journal, "replay-digest").await;
        assert_eq!(first.operation_id, second.operation_id);
        assert_eq!(first.record.payload_digest, second.record.payload_digest);
        assert_eq!(first.record.state, ExternalJournalState::Prepared);
        assert_eq!(second.record.state, ExternalJournalState::Prepared);
    }

    #[tokio::test]
    async fn transcription_provider_status_after_dispatch_is_failed_not_rejected() {
        let (_tmp, journal) = env_journal();
        let prepared = prepare_one(&journal, "provider-status-failed").await;
        let transport = CountingTransport {
            sends: AtomicUsize::new(0),
            response: Mutex::new(Ok(TranscriptionHttpResponse {
                status: 429,
                body: Vec::new(),
            })),
        };
        let audio = b"audio";
        let handoff = dispatch_prepared(
            &journal,
            &prepared,
            T0 + 1,
            audio,
            &mut [1u128].into_iter(),
            build_plan(audio.len() as u64),
            &transport,
            &cancellation(false),
        )
        .await
        .expect("failed handoff");
        assert!(matches!(handoff, TranscriptionHandoff::Failed { .. }));
        assert_eq!(transport.send_count(), 1);
        assert_eq!(
            journal
                .get(prepared.operation_id)
                .await
                .unwrap()
                .unwrap()
                .state,
            ExternalJournalState::Failed
        );
    }

    struct TestClock;
    impl MonotonicClock for TestClock {
        fn now_ms(&self) -> u64 {
            1
        }
    }

    fn media_plan(dimension: MediaDimension, requested: u64) -> MediaReservationPlan {
        MediaResourcePolicy::default()
            .evaluate(MediaEvaluationRequest {
                dimension,
                requested: Some(requested),
                current_scope: 0,
                profile: None,
                adapter_limit: None,
                request_limit: None,
            })
            .unwrap()
    }

    fn reserved_stack(
        transport: Arc<dyn TranscriptionEgressTransport>,
    ) -> (
        tempfile::TempDir,
        TranscriptionDispatchService,
        MediaReservationLedger,
        cockpit_db::Db,
    ) {
        let tmp = tempfile::TempDir::new().expect("tempdir");
        let db = cockpit_db::Db::open(&tmp.path().join("journal.db")).expect("db");
        let journal = ExternalJournal::for_test_at(db.clone(), &tmp.path().join("spool"));
        let ledger = MediaReservationLedger::new(db.clone(), Arc::new(TestClock));
        let service = TranscriptionDispatchService::new(
            Arc::new(journal),
            transport,
            TranscriptionDestinationIdentity {
                provider_id: "openai".into(),
                origin: "https://api.openai.com".into(),
                resolved_location: "public_network".into(),
                credential_fingerprint:
                    crate::audio_transcription::authorization::CredentialFingerprintDigest::from_raw_for_test(
                        "aa".repeat(32),
                    ),
                endpoint_config_generation: 1,
            },
        );
        (tmp, service, ledger, db)
    }

    async fn reserve_transcription(
        ledger: &MediaReservationLedger,
        id: &str,
    ) -> (
        crate::media_reservation::ReservationReceipt,
        Vec<MediaReservationPlan>,
    ) {
        let outbound = media_plan(MediaDimension::OutboundSubmissionsGlobal, 1);
        let invocation = media_plan(MediaDimension::TranscriptionInvocationsPerSession, 1);
        let deadline = media_plan(MediaDimension::OperationDeadlineSeconds, 30);
        let receipt = ledger
            .reserve(ReserveRequest {
                reservation_id: id.into(),
                recovery_id: format!("recovery-{id}"),
                owner: MediaOwner {
                    project_id: "project".into(),
                    session_id: "session-owner".into(),
                },
                operation: "transcribe_audio".into(),
                purpose: "transcription".into(),
                plans: vec![outbound.clone(), invocation.clone(), deadline],
                wall_ms: 1,
            })
            .await
            .expect("reserve");
        (receipt, vec![outbound, invocation])
    }

    struct HoldTransport {
        sends: AtomicUsize,
        released: AtomicBool,
    }

    impl HoldTransport {
        fn new() -> Self {
            Self {
                sends: AtomicUsize::new(0),
                released: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl TranscriptionEgressTransport for HoldTransport {
        async fn post_multipart(
            &self,
            _boundary: &str,
            _body: Vec<u8>,
        ) -> std::result::Result<TranscriptionHttpResponse, TranscriptionEgressError> {
            self.sends.fetch_add(1, Ordering::SeqCst);
            loop {
                if self.released.load(Ordering::SeqCst) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
            Ok(TranscriptionHttpResponse {
                status: 200,
                body: OK_BODY.to_vec(),
            })
        }
    }

    #[tokio::test]
    async fn transcription_reserved_cancel_before_ticket_zero_send() {
        let transport = Arc::new(CountingTransport::ok());
        let (_tmp, service, ledger, _) = reserved_stack(transport.clone());
        let (reservation, plans) = reserve_transcription(&ledger, "cancel-before-ticket").await;
        let audio = b"audio";
        let handoff = service
            .dispatch_reserved(
                &ledger,
                reservation,
                plans,
                &owner(),
                &key("cancel-before-ticket"),
                source_digest(),
                1_000,
                T0,
                audio,
                &mut [1u128].into_iter(),
                build_plan(audio.len() as u64),
                &cancellation(true),
            )
            .await
            .expect("cancelled before ticket");
        assert!(matches!(handoff, TranscriptionHandoff::Cancelled { .. }));
        assert_eq!(transport.send_count(), 0);
        assert!(
            service
                .journal()
                .operation_by_identity(
                    &owner(),
                    &key("cancel-before-ticket"),
                    &transcription_projection(source_digest(), 1_000)
                )
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn transcription_reserved_provider_status_after_dispatch_is_failed() {
        let transport = Arc::new(CountingTransport {
            sends: AtomicUsize::new(0),
            response: Mutex::new(Ok(TranscriptionHttpResponse {
                status: 429,
                body: Vec::new(),
            })),
        });
        let (_tmp, service, ledger, db) = reserved_stack(transport.clone());
        let (reservation, plans) = reserve_transcription(&ledger, "reserved-429").await;
        let audio = b"audio";
        let handoff = service
            .dispatch_reserved(
                &ledger,
                reservation,
                plans,
                &owner(),
                &key("reserved-429"),
                source_digest(),
                1_000,
                T0,
                audio,
                &mut [1u128].into_iter(),
                build_plan(audio.len() as u64),
                &cancellation(false),
            )
            .await
            .expect("failed handoff");
        assert!(matches!(handoff, TranscriptionHandoff::Failed { .. }));
        assert_eq!(transport.send_count(), 1);
        let record = service
            .journal()
            .operation_by_identity(
                &owner(),
                &key("reserved-429"),
                &transcription_projection(source_digest(), 1_000),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, ExternalJournalState::Failed);
        let outbound = db
            .read(|connection| {
                connection.query_row(
                    "SELECT COALESCE(SUM(charged),0) FROM media_resource_counters WHERE dimension='outbound_submissions_global'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
            })
            .await
            .unwrap();
        assert_eq!(outbound, 0, "terminal failed releases the global slot");
    }

    #[tokio::test]
    async fn transcription_reserved_ambiguous_acceptance_does_not_settle_outbound() {
        let transport = Arc::new(CountingTransport {
            sends: AtomicUsize::new(0),
            response: Mutex::new(Err(TranscriptionEgressError::AmbiguousAcceptance)),
        });
        let (_tmp, service, ledger, db) = reserved_stack(transport.clone());
        let (reservation, plans) = reserve_transcription(&ledger, "reserved-unknown").await;
        let audio = b"audio";
        let handoff = service
            .dispatch_reserved(
                &ledger,
                reservation,
                plans,
                &owner(),
                &key("reserved-unknown"),
                source_digest(),
                1_000,
                T0,
                audio,
                &mut [1u128].into_iter(),
                build_plan(audio.len() as u64),
                &cancellation(false),
            )
            .await
            .expect("unknown handoff");
        match handoff {
            TranscriptionHandoff::Failed { reason, .. } => {
                assert!(
                    reason.contains("acceptance is unknown"),
                    "live path must surface the timeout/ambiguous reason, not a ledger error: {reason}"
                );
            }
            other => panic!("expected Failed handoff, got {other:?}"),
        }
        let record = service
            .journal()
            .operation_by_identity(
                &owner(),
                &key("reserved-unknown"),
                &transcription_projection(source_digest(), 1_000),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, ExternalJournalState::SubmissionUnknown);
        let (outbound, state) = db
            .read(|connection| {
                Ok((
                    connection.query_row(
                        "SELECT COALESCE(SUM(charged),0) FROM media_resource_counters WHERE dimension='outbound_submissions_global'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )?,
                    connection.query_row(
                        "SELECT state FROM media_reservations WHERE reservation_id='reserved-unknown'",
                        [],
                        |row| row.get::<_, String>(0),
                    )?,
                ))
            })
            .await
            .unwrap();
        assert_eq!(
            outbound, 1,
            "ambiguous acceptance keeps the outbound charge"
        );
        assert_eq!(state, "external_pending");
    }

    #[tokio::test]
    async fn transcription_reserved_cancel_after_ticket_discards_content() {
        let transport = Arc::new(HoldTransport::new());
        let (_tmp, service, ledger, _) = reserved_stack(transport.clone());
        let (reservation, plans) = reserve_transcription(&ledger, "reserved-cancel-send").await;
        let cancel = CancellationToken::new();
        let cancel_for_task = cancel.clone();
        let service = Arc::new(service);
        let service_for_task = service.clone();
        let task = tokio::spawn(async move {
            let audio = b"audio";
            service_for_task
                .dispatch_reserved(
                    &ledger,
                    reservation,
                    plans,
                    &owner(),
                    &key("reserved-cancel-send"),
                    source_digest(),
                    1_000,
                    T0,
                    audio,
                    &mut [1u128].into_iter(),
                    build_plan(audio.len() as u64),
                    &cancel_for_task,
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if transport.sends.load(Ordering::SeqCst) >= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("send started");
        cancel.cancel();
        transport.released.store(true, Ordering::SeqCst);
        let handoff = task.await.expect("join").expect("handoff");
        assert!(matches!(
            handoff,
            TranscriptionHandoff::CompletedAfterCancel { .. }
        ));
        assert!(handoff.body().is_none());
        let record = service
            .journal()
            .operation_by_identity(
                &owner(),
                &key("reserved-cancel-send"),
                &transcription_projection(source_digest(), 1_000),
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(record.state, ExternalJournalState::CompletedAfterCancel);
    }

    #[tokio::test]
    async fn transcription_reserved_in_flight_identity_does_not_start_second_send() {
        let transport = Arc::new(HoldTransport::new());
        let (_tmp, service, ledger, _) = reserved_stack(transport.clone());
        let (reservation, plans) = reserve_transcription(&ledger, "reserved-in-flight").await;
        let service = Arc::new(service);
        let service_for_task = service.clone();
        let ledger_for_task = ledger.clone();
        let first = tokio::spawn(async move {
            let audio = b"audio";
            service_for_task
                .dispatch_reserved(
                    &ledger_for_task,
                    reservation,
                    plans,
                    &owner(),
                    &key("reserved-in-flight"),
                    source_digest(),
                    1_000,
                    T0,
                    audio,
                    &mut [1u128].into_iter(),
                    build_plan(audio.len() as u64),
                    &cancellation(false),
                )
                .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if transport.sends.load(Ordering::SeqCst) >= 1 {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("first send started");
        let (replay_reservation, replay_plans) =
            reserve_transcription(&ledger, "reserved-in-flight").await;
        let replay = service
            .dispatch_reserved(
                &ledger,
                replay_reservation,
                replay_plans,
                &owner(),
                &key("reserved-in-flight"),
                source_digest(),
                1_000,
                T0,
                b"audio",
                &mut [2u128].into_iter(),
                build_plan(b"audio".len() as u64),
                &cancellation(false),
            )
            .await
            .expect("in-flight replay");
        match replay {
            TranscriptionHandoff::Failed { reason, .. } => {
                assert!(
                    reason.contains("dispatching"),
                    "retry of an in-flight identity must not send: {reason}"
                );
            }
            other => panic!("expected in-flight Failed, got {other:?}"),
        }
        assert_eq!(transport.sends.load(Ordering::SeqCst), 1);
        transport.released.store(true, Ordering::SeqCst);
        let first_handoff = first.await.expect("join").expect("first handoff");
        assert!(matches!(
            first_handoff,
            TranscriptionHandoff::Succeeded { .. }
        ));
    }
}
