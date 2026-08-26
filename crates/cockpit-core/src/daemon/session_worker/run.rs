use super::handle::*;
use super::helpers::*;
use super::lifecycle::*;
use super::*;
use anyhow::Context;

pub(super) const INTERRUPT_REDACTION_FAILED: &str = "[redaction failed]";

/// Poll cadence for the graceful-shutdown park-drain loop
/// (`daemon-lifecycle-replay-timing-robustness.md`, finding 2): after each
/// re-park it waits at most this long for the driver task to exit before
/// re-parking again, so a fresh interrupt the in-flight turn registers is
/// caught promptly. Bounded work; the drain path force-aborts the worker at its
/// own deadline regardless, so this never blocks shutdown indefinitely.
const PARK_DRAIN_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(10);

/// An accepted oversized source has a ten-minute DB-owned lease. Startup and
/// individual dispatches reconcile it synchronously; this bounded worker tick
/// also prevents an idle session from retaining an expired reservation until a
/// later client submission happens to arrive.
const TEXT_ARTIFACT_RESERVATION_REAP_INTERVAL: std::time::Duration =
    std::time::Duration::from_secs(60);

pub(super) fn persistent_llm_mode_control(
    mode: crate::config::extended::LlmMode,
) -> crate::engine::driver::DriverControl {
    crate::engine::driver::DriverControl::SetLlmMode {
        mode: Some(mode),
        prune_after_switch: true,
    }
}

pub(super) fn session_llm_mode_control(
    mode: crate::config::extended::LlmMode,
) -> crate::engine::driver::DriverControl {
    crate::engine::driver::DriverControl::SetLlmMode {
        mode: Some(mode),
        prune_after_switch: false,
    }
}

pub(super) fn tool_surface_override_control(
    selection: crate::agents::ToolSurfaceSelection,
    prune_after_switch: bool,
    monty_nudge: Option<String>,
) -> crate::engine::driver::DriverControl {
    crate::engine::driver::DriverControl::SetToolSurfaceOverride {
        selection,
        prune_after_switch,
        monty_nudge,
    }
}

pub(super) fn stored_session_llm_mode(
    session: &Session,
) -> Option<crate::config::extended::LlmMode> {
    let raw = session.session_llm_mode_raw()?;
    match session.session_llm_mode() {
        Some(mode) => Some(mode),
        None => {
            tracing::warn!(
                session_id = %session.id,
                mode = %raw,
                "stored session llm mode is invalid; falling back to resolved config mode"
            );
            None
        }
    }
}

pub(super) fn stored_tool_surface_override(
    session: &Session,
) -> Option<crate::agents::ToolSurfaceSelection> {
    let raw = session.tool_surface_override_json()?;
    match serde_json::from_str::<crate::agents::ToolSurfaceSelection>(&raw) {
        Ok(selection) => Some(selection),
        Err(error) => {
            tracing::warn!(
                session_id = %session.id,
                %error,
                "stored tool surface override is invalid JSON; falling back to agent definition"
            );
            None
        }
    }
}

pub(super) fn stored_goal_settings_override(
    session: &Session,
) -> Option<crate::agents::GoalSettingsOverride> {
    let raw = session.goal_settings_override_json()?;
    match crate::agents::parse_goal_settings_override_json(&raw) {
        Ok(override_) => Some(override_),
        Err(error) => {
            tracing::warn!(
                session_id = %session.id,
                %error,
                "stored goal settings override is invalid; falling back to lower-priority defaults"
            );
            None
        }
    }
}

pub(super) struct ParkedReplayCompletion {
    interrupt_id: uuid::Uuid,
    decision: Option<proto::InterruptDecision>,
    was_active: bool,
    result: std::result::Result<crate::engine::driver::ParkedReplayOutcome, String>,
}

pub(super) fn redaction_failed_interrupt_decision_payload(
    interrupt_id: uuid::Uuid,
    decision: &crate::daemon::proto::InterruptDecision,
) -> serde_json::Value {
    let lines = decision
        .lines
        .iter()
        .map(|_| {
            serde_json::json!({
                "prompt": INTERRUPT_REDACTION_FAILED,
                "answer": INTERRUPT_REDACTION_FAILED,
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "interrupt_id": interrupt_id,
        "decision": {
            "permission": decision.permission,
            "cancelled": decision.cancelled,
            "lines": lines,
        },
    })
}

pub(super) fn record_interrupt_decision_event(
    session: &Session,
    redaction: &SharedRedactionTable,
    interrupt_id: uuid::Uuid,
    decision: &proto::InterruptDecision,
) -> Option<i64> {
    let data = serde_json::json!({
        "interrupt_id": interrupt_id,
        "decision": decision,
    });
    let scrubbed = crate::daemon::current_redaction(redaction).scrub(&data.to_string());
    let redacted_data = serde_json::from_str(&scrubbed).unwrap_or_else(|error| {
        tracing::warn!(
            %error,
            %interrupt_id,
            "interrupt decision redaction produced invalid JSON; persisting fail-closed placeholder"
        );
        redaction_failed_interrupt_decision_payload(interrupt_id, decision)
    });
    let data_json = match serde_json::to_string(&redacted_data) {
        Ok(data_json) => data_json,
        Err(error) => {
            tracing::warn!(%error, %interrupt_id, "serializing interrupt decision failed");
            return None;
        }
    };
    let session_id = session.id;
    session
        .db
        .blocking_write_for_sync_event(move |conn| {
            crate::db::Db::insert_session_event_json_conn(
                conn,
                session_id,
                crate::db::session_log::SessionEventKind::InterruptDecision,
                None,
                None,
                crate::db::session_log::SessionEventContext::default(),
                crate::db::session_log::now_ms(),
                &data_json,
            )
        })
        .map_err(|error| {
            tracing::warn!(%error, %interrupt_id, "recording interrupt decision failed");
            error
        })
        .ok()
}

pub(super) async fn finish_parked_replay_completion(
    session: &Session,
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    interrupts: &Arc<crate::engine::interrupt::InterruptHub>,
    session_id: uuid::Uuid,
    completion: ParkedReplayCompletion,
) {
    let outcome = match completion.result {
        Ok(outcome) => outcome,
        Err(error) => {
            let _ = session
                .db
                .mark_interrupt_interrupted(completion.interrupt_id)
                .await;
            tracing::warn!(
                %error,
                interrupt_id = %completion.interrupt_id,
                "parked interrupt replay failed"
            );
            send_current_session_event(
                session,
                event_tx,
                redaction,
                proto::Event::Notice {
                    session_id,
                    text: format!(
                        "Interrupted parked request {}: {error}",
                        completion.interrupt_id
                    ),
                },
                NoticeSource::DaemonDirect,
            );
            interrupts.emit_queue_state().await;
            return;
        }
    };
    if matches!(
        outcome,
        crate::engine::driver::ParkedReplayOutcome::ParkedAgain
    ) {
        tracing::debug!(
            interrupt_id = %completion.interrupt_id,
            "parked interrupt replay parked on a later prompt"
        );
    }
    if let Err(error) = session
        .db
        .complete_executing_interrupt(completion.interrupt_id)
        .await
    {
        tracing::warn!(
            %error,
            interrupt_id = %completion.interrupt_id,
            "completing parked interrupt failed"
        );
    }
    let seq = completion.decision.as_ref().and_then(|decision| {
        record_interrupt_decision_event(session, redaction, completion.interrupt_id, decision)
    });
    send_current_event(
        event_tx,
        redaction,
        proto::Event::InterruptResolved {
            session_id,
            interrupt_id: completion.interrupt_id,
            decision: completion.decision,
            seq,
        },
    );
    if matches!(
        outcome,
        crate::engine::driver::ParkedReplayOutcome::ParkedAgain
    ) {
        interrupts.emit_active_from_db().await;
        return;
    }
    if completion.was_active {
        interrupts.emit_active_from_db().await;
    } else {
        interrupts.emit_queue_state().await;
    }
}

pub(super) fn validate_parked_interrupt_payload(
    row: &crate::db::needs_attention::NeedsAttentionRow,
) -> std::result::Result<(), &'static str> {
    let Some(payload) = row.parked.as_ref() else {
        return Err("missing replay payload");
    };
    if payload.tool.trim().is_empty() {
        return Err("missing parked tool name");
    }
    if payload.call_id.trim().is_empty() {
        return Err("missing parked tool call id");
    }
    if payload.resume.agent_id != row.agent_id {
        return Err("parked replay agent does not match interrupt row");
    }
    if payload.resume.call_id != payload.call_id {
        return Err("parked replay call id does not match resume anchor");
    }
    Ok(())
}

pub(super) async fn forward_queue_updates(
    mut queue_update_rx: watch::Receiver<Vec<crate::engine::message::QueuedUserMessage>>,
    event_tx: EventSender,
    redaction: SharedRedactionTable,
    session_id: Uuid,
) {
    while queue_update_rx.changed().await.is_ok() {
        let queue = queue_update_rx.borrow_and_update().clone();
        send_current_event(
            &event_tx,
            &redaction,
            proto::Event::QueueUpdated {
                session_id,
                queue: queue.into_iter().map(queue_item_to_proto).collect(),
            },
        );
    }
}

pub(super) async fn persist_staged_terminal_removal(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    staged: crate::engine::message::StagedQueueRemoval,
    disposition: crate::db::session_log::ClientSubmissionTerminalDisposition,
) -> std::result::Result<
    (
        Vec<crate::engine::message::QueuedUserMessage>,
        Vec<crate::engine::message::QueuedUserMessage>,
        Vec<crate::engine::message::ClientSubmissionReceipt>,
    ),
    proto::ErrorPayload,
> {
    let removed = staged.removed().to_vec();
    let receipts = queue.accepted_receipts(staged.ids()).await;
    let terminal_receipts = receipts
        .iter()
        .map(
            |receipt| crate::db::session_log::ClientSubmissionTerminalReceipt {
                client_submission_id: receipt.id,
                fingerprint: receipt.fingerprint.clone(),
                wire_fingerprint: receipt.wire_fingerprint.clone(),
                origin_principal: receipt.origin_principal.clone(),
                disposition,
            },
        )
        .collect::<Vec<_>>();
    if !terminal_receipts.is_empty()
        && let Err(error) = session
            .db
            .terminalize_queued_text_artifact_submissions(
                session.id,
                terminal_receipts,
                chrono::Utc::now().timestamp_millis(),
            )
            .await
    {
        queue.mark_staged_removal_failed(&staged).await;
        tracing::warn!(
            %error,
            receipt_count = receipts.len(),
            disposition = disposition.as_str(),
            "terminal client-submission receipt write failed; exact queued payload remains held"
        );
        return Err(proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "could not durably remove queued message; its exact payload remains held and will not execute; retry the same removal"
                .to_string(),
        });
    }
    let snapshot = commit_staged_removal_after_receipts(session, queue, staged, &receipts).await;
    Ok((removed, snapshot, receipts))
}

async fn commit_staged_removal_after_receipts(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    staged: crate::engine::message::StagedQueueRemoval,
    receipts: &[crate::engine::message::ClientSubmissionReceipt],
) -> Vec<crate::engine::message::QueuedUserMessage> {
    let snapshot = queue.commit_staged_removal(staged).await;
    struct TerminalCleanupClock;
    impl crate::media_reservation::MonotonicClock for TerminalCleanupClock {
        fn now_ms(&self) -> u64 {
            0
        }
    }
    let ledger = crate::media_reservation::MediaReservationLedger::new(
        session.db.clone(),
        std::sync::Arc::new(TerminalCleanupClock),
    );
    let wall_ms = chrono::Utc::now()
        .timestamp_millis()
        .try_into()
        .unwrap_or(0);
    for receipt in receipts {
        if let Err(error) = ledger
            .complete_downstream_invocation(&receipt.id.to_string(), wall_ms)
            .await
        {
            tracing::warn!(%error,invocation=%receipt.id,"terminal queue removal left downstream media ownership retryable");
        }
    }
    snapshot
}

fn queue_removal_in_progress_error() -> proto::ErrorPayload {
    proto::ErrorPayload {
        code: proto::ErrorCode::Internal,
        message: "a previous failed queue removal remains held; retry that same removal or cancel the queued work"
            .to_string(),
    }
}

#[cfg(feature = "remote")]
pub(super) fn remote_queue_mutation_response(
    receipt: RemoteQueueMutationReceiptV1,
) -> proto::RemoveQueuedUserMessageResult {
    proto::RemoveQueuedUserMessageResult {
        applied: receipt.applied,
        reason: receipt.reason,
        removed_item: None,
        // QueueUpdated owns the mutable full queue view. Keeping it out of
        // this response makes Applied and Replay byte-identical and secret-free.
        queue: Vec::new(),
    }
}

/// Outcome of committing the transactional remote-operation ledger for an
/// authenticated remote `send_user_message`. Shared by the worker accept path
/// and the dispatch image-duplicate fast path so BOTH reserve the operation
/// through the SAME ledger primitive (no remote send returns accepted without a
/// ledger operation row).
/// Reserve+commit the transactional remote-operation ledger row for a remote
/// send. The request hash (bound to session + client_submission_id + payload in
/// dispatch) is the exactly-once key: a replayed identity returns `Replayed`
/// (no second commit), a reused identity carrying different content returns a
/// conflict, and the CALLER decides whether to enqueue based on the in-memory
/// dedup decision it already made (so a conflicting/duplicate submission never
/// double-enqueues). The closure performs no domain mutation — the ledger row
/// itself is the durable exactly-once acceptance record for the operation.
///
/// KNOWN NON-ATOMICITY (there is NO atomic durable-accept at the daemon accept
/// path yet, and this lane deliberately does NOT try to build one). Three
/// records that morally describe "this send was accepted" are committed
/// SEPARATELY, not in one transaction: for legacy inline/media sends, the
/// run-invocation MARKER (`accept_run_if_marked`, committed in the dispatch
/// arm before the worker dispatch); this transactional LEDGER row (committed
/// here on the worker accept); and the durable MESSAGE itself (written only
/// later when the driver folds it into `session_events`, post-inference).
/// Oversized FCM2 text bypasses this *legacy remote-attachment* ledger because
/// its atomic phase-one `message_operation_receipts` row is itself the durable
/// remote operation ledger (actor, operation id, keyed FCOR hash, request
/// digest, and replay-safe outcome), joined to its reservation and any bound
/// run invocation in one transaction.
/// The ledger DOES prevent a second ACCEPT and a normal-operation replay is
/// idempotent (no double-enqueue). BUT because the three are not mutually atomic,
/// a crash between any two of them leaves an inconsistent prefix: a committed
/// ledger/marker with no durable message; or (the marker predating the driver
/// notify) a run that starts before its marker is visible; and a crash after
/// inference STARTS but before the fold, followed by a client replay, re-drives
/// the enqueue and can invoke the model a SECOND time (a genuine double-EXECUTE
/// — the same exposure a LOCAL send has, which is also durable only at fold).
/// Closing all of these together requires routing acceptance through the atomic
/// `accept_message_with_attachments` (`message_operation_receipts` +
/// `message_submission_receipts` + `message_queue_items` — message + marker +
/// ledger in ONE tx, committed before the driver is notified), which needs the
/// `CanonicalSendUserMessageV2` envelope owned by the
/// `unify-media-model-and-send-user-message-v2-cutover` lane. This lane adds only
/// the ledger row; the marker is unchanged from main; the cross-record atomicity
/// is the V2 cutover's job.
#[cfg(feature = "remote")]
pub(super) async fn reserve_remote_send_operation_impl(
    db: &crate::db::Db,
    remote: &crate::daemon::session_worker::RemoteQueueOperation,
) -> crate::daemon::session_worker::RemoteSendDecision {
    use crate::daemon::session_worker::RemoteSendDecision;
    let outcome = db
        .execute_transactional_remote_operation(
            crate::db::remote_attachment_operations::ReserveRemoteOperation {
                logical_attachment_id: &remote.logical_attachment_id,
                operation_id: &remote.operation_id,
                authenticated_device_id: &remote.authenticated_device_id,
                authenticated_device_generation: remote.authenticated_device_generation,
                operation_class:
                    crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                request_hash: remote.request_hash,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            move |_conn| {
                let safe_response = serde_json::to_vec(&serde_json::json!({
                    "schema_version": 1,
                    "kind": "send_user_message_accept",
                }))?;
                Ok(
                    crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                        value: (),
                        safe_response: safe_response.clone(),
                        outbox_kind: "send_user_message".into(),
                        outbox_payload: safe_response,
                    },
                )
            },
        )
        .await;
    match outcome {
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(())) => {
            RemoteSendDecision::Accepted
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(_)) => {
            RemoteSendDecision::Replayed
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict)
        | Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate) => {
            RemoteSendDecision::Rejected(proto::ErrorPayload {
                code: proto::ErrorCode::Conflict,
                message: "remote operation conflict".into(),
            })
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity)
        | Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity) => RemoteSendDecision::Rejected(proto::ErrorPayload {
            code: proto::ErrorCode::Conflict,
            message: "remote operation capacity reached".into(),
        }),
        Err(error) => RemoteSendDecision::Rejected(user_message_database_error(
            &error,
            proto::ErrorCode::Internal,
            "remote send could not be committed to the operation ledger",
        )),
    }
}

struct TextArtifactReceiptJoin;

impl crate::db::db::message_attachments::MessageAcceptanceJoin for TextArtifactReceiptJoin {
    fn validate_and_join(
        &self,
        _: &rusqlite::Connection,
        input: &crate::db::db::message_attachments::AcceptMessageInput,
    ) -> anyhow::Result<()> {
        // The FCM2 codec owns semantic validation. This local join is still an
        // explicit transaction participant so the receipt/queue/reservation
        // composition has the same shape as media admissions.
        anyhow::ensure!(
            input.attachments.is_empty(),
            "oversized text artifact admission cannot carry attachments"
        );
        Ok(())
    }
}

fn validate_oversized_artifact_admission(
    session_id: Uuid,
    submission: &crate::engine::message::UserSubmission,
    admission: &OversizedTextArtifactAdmission,
) -> anyhow::Result<crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2> {
    let receipt = submission
        .client_submissions
        .first()
        .ok_or_else(|| anyhow::anyhow!("oversized admission lacks a client submission receipt"))?;
    anyhow::ensure!(
        submission.client_submissions.len() == 1,
        "oversized artifact admission cannot fold multiple receipts"
    );
    anyhow::ensure!(
        submission.images.is_empty(),
        "oversized artifact admission cannot carry image parts"
    );
    match (
        admission.model_fence.as_ref(),
        submission.expected_model_state_generation,
        submission.expected_model.as_ref(),
    ) {
        (None, None, None) => {}
        (Some((generation, model)), Some(expected_generation), Some(expected_model))
            if *generation == expected_generation && model == expected_model => {}
        _ => {
            anyhow::bail!("oversized artifact admission model fence does not match the submission")
        }
    }
    let canonical = crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
        &admission.canonical_message,
    )?;
    anyhow::ensure!(
        canonical.session_id == session_id,
        "FCM2 session does not match worker"
    );
    anyhow::ensure!(
        canonical.request.client_submission_id == receipt.id,
        "FCM2 submission identity does not match queue receipt"
    );
    anyhow::ensure!(
        canonical.request.text == submission.text,
        "FCM2 source text does not match the transport-normalized submission"
    );
    anyhow::ensure!(
        canonical.request.display_text == submission.display_text,
        "FCM2 display text does not match the submission"
    );
    anyhow::ensure!(
        canonical.request.forced_skill == submission.forced_skill,
        "FCM2 forced skill does not match the submission"
    );
    anyhow::ensure!(
        canonical.request.attachments.is_empty(),
        "FCM2 oversized-source admission unexpectedly contains media"
    );
    anyhow::ensure!(
        canonical.request.tag_expansions.len() == submission.tag_expansions.len()
            && canonical
                .request
                .tag_expansions
                .iter()
                .zip(&submission.tag_expansions)
                .all(|(canonical, submitted)| {
                    canonical.tool == submitted.tool
                        && canonical.path == submitted.path
                        && canonical.detail == submitted.detail
                        && canonical.ok == submitted.ok
                }),
        "FCM2 tag expansions do not match the submission"
    );
    anyhow::ensure!(
        canonical.request.text.len() > 64 * 1024,
        "FCM2 artifact admission does not cross the inline threshold"
    );
    anyhow::ensure!(
        canonical.message_request_digest()? == admission.message_request_digest
            && canonical.attachment_set_digest()? == admission.attachment_set_digest,
        "FCM2 receipt digests do not match admission evidence"
    );
    Ok(canonical)
}

fn text_artifact_terminal_error(
    reason: crate::db::db::text_artifacts::TextArtifactRejectReason,
) -> proto::ErrorPayload {
    proto::ErrorPayload {
        code: if reason
            == crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict
        {
            proto::ErrorCode::IdempotencyConflict
        } else {
            proto::ErrorCode::UserMessageTerminated
        },
        message: format!("oversized user message is terminal ({})", reason.as_str()),
    }
}

/// Preserve SQLite durability categories at the user-message boundary.
///
/// User-message admission has specialized fallback errors, but those must not
/// erase a storage failure whose commit outcome may be unknown. Clients retain
/// and reconcile the exact submission only for these structured storage codes.
fn user_message_database_error(
    error: &anyhow::Error,
    fallback_code: proto::ErrorCode,
    fallback_message: impl Into<String>,
) -> proto::ErrorPayload {
    let code = match crate::db::classify_database_storage_failure(error.as_ref()) {
        Some(crate::db::DatabaseStorageFailure::Capacity) => proto::ErrorCode::StorageFull,
        Some(crate::db::DatabaseStorageFailure::Memory) => proto::ErrorCode::StorageMemory,
        Some(crate::db::DatabaseStorageFailure::ReadOnly) => proto::ErrorCode::StorageReadOnly,
        Some(crate::db::DatabaseStorageFailure::Io) => proto::ErrorCode::StorageIo,
        Some(crate::db::DatabaseStorageFailure::Corrupt) => proto::ErrorCode::StorageCorrupt,
        None => {
            return proto::ErrorPayload {
                code: fallback_code,
                message: fallback_message.into(),
            };
        }
    };
    proto::ErrorPayload {
        code,
        message: format!("{error:#}"),
    }
}

#[cfg(test)]
mod user_message_database_error_tests {
    use super::*;

    #[test]
    fn every_sqlite_storage_failure_keeps_its_protocol_reconciliation_code() {
        for (sqlite_code, protocol_code) in [
            (rusqlite::ErrorCode::DiskFull, proto::ErrorCode::StorageFull),
            (
                rusqlite::ErrorCode::OutOfMemory,
                proto::ErrorCode::StorageMemory,
            ),
            (
                rusqlite::ErrorCode::ReadOnly,
                proto::ErrorCode::StorageReadOnly,
            ),
            (
                rusqlite::ErrorCode::SystemIoFailure,
                proto::ErrorCode::StorageIo,
            ),
            (
                rusqlite::ErrorCode::DatabaseCorrupt,
                proto::ErrorCode::StorageCorrupt,
            ),
        ] {
            let sqlite = rusqlite::Error::SqliteFailure(
                rusqlite::ffi::Error {
                    code: sqlite_code,
                    extended_code: 0,
                },
                None,
            );
            let error = anyhow::Error::new(sqlite).context("real user-message database phase");
            let payload = user_message_database_error(
                &error,
                proto::ErrorCode::UserMessageNotAccepted,
                "fallback must not win",
            );
            assert_eq!(payload.code, protocol_code);
            assert!(payload.message.contains("real user-message database phase"));
        }
    }

    #[test]
    fn non_storage_failure_retains_the_phase_specific_fallback() {
        let payload = user_message_database_error(
            &anyhow::anyhow!("validation failed"),
            proto::ErrorCode::UserMessageNotAccepted,
            "phase-specific refusal",
        );
        assert_eq!(payload.code, proto::ErrorCode::UserMessageNotAccepted);
        assert_eq!(payload.message, "phase-specific refusal");
    }
}

/// Map a fresh remote-ledger rejection to the closed FCM2 terminal domain.
/// Once phase one owns a reservation, callers must not leave it accepted just
/// because a later, independent in-memory/remote admission gate declined the
/// message. The exact lease composition below owns the receipt, reservation,
/// and any bound run invocation together.
#[cfg(feature = "remote")]
fn remote_send_rejection_reason(
    error: &proto::ErrorPayload,
) -> crate::db::db::text_artifacts::TextArtifactRejectReason {
    match error.code {
        proto::ErrorCode::Conflict | proto::ErrorCode::IdempotencyConflict => {
            crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict
        }
        _ => crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
    }
}

/// Consume a phase-one lease only when this caller still owns its exact
/// token/expiry pair.  A stale token is deliberately not treated as a
/// rejection: another renewer, materializer, or reaper owns the durable
/// outcome, so reload it and make the client retry rather than inventing a
/// second terminal result.
async fn reject_oversized_text_artifact_admission(
    session: &Session,
    reservation: crate::db::db::text_artifacts::TextArtifactReservation,
    reason: crate::db::db::text_artifacts::TextArtifactRejectReason,
) -> proto::ErrorPayload {
    let replay_session_id = reservation.session_id;
    let replay_operation_id = reservation.operation_id;
    let now_ms = chrono::Utc::now().timestamp_millis();
    match session
        .db
        .reject_and_release_text_artifact_reservation(reservation, reason, now_ms)
        .await
    {
        Ok(crate::db::db::text_artifacts::TextArtifactReservationTransition::Applied(reason)) => {
            text_artifact_terminal_error(reason)
        }
        Ok(crate::db::db::text_artifacts::TextArtifactReservationTransition::Stale) => {
            match session
                .db
                .text_artifact_reservation_replay(replay_session_id, replay_operation_id, now_ms)
                .await
            {
                Ok(crate::db::db::text_artifacts::TextArtifactReservationReplay::Terminal {
                    reason,
                }) => text_artifact_terminal_error(reason),
                Ok(_) => {
                    tracing::warn!(%replay_session_id, operation_id = ?replay_operation_id,
                        "oversized admission changed while terminalizing; retry will join its durable winner");
                    proto::ErrorPayload {
                        code: proto::ErrorCode::UserMessageNotAccepted,
                        message: "oversized user message admission changed; retry".to_owned(),
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, %replay_session_id, operation_id = ?replay_operation_id,
                        "could not reload stale oversized admission after terminalization");
                    user_message_database_error(
                        &error,
                        proto::ErrorCode::UserMessageNotAccepted,
                        "could not finalize oversized user message admission; retry",
                    )
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, %replay_session_id, operation_id = ?replay_operation_id,
                "failed to terminalize oversized user-message admission");
            user_message_database_error(
                &error,
                proto::ErrorCode::UserMessageNotAccepted,
                "could not finalize oversized user message admission; retry",
            )
        }
    }
}

/// Rebuild only phase-one FCM2 oversized text entries after startup
/// reconciliation. The durable receipt/lease remains the authority; the
/// in-memory queue is merely reconstituted so the driver can perform phase
/// two. No security, preflight, translation, title, or provider work occurs
/// here.
pub(super) async fn replay_accepted_oversized_text_artifact_queue(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    target: crate::engine::message::QueueTarget,
    authoritative_active_model_state: &Arc<RwLock<Option<proto::ActiveModelState>>>,
) -> Result<usize> {
    let now_ms = chrono::Utc::now().timestamp_millis();
    session
        .db
        .reap_expired_text_artifact_reservations(now_ms)
        .await
        .context("reconciling expired oversized text reservations")?;
    let rows = session
        .db
        .accepted_message_queue(session.id)
        .await
        .context("loading accepted FCM2 message queue")?;
    let mut replayed = 0usize;
    for row in rows {
        let canonical =
            match crate::proto_crate::send_user_message_v2::CanonicalSendUserMessageV2::decode(
                &row.canonical_message,
            ) {
                Ok(canonical) => canonical,
                // Accepted attachment rows can also carry FCM2. This replay path
                // owns only text-artifact rows, so another attachment owner keeps
                // responsibility for its own durable restart behavior.
                Err(_) => continue,
            };
        if canonical.session_id != session.id
            || !canonical.request.attachments.is_empty()
            || canonical.request.text.len() <= 64 * 1024
        {
            continue;
        }
        let client_submission_id = Uuid::from_bytes(row.client_submission_id);
        anyhow::ensure!(
            canonical.request.client_submission_id == client_submission_id
                && row.queue_item_id == row.client_submission_id,
            "accepted oversized FCM2 queue identity is inconsistent"
        );
        let reservation = session
            .db
            .reserved_text_artifact_submission(session.id, row.client_submission_id)
            .await?
            .ok_or_else(|| {
                anyhow::anyhow!("accepted oversized FCM2 queue row lacks its reservation")
            })?;
        let run_invocation_id =
            if reservation.reservation.run_invocation_bound {
                session
                .db
                .bound_text_artifact_run_invocation(session.id, row.client_submission_id)
                .await?
                .ok_or_else(|| anyhow::anyhow!(
                    "bound oversized FCM2 reservation lacks its exact run invocation binding"
                ))
                .map(Some)?
            } else {
                None
            };
        let durable_model_fence = match reservation.reservation.model_fence.as_ref() {
            None => None,
            Some(fence) => match decode_durable_model_fence(&fence.model_json) {
                Ok(model) => Some((fence.generation, model)),
                Err(error) => {
                    tracing::warn!(%error, session_id = %session.id, client_submission_id = %client_submission_id,
                        "rejecting oversized replay with corrupt durable model fence");
                    let _ = reject_oversized_text_artifact_admission(
                        session,
                        reservation.reservation.clone(),
                        crate::db::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                    )
                    .await;
                    continue;
                }
            },
        };
        if let Some((generation, model)) = durable_model_fence.as_ref() {
            let matches = {
                let current = authoritative_active_model_state
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                model_fence_allows_insert(current.as_ref(), *generation, model)
            };
            if !matches {
                tracing::info!(session_id = %session.id, client_submission_id = %client_submission_id,
                    "rejecting oversized replay with stale durable model fence");
                let _ = reject_oversized_text_artifact_admission(
                    session,
                    reservation.reservation.clone(),
                    crate::db::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                )
                .await;
                continue;
            }
        }
        let wire_fingerprint = format!(
            "fcm2:{}",
            crate::intel::hex_lower(&canonical.message_request_digest()?)
        );
        let mut submission = crate::engine::message::UserSubmission {
            expected_model_state_generation: durable_model_fence
                .as_ref()
                .map(|(generation, _)| *generation),
            expected_model: durable_model_fence.map(|(_, model)| model),
            kind: crate::engine::message::UserSubmissionKind::User,
            origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
            text: canonical.request.text,
            display_text: canonical.request.display_text,
            tag_expansions: canonical
                .request
                .tag_expansions
                .into_iter()
                .map(|tag| proto::TagExpansionMeta {
                    tool: tag.tool,
                    path: tag.path,
                    detail: tag.detail,
                    ok: tag.ok,
                })
                .collect(),
            images: Vec::new(),
            forced_skill: canonical.request.forced_skill.clone(),
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: vec![client_submission_id],
            client_submissions: Vec::new(),
            queue_target: Some(target.clone()),
            // This durable FCM2 queue row is an oversized lease owner.  Keep
            // that identity on the reconstructed submission so a reaper or
            // terminal receipt can never make it fall through the ordinary
            // inline/provider path.
            pending_terminal_disposition: Some(
                crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact,
            ),
            run_invocation_id,
        };
        let fingerprint = submission.client_fingerprint();
        submission
            .client_submissions
            .push(crate::engine::message::ClientSubmissionReceipt {
                id: client_submission_id,
                fingerprint,
                wire_fingerprint,
                origin_principal: None,
            });
        let (_, _, outcome) = queue
            .push_idempotent(
                submission.client_submissions[0].clone(),
                submission,
                target.clone(),
            )
            .await;
        anyhow::ensure!(
            matches!(outcome, crate::engine::message::IdempotentPush::Inserted),
            "duplicate oversized FCM2 queue replay identity"
        );
        replayed += 1;
    }
    Ok(replayed)
}

#[cfg(feature = "remote")]
struct RemoteQueueMutationCommit<'a> {
    session: &'a Session,
    queue: &'a crate::engine::message::UserSubmissionQueue,
    staged: Option<crate::engine::message::StagedQueueRemoval>,
    result: crate::engine::message::RemoveQueuedMessageResult,
    operation: RemoteQueueOperation,
    outbox_kind: &'static str,
    event_tx: &'a EventSender,
    redaction: &'a SharedRedactionTable,
}

#[cfg(feature = "remote")]
async fn commit_remote_queue_mutation(
    input: RemoteQueueMutationCommit<'_>,
) -> std::result::Result<RemoteQueueMutationReceiptV1, proto::ErrorPayload> {
    let RemoteQueueMutationCommit {
        session,
        queue,
        staged,
        result,
        operation,
        outbox_kind,
        event_tx,
        redaction,
    } = input;
    let disposition = crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
    let receipts = if let Some(staged) = staged.as_ref() {
        queue.accepted_receipts(staged.ids()).await
    } else {
        Vec::new()
    };
    if let Some(staged) = staged.as_ref()
        && receipts.is_empty()
    {
        queue.mark_staged_removal_failed(staged).await;
        return Err(proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "queued message lacks its durable acceptance receipt; removal remains held"
                .into(),
        });
    }
    let terminal_receipts = receipts
        .iter()
        .map(
            |receipt| crate::db::session_log::ClientSubmissionTerminalReceipt {
                client_submission_id: receipt.id,
                fingerprint: receipt.fingerprint.clone(),
                wire_fingerprint: receipt.wire_fingerprint.clone(),
                origin_principal: receipt.origin_principal.clone(),
                disposition,
            },
        )
        .collect::<Vec<_>>();
    let reason = remove_reason_to_proto(result);
    let removed_count = u32::try_from(staged.as_ref().map_or(0, |value| value.ids().len()))
        .map_err(|_| proto::ErrorPayload {
            code: proto::ErrorCode::Internal,
            message: "queue removal count exceeds protocol bound".into(),
        })?;
    let receipt = RemoteQueueMutationReceiptV1 {
        schema_version: 1,
        applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
        reason,
        removed_count,
    };
    let session_id = session.id;
    let now_ms = chrono::Utc::now().timestamp_millis();
    let outcome = session.db.execute_transactional_remote_operation(
        crate::db::remote_attachment_operations::ReserveRemoteOperation {
            logical_attachment_id: &operation.logical_attachment_id, operation_id: &operation.operation_id,
            authenticated_device_id: &operation.authenticated_device_id, authenticated_device_generation: operation.authenticated_device_generation,
            operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
            request_hash: operation.request_hash, now_ms,
        },
        move |conn| {
            crate::db::Db::terminalize_queued_text_artifact_submissions_conn(
                conn,
                session_id,
                &terminal_receipts,
                now_ms,
            )?;
            receipt.validate()?;
            let safe_response = serde_json::to_vec(&receipt)?;
            Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation { value: receipt, safe_response: safe_response.clone(), outbox_kind: outbox_kind.into(), outbox_payload: safe_response })
        },
    ).await;
    match outcome {
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(receipt)) => {
            if let Some(staged) = staged { let _ = commit_staged_removal_after_receipts(session, queue, staged, &receipts).await; }
            send_terminal_receipts_event(event_tx, redaction, session_id, &receipts, disposition);
            Ok(receipt)
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes)) => {
            let receipt: RemoteQueueMutationReceiptV1 = serde_json::from_slice(&bytes).map_err(|error| proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() })?;
            receipt.validate().map_err(|error| proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() })?;
            if let Some(staged) = staged { let _ = commit_staged_removal_after_receipts(session, queue, staged, &receipts).await; }
            send_terminal_receipts_event(event_tx, redaction, session_id, &receipts, disposition);
            Ok(receipt)
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate) => {
            if let Some(staged) = staged.as_ref() { queue.abort_staged_removal(staged).await; }
            Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation conflict".into() })
        }
        Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity) => {
            if let Some(staged) = staged.as_ref() { queue.mark_staged_removal_failed(staged).await; }
            Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation capacity reached".into() })
        }
        Err(_) => {
            if let Some(staged) = staged.as_ref() { queue.mark_staged_removal_failed(staged).await; }
            Err(proto::ErrorPayload { code: proto::ErrorCode::Internal, message: "remote queue operation could not be committed".into() })
        }
    }
}

fn send_terminal_receipts_event(
    event_tx: &EventSender,
    redaction: &SharedRedactionTable,
    session_id: Uuid,
    receipts: &[crate::engine::message::ClientSubmissionReceipt],
    disposition: crate::db::session_log::ClientSubmissionTerminalDisposition,
) {
    if receipts.is_empty() {
        return;
    }
    send_current_event(
        event_tx,
        redaction,
        proto::Event::UserMessagesTerminated {
            session_id,
            client_submission_ids: receipts.iter().map(|receipt| receipt.id).collect(),
            disposition: disposition.into(),
        },
    );
}

async fn probe_user_message(
    session: &Session,
    queue: &crate::engine::message::UserSubmissionQueue,
    session_id: Uuid,
    client_submission_id: Uuid,
    wire_fingerprint: &str,
    origin_principal: Option<&str>,
) -> std::result::Result<UserMessageProbeResult, proto::ErrorPayload> {
    let durable = session
        .db
        .client_submission_receipt(session_id, client_submission_id)
        .await
        .map_err(|error| {
            tracing::warn!(%error, %session_id, %client_submission_id,
                "client submission probe failed; refusing ambiguous retry");
            proto::ErrorPayload {
                code: proto::ErrorCode::Internal,
                message: "could not verify whether this message was already accepted; retry"
                    .to_string(),
            }
        })?;

    let terminal = if durable.is_none() {
        session
            .db
            .client_submission_terminal_receipt(session_id, client_submission_id)
            .await
            .map_err(|error| {
                tracing::warn!(%error, %session_id, %client_submission_id,
                    "terminal client submission probe failed; refusing ambiguous retry");
                proto::ErrorPayload {
                    code: proto::ErrorCode::Internal,
                    message: "could not verify whether this message was already terminated; retry"
                        .to_string(),
                }
            })?
    } else {
        None
    };

    let (probe, snapshot) = if let Some(receipt) = durable {
        let probe = if receipt.origin_principal.as_deref() != origin_principal {
            crate::engine::message::IdempotentProbe::Conflict
        } else if receipt.wire_fingerprint == wire_fingerprint {
            crate::engine::message::IdempotentProbe::ExactDuplicate
        } else {
            crate::engine::message::IdempotentProbe::ContentCheckRequired
        };
        (probe, queue.snapshot().await)
    } else if let Some(receipt) = terminal {
        if receipt.origin_principal.as_deref() != origin_principal {
            return Ok(UserMessageProbeResult::Conflict);
        }
        if receipt.wire_fingerprint == wire_fingerprint {
            return Err(proto::ErrorPayload {
                code: proto::ErrorCode::UserMessageTerminated,
                message: format!(
                    "client_submission_id {client_submission_id} is terminal ({}) and will not be executed",
                    receipt.disposition.as_str()
                ),
            });
        }
        (
            crate::engine::message::IdempotentProbe::ContentCheckRequired,
            queue.snapshot().await,
        )
    } else {
        queue
            .probe_idempotent(client_submission_id, wire_fingerprint, origin_principal)
            .await
    };
    Ok(match probe {
        crate::engine::message::IdempotentProbe::Unknown => UserMessageProbeResult::Unknown,
        crate::engine::message::IdempotentProbe::ContentCheckRequired => {
            UserMessageProbeResult::ContentCheckRequired
        }
        crate::engine::message::IdempotentProbe::Conflict => UserMessageProbeResult::Conflict,
        crate::engine::message::IdempotentProbe::ExactDuplicate => {
            let queue: Vec<proto::QueueItem> =
                snapshot.into_iter().map(queue_item_to_proto).collect();
            let item = queue
                .iter()
                .find(|item| item.id == client_submission_id)
                .cloned()
                .unwrap_or(proto::QueueItem {
                    id: client_submission_id,
                    status: proto::QueueItemStatus::Folding,
                    text: String::new(),
                    display_text: None,
                    target: proto::QueueTarget::default(),
                });
            UserMessageProbeResult::Duplicate { item, queue }
        }
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_worker(
    session: Arc<Session>,
    locks: Arc<LockManager>,
    redact: Arc<RedactionTable>,
    model: Arc<Model>,
    model_override: Option<Arc<Model>>,
    thinking_params: Option<serde_json::Value>,
    endpoint_recovery_thinking_params: Option<
        crate::engine::model::EndpointRecoveryAdditionalParams,
    >,
    project_root: PathBuf,
    trust_policy: crate::config::trust::WorkspaceTrustPolicy,
    mut work_rx: mpsc::Receiver<SessionWork>,
    event_tx: EventSender,
    turn_completions: Arc<Mutex<TurnCompletions>>,
    redaction: SharedRedactionTable,
    live: Arc<LiveState>,
    interactive_clients: Arc<std::sync::atomic::AtomicUsize>,
    sandbox_notice_armed: Arc<AtomicBool>,
    env_overlay: Arc<RwLock<HashMap<String, String>>>,
    repair_required: Arc<RwLock<Option<proto::ResumeRepairState>>>,
    foreground: Arc<Mutex<LiveForegroundState>>,
    config_snapshot: Arc<RwLock<SessionConfigSnapshot>>,
    authoritative_active_model_state: Arc<RwLock<Option<proto::ActiveModelState>>>,
    lsp: Arc<crate::daemon::lsp::LspManager>,
    resource_scheduler: Option<Arc<crate::engine::resource_scheduler::ResourceScheduler>>,
    scheduler: Arc<std::sync::Mutex<Option<crate::daemon::scheduler::DaemonSchedulerHandle>>>,
    write_scope: crate::write_scope::WriteScopeSource,
    _global_bus: Option<EventSender>,
    park_commit: crate::engine::interrupt::ParkCommit,
) {
    let session_id = session.id;

    // Session config is resolved by the registry/ConfigSource, then held as a
    // generationed snapshot. Live-safe keys are read from the current snapshot
    // at turn boundaries; agent/model construction uses the snapshot captured
    // for that boundary.
    let start_config = config_snapshot
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let extended_cfg = start_config.extended.clone();
    // Effective LLM mode = active model `mode` override → active provider
    // `mode` override → the persisted global `llm_mode`
    // (implementation note). Re-resolved here so a
    // model/provider that pins a mode takes effect at session start (and on a
    // `/model` change, which restarts the worker on the new active model). A
    // live `/llm-mode` toggle still overrides this for the running session via
    // `DriverControl::SetLlmMode`.
    let llm_mode = stored_session_llm_mode(&session).unwrap_or_else(|| {
        resolve_effective_llm_mode(&session, &start_config.providers, extended_cfg.llm_mode)
    });
    // Root primary: the session's stored active agent (so a resume restarts
    // on `Plan` after a `/plan` swap, `plan.md §4.6.d`), falling back to the
    // configured default when it's unset/unknown. Removed stored primaries
    // force the release default (`Build`).
    let root_agent_name = match session.assistant_name.clone() {
        Some(name) => name,
        None => resolve_root_agent(session_id, &session.db, &extended_cfg, llm_mode).await,
    };
    if session.assistant_name.is_none()
        && let Some(text) =
            super::removed_primary_notice(session_id, &session.db, &extended_cfg).await
    {
        send_current_session_event(
            &session,
            &event_tx,
            &redaction,
            proto::Event::Notice { session_id, text },
            NoticeSource::DaemonDirect,
        );
    }
    let assistant_row = if let Some(name) = session.assistant_name.as_deref() {
        match session.db.get_assistant(name).await {
            Ok(row) => row,
            Err(error) => {
                tracing::warn!(%error, assistant = name, "loading assistant row for identity failed");
                None
            }
        }
    } else {
        None
    };
    let assistant_identity_prefix = match assistant_row {
        Some(row) => match crate::assistants::identity::load_for_session(&session.db, &row).await {
            Ok(load) => {
                for text in &load.notices {
                    send_current_session_event(
                        &session,
                        &event_tx,
                        &redaction,
                        proto::Event::Notice {
                            session_id,
                            text: text.clone(),
                        },
                        NoticeSource::DaemonDirect,
                    );
                }
                Some(load.system_prefix)
            }
            Err(error) => {
                tracing::warn!(%error, assistant = %row.name, "loading assistant identity failed");
                send_current_session_event(
                    &session,
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!("Assistant identity could not be loaded: {error}"),
                    },
                    NoticeSource::DaemonDirect,
                );
                // Preserve the daemon-authenticated assistant-root marker
                // even when optional SOUL/USER prompt material is malformed.
                // Root definition resolution must still select the private
                // installation snapshot ahead of a same-named workspace file.
                Some(String::new())
            }
        },
        None => None,
    };
    // Capture the daemon-owned installation table once for the entire
    // session.  UUID child references select these authenticated definition
    // snapshots directly; neither child preflight nor construction may fall
    // back to a checkout name lookup.
    let vnext_local_installation_resolver =
        match crate::assistants::local_installation_resolver(&session.db).await {
            Ok(resolver) => resolver,
            Err(error) => {
                // The authenticated local-installation table is part of vNext
                // launch authority.  Starting a session without it would make
                // UUID children ambiguous (or invite a name-lookup fallback),
                // so report a terminal worker failure and refuse the session.
                let message =
                    format!("could not load daemon-local agent installation bindings: {error:#}");
                tracing::error!(%message, %session_id, "session startup refused");
                let mut driver_failed = false;
                emit_session_driver_failed_once(
                    &event_tx,
                    &turn_completions,
                    &redaction,
                    session_id,
                    &mut driver_failed,
                    message,
                );
                return;
            }
        };
    // The daemon's shared shutdown gate, captured before `model` is moved into
    // `spawn_args`. Reused when building model-comparison tandem (shadow)
    // models so a tandem request — itself a new provider round-trip — refuses
    // to dispatch once a drain begins (`model-comparison-tandem-
    // inference.md`).
    let initial_model_for_toggles = model_override.as_ref().unwrap_or(&model);
    let initial_model_for_toggles = (
        initial_model_for_toggles.provider_id().to_string(),
        initial_model_for_toggles.model_id_ref().to_string(),
    );
    let shutdown_gate = model.shutdown_gate();
    let spawn_args = SpawnArgs {
        model,
        env_overlay: env_overlay.clone(),
        // The active model's resolved extra-request-body fragment
        // (implementation note) rides on every outbound
        // request via `ModelParams`; the rest are defaults as before.
        params: ModelParams {
            additional_params: thinking_params,
            endpoint_recovery_additional_params: endpoint_recovery_thinking_params,
            // Top-level `prompt_cache_key` = session id for OpenAI-compatible
            // backends (prompt `prompt-caching-strategy.md`, decision 3),
            // held constant across the session so per-key prefix caching keeps
            // hitting. Only the main session worker's foreground model sets
            // it; background/utility models leave it `None`. The native
            // Anthropic arm ignores it (it caches per-block instead).
            prompt_cache_key: Some(session_id.to_string()),
            ..ModelParams::default()
        },
        cwd: project_root.clone(),
        config: SessionConfigHandle::new(config_snapshot.clone()),
        session_short_id: session.short_id.clone(),
        assistant_identity_prefix,
        model_system_prompt_snapshot: session.model_system_prompt_snapshot(),
        // The daemon root is always the user-facing interactive agent —
        // it gets the cross-session recall tools.
        interactive: true,
        llm_mode,
        // Plan-level model override (`plan-duplication-and-model-override.md`):
        // when set, the root and every spawned subagent run under it.
        model_override: model_override.clone(),
        delegation_model: None,
        delegated: false,
        delegation_recursion: builtin::configured_recursion_context(
            &extended_cfg.delegation,
            &root_agent_name,
            None,
        ),
        vnext_grant: None,
        // vNext definitions are declarative requests only; the daemon
        // snapshots the core-owned host policy at root construction so their
        // effective grants are both usable and bounded for the whole tree.
        vnext_host_policy: Some(std::sync::Arc::new(
            crate::agents::VnextHostPolicy::for_session_config(&extended_cfg),
        )),
        vnext_local_installation_resolver,
        parent_vnext_grant: None,
        // Recursive-`Swarm` depth (GOALS §24): the `Swarm` root is depth 0;
        // each `bee` fan-out spawn advances it. The ceiling rides along so
        // the `spawn` description shows the remaining budget.
        swarm_depth: 0,
        swarm_max_depth: crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        // The root primary carries no per-delegation grants — grants attach to
        // an individual `task` delegation, never to the root spawn.
        granted_tools: Vec::new(),
        lock_identity: None,
        write_scope: None,
        // Owner-scoped store for delegated/computer-use model construction: a
        // child's `$secret:` model/header ref can only resolve a secret owned by
        // (provider, this session's workspace), never a foreign workspace's. See
        // `named-secret-ownership-boundary`.
        credential_store: session
            .provider_credential_store(&start_config.providers)
            .ok(),
    };
    let tool_surface_override = stored_tool_surface_override(&session);
    let _goal_settings_override = stored_goal_settings_override(&session);
    let root = Arc::new(
        match builtin::load_with_assistant_db_and_tool_surface_override(
            &root_agent_name,
            &spawn_args,
            &session.db,
            tool_surface_override.as_ref(),
        )
        .await
        {
            Ok(agent) => agent,
            Err(error) if tool_surface_override.is_some() => {
                tracing::warn!(
                    %error,
                    session_id = %session_id,
                    agent = %root_agent_name,
                    "applying stored tool surface override failed; falling back to agent definition"
                );
                builtin::load_with_assistant_db_and_tool_surface_override(
                    &root_agent_name,
                    &spawn_args,
                    &session.db,
                    None,
                )
                .await
                .unwrap_or_else(|_| builtin::default_build(&spawn_args))
            }
            Err(_) => builtin::load_with_assistant_db_and_tool_surface_override(
                &root_agent_name,
                &spawn_args,
                &session.db,
                None,
            )
            .await
            .unwrap_or_else(|_| builtin::default_build(&spawn_args)),
        },
    );

    // Snapshot the resolved agent-guidance file body that just went into
    // the frozen system block (live instructions-file diff injection,
    // prompt `instructions-file-live-diff.md`). This is the start-of-
    // session baseline a later in-place edit is diffed against; the driver
    // checks it on every outbound request. Recomputed on each worker spawn
    // (fresh or resumed) because `builtin::build` re-composes the system
    // block from the current file each time.
    session.snapshot_guidance_baseline(&project_root).await;

    let (queue_update_tx, queue_update_rx) =
        watch::channel::<Vec<crate::engine::message::QueuedUserMessage>>(Vec::new());
    let driver_input_queue = crate::engine::message::UserSubmissionQueue::new(queue_update_tx);
    let foreground_input_target = Arc::new(Mutex::new(crate::engine::message::QueueTarget::root(
        root.name.clone(),
    )));
    // Reconcile exact-expiry leases before rebuilding accepted FCM2 work. A
    // worker restart must either enqueue the still-live owner once or observe
    // its durable terminal/materialized winner; it never reruns preprocessing
    // merely because the in-memory queue was lost.
    let replay_target = foreground_input_target
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    match replay_accepted_oversized_text_artifact_queue(
        &session,
        &driver_input_queue,
        replay_target,
        &authoritative_active_model_state,
    )
    .await
    {
        Ok(replayed) if replayed > 0 => {
            tracing::info!(%session_id, replayed, "replayed accepted oversized FCM2 queue entries");
        }
        Ok(_) => {}
        Err(error) => {
            tracing::error!(%error, %session_id, "oversized FCM2 startup reconciliation failed; refusing provider dispatch");
            send_current_session_event(
                &session,
                &event_tx,
                &redaction,
                proto::Event::Notice {
                    session_id,
                    text:
                        "Oversized message recovery could not be verified; no provider was started."
                            .to_owned(),
                },
                NoticeSource::DaemonDirect,
            );
            return;
        }
    }
    let (driver_control_tx, driver_control_rx) =
        mpsc::channel::<crate::engine::driver::DriverControl>(WORK_QUEUE_CAPACITY);
    let (engine_event_tx, mut engine_event_rx) = mpsc::channel::<TurnEvent>(WORK_QUEUE_CAPACITY);
    let engine_event_notice_tx = engine_event_tx.clone();

    // Forward engine events → broadcast channel as proto::Event, and
    // maintain the live job/turn status (GOALS §17f) off the same
    // authoritative stream. These signals originate from the driver turn
    // loop (`ThinkingStarted` / `AgentIdle`) and the single `ScheduleAuthority`
    // (`ScheduleStarted` / `ScheduleCompleted`); the forwarder is the one seam they
    // all pass through, so updating here never duplicates the authority.
    let event_tx_for_forward = event_tx.clone();
    let event_tx_for_queue = event_tx.clone();
    let turn_completions_for_forward = turn_completions.clone();
    let redaction_for_forward = redaction.clone();
    let redaction_for_queue = redaction.clone();
    let foreground_input_target_for_forward = foreground_input_target.clone();
    let foreground_for_forward = foreground.clone();
    let live_for_forward = live.clone();
    let sandbox_notice_armed_for_forward = sandbox_notice_armed.clone();
    let session_for_forward = session.clone();
    let authoritative_active_model_state_for_forward = authoritative_active_model_state.clone();
    // The lock authority + the interactive-client count, for the
    // `AgentIdle`-with-zero-clients release edge
    // (implementation note). When a turn finishes and no
    // interactive client is attached, the session's locks are released here —
    // the second of the two edges (the first is the last-detach drop above).
    let locks_for_forward = locks.clone();
    let interactive_clients_for_forward = interactive_clients.clone();
    let forward = tokio::spawn(async move {
        let send_event = |ev: proto::Event| {
            update_authoritative_active_model_state(
                &authoritative_active_model_state_for_forward,
                &ev,
            );
            // Per-session de-dupe (§6.5): the engine emits `SandboxUnavailable`
            // on every refused `bash` (the verdict is process-lifetime-cached,
            // so it recurs), but the user needs only one persistent notice.
            // Forward the first; drop the recurring duplicates. `set_sandbox`
            // re-arms the latch when the user toggles `/sandbox`.
            if matches!(ev, proto::Event::SandboxUnavailable { .. })
                && !forward_sandbox_unavailable(&sandbox_notice_armed_for_forward)
            {
                return;
            }
            match &ev {
                proto::Event::ThinkingStarted { .. } => {
                    live_for_forward.processing.store(true, Ordering::Relaxed);
                }
                proto::Event::AgentIdle { .. } => {
                    live_for_forward.processing.store(false, Ordering::Relaxed);
                    live_for_forward.tool_running.store(0, Ordering::Relaxed);
                    // Last-detach-while-idle edge, idle side
                    // (implementation note): the turn just finished, so if no
                    // interactive client is attached, release this session's locks now.
                    if interactive_clients_for_forward.load(Ordering::SeqCst) == 0 {
                        schedule_session_locks_unattended(
                            locks_for_forward.clone(),
                            interactive_clients_for_forward.clone(),
                            live_for_forward.clone(),
                            session_id,
                            "idle with no attached clients",
                        );
                        schedule_session_container_release(
                            interactive_clients_for_forward.clone(),
                            live_for_forward.clone(),
                            session_id,
                            "idle with no attached clients",
                        );
                    }
                }
                proto::Event::ScheduleStarted { .. } => {
                    live_for_forward
                        .active_schedules
                        .fetch_add(1, Ordering::Relaxed);
                }
                proto::Event::ScheduleCompleted { .. } => {
                    // Saturating: never underflow if a completion is ever seen without its start.
                    let _ = live_for_forward.active_schedules.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
                proto::Event::ToolStart { .. } => {
                    live_for_forward
                        .tool_running
                        .fetch_add(1, Ordering::Relaxed);
                }
                proto::Event::ToolEnd { .. } | proto::Event::ToolError { .. } => {
                    let _ = live_for_forward.tool_running.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |n| Some(n.saturating_sub(1)),
                    );
                }
                _ => {}
            }
            resolve_turn_terminal_event(&turn_completions_for_forward, &ev);
            // `send` returns `Err` only when there are no subscribers — that's fine.
            send_current_session_event(
                &session_for_forward,
                &event_tx_for_forward,
                &redaction_for_forward,
                ev,
                NoticeSource::EngineTurn,
            );
        };

        let mut coalescer = StreamDeltaCoalescer::default();
        loop {
            if let Some(deadline) = coalescer.deadline() {
                tokio::select! {
                    maybe_event = engine_event_rx.recv() => {
                        let Some(event) = maybe_event else {
                            for ev in coalescer.flush() {
                                send_event(ev);
                            }
                            break;
                        };
                        update_live_foreground(
                            &foreground_for_forward,
                            &foreground_input_target_for_forward,
                            &event,
                        );
                        for ev in proto::turn_event_to_proto(event, session_id) {
                            for ready in coalescer.push(ev) {
                                send_event(ready);
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        for ev in coalescer.flush() {
                            send_event(ev);
                        }
                    }
                }
            } else {
                let Some(event) = engine_event_rx.recv().await else {
                    break;
                };
                update_live_foreground(
                    &foreground_for_forward,
                    &foreground_input_target_for_forward,
                    &event,
                );
                for ev in proto::turn_event_to_proto(event, session_id) {
                    for ready in coalescer.push(ev) {
                        send_event(ready);
                    }
                }
            }
        }
        close_pending_turn_completions(&turn_completions_for_forward);
    });
    let queue_forward = tokio::spawn(forward_queue_updates(
        queue_update_rx,
        event_tx_for_queue,
        redaction_for_queue,
        session_id,
    ));

    // Build the driver, then capture its async-job command sender (GOALS
    // §22) so a human-initiated `/schedule cancel` reaches the single
    // authority before moving the driver into its task.
    let max_concurrent_schedules = max_concurrent_schedules_for(&extended_cfg);
    let mut driver = Driver::with_max_schedules(
        session.clone(),
        locks.clone(),
        redact.clone(),
        project_root.clone(),
        root,
        max_concurrent_schedules,
    );
    // Keep the exact daemon-owned binding input for every descendant spawn;
    // the driver never reconstructs local UUID references from display names.
    driver.set_vnext_local_installation_resolver(
        spawn_args.vnext_local_installation_resolver.clone(),
    );
    // Install the session config reader before the loop starts so the driver
    // and every `ToolCtx` it builds read config through the generationed
    // snapshot rather than from disk (`engine-config-snapshot-adoption`).
    driver.set_config_handle(SessionConfigHandle::new(config_snapshot.clone()));
    driver.set_assistant_identity_prefix(spawn_args.assistant_identity_prefix.clone());
    // Propagate any plan-level model override to the whole delegation tree
    // (`plan-duplication-and-model-override.md`): the root already runs under
    // it (loaded with the override `SpawnArgs`); this carries it down to
    // delegated subagents whose frontmatter would otherwise win.
    driver.set_model_override(model_override);
    // Recursive-`Swarm` knobs (GOALS §24): the depth ceiling + the global
    // concurrency cap on simultaneously-running `bee` workers, enforced
    // centrally by the single async-job authority.
    driver.set_swarm_config(
        crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_DEPTH,
        crate::config::extended::DEFAULT_RECURSIVE_SPAWN_MAX_CONCURRENCY,
    );
    driver.set_lsp_manager(lsp);
    if let Some(scheduler) = resource_scheduler {
        driver.set_resource_scheduler(scheduler);
    }
    driver.set_daemon_scheduler_source(scheduler);
    driver.set_write_scope_source(write_scope.clone());
    // Open the session's root write authority. Every delegation descends from
    // it, and it is what session deletion and shutdown drain against. Idempotent
    // so a worker restart reuses the existing root rather than minting a second.
    // Bind the clone in its own statement: an `if let` scrutinee keeps the
    // MutexGuard temporary alive for the whole block, and holding a std guard
    // across the `.await` below would make this future non-Send.
    let installed_coordinator = crate::sync::lock_or_recover(&write_scope).clone();
    if let Some(coordinator) = installed_coordinator {
        match crate::write_scope::CanonicalScope::resolve_under(&project_root, ".") {
            Ok(scope) => {
                if let Err(error) = coordinator
                    .ensure_session_root_lease(session.id, "session-root", scope)
                    .await
                {
                    tracing::warn!(
                        error = %error,
                        "could not open the session write-scope root lease"
                    );
                }
            }
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    "session cwd does not resolve; no write-scope root lease opened"
                );
            }
        }
    }
    let job_cmd_tx = driver.job_command_sender();
    // Capture the driver's cancel handle (GOALS §3a) before moving it into
    // its task, so a user ctrl+c (`SessionWork::Cancel`) can abort the
    // in-flight user-message run — aborting the streaming inference and
    // killing any running `bash` subprocess.
    let cancel_handle = driver.cancel_handle();

    // Interrupt wakeup hub (GOALS §3b): wire the driver's tool calls to
    // the client event fan-out so the `question` tool can raise an
    // interrupt and block on the answer. We keep the same `Arc` so the
    // `ResolveInterrupt` handler below can wake the blocked tool. The
    // hub must be installed before the driver loop starts.
    let interrupts = Arc::new(
        crate::engine::interrupt::InterruptHub::new(
            event_tx.clone(),
            redaction.clone(),
            interactive_clients,
            session.db.clone(),
            session_id,
        )
        // Wire the shared park-commit rendezvous
        // (`daemon-lifecycle-replay-timing-robustness.md`) so this worker's
        // waiter registration and `SessionWork::Shutdown` park land the
        // drain-path synchronization signal.
        .with_park_commit(park_commit.clone()),
    );
    driver.set_interrupt_hub(interrupts.clone());

    // Command/path approval driver (sandboxing part 2). Built on the
    // session's grant store + the client-wired interrupt hub above, so a
    // `bash` run-fail-escalate or a native out-of-boundary path access
    // raises a prompt that fans out to the attached client exactly like a
    // `question`. The driver threads it into every `ToolCtx`. Installed
    // after the hub (the approver captures the same `Arc`). The active
    // agent for the prompt is the foreground primary agent at spawn time;
    // a delegated builder shares the same approver via the `ToolCtx`
    // `Arc`, so grants persist across the delegation tree.
    let grant_store = crate::approval::store::GrantStore::new(
        session.db.clone(),
        session_id,
        project_root.clone(),
        // Live handle over the worker's shared snapshot: the approval policy is
        // read live and trust-aware (the snapshot is resolved by the daemon's
        // `ConfigSource`), so a policy change on the running session takes
        // effect without rebuilding the store.
        SessionConfigHandle::new(config_snapshot.clone()),
    );
    let approver = Arc::new(crate::approval::Approver::new_for_session(
        grant_store,
        session.db.clone(),
        session.clone(),
        redaction.clone(),
        &root_agent_name,
        interrupts.clone(),
    ));
    driver.set_approver(approver);

    // Loop-guard threshold (GOALS §1/§12) from the layered config, same
    // discovery the jobs cap uses. Clamped to ≥ 2 by the setter.
    driver.set_loop_guard_threshold(loop_guard_threshold_for(&extended_cfg));
    driver.set_max_primary_rounds(max_primary_rounds_for(&extended_cfg));
    driver.set_allow_unbounded_schedule_loops(extended_cfg.schedule.allow_unbounded_loops);

    // Resume rehydration (implementation note): on a
    // fresh worker for a session that has prior recorded turns (a daemon
    // restart, an `/exit` + `/resume`, or resuming a `/compact` successor
    // that already had turns), rebuild the root agent's model-bound history
    // from the durable transcript + prune ledger so the next message
    // continues the conversation in its PRUNED form rather than starting
    // fresh. Automatic — only when the root frame has no live in-memory
    // history (which a freshly-built driver never does). A hard rebuild
    // failure (corrupt/unpairable rows) is surfaced as a clear error rather
    // than sending a malformed or silently-fresh context (priority #1).
    let (_, _, active_wire_api) = active_wire_api_for_session(&session, &start_config.providers);
    let responses_strict_replay = matches!(
        active_wire_api,
        crate::config::providers::WireApi::Responses
    );
    let rehydrate_policy = if responses_strict_replay {
        crate::engine::rehydrate::RehydratePolicy::strict()
    } else {
        crate::engine::rehydrate::RehydratePolicy::heal()
    };
    let rehydrated = match driver
        .rehydrate_root_if_empty_with_policy(&root_agent_name, rehydrate_policy)
        .await
    {
        Ok(r) => r,
        Err(e) => {
            if responses_strict_replay
                && let Some(repair) =
                    e.downcast_ref::<crate::engine::rehydrate::RehydrateRepairRequired>()
            {
                let state = build_resume_repair_state(&session, &start_config.providers, repair);
                tracing::error!(
                    session_id = %session_id,
                    failure_kind = %state.failure_kind,
                    failing_tool_call_ids = ?state.failing_tool_call_ids,
                    "resume rehydration requires explicit Responses repair before provider replay"
                );
                {
                    let mut slot = repair_required
                        .write()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    *slot = Some(state.clone());
                }
                let label = if state.short_id.is_empty() {
                    state.session_id.to_string()
                } else {
                    state.short_id.clone()
                };
                send_current_session_event(
                    &session,
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Resume repair required for {label}: {}. The transcript is open read-only; fork from the last valid turn, export a debug bundle, or explicitly repair before continuing.",
                            state.detail
                        ),
                    },
                    NoticeSource::DaemonDirect,
                );
            } else {
                tracing::error!(error = %e, session_id = %session_id,
                    "resume rehydration failed; the transcript could not be rebuilt into a \
                     provider-valid conversation");
                send_current_session_event(
                    &session,
                    &event_tx,
                    &redaction,
                    proto::Event::Notice {
                        session_id,
                        text: format!(
                            "Resume failed: the prior conversation could not be rebuilt ({e}). \
                         Start a new session to continue."
                        ),
                    },
                    NoticeSource::DaemonDirect,
                );
            }
            None
        }
    };
    if let Some(r) = &rehydrated
        && r.ledger_fallback
    {
        // Continuity preserved, just less pruned — surface a non-fatal
        // warning (never a silent drop to a fresh context).
        send_current_session_event(
            &session,
            &event_tx,
            &redaction,
            proto::Event::Notice {
                session_id,
                text: "Resume: the prune ledger was inconsistent; restored the full \
                   (unpruned) prior context instead."
                    .to_string(),
            },
            NoticeSource::DaemonDirect,
        );
    }
    if let Some(r) = &rehydrated
        && !r.heals.is_empty()
    {
        // The heal pass stubbed/dropped unpairable rows so the prior
        // conversation could be rebuilt instead of dead-ending — degrade
        // visibly (alongside any ledger-fallback notice above), never a
        // silent alteration of the resumed context.
        let n = r.heals.len();
        send_current_session_event(
            &session,
            &event_tx,
            &redaction,
            proto::Event::Notice {
                session_id,
                text: format!(
                    "Resume: {n} incomplete tool call(s) were stubbed to rebuild the conversation."
                ),
            },
            NoticeSource::DaemonDirect,
        );
    }

    // `sessionStart` observe hooks: fire once per worker start, after
    // rehydration completes. Matcher / `startSource` is `resume` when the
    // session was rehydrated from durable history, else `fresh`. Observe-only /
    // fail-open; the registry comes from the current config snapshot (cloned so
    // no lock guard is held across the hook run).
    {
        let start_source = if rehydrated.is_some() {
            "resume"
        } else {
            "fresh"
        };
        let registry = config_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .hooks()
            .clone();
        crate::engine::agent::hooks::run_observe_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            &registry,
            crate::config::extended::hooks::HookEvent::SessionStart,
            start_source,
            session.id,
            &project_root,
            &session.db,
            None,
            None,
            None,
            None,
            crate::engine::agent::hooks::ObserveFields {
                start_source: Some(start_source),
                ..Default::default()
            },
        )
        .await;
    }

    // Releasable, debug-build + env-gated pause point
    // (`daemon-lifecycle-replay-timing-robustness.md`, §3 / criterion 1): hold
    // the attach reconciliation BEFORE the crash-surviving `Open → Parked`
    // write so a test can prove the attach path awaits the park-commit signal.
    // Bounded (self-releasing) so the fixed code's reconciliation still lands
    // within `INTERRUPT_PARK_COMMIT_DEADLINE`; not the irreversible
    // `COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING` loop. Unreachable in release.
    test_injected_park_delay("COCKPIT_TEST_DELAY_STARTUP_RECONCILE_MS").await;
    match session.db.list_reconcilable_interrupts(session_id).await {
        Ok(rows) => {
            for row in rows {
                match row.state {
                    crate::db::needs_attention::InterruptState::Open
                        if validate_parked_interrupt_payload(&row).is_ok() =>
                    {
                        if let Err(error) = session.db.park_interrupt(row.interrupt_id).await {
                            tracing::warn!(
                                %error,
                                interrupt_id = %row.interrupt_id,
                                "parking crash-surviving interrupt failed"
                            );
                        }
                    }
                    crate::db::needs_attention::InterruptState::Parked
                        if validate_parked_interrupt_payload(&row).is_ok() => {}
                    crate::db::needs_attention::InterruptState::Open
                    | crate::db::needs_attention::InterruptState::Parked
                    | crate::db::needs_attention::InterruptState::Executing => {
                        if let Err(error) = session
                            .db
                            .mark_interrupt_interrupted(row.interrupt_id)
                            .await
                        {
                            tracing::warn!(
                                %error,
                                interrupt_id = %row.interrupt_id,
                                "marking unrecoverable interrupt failed"
                            );
                        }
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: match validate_parked_interrupt_payload(&row) {
                                    Ok(()) => format!(
                                        "Interrupted request {}: replay was in progress during worker restart.",
                                        row.interrupt_id
                                    ),
                                    Err(reason) => format!(
                                        "Interrupted request {}: {reason}.",
                                        row.interrupt_id
                                    ),
                                },
                            },
                            NoticeSource::DaemonDirect,
                        );
                    }
                    _ => {}
                }
            }
        }
        Err(error) => {
            tracing::warn!(%error, "interrupt reconciliation failed");
        }
    }
    // Publish the attach-path park-commit edge
    // (`daemon-lifecycle-replay-timing-robustness.md`, §3): the crash-surviving
    // `Open → Parked` reconciliation above has now committed (or there was
    // nothing to reconcile), so a client that attached and is awaiting this
    // signal can observe the durable `Parked` row. Always fired (even on the
    // error/empty paths) so `attach` never blocks to the deadline needlessly.
    park_commit.report_startup_reconciled();

    // Session-only redaction source overrides (`/toggle-redaction`). The
    // base config is reloaded at every turn boundary so dotenv/settings/SSH
    // changes made after session start are picked up before the next provider
    // request; these overrides preserve any live toggles without writing them
    // to disk.
    let mut redaction_overrides = RedactionSourceOverrides::default();
    let mut preflight_override = None;
    let mut longcache_enabled = false;
    let mut unsupported_redaction_notified: HashSet<PathBuf> = HashSet::new();

    // Spawn the driver loop.
    let driver_queue_for_loop = driver_input_queue.clone();
    let mut driver_handle = tokio::spawn(async move {
        crate::config::trust::scope_workspace_trust_policy(trust_policy, async move {
            let driver_loop = Box::pin(driver.run_main_loop(
                driver_queue_for_loop,
                driver_control_rx,
                &engine_event_tx,
            ));
            let outcome = driver_loop.await;
            // Pairing teardown: a driver-loop exit that still holds interactive
            // child frames (only reachable via a fatal `Err` — every clean /
            // cancel / gate / interrupt / inference-failure path already
            // unwinds to root) emits one paired `subagentStop` per abandoned
            // child so no `subagentStart` is left unpaired. No-op when the stack
            // is already at root.
            driver.drain_orphaned_child_stop_hooks().await;
            // Same pairing teardown for detached-`Swarm` children: any child
            // still tracked (its terminal `Completed` was never drained — detach
            // loss / shutdown) emits one paired `subagentStop` (`aborted`) so no
            // `subagentStart` is left unpaired. No-op when every child already
            // completed (each `Completed` removed it from the map).
            driver.drain_orphaned_swarm_stop_hooks().await;
            match outcome {
                Ok(()) => DriverOutcome::Ok,
                Err(e) => {
                    let error = format!("{e:#}");
                    tracing::error!(error = %error, "driver loop terminated with error");
                    DriverOutcome::Err(error)
                }
            }
        })
        .await
    });

    // Main work loop.
    enum WorkerInput {
        Work(Box<SessionWork>),
        ParkedReplay(ParkedReplayCompletion),
        ReapExpiredTextArtifactReservations,
    }
    let (replay_completion_tx, mut replay_completion_rx) =
        mpsc::channel::<ParkedReplayCompletion>(WORK_QUEUE_CAPACITY);
    let mut driver_failed = false;
    let mut driver_joined = false;
    // Whether every registered interrupt's shutdown park committed durably.
    // Seeded by the initial snapshot's sweep and refined by the post-drain
    // park-drain loop; reported once after the driver quiesces (finding 2).
    let mut shutdown_park_committed = true;
    let mut text_artifact_reservation_reaper =
        tokio::time::interval(TEXT_ARTIFACT_RESERVATION_REAP_INTERVAL);
    text_artifact_reservation_reaper
        .set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` ticks immediately. Startup reconciliation above already
    // performed the required first sweep, so consume that instant rather than
    // adding a redundant write before the work loop begins.
    text_artifact_reservation_reaper.tick().await;
    let stop = loop {
        let input = tokio::select! {
            biased;
            replay = replay_completion_rx.recv() => {
                match replay {
                    Some(replay) => WorkerInput::ParkedReplay(replay),
                    None => continue,
                }
            }
            work = work_rx.recv() => {
                match work {
                    Some(work) => WorkerInput::Work(Box::new(work)),
                    None => break WorkerStop::WorkerStopped,
                }
            }
            _ = text_artifact_reservation_reaper.tick() => {
                WorkerInput::ReapExpiredTextArtifactReservations
            }
            outcome = &mut driver_handle => {
                driver_joined = true;
                let outcome = driver_join_outcome(outcome);
                if let Some(error) = outcome.failure_error() {
                    emit_session_driver_failed_once(
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                        error.to_string(),
                    );
                    break WorkerStop::DriverFailed;
                }
                break WorkerStop::DriverExited;
            }
        };
        match input {
            WorkerInput::ReapExpiredTextArtifactReservations => {
                let now_ms = chrono::Utc::now().timestamp_millis();
                if let Err(error) = session
                    .db
                    .reap_expired_text_artifact_reservations(now_ms)
                    .await
                {
                    // This is an opportunistic reconciliation sweep. A failed
                    // transaction leaves the durable accepted lease untouched,
                    // so replay/dispatch can retry without inventing a terminal
                    // outcome outside the DB composition.
                    tracing::warn!(%error, %session_id, "periodic oversized text reservation reap failed");
                }
            }
            WorkerInput::ParkedReplay(completion) => {
                finish_parked_replay_completion(
                    &session,
                    &event_tx,
                    &redaction,
                    &interrupts,
                    session_id,
                    completion,
                )
                .await;
            }
            WorkerInput::Work(work) => match *work {
                SessionWork::WakeGoal => {
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::WakeGoal,
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::ProbeUserMessage {
                    client_submission_id,
                    wire_fingerprint,
                    origin_principal,
                    respond_to,
                } => {
                    let outcome = Box::pin(probe_user_message(
                        &session,
                        &driver_input_queue,
                        session_id,
                        client_submission_id,
                        &wire_fingerprint,
                        origin_principal.as_deref(),
                    ))
                    .await;
                    let _ = respond_to.send(outcome);
                }
                SessionWork::UserMessage {
                    mut submission,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    artifact_admission,
                    respond_to,
                } => {
                    let client_submission_id = submission
                        .client_submissions
                        .first()
                        .map(|receipt| receipt.id)
                        .expect("wire user submissions carry a client receipt");
                    let receipt = submission
                        .client_submissions
                        .first()
                        .expect("wire user submissions carry a client receipt");
                    // A repair-locked session cannot ever hand this source to
                    // phase two. Check before phase one so an oversized retry
                    // does not create a receipt/lease which the repair gate
                    // would immediately strand.
                    if artifact_admission.is_some()
                        && let Some(state) = repair_required
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                    {
                        let ids = if state.failing_tool_call_ids.is_empty() {
                            "unknown tool id".to_string()
                        } else {
                            state.failing_tool_call_ids.join(", ")
                        };
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Read-only resume: refusing to send model context until Responses repair is resolved ({}: {}). Use the resume repair dialog, fork, or export a debug bundle.",
                                    state.failure_kind, ids
                                ),
                            },
                            NoticeSource::DaemonDirect,
                        );
                        let _ = respond_to.send(Err(proto::ErrorPayload {
                            code: proto::ErrorCode::UserMessageNotAccepted,
                            message: format!(
                                "session resume requires explicit repair before accepting message {client_submission_id}"
                            ),
                        }));
                        continue;
                    }
                    // The oversized text path owns a durable FCM2 receipt and
                    // quota lease before any legacy queue, security/preflight,
                    // utility model, title, or primary-model side effect. It is
                    // intentionally handled before the old client-submission
                    // receipt probe: the two receipt families have different
                    // ownership and must never be used as compatibility aliases.
                    let mut phase_one_reservation = None;
                    if let Some(admission) = artifact_admission.as_ref() {
                        if let Err(error) = session.persist_if_needed() {
                            tracing::error!(%error, %session_id, client_submission_id = %receipt.id,
                                "persisting session before FCM2 artifact admission failed");
                            let _ = respond_to.send(Err(user_message_database_error(
                                &error,
                                proto::ErrorCode::UserMessageNotAccepted,
                                "session persistence failed before oversized message admission",
                            )));
                            continue;
                        }
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        if let Err(error) = session
                            .db
                            .reap_expired_text_artifact_reservations(now_ms)
                            .await
                        {
                            tracing::warn!(%error, %session_id,
                                "reconciling expired oversized reservations before admission failed");
                            let _ = respond_to.send(Err(user_message_database_error(
                                &error,
                                proto::ErrorCode::UserMessageNotAccepted,
                                "could not reconcile oversized message admission; retry",
                            )));
                            continue;
                        }
                        let canonical = match validate_oversized_artifact_admission(
                            session_id,
                            &submission,
                            admission,
                        ) {
                            Ok(value) => value,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                    "rejecting malformed oversized artifact admission evidence");
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                    code: proto::ErrorCode::BadRequest,
                                    message: "invalid oversized user-message admission".to_owned(),
                                }));
                                continue;
                            }
                        };
                        let accept_input = crate::db::db::message_attachments::AcceptMessageInput {
                            session_id,
                            operation_id: admission.operation_id,
                            actor: admission.actor,
                            request_hash: admission.request_hash,
                            message_request_digest: admission.message_request_digest,
                            attachment_set_digest: admission.attachment_set_digest,
                            client_submission_id: *receipt.id.as_bytes(),
                            queue_item_id: *receipt.id.as_bytes(),
                            canonical_message: admission.canonical_message.clone(),
                            attachments: Vec::new(),
                            outbox_sequence: 0,
                            now_ms,
                        };
                        let source_digest =
                            crate::db::db::text_artifacts::source_digest(&canonical.request.text);
                        let model_fence = match admission
                            .model_fence
                            .as_ref()
                            .map(|(generation, model)| -> anyhow::Result<_> {
                                Ok(crate::db::db::text_artifacts::TextArtifactModelFence {
                                    generation: *generation,
                                    model_json: encode_durable_model_fence(model)?,
                                })
                            })
                            .transpose()
                            .map_err(|error: anyhow::Error| proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!("invalid oversized model fence: {error}"),
                            }) {
                            Ok(model_fence) => model_fence,
                            Err(error) => {
                                let _ = respond_to.send(Err(error));
                                continue;
                            }
                        };
                        let accepted = match admission.run_invocation.as_ref() {
                            Some(run_invocation) => session
                                .db
                                .accept_message_with_text_artifact_reservation_and_run_invocation_with_model_fence(
                                    accept_input,
                                    std::sync::Arc::new(TextArtifactReceiptJoin),
                                    source_digest,
                                    canonical.request.text.len(),
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationInput {
                                        origin_principal_digest: run_invocation
                                            .origin_principal_digest
                                            .clone(),
                                        options_json: run_invocation.options_json.clone(),
                                        options_digest: run_invocation.options_digest.clone(),
                                        content_digest: run_invocation.content_digest.clone(),
                                        max_turns: run_invocation.max_turns,
                                        timeout_ms: run_invocation.timeout_ms,
                                    },
                                    model_fence,
                                )
                                .await,
                            None => {
                                session
                                    .db
                                    .accept_message_with_text_artifact_reservation_with_model_fence(
                                        accept_input,
                                        std::sync::Arc::new(TextArtifactReceiptJoin),
                                        source_digest,
                                        canonical.request.text.len(),
                                        model_fence,
                                    )
                                    .await
                            }
                        };
                        let acquired_phase_one_reservation = match accepted {
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Reserved(reservation)) => reservation,
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Materialized { .. }) => {
                                // Exact durable replay: never enqueue a second
                                // copy or re-run preprocessing/providers.
                                let queue = driver_input_queue
                                    .snapshot()
                                    .await
                                    .into_iter()
                                    .map(queue_item_to_proto)
                                    .collect();
                                let target = foreground_input_target
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                                    .clone();
                                let _ = respond_to.send(Ok((
                                    proto::QueueItem {
                                        id: receipt.id,
                                        status: proto::QueueItemStatus::Folding,
                                        text: submission.text.clone(),
                                        display_text: submission.display_text.clone(),
                                        target: queue_target_to_proto(target),
                                    },
                                    queue,
                                )));
                                continue;
                            }
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Terminal { reason }) => {
                                let _ = respond_to.send(Err(text_artifact_terminal_error(reason)));
                                continue;
                            }
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::RunInvocationRejected(reason)) => {
                                let error = match reason {
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationReject::IdempotencyConflict => proto::ErrorPayload {
                                        code: proto::ErrorCode::IdempotencyConflict,
                                        message: "client_submission_id was already used with different content".to_owned(),
                                    },
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationReject::ClientSubmissionIdUnavailable => proto::ErrorPayload {
                                        code: proto::ErrorCode::ClientSubmissionIdUnavailable,
                                        message: "client_submission_id is unavailable".to_owned(),
                                    },
                                    crate::db::db::text_artifacts::TextArtifactRunInvocationReject::CapacityExceeded => proto::ErrorPayload {
                                        code: proto::ErrorCode::InvocationCapacityExceeded,
                                        message: "invocation capacity exceeded".to_owned(),
                                    },
                                };
                                let _ = respond_to.send(Err(error));
                                continue;
                            }
                            Ok(crate::db::db::text_artifacts::TextArtifactPhaseOneResult::Conflict) => {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                    code: proto::ErrorCode::IdempotencyConflict,
                                    message: "client submission id conflicts with an existing oversized message"
                                        .to_owned(),
                                }));
                                continue;
                            }
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                    "oversized FCM2 receipt/reservation composition failed");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::UserMessageNotAccepted,
                                    "could not durably admit oversized user message; retry",
                                )));
                                continue;
                            }
                        };
                        phase_one_reservation = Some(acquired_phase_one_reservation);
                        // The in-memory queue is deliberately not an authority
                        // for this path. Preserve the receipt-keyed durable
                        // identity through every enqueue/requeue so a later
                        // reservation lookup returning None is terminal, not
                        // permission to use the legacy inline route.
                        submission.pending_terminal_disposition = Some(
                            crate::engine::message::PendingSubmissionTerminalDisposition::OversizedTextArtifact,
                        );
                    }
                    // FCM2 artifact admissions use the message receipt triple
                    // above as their sole durable authority. Never consult the
                    // legacy client-submission receipt family for them.
                    if artifact_admission.is_none() {
                        let terminal_receipt = match session
                            .db
                            .client_submission_terminal_receipt(session_id, receipt.id)
                            .await
                        {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                "terminal client submission lookup failed; refusing ambiguous enqueue");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::Internal,
                                    "could not verify whether this message was already terminated; retry",
                                )));
                                continue;
                            }
                        };
                        if let Some(terminal) = terminal_receipt {
                            if terminal.origin_principal != receipt.origin_principal
                                || terminal.fingerprint != receipt.fingerprint
                            {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!(
                                    "client_submission_id {} was already used for a different payload",
                                    receipt.id
                                ),
                            }));
                            } else {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::UserMessageTerminated,
                                message: format!(
                                    "client_submission_id {} is terminal ({}) and will not be executed",
                                    receipt.id,
                                    terminal.disposition.as_str()
                                ),
                            }));
                            }
                            continue;
                        }
                    }
                    // Early durable-receipt conflict check: a same-UUID
                    // different-content conflict must be rejected with
                    // BadRequest before any driver interaction (persist,
                    // redaction refresh, round limits). Otherwise a driver
                    // availability failure masks the conflict with
                    // UserMessageNotAccepted instead of the correct BadRequest.
                    // Duplicate detection remains at the original post-driver
                    // check below so the full duplicate path (remote operation
                    // resolution, queue snapshot) is unchanged.
                    if artifact_admission.is_none() {
                        if let Ok(Some(durable)) = session
                            .db
                            .client_submission_receipt(session_id, receipt.id)
                            .await
                        {
                            if durable.origin_principal != receipt.origin_principal
                                || durable.fingerprint != receipt.fingerprint
                            {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                    code: proto::ErrorCode::BadRequest,
                                    message: format!(
                                        "client_submission_id {} was already used for a different payload",
                                        receipt.id
                                    ),
                                }));
                                continue;
                            }
                        }
                    }
                    if artifact_admission.is_none()
                        && let Some(state) = repair_required
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone()
                    {
                        let ids = if state.failing_tool_call_ids.is_empty() {
                            "unknown tool id".to_string()
                        } else {
                            state.failing_tool_call_ids.join(", ")
                        };
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::Notice {
                                session_id,
                                text: format!(
                                    "Read-only resume: refusing to send model context until Responses repair is resolved ({}: {}). Use the resume repair dialog, fork, or export a debug bundle.",
                                    state.failure_kind, ids
                                ),
                            },
                            NoticeSource::DaemonDirect,
                        );
                        let _ = respond_to.send(Err(proto::ErrorPayload {
                            code: proto::ErrorCode::UserMessageNotAccepted,
                            message: format!(
                                "session resume requires explicit repair before accepting message {client_submission_id}"
                            ),
                        }));
                        continue;
                    }
                    // Lazy persistence (session-id-display-and-lazy-persist): the
                    // first user message is what commits the `sessions` row.
                    // Flush it *before* `touch()` and before the driver runs, so
                    // the row exists ahead of any dependent write (tool_calls,
                    // inference_calls, locks). A persist failure aborts the
                    // message rather than letting dependents reference a missing
                    // row.
                    match session.persist_if_needed() {
                        Ok(_) => {}
                        Err(e) => {
                            let error = format!("{e:#}");
                            let database_rejection = user_message_database_error(
                                &e,
                                proto::ErrorCode::UserMessageNotAccepted,
                                format!(
                                    "session persistence failed before accepting message {client_submission_id}: {error}"
                                ),
                            );
                            tracing::error!(error = %error, session_id = %session_id,
                            "persisting session on first message failed; dropping message");
                            send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::SessionPersistFailed {
                                    session_id,
                                    client_submission_id,
                                    error: error.clone(),
                                },
                            );
                            let rejection = match phase_one_reservation.take() {
                                Some(reservation) => reject_oversized_text_artifact_admission(
                                    &session,
                                    reservation,
                                    crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                                )
                                .await,
                                None => database_rejection,
                            };
                            let _ = respond_to.send(Err(rejection));
                            continue;
                        }
                    }
                    if let Err(e) = session.touch() {
                        tracing::warn!(error = %e, "session touch failed");
                    }
                    let session_env = env_overlay
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    let base_redact = {
                        let snapshot = config_snapshot
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        snapshot.extended.redact.clone()
                    };
                    if !refresh_redaction_for_turn(
                        &session,
                        session_id,
                        &project_root,
                        base_redact,
                        &redaction_overrides,
                        &mut unsupported_redaction_notified,
                        &redaction,
                        &interrupts,
                        &event_tx,
                        &driver_control_tx,
                        &session_env,
                    )
                    .await
                    {
                        emit_session_driver_failed_once(
                            &event_tx,
                            &turn_completions,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                            "driver control channel closed".to_string(),
                        );
                        let rejection = match phase_one_reservation.take() {
                            Some(reservation) => reject_oversized_text_artifact_admission(
                                &session,
                                reservation,
                                crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                            )
                            .await,
                            None => proto::ErrorPayload {
                                code: proto::ErrorCode::UserMessageNotAccepted,
                                message: format!(
                                    "session driver became unavailable before accepting message {client_submission_id} while refreshing redaction"
                                ),
                            },
                        };
                        let _ = respond_to.send(Err(rejection));
                        break WorkerStop::DriverFailed;
                    }
                    let max_primary_rounds = {
                        let snapshot = config_snapshot
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        max_primary_rounds_for(&snapshot.extended)
                    };
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetMaxPrimaryRounds {
                            max_primary_rounds,
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        let rejection = match phase_one_reservation.take() {
                            Some(reservation) => reject_oversized_text_artifact_admission(
                                &session,
                                reservation,
                                crate::db::db::text_artifacts::TextArtifactRejectReason::PersistenceFailed,
                            )
                            .await,
                            None => proto::ErrorPayload {
                                code: proto::ErrorCode::UserMessageNotAccepted,
                                message: format!(
                                    "session driver became unavailable before accepting message {client_submission_id} while applying round limits"
                                ),
                            },
                        };
                        let _ = respond_to.send(Err(rejection));
                        break WorkerStop::DriverFailed;
                    }
                    let target = foreground_input_target
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    let receipt = submission
                        .client_submissions
                        .first()
                        .cloned()
                        .expect("wire user submissions carry a client receipt");
                    if artifact_admission.is_none() {
                        let durable_receipt = match session
                            .db
                            .client_submission_receipt(session_id, receipt.id)
                            .await
                        {
                            Ok(receipt) => receipt,
                            Err(error) => {
                                tracing::warn!(%error, %session_id, client_submission_id = %receipt.id,
                                "client submission dedupe lookup failed; refusing ambiguous enqueue");
                                let _ = respond_to.send(Err(user_message_database_error(
                                    &error,
                                    proto::ErrorCode::Internal,
                                    "could not verify whether this message was already accepted; retry",
                                )));
                                continue;
                            }
                        };
                        if let Some(durable_receipt) = durable_receipt {
                            if durable_receipt.origin_principal != receipt.origin_principal
                                || durable_receipt.fingerprint != receipt.fingerprint
                            {
                                let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!(
                                    "client_submission_id {} was already used for a different payload",
                                    receipt.id
                                ),
                            }));
                                continue;
                            }
                            // The submission is already durable. For an authenticated
                            // remote send, still resolve its operation identity through
                            // the transactional ledger (#3) — record a fresh operation,
                            // replay an already-committed one, or reject an
                            // operation/actor conflict — but NEVER enqueue a second copy.
                            #[cfg(feature = "remote")]
                            if let Some(remote) = remote_operation.as_ref() {
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        let _ = respond_to.send(Err(error));
                                        continue;
                                    }
                                }
                            }
                            let queue = driver_input_queue
                                .snapshot()
                                .await
                                .into_iter()
                                .map(queue_item_to_proto)
                                .collect();
                            let _ = respond_to.send(Ok((
                                proto::QueueItem {
                                    id: receipt.id,
                                    status: proto::QueueItemStatus::Folding,
                                    text: submission.text.clone(),
                                    display_text: submission.display_text.clone(),
                                    target: queue_target_to_proto(target),
                                },
                                queue,
                            )));
                            continue;
                        }
                    }
                    if let (Some(expected_generation), Some(expected_model)) = (
                        submission.expected_model_state_generation,
                        submission.expected_model.as_ref(),
                    ) {
                        let current = authoritative_active_model_state
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone();
                        let matches = model_fence_allows_insert(
                            current.as_ref(),
                            expected_generation,
                            expected_model,
                        );
                        if !matches {
                            let rejection = match phase_one_reservation.take() {
                                Some(reservation) => {
                                    reject_oversized_text_artifact_admission(
                                        &session,
                                        reservation,
                                        crate::db::db::text_artifacts::TextArtifactRejectReason::PreflightRejected,
                                    )
                                    .await
                                }
                                None => proto::ErrorPayload {
                                    code: proto::ErrorCode::ModelGenerationStale,
                                    message: "captured model generation is no longer active"
                                        .to_string(),
                                },
                            };
                            let _ = respond_to.send(Err(rejection));
                            continue;
                        }
                    }
                    // Authenticated remote send: commit the transactional
                    // remote-operation ledger (FCM2 identity) on THIS worker
                    // ACCEPT path (never a dispatch-arm shim — AC5). Make the
                    // in-memory dedup decision FIRST with a NON-mutating peek so
                    // a conflicting or already-accepted submission never commits
                    // a fresh ledger row (#2): only a genuine fresh accept both
                    // commits the ledger AND enqueues; a duplicate records/replays
                    // the operation WITHOUT a second enqueue (#3); a conflict is
                    // rejected with no ledger row. This runs after the terminal /
                    // durable-receipt / model-fence checks above.
                    #[cfg(feature = "remote")]
                    if let Some(remote) = remote_operation.as_ref() {
                        let (peek, snapshot) = driver_input_queue
                            .peek_idempotent(
                                receipt.id,
                                &receipt.fingerprint,
                                receipt.origin_principal.as_deref(),
                            )
                            .await;
                        match peek {
                            crate::engine::message::IdempotentPush::Conflict => {
                                let rejection = match phase_one_reservation.take() {
                                    Some(reservation) => {
                                        reject_oversized_text_artifact_admission(
                                            &session,
                                            reservation,
                                            crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict,
                                        )
                                        .await
                                    }
                                    None => proto::ErrorPayload {
                                        code: proto::ErrorCode::BadRequest,
                                        message: format!(
                                            "client_submission_id {} was already used for a different payload",
                                            receipt.id
                                        ),
                                    },
                                };
                                let _ = respond_to.send(Err(rejection));
                                continue;
                            }
                            crate::engine::message::IdempotentPush::Duplicate => {
                                // Already accepted this epoch (not yet durable):
                                // record/replay the operation, never re-enqueue.
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                        let queue: Vec<proto::QueueItem> =
                                            snapshot.into_iter().map(queue_item_to_proto).collect();
                                        let item = queue
                                            .iter()
                                            .find(|item| item.id == receipt.id)
                                            .cloned()
                                            .unwrap_or(proto::QueueItem {
                                                id: receipt.id,
                                                status: proto::QueueItemStatus::Folding,
                                                text: submission.text.clone(),
                                                display_text: submission.display_text.clone(),
                                                target: queue_target_to_proto(target),
                                            });
                                        let _ = respond_to.send(Ok((item, queue)));
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        let _ = respond_to.send(Err(error));
                                    }
                                }
                                continue;
                            }
                            crate::engine::message::IdempotentPush::Inserted => {
                                // Genuine fresh acceptance: commit the ledger,
                                // THEN enqueue below. A conflict/failure here
                                // rejects without enqueuing.
                                match reserve_remote_send_operation(&session.db, remote).await {
                                    RemoteSendDecision::Accepted | RemoteSendDecision::Replayed => {
                                    }
                                    RemoteSendDecision::Rejected(error) => {
                                        // This is a fresh in-memory insertion
                                        // owner. Unlike Duplicate above, it
                                        // still owns the phase-one FCM2 lease
                                        // and must atomically reject/release it
                                        // (including a bound run invocation).
                                        let rejection = match phase_one_reservation.take() {
                                            Some(reservation) => {
                                                reject_oversized_text_artifact_admission(
                                                    &session,
                                                    reservation,
                                                    remote_send_rejection_reason(&error),
                                                )
                                                .await
                                            }
                                            None => error,
                                        };
                                        let _ = respond_to.send(Err(rejection));
                                        continue;
                                    }
                                }
                            }
                        }
                    }
                    let (id, snapshot, outcome) = driver_input_queue
                        .push_idempotent(receipt, *submission, target)
                        .await;
                    if matches!(outcome, crate::engine::message::IdempotentPush::Conflict) {
                        let rejection = match phase_one_reservation.take() {
                            Some(reservation) => reject_oversized_text_artifact_admission(
                                &session,
                                reservation,
                                crate::db::db::text_artifacts::TextArtifactRejectReason::IdempotencyConflict,
                            )
                            .await,
                            None => proto::ErrorPayload {
                                code: proto::ErrorCode::BadRequest,
                                message: format!(
                                    "client_submission_id {} was already used for a different payload",
                                    id
                                ),
                            },
                        };
                        let _ = respond_to.send(Err(rejection));
                        continue;
                    }
                    let queue: Vec<proto::QueueItem> =
                        snapshot.into_iter().map(queue_item_to_proto).collect();
                    let item = queue.iter().find(|item| item.id == id).cloned().unwrap_or(
                        proto::QueueItem {
                            id,
                            status: proto::QueueItemStatus::Folding,
                            text: String::new(),
                            display_text: None,
                            target: proto::QueueTarget::default(),
                        },
                    );
                    let _ = respond_to.send(Ok((item, queue)));
                }
                SessionWork::EmitRecoveredDefaultTerminals { transactions } => {
                    // Best effort: if the driver is gone there is no terminal
                    // gate left to satisfy, and the converged durable state is
                    // already what the next attach will serve.
                    let _ = send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::EmitRecoveredDefaultTerminals {
                            transactions,
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await;
                }
                SessionWork::SteerDelegation {
                    task_call_id,
                    label,
                    message,
                    origin_principal,
                    respond_to,
                } => {
                    let result = steer_delegation_side_channel(
                        &session,
                        &redact,
                        task_call_id,
                        label,
                        message,
                        origin_principal,
                    )
                    .await;
                    let _ = respond_to.send(result);
                }
                SessionWork::RemoveQueuedUserMessage {
                    queue_item_id,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    respond_to,
                } => {
                    let (result, staged, mut snapshot) =
                        match driver_input_queue.stage_remove(queue_item_id).await {
                            Ok(staged) => staged,
                            Err(_) => {
                                let _ = respond_to.send(Err(queue_removal_in_progress_error()));
                                continue;
                            }
                        };
                    #[cfg(feature = "remote")]
                    if let Some(operation) = remote_operation {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let receipts = if let Some(staged) = staged.as_ref() {
                            driver_input_queue.accepted_receipts(staged.ids()).await
                        } else {
                            Vec::new()
                        };
                        if let Some(staged) = staged.as_ref()
                            && receipts.is_empty()
                        {
                            driver_input_queue.mark_staged_removal_failed(staged).await;
                            let _ = respond_to.send(Err(proto::ErrorPayload {
                                code: proto::ErrorCode::Internal,
                                message: "queued message lacks its durable acceptance receipt; removal remains held".into(),
                            }));
                            continue;
                        }
                        let terminal_receipts = receipts
                            .iter()
                            .map(|receipt| {
                                crate::db::session_log::ClientSubmissionTerminalReceipt {
                                    client_submission_id: receipt.id,
                                    fingerprint: receipt.fingerprint.clone(),
                                    wire_fingerprint: receipt.wire_fingerprint.clone(),
                                    origin_principal: receipt.origin_principal.clone(),
                                    disposition,
                                }
                            })
                            .collect::<Vec<_>>();
                        let reason = remove_reason_to_proto(result);
                        let receipt = RemoteQueueMutationReceiptV1 {
                            schema_version: 1,
                            applied: matches!(
                                reason,
                                proto::RemoveQueuedUserMessageReason::Removed
                            ),
                            reason,
                            removed_count: u32::from(staged.is_some()),
                        };
                        let now_ms = chrono::Utc::now().timestamp_millis();
                        let outcome = session.db.execute_transactional_remote_operation(
                            crate::db::remote_attachment_operations::ReserveRemoteOperation {
                                logical_attachment_id: &operation.logical_attachment_id,
                                operation_id: &operation.operation_id,
                                authenticated_device_id: &operation.authenticated_device_id,
                                authenticated_device_generation: operation.authenticated_device_generation,
                                operation_class: crate::db::remote_attachment_operations::RemoteOperationClass::TransactionalMutation,
                                request_hash: operation.request_hash,
                                now_ms,
                            },
                            move |conn| {
                                crate::db::Db::terminalize_queued_text_artifact_submissions_conn(
                                    conn,
                                    session_id,
                                    &terminal_receipts,
                                    now_ms,
                                )?;
                                receipt.validate()?;
                                let safe_response = serde_json::to_vec(&receipt)?;
                                Ok(crate::db::remote_attachment_operations::TransactionalRemoteMutation {
                                    value: receipt,
                                    safe_response: safe_response.clone(),
                                    outbox_kind: "remove_queued_user_message".into(),
                                    outbox_payload: safe_response,
                                })
                            },
                        ).await;
                        let receipt = match outcome {
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Applied(receipt)) => {
                                if let Some(staged) = staged {
                                    let _ = commit_staged_removal_after_receipts(&session, &driver_input_queue, staged, &receipts).await;
                                    send_terminal_receipts_event(&event_tx, &redaction, session_id, &receipts, disposition);
                                }
                                receipt
                            }
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::Replay(bytes)) => match serde_json::from_slice::<RemoteQueueMutationReceiptV1>(&bytes) {
                                Ok(receipt) => {
                                    if let Err(error) = receipt.validate() {
                                        let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() }));
                                        continue;
                                    }
                                    if let Some(staged) = staged {
                                        let _ = commit_staged_removal_after_receipts(&session, &driver_input_queue, staged, &receipts).await;
                                    }
                                    receipt
                                }
                                Err(error) => { let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Internal, message: error.to_string() })); continue; }
                            },
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::OperationActorConflict | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::ExistingIndeterminate) => {
                                if let Some(staged) = staged.as_ref() { driver_input_queue.abort_staged_removal(staged).await; }
                                let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation conflict".into() })); continue;
                            }
                            Ok(crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity | crate::db::remote_attachment_operations::TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity) => {
                                if let Some(staged) = staged.as_ref() { driver_input_queue.mark_staged_removal_failed(staged).await; }
                                let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Conflict, message: "remote operation capacity reached".into() })); continue;
                            }
                            Err(_) => {
                                if let Some(staged) = staged.as_ref() { driver_input_queue.mark_staged_removal_failed(staged).await; }
                                let _ = respond_to.send(Err(proto::ErrorPayload { code: proto::ErrorCode::Internal, message: "remote queue operation could not be committed".into() })); continue;
                            }
                        };
                        let _ = respond_to.send(Ok(remote_queue_mutation_response(receipt)));
                        continue;
                    }
                    if let Some(staged) = staged {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let (_, committed_snapshot, receipts) =
                            match persist_staged_terminal_removal(
                                &session,
                                &driver_input_queue,
                                staged,
                                disposition,
                            )
                            .await
                            {
                                Ok(committed) => committed,
                                Err(error) => {
                                    let _ = respond_to.send(Err(error));
                                    continue;
                                }
                            };
                        snapshot = committed_snapshot;
                        send_terminal_receipts_event(
                            &event_tx,
                            &redaction,
                            session_id,
                            &receipts,
                            disposition,
                        );
                    }
                    let reason = remove_reason_to_proto(result);
                    let _ = respond_to.send(Ok(proto::RemoveQueuedUserMessageResult {
                        applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                        reason,
                        removed_item: None,
                        queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                    }));
                }
                SessionWork::RemoveNewestQueuedUserMessage {
                    target_id,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    respond_to,
                } => {
                    let target_id = target_id.unwrap_or_else(|| {
                        foreground_input_target
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .id
                            .clone()
                    });
                    let (result, staged, mut snapshot) =
                        match driver_input_queue.stage_remove_newest_for(&target_id).await {
                            Ok(staged) => staged,
                            Err(_) => {
                                let _ = respond_to.send(Err(queue_removal_in_progress_error()));
                                continue;
                            }
                        };
                    #[cfg(feature = "remote")]
                    if let Some(operation) = remote_operation {
                        match commit_remote_queue_mutation(RemoteQueueMutationCommit {
                            session: &session,
                            queue: &driver_input_queue,
                            staged,
                            result,
                            operation,
                            outbox_kind: "remove_newest_queued_user_message",
                            event_tx: &event_tx,
                            redaction: &redaction,
                        })
                        .await
                        {
                            Ok(receipt) => {
                                let _ =
                                    respond_to.send(Ok(remote_queue_mutation_response(receipt)));
                            }
                            Err(error) => {
                                let _ = respond_to.send(Err(error));
                            }
                        }
                        continue;
                    }
                    let mut removed_item = None;
                    if let Some(staged) = staged {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let (mut removed, committed_snapshot, receipts) =
                            match persist_staged_terminal_removal(
                                &session,
                                &driver_input_queue,
                                staged,
                                disposition,
                            )
                            .await
                            {
                                Ok(committed) => committed,
                                Err(error) => {
                                    let _ = respond_to.send(Err(error));
                                    continue;
                                }
                            };
                        snapshot = committed_snapshot;
                        removed_item = removed.pop();
                        send_terminal_receipts_event(
                            &event_tx,
                            &redaction,
                            session_id,
                            &receipts,
                            disposition,
                        );
                    }
                    let reason = remove_reason_to_proto(result);
                    let _ = respond_to.send(Ok(proto::RemoveQueuedUserMessageResult {
                        applied: matches!(reason, proto::RemoveQueuedUserMessageReason::Removed),
                        reason,
                        removed_item: removed_item.map(queue_item_to_proto),
                        queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                    }));
                }
                SessionWork::RemoveEditableQueuedUserMessages {
                    target_id,
                    #[cfg(feature = "remote")]
                    remote_operation,
                    respond_to,
                } => {
                    let target_id = target_id.unwrap_or_else(|| {
                        foreground_input_target
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .id
                            .clone()
                    });
                    let (result, staged, mut snapshot) = match driver_input_queue
                        .stage_remove_editable_for(&target_id)
                        .await
                    {
                        Ok(staged) => staged,
                        Err(_) => {
                            let _ = respond_to.send(Err(queue_removal_in_progress_error()));
                            continue;
                        }
                    };
                    #[cfg(feature = "remote")]
                    if let Some(operation) = remote_operation {
                        match commit_remote_queue_mutation(RemoteQueueMutationCommit {
                            session: &session,
                            queue: &driver_input_queue,
                            staged,
                            result,
                            operation,
                            outbox_kind: "remove_editable_queued_user_messages",
                            event_tx: &event_tx,
                            redaction: &redaction,
                        })
                        .await
                        {
                            Ok(receipt) => {
                                let _ =
                                    respond_to.send(Ok(proto::RemoveQueuedUserMessagesResult {
                                        applied: receipt.applied,
                                        reason: receipt.reason,
                                        removed_items: Vec::new(),
                                        queue: Vec::new(),
                                    }));
                            }
                            Err(error) => {
                                let _ = respond_to.send(Err(error));
                            }
                        }
                        continue;
                    }
                    let mut removed_items = Vec::new();
                    if let Some(staged) = staged {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Removed;
                        let (removed, committed_snapshot, receipts) =
                            match persist_staged_terminal_removal(
                                &session,
                                &driver_input_queue,
                                staged,
                                disposition,
                            )
                            .await
                            {
                                Ok(committed) => committed,
                                Err(error) => {
                                    let _ = respond_to.send(Err(error));
                                    continue;
                                }
                            };
                        removed_items = removed;
                        snapshot = committed_snapshot;
                        send_terminal_receipts_event(
                            &event_tx,
                            &redaction,
                            session_id,
                            &receipts,
                            disposition,
                        );
                    }
                    let reason = remove_reason_to_proto(result);
                    let _ = respond_to.send(Ok(proto::RemoveQueuedUserMessagesResult {
                        applied: !removed_items.is_empty(),
                        reason,
                        removed_items: removed_items.into_iter().map(queue_item_to_proto).collect(),
                        queue: snapshot.into_iter().map(queue_item_to_proto).collect(),
                    }));
                }
                SessionWork::RepublishQueue => {
                    driver_input_queue.republish().await;
                }
                SessionWork::Cancel => {
                    // User ctrl+c (`CancelTurn`). Fire the in-flight run's
                    // cancellation token: the driver's `turn` aborts the
                    // streaming inference (returning an `InferenceCancelled`
                    // sentinel that unwinds the run cleanly), and any running
                    // `bash` subprocess is killed via its process group. Safe
                    // and idempotent at idle / mid-cancel — `CancelHandle::cancel`
                    // is a no-op when no run is in flight. The driver then emits
                    // `AgentIdle`, clearing the TUI's busy state.
                    tracing::info!(session_id = %session_id, "cancel requested");
                    if let Some(staged) = driver_input_queue.stage_discard_pending().await {
                        let disposition =
                            crate::db::session_log::ClientSubmissionTerminalDisposition::Cancelled;
                        match persist_staged_terminal_removal(
                            &session,
                            &driver_input_queue,
                            staged,
                            disposition,
                        )
                        .await
                        {
                            Ok((_, _, receipts)) => send_terminal_receipts_event(
                                &event_tx,
                                &redaction,
                                session_id,
                                &receipts,
                                disposition,
                            ),
                            Err(_) => send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: "Could not durably cancel queued messages; their exact payloads remain held. Retry cancellation after storage recovers."
                                        .to_string(),
                                },
                            ),
                        }
                    }
                    cancel_handle.cancel();
                }
                SessionWork::ResolveInterrupt {
                    interrupt_id,
                    response,
                } => {
                    let row = session.db.get_interrupt(interrupt_id).await.ok().flatten();
                    let was_active = session
                        .db
                        .list_open_interrupts(session_id)
                        .await
                        .ok()
                        .and_then(|open| open.first().map(|row| row.interrupt_id))
                        == Some(interrupt_id);
                    let decision = row.as_ref().map(|row| {
                        crate::db::needs_attention::summarize_interrupt_decision(row, &response)
                    });
                    if let Some(row) = row.as_ref()
                        && row.state == crate::db::needs_attention::InterruptState::Parked
                    {
                        let claimed = match session
                            .db
                            .begin_parked_interrupt_execution(interrupt_id, &response)
                            .await
                        {
                            Ok(claimed) => claimed,
                            Err(error) => {
                                tracing::warn!(%error, %interrupt_id, "claiming parked interrupt failed");
                                false
                            }
                        };
                        if !claimed {
                            interrupts.emit_queue_state().await;
                            continue;
                        }
                        // Process-boundary lifecycle tests kill the daemon while
                        // a parked replay is durably `executing`. The hook is
                        // debug-build + env-gated, so release production binaries
                        // cannot enter this pause.
                        if cfg!(debug_assertions)
                            && std::env::var_os("COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING")
                                .is_some()
                        {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                            }
                        }
                        let Some(payload) = row.parked.clone() else {
                            let _ = session.db.mark_interrupt_interrupted(interrupt_id).await;
                            send_current_session_event(
                                &session,
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: format!(
                                        "Interrupted parked request {interrupt_id}: missing replay payload."
                                    ),
                                },
                                NoticeSource::DaemonDirect,
                            );
                            interrupts.emit_queue_state().await;
                            continue;
                        };
                        let Some(questions) = row.questions.clone().or_else(|| {
                            row.question.clone().map(|question| {
                                crate::daemon::proto::InterruptQuestionSet {
                                    questions: vec![question],
                                }
                            })
                        }) else {
                            let _ = session.db.mark_interrupt_interrupted(interrupt_id).await;
                            send_current_session_event(
                                &session,
                                &event_tx,
                                &redaction,
                                proto::Event::Notice {
                                    session_id,
                                    text: format!(
                                        "Interrupted parked request {interrupt_id}: missing replay question."
                                    ),
                                },
                                NoticeSource::DaemonDirect,
                            );
                            interrupts.emit_queue_state().await;
                            continue;
                        };
                        let occurrence = match session
                            .db
                            .interrupt_question_occurrence(interrupt_id)
                            .await
                        {
                            Ok(occurrence) => occurrence,
                            Err(error) => {
                                tracing::warn!(
                                    %error,
                                    %interrupt_id,
                                    "failed to compute parked interrupt replay occurrence; using first occurrence"
                                );
                                1
                            }
                        };
                        let question = crate::engine::interrupt::PreResolvedInterruptQuestion {
                            agent: row.agent_id.clone(),
                            description: row.description.clone(),
                            questions,
                            occurrence,
                        };
                        let driver_control_tx = driver_control_tx.clone();
                        let replay_completion_tx = replay_completion_tx.clone();
                        let replay_response = response.clone();
                        tokio::spawn(async move {
                            let (respond_to, replay_result_rx) = tokio::sync::oneshot::channel();
                            let result = if driver_control_tx
                                .send(
                                    crate::engine::driver::DriverControl::ReplayParkedInterrupt {
                                        interrupt_id,
                                        payload: Box::new(payload),
                                        response: replay_response,
                                        question: Box::new(question),
                                        respond_to,
                                    },
                                )
                                .await
                                .is_ok()
                            {
                                replay_result_rx.await.unwrap_or_else(|error| {
                                    Err(format!("driver replay response dropped: {error}"))
                                })
                            } else {
                                Err("driver is not available for parked interrupt replay"
                                    .to_string())
                            };
                            let _ = replay_completion_tx
                                .send(ParkedReplayCompletion {
                                    interrupt_id,
                                    decision,
                                    was_active,
                                    result,
                                })
                                .await;
                        });
                        continue;
                    }
                    if let Err(e) = session.db.resolve_interrupt(interrupt_id, &response).await {
                        tracing::warn!(error = %e, %interrupt_id, "resolve_interrupt failed");
                        interrupts.emit_queue_state().await;
                        continue;
                    }
                    let seq = decision.as_ref().and_then(|decision| {
                        record_interrupt_decision_event(
                            &session,
                            &redaction,
                            interrupt_id,
                            decision,
                        )
                    });
                    send_current_event(
                        &event_tx,
                        &redaction,
                        proto::Event::InterruptResolved {
                            session_id,
                            interrupt_id,
                            decision,
                            seq,
                        },
                    );
                    // Engine-side wakeup (GOALS §3b): hand the resolution to
                    // whatever tool call is blocked on this interrupt id (the
                    // `question` tool). `false` just means nobody was blocked
                    // locally — e.g. a `schedule` needs-attention nudge — and the
                    // DB row update above is the only effect.
                    interrupts.resolve(interrupt_id, response);
                    if was_active {
                        interrupts.emit_active_from_db().await;
                    } else {
                        interrupts.emit_queue_state().await;
                    }
                }
                SessionWork::RepairResume { respond_to } => {
                    let Some(state) = repair_required
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone()
                    else {
                        let _ = respond_to.send(Err(
                            "no Responses resume repair is pending for this session".to_string(),
                        ));
                        continue;
                    };
                    let (driver_respond_to, driver_response_rx) = oneshot::channel();
                    if driver_control_tx
                        .send(crate::engine::driver::DriverControl::RepairResume {
                            root_agent: root_agent_name.clone(),
                            respond_to: driver_respond_to,
                        })
                        .await
                        .is_err()
                    {
                        let message = "driver control channel closed".to_string();
                        emit_session_driver_failed_once(
                            &event_tx,
                            &turn_completions,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                            message.clone(),
                        );
                        let _ = respond_to.send(Err(message));
                        break WorkerStop::DriverFailed;
                    }
                    match driver_response_rx.await {
                        Ok(Ok(heal_count)) => {
                            {
                                let mut slot = repair_required
                                    .write()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                *slot = None;
                            }
                            let text = format!(
                                "Responses resume repair approved: synthetic resume heal applied to {heal_count} tool call(s)."
                            );
                            if let Err(error) = session
                                .record_event(
                                    crate::db::session_log::SessionEventKind::UserNote,
                                    Some(&root_agent_name),
                                    None,
                                    &serde_json::json!({
                                        "text": text,
                                        "resume_repair": {
                                            "approved": true,
                                            "failure_kind": state.failure_kind,
                                            "failing_tool_call_ids": state.failing_tool_call_ids,
                                            "provider": state.provider,
                                            "model": state.model,
                                            "wire_api": state.wire_api,
                                            "synthetic_heal_count": heal_count,
                                            "detail": state.detail,
                                        }
                                    }),
                                )
                                .await
                            {
                                tracing::warn!(%error, %session_id, "record resume repair provenance failed");
                            }
                            send_current_session_event(
                                &session,
                                &event_tx,
                                &redaction,
                                proto::Event::Notice { session_id, text },
                                NoticeSource::DaemonDirect,
                            );
                            let _ = respond_to.send(Ok(()));
                        }
                        Ok(Err(message)) => {
                            let _ = respond_to
                                .send(Err(format!("explicit Responses repair failed: {message}")));
                        }
                        Err(error) => {
                            let _ = respond_to
                                .send(Err(format!("explicit Responses repair failed: {error}")));
                        }
                    }
                }
                SessionWork::SetActiveModel {
                    selection_id,
                    selection_deadline,
                    provider,
                    model,
                    persist_as_default,
                    trigger,
                    reasoning_effort,
                    thinking_mode,
                    prompt_cache_retention,
                } => {
                    if std::time::Instant::now() >= selection_deadline {
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::ModelSelectionResult {
                                session_id,
                                selection_id,
                                provider,
                                model,
                                reasoning_effort,
                                thinking_mode,
                                prompt_cache_retention,
                                outcome: proto::ModelSelectionOutcome::Rejected {
                                    user_message: "Model selection timed out before the daemon could apply it; retry from /model.".to_string(),
                                    diagnostic_code: "model_selection_deadline_exceeded".to_string(),
                                },
                            },
                            NoticeSource::DaemonDirect,
                        );
                        tracing::warn!(
                            %session_id,
                            %selection_id,
                            "model selection deadline expired before driver dispatch"
                        );
                        continue;
                    }
                    let rejected_provider = provider.clone();
                    let rejected_model = model.clone();
                    let rejected_reasoning_effort = reasoning_effort.clone();
                    let rejected_thinking_mode = thinking_mode;
                    let rejected_prompt_cache_retention = prompt_cache_retention;
                    // Mid-session model switch (implementation note):
                    // route the new `(provider, model)` to the running driver. The
                    // driver owns the whole daemon-side transaction: build first,
                    // then session/config persistence, then the root-primary swap
                    // and authoritative active-model state event. Legitimate
                    // config/session drift (for example an on-disk edit while the
                    // session is live) is reported back to every attached client
                    // instead of being silently reconciled here.
                    let terminal_claimed =
                        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let (completion_tx, mut completion_rx) = tokio::sync::oneshot::channel();
                    let sent = send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetActiveModelWithDeadline {
                            selection_id,
                            deadline: selection_deadline,
                            terminal_claimed: terminal_claimed.clone(),
                            completion: completion_tx,
                            provider,
                            model,
                            persist_as_default,
                            trigger,
                            reasoning_effort,
                            thinking_mode,
                            prompt_cache_retention,
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await;
                    let failure = if !sent {
                        Some((
                            "The daemon driver stopped before it could apply the model selection. Retry from /model.",
                            "model_selection_driver_unavailable",
                        ))
                    } else {
                        match tokio::time::timeout_at(
                            tokio::time::Instant::from_std(selection_deadline),
                            &mut completion_rx,
                        )
                        .await
                        {
                            Ok(Ok(())) => None,
                            Ok(Err(_)) => Some((
                                "The daemon driver stopped before it could apply the model selection. Retry from /model.",
                                "model_selection_driver_unavailable",
                            )),
                            Err(_) => Some((
                                "Model selection timed out before the daemon could apply it; retry from /model.",
                                "model_selection_deadline_exceeded",
                            )),
                        }
                    };
                    if let Some((user_message, diagnostic_code)) = failure
                        && !terminal_claimed.swap(true, std::sync::atomic::Ordering::AcqRel)
                    {
                        send_current_session_event(
                            &session,
                            &event_tx,
                            &redaction,
                            proto::Event::ModelSelectionResult {
                                session_id,
                                selection_id,
                                provider: rejected_provider,
                                model: rejected_model,
                                reasoning_effort: rejected_reasoning_effort,
                                thinking_mode: rejected_thinking_mode,
                                prompt_cache_retention: rejected_prompt_cache_retention,
                                outcome: proto::ModelSelectionOutcome::Rejected {
                                    user_message: user_message.to_string(),
                                    diagnostic_code: diagnostic_code.to_string(),
                                },
                            },
                            NoticeSource::DaemonDirect,
                        );
                    }
                    if !sent {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::ReplaceConfigSnapshot {
                    snapshot,
                    respond_to,
                } => {
                    let result = replace_config_snapshot(&config_snapshot, *snapshot);
                    let changed = result.changed;
                    send_config_snapshot_event_if_changed(
                        &event_tx,
                        &redaction,
                        &config_snapshot,
                        session_id,
                        result,
                    );
                    if changed
                        && !send_driver_control_or_fail(
                            &driver_control_tx,
                            crate::engine::driver::DriverControl::RefreshConfigDerivedState,
                            &event_tx,
                            &turn_completions,
                            &redaction,
                            session_id,
                            &mut driver_failed,
                        )
                        .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                    let _ = respond_to.send(result);
                }
                SessionWork::SetAgent { name } => {
                    // Persist the active-agent choice so a resume restarts on it,
                    // then swap the live primary in place at the idle boundary
                    // (`/plan` → `Plan`, `/build` → `Build`, `plan.md §4.6.d`).
                    if let Err(e) = session.set_active_agent(&name) {
                        tracing::warn!(error = %e, "set_active_agent failed");
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SwapPrimary { name },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetLlmMode { mode } => {
                    // Resolve toggle against the current config value (the
                    // single source of truth shared with `/settings` + the
                    // config file), persist the resolved value so a resume keeps
                    // it, then route the explicit mode to the driver to rebuild
                    // the root agent in place.
                    let current = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .extended
                        .llm_mode;
                    let resolved = mode.unwrap_or_else(|| current.cycled());
                    if let Err(e) = persist_llm_mode(&project_root, resolved) {
                        tracing::warn!(error = %e, "persisting llm_mode failed");
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        persistent_llm_mode_control(resolved),
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetSessionLlmMode { mode } => {
                    if let Err(error) = session.set_session_llm_mode(mode) {
                        tracing::warn!(%error, session_id = %session_id, "persisting session llm mode failed");
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        session_llm_mode_control(mode),
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetToolSurfaceOverride {
                    override_json,
                    persist_session,
                    prune_after_switch,
                    monty_nudge,
                } => {
                    let selection = match serde_json::from_str::<crate::agents::ToolSurfaceSelection>(
                        &override_json,
                    ) {
                        Ok(selection) => selection,
                        Err(error) => {
                            tracing::warn!(%error, session_id = %session_id, "invalid tool surface override JSON");
                            let _ = engine_event_notice_tx
                                    .send(TurnEvent::Notice {
                                        text: format!(
                                            "Tool surface update failed — invalid override JSON: {error}"
                                        ),
                                    })
                                    .await;
                            continue;
                        }
                    };
                    if persist_session
                        && let Err(error) =
                            session.set_tool_surface_override_json(Some(override_json.clone()))
                    {
                        tracing::warn!(%error, session_id = %session_id, "persisting tool surface override failed");
                        let _ = engine_event_notice_tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Tool surface update failed — could not persist session override: {error:#}"
                                ),
                            })
                            .await;
                        continue;
                    }
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        tool_surface_override_control(selection, prune_after_switch, monty_nudge),
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetGoalSettingsOverride {
                    override_json,
                    persist_session,
                } => {
                    if let Some(raw) = override_json.as_deref()
                        && let Err(error) = crate::agents::parse_goal_settings_override_json(raw)
                    {
                        tracing::warn!(%error, session_id = %session_id, "invalid goal settings override JSON");
                        let _ = engine_event_notice_tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Goal settings update failed — invalid override JSON: {error}"
                                ),
                            })
                            .await;
                        continue;
                    }
                    if persist_session
                        && let Err(error) =
                            session.set_goal_settings_override_json(override_json.clone())
                    {
                        tracing::warn!(%error, session_id = %session_id, "persisting goal settings override failed");
                        let _ = engine_event_notice_tx
                            .send(TurnEvent::Notice {
                                text: format!(
                                    "Goal settings update failed — could not persist session override: {error:#}"
                                ),
                            })
                            .await;
                        continue;
                    }
                    let _ = engine_event_notice_tx
                        .send(TurnEvent::Notice {
                            text: "Goal settings updated.".to_string(),
                        })
                        .await;
                }
                SessionWork::SetDelegationRecursion {
                    enabled,
                    default_depth,
                } => {
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetDelegationRecursion {
                            enabled,
                            default_depth,
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::SetRedaction {
                    scan_environment,
                    scan_dotenv,
                    scan_ssh_keys,
                    respond_to,
                } => {
                    // `/toggle-redaction`: mutate the session's in-memory
                    // effective `RedactConfig`, rebuild the newly discoverable
                    // redaction table, then union it into the session's
                    // accumulated egress table. Session-only — never persisted.
                    // Turning a source off stops future discovery; it never
                    // removes values already known in this session.
                    //
                    // Prompt-cache note (`prompt-caching-strategy.md`): changing
                    // what's redacted can change the scrubbed bytes of the cached
                    // prefix, so the *next* outbound request after a toggle is a
                    // one-time cache re-warm. This is accepted — the toggle is a
                    // deliberate, rare user action; `scrub()` output is otherwise
                    // deterministic/byte-stable turn-to-turn (see
                    // `redact::tests::scrub_is_deterministic_within_a_session`),
                    // so it never silently varies the prefix between turns.
                    let mut effective_redact = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .extended
                        .redact
                        .clone();
                    redaction_overrides.apply_to(&mut effective_redact);
                    if let Some(v) = scan_environment {
                        redaction_overrides.scan_environment = Some(v);
                        effective_redact.scan_environment = v;
                    }
                    if let Some(v) = scan_dotenv {
                        redaction_overrides.scan_dotenv = Some(v);
                        effective_redact.scan_dotenv = v;
                    }
                    if let Some(v) = scan_ssh_keys {
                        redaction_overrides.scan_ssh_keys = Some(v);
                        effective_redact.scan_ssh_keys = v;
                    }
                    let session_env = env_overlay
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .clone();
                    match session.credential_store().and_then(|store| {
                        crate::redact::RedactionTable::build_with_env_and_credential_store(
                            &effective_redact,
                            &project_root,
                            &session_env,
                            &store,
                        )
                    }) {
                        Ok(new_table) => {
                            // H1: read the LATEST table, union, persist, and swap
                            // under the per-session redaction-table write lock so
                            // this `/toggle-redaction` refresh serializes with
                            // sealed adoption / approved-secret-file registration
                            // and cannot clobber a concurrently-committed adoption.
                            // The guard is released before the driver `.await`.
                            let table = {
                                let _redaction_guard =
                                    interrupts.lock_redaction_table_write().await;
                                let base = current_redaction(&redaction);
                                match base.union(&new_table) {
                                    Ok(unioned) => {
                                        let unioned = Arc::new(unioned);
                                        // J3: persist BEFORE swapping the live table
                                        // so a persist failure never leaves the live
                                        // table advanced ahead of the durable one (a
                                        // restart would lose the accumulated entry).
                                        // On failure keep the previously-committed
                                        // table live and surface the error.
                                        match session.persist_redaction_table(&unioned) {
                                            Ok(()) => {
                                                set_current_redaction(&redaction, unioned.clone());
                                                unioned
                                            }
                                            Err(error) => {
                                                tracing::warn!(error = %error, %session_id, "persisting redaction table failed; keeping previously committed redaction table live");
                                                base
                                            }
                                        }
                                    }
                                    Err(error) => {
                                        // K6: never overwrite the committed table
                                        // (which may hold a sealed literal adopted this
                                        // turn) with a bare disk scan on a union error.
                                        // Keep the committed `base` live and durable and
                                        // defer the disk delta to the next refresh,
                                        // mirroring
                                        // `InterruptHub::refresh_union_redaction`.
                                        tracing::warn!(error = %error, %session_id, "unioning redaction table failed; keeping committed redaction table live");
                                        base
                                    }
                                }
                            };
                            for path in table.unsupported_files() {
                                if unsupported_redaction_notified.insert(path.clone()) {
                                    send_current_session_event(
                                        &session,
                                        &event_tx,
                                        &redaction,
                                        proto::Event::Notice {
                                            session_id,
                                            text: format!(
                                                "`{}` is an unsupported format; redaction for this file will not work",
                                                path.display()
                                            ),
                                        },
                                        NoticeSource::DaemonDirect,
                                    );
                                }
                            }
                            if !send_driver_control_or_fail(
                                &driver_control_tx,
                                crate::engine::driver::DriverControl::SetRedaction {
                                    table,
                                    scan_environment,
                                    scan_dotenv,
                                    scan_ssh_keys,
                                },
                                &event_tx,
                                &turn_completions,
                                &redaction,
                                session_id,
                                &mut driver_failed,
                            )
                            .await
                            {
                                let _ = respond_to
                                    .send(Err("session driver is unavailable".to_string()));
                                break WorkerStop::DriverFailed;
                            }
                            send_current_event(
                                &event_tx,
                                &redaction,
                                proto::Event::RedactionState {
                                    session_id,
                                    scan_environment: effective_redact.scan_environment,
                                    scan_dotenv: effective_redact.scan_dotenv,
                                    scan_ssh_keys: effective_redact.scan_ssh_keys,
                                },
                            );
                            let _ = respond_to.send(Ok((
                                effective_redact.scan_environment,
                                effective_redact.scan_dotenv,
                                effective_redact.scan_ssh_keys,
                            )));
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "rebuilding redaction table failed");
                            let _ = respond_to.send(Err(e.to_string()));
                        }
                    }
                }
                SessionWork::SetPreflight {
                    enabled,
                    respond_to,
                } => {
                    // `/preflight`: resolve the effective value in the worker so the
                    // RPC remains responsive during a running turn, then queue an
                    // explicit driver override and its existing state broadcast. Session-only — never
                    // persisted (mirrors `/toggle-redaction`).
                    let configured = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .extended
                        .preflight
                        .enabled;
                    let target = enabled.unwrap_or(!preflight_override.unwrap_or(configured));
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetPreflight {
                            enabled: Some(target),
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        let _ = respond_to.send(Err("session driver is unavailable".to_string()));
                        break WorkerStop::DriverFailed;
                    }
                    preflight_override = Some(target);
                    let _ = respond_to.send(Ok(target));
                }
                SessionWork::SetLongcache {
                    enabled,
                    respond_to,
                } => {
                    let providers_cfg = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .providers
                        .clone();
                    let target = enabled.unwrap_or(!longcache_enabled);
                    let active_selection = session.active_model_ref();
                    let (active_provider, active_model) = active_selection
                        .as_ref()
                        .map(|active| (active.provider.as_str(), active.model.as_str()))
                        .unwrap_or((
                            initial_model_for_toggles.0.as_str(),
                            initial_model_for_toggles.1.as_str(),
                        ));
                    let supported = providers_cfg
                        .resolve_prompt_cache_retention(
                            active_provider,
                            active_model,
                            Some(crate::config::providers::PromptCacheRetention::Extended),
                        )
                        .is_some();
                    let effective = if target && !supported {
                        longcache_enabled
                    } else {
                        target
                    };
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetLongcache {
                            enabled: Some(target),
                        },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        let _ = respond_to.send(Err("session driver is unavailable".to_string()));
                        break WorkerStop::DriverFailed;
                    }
                    longcache_enabled = effective;
                    let _ = respond_to.send(Ok(effective));
                }
                SessionWork::SetTandemModels { models } => {
                    // `/model-comparison`: build a completion model for each
                    // selected `(provider, model)` from the already-configured
                    // providers, route them to the driver's in-memory tandem set,
                    // and broadcast the resulting state (+ a one-line token-burn
                    // warning when non-empty). Empty disables the feature.
                    // Session-only — never persisted (mirrors `/toggle-redaction`).
                    let providers_cfg = config_snapshot
                        .read()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .providers
                        .clone();
                    // Reuse the session redaction table the registry already
                    // built successfully. Tandem models must never install an
                    // empty fail-open table after a redaction rebuild error.
                    let tandem_redact = redact.clone();
                    let active = (session.active_provider(), session.active_model());
                    let mut targets: Vec<crate::engine::schedule::TandemTarget> = Vec::new();
                    for (provider, model_id) in &models {
                        // Defensive: never shadow the active model itself (the
                        // client already excludes it; no self-shadowing).
                        if active.0.as_deref() == Some(provider.as_str())
                            && active.1.as_deref() == Some(model_id.as_str())
                        {
                            continue;
                        }
                        let session_env = env_overlay
                            .read()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .clone();
                        let store = match session.provider_credential_store(&providers_cfg) {
                            Ok(store) => store,
                            Err(e) => {
                                send_current_session_event(
                                    &session,
                                    &event_tx,
                                    &redaction,
                                    proto::Event::Notice {
                                        session_id,
                                        text: format!(
                                            "model-comparison: skipping `{provider}/{model_id}` — {e:#}"
                                        ),
                                    },
                                    NoticeSource::DaemonDirect,
                                );
                                continue;
                            }
                        };
                        match crate::engine::model::Model::for_provider_with_store(
                            &providers_cfg,
                            provider,
                            model_id,
                            tandem_redact.clone(),
                            |name| session_env.get(name).cloned(),
                            store,
                        ) {
                            Ok(m) => {
                                let m = m.with_shutdown_gate(shutdown_gate.clone());
                                targets.push(crate::engine::schedule::TandemTarget {
                                    provider: provider.clone(),
                                    model: model_id.clone(),
                                    handle: Arc::new(m),
                                });
                            }
                            Err(e) => {
                                // A misconfigured tandem provider/model is skipped
                                // with a notice rather than failing the toggle.
                                send_current_session_event(
                                    &session,
                                    &event_tx,
                                    &redaction,
                                    proto::Event::Notice {
                                        session_id,
                                        text: format!(
                                            "model-comparison: skipping `{provider}/{model_id}` — {e:#}"
                                        ),
                                    },
                                    NoticeSource::DaemonDirect,
                                );
                            }
                        }
                    }
                    let labels: Vec<String> = targets
                        .iter()
                        .map(crate::engine::schedule::TandemTarget::label)
                        .collect();
                    // Token-burn warning on a non-empty set (warning only — no cap,
                    // no meter) for tandem model-comparison fan-out.
                    let warning = (!labels.is_empty()).then(|| {
                    format!(
                        "model-comparison ON: every substantive request is ALSO sent to {} tandem model(s) ({}). This multiplies token spend — it is off by default and reverts on restart.",
                        labels.len(),
                        labels.join(", ")
                    )
                });
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::SetTandemModels { targets },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                    send_current_event(
                        &event_tx,
                        &redaction,
                        proto::Event::TandemState {
                            session_id,
                            models: labels,
                            warning,
                        },
                    );
                }
                SessionWork::CancelSchedule { job_id } => {
                    if job_cmd_tx
                        .send(crate::engine::schedule::ScheduleCommand::Cancel { job_id })
                        .await
                        .is_err()
                    {
                        tracing::warn!(session_id = %session_id, "job command channel closed");
                    }
                }
                SessionWork::Prune => {
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::Prune,
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::Compact => {
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::Compact,
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::Pin { text } => {
                    if !send_driver_control_or_fail(
                        &driver_control_tx,
                        crate::engine::driver::DriverControl::Pin { text },
                        &event_tx,
                        &turn_completions,
                        &redaction,
                        session_id,
                        &mut driver_failed,
                    )
                    .await
                    {
                        break WorkerStop::DriverFailed;
                    }
                }
                SessionWork::Shutdown { pause_for_resume } => {
                    let (active, pending_tool_count, initial_committed) =
                        shutdown_activity_snapshot(&session, session_id, &interrupts, &live).await;
                    shutdown_park_committed = initial_committed;
                    break WorkerStop::Shutdown {
                        pause_for_resume,
                        active,
                        pending_tool_count,
                    };
                }
            },
        }
    };

    // Drain: close the driver input → the driver finishes its current
    // turn (if any) and exits. Then the engine event channel closes
    // and the forwarder task exits.
    //
    // Registration barrier (`daemon-lifecycle-replay-timing-robustness.md`,
    // finding 2): closing the input FIRST admits no new turn, so the in-flight
    // turn can only run to completion or block on an interrupt. On a graceful
    // (resumable) shutdown we then run a park-drain loop — re-parking any
    // interrupt the in-flight turn registers (waking a blocked driver so its
    // turn ends) until the driver task exits — and only THEN report the
    // shutdown park-commit. This closes the TOCTOU where a turn registered a
    // waiter after the drain's initial snapshot: `Committed` is published only
    // once no further registration is possible. The loop is bounded: the input
    // is closed so the turn must terminate, and the drain path force-aborts
    // this worker at its deadline regardless.
    driver_input_queue.close().await;
    let graceful_park = matches!(
        stop,
        WorkerStop::Shutdown {
            pause_for_resume: true,
            ..
        }
    );
    if !driver_joined {
        if graceful_park {
            loop {
                // Park first so a driver blocked on an interrupt is woken
                // immediately (its tool returns Parked → the turn ends).
                let sweep = interrupts.park_all_registered_collect().await;
                shutdown_park_committed = shutdown_park_committed && sweep.all_committed;
                match tokio::time::timeout(PARK_DRAIN_POLL_INTERVAL, &mut driver_handle).await {
                    Ok(join_result) => {
                        let outcome = driver_join_outcome(join_result);
                        if let Some(error) = outcome.failure_error() {
                            tracing::warn!(session_id = %session_id, error = %error, "driver ended during worker drain");
                        }
                        break;
                    }
                    // Driver still running/blocked: re-park (catch a fresh
                    // registration) and keep waiting for it to exit.
                    Err(_) => continue,
                }
            }
        } else {
            let outcome = driver_join_outcome(driver_handle.await);
            if let Some(error) = outcome.failure_error() {
                tracing::warn!(session_id = %session_id, error = %error, "driver ended during worker drain");
            }
        }
    }
    if graceful_park {
        // Final sweep: the driver task has exited, so no further interrupt can
        // be registered. Report the shutdown park-commit exactly once, now that
        // it is sound: every registered-or-registerable interrupt is parked.
        let sweep = interrupts.park_all_registered_collect().await;
        shutdown_park_committed = shutdown_park_committed && sweep.all_committed;
        interrupts.report_shutdown_commit(shutdown_park_committed);
    }
    drop(driver_input_queue);
    drop(engine_event_notice_tx);
    let _ = forward.await;
    let _ = queue_forward.await;

    // `sessionEnd` observe hooks: fire once per worker teardown, at the same
    // boundary that emits `SessionEnded` below. Fired here — after the driver
    // has drained but BEFORE the DB teardown in the `match stop` arms — so the
    // `session.db` ledger write is guaranteed live. The matcher / `endReason`
    // comes from the CLOSED [`WorkerStop::session_end_matcher`] map (never the
    // human-readable proto reason text). Observe-only / fail-open; the registry
    // is cloned from the current snapshot so no lock guard is held across the
    // hook run.
    {
        let end_matcher = stop.session_end_matcher();
        let registry = config_snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .hooks()
            .clone();
        crate::engine::agent::hooks::run_observe_hooks(
            &crate::engine::agent::hooks::TokioCommandRunner::with_optional_containment(
                session.process_containment(),
            ),
            &crate::engine::agent::hooks::DefaultProcessEnv,
            &registry,
            crate::config::extended::hooks::HookEvent::SessionEnd,
            end_matcher,
            session.id,
            &project_root,
            &session.db,
            None,
            None,
            None,
            None,
            crate::engine::agent::hooks::ObserveFields {
                end_reason: Some(end_matcher),
                ..Default::default()
            },
        )
        .await;
    }

    match stop {
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: true,
            pending_tool_count,
        } => {
            if let Err(e) = session
                .db
                .upsert_paused_session_work(
                    session_id,
                    &root_agent_name,
                    &project_root.display().to_string(),
                    "daemon shutdown paused active work",
                    pending_tool_count,
                    proto::DAEMON_VERSION,
                )
                .await
            {
                tracing::warn!(error = %e, "persisting paused session work failed");
            }
        }
        WorkerStop::Shutdown {
            pause_for_resume: true,
            active: false,
            ..
        } => {}
        _ => {
            // Mark session ended in DB for destructive/explicit worker stops. A
            // graceful daemon drain keeps the session resumable instead.
            if let Err(e) = locks.end_session(session_id).await {
                tracing::warn!(error = %e, "lock cleanup failed during terminal session shutdown");
            }
            if let Err(e) = session.end() {
                tracing::warn!(error = %e, "session.end() failed during shutdown");
            }
        }
    }
    send_current_event(
        &event_tx,
        &redaction,
        proto::Event::SessionEnded {
            session_id,
            reason: stop.session_ended_reason().into(),
        },
    );
    tracing::info!(session_id = %session_id, "session worker exited");
}

pub(super) fn model_expectation_matches(
    current: Option<&proto::ActiveModelState>,
    expected_generation: u64,
    expected_model: &cockpit_config::providers::ActiveModelRef,
) -> bool {
    current.is_some_and(|current| {
        current.generation == expected_generation && &current.selection == expected_model
    })
}

pub(super) fn model_fence_allows_insert(
    current: Option<&proto::ActiveModelState>,
    expected_generation: u64,
    expected_model: &cockpit_config::providers::ActiveModelRef,
) -> bool {
    model_expectation_matches(current, expected_generation, expected_model)
}

const DURABLE_ACTIVE_MODEL_FENCE_KEYS: [&str; 5] = [
    "provider",
    "model",
    "reasoning_effort",
    "thinking_mode",
    "prompt_cache_retention",
];

fn decode_durable_model_fence(
    model_json: &str,
) -> anyhow::Result<cockpit_config::providers::ActiveModelRef> {
    let value: serde_json::Value =
        serde_json::from_str(model_json).context("decoding durable oversized model fence")?;
    let object = value
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("durable oversized model fence must be an object"))?;
    anyhow::ensure!(
        object
            .keys()
            .all(|key| DURABLE_ACTIVE_MODEL_FENCE_KEYS.contains(&key.as_str())),
        "durable oversized model fence has unknown fields"
    );
    let model: cockpit_config::providers::ActiveModelRef =
        serde_json::from_value(value).context("decoding typed durable oversized model fence")?;
    model
        .validate()
        .map_err(|error| anyhow::anyhow!(error))
        .context("validating durable oversized model fence")?;
    anyhow::ensure!(
        canonical_durable_model_fence_json(&model)? == model_json,
        "durable oversized model fence is not canonical"
    );
    Ok(model)
}

/// Match the database leaf's canonical JSON representation: serialize the
/// typed DTO into a JSON value first, then render that value.  Direct struct
/// serialization preserves declaration order while the DB validates the
/// parsed `Value` representation, so using the latter on both sides makes a
/// durable fence replay-stable.
fn canonical_durable_model_fence_json(
    model: &cockpit_config::providers::ActiveModelRef,
) -> anyhow::Result<String> {
    serde_json::to_string(&serde_json::to_value(model)?)
        .context("encoding canonical durable oversized model fence")
}

pub(super) fn encode_durable_model_fence(
    model: &cockpit_config::providers::ActiveModelRef,
) -> anyhow::Result<String> {
    model.validate().map_err(|error| anyhow::anyhow!(error))?;
    let encoded = canonical_durable_model_fence_json(model)?;
    let decoded = decode_durable_model_fence(&encoded)?;
    anyhow::ensure!(
        decoded == *model,
        "durable model fence round-trip changed model"
    );
    Ok(encoded)
}

fn update_authoritative_active_model_state(
    state: &Arc<RwLock<Option<proto::ActiveModelState>>>,
    event: &proto::Event,
) {
    let next = match event {
        proto::Event::ActiveModelState {
            selection,
            default_selection,
            diverged,
            generation,
            ..
        } => Some(proto::ActiveModelState {
            selection: selection.clone(),
            default_selection: default_selection.clone(),
            diverged: *diverged,
            generation: *generation,
        }),
        proto::Event::ModelSelectionResult {
            outcome: proto::ModelSelectionOutcome::Applied { active_state, .. },
            ..
        } => Some(proto::ActiveModelState {
            selection: active_state.selection.clone(),
            default_selection: active_state.default_selection.clone(),
            diverged: active_state.diverged,
            generation: active_state.generation,
        }),
        _ => None,
    };
    if let Some(next) = next {
        *state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(next);
    }
}

/// Releasable, debug-build + env-gated injected pause point
/// (`daemon-lifecycle-replay-timing-robustness.md`, matching
/// `COCKPIT_TEST_PAUSE_PARKED_REPLAY_EXECUTING`'s `cfg!(debug_assertions)` +
/// env shape). Sleeps `<var>` milliseconds so a test can force the worst-case
/// drain interleaving deterministically — the park write lands *after* the
/// `--grace` deadline would have fired on the pre-fix code — without relying on
/// host CPU starvation. Bounded/self-releasing, so the fixed drain path still
/// observes a committed park within `INTERRUPT_PARK_COMMIT_DEADLINE`.
/// Compiled out of release binaries entirely.
async fn test_injected_park_delay(_var: &str) {
    #[cfg(debug_assertions)]
    {
        if let Some(ms) =
            std::env::var_os(_var).and_then(|raw| raw.to_str().and_then(|s| s.parse::<u64>().ok()))
        {
            tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
        }
    }
}

pub(super) async fn shutdown_activity_snapshot(
    session: &Session,
    session_id: Uuid,
    interrupts: &crate::engine::interrupt::InterruptHub,
    live: &LiveState,
) -> (bool, i64, bool) {
    // Injected worst-case interleaving for criteria 2/3/8: delay the shutdown
    // park commit so the pre-fix drain path (which released pid/socket at the
    // `--grace` deadline) races ahead of it, while the fixed path awaits the
    // park-commit signal below.
    test_injected_park_delay("COCKPIT_TEST_DELAY_SHUTDOWN_PARK_MS").await;
    // Initial sweep only — the shutdown park-commit is NOT reported here.
    // The worker re-parks (finding 2 registration barrier) and reports once,
    // after the driver task exits, so `Committed` cannot be observed while an
    // in-flight turn could still register a fresh interrupt. The sweep's
    // write-commit status is threaded out so a failed *initial* park (whose
    // waiter is then gone from the map and cannot be re-detected by a later
    // sweep) still surfaces as a non-clean terminal.
    let sweep = interrupts.park_all_registered_collect().await;
    let pending_tool_count = session
        .db
        .list_open_interrupts(session_id)
        .await
        .map(|rows| rows.len() as i64)
        .unwrap_or(sweep.count as i64);
    let active = {
        let (has_schedules, processing) = (live.has_active_schedules(), live.processing());
        has_schedules || processing || pending_tool_count > 0
    };
    (active, pending_tool_count, sweep.all_committed)
}

#[cfg(test)]
mod interrupt_redaction_tests {
    use super::*;

    #[test]
    fn redaction_failure_payload_preserves_shape_without_raw_interrupt_text() {
        let interrupt_id = uuid::Uuid::new_v4();
        let decision = crate::daemon::proto::InterruptDecision {
            permission: true,
            cancelled: false,
            lines: vec![crate::daemon::proto::InterruptDecisionLine {
                prompt: "Run `cat /tmp/secret`?".to_string(),
                answer: "Allow once".to_string(),
            }],
        };

        let payload = redaction_failed_interrupt_decision_payload(interrupt_id, &decision);
        let serialized = payload.to_string();

        assert_eq!(payload["interrupt_id"], interrupt_id.to_string());
        assert_eq!(payload["decision"]["permission"], true);
        assert_eq!(payload["decision"]["cancelled"], false);
        assert_eq!(
            payload["decision"]["lines"][0]["prompt"],
            INTERRUPT_REDACTION_FAILED
        );
        assert_eq!(
            payload["decision"]["lines"][0]["answer"],
            INTERRUPT_REDACTION_FAILED
        );
        assert!(!serialized.contains("/tmp/secret"));
        assert!(!serialized.contains("Allow once"));
    }
}
