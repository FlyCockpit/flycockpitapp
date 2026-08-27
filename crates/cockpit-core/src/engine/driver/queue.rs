use super::*;

/// Drain queued user submissions from the channel without blocking.
/// Stops at the [`MAX_FOLD`] batch cap; anything beyond stays queued.
pub(super) async fn drain_queue(
    rx: &crate::engine::message::UserSubmissionQueue,
    into: &mut Vec<UserSubmission>,
    target_id: &str,
) {
    drain_queue_limit(rx, into, target_id, MAX_FOLD).await;
}

pub(super) async fn drain_queue_limit(
    rx: &crate::engine::message::UserSubmissionQueue,
    into: &mut Vec<UserSubmission>,
    target_id: &str,
    max: usize,
) {
    rx.drain_into_for(into, max, Some(target_id)).await;
}

pub(super) async fn drain_steering_queue(
    rx: &crate::engine::message::UserSubmissionQueue,
    into: &mut Vec<UserSubmission>,
    target_id: &str,
    max: usize,
) {
    rx.drain_into_for_filtered(
        into,
        max,
        Some(target_id),
        crate::engine::message::QueueDrainFilter::Steering,
    )
    .await;
    let remaining = max.saturating_sub(into.len());
    if remaining > 0 {
        rx.drain_into_for_filtered(
            into,
            remaining,
            Some(target_id),
            crate::engine::message::QueueDrainFilter::SendNowHeld,
        )
        .await;
    }
}

/// Run-end / idle: steering (and send-now) first, then held. No item is
/// stranded for this target; `max` still respects fold batching.
pub(super) async fn drain_group_order_queue(
    rx: &crate::engine::message::UserSubmissionQueue,
    into: &mut Vec<UserSubmission>,
    target_id: &str,
    max: usize,
) {
    rx.drain_group_order_into_for(into, max, Some(target_id))
        .await;
}

/// Discard *all* currently-queued user submissions from the channel
/// (no [`MAX_FOLD`] cap, unlike [`drain_queue`]) and report how many were
/// dropped. Used on the ctrl+c cancel-unwind so messages the user queued
/// during the cancelled span never auto-start a fresh turn — the cancel
/// returns the session to idle rather than silently rolling into the next
/// queued message. Non-blocking: only what is already buffered is dropped.
#[cfg(test)]
pub(super) async fn discard_pending_input(
    rx: &crate::engine::message::UserSubmissionQueue,
) -> usize {
    discard_pending_input_with_receipts(rx).await.0
}

#[cfg(test)]
pub(super) async fn discard_pending_input_with_receipts(
    rx: &crate::engine::message::UserSubmissionQueue,
) -> (usize, Vec<crate::engine::message::ClientSubmissionReceipt>) {
    let (dropped, receipts) = rx.discard_pending_with_receipts().await;
    if dropped > 0 {
        tracing::info!(dropped, "discarded queued user messages on cancel");
    }
    (dropped, receipts)
}

/// Header line for a late-arriving async-result delivery
/// (implementation note). Names both the job `kind`
/// (`loop`/`timer`/`background`/`swarm`) and the originating `job_id` (the
/// same `job-…` string `loop.cancel` / `TurnEvent::ScheduleCompleted` use) so the
/// model has an unambiguous referent for a delivery that may land turns away
/// from its trigger. Identical across every job kind.
pub(super) fn async_result_header(kind: &str, job_id: &str) -> String {
    format!("[async result · {kind} · {job_id}]")
}

/// Build the `data` object for a recorded `user_message` timeline event.
/// Always carries `text`; an async-result delivery additionally stamps an
/// optional `job_id` (implementation note) attributing it to
/// its originating job. Additive to the existing `data` shape — no exporter
/// schema bump; ordinary input omits the key entirely.
pub(super) struct UserMessageEventData<'a> {
    pub(super) text: &'a str,
    pub(super) display_text: Option<&'a str>,
    pub(super) tag_expansions: &'a [crate::daemon::proto::TagExpansionMeta],
    pub(super) job_id: Option<&'a str>,
    pub(super) queue_item_ids: &'a [uuid::Uuid],
    pub(super) client_submissions: &'a [crate::engine::message::ClientSubmissionReceipt],
    pub(super) queue_target: Option<&'a crate::engine::message::QueueTarget>,
    pub(super) preflight_cleaned: Option<&'a str>,
}

pub(super) fn user_message_event_data(input: UserMessageEventData<'_>) -> serde_json::Value {
    let UserMessageEventData {
        text,
        display_text,
        tag_expansions,
        job_id,
        queue_item_ids,
        client_submissions,
        queue_target,
        preflight_cleaned,
    } = input;
    let mut data = serde_json::json!({ "text": text });
    if let Some(display_text) = display_text {
        data["display_text"] = serde_json::Value::String(display_text.to_string());
    }
    if !tag_expansions.is_empty() {
        data["tag_expansions"] = serde_json::json!(tag_expansions);
    }
    if let Some(jid) = job_id {
        data["job_id"] = serde_json::Value::String(jid.to_string());
    }
    if !queue_item_ids.is_empty() {
        data["queued"] = serde_json::Value::Bool(true);
        data["queue_item_ids"] = serde_json::json!(queue_item_ids);
        if let Some(target) = queue_target {
            data["queue_target"] = serde_json::json!(target);
        }
        data["preflight_cleaned"] = preflight_cleaned
            .map(|text| serde_json::Value::String(text.to_string()))
            .unwrap_or(serde_json::Value::Null);
    }
    if !client_submissions.is_empty() {
        data["client_submission_ids"] = serde_json::json!(
            client_submissions
                .iter()
                .map(|receipt| receipt.id)
                .collect::<Vec<_>>()
        );
        data["client_submissions"] = serde_json::json!(client_submissions);
    }
    data
}

pub(super) enum FoldedSubmission {
    User(Box<UserSubmission>),
    Compact(Vec<uuid::Uuid>),
}

pub(super) fn fold_submission_commands(submissions: Vec<UserSubmission>) -> Vec<FoldedSubmission> {
    submissions
        .into_iter()
        .map(|submission| match submission.kind {
            UserSubmissionKind::User => FoldedSubmission::User(Box::new(submission)),
            UserSubmissionKind::Compact => FoldedSubmission::Compact(submission.queue_item_ids),
        })
        .collect()
}
