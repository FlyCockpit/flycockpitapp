//! Thin aliases over `rig::message::*` so callers don't need a `rig::` import.
//!
//! Why aliasing rather than re-wrapping: rig's types are well-shaped, and
//! re-implementing them buys nothing except divergence drift when rig
//! evolves. The aliases give us a single import point if we ever do want
//! to swap implementations.

pub use rig::OneOrMany;
pub use rig::completion::ToolDefinition;
pub use rig::message::{AssistantContent, Message, ToolCall};
use rig::message::{ImageMediaType, UserContent};

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use base64::Engine as _;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Mutex, Notify, watch};
use uuid::Uuid;

/// Sentinel emitted in wire text by
/// the TUI paste registry at each real-image
/// position. We split on it here to interleave text and image content
/// parts in order when assembling the outbound user [`Message`].
pub use crate::daemon::proto::IMAGE_PART_SENTINEL;

/// A user submission destined for the agent: scrubbed wire text plus the
/// ordered PNG payloads for any pasted images sent as real image parts
/// (vision models only — non-vision callers fold images into the text and
/// pass an empty `images`). Travels the daemon→driver path so image bytes
/// reach the prompt-assembly point without being mangled by the
/// text-only redaction/queue-folding plumbing.
///
/// `text` may contain [`IMAGE_PART_SENTINEL`] markers; there must be
/// exactly `images.len()` of them, in the same left-to-right order as
/// `images`. [`build_user_message`] consumes both.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct UserSubmission {
    #[serde(default)]
    pub kind: UserSubmissionKind,
    pub text: String,
    /// User-facing transcript form. `None` means the wire text is also the
    /// display text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_text: Option<String>,
    /// Structured `@`-tag expansion rows displayed after the user message.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tag_expansions: Vec<crate::daemon::proto::TagExpansionMeta>,
    /// PNG-encoded image bytes, one per real image part, in order.
    #[serde(default)]
    pub images: Vec<Vec<u8>>,
    /// A user-issued skill slash command (`/<skill-name>` or
    /// `/skill <name>`): the exact skill name to invoke deterministically
    /// before this turn's inference (implementation note).
    /// The driver synthesizes a real `skill` tool call for it — reusing the
    /// one skill-tool loading path — so the body loads regardless of whether
    /// the model would have called the tool. `text` carries any trailing
    /// args as the accompanying task input. `None` for an ordinary message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forced_skill: Option<String>,
    /// Principal that originated this submission (`flycockpit:<user_id>` for
    /// remote sharees). `None` is the local owner / legacy path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_principal: Option<String>,
    /// Originating async-job id when this submission is a late-arriving
    /// async-result delivery (`loop`/`timer`/`background`/`swarm` —
    /// implementation note). Carried so the recorded
    /// `user_message` event can stamp `data.job_id`, attributing the
    /// delivery to the job it came from. `None` for ordinary input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<String>,
    /// The request-preflight **cleaned** (rewritten) text, when preflight
    /// rewrote this submission (implementation note). UI/DB-only
    /// — the cleaned text is already in [`Self::text`] (the model-facing
    /// body); this copy rides to the TUI via `UserMessageRecorded` so the
    /// transcript can show the cleaned form + `⚙ preflighted` chip while the
    /// reveal shows the user's original typed input (the wire-vs-user split,
    /// GOALS §14). `None` when preflight didn't run / was a no-op / fell back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_cleaned: Option<String>,
    /// Queue item ids that were drained to produce this submission. A v6
    /// `SendUserMessage` seeds this with its required client submission id;
    /// the queue preserves that UUID as its canonical item/idempotency key.
    /// Empty for direct, non-queued driver calls. Folded submissions keep every
    /// id in FIFO order for exact UI/export correlation.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queue_item_ids: Vec<Uuid>,
    /// Client idempotency receipts carried unchanged from daemon acceptance to
    /// the durable user event. Empty for internal/system submissions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub client_submissions: Vec<ClientSubmissionReceipt>,
    /// Queue target captured when the daemon accepted the queued message. All
    /// items in one fold are drained for the same target, so the folded
    /// submission carries the first target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_target: Option<QueueTarget>,
    /// Internal retry phase for an accepted submission whose terminal
    /// preflight disposition could not yet be made durable. This is queue
    /// state, not wire state: on retry the driver must persist the disposition
    /// without re-running injection detection or request preflight.
    #[serde(skip)]
    pub pending_terminal_disposition: Option<PendingSubmissionTerminalDisposition>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingSubmissionTerminalDisposition {
    PreflightRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ClientSubmissionReceipt {
    pub id: Uuid,
    /// Canonical fingerprint of consumed content, including image bytes.
    pub fingerprint: String,
    /// Canonical fingerprint of the original wire request, including ordered
    /// image-ref ids. This permits an exact retry to be acknowledged after
    /// attachment bytes expire or the daemon restarts.
    pub wire_fingerprint: String,
    /// Stable principal scope for the idempotency key (`None` for owner).
    pub origin_principal: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserSubmissionKind {
    #[default]
    User,
    Compact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueItemStatus {
    Queued,
    Folding,
}

#[derive(Debug, Clone)]
pub struct QueuedUserMessage {
    pub id: Uuid,
    pub status: QueueItemStatus,
    pub text: String,
    pub display_text: Option<String>,
    pub target: QueueTarget,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QueueTarget {
    pub id: String,
    pub agent: String,
    pub depth: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_call_id: Option<String>,
}

impl Default for QueueTarget {
    fn default() -> Self {
        Self::root("")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveQueuedMessageResult {
    Removed,
    AlreadyStarted,
    NotFound,
}

#[derive(Debug, Clone)]
struct QueuedSubmission {
    id: Uuid,
    submission: UserSubmission,
    target: QueueTarget,
    not_before: Option<tokio::time::Instant>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StagedRemovalScope {
    Exact(Uuid),
    NewestFor(String),
    EditableFor(String),
    AllPending,
}

/// Opaque claim over queued submissions that are blocked from execution but
/// are not terminal until their durable receipts commit.
#[derive(Debug, Clone)]
pub struct StagedQueueRemoval {
    ids: Vec<Uuid>,
    removed: Vec<QueuedUserMessage>,
    scope: StagedRemovalScope,
}

impl StagedQueueRemoval {
    pub fn ids(&self) -> &[Uuid] {
        &self.ids
    }

    pub fn removed(&self) -> &[QueuedUserMessage] {
        &self.removed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueRemovalInProgress;

#[derive(Debug, Default)]
struct UserSubmissionQueueState {
    pending: VecDeque<QueuedSubmission>,
    /// Identity claim over queued payloads while their terminal receipts are
    /// being persisted. Claimed payloads remain in `pending`, preserving their
    /// exact contents and FIFO position across concurrent front requeues. Queue
    /// consumers pause until the claim commits. A failed write deliberately
    /// leaves the claim held so execution cannot beat the client's retry.
    staged_removal: Option<StagedQueueRemoval>,
    staged_removal_failed: bool,
    started: HashSet<Uuid>,
    started_targets: HashMap<Uuid, QueueTarget>,
    /// Every id accepted during this worker epoch, including completed and
    /// explicitly removed items. This closes the check/enqueue race for
    /// idempotent retries; restart retries are resolved from durable events.
    accepted: HashMap<Uuid, AcceptedClientSubmission>,
    closed: bool,
}

#[derive(Debug, Clone)]
struct AcceptedClientSubmission {
    fingerprint: String,
    wire_fingerprint: String,
    origin_principal: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotentProbe {
    Unknown,
    ExactDuplicate,
    ContentCheckRequired,
    Conflict,
}

#[derive(Debug, Clone)]
pub struct UserSubmissionQueue {
    inner: Arc<Mutex<UserSubmissionQueueState>>,
    notify: Arc<Notify>,
    stage_updates: watch::Sender<u64>,
    updates: watch::Sender<Vec<QueuedUserMessage>>,
}

impl UserSubmissionQueue {
    pub fn new(updates: watch::Sender<Vec<QueuedUserMessage>>) -> Self {
        let (stage_updates, _) = watch::channel(0);
        Self {
            inner: Arc::new(Mutex::new(UserSubmissionQueueState::default())),
            notify: Arc::new(Notify::new()),
            stage_updates,
            updates,
        }
    }

    pub async fn push(
        &self,
        submission: UserSubmission,
        target: QueueTarget,
    ) -> (Uuid, Vec<QueuedUserMessage>) {
        let id = Uuid::new_v4();
        let receipt = ClientSubmissionReceipt {
            id,
            fingerprint: id.to_string(),
            wire_fingerprint: id.to_string(),
            origin_principal: submission.origin_principal.clone(),
        };
        let (_, snapshot, _) = self.push_idempotent(receipt, submission, target).await;
        (id, snapshot)
    }

    /// Accept a client-correlated submission exactly once in this worker
    /// epoch. `inserted = false` acknowledges an earlier acceptance without
    /// enqueuing a second inference.
    pub async fn push_idempotent(
        &self,
        receipt: ClientSubmissionReceipt,
        submission: UserSubmission,
        target: QueueTarget,
    ) -> (Uuid, Vec<QueuedUserMessage>, IdempotentPush) {
        let id = receipt.id;
        let snapshot = {
            let mut state = self.inner.lock().await;
            if let Some(existing) = state.accepted.get(&id) {
                let outcome = if existing.origin_principal != receipt.origin_principal
                    || existing.fingerprint != receipt.fingerprint
                {
                    IdempotentPush::Conflict
                } else {
                    IdempotentPush::Duplicate
                };
                return (id, snapshot_pending(&state), outcome);
            }
            state.accepted.insert(
                id,
                AcceptedClientSubmission {
                    fingerprint: receipt.fingerprint,
                    wire_fingerprint: receipt.wire_fingerprint,
                    origin_principal: receipt.origin_principal,
                },
            );
            state.pending.push_back(QueuedSubmission {
                id,
                submission,
                target,
                not_before: None,
            });
            snapshot_pending(&state)
        };
        self.publish(snapshot.clone());
        self.notify.notify_one();
        (id, snapshot, IdempotentPush::Inserted)
    }

    pub async fn probe_idempotent(
        &self,
        id: Uuid,
        wire_fingerprint: &str,
        origin_principal: Option<&str>,
    ) -> (IdempotentProbe, Vec<QueuedUserMessage>) {
        let state = self.inner.lock().await;
        let probe = match state.accepted.get(&id) {
            None => IdempotentProbe::Unknown,
            Some(existing) if existing.origin_principal.as_deref() != origin_principal => {
                IdempotentProbe::Conflict
            }
            Some(existing) if existing.wire_fingerprint == wire_fingerprint => {
                IdempotentProbe::ExactDuplicate
            }
            Some(_) => IdempotentProbe::ContentCheckRequired,
        };
        (probe, snapshot_pending(&state))
    }

    pub async fn requeue_front(
        &self,
        submission: UserSubmission,
        fallback_target: QueueTarget,
    ) -> Vec<QueuedUserMessage> {
        self.requeue_front_after(submission, fallback_target, std::time::Duration::ZERO)
            .await
    }

    /// Requeue an exact started payload at the front while keeping it visible
    /// to snapshots and terminal-removal controls. Consumers preserve FIFO but
    /// do not receive it until `delay` elapses, so persistent storage failures
    /// cannot create a hot loop that starves driver controls.
    pub async fn requeue_front_after(
        &self,
        mut submission: UserSubmission,
        fallback_target: QueueTarget,
        delay: std::time::Duration,
    ) -> Vec<QueuedUserMessage> {
        let id = submission
            .queue_item_ids
            .first()
            .copied()
            .unwrap_or_else(Uuid::new_v4);
        let target = submission.queue_target.take().unwrap_or(fallback_target);
        submission.queue_item_ids.clear();
        let snapshot = {
            let mut state = self.inner.lock().await;
            state.started.remove(&id);
            state.started_targets.remove(&id);
            state.pending.push_front(QueuedSubmission {
                id,
                submission,
                target,
                not_before: (!delay.is_zero()).then(|| tokio::time::Instant::now() + delay),
            });
            snapshot_pending(&state)
        };
        self.publish(snapshot.clone());
        self.notify.notify_one();
        snapshot
    }

    pub async fn finish(&self, ids: &[Uuid]) {
        if ids.is_empty() {
            return;
        }
        let mut state = self.inner.lock().await;
        for id in ids {
            state.started.remove(id);
            state.started_targets.remove(id);
        }
    }

    pub async fn snapshot(&self) -> Vec<QueuedUserMessage> {
        let state = self.inner.lock().await;
        snapshot_pending(&state)
    }

    #[cfg(test)]
    pub async fn pending_submission(&self, id: Uuid) -> Option<UserSubmission> {
        let state = self.inner.lock().await;
        state
            .pending
            .iter()
            .find(|item| item.id == id)
            .map(|item| item.submission.clone())
    }

    pub async fn accepted_receipts(&self, ids: &[Uuid]) -> Vec<ClientSubmissionReceipt> {
        let state = self.inner.lock().await;
        ids.iter()
            .filter_map(|id| {
                state
                    .accepted
                    .get(id)
                    .map(|accepted| ClientSubmissionReceipt {
                        id: *id,
                        fingerprint: accepted.fingerprint.clone(),
                        wire_fingerprint: accepted.wire_fingerprint.clone(),
                        origin_principal: accepted.origin_principal.clone(),
                    })
            })
            .collect()
    }

    pub async fn stage_remove(
        &self,
        id: Uuid,
    ) -> Result<
        (
            RemoveQueuedMessageResult,
            Option<StagedQueueRemoval>,
            Vec<QueuedUserMessage>,
        ),
        QueueRemovalInProgress,
    > {
        let mut state = self.inner.lock().await;
        let scope = StagedRemovalScope::Exact(id);
        if let Some(staged) = existing_stage_for_scope(&mut state, &scope)? {
            let snapshot = snapshot_pending(&state);
            return Ok((RemoveQueuedMessageResult::Removed, Some(staged), snapshot));
        }
        let (result, staged) =
            if let Some(index) = state.pending.iter().position(|item| item.id == id) {
                (
                    RemoveQueuedMessageResult::Removed,
                    Some(stage_pending_indices(&mut state, vec![index], scope)),
                )
            } else if state.started.contains(&id) {
                (RemoveQueuedMessageResult::AlreadyStarted, None)
            } else {
                (RemoveQueuedMessageResult::NotFound, None)
            };
        let snapshot = snapshot_pending(&state);
        Ok((result, staged, snapshot))
    }

    pub async fn stage_remove_newest_for(
        &self,
        target_id: &str,
    ) -> Result<
        (
            RemoveQueuedMessageResult,
            Option<StagedQueueRemoval>,
            Vec<QueuedUserMessage>,
        ),
        QueueRemovalInProgress,
    > {
        let mut state = self.inner.lock().await;
        let scope = StagedRemovalScope::NewestFor(target_id.to_string());
        if let Some(staged) = existing_stage_for_scope(&mut state, &scope)? {
            let snapshot = snapshot_pending(&state);
            return Ok((RemoveQueuedMessageResult::Removed, Some(staged), snapshot));
        }
        let (result, staged) = if let Some(index) = state
            .pending
            .iter()
            .rposition(|item| item.target.id == target_id)
        {
            (
                RemoveQueuedMessageResult::Removed,
                Some(stage_pending_indices(&mut state, vec![index], scope)),
            )
        } else if state
            .started_targets
            .values()
            .any(|target| target.id == target_id)
        {
            (RemoveQueuedMessageResult::AlreadyStarted, None)
        } else {
            (RemoveQueuedMessageResult::NotFound, None)
        };
        let snapshot = snapshot_pending(&state);
        Ok((result, staged, snapshot))
    }

    pub async fn stage_remove_editable_for(
        &self,
        target_id: &str,
    ) -> Result<
        (
            RemoveQueuedMessageResult,
            Option<StagedQueueRemoval>,
            Vec<QueuedUserMessage>,
        ),
        QueueRemovalInProgress,
    > {
        let mut state = self.inner.lock().await;
        let scope = StagedRemovalScope::EditableFor(target_id.to_string());
        if let Some(staged) = existing_stage_for_scope(&mut state, &scope)? {
            let snapshot = snapshot_pending(&state);
            return Ok((RemoveQueuedMessageResult::Removed, Some(staged), snapshot));
        }
        let indices = state
            .pending
            .iter()
            .enumerate()
            .filter_map(|(index, item)| (item.target.id == target_id).then_some(index))
            .collect::<Vec<_>>();
        let has_started_target = state
            .started_targets
            .values()
            .any(|target| target.id == target_id);
        let result = if !indices.is_empty() {
            if has_started_target {
                RemoveQueuedMessageResult::AlreadyStarted
            } else {
                RemoveQueuedMessageResult::Removed
            }
        } else if has_started_target {
            RemoveQueuedMessageResult::AlreadyStarted
        } else {
            RemoveQueuedMessageResult::NotFound
        };
        let staged =
            (!indices.is_empty()).then(|| stage_pending_indices(&mut state, indices, scope));
        let snapshot = snapshot_pending(&state);
        Ok((result, staged, snapshot))
    }

    /// Hold every submission currently pending at a cancellation boundary.
    /// A prior failed targeted removal is widened into this cancellation claim;
    /// submissions accepted after the claim remain queued for the next turn.
    pub async fn stage_discard_pending(&self) -> Option<StagedQueueRemoval> {
        let mut stage_updates = self.stage_updates.subscribe();
        loop {
            let mut state = self.inner.lock().await;
            if state.staged_removal.is_some() && !state.staged_removal_failed {
                drop(state);
                let _ = stage_updates.changed().await;
                continue;
            }
            let indices = (0..state.pending.len()).collect::<Vec<_>>();
            if indices.is_empty() {
                state.staged_removal = None;
                state.staged_removal_failed = false;
                return None;
            }
            state.staged_removal = None;
            state.staged_removal_failed = false;
            return Some(stage_pending_indices(
                &mut state,
                indices,
                StagedRemovalScope::AllPending,
            ));
        }
    }

    /// Keep a failed claim non-runnable while allowing the same removal or a
    /// cancellation boundary to retry it. The phase transition wakes only
    /// barrier waiters; queue consumers remain asleep and cannot execute it.
    pub async fn mark_staged_removal_failed(&self, staged: &StagedQueueRemoval) {
        {
            let mut state = self.inner.lock().await;
            assert_staged_removal(&state, staged);
            state.staged_removal_failed = true;
        }
        self.stage_updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
    }

    /// Make a staged removal visible only after its terminal receipts are
    /// durable. Consumers resume from the remaining queue at this boundary.
    pub async fn commit_staged_removal(
        &self,
        staged: StagedQueueRemoval,
    ) -> Vec<QueuedUserMessage> {
        let snapshot = {
            let mut state = self.inner.lock().await;
            assert_staged_removal(&state, &staged);
            let ids = staged.ids.iter().copied().collect::<HashSet<_>>();
            state.pending.retain(|item| !ids.contains(&item.id));
            state.staged_removal = None;
            state.staged_removal_failed = false;
            snapshot_pending(&state)
        };
        self.publish(snapshot.clone());
        self.stage_updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
        self.notify.notify_one();
        snapshot
    }

    /// Publish the current pending-queue snapshot without mutating it.
    ///
    /// Attach hydration uses this so a newly subscribed client learns the
    /// authoritative queue even when the last queue mutation happened before
    /// it connected. Publishing an empty snapshot is intentional: it clears a
    /// stale client-side mirror after reconnect.
    pub async fn republish(&self) {
        let snapshot = {
            let state = self.inner.lock().await;
            snapshot_pending(&state)
        };
        self.publish(snapshot);
    }

    #[cfg(test)]
    pub async fn remove(&self, id: Uuid) -> (RemoveQueuedMessageResult, Vec<QueuedUserMessage>) {
        let (result, snapshot) = {
            let mut state = self.inner.lock().await;
            if let Some(idx) = state.pending.iter().position(|item| item.id == id) {
                state.pending.remove(idx);
                (RemoveQueuedMessageResult::Removed, snapshot_pending(&state))
            } else if state.started.contains(&id) {
                (
                    RemoveQueuedMessageResult::AlreadyStarted,
                    snapshot_pending(&state),
                )
            } else {
                (
                    RemoveQueuedMessageResult::NotFound,
                    snapshot_pending(&state),
                )
            }
        };
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(snapshot.clone());
        }
        (result, snapshot)
    }

    #[cfg(test)]
    pub async fn remove_newest_for(
        &self,
        target_id: &str,
    ) -> (
        RemoveQueuedMessageResult,
        Option<QueuedUserMessage>,
        Vec<QueuedUserMessage>,
    ) {
        let (result, removed, snapshot) = {
            let mut state = self.inner.lock().await;
            if let Some(idx) = state
                .pending
                .iter()
                .rposition(|item| item.target.id == target_id)
            {
                let item = state.pending.remove(idx).expect("index came from position");
                let removed = queued_message_from_submission(&item);
                (
                    RemoveQueuedMessageResult::Removed,
                    Some(removed),
                    snapshot_pending(&state),
                )
            } else if state
                .started_targets
                .values()
                .any(|target| target.id == target_id)
            {
                (
                    RemoveQueuedMessageResult::AlreadyStarted,
                    None,
                    snapshot_pending(&state),
                )
            } else {
                (
                    RemoveQueuedMessageResult::NotFound,
                    None,
                    snapshot_pending(&state),
                )
            }
        };
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(snapshot.clone());
        }
        (result, removed, snapshot)
    }

    #[cfg(test)]
    pub async fn remove_editable_for(
        &self,
        target_id: &str,
    ) -> (
        RemoveQueuedMessageResult,
        Vec<QueuedUserMessage>,
        Vec<QueuedUserMessage>,
    ) {
        let (result, removed, snapshot) = {
            let mut state = self.inner.lock().await;
            let mut removed = Vec::new();
            let mut kept = VecDeque::with_capacity(state.pending.len());
            while let Some(item) = state.pending.pop_front() {
                if item.target.id == target_id {
                    removed.push(queued_message_from_submission(&item));
                } else {
                    kept.push_back(item);
                }
            }
            state.pending = kept;
            let has_started_target = state
                .started_targets
                .values()
                .any(|target| target.id == target_id);
            let result = if !removed.is_empty() {
                if has_started_target {
                    RemoveQueuedMessageResult::AlreadyStarted
                } else {
                    RemoveQueuedMessageResult::Removed
                }
            } else if has_started_target {
                RemoveQueuedMessageResult::AlreadyStarted
            } else {
                RemoveQueuedMessageResult::NotFound
            };
            (result, removed, snapshot_pending(&state))
        };
        if !removed.is_empty() {
            self.publish(snapshot.clone());
        }
        (result, removed, snapshot)
    }

    pub async fn recv(&self) -> Option<UserSubmission> {
        self.recv_for(None).await
    }

    pub async fn recv_for(&self, target_id: Option<&str>) -> Option<UserSubmission> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            match self.pop_one(target_id).await {
                QueuePop::Item(submission) => return Some(*submission),
                QueuePop::Closed => return None,
                QueuePop::Empty => notified.await,
                QueuePop::Deferred(deadline) => {
                    tokio::select! {
                        _ = &mut notified => {}
                        _ = tokio::time::sleep_until(deadline) => {}
                    }
                }
            }
        }
    }

    pub async fn drain_into_for(
        &self,
        into: &mut Vec<UserSubmission>,
        max: usize,
        target_id: Option<&str>,
    ) {
        while into.len() < max {
            match self.pop_one(target_id).await {
                QueuePop::Item(submission) => into.push(*submission),
                QueuePop::Empty | QueuePop::Closed | QueuePop::Deferred(_) => break,
            }
        }
    }

    pub async fn has_pending_for(&self, target_id: Option<&str>) -> bool {
        let state = self.inner.lock().await;
        match target_id {
            Some(target_id) => state.pending.iter().any(|item| item.target.id == target_id),
            None => !state.pending.is_empty(),
        }
    }

    #[cfg(test)]
    pub async fn discard_pending(&self) -> usize {
        self.discard_pending_with_receipts().await.0
    }

    #[cfg(test)]
    pub async fn discard_pending_with_receipts(&self) -> (usize, Vec<ClientSubmissionReceipt>) {
        let (dropped, receipts, snapshot) = {
            let mut state = self.inner.lock().await;
            let dropped = state.pending.len();
            let receipts = state
                .pending
                .iter()
                .filter_map(|item| {
                    state
                        .accepted
                        .get(&item.id)
                        .map(|accepted| ClientSubmissionReceipt {
                            id: item.id,
                            fingerprint: accepted.fingerprint.clone(),
                            wire_fingerprint: accepted.wire_fingerprint.clone(),
                            origin_principal: accepted.origin_principal.clone(),
                        })
                })
                .collect();
            state.pending.clear();
            (dropped, receipts, snapshot_pending(&state))
        };
        if dropped > 0 {
            self.publish(snapshot);
        }
        (dropped, receipts)
    }

    pub async fn close(&self) {
        let mut state = self.inner.lock().await;
        state.closed = true;
        self.notify.notify_waiters();
    }

    async fn pop_one(&self, target_id: Option<&str>) -> QueuePop {
        let (item, snapshot) = {
            let mut state = self.inner.lock().await;
            if state.closed {
                return QueuePop::Closed;
            }
            if state.staged_removal.is_some() {
                return QueuePop::Empty;
            }
            let idx = match target_id {
                Some(target_id) => state
                    .pending
                    .iter()
                    .position(|item| item.target.id == target_id),
                None => (!state.pending.is_empty()).then_some(0),
            };
            let Some(idx) = idx else {
                return if state.closed {
                    QueuePop::Closed
                } else {
                    QueuePop::Empty
                };
            };
            if let Some(not_before) = state.pending[idx].not_before
                && not_before > tokio::time::Instant::now()
            {
                return QueuePop::Deferred(not_before);
            }
            let Some(item) = state.pending.remove(idx) else {
                return if state.closed {
                    QueuePop::Closed
                } else {
                    QueuePop::Empty
                };
            };
            state.started.insert(item.id);
            state.started_targets.insert(item.id, item.target.clone());
            (item, snapshot_pending(&state))
        };
        self.publish(snapshot);
        let mut submission = item.submission;
        if !submission.queue_item_ids.contains(&item.id) {
            submission.queue_item_ids.push(item.id);
        }
        submission.queue_target = Some(item.target);
        QueuePop::Item(Box::new(submission))
    }

    fn publish(&self, snapshot: Vec<QueuedUserMessage>) {
        let _ = self.updates.send(snapshot);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdempotentPush {
    Inserted,
    Duplicate,
    Conflict,
}

enum QueuePop {
    Item(Box<UserSubmission>),
    Empty,
    Deferred(tokio::time::Instant),
    Closed,
}

fn snapshot_pending(state: &UserSubmissionQueueState) -> Vec<QueuedUserMessage> {
    state
        .pending
        .iter()
        .map(queued_message_from_submission)
        .collect()
}

fn stage_pending_indices(
    state: &mut UserSubmissionQueueState,
    indices: Vec<usize>,
    scope: StagedRemovalScope,
) -> StagedQueueRemoval {
    debug_assert!(state.staged_removal.is_none());
    let items = indices
        .into_iter()
        .map(|index| {
            state
                .pending
                .get(index)
                .expect("staged queue index came from the pending queue")
        })
        .collect::<Vec<_>>();
    let ids = items.iter().map(|item| item.id).collect();
    let messages = items
        .iter()
        .map(|item| queued_message_from_submission(item))
        .collect();
    let staged = StagedQueueRemoval {
        ids,
        removed: messages,
        scope,
    };
    state.staged_removal = Some(staged.clone());
    state.staged_removal_failed = false;
    staged
}

fn assert_staged_removal(state: &UserSubmissionQueueState, staged: &StagedQueueRemoval) {
    assert_eq!(
        state
            .staged_removal
            .as_ref()
            .map(|current| (&current.ids, &current.scope)),
        Some((&staged.ids, &staged.scope)),
        "staged queue removal ticket must match the queue claim"
    );
}

fn existing_stage_for_scope(
    state: &mut UserSubmissionQueueState,
    scope: &StagedRemovalScope,
) -> Result<Option<StagedQueueRemoval>, QueueRemovalInProgress> {
    match state.staged_removal.clone() {
        None => Ok(None),
        Some(staged) if &staged.scope == scope && state.staged_removal_failed => {
            state.staged_removal_failed = false;
            Ok(Some(staged))
        }
        Some(_) => Err(QueueRemovalInProgress),
    }
}

fn queued_message_from_submission(item: &QueuedSubmission) -> QueuedUserMessage {
    QueuedUserMessage {
        id: item.id,
        status: QueueItemStatus::Queued,
        text: item.submission.text.clone(),
        display_text: item.submission.display_text.clone(),
        target: item.target.clone(),
    }
}

impl QueueTarget {
    pub fn root(agent: impl Into<String>) -> Self {
        Self {
            id: "root".to_string(),
            agent: agent.into(),
            depth: 0,
            task_call_id: None,
        }
    }

    pub fn child(
        agent: impl Into<String>,
        depth: usize,
        task_call_id: impl Into<String>,
        label: impl AsRef<str>,
    ) -> Self {
        let task_call_id = task_call_id.into();
        Self {
            id: format!("task:{task_call_id}:{}", label.as_ref()),
            agent: agent.into(),
            depth,
            task_call_id: Some(task_call_id),
        }
    }
}

impl UserSubmission {
    /// Text-only submission (no images). Used everywhere the legacy
    /// string path fed a bare message.
    pub fn text(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            ..Self::default()
        }
    }

    pub fn compact_notice() -> Self {
        Self {
            kind: UserSubmissionKind::Compact,
            text: "/compact: assembling handoff (prune-first, model brief, deterministic appendix, context tags)...".to_string(),
            ..Self::default()
        }
    }

    /// Fingerprint the canonical consumed payload, including image bytes, but
    /// excluding transport/queue metadata. Re-uploaded copies therefore match
    /// while UUID reuse with changed text/display/tags/images/skill conflicts.
    pub fn client_fingerprint(&self) -> String {
        fn part(hasher: &mut Sha256, bytes: &[u8]) {
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }

        fn optional_part(hasher: &mut Sha256, value: Option<&str>) {
            match value {
                None => part(hasher, b"none"),
                Some(value) => {
                    part(hasher, b"some");
                    part(hasher, value.as_bytes());
                }
            }
        }

        let mut hasher = Sha256::new();
        part(
            &mut hasher,
            match self.kind {
                UserSubmissionKind::User => b"user",
                UserSubmissionKind::Compact => b"compact",
            },
        );
        part(&mut hasher, self.text.as_bytes());
        optional_part(&mut hasher, self.display_text.as_deref());
        part(
            &mut hasher,
            &serde_json::to_vec(&self.tag_expansions).unwrap_or_default(),
        );
        for image in &self.images {
            part(&mut hasher, image);
        }
        optional_part(&mut hasher, self.forced_skill.as_deref());
        crate::intel::hex_lower(&hasher.finalize())
    }

    /// True when there are no image parts — the common case, letting the
    /// driver keep the cheap `Message::user(text)` path.
    pub fn is_text_only(&self) -> bool {
        self.images.is_empty()
    }
}

/// Build a user [`Message`] from a [`UserSubmission`]. With no images this
/// is exactly `Message::user(text)`. With images, the `text` is split on
/// [`IMAGE_PART_SENTINEL`] and reassembled as an ordered
/// `OneOrMany<UserContent>` of interleaved text + base64-PNG image parts,
/// which rig serializes as `image_url` data-URIs for OpenAI-compatible
/// chat completions (verified via kcl `rig-core`). Empty text segments
/// between/around images are dropped so we don't emit empty text parts.
pub fn build_user_message(sub: UserSubmission) -> Message {
    if sub.is_text_only() {
        return Message::user(sub.text);
    }
    let segments: Vec<&str> = sub.text.split(IMAGE_PART_SENTINEL).collect();
    let mut parts: Vec<UserContent> = Vec::new();
    let mut imgs = sub.images.into_iter();
    for (i, seg) in segments.iter().enumerate() {
        if !seg.is_empty() {
            parts.push(UserContent::text(*seg));
        }
        // A sentinel separated this segment from the next → an image part
        // belongs here (one fewer sentinel than there are segments).
        if i + 1 < segments.len()
            && let Some(png) = imgs.next()
        {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
            parts.push(UserContent::image_base64(
                b64,
                Some(ImageMediaType::PNG),
                None,
            ));
        }
    }
    // Any images without a matching sentinel (defensive — shouldn't
    // happen) are appended so bytes are never silently dropped.
    for png in imgs {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        parts.push(UserContent::image_base64(
            b64,
            Some(ImageMediaType::PNG),
            None,
        ));
    }
    match OneOrMany::many(parts) {
        Ok(content) => Message::User { content },
        // Empty content is unreachable (caller has images), but never
        // panic on the wire path — fall back to the plain text form.
        Err(_) => Message::user(sub.text),
    }
}

/// Extract concatenated text from an assistant turn's content vector.
pub fn extract_text(choice: &OneOrMany<AssistantContent>) -> String {
    choice
        .iter()
        .filter_map(|c| match c {
            AssistantContent::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Extract concatenated plain text from a user turn's content vector.
/// Only `UserContent::Text` parts contribute — tool-result and image
/// parts are skipped, so a tool-result `User` message projects to the
/// empty string (used by the turn-assembly projection in
/// [`crate::engine::predict`] to distinguish real user input from
/// tool-answer rounds).
pub fn extract_user_text(content: &OneOrMany<UserContent>) -> String {
    content
        .iter()
        .filter_map(|c| match c {
            UserContent::Text(t) => Some(t.text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Concatenated *channel* reasoning text from an assistant turn — the
/// `reasoning_content` the provider aggregated into `AssistantContent::
/// Reasoning` blocks (joined with newlines). Empty for models that emit
/// no channel reasoning (e.g. the inline-`<think>` models, whose reasoning
/// rides in `Text`). Used at finalization to persist channel reasoning
/// alongside any inline-`<think>` reasoning (implementation note).
pub fn extract_reasoning(choice: &OneOrMany<AssistantContent>) -> String {
    let mut seen = std::collections::HashSet::new();
    let mut parts = Vec::new();
    for content in choice.iter() {
        let AssistantContent::Reasoning(reasoning) = content else {
            continue;
        };
        for item in reasoning.content.iter() {
            let text = match item {
                rig::message::ReasoningContent::Text { text, .. }
                | rig::message::ReasoningContent::Summary(text) => text.as_str(),
                _ => continue,
            };
            if !text.is_empty() && seen.insert(text.to_string()) {
                parts.push(text.to_string());
            }
        }
    }
    parts.join("\n")
}

/// Rebuild an assistant turn's content with every `Text` part's inline
/// `<think>…</think>` blocks stripped (via the single shared parser), so
/// the stored model history carries no reasoning tags — used when the
/// inline-think toggle classifies the block as THINKING (toggle ON), where
/// reasoning must not re-enter the model's context on a later turn (rule 1;
/// token economy, GOALS §10). Tool calls and channel `Reasoning` blocks are
/// preserved unchanged; `Reasoning` is later dropped on the wire by
/// `model::strip_reasoning`. A `Text` part that becomes empty after stripping
/// (a think-only turn) is omitted.
///
/// Returns `None` when nothing survives — a genuinely empty turn (reasoning
/// only, no body, no tool call). The caller must then drop the turn rather
/// than persist a blank `[{"text":""}]` assistant message, which would
/// re-enter every later request and poison context (defect B). A turn that
/// still has tool calls is never empty (the calls survive), so this only
/// returns `None` for a true reasoning-only-with-no-action turn.
pub fn strip_think_from_choice(
    choice: &OneOrMany<AssistantContent>,
) -> Option<OneOrMany<AssistantContent>> {
    let mut parts: Vec<AssistantContent> = Vec::new();
    for c in choice.iter() {
        match c {
            AssistantContent::Text(t) => {
                let (body, _reasoning) = crate::engine::think::split_think(&t.text);
                if !body.is_empty() {
                    parts.push(AssistantContent::text(body));
                }
            }
            other => parts.push(other.clone()),
        }
    }
    OneOrMany::many(parts).ok()
}

/// Rebuild an assistant turn's content with every `Text` part replaced by
/// `text` (implementation note). A `Text` part whose
/// replacement is empty is dropped (an empty text part poisons later requests);
/// non-text parts (tool calls, reasoning) are preserved verbatim. Used to keep
/// the wire history in lockstep with the sanitized user-visible text after a
/// leading Harmony special-token bleed is stripped — the model must read back
/// the stripped form, not its own broken output. Returns `None` if no part
/// survives (rig requires a non-empty content vector).
pub fn replace_text_in_choice(
    choice: &OneOrMany<AssistantContent>,
    text: &str,
) -> Option<OneOrMany<AssistantContent>> {
    let mut parts: Vec<AssistantContent> = Vec::new();
    let mut text_used = false;
    for c in choice.iter() {
        match c {
            AssistantContent::Text(_) => {
                if !text_used {
                    text_used = true;
                    if !text.is_empty() {
                        parts.push(AssistantContent::text(text.to_string()));
                    }
                }
            }
            other => parts.push(other.clone()),
        }
    }
    OneOrMany::many(parts).ok()
}

/// Collect all `ToolCall`s from an assistant turn's content vector.
pub fn collect_tool_calls(choice: &OneOrMany<AssistantContent>) -> Vec<ToolCall> {
    choice
        .iter()
        .filter_map(|c| match c {
            AssistantContent::ToolCall(tc) => Some(tc.clone()),
            _ => None,
        })
        .collect()
}

/// Build the tool-result message rig expects in the next request, given a
/// `ToolCall` and the (already-serialized) output string.
pub fn tool_result_message(tc: &ToolCall, output: String) -> Message {
    Message::tool_result_with_call_id(tc.id.clone(), tc.call_id.clone(), output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_parts(msg: &Message) -> Vec<UserContent> {
        match msg {
            Message::User { content } => content.iter().cloned().collect(),
            _ => panic!("expected a user message"),
        }
    }

    #[test]
    fn text_only_submission_is_a_plain_user_text_message() {
        let msg = build_user_message(UserSubmission::text("hello world"));
        let parts = user_parts(&msg);
        assert_eq!(parts.len(), 1);
        assert!(matches!(parts[0], UserContent::Text(_)));
    }

    #[test]
    fn build_user_message_uses_wire_text_not_display_text() {
        let msg = build_user_message(UserSubmission {
            text: "<file path=\"src/lib.rs\">expanded</file>".to_string(),
            display_text: Some("review @src/lib.rs".to_string()),
            tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
                tool: "read".into(),
                path: "src/lib.rs".into(),
                detail: "142 lines".into(),
                ok: true,
            }],
            ..Default::default()
        });
        let parts = user_parts(&msg);
        let UserContent::Text(text) = &parts[0] else {
            panic!("expected text-only user message")
        };
        assert!(text.text.starts_with("<file"));
        assert!(!text.text.contains("@src/lib.rs"));
    }

    #[test]
    fn vision_submission_interleaves_text_and_one_image_part() {
        // "see <img> done" with one PNG → text, image, text.
        let text = format!("see {IMAGE_PART_SENTINEL} done");
        let msg = build_user_message(UserSubmission {
            text,
            images: vec![vec![1u8, 2, 3]],
            ..Default::default()
        });
        let parts = user_parts(&msg);
        assert_eq!(parts.len(), 3);
        assert!(matches!(parts[0], UserContent::Text(_)));
        assert!(matches!(parts[1], UserContent::Image(_)));
        assert!(matches!(parts[2], UserContent::Text(_)));
    }

    #[test]
    fn leading_image_drops_empty_text_segment() {
        // Sentinel at the very start → no empty leading text part.
        let text = format!("{IMAGE_PART_SENTINEL}after");
        let msg = build_user_message(UserSubmission {
            text,
            images: vec![vec![9u8]],
            ..Default::default()
        });
        let parts = user_parts(&msg);
        assert_eq!(parts.len(), 2);
        assert!(matches!(parts[0], UserContent::Image(_)));
        assert!(matches!(parts[1], UserContent::Text(_)));
    }

    fn assistant_choice(parts: Vec<AssistantContent>) -> OneOrMany<AssistantContent> {
        OneOrMany::many(parts).unwrap()
    }

    /// A channel-reasoning model's choice is byte-for-byte unchanged by
    /// `strip_think_from_choice` (no inline tags in the Text part), and its
    /// channel reasoning is read out separately.
    #[test]
    fn channel_reasoning_model_text_unchanged_reasoning_extracted() {
        use rig::message::Reasoning;
        let choice = assistant_choice(vec![
            AssistantContent::Reasoning(Reasoning::new("internal chain of thought")),
            AssistantContent::text("the visible answer"),
        ]);
        // Body text carries no tags → stripping is a no-op on the visible body.
        let stripped = strip_think_from_choice(&choice).expect("non-empty turn");
        assert_eq!(stripped.iter().count(), 2);
        assert_eq!(extract_text(&stripped), "the visible answer");
        // Channel reasoning is read out.
        assert_eq!(extract_reasoning(&choice), "internal chain of thought");
    }

    /// An inline-`<think>` model: the Text part's tags are stripped from the
    /// stored choice; `extract_reasoning` is empty (no channel reasoning).
    #[test]
    fn channel_reasoning_summaries_are_extracted_once() {
        use rig::message::{Reasoning, ReasoningContent};

        let mut reasoning = Reasoning::new("step one");
        reasoning
            .content
            .push(ReasoningContent::Summary("provider summary".into()));
        reasoning
            .content
            .push(ReasoningContent::Summary("provider summary".into()));
        reasoning.content.push(ReasoningContent::Text {
            text: "step one".into(),
            signature: None,
        });
        let choice = assistant_choice(vec![AssistantContent::Reasoning(reasoning)]);

        assert_eq!(extract_reasoning(&choice), "step one\nprovider summary");
    }

    #[test]
    fn inline_think_text_is_stripped_from_choice() {
        let choice = assistant_choice(vec![AssistantContent::text(
            "<think>hidden reasoning</think>\nthe answer",
        )]);
        let stripped = strip_think_from_choice(&choice).expect("non-empty turn");
        let text = extract_text(&stripped);
        assert_eq!(text, "the answer");
        assert!(!text.contains("<think>"));
        // No channel reasoning on this model.
        assert_eq!(extract_reasoning(&choice), "");
    }

    /// A think-only Text part (reasoning, no answer) + a tool call: the
    /// emptied Text is dropped from the stored choice, the tool call is
    /// preserved (never an empty assistant turn that's all whitespace).
    #[test]
    fn think_only_text_with_tool_call_drops_empty_text_keeps_call() {
        use rig::message::{ToolCall, ToolFunction};
        let choice = assistant_choice(vec![
            AssistantContent::text("<think>just thinking</think>"),
            AssistantContent::ToolCall(ToolCall {
                id: "tc-1".into(),
                call_id: None,
                function: ToolFunction {
                    name: "read".into(),
                    arguments: serde_json::json!({"path": "x"}),
                },
                signature: None,
                additional_params: None,
            }),
        ]);
        // The tool call keeps the turn non-empty.
        let stripped = strip_think_from_choice(&choice).expect("tool call keeps turn non-empty");
        // Only the tool call survives — no empty Text part.
        assert_eq!(stripped.iter().count(), 1);
        assert!(collect_tool_calls(&stripped).iter().any(|c| c.id == "tc-1"));
        assert_eq!(extract_text(&stripped), "");
    }

    /// Defect B: a reasoning-only turn (closed `<think>`, no body, no tool
    /// call) strips to nothing → `None`, so the caller drops the turn rather
    /// than persist a blank `[{"text":""}]` message that would poison context.
    #[test]
    fn reasoning_only_turn_strips_to_none_never_blank_text() {
        let choice = assistant_choice(vec![AssistantContent::text(
            "<think>only reasoning, no answer</think>",
        )]);
        assert!(
            strip_think_from_choice(&choice).is_none(),
            "an empty stripped turn must be dropped, not stored blank"
        );
    }

    /// An unterminated `<think>` (no close) is NOT reasoning: the whole body
    /// — open tag included — survives stripping, so action-driving text after
    /// a missing close tag is never lost.
    #[test]
    fn unterminated_think_body_is_preserved_by_strip() {
        let choice = assistant_choice(vec![AssistantContent::text(
            "<think>weighing it\nI'll edit the file now",
        )]);
        let stripped = strip_think_from_choice(&choice).expect("unterminated block stays as body");
        assert_eq!(
            extract_text(&stripped),
            "<think>weighing it\nI'll edit the file now"
        );
    }

    #[test]
    fn model_switch_round_trip_text_note_vs_image_part() {
        // The non-vision wire (a text note, no images) builds a plain text
        // message; the vision wire (sentinel + bytes) builds an image
        // part — the same paste, two model states, no re-paste.
        let note = build_user_message(UserSubmission::text(
            "[Pasted image #1: not sent — current model has no image support]",
        ));
        assert!(
            user_parts(&note)
                .iter()
                .all(|p| matches!(p, UserContent::Text(_)))
        );

        let img = build_user_message(UserSubmission {
            text: IMAGE_PART_SENTINEL.to_string(),
            images: vec![vec![1u8, 2]],
            ..Default::default()
        });
        assert!(
            user_parts(&img)
                .iter()
                .any(|p| matches!(p, UserContent::Image(_)))
        );
    }

    #[tokio::test]
    async fn queue_snapshot_channel_is_bounded_and_latest_wins() {
        let (updates_tx, mut updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");

        for idx in 0..32 {
            queue
                .push(
                    UserSubmission::text(format!("queued message {idx}")),
                    target.clone(),
                )
                .await;
        }

        updates_rx.changed().await.unwrap();
        let latest = updates_rx.borrow_and_update().clone();
        assert_eq!(latest.len(), 32);
        assert_eq!(
            latest.last().map(|item| item.text.as_str()),
            Some("queued message 31")
        );
        assert!(
            !updates_rx.has_changed().unwrap(),
            "watch coalesces parked consumers to one pending latest snapshot"
        );
    }

    #[tokio::test]
    async fn user_submission_queue_remove_prevents_later_drain_and_keeps_fifo() {
        let (updates_tx, mut updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");

        let (first_id, _) = queue
            .push(UserSubmission::text("first"), target.clone())
            .await;
        let (second_id, _) = queue
            .push(UserSubmission::text("second"), target.clone())
            .await;
        let (third_id, _) = queue
            .push(UserSubmission::text("third"), target.clone())
            .await;

        let (removed, snapshot) = queue.remove(second_id).await;
        assert_eq!(removed, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            queue
                .accepted_receipts(&[second_id])
                .await
                .into_iter()
                .map(|receipt| (receipt.id, receipt.fingerprint, receipt.wire_fingerprint,))
                .collect::<Vec<_>>(),
            vec![(second_id, second_id.to_string(), second_id.to_string(),)],
            "removal keeps the exact accepted receipt available for durable tombstoning"
        );
        assert_eq!(
            snapshot.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![first_id, third_id]
        );

        let first = queue.recv().await.expect("first item");
        let third = queue.recv().await.expect("third item");
        assert_eq!(first.text, "first");
        assert_eq!(third.text, "third");

        updates_rx.changed().await.unwrap();
        let last = updates_rx.borrow_and_update().clone();
        assert!(!updates_rx.has_changed().unwrap());
        assert!(
            last.is_empty(),
            "draining publishes an empty queue snapshot"
        );
    }

    #[tokio::test]
    async fn staged_removal_holds_the_exact_payload_until_durable_commit() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let id = Uuid::new_v4();
        let receipt = ClientSubmissionReceipt {
            id,
            fingerprint: "consumed-fingerprint".into(),
            wire_fingerprint: "wire-fingerprint".into(),
            origin_principal: Some("flycockpit:user-1".into()),
        };
        let original = UserSubmission {
            text: format!("inspect {IMAGE_PART_SENTINEL}"),
            display_text: Some("inspect screenshot".into()),
            tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
                tool: "read".into(),
                path: "src/lib.rs".into(),
                detail: "expanded source".into(),
                ok: true,
            }],
            images: vec![vec![0, 1, 2, 3]],
            forced_skill: Some("review".into()),
            origin_principal: receipt.origin_principal.clone(),
            queue_item_ids: vec![id],
            client_submissions: vec![receipt.clone()],
            queue_target: Some(target.clone()),
            ..Default::default()
        };
        let (_, _, inserted) = queue
            .push_idempotent(receipt, original.clone(), target)
            .await;
        assert_eq!(inserted, IdempotentPush::Inserted);

        let (result, staged, snapshot) = queue.stage_remove(id).await.unwrap();
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            snapshot.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![id],
            "the visible queue does not change before the terminal receipt commits"
        );
        let staged = staged.expect("queued item is staged");
        assert_eq!(staged.ids(), &[id]);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
                .await
                .is_err(),
            "a staged removal must not race into execution"
        );
        assert_eq!(
            serde_json::to_value(
                queue
                    .pending_submission(id)
                    .await
                    .expect("held payload remains in the queue")
            )
            .unwrap(),
            serde_json::to_value(original).unwrap(),
            "the hold preserves wire text, display text, tags, images, skill, principal, and receipt"
        );
        queue.mark_staged_removal_failed(&staged).await;
        let (_, retry, _) = queue
            .stage_remove(id)
            .await
            .expect("retrying the same removal reclaims the hold");
        assert_eq!(retry.as_ref().map(StagedQueueRemoval::ids), Some(&[id][..]));
        let committed = queue.commit_staged_removal(staged).await;
        assert!(committed.is_empty());
        assert!(
            queue.pending_submission(id).await.is_none(),
            "only the durable commit releases the exact payload"
        );
    }

    #[tokio::test]
    async fn staged_removal_retry_and_front_requeue_preserve_fifo_order() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("Review", 1, "task-1", "review");
        let (root_first, _) = queue
            .push(UserSubmission::text("root first"), root.clone())
            .await;
        let (child_first, _) = queue
            .push(UserSubmission::text("child first"), child.clone())
            .await;
        let (root_newest, _) = queue
            .push(UserSubmission::text("root newest"), root.clone())
            .await;
        let (child_newest, _) = queue
            .push(UserSubmission::text("child newest"), child.clone())
            .await;

        let (result, staged, snapshot) = queue.stage_remove_newest_for(&root.id).await.unwrap();
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        let staged = staged.expect("newest root item is staged");
        assert_eq!(staged.ids(), &[root_newest]);
        assert_eq!(
            snapshot.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![root_first, child_first, root_newest, child_newest]
        );
        let committed = queue.commit_staged_removal(staged).await;
        assert_eq!(
            committed.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![root_first, child_first, child_newest]
        );

        let (root_last, _) = queue
            .push(UserSubmission::text("root last"), root.clone())
            .await;
        let started_child = queue
            .recv_for(Some(&child.id))
            .await
            .expect("child item starts before the removal hold");
        let (result, staged, snapshot) = queue.stage_remove_editable_for(&root.id).await.unwrap();
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        let staged = staged.expect("all editable root items are staged");
        assert_eq!(staged.ids(), &[root_first, root_last]);
        assert_eq!(
            snapshot.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![root_first, child_newest, root_last]
        );
        let requeued = queue.requeue_front(started_child, child.clone()).await;
        assert_eq!(
            requeued.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![child_first, root_first, child_newest, root_last],
            "front requeue preserves its normal FIFO semantics while removal is held"
        );
        queue.mark_staged_removal_failed(&staged).await;
        assert!(
            queue.stage_remove(child_newest).await.is_err(),
            "a different removal cannot steal a failed hold"
        );
        let (_, retry, _) = queue
            .stage_remove_editable_for(&root.id)
            .await
            .expect("the same editable removal can retry");
        assert_eq!(
            retry.as_ref().map(StagedQueueRemoval::ids),
            Some(&[root_first, root_last][..])
        );
        let committed = queue.commit_staged_removal(staged).await;
        assert_eq!(
            committed.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![child_first, child_newest],
            "identity commit removes only held items after the concurrent front requeue"
        );
    }

    #[tokio::test]
    async fn repeated_cancel_hold_widens_to_newly_accepted_payloads() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let (first, _) = queue
            .push(UserSubmission::text("first"), target.clone())
            .await;
        let staged = queue
            .stage_discard_pending()
            .await
            .expect("first cancellation holds the pending queue");
        assert_eq!(staged.ids(), &[first]);
        queue.mark_staged_removal_failed(&staged).await;

        let (second, _) = queue
            .push(UserSubmission::text("accepted after failed cancel"), target)
            .await;
        let widened = queue
            .stage_discard_pending()
            .await
            .expect("retrying cancellation widens the existing hold");
        assert_eq!(widened.ids(), &[first, second]);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), queue.recv())
                .await
                .is_err(),
            "neither the original nor newly accepted payload can execute while held"
        );
        assert!(queue.commit_staged_removal(widened).await.is_empty());
    }

    #[tokio::test]
    async fn cancellation_waits_for_an_in_progress_targeted_removal() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let (first, _) = queue
            .push(UserSubmission::text("first"), target.clone())
            .await;
        let (second, _) = queue.push(UserSubmission::text("second"), target).await;
        let (_, targeted, _) = queue.stage_remove(second).await.unwrap();
        let targeted = targeted.expect("targeted receipt write owns the barrier");

        let cancel_queue = queue.clone();
        let mut cancellation = tokio::spawn(async move {
            cancel_queue
                .stage_discard_pending()
                .await
                .expect("remaining queue becomes the cancellation claim")
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), &mut cancellation)
                .await
                .is_err(),
            "cancellation cannot overwrite an in-progress removal ticket"
        );

        assert_eq!(
            queue
                .commit_staged_removal(targeted)
                .await
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            vec![first]
        );
        let cancellation = tokio::time::timeout(std::time::Duration::from_secs(1), cancellation)
            .await
            .expect("targeted commit releases the cancellation barrier")
            .unwrap();
        assert_eq!(cancellation.ids(), &[first]);
        assert!(queue.commit_staged_removal(cancellation).await.is_empty());
    }

    #[tokio::test]
    async fn client_submission_id_is_idempotent_for_identical_payload_and_rejects_reuse() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let id = Uuid::new_v4();
        let original = UserSubmission {
            text: format!("inspect {IMAGE_PART_SENTINEL}"),
            display_text: Some("inspect pasted image".to_string()),
            tag_expansions: vec![crate::daemon::proto::TagExpansionMeta {
                tool: "read".into(),
                path: "src/lib.rs".into(),
                detail: "12 lines".into(),
                ok: true,
            }],
            images: vec![vec![1, 2, 3, 4]],
            forced_skill: Some("review".to_string()),
            ..Default::default()
        };
        let fingerprint = original.client_fingerprint();
        let receipt = |fingerprint: String| ClientSubmissionReceipt {
            id,
            fingerprint,
            wire_fingerprint: "wire-original".to_string(),
            origin_principal: None,
        };

        let (_, first_snapshot, first) = queue
            .push_idempotent(
                receipt(fingerprint.clone()),
                original.clone(),
                target.clone(),
            )
            .await;
        assert_eq!(first, IdempotentPush::Inserted);
        assert_eq!(
            first_snapshot
                .iter()
                .map(|item| item.id)
                .collect::<Vec<_>>(),
            vec![id]
        );

        let (_, duplicate_snapshot, duplicate) = queue
            .push_idempotent(
                receipt(fingerprint.clone()),
                original.clone(),
                target.clone(),
            )
            .await;
        assert_eq!(duplicate, IdempotentPush::Duplicate);
        assert_eq!(duplicate_snapshot.len(), 1, "retry must not enqueue twice");
        assert_eq!(
            queue.probe_idempotent(id, "wire-original", None).await.0,
            IdempotentProbe::ExactDuplicate
        );
        assert_eq!(
            queue.probe_idempotent(id, "wire-reupload", None).await.0,
            IdempotentProbe::ContentCheckRequired
        );
        assert_eq!(
            queue
                .probe_idempotent(id, "wire-original", Some("flycockpit:other"))
                .await
                .0,
            IdempotentProbe::Conflict
        );

        let mut changed = original.clone();
        changed.images[0].push(5);
        let (_, conflict_snapshot, conflict) = queue
            .push_idempotent(
                receipt(changed.client_fingerprint()),
                changed,
                target.clone(),
            )
            .await;
        assert_eq!(conflict, IdempotentPush::Conflict);
        assert_eq!(
            conflict_snapshot.len(),
            1,
            "conflict must not mutate the queue"
        );

        let delivered = queue.recv().await.expect("one accepted payload");
        assert_eq!(delivered.text, original.text);
        assert_eq!(delivered.images, original.images);
        assert_eq!(delivered.queue_item_ids, vec![id]);
        queue.finish(&[id]).await;

        let (_, completed_retry_snapshot, completed_retry) = queue
            .push_idempotent(receipt(fingerprint), original, target)
            .await;
        assert_eq!(completed_retry, IdempotentPush::Duplicate);
        assert!(
            completed_retry_snapshot.is_empty(),
            "a retry after completion must acknowledge without new inference"
        );
    }

    #[test]
    fn client_fingerprint_distinguishes_absent_and_empty_optional_fields() {
        let absent = UserSubmission::text("same wire text");

        let mut empty_display = absent.clone();
        empty_display.display_text = Some(String::new());
        assert_ne!(
            absent.client_fingerprint(),
            empty_display.client_fingerprint(),
            "display_text presence is part of the exact client payload"
        );

        let mut empty_skill = absent.clone();
        empty_skill.forced_skill = Some(String::new());
        assert_ne!(
            absent.client_fingerprint(),
            empty_skill.client_fingerprint(),
            "forced_skill presence is part of the exact client payload"
        );

        assert_ne!(
            empty_display.client_fingerprint(),
            empty_skill.client_fingerprint(),
            "option discriminants remain scoped to their payload fields"
        );
    }

    #[tokio::test]
    async fn user_submission_queue_remove_after_drain_reports_already_started() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);

        let (id, _) = queue
            .push(UserSubmission::text("started"), QueueTarget::root("Build"))
            .await;
        assert_eq!(queue.recv().await.expect("started").text, "started");

        let (result, snapshot) = queue.remove(id).await;
        assert_eq!(result, RemoveQueuedMessageResult::AlreadyStarted);
        assert!(snapshot.is_empty());
    }

    #[tokio::test]
    async fn user_submission_queue_remove_after_finish_reports_not_found() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);

        let (id, _) = queue
            .push(UserSubmission::text("started"), QueueTarget::root("Build"))
            .await;
        assert_eq!(queue.recv().await.expect("started").text, "started");
        queue.finish(&[id]).await;

        let (result, snapshot) = queue.remove(id).await;
        assert_eq!(result, RemoveQueuedMessageResult::NotFound);
        assert!(snapshot.is_empty());
    }

    #[tokio::test]
    async fn user_submission_queue_remove_editable_reports_started_only_while_in_flight() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");

        let (id, _) = queue
            .push(UserSubmission::text("started"), root.clone())
            .await;
        assert_eq!(
            queue.recv_for(Some(&root.id)).await.expect("started").text,
            "started"
        );

        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::AlreadyStarted);
        assert!(removed.is_empty());
        assert!(snapshot.is_empty());

        queue.finish(&[id]).await;
        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::NotFound);
        assert!(removed.is_empty());
        assert!(snapshot.is_empty());
    }

    #[tokio::test]
    async fn user_submission_queue_finish_prevents_stale_started_target_mirror_case() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");

        let (root_id, _) = queue
            .push(UserSubmission::text("root started"), root.clone())
            .await;
        assert_eq!(
            queue.recv_for(Some(&root.id)).await.expect("root").text,
            "root started"
        );
        queue.finish(&[root_id]).await;
        queue
            .push(UserSubmission::text("child pending"), child.clone())
            .await;

        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::NotFound);
        assert!(removed.is_empty());
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child pending"]
        );
    }

    #[tokio::test]
    async fn user_submission_queue_finish_is_idempotent_with_requeue_front() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");

        let (id, _) = queue
            .push(UserSubmission::text("first"), root.clone())
            .await;
        let first = queue.recv_for(Some(&root.id)).await.expect("first");
        queue.requeue_front(first, root.clone()).await;
        queue.finish(&[id]).await;

        let first_again = queue.recv_for(Some(&root.id)).await.expect("first again");
        assert_eq!(first_again.queue_item_ids, vec![id]);
    }

    #[tokio::test]
    async fn user_submission_queue_finish_clears_folded_submission_ids() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");

        queue
            .push(UserSubmission::text("first"), root.clone())
            .await;
        queue
            .push(UserSubmission::text("second"), root.clone())
            .await;
        let mut drained = Vec::new();
        queue.drain_into_for(&mut drained, 2, Some(&root.id)).await;
        let ids = drained
            .iter()
            .flat_map(|submission| submission.queue_item_ids.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(ids.len(), 2);

        queue.finish(&ids).await;
        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::NotFound);
        assert!(removed.is_empty());
        assert!(snapshot.is_empty());
    }

    #[tokio::test]
    async fn user_submission_queue_drain_respects_max_fold() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        for idx in 0..3 {
            queue
                .push(UserSubmission::text(format!("msg {idx}")), target.clone())
                .await;
        }

        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, 2, Some(&target.id))
            .await;

        assert_eq!(
            drained
                .iter()
                .map(|submission| submission.text.as_str())
                .collect::<Vec<_>>(),
            vec!["msg 0", "msg 1"]
        );
        assert_eq!(queue.recv().await.expect("remaining").text, "msg 2");
    }

    #[tokio::test]
    async fn user_submission_queue_requeue_front_restores_started_item() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let (id, _) = queue
            .push(UserSubmission::text("first"), target.clone())
            .await;
        queue
            .push(UserSubmission::text("second"), target.clone())
            .await;

        let first = queue.recv_for(Some(&target.id)).await.expect("first");
        assert_eq!(first.queue_item_ids, vec![id]);
        queue.requeue_front(first, target.clone()).await;

        let first_again = queue.recv_for(Some(&target.id)).await.expect("first again");
        assert_eq!(first_again.text, "first");
        assert_eq!(first_again.queue_item_ids, vec![id]);
        assert_eq!(
            queue.recv_for(Some(&target.id)).await.expect("second").text,
            "second"
        );
    }

    #[tokio::test]
    async fn user_submission_queue_drains_only_matching_target() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");

        queue
            .push(UserSubmission::text("root first"), root.clone())
            .await;
        queue
            .push(UserSubmission::text("child only"), child.clone())
            .await;
        queue
            .push(UserSubmission::text("root second"), root.clone())
            .await;

        let mut drained = Vec::new();
        queue.drain_into_for(&mut drained, 10, Some(&root.id)).await;
        assert_eq!(
            drained
                .iter()
                .map(|submission| submission.text.as_str())
                .collect::<Vec<_>>(),
            vec!["root first", "root second"]
        );
        assert_eq!(
            queue.recv_for(Some(&child.id)).await.map(|s| s.text),
            Some("child only".to_string())
        );
    }

    #[tokio::test]
    async fn user_submission_queue_bulk_removes_matching_target_fifo() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");

        queue
            .push(UserSubmission::text("root first"), root.clone())
            .await;
        queue
            .push(UserSubmission::text("child only"), child.clone())
            .await;
        queue
            .push(UserSubmission::text("root second"), root.clone())
            .await;

        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            removed
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["root first", "root second"]
        );
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child only"]
        );
        assert_eq!(
            queue.recv_for(Some(&child.id)).await.map(|s| s.text),
            Some("child only".to_string())
        );
    }

    #[tokio::test]
    async fn user_submission_queue_bulk_reports_started_after_partial_removal() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");

        queue
            .push(UserSubmission::text("root folding"), root.clone())
            .await;
        let mut drained = Vec::new();
        queue.drain_into_for(&mut drained, 1, Some(&root.id)).await;
        assert_eq!(drained[0].text, "root folding");
        queue
            .push(UserSubmission::text("root editable"), root.clone())
            .await;

        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::AlreadyStarted);
        assert_eq!(
            removed
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["root editable"]
        );
        assert!(snapshot.is_empty());
    }

    #[tokio::test]
    async fn user_submission_queue_removes_newest_matching_target_only() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");

        queue
            .push(UserSubmission::text("root older"), root.clone())
            .await;
        queue
            .push(UserSubmission::text("child only"), child.clone())
            .await;
        queue
            .push(UserSubmission::text("root newest"), root.clone())
            .await;

        let (result, removed, snapshot) = queue.remove_newest_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            removed.as_ref().map(|item| item.text.as_str()),
            Some("root newest")
        );
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["root older", "child only"]
        );

        let (result, removed, snapshot) = queue.remove_newest_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            removed.as_ref().map(|item| item.text.as_str()),
            Some("root older")
        );
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child only"]
        );
        assert_eq!(
            queue.recv_for(Some(&child.id)).await.map(|s| s.text),
            Some("child only".to_string())
        );
    }

    #[tokio::test]
    async fn user_submission_queue_remove_newest_does_not_steal_other_target() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let child = QueueTarget::child("builder", 1, "call-1", "default");

        queue
            .push(UserSubmission::text("child only"), child.clone())
            .await;

        let (result, removed, snapshot) = queue.remove_newest_for("root").await;
        assert_eq!(result, RemoveQueuedMessageResult::NotFound);
        assert!(removed.is_none());
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child only"]
        );
        assert_eq!(
            queue.recv_for(Some(&child.id)).await.map(|s| s.text),
            Some("child only".to_string())
        );
    }

    #[tokio::test]
    async fn user_submission_queue_remove_newest_reports_started_at_folding_boundary() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");

        queue
            .push(UserSubmission::text("root folding"), root.clone())
            .await;
        queue
            .push(UserSubmission::text("child pending"), child.clone())
            .await;

        let mut drained = Vec::new();
        queue.drain_into_for(&mut drained, 1, Some(&root.id)).await;
        assert_eq!(drained[0].text, "root folding");

        let (result, removed, snapshot) = queue.remove_newest_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::AlreadyStarted);
        assert!(removed.is_none());
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child pending"]
        );
        assert_eq!(
            queue.recv_for(Some(&child.id)).await.map(|s| s.text),
            Some("child pending".to_string())
        );
    }
}
