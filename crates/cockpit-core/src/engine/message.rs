//! Thin aliases over `rig::message::*` so callers don't need a `rig::` import.
//!
//! Why aliasing rather than re-wrapping: rig's types are well-shaped, and
//! re-implementing them buys nothing except divergence drift when rig
//! evolves. The aliases give us a single import point if we ever do want
//! to swap implementations.

use rig::message::{
    AudioMediaType, ImageMediaType, MimeType as _, ProviderCallId, ToolCallId, UserContent,
    VideoMediaType,
};
pub use rig::{
    completion::ToolDefinition,
    message::{AssistantContent, Message, ToolCall},
};

use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use base64::Engine as _;
use tokio::sync::{Mutex, Notify, watch};
use uuid::Uuid;

pub use crate::daemon::proto::{
    QueueDeliveryClass, QueueItem as QueuedUserMessage, QueueItemStatus, QueueTarget,
};
pub use cockpit_client::{
    image_upload::SubmissionImage,
    submission::{
        ClientSubmissionReceipt, ClientUserSubmission as UserSubmission,
        PendingSubmissionTerminalDisposition, SubmissionMedia, SubmissionOrigin,
        UserSubmissionKind,
    },
};

/// Sentinel emitted in wire text by
/// the TUI paste registry at each real-image
/// position. We split on it here to interleave text and image content
/// parts in order when assembling the outbound user [`Message`].
pub use crate::daemon::proto::IMAGE_PART_SENTINEL;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoveQueuedMessageResult {
    Removed,
    AlreadyStarted,
    NotFound,
    EditConflict,
}

#[derive(Debug, Clone)]
struct QueuedSubmission {
    id: Uuid,
    submission: UserSubmission,
    target: QueueTarget,
    delivery_class: QueueDeliveryClass,
    /// Escalation flag: deliver as soon as a safe boundary exists.
    /// Distinct from [`QueueDeliveryClass`]; send-now never changes the
    /// stored class of sibling messages.
    send_now: bool,
    /// This escalation came from the whole-queue control, so a foreground
    /// tool must yield even when every currently escalated item belongs to a
    /// different target.
    send_now_all: bool,
    not_before: Option<tokio::time::Instant>,
    edit_lease: Option<QueueEditLease>,
    last_edit_operation: Option<(Uuid, cockpit_proto::QueueEditAction)>,
}

#[derive(Debug, Clone, Copy)]
struct QueueEditLease {
    operation_id: Uuid,
    expires_at: tokio::time::Instant,
}

/// Queue-only state retained while an item is started. `UserSubmission`
/// carries the effective delivery class used by the driver, so it cannot also
/// be the source of truth for an escalated held item's original class.
#[derive(Debug, Clone)]
struct StartedQueueMetadata {
    delivery_class: QueueDeliveryClass,
    send_now: bool,
    send_now_all: bool,
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
    started_metadata: HashMap<Uuid, StartedQueueMetadata>,
    /// Every id accepted during this worker epoch, including completed and
    /// explicitly removed items. This closes the check/enqueue race for
    /// idempotent retries; restart retries are resolved from durable events.
    accepted: HashMap<Uuid, AcceptedClientSubmission>,
    /// Session cancellation epoch captured by adopted work when it registers.
    /// Advancing this under `inner` makes cancellation and late-result enqueue
    /// mutually ordered even though `CancellationToken::cancel` is lock-free.
    cancellation_generation: u64,
    /// Monotonic ordering for queue watch publications. Cancellation advances
    /// this even when it has no immediate snapshot to publish, suppressing a
    /// pre-cancellation snapshot whose sender was delayed after dropping
    /// `inner`.
    publication_revision: u64,
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
    published_revision: Arc<std::sync::Mutex<u64>>,
    send_now_updates: watch::Sender<u64>,
}

struct QueuePublication {
    revision: u64,
    snapshot: Vec<QueuedUserMessage>,
}

pub(crate) struct QueueCancellationFence<'a> {
    state: tokio::sync::MutexGuard<'a, UserSubmissionQueueState>,
}

impl QueueCancellationFence<'_> {
    pub(crate) fn generation(&self) -> u64 {
        self.state.cancellation_generation
    }
}

impl UserSubmissionQueue {
    pub fn new(updates: watch::Sender<Vec<QueuedUserMessage>>) -> Self {
        let (stage_updates, _) = watch::channel(0);
        let (send_now_updates, _) = watch::channel(0);
        Self {
            inner: Arc::new(Mutex::new(UserSubmissionQueueState::default())),
            notify: Arc::new(Notify::new()),
            stage_updates,
            updates,
            published_revision: Arc::new(std::sync::Mutex::new(0)),
            send_now_updates,
        }
    }

    /// Hold the queue cancellation fence while adopted work is registered.
    /// Callers acquire their registry lock only after this guard, matching the
    /// cancellation path's queue -> registry lock order.
    pub(crate) async fn cancellation_fence(&self) -> QueueCancellationFence<'_> {
        QueueCancellationFence {
            state: self.inner.lock().await,
        }
    }

    /// Advance the adopted-result epoch and suppress every older queue
    /// publication before returning the held fence to the cancellation path.
    pub(crate) async fn advance_cancellation_fence(&self) -> QueueCancellationFence<'_> {
        let mut state = self.inner.lock().await;
        state.cancellation_generation = state.cancellation_generation.saturating_add(1);
        state.publication_revision = state.publication_revision.saturating_add(1);
        let revision = state.publication_revision;
        {
            let mut published = crate::sync::lock_or_recover(&self.published_revision);
            *published = (*published).max(revision);
        }
        QueueCancellationFence { state }
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

    /// Enqueue an adopted tool result only if both its token and queue-owned
    /// cancellation generation are live at the mutation boundary. The
    /// generation closes the lock-free token race, while versioned publication
    /// prevents an accepted pre-fence snapshot from surfacing after cancel.
    pub(crate) async fn push_if_not_cancelled(
        &self,
        submission: UserSubmission,
        target: QueueTarget,
        cancel: &tokio_util::sync::CancellationToken,
        expected_cancellation_generation: u64,
    ) -> Option<(Uuid, Vec<QueuedUserMessage>)> {
        let id = Uuid::new_v4();
        let publication = {
            let mut state = self.inner.lock().await;
            if state.closed
                || cancel.is_cancelled()
                || state.cancellation_generation != expected_cancellation_generation
            {
                return None;
            }
            state.pending.push_back(QueuedSubmission {
                id,
                delivery_class: submission.delivery_class,
                send_now: false,
                send_now_all: false,
                submission,
                target,
                not_before: None,
                edit_lease: None,
                last_edit_operation: None,
            });
            publication_snapshot(&mut state)
        };
        let snapshot = publication.snapshot.clone();
        self.publish(publication);
        self.notify.notify_one();
        Some((id, snapshot))
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
        let committed = {
            let mut state = self.inner.lock().await;
            commit_idempotent_push(&mut state, receipt, submission, target)
        };
        self.finish_idempotent_push(committed)
    }

    /// Stamp and insert from the live enqueue replica.
    ///
    /// Lock order: `enqueue_target` (std) then `inner` (tokio). The std mutex
    /// is never held across an await. On queue contention this drops the
    /// replica, waits for `inner`, and retries so the id written at insert is
    /// `enqueue_target` at that instant — not a clone taken before FCM2/DB
    /// work or before a stack-last adopt.
    pub async fn push_idempotent_on_live_target(
        &self,
        receipt: ClientSubmissionReceipt,
        mut submission: UserSubmission,
        enqueue_target: &std::sync::Mutex<QueueTarget>,
    ) -> (Uuid, Vec<QueuedUserMessage>, IdempotentPush) {
        let committed = loop {
            {
                let replica = crate::sync::lock_or_recover(enqueue_target);
                match self.inner.try_lock() {
                    Ok(mut state) => {
                        let target = replica.clone();
                        submission.queue_target = Some(target.clone());
                        break commit_idempotent_push(&mut state, receipt, submission, target);
                    }
                    Err(_) => {}
                }
            }
            drop(self.inner.lock().await);
        };
        self.finish_idempotent_push(committed)
    }

    fn finish_idempotent_push(
        &self,
        committed: IdempotentPushCommit,
    ) -> (Uuid, Vec<QueuedUserMessage>, IdempotentPush) {
        match committed.publication {
            Some(publication) => {
                let snapshot = publication.snapshot.clone();
                self.publish(publication);
                self.notify.notify_one();
                (committed.id, snapshot, committed.outcome)
            }
            None => (
                committed.id,
                committed.unpublished_snapshot,
                committed.outcome,
            ),
        }
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

    /// Whether this worker epoch already accepted `id`. Callers use this to
    /// preserve lost-ack replay semantics before applying fresh-insert fences.
    pub async fn has_accepted(&self, id: Uuid) -> bool {
        self.inner.lock().await.accepted.contains_key(&id)
    }

    /// Non-mutating variant of [`Self::push_idempotent`]'s dedup decision: does
    /// this content fingerprint / origin match an already-accepted submission
    /// for `id`? Returns `Inserted` when the id is unseen (a genuine fresh
    /// accept would occur), `Duplicate` on an exact match, and `Conflict` on a
    /// different-payload reuse — WITHOUT enqueuing anything. The worker uses
    /// this to make the acceptance decision BEFORE committing a durable
    /// remote-operation ledger row, so a conflicting or already-accepted send
    /// never reserves/commits a fresh ledger row. Safe against the mutating
    /// `push_idempotent` because the worker processes `SessionWork` serially and
    /// the `accepted` set is append-only within an epoch.
    pub async fn peek_idempotent(
        &self,
        id: Uuid,
        fingerprint: &str,
        origin_principal: Option<&str>,
    ) -> (IdempotentPush, Vec<QueuedUserMessage>) {
        let state = self.inner.lock().await;
        let outcome = match state.accepted.get(&id) {
            Some(existing) => {
                if existing.origin_principal.as_deref() != origin_principal
                    || existing.fingerprint != fingerprint
                {
                    IdempotentPush::Conflict
                } else {
                    IdempotentPush::Duplicate
                }
            }
            None => IdempotentPush::Inserted,
        };
        (outcome, snapshot_pending(&state))
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
        let submission_target = submission.queue_target.take();
        submission.queue_item_ids.clear();
        let publication = {
            let mut state = self.inner.lock().await;
            state.started.remove(&id);
            let target = state
                .started_targets
                .remove(&id)
                .or(submission_target)
                .unwrap_or(fallback_target);
            let metadata = state.started_metadata.remove(&id);
            let delivery_class = metadata
                .as_ref()
                .map_or(submission.delivery_class, |metadata| {
                    metadata.delivery_class
                });
            let send_now = metadata.as_ref().is_some_and(|metadata| metadata.send_now);
            let send_now_all = metadata.is_some_and(|metadata| metadata.send_now_all);
            submission.delivery_class = delivery_class;
            state.pending.push_front(QueuedSubmission {
                id,
                delivery_class,
                send_now,
                send_now_all,
                submission,
                target,
                not_before: (!delay.is_zero()).then(|| tokio::time::Instant::now() + delay),
                edit_lease: None,
                last_edit_operation: None,
            });
            publication_snapshot(&mut state)
        };
        let snapshot = publication.snapshot.clone();
        self.publish(publication);
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
            state.started_metadata.remove(id);
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
        for pending in &mut state.pending {
            clear_expired_edit_lease(pending);
        }
        if state
            .pending
            .iter()
            .any(|pending| pending.id == id && pending.edit_lease.is_some())
        {
            return Err(QueueRemovalInProgress);
        }
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
        stage_remove_newest_locked(&mut state, target_id)
    }

    /// Remove the newest pending item for the live enqueue replica.
    ///
    /// Same lock order as [`Self::push_idempotent_on_live_target`]: replica
    /// then `inner`, never holding the std mutex across an await.
    pub async fn stage_remove_newest_on_live_target(
        &self,
        enqueue_target: &std::sync::Mutex<QueueTarget>,
    ) -> Result<
        (
            RemoveQueuedMessageResult,
            Option<StagedQueueRemoval>,
            Vec<QueuedUserMessage>,
        ),
        QueueRemovalInProgress,
    > {
        loop {
            {
                let replica = crate::sync::lock_or_recover(enqueue_target);
                match self.inner.try_lock() {
                    Ok(mut state) => {
                        return stage_remove_newest_locked(&mut state, &replica.id);
                    }
                    Err(_) => {}
                }
            }
            drop(self.inner.lock().await);
        }
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
        for pending in &mut state.pending {
            clear_expired_edit_lease(pending);
        }
        if state
            .pending
            .iter()
            .any(|pending| pending.target.id == target_id && pending.edit_lease.is_some())
        {
            return Err(QueueRemovalInProgress);
        }
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
        // Editable removal targets pending (not-yet-started) submissions. When
        // any such submission exists it is removed, so the result must be
        // `Removed` even if the target also has an in-flight started turn: the
        // started turn is not an editable item and is left untouched. Reporting
        // `AlreadyStarted` here while still staging indices would make the
        // durable receipt inconsistent (`applied=false` with `removed_count>0`),
        // which `RemoteQueueMutationReceiptV1::validate` rejects. `AlreadyStarted`
        // is reserved for the case where nothing pending matched but a started
        // turn exists — matching `stage_remove_newest_for`'s precedent.
        let result = if !indices.is_empty() {
            RemoveQueuedMessageResult::Removed
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

    /// Atomically claim every pending queue item for a whole-queue edit or
    /// cancellation. The snapshot is session-wide, so this operation must not
    /// silently narrow itself to whichever agent happens to be foregrounded.
    pub async fn stage_remove_all(
        &self,
        foreground_target_id: Option<&str>,
    ) -> Result<
        (
            RemoveQueuedMessageResult,
            Option<StagedQueueRemoval>,
            Vec<QueuedUserMessage>,
        ),
        QueueRemovalInProgress,
    > {
        let mut state = self.inner.lock().await;
        for pending in &mut state.pending {
            clear_expired_edit_lease(pending);
        }
        if state
            .pending
            .iter()
            .any(|pending| pending.edit_lease.is_some())
        {
            return Err(QueueRemovalInProgress);
        }
        let scope = StagedRemovalScope::AllPending;
        if let Some(staged) = existing_stage_for_scope(&mut state, &scope)? {
            let snapshot = snapshot_pending(&state);
            return Ok((RemoveQueuedMessageResult::Removed, Some(staged), snapshot));
        }
        let mut targets = Vec::<(usize, QueueTarget)>::new();
        for pending in &state.pending {
            if !targets
                .iter()
                .any(|(_, target)| target.id == pending.target.id)
            {
                targets.push((targets.len(), pending.target.clone()));
            }
        }
        targets.sort_by(|(left_index, left), (right_index, right)| {
            let left_focused = foreground_target_id == Some(left.id.as_str());
            let right_focused = foreground_target_id == Some(right.id.as_str());
            right_focused
                .cmp(&left_focused)
                .then_with(|| right.depth.cmp(&left.depth))
                .then_with(|| left_index.cmp(right_index))
        });
        let mut indices = Vec::with_capacity(state.pending.len());
        for (_, target) in targets {
            indices.extend(
                state
                    .pending
                    .iter()
                    .enumerate()
                    .filter_map(|(index, item)| {
                        (item.target.id == target.id
                            && (item.delivery_class.is_steering() || item.send_now))
                            .then_some(index)
                    }),
            );
            indices.extend(
                state
                    .pending
                    .iter()
                    .enumerate()
                    .filter_map(|(index, item)| {
                        (item.target.id == target.id
                            && !item.send_now
                            && item.delivery_class == QueueDeliveryClass::Held)
                            .then_some(index)
                    }),
            );
        }
        let result = if indices.is_empty() {
            if state.started.is_empty() {
                RemoveQueuedMessageResult::NotFound
            } else {
                RemoveQueuedMessageResult::AlreadyStarted
            }
        } else {
            RemoveQueuedMessageResult::Removed
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

    /// Release a staged claim when the enclosing remote operation is rejected
    /// before any durable terminal receipt is written.
    pub async fn abort_staged_removal(&self, staged: &StagedQueueRemoval) {
        {
            let mut state = self.inner.lock().await;
            assert_staged_removal(&state, staged);
            state.staged_removal = None;
            state.staged_removal_failed = false;
        }
        self.stage_updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
        self.notify.notify_one();
    }

    /// Make a staged removal visible only after its terminal receipts are
    /// durable. Consumers resume from the remaining queue at this boundary.
    pub async fn commit_staged_removal(
        &self,
        staged: StagedQueueRemoval,
    ) -> Vec<QueuedUserMessage> {
        let publication = {
            let mut state = self.inner.lock().await;
            assert_staged_removal(&state, &staged);
            let ids = staged.ids.iter().copied().collect::<HashSet<_>>();
            state.pending.retain(|item| !ids.contains(&item.id));
            state.staged_removal = None;
            state.staged_removal_failed = false;
            publication_snapshot(&mut state)
        };
        let snapshot = publication.snapshot.clone();
        self.publish(publication);
        self.stage_updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
        self.notify.notify_one();
        snapshot
    }

    /// Move pending items whose target is no longer a live stack frame onto
    /// `live_target`. Wait/drain select by the live frame id; leaving a
    /// popped child's id on an item would strand it (AC2).
    pub async fn adopt_orphaned_pending(
        &self,
        live_target_ids: &HashSet<String>,
        live_target: QueueTarget,
    ) {
        let publication = {
            let mut state = self.inner.lock().await;
            let started = state.started.clone();
            let mut changed = false;
            for item in state.pending.iter_mut() {
                if started.contains(&item.id) || live_target_ids.contains(&item.target.id) {
                    continue;
                }
                item.target = live_target.clone();
                item.submission.queue_target = Some(live_target.clone());
                changed = true;
            }
            changed.then(|| publication_snapshot(&mut state))
        };
        let Some(publication) = publication else {
            return;
        };
        self.publish(publication);
        self.notify.notify_one();
    }

    /// Publish the current pending-queue snapshot without mutating it.
    ///
    /// Attach hydration uses this so a newly subscribed client learns the
    /// authoritative queue even when the last queue mutation happened before
    /// it connected. Publishing an empty snapshot is intentional: it clears a
    /// stale client-side mirror after reconnect.
    pub async fn republish(&self) {
        let publication = {
            let mut state = self.inner.lock().await;
            publication_snapshot(&mut state)
        };
        self.publish(publication);
    }

    /// Change the delivery class of one pending item. Folding/started
    /// items are not rewritten.
    pub async fn set_delivery_class(
        &self,
        id: Uuid,
        delivery_class: QueueDeliveryClass,
        replacement: Option<cockpit_proto::QueueItemReplacement>,
    ) -> (
        RemoveQueuedMessageResult,
        Option<QueuedUserMessage>,
        Vec<QueuedUserMessage>,
    ) {
        const EDIT_LEASE: std::time::Duration = std::time::Duration::from_secs(10 * 60);
        let reserve_lease = replacement.as_ref().is_some_and(|replacement| {
            replacement.action == cockpit_proto::QueueEditAction::Reserve
        });
        let (result, item, publication) = {
            let mut state = self.inner.lock().await;
            if let Some(pending) = state.pending.iter_mut().find(|item| item.id == id) {
                clear_expired_edit_lease(pending);
                let result = match replacement {
                    None if pending.edit_lease.is_some() => RemoveQueuedMessageResult::EditConflict,
                    None => {
                        pending.delivery_class = delivery_class;
                        pending.submission.delivery_class = delivery_class;
                        if delivery_class == QueueDeliveryClass::Held {
                            pending.send_now = false;
                            pending.send_now_all = false;
                        }
                        RemoveQueuedMessageResult::Removed
                    }
                    Some(replacement)
                        if pending.last_edit_operation
                            == Some((replacement.operation_id, replacement.action)) =>
                    {
                        RemoveQueuedMessageResult::Removed
                    }
                    Some(replacement)
                        if pending
                            .last_edit_operation
                            .is_some_and(|(operation_id, _)| {
                                operation_id == replacement.operation_id
                            }) =>
                    {
                        RemoveQueuedMessageResult::EditConflict
                    }
                    Some(replacement) => match replacement.action {
                        cockpit_proto::QueueEditAction::Reserve => match pending.edit_lease {
                            Some(lease) if lease.operation_id == replacement.operation_id => {
                                RemoveQueuedMessageResult::Removed
                            }
                            Some(_) => RemoveQueuedMessageResult::EditConflict,
                            None => {
                                let expires_at = tokio::time::Instant::now() + EDIT_LEASE;
                                pending.edit_lease = Some(QueueEditLease {
                                    operation_id: replacement.operation_id,
                                    expires_at,
                                });
                                RemoveQueuedMessageResult::Removed
                            }
                        },
                        cockpit_proto::QueueEditAction::Commit => match pending.edit_lease {
                            Some(lease) if lease.operation_id == replacement.operation_id => {
                                pending.delivery_class = delivery_class;
                                pending.submission.delivery_class = delivery_class;
                                pending.submission.text = replacement.text;
                                pending.submission.display_text = replacement.display_text;
                                pending.submission.tag_expansions = replacement.tag_expansions;
                                // Existing image attachments belong to the queue item, not to
                                // the editable text projection, and survive the edit.
                                if delivery_class == QueueDeliveryClass::Held {
                                    pending.send_now = false;
                                    pending.send_now_all = false;
                                }
                                pending.edit_lease = None;
                                pending.last_edit_operation = Some((
                                    replacement.operation_id,
                                    cockpit_proto::QueueEditAction::Commit,
                                ));
                                RemoveQueuedMessageResult::Removed
                            }
                            _ => RemoveQueuedMessageResult::EditConflict,
                        },
                        cockpit_proto::QueueEditAction::Release => match pending.edit_lease {
                            Some(lease) if lease.operation_id == replacement.operation_id => {
                                pending.edit_lease = None;
                                pending.last_edit_operation = Some((
                                    replacement.operation_id,
                                    cockpit_proto::QueueEditAction::Release,
                                ));
                                RemoveQueuedMessageResult::Removed
                            }
                            _ => RemoveQueuedMessageResult::EditConflict,
                        },
                    },
                };
                let item = queued_message_from_submission(pending);
                (result, Some(item), publication_snapshot(&mut state))
            } else if state.started.contains(&id) {
                (
                    RemoveQueuedMessageResult::AlreadyStarted,
                    None,
                    publication_snapshot(&mut state),
                )
            } else {
                (
                    RemoveQueuedMessageResult::NotFound,
                    None,
                    publication_snapshot(&mut state),
                )
            }
        };
        let snapshot = publication.snapshot.clone();
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(publication);
            if reserve_lease {
                let notify = self.notify.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(EDIT_LEASE).await;
                    notify.notify_one();
                });
            }
        }
        (result, item, snapshot)
    }

    /// Set every pending item to `delivery_class`. Original queue order
    /// is preserved; folding/started items are left alone.
    pub async fn set_all_delivery_class(
        &self,
        delivery_class: QueueDeliveryClass,
    ) -> (RemoveQueuedMessageResult, Vec<QueuedUserMessage>) {
        let (result, publication) = {
            let mut state = self.inner.lock().await;
            for pending in &mut state.pending {
                clear_expired_edit_lease(pending);
            }
            if state
                .pending
                .iter()
                .any(|pending| pending.edit_lease.is_some())
            {
                return (
                    RemoveQueuedMessageResult::EditConflict,
                    snapshot_pending(&state),
                );
            }
            for pending in &mut state.pending {
                pending.delivery_class = delivery_class;
                pending.submission.delivery_class = delivery_class;
                if delivery_class == QueueDeliveryClass::Held {
                    pending.send_now = false;
                    pending.send_now_all = false;
                }
            }
            (
                RemoveQueuedMessageResult::Removed,
                publication_snapshot(&mut state),
            )
        };
        let snapshot = publication.snapshot.clone();
        self.publish(publication);
        (result, snapshot)
    }

    /// Mark one pending item for send-now escalation. The stored class is
    /// unchanged so siblings keep their classes.
    pub async fn mark_send_now(
        &self,
        id: Uuid,
    ) -> (
        RemoveQueuedMessageResult,
        Option<QueuedUserMessage>,
        Vec<QueuedUserMessage>,
    ) {
        let (result, item, publication) = {
            let mut state = self.inner.lock().await;
            if let Some(pending) = state.pending.iter_mut().find(|item| item.id == id) {
                clear_expired_edit_lease(pending);
                if pending.edit_lease.is_some() {
                    return (
                        RemoveQueuedMessageResult::EditConflict,
                        None,
                        snapshot_pending(&state),
                    );
                }
                pending.send_now = true;
                let item = queued_message_from_submission(pending);
                (
                    RemoveQueuedMessageResult::Removed,
                    Some(item),
                    publication_snapshot(&mut state),
                )
            } else if state.started.contains(&id) {
                (
                    RemoveQueuedMessageResult::AlreadyStarted,
                    None,
                    publication_snapshot(&mut state),
                )
            } else {
                (
                    RemoveQueuedMessageResult::NotFound,
                    None,
                    publication_snapshot(&mut state),
                )
            }
        };
        let snapshot = publication.snapshot.clone();
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(publication);
            self.notify.notify_one();
            self.signal_send_now();
        }
        (result, item, snapshot)
    }

    /// Atomically escalate the entire pending queue. This is the box-level
    /// operation; issuing one RPC per visible row races queue consumption and
    /// can otherwise produce a half-escalated queue.
    pub async fn mark_all_send_now(&self) -> (RemoveQueuedMessageResult, Vec<QueuedUserMessage>) {
        let (result, publication) = {
            let mut state = self.inner.lock().await;
            for pending in &mut state.pending {
                clear_expired_edit_lease(pending);
            }
            if state
                .pending
                .iter()
                .any(|pending| pending.edit_lease.is_some())
            {
                return (
                    RemoveQueuedMessageResult::EditConflict,
                    snapshot_pending(&state),
                );
            }
            let result = if state.pending.is_empty() {
                RemoveQueuedMessageResult::NotFound
            } else {
                RemoveQueuedMessageResult::Removed
            };
            for pending in &mut state.pending {
                pending.send_now = true;
                pending.send_now_all = true;
            }
            (result, publication_snapshot(&mut state))
        };
        let snapshot = publication.snapshot.clone();
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(publication);
            self.notify.notify_one();
            self.signal_send_now();
        }
        (result, snapshot)
    }

    pub(crate) fn subscribe_send_now(&self) -> watch::Receiver<u64> {
        self.send_now_updates.subscribe()
    }

    fn signal_send_now(&self) {
        self.send_now_updates.send_modify(|revision| {
            *revision = revision.saturating_add(1);
        });
    }

    pub(crate) async fn has_send_now_for(&self, target_id: Option<&str>) -> bool {
        self.first_send_now_for(target_id).await.is_some()
    }

    /// Whether a running foreground operation must yield at the next safe
    /// boundary. A whole-queue escalation is session-scoped, while a row
    /// escalation interrupts only the matching target.
    pub(crate) async fn has_send_now_boundary_for(&self, target_id: &str) -> bool {
        let state = self.inner.lock().await;
        state
            .pending
            .iter()
            .any(|item| item.send_now && (item.send_now_all || item.target.id == target_id))
    }

    /// Wait until a send-now escalation should yield the in-flight
    /// foreground operation for `target_id`, without popping.
    ///
    /// Held and steering items stay queued for Continue / run-end. A
    /// whole-queue (`send_now_all`) escalation is session-scoped and
    /// unblocks every target, matching [`Self::has_send_now_boundary_for`].
    /// Closed queues return `false` so shutdown does not hang.
    pub(crate) async fn wait_for_send_now_boundary_for(&self, target_id: &str) -> bool {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            {
                let state = self.inner.lock().await;
                if state.closed {
                    return false;
                }
                if state
                    .pending
                    .iter()
                    .any(|item| item.send_now && (item.send_now_all || item.target.id == target_id))
                {
                    return true;
                }
            }
            notified.await;
        }
    }

    async fn first_send_now_for(&self, target_id: Option<&str>) -> Option<Uuid> {
        let state = self.inner.lock().await;
        match target_id {
            Some(target_id) => state
                .pending
                .iter()
                .find(|item| item.send_now && item.target.id == target_id)
                .map(|item| item.id),
            None => state
                .pending
                .iter()
                .find(|item| item.send_now)
                .map(|item| item.id),
        }
    }

    /// Wait until all escalations that can precede an async tool result have
    /// actually left the pending queue. This prevents a fast adopted result
    /// from overtaking either the triggering item or another visible
    /// send-now predecessor (including a different target batch).
    pub(crate) async fn wait_until_no_send_now(&self) {
        let mut updates = self.updates.subscribe();
        loop {
            let state = self.inner.lock().await;
            if state.closed || !state.pending.iter().any(|item| item.send_now) {
                return;
            }
            drop(state);
            if updates.changed().await.is_err() {
                return;
            }
        }
    }

    #[cfg(test)]
    pub async fn remove(&self, id: Uuid) -> (RemoveQueuedMessageResult, Vec<QueuedUserMessage>) {
        let (result, publication) = {
            let mut state = self.inner.lock().await;
            if let Some(idx) = state.pending.iter().position(|item| item.id == id) {
                state.pending.remove(idx);
                (
                    RemoveQueuedMessageResult::Removed,
                    publication_snapshot(&mut state),
                )
            } else if state.started.contains(&id) {
                (
                    RemoveQueuedMessageResult::AlreadyStarted,
                    publication_snapshot(&mut state),
                )
            } else {
                (
                    RemoveQueuedMessageResult::NotFound,
                    publication_snapshot(&mut state),
                )
            }
        };
        let snapshot = publication.snapshot.clone();
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(publication);
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
        let (result, removed, publication) = {
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
                    publication_snapshot(&mut state),
                )
            } else if state
                .started_targets
                .values()
                .any(|target| target.id == target_id)
            {
                (
                    RemoveQueuedMessageResult::AlreadyStarted,
                    None,
                    publication_snapshot(&mut state),
                )
            } else {
                (
                    RemoveQueuedMessageResult::NotFound,
                    None,
                    publication_snapshot(&mut state),
                )
            }
        };
        let snapshot = publication.snapshot.clone();
        if matches!(result, RemoveQueuedMessageResult::Removed) {
            self.publish(publication);
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
        let (result, removed, publication) = {
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
            // Mirror `stage_remove_editable_for`: removing any pending editable
            // item yields `Removed`; `AlreadyStarted` is reserved for when
            // nothing pending matched but a started turn exists.
            let result = if !removed.is_empty() {
                RemoveQueuedMessageResult::Removed
            } else if has_started_target {
                RemoveQueuedMessageResult::AlreadyStarted
            } else {
                RemoveQueuedMessageResult::NotFound
            };
            (result, removed, publication_snapshot(&mut state))
        };
        let snapshot = publication.snapshot.clone();
        if !removed.is_empty() {
            self.publish(publication);
        }
        (result, removed, snapshot)
    }

    /// Pop the next pending item of any class for any target.
    ///
    /// In-run waits (foreground `task`, bash) must not use this: it
    /// consumes held items mid-run and treats steering as send-now.
    /// Use [`Self::wait_for_send_now_boundary_for`] or the class-aware
    /// drain helpers instead.
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

    /// Wait for the next submission using the same group ordering exposed by
    /// the queue UI: one effective-top group, then ordinary held.
    pub async fn recv_group_order_for(&self, target_id: Option<&str>) -> Option<UserSubmission> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            let mut deferred_until = None;
            for filter in [QueueDrainFilter::EffectiveTop, QueueDrainFilter::Held] {
                match self.pop_one_filtered(target_id, filter).await {
                    QueuePop::Item(submission) => return Some(*submission),
                    QueuePop::Closed => return None,
                    QueuePop::Deferred(deadline) => {
                        // A deferred item in an earlier rendered group must
                        // remain ahead of every later group. Falling through
                        // here would let held work overtake delayed effective-top work.
                        deferred_until = Some(deadline);
                        break;
                    }
                    QueuePop::Empty => {}
                }
            }
            if let Some(deadline) = deferred_until {
                tokio::select! {
                    _ = &mut notified => {}
                    _ = tokio::time::sleep_until(deadline) => {}
                }
            } else {
                notified.await;
            }
        }
    }

    pub async fn drain_into_for(
        &self,
        into: &mut Vec<UserSubmission>,
        max: usize,
        target_id: Option<&str>,
    ) {
        self.drain_into_for_filtered(into, max, target_id, QueueDrainFilter::Any)
            .await;
    }

    pub async fn drain_into_for_filtered(
        &self,
        into: &mut Vec<UserSubmission>,
        max: usize,
        target_id: Option<&str>,
        filter: QueueDrainFilter,
    ) {
        while into.len() < max {
            // Independently addressable run invocations never share a provider
            // dispatch with another submission.
            if into.iter().any(|item| item.run_invocation_id.is_some()) {
                break;
            }
            if into.is_empty() {
                match self.pop_one_filtered(target_id, filter).await {
                    QueuePop::Item(submission) => {
                        let is_run = submission.run_invocation_id.is_some();
                        into.push(*submission);
                        if is_run {
                            break;
                        }
                    }
                    QueuePop::Empty | QueuePop::Closed | QueuePop::Deferred(_) => break,
                }
                continue;
            }
            // Do not fold a following run invocation into interactive work.
            if self
                .peek_front_is_run_invocation_filtered(target_id, filter)
                .await
            {
                break;
            }
            match self.pop_one_filtered(target_id, filter).await {
                QueuePop::Item(submission) => into.push(*submission),
                QueuePop::Empty | QueuePop::Closed | QueuePop::Deferred(_) => break,
            }
        }
    }

    /// Drain the effective-top (steering or send-now) group first, then held, preserving
    /// original order within each group.
    pub async fn drain_group_order_into_for(
        &self,
        into: &mut Vec<UserSubmission>,
        max: usize,
        target_id: Option<&str>,
    ) {
        self.drain_into_for_filtered(into, max, target_id, QueueDrainFilter::EffectiveTop)
            .await;
        self.drain_into_for_filtered(into, max, target_id, QueueDrainFilter::Held)
            .await;
    }

    async fn peek_front_is_run_invocation(&self, target_id: Option<&str>) -> bool {
        self.peek_front_is_run_invocation_filtered(target_id, QueueDrainFilter::Any)
            .await
    }

    async fn peek_front_is_run_invocation_filtered(
        &self,
        target_id: Option<&str>,
        filter: QueueDrainFilter,
    ) -> bool {
        let state = self.inner.lock().await;
        let item = state.pending.iter().find(|item| {
            target_id.is_none_or(|target_id| item.target.id == target_id) && filter.matches(item)
        });
        item.is_some_and(|item| item.submission.run_invocation_id.is_some())
    }

    pub async fn has_pending_for(&self, target_id: Option<&str>) -> bool {
        let state = self.inner.lock().await;
        match target_id {
            Some(target_id) => state.pending.iter().any(|item| item.target.id == target_id),
            None => !state.pending.is_empty(),
        }
    }

    /// Wait until a matching foreground submission is pending without taking
    /// it from the queue. Utility work uses this to yield immediately to user
    /// re-entry while preserving the normal group-order dequeue path.
    pub async fn wait_for_pending_for(&self, target_id: Option<&str>) -> bool {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            {
                let state = self.inner.lock().await;
                if state.closed {
                    return false;
                }
                let pending = match target_id {
                    Some(target_id) => state.pending.iter().any(|item| item.target.id == target_id),
                    None => !state.pending.is_empty(),
                };
                if pending {
                    return true;
                }
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub async fn discard_pending(&self) -> usize {
        self.discard_pending_with_receipts().await.0
    }

    #[cfg(test)]
    pub async fn discard_pending_with_receipts(&self) -> (usize, Vec<ClientSubmissionReceipt>) {
        let (dropped, receipts, publication) = {
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
            (dropped, receipts, publication_snapshot(&mut state))
        };
        if dropped > 0 {
            self.publish(publication);
        }
        (dropped, receipts)
    }

    pub async fn close(&self) {
        let publication = {
            let mut state = self.inner.lock().await;
            state.closed = true;
            publication_snapshot(&mut state)
        };
        self.publish(publication);
        self.notify.notify_waiters();
    }

    async fn pop_one(&self, target_id: Option<&str>) -> QueuePop {
        self.pop_one_filtered(target_id, QueueDrainFilter::Any)
            .await
    }

    async fn pop_one_filtered(
        &self,
        target_id: Option<&str>,
        filter: QueueDrainFilter,
    ) -> QueuePop {
        let (item, publication) = {
            let mut state = self.inner.lock().await;
            if state.closed {
                return QueuePop::Closed;
            }
            if state.staged_removal.is_some() {
                return QueuePop::Empty;
            }
            for pending in &mut state.pending {
                clear_expired_edit_lease(pending);
            }
            let idx = state.pending.iter().position(|item| {
                target_id.is_none_or(|target_id| item.target.id == target_id)
                    && filter.matches(item)
            });
            let Some(idx) = idx else {
                return if state.closed {
                    QueuePop::Closed
                } else {
                    QueuePop::Empty
                };
            };
            if let Some(lease) = state.pending[idx].edit_lease {
                return QueuePop::Deferred(lease.expires_at);
            }
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
            state.started_metadata.insert(
                item.id,
                StartedQueueMetadata {
                    delivery_class: item.delivery_class,
                    send_now: item.send_now,
                    send_now_all: item.send_now_all,
                },
            );
            (item, publication_snapshot(&mut state))
        };
        self.publish(publication);
        let mut submission = item.submission;
        if !submission.queue_item_ids.contains(&item.id) {
            submission.queue_item_ids.push(item.id);
        }
        submission.queue_target = Some(item.target);
        // Keep the durable class in `started_metadata` for a later requeue,
        // but expose a send-now held item to the active turn as effective
        // steering. Once popped, the consumer has no separate `send_now`
        // flag; preserving Held here would make an explicitly escalated turn
        // look like ordinary deferred work after it won the effective-top
        // queue race.
        submission.delivery_class = if item.send_now {
            QueueDeliveryClass::Steering
        } else {
            item.delivery_class
        };
        QueuePop::Item(Box::new(submission))
    }

    fn publish(&self, publication: QueuePublication) {
        let mut published = crate::sync::lock_or_recover(&self.published_revision);
        if publication.revision <= *published {
            return;
        }
        let _ = self.updates.send(publication.snapshot);
        *published = publication.revision;
    }
}

fn publication_snapshot(state: &mut UserSubmissionQueueState) -> QueuePublication {
    state.publication_revision = state.publication_revision.saturating_add(1);
    QueuePublication {
        revision: state.publication_revision,
        snapshot: snapshot_pending(state),
    }
}

struct IdempotentPushCommit {
    id: Uuid,
    outcome: IdempotentPush,
    publication: Option<QueuePublication>,
    unpublished_snapshot: Vec<QueuedUserMessage>,
}

fn commit_idempotent_push(
    state: &mut UserSubmissionQueueState,
    receipt: ClientSubmissionReceipt,
    submission: UserSubmission,
    target: QueueTarget,
) -> IdempotentPushCommit {
    let id = receipt.id;
    if let Some(existing) = state.accepted.get(&id) {
        let outcome = if existing.origin_principal != receipt.origin_principal
            || existing.fingerprint != receipt.fingerprint
        {
            IdempotentPush::Conflict
        } else {
            IdempotentPush::Duplicate
        };
        return IdempotentPushCommit {
            id,
            outcome,
            publication: None,
            unpublished_snapshot: snapshot_pending(state),
        };
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
        delivery_class: submission.delivery_class,
        send_now: false,
        send_now_all: false,
        submission,
        target,
        not_before: None,
        edit_lease: None,
        last_edit_operation: None,
    });
    IdempotentPushCommit {
        id,
        outcome: IdempotentPush::Inserted,
        publication: Some(publication_snapshot(state)),
        unpublished_snapshot: Vec::new(),
    }
}

fn stage_remove_newest_locked(
    state: &mut UserSubmissionQueueState,
    target_id: &str,
) -> Result<
    (
        RemoveQueuedMessageResult,
        Option<StagedQueueRemoval>,
        Vec<QueuedUserMessage>,
    ),
    QueueRemovalInProgress,
> {
    for pending in &mut state.pending {
        clear_expired_edit_lease(pending);
    }
    if state
        .pending
        .iter()
        .any(|pending| pending.target.id == target_id && pending.edit_lease.is_some())
    {
        return Err(QueueRemovalInProgress);
    }
    let scope = StagedRemovalScope::NewestFor(target_id.to_string());
    if let Some(staged) = existing_stage_for_scope(state, &scope)? {
        let snapshot = snapshot_pending(state);
        return Ok((RemoveQueuedMessageResult::Removed, Some(staged), snapshot));
    }
    let (result, staged) = if let Some(index) = state
        .pending
        .iter()
        .rposition(|item| item.target.id == target_id)
    {
        (
            RemoveQueuedMessageResult::Removed,
            Some(stage_pending_indices(state, vec![index], scope)),
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
    let snapshot = snapshot_pending(state);
    Ok((result, staged, snapshot))
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

/// Which pending items a drain/pop may take. The effective-top group contains
/// steering and send-now items in their original queue order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueueDrainFilter {
    Any,
    EffectiveTop,
    Held,
}

impl QueueDrainFilter {
    fn matches(self, item: &QueuedSubmission) -> bool {
        match self {
            Self::Any => true,
            Self::EffectiveTop => item.send_now || item.delivery_class.is_steering(),
            Self::Held => !item.send_now && item.delivery_class == QueueDeliveryClass::Held,
        }
    }
}

fn snapshot_pending(state: &UserSubmissionQueueState) -> Vec<QueuedUserMessage> {
    // Staged removals stay visible until the terminal receipt commits.
    // `pop_one_filtered` already refuses to drain while a hold is live, so
    // snapshots must not hide the payload that durable commit still owns.
    state
        .pending
        .iter()
        .map(queued_message_from_submission)
        .collect()
}

fn clear_expired_edit_lease(item: &mut QueuedSubmission) {
    if item
        .edit_lease
        .is_some_and(|lease| lease.expires_at <= tokio::time::Instant::now())
    {
        item.edit_lease = None;
    }
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
        delivery_class: item.delivery_class,
        send_now: item.send_now,
    }
}

/// Build a user [`Message`] from a [`UserSubmission`]. With no media this is
/// exactly `Message::user(text)`. Client-composer images preserve their
/// sentinel ordering; normalized durable V2 media is appended in canonical
/// attachment order using Rig's typed image/audio/video blocks.
///
/// With client-composer images, the `text` is split on
/// [`IMAGE_PART_SENTINEL`] and reassembled as an ordered
/// `Vec<UserContent>` of interleaved text + base64-PNG image parts,
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
            let SubmissionImage::Png { bytes: png } = png else {
                continue;
            };
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
        let SubmissionImage::Png { bytes: png } = png else {
            continue;
        };
        let b64 = base64::engine::general_purpose::STANDARD.encode(&png);
        parts.push(UserContent::image_base64(
            b64,
            Some(ImageMediaType::PNG),
            None,
        ));
    }
    for media in sub.media {
        match media {
            SubmissionMedia::Image { bytes, mime_type } => {
                let media_type = ImageMediaType::from_mime_type(&mime_type)
                    .expect("durable image MIME was validated before queue insertion");
                parts.push(UserContent::image_raw(bytes, Some(media_type), None));
            }
            SubmissionMedia::Audio { bytes, mime_type } => {
                let media_type = AudioMediaType::from_mime_type(&mime_type)
                    .expect("durable audio MIME was validated before queue insertion");
                parts.push(UserContent::audio_raw(bytes, Some(media_type)));
            }
            SubmissionMedia::Video { bytes, mime_type } => {
                let media_type = VideoMediaType::from_mime_type(&mime_type)
                    .expect("durable video MIME was validated before queue insertion");
                parts.push(UserContent::video_raw(bytes, Some(media_type)));
            }
        }
    }
    if parts.is_empty() {
        // Empty content is unreachable (caller has images), but never panic
        // on the wire path — fall back to the plain text form.
        Message::user(sub.text)
    } else {
        Message::User { content: parts }
    }
}

/// Extract concatenated text from an assistant turn's content vector.
pub fn extract_text(choice: &[AssistantContent]) -> String {
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
pub fn extract_user_text(content: &[UserContent]) -> String {
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
pub fn extract_reasoning(choice: &[AssistantContent]) -> String {
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
pub fn strip_think_from_choice(choice: &[AssistantContent]) -> Option<Vec<AssistantContent>> {
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
    (!parts.is_empty()).then_some(parts)
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
    choice: &[AssistantContent],
    text: &str,
) -> Option<Vec<AssistantContent>> {
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
    (!parts.is_empty()).then_some(parts)
}

/// Collect all `ToolCall`s from an assistant turn's content vector.
pub fn collect_tool_calls(choice: &[AssistantContent]) -> Vec<ToolCall> {
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
    tool_result_message_for(tc, &tc.function.name, output)
}

/// Build a tool-result message for the tool that actually executed. This is
/// distinct from the model-emitted call name when Cockpit repaired that name
/// before dispatch; Rig replays the result name on name-keyed provider wires.
pub fn tool_result_message_for(
    tc: &ToolCall,
    executed_name: impl Into<String>,
    output: String,
) -> Message {
    tool_result_message_for_contents(
        tc,
        executed_name,
        vec![rig::message::ToolResultContent::text(output)],
    )
}

/// Build a typed tool-result history message. JSON remains JSON all the way
/// through prune/compaction/provider serialization; media bytes may enter
/// this vector only after the storage-backed resolver has acquired and
/// verified its component lease.
pub fn tool_result_message_for_contents(
    tc: &ToolCall,
    executed_name: impl Into<String>,
    content: Vec<rig::message::ToolResultContent>,
) -> Message {
    Message::User {
        content: vec![UserContent::tool_result_for(
            tc.id.clone(),
            tc.provider.clone(),
            executed_name.into(),
            content,
        )],
    }
}

/// Construct a Cockpit-authored tool call while keeping its internal
/// correlator separate from the optional provider-issued replay identity.
pub(crate) fn tool_call_with_identity(
    call: impl Into<String>,
    provider_item_id: Option<String>,
    provider_call: Option<String>,
    function: rig::message::ToolFunction,
    signature: Option<String>,
    additional_params: Option<serde_json::Value>,
) -> ToolCall {
    ToolCall {
        id: ToolCallId::new_or_mint(call),
        provider: provider_call.and_then(ProviderCallId::new).map(
            |provider| match provider_item_id {
                Some(item_id) => provider.with_item_id(item_id),
                None => provider,
            },
        ),
        function,
        signature,
        additional_params,
    }
}

/// Construct a Cockpit-authored tool result for a known call.
pub(crate) fn tool_result_with_identity(
    call: impl Into<String>,
    provider_call: Option<String>,
    name: impl Into<String>,
    content: Vec<rig::message::ToolResultContent>,
) -> rig::message::ToolResult {
    rig::message::ToolResult {
        call: ToolCallId::new_or_mint(call),
        provider: provider_call.and_then(ProviderCallId::new),
        name: name.into(),
        content,
    }
}

/// Build a structural tool-result turn when Cockpit retained both parts of a
/// provider's dual call identity. The correlation handle remains `call`; the
/// provider values are replay-only wire handles and must not be conflated.
pub(crate) fn synthetic_tool_result_message_with_provider_identity(
    call: impl Into<String>,
    provider_item_id: Option<String>,
    provider_call: Option<String>,
    name: impl Into<String>,
    output: impl Into<String>,
) -> Message {
    let provider =
        provider_call
            .and_then(ProviderCallId::new)
            .map(|provider| match provider_item_id {
                Some(item_id) => provider.with_item_id(item_id),
                None => provider,
            });
    Message::User {
        content: vec![UserContent::ToolResult(rig::message::ToolResult {
            call: ToolCallId::new_or_mint(call),
            provider,
            name: name.into(),
            content: vec![rig::message::ToolResultContent::text(output.into())],
        })],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_parts(msg: &Message) -> Vec<UserContent> {
        match msg {
            Message::User { content } => content.to_vec(),
            _ => panic!("expected a user message"),
        }
    }

    #[test]
    fn synthetic_task_result_keeps_task_name_and_provider_identity_on_gemini_wire() {
        use rig::{
            message::ToolFunction,
            providers::gemini::completion::gemini_api_types::{Content, PartKind},
        };

        let call = tool_call_with_identity(
            "task-call",
            Some("item-7".to_string()),
            Some("provider-call-9".to_string()),
            ToolFunction {
                name: "task".to_string(),
                arguments: serde_json::json!({ "child_agent": "explore" }),
            },
            None,
            None,
        );
        let result = synthetic_tool_result_message_with_provider_identity(
            "task-call",
            Some("item-7".to_string()),
            Some("provider-call-9".to_string()),
            "task",
            "completed",
        );

        assert_eq!(call.id.as_str(), "task-call");
        assert_eq!(call.function.name, "task");
        let parts = user_parts(&result);
        let UserContent::ToolResult(result_part) = &parts[0] else {
            panic!("expected a tool result");
        };
        assert_eq!(result_part.call.as_str(), call.id.as_str());
        assert_eq!(result_part.name, call.function.name);
        assert_eq!(
            result_part
                .provider
                .as_ref()
                .map(|provider| (provider.call_id.as_str(), provider.item_id.as_deref())),
            call.provider
                .as_ref()
                .map(|provider| (provider.call_id.as_str(), provider.item_id.as_deref()))
        );

        let wire: Content = result.try_into().expect("Gemini wire conversion");
        let PartKind::FunctionResponse(response) = &wire.parts[0].part else {
            panic!("expected Gemini functionResponse");
        };
        assert_eq!(response.name, "task");
        assert_eq!(response.id.as_deref(), Some("provider-call-9"));
    }

    #[test]
    fn text_only_submission_is_a_plain_user_text_message() {
        let msg = build_user_message(UserSubmission::text("hello world"));
        let parts = user_parts(&msg);
        assert_eq!(parts.len(), 1);
        assert!(matches!(parts[0], UserContent::Text(_)));
    }

    #[test]
    fn submission_origin_only_external_root_advances_compaction_activity() {
        assert!(SubmissionOrigin::ExternalRoot.advances_activity_epoch());
        for origin in [
            SubmissionOrigin::GoalContinuation,
            SubmissionOrigin::ScheduledJob,
            SubmissionOrigin::AutoContinue,
            SubmissionOrigin::RetryRecovery,
            SubmissionOrigin::ToolResult,
            SubmissionOrigin::CompactNotice,
            SubmissionOrigin::Internal,
        ] {
            assert!(!origin.advances_activity_epoch(), "{origin:?}");
        }
        assert_eq!(
            UserSubmission::compact_notice().origin,
            SubmissionOrigin::CompactNotice
        );
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
            images: vec![SubmissionImage::png(vec![1u8, 2, 3])],
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
            images: vec![SubmissionImage::png(vec![9u8])],
            ..Default::default()
        });
        let parts = user_parts(&msg);
        assert_eq!(parts.len(), 2);
        assert!(matches!(parts[0], UserContent::Image(_)));
        assert!(matches!(parts[1], UserContent::Text(_)));
    }

    fn assistant_choice(parts: Vec<AssistantContent>) -> Vec<AssistantContent> {
        assert!(!parts.is_empty(), "assistant test choice must be non-empty");
        parts
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
        assert_eq!(stripped.len(), 2);
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
                id: rig::message::ToolCallId::new_or_mint("tc-1"),
                provider: None,
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
        assert_eq!(stripped.len(), 1);
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
            images: vec![SubmissionImage::png(vec![1u8, 2])],
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
            images: vec![SubmissionImage::png(vec![0, 1, 2, 3])],
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
            images: vec![SubmissionImage::png(vec![1, 2, 3, 4])],
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
        let SubmissionImage::Png { bytes } = &mut changed.images[0] else {
            panic!("fixture image must remain inline PNG bytes");
        };
        bytes.push(5);
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
    async fn run_invocations_are_not_coalesced() {
        let (updates_tx, _) = watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let run_a = Uuid::from_u128(1);
        let run_b = Uuid::from_u128(2);
        let interactive = Uuid::from_u128(3);

        let mut a = UserSubmission::text("run-a");
        a.run_invocation_id = Some(run_a);
        a.client_submissions = vec![ClientSubmissionReceipt {
            id: run_a,
            fingerprint: "a".into(),
            wire_fingerprint: "a".into(),
            origin_principal: None,
        }];
        let mut b = UserSubmission::text("run-b");
        b.run_invocation_id = Some(run_b);
        b.client_submissions = vec![ClientSubmissionReceipt {
            id: run_b,
            fingerprint: "b".into(),
            wire_fingerprint: "b".into(),
            origin_principal: None,
        }];
        let mut i = UserSubmission::text("interactive");
        i.client_submissions = vec![ClientSubmissionReceipt {
            id: interactive,
            fingerprint: "i".into(),
            wire_fingerprint: "i".into(),
            origin_principal: None,
        }];

        queue
            .push_idempotent(a.client_submissions[0].clone(), a, target.clone())
            .await;
        queue
            .push_idempotent(i.client_submissions[0].clone(), i, target.clone())
            .await;
        queue
            .push_idempotent(b.client_submissions[0].clone(), b, target.clone())
            .await;

        let mut first = Vec::new();
        queue.drain_into_for(&mut first, 16, Some(&target.id)).await;
        assert_eq!(first.len(), 1, "run invocation must not fold with others");
        assert_eq!(first[0].run_invocation_id, Some(run_a));

        let mut second = Vec::new();
        queue
            .drain_into_for(&mut second, 16, Some(&target.id))
            .await;
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].text, "interactive");
        assert!(second[0].run_invocation_id.is_none());

        let mut third = Vec::new();
        queue.drain_into_for(&mut third, 16, Some(&target.id)).await;
        assert_eq!(third.len(), 1);
        assert_eq!(third[0].run_invocation_id, Some(run_b));
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
    async fn adopt_orphaned_pending_moves_dead_child_items_to_live_frame() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");
        queue
            .push(UserSubmission::text("root stays"), root.clone())
            .await;
        queue
            .push(UserSubmission::text("orphaned child"), child.clone())
            .await;

        let live_ids = std::collections::HashSet::from([root.id.clone()]);
        queue.adopt_orphaned_pending(&live_ids, root.clone()).await;

        let snapshot = queue.snapshot().await;
        assert_eq!(
            snapshot
                .iter()
                .map(|item| (item.text.as_str(), item.target.id.as_str()))
                .collect::<Vec<_>>(),
            vec![("root stays", "root"), ("orphaned child", "root")]
        );
        let mut drained = Vec::new();
        queue.drain_into_for(&mut drained, 10, Some(&root.id)).await;
        assert_eq!(
            drained
                .iter()
                .map(|submission| submission.text.as_str())
                .collect::<Vec<_>>(),
            vec!["root stays", "orphaned child"]
        );
        assert!(!queue.has_pending_for(Some(&child.id)).await);
    }

    #[tokio::test]
    async fn live_push_stamps_the_replica_not_a_stale_submission_target() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");
        let replica = std::sync::Mutex::new(root.clone());
        let mut submission = UserSubmission::text("do not strand");
        submission.queue_target = Some(child);
        let id = Uuid::new_v4();
        let receipt = ClientSubmissionReceipt {
            id,
            fingerprint: submission.client_fingerprint(),
            wire_fingerprint: id.to_string(),
            origin_principal: None,
        };

        let (_, snapshot, outcome) = queue
            .push_idempotent_on_live_target(receipt, submission, &replica)
            .await;
        assert_eq!(outcome, IdempotentPush::Inserted);
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.target.id.as_str())
                .collect::<Vec<_>>(),
            vec!["root"]
        );
        let got = queue
            .recv_group_order_for(Some("root"))
            .await
            .expect("root wait observes the live-stamped item");
        assert_eq!(got.text, "do not strand");
        assert_eq!(
            got.queue_target.as_ref().map(|target| target.id.as_str()),
            Some("root")
        );
    }

    #[tokio::test]
    async fn live_push_retries_after_queue_contention_and_stamps_replica_at_insert() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");
        let replica = std::sync::Arc::new(std::sync::Mutex::new(child));
        let submission = UserSubmission::text("late insert");
        let id = Uuid::new_v4();
        let receipt = ClientSubmissionReceipt {
            id,
            fingerprint: submission.client_fingerprint(),
            wire_fingerprint: id.to_string(),
            origin_principal: None,
        };

        let fence = queue.cancellation_fence().await;
        let push = tokio::spawn({
            let queue = queue.clone();
            let replica = replica.clone();
            async move {
                queue
                    .push_idempotent_on_live_target(receipt, submission, &replica)
                    .await
            }
        });
        tokio::task::yield_now().await;
        *crate::sync::lock_or_recover(&replica) = root.clone();
        drop(fence);
        let (_, snapshot, outcome) = push.await.expect("live push task");
        assert_eq!(outcome, IdempotentPush::Inserted);
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.target.id.as_str())
                .collect::<Vec<_>>(),
            vec!["root"]
        );
        let got = queue
            .recv_group_order_for(Some("root"))
            .await
            .expect("item remains dispatchable on the live frame");
        assert_eq!(got.text, "late insert");
        assert_eq!(
            got.queue_target.as_ref().map(|target| target.id.as_str()),
            Some("root")
        );
    }

    #[tokio::test]
    async fn live_remove_newest_uses_replica_id_at_the_mutation() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let root = QueueTarget::root("Build");
        let child = QueueTarget::child("builder", 1, "call-1", "default");
        queue
            .push(UserSubmission::text("keep child"), child.clone())
            .await;
        queue
            .push(UserSubmission::text("drop root"), root.clone())
            .await;
        let replica = std::sync::Mutex::new(root.clone());

        let (result, staged, snapshot) = queue
            .stage_remove_newest_on_live_target(&replica)
            .await
            .expect("live remove");
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            staged.as_ref().map(|staged| staged
                .removed()
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>()),
            Some(vec!["drop root"])
        );
        assert_eq!(
            snapshot
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["keep child", "drop root"],
            "staged removals stay visible until the terminal receipt commits"
        );
        let committed = queue
            .commit_staged_removal(staged.expect("live remove staged"))
            .await;
        assert_eq!(
            committed
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["keep child"]
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
    async fn user_submission_queue_bulk_removes_editable_despite_started_target() {
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

        // The still-pending "root editable" submission is removed even though the
        // target has an in-flight started turn ("root folding"): editable removal
        // only ever touches pending items, so removing one is a genuine `Removed`.
        // Reporting `AlreadyStarted` here would contradict the durable receipt
        // invariant `removed == (removed_count > 0)` enforced by
        // `RemoteQueueMutationReceiptV1::validate`.
        let (result, removed, snapshot) = queue.remove_editable_for(&root.id).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
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

    #[tokio::test]
    async fn queued_delivery_class_round_trips_on_snapshot_and_set() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");

        let mut steering = UserSubmission::text("steer me");
        steering.delivery_class = QueueDeliveryClass::Steering;
        let mut held = UserSubmission::text("hold me");
        held.delivery_class = QueueDeliveryClass::Held;

        let (steer_id, _) = queue.push(steering, target.clone()).await;
        let (hold_id, snapshot) = queue.push(held, target.clone()).await;
        assert_eq!(snapshot[0].delivery_class, QueueDeliveryClass::Steering);
        assert_eq!(snapshot[1].delivery_class, QueueDeliveryClass::Held);
        assert_eq!(snapshot[0].target.agent, "Build");
        assert_eq!(snapshot[1].id, hold_id);

        let (result, item, snapshot) = queue
            .set_delivery_class(hold_id, QueueDeliveryClass::Steering, None)
            .await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(
            item.map(|item| item.delivery_class),
            Some(QueueDeliveryClass::Steering)
        );
        assert!(
            snapshot
                .iter()
                .all(|item| item.delivery_class == QueueDeliveryClass::Steering)
        );

        let (result, snapshot) = queue.set_all_delivery_class(QueueDeliveryClass::Held).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert!(
            snapshot
                .iter()
                .all(|item| item.delivery_class == QueueDeliveryClass::Held)
        );

        let (result, item, snapshot) = queue.mark_send_now(steer_id).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        let item = item.expect("escalated item is projected");
        assert_eq!(item.id, steer_id);
        assert!(item.send_now);
        assert!(
            snapshot
                .iter()
                .find(|item| item.id == steer_id)
                .unwrap()
                .send_now
        );
        assert!(queue.has_send_now_for(Some(&target.id)).await);

        let mut drained = Vec::new();
        queue
            .drain_into_for(&mut drained, 16, Some(&target.id))
            .await;
        assert_eq!(
            drained
                .iter()
                .map(|item| item.delivery_class)
                .collect::<Vec<_>>(),
            vec![QueueDeliveryClass::Steering, QueueDeliveryClass::Held],
            "a send-now item retains Held durably but is steering while it is consumed"
        );
    }

    #[tokio::test]
    async fn explicit_hold_clears_send_now_for_one_and_all_items() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let (first, _) = queue
            .push(UserSubmission::text("one"), target.clone())
            .await;
        let (second, _) = queue.push(UserSubmission::text("two"), target).await;

        queue.mark_send_now(first).await;
        queue.mark_send_now(second).await;
        let (_, _, snapshot) = queue
            .set_delivery_class(first, QueueDeliveryClass::Held, None)
            .await;
        assert!(
            !snapshot
                .iter()
                .find(|item| item.id == first)
                .unwrap()
                .send_now
        );
        assert!(
            snapshot
                .iter()
                .find(|item| item.id == second)
                .unwrap()
                .send_now
        );

        let (_, snapshot) = queue.set_all_delivery_class(QueueDeliveryClass::Held).await;
        assert!(snapshot.iter().all(|item| !item.send_now));
    }

    #[tokio::test]
    async fn idle_receive_uses_rendered_group_order_instead_of_fifo() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let mut held = UserSubmission::text("held first in fifo");
        held.delivery_class = QueueDeliveryClass::Held;
        queue.push(held, target.clone()).await;
        queue
            .push(
                UserSubmission::text("steering second in fifo"),
                target.clone(),
            )
            .await;

        let first = queue.recv_group_order_for(Some(&target.id)).await.unwrap();
        let mut batch = vec![first];
        queue
            .drain_group_order_into_for(&mut batch, 16, Some(&target.id))
            .await;

        assert_eq!(
            batch
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["steering second in fifo", "held first in fifo"]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn idle_receive_does_not_bypass_a_deferred_earlier_group() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        queue
            .requeue_front_after(
                UserSubmission::text("delayed steering"),
                target.clone(),
                std::time::Duration::from_secs(60),
            )
            .await;
        let mut held = UserSubmission::text("ready held");
        held.delivery_class = QueueDeliveryClass::Held;
        queue.push(held, target.clone()).await;

        let receiver = tokio::spawn({
            let queue = queue.clone();
            let target_id = target.id.clone();
            async move { queue.recv_group_order_for(Some(&target_id)).await }
        });
        tokio::task::yield_now().await;
        assert!(!receiver.is_finished());

        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        assert_eq!(receiver.await.unwrap().unwrap().text, "delayed steering");
        assert_eq!(
            queue
                .recv_group_order_for(Some(&target.id))
                .await
                .unwrap()
                .text,
            "ready held"
        );
    }

    #[tokio::test]
    async fn correlated_edit_is_idempotent_and_preserves_images() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let mut submission = UserSubmission::text("before");
        submission.images = vec![SubmissionImage::png(vec![1, 2, 3])];
        let (id, _) = queue.push(submission, QueueTarget::root("Build")).await;
        let operation_id = Uuid::new_v4();
        let replacement = |action, text: &str| cockpit_proto::QueueItemReplacement {
            operation_id,
            action,
            text: text.to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
        };

        let (reserved, _, _) = queue
            .set_delivery_class(
                id,
                QueueDeliveryClass::Steering,
                Some(replacement(
                    cockpit_proto::QueueEditAction::Reserve,
                    "before",
                )),
            )
            .await;
        assert_eq!(reserved, RemoveQueuedMessageResult::Removed);
        let (competing, _, _) = queue
            .set_delivery_class(id, QueueDeliveryClass::Held, None)
            .await;
        assert_eq!(competing, RemoveQueuedMessageResult::EditConflict);
        let (committed, _, _) = queue
            .set_delivery_class(
                id,
                QueueDeliveryClass::Steering,
                Some(replacement(cockpit_proto::QueueEditAction::Commit, "after")),
            )
            .await;
        assert_eq!(committed, RemoveQueuedMessageResult::Removed);
        let (retried, _, _) = queue
            .set_delivery_class(
                id,
                QueueDeliveryClass::Steering,
                Some(replacement(cockpit_proto::QueueEditAction::Commit, "after")),
            )
            .await;
        assert_eq!(retried, RemoveQueuedMessageResult::Removed);
        let pending = queue.pending_submission(id).await.unwrap();
        assert_eq!(pending.text, "after");
        assert_eq!(pending.images, vec![SubmissionImage::png(vec![1, 2, 3])]);
    }

    #[tokio::test]
    async fn edit_lease_does_not_replace_a_delivery_delay() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let snapshot = queue
            .requeue_front_after(
                UserSubmission::text("delayed"),
                QueueTarget::root("Build"),
                std::time::Duration::from_secs(60),
            )
            .await;
        let id = snapshot[0].id;
        let original_not_before = queue.inner.lock().await.pending[0].not_before;
        let operation_id = Uuid::new_v4();
        let replacement = |action| cockpit_proto::QueueItemReplacement {
            operation_id,
            action,
            text: "delayed edit".to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
        };

        queue
            .set_delivery_class(
                id,
                QueueDeliveryClass::Steering,
                Some(replacement(cockpit_proto::QueueEditAction::Reserve)),
            )
            .await;
        assert_eq!(
            queue.inner.lock().await.pending[0].not_before,
            original_not_before
        );
        queue
            .set_delivery_class(
                id,
                QueueDeliveryClass::Steering,
                Some(replacement(cockpit_proto::QueueEditAction::Commit)),
            )
            .await;
        assert_eq!(
            queue.inner.lock().await.pending[0].not_before,
            original_not_before
        );

        let mut state = queue.inner.lock().await;
        state.pending[0].edit_lease = Some(QueueEditLease {
            operation_id: Uuid::new_v4(),
            expires_at: tokio::time::Instant::now(),
        });
        clear_expired_edit_lease(&mut state.pending[0]);
        assert!(state.pending[0].edit_lease.is_none());
        assert_eq!(state.pending[0].not_before, original_not_before);
    }

    #[tokio::test]
    async fn whole_queue_send_now_interrupts_a_different_foreground_target() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let child = QueueTarget::child("builder", 1, "call-1", "default");
        let (id, _) = queue
            .push(UserSubmission::text("child work"), child.clone())
            .await;

        queue.mark_send_now(id).await;
        assert!(!queue.has_send_now_boundary_for("root").await);
        queue
            .set_delivery_class(id, QueueDeliveryClass::Held, None)
            .await;
        queue.mark_all_send_now().await;
        assert!(queue.has_send_now_boundary_for("root").await);
        assert!(queue.has_send_now_boundary_for(&child.id).await);
    }

    #[tokio::test]
    async fn send_now_wait_ignores_held_and_steering_and_does_not_pop() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let child = QueueTarget::child("explore", 1, "call-1", "default");

        let mut held = UserSubmission::text("held");
        held.delivery_class = QueueDeliveryClass::Held;
        queue.push(held, target.clone()).await;
        queue
            .push(UserSubmission::text("steer"), target.clone())
            .await;

        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                queue.wait_for_send_now_boundary_for(&target.id)
            )
            .await
            .is_err(),
            "held/steering must not complete a send-now wait"
        );
        assert_eq!(queue.snapshot().await.len(), 2);

        let (child_id, _) = queue
            .push(UserSubmission::text("child send-now"), child.clone())
            .await;
        queue.mark_send_now(child_id).await;
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                queue.wait_for_send_now_boundary_for(&target.id)
            )
            .await
            .is_err(),
            "other-target send-now must not yield the focused agent"
        );

        let waiter = tokio::spawn({
            let queue = queue.clone();
            let target_id = target.id.clone();
            async move { queue.wait_for_send_now_boundary_for(&target_id).await }
        });
        queue.mark_all_send_now().await;
        assert!(waiter.await.unwrap());
        assert_eq!(
            queue.snapshot().await.len(),
            3,
            "send-now wait must not pop; Continue/run-end drain own delivery"
        );
    }

    #[tokio::test]
    async fn send_now_wait_unblocks_for_matching_target_without_popping() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let (id, _) = queue
            .push(UserSubmission::text("deliver now"), target.clone())
            .await;

        let waiter = tokio::spawn({
            let queue = queue.clone();
            let target_id = target.id.clone();
            async move { queue.wait_for_send_now_boundary_for(&target_id).await }
        });
        tokio::task::yield_now().await;
        assert!(!waiter.is_finished());

        queue.mark_send_now(id).await;
        assert!(waiter.await.unwrap());
        let snapshot = queue.snapshot().await;
        assert_eq!(snapshot.len(), 1);
        assert!(snapshot[0].send_now);
    }

    #[tokio::test]
    async fn send_now_wait_returns_false_on_close_without_popping() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let mut held = UserSubmission::text("held");
        held.delivery_class = QueueDeliveryClass::Held;
        queue.push(held, QueueTarget::root("Build")).await;
        queue.close().await;
        assert!(!queue.wait_for_send_now_boundary_for("root").await);
        assert_eq!(queue.snapshot().await.len(), 1);
    }

    #[tokio::test]
    async fn whole_queue_mutations_are_atomic_across_targets() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        queue
            .push(UserSubmission::text("root"), QueueTarget::root("Build"))
            .await;
        queue
            .push(
                UserSubmission::text("child"),
                QueueTarget::child("builder", 1, "call-1", "default"),
            )
            .await;

        let (result, snapshot) = queue.mark_all_send_now().await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.iter().all(|item| item.send_now));
        let (result, staged, _) = queue
            .stage_remove_all(Some("task:call-1:default"))
            .await
            .unwrap();
        assert_eq!(result, RemoveQueuedMessageResult::Removed);
        let staged = staged.expect("whole queue is claimed in one operation");
        assert_eq!(
            staged
                .removed()
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child", "root"]
        );
    }

    #[tokio::test]
    async fn adopted_result_cancelled_while_waiting_for_queue_lock_is_not_inserted() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let cancel = tokio_util::sync::CancellationToken::new();
        let expected_generation = queue.cancellation_fence().await.generation();
        let queue_lock = queue.inner.lock().await;
        let enqueue_queue = queue.clone();
        let enqueue_cancel = cancel.clone();
        let enqueue = tokio::spawn(async move {
            enqueue_queue
                .push_if_not_cancelled(
                    UserSubmission::text("stale async result"),
                    QueueTarget::root("Build"),
                    &enqueue_cancel,
                    expected_generation,
                )
                .await
        });
        tokio::task::yield_now().await;

        cancel.cancel();
        drop(queue_lock);

        assert!(enqueue.await.unwrap().is_none());
        assert!(queue.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn foreground_cancel_precedes_fence_and_rejects_async_insert() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let cancel = tokio_util::sync::CancellationToken::new();
        let expected_generation = queue.cancellation_fence().await.generation();
        let queue_lock = queue.inner.lock().await;

        let cancelling_queue = queue.clone();
        let cancelling_token = cancel.clone();
        let cancellation = tokio::spawn(async move {
            // Match Ctrl+C ordering: inherited work is cancelled before the
            // fence can block on the queue mutation lock.
            cancelling_token.cancel();
            let _fence = cancelling_queue.advance_cancellation_fence().await;
        });
        tokio::task::yield_now().await;

        let enqueue_queue = queue.clone();
        let enqueue_cancel = cancel.clone();
        let enqueue = tokio::spawn(async move {
            enqueue_queue
                .push_if_not_cancelled(
                    UserSubmission::text("generation-zero result"),
                    QueueTarget::root("Build"),
                    &enqueue_cancel,
                    expected_generation,
                )
                .await
        });
        tokio::task::yield_now().await;
        drop(queue_lock);

        cancellation.await.unwrap();
        assert!(enqueue.await.unwrap().is_none());
        assert!(queue.snapshot().await.is_empty());
    }

    #[tokio::test]
    async fn cancellation_fence_suppresses_delayed_pre_cancel_snapshot_publication() {
        let (updates_tx, mut updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        queue
            .push(UserSubmission::text("visible"), QueueTarget::root("Build"))
            .await;
        updates_rx.borrow_and_update();

        // Model a publisher descheduled after taking its snapshot but before
        // acquiring the serialized publication lock.
        let delayed = {
            let mut state = queue.inner.lock().await;
            publication_snapshot(&mut state)
        };
        drop(queue.advance_cancellation_fence().await);
        queue.publish(delayed);

        assert!(!updates_rx.has_changed().unwrap());
    }

    #[tokio::test]
    async fn drain_steering_preserves_group_order_and_leaves_held() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");
        let child = QueueTarget::child("explore", 1, "call-1", "default");

        let mut first = UserSubmission::text("steer first");
        first.delivery_class = QueueDeliveryClass::Steering;
        let mut held = UserSubmission::text("hold");
        held.delivery_class = QueueDeliveryClass::Held;
        let mut second = UserSubmission::text("steer second");
        second.delivery_class = QueueDeliveryClass::Steering;
        let mut child_steer = UserSubmission::text("child steer");
        child_steer.delivery_class = QueueDeliveryClass::Steering;

        queue.push(first, target.clone()).await;
        queue.push(held, target.clone()).await;
        queue.push(second, target.clone()).await;
        queue.push(child_steer, child.clone()).await;

        let mut steering = Vec::new();
        queue
            .drain_into_for_filtered(
                &mut steering,
                16,
                Some(&target.id),
                QueueDrainFilter::EffectiveTop,
            )
            .await;
        assert_eq!(
            steering
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["steer first", "steer second"]
        );

        let mut remaining = Vec::new();
        queue
            .drain_group_order_into_for(&mut remaining, usize::MAX, Some(&target.id))
            .await;
        assert_eq!(
            remaining
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["hold"]
        );

        let mut child_drained = Vec::new();
        queue
            .drain_into_for_filtered(
                &mut child_drained,
                16,
                Some(&child.id),
                QueueDrainFilter::EffectiveTop,
            )
            .await;
        assert_eq!(
            child_drained
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["child steer"]
        );
    }

    #[tokio::test]
    async fn send_now_held_item_drains_with_steering_before_siblings() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::root("Build");

        let mut first_held = UserSubmission::text("held one");
        first_held.delivery_class = QueueDeliveryClass::Held;
        let mut second_held = UserSubmission::text("held two");
        second_held.delivery_class = QueueDeliveryClass::Held;
        let (first_id, _) = queue.push(first_held, target.clone()).await;
        queue.push(second_held, target.clone()).await;
        let (result, _, _) = queue.mark_send_now(first_id).await;
        assert_eq!(result, RemoveQueuedMessageResult::Removed);

        let mut send_now = Vec::new();
        queue
            .drain_into_for_filtered(
                &mut send_now,
                16,
                Some(&target.id),
                QueueDrainFilter::EffectiveTop,
            )
            .await;
        assert_eq!(
            send_now
                .iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["held one"]
        );
        let mut rest = Vec::new();
        queue
            .drain_into_for_filtered(&mut rest, 16, Some(&target.id), QueueDrainFilter::Held)
            .await;
        assert_eq!(
            rest.iter()
                .map(|item| item.text.as_str())
                .collect::<Vec<_>>(),
            vec!["held two"]
        );
    }

    #[tokio::test]
    async fn requeue_preserves_held_class_and_send_now_escalation() {
        let (updates_tx, _updates_rx) = tokio::sync::watch::channel(Vec::new());
        let queue = UserSubmissionQueue::new(updates_tx);
        let target = QueueTarget::child("builder", 1, "call-1", "default");
        let resumed_parent = QueueTarget::root("Build");
        let mut held = UserSubmission::text("retry me now");
        held.delivery_class = QueueDeliveryClass::Held;
        let (id, _) = queue.push(held, target.clone()).await;
        queue.mark_send_now(id).await;

        let started = queue
            .recv_group_order_for(Some(&target.id))
            .await
            .expect("escalated held item starts");
        assert_eq!(started.delivery_class, QueueDeliveryClass::Steering);
        let snapshot = queue.requeue_front(started, resumed_parent).await;

        assert_eq!(snapshot.len(), 1);
        assert_eq!(snapshot[0].target.id, target.id);
        assert_eq!(snapshot[0].delivery_class, QueueDeliveryClass::Held);
        assert!(snapshot[0].send_now);
        let retried = queue
            .recv_group_order_for(Some(&target.id))
            .await
            .expect("requeued escalation starts again");
        assert_eq!(retried.delivery_class, QueueDeliveryClass::Steering);
    }
}
