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
use tokio::sync::{Mutex, Notify, mpsc};
use uuid::Uuid;

/// Sentinel emitted in wire text by
/// [`crate::tui::paste::PasteRegistry::build_wire`] at each real-image
/// position. We split on it here to interleave text and image content
/// parts in order when assembling the outbound user [`Message`].
pub use crate::tui::paste::IMAGE_PART_SENTINEL;

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
    /// Queue item ids that were drained to produce this submission. Empty for
    /// direct, non-queued driver calls. Folded queued submissions keep every id
    /// in FIFO order so UI/export consumers can correlate the visible row with
    /// the daemon queue item(s) that became model context.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queue_item_ids: Vec<Uuid>,
    /// Queue target captured when the daemon accepted the queued message. All
    /// items in one fold are drained for the same target, so the folded
    /// submission carries the first target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_target: Option<QueueTarget>,
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
}

#[derive(Debug, Default)]
struct UserSubmissionQueueState {
    pending: VecDeque<QueuedSubmission>,
    started: HashSet<Uuid>,
    started_targets: HashMap<Uuid, QueueTarget>,
    closed: bool,
}

#[derive(Debug, Clone)]
pub struct UserSubmissionQueue {
    inner: Arc<Mutex<UserSubmissionQueueState>>,
    notify: Arc<Notify>,
    updates: mpsc::UnboundedSender<Vec<QueuedUserMessage>>,
}

impl UserSubmissionQueue {
    pub fn new(updates: mpsc::UnboundedSender<Vec<QueuedUserMessage>>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(UserSubmissionQueueState::default())),
            notify: Arc::new(Notify::new()),
            updates,
        }
    }

    pub async fn push(
        &self,
        submission: UserSubmission,
        target: QueueTarget,
    ) -> (Uuid, Vec<QueuedUserMessage>) {
        let id = Uuid::new_v4();
        let snapshot = {
            let mut state = self.inner.lock().await;
            state.pending.push_back(QueuedSubmission {
                id,
                submission,
                target,
            });
            snapshot_pending(&state)
        };
        self.publish(snapshot.clone());
        self.notify.notify_one();
        (id, snapshot)
    }

    pub async fn requeue_front(
        &self,
        mut submission: UserSubmission,
        fallback_target: QueueTarget,
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
            match self.pop_one(target_id).await {
                QueuePop::Item(submission) => return Some(*submission),
                QueuePop::Closed => return None,
                QueuePop::Empty => {}
            }
            self.notify.notified().await;
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
                QueuePop::Empty | QueuePop::Closed => break,
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

    pub async fn discard_pending(&self) -> usize {
        let (dropped, snapshot) = {
            let mut state = self.inner.lock().await;
            let dropped = state.pending.len();
            state.pending.clear();
            (dropped, snapshot_pending(&state))
        };
        if dropped > 0 {
            self.publish(snapshot);
        }
        dropped
    }

    pub async fn close(&self) {
        let mut state = self.inner.lock().await;
        state.closed = true;
        self.notify.notify_waiters();
    }

    async fn pop_one(&self, target_id: Option<&str>) -> QueuePop {
        let (item, snapshot) = {
            let mut state = self.inner.lock().await;
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
        submission.queue_item_ids.push(item.id);
        submission.queue_target = Some(item.target);
        QueuePop::Item(Box::new(submission))
    }

    fn publish(&self, snapshot: Vec<QueuedUserMessage>) {
        let _ = self.updates.send(snapshot);
    }
}

enum QueuePop {
    Item(Box<UserSubmission>),
    Empty,
    Closed,
}

fn snapshot_pending(state: &UserSubmissionQueueState) -> Vec<QueuedUserMessage> {
    state
        .pending
        .iter()
        .map(queued_message_from_submission)
        .collect()
}

fn queued_message_from_submission(item: &QueuedSubmission) -> QueuedUserMessage {
    QueuedUserMessage {
        id: item.id,
        status: QueueItemStatus::Queued,
        text: item.submission.text.clone(),
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
            text: "/compact: assembling handoff (prune-first, model brief, deterministic appendix, seed tools)...".to_string(),
            ..Self::default()
        }
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
    async fn user_submission_queue_remove_prevents_later_drain_and_keeps_fifo() {
        let (updates_tx, mut updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
            snapshot.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![first_id, third_id]
        );

        let first = queue.recv().await.expect("first item");
        let third = queue.recv().await.expect("third item");
        assert_eq!(first.text, "first");
        assert_eq!(third.text, "third");

        let mut last = Vec::new();
        while let Ok(update) = updates_rx.try_recv() {
            last = update;
        }
        assert!(
            last.is_empty(),
            "draining publishes an empty queue snapshot"
        );
    }

    #[tokio::test]
    async fn user_submission_queue_remove_after_drain_reports_already_started() {
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
        let (updates_tx, _updates_rx) = tokio::sync::mpsc::unbounded_channel();
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
