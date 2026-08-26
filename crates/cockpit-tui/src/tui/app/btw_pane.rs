use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use uuid::Uuid;

use crate::tui::agent_runner::{self, AgentRunner};
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::composer::Composer;
use crate::tui::history::{HistoryEntry, PendingMsg};
use cockpit_client::submission::ClientUserSubmission as UserSubmission;
use cockpit_core::engine::TurnEvent;
use cockpit_proto::QueueItem as QueuedUserMessage;
use cockpit_proto::{self, Request, Response};
use cockpit_proto::{QueueItemStatus, QueueTarget};

use super::{
    App, FreshQueueAck, RunnerAttachContinuation,
    events::{
        reconcile_folded_user_history, reconcile_history_replay,
        remove_correlated_optimistic_user_history,
    },
    new_pending, wire_history_to_entries,
};

pub(super) const BTW_MIN_AUX_WIDTH: u16 = 30;
pub(super) const BTW_THREE_REGION_MIN_WIDTH: u16 = 120;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BtwMode {
    Seeded,
    Tangent,
}

impl BtwMode {
    pub(super) fn tangent(self) -> bool {
        matches!(self, Self::Tangent)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BtwCommand {
    Open { question: Option<String> },
    New { question: Option<String> },
    Tangent { question: String },
    End,
    NotYetAvailable(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BtwRpcPlan {
    Create { mode: BtwMode },
    End,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum BtwAuxVisible {
    Btw,
    Pty,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct BtwPaneLayout {
    pub main: Option<Rect>,
    pub btw: Option<Rect>,
    pub pty: Option<Rect>,
    pub hidden_live: Option<BtwAuxVisible>,
    pub narrow: bool,
}

pub(super) struct BtwPane {
    pub info: proto::BtwForkInfo,
    pub runner: Option<Result<AgentRunner, String>>,
    runner_attach_action_id: Option<crate::tui::async_action::AsyncActionId>,
    pub composer: Composer,
    pub history: Vec<HistoryEntry>,
    pub pending: Option<PendingMsg>,
    /// Live typed-display attempt owning BTW provisional UI (mirrors main TUI).
    active_display_attempt_id: Option<cockpit_client::presentation::AssistantAttemptId>,
    pub queue: Vec<QueuedUserMessage>,
    fresh_queue_ack: FreshQueueAck,
    folded_queue_item_ids: std::collections::HashSet<Uuid>,
    folded_queue_item_order: std::collections::VecDeque<Uuid>,
    pub focused: bool,
    pub zoomed: bool,
    pub hidden_streaming: bool,
    pub history_scroll_offset: usize,
    pub body_rect: Option<Rect>,
    pub input_rect: Option<Rect>,
}

impl BtwPane {
    const FOLDED_QUEUE_TOMBSTONE_CAPACITY: usize = 1024;

    pub(super) fn new(info: proto::BtwForkInfo, vim_enabled: bool) -> Self {
        Self {
            info,
            runner: None,
            runner_attach_action_id: None,
            composer: Composer::new(vim_enabled),
            history: Vec::new(),
            pending: None,
            active_display_attempt_id: None,
            queue: Vec::new(),
            fresh_queue_ack: FreshQueueAck::None,
            folded_queue_item_ids: std::collections::HashSet::new(),
            folded_queue_item_order: std::collections::VecDeque::new(),
            focused: false,
            zoomed: false,
            hidden_streaming: false,
            history_scroll_offset: 0,
            body_rect: None,
            input_rect: None,
        }
    }

    pub(super) fn paste(&mut self, text: &str) {
        self.composer.insert_str(text);
    }

    fn remember_folded_queue_item_ids(&mut self, ids: impl IntoIterator<Item = Uuid>) {
        for id in ids {
            if self.folded_queue_item_ids.insert(id) {
                self.folded_queue_item_order.push_back(id);
            }
        }
        while self.folded_queue_item_order.len() > Self::FOLDED_QUEUE_TOMBSTONE_CAPACITY {
            if let Some(expired) = self.folded_queue_item_order.pop_front() {
                self.folded_queue_item_ids.remove(&expired);
            }
        }
    }

    fn reconcile_queue_update(&mut self, queue: Vec<QueuedUserMessage>) {
        let contains_tracked = |id| queue.iter().any(|item| item.id == id);
        let (suppress_id, next_ack) = match self.fresh_queue_ack {
            FreshQueueAck::AwaitingAck(id) if contains_tracked(id) => {
                (Some(id), FreshQueueAck::SuppressId(id))
            }
            FreshQueueAck::SuppressId(id) => (Some(id), FreshQueueAck::SuppressId(id)),
            FreshQueueAck::FoldedBeforeAck(id) if contains_tracked(id) => {
                (Some(id), FreshQueueAck::None)
            }
            FreshQueueAck::FoldedBeforeAck(id) => (Some(id), FreshQueueAck::FoldedBeforeAck(id)),
            FreshQueueAck::None | FreshQueueAck::AwaitingAck(_) => (None, self.fresh_queue_ack),
        };
        self.queue = queue
            .into_iter()
            .filter(|item| {
                !self.folded_queue_item_ids.contains(&item.id) && suppress_id != Some(item.id)
            })
            .collect();
        self.fresh_queue_ack = next_ack;
    }

    #[cfg(test)]
    pub(super) fn session_id(&self) -> Uuid {
        self.info.session_id
    }

    pub(super) fn mode(&self) -> BtwMode {
        if self.info.tangent {
            BtwMode::Tangent
        } else {
            BtwMode::Seeded
        }
    }

    pub(super) fn drain_events(&self) -> Vec<TurnEvent> {
        let Some(Ok(runner)) = self.runner.as_ref() else {
            return Vec::new();
        };
        agent_runner::drain_turn_events(&runner.events)
            .into_iter()
            .map(|queued| queued.event)
            .collect()
    }

    pub(super) fn apply_event(&mut self, event: TurnEvent, strip_inline_think: bool) {
        match event {
            TurnEvent::HistoryReplay { entries } => {
                reconcile_history_replay(&mut self.history, entries);
            }
            TurnEvent::QueueUpdated { queue } => {
                self.reconcile_queue_update(queue);
            }
            TurnEvent::QueuedUserMessagesFolded {
                text,
                display_text,
                queue_item_ids,
                seq,
                preflight_cleaned,
                ..
            } => {
                let folded_ids = queue_item_ids
                    .iter()
                    .copied()
                    .collect::<std::collections::HashSet<_>>();
                self.remember_folded_queue_item_ids(queue_item_ids.iter().copied());
                let folded_before_ack_id = match self.fresh_queue_ack {
                    FreshQueueAck::AwaitingAck(id) if folded_ids.contains(&id) => Some(id),
                    _ => None,
                };
                self.queue.retain(|item| !folded_ids.contains(&item.id));
                reconcile_folded_user_history(
                    &mut self.history,
                    &folded_ids,
                    text,
                    display_text,
                    seq,
                    preflight_cleaned,
                );
                self.fresh_queue_ack = match self.fresh_queue_ack {
                    FreshQueueAck::AwaitingAck(id) if folded_before_ack_id == Some(id) => {
                        FreshQueueAck::FoldedBeforeAck(id)
                    }
                    FreshQueueAck::SuppressId(id) if folded_ids.contains(&id) => {
                        FreshQueueAck::None
                    }
                    other => other,
                };
            }
            TurnEvent::UserMessageRecorded {
                seq,
                client_submission_ids,
                preflight_cleaned,
            } => {
                self.remember_folded_queue_item_ids(client_submission_ids.iter().copied());
                self.fresh_queue_ack = match self.fresh_queue_ack {
                    FreshQueueAck::AwaitingAck(id) if client_submission_ids.contains(&id) => {
                        FreshQueueAck::FoldedBeforeAck(id)
                    }
                    FreshQueueAck::SuppressId(id) if client_submission_ids.contains(&id) => {
                        FreshQueueAck::None
                    }
                    other => other,
                };
                if self.history.iter().any(
                    |entry| matches!(entry, HistoryEntry::User { seq: Some(existing), .. } if *existing == seq),
                ) {
                    return;
                }
                for entry in self.history.iter_mut() {
                    if let HistoryEntry::User {
                        seq: row_seq @ None,
                        cleaned,
                        optimistic_submission_id,
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                        && optimistic_submission_id
                            .is_some_and(|id| client_submission_ids.contains(&id))
                    {
                        *row_seq = Some(seq);
                        *cleaned = preflight_cleaned;
                        *preflight_pending = false;
                        *persist_failed = false;
                        *optimistic_submission_id = None;
                        break;
                    }
                }
            }
            TurnEvent::PreflightStarted {
                client_submission_ids,
            } => {
                for entry in &mut self.history {
                    if let HistoryEntry::User {
                        seq: None,
                        optimistic_submission_id: Some(id),
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                        && !*persist_failed
                        && client_submission_ids.contains(id)
                    {
                        *preflight_pending = true;
                    }
                }
            }
            TurnEvent::UserMessagesTerminated {
                client_submission_ids,
                ..
            } => {
                let terminal_ids = client_submission_ids
                    .iter()
                    .copied()
                    .collect::<std::collections::HashSet<_>>();
                self.remember_folded_queue_item_ids(client_submission_ids.iter().copied());
                self.queue.retain(|item| !terminal_ids.contains(&item.id));
                remove_correlated_optimistic_user_history(&mut self.history, &terminal_ids);
                self.fresh_queue_ack = match self.fresh_queue_ack {
                    FreshQueueAck::AwaitingAck(id) if terminal_ids.contains(&id) => {
                        FreshQueueAck::FoldedBeforeAck(id)
                    }
                    FreshQueueAck::SuppressId(id) if terminal_ids.contains(&id) => {
                        FreshQueueAck::None
                    }
                    other => other,
                };
            }
            TurnEvent::UserMessageRetracted {
                client_submission_ids,
            } => {
                let ids = client_submission_ids
                    .iter()
                    .copied()
                    .collect::<std::collections::HashSet<_>>();
                remove_correlated_optimistic_user_history(&mut self.history, &ids);
            }
            TurnEvent::ThinkingStarted { agent, .. } => {
                self.finalize_pending();
                self.active_display_attempt_id = None;
                self.pending = Some(new_pending(agent, strip_inline_think));
            }
            TurnEvent::AssistantTextDelta { .. } => {
                // Live provisional/chip is typed AssistantDisplay* only.
            }
            TurnEvent::AssistantDisplayTextDelta {
                agent,
                attempt_id,
                delta,
            } => {
                if self
                    .active_display_attempt_id
                    .is_some_and(|active| active != attempt_id)
                {
                    return;
                }
                self.active_display_attempt_id = Some(attempt_id);
                let p = self
                    .pending
                    .get_or_insert_with(|| new_pending(agent, false));
                p.strip_think = false;
                p.attempt_id = Some(attempt_id);
                p.text.push_str(&delta);
                if !delta.trim().is_empty() && p.text_started_at.is_none() {
                    p.text_started_at = Some(std::time::Instant::now());
                }
            }
            TurnEvent::ReasoningDelta { .. } => {
                // Live reasoning is typed AssistantDisplayReasoningDelta only.
            }
            TurnEvent::AssistantDisplayReasoningDelta {
                agent,
                attempt_id,
                delta,
            } => {
                if self
                    .active_display_attempt_id
                    .is_some_and(|active| active != attempt_id)
                {
                    return;
                }
                self.active_display_attempt_id = Some(attempt_id);
                let p = self
                    .pending
                    .get_or_insert_with(|| new_pending(agent, false));
                p.strip_think = false;
                p.attempt_id = Some(attempt_id);
                p.reasoning.push_str(&delta);
            }
            TurnEvent::AssistantDisplayAttemptReset {
                failed_attempt_id,
                replacement_attempt_id,
                ..
            } => {
                if self.pending.as_ref().is_some_and(|p| {
                    p.attempt_id == Some(failed_attempt_id) || p.attempt_id.is_none()
                }) {
                    self.pending = None;
                }
                self.active_display_attempt_id = Some(replacement_attempt_id);
            }
            TurnEvent::AssistantDisplayComplete {
                agent,
                attempt_id,
                assistant,
            } => {
                if self
                    .active_display_attempt_id
                    .is_some_and(|active| active != attempt_id)
                {
                    return;
                }
                self.active_display_attempt_id = Some(attempt_id);
                let p = self
                    .pending
                    .get_or_insert_with(|| new_pending(agent, false));
                p.attempt_id = Some(attempt_id);
                p.strip_think = false;
                if p.text_started_at.is_none() {
                    p.text_started_at = Some(std::time::Instant::now());
                }
                p.seq = assistant.seq;
                p.response_performance = assistant.response_performance;
                let display = assistant
                    .presentation_text
                    .as_deref()
                    .unwrap_or(&assistant.text);
                if !display.trim().is_empty() {
                    p.text = display.to_string();
                }
                if p.reasoning.trim().is_empty() && !assistant.reasoning.trim().is_empty() {
                    p.reasoning = assistant.reasoning;
                }
                self.finalize_pending();
            }
            TurnEvent::AssistantDisplayError {
                attempt_id,
                message,
                presentation_text,
                ..
            } => {
                if self
                    .active_display_attempt_id
                    .is_some_and(|active| active != attempt_id)
                {
                    return;
                }
                let body = presentation_text.unwrap_or_default();
                if !body.trim().is_empty() || !message.trim().is_empty() {
                    self.history.push(HistoryEntry::CommandError {
                        line: if body.trim().is_empty() {
                            message
                        } else {
                            format!("{body}\n{message}")
                        },
                    });
                }
                self.pending = None;
                self.active_display_attempt_id = None;
            }
            TurnEvent::AssistantText {
                agent,
                text,
                reasoning,
                seq,
                response_performance,
                presentation_text,
                ..
            } => {
                // After typed Complete finalized, ignore durable AssistantText
                // (avoids double rows). Still accept when pending remains.
                let Some(p) = self.pending.as_mut() else {
                    return;
                };
                if p.text_started_at.is_none() {
                    p.text_started_at = Some(std::time::Instant::now());
                }
                let display = presentation_text.as_deref().unwrap_or(&text);
                if !display.trim().is_empty() && display != p.text {
                    p.text = display.to_string();
                }
                if p.reasoning.trim().is_empty() && !reasoning.trim().is_empty() {
                    p.reasoning = reasoning;
                }
                p.seq = seq;
                if response_performance.is_some() {
                    p.response_performance = response_performance;
                }
                let _ = agent;
                self.finalize_pending();
            }
            TurnEvent::InferenceFailed {
                provider,
                model,
                error_class,
                detail,
                ..
            } => {
                self.finalize_pending();
                let summary = format!("{provider}/{model}: {error_class}");
                self.history.push(HistoryEntry::InferenceError {
                    summary,
                    detail,
                    expanded: false,
                });
            }
            TurnEvent::UserMessageDispatchFailed {
                error,
                optimistic_submission_id,
            } => {
                self.finalize_pending();
                for entry in self.history.iter_mut() {
                    if let HistoryEntry::User {
                        optimistic_submission_id: Some(id),
                        seq: None,
                        preflight_pending,
                        persist_failed,
                        ..
                    } = entry
                        && *id == optimistic_submission_id
                    {
                        *preflight_pending = false;
                        *persist_failed = true;
                        break;
                    }
                }
                self.queue
                    .retain(|item| item.id != optimistic_submission_id);
                let summary = format!("message was not sent: {error}");
                self.history.push(HistoryEntry::InferenceError {
                    summary: summary.clone(),
                    detail: summary,
                    expanded: false,
                });
            }
            TurnEvent::UserMessageDispatchRetained {
                error,
                optimistic_submission_id,
            } => {
                self.history.push(HistoryEntry::Plain {
                    line: format!(
                        "Message {optimistic_submission_id} was not accepted and was retained for retry: {error}"
                    ),
                });
            }
            TurnEvent::UserMessageDispatchRestored {
                optimistic_submission_id,
                text,
                display_text,
                ..
            } => {
                let exists = self.history.iter().any(|entry| {
                    matches!(
                        entry,
                        HistoryEntry::User {
                            optimistic_submission_id: Some(id),
                            ..
                        } if *id == optimistic_submission_id
                    )
                });
                if !exists {
                    self.history.push(HistoryEntry::User {
                        text: display_text
                            .filter(|value| !value.is_empty())
                            .unwrap_or(text),
                        cleaned: None,
                        expanded: false,
                        timestamp: chrono::Local::now(),
                        seq: None,
                        optimistic_submission_id: Some(optimistic_submission_id),
                        preflight_pending: false,
                        persist_failed: false,
                    });
                }
            }
            TurnEvent::AgentIdle { .. } => {
                self.finalize_pending();
            }
            TurnEvent::Notice { text } => self.history.push(HistoryEntry::Plain { line: text }),
            _ => {}
        }
    }

    pub(super) fn finalize_pending(&mut self) {
        let Some(p) = self.pending.take() else {
            return;
        };
        self.active_display_attempt_id = None;
        if !p.text.trim().is_empty() || !p.reasoning.trim().is_empty() {
            let think_duration = p
                .text_started_at
                .map(|ts| ts.saturating_duration_since(p.started_at));
            self.history.push(HistoryEntry::Agent {
                name: p.name,
                text: p.text,
                reasoning: p.reasoning,
                timestamp: p.timestamp,
                expanded: false,
                reasoning_offset: 0,
                think_duration,
                seq: p.seq,
                performance: p.response_performance,
                performance_expanded: false,
            });
        }
    }

    pub(super) fn send_text(&mut self, text: String) -> Result<(), String> {
        let Some(Ok(runner)) = self.runner.as_ref() else {
            return Err("btw pane is not attached".to_string());
        };
        let submission = UserSubmission {
            expected_model_state_generation: None,
            expected_model: None,
            kind: cockpit_client::submission::UserSubmissionKind::User,
            origin: cockpit_client::submission::SubmissionOrigin::ExternalRoot,
            text: text.clone(),
            display_text: Some(text.clone()),
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: None,
            ..Default::default()
        };
        let client_submission_id = Uuid::new_v4();
        runner
            .try_send_optimistic_input(submission, client_submission_id)
            .map_err(|_| "btw message could not be sent".to_string())?;
        self.history.push(HistoryEntry::User {
            text: text.clone(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            optimistic_submission_id: Some(client_submission_id),
            preflight_pending: false,
            persist_failed: false,
        });
        self.queue
            .push(optimistic_queue_item(client_submission_id, text));
        self.fresh_queue_ack = FreshQueueAck::AwaitingAck(client_submission_id);
        Ok(())
    }

    pub(super) fn handle_focused_key(&mut self, key: KeyEvent) -> BtwFocusedKeyOutcome {
        if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('b')) {
            self.focused = false;
            return BtwFocusedKeyOutcome::Consumed;
        }
        if matches!(key.code, KeyCode::F(11)) {
            self.zoomed = !self.zoomed;
            return BtwFocusedKeyOutcome::Consumed;
        }
        if matches!(key.code, KeyCode::Esc) && self.composer.is_empty() && self.pending.is_none() {
            self.focused = false;
            return BtwFocusedKeyOutcome::Consumed;
        }
        match key.code {
            KeyCode::Enter if !key.modifiers.contains(KeyModifiers::SHIFT) => {
                let text = self.composer.text().trim().to_string();
                if text.is_empty() {
                    return BtwFocusedKeyOutcome::Consumed;
                }
                match self.send_text(text) {
                    Ok(()) => {
                        self.composer = Composer::new(self.composer.vim_enabled());
                        BtwFocusedKeyOutcome::Consumed
                    }
                    Err(error) => BtwFocusedKeyOutcome::Error(error),
                }
            }
            KeyCode::Enter => {
                self.composer.insert_char('\n');
                BtwFocusedKeyOutcome::Consumed
            }
            KeyCode::Backspace => {
                self.composer.delete_left();
                BtwFocusedKeyOutcome::Consumed
            }
            KeyCode::Delete => {
                self.composer.delete_right();
                BtwFocusedKeyOutcome::Consumed
            }
            KeyCode::Left => {
                self.composer.move_left();
                BtwFocusedKeyOutcome::Consumed
            }
            KeyCode::Right => {
                self.composer.move_right();
                BtwFocusedKeyOutcome::Consumed
            }
            KeyCode::Char(ch)
                if key.modifiers.is_empty() || key.modifiers == KeyModifiers::SHIFT =>
            {
                self.composer.insert_char(ch);
                BtwFocusedKeyOutcome::Consumed
            }
            _ => BtwFocusedKeyOutcome::Unhandled,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum BtwFocusedKeyOutcome {
    Consumed,
    Unhandled,
    Error(String),
}

pub(super) fn parse_btw_command(args: &str) -> Result<BtwCommand, String> {
    let trimmed = args.trim();
    if trimmed.is_empty() {
        return Ok(BtwCommand::Open { question: None });
    }
    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let first = parts.next().unwrap_or_default();
    let rest = parts.next().unwrap_or_default().trim();
    match first {
        "new" => Ok(BtwCommand::New {
            question: (!rest.is_empty()).then(|| rest.to_string()),
        }),
        "tangent" => {
            if rest.is_empty() {
                Err("/btw tangent: usage `/btw tangent <question>`".to_string())
            } else {
                Ok(BtwCommand::Tangent {
                    question: rest.to_string(),
                })
            }
        }
        "end" if rest.is_empty() => Ok(BtwCommand::End),
        "inject" if rest.is_empty() => Ok(BtwCommand::NotYetAvailable("inject")),
        "handoff" if rest.is_empty() => Ok(BtwCommand::NotYetAvailable("handoff")),
        "note" if rest.is_empty() => Ok(BtwCommand::NotYetAvailable("note")),
        "end" => Err("/btw end: usage `/btw end`".to_string()),
        other if rest.is_empty() && is_unknown_subcommand(other) => {
            Err(format!("/btw: unknown subcommand `{other}`"))
        }
        _ => Ok(BtwCommand::Open {
            question: Some(trimmed.to_string()),
        }),
    }
}

fn is_unknown_subcommand(value: &str) -> bool {
    matches!(
        value,
        "bogus" | "new" | "tangent" | "inject" | "handoff" | "note" | "end"
    )
}

pub(super) fn plan_btw_rpcs(
    command: &BtwCommand,
    existing_mode: Option<BtwMode>,
) -> Vec<BtwRpcPlan> {
    match command {
        BtwCommand::Open { .. } => {
            if existing_mode.is_some() {
                Vec::new()
            } else {
                vec![BtwRpcPlan::Create {
                    mode: BtwMode::Seeded,
                }]
            }
        }
        BtwCommand::New { .. } => {
            let mut plan = Vec::new();
            if existing_mode.is_some() {
                plan.push(BtwRpcPlan::End);
            }
            plan.push(BtwRpcPlan::Create {
                mode: BtwMode::Seeded,
            });
            plan
        }
        BtwCommand::Tangent { .. } => {
            let mut plan = Vec::new();
            if existing_mode.is_some() {
                plan.push(BtwRpcPlan::End);
            }
            plan.push(BtwRpcPlan::Create {
                mode: BtwMode::Tangent,
            });
            plan
        }
        BtwCommand::End => {
            if existing_mode.is_some() {
                vec![BtwRpcPlan::End]
            } else {
                Vec::new()
            }
        }
        BtwCommand::NotYetAvailable(_) => Vec::new(),
    }
}

pub(super) fn compose_aux_layout(
    body: Rect,
    btw_live: bool,
    pty_live: bool,
    btw_zoomed: bool,
    btw_focused: bool,
    pty_focused: bool,
) -> BtwPaneLayout {
    if btw_zoomed && btw_live {
        return BtwPaneLayout {
            main: None,
            btw: Some(body),
            pty: None,
            hidden_live: pty_live.then_some(BtwAuxVisible::Pty),
            narrow: false,
        };
    }
    match (btw_live, pty_live) {
        (false, false) => BtwPaneLayout {
            main: Some(body),
            btw: None,
            pty: None,
            hidden_live: None,
            narrow: false,
        },
        (true, false) => {
            let aux_width = (body.width / 3)
                .max(BTW_MIN_AUX_WIDTH)
                .min(body.width.saturating_sub(1));
            let main_width = body.width.saturating_sub(aux_width + 1);
            BtwPaneLayout {
                main: Some(Rect::new(body.x, body.y, main_width, body.height)),
                btw: Some(Rect::new(
                    body.x + main_width + 1,
                    body.y,
                    aux_width,
                    body.height,
                )),
                pty: None,
                hidden_live: None,
                narrow: false,
            }
        }
        (false, true) => BtwPaneLayout {
            main: Some(body),
            btw: None,
            pty: Some(body),
            hidden_live: None,
            narrow: false,
        },
        (true, true) if body.width >= BTW_THREE_REGION_MIN_WIDTH => {
            let aux_width = ((body.width - 2) / 4).max(BTW_MIN_AUX_WIDTH);
            let main_width = body.width.saturating_sub(aux_width * 2 + 2);
            BtwPaneLayout {
                main: Some(Rect::new(body.x, body.y, main_width, body.height)),
                btw: Some(Rect::new(
                    body.x + main_width + 1,
                    body.y,
                    aux_width,
                    body.height,
                )),
                pty: Some(Rect::new(
                    body.x + main_width + aux_width + 2,
                    body.y,
                    aux_width,
                    body.height,
                )),
                hidden_live: None,
                narrow: false,
            }
        }
        (true, true) => {
            let show_btw = btw_focused || !pty_focused;
            let aux_width = (body.width / 2)
                .max(BTW_MIN_AUX_WIDTH)
                .min(body.width.saturating_sub(1));
            let main_width = body.width.saturating_sub(aux_width + 1);
            BtwPaneLayout {
                main: Some(Rect::new(body.x, body.y, main_width, body.height)),
                btw: show_btw.then_some(Rect::new(
                    body.x + main_width + 1,
                    body.y,
                    aux_width,
                    body.height,
                )),
                pty: (!show_btw).then_some(Rect::new(
                    body.x + main_width + 1,
                    body.y,
                    aux_width,
                    body.height,
                )),
                hidden_live: Some(if show_btw {
                    BtwAuxVisible::Pty
                } else {
                    BtwAuxVisible::Btw
                }),
                narrow: true,
            }
        }
    }
}

fn optimistic_queue_item(id: Uuid, text: String) -> QueuedUserMessage {
    QueuedUserMessage {
        id,
        status: QueueItemStatus::Queued,
        text: text.clone(),
        display_text: Some(text),
        target: QueueTarget::root("btw"),
    }
}

impl App {
    pub(super) fn handle_btw_command(&mut self, args: &str) {
        if self.side_conversation.is_some() {
            self.history.push(HistoryEntry::CommandError {
                line: "/btw: end /side first".to_string(),
            });
            return;
        }
        let command = match parse_btw_command(args) {
            Ok(command) => command,
            Err(line) => {
                self.history.push(HistoryEntry::CommandError { line });
                return;
            }
        };
        if let BtwCommand::NotYetAvailable(name) = command {
            self.history.push(HistoryEntry::CommandError {
                line: format!("/btw {name}: not yet available"),
            });
            return;
        }

        let existing_mode = self.btw_pane.as_ref().map(BtwPane::mode);
        let operation = self.btw_blocking_operation();
        #[cfg(test)]
        let barrier = self.take_owned_test_barrier(operation);
        #[cfg(test)]
        let has_test_gate = barrier.is_some();
        #[cfg(not(test))]
        let has_test_gate = false;
        let runner = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok());
        if runner.is_none() && !has_test_gate {
            self.start_runner_attach(true, RunnerAttachContinuation::BtwCommand(args.to_string()));
            self.push_plain("/btw: connecting".to_string());
            return;
        }
        let parent_session_id = runner
            .map(|runner| runner.session_id())
            .unwrap_or_else(uuid::Uuid::nil);
        let attached_request = runner.map(|runner| runner.attached_request_binding());

        let requests = plan_btw_rpcs(&command, existing_mode)
            .into_iter()
            .map(|rpc| match rpc {
                BtwRpcPlan::End => Request::EndBtwFork { parent_session_id },
                BtwRpcPlan::Create { mode } => Request::CreateBtwFork {
                    parent_session_id,
                    tangent: mode.tangent(),
                },
            })
            .collect::<Vec<_>>();
        let question = match command {
            BtwCommand::Open { question } | BtwCommand::New { question } => question,
            BtwCommand::Tangent { question } => Some(question),
            BtwCommand::End | BtwCommand::NotYetAvailable(_) => None,
        };
        self.push_plain("/btw: pending".to_string());
        let action_kind = operation.action_kind();
        self.async_actions.start(
            action_kind,
            crate::tui::async_action::AsyncActionPolicy::Replace(
                crate::tui::async_action::AsyncActionKey::new("btw.transition"),
            ),
            async move {
                #[cfg(test)]
                if let Some(barrier) = barrier {
                    tokio::task::spawn_blocking(move || barrier.arrive_and_wait())
                        .await
                        .map_err(|error| error.to_string())?;
                    return Ok(AsyncActionPayload::Unit);
                }
                let attached_request = attached_request.expect("BTW dispatch checked runner");
                let mut created = None;
                let mut ended = false;
                let mut error = None;
                for request in requests {
                    match attached_request.request(request).await {
                        Ok(Response::Ack) => ended = true,
                        Ok(Response::BtwFork { info, .. }) => created = Some(info),
                        Ok(other) => {
                            error = Some(format!("unexpected daemon response: {other:?}"));
                            break;
                        }
                        Err(rpc_error) => {
                            error = Some(rpc_error);
                            break;
                        }
                    }
                }
                Ok(
                    crate::tui::async_action::AsyncActionPayload::BtwTransition {
                        created,
                        ended,
                        question,
                        error,
                    },
                )
            },
        );
    }

    pub(super) fn open_btw_pane_from_info(&mut self, info: proto::BtwForkInfo, attach: bool) {
        let mut pane = BtwPane::new(info, self.composer.vim_enabled());
        if attach {
            pane.runner_attach_action_id = Some(self.start_btw_runner_attach(pane.info.session_id));
        }
        pane.focused = false;
        self.btw_pane = Some(pane);
    }

    fn start_btw_runner_attach(
        &mut self,
        session_id: uuid::Uuid,
    ) -> crate::tui::async_action::AsyncActionId {
        let cwd = self.launch.cwd.clone();
        let no_sandbox = self.no_sandbox;
        let intent = self.lifecycle_intent();
        let lifecycle = self.lifecycle.clone();
        self.async_actions
            .start(
                AsyncActionKind::Internal("btw.runner.attach"),
                AsyncActionPolicy::Replace(AsyncActionKey::new("btw.runner.attach")),
                async move {
                    let runner = agent_runner::attach_to_session(
                        &cwd, session_id, no_sandbox, lifecycle, intent,
                    )
                    .await?;
                    Ok(AsyncActionPayload::BtwRunnerAttached {
                        session_id,
                        runner: Box::new(runner),
                    })
                },
            )
            .id()
    }

    pub(super) fn apply_btw_runner_attach(
        &mut self,
        action_id: crate::tui::async_action::AsyncActionId,
        payload: Result<AsyncActionPayload, String>,
    ) {
        let Some(pane) = self
            .btw_pane
            .as_mut()
            .filter(|pane| pane.runner_attach_action_id == Some(action_id))
        else {
            return;
        };
        pane.runner_attach_action_id = None;
        match payload {
            Ok(AsyncActionPayload::BtwRunnerAttached {
                session_id,
                mut runner,
            }) => {
                if pane.info.session_id != session_id {
                    return;
                }
                pane.history
                    .extend(wire_history_to_entries(std::mem::take(&mut runner.history)));
                pane.runner = Some(Ok(*runner));
            }
            Err(error) => {
                pane.runner = Some(Err(error));
            }
            Ok(_) => {}
        }
    }

    pub(super) fn close_btw_pane(&mut self) {
        self.async_actions
            .abort_key(&crate::tui::async_action::AsyncActionKey::new(
                "btw.transition",
            ));
        self.async_actions
            .abort_key(&crate::tui::async_action::AsyncActionKey::new(
                "btw.runner.attach",
            ));
        self.btw_pane = None;
    }

    pub(super) fn drain_btw_events(&mut self) -> bool {
        let Some(pane) = self.btw_pane.as_ref() else {
            return false;
        };
        let events = pane.drain_events();
        let changed = !events.is_empty();
        let strip = self.strip_inline_think();
        for event in events {
            let streaming = matches!(
                event,
                TurnEvent::ThinkingStarted { .. }
                    | TurnEvent::AssistantTextDelta { .. }
                    | TurnEvent::AssistantDisplayTextDelta { .. }
                    | TurnEvent::AssistantDisplayReasoningDelta { .. }
                    | TurnEvent::AssistantDisplayComplete { .. }
                    | TurnEvent::ReasoningDelta { .. }
                    | TurnEvent::AssistantText { .. }
            );
            if matches!(event, TurnEvent::InterruptRaised { .. }) {
                self.handle_btw_interrupt(event);
                continue;
            }
            if let Some(pane) = self.btw_pane.as_mut() {
                if streaming && !pane.focused {
                    pane.hidden_streaming = true;
                }
                pane.apply_event(event, strip);
            }
        }
        changed
    }

    pub(super) fn handle_btw_interrupt(&mut self, event: TurnEvent) {
        if self.question_dialog.is_some() && !self.question_dialog_btw {
            self.pending_btw_interrupt = Some(event);
            return;
        }
        self.install_btw_interrupt(event);
    }

    pub(super) fn install_pending_btw_interrupt(&mut self) {
        if self.question_dialog.is_some() {
            return;
        }
        if let Some(event) = self.pending_btw_interrupt.take() {
            self.install_btw_interrupt(event);
        }
    }

    fn install_btw_interrupt(&mut self, event: TurnEvent) {
        let TurnEvent::InterruptRaised {
            interrupt_id,
            description,
            questions,
            pending_count,
            reason,
            ..
        } = event
        else {
            return;
        };
        let lockout = match reason {
            cockpit_proto::InterruptRaiseReason::Initial => self.dialog_lockout(),
            cockpit_proto::InterruptRaiseReason::Advance => {
                crate::tui::dialog::DialogState::NO_LOCKOUT
            }
            cockpit_proto::InterruptRaiseReason::Rehydration => self.rehydrated_dialog_lockout(),
        };
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::new(
                interrupt_id,
                if description.trim().is_empty() {
                    "BTW side thread needs approval".to_string()
                } else {
                    format!("BTW side thread: {description}")
                },
                questions,
                lockout,
            )
            .with_pending_count(pending_count)
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
        self.question_dialog_btw = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cockpit_proto::{
        InterruptOption, InterruptQuestion, InterruptQuestionSet, InterruptRaiseReason,
    };

    fn info(tangent: bool) -> proto::BtwForkInfo {
        proto::BtwForkInfo {
            session_id: Uuid::new_v4(),
            parent_session_id: Uuid::new_v4(),
            short_id: Some("btw001".to_string()),
            tangent,
            created_at: 1,
            message_count: 0,
        }
    }

    fn question_set(permission: bool) -> InterruptQuestionSet {
        InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt: "Approve?".to_string(),
                options: vec![InterruptOption {
                    id: "yes".to_string(),
                    label: "Yes".to_string(),
                    description: None,
                    secondary: false,
                }],
                allow_freetext: false,
                command_detail: None,
                permission,
                approval_class: None,
                sandbox_escalation: None,
            }],
        }
    }

    #[test]
    fn btw_same_session_replay_replaces_correlated_optimistic_row() {
        let mut pane = BtwPane::new(info(false), false);
        let id = Uuid::new_v4();
        pane.history.push(HistoryEntry::User {
            text: "optimistic".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            optimistic_submission_id: Some(id),
            preflight_pending: false,
            persist_failed: false,
        });

        pane.apply_event(
            TurnEvent::HistoryReplay {
                entries: vec![proto::HistoryEntry::User {
                    text: "authoritative wire".to_string(),
                    display_text: Some("authoritative".to_string()),
                    tag_expansions: Vec::new(),
                    ts_ms: 1,
                    seq: 9,
                    client_submission_ids: vec![id],
                    origin_principal: None,
                }],
            },
            false,
        );

        assert_eq!(
            pane.history
                .iter()
                .filter(|entry| matches!(entry, HistoryEntry::User { .. }))
                .count(),
            1
        );
        assert!(matches!(
            pane.history.first(),
            Some(HistoryEntry::User {
                text,
                seq: Some(9),
                optimistic_submission_id: None,
                ..
            }) if text == "authoritative"
        ));
    }

    fn interrupt(session_id: Uuid, description: &str, permission: bool) -> TurnEvent {
        interrupt_with_reason(
            session_id,
            description,
            permission,
            InterruptRaiseReason::Initial,
        )
    }

    fn interrupt_with_reason(
        session_id: Uuid,
        description: &str,
        permission: bool,
        reason: InterruptRaiseReason,
    ) -> TurnEvent {
        TurnEvent::InterruptRaised {
            session_id,
            interrupt_id: Uuid::new_v4(),
            description: description.to_string(),
            questions: question_set(permission),
            pending_count: 0,
            reason,
        }
    }

    #[test]
    fn btw_pane_opens_and_streams() {
        let mut app = App::new(None, false);
        app.history.push(HistoryEntry::Plain {
            line: "main stays put".to_string(),
        });
        app.open_btw_pane_from_info(info(false), false);
        let pane = app.btw_pane.as_mut().expect("pane");
        pane.apply_event(
            TurnEvent::ThinkingStarted {
                agent: "Btw".to_string(),
                turn_id: Some("side".to_string()),
            },
            true,
        );
        pane.apply_event(
            TurnEvent::AssistantText {
                agent: "Btw".to_string(),
                text: "hello from side".to_string(),
                presentation_text: None,
                reasoning: String::new(),
                seq: Some(1),
                response_performance: None,
            },
            true,
        );
        assert!(
            matches!(pane.history.last(), Some(HistoryEntry::Agent { text, .. }) if text == "hello from side")
        );
        assert_eq!(app.history.len(), 1, "main transcript is unchanged");
    }

    #[test]
    fn btw_pane_new_replaces_fork() {
        assert_eq!(
            plan_btw_rpcs(
                &BtwCommand::New {
                    question: Some("q".to_string())
                },
                Some(BtwMode::Tangent)
            ),
            vec![
                BtwRpcPlan::End,
                BtwRpcPlan::Create {
                    mode: BtwMode::Seeded
                }
            ]
        );
    }

    #[test]
    fn btw_pane_tangent_replaces_mode() {
        assert_eq!(
            plan_btw_rpcs(
                &BtwCommand::Tangent {
                    question: "q".to_string()
                },
                Some(BtwMode::Seeded)
            ),
            vec![
                BtwRpcPlan::End,
                BtwRpcPlan::Create {
                    mode: BtwMode::Tangent
                }
            ]
        );
    }

    #[test]
    fn btw_pane_end_discards() {
        assert_eq!(
            plan_btw_rpcs(&BtwCommand::End, Some(BtwMode::Seeded)),
            vec![BtwRpcPlan::End]
        );
        assert!(plan_btw_rpcs(&BtwCommand::End, None).is_empty());
    }

    #[test]
    fn btw_pane_unknown_subcommand_errors() {
        assert_eq!(
            parse_btw_command("bogus").unwrap_err(),
            "/btw: unknown subcommand `bogus`"
        );
    }

    #[test]
    fn btw_pane_concurrent_with_main_turn() {
        let mut pane = BtwPane::new(info(false), false);
        let attempt = cockpit_client::presentation::AssistantAttemptId::new(1);
        pane.apply_event(
            TurnEvent::ThinkingStarted {
                agent: "Btw".to_string(),
                turn_id: Some("side".to_string()),
            },
            true,
        );
        pane.apply_event(
            TurnEvent::AssistantDisplayTextDelta {
                agent: "Btw".to_string(),
                attempt_id: attempt,
                delta: "side answer".to_string(),
            },
            true,
        );
        pane.apply_event(
            TurnEvent::AgentIdle {
                turn_id: Some("side".to_string()),
                reason: cockpit_core::engine::IdleReason::Completed,
            },
            true,
        );
        assert!(
            matches!(pane.history.last(), Some(HistoryEntry::Agent { text, .. }) if text == "side answer")
        );
    }

    #[test]
    fn btw_typed_display_attempt_correlation_rejects_stale_and_raw_deltas() {
        let mut pane = BtwPane::new(info(false), false);
        let failed = cockpit_client::presentation::AssistantAttemptId::new(7);
        let replacement = cockpit_client::presentation::AssistantAttemptId::new(8);
        pane.apply_event(
            TurnEvent::ThinkingStarted {
                agent: "Btw".to_string(),
                turn_id: Some("side".to_string()),
            },
            true,
        );
        pane.apply_event(
            TurnEvent::AssistantDisplayTextDelta {
                agent: "Btw".to_string(),
                attempt_id: failed,
                delta: "partial".to_string(),
            },
            true,
        );
        // Raw live deltas must not mutate provisional body / chip path.
        pane.apply_event(
            TurnEvent::AssistantTextDelta {
                agent: "Btw".to_string(),
                delta: "<think>nope</think>raw".to_string(),
            },
            true,
        );
        assert_eq!(
            pane.pending.as_ref().map(|p| p.text.as_str()),
            Some("partial")
        );
        pane.apply_event(
            TurnEvent::AssistantDisplayAttemptReset {
                agent: "Btw".to_string(),
                failed_attempt_id: failed,
                replacement_attempt_id: replacement,
                reason: "timeout".to_string(),
            },
            true,
        );
        assert!(pane.pending.is_none());
        // Late failed-attempt delta must not recreate a provisional row.
        pane.apply_event(
            TurnEvent::AssistantDisplayTextDelta {
                agent: "Btw".to_string(),
                attempt_id: failed,
                delta: "late".to_string(),
            },
            true,
        );
        assert!(pane.pending.is_none());
        pane.apply_event(
            TurnEvent::AssistantDisplayTextDelta {
                agent: "Btw".to_string(),
                attempt_id: replacement,
                delta: "ok".to_string(),
            },
            true,
        );
        assert_eq!(pane.pending.as_ref().map(|p| p.text.as_str()), Some("ok"));
    }

    #[test]
    fn btw_pane_focus_toggle() {
        let mut pane = BtwPane::new(info(false), false);
        pane.focused = true;
        assert_eq!(
            pane.handle_focused_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE)),
            BtwFocusedKeyOutcome::Consumed
        );
        assert_eq!(pane.composer.text(), "x");
        assert_eq!(
            pane.handle_focused_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            BtwFocusedKeyOutcome::Unhandled,
            "non-empty composer keeps Esc available to editor state"
        );
        pane.composer.clear();
        assert_eq!(
            pane.handle_focused_key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
            BtwFocusedKeyOutcome::Consumed
        );
        assert!(!pane.focused);
    }

    #[test]
    fn btw_pane_zoom_roundtrip() {
        let mut pane = BtwPane::new(info(false), false);
        pane.focused = true;
        pane.composer.insert_str("draft");
        assert_eq!(
            pane.handle_focused_key(KeyEvent::new(KeyCode::F(11), KeyModifiers::NONE)),
            BtwFocusedKeyOutcome::Consumed
        );
        assert!(pane.zoomed);
        assert_eq!(
            pane.handle_focused_key(KeyEvent::new(KeyCode::F(11), KeyModifiers::NONE)),
            BtwFocusedKeyOutcome::Consumed
        );
        assert!(!pane.zoomed);
        assert_eq!(pane.composer.text(), "draft");
    }

    #[test]
    fn btw_pane_rehydrate_on_attach() {
        let info = info(true);
        let mut app = App::new(None, false);
        app.open_btw_pane_from_info(info.clone(), false);
        let pane = app.btw_pane.as_ref().expect("pane");
        assert_eq!(pane.session_id(), info.session_id);
        assert!(
            !pane.focused,
            "attach rehydrates with main composer focused"
        );
        assert_eq!(pane.mode(), BtwMode::Tangent);
    }

    #[test]
    fn btw_pane_approval_labeling() {
        let mut app = App::new(None, false);
        let main_session = Uuid::new_v4();
        let side = info(false);
        app.launch.session_id = Some(main_session);
        app.open_btw_pane_from_info(side.clone(), false);

        app.apply_event(interrupt(main_session, "main approval", true));
        assert!(app.question_dialog.is_some());
        assert!(!app.question_dialog_btw);

        app.handle_btw_interrupt(interrupt(side.session_id, "write approval", true));
        assert!(
            app.pending_btw_interrupt.is_some(),
            "side approval queues behind visible main dialog"
        );
        app.question_dialog = None;
        app.install_pending_btw_interrupt();
        assert!(app.question_dialog.is_some());
        assert!(
            app.question_dialog_btw,
            "side approval is labeled/routed as btw"
        );
        assert!(app.question_dialog.as_ref().expect("dialog").is_approval());
    }

    #[test]
    fn btw_interrupt_raise_reasons_control_lockout() {
        for (reason, expected_locked) in [
            (InterruptRaiseReason::Initial, true),
            (InterruptRaiseReason::Advance, false),
            (InterruptRaiseReason::Rehydration, true),
        ] {
            let side = info(false);
            let mut app = App::new(None, false);
            app.daemon_prompt = None;
            app.dialog = crate::tui::settings::Dialog::None;
            app.open_btw_pane_from_info(side.clone(), false);
            app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
            assert_eq!(app.composer.text(), "x");

            app.handle_btw_interrupt(interrupt_with_reason(
                side.session_id,
                "side question",
                false,
                reason,
            ));

            let dialog = app.question_dialog.as_ref().expect("dialog");
            assert!(app.question_dialog_btw);
            assert_eq!(dialog.locked(), expected_locked, "{reason:?}");
        }
    }

    #[test]
    fn btw_pane_hidden_chrome_states() {
        let mut pane = BtwPane::new(info(false), false);
        assert!(!pane.hidden_streaming);
        pane.hidden_streaming = true;
        assert!(pane.hidden_streaming);
    }

    #[test]
    fn btw_pane_slash_registration() {
        let btw = super::super::slash::SLASH_COMMANDS
            .iter()
            .find(|cmd| cmd.name == "btw")
            .expect("/btw registered");
        assert!(btw.takes_args);
        let side = super::super::slash::SLASH_COMMANDS
            .iter()
            .find(|cmd| cmd.name == "side")
            .expect("/side remains registered");
        assert_eq!(side.name, "side");
        assert!(matches!(
            parse_btw_command("hello there").unwrap(),
            BtwCommand::Open { question: Some(_) }
        ));
    }

    #[test]
    fn btw_pane_composes_with_pty() {
        let wide = compose_aux_layout(Rect::new(0, 0, 150, 40), true, true, false, true, false);
        assert!(wide.main.is_some());
        assert!(wide.btw.is_some());
        assert!(wide.pty.is_some());
        assert_eq!(wide.hidden_live, None);

        let narrow = compose_aux_layout(Rect::new(0, 0, 80, 40), true, true, false, true, false);
        assert!(narrow.narrow);
        assert!(narrow.btw.is_some());
        assert!(narrow.pty.is_none());
        assert_eq!(narrow.hidden_live, Some(BtwAuxVisible::Pty));
    }

    #[test]
    fn btw_pane_queue_and_navigation() {
        let mut pane = BtwPane::new(info(false), false);
        let id = Uuid::new_v4();
        let item = optimistic_queue_item(id, "queued".to_string());
        pane.apply_event(TurnEvent::QueueUpdated { queue: vec![item] }, true);
        assert_eq!(pane.queue.len(), 1);
        pane.apply_event(
            TurnEvent::QueuedUserMessagesFolded {
                text: "queued".to_string(),
                display_text: Some("queued".to_string()),
                tag_expansions: Vec::new(),
                queue_item_ids: vec![id],
                target: QueueTarget::root("btw"),
                seq: Some(9),
                preflight_cleaned: None,
            },
            true,
        );
        assert!(pane.queue.is_empty());
        assert!(
            matches!(pane.history.last(), Some(HistoryEntry::User { text, seq, .. }) if text == "queued" && *seq == Some(9))
        );
    }

    #[test]
    fn btw_rapid_submissions_and_fold_record_pairs_reconcile_exactly_once() {
        let mut pane = BtwPane::new(info(false), false);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        for (id, text) in [(a, "A"), (b, "B")] {
            pane.history.push(HistoryEntry::User {
                text: text.to_string(),
                cleaned: None,
                expanded: false,
                timestamp: chrono::Local::now(),
                seq: None,
                optimistic_submission_id: Some(id),
                preflight_pending: false,
                persist_failed: false,
            });
            pane.queue.push(optimistic_queue_item(id, text.to_string()));
        }

        // Interleave B's durable signals ahead of A. Positional correlation
        // would stamp/render the wrong text; UUID correlation must not.
        pane.apply_event(
            TurnEvent::QueuedUserMessagesFolded {
                text: "wire B".to_string(),
                display_text: Some("B".to_string()),
                tag_expansions: Vec::new(),
                queue_item_ids: vec![b],
                target: QueueTarget::root("btw"),
                seq: Some(20),
                preflight_cleaned: None,
            },
            true,
        );
        pane.apply_event(
            TurnEvent::UserMessageRecorded {
                seq: 20,
                client_submission_ids: vec![b],
                preflight_cleaned: None,
            },
            true,
        );
        pane.apply_event(
            TurnEvent::QueuedUserMessagesFolded {
                text: "wire A".to_string(),
                display_text: Some("A".to_string()),
                tag_expansions: Vec::new(),
                queue_item_ids: vec![a],
                target: QueueTarget::root("btw"),
                seq: Some(21),
                preflight_cleaned: None,
            },
            true,
        );
        pane.apply_event(
            TurnEvent::UserMessageRecorded {
                seq: 21,
                client_submission_ids: vec![a],
                preflight_cleaned: None,
            },
            true,
        );

        let rows = pane
            .history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User { text, seq, .. } => Some((text.as_str(), *seq)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(rows, vec![("A", Some(21)), ("B", Some(20))]);
        assert!(pane.queue.is_empty());
    }

    #[test]
    fn btw_multi_id_fold_is_canonical_and_delayed_ack_cannot_resurrect_rows() {
        let mut pane = BtwPane::new(info(false), false);
        let first_id = Uuid::from_u128(301);
        let second_id = Uuid::from_u128(302);
        for (id, text) in [
            (first_id, "optimistic first"),
            (second_id, "optimistic second"),
        ] {
            pane.history.push(HistoryEntry::User {
                text: text.to_string(),
                cleaned: None,
                expanded: false,
                timestamp: chrono::Local::now(),
                seq: None,
                optimistic_submission_id: Some(id),
                preflight_pending: false,
                persist_failed: false,
            });
            pane.queue.push(optimistic_queue_item(id, text.to_string()));
        }
        pane.fresh_queue_ack = FreshQueueAck::AwaitingAck(second_id);

        pane.apply_event(
            TurnEvent::QueuedUserMessagesFolded {
                text: "expanded first\n\nexpanded second".to_string(),
                display_text: Some("canonical first\n\ncanonical second".to_string()),
                tag_expansions: Vec::new(),
                queue_item_ids: vec![first_id, second_id],
                target: QueueTarget::root("btw"),
                seq: Some(30),
                preflight_cleaned: None,
            },
            true,
        );

        let rows = pane
            .history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User {
                    text,
                    seq,
                    optimistic_submission_id,
                    ..
                } => Some((text.as_str(), *seq, *optimistic_submission_id)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            rows,
            vec![("canonical first\n\ncanonical second", Some(30), None)]
        );
        assert_eq!(
            pane.fresh_queue_ack,
            FreshQueueAck::FoldedBeforeAck(second_id)
        );

        let unrelated_id = Uuid::from_u128(303);
        pane.apply_event(
            TurnEvent::QueueUpdated {
                queue: vec![
                    optimistic_queue_item(first_id, "late first".to_string()),
                    optimistic_queue_item(second_id, "late second".to_string()),
                    optimistic_queue_item(unrelated_id, "still queued".to_string()),
                ],
            },
            true,
        );
        assert_eq!(
            pane.queue.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![unrelated_id],
            "fold tombstones and the delayed-ACK state suppress all already-recorded items"
        );
        assert_eq!(pane.fresh_queue_ack, FreshQueueAck::None);
    }

    #[test]
    fn btw_dispatch_failure_marks_only_the_correlated_optimistic_submission() {
        let mut pane = BtwPane::new(info(false), false);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        for (id, text) in [(a, "A"), (b, "B")] {
            pane.history.push(HistoryEntry::User {
                text: text.to_string(),
                cleaned: None,
                expanded: false,
                timestamp: chrono::Local::now(),
                seq: None,
                optimistic_submission_id: Some(id),
                preflight_pending: true,
                persist_failed: false,
            });
            pane.queue.push(optimistic_queue_item(id, text.to_string()));
        }

        pane.apply_event(
            TurnEvent::UserMessageDispatchFailed {
                error: "definite rejection".to_string(),
                optimistic_submission_id: a,
            },
            true,
        );

        let rows = pane
            .history
            .iter()
            .filter_map(|entry| match entry {
                HistoryEntry::User {
                    text,
                    preflight_pending,
                    persist_failed,
                    ..
                } => Some((text.as_str(), *preflight_pending, *persist_failed)),
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(rows, vec![("A", false, true), ("B", true, false)]);
        assert_eq!(
            pane.queue.iter().map(|item| item.id).collect::<Vec<_>>(),
            vec![b]
        );
        assert!(matches!(
            pane.history.last(),
            Some(HistoryEntry::InferenceError { summary, .. })
                if summary.contains("definite rejection")
        ));
    }

    #[test]
    fn btw_pane_main_composer_behavior_unchanged() {
        let mut app = App::new(None, false);
        app.composer.insert_str("main");
        app.open_btw_pane_from_info(info(false), false);
        let pane = app.btw_pane.as_mut().expect("pane");
        pane.focused = true;
        assert_eq!(
            pane.handle_focused_key(KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE)),
            BtwFocusedKeyOutcome::Consumed
        );
        assert_eq!(app.composer.text(), "main");
        assert_eq!(pane.composer.text(), "s");
    }

    #[tokio::test]
    async fn end_ack_then_create_failure_closes_dead_pane() {
        let mut app = App::new(None, false);
        app.open_btw_pane_from_info(info(false), false);
        app.async_actions.start(
            crate::tui::async_action::AsyncActionKind::Blocking("btw.teardown"),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            async {
                Ok(
                    crate::tui::async_action::AsyncActionPayload::BtwTransition {
                        created: None,
                        ended: true,
                        question: None,
                        error: Some("create failed".to_string()),
                    },
                )
            },
        );
        app.async_actions.notifier().notified().await;
        app.drain_async_actions();

        assert!(app.btw_pane.is_none());
        assert!(matches!(
            app.history.last(),
            Some(HistoryEntry::Plain { line }) if line.contains("create failed")
        ));
    }
}
