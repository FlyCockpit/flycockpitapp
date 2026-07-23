use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::Rect;
use uuid::Uuid;

use crate::tui::agent_runner::{self, AgentRunner};
use crate::tui::composer::Composer;
use crate::tui::history::{HistoryEntry, PendingMsg, route_text_delta};
use cockpit_core::daemon::proto::{self, Request, Response};
use cockpit_core::engine::TurnEvent;
use cockpit_core::engine::message::{
    QueueItemStatus, QueueTarget, QueuedUserMessage, UserSubmission,
};

use super::{App, new_pending, wire_history_to_entries};

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
    pub composer: Composer,
    pub history: Vec<HistoryEntry>,
    pub pending: Option<PendingMsg>,
    pub queue: Vec<QueuedUserMessage>,
    pub focused: bool,
    pub zoomed: bool,
    pub hidden_streaming: bool,
    pub history_scroll_offset: usize,
    pub body_rect: Option<Rect>,
    pub input_rect: Option<Rect>,
    pub last_message_dispatched: Option<String>,
}

impl BtwPane {
    pub(super) fn new(info: proto::BtwForkInfo, vim_enabled: bool) -> Self {
        Self {
            info,
            runner: None,
            composer: Composer::new(vim_enabled),
            history: Vec::new(),
            pending: None,
            queue: Vec::new(),
            focused: false,
            zoomed: false,
            hidden_streaming: false,
            history_scroll_offset: 0,
            body_rect: None,
            input_rect: None,
            last_message_dispatched: None,
        }
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
    }

    pub(super) fn attach_runner(
        &mut self,
        cwd: &std::path::Path,
        no_sandbox: bool,
        mode: cockpit_core::daemon::client::LifecycleMode,
    ) {
        if matches!(self.runner, Some(Ok(_))) {
            return;
        }
        let mut runner =
            agent_runner::attach_to_session(cwd, self.info.session_id, no_sandbox, mode);
        if let Ok(runner) = &mut runner {
            self.history
                .extend(wire_history_to_entries(std::mem::take(&mut runner.history)));
        }
        self.runner = Some(runner);
    }

    pub(super) fn apply_event(&mut self, event: TurnEvent, strip_inline_think: bool) {
        match event {
            TurnEvent::HistoryReplay { entries } => {
                self.history.extend(wire_history_to_entries(entries));
            }
            TurnEvent::QueueUpdated { queue } => {
                self.queue = queue;
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
                self.queue.retain(|item| !folded_ids.contains(&item.id));
                self.history.push(HistoryEntry::User {
                    text: display_text
                        .filter(|value| !value.is_empty())
                        .unwrap_or(text),
                    cleaned: preflight_cleaned,
                    expanded: false,
                    timestamp: chrono::Local::now(),
                    seq,
                    preflight_pending: false,
                    persist_failed: false,
                });
            }
            TurnEvent::UserMessageRecorded {
                seq,
                preflight_cleaned,
            } => {
                let text = self
                    .last_message_dispatched
                    .clone()
                    .unwrap_or_else(|| "btw message".to_string());
                self.history.push(HistoryEntry::User {
                    text,
                    cleaned: preflight_cleaned,
                    expanded: false,
                    timestamp: chrono::Local::now(),
                    seq: Some(seq),
                    preflight_pending: false,
                    persist_failed: false,
                });
            }
            TurnEvent::ThinkingStarted { agent, .. } => {
                self.finalize_pending();
                self.pending = Some(new_pending(agent, strip_inline_think));
            }
            TurnEvent::AssistantTextDelta { agent, delta } => {
                let p = self
                    .pending
                    .get_or_insert_with(|| new_pending(agent, strip_inline_think));
                if p.strip_think {
                    route_text_delta(
                        &delta,
                        &mut p.text,
                        &mut p.reasoning,
                        &mut p.inside_think,
                        &mut p.body_started,
                        &mut p.tag_partial,
                    );
                } else {
                    p.text.push_str(&delta);
                }
            }
            TurnEvent::ReasoningDelta { agent, delta } => {
                let p = self
                    .pending
                    .get_or_insert_with(|| new_pending(agent, strip_inline_think));
                p.reasoning.push_str(&delta);
            }
            TurnEvent::AssistantText {
                agent,
                text,
                reasoning,
                seq,
                ..
            } => {
                let p = self
                    .pending
                    .get_or_insert_with(|| new_pending(agent, strip_inline_think));
                if !text.is_empty() {
                    p.text.push_str(&text);
                }
                p.reasoning.push_str(&reasoning);
                p.seq = seq;
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
            TurnEvent::UserMessageDispatchFailed { error } => {
                self.finalize_pending();
                self.history.push(HistoryEntry::InferenceError {
                    summary: error.clone(),
                    detail: error,
                    expanded: false,
                });
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
            });
        }
    }

    pub(super) fn send_text(&mut self, text: String) -> Result<(), String> {
        let Some(Ok(runner)) = self.runner.as_ref() else {
            return Err("btw pane is not attached".to_string());
        };
        let submission = UserSubmission {
            kind: cockpit_core::engine::message::UserSubmissionKind::User,
            text: text.clone(),
            display_text: Some(text.clone()),
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: None,
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            queue_target: None,
        };
        runner
            .input_tx
            .try_send(submission)
            .map_err(|_| "btw message could not be sent".to_string())?;
        self.last_message_dispatched = Some(text);
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
                self.composer.clear();
                match self.send_text(text) {
                    Ok(()) => BtwFocusedKeyOutcome::Consumed,
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

fn optimistic_queue_item(text: String) -> QueuedUserMessage {
    QueuedUserMessage {
        id: Uuid::new_v4(),
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
        let parent_session_id = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.session_id(),
            _ => {
                self.ensure_agent_runner();
                match self.agent_runner.as_ref() {
                    Some(Ok(runner)) => runner.session_id(),
                    _ => {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/btw: no daemon connection".to_string(),
                        });
                        return;
                    }
                }
            }
        };
        let attached_request_tx = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.attached_request_tx.clone(),
            _ => unreachable!("runner checked above"),
        };

        let plan = plan_btw_rpcs(&command, existing_mode);
        let mut created_info = None;
        for rpc in plan {
            let request = match rpc {
                BtwRpcPlan::End => Request::EndBtwFork { parent_session_id },
                BtwRpcPlan::Create { mode } => Request::CreateBtwFork {
                    parent_session_id,
                    tangent: mode.tangent(),
                },
            };
            match agent_runner::attached_request_tx_blocking(attached_request_tx.clone(), request) {
                Ok(Response::Ack) => {
                    self.close_btw_pane();
                }
                Ok(Response::BtwFork { info, .. }) => {
                    created_info = Some(info);
                }
                Ok(other) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("/btw: unexpected daemon response: {other:?}"),
                    });
                    return;
                }
                Err(error) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("/btw: {error}"),
                    });
                    return;
                }
            }
        }

        if let Some(info) = created_info {
            self.open_btw_pane_from_info(info, true);
        } else if matches!(command, BtwCommand::End) {
            self.close_btw_pane();
            return;
        } else if self.btw_pane.is_none() {
            self.history.push(HistoryEntry::CommandError {
                line: "/btw: no live fork".to_string(),
            });
            return;
        }

        let question = match command {
            BtwCommand::Open { question } | BtwCommand::New { question } => question,
            BtwCommand::Tangent { question } => Some(question),
            BtwCommand::End | BtwCommand::NotYetAvailable(_) => None,
        };
        if let Some(pane) = self.btw_pane.as_mut() {
            pane.focused = true;
            if let Some(question) = question
                && let Err(error) = pane.send_text(question.clone())
            {
                pane.queue.push(optimistic_queue_item(question));
                pane.history.push(HistoryEntry::InferenceError {
                    summary: error.clone(),
                    detail: error,
                    expanded: false,
                });
            }
        }
    }

    pub(super) fn open_btw_pane_from_info(&mut self, info: proto::BtwForkInfo, attach: bool) {
        let mut pane = BtwPane::new(info, self.composer.vim_enabled());
        if attach {
            pane.attach_runner(&self.launch.cwd, self.no_sandbox, self.lifecycle_mode());
        }
        pane.focused = false;
        self.btw_pane = Some(pane);
    }

    pub(super) fn close_btw_pane(&mut self) {
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
            cockpit_core::daemon::proto::InterruptRaiseReason::Initial => self.dialog_lockout(),
            cockpit_core::daemon::proto::InterruptRaiseReason::Advance => {
                crate::tui::dialog::DialogState::NO_LOCKOUT
            }
            cockpit_core::daemon::proto::InterruptRaiseReason::Rehydration => {
                self.fresh_dialog_lockout()
            }
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
    use cockpit_core::daemon::proto::{
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
                reasoning: String::new(),
                seq: Some(1),
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
        pane.apply_event(
            TurnEvent::ThinkingStarted {
                agent: "Btw".to_string(),
                turn_id: Some("side".to_string()),
            },
            true,
        );
        pane.apply_event(
            TurnEvent::AssistantTextDelta {
                agent: "Btw".to_string(),
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
    fn dialog_ux_lockout_only_first_of_chain_btw_path() {
        for (reason, expected_locked) in [
            (InterruptRaiseReason::Initial, true),
            (InterruptRaiseReason::Advance, false),
            (InterruptRaiseReason::Rehydration, true),
        ] {
            let side = info(false);
            let mut app = App::new(None, false);
            app.open_btw_pane_from_info(side.clone(), false);
            app.composer_active_since_dialog = true;

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
        let item = optimistic_queue_item("queued".to_string());
        let id = item.id;
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
}
