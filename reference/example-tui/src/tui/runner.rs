//! The time-driven side of the simulated chat: how a scripted [`Turn`] plays
//! out over wall-clock ticks, and how queued messages get to cut in.
//!
//! A [`Run`] walks its steps one at a time. Prose and reasoning stream in at a
//! reading pace; waits stand in for tool calls. The gaps *between* steps are
//! the boundaries where a `Boundary`-level queued message may cut in, while an
//! `Interrupt`-level message stops the run mid-step. When a turn ends — on its
//! own terms or because it was cut short — any queued messages that are now due
//! are delivered as the next turn, so the transcript keeps flowing without the
//! user having to resend.

use std::time::{Duration, Instant};

use super::model::{
    Effort, FileDiff, Message, ModelInfo, QueueMode, Segment, Session, Status, Step, Turn,
    TurnStats, estimate_prompt_tokens, model_by_display, peak_mode, take_due, token_count,
};
use super::scenario::fallback_turn;

/// Characters per second for streamed prose, before the effort pace is applied.
const PROSE_CPS: f64 = 220.0;
/// Reasoning streams a touch faster than prose, matching the web console.
const REASON_CPS: f64 = 340.0;

/// A turn in flight against one session's pending agent message.
#[derive(Debug)]
pub struct Run {
    /// Index into `session.messages` of the agent message being produced.
    agent_idx: usize,
    steps: Vec<Step>,
    step: usize,
    /// Fixed at turn start from the sending effort.
    pace: f64,
    follow_ups: Vec<String>,
    /// Set once the run reaches an [`Step::AwaitUser`].
    await_user: bool,
    /// Whether the current step's transient state has been initialised.
    step_entered: bool,
    /// Deadline for the current [`Step::Wait`].
    wait_until: Option<Instant>,
    /// When the current streaming step began revealing text.
    step_start: Option<Instant>,
    /// Index into the agent message's segments of the streaming segment.
    seg_idx: usize,
    /// The interactive child ran `done` this turn.
    complete_interactive: bool,
    done_summary: String,
}

impl Run {
    fn advance(&mut self) {
        self.step += 1;
        self.step_entered = false;
        self.wait_until = None;
        self.step_start = None;
    }
}

/// The outcome of nudging the current step forward by one tick.
enum Advance {
    /// Still working this step; nothing to do until more time passes.
    Pending,
    /// The step completed; we're now sitting on a step boundary.
    Boundary,
    /// The whole turn is complete.
    Finished,
}

impl Session {
    /// Deliver `texts` as user messages and start the scripted turn that
    /// answers them. The view is pinned to the tail so the new turn is in view.
    pub fn start_turn(
        &mut self,
        texts: Vec<String>,
        effort: Effort,
        now: Instant,
        model: ModelInfo,
    ) {
        let first_message = self.focused_messages().is_empty();
        for (i, text) in texts.iter().enumerate() {
            if first_message && i == 0 && self.focus.is_empty() {
                self.title = derive_title(text);
            }
            self.subtitle = subtitle(text);
            self.focused_messages_mut()
                .push(Message::user(text.clone()));
        }

        let chosen = self
            .focused_model()
            .and_then(model_by_display)
            .unwrap_or(model);
        let (cached, input) = estimate_prompt_tokens(self.focused_messages());
        let agent_idx = self.focused_messages().len();
        let mut pending = Message::pending_agent();
        pending.stats = Some(TurnStats::live(chosen, cached, input, now));
        self.focused_messages_mut().push(pending);

        let turn = self.pop_next_turn();
        let steps: Vec<Step> = turn
            .steps
            .into_iter()
            .filter(|step| effort.shows_reasoning() || !matches!(step, Step::Think(_)))
            .collect();

        self.suggestions.clear();
        self.touch();
        self.pinned = true;
        self.run = Some(Run {
            agent_idx,
            steps,
            step: 0,
            pace: effort.pace(),
            follow_ups: turn.follow_ups.iter().map(|s| s.to_string()).collect(),
            await_user: false,
            step_entered: false,
            wait_until: None,
            step_start: now.into(),
            seg_idx: 0,
            complete_interactive: false,
            done_summary: String::new(),
        });
    }

    fn pop_next_turn(&mut self) -> Turn {
        if self.focus.is_empty() {
            self.script.pop_front()
        } else {
            let path = self.focus.clone();
            self.node_at_mut(&path)
                .and_then(|node| node.script.pop_front())
        }
        .unwrap_or_else(fallback_turn)
    }

    /// Advance the active run by one frame at `now`, honouring the queue, then
    /// deliver any background reports that became due.
    pub fn tick(&mut self, now: Instant, effort: Effort, model: ModelInfo) {
        if let Some(mut run) = self.run.take() {
            // An interrupt cuts in as soon as it's noticed, mid-step.
            if peak_mode(&self.queue) == Some(QueueMode::Interrupt) {
                self.finish(run, true);
                self.deliver(QueueMode::Interrupt, now, effort, model);
            } else {
                // Make as much step progress as this frame allows, stopping
                // at boundaries to let boundary-level messages cut in.
                loop {
                    match self.step_progress(&mut run, now) {
                        Advance::Pending => {
                            self.run = Some(run);
                            break;
                        }
                        Advance::Boundary => match peak_mode(&self.queue) {
                            Some(level) if level >= QueueMode::Boundary => {
                                self.finish(run, true);
                                self.deliver(level, now, effort, model);
                                break;
                            }
                            _ => continue,
                        },
                        Advance::Finished => {
                            self.finish(run, false);
                            if !self.queue.is_empty() {
                                self.deliver(QueueMode::Turn, now, effort, model);
                            }
                            break;
                        }
                    }
                }
            }
        }
        self.deliver_due_reports(now);
    }

    /// Push the current step of `run` forward by whatever `now` allows.
    fn step_progress(&mut self, run: &mut Run, now: Instant) -> Advance {
        let Some(&step) = run.steps.get(run.step) else {
            return Advance::Finished;
        };

        match step {
            Step::Wait(ms) => {
                let scaled = (ms as f64 * run.pace) as u64;
                let until = *run
                    .wait_until
                    .get_or_insert_with(|| now + Duration::from_millis(scaled));
                if now >= until {
                    run.advance();
                    Advance::Boundary
                } else {
                    Advance::Pending
                }
            }
            Step::Write { path, body } => {
                self.focused_messages_mut()[run.agent_idx]
                    .segments
                    .push(Segment::Diff(FileDiff::write(path, body)));
                run.advance();
                Advance::Boundary
            }
            Step::Edit { path, hunk } => {
                self.focused_messages_mut()[run.agent_idx]
                    .segments
                    .push(Segment::Diff(FileDiff::edit(path, hunk)));
                run.advance();
                Advance::Boundary
            }
            Step::AwaitUser => {
                run.await_user = true;
                run.step = run.steps.len();
                Advance::Finished
            }
            Step::Tool { name, hint } => {
                self.focused_messages_mut()[run.agent_idx]
                    .segments
                    .push(Segment::Tool {
                        name: name.to_string(),
                        hint: hint.to_string(),
                    });
                run.advance();
                Advance::Boundary
            }
            Step::Done { summary } => {
                self.focused_messages_mut()[run.agent_idx]
                    .segments
                    .push(Segment::Tool {
                        name: "done".into(),
                        hint: summary.to_string(),
                    });
                run.complete_interactive = true;
                run.done_summary = summary.to_string();
                run.step = run.steps.len();
                Advance::Finished
            }
            Step::Think(text) | Step::Say(text) => {
                let reasoning = matches!(step, Step::Think(_));
                if !run.step_entered {
                    run.step_entered = true;
                    run.step_start = Some(now);
                    let segment = if reasoning {
                        Segment::Reasoning(String::new())
                    } else {
                        Segment::Prose(String::new())
                    };
                    let message = &mut self.focused_messages_mut()[run.agent_idx];
                    message.segments.push(segment);
                    run.seg_idx = message.segments.len() - 1;
                }

                let cps = if reasoning { REASON_CPS } else { PROSE_CPS } / run.pace;
                let start = run.step_start.unwrap_or(now);
                let elapsed = now.saturating_duration_since(start).as_millis() as f64;
                let total = text.chars().count();
                let show = ((elapsed * cps / 1000.0) as usize).min(total);

                let message = &mut self.focused_messages_mut()[run.agent_idx];
                if let Some(segment) = message.segments.get_mut(run.seg_idx) {
                    let revealed: String = text.chars().take(show).collect();
                    match segment {
                        Segment::Reasoning(buf) | Segment::Prose(buf) => *buf = revealed,
                        // The streaming segment is only ever text; a diff is
                        // pushed as its own settled segment.
                        Segment::Diff(_)
                        | Segment::Subagent { .. }
                        | Segment::Tool { .. }
                        | Segment::Injection { .. }
                        | Segment::Compaction { .. } => {}
                    }
                }
                let tokens = completion_tokens(message);
                if let Some(stats) = &mut message.stats {
                    stats.observe(now, tokens);
                }

                if show >= total {
                    run.advance();
                    Advance::Boundary
                } else {
                    Advance::Pending
                }
            }
        }
    }

    /// Settle the pending agent message and set the resting status. An
    /// interrupted turn keeps no follow-ups and is marked stopped.
    fn finish(&mut self, run: Run, interrupted: bool) {
        let message = &mut self.focused_messages_mut()[run.agent_idx];
        message.streaming = false;
        message.interrupted = interrupted;

        if !interrupted && run.complete_interactive {
            let summary = run.done_summary;
            // The `done` turn's follow-ups become the parent's next chips so
            // the handoff is obvious instead of a blank composer.
            let follow_ups = run.follow_ups;
            self.complete_interactive(&summary);
            self.suggestions = follow_ups;
            return;
        }

        if self.focus.is_empty() {
            self.resting = if run.await_user {
                Status::Waiting
            } else {
                Status::Done
            };
        } else if let Some(node) = self.node_at_mut(&self.focus.clone()) {
            node.status = if run.await_user {
                Status::Waiting
            } else {
                Status::Working
            };
            self.resting = Status::Working;
        }
        self.suggestions = if interrupted {
            Vec::new()
        } else {
            run.follow_ups
        };
    }

    /// Release the messages due at `level` and start the turn that answers
    /// them. A no-op when nothing is due.
    fn deliver(&mut self, level: QueueMode, now: Instant, effort: Effort, model: ModelInfo) {
        let due = take_due(&mut self.queue, level);
        if due.is_empty() {
            return;
        }
        let texts = due.into_iter().map(|item| item.text).collect();
        self.start_turn(texts, effort, now, model);
    }
}

/// A session title from its first message: cleaned up and capped.
fn derive_title(text: &str) -> String {
    let clean = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars: Vec<char> = clean.chars().collect();
    if chars.len() > 38 {
        chars.truncate(36);
        chars.push('…');
    }
    let mut title: String = chars.into_iter().collect();
    if let Some(first) = title.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    if title.is_empty() {
        "New session".to_string()
    } else {
        title
    }
}

fn completion_tokens(message: &Message) -> u64 {
    message
        .segments
        .iter()
        .map(|segment| match segment {
            Segment::Reasoning(text) | Segment::Prose(text) => token_count(text),
            _ => 0,
        })
        .sum()
}

/// The one-line subtitle shown under a session in the sidebar.
fn subtitle(text: &str) -> String {
    let clean = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = clean.chars().collect();
    if chars.len() > 60 {
        let mut cut: String = chars.into_iter().take(57).collect();
        cut.push('…');
        cut
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::model::{MODELS, QueueMode, QueuedMessage, Role, Turn};
    use std::collections::VecDeque;
    use std::time::Duration;

    fn session_with(turns: Vec<Turn>) -> Session {
        Session {
            title: "test".into(),
            subtitle: String::new(),
            repo: "acme/demo".into(),
            messages: Vec::new(),
            script: VecDeque::from(turns),
            suggestions: Vec::new(),
            queue: Vec::new(),
            run: None,
            resting: Status::Idle,
            scroll: 0,
            pinned: true,
            last_active: std::time::SystemTime::now(),
            archived: false,
            starred: false,
            show_thinking: false,
            focus: Vec::new(),
            subagents: Vec::new(),
            tools: Vec::new(),
            skills: Vec::new(),
            tasks: Vec::new(),
            timers: Vec::new(),
        }
    }

    fn queued(tag: u32, mode: QueueMode) -> QueuedMessage {
        QueuedMessage {
            text: format!("q{tag}"),
            mode,
        }
    }

    /// Drive the clock forward far enough to fully play a turn out.
    fn run_to_rest(session: &mut Session, effort: Effort, start: Instant) {
        let mut now = start;
        for _ in 0..2000 {
            if session.run.is_none() {
                break;
            }
            now += Duration::from_millis(50);
            session.tick(now, effort, MODELS[0]);
        }
    }

    #[test]
    fn a_turn_streams_then_settles_done() {
        let start = Instant::now();
        let mut session = session_with(vec![Turn {
            steps: vec![Step::Say("hello there")],
            follow_ups: vec!["next"],
        }]);
        session.start_turn(vec!["hi".into()], Effort::Medium, start, MODELS[0]);
        assert_eq!(session.status(), Status::Working);
        run_to_rest(&mut session, Effort::Medium, start);
        assert_eq!(session.status(), Status::Done);
        let agent = session.messages.last().unwrap();
        assert_eq!(agent.role, Role::Agent);
        assert_eq!(agent.plain(), "hello there");
        assert_eq!(session.suggestions, vec!["next".to_string()]);
    }

    #[test]
    fn low_effort_strips_the_reasoning_step() {
        let start = Instant::now();
        let mut session = session_with(vec![Turn {
            steps: vec![Step::Think("pondering"), Step::Say("answer")],
            follow_ups: vec![],
        }]);
        session.start_turn(vec!["go".into()], Effort::Low, start, MODELS[0]);
        run_to_rest(&mut session, Effort::Low, start);
        let agent = session.messages.last().unwrap();
        assert_eq!(agent.segments.len(), 1);
        assert!(matches!(agent.segments[0], Segment::Prose(_)));
    }

    #[test]
    fn await_user_leaves_the_session_waiting() {
        let start = Instant::now();
        let mut session = session_with(vec![Turn {
            steps: vec![Step::Say("need a decision"), Step::AwaitUser],
            follow_ups: vec![],
        }]);
        session.start_turn(vec!["?".into()], Effort::Medium, start, MODELS[0]);
        run_to_rest(&mut session, Effort::Medium, start);
        assert_eq!(session.status(), Status::Waiting);
    }

    #[test]
    fn an_interrupt_cuts_the_turn_short_and_delivers_now() {
        let start = Instant::now();
        let mut session = session_with(vec![
            Turn {
                steps: vec![Step::Wait(10_000), Step::Say("slow answer")],
                follow_ups: vec![],
            },
            Turn {
                steps: vec![Step::Say("cut-in reply")],
                follow_ups: vec![],
            },
        ]);
        session.start_turn(vec!["start".into()], Effort::Medium, start, MODELS[0]);
        session.queue.push(queued(1, QueueMode::Interrupt));

        // One tick notices the interrupt, cuts the first turn, and starts the
        // second against the queued message.
        session.tick(start + Duration::from_millis(50), Effort::Medium, MODELS[0]);
        assert!(session.queue.is_empty());
        let interrupted = session
            .messages
            .iter()
            .find(|m| m.role == Role::Agent && m.interrupted);
        assert!(interrupted.is_some(), "the first turn is marked stopped");
        assert!(
            session
                .messages
                .iter()
                .any(|m| m.role == Role::User && m.plain() == "q1"),
            "the queued message was delivered as a user turn"
        );
    }

    #[test]
    fn write_and_edit_steps_emit_diff_segments() {
        use crate::tui::model::{DiffKind, DiffLine, Hunk, Segment};

        let start = Instant::now();
        let mut session = session_with(vec![Turn {
            steps: vec![
                Step::Write {
                    path: "src/new.ts",
                    body: &["export const x = 1;", "export const y = 2;"],
                },
                Step::Edit {
                    path: "src/old.ts",
                    hunk: &[
                        Hunk::Context("keep"),
                        Hunk::Removed("gone"),
                        Hunk::Added("new"),
                    ],
                },
            ],
            follow_ups: vec![],
        }]);
        session.start_turn(vec!["do it".into()], Effort::Medium, start, MODELS[0]);
        run_to_rest(&mut session, Effort::Medium, start);

        let agent = session.messages.last().unwrap();
        let diffs: Vec<&FileDiff> = agent
            .segments
            .iter()
            .filter_map(|s| match s {
                Segment::Diff(d) => Some(d),
                _ => None,
            })
            .collect();
        assert_eq!(diffs.len(), 2);

        // The write is all additions.
        assert_eq!(diffs[0].kind, DiffKind::Write);
        assert_eq!(diffs[0].counts(), (2, 0));
        assert!(
            diffs[0]
                .lines
                .iter()
                .all(|l| matches!(l, DiffLine::Added(_)))
        );

        // The edit interleaves context, a removal, and an addition.
        assert_eq!(diffs[1].kind, DiffKind::Edit);
        assert_eq!(diffs[1].counts(), (1, 1));
    }

    #[test]
    fn a_turn_level_message_waits_for_the_turn_to_finish() {
        let start = Instant::now();
        let mut session = session_with(vec![
            Turn {
                steps: vec![Step::Say("first")],
                follow_ups: vec![],
            },
            Turn {
                steps: vec![Step::Say("second")],
                follow_ups: vec![],
            },
        ]);
        session.start_turn(vec!["a".into()], Effort::Medium, start, MODELS[0]);
        session.queue.push(queued(1, QueueMode::Turn));
        run_to_rest(&mut session, Effort::Medium, start);

        // The turn-level message never cut the first turn short — no agent
        // message is marked interrupted — and it was delivered afterwards.
        assert!(session.messages.iter().all(|m| !m.interrupted));
        assert!(
            session
                .messages
                .iter()
                .any(|m| m.role == Role::User && m.plain() == "q1")
        );
    }

    #[test]
    fn a_turn_records_ttft_tps_and_cache() {
        let start = Instant::now();
        let mut session = session_with(vec![Turn {
            steps: vec![Step::Say("hello there friend")],
            follow_ups: vec![],
        }]);
        session.start_turn(vec!["hi".into()], Effort::Medium, start, MODELS[0]);
        let stats = session.messages.last().unwrap().stats.as_ref().unwrap();
        assert_eq!(stats.provider, "OpenAI");
        assert_eq!(stats.model, "GPT-5 Codex");
        assert!(stats.input_tokens > 0);
        assert!(stats.cached_tokens <= stats.input_tokens);
        assert!(stats.ttft.is_none());

        session.tick(start + Duration::from_millis(40), Effort::Medium, MODELS[0]);
        session.tick(
            start + Duration::from_millis(120),
            Effort::Medium,
            MODELS[0],
        );
        let mid = session.messages.last().unwrap().stats.as_ref().unwrap();
        assert!(mid.ttft.is_some(), "the first token has landed");

        run_to_rest(&mut session, Effort::Medium, start);
        let done = session.messages.last().unwrap().stats.as_ref().unwrap();
        assert!(done.tps.unwrap() > 0.0);
        assert_eq!(done.cache_pct(), Some(67));
    }
}
