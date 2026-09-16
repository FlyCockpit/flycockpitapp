//! The simulated chat's domain model: sessions, messages, the model catalog,
//! reasoning effort, session status, and the message queue.
//!
//! Everything here is deliberately small and pure. The time-driven behaviour
//! (streaming, step boundaries, queue delivery) lives in [`super::runner`];
//! this module only holds the data those routines read and mutate, plus the
//! queue arithmetic that has nothing to do with the clock.

use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime};

use ratatui::style::Color;

use super::palette;
use super::runner::Run;

/* --------------------------------- effort --------------------------------- */

/// How hard the model is asked to think. Higher effort visibly takes longer
/// and shows a reasoning pass; the lowest answers directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effort {
    Low,
    Medium,
    High,
}

impl Effort {
    pub const ORDER: [Effort; 3] = [Effort::Low, Effort::Medium, Effort::High];

    pub fn label(self) -> &'static str {
        match self {
            Effort::Low => "Fast",
            Effort::Medium => "Balanced",
            Effort::High => "Thorough",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Effort::Low => "Answers directly, skips the reasoning pass",
            Effort::Medium => "Reasons briefly before acting",
            Effort::High => "Thinks longer and explains its plan",
        }
    }

    /// Multiplies step delays and slows streaming, so effort is felt as pace.
    pub fn pace(self) -> f64 {
        match self {
            Effort::Low => 0.45,
            Effort::Medium => 1.0,
            Effort::High => 1.7,
        }
    }

    /// Low effort answers directly, so its reasoning steps are stripped.
    pub fn shows_reasoning(self) -> bool {
        !matches!(self, Effort::Low)
    }
}

/* ---------------------------------- models -------------------------------- */

/// One entry in the model picker.
#[derive(Debug, Clone, Copy)]
pub struct ModelInfo {
    pub display: &'static str,
    pub provider: &'static str,
}

/// The catalog offered in the composer's model picker. Purely cosmetic here —
/// the simulated responses don't change with the choice — but it exercises the
/// same selection UX the product needs.
pub const MODELS: &[ModelInfo] = &[
    ModelInfo {
        display: "GPT-5 Codex",
        provider: "OpenAI",
    },
    ModelInfo {
        display: "Claude Sonnet 4.5",
        provider: "Anthropic",
    },
    ModelInfo {
        display: "Claude Opus 4.1",
        provider: "Anthropic",
    },
    ModelInfo {
        display: "Grok Code",
        provider: "xAI",
    },
    ModelInfo {
        display: "Gemini 2.5 Pro",
        provider: "Google",
    },
    ModelInfo {
        display: "Qwen3 Coder",
        provider: "local",
    },
];

/// The distinct providers in catalog order (first appearance wins), for the
/// picker's first level.
pub fn providers() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for model in MODELS {
        if !out.contains(&model.provider) {
            out.push(model.provider);
        }
    }
    out
}

/// One named agent the composer can run as.
#[derive(Debug, Clone, Copy)]
pub struct AgentInfo {
    pub name: &'static str,
    pub hint: &'static str,
}

/// Demo agents — cosmetic here, same picker UX the product needs.
pub const AGENTS: &[AgentInfo] = &[
    AgentInfo {
        name: "Cockpit",
        hint: "General assistant for this workspace",
    },
    AgentInfo {
        name: "Explorer",
        hint: "Reads widely, changes little",
    },
    AgentInfo {
        name: "Reviewer",
        hint: "Critiques diffs and plans",
    },
    AgentInfo {
        name: "Planner",
        hint: "Breaks work into steps",
    },
];

/// Where the agent is allowed to run tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sandbox {
    On,
    Off,
    Container,
}

impl Sandbox {
    pub const ORDER: [Sandbox; 3] = [Sandbox::On, Sandbox::Off, Sandbox::Container];

    pub fn label(self) -> &'static str {
        match self {
            Sandbox::On => "on",
            Sandbox::Off => "off",
            Sandbox::Container => "container",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Sandbox::On => "Filesystem and network are sandboxed",
            Sandbox::Off => "The agent runs with host permissions",
            Sandbox::Container => "Tools run inside an isolated container",
        }
    }
}

/// How tool calls are approved. Independent of [`Sandbox`]: yolo skips
/// confirmations, it does not unsandbox the process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permissions {
    Yolo,
    Auto,
    Ask,
}

impl Permissions {
    pub const ORDER: [Permissions; 3] = [Permissions::Yolo, Permissions::Auto, Permissions::Ask];

    pub fn label(self) -> &'static str {
        match self {
            Permissions::Yolo => "yolo",
            Permissions::Auto => "auto",
            Permissions::Ask => "ask",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Permissions::Yolo => "Skip every confirmation, including destructive ones",
            Permissions::Auto => "Approve routine tool calls; ask for the rest",
            Permissions::Ask => "Ask before any tool call",
        }
    }
}

/// How a tool is granted to the agent. Enabled tools sit in the prompt (so
/// flipping to or from that state busts the cache); discoverable and disabled
/// do not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolTier {
    Enabled,
    Discoverable,
    Disabled,
}

impl ToolTier {
    pub fn label(self) -> &'static str {
        match self {
            ToolTier::Enabled => "enabled",
            ToolTier::Discoverable => "discoverable",
            ToolTier::Disabled => "disabled",
        }
    }

    pub fn cycle(self) -> Self {
        match self {
            ToolTier::Enabled => ToolTier::Discoverable,
            ToolTier::Discoverable => ToolTier::Disabled,
            ToolTier::Disabled => ToolTier::Enabled,
        }
    }

    /// Prompt-cache bust: the schema is in the prompt only while enabled.
    pub fn breaks_cache(from: Self, to: Self) -> bool {
        matches!(from, ToolTier::Enabled) != matches!(to, ToolTier::Enabled)
    }
}

/// A tool offered at one agent layer (root or a focused subagent).
#[derive(Debug, Clone)]
pub struct ToolInfo {
    pub name: String,
    pub hint: String,
    pub tier: ToolTier,
}

/// A skill offered at one agent layer.
#[derive(Debug, Clone)]
pub struct SkillInfo {
    pub name: String,
    pub hint: String,
}

/// A background command running under the current agent layer.
#[derive(Debug, Clone)]
pub struct TaskInfo {
    pub name: String,
    pub status: Status,
}

/// A scheduled timer or loop under the current agent layer.
#[derive(Debug, Clone)]
pub struct TimerInfo {
    pub name: String,
    pub remaining: String,
}

/// One delegated agent. Interactive nodes take over the composer until they
/// run `done`; background nodes stay inlined and report back.
#[derive(Debug, Clone)]
pub struct AgentNode {
    pub name: String,
    pub interactive: bool,
    pub status: Status,
    pub messages: Vec<Message>,
    pub children: Vec<AgentNode>,
    pub tools: Vec<ToolInfo>,
    pub skills: Vec<SkillInfo>,
    pub tasks: Vec<TaskInfo>,
    pub timers: Vec<TimerInfo>,
    /// Scripted turns played while this node holds the foreground.
    pub script: VecDeque<Turn>,
    /// Optional model label for the takeover chrome; `None` uses the session's.
    pub model: Option<String>,
    /// Result a background node will emit at [`AgentNode::ready_at`].
    pub report: Option<String>,
    pub ready_at: Option<Instant>,
}

impl AgentNode {
    pub fn new(name: &str, interactive: bool, status: Status) -> Self {
        Self {
            name: name.to_string(),
            interactive,
            status,
            messages: Vec::new(),
            children: Vec::new(),
            tools: Vec::new(),
            skills: Vec::new(),
            tasks: Vec::new(),
            timers: Vec::new(),
            script: VecDeque::new(),
            model: None,
            report: None,
            ready_at: None,
        }
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
}

/// The global [`MODELS`] indices offered by `provider`, in catalog order, for
/// the picker's second level.
/// Look up a catalog entry by the name shown in the composer pill.
pub fn model_by_display(name: &str) -> Option<ModelInfo> {
    MODELS.iter().copied().find(|model| model.display == name)
}

pub fn models_for(provider: &str) -> Vec<usize> {
    MODELS
        .iter()
        .enumerate()
        .filter(|(_, model)| model.provider == provider)
        .map(|(index, _)| index)
        .collect()
}

/* ---------------------------------- queue --------------------------------- */

/// How urgently a queued message wants to land. Each press of Enter on an empty
/// composer escalates the whole queue one step. Variant order is the escalation
/// order, so the derived `Ord` is the urgency ranking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum QueueMode {
    /// Sends when the current turn finishes.
    Turn,
    /// Cuts in at the next step boundary.
    Boundary,
    /// Stops the agent and sends now.
    Interrupt,
}

impl QueueMode {
    pub const ORDER: [QueueMode; 3] = [QueueMode::Turn, QueueMode::Boundary, QueueMode::Interrupt];

    pub fn label(self) -> &'static str {
        match self {
            QueueMode::Turn => "Queued",
            QueueMode::Boundary => "Cutting in",
            QueueMode::Interrupt => "Interrupting",
        }
    }

    pub fn detail(self) -> &'static str {
        match self {
            QueueMode::Turn => "Sends when this turn finishes",
            QueueMode::Boundary => "Sends at the next step boundary",
            QueueMode::Interrupt => "Stops the agent and sends now",
        }
    }

    /// Bracketed chip drawn in the per-message schedule control.
    pub fn chip(self) -> &'static str {
        match self {
            QueueMode::Turn => "[Queued]",
            QueueMode::Boundary => "[Boundary]",
            QueueMode::Interrupt => "[Interrupt]",
        }
    }

    pub fn color(self) -> Color {
        match self {
            QueueMode::Turn => palette::FOG,
            QueueMode::Boundary => palette::YELLOW,
            QueueMode::Interrupt => palette::RED,
        }
    }

    /// What Enter promises next, shown under the queue.
    pub fn next_hint(self) -> &'static str {
        match self {
            QueueMode::Turn => "Enter again to cut in at the next step",
            QueueMode::Boundary => "Enter again to stop the agent and send now",
            QueueMode::Interrupt => "",
        }
    }

    /// One rung up the urgency ladder; interrupt is the top.
    pub fn escalated(self) -> QueueMode {
        match self {
            QueueMode::Turn => QueueMode::Boundary,
            QueueMode::Boundary | QueueMode::Interrupt => QueueMode::Interrupt,
        }
    }
}

/// A message typed while the agent was busy, waiting for its release point.
#[derive(Debug, Clone)]
pub struct QueuedMessage {
    pub text: String,
    pub mode: QueueMode,
}

/// The most urgent mode in a queue, or `None` when nothing is waiting.
pub fn peak_mode(items: &[QueuedMessage]) -> Option<QueueMode> {
    items.iter().map(|item| item.mode).max()
}

/// Escalate every queued message one rung and report the new level. Escalation
/// is a property of the batch, so it levels everything up together rather than
/// widening the gap between messages. Returns `None` for an empty queue.
pub fn escalate(items: &mut [QueuedMessage]) -> Option<QueueMode> {
    let top = peak_mode(items)?;
    let next = top.escalated();
    for item in items.iter_mut() {
        item.mode = next;
    }
    Some(next)
}

/// Remove and return every message at or above `level`, leaving the politer
/// ones in the queue. Cutting in early only carries the messages that asked to.
pub fn take_due(items: &mut Vec<QueuedMessage>, level: QueueMode) -> Vec<QueuedMessage> {
    let mut due = Vec::new();
    let mut rest = Vec::new();
    for item in items.drain(..) {
        if item.mode >= level {
            due.push(item);
        } else {
            rest.push(item);
        }
    }
    *items = rest;
    due
}

/* --------------------------------- status --------------------------------- */

/// What a session is doing right now, surfaced as a coloured dot in the
/// sidebar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// No messages yet.
    Idle,
    /// A turn is in flight.
    Working,
    /// The run is parked on your answer.
    Waiting,
    /// Finished on its own terms.
    Done,
}

impl Status {
    pub fn short(self) -> &'static str {
        match self {
            Status::Idle => "Idle",
            Status::Working => "Working",
            Status::Waiting => "Waiting",
            Status::Done => "Done",
        }
    }

    pub fn dot(self) -> Color {
        match self {
            Status::Idle => palette::DISABLED,
            Status::Working => palette::YELLOW,
            Status::Waiting => palette::RED,
            Status::Done => palette::GREEN,
        }
    }

    /// Working and waiting pulse in the sidebar; the resting states don't.
    pub fn pulses(self) -> bool {
        matches!(self, Status::Working | Status::Waiting)
    }

    /// Still in flight — the subagent picker lists only these.
    pub fn is_active(self) -> bool {
        matches!(self, Status::Working | Status::Waiting)
    }
}

/* -------------------------------- messages -------------------------------- */

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Agent,
    /// A local note from a slash command (e.g. `/compact`), rendered as a dim
    /// centered divider rather than a chat bubble.
    System,
}

/// One run of the agent's output. Reasoning renders dim; prose renders as the
/// answer; a diff renders as a framed file change. Splitting them lets low
/// effort drop the reasoning entirely and lets prose and reasoning stream at
/// different speeds, while a diff lands atomically like a completed tool call.
#[derive(Debug, Clone)]
pub enum Segment {
    Reasoning(String),
    Prose(String),
    Diff(FileDiff),
    /// An inlined subagent card in the parent transcript. Interactive nodes
    /// use a teal gutter; background nodes use a dimmer one.
    Subagent {
        name: String,
        interactive: bool,
        summary: String,
        path: Vec<usize>,
    },
    /// A settled tool call (including `done`).
    Tool {
        name: String,
        hint: String,
    },
    /// A background result injected into the main agent after the interactive
    /// subagent that spawned it has already handed back.
    Injection {
        from: String,
        body: String,
    },
    /// A context-compaction boundary. The notice is always shown; the summary
    /// expands behind a `[show summary]` chip.
    Compaction {
        notice: String,
        summary: String,
    },
}

impl Segment {
    /// The streamable text of a segment. A diff has no streamed text (it lands
    /// whole), so it reports empty.
    pub fn text(&self) -> &str {
        match self {
            Segment::Reasoning(text)
            | Segment::Prose(text)
            | Segment::Injection { body: text, .. }
            | Segment::Compaction { notice: text, .. } => text,
            Segment::Diff(_) | Segment::Subagent { .. } | Segment::Tool { .. } => "",
        }
    }
}

/* ---------------------------------- diffs --------------------------------- */

/// Whether a file change created a new file or edited an existing one. A write
/// renders as all-additions; an edit interleaves context with additions and
/// removals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiffKind {
    Write,
    Edit,
}

/// One line of a rendered diff.
#[derive(Debug, Clone)]
pub enum DiffLine {
    /// Unchanged surrounding context.
    Context(String),
    /// An added line (`+`, green).
    Added(String),
    /// A removed line (`-`, red).
    Removed(String),
}

/// A file change the agent applied, shown in the transcript as a diff. Built
/// from the [`Step::Write`] / [`Step::Edit`] script data or seeded directly.
#[derive(Debug, Clone)]
pub struct FileDiff {
    pub path: String,
    pub kind: DiffKind,
    pub lines: Vec<DiffLine>,
}

impl FileDiff {
    /// A new file: every body line is an addition.
    pub fn write(path: &str, body: &[&str]) -> Self {
        Self {
            path: path.to_string(),
            kind: DiffKind::Write,
            lines: body
                .iter()
                .map(|line| DiffLine::Added((*line).to_string()))
                .collect(),
        }
    }

    /// An edit assembled from a [`Hunk`] script.
    pub fn edit(path: &str, hunk: &[Hunk]) -> Self {
        Self {
            path: path.to_string(),
            kind: DiffKind::Edit,
            lines: hunk
                .iter()
                .map(|h| match h {
                    Hunk::Context(s) => DiffLine::Context((*s).to_string()),
                    Hunk::Added(s) => DiffLine::Added((*s).to_string()),
                    Hunk::Removed(s) => DiffLine::Removed((*s).to_string()),
                })
                .collect(),
        }
    }

    /// The verb shown in the diff header.
    pub fn verb(&self) -> &'static str {
        match self.kind {
            DiffKind::Write => "Created",
            DiffKind::Edit => "Edited",
        }
    }

    /// `(added, removed)` line counts for the header summary.
    pub fn counts(&self) -> (usize, usize) {
        let added = self
            .lines
            .iter()
            .filter(|l| matches!(l, DiffLine::Added(_)))
            .count();
        let removed = self
            .lines
            .iter()
            .filter(|l| matches!(l, DiffLine::Removed(_)))
            .count();
        (added, removed)
    }
}

/// Timing and usage for one agent reply. Clicking the header name reveals it.
#[derive(Debug, Clone)]
pub struct TurnStats {
    pub provider: String,
    pub model: String,
    /// Time from the request to the first streamed token.
    pub ttft: Option<Duration>,
    /// Tokens per second after that first token.
    pub tps: Option<f64>,
    pub cached_tokens: u64,
    pub input_tokens: u64,
    started: Option<Instant>,
    first_token: Option<Instant>,
}

impl TurnStats {
    pub fn settled(
        provider: impl Into<String>,
        model: impl Into<String>,
        ttft: Duration,
        tps: f64,
        cached_tokens: u64,
        input_tokens: u64,
    ) -> Self {
        Self {
            provider: provider.into(),
            model: model.into(),
            ttft: Some(ttft),
            tps: Some(tps),
            cached_tokens: cached_tokens.min(input_tokens),
            input_tokens,
            started: None,
            first_token: None,
        }
    }

    /// Deterministic demo numbers so seeded history looks measured, not random.
    pub fn demo(provider: &'static str, model: &'static str, seed: u64) -> Self {
        let ttft = Duration::from_millis(210 + (seed * 23) % 420);
        let tps = 28.0 + ((seed * 11) % 35) as f64 + (seed % 10) as f64 / 10.0;
        let input = 4_800 + seed * 180;
        let cached = input * (58 + seed % 25) / 100;
        Self::settled(provider, model, ttft, tps, cached, input)
    }

    pub fn live(model: ModelInfo, cached_tokens: u64, input_tokens: u64, started: Instant) -> Self {
        Self {
            provider: model.provider.to_string(),
            model: model.display.to_string(),
            ttft: None,
            tps: None,
            cached_tokens: cached_tokens.min(input_tokens),
            input_tokens,
            started: Some(started),
            first_token: None,
        }
    }

    /// Record newly revealed completion tokens so TTFT and TPS fill in live.
    pub fn observe(&mut self, now: Instant, output_tokens: u64) {
        if output_tokens == 0 {
            return;
        }
        let first = *self.first_token.get_or_insert(now);
        if self.ttft.is_none()
            && let Some(started) = self.started
        {
            self.ttft = Some(now.saturating_duration_since(started));
        }
        if output_tokens > 1 {
            let after = now
                .saturating_duration_since(first)
                .as_secs_f64()
                .max(0.001);
            self.tps = Some((output_tokens - 1) as f64 / after);
        }
    }

    pub fn cache_pct(&self) -> Option<u32> {
        if self.input_tokens == 0 {
            None
        } else {
            Some(((self.cached_tokens as f64 / self.input_tokens as f64) * 100.0).round() as u32)
        }
    }

    pub fn model_text(&self) -> String {
        format!("{} / {}", self.provider, self.model)
    }

    pub fn ttft_text(&self, streaming: bool) -> String {
        match self.ttft {
            Some(duration) => format_ttft(duration),
            None if streaming => "…".into(),
            None => "—".into(),
        }
    }

    pub fn tps_text(&self, streaming: bool) -> String {
        match self.tps {
            Some(tps) => format!("{tps:.1}"),
            None if streaming => "…".into(),
            None => "—".into(),
        }
    }

    pub fn cache_text(&self) -> String {
        let cached = group_thousands(self.cached_tokens);
        let total = group_thousands(self.input_tokens);
        match self.cache_pct() {
            Some(pct) => format!("{cached} / {total} ({pct}%)"),
            None => format!("{cached} / {total} (—)"),
        }
    }
}

fn format_ttft(duration: Duration) -> String {
    let ms = duration.as_millis();
    if ms < 1000 {
        format!("{ms} ms")
    } else {
        format!("{:.2} s", duration.as_secs_f64())
    }
}

fn group_thousands(n: u64) -> String {
    let raw = n.to_string();
    let mut out = String::new();
    for (i, ch) in raw.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out.chars().rev().collect()
}

/// Rough completion-token count: four characters per token.
pub fn token_count(text: &str) -> u64 {
    (text.chars().count() as u64).div_ceil(4)
}

/// Prompt tokens for a live turn: a fixed system-prompt floor plus history.
pub fn estimate_prompt_tokens(messages: &[Message]) -> (u64, u64) {
    let chars: u64 = messages
        .iter()
        .map(|message| message.plain().chars().count() as u64)
        .sum();
    let input = 2_400 + chars.div_ceil(4);
    let cached = input.saturating_mul(2) / 3;
    (cached, input)
}

#[derive(Debug, Clone)]
pub struct Message {
    pub role: Role,
    pub segments: Vec<Segment>,
    /// The run was cut short because a message cut in.
    pub interrupted: bool,
    /// The agent is still producing this message.
    pub streaming: bool,
    /// Wall-clock time the message appeared, shown as an `HH:MM` stamp on user
    /// and agent messages.
    pub at: SystemTime,
    /// The user pinned this message; the header shows `[Unpin]` instead of `[Pin]`.
    pub pinned: bool,
    /// Per-message thinking override. `None` follows [`Session::show_thinking`].
    pub thinking_open: Option<bool>,
    /// Usage for this reply. Agent messages carry one; user/system leave it empty.
    pub stats: Option<TurnStats>,
    /// Whether the header name is expanded to show [`Message::stats`].
    pub stats_open: bool,
    /// Whether a [`Segment::Compaction`] summary is expanded.
    pub summary_open: bool,
}

impl Message {
    pub fn user(text: String) -> Self {
        Self {
            role: Role::User,
            segments: vec![Segment::Prose(text)],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        }
    }

    /// A host-authored injection into the main agent's context after a
    /// background child finishes. Attribution is the `from` name; the
    /// body is the child's report, not model-written.
    pub fn injection(from: impl Into<String>, body: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            segments: vec![Segment::Injection {
                from: from.into(),
                body: body.into(),
            }],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        }
    }

    /// A local system note (slash-command feedback).
    pub fn system(text: String) -> Self {
        Self {
            role: Role::System,
            segments: vec![Segment::Prose(text)],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        }
    }

    /// A compaction boundary with a collapsed, expandable summary.
    pub fn compaction(notice: impl Into<String>, summary: impl Into<String>) -> Self {
        Self {
            role: Role::System,
            segments: vec![Segment::Compaction {
                notice: notice.into(),
                summary: summary.into(),
            }],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        }
    }

    pub fn pending_agent() -> Self {
        Self {
            role: Role::Agent,
            segments: Vec::new(),
            interrupted: false,
            streaming: true,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        }
    }

    pub fn has_thinking(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| matches!(segment, Segment::Reasoning(_)))
    }

    pub fn has_compaction(&self) -> bool {
        self.segments
            .iter()
            .any(|segment| matches!(segment, Segment::Compaction { .. }))
    }

    /// The user message's raw text, for the sticky header and titles.
    pub fn plain(&self) -> String {
        self.segments
            .iter()
            .map(Segment::text)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/* --------------------------------- script --------------------------------- */

/// One line of a scripted [`Step::Edit`] hunk. `'static` so a whole turn stays
/// `Copy` and can live in a `const` script.
#[derive(Debug, Clone, Copy)]
pub enum Hunk {
    Context(&'static str),
    Added(&'static str),
    Removed(&'static str),
}

/// One beat of a scripted turn.
#[derive(Debug, Clone, Copy)]
pub enum Step {
    /// A reasoning trace, streamed and dimmed. Stripped at low effort.
    Think(&'static str),
    /// Agent prose, streamed at reading speed.
    Say(&'static str),
    /// A pause — where the agent would be running a tool.
    Wait(u64),
    /// Write a new file: its body lands as an all-additions diff.
    Write {
        path: &'static str,
        body: &'static [&'static str],
    },
    /// Edit an existing file: the hunk lands as a context/±diff.
    Edit {
        path: &'static str,
        hunk: &'static [Hunk],
    },
    /// End the turn parked on the user (the sidebar dot goes red).
    AwaitUser,
    /// A settled tool call shown in the transcript.
    Tool {
        name: &'static str,
        hint: &'static str,
    },
    /// The interactive subagent's `done` tool: lands the call, then hands
    /// the composer back to the parent.
    Done { summary: &'static str },
}

/// A scripted turn: a sequence of steps plus the suggestion chips to offer once
/// it finishes.
#[derive(Debug, Clone)]
pub struct Turn {
    pub steps: Vec<Step>,
    pub follow_ups: Vec<&'static str>,
}

/* --------------------------------- session -------------------------------- */

#[derive(Debug)]
pub struct Session {
    pub title: String,
    pub subtitle: String,
    pub repo: String,
    pub messages: Vec<Message>,
    /// Remaining scripted turns; one is played per delivered batch.
    pub script: VecDeque<Turn>,
    pub suggestions: Vec<String>,
    pub queue: Vec<QueuedMessage>,
    /// Non-`None` while a turn is in flight.
    pub run: Option<Run>,
    /// The state to show when no run is active.
    pub resting: Status,
    /// Topmost transcript line index in view.
    pub scroll: usize,
    /// Following the tail; new content keeps the view pinned to the bottom.
    pub pinned: bool,
    /// Wall-clock time of the last send, reply, note, or queue change.
    pub last_active: SystemTime,
    /// Hidden from the sidebar until (in a fuller product) an archive list.
    pub archived: bool,
    /// Kept at the top of the sidebar, above unstarred sessions.
    pub starred: bool,
    /// Conversation default for rendering [`Segment::Reasoning`]. `/think`
    /// toggles this and clears per-message overrides.
    pub show_thinking: bool,
    /// Path into [`Session::subagents`] for the agent the composer is talking
    /// to. Empty means the root (main) agent.
    pub focus: Vec<usize>,
    pub subagents: Vec<AgentNode>,
    pub tools: Vec<ToolInfo>,
    pub skills: Vec<SkillInfo>,
    pub tasks: Vec<TaskInfo>,
    pub timers: Vec<TimerInfo>,
}

impl Session {
    pub fn status(&self) -> Status {
        if self.run.is_some() {
            Status::Working
        } else {
            self.resting
        }
    }

    pub fn is_working(&self) -> bool {
        self.run.is_some()
    }

    pub fn touch(&mut self) {
        self.last_active = SystemTime::now();
    }

    /// A new session that copies history through `message_idx` (inclusive) and
    /// keeps the remaining script, so the fork can keep chatting independently.
    /// System notes cannot be forked. The snapshot is settled (not streaming).
    pub fn fork_at(&self, message_idx: usize) -> Option<Session> {
        let source = self.focused_messages().get(message_idx)?;
        if matches!(source.role, Role::System) {
            return None;
        }
        let mut messages: Vec<Message> = self.focused_messages()[..=message_idx].to_vec();
        for message in &mut messages {
            message.streaming = false;
        }
        let last = messages.last()?;
        let plain = last.plain();
        let resting = match last.role {
            Role::Agent if !last.interrupted => Status::Done,
            _ => Status::Idle,
        };
        Some(Session {
            title: fork_title(&plain),
            subtitle: fork_subtitle(&plain),
            repo: self.repo.clone(),
            messages,
            script: self.script.clone(),
            suggestions: Vec::new(),
            queue: Vec::new(),
            run: None,
            resting,
            scroll: 0,
            pinned: true,
            last_active: SystemTime::now(),
            archived: false,
            starred: false,
            show_thinking: self.show_thinking,
            focus: Vec::new(),
            subagents: self.subagents.clone(),
            tools: self.tools.clone(),
            skills: self.skills.clone(),
            tasks: Vec::new(),
            timers: Vec::new(),
        })
    }

    pub fn node_at(&self, path: &[usize]) -> Option<&AgentNode> {
        let first = *path.first()?;
        let mut node = self.subagents.get(first)?;
        for &index in &path[1..] {
            node = node.children.get(index)?;
        }
        Some(node)
    }

    pub fn node_at_mut(&mut self, path: &[usize]) -> Option<&mut AgentNode> {
        let first = *path.first()?;
        let mut node = self.subagents.get_mut(first)?;
        for &index in &path[1..] {
            node = node.children.get_mut(index)?;
        }
        Some(node)
    }

    /// Drop trailing focus entries that no longer resolve.
    pub fn ensure_focus(&mut self) {
        let mut valid = 0usize;
        {
            let mut nodes = self.subagents.as_slice();
            for &index in &self.focus {
                if index >= nodes.len() {
                    break;
                }
                nodes = nodes[index].children.as_slice();
                valid += 1;
            }
        }
        self.focus.truncate(valid);
    }

    pub fn focused_name(&self) -> Option<&str> {
        self.node_at(&self.focus).map(|node| node.name.as_str())
    }

    pub fn thinking_visible(&self, message: &Message) -> bool {
        message.thinking_open.unwrap_or(self.show_thinking)
    }

    /// Flip the conversation-wide thinking default and drop per-message overrides.
    pub fn toggle_show_thinking(&mut self) {
        self.show_thinking = !self.show_thinking;
        clear_thinking_overrides(&mut self.messages);
        clear_node_thinking(&mut self.subagents);
    }

    pub fn toggle_message_thinking(&mut self, index: usize) {
        let default = self.show_thinking;
        if let Some(message) = self.focused_messages_mut().get_mut(index)
            && message.has_thinking()
        {
            let current = message.thinking_open.unwrap_or(default);
            message.thinking_open = Some(!current);
        }
    }

    pub fn toggle_message_stats(&mut self, index: usize) {
        if let Some(message) = self.focused_messages_mut().get_mut(index)
            && message.stats.is_some()
        {
            message.stats_open = !message.stats_open;
        }
    }

    pub fn toggle_message_summary(&mut self, index: usize) {
        if let Some(message) = self.focused_messages_mut().get_mut(index)
            && message.has_compaction()
        {
            message.summary_open = !message.summary_open;
        }
    }

    /// Fold the focused transcript into a compaction boundary. Returns `false`
    /// when there is nothing to summarise.
    pub fn compact_context(&mut self) -> bool {
        let turns = self
            .focused_messages()
            .iter()
            .filter(|message| matches!(message.role, Role::User))
            .count();
        if !self
            .focused_messages()
            .iter()
            .any(|message| matches!(message.role, Role::User | Role::Agent))
        {
            return false;
        }
        let summary = write_compact_summary(self.focused_messages());
        let notice = if turns == 1 {
            "Compacted the context — folded 1 older turn into a summary.".to_string()
        } else {
            format!("Compacted the context — folded {turns} older turns into a summary.")
        };
        self.focused_messages_mut()
            .push(Message::compaction(notice, summary));
        self.touch();
        self.pinned = true;
        true
    }

    pub fn focused_messages(&self) -> &[Message] {
        if self.focus.is_empty() {
            &self.messages
        } else {
            self.node_at(&self.focus)
                .map(|node| node.messages.as_slice())
                .unwrap_or(&self.messages)
        }
    }

    pub fn focused_messages_mut(&mut self) -> &mut Vec<Message> {
        if self.focus.is_empty() {
            return &mut self.messages;
        }
        let path = self.focus.clone();
        if self.node_at(&path).is_none() {
            return &mut self.messages;
        }
        &mut self
            .node_at_mut(&path)
            .expect("focus path was just resolved")
            .messages
    }

    /// Background workers anywhere under the session. Interactive nodes are
    /// not places — they are skipped as rows, but their background descendants
    /// hoist into this list.
    pub fn background_workers(&self) -> Vec<(Vec<usize>, &AgentNode)> {
        let mut out = Vec::new();
        collect_background(&self.subagents, &[], &mut out);
        out
    }

    pub fn layer_tools(&self) -> &[ToolInfo] {
        if self.focus.is_empty() {
            &self.tools
        } else {
            self.node_at(&self.focus)
                .map(|node| node.tools.as_slice())
                .unwrap_or(&self.tools)
        }
    }

    pub fn layer_tools_mut(&mut self) -> &mut [ToolInfo] {
        if self.focus.is_empty() {
            return &mut self.tools;
        }
        let path = self.focus.clone();
        if self.node_at(&path).is_none() {
            return &mut self.tools;
        }
        &mut self
            .node_at_mut(&path)
            .expect("focus path was just resolved")
            .tools
    }

    pub fn layer_skills(&self) -> &[SkillInfo] {
        if self.focus.is_empty() {
            &self.skills
        } else {
            self.node_at(&self.focus)
                .map(|node| node.skills.as_slice())
                .unwrap_or(&self.skills)
        }
    }

    pub fn layer_tasks(&self) -> &[TaskInfo] {
        if self.focus.is_empty() {
            &self.tasks
        } else {
            self.node_at(&self.focus)
                .map(|node| node.tasks.as_slice())
                .unwrap_or(&self.tasks)
        }
    }

    pub fn layer_timers(&self) -> &[TimerInfo] {
        if self.focus.is_empty() {
            &self.timers
        } else {
            self.node_at(&self.focus)
                .map(|node| node.timers.as_slice())
                .unwrap_or(&self.timers)
        }
    }

    /// True while an interactive child holds the foreground and has not run `done`.
    pub fn locked_in_interactive(&self) -> bool {
        self.node_at(&self.focus)
            .is_some_and(|node| node.interactive && node.is_active())
    }

    pub fn focused_model(&self) -> Option<&str> {
        self.node_at(&self.focus)
            .and_then(|node| node.model.as_deref())
    }

    /// Hand control back one stack frame after `done`. Updates the parent's
    /// inlined card and leaves leftover background children running.
    pub fn complete_interactive(&mut self, summary: &str) {
        let path = self.focus.clone();
        if path.is_empty() {
            return;
        }
        if let Some(node) = self.node_at_mut(&path) {
            node.status = Status::Done;
        }
        let parent_path: Vec<usize> = path[..path.len() - 1].to_vec();
        self.patch_subagent_card(&parent_path, &path, summary);
        self.focus.pop();
        self.ensure_focus();
        self.pinned = true;
        self.touch();
        self.refresh_resting();
    }

    /// Emit any background reports whose `ready_at` has passed. A live
    /// interactive ancestor keeps the result in its own context; a finished
    /// one forwards it to the main agent with a deterministic attribution.
    pub fn deliver_due_reports(&mut self, now: Instant) {
        let mut due = Vec::new();
        let mut paths = Vec::new();
        collect_paths(&self.subagents, &[], &mut paths);
        for path in paths {
            let Some(node) = self.node_at(&path) else {
                continue;
            };
            if node.interactive || !node.is_active() {
                continue;
            }
            let Some(report) = node.report.clone() else {
                continue;
            };
            let Some(ready_at) = node.ready_at else {
                continue;
            };
            if now >= ready_at {
                due.push((path, report));
            }
        }
        for (path, report) in due {
            self.complete_background(&path, &report);
        }
    }

    fn complete_background(&mut self, path: &[usize], report: &str) {
        let child_name = self
            .node_at(path)
            .map(|node| node.name.clone())
            .unwrap_or_else(|| "subagent".into());
        if let Some(node) = self.node_at_mut(path) {
            node.status = Status::Done;
            node.report = None;
            node.ready_at = None;
        }
        let ancestor = nearest_interactive_ancestor(self, path);
        match ancestor {
            Some(apath) if self.node_at(&apath).is_some_and(|node| node.is_active()) => {
                if let Some(node) = self.node_at_mut(&apath) {
                    node.messages
                        .push(Message::system(format!("{child_name} finished — {report}")));
                }
                self.patch_subagent_card(&apath, path, report);
            }
            Some(apath) => {
                let from = self
                    .node_at(&apath)
                    .map(|node| node.name.clone())
                    .unwrap_or_else(|| "subagent".into());
                self.messages.push(Message::injection(from, report));
                self.patch_subagent_card(&apath, path, report);
                if self.focus.is_empty() {
                    self.pinned = true;
                }
            }
            None => {
                self.messages.push(Message::system(report.to_string()));
                self.patch_subagent_card(&[], path, report);
                if self.focus.is_empty() {
                    self.pinned = true;
                }
            }
        }
        self.touch();
        self.refresh_resting();
    }

    fn patch_subagent_card(&mut self, layer: &[usize], card: &[usize], summary: &str) {
        let messages = if layer.is_empty() {
            &mut self.messages
        } else if let Some(node) = self.node_at_mut(layer) {
            &mut node.messages
        } else {
            return;
        };
        for message in messages.iter_mut() {
            for segment in &mut message.segments {
                if let Segment::Subagent {
                    path,
                    summary: text,
                    ..
                } = segment
                    && path == card
                {
                    *text = summary.to_string();
                }
            }
        }
    }

    fn refresh_resting(&mut self) {
        if self.run.is_some() {
            return;
        }
        self.resting = if any_active(&self.subagents) {
            Status::Working
        } else if self.resting == Status::Waiting {
            Status::Waiting
        } else if self.messages.is_empty() {
            Status::Idle
        } else {
            Status::Done
        };
    }

    /// Non-archived sessions, starred (pinned-to-top) first, then the rest,
    /// preserving relative order within each group.
    pub fn visible_indices(sessions: &[Session]) -> Vec<usize> {
        let mut visible: Vec<usize> = sessions
            .iter()
            .enumerate()
            .filter(|(_, session)| !session.archived)
            .map(|(index, _)| index)
            .collect();
        visible.sort_by_key(|&index| !sessions[index].starred);
        visible
    }
}

/// A readable brief of the live transcript, used as the expandable compaction
/// summary. Deterministic: same messages always produce the same text.
pub fn write_compact_summary(messages: &[Message]) -> String {
    let mut asks = Vec::new();
    let mut files = Vec::new();
    let mut children = Vec::new();
    let mut last_prose = None;

    for message in messages {
        match message.role {
            Role::User => {
                let text = collapse_ws(&message.plain());
                if !text.is_empty() {
                    asks.push(text);
                }
            }
            Role::Agent => {
                for segment in &message.segments {
                    match segment {
                        Segment::Diff(file) => {
                            files.push(format!(
                                "{} {}",
                                file.verb().to_ascii_lowercase(),
                                file.path
                            ));
                        }
                        Segment::Subagent { name, summary, .. } => {
                            children.push(format!("{name} — {summary}"));
                        }
                        Segment::Prose(text) if !text.is_empty() => {
                            last_prose = Some(collapse_ws(text));
                        }
                        _ => {}
                    }
                }
            }
            Role::System => {}
        }
    }

    let mut parts = Vec::new();
    match asks.as_slice() {
        [] => {}
        [one] => parts.push(format!("The user asked: {}.", trim_end_punct(one))),
        [first, .., last] => parts.push(format!(
            "The user asked: {}. Later: {}.",
            trim_end_punct(first),
            trim_end_punct(last)
        )),
    }
    if !files.is_empty() {
        parts.push(format!("Changes: {}.", files.join("; ")));
    }
    if !children.is_empty() {
        parts.push(format!("Subagents: {}.", children.join("; ")));
    }
    if let Some(prose) = last_prose {
        parts.push(brief_prose(&prose));
    }
    if parts.is_empty() {
        "Earlier turns were summarised so the live context stays small.".into()
    } else {
        parts.join("\n\n")
    }
}

fn collapse_ws(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn trim_end_punct(text: &str) -> &str {
    text.trim_end_matches(['.', '!', '?'])
}

fn brief_prose(text: &str) -> String {
    let text = trim_end_punct(text);
    if text.chars().count() <= 180 {
        return format!("{text}.");
    }
    let mut cut: String = text.chars().take(177).collect();
    if let Some(index) = cut.rfind(' ') {
        cut.truncate(index);
    }
    format!("{cut}…")
}

fn collect_paths(nodes: &[AgentNode], prefix: &[usize], out: &mut Vec<Vec<usize>>) {
    for (index, node) in nodes.iter().enumerate() {
        let mut path = prefix.to_vec();
        path.push(index);
        out.push(path.clone());
        collect_paths(&node.children, &path, out);
    }
}

fn collect_background<'a>(
    nodes: &'a [AgentNode],
    prefix: &[usize],
    out: &mut Vec<(Vec<usize>, &'a AgentNode)>,
) {
    for (index, node) in nodes.iter().enumerate() {
        let mut path = prefix.to_vec();
        path.push(index);
        if node.interactive {
            collect_background(&node.children, &path, out);
        } else if node.is_active() {
            out.push((path, node));
        }
    }
}

fn nearest_interactive_ancestor(session: &Session, path: &[usize]) -> Option<Vec<usize>> {
    if path.is_empty() {
        return None;
    }
    let mut ancestor = path.to_vec();
    ancestor.pop();
    while !ancestor.is_empty() {
        if session
            .node_at(&ancestor)
            .is_some_and(|node| node.interactive)
        {
            return Some(ancestor);
        }
        ancestor.pop();
    }
    None
}

fn any_active(nodes: &[AgentNode]) -> bool {
    nodes
        .iter()
        .any(|node| node.is_active() || any_active(&node.children))
}

fn clear_thinking_overrides(messages: &mut [Message]) {
    for message in messages {
        message.thinking_open = None;
    }
}

fn clear_node_thinking(nodes: &mut [AgentNode]) {
    for node in nodes {
        clear_thinking_overrides(&mut node.messages);
        clear_node_thinking(&mut node.children);
    }
}

fn fork_title(text: &str) -> String {
    let clean = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut chars: Vec<char> = clean.chars().collect();
    if chars.len() > 32 {
        chars.truncate(30);
        chars.push('…');
    }
    let body: String = chars.into_iter().collect();
    if body.is_empty() {
        "Forked session".to_string()
    } else {
        format!("Fork: {body}")
    }
}

fn fork_subtitle(text: &str) -> String {
    let clean = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let chars: Vec<char> = clean.chars().collect();
    if chars.len() > 60 {
        let mut cut: String = chars.into_iter().take(57).collect();
        cut.push('…');
        cut
    } else if clean.is_empty() {
        "Forked from a message".to_string()
    } else {
        clean
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn q(tag: u32, mode: QueueMode) -> QueuedMessage {
        QueuedMessage {
            text: format!("m{tag}"),
            mode,
        }
    }

    #[test]
    fn tool_tier_cache_breaks_only_when_crossing_enabled() {
        assert!(ToolTier::breaks_cache(
            ToolTier::Enabled,
            ToolTier::Discoverable
        ));
        assert!(ToolTier::breaks_cache(
            ToolTier::Enabled,
            ToolTier::Disabled
        ));
        assert!(ToolTier::breaks_cache(
            ToolTier::Discoverable,
            ToolTier::Enabled
        ));
        assert!(ToolTier::breaks_cache(
            ToolTier::Disabled,
            ToolTier::Enabled
        ));
        assert!(!ToolTier::breaks_cache(
            ToolTier::Discoverable,
            ToolTier::Disabled
        ));
        assert!(!ToolTier::breaks_cache(
            ToolTier::Disabled,
            ToolTier::Discoverable
        ));
        assert!(!ToolTier::breaks_cache(
            ToolTier::Enabled,
            ToolTier::Enabled
        ));
        assert_eq!(ToolTier::Enabled.cycle(), ToolTier::Discoverable);
        assert_eq!(ToolTier::Discoverable.cycle(), ToolTier::Disabled);
        assert_eq!(ToolTier::Disabled.cycle(), ToolTier::Enabled);
    }

    #[test]
    fn peak_is_the_most_urgent_mode() {
        assert_eq!(peak_mode(&[]), None);
        let items = vec![q(1, QueueMode::Turn), q(2, QueueMode::Boundary)];
        assert_eq!(peak_mode(&items), Some(QueueMode::Boundary));
    }

    #[test]
    fn escalate_levels_the_whole_batch_up_one_rung() {
        let mut items = vec![q(1, QueueMode::Turn), q(2, QueueMode::Boundary)];
        // Peak is Boundary, so the batch escalates to Interrupt together.
        assert_eq!(escalate(&mut items), Some(QueueMode::Interrupt));
        assert!(items.iter().all(|item| item.mode == QueueMode::Interrupt));
        // Already at the top: escalation is a no-op that stays interrupt.
        assert_eq!(escalate(&mut items), Some(QueueMode::Interrupt));
        assert_eq!(escalate(&mut []), None);
    }

    #[test]
    fn take_due_carries_only_the_urgent_and_leaves_the_rest() {
        let mut items = vec![
            q(1, QueueMode::Turn),
            q(2, QueueMode::Boundary),
            q(3, QueueMode::Interrupt),
        ];
        let due = take_due(&mut items, QueueMode::Boundary);
        assert_eq!(
            due.iter().map(|d| d.text.clone()).collect::<Vec<_>>(),
            vec!["m2", "m3"]
        );
        assert_eq!(
            items.iter().map(|d| d.text.clone()).collect::<Vec<_>>(),
            vec!["m1"]
        );
    }

    #[test]
    fn take_due_turn_level_drains_everything() {
        let mut items = vec![q(1, QueueMode::Turn), q(2, QueueMode::Interrupt)];
        let due = take_due(&mut items, QueueMode::Turn);
        assert_eq!(due.len(), 2);
        assert!(items.is_empty());
    }

    #[test]
    fn providers_are_unique_and_in_catalog_order() {
        assert_eq!(
            providers(),
            vec!["OpenAI", "Anthropic", "xAI", "Google", "local"]
        );
    }

    #[test]
    fn models_for_returns_catalog_indices_for_that_provider() {
        assert_eq!(models_for("Anthropic"), vec![1, 2]);
        assert_eq!(models_for("OpenAI"), vec![0]);
        assert!(models_for("unknown").is_empty());
        assert_eq!(
            model_by_display("Grok Code").map(|m| m.provider),
            Some("xAI")
        );
    }

    #[test]
    fn fork_at_copies_history_through_the_chosen_message() {
        let mut session = Session {
            title: "original".into(),
            subtitle: String::new(),
            repo: "acme/demo".into(),
            messages: vec![
                Message::user("first".into()),
                Message::pending_agent(),
                Message::user("second".into()),
            ],
            script: VecDeque::new(),
            suggestions: vec!["keep going".into()],
            queue: vec![q(1, QueueMode::Turn)],
            run: None,
            resting: Status::Done,
            scroll: 4,
            pinned: false,
            last_active: SystemTime::now(),
            archived: false,
            starred: false,
            show_thinking: false,
            focus: Vec::new(),
            subagents: Vec::new(),
            tools: Vec::new(),
            skills: Vec::new(),
            tasks: Vec::new(),
            timers: Vec::new(),
        };
        session.messages[1].streaming = false;
        session.messages[1].segments = vec![Segment::Prose("reply".into())];

        let fork = session.fork_at(1).expect("user/agent can fork");
        assert_eq!(
            fork.messages.len(),
            2,
            "history stops at the forked message"
        );
        assert_eq!(fork.messages[0].plain(), "first");
        assert_eq!(fork.messages[1].plain(), "reply");
        assert!(fork.messages.iter().all(|m| !m.streaming));
        assert!(fork.queue.is_empty());
        assert!(fork.suggestions.is_empty());
        assert_eq!(fork.repo, "acme/demo");
        assert!(fork.title.starts_with("Fork:"));
        assert!(fork.pinned);
        assert_eq!(session.messages.len(), 3, "the original is untouched");
        assert!(session.fork_at(9).is_none());
    }

    fn blank_session(title: &str, starred: bool, archived: bool) -> Session {
        Session {
            title: title.into(),
            subtitle: String::new(),
            repo: "acme/demo".into(),
            messages: Vec::new(),
            script: VecDeque::new(),
            suggestions: Vec::new(),
            queue: Vec::new(),
            run: None,
            resting: Status::Idle,
            scroll: 0,
            pinned: true,
            last_active: SystemTime::now(),
            archived,
            starred,
            show_thinking: false,
            focus: Vec::new(),
            subagents: Vec::new(),
            tools: Vec::new(),
            skills: Vec::new(),
            tasks: Vec::new(),
            timers: Vec::new(),
        }
    }

    #[test]
    fn background_workers_skip_interactive_and_finished() {
        let mut session = blank_session("a", false, false);
        let mut live = AgentNode::new("live", true, Status::Working);
        live.children
            .push(AgentNode::new("writer", false, Status::Working));
        session.subagents = vec![live, AgentNode::new("done", false, Status::Done)];
        let workers = session.background_workers();
        assert_eq!(workers.len(), 1);
        assert_eq!(workers[0].1.name, "writer");
    }

    #[test]
    fn visible_indices_put_starred_sessions_first() {
        let sessions = vec![
            blank_session("a", false, false),
            blank_session("b", true, false),
            blank_session("c", false, true),
            blank_session("d", true, false),
        ];
        assert_eq!(Session::visible_indices(&sessions), vec![1, 3, 0]);
    }

    #[test]
    fn done_hands_back_and_late_background_lands_on_the_parent() {
        use std::time::{Duration, Instant};

        let mut session = blank_session("a", false, false);
        session.messages.push(Message::user("go".into()));
        session.messages.push(Message {
            role: Role::Agent,
            segments: vec![Segment::Subagent {
                name: "Explore".into(),
                interactive: true,
                summary: "looking".into(),
                path: vec![0],
            }],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        });
        let mut writer = AgentNode::new("Write test", false, Status::Working);
        writer.report = Some("drafted the test".into());
        writer.ready_at = Some(Instant::now() + Duration::from_secs(60));
        let mut explore = AgentNode::new("Explore", true, Status::Working);
        explore.messages.push(Message {
            role: Role::Agent,
            segments: vec![Segment::Subagent {
                name: "Write test".into(),
                interactive: false,
                summary: "drafting".into(),
                path: vec![0, 0],
            }],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        });
        explore.children.push(writer);
        session.subagents.push(explore);
        session.focus = vec![0];

        session.complete_interactive("three call sites");
        assert!(session.focus.is_empty());
        assert_eq!(session.subagents[0].status, Status::Done);
        assert!(matches!(
            session.messages[1].segments.last(),
            Some(Segment::Subagent { summary, .. }) if summary == "three call sites"
        ));

        session.subagents[0].children[0].ready_at = Some(Instant::now());
        session.deliver_due_reports(Instant::now() + Duration::from_millis(1));
        let last = session.messages.last().expect("injected");
        assert!(matches!(last.role, Role::System));
        assert!(matches!(
            last.segments.first(),
            Some(Segment::Injection { from, body })
                if from == "Explore" && body == "drafted the test"
        ));
        assert_eq!(session.subagents[0].children[0].status, Status::Done);
    }

    #[test]
    fn live_background_report_stays_on_the_interactive() {
        use std::time::{Duration, Instant};

        let mut session = blank_session("a", false, false);
        let mut writer = AgentNode::new("Write test", false, Status::Working);
        writer.report = Some("drafted the test".into());
        writer.ready_at = Some(Instant::now());
        let mut explore = AgentNode::new("Explore", true, Status::Working);
        explore.children.push(writer);
        session.subagents.push(explore);
        session.focus = vec![0];

        session.deliver_due_reports(Instant::now() + Duration::from_millis(1));
        assert!(
            session.messages.iter().all(|message| !matches!(
                message.segments.first(),
                Some(Segment::Injection { .. })
            )),
            "the parent must not see a late injection while Explore is still live"
        );
        assert!(
            session.subagents[0]
                .messages
                .iter()
                .any(|message| message.plain().contains("Write test finished"))
        );
        assert_eq!(session.subagents[0].children[0].status, Status::Done);
        assert!(session.subagents[0].is_active());
    }

    #[test]
    fn think_toggle_is_conversation_wide_and_chips_override() {
        let mut session = blank_session("a", false, false);
        session.messages.push(Message {
            role: Role::Agent,
            segments: vec![
                Segment::Reasoning("plan".into()),
                Segment::Prose("answer".into()),
            ],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        });
        assert!(!session.thinking_visible(&session.messages[0]));
        session.toggle_message_thinking(0);
        assert_eq!(session.messages[0].thinking_open, Some(true));
        assert!(session.thinking_visible(&session.messages[0]));
        session.toggle_show_thinking();
        assert!(session.show_thinking);
        assert!(session.messages[0].thinking_open.is_none());
        assert!(session.thinking_visible(&session.messages[0]));
    }

    #[test]
    fn turn_stats_format_ttft_tps_and_cache_percent() {
        let stats = TurnStats::settled(
            "OpenAI",
            "GPT-5 Codex",
            Duration::from_millis(312),
            47.62,
            8_410,
            12_180,
        );
        assert_eq!(stats.model_text(), "OpenAI / GPT-5 Codex");
        assert_eq!(stats.ttft_text(false), "312 ms");
        assert_eq!(stats.tps_text(false), "47.6");
        assert_eq!(stats.cache_text(), "8,410 / 12,180 (69%)");
        assert_eq!(stats.cache_pct(), Some(69));

        let live = TurnStats::live(MODELS[0], 100, 200, Instant::now());
        assert_eq!(live.ttft_text(true), "…");
        assert_eq!(live.tps_text(true), "…");
        assert_eq!(live.cache_text(), "100 / 200 (50%)");
    }

    #[test]
    fn clicking_agent_stats_toggles_only_that_message() {
        let mut session = blank_session("a", false, false);
        session.messages.push(Message {
            role: Role::Agent,
            segments: vec![Segment::Prose("answer".into())],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: Some(TurnStats::demo("OpenAI", "GPT-5 Codex", 3)),
            stats_open: false,
            summary_open: false,
        });
        session.toggle_message_stats(0);
        assert!(session.messages[0].stats_open);
        session.toggle_message_stats(0);
        assert!(!session.messages[0].stats_open);
    }

    #[test]
    fn compact_context_writes_a_readable_summary() {
        let mut session = blank_session("a", false, false);
        assert!(!session.compact_context());
        session.messages.push(Message::user(
            "Can you take a look at how requireAuth is structured?".into(),
        ));
        session.messages.push(Message {
            role: Role::Agent,
            segments: vec![
                Segment::Prose("Extracted verifyToken.".into()),
                Segment::Diff(FileDiff::write("src/auth/verify-token.ts", &["export {}"])),
            ],
            interrupted: false,
            streaming: false,
            at: SystemTime::now(),
            pinned: false,
            thinking_open: None,
            stats: None,
            stats_open: false,
            summary_open: false,
        });
        assert!(session.compact_context());
        let last = session.messages.last().unwrap();
        assert!(last.has_compaction());
        assert!(!last.summary_open);
        assert!(last.plain().contains("folded 1 older turn"));
        let Segment::Compaction { summary, .. } = &last.segments[0] else {
            panic!("expected a compaction segment");
        };
        assert!(summary.contains("The user asked: Can you take a look"));
        assert!(summary.contains("created src/auth/verify-token.ts"));
        session.toggle_message_summary(session.messages.len() - 1);
        assert!(session.messages.last().unwrap().summary_open);
    }
}
