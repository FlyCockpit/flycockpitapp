//! Typed entries that live in `App.history` plus the renderers that
//! turn them into `ratatui::text::Line` for display.
//!
//! Why a typed model rather than `Vec<String>`: the chrome needs to
//! style entries differently (user messages get bg color + padding,
//! thinking blocks get a "Thinking…" placeholder with a chip,
//! timestamps land right-aligned on the first wrapped line, …). All of
//! that needs structured data; a flat `Vec<String>` would force string
//! parsing tricks at render time.

use std::collections::HashSet;
use std::rc::Rc;
use std::time::Duration;

use chrono::{DateTime, Local};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use unicode_width::UnicodeWidthStr;

use crate::tui::markdown;
#[cfg(test)]
use crate::tui::message_block::wrap_lines_to_width_reserving_first;
use crate::tui::message_block::{
    MessageBlock, layout_markdown_message_lines, render_markdown_message_block,
    slice_spans_at_width, wrap_lines_to_width,
};
use crate::tui::progress::render_bar;
use crate::tui::theme::{
    BRASS, DISABLED, ERROR_TEXT, FOG, INFO_TEXT, INK, PLAN_YELLOW, SUBAGENT_ORANGE, SUCCESS_TEXT,
    TEAL, TOOL_OUTPUT, WARNING_TEXT,
};
use cockpit_client::presentation::{ResponsePerformance, ToolProgress};
use cockpit_config::extended::ThinkingDisplay;
use cockpit_core::engine::tool::ToolPresentation;

mod pending;
mod scroll;

pub use pending::PendingMsg;
#[allow(unused_imports)]
pub use scroll::InnerScrollWindow;
pub use scroll::{ReasoningScrollRegion, ToolResultScrollRegion, inner_scroll_window};

/// Markdown render preferences, threaded from `App` to each
/// per-entry renderer. Cheap to copy, so we pass by value.
#[derive(Debug, Clone, Copy, Default)]
pub struct MarkdownOpts {
    pub agent: bool,
    pub user: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubagentRoutingChips {
    pub model: Option<String>,
    pub location: Option<String>,
    pub fallback: Option<String>,
}

/// How a [`HistoryEntry::Diff`] should label its header chrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DiffVerb {
    #[default]
    Edited,
    Created,
}

/// The user's own message and the assistant's response carry
/// timestamps; engine events (tool calls, errors, subagent
/// spawn/report) don't — they're scoped within the surrounding
/// assistant turn so a per-event timestamp would clutter.
#[derive(Debug, Clone)]
pub enum HistoryEntry {
    User {
        /// The user's **original typed** input — the wire-vs-user user side
        /// (GOALS §14). Always present. Shown at rest unless [`Self::User::cleaned`]
        /// is set (request preflight rewrote it), in which case it's revealed
        /// on click / Ctrl+E.
        text: String,
        /// The request-preflight **cleaned** (rewritten) body, when this
        /// message was preflighted (implementation note). When
        /// `Some`, the resting render shows this + a `⚙ preflighted` chip and
        /// clicking the row (or Ctrl+E) reveals [`Self::User::text`]. `None`
        /// when preflight didn't run / was a no-op / fell back — render exactly
        /// as today (no chip, no reveal).
        cleaned: Option<String>,
        /// Whether the original typed input is revealed instead of the cleaned
        /// form. Only meaningful when `cleaned.is_some()`; toggled by click /
        /// Ctrl+E (reuses the [`Self::Agent`] reasoning reveal pattern).
        expanded: bool,
        timestamp: DateTime<Local>,
        /// `session_events.seq` of this message (the stable id a pin
        /// references — `pinned-messages`). `None` until the daemon's
        /// `UserMessageRecorded` event stamps it (the row is pushed
        /// optimistically on submit, before the timeline write completes).
        seq: Option<i64>,
        /// Client-local identity assigned while this row is optimistic.
        /// Persisted/replayed rows have `None`. The id survives a transactional
        /// `/new` replay and correlates client-side dispatch failures without
        /// guessing from text or transcript position.
        optimistic_submission_id: Option<uuid::Uuid>,
        /// Request preflight (implementation note) is
        /// running for this optimistically-shown row: the top-border slot hosts
        /// the animated `Preflight…` indicator (reusing the busy/Thinking
        /// spinner) instead of the resting chip. Set by `PreflightStarted`,
        /// cleared when the message resolves (`UserMessageRecorded` — replaced
        /// by the `⚙ preflighted` chip when `cleaned` lands, or nothing) or the
        /// row is retracted (`UserMessageRetracted` — injection block).
        preflight_pending: bool,
        /// The daemon failed to persist the deferred session before starting
        /// inference. The optimistic row stays visible but is marked as not
        /// sent.
        persist_failed: bool,
    },
    Plain {
        line: String,
    },
    /// A user-visible command, dispatch, daemon, or session-operation failure.
    /// Separate from provider/model inference failures, but rendered with the
    /// same red error treatment so failed local actions do not look like notes.
    CommandError {
        line: String,
    },
    Maintenance {
        line: String,
    },
    /// Structured question/approval resolution row. Distinct from generic
    /// maintenance so dismissed decisions can be styled from the wire
    /// `cancelled` flag instead of string-matching the answer.
    InterruptDecision {
        decision: cockpit_proto::InterruptDecision,
    },
    /// A user-authored session-history note (`/note <text>`,
    /// implementation note). Rendered as a DISTINCT "note to
    /// self" row — visually separate from a normal user message and from
    /// assistant output — and included in exports. Display/export state only:
    /// it is never sent to the model and never triggers an inference call
    /// (rehydration skips the backing `user_note` session event).
    UserNote {
        text: String,
        timestamp: DateTime<Local>,
    },
    /// A skill the utility-model auto-selector injected onto a turn
    /// (implementation note). Rendered
    /// as a DISTINCT `/{name} · injected by agent` row ahead of the user's
    /// message, so the user can tell an auto-injected skill apart from a
    /// user-typed `/{name}` (which renders as a `skill` tool-call row) and
    /// from the agent's own `skill` tool call. The "injected by agent"
    /// label is the discriminator. Display/export state only — the skill
    /// body itself rides the user message on the wire (wire-vs-user split,
    /// GOALS §14), so this row costs zero model context.
    SkillAutoInjected {
        /// The injected skill's id, e.g. `firecrawl`.
        name: String,
        /// Optional short reason the skill was selected
        /// (implementation note): the utility model's
        /// clause when given, else a keyword-overlap fallback. Rendered as a
        /// muted `  └ <reason>` sub-line beneath the row; `None` → plain row,
        /// no sub-line. Display/export state only — off-wire (GOALS §14), so
        /// it costs zero model context.
        reason: Option<String>,
    },
    /// A terminal inference failure (TTFT / idle timeout, connection error,
    /// or non-retryable HTTP — `inference-timeout-and-failure-
    /// observability.md`), rendered as a RED inline row, the same visual
    /// treatment a failed tool call gets. The collapsed row shows `summary`;
    /// expanding reveals `detail`. Display-only; never sent to the model.
    InferenceError {
        summary: String,
        detail: String,
        expanded: bool,
    },
    /// A per-turn backup-model fallback notice (`per-model-backup-
    /// fallback.md`): the primary failed a qualifying inference and the turn was
    /// answered by the configured backup, rendered as a DISPLAY-ONLY YELLOW
    /// line. Wire-vs-user split (GOALS §14): UI-only; never sent to the model.
    BackupWarning {
        line: String,
    },
    /// A slow-stream inference warning (TTFT / idle threshold crossed while the
    /// provider is still running), rendered as a DISPLAY-ONLY YELLOW line.
    /// Distinct from backup fallback banners so exports can tell them apart.
    InferenceWarning {
        line: String,
    },
    /// Assistant turn with text. `reasoning` is captured but only
    /// rendered when `expanded` is true (see [`crate::tui::app`]).
    /// `think_duration` is the wall-clock time between
    /// `ThinkingStarted` and the first `AssistantTextDelta` — used to
    /// render `Agent thought for X seconds` once the turn finalizes.
    /// `None` when no reasoning content was captured.
    Agent {
        name: String,
        text: String,
        reasoning: String,
        timestamp: DateTime<Local>,
        expanded: bool,
        /// Top-anchored offset into the wrapped reasoning window.
        reasoning_offset: usize,
        think_duration: Option<Duration>,
        /// `session_events.seq` of this message (the stable id a pin
        /// references — `pinned-messages`). `None` only when the timeline
        /// write failed for this turn.
        seq: Option<i64>,
        /// Optional durable response-performance snapshot (TTFT,
        /// generation, displayed tokens, encoding). `None` for
        /// empty/think-only/no-visible-body/zero-duration responses —
        /// the foundation omits the snapshot in those cases. When
        /// present, the renderer draws a clickable `<ttft>/<tps>` chip
        /// immediately left of fork/pin/timestamp.
        performance: Option<ResponsePerformance>,
        /// Whether the performance chip is expanded to show the detail
        /// line (`TTFT: <value> / TPS: <value>`). TUI-local; defaults
        /// closed on live/replay and is never persisted. Toggled
        /// independently of the reasoning `expanded` field.
        performance_expanded: bool,
        /// The turn was cut short by the user (Ctrl+C or a message that
        /// raced the stream). Set from `AgentIdle(Interrupted)` at
        /// finalization — see `App::finalize_pending_interrupted` — so the
        /// frozen entry renders the trailing `⎯ Stopped — you sent a
        /// message` marker row instead of looking like a settled reply.
        interrupted: bool,
    },
    /// Completed `edit` tool call. Rendered as a diff per `tui.diff_style`
    /// (side-by-side / inline / hidden). Stored instead of a `Plain` line so
    /// the renderer can re-flow if the pane width changes mid-session and
    /// re-pick side-by-side vs. inline.
    Diff {
        tool: String,
        path: String,
        old: String,
        new: String,
        verb: DiffVerb,
    },
    /// A run of consecutive boxable tool calls (read, unlock, bash,
    /// webfetch, …) rendered inside a light-grey rounded sidebar. Diff tools
    /// (`edit`), write tools, and subagent calls break the run, so a box never
    /// holds them. When every call is collapsed, the box shows at most
    /// [`TOOLBOX_VISIBLE`] calls with an internal scroll. Clicking a call
    /// expands only that call.
    ToolBox {
        calls: Vec<ToolCall>,
        /// Topmost visible call when no individual call is expanded.
        /// Ignored while `follow` is true.
        view_offset: usize,
        /// Collapsed viewport auto-pins to the newest call as calls
        /// stream in. Cleared when the user scrolls up; restored when
        /// they scroll back to the end.
        follow: bool,
    },
    /// A standalone tool call rendered as one styled line outside any
    /// box. Used for `write`: conceptually diffs that break the box, but the
    /// engine doesn't surface pre-write file content yet (see
    /// [`crate::tui::diff`]), so they render as a one-liner until that lands.
    ToolLine {
        call_id: String,
        tool: String,
        summary: String,
        /// Path used for file-icon selection when the visible summary is not
        /// a path (for example, a standalone edit error).
        icon_path: Option<String>,
        state: ToolCallState,
    },
    /// A locally-run command and its captured (display-capped) output,
    /// shown in chat (GOALS §1k/§1l). `!` shell runs are local-only;
    /// `/git` runs also buffer a `<git>` block onto the next user
    /// message. Either way the displayed copy is **not** sent to the
    /// agent and `estimate_context_tokens` ignores it.
    LocalCommand {
        /// Display label, e.g. `! ls -la` or `/git status`.
        label: String,
        /// Captured, ANSI-stripped, display-capped output.
        output: String,
        /// True when the command exited non-zero — tints the label red.
        failed: bool,
    },
    /// A noninteractive subagent delegation, surfaced via the subagent
    /// spawn/report events. While the child runs (`outcome` is `None`)
    /// it renders as a single live line — `{parent} delegated to
    /// {child}… (elapsed)` — with animated ellipses and a ticking timer
    /// driven by `spawned_at`. Once it returns, `outcome` is `Some` and
    /// the line becomes a `{child} worked for {duration}` (or `failed
    /// after`) header plus the markdown-rendered, left-bar-quoted,
    /// truncatable response body. Child name renders in bold ink; parent
    /// in the default style.
    Subagent {
        /// Delegating agent's name (default style).
        parent: String,
        /// Delegated-to agent's name (bold ink).
        child: String,
        task_call_id: String,
        label: String,
        /// True when the delegating/subagent inference ran under a
        /// True when the selected subagent model is trusted.
        model_trusted: bool,
        /// Compact display subset from the durable routing metadata.
        routing: SubagentRoutingChips,
        /// `Instant` the spawn event arrived — drives the live elapsed
        /// clock while running and freezes into `outcome.duration` on
        /// report.
        spawned_at: std::time::Instant,
        /// `None` while the child is still running; `Some` once it has
        /// reported (or failed).
        outcome: Option<SubagentOutcome>,
        /// Click-expanded: render the full report body instead of the
        /// truncated leading-lines preview. Only meaningful once
        /// `outcome` is `Some`.
        expanded: bool,
    },
    /// Boundary marker at the top of a `/compact`-created session
    /// (`prune-and-compact.md`). `/compact` forks to a fresh thread and
    /// preserves the old session whole, so this is the divider-equivalent
    /// for compaction — a muted rule at the session boundary, not an
    /// inline summary. The predecessor's content lives in the preserved
    /// session (viewable via `cockpit session show/resume`), so nothing is
    /// inlined or dimmed here.
    CompactBoundary {
        /// Predecessor session's 6-char display id.
        predecessor_short_id: String,
        /// Seed-tools re-run in the fresh session (from `CompactReady`).
        seed_tool_count: usize,
        /// Approx wire tokens the seed-tools + brief cost on the first
        /// turn. Shown only when it reads cleanly (non-zero).
        seed_tool_tokens: u64,
        source: String,
        trigger_ctx_pct: Option<f64>,
        tokens_before: u64,
        tokens_after: u64,
        turns_summarized: usize,
        tail_kept: usize,
        tail_trimmed: usize,
        /// Exact handoff installed on the model wire.
        handoff: Option<String>,
        /// Click-expanded through the ordinary tool-call affordance.
        expanded: bool,
        result_offset: usize,
    },
}

impl HistoryEntry {
    /// Whether this entry is a model tool-call presentation row. The entry
    /// stays in display history and the daemon-backed transcript; views may
    /// filter it without changing either of those sources of truth.
    pub(crate) fn is_tool_call_entry(&self) -> bool {
        matches!(
            self,
            Self::Diff { .. }
                | Self::ToolBox { .. }
                | Self::ToolLine { .. }
                | Self::Subagent { .. }
        )
    }
}

/// The settled result of a [`HistoryEntry::Subagent`] delegation.
#[derive(Debug, Clone)]
pub struct SubagentOutcome {
    /// The child's final report text. May be empty (renders as a bare
    /// header with no quoted block).
    pub report: String,
    /// True when the delegation ended in error rather than a normal
    /// report — flips the header to `failed after {duration}`.
    pub failed: bool,
    /// Total wall-clock from spawn to report.
    pub duration: Duration,
    /// Terse user-facing status for risky/partial endings. `None` means the
    /// report looks like an ordinary successful delegation.
    pub status: Option<String>,
}

/// Classify a completed delegation report for the compact status chrome.
pub fn classify_subagent_status(child: &str, report: &str, failed: bool) -> Option<String> {
    if failed {
        return Some(format!(
            "{} stopped with an error",
            agent_display_label(child)
        ));
    }
    let lower = report.to_lowercase();
    let wrote_files = [
        "wrote",
        "written",
        "edited",
        "modified",
        "changed",
        "created",
        "updated",
        "writeunlock", // Historical report text from pre-rename sessions.
        "editunlock",  // Historical report text from pre-rename sessions.
        "files changed",
        "files modified",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    let validation_not_run = [
        "validation not run",
        "validation wasn't run",
        "validation was not run",
        "tests not run",
        "tests weren't run",
        "tests were not run",
        "not validated",
        "unvalidated",
        "did not run validation",
        "didn't run validation",
        "did not run tests",
        "didn't run tests",
    ]
    .iter()
    .any(|needle| lower.contains(needle));
    if child == "builder" && wrote_files && validation_not_run {
        return Some("builder stopped after writing files; validation not run yet".to_string());
    }
    if lower.contains("blocked") || lower.contains("blocker") {
        return Some(format!(
            "{} returned with blockers",
            agent_display_label(child)
        ));
    }
    if lower.contains("partial") || lower.contains("incomplete") {
        return Some(format!(
            "{} returned partial work",
            agent_display_label(child)
        ));
    }
    None
}

/// Leading report lines a collapsed [`HistoryEntry::Subagent`] shows
/// before the `… (expand)` affordance.
pub const SUBAGENT_PREVIEW_LINES: usize = 3;

/// Lifecycle state of one tool call. Drives the line color: yellow
/// while the model waits, white on success, red when the tool failed,
/// bold red when the model built the call badly (unrecoverable).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolCallState {
    /// The call is being verified before any dispatch — a distinct semantic
    /// verification treatment with an accessible `Verifying` label. A
    /// no-dispatch outcome moves straight from here to [`Self::Success`]
    /// (`done`); an approved candidate moves to [`Self::Processing`]
    /// (`running`) only once final dispatch starts. The stable row never shows
    /// hidden original or candidate content.
    Verifying,
    /// The model is waiting on the tool — yellow.
    Processing,
    /// Completed successfully — white.
    Success,
    /// The tool ran but failed for an environmental reason — red.
    Failed,
    /// The model constructed the call badly; unrecoverable — bold red.
    BadCall,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpChildMeta {
    pub parent_call_id: String,
    pub parent_child_index: i64,
    pub server: Option<String>,
    pub builtin: Option<bool>,
    pub kind: Option<String>,
}

/// One tool call inside a [`HistoryEntry::ToolBox`].
#[derive(Debug, Clone)]
pub struct ToolCall {
    pub call_id: String,
    pub tool: String,
    /// One-line collapsed summary: a path, the first line of a bash
    /// command, a URL, … Truncated to the pane width at render time.
    pub summary: String,
    /// Full invocation text for the expanded view (e.g. a multi-line
    /// bash command). Equal to `summary` for single-line calls.
    pub full_input: String,
    /// Full tool output, shown only when this call is expanded and the
    /// tool is output-bearing. Empty for input-only tools.
    pub output: String,
    /// Per-call expansion state; neighboring calls remain collapsed.
    pub expanded: bool,
    /// Top-anchored offset into this call's wrapped result window.
    pub result_offset: usize,
    pub state: ToolCallState,
    /// Post-result hint text (`engine::bash_hints`, `data.hint.text`) when a
    /// rule fired on this (`bash`) call. Rendered as a single dim/italic
    /// `hint: <text>` line beneath the command output (wire-vs-user split,
    /// GOALS §14 — this is the user-side surface). `None` when no rule fired.
    pub hint: Option<String>,
    pub progress: Option<ToolProgress>,
    pub mcp_child: Option<McpChildMeta>,
}

/// Max tool-call rows a collapsed [`HistoryEntry::ToolBox`] shows
/// before it scrolls internally.
pub const TOOLBOX_VISIBLE: usize = 6;

/// Wrapped result rows shown for one expanded tool call before the result
/// scrolls internally.
pub const TOOLCALL_RESULT_VISIBLE: usize = 20;

/// Wrapped reasoning rows shown for one expanded thinking block before
/// the reasoning scrolls internally.
pub const THINKING_VISIBLE: usize = 20;

/// Display columns reserved for the tool glyph (emoji or Nerd Font
/// file-type icon + separator) in a tool-call row. Emoji glyphs are
/// width 2; Nerd Font file icons are width 1. Double-width glyphs are
/// excluded from the file-icon table so this column stays 3 cells
/// (icon + padding) and every `tool:` label starts at the same column.
const TOOL_GLYPH_COLUMN: usize = 3;

/// Dim grey for expanded tool output lines.
const TOOL_OUTPUT_FG: Color = TOOL_OUTPUT;

const USER_BORDER_FG: Color = BRASS;
const TIMESTAMP_FG: Color = DISABLED;
const REASONING_FG: Color = DISABLED;
const THINKING_FG: Color = FOG;
/// Width of an `HH:MM` timestamp string.
pub const TIMESTAMP_WIDTH: usize = 5;

/// Deterministic color assignment for an agent's bullet point. The
/// bundled cast gets stable hand-picked hues; user-authored agents
/// get a hash-based pick from the same palette so a project's agents
/// stay visually distinct even when their names collide on a prefix.
/// The user-facing display label for an agent name.
pub fn agent_display_label(name: &str) -> &str {
    name
}

pub fn user_display_label() -> &'static str {
    "You"
}

pub fn user_message_color() -> Color {
    USER_BORDER_FG
}

pub fn agent_color(name: &str) -> Color {
    match name {
        "Auto" => SUCCESS_TEXT,
        "Build" => Color::Cyan,
        "Plan" => PLAN_YELLOW,
        "builder" => Color::Magenta,
        "explore" => WARNING_TEXT,
        "docs" => Color::Blue,
        _ => {
            const PALETTE: &[Color] = &[
                Color::Cyan,
                Color::Magenta,
                SUCCESS_TEXT,
                WARNING_TEXT,
                ERROR_TEXT,
                Color::LightCyan,
                Color::LightMagenta,
                Color::LightGreen,
                Color::LightYellow,
                Color::LightRed,
            ];
            let h: u32 = name
                .bytes()
                .fold(0u32, |a, b| a.wrapping_mul(31).wrapping_add(b as u32));
            PALETTE[(h as usize) % PALETTE.len()]
        }
    }
}

/// The render-ready color for an agent — `agent_color()` with the truecolor
/// fallback applied. This is the **single** shared seam through which the
/// `agent_color()` palette reaches a terminal, so the history view and the
/// status bar stay consistent; render call sites use this, never the raw
/// `agent_color()`.
pub fn agent_color_rendered(name: &str) -> Color {
    downgrade_for_terminal(agent_color(name), terminal_supports_truecolor())
}

/// Map an `agent_color()` output to an ANSI-safe color when the terminal lacks
/// 24-bit color. Pure (capability passed in) so it is unit-testable.
/// [`PLAN_YELLOW`] downgrades to [`WARNING_TEXT`];
/// non-RGB palette entries pass through unchanged.
fn downgrade_for_terminal(color: Color, truecolor: bool) -> Color {
    match color {
        Color::Rgb(..) if !truecolor => WARNING_TEXT,
        other => other,
    }
}

/// Whether `COLORTERM` advertises 24-bit color. Conventional check: the value
/// contains `truecolor` or `24bit`. Pure (env value passed in) so it is
/// unit-testable.
fn colorterm_is_truecolor(colorterm: &str) -> bool {
    colorterm.contains("truecolor") || colorterm.contains("24bit")
}

/// Read `COLORTERM` from the environment and classify it via
/// `colorterm_is_truecolor`. Absent / unset `COLORTERM` is treated as
/// non-truecolor.
fn terminal_supports_truecolor() -> bool {
    std::env::var("COLORTERM")
        .map(|v| colorterm_is_truecolor(&v))
        .unwrap_or(false)
}

/// Agent messages render with no leading marker — the active-agent
/// indicator in the chrome and the thinking-chip (when present)
/// already signal who's talking, and the bullet was visual noise that
/// accumulated as the conversation grew. Kept as an empty constant so
/// callers don't sprinkle string literals.
const AGENT_BULLET: &str = "";

/// Left-side horizontal padding applied to every agent message line, so
/// the text doesn't sit flush against the terminal edge now that the
/// bullet is gone. Continuation lines inherit this indent; the first
/// line gets it too, with the timestamp reserve on the right side.
/// Public so the copy path can strip exactly this much from each
/// row of an agent-message selection.
pub const AGENT_INDENT: usize = 2;
/// Right-side margin that transcript timestamps keep clear, matching the
/// transcript hover inset.
pub(crate) const TIMESTAMP_RIGHT_MARGIN: usize = AGENT_INDENT;

/// One rendered history entry. The chrome assembles a flat list of
/// `Rendered` for the chat pane, then uses each entry's `chip_row` to
/// build a click-targeting map: a click on row N of the pane resolves
/// to whichever entry has `chip_row == Some(row_within_entry)`.
#[derive(Clone)]
pub struct Rendered {
    pub lines: Vec<Line<'static>>,
    /// First row occupied by parser-rendered Markdown message content. `None`
    /// for non-message entries and when Markdown rendering is disabled.
    pub(crate) copy_body_start: Option<RenderedCopy>,
    /// Index of the row within `lines` that is the clickable "thinking"
    /// chip. `None` for entries without one (everything except a
    /// `HistoryEntry::Agent` with non-empty reasoning).
    pub chip_row: Option<usize>,
    /// One bool per row in `lines`. `true` for rows that are a
    /// soft-wrap continuation of the prior logical line — the copy
    /// path joins these with a space instead of a newline so pasted
    /// agent text reconstructs the original paragraph rather than
    /// preserving the screen-level wraps.
    pub continuations: Vec<bool>,
    /// One optional call index per row in `lines`, for per-call hover and
    /// click targeting inside a tool box.
    pub tool_call_rows: Vec<Option<usize>>,
    /// Relative row ranges for scrollable expanded tool-call result windows.
    pub tool_result_scroll_regions: Vec<ToolResultScrollRegion>,
    /// Relative row range for a scrollable expanded reasoning window.
    pub reasoning_scroll_region: Option<ReasoningScrollRegion>,
    /// Where the clickable `[Pin]`/`[Unpin]` and `[Fork]` mouse controls
    /// landed within `lines`, when drawn. `None` when the entry is not
    /// pinnable, the controls are hidden (mouse mode off), or the line was
    /// too narrow to fit any control. Carries the seq + exact row/column
    /// ranges so hit-tests route only visible glyphs.
    pub pin_region: Option<PinRegion>,
    /// Where the clickable response-performance metric chip landed, when
    /// drawn. `None` when the entry has no performance snapshot or the
    /// chip was hidden (mouse mode off); below the minimum supported
    /// width (24 columns) the `Agent` label itself remains the chip's
    /// union hit target. Carries exact row/column ranges so hit-tests
    /// route only visible glyphs; clicking toggles
    /// `performance_expanded` only.
    pub metric_region: Option<MetricRegion>,
}

#[derive(Clone)]
pub(crate) struct RenderedCopy {
    pub(crate) start: usize,
    pub(crate) cells: Vec<Vec<Option<u32>>>,
    pub(crate) newlines_before: Vec<usize>,
    pub(crate) incomplete: Vec<bool>,
    pub(crate) fragments: std::rc::Rc<Vec<markdown::CopyFragment>>,
}

impl RenderedCopy {
    fn from_block(start: usize, block: &crate::tui::message_block::MessageBlock) -> Self {
        Self {
            start,
            cells: block.copy_cells.clone(),
            newlines_before: block.copy_newlines_before.clone(),
            incomplete: block.copy_incomplete.clone(),
            fragments: std::rc::Rc::clone(&block.copy_fragments),
        }
    }
}

fn prepend_copy_rows(copy: &mut RenderedCopy, count: usize) {
    copy.cells
        .splice(0..0, std::iter::repeat_n(Vec::new(), count));
    copy.newlines_before
        .splice(0..0, std::iter::repeat_n(0, count));
    copy.incomplete
        .splice(0..0, std::iter::repeat_n(false, count));
}

/// The render-time placement + state of a pinnable message's fork/pin controls,
/// computed by the chrome from `App` state and threaded into
/// [`render_entry`] (`pinned-messages`). When controls should be drawn, they
/// ride the message's own first line (agent) or top border row (user) — not a
/// separate prefix row.
#[derive(Debug, Clone, Copy, Hash)]
pub struct PinControl {
    /// The message's pin seq (the DB key the toggle operates on).
    pub seq: i64,
    /// `true` → the message is currently pinned (`[Unpin]`, yellow);
    /// `false` → not pinned (`[Pin]`, grey). Drives the state-dependent
    /// control width (7 vs 5).
    pub pinned: bool,
    /// `true` → draw the clickable `[Pin]`/`[Unpin]` plus `[Fork]` controls
    /// (mouse mode on). When `false` the controls are omitted and reserve no
    /// width.
    pub show_control: bool,
    /// `true` → this entry is the `/pin` or `/fork` pick-mode selection; the
    /// `▶` arrow attaches immediately left of the inline/corner controls.
    pub is_pick: bool,
}

impl PinControl {
    /// Width (columns) the `[Pin]`/`[Unpin]` glyphs occupy when shown,
    /// else 0. State-dependent: 7 for `[Unpin]`, 5 for `[Pin]`.
    fn pin_control_width(&self) -> usize {
        if self.show_control {
            crate::tui::pins_overlay::pin_control_width(self.pinned) as usize
        } else {
            0
        }
    }

    fn fork_control_width(&self) -> usize {
        if self.show_control {
            crate::tui::pins_overlay::fork_control_width() as usize
        } else {
            0
        }
    }

    fn control_width(&self, include_fork: bool) -> usize {
        let pin = self.pin_control_width();
        if include_fork && self.fork_control_width() > 0 && pin > 0 {
            self.fork_control_width() + 1 + pin
        } else {
            pin
        }
    }
}

/// Where drawn controls landed: their shared seq plus the row (within an
/// entry's `lines`) and half-open column ranges for visible glyphs. The
/// chrome offsets `row` by the entry's position in the scroll buffer and
/// hit-tests only the recorded ranges.
#[derive(Debug, Clone, Copy)]
pub struct PinRegion {
    pub seq: i64,
    pub row: usize,
    pub col_start: u16,
    pub col_end: u16,
    pub fork_col_start: Option<u16>,
    pub fork_col_end: Option<u16>,
}

/// Where the clickable `Agent` statistics chip landed. Clicking toggles only
/// `performance_expanded` — never the reasoning `expanded` field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetricRegion {
    /// The row ranges (within an entry's `lines`) and their column
    /// ranges that form the union hit target of the metric chip.
    pub rows: Vec<MetricRow>,
}

/// One row of the metric chip's hit target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetricRow {
    pub row: usize,
    pub col_start: u16,
    pub col_end: u16,
}

#[cfg(test)]
thread_local! {
    static RENDER_ENTRY_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_render_entry_call_count() {
    RENDER_ENTRY_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn render_entry_call_count() -> usize {
    RENDER_ENTRY_CALLS.with(std::cell::Cell::get)
}

fn centered_note(text: &str) -> Line<'static> {
    Line::from(Span::styled(
        format!("⋯ {text} ⋯"),
        Style::default()
            .fg(crate::tui::theme::DISABLED)
            .add_modifier(Modifier::ITALIC),
    ))
    .centered()
}

/// Trailing marker row for an agent turn the user cut short: a short `⎯`
/// rule in warning yellow plus the muted explanation. Rendered as the last
/// row of the frozen [`HistoryEntry::Agent`] entry so an interrupted turn
/// reads as stopped rather than settled.
fn interrupted_marker_line() -> Line<'static> {
    Line::from(vec![
        Span::styled("  ⎯ ", Style::default().fg(crate::tui::theme::YELLOW)),
        Span::styled(
            "Stopped — you sent a message".to_string(),
            Style::default().fg(FOG),
        ),
    ])
}

fn render_plain(line: &str) -> Rendered {
    let lines = if let Some((from, body)) = line
        .strip_prefix("steer from ")
        .and_then(|rest| rest.split_once(": "))
    {
        vec![
            Line::from(Span::styled(
                format!("  ▸ {from}"),
                Style::default().fg(FOG),
            )),
            Line::from(Span::styled(format!("  {body}"), Style::default().fg(FOG))),
        ]
    } else {
        vec![centered_note(line)]
    };
    let continuations = vec![false; lines.len()];
    Rendered {
        lines,
        copy_body_start: None,
        chip_row: None,
        continuations,
        tool_call_rows: Vec::new(),
        tool_result_scroll_regions: Vec::new(),
        reasoning_scroll_region: None,
        pin_region: None,
        metric_region: None,
    }
}

/// Render one history entry. The renderer receives the area's `width`
/// so it can right-align timestamps and pad the user-message
/// background to the full width.
///
/// `thinking` controls how reasoning is surfaced:
/// - [`ThinkingDisplay::Condensed`] (default) — chip, expands on `Ctrl+T`
/// - [`ThinkingDisplay::Hidden`] — drop the chip and reasoning entirely
/// - [`ThinkingDisplay::Verbose`] — force expanded regardless of the stored flag
///
/// `elided` is the live set of wire-side elided `original_event_id`s
/// (`call_id`s). A boxed tool call whose `call_id` is in the set has its
/// result body dimmed in the expanded view to signal it's out of the
/// model's context — full text stays visible (GOALS §14). A render-time
/// lookup against live prune state, not a persisted flag.
///
/// `preflight_dots_ms` drives the animated `Preflight…` indicator on a
/// preflight-pending user row (implementation note):
/// the dots cycle off the same continuously-advancing clock the busy/Thinking
/// spinner uses ([`thinking_dots`]). Ignored for non-pending rows.
// `pin` is one more independent render input (pin-control state for a
// pinnable User/Agent entry); other entry kinds ignore it.
#[allow(clippy::too_many_arguments)]
pub fn render_entry(
    entry: &HistoryEntry,
    width: u16,
    thinking: ThinkingDisplay,
    md: MarkdownOpts,
    diff_style: cockpit_config::extended::DiffStyle,
    emojis: bool,
    file_icons: bool,
    elided: &HashSet<String>,
    preflight_dots_ms: u128,
    pin: Option<PinControl>,
) -> Rendered {
    #[cfg(test)]
    RENDER_ENTRY_CALLS.with(|calls| calls.set(calls.get() + 1));

    match entry {
        HistoryEntry::User {
            text,
            cleaned,
            expanded,
            timestamp,
            preflight_pending,
            persist_failed,
            ..
        } => {
            // Request-preflight display: while preflight is still running for
            // this optimistically-shown row, the border slot hosts the animated
            // `Preflight…` indicator over the user's ORIGINAL text (not a reveal
            // toggle — there's no cleaned form yet)
            // (implementation note). Once it resolves:
            // a cleaned form shows it + a `⚙ preflighted` chip (revealing the
            // original); no cleaned form renders exactly as today.
            let preflight_chip;
            let (body, chip, toggleable): (&str, Option<&str>, bool) = if *preflight_pending {
                preflight_chip = format!("Preflight{}", thinking_dots(preflight_dots_ms));
                (text.as_str(), Some(preflight_chip.as_str()), false)
            } else {
                match cleaned {
                    Some(c) if !*expanded => (c.as_str(), Some("⚙ preflighted"), true),
                    Some(_) => (text.as_str(), Some("⚙ preflighted · original"), true),
                    None => (text.as_str(), None, false),
                }
            };
            let (lines, mut continuations, pin_region, copy_body_start) =
                render_user(body, *timestamp, width, md.user, chip, *persist_failed, pin);
            if !md.user && lines.len() > 3 {
                for continuation in continuations.iter_mut().take(lines.len() - 1).skip(2) {
                    *continuation = true;
                }
            }
            // The chip sits immediately below the You role header. Only a
            // resolved cleaned form makes it the clickable reveal toggle.
            let chip_row = toggleable.then_some(1);
            Rendered {
                lines,
                copy_body_start,
                chip_row,
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                pin_region,
                metric_region: None,
            }
        }
        HistoryEntry::Plain { line } => render_plain(line),
        HistoryEntry::CommandError { line } => Rendered {
            lines: vec![Line::from(vec![
                Span::styled(" ".repeat(AGENT_INDENT), Style::default().fg(ERROR_TEXT)),
                Span::styled(line.clone(), Style::default().fg(ERROR_TEXT)),
            ])],
            chip_row: None,
            continuations: vec![false],
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region: None,
            copy_body_start: None,
            pin_region: None,
            metric_region: None,
        },
        HistoryEntry::Maintenance { line } => Rendered {
            lines: vec![centered_note(line)],
            chip_row: None,
            continuations: vec![false],
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region: None,
            copy_body_start: None,
            pin_region: None,
            metric_region: None,
        },
        HistoryEntry::InterruptDecision { decision } => {
            let lines = render_interrupt_decision(decision);
            let continuations = vec![false; lines.len()];
            Rendered {
                lines,
                chip_row: None,
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::UserNote {
            text, timestamp, ..
        } => {
            let lines = render_user_note(text, *timestamp, width);
            let continuations = vec![false; lines.len()];
            Rendered {
                lines,
                chip_row: None,
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::SkillAutoInjected { name, reason } => {
            let (lines, continuations) = render_skill_auto_injected(name, reason.as_deref(), width);
            Rendered {
                lines,
                chip_row: None,
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::InferenceError {
            summary,
            detail,
            expanded,
        } => {
            // Red, mirroring a failed tool call's treatment. The first row is
            // the click target; expanded rows reveal persisted provider detail.
            let avail = (width as usize).saturating_sub(2 * AGENT_INDENT);
            let summary = if *expanded {
                summary.clone()
            } else {
                truncate(summary, avail)
            };
            let mut lines = vec![Line::from(vec![
                Span::styled(" ".repeat(AGENT_INDENT), Style::default().fg(ERROR_TEXT)),
                Span::styled(summary, Style::default().fg(ERROR_TEXT)),
            ])];
            if *expanded {
                let body = if detail.trim().is_empty() {
                    "No additional inference detail was recorded.".to_string()
                } else {
                    detail.clone()
                };
                for raw in body.lines() {
                    lines.push(Line::from(vec![
                        Span::raw(" ".repeat(AGENT_INDENT)),
                        Span::styled(raw.to_string(), Style::default().fg(ERROR_TEXT).dim()),
                    ]));
                }
            }
            let continuations = vec![false; lines.len()];
            Rendered {
                lines,
                chip_row: Some(0),
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::BackupWarning { line } | HistoryEntry::InferenceWarning { line } => {
            Rendered {
                // Yellow display-only banners; backup fallback and slow-stream
                // warnings remain semantically distinct in history/export.
                lines: vec![Line::from(Span::styled(
                    line.clone(),
                    Style::default().fg(WARNING_TEXT),
                ))],
                chip_row: None,
                continuations: vec![false],
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::Diff {
            tool: _,
            path,
            old,
            new,
            verb,
        } => {
            let lines = crate::tui::diff::render_diff(
                *verb, path, old, new, diff_style, width, emojis, file_icons,
            );
            let continuations = vec![false; lines.len()];
            Rendered {
                lines,
                chip_row: None,
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::ToolBox {
            calls,
            view_offset,
            follow,
        } => render_toolbox(
            calls,
            *view_offset,
            *follow,
            width,
            emojis,
            file_icons,
            elided,
        ),
        HistoryEntry::ToolLine {
            tool,
            summary,
            icon_path,
            state,
            ..
        } => {
            let icon_path = icon_path.as_deref().unwrap_or(summary);
            // Standalone styled one-liner, indented to align with box
            // content (the box's sidebar+space is 2 cells wide).
            let avail = tool_summary_budget(tool, width as usize, 2, emojis, file_icons, icon_path);
            let mut spans = vec![Span::raw("  ".to_string())];
            spans.extend(tool_line_spans(
                tool,
                &truncate(summary, avail),
                *state,
                emojis,
                file_icons,
                icon_path,
            ));
            Rendered {
                lines: vec![Line::from(spans)],
                chip_row: None,
                continuations: vec![false],
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::LocalCommand {
            label,
            output,
            failed,
        } => {
            let mut lines: Vec<Line<'static>> = Vec::new();
            lines.push(if *failed {
                Line::from(Span::styled(
                    format!("⋯ {label} ⋯"),
                    Style::default()
                        .fg(ERROR_TEXT)
                        .add_modifier(Modifier::ITALIC),
                ))
                .centered()
            } else {
                centered_note(label)
            });
            for raw in output.lines() {
                lines.push(Line::from(vec![
                    Span::raw("  ".to_string()),
                    Span::styled(raw.to_string(), Style::default().fg(TOOL_OUTPUT_FG)),
                ]));
            }
            let continuations = vec![false; lines.len()];
            Rendered {
                lines,
                chip_row: None,
                continuations,
                tool_call_rows: Vec::new(),
                tool_result_scroll_regions: Vec::new(),
                reasoning_scroll_region: None,
                copy_body_start: None,
                pin_region: None,
                metric_region: None,
            }
        }
        HistoryEntry::Subagent {
            parent,
            child,
            label,
            model_trusted,
            routing,
            spawned_at,
            outcome,
            expanded,
            ..
        } => render_subagent(SubagentRenderInput {
            parent,
            child,
            label,
            model_trusted: *model_trusted,
            routing,
            spawned_at: *spawned_at,
            outcome: outcome.as_ref(),
            expanded: *expanded,
            width,
        }),
        HistoryEntry::CompactBoundary {
            predecessor_short_id,
            seed_tool_count,
            seed_tool_tokens,
            source,
            trigger_ctx_pct,
            tokens_before,
            tokens_after,
            turns_summarized,
            tail_kept,
            tail_trimmed,
            handoff,
            expanded,
            result_offset,
        } => render_compaction(
            predecessor_short_id,
            *seed_tool_count,
            *seed_tool_tokens,
            source,
            *trigger_ctx_pct,
            *tokens_before,
            *tokens_after,
            *turns_summarized,
            *tail_kept,
            *tail_trimmed,
            handoff.as_deref(),
            *expanded,
            *result_offset,
            width,
        ),
        HistoryEntry::Agent {
            name,
            text,
            reasoning,
            timestamp,
            expanded,
            reasoning_offset,
            think_duration,
            performance,
            performance_expanded,
            interrupted,
            ..
        } => {
            let effective_reasoning: &str = match thinking {
                ThinkingDisplay::Hidden => "",
                ThinkingDisplay::Condensed | ThinkingDisplay::Verbose => reasoning,
            };
            let effective_expanded = match thinking {
                ThinkingDisplay::Verbose => true,
                ThinkingDisplay::Condensed => *expanded,
                ThinkingDisplay::Hidden => false,
            };
            let mut rendered = render_agent(
                name,
                text,
                effective_reasoning,
                *timestamp,
                effective_expanded,
                *reasoning_offset,
                *think_duration,
                width,
                md.agent,
                pin,
                performance.clone(),
                *performance_expanded,
            );
            if *interrupted {
                rendered.lines.push(interrupted_marker_line());
                rendered.continuations.push(false);
            }
            rendered
        }
    }
}

#[derive(Clone, Default)]
pub struct PendingRenderState {
    width: u16,
    body_width: usize,
    source_len: usize,
    commit_byte: usize,
    committed_lines: Vec<Rc<Line<'static>>>,
    committed_display_key: Option<(usize, u16)>,
    committed_display: Vec<Rc<Line<'static>>>,
    rendered_lines: Vec<Line<'static>>,
}

impl PendingRenderState {
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn commit_byte(&self) -> usize {
        self.commit_byte
    }
}

#[derive(Clone, Debug, Default)]
pub struct PendingRender {
    pub committed: Vec<Rc<Line<'static>>>,
    pub tail: Vec<Line<'static>>,
}

impl PendingRender {
    pub fn into_lines(self) -> Vec<Line<'static>> {
        self.committed
            .into_iter()
            .map(|line| line.as_ref().clone())
            .chain(self.tail)
            .collect()
    }

    pub fn lines(&self) -> Vec<Line<'static>> {
        self.committed
            .iter()
            .map(|line| line.as_ref().clone())
            .chain(self.tail.iter().cloned())
            .collect()
    }
}

impl IntoIterator for PendingRender {
    type Item = Line<'static>;
    type IntoIter = std::vec::IntoIter<Line<'static>>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_lines().into_iter()
    }
}

impl PartialEq<Vec<Line<'static>>> for PendingRender {
    fn eq(&self, other: &Vec<Line<'static>>) -> bool {
        self.lines() == *other
    }
}

pub fn render_pending_incremental(
    msg: &PendingMsg,
    width: u16,
    state: &mut PendingRenderState,
) -> PendingRender {
    if !msg.reasoning.trim().is_empty() {
        state.reset();
        return PendingRender {
            committed: Vec::new(),
            tail: render_pending(msg, width),
        };
    }
    if msg.text.trim().is_empty() {
        state.reset();
        return PendingRender::default();
    }

    let body_width = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
    if state.width != width || state.body_width != body_width || msg.text.len() < state.source_len {
        state.reset();
        state.width = width;
        state.body_width = body_width;
    }

    if state.source_len == msg.text.len()
        && (!state.committed_display.is_empty() || !state.rendered_lines.is_empty())
    {
        return pending_render_with_cursor(
            state.committed_display.clone(),
            state.rendered_lines.clone(),
        );
    }

    let new_commit = stable_pending_commit_byte(&msg.text);
    if new_commit < state.commit_byte || !msg.text.is_char_boundary(new_commit) {
        state.reset();
        state.width = width;
        state.body_width = body_width;
    }

    if new_commit > state.commit_byte {
        let committed = &msg.text[state.commit_byte..new_commit];
        if !committed.trim().is_empty() {
            if state.commit_byte > 0 && !state.committed_lines.is_empty() {
                state.committed_lines.push(Rc::new(Line::default()));
            }
            state.committed_lines.extend(
                render_markdown_message_block(
                    committed,
                    body_width,
                    0,
                    0,
                    Style::default().fg(INK),
                )
                .lines
                .into_iter()
                .map(Rc::new),
            );
        }
        state.commit_byte = new_commit;
        state.committed_display_key = None;
    }

    let tail = &msg.text[state.commit_byte..];
    if state.committed_display_key != Some((state.commit_byte, width)) {
        let markdown_lines: Vec<Line<'static>> = state
            .committed_lines
            .iter()
            .map(|line| line.as_ref().clone())
            .collect();
        state.committed_display = if markdown_lines.is_empty() {
            Vec::new()
        } else {
            render_pending_markdown_lines(markdown_lines, msg.timestamp, width)
                .into_iter()
                .map(Rc::new)
                .collect()
        };
        state.committed_display_key = Some((state.commit_byte, width));
    }

    let mut tail_markdown_lines: Vec<Line<'static>> = Vec::new();
    if !tail.trim().is_empty() {
        if state.commit_byte > 0 && !state.committed_display.is_empty() {
            tail_markdown_lines.push(Line::default());
        }
        tail_markdown_lines.extend(
            render_markdown_message_block(tail, body_width, 0, 0, Style::default().fg(INK)).lines,
        );
    }

    state.source_len = msg.text.len();
    state.rendered_lines = render_pending_tail_lines(
        tail_markdown_lines,
        msg.timestamp,
        width,
        state.committed_display.is_empty(),
    );
    pending_render_with_cursor(
        state.committed_display.clone(),
        state.rendered_lines.clone(),
    )
}

fn pending_render_with_cursor(
    mut committed: Vec<Rc<Line<'static>>>,
    tail: Vec<Line<'static>>,
) -> PendingRender {
    if tail.is_empty()
        && let Some(last) = committed.last_mut()
    {
        let mut line = last.as_ref().clone();
        line.spans
            .push(Span::styled("▌", Style::default().fg(USER_BORDER_FG)));
        *last = Rc::new(line);
    }
    PendingRender { committed, tail }
}

fn stable_pending_commit_byte(text: &str) -> usize {
    let mut in_fence: Option<char> = None;
    let mut line_start = 0usize;
    let mut boundaries = Vec::new();
    let mut link_refs_seen = 0usize;
    for line in text.split_inclusive('\n') {
        let line_end = line_start + line.len();
        let trimmed = line.trim_end_matches('\n').trim();
        if in_fence.is_none() && is_link_reference_definition_start(line) {
            link_refs_seen += 1;
        }
        if let Some(fence) = markdown_fence_marker(trimmed) {
            match in_fence {
                Some(open) if open == fence => in_fence = None,
                None => in_fence = Some(fence),
                _ => {}
            }
        }
        if in_fence.is_none() && trimmed.is_empty() {
            boundaries.push((line_end, link_refs_seen));
        }
        line_start = line_end;
    }

    for (boundary, refs_at_boundary) in boundaries.into_iter().rev() {
        if refs_at_boundary == link_refs_seen {
            return boundary;
        }
    }

    0
}

fn markdown_fence_marker(trimmed_line: &str) -> Option<char> {
    let mut chars = trimmed_line.chars();
    let first = chars.next()?;
    if first != '`' && first != '~' {
        return None;
    }
    let mut count = 1usize;
    for ch in chars {
        if ch == first {
            count += 1;
        } else {
            break;
        }
    }
    (count >= 3).then_some(first)
}

fn is_link_reference_definition_start(line: &str) -> bool {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut rest = line;
    let leading_spaces = rest.bytes().take_while(|byte| *byte == b' ').count();
    if leading_spaces > 3 {
        return false;
    }
    rest = &rest[leading_spaces..];
    let Some(label) = rest.strip_prefix('[') else {
        return false;
    };

    let mut escaped = false;
    let mut label_len = 0usize;
    for (idx, ch) in label.char_indices() {
        if escaped {
            label_len += ch.len_utf8();
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                label_len += ch.len_utf8();
                escaped = true;
            }
            '[' => return false,
            ']' => {
                return label_len > 0 && label[idx + ch.len_utf8()..].starts_with(':');
            }
            _ => label_len += ch.len_utf8(),
        }
    }
    false
}

fn render_pending_markdown_lines(
    markdown_lines: Vec<Line<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
) -> Vec<Line<'static>> {
    let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
    let body = layout_markdown_message_lines(
        markdown_lines,
        body_content_w,
        0,
        AGENT_INDENT,
        Style::default().fg(INK),
    );
    let header = vec![
        Span::styled("▌ ", Style::default().fg(USER_BORDER_FG)),
        Span::styled(
            "Agent",
            Style::default()
                .fg(USER_BORDER_FG)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    let mut out = Vec::with_capacity(1 + body.lines.len());
    out.push(render_first_line_with_pin_and_timestamp(header, timestamp, width, None).0);
    out.extend(body.lines);
    out
}

fn render_pending_tail_lines(
    markdown_lines: Vec<Line<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
    include_header: bool,
) -> Vec<Line<'static>> {
    if include_header {
        let mut lines = render_pending_markdown_lines(markdown_lines, timestamp, width);
        if let Some(last) = lines.last_mut() {
            last.spans
                .push(Span::styled("▌", Style::default().fg(USER_BORDER_FG)));
        }
        return lines;
    }
    if markdown_lines.is_empty() {
        return Vec::new();
    }
    let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
    let mut lines: Vec<Line<'static>> = layout_markdown_message_lines(
        markdown_lines,
        body_content_w,
        0,
        AGENT_INDENT,
        Style::default().fg(INK),
    )
    .lines
    .into_iter()
    .collect();
    if let Some(last) = lines.last_mut() {
        last.spans
            .push(Span::styled("▌", Style::default().fg(USER_BORDER_FG)));
    }
    lines
}

/// Render an in-flight pending message: the agent's text as it streams
/// in. The live "Thinking…"/status readout (with its elapsed clock) is
/// owned by the status indicator (`render_status_indicator`), so before
/// any text arrives this renders nothing — keeping a single live status
/// line on screen instead of a duplicate "Thinking" in two places.
/// While reasoning is streaming it renders live: the `Thinking` header
/// (FOG + italic) followed by the reasoning body wrapped to the pane
/// (DISABLED + italic), above the answer body once it starts.
pub fn render_pending(msg: &PendingMsg, width: u16) -> Vec<Line<'static>> {
    // Text streaming in — same rendering as Agent (no expansion in
    // live state; reasoning shown after finalization). Markdown is
    // rendered live mid-stream via the same path the finalized entry
    // uses: the whole pending buffer is re-parsed each frame. Partial
    // inline syntax (`**`/`_`/`` ` ``/`[` with no closer yet) restyles
    // the trailing text until the closer arrives, and an open ` ``` `
    // fence streams as a code block to end-of-input — accepted, since
    // it matches what the finalized render will show.
    let mut lines = render_agent(
        &msg.name,
        &msg.text,
        "",
        msg.timestamp,
        false,
        0,
        None,
        width,
        true,
        None,
        None,
        false,
    )
    .lines;
    if !msg.reasoning.trim().is_empty() {
        // Live thinking block: the `Thinking` header plus the reasoning
        // streamed so far, wrapped to `width - 2` (DISABLED + italic),
        // matching the reference's live-thought rows. It sits above the
        // answer body and is never treated as the agent's body text.
        let reasoning_w = (width as usize).saturating_sub(2).max(1);
        let mut reasoning_rows = vec![Line::from(Span::styled(
            "  Thinking",
            Style::default()
                .fg(THINKING_FG)
                .add_modifier(Modifier::ITALIC),
        ))];
        for chunk in wrap_with_reserved_first_line(&msg.reasoning, reasoning_w, 0) {
            reasoning_rows.push(Line::from(Span::styled(
                format!("  {chunk}"),
                Style::default()
                    .fg(REASONING_FG)
                    .add_modifier(Modifier::ITALIC),
            )));
        }
        lines.splice(1..1, reasoning_rows);
    }
    if msg.text.trim().is_empty() && msg.reasoning.trim().is_empty() {
        lines.push(Line::from(Span::styled(
            "  · · ·",
            Style::default().fg(crate::tui::theme::FOG),
        )));
    } else if let Some(last) = lines.last_mut() {
        last.spans
            .push(Span::styled("▌", Style::default().fg(USER_BORDER_FG)));
    }
    lines
}

/// User message: a barred `You` role header followed by barred body rows.
fn render_user(
    text: &str,
    timestamp: DateTime<Local>,
    width: u16,
    markdown: bool,
    chip: Option<&str>,
    failed: bool,
    pin: Option<PinControl>,
) -> (
    Vec<Line<'static>>,
    Vec<bool>,
    Option<PinRegion>,
    Option<RenderedCopy>,
) {
    let accent = if failed { ERROR_TEXT } else { USER_BORDER_FG };
    let header_spans = vec![
        Span::styled("▌ ", Style::default().fg(accent)),
        Span::styled(
            "You",
            Style::default()
                .fg(crate::tui::theme::INK)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    let (header, pin_region) =
        render_first_line_with_pin_and_timestamp(header_spans, timestamp, width, pin);
    let body_width = usize::from(width).saturating_sub(2).max(1);
    let body = if markdown {
        render_markdown_message_block(text, body_width, 0, 0, Style::default().fg(INK))
    } else {
        let chunks = wrap_with_reserved_first_line(text, body_width, 0);
        MessageBlock {
            lines: chunks
                .iter()
                .cloned()
                .map(|chunk| Line::from(Span::styled(chunk, Style::default().fg(INK))))
                .collect(),
            continuations: (0..chunks.len()).map(|index| index > 0).collect(),
            copy_cells: Vec::new(),
            copy_newlines_before: Vec::new(),
            copy_incomplete: Vec::new(),
            copy_fragments: Rc::new(Vec::new()),
        }
    };
    let chip_rows = usize::from(chip.is_some());
    let mut copy = markdown.then(|| RenderedCopy::from_block(1 + chip_rows, &body));
    if let Some(copy) = copy.as_mut() {
        for cells in &mut copy.cells {
            cells.splice(0..0, [None, None]);
        }
    }
    let mut lines = vec![header];
    let mut continuations = vec![false];
    if let Some(chip) = chip {
        lines.push(Line::from(vec![
            Span::styled("▌ ", Style::default().fg(accent)),
            Span::styled(
                chip.to_string(),
                Style::default().fg(crate::tui::theme::FOG),
            ),
        ]));
        continuations.push(false);
    }
    for (line, continuation) in body.lines.into_iter().zip(body.continuations) {
        let mut spans = vec![Span::styled("▌ ", Style::default().fg(accent))];
        spans.extend(line.spans);
        lines.push(Line::from(spans).style(Style::default().fg(INK)));
        continuations.push(continuation);
    }
    if lines.len() == 1 + chip_rows {
        lines.push(Line::from(Span::styled("▌ ", Style::default().fg(accent))));
        continuations.push(false);
    }
    (lines, continuations, pin_region, copy)
}

fn render_interrupt_decision(decision: &cockpit_proto::InterruptDecision) -> Vec<Line<'static>> {
    let prefix = if decision.permission {
        "approval"
    } else {
        "decision"
    };
    let prefix_style = Style::default()
        .fg(if decision.permission {
            PLAN_YELLOW
        } else {
            INFO_TEXT
        })
        .add_modifier(Modifier::BOLD);
    let answer_style = if decision.cancelled {
        Style::default()
            .fg(WARNING_TEXT)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(SUCCESS_TEXT)
    };
    decision
        .lines
        .iter()
        .map(|line| {
            let answer = if decision.cancelled {
                "dismissed"
            } else {
                line.answer.as_str()
            };
            Line::from(vec![
                Span::styled(" ".repeat(AGENT_INDENT), Style::default().fg(INFO_TEXT)),
                Span::styled(prefix.to_string(), prefix_style),
                Span::styled(": ", Style::default().fg(INFO_TEXT)),
                Span::styled(line.prompt.clone(), Style::default().fg(INFO_TEXT)),
                Span::styled(" → ", Style::default().fg(FOG)),
                Span::styled(answer.to_string(), answer_style),
            ])
        })
        .collect()
}

/// A user-authored session-history note (`/note <text>`). Rendered as a
/// muted, dim "note to self" block — deliberately distinct from a normal
/// user message (no rounded bubble) and from assistant output: a `note to
/// self` header row (timestamp right-aligned) followed by the wrapped note
/// text, each line prefixed with a muted `┊ ` bar. Long notes wrap; nothing
/// is truncated. Display/export only; never model context. Emoji-free so it
/// reads identically with glyphs on or off.
fn render_user_note(text: &str, timestamp: DateTime<Local>, width: u16) -> Vec<Line<'static>> {
    let muted = Style::default().fg(FOG);
    let muted_italic = muted.add_modifier(Modifier::ITALIC);
    let area = width as usize;
    let ts = format_timestamp(timestamp);

    let mut out: Vec<Line<'static>> = Vec::new();

    // Header: a "note to self" label, timestamp right-aligned.
    let label = "note to self";
    let used = label.width();
    let right_margin = TIMESTAMP_RIGHT_MARGIN.min(area.saturating_sub(used + TIMESTAMP_WIDTH + 1));
    let pad = area.saturating_sub(used + TIMESTAMP_WIDTH + 1 + right_margin);
    out.push(Line::from(vec![
        Span::styled(label.to_string(), muted_italic),
        Span::raw(" ".repeat(pad + 1)),
        Span::styled(ts, Style::default().fg(TIMESTAMP_FG)),
        Span::raw(" ".repeat(right_margin)),
    ]));

    // Body: each wrapped line prefixed with a muted `┊ ` bar.
    let bar = "┊ ";
    let text_w = area.saturating_sub(bar.width()).max(1);
    let wrapped = wrap_with_reserved_first_line(text, text_w, 0);
    for chunk in wrapped {
        out.push(Line::from(vec![
            Span::styled(bar.to_string(), muted),
            Span::styled(chunk, muted),
        ]));
    }

    out
}

/// An auto-injected skill row: `/{name} · injected by agent`
/// (implementation note). The skill id
/// renders **bold** in the subagent accent (the same orange used for
/// delegations — "the agent did this"), the trailing `· injected by agent`
/// label muted italic. Distinct from a user-typed `/{name}` (a `skill`
/// tool-call row, no label) and from the agent's own `skill` tool call.
///
/// When `reason` is present (implementation note) a
/// second indented muted-italic tree-style sub-line `  └ <reason>` is
/// rendered beneath, wrapping like other muted text — each wrapped row past
/// the first marked a continuation. When `reason` is `None` only the first
/// line is returned (today's behavior, unchanged). Returns the lines plus a
/// parallel continuation-flag vector for the copy path / spill math.
fn render_skill_auto_injected(
    name: &str,
    reason: Option<&str>,
    width: u16,
) -> (Vec<Line<'static>>, Vec<bool>) {
    let accent = Style::default()
        .fg(SUBAGENT_ORANGE)
        .add_modifier(Modifier::BOLD);
    let muted_italic = Style::default().fg(FOG).add_modifier(Modifier::ITALIC);

    let mut lines: Vec<Line<'static>> = vec![Line::from(vec![
        Span::styled(format!("/{name}"), accent),
        Span::styled(" · injected by agent".to_string(), muted_italic),
    ])];
    let mut continuations: Vec<bool> = vec![false];

    if let Some(reason) = reason.map(str::trim).filter(|r| !r.is_empty()) {
        // Tree-style indented sub-line: `  └ ` prefix, the reason wrapping
        // into the remaining width as muted italic. Continuation rows align
        // under the reason text (a blank prefix of the same width).
        let prefix = "  └ ";
        let area = width as usize;
        let text_w = area.saturating_sub(prefix.width()).max(1);
        let wrapped = wrap_with_reserved_first_line(reason, text_w, 0);
        let indent = " ".repeat(prefix.width());
        for (i, chunk) in wrapped.into_iter().enumerate() {
            let lead = if i == 0 {
                prefix.to_string()
            } else {
                indent.clone()
            };
            lines.push(Line::from(vec![
                Span::styled(lead, muted_italic),
                Span::styled(chunk, muted_italic),
            ]));
            // Every sub-line row is a soft-wrap continuation of the logical
            // skill row (copy rejoins with a space, not a newline).
            continuations.push(true);
        }
    }

    (lines, continuations)
}

/// Minimum terminal width for response-header controls (metric chip,
/// detail, timestamp, fork, pin, overflow menu). Below this the grouped
/// controls collapse as one block — no glyphs are painted and no hit
/// targets are recorded — while the role header (label, plus the
/// timestamp whenever it fits) and the body stay readable.
const RESPONSE_HEADER_MIN_WIDTH: u16 = 24;

/// Format TTFT (time-to-first-token) for the compact chip per the spec:
/// seconds rounded half-up to one decimal below 10; a carry to 10.0+
/// renders integer seconds half-up. Examples: 3000ms->`3`, 9949ms->`9.9`,
/// 9950ms->`10`, 10500ms->`11`.
fn format_ttft(ttft_ms: u64) -> String {
    let secs = ttft_ms as f64 / 1000.0;
    if secs < 10.0 {
        // One decimal, rounded half-up.
        let rounded = (secs * 10.0 + 0.5).floor() / 10.0;
        // If rounding carried to 10.0+, render as integer.
        if rounded >= 10.0 {
            format!("{}", (secs + 0.5).floor() as u64)
        } else if rounded == rounded.floor() {
            // 3000ms -> 3.0 -> "3" (spec example: integer when decimal is .0).
            format!("{}", rounded as u64)
        } else {
            format!("{:.1}", rounded)
        }
    } else {
        // Integer seconds, rounded half-up.
        format!("{}", (secs + 0.5).floor() as u64)
    }
}

/// Format TPS (tokens-per-second) for the compact chip per the spec:
/// `displayed_tokens * 1_000 / generation_ms`, rounded half-up to an
/// integer (53.5->`54`). Returns `None` when `generation_ms` is zero
/// (no TPS snapshot).
fn format_tps(perf: &ResponsePerformance) -> Option<String> {
    if perf.generation_ms == 0 {
        return None;
    }
    let tps = perf.displayed_tokens * 1000 / perf.generation_ms;
    // Round half-up: check the remainder.
    let remainder = (perf.displayed_tokens * 1000) % perf.generation_ms;
    let rounded = if remainder * 2 >= perf.generation_ms {
        tps + 1
    } else {
        tps
    };
    Some(format!("{rounded}"))
}

/// Style for the response-metadata chip.
fn metric_chip_style() -> Style {
    Style::default()
        .fg(crate::tui::theme::BRASS)
        .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
}

/// Agent reply: `• text...` with timestamp right-aligned, optional
/// indented reasoning trailing when expanded. The agent name is *not*
/// rendered per-line — the active-agent indicator in the chrome is the
/// canonical place. Returns the row-index of the clickable thinking
/// chip (if any) so callers can build a hit map.
// Args are independent render inputs with no natural grouping; bundling
// them into a struct would only add construction noise at every call site.
#[allow(clippy::too_many_arguments)]
fn render_agent(
    name: &str,
    text: &str,
    reasoning: &str,
    timestamp: DateTime<Local>,
    expanded: bool,
    reasoning_offset: usize,
    _think_duration: Option<Duration>,
    width: u16,
    markdown: bool,
    pin: Option<PinControl>,
    performance: Option<ResponsePerformance>,
    performance_expanded: bool,
) -> Rendered {
    let bullet_width: usize = AGENT_INDENT
        + if AGENT_BULLET.is_empty() {
            0
        } else {
            AGENT_BULLET.width() + 1 // bullet + space
        };
    let indent_span = || Span::raw(" ".repeat(AGENT_INDENT));
    let has_text = !text.trim().is_empty();
    let has_reasoning = !reasoning.trim().is_empty();
    // Pin/Fork and the timestamp live on the role header, so body rows need no
    // right-edge chrome reservation.
    // Filled in when the role header draws the clickable action group.
    let agent_style = crate::tui::chrome::chip_style(
        Style::default()
            .fg(USER_BORDER_FG)
            .add_modifier(Modifier::BOLD),
        performance_expanded,
    );
    let header_spans = vec![
        Span::styled("▌ ", Style::default().fg(USER_BORDER_FG)),
        Span::styled("Agent", agent_style),
    ];
    let (header, header_pin_region) = render_first_line_with_pin_and_timestamp(
        header_spans,
        timestamp,
        width,
        // Below RESPONSE_HEADER_MIN_WIDTH the grouped controls collapse as
        // one block — no `[Pin]`/`[Fork]` glyphs are painted and no hit
        // targets are recorded, so the controls are never rendered dead.
        // The role header (label + timestamp when it fits) stays readable.
        if width >= RESPONSE_HEADER_MIN_WIDTH {
            pin
        } else {
            None
        },
    );
    let mut pin_region = header_pin_region;
    let has_metrics = performance
        .as_ref()
        .is_some_and(|snapshot| format_tps(snapshot).is_some());
    let mut metric_region = (has_metrics && width >= 7).then(|| MetricRegion {
        rows: vec![MetricRow {
            row: 0,
            col_start: 2,
            col_end: 7,
        }],
    });
    let mut copy_body_start: Option<RenderedCopy> = None;

    let mut out: Vec<Line<'static>> = vec![header.clone()];
    // Parallel to `out`: `conts[i]` is `true` when row `i` is a
    // soft-wrap continuation of the previous logical line. The copy
    // path uses this to rejoin soft-wraps with a space instead of a
    // newline.
    let mut conts: Vec<bool> = vec![false];
    let mut chip_row = None;
    let mut reasoning_scroll_region: Option<ReasoningScrollRegion> = None;

    // Agent statistics are opened from the `Agent` label itself, matching the
    // reference transcript. No second compact stats label is inserted.
    let metric_text: Option<String> = None;

    // Below the minimum supported width for response-header controls, the
    // grouped controls (metric detail, timestamp, fork, pin, overflow menu)
    // collapse as one block: no control glyphs are painted and no hit
    // targets are recorded, so nothing renders dead. The role header —
    // `Agent` label plus the timestamp whenever it fits — and the body
    // stay readable at every width; the complete interactive header
    // returns after resize to 24 columns or wider.
    if width < RESPONSE_HEADER_MIN_WIDTH {
        let mut out: Vec<Line<'static>> = vec![header];
        let mut conts: Vec<bool> = vec![false];
        let mut body_copy: Option<RenderedCopy> = None;
        let mut body_lines = Vec::new();
        let mut body_conts = Vec::new();

        // Prepare body content now, then append it after any expanded thought
        // block so narrow and wide layouts preserve the same reading order.
        let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
        if markdown && has_text {
            let body = render_markdown_message_block(
                text,
                body_content_w,
                0,
                AGENT_INDENT,
                Style::default().fg(INK),
            );
            body_copy = Some(RenderedCopy::from_block(0, &body));
            body_lines = body.lines;
            body_conts = body.continuations;
        } else if has_text {
            let wrapped = wrap_with_reserved_first_line(text, body_content_w, 0);
            let indent = " ".repeat(AGENT_INDENT);
            for (i, chunk) in wrapped.iter().enumerate() {
                body_lines.push(Line::from(Span::styled(
                    format!("{indent}{chunk}"),
                    Style::default().fg(INK),
                )));
                body_conts.push(i > 0);
            }
        }

        // Reasoning chip still renders (it's content, not header chrome).
        if has_reasoning {
            let label = if expanded {
                "▾ Thought"
            } else {
                "▸ Thought"
            }
            .to_string();
            chip_row = Some(1);
            // Insert the reasoning chip after the role header.
            let chip_line = Line::from(vec![
                Span::raw(" ".repeat(bullet_width)),
                Span::styled(label, Style::default().fg(THINKING_FG)),
            ]);
            out.insert(1, chip_line);
            conts.insert(1, false);
            // Expanded reasoning renders below the chip.
            if expanded {
                let reasoning_indent = AGENT_INDENT;
                let reasoning_w = (width as usize).saturating_sub(reasoning_indent).max(1);
                let mut reasoning_rows: Vec<(Line<'static>, bool)> = Vec::new();
                for raw_line in reasoning.lines() {
                    let chunks = if raw_line.is_empty() {
                        vec![String::new()]
                    } else {
                        wrap_with_reserved_first_line_and_prefix(raw_line, reasoning_w, 0, 0)
                    };
                    for (i, chunk) in chunks.into_iter().enumerate() {
                        reasoning_rows.push((
                            Line::from(vec![
                                Span::raw(" ".repeat(reasoning_indent)),
                                Span::styled(
                                    chunk,
                                    Style::default()
                                        .fg(REASONING_FG)
                                        .add_modifier(Modifier::ITALIC),
                                ),
                            ]),
                            i > 0,
                        ));
                    }
                }
                let window =
                    inner_scroll_window(reasoning_rows.len(), THINKING_VISIBLE, reasoning_offset);
                // The reasoning window is a single contiguous block appended
                // after the chip and before the body. `region_start` must anchor
                // to the first row of that block (the `more above` indicator
                // when present, else the first visible reasoning row) so the
                // scroll region covers only the reasoning window.
                let region_start = out.len();
                if window.more_above > 0 {
                    out.push(Line::from(vec![
                        Span::raw(" ".repeat(reasoning_indent)),
                        Span::styled(
                            format!("{} more above", window.more_above),
                            Style::default().fg(FOG),
                        ),
                    ]));
                    conts.push(false);
                }
                for (line, continuation) in reasoning_rows
                    .iter()
                    .skip(window.offset)
                    .take(window.end.saturating_sub(window.offset))
                {
                    out.push(line.clone());
                    conts.push(*continuation);
                }
                if window.more_below > 0 {
                    out.push(Line::from(vec![
                        Span::raw(" ".repeat(reasoning_indent)),
                        Span::styled(
                            format!("{} more below", window.more_below),
                            Style::default().fg(FOG),
                        ),
                    ]));
                    conts.push(false);
                }
                let region_end = out.len().saturating_sub(1);
                if window.max_offset > 0 && region_start <= region_end {
                    reasoning_scroll_region = Some(ReasoningScrollRegion {
                        row_start: region_start,
                        row_end: region_end,
                        offset: window.offset,
                        max_offset: window.max_offset,
                    });
                }
            }
        }

        let copy_body_start = body_copy.map(|mut copy| {
            copy.start = out.len();
            copy
        });
        out.extend(body_lines);
        conts.extend(body_conts);

        return Rendered {
            lines: out,
            copy_body_start,
            chip_row,
            continuations: conts,
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region,
            pin_region: None,
            metric_region,
        };
    }

    // width >= RESPONSE_HEADER_MIN_WIDTH: render the full header chrome.
    // When the agent produced reasoning, the *first* row of this entry
    // is the bullet + chip line — replacing the "Thinking…" placeholder
    // that lived there during streaming.  The timestamp lands on the
    // first actual text line (render_first_line_with_pin_and_timestamp
    // handles that naturally for the first wrapped text chunk).
    if has_reasoning {
        let label = if expanded {
            "▾ Thought"
        } else {
            "▸ Thought"
        }
        .to_string();
        chip_row = Some(out.len());
        let indent = " ".repeat(bullet_width);
        // Wrap to width minus left indent (bullet_width == AGENT_INDENT
        // since the bullet is empty) minus a matching right pad
        // (AGENT_INDENT) so body lines have symmetric breathing room.
        let text_width = (width as usize)
            .saturating_sub(bullet_width + AGENT_INDENT)
            .max(1);
        let label_width = label.width();
        // Default wrap (used for the expanded body and for wrapped[1..]
        // continuation lines in the collapsed case). The collapsed-no-
        // markdown branch will re-wrap with extra reserve so the first
        // chunk can sit beside the chip without pushing the timestamp.
        let wrapped: Vec<String> = wrap_with_reserved_first_line(text, text_width, 0);

        let mut chip_spans: Vec<Span<'static>> = vec![indent_span()];
        if !AGENT_BULLET.is_empty() {
            chip_spans.push(Span::styled(
                format!("{AGENT_BULLET} "),
                Style::default().fg(agent_color_rendered(name)),
            ));
        }
        chip_spans.push(Span::styled(label, Style::default().fg(THINKING_FG)));

        // Body content target width: full width minus left indent
        // (AGENT_INDENT) and a matching right pad (AGENT_INDENT) so
        // wrapped continuations don't go all the way to the right
        // edge.
        let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
        let (body_lines, body_conts, body_copy) = if !has_text {
            (Vec::new(), Vec::new(), None)
        } else if markdown {
            // Pre-wrap the markdown lines ourselves so ratatui's
            // Paragraph::wrap doesn't strip the indent on
            // continuation rows.
            let body = render_markdown_message_block(
                text,
                body_content_w,
                0,
                AGENT_INDENT,
                Style::default().fg(INK),
            );
            let copy = RenderedCopy::from_block(0, &body);
            (body.lines, body.continuations, Some(copy))
        } else {
            let lines = wrapped
                .iter()
                .map(|chunk| {
                    Line::from(Span::styled(
                        format!("{indent}{chunk}"),
                        Style::default().fg(INK),
                    ))
                })
                .collect::<Vec<_>>();
            // wrapped[0] starts a fresh logical line; the rest are
            // soft-wrap continuations of the agent's text.
            let conts = (0..lines.len()).map(|i| i > 0).collect();
            (lines, conts, None)
        };

        if expanded {
            // Chip alone on row 1; reasoning lines under it, nested
            // under the chip's text (column ≈ AGENT_INDENT + 2 to land
            // right after "▼ "); then the agent's text. The user reads
            // the reasoning *before* the conclusion. Long reasoning
            // lines wrap explicitly so the continuation keeps the same
            // left indent — otherwise ratatui's auto-wrap drops them
            // to column 0 and the block looks ragged.
            let (line, region, metric_row) = render_agent_body_first_line(
                chip_spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            if region.is_some() {
                pin_region = region;
            }
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
            let reasoning_indent = AGENT_INDENT;
            let reasoning_w = (width as usize).saturating_sub(reasoning_indent).max(1);
            let mut reasoning_rows: Vec<(Line<'static>, bool)> = Vec::new();
            for raw_line in reasoning.lines() {
                let chunks = if raw_line.is_empty() {
                    vec![String::new()]
                } else {
                    wrap_with_reserved_first_line_and_prefix(raw_line, reasoning_w, 0, 0)
                };
                for (i, chunk) in chunks.into_iter().enumerate() {
                    reasoning_rows.push((
                        Line::from(vec![
                            Span::raw(" ".repeat(reasoning_indent)),
                            Span::styled(
                                chunk,
                                Style::default()
                                    .fg(REASONING_FG)
                                    .add_modifier(Modifier::ITALIC),
                            ),
                        ]),
                        i > 0,
                    ));
                }
            }
            let window =
                inner_scroll_window(reasoning_rows.len(), THINKING_VISIBLE, reasoning_offset);
            let region_start = out.len();
            if window.more_above > 0 {
                out.push(Line::from(vec![
                    Span::raw(" ".repeat(reasoning_indent)),
                    Span::styled(
                        format!("{} more above", window.more_above),
                        Style::default().fg(FOG),
                    ),
                ]));
                conts.push(false);
            }
            for (line, continuation) in reasoning_rows
                .iter()
                .skip(window.offset)
                .take(window.end.saturating_sub(window.offset))
            {
                out.push(line.clone());
                conts.push(*continuation);
            }
            if window.more_below > 0 {
                out.push(Line::from(vec![
                    Span::raw(" ".repeat(reasoning_indent)),
                    Span::styled(
                        format!("{} more below", window.more_below),
                        Style::default().fg(FOG),
                    ),
                ]));
                conts.push(false);
            }
            let region_end = out.len().saturating_sub(1);
            if window.max_offset > 0 && region_start <= region_end {
                reasoning_scroll_region = Some(ReasoningScrollRegion {
                    row_start: region_start,
                    row_end: region_end,
                    offset: window.offset,
                    max_offset: window.max_offset,
                });
            }
            if let Some(mut copy) = body_copy {
                copy.start = out.len();
                prepend_copy_rows(&mut copy, out.len());
                copy_body_start = Some(copy);
            }
            out.extend(body_lines);
            conts.extend(body_conts);
        } else if markdown {
            // Collapsed + markdown: chip on its own row (folding
            // markdown spans onto the chip line is more visual jank than
            // it's worth), body markdown lines follow.
            let (line, region, metric_row) = render_agent_body_first_line(
                chip_spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            if region.is_some() {
                pin_region = region;
            }
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
            if let Some(mut copy) = body_copy {
                copy.start = out.len();
                prepend_copy_rows(&mut copy, out.len());
                copy_body_start = Some(copy);
            }
            out.extend(body_lines);
            conts.extend(body_conts);
        } else {
            // Collapsed: chip + first text chunk on the same line so
            // there's no visual blank between the chip and the answer.
            // The first chunk shares row 1 with `chip + " "` and the
            // right-edge timestamp, so re-wrap with both reserved —
            // otherwise the chunk pushes the timestamp onto row 2.
            let collapsed_first_reserve = label_width + 1;
            let collapsed_wrapped: Vec<String> =
                wrap_with_reserved_first_line(text, text_width, collapsed_first_reserve);
            let mut first_line_spans = chip_spans;
            if !collapsed_wrapped.is_empty() {
                first_line_spans.push(Span::raw(" "));
                first_line_spans.push(Span::styled(
                    collapsed_wrapped[0].clone(),
                    Style::default().fg(INK),
                ));
            }
            let (line, region, metric_row) = render_agent_body_first_line(
                first_line_spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            if region.is_some() {
                pin_region = region;
            }
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
            for chunk in collapsed_wrapped.iter().skip(1) {
                out.push(Line::from(Span::styled(
                    format!("{indent}{chunk}"),
                    Style::default().fg(INK),
                )));
                conts.push(true);
            }
        }
    } else if !has_text {
        // Empty Markdown intentionally renders one logical row. An Agent with
        // no answer text has no body, though: think-only finalized turns keep
        // just their Thought block, and the pending renderer can put its caret
        // directly on the final live-thinking row.
    } else if markdown {
        // No reasoning + markdown: emit markdown lines, attaching the
        // timestamp to the first line via right-edge padding. Every
        // line carries AGENT_INDENT on the left AND a matching right
        // pad. Pre-wrap with `wrap_lines_to_width_reserving_first` so
        // ratatui's Paragraph::wrap can't strip the indent from
        // continuation rows AND so the timestamp width is reserved on
        // the first visual row *before* wrapping — overflow then flows
        // into the normal wrap stream (filling row 2 at full width)
        // instead of being sliced off afterward as a one-word orphan.
        let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
        let body = render_markdown_message_block(
            text,
            body_content_w,
            0,
            AGENT_INDENT,
            Style::default().fg(INK),
        );
        copy_body_start = Some(RenderedCopy::from_block(out.len(), &body));
        if body.lines.is_empty() {
            let (line, region, metric_row) =
                render_agent_body_first_line(vec![], timestamp, width, pin, metric_text.as_deref());
            if region.is_some() {
                pin_region = region;
            }
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
        } else {
            // First row was already narrowed for the timestamp; attach
            // the timestamp to it and emit the rest unchanged. The
            // continuation flags from the wrap helper already mark the
            // timestamp-induced break of the first logical line as a
            // continuation (copy rejoins with a space, not a newline).
            let mut iter = body.lines.into_iter().zip(body.continuations);
            let (first, first_cont) = iter.next().expect("body non-empty");
            let (mut line, region, metric_row) = render_agent_body_first_line(
                first.spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            line.style = Style::default().fg(INK);
            if region.is_some() {
                pin_region = region;
            }
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(first_cont);
            for (line, cont) in iter {
                out.push(line);
                conts.push(cont);
            }
        }
    } else {
        // No reasoning, no markdown — text gets the standard left
        // indent and a matching right pad; the timestamp is right-
        // aligned on the first wrapped line. Wrap area is `width -
        // 2*AGENT_INDENT` so continuations leave breathing room on
        // both sides.
        let chunks = wrap_with_reserved_first_line_and_prefix(
            text,
            (width as usize)
                .saturating_sub(bullet_width + AGENT_INDENT)
                .max(1),
            0,
            0,
        );
        if chunks.is_empty() {
            let (line, region, metric_row) =
                render_agent_body_first_line(vec![], timestamp, width, pin, metric_text.as_deref());
            if region.is_some() {
                pin_region = region;
            }
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
        } else {
            for (i, chunk) in chunks.iter().enumerate() {
                if i == 0 {
                    let mut spans: Vec<Span<'static>> = vec![indent_span()];
                    if !AGENT_BULLET.is_empty() {
                        spans.push(Span::styled(
                            format!("{AGENT_BULLET} "),
                            Style::default().fg(agent_color_rendered(name)),
                        ));
                    }
                    spans.push(Span::styled(chunk.clone(), Style::default().fg(INK)));
                    let (line, region, metric_row) = render_agent_body_first_line(
                        spans,
                        timestamp,
                        width,
                        pin,
                        metric_text.as_deref(),
                    );
                    if region.is_some() {
                        pin_region = region;
                    }
                    if let Some(mr) = metric_row {
                        metric_region = Some(MetricRegion { rows: vec![mr] });
                    }
                    out.push(line);
                    conts.push(false);
                } else {
                    let indent = " ".repeat(bullet_width);
                    out.push(Line::from(Span::styled(
                        format!("{indent}{chunk}"),
                        Style::default().fg(INK),
                    )));
                    conts.push(true);
                }
            }
        }
    }

    if metric_region.is_some() && performance_expanded {
        let perf = performance.as_ref().unwrap();
        let detail_rows = [
            format!("  {:<5}  {}", "Model", name),
            format!("  {:<5}  {}s", "TTFT", format_ttft(perf.ttft_ms)),
            format!(
                "  {:<5}  {}",
                "TPS",
                format_tps(perf).unwrap_or_else(|| "-".to_string())
            ),
            format!("  {:<5}  —", "Cache"),
        ];
        let insert_at = 1.min(out.len());
        for (i, d) in detail_rows.iter().enumerate() {
            out.insert(
                insert_at + i,
                Line::from(Span::styled(
                    d.clone(),
                    Style::default().fg(crate::tui::theme::FOG),
                )),
            );
            conts.insert(insert_at + i, false);
        }
        let inserted = detail_rows.len();
        if let Some(cr) = chip_row.as_mut()
            && *cr >= insert_at
        {
            *cr += inserted;
        }
        if let Some(copy) = copy_body_start.as_mut() {
            copy.start += inserted;
        }
        if let Some(region) = reasoning_scroll_region.as_mut() {
            region.row_start += inserted;
            region.row_end += inserted;
        }
    }

    Rendered {
        lines: out,
        copy_body_start,
        chip_row,
        continuations: conts,
        tool_call_rows: Vec::new(),
        tool_result_scroll_regions: Vec::new(),
        reasoning_scroll_region,
        pin_region,
        metric_region,
    }
}

/// Light grey for the subagent response body.
const SUBAGENT_BODY_FG: Color = FOG;
/// Style for a delegated child agent's display name in history rows.
///
/// Shared with chrome's active-agent slot so the bottom status color follows
/// the same source of truth as the live/settled subagent history headers.
pub fn subagent_child_name_style(_name: &str) -> Style {
    Style::default()
        .fg(crate::tui::theme::INK)
        .add_modifier(Modifier::BOLD)
}

/// Render a [`HistoryEntry::Subagent`].
///
/// While the child runs (`outcome` is `None`) this is a single live
/// line — `{parent} delegated to {child}… (elapsed)` — whose animated
/// ellipses and ticking timer reuse the main working-span mechanism
/// ([`thinking_dots_padded`] + [`format_status_elapsed`], fed
/// `spawned_at.elapsed()`); the chat pane re-renders every event-loop
/// tick, so the values advance on screen without a second timer.
///
/// Once the child reports, the line becomes a `{child} worked for
/// {duration}` header (or `failed after` on error) followed by the
/// response body: markdown-rendered and tinted light grey. Interactive
/// responses keep an active `▌` bar; background reports use a quiet indent.
/// The body is truncated to
/// [`SUBAGENT_PREVIEW_LINES`] leading lines with a clickable `…
/// (expand)` affordance (the returned `chip_row`) unless `expanded`.
/// An empty report renders the header alone with no quoted block.
///
/// The child name uses bold ink; the parent uses the default style.
struct SubagentRenderInput<'a> {
    parent: &'a str,
    child: &'a str,
    label: &'a str,
    model_trusted: bool,
    routing: &'a SubagentRoutingChips,
    spawned_at: std::time::Instant,
    outcome: Option<&'a SubagentOutcome>,
    expanded: bool,
    width: u16,
}

fn render_subagent(input: SubagentRenderInput<'_>) -> Rendered {
    let SubagentRenderInput {
        parent,
        child,
        label,
        model_trusted,
        routing,
        spawned_at,
        outcome,
        expanded,
        width,
    } = input;
    let name_style = subagent_child_name_style(child);
    let bar_color = if label == "interactive" { TEAL } else { FOG };
    // Display the user-facing label; the internal `child` name still drives
    // settling/matching elsewhere.
    let child = agent_display_label(child);
    let batch_label = if label.is_empty() || label == "default" {
        None
    } else {
        Some(label)
    };

    let Some(outcome) = outcome else {
        // Running: one live line. Dots + elapsed advance every tick
        // because the renderer reads `spawned_at.elapsed()` fresh each
        // frame — the same source the working-span indicator uses.
        let elapsed = spawned_at.elapsed();
        let dots = thinking_dots_padded(elapsed.as_millis());
        let mut spans = vec![Span::styled("▌ ", Style::default().fg(bar_color))];
        if let Some(label) = batch_label {
            spans.push(Span::styled(
                format!("{label} "),
                Style::default().fg(FOG).add_modifier(Modifier::BOLD),
            ));
        }
        spans.extend([
            Span::styled(
                format!("{parent} delegated to "),
                Style::default().add_modifier(Modifier::UNDERLINED),
            ),
            Span::styled(
                child.to_string(),
                name_style.add_modifier(Modifier::UNDERLINED),
            ),
            Span::styled(
                format!("{dots} {}", format_status_elapsed(elapsed)),
                Style::default().add_modifier(Modifier::ITALIC),
            ),
        ]);
        append_subagent_routing_chips(&mut spans, model_trusted, routing);
        let mut lines = Vec::new();
        if label == "interactive" {
            lines.push(Line::from(Span::styled(
                format!("  ─ {child}"),
                Style::default().fg(DISABLED),
            )));
        }
        lines.push(Line::from(spans));
        let continuations = vec![false; lines.len()];
        return Rendered {
            lines,
            chip_row: None,
            continuations,
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region: None,
            copy_body_start: None,
            pin_region: None,
            metric_region: None,
        };
    };

    // Settled: header line, child name in bold ink.
    let verb = if outcome.failed {
        "failed after"
    } else {
        "worked for"
    };
    let duration = format_compact_duration(outcome.duration);
    let mut header_spans = vec![Span::styled("▌ ", Style::default().fg(bar_color))];
    if let Some(label) = batch_label {
        header_spans.push(Span::styled(
            format!("{label} ✓ "),
            Style::default().fg(FOG).add_modifier(Modifier::BOLD),
        ));
    }
    header_spans.extend([
        Span::styled(child.to_string(), name_style),
        Span::raw(format!(" {verb} {duration}")),
    ]);
    append_subagent_routing_chips(&mut header_spans, model_trusted, routing);
    let header = Line::from(header_spans);

    let mut out: Vec<Line<'static>> = Vec::new();
    if label == "interactive" {
        out.push(Line::from(Span::styled(
            format!("  ─ {child}"),
            Style::default().fg(DISABLED),
        )));
    }
    out.push(header);
    let mut conts: Vec<bool> = vec![false; out.len()];
    let mut chip_row = None;

    if let Some(status) = &outcome.status {
        out.push(Line::from(vec![
            Span::styled("▌ ", Style::default().fg(bar_color)),
            Span::styled(
                status.clone(),
                Style::default()
                    .fg(WARNING_TEXT)
                    .add_modifier(Modifier::ITALIC),
            ),
        ]));
        conts.push(false);
    }

    if outcome.report.trim().is_empty() {
        return Rendered {
            lines: out,
            chip_row,
            continuations: conts,
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region: None,
            copy_body_start: None,
            pin_region: None,
            metric_region: None,
        };
    }

    // Interactive children retain an active left bar; settled background
    // reports use only a quiet body indent.
    let bar = if label == "interactive" { "▌ " } else { "  " };
    let body_w = (width as usize).saturating_sub(bar.width()).max(1);
    let (wrapped, _conts) =
        wrap_lines_to_width(markdown::render_with_width(&outcome.report, body_w), body_w);

    // Collapsed: show the leading lines, then a clickable expand chip.
    // Expanded: show the whole body. (Mirrors the toolbox collapse
    // affordance — a single click toggles `expanded`.)
    let (visible, truncated) = if expanded || wrapped.len() <= SUBAGENT_PREVIEW_LINES {
        (wrapped.as_slice(), false)
    } else {
        (&wrapped[..SUBAGENT_PREVIEW_LINES], true)
    };

    for line in visible {
        let mut spans: Vec<Span<'static>> = vec![Span::styled(
            bar.to_string(),
            Style::default().fg(bar_color),
        )];
        for s in &line.spans {
            spans.push(Span::styled(
                s.content.to_string(),
                s.style.patch(Style::default().fg(SUBAGENT_BODY_FG)),
            ));
        }
        out.push(Line::from(spans));
        conts.push(false);
    }

    if truncated {
        let hidden = wrapped.len() - SUBAGENT_PREVIEW_LINES;
        chip_row = Some(out.len());
        out.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                format!("… ({hidden} more — click to expand)"),
                Style::default()
                    .fg(SUBAGENT_BODY_FG)
                    .add_modifier(Modifier::DIM | Modifier::UNDERLINED),
            ),
        ]));
        conts.push(false);
    } else if expanded && wrapped.len() > SUBAGENT_PREVIEW_LINES {
        // Expanded: offer a collapse affordance so it's reversible.
        chip_row = Some(out.len());
        out.push(Line::from(vec![
            Span::raw("  "),
            Span::styled(
                "(click to collapse)".to_string(),
                Style::default()
                    .fg(SUBAGENT_BODY_FG)
                    .add_modifier(Modifier::DIM | Modifier::UNDERLINED),
            ),
        ]));
        conts.push(false);
    }

    Rendered {
        lines: out,
        chip_row,
        continuations: conts,
        tool_call_rows: Vec::new(),
        tool_result_scroll_regions: Vec::new(),
        reasoning_scroll_region: None,
        copy_body_start: None,
        pin_region: None,
        metric_region: None,
    }
}

fn append_subagent_routing_chips(
    spans: &mut Vec<Span<'static>>,
    model_trusted: bool,
    routing: &SubagentRoutingChips,
) {
    let trust = if model_trusted { "t" } else { "u" };
    let model = routing
        .model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let trust_chip = match model {
        Some(model) => format!("[{model} · {trust}]"),
        None => format!("[{trust}]"),
    };
    spans.push(Span::raw(" "));
    spans.push(Span::styled(
        trust_chip,
        Style::default().fg(FOG).add_modifier(Modifier::DIM),
    ));
    if let Some(location) = routing
        .location
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!("[{location}]"),
            Style::default().fg(FOG).add_modifier(Modifier::DIM),
        ));
    }
    if let Some(fallback) = routing
        .fallback
        .as_deref()
        .filter(|value| !value.is_empty() && *value != "none")
    {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!("[fallback:{fallback}]"),
            Style::default().fg(FOG).add_modifier(Modifier::DIM),
        ));
    }
}

pub fn resolve_tool_presentation(
    tool: &str,
    args: &serde_json::Value,
    mcp_child: Option<&McpChildMeta>,
) -> ToolPresentation {
    if let Some(meta) = mcp_child {
        if meta.builtin == Some(true)
            && meta.server.as_deref() == Some(cockpit_core::mcp::builtin::BUILTIN_SERVER_ID)
            && let Some(presentation) = cockpit_core::mcp::builtin::presentation(tool, args)
        {
            return presentation;
        }
        return mcp_child_presentation(tool, args, meta);
    }
    cockpit_core::engine::tool::known_tool_presentation(tool, args)
}

fn mcp_child_presentation(
    tool: &str,
    args: &serde_json::Value,
    meta: &McpChildMeta,
) -> ToolPresentation {
    let server_tool = meta
        .server
        .as_deref()
        .filter(|server| !server.is_empty())
        .map(|server| format!("{server}.{tool}"))
        .unwrap_or_else(|| tool.to_string());
    let (args_summary, args_full) = cockpit_core::engine::tool::readable_args(
        args.get("args")
            .filter(|_| meta.kind.as_deref() == Some("invoke"))
            .unwrap_or(args),
    );
    let summary = match meta.kind.as_deref() {
        Some("cap") => args
            .get("unrecorded_dispatches")
            .and_then(serde_json::Value::as_i64)
            .map(|count| format!("{count} unrecorded MCP dispatches"))
            .unwrap_or_else(|| "MCP child dispatches truncated".to_string()),
        Some("search") => {
            if args_summary.is_empty() {
                "search".to_string()
            } else {
                format!("search {args_summary}")
            }
        }
        Some("describe") => format!("describe {server_tool}"),
        Some("invoke") if args_summary.is_empty() => server_tool.clone(),
        Some("invoke") => format!("{server_tool} {args_summary}"),
        _ if args_summary.is_empty() => server_tool.clone(),
        _ => format!("{server_tool} {args_summary}"),
    };
    let full_input = if args_full.is_empty() {
        server_tool.clone()
    } else {
        format!("{server_tool}\n{args_full}")
    };
    ToolPresentation::with_parts(None, "mcp", summary, full_input)
}

/// `(glyph, label)` for a tool's rendered line. `glyph` is an emoji
/// padded to a fixed display-column width ([`TOOL_GLYPH_COLUMN`]) when
/// `emojis` is on, empty otherwise; `label` is the verb shown bold
/// before the `:`. File-type icons are off here — callers that have a
/// path use [`tool_glyph_label_for`].
pub fn tool_glyph_label(tool: &str, emojis: bool) -> (String, String) {
    tool_glyph_label_for(tool, emojis, false, None)
}

/// Like [`tool_glyph_label`], but when `file_icons` is on, write/edit tools use
/// a Nerd Font file-type icon derived from `path`.
/// Never re-resolves presentation from args (`Value::Null`).
pub(crate) fn tool_glyph_label_for(
    tool: &str,
    emojis: bool,
    file_icons: bool,
    path: Option<&str>,
) -> (String, String) {
    let presentation = resolve_tool_presentation(tool, &serde_json::Value::Null, None);
    let file_icon = file_icons
        .then(|| crate::tui::file_icons::glyph_for_tool(tool, path))
        .flatten();
    format_tool_glyph_label(&presentation, emojis, file_icon)
}

fn tool_call_glyph_label(call: &ToolCall, emojis: bool, file_icons: bool) -> (String, String) {
    let presentation = resolve_tool_presentation(
        &call.tool,
        &serde_json::Value::Null,
        call.mcp_child.as_ref(),
    );
    // Write/edit calls derive the file-type icon from their rendered path
    // summary.
    let file_icon = file_icons
        .then(|| crate::tui::file_icons::glyph_for_tool(&call.tool, Some(&call.summary)))
        .flatten();
    format_tool_glyph_label(&presentation, emojis, file_icon)
}

fn format_tool_glyph_label(
    presentation: &ToolPresentation,
    emojis: bool,
    file_icon: Option<&'static str>,
) -> (String, String) {
    let glyph = file_icon.unwrap_or(presentation.glyph.unwrap_or(""));
    let label = if emojis {
        if presentation.label == "unlock" {
            &presentation.label
        } else {
            presentation
                .label
                .strip_suffix("unlock")
                .or_else(|| presentation.label.strip_suffix("lock"))
                .filter(|label| !label.is_empty())
                .unwrap_or(&presentation.label)
        }
    } else {
        &presentation.label
    };
    let show_glyph = file_icon.is_some() || (emojis && !glyph.is_empty());
    let glyph = if show_glyph && !glyph.is_empty() {
        // Pad to a fixed display width so every label lines up at the
        // same column, rather than relying on each glyph being exactly
        // one column short of `TOOL_GLYPH_COLUMN`. Nerd Font file icons
        // are single-cell; emoji glyphs are width 2.
        let pad = TOOL_GLYPH_COLUMN.saturating_sub(glyph.width()).max(1);
        format!("{glyph}{}", " ".repeat(pad))
    } else {
        String::new()
    };
    (glyph, label.to_string())
}

/// Distinct semantic colour for the pre-dispatch verification state. Kept
/// separate from the `running` yellow, terminal-white, and error-red so a
/// `verifying` row is never confused with any of them.
const VERIFYING_TEXT: Color = Color::Magenta;

fn tool_state_style(state: ToolCallState) -> Style {
    match state {
        ToolCallState::Verifying => Style::default().fg(VERIFYING_TEXT),
        ToolCallState::Processing => Style::default().fg(WARNING_TEXT),
        ToolCallState::Success => Style::default().fg(crate::tui::theme::FOG),
        ToolCallState::Failed => Style::default().fg(ERROR_TEXT),
        ToolCallState::BadCall => Style::default().fg(ERROR_TEXT).add_modifier(Modifier::BOLD),
    }
}

/// Tools whose output is worth showing when a box is expanded. `read` shows its
/// captured, capped tool output so the user can inspect exactly what the model
/// saw; `unlock` remains input-only. Public so the event handler can avoid
/// storing outputs it will never display.
pub fn tool_shows_output(tool: &str) -> bool {
    !matches!(tool, "unlock")
}

fn tool_uses_read_output_renderer(tool: &str) -> bool {
    matches!(
        tool,
        "read"
            // Historical display only: pre-rename persisted sessions used this
            // retired verb name in tool-call rows.
            | "readlock"
    )
}

/// Spans for one tool-call line: `[glyph] label: summary`, the label
/// bold and the whole line tinted by `state`.
fn tool_call_spans(
    call: &ToolCall,
    text: &str,
    emojis: bool,
    file_icons: bool,
    progress_width: Option<usize>,
) -> Vec<Span<'static>> {
    let (_, label) = tool_call_glyph_label(call, emojis, file_icons);
    let style = tool_state_style(call.state);
    let mut spans = vec![Span::styled("▸ ", style)];
    spans.push(Span::styled(label, style));
    if !text.is_empty() {
        spans.push(Span::raw("  ".to_string()));
        spans.push(Span::styled(text.to_string(), style));
    }
    if let Some(suffix) = progress_width.and_then(|width| tool_progress_suffix(call, width)) {
        spans.push(Span::styled(suffix, style));
    }
    // Accessible label so the pre-dispatch verification state reads in the
    // no-colour projection too (colour is supplementary).
    if call.state == ToolCallState::Verifying {
        spans.push(Span::styled(" Verifying".to_string(), style));
    }
    spans
}

fn tool_line_spans(
    tool: &str,
    text: &str,
    state: ToolCallState,
    emojis: bool,
    file_icons: bool,
    path: &str,
) -> Vec<Span<'static>> {
    let (_, label) = tool_glyph_label_for(tool, emojis, file_icons, Some(path));
    let style = tool_state_style(state);
    let mut spans = vec![Span::styled("▸ ", style)];
    spans.push(Span::styled(label, style));
    if !text.is_empty() {
        spans.push(Span::raw("  ".to_string()));
        spans.push(Span::styled(text.to_string(), style));
    }
    if state == ToolCallState::Verifying {
        spans.push(Span::styled(" Verifying".to_string(), style));
    }
    spans
}

/// Display columns available for a collapsed summary after the left
/// `indent`, the glyph, the bold `label`, and the `": "` separator.
fn tool_summary_budget(
    tool: &str,
    width: usize,
    indent: usize,
    emojis: bool,
    file_icons: bool,
    path: &str,
) -> usize {
    let (glyph, label) = tool_glyph_label_for(tool, emojis, file_icons, Some(path));
    let prefix = indent + glyph.width() + label.width() + 2;
    width.saturating_sub(prefix).max(8)
}

fn tool_call_summary_budget(
    call: &ToolCall,
    width: usize,
    indent: usize,
    emojis: bool,
    file_icons: bool,
) -> usize {
    let (glyph, label) = tool_call_glyph_label(call, emojis, file_icons);
    let prefix = indent + glyph.width() + label.width() + 2;
    let available = width.saturating_sub(prefix);
    if let Some(suffix) = tool_progress_suffix(call, available) {
        available.saturating_sub(suffix.width())
    } else {
        available.max(8)
    }
}

fn tool_call_progress_available(
    call: &ToolCall,
    width: usize,
    indent: usize,
    emojis: bool,
    file_icons: bool,
) -> usize {
    let (glyph, label) = tool_call_glyph_label(call, emojis, file_icons);
    let prefix = indent + glyph.width() + label.width() + 2;
    width.saturating_sub(prefix)
}

fn tool_progress_suffix(call: &ToolCall, available: usize) -> Option<String> {
    let progress = call.progress.as_ref()?;
    if call.state != ToolCallState::Processing || progress.total == 0 {
        return None;
    }
    let done = progress.done.min(progress.total);
    let counts = format!(
        "{}/{}",
        format_progress_count(done),
        format_progress_count(progress.total)
    );
    let unit = progress.unit.trim();
    let pct = if progress.total == 0 {
        0.0
    } else {
        done as f64 * 100.0 / progress.total as f64
    };
    let full = if unit.is_empty() {
        format!(" [{}] {counts}", render_bar(pct, 10))
    } else {
        format!(" [{}] {counts} {unit}", render_bar(pct, 10))
    };
    if full.width() <= available {
        return Some(full);
    }
    if !unit.is_empty() {
        let no_bar = format!(" {counts} {unit}");
        if no_bar.width() <= available {
            return Some(no_bar);
        }
    }
    let counts_only = format!(" {counts}");
    (counts_only.width() <= available).then_some(counts_only)
}

fn format_progress_count(n: u64) -> String {
    let raw = n.to_string();
    let first = raw.len() % 3;
    let mut out = String::with_capacity(raw.len() + raw.len() / 3);
    for (idx, ch) in raw.chars().enumerate() {
        if idx > 0 && (idx == first || (idx > first && (idx - first).is_multiple_of(3))) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Truncate `s` to `max` display columns with a trailing `…` when it
/// overflows. Measures and cuts on display columns (not chars), so a
/// trailing wide grapheme can't push the line one column past `max`.
fn truncate(s: &str, max: usize) -> String {
    if s.width() <= max {
        return s.to_string();
    }
    // Reserve one column for the `…`. Accumulate chars until adding the
    // next would exceed the budget, measuring each char's display width.
    let budget = max.saturating_sub(1);
    let mut out = String::new();
    let mut used = 0usize;
    for c in s.chars() {
        let w = c.to_string().width();
        if used + w > budget {
            break;
        }
        out.push(c);
        used += w;
    }
    out.push('…');
    out
}

/// Take the longest leading prefix of `s` whose display width is `<=
/// max` columns. At least one char is always taken (so a wide grapheme
/// wider than `max` still makes progress) to guarantee termination of
/// hard-slice loops.
fn take_to_width(s: &str, max: usize) -> String {
    let mut out = String::new();
    let mut used = 0usize;
    for c in s.chars() {
        let w = c.to_string().width();
        if !out.is_empty() && used + w > max {
            break;
        }
        out.push(c);
        used += w;
    }
    out
}

/// Topmost visible call index for a collapsed [`HistoryEntry::ToolBox`].
/// `follow` pins to the last [`TOOLBOX_VISIBLE`] calls; otherwise the
/// stored `view_offset` (clamped) wins. Public so the scroll handler
/// can compute the same window.
pub fn toolbox_top(len: usize, view_offset: usize, follow: bool) -> usize {
    if len <= TOOLBOX_VISIBLE {
        return 0;
    }
    let max_offset = len - TOOLBOX_VISIBLE;
    if follow {
        max_offset
    } else {
        view_offset.min(max_offset)
    }
}

fn push_toolbox_content_row(
    content: &mut Vec<Vec<Span<'static>>>,
    tool_call_rows: &mut Vec<Option<usize>>,
    spans: Vec<Span<'static>>,
    call_index: Option<usize>,
) {
    content.push(spans);
    tool_call_rows.push(call_index);
}

fn wrap_line_with_hanging_indent(
    line: Line<'static>,
    max_width: usize,
    continuation_indent: usize,
    indent_style: Style,
) -> Vec<Vec<Span<'static>>> {
    if max_width == 0 {
        return vec![line.spans];
    }
    let mut rows = Vec::new();
    let mut remaining = line.spans;
    let mut first = true;
    let indent = continuation_indent.min(max_width.saturating_sub(1));
    loop {
        let budget = if first {
            max_width
        } else {
            max_width.saturating_sub(indent).max(1)
        };
        let (mut head, tail) = slice_spans_at_width(remaining, budget);
        if !first && indent > 0 {
            let mut row = vec![Span::styled(" ".repeat(indent), indent_style)];
            row.append(&mut head);
            rows.push(row);
        } else {
            rows.push(head);
        }
        first = false;
        match tail {
            Some(t) => remaining = t,
            None => break,
        }
    }
    rows
}

fn push_wrapped_toolbox_input_row(
    content: &mut Vec<Vec<Span<'static>>>,
    tool_call_rows: &mut Vec<Option<usize>>,
    line: Line<'static>,
    call_index: usize,
    body_width: usize,
    continuation_indent: usize,
    indent_style: Style,
) {
    for spans in wrap_line_with_hanging_indent(line, body_width, continuation_indent, indent_style)
    {
        push_toolbox_content_row(content, tool_call_rows, spans, Some(call_index));
    }
}

/// Render a [`HistoryEntry::ToolBox`]: a light-grey rounded sidebar with
/// the tool-call lines inside it. When every call is collapsed, shows up
/// to [`TOOLBOX_VISIBLE`] calls (windowed by scroll/follow). Expanded
/// calls render their full input and an independently scrollable result
/// window, while neighboring calls stay as one-line summaries.
fn render_toolbox(
    calls: &[ToolCall],
    view_offset: usize,
    follow: bool,
    width: u16,
    emojis: bool,
    file_icons: bool,
    elided: &HashSet<String>,
) -> Rendered {
    let mut content: Vec<Vec<Span<'static>>> = Vec::new();
    let mut tool_call_rows: Vec<Option<usize>> = Vec::new();
    let mut result_regions: Vec<ToolResultScrollRegion> = Vec::new();
    let any_expanded = calls.iter().any(|call| call.expanded);
    let call_body_width = (width as usize).saturating_sub(2).max(1);

    let child_count = |parent: &ToolCall| -> usize {
        calls
            .iter()
            .filter(|candidate| {
                candidate
                    .mcp_child
                    .as_ref()
                    .is_some_and(|meta| meta.parent_call_id == parent.call_id)
            })
            .count()
    };
    let render_collapsed_call = |call: &ToolCall| {
        let is_child = call.mcp_child.is_some();
        let indent = if is_child { 4 } else { 2 };
        let summary = if call.tool == "mcp" {
            let count = child_count(call);
            if count > 0 {
                format!("{count} MCP dispatch{}", if count == 1 { "" } else { "es" })
            } else {
                call.summary.clone()
            }
        } else {
            call.summary.clone()
        };
        let progress_width =
            tool_call_progress_available(call, width as usize, indent, emojis, file_icons);
        let budget = tool_call_summary_budget(call, width as usize, indent, emojis, file_icons);
        let mut spans = Vec::new();
        if is_child {
            spans.push(Span::raw("  ".to_string()));
        }
        spans.extend(tool_call_spans(
            call,
            &truncate(&summary, budget),
            emojis,
            file_icons,
            Some(progress_width),
        ));
        if elided.contains(&call.call_id) {
            spans.push(Span::styled(
                "  (pruned)".to_string(),
                Style::default().fg(FOG),
            ));
        }
        spans
    };

    if any_expanded {
        for (call_index, call) in calls.iter().enumerate() {
            if !call.expanded {
                push_toolbox_content_row(
                    &mut content,
                    &mut tool_call_rows,
                    render_collapsed_call(call),
                    Some(call_index),
                );
                continue;
            }

            // A call whose wire-side body is currently elided renders its
            // expanded output dimmed (muted) to signal it's out of the
            // model's context. The full text is still shown + selectable;
            // only the color changes (GOALS §14). Render-time lookup —
            // the kept most-recent body and any engine "keep full content"
            // fallback aren't in the set, so they render normally.
            let is_elided = elided.contains(&call.call_id);
            let input_lines: Vec<&str> = call.full_input.split('\n').collect();
            let first = input_lines.first().copied().unwrap_or("");
            let child_indent = if call.mcp_child.is_some() { 2 } else { 0 };
            let progress_width = tool_call_progress_available(
                call,
                call_body_width,
                child_indent,
                emojis,
                file_icons,
            );
            let budget =
                tool_call_summary_budget(call, call_body_width, child_indent, emojis, file_icons);
            let first_text = if tool_progress_suffix(call, progress_width).is_some() {
                truncate(first, budget)
            } else {
                first.to_string()
            };
            let mut first_spans =
                tool_call_spans(call, &first_text, emojis, file_icons, Some(progress_width));
            if child_indent > 0 {
                first_spans.insert(0, Span::raw(" ".repeat(child_indent)));
            }
            if is_elided {
                first_spans.push(Span::styled(
                    "  (pruned — superseded by a newer read)".to_string(),
                    Style::default().fg(FOG),
                ));
            }
            let (glyph, label) = tool_call_glyph_label(call, emojis, file_icons);
            let label_indent = child_indent + glyph.width() + label.width() + 2;
            let input_style = tool_state_style(call.state);
            push_wrapped_toolbox_input_row(
                &mut content,
                &mut tool_call_rows,
                Line::from(first_spans),
                call_index,
                call_body_width,
                label_indent,
                input_style,
            );
            for cont in input_lines.iter().skip(1) {
                let cont_spans = if child_indent > 0 {
                    vec![
                        Span::raw(" ".repeat(child_indent)),
                        Span::styled((*cont).to_string(), input_style),
                    ]
                } else {
                    vec![Span::styled((*cont).to_string(), input_style)]
                };
                push_wrapped_toolbox_input_row(
                    &mut content,
                    &mut tool_call_rows,
                    Line::from(cont_spans),
                    call_index,
                    call_body_width,
                    child_indent,
                    input_style,
                );
            }

            if tool_shows_output(&call.tool) && !call.output.is_empty() {
                let out_style = if is_elided {
                    Style::default().fg(FOG)
                } else {
                    Style::default().fg(TOOL_OUTPUT_FG)
                };
                let output_lines = if tool_uses_read_output_renderer(&call.tool) {
                    crate::tui::read_highlight::render_read_output_lines(
                        &call.output,
                        &call.full_input,
                        out_style,
                        !is_elided,
                    )
                } else {
                    call.output
                        .split('\n')
                        .map(|out_line| {
                            Line::from(vec![Span::styled(format!("    {out_line}"), out_style)])
                        })
                        .collect::<Vec<_>>()
                };
                let (wrapped, _) = wrap_lines_to_width(output_lines, call_body_width);
                let window =
                    inner_scroll_window(wrapped.len(), TOOLCALL_RESULT_VISIBLE, call.result_offset);
                let region_start = content.len();
                if window.more_above > 0 {
                    push_toolbox_content_row(
                        &mut content,
                        &mut tool_call_rows,
                        vec![Span::styled(
                            format!("    {} more above", window.more_above),
                            Style::default().fg(FOG),
                        )],
                        Some(call_index),
                    );
                }
                for line in wrapped
                    .iter()
                    .skip(window.offset)
                    .take(window.end.saturating_sub(window.offset))
                {
                    push_toolbox_content_row(
                        &mut content,
                        &mut tool_call_rows,
                        line.spans.clone(),
                        Some(call_index),
                    );
                }
                if window.more_below > 0 {
                    push_toolbox_content_row(
                        &mut content,
                        &mut tool_call_rows,
                        vec![Span::styled(
                            format!("    {} more below", window.more_below),
                            Style::default().fg(FOG),
                        )],
                        Some(call_index),
                    );
                }
                let region_end = content.len().saturating_sub(1);
                if window.max_offset > 0 && region_start <= region_end {
                    result_regions.push(ToolResultScrollRegion {
                        call_index,
                        row_start: region_start,
                        row_end: region_end,
                        offset: window.offset,
                        max_offset: window.max_offset,
                    });
                }
            }

            // Post-result hint chip: one dim/italic line beneath the command
            // output (implementation note). There is no `recovery_kind` chip
            // on a tool-call row to nest under, so this is the single dim line
            // the spec's fallback specifies.
            if let Some(hint) = &call.hint {
                push_toolbox_content_row(
                    &mut content,
                    &mut tool_call_rows,
                    vec![Span::styled(
                        format!("    hint: {hint}"),
                        Style::default().fg(FOG).add_modifier(Modifier::ITALIC),
                    )],
                    Some(call_index),
                );
            }
        }
    } else {
        let top = toolbox_top(calls.len(), view_offset, follow);
        for (call_index, call) in calls.iter().enumerate().skip(top).take(TOOLBOX_VISIBLE) {
            push_toolbox_content_row(
                &mut content,
                &mut tool_call_rows,
                render_collapsed_call(call),
                Some(call_index),
            );
        }
    }

    if content.is_empty() {
        content.push(Vec::new());
        tool_call_rows.push(None);
    }

    let mut out: Vec<Line<'static>> = Vec::with_capacity(content.len());
    for mut spans in content {
        let mut row = vec![Span::raw("  ".to_string())];
        row.append(&mut spans);
        out.push(Line::from(row));
    }
    let continuations = vec![false; out.len()];
    Rendered {
        lines: out,
        chip_row: None,
        continuations,
        tool_call_rows,
        tool_result_scroll_regions: result_regions,
        reasoning_scroll_region: None,
        copy_body_start: None,
        pin_region: None,
        metric_region: None,
    }
}

/// Render the daemon-owned compaction record as the reference's centred
/// boundary plus a reversible summary chip.
#[allow(clippy::too_many_arguments)]
fn render_compaction(
    predecessor_short_id: &str,
    seed_tool_count: usize,
    seed_tool_tokens: u64,
    source: &str,
    trigger_ctx_pct: Option<f64>,
    tokens_before: u64,
    tokens_after: u64,
    turns_summarized: usize,
    tail_kept: usize,
    tail_trimmed: usize,
    handoff: Option<&str>,
    expanded: bool,
    _result_offset: usize,
    width: u16,
) -> Rendered {
    let ctx = trigger_ctx_pct
        .map(|pct| format!(" · ctx {pct:.1}%"))
        .unwrap_or_default();
    let notice = format!(
        "Compacted from {predecessor_short_id} · {source}{ctx} · \
         {tokens_before}→{tokens_after} tokens · {turns_summarized} turns · \
         tail {tail_kept}/{tail_trimmed} · {seed_tool_count} seed tools (~{seed_tool_tokens})"
    );
    let mut lines =
        wrap_with_reserved_first_line(&notice, usize::from(width).saturating_sub(6).max(1), 0)
            .into_iter()
            .map(|line| centered_note(&line))
            .collect::<Vec<_>>();
    let chip_row = lines.len();
    lines.push(Line::from(Span::styled(
        if expanded {
            "  [hide summary]"
        } else {
            "  [show summary]"
        },
        Style::default().fg(crate::tui::theme::FOG),
    )));
    if expanded {
        let summary = handoff.unwrap_or("");
        for row in
            wrap_with_reserved_first_line(summary, usize::from(width).saturating_sub(2).max(1), 0)
        {
            lines.push(Line::from(vec![Span::raw("  "), Span::raw(row)]));
        }
    }
    let continuations = vec![false; lines.len()];
    Rendered {
        lines,
        copy_body_start: None,
        chip_row: Some(chip_row),
        continuations,
        tool_call_rows: Vec::new(),
        tool_result_scroll_regions: Vec::new(),
        reasoning_scroll_region: None,
        pin_region: None,
        metric_region: None,
    }
}

/// Build a one-line span vec with an HH:MM timestamp right-aligned inside
/// the transcript right margin. The leading spans fill from the left;
/// padding spaces take up the slack.
fn render_first_line_timestamped(
    mut spans: Vec<Span<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
    add_timestamp: bool,
) -> Line<'static> {
    if !add_timestamp {
        return Line::from(spans);
    }
    let area = width as usize;
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    let ts = format_timestamp(timestamp);
    let right_margin = TIMESTAMP_RIGHT_MARGIN.min(area.saturating_sub(used + TIMESTAMP_WIDTH + 1));
    let needed = used + TIMESTAMP_WIDTH + 1 + right_margin;
    let pad = area.saturating_sub(needed);
    spans.push(Span::raw(" ".repeat(pad + 1)));
    spans.push(Span::styled(ts, Style::default().fg(TIMESTAMP_FG)));
    spans.push(Span::raw(" ".repeat(right_margin)));
    Line::from(spans)
}

/// Build a role header with the grouped Pin/Fork actions immediately left of
/// the right-aligned timestamp. If the complete group cannot fit, both actions
/// disappear and the timestamp remains.
fn render_first_line_with_pin_and_timestamp(
    spans: Vec<Span<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
    pin: Option<PinControl>,
) -> (Line<'static>, Option<PinRegion>) {
    let (line, region, _) =
        render_first_line_with_pin_and_timestamp_metric(spans, timestamp, width, pin, None);
    (line, region)
}

/// Agent body rows are deliberately chrome-free: the role header owns the
/// timestamp, Pin/Fork actions, and Agent stats target.
fn render_agent_body_first_line(
    spans: Vec<Span<'static>>,
    _timestamp: DateTime<Local>,
    _width: u16,
    _pin: Option<PinControl>,
    _metric_text: Option<&str>,
) -> (Line<'static>, Option<PinRegion>, Option<MetricRow>) {
    (Line::from(spans), None, None)
}

/// Like [`render_first_line_with_pin_and_timestamp`] but also places an
/// optional metric chip immediately left of the pin block. Returns the
/// line, the pin region, and the metric hit row (if the chip was placed
/// inline on this row). When the metric doesn't fit inline, the metric
/// hit row is `None` — the caller must emit a dedicated metadata row.
fn render_first_line_with_pin_and_timestamp_metric(
    mut spans: Vec<Span<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
    pin: Option<PinControl>,
    metric_text: Option<&str>,
) -> (Line<'static>, Option<PinRegion>, Option<MetricRow>) {
    let area = width as usize;
    let ts = format_timestamp(timestamp);
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    let metric_w = metric_text.map(|t| t.width()).unwrap_or(0);
    if metric_text.is_none() {
        let (line, region) =
            render_first_line_with_pin_and_timestamp_inner(spans, timestamp, width, pin);
        return (line, region, None);
    }

    let Some(p) = pin else {
        // No pin: try to place metric + timestamp.
        let right_margin =
            TIMESTAMP_RIGHT_MARGIN.min(area.saturating_sub(used + TIMESTAMP_WIDTH + 1));
        let metric_fits =
            metric_w > 0 && used + metric_w + 1 + TIMESTAMP_WIDTH + 1 + right_margin <= area;
        if metric_fits {
            let total_right = metric_w + 1 + TIMESTAMP_WIDTH + 1 + right_margin;
            let pad = area.saturating_sub(used + total_right);
            spans.push(Span::raw(" ".repeat(pad + 1)));
            let metric_start = (used + pad + 1) as u16;
            spans.push(Span::styled(
                metric_text.unwrap().to_string(),
                metric_chip_style(),
            ));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(ts, Style::default().fg(TIMESTAMP_FG)));
            spans.push(Span::raw(" ".repeat(right_margin)));
            return (
                Line::from(spans),
                None,
                Some(MetricRow {
                    row: 0,
                    col_start: metric_start,
                    col_end: metric_start + metric_w as u16,
                }),
            );
        }
        return (
            render_first_line_timestamped(spans, timestamp, width, true),
            None,
            None,
        );
    };

    let arrow_w = if p.is_pick {
        crate::tui::pins_overlay::PICK_ARROW.width() + 1
    } else {
        0
    };
    let pin_w = p.pin_control_width();
    let full_ctrl = p.control_width(true);
    let right_margin = TIMESTAMP_RIGHT_MARGIN.min(area.saturating_sub(used + TIMESTAMP_WIDTH + 1));
    let timestamp_reserve = TIMESTAMP_WIDTH + 1 + right_margin;
    let (control_w, include_fork) =
        if full_ctrl > 0 && used + arrow_w + full_ctrl + timestamp_reserve < area {
            (full_ctrl, true)
        } else if arrow_w > 0 && used + arrow_w + TIMESTAMP_WIDTH + right_margin < area {
            (0, false)
        } else {
            // No pin block fits. Try metric + timestamp only.
            let metric_fits =
                metric_w > 0 && used + metric_w + 1 + TIMESTAMP_WIDTH + 1 + right_margin <= area;
            if metric_fits {
                let total_right = metric_w + 1 + TIMESTAMP_WIDTH + 1 + right_margin;
                let pad = area.saturating_sub(used + total_right);
                spans.push(Span::raw(" ".repeat(pad + 1)));
                let metric_start = (used + pad + 1) as u16;
                spans.push(Span::styled(
                    metric_text.unwrap().to_string(),
                    metric_chip_style(),
                ));
                spans.push(Span::raw(" "));
                spans.push(Span::styled(ts, Style::default().fg(TIMESTAMP_FG)));
                spans.push(Span::raw(" ".repeat(right_margin)));
                return (
                    Line::from(spans),
                    None,
                    Some(MetricRow {
                        row: 0,
                        col_start: metric_start,
                        col_end: metric_start + metric_w as u16,
                    }),
                );
            }
            return (
                render_first_line_timestamped(spans, timestamp, width, true),
                None,
                None,
            );
        };
    let pin_block = arrow_w + control_w + usize::from(control_w > 0);

    // Check if metric fits inline: metric + space + pin_block + space + ts + margin.
    let metric_fits_inline = metric_w > 0
        && used + metric_w + 1 + pin_block + TIMESTAMP_WIDTH + 1 + right_margin <= area;

    if metric_fits_inline {
        // Layout: ...content... [pad] [metric] [space] [pin_block] [space] [ts] [margin]
        let total_right = metric_w + 1 + pin_block + TIMESTAMP_WIDTH + 1 + right_margin;
        let pad = area.saturating_sub(used + total_right);
        spans.push(Span::raw(" ".repeat(pad + 1)));
        let metric_start = (used + pad + 1) as u16;
        spans.push(Span::styled(
            metric_text.unwrap().to_string(),
            metric_chip_style(),
        ));
        spans.push(Span::raw(" "));
        // Pin block.
        if p.is_pick {
            spans.push(Span::styled(
                format!("{} ", crate::tui::pins_overlay::PICK_ARROW),
                Style::default()
                    .fg(crate::tui::pins_overlay::PIN_YELLOW)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        let mut region = None;
        if control_w > 0 {
            let pin_end = area - right_margin - TIMESTAMP_WIDTH - 1;
            let pin_start = pin_end - pin_w;
            let fork_range = if include_fork {
                let fork_end = pin_start - 1;
                let fork_start = fork_end - p.fork_control_width();
                spans.extend(crate::tui::pins_overlay::fork_control_spans());
                spans.push(Span::raw(" "));
                Some((fork_start as u16, fork_end as u16))
            } else {
                None
            };
            let col_start = pin_start as u16;
            region = Some(PinRegion {
                seq: p.seq,
                row: 0,
                col_start,
                col_end: col_start + pin_w as u16,
                fork_col_start: fork_range.map(|(start, _)| start),
                fork_col_end: fork_range.map(|(_, end)| end),
            });
            spans.extend(crate::tui::pins_overlay::pin_control_spans(p.pinned));
            spans.push(Span::raw(" "));
        }
        spans.push(Span::styled(ts, Style::default().fg(TIMESTAMP_FG)));
        spans.push(Span::raw(" ".repeat(right_margin)));
        return (
            Line::from(spans),
            region,
            Some(MetricRow {
                row: 0,
                col_start: metric_start,
                col_end: metric_start + metric_w as u16,
            }),
        );
    }

    // Metric doesn't fit inline — use the original pin-only layout.
    // Rebuild spans without the metric (it goes on a dedicated row).
    let (line, region) =
        render_first_line_with_pin_and_timestamp_inner(spans, timestamp, width, Some(p));
    (line, region, None)
}

/// The inner pin+timestamp layout (no metric). This is the original
/// `render_first_line_with_pin_and_timestamp` body, factored out so the
/// metric-aware wrapper can fall back to it.
fn render_first_line_with_pin_and_timestamp_inner(
    mut spans: Vec<Span<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
    pin: Option<PinControl>,
) -> (Line<'static>, Option<PinRegion>) {
    let area = width as usize;
    let ts = format_timestamp(timestamp);
    let used: usize = spans.iter().map(|s| s.content.width()).sum();
    let Some(p) = pin else {
        return (
            render_first_line_timestamped(spans, timestamp, width, true),
            None,
        );
    };
    let arrow_w = if p.is_pick {
        crate::tui::pins_overlay::PICK_ARROW.width() + 1
    } else {
        0
    };
    let pin_w = p.pin_control_width();
    let fork_w = p.fork_control_width();
    let actions_w = arrow_w + pin_w + 1 + fork_w;
    let show_actions = p.show_control && area >= used + 1 + actions_w + TIMESTAMP_RIGHT_MARGIN;
    let show_time = if show_actions {
        area >= used + 1 + actions_w + 2 + TIMESTAMP_WIDTH + TIMESTAMP_RIGHT_MARGIN
    } else {
        area >= used + 1 + TIMESTAMP_WIDTH + TIMESTAMP_RIGHT_MARGIN
    };

    if show_actions {
        let trailing_w = if show_time {
            2 + TIMESTAMP_WIDTH + TIMESTAMP_RIGHT_MARGIN
        } else {
            TIMESTAMP_RIGHT_MARGIN
        };
        let gap = area.saturating_sub(used + actions_w + trailing_w);
        spans.push(Span::raw(" ".repeat(gap)));
        if p.is_pick {
            spans.push(Span::styled(
                format!("{} ", crate::tui::pins_overlay::PICK_ARROW),
                Style::default()
                    .fg(crate::tui::pins_overlay::PIN_YELLOW)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        let pin_start = used + gap + arrow_w;
        spans.extend(crate::tui::pins_overlay::pin_control_spans(p.pinned));
        spans.push(Span::raw(" "));
        let fork_start = pin_start + pin_w + 1;
        spans.extend(crate::tui::pins_overlay::fork_control_spans());
        if show_time {
            spans.push(Span::raw("  "));
            spans.push(Span::styled(ts, Style::default().fg(TIMESTAMP_FG)));
        }
        spans.push(Span::raw(" ".repeat(TIMESTAMP_RIGHT_MARGIN)));
        return (
            Line::from(spans),
            Some(PinRegion {
                seq: p.seq,
                row: 0,
                col_start: pin_start as u16,
                col_end: (pin_start + pin_w) as u16,
                fork_col_start: Some(fork_start as u16),
                fork_col_end: Some((fork_start + fork_w) as u16),
            }),
        );
    }

    if show_time {
        let gap = area.saturating_sub(used + TIMESTAMP_WIDTH + TIMESTAMP_RIGHT_MARGIN);
        spans.push(Span::raw(" ".repeat(gap)));
        spans.push(Span::styled(ts, Style::default().fg(TIMESTAMP_FG)));
        spans.push(Span::raw(" ".repeat(TIMESTAMP_RIGHT_MARGIN)));
    }
    (Line::from(spans), None)
}

fn format_timestamp(t: DateTime<Local>) -> String {
    #[cfg(any(test, feature = "test-support"))]
    if let Some(hms) = crate::tui::golden::pinned_hhmm() {
        return hms.to_string();
    }
    t.format("%H:%M").to_string()
}

/// Render a dedicated metric metadata row: the compact chip (or expanded
/// detail) left-aligned at `AGENT_INDENT`. Returns the line and the
/// metric hit row (column range covering the chip text).
/// Split `text` into chunks that fit within `area_width`, reserving
/// `reserve_first` extra columns on the *first* line (so a timestamp
/// can land at the right edge without overlapping the text). Greedy
/// word-wrap on whitespace boundaries; falls back to hard char-break
/// for single words longer than the wrap width.
fn wrap_with_reserved_first_line(
    text: &str,
    area_width: usize,
    reserve_first: usize,
) -> Vec<String> {
    wrap_with_reserved_first_line_and_prefix(text, area_width, reserve_first, 0)
}

/// Like [`wrap_with_reserved_first_line`] but the first line is
/// further shortened by `prefix_width` (because an agent-name prefix
/// will be prepended to it before display).
fn wrap_with_reserved_first_line_and_prefix(
    text: &str,
    area_width: usize,
    reserve_first: usize,
    prefix_width: usize,
) -> Vec<String> {
    if area_width == 0 {
        return vec![text.to_string()];
    }
    let mut out: Vec<String> = Vec::new();
    for line in text.split('\n') {
        if line.is_empty() && out.is_empty() {
            // preserve leading blank lines as empty chunks
            out.push(String::new());
            continue;
        }
        let first_width = area_width
            .saturating_sub(reserve_first)
            .saturating_sub(prefix_width.saturating_mul(out.is_empty() as usize));
        let mut budget = if out.is_empty() {
            first_width.max(1)
        } else {
            area_width.max(1)
        };

        let mut current = String::new();
        let mut current_width = 0usize;
        for word in line.split_inclusive([' ', '\t']) {
            let w = word.width();
            if w + current_width <= budget {
                current.push_str(word);
                current_width += w;
            } else if current_width == 0 {
                // Single word longer than budget — emit a hard slice.
                let mut remaining = word;
                while !remaining.is_empty() {
                    let take = take_to_width(remaining, budget);
                    remaining = &remaining[take.len()..];
                    out.push(take);
                    budget = area_width.max(1);
                }
            } else {
                out.push(std::mem::take(&mut current));
                current_width = 0;
                budget = area_width.max(1);
                if w <= budget {
                    current.push_str(word);
                    current_width = w;
                } else {
                    let mut remaining = word;
                    while !remaining.is_empty() {
                        let take = take_to_width(remaining, budget);
                        remaining = &remaining[take.len()..];
                        out.push(take);
                    }
                }
            }
        }
        if !current.is_empty() {
            out.push(current);
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

/// Feed a streaming text delta through the `<think>` tag router.
/// Outside of think tags, content goes to `text`; inside, content goes
/// to `reasoning`. Partial tags at the chunk boundary (e.g. ending in
/// `<th`) are buffered in `tag_partial` and resolved on the next
/// delta. Returns `true` if any non-think-block text content was
/// appended — callers use this as the signal to mark `text_started_at`.
///
/// Why streaming-aware: many open-weights thinking-mode models inline
/// reasoning as `<think>...</think>` blocks in the regular content
/// stream rather than using the OpenAI-compat `reasoning_content`
/// field. Post-finalize stripping would work but flashes the
/// reasoning live before hiding it, which is what the user reported
/// as "thinking block is always displayed."
pub fn route_text_delta(
    chunk: &str,
    text: &mut String,
    reasoning: &mut String,
    inside_think: &mut bool,
    body_started: &mut bool,
    tag_partial: &mut String,
) -> bool {
    // Single source of truth: the streaming split and the engine's
    // finalization split drive the SAME state machine
    // (`cockpit_core::engine::think`), so the displayed body, the stored text,
    // and the rebuilt model history can never disagree. We adapt the
    // splitter's state to/from `PendingMsg`'s two flat fields here.
    let mut splitter = cockpit_core::engine::think::ThinkSplitter::from_parts(
        *inside_think,
        *body_started,
        std::mem::take(tag_partial),
    );
    let wrote = splitter.feed(chunk, text, reasoning);
    let (next_inside, next_body_started, next_partial) = splitter.into_parts();
    *inside_think = next_inside;
    *body_started = next_body_started;
    *tag_partial = next_partial;
    wrote
}

/// Advance the thinking dots through `"" → "." → ".." → "..."` on a
/// 333 ms phase cycle. The empty phase is intentional — the visible
/// "Thinking" word stays put while the dots vanish and re-appear,
/// giving a clearer "still working" pulse than a fixed-width
/// animation.
pub fn thinking_dots(elapsed_ms: u128) -> &'static str {
    match (elapsed_ms / 333) % 4 {
        0 => "",
        1 => ".",
        2 => "..",
        _ => "...",
    }
}

/// [`thinking_dots`] space-padded to a fixed width of 3 (`"" → "   "`,
/// `"..." → "..."`). Used by the status indicator so the trailing
/// timer stays horizontally fixed instead of jiggling as the dots
/// cycle.
pub fn thinking_dots_padded(elapsed_ms: u128) -> String {
    format!("{:<3}", thinking_dots(elapsed_ms))
}

/// Format an elapsed span compactly, whole seconds only: `Xs` under a
/// minute, `Xm Ys` at or beyond. Shared by the parenthesized status
/// readout and the subagent `worked for …` / `failed after …` header.
pub fn format_compact_duration(d: Duration) -> String {
    let secs = d.as_secs();
    if secs < 60 {
        format!("{secs}s")
    } else {
        format!("{}m {}s", secs / 60, secs % 60)
    }
}

/// Format an elapsed span for the working / thinking status indicator:
/// `(Xs)` under a minute, `(Xm Ys)` at or beyond. Whole seconds only —
/// the indicator advances once a second; sub-second precision is noise.
pub fn format_status_elapsed(d: Duration) -> String {
    format!("({})", format_compact_duration(d))
}

/// Format a thinking duration. Examples: `0.4 seconds`, `7 seconds`,
/// `2m 14s` for longer pauses. Single-precision feels right for the
/// in-chat chip — exact milliseconds are noise.
pub fn format_think_duration(d: Duration) -> String {
    let total_ms = d.as_millis();
    if total_ms < 1000 {
        return "<1 second".to_string();
    }
    let total_secs = d.as_secs();
    if total_secs < 60 {
        if total_secs < 10 {
            let secs = total_ms as f64 / 1000.0;
            return format!("{secs:.1} seconds");
        }
        return format!("{total_secs} seconds");
    }
    let m = total_secs / 60;
    let s = total_secs % 60;
    format!("{m}m {s}s")
}

#[cfg(test)]
mod tests;
