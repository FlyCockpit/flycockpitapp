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
    layout_markdown_message_lines, render_markdown_message_block, slice_spans_at_width,
    wrap_lines_to_width,
};
use crate::tui::progress::render_bar;
use crate::tui::theme::{
    ERROR_TEXT, INFO_TEXT, METADATA_TEXT, MUTED_COLOR_INDEX, PLAN_YELLOW, SUBAGENT_ORANGE,
    SUCCESS_TEXT, TOOL_OUTPUT, TOOL_SIDEBAR, WARNING_TEXT,
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
    /// truncatable response body. Child name renders in orange; parent
    /// in the default style.
    Subagent {
        /// Delegating agent's name (default style).
        parent: String,
        /// Delegated-to agent's name (orange).
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

/// Light grey for the tool-box sidebar.
const SIDEBAR_FG: Color = TOOL_SIDEBAR;
/// Dim grey for expanded tool output lines.
const TOOL_OUTPUT_FG: Color = TOOL_OUTPUT;

// Retained for the user-message background fill; not yet applied.
#[allow(dead_code)]
const USER_BG: Color = Color::Indexed(17); // dark blue (xterm 256-color)
const USER_BORDER_FG: Color = crate::tui::theme::ACCENT_BLUE;
const TIMESTAMP_FG: Color = METADATA_TEXT;
const REASONING_FG: Color = TOOL_SIDEBAR;
const THINKING_FG: Color = WARNING_TEXT;
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

/// Outer gutter on either side of a user-message bubble (cells of
/// terminal-default bg outside the rounded box).
const USER_GUTTER: usize = 1;
/// Inner padding between the bubble's vertical border and the text.
const USER_INNER_PAD: usize = 1;

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
    /// Where the clickable `[fork]` and/or `[pin]`/`[unpin]` mouse controls
    /// landed within `lines`, when drawn. `None` when the entry is not
    /// pinnable, the controls are hidden (mouse mode off), or the line was
    /// too narrow to fit any control. Carries the seq + exact row/column
    /// ranges so hit-tests route only visible glyphs.
    pub pin_region: Option<PinRegion>,
    /// Where the clickable response-performance metric chip landed, when
    /// drawn. `None` when the entry has no performance snapshot, the chip
    /// was hidden (mouse mode off), or the terminal is below the minimum
    /// supported width (24 columns) and the header is replaced by the
    /// `↔` resize state. Carries exact row/column ranges so hit-tests
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
    /// `true` → the message is currently pinned (`[unpin]`, yellow);
    /// `false` → not pinned (`[pin]`, grey). Drives the state-dependent
    /// control width (7 vs 5).
    pub pinned: bool,
    /// `true` → draw the clickable `[fork]` plus `[pin]`/`[unpin]` controls
    /// (mouse mode on). When `false` the controls are omitted and reserve no
    /// width.
    pub show_control: bool,
    /// `true` → this entry is the `/pin` or `/fork` pick-mode selection; the
    /// `▶` arrow attaches immediately left of the inline/corner controls.
    pub is_pick: bool,
}

impl PinControl {
    /// Width (columns) the `[pin]`/`[unpin]` glyphs occupy when shown,
    /// else 0. State-dependent: 7 for `[unpin]`, 5 for `[pin]`.
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

/// Where the clickable response-performance metric chip landed: the
/// half-open `[col_start, col_end)` column range on each row that
/// belongs to the chip. The chip may span multiple rows when the
/// metric is split across dedicated metadata rows on narrow terminals.
/// The chrome offsets each `row` by the entry's position in the scroll
/// buffer and hit-tests only the recorded ranges. Clicking toggles
/// only `performance_expanded` — never the reasoning `expanded` field.
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
            // The chip rides the bubble's top border row (row 0). Only a
            // resolved cleaned form makes it the clickable reveal toggle; the
            // transient `Preflight…` indicator is not toggleable.
            let chip_row = toggleable.then_some(0);
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
        HistoryEntry::Plain { line } => Rendered {
            lines: vec![Line::from(vec![
                Span::styled(" ".repeat(AGENT_INDENT), Style::default().fg(INFO_TEXT)),
                Span::styled(line.clone(), Style::default().fg(INFO_TEXT)),
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
            lines: vec![Line::from(vec![
                Span::styled(" ".repeat(AGENT_INDENT), Style::default().fg(INFO_TEXT)),
                Span::styled(line.clone(), Style::default().fg(INFO_TEXT)),
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
            tool,
            path,
            old,
            new,
        } => {
            let lines = crate::tui::diff::render_diff(
                tool, path, old, new, diff_style, width, emojis, file_icons,
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
            let label_color = if *failed { ERROR_TEXT } else { Color::Cyan };
            let mut lines: Vec<Line<'static>> = Vec::new();
            lines.push(Line::from(vec![Span::styled(
                label.clone(),
                Style::default()
                    .fg(label_color)
                    .add_modifier(Modifier::BOLD),
            )]));
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
        } => render_toolbox(
            &[compact_tool_call(
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
            )],
            0,
            true,
            width,
            emojis,
            file_icons,
            elided,
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
            render_agent(
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
            )
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
    if msg.text.trim().is_empty() {
        state.reset();
        return PendingRender::default();
    }
    if !msg.reasoning.trim().is_empty() {
        state.reset();
        return PendingRender {
            committed: Vec::new(),
            tail: render_pending(msg, width),
        };
    }

    let body_width = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
    if state.width != width || state.body_width != body_width || msg.text.len() < state.source_len {
        state.reset();
        state.width = width;
        state.body_width = body_width;
    }

    if state.source_len == msg.text.len() && !state.rendered_lines.is_empty() {
        return PendingRender {
            committed: state.committed_display.clone(),
            tail: state.rendered_lines.clone(),
        };
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
                markdown::render_with_width(committed, body_width)
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
        tail_markdown_lines.extend(markdown::render_with_width(tail, body_width));
    }

    state.source_len = msg.text.len();
    state.rendered_lines = render_pending_tail_lines(
        tail_markdown_lines,
        msg.timestamp,
        width,
        state.committed_display.is_empty(),
    );
    PendingRender {
        committed: state.committed_display.clone(),
        tail: state.rendered_lines.clone(),
    }
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
        TIMESTAMP_WIDTH + 1 + TIMESTAMP_RIGHT_MARGIN,
        AGENT_INDENT,
        Style::default(),
    );
    if body.lines.is_empty() {
        return vec![render_first_line_with_pin_and_timestamp(vec![], timestamp, width, None).0];
    }

    let mut out = Vec::with_capacity(body.lines.len());
    let mut iter = body.lines.into_iter().zip(body.continuations);
    let (first, _) = iter.next().expect("body non-empty");
    out.push(render_first_line_with_pin_and_timestamp(first.spans, timestamp, width, None).0);
    out.extend(iter.map(|(line, _)| line));
    out
}

fn render_pending_tail_lines(
    markdown_lines: Vec<Line<'static>>,
    timestamp: DateTime<Local>,
    width: u16,
    include_header: bool,
) -> Vec<Line<'static>> {
    if include_header {
        return render_pending_markdown_lines(markdown_lines, timestamp, width);
    }
    if markdown_lines.is_empty() {
        return Vec::new();
    }
    let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
    layout_markdown_message_lines(
        markdown_lines,
        body_content_w,
        0,
        AGENT_INDENT,
        Style::default(),
    )
    .lines
    .into_iter()
    .collect()
}

/// Render an in-flight pending message: the agent's text as it streams
/// in. The live "Thinking…"/status readout (with its elapsed clock) is
/// owned by the status indicator (`render_status_indicator`), so before
/// any text arrives this renders nothing — keeping a single live status
/// line on screen instead of a duplicate "Thinking" in two places.
/// Reasoning is captured but not displayed live (the user can expand
/// once the turn finalizes).
pub fn render_pending(msg: &PendingMsg, width: u16) -> Vec<Line<'static>> {
    if msg.text.trim().is_empty() {
        return Vec::new();
    }
    // Text streaming in — same rendering as Agent (no expansion in
    // live state; reasoning shown after finalization). Markdown is
    // rendered live mid-stream via the same path the finalized entry
    // uses: the whole pending buffer is re-parsed each frame. Partial
    // inline syntax (`**`/`_`/`` ` ``/`[` with no closer yet) restyles
    // the trailing text until the closer arrives, and an open ` ``` `
    // fence streams as a code block to end-of-input — accepted, since
    // it matches what the finalized render will show.
    render_agent(
        &msg.name,
        &msg.text,
        &msg.reasoning,
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
    .lines
}

/// User message: outline-only rounded box drawn with `╭ ╮ ╰ ╯ ─ │`.
/// Text and interior cells sit on the terminal-default bg — just the
/// border characters carry color. Padding cells inside the box are
/// kept (so text doesn't slam into the border) but render as plain
/// spaces.
///
/// When `markdown` is on, the bubble is dropped and we render the text
/// through the markdown emitter with a left-edge `│` marker — wrapping
/// styled markdown spans inside a bubble is more trouble than it's
/// worth for the small visual win.
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
    if markdown {
        return render_user_markdown(text, timestamp, width, chip, failed, pin);
    }
    let area = width as usize;
    let bubble_w = area.saturating_sub(USER_GUTTER * 2).max(4);
    let interior_w = bubble_w.saturating_sub(2);
    let text_w = interior_w.saturating_sub(USER_INNER_PAD * 2);

    let ts = format_timestamp(timestamp);
    let border_style = Style::default().fg(if failed { ERROR_TEXT } else { USER_BORDER_FG });
    let gutter = Span::raw(" ".repeat(USER_GUTTER));
    let inner_pad = || Span::raw(" ".repeat(USER_INNER_PAD));

    let mut out: Vec<Line<'static>> = Vec::new();
    // Top border row, optionally carrying the `⚙ preflighted` chip
    // (implementation note) appended past the box, and the mouse controls
    // tucked into the top-right border corner (`pinned-messages`) — neither
    // costs vertical space.
    let (border_spans, pin_region) =
        user_top_border(interior_w, border_style, pin, USER_GUTTER + 1);
    let mut top = vec![gutter.clone()];
    top.extend(border_spans);
    top.push(gutter.clone());
    if let Some(chip) = chip {
        top.push(Span::raw("  "));
        top.push(Span::styled(
            chip.to_string(),
            Style::default().fg(TIMESTAMP_FG),
        ));
    }
    out.push(Line::from(top));

    let wrapped = wrap_with_reserved_first_line(text, text_w, TIMESTAMP_WIDTH + 1);
    for (i, chunk) in wrapped.iter().enumerate() {
        let chunk_w = chunk.width();
        let mut spans = vec![gutter.clone(), Span::styled("│", border_style), inner_pad()];
        if i == 0 {
            let used = chunk_w + TIMESTAMP_WIDTH + 1;
            let middle = text_w.saturating_sub(used);
            spans.push(Span::raw(chunk.clone()));
            spans.push(Span::raw(" ".repeat(middle)));
            spans.push(Span::raw(" "));
            spans.push(Span::styled(ts.clone(), Style::default().fg(TIMESTAMP_FG)));
        } else {
            let middle = text_w.saturating_sub(chunk_w);
            spans.push(Span::raw(chunk.clone()));
            spans.push(Span::raw(" ".repeat(middle)));
        }
        spans.push(inner_pad());
        spans.push(Span::styled("│", border_style));
        spans.push(gutter.clone());
        out.push(Line::from(spans));
    }

    out.push(Line::from(vec![
        gutter.clone(),
        Span::styled(format!("╰{}╯", "─".repeat(interior_w)), border_style),
        gutter,
    ]));

    let continuations = vec![false; out.len()];
    (out, continuations, pin_region, None)
}

/// Build the bubble's top border spans (`╭───╮`) with the fork/pin controls —
/// the `▶` pick-arrow (when selected) + `[fork] [pin]`/`[unpin]` glyphs (when
/// mouse mode is on) — tucked into the top-right corner, replacing the
/// rightmost run of `─` glyphs just inside the `╮` (`pinned-messages`).
/// `first_dash_col` is the chat-relative column of the first `─` (i.e. the
/// `╭` column + 1), so the recorded region's columns line up with the
/// chat-area-relative coordinates the click hit-test uses. Returns
/// `(spans, region)`; `region` carries the clickable fork and pin columns,
/// or `None` when no control was drawn (mouse off) or the bubble is too
/// narrow to host even `[pin]` without breaking the box — the box width is
/// preserved exactly in every case. When both chips do not fit, `[fork]`
/// is dropped first.
fn user_top_border(
    interior_w: usize,
    border_style: Style,
    pin: Option<PinControl>,
    first_dash_col: usize,
) -> (Vec<Span<'static>>, Option<PinRegion>) {
    let arrow_w = pin
        .filter(|p| p.is_pick)
        .map(|_| crate::tui::pins_overlay::PICK_ARROW.width())
        .unwrap_or(0);
    let (ctrl_w, include_fork) = match pin {
        Some(p) if p.show_control => {
            let full = p.control_width(true);
            if arrow_w + full < interior_w {
                (full, true)
            } else {
                let pin_only = p.control_width(false);
                if arrow_w + pin_only < interior_w {
                    (pin_only, false)
                } else {
                    (0, false)
                }
            }
        }
        _ => (0, false),
    };
    let corner = arrow_w + ctrl_w;
    // Only host the corner controls when the box is wide enough to keep at
    // least one `─` to the left of them — otherwise drop controls (box
    // unbroken), falling back from `[fork] [pin]` to `[pin]` first.
    if corner == 0 || corner >= interior_w {
        return (
            vec![Span::styled(
                format!("╭{}╮", "─".repeat(interior_w)),
                border_style,
            )],
            None,
        );
    }
    let dashes = interior_w - corner;
    let mut spans = vec![Span::styled(
        format!("╭{}", "─".repeat(dashes)),
        border_style,
    )];
    if arrow_w > 0 {
        spans.push(Span::styled(
            crate::tui::pins_overlay::PICK_ARROW.to_string(),
            Style::default()
                .fg(crate::tui::pins_overlay::PIN_YELLOW)
                .add_modifier(Modifier::BOLD),
        ));
    }
    let mut region = None;
    if ctrl_w > 0 {
        let p = pin.expect("ctrl_w > 0 implies Some");
        // The controls occupy the columns immediately left of the `╮`:
        // first-dash column + the dashes + the arrow.
        let control_start = first_dash_col + dashes + arrow_w;
        let mut pin_start = control_start;
        let mut fork_range = None;
        if include_fork {
            let fork_start = control_start;
            let fork_end = fork_start + p.fork_control_width();
            fork_range = Some((fork_start as u16, fork_end as u16));
            spans.extend(crate::tui::pins_overlay::fork_control_spans());
            spans.push(Span::styled("─".to_string(), border_style));
            pin_start = fork_end + 1;
        }
        let pin_w = p.pin_control_width();
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
    }
    spans.push(Span::styled("╮".to_string(), border_style));
    (spans, region)
}

/// Markdown-styled user message: no bubble, left-edge `│` marker in
/// the user-message border color, timestamp right-aligned on row 1.
fn render_user_markdown(
    text: &str,
    timestamp: DateTime<Local>,
    width: u16,
    chip: Option<&str>,
    failed: bool,
    pin: Option<PinControl>,
) -> (
    Vec<Line<'static>>,
    Vec<bool>,
    Option<PinRegion>,
    Option<RenderedCopy>,
) {
    let bar_style = Style::default().fg(if failed { ERROR_TEXT } else { USER_BORDER_FG });
    // Content width inside the `│ ` bar (and a matching right margin), so
    // display-math blocks degrade to raw if they'd exceed the viewport.
    let md_width = (width as usize).saturating_sub(2 + 2).max(1);
    let reserve_first = TIMESTAMP_WIDTH + 1 + TIMESTAMP_RIGHT_MARGIN + agent_pin_reserve(pin);
    let body = render_markdown_message_block(text, md_width, reserve_first, 0, Style::default());
    let body_row_offset = chip.is_some() as usize;
    let mut copy = RenderedCopy::from_block(body_row_offset, &body);
    for cells in &mut copy.cells {
        cells.splice(0..0, [None, None]);
    }
    if body_row_offset > 0 {
        copy.cells.insert(0, Vec::new());
        copy.newlines_before.insert(0, 0);
        copy.incomplete.insert(0, false);
    }
    let mut body_continuations = body.continuations.into_iter();
    let body = body.lines;

    let mut out: Vec<Line<'static>> = Vec::with_capacity(body.len() + 1);
    // The controls ride the first body line (no bubble to host a corner
    // here), inline immediately left of the timestamp — same shape as an
    // agent line (`pinned-messages`). The chip stays on its own row.
    let mut pin_region: Option<PinRegion> = None;
    // The control block lives on the first *body* line; once the chip takes
    // row 0, the body's first line is offset by one.
    // Request-preflight chip on its own row 0 (implementation note)
    // — the clickable reveal-toggle row for the markdown render shape.
    if let Some(chip) = chip {
        out.push(Line::from(vec![Span::styled(
            chip.to_string(),
            Style::default().fg(TIMESTAMP_FG),
        )]));
    }
    let mut continuations = vec![false; body_row_offset];
    for (i, line) in body.into_iter().enumerate() {
        continuations.push(body_continuations.next().unwrap_or(false));
        let mut spans: Vec<Span<'static>> = Vec::with_capacity(line.spans.len() + 2);
        spans.push(Span::styled("│ ".to_string(), bar_style));
        spans.extend(line.spans);
        if i == 0 {
            let (timestamped, region) =
                render_first_line_with_pin_and_timestamp(spans, timestamp, width, pin);
            pin_region = region.map(|mut r| {
                r.row += body_row_offset;
                r
            });
            out.push(timestamped);
        } else {
            out.push(Line::from(spans));
        }
    }
    if out.len() <= body_row_offset {
        let spans: Vec<Span<'static>> = vec![Span::styled("│ ".to_string(), bar_style)];
        let (timestamped, region) =
            render_first_line_with_pin_and_timestamp(spans, timestamp, width, pin);
        pin_region = region.map(|mut r| {
            r.row += body_row_offset;
            r
        });
        out.push(timestamped);
        continuations.push(false);
    }
    continuations.resize(out.len(), false);
    (out, continuations, pin_region, Some(copy))
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
                Span::styled(
                    " → ",
                    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
                ),
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
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
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
    let muted_italic = Style::default()
        .fg(Color::Indexed(MUTED_COLOR_INDEX))
        .add_modifier(Modifier::ITALIC);

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
/// detail, timestamp, fork, pin, overflow menu). Below this the complete
/// header is replaced by a noninteractive one-cell `↔` resize state.
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

/// The compact `<ttft>/<tps>` chip text, or `None` when the snapshot has
/// no TPS (zero `generation_ms`).
fn metric_chip_text(perf: &ResponsePerformance) -> Option<String> {
    let tps = format_tps(perf)?;
    Some(format!("{}/{}", format_ttft(perf.ttft_ms), tps))
}

/// The expanded detail line text: `TTFT: <value>s / TPS: <value>`,
/// using the same rounded values as the chip. TPS is `-` when absent
/// (zero generation).
fn metric_detail_text(perf: &ResponsePerformance) -> String {
    let ttft = format_ttft(perf.ttft_ms);
    let tps = format_tps(perf).unwrap_or_else(|| "-".to_string());
    format!("TTFT: {ttft}s / TPS: {tps}")
}

/// Style for the metric chip text -- a muted cyan accent, distinct from
/// the timestamp's grey and the fork/pin yellow/grey.
fn metric_chip_style() -> Style {
    Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::DIM | Modifier::UNDERLINED)
}

/// Style for the expanded metric detail line.
fn metric_detail_style() -> Style {
    Style::default().fg(Color::Cyan).add_modifier(Modifier::DIM)
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
    think_duration: Option<Duration>,
    width: u16,
    markdown: bool,
    pin: Option<PinControl>,
    performance: Option<ResponsePerformance>,
    performance_expanded: bool,
) -> Rendered {
    let _ = name;
    let bullet_width: usize = AGENT_INDENT
        + if AGENT_BULLET.is_empty() {
            0
        } else {
            AGENT_BULLET.width() + 1 // bullet + space
        };
    let indent_span = || Span::raw(" ".repeat(AGENT_INDENT));
    let has_reasoning = !reasoning.trim().is_empty();
    // The inline control block (`▶ ` + `[fork] [pin]`/`[unpin]`) rides
    // immediately left of the timestamp on the first content line, so the
    // first line's right-edge reservation grows by the control block's columns
    // (`pinned-messages`).
    let pin_reserve = agent_pin_reserve(pin);
    let reserve_first = TIMESTAMP_WIDTH + 1 + TIMESTAMP_RIGHT_MARGIN + pin_reserve;
    // Filled in when the first content line actually draws a clickable
    // control (mouse mode on and it fit). The `▶` pick-arrow alone is not
    // clickable, so it leaves this `None`.
    let mut pin_region: Option<PinRegion> = None;
    let mut metric_region: Option<MetricRegion> = None;
    let mut copy_body_start: Option<RenderedCopy> = None;

    let mut out: Vec<Line<'static>> = Vec::new();
    // Parallel to `out`: `conts[i]` is `true` when row `i` is a
    // soft-wrap continuation of the previous logical line. The copy
    // path uses this to rejoin soft-wraps with a space instead of a
    // newline.
    let mut conts: Vec<bool> = Vec::new();
    let mut chip_row = None;
    let mut reasoning_scroll_region: Option<ReasoningScrollRegion> = None;

    // Compute the compact metric chip text (if any). The chip is absent
    // for None or invalid/zero-duration snapshots (no TPS).
    let metric_text: Option<String> = performance.as_ref().and_then(metric_chip_text);

    // Below the minimum supported width for response-header controls,
    // replace all header chrome (metric, detail, timestamp, fork, pin,
    // overflow menu) with a noninteractive one-cell `↔` resize state.
    // It has no hit target, never clips horizontally, and retains no
    // hidden mouse action; the complete accessible header returns only
    // after resize to 24 columns or wider.
    if width < RESPONSE_HEADER_MIN_WIDTH {
        let mut out: Vec<Line<'static>> = Vec::new();
        let mut conts: Vec<bool> = Vec::new();
        let mut copy_body_start: Option<RenderedCopy> = None;

        // The resize indicator on its own row.
        let resize_style = Style::default()
            .fg(Color::Indexed(MUTED_COLOR_INDEX))
            .add_modifier(Modifier::DIM);
        out.push(Line::from(vec![
            Span::raw(" ".repeat(AGENT_INDENT)),
            Span::styled("↔", resize_style),
        ]));
        conts.push(false);

        // Body content still renders below the resize indicator, just
        // without any header chrome.
        let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
        if markdown {
            let body = render_markdown_message_block(
                text,
                body_content_w,
                0,
                AGENT_INDENT,
                Style::default(),
            );
            copy_body_start = Some(RenderedCopy::from_block(1, &body));
            out.extend(body.lines);
            conts.extend(body.continuations);
        } else if !text.trim().is_empty() {
            let wrapped = wrap_with_reserved_first_line(text, body_content_w, 0);
            let indent = " ".repeat(AGENT_INDENT);
            for (i, chunk) in wrapped.iter().enumerate() {
                out.push(Line::from(vec![
                    Span::raw(indent.clone()),
                    Span::raw(chunk.clone()),
                ]));
                conts.push(i > 0);
            }
        }

        // Reasoning chip still renders (it's content, not header chrome).
        if has_reasoning {
            let arrow = if expanded { "▼" } else { "▶" };
            let action_hint = if expanded {
                "ctrl+t to collapse"
            } else {
                "ctrl+t to expand"
            };
            let label = match think_duration {
                Some(d) => format!(
                    "{arrow} thought for {} ({action_hint})",
                    format_think_duration(d)
                ),
                None => format!("{arrow} thinking ({action_hint})"),
            };
            chip_row = Some(0);
            // Insert the reasoning chip as the first row, pushing the
            // resize indicator + body down.
            let chip_line = Line::from(vec![
                Span::raw(" ".repeat(bullet_width)),
                Span::styled(
                    label,
                    Style::default()
                        .fg(THINKING_FG)
                        .add_modifier(Modifier::DIM | Modifier::UNDERLINED),
                ),
            ]);
            out.insert(0, chip_line);
            conts.insert(0, false);
            if let Some(mut copy) = copy_body_start {
                copy.start += 1;
                copy_body_start = Some(copy);
            }
            // Expanded reasoning renders below the chip.
            if expanded {
                let reasoning_indent = AGENT_INDENT + 2;
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
                                Span::styled(chunk, Style::default().fg(REASONING_FG)),
                            ]),
                            i > 0,
                        ));
                    }
                }
                let window =
                    inner_scroll_window(reasoning_rows.len(), THINKING_VISIBLE, reasoning_offset);
                // The reasoning window is a single contiguous block appended
                // after the chip/resize/body rows. `region_start` must anchor
                // to the first row of that block (the `more above` indicator
                // when present, else the first visible reasoning row) so the
                // scroll region covers only the reasoning window — never the
                // resize/body rows above it.
                let region_start = out.len();
                if window.more_above > 0 {
                    out.push(Line::from(vec![
                        Span::raw(" ".repeat(reasoning_indent)),
                        Span::styled(
                            format!("{} more above", window.more_above),
                            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
                            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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

        return Rendered {
            lines: out,
            copy_body_start,
            chip_row,
            continuations: conts,
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region,
            pin_region: None,
            metric_region: None,
        };
    }

    // width >= RESPONSE_HEADER_MIN_WIDTH: render the full header chrome.
    // When the agent produced reasoning, the *first* row of this entry
    // is the bullet + chip line — replacing the "Thinking…" placeholder
    // that lived there during streaming.  The timestamp lands on the
    // first actual text line (render_first_line_with_pin_and_timestamp
    // handles that naturally for the first wrapped text chunk).
    if has_reasoning {
        let arrow = if expanded { "▼" } else { "▶" };
        let action_hint = if expanded {
            "ctrl+t to collapse"
        } else {
            "ctrl+t to expand"
        };
        let label = match think_duration {
            Some(d) => format!(
                "{arrow} thought for {} ({action_hint})",
                format_think_duration(d)
            ),
            None => format!("{arrow} thinking ({action_hint})"),
        };
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
        chip_spans.push(Span::styled(
            label,
            Style::default()
                .fg(THINKING_FG)
                .add_modifier(Modifier::DIM | Modifier::UNDERLINED),
        ));

        // Body content target width: full width minus left indent
        // (AGENT_INDENT) and a matching right pad (AGENT_INDENT) so
        // wrapped continuations don't go all the way to the right
        // edge.
        let body_content_w = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
        let (body_lines, body_conts, body_copy) = if markdown {
            // Pre-wrap the markdown lines ourselves so ratatui's
            // Paragraph::wrap doesn't strip the indent on
            // continuation rows.
            let body = render_markdown_message_block(
                text,
                body_content_w,
                0,
                AGENT_INDENT,
                Style::default(),
            );
            let copy = RenderedCopy::from_block(0, &body);
            (body.lines, body.continuations, Some(copy))
        } else {
            let lines = wrapped
                .iter()
                .map(|chunk| Line::from(vec![Span::raw(format!("{indent}{chunk}"))]))
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
            let (line, region, metric_row) = render_first_line_with_pin_and_timestamp_metric(
                chip_spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            pin_region = region;
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
            let reasoning_indent = AGENT_INDENT + 2;
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
                            Span::styled(chunk, Style::default().fg(REASONING_FG)),
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
                        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
                        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
            let (line, region, metric_row) = render_first_line_with_pin_and_timestamp_metric(
                chip_spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            pin_region = region;
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
            let collapsed_first_reserve =
                label_width + 1 + TIMESTAMP_WIDTH + 1 + TIMESTAMP_RIGHT_MARGIN + pin_reserve;
            let collapsed_wrapped: Vec<String> =
                wrap_with_reserved_first_line(text, text_width, collapsed_first_reserve);
            let mut first_line_spans = chip_spans;
            if !collapsed_wrapped.is_empty() {
                first_line_spans.push(Span::raw(" "));
                first_line_spans.push(Span::raw(collapsed_wrapped[0].clone()));
            }
            let (line, region, metric_row) = render_first_line_with_pin_and_timestamp_metric(
                first_line_spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            pin_region = region;
            if let Some(mr) = metric_row {
                metric_region = Some(MetricRegion { rows: vec![mr] });
            }
            out.push(line);
            conts.push(false);
            for chunk in collapsed_wrapped.iter().skip(1) {
                out.push(Line::from(vec![Span::raw(format!("{indent}{chunk}"))]));
                conts.push(true);
            }
        }
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
        // The reservation is relative to `body_content_w`, which already
        // accounts for the left AGENT_INDENT applied by indent_lines;
        // `render_first_line_with_pin_and_timestamp` adds AGENT_INDENT back
        // to `used`, so reserving (TIMESTAMP_WIDTH + 1 + control block) here
        // leaves the right-edge controls + timestamp + gap exactly clear on row 1.
        let body = render_markdown_message_block(
            text,
            body_content_w,
            TIMESTAMP_WIDTH + 1 + TIMESTAMP_RIGHT_MARGIN + pin_reserve,
            AGENT_INDENT,
            Style::default(),
        );
        copy_body_start = Some(RenderedCopy::from_block(0, &body));
        if body.lines.is_empty() {
            let (line, region, metric_row) = render_first_line_with_pin_and_timestamp_metric(
                vec![],
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            pin_region = region;
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
            let (line, region, metric_row) = render_first_line_with_pin_and_timestamp_metric(
                first.spans,
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            pin_region = region;
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
            reserve_first,
            0,
        );
        if chunks.is_empty() {
            let (line, region, metric_row) = render_first_line_with_pin_and_timestamp_metric(
                vec![],
                timestamp,
                width,
                pin,
                metric_text.as_deref(),
            );
            pin_region = region;
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
                    spans.push(Span::raw(chunk.clone()));
                    let (line, region, metric_row) =
                        render_first_line_with_pin_and_timestamp_metric(
                            spans,
                            timestamp,
                            width,
                            pin,
                            metric_text.as_deref(),
                        );
                    pin_region = region;
                    if let Some(mr) = metric_row {
                        metric_region = Some(MetricRegion { rows: vec![mr] });
                    }
                    out.push(line);
                    conts.push(false);
                } else {
                    let indent = " ".repeat(bullet_width);
                    out.push(Line::from(vec![Span::raw(format!("{indent}{chunk}"))]));
                    conts.push(true);
                }
            }
        }
    }

    // If the metric chip didn't fit inline, emit a dedicated metadata row
    // (or rows) for it. This row is inserted after the first row (which
    // carries the timestamp/pin) so the timestamp and controls are
    // preserved. The dedicated row is clickable.
    if let Some(chip_text) = metric_text.as_ref()
        && metric_region.is_none()
    {
        let chip_w = chip_text.width();
        let avail = (width as usize).saturating_sub(2 * AGENT_INDENT).max(1);
        let mut metric_rows: Vec<MetricRow> = Vec::new();

        if chip_w + AGENT_INDENT <= avail + AGENT_INDENT {
            // The chip fits on one row.
            let (row_line, mr) = render_metric_metadata_row(chip_text, false, width);
            let insert_at = 1.min(out.len());
            out.insert(insert_at, row_line);
            conts.insert(insert_at, false);
            // Adjust chip_row if it was set.
            if let Some(cr) = chip_row.as_mut()
                && *cr >= insert_at
            {
                *cr += 1;
            }
            // Adjust copy_body_start if it was set.
            if let Some(copy) = copy_body_start.as_mut() {
                copy.start += 1;
            }
            // Adjust reasoning_scroll_region if set.
            if let Some(region) = reasoning_scroll_region.as_mut() {
                region.row_start += 1;
                region.row_end += 1;
            }
            metric_rows.push(MetricRow {
                row: insert_at,
                col_start: mr.col_start,
                col_end: mr.col_end,
            });
        } else {
            // Long metric: split TTFT and TPS onto separate rows.
            let perf = performance.as_ref().unwrap();
            let ttft_label = format!("TTFT: {}", format_ttft(perf.ttft_ms));
            let tps_label = match format_tps(perf) {
                Some(tps) => format!("TPS: {tps}"),
                None => "TPS: -".to_string(),
            };
            let insert_at = 1.min(out.len());
            let mut current_row = insert_at;
            for label in [&ttft_label, &tps_label] {
                let label_w = label.width();
                if label_w + AGENT_INDENT <= width as usize {
                    let (row_line, mr) = render_metric_metadata_row(label, false, width);
                    out.insert(current_row, row_line);
                    conts.insert(current_row, false);
                    metric_rows.push(MetricRow {
                        row: current_row,
                        col_start: mr.col_start,
                        col_end: mr.col_end,
                    });
                    current_row += 1;
                } else {
                    // Label on one row, value on the next.
                    let parts: Vec<&str> = label.splitn(2, ' ').collect();
                    if parts.len() == 2 {
                        let (l1, _) = render_metric_metadata_row(parts[0], false, width);
                        out.insert(current_row, l1);
                        conts.insert(current_row, false);
                        current_row += 1;
                        let (l2, mr2) = render_metric_metadata_row(parts[1], false, width);
                        out.insert(current_row, l2);
                        conts.insert(current_row, false);
                        metric_rows.push(MetricRow {
                            row: current_row,
                            col_start: mr2.col_start,
                            col_end: mr2.col_end,
                        });
                        current_row += 1;
                    } else {
                        let (row_line, mr) = render_metric_metadata_row(label, false, width);
                        out.insert(current_row, row_line);
                        conts.insert(current_row, false);
                        metric_rows.push(MetricRow {
                            row: current_row,
                            col_start: mr.col_start,
                            col_end: mr.col_end,
                        });
                        current_row += 1;
                    }
                }
            }
            // Adjust chip_row and copy_body_start for inserted rows.
            let inserted = current_row - insert_at;
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

        // Expanded detail line (if the metric is expanded).
        if performance_expanded {
            let perf = performance.as_ref().unwrap();
            let detail = metric_detail_text(perf);
            let detail_w = detail.width();
            let detail_rows = if detail_w + AGENT_INDENT <= width as usize {
                vec![detail]
            } else {
                // Split detail across rows per the wrapping rule.
                let ttft_part = format!("TTFT: {}s", format_ttft(perf.ttft_ms));
                let tps_part = match format_tps(perf) {
                    Some(tps) => format!("TPS: {tps}"),
                    None => "TPS: -".to_string(),
                };
                vec![ttft_part, tps_part]
            };
            for d in &detail_rows {
                let (row_line, _) = render_metric_metadata_row(d, true, width);
                out.push(row_line);
                conts.push(false);
            }
        }

        if !metric_rows.is_empty() {
            metric_region = Some(MetricRegion { rows: metric_rows });
        }
    } else if metric_region.is_some() && performance_expanded {
        // Inline metric was placed; add expanded detail rows after the
        // first row.
        let perf = performance.as_ref().unwrap();
        let detail = metric_detail_text(perf);
        let detail_w = detail.width();
        let detail_rows = if detail_w + AGENT_INDENT <= width as usize {
            vec![detail]
        } else {
            let ttft_part = format!("TTFT: {}s", format_ttft(perf.ttft_ms));
            let tps_part = match format_tps(perf) {
                Some(tps) => format!("TPS: {tps}"),
                None => "TPS: -".to_string(),
            };
            vec![ttft_part, tps_part]
        };
        let insert_at = 1.min(out.len());
        for (i, d) in detail_rows.iter().enumerate() {
            let (row_line, _) = render_metric_metadata_row(d, true, width);
            out.insert(insert_at + i, row_line);
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

/// Light grey for the subagent response body — the same chrome/banner
/// muted grey used elsewhere for secondary text.
const SUBAGENT_BODY_FG: Color = Color::Indexed(MUTED_COLOR_INDEX);
/// Orange for a subagent's (child) name in both the running line and
/// the settled header.
const SUBAGENT_NAME_FG: Color = SUBAGENT_ORANGE;

/// Style for a delegated child agent's display name in history rows.
///
/// Shared with chrome's active-agent slot so the bottom status color follows
/// the same source of truth as the live/settled subagent history headers.
pub fn subagent_child_name_style(_name: &str) -> Style {
    Style::default().fg(SUBAGENT_NAME_FG)
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
/// response body: markdown-rendered, tinted light grey, sitting in a
/// left-`│`-bar quoted block. The body is truncated to
/// [`SUBAGENT_PREVIEW_LINES`] leading lines with a clickable `…
/// (expand)` affordance (the returned `chip_row`) unless `expanded`.
/// An empty report renders the header alone with no quoted block.
///
/// Only the child name carries orange; the parent uses the default
/// style.
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
    let indent = " ".repeat(AGENT_INDENT);
    let name_style = subagent_child_name_style(child);
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
        let mut spans = vec![Span::raw(indent)];
        if let Some(label) = batch_label {
            spans.push(Span::styled(
                format!("{label} "),
                Style::default()
                    .fg(Color::Indexed(MUTED_COLOR_INDEX))
                    .add_modifier(Modifier::BOLD),
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
        return Rendered {
            lines: vec![Line::from(spans)],
            chip_row: None,
            continuations: vec![false],
            tool_call_rows: Vec::new(),
            tool_result_scroll_regions: Vec::new(),
            reasoning_scroll_region: None,
            copy_body_start: None,
            pin_region: None,
            metric_region: None,
        };
    };

    // Settled: header line, child name in orange.
    let verb = if outcome.failed {
        "failed after"
    } else {
        "worked for"
    };
    let duration = format_compact_duration(outcome.duration);
    let mut header_spans = vec![Span::raw(indent.clone())];
    if let Some(label) = batch_label {
        header_spans.push(Span::styled(
            format!("{label} ✓ "),
            Style::default()
                .fg(Color::Indexed(MUTED_COLOR_INDEX))
                .add_modifier(Modifier::BOLD),
        ));
    }
    header_spans.extend([
        Span::styled(child.to_string(), name_style),
        Span::raw(format!(" {verb} {duration}")),
    ]);
    append_subagent_routing_chips(&mut header_spans, model_trusted, routing);
    let header = Line::from(header_spans);

    let mut out: Vec<Line<'static>> = vec![header];
    let mut conts: Vec<bool> = vec![false];
    let mut chip_row = None;

    if let Some(status) = &outcome.status {
        out.push(Line::from(vec![
            Span::raw(indent.clone()),
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

    // Quoted body: markdown-rendered, light grey, behind a left `│`
    // bar. Pre-wrap to the bar-reduced width so continuations keep the
    // bar instead of dropping to column 0.
    let bar = "│ ";
    let body_w = (width as usize)
        .saturating_sub(AGENT_INDENT + bar.width())
        .max(1);
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
        let mut spans: Vec<Span<'static>> = vec![
            Span::raw(indent.clone()),
            Span::styled(bar.to_string(), Style::default().fg(SUBAGENT_BODY_FG)),
        ];
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
            Span::raw(indent.clone()),
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
            Span::raw(indent),
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
        Style::default()
            .fg(Color::Indexed(MUTED_COLOR_INDEX))
            .add_modifier(Modifier::DIM),
    ));
    if let Some(location) = routing
        .location
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        spans.push(Span::raw(" "));
        spans.push(Span::styled(
            format!("[{location}]"),
            Style::default()
                .fg(Color::Indexed(MUTED_COLOR_INDEX))
                .add_modifier(Modifier::DIM),
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
            Style::default()
                .fg(Color::Indexed(MUTED_COLOR_INDEX))
                .add_modifier(Modifier::DIM),
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

/// Like [`tool_glyph_label`], but when `file_icons` is on, real write/edit
/// tools use a Nerd Font file-type icon derived from `path`; virtual plan
/// documents use the generic document glyph instead.
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
    // Real write/edit calls derive the file-type icon from their rendered path
    // summary. Virtual plan documents have no path and receive a generic
    // document glyph without inspecting their arbitrary summary.
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
        ToolCallState::Success => Style::default().fg(Color::White),
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
    let (glyph, label) = tool_call_glyph_label(call, emojis, file_icons);
    let style = tool_state_style(call.state);
    let mut spans = Vec::new();
    if !glyph.is_empty() {
        spans.push(Span::raw(glyph));
    }
    spans.push(Span::styled(
        format!("{label}:"),
        style.add_modifier(Modifier::BOLD),
    ));
    if !text.is_empty() {
        spans.push(Span::raw(" ".to_string()));
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
    let (glyph, label) = tool_glyph_label_for(tool, emojis, file_icons, Some(path));
    let style = tool_state_style(state);
    let mut spans = Vec::new();
    if !glyph.is_empty() {
        spans.push(Span::raw(glyph));
    }
    spans.push(Span::styled(
        format!("{label}:"),
        style.add_modifier(Modifier::BOLD),
    ));
    if !text.is_empty() {
        spans.push(Span::raw(" ".to_string()));
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

/// Left sidebar glyph for row `i` of an `n`-row box: rounded caps top
/// and bottom, a plain rule in between, a single rule for a 1-row box.
fn sidebar_glyph(i: usize, n: usize) -> char {
    if n <= 1 {
        '│'
    } else if i == 0 {
        '╭'
    } else if i + 1 == n {
        '╰'
    } else {
        '│'
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
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
                    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
                    Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))
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
                            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
                            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
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
                        Style::default()
                            .fg(Color::Indexed(MUTED_COLOR_INDEX))
                            .add_modifier(Modifier::ITALIC),
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

    let n = content.len();
    let mut out: Vec<Line<'static>> = Vec::with_capacity(n);
    for (i, mut spans) in content.into_iter().enumerate() {
        let mut row = vec![
            Span::styled(
                sidebar_glyph(i, n).to_string(),
                Style::default().fg(SIDEBAR_FG),
            ),
            Span::raw(" ".to_string()),
        ];
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

/// Project the daemon-owned compaction record into the ordinary tool-call
/// renderer. The handoff stays a user message on the model wire; this is
/// presentation-only synthetic tool chrome.
#[allow(clippy::too_many_arguments)]
fn compact_tool_call(
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
    result_offset: usize,
) -> ToolCall {
    let ctx = trigger_ctx_pct
        .map(|pct| format!(" · ctx {pct:.1}%"))
        .unwrap_or_default();
    let summary = format!("source={source}{ctx} · from {predecessor_short_id}");
    let full_input = format!(
        "source={source}{ctx}\n\
         tokens={tokens_before}→{tokens_after}\n\
         turns summarized={turns_summarized}\n\
         tail kept={tail_kept}, trimmed={tail_trimmed}\n\
         seed tools={seed_tool_count} (~{seed_tool_tokens} tokens)"
    );
    ToolCall {
        call_id: format!("compact-{predecessor_short_id}"),
        tool: "compact".to_string(),
        summary,
        full_input,
        output: handoff.unwrap_or("").to_string(),
        expanded,
        result_offset,
        state: ToolCallState::Success,
        hint: None,
        progress: None,
        mcp_child: None,
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

/// Columns the inline control block (`▶ ` pick-arrow when selected + the
/// `[fork] [pin]`/`[unpin]` controls when shown) reserves on an agent's
/// first line, *plus* one separating space before the timestamp when the
/// control is present (`pinned-messages`). Zero when neither arrow nor
/// control is drawn — the line then reserves only the timestamp, exactly
/// as before this feature.
fn agent_pin_reserve(pin: Option<PinControl>) -> usize {
    let Some(p) = pin else { return 0 };
    let mut w = 0;
    if p.is_pick {
        // `▶ ` — arrow glyph + a trailing space.
        w += crate::tui::pins_overlay::PICK_ARROW.width() + 1;
    }
    let ctrl = p.control_width(true);
    if ctrl > 0 {
        // The controls' glyphs + one space separating them from the ts.
        w += ctrl + 1;
    }
    w
}

/// Build an agent first line with the inline control block sitting immediately
/// left of the right-margin-aligned timestamp: `…content…  ▶ [fork] [pin] 12:00`
/// (`pinned-messages`). The caller has already wrapped `spans`' text
/// leaving the control block plus `TIMESTAMP_WIDTH + 1` columns clear on the
/// right. Degrades gracefully on narrow widths: the timestamp always wins;
/// if both chips cannot fit, `[fork]` is dropped before `[pin]`; if `[pin]`
/// cannot fit either, no region is returned.
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
    let pin_only_ctrl = p.control_width(false);
    let right_margin = TIMESTAMP_RIGHT_MARGIN.min(area.saturating_sub(used + TIMESTAMP_WIDTH + 1));
    let timestamp_reserve = TIMESTAMP_WIDTH + 1 + right_margin;
    let (control_w, include_fork) =
        if full_ctrl > 0 && used + arrow_w + full_ctrl + timestamp_reserve < area {
            (full_ctrl, true)
        } else if pin_only_ctrl > 0 && used + arrow_w + pin_only_ctrl + timestamp_reserve < area {
            (pin_only_ctrl, false)
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
    let full_ctrl = p.control_width(true);
    let pin_only_ctrl = p.control_width(false);
    let right_margin = TIMESTAMP_RIGHT_MARGIN.min(area.saturating_sub(used + TIMESTAMP_WIDTH + 1));
    let timestamp_reserve = TIMESTAMP_WIDTH + 1 + right_margin;
    let (control_w, include_fork) =
        if full_ctrl > 0 && used + arrow_w + full_ctrl + timestamp_reserve < area {
            (full_ctrl, true)
        } else if pin_only_ctrl > 0 && used + arrow_w + pin_only_ctrl + timestamp_reserve < area {
            (pin_only_ctrl, false)
        } else if arrow_w > 0 && used + arrow_w + TIMESTAMP_WIDTH + right_margin < area {
            (0, false)
        } else {
            return (
                render_first_line_timestamped(spans, timestamp, width, true),
                None,
            );
        };
    let pin_block = arrow_w + control_w + usize::from(control_w > 0);
    let pad = area.saturating_sub(used + pin_block + TIMESTAMP_WIDTH + 1 + right_margin);
    spans.push(Span::raw(" ".repeat(pad + 1)));
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
    (Line::from(spans), region)
}

fn format_timestamp(t: DateTime<Local>) -> String {
    t.format("%H:%M").to_string()
}

/// Render a dedicated metric metadata row: the compact chip (or expanded
/// detail) left-aligned at `AGENT_INDENT`. Returns the line and the
/// metric hit row (column range covering the chip text).
fn render_metric_metadata_row(
    metric_text: &str,
    detail: bool,
    width: u16,
) -> (Line<'static>, MetricRow) {
    let indent = " ".repeat(AGENT_INDENT);
    let text_w = metric_text.width();
    let col_start = AGENT_INDENT as u16;
    let style = if detail {
        metric_detail_style()
    } else {
        metric_chip_style()
    };
    let line = Line::from(vec![
        Span::raw(indent),
        Span::styled(metric_text.to_string(), style),
    ]);
    let _ = width;
    (
        line,
        MetricRow {
            row: 0,
            col_start,
            col_end: col_start + text_w as u16,
        },
    )
}

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
