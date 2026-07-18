//! Top-level TUI state and event loop.
//!
//! Mouse capture is gated by `tui.mouse_capture` (default on, plan.md
//! T8.c). With capture on: clickable chips, click-to-position-cursor
//! in the composer, and drag-select in chat history (T8.f). Native
//! terminal selection still works under capture if the user holds the
//! terminal's bypass modifier (Shift on most Linux/Windows Terminal,
//! Option on iTerm2, Fn on macOS Terminal). With capture off: the
//! terminal handles wheel/select/copy natively and `MouseEvent`s
//! never reach this loop — the user can use `Ctrl+J` as a newline
//! fallback in the composer.

mod btw_pane;
mod events;
pub(in crate::tui) mod help_overlay;
mod input;
mod mouse;
mod pins;
mod render;
mod slash;

use events::{
    GIT_AGENT_TOKEN_CAP, WORKING_MESSAGES, cache_config_caches, cap_display_lines, cap_tokens,
    exec_capture_git, exec_capture_shell, format_schedule_line, merge_counts, new_pending,
    parse_llm_mode_arg, sanitize_for_raw_stdout, session_schedule_ids, strip_ansi,
    turns_from_history, wire_history_to_entries, xml_escape,
};
#[cfg(test)]
use events::{
    LOCAL_CMD_DISPLAY_LINES, RunCaptureOptions, SubagentReportUpdate, pick_working_msg,
    run_capture_with_options, settle_subagent_in, tool_invocation,
};
use input::accepts_key;
use render::{extract_selection_markdown_source, extract_selection_plaintext, is_edit_tool};
#[cfg(test)]
use slash::{
    AgentCommandOutcome, CopyFormat, McpAction, SLASH_COMMANDS, SandboxCommand,
    SandboxEscalationCommand, SkillDispatch, agent_command_outcome, builtin_slash_name_taken,
    last_agent_text, next_sandbox_mode, parse_copy_format, parse_mcp_action, parse_pane_side,
    parse_sandbox_arg, parse_sandbox_escalation_arg, resolve_skill_dispatch, slash_matches,
};
use slash::{
    SkillCommand, SlashCommand, SlashEntry, SlashMenuCache, bare_skill_commands_from,
    discover_bare_skill_commands, hidden_slash_alias, sandbox_mode_label, slash_args,
    slash_matches_in,
};

use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::future::pending;
use std::io::{Read, Write, stdout};
use std::path::{Path, PathBuf};
use std::rc::Rc;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossterm::cursor::SetCursorStyle;
use crossterm::event::{
    DisableMouseCapture, EnableMouseCapture, Event, KeyboardEnhancementFlags, MouseButton,
    MouseEvent, MouseEventKind, PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use ratatui::DefaultTerminal;
use ratatui::layout::Rect;
use unicode_width::UnicodeWidthChar;

use crate::config::extended::{DiffStyle, ThinkingDisplay, VimModeSetting};
use crate::engine::TurnEvent;
use crate::engine::message::{QueueTarget, QueuedUserMessage};
use crate::git::{self, RepoStatus};
use crate::tui::agent_runner::{self, AgentRunner};
use crate::tui::app::btw_pane::BtwPane;
use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy, AsyncActionResult,
    AsyncActionRunner,
};
use crate::tui::composer::{Composer, VimMode, input_prefix_width};
use crate::tui::geometry::PaneGeometry;
use crate::tui::history::{
    HistoryEntry, MarkdownOpts, PendingMsg, SubagentOutcome, SubagentRoutingChips, ToolCall,
    ToolCallState, classify_subagent_status, route_text_delta,
};
use crate::tui::input_source::{MAX_DRAIN_PER_PASS, TerminalInput, with_input_suspended};
use crate::tui::settings::{self, Dialog, OAuthBeginResult, OAuthFlowOp, OAuthProvider};
use crate::welcome::{self, LaunchBundle, LaunchInfo};

const GIT_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const ANIMATION_TICK: Duration = Duration::from_millis(100);
const RUN_CAPTURE_MAX_BYTES: usize = 256 * 1024;
const RUN_CAPTURE_TIMEOUT: Duration = Duration::from_secs(30);
const RUN_CAPTURE_POLL: Duration = Duration::from_millis(10);

/// Double-press window for ctrl+c (GOALS §3a). A single ctrl+c interrupts
/// the running agent (never quits); a second press within this window of
/// the previous press exits the TUI. Sliding from the last press, so a
/// steady stream of slow presses interrupts repeatedly and never exits.
pub(super) const CTRL_C_EXIT_WINDOW: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FooterHitArea {
    control: crate::tui::chrome::FooterControl,
    rect: Rect,
}

#[cfg(test)]
mod auth_failure_recovery_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FooterPickerKind {
    Agent,
    Mode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SuggestionBoxKind {
    At,
    Slash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SuggestionBoxTarget {
    kind: SuggestionBoxKind,
    index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SuggestionBoxRowHit {
    target: SuggestionBoxTarget,
    rect: Rect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FooterPickerRowHit {
    kind: FooterPickerKind,
    index: usize,
    rect: Rect,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FooterAgentPicker {
    entries: Vec<String>,
    cursor: usize,
}

impl FooterAgentPicker {
    fn new(current: &str, entries: Vec<String>) -> Self {
        let cursor = entries.iter().position(|name| name == current).unwrap_or(0);
        Self { entries, cursor }
    }

    fn selected_agent(&self) -> Option<&str> {
        self.entries.get(self.cursor).map(String::as_str)
    }

    fn next(&mut self) {
        self.cursor = crate::tui::nav::wrap_next(self.cursor, self.entries.len());
    }

    fn prev(&mut self) {
        self.cursor = crate::tui::nav::wrap_prev(self.cursor, self.entries.len());
    }

    fn select(&mut self, index: usize) {
        if index < self.entries.len() {
            self.cursor = index;
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FooterModePicker {
    cursor: usize,
}

impl FooterModePicker {
    fn new(current: crate::config::extended::LlmMode) -> Self {
        Self {
            cursor: footer_mode_index(current),
        }
    }

    fn selected_mode(self) -> crate::config::extended::LlmMode {
        FOOTER_MODE_ORDER[self.cursor]
    }

    fn next(&mut self) {
        self.cursor = (self.cursor + 1) % FOOTER_MODE_ORDER.len();
    }

    fn prev(&mut self) {
        self.cursor = if self.cursor == 0 {
            FOOTER_MODE_ORDER.len() - 1
        } else {
            self.cursor - 1
        };
    }

    fn select(&mut self, index: usize) {
        if index < FOOTER_MODE_ORDER.len() {
            self.cursor = index;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PendingAgentSwitchLog {
    confirmation_index: usize,
    target: String,
}

const FOOTER_MODE_ORDER: [crate::config::extended::LlmMode; 3] = [
    crate::config::extended::LlmMode::Defensive,
    crate::config::extended::LlmMode::Normal,
    crate::config::extended::LlmMode::Frontier,
];

fn footer_mode_index(mode: crate::config::extended::LlmMode) -> usize {
    FOOTER_MODE_ORDER
        .iter()
        .position(|m| *m == mode)
        .unwrap_or(0)
}

fn footer_agent_picker_height(picker: Option<&FooterAgentPicker>) -> u16 {
    let rows = picker.map(|p| p.entries.len()).unwrap_or(0).min(12) as u16;
    rows + 4
}

fn resolve_tui_llm_mode(
    active_model: Option<&(String, String)>,
    global: crate::config::extended::LlmMode,
    providers: &crate::config::providers::ProvidersConfig,
) -> crate::config::extended::LlmMode {
    let Some((provider, model)) = active_model else {
        return global;
    };
    providers.resolve_mode(provider, model, global)
}

fn persist_trusted_only_default(cwd: &Path, enabled: bool) -> anyhow::Result<()> {
    use crate::config::dirs::{CONFIG_FILE, discover_config_dirs};
    use crate::config::extended::ExtendedConfigDoc;

    let target = discover_config_dirs(cwd)
        .into_iter()
        .map(|d| d.path.join(CONFIG_FILE))
        .find(|p| p.exists())
        .unwrap_or_else(|| cwd.join(".cockpit").join(CONFIG_FILE));
    let mut doc = ExtendedConfigDoc::load(&target)?;
    let mut cfg = doc.config();
    cfg.trusted_only = enabled;
    doc.write(&cfg)?;
    Ok(())
}

fn new_external_editor_tempfile() -> std::io::Result<tempfile::NamedTempFile> {
    let mut builder = tempfile::Builder::new();
    builder.prefix("cockpit-prompt-").suffix(".md");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }
    builder.tempfile()
}

#[cfg(test)]
mod selection_copy_state_tests;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalCleanupCommand {
    DisableMouseCapture,
    DisableBracketedPaste,
    PopKeyboardEnhancementFlags,
    RestoreDefaultCursorShape,
    RestoreTerminalTitle { pushed: bool },
    RestoreRatatui,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FreshQueueAck {
    None,
    AwaitingAck,
    SuppressId(uuid::Uuid),
    FoldedBeforeAck(uuid::Uuid),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum WorkingSpanState {
    Idle,
    PendingStart,
    Running { turn_id: Option<String> },
}

const ENABLE_ANY_MOUSE_MOTION: &str = "\x1b[?1003h";
const DISABLE_ANY_MOUSE_MOTION: &str = "\x1b[?1003l";

fn keyboard_enhancement_flags() -> KeyboardEnhancementFlags {
    KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES
        | KeyboardEnhancementFlags::REPORT_ALL_KEYS_AS_ESCAPE_CODES
        | KeyboardEnhancementFlags::REPORT_ALTERNATE_KEYS
        | KeyboardEnhancementFlags::REPORT_EVENT_TYPES
}

fn enable_mouse_capture_with_motion() -> std::io::Result<()> {
    crossterm::execute!(stdout(), EnableMouseCapture)?;
    if let Err(err) =
        crossterm::execute!(stdout(), crossterm::style::Print(ENABLE_ANY_MOUSE_MOTION))
    {
        let _ = crossterm::execute!(stdout(), DisableMouseCapture);
        return Err(err);
    }
    Ok(())
}

fn disable_mouse_capture_with_motion() -> std::io::Result<()> {
    let motion = crossterm::execute!(stdout(), crossterm::style::Print(DISABLE_ANY_MOUSE_MOTION));
    let capture = crossterm::execute!(stdout(), DisableMouseCapture);
    motion.and(capture)
}

trait TerminalModeSink {
    fn apply(&mut self, command: TerminalCleanupCommand) -> Result<()>;
}

struct CrosstermTerminalModeSink;

impl TerminalModeSink for CrosstermTerminalModeSink {
    fn apply(&mut self, command: TerminalCleanupCommand) -> Result<()> {
        match command {
            TerminalCleanupCommand::DisableMouseCapture => {
                disable_mouse_capture_with_motion()?;
            }
            TerminalCleanupCommand::DisableBracketedPaste => {
                crossterm::execute!(stdout(), crossterm::event::DisableBracketedPaste)?;
            }
            TerminalCleanupCommand::PopKeyboardEnhancementFlags => {
                crossterm::execute!(stdout(), PopKeyboardEnhancementFlags)?;
            }
            TerminalCleanupCommand::RestoreDefaultCursorShape => {
                crossterm::execute!(stdout(), SetCursorStyle::DefaultUserShape)?;
            }
            TerminalCleanupCommand::RestoreTerminalTitle { pushed } => {
                emit_terminal_title_sequence(
                    &crate::tui::attention::terminal_title_restore_escapes(pushed),
                );
            }
            TerminalCleanupCommand::RestoreRatatui => {
                ratatui::try_restore()?;
            }
        }
        Ok(())
    }
}

struct TerminalModeGuard<S: TerminalModeSink = CrosstermTerminalModeSink> {
    sink: S,
    mouse_capture_enabled: bool,
    bracketed_paste_enabled: bool,
    keyboard_enhancement_pushed: bool,
    restore_cursor_shape: bool,
    terminal_title_pushed: Arc<AtomicBool>,
    restored: bool,
}

impl<S: TerminalModeSink> TerminalModeGuard<S> {
    #[cfg(test)]
    fn with_sink(sink: S) -> Self {
        Self::with_sink_and_title_state(sink, Arc::new(AtomicBool::new(false)))
    }

    fn with_sink_and_title_state(sink: S, terminal_title_pushed: Arc<AtomicBool>) -> Self {
        Self {
            sink,
            mouse_capture_enabled: false,
            bracketed_paste_enabled: false,
            keyboard_enhancement_pushed: false,
            restore_cursor_shape: true,
            terminal_title_pushed,
            restored: false,
        }
    }

    fn mark_mouse_capture_enabled(&mut self) {
        self.mouse_capture_enabled = true;
    }

    fn mark_bracketed_paste_enabled(&mut self) {
        self.bracketed_paste_enabled = true;
    }

    fn mark_keyboard_enhancement_pushed(&mut self) {
        self.keyboard_enhancement_pushed = true;
    }

    fn apply_cleanup_command(
        &mut self,
        command: TerminalCleanupCommand,
        first_error: &mut Option<anyhow::Error>,
    ) {
        if let Err(err) = self.sink.apply(command) {
            first_error.get_or_insert(err);
        }
    }

    fn cleanup(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        let mut first_error = None;
        if self.mouse_capture_enabled {
            self.apply_cleanup_command(
                TerminalCleanupCommand::DisableMouseCapture,
                &mut first_error,
            );
            self.mouse_capture_enabled = false;
        }
        if self.bracketed_paste_enabled {
            self.apply_cleanup_command(
                TerminalCleanupCommand::DisableBracketedPaste,
                &mut first_error,
            );
            self.bracketed_paste_enabled = false;
        }
        if self.keyboard_enhancement_pushed {
            self.apply_cleanup_command(
                TerminalCleanupCommand::PopKeyboardEnhancementFlags,
                &mut first_error,
            );
            self.keyboard_enhancement_pushed = false;
        }
        if self.restore_cursor_shape {
            self.apply_cleanup_command(
                TerminalCleanupCommand::RestoreDefaultCursorShape,
                &mut first_error,
            );
            self.restore_cursor_shape = false;
        }
        let pushed = self.terminal_title_pushed.swap(false, Ordering::SeqCst);
        self.apply_cleanup_command(
            TerminalCleanupCommand::RestoreTerminalTitle { pushed },
            &mut first_error,
        );
        self.apply_cleanup_command(TerminalCleanupCommand::RestoreRatatui, &mut first_error);
        if let Some(err) = first_error {
            Err(err)
        } else {
            Ok(())
        }
    }
}

impl<S: TerminalModeSink> Drop for TerminalModeGuard<S> {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

/// What a ctrl+c press should do, decided purely from the prior-press
/// time, the agent's busy state, and the configured window. Factored out
/// of [`App`] so the state machine is unit-testable without a live
/// terminal or daemon. See [`decide_ctrl_c`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CtrlCAction {
    /// Second press inside the window — exit the TUI now (regardless of
    /// agent state). During a run, this is the "interrupt AND exit" case:
    /// the first press already sent the interrupt.
    Exit,
    /// First press (or first after the window lapsed) while the agent is
    /// running — arm the exit window, show the hint, and interrupt the
    /// agent.
    ArmAndInterrupt,
    /// First press while the agent is idle — arm the exit window and show
    /// the hint only (nothing to interrupt).
    ArmOnly,
}

/// Pure double-press decision (GOALS §3a). `now` is a monotonic clock
/// reading; `armed_at` is the previous press time while the window is
/// live (`None` once it has lapsed); `agent_busy` is whether a turn is in
/// flight. Returns the action plus the new `armed_at` to store: `None`
/// when exiting (window is moot), `Some(now)` when arming/re-arming.
///
/// Rules:
/// - A press within `window` of `armed_at` → [`CtrlCAction::Exit`].
/// - Otherwise it's a fresh first press: re-arm at `now`, and interrupt
///   iff the agent is running.
pub(super) fn decide_ctrl_c(
    now: Instant,
    armed_at: Option<Instant>,
    window: Duration,
    agent_busy: bool,
) -> (CtrlCAction, Option<Instant>) {
    if let Some(prev) = armed_at
        && now.duration_since(prev) <= window
    {
        // Second press inside the window: exit regardless of agent state.
        return (CtrlCAction::Exit, None);
    }
    // Fresh first press (or the window lapsed): arm and, if busy, interrupt.
    let action = if agent_busy {
        CtrlCAction::ArmAndInterrupt
    } else {
        CtrlCAction::ArmOnly
    };
    (action, Some(now))
}

/// Pure gate for the eager display attach (session-id-shown-before-first-
/// message). Decides whether [`App::ensure_session_for_display`] should
/// attach a deferred session now so the welcome box can show its short id
/// before any message is sent. Factored out of [`App`] so the precedence is
/// unit-testable without a live daemon or terminal.
///
/// `probe_when` is the (costly) "is the canonical daemon reachable right
/// now?" check; it is invoked lazily — only when the cheap struct-only gates
/// all pass — so a tick that can't attach for any other reason never pays for
/// a socket probe.
///
/// All of these must hold:
/// - no runner exists yet (`!has_runner`) — a live runner already shows the
///   id, and a poisoned `Some(Err)` from a *first-message* attempt is left
///   alone (it was already surfaced to the user);
/// - the "daemon not running" prompt is closed (`!prompt_open`) — never spawn
///   a daemon out from under the user's pending choice;
/// - not daemonless (`!daemonless`) — eager-attaching there would spawn the
///   owned ephemeral daemon purely to display an id (a deliberate non-goal);
/// - we believe a daemon should be reachable (`daemon_connected`); and
/// - the canonical daemon actually answers right now (`probe_when()`) — so we
///   don't fire against the not-yet-bound socket in the "Start and connect"
///   startup gap.
fn should_attempt_display_attach(
    has_runner: bool,
    prompt_open: bool,
    daemonless: bool,
    daemon_connected: bool,
    probe_when: impl FnOnce() -> bool,
) -> bool {
    if has_runner || prompt_open || daemonless || !daemon_connected {
        return false;
    }
    probe_when()
}

/// Max suggestion rows the slash / @ autocomplete popup ever takes.
/// When fewer matches exist, the popup pads with blank lines so the
/// composer doesn't visibly shift as the user types and the candidate
/// set narrows. Keeps layout pinned to a 6-row reservation.
pub(crate) const AUTOCOMPLETE_ROWS: u16 = 6;

fn attach_to_session_retry_once<T, E>(mut attach: impl FnMut() -> Result<T, E>) -> Result<T, E> {
    match attach() {
        Ok(value) => Ok(value),
        Err(_) => attach(),
    }
}

const DISPLAY_ATTACH_INITIAL_BACKOFF: Duration = Duration::from_millis(250);
const DISPLAY_ATTACH_MAX_BACKOFF: Duration = Duration::from_secs(5);

#[derive(Debug, Clone)]
struct DisplayAttachBackoff {
    next_attempt_at: Option<Instant>,
    delay: Duration,
}

impl Default for DisplayAttachBackoff {
    fn default() -> Self {
        Self {
            next_attempt_at: None,
            delay: DISPLAY_ATTACH_INITIAL_BACKOFF,
        }
    }
}

impl DisplayAttachBackoff {
    fn can_attempt(&self, now: Instant) -> bool {
        self.next_attempt_at.is_none_or(|next| now >= next)
    }

    fn record_failure(&mut self, now: Instant) {
        let delay = self.delay.min(DISPLAY_ATTACH_MAX_BACKOFF);
        self.next_attempt_at = Some(now + delay);
        self.delay = delay.saturating_mul(2).min(DISPLAY_ATTACH_MAX_BACKOFF);
    }

    fn reset(&mut self) {
        *self = Self::default();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum AffordanceTarget {
    Chip {
        history_index: usize,
    },
    Subagent {
        history_index: usize,
    },
    ToolBox {
        history_index: usize,
    },
    ToolCall {
        history_index: usize,
        call_index: usize,
    },
    ReasoningWindow {
        history_index: usize,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct AffordanceScrollRegion {
    pub(super) target: AffordanceTarget,
    pub(super) row_start: usize,
    pub(super) row_end: usize,
    pub(super) offset: usize,
    pub(super) max_offset: usize,
}

/// Live network-retry status for the indicator (`Reconnecting` event). Held
/// for the whole `Network`-class retry loop so the status line stays the
/// distinct reconnect message, never the generic working spinner, and names
/// the unreachable target.
#[derive(Debug, Clone)]
pub(super) struct ReconnectStatus {
    /// 1-based attempt number — increments as retries proceed.
    pub(super) attempt: u32,
    /// Provider wire-flavor label of the unreachable endpoint.
    pub(super) provider: String,
    /// Model id being retried.
    pub(super) model: String,
    /// Base URL being retried.
    pub(super) url: String,
}

#[derive(Debug, Clone)]
pub(super) struct DaemonLinkStatus {
    pub(super) restarting: bool,
    pub(super) attempt: u32,
    pub(super) started_at: Instant,
}

/// Legacy `/compact` handoff state from the old review-then-commit path.
/// New compactions are queued and applied in place by the driver.
#[allow(dead_code)]
#[derive(Clone)]
pub(super) struct PendingCompact {
    pub(super) new_session_id: uuid::Uuid,
    pub(super) seed_tool_count: usize,
    /// Approx wire tokens the seed-tools cost on the fresh session's
    /// first turn (from `CompactReady`). Surfaced in the boundary marker.
    pub(super) seed_tool_tokens: u64,
    /// The predecessor (current) session's short id, captured at
    /// `CompactReady` time so the fresh session can draw a `compacted
    /// from <short-id>` boundary marker once committed. Empty when the
    /// runner had no short id.
    pub(super) predecessor_short_id: String,
}

/// A `/init` whose target file already exists, awaiting the user's
/// update/overwrite/cancel choice in the (locally-driven) question
/// dialog. The dialog carries `interrupt_id`; the close handler matches
/// it so the local choice resolves here rather than going to the daemon.
pub(super) struct PendingInit {
    /// The synthetic interrupt id minted for the local choice dialog.
    pub(super) interrupt_id: uuid::Uuid,
    /// The target path to hand the agent (relative to cwd when under it).
    pub(super) display: String,
}

/// A reattached session has durable work paused by daemon shutdown and is
/// awaiting the user's local resume/cancel choice.
pub(super) struct PendingPausedWork {
    pub(super) interrupt_id: uuid::Uuid,
    pub(super) session_id: uuid::Uuid,
}

/// A Responses-backed session reopened read-only because provider replay
/// history needs an explicit repair/fork/export decision.
pub(super) struct PendingResumeRepair {
    pub(super) interrupt_id: uuid::Uuid,
    pub(super) state: crate::daemon::proto::ResumeRepairState,
}

#[derive(Default)]
pub(super) enum Overlay {
    #[default]
    None,
    ModelPicker(crate::tui::model_picker::ModelPickerDialog),
    Multireview(crate::tui::multireview_dialog::MultireviewDialog),
    Stats(crate::tui::stats_pane::StatsPane),
    Usage(crate::tui::usage_pane::UsagePane),
    Sessions(crate::tui::sessions_pane::SessionsPane),
    Skills(crate::tui::skills_pane::SkillsPane),
    Permissions(crate::tui::permissions_pane::PermissionsPane),
    Resources(crate::tui::resources_pane::ResourcesPane),
    Quick(crate::tui::quick_dialog::QuickDialog),
    Context(crate::tui::context_pane::ContextPane),
    Notes(crate::tui::notes_pane::NotesPane),
    Diff(crate::tui::diff_pane::DiffPane),
    Help(help_overlay::HelpOverlay),
}

impl Overlay {
    pub(super) fn is_open(&self) -> bool {
        !matches!(self, Self::None)
    }

    pub(super) fn dialog_height(&self) -> u16 {
        match self {
            Self::ModelPicker(_) => crate::tui::model_picker::DIALOG_HEIGHT,
            Self::Quick(_) => 14,
            Self::Multireview(_) => crate::tui::multireview_dialog::DIALOG_HEIGHT,
            _ => 0,
        }
    }

    pub(super) fn key_context(&self) -> Option<crate::tui::keys_overlay::KeyContext> {
        use crate::tui::keys_overlay::KeyContext;
        match self {
            Self::None => None,
            Self::ModelPicker(_) => Some(KeyContext::ModelPicker),
            Self::Multireview(_) => Some(KeyContext::Settings),
            Self::Sessions(_) => Some(KeyContext::Sessions),
            Self::Permissions(_) => Some(KeyContext::Permissions),
            Self::Resources(_) => Some(KeyContext::Resources),
            Self::Quick(_) => Some(KeyContext::QuickSettings),
            Self::Notes(_) => Some(KeyContext::Scratchpad),
            Self::Diff(_) => Some(KeyContext::Diff),
            Self::Stats(_)
            | Self::Usage(_)
            | Self::Skills(_)
            | Self::Context(_)
            | Self::Help(_) => None,
        }
    }
}

pub(super) enum LocalChoice {
    Init(PendingInit),
    PausedWork(PendingPausedWork),
    ResumeRepair(PendingResumeRepair),
    RedactionToggle(uuid::Uuid),
    ModelComparison(uuid::Uuid),
}

impl LocalChoice {
    fn interrupt_id(&self) -> uuid::Uuid {
        match self {
            Self::Init(pending) => pending.interrupt_id,
            Self::PausedWork(pending) => pending.interrupt_id,
            Self::ResumeRepair(pending) => pending.interrupt_id,
            Self::RedactionToggle(interrupt_id) | Self::ModelComparison(interrupt_id) => {
                *interrupt_id
            }
        }
    }

    fn is_multi(&self) -> bool {
        matches!(self, Self::RedactionToggle(_) | Self::ModelComparison(_))
    }
}

pub(super) enum LocalChoiceSelection {
    Single(Option<String>),
    Multi(Option<Vec<String>>),
}

/// An open `/side` side conversation. Created when `/side` forks the main
/// session into an ephemeral throwaway and switches the TUI onto it; the
/// snapshot is everything needed to restore the **main** session exactly
/// where the user left off when the side conversation ends (`/side end`,
/// or process exit). Restoring re-binds the saved runner and view
/// verbatim — no re-attach, so no lost scrollback. While `Some`, the chrome
/// shows the side indicator and the ephemeral fork id is discarded on exit.
pub(super) struct SideConversation {
    /// The ephemeral fork's session id — the row to discard on exit.
    pub(super) side_session_id: uuid::Uuid,
    /// The daemon socket the side fork lives on (the same one the parent
    /// runner is attached to), so the discard RPC reaches the right daemon.
    pub(super) socket: std::path::PathBuf,
    /// Saved main-session view, restored on exit.
    saved_runner: Option<Result<AgentRunner, String>>,
    saved_history: Vec<HistoryEntry>,
    saved_queue: Vec<QueuedUserMessage>,
    saved_pending: Option<PendingMsg>,
    saved_prunable_tokens: u64,
    saved_cache_cold: bool,
    saved_elided_event_ids: std::collections::HashSet<String>,
    saved_active_schedules: std::collections::BTreeMap<String, ActiveSchedule>,
    saved_pending_stop_confirm: Option<Vec<String>>,
    saved_chat_scroll_offset: usize,
    saved_project_id: Option<String>,
    saved_session_id: Option<uuid::Uuid>,
    saved_session_short_id: Option<String>,
    saved_current_session_persisted: bool,
}

/// Stable option ids for the bare-`/toggle-redaction` multiselect dialog,
/// mapped back to the per-source booleans in [`App::resolve_redaction_toggle`].
const REDACT_OPT_ENV: &str = "redact_env";
const REDACT_OPT_FILE: &str = "redact_file";
const REDACT_OPT_SSH: &str = "redact_ssh";

/// Token-burn caution shown on every entry into the `Swarm` primary
/// (GOALS §24 / §26). Warning only — no budget cap, no spend meter; the user
/// interrupts. Lives on the shared [`App::swap_primary_agent`] path so every
/// route onto `Swarm` (`/swarm`, `/agent Swarm`, the `Shift+Tab`
/// cycle) fires the identical text exactly once.
const SWARM_TOKEN_BURN_WARNING: &str = "Heads up: Swarm mode can spawn parallel recursive subagents and burn a LOT of tokens. \
     There is no budget cap — interrupt (esc) if a fan-out runs away.";
const MULTIREVIEW_TOKEN_BURN_WARNING: &str = "Heads up: `/multireview` can run many models and harnesses at once and burn a LOT of tokens. \
     There is no budget cap — interrupt (esc) if review fan-out runs away.";

/// Result of handing a submitted turn to the agent runner. Carries
/// whether the working span this submit may have started was orphaned —
/// i.e. no worker received the turn, so no `AgentIdle` will ever arrive
/// to lower `busy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DispatchOutcome {
    /// The wire was accepted by a running worker; `AgentIdle` will end
    /// the span normally.
    Sent,
    /// The input queue was full; the turn was rejected.
    QueueFull,
    /// The driver task has exited; the channel is closed.
    DriverClosed,
    /// Runner construction failed (`Some(Err(_))`) — e.g. the model
    /// won't resolve, so no worker was ever spawned.
    RunnerFailed,
    /// No runner present (`None`) — nothing was started.
    NoRunner,
}

impl DispatchOutcome {
    /// True when the turn never reached a worker, so a working span
    /// opened for this submit would otherwise hang forever.
    pub(super) fn span_orphaned(self) -> bool {
        matches!(
            self,
            DispatchOutcome::QueueFull
                | DispatchOutcome::DriverClosed
                | DispatchOutcome::RunnerFailed
                | DispatchOutcome::NoRunner
        )
    }
}

fn failed_dispatch_line(prefix: &str, outcome: DispatchOutcome) -> String {
    match outcome {
        DispatchOutcome::Sent => format!("{prefix}: sent"),
        DispatchOutcome::QueueFull => {
            format!("{prefix}: engine input queue full — try again in a moment")
        }
        DispatchOutcome::DriverClosed => format!("{prefix}: engine driver task has exited"),
        DispatchOutcome::RunnerFailed => format!("{prefix}: could not start agent runner"),
        DispatchOutcome::NoRunner => format!("{prefix}: no engine runner — cannot start"),
    }
}

/// The caution line (if any) that heads the confirmation when swapping the
/// primary to `name`. Returns the [`SWARM_TOKEN_BURN_WARNING`] for
/// `Swarm` and nothing for every other primary — so the warning fires on
/// every route onto `Swarm` (`/swarm`, `/agent Swarm`, the
/// `Shift+Tab` cycle) and never spams the others. Pure so the keying is
/// unit-testable without an `App`.
fn primary_swap_warning(name: &str) -> Option<&'static str> {
    (name == "Swarm").then_some(SWARM_TOKEN_BURN_WARNING)
}

/// Compose the persistent sandbox-down notice (`implementation notes` §6.5) from
/// the daemon-diagnosed `remedy` (incl. the `sudo sysctl …=0` command when
/// present). Always names the deterministic `/sandbox off` composer action so
/// the user has a clear instruction independent of the model. Pure chrome
/// text — it never enters history or any inference request.
const MAX_SANDBOX_NOTICE_ROWS: u16 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SandboxDownNotice {
    pub remedy: String,
    pub fix_command: Option<String>,
}

fn sandbox_down_notice_text(remedy: &str, fix_command: Option<&str>, copy_chip: bool) -> String {
    let mut text = if copy_chip && fix_command.is_some() {
        format!("[copy] ⚠ shell sandbox can't start: {remedy}.")
    } else {
        format!("⚠ shell sandbox can't start: {remedy}.")
    };
    if let Some(command) = fix_command
        && !copy_chip
        && !remedy.contains(command)
    {
        text.push_str(" Fix: ");
        text.push_str(command);
        text.push('.');
    }
    text.push_str(" Run /sandbox off in the composer to continue.");
    text
}

pub(super) fn sandbox_notice_render_text(text: &str) -> String {
    format!(" {text}")
}

pub(super) fn sandbox_notice_wrapped_rows(text: &str, width: u16) -> u16 {
    let width = width.max(1);
    word_wrap_line_count(&sandbox_notice_render_text(text), width).min(MAX_SANDBOX_NOTICE_ROWS)
}

fn word_wrap_line_count(line: &str, width: u16) -> u16 {
    let mut rows = 0u16;
    let mut line_width = 0u16;
    let mut word_width = 0u16;
    let mut whitespace_width = 0u16;
    let mut line_has_content = false;
    let mut non_whitespace_previous = false;

    for ch in line.chars() {
        let is_whitespace = ch.is_whitespace();
        let symbol_width = ch.width().unwrap_or(0) as u16;
        if symbol_width > width {
            continue;
        }

        let word_found = non_whitespace_previous && is_whitespace;
        let trimmed_overflow = !line_has_content && word_width + symbol_width > width;
        let whitespace_overflow = !line_has_content && whitespace_width + symbol_width > width;
        if word_found || trimmed_overflow || whitespace_overflow {
            if line_has_content {
                line_width = line_width.saturating_add(whitespace_width);
            }
            line_width = line_width.saturating_add(word_width);
            line_has_content |= word_width > 0;
            whitespace_width = 0;
            word_width = 0;
        }

        let line_full = line_width >= width;
        let pending_word_overflow =
            symbol_width > 0 && line_width + whitespace_width + word_width >= width;
        if line_full || pending_word_overflow {
            rows = rows.saturating_add(1);
            line_width = 0;
            line_has_content = false;
            if is_whitespace {
                whitespace_width = 0;
                non_whitespace_previous = false;
                continue;
            }
        }

        if is_whitespace {
            whitespace_width = whitespace_width.saturating_add(symbol_width);
        } else {
            word_width = word_width.saturating_add(symbol_width);
        }
        non_whitespace_previous = !is_whitespace;
    }

    if line_has_content || word_width > 0 || rows == 0 {
        rows = rows.saturating_add(1);
    }
    rows
}

/// True when `prog` is found as a file on any `PATH` entry. On Windows
/// also probes `prog.exe`. Used to gate `/lazygit`.
fn program_on_path(prog: &str) -> bool {
    #[cfg(test)]
    PROGRAM_ON_PATH_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    let names: Vec<String> = if cfg!(windows) {
        vec![format!("{prog}.exe"), prog.to_string()]
    } else {
        vec![prog.to_string()]
    };
    std::env::split_paths(&paths).any(|dir| names.iter().any(|n| dir.join(n).is_file()))
}

#[cfg(test)]
static PROGRAM_ON_PATH_CALLS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
fn reset_program_on_path_call_count() {
    PROGRAM_ON_PATH_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn program_on_path_call_count() -> usize {
    PROGRAM_ON_PATH_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

#[cfg(test)]
static MCP_LOAD_CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

#[cfg(test)]
static SLASH_MENU_COUNTER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
fn reset_mcp_load_call_count() {
    MCP_LOAD_CALLS.store(0, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
fn mcp_load_call_count() -> usize {
    MCP_LOAD_CALLS.load(std::sync::atomic::Ordering::SeqCst)
}

fn build_goal_clarification_prompt(objective: &str) -> String {
    format!(
        "The user started `/goal` with this rough objective:\n\n{objective}\n\n\
         Act as Build. First investigate the working directory read-only using normal tools and identify relevant repo facts. \
         Then propose a clarified goal for user review with exactly these parts: `goal` (terse, stable, acceptance-oriented), \
         `context` (repo findings, constraints, relevant files, user preferences), acceptance criteria, and an initial task/todo breakdown when useful. \
         Continue the clarification loop until the user confirms. Only after confirmation call create_goal(objective, context, token_budget if specified). \
         After create_goal, continue normal Build execution toward the active goal using get_goal/update_goal and durable todos."
    )
}

/// Where an embedded pane (`/editor`, `/lazygit`) sits in the chat-body
/// region (GOALS §1i). `Full` fills the body; the others split it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PaneSide {
    Full,
    Left,
    Right,
    Top,
    Bottom,
}

#[derive(Debug, Clone)]
struct StartupBackground {
    daemon_socket: Option<PathBuf>,
    db: Option<crate::db::Db>,
    started: bool,
}

#[allow(private_interfaces)]
pub struct App {
    pub(super) launch: LaunchInfo,
    pub(super) composer: Composer,
    /// User's vim_mode setting (hint/enabled/disabled). Drives whether
    /// the Normal-mode hint chip is shown.
    pub(super) vim_setting: VimModeSetting,
    /// User's thinking-display setting. Drives whether the chip is shown
    /// and whether reasoning is rendered inline.
    pub(super) thinking_setting: ThinkingDisplay,
    /// User's markdown-rendering preferences. Threaded into each
    /// `render_entry` call so the renderer can pick the markdown path
    /// per kind of entry.
    pub(super) markdown_opts: MarkdownOpts,
    /// How `edit` / `editunlock` tool calls render in history
    /// (`tui.diff_style`). The narrow-terminal degradation from
    /// side-by-side → inline is per-render, computed from the
    /// rendered pane width.
    pub(super) diff_style: DiffStyle,
    /// `tui.use_emojis`. Threaded into the history renderers so tool-call
    /// boxes (and other glyphs) pick emoji vs. text-only labels.
    pub(super) use_emojis: bool,
    /// Cached args from `ToolStart` for edit tools that need them at
    /// `ToolEnd` time (to build the `Diff` history entry). Keyed by
    /// `call_id`; entries are popped at `ToolEnd`. Anything left
    /// behind (e.g. a tool that errored before emitting `ToolEnd`)
    /// gets cleaned up on the next `finalize_pending`.
    pub(super) pending_edit_args: HashMap<String, PendingEditArgs>,
    /// Messages typed and submitted while an agent turn is in flight.
    /// Mirrors the daemon's authoritative queue (GOALS §1c) for display
    /// and edit controls. Daemon `QueueUpdated` events are the source of
    /// truth; local code only adds optimistic placeholders while awaiting
    /// the daemon ack.
    pub(super) queue: Vec<QueuedUserMessage>,
    /// Current queue-edit foreground target. Seeded from the daemon attach
    /// snapshot and kept current by `ForegroundInputTarget` events. `None`
    /// means the client lacks enough information to mark any queue item as
    /// non-editable.
    pub(super) foreground_input_target: Option<QueueTarget>,
    /// Fresh idle submits render immediately as a transcript row. The daemon
    /// still acknowledges them through the queue API, so the originating TUI
    /// suppresses that one daemon queue item until the row is recorded.
    pub(super) fresh_queue_ack: FreshQueueAck,
    /// Submitted user messages (excluding queued ones). Used for Up/Down
    /// shell-style history navigation in the composer.
    pub(super) prompt_history: Vec<String>,
    /// Index into `prompt_history` for history navigation. `0` means
    /// "at the live buffer" (no history offset); `1` = most recent, etc.
    pub(super) prompt_history_cursor: usize,
    /// In-progress composer text saved when the user first pressed
    /// Up to enter history mode. Restored when they walk back past
    /// the newest entry (cursor going `1 → 0`). `None` when not in
    /// history mode or when entry happened from an empty composer.
    pub(super) staged_draft: Option<String>,
    pub(super) history: Vec<HistoryEntry>,
    /// In-flight assistant turn (between `ThinkingStarted` and the
    /// matching `AssistantText`/tool boundary). When `Some`, the
    /// renderer appends a live entry to the bottom of the history
    /// pane.
    pub(super) pending: Option<PendingMsg>,
    /// Currently rendered transcript view. `Main` is the normal session transcript;
    /// `Subagent` means `history`/`pending` have been swapped to the selected child.
    pub(super) transcript_view: TranscriptViewMeta,
    /// Parent transcript views captured while drilling into subagents.
    pub(super) transcript_view_stack: Vec<StoredTranscriptView>,
    /// Reference point for the animated `Thinking…` dots. Set once at
    /// `App::new` time; the renderer derives the dot count from the
    /// elapsed time so the animation advances each tick.
    pub(super) started_at: Instant,
    /// True while the agent is actively working on the user's turn —
    /// from a fresh submit (rising edge) until the daemon's `AgentIdle`
    /// (falling edge). Unlike `pending.is_some()` this stays set across
    /// tool execution and inter-round gaps, so it's the signal the
    /// working indicator and the grey input border track.
    pub(super) busy: bool,
    /// Correlates the visible working span with daemon lifecycle events.
    /// A fresh submit is `PendingStart` until the matching
    /// `ThinkingStarted`; only a matching `AgentIdle` may complete a
    /// `Running` span. This keeps stale idle edges from producing a fake
    /// "finished" notification.
    pub(super) working_span_state: WorkingSpanState,
    /// Start of the cumulative "span" clock — set on a fresh submit,
    /// re-set on the next fresh submit, never touched by a queued
    /// message folded into an in-flight turn. Drives the working
    /// indicator's elapsed readout. `None` before the first submit.
    pub(super) span_started_at: Option<Instant>,
    /// Index into [`WORKING_MESSAGES`] held for the current span. Re-
    /// rolled on each fresh submit, avoiding the immediately previous
    /// pick. Initialized one-past-the-end so the first roll may land on
    /// any message (including index 0).
    pub(super) working_msg_idx: usize,
    /// Set while an inference call is mid network-retry (`Reconnecting`
    /// event); the status indicator shows a distinct, persistent
    /// `reconnecting — <provider>/<model> unreachable at <url> (attempt N)`
    /// line instead of the generic working spinner, and persists across the
    /// backoff wait *and* the in-flight retry attempt (only output flowing
    /// or the turn ending clears it). Cleared on the next
    /// `AssistantTextDelta` / `AgentIdle` / `InferenceFailed` (the call
    /// produced output, the turn ended, or it failed terminally) — NOT on a
    /// bare `ThinkingStarted`, which fires once at turn start before the
    /// retry loop and must not blank the reconnect status mid-loop.
    pub(super) reconnect: Option<ReconnectStatus>,
    /// Local TUI↔daemon socket reconnect status. Separate from inference
    /// provider reconnects so daemon restarts do not collide with model retry
    /// state.
    pub(super) daemon_link: Option<DaemonLinkStatus>,
    /// Live git status; updated by a background tokio task spawned in
    /// `run`. The event loop syncs this into `launch.repo_status` once
    /// per tick.
    pub(super) repo_status: Arc<Mutex<Option<RepoStatus>>>,
    pub(super) dialog: Dialog,
    /// User-opened modal/pane overlays. Required prompts (`daemon_prompt` and
    /// `question_dialog`) stay separate so they can shadow and resume this
    /// state without destroying the user's underlying overlay.
    pub(super) overlay: Overlay,
    /// "Daemon not running" prompt shown at startup. Once the user picks,
    /// this is taken and the prompt closes.
    pub(super) daemon_prompt: Option<crate::tui::daemon_prompt::DaemonPromptDialog>,
    /// Answering dialog for a `question`-tool interrupt (GOALS §3b).
    /// Opened from `TurnEvent::InterruptRaised`, replaces the composer,
    /// and on submit/cancel sends `ResolveInterrupt` back to the daemon.
    /// `None` when no question is pending.
    pub(super) question_dialog: Option<crate::tui::dialog::question::QuestionDialog>,
    /// True when the visible question dialog came from the `/btw` side runner
    /// and must resolve over that runner's attached daemon client.
    pub(super) question_dialog_btw: bool,
    /// A side-pane interrupt waiting behind the currently visible main dialog.
    pub(super) pending_btw_interrupt: Option<TurnEvent>,
    /// Whether the composer has genuinely been the user's active input
    /// surface since the last question dialog closed
    /// (implementation note). Set true by a render pass
    /// that found no `question_dialog`, and consumed (set false) when a
    /// dialog is installed. The anti-misfire lockout arms with the full
    /// configured delay only when this is true at install time
    /// (the genuine composer→dialog edge); a follow-up dialog installed
    /// while this is still false — including the same-cycle "dialog A
    /// resolved, dialog B installed before any composer render" handoff —
    /// opens immediately answerable (zero lockout). It is a render-driven
    /// signal precisely so the instantaneous `None→Some` flip on
    /// `question_dialog` during one resolve/poll cycle cannot masquerade as
    /// a fresh edge. Starts `true` (a cold dialog from the idle composer
    /// arms normally).
    pub(super) composer_active_since_dialog: bool,
    /// In-flight `/init` awaiting the user's update/overwrite/cancel
    /// choice. Set when the target file already exists; the question
    /// dialog open at that moment is this local prompt (not a daemon
    /// interrupt), so its close resolves here instead of going back to the
    /// daemon. `None` whenever no `/init` choice is pending.
    pub(super) pending_local_choice: Option<LocalChoice>,
    /// True after we've successfully connected to (or started) the daemon.
    pub(super) daemon_connected: bool,
    /// Daemonless mode (`DaemonChoice::ContinueWithout`): this TUI owns its
    /// own pid+nonce *ephemeral* daemon, fully isolated from the canonical
    /// persistent daemon and from any other TUI's ephemeral daemon. Set when
    /// the user picks "Continue without daemon" at the launch prompt; it
    /// flips the agent-runner lifecycle to `AlwaysEphemeral` so we spawn (and
    /// own) a fresh daemon rather than auto-promoting the canonical one.
    pub(super) daemonless: bool,
    /// RAII guard that reaps the owned ephemeral daemon on every exit path
    /// (clean quit, error, panic/unwind, SIGINT/SIGTERM) — the same
    /// ownership contract `cockpit run` uses. `Some` only in daemonless mode
    /// once the runner has spawned the owned daemon; `None` when attached to
    /// a daemon we don't own.
    pub(super) daemon_guard: Option<crate::daemon::ephemeral_guard::EphemeralDaemonGuard>,
    /// Signal task that fires the guard's shutdown on SIGINT/SIGTERM. Held so
    /// it can be aborted once the happy-path teardown has run.
    pub(super) daemon_signal_task: Option<tokio::task::JoinHandle<()>>,
    /// Lines emitted by an in-flight `/fetch-models` task. The event
    /// loop drains this each tick and appends to history.
    pub(super) fetch_models_progress: Arc<Mutex<Vec<String>>>,
    /// Lazily-initialized agent runner. None until the first user
    /// submit; populated by [`Self::ensure_agent_runner`]. Stored as
    /// `Result<AgentRunner, String>` so a failed init keeps the error
    /// around for next-time visibility.
    pub(super) agent_runner: Option<Result<AgentRunner, String>>,
    display_attach_backoff: DisplayAttachBackoff,
    /// Shared client-side runner for TUI background actions. Daemon RPCs and
    /// blocking filesystem/subprocess probes can complete through this tick
    /// drain instead of freezing the event loop.
    pub(super) async_actions: AsyncActionRunner,
    pub(super) completed_async_actions: Vec<AsyncActionResult>,
    startup_background: StartupBackground,
    /// Last-rendered chat area `Rect`. Used to translate absolute
    /// terminal mouse coordinates into chat-relative coordinates so
    /// click-to-expand works on thinking blocks.
    pub(super) chat_area: Option<Rect>,
    /// Last-rendered composer-input `Rect` (the outer rect — block
    /// border included). Used by `handle_mouse` to route clicks into
    /// click-to-position-cursor (plan.md T8.d).
    pub(super) input_area: Option<Rect>,
    /// Last-rendered suggestion/vim-hint box outer rect. Border rows are
    /// intentionally recorded so mouse wheel over the chrome is captured,
    /// while row hit records below limit click acceptance to content rows.
    pub(super) suggestion_box_area: Option<Rect>,
    /// Absolute row hit rectangles for rendered suggestion rows.
    pub(super) suggestion_row_hits: Vec<SuggestionBoxRowHit>,
    /// Suggestion row currently under the mouse, if capture is enabled.
    pub(super) hovered_suggestion: Option<SuggestionBoxTarget>,
    /// Logical-line scroll offset for the chat history pane. `0` =
    /// pinned to the bottom (live). Higher = scrolled further back in
    /// time. Bumped by mouse wheel when capture is on; clamped by
    /// `render_history` so we never scroll past the top.
    pub(super) chat_scroll_offset: usize,
    /// How tall (logical lines) the full chat content was at the last
    /// render. Updated each `render_history` and consulted by the
    /// mouse-wheel handler to clamp scroll-back to a valid maximum.
    pub(super) chat_total_lines: usize,
    /// How many logical lines fit in the chat pane at the last render.
    /// Same purpose — clamp scrollback so the bottom of the visible
    /// window can't go below the top of the content.
    pub(super) chat_visible_lines: usize,
    /// Plain-text copy of the full banner-inclusive visual line model
    /// from the last render. Indices match `chat_total_lines` absolute
    /// lines and are searched by transcript find.
    pub(super) chat_find_lines: Vec<String>,
    pub(super) transcript_find: Option<TranscriptFind>,
    /// In-app drag-select state for chat content (plan.md T8.f). Set
    /// when the user mouse-downs in the chat area; updated on drag;
    /// committed on release. `Ctrl+Shift+C` copies the underlying
    /// plaintext via `clipboard::copy_plain` (OSC52 → SSH-safe).
    pub(super) selection: Option<Selection>,
    /// Snapshot of the chat area's rendered cells, one row per outer
    /// element, one cell per inner element. Each cell's `String` is
    /// the cell's `symbol()` — typically one char, but multi-byte for
    /// non-ASCII and an empty marker for the continuation cell of a
    /// wide glyph. Populated by `render_history` after the paragraph
    /// widget writes to the buffer. Used by the copy path so we don't
    /// have to redo ratatui's wrap math to extract the selected
    /// plaintext.
    pub(super) chat_text_grid: Vec<Vec<String>>,
    /// Parallel to `chat_text_grid`: `chat_cont_rows[i]` is `true`
    /// when visible row `i` is a soft-wrap continuation of the
    /// previous logical line. The copy path joins continuations with
    /// a space, real line boundaries with a newline — so pasted
    /// agent text reconstructs the original paragraphs rather than
    /// preserving the screen-level wraps.
    pub(super) chat_cont_rows: Vec<bool>,
    /// Authoritative per-visible-row ownership and hit metadata for the
    /// last rendered chat area. Compatibility row maps below are derived
    /// from this vector after each render.
    pub(super) chat_row_meta: Vec<render::ChatRowMeta>,
    /// Click hit map: for each *visible* row in `chat_area`, the index
    /// (within `self.history`) of the agent entry whose thinking chip
    /// lives there — or `None` for non-clickable rows. Refreshed every
    /// render.
    pub(super) clickable_rows: Vec<Option<usize>>,
    /// Click/wheel hit map: for each *visible* chat row, the index
    /// (within `self.history`) of the `ToolBox` rendered there, or
    /// `None`. A wheel over a collapsed box scrolls the box; a click on
    /// any box row toggles its expansion. Refreshed every render.
    pub(super) box_rows: Vec<Option<usize>>,
    pub(super) hovered_affordance: Option<AffordanceTarget>,
    pub(super) hovered_control_chip: Option<render::ControlChip>,
    pub(super) affordance_scroll_regions: Vec<AffordanceScrollRegion>,
    /// Hit map for rendered diff rows. Header/body rows for a diff entry
    /// carry the edited path so right-click can offer editor actions only
    /// on real diff content.
    pub(super) diff_rows: Vec<Option<String>>,
    /// Last cursor-shape we asked the terminal to use. Tracked so we
    /// only re-issue the escape when the desired shape changes (most
    /// terminals tolerate redundant `SetCursorStyle` writes but a few
    /// blink visibly).
    pub(super) last_cursor_shape: Option<CursorShape>,
    /// Highlighted index in the `@`-popup. Reset to 0 whenever the
    /// composer's at-query changes; bumped by Up/Down while the popup
    /// is open.
    pub(super) at_selected: usize,
    /// Top visible index of the `@`-popup scroll window. Maintained with
    /// a 1-row scrolloff so the next/prev candidate is always visible
    /// except at the true ends of the list (see [`crate::tui::nav::windowed_scroll`]).
    pub(super) at_scroll: usize,
    /// Per-query memo of the suggestion walk so the filesystem isn't
    /// re-walked on every render / arrow keypress. Keyed by the exact
    /// `@`-query string; recomputed when the query changes. `RefCell`
    /// because `at_suggestions` is called from `&self` render paths.
    pub(super) at_cache:
        std::cell::RefCell<Option<(String, Vec<crate::tui::file_tag::Suggestion>)>>,
    /// Accepted `@`-tag paths that contain a space / shell-special char.
    /// Tracked so the submit-time pass can wrap them in quotes (the
    /// composer shows them unquoted; the wire payload needs the quotes
    /// to disambiguate the path boundary). Content-matched at submit, so
    /// editing elsewhere in the buffer can't desync it; cleared on
    /// submit and on `/new`.
    pub(super) accepted_tags: Vec<String>,
    /// Registry of condensed-text / image paste blocks currently in the
    /// composer buffer (composer-paste-handling). Kept byte-range-synced
    /// with [`Self::composer`] across every edit; consumed at submit to
    /// inline text + emit real image parts (vision) or text notes
    /// (non-vision). Cleared on submit and `/new`.
    pub(super) paste_registry: crate::tui::paste::PasteRegistry,
    /// Pending vim text-object selector: `Some(true)` after `a` (around),
    /// `Some(false)` after `i` (inner), in operator-pending / visual
    /// contexts; the next char picks the object (`w`, `"`, `(`, …). `None`
    /// otherwise. Lives on App (not the composer) because resolving the
    /// object can interact with the paste registry.
    pub(super) pending_text_object: Option<bool>,
    /// True once the user dismissed the `@`-popup with `Esc`. Stays
    /// suppressed until the active `@partial` token is dropped (e.g.
    /// whitespace appears after `@` or the `@` is deleted).
    pub(super) at_dismissed: bool,
    /// Highlighted index in the slash-command popup. Reset to 0 (the
    /// frequency-ranked top match) whenever the slash query changes;
    /// moved by Up/Down while the popup is open. While the popup shows,
    /// Up/Down drive this cursor instead of composer history recall.
    pub(super) slash_selected: usize,
    /// Top visible index of the slash popup's scroll window, maintained
    /// with the same 1-row scrolloff as the `@`-popup (see
    /// [`crate::tui::nav::windowed_scroll`]). Reset alongside `slash_selected`.
    pub(super) slash_scroll: usize,
    /// Cached availability and expensive descriptions for the current
    /// slash-menu-open interaction. Rebuilt when the menu opens; cleared when
    /// the composer no longer contains a slash query.
    pub(super) slash_menu_cache: std::cell::RefCell<Option<SlashMenuCache>>,
    /// The originally-typed slash stem that Tab-completion is cycling
    /// against (`slash-command-tab-completion.md`). `Tab` completes the
    /// composer to the highlighted command's full name — which would
    /// otherwise collapse the prefix-matched candidate set to that one
    /// name. Anchoring the menu's match set on the pre-completion stem
    /// keeps the full set visible so a second `Tab` cycles forward
    /// through it the same way ↑/↓ moves the highlight. `None` when not
    /// mid-cycle; cleared by any non-Tab composer edit via
    /// [`App::reset_slash_window`].
    pub(super) slash_cycle_stem: Option<String>,
    /// `/new` was invoked; the event loop services it on the next tick
    /// (needs the terminal handle for `insert_before` so the existing
    /// history spills to scrollback before the welcome header is
    /// reprinted above the viewport).
    pub(super) pending_new_session: bool,
    /// Provider-reported usage from the most recent round-trip. Anchors
    /// the live context counter (see `context_tokens`): the displayed
    /// value is this total plus a local estimate of everything streamed
    /// since it arrived. `None` until the first call returns.
    pub(super) last_usage: Option<crate::tokens::TokenUsage>,
    /// Local cl100k_base estimate captured the instant `last_usage` was
    /// set — the baseline the live counter measures streamed tokens
    /// against, so the number climbs per token and re-snaps to the
    /// provider's exact count on the next report.
    pub(super) estimate_at_last_usage: u32,
    /// Memoized `(length-signature, token count)` for the finalized
    /// history portion of the context estimate. History is static while
    /// a turn streams, so the per-frame live counter only re-tokenizes
    /// the growing `pending` buffer instead of the whole transcript.
    /// `Cell` because the estimate runs from `&self` render paths.
    pub(super) history_estimate_cache: Cell<Option<(u64, u32)>>,
    /// Memoized token count for the in-flight assistant buffer. The
    /// streaming buffer is append-only within a turn, so lengths are the
    /// cheap invalidation key for the render-path estimate.
    pub(super) pending_token_cache: Cell<Option<((usize, usize), u32)>>,
    /// Per-history-entry render versions. Versions are bumped when a cheap
    /// shape fingerprint changes, letting render-cache validation compare a
    /// small integer instead of hashing full transcript text every frame.
    pub(super) history_render_versions: Vec<u64>,
    pub(super) history_render_fingerprints: Vec<u64>,
    pub(super) next_history_render_version: u64,
    /// Per-history-index render cache for stable transcript entries. The
    /// signature includes the entry content plus render-affecting settings and
    /// chrome state; stale indices are evicted at the end of `render_history`.
    pub(super) history_render_cache: HashMap<usize, HistoryRenderCacheEntry>,
    /// Cached render output for the live pending assistant message. The
    /// signature is based on pending text/reasoning/width, so unrelated frame
    /// ticks do not reparse the same markdown buffer.
    pub(super) pending_render_cache: Option<PendingRenderCacheEntry>,
    /// 30-day autocomplete frequency counts, used as a tie-breaker in
    /// the slash / model / @-tag surfaces. Seeded from the daemon at
    /// attach and incremented optimistically on each local pick. `tags`
    /// is scoped to the attached project. Empty until the first attach
    /// (sorts fall back to their existing alphabetical/declaration
    /// order until then).
    pub(super) usage_models: HashMap<String, u64>,
    pub(super) usage_slash: HashMap<String, u64>,
    pub(super) usage_tags: HashMap<String, u64>,
    /// Discovered skills surfaced as bare-`/<name>` slash-menu entries
    /// (implementation note). Built once at startup from
    /// the layered skills config; names colliding with a builtin are omitted
    /// (the builtin wins) but stay reachable via the `/skill <name>`
    /// dispatcher. The dispatcher re-discovers per call (so it sees colliding
    /// + freshly-added skills regardless of this cache).
    pub(super) skill_commands: Vec<SkillCommand>,
    /// The attached session's project id — the scope for `tag` records.
    /// `None` until the first attach.
    pub(super) project_id: Option<String>,
    /// Whether the *currently bound* session has been persisted to the DB
    /// (session-id-display-and-lazy-persist). The daemon writes the
    /// `sessions` row on the first user message, so this flips `true` the
    /// instant a submission is accepted by the runner, and resets to `false`
    /// whenever the runner is rebound (`/new`, `/resume`, `/compact`) since
    /// those open or switch to a different session. Read on exit to decide
    /// whether to print the session id; a resumed session is persisted from
    /// the start, so its rebind sets this `true`.
    pub(super) current_session_persisted: bool,
    /// Fresh-chat sizing for this project, resolved at launch: the
    /// guidance-file basename + body tokens (the `X tokens in <file>`
    /// label) and the full composed system prompt tokens (the baseline
    /// the running context estimate folds in). Calibrated when a daemon
    /// is running, raw cl100k otherwise. `None` only before the launch
    /// fetch has run.
    pub(super) guidance_estimate: Option<agent_runner::GuidanceEstimate>,
    /// Wire tokens `/prune` would drop from the foreground agent right
    /// now (GOALS §1a). Pushed by the daemon's `ContextProjection` event
    /// — the authoritative figure from the same `dedup_plan` `/prune`
    /// executes, so the status-line `→ Y% prunable` always matches what
    /// `/prune` removes. `0` until the first projection arrives.
    pub(super) prunable_tokens: u64,
    /// Whether the provider cache is expected cold on the next call (from
    /// the daemon's cache-cold predicate). Drives the `/prune` confirm's
    /// hot-vs-cold warning. Defaults true (no warm cache to lose).
    pub(super) cache_cold: bool,
    /// The active LLM-strength mode (implementation note).
    /// Resolved from the layered config at launch and tracked live off the
    /// daemon's `LlmModeChanged` event so the `/llm-mode` toggle + cache-break
    /// warning resolve against the authoritative current value.
    pub(super) llm_mode: crate::config::extended::LlmMode,
    /// Root primary plus active interactive subagent path for footer chrome.
    pub(super) agent_path: Vec<String>,
    /// Footer control selected by mouse; arrow/enter keys operate on it until
    /// Esc or ordinary typing clears it.
    pub(super) footer_selection: Option<crate::tui::chrome::FooterControl>,
    /// Absolute hit rectangles recorded by the last status render.
    pub(super) footer_hit_areas: Vec<FooterHitArea>,
    /// Agent picker opened from the footer agent segment.
    pub(super) footer_agent_picker: Option<FooterAgentPicker>,
    /// Mode picker opened from the footer mode segment.
    pub(super) footer_mode_picker: Option<FooterModePicker>,
    /// Absolute row hit rectangles recorded by the last footer picker render.
    pub(super) footer_picker_row_hits: Vec<FooterPickerRowHit>,
    /// Mutable confirmation row for rapid agent switching before the next turn.
    pub(super) pending_agent_switch_log: Option<PendingAgentSwitchLog>,
    /// The live set of wire-side elided tool-result `call_id`s on the
    /// foreground agent (from the daemon's `Pruned` event). The scrollback
    /// renderer dims any boxed tool call whose `call_id` is in here —
    /// full text stays visible (GOALS §14). A render-time view of live
    /// prune state, replaced wholesale on each `Pruned`, not a persisted
    /// flag. Cleared on a fresh thread (`/compact` commit, `/clear`).
    pub(super) elided_event_ids: std::collections::HashSet<String>,
    /// A `/compact` handoff awaiting review-then-commit (T6.e). `Some`
    /// while the assembled handoff sits in the composer for editing.
    pub(super) pending_compact: Option<PendingCompact>,
    /// `/prune` confirm armed: the user ran `/prune`, saw the before→after
    /// numbers + cache warning, and the next `y`/Enter commits (anything
    /// else cancels). `Some` holds nothing meaningful — its presence is
    /// the armed flag; the numbers were already pushed to history.
    pub(super) pending_prune_confirm: bool,
    /// Bare `/stop` confirm armed: the user ran `/stop` with no id, saw
    /// the `Stop N job(s) in this session? [y/N]` prompt, and the next
    /// `y` commits (anything else cancels). Carries the current-session
    /// job ids captured at arm time so the cancel set can't drift between
    /// the prompt and the confirmation.
    pub(super) pending_stop_confirm: Option<Vec<String>>,
    /// `RecordUsage` requests made before the daemon runner exists.
    /// Flushed (with tag project ids backfilled) once it's created.
    pub(super) pending_usage: Vec<crate::daemon::proto::Request>,
    /// Ctrl+G was pressed — the event loop suspends ratatui, runs
    /// `$EDITOR` against the composer text, then reloads the file back
    /// into the composer.
    pub(super) pending_external_edit: bool,
    /// Whether crossterm mouse capture is currently enabled. Tracks the
    /// real terminal state so the settings toggle can push/pop the
    /// escape sequence without double-enabling. Sourced from
    /// `tui.mouse_capture` at startup; mutated when the user toggles
    /// the setting mid-session.
    pub(super) mouse_capture: bool,
    pub(super) hyperlinks: bool,
    pub(super) link_registry: crate::tui::links::LinkRegistry,
    /// User's `tui.exit_tail_lines` setting (GOALS §1d). Cached at
    /// startup so the exit-tail dump survives the dialog being closed.
    pub(super) exit_tail_lines: i32,
    /// User's `tui.rich_text_copy` setting. Gates the `Ctrl+Shift+Y`
    /// keybind that copies the last agent message as HTML to the
    /// system clipboard (plan.md T8.g).
    pub(super) rich_text_copy: bool,
    /// True once the per-session tmux OSC52 discoverability hint has
    /// been shown; suppresses repeats for the rest of the session
    /// (resets on restart, never persisted).
    pub(super) tmux_copy_hint_shown: bool,
    /// Active right-click context menu in the chat area. Modal while
    /// `Some` — intercepts every key + mouse event.
    pub(super) context_menu: Option<crate::tui::context_menu::ContextMenu>,
    /// Transient FYI message overlaid on the status line
    /// (TUI-design-philosophy §7). 3-second TTL; dismissed early by
    /// any user interaction (keystroke or mouse click/wheel).
    pub(super) toast: Option<Toast>,
    pub(super) idle_reason_status: Option<IdleReasonStatus>,
    /// Live embedded `$EDITOR` / `lazygit` pane (GOALS §1i/§1j). One at
    /// a time; `None` when no pane is open. Auto-closes when the child
    /// exits, serviced once per event-loop tick.
    pub(super) pane: Option<crate::tui::pty::PtyPane>,
    /// Live `/btw` side conversation pane. Unlike legacy `/side`, this does
    /// not replace the main session view; it owns its own daemon runner,
    /// composer, queue mirror, history, and pending assistant turn.
    pub(super) btw_pane: Option<BtwPane>,
    /// Where the open pane sits in the chat-body region.
    pub(super) pane_side: PaneSide,
    /// Pane's share of the body in a split (0.0–1.0), persisted for the
    /// session. Ignored when `pane_side` is `Full`.
    pub(super) pane_ratio: f32,
    /// True when keyboard/mouse route to the pane; false when they go to
    /// the composer. Toggled by `Ctrl+O` and by clicking a pane.
    pub(super) pane_focused: bool,
    /// Last-rendered pane content rect (absolute coords). Used for mouse
    /// hit-testing, PTY resize, and parking the real cursor.
    pub(super) pane_rect: Option<Rect>,
    /// Last-rendered split-divider rect, and whether it's a vertical
    /// rule (left/right split) vs. a horizontal one (top/bottom). Used
    /// to start a divider drag-resize. `None` in fullscreen.
    pub(super) divider: Option<(Rect, bool)>,
    /// Last-rendered body rect the split was computed from. Lets the
    /// mouse handler convert a divider drag into a new ratio without a
    /// frame.
    pub(super) pane_body: Option<Rect>,
    /// True while a left-drag that began on the divider is resizing the
    /// split.
    pub(super) dragging_divider: bool,
    /// Buffered `<git cmd="…">…</git>` blocks from `/git` (GOALS §1l),
    /// attached to the next user message's wire text and cleared on
    /// send (and on `/new`).
    pub(super) pending_git_blocks: Vec<String>,
    /// Live scheduled tasks (GOALS §22), keyed by task id. Drives the transient
    /// schedule strip (rendered only when non-empty) and `/schedule`. Maintained
    /// from `ScheduleStarted` / `ScheduleNote` / `ScheduleProgress` / `ScheduleCompleted`
    /// events.
    pub(super) active_schedules: std::collections::BTreeMap<String, ActiveSchedule>,
    /// Monotonic timestamp of the most recent ctrl+c press, while the
    /// double-press exit window is armed. A single ctrl+c interrupts a
    /// running agent (never quits); a second press within
    /// [`CTRL_C_EXIT_WINDOW`] of the previous one exits the TUI. `None`
    /// when the window has lapsed (the next press is a fresh first press).
    /// Uses `Instant` (monotonic) so a wall-clock jump can't mis-trigger.
    pub(super) ctrl_c_armed_at: Option<Instant>,
    /// The client's `--no-sandbox` flag (sandboxing part 2). Passed to
    /// the daemon at attach so sessions this TUI creates start with
    /// filesystem sandboxing OFF (unless the daemon itself was launched
    /// `--no-sandbox`, which wins). A `/sandbox` flip still overrides.
    pub(super) no_sandbox: bool,
    pub(super) sandbox_mode: crate::tools::sandbox_mode::SandboxMode,
    pub(super) container_network_enabled: bool,
    pub(super) container_availability: crate::container::ContainerAvailability,
    /// Daemon-broadcast caffeination state (`/caffeinate`). Drives the `☕`
    /// chrome glyph; set/cleared from the daemon-global `CaffeinateState`
    /// event so it stays in sync across all clients (incl. until-idle
    /// auto-off). Not client-owned: the assertion lives in the daemon.
    pub(super) caffeinate_active: bool,
    /// User attention-notification settings (implementation note):
    /// in-TUI toast (default on), terminal title (default on), terminal bell,
    /// desktop notification.
    pub(super) attention: crate::tui::attention::AttentionConfig,
    /// Debounce bookkeeping for the attention subsystem so a burst of
    /// identical events (tool errors, plan updates) rings the bell / pops a
    /// desktop notification at most once per window.
    pub(super) attention_state: crate::tui::attention::AttentionState,
    /// Pending action-required interrupt tracked for persistent toast,
    /// terminal-title marker, and periodic re-nudge.
    attention_interrupt: Option<AttentionInterruptState>,
    /// Action-required interrupts from sessions other than the attached
    /// foreground session. They never open a dialog in this TUI, but still
    /// drive persistent toast, title marker, and periodic re-nudge.
    background_attention_interrupts:
        std::collections::BTreeMap<uuid::Uuid, AttentionInterruptState>,
    /// Terminal-title marker push/pop state.
    terminal_title: TerminalTitleState,
    /// When the user last pressed a meaningful key. Used as a conservative
    /// "is the user actively here?" proxy (terminals can't report focus
    /// reliably) so a turn the user watched finish stays subtle.
    pub(super) last_user_interaction: Instant,
    /// Transient "waiting for lock" chrome indicator
    /// (`readlock-wait-and-lock-expiry.md`). `Some((path, holder))` while a
    /// `readlock` in this session is blocked on a lock another agent/session
    /// holds; cleared when the wait ends (lock acquired or cancelled). Driven
    /// by the daemon's per-session `WaitingForLock` start/clear broadcast and
    /// rendered alongside the fixed chrome, like the `☕` glyph — never
    /// displacing a fixed slot. Never enters history or any inference request.
    pub(super) waiting_for_lock: Option<(String, String)>,
    /// Persistent sandbox-down remedy notice (`implementation notes` §6.5).
    /// `Some(remedy)` while the shell sandbox can't initialize: rendered as a
    /// persistent (non-timing-out) red below-input notice telling the user to
    /// run `/sandbox off` plus the `sudo sysctl …=0` command when diagnosed.
    /// Set from the daemon's `SandboxUnavailable` broadcast; cleared on the
    /// `SandboxState { enabled: false }` a `/sandbox off` triggers. Never
    /// enters history or any inference request — purely client-side chrome.
    pub(super) sandbox_down_notice: Option<SandboxDownNotice>,
    pub(super) sandbox_notice_copy_rect: Option<Rect>,
    /// Process-local, event-earned per-model auth failures. These deliberately
    /// have no persistence path and start empty for every TUI process.
    pub(super) auth_failure_annotations: crate::tui::auth_failure::AuthFailureAnnotations,
    pub(super) auth_failure_notice: Option<crate::tui::auth_failure::AuthFailureNotice>,
    auth_failure_fingerprints: std::collections::HashMap<String, u64>,
    pub(super) auth_notice_switch_rect: Option<Rect>,
    pub(super) auth_notice_fix_rect: Option<Rect>,
    /// Session-only redaction-source state (`/toggle-redaction`). Seeded
    /// from the layered `redact` config at launch and kept in sync by the
    /// daemon's `RedactionState` broadcast. Tracked client-side so a bare
    /// `/toggle-redaction` can pre-check the multiselect and an
    /// `env`/`file`/`ssh` arg can flip the right source. Never persisted —
    /// the daemon's effective `RedactConfig` is also session-only.
    pub(super) redact_scan_environment: bool,
    pub(super) redact_scan_dotenv: bool,
    pub(super) redact_scan_ssh_keys: bool,
    /// Session-only request-preflight effective state (`/preflight`,
    /// implementation note). Seeded from the layered
    /// `preflight.enabled` config at launch and kept in sync by the daemon's
    /// `PreflightState` broadcast. Mirrored client-side so the `/preflight`
    /// slash-command description renders the live on/off state and a bare
    /// `/preflight` can toggle the right way. Never persisted — the driver's
    /// effective override is also session-only.
    pub(super) preflight_enabled: bool,
    /// Live trusted-only inference state (`/trusted-only`). Seeded from
    /// `trustedOnly` config at launch and kept in sync by daemon broadcasts.
    pub(super) trusted_only_enabled: bool,
    /// Live sandbox-escalation availability for this session. Seeded from
    /// config and kept in sync by daemon broadcasts.
    pub(super) sandbox_escalation_enabled: bool,
    /// Live command-approval mode for this session (`/quick`). Seeded from the
    /// config default and kept in sync by daemon broadcasts.
    pub(super) approval_mode: crate::config::extended::ApprovalMode,
    /// Live delegation recursion setting for this session (`/quick`). Seeded
    /// from config defaults and kept in sync by daemon broadcasts.
    pub(super) delegation_recursion_enabled: bool,
    pub(super) delegation_recursion_depth: u32,
    /// Session-only gitignore read-allowlist globs approved "for this session"
    /// (implementation note). Pushed by the daemon
    /// (per-session `GitignoreAllow` broadcast — on change and on attach) and
    /// overwritten wholesale (full-list replace). Unioned with the persisted
    /// per-layer config in `at_suggestions` so the `@`-tag popup re-includes
    /// session-approved gitignored entries. In-memory — resets on TUI restart;
    /// never persisted.
    pub(super) gitignore_session_allow: Vec<String>,
    /// Session-only model-comparison tandem (shadow) set
    /// (`/model-comparison`, implementation note) —
    /// the `provider/model` labels currently selected. Pushed by the daemon
    /// (`TandemState` broadcast — on change) and overwritten wholesale.
    /// Pre-checks the `/model-comparison` multiselect. In-memory; resets on TUI
    /// restart (empty = feature off).
    pub(super) tandem_models: Vec<String>,
    /// Row-index → `(provider, model)` mapping for the open `/model-comparison`
    /// multiselect, so the close handler resolves checked row ids back to pairs
    /// (model ids can contain `/`, so the label isn't a safe key). Taken on
    /// resolve.
    pub(super) pending_tandem_options: Vec<(String, String)>,
    /// Persistent enterprise org-policy session-log sync disclosure. Loaded
    /// from durable sync state at startup; absence means no active policy.
    pub(super) org_sync_disclosure: Option<crate::db::org_sync::OrgSyncDisclosure>,
    /// Persisted/daemon-broadcast remote connector status. Drives the additive
    /// remote-access chrome slot while connector access is enabled.
    pub(super) connector_disclosure: Option<crate::db::connector::ConnectorDisclosure>,
    has_no_providers_at_startup: bool,
    /// An open `/side` side conversation, or `None` in the main session. While
    /// `Some`, the TUI is bound to an ephemeral throwaway fork: the chrome
    /// shows the side indicator with `/side end` guidance, and the fork is
    /// discarded on explicit `/side end` or process death (see the run teardown
    /// and the daemon boot sweep).
    pub(super) side_conversation: Option<SideConversation>,
    /// Daemon is draining for a graceful shutdown
    /// (`daemon-graceful-drain-shutdown.md`). Set from the daemon-global
    /// `DaemonDraining` event. While set, the composer refuses new
    /// submissions with a short notice — new work is rejected, not queued.
    pub(super) daemon_draining: bool,
    /// Composer next-message prediction setting
    /// (implementation note). `off` short-circuits before
    /// any utility call; `short`/`long` bound the prediction.
    pub(super) predict_setting: crate::config::extended::PredictNextMessage,
    /// The next-message prediction lifecycle state (turn counter, cache,
    /// live ghost). Pure + unit-testable; see [`PredictionState`].
    pub(super) prediction_state: PredictionState,
    /// Async prediction-result slot. The spawned utility-model task writes
    /// `(turn, Option<bounded-text>)`; the event loop drains it each tick
    /// and adopts the text only when `turn` still matches the current turn
    /// and the box is empty (appear-once-ready, discard-if-stale).
    pub(super) prediction_result: PredictionResultSlot,
    /// Active `/pin` pick-a-message mode (`pinned-messages`). While `Some`,
    /// the composer is unfocused and an arrow on the left of the transcript
    /// marks the selected message; ↑/↓/j/k move it, enter pins, esc exits.
    pub(super) pin_pick: Option<crate::tui::pins_overlay::PinPick>,
    /// Active `/fork` pick-a-message mode. Navigation mirrors `/pin`, but
    /// enter creates a fork at the selected recorded message.
    pub(super) fork_pick: Option<crate::tui::pins_overlay::ForkPick>,
    /// Active `/copy-pick` keyboard message copy mode. While `Some`, the
    /// same left-margin arrow marks the selected message; Tab cycles the
    /// whole-message/code-block target before opening a copy-format menu.
    pub(super) copy_pick: Option<crate::tui::pins_overlay::CopyPick>,
    /// Active `/pins` review mode (`pinned-messages`). While `Some`, a
    /// checklist of pinned messages is shown; ↑/↓/j/k jump the transcript
    /// to each pin, `d`/space (check) unpin, esc closes.
    pub(super) pins_review: Option<crate::tui::pins_overlay::PinsReview>,
    /// Count of pinned messages in this session (`pinned-messages`). Drives
    /// the below-input indicator (hidden at zero). Refreshed from the DB on
    /// every pin/unpin and on attach.
    pub(super) pin_count: usize,
    /// Click hit map: for each *visible* chat row, the clickable pin-control
    /// region (seq + `[col_start, col_end)` columns) of a pinnable
    /// User/Agent message whose mouse `[pin]`/`[unpin]` control sits on that
    /// row, or `None`. The control rides the message's own first line / top
    /// border, so a click only toggles when it lands inside the column range.
    /// Refreshed every render; consumed by the mouse handler.
    pub(super) pin_control_rows: Vec<Option<render::PinHit>>,
    /// Content line (within the message buffer `all`, i.e. excluding the
    /// banner-box prefix) of each pinnable message's first row, keyed by
    /// history index. Combined with `chat_banner_lines` this gives the line
    /// in the full scrollback, letting review-mode scroll a pin into view.
    /// Refreshed every render.
    pub(super) msg_abs_line: std::collections::HashMap<usize, usize>,
    /// Banner-box line count prefixed to the scroll buffer at the last
    /// render (`pinned-messages` scroll math). `0` when the banner has
    /// scrolled off or isn't shown.
    pub(super) chat_banner_lines: usize,
    /// The session id `pin_count` was last refreshed for. When the active
    /// session changes (eager attach, `/new`, `/compact`, resume) the
    /// count is re-read so the below-input indicator tracks the right
    /// session. `None` until the first refresh.
    pub(super) pin_count_session: Option<uuid::Uuid>,
    /// Cached pinned message seqs for the active session. Render reads this
    /// only; DB refreshes happen on session sync and pin mutations.
    pub(super) pinned_seqs_cache: HashSet<i64>,
    pub(super) pinned_seqs_session: Option<uuid::Uuid>,
    /// Active which-key overlay (`crate::tui::keys_overlay`, `which-key-overlay.md`).
    /// `Some` while the context-aware keybinding panel is open. Opened by the
    /// leader key (`Ctrl+K`) or `/keys`; informational + TUI-only — it never
    /// sends anything to the agent and never enters history or any inference
    /// request. Renders LAST over the chat body (never over a required-decision
    /// dialog) and consumes its own keys while open.
    pub(super) keys_overlay: Option<crate::tui::keys_overlay::KeysOverlay>,
    pub(super) keyboard_enhancement_active: bool,
}

/// Shared slot a spawned prediction task posts its `(turn, bounded-text)`
/// result back through; drained by the event loop each tick.
pub(super) type PredictionResultSlot = Arc<Mutex<Option<(u64, Option<String>)>>>;

/// A completed composer next-message prediction
/// (implementation note), cached so a clear-to-empty within
/// the same turn restores the ghost without a new utility call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Prediction {
    /// Agent turn the prediction was generated for.
    pub(super) turn: u64,
    /// Bounded prediction text (mode-capped by `engine::predict`).
    pub(super) text: String,
    /// `true` when the active setting is `long` (enables the two-stage
    /// reveal for multi-line predictions).
    pub(super) long_mode: bool,
}

/// The next-message prediction lifecycle (implementation note),
/// kept pure so the eager-generate / hide-on-type / restore-on-clear /
/// stale-replacement behavior is unit-testable without an `App`.
///
/// `turn` is a monotonic agent-turn counter (bumped at each `AgentIdle` and
/// on `/new`); a prediction belongs to the turn it was generated for, so a
/// result tagged with an older turn is discarded rather than shown. `cached`
/// is the bounded prediction for the current turn (the restore-on-clear
/// cache); `ghost` is the live two-stage reveal state, present only while
/// the box is empty.
#[derive(Debug, Default)]
pub(super) struct PredictionState {
    /// Monotonic agent-turn counter.
    turn: u64,
    /// Cached prediction for the current turn (`None` until one lands).
    cached: Option<Prediction>,
    /// Live ghost shown while the box is empty.
    ghost: Option<crate::tui::composer::PredictionGhost>,
}

impl PredictionState {
    /// The current agent-turn id (the tag a freshly-spawned prediction
    /// carries).
    pub(super) fn turn(&self) -> u64 {
        self.turn
    }

    /// The live ghost, if any (read by the renderer + key handler).
    pub(super) fn ghost(&self) -> Option<&crate::tui::composer::PredictionGhost> {
        self.ghost.as_ref()
    }

    /// Mutable access to the live ghost (the Tab-accept path advances its
    /// stage).
    pub(super) fn ghost_mut(&mut self) -> Option<&mut crate::tui::composer::PredictionGhost> {
        self.ghost.as_mut()
    }

    /// A new agent turn ended (or `/new`): bump the turn id (invalidating
    /// any in-flight or cached prior-turn prediction) and drop the cache +
    /// ghost so a stale prediction never shows.
    pub(super) fn begin_turn(&mut self) {
        self.turn = self.turn.wrapping_add(1);
        self.cached = None;
        self.ghost = None;
    }

    /// Adopt a completed async result tagged with `result_turn`. Discards a
    /// stale result (older turn) or a `None` text. Caches a usable result
    /// and — only when `box_empty` (appear-once-ready, never over active
    /// input) — builds the ghost. `long_mode` enables the two-stage reveal.
    pub(super) fn on_result(
        &mut self,
        result_turn: u64,
        text: Option<String>,
        long_mode: bool,
        box_empty: bool,
    ) {
        if result_turn != self.turn {
            return; // stale: a newer turn started
        }
        let Some(text) = text else {
            return;
        };
        self.cached = Some(Prediction {
            turn: result_turn,
            text: text.clone(),
            long_mode,
        });
        if box_empty {
            self.ghost = Some(crate::tui::composer::PredictionGhost::new(text, long_mode));
        }
    }

    /// Reconcile the ghost with the composer's empty/non-empty state. A
    /// non-empty box hides the ghost (user typing wins); a box cleared back
    /// to empty restores the cached prediction's ghost for the current turn
    /// — **without** a new utility call (the cache is reused).
    pub(super) fn reconcile(&mut self, box_empty: bool) {
        if !box_empty {
            self.ghost = None;
            return;
        }
        if self.ghost.is_none()
            && let Some(p) = &self.cached
            && p.turn == self.turn
        {
            self.ghost = Some(crate::tui::composer::PredictionGhost::new(
                p.text.clone(),
                p.long_mode,
            ));
        }
    }

    /// The Tab-accept terminal step: the ghost converted to real text, so
    /// consume the ghost AND the cache (the prediction has been acted on
    /// and must not be re-offered on a later clear-to-empty).
    pub(super) fn consume(&mut self) {
        self.ghost = None;
        self.cached = None;
    }

    /// Force the feature off (setting changed to `off`): drop cache + ghost.
    pub(super) fn clear(&mut self) {
        self.cached = None;
        self.ghost = None;
    }
}

/// A live scheduled task tracked by the TUI for the schedule strip / `/schedule`.
#[derive(Debug, Clone)]
pub(super) struct ActiveSchedule {
    /// Session that owns the task. `/schedule` shows every session's tasks;
    /// `/ps` / `/stop` filter to the current session by this id.
    pub(super) session_id: uuid::Uuid,
    pub(super) label: String,
    /// `loop` / `timer` / `background`.
    pub(super) kind: String,
    /// Iterations observed so far (loops; bumped per note).
    pub(super) iteration: u64,
    /// Last time the job showed activity — drives an idle/elapsed readout.
    pub(super) last_activity: Instant,
}

/// Toast intent — drives the message's foreground color.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ToastKind {
    Success,
    Warning,
    Error,
    Info,
}

#[derive(Debug, Clone)]
struct Toast {
    text: String,
    kind: ToastKind,
    expires_at: Instant,
    persistent: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct IdleReasonStatus {
    text: String,
    kind: ToastKind,
}

fn idle_reason_status(reason: crate::engine::IdleReason) -> Option<IdleReasonStatus> {
    match reason {
        crate::engine::IdleReason::Completed => None,
        crate::engine::IdleReason::GoalComplete => Some(IdleReasonStatus {
            text: "goal session completed".to_string(),
            kind: ToastKind::Success,
        }),
        crate::engine::IdleReason::NeedsIntervention { code } => Some(IdleReasonStatus {
            text: format!("goal stalled ({code}) — run `/goal resume` or send guidance"),
            kind: ToastKind::Warning,
        }),
        crate::engine::IdleReason::BudgetLimited => Some(IdleReasonStatus {
            text: "goal paused: token budget reached — run `/goal resume` or adjust budget"
                .to_string(),
            kind: ToastKind::Warning,
        }),
        crate::engine::IdleReason::UsageLimited => Some(IdleReasonStatus {
            text: "usage limit — auto-resuming shortly".to_string(),
            kind: ToastKind::Warning,
        }),
        crate::engine::IdleReason::Error { class } => Some(IdleReasonStatus {
            text: format!("turn stopped on {class} — inspect the error and retry"),
            kind: ToastKind::Error,
        }),
        crate::engine::IdleReason::Interrupted => Some(IdleReasonStatus {
            text: "turn interrupted".to_string(),
            kind: ToastKind::Info,
        }),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AttentionInterruptKind {
    Question,
    Approval,
}

impl AttentionInterruptKind {
    fn event(self) -> crate::tui::attention::AttentionEvent {
        match self {
            Self::Question => crate::tui::attention::AttentionEvent::Question,
            Self::Approval => crate::tui::attention::AttentionEvent::Approval,
        }
    }
}

#[derive(Debug, Clone)]
struct AttentionInterruptState {
    interrupt_id: uuid::Uuid,
    kind: AttentionInterruptKind,
    pending: bool,
    pending_count: usize,
    next_renudge_at: Instant,
}

#[derive(Debug, Clone)]
struct TerminalTitleState {
    active: bool,
    stack_pushed: bool,
    pushed_for_cleanup: Arc<AtomicBool>,
}

/// Default toast lifetime per TUI-design-philosophy §7.
const TOAST_TTL: Duration = Duration::from_secs(3);

/// How recently a keystroke must have landed for the attention subsystem to
/// treat the user as actively present (the conservative focus proxy — see
/// [`App::notify_attention`]). A turn that finishes inside this window while
/// the user is typing stays toast-only.
const RECENT_INTERACTION_WINDOW: Duration = Duration::from_secs(20);

/// A turn running at least this long is treated as "long-running" for the
/// attention subsystem: its completion escalates (desktop) even when the user
/// is still at the keyboard, since a long wait is exactly when they look away.
const LONG_RUNNING_TURN: Duration = Duration::from_secs(30);

fn emit_terminal_title_sequence(sequence: &str) {
    use std::io::{IsTerminal, Write};
    let mut out = stdout();
    if !out.is_terminal() {
        return;
    }
    let _ = out.write_all(sequence.as_bytes());
    let _ = out.flush();
}

/// Ring the terminal bell once (`BEL`, `0x07`). Best-effort: a write failure
/// (closed/odd terminal) is ignored — a missed bell must never crash the TUI.
fn ring_terminal_bell() {
    use std::io::Write;
    let mut out = stdout();
    let _ = out.write_all(b"\x07");
    let _ = out.flush();
}

/// Post a best-effort desktop notification with a terse, secret-safe summary.
///
/// Two mutually exclusive layers, both non-fatal by construction — emitting
/// both would double-notify, since OSC-honoring terminals post their own
/// popups on top of the `notify-rust` one:
///
/// 1. **Terminal notification escapes**, over SSH only. We write OSC 777 +
///    OSC 9 (built by [`crate::tui::attention::desktop_notification_escapes`])
///    straight to the raw terminal. Supporting terminals (kitty / WezTerm /
///    foot / Ghostty) turn them into native notifications; others ignore the
///    unknown OSC; and they carry over SSH — which `notify-rust` can't. The
///    bytes contain no cursor movement or visible glyphs, so emitting them
///    mid-frame under crossterm raw mode + ratatui is safe.
/// 2. **The OS notification service** via `notify-rust`, for local sessions
///    only. Over SSH it would post on the *remote* host (useless), so we skip
///    it when an SSH session is detected. It can block on D-Bus, so it runs on
///    a detached thread and every error is swallowed (logged at debug for
///    observability).
fn post_desktop_notification(summary: &str) {
    use std::io::Write;

    let over_ssh =
        std::env::var_os("SSH_CONNECTION").is_some() || std::env::var_os("SSH_TTY").is_some();

    // Layer 1 — terminal escapes, SSH sessions only. The terminal is the only
    // path back to the user's desktop; locally we'd double-notify terminals
    // that honor the OSC (and WezTerm honors both 777 and 9).
    if over_ssh {
        let escapes = crate::tui::attention::desktop_notification_escapes("Cockpit", summary);
        let mut out = stdout();
        let _ = out.write_all(escapes.as_bytes());
        let _ = out.flush();
        return;
    }

    // Layer 2 — OS notification service, local sessions only.
    let summary = summary.to_string();
    std::thread::spawn(move || {
        if let Err(e) = notify_rust::Notification::new()
            .summary("Cockpit")
            .body(&summary)
            .show()
        {
            tracing::debug!(
                target: "cockpit::attention",
                error = %e,
                "desktop notification backend failed (best-effort, ignored)"
            );
        }
    });
}

/// Args cached at `ToolStart` for an `edit` / `editunlock` call so the
/// matching `ToolEnd` can build a `HistoryEntry::Diff`. We don't keep
/// the whole `Value` because we only need three fields.
#[derive(Debug, Clone)]
struct PendingEditArgs {
    path: String,
    old: String,
    new: String,
}

/// Drag-select state for the chat area (plan.md T8.f). Coordinates
/// are absolute terminal cells; we re-derive chat-relative positions
/// at render time so resize / scroll changes don't desync.
#[derive(Debug, Clone, Copy)]
struct Selection {
    /// Where the drag started.
    anchor: (u16, u16),
    /// Where the drag is right now (or where it ended on mouse-up).
    focus: (u16, u16),
    /// True while the left button is still held. False once released
    /// (selection persists for copy until Esc or a new selection).
    active: bool,
}

impl Selection {
    /// Normalize into reading-order `(start, end)` cells, both
    /// inclusive. When the user drags right-to-left or bottom-to-top,
    /// anchor > focus; this swaps them so callers can iterate the
    /// selection in a single direction.
    fn ordered(&self) -> ((u16, u16), (u16, u16)) {
        let (a_col, a_row) = self.anchor;
        let (f_col, f_row) = self.focus;
        if (a_row, a_col) <= (f_row, f_col) {
            (self.anchor, self.focus)
        } else {
            (self.focus, self.anchor)
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(super) struct TranscriptFind {
    pub(super) query: String,
    pub(super) matches: Vec<usize>,
    pub(super) current: Option<usize>,
    pub(super) saved_offset: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CursorShape {
    /// Steady vertical bar — used in Insert mode (and when vim is
    /// disabled). Explicit rather than `DefaultUserShape` because many
    /// modern terminals default to a block cursor; without an explicit
    /// bar, Insert mode would visually match Normal.
    Bar,
    /// Solid block — used in Normal / Operator-pending mode.
    Block,
}

#[derive(Clone)]
pub(super) struct HistoryRenderCacheEntry {
    pub(super) sig: u64,
    pub(super) rendered: Rc<crate::tui::history::Rendered>,
}

#[derive(Clone, Default)]
pub(super) struct PendingRenderCacheEntry {
    pub(super) state: crate::tui::history::PendingRenderState,
}

#[derive(Debug, Clone, Default)]
pub(super) enum TranscriptViewMeta {
    #[default]
    Main,
    Subagent(SubagentViewMeta),
}

#[derive(Debug, Clone)]
pub(super) struct SubagentViewMeta {
    pub(super) parent: String,
    pub(super) child: String,
    pub(super) task_call_id: String,
    pub(super) label: String,
    pub(super) read_only: bool,
    pub(super) finished: bool,
    pub(super) countdown_started: Option<Instant>,
    pub(super) countdown_cancelled: bool,
    pub(super) notice: Option<String>,
}

#[derive(Clone)]
pub(super) struct StoredTranscriptView {
    pub(super) meta: TranscriptViewMeta,
    pub(super) history: Vec<HistoryEntry>,
    pub(super) pending: Option<PendingMsg>,
    pub(super) history_render_versions: Vec<u64>,
    pub(super) history_render_fingerprints: Vec<u64>,
    pub(super) history_render_cache: HashMap<usize, HistoryRenderCacheEntry>,
    pub(super) pending_render_cache: Option<PendingRenderCacheEntry>,
    pub(super) chat_scroll_offset: usize,
}

impl App {
    fn capture_transcript_view(&mut self) -> StoredTranscriptView {
        StoredTranscriptView {
            meta: std::mem::take(&mut self.transcript_view),
            history: std::mem::take(&mut self.history),
            pending: self.pending.take(),
            history_render_versions: std::mem::take(&mut self.history_render_versions),
            history_render_fingerprints: std::mem::take(&mut self.history_render_fingerprints),
            history_render_cache: std::mem::take(&mut self.history_render_cache),
            pending_render_cache: self.pending_render_cache.take(),
            chat_scroll_offset: self.chat_scroll_offset,
        }
    }

    fn restore_transcript_view(&mut self, mut view: StoredTranscriptView) {
        self.transcript_view = std::mem::take(&mut view.meta);
        self.history = std::mem::take(&mut view.history);
        self.pending = view.pending.take();
        self.history_render_versions = std::mem::take(&mut view.history_render_versions);
        self.history_render_fingerprints = std::mem::take(&mut view.history_render_fingerprints);
        self.history_render_cache = std::mem::take(&mut view.history_render_cache);
        self.pending_render_cache = view.pending_render_cache.take();
        self.chat_scroll_offset = view.chat_scroll_offset;
        self.chat_row_meta.clear();
        self.clickable_rows.clear();
        self.box_rows.clear();
        self.diff_rows.clear();
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
    }

    pub(super) fn active_subagent_view(&self) -> Option<&SubagentViewMeta> {
        match &self.transcript_view {
            TranscriptViewMeta::Subagent(view) => Some(view),
            TranscriptViewMeta::Main => None,
        }
    }

    pub(super) fn active_subagent_view_mut(&mut self) -> Option<&mut SubagentViewMeta> {
        match &mut self.transcript_view {
            TranscriptViewMeta::Subagent(view) => Some(view),
            TranscriptViewMeta::Main => None,
        }
    }

    pub(super) fn open_subagent_view_for_history_index(&mut self, idx: usize) -> bool {
        let Some(HistoryEntry::Subagent {
            parent,
            child,
            task_call_id,
            label,
            outcome,
            ..
        }) = self.history.get(idx).cloned()
        else {
            return false;
        };

        let history = self.backfill_subagent_history(&task_call_id, &label);
        let read_only = outcome.is_some() || child == "docs";
        let finished = outcome.is_some();
        let meta = SubagentViewMeta {
            parent,
            child,
            task_call_id,
            label,
            read_only,
            finished,
            countdown_started: None,
            countdown_cancelled: true,
            notice: if read_only && outcome.is_none() {
                Some("This subagent is read-only.".to_string())
            } else {
                None
            },
        };

        let previous = self.capture_transcript_view();
        self.transcript_view_stack.push(previous);
        self.transcript_view = TranscriptViewMeta::Subagent(meta);
        self.history = history;
        self.pending = None;
        self.history_render_versions = vec![0; self.history.len()];
        self.history_render_fingerprints = vec![0; self.history.len()];
        self.history_render_cache.clear();
        self.pending_render_cache = None;
        self.chat_scroll_offset = 0;
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        true
    }

    fn backfill_subagent_history(&self, task_call_id: &str, label: &str) -> Vec<HistoryEntry> {
        let Some(session_id) = self.current_session_id() else {
            return Vec::new();
        };
        let snapshot = crate::db::Db::open_default()
            .and_then(|db| {
                db.read_blocking(|conn| {
                    crate::engine::rehydrate::subagent_history_snapshot_conn(
                        conn,
                        session_id,
                        task_call_id,
                        label,
                    )
                })
            })
            .unwrap_or_default();
        wire_history_to_entries(snapshot)
    }

    pub(super) fn return_from_subagent_view(&mut self) -> bool {
        let Some(previous) = self.transcript_view_stack.pop() else {
            return false;
        };
        self.restore_transcript_view(previous);
        self.chat_scroll_offset = 0;
        true
    }

    pub(super) fn cancel_subagent_countdown_or_return(&mut self) -> bool {
        if let Some(view) = self.active_subagent_view_mut()
            && view.countdown_started.is_some()
            && !view.countdown_cancelled
        {
            view.countdown_cancelled = true;
            view.notice = Some("Stayed in finished subagent view.".to_string());
            return true;
        }
        self.return_from_subagent_view()
    }

    pub(super) fn refresh_subagent_countdown(&mut self) {
        let should_return = self
            .active_subagent_view()
            .and_then(|view| {
                view.countdown_started
                    .map(|started| (started, view.countdown_cancelled))
            })
            .is_some_and(|(started, cancelled)| {
                !cancelled && started.elapsed() >= Duration::from_secs(5)
            });
        if should_return {
            let _ = self.return_from_subagent_view();
        }
    }

    pub(super) fn active_subagent_countdown_line(&self) -> Option<String> {
        let view = self.active_subagent_view()?;
        let started = view.countdown_started?;
        if view.countdown_cancelled {
            return None;
        }
        let elapsed = started.elapsed().as_secs();
        let remaining = 5_u64.saturating_sub(elapsed).max(1);
        Some(format!(
            "Returning to {} from {} in {remaining}s - press esc to stay here",
            view.parent, view.child
        ))
    }

    pub(super) fn submit_subagent_steer(&mut self) -> bool {
        let Some(view) = self.active_subagent_view().cloned() else {
            return false;
        };
        let message = self.composer.text().trim().to_string();
        if message.is_empty() {
            return true;
        }
        if view.read_only || view.finished {
            if let Some(active) = self.active_subagent_view_mut() {
                active.notice =
                    Some("This subagent is read-only; steering is disabled.".to_string());
            }
            return true;
        }
        let Some(session_id) = self.current_session_id() else {
            if let Some(active) = self.active_subagent_view_mut() {
                active.notice = Some("No active session; steer was not sent.".to_string());
            }
            return true;
        };
        self.composer.clear();
        self.history.push(HistoryEntry::User {
            text: message.clone(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: false,
            persist_failed: false,
        });
        self.push_plain("steer queued for next turn boundary".to_string());
        self.history_render_versions.resize(self.history.len(), 0);
        self.history_render_fingerprints
            .resize(self.history.len(), 0);
        let req = crate::daemon::proto::Request::SteerDelegation {
            session_id,
            task_call_id: view.task_call_id,
            label: view.label,
            message,
        };
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("subagent.steer"),
            AsyncActionPolicy::AllowConcurrent,
            move || match agent_runner::daemon_request_blocking(req)? {
                crate::daemon::proto::Response::DelegationSteer { result } => {
                    Ok(AsyncActionPayload::DelegationSteer(result))
                }
                other => Err(format!("unexpected steer response: {other:?}")),
            },
        );
        true
    }

    fn apply_subagent_steer_result(&mut self, result: crate::daemon::proto::DelegationSteerResult) {
        let line = match result.status {
            crate::daemon::proto::DelegationSteerStatus::Queued => {
                let label = result.label.clone().unwrap_or_default();
                format!(
                    "steer queued for {}/{} at next turn boundary",
                    result.task_call_id, label
                )
            }
            crate::daemon::proto::DelegationSteerStatus::NotSteerable => {
                format!("steer not queued: {}", result.message)
            }
            crate::daemon::proto::DelegationSteerStatus::InternalError => {
                format!("steer failed: {}", result.message)
            }
        };
        match result.status {
            crate::daemon::proto::DelegationSteerStatus::Queued => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.notice = Some(line);
                } else {
                    self.show_toast(line, ToastKind::Success);
                }
            }
            crate::daemon::proto::DelegationSteerStatus::NotSteerable => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.read_only = true;
                    view.finished = true;
                    view.notice = Some(line);
                    if view.countdown_started.is_none() {
                        view.countdown_started = Some(Instant::now());
                        view.countdown_cancelled = false;
                    }
                } else {
                    self.show_toast(line, ToastKind::Warning);
                }
            }
            crate::daemon::proto::DelegationSteerStatus::InternalError => {
                if let Some(view) = self.active_subagent_view_mut() {
                    view.notice = Some(line);
                } else {
                    self.show_toast(line, ToastKind::Error);
                }
            }
        }
    }
}

async fn wait_optional_notify(notify: Option<Arc<tokio::sync::Notify>>) {
    match notify {
        Some(notify) => notify.notified().await,
        None => pending::<()>().await,
    }
}

fn clear_redraw(needs_redraw: &mut bool) {
    *needs_redraw = false;
}

fn take_redraw_request(needs_redraw: &mut bool) -> bool {
    if !*needs_redraw {
        return false;
    }
    clear_redraw(needs_redraw);
    true
}

#[cfg(test)]
static EVENT_LOOP_DRAW_CALL_COUNT: AtomicUsize = AtomicUsize::new(0);

#[cfg(test)]
pub(crate) fn reset_event_loop_draw_call_count() {
    EVENT_LOOP_DRAW_CALL_COUNT.store(0, Ordering::SeqCst);
}

#[cfg(test)]
pub(crate) fn event_loop_draw_call_count() -> usize {
    EVENT_LOOP_DRAW_CALL_COUNT.load(Ordering::SeqCst)
}

impl App {
    #[cfg(test)]
    pub fn new(project: Option<&Path>, no_sandbox: bool) -> Self {
        Self::new_inner(project, no_sandbox, None)
    }

    pub fn new_with_db(project: Option<&Path>, no_sandbox: bool, db: crate::db::Db) -> Self {
        Self::new_inner(project, no_sandbox, Some(db))
    }

    pub fn new_with_db_and_session(
        project: Option<&Path>,
        no_sandbox: bool,
        db: crate::db::Db,
        session_id: uuid::Uuid,
    ) -> Self {
        let mut app = Self::new_inner(project, no_sandbox, Some(db));
        app.launch.session_id = Some(session_id);
        app
    }

    fn new_inner(
        project: Option<&Path>,
        no_sandbox: bool,
        startup_db: Option<crate::db::Db>,
    ) -> Self {
        let mut timer = crate::startup::PhaseTimer::start("App::new");
        // Skip the synchronous `git status` here — it can take seconds in a
        // giant repo and would block the first frame. `spawn_git_refresh`
        // does an immediate background refresh and the branch pill pops in
        // a tick later (chrome guards on `repo_status.is_some()`).
        let LaunchBundle {
            launch,
            providers,
            extended,
        } = welcome::load_bundle(project, false);
        timer.phase("welcome_load");
        let tui_cfg = extended.tui.clone();
        timer.phase("config_load");
        // Discovered skills surfaced as bare-`/<name>` slash-menu entries
        // (implementation note); builtin-colliding names are
        // dropped here (still reachable via `/skill <name>`).
        let skill_commands =
            discover_bare_skill_commands(&launch.cwd, &extended, &launch.agent_name);
        timer.phase("skill_discovery");
        let llm_mode =
            resolve_tui_llm_mode(launch.active_model.as_ref(), extended.llm_mode, &providers);
        let approval_mode = extended.default_approval_mode;
        let delegation_recursion_enabled = extended.delegation.recursion_enabled
            && extended.delegation.default_recursion_depth > 0;
        let delegation_recursion_depth = extended.delegation.default_recursion_depth.min(6);
        let predict_setting = extended.predict_next_message;
        // Session-only redaction-source state, seeded from config; the daemon
        // keeps it in sync via `RedactionState` broadcasts (`/toggle-redaction`).
        let redact_scan_environment = extended.redact.scan_environment;
        let redact_scan_dotenv = extended.redact.scan_dotenv;
        let redact_scan_ssh_keys = extended.redact.scan_ssh_keys;
        // Session-only request-preflight state, seeded from the layered
        // config (project wins); the daemon keeps it in sync via
        // `PreflightState` broadcasts (`/preflight`).
        let preflight_enabled = extended.preflight.enabled;
        let trusted_only_enabled = extended.trusted_only;
        let sandbox_escalation_enabled = extended.sandbox_escalation_enabled;
        let has_no_providers_at_startup = providers.providers.is_empty();
        let vim_setting = tui_cfg.vim_mode;
        let thinking_setting = tui_cfg.thinking;
        let markdown_opts = MarkdownOpts {
            agent: tui_cfg.render_agent_markdown,
            user: tui_cfg.render_user_markdown,
        };
        let mut composer = Composer::new(vim_setting.vim_enabled());
        // We start in Insert mode regardless — landing in Normal on
        // first keystroke is jarring for users new to the TUI. The
        // hint (when enabled) tells them how to switch back if they
        // Esc out.
        composer.set_vim_mode(VimMode::Insert);

        let repo_status = Arc::new(Mutex::new(launch.repo_status.clone()));

        // Probe the daemon synchronously up front so the prompt shows
        // immediately when we open the TUI rather than after a tick.
        let (daemon_prompt, daemon_connected, startup_daemon_socket) =
            match crate::daemon::DaemonPaths::resolve() {
                Ok(paths) if paths.ephemeral => match crate::daemon::probe_blocking(&paths) {
                    crate::daemon::DaemonStatus::Running => {
                        (None, true, Some(paths.socket.clone()))
                    }
                    status => (
                        Some(crate::tui::daemon_prompt::DaemonPromptDialog::new(
                            status, paths,
                        )),
                        false,
                        None,
                    ),
                },
                Ok(_) => {
                    let probe = crate::daemon::discover_blocking();
                    match probe.status {
                        crate::daemon::DaemonStatus::Running => {
                            (None, true, Some(probe.paths.socket.clone()))
                        }
                        status => (
                            Some(crate::tui::daemon_prompt::DaemonPromptDialog::new(
                                status,
                                probe.paths,
                            )),
                            false,
                            None,
                        ),
                    }
                }
                Err(_) => (None, false, None),
            };
        timer.phase("daemon_probe");
        let org_sync_disclosure = None;
        let connector_disclosure = None;
        timer.phase("remote_disclosures_deferred");
        timer.done();

        let diff_style = tui_cfg.diff_style;
        let mouse_capture = tui_cfg.mouse_capture;
        let hyperlinks = tui_cfg.hyperlinks;
        let exit_tail_lines = tui_cfg.exit_tail_lines;
        let rich_text_copy = tui_cfg.rich_text_copy;
        let use_emojis = tui_cfg.use_emojis;
        let attention = tui_cfg.attention;
        let initial_agent_path = vec![launch.agent_name.clone()];
        let terminal_title_pushed_for_cleanup = Arc::new(AtomicBool::new(false));
        let mut app = Self {
            launch,
            composer,
            vim_setting,
            thinking_setting,
            markdown_opts,
            diff_style,
            use_emojis,
            pending_edit_args: HashMap::new(),
            queue: Vec::new(),
            foreground_input_target: None,
            fresh_queue_ack: FreshQueueAck::None,
            prompt_history: Vec::new(),
            prompt_history_cursor: 0,
            staged_draft: None,
            history: Vec::new(),
            pending: None,
            transcript_view: TranscriptViewMeta::Main,
            transcript_view_stack: Vec::new(),
            started_at: Instant::now(),
            busy: false,
            working_span_state: WorkingSpanState::Idle,
            span_started_at: None,
            working_msg_idx: WORKING_MESSAGES.len(),
            reconnect: None,
            daemon_link: None,
            repo_status,
            dialog: Dialog::None,
            overlay: Overlay::None,
            daemon_prompt,
            question_dialog: None,
            question_dialog_btw: false,
            pending_btw_interrupt: None,
            composer_active_since_dialog: true,
            pending_local_choice: None,
            daemon_connected,
            daemonless: false,
            daemon_guard: None,
            daemon_signal_task: None,
            fetch_models_progress: Arc::new(Mutex::new(Vec::new())),
            agent_runner: None,
            display_attach_backoff: DisplayAttachBackoff::default(),
            async_actions: AsyncActionRunner::default(),
            completed_async_actions: Vec::new(),
            startup_background: StartupBackground {
                daemon_socket: startup_daemon_socket,
                db: startup_db,
                started: false,
            },
            chat_area: None,
            input_area: None,
            suggestion_box_area: None,
            suggestion_row_hits: Vec::new(),
            hovered_suggestion: None,
            chat_scroll_offset: 0,
            chat_total_lines: 0,
            chat_visible_lines: 0,
            chat_find_lines: Vec::new(),
            transcript_find: None,
            selection: None,
            chat_text_grid: Vec::new(),
            chat_cont_rows: Vec::new(),
            chat_row_meta: Vec::new(),
            clickable_rows: Vec::new(),
            box_rows: Vec::new(),
            hovered_affordance: None,
            hovered_control_chip: None,
            affordance_scroll_regions: Vec::new(),
            diff_rows: Vec::new(),
            last_cursor_shape: None,
            at_selected: 0,
            at_scroll: 0,
            at_cache: std::cell::RefCell::new(None),
            accepted_tags: Vec::new(),
            paste_registry: crate::tui::paste::PasteRegistry::new(),
            pending_text_object: None,
            at_dismissed: false,
            slash_selected: 0,
            slash_scroll: 0,
            slash_menu_cache: std::cell::RefCell::new(None),
            slash_cycle_stem: None,
            pending_new_session: false,
            last_usage: None,
            estimate_at_last_usage: 0,
            history_estimate_cache: Cell::new(None),
            pending_token_cache: Cell::new(None),
            history_render_versions: Vec::new(),
            history_render_fingerprints: Vec::new(),
            next_history_render_version: 1,
            history_render_cache: HashMap::new(),
            pending_render_cache: None,
            usage_models: HashMap::new(),
            usage_slash: HashMap::new(),
            usage_tags: HashMap::new(),
            skill_commands,
            project_id: None,
            current_session_persisted: false,
            guidance_estimate: None,
            prunable_tokens: 0,
            cache_cold: true,
            llm_mode,
            agent_path: initial_agent_path,
            footer_selection: None,
            footer_hit_areas: Vec::new(),
            footer_agent_picker: None,
            footer_mode_picker: None,
            footer_picker_row_hits: Vec::new(),
            pending_agent_switch_log: None,
            elided_event_ids: std::collections::HashSet::new(),
            pending_compact: None,
            pending_prune_confirm: false,
            pending_stop_confirm: None,
            pending_usage: Vec::new(),
            pending_external_edit: false,
            mouse_capture,
            hyperlinks,
            link_registry: crate::tui::links::LinkRegistry::default(),
            exit_tail_lines,
            rich_text_copy,
            tmux_copy_hint_shown: false,
            context_menu: None,
            toast: None,
            idle_reason_status: None,
            pane: None,
            btw_pane: None,
            pane_side: PaneSide::Full,
            pane_ratio: 0.5,
            pane_focused: false,
            pane_rect: None,
            divider: None,
            pane_body: None,
            dragging_divider: false,
            pending_git_blocks: Vec::new(),
            active_schedules: std::collections::BTreeMap::new(),
            ctrl_c_armed_at: None,
            no_sandbox,
            sandbox_mode: crate::tools::sandbox_mode::SandboxMode::from_enabled(!no_sandbox),
            container_network_enabled: false,
            container_availability: crate::container::initial_availability_unknown(),
            caffeinate_active: false,
            attention,
            attention_state: crate::tui::attention::AttentionState::new(),
            attention_interrupt: None,
            background_attention_interrupts: std::collections::BTreeMap::new(),
            terminal_title: TerminalTitleState {
                active: false,
                stack_pushed: false,
                pushed_for_cleanup: terminal_title_pushed_for_cleanup,
            },
            last_user_interaction: Instant::now(),
            waiting_for_lock: None,
            sandbox_down_notice: None,
            sandbox_notice_copy_rect: None,
            auth_failure_annotations: Default::default(),
            auth_failure_notice: None,
            auth_failure_fingerprints: Default::default(),
            auth_notice_switch_rect: None,
            auth_notice_fix_rect: None,
            redact_scan_environment,
            redact_scan_dotenv,
            redact_scan_ssh_keys,
            preflight_enabled,
            trusted_only_enabled,
            sandbox_escalation_enabled,
            approval_mode,
            delegation_recursion_enabled,
            delegation_recursion_depth,
            gitignore_session_allow: Vec::new(),
            tandem_models: Vec::new(),
            pending_tandem_options: Vec::new(),
            org_sync_disclosure,
            connector_disclosure,
            has_no_providers_at_startup,
            side_conversation: None,
            daemon_draining: false,
            predict_setting,
            prediction_state: PredictionState::default(),
            prediction_result: Arc::new(Mutex::new(None)),
            pin_pick: None,
            fork_pick: None,
            copy_pick: None,
            pins_review: None,
            pin_count: 0,
            pin_control_rows: Vec::new(),
            msg_abs_line: std::collections::HashMap::new(),
            chat_banner_lines: 0,
            pin_count_session: None,
            pinned_seqs_cache: HashSet::new(),
            pinned_seqs_session: None,
            keys_overlay: None,
            keyboard_enhancement_active: false,
        };
        // First-run convenience: if the daemon prompt doesn't gate
        // startup, open the Add-Provider wizard immediately when no
        // providers are configured. The prompt-resolution branches
        // call this same helper after the user dismisses the daemon
        // prompt.
        if app.daemon_prompt.is_none() {
            app.maybe_open_add_provider_wizard();
        }
        app
    }

    /// If the user has no providers configured in the active config
    /// layer, open `/settings → Providers → Add` directly. No-op when
    /// providers already exist or when the settings dialog is already
    /// open. Evaluated each launch so emptying the providers list
    /// re-triggers the wizard on the next start.
    pub(super) fn maybe_open_add_provider_wizard(&mut self) {
        if self.dialog.is_active() {
            return;
        }
        if !self.has_no_providers_at_startup {
            return;
        }
        self.dialog = crate::tui::settings::Dialog::open_providers_add(&self.launch.cwd);
    }

    fn apply_startup_guidance_estimate(
        &mut self,
        cwd: PathBuf,
        active_model: Option<(String, String)>,
        estimate: agent_runner::GuidanceEstimate,
    ) {
        if cwd == self.launch.cwd && active_model == self.launch.active_model {
            self.guidance_estimate = Some(estimate);
        }
    }

    fn start_startup_background_tasks(&mut self) {
        if self.startup_background.started {
            return;
        }
        self.startup_background.started = true;

        tokio::task::spawn_blocking(crate::tokens::warm_cl100k);

        let cwd = self.launch.cwd.clone();
        let active_model = self.launch.active_model.clone();
        let socket = self.startup_background.daemon_socket.clone();
        self.async_actions.start(
            AsyncActionKind::Internal("startup.guidance.estimate"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("startup.guidance.estimate")),
            async move {
                let (provider, model) = match &active_model {
                    Some((p, m)) => (Some(p.clone()), Some(m.clone())),
                    None => (None, None),
                };
                let estimate = agent_runner::fetch_guidance_estimate_with_socket(
                    &cwd, provider, model, socket,
                )
                .await;
                Ok(AsyncActionPayload::StartupGuidanceEstimate {
                    cwd,
                    active_model,
                    estimate,
                })
            },
        );

        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("container.availability"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("container.availability")),
            || {
                Ok(AsyncActionPayload::ContainerAvailability(
                    crate::container::availability_snapshot(),
                ))
            },
        );

        let db = self.startup_background.db.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("startup.remote_disclosures"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("startup.remote_disclosures")),
            move || {
                let Some(credential) = crate::auth::flycockpit::maybe_load_credential() else {
                    return Ok(AsyncActionPayload::RemoteDisclosures {
                        org: None,
                        connector: None,
                    });
                };
                let db = match db {
                    Some(db) => db,
                    None => crate::db::Db::open_default().map_err(|e| e.to_string())?,
                };
                let org = db
                    .org_sync_disclosure_for_server(&credential.server_url)
                    .map_err(|e| e.to_string())?;
                let connector = db
                    .connector_disclosure(&credential.server_url, &credential.instance_id)
                    .map_err(|e| e.to_string())?;
                Ok(AsyncActionPayload::RemoteDisclosures { org, connector })
            },
        );
    }

    pub(super) fn geometry(&self) -> PaneGeometry {
        let dialog = if self.daemon_prompt.is_some() {
            crate::tui::daemon_prompt::DIALOG_HEIGHT
        } else if self.dialog.is_active() {
            settings::DIALOG_HEIGHT
        } else if self.overlay.dialog_height() > 0 {
            self.overlay.dialog_height()
        } else if self.footer_agent_picker.is_some() {
            footer_agent_picker_height(self.footer_agent_picker.as_ref())
        } else if self.footer_mode_picker.is_some() {
            FOOTER_MODE_ORDER.len() as u16 + 4
        } else {
            0
        };
        // The answering dialog (GOALS §3b) is a compact, bottom-anchored
        // overlay sized to its content (capped), not a fullscreen modal.
        let compact = self
            .question_dialog
            .as_ref()
            .map(|d| d.desired_height())
            .unwrap_or(0);
        PaneGeometry::compute(
            self.input_height(),
            self.indicator_lines(),
            self.queue_lines(),
            self.suggestion_box_lines(),
            self.pins_indicator_lines(),
            self.sandbox_notice_lines(),
            self.total_history_lines(),
            dialog,
            compact,
        )
    }

    /// Height of the below-input pin-count indicator (`pinned-messages`):
    /// one row when the session has ≥1 pin, hidden (zero) otherwise.
    pub(super) fn pins_indicator_lines(&self) -> u16 {
        if self.pin_count > 0 { 1 } else { 0 }
    }

    /// Full text of the persistent sandbox-down notice (§6.5), or `None` when
    /// the sandbox is fine. Combines the diagnosed remedy (incl. the `sudo
    /// sysctl …=0` command when present) with the deterministic `/sandbox off`
    /// instruction the user must act on. Pure UI chrome — never enters history
    /// or any inference request.
    pub(super) fn sandbox_down_notice_text(&self) -> Option<String> {
        self.sandbox_down_notice.as_ref().map(|notice| {
            sandbox_down_notice_text(
                &notice.remedy,
                notice.fix_command.as_deref(),
                self.mouse_capture && notice.fix_command.is_some(),
            )
        })
    }

    pub(super) fn persistent_notice_text(&self) -> Option<String> {
        // Sandbox recovery is safety-critical, so it keeps the shared notice
        // row while active. The auth notice remains queued and appears as soon
        // as the sandbox remedy clears.
        self.sandbox_down_notice_text().or_else(|| {
            self.auth_failure_notice
                .as_ref()
                .map(|notice| crate::tui::auth_failure::notice_text(notice, self.mouse_capture))
        })
    }

    /// Height of the persistent below-input sandbox-down notice (§6.5): its
    /// wrapped row count (capped) when the sandbox can't initialize, zero
    /// otherwise. Persistent — never times out like a toast.
    pub(super) fn sandbox_notice_lines(&self) -> u16 {
        let Some(text) = self.persistent_notice_text() else {
            return 0;
        };
        let (term_w, _) = crossterm::terminal::size().unwrap_or((80, 24));
        sandbox_notice_wrapped_rows(&text, term_w)
    }

    pub async fn run(&mut self) -> Result<()> {
        // The launch banner now renders *inside* the alt screen as the
        // top of the chat pane (see `render_history` / `banner_box`),
        // so we no longer dump it to stdout before entering the alt
        // screen — that only ever showed up in scrollback after exit.

        // `try_init` enters the alternate screen and uses a full-
        // terminal viewport by default. GOALS §1d: alt screen during
        // the session for the clean full-screen experience; on exit
        // we leave alt screen and print the tail to stdout.
        let mut terminal = ratatui::try_init()?;
        let mut terminal_mode_guard = TerminalModeGuard::with_sink_and_title_state(
            CrosstermTerminalModeSink,
            self.terminal_title.pushed_for_cleanup.clone(),
        );

        if crossterm::execute!(
            stdout(),
            PushKeyboardEnhancementFlags(keyboard_enhancement_flags())
        )
        .is_ok()
        {
            terminal_mode_guard.mark_keyboard_enhancement_pushed();
            self.keyboard_enhancement_active = true;
        }

        // Bracketed paste (composer-paste-handling): the terminal wraps a
        // genuine paste in escape sequences crossterm surfaces as one
        // `Event::Paste(String)`, distinguishing it from char-by-char
        // typing (which keeps arriving as individual `KeyEvent`s). Without
        // this, large pastes would stream in as a flood of key events and
        // never trigger block behavior.
        if crossterm::execute!(stdout(), crossterm::event::EnableBracketedPaste).is_ok() {
            terminal_mode_guard.mark_bracketed_paste_enabled();
        }

        // Mouse capture is configurable (tui.mouse_capture, GOALS §1
        // T8.c). On: click-to-position in composer, clickable chips,
        // drag-select in chat. Off: native terminal select + copy +
        // scroll-wheel via alternate-scroll translation. Native
        // selection still works under capture if the user holds the
        // terminal's bypass modifier (Shift / Option / Fn).
        if self.mouse_capture && enable_mouse_capture_with_motion().is_ok() {
            terminal_mode_guard.mark_mouse_capture_enabled();
        }

        let refresh_handle = spawn_git_refresh(self.launch.cwd.clone(), self.repo_status.clone());

        let result = self.event_loop(&mut terminal).await;

        refresh_handle.abort();

        // Process-exit cleanup for an open `/side` (no orphaned ephemeral
        // sessions): discard the throwaway fork *before* the daemon guard
        // reaps an owned ephemeral daemon, so the discard RPC still reaches a
        // live daemon. The daemon's boot sweep is the SIGKILL backstop.
        if self.side_conversation.is_some() {
            self.end_side_conversation(false);
        }
        if self.btw_pane.is_some() {
            if let Some(Ok(runner)) = self.agent_runner.as_ref() {
                let _ = agent_runner::attached_request_tx_blocking(
                    runner.attached_request_tx.clone(),
                    crate::daemon::proto::Request::EndBtwFork {
                        parent_session_id: runner.session_id,
                    },
                );
            }
            self.close_btw_pane();
        }

        // Daemonless teardown (happy path): reap the owned ephemeral daemon
        // and stop its signal watcher. The guard routes a synchronous
        // `StopDaemon` through the daemon's single graceful drain path, so
        // an in-flight ephemeral daemon drains before exiting. This fires on
        // a clean quit *and* the error path below (the guard's `Drop` is the
        // backstop if `run` returns early); SIGINT/SIGTERM are covered by the
        // signal task. The self-reaping idle watchdog remains the backstop
        // for an uncatchable death (SIGKILL). Reaping here is independent of
        // whether a message was sent — a persisted session never keeps an
        // owned ephemeral daemon alive past its owner's exit.
        if let Some(task) = self.daemon_signal_task.take() {
            task.abort();
        }
        if let Some(guard) = &self.daemon_guard {
            guard.shutdown();
        }

        // Build the exit-tail text while we still own the alt screen
        // (history is in memory; rendering is irrelevant — we want
        // the plaintext projection of recent entries).
        let tail = self.build_exit_tail_lines();

        // Restore every terminal mode Cockpit owns before printing the
        // post-alt-screen tail. The guard's Drop repeats this path as the
        // panic/unwind backstop, but `cleanup` is idempotent.
        terminal_mode_guard.cleanup()?;
        // Print the tail to normal stdout. Lands in regular terminal
        // scrollback right after the welcome header that was printed
        // pre-alt-screen, so the user can scroll back through both.
        for line in tail {
            println!("{line}");
        }
        // Print the last opened session id — but only when it was actually
        // persisted (session-id-display-and-lazy-persist). An opened-but-
        // unused session left no DB row, so we print nothing about it.
        // Print the 6-char short id so the exit line matches the welcome
        // box; fall back to the full UUID only if the short id is somehow
        // absent (defensive — it should always be set once attached).
        if self.current_session_persisted {
            if let Some(short_id) = self.launch.session_short_id.as_deref() {
                println!("session {short_id}");
            } else if let Some(session_id) = self.launch.session_id {
                println!("session {session_id}");
            }
        }
        result
    }

    /// Build the tail of history as plain text lines for the post-
    /// alt-screen dump (GOALS §1d). Capped by `tui.exit_tail_lines`
    /// (default 100). `0` disables the dump entirely; `-1` returns
    /// the whole session. Returns an empty `Vec` when nothing should
    /// be printed.
    pub(super) fn build_exit_tail_lines(&mut self) -> Vec<String> {
        // Finalize any in-flight pending turn first so its text shows
        // up in the dump.
        self.finalize_pending();
        if self.history.is_empty() || self.exit_tail_lines == 0 {
            return Vec::new();
        }
        let plain: Vec<String> = self
            .history
            .iter()
            .flat_map(|entry| {
                let mut lines = entry_to_plain_lines(entry);
                // Match the chat-area visual: one blank row after
                // each user/agent block.
                if matches!(
                    entry,
                    HistoryEntry::User { .. } | HistoryEntry::Agent { .. }
                ) {
                    lines.push(String::new());
                }
                lines
            })
            .collect();
        let tail = if self.exit_tail_lines < 0 {
            plain
        } else {
            let n = self.exit_tail_lines as usize;
            if plain.len() > n {
                plain[plain.len() - n..].to_vec()
            } else {
                plain
            }
        };
        tail.into_iter()
            .map(|line| sanitize_for_raw_stdout(&line))
            .collect()
    }

    pub(super) async fn event_loop(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        self.event_loop_with_input(terminal, TerminalInput::new())
            .await
    }

    async fn event_loop_with_input(
        &mut self,
        terminal: &mut DefaultTerminal,
        mut terminal_input: TerminalInput,
    ) -> Result<()> {
        let mut needs_redraw = true;

        loop {
            if self.service_event_loop_wake(terminal, &mut terminal_input)? {
                needs_redraw = true;
            }
            if self.tick_attention_interrupt() {
                needs_redraw = true;
            }
            self.start_startup_background_tasks();

            if take_redraw_request(&mut needs_redraw) {
                #[cfg(test)]
                EVENT_LOOP_DRAW_CALL_COUNT.fetch_add(1, Ordering::SeqCst);
                self.link_registry.begin_frame();
                terminal.draw(|frame| self.render(frame))?;
                crate::tui::links::emit_osc8(&self.link_registry, self.hyperlinks)?;
                // The composer is the user's active input surface this frame iff
                // no question dialog is displacing it
                // (implementation note). A render with no
                // dialog means the composer has genuinely been usable, so the
                // next dialog opened from here arms the full anti-misfire
                // lockout. This render-driven mark is what makes the signal
                // robust to the same-cycle `None→Some` handoff: a follow-up
                // dialog installed before any composer render keeps the flag
                // false and opens immediately answerable.
                if self.question_dialog.is_none() {
                    self.composer_active_since_dialog = true;
                }
                self.sync_cursor_shape();
            }

            let agent_notify = self
                .agent_runner
                .as_ref()
                .and_then(|runner| runner.as_ref().ok())
                .map(AgentRunner::event_notifier);
            let async_notify = self.async_actions.notifier();

            if self.animation_tick_active() {
                let animation = tokio::time::sleep(ANIMATION_TICK);
                tokio::pin!(animation);
                tokio::select! {
                    maybe_event = terminal_input.next() => {
                        if self.handle_event_stream_item(maybe_event)? {
                            break;
                        }
                        if terminal_input.drain_ready(MAX_DRAIN_PER_PASS, |item| self.handle_event_stream_item(item)).await? {
                            break;
                        }
                        needs_redraw = true;
                    }
                    _ = wait_optional_notify(agent_notify) => {
                        self.drain_agent_events();
                        needs_redraw = true;
                    }
                    _ = async_notify.notified() => {
                        needs_redraw = self.drain_async_actions();
                    }
                    _ = &mut animation => {
                        needs_redraw = true;
                    }
                }
            } else {
                tokio::select! {
                    maybe_event = terminal_input.next() => {
                        if self.handle_event_stream_item(maybe_event)? {
                            break;
                        }
                        if terminal_input.drain_ready(MAX_DRAIN_PER_PASS, |item| self.handle_event_stream_item(item)).await? {
                            break;
                        }
                        needs_redraw = true;
                    }
                    _ = wait_optional_notify(agent_notify) => {
                        self.drain_agent_events();
                        needs_redraw = true;
                    }
                    _ = async_notify.notified() => {
                        needs_redraw = self.drain_async_actions();
                    }
                }
            }
        }

        Ok(())
    }

    fn service_event_loop_wake(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<bool> {
        let mut changed = false;
        self.ensure_session_for_display();
        changed |= self.sync_repo_status();
        changed |= self.drain_fetch_progress();
        changed |= self.drain_agent_events();
        changed |= self.drain_async_actions();
        changed |= self.drain_prediction();
        self.sync_prediction_ghost();
        self.sync_active_agent();
        self.sync_pin_count();
        self.sync_mouse_capture_from_dialog();
        changed |= self.tick_toast();
        changed |= self.tick_ctrl_c_window();
        self.dialog.tick();
        // Auto-close the embedded pane when its child has exited
        // (GOALS §1i — e.g. `:q`).
        self.service_pane();
        // In alt-screen mode the viewport is always the full
        // terminal; no need to grow it or spill history into
        // scrollback (alt screen doesn't have scrollback). The
        // wheel-scroll path handles in-app scrollback instead.
        changed |= self.maybe_service_new_session(terminal)?;
        self.maybe_service_external_edit(terminal, terminal_input)?;
        self.maybe_service_agent_file_edit(terminal, terminal_input)?;
        self.maybe_service_category_setting_edit(terminal, terminal_input)?;
        Ok(changed)
    }

    fn handle_event_stream_item(&mut self, item: Option<std::io::Result<Event>>) -> Result<bool> {
        match item {
            Some(Ok(event)) => Ok(self.handle_terminal_event(event)),
            Some(Err(error)) => Err(error.into()),
            None => Ok(true),
        }
    }

    fn handle_terminal_event(&mut self, event: Event) -> bool {
        match event {
            Event::Key(key) if accepts_key(&key) => self.handle_key(key),
            Event::Paste(data) => {
                self.handle_paste(data);
                false
            }
            Event::Mouse(mouse) => {
                self.handle_mouse(mouse);
                false
            }
            Event::Resize(_, _) => false,
            _ => false,
        }
    }

    fn animation_tick_active(&self) -> bool {
        self.busy
            || self.pending.is_some()
            || self.toast.is_some()
            || self.ctrl_c_armed_at.is_some()
            || self.reconnect.is_some()
            || self.pane.is_some()
            || self.async_actions.pending_count() > 0
            || self.dialog.is_active()
            || self.question_dialog.is_some()
            || self.daemon_prompt.is_some()
    }

    /// Show a transient toast (TUI-design-philosophy §7). Replaces
    /// any existing toast — newest wins, the older one is gone.
    /// 3-second TTL; cleared early by any user interaction (see the
    /// `dismiss_toast_on_interaction` hooks in handle_key and
    /// handle_mouse).
    pub(super) fn show_toast(&mut self, text: impl Into<String>, kind: ToastKind) {
        self.toast = Some(Toast {
            text: text.into(),
            kind,
            expires_at: Instant::now() + TOAST_TTL,
            persistent: false,
        });
    }

    pub(super) fn apply_idle_reason_status(&mut self, reason: crate::engine::IdleReason) {
        self.idle_reason_status = idle_reason_status(reason);
    }

    #[cfg(test)]
    pub(super) fn idle_reason_status_text(&self) -> Option<&str> {
        self.idle_reason_status
            .as_ref()
            .map(|status| status.text.as_str())
    }

    pub(super) fn push_plain(&mut self, line: impl Into<String>) {
        self.history.push(HistoryEntry::Plain { line: line.into() });
    }

    /// Run one attention event (implementation note) through
    /// the pure decision layer and apply the result: in-TUI toast, optional
    /// terminal bell, optional desktop notification. Never blocks the event
    /// loop and never enters the model's context — these are user-facing only.
    ///
    /// The decision (classification + debounce + focus policy) is computed by
    /// [`crate::tui::attention::decide`], a pure function tested in isolation;
    /// this method only performs the side effects it asks for, each of which
    /// is failure-tolerant.
    pub(super) fn notify_attention(&mut self, event: crate::tui::attention::AttentionEvent) {
        self.apply_attention_decision(event, false, true, 1);
    }

    fn apply_attention_decision(
        &mut self,
        event: crate::tui::attention::AttentionEvent,
        persistent_toast: bool,
        show_toast: bool,
        waiting_count: usize,
    ) {
        use crate::tui::attention::{NoticeKind, TitleDecision, decide};
        let now = Instant::now();
        // "Recently interacted" — a conservative focus proxy. Terminals can't
        // reliably report focus, so we treat a keystroke within the last few
        // seconds as "the user is here watching."
        let recently_interacted =
            now.duration_since(self.last_user_interaction) < RECENT_INTERACTION_WINDOW;
        let decision = decide(
            event,
            &self.attention,
            recently_interacted,
            waiting_count,
            now,
            &mut self.attention_state,
        );
        if decision.is_noop() {
            return;
        }
        if show_toast && let Some((text, kind)) = decision.toast {
            let toast_kind = match kind {
                NoticeKind::Info => ToastKind::Info,
                NoticeKind::Success => ToastKind::Success,
                NoticeKind::Error => ToastKind::Error,
            };
            self.toast = Some(Toast {
                text: text.to_string(),
                kind: toast_kind,
                expires_at: Instant::now() + TOAST_TTL,
                persistent: persistent_toast,
            });
        }
        if decision.bell {
            ring_terminal_bell();
        }
        if decision.desktop {
            post_desktop_notification(event.toast_text());
        }
        match decision.title {
            TitleDecision::Set(title) => self.set_terminal_title_marker(&title),
            TitleDecision::Clear => self.clear_terminal_title_marker(),
            TitleDecision::Unchanged => {}
        }
    }

    fn raise_attention_interrupt(
        &mut self,
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
        kind: AttentionInterruptKind,
        pending_count: usize,
    ) {
        let event = kind.event();
        let state = AttentionInterruptState {
            interrupt_id,
            kind,
            pending: true,
            pending_count,
            next_renudge_at: Instant::now() + crate::tui::attention::RENUDGE_INTERVAL,
        };
        let foreground = self.current_session_id() == Some(session_id);
        if foreground {
            self.attention_interrupt = Some(state);
        } else {
            self.background_attention_interrupts
                .insert(session_id, state);
        }
        let visible = foreground && self.foreground_interrupt_visible();
        self.apply_attention_decision(event, !visible, !visible, self.attention_waiting_count());
    }

    fn resolve_attention_interrupt(&mut self) {
        self.attention_interrupt = None;
        self.refresh_attention_interrupt_surfaces();
    }

    fn resolve_attention_interrupt_for(
        &mut self,
        session_id: uuid::Uuid,
        interrupt_id: uuid::Uuid,
    ) {
        if self.current_session_id() == Some(session_id)
            && self
                .attention_interrupt
                .as_ref()
                .is_some_and(|state| state.interrupt_id == interrupt_id)
        {
            self.attention_interrupt = None;
        }
        self.background_attention_interrupts
            .retain(|sid, state| *sid != session_id || state.interrupt_id != interrupt_id);
        self.refresh_attention_interrupt_surfaces();
    }

    fn refresh_attention_interrupt_surfaces(&mut self) {
        let foreground_visible = self.foreground_interrupt_visible();
        let persistent_toast_needed = !self.background_attention_interrupts.is_empty()
            || (self.attention_interrupt.is_some() && !foreground_visible);
        let Some(kind) = self
            .attention_interrupt
            .as_ref()
            .map(|state| state.kind)
            .or_else(|| {
                self.background_attention_interrupts
                    .values()
                    .next()
                    .map(|state| state.kind)
            })
        else {
            if self.toast.as_ref().is_some_and(|toast| toast.persistent) {
                self.toast = None;
            }
            self.clear_terminal_title_marker();
            return;
        };
        if !persistent_toast_needed && self.toast.as_ref().is_some_and(|toast| toast.persistent) {
            self.toast = None;
        }
        self.apply_attention_decision(kind.event(), true, false, self.attention_waiting_count());
    }

    fn foreground_interrupt_visible(&self) -> bool {
        self.question_dialog.is_some() && !self.overlay.is_open() && self.keys_overlay.is_none()
    }

    fn attention_waiting_count(&self) -> usize {
        let foreground_count = self
            .attention_interrupt
            .as_ref()
            .filter(|state| state.pending)
            .map(|state| state.pending_count.saturating_add(1))
            .unwrap_or(0);
        foreground_count
            + self
                .background_attention_interrupts
                .values()
                .filter(|state| state.pending)
                .map(|state| state.pending_count.saturating_add(1))
                .sum::<usize>()
    }

    fn update_background_attention_interrupt(
        &mut self,
        session_id: uuid::Uuid,
        active_interrupt_id: Option<uuid::Uuid>,
        pending_count: usize,
    ) {
        match active_interrupt_id {
            Some(active) => {
                if let Some(state) = self.background_attention_interrupts.get_mut(&session_id) {
                    state.interrupt_id = active;
                    state.pending_count = pending_count;
                }
            }
            None => {
                self.background_attention_interrupts.remove(&session_id);
            }
        }
        self.refresh_attention_interrupt_surfaces();
    }

    fn update_foreground_attention_interrupt(
        &mut self,
        active_interrupt_id: Option<uuid::Uuid>,
        pending_count: usize,
    ) {
        match (self.question_dialog.as_mut(), active_interrupt_id) {
            (Some(dialog), Some(active)) if dialog.interrupt_id() == active => {
                dialog.set_pending_count(pending_count);
                if let Some(state) = self.attention_interrupt.as_mut() {
                    state.interrupt_id = active;
                    state.pending_count = pending_count;
                }
                self.refresh_attention_interrupt_surfaces();
            }
            (Some(_), None) => {
                self.question_dialog = None;
                self.resolve_attention_interrupt();
            }
            (Some(_), Some(_)) => {
                self.question_dialog = None;
                self.resolve_attention_interrupt();
            }
            _ => {}
        }
    }

    fn tick_attention_interrupt(&mut self) -> bool {
        let now = Instant::now();
        let mut nudge = None;
        let foreground_visible = self.foreground_interrupt_visible();
        if let Some(state) = self.attention_interrupt.as_mut()
            && state.pending
            && now >= state.next_renudge_at
        {
            state.next_renudge_at = now + crate::tui::attention::RENUDGE_INTERVAL;
            nudge = Some((state.kind, !foreground_visible, !foreground_visible));
        }
        if nudge.is_none()
            && let Some(state) = self
                .background_attention_interrupts
                .values_mut()
                .find(|state| state.pending && now >= state.next_renudge_at)
        {
            state.next_renudge_at = now + crate::tui::attention::RENUDGE_INTERVAL;
            nudge = Some((state.kind, true, true));
        }
        let Some((kind, persistent_toast, show_toast)) = nudge else {
            return false;
        };
        self.apply_attention_decision(
            kind.event(),
            persistent_toast,
            show_toast,
            self.attention_waiting_count(),
        );
        true
    }

    fn set_terminal_title_marker(&mut self, title: &str) {
        if !self.attention.title {
            return;
        }
        if !self.terminal_title.stack_pushed {
            emit_terminal_title_sequence(&crate::tui::attention::terminal_title_marker_escapes(
                title,
            ));
            self.terminal_title.stack_pushed = true;
            self.terminal_title
                .pushed_for_cleanup
                .store(true, Ordering::SeqCst);
        } else {
            emit_terminal_title_sequence(&crate::tui::attention::terminal_title_set_escapes(title));
        }
        self.terminal_title.active = true;
    }

    fn clear_terminal_title_marker(&mut self) {
        if !self.terminal_title.active {
            return;
        }
        emit_terminal_title_sequence(&crate::tui::attention::terminal_title_restore_escapes(
            self.terminal_title.stack_pushed,
        ));
        self.terminal_title.active = false;
        self.terminal_title.stack_pushed = false;
        self.terminal_title
            .pushed_for_cleanup
            .store(false, Ordering::SeqCst);
    }

    /// Drop the toast if it has expired. Called once per event-loop
    /// tick so a toast left untouched for 3 seconds cleans itself
    /// up without needing a new event to fire.
    pub(super) fn tick_toast(&mut self) -> bool {
        if let Some(toast) = &self.toast
            && !toast.persistent
            && Instant::now() > toast.expires_at
        {
            self.toast = None;
            return true;
        }
        false
    }

    /// Handle a ctrl+c press (GOALS §3a). Single press interrupts a
    /// running agent (never quits); a second press within
    /// [`CTRL_C_EXIT_WINDOW`] of the previous exits. Returns `true` to
    /// exit the TUI (the event loop breaks). Drives the double-press
    /// state machine via the pure [`decide_ctrl_c`] unit, sends the
    /// daemon `CancelTurn` on an interrupt, and shows the transient exit
    /// hint via the existing toast mechanism.
    pub(super) fn handle_ctrl_c(&mut self) -> bool {
        let (action, new_armed) = decide_ctrl_c(
            Instant::now(),
            self.ctrl_c_armed_at,
            CTRL_C_EXIT_WINDOW,
            self.busy,
        );
        self.ctrl_c_armed_at = new_armed;
        match action {
            CtrlCAction::Exit => true,
            CtrlCAction::ArmAndInterrupt => {
                self.interrupt_agent();
                self.end_working_span();
                // A ctrl+c cancels the whole working span the user is looking
                // at — including any messages they queued *during* it (typed +
                // submitted while the turn was in flight). The daemon discards
                // those un-dispatched queued messages on cancel so it returns
                // to idle rather than rolling straight into the next one; clear
                // our mirror of the queue here so the pending rows above the
                // composer disappear in lockstep and don't masquerade as still
                self.queue.clear();
                self.show_ctrl_c_hint();
                false
            }
            CtrlCAction::ArmOnly => {
                self.show_ctrl_c_hint();
                false
            }
        }
    }

    /// Send the daemon a `CancelTurn` for the attached session (GOALS
    /// §3a). Fire-and-forget over the runner's request channel — same
    /// path `/schedule cancel` uses. No-op (and harmless) when no runner is
    /// connected. The daemon aborts the in-flight inference and kills any
    /// running `bash` subprocess; the resulting `AgentIdle` clears `busy`.
    pub(super) fn interrupt_agent(&self) {
        self.send_daemon_request(crate::daemon::proto::Request::CancelTurn);
    }

    /// Show the transient "press ctrl+c again to exit" hint. Reuses the
    /// status-line toast; its TTL is the exit window so it disappears
    /// exactly when a second press would no longer exit.
    fn show_ctrl_c_hint(&mut self) {
        self.toast = Some(Toast {
            text: "Press ctrl+c again to exit".to_string(),
            kind: ToastKind::Info,
            expires_at: Instant::now() + CTRL_C_EXIT_WINDOW,
            persistent: false,
        });
    }

    /// Disarm the ctrl+c exit window once it has lapsed. Called once per
    /// event-loop tick so a lone press auto-resets to a fresh first press
    /// without needing another event. The hint toast self-expires on the
    /// same TTL via [`Self::tick_toast`].
    pub(super) fn tick_ctrl_c_window(&mut self) -> bool {
        if let Some(armed) = self.ctrl_c_armed_at
            && Instant::now().duration_since(armed) > CTRL_C_EXIT_WINDOW
        {
            self.ctrl_c_armed_at = None;
            return true;
        }
        false
    }

    /// Flip `tui.mouse_capture` on disk, push/pop the live terminal
    /// state, and return a status line for the chat log. Used by the
    /// `/mouse` slash command (T8.c). Save errors degrade gracefully:
    /// we still flip the live state and report the error in the
    /// status line so the user knows the change isn't persistent.
    /// Toggle the *live* mouse-capture state and surface a toast.
    /// `/mouse` is intentionally non-persistent — useful for "try
    /// capture off for one operation" without affecting the
    /// configured default for the next session. The persistent
    /// toggle lives in `/settings → ui`.
    pub(super) fn toggle_mouse_capture_inline(&mut self) {
        let new_value = !self.mouse_capture;
        let exec_ok = if new_value {
            enable_mouse_capture_with_motion().is_ok()
        } else {
            disable_mouse_capture_with_motion().is_ok()
        };
        if exec_ok {
            self.mouse_capture = new_value;
            if !new_value {
                self.hovered_affordance = None;
            }
            let state = if new_value { "on" } else { "off" };
            self.show_toast(
                format!("/mouse: capture {state} (this session only)"),
                ToastKind::Info,
            );
        } else {
            self.show_toast(
                "/mouse: terminal rejected the capture toggle",
                ToastKind::Error,
            );
        }
    }

    /// Pick up a pending mouse-capture toggle from the settings dialog
    /// (UI page) and push/pop the crossterm capture state to match.
    /// The setting itself is persisted by the dialog's save path; this
    /// just keeps the live terminal state in sync.
    pub(super) fn sync_mouse_capture_from_dialog(&mut self) {
        let Some(want) = self.dialog.take_pending_mouse_capture() else {
            return;
        };
        self.set_mouse_capture_live(want);
    }

    fn set_mouse_capture_live(&mut self, want: bool) {
        if want == self.mouse_capture {
            return;
        }
        let res = if want {
            enable_mouse_capture_with_motion()
        } else {
            disable_mouse_capture_with_motion()
        };
        if res.is_ok() {
            self.mouse_capture = want;
            if !want {
                self.hovered_affordance = None;
                self.hovered_suggestion = None;
                self.link_registry.clear_hover();
            }
        }
    }

    pub(super) fn drain_fetch_progress(&mut self) -> bool {
        let drained: Vec<String> = match self.fetch_models_progress.lock() {
            Ok(mut buf) if !buf.is_empty() => buf.drain(..).collect(),
            _ => return false,
        };
        let touches_config = drained
            .iter()
            .any(|l| l.contains("model(s)") || l.ends_with(": done"));
        for line in drained {
            if let Some(rest) = line.strip_prefix("/fetch-models: provider ")
                && line.contains(" provider model(s)")
                && let Some(provider) = rest.split_whitespace().next()
            {
                self.clear_auth_failures_for_provider(provider);
            }
            self.push_plain(line);
        }
        if touches_config {
            self.reload_launch_info();
        }
        true
    }

    /// Assemble the prediction input from the visible transcript: the
    /// trailing turns, each reduced to the user's message + the agent's
    /// final response text. Tool calls, diffs, subagent reports, plain
    /// notices, and reasoning are skipped — only [`HistoryEntry::User`]
    /// and [`HistoryEntry::Agent`] carry into a turn (the latter's `text`
    /// is the final response; `reasoning` is never included).
    ///
    /// A user message opens a turn; the next agent message closes it.
    /// Consecutive user messages (e.g. queued + folded) flatten into the
    /// most recent open turn's user text so the turn count stays faithful.
    /// `engine::predict::last_turns` then keeps only the last 3.
    pub(super) fn prediction_turns(&self) -> Vec<crate::engine::predict::PredictionTurn> {
        turns_from_history(&self.history)
    }

    /// Kick off the eager next-message prediction for the current turn
    /// (implementation note). Short-circuits before any
    /// utility call when the setting is `off`, when there's no agent
    /// response to predict from (fresh session), or when no provider
    /// config can be loaded. The result lands in `prediction_result`
    /// tagged with the turn it belongs to; `drain_prediction` adopts it.
    pub(super) fn spawn_prediction(&mut self) {
        let mode = self.predict_setting;
        if !mode.is_enabled() {
            return;
        }
        if self.daemon_draining {
            return;
        }
        let turns = self.prediction_turns();
        // Nothing to predict yet (no agent final response) → no call.
        if turns.is_empty() || turns.iter().all(|t| t.agent.trim().is_empty()) {
            return;
        }
        let turn_id = self.prediction_state.turn();
        let cwd = self.launch.cwd.clone();
        let slot = Arc::clone(&self.prediction_result);
        tokio::spawn(async move {
            let (extended, providers) = crate::auto_title::load_configs_for(&cwd);
            // Build the same non-bypassable redaction table the driver uses
            // (GOALS §7) so the prediction prompt is scrubbed before send.
            let redactor = match crate::redact::RedactionTable::build(&extended.redact, &cwd) {
                Ok(r) => Arc::new(r),
                Err(e) => {
                    tracing::debug!(error = %e, "predict: redaction table build failed; no ghost");
                    return;
                }
            };
            let trusted_only = Arc::new(std::sync::atomic::AtomicBool::new(extended.trusted_only));
            let text = crate::engine::predict::predict(
                &turns,
                mode,
                &extended,
                &providers,
                redactor,
                trusted_only,
            )
            .await;
            if let Ok(mut guard) = slot.lock() {
                *guard = Some((turn_id, text));
            }
        });
    }

    /// Adopt a completed async prediction. Runs each tick. Discards a
    /// result tagged with a stale turn (a newer turn started) or one that
    /// arrives after the user began typing (box non-empty) —
    /// appear-once-ready, never pop in over active input. On a usable
    /// result for the current empty turn, caches it and builds the ghost.
    pub(super) fn drain_prediction(&mut self) -> bool {
        let drained = match self.prediction_result.lock() {
            Ok(mut slot) => slot.take(),
            Err(_) => return false,
        };
        let Some((turn_id, text)) = drained else {
            return false;
        };
        let long_mode = matches!(
            self.predict_setting,
            crate::config::extended::PredictNextMessage::Long
        );
        self.prediction_state
            .on_result(turn_id, text, long_mode, self.composer.is_empty());
        true
    }

    pub(super) fn drain_async_actions(&mut self) -> bool {
        let results = self.async_actions.drain_completed();
        let changed = !results.is_empty();
        let oauth_completed = results.iter().any(|result| {
            matches!(
                result.kind,
                AsyncActionKind::Internal("oauth.codex.poll" | "oauth.grok.complete")
            )
        });
        for result in results {
            self.apply_async_action_result(result);
        }
        // OAuth completion writes credentials asynchronously while its dialog
        // remains open. Fingerprint reconciliation is deliberately performed
        // after applying the result; failed/cancelled flows leave the stored
        // fingerprint unchanged and therefore retain the annotation.
        if oauth_completed {
            self.clear_changed_provider_auth_failures();
        }
        changed
    }

    fn apply_async_action_result(&mut self, result: AsyncActionResult) {
        match result.kind {
            AsyncActionKind::DaemonRpc("sessions.list") => {
                let mut live_ids = None;
                let mut preview_request = None;
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::Sessions(sessions)) => Ok(sessions),
                        Ok(_) => Err("unexpected daemon response".to_string()),
                        Err(e) => Err(e),
                    };
                    let ids = pane.apply_sessions_result(payload);
                    if !ids.is_empty() {
                        live_ids = Some(ids);
                    }
                    if pane.is_preview_enabled()
                        && let Some(crate::tui::sessions_pane::SessionsOutcome::LoadPreview {
                            session_id,
                            before_seq,
                        }) = pane.ensure_preview_for_selection()
                    {
                        preview_request = Some((session_id, before_seq));
                    }
                }
                if let Some(ids) = live_ids {
                    self.start_sessions_live_status_action(ids);
                }
                if let Some((session_id, before_seq)) = preview_request {
                    self.start_sessions_preview_action(session_id, before_seq);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.live") => {
                if let Overlay::Sessions(pane) = &mut self.overlay
                    && let Ok(AsyncActionPayload::SessionLiveStatus(live)) = result.payload
                {
                    pane.apply_live_status(live);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.preview") => {
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    match result.payload {
                        Ok(AsyncActionPayload::SessionMessages {
                            session_id,
                            before_seq,
                            messages,
                            has_more,
                        }) => pane.apply_preview_result(
                            session_id,
                            before_seq,
                            Ok((messages, has_more)),
                        ),
                        Err(error) => {
                            if let Some((session_id, before_seq)) = pane.take_preview_load() {
                                pane.apply_preview_result(session_id, before_seq, Err(error));
                            }
                        }
                        Ok(_) => {}
                    }
                }
            }
            AsyncActionKind::DaemonRpc("guidance.estimate") => {
                if let Ok(AsyncActionPayload::GuidanceEstimate(estimate)) = result.payload {
                    self.guidance_estimate = Some(estimate);
                }
            }
            AsyncActionKind::Internal("startup.guidance.estimate") => {
                if let Ok(AsyncActionPayload::StartupGuidanceEstimate {
                    cwd,
                    active_model,
                    estimate,
                }) = result.payload
                {
                    self.apply_startup_guidance_estimate(cwd, active_model, estimate);
                }
            }
            AsyncActionKind::Refresh("container.availability") => {
                if let Ok(AsyncActionPayload::ContainerAvailability(availability)) = result.payload
                {
                    self.container_availability = availability;
                }
            }
            AsyncActionKind::Internal("startup.remote_disclosures") => {
                if let Ok(AsyncActionPayload::RemoteDisclosures { org, connector }) = result.payload
                {
                    self.org_sync_disclosure = org;
                    self.connector_disclosure = connector;
                }
            }
            AsyncActionKind::Refresh("provider.usage") => match result.payload {
                Ok(AsyncActionPayload::ProviderUsage(rows)) => {
                    self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::open(rows));
                }
                Ok(_) => {
                    self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::error(
                        "unexpected usage response".to_string(),
                    ));
                }
                Err(e) => {
                    self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::error(e));
                }
            },
            AsyncActionKind::Internal("paste.token_count") => match result.payload {
                Ok(AsyncActionPayload::PasteTokenCount { block_id, tokens }) => {
                    self.apply_paste_token_count(block_id, tokens);
                }
                Ok(_) => {
                    tracing::debug!("paste token count returned unexpected payload");
                }
                Err(e) => {
                    tracing::debug!(error = %e, "paste token count failed");
                }
            },
            AsyncActionKind::DaemonRpc("resources.snapshot") => {
                if let Overlay::Resources(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::ResourceSnapshot(snapshot)) => Ok(snapshot),
                        Ok(_) => Err("unexpected daemon response".to_string()),
                        Err(e) => Err(e),
                    };
                    pane.apply_snapshot_result(payload);
                }
            }
            AsyncActionKind::DaemonRpc("resources.promote") => match result.payload {
                Ok(AsyncActionPayload::PromoteResource {
                    status,
                    message,
                    snapshot,
                }) => {
                    if let Overlay::Resources(pane) = &mut self.overlay {
                        pane.apply_snapshot_result(Ok(snapshot));
                    }
                    let kind = match status {
                        crate::daemon::proto::ResourcePromoteStatus::Promoted => ToastKind::Success,
                        crate::daemon::proto::ResourcePromoteStatus::NotQueued
                        | crate::daemon::proto::ResourcePromoteStatus::NotFound => ToastKind::Info,
                        crate::daemon::proto::ResourcePromoteStatus::Disabled => ToastKind::Warning,
                    };
                    self.show_toast(message, kind);
                }
                Ok(_) => {
                    self.show_toast("/resources: unexpected daemon response", ToastKind::Error)
                }
                Err(e) => self.show_toast(format!("/resources: {e}"), ToastKind::Error),
            },
            AsyncActionKind::DaemonRpc("rename") => match result.payload {
                Ok(AsyncActionPayload::Text(title)) => {
                    self.push_plain(format!("Renamed session to `{title}`"));
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/rename: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/rename: {e}"),
                }),
            },
            AsyncActionKind::Internal("rename.auto") => match result.payload {
                Ok(AsyncActionPayload::Text(title)) => {
                    self.push_plain(format!("Renamed session to `{title}`"));
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/rename: unexpected title result".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/rename: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("note") => match result.payload {
                Ok(AsyncActionPayload::NoteRecorded { text }) => {
                    self.history.push(HistoryEntry::UserNote {
                        text,
                        timestamp: chrono::Local::now(),
                    });
                    self.chat_scroll_offset = 0;
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/note: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/note: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("subagent.steer") => match result.payload {
                Ok(AsyncActionPayload::DelegationSteer(result)) => {
                    self.apply_subagent_steer_result(result);
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "subagent steer: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("subagent steer: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("fork.create") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    session_id,
                    short_id,
                    seed_composer,
                    ..
                }) => {
                    self.apply_fork_created(parent_session_id, session_id, short_id, seed_composer);
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/fork: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/fork: could not fork: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("side.start") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    socket,
                    session_id,
                    short_id,
                    ..
                }) => {
                    self.apply_side_created(parent_session_id, socket, session_id, short_id);
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/side: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/side: could not fork: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("side.discard") => {
                if let Err(e) = result.payload {
                    tracing::warn!(error = %e, "discarding ephemeral side session failed; boot sweep will reclaim it");
                }
            }
            AsyncActionKind::Blocking("local.command") => match result.payload {
                Ok(AsyncActionPayload::LocalCommand {
                    label,
                    raw_output,
                    failed,
                    git_args,
                }) => {
                    self.apply_local_command_result(label, raw_output, failed, git_args);
                }
                Ok(_) => self.push_plain("local command: unexpected async response".to_string()),
                Err(e) => self.push_plain(format!("local command: {e}")),
            },
            AsyncActionKind::Refresh("display.daemon.probe") => match result.payload {
                Ok(AsyncActionPayload::DaemonProbe { cwd, status }) => {
                    self.apply_display_daemon_probe_result(cwd, status);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "display daemon probe failed");
                }
            },
            AsyncActionKind::Internal("oauth.codex.begin") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthCodexBegin(login)) => Ok(login),
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_begin(OAuthProvider::Codex, OAuthBeginResult::Device(payload));
            }
            AsyncActionKind::Internal("oauth.codex.poll") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthCodexComplete { logged_in }) => Ok(logged_in),
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_complete(OAuthProvider::Codex, payload);
            }
            AsyncActionKind::Internal("oauth.grok.begin") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthGrokBegin { login }) => {
                        let settings::GrokBrowserStart { begin, listener } =
                            settings::prepare_grok_browser_start(
                                login,
                                settings::OAuthEffects::production(),
                                crate::auth::xai_oauth::CALLBACK_PORT,
                            );
                        if let Some(listener) = listener {
                            let listener_login = begin.login.clone();
                            self.async_actions.start(
                                AsyncActionKind::Internal("oauth.grok.complete"),
                                AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                                async move {
                                    crate::auth::xai_oauth::complete_local_callback_login(
                                        listener_login,
                                        listener,
                                    )
                                    .await
                                    .map(|_| AsyncActionPayload::OAuthGrokComplete {
                                        logged_in: true,
                                    })
                                    .map_err(|e| e.to_string())
                                },
                            );
                        }
                        Ok(begin)
                    }
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_begin(OAuthProvider::Grok, OAuthBeginResult::Browser(payload));
            }
            AsyncActionKind::Internal("oauth.grok.complete") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthGrokComplete { logged_in }) => Ok(logged_in),
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_complete(OAuthProvider::Grok, payload);
            }
            _ => self.completed_async_actions.push(result),
        }
    }

    pub(super) fn drain_oauth_actions(&mut self) {
        while let Some(action) = self.dialog.take_oauth_action() {
            match (action.provider, action.op) {
                (OAuthProvider::Codex, OAuthFlowOp::Begin) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.codex.begin"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.codex")),
                        async {
                            crate::auth::codex_oauth::begin_device_code_login()
                                .await
                                .map(AsyncActionPayload::OAuthCodexBegin)
                                .map_err(|e| e.to_string())
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Poll(login)) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.codex.poll"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.codex")),
                        async move {
                            crate::auth::codex_oauth::complete_device_code_login(login)
                                .await
                                .map(|_| AsyncActionPayload::OAuthCodexComplete { logged_in: true })
                                .map_err(|e| e.to_string())
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Cancel) => {
                    self.async_actions
                        .abort_key(&AsyncActionKey::new("oauth.codex"));
                }
                (OAuthProvider::Grok, OAuthFlowOp::Begin) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.grok.begin"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                        async move {
                            let login = crate::auth::xai_oauth::begin_manual_login()
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok(AsyncActionPayload::OAuthGrokBegin { login })
                        },
                    );
                }
                (OAuthProvider::Grok, OAuthFlowOp::Complete { login, input }) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.grok.complete"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                        async move {
                            crate::auth::xai_oauth::complete_manual_login(login, &input)
                                .await
                                .map(|_| AsyncActionPayload::OAuthGrokComplete { logged_in: true })
                                .map_err(|e| e.to_string())
                        },
                    );
                }
                (OAuthProvider::Grok, OAuthFlowOp::Cancel) => {
                    self.async_actions
                        .abort_key(&AsyncActionKey::new("oauth.grok"));
                }
                (OAuthProvider::Codex, OAuthFlowOp::Complete { .. })
                | (OAuthProvider::Grok, OAuthFlowOp::Poll(_)) => {}
            }
        }
    }

    fn start_resources_snapshot_action(&mut self) {
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("resources.snapshot"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("resources.snapshot")),
            || match crate::tui::agent_runner::resource_snapshot_blocking()? {
                crate::daemon::proto::Response::ResourceSnapshot { snapshot } => {
                    Ok(AsyncActionPayload::ResourceSnapshot(snapshot))
                }
                other => Err(format!("unexpected resource_snapshot response: {other:?}")),
            },
        );
    }

    fn start_resource_promote_action(&mut self, request_id: String) {
        let session_id = self.current_session_id();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("resources.promote"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!(
                "resources.promote:{request_id}"
            ))),
            move || match crate::tui::agent_runner::promote_resource_blocking(
                request_id, session_id,
            )? {
                crate::daemon::proto::Response::PromoteResourceResult {
                    status,
                    message,
                    snapshot,
                } => Ok(AsyncActionPayload::PromoteResource {
                    status,
                    message,
                    snapshot,
                }),
                other => Err(format!("unexpected promote_resource response: {other:?}")),
            },
        );
    }

    pub(super) fn start_resources_outcome(
        &mut self,
        outcome: crate::tui::resources_pane::ResourcesOutcome,
    ) {
        match outcome {
            crate::tui::resources_pane::ResourcesOutcome::Close => self.overlay = Overlay::None,
            crate::tui::resources_pane::ResourcesOutcome::Refresh => {
                self.start_resources_snapshot_action();
            }
            crate::tui::resources_pane::ResourcesOutcome::Promote(request_id) => {
                self.start_resource_promote_action(request_id);
            }
        }
    }

    fn sessions_daemon_socket(&self) -> Option<&Path> {
        self.agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok().map(|runner| runner.socket.as_path()))
            .or(self.startup_background.daemon_socket.as_deref())
    }

    pub(super) fn start_sessions_list_action(&mut self) {
        let Overlay::Sessions(pane) = &self.overlay else {
            return;
        };
        let (project_id, parent) = pane.root_request();
        let socket = self.sessions_daemon_socket().map(Path::to_path_buf);
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.list"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.list")),
            move || {
                let socket = socket
                    .ok_or_else(|| "daemon socket unavailable for sessions.list".to_string())?;
                crate::tui::agent_runner::list_sessions_blocking(&socket, project_id, parent)
                    .map(AsyncActionPayload::Sessions)
            },
        );
    }

    fn start_sessions_live_status_action(&mut self, ids: Vec<uuid::Uuid>) {
        let socket = self.sessions_daemon_socket().map(Path::to_path_buf);
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.live"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.live")),
            move || {
                let socket = socket
                    .ok_or_else(|| "daemon socket unavailable for sessions.live".to_string())?;
                Ok(AsyncActionPayload::SessionLiveStatus(
                    crate::tui::agent_runner::session_live_status_blocking(&socket, ids),
                ))
            },
        );
    }

    pub(super) fn start_sessions_preview_action(
        &mut self,
        session_id: uuid::Uuid,
        before_seq: Option<i64>,
    ) {
        let socket = self.sessions_daemon_socket().map(Path::to_path_buf);
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.preview"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.preview")),
            move || {
                let socket = socket
                    .ok_or_else(|| "daemon socket unavailable for sessions.preview".to_string())?;
                let (messages, has_more) =
                    crate::tui::agent_runner::read_session_messages_blocking(
                        &socket, session_id, before_seq, 50,
                    )?;
                Ok(AsyncActionPayload::SessionMessages {
                    session_id,
                    before_seq,
                    messages,
                    has_more,
                })
            },
        );
    }

    fn start_provider_usage_action(&mut self, args: String) {
        let filter = args.split_whitespace().next().map(str::to_string);
        let cwd = self.launch.cwd.clone();
        self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::loading());
        self.async_actions.start(
            AsyncActionKind::Refresh("provider.usage"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("provider.usage")),
            async move {
                let cfg = crate::secret_ref::load_effective(&cwd);
                crate::providers::usage::probes::fetch_all_provider_usage(&cfg, filter.as_deref())
                    .await
                    .map(AsyncActionPayload::ProviderUsage)
                    .map_err(|e| e.to_string())
            },
        );
    }

    /// Reconcile the ghost with the composer's empty/non-empty state. Runs
    /// each tick after key handling: a non-empty box hides the ghost; a
    /// box cleared back to empty within the same turn restores the cached
    /// prediction's ghost — **without** a new utility call (the cache is
    /// reused). Never overwrites typed content.
    pub(super) fn sync_prediction_ghost(&mut self) {
        self.prediction_state.reconcile(self.composer.is_empty());
    }

    pub(super) fn sync_repo_status(&mut self) -> bool {
        if let Ok(guard) = self.repo_status.lock()
            && self.launch.repo_status != *guard
        {
            self.launch.repo_status = guard.clone();
            return true;
        }
        false
    }

    fn reset_session_live_state(&mut self) {
        self.queue.clear();
        self.pending = None;
        self.pending_render_cache = None;
        self.prunable_tokens = 0;
        self.elided_event_ids.clear();
        self.active_schedules.clear();
        self.pending_stop_confirm = None;
        self.chat_scroll_offset = 0;
        self.end_working_span();
        self.prediction_state.begin_turn();
        // prompt_history is shell-style across sessions; only the active
        // recall cursor and hidden draft belong to the outgoing session.
        self.prompt_history_cursor = 0;
        self.staged_draft = None;
        self.pending_git_blocks.clear();
        self.accepted_tags.clear();
        self.pending_edit_args.clear();
        self.pin_count = 0;
        self.pin_count_session = None;
        self.pinned_seqs_cache.clear();
        self.pinned_seqs_session = None;
    }

    fn cancel_outgoing_turn_if_busy(&self) {
        if self.busy {
            self.interrupt_agent();
        }
    }

    /// `/new` was invoked: clear chat history and drop the daemon-
    /// attached runner so the next user message opens a fresh session.
    /// In alt-screen mode the chat pane is the whole canvas, so the
    /// "fresh session" visual is simply an empty pane.
    pub(super) fn maybe_service_new_session(
        &mut self,
        terminal: &mut DefaultTerminal,
    ) -> Result<bool> {
        self.maybe_service_new_session_with_clear(|| terminal.clear().map_err(Into::into))
    }

    fn maybe_service_new_session_with_clear(
        &mut self,
        mut clear_terminal: impl FnMut() -> Result<()>,
    ) -> Result<bool> {
        if !self.pending_new_session {
            return Ok(false);
        }
        self.pending_new_session = false;

        self.cancel_outgoing_turn_if_busy();

        // `/new` from inside a side conversation: discard the ephemeral fork
        // first (no orphan), then proceed to open a fresh session. We don't
        // restore the main session's view — `/new` is clearing everything
        // anyway — but the discard must still fire and the chrome flag clear.
        if self.side_conversation.is_some() {
            self.end_side_conversation(false);
        }

        // Alt-screen mode: the chat pane is the whole canvas, and
        // there's no terminal scrollback to spill into. Clearing
        // history makes the chat pane empty — that's the "new
        // session" visual.
        self.finalize_pending();

        // Reset transcript state.
        self.history.clear();
        self.reset_session_live_state();
        self.clickable_rows.clear();
        self.box_rows.clear();
        self.hovered_affordance = None;
        self.hovered_control_chip = None;
        self.affordance_scroll_regions.clear();
        self.chat_row_meta.clear();
        self.chat_area = None;
        self.chat_text_grid.clear();
        self.chat_cont_rows.clear();
        self.selection = None;
        // Reload from disk in case settings changed.
        self.reload_launch_info();
        self.reload_tui_config();

        // Drop the runner so the next submit re-attaches the daemon
        // with `session_id: None`, opening a fresh session.
        self.agent_runner = None;
        self.reset_display_attach_backoff();
        // The fresh session is deferred-persistence until its first message
        // (session-id-display-and-lazy-persist).
        self.current_session_persisted = false;

        // Reset the autocomplete tally so the next attach re-seeds it
        // fresh (additive merge would otherwise double-count). The
        // daemon re-fetch picks up everything recorded this session.
        self.usage_models.clear();
        self.usage_slash.clear();
        self.usage_tags.clear();
        self.project_id = None;
        self.pending_usage.clear();
        // Clear the provider usage so the fresh-chat instruction-file
        // estimate re-triggers on the new (empty) session.
        self.last_usage = None;
        self.estimate_at_last_usage = 0;

        // Repaint the cleared canvas on the next draw. `Terminal::clear`
        // invalidates ratatui's buffers on success, but crossterm may fail
        // its cursor-position probe. That UI cleanup must never abort the
        // already-completed fresh-session state transition.
        if let Err(error) = clear_terminal() {
            tracing::warn!(error = %error, "terminal clear after /new failed; continuing with redraw");
        }

        Ok(true)
    }

    fn run_external_editor_command(
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
        editor: &std::ffi::OsStr,
        path: &std::path::Path,
    ) -> Result<std::io::Result<std::process::ExitStatus>> {
        with_input_suspended(terminal_input, |_| {
            // Suspend ratatui's input handling for the editor invocation.
            // We disable the keyboard-enhancement flags / cursor styles
            // crossterm pushed for us, leave raw mode, and let the editor
            // own the TTY. Re-enable everything after it exits.
            use crossterm::terminal::{
                EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
            };
            let _ = crossterm::execute!(stdout(), LeaveAlternateScreen);
            let _ = disable_raw_mode();

            let status = std::process::Command::new(editor).arg(path).status();

            let _ = enable_raw_mode();
            let _ = crossterm::execute!(stdout(), EnterAlternateScreen);
            terminal.clear()?;

            Ok(status)
        })
    }

    /// Ctrl+G was pressed: pop the composer text out into `$EDITOR`,
    /// then reload whatever the user wrote back into the buffer. Quits
    /// raw mode for the duration so the editor owns the terminal.
    pub(super) fn maybe_service_external_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<()> {
        if !self.pending_external_edit {
            return Ok(());
        }
        self.pending_external_edit = false;

        let Some(editor) = std::env::var_os("EDITOR") else {
            // Defensive — we re-check here because env state can shift
            // between the keypress and now. The handler already
            // surfaced a toast when EDITOR was unset, so just bail.
            return Ok(());
        };

        // Stash the buffer in a random Markdown tempfile so editor syntax
        // detection still works without a predictable shared-temp path.
        let mut temp = match new_external_editor_tempfile() {
            Ok(temp) => temp,
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: failed to create temp file: {e}"),
                });
                return Ok(());
            }
        };
        let editor_text = self.paste_registry.expand_editor(self.composer.text());
        let retained_images = self.paste_registry.image_payloads_by_number();
        if let Err(e) = temp.write_all(editor_text.as_bytes()) {
            self.history.push(HistoryEntry::CommandError {
                line: format!("editor: failed to write temp file: {e}"),
            });
            return Ok(());
        }
        if let Err(e) = temp.flush() {
            self.history.push(HistoryEntry::CommandError {
                line: format!("editor: failed to flush temp file: {e}"),
            });
            return Ok(());
        }
        let path = temp.path().to_path_buf();

        let status = Self::run_external_editor_command(terminal, terminal_input, &editor, &path)?;

        match status {
            Ok(s) if s.success() => match std::fs::read_to_string(&path) {
                Ok(text) => {
                    // Drop a single trailing newline — most editors
                    // write one even when the user didn't add one.
                    let text = text.strip_suffix('\n').unwrap_or(&text).to_string();
                    let rebuilt = crate::tui::paste::PasteRegistry::rebuild_from_editor(
                        &text,
                        &retained_images,
                        crate::tokens::count,
                    );
                    self.composer.set(rebuilt.buffer);
                    self.paste_registry = rebuilt.registry;
                }
                Err(e) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("editor: failed to read temp file back: {e}"),
                    });
                }
            },
            Ok(s) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: exited with {s}"),
                });
            }
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("editor: invoking `{}`: {e}", editor.to_string_lossy()),
                });
            }
        }
        Ok(())
    }

    /// The `/settings → Agents` page asked to edit an agent file in
    /// `$EDITOR` (implementation note). The page can't
    /// suspend the TUI from inside a key handler, so it records the path
    /// and we service it here: suspend ratatui, run `$EDITOR <file>`, then
    /// hand the outcome back so the page re-reads + re-parses the file
    /// (surfacing a parse error inline, never silently accepting a broken
    /// agent). External-process failure leaves the file untouched and is
    /// reported inline. Reuses the same raw-mode/alt-screen toggle dance as
    /// the composer's Ctrl+G handoff.
    pub(super) fn maybe_service_agent_file_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<()> {
        let Some(path) = self.dialog.take_pending_agent_edit() else {
            return Ok(());
        };

        let Some(editor) = std::env::var_os("EDITOR") else {
            // Env shifted between the page deciding to defer and now; the
            // page only defers when EDITOR was set, so this is defensive.
            self.dialog
                .finish_agent_edit(Some("$EDITOR is no longer set".to_string()));
            return Ok(());
        };

        let status = Self::run_external_editor_command(terminal, terminal_input, &editor, &path)?;

        let editor_error = match status {
            Ok(s) if s.success() => None,
            Ok(s) => Some(format!("editor exited with {s} — file left unchanged")),
            Err(e) => Some(format!(
                "invoking `{}`: {e} — file left unchanged",
                editor.to_string_lossy()
            )),
        };
        self.dialog.finish_agent_edit(editor_error);
        Ok(())
    }

    /// A category setting requested a `$EDITOR` round trip against a private
    /// tempfile. The dialog owns the temp path and validation; the app only
    /// suspends the terminal and reports process success/failure.
    pub(super) fn maybe_service_category_setting_edit(
        &mut self,
        terminal: &mut DefaultTerminal,
        terminal_input: &mut TerminalInput,
    ) -> Result<()> {
        let Some(path) = self.dialog.take_pending_category_setting_edit() else {
            return Ok(());
        };

        let Some(editor) = std::env::var_os("EDITOR") else {
            self.dialog
                .finish_category_setting_edit(Some("$EDITOR is no longer set".to_string()));
            return Ok(());
        };

        let status = Self::run_external_editor_command(terminal, terminal_input, &editor, &path)?;
        let editor_error = match status {
            Ok(s) if s.success() => None,
            Ok(s) => Some(format!("editor exited with {s} - value left unchanged")),
            Err(e) => Some(format!(
                "invoking `{}`: {e} - value left unchanged",
                editor.to_string_lossy()
            )),
        };
        self.dialog.finish_category_setting_edit(editor_error);
        Ok(())
    }

    /// Open `$EDITOR` in an embedded pane (GOALS §1i). No-op if a pane
    /// is already open (one at a time). `side` is `Full` for the bare
    /// `/editor`, or a split side.
    pub(super) fn open_editor(&mut self, side: PaneSide) {
        self.open_editor_target(side, None);
    }

    pub(super) fn open_editor_target(&mut self, side: PaneSide, target: Option<&str>) {
        if self.pane.is_some() {
            return;
        }
        let Some(editor) = std::env::var_os("EDITOR") else {
            self.push_plain("/editor: no `$EDITOR` set".to_string());
            return;
        };
        let argv = match target {
            Some(path) => editor_argv_for_target(&editor, path),
            None => editor_argv_for_cwd(&editor, &self.launch.cwd),
        };
        if argv.is_empty() {
            self.history.push(HistoryEntry::CommandError {
                line: "/editor: `$EDITOR` is empty".to_string(),
            });
            return;
        }
        self.spawn_pane(crate::tui::pty::PaneKind::Editor, &argv, side);
    }

    /// Open `lazygit` fullscreen in an embedded pane (GOALS §1j).
    pub(super) fn open_lazygit(&mut self) {
        if self.pane.is_some() {
            return;
        }
        if !program_on_path("lazygit") {
            self.history.push(HistoryEntry::CommandError {
                line: "/lazygit: `lazygit` not found on `PATH`".to_string(),
            });
            return;
        }
        self.spawn_pane(
            crate::tui::pty::PaneKind::Lazygit,
            &["lazygit".to_string()],
            PaneSide::Full,
        );
    }

    /// Spawn a pane. Initial PTY size is a placeholder corrected by the
    /// first render's resize. Focus moves to the new pane.
    fn spawn_pane(&mut self, kind: crate::tui::pty::PaneKind, argv: &[String], side: PaneSide) {
        match crate::tui::pty::PtyPane::spawn(kind, argv, &self.launch.cwd, 24, 80) {
            Ok(pane) => {
                self.pane = Some(pane);
                self.pane_side = side;
                self.pane_focused = true;
                self.dragging_divider = false;
            }
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("/{}: {e}", kind.label()),
                });
            }
        }
    }

    /// Close the open pane and return focus to the composer. `force`
    /// terminates a still-running child (Ctrl+X); otherwise the child
    /// has already exited and we just reap it (auto-close).
    pub(super) fn close_pane(&mut self, force: bool) {
        if let Some(mut pane) = self.pane.take() {
            if force {
                pane.terminate();
            } else {
                pane.reap();
            }
        }
        self.pane_focused = false;
        self.dragging_divider = false;
        self.pane_rect = None;
        self.divider = None;
    }

    /// Service the open pane once per event-loop tick: auto-close when
    /// the child has exited (GOALS §1i).
    pub(super) fn service_pane(&mut self) {
        let exited = self.pane.as_mut().is_some_and(|p| p.has_exited());
        if exited {
            self.close_pane(false);
        }
    }

    /// `!` shell mode (GOALS §1k): run a one-shot command via the shell,
    /// capture stdout+stderr, and render it locally. Never sent to the
    /// agent.
    pub(super) fn run_shell_command(&mut self, cmd: &str) {
        let cmd = cmd.trim();
        if cmd.is_empty() {
            return;
        }
        let cmd = cmd.to_string();
        let cwd = self.launch.cwd.clone();
        self.start_local_command_action(format!("! {cmd}"), None, move || {
            exec_capture_shell(&cmd, &cwd)
        });
    }

    /// `/git` (GOALS §1l): run `git <args>` locally, render it now, and
    /// buffer a `<git>` block (~2k-token cap) for the next user message.
    pub(super) fn run_git_command(&mut self, args: &str) {
        let args = args.trim();
        if args.is_empty() {
            self.push_plain("/git: usage `/git <args>` (e.g. `/git status`)".to_string());
            return;
        }
        let args = args.to_string();
        let cwd = self.launch.cwd.clone();
        self.start_local_command_action(format!("/git {args}"), Some(args.clone()), move || {
            exec_capture_git(&args, &cwd)
        });
    }

    fn start_local_command_action<F>(&mut self, label: String, git_args: Option<String>, work: F)
    where
        F: FnOnce() -> (String, bool) + Send + 'static,
    {
        self.push_plain(format!(
            "{label}: running (local command; cancellation unavailable)"
        ));
        self.chat_scroll_offset = 0;
        self.async_actions.start_blocking(
            AsyncActionKind::Blocking("local.command"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                let (raw_output, failed) = work();
                Ok(AsyncActionPayload::LocalCommand {
                    label,
                    raw_output,
                    failed,
                    git_args,
                })
            },
        );
    }

    fn apply_local_command_result(
        &mut self,
        label: String,
        raw_output: String,
        failed: bool,
        git_args: Option<String>,
    ) {
        let clean = strip_ansi(&raw_output);
        self.history.push(HistoryEntry::LocalCommand {
            label,
            output: cap_display_lines(&clean),
            failed,
        });
        self.chat_scroll_offset = 0;
        if let Some(args) = git_args {
            let capped = cap_tokens(&clean, GIT_AGENT_TOKEN_CAP);
            self.pending_git_blocks.push(format!(
                "<git cmd=\"{}\">\n{}\n</git>",
                xml_escape(&args),
                capped
            ));
        }
    }

    /// Resolve a closed `/init` existing-file prompt. `selected_id` is the
    /// chosen option id (or `None` on Esc/cancel). Update/overwrite
    /// dispatch the corresponding agent turn; cancel leaves the file
    /// untouched.
    fn resolve_init_choice(&mut self, pending: PendingInit, selected_id: Option<&str>) {
        let mode = match selected_id {
            Some("update") => crate::commands::init::InitMode::Update,
            Some("overwrite") => crate::commands::init::InitMode::Overwrite,
            _ => {
                self.push_plain(format!(
                    "/init: cancelled — `{}` left untouched",
                    pending.display
                ));
                return;
            }
        };
        let prompt = crate::commands::init::build_init_prompt(&pending.display, mode);
        self.dispatch_init_turn(&pending.display, prompt);
    }

    pub(super) fn pending_local_choice_matches(&self, interrupt_id: uuid::Uuid) -> bool {
        self.pending_local_choice
            .as_ref()
            .is_some_and(|choice| choice.interrupt_id() == interrupt_id)
    }

    pub(super) fn pending_local_choice_is_multi(&self) -> bool {
        self.pending_local_choice
            .as_ref()
            .is_some_and(LocalChoice::is_multi)
    }

    pub(super) fn resolve_local_choice(&mut self, selection: LocalChoiceSelection) {
        match self.pending_local_choice.take() {
            Some(LocalChoice::Init(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_init_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::PausedWork(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_paused_work_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::ResumeRepair(pending)) => {
                let LocalChoiceSelection::Single(selected) = selection else {
                    return;
                };
                self.resolve_resume_repair_choice(pending, selected.as_deref());
            }
            Some(LocalChoice::RedactionToggle(_)) => {
                let LocalChoiceSelection::Multi(selected) = selection else {
                    return;
                };
                self.resolve_redaction_toggle(selected.as_deref());
            }
            Some(LocalChoice::ModelComparison(_)) => {
                let LocalChoiceSelection::Multi(selected) = selection else {
                    return;
                };
                self.resolve_model_comparison_select(selected.as_deref());
            }
            None => {}
        }
    }

    /// Send an `/init` turn to the agent: render `/init <target>` as the
    /// user's turn (display side) and hand the full exploration+write
    /// instruction to the agent as the wire (wire/user split, GOALS §14).
    /// Reuses the runner input channel `submit_input` uses, including the
    /// working-span bookkeeping so an orphaned dispatch never hangs the
    /// indicator.
    fn dispatch_init_turn(&mut self, display: &str, wire: String) {
        self.chat_scroll_offset = 0;
        self.begin_working_span();
        let submission = crate::engine::message::UserSubmission::text(wire);
        self.dispatch_optimistic_user_submission(
            format!("/init {display}"),
            submission,
            "/init",
            true,
            &[],
        );
    }

    pub(super) fn dispatch_optimistic_user_submission(
        &mut self,
        display: String,
        mut submission: crate::engine::message::UserSubmission,
        error_prefix: &str,
        owns_working_span: bool,
        tag_expansions: &[crate::daemon::proto::TagExpansionMeta],
    ) -> DispatchOutcome {
        if submission.display_text.is_none() && submission.text != display {
            submission.display_text = Some(display.clone());
        }
        if submission.tag_expansions.is_empty() && !tag_expansions.is_empty() {
            submission.tag_expansions = tag_expansions.to_vec();
        }
        self.lock_pending_agent_switch_log();
        self.history.push(HistoryEntry::User {
            text: display,
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: None,
            preflight_pending: false,
            persist_failed: false,
        });
        self.push_tag_call_entries(tag_expansions);
        self.ensure_agent_runner();
        let outcome = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => match runner.input_tx.try_send(submission) {
                Ok(_) => {
                    self.current_session_persisted = true;
                    if owns_working_span {
                        self.fresh_queue_ack = FreshQueueAck::AwaitingAck;
                    }
                    DispatchOutcome::Sent
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => DispatchOutcome::QueueFull,
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    DispatchOutcome::DriverClosed
                }
            },
            Some(Err(_)) => DispatchOutcome::RunnerFailed,
            None => DispatchOutcome::NoRunner,
        };
        if outcome != DispatchOutcome::Sent {
            if owns_working_span {
                self.fresh_queue_ack = FreshQueueAck::None;
            }
            self.reconcile_failed_dispatch(outcome, error_prefix, tag_expansions.len());
        }
        if owns_working_span && outcome.span_orphaned() {
            self.end_working_span();
        }
        outcome
    }

    pub(super) fn reconcile_failed_dispatch(
        &mut self,
        outcome: DispatchOutcome,
        error_prefix: &str,
        optimistic_tag_entries: usize,
    ) {
        if let Some(idx) = self.history.iter().rposition(|entry| {
            matches!(
                entry,
                HistoryEntry::User {
                    seq: None,
                    persist_failed: false,
                    ..
                }
            )
        }) {
            for _ in 0..optimistic_tag_entries {
                if idx + 1 < self.history.len() {
                    self.history.remove(idx + 1);
                }
            }
            if let HistoryEntry::User {
                preflight_pending,
                persist_failed,
                ..
            } = &mut self.history[idx]
            {
                *preflight_pending = false;
                *persist_failed = true;
            }
        }
        self.history.push(HistoryEntry::CommandError {
            line: failed_dispatch_line(error_prefix, outcome),
        });
    }

    fn resolve_paused_work_choice(
        &mut self,
        pending: PendingPausedWork,
        selected_id: Option<&str>,
    ) {
        let request = match selected_id {
            Some("resume") => {
                self.push_plain("/resume: resuming paused daemon work.".to_string());
                crate::daemon::proto::Request::ResumePausedWork {
                    session_id: pending.session_id,
                }
            }
            Some("cancel") | None => {
                self.push_plain("/resume: cancelled paused daemon work.".to_string());
                crate::daemon::proto::Request::CancelPausedWork {
                    session_id: pending.session_id,
                }
            }
            Some(_) => return,
        };
        self.send_daemon_request(request);
    }

    fn show_goal_status(&mut self) {
        let Some(session_id) = self.launch.session_id else {
            self.push_plain("/goal: no active session. Usage: /goal <objective> | status | pause | resume | clear | edit".to_string());
            return;
        };
        match crate::db::Db::open_default().and_then(|db| {
            db.refresh_session_goal_usage(session_id)?;
            db.current_session_goal(session_id, false)
        }) {
            Ok(Some(goal)) => {
                let budget = goal
                    .token_budget
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "none".to_string());
                self.push_plain(format!(
                        "/goal: {} · {} · tokens {}/{} · subcommands: status, pause, resume, clear, edit",
                        goal.status.as_str(),
                        goal.objective,
                        goal.tokens_used,
                        budget
                    ));
            }
            Ok(None) => self.push_plain(
                "/goal: no goal. Usage: /goal <objective> | status | pause | resume | clear | edit"
                    .to_string(),
            ),
            Err(e) => self.history.push(HistoryEntry::CommandError {
                line: format!("/goal: {e:#}"),
            }),
        }
    }

    fn set_goal_status(&mut self, status: crate::db::session_goals::GoalStatus, label: &str) {
        let Some(session_id) = self.launch.session_id else {
            self.history.push(HistoryEntry::CommandError {
                line: format!("{label}: no active session."),
            });
            return;
        };
        match crate::db::Db::open_default()
            .and_then(|db| db.set_session_goal_status(session_id, status))
        {
            Ok(goal) => self.push_plain(format!("{label}: goal is now {}.", goal.status.as_str())),
            Err(e) => self.history.push(HistoryEntry::CommandError {
                line: format!("{label}: {e:#}"),
            }),
        }
    }

    fn dispatch_goal_turn(&mut self, display: &str, wire: String) {
        self.chat_scroll_offset = 0;
        self.begin_working_span();
        let submission = crate::engine::message::UserSubmission::text(wire);
        self.dispatch_optimistic_user_submission(
            format!("/goal {display}"),
            submission,
            "/goal",
            true,
            &[],
        );
    }

    /// Dispatch a user-issued skill slash command
    /// (implementation note): seed a deterministic `skill`
    /// tool call for `name` before the turn's inference and forward `args`
    /// (possibly empty) as the accompanying task input.
    ///
    /// `display` is the user-facing turn label (`/<name> args` for the bare
    /// form, `/skill <name> args` for the dispatcher). The seed itself rides
    /// in `UserSubmission::forced_skill`, so the harness — not the model —
    /// loads the skill body (priority #1). Reuses the runner-input dispatch
    /// `dispatch_init_turn` uses, including the working-span bookkeeping.
    fn dispatch_skill_invocation(&mut self, display: String, name: &str, args: &str) {
        self.chat_scroll_offset = 0;
        self.begin_working_span();
        let submission = crate::engine::message::UserSubmission {
            kind: crate::engine::message::UserSubmissionKind::User,
            text: args.trim().to_string(),
            display_text: None,
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: Some(name.to_string()),
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            queue_target: None,
        };
        self.dispatch_optimistic_user_submission(display, submission, "/skill", true, &[]);
    }

    /// The id of the session this client is attached to (live runner if
    /// connected, else the last-attached id from launch info). `None`
    /// before the first session exists. Same resolution `/rename` uses.
    pub(super) fn current_session_id(&self) -> Option<uuid::Uuid> {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => Some(runner.session_id),
            _ => self.launch.session_id,
        }
    }

    /// Job ids in `active_schedules` that belong to the current session, in the
    /// map's (stable, job-id) order. The single filter `/ps` and `/stop`
    /// share so the listed set, the cancel set, and the confirm count can
    /// never disagree. Empty when there's no current session or no jobs.
    pub(super) fn current_session_job_ids(&self) -> Vec<String> {
        match self.current_session_id() {
            Some(sid) => session_schedule_ids(&self.active_schedules, sid),
            None => Vec::new(),
        }
    }

    /// Send a `CancelSchedule` for one job over the runner's record channel —
    /// the same fire-and-forget path `/schedule cancel` uses. `cmd` is the
    /// command label for the rendered line.
    fn cancel_schedule(&mut self, job_id: &str, cmd: &str) {
        let sent = self.send_daemon_request(crate::daemon::proto::Request::CancelSchedule {
            job_id: job_id.to_string(),
        });
        let line = if sent {
            format!("{cmd}: cancel requested for `{job_id}`")
        } else {
            format!("{cmd}: no daemon connection — cannot cancel `{job_id}`")
        };
        self.push_plain(line);
    }

    /// Bare `/stop`: count the current-session jobs and arm the `[y/N]`
    /// confirm (mirrors `/prune`'s arm-then-commit). With zero jobs it
    /// says so and arms nothing.
    pub(super) fn arm_stop_confirm(&mut self) {
        let ids = self.current_session_job_ids();
        if ids.is_empty() {
            self.push_plain("No background jobs in this session.".to_string());
            self.pending_stop_confirm = None;
            return;
        }
        let n = ids.len();
        self.push_plain(format!("/stop: Stop {n} job(s) in this session? [y/N]"));
        self.pending_stop_confirm = Some(ids);
    }

    /// Commit an armed bare `/stop`: cancel every job captured at arm
    /// time. A job that already ended (no longer in `active_schedules`) is
    /// skipped silently — its strip entry is already gone.
    pub(super) fn commit_stop(&mut self) {
        let Some(ids) = self.pending_stop_confirm.take() else {
            return;
        };
        let mut cancelled = 0;
        for job_id in ids {
            if self.active_schedules.contains_key(&job_id) {
                self.cancel_schedule(&job_id, "/stop");
                cancelled += 1;
            }
        }
        if cancelled == 0 {
            self.push_plain("/stop: those jobs already ended.".to_string());
        }
    }

    /// Cancel an armed bare `/stop`.
    pub(super) fn cancel_stop(&mut self) {
        self.pending_stop_confirm = None;
        self.push_plain("/stop: cancelled.".to_string());
    }

    /// Resolve the layered `mcp.json` path for the cwd (first discovered
    /// `.cockpit/`), preferring an existing file, else the first creatable.
    fn mcp_config_path(&self) -> Option<std::path::PathBuf> {
        let cwd = &self.launch.cwd;
        for d in crate::config::dirs::discover_config_dirs(cwd) {
            let p = d.path.join("mcp.json");
            if p.exists() {
                return Some(p);
            }
        }
        crate::config::dirs::cwd_scoped_creatable_dirs(cwd)
            .into_iter()
            .next()
            .map(|d| d.path.join("mcp.json"))
    }

    fn mcp_load(&self) -> crate::mcp::config::McpConfig {
        #[cfg(test)]
        MCP_LOAD_CALLS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        crate::mcp::config::McpConfig::discover(&self.launch.cwd)
    }

    fn mcp_save(&mut self, cfg: &crate::mcp::config::McpConfig) -> bool {
        self.slash_menu_cache.borrow_mut().take();
        let Some(path) = self.mcp_config_path() else {
            self.push_plain("No writable .cockpit/ directory for MCP config".to_string());
            return false;
        };
        match cfg.write_private(&path) {
            Ok(_) => true,
            Err(_) => {
                self.push_plain("Failed to write mcp.json".to_string());
                false
            }
        }
    }

    fn mcp_list(&mut self) {
        let cfg = self.mcp_load();
        if cfg.servers.is_empty() {
            self.push_plain("No MCP servers configured.".to_string());
            return;
        }
        for (name, s) in &cfg.servers {
            let color = crate::tui::settings::mcp_row_color(name, s);
            let dot = match color {
                ratatui::style::Color::Green => "●",
                ratatui::style::Color::Yellow => "○",
                _ => "✗",
            };
            self.push_plain(format!(
                "{dot} {name}  {}  {}  auth={}",
                s.transport.as_str(),
                if s.enabled { "enabled" } else { "disabled" },
                s.auth.kind_str(),
            ));
        }
    }

    /// `/mcp on|off|toggle [id]`. `enable=None` toggles; a mixed set toggled
    /// in bulk turns all **off** (spec). `id=None` applies to every server.
    fn mcp_set_enabled(&mut self, id: Option<&str>, enable: Option<bool>) {
        let mut cfg = self.mcp_load();
        if let Some(id) = id {
            let Some(server) = cfg.servers.get_mut(id) else {
                self.push_plain(format!("Unknown MCP server `{id}`"));
                return;
            };
            server.enabled = enable.unwrap_or(!server.enabled);
        } else {
            let target = match enable {
                Some(v) => v,
                None => {
                    // Bulk toggle: if any is enabled (mixed/all-on), turn all
                    // off; only when all are off do we turn all on.
                    !cfg.servers.values().any(|s| s.enabled)
                }
            };
            for s in cfg.servers.values_mut() {
                s.enabled = target;
            }
        }
        if self.mcp_save(&cfg) {
            self.mcp_list();
        }
    }

    /// Shared cache-break warning helper. Returns the one-line warning to
    /// show when an action busts the cached system prefix (a `/llm-mode`
    /// switch today; the shift+tab agent cycle and `/agent` — specced
    /// elsewhere — reuse this verbatim). Returns `None` when the warning is
    /// meaningless because the active model/provider does not cache: reuses
    /// the pruning-policy no-cache predicate
    /// ([`crate::engine::prune::cache_state`] →
    /// [`crate::engine::prune::ColdReason::NoCacheProvider`]) rather than
    /// re-deriving "does this provider cache."
    pub(super) fn cache_break_warning(&self) -> Option<String> {
        if self.active_provider_caches() {
            Some(
                "Heads up: switching busts the prompt cache — the next call re-sends the \
                 full prefix uncached."
                    .to_string(),
            )
        } else {
            // No-cache provider: nothing to bust, so no warning.
            None
        }
    }

    /// Whether the active model/provider has a prompt cache at all. Reuses
    /// the pruning-policy no-cache predicate: the resolved
    /// [`crate::config::providers::CacheConfig`] is fed to
    /// [`crate::engine::prune::cache_state`]; a `NoCacheProvider` cold reason
    /// means it never caches. Best-effort — an unresolvable model is treated
    /// as caching so the warning errs on the side of showing.
    fn active_provider_caches(&self) -> bool {
        let Some((provider, model)) = self.launch.active_model.as_ref() else {
            return true;
        };
        let providers = crate::secret_ref::load_effective(&self.launch.cwd);
        let cache = providers.resolve_cache(provider, model);
        cache_config_caches(&cache)
    }

    /// Whether inline `<think>` stripping runs for the active session model,
    /// resolved through the three-tier toggle (model `inline_think` → provider
    /// `inline_think` → global `inlineThink`,
    /// implementation note). Loaded fresh from
    /// the layered config at each turn start so model swaps and `/settings`
    /// edits take effect on the next turn without a restart. An unresolvable
    /// model falls through to the global default (on).
    fn strip_inline_think(&self) -> bool {
        let (extended, providers) = crate::auto_title::load_configs_for(&self.launch.cwd);
        match self.launch.active_model.as_ref() {
            Some((provider, model)) => {
                providers.resolve_inline_think(provider, model, extended.inline_think)
            }
            None => extended.inline_think,
        }
    }

    fn pending_or_insert_with_strip<F>(
        &mut self,
        agent: String,
        resolve_strip: F,
    ) -> &mut PendingMsg
    where
        F: FnOnce(&Self) -> bool,
    {
        if self.pending.is_none() {
            let strip_think = resolve_strip(self);
            self.pending = Some(new_pending(agent, strip_think));
        }
        self.pending.as_mut().expect("pending initialized")
    }

    pub(super) fn swap_primary_agent(&mut self, name: &str) {
        if crate::agents::is_hidden_primary(name) {
            self.push_plain(format!(
                "`{name}` is hidden — start it with `/multireview`."
            ));
            return;
        }
        // Experimental-mode gate (implementation note):
        // with the flag off, a swap that targets a gated builtin
        // (`Auto`/`Plan`/`Swarm`/`Build`) is rejected with a one-line
        // history message and does NOT swap. Routed through the same
        // `is_experimental_primary` predicate the hiding uses (no duplicated
        // name list). This is the single chokepoint every swap route
        // (`/plan`/`/swarm`/`/build`, `/agent <gated>`, `Shift+Tab`)
        // passes through; the gated names are already hidden from the cycle /
        // `/agent` list, so this guards a direct `/plan`-style invocation.
        if crate::agents::is_experimental_primary(name)
            && !crate::config::extended::load_for_cwd(&self.launch.cwd).experimental_mode
        {
            self.push_plain(format!(
                "`{name}` requires experimental mode — enable it in `/settings`."
            ));
            return;
        }
        let sent = self.send_daemon_request(crate::daemon::proto::Request::SetAgent {
            name: name.to_string(),
        });
        if sent {
            self.record_primary_switch_confirmation(name);
        } else {
            self.push_plain(
                "Send a message first to start a session, then switch agents".to_string(),
            );
        }
    }

    pub(super) fn record_primary_switch_confirmation(&mut self, name: &str) {
        let line_to_record = format!("Switched primary agent to `{name}`");
        if let Some(pending) = self.pending_agent_switch_log.as_mut()
            && let Some(HistoryEntry::Plain { line }) =
                self.history.get_mut(pending.confirmation_index)
        {
            *line = line_to_record;
            pending.target = name.to_string();
            return;
        }
        self.push_plain(line_to_record);
        self.pending_agent_switch_log = Some(PendingAgentSwitchLog {
            confirmation_index: self.history.len().saturating_sub(1),
            target: name.to_string(),
        });
    }

    pub(super) fn lock_pending_agent_switch_log(&mut self) {
        let Some(pending) = self.pending_agent_switch_log.take() else {
            return;
        };
        if let Some(warning) = primary_swap_warning(&pending.target) {
            let idx = pending.confirmation_index.min(self.history.len());
            self.history.insert(
                idx,
                HistoryEntry::Plain {
                    line: warning.to_string(),
                },
            );
        }
    }

    pub(super) fn start_multireview(&mut self, kickoff: String) {
        let sent = self.send_daemon_request(crate::daemon::proto::Request::SetAgent {
            name: "Multireview".to_string(),
        });
        if !sent {
            self.push_plain(
                "Send a message first to start a session, then run `/multireview`".to_string(),
            );
            return;
        }
        self.push_plain(MULTIREVIEW_TOKEN_BURN_WARNING.to_string());
        self.begin_working_span();
        let submission = crate::engine::message::UserSubmission {
            kind: crate::engine::message::UserSubmissionKind::User,
            text: kickoff.clone(),
            display_text: None,
            tag_expansions: Vec::new(),
            images: Vec::new(),
            forced_skill: None,
            origin_principal: None,
            job_id: None,
            preflight_cleaned: None,
            queue_item_ids: Vec::new(),
            queue_target: None,
        };
        self.dispatch_optimistic_user_submission(kickoff, submission, "/multireview", true, &[]);
    }

    /// `Shift+Tab` — advance the active primary to the next agent in the
    /// wrapping cycle `Auto → Plan → Build → Swarm → <user primaries alpha> → Auto`
    /// (implementation note). Routes through
    /// [`Self::swap_primary_agent`], so it carries the same confirmation
    /// line and start-a-session-first guard `/plan`/`/build` have.
    pub(super) fn cycle_primary_agent(&mut self) {
        let order = crate::agents::chat_ownable_primaries(&self.launch.cwd);
        let next = crate::agents::next_primary_in_cycle(&self.launch.agent_name, &order);
        self.swap_primary_agent(&next);
    }

    pub(super) fn open_footer_agent_picker(&mut self) {
        self.footer_mode_picker = None;
        let order = crate::agents::chat_ownable_primaries(&self.launch.cwd);
        let current = self
            .agent_path
            .first()
            .map(String::as_str)
            .unwrap_or(self.launch.agent_name.as_str());
        self.footer_agent_picker = Some(FooterAgentPicker::new(current, order));
    }

    pub(super) fn commit_footer_agent_picker(&mut self, picker: &FooterAgentPicker) {
        if self.agent_path.len() > 1 {
            self.push_plain(
                "Agent switch is disabled while an interactive subagent is active.".to_string(),
            );
            self.footer_agent_picker = Some(picker.clone());
            return;
        }
        if let Some(name) = picker.selected_agent() {
            self.footer_agent_picker = None;
            self.footer_selection = None;
            self.swap_primary_agent(name);
        } else {
            self.footer_agent_picker = Some(picker.clone());
        }
    }

    pub(super) fn open_footer_mode_picker(&mut self) {
        self.footer_agent_picker = None;
        self.footer_mode_picker = Some(FooterModePicker::new(self.llm_mode));
    }

    pub(super) fn open_model_picker(&mut self) {
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        match crate::tui::model_picker::ModelPickerDialog::open_with_failures(
            &self.launch.cwd,
            &self.usage_models,
            &self.auth_failure_annotations,
            chrono::Utc::now().timestamp(),
        ) {
            Ok(picker) => {
                self.overlay = Overlay::ModelPicker(picker);
            }
            Err(e) => {
                self.push_plain(format!("/model: {e}"));
            }
        }
    }

    pub(super) fn record_auth_failure(
        &mut self,
        provider: String,
        model: String,
        kind: crate::daemon::proto::AuthFailureKind,
        failed_at_epoch_secs: i64,
    ) {
        self.auth_failure_annotations.insert(
            (provider.clone(), model.clone()),
            crate::tui::auth_failure::AuthFailureRecord {
                kind: kind.clone(),
                failed_at_epoch_secs,
            },
        );
        self.auth_failure_fingerprints.insert(
            provider.clone(),
            crate::tui::auth_failure::provider_auth_fingerprint(&self.launch.cwd, &provider),
        );
        self.auth_failure_notice = Some(crate::tui::auth_failure::AuthFailureNotice {
            provider,
            model,
            kind,
        });
    }

    pub(super) fn clear_auth_failure_for_model(&mut self, provider: &str, model: &str) {
        self.auth_failure_annotations
            .remove(&(provider.to_string(), model.to_string()));
        if self
            .auth_failure_notice
            .as_ref()
            .is_some_and(|notice| notice.provider == provider && notice.model == model)
        {
            self.auth_failure_notice = None;
        }
        if !self
            .auth_failure_annotations
            .keys()
            .any(|(failed_provider, _)| failed_provider == provider)
        {
            self.auth_failure_fingerprints.remove(provider);
        }
    }

    pub(super) fn clear_auth_failures_for_provider(&mut self, provider: &str) {
        self.auth_failure_annotations
            .retain(|(failed_provider, _), _| failed_provider != provider);
        self.auth_failure_fingerprints.remove(provider);
        if self
            .auth_failure_notice
            .as_ref()
            .is_some_and(|notice| notice.provider == provider)
        {
            self.auth_failure_notice = None;
        }
    }

    pub(super) fn clear_changed_provider_auth_failures(&mut self) {
        let changed = self
            .auth_failure_fingerprints
            .iter()
            .filter_map(|(provider, fingerprint)| {
                (*fingerprint
                    != crate::tui::auth_failure::provider_auth_fingerprint(
                        &self.launch.cwd,
                        provider,
                    ))
                .then_some(provider.clone())
            })
            .collect::<Vec<_>>();
        for provider in changed {
            self.clear_auth_failures_for_provider(&provider);
        }
    }

    pub(super) fn open_auth_failure_provider(&mut self) {
        let Some(notice) = self.auth_failure_notice.clone() else {
            return;
        };
        let oauth_expired = matches!(
            notice.kind,
            crate::daemon::proto::AuthFailureKind::OAuthExpired { .. }
        );
        self.dialog = crate::tui::settings::Dialog::open_provider_settings(
            &self.launch.cwd,
            &notice.provider,
            oauth_expired,
        );
    }

    pub(super) fn close_model_picker(&mut self, accepted: bool) {
        self.overlay = Overlay::None;
        self.reload_launch_info();
        if accepted && let Some((p, m)) = self.launch.active_model.clone() {
            self.notify_active_model_selected(p, m);
        }
        let line = self.model_summary_history_line();
        self.push_plain(line);
    }

    fn notify_active_model_selected(&mut self, provider: String, model: String) {
        self.record_usage(
            crate::daemon::proto::UsageKind::Model,
            format!("{provider}/{model}"),
            None,
        );
        self.send_daemon_request(crate::daemon::proto::Request::SetActiveModel { provider, model });
    }

    pub(super) fn cycle_footer_model(&mut self, forward: bool) {
        match crate::tui::model_picker::cycle_active_favorite(
            &self.launch.cwd,
            &self.usage_models,
            forward,
        ) {
            Ok(Some((provider, model))) => {
                self.reload_launch_info();
                self.notify_active_model_selected(provider.clone(), model.clone());
                self.push_plain(format!("/model: active model is now {provider}/{model} ★"));
            }
            Ok(None) => {
                self.push_plain(
                    "No other favorite model to cycle to; open `/model` for the full list."
                        .to_string(),
                );
            }
            Err(e) => {
                self.push_plain(format!("/model: {e}"));
            }
        }
    }

    pub(super) fn open_quick_dialog(&mut self) {
        let models = match crate::tui::model_picker::ordered_model_choices(
            &self.launch.cwd,
            &self.usage_models,
        ) {
            Ok(choices) => choices
                .into_iter()
                .filter(|choice| choice.is_favorite)
                .map(crate::tui::quick_dialog::QuickModelChoice::from)
                .collect(),
            Err(_) => Vec::new(),
        };
        let current = crate::tui::quick_dialog::QuickCurrent {
            llm_mode: self.llm_mode,
            recursion_enabled: self.delegation_recursion_enabled,
            recursion_depth: self.delegation_recursion_depth,
            trusted_only: self.trusted_only_enabled,
            sandbox_mode: self.sandbox_mode,
            container_network_enabled: self.container_network_enabled,
            container_availability: self.container_availability.clone(),
            approval_mode: self.approval_mode,
            active_model: self.launch.active_model.clone(),
        };
        self.footer_selection = None;
        self.footer_agent_picker = None;
        self.footer_mode_picker = None;
        self.overlay = Overlay::Quick(crate::tui::quick_dialog::QuickDialog::open(current, models));
    }

    pub(super) fn apply_quick_commit(&mut self, commit: crate::tui::quick_dialog::QuickCommit) {
        let mut any_failed = false;
        if let Some(mode) = commit.llm_mode {
            if self.send_daemon_request(crate::daemon::proto::Request::SetSessionLlmMode { mode }) {
                if let Some(warning) = self.cache_break_warning() {
                    self.push_plain(warning);
                }
            } else {
                any_failed = true;
            }
        }
        if let Some((enabled, default_depth)) = commit.recursion
            && !self.send_daemon_request(crate::daemon::proto::Request::SetDelegationRecursion {
                enabled,
                default_depth,
            })
        {
            any_failed = true;
        }
        if let Some(enabled) = commit.trusted_only
            && !self.send_daemon_request(crate::daemon::proto::Request::SetTrustedOnly {
                enabled: Some(enabled),
            })
        {
            any_failed = true;
        }
        if (commit.sandbox_mode.is_some() || commit.container_network_enabled.is_some())
            && !self.send_daemon_request(crate::daemon::proto::Request::SetSandbox {
                mode: commit.sandbox_mode,
                container_network_enabled: commit.container_network_enabled,
            })
        {
            any_failed = true;
        }
        if let Some(mode) = commit.approval_mode
            && !self.send_daemon_request(crate::daemon::proto::Request::SetApprovalMode { mode })
        {
            any_failed = true;
        }
        if let Some((provider, model)) = commit.active_model {
            self.record_usage(
                crate::daemon::proto::UsageKind::Model,
                format!("{provider}/{model}"),
                None,
            );
            if self.send_daemon_request(crate::daemon::proto::Request::SetActiveModel {
                provider: provider.clone(),
                model: model.clone(),
            }) {
                self.launch.active_model = Some((provider.clone(), model.clone()));
                self.push_plain(format!("/quick: active model is now {provider}/{model}"));
            } else {
                any_failed = true;
            }
        }
        if any_failed {
            self.push_plain("/quick: send a message first to start a session".to_string());
        }
    }

    pub(super) fn footer_cycle_agent(&mut self) {
        if self.agent_path.len() > 1 {
            self.push_plain(
                "Agent cycle is disabled while an interactive subagent is active.".to_string(),
            );
            return;
        }
        self.cycle_primary_agent();
    }

    pub(super) fn set_footer_llm_mode(&mut self, target: crate::config::extended::LlmMode) {
        self.handle_llm_mode_command(target.as_str());
    }

    pub(super) fn previous_llm_mode(
        mode: crate::config::extended::LlmMode,
    ) -> crate::config::extended::LlmMode {
        match mode {
            crate::config::extended::LlmMode::Defensive => {
                crate::config::extended::LlmMode::Frontier
            }
            crate::config::extended::LlmMode::Normal => crate::config::extended::LlmMode::Defensive,
            crate::config::extended::LlmMode::Frontier => crate::config::extended::LlmMode::Normal,
        }
    }

    /// Send a fire-and-forget daemon request over the runner's record
    /// channel (same path `/schedule cancel` uses). Returns whether a runner
    /// was connected to receive it.
    pub(super) fn send_daemon_request(&self, req: crate::daemon::proto::Request) -> bool {
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => runner.record_tx.try_send(req).is_ok(),
            _ => false,
        }
    }

    /// The anti-misfire lockout to stamp on a question dialog about to be
    /// installed (implementation note). Returns the
    /// configured `lockout_ms` only on the genuine composer→dialog edge —
    /// the composer has actually been the active input surface since the
    /// last dialog closed (`composer_active_since_dialog`) — and
    /// [`Duration::ZERO`] (immediately answerable) for a direct
    /// continuation, where one dialog succeeds another without the composer
    /// ever regaining focus (including the same resolve/poll cycle). Either
    /// way the composer is now displaced, so the flag is consumed; a render
    /// pass with no dialog re-arms it.
    pub(super) fn dialog_lockout(&mut self) -> Duration {
        let lockout = if self.composer_active_since_dialog {
            Duration::from_millis(load_dialog_config(&self.launch.cwd).lockout_ms)
        } else {
            crate::tui::dialog::DialogState::NO_LOCKOUT
        };
        self.composer_active_since_dialog = false;
        lockout
    }

    /// Fresh lockout for daemon-authoritative interrupt re-install paths:
    /// queue advance and attach re-hydration. The old zero-lockout branch is
    /// still valid for a genuine same-flow continuation, but FIFO advance and
    /// re-hydration are new dialogs from the user's perspective and must not
    /// be immediately answerable.
    pub(super) fn fresh_dialog_lockout(&mut self) -> Duration {
        self.composer_active_since_dialog = false;
        Duration::from_millis(load_dialog_config(&self.launch.cwd).lockout_ms)
    }

    /// Send the answering dialog's outcome back to the daemon (GOALS
    /// §3b). Both submit and cancel become a `ResolveInterrupt` — cancel
    /// carries `ResolveResponse::Cancel`, which the worker fans out to a
    /// per-question `Cancel` so the blocked `question` tool unblocks with
    /// dismissed answers.
    pub(super) fn resolve_question_dialog(
        &mut self,
        result: crate::tui::dialog::question::QuestionResult,
    ) {
        use crate::daemon::proto::{Request, ResolveResponse};
        use crate::tui::dialog::question::QuestionResult;
        let (interrupt_id, response) = match result {
            QuestionResult::Submit {
                interrupt_id,
                responses,
            } => (interrupt_id, ResolveResponse::Batch { responses }),
            QuestionResult::Cancel { interrupt_id } => (interrupt_id, ResolveResponse::Cancel),
        };
        let request = Request::ResolveInterrupt {
            interrupt_id,
            response,
        };
        let was_btw_dialog = self.question_dialog_btw;
        if was_btw_dialog {
            if let Some(Ok(runner)) = self.btw_pane.as_ref().and_then(|pane| pane.runner.as_ref()) {
                let _ = agent_runner::attached_request_tx_blocking(
                    runner.attached_request_tx.clone(),
                    request,
                );
            }
        } else {
            self.send_daemon_request(request);
        }
        self.question_dialog_btw = false;
        self.install_pending_btw_interrupt();
    }

    /// `/prune` (T6.d): show the before→after context % and the
    /// cache-bust warning, then arm the confirm. The numbers come from the
    /// daemon-authoritative `prunable_tokens` (same `dedup_plan` `/prune`
    /// executes), so the projection equals the result.
    pub(super) fn arm_prune_confirm(&mut self) {
        if self.prunable_tokens == 0 {
            self.push_plain("/prune: 0% prunable — nothing to do.".to_string());
            self.pending_prune_confirm = false;
            return;
        }
        let tokens = self.context_tokens();
        let prunable = self.prunable_tokens;
        let numbers = match self.launch.active_model_max_context {
            Some(max) if max > 0 => {
                let pct = (tokens as u64 * 100 / max as u64).min(999);
                let after = (tokens as u64).saturating_sub(prunable);
                let after_pct = (after * 100 / max as u64).min(999);
                format!("context {pct}% → {after_pct}% (~{prunable} wire tokens)")
            }
            _ => format!("~{prunable} wire tokens"),
        };
        // Cache warning derived from the predicate, not a guess.
        let cache_line = if self.cache_cold {
            "Cache is cold — pruning is free (auto-prune normally handles this)."
        } else {
            "Cache is HOT — pruning breaks it; the cache-bust cost may exceed the savings. \
             When the cache goes cold, auto-prune handles it for free."
        };
        self.push_plain(format!(
            "/prune: {numbers}. {cache_line} Press y or Enter to confirm, any other key to cancel."
        ));
        self.pending_prune_confirm = true;
    }

    /// Commit an armed `/prune`: send the request to the daemon. The
    /// `Pruned` + refreshed `ContextProjection` events render the result.
    pub(super) fn commit_prune(&mut self) {
        self.pending_prune_confirm = false;
        if !self.send_daemon_request(crate::daemon::proto::Request::Prune) {
            self.push_plain("/prune: no daemon connection — cannot prune.".to_string());
        }
    }

    /// Cancel an armed `/prune`.
    pub(super) fn cancel_prune(&mut self) {
        self.pending_prune_confirm = false;
        self.push_plain("/prune: cancelled.".to_string());
    }

    /// `/compact`: enqueue an in-place compaction turn on the active session.
    pub(super) fn start_compact(&mut self) {
        let submission = crate::engine::message::UserSubmission::compact_notice();
        self.ensure_agent_runner();
        let span_orphaned = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => match runner.input_tx.try_send(submission) {
                Ok(_) => {
                    self.current_session_persisted = true;
                    false
                }
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: "engine: input queue full — wait for the current turn to finish"
                            .to_string(),
                    });
                    true
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: "engine: driver task has exited".to_string(),
                    });
                    true
                }
            },
            Some(Err(e)) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("engine: {e}"),
                });
                true
            }
            None => true,
        };
        if span_orphaned {
            return;
        }
        if self.busy {
            self.queue
                .push(input::optimistic_queue_item("/compact".to_string()));
        } else {
            self.begin_working_span();
            self.push_plain("/compact: assembling handoff (prune-first, model brief, deterministic appendix, seed tools)...".to_string());
        }
    }

    /// Legacy reviewed `/compact` handoff path. New compactions are applied
    /// in place by the driver, so this only clears stale pending state.
    pub(super) fn commit_compact(&mut self, _handoff: String) -> bool {
        self.pending_compact = None;
        self.push_plain(
            "/compact: stale reviewed handoff discarded; run `/compact` again".to_string(),
        );
        false
    }

    /// Resume `session_id` from the `/sessions` browser. Reuses the
    /// existing session-switch path (`attach_to_session`) — the runner's
    /// event stream + input channel move onto the resumed session, and the
    /// daemon marks it viewed on attach (clearing its unread state).
    pub(super) fn resume_session(&mut self, session_id: uuid::Uuid) {
        self.cancel_outgoing_turn_if_busy();

        // Resuming another session from inside a side conversation: discard the
        // ephemeral fork first (no orphan). The resume below then overwrites
        // the restored main view with the resumed session's.
        if self.side_conversation.is_some() {
            self.end_side_conversation(false);
        }
        match agent_runner::attach_to_session(
            &self.launch.cwd,
            session_id,
            self.no_sandbox,
            self.lifecycle_mode(),
        ) {
            Ok(mut runner) => {
                // Daemonless: keep the ownership guard armed across resume.
                self.arm_daemon_guard(&runner);
                let short_id = runner.short_id.clone();
                self.project_id = Some(runner.project_id.clone());
                self.launch.session_id = Some(runner.session_id);
                self.launch.session_short_id = Some(runner.short_id.clone());
                // A resumed session already has a DB row
                // (session-id-display-and-lazy-persist).
                self.current_session_persisted = true;
                // Switch the runner: fresh transcript view bound to the
                // resumed session.
                self.history.clear();
                self.reset_session_live_state();
                // Repopulate the full prior transcript from the daemon's
                // chronological history snapshot
                // (implementation note): user bubbles,
                // agent messages, and tool boxes render exactly as a live
                // session would, in order — no "resumed" divider. The status
                // line below comes AFTER so it sits at the bottom.
                let restored = wire_history_to_entries(std::mem::take(&mut runner.history));
                self.history.extend(restored);
                let paused_work = std::mem::take(&mut runner.paused_work);
                let repair_required = runner.repair_required.clone();
                let daemon_version = runner.daemon_version.clone();
                let daemon_compatible = runner.daemon_compatible;
                let live_btw_fork = runner.btw_fork.clone();
                self.agent_runner = Some(Ok(runner));
                if let Some(info) = live_btw_fork {
                    self.open_btw_pane_from_info(info, true);
                }
                let label = if short_id.is_empty() {
                    session_id.to_string()
                } else {
                    short_id
                };
                self.push_plain(format!("/resume: switched to session {label}."));
                if let Some(repair) = repair_required {
                    self.maybe_prompt_resume_repair(repair);
                }
                self.maybe_prompt_paused_work(session_id, paused_work);
                self.maybe_show_daemon_version_chip(&daemon_version, daemon_compatible);
            }
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("/resume: could not attach to session: {e}"),
                });
            }
        }
    }

    fn maybe_prompt_paused_work(
        &mut self,
        session_id: uuid::Uuid,
        paused_work: Vec<crate::daemon::proto::PausedWorkSummary>,
    ) {
        if paused_work.is_empty() {
            return;
        }
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
        let pending_tools: i64 = paused_work.iter().map(|item| item.pending_tool_count).sum();
        let agents = paused_work
            .iter()
            .map(|item| item.active_agent.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(", ");
        let prompt = if pending_tools > 0 {
            format!(
                "Paused work from daemon shutdown is waiting for {agents} ({pending_tools} pending tool call(s))."
            )
        } else {
            format!("Paused work from daemon shutdown is waiting for {agents}.")
        };
        let interrupt_id = uuid::Uuid::new_v4();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt,
                options: vec![
                    InterruptOption {
                        id: "resume".into(),
                        label: "Resume".into(),
                        description: Some("Continue through the normal approval flow".into()),
                        secondary: false,
                    },
                    InterruptOption {
                        id: "cancel".into(),
                        label: "Cancel".into(),
                        description: Some("Mark paused work cancelled and wait for input".into()),
                        secondary: false,
                    },
                ],
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        self.pending_local_choice = Some(LocalChoice::PausedWork(PendingPausedWork {
            interrupt_id,
            session_id,
        }));
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::new(
                interrupt_id,
                String::new(),
                set,
                self.dialog_lockout(),
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    fn maybe_prompt_resume_repair(&mut self, state: crate::daemon::proto::ResumeRepairState) {
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
        let ids = if state.failing_tool_call_ids.is_empty() {
            "unknown tool id".to_string()
        } else {
            state.failing_tool_call_ids.join(", ")
        };
        let prompt = format!(
            "Responses replay needs repair before continuing on `{}/{}` ({}, {}). Failing id(s): {ids}.",
            state.provider, state.model, state.wire_api, state.failure_kind
        );
        let interrupt_id = uuid::Uuid::new_v4();
        let mut options = vec![
            InterruptOption {
                id: "read_only".into(),
                label: "Read-only".into(),
                description: Some("Keep browsing, copying, and exporting this transcript".into()),
                secondary: false,
            },
            InterruptOption {
                id: "fork".into(),
                label: "Fork".into(),
                description: Some(
                    "Create a normal continuation from the last provider-valid turn".into(),
                ),
                secondary: false,
            },
            InterruptOption {
                id: "repair".into(),
                label: "Repair".into(),
                description: Some(
                    "Requires explicit synthetic-result repair support before dispatch".into(),
                ),
                secondary: false,
            },
            InterruptOption {
                id: "export".into(),
                label: "Export".into(),
                description: Some("Export a debug bundle with identity provenance".into()),
                secondary: false,
            },
            InterruptOption {
                id: "cancel".into(),
                label: "Cancel".into(),
                description: Some("Close this dialog and leave the transcript read-only".into()),
                secondary: false,
            },
        ];
        if state.safe_last_turn_seq.is_none() {
            options[1].description =
                Some("No safe provider-valid turn was computed for automatic fork".into());
        }
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Single {
                prompt,
                options,
                allow_freetext: false,
                command_detail: None,
                permission: false,
                approval_class: None,
                sandbox_escalation: None,
            }],
        };
        self.pending_local_choice = Some(LocalChoice::ResumeRepair(PendingResumeRepair {
            interrupt_id,
            state,
        }));
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::new(
                interrupt_id,
                String::new(),
                set,
                self.dialog_lockout(),
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    fn resolve_resume_repair_choice(
        &mut self,
        pending: PendingResumeRepair,
        selected_id: Option<&str>,
    ) {
        match selected_id {
            Some("fork") => {
                let Some(seq) = pending.state.safe_last_turn_seq else {
                    self.history.push(HistoryEntry::CommandError {
                        line: "/resume: cannot fork automatically; no safe provider-valid turn was recorded".to_string(),
                    });
                    return;
                };
                let (parent_session_id, socket) = match self.agent_runner.as_ref() {
                    Some(Ok(runner)) => (runner.session_id, runner.socket.clone()),
                    _ => {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/resume: no active session to fork from".to_string(),
                        });
                        return;
                    }
                };
                self.push_plain("/resume: fork pending".to_string());
                self.async_actions.start_blocking(
                    AsyncActionKind::DaemonRpc("fork.create"),
                    AsyncActionPolicy::Replace(AsyncActionKey::new("fork.create")),
                    move || {
                        let fork_point_turn_id = Some(seq.to_string());
                        let (session_id, short_id) = agent_runner::fork_session_blocking(
                            &socket,
                            parent_session_id,
                            fork_point_turn_id,
                            false,
                        )?;
                        Ok(AsyncActionPayload::ForkCreated {
                            parent_session_id,
                            socket,
                            session_id,
                            short_id,
                            seed_composer: None,
                        })
                    },
                );
            }
            Some("repair") => {
                self.push_plain("/resume: applying explicit synthetic repair.".to_string());
                self.send_daemon_request(crate::daemon::proto::Request::RepairResume {
                    session_id: pending.state.session_id,
                });
            }
            Some("export") => {
                let label = if pending.state.short_id.is_empty() {
                    pending.state.session_id.to_string()
                } else {
                    pending.state.short_id
                };
                self.push_plain(format!(
                        "/resume: export a debug bundle with `cockpit export {label}`; identity provenance is included in tool-call records"
                    ));
            }
            Some("read_only") => {
                self.push_plain("/resume: transcript remains open read-only; model dispatch is blocked until fork or repair".to_string());
            }
            Some("cancel") | None => {
                self.push_plain(
                    "/resume: repair dialog closed; transcript remains read-only".to_string(),
                );
            }
            Some(_) => {}
        }
    }

    fn maybe_show_daemon_version_chip(&mut self, daemon_version: &str, compatible: bool) {
        if compatible || daemon_version == crate::daemon::proto::DAEMON_VERSION {
            return;
        }
        self.push_plain(format!(
            "daemon {daemon_version} is newer than this client {}; relaunch cockpit to refresh",
            crate::daemon::proto::DAEMON_VERSION
        ));
    }

    fn side_entry_banner(side_short_id: &str) -> String {
        format!(
            "Side conversation {side_short_id} — a throwaway fork. `/side end` to discard and return."
        )
    }

    fn apply_fork_created(
        &mut self,
        parent_session_id: uuid::Uuid,
        fork_session_id: uuid::Uuid,
        fork_short_id: String,
        seed_composer: Option<String>,
    ) {
        if self.side_conversation.is_some()
            || !self.current_session_persisted
            || !matches!(
                self.agent_runner.as_ref(),
                Some(Ok(runner)) if runner.session_id == parent_session_id
            )
        {
            return;
        }
        match attach_to_session_retry_once(|| {
            agent_runner::attach_to_session(
                &self.launch.cwd,
                fork_session_id,
                self.no_sandbox,
                self.lifecycle_mode(),
            )
        }) {
            Ok(mut runner) => {
                self.arm_daemon_guard(&runner);
                self.project_id = Some(runner.project_id.clone());
                self.launch.session_id = Some(runner.session_id);
                self.launch.session_short_id = Some(runner.short_id.clone());
                self.current_session_persisted = true;
                self.history.clear();
                self.reset_session_live_state();
                let restored = wire_history_to_entries(std::mem::take(&mut runner.history));
                self.history.extend(restored);
                self.agent_runner = Some(Ok(runner));
                self.push_plain(format!("/fork: switched to fork {fork_short_id}."));
                if let Some(seed) = seed_composer {
                    self.composer.set(seed);
                    self.composer.set_vim_mode(VimMode::Insert);
                }
            }
            Err(e) => {
                self.history.push(HistoryEntry::CommandError {
                    line: format!("/fork: created {fork_short_id}, but could not attach: {e}"),
                });
            }
        }
    }

    /// Fork the current (main) session into an ephemeral throwaway and switch
    /// the TUI onto it. The fork reuses `ForkSession` (with `ephemeral`), and
    /// we keep the visible scrollback so the user sees the full prior history.
    /// The main-session view is snapshotted into `side_conversation` so a
    /// later `/side end` / exit restores it verbatim.
    fn enter_side_conversation(&mut self) {
        // Need a live runner: the side fork goes onto the same daemon, and
        // forking off an un-persisted session has nothing to branch from.
        let (parent_session_id, socket) = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => (runner.session_id, runner.socket.clone()),
            _ => {
                self.history.push(HistoryEntry::CommandError {
                    line: "/side: no active session to fork from".to_string(),
                });
                return;
            }
        };
        // Forking off a never-persisted session has no parent row in the DB.
        if !self.current_session_persisted {
            self.history.push(HistoryEntry::CommandError {
                line: "/side: send a message first — there's nothing to fork yet".to_string(),
            });
            return;
        }

        self.push_plain("/side: pending".to_string());
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("side.start"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("side.start")),
            move || {
                let (session_id, short_id) =
                    agent_runner::fork_session_blocking(&socket, parent_session_id, None, true)?;
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    socket,
                    session_id,
                    short_id,
                    seed_composer: None,
                })
            },
        );
    }

    fn apply_side_created(
        &mut self,
        parent_session_id: uuid::Uuid,
        socket: std::path::PathBuf,
        side_session_id: uuid::Uuid,
        side_short_id: String,
    ) {
        if self.side_conversation.is_some()
            || !self.current_session_persisted
            || !matches!(
                self.agent_runner.as_ref(),
                Some(Ok(runner)) if runner.session_id == parent_session_id
            )
        {
            let socket = socket.clone();
            self.async_actions.start_blocking(
                AsyncActionKind::DaemonRpc("side.discard"),
                AsyncActionPolicy::AllowConcurrent,
                move || {
                    agent_runner::discard_session_blocking(&socket, side_session_id)
                        .map(|_| AsyncActionPayload::Unit)
                },
            );
            return;
        }
        // Attach to the ephemeral fork. On failure, discard the orphan fork
        // we just created and stay in the main session, untouched.
        let runner = match agent_runner::attach_to_session(
            &self.launch.cwd,
            side_session_id,
            self.no_sandbox,
            self.lifecycle_mode(),
        ) {
            Ok(runner) => runner,
            Err(e) => {
                let discard_socket = socket.clone();
                self.async_actions.start_blocking(
                    AsyncActionKind::DaemonRpc("side.discard"),
                    AsyncActionPolicy::AllowConcurrent,
                    move || {
                        agent_runner::discard_session_blocking(&discard_socket, side_session_id)
                            .map(|_| AsyncActionPayload::Unit)
                    },
                );
                self.history.push(HistoryEntry::CommandError {
                    line: format!("/side: could not enter side conversation: {e}"),
                });
                return;
            }
        };
        self.arm_daemon_guard(&runner);

        // Snapshot the main-session view, then swap onto the side fork. We
        // keep `history` (prior scrollback stays visible) but take everything
        // else into the snapshot so `end` restores it exactly.
        let side = SideConversation {
            side_session_id,
            socket,
            saved_runner: self.agent_runner.take(),
            saved_history: self.history.clone(),
            saved_queue: std::mem::take(&mut self.queue),
            saved_pending: self.pending.take(),
            saved_prunable_tokens: self.prunable_tokens,
            saved_cache_cold: self.cache_cold,
            saved_elided_event_ids: std::mem::take(&mut self.elided_event_ids),
            saved_active_schedules: std::mem::take(&mut self.active_schedules),
            saved_pending_stop_confirm: self.pending_stop_confirm.take(),
            saved_chat_scroll_offset: self.chat_scroll_offset,
            saved_project_id: self.project_id.clone(),
            saved_session_id: self.launch.session_id,
            saved_session_short_id: self.launch.session_short_id.clone(),
            saved_current_session_persisted: self.current_session_persisted,
        };

        self.project_id = Some(runner.project_id.clone());
        self.launch.session_id = Some(runner.session_id);
        self.launch.session_short_id = Some(runner.short_id.clone());
        // The ephemeral fork is never surfaced as resumable — keep
        // `current_session_persisted = false` so the exit-tail never prints
        // its id, even though the fork has a (throwaway) DB row.
        self.current_session_persisted = false;
        // Reset the live-view fields the side conversation tracks on its own;
        // the visible scrollback (history) is intentionally preserved.
        self.queue.clear();
        self.pending = None;
        self.pending_render_cache = None;
        self.prunable_tokens = 0;
        self.cache_cold = true;
        self.elided_event_ids.clear();
        self.active_schedules.clear();
        self.pending_stop_confirm = None;
        self.chat_scroll_offset = 0;
        self.agent_runner = Some(Ok(runner));
        self.side_conversation = Some(side);

        self.push_plain(Self::side_entry_banner(&side_short_id));
    }

    /// End the open side conversation: restore the main-session view verbatim
    /// and discard the ephemeral fork (row + descendant forks). Unconditional
    /// — no "keep this fork?" prompt (that's `/fork`). `announce` controls the
    /// confirmation line; the process-exit path passes `false`.
    pub(super) fn end_side_conversation(&mut self, announce: bool) {
        let Some(side) = self.side_conversation.take() else {
            return;
        };

        // Discard the ephemeral fork asynchronously: stops its worker and
        // deletes its row. Best-effort — a transport failure still leaves the
        // daemon's boot sweep as the backstop, so an orphan can't survive long.
        let discard_socket = side.socket.clone();
        let discard_session_id = side.side_session_id;
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("side.discard"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                agent_runner::discard_session_blocking(&discard_socket, discard_session_id)
                    .map(|_| AsyncActionPayload::Unit)
            },
        );

        // Restore the main-session view exactly as it was on entry.
        self.agent_runner = side.saved_runner;
        self.history = side.saved_history;
        self.queue = side.saved_queue;
        self.pending = side.saved_pending;
        self.prunable_tokens = side.saved_prunable_tokens;
        self.cache_cold = side.saved_cache_cold;
        self.elided_event_ids = side.saved_elided_event_ids;
        self.active_schedules = side.saved_active_schedules;
        self.pending_stop_confirm = side.saved_pending_stop_confirm;
        self.chat_scroll_offset = side.saved_chat_scroll_offset;
        self.project_id = side.saved_project_id;
        self.launch.session_id = side.saved_session_id;
        self.launch.session_short_id = side.saved_session_short_id;
        self.current_session_persisted = side.saved_current_session_persisted;
        // The daemonless ownership guard stays armed throughout — the side
        // fork lives on the same owned daemon, so it's never dropped and
        // needs no re-arming here.

        if announce {
            self.push_plain("Side conversation discarded — back in the main session.".to_string());
        }
    }

    /// Send a redaction-source toggle to the daemon. `None` leaves a source
    /// unchanged; `Some(v)` sets it explicitly. The resulting state arrives
    /// back via the `RedactionState` event → toast (and tracked-state sync).
    fn send_redaction_toggle(
        &mut self,
        scan_environment: Option<bool>,
        scan_dotenv: Option<bool>,
        scan_ssh_keys: Option<bool>,
    ) {
        if !self.send_daemon_request(crate::daemon::proto::Request::SetRedaction {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        }) {
            self.push_plain("/toggle-redaction: no daemon connection".to_string());
        }
    }

    /// Open the bare-`/toggle-redaction` multiselect: one checkbox per source
    /// pre-checked to the current per-source state. Driven locally (no daemon
    /// interrupt) like the `/init` existing-file prompt; the close handler
    /// matches the synthetic interrupt id and applies the selection.
    fn open_redaction_toggle_dialog(&mut self) {
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};
        let interrupt_id = uuid::Uuid::new_v4();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Multi {
                prompt: "Redaction sources (session-only — reverts on restart):".to_string(),
                options: vec![
                    InterruptOption {
                        id: REDACT_OPT_ENV.into(),
                        label: "redact environment variables".into(),
                        description: None,
                        secondary: false,
                    },
                    InterruptOption {
                        id: REDACT_OPT_FILE.into(),
                        label: "redact environment files (default: .env)".into(),
                        description: None,
                        secondary: false,
                    },
                    InterruptOption {
                        id: REDACT_OPT_SSH.into(),
                        label: "redact private SSH keys (~/.ssh)".into(),
                        description: None,
                        secondary: false,
                    },
                ],
                // A blank multiselect (both unchecked) is a valid answer here:
                // it means "turn both off". No free-text custom row.
                allow_freetext: false,
            }],
        };
        let mut preselected: Vec<String> = Vec::new();
        if self.redact_scan_environment {
            preselected.push(REDACT_OPT_ENV.into());
        }
        if self.redact_scan_dotenv {
            preselected.push(REDACT_OPT_FILE.into());
        }
        if self.redact_scan_ssh_keys {
            preselected.push(REDACT_OPT_SSH.into());
        }
        let lockout = self.dialog_lockout();
        self.pending_local_choice = Some(LocalChoice::RedactionToggle(interrupt_id));
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::with_preselected(
                interrupt_id,
                String::new(),
                set,
                lockout,
                &[preselected],
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    /// Resolve a closed bare-`/toggle-redaction` multiselect. `selected_ids`
    /// is the checked set (empty on a both-off confirm); `None` on Esc/cancel
    /// leaves the state untouched. Applies the selection by sending the
    /// resulting per-source booleans to the daemon.
    pub(super) fn resolve_redaction_toggle(&mut self, selected_ids: Option<&[String]>) {
        let Some(ids) = selected_ids else {
            return;
        };
        let env = ids.iter().any(|id| id == REDACT_OPT_ENV);
        let file = ids.iter().any(|id| id == REDACT_OPT_FILE);
        let ssh = ids.iter().any(|id| id == REDACT_OPT_SSH);
        self.send_redaction_toggle(Some(env), Some(file), Some(ssh));
    }

    /// Open the `/model-comparison` multiselect: every configured
    /// `(provider, model)` pair (same source as `/model`), with the **active**
    /// model excluded (no self-shadowing) and the current tandem set
    /// pre-checked (implementation note). Selecting
    /// updates the session's tandem set (session-only / in-memory). An empty
    /// confirm clears it — that is the OFF control. Driven locally (no daemon
    /// interrupt) like the bare `/toggle-redaction` picker; the close handler
    /// matches the synthetic id and routes the selection to the daemon.
    fn open_model_comparison_dialog(&mut self) {
        use crate::daemon::proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        // Load configured `(provider, model)` pairs from the effective
        // `config.json` layers; tandem models must have working url/credentials.
        let cfg = crate::secret_ref::load_effective(&self.launch.cwd);
        if cfg.providers.is_empty() {
            self.push_plain(
                "/model-comparison: no cockpit config found — run `/settings` to add a provider"
                    .to_string(),
            );
            return;
        }

        // Build the (provider, model) option list, excluding the active model.
        let active = self.launch.active_model.clone();
        let mut pairs: Vec<(String, String)> = Vec::new();
        for (pid, entry) in &cfg.providers {
            for model in &entry.models {
                let pair = (pid.clone(), model.id.clone());
                if active.as_ref() == Some(&pair) {
                    continue; // never shadow the active model itself.
                }
                pairs.push(pair);
            }
        }
        pairs.sort();
        if pairs.is_empty() {
            self.push_plain(
                "/model-comparison: no other configured models to compare against".to_string(),
            );
            return;
        }

        // Option ids are the row index (stable for this dialog instance); the
        // index→pair mapping is held so the close handler resolves the checked
        // rows back to `(provider, model)` pairs without re-parsing labels
        // (model ids can contain `/`).
        let options: Vec<InterruptOption> = pairs
            .iter()
            .enumerate()
            .map(|(i, (p, m))| InterruptOption {
                id: i.to_string(),
                label: format!("{p}/{m}"),
                description: None,
                secondary: false,
            })
            .collect();
        // Pre-check rows already in the session's tandem set.
        let preselected: Vec<String> = pairs
            .iter()
            .enumerate()
            .filter(|(_, (p, m))| self.tandem_models.contains(&format!("{p}/{m}")))
            .map(|(i, _)| i.to_string())
            .collect();

        let interrupt_id = uuid::Uuid::new_v4();
        let set = InterruptQuestionSet {
            questions: vec![InterruptQuestion::Multi {
                prompt:
                    "Tandem models to shadow every request to (session-only — reverts on restart):"
                        .to_string(),
                options,
                // A blank confirm (nothing checked) is valid — it turns the
                // feature off. No free-text custom row.
                allow_freetext: false,
            }],
        };
        let lockout = self.dialog_lockout();
        self.pending_local_choice = Some(LocalChoice::ModelComparison(interrupt_id));
        self.pending_tandem_options = pairs;
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::with_preselected(
                interrupt_id,
                String::new(),
                set,
                lockout,
                &[preselected],
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    /// Resolve a closed `/model-comparison` multiselect. `selected_ids` is the
    /// checked set of row-index ids (empty on a clear-all confirm); `None` on
    /// Esc/cancel leaves the set untouched. Maps the checked rows back to
    /// `(provider, model)` pairs and sends them to the daemon, which builds the
    /// tandem models + routes them to the driver and broadcasts the resulting
    /// state (+ token-burn warning). Empty = feature off.
    pub(super) fn resolve_model_comparison_select(&mut self, selected_ids: Option<&[String]>) {
        let options = std::mem::take(&mut self.pending_tandem_options);
        let Some(ids) = selected_ids else {
            return;
        };
        let models: Vec<(String, String)> = ids
            .iter()
            .filter_map(|id| id.parse::<usize>().ok())
            .filter_map(|i| options.get(i).cloned())
            .collect();
        if !self.send_daemon_request(crate::daemon::proto::Request::SetTandemModels { models }) {
            self.push_plain("/model-comparison: no daemon connection".to_string());
        }
    }

    /// Attach the session eagerly once the daemon is reachable so the
    /// startup graphic can show its id (session-id-display-and-lazy-persist).
    /// The attach creates a deferred (un-persisted) session in the daemon;
    /// the first user message is what writes the `sessions` row. Runs each
    /// event-loop tick.
    ///
    /// Gates (all must hold):
    /// - No live runner yet. A successful attach (`Some(Ok)`) stops the
    ///   eager loop; a poisoned `Some(Err)` from a *previous first-message*
    ///   attempt would too, so this also short-circuits then — only the
    ///   `None` state retries here.
    /// - The "daemon not running" prompt is closed — we don't spawn a
    ///   daemon out from under the user's choice.
    /// - Not daemonless. In daemonless mode there is no daemon to merely
    ///   *show* an id for; eager-attaching would spawn the owned ephemeral
    ///   daemon purely for display. The short id appears once a daemon comes
    ///   up on its own (the first message). `daemon_connected` stays true in
    ///   that mode (the `/sessions` pane needs it), so it can't be the gate.
    /// - The canonical daemon probe is allowed to start. After "Start and
    ///   connect" the just-spawned socket isn't bound for a beat; probing in
    ///   the background lets us wait quietly and attach the instant it's up
    ///   without blocking this tick.
    pub(super) fn ensure_session_for_display(&mut self) {
        // Evaluate the cheap struct-only gates first; the daemon probe is the
        // only costly check, so only start it when everything else already
        // permits an attach (`probe_when` is lazy for exactly this reason).
        let should_probe = should_attempt_display_attach(
            self.agent_runner.is_some(),
            self.daemon_prompt.is_some(),
            self.daemonless,
            self.daemon_connected,
            || true,
        );
        if should_probe && self.display_attach_backoff.can_attempt(Instant::now()) {
            self.start_display_daemon_probe_action(|| crate::daemon::discover_blocking().status);
        }
    }

    fn start_display_daemon_probe_action<F>(&mut self, work: F)
    where
        F: FnOnce() -> crate::daemon::DaemonStatus + Send + 'static,
    {
        let cwd = self.launch.cwd.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("display.daemon.probe"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("display.daemon.probe")),
            move || {
                Ok(AsyncActionPayload::DaemonProbe {
                    cwd,
                    status: work(),
                })
            },
        );
    }

    fn apply_display_daemon_probe_result(
        &mut self,
        cwd: PathBuf,
        status: crate::daemon::DaemonStatus,
    ) {
        if cwd != self.launch.cwd {
            return;
        }
        if !matches!(status, crate::daemon::DaemonStatus::Running) {
            return;
        }
        let attach = should_attempt_display_attach(
            self.agent_runner.is_some(),
            self.daemon_prompt.is_some(),
            self.daemonless,
            self.daemon_connected,
            || true,
        );
        if attach && self.display_attach_backoff.can_attempt(Instant::now()) {
            self.try_attach_for_display();
        }
    }

    /// The daemon lifecycle this TUI attaches with. Daemonless mode owns a
    /// fresh pid+nonce ephemeral daemon (`AlwaysEphemeral`); otherwise the TUI
    /// attaches to the canonical daemon, auto-promoting a persistent one if
    /// none is running.
    pub(super) fn lifecycle_mode(&self) -> crate::daemon::client::LifecycleMode {
        if self.daemonless {
            // First attach spawns our owned pid+nonce ephemeral daemon; later
            // re-attaches (`/compact`, `/sessions` resume, `/new`) reconnect
            // to that same daemon instead of spawning a second one.
            crate::daemon::client::LifecycleMode::AttachOwnEphemeral
        } else {
            crate::daemon::client::LifecycleMode::AttachOrAutoPromote
        }
    }

    /// Build the ephemeral-daemon ownership guard (and arm its signal
    /// handler) for a runner that just spawned an owned daemon. No-op when
    /// the runner attached to a daemon we don't own or a guard already
    /// exists. The signal handler hands control back to the TUI's own
    /// restore path on SIGINT/SIGTERM rather than `exit`ing outright, so the
    /// alt-screen teardown still runs.
    fn arm_daemon_guard(&mut self, runner: &AgentRunner) {
        if !runner.owns_daemon || self.daemon_guard.is_some() {
            return;
        }
        let guard =
            crate::daemon::ephemeral_guard::EphemeralDaemonGuard::new(runner.socket.clone());
        self.daemon_signal_task =
            crate::daemon::ephemeral_guard::spawn_signal_shutdown(Some(&guard), false);
        self.daemon_guard = Some(guard);
    }

    /// Spawn (or attach to) the daemon and **latch** the result —
    /// including a failure. The first-message path
    /// (`src/tui/app/input.rs`) calls this: a user-initiated submit must
    /// surface a spawn error in history, and storing `Some(Err)` keeps it
    /// visible. The opportunistic display attach uses
    /// [`Self::try_attach_for_display`] instead, which never latches an
    /// error.
    pub(super) fn ensure_agent_runner(&mut self) {
        if matches!(self.agent_runner, Some(Ok(_))) {
            return;
        }
        let runner =
            agent_runner::try_spawn(&self.launch.cwd, self.no_sandbox, self.lifecycle_mode());
        self.adopt_runner(runner);
    }

    /// Adopt a freshly-spawned runner: on success, record its identity
    /// (session id + short id for the startup graphic), seed the usage
    /// tallies, flush buffered usage records, and refresh the guidance
    /// estimate from the now-live daemon. Always stores the result (`Ok`
    /// or `Err`) so the caller's latch semantics hold. Shared by the
    /// first-message path and the eager display attach.
    fn adopt_runner(&mut self, runner: Result<AgentRunner, String>) {
        if let Ok(r) = &runner {
            let live_btw_fork = r.btw_fork.clone();
            self.reset_display_attach_backoff();
            // In daemonless mode this runner spawned our own ephemeral
            // daemon; arm the ownership guard so it's reaped on exit.
            self.arm_daemon_guard(r);
            // Record the daemon-assigned session id so the startup graphic
            // shows it and `/new` re-renders with the fresh one
            // (session-id-display-and-lazy-persist).
            self.launch.session_id = Some(r.session_id);
            self.launch.session_short_id = Some(r.short_id.clone());
            // Seed the in-memory tally from the daemon's authoritative
            // counts. Additive: any optimistic increments made before
            // attach (held in the maps) stay on top of the historical
            // counts; the daemon's value isn't double-counted because we
            // only fetch once per session.
            merge_counts(&mut self.usage_models, &r.usage.models);
            merge_counts(&mut self.usage_slash, &r.usage.slash);
            merge_counts(&mut self.usage_tags, &r.usage.tags);
            self.project_id = Some(r.project_id.clone());
            self.foreground_input_target = r.foreground_target.clone();
            self.maybe_show_daemon_version_chip(&r.daemon_version, r.daemon_compatible);
            // Flush records buffered before the runner existed,
            // backfilling tag project ids now that we know the project.
            let pid = self.project_id.clone();
            for mut req in std::mem::take(&mut self.pending_usage) {
                if let crate::daemon::proto::Request::RecordUsage {
                    kind: crate::daemon::proto::UsageKind::Tag,
                    project_id,
                    ..
                } = &mut req
                    && project_id.is_none()
                {
                    *project_id = pid.clone();
                }
                let _ = r.record_tx.try_send(req);
            }
            // Refresh the fresh-chat guidance estimate from the daemon now
            // that one is guaranteed up (lazy spawn / attach just completed).
            // The launch-time figure was a local raw-cl100k fallback computed
            // before any daemon existed; the daemon answers with the active
            // model's calibrated tokenizer and the same file-resolution the
            // engine then injects, so the indicator matches what's actually
            // sent. Best-effort: a daemon that can't answer leaves the
            // launch-time estimate in place (no regression). Targets the
            // runner's own socket so it reaches an owned pid+nonce ephemeral
            // daemon (daemonless / auto-spawn), not just the canonical one —
            // reuses the just-established daemon, no new spawn, one request.
            self.refresh_guidance_estimate_from_daemon(&r.socket);
            if let Some(info) = live_btw_fork {
                self.open_btw_pane_from_info(info, true);
            }
        }
        let refresh_skills = runner.is_ok();
        self.agent_runner = Some(runner);
        if refresh_skills {
            self.refresh_skill_commands();
        }
    }

    /// Opportunistic display attach: attach a deferred session so the
    /// welcome box can show its short id before the first message, but —
    /// unlike [`Self::ensure_agent_runner`] — **never latch a failure**. A
    /// transient `try_spawn` error (e.g. the just-started daemon's socket
    /// isn't bound yet) leaves `agent_runner = None` so the next event-loop
    /// tick retries, rather than poisoning the runner to `Some(Err)` and
    /// permanently disabling the eager display. On success the runner is
    /// the same one the first-message path then reuses (it early-returns on
    /// `is_some()`), so the id shown in the welcome box is exactly the
    /// session persisted on first message.
    fn try_attach_for_display(&mut self) {
        let runner =
            agent_runner::try_spawn(&self.launch.cwd, self.no_sandbox, self.lifecycle_mode());
        if runner.is_ok() {
            self.adopt_runner(runner);
        } else {
            self.display_attach_backoff.record_failure(Instant::now());
        }
        // On `Err`, drop it silently: leave `agent_runner` as `None` so a
        // later tick can retry once the daemon is actually reachable.
    }

    pub(super) fn reset_display_attach_backoff(&mut self) {
        self.display_attach_backoff.reset();
    }

    /// Re-fetch the fresh-chat guidance estimate from the daemon at `socket`
    /// (the attached runner's own socket) and adopt it when it carries a
    /// resolved file or a non-zero system-prompt size. Called once the lazy
    /// daemon spawn/attach completes so the indicator reflects the daemon's
    /// calibrated figure rather than staying stuck on the launch-time local
    /// fallback (which is computed before any daemon exists). A daemon that
    /// can't answer, or a degenerate all-zero/no-file reply, is ignored so a
    /// transient miss never blanks a correct local estimate. Touches only the
    /// indicator — never the cached system prompt — so the prompt cache is
    /// undisturbed.
    fn refresh_guidance_estimate_from_daemon(&mut self, socket: &Path) {
        let (provider, model) = match &self.launch.active_model {
            Some((p, m)) => (Some(p.clone()), Some(m.clone())),
            None => (None, None),
        };
        let socket = socket.to_path_buf();
        let project_root = self.launch.cwd.to_string_lossy().into_owned();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("guidance.estimate"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("guidance.estimate")),
            move || {
                let resp = agent_runner::daemon_request_at_blocking(
                    &socket,
                    crate::daemon::proto::Request::GuidanceEstimate {
                        project_root,
                        provider,
                        model,
                    },
                )?;
                match resp {
                    crate::daemon::proto::Response::GuidanceEstimate {
                        file,
                        tokens,
                        system_tokens,
                        model_instruction_tokens,
                    } if file.is_some() || system_tokens > 0 || model_instruction_tokens > 0 => Ok(
                        AsyncActionPayload::GuidanceEstimate(agent_runner::GuidanceEstimate {
                            file,
                            guidance_tokens: tokens,
                            system_tokens,
                            model_instruction_tokens,
                        }),
                    ),
                    _ => Err("empty guidance estimate".to_string()),
                }
            },
        );
    }

    /// Record one accepted autocomplete pick: bump the in-memory count
    /// optimistically (so the current session reflects it without a
    /// round-trip) and forward it to the daemon, buffering until the
    /// runner exists.
    pub(super) fn record_usage(
        &mut self,
        kind: crate::daemon::proto::UsageKind,
        key: String,
        project_id: Option<String>,
    ) {
        use crate::daemon::proto::UsageKind;
        let map = match kind {
            UsageKind::Model => &mut self.usage_models,
            UsageKind::Slash => &mut self.usage_slash,
            UsageKind::Tag => &mut self.usage_tags,
        };
        *map.entry(key.clone()).or_insert(0) += 1;
        let req = crate::daemon::proto::Request::RecordUsage {
            kind,
            key,
            project_id,
        };
        match self.agent_runner.as_ref() {
            Some(Ok(runner)) => {
                let _ = runner.record_tx.try_send(req);
            }
            _ => self.pending_usage.push(req),
        }
    }

    /// True while the current inference round is in its reasoning phase:
    /// no assistant text has started yet *and* we're either accumulating
    /// channel reasoning or mid an unclosed leading inline `<think>` block.
    /// Keyed off parser state (not `ThinkingStarted`, which fires for every
    /// round including non-thinking models), so a model that emits no
    /// reasoning never flips the indicator to yellow, while an inline
    /// `<think>` lights it on the open tag — gated on `strip_think`, since
    /// with stripping off a `<think>` tag is literal body, not reasoning.
    pub(super) fn in_thinking_block(&self) -> bool {
        self.pending.as_ref().is_some_and(|p| {
            p.text_started_at.is_none()
                && (!p.reasoning.trim().is_empty() || (p.strip_think && p.inside_think))
        })
    }

    pub(super) fn copy_sandbox_fix_command(&mut self) {
        let Some(command) = self
            .sandbox_down_notice
            .as_ref()
            .and_then(|notice| notice.fix_command.as_deref())
            .map(str::to_string)
        else {
            return;
        };
        match crate::clipboard::copy_plain(&command) {
            Ok(_) => self.show_copy_ok_or_tmux_hint("Copied sandbox fix command.".to_string()),
            Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
        }
    }

    /// Execute one of the context-menu actions. Called both when the
    /// user clicks an item and when they hit Enter on a focused item.
    /// `clicked_chat_row` is the chat-relative row that was
    /// right-clicked — used by "Copy as rich text" to find which
    /// agent message was under the click; ignored by the other
    /// actions.
    pub(super) fn execute_context_menu_action(
        &mut self,
        action: crate::tui::context_menu::ContextMenuAction,
        clicked_chat_row: usize,
    ) {
        use crate::tui::context_menu::ContextMenuAction;
        if matches!(action, ContextMenuAction::OpenInEditor) {
            let Some(path) = self
                .chat_row_meta
                .get(clicked_chat_row)
                .and_then(|meta| meta.diff_path.as_deref())
                .map(str::to_string)
            else {
                self.show_toast("No diff file under that row.", ToastKind::Info);
                return;
            };
            if std::env::var_os("EDITOR").is_none() {
                self.push_plain("Open in $EDITOR: `$EDITOR` is no longer set".to_string());
                self.show_toast("$EDITOR is no longer set.", ToastKind::Error);
                return;
            }
            self.open_editor_target(PaneSide::Full, Some(&path));
            return;
        }
        let copy_pick_target = self
            .copy_pick
            .is_some()
            .then(|| self.copy_target_text())
            .flatten();
        let Some((title, text, shape)) = copy_pick_target.or_else(|| {
            self.message_at_chat_row(clicked_chat_row)
                .map(|(title, text)| (title, text, pins::CopyShape::Message))
        }) else {
            self.show_toast("No message under that row.", ToastKind::Info);
            return;
        };
        if text.trim().is_empty() {
            self.show_toast("/copy-pick: that message has no text", ToastKind::Info);
            return;
        }
        let (msg, kind) = match action {
            ContextMenuAction::OpenInEditor => unreachable!("handled before copy actions"),
            ContextMenuAction::CopyAsRichText => {
                let rich_source = match shape {
                    pins::CopyShape::Message => text.clone(),
                    pins::CopyShape::CodeBlock => format!("```\n{text}```\n"),
                };
                let html = crate::clipboard::markdown_to_html(&rich_source);
                match crate::clipboard::copy_rich(&rich_source, &html) {
                    Ok(_) => (format!("Copied {title} as rich text."), ToastKind::Success),
                    Err(crate::clipboard::CopyError::UnsupportedOverSsh) => {
                        // Shouldn't normally happen because the menu
                        // builder hides this option over SSH, but
                        // guard anyway so a stale menu doesn't error.
                        match crate::clipboard::copy_plain(&text) {
                            Ok(_) => (
                                format!(
                                    "SSH — copied {title} as plain text \
                                     (rich-text unavailable over SSH)."
                                ),
                                ToastKind::Success,
                            ),
                            Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                        }
                    }
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            ContextMenuAction::CopyAsMarkdown => match crate::clipboard::copy_plain(&text) {
                Ok(_) => (format!("Copied {title} as markdown."), ToastKind::Success),
                Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
            },
            ContextMenuAction::CopyAsPlainText => {
                let plain = match shape {
                    pins::CopyShape::Message => crate::clipboard::markdown_to_plain(&text),
                    pins::CopyShape::CodeBlock => text.clone(),
                };
                match crate::clipboard::copy_plain(&plain) {
                    Ok(_) => (format!("Copied {title} as plain text."), ToastKind::Success),
                    Err(e) => (format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
        };
        self.show_toast(msg, kind);
        self.copy_pick = None;
    }

    /// Resolve the exact message owned by a visible chat row.
    pub(super) fn message_at_chat_row(&self, clicked_chat_row: usize) -> Option<(String, String)> {
        let meta = self.chat_row_meta.get(clicked_chat_row)?;
        let render::ChatCopyTarget::Message { history_index } = meta.copy_target?;
        match self.history.get(history_index)? {
            HistoryEntry::User { text, .. } if !text.trim().is_empty() => {
                Some(("user message".to_string(), text.clone()))
            }
            HistoryEntry::Agent { name, text, .. } if !text.trim().is_empty() => {
                Some((format!("{name} message"), text.clone()))
            }
            _ => None,
        }
    }

    /// Build the plaintext of the active drag-selection from the
    /// cached chat grid and push it to the system clipboard via
    /// `clipboard::copy_plain` (OSC52 + arboard locally). No-op when
    /// the selection is empty or stale (chat_area moved between
    /// selection and copy).
    /// On a successful copy, show the one-time-per-session tmux OSC52
    /// discoverability hint (first cockpit copy while `$TMUX` is set,
    /// independent of whether OSC52 was acknowledged); otherwise show
    /// the plain success toast.
    fn show_copy_ok_or_tmux_hint(&mut self, success_msg: String) {
        if !self.tmux_copy_hint_shown && std::env::var_os("TMUX").is_some() {
            self.tmux_copy_hint_shown = true;
            self.show_toast(
                "Copied via OSC52. If it didn't reach your clipboard, your terminal must allow OSC52 (tmux: set -g set-clipboard on).",
                ToastKind::Info,
            );
        } else {
            self.show_toast(success_msg, ToastKind::Success);
        }
    }

    pub(super) fn copy_selection_plaintext(&mut self) {
        self.copy_selection_plaintext_with(crate::clipboard::copy_plain);
    }

    fn copy_selection_plaintext_with(
        &mut self,
        copy_plain: impl FnOnce(
            &str,
        )
            -> Result<crate::clipboard::CopyOutcome, crate::clipboard::CopyError>,
    ) {
        let Some(sel) = self.selection else {
            return;
        };
        let Some(area) = self.chat_area else {
            return;
        };
        let (start, end) = sel.ordered();
        // Stale guard: if either selection endpoint is outside the
        // current chat area, the snapshot we have no longer
        // corresponds. Clear the selection and bail.
        if start.1 < area.y
            || end.1 >= area.y + area.height
            || start.0 < area.x
            || end.0 >= area.x + area.width
        {
            self.selection = None;
            return;
        }
        if self.chat_text_grid.len() != area.height as usize
            || self
                .chat_text_grid
                .iter()
                .any(|row| row.len() != area.width as usize)
        {
            return;
        }
        let text_to_copy =
            extract_selection_markdown_source(&self.history, &self.chat_row_meta, area, sel)
                .unwrap_or_else(|| {
                    extract_selection_plaintext(
                        &self.chat_text_grid,
                        &self.chat_row_meta,
                        area,
                        sel,
                    )
                });
        if text_to_copy.is_empty() {
            return;
        }
        match copy_plain(&text_to_copy) {
            Ok(_) => {
                self.show_copy_ok_or_tmux_hint(format!(
                    "Copied {} chars to clipboard.",
                    text_to_copy.chars().count()
                ));
                // Clear selection after an accepted copy — the user got
                // what they wanted; leaving it highlighted just gets in the
                // way of the next interaction.
                self.selection = None;
            }
            Err(crate::clipboard::CopyError::TooLarge { .. }) => {
                self.show_toast(
                    "Selection too large to copy over OSC52 (max ~73 KB) — copy a smaller range.",
                    ToastKind::Error,
                );
            }
            Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
        }
    }

    /// Copy the most recent agent message to the system clipboard as
    /// rich text (HTML + plain alt). Surfaces feedback via a toast
    /// (TUI-design-philosophy §7). No-op when `tui.rich_text_copy`
    /// is off or no agent messages exist.
    pub(super) fn copy_last_agent_message_as_rich_text(&mut self) {
        if !self.rich_text_copy {
            self.show_toast(
                "Rich-text copy is disabled (toggle in /settings → ui).",
                ToastKind::Info,
            );
            return;
        }
        let last_agent_text = self.history.iter().rev().find_map(|e| match e {
            HistoryEntry::Agent { text, .. } if !text.trim().is_empty() => Some(text.clone()),
            _ => None,
        });
        let Some(text) = last_agent_text else {
            self.show_toast("No agent message to copy yet.", ToastKind::Info);
            return;
        };
        let html = crate::clipboard::markdown_to_html(&text);
        match crate::clipboard::copy_rich(&text, &html) {
            Ok(_) => self
                .show_copy_ok_or_tmux_hint("Copied last agent message as rich text.".to_string()),
            Err(crate::clipboard::CopyError::UnsupportedOverSsh) => {
                // SSH session — fall back to plain text via OSC52 so
                // the user gets at least something on the local
                // clipboard.
                match crate::clipboard::copy_plain(&text) {
                    Ok(_) => self.show_copy_ok_or_tmux_hint(
                        "SSH — copied as plain text (rich-text unavailable over SSH).".to_string(),
                    ),
                    Err(crate::clipboard::CopyError::TooLarge { .. }) => self.show_toast(
                        "Selection too large to copy over OSC52 (max ~73 KB) — copy a smaller range.",
                        ToastKind::Error,
                    ),
                    Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
                }
            }
            Err(e) => self.show_toast(format!("Copy failed: {e}"), ToastKind::Error),
        }
    }

    /// Toggle every Ctrl+E reveal row: preflighted user messages reveal their
    /// original input, and compact boundaries reveal their handoff brief.
    pub(super) fn toggle_ctrl_e_reveals(&mut self) {
        let any_hidden = self.history.iter().any(|e| {
            matches!(e, HistoryEntry::User { cleaned: Some(_), expanded, .. } if !*expanded)
                || matches!(
                    e,
                    HistoryEntry::CompactBoundary {
                        handoff: Some(handoff),
                        expanded,
                        ..
                    } if !handoff.trim().is_empty() && !*expanded
                )
        });
        for entry in self.history.iter_mut() {
            match entry {
                HistoryEntry::User {
                    cleaned: Some(_),
                    expanded,
                    ..
                } => *expanded = any_hidden,
                HistoryEntry::CompactBoundary {
                    handoff: Some(handoff),
                    expanded,
                    ..
                } if !handoff.trim().is_empty() => *expanded = any_hidden,
                _ => {}
            }
        }
    }

    pub(super) fn toggle_recent_reasoning(&mut self) {
        let any_collapsed = self.history.iter().any(|entry| {
            matches!(entry,
                HistoryEntry::Agent { reasoning, expanded, .. }
                    if !reasoning.trim().is_empty() && !*expanded)
        });
        for entry in &mut self.history {
            if let HistoryEntry::Agent {
                expanded,
                reasoning,
                reasoning_offset,
                ..
            } = entry
                && !reasoning.trim().is_empty()
            {
                *expanded = any_collapsed;
                if !*expanded {
                    *reasoning_offset = 0;
                }
            }
        }
    }

    /// Push the right cursor shape to the terminal based on vim mode.
    /// Idempotent — only writes when the desired shape changes.
    pub(super) fn sync_cursor_shape(&mut self) {
        let desired = if self.composer.vim_enabled()
            && !matches!(self.composer.vim_mode(), VimMode::Insert)
        {
            CursorShape::Block
        } else {
            CursorShape::Bar
        };
        if self.last_cursor_shape == Some(desired) {
            return;
        }
        let style = match desired {
            CursorShape::Block => SetCursorStyle::SteadyBlock,
            CursorShape::Bar => SetCursorStyle::SteadyBar,
        };
        let _ = crossterm::execute!(stdout(), style);
        self.last_cursor_shape = Some(desired);
    }

    pub(super) fn sync_active_agent(&mut self) {
        let (name, path) = {
            let Some(Ok(runner)) = self.agent_runner.as_ref() else {
                return;
            };
            (
                crate::sync::lock_or_recover(&runner.active_agent).clone(),
                crate::sync::lock_or_recover(&runner.active_agent_path).clone(),
            )
        };
        let mut changed = false;
        if name != self.launch.agent_name {
            self.launch.agent_name = name;
            changed = true;
        }
        if !path.is_empty() && path != self.agent_path {
            self.agent_path = path;
        }
        if changed {
            self.refresh_skill_commands();
        }
    }

    /// Return the skill inventory visible to the current agent. Once attached,
    /// the daemon publishes names filtered against the exact live toolbox;
    /// before that point discovery uses the agent definition as a best-effort
    /// startup approximation.
    pub(super) fn visible_skills(&self) -> Vec<crate::skills::Skill> {
        let extended = crate::config::extended::load_for_cwd(&self.launch.cwd);
        let exact_names = self
            .agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .and_then(|runner| runner.skill_inventory_names.lock().unwrap().clone());
        if let Some(exact_names) = exact_names {
            crate::skills::discover(&self.launch.cwd, &extended.skills)
                .unwrap_or_default()
                .into_iter()
                .filter(|skill| exact_names.contains(&skill.frontmatter.name))
                .collect()
        } else {
            crate::skills::discover_for_agent(
                &self.launch.cwd,
                &extended.skills,
                &self.launch.agent_name,
            )
            .unwrap_or_default()
        }
    }

    /// Rebuild conditional skill slash entries after the root agent changes.
    /// The active agent's declared tool grant is the pre-spawn inventory seam;
    /// actual skill loading rechecks against the live toolbox.
    pub(super) fn refresh_skill_commands(&mut self) {
        self.skill_commands = bare_skill_commands_from(self.visible_skills());
    }

    pub(super) fn push_agent_path_child(&mut self, parent: &str, child: &str) {
        if let Some(parent_idx) = self.agent_path.iter().position(|name| name == parent) {
            self.agent_path.truncate(parent_idx + 1);
        } else {
            self.agent_path.clear();
            self.agent_path.push(self.launch.agent_name.clone());
        }
        self.agent_path.push(child.to_string());
        self.launch.agent_name = child.to_string();
        self.refresh_skill_commands();
    }

    pub(super) fn pop_agent_path_for_report(&mut self, agent: &str) {
        if let Some(agent_idx) = self.agent_path.iter().position(|name| name == agent) {
            self.agent_path.truncate(agent_idx);
        } else {
            self.agent_path.pop();
        }
        if self.agent_path.is_empty() {
            self.agent_path.push(self.launch.agent_name.clone());
        }
        if let Some(current) = self.agent_path.last() {
            self.launch.agent_name = current.clone();
            self.refresh_skill_commands();
        }
    }

    /// Bare-`/<skill-name>` sugar (implementation note):
    /// the composer holds `/<name>` optionally followed by trailing args. Seed
    /// a deterministic skill invocation, forwarding the trailing text as the
    /// task input. Tallies under the `/skill` dispatcher for frequency ranking
    /// (the bare names aren't builtins, so they share one counter). Always
    /// returns `false` (the TUI stays open).
    pub(super) fn invoke_skill_slash(&mut self, name: &str) -> bool {
        let raw = self.composer.text().to_string();
        let args = slash_args(&raw);
        self.composer.clear();
        self.paste_registry.clear();
        self.reset_slash_window();
        self.record_usage(
            crate::daemon::proto::UsageKind::Slash,
            "skill".to_string(),
            None,
        );
        let display = if args.trim().is_empty() {
            format!("/{name}")
        } else {
            format!("/{name} {}", args.trim())
        };
        self.dispatch_skill_invocation(display, name, &args);
        false
    }

    /// `/export` (default) — write the live transcript as
    /// `<stem>.json`, overwriting any prior file.
    fn export_transcript_json(&mut self, file_stem: &str, exports_dir: &Path) {
        let out_path = exports_dir.join(format!("{file_stem}.json"));
        let result = (|| -> anyhow::Result<()> {
            std::fs::create_dir_all(exports_dir).with_context(|| {
                format!("creating export directory `{}`", exports_dir.display())
            })?;
            let value = crate::tui::history::export_transcript(&self.history);
            let json = serde_json::to_string_pretty(&value)?;
            std::fs::write(&out_path, json)
                .with_context(|| format!("writing export to `{}`", out_path.display()))?;
            Ok(())
        })();
        let line = match result {
            Ok(_) => format!("Exported conversation → {}", out_path.display()),
            Err(e) => format!("/export: {e}"),
        };
        self.push_plain(line);
    }

    /// Open the project scratchpad dialog. Shared by the `/scratchpad`
    /// slash command and the Ctrl+N keyboard shortcut. The editor mirrors the
    /// composer's vim setting so vim users get vim editing in their scratchpad.
    pub(super) fn open_scratchpad_pane(&mut self) {
        self.overlay = Overlay::Notes(crate::tui::notes_pane::NotesPane::open(
            &self.launch.cwd,
            self.composer.vim_enabled(),
        ));
    }

    /// The active TUI context the which-key overlay should describe
    /// (`which-key-overlay.md`). Resolved from the live modal / pane state in
    /// the same priority order the key router uses, so the overlay always
    /// names the context whose keys are actually live. A required-decision
    /// dialog (approval / question) wins — the leader is routed *after* those
    /// handlers, so this is only ever consulted when the overlay is allowed to
    /// open, but the resolver keeps the priority explicit so the overlay shows
    /// that dialog's keys when reached via `/keys`.
    pub(super) fn key_context(&self) -> crate::tui::keys_overlay::KeyContext {
        use crate::tui::keys_overlay::KeyContext;
        if self.btw_pane.as_ref().is_some_and(|pane| pane.focused) {
            KeyContext::BtwPane
        } else if self.pane.is_some() {
            KeyContext::EmbeddedPane
        } else if let Some(dialog) = self.question_dialog.as_ref() {
            // The approval dialog is a `question`-tool interrupt rendered
            // through the same dialog widget; both are required decisions sharing
            // the question-dialog routing. A command/permission approval carries
            // a `command_detail` block and shows `y/n` decision keys, so it maps
            // to the dedicated `ApprovalDialog` context; every other interrupt is
            // a plain `QuestionDialog`.
            if dialog.is_approval() {
                KeyContext::ApprovalDialog
            } else {
                KeyContext::QuestionDialog
            }
        } else if self.dialog.is_active() {
            KeyContext::Settings
        } else if let Some(context) = self.overlay.key_context() {
            context
        } else if self.pins_review.is_some()
            || self.pin_pick.is_some()
            || self.fork_pick.is_some()
            || self.copy_pick.is_some()
        {
            KeyContext::Pins
        } else if self.slash_query().is_some() {
            KeyContext::SlashMenu
        } else {
            KeyContext::Composer
        }
    }

    /// Open (or, when already open, close) the which-key overlay over the
    /// current context (`which-key-overlay.md`). The leader key and `/keys`
    /// both route here. Pure TUI state: nothing is sent to the agent and
    /// nothing enters history or any inference request.
    pub(super) fn toggle_keys_overlay(&mut self) {
        if self.keys_overlay.is_some() {
            self.keys_overlay = None;
            return;
        }
        let context = self.key_context();
        self.keys_overlay = Some(
            crate::tui::keys_overlay::KeysOverlay::open_with_keyboard_enhancement(
                context,
                self.keyboard_enhancement_active,
            ),
        );
    }

    /// `/export debug` (hidden) — write the full CLI bundle `.zip` for
    /// the current session, overwriting any prior file. Reads the DB
    /// directly (like the CLI) so it works regardless of daemon state,
    /// reusing the single shared zip-assembly implementation.
    fn export_debug_bundle(&mut self, session_id: uuid::Uuid, file_stem: &str, exports_dir: &Path) {
        let out_path = exports_dir.join(format!("{file_stem}.zip"));
        let result = (|| -> anyhow::Result<crate::commands::export::BundleSummary> {
            let db = crate::db::Db::open_default()?;
            let target = db
                .get_session(session_id)?
                .ok_or_else(|| anyhow::anyhow!("session `{session_id}` not found in the DB"))?;
            // Unconditional overwrite (the TUI has no `--force`); this
            // does not weaken the CLI's no-clobber-without-`--force`
            // guarantee, which lives in `commands::export::run`.
            crate::commands::export::write_bundle_zip(&db, &target, &out_path, true, false, false)
        })();
        let line = match result {
            Ok(summary) => format!(
                "Exported debug bundle ({} session{}, {} bytes) → {}",
                summary.session_count,
                if summary.session_count == 1 { "" } else { "s" },
                summary.byte_len,
                out_path.display()
            ),
            Err(e) => format!("/export debug: {e}"),
        };
        self.push_plain(line);
    }

    /// Re-read launch info (provider/model/favorite) from disk and
    /// keep the cwd + repo_status we already have.
    pub(super) fn reload_launch_info(&mut self) {
        // Skip the synchronous git fetch: the freshly-loaded `repo_status`
        // is discarded below in favor of the live polled one, so re-running
        // `git status` here is pure waste.
        let LaunchBundle {
            launch: mut fresh,
            providers,
            extended,
        } = welcome::load_bundle(Some(&self.launch.cwd), false);
        // Don't clobber the live repo status — it's maintained by the
        // background poller and is fresher than a re-read here.
        fresh.repo_status = self.launch.repo_status.clone();
        if let Some(active_agent) = self.agent_path.last() {
            fresh.agent_name = active_agent.clone();
        }
        self.llm_mode =
            resolve_tui_llm_mode(fresh.active_model.as_ref(), extended.llm_mode, &providers);
        self.launch = fresh;
    }

    /// Re-read the TUI-side config (vim mode, thinking display,
    /// markdown rendering) so changes made via `/settings` take effect
    /// immediately on dialog close.
    pub(super) fn reload_tui_config(&mut self) {
        let extended = crate::config::extended::load_for_cwd(&self.launch.cwd);
        let tui_cfg = extended.tui.clone();
        self.vim_setting = tui_cfg.vim_mode;
        self.thinking_setting = tui_cfg.thinking;
        self.markdown_opts = MarkdownOpts {
            agent: tui_cfg.render_agent_markdown,
            user: tui_cfg.render_user_markdown,
        };
        self.diff_style = tui_cfg.diff_style;
        self.exit_tail_lines = tui_cfg.exit_tail_lines;
        self.rich_text_copy = tui_cfg.rich_text_copy;
        self.use_emojis = tui_cfg.use_emojis;
        // Attention notification settings (implementation note):
        // pick up a `/settings` change so it takes effect immediately. The
        // debounce state intentionally survives — toggling the setting
        // shouldn't reset the burst-suppression window.
        self.attention = tui_cfg.attention;
        // The predict-next-message setting lives at the extended-config
        // root (not in `tui`); reload it so a `/settings` change takes
        // effect on subsequent turns. Turning it `off` also drops any
        // pending ghost/cache immediately.
        let predict_setting = extended.predict_next_message;
        self.predict_setting = predict_setting;
        if !predict_setting.is_enabled() {
            self.prediction_state.clear();
        }
        // Note: mouse_capture is *not* synced here. The live terminal
        // state is reconciled via the dialog's pending-flag drain
        // (see sync_mouse_capture_from_dialog) so we don't reapply
        // EnableMouseCapture on every reload — only when the user
        // actually toggled the setting.
        let vim_enabled = self.vim_setting.vim_enabled();
        if self.composer.vim_enabled() != vim_enabled {
            self.composer.set_vim_enabled(vim_enabled);
            // Mode stays whatever the composer was in; if vim flipped
            // off the composer will treat further input as Insert.
        }
    }

    /// Kick off a non-interactive cross-provider `/models` refresh.
    /// Lines land in `fetch_models_progress`; the event loop drains
    /// them into history.
    pub(super) fn spawn_fetch_models(&mut self) {
        use crate::commands::fetch_models::persist_provider;
        use crate::config::providers::{
            ModelMergePolicy, OnUnlistedModelsFetch, merge_fetched_models_with_policy,
            redact_model_fetch_reason,
        };
        use crate::providers::models_fetch::{self, FetchOutcome};
        use std::time::Duration;

        let cwd = self.launch.cwd.clone();
        let progress = Arc::clone(&self.fetch_models_progress);
        self.push_plain("/fetch-models: starting provider model refresh…".to_string());

        tokio::spawn(async move {
            let push = |lines: &Arc<Mutex<Vec<String>>>, s: String| {
                if let Ok(mut g) = lines.lock() {
                    g.push(s);
                }
            };

            let mut cfg = crate::secret_ref::load_effective(&cwd);
            let policy = cfg
                .on_unlisted_models_fetch
                .unwrap_or(OnUnlistedModelsFetch::Keep);

            if cfg.providers.is_empty() {
                push(
                    &progress,
                    "/fetch-models: no providers configured for provider models".into(),
                );
                return;
            }

            let ids: Vec<String> = cfg.providers.keys().cloned().collect();
            for id in &ids {
                let entry = cfg.providers.get(id).cloned().unwrap();
                let resolved = match models_fetch::resolve_provider_request_async(id, &entry).await
                {
                    Ok(r) => r,
                    Err(e) => {
                        push(&progress, format!("/fetch-models: {id} skipped — {e}"));
                        continue;
                    }
                };
                match models_fetch::fetch_models_for_provider(
                    id,
                    &entry,
                    &resolved,
                    Duration::from_secs(15),
                )
                .await
                {
                    Ok(FetchOutcome::Models {
                        models: remote,
                        catalog,
                    }) => {
                        let n = remote.len();
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        let merge_policy = match policy {
                            OnUnlistedModelsFetch::Keep => ModelMergePolicy::KeepUnlisted,
                            OnUnlistedModelsFetch::Remove | OnUnlistedModelsFetch::Ask => {
                                ModelMergePolicy::RemoveUnlisted
                            }
                        };
                        entry_mut.models = merge_fetched_models_with_policy(
                            entry_mut.effective_template(id),
                            &entry_mut.models,
                            remote,
                            merge_policy,
                        );
                        entry_mut.models_fetched_at = Some(chrono::Utc::now());
                        entry_mut.model_catalog = catalog;
                        entry_mut.mark_model_fetch_success(catalog);
                        match persist_provider(&cwd, id, entry_mut.clone()) {
                            Ok(_) => {
                                let suffix = if matches!(
                                    catalog,
                                    crate::config::providers::ProviderModelCatalog::CodexFallback
                                ) {
                                    " (fallback catalog)"
                                } else {
                                    ""
                                };
                                push(
                                    &progress,
                                    format!(
                                        "/fetch-models: provider {id} → {n} provider model(s){suffix}"
                                    ),
                                )
                            }
                            Err(e) => {
                                push(&progress, format!("/fetch-models: {id} write failed: {e}"))
                            }
                        }
                    }
                    Ok(FetchOutcome::FallbackAvailable { reason, .. }) => {
                        let reason = redact_model_fetch_reason(reason);
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        entry_mut.mark_model_fetch_failed_kept_existing(reason.clone());
                        let _ = persist_provider(&cwd, id, entry_mut.clone());
                        push(
                            &progress,
                            format!(
                                "/fetch-models: provider {id} live catalog fetch failed; kept existing provider catalog; fallback available from provider settings: {reason}"
                            ),
                        );
                    }
                    Ok(FetchOutcome::Unsupported) => {
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        entry_mut.mark_model_fetch_unsupported();
                        let _ = persist_provider(&cwd, id, entry_mut.clone());
                        push(
                            &progress,
                            format!("/fetch-models: provider {id} has no /models endpoint"),
                        );
                    }
                    Err(e) => {
                        let reason = redact_model_fetch_reason(e.to_string());
                        let entry_mut = cfg.providers.get_mut(id).unwrap();
                        entry_mut.mark_model_fetch_failed_kept_existing(reason.clone());
                        let _ = persist_provider(&cwd, id, entry_mut.clone());
                        push(
                            &progress,
                            format!("/fetch-models: provider {id} failed: {reason}"),
                        );
                    }
                }
            }

            push(
                &progress,
                "/fetch-models: provider model refresh done".into(),
            );
        });
    }
}

fn editor_argv_for_cwd(editor: &std::ffi::OsStr, cwd: &std::path::Path) -> Vec<String> {
    let mut argv = crate::tui::pty::shell_split(&editor.to_string_lossy());
    if !argv.is_empty() {
        argv.push(cwd.to_string_lossy().into_owned());
    }
    argv
}

fn editor_argv_for_target(editor: &std::ffi::OsStr, target: &str) -> Vec<String> {
    let mut argv = crate::tui::pty::shell_split(&editor.to_string_lossy());
    if !argv.is_empty() {
        argv.push(target.to_string());
    }
    argv
}

/// Pull `(path, old, new)` out of an edit tool's args. Returns
/// `None` when any field is missing; the caller falls back to the
/// generic Plain rendering in that case.
fn entry_to_plain_lines(entry: &HistoryEntry) -> Vec<String> {
    match entry {
        HistoryEntry::Plain { line }
        | HistoryEntry::CommandError { line }
        | HistoryEntry::Maintenance { line } => vec![line.clone()],
        HistoryEntry::InterruptDecision { decision } => decision
            .lines
            .iter()
            .map(|line| {
                let answer = if decision.cancelled {
                    "dismissed"
                } else {
                    line.answer.as_str()
                };
                let prefix = if decision.permission {
                    "approval"
                } else {
                    "decision"
                };
                format!("{prefix}: {} → {answer}", line.prompt)
            })
            .collect(),
        HistoryEntry::InferenceError {
            summary,
            detail,
            expanded,
        } => {
            let mut out = vec![summary.clone()];
            if *expanded {
                let body = if detail.trim().is_empty() {
                    "No additional inference detail was recorded."
                } else {
                    detail.as_str()
                };
                for line in body.lines() {
                    out.push(format!("  {line}"));
                }
            }
            out
        }
        HistoryEntry::BackupWarning { line } | HistoryEntry::InferenceWarning { line } => {
            vec![line.clone()]
        }
        HistoryEntry::LocalCommand { label, output, .. } => {
            let mut out = vec![label.clone()];
            for line in output.lines() {
                out.push(format!("  {line}"));
            }
            out
        }
        HistoryEntry::ToolLine { tool, summary, .. } => {
            let (_, label) = crate::tui::history::tool_glyph_label(tool, false);
            vec![format!("  {label}: {summary}")]
        }
        HistoryEntry::ToolBox { calls, .. } => calls
            .iter()
            .map(|c| {
                let (_, label) = crate::tui::history::tool_glyph_label(&c.tool, false);
                format!("  {label}: {}", c.summary)
            })
            .collect(),
        HistoryEntry::Diff {
            tool,
            path,
            old,
            new,
        } => {
            // Plain-lines is what the "spill to scrollback" path uses
            // on `/new`. Reduce the diff to a tool-result-style
            // summary plus the textual diff body in unified form —
            // anything fancier would need ratatui Lines which the
            // plain-text dump can't render.
            let added = new.lines().count();
            let removed = old.lines().count();
            let mut out = vec![format!("  ✓ {tool}: {path} (+{added} −{removed})")];
            let diff = similar::TextDiff::from_lines(old.as_str(), new.as_str());
            for group in diff.grouped_ops(3) {
                if out.len() > 1 {
                    out.push("    …".to_string());
                }
                for op in group {
                    for change in diff.iter_changes(&op) {
                        let v = change.value().trim_end_matches('\n');
                        let prefix = match change.tag() {
                            similar::ChangeTag::Delete => "- ",
                            similar::ChangeTag::Insert => "+ ",
                            similar::ChangeTag::Equal => "  ",
                        };
                        out.push(format!("  {prefix}{v}"));
                    }
                }
            }
            out
        }
        HistoryEntry::User {
            text, timestamp, ..
        } => {
            let ts = timestamp.format("%H:%M").to_string();
            let mut out: Vec<String> = vec![format!("[{ts}] you:")];
            for line in text.split('\n') {
                out.push(format!("  {line}"));
            }
            out
        }
        HistoryEntry::UserNote {
            text, timestamp, ..
        } => {
            let ts = timestamp.format("%H:%M").to_string();
            let mut out: Vec<String> = vec![format!("[{ts}] note to self:")];
            for line in text.split('\n') {
                out.push(format!("  {line}"));
            }
            out
        }
        HistoryEntry::SkillAutoInjected { name, reason } => {
            let mut out = vec![format!("/{name} · injected by agent")];
            if let Some(r) = reason {
                out.push(format!("  └ {r}"));
            }
            out
        }
        HistoryEntry::Agent {
            name,
            text,
            reasoning,
            timestamp,
            expanded,
            ..
        } => {
            let ts = timestamp.format("%H:%M").to_string();
            let mut out: Vec<String> = vec![format!("[{ts}] {name}:")];
            if !reasoning.trim().is_empty() && *expanded {
                out.push("  thinking:".to_string());
                for raw in reasoning.lines() {
                    out.push(format!("    {raw}"));
                }
                out.push(String::new());
            }
            // A think-only turn has empty body text — emit just the
            // header (+ reasoning when expanded), never a blank body line.
            if !text.trim().is_empty() {
                for line in text.split('\n') {
                    out.push(format!("  {line}"));
                }
            }
            out
        }
        HistoryEntry::Subagent {
            parent,
            child,
            outcome,
            ..
        } => match outcome {
            // A still-running delegation spilled on `/new`: record the
            // delegation line without the (now-meaningless) live timer.
            None => vec![format!("{parent} delegated to {child}…")],
            Some(o) => {
                let verb = if o.failed {
                    "failed after"
                } else {
                    "worked for"
                };
                let header = format!(
                    "{child} {verb} {}",
                    crate::tui::history::format_compact_duration(o.duration)
                );
                let mut out = vec![header];
                if let Some(status) = &o.status {
                    out.push(format!("  {status}"));
                }
                for line in o.report.lines() {
                    out.push(format!("  {line}"));
                }
                out
            }
        },
        HistoryEntry::CompactBoundary {
            predecessor_short_id,
            seed_tool_count,
            source,
            tokens_before,
            tokens_after,
            tail_kept,
            tail_trimmed,
            handoff,
            expanded,
            ..
        } => {
            let mut lines = vec![format!(
                "compact: source={source} · from {predecessor_short_id} · tokens {tokens_before}→{tokens_after} · tail {tail_kept} kept/{tail_trimmed} trimmed · {seed_tool_count} seed-tool(s)"
            )];
            if *expanded
                && let Some(handoff) = handoff.as_deref().map(str::trim).filter(|s| !s.is_empty())
            {
                lines.extend(handoff.lines().map(|line| format!("    {line}")));
            }
            lines
        }
    }
}

/// Resolve the answering-dialog config (GOALS §3b) from the effective layered
/// `config.json`. Used to read the anti-misfire lockout delay.
fn load_dialog_config(cwd: &Path) -> crate::config::extended::DialogConfig {
    crate::config::extended::load_for_cwd(cwd).dialog
}

/// Background task that polls `git status` every `GIT_REFRESH_INTERVAL`
/// without blocking the event-loop thread. The result lands in `shared`;
/// the event loop reads it on the next tick.
fn spawn_git_refresh(
    cwd: std::path::PathBuf,
    shared: Arc<Mutex<Option<RepoStatus>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(GIT_REFRESH_INTERVAL);
        // Do NOT skip the first tick: `App::new` no longer fetches git
        // status synchronously (it would block the first frame in a giant
        // repo), so this background poller owns the initial fetch too. The
        // first `interval.tick()` completes immediately, populating the
        // branch pill a tick after launch; subsequent ticks refresh on
        // `GIT_REFRESH_INTERVAL`.
        loop {
            interval.tick().await;
            let cwd = cwd.clone();
            let status = tokio::task::spawn_blocking(move || git::repo_status(&cwd).ok().flatten())
                .await
                .unwrap_or(None);
            if let Ok(mut guard) = shared.lock() {
                *guard = status;
            }
        }
    })
}

#[cfg(test)]
mod async_action_app_tests;
#[cfg(test)]
mod attention_interrupt_surface_tests;
#[cfg(test)]
mod caffeinate_toast_tests;
#[cfg(test)]
mod copy_cmd_tests;
#[cfg(test)]
mod ctrl_c_tests;
#[cfg(test)]
mod display_attach_backoff_tests;
#[cfg(test)]
mod display_attach_gate_tests;
#[cfg(test)]
mod event_loop_redraw_tests;
#[cfg(test)]
mod failed_dispatch_reconciliation_tests;
#[cfg(test)]
mod footer_selector_tests;
#[cfg(test)]
mod fork_attach_retry_tests;
#[cfg(test)]
mod fresh_queue_ack_tests;
#[cfg(test)]
mod gitignore_session_allow_tests;
#[cfg(test)]
mod inline_think_cache_tests;
#[cfg(test)]
mod keys_overlay_tests;
#[cfg(test)]
mod local_cmd_tests;
#[cfg(test)]
mod model_picker_input_tests;
#[cfg(test)]
mod prediction_lifecycle_tests;
#[cfg(test)]
mod prediction_turn_assembly_tests;
#[cfg(test)]
mod preflight_in_progress_tests;
#[cfg(test)]
mod reasoning_toggle_key_tests;
#[cfg(test)]
mod resume_history_conversion_tests;
#[cfg(test)]
mod sandbox_notice_tests;
#[cfg(test)]
mod session_schedule_tests;
#[cfg(test)]
mod skill_auto_injected_tests;
#[cfg(test)]
mod slash_rank_tests;
#[cfg(test)]
mod startup_first_paint_tests;
#[cfg(test)]
mod subagent_settle_tests;
#[cfg(test)]
mod vim_mouse_pending_state_tests;
#[cfg(test)]
mod working_msg_tests;
#[cfg(test)]
mod working_span_lifecycle_tests;
