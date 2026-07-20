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

mod agent_inventory;
mod async_actions;
mod attach_lifecycle;
mod attention;
mod btw_pane;
mod config_reload;
mod copy_actions;
mod events;
mod exit_tail;
mod export_actions;
pub(in crate::tui) mod help_overlay;
mod input;
mod local_commands;
mod model_controls;
mod models_refresh;
mod mouse;
mod overlay_actions;
mod panes;
mod pins;
mod prediction;
mod render;
mod resume;
mod session_services;
mod side_conversation;
mod slash;
mod startup_layout;
mod subagent_view;
mod terminal_controls;
mod terminal_display;
mod toggles;
mod transcript_toggles;

use events::{
    GIT_AGENT_TOKEN_CAP, WORKING_MESSAGES, cache_config_caches, cap_display_lines, cap_tokens,
    exec_capture_git, exec_capture_shell, format_schedule_line, merge_counts, new_pending,
    parse_llm_mode_arg, sanitize_for_raw_stdout, session_schedule_ids, strip_ansi,
    turns_from_history, wire_history_to_entries, xml_escape,
};
#[cfg(test)]
use events::{
    LOCAL_CMD_DISPLAY_LINES, RunCaptureOptions, SubagentReportUpdate, SubagentRoutingUpdate,
    amend_subagent_routing_in, pick_working_msg, run_capture_with_options, settle_subagent_in,
    tool_invocation,
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
use cockpit_config::extended::{DiffStyle, ThinkingDisplay, VimModeSetting};
use cockpit_core::engine::message::{QueueTarget, QueuedUserMessage};
use cockpit_core::engine::{
    ControlRequestId, ControlRequestNotDelivered, ControlRequestOutcome, TurnEvent,
};
use cockpit_core::git::{self, RepoStatus};
use cockpit_core::welcome::{self, LaunchBundle, LaunchInfo};

const GIT_REFRESH_INTERVAL: Duration = Duration::from_secs(1);
const ANIMATION_TICK: Duration = Duration::from_millis(100);
const SESSION_SWITCH_SPINNER_THRESHOLD: Duration = Duration::from_millis(150);
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
#[cfg(test)]
mod control_request_tests;
#[cfg(test)]
mod first_run_tests;

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
    fn new(current: cockpit_config::extended::LlmMode) -> Self {
        Self {
            cursor: footer_mode_index(current),
        }
    }

    fn selected_mode(self) -> cockpit_config::extended::LlmMode {
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingControlRequest {
    label: String,
    applied: ControlApplied,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlApplied {
    None,
    CacheBreakWarning,
    PrimaryAgentSwitch { name: String },
    Multireview { kickoff: String },
    QuickActiveModel { provider: String, model: String },
    ScheduleCancel { command: String, job_id: String },
    PinContext { text: String },
}

#[derive(Debug, Clone)]
pub enum StartupWorkspaceTrust {
    Decided,
    Pending(cockpit_config::trust::TrustRoot),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FirstRunFlow {
    None,
    AwaitProvider,
    AwaitModel,
}

struct StartupDaemonState {
    prompt: Option<crate::tui::daemon_prompt::DaemonPromptDialog>,
    connected: bool,
    socket: Option<std::path::PathBuf>,
    daemonless: bool,
    notice: Option<String>,
}

const FOOTER_MODE_ORDER: [cockpit_config::extended::LlmMode; 3] = [
    cockpit_config::extended::LlmMode::Defensive,
    cockpit_config::extended::LlmMode::Normal,
    cockpit_config::extended::LlmMode::Frontier,
];

fn footer_mode_index(mode: cockpit_config::extended::LlmMode) -> usize {
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
    global: cockpit_config::extended::LlmMode,
    providers: &cockpit_config::providers::ProvidersConfig,
) -> cockpit_config::extended::LlmMode {
    let Some((provider, model)) = active_model else {
        return global;
    };
    providers.resolve_mode(provider, model, global)
}

fn persist_trusted_only_default(cwd: &Path, enabled: bool) -> anyhow::Result<()> {
    use cockpit_config::dirs::{CONFIG_FILE, discover_config_dirs};
    use cockpit_config::extended::ExtendedConfigDoc;

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

const DAEMON_AUTOSTART_NOTICE_FLAG: &str = "daemon-autostart-notice-v1";

fn startup_daemon_state(
    autostart: cockpit_config::extended::DaemonAutostart,
    db: Option<&cockpit_db::Db>,
) -> StartupDaemonState {
    let notice_seen = db
        .and_then(|db| db.app_flag_seen(DAEMON_AUTOSTART_NOTICE_FLAG).ok())
        .unwrap_or(false);
    match cockpit_core::daemon::DaemonPaths::resolve() {
        Ok(paths) if paths.ephemeral => match cockpit_core::daemon::probe_blocking(&paths) {
            cockpit_core::daemon::DaemonStatus::Running => StartupDaemonState {
                prompt: None,
                connected: true,
                socket: Some(paths.socket.clone()),
                daemonless: false,
                notice: None,
            },
            status => daemon_not_running_state(status, paths, autostart, db, notice_seen),
        },
        Ok(_) => {
            let probe = cockpit_core::daemon::discover_blocking();
            match probe.status {
                cockpit_core::daemon::DaemonStatus::Running => StartupDaemonState {
                    prompt: None,
                    connected: true,
                    socket: Some(probe.paths.socket.clone()),
                    daemonless: false,
                    notice: None,
                },
                status => daemon_not_running_state(status, probe.paths, autostart, db, notice_seen),
            }
        }
        Err(_) => StartupDaemonState {
            prompt: None,
            connected: false,
            socket: None,
            daemonless: false,
            notice: None,
        },
    }
}

fn daemon_not_running_state(
    status: cockpit_core::daemon::DaemonStatus,
    paths: cockpit_core::daemon::DaemonPaths,
    autostart: cockpit_config::extended::DaemonAutostart,
    db: Option<&cockpit_db::Db>,
    notice_seen: bool,
) -> StartupDaemonState {
    daemon_not_running_state_with_spawn(status, paths, autostart, db, notice_seen, || {
        cockpit_core::daemon::spawn_detached(false)
    })
}

fn daemon_not_running_state_with_spawn(
    status: cockpit_core::daemon::DaemonStatus,
    paths: cockpit_core::daemon::DaemonPaths,
    autostart: cockpit_config::extended::DaemonAutostart,
    db: Option<&cockpit_db::Db>,
    notice_seen: bool,
    spawn_shared: impl FnOnce() -> anyhow::Result<u32>,
) -> StartupDaemonState {
    match autostart {
        cockpit_config::extended::DaemonAutostart::Ask => StartupDaemonState {
            prompt: Some(crate::tui::daemon_prompt::DaemonPromptDialog::new(
                status, paths,
            )),
            connected: false,
            socket: None,
            daemonless: false,
            notice: None,
        },
        cockpit_config::extended::DaemonAutostart::Private => StartupDaemonState {
            prompt: None,
            connected: true,
            socket: None,
            daemonless: true,
            notice: daemon_autostart_notice(
                db,
                notice_seen,
                "started a private cockpit daemon for this window only",
            ),
        },
        cockpit_config::extended::DaemonAutostart::Shared => match spawn_shared() {
            Ok(pid) => StartupDaemonState {
                prompt: None,
                connected: true,
                socket: Some(paths.socket.clone()),
                daemonless: false,
                notice: daemon_autostart_notice(
                    db,
                    notice_seen,
                    &format!(
                        "started the cockpit daemon (pid {pid}) — persists across windows; `cockpit daemon stop` to stop"
                    ),
                ),
            },
            Err(error) => {
                let mut prompt = crate::tui::daemon_prompt::DaemonPromptDialog::new(status, paths);
                prompt.set_error(format!("failed to spawn daemon: {error}"));
                StartupDaemonState {
                    prompt: Some(prompt),
                    connected: false,
                    socket: None,
                    daemonless: false,
                    notice: None,
                }
            }
        },
    }
}

fn daemon_autostart_notice(
    db: Option<&cockpit_db::Db>,
    notice_seen: bool,
    text: &str,
) -> Option<String> {
    if notice_seen {
        return None;
    }
    let db = db?;
    let _ = db.mark_app_flag_seen(DAEMON_AUTOSTART_NOTICE_FLAG);
    Some(text.to_string())
}

impl App {
    pub(super) fn apply_workspace_trust_choice(
        &mut self,
        root: cockpit_config::trust::TrustRoot,
        mode: cockpit_db::workspace_trust::WorkspaceTrustMode,
    ) -> bool {
        let Some(db) = self.startup_background.db.clone() else {
            self.show_toast("workspace trust could not be saved", ToastKind::Error);
            return false;
        };
        if let Err(error) = db.set_workspace_trust(&root.root, mode) {
            self.show_toast(
                format!("workspace trust could not be saved: {error}"),
                ToastKind::Error,
            );
            return false;
        }
        if mode == cockpit_db::workspace_trust::WorkspaceTrustMode::Untrusted {
            self.push_plain(format!(
                "workspace {} is untrusted and cannot be opened",
                root.root.display()
            ));
            return true;
        }
        if let Err(error) = cockpit_config::trust::apply_trusted_workspace(root, mode) {
            self.show_toast(format!("workspace trust failed: {error}"), ToastKind::Error);
            return false;
        }
        if mode == cockpit_db::workspace_trust::WorkspaceTrustMode::Trust {
            self.reload_launch_info();
            self.reload_tui_config();
        }
        self.dialog = Dialog::None;
        if self.daemon_prompt.is_none() {
            self.maybe_open_add_provider_wizard();
        }
        false
    }
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
    pub(super) state: cockpit_core::daemon::proto::ResumeRepairState,
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
    /// A session switch is in flight; sending now would target the outgoing
    /// daemon attachment.
    SessionSwitching,
    /// No runner present (`None`) — nothing was started.
    NoRunner,
}

pub(super) struct PendingSessionSwitchSubmission {
    pub submission: cockpit_core::engine::message::UserSubmission,
    pub error_prefix: String,
    pub optimistic_tag_entries: usize,
    pub owns_working_span: bool,
    pub queued_text: Option<String>,
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
                | DispatchOutcome::SessionSwitching
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
        DispatchOutcome::SessionSwitching => {
            format!("{prefix}: session switch in progress — try again in a moment")
        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct CommandCapabilityNotice {
    pub text: String,
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

fn command_capability_notice_text(
    text: &str,
    fix_command: Option<&str>,
    copy_chip: bool,
) -> String {
    if copy_chip && fix_command.is_some() {
        format!("[copy] ⚠ {text}")
    } else {
        format!("⚠ {text}")
    }
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
    db: Option<cockpit_db::Db>,
    started: bool,
}

#[allow(private_interfaces)]
pub struct App {
    pub(super) launch: LaunchInfo,
    pub(super) active_model_state_generation: u64,
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
    /// User submissions accepted by the TUI while a session switch is in
    /// flight. They are held locally until the new daemon attachment is
    /// accepted, so they cannot be sent to the outgoing session.
    pub(super) pending_session_switch_submissions: Vec<PendingSessionSwitchSubmission>,
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
    pub(super) daemon_guard: Option<cockpit_core::daemon::ephemeral_guard::EphemeralDaemonGuard>,
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
    pub(super) last_usage: Option<cockpit_core::tokens::TokenUsage>,
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
    pub(super) llm_mode: cockpit_config::extended::LlmMode,
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
    /// TUI-issued daemon control requests awaiting a response-bearing ack.
    pub(super) pending_control_requests: HashMap<ControlRequestId, PendingControlRequest>,
    pub(super) next_control_request_seq: u64,
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
    pub(super) pending_usage: Vec<cockpit_core::daemon::proto::Request>,
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
    pub(super) sandbox_mode: cockpit_core::tools::sandbox_mode::SandboxMode,
    pub(super) container_network_enabled: bool,
    pub(super) container_availability: cockpit_core::container::ContainerAvailability,
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
    pub(super) command_capability_notice: Option<CommandCapabilityNotice>,
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
    pub(super) approval_mode: cockpit_config::extended::ApprovalMode,
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
    pub(super) org_sync_disclosure: Option<cockpit_db::org_sync::OrgSyncDisclosure>,
    /// Persisted/daemon-broadcast remote connector status. Drives the additive
    /// remote-access chrome slot while connector access is enabled.
    pub(super) connector_disclosure: Option<cockpit_db::connector::ConnectorDisclosure>,
    has_no_providers_at_startup: bool,
    first_run_flow: FirstRunFlow,
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
    pub(super) predict_setting: cockpit_config::extended::PredictNextMessage,
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

fn idle_reason_status(reason: cockpit_core::engine::IdleReason) -> Option<IdleReasonStatus> {
    match reason {
        cockpit_core::engine::IdleReason::Completed => None,
        cockpit_core::engine::IdleReason::GoalComplete => Some(IdleReasonStatus {
            text: "goal session completed".to_string(),
            kind: ToastKind::Success,
        }),
        cockpit_core::engine::IdleReason::NeedsIntervention { code } => Some(IdleReasonStatus {
            text: format!("goal stalled ({code}) — run `/goal resume` or send guidance"),
            kind: ToastKind::Warning,
        }),
        cockpit_core::engine::IdleReason::BudgetLimited => Some(IdleReasonStatus {
            text: "goal paused: token budget reached — run `/goal resume` or adjust budget"
                .to_string(),
            kind: ToastKind::Warning,
        }),
        cockpit_core::engine::IdleReason::UsageLimited => Some(IdleReasonStatus {
            text: "usage limit — auto-resuming shortly".to_string(),
            kind: ToastKind::Warning,
        }),
        cockpit_core::engine::IdleReason::Error { class } => Some(IdleReasonStatus {
            text: format!("turn stopped on {class} — inspect the error and retry"),
            kind: ToastKind::Error,
        }),
        cockpit_core::engine::IdleReason::Interrupted => Some(IdleReasonStatus {
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
        Self::new_inner(project, no_sandbox, None, StartupWorkspaceTrust::Decided)
    }

    #[cfg(test)]
    pub fn new_with_db(project: Option<&Path>, no_sandbox: bool, db: cockpit_db::Db) -> Self {
        Self::new_inner(
            project,
            no_sandbox,
            Some(db),
            StartupWorkspaceTrust::Decided,
        )
    }

    pub fn new_with_db_and_workspace_trust(
        project: Option<&Path>,
        no_sandbox: bool,
        db: cockpit_db::Db,
        trust: StartupWorkspaceTrust,
    ) -> Self {
        Self::new_inner(project, no_sandbox, Some(db), trust)
    }

    pub fn new_with_db_and_session(
        project: Option<&Path>,
        no_sandbox: bool,
        db: cockpit_db::Db,
        session_id: uuid::Uuid,
    ) -> Self {
        let mut app = Self::new_inner(
            project,
            no_sandbox,
            Some(db),
            StartupWorkspaceTrust::Decided,
        );
        app.launch.session_id = Some(session_id);
        app
    }

    pub fn set_startup_workspace_trust(&mut self, trust: StartupWorkspaceTrust) {
        if let StartupWorkspaceTrust::Pending(root) = trust {
            self.dialog = Dialog::open_workspace_trust(root);
        }
    }

    fn new_inner(
        project: Option<&Path>,
        no_sandbox: bool,
        startup_db: Option<cockpit_db::Db>,
        startup_trust: StartupWorkspaceTrust,
    ) -> Self {
        let mut timer = cockpit_core::startup::PhaseTimer::start("App::new");
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

        // Probe the daemon synchronously up front so startup can either
        // autostart it per config or show the ask-mode/failure prompt on the
        // first frame.
        let daemon_state = startup_daemon_state(extended.daemon.autostart, startup_db.as_ref());
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
            active_model_state_generation: 0,
            composer,
            vim_setting,
            thinking_setting,
            markdown_opts,
            diff_style,
            use_emojis,
            pending_edit_args: HashMap::new(),
            queue: Vec::new(),
            pending_session_switch_submissions: Vec::new(),
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
            daemon_prompt: daemon_state.prompt,
            question_dialog: None,
            question_dialog_btw: false,
            pending_btw_interrupt: None,
            composer_active_since_dialog: true,
            pending_local_choice: None,
            daemon_connected: daemon_state.connected,
            daemonless: daemon_state.daemonless,
            daemon_guard: None,
            daemon_signal_task: None,
            fetch_models_progress: Arc::new(Mutex::new(Vec::new())),
            agent_runner: None,
            display_attach_backoff: DisplayAttachBackoff::default(),
            async_actions: AsyncActionRunner::default(),
            completed_async_actions: Vec::new(),
            startup_background: StartupBackground {
                daemon_socket: daemon_state.socket,
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
            pending_control_requests: HashMap::new(),
            next_control_request_seq: 0,
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
            sandbox_mode: cockpit_core::tools::sandbox_mode::SandboxMode::from_enabled(!no_sandbox),
            container_network_enabled: false,
            container_availability: cockpit_core::container::initial_availability_unknown(),
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
            command_capability_notice: None,
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
            first_run_flow: if has_no_providers_at_startup {
                FirstRunFlow::AwaitProvider
            } else {
                FirstRunFlow::None
            },
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
        if let Some(notice) = daemon_state.notice {
            app.show_toast(notice, ToastKind::Info);
        }
        // First-run convenience: if the daemon prompt doesn't gate
        // startup, open the Add-Provider wizard immediately when no
        // providers are configured. The prompt-resolution branches
        // call this same helper after the user dismisses the daemon
        // prompt.
        match startup_trust {
            StartupWorkspaceTrust::Pending(root) => {
                app.dialog = Dialog::open_workspace_trust(root);
            }
            StartupWorkspaceTrust::Decided if app.daemon_prompt.is_none() => {
                app.maybe_open_add_provider_wizard();
            }
            StartupWorkspaceTrust::Decided => {}
        }
        app
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
                    cockpit_core::daemon::proto::Request::EndBtwFork {
                        parent_session_id: runner.session_id(),
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
        changed |= self.service_first_run_flow();
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
        let now = Instant::now();
        self.busy
            || self.pending.is_some()
            || self.toast.is_some()
            || self.ctrl_c_armed_at.is_some()
            || self.reconnect.is_some()
            || self.pane.is_some()
            || self.async_action_animation_active(now)
            || self.dialog.is_active()
            || self.question_dialog.is_some()
            || self.daemon_prompt.is_some()
    }

    fn async_action_animation_active(&self, now: Instant) -> bool {
        let session_switches = [
            AsyncActionKind::Internal("session.switch"),
            AsyncActionKind::Internal("session.resume"),
            AsyncActionKind::Internal("session.fork"),
            AsyncActionKind::Internal("session.side"),
            AsyncActionKind::Internal("session.side.return"),
        ];
        self.async_actions.has_pending_not_in(&session_switches)
            || self
                .async_actions
                .pending_any_kind_elapsed(&session_switches, now)
                .is_some_and(|elapsed| elapsed >= SESSION_SWITCH_SPINNER_THRESHOLD)
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

/// Resolve the answering-dialog config (GOALS §3b) from the effective layered
/// `config.json`. Used to read the anti-misfire lockout delay.
fn load_dialog_config(cwd: &Path) -> cockpit_config::extended::DialogConfig {
    cockpit_config::extended::load_for_cwd(cwd).dialog
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
mod new_session_swap_tests;
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
