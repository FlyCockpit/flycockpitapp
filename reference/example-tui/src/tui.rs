//! `excoc tui` — a simulated agentic chat TUI, built with ratatui, that mirrors
//! the web console's interaction design so it can be handed to agents as a
//! reference for the real `flycockpitapp` client.
//!
//! It is a *demo of the UX*, not a client: every response is scripted (see
//! [`scenario`]) and no daemon or model is involved. What it does implement,
//! faithfully, are the four interactions this slice is about:
//!
//! 1. **Sticky user messages** — the current turn's request stays pinned to the
//!    top of the transcript as its answer scrolls underneath. This is always on;
//!    there is no toggle. User and agent headers also offer **[Pin]** (toggle a
//!    mark) and **[Fork]** (new session from that point).
//! 2. **A hidable sidebar** — session names with a red / yellow / green status
//!    dot (waiting / working / done).
//! 3. **Model and effort selection** — pickers opened from pills that sit on
//!    the input box's bottom border (`⌃P` / `⌃E`, or a click). The model picker
//!    is two levels (provider, then model); the wheel scrolls a hovered picker.
//! 4. **A message queue** — typing while the agent works queues a message, and
//!    Enter escalates the whole batch from "send when the turn finishes" to
//!    "cut in at the next step boundary" to "stop the agent and send now".
//! 5. **Slash commands** — a bare `/` opens a command palette (`/new`, `/clear`,
//!    `/model`, `/effort`, and simulated context/tooling commands).
//! 6. **A multi-line, wrapping composer** — Shift+Enter (or Alt+Enter) inserts a
//!    newline while plain Enter sends; the box grows and wraps as you type, and
//!    the header shows the working directory's live git branch and dirty count.
//! 7. **Thinking and turn stats** — a live **Thinking** block streams before
//!    tool calls and replies, then collapses to **Thought**. `/think` or a
//!    click expands it; clicking **Agent** on a reply shows provider/model, TTFT, TPS,
//!    and cache-hit tokens. `/compact` drops a boundary with a `[show summary]`
//!    chip that expands into a readable brief of the folded turns.
//!
//! Every control is mouse-drivable as well as keyboard-drivable, matching the
//! onboarding wizard's convention.

mod banner;
mod command;
mod git;
mod model;
mod palette;
mod render;
mod runner;
mod scenario;
mod widgets;

use std::io::{self, IsTerminal, Stdout, Write};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers, KeyboardEnhancementFlags, MouseButton, MouseEvent, MouseEventKind,
    PopKeyboardEnhancementFlags, PushKeyboardEnhancementFlags,
};
use crossterm::execute;
use crossterm::terminal::supports_keyboard_enhancement;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Position;

use model::{Effort, Message, QueueMode, QueuedMessage, Session, Status, escalate};
use render::{Hits, Overlay};
use widgets::{TextField, hit};

const FRAME: Duration = Duration::from_millis(40);
/// How often the header re-reads the working directory's git state.
const GIT_REFRESH: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScrollDrag {
    Transcript,
    Sidebar,
    Overlay,
}

/// The whole application state. Submodules of `tui` can read its fields
/// directly; the event loop is the only thing that mutates them.
pub struct App {
    sessions: Vec<Session>,
    active: usize,

    sidebar_open: bool,
    effort: Effort,
    model: usize,
    agent: usize,
    sandbox: model::Sandbox,
    permissions: model::Permissions,
    /// Click-drag on a scrollbar track.
    scroll_drag: Option<ScrollDrag>,

    input: TextField,
    overlay: Option<Overlay>,
    /// Selected row in the slash-command palette.
    slash_cursor: usize,
    /// Escape hides the palette without clearing the typed `/query`.
    slash_dismissed: bool,
    quit: bool,

    /// Rebuilt every frame by [`render::draw`]; read by the mouse handler.
    hits: Hits,
    /// The control row the pickers open above; set during render.
    overlay_anchor: ratatui::layout::Rect,
    /// Transcript metrics from the last frame, for scroll clamping.
    transcript_total: usize,
    transcript_view: usize,
    /// First visible session slot in the sidebar, and how many slots fit.
    sidebar_scroll: usize,
    sidebar_view: usize,
    /// First visible row in a header popover, and how many rows fit.
    overlay_scroll: usize,
    overlay_view: usize,
    /// Last tool-tier change took the schema in or out of the prompt.
    tool_cache_warn: bool,

    /// Working-directory git state for the header, refreshed on a slow timer.
    git: git::GitInfo,
    /// Latest mouse position, used to highlight clickable chips on hover.
    mouse: Option<Position>,
}

impl App {
    fn new() -> Self {
        let sessions = scenario::initial_sessions();
        Self {
            sessions,
            active: 0,
            sidebar_open: true,
            effort: Effort::Medium,
            model: 0,
            agent: 0,
            sandbox: model::Sandbox::On,
            permissions: model::Permissions::Ask,
            scroll_drag: None,
            input: TextField::default(),
            overlay: None,
            slash_cursor: 0,
            slash_dismissed: false,
            quit: false,
            hits: Hits::default(),
            overlay_anchor: ratatui::layout::Rect::default(),
            transcript_total: 0,
            transcript_view: 0,
            sidebar_scroll: 0,
            sidebar_view: 0,
            overlay_scroll: 0,
            overlay_view: 0,
            tool_cache_warn: false,
            git: git::GitInfo::unknown(),
            mouse: None,
        }
    }

    /* -------------------------------- input ------------------------------- */

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char('c' | 'C') => {
                    self.quit = true;
                    return;
                }
                KeyCode::Char('b' | 'B') => {
                    self.sidebar_open = !self.sidebar_open;
                    return;
                }
                KeyCode::Char('n' | 'N') => {
                    self.new_session();
                    return;
                }
                KeyCode::Char('p' | 'P') => {
                    self.overlay = Some(Overlay::Provider {
                        cursor: self.provider_index(),
                    });
                    return;
                }
                KeyCode::Char('e' | 'E') => {
                    self.overlay = Some(Overlay::Effort {
                        cursor: self.effort_index(),
                    });
                    return;
                }
                _ => {}
            }
        }

        // Alt+↑/↓ switches the active session regardless of focus.
        if key.modifiers.contains(KeyModifiers::ALT) {
            match key.code {
                KeyCode::Up => {
                    self.switch_session(-1);
                    return;
                }
                KeyCode::Down => {
                    self.switch_session(1);
                    return;
                }
                _ => {}
            }
        }

        if self.overlay.is_some() {
            self.handle_overlay_key(key);
            return;
        }

        if self.slash_active() && self.handle_slash_key(key) {
            return;
        }

        match key.code {
            // Shift+Enter inserts a newline so the composer can hold multi-line
            // messages; plain Enter still sends. Alt+Enter is accepted too, as a
            // fallback for terminals that can't report Shift+Enter.
            KeyCode::Enter
                if key
                    .modifiers
                    .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT) =>
            {
                self.input.insert_newline();
                self.slash_cursor = 0;
                if self.slash_query().is_none() {
                    self.slash_dismissed = false;
                }
            }
            KeyCode::Enter => self.submit(),
            KeyCode::Esc => {
                if !self.input.is_empty() {
                    self.input.clear();
                }
            }
            KeyCode::PageUp => self.scroll_lines(-(self.transcript_view.max(1) as isize)),
            KeyCode::PageDown => self.scroll_lines(self.transcript_view.max(1) as isize),
            KeyCode::Up
                if self.input.is_empty() && !self.sessions[self.active].queue.is_empty() =>
            {
                self.recall_queued();
            }
            KeyCode::Up => self.scroll_lines(-1),
            KeyCode::Down => self.scroll_lines(1),
            _ => {
                self.input.handle_key(key);
                // Any edit re-ranks the palette from the top, and leaving
                // command mode clears a prior Escape-dismissal.
                self.slash_cursor = 0;
                if self.slash_query().is_none() {
                    self.slash_dismissed = false;
                }
            }
        }
    }

    /// Handle a key while the slash palette is open. Returns whether it was
    /// consumed; unconsumed keys (typing, backspace) fall through to the input.
    fn handle_slash_key(&mut self, key: KeyEvent) -> bool {
        let matches = self.slash_matches();
        let len = matches.len();
        if len == 0 {
            return false;
        }
        match key.code {
            KeyCode::Up => {
                self.slash_cursor = (self.slash_cursor + len - 1) % len;
                true
            }
            KeyCode::Down | KeyCode::Tab => {
                if key.code == KeyCode::Tab {
                    // Tab completes to `/name ` so you can type arguments.
                    let name = matches[self.slash_cursor.min(len - 1)].name;
                    self.input.set_text(&format!("/{name} "));
                } else {
                    self.slash_cursor = (self.slash_cursor + 1) % len;
                }
                true
            }
            KeyCode::Esc => {
                self.slash_dismissed = true;
                true
            }
            // Shift/Alt+Enter is a newline, not a command run: let it fall
            // through to the composer.
            KeyCode::Enter
                if !key
                    .modifiers
                    .intersects(KeyModifiers::SHIFT | KeyModifiers::ALT) =>
            {
                let name = matches[self.slash_cursor.min(len - 1)].name;
                self.run_command(name);
                true
            }
            _ => false,
        }
    }

    fn handle_overlay_key(&mut self, key: KeyEvent) {
        let Some(overlay) = self.overlay else {
            return;
        };
        if overlay.len() == 0 {
            self.overlay = None;
            return;
        }
        match key.code {
            KeyCode::Esc => {
                // Backing out of a model list returns to the provider list;
                // otherwise the picker closes.
                self.overlay = match overlay {
                    Overlay::Model { provider, .. } => Some(Overlay::Provider { cursor: provider }),
                    _ => None,
                };
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_overlay_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_overlay_cursor(1),
            KeyCode::Enter => self.activate_overlay(overlay.cursor()),
            KeyCode::Char(' ') if matches!(overlay, Overlay::Tools { .. }) => {
                self.activate_overlay(overlay.cursor());
            }
            _ => {}
        }
    }

    fn handle_mouse(&mut self, mouse: MouseEvent) {
        let pos = Position::new(mouse.column, mouse.row);
        self.mouse = Some(pos);
        // Header menus pan their viewport; composer pickers move the highlight.
        // Elsewhere the wheel scrolls the transcript (or the sidebar).
        let over_overlay = self.overlay.is_some() && hit(self.hits.overlay_box, pos);
        let over_sidebar = self.sidebar_open && hit(self.hits.sidebar_list, pos);
        match mouse.kind {
            MouseEventKind::ScrollUp if over_overlay => self.wheel_overlay(-3),
            MouseEventKind::ScrollDown if over_overlay => self.wheel_overlay(3),
            MouseEventKind::ScrollUp if over_sidebar => self.scroll_sidebar(-1),
            MouseEventKind::ScrollDown if over_sidebar => self.scroll_sidebar(1),
            MouseEventKind::ScrollUp => self.scroll_lines(-3),
            MouseEventKind::ScrollDown => self.scroll_lines(3),
            MouseEventKind::Down(MouseButton::Left) => {
                if self.hits.transcript_sb.height > 0 && hit(self.hits.transcript_sb, pos) {
                    self.scroll_drag = Some(ScrollDrag::Transcript);
                    self.apply_scroll_drag(pos);
                } else if self.hits.sidebar_sb.height > 0 && hit(self.hits.sidebar_sb, pos) {
                    self.scroll_drag = Some(ScrollDrag::Sidebar);
                    self.apply_scroll_drag(pos);
                } else if self.hits.overlay_sb.height > 0 && hit(self.hits.overlay_sb, pos) {
                    self.scroll_drag = Some(ScrollDrag::Overlay);
                    self.apply_scroll_drag(pos);
                } else {
                    self.handle_click(pos);
                }
            }
            MouseEventKind::Up(_) => self.scroll_drag = None,
            MouseEventKind::Moved | MouseEventKind::Drag(_) => {
                if self.scroll_drag.is_some() {
                    self.apply_scroll_drag(pos);
                } else {
                    self.hover_menus(pos);
                }
            }
            _ => {}
        }
    }

    fn apply_scroll_drag(&mut self, pos: Position) {
        match self.scroll_drag {
            Some(ScrollDrag::Transcript) => {
                let max = self.transcript_total.saturating_sub(self.transcript_view);
                let scroll = scroll_from_track(self.hits.transcript_sb, pos.y, max);
                let session = &mut self.sessions[self.active];
                session.scroll = scroll;
                session.pinned = max == 0 || scroll >= max;
            }
            Some(ScrollDrag::Sidebar) => {
                let max = self
                    .visible_sessions()
                    .len()
                    .saturating_sub(self.sidebar_view.max(1));
                self.sidebar_scroll = scroll_from_track(self.hits.sidebar_sb, pos.y, max);
            }
            Some(ScrollDrag::Overlay) => {
                let max = self
                    .overlay
                    .map(|overlay| overlay.len().saturating_sub(self.overlay_view.max(1)))
                    .unwrap_or(0);
                self.overlay_scroll = scroll_from_track(self.hits.overlay_sb, pos.y, max);
            }
            None => {}
        }
    }

    /// Highlight the overlay or slash row under the pointer.
    fn hover_menus(&mut self, pos: Position) {
        if self.overlay.is_some() {
            for (index, rect) in &self.hits.overlay_rows {
                if hit(*rect, pos) {
                    if let Some(overlay) = self.overlay.as_mut() {
                        overlay.set_cursor(*index);
                    }
                    return;
                }
            }
        }
        if self.slash_active() {
            for (name, rect) in &self.hits.slash_rows {
                if hit(*rect, pos) {
                    if let Some(index) = self.slash_matches().iter().position(|c| c.name == *name) {
                        self.slash_cursor = index;
                    }
                    return;
                }
            }
        }
    }

    /// Wheel over a header menu pans the list; composer pickers still step
    /// the highlighted row.
    fn wheel_overlay(&mut self, delta: isize) {
        if self.overlay.is_some_and(Overlay::opens_from_header) {
            self.scroll_overlay(delta);
        } else if delta < 0 {
            self.move_overlay_cursor(-1);
        } else {
            self.move_overlay_cursor(1);
        }
    }

    fn scroll_overlay(&mut self, delta: isize) {
        let max = self
            .overlay
            .map(|overlay| overlay.len().saturating_sub(self.overlay_view.max(1)))
            .unwrap_or(0) as isize;
        self.overlay_scroll = (self.overlay_scroll as isize + delta).clamp(0, max.max(0)) as usize;
    }

    /// Move the open picker's selection by `delta`, wrapping around.
    fn move_overlay_cursor(&mut self, delta: isize) {
        if let Some(overlay) = self.overlay.as_mut() {
            let len = overlay.len();
            if len == 0 {
                return;
            }
            let next = (overlay.cursor() as isize + delta).rem_euclid(len as isize) as usize;
            overlay.set_cursor(next);
        }
        self.ensure_overlay_visible();
    }

    fn ensure_overlay_visible(&mut self) {
        let Some(overlay) = self.overlay else {
            return;
        };
        if !overlay.opens_from_header() {
            return;
        }
        let cursor = overlay.cursor();
        let view = self.overlay_view.max(1);
        if cursor < self.overlay_scroll {
            self.overlay_scroll = cursor;
        } else if cursor >= self.overlay_scroll + view {
            self.overlay_scroll = cursor + 1 - view;
        }
    }

    fn handle_click(&mut self, pos: Position) {
        // Take the hit map out; draw rebuilds it next frame anyway.
        let hits = std::mem::take(&mut self.hits);

        if self.overlay.is_some() {
            for (i, rect) in &hits.overlay_rows {
                if hit(*rect, pos) {
                    self.hits.subagent_lines = hits.subagent_lines.clone();
                    self.activate_overlay(*i);
                    return;
                }
            }
            // A click anywhere else dismisses the picker.
            self.overlay = None;
            return;
        }

        // Clicking a slash-palette row runs that command.
        if let Some((name, _)) = hits.slash_rows.iter().find(|(_, r)| hit(*r, pos)) {
            let name = *name;
            self.run_command(name);
            return;
        }

        // Transcript navigation: the jump-to-latest chip re-pins to the tail;
        // clicking the sticky header steps back one turn.
        if hit(hits.jump_latest, pos) {
            self.jump_to_latest();
            return;
        }
        if let Some((i, _)) = hits.pin.iter().find(|(_, r)| hit(*r, pos)) {
            self.toggle_pin(*i);
            return;
        }
        if let Some((i, _)) = hits.fork.iter().find(|(_, r)| hit(*r, pos)) {
            self.fork_message(*i);
            return;
        }
        if let Some((i, _)) = hits.agent_name.iter().find(|(_, r)| hit(*r, pos)) {
            self.sessions[self.active].toggle_message_stats(*i);
            return;
        }
        if let Some((i, _)) = hits.thinking.iter().find(|(_, r)| hit(*r, pos)) {
            self.sessions[self.active].toggle_message_thinking(*i);
            return;
        }
        if let Some((i, _)) = hits.summaries.iter().find(|(_, r)| hit(*r, pos)) {
            self.sessions[self.active].toggle_message_summary(*i);
            return;
        }
        if hit(hits.sticky, pos) {
            self.scroll_to(hits.sticky_target);
            return;
        }
        if let Some((path, interactive, _)) = hits
            .subagent_blocks
            .iter()
            .find(|(_, _, rect)| hit(*rect, pos))
        {
            self.reveal_subagent(path.clone(), *interactive, &hits.subagent_lines);
            return;
        }
        if let Some((path, _)) = hits.crumbs.iter().find(|(_, rect)| hit(*rect, pos)) {
            self.set_focus(path.clone());
            return;
        }
        if hit(hits.subagents_pill, pos) {
            self.open_subagents_overlay();
            return;
        }
        if hit(hits.tasks_pill, pos) {
            let count = self.sessions[self.active].layer_tasks().len().max(1);
            self.show_overlay(Overlay::Background { cursor: 0, count });
            return;
        }
        if hit(hits.timers_pill, pos) {
            let count = self.sessions[self.active].layer_timers().len().max(1);
            self.show_overlay(Overlay::Timers { cursor: 0, count });
            return;
        }
        if hit(hits.tools_pill, pos) {
            let count = self.sessions[self.active].layer_tools().len().max(1);
            self.show_overlay(Overlay::Tools { cursor: 0, count });
            return;
        }
        if hit(hits.skills_pill, pos) {
            let count = self.sessions[self.active].layer_skills().len().max(1);
            self.show_overlay(Overlay::Skills { cursor: 0, count });
            return;
        }

        if let Some((i, _)) = hits.session_pin.iter().find(|(_, r)| hit(*r, pos)) {
            self.toggle_session_pin(*i);
            return;
        }
        if let Some((i, _)) = hits.archive.iter().find(|(_, r)| hit(*r, pos)) {
            self.archive_session(*i);
            return;
        }
        if let Some((i, _)) = hits.delete.iter().find(|(_, r)| hit(*r, pos)) {
            self.overlay = Some(Overlay::ConfirmDelete {
                session: *i,
                cursor: 0,
            });
            return;
        }

        if hit(hits.sidebar_toggle, pos) {
            self.sidebar_open = !self.sidebar_open;
        } else if hit(hits.new_session, pos) {
            self.new_session();
        } else if hit(hits.agent_pill, pos) {
            if !self.sessions[self.active].locked_in_interactive() {
                self.overlay = Some(Overlay::Agent { cursor: self.agent });
            }
        } else if hit(hits.model_pill, pos) {
            if !self.sessions[self.active].locked_in_interactive() {
                self.overlay = Some(Overlay::Provider {
                    cursor: self.provider_index(),
                });
            }
        } else if hit(hits.effort_pill, pos) {
            self.overlay = Some(Overlay::Effort {
                cursor: self.effort_index(),
            });
        } else if hit(hits.permissions_pill, pos) {
            self.overlay = Some(Overlay::Permissions {
                cursor: self.permissions_index(),
            });
        } else if hit(hits.sandbox_pill, pos) {
            self.overlay = Some(Overlay::Sandbox {
                cursor: self.sandbox_index(),
            });
        } else if hit(hits.send, pos) {
            self.submit();
        } else if let Some((i, _)) = hits.sessions.iter().find(|(_, r)| hit(*r, pos)) {
            self.active = *i;
        } else if let Some((i, _)) = hits.suggestions.iter().find(|(_, r)| hit(*r, pos)) {
            if let Some(text) = self.sessions[self.active].suggestions.get(*i).cloned() {
                self.send_text(text);
            }
        } else if let Some((row, mode)) = queue_mode_click(&hits, pos) {
            self.set_queue_mode(row, mode);
        } else if hit(hits.queue_edit, pos) {
            self.recall_queued();
        } else if let Some((row, _)) = hits.queue_remove.iter().find(|(_, r)| hit(*r, pos)) {
            self.remove_queued(*row);
        }
    }

    /* ------------------------------- actions ------------------------------ */

    fn effort_index(&self) -> usize {
        Effort::ORDER
            .iter()
            .position(|e| *e == self.effort)
            .unwrap_or(0)
    }

    /* -------------------------- slash commands ---------------------------- */

    fn slash_query(&self) -> Option<&str> {
        command::slash_query(self.input.text())
    }

    fn slash_matches(&self) -> Vec<&'static command::Command> {
        match self.slash_query() {
            Some(query) => command::matches(query),
            None => Vec::new(),
        }
    }

    /// Whether the command palette is showing: a bare `/query` with matches,
    /// not Escape-dismissed, and no picker on top.
    fn slash_active(&self) -> bool {
        self.overlay.is_none() && !self.slash_dismissed && !self.slash_matches().is_empty()
    }

    fn slash_cursor(&self) -> usize {
        self.slash_cursor
    }

    /// Run a slash command by name, clearing the composer first.
    fn run_command(&mut self, name: &str) {
        self.input.clear();
        self.slash_cursor = 0;
        self.slash_dismissed = false;
        match name {
            "new" => self.new_session(),
            "clear" => self.clear_transcript(),
            "model" => {
                self.overlay = Some(Overlay::Provider {
                    cursor: self.provider_index(),
                })
            }
            "effort" => {
                self.overlay = Some(Overlay::Effort {
                    cursor: self.effort_index(),
                })
            }
            "think" => self.toggle_session_thinking(),
            "compact" => self.compact_session(),
            "prune" => {
                self.system_note("Pruned 6 stale tool results from the context. (simulated)")
            }
            "agents" => self.open_subagents_overlay(),
            "timers" => {
                let count = self.sessions[self.active].layer_timers().len().max(1);
                self.show_overlay(Overlay::Timers { cursor: 0, count });
            }
            "background" => {
                let count = self.sessions[self.active].layer_tasks().len().max(1);
                self.show_overlay(Overlay::Background { cursor: 0, count });
            }
            "export" => self.system_note("Exported this transcript to chat.md. (simulated)"),
            _ => {}
        }
    }

    /// Wipe the focused transcript without deleting the session.
    /// While an interactive subagent holds the chat, only that layer is
    /// cleared — focus stays put so `/clear` is not a way out.
    fn clear_transcript(&mut self) {
        let session = &mut self.sessions[self.active];
        let locked = session.locked_in_interactive();
        session.focused_messages_mut().clear();
        session.queue.clear();
        session.suggestions.clear();
        session.run = None;
        session.resting = Status::Idle;
        session.scroll = 0;
        session.pinned = true;
        if !locked {
            session.focus.clear();
        }
    }

    fn compact_session(&mut self) {
        if !self.sessions[self.active].compact_context() {
            self.system_note("Nothing to compact yet.");
        }
    }

    fn toggle_session_thinking(&mut self) {
        self.sessions[self.active].toggle_show_thinking();
        let showing = self.sessions[self.active].show_thinking;
        self.system_note(if showing {
            "Showing thinking for this conversation."
        } else {
            "Hiding thinking for this conversation."
        });
    }

    /// Append a dim local note (slash-command feedback) to the focused transcript.
    fn system_note(&mut self, text: &str) {
        let session = &mut self.sessions[self.active];
        session
            .focused_messages_mut()
            .push(Message::system(text.to_string()));
        session.touch();
        session.pinned = true;
    }

    /// The provider-list index of the currently selected model.
    fn sandbox_index(&self) -> usize {
        model::Sandbox::ORDER
            .iter()
            .position(|mode| *mode == self.sandbox)
            .unwrap_or(0)
    }

    fn permissions_index(&self) -> usize {
        model::Permissions::ORDER
            .iter()
            .position(|mode| *mode == self.permissions)
            .unwrap_or(0)
    }

    fn show_overlay(&mut self, overlay: Overlay) {
        self.overlay_scroll = 0;
        self.tool_cache_warn = false;
        self.overlay = Some(overlay);
    }

    fn open_subagents_overlay(&mut self) {
        let count = self.sessions[self.active].background_workers().len().max(1);
        self.show_overlay(Overlay::Subagents { cursor: 0, count });
    }

    fn cycle_tool_tier(&mut self, index: usize) {
        let Some(tool) = self.sessions[self.active].layer_tools_mut().get_mut(index) else {
            return;
        };
        let from = tool.tier;
        let to = from.cycle();
        tool.tier = to;
        if model::ToolTier::breaks_cache(from, to) {
            self.tool_cache_warn = true;
        }
    }

    fn set_focus(&mut self, path: Vec<usize>) {
        let session = &mut self.sessions[self.active];
        session.focus = path;
        session.ensure_focus();
        session.scroll = 0;
        session.pinned = true;
    }

    fn reveal_subagent(
        &mut self,
        path: Vec<usize>,
        _interactive: bool,
        lines: &[(Vec<usize>, bool, usize)],
    ) {
        if let Some((_, _, line)) = lines.iter().find(|(item, _, _)| item == &path) {
            self.scroll_to(*line);
        }
    }

    fn provider_index(&self) -> usize {
        let current = model::MODELS[self.model].provider;
        model::providers()
            .iter()
            .position(|p| *p == current)
            .unwrap_or(0)
    }

    /// Act on the picker row at `index`: a provider drills into its models, a
    /// model is applied, an effort is applied.
    fn activate_overlay(&mut self, index: usize) {
        match self.overlay {
            Some(Overlay::Provider { .. }) => {
                if index < model::providers().len() {
                    self.overlay = Some(Overlay::Model {
                        provider: index,
                        cursor: 0,
                    });
                }
            }
            Some(Overlay::Model { provider, .. }) => {
                let providers = model::providers();
                if let Some(name) = providers.get(provider)
                    && let Some(&global) = model::models_for(name).get(index)
                {
                    self.model = global;
                }
                self.overlay = None;
            }
            Some(Overlay::Effort { .. }) => {
                if let Some(effort) = Effort::ORDER.get(index) {
                    self.effort = *effort;
                }
                self.overlay = None;
            }
            Some(Overlay::Agent { .. }) => {
                if index < model::AGENTS.len() {
                    self.agent = index;
                }
                self.overlay = None;
            }
            Some(Overlay::Sandbox { .. }) => {
                if let Some(mode) = model::Sandbox::ORDER.get(index) {
                    self.sandbox = *mode;
                }
                self.overlay = None;
            }
            Some(Overlay::Permissions { .. }) => {
                if let Some(mode) = model::Permissions::ORDER.get(index) {
                    self.permissions = *mode;
                }
                self.overlay = None;
            }
            Some(Overlay::Subagents { .. }) => {
                let lines = self.hits.subagent_lines.clone();
                let paths: Vec<Vec<usize>> = self.sessions[self.active]
                    .background_workers()
                    .into_iter()
                    .map(|(path, _)| path)
                    .collect();
                self.overlay = None;
                if let Some(path) = paths.get(index) {
                    self.reveal_subagent(path.clone(), false, &lines);
                }
            }
            Some(Overlay::Tools { .. }) => {
                self.cycle_tool_tier(index);
            }
            Some(Overlay::Background { .. } | Overlay::Timers { .. } | Overlay::Skills { .. }) => {
                // Inspect-only: dismiss the menu.
                self.overlay = None;
            }
            Some(Overlay::ConfirmDelete { session, .. }) => {
                self.overlay = None;
                if index == 1 {
                    self.delete_session(session);
                }
            }
            None => {}
        }
    }

    /// Send the typed text, or — when the composer is empty and a queue is
    /// waiting — escalate the queue one rung.
    fn submit(&mut self) {
        let text = self.input.trimmed().to_string();
        if text.is_empty() {
            let idx = self.active;
            if !self.sessions[idx].queue.is_empty() {
                escalate(&mut self.sessions[idx].queue);
            }
            return;
        }
        // A completed `/name` (with or without arguments) runs the command
        // rather than sending it as a message.
        if let Some(rest) = text.strip_prefix('/') {
            let name = rest.split_whitespace().next().unwrap_or("");
            if command::find(name).is_some() {
                self.run_command(name);
                return;
            }
        }
        self.send_text(text);
        self.input.clear();
    }

    /// Deliver `text`: queue it while the agent is working, otherwise start a
    /// turn immediately.
    fn send_text(&mut self, text: String) {
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }
        let idx = self.active;
        if self.sessions[idx].is_working() {
            self.sessions[idx].queue.push(QueuedMessage {
                text,
                mode: QueueMode::Turn,
            });
            self.sessions[idx].touch();
        } else {
            let effort = self.effort;
            self.sessions[idx].start_turn(
                vec![text],
                effort,
                Instant::now(),
                model::MODELS[self.model],
            );
        }
    }

    fn set_queue_mode(&mut self, row: usize, mode: QueueMode) {
        if let Some(item) = self.sessions[self.active].queue.get_mut(row) {
            item.mode = mode;
        }
    }

    fn remove_queued(&mut self, row: usize) {
        let queue = &mut self.sessions[self.active].queue;
        if row < queue.len() {
            queue.remove(row);
            self.sessions[self.active].touch();
        }
    }

    /// Combine every queued message into one draft and put it in the composer.
    fn recall_queued(&mut self) {
        let queue = &mut self.sessions[self.active].queue;
        if queue.is_empty() {
            return;
        }
        let text = queue
            .drain(..)
            .map(|item| item.text)
            .collect::<Vec<_>>()
            .join("\n\n");
        self.sessions[self.active].touch();
        self.put_in_composer(&text);
    }

    fn put_in_composer(&mut self, text: &str) {
        if self.input.is_empty() {
            self.input.set_text(text);
        } else {
            let mut combined = self.input.text().to_string();
            if !combined.ends_with('\n') {
                combined.push('\n');
            }
            combined.push('\n');
            combined.push_str(text);
            self.input.set_text(&combined);
        }
        self.slash_cursor = 0;
        if self.slash_query().is_none() {
            self.slash_dismissed = false;
        }
    }

    fn visible_sessions(&self) -> Vec<usize> {
        Session::visible_indices(&self.sessions)
    }

    fn toggle_session_pin(&mut self, index: usize) {
        if let Some(session) = self.sessions.get_mut(index) {
            session.starred = !session.starred;
        }
        self.ensure_sidebar_shows_active();
    }

    fn switch_session(&mut self, delta: isize) {
        let visible = self.visible_sessions();
        let n = visible.len();
        if n == 0 {
            return;
        }
        let current = visible
            .iter()
            .position(|&index| index == self.active)
            .unwrap_or(0);
        let next = (current as isize + delta).rem_euclid(n as isize) as usize;
        self.active = visible[next];
        self.ensure_sidebar_shows_active();
    }

    fn new_session(&mut self) {
        let session = scenario::new_session();
        self.sessions.insert(0, session);
        self.active = 0;
        self.sidebar_scroll = 0;
    }

    fn archive_session(&mut self, index: usize) {
        if let Some(session) = self.sessions.get_mut(index) {
            session.archived = true;
        }
        self.ensure_active_visible();
    }

    fn delete_session(&mut self, index: usize) {
        if index >= self.sessions.len() {
            return;
        }
        self.sessions.remove(index);
        if self.active > index {
            self.active -= 1;
        } else if self.active >= self.sessions.len() {
            self.active = self.sessions.len().saturating_sub(1);
        }
        self.ensure_active_visible();
    }

    /// After archive/delete, land on a visible session (or spawn a blank one).
    fn ensure_active_visible(&mut self) {
        let visible = self.visible_sessions();
        if visible.is_empty() {
            self.sessions.insert(0, scenario::new_session());
            self.active = 0;
            return;
        }
        if !visible.contains(&self.active) {
            self.active = visible
                .iter()
                .copied()
                .min_by_key(|index| index.abs_diff(self.active))
                .unwrap_or(visible[0]);
        }
        self.ensure_sidebar_shows_active();
    }

    fn scroll_sidebar(&mut self, delta: isize) {
        let visible = self.visible_sessions().len();
        let view = self.sidebar_view.max(1);
        let max = visible.saturating_sub(view);
        if delta < 0 {
            self.sidebar_scroll = self.sidebar_scroll.saturating_sub((-delta) as usize);
        } else {
            self.sidebar_scroll = (self.sidebar_scroll + delta as usize).min(max);
        }
    }

    /// Keep the active session inside the sidebar window after a selection change.
    fn ensure_sidebar_shows_active(&mut self) {
        let visible = self.visible_sessions();
        let Some(pos) = visible.iter().position(|&index| index == self.active) else {
            return;
        };
        let view = self.sidebar_view.max(1);
        if pos < self.sidebar_scroll {
            self.sidebar_scroll = pos;
        } else if pos >= self.sidebar_scroll + view {
            self.sidebar_scroll = pos + 1 - view;
        }
    }

    fn scroll_lines(&mut self, delta: isize) {
        let session = &mut self.sessions[self.active];
        let max = self.transcript_total.saturating_sub(self.transcript_view);
        if delta < 0 {
            session.pinned = false;
            session.scroll = session.scroll.saturating_sub((-delta) as usize);
        } else {
            session.scroll = (session.scroll + delta as usize).min(max);
            session.pinned = session.scroll >= max;
        }
    }

    /// Snap to the tail and resume following the agent as it streams.
    fn jump_to_latest(&mut self) {
        let max = self.transcript_total.saturating_sub(self.transcript_view);
        let session = &mut self.sessions[self.active];
        session.scroll = max;
        session.pinned = true;
    }

    /// Toggle the pin on a user or agent message.
    fn toggle_pin(&mut self, message: usize) {
        if let Some(item) = self.sessions[self.active]
            .focused_messages_mut()
            .get_mut(message)
            && matches!(item.role, model::Role::User | model::Role::Agent)
        {
            item.pinned = !item.pinned;
        }
    }

    /// Open a new session that copies history through `message` inclusive.
    fn fork_message(&mut self, message: usize) {
        let Some(forked) = self.sessions[self.active].fork_at(message) else {
            return;
        };
        self.sessions.insert(self.active, forked);
    }

    /// Scroll to a specific line offset and stop following the tail. Used by the
    /// sticky header to step back through the conversation.
    fn scroll_to(&mut self, target: usize) {
        let max = self.transcript_total.saturating_sub(self.transcript_view);
        let session = &mut self.sessions[self.active];
        session.scroll = target.min(max);
        session.pinned = false;
    }

    /* -------------------------------- loop -------------------------------- */

    fn tick_all(&mut self, now: Instant) {
        let effort = self.effort;
        let model = model::MODELS[self.model];
        for session in &mut self.sessions {
            session.tick(now, effort, model);
        }
    }
}

/// Map a pointer y on a scrollbar track to a scroll offset in `0..=max`.
fn scroll_from_track(track: ratatui::layout::Rect, y: u16, max: usize) -> usize {
    if track.height <= 1 || max == 0 {
        return 0;
    }
    let rel = (y as i32 - track.y as i32).clamp(0, i32::from(track.height) - 1) as usize;
    let span = usize::from(track.height) - 1;
    (rel * max + span / 2) / span
}

/// The left click's `(queue row, mode)` if it landed on a schedule chip.
fn queue_mode_click(hits: &Hits, pos: Position) -> Option<(usize, QueueMode)> {
    for (row, rects) in &hits.queue_modes {
        for (k, rect) in rects.iter().enumerate() {
            if hit(*rect, pos) {
                return Some((*row, QueueMode::ORDER[k]));
            }
        }
    }
    None
}

/* --------------------------------- entry ---------------------------------- */

/// Enter the alternate screen and run the chat demo until the user quits.
pub fn run() -> Result<()> {
    if !io::stdout().is_terminal() {
        bail!("excoc tui needs a terminal (stdout is not a TTY)");
    }
    let mut screen = Screen::enter()?;
    let mut app = App::new();
    let mut last = Instant::now();
    // Force a git read before the first paint, then refresh on a slow timer.
    let mut git_checked: Option<Instant> = None;

    loop {
        if git_checked.is_none_or(|at| at.elapsed() >= GIT_REFRESH) {
            app.git = git::GitInfo::detect();
            git_checked = Some(Instant::now());
        }

        app.tick_all(Instant::now());

        screen.terminal.draw(|frame| {
            let caret = render::draw(&mut app, frame);
            if let Some(position) = caret {
                frame.set_cursor_position(position);
            }
        })?;

        let timeout = FRAME.saturating_sub(last.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key)
                    if key.kind == KeyEventKind::Press || key.kind == KeyEventKind::Repeat =>
                {
                    app.handle_key(key);
                }
                Event::Mouse(mouse) => app.handle_mouse(mouse),
                _ => {}
            }
        }
        last = Instant::now();

        if app.quit {
            break;
        }
    }
    Ok(())
}

/// RAII guard for the raw-mode alternate screen with mouse capture, mirroring
/// [`crate::onboard`]'s terminal handling.
struct Screen {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    /// Whether we pushed keyboard-enhancement flags (so Shift+Enter is
    /// distinguishable) and must pop them on the way out.
    enhanced: bool,
}

impl Screen {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        if let Err(error) = execute!(stdout, EnterAlternateScreen, EnableMouseCapture) {
            let _ = disable_raw_mode();
            return Err(error.into());
        }
        // Ask the terminal to disambiguate modified keys so we can tell
        // Shift+Enter from a bare Enter. Best-effort: terminals that don't
        // support it simply won't distinguish the two (Alt+Enter still works).
        let enhanced = supports_keyboard_enhancement().unwrap_or(false)
            && execute!(
                stdout,
                PushKeyboardEnhancementFlags(KeyboardEnhancementFlags::DISAMBIGUATE_ESCAPE_CODES)
            )
            .is_ok();
        let backend = CrosstermBackend::new(stdout);
        match Terminal::new(backend) {
            Ok(terminal) => Ok(Self { terminal, enhanced }),
            Err(error) => {
                if enhanced {
                    let _ = execute!(io::stdout(), PopKeyboardEnhancementFlags);
                }
                let _ = execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture);
                let _ = disable_raw_mode();
                Err(error.into())
            }
        }
    }
}

impl Drop for Screen {
    fn drop(&mut self) {
        if self.enhanced {
            let _ = execute!(self.terminal.backend_mut(), PopKeyboardEnhancementFlags);
        }
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
        let _ = io::stdout().flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    /// Draw the app once at `w`×`h` and return the flattened buffer text.
    fn draw_once(app: &mut App, w: u16, h: u16) -> String {
        buffer_text(&draw_term(app, w, h))
    }

    fn draw_term(app: &mut App, w: u16, h: u16) -> Terminal<TestBackend> {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        terminal
            .draw(|frame| {
                let _ = render::draw(app, frame);
            })
            .unwrap();
        terminal
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    /// Peek at the parent transcript. Breadcrumbs stay locked in product use;
    /// tests need this to assert the inlined parent history.
    fn show_parent(app: &mut App) {
        app.set_focus(Vec::new());
    }

    /// Drive scripted turns until the active session is idle.
    fn play_until_idle(app: &mut App) {
        let start = Instant::now();
        for i in 0..400 {
            app.tick_all(start + Duration::from_millis(i * 40));
            if !app.sessions[app.active].is_working() {
                break;
            }
        }
    }

    fn cells_on_row(terminal: &Terminal<TestBackend>, y: u16, x0: u16, x1: u16) -> String {
        let buf = terminal.backend().buffer();
        (x0..x1).map(|x| buf[(x, y)].symbol()).collect()
    }

    #[test]
    fn renders_at_a_range_of_sizes_without_panicking() {
        for (w, h) in [(80, 24), (120, 40), (40, 12), (24, 8), (16, 6)] {
            let mut app = App::new();
            let _ = draw_once(&mut app, w, h);
            app.sidebar_open = false;
            let _ = draw_once(&mut app, w, h);
        }
    }

    #[test]
    fn a_working_turn_shows_the_working_status() {
        let mut app = App::new();
        // The fourth seeded session is the blank one; send into it.
        app.active = app.sessions.len() - 1;
        app.send_text("start something".into());
        assert!(app.sessions[app.active].is_working());
        let text = draw_once(&mut app, 80, 24);
        assert!(text.contains("Working"), "status badge should read Working");
    }

    #[test]
    fn typing_while_working_queues_then_escalates() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        app.send_text("kick off a turn".into());
        assert!(app.sessions[app.active].is_working());

        // A message typed mid-run queues at the politest level.
        for ch in "hold on".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.sessions[app.active].queue.len(), 1);
        assert_eq!(app.sessions[app.active].queue[0].mode, QueueMode::Turn);

        // Enter on the now-empty composer escalates the whole batch.
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.sessions[app.active].queue[0].mode, QueueMode::Boundary);
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.sessions[app.active].queue[0].mode, QueueMode::Interrupt);

        // It renders in the queue panel.
        let text = draw_once(&mut app, 80, 24);
        assert!(text.contains("Interrupting"));
    }

    #[test]
    fn shift_enter_inserts_a_newline_instead_of_sending() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1; // the blank session
        for ch in "line one".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        let mut shift_enter = KeyEvent::from(KeyCode::Enter);
        shift_enter.modifiers = KeyModifiers::SHIFT;
        app.handle_key(shift_enter);
        for ch in "line two".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }

        assert_eq!(app.input.text(), "line one\nline two");
        assert!(
            !app.sessions[app.active].is_working(),
            "a newline must not start a turn"
        );

        // Plain Enter then sends the whole multi-line message.
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.input.text().is_empty(), "the composer was cleared");
        assert!(app.sessions[app.active].is_working(), "plain Enter sends");
    }

    #[test]
    fn a_blank_session_shows_the_p51_and_version() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("cockpit"));
        assert!(text.contains("v0.1.0"));
        assert!(
            text.chars().any(|c| "█▀▄▌▐▛▜▙▟▚▞▘▝▖▗".contains(c)),
            "the empty transcript should paint the P-51 half-blocks"
        );
    }

    #[test]
    fn the_header_shows_the_git_branch_and_change_count() {
        let mut app = App::new();
        app.git = git::GitInfo {
            is_repo: true,
            branch: Some("main".into()),
            changes: 3,
        };
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("main"), "the branch shows in the header");
        assert!(text.contains("3 changes"), "the dirty count shows");

        app.git.changes = 0;
        let clean = draw_once(&mut app, 100, 30);
        assert!(clean.contains("clean"), "a clean tree is labelled");
    }

    #[test]
    fn jump_to_latest_appears_when_scrolled_up_and_re_pins() {
        let mut app = App::new();
        app.active = 0; // a seeded session with scrollable history
        // Learn the transcript metrics, then scroll up off the tail.
        let _ = draw_once(&mut app, 90, 12);
        app.scroll_lines(-3);
        assert!(!app.sessions[0].pinned, "scrolling up stops following");

        // The chip is now offered.
        let _ = draw_once(&mut app, 90, 12);
        assert!(
            app.hits.jump_latest.height > 0,
            "the jump-to-latest chip shows while scrolled up"
        );

        // Clicking it re-pins to the tail and resumes following.
        app.jump_to_latest();
        let max = app.transcript_total.saturating_sub(app.transcript_view);
        assert!(app.sessions[0].pinned);
        assert_eq!(app.sessions[0].scroll, max);

        // At the tail the chip is gone again.
        let _ = draw_once(&mut app, 90, 12);
        assert_eq!(app.hits.jump_latest.height, 0);
    }

    #[test]
    fn clicking_the_sticky_header_steps_back_a_turn() {
        let mut app = App::new();
        app.active = 0;
        let _ = draw_once(&mut app, 90, 12);
        app.jump_to_latest();
        let _ = draw_once(&mut app, 90, 12);

        // At the tail a prior turn's user message is pinned as the sticky.
        assert!(app.hits.sticky.height > 0, "the sticky header is showing");
        let target = app.hits.sticky_target;
        let before = app.sessions[0].scroll;

        app.scroll_to(target);
        assert!(
            app.sessions[0].scroll < before,
            "clicking the sticky scrolls back up"
        );
        assert!(!app.sessions[0].pinned, "and stops following the tail");
    }

    #[test]
    fn pin_and_fork_buttons_show_on_user_and_agent_headers() {
        let mut app = App::new();
        // The live explorer sits at the tail; those headers keep pin/fork.
        // Parent history above the handoff is read-only while locked.
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("[Pin]"), "user/agent headers offer pin");
        assert!(text.contains("[Fork]"), "user/agent headers offer fork");
        assert!(!app.hits.pin.is_empty());
        assert!(!app.hits.fork.is_empty());
    }

    #[test]
    fn pinning_a_message_toggles_the_label() {
        let mut app = App::new();
        let _ = draw_once(&mut app, 100, 30);
        assert!(!app.hits.pin.is_empty(), "a header pin target is on screen");
        let idx = app.hits.pin[0].0;
        assert!(
            !app.sessions[0].focused_messages()[idx].pinned,
            "seeded messages start unpinned"
        );
        app.toggle_pin(idx);
        assert!(
            app.sessions[0].focused_messages()[idx].pinned,
            "pin toggles the focused transcript message"
        );
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("[Unpin]"));
        app.toggle_pin(idx);
        assert!(!app.sessions[0].focused_messages()[idx].pinned);
    }

    #[test]
    fn forking_a_message_opens_a_new_session_with_that_history() {
        let mut app = App::new();
        let original = app.sessions.len();
        let kept = app.sessions[0].messages.len();
        let through = 1; // first session: user then agent
        app.fork_message(through);
        assert_eq!(app.sessions.len(), original + 1);
        assert!(app.sessions[app.active].title.starts_with("Fork:"));
        assert_eq!(app.sessions[app.active].messages.len(), through + 1);
        assert_eq!(app.sessions[app.active + 1].messages.len(), kept);
    }

    #[test]
    fn the_sidebar_shows_last_activity_and_hover_actions() {
        let mut app = App::new();
        let stamp = render::datetime_label(app.sessions[0].last_active);
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("Cockpit Code"));
        assert!(
            text.contains(&stamp),
            "sidebar should show last activity ({stamp})"
        );
        assert!(app.hits.archive.is_empty(), "actions hide until hover");

        let (_, row) = app.hits.sessions[0];
        app.mouse = Some(Position::new(row.x + 1, row.y + 1));
        let term = draw_term(&mut app, 100, 30);
        let hovered = buffer_text(&term);
        assert!(hovered.contains("[Archive]"));
        assert!(hovered.contains("[Pin]"));
        assert!(hovered.contains("[×]"));
        assert!(!app.hits.archive.is_empty());
        assert!(!app.hits.delete.is_empty());
        assert!(!app.hits.session_pin.is_empty());

        let pin = app.hits.session_pin[0].1;
        let archive = app.hits.archive[0].1;
        let trash = app.hits.delete[0].1;
        assert_eq!(trash.width, 3, "× is one column inside [×]");
        let gap = cells_on_row(&term, pin.y, pin.right(), archive.x);
        assert!(
            gap.chars().all(|c| c == ' '),
            "the gap between [Pin] and [Archive] should be spaces, got {gap:?}"
        );
    }

    #[test]
    fn activity_menus_open_under_their_pills() {
        let mut app = App::new();
        let _ = draw_once(&mut app, 140, 30);
        app.open_subagents_overlay();
        let _ = draw_once(&mut app, 140, 30);
        let pill = app.hits.subagents_pill;
        let menu = app.hits.overlay_box;
        assert!(pill.width > 0 && menu.height > 0);
        assert_eq!(
            menu.y,
            pill.bottom(),
            "the subagent menu should drop from its pill, not the composer"
        );
        assert!(
            menu.y < app.overlay_anchor.y,
            "activity menus sit in the header, not above the input"
        );

        app.overlay = Some(Overlay::Tools {
            cursor: 0,
            count: app.sessions[0].layer_tools().len().max(1),
        });
        let _ = draw_once(&mut app, 140, 30);
        let tools = app.hits.tools_pill;
        assert_eq!(app.hits.overlay_box.y, tools.bottom());
        assert!(
            app.hits.overlay_box.right() >= tools.right(),
            "header menus right-align to the pill that opened them"
        );
    }

    #[test]
    fn pinning_a_session_keeps_it_above_the_others() {
        let mut app = App::new();
        let last = app.sessions.len() - 1;
        let last_title = app.sessions[last].title.clone();
        app.toggle_session_pin(last);
        assert_eq!(app.visible_sessions()[0], last);
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains('★'), "a starred session shows a pin mark");
        app.toggle_session_pin(last);
        assert_ne!(app.visible_sessions()[0], last);
        assert_eq!(app.sessions[last].title, last_title);
    }

    #[test]
    fn archive_hides_a_session_and_delete_removes_it() {
        let mut app = App::new();
        let first_title = app.sessions[0].title.clone();
        let before = app.visible_sessions().len();
        app.archive_session(0);
        assert!(
            app.sessions
                .iter()
                .any(|s| s.title == first_title && s.archived)
        );
        assert_eq!(app.visible_sessions().len(), before - 1);
        assert!(!app.sessions[app.active].archived);

        let target = app.active;
        let title = app.sessions[target].title.clone();
        app.overlay = Some(Overlay::ConfirmDelete {
            session: target,
            cursor: 0,
        });
        let dialog = draw_once(&mut app, 100, 30);
        assert!(dialog.contains("Confirm delete"));
        assert!(dialog.contains("Cancel"));
        assert!(dialog.contains("Delete"));
        app.activate_overlay(0);
        assert!(
            app.sessions.iter().any(|s| s.title == title),
            "Cancel keeps the session"
        );
        app.overlay = Some(Overlay::ConfirmDelete {
            session: target,
            cursor: 1,
        });
        app.activate_overlay(1);
        assert!(app.sessions.iter().all(|s| s.title != title || s.archived));
    }

    #[test]
    fn clicking_trash_asks_before_deleting() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        let _ = draw_once(&mut app, 100, 30);
        let (_, row) = app.hits.sessions[0];
        app.mouse = Some(Position::new(row.x + 1, row.y + 1));
        let _ = draw_once(&mut app, 100, 30);
        let (index, trash) = app.hits.delete[0];
        let before = app.sessions.len();
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: trash.x,
            row: trash.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(matches!(
            app.overlay,
            Some(Overlay::ConfirmDelete { session, .. }) if session == index
        ));
        assert_eq!(app.sessions.len(), before, "delete waits for confirmation");

        let dialog = draw_once(&mut app, 100, 30);
        assert!(dialog.contains("Confirm delete"));
        assert!(dialog.contains("Cancel"));
        assert!(dialog.contains("Delete"));

        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.overlay.is_none(), "Escape dismisses the dialog");
        assert_eq!(app.sessions.len(), before);

        app.overlay = Some(Overlay::ConfirmDelete {
            session: index,
            cursor: 0,
        });
        let _ = draw_once(&mut app, 100, 30);
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            app.overlay.is_none(),
            "a click outside dismisses the dialog"
        );
        assert_eq!(app.sessions.len(), before);
    }

    #[test]
    fn queued_mode_chips_are_bracketed_words() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        app.send_text("kick off a turn".into());
        app.sessions[app.active].queue.push(QueuedMessage {
            text: "hold on".into(),
            mode: QueueMode::Turn,
        });
        let text = draw_once(&mut app, 120, 30);
        assert!(text.contains("[Queued]"));
        assert!(text.contains("[Boundary]"));
        assert!(text.contains("[Interrupt]"));
        assert!(text.contains("[Edit]"));
        assert!(!text.contains("[Edit all]"));
        assert!(text.contains("[x]"));

        app.sessions[app.active].queue.push(QueuedMessage {
            text: "and another".into(),
            mode: QueueMode::Turn,
        });
        let both = draw_once(&mut app, 120, 30);
        assert!(both.contains("[Edit all]"));
    }

    #[test]
    fn editing_the_queue_combines_every_message_in_the_composer() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        app.send_text("kick off a turn".into());
        app.sessions[app.active].queue.push(QueuedMessage {
            text: "hold on".into(),
            mode: QueueMode::Turn,
        });
        app.sessions[app.active].queue.push(QueuedMessage {
            text: "also this".into(),
            mode: QueueMode::Turn,
        });
        let _ = draw_once(&mut app, 140, 30);
        let edit = app.hits.queue_edit;
        assert!(edit.width > 0, "the group edit chip is on the queue header");
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: edit.x,
            row: edit.y,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.input.text(), "hold on\n\nalso this");
        assert!(app.sessions[app.active].queue.is_empty());
    }

    #[test]
    fn up_arrow_on_an_empty_composer_recalls_the_whole_queue() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        app.send_text("kick off a turn".into());
        app.sessions[app.active].queue.push(QueuedMessage {
            text: "first thought".into(),
            mode: QueueMode::Turn,
        });
        app.sessions[app.active].queue.push(QueuedMessage {
            text: "second thought".into(),
            mode: QueueMode::Boundary,
        });
        assert!(app.input.is_empty());
        app.handle_key(KeyEvent::from(KeyCode::Up));
        assert_eq!(app.input.text(), "first thought\n\nsecond thought");
        assert!(app.sessions[app.active].queue.is_empty());
    }

    #[test]
    fn up_arrow_with_typed_text_still_scrolls_the_transcript() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        app.send_text("kick off a turn".into());
        app.sessions[app.active].queue.push(QueuedMessage {
            text: "stay queued".into(),
            mode: QueueMode::Turn,
        });
        for ch in "draft".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        let _ = draw_once(&mut app, 80, 24);
        let before = app.sessions[app.active].scroll;
        app.handle_key(KeyEvent::from(KeyCode::Up));
        assert_eq!(app.input.text(), "draft");
        assert_eq!(app.sessions[app.active].queue.len(), 1);
        assert!(
            app.sessions[app.active].scroll <= before,
            "Up with a non-empty composer still scrolls the transcript"
        );
    }

    #[test]
    fn the_sidebar_scrolls_when_sessions_overflow() {
        use crossterm::event::{MouseEvent, MouseEventKind};

        let mut app = App::new();
        for _ in 0..8 {
            app.new_session();
        }
        let _ = draw_once(&mut app, 80, 14);
        assert!(
            app.sidebar_view < app.visible_sessions().len(),
            "enough sessions to overflow the list"
        );
        let top = app.hits.sessions[0].0;
        app.scroll_sidebar(1);
        let _ = draw_once(&mut app, 80, 14);
        assert_ne!(
            app.hits.sessions[0].0, top,
            "scrolling the sidebar reveals a later session"
        );

        let list = app.hits.sidebar_list;
        let before = app.sidebar_scroll;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: list.x + 1,
            row: list.y + 1,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            app.sidebar_scroll > before,
            "the wheel over the sidebar scrolls the session list"
        );
    }

    #[test]
    fn hide_and_show_buttons_toggle_the_sidebar() {
        let mut app = App::new();
        let open = draw_once(&mut app, 100, 30);
        assert!(open.contains("[Hide]"), "open sidebar offers Hide");
        assert!(!open.contains("[Show]"));
        assert!(app.hits.sidebar_toggle.width > 0);

        app.sidebar_open = false;
        let closed = draw_once(&mut app, 100, 30);
        assert!(closed.contains("[Show]"), "closed sidebar offers Show");
        assert!(!closed.contains("[Hide]"));
        // [Show] is in the terminal's top-left cell.
        assert_eq!(app.hits.sidebar_toggle.x, 0);
        assert_eq!(app.hits.sidebar_toggle.y, 0);
    }

    #[test]
    fn ctrl_b_toggles_the_sidebar() {
        let mut app = App::new();
        assert!(app.sidebar_open);
        let ctrl = |c: char| {
            let mut key = KeyEvent::from(KeyCode::Char(c));
            key.modifiers = KeyModifiers::CONTROL;
            key
        };
        app.handle_key(ctrl('b'));
        assert!(!app.sidebar_open);
    }

    #[test]
    fn the_first_session_opens_on_a_file_write_and_edit_diff() {
        let mut app = App::new();
        // Session 1 (the default) seeds an extraction: a written module and an
        // edited middleware, both shown as diffs on the parent transcript.
        assert_eq!(app.active, 0);

        // Draw once to learn the transcript height. The write sits above the
        // edit, so scroll to the top for one and to the bottom for the other.
        let _ = draw_once(&mut app, 100, 40);
        app.scroll_lines(-(app.transcript_total as isize));
        let top = draw_once(&mut app, 100, 40);
        assert!(top.contains("Created"), "the write shows a Created header");
        assert!(top.contains("verify-token.ts"), "the written path shows");

        // The edit sits after the write and before the inlined subagent cards,
        // so the tail is no longer the edit. Page down from the top to it.
        let mut found_edit = false;
        let max = app.transcript_total.saturating_sub(app.transcript_view);
        for scroll in 0..=max {
            app.sessions[0].pinned = false;
            app.sessions[0].scroll = scroll;
            let page = draw_once(&mut app, 100, 40);
            if page.contains("Edited") && page.contains("auth.ts") {
                found_edit = true;
                break;
            }
        }
        assert!(found_edit, "the edit shows an Edited header on some page");
    }

    #[test]
    fn the_input_footer_carries_agent_model_effort_permissions_and_sandbox() {
        let mut app = App::new();
        let text = draw_once(&mut app, 140, 30);
        assert!(text.contains("[Cockpit]"));
        assert!(text.contains("[Grok Code]"));
        assert!(text.contains("[Balanced]"));
        assert!(text.contains("[permissions: ask]"));
        assert!(text.contains("[sandbox: on]"));
        assert!(text.contains("[Send]"));
        assert!(app.hits.agent_pill.width > 0);
        assert!(app.hits.model_pill.width > 0);
        assert!(app.hits.effort_pill.width > 0);
        assert!(app.hits.permissions_pill.width > 0);
        assert!(app.hits.sandbox_pill.width > 0);
    }

    #[test]
    fn a_narrow_footer_uses_compact_pill_labels() {
        let mut app = App::new();
        app.sidebar_open = false;
        let text = draw_once(&mut app, 64, 24);
        assert!(
            text.contains("[Cockpit]"),
            "the footer keeps the session agent while a subagent holds the chat"
        );
        assert!(text.contains("[Balanced]"), "effort is just the level");
        assert!(text.contains("[ask]"), "permissions is just the mode");
        assert!(text.contains("[on]"), "sandbox is just the mode");
        assert!(
            !text.contains("[permissions:"),
            "the long permissions label should not fit"
        );
        assert!(!text.contains("[sandbox:"));
    }

    #[test]
    fn the_activity_bar_shows_layer_counts_and_omits_finished_subagents() {
        let mut app = App::new();
        let text = draw_once(&mut app, 140, 30);
        assert!(text.contains("[subagents]"));
        assert!(text.contains("[background tasks: 1]"));
        assert!(text.contains("[timers: 1]"));
        assert!(text.contains("[tools: 5]"));
        assert!(text.contains("[skills: 3]"));
        assert!(app.hits.subagents_pill.width > 0);
        assert!(app.hits.tools_pill.width > 0);
        assert!(app.hits.skills_pill.width > 0);

        app.open_subagents_overlay();
        let _ = draw_once(&mut app, 140, 30);
        assert_eq!(app.overlay.unwrap().len(), 1, "only background workers");
        let live: Vec<&str> = app.sessions[0]
            .background_workers()
            .iter()
            .map(|(_, node)| node.name.as_str())
            .collect();
        assert_eq!(live, ["Write regression test"]);
        assert!(
            app.sessions[0]
                .subagents
                .iter()
                .any(|node| node.name == "Explore call sites" && node.is_active()),
            "the live interactive child is not a picker row"
        );
        assert!(
            app.sessions[0]
                .subagents
                .iter()
                .any(|node| node.name == "Scan changelog" && !node.is_active()),
            "the finished subagent remains on the tree but not in the picker"
        );
        let menu = draw_once(&mut app, 140, 30);
        assert!(menu.contains("Write regression test"));
        assert!(menu.contains("Working"));
        assert_eq!(app.hits.overlay_rows.len(), 1);
    }

    #[test]
    fn the_first_session_opens_inside_the_live_interactive_subagent() {
        let mut app = App::new();
        assert_eq!(app.sessions[0].focus, vec![0]);
        assert!(app.sessions[0].locked_in_interactive());
        let text = draw_once(&mut app, 140, 30);
        assert!(text.contains("Explore call sites"));
        assert!(text.contains("Ask anything"));
        assert!(text.contains("What about the tests?"));
        assert!(text.contains("Write regression test"));
        assert!(
            app.hits.crumbs.is_empty(),
            "the stack is status, not a way out while the explorer is live"
        );

        let mut found_parent = false;
        let mut found_early = false;
        let max = app.transcript_total.saturating_sub(app.transcript_view);
        for scroll in 0..=max {
            app.sessions[0].pinned = false;
            app.sessions[0].scroll = scroll;
            let page = draw_once(&mut app, 140, 30);
            found_parent |= page.contains("verify-token.ts");
            found_early |= page.contains("Look at every jwt.verify");
            if found_parent && found_early {
                break;
            }
        }
        assert!(
            found_parent,
            "parent history stays in the same transcript while the explorer is live"
        );
        assert!(
            found_early,
            "the explorer's earlier turns stay in the same transcript"
        );
    }

    #[test]
    fn focusing_an_interactive_subagent_scopes_tools_and_transcript() {
        let mut app = App::new();
        let text = draw_once(&mut app, 140, 30);
        assert!(text.contains("Explore call sites"));
        assert!(text.contains("[tools: 5]"));
        assert!(text.contains("[skills: 3]"));
        assert!(text.contains("Ask anything"));
        assert!(text.contains("jwt.verify"));
        assert!(text.contains("[Grok Code]"));
        assert!(text.contains("Write regression test"));
    }

    #[test]
    fn clear_while_locked_wipes_the_explorer_not_the_parent() {
        let mut app = App::new();
        assert!(app.sessions[0].locked_in_interactive());
        let parent_len = app.sessions[0].messages.len();
        app.run_command("clear");
        assert_eq!(app.sessions[0].focus, vec![0]);
        assert!(app.sessions[0].locked_in_interactive());
        assert!(app.sessions[0].focused_messages().is_empty());
        assert_eq!(app.sessions[0].messages.len(), parent_len);
    }

    #[test]
    fn interactive_done_returns_to_the_parent_and_late_work_is_attributed() {
        let mut app = App::new();
        assert!(app.sessions[0].locked_in_interactive());
        app.send_text("Walk me through handshake.ts".into());
        play_until_idle(&mut app);
        assert!(
            app.sessions[0].locked_in_interactive(),
            "the first reply stays in the explorer"
        );
        assert!(
            app.sessions[0].subagents[0]
                .messages
                .iter()
                .any(|message| message.plain().contains("401 vs 403"))
        );

        app.send_text("That's enough — hand back".into());
        play_until_idle(&mut app);
        assert!(
            app.sessions[0].focus.is_empty(),
            "done should route the next message to the main agent"
        );
        let mut found_handoff = false;
        let _ = draw_once(&mut app, 140, 40);
        let max = app.transcript_total.saturating_sub(app.transcript_view);
        for scroll in 0..=max {
            app.sessions[0].pinned = false;
            app.sessions[0].scroll = scroll;
            let page = draw_once(&mut app, 140, 40);
            if page.contains("I'll return the remaining sites") {
                found_handoff = true;
                break;
            }
        }
        assert!(
            found_handoff,
            "the explorer's last turn stays in the same transcript after done"
        );
        assert!(!app.sessions[0].subagents[0].is_active());
        assert!(app.sessions[0].subagents[0].children[0].is_active());
        assert!(
            app.sessions[0].subagents[0]
                .messages
                .iter()
                .any(|message| message.segments.iter().any(
                    |segment| matches!(segment, model::Segment::Tool { name, .. } if name == "done")
                )),
            "the explorer's last turn shows the done tool call"
        );

        let start = Instant::now();
        app.sessions[0].subagents[0].children[0].ready_at = Some(start);
        app.tick_all(start + Duration::from_secs(1));
        assert!(
            app.sessions[0].messages.iter().any(|message| {
                matches!(
                    message.segments.first(),
                    Some(model::Segment::Injection { from, body })
                        if from == "Explore call sites" && body.contains("verify-token.test.ts")
                )
            }),
            "late background result lands on the main agent"
        );
        let text = draw_once(&mut app, 140, 30);
        assert!(text.contains("▸ Explore call sites"));
        assert!(text.contains("Add tests for the new module"));

        app.send_text("Add tests for the new module".into());
        play_until_idle(&mut app);
        assert!(
            app.sessions[0]
                .messages
                .iter()
                .any(|message| message
                    .segments
                    .iter()
                    .any(|segment| matches!(segment, model::Segment::Diff(diff) if diff.path.contains("verify-token.test.ts"))))
        );

        app.send_text("Migrate handshake.ts next".into());
        play_until_idle(&mut app);
        let after = draw_once(&mut app, 140, 40);
        assert!(after.contains("handshake.ts"));
        assert!(after.contains("Edited") || after.contains("verifyToken"));
    }

    #[test]
    fn hovering_a_picker_row_highlights_it() {
        use crossterm::event::{MouseEvent, MouseEventKind};

        let mut app = App::new();
        let mut ctrl_p = KeyEvent::from(KeyCode::Char('p'));
        ctrl_p.modifiers = KeyModifiers::CONTROL;
        app.handle_key(ctrl_p);
        let _ = draw_once(&mut app, 100, 30);
        assert!(app.hits.overlay_rows.len() >= 2);
        let (index, rect) = app.hits.overlay_rows[1];
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Moved,
            column: rect.x,
            row: rect.y,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.overlay.unwrap().cursor(), index);
    }

    #[test]
    fn dragging_the_transcript_scrollbar_moves_scroll() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        let _ = draw_once(&mut app, 100, 20);
        let track = app.hits.transcript_sb;
        assert!(track.height > 1, "the first session should overflow");
        assert_eq!(track.width, 1, "only the rightmost column is the track");
        assert_eq!(track.x, app.hits.transcript.right().saturating_sub(1));
        let start = app.sessions[0].scroll;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: track.x,
            row: track.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            app.sessions[0].scroll < start,
            "clicking the top of the track jumps toward the top"
        );
        assert!(!app.sessions[0].pinned);
        assert_eq!(app.scroll_drag, Some(ScrollDrag::Transcript));
    }

    #[test]
    fn clicking_the_transcript_body_does_not_start_a_scroll_drag() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        let _ = draw_once(&mut app, 100, 20);
        let area = app.hits.transcript;
        assert!(
            app.hits.transcript_sb.width > 0,
            "the first session should overflow"
        );
        let track = app.hits.transcript_sb;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: area.x + 2,
            row: area.y + area.height / 2,
            modifiers: KeyModifiers::empty(),
        });
        assert!(
            app.scroll_drag.is_none(),
            "a click in the chat body is not a scrollbar drag"
        );
        let after_click = app.sessions[0].scroll;
        // If the body click had armed a drag, sliding onto the track would
        // jump the viewport. Sticky / subagent hits may change scroll once;
        // a second motion must not keep scrolling.
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column: track.x,
            row: track.y,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            app.sessions[0].scroll, after_click,
            "dragging after a body click must not scroll the transcript"
        );
    }

    #[test]
    fn clicking_a_sidebar_row_does_not_start_a_scroll_drag() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        for _ in 0..8 {
            app.new_session();
        }
        let _ = draw_once(&mut app, 80, 14);
        assert!(
            app.sidebar_view < app.visible_sessions().len(),
            "enough sessions to overflow the list"
        );
        assert_eq!(app.hits.sidebar_sb.width, 1);
        assert_eq!(
            app.hits.sidebar_sb.x,
            app.hits.sidebar_list.right().saturating_sub(1)
        );
        let (index, row) = app.hits.sessions[1];
        let before = app.sidebar_scroll;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: row.x + 1,
            row: row.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.scroll_drag.is_none());
        assert_eq!(app.sidebar_scroll, before);
        assert_eq!(app.active, index);
    }

    #[test]
    fn header_popover_wheel_pans_without_moving_the_cursor() {
        use crossterm::event::{MouseEvent, MouseEventKind};

        let mut app = App::new();
        show_parent(&mut app);
        let count = app.sessions[0].layer_skills().len();
        let _ = draw_once(&mut app, 140, 30);
        app.show_overlay(Overlay::Skills { cursor: 0, count });
        let _ = draw_once(&mut app, 140, 30);
        assert!(
            app.overlay_view < count,
            "skills should overflow the menu so the wheel has somewhere to pan"
        );
        let cursor = app.overlay.unwrap().cursor();
        let start = app.overlay_scroll;
        let box_rect = app.hits.overlay_box;
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: box_rect.x + 1,
            row: box_rect.y + 2,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            app.overlay.unwrap().cursor(),
            cursor,
            "header menus pan the viewport; they do not step the highlight"
        );
        assert!(
            app.overlay_scroll > start,
            "the wheel should move the visible window down"
        );
    }

    #[test]
    fn cycling_a_tool_tier_warns_when_the_cache_breaks() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        show_parent(&mut app);
        let count = app.sessions[0].layer_tools().len();
        let _ = draw_once(&mut app, 140, 30);
        app.show_overlay(Overlay::Tools { cursor: 0, count });
        let text = draw_once(&mut app, 140, 30);
        assert!(text.contains("enabled ·"));
        assert!(text.contains("discoverable ·"));
        assert!(text.contains("disabled ·"));

        let enabled = app.sessions[0]
            .tools
            .iter()
            .position(|tool| tool.tier == model::ToolTier::Enabled)
            .expect("seeded catalog has an enabled tool");
        let row = app
            .hits
            .overlay_rows
            .iter()
            .find(|(index, _)| *index == enabled)
            .map(|(_, rect)| *rect)
            .expect("enabled tool is on screen");
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: row.x,
            row: row.y,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            app.sessions[0].tools[enabled].tier,
            model::ToolTier::Discoverable
        );
        assert!(
            app.tool_cache_warn,
            "leaving enabled busts the prompt cache"
        );
        let warned = draw_once(&mut app, 140, 30);
        assert!(warned.contains("busts the prompt cache"), "{warned}");

        app.show_overlay(Overlay::Tools { cursor: 0, count });
        let discoverable = app.sessions[0]
            .tools
            .iter()
            .position(|tool| tool.tier == model::ToolTier::Discoverable)
            .expect("seeded catalog has a discoverable tool");
        let _ = draw_once(&mut app, 140, 30);
        let row = app
            .hits
            .overlay_rows
            .iter()
            .find(|(index, _)| *index == discoverable)
            .map(|(_, rect)| *rect)
            .expect("discoverable tool is on screen");
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: row.x,
            row: row.y,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(
            app.sessions[0].tools[discoverable].tier,
            model::ToolTier::Disabled
        );
        assert!(
            !app.tool_cache_warn,
            "discoverable ↔ disabled must not bust the cache"
        );
    }

    #[test]
    fn slash_opens_the_palette_and_enter_runs_the_command() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1; // the blank session
        for ch in "/new".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        assert!(app.slash_active(), "a bare /query opens the palette");
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("Commands"), "the palette is titled");
        assert!(text.contains("/new"), "and lists the matching command");

        let before = app.sessions.len();
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert_eq!(app.sessions.len(), before + 1, "/new started a session");
        assert!(app.input.text().is_empty(), "the composer was cleared");
        assert!(!app.slash_active());
    }

    #[test]
    fn slash_effort_opens_the_effort_picker() {
        let mut app = App::new();
        for ch in "/effort".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        // Tab completes to "/effort ", which closes the palette (now typing
        // arguments); Enter on the completed command still runs it.
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.overlay, Some(Overlay::Effort { .. })));
    }

    #[test]
    fn slash_think_toggles_conversation_thinking() {
        let mut app = App::new();
        show_parent(&mut app);
        let _ = draw_once(&mut app, 100, 30);
        app.scroll_lines(-(app.transcript_total as isize));
        let hidden = draw_once(&mut app, 100, 30);
        assert!(hidden.contains("▸ Thought"));
        assert!(
            !hidden.contains("Extracting that keeps the two sites"),
            "settled thinking stays collapsed by default"
        );

        app.run_command("think");
        assert!(app.sessions[0].show_thinking);
        let note = draw_once(&mut app, 100, 30);
        assert!(note.contains("Showing thinking for this conversation."));
        app.scroll_lines(-(app.transcript_total as isize));
        let shown = draw_once(&mut app, 100, 30);
        assert!(shown.contains("▾ Thought"));
        assert!(shown.contains("Extracting that keeps the two sites"));

        app.run_command("think");
        assert!(!app.sessions[0].show_thinking);
        let hidden_note = draw_once(&mut app, 100, 30);
        assert!(hidden_note.contains("Hiding thinking for this conversation."));
        app.scroll_lines(-(app.transcript_total as isize));
        let hidden_again = draw_once(&mut app, 100, 30);
        assert!(hidden_again.contains("▸ Thought"));
    }

    #[test]
    fn clicking_think_chip_overrides_one_message() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        show_parent(&mut app);
        let _ = draw_once(&mut app, 100, 30);
        app.scroll_lines(-(app.transcript_total as isize));
        let _ = draw_once(&mut app, 100, 30);
        let (index, chip) = app.hits.thinking[0];
        assert!(app.sessions[0].messages[index].has_thinking());
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: chip.x,
            row: chip.y,
            modifiers: KeyModifiers::empty(),
        });
        assert_eq!(app.sessions[0].messages[index].thinking_open, Some(true));
        app.scroll_lines(-(app.transcript_total as isize));
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("▾ Thought"));
        assert!(text.contains("Extracting that keeps the two sites"));

        app.run_command("think");
        app.run_command("think");
        assert!(app.sessions[0].messages[index].thinking_open.is_none());
        assert!(!app.sessions[0].show_thinking);
    }

    #[test]
    fn a_live_turn_shows_thinking_before_tools_and_replies() {
        let mut app = App::new();
        assert!(!app.sessions[0].show_thinking);
        app.send_text("Walk me through handshake.ts".into());
        let start = Instant::now();
        app.tick_all(start + Duration::from_millis(200));
        let text = draw_once(&mut app, 140, 30);
        assert!(
            text.contains("Thinking"),
            "a live reasoning pass should show a Thinking header"
        );
        assert!(
            !text.contains("▸ Thought"),
            "the settled Thought row waits until the pass finishes"
        );
        let streaming = app.sessions[0]
            .focused_messages()
            .last()
            .expect("the explorer is streaming a reply");
        assert!(streaming.streaming);
        assert!(streaming.has_thinking());

        play_until_idle(&mut app);
        let settled = draw_once(&mut app, 140, 30);
        assert!(
            settled.contains("▸ Thought"),
            "finished reasoning collapses to Thought before the reply"
        );
        assert!(
            !settled.contains("They want the handshake walkthrough"),
            "the body stays folded once the pass is over"
        );
        assert!(settled.contains("401 vs 403") || settled.contains("handshake.ts"));
    }

    #[test]
    fn clicking_agent_name_shows_turn_stats() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        show_parent(&mut app);
        let _ = draw_once(&mut app, 100, 30);
        app.scroll_lines(-(app.transcript_total as isize));
        let hidden = draw_once(&mut app, 100, 30);
        assert!(
            !hidden.contains("TTFT"),
            "turn stats stay collapsed until the name is clicked"
        );
        assert!(!app.hits.agent_name.is_empty());
        let (index, name) = app.hits.agent_name[0];
        assert!(app.sessions[0].messages[index].stats.is_some());
        assert!(!app.sessions[0].messages[index].stats_open);

        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: name.x,
            row: name.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.sessions[0].messages[index].stats_open);
        app.scroll_lines(-(app.transcript_total as isize));
        let shown = draw_once(&mut app, 100, 30);
        assert!(shown.contains("OpenAI / GPT-5 Codex"));
        assert!(shown.contains("TTFT"));
        assert!(shown.contains("TPS"));
        assert!(shown.contains("Cache"));
        assert!(shown.contains('%'));

        let (index, name) = app.hits.agent_name[0];
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: name.x,
            row: name.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(!app.sessions[0].messages[index].stats_open);
        app.scroll_lines(-(app.transcript_total as isize));
        let hidden_again = draw_once(&mut app, 100, 30);
        assert!(!hidden_again.contains("TTFT"));
    }

    #[test]
    fn slash_compact_shows_a_summary_chip() {
        use crossterm::event::{MouseButton, MouseEvent, MouseEventKind};

        let mut app = App::new();
        show_parent(&mut app);
        app.run_command("compact");
        let collapsed = draw_once(&mut app, 100, 30);
        assert!(collapsed.contains("folded 2 older turns into a summary"));
        assert!(collapsed.contains("[show summary]"));
        assert!(
            !collapsed.contains("The user asked:"),
            "the brief stays collapsed until the chip is clicked"
        );
        assert!(!app.hits.summaries.is_empty());

        let (index, chip) = app.hits.summaries[0];
        assert!(app.sessions[0].messages[index].has_compaction());
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: chip.x,
            row: chip.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(app.sessions[0].messages[index].summary_open);
        let shown = draw_once(&mut app, 100, 30);
        assert!(shown.contains("[hide summary]"));
        assert!(shown.contains("The user asked:"));
        assert!(shown.contains("created src/auth/verify-token.ts"));

        let (index, chip) = app.hits.summaries[0];
        app.handle_mouse(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: chip.x,
            row: chip.y,
            modifiers: KeyModifiers::empty(),
        });
        assert!(!app.sessions[0].messages[index].summary_open);
        let hidden_again = draw_once(&mut app, 100, 30);
        assert!(hidden_again.contains("[show summary]"));
        assert!(!hidden_again.contains("The user asked:"));
    }

    #[test]
    fn slash_compact_on_a_blank_session_says_nothing_to_compact() {
        let mut app = App::new();
        app.active = app.sessions.len() - 1;
        app.run_command("compact");
        let text = draw_once(&mut app, 100, 30);
        assert!(text.contains("Nothing to compact yet."));
        assert!(app.hits.summaries.is_empty());
    }

    #[test]
    fn escape_dismisses_the_palette_without_clearing_the_query() {
        let mut app = App::new();
        for ch in "/mo".chars() {
            app.handle_key(KeyEvent::from(KeyCode::Char(ch)));
        }
        assert!(app.slash_active());
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(!app.slash_active(), "Escape hides the palette");
        assert_eq!(app.input.text(), "/mo", "but keeps what was typed");
    }

    #[test]
    fn the_model_picker_drills_provider_then_model() {
        let mut app = App::new();
        let mut ctrl_p = KeyEvent::from(KeyCode::Char('p'));
        ctrl_p.modifiers = KeyModifiers::CONTROL;
        app.handle_key(ctrl_p);
        assert!(matches!(app.overlay, Some(Overlay::Provider { .. })));

        // Second provider (Anthropic), then its second model (Claude Opus 4.1,
        // global index 2).
        app.handle_key(KeyEvent::from(KeyCode::Down));
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(matches!(app.overlay, Some(Overlay::Model { .. })));
        app.handle_key(KeyEvent::from(KeyCode::Down));
        app.handle_key(KeyEvent::from(KeyCode::Enter));
        assert!(app.overlay.is_none());
        assert_eq!(app.model, 2);
    }

    #[test]
    fn esc_steps_back_from_the_model_list_to_the_provider_list() {
        let mut app = App::new();
        let mut ctrl_p = KeyEvent::from(KeyCode::Char('p'));
        ctrl_p.modifiers = KeyModifiers::CONTROL;
        app.handle_key(ctrl_p);
        app.handle_key(KeyEvent::from(KeyCode::Enter)); // drill into a provider
        assert!(matches!(app.overlay, Some(Overlay::Model { .. })));
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(matches!(app.overlay, Some(Overlay::Provider { .. })));
        app.handle_key(KeyEvent::from(KeyCode::Esc));
        assert!(app.overlay.is_none());
    }

    #[test]
    fn the_wheel_moves_the_picker_selection_when_hovered() {
        use crossterm::event::{MouseEvent, MouseEventKind};

        let mut app = App::new();
        // Open the provider picker and record its rect.
        let mut ctrl_p = KeyEvent::from(KeyCode::Char('p'));
        ctrl_p.modifiers = KeyModifiers::CONTROL;
        app.handle_key(ctrl_p);
        let _ = draw_once(&mut app, 100, 30);
        let box_rect = app.hits.overlay_box;
        assert!(box_rect.height > 0, "the picker recorded its rect");

        let before = app.overlay.unwrap().cursor();
        let scroll = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: box_rect.x + 1,
            row: box_rect.y + 1,
            modifiers: KeyModifiers::empty(),
        };
        app.handle_mouse(scroll);
        assert_ne!(
            app.overlay.unwrap().cursor(),
            before,
            "scrolling over the picker moved the selection"
        );

        // A scroll outside the picker must not move its selection.
        let held = app.overlay.unwrap().cursor();
        let outside = MouseEvent {
            kind: MouseEventKind::ScrollDown,
            column: 0,
            row: 0,
            modifiers: KeyModifiers::empty(),
        };
        app.handle_mouse(outside);
        assert_eq!(app.overlay.unwrap().cursor(), held);
    }
}
