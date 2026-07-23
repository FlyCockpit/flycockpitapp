//! `/resume` + `/sessions` pane — the fullscreen session browser
//! (GOALS §17f).
//!
//! A scrollable list of rounded-border session cards, tier-sorted, with
//! fork drill-in navigation and an archive/delete confirm flow. Selecting
//! a card resumes that session. Mirrors [`crate::tui::stats_pane`]'s shape
//! (`open` / `handle_key` / `render`); `App` opens it over the chat body
//! and routes input/render the same way.
//!
//! ## Data sources
//!
//! - **Tiers 1-2** (active jobs / processing) come from the daemon's
//!   in-memory per-session [`cockpit_core::daemon::session_worker::LiveState`]
//!   via the `SessionLiveStatus` RPC. Daemon down → no live tiers, no
//!   crash (sessions fall to the DB-derived tiers).
//! - **Tiers 3-5** (unread / pending-question / read) come from the DB
//!   fields on each [`SessionSummary`]: `latest_activity_at` vs.
//!   `last_viewed_at` for read/unread, and `open_interrupts` for the
//!   pending-question split.
//!
//! Two data paths, chosen by `daemon_connected` at [`SessionsPane::open`]:
//!
//! - **Daemon-connected:** the pane is a socket client — fetch / archive /
//!   delete are blocking daemon requests through
//!   [`crate::tui::agent_runner`], and live status (tiers 1-2) is intact.
//! - **Daemonless:** the list is read straight from the session DB
//!   read-only ([`cockpit_db::Db::open_default`], same as `/stats`) via the
//!   shared [`cockpit_db::Db::list_session_summaries`] the daemon also calls,
//!   so ordering / scoping / fork-grouping match. Live status is absent
//!   (every session falls to its DB-derived tier — never an error), and the
//!   mutating actions (resume / archive / delete / unarchive) are disabled
//!   with a non-error hint rather than spawning a daemon or writing the DB.
//!
//! The resume action is *not* performed here — `handle_key` returns a
//! [`SessionsOutcome`] the `App` acts on, reusing the existing
//! session-switch path (`attach_to_session`).

use crossterm::event::{KeyCode, KeyEvent, MouseButton, MouseEvent, MouseEventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use uuid::Uuid;

use crate::tui::agent_runner;
use crate::tui::message_block::{MessageBlock, MessageBlockRole, render_markdown_message_block};
use crate::tui::pane::{Pane, ScrollList};
use crate::tui::pane_shared::{boxed_row, resolve_project_id, short_id};
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};
use cockpit_core::daemon::proto::{MessageRole, SessionMessage, SessionSummary};
use cockpit_db::Db;

/// Root-session row cap for the daemonless direct-DB list — matches the
/// daemon `ListSessions` handler's `100` so both modes show the same set.
const DAEMONLESS_LIST_LIMIT: u32 = 100;
const PREVIEW_PAGE_LIMIT: u32 = 50;
const DOUBLE_CLICK_WINDOW: std::time::Duration = std::time::Duration::from_millis(500);

/// Non-error status shown daemonless when the user tries an action that
/// needs a live daemon (resume, archive/delete, unarchive). Browsing is
/// read-only; running or mutating a session requires the agent loop /
/// single-writer that only the daemon hosts.
const DAEMONLESS_HINT: &str =
    "no daemon — browse only. Start one with `cockpit daemon` to resume or archive.";

/// Tier a session sorts into, top (lowest discriminant) to bottom. Within
/// a tier, sessions sort by `last_active_at` descending. GOALS §17f.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    /// 1 — has active background/loop/timer jobs (daemon-reported).
    ActiveSchedules,
    /// Currently executing a tool call.
    ToolRunning,
    /// Currently waiting on model inference.
    InferenceInProgress,
    /// Durable mid-turn interruption marker.
    Interrupted,
    /// 2 — currently processing a turn (daemon-reported).
    Processing,
    /// 3 — unread: the most recent agent event is newer than the marker.
    Unread,
    /// 4 — read, with a pending question (`open_interrupts > 0`).
    PendingQuestion,
    /// 5 — read, idle, no pending question (ended sessions live here too).
    Idle,
}

impl Tier {
    /// Terse status indicator for the card (kept short per token economy).
    fn label(self) -> &'static str {
        match self {
            Tier::ActiveSchedules => "● jobs running",
            Tier::ToolRunning => "● tool running",
            Tier::InferenceInProgress => "● inference",
            Tier::Interrupted => "● interrupted",
            Tier::Processing => "● working",
            Tier::Unread => "● unread",
            Tier::PendingQuestion => "● question pending",
            Tier::Idle => "idle",
        }
    }

    fn label_for(self, summary: &SessionSummary) -> String {
        match self {
            Tier::PendingQuestion if summary.open_interrupts > 0 => {
                format!("● {} pending", summary.open_interrupts)
            }
            _ => self.label().to_string(),
        }
    }

    /// Accent color for the status indicator.
    fn color(self) -> Color {
        match self {
            Tier::ActiveSchedules => Color::Green,
            Tier::ToolRunning => Color::Blue,
            Tier::InferenceInProgress => Color::Cyan,
            Tier::Interrupted => Color::Red,
            Tier::Processing => Color::Cyan,
            Tier::Unread => Color::Yellow,
            Tier::PendingQuestion => Color::Magenta,
            Tier::Idle => Color::Indexed(MUTED_COLOR_INDEX),
        }
    }
}

/// Classify one session into its tier given its live daemon status.
/// `live = (has_active_schedules, processing)`; `None` when the daemon has no
/// live worker (or is unreachable) — then only the DB-derived tiers 3-5
/// apply. Pure so the tiering rules are unit-testable without a daemon.
pub fn classify(summary: &SessionSummary, live: Option<(bool, bool)>) -> Tier {
    if let Some((has_schedules, _processing)) = live
        && has_schedules
    {
        return Tier::ActiveSchedules;
    }
    match summary.activity_state {
        Some(cockpit_core::daemon::proto::SessionActivityState::ToolRunning) => {
            return Tier::ToolRunning;
        }
        Some(cockpit_core::daemon::proto::SessionActivityState::InferenceInProgress) => {
            return Tier::InferenceInProgress;
        }
        Some(cockpit_core::daemon::proto::SessionActivityState::Interrupted) => {
            return Tier::Interrupted;
        }
        Some(cockpit_core::daemon::proto::SessionActivityState::PendingQuestion) => {
            return Tier::PendingQuestion;
        }
        Some(cockpit_core::daemon::proto::SessionActivityState::Parked) | None => {}
    }
    if let Some((_has_schedules, processing)) = live
        && processing
    {
        return Tier::Processing;
    }
    if is_unread(summary) {
        return Tier::Unread;
    }
    if summary.open_interrupts > 0 {
        return Tier::PendingQuestion;
    }
    Tier::Idle
}

/// Unread = the session has agent-produced activity newer than the
/// last-viewed marker. A never-viewed session with any agent activity is
/// unread; a session with no agent activity is never unread.
fn is_unread(summary: &SessionSummary) -> bool {
    match summary.latest_activity_at {
        None => false,
        Some(activity) => match summary.last_viewed_at {
            None => true,
            Some(viewed) => activity > viewed,
        },
    }
}

/// Sort `(summary, live)` pairs into display order: by tier ascending,
/// then `last_active_at` descending within a tier. Returns the classified
/// tier alongside each summary so the renderer doesn't re-classify.
pub fn tier_sort(
    mut items: Vec<(SessionSummary, Option<(bool, bool)>)>,
) -> Vec<(SessionSummary, Tier)> {
    let mut classified: Vec<(SessionSummary, Tier)> = items
        .drain(..)
        .map(|(s, live)| {
            let tier = classify(&s, live);
            (s, tier)
        })
        .collect();
    classified.sort_by(|a, b| {
        a.1.cmp(&b.1)
            .then(b.0.last_active_at.cmp(&a.0.last_active_at))
    });
    classified
}

/// One breadcrumb level: the parent session we drilled into (its short id
/// label) and the cards shown at that level.
struct Level {
    /// `None` at the root level; `Some` once we've drilled into a fork.
    parent: Option<SessionSummary>,
    cards: Vec<(SessionSummary, Tier)>,
    list: ScrollList,
}

/// Current archive/delete confirm sub-step (modelled like the model
/// picker's step enum — kept inside the pane, GOALS §17h).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    /// Browsing the list.
    Browse,
    /// Confirm dialog open for the highlighted session. `descendants` is
    /// the cascade count stated to the user; `live` is whether the target
    /// is mid-turn / has jobs (interrupt-first warning). `choice` is the
    /// highlighted button.
    Confirm {
        session_id: Uuid,
        label: String,
        descendants: u32,
        live: bool,
        choice: ConfirmChoice,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConfirmChoice {
    Archive,
    Delete,
    Cancel,
}

/// Active scope. `Project` lists root sessions in the current project;
/// `All` lists every session across projects (each card shows a label).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Scope {
    Project,
    All,
}

/// What the pane asks the `App` to do after a key. `App` owns the resume
/// path (it reuses `attach_to_session`); the pane never switches sessions
/// itself.
pub enum SessionsOutcome {
    /// Close the pane back to chat.
    Close,
    /// Resume this session (load it into the TUI).
    Resume(Uuid),
    /// Load the current browser level via the app-owned async daemon path.
    LoadList,
    /// Load a preview page via the app-owned async daemon path.
    LoadPreview {
        session_id: Uuid,
        before_seq: Option<i64>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    List,
    Preview,
}

#[derive(Debug, Clone)]
struct PreviewState {
    session_id: Uuid,
    messages: Vec<SessionMessage>,
    has_more: bool,
    loading: bool,
    error: Option<String>,
    /// Visual rows above the bottom of the loaded preview.
    scroll: usize,
    block_cache: std::collections::HashMap<(i64, usize), MessageBlock>,
    cache_width: Option<usize>,
}

impl PreviewState {
    fn new(session_id: Uuid) -> Self {
        Self {
            session_id,
            messages: Vec::new(),
            has_more: false,
            loading: false,
            error: None,
            scroll: 0,
            block_cache: std::collections::HashMap::new(),
            cache_width: None,
        }
    }

    fn oldest_seq(&self) -> Option<i64> {
        self.messages.first().map(|message| message.seq)
    }

    fn invalidate_for_width(&mut self, width: usize) {
        if self.cache_width != Some(width) {
            self.block_cache.clear();
            self.cache_width = Some(width);
        }
    }

    fn message_block(&mut self, index: usize, width: usize) -> MessageBlock {
        self.invalidate_for_width(width);
        let seq = self.messages[index].seq;
        let key = (seq, width);
        if let Some(body) = self.block_cache.get(&key) {
            return body.clone();
        }
        let text = self.messages[index].text.clone();
        let body_width = width.saturating_sub(2).max(1);
        let body = render_markdown_message_block(
            &text,
            body_width,
            0,
            2,
            Style::default().fg(Color::White),
        );
        self.block_cache.insert(key, body.clone());
        body
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionsLayout {
    Single {
        body: Rect,
    },
    Split {
        list: Rect,
        preview: Rect,
        left_width: u16,
        right_width: u16,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CardHit {
    index: usize,
    rect: Rect,
}

pub struct SessionsPane {
    /// Resolved current-project id, or `None` when the cwd couldn't be
    /// resolved. When `None` the scope is pinned to `All`.
    project_id: Option<String>,
    scope: Scope,
    /// Whether archived sessions are revealed (toggle, GOALS §17h).
    show_archived: bool,
    /// Breadcrumb stack of fork levels; `levels[0]` is the root list.
    levels: Vec<Level>,
    step: Step,
    /// Last-loaded error (a real failure: a connected daemon's list call
    /// errored, or — daemonless — the DB couldn't be opened), shown
    /// inline in red.
    error: Option<String>,
    /// Transient non-error status line (e.g. the daemonless "browse only"
    /// hint after a resume/archive/delete attempt), shown inline in a
    /// muted style. Never an error state.
    notice: Option<String>,
    loading: Option<&'static str>,
    /// `true` when a daemon is connected at open: the pane fetches via the
    /// RPC path (live status intact). `false` daemonless: it reads
    /// [`Self::db`] directly and disables resume/archive/delete.
    daemon_connected: bool,
    /// Socket for the daemon this pane is attached to. Present only for the
    /// daemon-connected RPC path, including ephemeral daemons that are not
    /// discoverable through the canonical daemon location.
    daemon_socket: Option<std::path::PathBuf>,
    use_emojis: bool,
    /// Read-only session DB handle, opened only in the daemonless case so
    /// the browser can list without a daemon. `None` when daemon-connected
    /// (the RPC path is used) or when the DB couldn't be opened.
    db: Option<Db>,
    /// Rendered body height + content rows at last draw (scroll clamp).
    last_body_height: usize,
    last_content_rows: usize,
    focus: Focus,
    preview: Option<PreviewState>,
    preview_enabled: bool,
    preview_area: Option<Rect>,
    list_area: Option<Rect>,
    card_hits: Vec<CardHit>,
    last_preview_height: usize,
    last_preview_rows: usize,
    last_preview_reached_top: bool,
    preview_clock_ms: fn() -> i64,
    last_card_click: Option<(usize, std::time::Instant)>,
}

impl SessionsPane {
    /// The which-key descriptor for this pane (`crate::tui::keys_overlay`).
    /// Static + data-driven so the overlay never scrapes the help line.
    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Sessions",
            bindings: &[
                KeyBinding {
                    key: "↑/↓",
                    action: "move",
                    desc: "highlight a session",
                },
                KeyBinding {
                    key: "Enter",
                    action: "resume",
                    desc: "resume the highlighted session",
                },
                KeyBinding {
                    key: "→/l",
                    action: "forks",
                    desc: "descend into a session's forks",
                },
                KeyBinding {
                    key: "←/h",
                    action: "back",
                    desc: "ascend to the parent level",
                },
                KeyBinding {
                    key: "a",
                    action: "archived",
                    desc: "toggle showing archived sessions",
                },
                KeyBinding {
                    key: "u / d",
                    action: "archive",
                    desc: "unarchive / archive the highlighted session",
                },
                KeyBinding {
                    key: "q · Esc",
                    action: "close",
                    desc: "close the browser",
                },
            ],
        }
    }

    /// Open the browser for `cwd`. Resolves the project scope and loads
    /// the root level. A load failure (daemon down) is non-fatal — the
    /// pane shows an inline message rather than refusing to open.
    ///
    /// `daemon_connected` selects the data path: connected → the RPC list
    /// (live status intact); daemonless → a read-only direct DB read
    /// ([`Db::open_default`], same as `/stats`), with resume / archive /
    /// delete disabled. A daemonless DB-open failure surfaces as an inline
    /// error, not a crash, and the pane still opens (empty list).
    pub fn open(
        cwd: &std::path::Path,
        daemon_connected: bool,
        daemon_socket: Option<std::path::PathBuf>,
        use_emojis: bool,
    ) -> Self {
        let project_id = resolve_project_id(cwd);
        let scope = if project_id.is_some() {
            Scope::Project
        } else {
            Scope::All
        };
        // Daemonless: open the DB read-only up front (WAL → concurrent
        // readers are safe; the startup probe already established no daemon
        // is writing). Daemon-connected: the RPC path is used, so no direct
        // handle is needed.
        let db = if daemon_connected {
            None
        } else {
            Db::open_default().ok()
        };
        let mut pane = Self {
            project_id,
            scope,
            show_archived: false,
            levels: Vec::new(),
            step: Step::Browse,
            error: None,
            notice: None,
            loading: None,
            daemon_connected,
            daemon_socket,
            use_emojis,
            db,
            last_body_height: 0,
            last_content_rows: 0,
            focus: Focus::List,
            preview: None,
            preview_enabled: false,
            preview_area: None,
            list_area: None,
            card_hits: Vec::new(),
            last_preview_height: 0,
            last_preview_rows: 0,
            last_preview_reached_top: false,
            preview_clock_ms: || chrono::Utc::now().timestamp_millis(),
            last_card_click: None,
        };
        if daemon_connected {
            pane.loading = Some("Loading sessions...");
            pane.levels = vec![Level {
                parent: None,
                cards: Vec::new(),
                list: ScrollList::new(),
            }];
        } else {
            pane.load_root();
        }
        pane
    }

    /// (Re)load the root level for the active scope, discarding any fork
    /// drill-in. Called at open and on a scope / archived-toggle change.
    fn load_root(&mut self) {
        let pid = match self.scope {
            Scope::Project => self.project_id.clone(),
            Scope::All => None,
        };
        if self.daemon_connected {
            self.loading = Some("Loading sessions...");
            self.levels = vec![Level {
                parent: None,
                cards: Vec::new(),
                list: ScrollList::new(),
            }];
            return;
        }
        let cards = self.fetch_level(pid, None);
        self.levels = vec![Level {
            parent: None,
            cards,
            list: ScrollList::new(),
        }];
    }

    pub fn root_request(&self) -> (Option<String>, Option<Uuid>) {
        let level = self.levels.last().expect("at least the root level");
        if let Some(parent) = &level.parent {
            return (None, Some(parent.session_id));
        }
        let project_id = match self.scope {
            Scope::Project => self.project_id.clone(),
            Scope::All => None,
        };
        (project_id, None)
    }

    pub fn is_preview_enabled(&self) -> bool {
        self.preview_enabled
    }

    pub fn apply_sessions_result(
        &mut self,
        result: Result<Vec<SessionSummary>, String>,
    ) -> Vec<Uuid> {
        self.loading = None;
        match result {
            Ok(mut sessions) => {
                self.error = None;
                if !self.show_archived {
                    sessions.retain(|s| s.archived_at.is_none());
                }
                let ids: Vec<_> = sessions.iter().map(|s| s.session_id).collect();
                let cards = tier_sort(sessions.into_iter().map(|s| (s, None)).collect());
                if let Some(level) = self.levels.last_mut() {
                    level.cards = cards;
                    level.list.clamp_cursor(level.cards.len());
                    level.list.set_scroll(0);
                }
                if self.selected_id().is_some() && self.preview_enabled {
                    self.preview = None;
                    if !self.daemon_connected {
                        let _ = self.ensure_preview_for_selection();
                    }
                } else {
                    self.preview = None;
                }
                ids
            }
            Err(e) => {
                self.error = Some(e);
                Vec::new()
            }
        }
    }

    pub fn apply_live_status(&mut self, live: std::collections::HashMap<Uuid, (bool, bool)>) {
        if let Some(level) = self.levels.last_mut() {
            let cards = level
                .cards
                .iter()
                .map(|(summary, _)| {
                    let status = live.get(&summary.session_id).copied();
                    (summary.clone(), status)
                })
                .collect();
            level.cards = tier_sort(cards);
            level.list.clamp_cursor(level.cards.len());
        }
    }

    /// Fetch + tier-sort one level: root sessions (`parent = None`) or the
    /// direct forks of `parent`. Filters archived per the toggle and
    /// attaches live status. Records (clears) the error on success.
    ///
    /// Data path: daemon-connected → the RPC list + per-session live
    /// status; daemonless → a read-only direct DB read with live status
    /// uniformly absent (every session degrades to its DB-derived tier).
    fn fetch_level(
        &mut self,
        project_id: Option<String>,
        parent: Option<Uuid>,
    ) -> Vec<(SessionSummary, Tier)> {
        let listed = if self.daemon_connected {
            match self.daemon_socket.as_deref() {
                Some(socket) => agent_runner::list_sessions_blocking(socket, project_id, parent),
                None => Err("daemon socket unavailable for sessions.list".to_string()),
            }
        } else {
            self.list_sessions_daemonless(project_id.as_deref(), parent)
        };
        match listed {
            Ok(mut sessions) => {
                self.error = None;
                // Archive filter (GOALS §17h): hidden by default.
                if !self.show_archived {
                    sessions.retain(|s| s.archived_at.is_none());
                }
                // Live status only exists with a daemon. Daemonless, every
                // session falls to its DB-derived tier (`None` live), which
                // `classify` handles without error.
                let live = if self.daemon_connected {
                    let ids: Vec<Uuid> = sessions.iter().map(|s| s.session_id).collect();
                    self.daemon_socket
                        .as_deref()
                        .map(|socket| agent_runner::session_live_status_blocking(socket, ids))
                        .unwrap_or_default()
                } else {
                    std::collections::HashMap::new()
                };
                let pairs: Vec<_> = sessions
                    .into_iter()
                    .map(|s| {
                        let l = live.get(&s.session_id).copied();
                        (s, l)
                    })
                    .collect();
                tier_sort(pairs)
            }
            Err(e) => {
                self.error = Some(e);
                Vec::new()
            }
        }
    }

    /// Daemonless list path: read the level straight from the read-only DB
    /// handle via the same `Db::list_session_summaries` the daemon uses, so
    /// ordering / scoping / fork-grouping match. `Err` only when the DB
    /// couldn't be opened (handle is `None`) or the query itself failed —
    /// both surface as the pane's inline error, never a crash.
    fn list_sessions_daemonless(
        &self,
        project_id: Option<&str>,
        parent: Option<Uuid>,
    ) -> Result<Vec<SessionSummary>, String> {
        let Some(db) = self.db.as_ref() else {
            return Err("could not open the session database".to_string());
        };
        let project_id = project_id.map(str::to_string);
        db.blocking_read_for_sync_ui(move |conn| {
            cockpit_db::Db::list_session_summaries_conn(
                conn,
                project_id.as_deref(),
                parent,
                DAEMONLESS_LIST_LIMIT,
            )
        })
        .map_err(|e| e.to_string())
    }

    /// Reload the current level in place, preserving scope/breadcrumb and
    /// clamping the cursor. Used after an archive/delete/unarchive.
    fn reload_current_level(&mut self) {
        if self.daemon_connected {
            self.mark_current_level_loading();
            return;
        }
        let (pid, parent) = {
            let depth = self.levels.len();
            let level = self.levels.last().expect("at least the root level");
            match (depth, &level.parent) {
                (_, Some(p)) => (None, Some(p.session_id)),
                _ => (
                    match self.scope {
                        Scope::Project => self.project_id.clone(),
                        Scope::All => None,
                    },
                    None,
                ),
            }
        };
        let cards = self.fetch_level(pid, parent);
        if let Some(level) = self.levels.last_mut() {
            level.cards = cards;
            level.list.clamp_cursor(level.cards.len());
            level.list.set_scroll(0);
        }
    }

    fn mark_current_level_loading(&mut self) {
        self.loading = Some("Loading sessions...");
        if let Some(level) = self.levels.last_mut() {
            level.cards.clear();
            level.list.reset();
        }
    }

    fn current(&self) -> &Level {
        self.levels.last().expect("at least the root level")
    }

    fn current_mut(&mut self) -> &mut Level {
        self.levels.last_mut().expect("at least the root level")
    }

    /// The highlighted card's summary, if any.
    fn selected(&self) -> Option<&SessionSummary> {
        let level = self.current();
        level.cards.get(level.list.cursor()).map(|(s, _)| s)
    }

    fn selected_id(&self) -> Option<Uuid> {
        self.selected().map(|summary| summary.session_id)
    }

    pub fn take_preview_load(&mut self) -> Option<(Uuid, Option<i64>)> {
        let preview = self.preview.as_ref()?;
        (self.daemon_connected && preview.loading)
            .then_some((preview.session_id, preview.oldest_seq()))
    }

    pub fn needs_preview_for_selection(&self) -> bool {
        self.daemon_connected
            && self.preview_enabled
            && self.preview.is_none()
            && self.selected_id().is_some()
    }

    #[cfg(test)]
    pub fn preview_error(&self) -> Option<&str> {
        self.preview.as_ref()?.error.as_deref()
    }

    pub fn ensure_preview_for_selection(&mut self) -> Option<SessionsOutcome> {
        let session_id = self.selected_id()?;
        let needs_reset = self
            .preview
            .as_ref()
            .map(|preview| preview.session_id != session_id)
            .unwrap_or(true);
        if needs_reset {
            self.preview = Some(PreviewState::new(session_id));
        }
        self.load_preview_page(session_id, None)
    }

    pub fn apply_preview_result(
        &mut self,
        session_id: Uuid,
        before_seq: Option<i64>,
        result: Result<(Vec<SessionMessage>, bool), String>,
    ) {
        if self.selected_id() != Some(session_id) {
            return;
        }
        if self
            .preview
            .as_ref()
            .map(|preview| preview.session_id != session_id)
            .unwrap_or(true)
        {
            self.preview = Some(PreviewState::new(session_id));
        }
        let Some(preview) = self.preview.as_mut() else {
            return;
        };
        preview.loading = false;
        match result {
            Ok((messages, has_more)) => {
                preview.error = None;
                preview.has_more = has_more;
                if before_seq.is_none() {
                    preview.messages = messages;
                    preview.scroll = 0;
                    preview.block_cache.clear();
                } else {
                    let existing: std::collections::HashSet<i64> =
                        preview.messages.iter().map(|message| message.seq).collect();
                    let mut older: Vec<_> = messages
                        .into_iter()
                        .filter(|message| !existing.contains(&message.seq))
                        .collect();
                    older.append(&mut preview.messages);
                    preview.messages = older;
                    // `scroll` is measured from the bottom. Prepending older
                    // messages does not move the existing rows relative to
                    // that bottom, so retaining it preserves the viewport
                    // anchor and lets the new page be laid out lazily.
                }
            }
            Err(error) => {
                preview.error = Some(error);
            }
        }
    }

    fn load_preview_page(
        &mut self,
        session_id: Uuid,
        before_seq: Option<i64>,
    ) -> Option<SessionsOutcome> {
        if self
            .preview
            .as_ref()
            .map(|preview| preview.session_id != session_id)
            .unwrap_or(true)
        {
            self.preview = Some(PreviewState::new(session_id));
        }
        if self.daemon_connected {
            if let Some(preview) = self.preview.as_mut() {
                preview.loading = true;
                preview.error = None;
            }
            return Some(SessionsOutcome::LoadPreview {
                session_id,
                before_seq,
            });
        }
        let result = self.read_preview_daemonless(session_id, before_seq);
        self.apply_preview_result(session_id, before_seq, result);
        None
    }

    fn read_preview_daemonless(
        &self,
        session_id: Uuid,
        before_seq: Option<i64>,
    ) -> Result<(Vec<SessionMessage>, bool), String> {
        let Some(db) = self.db.as_ref() else {
            return Err("could not open the session database".to_string());
        };
        db.blocking_read_for_sync_ui(move |conn| {
            cockpit_db::Db::read_session_messages_conn(
                conn,
                session_id,
                before_seq,
                PREVIEW_PAGE_LIMIT,
            )
        })
        .map_err(|error| error.to_string())
    }

    /// Handle a key. Returns `Some(outcome)` for close/resume; `None`
    /// otherwise (the pane stays open). Always consumed by `App` so
    /// nothing leaks to the composer (the modal rule).
    pub fn handle_key(&mut self, key: KeyEvent) -> Option<SessionsOutcome> {
        // The confirm sub-dialog owns input while open.
        if matches!(self.step, Step::Confirm { .. }) {
            return self.handle_confirm_key(key);
        }
        // Any keystroke clears the transient daemonless hint; gated actions
        // below re-set it, so it shows for exactly one action and then
        // dismisses on the next key.
        self.notice = None;
        match key.code {
            KeyCode::Char('q') => return Some(SessionsOutcome::Close),
            KeyCode::Esc => {
                if self.levels.len() > 1 {
                    self.drill_out();
                    self.preview = None;
                    if self.daemon_connected {
                        self.mark_current_level_loading();
                        return Some(SessionsOutcome::LoadList);
                    }
                } else {
                    return Some(SessionsOutcome::Close);
                }
            }
            KeyCode::Tab | KeyCode::BackTab if self.preview_enabled => {
                self.focus = match self.focus {
                    Focus::List => Focus::Preview,
                    Focus::Preview => Focus::List,
                };
            }
            KeyCode::Up | KeyCode::Char('k') if self.focus == Focus::Preview => {
                return self.scroll_preview_up();
            }
            KeyCode::Down | KeyCode::Char('j') if self.focus == Focus::Preview => {
                self.scroll_preview_down();
            }
            KeyCode::PageUp if self.focus == Focus::Preview => {
                return self.page_preview_up();
            }
            KeyCode::PageDown if self.focus == Focus::Preview => {
                self.page_preview_down();
            }
            KeyCode::Up | KeyCode::Char('k') => {
                if self.move_cursor(-1) && self.preview_enabled {
                    return self.ensure_preview_for_selection();
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if self.move_cursor(1) && self.preview_enabled {
                    return self.ensure_preview_for_selection();
                }
            }
            KeyCode::Enter => {
                // Resume needs the daemon (agent loop + locks + single
                // writer live there). Daemonless we must NOT auto-spawn one
                // — show a non-error hint and stay in the browser.
                if !self.daemon_connected {
                    self.notice = Some(DAEMONLESS_HINT.to_string());
                } else if let Some(s) = self.selected() {
                    return Some(SessionsOutcome::Resume(s.session_id));
                }
            }
            // Drill into the highlighted session's forks.
            KeyCode::Right | KeyCode::Char('l') => {
                let before_depth = self.levels.len();
                if self.drill_in() || self.levels.len() != before_depth {
                    self.preview = None;
                    if self.daemon_connected {
                        return Some(SessionsOutcome::LoadList);
                    }
                }
            }
            // Go back up one fork level (no-op at the root).
            KeyCode::Left | KeyCode::Char('h') => {
                if self.drill_out() {
                    self.preview = None;
                    if self.daemon_connected {
                        self.mark_current_level_loading();
                        return Some(SessionsOutcome::LoadList);
                    }
                }
            }
            // Scope toggle — only meaningful with a current project.
            KeyCode::Char('p') if self.project_id.is_some() => {
                self.scope = match self.scope {
                    Scope::Project => Scope::All,
                    Scope::All => Scope::Project,
                };
                self.preview = None;
                self.load_root();
                if self.daemon_connected {
                    return Some(SessionsOutcome::LoadList);
                }
            }
            // Reveal / hide archived sessions.
            KeyCode::Char('a') => {
                self.show_archived = !self.show_archived;
                self.preview = None;
                if self.daemon_connected {
                    self.mark_current_level_loading();
                    return Some(SessionsOutcome::LoadList);
                } else {
                    self.reload_current_level();
                }
            }
            // Unarchive the highlighted session (only from the archived
            // view, where archived rows are visible).
            KeyCode::Char('u') => return self.unarchive_selected(),
            // Open the archive/delete confirm for the highlighted session.
            KeyCode::Char('d') => self.open_confirm(),
            _ => {}
        }
        None
    }

    fn move_cursor(&mut self, delta: isize) -> bool {
        let len = self.current().cards.len();
        if len == 0 {
            return false;
        }
        let level = self.current_mut();
        let prev = level.list.cursor();
        // Wrap at both ends, consistent with every other selectable list.
        level.list.move_by(delta, len);
        // Keep the cursor inside the visible window (rough: each card is
        // ~4 rows). The render pass does the precise clamp.
        if delta < 0 {
            if level.list.cursor() > prev {
                // Wrapped first → last: scroll toward the bottom; render
                // clamps to the precise floor.
                level
                    .list
                    .set_scroll(level.list.scroll().saturating_add(len));
            } else {
                level.list.set_scroll(level.list.scroll().saturating_sub(1));
            }
        } else if level.list.cursor() < prev {
            // Wrapped last → first: jump back to the top.
            level.list.set_scroll(0);
        } else {
            level.list.set_scroll(level.list.scroll() + 1);
        }
        level.list.cursor() != prev
    }

    /// Drill into the highlighted session's direct forks (unbounded
    /// depth). No-op when the session has no forks.
    fn drill_in(&mut self) -> bool {
        let Some(parent) = self.selected().cloned() else {
            return false;
        };
        if parent.fork_count == 0 {
            return false;
        }
        if self.daemon_connected {
            self.loading = Some("Loading sessions...");
            self.levels.push(Level {
                parent: Some(parent),
                cards: Vec::new(),
                list: ScrollList::new(),
            });
            return true;
        }
        let cards = self.fetch_level(None, Some(parent.session_id));
        self.levels.push(Level {
            parent: Some(parent),
            cards,
            list: ScrollList::new(),
        });
        false
    }

    /// Pop one fork level. No-op at the root.
    fn drill_out(&mut self) -> bool {
        if self.levels.len() > 1 {
            self.levels.pop();
            return true;
        }
        false
    }

    /// Open the Archive/Delete/Cancel confirm for the highlighted session,
    /// stating the cascade count and whether the target is live.
    fn open_confirm(&mut self) {
        // Archive/delete are daemon-only (no direct-DB write path).
        // Daemonless, surface the non-error hint instead of opening the
        // confirm dialog.
        if !self.daemon_connected {
            self.notice = Some(DAEMONLESS_HINT.to_string());
            return;
        }
        let Some(s) = self.selected().cloned() else {
            return;
        };
        // Cascade count: the full descendant subtree the daemon walks on
        // archive/delete (GOALS §17h) — carried on the summary, accurate
        // without an extra round-trip.
        let descendants = s.descendant_count;
        // Live status drives the interrupt-first warning.
        let live_map = self
            .daemon_socket
            .as_deref()
            .map(|socket| agent_runner::session_live_status_blocking(socket, vec![s.session_id]))
            .unwrap_or_default();
        let live = live_map
            .get(&s.session_id)
            .map(|(j, p)| *j || *p)
            .unwrap_or(false);
        let label = card_description(&s);
        self.step = Step::Confirm {
            session_id: s.session_id,
            label,
            descendants,
            live,
            choice: ConfirmChoice::Cancel,
        };
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) -> Option<SessionsOutcome> {
        let Step::Confirm {
            session_id, choice, ..
        } = &mut self.step
        else {
            return None;
        };
        let session_id = *session_id;
        match key.code {
            KeyCode::Char('q') => return Some(SessionsOutcome::Close),
            KeyCode::Esc => {
                self.step = Step::Browse;
            }
            KeyCode::Left | KeyCode::Char('h') => {
                *choice = match choice {
                    ConfirmChoice::Archive => ConfirmChoice::Cancel,
                    ConfirmChoice::Delete => ConfirmChoice::Archive,
                    ConfirmChoice::Cancel => ConfirmChoice::Delete,
                };
            }
            KeyCode::Right | KeyCode::Char('l') => {
                *choice = match choice {
                    ConfirmChoice::Archive => ConfirmChoice::Delete,
                    ConfirmChoice::Delete => ConfirmChoice::Cancel,
                    ConfirmChoice::Cancel => ConfirmChoice::Archive,
                };
            }
            KeyCode::Enter => {
                let decided = *choice;
                return self.apply_confirm(session_id, decided);
            }
            _ => {}
        }
        None
    }

    /// Apply the confirm choice. Both Archive and Delete cascade the whole
    /// fork subtree; the daemon interrupts any live worker in the subtree
    /// first (GOALS §17h). On success we reload the current level.
    fn apply_confirm(
        &mut self,
        session_id: Uuid,
        choice: ConfirmChoice,
    ) -> Option<SessionsOutcome> {
        use cockpit_core::daemon::proto::Request;
        let req = match choice {
            ConfirmChoice::Cancel => {
                self.step = Step::Browse;
                return None;
            }
            ConfirmChoice::Archive => Request::ArchiveSession {
                session_id,
                cascade: true,
            },
            ConfirmChoice::Delete => Request::DeleteSession {
                session_id,
                cascade: true,
            },
        };
        match agent_runner::daemon_request_blocking(req) {
            Ok(_) => {
                self.error = None;
            }
            Err(e) => {
                self.error = Some(e);
            }
        }
        self.step = Step::Browse;
        self.reload_current_level();
        if self.daemon_connected {
            Some(SessionsOutcome::LoadList)
        } else {
            None
        }
    }

    fn unarchive_selected(&mut self) -> Option<SessionsOutcome> {
        // Unarchive is a DB write — daemon-only, same as archive/delete.
        if !self.daemon_connected {
            self.notice = Some(DAEMONLESS_HINT.to_string());
            return None;
        }
        let s = self.selected().cloned()?;
        s.archived_at?;
        match agent_runner::daemon_request_blocking(
            cockpit_core::daemon::proto::Request::UnarchiveSession {
                session_id: s.session_id,
            },
        ) {
            Ok(_) => self.error = None,
            Err(e) => self.error = Some(e),
        }
        self.reload_current_level();
        Some(SessionsOutcome::LoadList)
    }

    /// Mouse-wheel scroll (one row).
    pub fn scroll_up(&mut self) {
        let level = self.current_mut();
        level.list.set_scroll(level.list.scroll().saturating_sub(1));
    }

    pub fn scroll_down(&mut self) {
        let max = self.last_content_rows.saturating_sub(self.last_body_height);
        let level = self.current_mut();
        level.list.set_scroll((level.list.scroll() + 1).min(max));
    }

    fn scroll_preview_up(&mut self) -> Option<SessionsOutcome> {
        let preview = self.preview.as_mut()?;
        let max = self
            .last_preview_rows
            .saturating_sub(self.last_preview_height);
        if preview.scroll >= max && self.last_preview_reached_top {
            let request = (preview.has_more && !preview.loading)
                .then(|| {
                    preview
                        .oldest_seq()
                        .map(|before_seq| (preview.session_id, before_seq))
                })
                .flatten();
            if let Some((session_id, before_seq)) = request {
                return self.load_preview_page(session_id, Some(before_seq));
            }
            return None;
        }
        preview.scroll = (preview.scroll + 1).min(max);
        None
    }

    fn scroll_preview_down(&mut self) {
        if let Some(preview) = self.preview.as_mut() {
            preview.scroll = preview.scroll.saturating_sub(1);
        }
    }

    fn page_preview_up(&mut self) -> Option<SessionsOutcome> {
        let amount = self.last_preview_height.max(1);
        for _ in 0..amount {
            if let Some(outcome) = self.scroll_preview_up() {
                return Some(outcome);
            }
        }
        None
    }

    fn page_preview_down(&mut self) {
        let amount = self.last_preview_height.max(1);
        for _ in 0..amount {
            self.scroll_preview_down();
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<SessionsOutcome> {
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if self
                    .preview_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus = Focus::Preview;
                    self.scroll_preview_up()
                } else {
                    self.focus = Focus::List;
                    self.scroll_up();
                    None
                }
            }
            MouseEventKind::ScrollDown => {
                if self
                    .preview_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus = Focus::Preview;
                    self.scroll_preview_down();
                } else {
                    self.focus = Focus::List;
                    self.scroll_down();
                }
                None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self
                    .preview_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus = Focus::Preview;
                    return None;
                }
                let index = hit_card(&self.card_hits, mouse.column, mouse.row)?;
                self.focus = Focus::List;
                let now = std::time::Instant::now();
                let double_click = is_double_click(self.last_card_click, index, now);
                self.last_card_click = Some((index, now));
                let selected = self.current().list.cursor();
                if click_resumes(selected, index, double_click) {
                    if !self.daemon_connected {
                        self.notice = Some(DAEMONLESS_HINT.to_string());
                        return None;
                    }
                    if let Some((summary, _)) = self.current().cards.get(index) {
                        return Some(SessionsOutcome::Resume(summary.session_id));
                    }
                    return None;
                }
                if let Some(level) = self.levels.last_mut() {
                    level.list.set_cursor(index);
                }
                self.ensure_preview_for_selection()
            }
            _ => None,
        }
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
        self.card_hits.clear();
        self.list_area = None;
        self.preview_area = None;
        let title = self.title();
        let block = Block::default().borders(Borders::ALL).title(title);
        let inner = block.inner(area);
        frame.render_widget(block, area);

        let layout = Layout::vertical([
            Constraint::Length(1), // breadcrumb
            Constraint::Min(0),    // cards
            Constraint::Length(1), // help
        ])
        .split(inner);
        let crumb_area = layout[0];
        let body = layout[1];
        let help_area = layout[2];

        frame.render_widget(Paragraph::new(self.breadcrumb_line()), crumb_area);

        match sessions_layout_for_inner(body) {
            SessionsLayout::Single { body } => {
                self.preview_enabled = false;
                self.focus = Focus::List;
                self.render_list_body(frame, body, body.width as usize, false);
            }
            SessionsLayout::Split { list, preview, .. } => {
                self.preview_enabled = true;
                self.list_area = Some(list);
                self.preview_area = Some(preview);
                if self.preview.is_none() && !self.daemon_connected {
                    let _ = self.ensure_preview_for_selection();
                }

                let list_block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(column_border_style(self.focus, Focus::List))
                    .title(" sessions ");
                let list_inner = list_block.inner(list);
                frame.render_widget(list_block, list);
                self.render_list_body(frame, list_inner, list_inner.width as usize, true);

                let preview_block = Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Rounded)
                    .border_style(column_border_style(self.focus, Focus::Preview))
                    .title(" preview ");
                let preview_inner = preview_block.inner(preview);
                frame.render_widget(preview_block, preview);
                self.render_preview_body(frame, preview_inner);
            }
        }

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(Paragraph::new(self.help_line()).style(muted), help_area);

        // The confirm sub-dialog draws over the bottom of the body.
        if let Step::Confirm { .. } = &self.step {
            self.render_confirm(frame, body);
        }
    }

    fn render_list_body(&mut self, frame: &mut Frame, body: Rect, width: usize, record_hits: bool) {
        let (lines, selected_span) = self.body_lines_with_selected_span(width);
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        let mut scroll = self
            .current()
            .list
            .scroll()
            .min(self.last_content_rows.saturating_sub(self.last_body_height));
        if let Some((start, end)) = selected_span {
            scroll = crate::tui::pane_shared::clamp_scroll_to_visible_span(
                scroll,
                self.last_body_height,
                self.last_content_rows,
                start,
                end,
            );
        }
        if let Some(level) = self.levels.last_mut() {
            level.list.set_scroll(scroll);
        }
        if record_hits {
            self.record_card_hits(body, scroll);
        }
        frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), body);
    }

    fn render_preview_body(&mut self, frame: &mut Frame, area: Rect) {
        self.last_preview_height = area.height as usize;
        let lines = self.preview_window_lines(
            area.width as usize,
            area.height as usize,
            (self.preview_clock_ms)(),
        );
        frame.render_widget(Paragraph::new(lines), area);
    }

    fn title(&self) -> Line<'static> {
        let scope_label = match self.scope {
            Scope::Project => match &self.project_id {
                Some(id) => format!("project {}", short_id(id)),
                None => "project".to_string(),
            },
            Scope::All => "all projects".to_string(),
        };
        let mut spans = vec![
            Span::raw(" /sessions "),
            Span::styled(
                format!("scope: {scope_label} "),
                Style::default().fg(Color::Yellow),
            ),
        ];
        if self.show_archived {
            spans.push(Span::styled(
                "[archived shown] ",
                Style::default().fg(Color::Magenta),
            ));
        }
        Line::from(spans)
    }

    /// Breadcrumb / depth header for fork drill-in (GOALS §17f).
    fn breadcrumb_line(&self) -> Line<'static> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        if self.levels.len() == 1 {
            return Line::from(Span::styled("sessions", muted));
        }
        let mut parts = vec!["sessions".to_string()];
        for level in self.levels.iter().skip(1) {
            if let Some(p) = &level.parent {
                parts.push(format!("forks of {}", card_description(p)));
            }
        }
        Line::from(Span::styled(parts.join("  ›  "), muted))
    }

    fn help_line(&self) -> Line<'static> {
        let scope_hint = if self.project_id.is_some() {
            "p scope  "
        } else {
            ""
        };
        // Daemonless the mutating actions (resume / archive / delete /
        // unarchive) are disabled, so the help line drops them and states
        // browse-only rather than advertising keys that only show a hint.
        if self.daemon_connected {
            Line::from(format!(
                "q quit  ↑/↓ move  enter resume  →/l forks  ←/h back  {scope_hint}a archived  u unarchive  d archive/delete"
            ))
        } else {
            Line::from(format!(
                "q quit  ↑/↓ move  →/l forks  ←/h back  {scope_hint}a archived  (browse only — no daemon)"
            ))
        }
    }

    /// Assemble every body row as owned [`Line`]s and report the selected
    /// rendered card span. Pure aside from reading `self`; the per-card
    /// assembly lives in [`card_lines`] so it's unit-testable without a
    /// terminal.
    fn body_lines_with_selected_span(
        &self,
        width: usize,
    ) -> (Vec<Line<'static>>, Option<(usize, usize)>) {
        let mut lines: Vec<Line<'static>> = Vec::new();
        let mut selected_span = None;
        if let Some(e) = &self.error {
            // Daemon-connected, a list error means the daemon went away
            // ("daemon unavailable"). Daemonless, the only error is a
            // DB-open/query failure — phrase it plainly, never as "daemon
            // unavailable" (the absent daemon is the expected case).
            let prefix = if self.daemon_connected {
                "daemon unavailable: "
            } else {
                ""
            };
            lines.push(Line::from(Span::styled(
                format!("{prefix}{e}"),
                Style::default().fg(Color::Red),
            )));
            lines.push(Line::default());
        }
        if let Some(n) = &self.notice {
            lines.push(Line::from(Span::styled(
                n.clone(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            )));
            lines.push(Line::default());
        }
        if let Some(text) = self.loading {
            lines.push(Line::from(Span::styled(
                text,
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            )));
            return (lines, selected_span);
        }
        let level = self.current();
        if level.cards.is_empty() {
            lines.push(Line::from(Span::styled(
                "  (no sessions)".to_string(),
                Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX)),
            )));
            return (lines, selected_span);
        }
        let show_project = matches!(self.scope, Scope::All) || self.levels.len() > 1;
        for (i, (summary, tier)) in level.cards.iter().enumerate() {
            let start = lines.len();
            let card = card_lines(
                summary,
                *tier,
                i == level.list.cursor(),
                show_project,
                width,
                self.use_emojis,
            );
            let end = start + card.len();
            if i == level.list.cursor() {
                selected_span = Some((start, end));
            }
            lines.extend(card);
        }
        (lines, selected_span)
    }

    fn record_card_hits(&mut self, body: Rect, scroll: usize) {
        let mut hits = Vec::new();
        let show_project = matches!(self.scope, Scope::All) || self.levels.len() > 1;
        let mut row = 0usize;
        for (index, (summary, tier)) in self.current().cards.iter().enumerate() {
            let height = card_lines(
                summary,
                *tier,
                index == self.current().list.cursor(),
                show_project,
                body.width as usize,
                self.use_emojis,
            )
            .len();
            let start = row;
            let end = row + height;
            row = end;
            let visible_start = start.max(scroll);
            let visible_end = end.min(scroll + body.height as usize);
            if visible_start < visible_end {
                hits.push(CardHit {
                    index,
                    rect: Rect {
                        x: body.x,
                        y: body.y + (visible_start - scroll) as u16,
                        width: body.width,
                        height: (visible_end - visible_start) as u16,
                    },
                });
            }
        }
        self.card_hits = hits;
    }

    fn preview_lines(&mut self, width: usize, now_ms: i64) -> Vec<Line<'static>> {
        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let agent_name = self
            .selected()
            .map(|summary| summary.active_agent.clone())
            .unwrap_or_else(|| "Agent".to_string());
        let Some(preview) = self.preview.as_mut() else {
            return vec![Line::from(Span::styled("  (no session selected)", muted))];
        };
        if let Some(error) = &preview.error {
            return vec![Line::from(Span::styled(
                format!("preview unavailable: {error}"),
                Style::default().fg(Color::Red),
            ))];
        }
        if preview.messages.is_empty() {
            if preview.loading {
                return vec![Line::from(Span::styled("  Loading messages...", muted))];
            }
            return vec![Line::from(Span::styled(
                "  no text messages in this session",
                muted,
            ))];
        }
        let mut lines = Vec::new();
        if preview.has_more {
            lines.push(Line::from(Span::styled("  ↑ more messages", muted)));
        }
        if preview.loading {
            lines.push(Line::from(Span::styled(
                "  Loading older messages...",
                muted,
            )));
        }
        for index in 0..preview.messages.len() {
            lines.extend(preview_message_lines(
                preview,
                index,
                width,
                now_ms,
                &agent_name,
            ));
            lines.push(Line::default());
        }
        if lines.last().is_some_and(|line| line.spans.is_empty()) {
            lines.pop();
        }
        lines
    }

    /// Materialize only the suffix needed for the visible viewport plus one
    /// viewport of look-ahead. The preview scroll is measured from the bottom,
    /// so the common initial/newest-message view does not parse all 50 loaded
    /// Markdown messages. Moving upward extends the cached suffix lazily.
    fn preview_window_lines(
        &mut self,
        width: usize,
        height: usize,
        now_ms: i64,
    ) -> Vec<Line<'static>> {
        let special_state = self
            .preview
            .as_ref()
            .is_none_or(|preview| preview.error.is_some() || preview.messages.is_empty());
        if special_state {
            let lines = self.preview_lines(width, now_ms);
            self.last_preview_rows = lines.len();
            self.last_preview_reached_top = true;
            return lines.into_iter().take(height).collect();
        }

        let agent_name = self
            .selected()
            .map(|summary| summary.active_agent.clone())
            .unwrap_or_else(|| "Agent".to_string());
        let preview = self.preview.as_mut().expect("special state handled");
        let requested_from_bottom = preview.scroll;
        let target_rows = if requested_from_bottom == usize::MAX {
            usize::MAX
        } else {
            requested_from_bottom
                .saturating_add(height)
                .saturating_add(height.max(4))
        };

        let mut blocks_reversed: Vec<Vec<Line<'static>>> = Vec::new();
        let mut materialized_rows = 0usize;
        let mut reached_top = true;
        for index in (0..preview.messages.len()).rev() {
            let mut block = preview_message_lines(preview, index, width, now_ms, &agent_name);
            if !blocks_reversed.is_empty() {
                block.push(Line::default());
            }
            materialized_rows = materialized_rows.saturating_add(block.len());
            blocks_reversed.push(block);
            if materialized_rows >= target_rows {
                reached_top = index == 0;
                break;
            }
        }

        let mut lines = Vec::with_capacity(materialized_rows + 2);
        if reached_top {
            let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
            if preview.has_more {
                lines.push(Line::from(Span::styled("  ↑ more messages", muted)));
            }
            if preview.loading {
                lines.push(Line::from(Span::styled(
                    "  Loading older messages...",
                    muted,
                )));
            }
        }
        for block in blocks_reversed.into_iter().rev() {
            lines.extend(block);
        }

        self.last_preview_rows = lines.len();
        self.last_preview_reached_top = reached_top;
        let max = lines.len().saturating_sub(height);
        preview.scroll = requested_from_bottom.min(max);
        let from_top = max.saturating_sub(preview.scroll);
        lines.into_iter().skip(from_top).take(height).collect()
    }

    fn render_confirm(&self, frame: &mut Frame, body: Rect) {
        let Step::Confirm {
            label,
            descendants,
            live,
            choice,
            ..
        } = &self.step
        else {
            return;
        };
        // A 6-row modal pinned to the bottom of the body.
        let h = 7u16.min(body.height);
        let rect = Rect {
            x: body.x,
            y: body.y + body.height.saturating_sub(h),
            width: body.width,
            height: h,
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX)))
            .title(" archive / delete ");
        let inner = block.inner(rect);
        frame.render_widget(ratatui::widgets::Clear, rect);
        frame.render_widget(block, rect);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        let mut lines: Vec<Line<'static>> = Vec::new();
        lines.push(Line::from(label.clone()));
        let cascade = if *descendants > 0 {
            format!("Cascades to {descendants} fork(s) and their descendants.")
        } else {
            "No forks affected.".to_string()
        };
        lines.push(Line::from(Span::styled(cascade, muted)));
        if *live {
            lines.push(Line::from(Span::styled(
                "Session is live — it will be interrupted first.".to_string(),
                Style::default().fg(Color::Yellow),
            )));
        }
        lines.push(button_row(*choice));
        frame.render_widget(Paragraph::new(lines), inner);
    }
}

// ---- pure helpers ----------------------------------------------------------

/// Card description: the title when set, else the short id, else a short
/// prefix of the full session id (defensive — short_id is always set on
/// modern rows).
pub fn card_description(s: &SessionSummary) -> String {
    if let Some(t) = &s.title
        && !t.trim().is_empty()
    {
        return t.clone();
    }
    if let Some(sid) = &s.short_id
        && !sid.is_empty()
    {
        return sid.clone();
    }
    short_id(&s.session_id.to_string())
}

/// Assemble one card's rendered rows (pure, terminal-free). A rounded
/// border isn't drawn glyph-by-glyph here — `Paragraph` can't host nested
/// borders cheaply per card in a scroll region, so each card is a framed
/// text block: a top rule, content rows, a bottom rule, using rounded
/// corner glyphs to match `BorderType::Rounded`.
pub fn card_lines(
    s: &SessionSummary,
    tier: Tier,
    selected: bool,
    show_project: bool,
    width: usize,
    use_emojis: bool,
) -> Vec<Line<'static>> {
    let inner_w = width.saturating_sub(2).max(8);
    let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
    let border_style = if selected {
        Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX))
    } else {
        muted
    };

    let mut out: Vec<Line<'static>> = Vec::new();
    // Top rule with rounded corners.
    out.push(Line::from(Span::styled(
        format!("╭{}╮", "─".repeat(inner_w)),
        border_style,
    )));

    // Row 1: description + tier status.
    let desc = card_description(s);
    let status = Span::styled(tier.label_for(s), Style::default().fg(tier.color()));
    out.push(boxed_row(
        vec![
            Span::styled(
                desc,
                if selected {
                    Style::default()
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                },
            ),
            Span::raw("  "),
            status,
        ],
        inner_w,
        border_style,
    ));

    // Row 2: relative + absolute most-recent-event time + (optional) project
    // label.
    let mut meta: Vec<Span<'static>> = vec![Span::styled(
        fmt_time_with_relative(s.last_active_at),
        muted,
    )];
    if show_project {
        meta.push(Span::raw("  "));
        meta.push(Span::styled(
            format!("[{}]", project_label(&s.project_root)),
            muted,
        ));
    }
    if s.archived_at.is_some() {
        meta.push(Span::raw("  "));
        meta.push(Span::styled(
            "archived".to_string(),
            Style::default().fg(Color::Magenta),
        ));
    }
    // Pinned-message count (`pinned-messages`). Shown only when non-zero —
    // a zero-pin session shows no pin chrome (matches the fork-hint /
    // archived conventions, which only render when relevant).
    if s.pin_count > 0 {
        meta.push(Span::raw("  "));
        let pin = if use_emojis {
            format!("📌 {}", s.pin_count)
        } else {
            format!("pin {}", s.pin_count)
        };
        meta.push(Span::styled(pin, Style::default().fg(Color::Yellow)));
    }
    out.push(boxed_row(meta, inner_w, border_style));

    // Row 3 (only when forks exist): fork hint.
    if s.fork_count > 0 {
        out.push(boxed_row(
            vec![Span::styled(
                format!("press →/l to view {} fork(s)", s.fork_count),
                Style::default().fg(Color::Cyan),
            )],
            inner_w,
            border_style,
        ));
    }

    // Bottom rule.
    out.push(Line::from(Span::styled(
        format!("╰{}╯", "─".repeat(inner_w)),
        border_style,
    )));
    out
}

impl Pane for SessionsPane {
    type Outcome = Option<SessionsOutcome>;

    fn handle_key(&mut self, key: KeyEvent) -> Self::Outcome {
        SessionsPane::handle_key(self, key)
    }

    fn render(&mut self, frame: &mut Frame, area: Rect) {
        SessionsPane::render(self, frame, area);
    }
}

/// The Archive / Delete / Cancel button row, highlighting the selection.
fn button_row(choice: ConfirmChoice) -> Line<'static> {
    let mk = |label: &str, this: ConfirmChoice| {
        if this == choice {
            Span::styled(
                format!("[ {label} ]"),
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
        } else {
            Span::styled(format!("  {label}  "), Style::default().fg(Color::White))
        }
    };
    Line::from(vec![
        mk("Archive", ConfirmChoice::Archive),
        Span::raw(" "),
        mk("Delete", ConfirmChoice::Delete),
        Span::raw(" "),
        mk("Cancel", ConfirmChoice::Cancel),
    ])
}

/// Absolute, human-readable local timestamp for `last_active_at`.
fn fmt_time(epoch: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(epoch, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => "—".to_string(),
    }
}

/// `<relative> · <absolute>` for `last_active_at`, computed against the
/// current wall clock.
fn fmt_time_with_relative(epoch: i64) -> String {
    let elapsed = chrono::Utc::now().timestamp() - epoch;
    format!("{} · {}", relative_time(elapsed), fmt_time(epoch))
}

/// Hand-rolled coarse "time ago" string from an elapsed duration in seconds
/// (`now - last_active_at`). Buckets per spec; future timestamps (negative
/// elapsed) clamp to `just now`. 30-day months, 365-day years.
fn relative_time(elapsed_secs: i64) -> String {
    fn unit(n: i64, singular: &str) -> String {
        if n == 1 {
            format!("1 {singular} ago")
        } else {
            format!("{n} {singular}s ago")
        }
    }

    if elapsed_secs < 60 {
        // Includes the future-timestamp (negative) clamp.
        return "just now".to_string();
    }
    let minutes = elapsed_secs / 60;
    if minutes < 60 {
        return unit(minutes, "minute");
    }
    let hours = elapsed_secs / 3_600;
    if hours < 48 {
        return unit(hours, "hour");
    }
    let days = elapsed_secs / 86_400;
    if days < 30 {
        return unit(days, "day");
    }
    if days < 365 {
        return unit(days / 30, "month");
    }
    unit(days / 365, "year")
}

/// Last path component of a project root, for the all-projects card label.
fn project_label(root: &str) -> String {
    std::path::Path::new(root)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| root.to_string())
}

pub fn sessions_layout_for_inner(inner: Rect) -> SessionsLayout {
    if inner.width < 100 {
        return SessionsLayout::Single { body: inner };
    }
    let left_width = (inner.width / 5).max(64).min(inner.width.saturating_sub(2));
    let preview_x = inner.x + left_width + 1;
    let right_width = inner.width.saturating_sub(left_width).saturating_sub(1);
    SessionsLayout::Split {
        list: Rect {
            x: inner.x,
            y: inner.y,
            width: left_width,
            height: inner.height,
        },
        preview: Rect {
            x: preview_x,
            y: inner.y,
            width: right_width,
            height: inner.height,
        },
        left_width,
        right_width,
    }
}

pub fn column_border_style(focus: Focus, column: Focus) -> Style {
    if focus == column {
        Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX))
    } else {
        Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))
    }
}

fn point_in_rect(rect: Rect, col: u16, row: u16) -> bool {
    col >= rect.x && col < rect.x + rect.width && row >= rect.y && row < rect.y + rect.height
}

fn hit_card(hits: &[CardHit], col: u16, row: u16) -> Option<usize> {
    hits.iter()
        .find(|hit| point_in_rect(hit.rect, col, row))
        .map(|hit| hit.index)
}

fn click_resumes(selected: usize, clicked: usize, double_click: bool) -> bool {
    selected == clicked || double_click
}

fn is_double_click(
    previous: Option<(usize, std::time::Instant)>,
    clicked: usize,
    now: std::time::Instant,
) -> bool {
    previous
        .map(|(index, at)| index == clicked && now.duration_since(at) <= DOUBLE_CLICK_WINDOW)
        .unwrap_or(false)
}

fn preview_message_role(role: MessageRole, agent_name: &str) -> MessageBlockRole {
    match role {
        MessageRole::User => MessageBlockRole {
            label: crate::tui::history::user_display_label().to_string(),
            style: Style::default().fg(crate::tui::history::user_message_color()),
        },
        MessageRole::Agent => MessageBlockRole {
            label: crate::tui::history::agent_display_label(agent_name).to_string(),
            style: Style::default().fg(crate::tui::history::agent_color_rendered(agent_name)),
        },
    }
}

fn preview_message_lines(
    preview: &mut PreviewState,
    index: usize,
    width: usize,
    now_ms: i64,
    agent_name: &str,
) -> Vec<Line<'static>> {
    let role = preview_message_role(preview.messages[index].role, agent_name);
    let timestamp = preview_timestamp(preview.messages[index].ts_ms, now_ms);
    let block = preview.message_block(index, width);
    block.with_header(role, timestamp)
}

fn preview_timestamp(ts_ms: i64, now_ms: i64) -> String {
    use chrono::{Local, TimeZone};

    let Some(timestamp) = Local.timestamp_millis_opt(ts_ms).single() else {
        return "—".to_string();
    };
    let elapsed_ms = now_ms.saturating_sub(ts_ms);
    if elapsed_ms < 0 {
        return "just now".to_string();
    }
    const SEVEN_DAYS_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
    if elapsed_ms <= SEVEN_DAYS_MS {
        return relative_time(elapsed_ms / 1_000);
    }
    timestamp.format("%Y-%m-%d %H:%M").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};

    fn press(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        }
    }

    fn summary(id: Uuid, last_active: i64) -> SessionSummary {
        SessionSummary {
            session_id: id,
            short_id: Some("abc123".into()),
            project_root: "/proj/alpha".into(),
            project_id: "pid".into(),
            started_at: 0,
            last_active_at: last_active,
            turns: 0,
            active_agent: "builder".into(),
            title: None,
            parent_session_id: None,
            fork_count: 0,
            descendant_count: 0,
            last_viewed_at: None,
            latest_activity_at: None,
            open_interrupts: 0,
            activity_state: None,
            archived_at: None,
            created_by_principal: None,
            shared_with_collaborators: false,
            pin_count: 0,
        }
    }

    #[test]
    fn classify_respects_tier_precedence() {
        let mut s = summary(Uuid::new_v4(), 100);
        // Live jobs win over everything.
        s.latest_activity_at = Some(200);
        s.open_interrupts = 3;
        assert_eq!(classify(&s, Some((true, true))), Tier::ActiveSchedules);
        // Processing (no jobs) is tier 2.
        assert_eq!(classify(&s, Some((false, true))), Tier::Processing);
        // No live status → unread because activity is newer than the
        // (never-set) viewed marker.
        assert_eq!(classify(&s, None), Tier::Unread);
    }

    #[test]
    fn unread_computation() {
        let mut s = summary(Uuid::new_v4(), 100);
        // No agent activity → never unread.
        assert!(!is_unread(&s));
        // Activity but never viewed → unread.
        s.latest_activity_at = Some(50);
        assert!(is_unread(&s));
        // Viewed after the activity → read.
        s.last_viewed_at = Some(60);
        assert!(!is_unread(&s));
        // New activity after the view → unread again.
        s.latest_activity_at = Some(70);
        assert!(is_unread(&s));
    }

    #[test]
    fn read_with_pending_question_is_tier_4() {
        let mut s = summary(Uuid::new_v4(), 100);
        // Read (activity <= viewed), but an open interrupt.
        s.latest_activity_at = Some(50);
        s.last_viewed_at = Some(60);
        s.open_interrupts = 1;
        assert_eq!(classify(&s, None), Tier::PendingQuestion);
        // Read, no question → idle.
        s.open_interrupts = 0;
        assert_eq!(classify(&s, None), Tier::Idle);
    }

    #[test]
    fn daemon_down_degrades_to_db_tiers() {
        // `None` live status (daemon unreachable) → the session still
        // classifies into a DB tier, never panics.
        let mut s = summary(Uuid::new_v4(), 100);
        s.latest_activity_at = Some(10);
        s.last_viewed_at = Some(20);
        assert_eq!(classify(&s, None), Tier::Idle);
    }

    #[test]
    fn tier_sort_orders_by_tier_then_recency() {
        let idle_old = summary(Uuid::new_v4(), 10);
        let idle_new = summary(Uuid::new_v4(), 90);
        let mut unread = summary(Uuid::new_v4(), 50);
        unread.latest_activity_at = Some(55); // never viewed → unread

        let sorted = tier_sort(vec![
            (idle_old.clone(), None),
            (idle_new.clone(), None),
            (unread.clone(), None),
        ]);
        // Unread (tier 3) sorts above the two idle (tier 5) regardless of
        // recency; within idle, the newer one is first.
        assert_eq!(sorted[0].1, Tier::Unread);
        assert_eq!(sorted[0].0.session_id, unread.session_id);
        assert_eq!(sorted[1].0.session_id, idle_new.session_id);
        assert_eq!(sorted[2].0.session_id, idle_old.session_id);
    }

    #[test]
    fn split_layout_breakpoint_and_widths_are_stable() {
        let layout = |width| sessions_layout_for_inner(Rect::new(0, 0, width, 20));
        assert!(matches!(
            layout(300),
            SessionsLayout::Split {
                left_width: 64,
                right_width: 235,
                ..
            }
        ));
        assert!(matches!(
            layout(120),
            SessionsLayout::Split {
                left_width: 64,
                right_width: 55,
                ..
            }
        ));
        assert!(matches!(layout(100), SessionsLayout::Split { .. }));
        assert!(matches!(
            layout(400),
            SessionsLayout::Split { left_width: 80, .. }
        ));
        assert!(matches!(layout(99), SessionsLayout::Single { .. }));
        assert!(matches!(layout(80), SessionsLayout::Single { .. }));
    }

    #[test]
    fn classify_distinguishes_activity_states() {
        let mut s = summary(Uuid::new_v4(), 100);
        s.activity_state = Some(cockpit_core::daemon::proto::SessionActivityState::ToolRunning);
        assert_eq!(classify(&s, Some((false, true))), Tier::ToolRunning);
        s.activity_state =
            Some(cockpit_core::daemon::proto::SessionActivityState::InferenceInProgress);
        assert_eq!(classify(&s, None), Tier::InferenceInProgress);
        s.activity_state = Some(cockpit_core::daemon::proto::SessionActivityState::Interrupted);
        assert_eq!(classify(&s, None), Tier::Interrupted);
        s.activity_state = Some(cockpit_core::daemon::proto::SessionActivityState::PendingQuestion);
        s.open_interrupts = 2;
        assert_eq!(classify(&s, None), Tier::PendingQuestion);
        assert_eq!(classify(&s, Some((true, true))), Tier::ActiveSchedules);
    }

    #[test]
    fn preview_pages_prepend_without_duplicates_and_discard_stale() {
        let session_id = Uuid::new_v4();
        let other_id = Uuid::new_v4();
        let mut pane = test_pane(vec![
            (summary(session_id, 100), Tier::Idle),
            (summary(other_id, 90), Tier::Idle),
        ]);
        pane.preview = Some(PreviewState::new(session_id));
        pane.apply_preview_result(
            session_id,
            None,
            Ok((
                vec![
                    message(3, MessageRole::User, "three"),
                    message(4, MessageRole::Agent, "four"),
                ],
                true,
            )),
        );
        pane.apply_preview_result(
            other_id,
            None,
            Ok((vec![message(9, MessageRole::User, "stale")], false)),
        );
        pane.preview.as_mut().unwrap().scroll = 7;
        pane.apply_preview_result(
            session_id,
            Some(3),
            Ok((
                vec![
                    message(1, MessageRole::User, "one"),
                    message(2, MessageRole::Agent, "two"),
                    message(3, MessageRole::User, "duplicate"),
                ],
                false,
            )),
        );
        let preview = pane.preview.as_ref().unwrap();
        assert_eq!(
            preview.scroll, 7,
            "prepending must preserve the viewport anchor"
        );
        assert_eq!(
            preview
                .messages
                .iter()
                .map(|message| message.seq)
                .collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert!(!preview.has_more);
    }

    fn preview_with_messages(messages: Vec<SessionMessage>) -> SessionsPane {
        let session_id = Uuid::new_v4();
        let mut pane = test_pane(vec![(summary(session_id, 100), Tier::Idle)]);
        let mut preview = PreviewState::new(session_id);
        preview.messages = messages;
        pane.preview = Some(preview);
        pane
    }

    fn line_text(line: &Line<'_>) -> String {
        line.spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect()
    }

    #[test]
    fn preview_header_shows_role_and_relative_time() {
        use chrono::{Local, TimeZone};

        const DAY_MS: i64 = 24 * 60 * 60 * 1_000;
        let now_ms = 1_700_000_000_000;
        let older_ms = now_ms - 7 * DAY_MS - 1;
        let mut pane = preview_with_messages(vec![
            SessionMessage {
                seq: 1,
                ts_ms: now_ms - 30_000,
                role: MessageRole::User,
                text: "now".into(),
            },
            SessionMessage {
                seq: 2,
                ts_ms: now_ms - 90 * 60 * 1_000,
                role: MessageRole::Agent,
                text: "relative".into(),
            },
            SessionMessage {
                seq: 3,
                ts_ms: now_ms - 7 * DAY_MS,
                role: MessageRole::Agent,
                text: "boundary".into(),
            },
            SessionMessage {
                seq: 4,
                ts_ms: older_ms,
                role: MessageRole::Agent,
                text: "absolute".into(),
            },
            SessionMessage {
                seq: 5,
                ts_ms: now_ms + 1_000,
                role: MessageRole::User,
                text: "future".into(),
            },
            SessionMessage {
                seq: 6,
                ts_ms: i64::MAX,
                role: MessageRole::Agent,
                text: "invalid".into(),
            },
        ]);

        let text = pane
            .preview_lines(80, now_ms)
            .iter()
            .map(line_text)
            .collect::<Vec<_>>()
            .join("\n");
        let absolute = Local
            .timestamp_millis_opt(older_ms)
            .single()
            .unwrap()
            .format("%Y-%m-%d %H:%M")
            .to_string();
        assert!(text.contains("You · just now"), "{text}");
        assert!(text.contains("builder · 1 hour ago"), "{text}");
        assert!(text.contains("builder · 7 days ago"), "{text}");
        assert!(text.contains(&format!("builder · {absolute}")), "{text}");
        assert_eq!(text.matches("You · just now").count(), 2, "{text}");
        assert!(text.contains("builder · —"), "{text}");
    }

    #[test]
    fn preview_wraps_on_word_boundaries() {
        let mut pane =
            preview_with_messages(vec![message(1, MessageRole::Agent, "alpha bravo charlie")]);
        let lines = pane.preview_lines(10, 1_000);
        let body = lines
            .iter()
            .skip(1)
            .map(line_text)
            .filter(|line| !line.is_empty())
            .map(|line| line.trim().to_string())
            .collect::<Vec<_>>();
        assert_eq!(body, vec!["alpha", "bravo", "charlie"]);
    }

    #[test]
    fn preview_renders_markdown() {
        let mut pane =
            preview_with_messages(vec![message(1, MessageRole::Agent, "**bold** and `code`")]);
        let lines = pane.preview_lines(40, 1_000);
        let text = lines.iter().map(line_text).collect::<Vec<_>>().join("\n");
        assert!(!text.contains("**"), "{text}");
        assert!(lines.iter().flat_map(|line| &line.spans).any(|span| {
            span.content == "bold" && span.style.add_modifier.contains(Modifier::BOLD)
        }));
    }

    #[test]
    fn preview_continuation_lines_styled() {
        let mut pane = preview_with_messages(vec![message(
            1,
            MessageRole::Agent,
            "alpha bravo charlie delta",
        )]);
        let lines = pane.preview_lines(10, 1_000);
        let body = lines
            .iter()
            .skip(1)
            .filter(|line| !line_text(line).is_empty())
            .collect::<Vec<_>>();
        assert!(body.len() >= 3);
        assert!(body.iter().all(|line| line.style.fg == Some(Color::White)));
    }

    #[test]
    fn preview_empty_state() {
        let mut pane = preview_with_messages(Vec::new());
        let lines = pane.preview_lines(40, 1_000);
        assert_eq!(line_text(&lines[0]), "  no text messages in this session");
        assert_eq!(
            lines[0].spans[0].style.fg,
            Some(Color::Indexed(MUTED_COLOR_INDEX))
        );
    }

    #[test]
    fn preview_block_cache_hits() {
        let mut pane =
            preview_with_messages(vec![message(1, MessageRole::Agent, "**cached** message")]);
        crate::tui::markdown::reset_render_counters();
        let _ = pane.preview_lines(40, 1_000);
        assert_eq!(crate::tui::markdown::render_call_count(), 1);
        let _ = pane.preview_lines(40, 2_000);
        assert_eq!(crate::tui::markdown::render_call_count(), 1);
        let _ = pane.preview_lines(41, 2_000);
        assert_eq!(crate::tui::markdown::render_call_count(), 2);
    }

    #[test]
    fn preview_virtualizes_markdown_layout_to_viewport() {
        let messages = (1..=20)
            .map(|seq| message(seq, MessageRole::Agent, &format!("message {seq}")))
            .collect();
        let mut pane = preview_with_messages(messages);
        crate::tui::markdown::reset_render_counters();
        let lines = pane.preview_window_lines(40, 4, 1_000);
        assert_eq!(lines.len(), 4);
        let calls = crate::tui::markdown::render_call_count();
        assert!(calls < 20, "laid out all {calls} messages");
        assert!(!pane.last_preview_reached_top);
    }

    #[test]
    fn preview_pagination_preserves_anchor_and_lays_out_older_page_lazily() {
        const HEIGHT: usize = 4;
        let initial = (51..=60)
            .map(|seq| message(seq, MessageRole::Agent, &format!("message {seq}")))
            .collect();
        let mut pane = preview_with_messages(initial);
        let full = pane.preview_lines(40, 1_000);
        let old_max = full.len().saturating_sub(HEIGHT);
        pane.preview.as_mut().unwrap().scroll = old_max;
        let before = pane.preview_window_lines(40, HEIGHT, 1_000);
        assert!(pane.last_preview_reached_top);

        let session_id = pane.preview.as_ref().unwrap().session_id;
        let older = (1..=50)
            .map(|seq| message(seq, MessageRole::User, &format!("message {seq}")))
            .collect();
        pane.apply_preview_result(session_id, Some(51), Ok((older, false)));

        crate::tui::markdown::reset_render_counters();
        let after = pane.preview_window_lines(40, HEIGHT, 1_000);
        assert_eq!(
            after, before,
            "older rows must be inserted above the viewport"
        );
        let calls = crate::tui::markdown::render_call_count();
        assert!(
            calls < 50,
            "laid out the whole older page ({calls} messages)"
        );
        assert!(!pane.last_preview_reached_top);
    }

    #[test]
    fn hit_rect_and_double_click_decisions_are_pure() {
        let hits = vec![
            CardHit {
                index: 0,
                rect: Rect::new(0, 0, 10, 3),
            },
            CardHit {
                index: 1,
                rect: Rect::new(0, 3, 10, 3),
            },
        ];
        assert_eq!(hit_card(&hits, 2, 4), Some(1));
        assert_eq!(hit_card(&hits, 20, 4), None);
        assert!(click_resumes(1, 1, false));
        assert!(click_resumes(0, 1, true));
        assert!(!click_resumes(0, 1, false));

        let now = std::time::Instant::now();
        assert!(is_double_click(
            Some((1, now)),
            1,
            now + std::time::Duration::from_millis(10)
        ));
        assert!(!is_double_click(
            Some((1, now)),
            1,
            now + DOUBLE_CLICK_WINDOW + std::time::Duration::from_millis(1)
        ));
    }

    #[test]
    fn focus_tab_and_border_style_are_distinct() {
        assert_eq!(
            column_border_style(Focus::List, Focus::List),
            Style::default().fg(Color::Indexed(ACCENT_BLUE_INDEX))
        );
        assert_eq!(
            column_border_style(Focus::List, Focus::Preview),
            Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX))
        );
        let mut pane = test_pane(vec![(summary(Uuid::new_v4(), 100), Tier::Idle)]);
        pane.preview_enabled = true;
        assert_eq!(pane.focus, Focus::List);
        pane.handle_key(press(KeyCode::Tab));
        assert_eq!(pane.focus, Focus::Preview);
        pane.preview_enabled = false;
        pane.handle_key(press(KeyCode::Tab));
        assert_eq!(pane.focus, Focus::Preview, "single-column Tab is a no-op");
    }

    #[test]
    fn preview_error_does_not_replace_list_body() {
        let session_id = Uuid::new_v4();
        let mut s = summary(session_id, 100);
        s.title = Some("keep visible".into());
        let mut pane = test_pane(vec![(s, Tier::Idle)]);
        pane.preview = Some(PreviewState::new(session_id));
        pane.apply_preview_result(session_id, None, Err("boom".into()));
        let body = pane
            .body_lines_with_selected_span(80)
            .0
            .into_iter()
            .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
            .collect::<Vec<_>>()
            .join("\n");
        let preview = pane
            .preview_lines(80, 1_000)
            .into_iter()
            .flat_map(|line| line.spans.into_iter().map(|span| span.content.into_owned()))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(body.contains("keep visible"));
        assert!(preview.contains("preview unavailable: boom"));
    }

    #[test]
    fn card_fields_assemble() {
        let mut s = summary(Uuid::new_v4(), 1_700_000_000);
        s.title = Some("fix the parser".into());
        s.fork_count = 2;
        let text: String = card_lines(&s, Tier::Unread, true, true, 60, true)
            .iter()
            .map(|l| {
                l.spans
                    .iter()
                    .map(|sp| sp.content.as_ref())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("fix the parser"), "title is the description");
        assert!(text.contains("unread"), "tier status shown");
        assert!(
            text.contains("press →/l to view 2 fork(s)"),
            "fork hint shown when forks exist"
        );
        assert!(text.contains("[alpha]"), "all-projects label shown");
        assert!(text.contains("╭") && text.contains("╰"), "rounded corners");
    }

    #[test]
    fn pending_card_renders_interrupt_count() {
        let mut s = summary(Uuid::new_v4(), 1_700_000_000);
        s.open_interrupts = 3;
        let text: String = card_lines(&s, Tier::PendingQuestion, false, false, 60, false)
            .iter()
            .flat_map(|line| line.spans.iter().map(|span| span.content.as_ref()))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(text.contains("● 3 pending"), "{text}");
    }

    #[test]
    fn description_falls_back_to_short_id() {
        let s = summary(Uuid::new_v4(), 0); // title None
        assert_eq!(card_description(&s), "abc123");
    }

    /// Regression guard (implementation note): a
    /// session carrying a non-null title renders THAT title through the
    /// `/sessions` path, not the short id.
    #[test]
    fn description_renders_title_when_present() {
        let mut s = summary(Uuid::new_v4(), 0);
        s.title = Some("fix-redact-allowlist".into());
        assert_eq!(card_description(&s), "fix-redact-allowlist");
    }

    /// Per-session pin count renders on the card only when non-zero
    /// (`pinned-messages`); a zero-pin session shows no pin chrome.
    #[test]
    fn card_shows_pin_count_only_when_nonzero() {
        let render = |n: u32| -> String {
            let mut s = summary(Uuid::new_v4(), 1_700_000_000);
            s.pin_count = n;
            card_lines(&s, Tier::Idle, false, false, 60, true)
                .iter()
                .map(|l| {
                    l.spans
                        .iter()
                        .map(|sp| sp.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
        };
        assert!(
            !render(0).contains("📌"),
            "zero-pin session shows no pin chrome"
        );
        let with_pins = render(3);
        assert!(with_pins.contains("📌 3"), "pin count shown when non-zero");
    }

    #[test]
    fn card_pin_count_honors_emoji_setting() {
        let mut s = summary(Uuid::new_v4(), 1_700_000_000);
        s.pin_count = 3;
        let render = |use_emojis: bool| -> String {
            card_lines(&s, Tier::Idle, false, false, 60, use_emojis)
                .iter()
                .map(|l| {
                    l.spans
                        .iter()
                        .map(|sp| sp.content.as_ref())
                        .collect::<String>()
                })
                .collect::<Vec<_>>()
                .join("\n")
        };

        let emoji = render(true);
        assert!(emoji.contains("📌 3"), "{emoji}");

        let plain = render(false);
        assert!(plain.contains("pin 3"), "{plain}");
        assert!(!plain.contains("📌"), "{plain}");
    }

    #[test]
    fn esc_closes() {
        // Build a pane without touching the daemon (empty root level).
        let mut pane = test_pane(vec![]);
        assert!(matches!(
            pane.handle_key(press(KeyCode::Esc)),
            Some(SessionsOutcome::Close)
        ));
    }

    #[test]
    fn enter_resumes_highlighted() {
        let id = Uuid::new_v4();
        let mut pane = test_pane(vec![(summary(id, 100), Tier::Idle)]);
        match pane.handle_key(press(KeyCode::Enter)) {
            Some(SessionsOutcome::Resume(got)) => assert_eq!(got, id),
            other => panic!(
                "expected Resume, got a non-resume outcome: {}",
                other.is_none()
            ),
        }
    }

    #[test]
    fn fork_breadcrumb_drill_out_is_bounded() {
        // Drilling out at the root is a no-op (never pops below level 0).
        let mut pane = test_pane(vec![(summary(Uuid::new_v4(), 1), Tier::Idle)]);
        assert_eq!(pane.levels.len(), 1);
        pane.drill_out();
        assert_eq!(pane.levels.len(), 1);
    }

    #[test]
    fn drill_in_noop_without_forks() {
        // A card with fork_count = 0 doesn't push a level.
        let mut pane = test_pane(vec![(summary(Uuid::new_v4(), 1), Tier::Idle)]);
        pane.drill_in();
        assert_eq!(pane.levels.len(), 1);
    }

    #[test]
    fn sessions_pane_preview_resets_on_fork_drill_in_and_out() {
        let parent_id = Uuid::new_v4();
        let mut parent = summary(parent_id, 1);
        parent.fork_count = 1;
        let mut pane = test_pane(vec![(parent.clone(), Tier::Idle)]);
        pane.preview = Some(PreviewState::new(parent_id));

        assert!(matches!(
            pane.handle_key(press(KeyCode::Right)),
            Some(SessionsOutcome::LoadList)
        ));
        assert!(pane.preview.is_none());

        pane.apply_sessions_result(Ok(vec![summary(Uuid::new_v4(), 2)]));
        pane.preview = Some(PreviewState::new(Uuid::new_v4()));
        assert!(matches!(
            pane.handle_key(press(KeyCode::Left)),
            Some(SessionsOutcome::LoadList)
        ));
        assert!(pane.preview.is_none());
    }

    #[test]
    fn sessions_pane_resize_to_split_starts_daemon_preview_load() {
        let session_id = Uuid::new_v4();
        let mut pane = test_pane(vec![(summary(session_id, 100), Tier::Idle)]);
        pane.preview = None;
        pane.preview_enabled = false;
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 120, 24)))
            .unwrap();

        assert!(pane.is_preview_enabled());
        assert!(pane.needs_preview_for_selection());
        assert!(matches!(
            pane.ensure_preview_for_selection(),
            Some(SessionsOutcome::LoadPreview {
                session_id: got,
                before_seq: None,
            }) if got == session_id
        ));
    }

    #[tokio::test]
    async fn daemonless_split_first_render_populates_preview() {
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("pid", "/proj", "builder").await.unwrap();
        db.insert_session_event(
            root.session_id,
            cockpit_db::session_log::SessionEventKind::UserMessage,
            Some("builder"),
            None,
            &serde_json::json!({"text": "preview on first render"}),
        )
        .await
        .unwrap();
        let mut loader = test_pane_mode(vec![], false);
        loader.db = Some(db);
        let cards = loader.fetch_level(Some("pid".into()), None);
        let mut pane = test_pane_mode(cards, false);
        pane.db = loader.db.take();
        pane.preview = None;
        pane.preview_enabled = false;
        let backend = TestBackend::new(120, 24);
        let mut terminal = Terminal::new(backend).unwrap();

        terminal
            .draw(|frame| pane.render(frame, Rect::new(0, 0, 120, 24)))
            .unwrap();

        let preview = pane.preview.as_ref().expect("preview populated");
        assert_eq!(preview.session_id, root.session_id);
        assert!(!preview.loading, "daemonless preview loads locally");
        assert_eq!(preview.messages.len(), 1);
        assert_eq!(preview.messages[0].text, "preview on first render");
        assert!(pane.is_preview_enabled());
    }

    #[test]
    fn breadcrumb_reflects_depth() {
        let mut parent = summary(Uuid::new_v4(), 1);
        parent.title = Some("root-task".into());
        let mut pane = test_pane(vec![(parent.clone(), Tier::Idle)]);
        // Simulate a drill-in by pushing a level (the real drill-in fetches
        // from the daemon, which isn't available under test).
        pane.levels.push(Level {
            parent: Some(parent),
            cards: vec![],
            list: ScrollList::new(),
        });
        let crumb: String = pane
            .breadcrumb_line()
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(crumb.contains("forks of root-task"));
    }

    #[test]
    fn confirm_choice_cycles_and_archive_delete_cascade() {
        // Drive the confirm sub-dialog's choice cycling + that both
        // Archive and Delete map to cascading subtree requests.
        let mut pane = test_pane(vec![]);
        pane.step = Step::Confirm {
            session_id: Uuid::new_v4(),
            label: "task".into(),
            descendants: 4,
            live: true,
            choice: ConfirmChoice::Cancel,
        };
        // Right cycles Cancel → Archive → Delete → Cancel.
        pane.handle_key(press(KeyCode::Right));
        assert!(matches!(
            pane.step,
            Step::Confirm {
                choice: ConfirmChoice::Archive,
                ..
            }
        ));
        pane.handle_key(press(KeyCode::Right));
        assert!(matches!(
            pane.step,
            Step::Confirm {
                choice: ConfirmChoice::Delete,
                ..
            }
        ));
        // Esc returns to Browse.
        pane.handle_key(press(KeyCode::Esc));
        assert_eq!(pane.step, Step::Browse);
    }

    #[test]
    fn confirm_dialog_states_cascade_count_and_live_warning() {
        // The rendered confirm text states the descendant cascade count
        // and the interrupt-first warning when the target is live.
        let pane = {
            let mut p = test_pane(vec![]);
            p.step = Step::Confirm {
                session_id: Uuid::new_v4(),
                label: "build the thing".into(),
                descendants: 3,
                live: true,
                choice: ConfirmChoice::Archive,
            };
            p
        };
        // Reconstruct the confirm body the renderer assembles.
        let Step::Confirm {
            descendants, live, ..
        } = &pane.step
        else {
            unreachable!()
        };
        assert_eq!(*descendants, 3);
        assert!(*live);
        // The button row marks the active choice.
        let row: String = button_row(ConfirmChoice::Archive)
            .spans
            .iter()
            .map(|s| s.content.as_ref())
            .collect();
        assert!(row.contains("[ Archive ]"));
        assert!(row.contains("Delete"));
        assert!(row.contains("Cancel"));
    }

    /// Build a pane with a fixed root level and no daemon interaction.
    #[test]
    fn cursor_wraps_at_both_ends() {
        let cards = vec![
            (summary(Uuid::new_v4(), 300), Tier::Unread),
            (summary(Uuid::new_v4(), 200), Tier::Unread),
            (summary(Uuid::new_v4(), 100), Tier::Unread),
        ];
        let mut pane = test_pane(cards);
        assert_eq!(pane.current().list.cursor(), 0);
        // Up from the first card wraps to the last.
        pane.handle_key(press(KeyCode::Up));
        assert_eq!(pane.current().list.cursor(), 2);
        // Down from the last card wraps to the first.
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.current().list.cursor(), 0);
        // `j`/`k` navigate the same (non-typing list).
        pane.handle_key(press(KeyCode::Char('k')));
        assert_eq!(pane.current().list.cursor(), 2);
        pane.handle_key(press(KeyCode::Char('j')));
        assert_eq!(pane.current().list.cursor(), 0);
    }

    #[test]
    fn cursor_single_card_stays_put() {
        let cards = vec![(summary(Uuid::new_v4(), 100), Tier::Unread)];
        let mut pane = test_pane(cards);
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.current().list.cursor(), 0);
        pane.handle_key(press(KeyCode::Up));
        assert_eq!(pane.current().list.cursor(), 0);
    }

    #[test]
    fn selected_card_span_tracks_variable_session_card_heights() {
        let mut first = summary(Uuid::new_v4(), 300);
        first.short_id = Some("first".into());
        let mut selected = summary(Uuid::new_v4(), 200);
        selected.short_id = Some("selected".into());
        selected.fork_count = 2; // Adds the fork-hint row.
        let mut last = summary(Uuid::new_v4(), 100);
        last.short_id = Some("last".into());
        let mut pane = test_pane(vec![
            (first, Tier::Idle),
            (selected, Tier::Idle),
            (last, Tier::Idle),
        ]);
        pane.current_mut().list.set_cursor(1);

        let (lines, span) = pane.body_lines_with_selected_span(80);

        assert_eq!(span, Some((4, 9)));
        assert_eq!(lines.len(), 13);
        assert_eq!(
            crate::tui::pane_shared::clamp_scroll_to_visible_span(0, 5, lines.len(), 4, 9),
            4
        );
    }

    #[test]
    fn relative_time_buckets() {
        const MIN: i64 = 60;
        const HOUR: i64 = 3_600;
        const DAY: i64 = 86_400;

        // `just now` covers everything under a minute, including the
        // exact boundary just below.
        assert_eq!(relative_time(0), "just now");
        assert_eq!(relative_time(59), "just now");

        // Future timestamps (negative elapsed) clamp to `just now`.
        assert_eq!(relative_time(-5), "just now");
        assert_eq!(relative_time(-DAY), "just now");

        // Minutes, singular vs plural, up to 59.
        assert_eq!(relative_time(MIN), "1 minute ago");
        assert_eq!(relative_time(2 * MIN), "2 minutes ago");
        assert_eq!(relative_time(59 * MIN), "59 minutes ago");

        // 60 min crosses into hours; hours run up to 47.
        assert_eq!(relative_time(60 * MIN), "1 hour ago");
        assert_eq!(relative_time(2 * HOUR), "2 hours ago");
        assert_eq!(relative_time(47 * HOUR), "47 hours ago");

        // 48h switches to days (NOT at 24h).
        assert_eq!(relative_time(24 * HOUR), "24 hours ago");
        assert_eq!(relative_time(48 * HOUR), "2 days ago");
        assert_eq!(relative_time(29 * DAY), "29 days ago");

        // 30 days crosses into months (30-day months), up to 11 months.
        assert_eq!(relative_time(30 * DAY), "1 month ago");
        assert_eq!(relative_time(59 * DAY), "1 month ago");
        assert_eq!(relative_time(60 * DAY), "2 months ago");
        // 11 months: 11*30 = 330 days, still < 365.
        assert_eq!(relative_time(360 * DAY), "12 months ago");
        assert_eq!(relative_time(364 * DAY), "12 months ago");

        // 365 days crosses into years (365-day years).
        assert_eq!(relative_time(365 * DAY), "1 year ago");
        assert_eq!(relative_time(729 * DAY), "1 year ago");
        assert_eq!(relative_time(730 * DAY), "2 years ago");
    }

    #[test]
    fn nested_escape_backs_out_but_q_closes() {
        let parent = summary(Uuid::new_v4(), 100);
        let mut pane = test_pane(vec![(parent.clone(), Tier::Idle)]);
        pane.levels.push(Level {
            parent: Some(parent),
            cards: vec![(summary(Uuid::new_v4(), 101), Tier::Idle)],
            list: ScrollList::new(),
        });

        assert!(matches!(
            pane.handle_key(press(KeyCode::Esc)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.levels.len(), 1, "Esc backs out one fork level");

        pane.levels.push(Level {
            parent: Some(summary(Uuid::new_v4(), 102)),
            cards: Vec::new(),
            list: ScrollList::new(),
        });
        assert!(matches!(
            pane.handle_key(press(KeyCode::Char('q'))),
            Some(SessionsOutcome::Close)
        ));
    }

    #[test]
    fn confirm_escape_cancels_but_q_closes() {
        let mut pane = test_pane(vec![]);
        pane.step = Step::Confirm {
            session_id: Uuid::new_v4(),
            label: "task".into(),
            descendants: 0,
            live: false,
            choice: ConfirmChoice::Cancel,
        };
        assert!(pane.handle_key(press(KeyCode::Esc)).is_none());
        assert_eq!(pane.step, Step::Browse);

        pane.step = Step::Confirm {
            session_id: Uuid::new_v4(),
            label: "task".into(),
            descendants: 0,
            live: false,
            choice: ConfirmChoice::Cancel,
        };
        assert!(matches!(
            pane.handle_key(press(KeyCode::Char('q'))),
            Some(SessionsOutcome::Close)
        ));
    }

    #[test]
    fn daemon_nested_escape_and_back_schedule_current_level_reload() {
        let parent = summary(Uuid::new_v4(), 100);
        let mut pane = test_pane(vec![(parent.clone(), Tier::Idle)]);
        pane.levels.push(Level {
            parent: Some(parent),
            cards: vec![],
            list: ScrollList::new(),
        });
        pane.loading = Some("Loading sessions...");

        assert!(matches!(
            pane.handle_key(press(KeyCode::Esc)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.levels.len(), 1, "Esc backs out one fork level");
        assert_eq!(pane.loading, Some("Loading sessions..."));
        assert!(pane.current().cards.is_empty());

        let parent = summary(Uuid::new_v4(), 200);
        pane.levels.push(Level {
            parent: Some(parent),
            cards: vec![(summary(Uuid::new_v4(), 201), Tier::Idle)],
            list: ScrollList::new(),
        });
        pane.loading = None;

        assert!(matches!(
            pane.handle_key(press(KeyCode::Left)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.levels.len(), 1, "Left backs out one fork level");
        assert_eq!(pane.loading, Some("Loading sessions..."));
    }

    #[test]
    fn daemon_reload_error_clears_loading_and_surfaces_inline_error() {
        let mut pane = test_pane(vec![(summary(Uuid::new_v4(), 100), Tier::Idle)]);
        pane.loading = Some("Loading sessions...");

        let ids = pane.apply_sessions_result(Err("daemon unavailable".into()));

        assert!(ids.is_empty());
        assert!(pane.loading.is_none(), "failed reload clears spinner");
        assert_eq!(pane.error.as_deref(), Some("daemon unavailable"));
    }

    #[test]
    fn archive_delete_and_unarchive_schedule_daemon_reload() {
        let session_id = Uuid::new_v4();
        let mut pane = test_pane(vec![(summary(session_id, 100), Tier::Idle)]);
        pane.step = Step::Confirm {
            session_id,
            label: "task".into(),
            descendants: 0,
            live: false,
            choice: ConfirmChoice::Archive,
        };

        assert!(matches!(
            pane.handle_key(press(KeyCode::Enter)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.step, Step::Browse);
        assert_eq!(pane.loading, Some("Loading sessions..."));

        pane.loading = None;
        pane.step = Step::Confirm {
            session_id,
            label: "task".into(),
            descendants: 0,
            live: false,
            choice: ConfirmChoice::Delete,
        };
        assert!(matches!(
            pane.handle_key(press(KeyCode::Enter)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.loading, Some("Loading sessions..."));

        let mut archived = summary(Uuid::new_v4(), 200);
        archived.archived_at = Some(300);
        let mut pane = test_pane(vec![(archived, Tier::Idle)]);
        pane.show_archived = true;
        assert!(matches!(
            pane.handle_key(press(KeyCode::Char('u'))),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.loading, Some("Loading sessions..."));
    }

    fn test_pane(cards: Vec<(SessionSummary, Tier)>) -> SessionsPane {
        test_pane_mode(cards, true)
    }

    /// Build a pane with a fixed root level, choosing the daemon-connected
    /// mode. No daemon/DB interaction either way (the level is seeded).
    fn test_pane_mode(cards: Vec<(SessionSummary, Tier)>, daemon_connected: bool) -> SessionsPane {
        SessionsPane {
            project_id: Some("pid".into()),
            scope: Scope::Project,
            show_archived: false,
            levels: vec![Level {
                parent: None,
                cards,
                list: ScrollList::new(),
            }],
            step: Step::Browse,
            error: None,
            notice: None,
            loading: None,
            daemon_connected,
            daemon_socket: daemon_connected
                .then(|| std::path::PathBuf::from("/tmp/cockpit-test.sock")),
            use_emojis: true,
            db: None,
            last_body_height: 100,
            last_content_rows: 0,
            focus: Focus::List,
            preview: None,
            preview_enabled: false,
            preview_area: None,
            list_area: None,
            card_hits: Vec::new(),
            last_preview_height: 0,
            last_preview_rows: 0,
            last_preview_reached_top: false,
            preview_clock_ms: || 1_700_000_000_000,
            last_card_click: None,
        }
    }

    fn message(seq: i64, role: MessageRole, text: &str) -> SessionMessage {
        SessionMessage {
            seq,
            ts_ms: seq * 10,
            role,
            text: text.to_string(),
        }
    }

    #[test]
    fn daemonless_enter_does_not_resume_and_shows_hint() {
        // Daemonless: Enter on a highlighted card must NOT return Resume
        // (no daemon to spawn) — it sets a non-error notice and stays open.
        let id = Uuid::new_v4();
        let mut pane = test_pane_mode(vec![(summary(id, 100), Tier::Idle)], false);
        let outcome = pane.handle_key(press(KeyCode::Enter));
        assert!(
            outcome.is_none(),
            "daemonless Enter must not resume / close the pane"
        );
        assert!(pane.error.is_none(), "the hint is a notice, not an error");
        let notice = pane.notice.as_deref().unwrap_or_default();
        assert!(
            notice.contains("daemon"),
            "the hint mentions the missing daemon"
        );
    }

    #[test]
    fn daemonless_archive_and_unarchive_are_gated() {
        // Daemonless: `d` (archive/delete) never opens the confirm dialog,
        // and `u` (unarchive) is a no-op; both surface the same hint.
        let id = Uuid::new_v4();
        let mut pane = test_pane_mode(vec![(summary(id, 100), Tier::Idle)], false);
        pane.handle_key(press(KeyCode::Char('d')));
        assert_eq!(pane.step, Step::Browse, "no confirm dialog daemonless");
        assert!(pane.notice.is_some(), "archive shows the daemonless hint");
        pane.handle_key(press(KeyCode::Char('u')));
        assert_eq!(pane.step, Step::Browse);
        assert!(pane.notice.is_some(), "unarchive shows the daemonless hint");
        assert!(pane.error.is_none(), "gating is never an error state");
    }

    #[test]
    fn daemonless_notice_clears_on_next_key() {
        // The hint shows for one action then dismisses on the next key.
        let mut pane = test_pane_mode(vec![(summary(Uuid::new_v4(), 1), Tier::Idle)], false);
        pane.handle_key(press(KeyCode::Enter));
        assert!(pane.notice.is_some());
        pane.handle_key(press(KeyCode::Down));
        assert!(pane.notice.is_none(), "navigation clears the hint");
    }

    #[test]
    fn daemonless_open_with_unopenable_db_lists_empty_no_crash() {
        // Open daemonless against a pane whose DB handle is `None` (the
        // DB-unopenable case): the list is empty and an inline error is
        // set, never a crash. Drive the daemonless fetch directly.
        let mut pane = test_pane_mode(vec![], false);
        pane.db = None;
        let cards = pane.fetch_level(Some("pid".into()), None);
        assert!(cards.is_empty(), "no cards when the DB can't be opened");
        assert!(
            pane.error
                .as_deref()
                .unwrap_or_default()
                .contains("database"),
            "DB-unopenable surfaces a clear inline error"
        );
    }

    #[tokio::test]
    async fn daemonless_lists_from_the_db() {
        // The factored `Db::list_session_summaries` populates the daemonless
        // list: open an in-memory DB, seed a root session, and confirm the
        // pane's daemonless fetch returns it tier-classified.
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("pid", "/proj", "builder").await.unwrap();
        let mut pane = test_pane_mode(vec![], false);
        pane.db = Some(db);
        let cards = pane.fetch_level(Some("pid".into()), None);
        assert_eq!(cards.len(), 1, "the seeded root session is listed");
        assert_eq!(cards[0].0.session_id, root.session_id);
        assert!(pane.error.is_none(), "a successful list clears the error");
    }

    #[test]
    fn daemon_connected_open_starts_loading_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let pane = SessionsPane::open(
            tmp.path(),
            true,
            Some(tmp.path().join("missing-daemon.sock")),
            false,
        );

        assert_eq!(pane.loading, Some("Loading sessions..."));
        assert!(pane.current().cards.is_empty());
    }
}
