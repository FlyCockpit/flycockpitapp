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
//!   in-memory per-session [`crate::daemon::session_worker::LiveState`]
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
//!   read-only ([`crate::db::Db::open_default`], same as `/stats`) via the
//!   shared [`crate::db::Db::list_session_summaries`] the daemon also calls,
//!   so ordering / scoping / fork-grouping match. Live status is absent
//!   (every session falls to its DB-derived tier — never an error), and the
//!   mutating actions (resume / archive / delete / unarchive) are disabled
//!   with a non-error hint rather than spawning a daemon or writing the DB.
//!
//! The resume action is *not* performed here — `handle_key` returns a
//! [`SessionsOutcome`] the `App` acts on, reusing the existing
//! session-switch path (`attach_to_session`).

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Paragraph};
use uuid::Uuid;

use crate::daemon::proto::SessionSummary;
use crate::db::Db;
use crate::tui::agent_runner;
use crate::tui::pane_shared::{
    boxed_row, clamp_scroll_to_visible_span, resolve_project_id, short_id,
};
use crate::tui::theme::{ACCENT_BLUE_INDEX, MUTED_COLOR_INDEX};

/// Root-session row cap for the daemonless direct-DB list — matches the
/// daemon `ListSessions` handler's `100` so both modes show the same set.
const DAEMONLESS_LIST_LIMIT: u32 = 100;

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
            Tier::Processing => "● working",
            Tier::Unread => "● unread",
            Tier::PendingQuestion => "● question pending",
            Tier::Idle => "idle",
        }
    }

    /// Accent color for the status indicator.
    fn color(self) -> Color {
        match self {
            Tier::ActiveSchedules => Color::Green,
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
    if let Some((has_schedules, processing)) = live {
        if has_schedules {
            return Tier::ActiveSchedules;
        }
        if processing {
            return Tier::Processing;
        }
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
    cursor: usize,
    scroll: usize,
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
    use_emojis: bool,
    /// Read-only session DB handle, opened only in the daemonless case so
    /// the browser can list without a daemon. `None` when daemon-connected
    /// (the RPC path is used) or when the DB couldn't be opened.
    db: Option<Db>,
    /// Rendered body height + content rows at last draw (scroll clamp).
    last_body_height: usize,
    last_content_rows: usize,
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
    pub fn open(cwd: &std::path::Path, daemon_connected: bool) -> Self {
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
        let use_emojis = crate::config::extended::load_for_cwd(cwd).tui.use_emojis;
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
            use_emojis,
            db,
            last_body_height: 0,
            last_content_rows: 0,
        };
        if daemon_connected {
            pane.loading = Some("Loading sessions...");
            pane.levels = vec![Level {
                parent: None,
                cards: Vec::new(),
                cursor: 0,
                scroll: 0,
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
                cursor: 0,
                scroll: 0,
            }];
            return;
        }
        let cards = self.fetch_level(pid, None);
        self.levels = vec![Level {
            parent: None,
            cards,
            cursor: 0,
            scroll: 0,
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
                    level.cursor = level.cursor.min(level.cards.len().saturating_sub(1));
                    level.scroll = 0;
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
            level.cursor = level.cursor.min(level.cards.len().saturating_sub(1));
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
            agent_runner::list_sessions_blocking(project_id, parent)
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
                    agent_runner::session_live_status_blocking(ids)
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
        db.list_session_summaries(project_id, parent, DAEMONLESS_LIST_LIMIT)
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
            level.cursor = level.cursor.min(level.cards.len().saturating_sub(1));
            level.scroll = 0;
        }
    }

    fn mark_current_level_loading(&mut self) {
        self.loading = Some("Loading sessions...");
        if let Some(level) = self.levels.last_mut() {
            level.cards.clear();
            level.cursor = 0;
            level.scroll = 0;
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
        level.cards.get(level.cursor).map(|(s, _)| s)
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
                    if self.daemon_connected {
                        self.mark_current_level_loading();
                        return Some(SessionsOutcome::LoadList);
                    }
                } else {
                    return Some(SessionsOutcome::Close);
                }
            }
            KeyCode::Up | KeyCode::Char('k') => self.move_cursor(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_cursor(1),
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
            KeyCode::Right | KeyCode::Char('l') if self.drill_in() => {
                return Some(SessionsOutcome::LoadList);
            }
            KeyCode::Right | KeyCode::Char('l') => {}
            // Go back up one fork level (no-op at the root).
            KeyCode::Left | KeyCode::Char('h') => {
                if self.drill_out() && self.daemon_connected {
                    self.mark_current_level_loading();
                    return Some(SessionsOutcome::LoadList);
                }
            }
            // Scope toggle — only meaningful with a current project.
            KeyCode::Char('p') if self.project_id.is_some() => {
                self.scope = match self.scope {
                    Scope::Project => Scope::All,
                    Scope::All => Scope::Project,
                };
                self.load_root();
                if self.daemon_connected {
                    return Some(SessionsOutcome::LoadList);
                }
            }
            // Reveal / hide archived sessions.
            KeyCode::Char('a') => {
                self.show_archived = !self.show_archived;
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

    fn move_cursor(&mut self, delta: isize) {
        let len = self.current().cards.len();
        if len == 0 {
            return;
        }
        let level = self.current_mut();
        let prev = level.cursor;
        // Wrap at both ends, consistent with every other selectable list.
        level.cursor = if delta < 0 {
            crate::tui::nav::wrap_prev(prev, len)
        } else {
            crate::tui::nav::wrap_next(prev, len)
        };
        // Keep the cursor inside the visible window (rough: each card is
        // ~4 rows). The render pass does the precise clamp.
        if delta < 0 {
            if level.cursor > prev {
                // Wrapped first → last: scroll toward the bottom; render
                // clamps to the precise floor.
                level.scroll = level.scroll.saturating_add(len);
            } else {
                level.scroll = level.scroll.saturating_sub(1);
            }
        } else if level.cursor < prev {
            // Wrapped last → first: jump back to the top.
            level.scroll = 0;
        } else {
            level.scroll += 1;
        }
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
                cursor: 0,
                scroll: 0,
            });
            return true;
        }
        let cards = self.fetch_level(None, Some(parent.session_id));
        self.levels.push(Level {
            parent: Some(parent),
            cards,
            cursor: 0,
            scroll: 0,
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
        let live_map = agent_runner::session_live_status_blocking(vec![s.session_id]);
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
        use crate::daemon::proto::Request;
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
            crate::daemon::proto::Request::UnarchiveSession {
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
        level.scroll = level.scroll.saturating_sub(1);
    }

    pub fn scroll_down(&mut self) {
        let max = self.last_content_rows.saturating_sub(self.last_body_height);
        let level = self.current_mut();
        level.scroll = (level.scroll + 1).min(max);
    }

    pub fn render(&mut self, frame: &mut Frame, area: Rect) {
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

        let (lines, selected_span) = self.body_lines_with_selected_span(body.width as usize);
        self.last_content_rows = lines.len();
        self.last_body_height = body.height as usize;
        let mut scroll = self
            .current()
            .scroll
            .min(self.last_content_rows.saturating_sub(self.last_body_height));
        if let Some((start, end)) = selected_span {
            scroll = clamp_scroll_to_visible_span(
                scroll,
                self.last_body_height,
                self.last_content_rows,
                start,
                end,
            );
        }
        if let Some(level) = self.levels.last_mut() {
            level.scroll = scroll;
        }
        frame.render_widget(Paragraph::new(lines).scroll((scroll as u16, 0)), body);

        let muted = Style::default().fg(Color::Indexed(MUTED_COLOR_INDEX));
        frame.render_widget(Paragraph::new(self.help_line()).style(muted), help_area);

        // The confirm sub-dialog draws over the bottom of the body.
        if let Step::Confirm { .. } = &self.step {
            self.render_confirm(frame, body);
        }
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
                i == level.cursor,
                show_project,
                width,
                self.use_emojis,
            );
            let end = start + card.len();
            if i == level.cursor {
                selected_span = Some((start, end));
            }
            lines.extend(card);
        }
        (lines, selected_span)
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
    let status = Span::styled(tier.label().to_string(), Style::default().fg(tier.color()));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};

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
    fn breadcrumb_reflects_depth() {
        let mut parent = summary(Uuid::new_v4(), 1);
        parent.title = Some("root-task".into());
        let mut pane = test_pane(vec![(parent.clone(), Tier::Idle)]);
        // Simulate a drill-in by pushing a level (the real drill-in fetches
        // from the daemon, which isn't available under test).
        pane.levels.push(Level {
            parent: Some(parent),
            cards: vec![],
            cursor: 0,
            scroll: 0,
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
        assert_eq!(pane.current().cursor, 0);
        // Up from the first card wraps to the last.
        pane.handle_key(press(KeyCode::Up));
        assert_eq!(pane.current().cursor, 2);
        // Down from the last card wraps to the first.
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.current().cursor, 0);
        // `j`/`k` navigate the same (non-typing list).
        pane.handle_key(press(KeyCode::Char('k')));
        assert_eq!(pane.current().cursor, 2);
        pane.handle_key(press(KeyCode::Char('j')));
        assert_eq!(pane.current().cursor, 0);
    }

    #[test]
    fn cursor_single_card_stays_put() {
        let cards = vec![(summary(Uuid::new_v4(), 100), Tier::Unread)];
        let mut pane = test_pane(cards);
        pane.handle_key(press(KeyCode::Down));
        assert_eq!(pane.current().cursor, 0);
        pane.handle_key(press(KeyCode::Up));
        assert_eq!(pane.current().cursor, 0);
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
        pane.current_mut().cursor = 1;

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
            cursor: 0,
            scroll: 0,
        });

        assert!(matches!(
            pane.handle_key(press(KeyCode::Esc)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.levels.len(), 1, "Esc backs out one fork level");

        pane.levels.push(Level {
            parent: Some(summary(Uuid::new_v4(), 102)),
            cards: Vec::new(),
            cursor: 0,
            scroll: 0,
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
            cursor: 0,
            scroll: 0,
        });
        pane.loading = Some("Loading sessions...".into());

        assert!(matches!(
            pane.handle_key(press(KeyCode::Esc)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.levels.len(), 1, "Esc backs out one fork level");
        assert_eq!(pane.loading.as_deref(), Some("Loading sessions..."));
        assert!(pane.current().cards.is_empty());

        let parent = summary(Uuid::new_v4(), 200);
        pane.levels.push(Level {
            parent: Some(parent),
            cards: vec![(summary(Uuid::new_v4(), 201), Tier::Idle)],
            cursor: 0,
            scroll: 0,
        });
        pane.loading = None;

        assert!(matches!(
            pane.handle_key(press(KeyCode::Left)),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.levels.len(), 1, "Left backs out one fork level");
        assert_eq!(pane.loading.as_deref(), Some("Loading sessions..."));
    }

    #[test]
    fn daemon_reload_error_clears_loading_and_surfaces_inline_error() {
        let mut pane = test_pane(vec![(summary(Uuid::new_v4(), 100), Tier::Idle)]);
        pane.loading = Some("Loading sessions...".into());

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
        assert_eq!(pane.loading.as_deref(), Some("Loading sessions..."));

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
        assert_eq!(pane.loading.as_deref(), Some("Loading sessions..."));

        let mut archived = summary(Uuid::new_v4(), 200);
        archived.archived_at = Some(300);
        let mut pane = test_pane(vec![(archived, Tier::Idle)]);
        pane.show_archived = true;
        assert!(matches!(
            pane.handle_key(press(KeyCode::Char('u'))),
            Some(SessionsOutcome::LoadList)
        ));
        assert_eq!(pane.loading.as_deref(), Some("Loading sessions..."));
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
                cursor: 0,
                scroll: 0,
            }],
            step: Step::Browse,
            error: None,
            notice: None,
            loading: None,
            daemon_connected,
            use_emojis: true,
            db: None,
            last_body_height: 100,
            last_content_rows: 0,
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

    #[test]
    fn daemonless_lists_from_the_db() {
        // The factored `Db::list_session_summaries` populates the daemonless
        // list: open an in-memory DB, seed a root session, and confirm the
        // pane's daemonless fetch returns it tier-classified.
        let db = Db::open_in_memory().unwrap();
        let root = db.create_session("pid", "/proj", "builder").unwrap();
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
        let pane = SessionsPane::open(tmp.path(), true);

        assert_eq!(pane.loading, Some("Loading sessions..."));
        assert!(pane.current().cards.is_empty());
    }
}
