//! Persistent daemon-backed session rail.
//!
//! Replaces the fullscreen `/sessions` overlay. The rail owns one bounded
//! `ListSessions` projection, one live-status batch, one selected-UUID
//! preview, and one coalesced favorite mutation per canonical lineage root.

mod layout;
mod render;
mod sort;

#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::layout::Rect;
use uuid::Uuid;

use crate::tui::pane_shared::{resolve_project_id, short_id};
use cockpit_proto::{SessionMessage, SessionSummary};

pub use layout::{
    COMPACT_AFFORDANCE_WIDTH, COMPACT_BREAKPOINT, RAIL_MAX_WIDTH, RAIL_MIN_WIDTH, RailLayoutMode,
    WIDE_BREAKPOINT,
};
pub use sort::{Tier, canonical_root, classify, tier_sort};

/// Daemon list cap. The rail never stores more than this many cards.
pub const LIST_LIMIT: usize = 100;
/// Existing preview page size.
pub const PREVIEW_PAGE: u32 = 50;
/// Preview window cap: eight pages of `PREVIEW_PAGE` messages.
pub const PREVIEW_MAX_MESSAGES: usize = PREVIEW_PAGE as usize * 8;
const SKELETON_CARDS: usize = 4;

const DAEMON_UNAVAILABLE_HINT: &str =
    "no daemon — browse only. Start one with `cockpit daemon` to resume or archive.";

/// What the rail asks `App` to do after a key or mouse event.
#[derive(Debug)]
pub enum RailOutcome {
    Unfocus,
    ToggleVisibility,
    NewSession,
    Resume(Uuid),
    LoadList,
    LoadPreview {
        session_id: Uuid,
        before_seq: Option<i64>,
    },
    LoadInbox {
        main_session_id: Uuid,
    },
    Mutate(Box<SessionsMutationEffect>),
    SetFavorite {
        session_id: Uuid,
        favorite: bool,
        canonical_root: Uuid,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionsMutationTarget {
    pub session_id: Uuid,
    pub kind: &'static str,
}

#[derive(Debug)]
pub struct SessionsMutationEffect {
    pub rail_id: Uuid,
    pub operation_id: Uuid,
    pub generation: u64,
    pub attachment_generation: u64,
    pub target: SessionsMutationTarget,
    pub request: cockpit_proto::Request,
}

#[derive(Debug)]
pub struct SessionsMutationCompletion {
    pub rail_id: Uuid,
    pub operation_id: Uuid,
    pub generation: u64,
    pub attachment_generation: u64,
    pub target: SessionsMutationTarget,
    pub response: Result<cockpit_proto::Response, String>,
}

#[derive(Debug, Clone)]
struct PendingSessionsMutation {
    operation_id: Uuid,
    generation: u64,
    attachment_generation: u64,
    target: SessionsMutationTarget,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Project,
    All,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Browse,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ColumnFocus {
    List,
    Search,
    Preview,
}

struct Level {
    parent: Option<SessionSummary>,
    lineage_root: Option<Uuid>,
    cards: Vec<(SessionSummary, Tier)>,
    selected_session_id: Option<Uuid>,
    /// First visible session index in the filtered list (excoc `sidebar_scroll`).
    session_scroll: usize,
}

impl Level {
    fn empty(parent: Option<SessionSummary>) -> Self {
        Self {
            parent,
            lineage_root: None,
            cards: Vec::new(),
            selected_session_id: None,
            session_scroll: 0,
        }
    }

    #[cfg(test)]
    fn with_cards(parent: Option<SessionSummary>, cards: Vec<(SessionSummary, Tier)>) -> Self {
        let mut level = Self::empty(parent);
        level.cards = cards;
        level.restore_selection(None);
        level
    }

    fn restore_selection(&mut self, session_id: Option<Uuid>) {
        let requested_id = session_id.or(self.selected_session_id);
        let index = requested_id.and_then(|id| {
            self.cards
                .iter()
                .position(|(summary, _)| summary.session_id == id)
        });
        self.selected_session_id = index
            .and_then(|index| self.cards.get(index))
            .map(|(summary, _)| summary.session_id)
            .or_else(|| self.cards.first().map(|(summary, _)| summary.session_id));
    }
}

#[derive(Debug, Clone)]
struct PreviewState {
    session_id: Uuid,
    generation: u64,
    attachment_generation: u64,
    messages: Vec<SessionMessage>,
    has_more: bool,
    loading: bool,
    error: Option<String>,
    scroll: usize,
}

impl PreviewState {
    fn new(session_id: Uuid, generation: u64, attachment_generation: u64) -> Self {
        Self {
            session_id,
            generation,
            attachment_generation,
            messages: Vec::new(),
            has_more: false,
            loading: false,
            error: None,
            scroll: 0,
        }
    }

    fn oldest_seq(&self) -> Option<i64> {
        self.messages.first().map(|message| message.seq)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardAction {
    Select,
    Open,
    Favorite,
    Preview,
    Archive,
    Unarchive,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CardHit {
    index: usize,
    rect: Rect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ActionHit {
    index: usize,
    action: CardAction,
    rect: Rect,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RailRequestCounts {
    pub list_started: u32,
    pub list_in_flight: u32,
    pub live_started: u32,
    pub live_in_flight: u32,
    pub preview_started: u32,
    pub preview_in_flight: u32,
    pub favorite_started: u32,
    pub favorite_in_flight: u32,
}

#[derive(Debug, Clone)]
struct FavoriteIntent {
    generation: u64,
    attachment_generation: u64,
    target_session_id: Uuid,
    desired: bool,
    in_flight: bool,
    queued: Option<bool>,
}

/// One generation-fenced rail projection.
pub struct SessionRail {
    rail_id: Uuid,
    project_id: Option<String>,
    scope: Scope,
    show_archived: bool,
    search: String,
    levels: Vec<Level>,
    step: Step,
    error: Option<String>,
    notice: Option<String>,
    loading: bool,
    stale: bool,
    daemon_connected: bool,
    use_emojis: bool,
    focused: bool,
    column_focus: ColumnFocus,
    list_generation: u64,
    attachment_generation: u64,
    preview: Option<PreviewState>,
    pending_list: Option<(u64, u64)>,
    pending_live: Option<(u64, u64)>,
    pending_preview: Option<(u64, u64, Uuid, Option<i64>)>,
    pending_favorites: HashMap<Uuid, FavoriteIntent>,
    pending_mutation: Option<PendingSessionsMutation>,
    last_body_height: usize,
    last_content_rows: usize,
    last_preview_height: usize,
    last_preview_rows: usize,
    last_preview_reached_top: bool,
    last_session_view: usize,
    card_hits: Vec<CardHit>,
    action_hits: Vec<ActionHit>,
    list_area: Option<Rect>,
    preview_area: Option<Rect>,
    search_area: Option<Rect>,
    compact_area: Option<Rect>,
    rail_area: Option<Rect>,
    last_frame_width: u16,
    confirm_buttons: crate::tui::button::ButtonRegistry,
    pointer_capture: bool,
    visible: bool,
    hovered_card: Option<usize>,
    pointer_position: Option<(u16, u16)>,
    toggle_area: Option<Rect>,
    new_session_area: Option<Rect>,
    counts: RailRequestCounts,
}

impl SessionRail {
    pub fn new(
        worktree_root: Option<&std::path::Path>,
        cwd: &std::path::Path,
        daemon_connected: bool,
        use_emojis: bool,
    ) -> Self {
        let project_id = resolve_project_id(worktree_root, cwd);
        let scope = if project_id.is_some() {
            Scope::Project
        } else {
            Scope::All
        };
        Self {
            rail_id: Uuid::new_v4(),
            project_id,
            scope,
            show_archived: false,
            search: String::new(),
            levels: vec![Level::empty(None)],
            step: Step::Browse,
            error: None,
            notice: None,
            loading: daemon_connected,
            stale: false,
            daemon_connected,
            use_emojis,
            focused: false,
            column_focus: ColumnFocus::List,
            list_generation: 0,
            attachment_generation: 1,
            preview: None,
            pending_list: None,
            pending_live: None,
            pending_preview: None,
            pending_favorites: HashMap::new(),
            pending_mutation: None,
            last_body_height: 0,
            last_content_rows: 0,
            last_preview_height: 0,
            last_preview_rows: 0,
            last_preview_reached_top: false,
            last_session_view: 1,
            card_hits: Vec::new(),
            action_hits: Vec::new(),
            list_area: None,
            preview_area: None,
            search_area: None,
            compact_area: None,
            rail_area: None,
            last_frame_width: 0,
            confirm_buttons: crate::tui::button::ButtonRegistry::default(),
            pointer_capture: false,
            visible: true,
            hovered_card: None,
            pointer_position: None,
            toggle_area: None,
            new_session_area: None,
            counts: RailRequestCounts::default(),
        }
    }

    pub fn keybindings() -> crate::tui::keys_overlay::KeyGroup {
        use crate::tui::keys_overlay::{KeyBinding, KeyGroup};
        KeyGroup {
            title: "Sessions",
            bindings: &[
                KeyBinding {
                    key: "Ctrl+J",
                    action: "focus",
                    desc: "focus the session rail",
                },
                KeyBinding {
                    key: "↑/↓",
                    action: "move",
                    desc: "highlight a session",
                },
                KeyBinding {
                    key: "Enter",
                    action: "open",
                    desc: "open the highlighted session",
                },
                KeyBinding {
                    key: "Tab",
                    action: "preview",
                    desc: "focus the selected session preview",
                },
                KeyBinding {
                    key: "Ctrl+N",
                    action: "new session",
                    desc: "start a fresh session",
                },
                KeyBinding {
                    key: "Alt+↑/↓",
                    action: "switch",
                    desc: "resume the previous or next session",
                },
                KeyBinding {
                    key: "Ctrl+B",
                    action: "hide/show",
                    desc: "toggle the session rail",
                },
                KeyBinding {
                    key: "/",
                    action: "search",
                    desc: "search the current projection",
                },
                KeyBinding {
                    key: "→/l",
                    action: "forks",
                    desc: "descend into a session's forks",
                },
                KeyBinding {
                    key: "e",
                    action: "windows",
                    desc: "expand a compaction lineage",
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
                    key: "f",
                    action: "favorite",
                    desc: "toggle the lineage favorite",
                },
                KeyBinding {
                    key: "Esc",
                    action: "composer",
                    desc: "return focus to the composer",
                },
            ],
        }
    }

    pub fn has_unsettled_local_authority(&self) -> bool {
        self.pending_mutation.is_some()
            || self
                .pending_favorites
                .values()
                .any(|intent| intent.in_flight || intent.queued.is_some())
    }

    pub fn is_focused(&self) -> bool {
        self.focused
    }

    pub fn focus(&mut self) {
        self.focused = true;
        if self.column_focus == ColumnFocus::Search {
            return;
        }
        self.column_focus = ColumnFocus::List;
    }

    pub fn focus_search(&mut self) {
        self.focused = true;
        self.column_focus = ColumnFocus::Search;
    }

    pub fn unfocus(&mut self) {
        self.focused = false;
        self.column_focus = ColumnFocus::List;
    }

    pub fn is_search_focused(&self) -> bool {
        self.focused && self.column_focus == ColumnFocus::Search
    }

    pub fn search_query(&self) -> &str {
        &self.search
    }

    pub fn include_archived(&self) -> bool {
        self.show_archived
    }

    pub fn daemon_connected(&self) -> bool {
        self.daemon_connected
    }

    /// Update the daemon link. Returns `true` when the rail transitioned
    /// from connected to disconnected and invalidated in-flight reads.
    pub fn set_daemon_connected(&mut self, connected: bool) -> bool {
        if self.daemon_connected == connected {
            return false;
        }
        self.daemon_connected = connected;
        if !connected {
            self.mark_disconnected();
            true
        } else {
            false
        }
    }

    pub fn set_use_emojis(&mut self, use_emojis: bool) {
        self.use_emojis = use_emojis;
    }

    pub fn set_visible(&mut self, visible: bool) {
        self.visible = visible;
        if !visible {
            self.unfocus();
        }
    }

    pub fn is_visible(&self) -> bool {
        self.visible
    }

    pub fn toggle_visibility(&mut self) -> bool {
        self.set_visible(!self.visible);
        self.visible
    }

    pub fn clear_hover(&mut self) {
        self.hovered_card = None;
        self.pointer_position = None;
    }

    pub fn set_pointer_capture(&mut self, capture: bool) {
        self.pointer_capture = capture;
    }

    /// Drop last-frame pointer geometry. Hit-testing a rail that was not
    /// painted this frame steals hover/clicks from body-owning surfaces
    /// (settings, wizard, overlays) that reuse `Overlay::None`.
    pub fn begin_frame(&mut self) {
        self.card_hits.clear();
        self.action_hits.clear();
        self.list_area = None;
        self.preview_area = None;
        self.search_area = None;
        self.compact_area = None;
        self.rail_area = None;
        self.toggle_area = None;
        self.new_session_area = None;
        self.confirm_buttons.begin_frame(self.pointer_capture, 1);
    }

    pub fn set_project_scope(
        &mut self,
        worktree_root: Option<&std::path::Path>,
        cwd: &std::path::Path,
    ) {
        self.project_id = resolve_project_id(worktree_root, cwd);
        if self.project_id.is_none() {
            self.scope = Scope::All;
        }
    }

    pub fn layout_mode(&self, width: u16) -> RailLayoutMode {
        RailLayoutMode::from_width_and_preference(width, self.visible)
    }

    pub fn rail_area(&self) -> Option<Rect> {
        self.rail_area
    }

    pub fn compact_area(&self) -> Option<Rect> {
        self.compact_area
    }

    pub fn request_counts(&self) -> RailRequestCounts {
        self.counts
    }

    pub fn list_generation(&self) -> u64 {
        self.list_generation
    }

    pub fn attachment_generation(&self) -> u64 {
        self.attachment_generation
    }

    pub fn visible_cards(&self) -> Vec<SessionSummary> {
        self.filtered_cards()
            .into_iter()
            .map(|(summary, _)| summary)
            .collect()
    }

    pub fn selected_id(&self) -> Option<Uuid> {
        let level = self.current();
        let id = level.selected_session_id?;
        self.filtered_cards()
            .into_iter()
            .any(|(summary, _)| summary.session_id == id)
            .then_some(id)
    }

    pub fn selected_session_id_for_action(&self) -> Option<Uuid> {
        self.selected_id()
    }

    pub fn is_loading(&self) -> bool {
        self.loading
    }

    pub fn is_stale(&self) -> bool {
        self.stale
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    pub fn notice(&self) -> Option<&str> {
        self.notice.as_deref()
    }

    pub fn preview_error(&self) -> Option<&str> {
        self.preview.as_ref()?.error.as_deref()
    }

    pub fn preview_session_id(&self) -> Option<Uuid> {
        self.preview.as_ref().map(|preview| preview.session_id)
    }

    pub fn preview_message_count(&self) -> usize {
        self.preview
            .as_ref()
            .map(|preview| preview.messages.len())
            .unwrap_or(0)
    }

    pub fn card_count(&self) -> usize {
        self.current().cards.len()
    }

    pub fn stored_card_bound_ok(&self) -> bool {
        self.current().cards.len() <= LIST_LIMIT
            && self
                .preview
                .as_ref()
                .is_none_or(|preview| preview.messages.len() <= PREVIEW_MAX_MESSAGES)
            && self.counts.list_in_flight <= 1
            && self.counts.live_in_flight <= 1
            && self.counts.preview_in_flight <= 1
    }

    pub fn root_request(&self) -> (Option<String>, Option<Uuid>, Option<Uuid>) {
        let level = self.current();
        if let Some(lineage_root) = level.lineage_root {
            return (None, None, Some(lineage_root));
        }
        if let Some(parent) = &level.parent {
            let fork_parent = parent
                .compaction_lineage_root_id
                .unwrap_or(parent.session_id);
            return (None, Some(fork_parent), None);
        }
        let project_id = match self.scope {
            Scope::Project => self.project_id.clone(),
            Scope::All => None,
        };
        (project_id, None, None)
    }

    /// Begin a replacement list for the current scope. At most one list is
    /// in flight; a newer call replaces the previous generation.
    pub fn begin_list(&mut self) -> bool {
        if !self.daemon_connected {
            self.mark_disconnected();
            return false;
        }
        self.list_generation = self.list_generation.saturating_add(1);
        self.clear_read_pendings();
        self.pending_list = Some((self.list_generation, self.attachment_generation));
        self.counts.list_in_flight = 1;
        if self.current().cards.is_empty() {
            self.loading = true;
        } else {
            self.stale = true;
        }
        self.error = None;
        self.counts.list_started = self.counts.list_started.saturating_add(1);
        true
    }

    pub fn needs_initial_list(&self) -> bool {
        self.daemon_connected
            && self.pending_list.is_none()
            && self.list_generation == 0
            && self.current().cards.is_empty()
    }

    /// Discard every in-flight rail generation. Called on daemon attach
    /// replacement. The App must also abort matching runner actions so a
    /// durable write intent cannot be orphaned from its RPC.
    pub fn discard_for_attachment_change(&mut self) {
        self.attachment_generation = self.attachment_generation.saturating_add(1);
        self.list_generation = 0;
        self.clear_read_pendings();
        self.clear_write_intents();
        self.preview = None;
        self.loading = self.daemon_connected;
        self.stale = false;
        self.levels = vec![Level::empty(None)];
        self.error = None;
    }

    /// Same-session reconnect/resync: bump the attachment fence, drop every
    /// in-flight rail intent (reads and writes), and keep confirmed cards
    /// tagged stale.
    pub fn invalidate_for_reconnect(&mut self) {
        self.attachment_generation = self.attachment_generation.saturating_add(1);
        self.clear_read_pendings();
        self.clear_write_intents();
        if !self.current().cards.is_empty() {
            self.stale = true;
        }
    }

    /// Search/filter changes fence out in-flight projection reads. Favorite
    /// and archive/delete/unarchive writes stay paired with their runner
    /// actions: they are durable mutations, not a projection load.
    pub fn invalidate_for_search(&mut self) {
        self.list_generation = self.list_generation.saturating_add(1);
        self.clear_read_pendings();
    }

    pub fn apply_sessions_result(
        &mut self,
        generation: u64,
        attachment_generation: u64,
        result: Result<Vec<SessionSummary>, String>,
    ) -> Option<Vec<Uuid>> {
        if !self.matches_list_fence(generation, attachment_generation) {
            return None;
        }
        self.pending_list = None;
        self.counts.list_in_flight = 0;
        self.loading = false;
        match result {
            Ok(sessions) => {
                let selected_id = self.selected_id();
                self.error = None;
                self.stale = false;
                let sessions: Vec<_> = sessions.into_iter().take(LIST_LIMIT).collect();
                let ids: Vec<_> = sessions.iter().map(|s| s.session_id).collect();
                let cards = tier_sort(sessions.into_iter().map(|s| (s, None)).collect());
                if let Some(level) = self.levels.last_mut() {
                    level.cards = cards;
                    level.restore_selection(selected_id);
                    if level.selected_session_id.is_some_and(|id| {
                        !level
                            .cards
                            .iter()
                            .any(|(summary, _)| summary.session_id == id)
                    }) {
                        level.selected_session_id = None;
                    }
                    level.session_scroll = 0;
                    self.ensure_session_scroll_shows_selected();
                }
                if self.selected_id() != self.preview.as_ref().map(|preview| preview.session_id) {
                    self.preview = None;
                }
                Some(ids)
            }
            Err(error) => {
                if self.current().cards.is_empty() {
                    self.error = Some(error);
                } else {
                    self.stale = true;
                    self.error = Some(error);
                }
                None
            }
        }
    }

    pub fn begin_live(&mut self, ids: Vec<Uuid>) -> Option<Vec<Uuid>> {
        if self.pending_list.is_some() {
            return None;
        }
        let ids: Vec<_> = ids.into_iter().take(LIST_LIMIT).collect();
        if ids.is_empty() {
            return None;
        }
        self.pending_live = Some((self.list_generation, self.attachment_generation));
        self.counts.live_started = self.counts.live_started.saturating_add(1);
        self.counts.live_in_flight = 1;
        Some(ids)
    }

    pub fn apply_live_status(
        &mut self,
        generation: u64,
        attachment_generation: u64,
        live: Result<HashMap<Uuid, (bool, bool)>, String>,
    ) {
        if self.pending_live != Some((generation, attachment_generation)) {
            return;
        }
        self.pending_live = None;
        self.counts.live_in_flight = 0;
        let Ok(live) = live else {
            return;
        };
        let selected_id = self.current().selected_session_id;
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
            level.restore_selection(selected_id);
        }
    }

    pub fn begin_preview(&mut self, before_seq: Option<i64>) -> Option<(Uuid, Option<i64>)> {
        let session_id = self.selected_id()?;
        if !self.daemon_connected {
            return None;
        }
        if before_seq.is_some()
            && self
                .preview
                .as_ref()
                .is_some_and(|preview| preview.messages.len() >= PREVIEW_MAX_MESSAGES)
        {
            return None;
        }
        let needs_reset = self
            .preview
            .as_ref()
            .map(|preview| preview.session_id != session_id)
            .unwrap_or(true);
        if needs_reset {
            self.preview = Some(PreviewState::new(
                session_id,
                self.list_generation,
                self.attachment_generation,
            ));
        }
        if let Some(preview) = self.preview.as_mut() {
            preview.loading = true;
            preview.error = None;
            preview.generation = self.list_generation;
            preview.attachment_generation = self.attachment_generation;
        }
        self.pending_preview = Some((
            self.list_generation,
            self.attachment_generation,
            session_id,
            before_seq,
        ));
        self.counts.preview_started = self.counts.preview_started.saturating_add(1);
        self.counts.preview_in_flight = 1;
        Some((session_id, before_seq))
    }

    pub fn needs_preview_for_selection(&self) -> bool {
        self.daemon_connected
            && self.selected_id().is_some()
            && self.pending_preview.is_none()
            && self
                .preview
                .as_ref()
                .is_none_or(|preview| Some(preview.session_id) != self.selected_id())
    }

    pub fn apply_preview_result(
        &mut self,
        generation: u64,
        attachment_generation: u64,
        session_id: Uuid,
        before_seq: Option<i64>,
        result: Result<(Vec<SessionMessage>, bool), String>,
    ) {
        if self.pending_preview != Some((generation, attachment_generation, session_id, before_seq))
        {
            return;
        }
        self.pending_preview = None;
        self.counts.preview_in_flight = 0;
        if self.selected_id() != Some(session_id) {
            return;
        }
        if self
            .preview
            .as_ref()
            .map(|preview| {
                preview.session_id != session_id
                    || preview.generation != generation
                    || preview.attachment_generation != attachment_generation
            })
            .unwrap_or(true)
        {
            return;
        }
        let Some(preview) = self.preview.as_mut() else {
            return;
        };
        preview.loading = false;
        match result {
            Ok((messages, has_more)) => {
                preview.error = None;
                if before_seq.is_none() {
                    preview.messages = messages.into_iter().take(PREVIEW_PAGE as usize).collect();
                    preview.scroll = 0;
                    preview.has_more = has_more && preview.messages.len() < PREVIEW_MAX_MESSAGES;
                } else {
                    let existing: HashSet<i64> =
                        preview.messages.iter().map(|message| message.seq).collect();
                    let room = PREVIEW_MAX_MESSAGES.saturating_sub(preview.messages.len());
                    let mut older: Vec<_> = messages
                        .into_iter()
                        .filter(|message| !existing.contains(&message.seq))
                        .take(room)
                        .collect();
                    let filled_window = room == 0 || older.len() == room;
                    older.append(&mut preview.messages);
                    preview.messages = older;
                    preview.has_more =
                        has_more && !filled_window && preview.messages.len() < PREVIEW_MAX_MESSAGES;
                }
            }
            Err(error) => {
                preview.error = Some(error);
            }
        }
    }

    pub fn begin_favorite(
        &mut self,
        session_id: Uuid,
        desired: bool,
    ) -> Option<(Uuid, Uuid, bool)> {
        if !self.daemon_connected {
            self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
            return None;
        }
        let summary = self.card_by_id(session_id)?;
        let canonical_root = canonical_root(summary);
        let generation = self.list_generation;
        let attachment_generation = self.attachment_generation;
        match self.pending_favorites.get_mut(&canonical_root) {
            Some(intent) if intent.in_flight => {
                intent.queued = Some(desired);
                intent.target_session_id = session_id;
                None
            }
            Some(intent) => {
                intent.generation = generation;
                intent.attachment_generation = attachment_generation;
                intent.target_session_id = session_id;
                intent.desired = desired;
                intent.in_flight = true;
                intent.queued = None;
                self.counts.favorite_started = self.counts.favorite_started.saturating_add(1);
                self.counts.favorite_in_flight = self.counts.favorite_in_flight.max(1);
                Some((session_id, canonical_root, desired))
            }
            None => {
                self.pending_favorites.insert(
                    canonical_root,
                    FavoriteIntent {
                        generation,
                        attachment_generation,
                        target_session_id: session_id,
                        desired,
                        in_flight: true,
                        queued: None,
                    },
                );
                self.counts.favorite_started = self.counts.favorite_started.saturating_add(1);
                self.counts.favorite_in_flight = self
                    .pending_favorites
                    .values()
                    .filter(|intent| intent.in_flight)
                    .count() as u32;
                Some((session_id, canonical_root, desired))
            }
        }
    }

    pub fn apply_favorite_result(
        &mut self,
        generation: u64,
        attachment_generation: u64,
        canonical_root: Uuid,
        session_id: Uuid,
        result: Result<(Uuid, bool), String>,
    ) -> Option<(Uuid, Uuid, bool)> {
        let intent = self.pending_favorites.get(&canonical_root).cloned()?;
        if intent.generation != generation
            || intent.attachment_generation != attachment_generation
            || !intent.in_flight
        {
            return None;
        }
        match result {
            Ok((lineage_root_id, favorite)) => {
                if let Some(level) = self.levels.last_mut() {
                    for (summary, _) in &mut level.cards {
                        if sort::canonical_root(summary) == lineage_root_id
                            || summary.session_id == session_id
                        {
                            summary.favorite = favorite;
                        }
                    }
                    let selected = level.selected_session_id;
                    let resorted = tier_sort(
                        level
                            .cards
                            .drain(..)
                            .map(|(summary, _)| (summary, None))
                            .collect(),
                    );
                    level.cards = resorted;
                    level.restore_selection(selected);
                }
            }
            Err(error) => {
                self.notice = Some(format!("favorite failed: {error}"));
            }
        }
        let queued = self
            .pending_favorites
            .get(&canonical_root)
            .and_then(|intent| intent.queued);
        if let Some(desired) = queued
            && let Some(intent) = self.pending_favorites.get_mut(&canonical_root)
        {
            intent.desired = desired;
            intent.queued = None;
            intent.in_flight = true;
            intent.generation = self.list_generation;
            intent.attachment_generation = self.attachment_generation;
            intent.target_session_id = session_id;
            self.counts.favorite_started = self.counts.favorite_started.saturating_add(1);
            Some((session_id, canonical_root, desired))
        } else {
            self.pending_favorites.remove(&canonical_root);
            self.counts.favorite_in_flight = self
                .pending_favorites
                .values()
                .filter(|intent| intent.in_flight)
                .count() as u32;
            None
        }
    }

    pub fn apply_mutation_completion(&mut self, completion: SessionsMutationCompletion) -> bool {
        let Some(pending) = self.pending_mutation.as_ref() else {
            return false;
        };
        if completion.rail_id != self.rail_id
            || completion.operation_id != pending.operation_id
            || completion.generation != pending.generation
            || completion.attachment_generation != pending.attachment_generation
            || completion.target != pending.target
        {
            return false;
        }
        self.pending_mutation = None;
        match completion.response {
            Ok(cockpit_proto::Response::Ack) => {
                self.error = None;
                self.notice = Some(format!("{} committed", completion.target.kind));
                true
            }
            Ok(other) => {
                self.error = Some(format!(
                    "unexpected {} receipt: {other:?}",
                    completion.target.kind
                ));
                false
            }
            Err(error) => {
                self.error = Some(format!("{} failed: {error}", completion.target.kind));
                false
            }
        }
    }

    pub fn apply_inbox_result(
        &mut self,
        main_session_id: Uuid,
        result: Result<Vec<cockpit_proto::AssistantInboxItemWire>, String>,
    ) {
        if self.selected_id() != Some(main_session_id) {
            return;
        }
        self.notice = Some(match result {
            Ok(items) if items.is_empty() => "Assistant inbox is empty.".to_string(),
            Ok(items) => items
                .into_iter()
                .map(|item| {
                    format!(
                        "{} ← {}: {}",
                        item.delivery,
                        short_id(&item.raising_session_id.to_string()),
                        item.summary
                    )
                })
                .collect::<Vec<_>>()
                .join("  •  "),
            Err(error) => format!("Assistant inbox: {error}"),
        });
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<RailOutcome> {
        if !self.focused {
            return None;
        }
        if self.pending_mutation.is_some() {
            self.notice = Some(
                "Waiting for the daemon to settle the session change; the rail cannot close yet."
                    .to_string(),
            );
            return None;
        }
        if matches!(self.step, Step::Confirm { .. }) {
            return self.handle_confirm_key(key);
        }
        if self.column_focus == ColumnFocus::Search {
            return self.handle_search_key(key);
        }
        self.notice = None;
        match key.code {
            KeyCode::Esc => {
                if self.levels.len() > 1 {
                    self.drill_out();
                    self.preview = None;
                    return self.load_list_if_connected();
                }
                self.unfocus();
                Some(RailOutcome::Unfocus)
            }
            KeyCode::Char('/') if !key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.column_focus = ColumnFocus::Search;
                None
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.column_focus = match self.column_focus {
                    ColumnFocus::List => ColumnFocus::Preview,
                    ColumnFocus::Preview | ColumnFocus::Search => ColumnFocus::List,
                };
                None
            }
            KeyCode::Up | KeyCode::Char('k') if self.column_focus == ColumnFocus::Preview => {
                self.scroll_preview_up()
            }
            KeyCode::Down | KeyCode::Char('j') if self.column_focus == ColumnFocus::Preview => {
                self.scroll_preview_down();
                None
            }
            KeyCode::PageUp if self.column_focus == ColumnFocus::Preview => self.page_preview_up(),
            KeyCode::PageDown if self.column_focus == ColumnFocus::Preview => {
                self.page_preview_down();
                None
            }
            KeyCode::Up | KeyCode::Char('k') | KeyCode::PageUp => {
                let delta = if matches!(key.code, KeyCode::PageUp) {
                    -4
                } else {
                    -1
                };
                if self.move_cursor(delta) {
                    return self.preview_for_selection();
                }
                None
            }
            KeyCode::Down | KeyCode::Char('j') | KeyCode::PageDown => {
                let delta = if matches!(key.code, KeyCode::PageDown) {
                    4
                } else {
                    1
                };
                if self.move_cursor(delta) {
                    return self.preview_for_selection();
                }
                None
            }
            KeyCode::Enter => {
                if !self.daemon_connected {
                    self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
                    None
                } else {
                    self.selected_id().map(RailOutcome::Resume)
                }
            }
            KeyCode::Char('i') => {
                if !self.daemon_connected {
                    self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
                    return None;
                }
                match self
                    .selected()
                    .and_then(|session| session.assistant_inbox_latest_source_session_id)
                {
                    Some(source_session_id) => Some(RailOutcome::Resume(source_session_id)),
                    None => {
                        self.notice =
                            Some("No assistant inbox source for this session.".to_string());
                        None
                    }
                }
            }
            KeyCode::Char('n') => {
                if !self.daemon_connected {
                    self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
                    None
                } else if let Some(main_session_id) = self.selected_id() {
                    self.notice = Some("Loading assistant inbox...".to_string());
                    Some(RailOutcome::LoadInbox { main_session_id })
                } else {
                    None
                }
            }
            KeyCode::Right | KeyCode::Char('l') => {
                if self.drill_in() {
                    self.preview = None;
                    return self.load_list_if_connected();
                }
                None
            }
            KeyCode::Char('e') => {
                if self.drill_in_lineage() {
                    self.preview = None;
                    return self.load_list_if_connected();
                }
                None
            }
            KeyCode::Left | KeyCode::Char('h') => {
                if self.drill_out() {
                    self.preview = None;
                    return self.load_list_if_connected();
                }
                None
            }
            KeyCode::Char('p') if self.project_id.is_some() => {
                self.scope = match self.scope {
                    Scope::Project => Scope::All,
                    Scope::All => Scope::Project,
                };
                self.preview = None;
                self.levels = vec![Level::empty(None)];
                self.load_list_if_connected()
            }
            KeyCode::Char('a') => {
                self.show_archived = !self.show_archived;
                self.preview = None;
                self.load_list_if_connected()
            }
            KeyCode::Char('u') => self.unarchive_selected(),
            KeyCode::Char('d') => {
                self.open_confirm();
                None
            }
            KeyCode::Char('f') => self.toggle_selected_favorite(),
            KeyCode::Char('r') if self.error.is_some() => self.load_list_if_connected(),
            _ => None,
        }
    }

    pub fn handle_mouse(&mut self, mouse: MouseEvent) -> Option<RailOutcome> {
        if self.pending_mutation.is_some() {
            self.notice = Some(
                "Waiting for the daemon to settle the session change; controls are disabled."
                    .to_string(),
            );
            return None;
        }
        if matches!(self.step, Step::Confirm { .. })
            && matches!(
                mouse.kind,
                MouseEventKind::Moved
                    | MouseEventKind::Down(MouseButton::Left)
                    | MouseEventKind::Up(MouseButton::Left)
            )
            && let Some(outcome) = self.confirm_buttons.handle_mouse(mouse)
        {
            if let crate::tui::button::ButtonPointerOutcome::Activated(dispatch) = outcome {
                return self.pointer_activate_confirm(dispatch);
            }
            return None;
        }
        if matches!(mouse.kind, MouseEventKind::Moved) {
            self.pointer_position = Some((mouse.column, mouse.row));
            self.hovered_card = hit_card(&self.card_hits, mouse.column, mouse.row);
        }
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && self
                .toggle_area
                .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
        {
            return Some(RailOutcome::ToggleVisibility);
        }
        if matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
            && self
                .new_session_area
                .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
        {
            return Some(RailOutcome::NewSession);
        }
        if let Some(compact) = self.compact_area
            && point_in_rect(compact, mouse.column, mouse.row)
            && matches!(mouse.kind, MouseEventKind::Down(MouseButton::Left))
        {
            self.focus_search();
            return None;
        }
        match mouse.kind {
            MouseEventKind::ScrollUp => {
                if self
                    .preview_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.column_focus = ColumnFocus::Preview;
                    self.focus();
                    return self.scroll_preview_up();
                }
                if self
                    .list_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus();
                    self.column_focus = ColumnFocus::List;
                    self.scroll_up();
                }
                None
            }
            MouseEventKind::ScrollDown => {
                if self
                    .preview_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.column_focus = ColumnFocus::Preview;
                    self.focus();
                    self.scroll_preview_down();
                } else if self
                    .list_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus();
                    self.column_focus = ColumnFocus::List;
                    self.scroll_down();
                }
                None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                if self
                    .search_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus_search();
                    return None;
                }
                if self
                    .preview_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus();
                    self.column_focus = ColumnFocus::Preview;
                    return None;
                }
                if let Some(action) = hit_action(&self.action_hits, mouse.column, mouse.row) {
                    self.focus();
                    self.column_focus = ColumnFocus::List;
                    return self.activate_card_action(action.0, action.1);
                }
                if let Some(index) = hit_card(&self.card_hits, mouse.column, mouse.row) {
                    self.focus();
                    self.column_focus = ColumnFocus::List;
                    if let Some((summary, _)) = self.filtered_cards().get(index)
                        && let Some(level) = self.levels.last_mut()
                    {
                        level.selected_session_id = Some(summary.session_id);
                    }
                    self.ensure_session_scroll_shows_selected();
                    return self.preview_for_selection();
                }
                if self
                    .rail_area
                    .is_some_and(|rect| point_in_rect(rect, mouse.column, mouse.row))
                {
                    self.focus();
                }
                None
            }
            _ => None,
        }
    }

    pub(crate) fn pointer_activate_confirm(
        &mut self,
        dispatch: crate::tui::button::ButtonDispatch,
    ) -> Option<RailOutcome> {
        let choice = match dispatch {
            crate::tui::button::ButtonDispatch::SessionsConfirmArchive => ConfirmChoice::Archive,
            crate::tui::button::ButtonDispatch::SessionsConfirmDelete => ConfirmChoice::Delete,
            crate::tui::button::ButtonDispatch::SessionsConfirmCancel => ConfirmChoice::Cancel,
            _ => return None,
        };
        if let Step::Confirm { session_id, .. } = self.step {
            return self.apply_confirm(session_id, choice);
        }
        None
    }

    fn activate_card_action(&mut self, index: usize, action: CardAction) -> Option<RailOutcome> {
        let (summary, _) = self.filtered_cards().get(index).cloned()?;
        if let Some(level) = self.levels.last_mut() {
            level.selected_session_id = Some(summary.session_id);
        }
        self.ensure_session_scroll_shows_selected();
        match action {
            CardAction::Select => self.preview_for_selection(),
            CardAction::Open => {
                if !self.daemon_connected {
                    self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
                    None
                } else {
                    Some(RailOutcome::Resume(summary.session_id))
                }
            }
            CardAction::Favorite => self
                .begin_favorite(summary.session_id, !summary.favorite)
                .map(
                    |(session_id, canonical_root, favorite)| RailOutcome::SetFavorite {
                        session_id,
                        favorite,
                        canonical_root,
                    },
                ),
            CardAction::Preview => self.preview_for_selection(),
            CardAction::Archive => self.archive_selected(),
            CardAction::Delete => {
                self.open_confirm();
                None
            }
            CardAction::Unarchive => self.unarchive_selected(),
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) -> Option<RailOutcome> {
        match key.code {
            KeyCode::Esc => {
                if !self.search.is_empty() {
                    self.search.clear();
                    self.restore_selection_after_filter();
                    None
                } else {
                    self.column_focus = ColumnFocus::List;
                    None
                }
            }
            KeyCode::Enter => {
                self.column_focus = ColumnFocus::List;
                self.selected_id()
                    .filter(|_| self.daemon_connected)
                    .map(RailOutcome::Resume)
            }
            KeyCode::Backspace => {
                self.search.pop();
                self.restore_selection_after_filter();
                None
            }
            KeyCode::Char(ch)
                if !key.modifiers.contains(KeyModifiers::CONTROL) && !ch.is_control() =>
            {
                self.search.push(ch);
                self.restore_selection_after_filter();
                None
            }
            KeyCode::Up => {
                self.column_focus = ColumnFocus::List;
                let _ = self.move_cursor(-1);
                None
            }
            KeyCode::Down => {
                self.column_focus = ColumnFocus::List;
                let _ = self.move_cursor(1);
                None
            }
            _ => None,
        }
    }

    fn restore_selection_after_filter(&mut self) {
        self.invalidate_for_search();
        let selected = self.current().selected_session_id;
        if let Some(level) = self.levels.last_mut() {
            level.restore_selection(selected);
        }
        self.ensure_session_scroll_shows_selected();
        if self.selected_id() != self.preview.as_ref().map(|preview| preview.session_id) {
            self.preview = None;
        }
    }

    fn matches_list_fence(&self, generation: u64, attachment_generation: u64) -> bool {
        self.pending_list == Some((generation, attachment_generation))
    }

    fn current(&self) -> &Level {
        self.levels.last().expect("at least the root level")
    }

    fn current_mut(&mut self) -> &mut Level {
        self.levels.last_mut().expect("at least the root level")
    }

    fn selected(&self) -> Option<&SessionSummary> {
        let id = self.selected_id()?;
        self.current()
            .cards
            .iter()
            .find(|(summary, _)| summary.session_id == id)
            .map(|(summary, _)| summary)
    }

    fn card_by_id(&self, session_id: Uuid) -> Option<&SessionSummary> {
        self.current()
            .cards
            .iter()
            .find(|(summary, _)| summary.session_id == session_id)
            .map(|(summary, _)| summary)
    }

    fn filtered_cards(&self) -> Vec<(SessionSummary, Tier)> {
        let query = self.search.trim().to_ascii_lowercase();
        self.current()
            .cards
            .iter()
            .filter(|(summary, _)| query.is_empty() || card_matches(summary, &query))
            .cloned()
            .collect()
    }

    fn mark_disconnected(&mut self) {
        self.daemon_connected = false;
        self.loading = false;
        if self.current().cards.is_empty() {
            self.error = Some("Unavailable — reconnect to the daemon, then Retry".to_string());
        } else {
            self.stale = true;
        }
        // Fence projection reads. Keep in-flight write intents (favorite and
        // archive/delete/unarchive) paired with their runner actions so a
        // late receipt can settle and exit stays guarded until that durable
        // write completes.
        self.attachment_generation = self.attachment_generation.saturating_add(1);
        self.clear_read_pendings();
    }

    fn clear_read_pendings(&mut self) {
        self.pending_list = None;
        self.pending_live = None;
        self.pending_preview = None;
        self.counts.list_in_flight = 0;
        self.counts.live_in_flight = 0;
        self.counts.preview_in_flight = 0;
    }

    fn clear_favorite_intents(&mut self) {
        self.pending_favorites.clear();
        self.counts.favorite_in_flight = 0;
    }

    fn clear_write_intents(&mut self) {
        self.clear_favorite_intents();
        self.pending_mutation = None;
    }

    fn load_list_if_connected(&mut self) -> Option<RailOutcome> {
        if self.daemon_connected {
            Some(RailOutcome::LoadList)
        } else {
            self.mark_disconnected();
            None
        }
    }

    fn preview_for_selection(&mut self) -> Option<RailOutcome> {
        self.begin_preview(None)
            .map(|(session_id, before_seq)| RailOutcome::LoadPreview {
                session_id,
                before_seq,
            })
    }

    fn toggle_selected_favorite(&mut self) -> Option<RailOutcome> {
        let summary = self.selected()?.clone();
        self.begin_favorite(summary.session_id, !summary.favorite)
            .map(
                |(session_id, canonical_root, favorite)| RailOutcome::SetFavorite {
                    session_id,
                    favorite,
                    canonical_root,
                },
            )
    }

    fn move_cursor(&mut self, delta: isize) -> bool {
        let cards = self.filtered_cards();
        if cards.is_empty() {
            return false;
        }
        let current_id = self.current().selected_session_id;
        let prev = current_id
            .and_then(|id| {
                cards
                    .iter()
                    .position(|(summary, _)| summary.session_id == id)
            })
            .unwrap_or(0);
        let next = if delta < 0 {
            let steps = (-delta) as usize;
            let mut idx = prev;
            for _ in 0..steps {
                idx = crate::tui::nav::wrap_prev(idx, cards.len());
            }
            idx
        } else {
            let steps = delta as usize;
            let mut idx = prev;
            for _ in 0..steps {
                idx = crate::tui::nav::wrap_next(idx, cards.len());
            }
            idx
        };
        if let Some(level) = self.levels.last_mut() {
            level.selected_session_id = Some(cards[next].0.session_id);
        }
        if next != prev {
            self.ensure_session_scroll_shows_selected();
        }
        next != prev
    }

    fn drill_in(&mut self) -> bool {
        let Some(parent) = self.selected().cloned() else {
            return false;
        };
        if parent.fork_count == 0 {
            return false;
        }
        self.loading = self.daemon_connected;
        self.levels.push(Level::empty(Some(parent)));
        true
    }

    fn drill_in_lineage(&mut self) -> bool {
        let Some(selected) = self.selected().cloned() else {
            return false;
        };
        if selected.lineage_window_count <= 1 {
            return false;
        }
        let lineage_root = selected
            .compaction_lineage_root_id
            .unwrap_or(selected.session_id);
        let mut level = Level::empty(Some(selected));
        level.lineage_root = Some(lineage_root);
        self.loading = self.daemon_connected;
        self.levels.push(level);
        true
    }

    fn drill_out(&mut self) -> bool {
        if self.levels.len() > 1 {
            self.levels.pop();
            true
        } else {
            false
        }
    }

    fn open_confirm(&mut self) {
        if !self.daemon_connected {
            self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
            return;
        }
        let live = self.selected().is_some_and(|summary| {
            self.current()
                .cards
                .iter()
                .find(|(s, _)| s.session_id == summary.session_id)
                .is_some_and(|(_, status)| status.is_live())
        });
        let Some(s) = self.selected().cloned() else {
            return;
        };
        let descendants = s.descendant_count;
        let label = card_description(&s);
        self.step = Step::Confirm {
            session_id: s.session_id,
            label,
            descendants,
            live,
            choice: ConfirmChoice::Cancel,
        };
    }

    fn handle_confirm_key(&mut self, key: KeyEvent) -> Option<RailOutcome> {
        let Step::Confirm {
            session_id, choice, ..
        } = &mut self.step
        else {
            return None;
        };
        let session_id = *session_id;
        match key.code {
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

    fn apply_confirm(&mut self, session_id: Uuid, choice: ConfirmChoice) -> Option<RailOutcome> {
        use cockpit_proto::Request;
        let req = match choice {
            ConfirmChoice::Cancel => {
                self.step = Step::Browse;
                return None;
            }
            ConfirmChoice::Archive => Request::ArchiveSession {
                session_id,
                cascade: true,
            },
            ConfirmChoice::Delete => Request::DeleteSession { session_id },
        };
        self.step = Step::Browse;
        self.error = None;
        let kind = match choice {
            ConfirmChoice::Archive => "archive",
            ConfirmChoice::Delete => "delete",
            ConfirmChoice::Cancel => unreachable!("cancel returned before request construction"),
        };
        Some(RailOutcome::Mutate(Box::new(
            self.begin_mutation(session_id, kind, req),
        )))
    }

    fn unarchive_selected(&mut self) -> Option<RailOutcome> {
        if !self.daemon_connected {
            self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
            return None;
        }
        let s = self.selected()?.clone();
        s.archived_at_unix_ms?;
        self.error = None;
        Some(RailOutcome::Mutate(Box::new(self.begin_mutation(
            s.session_id,
            "unarchive",
            cockpit_proto::Request::UnarchiveSession {
                session_id: s.session_id,
            },
        ))))
    }

    fn begin_mutation(
        &mut self,
        session_id: Uuid,
        kind: &'static str,
        request: cockpit_proto::Request,
    ) -> SessionsMutationEffect {
        let operation_id = Uuid::new_v4();
        let generation = self.list_generation;
        let attachment_generation = self.attachment_generation;
        let target = SessionsMutationTarget { session_id, kind };
        self.pending_mutation = Some(PendingSessionsMutation {
            operation_id,
            generation,
            attachment_generation,
            target: target.clone(),
        });
        self.notice = Some(format!("{kind} pending…"));
        SessionsMutationEffect {
            rail_id: self.rail_id,
            operation_id,
            generation,
            attachment_generation,
            target,
            request,
        }
    }

    fn scroll_up(&mut self) {
        let level = self.current_mut();
        level.session_scroll = level.session_scroll.saturating_sub(1);
    }

    fn scroll_down(&mut self) {
        let cards = self.filtered_cards().len();
        let view = self.last_session_view.max(1);
        let max = cards.saturating_sub(view);
        let level = self.current_mut();
        level.session_scroll = (level.session_scroll + 1).min(max);
    }

    /// Keep the selected session inside the sidebar window after a selection change.
    fn ensure_session_scroll_shows_selected(&mut self) {
        let cards = self.filtered_cards();
        let selected_id = self.current().selected_session_id;
        let pos = selected_id.and_then(|id| {
            cards
                .iter()
                .position(|(summary, _)| summary.session_id == id)
        });
        let Some(pos) = pos else {
            return;
        };
        let view = self.last_session_view.max(1);
        let level = self.current_mut();
        if pos < level.session_scroll {
            level.session_scroll = pos;
        } else if pos >= level.session_scroll + view {
            level.session_scroll = pos + 1 - view;
        }
    }

    #[cfg(test)]
    pub(crate) fn session_scroll_for_test(&self) -> usize {
        self.current().session_scroll
    }

    #[cfg(test)]
    pub(crate) fn session_viewport_for_test(&self) -> usize {
        self.last_session_view
    }

    #[cfg(test)]
    pub(crate) fn list_area_for_test(&self) -> Option<Rect> {
        self.list_area
    }

    fn archive_selected(&mut self) -> Option<RailOutcome> {
        if !self.daemon_connected {
            self.notice = Some(DAEMON_UNAVAILABLE_HINT.to_string());
            return None;
        }
        let s = self.selected()?.clone();
        self.error = None;
        Some(RailOutcome::Mutate(Box::new(self.begin_mutation(
            s.session_id,
            "archive",
            cockpit_proto::Request::ArchiveSession {
                session_id: s.session_id,
                cascade: true,
            },
        ))))
    }

    fn scroll_preview_up(&mut self) -> Option<RailOutcome> {
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
            if let Some((_session_id, before_seq)) = request {
                return self
                    .begin_preview(Some(before_seq))
                    .map(|(session_id, before_seq)| RailOutcome::LoadPreview {
                        session_id,
                        before_seq,
                    });
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

    fn page_preview_up(&mut self) -> Option<RailOutcome> {
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
}

fn card_matches(summary: &SessionSummary, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let title = summary.title.as_deref().unwrap_or("");
    let description = summary.description.as_deref().unwrap_or("");
    let short = summary.short_id.as_deref().unwrap_or("");
    title.to_ascii_lowercase().contains(query)
        || description.to_ascii_lowercase().contains(query)
        || short.to_ascii_lowercase().contains(query)
        || summary
            .session_id
            .to_string()
            .to_ascii_lowercase()
            .contains(query)
}

pub fn card_description(s: &SessionSummary) -> String {
    let title = if let Some(t) = &s.title
        && !t.trim().is_empty()
    {
        t.clone()
    } else if let Some(sid) = &s.short_id
        && !sid.is_empty()
    {
        sid.clone()
    } else {
        short_id(&s.session_id.to_string())
    };
    match s
        .description
        .as_deref()
        .filter(|description| !description.is_empty())
    {
        Some(description) => format!("{title} — {description}"),
        None => title,
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

fn hit_action(hits: &[ActionHit], col: u16, row: u16) -> Option<(usize, CardAction)> {
    hits.iter()
        .find(|hit| point_in_rect(hit.rect, col, row))
        .map(|hit| (hit.index, hit.action))
}

/// Named capability-parity rows. Each SessionsPane operation maps to one
/// rail action or retained confirmation surface and a named behavioral test.
#[derive(Debug, Clone, Copy)]
pub struct CapabilityParityRow {
    pub operation: &'static str,
    pub surface: &'static str,
    pub proof: &'static str,
}

/// Named capability-parity rows. Each SessionsPane operation maps to one
/// rail action or retained confirmation surface.
pub fn capability_parity_table() -> &'static [CapabilityParityRow] {
    &[
        CapabilityParityRow {
            operation: "project/all scope",
            surface: "rail scope toggle (p)",
            proof: "list_scopes_send_existing_request_shapes",
        },
        CapabilityParityRow {
            operation: "root list",
            surface: "rail root ListSessions",
            proof: "list_scopes_send_existing_request_shapes",
        },
        CapabilityParityRow {
            operation: "fork drill-in",
            surface: "rail →/l LoadList parent_session_id",
            proof: "fork_and_lineage_are_named_rail_actions",
        },
        CapabilityParityRow {
            operation: "compaction lineage",
            surface: "rail e LoadList compaction_lineage_root_id",
            proof: "fork_and_lineage_are_named_rail_actions",
        },
        CapabilityParityRow {
            operation: "active/archived filter",
            surface: "rail a include_archived",
            proof: "archived_filter_reloads_list",
        },
        CapabilityParityRow {
            operation: "search/clear",
            surface: "rail / search field + Esc clear",
            proof: "slash_starts_search_while_focused",
        },
        CapabilityParityRow {
            operation: "selected preview pagination",
            surface: "rail preview 50-message page",
            proof: "preview_pagination_is_fenced_and_capped",
        },
        CapabilityParityRow {
            operation: "resume",
            surface: "rail Enter / Open hit",
            proof: "enter_resumes_selected_session",
        },
        CapabilityParityRow {
            operation: "fork",
            surface: "rail fork drill-in",
            proof: "fork_and_lineage_are_named_rail_actions",
        },
        CapabilityParityRow {
            operation: "compaction drill-in",
            surface: "rail e",
            proof: "fork_and_lineage_are_named_rail_actions",
        },
        CapabilityParityRow {
            operation: "attention/unread/live",
            surface: "rail card metadata from summary",
            proof: "cards_render_only_daemon_confirmed_fields",
        },
        CapabilityParityRow {
            operation: "favorite",
            surface: "rail f / Favorite hit SetSessionFavorite",
            proof: "open_hit_resumes_and_favorite_hit_does_not",
        },
        CapabilityParityRow {
            operation: "archive",
            surface: "rail d confirm ArchiveSession cascade",
            proof: "archive_and_delete_use_cascade_confirm",
        },
        CapabilityParityRow {
            operation: "unarchive",
            surface: "rail u UnarchiveSession",
            proof: "unarchive_is_a_named_rail_action",
        },
        CapabilityParityRow {
            operation: "delete",
            surface: "rail d confirm DeleteSession",
            proof: "archive_and_delete_use_cascade_confirm",
        },
        CapabilityParityRow {
            operation: "inbox source",
            surface: "rail i resume source session",
            proof: "inbox_source_resumes_source_session",
        },
        CapabilityParityRow {
            operation: "assistant inbox",
            surface: "rail n ReadAssistantInbox",
            proof: "assistant_inbox_loads_inbox",
        },
        CapabilityParityRow {
            operation: "mouse confirm",
            surface: "rail confirm button pointer path",
            proof: "mouse_confirm_archive_dispatches_existing_mutation",
        },
    ]
}
