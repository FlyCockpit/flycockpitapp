//! Pinned-messages TUI integration (`pinned-messages`): the `/pin`
//! pick-a-message mode, the `/pins` review mode, the mouse `[pin]|[unpin]`
//! control's toggle, and the below-input count indicator's data source.
//!
//! Pins are pure DB state the TUI owns directly via [`crate::db::Db`]
//! (`open_default`, same pattern as `/sessions` + `/export`). Nothing here
//! ever enters the outbound model prompt (token economy, priority #2).

use crate::db::Db;
use crate::tui::history::HistoryEntry;

use crate::tui::pins_overlay::{CopyPick, ForkPick, PinPick, PinsReview};
use std::collections::HashSet;

use super::{App, ToastKind};

#[cfg(test)]
thread_local! {
    static PIN_REFRESH_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_pin_refresh_call_count() {
    PIN_REFRESH_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn pin_refresh_call_count() -> usize {
    PIN_REFRESH_CALLS.with(std::cell::Cell::get)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CopyShape {
    Message,
    CodeBlock,
}

impl App {
    /// Transient info toast for a pin action.
    fn pin_toast(&mut self, text: impl Into<String>) {
        self.show_toast(text, ToastKind::Info);
    }

    /// Open the global DB for a pin operation. `None` (with a transcript
    /// note) when the DB can't be opened — pins degrade gracefully rather
    /// than crash the TUI.
    fn pins_db(&mut self) -> Option<Db> {
        match Db::open_default() {
            Ok(db) => Some(db),
            Err(e) => {
                self.push_plain(format!("pins: database unavailable ({e})"));
                None
            }
        }
    }

    /// Refresh pin state from the DB when the active session has changed
    /// since the last refresh (eager attach, `/new`, `/compact`, resume).
    /// Cheap no-op on the common per-tick path where the session is
    /// unchanged. Called once per event-loop iteration.
    pub(super) fn sync_pin_count(&mut self) {
        let sid = self.current_session_id();
        if sid == self.pin_count_session && sid == self.pinned_seqs_session {
            return;
        }
        self.refresh_pin_count();
    }

    /// Re-read this session's pin count and seq set from the DB into TUI
    /// state. Best-effort: a DB error clears the render cache for this
    /// session so stale `[unpin]` chrome is not reused. Called after every
    /// pin/unpin and on attach.
    pub(super) fn refresh_pin_count(&mut self) {
        #[cfg(test)]
        PIN_REFRESH_CALLS.with(|calls| calls.set(calls.get() + 1));

        let Some(sid) = self.current_session_id() else {
            self.pin_count = 0;
            self.pin_count_session = None;
            self.pinned_seqs_cache.clear();
            self.pinned_seqs_session = None;
            return;
        };
        match Db::open_default() {
            Ok(db) => self.refresh_pin_state_from_db(sid, &db),
            Err(_) => {
                self.pin_count_session = Some(sid);
                self.pinned_seqs_session = Some(sid);
                self.pinned_seqs_cache.clear();
            }
        }
    }

    fn refresh_pin_state_from_db(&mut self, sid: uuid::Uuid, db: &Db) {
        self.pin_count_session = Some(sid);
        self.pinned_seqs_session = Some(sid);
        if let Ok(n) = db.count_pins(sid) {
            self.pin_count = n.max(0) as usize;
        }
        self.pinned_seqs_cache = db
            .list_pin_seqs(sid)
            .map(|seqs| seqs.into_iter().collect())
            .unwrap_or_else(|_| HashSet::new());
    }

    /// Whether a history entry is a pinnable message with a resolved
    /// `seq` (a user or assistant message that has been recorded to the
    /// timeline). Returns its `seq` when pinnable.
    pub(super) fn entry_pin_seq(entry: &HistoryEntry) -> Option<i64> {
        match entry {
            HistoryEntry::User { seq, .. } | HistoryEntry::Agent { seq, .. } => *seq,
            _ => None,
        }
    }

    /// Whether a seq is pinned according to the render cache for the current
    /// session. Pure over App state: render never opens the DB.
    pub(super) fn is_seq_pinned_for_render(&self, seq: i64) -> bool {
        self.pinned_seqs_session == self.current_session_id()
            && self.pinned_seqs_cache.contains(&seq)
    }

    /// The pinnable message `seq` whose mouse `[pin]`/`[unpin]` control
    /// covers chat-area-relative row `row` + column `col`, or `None`
    /// (`pinned-messages`). The control rides the message's own first line
    /// (inline, left of the timestamp) / user-bubble top-right corner, so a
    /// click registers only inside the recorded `[col_start, col_end)`
    /// range — a click on the same row but just outside the glyphs is a
    /// no-op. Pure over `chat_row_meta`; the mouse handler routes the
    /// returned seq into `toggle_pin_for_seq`.
    pub(super) fn pin_seq_at(&self, row: usize, col: u16) -> Option<i64> {
        let hit = self.chat_row_meta.get(row).and_then(|meta| meta.pin_hit)?;
        (col >= hit.col_start && col < hit.col_end).then_some(hit.seq)
    }

    /// History indices of pinnable messages (User/Agent with a resolved
    /// `seq`), in transcript order. The candidate set for `/pin` pick-mode.
    pub(super) fn pinnable_indices(&self) -> Vec<usize> {
        self.history
            .iter()
            .enumerate()
            .filter(|(_, e)| Self::entry_pin_seq(e).is_some())
            .map(|(i, _)| i)
            .collect()
    }

    /// Toggle the pin state of the message at `seq` (the mouse control + a
    /// pick-mode confirm both route here). Refreshes the count and, when a
    /// review is open, its list. A toast surfaces the new state.
    pub(super) fn toggle_pin_for_seq(&mut self, seq: i64) {
        let Some(sid) = self.current_session_id() else {
            self.pin_toast("pins: no active session".to_string());
            return;
        };
        let Some(db) = self.pins_db() else { return };
        match db.toggle_pin(sid, seq) {
            Ok(now_pinned) => {
                self.pin_toast(if now_pinned {
                    "pinned".to_string()
                } else {
                    "unpinned".to_string()
                });
            }
            Err(e) => {
                self.pin_toast(format!("pin: {e}"));
                return;
            }
        }
        self.refresh_pin_count();
        // Keep an open review in sync if the toggle unpinned a listed item.
        if let Some(review) = self.pins_review.as_mut()
            && review.remove_seq_if_present(seq)
        {
            self.pins_review = None;
        }
    }

    /// `/pin` — enter pick-a-message mode. Unfocuses the composer and
    /// selects the most recently completed message; an arrow on the left of
    /// the transcript marks it. No-op note when there's nothing pinnable.
    pub(super) fn enter_pin_pick_mode(&mut self) {
        // A modal pane / dialog owns the screen — don't stack pin mode on
        // top of it.
        if self.any_overlay_open() {
            return;
        }
        match PinPick::enter(self.pinnable_indices()) {
            Some(pick) => {
                self.pins_review = None;
                self.copy_pick = None;
                self.fork_pick = None;
                self.pin_pick = Some(pick);
                self.scroll_pick_into_view();
            }
            None => {
                self.push_plain("/pin: no message to pin yet".to_string());
            }
        }
    }

    /// `/pins` — enter review mode over the session's pinned messages
    /// (rendered as a checklist with jump navigation). No-op note when the
    /// session has no pins.
    pub(super) fn enter_pins_review_mode(&mut self) {
        if self.any_overlay_open() {
            return;
        }
        let Some(sid) = self.current_session_id() else {
            self.push_plain("/pins: no active session".to_string());
            return;
        };
        let Some(db) = self.pins_db() else { return };
        let pins = match db.list_pins_with_text(sid) {
            Ok(p) => p,
            Err(e) => {
                self.push_plain(format!("/pins: {e}"));
                return;
            }
        };
        match PinsReview::enter(pins) {
            Some(review) => {
                self.pin_pick = None;
                self.fork_pick = None;
                self.copy_pick = None;
                self.pins_review = Some(review);
                self.scroll_review_selection_into_view();
            }
            None => {
                self.push_plain("/pins: no pinned messages".to_string());
            }
        }
    }

    /// Exit pick mode without pinning (esc); refocuses the composer (the
    /// composer is focused whenever no overlay holds it).
    pub(super) fn cancel_pin_pick(&mut self) {
        self.pin_pick = None;
    }

    /// `/fork` — enter pick-a-message mode. The selected message's durable
    /// seq becomes the fork point when confirmed.
    pub(super) fn enter_fork_pick_mode(&mut self) {
        if self.any_overlay_open() {
            return;
        }
        match ForkPick::enter(self.pinnable_indices()) {
            Some(pick) => {
                self.pins_review = None;
                self.pin_pick = None;
                self.copy_pick = None;
                self.fork_pick = Some(pick);
                self.scroll_fork_pick_into_view();
            }
            None => {
                self.push_plain("/fork: no message to fork from".to_string());
            }
        }
    }

    pub(super) fn cancel_fork_pick(&mut self) {
        self.fork_pick = None;
    }

    pub(super) fn fork_pick_up(&mut self) {
        if let Some(pick) = self.fork_pick.as_mut() {
            pick.up();
        }
        self.scroll_fork_pick_into_view();
    }

    pub(super) fn fork_pick_down(&mut self) {
        if let Some(pick) = self.fork_pick.as_mut() {
            pick.down();
        }
        self.scroll_fork_pick_into_view();
    }

    pub(super) fn confirm_fork_pick(&mut self) {
        let Some(pick) = self.fork_pick.take() else {
            return;
        };
        let idx = pick.selected_history_index();
        let Some(seq) = self.history.get(idx).and_then(Self::entry_pin_seq) else {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: message is not recorded yet".to_string(),
            });
            return;
        };
        let seed_composer = match self.history.get(idx) {
            Some(HistoryEntry::User { text, .. }) => Some(text.clone()),
            _ => None,
        };
        let (parent_session_id, socket) = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => (runner.session_id, runner.socket.clone()),
            _ => {
                self.history.push(HistoryEntry::CommandError {
                    line: "/fork: no active session to fork from".to_string(),
                });
                return;
            }
        };

        self.push_plain("/fork: pending".to_string());
        self.async_actions.start_blocking(
            super::AsyncActionKind::DaemonRpc("fork.create"),
            super::AsyncActionPolicy::Replace(super::AsyncActionKey::new("fork.create")),
            move || {
                let fork_point_turn_id = Some(seq.to_string());
                let (session_id, short_id) = super::agent_runner::fork_session_blocking(
                    &socket,
                    parent_session_id,
                    fork_point_turn_id,
                    false,
                )?;
                Ok(super::AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    socket,
                    session_id,
                    short_id,
                    seed_composer,
                })
            },
        );
    }

    /// Pin the message under the pick-mode arrow (enter) and exit the mode.
    pub(super) fn confirm_pin_pick(&mut self) {
        let Some(pick) = self.pin_pick.take() else {
            return;
        };
        let idx = pick.selected_history_index();
        let seq = self.history.get(idx).and_then(Self::entry_pin_seq);
        match seq {
            Some(seq) => {
                let Some(sid) = self.current_session_id() else {
                    return;
                };
                if let Some(db) = self.pins_db() {
                    match db.pin_message(sid, seq) {
                        Ok(true) => self.pin_toast("pinned".to_string()),
                        Ok(false) => self.pin_toast("already pinned".to_string()),
                        Err(e) => self.pin_toast(format!("pin: {e}")),
                    }
                    self.refresh_pin_count();
                }
            }
            None => {
                self.pin_toast("pin: message not yet recorded".to_string());
            }
        }
    }

    /// Move the pick arrow toward older messages and scroll it into view.
    pub(super) fn pin_pick_up(&mut self) {
        if let Some(pick) = self.pin_pick.as_mut() {
            pick.up();
        }
        self.scroll_pick_into_view();
    }

    /// Move the pick arrow toward newer messages and scroll it into view.
    pub(super) fn pin_pick_down(&mut self) {
        if let Some(pick) = self.pin_pick.as_mut() {
            pick.down();
        }
        self.scroll_pick_into_view();
    }

    /// Move the review cursor up and jump the transcript to that pin.
    pub(super) fn pins_review_up(&mut self) {
        if let Some(review) = self.pins_review.as_mut() {
            review.up();
        }
        self.scroll_review_selection_into_view();
    }

    /// Move the review cursor down and jump the transcript to that pin.
    pub(super) fn pins_review_down(&mut self) {
        if let Some(review) = self.pins_review.as_mut() {
            review.down();
        }
        self.scroll_review_selection_into_view();
    }

    /// Unpin the highlighted review item (`d` or checking it — both are the
    /// same unpin path). Closes the mode when the last pin is removed.
    pub(super) fn pins_review_unpin_selected(&mut self) {
        let Some(seq) = self
            .pins_review
            .as_ref()
            .and_then(|r| r.selected())
            .map(|p| p.seq)
        else {
            return;
        };
        let Some(sid) = self.current_session_id() else {
            return;
        };
        if let Some(db) = self.pins_db() {
            if let Err(e) = db.unpin_message(sid, seq) {
                self.pin_toast(format!("unpin: {e}"));
                return;
            }
            self.refresh_pin_count();
        }
        if let Some(review) = self.pins_review.as_mut() {
            let emptied = review.remove_seq(seq);
            if emptied {
                self.pins_review = None;
            } else {
                self.scroll_review_selection_into_view();
            }
        }
    }

    /// Close review mode (esc); refocuses the composer.
    pub(super) fn close_pins_review(&mut self) {
        self.pins_review = None;
    }

    pub(super) fn enter_copy_pick_mode(&mut self) {
        if self.any_overlay_open() {
            return;
        }
        match CopyPick::enter(self.pinnable_indices()) {
            Some(pick) => {
                self.pin_pick = None;
                self.fork_pick = None;
                self.pins_review = None;
                self.copy_pick = Some(pick);
                self.scroll_copy_pick_into_view();
            }
            None => {
                self.push_plain("/copy-pick: no message to copy yet".to_string());
            }
        }
    }

    pub(super) fn cancel_copy_pick(&mut self) {
        self.copy_pick = None;
    }

    pub(super) fn copy_pick_up(&mut self) {
        if let Some(pick) = self.copy_pick.as_mut() {
            pick.up();
        }
        self.scroll_copy_pick_into_view();
    }

    pub(super) fn copy_pick_down(&mut self) {
        if let Some(pick) = self.copy_pick.as_mut() {
            pick.down();
        }
        self.scroll_copy_pick_into_view();
    }

    pub(super) fn copy_pick_cycle_target(&mut self, delta: i32) {
        let block_count = self
            .copy_target_source_text()
            .map(|text| crate::clipboard::extract_code_blocks(&text).len())
            .unwrap_or(0);
        if let Some(pick) = self.copy_pick.as_mut() {
            pick.cycle_block_target(delta, block_count);
        }
    }

    pub(super) fn open_copy_pick_format_menu(&mut self) {
        let Some((_, text, _)) = self.copy_target_text() else {
            self.show_toast("/copy-pick: that message has no text", ToastKind::Info);
            return;
        };
        if text.trim().is_empty() {
            self.show_toast("/copy-pick: that message has no text", ToastKind::Info);
            return;
        }
        self.context_menu = Some(crate::tui::context_menu::ContextMenu {
            preferred_origin: (2, 2),
            clicked_chat_row: 0,
            cursor: 0,
            items: crate::tui::context_menu::ContextMenu::build_items(
                crate::clipboard::is_ssh(),
                false,
            ),
        });
    }

    pub(super) fn copy_pick_selected_history_index(&self) -> Option<usize> {
        self.copy_pick.as_ref().map(|p| p.selected_history_index())
    }

    pub(super) fn copy_pick_target_hint(&self) -> Option<String> {
        let pick = self.copy_pick.as_ref()?;
        if pick.block_target == 0 {
            return Some("target: whole message".to_string());
        }
        let text = self.copy_target_source_text()?;
        let blocks = crate::clipboard::extract_code_blocks(&text);
        let block = blocks.get(pick.block_target - 1)?;
        let lang = block.lang.as_deref().unwrap_or("plain");
        Some(format!(
            "target: code block {}/{} ({lang})",
            pick.block_target,
            blocks.len()
        ))
    }

    pub(super) fn copy_target_text(&self) -> Option<(String, String, CopyShape)> {
        let pick = self.copy_pick.as_ref()?;
        let (role, text) = self.copy_pick_message_text(pick.selected_history_index())?;
        if text.trim().is_empty() {
            return Some((role, text, CopyShape::Message));
        }
        if pick.block_target == 0 {
            return Some((role, text, CopyShape::Message));
        }
        let blocks = crate::clipboard::extract_code_blocks(&text);
        let block = blocks.get(pick.block_target - 1)?;
        let label = format!("{} code block {}", role, pick.block_target);
        Some((label, block.body.clone(), CopyShape::CodeBlock))
    }

    fn copy_target_source_text(&self) -> Option<String> {
        let pick = self.copy_pick.as_ref()?;
        self.copy_pick_message_text(pick.selected_history_index())
            .map(|(_, text)| text)
    }

    fn copy_pick_message_text(&self, idx: usize) -> Option<(String, String)> {
        match self.history.get(idx)? {
            HistoryEntry::User { text, .. } => Some(("message".to_string(), text.clone())),
            HistoryEntry::Agent { name, text, .. } => {
                Some((format!("{name} message"), text.clone()))
            }
            _ => None,
        }
    }

    /// Scroll the transcript so the pick-mode selected message is visible.
    /// Uses the absolute content line recorded at the last render; a no-op
    /// before the first render populates the map.
    fn scroll_pick_into_view(&mut self) {
        let Some(idx) = self.pin_pick.as_ref().map(|p| p.selected_history_index()) else {
            return;
        };
        self.scroll_history_index_into_view(idx);
    }

    fn scroll_fork_pick_into_view(&mut self) {
        let Some(idx) = self.fork_pick.as_ref().map(|p| p.selected_history_index()) else {
            return;
        };
        self.scroll_history_index_into_view(idx);
    }

    fn scroll_copy_pick_into_view(&mut self) {
        let Some(idx) = self.copy_pick.as_ref().map(|p| p.selected_history_index()) else {
            return;
        };
        self.scroll_history_index_into_view(idx);
    }

    /// Scroll the transcript so the review-highlighted pin's message is
    /// visible. The pin carries a `seq`; we find the history entry with
    /// that `seq` and scroll to it.
    fn scroll_review_selection_into_view(&mut self) {
        let Some(seq) = self
            .pins_review
            .as_ref()
            .and_then(|r| r.selected())
            .map(|p| p.seq)
        else {
            return;
        };
        let idx = self
            .history
            .iter()
            .position(|e| Self::entry_pin_seq(e) == Some(seq));
        if let Some(idx) = idx {
            self.scroll_history_index_into_view(idx);
        }
    }

    /// Set `chat_scroll_offset` so the given history index's first content
    /// line sits within the visible window. `chat_scroll_offset` counts
    /// logical lines up from the bottom; convert the absolute content line
    /// (from the top) accordingly.
    fn scroll_history_index_into_view(&mut self, idx: usize) {
        let Some(&rel) = self.msg_abs_line.get(&idx) else {
            return;
        };
        // `msg_abs_line` is relative to the message buffer; the full
        // scrollback prefixes the banner box.
        let abs = self.chat_banner_lines + rel;
        self.scroll_abs_line_into_view(abs);
    }

    pub(super) fn scroll_abs_line_into_view(&mut self, abs: usize) {
        let total = self.chat_total_lines;
        let visible = self.chat_visible_lines.max(1);
        if total <= visible {
            self.chat_scroll_offset = 0;
            return;
        }
        // Top of the visible window (counted from the top) we want, so the
        // target line lands a couple rows below the top for context.
        let desired_top = abs.saturating_sub(2);
        let max_offset = total - visible;
        // offset = how far the bottom is above the content bottom.
        // bottom_visible_line(from top) = total - offset. We want
        // desired_top..desired_top+visible visible, i.e. offset such that
        // (total - offset) - visible == desired_top → offset = total -
        // visible - desired_top.
        let offset = total
            .saturating_sub(visible)
            .saturating_sub(desired_top)
            .min(max_offset);
        // Clamp so the target is not below the window either.
        self.chat_scroll_offset = offset;
    }

    /// True when any modal overlay/pane currently owns the screen — pin
    /// modes don't stack on top of these.
    fn any_overlay_open(&self) -> bool {
        self.dialog.is_active()
            || self.overlay.is_open()
            || self.pane.is_some()
            || self.context_menu.is_some()
            || self.pin_pick.is_some()
            || self.fork_pick.is_some()
            || self.copy_pick.is_some()
            || self.pins_review.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::{App, CopyShape, pin_refresh_call_count, reset_pin_refresh_call_count};
    use crate::db::Db;
    use crate::db::session_log::SessionEventKind;
    use crate::tui::settings::Dialog;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use serde_json::json;
    use tokio::sync::mpsc;

    use crate::tui::agent_runner::{AgentRunner, ClientTasks, UsageCounts};
    use crate::tui::context_menu::{ContextMenu, ContextMenuAction};
    use crate::tui::history::{HistoryEntry, ToolCall, ToolCallState};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn test_app(root: &std::path::Path) -> App {
        let mut app = App::new(Some(root), false);
        app.daemon_prompt = None;
        app.dialog = Dialog::None;
        app
    }

    fn runner() -> AgentRunner {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let (record_tx, _record_rx) = mpsc::channel(1);
        let (attached_request_tx, _attached_request_rx) = mpsc::channel(1);
        AgentRunner {
            input_tx,
            record_tx,
            attached_request_tx,
            events: Arc::new(Mutex::new(Vec::new())),
            event_notify: Arc::new(tokio::sync::Notify::new()),
            active_agent: Arc::new(Mutex::new("Build".to_string())),
            active_agent_path: Arc::new(Mutex::new(vec!["Build".to_string()])),
            foreground_target: Some(crate::engine::message::QueueTarget::root("Build")),
            session_id: uuid::Uuid::new_v4(),
            short_id: "abc123".to_string(),
            project_id: "project".to_string(),
            usage: UsageCounts::default(),
            owns_daemon: false,
            socket: PathBuf::from("/tmp/cockpit-test.sock"),
            history: Vec::new(),
            paused_work: Vec::new(),
            repair_required: None,
            daemon_version: "test".to_string(),
            daemon_compatible: true,
            client_tasks: ClientTasks::default(),
        }
    }

    fn record_msg(db: &Db, sid: uuid::Uuid, text: &str) -> i64 {
        db.insert_session_event(
            sid,
            SessionEventKind::UserMessage,
            Some("Auto"),
            None,
            &json!({ "text": text }),
        )
        .unwrap()
    }

    fn user(seq: Option<i64>) -> HistoryEntry {
        HistoryEntry::User {
            text: "hi".into(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq,
            preflight_pending: false,
            persist_failed: false,
        }
    }

    fn agent(seq: Option<i64>) -> HistoryEntry {
        HistoryEntry::Agent {
            name: "Auto".into(),
            text: "ok".into(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq,
        }
    }

    fn tool_line() -> HistoryEntry {
        HistoryEntry::ToolLine {
            call_id: "c".into(),
            tool: "bash".into(),
            summary: "ls".into(),
            state: ToolCallState::Success,
        }
    }

    fn toolbox() -> HistoryEntry {
        HistoryEntry::ToolBox {
            calls: vec![ToolCall {
                call_id: "c".into(),
                tool: "read".into(),
                summary: "a.rs".into(),
                full_input: "a.rs".into(),
                output: String::new(),
                expanded: false,
                result_offset: 0,
                state: ToolCallState::Success,
                hint: None,
            }],
            view_offset: 0,
            follow: true,
        }
    }

    /// `pinned-messages`: the relocated control's click hit-test resolves a
    /// click to the right `seq` only when it lands inside the recorded
    /// `[col_start, col_end)` range on the control's row — a click on the
    /// same row but one column outside (either side), or on a different row,
    /// is a no-op. `pin_seq_at` is the pure predicate the mouse handler runs
    /// before routing into `toggle_pin_for_seq`.
    #[test]
    fn pin_hit_test_targets_only_the_control_columns() {
        use crate::tui::app::render::{ChatRowKind, ChatRowMeta, PinHit};
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        // Agent `[pin]` control rides row 3, columns 52..57 (5 wide), seq 42.
        let empty = ChatRowMeta {
            history_index: None,
            row_kind: ChatRowKind::Padding,
            copy_target: None,
            chip_target: None,
            subagent_target: None,
            tool_box_target: None,
            tool_call_target: None,
            tool_result_scroll: None,
            reasoning_window_scroll: None,
            reasoning_window_target: None,
            diff_path: None,
            pin_hit: None,
            continuation: false,
            selectable: false,
        };
        app.chat_row_meta = vec![
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty,
        ];
        app.chat_row_meta[3].pin_hit = Some(PinHit {
            seq: 42,
            col_start: 52,
            col_end: 57,
        });

        // Inside the region → resolves to the seq (every live column).
        for col in 52..57 {
            assert_eq!(app.pin_seq_at(3, col), Some(42), "col {col} is live");
        }
        // Just outside on either side → no-op.
        assert_eq!(app.pin_seq_at(3, 51), None, "one left of the glyphs");
        assert_eq!(
            app.pin_seq_at(3, 57),
            None,
            "one past the glyphs (half-open)"
        );
        // A different row, even at a live column → no-op.
        assert_eq!(app.pin_seq_at(2, 53), None, "wrong row");
        assert_eq!(app.pin_seq_at(4, 53), None, "wrong row");
        // A row with no recorded control → no-op.
        assert_eq!(app.pin_seq_at(0, 53), None, "no control on this row");
        // Out-of-bounds row → no panic, no-op.
        assert_eq!(app.pin_seq_at(99, 53), None, "out of range");
    }

    /// Only User/Agent messages WITH a resolved `seq` are pinnable; tool
    /// entries and not-yet-recorded messages are not.
    #[test]
    fn entry_pin_seq_classifies_pinnable_messages() {
        assert_eq!(App::entry_pin_seq(&user(Some(7))), Some(7));
        assert_eq!(App::entry_pin_seq(&agent(Some(9))), Some(9));
        // A pushed-but-not-yet-recorded user row has no seq → not pinnable.
        assert_eq!(App::entry_pin_seq(&user(None)), None);
        // Tool entries are never pinnable.
        assert_eq!(App::entry_pin_seq(&tool_line()), None);
        assert_eq!(App::entry_pin_seq(&toolbox()), None);
    }

    #[test]
    fn pin_cache_refreshes_after_pin_and_unpin() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let db = Db::open_in_memory().unwrap();
        let session = db.create_session("p", "/x", "Auto").unwrap();
        let sid = session.session_id;
        app.launch.session_id = Some(sid);
        let seq = record_msg(&db, sid, "pin me");

        app.refresh_pin_state_from_db(sid, &db);
        assert_eq!(app.pin_count, 0);
        assert!(!app.is_seq_pinned_for_render(seq));

        assert!(db.pin_message(sid, seq).unwrap());
        app.refresh_pin_state_from_db(sid, &db);
        assert_eq!(app.pin_count, 1);
        assert!(app.is_seq_pinned_for_render(seq));

        assert!(db.unpin_message(sid, seq).unwrap());
        app.refresh_pin_state_from_db(sid, &db);
        assert_eq!(app.pin_count, 0);
        assert!(!app.is_seq_pinned_for_render(seq));
    }

    #[test]
    fn pin_cache_session_sync_skips_idle_refresh_and_clears_stale_session() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let sid = uuid::Uuid::new_v4();
        app.launch.session_id = Some(sid);
        app.pin_count = 1;
        app.pin_count_session = Some(sid);
        app.pinned_seqs_session = Some(sid);
        app.pinned_seqs_cache.insert(42);

        reset_pin_refresh_call_count();
        app.sync_pin_count();
        assert_eq!(pin_refresh_call_count(), 0);
        assert!(app.is_seq_pinned_for_render(42));

        app.launch.session_id = None;
        app.sync_pin_count();
        assert_eq!(pin_refresh_call_count(), 1);
        assert_eq!(app.pin_count, 0);
        assert!(app.pinned_seqs_cache.is_empty());
        assert!(!app.is_seq_pinned_for_render(42));
    }

    #[test]
    fn copy_pick_enter_selects_last_message() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![user(Some(1)), agent(Some(2)), user(Some(3))];

        app.enter_copy_pick_mode();

        assert_eq!(
            app.copy_pick
                .as_ref()
                .map(|pick| pick.selected_history_index()),
            Some(2)
        );
    }

    #[test]
    fn copy_pick_refused_while_overlay_open() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![user(Some(1))];
        app.context_menu = Some(ContextMenu {
            preferred_origin: (0, 0),
            clicked_chat_row: 0,
            cursor: 0,
            items: vec![ContextMenuAction::CopyAsMarkdown],
        });

        app.enter_copy_pick_mode();

        assert!(app.copy_pick.is_none());
    }

    #[test]
    fn fork_command_enters_pick_mode() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.agent_runner = Some(Ok(runner()));
        app.current_session_persisted = true;
        app.history = vec![user(Some(11)), agent(Some(12))];

        app.handle_fork_command("");

        assert!(app.fork_pick.is_some());
        assert_eq!(
            app.fork_pick
                .as_ref()
                .map(|pick| pick.selected_history_index()),
            Some(1)
        );
        assert_eq!(app.async_actions.pending_count(), 0);
    }

    #[test]
    fn fork_pick_esc_cancels() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![user(Some(11))];
        app.enter_fork_pick_mode();

        app.cancel_fork_pick();

        assert!(app.fork_pick.is_none());
        assert_eq!(app.async_actions.pending_count(), 0);
    }

    #[test]
    fn fork_pick_navigation_and_keyboard_ownership() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![user(Some(11)), agent(Some(12))];
        app.enter_fork_pick_mode();

        app.handle_key(key(KeyCode::Char('k')));
        assert_eq!(
            app.fork_pick
                .as_ref()
                .map(|pick| pick.selected_history_index()),
            Some(0)
        );
        app.handle_key(key(KeyCode::Char('j')));
        assert_eq!(
            app.fork_pick
                .as_ref()
                .map(|pick| pick.selected_history_index()),
            Some(1)
        );
        assert_eq!(app.composer.text(), "");

        app.handle_key(key(KeyCode::Esc));
        assert!(app.fork_pick.is_none());
    }

    #[test]
    fn copy_pick_tab_noop_without_code_block() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![agent(Some(1))];
        app.enter_copy_pick_mode();

        app.copy_pick_cycle_target(1);

        assert_eq!(app.copy_pick.as_ref().unwrap().block_target, 0);
    }

    #[test]
    fn copy_target_text_block_returns_block_body_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![HistoryEntry::Agent {
            name: "Auto".into(),
            text: "before\n```rust\nlet x=1;\n```\nafter".into(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq: Some(1),
        }];
        app.enter_copy_pick_mode();
        app.copy_pick_cycle_target(1);

        let (label, text, shape) = app.copy_target_text().unwrap();

        assert_eq!(label, "Auto message code block 1");
        assert_eq!(text, "let x=1;\n");
        assert_eq!(shape, CopyShape::CodeBlock);
    }
}
