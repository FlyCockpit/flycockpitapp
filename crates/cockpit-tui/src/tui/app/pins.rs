//! Pinned-messages TUI integration (`pinned-messages`): the `/pin`
//! pick-a-message mode, the `/pins` review mode, the mouse `[fork]` and
//! `[pin]`/`[unpin]` controls, and the below-input count indicator's data source.
//!
//! Pins are daemon-owned state consumed through typed RPCs. Nothing here
//! ever enters the outbound model prompt (token economy, priority #2).

use crate::tui::async_action::{
    AsyncActionKey, AsyncActionKind, AsyncActionPayload, AsyncActionPolicy,
};
use crate::tui::history::HistoryEntry;
use crate::tui::pins_overlay::{CopyPick, ForkPick, PinPick, PinsReview};

use super::{App, ToastKind, render};

/// How long to wait before an autonomous retry of a failed pin-state refresh.
/// The pin count is non-critical below-input chrome, so a coarse fixed backoff
/// is enough to self-heal a transient daemon failure without re-kicking the RPC
/// every event-loop tick on a persistent one.
const PIN_STATE_RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

fn pin_rpc(
    endpoint: &cockpit_client::ClientEndpoint,
    request: cockpit_proto::Request,
) -> Result<cockpit_proto::Response, String> {
    crate::tui::agent_runner::daemon_request_at_blocking(endpoint, request)
}

fn load_pin_state(
    endpoint: &cockpit_client::ClientEndpoint,
    sid: uuid::Uuid,
) -> Result<(usize, Vec<i64>), String> {
    match pin_rpc(
        endpoint,
        cockpit_proto::Request::PinnedMessageState { session_id: sid },
    )? {
        cockpit_proto::Response::PinState { state } => {
            Ok((state.count.max(0) as usize, state.seqs))
        }
        other => Err(format!("unexpected pin-state response: {other:?}")),
    }
}

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
    pub(super) fn pin_toast(&mut self, text: impl Into<String>) {
        self.show_toast(text, ToastKind::Info);
    }

    /// Open the global DB for a pin operation. `None` (with a transcript
    /// note) when the DB can't be opened — pins degrade gracefully rather
    /// than crash the TUI.
    fn pins_socket(&mut self) -> Option<cockpit_client::ClientEndpoint> {
        if self.daemon_connected {
            self.attached_daemon_endpoint()
        } else {
            self.push_plain("pins: Unavailable — reconnect to the daemon, then Retry".to_string());
            None
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
        // A prior refresh for THIS session failed and un-stamped it (see
        // `note_pin_state_refresh_failed`); throttle the autonomous retry so a
        // persistent daemon failure re-kicks at the backoff interval rather than
        // every event-loop tick. A different or newly-attached session is never
        // gated by a stale failure, so it refreshes immediately.
        if let (Some(sid), Some((gated_sid, retry_after))) = (sid, self.pin_state_retry_after)
            && sid == gated_sid
            && self.event_loop_monotonic_now < retry_after
        {
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
        match self.pins_socket() {
            Some(socket) => self.start_pin_state_refresh(sid, socket, true),
            None => {
                self.pin_count_session = Some(sid);
                self.pinned_seqs_session = Some(sid);
                self.pinned_seqs_cache.clear();
                self.clear_pin_state_retry_gate(sid);
            }
        }
    }

    fn start_pin_state_refresh(
        &mut self,
        sid: uuid::Uuid,
        endpoint: cockpit_client::ClientEndpoint,
        clear_first: bool,
    ) {
        if clear_first {
            self.pin_count = 0;
            self.pinned_seqs_cache.clear();
        }
        self.pin_count_session = Some(sid);
        self.pinned_seqs_session = Some(sid);
        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("pins.state"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!("pins.state:{sid}"))),
            move || match load_pin_state(&endpoint, sid) {
                Ok((count, pinned_seqs)) => Ok(AsyncActionPayload::PinState {
                    session_id: sid,
                    count,
                    pinned_seqs,
                }),
                // Surface the failure WITH its session so the handler retries
                // the right session even after the user navigates away.
                Err(error) => Ok(AsyncActionPayload::PinStateRefreshFailed {
                    session_id: sid,
                    error,
                }),
            },
        );
    }

    pub(super) fn apply_pin_state(&mut self, sid: uuid::Uuid, count: usize, pinned_seqs: Vec<i64>) {
        if self.current_session_id() != Some(sid) {
            return;
        }
        self.pin_count_session = Some(sid);
        self.pinned_seqs_session = Some(sid);
        self.pin_count = count;
        self.pinned_seqs_cache = pinned_seqs.into_iter().collect();
        // A refresh landed: retire any pending failure-retry gate for it.
        self.clear_pin_state_retry_gate(sid);
    }

    /// A pin-state refresh RPC failed for `sid`. Un-stamp that session so
    /// `sync_pin_count` retries: `start_pin_state_refresh` stamps the session
    /// eagerly (before the async result) to avoid re-kicking the RPC every tick,
    /// so without this a single transient failure would wedge the pin count at 0
    /// forever. Arm a backoff gate so the retry re-kicks at
    /// [`PIN_STATE_RETRY_BACKOFF`], not on every event-loop tick.
    pub(super) fn note_pin_state_refresh_failed(&mut self, sid: uuid::Uuid) {
        // Act only while the eager stamp is still this session's. If the user
        // navigated away (a newer refresh re-stamped) or a later attempt already
        // succeeded, this failure is stale and must not perturb the now-current
        // session's cache or gate.
        if self.pin_count_session != Some(sid) && self.pinned_seqs_session != Some(sid) {
            return;
        }
        if self.pin_count_session == Some(sid) {
            self.pin_count_session = None;
        }
        if self.pinned_seqs_session == Some(sid) {
            self.pinned_seqs_session = None;
        }
        self.pin_state_retry_after =
            Some((sid, self.event_loop_monotonic_now + PIN_STATE_RETRY_BACKOFF));
    }

    /// Drop the failure-retry gate when it belongs to `sid` (a refresh for it
    /// succeeded or its socketless path completed).
    fn clear_pin_state_retry_gate(&mut self, sid: uuid::Uuid) {
        if matches!(self.pin_state_retry_after, Some((gated, _)) if gated == sid) {
            self.pin_state_retry_after = None;
        }
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

    /// The control chip whose mouse region covers chat-area-relative row
    /// `row` + column `col`, or `None`. Pure over `chat_row_meta`; the mouse
    /// handler routes pin and fork chips to distinct actions.
    pub(super) fn control_chip_at(&self, row: usize, col: u16) -> Option<render::ControlChip> {
        let meta = self.chat_row_meta.get(row)?;
        if let Some(hit) = meta.fork_hit
            && col >= hit.col_start
            && col < hit.col_end
        {
            return Some(render::ControlChip::Fork { seq: hit.seq });
        }
        if let Some(hit) = meta.pin_hit
            && col >= hit.col_start
            && col < hit.col_end
        {
            return Some(render::ControlChip::Pin { seq: hit.seq });
        }
        None
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
        let Some(socket) = self.pins_socket() else {
            return;
        };
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("pins.toggle"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                let now_pinned = match pin_rpc(
                    &socket,
                    cockpit_proto::Request::TogglePinnedMessage {
                        session_id: sid,
                        seq,
                    },
                )? {
                    cockpit_proto::Response::PinToggled { pinned } => pinned,
                    other => return Err(format!("unexpected pin-toggle response: {other:?}")),
                };
                let (count, pinned_seqs) = load_pin_state(&socket, sid)?;
                Ok(AsyncActionPayload::PinToggle {
                    session_id: sid,
                    seq,
                    now_pinned,
                    count,
                    pinned_seqs,
                })
            },
        );
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
        let Some(socket) = self.pins_socket() else {
            return;
        };
        self.async_actions.start_blocking(
            AsyncActionKind::Internal("pins.review"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!("pins.review:{sid}"))),
            move || {
                let pins = match pin_rpc(
                    &socket,
                    cockpit_proto::Request::ListPinnedMessagesWithText { session_id: sid },
                )? {
                    cockpit_proto::Response::PinsWithText { pins } => pins,
                    other => return Err(format!("unexpected pins-review response: {other:?}")),
                };
                Ok(AsyncActionPayload::PinsReview {
                    session_id: sid,
                    pins,
                })
            },
        );
    }

    pub(super) fn apply_pins_review(
        &mut self,
        sid: uuid::Uuid,
        pins: Vec<cockpit_proto::PinnedMessage>,
    ) {
        if self.current_session_id() != Some(sid) {
            return;
        }
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

    pub(super) fn apply_pin_toggle(
        &mut self,
        sid: uuid::Uuid,
        seq: i64,
        now_pinned: bool,
        count: usize,
        pinned_seqs: Vec<i64>,
    ) {
        if self.current_session_id() != Some(sid) {
            return;
        }
        self.pin_toast(if now_pinned {
            "pinned".to_string()
        } else {
            "unpinned".to_string()
        });
        self.apply_pin_state(sid, count, pinned_seqs);
        if let Some(review) = self.pins_review.as_mut()
            && review.remove_seq_if_present(seq)
        {
            self.pins_review = None;
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

    pub(super) fn fork_preconditions_ok(&mut self) -> bool {
        if self.side_conversation.is_some() {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: end the side conversation first (`/side end`)".to_string(),
            });
            return false;
        }
        if self.busy || self.pending.is_some() || self.question_dialog.is_some() {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: wait until the current turn or approval finishes".to_string(),
            });
            return false;
        }
        if !self.active_schedules.is_empty() {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: cancel or wait for active scheduled tasks first".to_string(),
            });
            return false;
        }
        match self.agent_runner.as_ref() {
            Some(Ok(_runner)) => {}
            _ => {
                self.history.push(HistoryEntry::CommandError {
                    line: "/fork: no active session to fork from".to_string(),
                });
                return false;
            }
        };
        if !self.current_session_persisted {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: send a message first — there's nothing to fork yet".to_string(),
            });
            return false;
        }
        true
    }

    pub(super) fn fork_for_seq(&mut self, seq: i64) {
        if !self.fork_preconditions_ok() {
            return;
        }
        let Some(idx) = self
            .history
            .iter()
            .position(|entry| Self::entry_pin_seq(entry) == Some(seq))
        else {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: message is not recorded yet".to_string(),
            });
            return;
        };
        self.fork_at_seq(idx, seq);
    }

    pub(super) fn confirm_fork_pick(&mut self) {
        let Some(pick) = self.fork_pick.take() else {
            return;
        };
        self.fork_history_index(pick.selected_history_index());
    }

    pub(super) fn fork_history_index(&mut self, idx: usize) {
        let Some(seq) = self.history.get(idx).and_then(Self::entry_pin_seq) else {
            self.history.push(HistoryEntry::CommandError {
                line: "/fork: message is not recorded yet".to_string(),
            });
            return;
        };
        self.fork_at_seq(idx, seq);
    }

    pub(super) fn fork_at_seq(&mut self, idx: usize, seq: i64) {
        let seed_composer = match self.history.get(idx) {
            Some(HistoryEntry::User { text, .. }) => Some(text.clone()),
            _ => None,
        };
        let (parent_session_id, endpoint, socket) = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => (
                runner.session_id(),
                runner.endpoint.clone(),
                runner.socket.clone(),
            ),
            _ => {
                self.history.push(HistoryEntry::CommandError {
                    line: "/fork: no active session to fork from".to_string(),
                });
                return;
            }
        };

        let start = self.async_actions.start_blocking(
            super::AsyncActionKind::DaemonRpc("fork.create"),
            super::AsyncActionPolicy::Dedupe(super::AsyncActionKey::new("fork.create")),
            move || {
                let fork_point_turn_id = Some(seq.to_string());
                let (session_id, short_id) = super::agent_runner::fork_session_blocking(
                    &endpoint,
                    parent_session_id,
                    fork_point_turn_id,
                    false,
                )?;
                Ok(super::AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    endpoint,
                    socket,
                    session_id,
                    short_id,
                    fork_point_seq: Some(seq),
                    seed_composer,
                })
            },
        );
        match start {
            super::AsyncActionStart::Started(_) => {
                self.push_plain("/fork: pending".to_string());
            }
            super::AsyncActionStart::Existing(_) => {
                self.history.push(HistoryEntry::CommandError {
                    line: "/fork: fork creation already pending".to_string(),
                });
            }
        }
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
                if let Some(socket) = self.pins_socket() {
                    self.async_actions.start_blocking(
                        AsyncActionKind::Internal("pins.pin"),
                        AsyncActionPolicy::AllowConcurrent,
                        move || {
                            let inserted = match pin_rpc(
                                &socket,
                                cockpit_proto::Request::PinMessage {
                                    session_id: sid,
                                    seq,
                                },
                            )? {
                                cockpit_proto::Response::PinChanged { changed } => changed,
                                other => return Err(format!("unexpected pin response: {other:?}")),
                            };
                            let (count, pinned_seqs) = load_pin_state(&socket, sid)?;
                            Ok(AsyncActionPayload::PinMessage {
                                session_id: sid,
                                seq,
                                inserted,
                                count,
                                pinned_seqs,
                            })
                        },
                    );
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
        if let Some(socket) = self.pins_socket() {
            self.async_actions.start_blocking(
                AsyncActionKind::Internal("pins.unpin"),
                AsyncActionPolicy::AllowConcurrent,
                move || {
                    match pin_rpc(
                        &socket,
                        cockpit_proto::Request::UnpinMessage {
                            session_id: sid,
                            seq,
                        },
                    )? {
                        cockpit_proto::Response::PinChanged { .. } => {}
                        other => return Err(format!("unexpected unpin response: {other:?}")),
                    }
                    let (count, pinned_seqs) = load_pin_state(&socket, sid)?;
                    Ok(AsyncActionPayload::PinUnpin {
                        session_id: sid,
                        seq,
                        count,
                        pinned_seqs,
                    })
                },
            );
        }
    }

    pub(super) fn apply_pin_message(
        &mut self,
        sid: uuid::Uuid,
        inserted: bool,
        count: usize,
        pinned_seqs: Vec<i64>,
    ) {
        if self.current_session_id() != Some(sid) {
            return;
        }
        self.pin_toast(if inserted {
            "pinned".to_string()
        } else {
            "already pinned".to_string()
        });
        self.apply_pin_state(sid, count, pinned_seqs);
    }

    pub(super) fn apply_pin_unpin(
        &mut self,
        sid: uuid::Uuid,
        seq: i64,
        count: usize,
        pinned_seqs: Vec<i64>,
    ) {
        if self.current_session_id() != Some(sid) {
            return;
        }
        self.apply_pin_state(sid, count, pinned_seqs);
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
                cockpit_host::sysinfo::is_ssh(),
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
            self.pin_chat_to_tail();
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
        self.set_chat_scroll_offset_from_interaction(offset);
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
    use crate::tui::settings::Dialog;

    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use crate::tui::agent_runner::{AgentRunner, TestRunnerOverrides};
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
        AgentRunner::test_fixture(TestRunnerOverrides::default())
    }

    fn user(seq: Option<i64>) -> HistoryEntry {
        HistoryEntry::User {
            text: "hi".into(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq,
            optimistic_submission_id: None,
            preflight_pending: false,
            persist_failed: false,
        }
    }

    fn agent(seq: Option<i64>) -> HistoryEntry {
        HistoryEntry::Agent {
            name: "Build".into(),
            text: "ok".into(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq,
            performance: None,
            performance_expanded: false,
        }
    }

    fn tool_line() -> HistoryEntry {
        HistoryEntry::ToolLine {
            call_id: "c".into(),
            tool: "bash".into(),
            summary: "ls".into(),
            icon_path: None,
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
                progress: None,
                mcp_child: None,
            }],
            view_offset: 0,
            follow: true,
        }
    }

    /// `pinned-messages`: the relocated control's click hit-test resolves a
    /// click to the right `seq` only when it lands inside the recorded
    /// `[col_start, col_end)` range on the control's row — a click on the
    /// same row but one column outside (either side), or on a different row,
    /// is a no-op. `control_chip_at` is the pure predicate the mouse handler
    /// runs before routing into fork or pin actions.
    #[test]
    fn pin_hit_test_targets_only_the_control_columns() {
        use crate::tui::app::render::{ChatRowKind, ChatRowMeta, ControlChip, PinHit};
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
            fork_hit: None,
            metric_hit: None,
            continuation: false,
            selectable: false,
            copy_cells: Vec::new(),
            copy_fragments: std::rc::Rc::new(Vec::new()),
            copy_newlines_before: 0,
            copy_fallback_if_unmapped: false,
            copy_provenance_present: false,
        };
        app.chat_row_meta = vec![
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty.clone(),
            empty,
        ];
        app.chat_row_meta[3].fork_hit = Some(PinHit {
            seq: 42,
            col_start: 45,
            col_end: 51,
        });
        app.chat_row_meta[3].pin_hit = Some(PinHit {
            seq: 42,
            col_start: 52,
            col_end: 57,
        });

        // Inside the fork region → resolves to fork, not pin.
        for col in 45..51 {
            assert_eq!(
                app.control_chip_at(3, col),
                Some(ControlChip::Fork { seq: 42 }),
                "col {col} is fork"
            );
            assert_ne!(
                app.control_chip_at(3, col),
                Some(ControlChip::Pin { seq: 42 }),
                "fork col {col} is not pin"
            );
        }
        // Inside the pin region → resolves to the seq (every live column).
        for col in 52..57 {
            assert_eq!(
                app.control_chip_at(3, col),
                Some(ControlChip::Pin { seq: 42 }),
                "col {col} is pin"
            );
        }
        // Just outside on either side → no-op.
        assert_eq!(app.control_chip_at(3, 51), None, "one left of the glyphs");
        assert_eq!(
            app.control_chip_at(3, 57),
            None,
            "one past the glyphs (half-open)"
        );
        // A different row, even at a live column → no-op.
        assert_eq!(app.control_chip_at(2, 53), None, "wrong row");
        assert_eq!(app.control_chip_at(4, 53), None, "wrong row");
        // A row with no recorded control → no-op.
        assert_eq!(app.control_chip_at(0, 53), None, "no control on this row");
        // Out-of-bounds row → no panic, no-op.
        assert_eq!(app.control_chip_at(99, 53), None, "out of range");
    }

    #[cfg(unix)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fork_for_seq_sends_fork_session_request_with_message_seq() {
        use cockpit_proto::{Body, Envelope, ProtoStream, RecvFrame, Request, Response};
        use tokio::net::UnixListener;

        let tmp = tempfile::tempdir().unwrap();
        let socket = tmp.path().join("daemon.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let child_session_id = uuid::Uuid::new_v4();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut proto = ProtoStream::new(stream);
            proto
                .send(&Envelope::response(
                    uuid::Uuid::nil(),
                    Response::DaemonStatus {
                        pid: 1,
                        uptime_secs: 0,
                        active_sessions: 0,
                        socket_path: "test.sock".to_string(),
                        daemon_version: "test".to_string(),
                        protocol_version: cockpit_proto::PROTOCOL_VERSION,
                        paused_sessions: 0,
                        database_path: "test.db".to_string(),
                        // Handshake negotiation intentionally ignores database
                        // metadata; keep this socket fixture independent of
                        // cockpit-core's private storage implementation.
                        schema_version: 0,
                    },
                ))
                .await
                .unwrap();
            let env = match proto.recv().await.unwrap().unwrap() {
                RecvFrame::Envelope(env) => env,
                RecvFrame::Unknown { .. } => panic!("unexpected unknown frame"),
                RecvFrame::VersionMismatch { .. } => panic!("unexpected version mismatch"),
            };
            let Body::Request { id, request, .. } = env.body else {
                panic!("expected request envelope");
            };
            let parent_session_id = match &request {
                Request::ForkSession {
                    parent_session_id, ..
                } => *parent_session_id,
                other => panic!("expected fork request, got {other:?}"),
            };
            proto
                .send(&Envelope::response(
                    id,
                    Response::Forked {
                        session_id: child_session_id,
                        short_id: "fork77".to_string(),
                        parent_session_id,
                        fork_point_turn_id: Some("77".to_string()),
                    },
                ))
                .await
                .unwrap();
            request
        });

        let mut app = test_app(tmp.path());
        let mut runner = runner();
        runner.endpoint = cockpit_client::ClientEndpoint::Wire(socket.clone());
        runner.socket = socket;
        let parent_session_id = runner.session_id();
        app.agent_runner = Some(Ok(runner));
        app.current_session_persisted = true;
        app.history.push(HistoryEntry::User {
            text: "seed me".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: Some(77),
            optimistic_submission_id: None,
            preflight_pending: false,
            persist_failed: false,
        });

        app.fork_for_seq(77);

        let request = tokio::time::timeout(std::time::Duration::from_secs(2), server)
            .await
            .expect("fork request reached daemon stub")
            .unwrap();
        match request {
            Request::ForkSession {
                parent_session_id: got_parent,
                fork_point_turn_id,
                ephemeral,
            } => {
                assert_eq!(got_parent, parent_session_id);
                assert_eq!(fork_point_turn_id, Some("77".to_string()));
                assert!(!ephemeral);
            }
            other => panic!("expected fork request, got {other:?}"),
        }
        assert!(app.history.iter().any(|entry| {
            matches!(entry, HistoryEntry::Plain { line } if line == "/fork: pending")
        }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_fork_creation_keeps_completed_undrained_action_registered() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let mut agent_runner = runner();
        agent_runner.socket = tmp.path().join("missing.sock");
        app.agent_runner = Some(Ok(agent_runner));
        app.current_session_persisted = true;
        app.history.push(HistoryEntry::User {
            text: "seed me".to_string(),
            cleaned: None,
            expanded: false,
            timestamp: chrono::Local::now(),
            seq: Some(77),
            optimistic_submission_id: None,
            preflight_pending: false,
            persist_failed: false,
        });

        let notify = app.async_actions.notifier();
        app.fork_for_seq(77);
        tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified())
            .await
            .expect("fork creation completed");
        let first_ids = app.async_actions.pending_ids();

        // The transport failure has completed, but the TUI has deliberately
        // not drained it yet. Reissuing must keep that result adoptable.
        app.fork_for_seq(77);

        assert_eq!(app.async_actions.pending_ids(), first_ids);
        assert!(app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::CommandError { line }
                if line == "/fork: fork creation already pending"
        )));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_side_creation_keeps_completed_undrained_action_registered() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let mut agent_runner = runner();
        agent_runner.socket = tmp.path().join("missing.sock");
        app.agent_runner = Some(Ok(agent_runner));
        app.current_session_persisted = true;

        let notify = app.async_actions.notifier();
        app.enter_side_conversation();
        tokio::time::timeout(std::time::Duration::from_secs(1), notify.notified())
            .await
            .expect("side creation completed");
        let first_ids = app.async_actions.pending_ids();

        app.enter_side_conversation();

        assert_eq!(app.async_actions.pending_ids(), first_ids);
        assert!(app.history.iter().any(|entry| matches!(
            entry,
            HistoryEntry::CommandError { line }
                if line == "/side: side-conversation creation already pending"
        )));
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

    /// A failed pin-state refresh must un-stamp the session so `sync_pin_count`
    /// retries (otherwise the eager stamp wedges the count forever), but the
    /// retry is throttled: no re-kick within the backoff window, exactly one
    /// once it elapses.
    #[test]
    fn failed_pin_state_refresh_retries_after_backoff_not_every_tick() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let sid = uuid::Uuid::new_v4();
        app.launch.session_id = Some(sid);
        // Simulate the eager stamp `start_pin_state_refresh` sets before the RPC.
        app.pin_count_session = Some(sid);
        app.pinned_seqs_session = Some(sid);
        app.event_loop_monotonic_now = std::time::Duration::from_secs(10);

        // The refresh RPC fails: un-stamp + arm the backoff gate.
        app.note_pin_state_refresh_failed(sid);
        assert_eq!(app.pin_count_session, None);
        assert_eq!(app.pinned_seqs_session, None);
        assert!(app.pin_state_retry_after.is_some());

        // Within the backoff window, sync does NOT re-kick the RPC (no storm).
        reset_pin_refresh_call_count();
        app.sync_pin_count();
        assert_eq!(
            pin_refresh_call_count(),
            0,
            "must not retry within the backoff window"
        );

        // Once the backoff elapses, sync retries exactly once.
        app.event_loop_monotonic_now =
            std::time::Duration::from_secs(10) + super::PIN_STATE_RETRY_BACKOFF;
        app.sync_pin_count();
        assert_eq!(
            pin_refresh_call_count(),
            1,
            "must retry once the backoff elapsed"
        );
    }

    /// A landed refresh retires the gate; a different (newly-attached) session
    /// is never blocked by another session's stale failure.
    #[test]
    fn pin_state_success_clears_gate_and_other_session_not_blocked() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let sid1 = uuid::Uuid::new_v4();
        let sid2 = uuid::Uuid::new_v4();
        app.launch.session_id = Some(sid1);
        app.pin_count_session = Some(sid1);
        app.pinned_seqs_session = Some(sid1);
        app.event_loop_monotonic_now = std::time::Duration::from_secs(5);
        app.note_pin_state_refresh_failed(sid1);
        assert!(app.pin_state_retry_after.is_some());

        // A DIFFERENT current session refreshes immediately — sid1's stale gate
        // does not apply to it.
        app.launch.session_id = Some(sid2);
        reset_pin_refresh_call_count();
        app.sync_pin_count();
        assert_eq!(
            pin_refresh_call_count(),
            1,
            "a new session must refresh immediately"
        );

        // A landed refresh for the gated session retires its gate.
        app.launch.session_id = Some(sid1);
        app.apply_pin_state(sid1, 3, vec![7]);
        assert!(
            app.pin_state_retry_after.is_none(),
            "success must retire the gate"
        );
        assert_eq!(app.pin_count, 3);
        assert!(app.is_seq_pinned_for_render(7));
    }

    /// A pin-state failure that lands after the user has navigated to another
    /// session must NOT un-stamp or gate the now-current session (the failure
    /// carries its originating session id, guarded against the live stamp).
    #[test]
    fn stale_pin_state_failure_does_not_perturb_current_session() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let sid1 = uuid::Uuid::new_v4();
        let sid2 = uuid::Uuid::new_v4();
        // The user navigated to sid2, whose refresh already landed and stamped it.
        app.launch.session_id = Some(sid2);
        app.pin_count_session = Some(sid2);
        app.pinned_seqs_session = Some(sid2);
        app.pin_count = 4;
        app.pinned_seqs_cache.insert(9);
        app.event_loop_monotonic_now = std::time::Duration::from_secs(7);

        // A late failure for the PREVIOUS session sid1 arrives: ignore it.
        app.note_pin_state_refresh_failed(sid1);
        assert_eq!(
            app.pin_count_session,
            Some(sid2),
            "current session stamp must be untouched"
        );
        assert_eq!(app.pinned_seqs_session, Some(sid2));
        assert!(
            app.pin_state_retry_after.is_none(),
            "no gate armed for a stale session"
        );
        assert_eq!(app.pin_count, 4);

        // sync stays a no-op — the current session is still fully stamped.
        reset_pin_refresh_call_count();
        app.sync_pin_count();
        assert_eq!(pin_refresh_call_count(), 0);
    }

    /// A persistently-failing session retries once per backoff cycle — the gate
    /// re-arms after each retry rather than either wedging or re-kicking every
    /// tick.
    #[test]
    fn persistent_pin_state_failure_retries_each_backoff_cycle() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let sid = uuid::Uuid::new_v4();
        app.launch.session_id = Some(sid);
        reset_pin_refresh_call_count();

        let mut now = std::time::Duration::from_secs(0);
        for cycle in 0..3 {
            // The (re-)kicked refresh eagerly stamps, then fails.
            app.pin_count_session = Some(sid);
            app.pinned_seqs_session = Some(sid);
            app.event_loop_monotonic_now = now;
            app.note_pin_state_refresh_failed(sid);

            // Still within the backoff window: no retry.
            app.event_loop_monotonic_now =
                now + super::PIN_STATE_RETRY_BACKOFF - std::time::Duration::from_millis(1);
            app.sync_pin_count();
            assert_eq!(
                pin_refresh_call_count(),
                cycle,
                "no retry within backoff cycle {cycle}"
            );

            // Backoff elapsed: exactly one retry (socketless branch re-stamps
            // and clears the gate, standing in for the next kicked attempt).
            now += super::PIN_STATE_RETRY_BACKOFF;
            app.event_loop_monotonic_now = now;
            app.sync_pin_count();
            assert_eq!(
                pin_refresh_call_count(),
                cycle + 1,
                "one retry after backoff cycle {cycle}"
            );
        }
    }

    /// A session switch/resume drops any pending failure-retry gate so the new
    /// (or returned-to) session refreshes immediately instead of showing a stale
    /// count until the backoff self-expires.
    #[test]
    fn session_reset_clears_pin_state_retry_gate() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        let sid = uuid::Uuid::new_v4();
        app.launch.session_id = Some(sid);
        app.pin_count_session = Some(sid);
        app.pinned_seqs_session = Some(sid);
        app.event_loop_monotonic_now = std::time::Duration::from_secs(1);
        app.note_pin_state_refresh_failed(sid);
        assert!(app.pin_state_retry_after.is_some());

        app.reset_session_live_state();
        assert!(
            app.pin_state_retry_after.is_none(),
            "session reset must clear the failure-retry gate"
        );
    }

    #[test]
    fn copy_pick_enter_selects_last_message() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![user(Some(1)), agent(Some(2)), user(Some(3))].into();

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
        app.history = vec![user(Some(1))].into();
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
        app.history = vec![user(Some(11)), agent(Some(12))].into();

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
        app.history = vec![user(Some(11))].into();
        app.enter_fork_pick_mode();

        app.cancel_fork_pick();

        assert!(app.fork_pick.is_none());
        assert_eq!(app.async_actions.pending_count(), 0);
    }

    #[test]
    fn fork_pick_navigation_and_keyboard_ownership() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![user(Some(11)), agent(Some(12))].into();
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
        app.history = vec![agent(Some(1))].into();
        app.enter_copy_pick_mode();

        app.copy_pick_cycle_target(1);

        assert_eq!(app.copy_pick.as_ref().unwrap().block_target, 0);
    }

    #[test]
    fn copy_target_text_block_returns_block_body_only() {
        let tmp = tempfile::tempdir().unwrap();
        let mut app = test_app(tmp.path());
        app.history = vec![HistoryEntry::Agent {
            name: "Build".into(),
            text: "before\n```rust\nlet x=1;\n```\nafter".into(),
            reasoning: String::new(),
            timestamp: chrono::Local::now(),
            expanded: false,
            reasoning_offset: 0,
            think_duration: None,
            seq: Some(1),
            performance: None,
            performance_expanded: false,
        }]
        .into();
        app.enter_copy_pick_mode();
        app.copy_pick_cycle_target(1);

        let (label, text, shape) = app.copy_target_text().unwrap();

        assert_eq!(label, "Build message code block 1");
        assert_eq!(text, "let x=1;\n");
        assert_eq!(shape, CopyShape::CodeBlock);
    }
}
