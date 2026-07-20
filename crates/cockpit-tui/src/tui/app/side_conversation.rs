use super::*;

impl App {
    pub(super) fn side_entry_banner(side_short_id: &str) -> String {
        format!(
            "Side conversation {side_short_id} — a throwaway fork. `/side end` to discard and return."
        )
    }

    pub(super) fn apply_fork_created(
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
                Some(Ok(runner)) if runner.session_id() == parent_session_id
            )
        {
            return;
        }
        let switch_task = match self.agent_runner.as_ref() {
            Some(Ok(runner)) if runner.can_switch_session() => Some(runner.switch_session_task(
                agent_runner::SessionTarget::Resume {
                    session_id: fork_session_id,
                    since_seq: None,
                },
            )),
            _ => None,
        };
        if let Some(switch_task) = switch_task {
            self.async_actions.start(
                AsyncActionKind::Internal("session.fork"),
                AsyncActionPolicy::Replace(AsyncActionKey::new("session.switch")),
                async move {
                    switch_task
                        .await
                        .map(|outcome| AsyncActionPayload::ForkSessionSwitched {
                            outcome: Box::new(outcome),
                            fork_short_id,
                            seed_composer,
                        })
                },
            );
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
                self.launch.session_id = Some(runner.session_id());
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
    pub(super) fn enter_side_conversation(&mut self) {
        // Need a live runner: the side fork goes onto the same daemon, and
        // forking off an un-persisted session has nothing to branch from.
        let (parent_session_id, socket) = match self.agent_runner.as_ref() {
            Some(Ok(runner)) => (runner.session_id(), runner.socket.clone()),
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

    pub(super) fn apply_side_created(
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
                Some(Ok(runner)) if runner.session_id() == parent_session_id
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
        self.launch.session_id = Some(runner.session_id());
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
}
