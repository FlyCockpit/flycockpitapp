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
        socket: std::path::PathBuf,
        fork_session_id: uuid::Uuid,
        fork_short_id: String,
        fork_point_seq: Option<i64>,
        seed_composer: Option<String>,
    ) {
        if self.side_conversation.is_some()
            || !self.current_session_persisted
            || !matches!(
                self.agent_runner.as_ref(),
                Some(Ok(runner)) if runner.session_id() == parent_session_id
            )
        {
            self.schedule_created_session_discard(socket, fork_session_id);
            return;
        }
        if self.has_pending_session_switch_action() {
            self.schedule_created_session_discard(socket, fork_session_id);
            self.report_session_switch_busy("/fork");
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
            let cleanup_socket = socket.clone();
            let cleanup_short_id = fork_short_id.clone();
            let start = self.async_actions.start(
                AsyncActionKind::Internal("session.fork"),
                Self::session_switch_action_policy(),
                async move {
                    match switch_task.await {
                        Ok(outcome) => Ok(AsyncActionPayload::ForkSessionSwitched {
                            outcome: Box::new(outcome),
                            fork_short_id,
                            seed_composer,
                        }),
                        Err(error) => {
                            let discard = tokio::task::spawn_blocking(move || {
                                agent_runner::discard_session_blocking(
                                    &cleanup_socket,
                                    fork_session_id,
                                )
                            })
                            .await;
                            match discard {
                                Ok(Ok(())) => {}
                                Ok(Err(discard_error)) => tracing::warn!(
                                    error = %discard_error,
                                    fork = %cleanup_short_id,
                                    "discarding unattached fork failed"
                                ),
                                Err(join_error) => tracing::warn!(
                                    error = %join_error,
                                    fork = %cleanup_short_id,
                                    "unattached fork discard task failed"
                                ),
                            }
                            Err(error)
                        }
                    }
                },
            );
            if matches!(start, AsyncActionStart::Existing(_)) {
                self.schedule_created_session_discard(socket, fork_session_id);
                self.report_session_switch_busy("/fork");
            } else {
                self.begin_ephemeral_session_switch_submission_target(
                    agent_runner::SessionTarget::Resume {
                        session_id: fork_session_id,
                        since_seq: None,
                    },
                    EphemeralSessionSwitchIntent::Fork {
                        parent_session_id,
                        fork_point_seq,
                    },
                );
            }
            return;
        }
        self.schedule_created_session_discard(socket, fork_session_id);
        self.history.push(HistoryEntry::CommandError {
            line: format!(
                "/fork: created {fork_short_id}, but the active runner cannot switch sessions"
            ),
        });
    }

    fn schedule_created_session_discard(
        &mut self,
        socket: std::path::PathBuf,
        session_id: uuid::Uuid,
    ) {
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("side.discard"),
            AsyncActionPolicy::AllowConcurrent,
            move || {
                agent_runner::discard_session_blocking(&socket, session_id)
                    .map(|_| AsyncActionPayload::Unit)
            },
        );
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

        let start = self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("side.start"),
            AsyncActionPolicy::Dedupe(AsyncActionKey::new("side.start")),
            move || {
                let (session_id, short_id) =
                    agent_runner::fork_session_blocking(&socket, parent_session_id, None, true)?;
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    socket,
                    session_id,
                    short_id,
                    fork_point_seq: None,
                    seed_composer: None,
                })
            },
        );
        match start {
            AsyncActionStart::Started(_) => self.push_plain("/side: pending".to_string()),
            AsyncActionStart::Existing(_) => {
                self.history.push(HistoryEntry::CommandError {
                    line: "/side: side-conversation creation already pending".to_string(),
                });
            }
        }
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
            self.schedule_created_session_discard(socket, side_session_id);
            return;
        }
        if self.has_pending_session_switch_action() {
            self.schedule_created_session_discard(socket, side_session_id);
            self.report_session_switch_busy("/side");
            return;
        }
        let switch_task = match self.agent_runner.as_ref() {
            Some(Ok(runner)) if runner.can_switch_session() => Some(runner.switch_session_task(
                agent_runner::SessionTarget::Resume {
                    session_id: side_session_id,
                    since_seq: None,
                },
            )),
            _ => None,
        };
        if let Some(switch_task) = switch_task {
            let start = self.async_actions.start(
                AsyncActionKind::Internal("session.side"),
                Self::session_switch_action_policy(),
                async move {
                    switch_task
                        .await
                        .map(|outcome| AsyncActionPayload::SideSessionSwitched {
                            outcome: Box::new(outcome),
                            side_short_id,
                        })
                },
            );
            if matches!(start, AsyncActionStart::Existing(_)) {
                self.schedule_created_session_discard(socket, side_session_id);
                self.report_session_switch_busy("/side");
                return;
            }
            self.begin_ephemeral_session_switch_submission_target(
                agent_runner::SessionTarget::Resume {
                    session_id: side_session_id,
                    since_seq: None,
                },
                EphemeralSessionSwitchIntent::Side { parent_session_id },
            );

            let side = SideConversation {
                side_session_id,
                socket,
                saved_runner: None,
                saved_history: self.history.clone(),
                saved_history_render_versions: self.history_render_versions.clone(),
                saved_history_render_fingerprints: self.history_render_fingerprints.clone(),
                saved_history_render_cache: self.history_render_cache.clone(),
                saved_history_render_cache_rows: self.history_render_cache_rows,
                saved_queue: std::mem::take(&mut self.queue),
                saved_pending: self.pending.take(),
                saved_active_display_attempt_id: self.active_display_attempt_id.take(),
                saved_prunable_tokens: self.prunable_tokens,
                saved_cache_cold: self.cache_cold,
                saved_elided_event_ids: std::mem::take(&mut self.elided_event_ids),
                saved_active_schedules: std::mem::take(&mut self.active_schedules),
                saved_pending_stop_confirm: self.pending_stop_confirm.take(),
                saved_chat_scroll_offset: self.chat_scroll_offset,
                saved_chat_scroll_anchor: self.chat_scroll_anchor,
                saved_chat_pinned_to_tail: self.chat_pinned_to_tail,
                saved_project_id: self.project_id.clone(),
                saved_session_id: self.launch.session_id,
                saved_session_short_id: self.launch.session_short_id.clone(),
                saved_current_session_persisted: self.current_session_persisted,
            };
            self.current_session_persisted = false;
            self.queue.clear();
            self.pending = None;
            self.active_display_attempt_id = None;
            self.pending_render_cache = None;
            self.prunable_tokens = 0;
            self.cache_cold = true;
            self.elided_event_ids.clear();
            self.active_schedules.clear();
            self.pending_stop_confirm = None;
            self.pin_chat_to_tail();
            self.side_conversation = Some(side);
            return;
        }
        self.schedule_created_session_discard(socket, side_session_id);
        self.history.push(HistoryEntry::CommandError {
            line: "/side: active runner cannot switch sessions".to_string(),
        });
    }

    pub(super) fn restore_side_snapshot(&mut self, side: SideConversation) {
        if side.saved_runner.is_some() {
            self.agent_runner = side.saved_runner;
        }
        self.history = side.saved_history;
        self.history_render_versions = side.saved_history_render_versions;
        self.history_render_fingerprints = side.saved_history_render_fingerprints;
        self.restore_history_render_cache(
            side.saved_history_render_cache,
            side.saved_history_render_cache_rows,
        );
        self.queue = side.saved_queue;
        self.pending = side.saved_pending;
        self.active_display_attempt_id = side.saved_active_display_attempt_id;
        self.mark_chat_geometry_dirty_from(0);
        self.chat_find_lines.clear();
        self.chat_find_lines_query = None;
        self.prunable_tokens = side.saved_prunable_tokens;
        self.cache_cold = side.saved_cache_cold;
        self.elided_event_ids = side.saved_elided_event_ids;
        self.active_schedules = side.saved_active_schedules;
        self.pending_stop_confirm = side.saved_pending_stop_confirm;
        self.restore_chat_scroll_state(
            side.saved_chat_scroll_offset,
            side.saved_chat_scroll_anchor,
            side.saved_chat_pinned_to_tail,
        );
        self.project_id = side.saved_project_id;
        self.launch.session_id = side.saved_session_id;
        self.launch.session_short_id = side.saved_session_short_id;
        self.current_session_persisted = side.saved_current_session_persisted;
    }

    /// A destination other than the saved main session supersedes the side
    /// conversation. Discard its ephemeral row without first launching the
    /// normal side-return attach (which would compete for the shared switch
    /// key). Resume restores the main snapshot as a coherent fallback while
    /// its claimed switch is pending; `/new` is about to clear it anyway.
    pub(super) fn discard_side_conversation_for_replacement(&mut self, restore_main: bool) {
        let Some(side) = self.side_conversation.take() else {
            return;
        };
        self.schedule_created_session_discard(side.socket.clone(), side.side_session_id);
        if restore_main {
            self.restore_side_snapshot(side);
        }
    }

    /// End the open side conversation: restore the main-session view verbatim
    /// and discard the ephemeral fork (row + descendant forks). Unconditional
    /// — no "keep this fork?" prompt (that's `/fork`). `announce` controls the
    /// confirmation line; the process-exit path passes `false`.
    pub(super) fn end_side_conversation(&mut self, announce: bool) {
        if self.side_conversation.is_none() {
            return;
        }

        // Process exit only needs deterministic discard scheduling. Starting
        // a return attach here races teardown and can be deduplicated by an
        // unrelated switch whose result will never be rendered.
        if !announce {
            self.discard_side_conversation_for_replacement(false);
            return;
        }

        if self.has_pending_session_switch_action() {
            self.report_session_switch_busy("/side end");
            return;
        }

        let switch_task = self.side_conversation.as_ref().and_then(|side| {
            match (side.saved_session_id, self.agent_runner.as_ref()) {
                (Some(session_id), Some(Ok(runner)))
                    if side.saved_runner.is_none() && runner.can_switch_session() =>
                {
                    Some(
                        runner.switch_session_task(agent_runner::SessionTarget::Resume {
                            session_id,
                            since_seq: None,
                        }),
                    )
                }
                _ => None,
            }
        });

        if let Some(switch_task) = switch_task {
            let start = self.async_actions.start(
                AsyncActionKind::Internal("session.side.return"),
                Self::session_switch_action_policy(),
                async move {
                    switch_task
                        .await
                        .map(|outcome| AsyncActionPayload::SideSessionReturned(Box::new(outcome)))
                },
            );
            if matches!(start, AsyncActionStart::Existing(_)) {
                self.report_session_switch_busy("/side end");
                return;
            }
            let target_session_id = self
                .side_conversation
                .as_ref()
                .and_then(|side| side.saved_session_id)
                .expect("side return attach has a saved session target");
            self.begin_session_switch_submission_target(agent_runner::SessionTarget::Resume {
                session_id: target_session_id,
                since_seq: None,
            });
            // The return attach has only been claimed, not committed. Keep
            // the side snapshot, side UI, and ephemeral row intact until the
            // authoritative attach outcome is adopted.
            return;
        }

        // No attach is needed (for example, a saved standalone runner can be
        // restored directly), so this path can commit synchronously.
        let side = self
            .side_conversation
            .take()
            .expect("side preflight preserved conversation");
        self.schedule_created_session_discard(side.socket.clone(), side.side_session_id);
        self.restore_side_snapshot(side);
        // The daemonless ownership guard stays armed throughout — the side
        // fork lives on the same owned daemon, so it's never dropped and
        // needs no re-arming here.

        self.push_plain("Side conversation discarded — back in the main session.".to_string());
    }

    pub(super) fn complete_side_conversation_return(
        &mut self,
        outcome: agent_runner::SessionSwitchOutcome,
    ) {
        // Consume any old-side events while the side view is still installed.
        // The switch outcome's transition guard prevents a later old-epoch
        // event from appearing after this drain.
        self.drain_agent_events();
        let Some(side) = self.side_conversation.take() else {
            self.history.push(HistoryEntry::CommandError {
                line: "/side: return completed without an active side conversation".to_string(),
            });
            self.fail_pending_session_switch_submissions();
            return;
        };
        self.schedule_created_session_discard(side.socket.clone(), side.side_session_id);
        self.restore_side_snapshot(side);
        let current_session_persisted = self.current_session_persisted;
        self.apply_session_switch_outcome_preserving_history(outcome, current_session_persisted);
        self.flush_pending_session_switch_submissions();
        self.push_plain("Side conversation discarded — back in the main session.".to_string());
    }
}
