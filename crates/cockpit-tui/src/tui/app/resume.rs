use super::*;

impl App {
    /// Send the answering dialog's outcome back to the daemon (GOALS
    /// §3b). Both submit and cancel become a `ResolveInterrupt` — cancel
    /// carries `ResolveResponse::Cancel`, which the worker fans out to a
    /// per-question `Cancel` so the blocked `question` tool unblocks with
    /// dismissed answers.
    pub(super) fn resolve_question_dialog(
        &mut self,
        result: crate::tui::dialog::question::QuestionResult,
    ) {
        use crate::tui::dialog::question::QuestionResult;
        use cockpit_core::daemon::proto::{Request, ResolveResponse};
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
            self.send_daemon_request("question", request, ControlApplied::None);
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
        self.send_daemon_request(
            "/prune",
            cockpit_core::daemon::proto::Request::Prune,
            ControlApplied::None,
        );
    }

    /// Cancel an armed `/prune`.
    pub(super) fn cancel_prune(&mut self) {
        self.pending_prune_confirm = false;
        self.push_plain("/prune: cancelled.".to_string());
    }

    /// `/compact`: enqueue an in-place compaction turn on the active session.
    pub(super) fn start_compact(&mut self) {
        let submission = cockpit_core::engine::message::UserSubmission::compact_notice();
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
                self.launch.session_id = Some(runner.session_id());
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

    pub(super) fn maybe_prompt_paused_work(
        &mut self,
        session_id: uuid::Uuid,
        paused_work: Vec<cockpit_core::daemon::proto::PausedWorkSummary>,
    ) {
        if paused_work.is_empty() {
            return;
        }
        use cockpit_core::daemon::proto::{
            InterruptOption, InterruptQuestion, InterruptQuestionSet,
        };
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

    pub(super) fn maybe_prompt_resume_repair(
        &mut self,
        state: cockpit_core::daemon::proto::ResumeRepairState,
    ) {
        use cockpit_core::daemon::proto::{
            InterruptOption, InterruptQuestion, InterruptQuestionSet,
        };
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

    pub(super) fn resolve_resume_repair_choice(
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
                    Some(Ok(runner)) => (runner.session_id(), runner.socket.clone()),
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
                self.send_daemon_request(
                    "/resume",
                    cockpit_core::daemon::proto::Request::RepairResume {
                        session_id: pending.state.session_id,
                    },
                    ControlApplied::None,
                );
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

    pub(super) fn maybe_show_daemon_version_chip(
        &mut self,
        daemon_version: &str,
        compatible: bool,
    ) {
        if compatible || daemon_version == cockpit_core::daemon::proto::DAEMON_VERSION {
            return;
        }
        self.push_plain(format!(
            "daemon {daemon_version} is newer than this client {}; relaunch cockpit to refresh",
            cockpit_core::daemon::proto::DAEMON_VERSION
        ));
    }
}
