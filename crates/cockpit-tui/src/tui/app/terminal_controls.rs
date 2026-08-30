use super::*;

impl App {
    /// One process-wide authority fence for every user-requested exit path.
    /// Read-only projection loads are intentionally absent. Operations that
    /// can have changed durable or host-published state remain represented by
    /// their exact owner/correlation until a terminal receipt is applied.
    pub(super) fn has_unsettled_local_authority(&self) -> bool {
        self.pending_workspace_trust.is_some()
            || self.dialog.has_unsettled_local_authority()
            || self.overlay.has_unsettled_local_authority()
            || self.pending_mcp_local.is_some()
            || self.pending_leak_reveal.is_some()
            || self.pending_runner_attach.is_some()
            || self.pending_model_selection.is_some()
            || self.pending_default_model_update_id.is_some()
            || !self.pending_control_requests.is_empty()
            || !self.pending_usage.is_empty()
            || !self.settings_blocking_actions.is_empty()
            || self.async_actions.has_unsettled_local_authority()
            || !self.image_ingress_draft_discards.is_empty()
    }

    /// Return true only when shutdown may surrender all local authority.
    /// A blocked exit leaves every owner ID and lease in place for its normal
    /// completion/reconciliation path.
    pub(super) fn request_guarded_exit(&mut self) -> bool {
        if self.has_unsettled_local_authority() {
            self.show_toast(
                "Exit is waiting for a local operation to reach a verified terminal state",
                ToastKind::Info,
            );
            false
        } else if self.has_live_work_for_exit_guard() {
            if self.exit_owner_is_ephemeral() {
                self.open_exit_guard_prompt();
                false
            } else {
                let notice = format!(
                    "This session is still running in the background; reattach with {}",
                    self.exit_reattach_command()
                );
                self.exit_notice = Some(notice.clone());
                self.show_toast(notice, ToastKind::Info);
                true
            }
        } else {
            true
        }
    }

    fn has_live_work_for_exit_guard(&self) -> bool {
        self.busy || !self.active_schedules.is_empty()
    }

    fn exit_owner_is_ephemeral(&self) -> bool {
        self.agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .is_some_and(|runner| runner.ephemeral_owner)
    }

    pub(super) fn exit_reattach_command(&self) -> String {
        self.agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok())
            .map(crate::tui::agent_runner::AgentRunner::session_id)
            .or(self.launch.session_id)
            .map(|session_id| format!("cockpit run --session {session_id}"))
            .unwrap_or_else(|| "cockpit".to_string())
    }

    fn open_exit_guard_prompt(&mut self) {
        use cockpit_proto::{InterruptOption, InterruptQuestion, InterruptQuestionSet};

        let interrupt_id = uuid::Uuid::new_v4();
        self.pending_local_choice = Some(LocalChoice::ExitGuard(interrupt_id));
        self.question_dialog = Some(
            crate::tui::dialog::question::QuestionDialog::new(
                interrupt_id,
                String::new(),
                InterruptQuestionSet {
                    questions: vec![InterruptQuestion::Single {
                        prompt: "This session is still working. What would you like to do?"
                            .to_string(),
                        options: vec![
                            InterruptOption {
                                id: "stop_all".to_string(),
                                label: "Stop all".to_string(),
                                description: Some(
                                    "Cancel work and stop the ephemeral daemon.".to_string(),
                                ),
                                secondary: false,
                            },
                            InterruptOption {
                                id: "background".to_string(),
                                label: "Run in background".to_string(),
                                description: Some(
                                    "Keep work running and make this daemon persistent."
                                        .to_string(),
                                ),
                                secondary: false,
                            },
                        ],
                        allow_freetext: false,
                        command_detail: None,
                        permission: false,
                        approval_class: None,
                        sandbox_escalation: None,
                    }],
                },
                self.dialog_lockout(),
            )
            .with_keyboard_enhancement_active(self.keyboard_enhancement_active),
        );
    }

    pub(super) fn resolve_exit_guard_choice(&mut self, selected: Option<&str>) {
        match selected {
            Some("stop_all") => self.send_daemon_request(
                "stop all",
                // Cancel only this attached session.  If this detach leaves
                // an ephemeral owner without clients, its reference-counted
                // reaper performs the daemon-wide process cleanup; shared
                // clients otherwise keep their daemon and work alive.
                cockpit_proto::Request::CancelTurn,
                ControlApplied::ExitAfterStoppingWork,
            ),
            Some("background") => self.send_daemon_request(
                "run in background",
                cockpit_proto::Request::PromoteToPersistent,
                ControlApplied::ExitAfterBackgroundPromotion,
            ),
            _ => self.show_toast("Exit cancelled", ToastKind::Info),
        }
    }

    /// Handle a ctrl+c press (GOALS §3a). Single press interrupts a
    /// running agent (never quits); a second press within
    /// [`CTRL_C_EXIT_WINDOW`] of the previous exits. Returns `true` to
    /// exit the TUI (the event loop breaks). Drives the double-press
    /// state machine via the pure [`decide_ctrl_c`] unit, sends the
    /// daemon `CancelTurn` on an interrupt, and shows the transient exit
    /// hint via the existing toast mechanism.
    pub(super) fn handle_ctrl_c(&mut self) -> bool {
        let (action, new_armed) = decide_ctrl_c(
            Instant::now(),
            self.ctrl_c_armed_at,
            CTRL_C_EXIT_WINDOW,
            self.busy,
        );
        self.ctrl_c_armed_at = new_armed;
        match action {
            CtrlCAction::Exit => self.request_guarded_exit(),
            CtrlCAction::ArmAndInterrupt => {
                self.interrupt_agent();
                self.end_working_span();
                // A ctrl+c cancels the whole working span the user is looking
                // at — including any messages they queued *during* it (typed +
                // submitted while the turn was in flight). The daemon discards
                // those un-dispatched queued messages on cancel so it returns
                // to idle rather than rolling straight into the next one; clear
                // our mirror of the queue here so the pending rows above the
                // composer disappear in lockstep and don't masquerade as still
                self.queue.clear();
                self.show_ctrl_c_hint();
                false
            }
            CtrlCAction::ArmOnly => {
                self.show_ctrl_c_hint();
                false
            }
        }
    }

    /// Send the daemon a `CancelTurn` for the attached session (GOALS
    /// §3a). The daemon aborts the in-flight inference and kills any running
    /// `bash` subprocess; the resulting `AgentIdle` clears `busy`.
    pub(super) fn interrupt_agent(&mut self) {
        self.send_daemon_request(
            "interrupt",
            cockpit_proto::Request::CancelTurn,
            ControlApplied::None,
        );
    }

    /// Show the transient "press ctrl+c again to exit" hint. Reuses the
    /// status-line toast; its TTL is the exit window so it disappears
    /// exactly when a second press would no longer exit.
    fn show_ctrl_c_hint(&mut self) {
        self.toast = Some(Toast {
            text: "Press ctrl+c again to exit".to_string(),
            kind: ToastKind::Info,
            expires_at: Instant::now() + CTRL_C_EXIT_WINDOW,
            persistent: false,
        });
    }

    /// Disarm the ctrl+c exit window once it has lapsed. Called once per
    /// event-loop tick so a lone press auto-resets to a fresh first press
    /// without needing another event. The hint toast self-expires on the
    /// same TTL via [`Self::tick_toast`].
    pub(super) fn tick_ctrl_c_window(&mut self) -> bool {
        if let Some(armed) = self.ctrl_c_armed_at
            && Instant::now().duration_since(armed) > CTRL_C_EXIT_WINDOW
        {
            self.ctrl_c_armed_at = None;
            return true;
        }
        false
    }

    /// Flip `tui.mouse_capture` on disk, push/pop the live terminal
    /// state, and return a status line for the chat log. Used by the
    /// `/mouse` slash command (T8.c). Save errors degrade gracefully:
    /// we still flip the live state and report the error in the
    /// status line so the user knows the change isn't persistent.
    /// Toggle the *live* mouse-capture state and surface a toast.
    /// `/mouse` is intentionally non-persistent — useful for "try
    /// capture off for one operation" without affecting the
    /// configured default for the next session. The persistent
    /// toggle lives in `/settings → ui`.
    pub(super) fn toggle_mouse_capture_inline(&mut self) {
        let new_value = !self.mouse_capture;
        let exec_ok = if new_value {
            enable_mouse_capture_with_motion().is_ok()
        } else {
            disable_mouse_capture_with_motion().is_ok()
        };
        if exec_ok {
            self.mouse_capture = new_value;
            self.invalidate_primary_paste();
            if !new_value {
                self.hovered_affordance = None;
            }
            let state = if new_value { "on" } else { "off" };
            self.show_toast(
                format!("/mouse: capture {state} (this session only)"),
                ToastKind::Info,
            );
        } else {
            self.show_toast(
                "/mouse: terminal rejected the capture toggle",
                ToastKind::Error,
            );
        }
    }

    /// Pick up a pending mouse-capture toggle from the settings dialog
    /// (UI page) and push/pop the crossterm capture state to match.
    /// The setting itself is persisted by the dialog's save path; this
    /// just keeps the live terminal state in sync.
    pub(super) fn sync_mouse_capture_from_dialog(&mut self) {
        let Some(want) = self.dialog.take_pending_mouse_capture() else {
            return;
        };
        self.set_mouse_capture_live(want);
    }

    fn set_mouse_capture_live(&mut self, want: bool) {
        if want == self.mouse_capture {
            return;
        }
        let res = if want {
            enable_mouse_capture_with_motion()
        } else {
            disable_mouse_capture_with_motion()
        };
        if res.is_ok() {
            self.mouse_capture = want;
            self.invalidate_primary_paste();
            if !want {
                self.link_pointer_gesture.cancel();
                self.hovered_affordance = None;
                self.hovered_suggestion = None;
                self.link_registry.clear_hover();
                self.dialog.clear_settings_pointer_hover();
            }
        }
    }

    pub(super) fn drain_fetch_progress(&mut self) -> bool {
        let drained: Vec<String> = match self.fetch_models_progress.lock() {
            Ok(mut buf) if !buf.is_empty() => buf.drain(..).collect(),
            _ => return false,
        };
        let touches_config = drained
            .iter()
            .any(|l| l.contains("model(s)") || l.ends_with(": done"));
        for line in drained {
            if let Some(rest) = line.strip_prefix("/fetch-models: provider ")
                && line.contains(" provider model(s)")
                && let Some(provider) = rest.split_whitespace().next()
            {
                self.clear_auth_failures_for_provider(provider);
            }
            self.push_plain(line);
        }
        if touches_config {
            self.resync_config_after_local_write();
        }
        true
    }
}
