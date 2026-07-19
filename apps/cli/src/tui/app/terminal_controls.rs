use super::*;

impl App {
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
            CtrlCAction::Exit => true,
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
    /// §3a). Fire-and-forget over the runner's request channel — same
    /// path `/schedule cancel` uses. No-op (and harmless) when no runner is
    /// connected. The daemon aborts the in-flight inference and kills any
    /// running `bash` subprocess; the resulting `AgentIdle` clears `busy`.
    pub(super) fn interrupt_agent(&self) {
        self.send_daemon_request(crate::daemon::proto::Request::CancelTurn);
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
            if !want {
                self.hovered_affordance = None;
                self.hovered_suggestion = None;
                self.link_registry.clear_hover();
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
            self.reload_launch_info();
        }
        true
    }
}
