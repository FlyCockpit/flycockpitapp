use super::*;

pub(super) struct PendingLeakReveal {
    pub(super) operation_id: uuid::Uuid,
    pub(super) report_id: String,
    pub(super) generation: u64,
    pub(super) receiver: std::sync::mpsc::Receiver<
        Result<
            cockpit_core::daemon::leak_reveal::RevealedLeakSecret,
            cockpit_core::daemon::leak_reveal::LeakRevealDenied,
        >,
    >,
}

impl App {
    /// Open the project scratchpad dialog. Shared by the `/scratchpad`
    /// slash command and the Ctrl+N keyboard shortcut. The editor mirrors the
    /// composer's vim setting so vim users get vim editing in their scratchpad.
    pub(super) fn open_scratchpad_pane(&mut self) {
        let pane = crate::tui::notes_pane::NotesPane::open(
            &self.launch.cwd,
            self.composer.vim_enabled(),
            self.startup_background.daemon_socket.clone(),
        );
        let action = pane.initial_load_action();
        self.overlay = Overlay::Notes(pane);
        if let Some(action) = action {
            self.start_notes_rpc_action(action);
        }
    }

    pub(super) fn start_notes_rpc_action(
        &mut self,
        action: crate::tui::notes_pane::NotesRpcAction,
    ) {
        self.async_actions.start_blocking(
            crate::tui::async_action::AsyncActionKind::Internal("notes.rpc"),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            move || {
                action
                    .run()
                    .map(crate::tui::async_action::AsyncActionPayload::NotesRpc)
                    .map_err(|e| e.to_string())
            },
        );
    }

    /// Open the `/leaks` pane (replacing the interim transcript list) and kick
    /// off the first-page metadata load.
    pub(super) fn open_leaks_pane(&mut self) {
        let pane =
            crate::tui::leaks_pane::LeaksPane::open(self.startup_background.daemon_socket.clone());
        let action = pane.initial_load_action();
        self.overlay = Overlay::Leaks(pane);
        if let Some(action) = action {
            self.start_leaks_rpc_action(action);
        }
    }

    pub(super) fn start_leaks_rpc_action(
        &mut self,
        action: crate::tui::leaks_pane::LeaksRpcAction,
    ) {
        self.async_actions.start_blocking(
            crate::tui::async_action::AsyncActionKind::Internal("leaks.rpc"),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            move || {
                action
                    .run()
                    .map(crate::tui::async_action::AsyncActionPayload::LeaksRpc)
            },
        );
    }

    /// Reveal a leak secret and install it into the open `LeaksPane` buffer.
    /// The plaintext is produced on a blocking worker (begin RPC →
    /// sensitive-channel reveal) and handed through a private one-shot channel
    /// into the pane's zeroizing buffer. It never crosses an
    /// `AsyncActionPayload`, the transcript, or any cache.
    pub(super) fn reveal_leak_into_pane(&mut self, report_id: String, generation: u64) {
        let Some(socket) = self.startup_background.daemon_socket.clone() else {
            if let Overlay::Leaks(pane) = &mut self.overlay {
                pane.set_reveal_error("daemon detached — reveal unavailable");
            }
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        let worker_report_id = report_id.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        tokio::task::spawn_blocking(move || {
            let result = (|| {
                let capability = match crate::tui::agent_runner::daemon_request_at_blocking(
                    &socket,
                    cockpit_core::daemon::proto::Request::BeginLeakReveal {
                        report_id: worker_report_id,
                    },
                ) {
                    Ok(cockpit_core::daemon::proto::Response::LeakRevealCapability {
                        capability,
                    }) => capability.capability,
                    _ => {
                        return Err(
                            cockpit_core::daemon::leak_reveal::LeakRevealDenied::Unauthorized,
                        );
                    }
                };
                crate::tui::agent_runner::daemon_reveal_leak_blocking(&socket, &capability)
            })();
            let _ = sender.send(result);
        });
        self.pending_leak_reveal = Some(PendingLeakReveal {
            operation_id,
            report_id,
            generation,
            receiver,
        });
    }

    pub(super) fn drain_leak_reveal(&mut self) -> bool {
        let Some(pending) = self.pending_leak_reveal.as_ref() else {
            return false;
        };
        let result = match pending.receiver.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return false,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                Err(cockpit_core::daemon::leak_reveal::LeakRevealDenied::Internal)
            }
        };
        let pending = self
            .pending_leak_reveal
            .take()
            .expect("leak reveal pending checked");
        tracing::debug!(operation_id = %pending.operation_id, "leak reveal worker settled");
        let Overlay::Leaks(pane) = &mut self.overlay else {
            return false;
        };
        match result {
            Ok(secret) => {
                if secret.report_id == pending.report_id {
                    pane.install_reveal(secret.plaintext, secret.report_id, pending.generation);
                } else {
                    pane.set_reveal_error("reveal denied");
                }
                // A new reveal replaced the buffer; request a full clear so the
                // prior frame's cells (if any) don't linger.
                self.leaks_reveal_clear_pending = true;
            }
            Err(denied) => {
                use cockpit_core::daemon::leak_reveal::LeakRevealDenied;
                let message = match denied {
                    LeakRevealDenied::RateLimited => "rate limited — try again shortly",
                    LeakRevealDenied::UnavailablePlatform => "reveal unavailable on this platform",
                    LeakRevealDenied::Unauthorized => "reveal denied",
                    LeakRevealDenied::Internal => "reveal failed",
                };
                pane.set_reveal_error(message);
            }
        }
        true
    }

    /// The active TUI context the which-key overlay should describe
    /// (`which-key-overlay.md`). Resolved from the live modal / pane state in
    /// the same priority order the key router uses, so the overlay always
    /// names the context whose keys are actually live. A required-decision
    /// dialog (approval / question) wins — the leader is routed *after* those
    /// handlers, so this is only ever consulted when the overlay is allowed to
    /// open, but the resolver keeps the priority explicit so the overlay shows
    /// that dialog's keys when reached via `/keys`.
    pub(super) fn key_context(&self) -> crate::tui::keys_overlay::KeyContext {
        use crate::tui::keys_overlay::KeyContext;
        if self.btw_pane.as_ref().is_some_and(|pane| pane.focused) {
            KeyContext::BtwPane
        } else if self.pane.is_some() {
            KeyContext::EmbeddedPane
        } else if let Some(dialog) = self.question_dialog.as_ref() {
            // The approval dialog is a `question`-tool interrupt rendered
            // through the same dialog widget; both are required decisions sharing
            // the question-dialog routing. A command/permission approval carries
            // a `command_detail` block and shows `y/n` decision keys, so it maps
            // to the dedicated `ApprovalDialog` context; every other interrupt is
            // a plain `QuestionDialog`.
            if dialog.is_approval() {
                KeyContext::ApprovalDialog
            } else {
                KeyContext::QuestionDialog
            }
        } else if self.dialog.is_active() {
            KeyContext::Settings
        } else if let Some(context) = self.overlay.key_context() {
            context
        } else if self.pins_review.is_some()
            || self.pin_pick.is_some()
            || self.fork_pick.is_some()
            || self.copy_pick.is_some()
        {
            KeyContext::Pins
        } else if self.slash_query().is_some() {
            KeyContext::SlashMenu
        } else {
            KeyContext::Composer
        }
    }

    /// Open (or, when already open, close) the which-key overlay over the
    /// current context (`which-key-overlay.md`). The leader key and `/keys`
    /// both route here. Pure TUI state: nothing is sent to the agent and
    /// nothing enters history or any inference request.
    pub(super) fn toggle_keys_overlay(&mut self) {
        if self.keys_overlay.is_some() {
            self.keys_overlay = None;
            return;
        }
        let context = self.key_context();
        self.keys_overlay = Some(
            crate::tui::keys_overlay::KeysOverlay::open_with_keyboard_enhancement(
                context,
                self.keyboard_enhancement_active,
            ),
        );
    }
}
