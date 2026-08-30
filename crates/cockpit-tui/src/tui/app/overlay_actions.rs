use super::*;

async fn resolve_notes_endpoint(
    lifecycle: cockpit_client::LifecycleClient,
) -> Result<cockpit_client::ClientEndpoint, String> {
    lifecycle
        .resolve_default()
        .await
        .map(|resolution| resolution.endpoint)
        .map_err(|error| format!("notes daemon lifecycle failed: {error}"))
}

pub(super) struct PendingLeakReveal {
    pub(super) operation_id: uuid::Uuid,
    pub(super) pane_instance_id: uuid::Uuid,
    pub(super) report_id: String,
    pub(super) generation: u64,
    pub(super) active: std::sync::Arc<std::sync::atomic::AtomicBool>,
    pub(super) receiver: std::sync::mpsc::Receiver<LeakRevealWorkerResult>,
}

pub(super) struct LeakRevealWorkerResult {
    operation_id: uuid::Uuid,
    pane_instance_id: uuid::Uuid,
    report_id: String,
    generation: u64,
    result: Result<
        cockpit_core::daemon::leak_reveal::RevealedLeakSecret,
        cockpit_core::daemon::leak_reveal::LeakRevealDenied,
    >,
}

fn canonical_leak_capability(value: &str) -> bool {
    value.len() == 64
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn cancel_leak_capability_blocking(
    endpoint: &cockpit_client::ClientEndpoint,
    capability: cockpit_proto::LeakRevealToken,
    expected_report_id: &str,
) -> bool {
    matches!(
        crate::tui::agent_runner::daemon_request_at_blocking(
            endpoint,
            cockpit_proto::Request::CancelLeakReveal { capability },
        ),
        Ok(cockpit_proto::Response::LeakRevealCancelled { report_id })
            if report_id == expected_report_id
    )
}

impl App {
    /// Open the project scratchpad dialog. Shared by the `/scratchpad`
    /// slash command and the Ctrl+N keyboard shortcut. The editor mirrors the
    /// composer's vim setting so vim users get vim editing in their scratchpad.
    pub(super) fn open_scratchpad_pane(&mut self) {
        let mut pane =
            crate::tui::notes_pane::NotesPane::open(&self.launch.cwd, self.composer.vim_enabled());
        let action = pane.initial_load_action();
        self.overlay = Overlay::Notes(pane);
        self.start_notes_rpc_action(action);
    }

    pub(super) fn start_notes_rpc_action(
        &mut self,
        action: crate::tui::notes_pane::NotesRpcAction,
    ) {
        let lifecycle = self.lifecycle.clone();
        let kind = crate::tui::async_action::AsyncActionKind::NotesProjection {
            instance_id: action.instance_id(),
            generation: action.generation(),
        };
        let key = crate::tui::async_action::AsyncActionKey::new(action.serialization_key());
        self.async_actions.start_serialized(kind, key, async move {
            let endpoint = resolve_notes_endpoint(lifecycle).await?;
            let result = tokio::task::spawn_blocking(move || action.run_blocking_rpc(endpoint))
                .await
                .map_err(|error| format!("notes rpc worker failed: {error}"))?;
            result
                .map(crate::tui::async_action::AsyncActionPayload::NotesRpc)
                .map_err(|error| error.to_string())
        });
    }

    /// Open the `/leaks` pane (replacing the interim transcript list) and kick
    /// off the first-page metadata load.
    pub(super) fn open_leaks_pane(&mut self) {
        self.cancel_pending_leak_reveal();
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
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            return;
        };
        self.async_actions.start_blocking(
            crate::tui::async_action::AsyncActionKind::Internal("leaks.rpc"),
            crate::tui::async_action::AsyncActionPolicy::AllowConcurrent,
            move || {
                action
                    .run_blocking_rpc(endpoint)
                    .map(crate::tui::async_action::AsyncActionPayload::LeaksRpc)
            },
        );
    }

    /// Reveal a leak secret and install it into the open `LeaksPane` buffer.
    /// The plaintext is produced on a blocking worker (begin RPC →
    /// sensitive-channel reveal) and handed through a private one-shot channel
    /// into the pane's zeroizing buffer. It never crosses an
    /// `AsyncActionPayload`, the transcript, or any cache.
    pub(super) fn reveal_leak_into_pane(
        &mut self,
        pane_instance_id: uuid::Uuid,
        report_id: String,
        generation: u64,
    ) {
        if self.pending_leak_reveal.is_some() {
            if let Overlay::Leaks(pane) = &mut self.overlay {
                pane.set_reveal_error("a reveal is already pending");
            }
            return;
        }
        let Some(endpoint) = self.attached_daemon_endpoint() else {
            if let Overlay::Leaks(pane) = &mut self.overlay {
                pane.set_reveal_error("daemon detached — reveal unavailable");
            }
            return;
        };
        let operation_id = uuid::Uuid::new_v4();
        let active = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let worker_active = std::sync::Arc::clone(&active);
        let worker_report_id = report_id.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let _ = tokio::task::spawn_blocking(move || {
            let result = (|| {
                let capability = match crate::tui::agent_runner::daemon_request_at_blocking(
                    &endpoint,
                    cockpit_proto::Request::BeginLeakReveal {
                        report_id: worker_report_id.clone(),
                    },
                ) {
                    Ok(cockpit_proto::Response::LeakRevealCapability { capability }) => capability,
                    _ => {
                        return Err(
                            cockpit_core::daemon::leak_reveal::LeakRevealDenied::Unauthorized,
                        );
                    }
                };
                let now_ms = chrono::Utc::now().timestamp_millis();
                let binding_valid = capability.report_id == worker_report_id
                    && canonical_leak_capability(capability.capability.as_str())
                    && capability.expires_at_ms > now_ms
                    && capability.expires_at_ms
                        <= now_ms
                            .saturating_add(cockpit_core::leaks::LEAK_REVEAL_CAPABILITY_TTL_MS);
                if !binding_valid || !worker_active.load(std::sync::atomic::Ordering::Acquire) {
                    let settled = cancel_leak_capability_blocking(
                        &endpoint,
                        capability.capability,
                        &capability.report_id,
                    );
                    return Err(if settled {
                        cockpit_core::daemon::leak_reveal::LeakRevealDenied::Unauthorized
                    } else {
                        cockpit_core::daemon::leak_reveal::LeakRevealDenied::Internal
                    });
                }
                let token = capability.capability;
                let reveal =
                    crate::tui::agent_runner::daemon_reveal_leak_blocking(&endpoint, &token);
                if reveal.is_err() {
                    // `RateLimited` and unavailable-channel paths do not consume
                    // the slot. An authorization failure may already have spent
                    // it; exact cancel then harmlessly fails closed.
                    let _ = cancel_leak_capability_blocking(&endpoint, token, &worker_report_id);
                }
                reveal
            })();
            let _ = sender.send(LeakRevealWorkerResult {
                operation_id,
                pane_instance_id,
                report_id: worker_report_id,
                generation,
                result,
            });
        });
        self.pending_leak_reveal = Some(PendingLeakReveal {
            operation_id,
            pane_instance_id,
            report_id,
            generation,
            active,
            receiver,
        });
    }

    /// Invalidate an in-flight reveal before its sensitive-channel step. The
    /// worker retains and receipt-settles the exact token it minted.
    pub(super) fn cancel_pending_leak_reveal(&mut self) {
        if let Some(pending) = self.pending_leak_reveal.take() {
            pending
                .active
                .store(false, std::sync::atomic::Ordering::Release);
        }
    }

    pub(super) fn drain_leak_reveal(&mut self) -> bool {
        let Some(pending) = self.pending_leak_reveal.as_ref() else {
            return false;
        };
        let worker = match pending.receiver.try_recv() {
            Ok(result) => result,
            Err(std::sync::mpsc::TryRecvError::Empty) => return false,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => LeakRevealWorkerResult {
                operation_id: pending.operation_id,
                pane_instance_id: pending.pane_instance_id,
                report_id: pending.report_id.clone(),
                generation: pending.generation,
                result: Err(cockpit_core::daemon::leak_reveal::LeakRevealDenied::Internal),
            },
        };
        let pending = self
            .pending_leak_reveal
            .take()
            .expect("leak reveal pending checked");
        tracing::debug!(operation_id = %pending.operation_id, "leak reveal worker settled");
        if worker.operation_id != pending.operation_id
            || worker.pane_instance_id != pending.pane_instance_id
            || worker.report_id != pending.report_id
            || worker.generation != pending.generation
        {
            return false;
        }
        let Overlay::Leaks(pane) = &mut self.overlay else {
            return false;
        };
        if pane.instance_id() != pending.pane_instance_id {
            return false;
        }
        match worker.result {
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

#[cfg(test)]
mod notes_lifecycle_tests {
    use super::resolve_notes_endpoint;

    #[tokio::test]
    async fn endpoint_resolution_requests_configured_default_exactly_once() {
        let (client, mut requests) = cockpit_client::LifecycleClient::channel(2);
        let client = client.with_default_intent(cockpit_client::LifecycleIntent::AttachOrEphemeral);
        let resolve = tokio::spawn(resolve_notes_endpoint(client));
        let request = requests.recv().await.expect("one lifecycle request");
        assert_eq!(
            request.intent,
            cockpit_client::LifecycleIntent::AttachOrEphemeral
        );
        let (connections, _connection_requests) = tokio::sync::mpsc::channel(1);
        let (sensitive, _sensitive_requests) = tokio::sync::mpsc::channel(1);
        assert!(
            request
                .reply
                .send(Ok(cockpit_client::LifecycleResolution {
                    endpoint: cockpit_client::ClientEndpoint::InProcess(
                        cockpit_client::InProcessEndpoint::new(connections, sensitive),
                    ),
                    owns_daemon: false,
                    socket: std::path::PathBuf::from("in-process"),
                    startup_notice: None,
                }))
                .is_ok()
        );
        let endpoint = resolve.await.expect("resolver task").expect("endpoint");
        assert!(matches!(
            endpoint,
            cockpit_client::ClientEndpoint::InProcess(_)
        ));
        assert!(
            requests.try_recv().is_err(),
            "later attachment must not duplicate a settled intent"
        );
    }

    #[tokio::test]
    async fn lifecycle_failure_is_a_correlated_worker_error() {
        let (client, mut requests) = cockpit_client::LifecycleClient::channel(1);
        let resolve = tokio::spawn(resolve_notes_endpoint(client));
        let request = requests.recv().await.expect("lifecycle request");
        assert!(request.reply.send(Err("attach unavailable".into())).is_ok());
        let result = resolve.await.expect("resolver task");
        let Err(error) = result else {
            panic!("resolution must fail");
        };
        assert!(error.contains("attach unavailable"));
        assert!(requests.try_recv().is_err());
    }
}

#[cfg(test)]
mod leak_capability_tests {
    use super::canonical_leak_capability;

    #[test]
    fn capability_grammar_is_exact_lowercase_hex() {
        assert!(canonical_leak_capability(&"ab".repeat(32)));
        assert!(!canonical_leak_capability(&"AB".repeat(32)));
        assert!(!canonical_leak_capability(&"ag".repeat(32)));
        assert!(!canonical_leak_capability(&"ab".repeat(31)));
        assert!(!canonical_leak_capability(&"ab".repeat(33)));
    }
}
