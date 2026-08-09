use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StartupDisclosureIdentity<'a> {
    project_root: &'a str,
    generation: u64,
    socket: Option<&'a std::path::Path>,
    launch_session_id: Option<uuid::Uuid>,
    attachment: Option<(uuid::Uuid, u64)>,
}

fn startup_disclosure_completion_is_current(
    current: StartupDisclosureIdentity<'_>,
    completed: StartupDisclosureIdentity<'_>,
) -> bool {
    current == completed
}

fn reconnectable_session_switch_error(error: &str) -> bool {
    error.contains("connection closed")
        || error.contains("broken pipe")
        || error.contains("connection reset")
}

fn floor_char_boundary(text: &str, requested: usize) -> usize {
    let mut offset = requested.min(text.len());
    while !text.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

impl App {
    pub(super) fn drain_async_actions(&mut self) -> bool {
        let results = self.async_actions.drain_completed();
        let changed = !results.is_empty();
        let oauth_completed = results.iter().any(|result| {
            matches!(
                result.kind,
                AsyncActionKind::Internal("oauth.codex.poll" | "oauth.grok.complete")
            )
        });
        for result in results {
            self.apply_async_action_result(result);
        }
        // OAuth completion writes credentials asynchronously while its dialog
        // remains open. Fingerprint reconciliation is deliberately performed
        // after applying the result; failed/cancelled flows leave the stored
        // fingerprint unchanged and therefore retain the annotation.
        if oauth_completed {
            self.clear_changed_provider_auth_failures();
        }
        changed
    }

    pub(super) fn apply_async_action_result(&mut self, result: AsyncActionResult) {
        match result.kind {
            AsyncActionKind::DaemonRpc("sessions.list") => {
                let mut live_ids = None;
                let mut preview_request = None;
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::Sessions(sessions)) => Ok(sessions),
                        Ok(_) => Err("unexpected daemon response".to_string()),
                        Err(e) => Err(e),
                    };
                    let ids = pane.apply_sessions_result(payload);
                    if !ids.is_empty() {
                        live_ids = Some(ids);
                    }
                    if pane.is_preview_enabled()
                        && let Some(crate::tui::sessions_pane::SessionsOutcome::LoadPreview {
                            session_id,
                            before_seq,
                        }) = pane.ensure_preview_for_selection()
                    {
                        preview_request = Some((session_id, before_seq));
                    }
                }
                if let Some(ids) = live_ids {
                    self.start_sessions_live_status_action(ids);
                }
                if let Some((session_id, before_seq)) = preview_request {
                    self.start_sessions_preview_action(session_id, before_seq);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.live") => {
                if let Overlay::Sessions(pane) = &mut self.overlay
                    && let Ok(AsyncActionPayload::SessionLiveStatus(live)) = result.payload
                {
                    pane.apply_live_status(live);
                }
            }
            AsyncActionKind::DaemonRpc("sessions.preview") => {
                if let Overlay::Sessions(pane) = &mut self.overlay {
                    match result.payload {
                        Ok(AsyncActionPayload::SessionMessages {
                            session_id,
                            before_seq,
                            messages,
                            has_more,
                        }) => pane.apply_preview_result(
                            session_id,
                            before_seq,
                            Ok((messages, has_more)),
                        ),
                        Err(error) => {
                            if let Some((session_id, before_seq)) = pane.take_preview_load() {
                                pane.apply_preview_result(session_id, before_seq, Err(error));
                            }
                        }
                        Ok(_) => {}
                    }
                }
            }
            AsyncActionKind::DaemonRpc("skills.list") => {
                if let Ok(AsyncActionPayload::Skills(result)) = result.payload {
                    if let Some(bundle) = result.bundle.clone() {
                        self.apply_inventory_bundle_response(bundle);
                    }
                    if let Overlay::Skills(pane) = &mut self.overlay {
                        pane.apply_fetch_result(result);
                    }
                }
            }
            AsyncActionKind::DaemonRpc("inventory.bundle") => match result.payload {
                Ok(AsyncActionPayload::InventoryBundle(response)) => {
                    self.apply_inventory_bundle_response(response);
                }
                Err(error) => {
                    if let Some(ticket) = self.inventory.in_flight.clone() {
                        self.inventory.apply_failure(&ticket, error);
                    }
                }
                _ => {}
            },
            AsyncActionKind::DaemonRpc("guidance.estimate") => {
                if let Ok(AsyncActionPayload::GuidanceEstimate(estimate)) = result.payload {
                    self.guidance_estimate = Some(estimate);
                }
            }
            AsyncActionKind::Internal("startup.guidance.estimate") => {
                if let Ok(AsyncActionPayload::StartupGuidanceEstimate {
                    cwd,
                    active_model,
                    estimate,
                }) = result.payload
                {
                    self.apply_startup_guidance_estimate(cwd, active_model, estimate);
                }
            }
            AsyncActionKind::Internal("paste.image_path_probe") => match result.payload {
                Ok(AsyncActionPayload::ImagePathProbe {
                    request_id,
                    request_generation,
                    terminal_generation,
                    original: _,
                    source_draft_generation,
                    cursor,
                    png: Some(png),
                }) if terminal_generation == self.terminal_input_generation => {
                    self.settle_paste_probe(
                        request_id,
                        request_generation,
                        source_draft_generation,
                        cursor,
                        Some(png),
                        false,
                    );
                }
                Ok(AsyncActionPayload::ImagePathProbe {
                    request_id,
                    request_generation,
                    terminal_generation,
                    original: _,
                    source_draft_generation,
                    cursor: _,
                    png: None,
                }) if terminal_generation == self.terminal_input_generation => {
                    self.settle_paste_probe(
                        request_id,
                        request_generation,
                        source_draft_generation,
                        0,
                        None,
                        true,
                    );
                }
                Err(_) => self.show_toast("Paste unavailable", ToastKind::Error),
                Ok(_) => {}
            },
            AsyncActionKind::Internal("paste.native_image") => match result.payload {
                Ok(AsyncActionPayload::NativeImagePaste {
                    request_id,
                    request_generation,
                    terminal_generation,
                    source_draft_generation,
                    cursor,
                    png: Some(png),
                }) if terminal_generation == self.terminal_input_generation => {
                    self.terminal_paste_classifier.resolve_shortcut_intent();
                    self.settle_paste_probe(
                        request_id,
                        request_generation,
                        source_draft_generation,
                        cursor,
                        Some(png),
                        false,
                    );
                }
                // The classifier owns the 250 ms timeout notice. A missing
                // bitmap can still be followed by authoritative bracketed
                // text, so the speculative native probe remains silent.
                Ok(AsyncActionPayload::NativeImagePaste {
                    request_id,
                    request_generation,
                    terminal_generation,
                    source_draft_generation,
                    png: None,
                    ..
                }) if terminal_generation == self.terminal_input_generation => {
                    self.settle_paste_probe(
                        request_id,
                        request_generation,
                        source_draft_generation,
                        0,
                        None,
                        false,
                    );
                }
                Err(_) => {}
                Ok(_) => {}
            },
            AsyncActionKind::Blocking("paste.delivery_receipt") => {
                if let Ok(AsyncActionPayload::ClientSubmissionReceipt {
                    client_submission_id,
                    result,
                }) = result.payload
                {
                    match result {
                        Ok(cockpit_core::daemon::proto::ClientSubmissionReceiptStatus::Pending)
                        | Err(_) => {
                            if let Some(record) = self
                                .delivery_unconfirmed_records
                                .get_mut(&client_submission_id)
                            {
                                record.probe_in_flight = false;
                                record.next_probe_at = self.event_loop_monotonic_now
                                    + std::time::Duration::from_millis(250);
                                if record.next_probe_at >= record.probe_deadline {
                                    record.probe_exhausted = true;
                                }
                            }
                        }
                        Ok(status) => {
                            let (outcome, wire_fingerprint) = match status {
                                cockpit_core::daemon::proto::ClientSubmissionReceiptStatus::Accepted {
                                    wire_fingerprint,
                                    ..
                                } => ("accepted".to_string(), wire_fingerprint),
                                cockpit_core::daemon::proto::ClientSubmissionReceiptStatus::Terminal {
                                    disposition,
                                    wire_fingerprint,
                                } => (disposition, wire_fingerprint),
                                cockpit_core::daemon::proto::ClientSubmissionReceiptStatus::Pending => unreachable!(),
                            };
                            if wire_fingerprint.is_empty() {
                                if let Some(record) = self
                                    .delivery_unconfirmed_records
                                    .get_mut(&client_submission_id)
                                {
                                    record.probe_in_flight = false;
                                    record.probe_exhausted = true;
                                }
                            } else if let Some(record) = self
                                .delivery_unconfirmed_records
                                .remove(&client_submission_id)
                            {
                                self.submission_fences.remove(&client_submission_id);
                                self.push_plain(format!(
                                    "Delivery {outcome} for message {} in session {} (daemon wire {}).",
                                    record.client_submission_id,
                                    record.session_id,
                                    wire_fingerprint
                                ));
                            }
                        }
                    }
                }
            }
            AsyncActionKind::Internal(label @ ("session.switch" | "session.resume")) => {
                match result.payload {
                    Ok(AsyncActionPayload::SessionSwitched(outcome)) => {
                        if label == "session.switch"
                            && !matches!(outcome.target, agent_runner::SessionTarget::New)
                        {
                            self.history.push(HistoryEntry::CommandError {
                                line: "/new: session switch returned the wrong target; old session preserved"
                                    .to_string(),
                            });
                            self.fail_pending_session_switch_submissions();
                        } else {
                            if label == "session.switch" {
                                self.commit_new_session_switch_outcome(*outcome);
                            } else {
                                self.apply_session_switch_outcome(*outcome);
                            }
                            self.flush_pending_session_switch_submissions();
                        }
                    }
                    Ok(_) => {
                        if label == "session.switch" {
                            self.history.push(HistoryEntry::CommandError {
                                line: "/new: session switch returned an unexpected response; old session preserved"
                                    .to_string(),
                            });
                            self.fail_pending_session_switch_submissions();
                        } else {
                            self.history.push(HistoryEntry::CommandError {
                                line: "/resume: session switch returned an unexpected response"
                                    .to_string(),
                            });
                            self.fail_pending_session_switch_submissions();
                        }
                    }
                    Err(error) => {
                        let command = if label == "session.resume" {
                            "/resume"
                        } else {
                            "/new"
                        };
                        if reconnectable_session_switch_error(&error)
                            && matches!(self.agent_runner, Some(Ok(_)))
                        {
                            self.history.push(HistoryEntry::CommandError {
                                line: format!("{command}: daemon connection lost; reconnecting"),
                            });
                        } else {
                            // Replacement Attach installs its new client only
                            // after success. A rejected switch therefore leaves
                            // the current attachment and its view retryable.
                            self.history.push(HistoryEntry::CommandError {
                                line: format!("{command}: {error}"),
                            });
                        }
                        self.fail_pending_session_switch_submissions();
                    }
                }
                if label == "session.switch"
                    && let Some((sequence, _)) = self.pending_session_switch_order.take()
                {
                    self.pending_session_switch_reconcile_started_at = None;
                    let _ = self.submission_order.complete(sequence);
                    self.dispatch_next_ready_paste_fence();
                }
            }
            AsyncActionKind::Internal("session.fork") => match result.payload {
                Ok(AsyncActionPayload::ForkSessionSwitched {
                    outcome,
                    fork_short_id,
                    seed_composer,
                }) => {
                    self.apply_session_switch_outcome_without_resume_chrome(*outcome);
                    self.flush_pending_session_switch_submissions();
                    self.push_plain(format!("/fork: switched to fork {fork_short_id}."));
                    if let Some(seed) = seed_composer {
                        self.composer.set(seed);
                        self.composer.set_vim_mode(VimMode::Insert);
                    }
                }
                Ok(_) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: "/fork: session switch returned an unexpected response".to_string(),
                    });
                    self.fail_pending_session_switch_submissions();
                }
                Err(error) => {
                    if reconnectable_session_switch_error(&error)
                        && matches!(self.agent_runner, Some(Ok(_)))
                    {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/fork: daemon connection lost; reconnecting".to_string(),
                        });
                    } else {
                        // The unattached fork is discarded by the switch task;
                        // the current session client was never replaced.
                        self.history.push(HistoryEntry::CommandError {
                            line: format!("/fork: could not attach to fork: {error}"),
                        });
                    }
                    self.fail_pending_session_switch_submissions();
                }
            },
            AsyncActionKind::Internal("session.side") => match result.payload {
                Ok(AsyncActionPayload::SideSessionSwitched {
                    outcome,
                    side_short_id,
                }) => {
                    self.apply_session_switch_outcome_preserving_history(*outcome, false);
                    self.flush_pending_session_switch_submissions();
                    self.push_plain(Self::side_entry_banner(&side_short_id));
                }
                Ok(_) => {
                    self.agent_runner = Some(Err("side switch returned unexpected payload".into()));
                    self.fail_pending_session_switch_submissions();
                }
                Err(error) => {
                    if let Some(side) = self.side_conversation.take() {
                        let discard_socket = side.socket.clone();
                        let discard_session_id = side.side_session_id;
                        self.restore_side_snapshot(side);
                        self.async_actions.start_blocking(
                            AsyncActionKind::DaemonRpc("side.discard"),
                            AsyncActionPolicy::AllowConcurrent,
                            move || {
                                agent_runner::discard_session_blocking(
                                    &discard_socket,
                                    discard_session_id,
                                )
                                .map(|_| AsyncActionPayload::Unit)
                            },
                        );
                    }
                    if reconnectable_session_switch_error(&error)
                        && matches!(self.agent_runner, Some(Ok(_)))
                    {
                        self.history.push(HistoryEntry::CommandError {
                            line: "/side: daemon connection lost; reconnecting".to_string(),
                        });
                    } else {
                        self.history.push(HistoryEntry::CommandError {
                            line: format!("/side: could not enter side conversation: {error}"),
                        });
                    }
                    self.fail_pending_session_switch_submissions();
                }
            },
            AsyncActionKind::Internal("session.side.return") => match result.payload {
                Ok(AsyncActionPayload::SideSessionReturned(outcome)) => {
                    self.complete_side_conversation_return(*outcome);
                }
                Ok(_) => {
                    self.history.push(HistoryEntry::CommandError {
                        line: "/side: return produced an unexpected response; still in side conversation"
                            .to_string(),
                    });
                    self.fail_pending_session_switch_submissions();
                }
                Err(error) => {
                    let line = if reconnectable_session_switch_error(&error) {
                        "/side: daemon connection lost; reconnecting — still in side conversation"
                            .to_string()
                    } else {
                        format!(
                            "/side: could not return to main session: {error}; still in side conversation — retry `/side end`"
                        )
                    };
                    self.history.push(HistoryEntry::CommandError { line });
                    self.fail_pending_session_switch_submissions();
                }
            },
            AsyncActionKind::Refresh("container.availability") => {
                if let Ok(AsyncActionPayload::ContainerAvailability(availability)) = result.payload
                {
                    self.container_availability = availability;
                }
            }
            AsyncActionKind::Internal("startup.remote_disclosures") => match result.payload {
                Ok(AsyncActionPayload::RemoteDisclosures {
                    project_root,
                    request_generation,
                    socket,
                    launch_session_id,
                    session_id,
                    attachment_epoch,
                    org,
                    connector,
                }) => {
                    let current_attachment = self
                        .agent_runner
                        .as_ref()
                        .and_then(|runner| runner.as_ref().ok())
                        .filter(|runner| runner.has_attached_client())
                        .map(|runner| (runner.session_id(), runner.attachment_epoch()));
                    if startup_disclosure_completion_is_current(
                        StartupDisclosureIdentity {
                            project_root: &self.launch.cwd.to_string_lossy(),
                            generation: self.startup_disclosures_generation,
                            socket: self.startup_background.daemon_socket.as_deref(),
                            launch_session_id: self.launch.session_id,
                            attachment: current_attachment,
                        },
                        StartupDisclosureIdentity {
                            project_root: &project_root,
                            generation: request_generation,
                            socket: socket.as_deref(),
                            launch_session_id,
                            attachment: session_id.zip(attachment_epoch),
                        },
                    ) {
                        self.startup_disclosures_ready = true;
                        self.org_sync_disclosure = org;
                        self.connector_disclosure = connector;
                    }
                }
                Ok(_) => {}
                Err(error) => self.show_toast(
                    format!("Startup disclosures Unavailable — {error}; Retry"),
                    ToastKind::Warning,
                ),
            },
            AsyncActionKind::DaemonRpc("assistant.resolve") => match result.payload {
                Ok(AsyncActionPayload::AssistantSessionResolved {
                    session_id,
                    source_session_id,
                }) => {
                    if self.launch.session_id == source_session_id {
                        self.resume_session(session_id);
                    }
                }
                Ok(_) => self.push_plain("/assistant: unexpected daemon response".to_string()),
                Err(error) => self.push_plain(format!("/assistant: Unavailable — {error}; Retry")),
            },
            AsyncActionKind::Refresh("stats.rollup") => {
                if let Overlay::Stats(pane) = &mut self.overlay
                    && let Ok(AsyncActionPayload::StatsRollup(result)) = result.payload
                {
                    pane.apply_fetch_result(result);
                }
            }
            AsyncActionKind::Internal("subagent.history") => {
                if let Ok(AsyncActionPayload::SubagentHistory {
                    session_id,
                    task_call_id,
                    label,
                    history,
                    has_more,
                    oldest_seq,
                }) = result.payload
                {
                    self.apply_subagent_history_result(
                        session_id,
                        &task_call_id,
                        &label,
                        history,
                        has_more,
                        oldest_seq,
                    );
                }
            }
            AsyncActionKind::Refresh("provider.usage") => match result.payload {
                Ok(AsyncActionPayload::ProviderUsage(rows)) => {
                    self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::open(rows));
                }
                Ok(_) => {
                    self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::error(
                        "unexpected usage response".to_string(),
                    ));
                }
                Err(e) => {
                    self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::error(e));
                }
            },
            AsyncActionKind::Internal("paste.token_count") => match result.payload {
                Ok(AsyncActionPayload::PasteTokenCount { block_id, tokens }) => {
                    self.apply_paste_token_count(block_id, tokens);
                }
                Ok(_) => {
                    tracing::debug!("paste token count returned unexpected payload");
                }
                Err(e) => {
                    tracing::debug!(error = %e, "paste token count failed");
                }
            },
            AsyncActionKind::Refresh("pins.state") => match result.payload {
                Ok(AsyncActionPayload::PinState {
                    session_id,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_state(session_id, count, pinned_seqs);
                }
                Ok(_) => {
                    tracing::debug!("pin state refresh returned unexpected payload");
                }
                Err(e) => {
                    tracing::debug!(error = %e, "pin state refresh failed");
                }
            },
            AsyncActionKind::Internal("pins.toggle") => match result.payload {
                Ok(AsyncActionPayload::PinToggle {
                    session_id,
                    seq,
                    now_pinned,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_toggle(session_id, seq, now_pinned, count, pinned_seqs);
                }
                Ok(_) => self.pin_toast("pin: unexpected response".to_string()),
                Err(e) => self.pin_toast(format!("pin: {e}")),
            },
            AsyncActionKind::Internal("pins.review") => match result.payload {
                Ok(AsyncActionPayload::PinsReview { session_id, pins }) => {
                    self.apply_pins_review(session_id, pins);
                }
                Ok(_) => self.push_plain("/pins: unexpected response".to_string()),
                Err(e) => self.push_plain(format!("/pins: {e}")),
            },
            AsyncActionKind::Internal("pins.pin") => match result.payload {
                Ok(AsyncActionPayload::PinMessage {
                    session_id,
                    seq: _,
                    inserted,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_message(session_id, inserted, count, pinned_seqs);
                }
                Ok(_) => self.pin_toast("pin: unexpected response".to_string()),
                Err(e) => self.pin_toast(format!("pin: {e}")),
            },
            AsyncActionKind::Internal("pins.unpin") => match result.payload {
                Ok(AsyncActionPayload::PinUnpin {
                    session_id,
                    seq,
                    count,
                    pinned_seqs,
                }) => {
                    self.apply_pin_unpin(session_id, seq, count, pinned_seqs);
                }
                Ok(_) => self.pin_toast("unpin: unexpected response".to_string()),
                Err(e) => self.pin_toast(format!("unpin: {e}")),
            },
            AsyncActionKind::DaemonRpc("resources.snapshot") => {
                if let Overlay::Resources(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::ResourceSnapshot(snapshot)) => Ok(snapshot),
                        Ok(_) => Err("unexpected daemon response".to_string()),
                        Err(e) => Err(e),
                    };
                    pane.apply_snapshot_result(payload);
                }
            }
            AsyncActionKind::DaemonRpc("resources.promote") => match result.payload {
                Ok(AsyncActionPayload::PromoteResource {
                    status,
                    message,
                    snapshot,
                }) => {
                    if let Overlay::Resources(pane) = &mut self.overlay {
                        pane.apply_snapshot_result(Ok(snapshot));
                    }
                    let kind = match status {
                        cockpit_core::daemon::proto::ResourcePromoteStatus::Promoted => {
                            ToastKind::Success
                        }
                        cockpit_core::daemon::proto::ResourcePromoteStatus::NotQueued
                        | cockpit_core::daemon::proto::ResourcePromoteStatus::NotFound => {
                            ToastKind::Info
                        }
                        cockpit_core::daemon::proto::ResourcePromoteStatus::Disabled => {
                            ToastKind::Warning
                        }
                    };
                    self.show_toast(message, kind);
                }
                Ok(_) => {
                    self.show_toast("/resources: unexpected daemon response", ToastKind::Error)
                }
                Err(e) => self.show_toast(format!("/resources: {e}"), ToastKind::Error),
            },
            AsyncActionKind::Internal("notes.rpc") => {
                if let Overlay::Notes(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::NotesRpc(result)) => Ok(result),
                        Ok(_) => Err("notes db returned an unexpected response".to_string()),
                        Err(e) => Err(e),
                    };
                    pane.apply_rpc_result(payload);
                }
            }
            AsyncActionKind::DaemonRpc("goal.status" | "goal.set" | "goal.clear") => {
                match result.payload {
                    Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                    Ok(_) => self.push_plain("/goal: unexpected daemon response".to_string()),
                    Err(error) => self.history.push(HistoryEntry::CommandError {
                        line: format!("/goal: {error}"),
                    }),
                }
            }
            AsyncActionKind::Internal("curator.command") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/curator: unexpected async response".to_string()),
                Err(e) => self.push_plain(format!("/curator: {e}")),
            },
            AsyncActionKind::Internal("export.transcript") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/export: unexpected async response".to_string()),
                Err(e) => self.push_plain(e),
            },
            AsyncActionKind::Internal("export.debug") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/export debug: unexpected async response".to_string()),
                Err(e) => self.push_plain(e),
            },
            AsyncActionKind::DaemonRpc("rename") => match result.payload {
                Ok(AsyncActionPayload::Text(title)) => {
                    self.push_plain(format!("Renamed session to `{title}`"));
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/rename: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/rename: {e}"),
                }),
            },
            AsyncActionKind::Internal("rename.auto") => match result.payload {
                Ok(AsyncActionPayload::Text(title)) => {
                    self.push_plain(format!("Renamed session to `{title}`"));
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/rename: unexpected title result".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/rename: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("sealed") => match result.payload {
                Ok(AsyncActionPayload::Text(message)) => self.push_plain(message),
                Ok(_) => self.push_plain("/sealed: unexpected daemon response".to_string()),
                Err(e) => self.push_plain(format!("/sealed: {e}")),
            },
            AsyncActionKind::DaemonRpc("note") => match result.payload {
                Ok(AsyncActionPayload::NoteRecorded { text }) => {
                    self.history.push(HistoryEntry::UserNote {
                        text,
                        timestamp: chrono::Local::now(),
                    });
                    self.pin_chat_to_tail();
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/note: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/note: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("subagent.steer") => match result.payload {
                Ok(AsyncActionPayload::DelegationSteer(result)) => {
                    self.apply_subagent_steer_result(result);
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "subagent steer: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("subagent steer: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("history.page") => match result.payload {
                Ok(AsyncActionPayload::HistoryPage {
                    request_id,
                    session_id,
                    entries,
                    has_more,
                    oldest_seq,
                }) => {
                    self.apply_older_history_page_result(
                        request_id, session_id, entries, has_more, oldest_seq,
                    );
                }
                Ok(AsyncActionPayload::HistoryPageError {
                    request_id,
                    session_id,
                    message: _,
                }) => self.apply_older_history_page_error(request_id, session_id),
                Ok(_) => {}
                Err(_) => {}
            },
            AsyncActionKind::DaemonRpc("subagent.history.page") => match result.payload {
                Ok(AsyncActionPayload::SubagentHistoryPage {
                    request_id,
                    session_id,
                    task_call_id,
                    label,
                    entries,
                    has_more,
                    oldest_seq,
                }) => {
                    self.apply_subagent_history_page_result(
                        request_id,
                        session_id,
                        (&task_call_id, &label),
                        entries,
                        has_more,
                        oldest_seq,
                    );
                }
                Ok(AsyncActionPayload::SubagentHistoryPageError {
                    request_id,
                    session_id,
                    task_call_id,
                    label,
                    message: _,
                }) => self.apply_subagent_history_page_error(
                    request_id,
                    session_id,
                    &task_call_id,
                    &label,
                ),
                Ok(_) => {}
                Err(_) => {}
            },
            AsyncActionKind::DaemonRpc("fork.create") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    socket,
                    session_id,
                    short_id,
                    fork_point_seq,
                    seed_composer,
                    ..
                }) => {
                    self.apply_fork_created(
                        parent_session_id,
                        socket,
                        session_id,
                        short_id,
                        fork_point_seq,
                        seed_composer,
                    );
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/fork: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/fork: could not fork: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("side.start") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    socket,
                    session_id,
                    short_id,
                    ..
                }) => {
                    self.apply_side_created(parent_session_id, socket, session_id, short_id);
                }
                Ok(_) => self.history.push(HistoryEntry::CommandError {
                    line: "/side: unexpected daemon response".to_string(),
                }),
                Err(e) => self.history.push(HistoryEntry::CommandError {
                    line: format!("/side: could not fork: {e}"),
                }),
            },
            AsyncActionKind::DaemonRpc("side.discard") => {
                if let Err(e) = result.payload {
                    tracing::warn!(error = %e, "discarding ephemeral side session failed; boot sweep will reclaim it");
                }
            }
            AsyncActionKind::Blocking("local.command") => match result.payload {
                Ok(AsyncActionPayload::LocalCommand {
                    label,
                    raw_output,
                    failed,
                    git_args,
                }) => {
                    self.apply_local_command_result(label, raw_output, failed, git_args);
                }
                Ok(_) => self.push_plain("local command: unexpected async response".to_string()),
                Err(e) => self.push_plain(format!("local command: {e}")),
            },
            AsyncActionKind::Blocking("copy.file") => match result.payload {
                Ok(AsyncActionPayload::CopyToFile {
                    path,
                    bytes_written,
                    durability_confirmed: true,
                }) => {
                    self.show_toast(
                        format!("Wrote {bytes_written} bytes to {}", path.display()),
                        ToastKind::Success,
                    );
                }
                Ok(AsyncActionPayload::CopyToFile {
                    path,
                    bytes_written,
                    durability_confirmed: false,
                }) => {
                    // The file is genuinely on disk — this is not a failed
                    // copy — but the directory-fsync durability barrier did
                    // not confirm, so it is not an ordinary success either.
                    self.show_toast(
                        format!(
                            "Wrote {bytes_written} bytes to {} (durability unconfirmed — a crash before the next fsync could lose the directory entry; verify the file)",
                            path.display()
                        ),
                        ToastKind::Warning,
                    );
                }
                Ok(_) => self.show_toast(
                    "copy file: unexpected async response".to_string(),
                    ToastKind::Error,
                ),
                Err(e) => self.show_toast(format!("copy file: {e}"), ToastKind::Error),
            },
            AsyncActionKind::Refresh("display.daemon.probe") => match result.payload {
                Ok(AsyncActionPayload::DaemonProbe { cwd, status }) => {
                    self.apply_display_daemon_probe_result(cwd, status);
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::debug!(error = %e, "display daemon probe failed");
                }
            },
            AsyncActionKind::Internal("oauth.codex.begin") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthCodexBegin(login)) => Ok(login),
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_begin(OAuthProvider::Codex, OAuthBeginResult::Device(payload));
            }
            AsyncActionKind::Internal("oauth.codex.poll") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthCodexComplete { logged_in }) => Ok(logged_in),
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_complete(OAuthProvider::Codex, payload);
            }
            AsyncActionKind::Internal("oauth.grok.begin") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthGrokBegin { login }) => {
                        let settings::GrokBrowserStart { begin, listener } =
                            settings::prepare_grok_browser_start(
                                login,
                                settings::OAuthEffects::production(),
                                cockpit_core::auth::xai_oauth::CALLBACK_PORT,
                            );
                        if let Some(listener) = listener {
                            let listener_login = begin.login.clone();
                            self.async_actions.start(
                                AsyncActionKind::Internal("oauth.grok.complete"),
                                AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                                async move {
                                    cockpit_core::auth::xai_oauth::complete_local_callback_login(
                                        listener_login,
                                        listener,
                                    )
                                    .await
                                    .map(|_| AsyncActionPayload::OAuthGrokComplete {
                                        logged_in: true,
                                    })
                                    .map_err(|e| e.to_string())
                                },
                            );
                        }
                        Ok(begin)
                    }
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_begin(OAuthProvider::Grok, OAuthBeginResult::Browser(payload));
            }
            AsyncActionKind::Internal("oauth.grok.complete") => {
                let payload = match result.payload {
                    Ok(AsyncActionPayload::OAuthGrokComplete { logged_in }) => Ok(logged_in),
                    Ok(_) => Err("unexpected OAuth response".to_string()),
                    Err(e) => Err(e),
                };
                self.dialog
                    .apply_oauth_complete(OAuthProvider::Grok, payload);
            }
            _ => self.completed_async_actions.push(result),
        }
    }

    fn settle_paste_probe(
        &mut self,
        request_id: uuid::Uuid,
        request_generation: u64,
        source_draft_generation: u64,
        cursor: usize,
        png: Option<Vec<u8>>,
        report_unavailable: bool,
    ) {
        let Some(probe) = self.pending_paste_probes.remove(&request_id) else {
            return;
        };
        if probe.request.paste_generation != request_generation
            || probe.source_draft_generation != source_draft_generation
        {
            return;
        }
        let _ = self.paste_correlations.commit(
            request_id,
            probe.request.host,
            self.monotonic_origin.elapsed(),
        );
        let Some(fence_id) = probe.owner_fence else {
            if source_draft_generation != self.draft_generation {
                return;
            }
            if let Some(png) = png {
                self.composer.set_cursor(cursor);
                self.insert_image_block(png);
            } else if report_unavailable {
                self.show_toast("Paste unavailable", ToastKind::Error);
            }
            return;
        };
        if png.is_none() && report_unavailable {
            self.show_toast("Paste unavailable", ToastKind::Error);
        }
        let ready = if let Some(fence) = self.submission_fences.get_mut(&fence_id) {
            let result = png.map(|png| ("[image]".to_string(), String::new(), Some(png)));
            let _ = fence.settle_slot(
                request_id,
                request_generation,
                source_draft_generation,
                result,
            );
            fence.lifecycle == crate::tui::structured_paste::FenceLifecycle::Ready
        } else {
            false
        };
        if ready {
            self.dispatch_ready_paste_fence(fence_id);
        }
    }

    fn dispatch_ready_paste_fence(&mut self, fence_id: uuid::Uuid) {
        if !matches!(
            self.submission_order.front(),
            Some((_, crate::tui::structured_paste::OrderedIntent::Fence(id))) if id == fence_id
        ) {
            return;
        }
        if self
            .deferred_fence_dispatches
            .get(&fence_id)
            .is_some_and(|dispatch| dispatch.waiting_model_selection.is_some())
        {
            return;
        }
        if !self.submission_fences.contains_key(&fence_id) {
            return;
        }
        let Some(mut deferred) = self.deferred_fence_dispatches.remove(&fence_id) else {
            return;
        };
        let Some(fence) = self.submission_fences.get_mut(&fence_id) else {
            return;
        };
        let mut resolved_images = Vec::new();
        for slot in &fence.slots {
            if let crate::tui::structured_paste::PasteSlotState::Ready {
                original_offset,
                png,
                ..
            } = slot
            {
                if let Some(png) = png {
                    resolved_images.push((*original_offset, png.clone()));
                }
            }
        }
        resolved_images.sort_by_key(|(offset, _)| *offset);
        let positional_wire = deferred.submission.text == fence.captured_composer;
        let positional_display = deferred.display == fence.captured_composer;
        if !fence.model.supports_images {
            let first_note_number = deferred.submission.text.matches("[Pasted image #").count()
                + deferred.submission.images.len()
                + 1;
            let notes = resolved_images
                .iter()
                .enumerate()
                .map(|(index, _)| {
                    format!(
                        "[Pasted image #{}: not sent — current model has no image support]",
                        first_note_number + index
                    )
                })
                .collect::<Vec<_>>();
            if positional_wire {
                for ((offset, _), note) in resolved_images.iter().zip(&notes).rev() {
                    let offset = floor_char_boundary(&deferred.submission.text, *offset);
                    deferred.submission.text.insert_str(offset, note);
                }
            } else {
                for note in &notes {
                    deferred.submission.text.push_str(note);
                }
            }
            if positional_display {
                for (offset, _) in resolved_images.iter().rev() {
                    let offset = floor_char_boundary(&deferred.display, *offset);
                    deferred.display.insert_str(offset, "[image]");
                }
            } else {
                for _ in &resolved_images {
                    deferred.display.push_str("[image]");
                }
            }
            resolved_images.clear();
        }
        if positional_wire {
            let original_wire = deferred.submission.text.clone();
            for (inserted, (offset, png)) in resolved_images.iter().enumerate() {
                let offset = floor_char_boundary(&original_wire, *offset);
                let existing_before = original_wire[..offset]
                    .matches(cockpit_core::daemon::proto::IMAGE_PART_SENTINEL)
                    .count();
                deferred
                    .submission
                    .images
                    .insert(existing_before + inserted, png.clone());
            }
            for (offset, _) in resolved_images.iter().rev() {
                let offset = floor_char_boundary(&deferred.submission.text, *offset);
                deferred
                    .submission
                    .text
                    .insert_str(offset, cockpit_core::daemon::proto::IMAGE_PART_SENTINEL);
            }
        } else {
            for (_, png) in &resolved_images {
                deferred
                    .submission
                    .text
                    .push_str(cockpit_core::daemon::proto::IMAGE_PART_SENTINEL);
                deferred.submission.images.push(png.clone());
            }
        }
        if positional_display {
            for (offset, _) in resolved_images.iter().rev() {
                let offset = floor_char_boundary(&deferred.display, *offset);
                deferred.display.insert_str(offset, "[image]");
            }
        } else {
            for _ in &resolved_images {
                deferred.display.push_str("[image]");
            }
        }
        if deferred.submission.text.trim().is_empty() && deferred.submission.images.is_empty() {
            fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::NoPayload;
            let sequence = fence.fence_sequence;
            self.submission_fences.remove(&fence_id);
            let _ = self.submission_order.complete(sequence);
            self.dispatch_next_ready_paste_fence();
            return;
        }
        if let Err(message) =
            super::input::validate_pasted_images_for_submit(&deferred.submission.images)
        {
            let sequence = fence.fence_sequence;
            self.submission_fences.remove(&fence_id);
            let _ = self.submission_order.complete(sequence);
            self.show_toast(message, ToastKind::Error);
            self.dispatch_next_ready_paste_fence();
            return;
        }
        let sequence = fence.fence_sequence;
        let was_busy = self.busy;
        if was_busy && self.has_pending_session_switch_action() {
            let item = super::input::optimistic_queue_item_with_id(
                fence_id,
                deferred.submission.text.clone(),
                Some(deferred.display),
            );
            self.queue.push(item.clone());
            self.queue_pending_session_switch_submission_with_optimistic_state(
                deferred.submission,
                "engine",
                false,
                OptimisticSubmissionState {
                    id: fence_id,
                    tag_entries: 0,
                    history: Vec::new(),
                    queue_item: Some(item),
                },
            );
            let _ = self.submission_order.complete(sequence);
            self.dispatch_next_ready_paste_fence();
            return;
        }
        if was_busy {
            self.queue.push(super::input::optimistic_queue_item_with_id(
                fence_id,
                deferred.submission.text.clone(),
                Some(deferred.display.clone()),
            ));
        } else {
            self.begin_working_span();
            self.prompt_history.push(deferred.display.clone());
            self.prompt_history_cursor = 0;
            self.staged_draft = None;
        }
        let optimistic_history_start = self.history.len();
        let assembled_wire_digest =
            crate::tui::structured_paste::user_submission_wire_digest(&deferred.submission);
        let outcome = self.dispatch_optimistic_user_submission_with_id(
            fence_id,
            deferred.display,
            deferred.submission,
            "engine",
            !was_busy,
            &deferred.tag_expansions,
        );
        if outcome == DispatchOutcome::Sent
            && let Some(fence) = self.submission_fences.get_mut(&fence_id)
        {
            fence.assembled_wire_digest = Some(assembled_wire_digest);
            fence.lifecycle = crate::tui::structured_paste::FenceLifecycle::PossiblySent;
        }
        if was_busy {
            let terminal_notices = self
                .history
                .drain(optimistic_history_start..)
                .filter(|entry| {
                    matches!(
                        entry,
                        HistoryEntry::InferenceError { .. } | HistoryEntry::CommandError { .. }
                    )
                })
                .collect::<Vec<_>>();
            self.history.extend(terminal_notices);
            if outcome != DispatchOutcome::Sent {
                self.queue.retain(|item| item.id != fence_id);
            }
        }
        let _ = self.submission_order.complete(sequence);
        self.dispatch_next_ready_paste_fence();
    }

    pub(super) fn dispatch_next_ready_paste_fence(&mut self) {
        let Some((_, crate::tui::structured_paste::OrderedIntent::Fence(id))) =
            self.submission_order.front()
        else {
            return;
        };
        if self.submission_fences.get(&id).is_some_and(|fence| {
            fence.lifecycle == crate::tui::structured_paste::FenceLifecycle::Ready
        }) {
            self.dispatch_ready_paste_fence(id);
        }
    }

    pub(super) fn drain_oauth_actions(&mut self) {
        while let Some(action) = self.dialog.take_oauth_action() {
            match (action.provider, action.op) {
                (OAuthProvider::Codex, OAuthFlowOp::Begin) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.codex.begin"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.codex")),
                        async {
                            cockpit_core::auth::codex_oauth::begin_device_code_login()
                                .await
                                .map(AsyncActionPayload::OAuthCodexBegin)
                                .map_err(|e| e.to_string())
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Poll(login)) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.codex.poll"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.codex")),
                        async move {
                            cockpit_core::auth::codex_oauth::complete_device_code_login(login)
                                .await
                                .map(|_| AsyncActionPayload::OAuthCodexComplete { logged_in: true })
                                .map_err(|e| e.to_string())
                        },
                    );
                }
                (OAuthProvider::Codex, OAuthFlowOp::Cancel) => {
                    self.async_actions
                        .abort_key(&AsyncActionKey::new("oauth.codex"));
                }
                (OAuthProvider::Grok, OAuthFlowOp::Begin) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.grok.begin"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                        async move {
                            let login = cockpit_core::auth::xai_oauth::begin_manual_login()
                                .await
                                .map_err(|e| e.to_string())?;
                            Ok(AsyncActionPayload::OAuthGrokBegin { login })
                        },
                    );
                }
                (OAuthProvider::Grok, OAuthFlowOp::Complete { login, input }) => {
                    self.async_actions.start(
                        AsyncActionKind::Internal("oauth.grok.complete"),
                        AsyncActionPolicy::Replace(AsyncActionKey::new("oauth.grok")),
                        async move {
                            cockpit_core::auth::xai_oauth::complete_manual_login(login, &input)
                                .await
                                .map(|_| AsyncActionPayload::OAuthGrokComplete { logged_in: true })
                                .map_err(|e| e.to_string())
                        },
                    );
                }
                (OAuthProvider::Grok, OAuthFlowOp::Cancel) => {
                    self.async_actions
                        .abort_key(&AsyncActionKey::new("oauth.grok"));
                }
                (OAuthProvider::Codex, OAuthFlowOp::Complete { .. })
                | (OAuthProvider::Grok, OAuthFlowOp::Poll(_)) => {}
            }
        }
    }

    pub(super) fn start_resources_snapshot_action(&mut self) {
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("resources.snapshot"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("resources.snapshot")),
            || match crate::tui::agent_runner::resource_snapshot_blocking()? {
                cockpit_core::daemon::proto::Response::ResourceSnapshot { snapshot } => {
                    Ok(AsyncActionPayload::ResourceSnapshot(snapshot))
                }
                other => Err(format!("unexpected resource_snapshot response: {other:?}")),
            },
        );
    }

    pub(super) fn start_resource_promote_action(&mut self, request_id: String) {
        let session_id = self.current_session_id();
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("resources.promote"),
            AsyncActionPolicy::Replace(AsyncActionKey::new(format!(
                "resources.promote:{request_id}"
            ))),
            move || match crate::tui::agent_runner::promote_resource_blocking(
                request_id, session_id,
            )? {
                cockpit_core::daemon::proto::Response::PromoteResourceResult {
                    status,
                    message,
                    snapshot,
                } => Ok(AsyncActionPayload::PromoteResource {
                    status,
                    message,
                    snapshot,
                }),
                other => Err(format!("unexpected promote_resource response: {other:?}")),
            },
        );
    }

    pub(super) fn start_resources_outcome(
        &mut self,
        outcome: crate::tui::resources_pane::ResourcesOutcome,
    ) {
        match outcome {
            crate::tui::resources_pane::ResourcesOutcome::Close => self.overlay = Overlay::None,
            crate::tui::resources_pane::ResourcesOutcome::Refresh => {
                self.start_resources_snapshot_action();
            }
            crate::tui::resources_pane::ResourcesOutcome::Promote(request_id) => {
                self.start_resource_promote_action(request_id);
            }
        }
    }

    pub(super) fn sessions_daemon_socket(&self) -> Option<&Path> {
        self.agent_runner
            .as_ref()
            .and_then(|runner| runner.as_ref().ok().map(|runner| runner.socket.as_path()))
            .or(self.startup_background.daemon_socket.as_deref())
    }

    pub(super) fn start_sessions_list_action(&mut self) {
        let Overlay::Sessions(pane) = &self.overlay else {
            return;
        };
        let (project_id, parent) = pane.root_request();
        let socket = self.sessions_daemon_socket().map(Path::to_path_buf);
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.list"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.list")),
            move || {
                let socket = socket
                    .ok_or_else(|| "daemon socket unavailable for sessions.list".to_string())?;
                crate::tui::agent_runner::list_sessions_blocking(&socket, project_id, parent)
                    .map(AsyncActionPayload::Sessions)
            },
        );
    }

    pub(super) fn start_sessions_live_status_action(&mut self, ids: Vec<uuid::Uuid>) {
        let socket = self.sessions_daemon_socket().map(Path::to_path_buf);
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.live"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.live")),
            move || {
                let socket = socket
                    .ok_or_else(|| "daemon socket unavailable for sessions.live".to_string())?;
                Ok(AsyncActionPayload::SessionLiveStatus(
                    crate::tui::agent_runner::session_live_status_blocking(&socket, ids),
                ))
            },
        );
    }

    pub(super) fn start_sessions_preview_action(
        &mut self,
        session_id: uuid::Uuid,
        before_seq: Option<i64>,
    ) {
        let socket = self.sessions_daemon_socket().map(Path::to_path_buf);
        self.async_actions.start_blocking(
            AsyncActionKind::DaemonRpc("sessions.preview"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("sessions.preview")),
            move || {
                let socket = socket
                    .ok_or_else(|| "daemon socket unavailable for sessions.preview".to_string())?;
                let (messages, has_more) =
                    crate::tui::agent_runner::read_session_messages_blocking(
                        &socket, session_id, before_seq, 50,
                    )?;
                Ok(AsyncActionPayload::SessionMessages {
                    session_id,
                    before_seq,
                    messages,
                    has_more,
                })
            },
        );
    }

    pub(super) fn start_provider_usage_action(&mut self, args: String) {
        let filter = args.split_whitespace().next().map(str::to_string);
        let cwd = self.launch.cwd.clone();
        self.overlay = Overlay::Usage(crate::tui::usage_pane::UsagePane::loading());
        self.async_actions.start(
            AsyncActionKind::Refresh("provider.usage"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("provider.usage")),
            async move {
                // Provider usage probes make authenticated network requests,
                // so they need full (unredacted) provider entries the daemon's
                // redacted snapshot cannot supply, and there is no wire request
                // for daemon-side usage. Load the layered provider config
                // directly (NOT `load_effective`); credentials resolve at
                // request-construction time in core, never in TUI state.
                let paths = cockpit_config::dirs::config_file_paths_for_load(&cwd);
                let cfg = cockpit_config::providers::ConfigDoc::providers_from_paths(&paths);
                cockpit_core::providers::usage::probes::fetch_all_provider_usage(
                    &cfg,
                    filter.as_deref(),
                )
                .await
                .map(AsyncActionPayload::ProviderUsage)
                .map_err(|e| e.to_string())
            },
        );
    }

    pub(super) fn start_stats_rollup_action(
        &mut self,
        key: crate::tui::stats_pane::StatsPaneFetchKey,
    ) {
        let socket = self.startup_background.daemon_socket.clone();
        self.async_actions.start_blocking(
            AsyncActionKind::Refresh("stats.rollup"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("stats.rollup")),
            move || {
                Ok(AsyncActionPayload::StatsRollup(
                    crate::tui::stats_pane::fetch_stats_rollup(socket.as_deref(), key),
                ))
            },
        );
    }

    pub(super) fn sync_repo_status(&mut self) -> bool {
        if let Ok(guard) = self.repo_status.lock()
            && self.launch.repo_status != *guard
        {
            self.launch.repo_status = guard.clone();
            return true;
        }
        false
    }
}

#[cfg(test)]
mod startup_disclosure_generation_tests {
    use super::{StartupDisclosureIdentity, startup_disclosure_completion_is_current};
    use std::path::Path;
    use uuid::Uuid;

    #[test]
    fn stale_or_detached_disclosure_completions_are_rejected_for_same_project() {
        fn identity<'a>(
            project_root: &'a str,
            generation: u64,
            socket: Option<&'a Path>,
            launch_session_id: Option<Uuid>,
            attachment: Option<(Uuid, u64)>,
        ) -> StartupDisclosureIdentity<'a> {
            StartupDisclosureIdentity {
                project_root,
                generation,
                socket,
                launch_session_id,
                attachment,
            }
        }

        let session = Uuid::new_v4();
        let current = Some((session, 4));
        let socket = Some(Path::new("/tmp/cockpit.sock"));
        let completed = identity("/repo", 8, socket, Some(session), current);
        assert!(startup_disclosure_completion_is_current(
            completed, completed
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 9, socket, Some(session), current),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 8, socket, Some(session), None),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 8, socket, Some(session), Some((session, 5))),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity(
                "/repo",
                8,
                Some(Path::new("/tmp/replacement.sock")),
                Some(session),
                current,
            ),
            completed,
        ));
        assert!(!startup_disclosure_completion_is_current(
            identity("/repo", 8, socket, None, current),
            completed,
        ));
    }
}
