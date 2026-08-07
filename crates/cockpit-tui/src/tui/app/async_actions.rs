use super::*;

fn reconnectable_session_switch_error(error: &str) -> bool {
    error.contains("connection closed")
        || error.contains("broken pipe")
        || error.contains("connection reset")
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
            AsyncActionKind::Internal("startup.remote_disclosures") => {
                if let Ok(AsyncActionPayload::RemoteDisclosures { org, connector }) = result.payload
                {
                    self.org_sync_disclosure = org;
                    self.connector_disclosure = connector;
                }
            }
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
            AsyncActionKind::Internal("notes.db") => {
                if let Overlay::Notes(pane) = &mut self.overlay {
                    let payload = match result.payload {
                        Ok(AsyncActionPayload::NotesDb(result)) => Ok(result),
                        Ok(_) => Err("notes db returned an unexpected response".to_string()),
                        Err(e) => Err(e),
                    };
                    pane.apply_db_result(payload);
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
        let db = self.startup_background.db.clone();
        self.async_actions.start(
            AsyncActionKind::Refresh("stats.rollup"),
            AsyncActionPolicy::Replace(AsyncActionKey::new("stats.rollup")),
            async move {
                Ok(AsyncActionPayload::StatsRollup(
                    crate::tui::stats_pane::fetch_stats_rollup(db, key).await,
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
