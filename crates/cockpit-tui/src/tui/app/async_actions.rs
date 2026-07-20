use super::*;

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
            AsyncActionKind::Internal("session.switch") => match result.payload {
                Ok(AsyncActionPayload::SessionSwitched(outcome)) => {
                    self.apply_session_switch_outcome(*outcome);
                }
                Ok(_) => {
                    self.agent_runner =
                        Some(Err("session switch returned unexpected payload".into()));
                }
                Err(error) => {
                    self.agent_runner = Some(Err(error.clone()));
                    self.history.push(HistoryEntry::CommandError {
                        line: format!("/new: {error}"),
                    });
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
            AsyncActionKind::DaemonRpc("note") => match result.payload {
                Ok(AsyncActionPayload::NoteRecorded { text }) => {
                    self.history.push(HistoryEntry::UserNote {
                        text,
                        timestamp: chrono::Local::now(),
                    });
                    self.chat_scroll_offset = 0;
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
            AsyncActionKind::DaemonRpc("fork.create") => match result.payload {
                Ok(AsyncActionPayload::ForkCreated {
                    parent_session_id,
                    session_id,
                    short_id,
                    seed_composer,
                    ..
                }) => {
                    self.apply_fork_created(parent_session_id, session_id, short_id, seed_composer);
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
                let cfg = cockpit_core::secret_ref::load_effective(&cwd);
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
