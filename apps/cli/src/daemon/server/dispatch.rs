async fn handle_request(
    request: Request,
    state: &mut ClientState,
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    prune_expired_attachments(state);
    let request_kind = principal::request_kind(&request);
    let audit_session_id = request_session_id(&request, state);
    let audit_path = request_audit_path(&request);
    let audit_remote = !state.principal.is_owner() && is_remote_mutating_request(&request);
    if let Err(error) = authorize_request(&request, state, ctx) {
        if audit_remote {
            audit_remote_request(
                ctx,
                &state.principal,
                request_kind,
                audit_session_id,
                audit_path.as_deref(),
                "denied",
            );
        }
        return Err(error);
    }
    if audit_remote {
        audit_remote_request(
            ctx,
            &state.principal,
            request_kind,
            audit_session_id,
            audit_path.as_deref(),
            "allowed",
        );
    }
    match request {
        Request::Attach {
            session_id,
            since_seq,
            project_root,
            no_sandbox,
            interactive,
            model_override,
            client_protocol_version,
            env_snapshot,
            env_policy,
        } => {
            let principal = state.principal.clone();
            attach(
                state,
                ctx,
                session_id,
                since_seq,
                project_root,
                no_sandbox,
                interactive,
                model_override,
                client_protocol_version,
                env_snapshot,
                env_policy,
                &principal,
            )
            .await
        }

        Request::SubagentTranscript {
            session_id,
            task_call_id,
            label,
        } => {
            let db = ctx.db.clone();
            let task_call_id_for_read = task_call_id.clone();
            let label_for_read = label.clone();
            let history = db
                .read(move |conn| {
                    crate::engine::rehydrate::subagent_history_snapshot_conn(
                        conn,
                        session_id,
                        &task_call_id_for_read,
                        &label_for_read,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SubagentTranscript {
                session_id,
                task_call_id,
                label,
                history,
            })
        }

        Request::SendUserMessage {
            text,
            image_refs,
            forced_skill,
        } => {
            // New-user-work gate (`daemon-graceful-drain-shutdown.md`): once
            // a drain begins, reject new turns with a short notice rather
            // than silently dropping or queuing them. In-flight turns keep
            // running; this only stops *new* work from starting.
            if ctx.shutdown.is_draining() {
                return Err(ErrorPayload {
                    code: ErrorCode::Shutdown,
                    message: "daemon is shutting down; not accepting new messages".into(),
                });
            }
            let session_id = require_attached(state)?.handle.session_id;
            let images = consume_image_refs(state, session_id, &image_refs)?;
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::UserMessage {
                    submission: Box::new(crate::engine::message::UserSubmission {
                        kind: crate::engine::message::UserSubmissionKind::User,
                        text,
                        images,
                        forced_skill,
                        origin_principal: state.principal.tag(),
                        job_id: None,
                        preflight_cleaned: None,
                        queue_item_ids: Vec::new(),
                        queue_target: None,
                    }),
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let (item, queue) = response_rx.await.map_err(internal)?;
            Ok(Response::UserMessageQueued { item, queue })
        }

        Request::SteerDelegation {
            session_id,
            task_call_id,
            label,
            message,
        } => {
            let Some(handle) = ctx.registry.live_handle(session_id) else {
                return Ok(Response::DelegationSteer {
                    result: proto::DelegationSteerResult::not_steerable(
                        task_call_id,
                        Some(label),
                        "session is not live".to_string(),
                    ),
                });
            };
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            handle
                .send_work(SessionWork::SteerDelegation {
                    task_call_id,
                    label,
                    message,
                    origin_principal: state.principal.steer_origin(),
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::DelegationSteer { result })
        }

        Request::BeginAttachmentUpload {
            mime,
            byte_len,
            sha256,
            purpose,
        } => begin_attachment_upload(state, mime, byte_len, sha256, purpose),

        Request::UploadAttachmentChunk {
            upload_id,
            offset,
            data_base64,
        } => upload_attachment_chunk(state, upload_id, offset, data_base64),

        Request::FinishAttachmentUpload { upload_id } => {
            finish_attachment_upload(state, upload_id).await
        }

        Request::CancelAttachmentUpload { upload_id } => {
            if state.pending_uploads.remove(&upload_id).is_some() {
                release_uploads(&state.upload_accounting, [upload_id]);
            }
            Ok(Response::Ack)
        }

        Request::RemoveQueuedUserMessage { queue_item_id } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveQueuedUserMessage {
                    queue_item_id,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::RemoveQueuedUserMessageResult {
                applied: result.applied,
                reason: result.reason,
                removed_item: result.removed_item,
                queue: result.queue,
            })
        }
        Request::RemoveNewestQueuedUserMessage { target_id } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveNewestQueuedUserMessage {
                    target_id,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::RemoveQueuedUserMessageResult {
                applied: result.applied,
                reason: result.reason,
                removed_item: result.removed_item,
                queue: result.queue,
            })
        }
        Request::RemoveEditableQueuedUserMessages { target_id } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RemoveEditableQueuedUserMessages {
                    target_id,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let result = response_rx.await.map_err(internal)?;
            Ok(Response::RemoveQueuedUserMessagesResult {
                applied: result.applied,
                reason: result.reason,
                removed_items: result.removed_items,
                queue: result.queue,
            })
        }

        Request::ResumePausedWork { session_id } => {
            let changed = ctx
                .db
                .mark_paused_session_work_resumed(session_id)
                .map_err(internal)?;
            if changed
                && let Some(att) = state.attached.as_ref()
                && att.handle.session_id == session_id
            {
                att.handle.broadcast_notice(
                    "paused work resumed; pending approvals will use the normal prompt flow"
                        .to_string(),
                );
            }
            Ok(Response::Ack)
        }

        Request::CancelPausedWork { session_id } => {
            let changed = ctx
                .db
                .cancel_paused_session_work(session_id)
                .map_err(internal)?;
            if changed {
                if let Err(e) = ctx.registry.locks().suspend_session(session_id) {
                    tracing::warn!(error = %e, %session_id, "releasing cancelled paused work locks failed");
                }
                if let Some(att) = state.attached.as_ref()
                    && att.handle.session_id == session_id
                {
                    att.handle.broadcast_notice(
                        "paused work cancelled; the session is waiting for new input".to_string(),
                    );
                }
            }
            Ok(Response::Ack)
        }

        Request::RepairResume { session_id } => {
            let att = require_attached(state)?;
            if att.handle.session_id != session_id {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "repair_resume session_id does not match the attached session".into(),
                });
            }
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::RepairResume { respond_to })
                .await
                .map_err(internal)?;
            match response_rx.await.map_err(internal)? {
                Ok(()) => Ok(Response::Ack),
                Err(message) => Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message,
                }),
            }
        }

        Request::CancelTurn => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Cancel)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::FsList {
            project_root,
            path,
            show_hidden,
        } => crate::daemon::fs_api::fs_list(&state.principal, &project_root, &path, show_hidden),

        Request::FsStat { project_root, path } => {
            crate::daemon::fs_api::fs_stat(&state.principal, &project_root, &path)
        }

        Request::FsRead {
            project_root,
            path,
            base64,
        } => crate::daemon::fs_api::fs_read(&state.principal, &project_root, &path, base64),

        Request::FsWrite {
            project_root,
            path,
            content,
            base_hash,
        } => crate::daemon::fs_api::fs_write(ctx, &project_root, &path, &content, base_hash),

        Request::FsCreateDir { project_root, path } => {
            crate::daemon::fs_api::fs_create_dir(&project_root, &path)
        }

        Request::FsRename {
            project_root,
            from_path,
            to_path,
        } => crate::daemon::fs_api::fs_rename(ctx, &project_root, &from_path, &to_path),

        Request::FsDelete { project_root, path } => {
            crate::daemon::fs_api::fs_delete(ctx, &project_root, &path)
        }

        Request::GitStatus { project_root } => crate::daemon::fs_api::git_status(&project_root),

        Request::GitDiffFile { project_root, path } => {
            crate::daemon::fs_api::git_diff_file(&project_root, &path)
        }

        Request::OpenTerminal { cwd, cols, rows } => {
            let response = state.terminal_host.open(cwd, cols, rows)?;
            if let Response::TerminalOpened { terminal_id, .. } = response {
                state.terminal_views.insert(terminal_id);
                Ok(Response::TerminalOpened {
                    terminal_id,
                    viewer_count: 1,
                    recording: false,
                })
            } else {
                Ok(response)
            }
        }

        Request::AttachTerminal {
            terminal_id,
            cols,
            rows,
        } => {
            let response = state.terminal_host.attach(terminal_id, cols, rows)?;
            state.terminal_views.insert(terminal_id);
            Ok(response)
        }

        Request::TerminalInput { terminal_id, bytes } => {
            state.terminal_host.input(terminal_id, bytes)
        }

        Request::TerminalResize {
            terminal_id,
            cols,
            rows,
        } => state.terminal_host.resize(terminal_id, cols, rows),

        Request::CloseTerminal { terminal_id } => {
            state.terminal_views.remove(&terminal_id);
            state.terminal_host.close(terminal_id)
        }

        Request::LspControl {
            project_root,
            server_id,
            action,
        } => {
            let att = require_attached(state)?;
            let cwd = Path::new(&project_root);
            let config = crate::config::trust::with_workspace_trust_policy(
                att.handle.trust_policy.clone(),
                || crate::config::extended::load_for_cwd(cwd),
            );
            let message = ctx
                .registry
                .lsp_manager()
                .control(cwd, &server_id, action, &config)
                .await;
            att.handle.broadcast_notice(message.clone());
            Ok(Response::LspControlResult { message })
        }

        Request::ResolveInterrupt {
            interrupt_id,
            response,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::ResolveInterrupt {
                    interrupt_id,
                    response,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::ListSessions {
            project_id,
            parent_session_id,
        } => list_sessions(ctx, &state.principal, project_id, parent_session_id).await,

        Request::ReadSessionMessages {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let (messages, has_more) = db
                .read(move |conn| {
                    crate::db::Db::read_session_messages_conn(
                        conn, session_id, before_seq, limit,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SessionMessages {
                session_id,
                messages,
                has_more,
            })
        }

        Request::SessionLiveStatus { session_ids } => {
            let mut visible_ids = Vec::new();
            for id in session_ids {
                if state.principal.is_owner() {
                    visible_ids.push(id);
                    continue;
                }
                match ctx.db.get_session(id) {
                    Ok(Some(row))
                        if session_access_for_row(&state.principal, &row)
                            != SessionAccess::None =>
                    {
                        visible_ids.push(id);
                    }
                    Ok(_) => {}
                    Err(e) => return Err(internal(e)),
                }
            }
            let statuses = visible_ids
                .into_iter()
                .filter_map(|id| {
                    ctx.registry
                        .live_status(id)
                        .map(|(has_active_schedules, processing, _tool_running)| proto::LiveStatus {
                            session_id: id,
                            has_active_schedules,
                            processing,
                        })
                })
                .collect();
            Ok(Response::SessionLiveStatus { statuses })
        }

        Request::ArchiveSession {
            session_id,
            cascade,
        } => archive_session(ctx, session_id, cascade).await,

        Request::UnarchiveSession { session_id } => unarchive_session(ctx, session_id),

        Request::ForkSession {
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        } => fork_session(
            ctx,
            &state.principal,
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        ),

        Request::DiscardSession { session_id } => discard_session(state, ctx, session_id).await,

        Request::RenameSession { session_id, title } => rename_session(ctx, session_id, &title),

        Request::ShareSession { session_id, shared } => {
            ctx.db
                .set_session_shared_with_collaborators(session_id, shared)
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::RecordSessionNote { session_id, text } => {
            record_session_note(ctx, session_id, &text)
        }

        Request::DeleteSession {
            session_id,
            cascade,
        } => delete_session(ctx, session_id, cascade).await,

        Request::ListSkills { project_root } => {
            // Resolve the configured scan dirs from the client's cwd so
            // per-project skills config applies, then run the shared
            // discovery used by the `skill` tool and auto-select path.
            let att = require_attached(state)?;
            let cwd = Path::new(&project_root);
            let extended = crate::config::trust::with_workspace_trust_policy(
                att.handle.trust_policy.clone(),
                || crate::config::extended::load_for_cwd(cwd),
            );
            let skills = crate::skills::discover(cwd, &extended.skills).map_err(internal)?;
            let skills = skills
                .into_iter()
                .map(|s| proto::SkillSummary {
                    name: s.frontmatter.name,
                    description: s.frontmatter.description,
                    source: s.source.display().to_string(),
                })
                .collect();
            Ok(Response::Skills { skills })
        }
        Request::ResourceSnapshot => Ok(Response::ResourceSnapshot {
            snapshot: resource_scheduler_snapshot(ctx),
        }),
        Request::PromoteResource {
            request_id,
            session_id,
        } => promote_resource_request(ctx, &request_id, session_id),

        Request::ListAgents => Err(not_implemented("ListAgents")),
        Request::ListModels { .. } => Err(not_implemented("ListModels")),

        Request::SetActiveModel { provider, model } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetActiveModel { provider, model })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetAgent { name } => {
            let att = require_attached(state)?;
            validate_set_agent(att, &name)?;
            att.handle
                .send_work(SessionWork::SetAgent { name })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetLlmMode { mode } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetLlmMode { mode })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetSessionLlmMode { mode } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetSessionLlmMode { mode })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetApprovalMode { mode } => {
            let att = require_attached(state)?;
            let mode = att.handle.set_approval_mode(mode);
            Ok(Response::ApprovalModeState { mode })
        }

        Request::SetDelegationRecursion {
            enabled,
            default_depth,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetDelegationRecursion {
                    enabled,
                    default_depth,
                })
                .await
                .map_err(internal)?;
            Ok(Response::DelegationRecursionState {
                enabled,
                default_depth,
            })
        }

        Request::SetCaffeinate { mode } => set_caffeinate(state, ctx, mode),

        Request::CancelSchedule { job_id } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::CancelSchedule { job_id })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetSandbox {
            mode,
            container_network_enabled,
        } => {
            // Flip the session's sandbox mode directly (it's a shared
            // atomic) and reply with the resulting state. The handle also
            // broadcasts a `SandboxState` event so every attached client
            // stays in sync.
            let att = require_attached(state)?;
            let new = att
                .handle
                .set_sandbox(mode, container_network_enabled)
                .map_err(bad_request)?;
            Ok(Response::SandboxState {
                mode: new,
                enabled: new.enabled(),
                container_network_enabled: att.handle.container_network_enabled(),
                container_availability: crate::container::availability_snapshot(),
            })
        }

        Request::SetSandboxEscalation { enabled } => {
            let att = require_attached(state)?;
            let enabled = att.handle.set_sandbox_escalation(enabled);
            Ok(Response::SandboxEscalationState { enabled })
        }

        Request::SetPreflight { enabled } => {
            // `/preflight`: route to the worker, which sets the session-only
            // override on the driver (precedence over config), and broadcasts
            // the resulting state (→ toast + mirror). Session-only — no
            // config-file write.
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetPreflight { enabled })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetTrustedOnly { enabled } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetTrustedOnly { enabled })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetRedaction {
            scan_environment,
            scan_dotenv,
            scan_ssh_keys,
        } => {
            // `/toggle-redaction`: route to the worker, which mutates the
            // session's effective `RedactConfig` in memory, rebuilds the
            // redaction table for subsequent outbound prompts, and
            // broadcasts the resulting state (→ toast). Session-only — no
            // config-file write. `scrub()` stays non-bypassable.
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetRedaction {
                    scan_environment,
                    scan_dotenv,
                    scan_ssh_keys,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetTandemModels { models } => {
            // `/model-comparison`: route to the worker, which builds a
            // completion model for each selected `(provider, model)`, replaces
            // the driver's in-memory tandem set, and broadcasts the resulting
            // state (+ token-burn warning) via `Event::TandemState`.
            // Session-only — no config-file write.
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetTandemModels { models })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::Prune => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Prune)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::Compact => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Compact)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::Pin { text } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::Pin { text })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::StoreFlycockpitCredential { credential } => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Flycockpit credential writes",
                ));
            }
            ctx.store_flycockpit_credential(&credential).map_err(internal)?;
            ctx.wake_connector();
            Ok(Response::Ack)
        }

        Request::ClearFlycockpitCredential => {
            if ctx.paths.ephemeral {
                return Err(bad_request(
                    "ephemeral daemons do not accept Flycockpit credential writes",
                ));
            }
            ctx.clear_flycockpit_credential().map_err(internal)?;
            ctx.wake_connector();
            Ok(Response::Ack)
        }

        Request::DaemonStatus => Ok(Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx.db.paused_session_work_all().map_err(internal)?.len() as u32,
        }),

        Request::RefreshEnv { vars } => {
            let att = require_attached(state)?;
            att.handle.set_env_overlay(vars);
            Ok(Response::Ack)
        }

        Request::RecordUsage {
            kind,
            key,
            project_id,
        } => {
            if key.trim().is_empty() {
                return Err(bad_request("usage key cannot be empty"));
            }
            // Global tally — no attached session required.
            ctx.db
                .record_usage(
                    kind.as_str(),
                    &key,
                    project_id.as_deref(),
                    chrono::Utc::now().timestamp(),
                )
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::GetUsageCounts { project_id } => {
            let since = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
            let models = ctx
                .db
                .usage_counts("model", None, since)
                .map_err(internal)?;
            let slash = ctx
                .db
                .usage_counts("slash", None, since)
                .map_err(internal)?;
            // Tags are per-project; with no project there's nothing to
            // scope to, so the map is empty rather than a global mash-up.
            let tags = match project_id.as_deref() {
                Some(pid) => ctx
                    .db
                    .usage_counts("tag", Some(pid), since)
                    .map_err(internal)?,
                None => std::collections::HashMap::new(),
            };
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            })
        }

        Request::GuidanceEstimate {
            project_root,
            provider,
            model,
        } => {
            // Resolve the single guidance file the engine would load and
            // estimate, with the calibrated tokenizer for the active model
            // (cl100k fallback when uncalibrated), two figures: the
            // guidance-file body (the `… in <file>` label) and the full
            // composed system prompt (the fresh-context baseline the
            // running estimate folds in). No session exists yet at the
            // fresh-chat indicator, so the system prompt omits the
            // `Session:` line — matching what the engine then sends.
            let cwd = Path::new(&project_root);
            let (strategy, scale) = ctx.db.resolve_tokenizer(
                provider.as_deref().unwrap_or(""),
                model.as_deref().unwrap_or(""),
            );
            let system_prompt = crate::engine::builtin::default_chat_system_prompt(cwd, "");
            let system_tokens = crate::tokens::scaled_estimate(&system_prompt, strategy, scale);
            let model_instruction_tokens = provider
                .as_deref()
                .zip(model.as_deref())
                .and_then(|(provider, model)| {
                    let cfg = crate::config::providers::ConfigDoc::load_effective(cwd);
                    cfg.resolve_model_system_prompt(provider, model).map(|prompt| {
                        crate::tokens::scaled_estimate(prompt, strategy, scale)
                    })
                })
                .unwrap_or(0);
            match crate::engine::builtin::load_agent_guidance(cwd) {
                Some((path, body)) => {
                    let tokens = crate::tokens::scaled_estimate(&body, strategy, scale);
                    let file = path.file_name().map(|n| n.to_string_lossy().into_owned());
                    Ok(Response::GuidanceEstimate {
                        file,
                        tokens,
                        system_tokens,
                        model_instruction_tokens,
                    })
                }
                None => Ok(Response::GuidanceEstimate {
                    file: None,
                    tokens: 0,
                    system_tokens,
                    model_instruction_tokens,
                }),
            }
        }

        Request::StopDaemon { grace_secs } => {
            tracing::info!(?grace_secs, "StopDaemon requested via client");
            if let Some(secs) = grace_secs {
                ctx.set_shutdown_grace_override(std::time::Duration::from_secs(secs));
            }
            // Route through the single graceful-shutdown path
            // (`daemon-graceful-drain-shutdown.md`): the same begin-drain /
            // shorten-to-force transition SIGINT/SIGTERM and the ephemeral
            // teardown use. A second `StopDaemon` while already draining
            // shortens to an immediate force-exit instead of starting a
            // second drain or resetting the deadline.
            request_shutdown(ctx);
            Ok(Response::Ack)
        }
    }
}

// ---- shutdown -------------------------------------------------------------

/// The single entry point every stop trigger (SIGINT/SIGTERM, explicit
/// `StopDaemon`, the ephemeral last-client/owner-exit teardown) routes
/// through (`daemon-graceful-drain-shutdown.md`).
///
/// First call begins the drain: it broadcasts the `DaemonDraining { forced:
/// false }` notice (TUIs show "finishing in-flight work, shutting down…"
/// and start refusing new input) and flips the central gate so the
/// inference-dispatch chokepoint refuses new provider requests. A *second*
/// call while already draining **shortens** to an immediate force-exit —
/// it promotes the gate to `Forced` and broadcasts `DaemonDraining { forced:
/// true }`. Both transitions are monotonic/idempotent, so a redundant
/// trigger never starts a second drain, resets the deadline, or deadlocks.
pub fn request_shutdown(ctx: &Arc<DaemonContext>) {
    if ctx.shutdown.begin_drain() {
        tracing::info!("daemon: graceful drain begun");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: false });
    } else if !ctx.shutdown.is_forced() {
        // Already draining and a second trigger arrived: shorten to force.
        ctx.shutdown.force();
        tracing::warn!("daemon: second stop request during drain; forcing exit");
        ctx.broadcast_global(proto::Event::DaemonDraining { forced: true });
    }
}

// ---- helpers --------------------------------------------------------------

/// Apply a `/caffeinate` request: resolve the display-awake scope from
/// config, drive the daemon-held [`CaffeineController`], broadcast the
/// resulting state to **all** clients, and (for `until-idle`) arm the
/// daemon's auto-off watcher. The OS assertion lives in this process so it
/// survives the requesting client's exit.
fn set_caffeinate(
    state: &ClientState,
    ctx: &Arc<DaemonContext>,
    mode: crate::daemon::caffeinate::CaffeinateMode,
) -> std::result::Result<Response, ErrorPayload> {
    use crate::daemon::caffeinate::InhibitScope;

    // Display-awake is a config setting; resolve it from the attached
    // session's project root when available, else the daemon's cwd.
    let attached_policy = state
        .attached
        .as_ref()
        .map(|att| att.handle.trust_policy.clone());
    let cfg_root = state
        .attached
        .as_ref()
        .map(|att| att.handle.project_root.clone())
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    let configs = match attached_policy {
        Some(policy) => load_configs_with_trust(&cfg_root, &policy),
        None => load_configs(&cfg_root),
    };
    let scope: InhibitScope = match configs {
        Ok((_, extended)) => extended.tui.sleep_scope().into(),
        // Config read failure must not block caffeination: fall back to
        // the safe default (system-only, display free to sleep).
        Err(_) => InhibitScope {
            keep_display_on: false,
        },
    };

    match ctx.caffeinate.apply(mode, scope) {
        Ok(applied) => {
            // Broadcast to every client so the ☕ glyph stays in sync.
            ctx.broadcast_global(proto::Event::CaffeinateState {
                active: applied.state.active,
                lid_close_guaranteed: applied.lid_close_guaranteed,
                message: None,
            });
            // Arm the daemon-owned until-idle watcher: it polls "is any
            // agent running?" and auto-offs once none are.
            if applied.state.until_idle {
                spawn_until_idle_watcher(ctx.clone());
            }
            Ok(Response::CaffeinateState {
                active: applied.state.active,
                lid_close_guaranteed: applied.lid_close_guaranteed,
                message: applied.message,
            })
        }
        // Missing-mechanism / acquire failure: report it so the TUI shows
        // an honest, actionable toast (never silent). State stays off.
        Err(message) => Ok(Response::CaffeinateState {
            active: false,
            lid_close_guaranteed: false,
            message,
        }),
    }
}

/// Poll interval for the until-idle auto-off watcher. Short enough that
/// the machine doesn't stay awake long after the last agent finishes,
/// long enough to be negligible overhead.
const UNTIL_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn the daemon's `until-idle` auto-off watcher. The daemon owns the
/// session workers / `ScheduleAuthority`, so it is the authority for "is an
/// agent running anywhere?". The watcher polls that and, once no agent is
/// running, releases the assertion and broadcasts the off-state to all
/// clients. It exits if the mode is no longer until-idle (a later
/// `on`/`off`/`toggle` superseded it) so a fresh `until-idle` can re-arm
/// without stacking watchers racing each other.
fn spawn_until_idle_watcher(ctx: Arc<DaemonContext>) {
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(UNTIL_IDLE_POLL).await;
            // Superseded (explicit on/off, or already auto-offed): stop.
            if !ctx.caffeinate.is_until_idle() {
                return;
            }
            let running = ctx.registry.any_agent_running();
            if let Some(applied) = ctx.caffeinate.idle_check(running) {
                ctx.broadcast_global(proto::Event::CaffeinateState {
                    active: applied.state.active,
                    lid_close_guaranteed: applied.lid_close_guaranteed,
                    message: None,
                });
                return;
            }
        }
    });
}

/// Poll interval for the idle-lock sweeper. Short relative to
/// [`crate::locks::LOCK_IDLE_TIMEOUT`] (5 min) so a reclaimable lock is
/// freed within a few seconds of crossing the threshold, but coarse enough
/// to be negligible overhead.
const LOCK_SWEEP_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn the daemon's idle-lock sweeper
/// (implementation note). On each tick it asks the
/// single lock authority to reclaim any lock whose holder has been idle
/// past [`crate::locks::LOCK_IDLE_TIMEOUT`] — releasing it, invalidating the
/// §3c read-record, persisting the release, and waking blocked `readlock`
/// waiters so they proceed. Modeled on [`spawn_until_idle_watcher`]; runs
/// for the daemon's lifetime and exits when the daemon drains.
pub(crate) fn spawn_lock_sweeper(ctx: Arc<DaemonContext>) {
    let locks = ctx.registry.locks();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(LOCK_SWEEP_POLL).await;
            if ctx.shutdown.is_draining() {
                return;
            }
            let now = chrono::Utc::now().timestamp();
            match locks.sweep_expired(now) {
                Ok(reclaimed) if !reclaimed.is_empty() => {
                    tracing::info!(count = reclaimed.len(), "swept idle-expired locks");
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "idle-lock sweep failed"),
            }
        }
    });
}

#[allow(clippy::too_many_arguments)]
async fn attach(
    state: &mut ClientState,
    ctx: &DaemonContext,
    session_id: Option<Uuid>,
    since_seq: Option<i64>,
    project_root: Option<String>,
    no_sandbox: bool,
    interactive: bool,
    model_override: Option<String>,
    client_protocol_version: u32,
    env_snapshot: Option<EnvSnapshotWire>,
    env_policy: EnvDriftPolicy,
    principal: &ClientPrincipal,
) -> std::result::Result<Response, ErrorPayload> {
    // The client's `--no-sandbox` only governs sessions it *creates*
    // (sandboxing part 2). On resume of an existing session id the session
    // keeps its own runtime state, so the flag is ignored there.
    let client_no_sandbox = no_sandbox && session_id.is_none();
    // The plan-level model override (`cockpit run --model`) governs only
    // sessions this attach *creates*; on resume the worker is already
    // running, so the flag is ignored (mirrors `--no-sandbox`).
    let model_override = model_override.filter(|_| session_id.is_none());
    let project_root = project_root.map(PathBuf::from);

    let cfg_root = match (session_id, &project_root) {
        (Some(id), _) => match ctx.db.get_session(id) {
            Ok(Some(row)) => Some(PathBuf::from(row.project_root)),
            Ok(None) => {
                return Err(ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {id}"),
                });
            }
            Err(e) => return Err(internal(e)),
        },
        (None, Some(root)) => Some(root.clone()),
        (None, None) => {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "attach requires session_id or project_root".into(),
            });
        }
    };

    let cfg_root = cfg_root.expect("resolved above");
    let remote_readonly_attach = !principal.is_owner()
        && !principal.can_agent_write_project(&cfg_root.to_string_lossy())
        && principal.can_agent_read_project(&cfg_root.to_string_lossy());
    let client_no_sandbox = client_no_sandbox && !remote_readonly_attach;
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cfg_root)
            .map_err(internal)?;
    let (providers_cfg, extended_cfg) =
        load_configs_with_trust(&cfg_root, &trust_policy).map_err(internal)?;
    let client_snapshot = env_snapshot.map(EnvSnapshot::from_wire);
    let (session_env, env_baseline_meta, env_session_meta, env_drift, env_policy_applied) =
        select_session_env(ctx, client_snapshot, env_policy)?;

    let handle = ctx
        .registry
        .attach(
            session_id,
            project_root,
            &providers_cfg,
            &extended_cfg,
            client_no_sandbox,
            model_override.as_deref(),
            trust_policy,
            session_env,
        )
        .await
        .map_err(internal)?;

    if session_id.is_none()
        && let Some(tag) = principal.tag()
    {
        handle
            .set_created_by_principal(Some(tag))
            .map_err(internal)?;
    }
    if remote_readonly_attach {
        let _ = handle.set_sandbox(Some(crate::tools::sandbox_mode::SandboxMode::Sandbox), None);
        handle.set_approval_mode(crate::config::extended::ApprovalMode::Manual);
    }

    // Replace any prior attachment. Register this client with the worker's
    // interactive-client counter when it can answer interrupts (the loop
    // guard reads that count for headless detection). Building the guard
    // before the old `state.attached` is replaced means a re-attach by the
    // same client transiently holds two guards, never zero — the count
    // can't briefly read headless mid-swap.
    let event_rx = handle.subscribe();
    let interactive_guard = if interactive {
        Some(handle.register_interactive_client())
    } else {
        None
    };
    let session_id = handle.session_id;

    // Read/unread marker (GOALS §17f): the session just became active for
    // this client, so everything the agent produced up to now is "seen."
    // Best-effort — a marker write failure must not block the attach.
    if let Err(e) = handle.mark_viewed() {
        tracing::warn!(error = %e, %session_id, "mark_session_viewed failed");
    }

    let foreground = handle.foreground_snapshot();
    let project_root = handle.project_root.to_string_lossy().into_owned();
    let active_agent = foreground
        .active_agent_path
        .last()
        .cloned()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| handle.active_agent_name.clone());
    // Source identity from the live session, not a DB read: a freshly
    // created session is deferred-persistence (session-id-display-and-lazy-
    // persist) and has no `sessions` row yet, so `get_session` would miss.
    let project_id = handle.project_id();
    let short_id = handle.short_id();

    state.pending_uploads.clear();
    state.ready_attachments.clear();
    state.upload_limits = extended_cfg.daemon.uploads.into();
    state.attached = Some(AttachedSession {
        handle,
        event_rx,
        _interactive_guard: interactive_guard,
    });

    // Hydrate the gitignore read-allowlist for this client
    // (implementation note): broadcast the session's
    // current session-approved globs over the per-session bus so a late-opened
    // or reconnecting TUI — and any second concurrent client — re-includes
    // approvals made before it attached, not only ones broadcast live
    // afterward. The just-subscribed `event_rx` receives it; full-list replace,
    // idempotent for already-attached clients. Only the allow-set is sent.
    if let Some(att) = state.attached.as_ref() {
        att.handle.broadcast_gitignore_allow();
        att.handle.broadcast_active_interrupt();
        att.handle.broadcast_sandbox_escalation();
        att.handle.broadcast_sandbox_unavailable_or_probe();
    }

    // Full chronological history snapshot (user messages + assistant turns +
    // tool calls) for the attached session, so a resuming TUI repopulates the
    // whole prior transcript (implementation note). Run the
    // scan-shaped attach reads on one blocking DB worker and one mutex
    // acquisition, while preserving the single history projection source.
    let db = ctx.db.clone();
    let extended_cfg_for_attach = extended_cfg.clone();
    let active_subagent_for_attach = foreground.active_subagent.clone();
    let (mut history, paused_work, replay_max_seq): (
        Vec<proto::HistoryEntry>,
        Vec<proto::PausedWorkSummary>,
        Option<i64>,
    ) = db
        .read(move |conn| {
            let root_agent = crate::daemon::session_worker::resolve_root_agent_conn(
                conn,
                session_id,
                &extended_cfg_for_attach,
            );
            let (history, replay_max_seq) = if let Some(since_seq) = since_seq {
                let replay_max_seq =
                    crate::db::Db::list_session_events_since_conn(conn, session_id, since_seq)
                        .ok()
                        .and_then(|rows| rows.into_iter().map(|row| row.seq).max());
                let history =
                    crate::engine::rehydrate::history_snapshot_since_with_active_subagent_conn(
                        conn,
                        session_id,
                        &root_agent,
                        active_subagent_for_attach.as_ref(),
                        since_seq,
                    )
                    .unwrap_or_else(|e| {
                        tracing::warn!(error = %e, %session_id, since_seq, "building attach replay snapshot failed; sending empty replay");
                        Vec::new()
                    });
                (history, replay_max_seq)
            } else {
                let history = crate::engine::rehydrate::history_snapshot_with_active_subagent_conn(
                    conn,
                    session_id,
                    &root_agent,
                    active_subagent_for_attach.as_ref(),
                )
                .unwrap_or_else(|e| {
                    tracing::warn!(error = %e, %session_id, "building attach history snapshot failed; sending empty history");
                    Vec::new()
                });
                (history, None)
            };
            let paused_work = crate::db::Db::paused_session_work_conn(conn, session_id)?
                .into_iter()
                .map(paused_work_to_proto)
                .collect();
            Ok((history, paused_work, replay_max_seq))
        })
        .await
        .map_err(internal)?;
    if !paused_work.is_empty()
        && let Some(att) = state.attached.as_ref()
    {
        att.handle.broadcast_notice(
            "paused work is waiting for resume or cancel after daemon restart".to_string(),
        );
    }

    history = if let Some(att) = state.attached.as_ref() {
        let redact = att.handle.redaction_table();
        scrub_history_for_principal(&state.principal, history, &redact)
    } else {
        history
    };
    if let Some(max_seq) = replay_max_seq {
        if !history.is_empty() {
            state.pending_replay.push(proto::Event::HistoryReplay {
                session_id,
                entries: history,
                max_seq,
            });
        }
        history = Vec::new();
    }

    Ok(Response::Attached {
        session_id,
        short_id,
        project_root,
        project_id,
        active_agent,
        active_agent_path: foreground.active_agent_path,
        foreground_target: Some(foreground.foreground_target),
        active_subagent: foreground.active_subagent,
        history,
        paused_work,
        repair_required: state
            .attached
            .as_ref()
            .and_then(|att| att.handle.repair_required())
            .map(Box::new),
        daemon_version: proto::DAEMON_VERSION.to_string(),
        compatible: proto::is_protocol_compatible(client_protocol_version),
        env_baseline: Some(env_baseline_meta),
        env_session: Some(env_session_meta),
        env_drift: env_drift.map(Box::new),
        env_policy_applied,
    })
}

fn select_session_env(
    ctx: &DaemonContext,
    client_snapshot: Option<EnvSnapshot>,
    policy: EnvDriftPolicy,
) -> std::result::Result<
    (
        EnvSnapshot,
        EnvSnapshotMeta,
        EnvSnapshotMeta,
        Option<EnvDiffSummary>,
        EnvDriftPolicy,
    ),
    ErrorPayload,
> {
    let Some(client_snapshot) = client_snapshot else {
        let baseline = ctx
            .env_baseline
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        let meta = baseline.meta();
        return Ok((baseline, meta.clone(), meta, None, EnvDriftPolicy::Daemon));
    };

    let baseline = ctx
        .env_baseline
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let drift = diff_summary(&baseline, &client_snapshot).filter(EnvDiffSummary::meaningful);
    if matches!(policy, EnvDriftPolicy::ErrorOnDrift) && drift.is_some() {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "client environment differs from daemon baseline".to_string(),
        });
    }

    let chosen = match policy {
        EnvDriftPolicy::Daemon | EnvDriftPolicy::ErrorOnDrift => baseline.clone(),
        EnvDriftPolicy::Client => client_snapshot.clone(),
        EnvDriftPolicy::UpdateDaemon => {
            {
                let mut guard = ctx
                    .env_baseline
                    .write()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                *guard = client_snapshot.clone();
            }
            client_snapshot.clone()
        }
    };
    let baseline_meta = if matches!(policy, EnvDriftPolicy::UpdateDaemon) {
        client_snapshot.meta()
    } else {
        baseline.meta()
    };
    let session_meta = chosen.meta();
    if matches!(policy, EnvDriftPolicy::Daemon)
        && let Some(diff) = drift.clone()
    {
        ctx.broadcast_global(proto::Event::EnvDriftWarning {
            baseline: baseline.meta(),
            candidate: client_snapshot.meta(),
            diff,
            policy,
        });
    }
    Ok((chosen, baseline_meta, session_meta, drift, policy))
}

fn paused_work_to_proto(row: crate::db::paused_work::PausedWorkRow) -> proto::PausedWorkSummary {
    proto::PausedWorkSummary {
        session_id: row.session_id,
        active_agent: row.active_agent,
        project_root: row.project_root,
        reason: row.reason,
        pending_tool_count: row.pending_tool_count,
        daemon_version: row.daemon_version,
        client_version: row.client_version,
        updated_at: row.updated_at,
    }
}
