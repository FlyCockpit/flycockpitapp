use super::attachments::*;
use super::authz::*;
use super::sessions::*;
use super::*;

static WORKSPACE_TRUST_RPC_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn app_flag_db_key(key: proto::AppFlagKey) -> &'static str {
    match key {
        proto::AppFlagKey::DaemonAutostartNotice => "daemon-autostart",
    }
}

fn workspace_trust_mode_to_db(
    mode: proto::WorkspaceTrustMode,
) -> crate::db::workspace_trust::WorkspaceTrustMode {
    match mode {
        proto::WorkspaceTrustMode::Trust => crate::db::workspace_trust::WorkspaceTrustMode::Trust,
        proto::WorkspaceTrustMode::IgnoreConfig => {
            crate::db::workspace_trust::WorkspaceTrustMode::IgnoreConfig
        }
        proto::WorkspaceTrustMode::Untrusted => {
            crate::db::workspace_trust::WorkspaceTrustMode::Untrusted
        }
    }
}

fn org_disclosure_to_proto(
    value: crate::db::org_sync::OrgSyncDisclosure,
) -> proto::OrgSyncDisclosure {
    proto::OrgSyncDisclosure {
        org_id: value.org_id,
        cursor_seq: value.cursor_seq,
        last_synced_at_ms: value.last_synced_at_ms,
    }
}

fn connector_disclosure_to_proto(
    value: crate::db::connector::ConnectorDisclosure,
) -> proto::ConnectorDisclosure {
    proto::ConnectorDisclosure {
        enabled: value.enabled,
        status: value.status,
        relay_url: value.relay_url,
        relay_id: value.relay_id,
        relay_region: value.relay_region,
        last_error: value.last_error,
    }
}

#[cfg(test)]
pub(super) async fn handle_request(
    request: Request,
    state: &mut MutableClientState,
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    let mut effects = ClientRequestEffects::default();
    let shared = state.shared_snapshot();
    let result = handle_serialized_request(request, state, &shared, ctx, &mut effects).await;
    if effects.shutdown_after_response {
        request_shutdown(ctx);
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn handle_send_user_message(
    state: &mut MutableClientState,
    ctx: &Arc<DaemonContext>,
    client_submission_id: Uuid,
    expected_model_state_generation: Option<u64>,
    expected_model: Option<cockpit_config::config::providers::ActiveModelRef>,
    text: String,
    display_text: Option<String>,
    tag_expansions: Vec<proto::TagExpansionMeta>,
    image_refs: Vec<proto::ImageAttachmentRef>,
    forced_skill: Option<String>,
    run_invocation_options: Option<proto::RunInvocationOptions>,
) -> std::result::Result<Response, ErrorPayload> {
    if let Some(scheduler) = &ctx.scheduler {
        scheduler.record_user_activity().await;
    }
    if ctx.shutdown.is_draining() {
        return Err(ErrorPayload {
            code: ErrorCode::Shutdown,
            message: "daemon is shutting down; not accepting new messages".into(),
        });
    }
    let session_id = require_attached(state)?.handle.session_id;
    let handle = require_attached(state)?.handle.clone();
    let origin_principal = state.principal.tag();
    let mut wire_fingerprint = user_message_wire_fingerprint(
        &text,
        display_text.as_deref(),
        &tag_expansions,
        &image_refs,
        forced_skill.as_deref(),
    );
    if let (Some(generation), Some(model)) =
        (expected_model_state_generation, expected_model.as_ref())
    {
        let model_json = serde_json::to_string(model).map_err(internal)?;
        wire_fingerprint.push_str(&format!("|model:{generation}:{model_json}"));
    }
    // Run marker acceptance is a durable barrier before queueing. Include
    // immutable options in the fingerprint so option drift conflicts.
    if let Some(options) = &run_invocation_options {
        let opts_digest = run_invocation::options_digest(options);
        wire_fingerprint = format!("{wire_fingerprint}|run:{opts_digest}");
        let _accepted = run_invocation::accept_run_if_marked(
            ctx,
            &state.principal,
            session_id,
            client_submission_id,
            &wire_fingerprint,
            options,
            run_invocation::wall_ms_now(),
        )
        .await?;
    }
    let mut requires_content_check = false;
    if !image_refs.is_empty() {
        let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
        handle
            .send_work(SessionWork::ProbeUserMessage {
                client_submission_id,
                wire_fingerprint: wire_fingerprint.clone(),
                origin_principal: origin_principal.clone(),
                respond_to: probe_tx,
            })
            .await
            .map_err(internal)?;
        match probe_rx.await.map_err(internal)?? {
            UserMessageProbeResult::Duplicate { item, queue } => {
                return Ok(Response::UserMessageQueued { item, queue });
            }
            UserMessageProbeResult::Conflict => {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: format!(
                        "client_submission_id {client_submission_id} was already used by a different principal"
                    ),
                });
            }
            UserMessageProbeResult::Unknown => {}
            UserMessageProbeResult::ContentCheckRequired => requires_content_check = true,
        }
    }
    let images = match claim_message_image_refs(
        state,
        session_id,
        client_submission_id,
        &image_refs,
    ) {
        Ok(images) => images,
        Err(_) if requires_content_check => {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: format!(
                    "client_submission_id {client_submission_id} was already used for a different payload"
                ),
            });
        }
        Err(error) => return Err(error),
    };
    let (respond_to, response_rx) = tokio::sync::oneshot::channel();
    let mut submission = crate::engine::message::UserSubmission {
        origin: crate::engine::message::SubmissionOrigin::ExternalRoot,
        expected_model_state_generation,
        expected_model,
        kind: crate::engine::message::UserSubmissionKind::User,
        text,
        display_text,
        tag_expansions,
        images,
        forced_skill,
        origin_principal: origin_principal.clone(),
        job_id: None,
        preflight_cleaned: None,
        queue_item_ids: Vec::new(),
        client_submissions: Vec::new(),
        queue_target: None,
        pending_terminal_disposition: None,
        run_invocation_id: run_invocation_options
            .as_ref()
            .map(|_| client_submission_id),
    };
    let fingerprint = submission.client_fingerprint();
    submission
        .client_submissions
        .push(crate::engine::message::ClientSubmissionReceipt {
            id: client_submission_id,
            fingerprint,
            wire_fingerprint,
            origin_principal,
        });
    handle
        .send_work(SessionWork::UserMessage {
            submission: Box::new(submission),
            respond_to,
        })
        .await
        .map_err(internal)?;
    let actor_result = response_rx.await.map_err(internal)?;
    let (item, queue) = match actor_result {
        Ok(result) => result,
        Err(error) => {
            if error.code == ErrorCode::ModelGenerationStale {
                release_message_image_refs(state, client_submission_id, &image_refs);
            }
            return Err(error);
        }
    };
    Ok(Response::UserMessageQueued { item, queue })
}

pub(super) async fn handle_serialized_request(
    request: Request,
    state: &mut MutableClientState,
    shared: &Arc<SharedClientState>,
    ctx: &Arc<DaemonContext>,
    effects: &mut ClientRequestEffects,
) -> std::result::Result<Response, ErrorPayload> {
    validate_request_semantics(&request)?;
    debug_assert_eq!(shared.principal, state.principal);
    prune_expired_attachments(state);
    let request_kind = principal::request_kind(&request);
    let audit_session_id = request_session_id(&request, state);
    let audit_path = request_audit_path(&request);
    let audit_remote = !state.principal.is_owner() && is_remote_mutating_request(&request);
    if let Err(error) = authorize_request(&request, state, ctx).await {
        if audit_remote {
            audit_remote_request(
                ctx,
                &state.principal,
                request_kind,
                audit_session_id,
                audit_path.as_deref(),
                "denied",
            )
            .await;
        }
        // `SetDefaultModel` is terminal-by-event: a bare authorization error
        // would leave a remote/shared client waiting for a correlated result
        // that never arrives. Emit the typed rejection instead — no scope
        // label, no path, no configuration content, and no mutation.
        if let Request::SetDefaultModel {
            default_update_id, ..
        } = &request
            && let Some(att) = state.attached.as_ref()
        {
            att.handle.broadcast_default_model_update_result(
                *default_update_id,
                proto::DefaultModelStandaloneOutcome::Rejected {
                    user_message: "Changing the default model for new sessions requires the                                    local owner of this workspace."
                        .to_string(),
                    diagnostic_code: "effective_default_local_owner_only".to_string(),
                },
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
        )
        .await;
    }
    match request {
        Request::Attach {
            session_id,
            since_seq,
            project_root,
            initial_model,
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
                initial_model,
                no_sandbox,
                interactive,
                model_override,
                client_protocol_version,
                env_snapshot,
                env_policy,
                &principal,
                effects,
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
            let mut history = db
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
            if !state.principal.is_owner() {
                let redact = if let Some(handle) = ctx.registry.live_handle(session_id) {
                    handle.redaction_table()
                } else {
                    let session = crate::session::Session::resume(ctx.db.clone(), session_id)
                        .map_err(internal)?
                        .ok_or_else(|| ErrorPayload {
                            code: ErrorCode::UnknownSession,
                            message: format!("unknown session {session_id}"),
                        })?;
                    std::sync::Arc::new(
                        session
                            .persisted_redaction_table()
                            .map_err(internal)?
                            .ok_or_else(|| ErrorPayload {
                                code: ErrorCode::Authorization,
                                message: "session transcript redaction data is unavailable"
                                    .to_string(),
                            })?,
                    )
                };
                history = scrub_history_for_principal(&state.principal, history, &redact);
            }
            Ok(Response::SubagentTranscript {
                session_id,
                task_call_id,
                label,
                history,
            })
        }

        Request::SendUserMessage {
            expected_model_state_generation,
            expected_model,
            client_submission_id,
            text,
            display_text,
            tag_expansions,
            image_refs,
            forced_skill,
            run_invocation_options,
        } => {
            Box::pin(handle_send_user_message(
                state,
                ctx,
                client_submission_id,
                expected_model_state_generation,
                expected_model,
                text,
                display_text,
                tag_expansions,
                image_refs,
                forced_skill,
                run_invocation_options,
            ))
            .await
        }

        Request::GetRunInvocationStatus {
            client_submission_id,
        } => {
            run_invocation::handle_get_run_invocation_status(state, ctx, client_submission_id).await
        }

        Request::CancelRunInvocation {
            client_submission_id,
        } => run_invocation::handle_cancel_run_invocation(state, ctx, client_submission_id).await,

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
            let result = response_rx.await.map_err(internal)??;
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
            let result = response_rx.await.map_err(internal)??;
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
            let result = response_rx.await.map_err(internal)??;
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
                .await
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
                .await
                .map_err(internal)?;
            if changed {
                if let Err(e) = ctx.registry.locks().suspend_session(session_id).await {
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

        Request::CreateGoal {
            session_id,
            objective,
            token_budget,
        } => {
            let session = ctx
                .db
                .get_session(session_id)
                .await
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {session_id}"),
                })?;
            let (_, extended) = ctx
                .config_source
                .load(std::path::Path::new(&session.project_root))
                .map_err(internal)?;
            let session_override = session
                .goal_settings_override_json
                .as_deref()
                .map(crate::agents::parse_goal_settings_override_json)
                .transpose()
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?;
            let policy = crate::agents::effective_goal_supervision_for_agent(
                std::path::Path::new(&session.project_root),
                &session.active_agent,
                session_override.as_ref(),
                extended.goal_supervision,
            );
            if !policy.enabled {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "goal supervision is disabled by operator configuration".to_string(),
                });
            }
            policy.validate().map_err(|error| ErrorPayload {
                code: ErrorCode::BadRequest,
                message: error.to_string(),
            })?;
            let budget = token_budget.unwrap_or(policy.default_token_budget);
            if budget <= 0 {
                return Err(ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: "goal budget must be positive".to_string(),
                });
            }
            let goal = ctx
                .db
                .create_session_goal_with_policy(
                    session_id,
                    &session.project_id,
                    &objective,
                    None,
                    Some(budget),
                    &serde_json::to_string(&policy).map_err(internal)?,
                )
                .await
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?;
            let goal = ctx
                .db
                .current_session_goal(session_id, false)
                .await
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::Internal,
                    message: "created goal disappeared".to_string(),
                })?;
            if let Some(attached) = state
                .attached
                .as_ref()
                .filter(|attached| attached.handle.session().id == session_id)
            {
                attached
                    .handle
                    .send_work(SessionWork::WakeGoal)
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::GoalUpdated {
                goal: goal_to_proto(goal),
            })
        }

        Request::GoalStatus { session_id } => {
            ctx.db
                .refresh_session_goal_usage(session_id)
                .await
                .map_err(internal)?;
            let goal = ctx
                .db
                .current_session_goal(session_id, false)
                .await
                .map_err(internal)?
                .map(goal_to_proto);
            Ok(Response::GoalStatus { goal })
        }

        Request::SetGoalStatus { session_id, status } => {
            if status == proto::GoalDisposition::Running {
                let session = ctx
                    .db
                    .get_session(session_id)
                    .await
                    .map_err(internal)?
                    .ok_or_else(|| ErrorPayload {
                        code: ErrorCode::UnknownSession,
                        message: format!("unknown session {session_id}"),
                    })?;
                let (_, extended) = ctx
                    .config_source
                    .load(std::path::Path::new(&session.project_root))
                    .map_err(internal)?;
                if !extended.goal_supervision.enabled {
                    return Err(ErrorPayload {
                        code: ErrorCode::BadRequest,
                        message: "goal supervision is disabled by operator configuration"
                            .to_string(),
                    });
                }
            }
            let goal = ctx
                .db
                .set_session_goal_status(session_id, status)
                .await
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?;
            if status == proto::GoalDisposition::Running
                && let Some(attached) = state
                    .attached
                    .as_ref()
                    .filter(|attached| attached.handle.session().id == session_id)
            {
                attached
                    .handle
                    .send_work(SessionWork::WakeGoal)
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::GoalUpdated {
                goal: goal_to_proto(goal),
            })
        }

        Request::ClearGoal { session_id } => {
            let cleared = ctx
                .db
                .clear_session_goal(session_id)
                .await
                .map_err(internal)?;
            if cleared
                && let Some(attached) = state
                    .attached
                    .as_ref()
                    .filter(|attached| attached.handle.session().id == session_id)
            {
                attached
                    .handle
                    .send_work(SessionWork::WakeGoal)
                    .await
                    .map_err(internal)?;
            }
            Ok(Response::GoalCleared { cleared })
        }

        Request::PinMessage { session_id, seq } => ctx
            .db
            .pin_message(session_id, seq)
            .await
            .map(|changed| Response::PinChanged { changed })
            .map_err(|error| bad_request(error.to_string())),
        Request::UnpinMessage { session_id, seq } => ctx
            .db
            .unpin_message(session_id, seq)
            .await
            .map(|changed| Response::PinChanged { changed })
            .map_err(|error| bad_request(error.to_string())),
        Request::TogglePinnedMessage { session_id, seq } => ctx
            .db
            .toggle_pin(session_id, seq)
            .await
            .map(|pinned| Response::PinToggled { pinned })
            .map_err(|error| bad_request(error.to_string())),
        Request::CountPinnedMessages { session_id } => ctx
            .db
            .count_pins(session_id)
            .await
            .map(|count| Response::PinCount { count })
            .map_err(internal),
        Request::ListPinnedMessageSeqs { session_id } => ctx
            .db
            .list_pin_seqs(session_id)
            .await
            .map(|seqs| Response::PinSeqs { seqs })
            .map_err(internal),
        Request::ListPinnedMessagesWithText { session_id } => ctx
            .db
            .list_pins_with_text(session_id)
            .await
            .map(|pins| Response::PinsWithText {
                pins: pins.into_iter().map(pinned_message_to_proto).collect(),
            })
            .map_err(internal),
        Request::PinnedMessageState { session_id } => {
            let count = ctx.db.count_pins(session_id).await.map_err(internal)?;
            let seqs = ctx.db.list_pin_seqs(session_id).await.map_err(internal)?;
            Ok(Response::PinState {
                state: proto::PinState { count, seqs },
            })
        }
        Request::ListSealedValues { session_id } => ctx
            .db
            .list_sealed_value_metadata(session_id)
            .await
            .map(|values| Response::SealedValues {
                values: values
                    .into_iter()
                    .map(sealed_value_metadata_to_proto)
                    .collect(),
            })
            .map_err(internal),
        Request::DeleteSealedValue {
            session_id,
            value_id,
        } => {
            // Both arms must go through the scoped delete: a session-scope
            // scoped value is dual-written, so removing only the legacy
            // `sealed_values` row would ack a delete that left the record
            // resolvable with no literal behind it.
            let deleted = if let Some(handle) = ctx.registry.live_handle(session_id) {
                handle
                    .delete_sealed_value(&value_id)
                    .await
                    .map_err(internal)?
            } else {
                ctx.db
                    .delete_sealed_value_for_session(
                        session_id.to_string(),
                        value_id.clone(),
                        chrono::Utc::now().timestamp_millis(),
                    )
                    .await
                    .map_err(internal)?
            };
            if !deleted {
                return Err(internal(anyhow::anyhow!(
                    "sealed value `{value_id}` is unknown"
                )));
            }
            Ok(Response::Ack)
        }

        Request::ListProjectNotes { project_root } => ctx
            .db
            .list_project_notes(&project_root)
            .await
            .map(|notes| Response::ProjectNotes {
                notes: notes.into_iter().map(project_note_to_proto).collect(),
            })
            .map_err(internal),
        Request::CreateProjectNote { project_root, name } => ctx
            .db
            .create_project_note(&project_root, &name)
            .await
            .map(|note| Response::ProjectNoteCreated {
                note: project_note_to_proto(note),
            })
            .map_err(|error| bad_request(error.to_string())),
        Request::SetProjectNoteContent {
            project_root,
            id,
            content,
        } => {
            ensure_project_note_member(&ctx.db, &project_root, id).await?;
            ctx.db
                .set_project_note_content(id, &content)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }
        Request::RenameProjectNote {
            project_root,
            id,
            name,
        } => {
            ensure_project_note_member(&ctx.db, &project_root, id).await?;
            ctx.db
                .rename_project_note(id, &name)
                .await
                .map(|name| Response::ProjectNoteRenamed { name })
                .map_err(|error| bad_request(error.to_string()))
        }
        Request::DeleteProjectNote { project_root, id } => {
            ensure_project_note_member(&ctx.db, &project_root, id).await?;
            ctx.db.delete_project_note(id).await.map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetWorkspaceTrust {
            project_root,
            mode,
            expected_config_generation,
        } => {
            let _guard = WORKSPACE_TRUST_RPC_LOCK.lock().await;
            let current = inventory::current_config_generation();
            if current != expected_config_generation {
                return Err(ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: format!(
                        "workspace trust config generation is {current}, expected {expected_config_generation}"
                    ),
                });
            }
            ctx.db
                .set_workspace_trust(
                    PathBuf::from(&project_root).as_path(),
                    workspace_trust_mode_to_db(mode),
                )
                .await
                .map_err(internal)?;
            let config_generation = inventory::compare_and_bump_config_generation(current)
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: "workspace trust config generation changed concurrently".into(),
                })?;
            Ok(Response::WorkspaceTrustSet { config_generation })
        }
        Request::GetStartupDisclosures { project_root: _ } => {
            let (org_sync, connector) =
                if let Some(credential) = crate::auth::flycockpit::maybe_load_credential() {
                    let org = ctx
                        .db
                        .org_sync_disclosure_for_server(&credential.server_url)
                        .await
                        .map_err(internal)?
                        .map(org_disclosure_to_proto);
                    let connector = ctx
                        .db
                        .connector_disclosure(&credential.server_url, &credential.instance_id)
                        .await
                        .map_err(internal)?
                        .map(connector_disclosure_to_proto);
                    (org, connector)
                } else {
                    (None, None)
                };
            Ok(Response::StartupDisclosures {
                org_sync,
                connector,
                config_generation: inventory::current_config_generation(),
            })
        }
        Request::GetAppFlag { key } => {
            let db_key = app_flag_db_key(key);
            let version = ctx
                .db
                .read(move |conn| crate::db::Db::app_flag_version_conn(conn, db_key))
                .await
                .map_err(internal)?;
            Ok(Response::AppFlag {
                key,
                seen: version > 0,
                version,
            })
        }
        Request::MarkAppFlagSeen {
            key,
            expected_version,
        } => {
            let db_key = app_flag_db_key(key);
            let outcome = ctx
                .db
                .write(move |conn| {
                    crate::db::Db::mark_app_flag_seen_versioned_conn(conn, db_key, expected_version)
                })
                .await
                .map_err(internal)?;
            let Some((version, changed)) = outcome else {
                return Err(ErrorPayload {
                    code: ErrorCode::Conflict,
                    message: "app flag version changed; refresh before retrying".into(),
                });
            };
            Ok(Response::AppFlagSeen {
                key,
                version,
                changed,
            })
        }
        Request::ResolveAssistantSession {
            assistant_id,
            project_root,
            mode: proto::AssistantSessionResolutionMode::MostRecentOrCreate,
        } => {
            let assistant_for_db = assistant_id.clone();
            let project_root_for_db = project_root.clone();
            let (session, created) = ctx
                .db
                .write(move |conn| {
                    let assistant = crate::db::Db::get_assistant_conn(conn, &assistant_for_db)?
                        .ok_or_else(|| {
                            anyhow::anyhow!("assistant `{assistant_for_db}` not found")
                        })?;
                    crate::assistants::load_from_row(&assistant)?;
                    let (row, created) =
                        match crate::db::Db::most_recent_session_for_assistant_conn(
                            conn,
                            &assistant_for_db,
                        )? {
                            Some(row) => (row, false),
                            None => {
                                let project_id =
                                    crate::session::project_id_for(Path::new(&project_root_for_db));
                                let row = crate::db::Db::build_new_assistant_session_row_conn(
                                    conn,
                                    &project_id,
                                    &project_root_for_db,
                                    &assistant_for_db,
                                    &assistant_for_db,
                                )?;
                                (crate::db::Db::insert_session_row_conn(conn, &row)?, true)
                            }
                        };
                    let summary = crate::db::Db::list_session_summaries_conn(
                        conn,
                        Some(&row.project_id),
                        None,
                        100,
                    )?
                    .into_iter()
                    .find(|summary| summary.session_id == row.session_id)
                    .ok_or_else(|| anyhow::anyhow!("resolved assistant session is unavailable"))?;
                    Ok((summary, created))
                })
                .await
                .map_err(|error| bad_request(error.to_string()))?;
            Ok(Response::AssistantSessionResolved { session, created })
        }

        Request::ListAssistants => {
            let assistants = ctx
                .db
                .list_assistants()
                .await
                .map_err(internal)?
                .into_iter()
                .map(assistant_to_proto)
                .collect();
            Ok(Response::Assistants { assistants })
        }
        Request::UpsertAssistant {
            name,
            home_dir,
            config_json,
            content_hash,
        } => ctx
            .db
            .upsert_assistant(&name, &home_dir, &config_json, &content_hash)
            .await
            .map(|row| Response::AssistantUpserted {
                assistant: assistant_to_proto(row),
            })
            .map_err(|error| bad_request(error.to_string())),

        Request::CreateAssistantSession {
            name,
            project_root,
            initial_model,
            no_sandbox,
            env_snapshot,
        } => {
            let env_snapshot = env_snapshot.map(EnvSnapshot::from_wire).unwrap_or_else(|| {
                ctx.env_baseline
                    .read()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
            });
            let handle = ctx
                .registry
                .create_assistant_session(
                    &name,
                    PathBuf::from(project_root),
                    initial_model,
                    no_sandbox,
                    env_snapshot,
                )
                .await
                .map_err(|error| {
                    if error
                        .downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
                        .is_some()
                    {
                        daemon_config_error(error)
                    } else {
                        ErrorPayload {
                            code: ErrorCode::BadRequest,
                            message: error.to_string(),
                        }
                    }
                })?;
            Ok(Response::AssistantSessionCreated {
                session: proto::AssistantSessionCreated {
                    session_id: handle.session_id,
                    short_id: handle.short_id(),
                    project_root: handle.project_root.display().to_string(),
                    project_id: handle.project_id(),
                    assistant_name: name,
                    active_agent: handle.active_agent_name,
                },
            })
        }

        Request::AutoTitle { session_id } => auto_title_request(ctx, session_id).await,

        Request::ExportSessionData {
            session_id,
            kind,
            include_generated_artifacts,
            include_sensitive,
        } => {
            export_session_data(
                ctx,
                session_id,
                kind,
                include_generated_artifacts,
                include_sensitive,
            )
            .await
        }

        Request::ImportSessionArchive { transfer, as_new } => {
            import_session_archive(ctx, &transfer, as_new).await
        }
        Request::WriteBulkTransferChunk {
            transfer,
            chunk_index,
            data_base64,
        } => write_bulk_transfer_chunk(&transfer, chunk_index, &data_base64).await,
        Request::ReadBulkTransferChunk {
            transfer_id,
            chunk_index,
        } => read_bulk_transfer_chunk(&transfer_id, chunk_index).await,

        Request::Curator {
            project_root,
            action,
        } => curator_request(ctx, PathBuf::from(project_root), action).await,

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
        } => {
            crate::daemon::fs_api::fs_list(
                ctx.clone(),
                state.principal.clone(),
                project_root,
                path,
                show_hidden,
            )
            .await
        }

        Request::FsStat { project_root, path } => {
            crate::daemon::fs_api::fs_stat(ctx.clone(), state.principal.clone(), project_root, path)
                .await
        }

        Request::FsRead {
            project_root,
            path,
            base64,
        } => {
            crate::daemon::fs_api::fs_read(
                ctx.clone(),
                state.principal.clone(),
                project_root,
                path,
                base64,
            )
            .await
        }

        Request::FsWrite {
            project_root,
            path,
            content,
            base_hash,
        } => {
            crate::daemon::fs_api::fs_write(ctx.clone(), project_root, path, content, base_hash)
                .await
        }

        Request::FsCreateDir { project_root, path } => {
            crate::daemon::fs_api::fs_create_dir(project_root, path).await
        }

        Request::FsRename {
            project_root,
            from_path,
            to_path,
        } => crate::daemon::fs_api::fs_rename(ctx.clone(), project_root, from_path, to_path).await,

        Request::FsDelete { project_root, path } => {
            crate::daemon::fs_api::fs_delete(ctx.clone(), project_root, path).await
        }

        Request::GitStatus { project_root } => {
            crate::daemon::fs_api::git_status(project_root).await
        }

        Request::GitDiffFile { project_root, path } => {
            crate::daemon::fs_api::git_diff_file(project_root, path).await
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
            let trust_policy = attached_trust_policy(ctx, att).await?;
            let (_, config) = ctx
                .config_source()
                .load_with_trust(cwd, &trust_policy)
                .map_err(internal)?;
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
                    crate::db::Db::read_session_messages_conn(conn, session_id, before_seq, limit)
                })
                .await
                .map_err(internal)?;
            Ok(Response::SessionMessages {
                session_id,
                messages,
                has_more,
            })
        }

        Request::ReadClientSubmissionReceipt {
            session_id,
            client_submission_id,
        } => {
            let durable = ctx
                .db
                .client_submission_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?;
            let status = if let Some(receipt) = durable {
                proto::ClientSubmissionReceiptStatus::Accepted {
                    seq: receipt.seq,
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else if let Some(receipt) = ctx
                .db
                .client_submission_terminal_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?
            {
                proto::ClientSubmissionReceiptStatus::Terminal {
                    disposition: receipt.disposition.as_str().to_string(),
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else {
                proto::ClientSubmissionReceiptStatus::Pending
            };
            Ok(Response::ClientSubmissionReceipt {
                session_id,
                client_submission_id,
                status,
            })
        }

        Request::ReadHistoryPage {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let config_source = ctx.config_source.clone();
            let page = db
                .read(move |conn| {
                    read_history_page_conn(conn, session_id, before_seq, limit, &config_source)
                })
                .await
                .map_err(internal)?;
            Ok(Response::HistoryPage {
                session_id,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }

        Request::ReadSubagentHistoryPage {
            session_id,
            task_call_id,
            label,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let query_task_call_id = task_call_id.clone();
            let query_label = label.clone();
            let page = db
                .read(move |conn| {
                    read_subagent_history_page_conn(
                        conn,
                        session_id,
                        &query_task_call_id,
                        &query_label,
                        before_seq,
                        limit,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SubagentHistoryPage {
                session_id,
                task_call_id,
                label,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }

        Request::SessionLiveStatus { session_ids } => {
            let mut visible_ids = Vec::new();
            for id in session_ids {
                if state.principal.is_owner() {
                    visible_ids.push(id);
                    continue;
                }
                match ctx.db.get_session(id).await {
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
                    ctx.registry.live_status(id).map(
                        |(has_active_schedules, processing, _tool_running)| proto::LiveStatus {
                            session_id: id,
                            has_active_schedules,
                            processing,
                        },
                    )
                })
                .collect();
            Ok(Response::SessionLiveStatus { statuses })
        }

        Request::ArchiveSession {
            session_id,
            cascade,
        } => archive_session(ctx, session_id, cascade).await,

        Request::UnarchiveSession { session_id } => unarchive_session(ctx, session_id).await,

        Request::ForkSession {
            parent_session_id,
            fork_point_turn_id,
            ephemeral,
        } => {
            fork_session(
                ctx,
                &state.principal,
                parent_session_id,
                fork_point_turn_id,
                ephemeral,
            )
            .await
        }

        Request::DiscardSession { session_id } => discard_session(state, ctx, session_id).await,

        Request::CreateBtwFork {
            parent_session_id,
            tangent,
        } => create_btw_fork(ctx, &state.principal, parent_session_id, tangent).await,

        Request::EndBtwFork { parent_session_id } => end_btw_fork(ctx, parent_session_id).await,

        Request::RenameSession { session_id, title } => {
            rename_session(ctx, session_id, &title).await
        }

        Request::ShareSession { session_id, shared } => {
            ctx.db
                .set_session_shared_with_collaborators(session_id, shared)
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::RecordSessionNote { session_id, text } => {
            record_session_note(ctx, session_id, &text).await
        }

        Request::DeleteSession { session_id } => delete_session(ctx, session_id).await,

        Request::GetInventoryBundle {
            project_root,
            session_id,
            selected_agent,
        } => get_inventory_bundle(ctx, state, project_root, session_id, selected_agent).await,
        Request::ResourceSnapshot => Ok(Response::ResourceSnapshot {
            snapshot: resource_scheduler_snapshot(ctx),
        }),
        Request::PromoteResource {
            request_id,
            session_id,
        } => promote_resource_request(ctx, &request_id, session_id).await,

        Request::CreateScheduledJob { job } => {
            let scheduler = require_scheduler(ctx)?;
            let job = scheduler.create_job(job).await.map_err(internal)?;
            Ok(Response::ScheduledJob { job })
        }
        Request::ListScheduledJobs { owner } => {
            let scheduler = require_scheduler(ctx)?;
            let jobs = scheduler
                .list_jobs(owner.as_deref())
                .await
                .map_err(internal)?;
            Ok(Response::ScheduledJobs { jobs })
        }
        Request::DeleteScheduledJob { id } => {
            let scheduler = require_scheduler(ctx)?;
            let deleted = scheduler.delete_job(&id).await.map_err(internal)?;
            Ok(Response::ScheduledJobDeleted { id, deleted })
        }
        Request::SetScheduledJobEnabled { id, enabled } => {
            let scheduler = require_scheduler(ctx)?;
            let job = scheduler
                .set_enabled(&id, enabled)
                .await
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: format!("scheduled job `{id}` not found"),
                })?;
            Ok(Response::ScheduledJob { job })
        }
        Request::RunScheduledJob { id } => {
            let scheduler = require_scheduler(ctx)?;
            scheduler.run_now(&id).await.map_err(internal)?;
            Ok(Response::ScheduledJobRunQueued { id })
        }

        Request::SetModelFavorite {
            provider,
            model,
            favorite,
        } => {
            let att = require_attached(state)?;
            let snapshot = att.handle.config_snapshot();
            let provider_entry = snapshot
                .providers
                .providers
                .get(&provider)
                .ok_or_else(|| bad_request(format!("provider {provider} not in config")))?;
            if !provider_entry.models.iter().any(|entry| entry.id == model) {
                return Err(bad_request(format!(
                    "model {model} not in provider {provider}"
                )));
            }
            let trust_policy = attached_trust_policy(ctx, att).await?;
            let path = crate::config::trust::with_workspace_trust_policy(trust_policy, || {
                ctx.config_source()
                    .config_write_target_for_provider(&att.handle.project_root, &provider)
            })
            .ok_or_else(|| bad_request("no cockpit config found"))?;
            // Trust selects the concrete provider layer above. The blocking
            // mutation uses only that path (it does not rediscover layers),
            // so no task-local trust state is needed inside this thread.
            tokio::task::spawn_blocking(move || {
                let mut doc = crate::config::providers::ConfigDoc::load(&path)?;
                doc.write_model_favorite(&provider, &model, favorite)
            })
            .await
            .map_err(internal)?
            .map_err(internal)?;
            crate::daemon::config_refresh::refresh_session_config(
                &ctx.db,
                ctx.config_source(),
                &att.handle,
                None,
            )
            .await
            .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetDefaultModel {
            default_update_id,
            provider,
            model,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
            clear,
        } => {
            let att = require_attached(state)?;
            let trust_policy = attached_trust_policy(ctx, att).await?;
            let cwd = att.handle.project_root.clone();
            let session_id = att.handle.session_id;
            // Project root and trust come solely from the authenticated
            // attachment; a caller can never name a filesystem target.
            let requested = if clear {
                None
            } else {
                Some(crate::config::providers::ActiveModelRef {
                    provider: provider.unwrap_or_default(),
                    model: model.unwrap_or_default(),
                    reasoning_effort: reasoning_effort
                        .map(|value| crate::config::providers::ActiveReasoningEffort { value }),
                    thinking_mode,
                    prompt_cache_retention,
                })
            };
            let result = tokio::task::spawn_blocking(move || {
                let write = || {
                    crate::config::providers::mutate_effective_default(
                        &cwd,
                        requested.as_ref(),
                        crate::config::providers::ActiveModelWriteMode::Replace,
                        None,
                        None,
                        Some(
                            crate::config::providers::TransactionCorrelation::DefaultUpdate {
                                default_update_id,
                                session_id,
                            },
                        ),
                    )
                };
                crate::config::trust::with_workspace_trust_policy(trust_policy, write)
            })
            .await
            .map_err(internal)?;
            let outcome = match result {
                Ok(result) => {
                    // The write is verified; the snapshot refresh is a
                    // best-effort follow-up. A refresh failure must never
                    // replace the correlated terminal result with a bare
                    // transport error — the client would wait forever.
                    if let Err(error) = crate::daemon::config_refresh::refresh_session_config(
                        &ctx.db,
                        ctx.config_source(),
                        &att.handle,
                        None,
                    )
                    .await
                    {
                        tracing::warn!(
                            %error,
                            "default model verified but the config snapshot refresh failed"
                        );
                    }
                    proto::DefaultModelStandaloneOutcome::Applied {
                        selection: result.selection,
                        generation: result.generation,
                        scope_label: result.scope_label,
                        unchanged: result.unchanged,
                    }
                }
                // A transaction still pending recovery is not terminal: the
                // recovery pass that converges the journal emits the one
                // correlated result. Ack the request and emit nothing here.
                Err(error) if error.recovery_pending => {
                    tracing::warn!(
                        diagnostic_code = error.diagnostic_code,
                        "default model update is pending recovery; no terminal result emitted"
                    );
                    return Ok(Response::Ack);
                }
                Err(error) => proto::DefaultModelStandaloneOutcome::Rejected {
                    user_message: error.user_message,
                    diagnostic_code: error.diagnostic_code.to_string(),
                },
            };
            att.handle
                .broadcast_default_model_update_result(default_update_id, outcome);
            Ok(Response::Ack)
        }

        Request::SetActiveModel {
            selection_id,
            provider,
            model,
            persist_as_default,
            trigger,
            reasoning_effort,
            thinking_mode,
            prompt_cache_retention,
        } => {
            let att = require_attached(state)?;
            att.handle
                .send_work(SessionWork::SetActiveModel {
                    selection_id,
                    selection_deadline: std::time::Instant::now()
                        + std::time::Duration::from_secs(60),
                    provider,
                    model,
                    persist_as_default,
                    trigger: active_model_trigger_from_proto(trigger),
                    reasoning_effort,
                    thinking_mode,
                    prompt_cache_retention,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetAgent { name } => {
            let att = require_attached(state)?;
            validate_set_agent(ctx, att, &name)?;
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

        Request::SetToolSurfaceOverride {
            override_json,
            persist_session,
            prune_after_switch,
            monty_nudge,
        } => {
            let att = require_attached(state)?;
            serde_json::from_str::<crate::agents::ToolSurfaceSelection>(&override_json)
                .map_err(|error| bad_request(format!("invalid tool surface override: {error}")))?;
            att.handle
                .send_work(SessionWork::SetToolSurfaceOverride {
                    override_json,
                    persist_session,
                    prune_after_switch,
                    monty_nudge,
                })
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::SetGoalSettingsOverride {
            override_json,
            persist_session,
        } => {
            let att = require_attached(state)?;
            if let Some(raw) = override_json.as_deref() {
                crate::agents::parse_goal_settings_override_json(raw).map_err(|error| {
                    bad_request(format!("invalid goal settings override: {error}"))
                })?;
            }
            att.handle
                .send_work(SessionWork::SetGoalSettingsOverride {
                    override_json,
                    persist_session,
                })
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
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::SetPreflight {
                    enabled,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            Ok(Response::PreflightState {
                enabled: response_rx
                    .await
                    .map_err(internal)?
                    .map_err(|error| internal(anyhow::anyhow!(error)))?,
            })
        }

        Request::SetLongcache { enabled } => {
            let att = require_attached(state)?;
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::SetLongcache {
                    enabled,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            Ok(Response::LongcacheState {
                enabled: response_rx
                    .await
                    .map_err(internal)?
                    .map_err(|error| internal(anyhow::anyhow!(error)))?,
            })
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
            let (respond_to, response_rx) = tokio::sync::oneshot::channel();
            att.handle
                .send_work(SessionWork::SetRedaction {
                    scan_environment,
                    scan_dotenv,
                    scan_ssh_keys,
                    respond_to,
                })
                .await
                .map_err(internal)?;
            let (scan_environment, scan_dotenv, scan_ssh_keys) = response_rx
                .await
                .map_err(internal)?
                .map_err(|error| internal(anyhow::anyhow!(error)))?;
            Ok(Response::RedactionState {
                scan_environment,
                scan_dotenv,
                scan_ssh_keys,
            })
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
            ctx.store_flycockpit_credential(&credential)
                .map_err(internal)?;
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
            paused_sessions: ctx
                .db
                .paused_session_work_all()
                .await
                .map_err(internal)?
                .len() as u32,
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().await.map_err(internal)?,
        }),

        Request::RefreshEnv { vars } => {
            let att = require_attached(state)?;
            att.handle.set_env_overlay(vars);
            Ok(Response::Ack)
        }

        Request::RefreshConfig => {
            let att = require_attached(state)?;
            let refreshed = crate::daemon::config_refresh::refresh_session_config_explicit(
                &ctx.db,
                ctx.config_source(),
                &att.handle,
            )
            .await
            .map_err(explicit_config_refresh_error)?;
            Ok(Response::ConfigRefreshed {
                applied_generation: refreshed.applied_generation,
                changed: refreshed.changed,
            })
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
                .await
                .map_err(internal)?;
            Ok(Response::Ack)
        }

        Request::GetUsageCounts { project_id } => {
            let since = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
            let models = ctx
                .db
                .usage_counts("model", None, since)
                .await
                .map_err(internal)?;
            let slash = ctx
                .db
                .usage_counts("slash", None, since)
                .await
                .map_err(internal)?;
            // Tags are per-project; with no project there's nothing to
            // scope to, so the map is empty rather than a global mash-up.
            let tags = match project_id.as_deref() {
                Some(pid) => ctx
                    .db
                    .usage_counts("tag", Some(pid), since)
                    .await
                    .map_err(internal)?,
                None => std::collections::HashMap::new(),
            };
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            })
        }

        Request::StatsRollup {
            project_id,
            range,
            by_role,
        } => stats_rollup(ctx, project_id, range, by_role).await,

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
            let (strategy, scale) = ctx
                .db
                .resolve_tokenizer(
                    provider.as_deref().unwrap_or(""),
                    model.as_deref().unwrap_or(""),
                )
                .await;
            let strategy = crate::tokens::calibration_strategy_from_persisted(strategy.as_str());
            let system_prompt = crate::engine::builtin::default_chat_system_prompt(cwd, "");
            let system_tokens = crate::tokens::scaled_estimate(&system_prompt, strategy, scale);
            let model_instruction_tokens = provider
                .as_deref()
                .zip(model.as_deref())
                .and_then(|(provider, model)| {
                    let (cfg, _) = ctx.config_source().load(cwd).ok()?;
                    cfg.resolve_model_system_prompt(provider, model)
                        .map(|prompt| crate::tokens::scaled_estimate(prompt, strategy, scale))
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
            effects.shutdown_after_response = true;
            Ok(Response::Ack)
        }
        Request::RestartIfIdle => {
            tracing::info!("RestartIfIdle requested via client");
            let _decision = crate::sync::lock_or_recover(&ctx.restart_decision);
            if ctx.shutdown.is_draining() {
                return Ok(Response::RestartDecision {
                    will_restart: false,
                    reason: Some("already shutting down".to_string()),
                });
            }
            if ctx.registry.any_agent_running() {
                return Ok(Response::RestartDecision {
                    will_restart: false,
                    reason: Some("a session is busy".to_string()),
                });
            }
            request_shutdown(ctx);
            Ok(Response::RestartDecision {
                will_restart: true,
                reason: None,
            })
        }
        Request::Unknown => Err(proto::unsupported_request_error(
            proto::PROTOCOL_VERSION,
            None,
        )),
    }
}

pub(super) async fn handle_concurrent_request(
    request: Request,
    shared: Arc<SharedClientState>,
    ctx: Arc<DaemonContext>,
) -> std::result::Result<Response, ErrorPayload> {
    validate_request_semantics(&request)?;
    let request_kind = principal::request_kind(&request);
    let audit_path = request_audit_path(&request);
    let audit_remote = !shared.principal.is_owner() && is_remote_mutating_request(&request);
    if let Err(error) = authorize_request_shared(&request, &shared, &ctx).await {
        if audit_remote {
            audit_remote_request(
                &ctx,
                &shared.principal,
                request_kind,
                None,
                audit_path.as_deref(),
                "denied",
            )
            .await;
        }
        return Err(error);
    }
    if audit_remote {
        audit_remote_request(
            &ctx,
            &shared.principal,
            request_kind,
            None,
            audit_path.as_deref(),
            "allowed",
        )
        .await;
    }
    #[cfg(test)]
    apply_concurrent_request_test_hook(&request).await;
    match request {
        Request::SubagentTranscript {
            session_id,
            task_call_id,
            label,
        } => {
            let db = ctx.db.clone();
            let task_call_id_for_read = task_call_id.clone();
            let label_for_read = label.clone();
            let mut history = db
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
            if !shared.principal.is_owner() {
                let redact = if let Some(handle) = ctx.registry.live_handle(session_id) {
                    handle.redaction_table()
                } else {
                    let session = crate::session::Session::resume(ctx.db.clone(), session_id)
                        .map_err(internal)?
                        .ok_or_else(|| ErrorPayload {
                            code: ErrorCode::UnknownSession,
                            message: format!("unknown session {session_id}"),
                        })?;
                    std::sync::Arc::new(
                        session
                            .persisted_redaction_table()
                            .map_err(internal)?
                            .ok_or_else(|| ErrorPayload {
                                code: ErrorCode::Authorization,
                                message: "session transcript redaction data is unavailable"
                                    .to_string(),
                            })?,
                    )
                };
                history = scrub_history_for_principal(&shared.principal, history, &redact);
            }
            Ok(Response::SubagentTranscript {
                session_id,
                task_call_id,
                label,
                history,
            })
        }
        Request::ListAssistants => {
            let assistants = ctx
                .db
                .list_assistants()
                .await
                .map_err(internal)?
                .into_iter()
                .map(assistant_to_proto)
                .collect();
            Ok(Response::Assistants { assistants })
        }
        Request::CountPinnedMessages { session_id } => ctx
            .db
            .count_pins(session_id)
            .await
            .map(|count| Response::PinCount { count })
            .map_err(internal),
        Request::ListPinnedMessageSeqs { session_id } => ctx
            .db
            .list_pin_seqs(session_id)
            .await
            .map(|seqs| Response::PinSeqs { seqs })
            .map_err(internal),
        Request::ListPinnedMessagesWithText { session_id } => ctx
            .db
            .list_pins_with_text(session_id)
            .await
            .map(|pins| Response::PinsWithText {
                pins: pins.into_iter().map(pinned_message_to_proto).collect(),
            })
            .map_err(internal),
        Request::PinnedMessageState { session_id } => {
            let count = ctx.db.count_pins(session_id).await.map_err(internal)?;
            let seqs = ctx.db.list_pin_seqs(session_id).await.map_err(internal)?;
            Ok(Response::PinState {
                state: proto::PinState { count, seqs },
            })
        }
        Request::ListSealedValues { session_id } => ctx
            .db
            .list_sealed_value_metadata(session_id)
            .await
            .map(|values| Response::SealedValues {
                values: values
                    .into_iter()
                    .map(sealed_value_metadata_to_proto)
                    .collect(),
            })
            .map_err(internal),
        Request::ExportSessionData {
            session_id,
            kind,
            include_generated_artifacts,
            include_sensitive,
        } => {
            export_session_data(
                &ctx,
                session_id,
                kind,
                include_generated_artifacts,
                include_sensitive,
            )
            .await
        }

        Request::ImportSessionArchive { transfer, as_new } => {
            import_session_archive(&ctx, &transfer, as_new).await
        }
        Request::WriteBulkTransferChunk {
            transfer,
            chunk_index,
            data_base64,
        } => write_bulk_transfer_chunk(&transfer, chunk_index, &data_base64).await,
        Request::ReadBulkTransferChunk {
            transfer_id,
            chunk_index,
        } => read_bulk_transfer_chunk(&transfer_id, chunk_index).await,
        Request::FsList {
            project_root,
            path,
            show_hidden,
        } => {
            crate::daemon::fs_api::fs_list(
                ctx.clone(),
                shared.principal.clone(),
                project_root,
                path,
                show_hidden,
            )
            .await
        }
        Request::FsStat { project_root, path } => {
            crate::daemon::fs_api::fs_stat(
                ctx.clone(),
                shared.principal.clone(),
                project_root,
                path,
            )
            .await
        }
        Request::FsRead {
            project_root,
            path,
            base64,
        } => {
            crate::daemon::fs_api::fs_read(
                ctx.clone(),
                shared.principal.clone(),
                project_root,
                path,
                base64,
            )
            .await
        }
        Request::GitStatus { project_root } => {
            crate::daemon::fs_api::git_status(project_root).await
        }
        Request::GitDiffFile { project_root, path } => {
            crate::daemon::fs_api::git_diff_file(project_root, path).await
        }
        Request::ListSessions {
            project_id,
            parent_session_id,
        } => list_sessions(&ctx, &shared.principal, project_id, parent_session_id).await,
        Request::ReadSessionMessages {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let (messages, has_more) = db
                .read(move |conn| {
                    crate::db::Db::read_session_messages_conn(conn, session_id, before_seq, limit)
                })
                .await
                .map_err(internal)?;
            Ok(Response::SessionMessages {
                session_id,
                messages,
                has_more,
            })
        }
        Request::ReadClientSubmissionReceipt {
            session_id,
            client_submission_id,
        } => {
            let durable = ctx
                .db
                .client_submission_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?;
            let status = if let Some(receipt) = durable {
                proto::ClientSubmissionReceiptStatus::Accepted {
                    seq: receipt.seq,
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else if let Some(receipt) = ctx
                .db
                .client_submission_terminal_receipt(session_id, client_submission_id)
                .await
                .map_err(internal)?
            {
                proto::ClientSubmissionReceiptStatus::Terminal {
                    disposition: receipt.disposition.as_str().to_string(),
                    wire_fingerprint: receipt.wire_fingerprint,
                }
            } else {
                proto::ClientSubmissionReceiptStatus::Pending
            };
            Ok(Response::ClientSubmissionReceipt {
                session_id,
                client_submission_id,
                status,
            })
        }
        Request::ReadHistoryPage {
            session_id,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let config_source = ctx.config_source.clone();
            let page = db
                .read(move |conn| {
                    read_history_page_conn(conn, session_id, before_seq, limit, &config_source)
                })
                .await
                .map_err(internal)?;
            Ok(Response::HistoryPage {
                session_id,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }
        Request::ReadSubagentHistoryPage {
            session_id,
            task_call_id,
            label,
            before_seq,
            limit,
        } => {
            let db = ctx.db.clone();
            let query_task_call_id = task_call_id.clone();
            let query_label = label.clone();
            let page = db
                .read(move |conn| {
                    read_subagent_history_page_conn(
                        conn,
                        session_id,
                        &query_task_call_id,
                        &query_label,
                        before_seq,
                        limit,
                    )
                })
                .await
                .map_err(internal)?;
            Ok(Response::SubagentHistoryPage {
                session_id,
                task_call_id,
                label,
                entries: page.entries,
                has_more: page.has_more,
                oldest_seq: page.oldest_seq,
            })
        }
        Request::SessionLiveStatus { session_ids } => {
            let mut visible_ids = Vec::new();
            for id in session_ids {
                if shared.principal.is_owner() {
                    visible_ids.push(id);
                    continue;
                }
                match ctx.db.get_session(id).await {
                    Ok(Some(row))
                        if session_access_for_row(&shared.principal, &row)
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
                    ctx.registry.live_status(id).map(
                        |(has_active_schedules, processing, _tool_running)| proto::LiveStatus {
                            session_id: id,
                            has_active_schedules,
                            processing,
                        },
                    )
                })
                .collect();
            Ok(Response::SessionLiveStatus { statuses })
        }
        Request::GetInventoryBundle {
            project_root,
            session_id,
            selected_agent,
        } => {
            get_inventory_bundle_shared(&ctx, &shared, project_root, session_id, selected_agent)
                .await
        }
        Request::ResourceSnapshot => Ok(Response::ResourceSnapshot {
            snapshot: resource_scheduler_snapshot(&ctx),
        }),
        Request::ListScheduledJobs { owner } => {
            let scheduler = require_scheduler(&ctx)?;
            let jobs = scheduler
                .list_jobs(owner.as_deref())
                .await
                .map_err(internal)?;
            Ok(Response::ScheduledJobs { jobs })
        }
        Request::DaemonStatus => Ok(Response::DaemonStatus {
            pid: std::process::id(),
            uptime_secs: ctx.started_at.elapsed().as_secs(),
            active_sessions: ctx.registry.active_session_ids().len() as u32,
            socket_path: ctx.paths.socket.display().to_string(),
            daemon_version: proto::DAEMON_VERSION.to_string(),
            protocol_version: proto::PROTOCOL_VERSION,
            paused_sessions: ctx
                .db
                .paused_session_work_all()
                .await
                .map_err(internal)?
                .len() as u32,
            database_path: ctx
                .db
                .path()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "<in-memory>".to_string()),
            schema_version: ctx.db.schema_version().await.map_err(internal)?,
        }),
        Request::GetUsageCounts { project_id } => {
            let since = chrono::Utc::now().timestamp() - crate::db::usage_events::USAGE_WINDOW_SECS;
            let models = ctx
                .db
                .usage_counts("model", None, since)
                .await
                .map_err(internal)?;
            let slash = ctx
                .db
                .usage_counts("slash", None, since)
                .await
                .map_err(internal)?;
            let tags = match project_id.as_deref() {
                Some(pid) => ctx
                    .db
                    .usage_counts("tag", Some(pid), since)
                    .await
                    .map_err(internal)?,
                None => std::collections::HashMap::new(),
            };
            Ok(Response::UsageCounts {
                models,
                slash,
                tags,
            })
        }
        Request::GetRunInvocationStatus {
            client_submission_id,
        } => {
            run_invocation::handle_get_run_invocation_status_shared(
                &shared,
                &ctx,
                client_submission_id,
            )
            .await
        }
        Request::StatsRollup {
            project_id,
            range,
            by_role,
        } => stats_rollup(&ctx, project_id, range, by_role).await,
        Request::GuidanceEstimate {
            project_root,
            provider,
            model,
        } => guidance_estimate(&ctx, project_root, provider, model).await,
        _ => Err(ErrorPayload {
            code: ErrorCode::Internal,
            message: format!("request `{request_kind}` is not marked concurrent"),
        }),
    }
}

fn validate_request_semantics(request: &Request) -> std::result::Result<(), ErrorPayload> {
    request
        .validate_semantics()
        .map_err(|message| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid {} request: {message}", request.wire_tag()),
        })
}

pub(super) async fn attached_trust_policy(
    ctx: &DaemonContext,
    att: &AttachedSession,
) -> std::result::Result<crate::config::trust::WorkspaceTrustPolicy, ErrorPayload> {
    crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &att.handle.project_root)
        .await
        .map_err(internal)
}

pub(super) async fn get_inventory_bundle(
    ctx: &DaemonContext,
    state: &MutableClientState,
    project_root: String,
    session_id: Uuid,
    selected_agent: String,
) -> std::result::Result<Response, ErrorPayload> {
    let att = require_attached(state)?;
    if att.handle.session_id != session_id {
        return Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("session `{session_id}` is not the attached session"),
        });
    }
    // Inventory is always projected for the attached session project; the
    // client-supplied project_root must match (canonical) or be rejected.
    let attached_root = att.handle.project_root.clone();
    if Path::new(&project_root) != attached_root.as_path()
        && canonicalize_opt(Path::new(&project_root)) != canonicalize_opt(&attached_root)
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!(
                "project_root `{project_root}` does not match attached session project `{}`",
                attached_root.display()
            ),
        });
    }

    let trust_policy = attached_trust_policy(ctx, att).await?;
    let cwd = attached_root.as_path();
    // One immutable snapshot: the session worker's last-good config is
    // authoritative. Disk is consulted only when the held snapshot has never
    // been populated (generation 0 and empty providers).
    let held = att.handle.config_snapshot();
    let (providers, skills_config, config_generation) =
        if held.generation > 0 || !held.providers.providers.is_empty() {
            (
                held.providers.clone(),
                held.extended.skills.clone(),
                held.generation,
            )
        } else {
            match ctx
                .config_source()
                .load_effective_for_daemon(cwd, &trust_policy)
            {
                Ok((providers, extended)) => (providers, extended.skills, 0),
                Err(err) => {
                    return Err(daemon_config_error(err));
                }
            }
        };

    // Session generation is the attached worker config epoch (attach identity).
    let session_generation = held.generation.max(config_generation);
    let inventory_generation = super::inventory::current_inventory_generation();
    let ownable_agents =
        crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
            crate::agents::chat_ownable_primaries(cwd)
        });

    let snapshot = super::inventory::InventorySourceSnapshot {
        project_root: cwd.to_path_buf(),
        session_id,
        selected_agent,
        session_generation,
        config_generation,
        inventory_generation,
        trust_policy,
        providers,
        skills_config,
        ownable_agents,
    };
    super::inventory::project_inventory_bundle(&snapshot)
}

fn canonicalize_opt(path: &Path) -> Option<std::path::PathBuf> {
    path.canonicalize().ok()
}

pub(super) fn require_shared_attached(
    shared: &SharedClientState,
) -> std::result::Result<&SharedAttachedSession, ErrorPayload> {
    shared.attached.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::NotAttached,
        message: "client has not attached to a session".into(),
    })
}

pub(super) fn daemon_config_error(error: anyhow::Error) -> ErrorPayload {
    if let Some(invalid) =
        error.downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
    {
        tracing::warn!(diagnostic = %invalid.diagnostic(), "daemon config rejected invalid response tokenizer");
        ErrorPayload {
            code: ErrorCode::InvalidResponseMetricsTokenizer,
            message: "configuration value is invalid".into(),
        }
    } else {
        ErrorPayload {
            code: ErrorCode::InvalidConfig,
            message: format!("invalid config: {error:#}"),
        }
    }
}

pub(super) fn explicit_config_refresh_error(
    error: crate::daemon::config_refresh::ExplicitConfigRefreshError,
) -> ErrorPayload {
    ErrorPayload {
        code: match &error {
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidResponseMetricsTokenizer => ErrorCode::InvalidResponseMetricsTokenizer,
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidConfig(_) => ErrorCode::InvalidConfig,
            crate::daemon::config_refresh::ExplicitConfigRefreshError::Internal => ErrorCode::Internal,
        },
        message: match &error {
            crate::daemon::config_refresh::ExplicitConfigRefreshError::Internal => "config refresh failed",
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidResponseMetricsTokenizer => "configuration value is invalid",
            crate::daemon::config_refresh::ExplicitConfigRefreshError::InvalidConfig(detail) => return ErrorPayload {
                code: ErrorCode::InvalidConfig,
                message: format!("invalid config: {detail}"),
            },
        }.into(),
    }
}

pub(super) async fn attached_trust_policy_shared(
    ctx: &DaemonContext,
    att: &SharedAttachedSession,
) -> std::result::Result<crate::config::trust::WorkspaceTrustPolicy, ErrorPayload> {
    crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &att.project_root)
        .await
        .map_err(internal)
}

pub(super) async fn get_inventory_bundle_shared(
    ctx: &DaemonContext,
    shared: &SharedClientState,
    project_root: String,
    session_id: Uuid,
    selected_agent: String,
) -> std::result::Result<Response, ErrorPayload> {
    let att = require_shared_attached(shared)?;
    if att.session_id != session_id {
        return Err(ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("session `{session_id}` is not the attached session"),
        });
    }
    if Path::new(&project_root) != att.project_root.as_path()
        && canonicalize_opt(Path::new(&project_root)) != canonicalize_opt(&att.project_root)
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!(
                "project_root `{project_root}` does not match attached session project `{}`",
                att.project_root.display()
            ),
        });
    }

    let trust_policy = attached_trust_policy_shared(ctx, att).await?;
    let cwd = att.project_root.as_path();
    let (providers, extended) = ctx
        .config_source()
        .load_effective_for_daemon(cwd, &trust_policy)
        .map_err(daemon_config_error)?;

    // Shared concurrent path has no live config handle; use inventory gen only.
    let config_generation = super::inventory::current_inventory_generation();
    let session_generation = config_generation;
    let inventory_generation = config_generation;
    let ownable_agents =
        crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
            crate::agents::chat_ownable_primaries(cwd)
        });

    let snapshot = super::inventory::InventorySourceSnapshot {
        project_root: cwd.to_path_buf(),
        session_id,
        selected_agent,
        session_generation,
        config_generation,
        inventory_generation,
        trust_policy,
        providers,
        skills_config: extended.skills,
        ownable_agents,
    };
    super::inventory::project_inventory_bundle(&snapshot)
}

pub(super) async fn guidance_estimate(
    ctx: &DaemonContext,
    project_root: String,
    provider: Option<String>,
    model: Option<String>,
) -> std::result::Result<Response, ErrorPayload> {
    let cwd = Path::new(&project_root);
    let (strategy, scale) = ctx
        .db
        .resolve_tokenizer(
            provider.as_deref().unwrap_or(""),
            model.as_deref().unwrap_or(""),
        )
        .await;
    let strategy = crate::tokens::calibration_strategy_from_persisted(strategy.as_str());
    let system_prompt = crate::engine::builtin::default_chat_system_prompt(cwd, "");
    let system_tokens = crate::tokens::scaled_estimate(&system_prompt, strategy, scale);
    let model_instruction_tokens = provider
        .as_deref()
        .zip(model.as_deref())
        .and_then(|(provider, model)| {
            let (cfg, _) = ctx.config_source().load(cwd).ok()?;
            cfg.resolve_model_system_prompt(provider, model)
                .map(|prompt| crate::tokens::scaled_estimate(prompt, strategy, scale))
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

#[allow(dead_code)] // retained for non-inventory agent summary projections
pub(super) fn agent_mode_summary(mode: crate::agents::AgentMode) -> &'static str {
    match mode {
        crate::agents::AgentMode::All => "all",
        crate::agents::AgentMode::Primary => "primary",
        crate::agents::AgentMode::Subagent => "subagent",
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
pub(super) fn set_caffeinate(
    state: &MutableClientState,
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
        Some(policy) => ctx.config_source().load_with_trust(&cfg_root, &policy),
        None => ctx.config_source().load(&cfg_root),
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

fn read_history_page_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    before_seq: Option<i64>,
    limit: u32,
    config_source: &crate::daemon::config_source::ConfigSource,
) -> anyhow::Result<crate::engine::rehydrate::HistoryPage> {
    let extended_cfg = crate::db::Db::get_session_conn(conn, session_id)?
        .and_then(|row| {
            config_source
                .load(std::path::Path::new(&row.project_root))
                .ok()
                .map(|(_, extended)| extended)
        })
        .unwrap_or_default();
    let root_agent = crate::daemon::session_worker::resolve_root_agent_conn(
        conn,
        session_id,
        &extended_cfg,
        extended_cfg.llm_mode,
    );
    crate::engine::rehydrate::history_page_before_conn(
        conn,
        session_id,
        &root_agent,
        before_seq,
        limit,
    )
}

fn read_subagent_history_page_conn(
    conn: &rusqlite::Connection,
    session_id: Uuid,
    task_call_id: &str,
    label: &str,
    before_seq: Option<i64>,
    limit: u32,
) -> anyhow::Result<crate::engine::rehydrate::HistoryPage> {
    crate::engine::rehydrate::subagent_history_page_before_conn(
        conn,
        session_id,
        task_call_id,
        label,
        before_seq,
        limit,
    )
}

/// Poll interval for the until-idle auto-off watcher. Short enough that
/// the machine doesn't stay awake long after the last agent finishes,
/// long enough to be negligible overhead.
pub(super) const UNTIL_IDLE_POLL: std::time::Duration = std::time::Duration::from_secs(5);

/// Spawn the daemon's `until-idle` auto-off watcher. The daemon owns the
/// session workers / `ScheduleAuthority`, so it is the authority for "is an
/// agent running anywhere?". The watcher polls that and, once no agent is
/// running, releases the assertion and broadcasts the off-state to all
/// clients. It exits if the mode is no longer until-idle (a later
/// `on`/`off`/`toggle` superseded it) so a fresh `until-idle` can re-arm
/// without stacking watchers racing each other.
pub(super) fn spawn_until_idle_watcher(ctx: Arc<DaemonContext>) {
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
pub(super) const LOCK_SWEEP_POLL: std::time::Duration = std::time::Duration::from_secs(10);

/// Spawn the daemon's idle-lock sweeper
/// (implementation note). On each tick it asks the
/// single lock authority to reclaim any lock whose holder has been idle
/// past [`crate::locks::LOCK_IDLE_TIMEOUT`] — releasing it, invalidating the
/// §3c read-record, persisting the release, and waking blocked `read`
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
            match locks.sweep_expired(now).await {
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
pub(super) async fn attach(
    state: &mut MutableClientState,
    ctx: &DaemonContext,
    session_id: Option<Uuid>,
    since_seq: Option<i64>,
    project_root: Option<String>,
    initial_model: Option<crate::config::providers::ActiveModelRef>,
    no_sandbox: bool,
    interactive: bool,
    model_override: Option<crate::config::providers::ActiveModelRef>,
    client_protocol_version: u32,
    env_snapshot: Option<EnvSnapshotWire>,
    env_policy: EnvDriftPolicy,
    principal: &ClientPrincipal,
    effects: &mut ClientRequestEffects,
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
        (Some(id), _) => match ctx.db.get_session(id).await {
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
    // Terminal results for transactions this attach converged. Delivered
    // through the worker below, once a handle exists to stamp the generation.
    let recovered_default_transactions;
    // Resolution barrier: finish any pending effective-default transaction —
    // including its guarded session half — before this attach can serve a
    // session or default snapshot. Failing closed here is deliberate: a
    // journal that cannot be converged means the durable default and the
    // session model may disagree, which is exactly what attach must not show.
    {
        let trust_policy =
            crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cfg_root)
                .await
                .ok();
        recovered_default_transactions =
            crate::daemon::effective_default_recovery::recover_effective_default_journals(
                &ctx.db,
                &cfg_root,
                trust_policy,
            )
            .await
            .map_err(|error| {
            tracing::error!(%error, "effective-default journal recovery failed during attach");
            ErrorPayload {
                code: ErrorCode::InvalidConfig,
                    message:
                        "a pending default-model update could not be recovered; run `cockpit doctor` \
                         to inspect the pending journal for this configuration layer"
                            .to_string(),
                }
            })?;
    }
    let remote_readonly_attach = !principal.is_owner()
        && !principal.can_agent_write_project(&cfg_root.to_string_lossy())
        && principal.can_agent_read_project(&cfg_root.to_string_lossy());
    let client_no_sandbox = client_no_sandbox && !remote_readonly_attach;
    // Cross-process freshness invariant: no trust or session lookup may be
    // cached across requests without an invalidation path. The registry makes
    // the atomic live-vs-start decision: a live worker keeps its snapshotted
    // policy, while every newly-created/resumed worker reads through SQLite
    // after winning its start claim. Thus a trust flip affects the next worker
    // creation and never retroactively mutates a running session.
    // An environment snapshot is process-authority input: it influences
    // provider credential expansion, subprocess PATH lookup, and redaction.
    // Remote principals may attach to sessions but never supply that ambient
    // authority. Authorization rejects the global UpdateDaemon mutation; this
    // dispatch boundary also ignores every non-owner snapshot/policy so a
    // future authz regression cannot inject values into a cold worker.
    let (client_snapshot, env_policy) = if principal.is_owner() {
        (env_snapshot.map(EnvSnapshot::from_wire), env_policy)
    } else {
        (None, EnvDriftPolicy::Daemon)
    };
    let (session_env, env_baseline_meta, env_session_meta, env_drift, env_policy_applied) =
        select_session_env(ctx, client_snapshot, env_policy)?;

    let handle = ctx
        .registry
        .attach(
            session_id,
            project_root,
            initial_model,
            client_no_sandbox,
            model_override.as_ref(),
            session_env,
        )
        .await
        .map_err(workspace_trust_error)?;
    // Attach-only projections use the policy snapshot of the handle that the
    // registry actually returned. This is safe for both branches: live
    // workers retain their original policy, while newly-started workers have
    // already performed the post-claim DB read-through.
    // The worker exists now, so any transaction this attach converged can be
    // delivered as a correlated terminal result stamped with the driver's own
    // generation.
    crate::daemon::effective_default_recovery::deliver_recovered_terminals(
        ctx,
        recovered_default_transactions,
    )
    .await;
    let config_snapshot = handle.config_snapshot();
    let extended_cfg = config_snapshot.extended.clone();

    if session_id.is_none()
        && let Some(tag) = principal.tag()
    {
        handle
            .set_created_by_principal(Some(tag))
            .map_err(internal)?;
    }
    // A per-run daemon can disappear as soon as its client exits. Make the
    // session row durable before returning its id so another daemon process
    // can always find it through the normal DB-backed resume path.
    if session_id.is_none() && ctx.paths.ephemeral {
        handle.persist_if_needed().map_err(internal)?;
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
    let mut event_rx = handle.subscribe();
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
    let active_model_state = handle.authoritative_active_model_state().map(|mut state| {
        state.generation = 0;
        state
    });

    state.pending_uploads.clear();
    state.ready_attachments.clear();
    state.upload_limits = extended_cfg.daemon.uploads.into();
    state.attached = Some(AttachedSession {
        handle,
        _interactive_guard: interactive_guard,
    });

    // Hydrate the queue and gitignore read-allowlist for this client. The
    // just-subscribed `event_rx` receives both full-list replacements, so a
    // late-opened or reconnecting TUI — and any second concurrent client —
    // learns state established before it attached, not only later mutations.
    // Queue replay intentionally includes an empty snapshot; gitignore replay
    // sends only the allow-set.
    if let Some(att) = state.attached.as_ref() {
        att.handle
            .broadcast_queue_snapshot()
            .await
            .map_err(internal)?;
        att.handle.broadcast_gitignore_allow();
        att.handle.broadcast_active_interrupt().await;
        att.handle.broadcast_sandbox_escalation();
        att.handle.broadcast_sandbox_unavailable_or_probe();
        att.handle.broadcast_config_snapshot();
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
                extended_cfg_for_attach.llm_mode,
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

    loop {
        match event_rx.try_recv() {
            Ok(envelope) => state.pending_replay.push(envelope.event),
            Err(broadcast::error::TryRecvError::Empty) => break,
            Err(broadcast::error::TryRecvError::Lagged(n)) => {
                tracing::warn!(missed = n, "attach hydration event replay lagged");
                break;
            }
            Err(broadcast::error::TryRecvError::Closed) => break,
        }
    }
    effects.session_event_rx = Some(event_rx);

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
    let btw_fork = ctx
        .db
        .live_btw_fork_info(session_id)
        .await
        .map_err(internal)?
        .map(btw_info_to_proto);

    Ok(Response::Attached {
        session_id,
        short_id,
        project_root,
        project_id,
        active_agent,
        active_agent_path: foreground.active_agent_path,
        foreground_target: Some(foreground.foreground_target),
        active_subagent: foreground.active_subagent,
        active_model_state,
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
        btw_fork,
    })
}

pub(super) fn select_session_env(
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

pub(super) fn active_model_trigger_from_proto(
    trigger: proto::ActiveModelSwitchTrigger,
) -> crate::session::ModelSwitchTrigger {
    match trigger {
        proto::ActiveModelSwitchTrigger::Picker => crate::session::ModelSwitchTrigger::Picker,
        proto::ActiveModelSwitchTrigger::Quick => crate::session::ModelSwitchTrigger::Quick,
        proto::ActiveModelSwitchTrigger::Cycle => crate::session::ModelSwitchTrigger::Cycle,
        proto::ActiveModelSwitchTrigger::Daemon => crate::session::ModelSwitchTrigger::Daemon,
    }
}

pub(super) fn goal_to_proto(goal: crate::db::session_goals::SessionGoal) -> proto::GoalSummary {
    proto::GoalSummary {
        id: goal.id,
        session_id: goal.session_id,
        project_id: goal.project_id,
        objective: goal.objective,
        context: goal.context,
        disposition: goal.disposition,
        phase: goal.phase,
        resume_phase: goal.resume_phase,
        pause_reason: goal.pause_reason,
        contract_available: goal.contract.is_some(),
        latest_gap_or_blocker: goal
            .unresolved_gaps
            .first()
            .cloned()
            .or(goal.blocker_key.clone()),
        verification_attempts: goal.verification_rounds,
        attempt_generation: goal.attempt_generation,
        token_budget: goal.token_budget,
        tokens_used: goal.tokens_used,
        remaining_tokens: goal.token_budget.saturating_sub(goal.tokens_used),
        blocked_attempts: goal.blocked_attempts,
        last_read_at: goal.last_read_at,
        created_at: goal.created_at,
        updated_at: goal.updated_at,
    }
}

pub(super) fn assistant_to_proto(
    row: crate::db::assistants::AssistantRow,
) -> proto::AssistantSummary {
    proto::AssistantSummary {
        name: row.name,
        created_at: row.created_at,
        home_dir: row.home_dir,
        config_json: row.config_json,
        content_hash: row.content_hash,
    }
}

fn pinned_message_to_proto(row: crate::db::pins::PinnedMessage) -> proto::PinnedMessage {
    proto::PinnedMessage {
        seq: row.seq,
        is_assistant: row.is_assistant,
        text: row.text,
    }
}

fn project_note_to_proto(row: crate::db::project_notes::ProjectNote) -> proto::ProjectNote {
    proto::ProjectNote {
        id: row.id,
        project_root: row.project_root,
        name: row.name,
        content: row.content,
    }
}

fn sealed_value_metadata_to_proto(
    row: crate::db::sealed_values::SealedValueMetadata,
) -> proto::SealedValueMetadata {
    proto::SealedValueMetadata {
        value_id: row.value_id,
        reason: row.reason,
        origin: row.origin,
        created_at: row.created_at,
        origin_session_id: row.origin_session_id,
    }
}

async fn ensure_project_note_member(
    db: &crate::db::Db,
    project_root: &str,
    id: uuid::Uuid,
) -> std::result::Result<(), ErrorPayload> {
    let found = db
        .list_project_notes(project_root)
        .await
        .map_err(internal)?
        .into_iter()
        .any(|note| note.id == id);
    if found {
        Ok(())
    } else {
        Err(bad_request(format!(
            "project note `{id}` does not belong to project root `{project_root}`"
        )))
    }
}

pub(super) fn stats_range_from_proto(range: proto::StatsRange) -> crate::db::stats::StatsRange {
    match range {
        proto::StatsRange::Last7Days => crate::db::stats::StatsRange::Last7Days,
        proto::StatsRange::AllTime => crate::db::stats::StatsRange::AllTime,
    }
}

pub(super) async fn stats_rollup(
    ctx: &Arc<DaemonContext>,
    project_id: Option<String>,
    range: proto::StatsRange,
    by_role: bool,
) -> std::result::Result<Response, ErrorPayload> {
    let scope = project_id
        .map(crate::db::stats::StatsScope::Project)
        .unwrap_or(crate::db::stats::StatsScope::All);
    let range = stats_range_from_proto(range);
    let prices = crate::db::stats::PriceTable::load_default();
    let now = chrono::Utc::now().timestamp();
    let rollup = ctx
        .db
        .read(move |conn| crate::db::stats::rollup(conn, &scope, range, &prices, by_role, now))
        .await
        .map_err(internal)?;
    Ok(Response::StatsRollup { rollup })
}

fn staging_error(error: crate::daemon::bulk_staging::BulkStagingError) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: format!("bulk transfer rejected: {error}"),
    }
}

/// Accept one pushed chunk of a bulk transfer into daemon-side staging.
pub(super) async fn write_bulk_transfer_chunk(
    transfer: &cockpit_proto::remote_transport::bulk::RemoteBulkTransferRef,
    chunk_index: u32,
    data_base64: &str,
) -> std::result::Result<Response, ErrorPayload> {
    if data_base64.len() > cockpit_proto::MAX_ATTACHMENT_CHUNK_BASE64_BYTES {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "bulk transfer chunk exceeds the advertised chunk bound".to_string(),
        });
    }
    let chunk = base64::engine::general_purpose::STANDARD
        .decode(data_base64)
        .map_err(|error| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid bulk transfer chunk encoding: {error}"),
        })?;
    let accepted = crate::daemon::bulk_staging::write_chunk(transfer, chunk_index, &chunk)
        .map_err(staging_error)?;
    Ok(Response::BulkTransferChunkAccepted {
        next_chunk_index: accepted.next_chunk_index,
        received_bytes: cockpit_proto::remote_protocol_id::CanonicalU64DecimalStringV1::from_u64(
            accepted.received_bytes,
        ),
        complete: accepted.complete,
        // Advertise the deadline so the peer is never surprised by expiry.
        idle_timeout_ms: crate::daemon::bulk_staging::STAGED_TRANSFER_TTL_MS as u32,
    })
}

/// Serve one chunk of a staged bulk transfer.
pub(super) async fn read_bulk_transfer_chunk(
    transfer_id: &cockpit_proto::remote_protocol_id::RemoteTransferId,
    chunk_index: u32,
) -> std::result::Result<Response, ErrorPayload> {
    let (chunk, last) =
        crate::daemon::bulk_staging::read_chunk(*transfer_id.as_bytes(), chunk_index)
            .map_err(staging_error)?;
    Ok(Response::BulkTransferChunk {
        chunk_index,
        data_base64: base64::engine::general_purpose::STANDARD.encode(&chunk),
        last,
    })
}

pub(super) async fn import_session_archive(
    ctx: &Arc<DaemonContext>,
    transfer: &cockpit_proto::remote_transport::bulk::RemoteBulkTransferRef,
    as_new: bool,
) -> std::result::Result<Response, ErrorPayload> {
    // The archive bytes were staged by prior WriteBulkTransferChunk calls; the
    // staging layer verified their length and SHA-256 before releasing them.
    let bytes = crate::daemon::bulk_staging::take(transfer).map_err(staging_error)?;
    let archive =
        crate::session::import::read_archive_bytes(&bytes).map_err(|error| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("invalid session import archive: {error:#}"),
        })?;
    let result = crate::session::import::import_archive(&ctx.db, archive, as_new)
        .await
        .map_err(internal)?;
    Ok(Response::ImportSessionArchive {
        imported: result.imported,
        redacted: result.redacted,
    })
}

/// Stage exported bytes for bulk pull and return their bounded reference.
fn stage_export_bytes(
    bytes: &[u8],
) -> std::result::Result<cockpit_proto::remote_transport::bulk::RemoteBulkTransferRef, ErrorPayload>
{
    use rand::RngExt as _;
    let mut transfer_id = [0u8; 16];
    rand::rng().fill(&mut transfer_id[..]);
    // A random 128-bit id is never all-zero in practice; force it if it is.
    if transfer_id.iter().all(|b| *b == 0) {
        transfer_id[0] = 1;
    }
    crate::daemon::bulk_staging::stage(
        bytes,
        cockpit_proto::remote_transport::bulk::RemoteBulkMimeClass::Export,
        transfer_id,
    )
    .map_err(staging_error)
}

pub(super) async fn export_session_data(
    ctx: &Arc<DaemonContext>,
    session_id: Uuid,
    kind: proto::ExportSessionKind,
    include_generated_artifacts: bool,
    include_sensitive: bool,
) -> std::result::Result<Response, ErrorPayload> {
    let db = ctx.db.clone();
    let target = db
        .get_session(session_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        })?;
    let data = match kind {
        proto::ExportSessionKind::TranscriptJson => {
            let mut messages = Vec::new();
            let mut before_seq = None;
            loop {
                let (mut page, has_more) = db
                    .read_session_messages(session_id, before_seq, u32::MAX)
                    .await
                    .map_err(internal)?;
                if page.is_empty() {
                    break;
                }
                before_seq = page.first().map(|message| message.seq);
                messages.append(&mut page);
                if !has_more {
                    break;
                }
            }
            messages.sort_by_key(|message| message.seq);
            let bytes = serde_json::to_vec_pretty(&messages).map_err(internal)?;
            let transfer = stage_export_bytes(&bytes)?;
            Ok(proto::ExportSessionData {
                session_id,
                kind,
                filename_extension: "json".to_string(),
                mime: "application/json".to_string(),
                transfer,
                session_count: Some(1),
                redacted: true,
            })
        }
        proto::ExportSessionKind::DebugBundle => {
            let bundle = crate::session::export::build_bundle_zip_bytes(
                &db,
                &target,
                include_generated_artifacts,
                include_sensitive,
            )
            .await
            .map_err(internal)?;
            let transfer = stage_export_bytes(&bundle.bytes)?;
            Ok(proto::ExportSessionData {
                session_id,
                kind,
                filename_extension: "zip".to_string(),
                mime: "application/zip".to_string(),
                transfer,
                session_count: Some(bundle.summary.session_count),
                redacted: !include_sensitive,
            })
        }
    }?;
    Ok(Response::ExportSessionData { data })
}

pub(super) async fn auto_title_request(
    ctx: &Arc<DaemonContext>,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let live = ctx.registry.live_handle(session_id);
    let session = if let Some(handle) = live.as_ref() {
        handle.session()
    } else {
        std::sync::Arc::new(
            crate::session::Session::resume(ctx.db.clone(), session_id)
                .map_err(internal)?
                .ok_or_else(|| ErrorPayload {
                    code: ErrorCode::UnknownSession,
                    message: format!("unknown session {session_id}"),
                })?,
        )
    };

    if session.title().is_some() {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "session already has a title".to_string(),
        });
    }

    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(
        &ctx.db,
        &session.project_root,
    )
    .await
    .map_err(workspace_trust_error)?;
    let (providers, extended) = ctx
        .config_source()
        .load_with_trust(&session.project_root, &trust_policy)
        .map_err(workspace_trust_error)?;
    let redact = if let Some(handle) = live {
        handle.redaction_table()
    } else {
        let table = match session.persisted_redaction_table().map_err(internal)? {
            Some(table) => table,
            None => crate::redact::RedactionTable::build(&extended.redact, &session.project_root)
                .map_err(internal)?,
        };
        std::sync::Arc::new(table)
    };

    let title = crate::auto_title::generate_session_title_slug_once(
        &session,
        extended,
        providers,
        redact,
        String::new(),
        crate::session::TitleAction::Explicit,
    )
    .await
    .map_err(|error| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: error.to_string(),
    })?
    .ok_or_else(|| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "utility model returned no usable title".to_string(),
    })?;

    if !session
        .set_explicit_auto_title_if_untitled(&title)
        .map_err(internal)?
    {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: "session already has a title".to_string(),
        });
    }

    Ok(Response::AutoTitle { session_id, title })
}

pub(super) async fn curator_request(
    ctx: &Arc<DaemonContext>,
    project_root: PathBuf,
    action: proto::CuratorAction,
) -> std::result::Result<Response, ErrorPayload> {
    let trust_policy =
        crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &project_root)
            .await
            .map_err(workspace_trust_error)?;
    let (_, extended) = ctx
        .config_source()
        .load_with_trust(&project_root, &trust_policy)
        .map_err(workspace_trust_error)?;
    let db = ctx.db.clone();
    let run_cron_refs = if matches!(action, proto::CuratorAction::Run { .. }) {
        Some(
            crate::skills::curator::cron_referenced_skills(&db)
                .await
                .map_err(|error| ErrorPayload {
                    code: ErrorCode::BadRequest,
                    message: error.to_string(),
                })?,
        )
    } else {
        None
    };
    let result = crate::config::trust::scope_workspace_trust_policy(trust_policy, async move {
        let curator = crate::skills::curator::SkillCurator::new(db, project_root, extended.skills);
        let result: Result<proto::CuratorResult> = match action {
            proto::CuratorAction::Status => Ok(proto::CuratorResult::Status {
                status: curator_status_to_proto(curator.status().await?),
            }),
            proto::CuratorAction::Run {
                dry_run,
                consolidate,
            } => Ok(proto::CuratorResult::Run {
                report: curator_run_report_to_proto(
                    curator
                        .run_with_cron_refs(
                            crate::skills::curator::CuratorRunOptions {
                                dry_run,
                                consolidate,
                            },
                            run_cron_refs.context("scheduler skill references not loaded")?,
                        )
                        .await?,
                ),
            }),
            proto::CuratorAction::Pin { name } => {
                curator.pin(&name, true).await?;
                Ok(proto::CuratorResult::Pinned { name, pinned: true })
            }
            proto::CuratorAction::Unpin { name } => {
                curator.pin(&name, false).await?;
                Ok(proto::CuratorResult::Pinned {
                    name,
                    pinned: false,
                })
            }
            proto::CuratorAction::Restore { name } => {
                curator.restore(&name).await?;
                Ok(proto::CuratorResult::Restored { name })
            }
            proto::CuratorAction::Rollback { list, id } => {
                if list {
                    Ok(proto::CuratorResult::Snapshots {
                        snapshots: curator
                            .snapshots()
                            .await?
                            .into_iter()
                            .map(curator_snapshot_to_proto)
                            .collect(),
                    })
                } else {
                    Ok(proto::CuratorResult::RolledBack {
                        snapshot: curator_snapshot_to_proto(curator.rollback(id.as_deref()).await?),
                    })
                }
            }
        };
        result
    })
    .await
    .map_err(|error| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: error.to_string(),
    })?;
    Ok(Response::Curator { result })
}

pub(super) fn curator_status_to_proto(
    status: crate::skills::curator::CuratorStatus,
) -> proto::CuratorStatus {
    proto::CuratorStatus {
        skills: status
            .skills
            .into_iter()
            .map(curator_skill_to_proto)
            .collect(),
        snapshots: status
            .snapshots
            .into_iter()
            .map(curator_snapshot_to_proto)
            .collect(),
    }
}

pub(super) fn curator_skill_to_proto(
    skill: crate::skills::curator::CuratorSkillStatus,
) -> proto::CuratorSkillStatus {
    proto::CuratorSkillStatus {
        name: skill.name,
        state: skill.state,
        created_by: skill.created_by,
        use_count: skill.use_count,
        view_count: skill.view_count,
        pinned: skill.pinned,
        source_path: skill.source_path,
        archive_path: skill.archive_path,
    }
}

pub(super) fn curator_snapshot_to_proto(
    snapshot: crate::skills::curator::CuratorSnapshotStatus,
) -> proto::CuratorSnapshotStatus {
    proto::CuratorSnapshotStatus {
        id: snapshot.id,
        path: snapshot.path,
        reason: snapshot.reason,
        created_at: snapshot.created_at,
    }
}

pub(super) fn curator_run_report_to_proto(
    report: crate::skills::curator::CuratorRunReport,
) -> proto::CuratorRunReport {
    proto::CuratorRunReport {
        dry_run: report.dry_run,
        scanned: report.scanned,
        stale: report.stale,
        archived: report.archived,
        reactivated: report.reactivated,
        skipped: report.skipped,
        snapshot_id: report.snapshot_id,
        consolidation: report.consolidation,
    }
}

pub(super) fn paused_work_to_proto(
    row: crate::db::paused_work::PausedWorkRow,
) -> proto::PausedWorkSummary {
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
