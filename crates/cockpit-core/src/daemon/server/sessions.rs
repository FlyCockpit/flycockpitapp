async fn list_sessions(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_id: Option<String>,
    parent_session_id: Option<Uuid>,
) -> std::result::Result<Response, ErrorPayload> {
    // The row assembly (level selection, fork counts, read/unread inputs)
    // lives in one place — `Db::list_session_summaries` — so the daemon
    // and the TUI's daemonless direct-DB fallback produce the same shape
    // (ordering / scoping / fork-grouping). The daemon adds its live
    // processing overlay below; daemonless readers still get the durable
    // DB-derived state.
    let db = ctx.db.clone();
    let mut sessions = db
        .read(move |conn| {
            crate::db::Db::list_session_summaries_conn(
                conn,
                project_id.as_deref(),
                parent_session_id,
                100,
            )
        })
        .await
        .map_err(internal)?;
    if !principal.is_owner() {
        sessions.retain(|summary| {
            session_access_for_summary(principal, summary) != SessionAccess::None
        });
    }
    for summary in &mut sessions {
        if let Some((_has_active_schedules, processing, tool_running)) =
            ctx.registry.live_status(summary.session_id)
        {
            apply_live_activity_state(summary, processing, tool_running);
        }
    }
    Ok(Response::Sessions { sessions })
}

fn apply_live_activity_state(
    summary: &mut proto::SessionSummary,
    processing: bool,
    tool_running: bool,
) {
    if summary.activity_state.is_some() {
        return;
    }
    if tool_running {
        summary.activity_state = Some(proto::SessionActivityState::ToolRunning);
    } else if processing {
        summary.activity_state = Some(proto::SessionActivityState::InferenceInProgress);
    }
}

fn resource_scheduler_snapshot(
    ctx: &DaemonContext,
) -> crate::engine::resource_scheduler::ResourceSchedulerSnapshot {
    ctx.registry
        .resource_scheduler()
        .map(|scheduler| scheduler.snapshot())
        .unwrap_or_else(|| {
            crate::engine::resource_scheduler::ResourceScheduler::disabled().snapshot()
        })
}

fn promote_resource_request(
    ctx: &DaemonContext,
    request_id: &str,
    fallback_session_id: Option<Uuid>,
) -> std::result::Result<Response, ErrorPayload> {
    use crate::engine::resource_scheduler::ResourcePromoteError;

    let Some(scheduler) = ctx.registry.resource_scheduler() else {
        let snapshot = resource_scheduler_snapshot(ctx);
        return Ok(Response::PromoteResourceResult {
            status: proto::ResourcePromoteStatus::Disabled,
            message: "resource scheduler is disabled for this daemon".to_string(),
            snapshot,
        });
    };

    let token = request_id.trim();
    let before = scheduler.snapshot();
    let running_match = before
        .running
        .iter()
        .find(|entry| entry.display_id == token || entry.id.to_string() == token);
    if let Some(entry) = running_match {
        let message = format!(
            "resource request {} is already running; running work cannot be promoted",
            entry.display_id
        );
        record_resource_promotion(
            ctx,
            Some(entry.metadata.session_id).flatten(),
            token,
            false,
            &message,
        );
        return Ok(Response::PromoteResourceResult {
            status: proto::ResourcePromoteStatus::NotQueued,
            message,
            snapshot: before,
        });
    }

    let queued_match = before
        .queued
        .iter()
        .find(|entry| entry.display_id == token || entry.id.to_string() == token);
    let promote_id = queued_match
        .map(|entry| entry.id)
        .or_else(|| Uuid::parse_str(token).ok());
    let audit_session_id = queued_match
        .and_then(|entry| entry.metadata.session_id)
        .or(fallback_session_id);

    let Some(promote_id) = promote_id else {
        let message = format!("resource request `{token}` is no longer queued");
        record_resource_promotion(ctx, audit_session_id, token, false, &message);
        return Ok(Response::PromoteResourceResult {
            status: proto::ResourcePromoteStatus::NotFound,
            message,
            snapshot: before,
        });
    };

    let result = scheduler.promote(promote_id, "tui");
    let snapshot = scheduler.snapshot();
    let (status, message, applied) = match result {
        Ok(()) => {
            let display = queued_match
                .map(|entry| entry.display_id.as_str())
                .unwrap_or(token);
            (
                proto::ResourcePromoteStatus::Promoted,
                format!("promoted resource request {display}"),
                true,
            )
        }
        Err(ResourcePromoteError::NotQueued(_)) => (
            proto::ResourcePromoteStatus::NotQueued,
            format!("resource request `{token}` is already running or completed"),
            false,
        ),
        Err(ResourcePromoteError::NotFound(_)) => (
            proto::ResourcePromoteStatus::NotFound,
            format!("resource request `{token}` is no longer queued"),
            false,
        ),
    };
    record_resource_promotion(ctx, audit_session_id, token, applied, &message);
    Ok(Response::PromoteResourceResult {
        status,
        message,
        snapshot,
    })
}

fn record_resource_promotion(
    ctx: &DaemonContext,
    session_id: Option<Uuid>,
    request_id: &str,
    applied: bool,
    message: &str,
) {
    let Some(session_id) = session_id else {
        return;
    };
    let data = serde_json::json!({
        "request_id": request_id,
        "applied": applied,
        "message": message,
        "source": "tui",
    });
    let _ = ctx.db.insert_session_event(
        session_id,
        crate::db::session_log::SessionEventKind::ResourcePromotion,
        None,
        None,
        &data,
    );
}

fn fork_session(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
) -> std::result::Result<Response, ErrorPayload> {
    // Guard rail: refuse forks of unknown parents with the typed
    // `UnknownSession` code so the TUI can surface a friendlier error
    // than a generic internal failure.
    match ctx.db.get_session(parent_session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown parent session {parent_session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    // `/side` forks land ephemeral (excluded from lists, never auto-titled,
    // discarded on end/exit); `/fork` forks persist normally.
    let row = if ephemeral {
        ctx.db
            .create_ephemeral_fork(parent_session_id, fork_point_turn_id.clone())
    } else {
        ctx.db
            .create_fork(parent_session_id, fork_point_turn_id.clone())
    }
    .map_err(internal)?;
    if let Some(tag) = principal.tag() {
        ctx.db
            .set_session_created_by_principal(row.session_id, Some(&tag))
            .map_err(internal)?;
    }
    Ok(Response::Forked {
        session_id: row.session_id,
        short_id: row.short_id.unwrap_or_default(),
        parent_session_id,
        fork_point_turn_id,
    })
}

fn btw_info_to_proto(info: crate::db::sessions::BtwForkInfo) -> proto::BtwForkInfo {
    proto::BtwForkInfo {
        session_id: info.session_id,
        parent_session_id: info.parent_session_id,
        short_id: info.short_id,
        tangent: info.tangent,
        created_at: info.created_at,
        message_count: info.message_count,
    }
}

fn create_btw_fork(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    tangent: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(parent_session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown parent session {parent_session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    let result = ctx
        .db
        .create_btw_fork(parent_session_id, tangent)
        .map_err(internal)?;
    if result.created
        && let Some(tag) = principal.tag()
    {
        ctx.db
            .set_session_created_by_principal(result.info.session_id, Some(&tag))
            .map_err(internal)?;
    }
    Ok(Response::BtwFork {
        info: btw_info_to_proto(result.info),
        created: result.created,
    })
}

async fn end_btw_fork(
    ctx: &DaemonContext,
    parent_session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    if let Some(info) = ctx
        .db
        .live_btw_fork_info(parent_session_id)
        .map_err(internal)?
    {
        ctx.registry
            .interrupt_and_stop(info.session_id)
            .await
            .map_err(internal)?;
    }
    ctx.db.end_btw_fork(parent_session_id).map_err(internal)?;
    Ok(Response::Ack)
}

/// Discard an ephemeral side-conversation (`/side`): stop its live worker
/// (cancelling jobs, ending the current turn) then delete its row +
/// descendant forks. Guarded — a non-ephemeral session is left untouched,
/// so a stray discard can never drop a persisted session. Idempotent: an
/// already-gone session acks without error.
async fn discard_session(
    state: &mut ClientState,
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    // Detach this client from the session it's discarding so the daemon
    // doesn't keep streaming a torn-down worker's events at it.
    if let Some(att) = &state.attached
        && att.handle.session_id == session_id
    {
        state.attached = None;
    }
    // Stop the live worker first. Fail closed: if the worker does not stop,
    // leave the ephemeral session row intact.
    ctx.registry
        .interrupt_and_stop(session_id)
        .await
        .map_err(internal)?;
    ctx.db
        .discard_ephemeral_session(session_id)
        .map_err(internal)?;
    Ok(Response::Ack)
}

fn rename_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    title: &str,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    ctx.db.rename_session(session_id, title).map_err(internal)?;
    Ok(Response::Ack)
}

/// Append a `/note` user-authored session-history note
/// (implementation note). Records a `user_note` session event on
/// the target session and returns its assigned `seq`. The note never enters
/// model-bound history (rehydration skips `user_note`) and triggers no
/// inference — it is purely a durable, exportable transcript annotation.
fn record_session_note(
    ctx: &DaemonContext,
    session_id: Uuid,
    text: &str,
) -> std::result::Result<Response, ErrorPayload> {
    let agent = match ctx.db.get_session(session_id) {
        Ok(Some(s)) => s.active_agent,
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    };
    let seq = ctx
        .db
        .insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::UserNote,
            Some(agent.as_str()),
            None,
            &serde_json::json!({ "text": text }),
        )
        .map_err(internal)?;
    Ok(Response::NoteRecorded { seq })
}

async fn delete_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    cascade: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    // Don't delete out from under a running worker (GOALS §17h): stop any
    // live workers in the affected subtree first — that cancels their
    // async jobs and ends the current turn cleanly.
    stop_subtree(ctx, session_id, cascade).await?;
    ctx.db
        .delete_session(session_id, cascade)
        .map_err(internal)?;
    Ok(Response::Ack)
}

async fn archive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    cascade: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    // Same interrupt-first rule as delete: don't archive a session while
    // its worker is live.
    stop_subtree(ctx, session_id, cascade).await?;
    ctx.db
        .archive_session(session_id, cascade)
        .map_err(internal)?;
    Ok(Response::Ack)
}

/// Stop any live worker for `root` (and, when `cascade`, its whole fork
/// subtree) before an archive/delete. Best-effort over the candidate ids
/// the daemon currently has active workers for — there is no DB walk
/// here because only sessions with a live worker need interrupting, and
/// the registry already knows those.
async fn stop_subtree(
    ctx: &DaemonContext,
    root: Uuid,
    cascade: bool,
) -> std::result::Result<(), ErrorPayload> {
    if !cascade {
        ctx.registry
            .interrupt_and_stop(root)
            .await
            .map_err(internal)?;
        return Ok(());
    }
    // Cascade: interrupt every active session whose row sits in the
    // subtree rooted at `root`. We intersect the daemon's live worker set
    // with the DB subtree so we only walk what's actually running.
    let active = ctx.registry.active_session_ids();
    for id in active {
        if ctx.db.is_in_subtree(root, id).unwrap_or(false) {
            ctx.registry
                .interrupt_and_stop(id)
                .await
                .map_err(internal)?;
        }
    }
    Ok(())
}

fn unarchive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id) {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    ctx.db.unarchive_session(session_id).map_err(internal)?;
    Ok(Response::Ack)
}

fn require_attached(state: &ClientState) -> std::result::Result<&AttachedSession, ErrorPayload> {
    state.attached.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::NotAttached,
        message: "client has not attached to a session".into(),
    })
}

fn validate_set_agent(
    ctx: &DaemonContext,
    att: &AttachedSession,
    name: &str,
) -> std::result::Result<(), ErrorPayload> {
    let (_, cfg) = ctx
        .config_source()
        .load_with_trust(&att.handle.project_root, &att.handle.trust_policy)
        .map_err(internal)?;
    let ownable =
        crate::config::trust::with_workspace_trust_policy(att.handle.trust_policy.clone(), || {
            crate::agents::chat_ownable_primaries(&att.handle.project_root)
        });
    validate_set_agent_name(name, cfg.experimental_mode, &ownable)
}

fn validate_set_agent_name(
    name: &str,
    experimental_mode: bool,
    ownable: &[String],
) -> std::result::Result<(), ErrorPayload> {
    if crate::agents::is_experimental_primary(name) && !experimental_mode {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("agent `{name}` requires experimental mode"),
        });
    }

    if !ownable.iter().any(|agent| agent == name) {
        return Err(ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!(
                "agent `{name}` is not a chat-ownable primary; valid choices: {}",
                ownable.join(", ")
            ),
        });
    }

    Ok(())
}

fn internal<E: std::fmt::Display>(err: E) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        // `{:#}` walks the full anyhow context chain (e.g. `resolving
        // model: provider ...: ...`) rather than printing only the
        // outermost context, so daemon-surfaced errors are legible
        // instead of an opaque `internal: resolving model`.
        message: format!("{err:#}"),
    }
}

fn workspace_trust_error(err: anyhow::Error) -> ErrorPayload {
    if err
        .downcast_ref::<crate::config::trust::WorkspaceTrustError>()
        .is_some()
    {
        ErrorPayload {
            code: ErrorCode::WorkspaceTrust,
            message: err.to_string(),
        }
    } else {
        internal(err)
    }
}

fn not_implemented(what: &str) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        // `{:#}` for consistency with `internal()`; `what` is a plain
        // slug here, so the alternate form is identical, but keeping the
        // same form means a future error-typed arg would print its chain.
        message: format!("{what:#} not yet implemented in v1"),
    }
}

#[cfg(test)]
mod sessions_activity_tests {
    use super::*;

    fn summary(activity_state: Option<proto::SessionActivityState>) -> proto::SessionSummary {
        proto::SessionSummary {
            session_id: Uuid::new_v4(),
            short_id: None,
            project_root: "/proj".into(),
            project_id: "pid".into(),
            started_at: 1,
            last_active_at: 1,
            turns: 0,
            active_agent: "Build".into(),
            title: None,
            parent_session_id: None,
            created_by_principal: None,
            shared_with_collaborators: false,
            fork_count: 0,
            descendant_count: 0,
            last_viewed_at: None,
            latest_activity_at: None,
            open_interrupts: 0,
            activity_state,
            archived_at: None,
            pin_count: 0,
        }
    }

    #[test]
    fn live_activity_overlay_distinguishes_tool_from_inference() {
        let mut tool = summary(None);
        apply_live_activity_state(&mut tool, true, true);
        assert_eq!(
            tool.activity_state,
            Some(proto::SessionActivityState::ToolRunning)
        );

        let mut inference = summary(None);
        apply_live_activity_state(&mut inference, true, false);
        assert_eq!(
            inference.activity_state,
            Some(proto::SessionActivityState::InferenceInProgress)
        );

        let mut durable = summary(Some(proto::SessionActivityState::PendingQuestion));
        apply_live_activity_state(&mut durable, true, true);
        assert_eq!(
            durable.activity_state,
            Some(proto::SessionActivityState::PendingQuestion)
        );
    }
}

