use super::authz::*;
use super::*;

pub(super) async fn list_sessions(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    project_id: Option<String>,
    parent_session_id: Option<Uuid>,
    assistant_id: Option<String>,
) -> std::result::Result<Response, ErrorPayload> {
    // The row assembly (level selection, fork counts, read/unread inputs)
    // lives in one place — `Db::list_session_summaries` — so the daemon
    // and the TUI's unavailable-connection fallback produce the same shape
    // (ordering / scoping / fork-grouping). The daemon adds its live
    // processing overlay below; disconnected readers still get the durable
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
    // v10-only assistant_id filter: retain only sessions whose
    // `assistant_name` matches. `SessionSummary` does not carry
    // `assistant_name`, so we look up the matching session ids from the
    // DB when the filter is present.
    if let Some(assistant) = assistant_id {
        let assistant_for_db = assistant.clone();
        let matching_ids = db
            .read(move |conn| {
                crate::db::Db::list_sessions_for_assistant_conn(conn, &assistant_for_db, false, 100)
            })
            .await
            .map_err(internal)?
            .into_iter()
            .map(|row| row.session_id)
            .collect::<std::collections::HashSet<_>>();
        sessions.retain(|summary| matching_ids.contains(&summary.session_id));
    }
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

pub(super) fn apply_live_activity_state(
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

pub(super) fn resource_scheduler_snapshot(
    ctx: &DaemonContext,
) -> crate::engine::resource_scheduler::ResourceSchedulerSnapshot {
    ctx.registry
        .resource_scheduler()
        .map(|scheduler| scheduler.snapshot())
        .unwrap_or_else(|| {
            crate::engine::resource_scheduler::ResourceScheduler::disabled().snapshot()
        })
}

pub(super) async fn promote_resource_request(
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
        )
        .await;
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
        record_resource_promotion(ctx, audit_session_id, token, false, &message).await;
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
    record_resource_promotion(ctx, audit_session_id, token, applied, &message).await;
    Ok(Response::PromoteResourceResult {
        status,
        message,
        snapshot,
    })
}

pub(super) async fn record_resource_promotion(
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
    let _ = ctx
        .db
        .insert_session_event(
            session_id,
            crate::db::session_log::SessionEventKind::ResourcePromotion,
            None,
            None,
            &data,
        )
        .await;
}

pub(super) async fn fork_session(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
    fresh_thread: bool,
) -> std::result::Result<Response, ErrorPayload> {
    // Guard rail: refuse forks of unknown parents with the typed
    // `UnknownSession` code so the TUI can surface a friendlier error
    // than a generic internal failure. Resolve this BEFORE reserving any
    // ledger row (L18: fallible resolution precedes the durable record).
    match ctx.db.get_session(parent_session_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown parent session {parent_session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    let created_by = principal.tag();
    // `/side` forks land ephemeral (excluded from lists, never auto-titled,
    // discarded on end/exit); fresh threads persist with only an anchor.
    if fresh_thread {
        if ephemeral {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "a fresh thread cannot be ephemeral".to_string(),
            });
        }
        if fork_point_turn_id.is_none() {
            return Err(ErrorPayload {
                code: ErrorCode::BadRequest,
                message: "a fresh thread requires a message anchor".to_string(),
            });
        }
    }
    // Vault custody is copied before the child row is visible, matching
    // `Session::create_fork`: a failed copy must not leave a resumable fork
    // without its redaction boundary.
    let row = crate::session::lifecycle::persist_fork_with_redaction_custody(
        &ctx.db,
        &ctx.secret_vault,
        parent_session_id,
        fork_point_turn_id.clone(),
        ephemeral,
        fresh_thread,
    )
    .map_err(internal)?;
    if let Some(tag) = created_by {
        ctx.db
            .set_session_created_by_principal(row.session_id, Some(&tag))
            .await
            .map_err(internal)?;
    }
    Ok(Response::Forked {
        session_id: row.session_id,
        short_id: row.short_id.unwrap_or_default(),
        parent_session_id,
        fork_point_turn_id,
    })
}

pub(super) fn btw_info_to_proto(info: crate::db::sessions::BtwForkInfo) -> proto::BtwForkInfo {
    proto::BtwForkInfo {
        session_id: info.session_id,
        parent_session_id: info.parent_session_id,
        short_id: info.short_id,
        tangent: info.tangent,
        created_at: info.created_at_unix_ms,
        message_count: info.message_count,
    }
}

pub(super) async fn create_btw_fork(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    tangent: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(parent_session_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown parent session {parent_session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    let created_by = principal.tag();
    let result = crate::session::lifecycle::persist_btw_fork_with_redaction_custody(
        &ctx.db,
        ctx.secret_vault.clone(),
        parent_session_id,
        tangent,
    )
    .await
    .map_err(internal)?;
    if result.created
        && let Some(tag) = created_by
    {
        ctx.db
            .set_session_created_by_principal(result.info.session_id, Some(&tag))
            .await
            .map_err(internal)?;
    }
    Ok(Response::BtwFork {
        info: btw_info_to_proto(result.info),
        created: result.created,
    })
}

pub(super) async fn end_btw_fork(
    ctx: &DaemonContext,
    parent_session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    // Stop the live `/btw` worker first (idempotent — safe to repeat on a
    // replayed operation) so the durable deletion below never races a
    // running worker.
    if let Some(info) = ctx
        .db
        .live_btw_fork_info(parent_session_id)
        .await
        .map_err(internal)?
    {
        ctx.registry
            .interrupt_and_stop(info.session_id)
            .await
            .map_err(internal)?;
    }
    ctx.db
        .end_btw_fork(parent_session_id)
        .await
        .map_err(internal)?;
    Ok(Response::Ack)
}

/// Discard an ephemeral side-conversation (`/side`): stop its live worker
/// (cancelling jobs, ending the current turn) then delete its row +
/// descendant forks. Guarded — a non-ephemeral session is left untouched,
/// so a stray discard can never drop a persisted session. Idempotent: an
/// already-gone session acks without error.
pub(super) async fn discard_session(
    state: &mut MutableClientState,
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
    // leave the ephemeral session row intact. Idempotent on a replayed
    // operation.
    ctx.registry
        .interrupt_and_stop(session_id)
        .await
        .map_err(internal)?;
    ctx.db
        .discard_ephemeral_session(session_id)
        .await
        .map_err(internal)?;
    Ok(Response::Ack)
}

pub(super) async fn rename_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    title: &str,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    ctx.db
        .rename_session(session_id, title)
        .await
        .map_err(internal)?;
    Ok(Response::Ack)
}

/// Append a `/note` user-authored session-history note
/// (implementation note). Records a `user_note` session event on
/// the target session and returns its assigned `seq`. The note never enters
/// model-bound history (rehydration skips `user_note`) and triggers no
/// inference — it is purely a durable, exportable transcript annotation.
pub(super) async fn record_session_note(
    ctx: &DaemonContext,
    session_id: Uuid,
    text: &str,
) -> std::result::Result<Response, ErrorPayload> {
    let agent = match ctx.db.get_session(session_id).await {
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
        .await
        .map_err(internal)?;
    Ok(Response::NoteRecorded { seq })
}

pub(super) async fn delete_session(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    let session = match ctx.db.get_session(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    };
    if session.ended_at_unix_ms.is_none() {
        return Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: format!("session {session_id} is active; end it before deleting"),
        });
    }
    // Capture filesystem targets before the relational cascade removes the
    // descendants that authorize them. Both workspace scratch and result blobs
    // are daemon-owned state and must be deleted with the session.
    let subtree = ctx
        .db
        .session_subtree_ids(session_id)
        .await
        .map_err(internal)?;
    let mut scratch_dirs = Vec::with_capacity(subtree.len());
    let mut result_blob_dirs = Vec::with_capacity(subtree.len());
    for member in subtree {
        let Some(member_session) = ctx.db.get_session(member).await.map_err(internal)? else {
            continue;
        };
        scratch_dirs.push(
            crate::session::workspace_scratch_path_for_session(&member_session.project_id, member)
                .map_err(internal)?,
        );
        result_blob_dirs
            .push(super::storage::result_blob_directory_for_session(member).map_err(internal)?);
    }
    prepare_session_deletion(ctx, session_id).await?;
    let now_wall_ms = super::run_invocation::wall_ms_now();
    // Local/owner path: terminalize then delete (each its own autocommit).
    ctx.db
        .terminalize_session_run_invocations(session_id, now_wall_ms)
        .await
        .map_err(internal)?;
    for scratch_dir in scratch_dirs {
        remove_session_scratch(&scratch_dir).map_err(internal)?;
    }
    for result_blob_dir in result_blob_dirs {
        remove_session_scratch(&result_blob_dir).map_err(internal)?;
        match std::fs::symlink_metadata(&result_blob_dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(internal(anyhow::anyhow!(
                    "session deletion left result blobs at `{}`",
                    result_blob_dir.display()
                )));
            }
            Err(error) => return Err(internal(error)),
        }
    }
    ctx.db.delete_session(session_id).await.map_err(internal)?;
    if let Some(service) = ctx.acp_catalog_composition.as_ref() {
        service.revoke_root(session_id);
    }
    if let Err(error) = crate::text_artifact_blob::reconcile_cleanup_intents(&ctx.db).await {
        tracing::warn!(%error, %session_id, "text artifact blob cleanup remains pending");
    }
    Ok(Response::Ack)
}

pub(crate) fn remove_session_scratch(path: &std::path::Path) -> anyhow::Result<()> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("inspecting `{}`", path.display()));
        }
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "refusing to remove non-directory session scratch `{}`",
        path.display()
    );
    std::fs::remove_dir_all(path).with_context(|| format!("removing `{}`", path.display()))
}

/// Complete every asynchronous, idempotent side-effect phase that must precede
/// the session-row transaction. Both the local and remote commit paths call
/// this exact sequence; the remote adapter performs committed-replay lookup
/// before entering it.
pub(super) async fn prepare_session_deletion(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<(), ErrorPayload> {
    // Don't delete out from under a running worker (GOALS §17h): stop any
    // live workers in the affected subtree first — that cancels their
    // async jobs and ends the current turn cleanly.
    stop_subtree(ctx, session_id, true).await?;
    // Deletion barrier: commit Deleting, wait for ProvenEmpty containments.
    if let Some(pc) = ctx.process_containment.as_ref() {
        pc.begin_session_deletion(session_id)
            .await
            .map_err(|e| ErrorPayload {
                code: ErrorCode::Internal,
                message: format!("containment deletion barrier: {e}"),
            })?;
        if let Err(e) = pc.finish_session_deletion(session_id).await {
            return Err(ErrorPayload {
                code: ErrorCode::Internal,
                message: format!("session deletion blocked on nonempty containments: {e}"),
            });
        }
    }
    // Write-scope barrier: block new transfers, then refuse to delete while any
    // lease still holds authority or any permit is still held. Deleting the
    // session rows underneath a live lease would drop the durable record of an
    // authority that a still-running descendant believes it owns.
    if let Some(ws) = ctx.write_scope.as_ref() {
        let blockers = ws
            .begin_session_deletion(session_id)
            .await
            .map_err(|e| ErrorPayload {
                code: ErrorCode::Internal,
                message: format!("write scope deletion barrier: {e}"),
            })?;
        if !blockers.is_empty() {
            return Err(ErrorPayload {
                code: ErrorCode::Internal,
                message: format!(
                    "session deletion blocked on {} outstanding write-scope lease(s)/permit(s)",
                    blockers.len()
                ),
            });
        }
    }
    let now_wall_ms = super::run_invocation::wall_ms_now();
    // Media cleanup is a durable PRECONDITION of the deletion barrier in
    // `delete_session_conn` (a session cannot be deleted until its media reaches
    // a deletion-evidenced terminal). It is a cross-subsystem async operation
    // that cannot run inside the SQLite ledger transaction, and it is idempotent
    // / reconcilable: a later ledger failure leaves the retry safe because the
    // reconcile pass re-runs it. Run it before either delete path.
    if let Some(storage) = &ctx.media_storage_recovery {
        storage
            .begin_session_deletion_cleanup(session_id, now_wall_ms)
            .await
            .map_err(internal)?;
        storage
            .reconcile_media_cleanup_intents(now_wall_ms)
            .await
            .map_err(internal)?;
    }
    Ok(())
}

pub(super) async fn archive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    cascade: bool,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id).await {
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
        .await
        .map_err(internal)?;
    if let Some(service) = ctx.acp_catalog_composition.as_ref() {
        service.revoke_root(session_id);
    }
    Ok(Response::Ack)
}

/// Stop any live worker for `root` (and, when `cascade`, its whole fork
/// subtree) before an archive/delete. Best-effort over the candidate ids
/// the daemon currently has active workers for — there is no DB walk
/// here because only sessions with a live worker need interrupting, and
/// the registry already knows those.
pub(super) async fn stop_subtree(
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
        if ctx.db.is_in_subtree(root, id).await.unwrap_or(false) {
            ctx.registry
                .interrupt_and_stop(id)
                .await
                .map_err(internal)?;
        }
    }
    Ok(())
}

pub(super) async fn unarchive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> std::result::Result<Response, ErrorPayload> {
    match ctx.db.get_session(session_id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return Err(ErrorPayload {
                code: ErrorCode::UnknownSession,
                message: format!("unknown session {session_id}"),
            });
        }
        Err(e) => return Err(internal(e)),
    }
    ctx.db
        .unarchive_session(session_id)
        .await
        .map_err(internal)?;
    Ok(Response::Ack)
}

pub(super) fn require_attached(
    state: &MutableClientState,
) -> std::result::Result<&AttachedSession, ErrorPayload> {
    state.attached.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::NotAttached,
        message: "client has not attached to a session".into(),
    })
}

pub(super) fn validate_set_agent(
    ctx: &DaemonContext,
    att: &AttachedSession,
    name: &str,
) -> std::result::Result<(), ErrorPayload> {
    let trust_policy = att.handle.current_trust_policy();
    let _ = ctx
        .config_source()
        .load_effective_for_daemon(&att.handle.project_root, &trust_policy)
        .map_err(super::dispatch::daemon_config_error)?;
    let ownable = crate::config::trust::with_workspace_trust_policy(trust_policy, || {
        crate::agents::chat_ownable_primaries(&att.handle.project_root)
    });
    validate_set_agent_name(name, &ownable)
}

pub(super) fn validate_set_agent_name(
    name: &str,
    ownable: &[String],
) -> std::result::Result<(), ErrorPayload> {
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

/// Map a [`crate::daemon::session_worker::SessionWorkerHandle::send_work`]
/// failure onto its wire error.
///
/// The trust-reconciliation refusal is transient by construction: the worker is
/// holding a committed decision's fail-closed admission gate and will accept the
/// same work again once its driver applies the projection at the next turn
/// boundary. Answering `Internal` there told the client "something broke" when
/// the correct instruction is "send this again shortly", so it is downcast —
/// typed, never matched on prose — into `RetryLater`. Every other `send_work`
/// failure means the worker channel is gone, which is terminal for that handle
/// and stays `Internal`.
pub(super) fn session_work_error(error: anyhow::Error) -> ErrorPayload {
    if let Some(reconciling) =
        error.downcast_ref::<crate::daemon::session_worker::SessionWorkTrustReconciling>()
    {
        return ErrorPayload {
            code: ErrorCode::RetryLater,
            message: reconciling.to_string(),
        };
    }
    internal(error)
}

pub(super) fn require_scheduler(
    ctx: &DaemonContext,
) -> std::result::Result<&DaemonSchedulerHandle, ErrorPayload> {
    ctx.scheduler.as_ref().ok_or_else(|| ErrorPayload {
        code: ErrorCode::BadRequest,
        message: "scheduler is only available in the shared daemon".to_string(),
    })
}

pub(super) fn workspace_trust_error(err: anyhow::Error) -> ErrorPayload {
    if err
        .downcast_ref::<crate::config::extended::InvalidResponseMetricsTokenizer>()
        .is_some()
    {
        return super::dispatch::daemon_config_error(err);
    }
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

#[cfg(test)]
mod sessions_activity_tests {
    use super::*;

    fn summary(activity_state: Option<proto::SessionActivityState>) -> proto::SessionSummary {
        proto::SessionSummary {
            session_id: Uuid::new_v4(),
            session_entry_mode: "code".into(),
            short_id: None,
            project_root: "/proj".into(),
            project_id: "pid".into(),
            started_at_unix_ms: 1,
            last_active_at_unix_ms: 1,
            turns: 0,
            active_agent: "Build".into(),
            title: None,
            description: None,
            parent_session_id: None,
            fork_point_turn_id: None,
            is_assistant_thread: false,
            created_by_principal: None,
            shared_with_collaborators: false,
            fork_count: 0,
            descendant_count: 0,
            last_viewed_at_unix_ms: None,
            latest_activity_at_unix_ms: None,
            open_interrupts: 0,
            activity_state,
            archived_at_unix_ms: None,
            pin_count: 0,
            assistant_inbox_unread: 0,
            assistant_inbox_latest_source_session_id: None,
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
