//! Remote-only session mutation adapters.
//!
//! Local session behavior lives in `sessions`; this module is the sole owner of
//! FCOR identities, remote replay/outbox state, and transactional remote
//! mutation composition for sessions.

use super::authz::ClientPrincipal;
use super::sessions::{btw_info_to_proto, stop_subtree};
use super::*;

#[derive(Debug, thiserror::Error)]
#[error("unknown session {0}")]
struct UnknownRemoteSession(Uuid);

fn require_mutated(existed: bool, session_id: Uuid) -> anyhow::Result<()> {
    if existed {
        Ok(())
    } else {
        Err(UnknownRemoteSession(session_id).into())
    }
}

fn remote_mutation_error(error: anyhow::Error) -> ErrorPayload {
    if let Some(unknown) = error.downcast_ref::<UnknownRemoteSession>() {
        ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: unknown.to_string(),
        }
    } else {
        internal(error)
    }
}

pub(super) struct RemoteSessionLedger {
    logical_attachment_id: String,
    operation_id: String,
    authenticated_device_id: String,
    authenticated_device_generation: u64,
    request_hash: [u8; 32],
}

impl RemoteSessionLedger {
    pub(super) fn new(operation: &super::RemoteOperationContext, request_hash: [u8; 32]) -> Self {
        Self {
            logical_attachment_id: operation.logical_attachment_id.to_string(),
            operation_id: operation.operation_id.to_string(),
            authenticated_device_id: operation.authenticated_device_id.to_string(),
            authenticated_device_generation: operation.authenticated_device_generation,
            request_hash,
        }
    }

    async fn committed_replay(
        &self,
        ctx: &DaemonContext,
    ) -> std::result::Result<Option<Response>, ErrorPayload> {
        use crate::db::remote_attachment_operations::{
            RemoteOperationClass, RemoteTransactionalReplayLookup, ReserveRemoteOperation,
        };
        let lookup = ctx
            .db
            .lookup_committed_remote_operation(ReserveRemoteOperation {
                logical_attachment_id: &self.logical_attachment_id,
                operation_id: &self.operation_id,
                authenticated_device_id: &self.authenticated_device_id,
                authenticated_device_generation: self.authenticated_device_generation,
                operation_class: RemoteOperationClass::TransactionalMutation,
                request_hash: self.request_hash,
                now_ms: chrono::Utc::now().timestamp_millis(),
            })
            .await
            .map_err(internal)?;
        match lookup {
            RemoteTransactionalReplayLookup::CommittedReplay(bytes) => {
                Ok(Some(serde_json::from_slice(&bytes).map_err(internal)?))
            }
            RemoteTransactionalReplayLookup::OperationConflict
            | RemoteTransactionalReplayLookup::OperationActorConflict => Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message: "remote operation conflict".into(),
            }),
            RemoteTransactionalReplayLookup::Absent => Ok(None),
            RemoteTransactionalReplayLookup::ExistingIndeterminate => Err(ErrorPayload {
                code: ErrorCode::Conflict,
                message:
                    "remote operation has an indeterminate persisted outcome; it will not be retried"
                        .into(),
            }),
        }
    }
}

pub(super) async fn commit_session_remote_mutation<F>(
    ctx: &DaemonContext,
    ledger: &RemoteSessionLedger,
    outbox_kind: &'static str,
    mutation: F,
) -> std::result::Result<Response, ErrorPayload>
where
    F: FnOnce(&rusqlite::Connection) -> anyhow::Result<Response> + Send + 'static,
{
    use crate::db::remote_attachment_operations::{
        RemoteOperationClass, ReserveRemoteOperation, TransactionalRemoteMutation,
        TransactionalRemoteOperationOutcome,
    };
    let outcome = ctx
        .db
        .execute_transactional_remote_operation(
            ReserveRemoteOperation {
                logical_attachment_id: &ledger.logical_attachment_id,
                operation_id: &ledger.operation_id,
                authenticated_device_id: &ledger.authenticated_device_id,
                authenticated_device_generation: ledger.authenticated_device_generation,
                operation_class: RemoteOperationClass::TransactionalMutation,
                request_hash: ledger.request_hash,
                now_ms: chrono::Utc::now().timestamp_millis(),
            },
            move |conn| {
                let response = mutation(conn)?;
                let safe_response = serde_json::to_vec(&response)?;
                Ok(TransactionalRemoteMutation {
                    value: response,
                    safe_response: safe_response.clone(),
                    outbox_kind: outbox_kind.into(),
                    outbox_payload: safe_response,
                })
            },
        )
        .await
        .map_err(remote_mutation_error)?;
    match outcome {
        TransactionalRemoteOperationOutcome::Applied(response) => Ok(response),
        TransactionalRemoteOperationOutcome::Replay(bytes) => {
            serde_json::from_slice(&bytes).map_err(internal)
        }
        TransactionalRemoteOperationOutcome::OperationConflict
        | TransactionalRemoteOperationOutcome::OperationActorConflict => Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "remote operation conflict".into(),
        }),
        TransactionalRemoteOperationOutcome::ExistingIndeterminate => Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message:
                "remote operation has an indeterminate persisted outcome; it will not be retried"
                    .into(),
        }),
        TransactionalRemoteOperationOutcome::AttachmentLedgerCapacity
        | TransactionalRemoteOperationOutcome::AttachmentOutboxCapacity => Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "remote operation capacity reached".into(),
        }),
    }
}

async fn require_session(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> Result<crate::db::sessions::SessionRow, ErrorPayload> {
    ctx.db
        .get_session(session_id)
        .await
        .map_err(internal)?
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        })
}

pub(super) async fn fork_session(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    fork_point_turn_id: Option<String>,
    ephemeral: bool,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    let created_by = principal.tag();
    let session_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp_millis();
    let fork_point = fork_point_turn_id.clone();
    commit_session_remote_mutation(ctx, ledger, "fork_session", move |conn| {
        if crate::db::Db::get_session_conn(conn, parent_session_id)?.is_none() {
            return Err(UnknownRemoteSession(parent_session_id).into());
        }
        let row = crate::db::Db::create_fork_row_conn(
            conn,
            parent_session_id,
            fork_point,
            ephemeral,
            session_id,
            now,
        )?;
        if let Some(tag) = created_by.as_deref() {
            crate::db::Db::set_session_created_by_principal_conn(conn, row.session_id, Some(tag))?;
        }
        Ok(Response::Forked {
            session_id: row.session_id,
            short_id: row.short_id.unwrap_or_default(),
            parent_session_id,
            fork_point_turn_id,
        })
    })
    .await
}

pub(super) async fn create_btw_fork(
    ctx: &DaemonContext,
    principal: &ClientPrincipal,
    parent_session_id: Uuid,
    tangent: bool,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    let created_by = principal.tag();
    let session_id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp_millis();
    commit_session_remote_mutation(ctx, ledger, "btw_create", move |conn| {
        if crate::db::Db::get_session_conn(conn, parent_session_id)?.is_none() {
            return Err(UnknownRemoteSession(parent_session_id).into());
        }
        let result =
            crate::db::Db::create_btw_fork_conn(conn, parent_session_id, tangent, session_id, now)?;
        if result.created
            && let Some(tag) = created_by.as_deref()
        {
            crate::db::Db::set_session_created_by_principal_conn(
                conn,
                result.info.session_id,
                Some(tag),
            )?;
        }
        Ok(Response::BtwFork {
            info: btw_info_to_proto(result.info),
            created: result.created,
        })
    })
    .await
}

pub(super) async fn end_btw_fork(
    ctx: &DaemonContext,
    parent_session_id: Uuid,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
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
    let response = commit_session_remote_mutation(ctx, ledger, "btw_end", move |conn| {
        if crate::db::Db::get_session_conn(conn, parent_session_id)?.is_none() {
            return Err(UnknownRemoteSession(parent_session_id).into());
        }
        let _ = crate::db::Db::end_btw_fork_conn(conn, parent_session_id)?;
        Ok(Response::Ack)
    })
    .await?;
    if let Err(error) = ctx.db.reconcile_delegation_sidecar_cleanup_intents().await {
        tracing::warn!(%error, %parent_session_id, "ledgered btw sidecar cleanup remains durably pending");
    }
    if let Err(error) = crate::text_artifact_blob::reconcile_cleanup_intents(&ctx.db).await {
        tracing::warn!(%error, %parent_session_id, "ledgered btw text artifact cleanup remains pending");
    }
    Ok(response)
}

pub(super) async fn discard_session(
    state: &mut MutableClientState,
    ctx: &DaemonContext,
    session_id: Uuid,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        // Durable replay does not replay connection-local state. A client
        // which reissues discard on a new connection must still detach its
        // own handle before observing the cached success.
        if state
            .attached
            .as_ref()
            .is_some_and(|att| att.handle.session_id == session_id)
        {
            state.attached = None;
        }
        return Ok(cached);
    }
    // The ingress identity guard makes this worker stop exclusive with every
    // same-identity contender. The client-local detach remains post-commit.
    ctx.registry
        .interrupt_and_stop(session_id)
        .await
        .map_err(internal)?;
    let response = commit_session_remote_mutation(ctx, ledger, "discard_session", move |conn| {
        let existed = crate::db::Db::discard_ephemeral_session_conn(conn, session_id)?;
        require_mutated(existed, session_id)?;
        Ok(Response::Ack)
    })
    .await?;
    if let Err(error) = ctx.db.reconcile_delegation_sidecar_cleanup_intents().await {
        tracing::warn!(%error, %session_id, "ledgered discard sidecar cleanup remains durably pending");
    }
    if let Err(error) = crate::text_artifact_blob::reconcile_cleanup_intents(&ctx.db).await {
        tracing::warn!(%error, %session_id, "ledgered discard text artifact cleanup remains pending");
    }
    if state
        .attached
        .as_ref()
        .is_some_and(|att| att.handle.session_id == session_id)
    {
        state.attached = None;
    }
    Ok(response)
}

pub(super) async fn archive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    cascade: bool,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    require_session(ctx, session_id).await?;
    // Stop occurs only after the exclusive identity reservation, replay/hash
    // conflict lookup, and target resolution.
    stop_subtree(ctx, session_id, cascade).await?;
    commit_session_remote_mutation(ctx, ledger, "archive_session", move |conn| {
        let existed = crate::db::Db::archive_existing_session_conn(
            conn,
            session_id,
            cascade,
            chrono::Utc::now().timestamp_millis(),
        )?;
        require_mutated(existed, session_id)?;
        Ok(Response::Ack)
    })
    .await
}

pub(super) async fn unarchive_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    require_session(ctx, session_id).await?;
    commit_session_remote_mutation(ctx, ledger, "unarchive_session", move |conn| {
        let existed = crate::db::Db::unarchive_existing_session_conn(conn, session_id)?;
        require_mutated(existed, session_id)?;
        Ok(Response::Ack)
    })
    .await
}

pub(super) async fn rename_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    title: String,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    require_session(ctx, session_id).await?;
    commit_session_remote_mutation(ctx, ledger, "rename_session", move |conn| {
        let existed = crate::db::Db::rename_existing_session_conn(conn, session_id, &title)?;
        require_mutated(existed, session_id)?;
        Ok(Response::Ack)
    })
    .await
}

pub(super) async fn record_session_note(
    ctx: &DaemonContext,
    session_id: Uuid,
    text: String,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    let data_json =
        serde_json::to_string(&serde_json::json!({ "text": text })).map_err(internal)?;
    commit_session_remote_mutation(ctx, ledger, "record_session_note", move |conn| {
        let agent = crate::db::Db::get_session_conn(conn, session_id)?
            .ok_or_else(|| UnknownRemoteSession(session_id))?
            .active_agent;
        let seq = crate::db::Db::insert_session_event_json_conn(
            conn,
            session_id,
            crate::db::session_log::SessionEventKind::UserNote,
            Some(&agent),
            None,
            crate::db::session_log::SessionEventContext::default(),
            chrono::Utc::now().timestamp_millis(),
            &data_json,
        )?;
        Ok(Response::NoteRecorded { seq })
    })
    .await
}

pub(super) async fn delete_session(
    ctx: &DaemonContext,
    session_id: Uuid,
    ledger: &RemoteSessionLedger,
) -> Result<Response, ErrorPayload> {
    if let Some(cached) = ledger.committed_replay(ctx).await? {
        return Ok(cached);
    }
    let session = require_session(ctx, session_id).await?;
    if session.ended_at_unix_ms.is_none() {
        return Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: format!("session {session_id} is active; end it before deleting"),
        });
    }
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
    super::sessions::prepare_session_deletion(ctx, session_id).await?;
    for scratch_dir in scratch_dirs {
        super::sessions::remove_session_scratch(&scratch_dir).map_err(internal)?;
    }
    for result_blob_dir in result_blob_dirs {
        super::sessions::remove_session_scratch(&result_blob_dir).map_err(internal)?;
        match std::fs::symlink_metadata(&result_blob_dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => {
                return Err(internal(anyhow::anyhow!(
                    "session deletion left result blobs at `{}`",
                    result_blob_dir.display()
                )));
            }
            Err(error) => return Err(internal(error.into())),
        }
    }
    let now_wall_ms = super::run_invocation::wall_ms_now();
    let response = commit_session_remote_mutation(ctx, ledger, "delete_session", move |conn| {
        crate::db::Db::terminalize_session_run_invocations_conn(conn, session_id, now_wall_ms)?;
        let existed = crate::db::Db::delete_existing_session_row_conn(conn, session_id)?;
        require_mutated(existed, session_id)?;
        Ok(Response::Ack)
    })
    .await?;
    if let Err(error) = ctx.db.reconcile_delegation_sidecar_cleanup_intents().await {
        tracing::warn!(%error, %session_id, "post-commit delegation sidecar cleanup failed; ledgered delete stands");
    }
    if let Err(error) = crate::text_artifact_blob::reconcile_cleanup_intents(&ctx.db).await {
        tracing::warn!(%error, %session_id, "post-commit text artifact cleanup failed; ledgered delete stands");
    }
    Ok(response)
}
