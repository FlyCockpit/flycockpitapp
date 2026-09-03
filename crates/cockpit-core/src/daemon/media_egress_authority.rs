//! Daemon authority for session-scoped transcription media-egress verdicts.

use std::path::PathBuf;

use cockpit_proto::media_egress_authority::MediaEgressVerdictV1;
use cockpit_proto::{ErrorCode, ErrorPayload, Response};
use uuid::Uuid;

use crate::approval::store::GrantStore;
use crate::daemon::server::DaemonContext;
use crate::daemon::session_worker::SessionConfigHandle;

pub async fn list_verdicts(
    ctx: &DaemonContext,
    session_id: Uuid,
) -> Result<Response, ErrorPayload> {
    let store = grant_store(ctx, session_id).await?;
    let rows = store
        .list_media_egress_verdicts()
        .await
        .map_err(|error| internal(error.to_string()))?;
    Ok(Response::MediaEgressVerdicts {
        session_id,
        verdicts: rows
            .into_iter()
            .map(|row| MediaEgressVerdictV1 {
                grant_id: row.grant_id,
                purpose: row.purpose,
                request_digest: row.request_digest,
                verdict: row.verdict,
                granted_at_unix_ms: u64::try_from(row.granted_at_unix_ms).unwrap_or(0),
            })
            .collect(),
    })
}

pub async fn revoke_verdict(
    ctx: &DaemonContext,
    session_id: Uuid,
    purpose: String,
    request_digest: String,
) -> Result<Response, ErrorPayload> {
    let store = grant_store(ctx, session_id).await?;
    store
        .revoke_media_egress_verdict(&purpose, &request_digest)
        .await
        .map_err(|error| internal(error.to_string()))?;
    Ok(Response::Ack)
}

async fn grant_store(ctx: &DaemonContext, session_id: Uuid) -> Result<GrantStore, ErrorPayload> {
    let session = ctx
        .db
        .get_session(session_id)
        .await
        .map_err(|error| internal(error.to_string()))?
        .ok_or_else(|| ErrorPayload {
            code: ErrorCode::UnknownSession,
            message: format!("unknown session {session_id}"),
        })?;
    Ok(GrantStore::new(
        ctx.db.clone(),
        session_id,
        PathBuf::from(session.project_root),
        SessionConfigHandle::detached_default(),
    ))
}

fn internal(message: String) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message,
    }
}
