//! LOCAL daemon authority for persistent image-sidecar grants.
//!
//! The real attachment/provider handoff is currently unavailable. This module
//! consequently records no invocation audit rows and reports health as
//! unavailable, while still making creation and optimistic revocation durable.

use std::time::{SystemTime, UNIX_EPOCH};

use cockpit_db::db::image_sidecar::{ImageSidecarGrantCreate, ImageSidecarGrantRow};
use cockpit_proto::image_sidecar_authority::{
    ImageSidecarAuthoritySnapshotV1, ImageSidecarGrantMutationV1, ImageSidecarGrantScopeV1,
    ImageSidecarGrantV1,
};
use cockpit_proto::{ErrorCode, ErrorPayload, Response};

use super::server::DaemonContext;

const PIPELINE_UNAVAILABLE: &str = "provider_transport_unavailable";

pub async fn snapshot(
    ctx: &DaemonContext,
    project_root: String,
    config_generation: u64,
    selection_id: String,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    let project_id = canonical_project_id(&project_root)?;
    let snapshot = ctx
        .db
        .image_sidecar_snapshot(project_id.clone())
        .await
        .map_err(internal)?;
    Ok(Response::ImageSidecarAuthoritySnapshot(
        ImageSidecarAuthoritySnapshotV1 {
            schema_version: 1,
            project_id,
            config_generation,
            selection_id,
            entity_version: snapshot.entity_version,
            pipeline_available: false,
            health_reason: PIPELINE_UNAVAILABLE.into(),
            grants: snapshot.grants.iter().map(grant_projection).collect(),
            invocations: Vec::new(),
        },
    ))
}

pub async fn create_grant(
    ctx: &DaemonContext,
    project_root: String,
    config_generation: u64,
    selection_id: String,
    destination: String,
    purpose: String,
    scope: ImageSidecarGrantScopeV1,
    session_id: Option<String>,
    invocation_id: Option<String>,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    let project_id = canonical_project_id(&project_root)?;
    let (grant, entity_version) = ctx
        .db
        .create_image_sidecar_grant(ImageSidecarGrantCreate {
            grant_id: uuid::Uuid::new_v4().to_string(),
            project_id,
            session_id,
            invocation_id,
            destination,
            purpose,
            scope: scope.as_str().into(),
            created_at_unix_ms: now_ms()?,
        })
        .await
        .map_err(internal)?;
    Ok(Response::ImageSidecarGrantMutated(
        ImageSidecarGrantMutationV1 {
            schema_version: 1,
            config_generation,
            selection_id,
            entity_version,
            grant: grant_projection(&grant),
        },
    ))
}

pub async fn revoke_grant(
    ctx: &DaemonContext,
    project_root: String,
    config_generation: u64,
    selection_id: String,
    grant_id: String,
    expected_version: u64,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    let project_id = canonical_project_id(&project_root)?;
    let Some((grant, entity_version)) = ctx
        .db
        .revoke_image_sidecar_grant(project_id, grant_id, expected_version, now_ms()?)
        .await
        .map_err(internal)?
    else {
        return Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "image-sidecar grant changed or is no longer active; refresh before revoking"
                .into(),
        });
    };
    Ok(Response::ImageSidecarGrantMutated(
        ImageSidecarGrantMutationV1 {
            schema_version: 1,
            config_generation,
            selection_id,
            entity_version,
            grant: grant_projection(&grant),
        },
    ))
}

fn ensure_current_generation(expected: u64) -> Result<(), ErrorPayload> {
    let actual = crate::daemon::server::inventory::current_config_generation();
    if expected == actual {
        Ok(())
    } else {
        Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "image-sidecar settings snapshot is stale; reload before changing grants"
                .into(),
        })
    }
}

fn canonical_project_id(project_root: &str) -> Result<String, ErrorPayload> {
    crate::daemon::fs_api::canonical_project_root(project_root)
        .map(|path| path.to_string_lossy().into_owned())
}

fn now_ms() -> Result<i64, ErrorPayload> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ErrorPayload {
            code: ErrorCode::Internal,
            message: "system clock is before Unix epoch".into(),
        })?;
    i64::try_from(duration.as_millis()).map_err(|_| ErrorPayload {
        code: ErrorCode::Internal,
        message: "system clock milliseconds exceed SQLite range".into(),
    })
}

fn grant_projection(row: &ImageSidecarGrantRow) -> ImageSidecarGrantV1 {
    ImageSidecarGrantV1 {
        grant_id: row.grant_id.clone(),
        version: row.version,
        project_id: row.project_id.clone(),
        destination: row.destination.clone(),
        purpose: row.purpose.clone(),
        scope: match row.scope.as_str() {
            "once" => ImageSidecarGrantScopeV1::Once,
            "session" => ImageSidecarGrantScopeV1::Session,
            "project" => ImageSidecarGrantScopeV1::Project,
            _ => unreachable!("database CHECK constraint owns sidecar grant scope"),
        },
        session_id: row.session_id.clone(),
        invocation_id: row.invocation_id.clone(),
        created_at_unix_ms: row.created_at_unix_ms,
        last_used_at_unix_ms: row.last_used_at_unix_ms,
        revoked_at_unix_ms: row.revoked_at_unix_ms,
        consumed_at_unix_ms: row.consumed_at_unix_ms,
    }
}

fn internal(error: anyhow::Error) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("image-sidecar authority failed: {error}"),
    }
}
