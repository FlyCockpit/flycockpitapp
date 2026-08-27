//! LOCAL daemon authority for persistent image-sidecar grants.
//!
//! The real attachment/provider handoff is currently unavailable. This module
//! consequently records no invocation audit rows and rejects grant creation.
//! The settings projection still comes from the daemon's effective config so
//! selection controls never rely on a client-invented catalog.

use std::time::{SystemTime, UNIX_EPOCH};

use cockpit_db::db::image_sidecar::ImageSidecarGrantRow;
use cockpit_proto::image_sidecar_authority::{
    ImageSidecarAuthoritySnapshotV1, ImageSidecarGrantMutationV1, ImageSidecarGrantScopeV1,
    ImageSidecarGrantV1, ImageSidecarModelOptionV1, ImageSidecarResolutionV1,
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
    let (models, resolution) = configured_projection(ctx, &project_root, config_generation).await?;
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
            models,
            resolution,
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
    grant_candidate_id: String,
    purpose: String,
    scope: ImageSidecarGrantScopeV1,
    session_id: Option<String>,
    invocation_id: Option<String>,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    // There is no production handoff that can consume this authority yet. Do
    // not turn an opaque candidate into a standing grant whose destination can
    // never be revalidated. In particular, no caller-provided URL reaches the
    // ledger or response path.
    let _ = (
        ctx,
        project_root,
        selection_id,
        grant_candidate_id,
        purpose,
        scope,
        session_id,
        invocation_id,
    );
    Err(ErrorPayload {
        code: ErrorCode::BadRequest,
        message: PIPELINE_UNAVAILABLE.into(),
    })
}

async fn configured_projection(
    ctx: &DaemonContext,
    project_root: &str,
    config_generation: u64,
) -> Result<(Vec<ImageSidecarModelOptionV1>, ImageSidecarResolutionV1), ErrorPayload> {
    let cwd = std::path::PathBuf::from(project_root);
    let trust = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
        .await
        .map_err(internal)?;
    let (providers, extended) = ctx
        .config_source()
        .load_effective_for_daemon(&cwd, &trust)
        .map_err(|error| ErrorPayload {
            code: ErrorCode::BadRequest,
            message: format!("image-sidecar configuration unavailable: {error}"),
        })?;
    // The effective config was read after the first fence, so check again
    // before minting a projection that a settings pane may use for mutation.
    ensure_current_generation(config_generation)?;
    let models = providers
        .providers
        .iter()
        .flat_map(|(provider, entry)| entry.models.iter().map(move |model| (provider, model)))
        .map(|(provider, model)| {
            let capability = providers.resolve_effective_model_capabilities(
                provider,
                &model.id,
                config_generation,
            );
            ImageSidecarModelOptionV1 {
                provider: provider.clone(),
                model: model.id.clone(),
                image_capable: capability.image_input.status
                    == cockpit_config::config::providers::CapabilityStatus::Supported,
                // A configured manual model is authoritative; fetched catalog
                // entries are fresh only when their provider has refresh evidence.
                fresh: model.manual
                    || providers
                        .providers
                        .get(provider)
                        .is_some_and(|entry| entry.models_fetched_at.is_some()),
            }
        })
        .collect::<Vec<_>>();
    let selected = extended
        .image_sidecar
        .per_primary_override
        .as_ref()
        .or(extended.image_sidecar.trusted_primary_default.as_ref())
        .or(extended.image_sidecar.untrusted_primary_default.as_ref());
    let (provider, model, origin, selected_is_configured) = selected
        .map(|selected| {
            let origin = providers
                .providers
                .get(&selected.provider)
                .and_then(|entry| crate::image_sidecar::NormalizedEndpointOrigin::parse(&entry.url))
                .map(|origin| match origin.port {
                    Some(port) => format!("{}://{}:{port}", origin.scheme, origin.host),
                    None => format!("{}://{}", origin.scheme, origin.host),
                });
            let configured = models.iter().any(|candidate| {
                candidate.provider == selected.provider
                    && candidate.model == selected.model
                    && candidate.image_capable
                    && candidate.fresh
            });
            (
                Some(selected.provider.clone()),
                Some(selected.model.clone()),
                origin,
                configured,
            )
        })
        .unwrap_or((None, None, None, false));
    Ok((
        models,
        ImageSidecarResolutionV1 {
            provider,
            model,
            origin,
            available: false,
            reason: if selected_is_configured {
                PIPELINE_UNAVAILABLE.into()
            } else {
                "missing_selection".into()
            },
            grant_candidate_id: None,
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
        // Historical rows are defensively normalized on every read. New rows
        // can only be created from daemon candidates, but an old bearer URL
        // must never be echoed through this safe projection.
        destination: safe_destination_origin(&row.destination),
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

fn safe_destination_origin(raw: &str) -> String {
    crate::image_sidecar::NormalizedEndpointOrigin::parse(raw)
        .map(|origin| match origin.port {
            Some(port) => format!("{}://{}:{port}", origin.scheme, origin.host),
            None => format!("{}://{}", origin.scheme, origin.host),
        })
        .unwrap_or_else(|| "invalid_destination".into())
}

fn internal(error: anyhow::Error) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Internal,
        message: format!("image-sidecar authority failed: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::safe_destination_origin;

    #[test]
    fn authority_projection_never_echoes_bearer_url_components() {
        assert_eq!(
            safe_destination_origin("https://user:token@example.test/private?sig=secret#fragment"),
            "https://example.test"
        );
        assert_eq!(safe_destination_origin("not a URL"), "invalid_destination");
    }
}
