//! LOCAL daemon authority for persistent image-sidecar grants.
//!
//! The real attachment/provider handoff is currently unavailable. This module
//! consequently records no invocation audit rows and rejects grant creation.
//! The settings projection still comes from the daemon's effective config so
//! selection controls never rely on a client-invented catalog.

use std::time::{SystemTime, UNIX_EPOCH};

use cockpit_config::config::media_budget::MediaResourcePolicy;
use cockpit_config::config::model_policy::EffectiveCapabilitySource;
use cockpit_config::config::providers::{CapabilityStatus, ProvidersConfig};
use cockpit_db::db::image_sidecar::ImageSidecarGrantRow;
use cockpit_proto::image_sidecar_authority::{
    ImageSidecarApprovalModeV1, ImageSidecarAuthoritySnapshotV1, ImageSidecarGrantMutationV1,
    ImageSidecarGrantScopeV1, ImageSidecarGrantV1, ImageSidecarInvocationCapSourceV1,
    ImageSidecarModelOptionV1, ImageSidecarPrimaryV1, ImageSidecarResolutionV1,
};
use cockpit_proto::{ErrorCode, ErrorPayload, Response};

use crate::image_sidecar::{
    ConnectedLocationClass, CredentialFingerprint, CredentialFingerprintDigest, SidecarResolver,
    SidecarSelectionConfig,
};

use super::server::DaemonContext;

const PIPELINE_UNAVAILABLE: &str = "provider_transport_unavailable";

pub async fn snapshot(
    ctx: &DaemonContext,
    project_root: String,
    config_generation: u64,
    selection_id: String,
    session_id: String,
    attached_project_root: std::path::PathBuf,
    approval_mode: cockpit_config::config::extended::ApprovalMode,
    expected_daemon_instance_id: Option<String>,
    expected_session_id: Option<String>,
    primary_provider: Option<String>,
    primary_model: Option<String>,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    let daemon_instance_id = crate::daemon::server::inventory::daemon_instance_id().to_owned();
    // A read is the rehydration path after reconnect/restart, so it returns
    // the daemon's current identity even when the caller's last projection
    // belonged to an older boot. Mutations below reject that mismatch.
    let _ = (expected_daemon_instance_id, expected_session_id);
    let project_id = bound_project_id(&project_root, &attached_project_root)?;
    let (models, resolution, cap) = configured_projection(
        ctx,
        &project_id,
        config_generation,
        primary_provider.as_deref(),
        primary_model.as_deref(),
    )
    .await?;
    let snapshot = ctx
        .db
        .image_sidecar_snapshot(project_id.clone())
        .await
        .map_err(internal)?;
    Ok(Response::ImageSidecarAuthoritySnapshot(
        ImageSidecarAuthoritySnapshotV1 {
            schema_version: 1,
            daemon_instance_id,
            session_id,
            project_id,
            config_generation,
            selection_id,
            entity_version: snapshot.entity_version,
            approval_mode: match approval_mode {
                cockpit_config::config::extended::ApprovalMode::Yolo => {
                    ImageSidecarApprovalModeV1::Yolo
                }
                cockpit_config::config::extended::ApprovalMode::Manual
                | cockpit_config::config::extended::ApprovalMode::Auto => {
                    ImageSidecarApprovalModeV1::Ask
                }
            },
            central_invocation_cap: cap.value,
            central_invocation_cap_source: match cap.provenance {
                crate::image_sidecar::SidecarInvocationCapProvenance::CompiledCeiling => {
                    ImageSidecarInvocationCapSourceV1::CompiledCeiling
                }
                crate::image_sidecar::SidecarInvocationCapProvenance::Configured => {
                    ImageSidecarInvocationCapSourceV1::Configured
                }
                crate::image_sidecar::SidecarInvocationCapProvenance::Profile => {
                    ImageSidecarInvocationCapSourceV1::Profile
                }
                crate::image_sidecar::SidecarInvocationCapProvenance::Adapter => {
                    ImageSidecarInvocationCapSourceV1::Adapter
                }
                crate::image_sidecar::SidecarInvocationCapProvenance::Request => {
                    ImageSidecarInvocationCapSourceV1::Request
                }
            },
            central_invocation_cap_hard_ceiling:
                cockpit_config::config::media_budget::MediaResourceLimits::hard_ceilings()
                    .sidecar_invocations_per_session,
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
    authority_session_id: String,
    attached_project_root: std::path::PathBuf,
    expected_daemon_instance_id: Option<String>,
    expected_session_id: Option<String>,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    let _project_id = bound_project_id(&project_root, &attached_project_root)?;
    ensure_identity(
        crate::daemon::server::inventory::daemon_instance_id(),
        &authority_session_id,
        expected_daemon_instance_id.as_deref(),
        expected_session_id.as_deref(),
    )?;
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
    primary_provider: Option<&str>,
    primary_model: Option<&str>,
) -> Result<
    (
        Vec<ImageSidecarModelOptionV1>,
        ImageSidecarResolutionV1,
        crate::image_sidecar::SidecarInvocationCap,
    ),
    ErrorPayload,
> {
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
        // Catalog discovery is not a user configuration grant. Preserve a
        // configured value elsewhere in the form, but never offer a fetched
        // `manual = false` row as a new sidecar destination.
        .filter(|(_, model)| model.manual)
        .map(|(provider, model)| {
            let capability = providers.resolve_effective_model_capabilities(
                provider,
                &model.id,
                config_generation,
            );
            ImageSidecarModelOptionV1 {
                provider: provider.clone(),
                model: model.id.clone(),
                configured: model.manual,
                image_capable: capability.image_input.status
                    == cockpit_config::config::providers::CapabilityStatus::Supported,
                // The resolved capability is stamped by the same config
                // generation that fences this projection. Do not substitute a
                // provider catalog timestamp for the model capability source.
                fresh: capability.image_input.source_generation == config_generation,
            }
        })
        .collect::<Vec<_>>();
    let cap = crate::image_sidecar::SidecarInvocationCap::from_media_policy(
        extended.media_resources.as_ref(),
    );
    let resolution = project_resolution(
        &providers,
        &extended.image_sidecar,
        extended.media_resources.as_ref(),
        config_generation,
        primary_provider,
        primary_model,
    );
    Ok((models, resolution, cap))
}

/// Project [`SidecarResolver`] output onto the wire type. The TUI consumes
/// this as-is and must not re-run matching.
fn project_resolution(
    providers: &ProvidersConfig,
    config: &SidecarSelectionConfig,
    media_policy: &MediaResourcePolicy,
    config_generation: u64,
    primary_provider: Option<&str>,
    primary_model: Option<&str>,
) -> ImageSidecarResolutionV1 {
    let Some((provider, model)) = primary_provider.zip(primary_model) else {
        return ImageSidecarResolutionV1 {
            provider: None,
            model: None,
            origin: None,
            available: false,
            reason: "missing_selection".into(),
            grant_candidate_id: None,
            primary: None,
            matched_source: "missing_selection".into(),
            capability_source: "none".into(),
            capability_freshness: "unavailable".into(),
            mode: config.mode.as_str().into(),
            fallback_outcome: None,
        };
    };
    let primary_caps =
        providers.resolve_effective_model_capabilities(provider, model, config_generation);
    let primary_image_capable = primary_caps.image_input.status == CapabilityStatus::Supported
        && primary_caps.image_input.source_generation == config_generation;
    let outcome = SidecarResolver::new(providers, media_policy, config, config_generation).resolve(
        provider,
        model,
        primary_image_capable,
    );
    let selected = outcome.selected.as_ref();
    let (capability_source, capability_freshness) = match selected {
        Some(selected) => (
            capability_source_label(selected.capability_evidence.source).into(),
            if selected.capability_evidence.source_generation == config_generation {
                "fresh"
            } else {
                "stale"
            }
            .into(),
        ),
        None => ("none".into(), "unavailable".into()),
    };
    ImageSidecarResolutionV1 {
        provider: selected.map(|selected| selected.provider.clone()),
        model: selected.map(|selected| selected.model.clone()),
        origin: selected.map(|selected| origin_display(&selected.endpoint_origin)),
        available: false,
        reason: outcome.reason.as_str().into(),
        grant_candidate_id: None,
        primary: Some(primary_trace(providers, provider, model)),
        matched_source: selected
            .map(|selected| selected.selection_source.as_str().to_string())
            .unwrap_or_else(|| outcome.reason.as_str().into()),
        capability_source,
        capability_freshness,
        mode: config.mode.as_str().into(),
        fallback_outcome: outcome
            .fallback_warning
            .map(|warning| warning.reason.as_str().to_string()),
    }
}

fn primary_trace(
    providers: &ProvidersConfig,
    provider: &str,
    model: &str,
) -> ImageSidecarPrimaryV1 {
    let trust = providers.resolve_trust(provider, model);
    let location =
        ConnectedLocationClass::from_model_location(providers.resolve_location(provider, model));
    let material = match providers
        .providers
        .get(provider)
        .and_then(|entry| entry.credential_ref.as_deref())
    {
        Some(cred) => format!("{provider}:{model}:{cred}"),
        None => format!("{provider}:{model}:no-credential-ref"),
    };
    ImageSidecarPrimaryV1 {
        provider: provider.into(),
        model: model.into(),
        trust: if trust.is_trusted() {
            "trusted"
        } else {
            "untrusted"
        }
        .into(),
        location: location.as_str().into(),
        credential_fingerprint: CredentialFingerprintDigest::from_fingerprint(
            &CredentialFingerprint::from_identity(&material),
        )
        .as_str()
        .to_string(),
    }
}

fn origin_display(origin: &crate::image_sidecar::NormalizedEndpointOrigin) -> String {
    match origin.port {
        Some(port) => format!("{}://{}:{port}", origin.scheme, origin.host),
        None => format!("{}://{}", origin.scheme, origin.host),
    }
}

fn capability_source_label(source: EffectiveCapabilitySource) -> &'static str {
    match source {
        EffectiveCapabilitySource::Override => "override",
        EffectiveCapabilitySource::Model => "model",
        EffectiveCapabilitySource::Provider => "provider",
        EffectiveCapabilitySource::Legacy => "legacy",
        EffectiveCapabilitySource::None => "none",
    }
}

pub async fn revoke_grant(
    ctx: &DaemonContext,
    project_root: String,
    config_generation: u64,
    selection_id: String,
    grant_id: String,
    expected_version: u64,
    session_id: String,
    attached_project_root: std::path::PathBuf,
    expected_daemon_instance_id: Option<String>,
    expected_session_id: Option<String>,
) -> Result<Response, ErrorPayload> {
    ensure_current_generation(config_generation)?;
    let daemon_instance_id = crate::daemon::server::inventory::daemon_instance_id().to_owned();
    ensure_identity(
        &daemon_instance_id,
        &session_id,
        expected_daemon_instance_id.as_deref(),
        expected_session_id.as_deref(),
    )?;
    let project_id = bound_project_id(&project_root, &attached_project_root)?;
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
            daemon_instance_id,
            session_id,
            config_generation,
            selection_id,
            entity_version,
            grant: grant_projection(&grant),
        },
    ))
}

fn ensure_identity(
    daemon_instance_id: &str,
    session_id: &str,
    expected_daemon_instance_id: Option<&str>,
    expected_session_id: Option<&str>,
) -> Result<(), ErrorPayload> {
    if expected_daemon_instance_id.is_some_and(|expected| expected != daemon_instance_id)
        || expected_session_id.is_some_and(|expected| expected != session_id)
    {
        return Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "image-sidecar authority identity changed; reload before continuing".into(),
        });
    }
    Ok(())
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

fn bound_project_id(
    requested_project_root: &str,
    attached_project_root: &std::path::Path,
) -> Result<String, ErrorPayload> {
    let requested = canonical_project_id(requested_project_root)?;
    let attached =
        crate::daemon::fs_api::canonical_project_root(&attached_project_root.to_string_lossy())?
            .to_string_lossy()
            .into_owned();
    ensure_attached_project(&requested, &attached)?;
    Ok(attached)
}

fn ensure_attached_project(requested: &str, attached: &str) -> Result<(), ErrorPayload> {
    if requested == attached {
        Ok(())
    } else {
        Err(ErrorPayload {
            code: ErrorCode::Conflict,
            message: "image-sidecar authority project does not match attached session; reload before continuing".into(),
        })
    }
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
    use super::{ensure_attached_project, project_resolution, safe_destination_origin};
    use crate::config::config::media_budget::MediaResourcePolicy;
    use crate::config::config::providers::{
        CapabilityStatus, ModelEntry, ModelLocation, ModelTrust, ProviderEntry, ProvidersConfig,
    };
    use crate::image_sidecar::{SidecarMode, SidecarProviderModel, SidecarSelectionConfig};

    fn image_model(id: &str) -> ModelEntry {
        let mut model = ModelEntry {
            id: id.to_string(),
            ..Default::default()
        };
        model.capabilities.image_input = CapabilityStatus::Supported;
        model
    }

    fn providers() -> ProvidersConfig {
        let mut providers = ProvidersConfig::default();
        providers.providers.insert(
            "trusted".into(),
            ProviderEntry {
                url: "https://trusted.example.test/v1?sig=secret".into(),
                trust: Some(ModelTrust::Trusted),
                location: Some(ModelLocation::Local),
                credential_ref: Some("trusted-cred".into()),
                models: vec![image_model("primary"), image_model("sidecar-trusted")],
                ..Default::default()
            },
        );
        providers.providers.insert(
            "untrusted".into(),
            ProviderEntry {
                url: "https://untrusted.example.test/v1".into(),
                trust: Some(ModelTrust::Untrusted),
                location: Some(ModelLocation::Remote),
                credential_ref: Some("untrusted-cred".into()),
                models: vec![image_model("primary"), image_model("sidecar-untrusted")],
                ..Default::default()
            },
        );
        providers
    }

    fn pair(provider: &str, model: &str) -> SidecarProviderModel {
        SidecarProviderModel {
            provider: provider.into(),
            model: model.into(),
        }
    }

    #[test]
    fn authority_projection_never_echoes_bearer_url_components() {
        assert_eq!(
            safe_destination_origin("https://user:token@example.test/private?sig=secret#fragment"),
            "https://example.test"
        );
        assert_eq!(safe_destination_origin("not a URL"), "invalid_destination");
    }

    #[test]
    fn authority_rejects_a_project_other_than_the_attached_session() {
        let error = ensure_attached_project("/project/a", "/project/b").unwrap_err();
        assert_eq!(error.code, cockpit_proto::ErrorCode::Conflict);
        assert!(error.message.contains("does not match attached session"));
    }

    #[test]
    fn resolver_projection_never_mode_does_not_select_a_sidecar() {
        let config = SidecarSelectionConfig {
            mode: SidecarMode::Never,
            trusted_primary_default: Some(pair("trusted", "sidecar-trusted")),
            untrusted_primary_default: Some(pair("untrusted", "sidecar-untrusted")),
            per_primary_override: None,
        };
        let resolution = project_resolution(
            &providers(),
            &config,
            &MediaResourcePolicy::default(),
            1,
            Some("trusted"),
            Some("primary"),
        );
        assert_eq!(resolution.reason, "never_mode");
        assert!(resolution.provider.is_none());
        assert!(resolution.model.is_none());
        assert_eq!(
            resolution
                .primary
                .as_ref()
                .map(|primary| primary.trust.as_str()),
            Some("trusted")
        );
        assert_eq!(resolution.matched_source, "never_mode");
        assert_eq!(resolution.mode, "never");
        assert!(resolution.fallback_outcome.is_none());
        assert!(!resolution.available);
    }

    #[test]
    fn resolver_projection_uses_untrusted_default_for_an_untrusted_primary() {
        let config = SidecarSelectionConfig {
            mode: SidecarMode::Always,
            trusted_primary_default: Some(pair("trusted", "sidecar-trusted")),
            untrusted_primary_default: Some(pair("untrusted", "sidecar-untrusted")),
            per_primary_override: None,
        };
        let resolution = project_resolution(
            &providers(),
            &config,
            &MediaResourcePolicy::default(),
            1,
            Some("untrusted"),
            Some("primary"),
        );
        assert_eq!(resolution.provider.as_deref(), Some("untrusted"));
        assert_eq!(resolution.model.as_deref(), Some("sidecar-untrusted"));
        assert_eq!(
            resolution
                .primary
                .as_ref()
                .map(|primary| primary.trust.as_str()),
            Some("untrusted")
        );
        assert_eq!(resolution.matched_source, "trust_class_default");
        assert_eq!(
            resolution.origin.as_deref(),
            Some("https://untrusted.example.test")
        );
        assert!(
            !resolution
                .origin
                .as_deref()
                .is_some_and(|origin| origin.contains('?'))
        );
        assert_eq!(resolution.reason, "selected");
        assert_eq!(resolution.mode, "always");
    }

    #[test]
    fn resolver_projection_without_a_primary_does_not_invent_a_trusted_default() {
        let config = SidecarSelectionConfig {
            mode: SidecarMode::Always,
            trusted_primary_default: Some(pair("trusted", "sidecar-trusted")),
            untrusted_primary_default: Some(pair("untrusted", "sidecar-untrusted")),
            per_primary_override: None,
        };
        let resolution = project_resolution(
            &providers(),
            &config,
            &MediaResourcePolicy::default(),
            1,
            None,
            None,
        );
        assert!(resolution.provider.is_none());
        assert!(resolution.primary.is_none());
        assert_eq!(resolution.reason, "missing_selection");
        assert_eq!(resolution.matched_source, "missing_selection");
    }
}
