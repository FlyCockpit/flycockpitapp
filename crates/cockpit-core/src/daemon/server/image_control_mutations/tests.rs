//! Behavioral proofs for the LOCAL image-config mutation edit funnel.
//!
//! These drive the pure `apply_edit`/`project_changes` core (the exact logic the
//! async handler runs after its trust-gated load and generation CAS), with
//! distinguishing inputs where a broken implementation gives a different answer:
//! an edit that would violate a registry invariant must FAIL CLOSED (no config),
//! a duplicate create must be rejected (idempotency), `set_default` must emit
//! BOTH the prior and the new default, and the emitted change set / event must
//! carry NO secret even when the edit introduces one.

use cockpit_config::config::image_generation::{
    IMAGE_GENERATION_ROUTE_PROFILE_VERSION, ImageAdapterKind, ImageCapabilityEvidence,
    ImageDimensionDescriptor, ImageDimensionRequestPolicy, ImageEndpoint, ImageFormat,
    ImageGenerationConfig, ImageGenerationTarget, ImageLocationClass, ImagePrice,
    ImageTargetIdentity, ReferenceImageSupport,
};
use cockpit_config::config::providers::CapabilityStatus;

use super::*;

const ENDPOINT_ID: &str = "openai-main";

fn endpoint(id: &str, enabled: bool, credential: Option<&str>) -> ImageEndpoint {
    ImageEndpoint {
        id: id.to_string(),
        adapter: ImageAdapterKind::OpenaiImages,
        origin: "https://api.openai.com/".to_string(),
        path_prefix: None,
        credential_ref: credential.map(str::to_string),
        headers: Vec::new(),
        allow_insecure_transport: false,
        location: ImageLocationClass::PublicCloud,
        enabled,
        route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
        exclusive_server: false,
    }
}

fn hosted_target(
    id: &str,
    endpoint_id: &str,
    enabled: bool,
    is_default: bool,
) -> ImageGenerationTarget {
    ImageGenerationTarget {
        id: id.to_string(),
        display_name: None,
        endpoint_id: endpoint_id.to_string(),
        identity: ImageTargetIdentity::HostedModel {
            model: "gpt-image-1".to_string(),
        },
        enabled,
        is_default,
        formats: vec![ImageFormat::Png],
        reference_support: ReferenceImageSupport::Unsupported,
        max_reference_images: 0,
        max_samples: 1,
        max_outputs: 1,
        dimensions: ImageDimensionDescriptor::ProviderDefault,
        dimension_policy: ImageDimensionRequestPolicy::ProviderDefault,
        parameters: Vec::new(),
        openrouter_routing: None,
        generation_capability: ImageCapabilityEvidence::new(CapabilityStatus::Unknown, None)
            .unwrap(),
        price: ImagePrice::Unknown,
    }
}

fn config(
    endpoints: Vec<ImageEndpoint>,
    targets: Vec<ImageGenerationTarget>,
) -> ImageGenerationConfig {
    ImageGenerationConfig::new(endpoints, targets, Vec::new(), Vec::new())
        .expect("valid base config")
}

fn base() -> ImageGenerationConfig {
    config(
        vec![endpoint(ENDPOINT_ID, true, Some("openai-key"))],
        vec![hosted_target("gpt-image", ENDPOINT_ID, true, true)],
    )
}

#[test]
fn endpoint_create_appends_and_upserts() {
    let (cfg, changes) = apply_edit(
        &base(),
        Edit::EndpointCreate(serde_json::to_string(&endpoint("second", false, None)).unwrap()),
    )
    .expect("create ok");
    assert_eq!(cfg.endpoints().len(), 2);
    assert!(cfg.endpoints().iter().any(|e| e.id == "second"));
    assert_eq!(changes.len(), 1);
    assert!(matches!(&changes[0], PendingChange::EndpointUpsert(id) if id == "second"));
}

#[test]
fn endpoint_create_duplicate_id_is_rejected() {
    // Idempotency: a repeated create with an existing id never double-applies —
    // `::new`'s unique-id invariant fails closed.
    let err = apply_edit(
        &base(),
        Edit::EndpointCreate(serde_json::to_string(&endpoint(ENDPOINT_ID, false, None)).unwrap()),
    )
    .expect_err("duplicate rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn target_create_referencing_missing_endpoint_fails_closed() {
    // Distinguishing input: an ENABLED target pointing at a non-existent
    // endpoint. `::new` must reject it, so no invalid config is produced.
    let orphan = hosted_target("t-orphan", "ghost-endpoint", true, false);
    let err = apply_edit(
        &base(),
        Edit::TargetCreate(serde_json::to_string(&orphan).unwrap()),
    )
    .expect_err("dangling target rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn endpoint_delete_referenced_by_enabled_target_fails_closed() {
    // Deleting the endpoint the enabled default target depends on must fail
    // closed rather than persist a registry with a dangling reference.
    let err = apply_edit(&base(), Edit::EndpointDelete(ENDPOINT_ID.to_string()))
        .expect_err("referenced endpoint delete rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn endpoint_delete_missing_is_not_found() {
    let err = apply_edit(&base(), Edit::EndpointDelete("nope".to_string()))
        .expect_err("missing endpoint");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("not found"));
}

#[test]
fn set_default_switches_and_emits_prior_and_new_default() {
    let cfg = config(
        vec![endpoint(ENDPOINT_ID, true, Some("openai-key"))],
        vec![
            hosted_target("t1", ENDPOINT_ID, true, true),
            hosted_target("t2", ENDPOINT_ID, true, false),
        ],
    );
    let (next, changes) =
        apply_edit(&cfg, Edit::TargetSetDefault("t2".to_string())).expect("set default ok");
    // Exactly one enabled default, and it is t2.
    let defaults: Vec<&str> = next
        .targets()
        .iter()
        .filter(|t| t.is_default)
        .map(|t| t.id.as_str())
        .collect();
    assert_eq!(defaults, vec!["t2"]);
    // The projected change set carries BOTH the prior (t1, now cleared) and the
    // new (t2) default — a naive "only the new default" implementation would
    // emit one — in the contract's deterministic (kind, id) order. Assert the
    // ACTUAL order project_changes produces (no test-side sort that would mask a
    // non-deterministic delta).
    let projected = project_changes(&next, &changes, "1");
    let ids: Vec<&str> = projected
        .iter()
        .map(|c| match c {
            ImageConfigChangeV1::TargetUpserted { entity_id, .. } => entity_id.as_str(),
            other => panic!("expected target upserts, got {other:?}"),
        })
        .collect();
    assert_eq!(ids, vec!["t1", "t2"]);
}

#[test]
fn set_default_missing_target_is_not_found() {
    let err = apply_edit(&base(), Edit::TargetSetDefault("ghost".to_string()))
        .expect_err("missing target");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("not found"));
}

#[test]
fn change_set_and_event_carry_no_secret() {
    const NEW_SECRET: &str = "sk-NEW-CREDENTIAL-SUPERSECRET-abc";
    // Update the endpoint, introducing a fresh credential secret in the opaque
    // payload the owner supplied.
    let replacement = endpoint(ENDPOINT_ID, true, Some(NEW_SECRET));
    let endpoint_json = serde_json::to_string(&replacement).unwrap();
    // Precondition: the raw opaque payload REALLY carries the secret.
    assert!(
        endpoint_json.contains(NEW_SECRET),
        "fixture lost the secret"
    );

    let (cfg, pending) = apply_edit(
        &base(),
        Edit::EndpointUpdate {
            endpoint_id: ENDPOINT_ID.to_string(),
            json: endpoint_json,
        },
    )
    .expect("update ok");

    let generation = "9";
    let change_set = ImageConfigChangeSetSafeV1::new(
        generation.to_string(),
        project_changes(&cfg, &pending, generation),
    );
    let event = ImageControlEventV1::config_changed(
        "daemon-1".to_string(),
        "/tmp/project".to_string(),
        change_set.clone(),
    );

    // The change set summarizes the credential (credentialConfigured) without
    // ever carrying the secret value.
    let change_wire = serde_json::to_string(&change_set).unwrap();
    assert!(
        !change_wire.contains(NEW_SECRET),
        "change set leaked secret: {change_wire}"
    );
    let event_wire = serde_json::to_string(&event).unwrap();
    assert!(
        !event_wire.contains(NEW_SECRET),
        "event leaked secret: {event_wire}"
    );
    // And the summarized signal is honest.
    match &change_set.changes[0] {
        ImageConfigChangeV1::EndpointUpserted { item, .. } => {
            assert!(item.credential_configured);
        }
        other => panic!("expected endpoint upsert, got {other:?}"),
    }
}
