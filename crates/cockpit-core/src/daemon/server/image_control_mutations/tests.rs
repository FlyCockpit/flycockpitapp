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
    DEFAULT_BASE_TIER_KNOWN_COST_THRESHOLD_USD_MICROS, IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
    ImageAdapterKind, ImageCapabilityEvidence, ImageDimensionDescriptor,
    ImageDimensionRequestPolicy, ImageEndpoint, ImageEvidence, ImageFormat, ImageGenerationConfig,
    ImageGenerationTarget, ImageLocationClass, ImageParameter, ImageParameterDescriptor,
    ImagePrice, ImageTargetIdentity, ReferenceImageSupport, RegisteredComfyWorkflow,
    WorkflowBinding, WorkflowOutput, WorkflowValueType, canonical_workflow_digest,
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
        Edit::EndpointCreate(
            serde_json::to_string(&endpoint("second", false, None))
                .unwrap()
                .into(),
        ),
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
        Edit::EndpointCreate(
            serde_json::to_string(&endpoint(ENDPOINT_ID, false, None))
                .unwrap()
                .into(),
        ),
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
        Edit::TargetCreate(serde_json::to_string(&orphan).unwrap().into()),
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
            json: endpoint_json.into(),
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
        "/tmp/project".to_string(),
        "/tmp/project/.cockpit/config.json".to_string(),
        "revision".to_string(),
        cockpit_proto::image_control::ImageConfigMutationCapabilityV1::new("cc".repeat(32)),
        9,
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

// ---------------------------------------------------------------------------
// inc3c — workflow mutations (upload / bind / delete)
// ---------------------------------------------------------------------------

/// A valid single-binding workflow. `graph_secret`, when set, is embedded inside
/// the opaque `graph_json` so a leak test can plant a distinctive marker there.
fn workflow(id: &str, graph_secret: Option<&str>) -> RegisteredComfyWorkflow {
    let api_key = graph_secret.unwrap_or("none");
    let graph_json =
        format!(r#"{{"1":{{"inputs":{{"seed":1,"api_key":"{api_key}"}}}},"2":{{"inputs":{{}}}}}}"#);
    RegisteredComfyWorkflow {
        id: id.to_string(),
        graph_digest: canonical_workflow_digest(&graph_json).unwrap(),
        graph_json,
        bindings: vec![WorkflowBinding {
            parameter: ImageParameter::Seed,
            node_id: "1".into(),
            input: "seed".into(),
            value_type: WorkflowValueType::Integer,
            min: Some(0),
            max: Some(1_000_000),
        }],
        outputs: vec![WorkflowOutput {
            node_id: "2".into(),
            output: "images".into(),
            value_type: WorkflowValueType::Image,
        }],
    }
}

/// The same workflow id re-registered with a DIFFERENT graph and two bindings —
/// used to prove `bind` replaces the stored definition rather than merging.
fn workflow_v2(id: &str) -> RegisteredComfyWorkflow {
    let graph_json = r#"{"1":{"inputs":{"seed":1,"steps":20}},"2":{"inputs":{}}}"#.to_owned();
    RegisteredComfyWorkflow {
        id: id.to_string(),
        graph_digest: canonical_workflow_digest(&graph_json).unwrap(),
        graph_json,
        bindings: vec![
            WorkflowBinding {
                parameter: ImageParameter::Seed,
                node_id: "1".into(),
                input: "seed".into(),
                value_type: WorkflowValueType::Integer,
                min: Some(0),
                max: Some(1_000_000),
            },
            WorkflowBinding {
                parameter: ImageParameter::Steps,
                node_id: "1".into(),
                input: "steps".into(),
                value_type: WorkflowValueType::Integer,
                min: Some(1),
                max: Some(100),
            },
        ],
        outputs: vec![WorkflowOutput {
            node_id: "2".into(),
            output: "images".into(),
            value_type: WorkflowValueType::Image,
        }],
    }
}

/// A base with one uploaded standalone workflow (`wf-a`), reachable through the
/// production `apply_edit` funnel (not hand-inserted), so bind/delete tests act
/// on a genuinely registered workflow.
fn base_with_workflow() -> ImageGenerationConfig {
    apply_edit(
        &base(),
        Edit::WorkflowUpload(
            serde_json::to_string(&workflow("wf-a", None))
                .unwrap()
                .into(),
        ),
    )
    .expect("upload ok")
    .0
}

/// A valid ComfyUI registry whose enabled default target BINDS workflow
/// `portrait-v1` (mirrors the config crate's canonical comfy fixture).
fn comfy_config_referencing_workflow() -> ImageGenerationConfig {
    let wf = workflow("portrait-v1", None);
    let endpoint = ImageEndpoint {
        id: "local-comfy".into(),
        adapter: ImageAdapterKind::Comfyui,
        origin: "http://127.0.0.1:8188/".into(),
        path_prefix: None,
        credential_ref: Some("comfy-token".into()),
        headers: Vec::new(),
        allow_insecure_transport: false,
        location: ImageLocationClass::Local,
        enabled: true,
        route_profile_version: IMAGE_GENERATION_ROUTE_PROFILE_VERSION,
        exclusive_server: false,
    };
    let target = ImageGenerationTarget {
        id: "portrait".into(),
        display_name: None,
        endpoint_id: "local-comfy".into(),
        identity: ImageTargetIdentity::Workflow {
            workflow_id: wf.id.clone(),
            workflow_digest: wf.graph_digest.clone(),
        },
        enabled: true,
        is_default: true,
        formats: vec![ImageFormat::Png],
        reference_support: ReferenceImageSupport::Unsupported,
        max_reference_images: 0,
        max_samples: 1,
        max_outputs: 1,
        dimensions: ImageDimensionDescriptor::ProviderDefault,
        dimension_policy: ImageDimensionRequestPolicy::ProviderDefault,
        parameters: vec![ImageParameterDescriptor::Integer {
            parameter: ImageParameter::Seed,
            min: 0,
            max: 1_000_000,
        }],
        openrouter_routing: None,
        generation_capability: ImageCapabilityEvidence::new(
            CapabilityStatus::Supported,
            Some(ImageEvidence::WorkflowDeclared {
                workflow_digest: wf.graph_digest.clone(),
            }),
        )
        .unwrap(),
        price: ImagePrice::Unknown,
    };
    ImageGenerationConfig::new(vec![endpoint], vec![target], vec![wf], Vec::new())
        .expect("valid comfy base")
}

#[test]
fn workflow_upload_appends_and_upserts() {
    let (cfg, changes) = apply_edit(
        &base(),
        Edit::WorkflowUpload(
            serde_json::to_string(&workflow("wf-new", None))
                .unwrap()
                .into(),
        ),
    )
    .expect("upload ok");
    assert_eq!(cfg.workflows().len(), 1);
    assert!(cfg.workflows().iter().any(|w| w.id == "wf-new"));
    assert_eq!(changes.len(), 1);
    assert!(matches!(&changes[0], PendingChange::WorkflowUpsert(id) if id == "wf-new"));
}

#[test]
fn mutation_preserves_authored_base_tier_threshold() {
    // AC8: a registry mutation edits only endpoints/targets/workflows. It must
    // NOT reset a non-default authored base-tier threshold — `::new` defaults
    // the field, so `rebuild` re-applies the prior value across the edit.
    let authored = base()
        .with_base_tier_known_cost_threshold_usd_micros(1_000_000)
        .expect("in-range threshold");
    assert_ne!(
        authored.base_tier_known_cost_threshold_usd_micros(),
        DEFAULT_BASE_TIER_KNOWN_COST_THRESHOLD_USD_MICROS
    );
    let (cfg, _changes) = apply_edit(
        &authored,
        Edit::WorkflowUpload(
            serde_json::to_string(&workflow("wf-new", None))
                .unwrap()
                .into(),
        ),
    )
    .expect("upload ok");
    assert_eq!(
        cfg.base_tier_known_cost_threshold_usd_micros(),
        1_000_000,
        "an authored base-tier threshold must survive a registry edit"
    );
}

#[test]
fn workflow_upload_duplicate_id_is_rejected() {
    // Idempotency: a repeated upload with an existing id never double-applies —
    // `::new`'s unique-id invariant fails closed.
    let err = apply_edit(
        &base_with_workflow(),
        Edit::WorkflowUpload(
            serde_json::to_string(&workflow("wf-a", None))
                .unwrap()
                .into(),
        ),
    )
    .expect_err("duplicate rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn workflow_upload_lying_graph_digest_is_rejected() {
    // graph_digest INTEGRITY: a client supplies a graph_digest that does NOT
    // match the actual graph_json. `::new` -> `RegisteredComfyWorkflow::validate`
    // must reject it, so a lying digest never enters the registry.
    let mut lying = workflow("wf-liar", None);
    let honest_digest = canonical_workflow_digest(&lying.graph_json).unwrap();
    lying.graph_digest = "0000000000000000000000000000000000000000000000000000000000000000".into();
    // Precondition: the planted digest really disagrees with the graph.
    assert_ne!(lying.graph_digest, honest_digest);
    let err = apply_edit(
        &base(),
        Edit::WorkflowUpload(serde_json::to_string(&lying).unwrap().into()),
    )
    .expect_err("lying digest rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn workflow_bind_replaces_definition_and_upserts() {
    let (cfg, changes) = apply_edit(
        &base_with_workflow(),
        Edit::WorkflowBind {
            workflow_id: "wf-a".into(),
            json: serde_json::to_string(&workflow_v2("wf-a")).unwrap().into(),
        },
    )
    .expect("bind ok");
    // Distinguishing input: the replacement has TWO bindings; a merge/no-op would
    // leave one. Replace-by-id must yield exactly the new definition.
    let bound = cfg.workflows().iter().find(|w| w.id == "wf-a").unwrap();
    assert_eq!(bound.bindings.len(), 2);
    assert!(matches!(&changes[0], PendingChange::WorkflowUpsert(id) if id == "wf-a"));
}

#[test]
fn workflow_bind_lying_graph_digest_is_rejected() {
    let mut lying = workflow_v2("wf-a");
    lying.graph_digest = "0000000000000000000000000000000000000000000000000000000000000000".into();
    let err = apply_edit(
        &base_with_workflow(),
        Edit::WorkflowBind {
            workflow_id: "wf-a".into(),
            json: serde_json::to_string(&lying).unwrap().into(),
        },
    )
    .expect_err("lying digest rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn workflow_bind_changing_id_is_rejected() {
    let err = apply_edit(
        &base_with_workflow(),
        Edit::WorkflowBind {
            workflow_id: "wf-a".into(),
            json: serde_json::to_string(&workflow("wf-b", None))
                .unwrap()
                .into(),
        },
    )
    .expect_err("id change rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("must not change the workflow id"));
}

#[test]
fn workflow_bind_missing_is_not_found() {
    let err = apply_edit(
        &base(),
        Edit::WorkflowBind {
            workflow_id: "ghost".into(),
            json: serde_json::to_string(&workflow("ghost", None))
                .unwrap()
                .into(),
        },
    )
    .expect_err("missing workflow");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("not found"));
}

#[test]
fn workflow_delete_removes_standalone_workflow() {
    let (cfg, changes) =
        apply_edit(&base_with_workflow(), Edit::WorkflowDelete("wf-a".into())).expect("delete ok");
    assert!(cfg.workflows().is_empty());
    assert!(matches!(&changes[0], PendingChange::WorkflowDelete(id) if id == "wf-a"));
}

#[test]
fn workflow_delete_missing_is_not_found() {
    let err =
        apply_edit(&base(), Edit::WorkflowDelete("nope".into())).expect_err("missing workflow");
    assert_eq!(err.code, ErrorCode::BadRequest);
    assert!(err.message.contains("not found"));
}

#[test]
fn workflow_delete_referenced_by_enabled_target_fails_closed() {
    // Deleting the workflow an enabled target binds must fail closed rather than
    // persist a registry with a dangling workflow reference (`MissingWorkflow`).
    let err = apply_edit(
        &comfy_config_referencing_workflow(),
        Edit::WorkflowDelete("portrait-v1".into()),
    )
    .expect_err("referenced workflow delete rejected");
    assert_eq!(err.code, ErrorCode::BadRequest);
}

#[test]
fn workflow_change_set_and_event_carry_no_graph_json() {
    const GRAPH_SECRET: &str = "sk-GRAPH-BLOB-SUPERSECRET-xyz";
    let uploaded = workflow("wf-secret", Some(GRAPH_SECRET));
    let workflow_json = serde_json::to_string(&uploaded).unwrap();
    // Precondition: the opaque graph blob REALLY carries the secret.
    assert!(
        workflow_json.contains(GRAPH_SECRET),
        "fixture lost the graph secret"
    );

    let (cfg, pending) =
        apply_edit(&base(), Edit::WorkflowUpload(workflow_json.into())).expect("upload ok");

    let generation = "9";
    let change_set = ImageConfigChangeSetSafeV1::new(
        generation.to_string(),
        project_changes(&cfg, &pending, generation),
    );
    let event = ImageControlEventV1::config_changed(
        "daemon-1".to_string(),
        "/tmp/project".to_string(),
        "/tmp/project".to_string(),
        "/tmp/project/.cockpit/config.json".to_string(),
        "revision".to_string(),
        cockpit_proto::image_control::ImageConfigMutationCapabilityV1::new("cc".repeat(32)),
        9,
        change_set.clone(),
    );

    // The projection drops graph_json entirely; only graph_digest (a hash)
    // crosses. The planted secret must appear on NEITHER the change set nor the
    // event.
    let change_wire = serde_json::to_string(&change_set).unwrap();
    assert!(
        !change_wire.contains(GRAPH_SECRET),
        "change set leaked graph_json: {change_wire}"
    );
    let event_wire = serde_json::to_string(&event).unwrap();
    assert!(
        !event_wire.contains(GRAPH_SECRET),
        "event leaked graph_json: {event_wire}"
    );
    // And the summarized signal is honest: the digest is present and matches.
    match &change_set.changes[0] {
        ImageConfigChangeV1::WorkflowUpserted { item, .. } => {
            assert_eq!(item.workflow_digest, uploaded.graph_digest);
        }
        other => panic!("expected workflow upsert, got {other:?}"),
    }
}

#[test]
fn registry_patch_preserves_raw_unknown_and_secret_bearing_siblings() {
    let raw = br#"{
      "unknown_future_key": {"opaque": "keep-me"},
      "providers": {"private": {"api_key": "named-secret-reference"}},
      "image_generation": {"endpoints": [], "targets": [], "workflows": []}
    }"#;
    let rendered = render_registry_patch(raw, &base()).expect("typed image patch renders");
    let document: serde_json::Value = serde_json::from_slice(&rendered).unwrap();
    assert_eq!(
        document.pointer("/unknown_future_key/opaque"),
        Some(&serde_json::json!("keep-me"))
    );
    assert_eq!(
        document.pointer("/providers/private/api_key"),
        Some(&serde_json::json!("named-secret-reference"))
    );
    assert!(document.get("image_generation").is_some());
}

#[test]
fn authoritative_registry_selection_uses_most_specific_authored_layer() {
    let temp = tempfile::tempdir().unwrap();
    let least = temp.path().join("least.json");
    let middle = temp.path().join("middle.json");
    let most = temp.path().join("most.json");
    std::fs::write(
        &least,
        br#"{"image_generation":{"endpoints":[],"targets":[],"workflows":[]}}"#,
    )
    .unwrap();
    std::fs::write(&middle, br#"{"unrelated":true}"#).unwrap();
    std::fs::write(
        &most,
        br#"{"image_generation":{"endpoints":[],"targets":[],"workflows":[]}}"#,
    )
    .unwrap();

    let selected = most_specific_authored_registry(&[least, middle, most.clone()]).unwrap();
    assert_eq!(selected.as_deref(), Some(most.as_path()));
}

#[test]
fn authoritative_registry_selection_does_not_promote_unrelated_layer() {
    let temp = tempfile::tempdir().unwrap();
    let authored = temp.path().join("authored.json");
    let unrelated = temp.path().join("unrelated.json");
    std::fs::write(
        &authored,
        br#"{"sibling":{"keep":true},"image_generation":{"endpoints":[],"targets":[],"workflows":[]}}"#,
    )
    .unwrap();
    std::fs::write(&unrelated, br#"{"other":"preserve-inheritance"}"#).unwrap();

    let selected = most_specific_authored_registry(&[authored.clone(), unrelated]).unwrap();
    assert_eq!(selected.as_deref(), Some(authored.as_path()));
    let raw = read_document(&authored).unwrap();
    assert!(registry_from_document(raw.as_slice()).is_ok());
}

#[test]
fn not_yet_created_target_is_bound_to_canonical_existing_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let alias_spelling = temp
        .path()
        .join("child")
        .join("..")
        .join(".cockpit/config.json");
    let exact = exact_target_path(&alias_spelling).unwrap();
    assert_eq!(exact, temp.path().join(".cockpit/config.json"));
    assert!(exact.is_absolute());
}

#[test]
fn durability_source_ratchet_requires_exact_cas_journal_and_post_commit_publication() {
    let source = include_str!("../image_control_mutations.rs");
    for required in [
        "expected_config_revision",
        "verify_mutation_capability",
        "most_specific_authored_registry",
        "exact_target_path",
        "registry_from_document(consumed.as_slice())",
        "image_config_mutation_journals",
        "publication_phase",
        "publication_authorized",
        "settle_unpublished_image_mutation",
        "settle_image_mutation_success_and_retire",
        "local_operation_receipts",
        "write_config_bytes_atomic",
        "publish_committed_config_generation",
        "recover_image_config_mutation_journals",
        "CONFIG_PUBLICATION_RPC_LOCK",
    ] {
        assert!(
            source.contains(required),
            "missing durability fence {required}"
        );
    }
    let write = source.find("write_config_bytes_atomic").unwrap();
    let publish = source[write..]
        .find("publish_committed_config_generation")
        .map(|offset| write + offset)
        .unwrap();
    assert!(
        write < publish,
        "generation publication must follow atomic commit"
    );
    assert!(
        !source.contains("let mut cfg = loaded.clone()")
            && !source.contains("apply_edit(&extended.image_generation"),
        "dedicated writer must never serialize the effective layered config"
    );
    let recovery = source
        .split("pub(crate) async fn recover_image_config_mutation_journals")
        .nth(1)
        .expect("image recovery exists");
    assert!(recovery.contains("receipt.state"));
    assert!(recovery.contains("receipt.terminal_outcome_json"));
    assert!(recovery.contains("if receipt_state == \"terminal_success\""));
    assert!(recovery.contains("if terminal != response_json"));
    assert!(recovery.contains("does not exactly match its journaled response"));
    assert!(recovery.contains("receipt.consumed_revision != consumed"));
    assert!(recovery.contains("receipt.result_config_generation != expected_generation"));
    assert!(recovery.contains("Every terminal receipt is final"));
    assert!(recovery.contains("bounded terminal image recovery"));
    assert!(recovery.contains("if actual == intended"));
    assert!(recovery.contains("publish_committed_config_generation_at_least"));
    assert!(recovery.contains("must never rewrite the terminal receipt"));
    assert!(recovery.contains("journal.consumed_generation"));
    assert!(recovery.contains("committed.client_operation_id != operation"));
    assert!(recovery.contains("committed.result_revision != intended"));
    assert!(recovery.contains("committed.result_config_generation != expected_generation"));
    assert!(!recovery.contains("state IN ('executing','terminal_error','terminal_cancelled')"));
    assert!(recovery.contains("actual != intended"));
    assert!(recovery.contains("if actual == intended"));
    assert!(recovery.contains("publication_phase == \"prepared\""));
    assert!(
        recovery.contains("publication_phase == \"publication_authorized\" && actual == consumed")
    );
    assert!(recovery.contains("diverged from both consumed and intended"));
}

#[test]
fn durability_source_ratchet_distinguishes_prepublication_conflict_from_ambiguity() {
    let source = include_str!("../image_control_mutations.rs");
    let journal_insert = source
        .find("'prepared'")
        .expect("journal insert records prepared phase");
    let live_cas = source
        .find("let precommit = read_document")
        .expect("live CAS re-reads target");
    let authorize = source
        .find("SET publication_phase='publication_authorized'")
        .expect("publication authorization is durable");
    let atomic_write = source
        .find("write_config_bytes_atomic")
        .expect("atomic publication exists");
    assert!(journal_insert < authorize && authorize < live_cas && live_cas < atomic_write);
    let live_handler = source
        .split("pub(crate) async fn dispatch_image_control_mutation(")
        .nth(1)
        .and_then(|tail| tail.split("fn bounded_prepublication_conflict").next())
        .expect("image mutation live handler");
    assert!(
        live_handler.contains("CONFIG_PUBLICATION_RPC_LOCK"),
        "live publication must take the daemon config-publication lock"
    );
    assert!(
        !live_handler.contains("hold_config_mutation_lock"),
        "image mutations must not block a runtime worker on the synchronous config lock"
    );

    let recovery = source
        .split("pub(crate) async fn recover_image_config_mutation_journals")
        .nth(1)
        .expect("image recovery exists");
    let prepared = recovery
        .find("publication_phase == \"prepared\"")
        .expect("prepared recovery branch exists");
    let authorized = recovery
        .find("publication_phase == \"publication_authorized\"")
        .expect("authorized recovery branch exists");
    assert!(prepared < authorized);
    assert!(recovery[prepared..authorized].contains("terminal_error"));
    assert!(recovery[authorized..].contains("diverged from both consumed and intended"));
}
