//! LOCAL owner image-generation control-plane CONFIG-MUTATION handlers
//! (`image-generation-control-plane` inc3b + inc3c).
//!
//! Ten `owner_only` + `local_only` + `serialized` mutations
//! (`image_endpoint_create/update/delete`,
//! `image_target_create/update/delete/set_default`, and the inc3c workflow
//! mutations `image_workflow_upload/bind/delete`) that edit the secret-bearing
//! image-generation registry. Each one:
//!
//! 1. resolves workspace trust and loads the registry from the exact,
//!    most-specific local layer that authors `image_generation` (or a newly
//!    selected most-specific write layer when none does). It never mutates a
//!    merged/effective projection;
//! 2. applies the edit to a clone of the accessor `Vec` and RECONSTRUCTS the
//!    registry through the single [`ImageGenerationConfig::new`] validation
//!    funnel, which enforces every invariant (unique ids, enabled-target →
//!    enabled-endpoint, exactly-one-default). A registry that fails validation
//!    is NEVER persisted — the mutation fails closed with `BadRequest`;
//! 3. requires both the config generation and exact authoritative target-layer
//!    content revision, with no optional freshness bypass;
//! 4. writes a secret-safe SQLite recovery intent bound to the owner, operation,
//!    public redacted intent, request identity, and execution fence;
//! 5. patches only `image_generation` in the raw target-layer document under
//!    the shared publication/file fences, preserving unknown and secret-bearing
//!    sibling keys, then publishes the process generation after atomic commit;
//! 6. settles a replayable fenced local-operation receipt and emits a `config_changed`
//!    [`ImageControlEventV1`](cockpit_proto::image_control::ImageControlEventV1)
//!    carrying only SAFE projections (never a raw credential/header/graph blob).
//!
//! The opaque `*_json` request payloads keep the raw `credential_ref`/`headers`
//! out of typed wire fields; they are accepted only over the authenticated local
//! owner socket. The reply and event carry only the redacting SafeV1
//! projections.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageGenerationConfig, ImageGenerationConfigError,
    ImageGenerationTarget, ImageTargetIdentity, RegisteredComfyWorkflow,
};
use cockpit_proto::image_control::{
    ImageConfigChangeSetSafeV1, ImageConfigChangeV1, ImageConfigMutationCapabilityV1,
    ImageConfigMutationIntentV1, ImageControlEventV1, ImageControlMutationResponseV1,
    ImageEndpointSafeV1, ImageTargetSafeV1, ImageWorkflowSafeV1,
};

use crate::daemon::proto::{ErrorCode, ErrorPayload, Request, Response};
use crate::daemon::server::sessions::internal;
use crate::daemon::server::{DaemonContext, inventory};

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

fn conflict(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Conflict,
        message: message.into(),
    }
}

/// Every `ImageGenerationConfig::new` validation failure maps to a client
/// `BadRequest` (the control-plane `malformed`/`invalid_state` class). A config
/// that fails validation is never persisted.
fn map_config_error(_error: ImageGenerationConfigError) -> ErrorPayload {
    bad_request("invalid image generation configuration")
}

/// The entity that one change-set member describes, resolved to its safe
/// projection after the new generation is minted.
#[derive(Debug)]
enum PendingChange {
    EndpointUpsert(String),
    EndpointDelete(String),
    TargetUpsert(String),
    TargetDelete(String),
    WorkflowUpsert(String),
    WorkflowDelete(String),
}

/// A pure edit over the loaded registry. Returns the reconstructed (validated)
/// registry plus the set of entities the edit changed. `ImageGenerationConfig`
/// is only ever built through `::new`, so an invalid edit returns `Err` and
/// nothing is persisted.
enum Edit {
    EndpointCreate(zeroize::Zeroizing<String>),
    EndpointUpdate {
        endpoint_id: String,
        json: zeroize::Zeroizing<String>,
    },
    EndpointDelete(String),
    TargetCreate(zeroize::Zeroizing<String>),
    TargetUpdate {
        target_id: String,
        json: zeroize::Zeroizing<String>,
    },
    TargetDelete(String),
    TargetSetDefault(String),
    WorkflowUpload(zeroize::Zeroizing<String>),
    WorkflowBind {
        workflow_id: String,
        json: zeroize::Zeroizing<String>,
    },
    WorkflowDelete(String),
}

fn parse_endpoint(json: &str) -> Result<ImageEndpoint, ErrorPayload> {
    serde_json::from_str(json).map_err(|_| bad_request("invalid image endpoint"))
}

fn parse_target(json: &str) -> Result<ImageGenerationTarget, ErrorPayload> {
    serde_json::from_str(json).map_err(|_| bad_request("invalid image target"))
}

fn parse_workflow(json: &str) -> Result<RegisteredComfyWorkflow, ErrorPayload> {
    serde_json::from_str(json).map_err(|_| bad_request("invalid image workflow"))
}

fn rebuild(
    endpoints: Vec<ImageEndpoint>,
    targets: Vec<ImageGenerationTarget>,
    workflows: Vec<RegisteredComfyWorkflow>,
    old: &ImageGenerationConfig,
) -> Result<ImageGenerationConfig, ErrorPayload> {
    ImageGenerationConfig::new(
        endpoints,
        targets,
        workflows,
        old.openrouter_provider_allowlist().to_vec(),
    )
    // `new` resets top-level scalars (e.g. the base-tier threshold) to their
    // defaults; a mutation edits only endpoints/targets/workflows, so carry the
    // prior authored threshold across so it is not silently reset.
    .and_then(|config| {
        config.with_base_tier_known_cost_threshold_usd_micros(
            old.base_tier_known_cost_threshold_usd_micros(),
        )
    })
    .map_err(map_config_error)
}

fn apply_edit(
    old: &ImageGenerationConfig,
    edit: Edit,
) -> Result<(ImageGenerationConfig, Vec<PendingChange>), ErrorPayload> {
    match edit {
        Edit::EndpointCreate(json) => {
            let endpoint = parse_endpoint(&json)?;
            let id = endpoint.id.clone();
            // A duplicate id is rejected by `::new` (idempotency: a repeated
            // create with the same id never double-applies).
            let mut endpoints = old.endpoints().to_vec();
            endpoints.push(endpoint);
            let cfg = rebuild(
                endpoints,
                old.targets().to_vec(),
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, vec![PendingChange::EndpointUpsert(id)]))
        }
        Edit::EndpointUpdate { endpoint_id, json } => {
            let endpoint = parse_endpoint(&json)?;
            if endpoint.id != endpoint_id {
                return Err(bad_request(
                    "image endpoint update must not change the endpoint id",
                ));
            }
            let mut endpoints = old.endpoints().to_vec();
            let position = endpoints
                .iter()
                .position(|e| e.id == endpoint_id)
                .ok_or_else(|| bad_request("image endpoint not found"))?;
            endpoints[position] = endpoint;
            let cfg = rebuild(
                endpoints,
                old.targets().to_vec(),
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, vec![PendingChange::EndpointUpsert(endpoint_id)]))
        }
        Edit::EndpointDelete(endpoint_id) => {
            let mut endpoints = old.endpoints().to_vec();
            let position = endpoints
                .iter()
                .position(|e| e.id == endpoint_id)
                .ok_or_else(|| bad_request("image endpoint not found"))?;
            endpoints.remove(position);
            // `::new` fails closed if a still-enabled target references the
            // removed endpoint, so a dangling delete never persists.
            let cfg = rebuild(
                endpoints,
                old.targets().to_vec(),
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, vec![PendingChange::EndpointDelete(endpoint_id)]))
        }
        Edit::TargetCreate(json) => {
            let target = parse_target(&json)?;
            let id = target.id.clone();
            let mut targets = old.targets().to_vec();
            targets.push(target);
            let cfg = rebuild(
                old.endpoints().to_vec(),
                targets,
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, vec![PendingChange::TargetUpsert(id)]))
        }
        Edit::TargetUpdate { target_id, json } => {
            let target = parse_target(&json)?;
            if target.id != target_id {
                return Err(bad_request(
                    "image target update must not change the target id",
                ));
            }
            let mut targets = old.targets().to_vec();
            let position = targets
                .iter()
                .position(|t| t.id == target_id)
                .ok_or_else(|| bad_request("image target not found"))?;
            targets[position] = target;
            let cfg = rebuild(
                old.endpoints().to_vec(),
                targets,
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, vec![PendingChange::TargetUpsert(target_id)]))
        }
        Edit::TargetDelete(target_id) => {
            let mut targets = old.targets().to_vec();
            let position = targets
                .iter()
                .position(|t| t.id == target_id)
                .ok_or_else(|| bad_request("image target not found"))?;
            targets.remove(position);
            let cfg = rebuild(
                old.endpoints().to_vec(),
                targets,
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, vec![PendingChange::TargetDelete(target_id)]))
        }
        Edit::TargetSetDefault(target_id) => {
            if !old.targets().iter().any(|t| t.id == target_id) {
                return Err(bad_request("image target not found"));
            }
            let mut targets = old.targets().to_vec();
            let mut changed = Vec::new();
            for target in &mut targets {
                let desired = target.id == target_id;
                if target.is_default != desired {
                    target.is_default = desired;
                    changed.push(PendingChange::TargetUpsert(target.id.clone()));
                }
            }
            // `::new` enforces exactly-one-enabled-default and rejects making a
            // disabled target the default (`DefaultTargetDisabled`).
            let cfg = rebuild(
                old.endpoints().to_vec(),
                targets,
                old.workflows().to_vec(),
                old,
            )?;
            Ok((cfg, changed))
        }
        Edit::WorkflowUpload(json) => {
            let workflow = parse_workflow(&json)?;
            let id = workflow.id.clone();
            // A duplicate id is rejected by `::new` (idempotency: a repeated
            // upload with the same id never double-applies). `::new` also runs
            // `RegisteredComfyWorkflow::validate`, which parses `graph_json`,
            // rejects a `graph_digest` that does not match the actual graph (a
            // client cannot register a lying digest), and checks the bindings.
            let mut workflows = old.workflows().to_vec();
            workflows.push(workflow);
            let cfg = rebuild(
                old.endpoints().to_vec(),
                old.targets().to_vec(),
                workflows,
                old,
            )?;
            Ok((cfg, vec![PendingChange::WorkflowUpsert(id)]))
        }
        Edit::WorkflowBind { workflow_id, json } => {
            let workflow = parse_workflow(&json)?;
            if workflow.id != workflow_id {
                return Err(bad_request(
                    "image workflow bind must not change the workflow id",
                ));
            }
            let mut workflows = old.workflows().to_vec();
            let position = workflows
                .iter()
                .position(|w| w.id == workflow_id)
                .ok_or_else(|| bad_request("image workflow not found"))?;
            // Replace-by-id: the caller re-supplies the workflow with its updated
            // bindings/outputs. `::new` re-verifies the `graph_digest` matches the
            // `graph_json` and that every binding/output references a real node,
            // so a lying digest or a binding to a missing node fails closed.
            workflows[position] = workflow;
            let cfg = rebuild(
                old.endpoints().to_vec(),
                old.targets().to_vec(),
                workflows,
                old,
            )?;
            Ok((cfg, vec![PendingChange::WorkflowUpsert(workflow_id)]))
        }
        Edit::WorkflowDelete(workflow_id) => {
            let mut workflows = old.workflows().to_vec();
            let position = workflows
                .iter()
                .position(|w| w.id == workflow_id)
                .ok_or_else(|| bad_request("image workflow not found"))?;
            workflows.remove(position);
            // `::new` fails closed if a still-enabled target binds the removed
            // workflow (`MissingWorkflow`), so a dangling delete never persists.
            let cfg = rebuild(
                old.endpoints().to_vec(),
                old.targets().to_vec(),
                workflows,
                old,
            )?;
            Ok((cfg, vec![PendingChange::WorkflowDelete(workflow_id)]))
        }
    }
}

/// Resolve an endpoint's adapter kind through the referenced endpoint (matches
/// the read surface's `target_adapter`).
fn target_adapter(cfg: &ImageGenerationConfig, endpoint_id: &str) -> Option<ImageAdapterKind> {
    cfg.endpoints()
        .iter()
        .find(|e| e.id == endpoint_id)
        .map(|e| e.adapter)
}

/// The ID-sorted-unique set of target ids that bind `workflow_id` (matches the
/// read surface's `referencing_target_ids`).
fn workflow_referencing_target_ids(cfg: &ImageGenerationConfig, workflow_id: &str) -> Vec<String> {
    let mut ids: Vec<String> = cfg
        .targets()
        .iter()
        .filter(|t| {
            matches!(
                &t.identity,
                ImageTargetIdentity::Workflow { workflow_id: w, .. } if w == workflow_id
            )
        })
        .map(|t| t.id.clone())
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

/// The stable sort key for a change-set member: `(entityKind ordinal, entity
/// id)` per the wire contract's "full sorted delta". Endpoint < Target <
/// Workflow, then ascending by id.
fn change_sort_key(change: &ImageConfigChangeV1) -> (u8, &str) {
    match change {
        ImageConfigChangeV1::EndpointUpserted { entity_id, .. }
        | ImageConfigChangeV1::EndpointDeleted { entity_id, .. } => (0, entity_id.as_str()),
        ImageConfigChangeV1::TargetUpserted { entity_id, .. }
        | ImageConfigChangeV1::TargetDeleted { entity_id, .. } => (1, entity_id.as_str()),
        ImageConfigChangeV1::WorkflowUpserted { entity_id, .. }
        | ImageConfigChangeV1::WorkflowDeleted { entity_id, .. } => (2, entity_id.as_str()),
    }
}

/// Build the safe change set from the applied edit, projecting every upserted
/// entity through the redacting SafeV1 funnel at the newly-minted generation.
/// The result is deterministically sorted by `(entityKind ordinal, entity id)`
/// so a `set_default` (which changes both the prior and new default) emits a
/// stable, contract-ordered delta.
fn project_changes(
    cfg: &ImageGenerationConfig,
    pending: &[PendingChange],
    generation: &str,
) -> Vec<ImageConfigChangeV1> {
    let mut changes: Vec<ImageConfigChangeV1> =
        pending
            .iter()
            .filter_map(|change| match change {
                PendingChange::EndpointUpsert(id) => cfg
                    .endpoints()
                    .iter()
                    .find(|e| e.id == *id)
                    .map(|endpoint| ImageConfigChangeV1::EndpointUpserted {
                        entity_id: id.clone(),
                        entity_generation: generation.to_string(),
                        item: ImageEndpointSafeV1::project(endpoint, generation.to_string()),
                    }),
                PendingChange::EndpointDelete(id) => Some(ImageConfigChangeV1::EndpointDeleted {
                    entity_id: id.clone(),
                    entity_generation: generation.to_string(),
                }),
                PendingChange::TargetUpsert(id) => {
                    cfg.targets().iter().find(|t| t.id == *id).map(|target| {
                        ImageConfigChangeV1::TargetUpserted {
                            entity_id: id.clone(),
                            entity_generation: generation.to_string(),
                            item: ImageTargetSafeV1::project(
                                target,
                                target_adapter(cfg, &target.endpoint_id),
                                generation.to_string(),
                            ),
                        }
                    })
                }
                PendingChange::TargetDelete(id) => Some(ImageConfigChangeV1::TargetDeleted {
                    entity_id: id.clone(),
                    entity_generation: generation.to_string(),
                }),
                PendingChange::WorkflowUpsert(id) => cfg
                    .workflows()
                    .iter()
                    .find(|w| w.id == *id)
                    .map(|workflow| ImageConfigChangeV1::WorkflowUpserted {
                        entity_id: id.clone(),
                        entity_generation: generation.to_string(),
                        // SafeV1 drops `graph_json`; only `graph_digest` crosses.
                        item: ImageWorkflowSafeV1::project(
                            workflow,
                            workflow_referencing_target_ids(cfg, id),
                            generation.to_string(),
                        ),
                    }),
                PendingChange::WorkflowDelete(id) => Some(ImageConfigChangeV1::WorkflowDeleted {
                    entity_id: id.clone(),
                    entity_generation: generation.to_string(),
                }),
            })
            .collect();
    changes.sort_by(|a, b| change_sort_key(a).cmp(&change_sort_key(b)));
    changes
}

fn amend_response_generation(
    ctx: &DaemonContext,
    response: &mut Response,
    generation: u64,
) -> anyhow::Result<()> {
    let Response::ImageControlMutated(receipt) = response else {
        return Ok(());
    };
    receipt.daemon_instance_id = inventory::daemon_instance_id().to_string();
    receipt.result_config_generation = generation;
    receipt.mutation_capability = mint_mutation_capability(
        ctx,
        Path::new(&receipt.canonical_project_root),
        Path::new(&receipt.target_path),
        &receipt.result_revision,
        generation,
    )?;
    let generation_text = generation.to_string();
    receipt
        .change_set
        .config_generation
        .clone_from(&generation_text);
    for change in &mut receipt.change_set.changes {
        match change {
            ImageConfigChangeV1::EndpointUpserted {
                entity_generation,
                item,
                ..
            } => {
                entity_generation.clone_from(&generation_text);
                item.entity_generation.clone_from(&generation_text);
            }
            ImageConfigChangeV1::EndpointDeleted {
                entity_generation, ..
            }
            | ImageConfigChangeV1::TargetDeleted {
                entity_generation, ..
            }
            | ImageConfigChangeV1::WorkflowDeleted {
                entity_generation, ..
            } => entity_generation.clone_from(&generation_text),
            ImageConfigChangeV1::TargetUpserted {
                entity_generation,
                item,
                ..
            } => {
                entity_generation.clone_from(&generation_text);
                item.entity_generation.clone_from(&generation_text);
            }
            ImageConfigChangeV1::WorkflowUpserted {
                entity_generation,
                item,
                ..
            } => {
                entity_generation.clone_from(&generation_text);
                item.entity_generation.clone_from(&generation_text);
            }
        }
    }
    Ok(())
}

/// The exact local layer that owns the atomic image registry.  A mutation must
/// never start from the merged `ExtendedConfig`: doing so would copy inherited
/// values into an unrelated layer and silently change future inheritance.
pub(crate) struct AuthoritativeImageLayer {
    pub(crate) target: PathBuf,
    pub(crate) registry: ImageGenerationConfig,
    pub(crate) revision: String,
}

fn digest_hex(digest: impl AsRef<[u8]>) -> String {
    let digest = digest.as_ref();
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn content_revision(ctx: &DaemonContext, bytes: &[u8]) -> String {
    digest_hex(
        ctx.secret_vault
            .keyed_request_identity(b"flycockpit.image-config.target-revision.v1\0", bytes),
    )
}

pub(crate) fn mint_mutation_capability(
    ctx: &DaemonContext,
    canonical_project_root: &Path,
    target: &Path,
    target_revision: &str,
    config_generation: u64,
) -> anyhow::Result<ImageConfigMutationCapabilityV1> {
    let material = zeroize::Zeroizing::new(serde_json::to_vec(&(
        "flycockpit.image-config.mutation-capability.v1",
        canonical_project_root.to_string_lossy().as_ref(),
        target.to_string_lossy().as_ref(),
        target_revision,
        config_generation,
    ))?);
    Ok(ImageConfigMutationCapabilityV1::new(digest_hex(
        ctx.secret_vault.keyed_request_identity(
            b"flycockpit.image-config.mutation-capability.v1\0",
            material.as_slice(),
        ),
    )))
}

fn verify_mutation_capability(
    ctx: &DaemonContext,
    presented: &ImageConfigMutationCapabilityV1,
    canonical_project_root: &Path,
    target: &Path,
    target_revision: &str,
    config_generation: u64,
) -> std::result::Result<(), ErrorPayload> {
    let expected = mint_mutation_capability(
        ctx,
        canonical_project_root,
        target,
        target_revision,
        config_generation,
    )
    .map_err(internal)?;
    let presented = crate::leaks::decode_hex_32(presented.as_str())
        .ok_or_else(|| conflict("image mutation capability is malformed"))?;
    let expected = crate::leaks::decode_hex_32(expected.as_str())
        .ok_or_else(|| internal("daemon minted a malformed image mutation capability"))?;
    if !crate::leaks::ct_eq_32(&presented, &expected) {
        return Err(conflict(
            "image mutation capability does not match the authoritative target",
        ));
    }
    Ok(())
}

fn read_document(path: &Path) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(zeroize::Zeroizing::new(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(zeroize::Zeroizing::new(b"{}".to_vec()))
        }
        Err(error) => Err(error.into()),
    }
}

/// Resolve the most-specific layer that actually authors `image_generation`.
/// When no layer authors it, choose the normal most-specific write target and
/// start from the empty registry. `config_file_paths_for_load` is already
/// ordered least-specific to most-specific and honors `COCKPIT_CONFIG`.
pub(crate) fn authoritative_image_layer(
    ctx: &DaemonContext,
    project_root: &Path,
    trust_policy: &crate::config::trust::WorkspaceTrustPolicy,
) -> anyhow::Result<AuthoritativeImageLayer> {
    crate::config::trust::with_workspace_trust_policy(trust_policy.clone(), || {
        authoritative_image_layer_trusted(ctx, project_root)
    })
}

fn authoritative_image_layer_trusted(
    ctx: &DaemonContext,
    project_root: &Path,
) -> anyhow::Result<AuthoritativeImageLayer> {
    use cockpit_config::config::dirs::{CONFIG_FILE, config_file_paths_for_load};

    let paths = config_file_paths_for_load(project_root);
    let defining = most_specific_authored_registry(&paths)?;
    let selected = defining
        .or_else(|| cockpit_config::config::dirs::most_specific_config_write_target(project_root))
        .unwrap_or_else(|| project_root.join(".cockpit").join(CONFIG_FILE));
    let target = exact_target_path(&selected)?;
    let raw = read_document(&target)?;
    let registry = registry_from_document(raw.as_slice())?;
    let revision = content_revision(ctx, raw.as_slice());
    Ok(AuthoritativeImageLayer {
        target,
        registry,
        revision,
    })
}

/// Canonicalize the existing prefix of a possibly-not-yet-created config path,
/// then append only the daemon-selected missing components. This gives the
/// capability and receipt one stable target identity even through project-root
/// aliases, without requiring the scaffold file to exist yet.
fn exact_target_path(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    let mut cursor = normalized.as_path();
    let mut missing = Vec::new();
    while !cursor.exists() {
        let name = cursor
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("image config target has no existing ancestor"))?;
        missing.push(name.to_os_string());
        cursor = cursor
            .parent()
            .ok_or_else(|| anyhow::anyhow!("image config target has no existing ancestor"))?;
    }
    let mut canonical = std::fs::canonicalize(cursor)?;
    for component in missing.into_iter().rev() {
        canonical.push(component);
    }
    Ok(canonical)
}

fn most_specific_authored_registry(paths: &[PathBuf]) -> anyhow::Result<Option<PathBuf>> {
    let mut defining = None;
    for path in paths {
        if !path.exists() {
            continue;
        }
        let raw = read_document(path)?;
        let document: serde_json::Value = serde_json::from_slice(raw.as_slice())?;
        let object = document
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("authoritative config root must be an object"))?;
        if object.contains_key("image_generation") {
            defining = Some(path.clone());
        }
    }
    Ok(defining)
}

fn registry_from_document(raw: &[u8]) -> anyhow::Result<ImageGenerationConfig> {
    let document: serde_json::Value = serde_json::from_slice(raw)?;
    let object = document
        .as_object()
        .ok_or_else(|| anyhow::anyhow!("authoritative config root must be an object"))?;
    match object.get("image_generation") {
        Some(value) => serde_json::from_value(value.clone()).map_err(Into::into),
        None => Ok(ImageGenerationConfig::default()),
    }
}

fn render_registry_patch(
    raw: &[u8],
    registry: &ImageGenerationConfig,
) -> Result<Vec<u8>, ErrorPayload> {
    let mut document: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|_| bad_request("invalid authoritative config document"))?;
    let object = document
        .as_object_mut()
        .ok_or_else(|| bad_request("authoritative config root must be an object"))?;
    object.insert(
        "image_generation".into(),
        serde_json::to_value(registry).map_err(internal)?,
    );
    serde_json::to_vec_pretty(&document).map_err(internal)
}

struct ExtractedMutation {
    client_operation_id: String,
    mutation_intent_hash: String,
    project_root: String,
    expected_generation: u64,
    expected_revision: String,
    mutation_capability: ImageConfigMutationCapabilityV1,
    edit: Edit,
}

fn extract(request: Request) -> Result<ExtractedMutation, ErrorPayload> {
    let (
        client_operation_id,
        mutation_intent_hash,
        project_root,
        expected,
        expected_revision,
        mutation_capability,
        edit,
    ) = match request {
        Request::ImageEndpointCreate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            endpoint_json,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::EndpointCreate(endpoint_json.into_zeroizing()),
        ),
        Request::ImageEndpointUpdate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            endpoint_id,
            endpoint_json,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::EndpointUpdate {
                endpoint_id,
                json: endpoint_json.into_zeroizing(),
            },
        ),
        Request::ImageEndpointDelete {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            endpoint_id,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::EndpointDelete(endpoint_id),
        ),
        Request::ImageTargetCreate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_json,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::TargetCreate(target_json.into_zeroizing()),
        ),
        Request::ImageTargetUpdate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_id,
            target_json,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::TargetUpdate {
                target_id,
                json: target_json.into_zeroizing(),
            },
        ),
        Request::ImageTargetDelete {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_id,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::TargetDelete(target_id),
        ),
        Request::ImageTargetSetDefault {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_id,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::TargetSetDefault(target_id),
        ),
        Request::ImageWorkflowUpload {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            workflow_json,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::WorkflowUpload(workflow_json.into_zeroizing()),
        ),
        Request::ImageWorkflowBind {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            workflow_id,
            bindings_json,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::WorkflowBind {
                workflow_id,
                json: bindings_json.into_zeroizing(),
            },
        ),
        Request::ImageWorkflowDelete {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            workflow_id,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
        } => (
            client_operation_id,
            mutation_intent_hash,
            project_root,
            expected_config_generation,
            expected_config_revision,
            mutation_capability,
            Edit::WorkflowDelete(workflow_id),
        ),
        other => {
            return Err(internal(format!(
                "dispatch_image_control_mutation called with non-mutation request `{}`",
                crate::daemon::principal::request_kind(&other)
            )));
        }
    };
    if project_root.trim().is_empty() {
        return Err(bad_request("project_root must not be empty"));
    }
    if client_operation_id.trim().is_empty()
        || mutation_intent_hash.len() != 64
        || !mutation_intent_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || expected_revision.len() != 64
        || !expected_revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(bad_request(
            "image mutation operation, intent, or revision identity is invalid",
        ));
    }
    Ok(ExtractedMutation {
        client_operation_id,
        mutation_intent_hash,
        project_root,
        expected_generation: expected,
        expected_revision,
        mutation_capability,
        edit,
    })
}

/// LOCAL owner image-config mutation dispatch. Declared
/// `owner_only`+`local_only`+`serialized`+`is_mutation`, so it reaches only the
/// serialized surface with no remote operation reserved.
pub(crate) async fn dispatch_image_control_mutation(
    ctx: &Arc<DaemonContext>,
    request: Request,
    owner: String,
    request_hash: [u8; 32],
    fencing_generation: i64,
) -> std::result::Result<Response, ErrorPayload> {
    let extracted = extract(request)?;
    let ExtractedMutation {
        client_operation_id,
        mutation_intent_hash,
        project_root,
        expected_generation,
        expected_revision,
        mutation_capability,
        edit,
    } = extracted;

    // Serialize image mutations so the read → CAS → write is atomic among them.
    let _guard = super::dispatch::CONFIG_PUBLICATION_RPC_LOCK.lock().await;

    // Read the current generation FIRST, then load the registry, so a config
    // write that lands between the two makes the generation CAS below fail
    // closed rather than persisting an edit built on a stale registry.
    let current = inventory::current_config_generation();
    if expected_generation != current {
        return Err(conflict(format!(
            "image config generation is {current}, expected {expected_generation}"
        )));
    }

    let cwd = std::fs::canonicalize(&project_root)
        .map_err(|_| bad_request("project_root must identify an existing canonical workspace"))?;
    let trust_policy = crate::config::trust::resolve_workspace_trust_policy_from_db(&ctx.db, &cwd)
        .await
        .map_err(internal)?;
    // Resolve the exact raw layer that owns this atomic registry. Never edit a
    // merged/effective projection: that would flatten inherited values into a
    // different layer and mutate the authority model as a side effect.
    let layer = authoritative_image_layer(ctx, &cwd, &trust_policy).map_err(internal)?;
    let target = layer.target;
    let target_display = target.to_string_lossy().into_owned();
    let publication_guard =
        cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
    let consumed = read_document(&target).map_err(internal)?;
    let consumed_revision = content_revision(ctx, consumed.as_slice());
    if consumed_revision != expected_revision {
        return Err(conflict(
            "image configuration document changed; reload before mutating",
        ));
    }
    verify_mutation_capability(
        ctx,
        &mutation_capability,
        &cwd,
        &target,
        &consumed_revision,
        current,
    )?;
    let registry = registry_from_document(consumed.as_slice())
        .map_err(|_| bad_request("the authoritative image configuration registry is malformed"))?;

    // Apply + validate through the single `ImageGenerationConfig::new` funnel.
    // An invalid result returns here — nothing is written or bumped.
    let (new_registry, pending) = apply_edit(&registry, edit)?;

    // The public mutation identity is derived exclusively from redacted safe
    // projections. Endpoint credentials/headers and workflow graph bytes can
    // influence the vault-keyed request identity, but never this public hash.
    let public_changes = project_changes(&new_registry, &pending, "intent");
    let computed_intent = ImageConfigMutationIntentV1 {
        project_id: project_root.clone(),
        expected_config_generation: expected_generation,
        expected_config_revision: expected_revision.clone(),
        changes: public_changes,
    }
    .sha256()
    .map_err(internal)?;
    if computed_intent != mutation_intent_hash {
        return Err(conflict(
            "image mutation public intent hash does not match the redacted request",
        ));
    }

    let intended =
        zeroize::Zeroizing::new(render_registry_patch(consumed.as_slice(), &new_registry)?);
    let result_revision = content_revision(ctx, intended.as_slice());
    let predicted_generation =
        current.saturating_add(u64::from(result_revision != consumed_revision));
    let generation = predicted_generation.to_string();

    let change_set = ImageConfigChangeSetSafeV1::new(
        generation.clone(),
        project_changes(&new_registry, &pending, &generation),
    );
    let daemon_instance_id = inventory::daemon_instance_id().to_string();
    let canonical_project_root = cwd.to_string_lossy().into_owned();
    let next_capability =
        mint_mutation_capability(ctx, &cwd, &target, &result_revision, predicted_generation)
            .map_err(internal)?;
    let mut response = Response::ImageControlMutated(ImageControlMutationResponseV1::new(
        client_operation_id.clone(),
        mutation_intent_hash.clone(),
        daemon_instance_id.clone(),
        project_root.clone(),
        canonical_project_root.clone(),
        target_display.clone(),
        consumed_revision.clone(),
        result_revision.clone(),
        current,
        predicted_generation,
        next_capability,
        change_set,
    ));
    let mut terminal_response_json = serde_json::to_string(&response).map_err(internal)?;
    drop(publication_guard);

    let journal_owner = owner.clone();
    let journal_operation = client_operation_id.clone();
    let journal_project = cwd.to_string_lossy().into_owned();
    let journal_target = target_display.clone();
    let journal_consumed = consumed_revision.clone();
    let journal_intended = result_revision.clone();
    let journal_intent = mutation_intent_hash.clone();
    let journal_response = terminal_response_json.clone();
    ctx.db
        .write(move |conn| {
            conn.execute(
                "INSERT INTO image_config_mutation_journals
             (owner_digest,client_operation_id,request_hash,fencing_generation,
              mutation_intent_hash,project_root,target_path,consumed_revision,
              intended_revision,consumed_generation,publication_phase,
              terminal_response_json,created_at_unix_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,'prepared',?11,?12)",
                rusqlite::params![
                    journal_owner,
                    journal_operation,
                    request_hash.as_slice(),
                    fencing_generation,
                    journal_intent,
                    journal_project,
                    journal_target,
                    journal_consumed,
                    journal_intended,
                    current,
                    journal_response,
                    chrono::Utc::now().timestamp_millis()
                ],
            )?;
            Ok(())
        })
        .await
        .map_err(internal)?;

    let publication_guard =
        cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
    let precommit = read_document(&target).map_err(internal)?;
    if content_revision(ctx, &precommit) != consumed_revision {
        return Err(settle_prepublication_conflict(
            ctx,
            owner,
            client_operation_id,
            request_hash,
            fencing_generation,
        )
        .await?);
    }
    let authorize_owner = owner.clone();
    let authorize_operation = client_operation_id.clone();
    ctx.db
        .write(move |conn| {
            let changed = conn.execute(
                "UPDATE image_config_mutation_journals
                    SET publication_phase='publication_authorized'
                  WHERE owner_digest=?1 AND client_operation_id=?2
                    AND request_hash=?3 AND fencing_generation=?4
                    AND publication_phase='prepared'",
                rusqlite::params![
                    authorize_owner,
                    authorize_operation,
                    request_hash.as_slice(),
                    fencing_generation
                ],
            )?;
            if changed != 1 {
                anyhow::bail!("image mutation lost its prepared publication journal");
            }
            Ok(())
        })
        .await
        .map_err(internal)?;
    let published_generation = if result_revision != consumed_revision {
        cockpit_config::config::write_config_bytes_atomic(&target, &intended).map_err(internal)?;
        inventory::publish_committed_config_generation()
    } else {
        // A semantic/no-byte-change result still reports the generation at
        // its commit observation point. Another config family may have
        // published while this operation waited on the target file lock.
        inventory::current_config_generation()
    };
    drop(publication_guard);

    if published_generation != predicted_generation {
        amend_response_generation(ctx, &mut response, published_generation).map_err(internal)?;
        terminal_response_json = serde_json::to_string(&response).map_err(internal)?;
        let amend_owner = owner.clone();
        let amend_operation = client_operation_id.clone();
        let amend_response = terminal_response_json;
        ctx.db
            .write(move |conn| {
                let changed = conn.execute(
                    "UPDATE image_config_mutation_journals SET terminal_response_json=?3
                 WHERE owner_digest=?1 AND client_operation_id=?2",
                    rusqlite::params![amend_owner, amend_operation, amend_response],
                )?;
                if changed != 1 {
                    anyhow::bail!(
                        "image mutation recovery intent disappeared before generation amendment"
                    );
                }
                Ok(())
            })
            .await
            .map_err(internal)?;
    }

    let change_set = match &response {
        Response::ImageControlMutated(receipt) => receipt.change_set.clone(),
        _ => unreachable!(),
    };

    // Emit the redacted `config_changed` replay event (safe projections only).
    ctx.broadcast_global(crate::daemon::proto::Event::ImageControlConfigChanged {
        event: ImageControlEventV1::config_changed(
            daemon_instance_id.clone(),
            project_root.clone(),
            canonical_project_root,
            target_display,
            match &response {
                Response::ImageControlMutated(receipt) => receipt.result_revision.clone(),
                _ => unreachable!(),
            },
            match &response {
                Response::ImageControlMutated(receipt) => receipt.mutation_capability.clone(),
                _ => unreachable!(),
            },
            match &response {
                Response::ImageControlMutated(receipt) => receipt.result_config_generation,
                _ => unreachable!(),
            },
            change_set.clone(),
        ),
    });

    Ok(response)
}

fn bounded_prepublication_conflict() -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::Conflict,
        // This is deliberately the same bounded public error persisted by the
        // generic local-operation terminalizer. Keeping it path- and
        // document-free also makes its second, idempotent settlement a no-op.
        message: "the local operation was rejected; inspect daemon diagnostics for details"
            .to_owned(),
    }
}

async fn settle_prepublication_conflict(
    ctx: &DaemonContext,
    owner: String,
    operation: String,
    request_hash: [u8; 32],
    fence: i64,
) -> std::result::Result<ErrorPayload, ErrorPayload> {
    let error = bounded_prepublication_conflict();
    let terminal = serde_json::to_string(&error).map_err(internal)?;
    ctx.db
        .transaction(move |conn| {
            let changed = conn.execute(
                "UPDATE local_operation_receipts
                    SET state='terminal_error',terminal_outcome_json=?5,
                        execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                  WHERE owner_digest=?1 AND client_operation_id=?2
                    AND request_hash=?3 AND fencing_generation=?4
                    AND state='executing'
                    AND EXISTS (
                        SELECT 1 FROM image_config_mutation_journals journal
                         WHERE journal.owner_digest=?1
                           AND journal.client_operation_id=?2
                           AND journal.request_hash=?3
                           AND journal.fencing_generation=?4
                           AND journal.publication_phase='prepared'
                    )",
                rusqlite::params![
                    owner,
                    operation,
                    request_hash.as_slice(),
                    fence,
                    terminal,
                    chrono::Utc::now().timestamp_millis()
                ],
            )?;
            if changed != 1 {
                anyhow::bail!("image mutation lost its exact prepublication receipt");
            }
            let retired = conn.execute(
                "DELETE FROM image_config_mutation_journals
                  WHERE owner_digest=?1 AND client_operation_id=?2
                    AND request_hash=?3 AND fencing_generation=?4
                    AND publication_phase='prepared'",
                rusqlite::params![owner, operation, request_hash.as_slice(), fence],
            )?;
            if retired != 1 {
                anyhow::bail!("image mutation lost its prepared recovery journal");
            }
            Ok(())
        })
        .await
        .map_err(internal)?;
    Ok(error)
}

/// Resolve secret-safe image publication journals before socket publication.
/// An intended hash proves the atomic file commit; a consumed hash proves no
/// commit. Any third value is external divergence and fails boot closed.
pub(crate) async fn recover_image_config_mutation_journals(
    ctx: &Arc<DaemonContext>,
) -> std::result::Result<u64, ErrorPayload> {
    type Row = (
        String,
        String,
        Vec<u8>,
        i64,
        String,
        String,
        String,
        String,
        String,
    );
    let rows: Vec<Row> = ctx
        .db
        .read(|conn| {
            let mut statement = conn.prepare(
                "SELECT journal.owner_digest,journal.client_operation_id,journal.request_hash,
                    journal.fencing_generation,journal.target_path,journal.consumed_revision,
                    journal.intended_revision,journal.publication_phase,
                    journal.terminal_response_json
               FROM image_config_mutation_journals journal
               JOIN local_operation_receipts receipt
                 ON receipt.owner_digest=journal.owner_digest
                AND receipt.client_operation_id=journal.client_operation_id
              ORDER BY journal.created_at_unix_ms",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
        .await
        .map_err(internal)?;
    let mut recovered = 0_u64;
    for (
        owner,
        operation,
        request_hash,
        fence,
        target,
        consumed,
        intended,
        publication_phase,
        response_json,
    ) in rows
    {
        let hash: [u8; 32] = request_hash
            .try_into()
            .map_err(|_| internal("image mutation journal request hash is malformed"))?;
        // The file is authoritative even when a receipt already looks
        // terminal. A process can commit the atomic replace and then have a
        // later path incorrectly terminalize the receipt before the journal is
        // retired. Never discard that evidence without reconciling it.
        let actual_bytes = read_document(Path::new(&target)).map_err(internal)?;
        let actual = content_revision(ctx, actual_bytes.as_slice());
        if actual == intended {
            let mut response: Response = serde_json::from_str(&response_json).map_err(internal)?;
            let published = if intended == consumed {
                inventory::current_config_generation()
            } else {
                inventory::publish_committed_config_generation()
            };
            amend_response_generation(ctx, &mut response, published).map_err(internal)?;
            let terminal = serde_json::to_string(&response).map_err(internal)?;
            ctx.db.transaction(move |conn| {
                let changed = conn.execute(
                    "UPDATE local_operation_receipts SET state='terminal_success',terminal_outcome_json=?5,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                     WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4",
                    rusqlite::params![owner,operation,hash.as_slice(),fence,terminal,chrono::Utc::now().timestamp_millis()],
                )?;
                if changed != 1 { anyhow::bail!("image mutation recovery lost its exact receipt"); }
                conn.execute("DELETE FROM image_config_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2", rusqlite::params![owner,operation])?;
                Ok(())
            }).await.map_err(internal)?;
        } else if publication_phase == "prepared" {
            // No process is allowed to replace the target until the durable
            // phase transition below the live CAS. Therefore any non-intended
            // value while still prepared proves this operation did not
            // publish, even if an external writer changed the file after the
            // journal was inserted. Retire it instead of poisoning boot.
            let error = bounded_prepublication_conflict();
            let terminal = serde_json::to_string(&error).map_err(internal)?;
            ctx.db.transaction(move |conn| {
                let changed = conn.execute(
                    "UPDATE local_operation_receipts SET state='terminal_error',terminal_outcome_json=?5,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                     WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4",
                    rusqlite::params![owner,operation,hash.as_slice(),fence,terminal,chrono::Utc::now().timestamp_millis()],
                )?;
                if changed != 1 { anyhow::bail!("image mutation recovery lost its exact prepared receipt"); }
                let retired = conn.execute(
                    "DELETE FROM image_config_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4 AND publication_phase='prepared'",
                    rusqlite::params![owner,operation,hash.as_slice(),fence],
                )?;
                if retired != 1 { anyhow::bail!("image mutation recovery lost its prepared journal"); }
                Ok(())
            }).await.map_err(internal)?;
        } else if publication_phase == "publication_authorized" && actual == consumed {
            let error = ErrorPayload {
                code: ErrorCode::Conflict,
                message:
                    "the daemon restarted before the image configuration commit; reload and retry"
                        .into(),
            };
            let terminal = serde_json::to_string(&error).map_err(internal)?;
            ctx.db.transaction(move |conn| {
                let changed = conn.execute(
                    "UPDATE local_operation_receipts SET state='terminal_cancelled',terminal_outcome_json=?5,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                     WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4",
                    rusqlite::params![owner,operation,hash.as_slice(),fence,terminal,chrono::Utc::now().timestamp_millis()],
                )?;
                if changed != 1 { anyhow::bail!("image mutation recovery lost its exact receipt"); }
                conn.execute("DELETE FROM image_config_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2", rusqlite::params![owner,operation])?;
                Ok(())
            }).await.map_err(internal)?;
        } else if publication_phase == "publication_authorized" {
            return Err(conflict(
                "image configuration diverged from both consumed and intended revisions during recovery",
            ));
        } else {
            return Err(internal(
                "image mutation journal has an invalid publication phase",
            ));
        }
        recovered = recovered.saturating_add(1);
    }
    Ok(recovered)
}

#[cfg(test)]
mod tests;
