//! LOCAL owner image-generation control-plane CONFIG-MUTATION handlers
//! (`image-generation-control-plane` inc3b + inc3c).
//!
//! Ten `owner_only` + `local_only` + `serialized` mutations
//! (`image_endpoint_create/update/delete`,
//! `image_target_create/update/delete/set_default`, and the inc3c workflow
//! mutations `image_workflow_upload/bind/delete`) that edit the secret-bearing
//! image-generation registry. Each one:
//!
//! 1. loads the registry through the SAME trust-gated daemon config contract the
//!    read surface uses (`resolve_workspace_trust_policy_from_db` +
//!    `load_effective_for_daemon`), so remote-injected `image_generation` is
//!    stripped and `project_root` is only a config cwd, never authority — the
//!    RPC is already `owner_only`-gated;
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
    ImageConfigChangeSetSafeV1, ImageConfigChangeV1, ImageConfigMutationIntentV1,
    ImageControlEventV1, ImageControlMutationResponseV1, ImageEndpointSafeV1, ImageTargetSafeV1,
    ImageWorkflowSafeV1,
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
fn map_config_error(error: ImageGenerationConfigError) -> ErrorPayload {
    bad_request(format!("invalid image generation configuration: {error:?}"))
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
    EndpointCreate(String),
    EndpointUpdate { endpoint_id: String, json: String },
    EndpointDelete(String),
    TargetCreate(String),
    TargetUpdate { target_id: String, json: String },
    TargetDelete(String),
    TargetSetDefault(String),
    WorkflowUpload(String),
    WorkflowBind { workflow_id: String, json: String },
    WorkflowDelete(String),
}

fn parse_endpoint(json: &str) -> Result<ImageEndpoint, ErrorPayload> {
    serde_json::from_str(json)
        .map_err(|error| bad_request(format!("invalid image endpoint: {error}")))
}

fn parse_target(json: &str) -> Result<ImageGenerationTarget, ErrorPayload> {
    serde_json::from_str(json)
        .map_err(|error| bad_request(format!("invalid image target: {error}")))
}

fn parse_workflow(json: &str) -> Result<RegisteredComfyWorkflow, ErrorPayload> {
    serde_json::from_str(json)
        .map_err(|error| bad_request(format!("invalid image workflow: {error}")))
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

fn amend_response_generation(response: &mut Response, generation: u64) {
    let Response::ImageControlMutated(receipt) = response else {
        return;
    };
    let generation = generation.to_string();
    receipt.config_generation.clone_from(&generation);
    receipt.change_set.config_generation.clone_from(&generation);
    for change in &mut receipt.change_set.changes {
        match change {
            ImageConfigChangeV1::EndpointUpserted {
                entity_generation,
                item,
                ..
            } => {
                entity_generation.clone_from(&generation);
                item.entity_generation.clone_from(&generation);
            }
            ImageConfigChangeV1::EndpointDeleted {
                entity_generation, ..
            }
            | ImageConfigChangeV1::TargetDeleted {
                entity_generation, ..
            }
            | ImageConfigChangeV1::WorkflowDeleted {
                entity_generation, ..
            } => entity_generation.clone_from(&generation),
            ImageConfigChangeV1::TargetUpserted {
                entity_generation,
                item,
                ..
            } => {
                entity_generation.clone_from(&generation);
                item.entity_generation.clone_from(&generation);
            }
            ImageConfigChangeV1::WorkflowUpserted {
                entity_generation,
                item,
                ..
            } => {
                entity_generation.clone_from(&generation);
                item.entity_generation.clone_from(&generation);
            }
        }
    }
}

/// Persist the new registry to the most-specific existing `config.json` on the
/// discovered layer path (scaffolding one in the project `.cockpit/` when none
/// exists), preserving unknown/sibling keys. `image_generation` is an atomic
/// registry, so `ExtendedConfigDoc::write` whole-replaces it under the
/// `ConfigMutationLock`.
fn target_path(project_root: &Path) -> PathBuf {
    use crate::config::dirs::{CONFIG_FILE, discover_config_dirs};
    discover_config_dirs(project_root)
        .into_iter()
        .map(|dir| dir.path.join(CONFIG_FILE))
        .find(|path| path.exists())
        .unwrap_or_else(|| project_root.join(".cockpit").join(CONFIG_FILE))
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

fn read_document(path: &Path) -> anyhow::Result<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(b"{}".to_vec()),
        Err(error) => Err(error.into()),
    }
}

pub(crate) fn authoritative_target_revision(
    ctx: &DaemonContext,
    project_root: &Path,
) -> anyhow::Result<(PathBuf, String)> {
    let target = target_path(project_root);
    let revision = content_revision(ctx, &read_document(&target)?);
    Ok((target, revision))
}

fn render_registry_patch(
    raw: &[u8],
    registry: &ImageGenerationConfig,
) -> Result<Vec<u8>, ErrorPayload> {
    let mut document: serde_json::Value = serde_json::from_slice(raw)
        .map_err(|error| bad_request(format!("invalid authoritative config document: {error}")))?;
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
    edit: Edit,
}

fn extract(request: &Request) -> Result<ExtractedMutation, ErrorPayload> {
    let (
        client_operation_id,
        mutation_intent_hash,
        project_root,
        expected,
        expected_revision,
        edit,
    ) = match request {
        Request::ImageEndpointCreate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            endpoint_json,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::EndpointCreate(endpoint_json.clone()),
        ),
        Request::ImageEndpointUpdate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            endpoint_id,
            endpoint_json,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::EndpointUpdate {
                endpoint_id: endpoint_id.clone(),
                json: endpoint_json.clone(),
            },
        ),
        Request::ImageEndpointDelete {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            endpoint_id,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::EndpointDelete(endpoint_id.clone()),
        ),
        Request::ImageTargetCreate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_json,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::TargetCreate(target_json.clone()),
        ),
        Request::ImageTargetUpdate {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_id,
            target_json,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::TargetUpdate {
                target_id: target_id.clone(),
                json: target_json.clone(),
            },
        ),
        Request::ImageTargetDelete {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_id,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::TargetDelete(target_id.clone()),
        ),
        Request::ImageTargetSetDefault {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            target_id,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::TargetSetDefault(target_id.clone()),
        ),
        Request::ImageWorkflowUpload {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            workflow_json,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::WorkflowUpload(workflow_json.clone()),
        ),
        Request::ImageWorkflowBind {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            workflow_id,
            bindings_json,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::WorkflowBind {
                workflow_id: workflow_id.clone(),
                json: bindings_json.clone(),
            },
        ),
        Request::ImageWorkflowDelete {
            client_operation_id,
            mutation_intent_hash,
            project_root,
            workflow_id,
            expected_config_generation,
            expected_config_revision,
        } => (
            client_operation_id.clone(),
            mutation_intent_hash.clone(),
            project_root.clone(),
            *expected_config_generation,
            expected_config_revision.clone(),
            Edit::WorkflowDelete(workflow_id.clone()),
        ),
        other => {
            return Err(internal(format!(
                "dispatch_image_control_mutation called with non-mutation request `{}`",
                crate::daemon::principal::request_kind(other)
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
    let extracted = extract(&request)?;
    let ExtractedMutation {
        client_operation_id,
        mutation_intent_hash,
        project_root,
        expected_generation,
        expected_revision,
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
    let (_, extended) = ctx
        .config_source
        .load_effective_for_daemon(&cwd, &trust_policy)
        .map_err(internal)?;

    // Apply + validate through the single `ImageGenerationConfig::new` funnel.
    // An invalid result returns here — nothing is written or bumped.
    let (new_registry, pending) = apply_edit(&extended.image_generation, edit)?;

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

    let target = target_path(&cwd);
    let target_display = target.to_string_lossy().into_owned();
    let publication_guard =
        cockpit_config::config::hold_config_mutation_lock(&target).map_err(internal)?;
    let consumed = read_document(&target).map_err(internal)?;
    let consumed_revision = content_revision(ctx, &consumed);
    if consumed_revision != expected_revision {
        return Err(conflict(
            "image configuration document changed; reload before mutating",
        ));
    }
    let intended = render_registry_patch(&consumed, &new_registry)?;
    let result_revision = content_revision(ctx, &intended);
    let predicted_generation =
        current.saturating_add(u64::from(result_revision != consumed_revision));
    let generation = predicted_generation.to_string();

    let change_set = ImageConfigChangeSetSafeV1::new(
        generation.clone(),
        project_changes(&new_registry, &pending, &generation),
    );
    let daemon_instance_id = inventory::daemon_instance_id().to_string();
    let canonical_project_id = cwd.to_string_lossy().into_owned();
    let mut response = Response::ImageControlMutated(ImageControlMutationResponseV1::new(
        client_operation_id.clone(),
        mutation_intent_hash.clone(),
        daemon_instance_id.clone(),
        canonical_project_id,
        project_root.clone(),
        target_display.clone(),
        consumed_revision.clone(),
        result_revision.clone(),
        current,
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
              intended_revision,consumed_generation,terminal_response_json,created_at_unix_ms)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
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
        return Err(conflict(
            "image configuration target changed immediately before commit",
        ));
    }
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
        amend_response_generation(&mut response, published_generation);
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
            change_set.clone(),
        ),
    });

    Ok(response)
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
                    journal.intended_revision,journal.terminal_response_json,receipt.state
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
        response_json,
        receipt_state,
    ) in rows
    {
        let hash: [u8; 32] = request_hash
            .try_into()
            .map_err(|_| internal("image mutation journal request hash is malformed"))?;
        if receipt_state.starts_with("terminal_") {
            ctx.db.write(move |conn| {
                conn.execute(
                    "DELETE FROM image_config_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2",
                    rusqlite::params![owner, operation],
                )?;
                Ok(())
            }).await.map_err(internal)?;
            recovered = recovered.saturating_add(1);
            continue;
        }
        let actual = content_revision(ctx, &read_document(Path::new(&target)).map_err(internal)?);
        if actual == intended {
            let mut response: Response = serde_json::from_str(&response_json).map_err(internal)?;
            let published = inventory::publish_committed_config_generation();
            amend_response_generation(&mut response, published);
            let terminal = serde_json::to_string(&response).map_err(internal)?;
            ctx.db.transaction(move |conn| {
                let changed = conn.execute(
                    "UPDATE local_operation_receipts SET state='terminal_success',terminal_outcome_json=?5,execution_expires_at_unix_ms=NULL,updated_at_unix_ms=?6
                     WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4 AND state='executing'",
                    rusqlite::params![owner,operation,hash.as_slice(),fence,terminal,chrono::Utc::now().timestamp_millis()],
                )?;
                if changed != 1 { anyhow::bail!("image mutation recovery lost its executing receipt"); }
                conn.execute("DELETE FROM image_config_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2", rusqlite::params![owner,operation])?;
                Ok(())
            }).await.map_err(internal)?;
        } else if actual == consumed {
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
                     WHERE owner_digest=?1 AND client_operation_id=?2 AND request_hash=?3 AND fencing_generation=?4 AND state='executing'",
                    rusqlite::params![owner,operation,hash.as_slice(),fence,terminal,chrono::Utc::now().timestamp_millis()],
                )?;
                if changed != 1 { anyhow::bail!("image mutation recovery lost its executing receipt"); }
                conn.execute("DELETE FROM image_config_mutation_journals WHERE owner_digest=?1 AND client_operation_id=?2", rusqlite::params![owner,operation])?;
                Ok(())
            }).await.map_err(internal)?;
        } else {
            return Err(conflict(
                "image configuration diverged from both consumed and intended revisions during recovery",
            ));
        }
        recovered = recovered.saturating_add(1);
    }
    Ok(recovered)
}

#[cfg(test)]
mod tests;
