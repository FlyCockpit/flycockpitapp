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
//! 3. fences the daemon config generation with
//!    [`inventory::compare_and_bump_config_generation`]: an expected-generation
//!    mismatch or a concurrently-moved generation fails closed with `Conflict`
//!    and performs NO write;
//! 4. persists the new registry atomically via [`ExtendedConfigDoc::write`]
//!    (which takes the `ConfigMutationLock` file lock);
//! 5. emits a `config_changed`
//!    [`ImageControlEventV1`](cockpit_proto::image_control::ImageControlEventV1)
//!    carrying only SAFE projections (never a raw credential/header/graph blob).
//!
//! The opaque `*_json` request payloads keep the raw `credential_ref`/`headers`
//! out of typed wire fields; they are accepted only over the authenticated local
//! owner socket. The reply and event carry only the redacting SafeV1
//! projections.

use std::path::Path;
use std::sync::Arc;

use cockpit_config::config::extended::{ExtendedConfig, ExtendedConfigDoc};
use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageEndpoint, ImageGenerationConfig, ImageGenerationConfigError,
    ImageGenerationTarget, ImageTargetIdentity, RegisteredComfyWorkflow,
};
use cockpit_proto::image_control::{
    ImageConfigChangeSetSafeV1, ImageConfigChangeV1, ImageControlEventV1,
    ImageControlMutationResponseV1, ImageEndpointSafeV1, ImageTargetSafeV1, ImageWorkflowSafeV1,
};

use crate::daemon::proto::{ErrorCode, ErrorPayload, Request, Response};
use crate::daemon::server::sessions::internal;
use crate::daemon::server::{DaemonContext, inventory};

/// Serializes image-config mutations among themselves so the read → apply →
/// generation-CAS → write sequence is atomic w.r.t. sibling image mutations
/// (mirrors `WORKSPACE_TRUST_RPC_LOCK`). Cross-RPC bumps by other config
/// writers are still caught by the generation CAS and fail closed.
static IMAGE_CONFIG_MUTATION_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

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

/// Persist the new registry to the most-specific existing `config.json` on the
/// discovered layer path (scaffolding one in the project `.cockpit/` when none
/// exists), preserving unknown/sibling keys. `image_generation` is an atomic
/// registry, so `ExtendedConfigDoc::write` whole-replaces it under the
/// `ConfigMutationLock`.
fn persist_registry(
    project_root: &Path,
    loaded: &ExtendedConfig,
    new_registry: &ImageGenerationConfig,
) -> anyhow::Result<()> {
    use crate::config::dirs::{CONFIG_FILE, discover_config_dirs};
    let target = discover_config_dirs(project_root)
        .into_iter()
        .map(|dir| dir.path.join(CONFIG_FILE))
        .find(|path| path.exists())
        .unwrap_or_else(|| project_root.join(".cockpit").join(CONFIG_FILE));
    let mut doc = ExtendedConfigDoc::load(&target)?;
    // Start from the effective config we loaded so sibling typed fields the doc
    // does not itself set are not resurrected as defaults; only the atomic
    // `image_generation` registry is the value under change.
    let mut cfg = loaded.clone();
    cfg.image_generation = new_registry.clone();
    doc.write(&cfg)?;
    Ok(())
}

fn extract(request: &Request) -> Result<(String, Option<u64>, Edit), ErrorPayload> {
    let (project_root, expected, edit) = match request {
        Request::ImageEndpointCreate {
            project_root,
            endpoint_json,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::EndpointCreate(endpoint_json.clone()),
        ),
        Request::ImageEndpointUpdate {
            project_root,
            endpoint_id,
            endpoint_json,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::EndpointUpdate {
                endpoint_id: endpoint_id.clone(),
                json: endpoint_json.clone(),
            },
        ),
        Request::ImageEndpointDelete {
            project_root,
            endpoint_id,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::EndpointDelete(endpoint_id.clone()),
        ),
        Request::ImageTargetCreate {
            project_root,
            target_json,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::TargetCreate(target_json.clone()),
        ),
        Request::ImageTargetUpdate {
            project_root,
            target_id,
            target_json,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::TargetUpdate {
                target_id: target_id.clone(),
                json: target_json.clone(),
            },
        ),
        Request::ImageTargetDelete {
            project_root,
            target_id,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::TargetDelete(target_id.clone()),
        ),
        Request::ImageTargetSetDefault {
            project_root,
            target_id,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::TargetSetDefault(target_id.clone()),
        ),
        Request::ImageWorkflowUpload {
            project_root,
            workflow_json,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::WorkflowUpload(workflow_json.clone()),
        ),
        Request::ImageWorkflowBind {
            project_root,
            workflow_id,
            bindings_json,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
            Edit::WorkflowBind {
                workflow_id: workflow_id.clone(),
                json: bindings_json.clone(),
            },
        ),
        Request::ImageWorkflowDelete {
            project_root,
            workflow_id,
            expected_config_generation,
        } => (
            project_root.clone(),
            *expected_config_generation,
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
    Ok((project_root, expected, edit))
}

/// LOCAL owner image-config mutation dispatch. Declared
/// `owner_only`+`local_only`+`serialized`+`is_mutation`, so it reaches only the
/// serialized surface with no remote operation reserved.
pub(crate) async fn dispatch_image_control_mutation(
    ctx: &Arc<DaemonContext>,
    request: Request,
) -> std::result::Result<Response, ErrorPayload> {
    let (project_root, expected, edit) = extract(&request)?;

    // Serialize image mutations so the read → CAS → write is atomic among them.
    let _guard = IMAGE_CONFIG_MUTATION_LOCK.lock().await;

    // Read the current generation FIRST, then load the registry, so a config
    // write that lands between the two makes the generation CAS below fail
    // closed rather than persisting an edit built on a stale registry.
    let current = inventory::current_config_generation();
    if let Some(expected) = expected
        && expected != current
    {
        return Err(conflict(format!(
            "image config generation is {current}, expected {expected}"
        )));
    }

    let cwd = std::path::PathBuf::from(&project_root);
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

    // Fence the daemon config generation. If it moved since `current`, fail
    // closed with NO write.
    let new_generation = inventory::compare_and_bump_config_generation(current)
        .ok_or_else(|| conflict("image config generation changed concurrently"))?;
    let generation = new_generation.to_string();

    // Persist the validated registry atomically. Only reached after the CAS.
    persist_registry(&cwd, &extended, &new_registry).map_err(internal)?;

    let change_set = ImageConfigChangeSetSafeV1::new(
        generation.clone(),
        project_changes(&new_registry, &pending, &generation),
    );
    let daemon_instance_id = inventory::daemon_instance_id().to_string();

    // Emit the redacted `config_changed` replay event (safe projections only).
    ctx.broadcast_global(crate::daemon::proto::Event::ImageControlConfigChanged {
        event: ImageControlEventV1::config_changed(
            daemon_instance_id.clone(),
            project_root.clone(),
            change_set.clone(),
        ),
    });

    Ok(Response::ImageControlMutated(
        ImageControlMutationResponseV1::new(daemon_instance_id, project_root, change_set),
    ))
}

#[cfg(test)]
mod tests;
