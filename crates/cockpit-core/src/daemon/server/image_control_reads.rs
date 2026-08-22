//! LOCAL owner image-generation control-plane READ handlers
//! (`image-generation-control-plane` inc3a).
//!
//! These assemble the redacted safe projections owned by
//! [`cockpit_proto::image_control`] from a loaded [`ImageGenerationConfig`].
//! Every projection routes through the single `cockpit-proto` funnel, so no
//! secret-bearing field (credential_ref/headers/graph_json/source_url) can
//! reach the wire. Handlers are pure over the loaded config: no network, no
//! mutation.
//!
//! Pagination is deterministic: items sort ascending by immutable id, the
//! opaque cursor is the base64url encoding of the last returned id, and a page
//! returns at most `limit` (default 50, max 100) items. `snapshotGeneration`
//! is the process config generation. Full cursor-generation binding /
//! `cursor_stale` fencing arrives with the snapshot increment.

use base64::Engine as _;

use cockpit_config::config::image_generation::{
    ImageAdapterKind, ImageGenerationConfig, ImageTargetIdentity,
};
use cockpit_proto::image_control::{
    ImageControlReadResponseV1, ImageControlReadResultV1, ImageEndpointSafeV1, ImageTargetSafeV1,
    ImageWorkflowSafeV1,
};

use crate::daemon::proto::{ErrorCode, ErrorPayload};

const DEFAULT_LIMIT: usize = 50;
const MAX_LIMIT: usize = 100;

fn bad_request(message: impl Into<String>) -> ErrorPayload {
    ErrorPayload {
        code: ErrorCode::BadRequest,
        message: message.into(),
    }
}

/// Resolve the effective page size. A supplied limit outside `1..=100` is a
/// client error; an absent limit defaults to 50.
fn resolve_limit(limit: Option<u16>) -> Result<usize, ErrorPayload> {
    match limit {
        None => Ok(DEFAULT_LIMIT),
        Some(l) => {
            let l = l as usize;
            if (1..=MAX_LIMIT).contains(&l) {
                Ok(l)
            } else {
                Err(bad_request("image control list limit must be 1..=100"))
            }
        }
    }
}

/// Decode an opaque cursor into the "last seen id" it encodes. A malformed
/// cursor is a client error.
fn decode_cursor(cursor: Option<&str>) -> Result<Option<String>, ErrorPayload> {
    match cursor {
        None => Ok(None),
        Some(raw) => {
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(raw.as_bytes())
                .map_err(|_| bad_request("image control cursor is malformed"))?;
            let id = String::from_utf8(bytes)
                .map_err(|_| bad_request("image control cursor is malformed"))?;
            Ok(Some(id))
        }
    }
}

fn encode_cursor(id: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_bytes())
}

/// Deterministic id-ordered pagination. Returns the selected slice of `sorted`
/// (already ascending by id) after the cursor, capped at `limit`, plus the
/// next cursor when more remain.
fn page<'a, T>(
    sorted: Vec<(&'a str, &'a T)>,
    after: Option<String>,
    limit: usize,
) -> (Vec<&'a T>, Option<String>) {
    let mut filtered: Vec<(&'a str, &'a T)> = sorted
        .into_iter()
        .filter(|(id, _)| after.as_ref().is_none_or(|a| *id > a.as_str()))
        .collect();
    let has_more = filtered.len() > limit;
    filtered.truncate(limit);
    let next_cursor = if has_more {
        filtered.last().map(|(id, _)| encode_cursor(id))
    } else {
        None
    };
    (
        filtered.into_iter().map(|(_, item)| item).collect(),
        next_cursor,
    )
}

/// The daemon adapter kind for a target, resolved through its endpoint.
fn target_adapter(cfg: &ImageGenerationConfig, endpoint_id: &str) -> Option<ImageAdapterKind> {
    cfg.endpoints()
        .iter()
        .find(|e| e.id == endpoint_id)
        .map(|e| e.adapter)
}

/// The ID-sorted-unique set of target ids that bind `workflow_id`.
fn referencing_target_ids(cfg: &ImageGenerationConfig, workflow_id: &str) -> Vec<String> {
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

pub(crate) fn endpoint_list(
    cfg: &ImageGenerationConfig,
    generation: &str,
    daemon_instance_id: String,
    project_id: String,
    limit: Option<u16>,
    cursor: Option<&str>,
) -> Result<ImageControlReadResponseV1, ErrorPayload> {
    let limit = resolve_limit(limit)?;
    let after = decode_cursor(cursor)?;
    let mut sorted: Vec<_> = cfg.endpoints().iter().map(|e| (e.id.as_str(), e)).collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let (items, next_cursor) = page(sorted, after, limit);
    let items = items
        .into_iter()
        .map(|e| ImageEndpointSafeV1::project(e, generation.to_string()))
        .collect();
    Ok(ImageControlReadResponseV1::new(
        daemon_instance_id,
        project_id,
        ImageControlReadResultV1::EndpointPage {
            items,
            next_cursor,
            snapshot_generation: generation.to_string(),
        },
    ))
}

pub(crate) fn endpoint_get(
    cfg: &ImageGenerationConfig,
    generation: &str,
    daemon_instance_id: String,
    project_id: String,
    endpoint_id: &str,
) -> Result<ImageControlReadResponseV1, ErrorPayload> {
    let endpoint = cfg
        .endpoints()
        .iter()
        .find(|e| e.id == endpoint_id)
        .ok_or_else(|| bad_request("image endpoint not found"))?;
    Ok(ImageControlReadResponseV1::new(
        daemon_instance_id,
        project_id,
        ImageControlReadResultV1::EndpointEntity {
            item: ImageEndpointSafeV1::project(endpoint, generation.to_string()),
        },
    ))
}

pub(crate) fn target_list(
    cfg: &ImageGenerationConfig,
    generation: &str,
    daemon_instance_id: String,
    project_id: String,
    limit: Option<u16>,
    cursor: Option<&str>,
) -> Result<ImageControlReadResponseV1, ErrorPayload> {
    let limit = resolve_limit(limit)?;
    let after = decode_cursor(cursor)?;
    let mut sorted: Vec<_> = cfg.targets().iter().map(|t| (t.id.as_str(), t)).collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let (items, next_cursor) = page(sorted, after, limit);
    let items = items
        .into_iter()
        .map(|t| {
            ImageTargetSafeV1::project(
                t,
                target_adapter(cfg, &t.endpoint_id),
                generation.to_string(),
            )
        })
        .collect();
    Ok(ImageControlReadResponseV1::new(
        daemon_instance_id,
        project_id,
        ImageControlReadResultV1::TargetPage {
            items,
            next_cursor,
            snapshot_generation: generation.to_string(),
        },
    ))
}

pub(crate) fn target_get(
    cfg: &ImageGenerationConfig,
    generation: &str,
    daemon_instance_id: String,
    project_id: String,
    target_id: &str,
) -> Result<ImageControlReadResponseV1, ErrorPayload> {
    let target = cfg
        .targets()
        .iter()
        .find(|t| t.id == target_id)
        .ok_or_else(|| bad_request("image target not found"))?;
    Ok(ImageControlReadResponseV1::new(
        daemon_instance_id,
        project_id,
        ImageControlReadResultV1::TargetEntity {
            item: ImageTargetSafeV1::project(
                target,
                target_adapter(cfg, &target.endpoint_id),
                generation.to_string(),
            ),
        },
    ))
}

pub(crate) fn workflow_list(
    cfg: &ImageGenerationConfig,
    generation: &str,
    daemon_instance_id: String,
    project_id: String,
    limit: Option<u16>,
    cursor: Option<&str>,
) -> Result<ImageControlReadResponseV1, ErrorPayload> {
    let limit = resolve_limit(limit)?;
    let after = decode_cursor(cursor)?;
    let mut sorted: Vec<_> = cfg.workflows().iter().map(|w| (w.id.as_str(), w)).collect();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let (items, next_cursor) = page(sorted, after, limit);
    let items = items
        .into_iter()
        .map(|w| {
            ImageWorkflowSafeV1::project(
                w,
                referencing_target_ids(cfg, &w.id),
                generation.to_string(),
            )
        })
        .collect();
    Ok(ImageControlReadResponseV1::new(
        daemon_instance_id,
        project_id,
        ImageControlReadResultV1::WorkflowPage {
            items,
            next_cursor,
            snapshot_generation: generation.to_string(),
        },
    ))
}

pub(crate) fn workflow_get(
    cfg: &ImageGenerationConfig,
    generation: &str,
    daemon_instance_id: String,
    project_id: String,
    workflow_id: &str,
) -> Result<ImageControlReadResponseV1, ErrorPayload> {
    let workflow = cfg
        .workflows()
        .iter()
        .find(|w| w.id == workflow_id)
        .ok_or_else(|| bad_request("image workflow not found"))?;
    let refs = referencing_target_ids(cfg, workflow_id);
    Ok(ImageControlReadResponseV1::new(
        daemon_instance_id,
        project_id,
        ImageControlReadResultV1::WorkflowEntity {
            item: ImageWorkflowSafeV1::project(workflow, refs, generation.to_string()),
        },
    ))
}
